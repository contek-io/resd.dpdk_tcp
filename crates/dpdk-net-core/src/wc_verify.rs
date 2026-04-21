//! Write-Combining BAR-mapping verification for AWS ENA. Mirrors the
//! pattern of `llq_verify.rs`: bring-up-time check, slow-path counter
//! bump on negative result, WARN-only (no fail-hard by default).
//!
//! Source: docs/references/ena-dpdk-readme.md §6.1 (mandatory WC for
//! ENAv2 + LLQ), §6.2.3 (verification recipe), §15 (DPDK 21.11
//! regression). On a misconfigured igb_uio (loaded without
//! `wc_activate=1`) or affected vfio-pci, LLQ activates but the BAR
//! falls back to uncached-minus → ena_com_prep_pkts dominates the
//! flame graph (perf-FAQ Q1).

/// Parse `/sys/kernel/debug/x86/pat_memtype_list` and return whether
/// the prefetchable BAR at `bar_phys_addr` (e.g. 0xfe900000) has a
/// `write-combining` mapping. Per the README §6.2.3 the file format is:
///
/// ```text
/// PAT: [mem 0x00000000fe900000-0x00000000fea00000] write-combining
/// ```
///
/// Match the second numeric — the start of the range — against
/// `bar_phys_addr` and confirm the trailing token is `write-combining`.
///
/// Consumed by `verify_wc_for_ena` below (engine bring-up path) and by
/// the Task 12 pure-unit smoke at `tests/ena_obs_smoke.rs`. Visibility
/// is `pub` (not `pub(crate)`) so the integration-test crate can reach
/// it across the crate boundary.
pub fn parse_pat_memtype_list(
    pat_contents: &str,
    bar_phys_addr: u64,
) -> WcVerdict {
    let needle_lo = format!("{:016x}", bar_phys_addr); // 16-hex zero-pad
    for line in pat_contents.lines() {
        // Line shape: "PAT: [mem 0x00000000fe900000-0x00000000fea00000] write-combining"
        let Some(after_mem) = line.find("[mem 0x") else { continue };
        let rest = &line[after_mem + "[mem 0x".len()..];
        let Some(dash) = rest.find('-') else { continue };
        let lo_hex = &rest[..dash];
        if !lo_hex.eq_ignore_ascii_case(&needle_lo) {
            continue;
        }
        // Found a matching BAR-start address. Decide WC vs other based
        // on the trailing token. The post-loop fall-through path means
        // "no matching range found at all" → NotFound.
        if line.contains("write-combining") {
            return WcVerdict::WriteCombining;
        } else {
            return WcVerdict::OtherMapping;
        }
    }
    WcVerdict::NotFound
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WcVerdict {
    WriteCombining,
    OtherMapping,
    NotFound,
}

use crate::counters::Counters;
use std::sync::atomic::Ordering;

/// Bring-up integration: read /sys/kernel/debug/x86/pat_memtype_list,
/// scan for the prefetchable BAR's WC mapping, bump the
/// `eth.llq_wc_missing` counter on miss + emit a WARN. Never fails
/// hard — the negative case is observable via the counter.
///
/// Returns unconditionally to keep the bring-up path infallible.
/// Skipped silently (no WARN spam) for non-ENA drivers, non-Linux /
/// non-x86_64 architectures, `bar_phys_addr == 0` (PMD did not expose
/// the BAR), or when /sys is unreadable (missing debugfs / container
/// permissions / non-root).
///
/// Called from `engine::Engine::configure_port_offloads` right after
/// the `dev_info_get` + driver-name capture block.
pub(crate) fn verify_wc_for_ena(
    port_id: u16,
    driver_name: &[u8; 32],
    bar_phys_addr: u64,
    counters: &Counters,
) {
    let driver_str = std::str::from_utf8(
        &driver_name[..driver_name.iter().position(|&b| b == 0).unwrap_or(32)],
    )
    .unwrap_or("");
    if driver_str != "net_ena" {
        return;
    }
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }
    if bar_phys_addr == 0 {
        eprintln!(
            "dpdk_net: port {} WC verification skipped: prefetchable BAR \
             address unavailable from PMD",
            port_id
        );
        return;
    }
    let path = "/sys/kernel/debug/x86/pat_memtype_list";
    let pat_contents = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "dpdk_net: port {} WC verification skipped: cannot read {}: {}",
                port_id, path, e
            );
            return;
        }
    };
    match parse_pat_memtype_list(&pat_contents, bar_phys_addr) {
        WcVerdict::WriteCombining => {
            // Healthy steady state. No log line needed.
        }
        WcVerdict::OtherMapping => {
            counters.eth.llq_wc_missing.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "dpdk_net: port {} prefetchable BAR 0x{:016x} is mapped \
                 NON-write-combining — LLQ will run but with severe perf \
                 degradation (ena_com_prep_pkts will dominate). See \
                 docs/references/ena-dpdk-readme.md §6.1 + §14 perf FAQ Q1.",
                port_id, bar_phys_addr
            );
        }
        WcVerdict::NotFound => {
            counters.eth.llq_wc_missing.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "dpdk_net: port {} prefetchable BAR 0x{:016x} not found in \
                 {} — kernel may lack PAT debug or BAR address is wrong.",
                port_id, bar_phys_addr, path
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
PAT: [mem 0x00000000fe800000-0x00000000fe900000] write-combining
PAT: [mem 0x00000000fe900000-0x00000000fea00000] write-combining
PAT: [mem 0x00000000fea00000-0x00000000feb00000] uncached-minus
";

    #[test]
    fn matches_write_combining_bar() {
        assert_eq!(
            parse_pat_memtype_list(SAMPLE, 0xfe900000),
            WcVerdict::WriteCombining,
        );
    }

    #[test]
    fn detects_uncached_bar() {
        assert_eq!(
            parse_pat_memtype_list(SAMPLE, 0xfea00000),
            WcVerdict::OtherMapping,
        );
    }

    #[test]
    fn missing_bar_is_not_found() {
        assert_eq!(
            parse_pat_memtype_list(SAMPLE, 0xdeadbeef),
            WcVerdict::NotFound,
        );
    }

    #[test]
    fn empty_input_is_not_found() {
        assert_eq!(
            parse_pat_memtype_list("", 0xfe900000),
            WcVerdict::NotFound,
        );
    }

    #[test]
    fn case_insensitive_hex() {
        let upper = "PAT: [mem 0x00000000FE900000-0x00000000FEA00000] write-combining\n";
        assert_eq!(
            parse_pat_memtype_list(upper, 0xfe900000),
            WcVerdict::WriteCombining,
        );
    }
}
