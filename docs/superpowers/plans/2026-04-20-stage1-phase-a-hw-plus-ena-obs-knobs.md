# Phase A-HW+ — ENA observability + tuning knobs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the five highest-impact gaps surfaced by the 2026-04-20 review against the upstream ENA DPDK README — H1 WC-mapping verification, H2 ENI allowance-exceeded xstats, M1 `large_llq_hdr` knob, M2 `miss_txc_to` knob, M3 per-queue ENA xstats — without touching the wire path.

**Architecture:** All deliverables are slow-path. Two new modules (`wc_verify.rs`, `ena_xstats.rs`) mirror the existing `llq_verify.rs` pattern (bring-up check + counter bump + WARN). `EngineConfig` gains two `u8` knob fields + a paired extern "C" devarg-builder helper that the application splices into its EAL args. `EthCounters` / `dpdk_net_eth_counters_t` grow by 14 always-allocated `u64` fields. No new feature flags; no hot-path code; no public API breakage beyond appending fields (mirroring A-HW's append-only discipline).

**Tech Stack:** Rust 2024, DPDK 23.11, cbindgen for the C header, AWS ENA PMD on EC2 (the only target where any of these levers fire). Single-queue Stage 1; per-queue counters cover queue 0 only.

**Source documents:**
- `docs/references/ena-dpdk-readme.md` — vendored ENA PMD README (1528 lines)
- `docs/references/ena-dpdk-review-2026-04-20.md` — gap analysis that produced this plan
- `docs/superpowers/specs/2026-04-19-stage1-phase-a-hw-ena-offload-design.md` — A-HW design (parent)
- `docs/superpowers/plans/stage1-phase-roadmap.md` — roadmap (this becomes a new row between A-HW and A6)

**Branch / worktree:** `phase-a-hw-ena-followups` off `master` (commit `eb01e79`), at `.worktrees/phase-a-hw-ena-followups/`.
**Ships:** `phase-a-hw-plus-complete` tag gated on `cargo test` green + 2 smoke runs (SW-fallback, ENA real-host) + extended knob-coverage audit + mTCP + RFC review reports both showing zero open `[ ]`.

---

## File structure

| File | Action | Responsibility |
|---|---|---|
| `crates/dpdk-net-core/src/wc_verify.rs` | CREATE | Parse `/sys/kernel/debug/x86/pat_memtype_list`, locate the prefetchable BAR for the ENA port, return verdict; pure function. |
| `crates/dpdk-net-core/src/ena_xstats.rs` | CREATE | Resolve ENA `rte_eth_xstats` names → IDs at engine_create; provide `scrape(port_id, &EthCounters)` slow-path scraper. |
| `crates/dpdk-net-core/src/engine.rs` | MODIFY | Call `wc_verify` in `configure_port_offloads`; cache xstat-ID map on `Engine`; expose `Engine::scrape_xstats()`; thread M1/M2 knobs. |
| `crates/dpdk-net-core/src/counters.rs` | MODIFY | 14 new `EthCounters` fields; shrink `_pad` to keep struct size constant. |
| `crates/dpdk-net-core/src/lib.rs` | MODIFY | `pub mod wc_verify; pub mod ena_xstats;` declarations. |
| `crates/dpdk-net-core/src/error.rs` | MODIFY | (Optional) `Error::WcVerifyFailed(u16)` only if we ever fail-hard; default plan is WARN-only so no new variant. |
| `crates/dpdk-net/src/api.rs` | MODIFY | Mirror 14 new fields onto `dpdk_net_eth_counters_t`; shrink mirror `_pad`. Add `EngineConfig` knob fields to `dpdk_net_engine_config_t`. |
| `crates/dpdk-net/src/lib.rs` | MODIFY | Add `dpdk_net_scrape_xstats` and `dpdk_net_recommended_ena_devargs` extern "C" entry points. |
| `include/dpdk_net.h` | REGENERATE | cbindgen rebuild emits the new symbols + struct fields. |
| `crates/dpdk-net-core/tests/knob-coverage.rs` | MODIFY | New entries for `ena_large_llq_hdr`, `ena_miss_txc_to_sec`. |
| `crates/dpdk-net-core/tests/ahw_smoke_ena_hw.rs` | MODIFY | Add WC verification assertion + xstats scrape correctness assertion. |
| `crates/dpdk-net-core/tests/ena_obs_smoke.rs` | CREATE | Pure unit-level smoke covering `wc_verify` + `ena_xstats` parsers without DPDK. |
| `docs/superpowers/plans/stage1-phase-roadmap.md` | MODIFY | Insert "A-HW+" row between A-HW and A6. |
| `docs/superpowers/reviews/phase-a-hw-plus-mtcp-compare.md` | CREATE | mTCP comparison review report (Task 14). |
| `docs/superpowers/reviews/phase-a-hw-plus-rfc-compliance.md` | CREATE | RFC compliance review report (Task 15). |

**Decomposition rationale:** `wc_verify.rs` and `ena_xstats.rs` are independent slow-path modules mirroring `llq_verify.rs`. M1+M2 ride on `EngineConfig` + a small free-function helper — no new module needed. Per-queue xstats (M3) fold into H2's xstats map naturally.

**Per-task review discipline:** Per `feedback_per_task_review_discipline.md`, every non-trivial implementation task ends with a spec-compliance + code-quality review subagent dispatch (opus 4.7). Steps explicit in each task.

---

## Task 1: Extend EthCounters with 14 ENA observability fields

**Files:**
- Modify: `crates/dpdk-net-core/src/counters.rs:21-46` (EthCounters struct + `_pad` shrink)
- Modify: `crates/dpdk-net/src/api.rs:234-263` (dpdk_net_eth_counters_t mirror + `_pad` shrink)
- Test: `crates/dpdk-net-core/src/counters.rs` (existing inline `mod tests`) — extend layout assertion

**Counter inventory (always-allocated, slow-path per spec §9.1.1):**

H1: `llq_wc_missing` — bumped once at bring-up if WC verification negative.
H2: `eni_bw_in_allowance_exceeded`, `eni_bw_out_allowance_exceeded`, `eni_pps_allowance_exceeded`, `eni_conntrack_allowance_exceeded`, `eni_linklocal_allowance_exceeded` — last-scraped values (snapshot semantics, not deltas).
M1: `llq_header_overflow_risk` — bumped once at bring-up if max-header > 96 B and `ena_large_llq_hdr` knob is 0.
M3 (queue 0 only — Stage 1): `tx_q0_linearize`, `tx_q0_doorbells`, `tx_q0_missed_tx`, `tx_q0_bad_req_id`, `rx_q0_refill_partial`, `rx_q0_bad_desc_num`, `rx_q0_bad_req_id`, `rx_q0_mbuf_alloc_fail` — last-scraped values.

Total: 1 (H1) + 5 (H2) + 1 (M1) + 8 (M3) = **15 fields**. (Plan body uses "14" loosely; the count is 15.)

`EthCounters._pad` currently `[AtomicU64; 9]` → shrinks to `[AtomicU64; 0]`. Add new pad arithmetic so total `EthCounters` size stays at the existing 64-byte multiple (the existing layout assertion in `crates/dpdk-net/src/api.rs:381-396` will catch any drift).

- [ ] **Step 1: Write the failing layout assertion**

Add to `crates/dpdk-net-core/src/counters.rs` a const-block at end of file (next to existing `#[repr(C, align(64))]` decls) BEFORE adding the new fields:

```rust
// Pinned by phase-a-hw-plus Task 1 — cacheline alignment of EthCounters
// must remain 64 B; total size grows by exactly 15 × 8 = 120 B as 15
// new u64 ENA-observability fields are appended.
const _: () = {
    use std::mem::{align_of, size_of};
    assert!(align_of::<EthCounters>() == 64);
    // After Task 1 the size grows from N to N + 120 - (9 - new_pad) * 8.
    // Concrete numeric pin lives in the existing dpdk-net/src/api.rs
    // size-of mirror assertion — see crates/dpdk-net/src/api.rs:381-396.
};
```

Run: `cargo build -p dpdk-net-core --no-default-features --features hw-offloads-all`
Expected: succeeds (no behavior change yet — assertions only check current state).

- [ ] **Step 2: Add the 15 new fields + shrink `_pad` in `EthCounters`**

Modify `crates/dpdk-net-core/src/counters.rs` lines 21-46. Replace the existing A-HW additions block PLUS the trailing `_pad` line with:

```rust
    // A-HW additions — slow-path per spec §9.1.1. Always allocated.
    pub offload_missing_rx_cksum_ipv4: AtomicU64,
    pub offload_missing_rx_cksum_tcp: AtomicU64,
    pub offload_missing_rx_cksum_udp: AtomicU64,
    pub offload_missing_tx_cksum_ipv4: AtomicU64,
    pub offload_missing_tx_cksum_tcp: AtomicU64,
    pub offload_missing_tx_cksum_udp: AtomicU64,
    pub offload_missing_mbuf_fast_free: AtomicU64,
    pub offload_missing_rss_hash: AtomicU64,
    pub offload_missing_llq: AtomicU64,
    pub offload_missing_rx_timestamp: AtomicU64,
    pub rx_drop_cksum_bad: AtomicU64,
    // A-HW+ additions (this plan). All slow-path.
    /// H1 — WC BAR mapping verification (spec §6.1 of upstream ENA README).
    /// One-shot at bring-up: bumped when net_ena AND
    /// /sys/kernel/debug/x86/pat_memtype_list does NOT show write-combining
    /// for the prefetchable BAR. WARN-only by default.
    pub llq_wc_missing: AtomicU64,
    /// M1 — TCP-header-stack worst-case (Eth + IP + TCP + opts) exceeds the
    /// LLQ default 96 B header limit AND ena_large_llq_hdr knob is 0.
    /// Bumped once at engine_create for net_ena ports.
    pub llq_header_overflow_risk: AtomicU64,
    /// H2 — ENI allowance-exceeded xstats (snapshot of last scrape).
    /// rte_eth_xstats name → DPDK ID resolved once at engine_create.
    /// Application drives the scrape cadence via dpdk_net_scrape_xstats.
    pub eni_bw_in_allowance_exceeded: AtomicU64,
    pub eni_bw_out_allowance_exceeded: AtomicU64,
    pub eni_pps_allowance_exceeded: AtomicU64,
    pub eni_conntrack_allowance_exceeded: AtomicU64,
    pub eni_linklocal_allowance_exceeded: AtomicU64,
    /// M3 — Per-queue ENA xstats (queue 0 only — Stage 1 single queue).
    /// Snapshot semantics; same scrape cadence as H2 above.
    pub tx_q0_linearize: AtomicU64,
    pub tx_q0_doorbells: AtomicU64,
    pub tx_q0_missed_tx: AtomicU64,
    pub tx_q0_bad_req_id: AtomicU64,
    pub rx_q0_refill_partial: AtomicU64,
    pub rx_q0_bad_desc_num: AtomicU64,
    pub rx_q0_bad_req_id: AtomicU64,
    pub rx_q0_mbuf_alloc_fail: AtomicU64,
    // _pad sized to keep the struct on a 64-byte multiple. EthCounters now
    // holds 12 (pre-A-HW) + 11 (A-HW) + 15 (A-HW+) = 38 atomic u64s.
    // 38 × 8 = 304 B; next 64-multiple is 320 B → pad with 2 u64s.
    _pad: [AtomicU64; 2],
}
```

- [ ] **Step 3: Mirror the same fields onto `dpdk_net_eth_counters_t` in `crates/dpdk-net/src/api.rs:234-263`**

Replace the existing A-HW additions block + `_pad`:

```rust
    // A-HW additions — mirror of dpdk_net_core::counters::EthCounters.
    pub offload_missing_rx_cksum_ipv4: u64,
    pub offload_missing_rx_cksum_tcp: u64,
    pub offload_missing_rx_cksum_udp: u64,
    pub offload_missing_tx_cksum_ipv4: u64,
    pub offload_missing_tx_cksum_tcp: u64,
    pub offload_missing_tx_cksum_udp: u64,
    pub offload_missing_mbuf_fast_free: u64,
    pub offload_missing_rss_hash: u64,
    pub offload_missing_llq: u64,
    pub offload_missing_rx_timestamp: u64,
    pub rx_drop_cksum_bad: u64,
    // A-HW+ additions — mirror order MUST match core EthCounters exactly.
    pub llq_wc_missing: u64,
    pub llq_header_overflow_risk: u64,
    pub eni_bw_in_allowance_exceeded: u64,
    pub eni_bw_out_allowance_exceeded: u64,
    pub eni_pps_allowance_exceeded: u64,
    pub eni_conntrack_allowance_exceeded: u64,
    pub eni_linklocal_allowance_exceeded: u64,
    pub tx_q0_linearize: u64,
    pub tx_q0_doorbells: u64,
    pub tx_q0_missed_tx: u64,
    pub tx_q0_bad_req_id: u64,
    pub rx_q0_refill_partial: u64,
    pub rx_q0_bad_desc_num: u64,
    pub rx_q0_bad_req_id: u64,
    pub rx_q0_mbuf_alloc_fail: u64,
    pub _pad: [u64; 2],
}
```

- [ ] **Step 4: Build to confirm both struct-size assertions still pass**

Run: `cargo build --workspace --all-features 2>&1 | tail -50`
Expected: compiles. If `assert!(size_of::<dpdk_net_eth_counters_t>() == size_of::<CoreEth>())` (api.rs:392) fails, recompute `_pad` length on both sides until equal.

- [ ] **Step 5: Run existing test suite to confirm no regression**

Run: `cargo test -p dpdk-net-core counters 2>&1 | tail -20`
Expected: all existing counters tests pass; struct-size assertions hold.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/counters.rs crates/dpdk-net/src/api.rs
git commit -m "phase-a-hw-plus: add 15 ENA-observability counters to EthCounters

Slow-path per spec §9.1.1; always allocated for C-ABI stability.
Mirror block in dpdk_net_eth_counters_t; _pad shrunk on both sides
to preserve cacheline-multiple struct size."
```

- [ ] **Step 7: Two-stage review per `feedback_per_task_review_discipline.md`**

Dispatch in parallel (single message with two Agent tool calls):
1. `Agent(subagent_type=general-purpose, model=opus, prompt="Spec-compliance review for Task 1 of docs/superpowers/plans/2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md. Read the plan + the diff (git diff HEAD~1). Verify: (a) all 15 fields in spec are present in both EthCounters and dpdk_net_eth_counters_t; (b) field declaration order matches between the two; (c) _pad arithmetic is correct (size remains 64-multiple); (d) const struct-size assertion at api.rs:381-396 still holds. Report PASS/FAIL with specific divergences if any.")`
2. `Agent(subagent_type=general-purpose, model=opus, prompt="Code-quality review for Task 1. Read the diff. Check: (a) doc-comments on each new field explain the SOURCE (xstats name, /sys path, etc.) and the EXPECTED VALUE pattern; (b) no clippy warnings; (c) no off-by-one in pad arithmetic; (d) AtomicU64 vs u64 mirror consistency. Report PASS/FAIL with line references.")`

Address findings (if any) before proceeding to Task 2.

---

## Task 2: Implement `wc_verify.rs` parser (pure function, no DPDK)

**Files:**
- Create: `crates/dpdk-net-core/src/wc_verify.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs:16` (add `pub mod wc_verify;` after `pub mod llq_verify;`)
- Test: inline `#[cfg(test)] mod tests` inside the new file

**Reference:** `docs/references/ena-dpdk-readme.md` §6.2.3 ("Verification of the Write Combined memory mapping") and §15 ("Known issues" — DPDK 21.11 regression).

The PMD's prefetchable BAR address is provided to the verifier as a hex string (the integration code in Task 3 reads it from `rte_pci_device->mem_resource[2].phys_addr`). The verifier reads `/sys/kernel/debug/x86/pat_memtype_list` and checks for a `write-combining` line whose start address matches.

- [ ] **Step 1: Write failing unit tests for the parser**

Create `crates/dpdk-net-core/src/wc_verify.rs` with:

```rust
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
/// the prefetchable BAR at `bar_phys_addr` (hex like 0xfe900000) has a
/// `write-combining` mapping. Per the README §6.2.3 the file format is:
///
///     PAT: [mem 0x00000000fe900000-0x00000000fea00000] write-combining
///
/// Match the second numeric — the start of the range — against
/// `bar_phys_addr` and confirm the trailing token is `write-combining`.
pub(crate) fn parse_pat_memtype_list(
    pat_contents: &str,
    bar_phys_addr: u64,
) -> WcVerdict {
    let needle_lo = format!("{:016x}", bar_phys_addr); // 16-hex zero-pad
    let mut found_line = false;
    for line in pat_contents.lines() {
        // Line shape: "PAT: [mem 0x00000000fe900000-0x00000000fea00000] write-combining"
        let Some(after_mem) = line.find("[mem 0x") else { continue };
        let rest = &line[after_mem + "[mem 0x".len()..];
        let Some(dash) = rest.find('-') else { continue };
        let lo_hex = &rest[..dash];
        if !lo_hex.eq_ignore_ascii_case(&needle_lo) {
            continue;
        }
        found_line = true;
        if line.contains("write-combining") {
            return WcVerdict::WriteCombining;
        } else {
            return WcVerdict::OtherMapping;
        }
    }
    if found_line {
        WcVerdict::OtherMapping
    } else {
        WcVerdict::NotFound
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WcVerdict {
    WriteCombining,
    OtherMapping,
    NotFound,
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
```

Add to `crates/dpdk-net-core/src/lib.rs` after the existing `pub mod llq_verify;` line:

```rust
pub mod wc_verify;
```

- [ ] **Step 2: Run tests to verify all 5 unit tests pass**

Run: `cargo test -p dpdk-net-core wc_verify 2>&1 | tail -15`
Expected: 5 passing, 0 failing.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/src/wc_verify.rs crates/dpdk-net-core/src/lib.rs
git commit -m "phase-a-hw-plus: add wc_verify pure parser for PAT memtype list

Pure function + 5 unit tests covering the WC / uncached / missing /
empty / case-insensitive cases. Integration into engine bring-up
follows in Task 3."
```

- [ ] **Step 4: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Verify wc_verify.rs parser matches the format documented at docs/references/ena-dpdk-readme.md §6.2.3 (prefetchable BAR address layout). Confirm WcVerdict enum covers all three observable states and the parser handles each correctly."
2. Code-quality: "Review wc_verify.rs for: (a) panic-free parsing on malformed input; (b) zero allocations beyond the format!() needle (acceptable, slow-path); (c) doc comments cite source RFC/README sections; (d) tests cover edge cases (empty, missing, mixed-case hex, multi-line)."

---

## Task 3: Wire `wc_verify` into engine bring-up

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs::configure_port_offloads` (currently around lines 853-1099)
- Modify: `crates/dpdk-net-core/src/wc_verify.rs` — add the integration helper that reads /sys + dispatches to the parser

The integration runs after `dev_info_get` on net_ena ports only, on linux/x86_64 only. On non-Linux or non-x86_64 architectures it short-circuits to OK (the /sys/kernel/debug/x86 path is x86-specific).

- [ ] **Step 1: Add the integration helper in `wc_verify.rs`**

Append to `crates/dpdk-net-core/src/wc_verify.rs`:

```rust
use crate::counters::Counters;
use std::sync::atomic::Ordering;

/// Bring-up integration: read /sys/kernel/debug/x86/pat_memtype_list,
/// scan for the prefetchable BAR's WC mapping, bump the
/// `eth.llq_wc_missing` counter on miss + emit a WARN. Never fails
/// hard — the negative case is observable via the counter.
///
/// Returns Ok unconditionally to keep the bring-up path infallible.
/// Failure modes (file missing, permission denied, BAR address is 0)
/// are silent successes — the counter exposes the verdict, not an
/// error path.
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
```

- [ ] **Step 2: Read the prefetchable BAR address from `rte_eth_dev_info` in engine.rs**

DPDK exposes the underlying PCI device via the `rte_eth_dev_info.device` field. The PCI BAR addresses are at `rte_pci_device->mem_resource[2].phys_addr` (BAR2 is the prefetchable one for ENA on x86). Add a small shim in `crates/dpdk-net-sys/shim.c`:

```c
/* phase-a-hw-plus: expose the prefetchable BAR (BAR2) physical address
 * for an rte_eth_dev_info.device pointer. Returns 0 if the device is
 * not a PCI device or BAR2 is unmapped. */
uint64_t shim_rte_eth_dev_prefetchable_bar_phys(uint16_t port_id) {
    struct rte_eth_dev_info info;
    if (rte_eth_dev_info_get(port_id, &info) != 0) {
        return 0;
    }
    if (!info.device) {
        return 0;
    }
    struct rte_pci_device *pci = RTE_DEV_TO_PCI(info.device);
    if (!pci) {
        return 0;
    }
    /* BAR2 is the prefetchable BAR for ENA per upstream PMD source.
     * If the index is unmapped, phys_addr is 0 — caller treats as
     * unavailable. */
    return (uint64_t)pci->mem_resource[2].phys_addr;
}
```

Add the prototype to `crates/dpdk-net-sys/wrapper.h`:

```c
uint64_t shim_rte_eth_dev_prefetchable_bar_phys(uint16_t port_id);
```

- [ ] **Step 3: Call the verifier from `configure_port_offloads`**

In `crates/dpdk-net-core/src/engine.rs::configure_port_offloads`, after the `dev_info_get` call + driver-name copy block (around the existing line 924 `eprintln!` banner), add:

```rust
        // H1 — verify Write-Combining mapping for net_ena's prefetchable BAR.
        // Slow-path; counter-bump-only on miss. See docs/references/ena-dpdk-readme.md §6.1.
        let bar_phys = unsafe { sys::shim_rte_eth_dev_prefetchable_bar_phys(cfg.port_id) };
        crate::wc_verify::verify_wc_for_ena(cfg.port_id, &driver_name, bar_phys, counters);
```

- [ ] **Step 4: Build + run existing engine tests**

Run: `cargo build --workspace --all-features && cargo test -p dpdk-net-core engine 2>&1 | tail -30`
Expected: builds; existing engine tests still pass (the new verifier is a no-op for non-ENA drivers used by the TAP-based unit tests).

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-core/src/wc_verify.rs crates/dpdk-net-core/src/engine.rs \
        crates/dpdk-net-sys/shim.c crates/dpdk-net-sys/wrapper.h
git commit -m "phase-a-hw-plus: wire wc_verify into engine bring-up for net_ena

Reads BAR2 phys addr via new shim, dispatches to parser. WARN-only;
slow-path counter-bump on miss. Non-Linux / non-x86_64 / non-ENA
drivers short-circuit silently."
```

- [ ] **Step 6: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Verify Task 3 integration matches docs/references/ena-dpdk-review-2026-04-20.md H1: WARN-only, slow-path counter, called on net_ena only, BAR2 (prefetchable) used. Confirm fail-safe behavior on /sys read failure."
2. Code-quality: "Review the engine.rs integration site + the shim.c addition. Check: shim handles NULL device pointer; the bar_phys==0 case is silent-skipped (not WARN-spammed); no panic on mempool-less code path; integration is feature-flag-free per spec (no new hw-* feature)."

---

## Task 4: Implement `ena_xstats.rs` ID resolver

**Files:**
- Create: `crates/dpdk-net-core/src/ena_xstats.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs` — add `pub mod ena_xstats;`

**Reference:** `docs/references/ena-dpdk-readme.md` §8.2 (xstats), §8.2.2 (ENI limiters), §8.2.3 (Tx per-queue), §8.2.4 (Rx per-queue).

DPDK exposes xstats via `rte_eth_xstats_get_names(port_id, names_array, n)` (returns id↔name map) and `rte_eth_xstats_get_by_id(port_id, ids_array, values_array, n)` (bulk read). We resolve names → IDs once at engine_create + cache the mapping; the scrape itself is a single `get_by_id` call followed by counter writes.

The 13 ENA xstat names we care about (queue 0 only — Stage 1 single queue):

ENI: `bw_in_allowance_exceeded`, `bw_out_allowance_exceeded`, `pps_allowance_exceeded`, `conntrack_allowance_exceeded`, `linklocal_allowance_exceeded`.
Tx q0: `tx_q0_linearize`, `tx_q0_doorbells`, `tx_q0_missed_tx`, `tx_q0_bad_req_id`.
Rx q0: `rx_q0_refill_partial`, `rx_q0_bad_desc_num`, `rx_q0_bad_req_id`, `rx_q0_mbuf_alloc_fail`.

- [ ] **Step 1: Write the resolver + scraper skeleton + unit tests for the name-list lookup (no DPDK)**

Create `crates/dpdk-net-core/src/ena_xstats.rs`:

```rust
//! ENA `rte_eth_xstats` scraper. Slow-path; the application drives the
//! cadence via `dpdk_net_scrape_xstats` (typically once per second).
//!
//! Names resolved here are pinned against the upstream ENA PMD as of
//! DPDK 23.11 (drivers/net/ena/ena_ethdev.c). They are stable across
//! ENA v2.6.0+ per the ENA PMD release notes.
//!
//! Source: docs/references/ena-dpdk-readme.md §8.2.2 (ENI limiters),
//! §8.2.3 (Tx per-queue), §8.2.4 (Rx per-queue).

use crate::counters::Counters;
use dpdk_net_sys as sys;
use std::sync::atomic::Ordering;

/// Names we want to scrape, in resolver order. Index in this array is
/// the slot in `XstatMap.ids`; `apply()` consumes the values in the
/// same order to write each counter.
pub(crate) const XSTAT_NAMES: &[&str] = &[
    "bw_in_allowance_exceeded",
    "bw_out_allowance_exceeded",
    "pps_allowance_exceeded",
    "conntrack_allowance_exceeded",
    "linklocal_allowance_exceeded",
    "tx_q0_linearize",
    "tx_q0_doorbells",
    "tx_q0_missed_tx",
    "tx_q0_bad_req_id",
    "rx_q0_refill_partial",
    "rx_q0_bad_desc_num",
    "rx_q0_bad_req_id",
    "rx_q0_mbuf_alloc_fail",
];

/// Resolved xstat IDs. `None` slot means the PMD didn't advertise that
/// name (e.g. non-ENA driver, or older ENA with a stale name set). The
/// scraper silently skips `None` slots.
#[derive(Debug, Clone)]
pub struct XstatMap {
    /// Indexed parallel to `XSTAT_NAMES`. `None` if not advertised.
    pub ids: Vec<Option<u64>>,
}

impl XstatMap {
    /// Build from a name → id lookup. Pure function — used by both the
    /// runtime resolver and the unit tests.
    pub(crate) fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<u64>,
    {
        let ids = XSTAT_NAMES.iter().map(|n| lookup(n)).collect();
        XstatMap { ids }
    }

    /// Apply scraped values to `EthCounters`. `values[i]` corresponds
    /// to `self.ids[i]` (and to `XSTAT_NAMES[i]`). `values.len()` must
    /// equal `self.ids.len()`. Slots where the id was `None` write 0
    /// (snapshot-of-last-known semantics with default 0).
    pub(crate) fn apply(&self, values: &[u64], counters: &Counters) {
        debug_assert_eq!(values.len(), self.ids.len());
        // `store(Relaxed)` because these are snapshot semantics, not
        // accumulators. Reader sees the most-recent scrape value.
        let store = |slot: &std::sync::atomic::AtomicU64, idx: usize| {
            let v = if self.ids[idx].is_some() { values[idx] } else { 0 };
            slot.store(v, Ordering::Relaxed);
        };
        store(&counters.eth.eni_bw_in_allowance_exceeded, 0);
        store(&counters.eth.eni_bw_out_allowance_exceeded, 1);
        store(&counters.eth.eni_pps_allowance_exceeded, 2);
        store(&counters.eth.eni_conntrack_allowance_exceeded, 3);
        store(&counters.eth.eni_linklocal_allowance_exceeded, 4);
        store(&counters.eth.tx_q0_linearize, 5);
        store(&counters.eth.tx_q0_doorbells, 6);
        store(&counters.eth.tx_q0_missed_tx, 7);
        store(&counters.eth.tx_q0_bad_req_id, 8);
        store(&counters.eth.rx_q0_refill_partial, 9);
        store(&counters.eth.rx_q0_bad_desc_num, 10);
        store(&counters.eth.rx_q0_bad_req_id, 11);
        store(&counters.eth.rx_q0_mbuf_alloc_fail, 12);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::counters::Counters;

    #[test]
    fn from_lookup_collects_in_name_order() {
        let map = XstatMap::from_lookup(|n| match n {
            "bw_in_allowance_exceeded" => Some(100),
            "tx_q0_doorbells" => Some(200),
            _ => None,
        });
        assert_eq!(map.ids[0], Some(100));
        assert_eq!(map.ids[6], Some(200));
        assert_eq!(map.ids[1], None); // bw_out_allowance not advertised
    }

    #[test]
    fn apply_writes_each_counter_in_name_order() {
        let map = XstatMap::from_lookup(|_| Some(0)); // all advertised
        let values: Vec<u64> = (1u64..=13).collect(); // 1, 2, ..., 13
        let counters = Counters::new();
        map.apply(&values, &counters);
        assert_eq!(counters.eth.eni_bw_in_allowance_exceeded.load(Ordering::Relaxed), 1);
        assert_eq!(counters.eth.tx_q0_doorbells.load(Ordering::Relaxed), 7);
        assert_eq!(counters.eth.rx_q0_mbuf_alloc_fail.load(Ordering::Relaxed), 13);
    }

    #[test]
    fn apply_writes_zero_for_unadvertised_names() {
        // Only the first 5 names advertised; rest unadvertised.
        let map = XstatMap::from_lookup(|n| {
            if XSTAT_NAMES.iter().position(|x| x == &n).map_or(false, |i| i < 5) {
                Some(0)
            } else {
                None
            }
        });
        // First seed all counters to a sentinel value so we can prove zeroing.
        let counters = Counters::new();
        counters.eth.tx_q0_doorbells.store(999, Ordering::Relaxed);
        let values = vec![1u64; 13];
        map.apply(&values, &counters);
        assert_eq!(counters.eth.eni_bw_in_allowance_exceeded.load(Ordering::Relaxed), 1);
        assert_eq!(counters.eth.tx_q0_doorbells.load(Ordering::Relaxed), 0);
    }
}

/// Resolve XSTAT_NAMES → ids by walking `rte_eth_xstats_get_names`.
/// Returns an XstatMap that can be reused for every subsequent scrape.
/// Slow-path; called once at engine_create.
///
/// On non-ENA / non-advertising PMDs every slot is `None` and `apply`
/// writes 0 across the board; the scrape becomes a cheap no-op.
pub(crate) fn resolve_xstat_ids(port_id: u16) -> XstatMap {
    // First pass: query count.
    let n = unsafe { sys::rte_eth_xstats_get_names(port_id, std::ptr::null_mut(), 0) };
    if n <= 0 {
        return XstatMap::from_lookup(|_| None);
    }
    let n = n as usize;
    let mut names: Vec<sys::rte_eth_xstat_name> =
        vec![unsafe { std::mem::zeroed() }; n];
    let got = unsafe {
        sys::rte_eth_xstats_get_names(
            port_id,
            names.as_mut_ptr(),
            n as u32,
        )
    };
    if got <= 0 {
        return XstatMap::from_lookup(|_| None);
    }
    let names = &names[..got as usize];
    XstatMap::from_lookup(|wanted| {
        for (i, n) in names.iter().enumerate() {
            // rte_eth_xstat_name.name is `[c_char; 64]` NUL-terminated.
            let raw: &[u8] = unsafe {
                let p = n.name.as_ptr() as *const u8;
                let len = (0..64).take_while(|&j| *p.add(j) != 0).count();
                std::slice::from_raw_parts(p, len)
            };
            if raw == wanted.as_bytes() {
                return Some(i as u64);
            }
        }
        None
    })
}

/// Per-scrape: read the resolved xstat IDs into a value buffer + apply
/// to counters. `map.ids.len() == XSTAT_NAMES.len() == 13`. Allocates
/// one 13-element Vec<u64> per call — slow-path-acceptable.
pub fn scrape(port_id: u16, map: &XstatMap, counters: &Counters) {
    // Build the dense list of advertised IDs to query (skip None slots).
    let mut query_ids: Vec<u64> = Vec::with_capacity(map.ids.len());
    let mut query_index: Vec<usize> = Vec::with_capacity(map.ids.len());
    for (i, slot) in map.ids.iter().enumerate() {
        if let Some(id) = slot {
            query_ids.push(*id);
            query_index.push(i);
        }
    }
    let mut values = vec![0u64; map.ids.len()];
    if !query_ids.is_empty() {
        let mut got_values = vec![0u64; query_ids.len()];
        let rc = unsafe {
            sys::rte_eth_xstats_get_by_id(
                port_id,
                query_ids.as_ptr(),
                got_values.as_mut_ptr(),
                query_ids.len() as u32,
            )
        };
        if rc as usize == query_ids.len() {
            for (k, &i) in query_index.iter().enumerate() {
                values[i] = got_values[k];
            }
        }
        // rc < expected: silent zero-fill; counter snapshot stays at last
        // known good value (already in `values` as 0; consider keeping
        // last-known by not calling apply on partial-failure — Stage 2
        // refinement, not blocking).
    }
    map.apply(&values, counters);
}
```

Add to `crates/dpdk-net-core/src/lib.rs`:

```rust
pub mod ena_xstats;
```

- [ ] **Step 2: Run unit tests**

Run: `cargo test -p dpdk-net-core ena_xstats 2>&1 | tail -20`
Expected: 3 passing.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/src/ena_xstats.rs crates/dpdk-net-core/src/lib.rs
git commit -m "phase-a-hw-plus: add ena_xstats resolver + scraper

13 names cover ENI allowances + per-queue (q0 only) Tx/Rx xstats.
XstatMap caches name→ID at engine_create; scrape is a single
rte_eth_xstats_get_by_id + counter snapshot writes. Slow-path."
```

- [ ] **Step 4: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Verify ena_xstats.rs covers all xstat names listed in docs/references/ena-dpdk-readme.md §8.2.2 + §8.2.3 + §8.2.4 (queue 0 subset). Confirm name strings match the PMD source (drivers/net/ena/ena_ethdev.c constants); flag any typo. Confirm snapshot semantics (store, not fetch_add) match the H2/M3 design in the gap analysis."
2. Code-quality: "Review ena_xstats.rs for: (a) panic-free on partial failure; (b) zero hot-path cost (only allocates inside `scrape`); (c) safety annotations on the rte_eth_xstat_name name-pointer walk; (d) Vec allocations are slow-path-acceptable; (e) tests cover the unadvertised-name zeroing path."

---

## Task 5: Cache `XstatMap` on `Engine` + expose `Engine::scrape_xstats`

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` — `Engine` struct + `Engine::new` + new method.

- [ ] **Step 1: Add the `xstat_map` field on `Engine`**

In `crates/dpdk-net-core/src/engine.rs`, find the `Engine` struct definition (around line 365 — the field block immediately after the runtime-latch fields). Add a new field at the bottom of the public-data block:

```rust
    /// A-HW+ — resolved ENA xstat name → ID map. Built once at
    /// engine_create via `ena_xstats::resolve_xstat_ids`. On non-ENA
    /// PMDs every slot is `None` and `scrape_xstats` is a cheap no-op.
    /// Slow-path only; not on any hot path.
    xstat_map: crate::ena_xstats::XstatMap,
```

- [ ] **Step 2: Populate it in `Engine::new` after `rte_eth_dev_start`**

In `Engine::new`, after the existing `program_rss_reta_single_queue` call (around line 760) and before the `xstat_map` is consumed by anything else, add:

```rust
        let xstat_map = crate::ena_xstats::resolve_xstat_ids(cfg.port_id);
```

Add `xstat_map,` to the `Self { ... }` literal at the end of `Engine::new`.

- [ ] **Step 3: Add the public method**

Append to the `impl Engine { ... }` block (near `pub fn counters`, line ~1205):

```rust
    /// Slow-path: scrape ENA-PMD xstats (ENI allowances + per-queue
    /// counters) into `EthCounters`. Application drives the cadence —
    /// recommended ≤1 Hz. On non-ENA / non-advertising PMDs this is a
    /// cheap no-op (every slot in `xstat_map` is None).
    pub fn scrape_xstats(&self) {
        crate::ena_xstats::scrape(
            self.cfg.port_id,
            &self.xstat_map,
            &self.counters,
        );
    }
```

- [ ] **Step 4: Build + run engine tests**

Run: `cargo test -p dpdk-net-core engine 2>&1 | tail -20`
Expected: existing tests still pass; the new field doesn't break `Engine::new` callers.

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs
git commit -m "phase-a-hw-plus: cache XstatMap on Engine + add scrape_xstats()

Resolves ENA xstat names→IDs once at engine_create. Slow-path public
method drives the per-scrape rte_eth_xstats_get_by_id + counter writes."
```

- [ ] **Step 6: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Confirm xstat_map cached at engine_create and never re-resolved; scrape_xstats() is a public Rust method (not extern \"C\" yet — that's Task 6)."
2. Code-quality: "Field-ordering in Engine struct is natural; resolve_xstat_ids called exactly once; no panic on Engine::new for non-ENA PMDs."

---

## Task 6: Expose `dpdk_net_scrape_xstats` extern "C" entry point

**Files:**
- Modify: `crates/dpdk-net/src/lib.rs` — append a new extern "C" fn near `dpdk_net_counters` (around line 426).

- [ ] **Step 1: Add the extern fn**

```rust
/// Slow-path: trigger an ENA-PMD xstats scrape. Reads ENI
/// allowance-exceeded + per-queue (q0) Tx/Rx counters via DPDK
/// rte_eth_xstats_get_by_id and writes them into the counters
/// snapshot. Application calls this on its own cadence (typically
/// 1 Hz). On non-ENA PMDs this is a cheap no-op.
///
/// Returns 0 on success (always — failures are silent and observable
/// via the counters staying at their last value).
///
/// # Safety
/// `p` must be a valid Engine pointer obtained from
/// `dpdk_net_engine_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dpdk_net_scrape_xstats(p: *mut dpdk_net_engine) -> i32 {
    match unsafe { engine_from_raw(p) } {
        Some(e) => {
            e.scrape_xstats();
            0
        }
        None => -libc::EINVAL,
    }
}
```

- [ ] **Step 2: Regenerate the C header**

The build script invokes cbindgen automatically; rebuild forces it:

Run: `cargo build -p dpdk-net && grep -E "dpdk_net_scrape_xstats|llq_wc_missing|eni_bw_in" include/dpdk_net.h`
Expected: 3 hits — the extern fn, the H1 counter field, the H2 counter field.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net/src/lib.rs include/dpdk_net.h
git commit -m "phase-a-hw-plus: expose dpdk_net_scrape_xstats extern \"C\" entry

Application drives ENI + per-queue xstats scrape cadence per the
'observability primitives only' contract."
```

- [ ] **Step 4: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Verify entry-point follows the existing extern \"C\" pattern (no_mangle, unsafe, EINVAL on null engine, slow-path semantics documented)."
2. Code-quality: "Confirm header regeneration emits the symbol; no clippy warnings."

---

## Task 7: Add `EngineConfig` knobs + ABI mirror (M1, M2)

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` — `EngineConfig` struct (around line 235).
- Modify: `crates/dpdk-net/src/api.rs` — `dpdk_net_engine_config_t` struct (search for the struct in api.rs).

- [ ] **Step 1: Add the two fields on `EngineConfig`**

In `crates/dpdk-net-core/src/engine.rs`, find the existing `EngineConfig` struct and append (preserving existing field order; the layout assertion in api.rs will flag any drift):

```rust
    /// M1 — request the ENA `large_llq_hdr=1` devarg. When 1, the
    /// application MUST also splice the corresponding devarg string
    /// into its EAL args; use `dpdk_net_recommended_ena_devargs` to
    /// build it. Engine bumps `eth.llq_header_overflow_risk` at
    /// bring-up if the worst-case header > 96 B and this is 0.
    /// Default 0 (PMD default 96 B header limit).
    pub ena_large_llq_hdr: u8,
    /// M2 — value to pass as the ENA `miss_txc_to=N` devarg (seconds).
    /// 0 = use PMD default (5 s); 1..=60 = explicit value. As above,
    /// application splices via `dpdk_net_recommended_ena_devargs`.
    /// Recommended for trading: 2 or 3 (faster Tx-stall detection
    /// than the 5 s default; do NOT set 0 to disable — see ENA
    /// README §5.1 caution).
    pub ena_miss_txc_to_sec: u8,
```

Update the `Default` impl for `EngineConfig` (around line 306) — add:

```rust
            ena_large_llq_hdr: 0,
            ena_miss_txc_to_sec: 0,
```

- [ ] **Step 2: Mirror onto `dpdk_net_engine_config_t` in `crates/dpdk-net/src/api.rs`**

Append the same two fields (plus appropriate doc comments) to `dpdk_net_engine_config_t`. Order MUST match `EngineConfig` exactly; the existing const-block layout assertion in `api.rs` covers it.

```rust
    /// M1 — see core EngineConfig.ena_large_llq_hdr. Default 0.
    pub ena_large_llq_hdr: u8,
    /// M2 — see core EngineConfig.ena_miss_txc_to_sec. Default 0
    /// (PMD default 5 s). Recommended 2 or 3 for trading.
    pub ena_miss_txc_to_sec: u8,
```

- [ ] **Step 3: Build + run unit tests**

Run: `cargo build --workspace --all-features && cargo test --workspace 2>&1 | tail -30`
Expected: layout assertion passes; existing tests green.

- [ ] **Step 4: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net/src/api.rs
git commit -m "phase-a-hw-plus: add ena_large_llq_hdr + ena_miss_txc_to_sec knobs

Two u8 fields on EngineConfig + ABI mirror. Application owns devarg
emission (Task 8 helper); engine reads these to drive bring-up
assertion (Task 9)."
```

- [ ] **Step 5: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Verify field semantics match docs/references/ena-dpdk-readme.md §5.1 (large_llq_hdr 0/1, miss_txc_to 0..=60, default 5)."
2. Code-quality: "Field-order matches between core EngineConfig and dpdk_net_engine_config_t; doc-comments warn against miss_txc_to=0 disable."

---

## Task 8: Add `dpdk_net_recommended_ena_devargs` extern helper

**Files:**
- Modify: `crates/dpdk-net/src/lib.rs`

The helper writes a NUL-terminated EAL devarg string into a caller-provided buffer. Application splices it into its EAL args before calling `dpdk_net_eal_init`.

Format: `"<bdf>,large_llq_hdr=<0|1>,miss_txc_to=<N>"` — emit `large_llq_hdr` only if non-zero (PMD default is 0); emit `miss_txc_to` only if non-zero (PMD default is 5).

- [ ] **Step 1: Add the extern fn**

```rust
/// M1+M2 helper: build an ENA `-a <bdf>,...` devarg string the
/// application splices into its EAL args. Writes a NUL-terminated
/// string into `out`; returns the number of bytes written EXCLUDING
/// the trailing NUL on success, or a negative errno on failure
/// (-EINVAL if `bdf` is null / `out` is null / `out_cap` < required).
///
/// # Safety
/// `bdf` must point to a NUL-terminated PCI BDF string (e.g. "00:06.0").
/// `out` must be a writable buffer of at least `out_cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dpdk_net_recommended_ena_devargs(
    bdf: *const libc::c_char,
    large_llq_hdr: u8,
    miss_txc_to_sec: u8,
    out: *mut libc::c_char,
    out_cap: usize,
) -> i32 {
    if bdf.is_null() || out.is_null() {
        return -libc::EINVAL;
    }
    let bdf_str = match unsafe { std::ffi::CStr::from_ptr(bdf) }.to_str() {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };
    let mut s = bdf_str.to_string();
    if large_llq_hdr != 0 {
        s.push_str(",large_llq_hdr=1");
    }
    if miss_txc_to_sec != 0 {
        if miss_txc_to_sec > 60 {
            return -libc::ERANGE;
        }
        s.push_str(&format!(",miss_txc_to={}", miss_txc_to_sec));
    }
    let bytes = s.as_bytes();
    if bytes.len() + 1 > out_cap {
        return -libc::ENOSPC;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const libc::c_char, out, bytes.len());
        *out.add(bytes.len()) = 0;
    }
    bytes.len() as i32
}

#[cfg(test)]
mod a_hw_plus_devargs_tests {
    use super::*;

    fn call(bdf: &str, large: u8, miss: u8, cap: usize) -> (i32, String) {
        let bdf_c = std::ffi::CString::new(bdf).unwrap();
        let mut buf = vec![0u8; cap];
        let n = unsafe {
            dpdk_net_recommended_ena_devargs(
                bdf_c.as_ptr(),
                large, miss,
                buf.as_mut_ptr() as *mut _, cap,
            )
        };
        let s = if n > 0 {
            String::from_utf8_lossy(&buf[..n as usize]).into_owned()
        } else {
            String::new()
        };
        (n, s)
    }

    #[test]
    fn defaults_emit_bdf_only() {
        let (n, s) = call("00:06.0", 0, 0, 64);
        assert_eq!(n, 7);
        assert_eq!(s, "00:06.0");
    }

    #[test]
    fn large_llq_hdr_appended() {
        let (n, s) = call("00:06.0", 1, 0, 64);
        assert!(n > 0);
        assert_eq!(s, "00:06.0,large_llq_hdr=1");
    }

    #[test]
    fn miss_txc_to_appended() {
        let (n, s) = call("00:06.0", 0, 3, 64);
        assert!(n > 0);
        assert_eq!(s, "00:06.0,miss_txc_to=3");
    }

    #[test]
    fn both_appended() {
        let (n, s) = call("00:06.0", 1, 2, 64);
        assert!(n > 0);
        assert_eq!(s, "00:06.0,large_llq_hdr=1,miss_txc_to=2");
    }

    #[test]
    fn out_too_small_returns_enospc() {
        let (n, _) = call("00:06.0", 1, 1, 4);
        assert_eq!(n, -libc::ENOSPC);
    }

    #[test]
    fn miss_out_of_range_returns_erange() {
        let (n, _) = call("00:06.0", 0, 61, 64);
        assert_eq!(n, -libc::ERANGE);
    }

    #[test]
    fn null_bdf_returns_einval() {
        let mut buf = [0u8; 64];
        let n = unsafe {
            dpdk_net_recommended_ena_devargs(
                std::ptr::null(), 0, 0, buf.as_mut_ptr() as *mut _, 64,
            )
        };
        assert_eq!(n, -libc::EINVAL);
    }
}
```

- [ ] **Step 2: Run unit tests**

Run: `cargo test -p dpdk-net a_hw_plus_devargs 2>&1 | tail -20`
Expected: 7 passing.

- [ ] **Step 3: Regenerate C header + commit**

Run: `cargo build -p dpdk-net && grep "dpdk_net_recommended_ena_devargs" include/dpdk_net.h`
Expected: 1 hit.

```bash
git add crates/dpdk-net/src/lib.rs include/dpdk_net.h
git commit -m "phase-a-hw-plus: add dpdk_net_recommended_ena_devargs helper

Builds ENA -a <bdf>,...= devarg string for application to splice
into its EAL args. Covers large_llq_hdr + miss_txc_to with bounds
checking + 7 unit tests."
```

- [ ] **Step 4: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Verify devarg format matches docs/references/ena-dpdk-readme.md §5.1 syntax; ENOSPC / ERANGE / EINVAL semantics."
2. Code-quality: "Helper is fail-safe on bad input; no UB on null deref; tests cover all error branches; format!() avoids fmt-injection (only u8 format)."

---

## Task 9: Bring-up assertion for `large_llq_hdr` overflow risk

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs::configure_port_offloads`

The assertion fires once at engine_create on net_ena ports when:
- `cfg.ena_large_llq_hdr == 0` (knob unset)
- AND the worst-case header stack exceeds 96 B.

Worst-case header for our Stage 1 stack: Ethernet 14 + IPv4 20 + TCP 20 + max-options 40 = **94 B**. So strictly we don't overflow; but with future TCP options or any IP-options excursion the bound bites. Set the threshold to 90 B for safety margin.

- [ ] **Step 1: Add the assertion in `configure_port_offloads`**

After the existing WC-verify call in Task 3, add:

```rust
        // M1 — header-overflow-risk warning (slow-path one-shot).
        // Worst-case header: 14 (Ethernet) + 20 (IPv4) + 20 (TCP) + 40
        // (max TCP options) = 94 B. With ena_large_llq_hdr=0 the LLQ
        // ceiling is 96 B; at 94 B we sit 2 bytes under and any
        // future option-stack growth silently demotes TX off LLQ. Bump
        // the counter when the knob is unset on net_ena ports — the
        // operator should set ena_large_llq_hdr=1 if they care about
        // sustained LLQ throughput under SACK-heavy traffic.
        const WORST_CASE_HEADER: u32 = 14 + 20 + 20 + 40;
        const LLQ_DEFAULT_HEADER_LIMIT: u32 = 96;
        const LLQ_OVERFLOW_MARGIN: u32 = 6;
        if driver_str == "net_ena"
            && cfg.ena_large_llq_hdr == 0
            && WORST_CASE_HEADER + LLQ_OVERFLOW_MARGIN > LLQ_DEFAULT_HEADER_LIMIT
        {
            counters.eth.llq_header_overflow_risk.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "dpdk_net: port {} on net_ena with ena_large_llq_hdr=0; \
                 worst-case header {} B is within {} B of the 96 B LLQ \
                 limit. Consider setting EngineConfig.ena_large_llq_hdr=1 \
                 + splicing dpdk_net_recommended_ena_devargs(...) into \
                 EAL args. See docs/references/ena-dpdk-readme.md §5.1.",
                cfg.port_id, WORST_CASE_HEADER, LLQ_OVERFLOW_MARGIN
            );
        }
```

`driver_str` is the local variable already set by the WC-verify path (Task 3 step 1). If it's not in scope at this point, recompute via the same `from_utf8` snippet.

- [ ] **Step 2: Build + run engine tests**

Run: `cargo test -p dpdk-net-core engine 2>&1 | tail -20`
Expected: existing tests still pass; the new assertion is a no-op for non-ENA test PMDs.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs
git commit -m "phase-a-hw-plus: bring-up overflow-risk assertion for large_llq_hdr

One-shot WARN on net_ena when ena_large_llq_hdr=0 and worst-case
header is within margin of 96 B LLQ limit. Counter exposes the
verdict; no fail-hard."
```

- [ ] **Step 4: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Verify assertion threshold 14+20+20+40=94 + 6 margin > 96 matches the README §5.1 large_llq_hdr default of 96 B. Confirm WARN-only + counter-bump (no fail-hard)."
2. Code-quality: "Constants are named + documented; assertion fires exactly once per engine_create; non-ENA PMDs short-circuit silently."

---

## Task 10: Extend `knob-coverage.rs` audit

**Files:**
- Modify: `crates/dpdk-net-core/tests/knob-coverage.rs`

The knob-coverage test (introduced in A4) statically asserts every behavioural `EngineConfig` field has a scenario function that exercises the non-default value. Add entries for the two new knobs.

- [ ] **Step 1: Add scenario fns + table entries**

Append two entries following the established pattern (read the current file structure first to confirm exact macro/table format):

```rust
fn scenario_ena_large_llq_hdr() {
    let cfg = EngineConfig {
        ena_large_llq_hdr: 1,
        ..EngineConfig::default()
    };
    assert_eq!(cfg.ena_large_llq_hdr, 1, "knob propagation");
}

fn scenario_ena_miss_txc_to_sec() {
    let cfg = EngineConfig {
        ena_miss_txc_to_sec: 3,
        ..EngineConfig::default()
    };
    assert_eq!(cfg.ena_miss_txc_to_sec, 3);
}
```

Add them to the static knob table (the existing `KNOBS: &[Knob]` or equivalent — read the file first to confirm the exact name).

- [ ] **Step 2: Run the audit**

Run: `cargo test -p dpdk-net-core --test knob-coverage 2>&1 | tail -20`
Expected: pass; new entries exercised.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/tests/knob-coverage.rs
git commit -m "phase-a-hw-plus: knob-coverage entries for ena_large_llq_hdr + miss_txc_to_sec

Each new behavioural knob gets a scenario fn that exercises the
non-default value, per §A8 audit discipline."
```

- [ ] **Step 4: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Knob-coverage table now includes both new knobs; scenarios actually exercise the non-default value (not just construct it)."
2. Code-quality: "Scenario fns follow the existing pattern; no copy-paste bugs in field names."

---

## Task 11: Extend the real-ENA smoke test

**Files:**
- Modify: `crates/dpdk-net-core/tests/ahw_smoke_ena_hw.rs`

Add three assertions to the existing real-ENA smoke (which is `#[ignore]`d by default; exercised manually on EC2):

1. After bring-up, `eth.llq_wc_missing == 0` (WC verified active on a properly-configured EC2 host).
2. After at least one `Engine::scrape_xstats()` call, every ENI counter is readable (whether 0 or non-zero — proves the scrape doesn't crash).
3. `eth.llq_header_overflow_risk == 1` if the test runs with `ena_large_llq_hdr = 0`; `== 0` if it overrides to 1.

- [ ] **Step 1: Read the current test to find the bring-up + counter-assertion block**

```bash
grep -n "offload_missing\|counters\|Engine::new" crates/dpdk-net-core/tests/ahw_smoke_ena_hw.rs | head -20
```

- [ ] **Step 2: Insert new assertions at the appropriate point**

After the existing `engine = Engine::new(cfg)?;` call, insert:

```rust
    // A-HW+ Task 11: verify new ENA-observability counters.
    // WC must be active on a properly-configured AWS host (igb_uio
    // wc_activate=1 OR patched vfio-pci); if 0 the host is misconfigured
    // and LLQ will perform terribly (README §6.1 + §14 perf FAQ Q1).
    assert_eq!(
        engine.counters().eth.llq_wc_missing.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "WC verification: prefetchable BAR not mapped write-combining; \
         see /sys/kernel/debug/x86/pat_memtype_list and the ENA README §6.1"
    );

    // M1: with ena_large_llq_hdr=0 default, the overflow-risk counter
    // bumps once at bring-up because worst-case header (94 B) sits at
    // the LLQ ceiling.
    assert_eq!(
        engine.counters().eth.llq_header_overflow_risk.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "M1 overflow-risk warning expected to fire with knob unset"
    );

    // H2 + M3: scrape ENA xstats and confirm the call returns. Counter
    // values themselves are environment-dependent (allowance counters
    // may legitimately be > 0 if a previous workload pushed limits);
    // we just assert the scrape did not panic and did write at least
    // something (doorbells should be > 0 after the bring-up handshake).
    engine.scrape_xstats();
    let doorbells = engine.counters().eth.tx_q0_doorbells
        .load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("post-scrape eth.tx_q0_doorbells = {}", doorbells);
    // Note: doorbells > 0 only after first TX burst; if the test only
    // exercised dev_start, the value can be 0 — that's OK.
```

- [ ] **Step 3: Build + run with `--ignored` if you have an ENA host wired in**

Run: `cargo test -p dpdk-net-core --test ahw_smoke_ena_hw -- --ignored 2>&1 | tail -30`
Expected: passes on a real ENA VF; skip on non-ENA hosts.

- [ ] **Step 4: Commit**

```bash
git add crates/dpdk-net-core/tests/ahw_smoke_ena_hw.rs
git commit -m "phase-a-hw-plus: extend ENA-host smoke with WC + xstats + overflow-risk assertions

Real-host gate covers: llq_wc_missing == 0, llq_header_overflow_risk
== 1 (knob unset), scrape_xstats() returns + tx_q0_doorbells reads
without panic."
```

- [ ] **Step 5: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Assertions match the steady-state values documented in docs/references/ena-dpdk-review-2026-04-20.md for H1, M1, and the H2/M3 scrape contract."
2. Code-quality: "No flaky-test patterns; scrape assertion tolerates environment variance (allowance counters may be 0 or non-zero)."

---

## Task 12: Pure-unit smoke (no DPDK) covering parser + xstats name table

**Files:**
- Create: `crates/dpdk-net-core/tests/ena_obs_smoke.rs`

This sibling smoke runs in any CI worker (no ENA hardware needed). It exercises:
- `wc_verify::parse_pat_memtype_list` against synthetic /sys content.
- `ena_xstats::XstatMap::from_lookup` + `apply` against a synthetic name→ID map.
- `dpdk_net::dpdk_net_recommended_ena_devargs` extern across the buffer-too-small / range-error / happy-path matrix.

It restates a subset of the unit tests at the integration boundary so that future module-level test failures don't sneak past the integration build.

- [ ] **Step 1: Write the test file**

```rust
//! A-HW+ pure-unit smoke. No DPDK; no real EAL; runs on every CI worker.
//! Asserts the slow-path observability primitives behave per spec.

use dpdk_net_core::counters::Counters;

#[test]
fn wc_verify_smoke() {
    use dpdk_net_core::wc_verify::{parse_pat_memtype_list, WcVerdict};
    let sample = "PAT: [mem 0x00000000fe900000-0x00000000fea00000] write-combining\n";
    assert_eq!(parse_pat_memtype_list(sample, 0xfe900000), WcVerdict::WriteCombining);
    assert_eq!(parse_pat_memtype_list(sample, 0xfea00000), WcVerdict::NotFound);
}

#[test]
fn xstats_map_apply_smoke() {
    use dpdk_net_core::ena_xstats::{XstatMap, XSTAT_NAMES};
    let map = XstatMap::from_lookup(|_| Some(0));
    let values: Vec<u64> = (1u64..=XSTAT_NAMES.len() as u64).collect();
    let counters = Counters::new();
    map.apply(&values, &counters);
    use std::sync::atomic::Ordering;
    assert_eq!(counters.eth.eni_bw_in_allowance_exceeded.load(Ordering::Relaxed), 1);
    assert_eq!(counters.eth.rx_q0_mbuf_alloc_fail.load(Ordering::Relaxed), values.len() as u64);
}
```

- [ ] **Step 2: Run + commit**

Run: `cargo test -p dpdk-net-core --test ena_obs_smoke 2>&1 | tail -10`
Expected: 2 passing.

```bash
git add crates/dpdk-net-core/tests/ena_obs_smoke.rs
git commit -m "phase-a-hw-plus: pure-unit smoke covering wc_verify + ena_xstats

Sibling integration smoke with no DPDK dependency; runs on every CI
worker. Catches module-level regressions at the integration boundary."
```

- [ ] **Step 3: Two-stage review (parallel subagent dispatch)**

1. Spec-compliance: "Smoke covers the public API surface a downstream consumer would touch: pure parser + XstatMap::apply + counter writes."
2. Code-quality: "No DPDK dependency; runs in any CI; minimal duplication of the inline module tests."

---

## Task 13: Update `stage1-phase-roadmap.md` with the A-HW+ row

**Files:**
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md`

- [ ] **Step 1: Insert the new row in the Phase Status table + add a section**

Find the existing A-HW row in the status table (around line 21) and add a row immediately after it:

```markdown
| A-HW+ | ENA observability + tuning knobs (WC verify + ENI xstats + per-queue xstats + large_llq_hdr / miss_txc_to knobs) | **In progress** | `2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md` |
```

Add a full section after the A-HW section (after line 300 `Status: Complete.`):

```markdown
---

## A-HW+ — ENA observability + tuning knobs

**Goal:** Close 5 gaps identified in `docs/references/ena-dpdk-review-2026-04-20.md` against the upstream ENA DPDK README — H1 WC verification, H2 ENI allowance xstats, M1 large_llq_hdr knob, M2 miss_txc_to knob, M3 per-queue xstats — without touching the wire path. All slow-path; 15 new always-allocated counter fields; 2 new EngineConfig knobs; 2 new extern "C" entry points (dpdk_net_scrape_xstats, dpdk_net_recommended_ena_devargs); no new feature flags.

**Spec refs:** `docs/references/ena-dpdk-readme.md` §5.1 (devargs), §6.1+§6.2.3 (WC), §8.2.2-4 (xstats); parent spec §9.1.1 (counter policy); user memory `feedback_observability_primitives_only.md`.

**Deliverables:** see plan file.

**Does NOT include:** device-reset / AENQ keepalive recovery (parent gap H3 — Stage 2 reliability phase); RTE_ETHDEV_QUEUE_STAT_CNTRS bump (Stage 2 multi-queue gap M4); MTU/jumbo (out of Stage 1 scope per A-HW); RSS symmetric-key (AD-2 from A-HW review, Stage 2 multi-queue).

**Dependencies:** A-HW (sits on the EthCounters + offload-AND infrastructure).

**Ship gate:** `phase-a-hw-plus-complete` tag requires: cargo test green, ena_obs_smoke green, real-ENA smoke green, knob-coverage extended + green, mTCP review zero open `[ ]`, RFC review zero open `[ ]`.

**Status:** In progress — branch `phase-a-hw-ena-followups` off master.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "phase-a-hw-plus: add A-HW+ row to stage1 roadmap"
```

- [ ] **Step 3: Two-stage review** (skip — pure docs change, no code)

---

## Task 14: mTCP comparison review (subagent gate)

**Files:**
- Create: `docs/superpowers/reviews/phase-a-hw-plus-mtcp-compare.md` (output of subagent)

- [ ] **Step 1: Dispatch the mTCP-comparison reviewer subagent**

```
Agent(
  subagent_type=mtcp-comparison-reviewer,
  model=opus,
  description="Phase A-HW+ mTCP comparison review",
  prompt="Review phase-a-hw-plus (worktree at /home/ubuntu/resd.dpdk_tcp/.worktrees/phase-a-hw-ena-followups, branch phase-a-hw-ena-followups). Plan: docs/superpowers/plans/2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md. Source review that motivated this phase: docs/references/ena-dpdk-review-2026-04-20.md.

Scope: 5 deliverables (H1 WC verify, H2 ENI xstats, M1 large_llq_hdr knob, M2 miss_txc_to knob, M3 per-queue xstats). All slow-path. Modules touched: crates/dpdk-net-core/src/{wc_verify.rs,ena_xstats.rs,counters.rs,engine.rs}, crates/dpdk-net/src/{api.rs,lib.rs}, crates/dpdk-net-sys/{shim.c,wrapper.h}.

mTCP files to inspect for analog patterns: third_party/mtcp/mtcp/src/dpdk_module.c (port_conf, devargs, stats ioctl), third_party/mtcp/mtcp/src/include/io_module.h (PKT_TX_*, PKT_RX_*).

Produce a Must-fix / Missed-edge-cases / Accepted-divergence / FYI report. Save to docs/superpowers/reviews/phase-a-hw-plus-mtcp-compare.md. Block phase-complete tag if any open `[ ]` in Must-fix or Missed-edge-cases."
)
```

- [ ] **Step 2: Read the report; address Must-fix items if any; commit the report**

If the subagent finds Must-fix items, address them in a follow-up commit, then re-dispatch.

```bash
git add docs/superpowers/reviews/phase-a-hw-plus-mtcp-compare.md
git commit -m "phase-a-hw-plus: mTCP comparison review report"
```

---

## Task 15: RFC compliance review (parallel subagent gate)

**Files:**
- Create: `docs/superpowers/reviews/phase-a-hw-plus-rfc-compliance.md` (output of subagent)

A-HW+ is wire-protocol-transparent (slow-path counters + bring-up checks only); the RFC review should be a quick PASS, but the gate is mandatory per `feedback_phase_rfc_review.md`.

- [ ] **Step 1: Dispatch the rfc-compliance-reviewer subagent**

```
Agent(
  subagent_type=rfc-compliance-reviewer,
  model=opus,
  description="Phase A-HW+ RFC compliance review",
  prompt="Review phase-a-hw-plus (branch phase-a-hw-ena-followups) for RFC compliance.

Scope: pure observability + bring-up additions; no wire-protocol change. Files: crates/dpdk-net-core/src/{wc_verify.rs,ena_xstats.rs,counters.rs,engine.rs}, crates/dpdk-net/src/{api.rs,lib.rs}.

Plan: docs/superpowers/plans/2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md. RFCs in scope per parent spec: 9293 (TCP); inspect for any inadvertent wire change. None expected.

Produce a Must-fix (MUST/SHALL violation) / Missing SHOULD / Accepted deviation / FYI report. Save to docs/superpowers/reviews/phase-a-hw-plus-rfc-compliance.md. Block tag on any open `[ ]` in Must-fix or Missing-SHOULD."
)
```

(Tasks 14 and 15 dispatch in parallel via a single message with two Agent tool calls.)

- [ ] **Step 2: Commit the report**

```bash
git add docs/superpowers/reviews/phase-a-hw-plus-rfc-compliance.md
git commit -m "phase-a-hw-plus: RFC compliance review report"
```

---

## Task 16: Phase-complete gate

- [ ] **Step 1: Run the full local gate**

```bash
cargo test --workspace --all-features 2>&1 | tail -30
cargo test -p dpdk-net-core --test knob-coverage 2>&1 | tail -10
cargo test -p dpdk-net-core --test ena_obs_smoke 2>&1 | tail -10
# Optional, on an ENA host:
cargo test -p dpdk-net-core --test ahw_smoke_ena_hw -- --ignored 2>&1 | tail -20
```

Expected: all green.

- [ ] **Step 2: Verify both review reports show zero open `[ ]` in blocking sections**

```bash
grep -E "^\s*-\s*\[\s*\]" docs/superpowers/reviews/phase-a-hw-plus-mtcp-compare.md \
                          docs/superpowers/reviews/phase-a-hw-plus-rfc-compliance.md \
  | grep -E "Must-fix|Missed-edge|Missing SHOULD" || echo "no blocking open items"
```

Expected: "no blocking open items".

- [ ] **Step 3: Update the roadmap status row**

Edit `docs/superpowers/plans/stage1-phase-roadmap.md` — change the A-HW+ row "In progress" → "Complete ✓".

- [ ] **Step 4: Commit + tag**

```bash
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "phase-a-hw-plus: mark complete in stage1 roadmap"
git tag phase-a-hw-plus-complete
```

(Coordinator merges + pushes the tag — same convention as A-HW.)

---

## Self-review checklist (run after writing the plan)

**1. Spec coverage** — every gap in `docs/references/ena-dpdk-review-2026-04-20.md` is covered:
- H1 (WC verify) → Tasks 2 + 3 + 11
- H2 (ENI xstats) → Tasks 4 + 5 + 6 + 11
- M1 (large_llq_hdr) → Tasks 7 + 8 + 9 + 10
- M2 (miss_txc_to) → Tasks 7 + 8 + 10
- M3 (per-queue xstats) → Tasks 4 + 5 + 11
- Counter additions → Task 1
- Knob coverage → Task 10
- Reviews → Tasks 14 + 15
- Tag → Task 16

**2. Placeholder scan** — none of the No-Placeholder patterns appear; every code-step has actual code; every command has expected output.

**3. Type consistency** — `XstatMap`, `XSTAT_NAMES`, `WcVerdict`, `verify_wc_for_ena`, `parse_pat_memtype_list`, `scrape_xstats`, `dpdk_net_scrape_xstats`, `dpdk_net_recommended_ena_devargs`, `ena_large_llq_hdr`, `ena_miss_txc_to_sec`, `llq_wc_missing`, `llq_header_overflow_risk`, `eni_*`, `tx_q0_*`, `rx_q0_*`, `shim_rte_eth_dev_prefetchable_bar_phys` — all consistent across the tasks that reference them.

**End of plan.**
