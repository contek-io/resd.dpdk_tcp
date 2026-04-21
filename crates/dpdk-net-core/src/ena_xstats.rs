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
/// same order to write each counter. Exposed as `pub` (not
/// `pub(crate)`) so diagnostic tooling + integration tests can
/// enumerate the consumed name set without reaching into private API.
pub const XSTAT_NAMES: &[&str] = &[
    // ENI allowances (README §8.2.2)
    "bw_in_allowance_exceeded",
    "bw_out_allowance_exceeded",
    "pps_allowance_exceeded",
    "conntrack_allowance_exceeded",
    "linklocal_allowance_exceeded",
    // Per-queue q0 Tx (README §8.2.3) — Stage 1 single queue
    "tx_q0_linearize",
    "tx_q0_doorbells",
    "tx_q0_missed_tx",
    "tx_q0_bad_req_id",
    // Per-queue q0 Rx (README §8.2.4)
    "rx_q0_refill_partial",
    "rx_q0_bad_desc_num",
    "rx_q0_bad_req_id",
    "rx_q0_mbuf_alloc_fail",
];

/// Resolved xstat IDs. `None` slot means the PMD didn't advertise that
/// name (e.g. non-ENA driver, or older ENA with a stale name set). The
/// scraper silently skips `None` slots — their counters stay at 0.
#[derive(Debug, Clone)]
pub struct XstatMap {
    /// Indexed parallel to `XSTAT_NAMES`. `None` if not advertised.
    pub ids: Vec<Option<u64>>,
}

impl XstatMap {
    /// Pure constructor — used by both the runtime resolver
    /// [`resolve_xstat_ids`] and the unit tests. Exposed as `pub` so the
    /// sibling `ena_obs_smoke` integration test (which runs on every CI
    /// worker without DPDK/EAL) can exercise the same code path the
    /// resolver uses, catching module-level regressions at the
    /// integration boundary. See Task 12 of
    /// `2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md`.
    pub fn from_lookup<F>(lookup: F) -> Self
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
    ///
    /// Call only on a *successful* scrape. On a failed scrape use
    /// [`XstatMap::apply_on_error`] — it preserves cumulative slots
    /// (5..=12) while resetting the allowance snapshots (0..=4). See
    /// the module-level note at [`scrape`] for the rationale.
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

    /// Failed-scrape variant. Zeros only the ENI allowance-exceeded
    /// slots (indices 0..=4) which have *snapshot* semantics — "no
    /// throttle observed this cycle" under a failed PMD read == "we
    /// don't know", which maps to 0. The per-queue TX/RX slots
    /// (indices 5..=12) are *cumulative* in the ENA PMD; zero-on-
    /// failure would drive a V→0→V transition that Prometheus
    /// `rate()`/`increase()` read as a counter-reset spike of
    /// magnitude V. Those slots keep their prior atomic value and the
    /// next successful scrape overwrites. See bug_001 review note.
    pub(crate) fn apply_on_error(&self, counters: &Counters) {
        // Only touch the snapshot slots. Cumulative slots (5..=12) are
        // left as-is — readers continue to see the last good value.
        counters
            .eth
            .eni_bw_in_allowance_exceeded
            .store(0, Ordering::Relaxed);
        counters
            .eth
            .eni_bw_out_allowance_exceeded
            .store(0, Ordering::Relaxed);
        counters
            .eth
            .eni_pps_allowance_exceeded
            .store(0, Ordering::Relaxed);
        counters
            .eth
            .eni_conntrack_allowance_exceeded
            .store(0, Ordering::Relaxed);
        counters
            .eth
            .eni_linklocal_allowance_exceeded
            .store(0, Ordering::Relaxed);
    }
}

/// Split-apply dispatcher — exercised by unit tests to cover both the
/// success branch and the cumulative-preserving error branch without
/// needing a live DPDK port. `scrape` calls this after the PMD query.
///
/// `rc_matches_len` is `true` iff `rte_eth_xstats_get_by_id` returned
/// exactly `query_ids.len()` entries (the one success condition; any
/// other return — negative errno, short return — is a failure).
fn apply_scrape_result(
    rc_matches_len: bool,
    values: &[u64],
    map: &XstatMap,
    counters: &Counters,
) {
    if rc_matches_len {
        map.apply(values, counters);
    } else {
        map.apply_on_error(counters);
    }
}

/// Resolve XSTAT_NAMES → ids by walking `rte_eth_xstats_get_names`.
/// Returns an XstatMap that can be reused for every subsequent scrape.
/// Slow-path resolver; called once per `Engine::new`.
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
/// four small Vecs per call (capacity ≤ 13 each) — slow-path-acceptable
/// at the ≤1 Hz cadence the application drives.
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
    // `query_ids.is_empty()` means the PMD advertised none of
    // XSTAT_NAMES — we treat that as a trivially-successful scrape
    // (all zeros) so allowance snapshots stay at 0 and cumulative
    // slots also read 0. Identical to the pre-bugfix behaviour on
    // non-ENA PMDs; the bugfix only changes the error branch.
    let mut rc_matches_len = true;
    if !query_ids.is_empty() {
        let mut got_values = vec![0u64; query_ids.len()];
        // SAFETY: `query_ids` and `got_values` are live, non-null,
        // and sized to `query_ids.len()`.
        let rc = unsafe {
            sys::rte_eth_xstats_get_by_id(
                port_id,
                query_ids.as_ptr(),
                got_values.as_mut_ptr(),
                query_ids.len() as u32,
            )
        };
        // `rc` is `c_int`. A negative errno cast through `as usize`
        // produces a huge value that will never equal
        // `query_ids.len()`, so a `rc < 0` failure falls into the
        // error branch below along with the short-read case.
        rc_matches_len = rc as usize == query_ids.len();
        if rc_matches_len {
            for (k, &i) in query_index.iter().enumerate() {
                values[i] = got_values[k];
            }
        }
        // On failure (`!rc_matches_len`): `values` stays at zero. The
        // split-apply path below only consumes `values` on success;
        // on error it calls `apply_on_error`, which zeros just the
        // allowance snapshot slots (0..=4) and leaves the cumulative
        // per-queue slots (5..=12) at their prior values. This
        // avoids the V→0→V Prometheus `rate()` spike that the pre-
        // bugfix unconditional `apply` produced on cumulative
        // counters. See bug_001.
    }
    apply_scrape_result(rc_matches_len, &values, map, counters);
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
        assert_eq!(map.ids[1], None);
    }

    #[test]
    fn apply_writes_each_counter_in_name_order() {
        let map = XstatMap::from_lookup(|_| Some(0));
        let values: Vec<u64> = (1u64..=13).collect();
        let counters = Counters::new();
        map.apply(&values, &counters);
        assert_eq!(counters.eth.eni_bw_in_allowance_exceeded.load(Ordering::Relaxed), 1);
        assert_eq!(counters.eth.tx_q0_doorbells.load(Ordering::Relaxed), 7);
        assert_eq!(counters.eth.rx_q0_mbuf_alloc_fail.load(Ordering::Relaxed), 13);
    }

    #[test]
    fn apply_writes_zero_for_unadvertised_names() {
        let map = XstatMap::from_lookup(|n| {
            if XSTAT_NAMES.iter().position(|x| x == &n).is_some_and(|i| i < 5) {
                Some(0)
            } else {
                None
            }
        });
        let counters = Counters::new();
        counters.eth.tx_q0_doorbells.store(999, Ordering::Relaxed);
        let values = vec![1u64; 13];
        map.apply(&values, &counters);
        assert_eq!(counters.eth.eni_bw_in_allowance_exceeded.load(Ordering::Relaxed), 1);
        assert_eq!(counters.eth.tx_q0_doorbells.load(Ordering::Relaxed), 0);
    }

    /// bug_001 regression: on a *failed* scrape the cumulative per-queue
    /// xstats (indices 5..=12) must retain their last-good values. The
    /// pre-bugfix path zeroed all 13 slots via a single `apply` call
    /// with a zero-filled value buffer, producing a V→0→V transition
    /// that Prometheus `rate()`/`increase()` read as a false counter-
    /// reset spike of magnitude V on every PMD scrape error.
    #[test]
    fn apply_on_error_preserves_cumulative_counters() {
        let map = XstatMap::from_lookup(|_| Some(0));
        let counters = Counters::new();

        // Seed a known non-zero cumulative state — the scenario the
        // bugfix must protect. Numbers chosen to make any
        // unintentional re-zero obvious in assertion output.
        counters.eth.tx_q0_linearize.store(42, Ordering::Relaxed);
        counters.eth.tx_q0_doorbells.store(1_000_000, Ordering::Relaxed);
        counters.eth.tx_q0_missed_tx.store(7, Ordering::Relaxed);
        counters.eth.tx_q0_bad_req_id.store(3, Ordering::Relaxed);
        counters.eth.rx_q0_refill_partial.store(128, Ordering::Relaxed);
        counters.eth.rx_q0_bad_desc_num.store(5, Ordering::Relaxed);
        counters.eth.rx_q0_bad_req_id.store(9, Ordering::Relaxed);
        counters.eth.rx_q0_mbuf_alloc_fail.store(17, Ordering::Relaxed);

        // Also seed a non-zero allowance-snapshot slot to prove the
        // error branch *does* zero those — that's the documented
        // snapshot semantics for ENI allowances.
        counters.eth.eni_bw_in_allowance_exceeded.store(500, Ordering::Relaxed);

        // Simulate the error branch of scrape(): rc from
        // rte_eth_xstats_get_by_id did NOT match query_ids.len()
        // (e.g. a negative errno or a short return).
        let values = vec![0u64; 13];
        apply_scrape_result(false, &values, &map, &counters);

        // Allowance snapshots: reset to 0 (intentional).
        assert_eq!(
            counters.eth.eni_bw_in_allowance_exceeded.load(Ordering::Relaxed),
            0,
            "allowance snapshot should be reset on failed scrape",
        );

        // Cumulative per-queue slots: untouched. This is the core
        // regression the bugfix guards against.
        assert_eq!(
            counters.eth.tx_q0_linearize.load(Ordering::Relaxed),
            42,
        );
        assert_eq!(
            counters.eth.tx_q0_doorbells.load(Ordering::Relaxed),
            1_000_000,
            "bug_001: tx_q0_doorbells must NOT be zeroed on scrape failure",
        );
        assert_eq!(counters.eth.tx_q0_missed_tx.load(Ordering::Relaxed), 7);
        assert_eq!(counters.eth.tx_q0_bad_req_id.load(Ordering::Relaxed), 3);
        assert_eq!(counters.eth.rx_q0_refill_partial.load(Ordering::Relaxed), 128);
        assert_eq!(counters.eth.rx_q0_bad_desc_num.load(Ordering::Relaxed), 5);
        assert_eq!(counters.eth.rx_q0_bad_req_id.load(Ordering::Relaxed), 9);
        assert_eq!(counters.eth.rx_q0_mbuf_alloc_fail.load(Ordering::Relaxed), 17);
    }

    /// Success branch of the split-apply dispatcher still writes all 13
    /// slots from the value buffer — confirms the refactor didn't
    /// regress the happy path. Complements `apply_on_error_preserves_
    /// cumulative_counters`: together they cover both branches of
    /// `apply_scrape_result`.
    #[test]
    fn apply_scrape_result_success_writes_all_slots() {
        let map = XstatMap::from_lookup(|_| Some(0));
        let counters = Counters::new();
        // Prior non-zero state (to show the success path overwrites).
        counters.eth.tx_q0_doorbells.store(999, Ordering::Relaxed);

        let values: Vec<u64> = (1u64..=13).collect();
        apply_scrape_result(true, &values, &map, &counters);

        assert_eq!(
            counters.eth.eni_bw_in_allowance_exceeded.load(Ordering::Relaxed),
            1,
        );
        assert_eq!(
            counters.eth.tx_q0_doorbells.load(Ordering::Relaxed),
            7,
            "success path must overwrite prior cumulative value",
        );
        assert_eq!(
            counters.eth.rx_q0_mbuf_alloc_fail.load(Ordering::Relaxed),
            13,
        );
    }
}
