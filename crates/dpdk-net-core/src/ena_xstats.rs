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
    /// Build from a name → id lookup. Pure function — used by both the
    /// runtime resolver and the unit tests.
    ///
    /// `allow(dead_code)` covers Task 4 — the Engine caching wiring
    /// that will call `resolve_xstat_ids` (and transitively this) lands
    /// in Task 5, mirroring the same gating pattern used by
    /// `wc_verify::parse_pat_memtype_list` pre-Task 3.
    #[allow(dead_code)]
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

/// Resolve XSTAT_NAMES → ids by walking `rte_eth_xstats_get_names`.
/// Returns an XstatMap that can be reused for every subsequent scrape.
/// Slow-path; called once at engine_create.
///
/// On non-ENA / non-advertising PMDs every slot is `None` and `apply`
/// writes 0 across the board; the scrape becomes a cheap no-op.
///
/// `allow(dead_code)` covers Task 4 — the Engine caching wiring lands
/// in Task 5. Same gating pattern used by `wc_verify::verify_wc_for_ena`
/// pre-Task 3.
#[allow(dead_code)]
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
        // rc < expected: leave `values` at zeros. For allowance
        // snapshot counters this is the correct reading of a failed
        // scrape — "no throttle observed this cycle" = we don't know,
        // which matches 0 under snapshot semantics. Preserving stale
        // values would freeze a nonzero allowance indefinitely across
        // PMD errors and hide the "throttle cleared" transition.
        // Next successful scrape overwrites.
    }
    map.apply(&values, counters);
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
}
