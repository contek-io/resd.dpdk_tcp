//! Spec §3.2 + §5: counter-name → value snapshot via the engine's master
//! `lookup_counter`. Distinct from bench-stress's narrower local copy:
//! we delegate to `dpdk_net_core::counters::lookup_counter` directly so
//! every counter in the engine's surface is reachable without porting
//! names into a layer-h-local table.
//!
//! Two counter shapes are exposed:
//!   1. `AtomicU64` counters via `lookup_counter` — the common case;
//!      participates in the snapshot delta machinery.
//!   2. `tcp.rx_mempool_avail` (`AtomicU32`, intentionally absent from
//!      `lookup_counter`'s `&AtomicU64` table per
//!      `crates/dpdk-net-core/src/counters.rs:534`) — read directly off
//!      `Counters` via [`live_rx_mempool_avail`]. Used in the
//!      observation loop's RX-mempool-floor side-check, not in
//!      counter-delta expectations.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use dpdk_net_core::counters::{lookup_counter, Counters};

/// Spec §5.4 constant: minimum allowed `tcp.rx_mempool_avail` at every
/// observation tick. Below this ⇒ approaching the cliff PR #9 was
/// chasing; fail-fast.
pub const MIN_RX_MEMPOOL_AVAIL: u32 = 32;

/// Side-check counters every scenario implicitly asserts in addition to
/// its own `counter_expectations` (spec §4 "Global side-checks"):
///   - `tcp.mbuf_refcnt_drop_unexpected` delta `== 0`.
///   - `obs.events_dropped` per-batch delta `== 0` (in observation.rs).
///
/// These names are added to the snapshot's name set automatically so
/// scenarios don't repeat them. Wired into snapshot collection by
/// `snapshot_with_side_checks`.
pub const SIDE_CHECK_COUNTERS: &[&str] =
    &["tcp.mbuf_refcnt_drop_unexpected", "obs.events_dropped"];

/// Ordered snapshot of named counter values. Ordered for deterministic
/// diagnostics in the failure bundle.
pub type Snapshot = BTreeMap<String, u64>;

/// Read a single counter by name. Wraps `lookup_counter` with `Relaxed`
/// load semantics. Returns `None` if the name is unknown.
pub fn read(c: &Counters, name: &str) -> Option<u64> {
    lookup_counter(c, name).map(|a| a.load(Ordering::Relaxed))
}

/// Snapshot every name in `names`. Errors if any name is unknown — the
/// driver calls this once at startup to validate all matrix names
/// before opening the first connection.
pub fn snapshot(c: &Counters, names: &[&str]) -> Result<Snapshot, SnapshotError> {
    let mut out = Snapshot::new();
    for n in names {
        match read(c, n) {
            Some(v) => {
                out.insert((*n).to_string(), v);
            }
            None => {
                return Err(SnapshotError::UnknownCounter((*n).to_string()));
            }
        }
    }
    Ok(out)
}

/// Compute `post - pre` for a named counter. Returns `i128` so a
/// hypothetical negative delta (impossible on monotonic u64 counters
/// but defensively typed) surfaces as a value rather than wrapping. The
/// caller (assertion engine) feeds this into [`Relation::check`].
pub fn delta(pre: &Snapshot, post: &Snapshot, name: &str) -> Result<i128, SnapshotError> {
    let p0 = pre
        .get(name)
        .ok_or_else(|| SnapshotError::MissingFromSnapshot(name.to_string()))?;
    let p1 = post
        .get(name)
        .ok_or_else(|| SnapshotError::MissingFromSnapshot(name.to_string()))?;
    Ok((*p1 as i128) - (*p0 as i128))
}

/// Live read of `tcp.rx_mempool_avail` (`AtomicU32`). Used by the
/// observation loop's RX-mempool-floor side-check. Not part of the
/// snapshot/delta machinery because it's a u32 + a level (not a
/// monotonic counter).
pub fn live_rx_mempool_avail(c: &Counters) -> u32 {
    c.tcp.rx_mempool_avail.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    #[error("unknown counter name (not wired into lookup_counter): {0:?}")]
    UnknownCounter(String),
    #[error("counter missing from snapshot (logic bug): {0:?}")]
    MissingFromSnapshot(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_known_counter_returns_zero_on_fresh() {
        let c = Counters::new();
        assert_eq!(read(&c, "tcp.tx_retrans"), Some(0));
        assert_eq!(read(&c, "obs.events_dropped"), Some(0));
        assert_eq!(read(&c, "fault_injector.drops"), Some(0));
    }

    #[test]
    fn read_unknown_counter_returns_none() {
        let c = Counters::new();
        assert_eq!(read(&c, "tcp.nonexistent"), None);
        assert_eq!(read(&c, "garbage"), None);
    }

    #[test]
    fn snapshot_collects_known_names() {
        let c = Counters::new();
        let names = ["tcp.tx_retrans", "obs.events_dropped"];
        let snap = snapshot(&c, &names).unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap["tcp.tx_retrans"], 0);
        assert_eq!(snap["obs.events_dropped"], 0);
    }

    #[test]
    fn snapshot_errors_on_unknown_name() {
        let c = Counters::new();
        let names = ["tcp.tx_retrans", "tcp.nonexistent"];
        let err = snapshot(&c, &names).unwrap_err();
        assert!(matches!(err, SnapshotError::UnknownCounter(_)));
    }

    #[test]
    fn delta_returns_post_minus_pre() {
        let mut pre = Snapshot::new();
        pre.insert("tcp.tx_retrans".into(), 5);
        let mut post = Snapshot::new();
        post.insert("tcp.tx_retrans".into(), 12);
        assert_eq!(delta(&pre, &post, "tcp.tx_retrans").unwrap(), 7);
    }

    #[test]
    fn delta_errors_when_counter_missing_from_either_snapshot() {
        let pre = Snapshot::new();
        let post = Snapshot::new();
        let err = delta(&pre, &post, "tcp.tx_retrans").unwrap_err();
        assert!(matches!(err, SnapshotError::MissingFromSnapshot(_)));
    }

    #[test]
    fn live_rx_mempool_avail_reads_atomic_u32() {
        let c = Counters::new();
        assert_eq!(live_rx_mempool_avail(&c), 0);
        c.tcp.rx_mempool_avail.store(128, Ordering::Relaxed);
        assert_eq!(live_rx_mempool_avail(&c), 128);
    }

    #[test]
    fn min_rx_mempool_avail_is_32() {
        // Spec §5.4 constant must not silently change.
        assert_eq!(MIN_RX_MEMPOOL_AVAIL, 32);
    }

    #[test]
    fn side_check_counters_listed_in_lookup_counter() {
        let c = Counters::new();
        for n in SIDE_CHECK_COUNTERS {
            assert!(
                read(&c, n).is_some(),
                "side-check counter {n} not wired into lookup_counter"
            );
        }
    }
}
