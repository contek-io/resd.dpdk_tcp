//! Named-counter snapshot + delta assertion.
//!
//! The `counter_expectations` field on `Scenario` (spec §7) carries pairs
//! of `(counter_name, relation)` where `counter_name` is a dotted path
//! like `tcp.tx_rto` or `fault_injector.drops`. The driver snapshots the
//! full set of known counters pre-run and post-run, computes a delta per
//! named counter, and asserts the relation.
//!
//! This module owns the name → counter-value lookup table. Keeping the
//! mapping in one place means a counter-rename in `dpdk_net_core` only
//! touches one site in the bench harness, and the test matrix in
//! `scenarios.rs` stays declarative (string-literal names, not Rust
//! field accessors).
//!
//! # Counter namespace
//!
//! The dotted path matches the `Counters` struct layout in
//! `dpdk-net-core/src/counters.rs`:
//!
//! - `eth.*`     — [`EthCounters`]
//! - `ip.*`      — [`IpCounters`]
//! - `tcp.*`     — [`TcpCounters`]
//! - `poll.*`    — [`PollCounters`]
//! - `obs.*`     — [`ObsCounters`]
//! - `fault_injector.*` — [`FaultInjectorCounters`]
//!
//! The set is incomplete — only the counters the A10 T7 matrix
//! references today are wired. Adding a counter reference to the matrix
//! without wiring it here produces an `UnknownCounter` error at driver
//! start, never a silent skip.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use dpdk_net_core::counters::Counters;

/// A named snapshot of u64-valued counters. Ordered for deterministic
/// diagnostics when the assertion fails.
pub type Snapshot = BTreeMap<&'static str, u64>;

/// Pass relations accepted in `counter_expectations`. Parsed in
/// `assert_delta` so an unknown literal errors at driver start, not at
/// assert time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// post > pre.
    GreaterThanZero,
    /// post == pre.
    EqualsZero,
}

impl Relation {
    /// Parse a relation literal from the scenario matrix. Unknown
    /// strings error; this parser is the single source of truth paired
    /// with the test in `scenarios.rs::counter_expectations_use_known_relations`.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            ">0" => Ok(Self::GreaterThanZero),
            "==0" => Ok(Self::EqualsZero),
            other => anyhow::bail!("unknown counter relation: {other}"),
        }
    }

    /// Apply the relation to a delta. Returns `Ok(())` on pass,
    /// `Err(String)` with a diagnostic on fail.
    pub fn check(self, counter: &str, delta: i128) -> Result<(), String> {
        match self {
            Self::GreaterThanZero => {
                if delta > 0 {
                    Ok(())
                } else {
                    Err(format!("{counter}: expected delta > 0, got {delta}"))
                }
            }
            Self::EqualsZero => {
                if delta == 0 {
                    Ok(())
                } else {
                    Err(format!("{counter}: expected delta == 0, got {delta}"))
                }
            }
        }
    }
}

/// Read a counter by dotted name. Returns `None` if the name isn't
/// wired into the lookup table. Expand this table when a new counter
/// is referenced from `scenarios.rs` — the coverage test in
/// `scenario_parse.rs` catches missing entries at test time.
pub fn read(counters: &Counters, name: &str) -> Option<u64> {
    match name {
        // tcp.*
        "tcp.tx_retrans" => Some(counters.tcp.tx_retrans.load(Ordering::Relaxed)),
        "tcp.tx_rto" => Some(counters.tcp.tx_rto.load(Ordering::Relaxed)),
        "tcp.tx_tlp" => Some(counters.tcp.tx_tlp.load(Ordering::Relaxed)),
        "tcp.tx_tlp_spurious" => Some(counters.tcp.tx_tlp_spurious.load(Ordering::Relaxed)),
        "tcp.rx_dup_ack" => Some(counters.tcp.rx_dup_ack.load(Ordering::Relaxed)),
        "tcp.rx_dsack" => Some(counters.tcp.rx_dsack.load(Ordering::Relaxed)),
        "tcp.rx_out_of_order" => Some(counters.tcp.rx_out_of_order.load(Ordering::Relaxed)),
        "tcp.rx_reassembly_queued" => {
            Some(counters.tcp.rx_reassembly_queued.load(Ordering::Relaxed))
        }
        "tcp.tx_rack_loss" => Some(counters.tcp.tx_rack_loss.load(Ordering::Relaxed)),
        // fault_injector.*
        "fault_injector.drops" => {
            Some(counters.fault_injector.drops.load(Ordering::Relaxed))
        }
        "fault_injector.dups" => {
            Some(counters.fault_injector.dups.load(Ordering::Relaxed))
        }
        "fault_injector.reorders" => {
            Some(counters.fault_injector.reorders.load(Ordering::Relaxed))
        }
        "fault_injector.corrupts" => {
            Some(counters.fault_injector.corrupts.load(Ordering::Relaxed))
        }
        _ => None,
    }
}

/// Take a point-in-time snapshot of all counters referenced from the
/// scenario matrix. `names` is the union of every scenario's
/// `counter_expectations` (first element of each tuple); the driver
/// computes this once up front so unknown names fail early.
pub fn snapshot(counters: &Counters, names: &[&'static str]) -> anyhow::Result<Snapshot> {
    let mut out = Snapshot::new();
    for n in names {
        match read(counters, n) {
            Some(v) => {
                out.insert(n, v);
            }
            None => anyhow::bail!("unknown counter name in scenario matrix: {n}"),
        }
    }
    Ok(out)
}

/// Assert a counter expectation against pre/post snapshots. Uses i128
/// for the delta so a decreasing counter (impossible on u64 monotonic
/// counters but catchable) surfaces as a negative delta rather than
/// underflowing. Returns `Err` with the full diagnostic on any fail.
pub fn assert_delta(
    pre: &Snapshot,
    post: &Snapshot,
    counter: &str,
    relation: Relation,
) -> Result<(), String> {
    let p0 = *pre
        .get(counter)
        .ok_or_else(|| format!("counter {counter} missing from pre snapshot"))?;
    let p1 = *post
        .get(counter)
        .ok_or_else(|| format!("counter {counter} missing from post snapshot"))?;
    let delta = (p1 as i128) - (p0 as i128);
    relation.check(counter, delta)
}

/// Collect the full set of counter names referenced from any
/// scenario's `counter_expectations`. Used by the driver to build the
/// snapshot targets list once at startup.
///
/// Takes an iterator over `&Scenario` so callers can pass either a
/// slice of owned `Scenario` values (the `MATRIX` static → `.iter()`)
/// or a slice of references (the driver's filtered selection →
/// `.iter().copied()`).
pub fn collect_names_from_matrix<'a, I>(scenarios: I) -> Vec<&'static str>
where
    I: IntoIterator<Item = &'a crate::scenarios::Scenario>,
{
    let mut set: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    for s in scenarios {
        for (name, _) in s.counter_expectations {
            set.insert(*name);
        }
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenarios::MATRIX;

    #[test]
    fn relation_parse_round_trip() {
        assert_eq!(Relation::parse(">0").unwrap(), Relation::GreaterThanZero);
        assert_eq!(Relation::parse("==0").unwrap(), Relation::EqualsZero);
        assert!(Relation::parse("<0").is_err());
        assert!(Relation::parse("").is_err());
    }

    #[test]
    fn relation_greater_than_zero_checks() {
        assert!(Relation::GreaterThanZero.check("c", 1).is_ok());
        assert!(Relation::GreaterThanZero.check("c", 0).is_err());
        assert!(Relation::GreaterThanZero.check("c", -1).is_err());
    }

    #[test]
    fn relation_equals_zero_checks() {
        assert!(Relation::EqualsZero.check("c", 0).is_ok());
        assert!(Relation::EqualsZero.check("c", 1).is_err());
        assert!(Relation::EqualsZero.check("c", -1).is_err());
    }

    #[test]
    fn read_known_counters_from_fresh_counters_returns_zero() {
        let c = Counters::new();
        assert_eq!(read(&c, "tcp.tx_retrans").unwrap(), 0);
        assert_eq!(read(&c, "tcp.tx_rto").unwrap(), 0);
        assert_eq!(read(&c, "fault_injector.drops").unwrap(), 0);
        assert_eq!(read(&c, "fault_injector.reorders").unwrap(), 0);
    }

    #[test]
    fn read_unknown_counter_returns_none() {
        let c = Counters::new();
        assert!(read(&c, "tcp.nonexistent").is_none());
        assert!(read(&c, "fault_injector.bogus").is_none());
        assert!(read(&c, "garbage").is_none());
    }

    /// Coverage guard: every counter name referenced from the scenario
    /// matrix must be wired into the `read` lookup table. If a new
    /// scenario adds a counter without updating `read`, this test fires
    /// and points at the gap.
    #[test]
    fn all_matrix_counter_names_resolve() {
        let c = Counters::new();
        for s in MATRIX {
            for (name, _) in s.counter_expectations {
                assert!(
                    read(&c, name).is_some(),
                    "scenario {} references counter {name} \
                     which is not wired in counters_snapshot::read",
                    s.name
                );
            }
        }
    }

    #[test]
    fn snapshot_collects_known_counter_values() {
        let c = Counters::new();
        let names = ["tcp.tx_retrans", "tcp.tx_rto", "fault_injector.drops"];
        let snap = snapshot(&c, &names).unwrap();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap["tcp.tx_retrans"], 0);
        assert_eq!(snap["fault_injector.drops"], 0);
    }

    #[test]
    fn snapshot_errors_on_unknown_counter() {
        let c = Counters::new();
        let names = ["tcp.tx_retrans", "nonexistent.counter"];
        assert!(snapshot(&c, &names).is_err());
    }

    #[test]
    fn assert_delta_pass_and_fail() {
        let pre: Snapshot = [("tcp.tx_rto", 5)].into_iter().collect();
        let post_gt: Snapshot = [("tcp.tx_rto", 10)].into_iter().collect();
        let post_eq: Snapshot = [("tcp.tx_rto", 5)].into_iter().collect();

        assert!(assert_delta(&pre, &post_gt, "tcp.tx_rto", Relation::GreaterThanZero).is_ok());
        assert!(assert_delta(&pre, &post_eq, "tcp.tx_rto", Relation::EqualsZero).is_ok());
        assert!(assert_delta(&pre, &post_eq, "tcp.tx_rto", Relation::GreaterThanZero).is_err());
        assert!(assert_delta(&pre, &post_gt, "tcp.tx_rto", Relation::EqualsZero).is_err());
    }

    #[test]
    fn assert_delta_errors_on_missing_counter() {
        let pre: Snapshot = Snapshot::new();
        let post: Snapshot = Snapshot::new();
        assert!(assert_delta(&pre, &post, "missing", Relation::EqualsZero).is_err());
    }

    #[test]
    fn collect_names_from_matrix_dedupes_and_sorts() {
        let names = collect_names_from_matrix(MATRIX.iter());
        // BTreeSet drive ensures sorted + dedup. Verify one of the counters
        // that appears in multiple scenarios only shows up once.
        let retrans_count = names.iter().filter(|n| **n == "tcp.tx_retrans").count();
        assert_eq!(retrans_count, 1);
        // Verify sort order.
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }
}
