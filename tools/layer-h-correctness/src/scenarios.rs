//! Spec §4: the 17-row Layer H scenario matrix.
//!
//! Each row asserts pass/fail under a specific netem (and optionally
//! FaultInjector) adversity configuration. All rows share three implicit
//! invariants enforced in `observation.rs`:
//!   1. State stays `Established` throughout the assertion window.
//!   2. `tcp.mbuf_refcnt_drop_unexpected` delta == 0 (PR #9 leak-detect).
//!   3. `tcp.rx_mempool_avail` ≥ MIN_RX_MEMPOOL_AVAIL at every observation
//!      tick (PR #9 RX-mempool floor).
//!
//! The static `MATRIX` is the single source of truth for the runner; the
//! orchestrator scripts in `scripts/layer-h-{smoke,nightly}.sh` invoke
//! the binary with `--scenarios` / `--smoke` filters that resolve into
//! subsets of this matrix.

use std::time::Duration;

/// One row in the Layer H matrix. Static `'static` strings because the
/// matrix is a compile-time constant — no runtime allocation, no
/// deserialiser round-trip.
#[derive(Debug, Clone, Copy)]
pub struct LayerHScenario {
    pub name: &'static str,
    /// netem qdisc spec for the peer iface, e.g. `"loss 1%"`. `None` =
    /// no netem (composed scenarios + pure-FI placeholder rows).
    pub netem: Option<&'static str>,
    /// FaultInjector spec for `DPDK_NET_FAULT_INJECTOR`. `None` = no FI.
    /// EAL is once-per-process; distinct FI specs require distinct
    /// process invocations (single-FI-spec invariant in `main.rs`).
    pub fault_injector: Option<&'static str>,
    /// Wall-clock duration for the assertion window.
    pub duration: Duration,
    /// True ⇒ row is part of the per-merge CI smoke subset (5 rows total).
    pub smoke: bool,
    /// `(counter_name, relation_str)` pairs. Relation strings: `">0"`,
    /// `"==0"`, `"<=N"`. Pre-flight at startup parses them.
    pub counter_expectations: &'static [(&'static str, &'static str)],
    /// Disjunctive groups: at least one counter in the inner slice must
    /// satisfy the relation. Used for offload-aware corruption-counter
    /// selection (row 14).
    pub disjunctive_expectations: &'static [(&'static [&'static str], &'static str)],
}

/// 30-second default per-scenario duration. Each row may override.
const DUR: Duration = Duration::from_secs(30);

/// The 17-row matrix. Order is significant only for log output; the
/// uniqueness invariant is asserted in `tests/scenario_parse.rs`.
pub const MATRIX: &[LayerHScenario] = &[
    // ── Delay (rows 1-6) ──────────────────────────────────────────────
    LayerHScenario {
        name: "delay_20ms",
        netem: Some("delay 20ms"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.tx_retrans", "==0"),
            ("tcp.tx_rto", "==0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "delay_20ms_jitter_5ms",
        netem: Some("delay 20ms 5ms"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.tx_retrans", "<=10"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "delay_50ms",
        netem: Some("delay 50ms"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.tx_retrans", "==0"),
            ("tcp.tx_rto", "==0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "delay_50ms_jitter_10ms",
        netem: Some("delay 50ms 10ms"),
        fault_injector: None,
        duration: DUR,
        smoke: true,
        counter_expectations: &[
            ("tcp.tx_retrans", "<=10"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "delay_200ms",
        netem: Some("delay 200ms"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.tx_retrans", "==0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "delay_200ms_jitter_50ms",
        netem: Some("delay 200ms 50ms"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.tx_retrans", "<=20"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    // ── Loss (rows 7-10) ──────────────────────────────────────────────
    LayerHScenario {
        name: "loss_01pct",
        netem: Some("loss 0.1%"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.tx_retrans", ">0"),
            ("tcp.tx_retrans", "<=10000"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "loss_1pct",
        netem: Some("loss 1%"),
        fault_injector: None,
        duration: DUR,
        smoke: true,
        counter_expectations: &[
            ("tcp.tx_retrans", ">0"),
            ("tcp.tx_retrans", "<=50000"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "loss_5pct",
        netem: Some("loss 5%"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.tx_retrans", ">0"),
            ("tcp.tx_retrans", "<=200000"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "loss_correlated_burst_1pct",
        netem: Some("loss 1% 25%"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.tx_retrans", ">0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[(
            &["tcp.tx_rto", "tcp.tx_tlp"],
            ">0",
        )],
    },
    // ── Duplication (rows 11-12) ──────────────────────────────────────
    LayerHScenario {
        name: "dup_05pct",
        netem: Some("duplicate 0.5%"),
        fault_injector: None,
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("tcp.rx_dup_ack", ">0"),
            ("tcp.tx_retrans", "==0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "dup_2pct",
        netem: Some("duplicate 2%"),
        fault_injector: None,
        duration: DUR,
        smoke: true,
        counter_expectations: &[
            ("tcp.rx_dup_ack", ">0"),
            ("tcp.tx_retrans", "==0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    // ── Reordering (row 13) ───────────────────────────────────────────
    // Spec §4 note: netem requires a base `delay` for reorder to fire.
    LayerHScenario {
        name: "reorder_depth_3",
        netem: Some("delay 5ms reorder 50% gap 3"),
        fault_injector: None,
        duration: DUR,
        smoke: true,
        counter_expectations: &[
            ("tcp.rx_dup_ack", ">0"),
            ("tcp.tx_retrans", "==0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    // ── Corruption (row 14) ───────────────────────────────────────────
    // Disjunctive cksum-bad assertion handles offload on/off without
    // runtime introspection (spec §4 row 14).
    LayerHScenario {
        name: "corruption_001pct",
        netem: Some("corrupt 0.01%"),
        fault_injector: None,
        duration: DUR,
        smoke: true,
        counter_expectations: &[
            ("obs.events_dropped", "==0"),
            ("tcp.rx_rst", "==0"),
        ],
        disjunctive_expectations: &[(
            &["eth.rx_drop_cksum_bad", "ip.rx_csum_bad"],
            ">0",
        )],
    },
    // ── Composed netem × FaultInjector (rows 15-17) ──────────────────
    // Each row carries a different FI spec; full matrix needs 3 separate
    // process invocations (one per FI spec) plus one for the 14 above.
    LayerHScenario {
        name: "composed_loss_1pct_50ms_fi_drop",
        netem: Some("loss 1% delay 50ms"),
        fault_injector: Some("drop=0.005"),
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("fault_injector.drops", ">0"),
            ("tcp.tx_retrans", ">0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "composed_loss_1pct_50ms_fi_dup",
        netem: Some("loss 1% delay 50ms"),
        fault_injector: Some("dup=0.005"),
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("fault_injector.dups", ">0"),
            ("tcp.rx_dup_ack", ">0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
    LayerHScenario {
        name: "composed_loss_1pct_50ms_fi_reord",
        netem: Some("loss 1% delay 50ms"),
        fault_injector: Some("reorder=0.005"),
        duration: DUR,
        smoke: false,
        counter_expectations: &[
            ("fault_injector.reorders", ">0"),
            ("tcp.rx_dup_ack", ">0"),
            ("obs.events_dropped", "==0"),
        ],
        disjunctive_expectations: &[],
    },
];

/// Find a scenario by name. `--scenarios <csv>` resolves through this.
pub fn find(name: &str) -> Option<&'static LayerHScenario> {
    MATRIX.iter().find(|s| s.name == name)
}

/// True iff the named scenario is in the per-merge CI smoke subset.
pub fn is_smoke_member(name: &str) -> bool {
    MATRIX.iter().any(|s| s.name == name && s.smoke)
}

/// Group selected scenarios by their FI spec (or `None` for pure-netem).
/// The returned vector has at most one entry per distinct FI spec; each
/// entry's scenarios all share the same FI config and can be run in one
/// process invocation.
pub fn partition_by_fi_spec(
    selected: &[&'static LayerHScenario],
) -> Vec<(Option<&'static str>, Vec<&'static LayerHScenario>)> {
    let mut groups: Vec<(Option<&'static str>, Vec<&'static LayerHScenario>)> = Vec::new();
    for s in selected {
        match groups.iter_mut().find(|(spec, _)| *spec == s.fault_injector) {
            Some((_, group)) => group.push(*s),
            None => groups.push((s.fault_injector, vec![*s])),
        }
    }
    groups
}
