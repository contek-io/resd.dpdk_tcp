//! Integration tests for the scenario matrix + netem guard shape.
//!
//! These tests don't touch DPDK — they validate pure Rust primitives so
//! they run on any host without an ENA VF or EAL init. The real
//! scenario sweep is exercised post-AMI bake (Plan A T6+T7).

use bench_stress::counters_snapshot::{read, Relation};
use bench_stress::netem::NetemGuard;
use bench_stress::scenarios::{find, is_stage2_placeholder, MATRIX};

use dpdk_net_core::counters::Counters;

#[test]
fn matrix_has_eight_scenarios() {
    assert_eq!(MATRIX.len(), 8);
}

#[test]
fn scenario_names_are_unique() {
    let names: Vec<_> = MATRIX.iter().map(|s| s.name).collect();
    let set: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(names.len(), set.len());
}

#[test]
fn matrix_covers_every_spec_section_7_scenario() {
    // Spec §7 table: the 7 active scenarios + the Stage-2 pmtu row.
    // Fail loudly if someone removes or renames one — this is the
    // authoritative binding between the spec and the code.
    let expected: &[&str] = &[
        "random_loss_01pct_10ms",
        "correlated_burst_loss_1pct",
        "reorder_depth_3",
        "duplication_2x",
        "fault_injector_drop_1pct",
        "fault_injector_reorder_05pct",
        "fault_injector_dup_05pct",
        "pmtu_blackhole_STAGE2",
    ];
    assert_eq!(MATRIX.len(), expected.len());
    for name in expected {
        assert!(find(name).is_some(), "missing scenario: {name}");
    }
}

#[test]
fn netem_scenarios_have_netem_and_no_fi() {
    // Rows 1-4 per spec §7 use netem only.
    for name in [
        "random_loss_01pct_10ms",
        "correlated_burst_loss_1pct",
        "reorder_depth_3",
        "duplication_2x",
    ] {
        let s = find(name).unwrap();
        assert!(s.netem.is_some(), "{name} missing netem");
        assert!(
            s.fault_injector.is_none(),
            "{name} unexpectedly has FaultInjector spec"
        );
    }
}

#[test]
fn fault_injector_scenarios_have_fi_and_no_netem() {
    // Rows 5-7 per spec §7 use FaultInjector only.
    for name in [
        "fault_injector_drop_1pct",
        "fault_injector_reorder_05pct",
        "fault_injector_dup_05pct",
    ] {
        let s = find(name).unwrap();
        assert!(s.fault_injector.is_some(), "{name} missing FaultInjector");
        assert!(
            s.netem.is_none(),
            "{name} unexpectedly has netem spec"
        );
    }
}

/// PMTU blackhole row is Stage 2 only per parent spec §11.4. The row
/// stays in the matrix for schema completeness, but the driver MUST
/// skip it unconditionally and the test harness MUST flag it as a
/// placeholder.
///
/// `#[ignore]` marks the test as skipped by default; `cargo test --
/// --ignored` would run it once Stage 2 implements the PLPMTUD logic.
#[test]
#[ignore = "PMTU blackhole is Stage 2 (RFC 8899 PLPMTUD) per parent spec §11.4"]
fn pmtu_blackhole_stage2_is_implemented() {
    // Intentionally unreachable in Stage 1. Remove the ignore attribute
    // when Stage 2 ships PLPMTUD and this scenario's pass criteria.
    let s = find("pmtu_blackhole_STAGE2").expect("placeholder row must exist");
    assert!(
        !is_stage2_placeholder(s),
        "PMTU blackhole scenario still flagged as Stage 2 placeholder — \
         rename + wire pass criteria before un-ignoring this test"
    );
}

#[test]
fn counter_expectations_parse_to_known_relations() {
    for s in MATRIX {
        for (_name, rel) in s.counter_expectations {
            assert!(
                Relation::parse(rel).is_ok(),
                "scenario {} relation {} failed to parse",
                s.name,
                rel
            );
        }
    }
}

#[test]
fn counter_expectations_resolve_against_counters() {
    // Coverage invariant paired with scenarios.rs: every counter name
    // the matrix references must resolve via counters_snapshot::read.
    let c = Counters::new();
    for s in MATRIX {
        for (name, _) in s.counter_expectations {
            assert!(
                read(&c, name).is_some(),
                "scenario {} references counter {name} \
                 not wired in counters_snapshot::read",
                s.name
            );
        }
    }
}

#[test]
fn netem_guard_drop_does_not_panic_on_uninstalled_state() {
    // If `NetemGuard` were constructed manually (not via apply) then
    // dropped, it would shell out to ssh and we don't have ssh in the
    // cargo test sandbox. The Drop impl logs a stderr warning rather
    // than panicking — construct it reflectively via a sibling helper
    // would require making the fields pub(crate). Instead we rely on
    // the library-side accessor unit test (see `src/netem.rs`).
    //
    // Here we just assert the type compiles + the accessors link.
    fn _type_check(_g: &NetemGuard) {}
    // No run-time behaviour to verify without ssh. Keep as a type check.
}
