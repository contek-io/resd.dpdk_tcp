//! Static-matrix invariants. No DPDK / EAL: pure compile-time data.

use layer_h_correctness::scenarios::{is_smoke_member, MATRIX};

#[test]
fn matrix_has_seventeen_scenarios() {
    assert_eq!(MATRIX.len(), 17);
}

#[test]
fn scenario_names_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for s in MATRIX {
        assert!(
            seen.insert(s.name),
            "duplicate scenario name: {}",
            s.name
        );
    }
}

#[test]
fn smoke_set_is_exactly_five_named_rows() {
    let smoke: Vec<_> = MATRIX.iter().filter(|s| s.smoke).map(|s| s.name).collect();
    assert_eq!(smoke.len(), 5, "expected 5 smoke rows, got {smoke:?}");
    let expected = [
        "delay_50ms_jitter_10ms",
        "loss_1pct",
        "dup_2pct",
        "reorder_depth_3",
        "corruption_001pct",
    ];
    for n in expected {
        assert!(
            is_smoke_member(n),
            "smoke set missing {n}; got {smoke:?}"
        );
    }
}

#[test]
fn pure_netem_scenarios_have_no_fi_spec() {
    for s in MATRIX {
        if !s.name.starts_with("composed_") {
            assert!(
                s.fault_injector.is_none(),
                "non-composed scenario {} has FI spec",
                s.name
            );
        }
    }
}

#[test]
fn composed_scenarios_partition_by_fi_spec() {
    let composed: Vec<_> = MATRIX
        .iter()
        .filter(|s| s.name.starts_with("composed_"))
        .collect();
    assert_eq!(composed.len(), 3);
    let mut specs: Vec<&str> = composed
        .iter()
        .map(|s| s.fault_injector.expect("composed row must set FI spec"))
        .collect();
    specs.sort();
    assert_eq!(specs, vec!["drop=0.005", "dup=0.005", "reorder=0.005"]);
}
