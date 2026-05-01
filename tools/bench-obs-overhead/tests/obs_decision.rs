//! Integration tests for the spec §10 obs-floor sanity invariant and
//! the 5-config observability matrix shape.
//!
//! These live as integration tests (against the `bench_obs_overhead`
//! library) rather than unit tests so any future refactor that privates
//! [`check_obs_floor_sanity`] or renames the matrix rows breaks the
//! build loudly rather than silently hiding the contract.
//!
//! Coverage:
//! - `obs_floor_invariant_ok_case` — every row >= `obs-none` → `Ok`.
//! - `obs_floor_invariant_violation_case` — a row BELOW `obs-none` → `Err`.
//! - `obs_matrix_shape` — 5 configs with the correct names and features.
//! - `obs_matrix_canonical_feature_names` — no drift from
//!   `crates/dpdk-net-core/Cargo.toml`.

use std::collections::BTreeMap;

use bench_offload_ab::report::Aggregated;

use bench_obs_overhead::decision::check_obs_floor_sanity;
use bench_obs_overhead::matrix::{ObsRow, DEFAULT_NAME, OBS_MATRIX, OBS_NONE_NAME};

fn agg_with_p99s(pairs: &[(&str, f64)]) -> BTreeMap<String, Aggregated> {
    pairs
        .iter()
        .map(|(name, p99)| {
            (
                (*name).to_string(),
                Aggregated {
                    p50_ns: 0.0,
                    p99_ns: *p99,
                    p999_ns: 0.0,
                },
            )
        })
        .collect()
}

/// OK case: every non-`obs-none` row's p99 is >= `obs-none` p99.
#[test]
fn obs_floor_invariant_ok_case() {
    let agg = agg_with_p99s(&[
        ("obs-none", 78.3),
        ("poll-saturation-only", 86.1),
        ("byte-counters-only", 103.2),
        ("obs-all-no-none", 112.5),
        ("default", 86.2),
    ]);
    let s = check_obs_floor_sanity(OBS_MATRIX, &agg);
    assert!(
        s.verdict.is_ok(),
        "every non-obs-none p99 >= obs-none p99 → ok, got: {:?}",
        s.verdict
    );
    assert_eq!(s.obs_none_p99_ns, Some(78.3));
    assert!(s.violators.is_empty());
}

/// Violation case: at least one row's p99 is BELOW `obs-none` p99.
/// The invariant must fire — observability can't save cost.
#[test]
fn obs_floor_invariant_violation_case() {
    let agg = agg_with_p99s(&[
        ("obs-none", 78.3),
        ("poll-saturation-only", 74.0), // below floor!
        ("byte-counters-only", 103.2),
        ("obs-all-no-none", 112.5),
        ("default", 86.2),
    ]);
    let s = check_obs_floor_sanity(OBS_MATRIX, &agg);
    let err = s.verdict.unwrap_err();
    assert!(
        err.contains("poll-saturation-only"),
        "err should name offending config: {err}"
    );
    assert!(err.contains("74"), "err should carry offending p99: {err}");
    assert!(err.contains("78"), "err should carry floor p99: {err}");
    assert_eq!(s.violators.len(), 1);
    assert_eq!(s.violators[0].0, "poll-saturation-only");
}

/// Spec §10 matrix shape: exactly 5 configs with the spec-specified names.
#[test]
fn obs_matrix_shape() {
    assert_eq!(OBS_MATRIX.len(), 5);
    let names: Vec<&str> = OBS_MATRIX.iter().map(|r| r.config.name).collect();
    assert!(names.contains(&OBS_NONE_NAME));
    assert!(names.contains(&"poll-saturation-only"));
    assert!(names.contains(&"byte-counters-only"));
    assert!(names.contains(&"obs-all-no-none"));
    assert!(names.contains(&DEFAULT_NAME));
}

/// Per-row features match the spec §10 table exactly.
#[test]
fn obs_matrix_canonical_feature_names() {
    let by_name: BTreeMap<&str, &ObsRow> =
        OBS_MATRIX.iter().map(|r| (r.config.name, r)).collect();
    assert_eq!(by_name[OBS_NONE_NAME].config.features, &["obs-none"]);
    assert_eq!(
        by_name["poll-saturation-only"].config.features,
        &["obs-poll-saturation"]
    );
    assert_eq!(
        by_name["byte-counters-only"].config.features,
        &["obs-byte-counters"]
    );
    assert_eq!(by_name["obs-all-no-none"].config.features, &["obs-all"]);
    assert_eq!(
        by_name[DEFAULT_NAME].config.features,
        &[] as &[&str],
        "default row must carry no explicit features (= production build)"
    );
}
