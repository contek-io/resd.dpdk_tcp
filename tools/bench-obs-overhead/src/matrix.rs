//! Feature matrix for the `obs-*` A/B sweep. Spec §10.
//!
//! Five configs per spec §10:
//!
//! | Config name | Features |
//! |---|---|
//! | `obs-none` | `obs-none` (NEW per D4, disables G1-G4) |
//! | `poll-saturation-only` | `obs-poll-saturation` |
//! | `byte-counters-only` | `obs-byte-counters` |
//! | `obs-all-no-none` | `obs-all` (= `obs-poll-saturation + obs-byte-counters`) |
//! | `default` | default features (= production build) |
//!
//! # `default` row encoding
//!
//! The `default` row is the only matrix entry that builds **with** default
//! features — everything else in `bench-offload-ab` and the spec §10 matrix
//! rebuilds with `--no-default-features`. The driver (`main.rs`) keys off
//! the [`is_default`] marker to decide whether to pass `--no-default-features`
//! to cargo for that row. Keeping the marker on `Config` means the spec §9
//! driver stays oblivious to it (every hw-* row has `is_default == false`).
//!
//! # No `is_full` row
//!
//! The obs-* matrix has no equivalent of `bench-offload-ab`'s `full`
//! row: the reference in `check_obs_floor_sanity` is [`OBS_NONE_NAME`]
//! (the observability-off floor), not a maximum-everything row. Every
//! `Config` in [`OBS_MATRIX`] therefore has `is_full: false`, which
//! short-circuits `bench_offload_ab::report::check_full_sanity` to a
//! trivially-ok verdict — we replace that check with the obs-specific
//! one in [`crate::decision`].

use bench_offload_ab::matrix::Config;

/// Canonical config name for the observability-off floor row. Callers
/// (the sanity-check code, the report writer, the main driver) import
/// this rather than hard-coding the string literal so a rename stays
/// local to this file.
pub const OBS_NONE_NAME: &str = "obs-none";

/// Canonical config name for the production-build row (= "keep whatever
/// `dpdk-net-core`'s default features say today").
pub const DEFAULT_NAME: &str = "default";

/// Extended matrix row — plain `Config` plus a couple of obs-specific
/// per-row bits the report writer reads out (default-ON? default-OFF?
/// is this the composite? the "default" pass-through?).
///
/// Using a separate wrapper rather than adding fields to
/// `bench_offload_ab::matrix::Config` keeps the hw-* side of the driver
/// library oblivious to obs-specific presentation concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObsRow {
    /// The underlying [`Config`] — name, feature slice, baseline marker.
    /// Passed verbatim into the `bench-offload-ab` report / subprocess
    /// plumbing.
    pub config: Config,
    /// Whether this row's corresponding production feature(s) ship
    /// default-ON. Rendered in the report's "Default" column so the
    /// reviewer can tell at a glance whether a Signal implies a
    /// remediation requirement (default-ON + Signal → ACTION; default-OFF
    /// + Signal → informational).
    pub default_state: DefaultState,
    /// Whether this row should be built with `--no-default-features`
    /// (the common case for every matrix row EXCEPT [`DEFAULT_NAME`]).
    /// The driver checks this to decide the cargo invocation shape.
    pub is_default: bool,
}

/// What position each row's feature(s) occupy in the production default
/// feature set — rendered directly in the report's "Default" column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultState {
    /// Feature is currently in `dpdk-net-core`'s `default = [...]` list.
    /// A hot-path Signal here demands one of the action-taxonomy
    /// responses (batch / remove / flip default / move off hot path).
    On,
    /// Feature exists but is not in the default set — opt-in today.
    /// A Signal here is informational (operators enabling it pay the
    /// cost knowingly).
    Off,
    /// Composite row (e.g. `obs-all-no-none`) whose "default" status is
    /// the sum of its parts — rendered as `(composite)` in the report.
    Composite,
    /// Meta row that isn't itself a feature (e.g. the `default` row
    /// which is "whatever the production build is today"). Rendered
    /// as `N/A`.
    NotApplicable,
}

impl DefaultState {
    /// Label rendered under the "Default" column in the spec §10 report.
    pub fn label(&self) -> &'static str {
        match self {
            DefaultState::On => "ON",
            DefaultState::Off => "OFF",
            DefaultState::Composite => "(composite)",
            DefaultState::NotApplicable => "N/A",
        }
    }
}

/// The spec §10 five-config matrix for the `obs-*` A/B sweep.
///
/// Row ordering matters for the report: the reviewer reads it
/// top-to-bottom, so `obs-none` is first (the floor), followed by the
/// single-feature experiments, the composite, and finally the `default`
/// production row that anchors the table to reality.
///
/// Every row has `is_baseline: false` — there is no separate "baseline"
/// in the obs matrix. `obs-none` IS the reference point and the
/// report-writer treats it as the floor via [`OBS_NONE_NAME`] instead of
/// via `is_baseline`.
pub const OBS_MATRIX: &[ObsRow] = &[
    ObsRow {
        config: Config {
            name: OBS_NONE_NAME,
            features: &["obs-none"],
            is_baseline: false,
            is_full: false,
        },
        default_state: DefaultState::Off,
        is_default: false,
    },
    ObsRow {
        config: Config {
            name: "poll-saturation-only",
            features: &["obs-poll-saturation"],
            is_baseline: false,
            is_full: false,
        },
        default_state: DefaultState::On,
        is_default: false,
    },
    ObsRow {
        config: Config {
            name: "byte-counters-only",
            features: &["obs-byte-counters"],
            is_baseline: false,
            is_full: false,
        },
        default_state: DefaultState::Off,
        is_default: false,
    },
    ObsRow {
        config: Config {
            name: "obs-all-no-none",
            features: &["obs-all"],
            is_baseline: false,
            is_full: false,
        },
        default_state: DefaultState::Composite,
        is_default: false,
    },
    ObsRow {
        config: Config {
            name: DEFAULT_NAME,
            features: &[],
            is_baseline: false,
            is_full: false,
        },
        default_state: DefaultState::NotApplicable,
        is_default: true,
    },
];

/// Convenience: project [`OBS_MATRIX`] into a `&[Config]` slice so the
/// `bench_offload_ab::report::aggregate_by_config` / `build_report_rows`
/// helpers can consume it without knowing about `ObsRow`.
pub fn obs_configs() -> Vec<Config> {
    OBS_MATRIX.iter().map(|r| r.config.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §10 says exactly 5 configs.
    #[test]
    fn obs_matrix_has_five_configs() {
        assert_eq!(OBS_MATRIX.len(), 5);
    }

    /// Exactly one `obs-none` row — the sanity-check floor.
    #[test]
    fn obs_matrix_has_exactly_one_obs_none_row() {
        let cnt = OBS_MATRIX
            .iter()
            .filter(|r| r.config.name == OBS_NONE_NAME)
            .count();
        assert_eq!(cnt, 1);
    }

    /// Exactly one `default` row — the production-build reference.
    #[test]
    fn obs_matrix_has_exactly_one_default_row() {
        let defaults: Vec<_> = OBS_MATRIX.iter().filter(|r| r.is_default).collect();
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0].config.name, DEFAULT_NAME);
        assert!(
            defaults[0].config.features.is_empty(),
            "default row carries no explicit feature flags (it's the \
             whatever-production-is row)"
        );
    }

    /// Config names are unique — the `feature_set` CSV column is the
    /// row key the aggregator uses.
    #[test]
    fn obs_matrix_names_are_unique() {
        let mut names: Vec<_> = OBS_MATRIX.iter().map(|r| r.config.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    /// Matrix canonical shape: obs-none present with its feature, the
    /// three experimental rows with their single or composite feature,
    /// `default` with no explicit features.
    #[test]
    fn obs_matrix_has_expected_shape() {
        let by_name: std::collections::BTreeMap<_, _> =
            OBS_MATRIX.iter().map(|r| (r.config.name, r)).collect();

        assert_eq!(
            by_name[OBS_NONE_NAME].config.features,
            &["obs-none"],
            "obs-none row must flip the obs-none feature"
        );
        assert_eq!(
            by_name["poll-saturation-only"].config.features,
            &["obs-poll-saturation"],
        );
        assert_eq!(
            by_name["byte-counters-only"].config.features,
            &["obs-byte-counters"],
        );
        assert_eq!(by_name["obs-all-no-none"].config.features, &["obs-all"],);
        assert_eq!(by_name[DEFAULT_NAME].config.features, &[] as &[&str],);
    }

    /// Every obs-* feature name referenced in the matrix must match
    /// `crates/dpdk-net-core/Cargo.toml` exactly. Drift here would
    /// silently build with the wrong flag set and make the A/B
    /// meaningless.
    #[test]
    fn obs_matrix_uses_canonical_flag_names() {
        let canonical: &[&str] = &[
            "obs-none",
            "obs-poll-saturation",
            "obs-byte-counters",
            "obs-all",
        ];
        for row in OBS_MATRIX {
            for f in row.config.features {
                assert!(
                    canonical.contains(f),
                    "feature {f} on row {} is not in the canonical obs-* flag set",
                    row.config.name,
                );
            }
        }
    }

    /// Default-state labels match the spec §10 report wording.
    #[test]
    fn default_state_labels_are_spec_wording() {
        assert_eq!(DefaultState::On.label(), "ON");
        assert_eq!(DefaultState::Off.label(), "OFF");
        assert_eq!(DefaultState::Composite.label(), "(composite)");
        assert_eq!(DefaultState::NotApplicable.label(), "N/A");
    }

    /// Per spec §10 table: poll-saturation is default-ON, byte-counters
    /// is default-OFF, obs-all-no-none is composite, default is N/A.
    /// obs-none sits outside the default set (opt-in) so it carries
    /// `Off` as well.
    #[test]
    fn obs_matrix_default_states_match_spec() {
        let by_name: std::collections::BTreeMap<_, _> =
            OBS_MATRIX.iter().map(|r| (r.config.name, r)).collect();
        assert_eq!(by_name[OBS_NONE_NAME].default_state, DefaultState::Off);
        assert_eq!(
            by_name["poll-saturation-only"].default_state,
            DefaultState::On
        );
        assert_eq!(
            by_name["byte-counters-only"].default_state,
            DefaultState::Off
        );
        assert_eq!(
            by_name["obs-all-no-none"].default_state,
            DefaultState::Composite
        );
        assert_eq!(
            by_name[DEFAULT_NAME].default_state,
            DefaultState::NotApplicable
        );
    }

    /// Exactly one row should carry `is_default = true`; every other
    /// row builds with `--no-default-features`.
    #[test]
    fn exactly_one_is_default_row() {
        let n = OBS_MATRIX.iter().filter(|r| r.is_default).count();
        assert_eq!(n, 1);
    }

    /// Projection helper returns exactly OBS_MATRIX.len() configs.
    #[test]
    fn obs_configs_projection_preserves_rows() {
        let cs = obs_configs();
        assert_eq!(cs.len(), OBS_MATRIX.len());
        for (i, c) in cs.iter().enumerate() {
            assert_eq!(c, &OBS_MATRIX[i].config);
        }
    }
}
