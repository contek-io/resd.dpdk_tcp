//! Feature matrix for the `hw-*` A/B sweep. Spec §9.
//!
//! Each [`Config`] names:
//!
//! - `name` — the value emitted as the `feature_set` CSV column and
//!   used as the human-readable key in the report table.
//! - `features` — the cargo feature list passed to `cargo build
//!   --no-default-features --features <…>` when rebuilding
//!   `bench-ab-runner` for this slot. Empty → pure baseline
//!   (`--no-default-features` only).
//! - `is_baseline` — true only for the `baseline` row. Used by the
//!   report writer to pick the reference p99 for delta computation.
//! - `is_full` — true only for the `full` row. Used by the sanity
//!   invariant check.
//!
//! The type is deliberately not a hand-coded `enum`: T11 (`bench-obs-
//! overhead`) reuses the driver plumbing with a different matrix
//! (`obs-none`, `poll-saturation-only`, `byte-counters-only`, etc.),
//! so exposing a generic `Config` lets T11 define its own `MATRIX`
//! slice without touching this file.

/// One row of a feature-matrix A/B sweep.
///
/// Plain-data struct — no methods beyond `features_as_cli_string` (a
/// tiny join helper the main driver uses to shell out to cargo). All
/// decision / reporting logic lives elsewhere so this module stays a
/// near-pure declaration of the spec §9 matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Config label (e.g. `"baseline"`, `"tx-cksum-only"`, `"full"`).
    /// Emitted as the `feature_set` CSV column by `bench-ab-runner`.
    pub name: &'static str,
    /// Cargo feature flag names to pass verbatim to `--features`. Empty
    /// for the `baseline` row (which uses `--no-default-features` and
    /// no feature additions).
    pub features: &'static [&'static str],
    /// Marker bit the report writer uses to locate the baseline row.
    /// Exactly one `Config` in a matrix must have this true.
    pub is_baseline: bool,
    /// Marker bit the sanity invariant uses to locate the full-offload
    /// row. At most one `Config` in a matrix must have this true —
    /// `obs-*` matrices won't have a "full" equivalent and leave it
    /// false everywhere, which skips the sanity check.
    pub is_full: bool,
}

impl Config {
    /// Comma-join `features` for `cargo build --features <…>`. Returns
    /// `""` for the baseline row — the caller must detect the empty
    /// return and omit `--features` (cargo rejects an empty flag value).
    pub fn features_as_cli_string(&self) -> String {
        self.features.join(",")
    }
}

/// The spec §9 eight-config matrix for the `hw-*` A/B sweep.
///
/// `baseline` is the reference row; `full` is the compose-everything
/// row the sanity invariant targets; every other row is a
/// single-feature experiment.
///
/// Pair ordering matters for the report: the driver writes the CSV
/// rows in this order, and the reviewer reads the table top-to-bottom.
/// Baseline first so a reviewer sees the reference number before any
/// delta row; `full` last so the compose-result is the terminal line.
pub const HW_OFFLOAD_MATRIX: &[Config] = &[
    Config {
        name: "baseline",
        features: &[],
        is_baseline: true,
        is_full: false,
    },
    Config {
        name: "tx-cksum-only",
        features: &["hw-offload-tx-cksum"],
        is_baseline: false,
        is_full: false,
    },
    Config {
        name: "rx-cksum-only",
        features: &["hw-offload-rx-cksum"],
        is_baseline: false,
        is_full: false,
    },
    Config {
        name: "mbuf-fast-free-only",
        features: &["hw-offload-mbuf-fast-free"],
        is_baseline: false,
        is_full: false,
    },
    Config {
        name: "rss-hash-only",
        features: &["hw-offload-rss-hash"],
        is_baseline: false,
        is_full: false,
    },
    Config {
        name: "rx-timestamp-only",
        features: &["hw-offload-rx-timestamp"],
        is_baseline: false,
        is_full: false,
    },
    Config {
        name: "llq-verify-only",
        features: &["hw-verify-llq"],
        is_baseline: false,
        is_full: false,
    },
    Config {
        name: "full",
        features: &["hw-offloads-all"],
        is_baseline: false,
        is_full: true,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §9 says exactly 8 configs.
    #[test]
    fn hw_offload_matrix_has_eight_configs() {
        assert_eq!(HW_OFFLOAD_MATRIX.len(), 8);
    }

    /// Exactly one baseline row.
    #[test]
    fn hw_offload_matrix_has_exactly_one_baseline() {
        let baselines: Vec<_> = HW_OFFLOAD_MATRIX.iter().filter(|c| c.is_baseline).collect();
        assert_eq!(baselines.len(), 1);
        assert_eq!(baselines[0].name, "baseline");
        assert!(baselines[0].features.is_empty(), "baseline has no features");
    }

    /// Exactly one full-offload row.
    #[test]
    fn hw_offload_matrix_has_exactly_one_full() {
        let fulls: Vec<_> = HW_OFFLOAD_MATRIX.iter().filter(|c| c.is_full).collect();
        assert_eq!(fulls.len(), 1);
        assert_eq!(fulls[0].name, "full");
        assert_eq!(fulls[0].features, &["hw-offloads-all"]);
    }

    /// Config names are unique — the feature_set column is the row
    /// key in the report.
    #[test]
    fn hw_offload_matrix_names_are_unique() {
        let mut names: Vec<_> = HW_OFFLOAD_MATRIX.iter().map(|c| c.name).collect();
        names.sort_unstable();
        let len_before = names.len();
        names.dedup();
        assert_eq!(names.len(), len_before);
    }

    /// baseline row yields the empty string → main driver omits
    /// --features (cargo rejects `--features ""`).
    #[test]
    fn baseline_features_cli_string_is_empty() {
        let b = HW_OFFLOAD_MATRIX.iter().find(|c| c.is_baseline).unwrap();
        assert_eq!(b.features_as_cli_string(), "");
    }

    /// Single-feature rows yield exactly that feature.
    #[test]
    fn single_feature_configs_emit_single_feature() {
        let tx = HW_OFFLOAD_MATRIX
            .iter()
            .find(|c| c.name == "tx-cksum-only")
            .unwrap();
        assert_eq!(tx.features_as_cli_string(), "hw-offload-tx-cksum");
    }

    /// The hw-* flag names match `crates/dpdk-net-core/Cargo.toml`
    /// exactly. If any of these drift the matrix silently compiles
    /// with the wrong flag set and the A/B sweep becomes meaningless.
    #[test]
    fn hw_offload_matrix_uses_canonical_flag_names() {
        let canonical: &[&str] = &[
            "hw-offload-tx-cksum",
            "hw-offload-rx-cksum",
            "hw-offload-mbuf-fast-free",
            "hw-offload-rss-hash",
            "hw-offload-rx-timestamp",
            "hw-verify-llq",
            "hw-offloads-all",
        ];
        for cfg in HW_OFFLOAD_MATRIX {
            for f in cfg.features {
                assert!(
                    canonical.contains(f),
                    "feature {f} on row {} is not in the canonical hw-* flag set",
                    cfg.name,
                );
            }
        }
    }
}
