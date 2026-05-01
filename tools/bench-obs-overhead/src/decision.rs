//! Obs-specific sanity wrapper over
//! [`bench_offload_ab::decision::check_observability_invariant`].
//!
//! The pure pairwise predicate lives in `bench-offload-ab` (symmetric
//! with `check_sanity_invariant` for the hw-* matrix). This wrapper
//! does the matrix-level work:
//!
//! 1. Locate the `obs-none` row's aggregated p99.
//! 2. For every other row in the matrix, call the pairwise predicate
//!    against the floor.
//! 3. Collect all violations into a single diagnostic (rather than
//!    bailing on the first one — the reviewer wants to see every row
//!    that undercuts the floor, not just the first).
//!
//! A dedicated module (rather than inlining in `report.rs`) so the
//! unit tests can exercise the floor-selection / multi-violation
//! surfaces without touching the Markdown writer.

use std::collections::BTreeMap;

use bench_offload_ab::decision::check_observability_invariant;
use bench_offload_ab::report::Aggregated;

use crate::matrix::{ObsRow, OBS_NONE_NAME};

/// Outcome of [`check_obs_floor_sanity`] — the verdict plus the p99
/// values that produced it, for inclusion in the Markdown report even
/// when the invariant held.
///
/// Named-struct form (rather than a tuple) so the report writer can
/// read fields by name — mirrors `bench_offload_ab::report::SanityReport`.
#[derive(Debug, Clone, PartialEq)]
pub struct ObsFloorSanity {
    /// `Ok(())` if every non-`obs-none` row's p99 >= `obs-none` p99
    /// (or the matrix / aggregated data is missing `obs-none`, in
    /// which case the check is skipped with a diagnostic so the
    /// report surfaces the missing row clearly).
    pub verdict: Result<(), String>,
    /// The `obs-none` p99 that served as the floor reference. `None` if
    /// the aggregated data didn't contain an `obs-none` row (which is
    /// itself a hard failure the caller reports separately — we return
    /// None here rather than an Err so the caller can distinguish "no
    /// floor data" from "floor data present but violated").
    pub obs_none_p99_ns: Option<f64>,
    /// List of rows that undercut the floor — `(config_name, p99)`.
    /// Empty if the invariant held.
    pub violators: Vec<(String, f64)>,
}

/// Apply the spec §10 floor invariant to an aggregated matrix.
///
/// The invariant is pairwise: for every non-`obs-none` row in the
/// matrix, its p99 must be `>=` the `obs-none` row's p99. See
/// [`check_observability_invariant`] for the rationale (observability
/// can only add cost, not save it).
///
/// # Shape of return
///
/// - `ObsFloorSanity { verdict: Ok(()), obs_none_p99_ns: Some(_), violators: [] }`
///   — every row passed. Typical.
/// - `ObsFloorSanity { verdict: Err(multi-line), obs_none_p99_ns: Some(_), violators: [..] }`
///   — one or more rows undercut the floor. The `verdict` is a single
///   string containing every violating row's per-pair diagnostic
///   (joined with `; `) so the operator sees everything in one place.
/// - `ObsFloorSanity { verdict: Err("aggregated data missing obs-none"), obs_none_p99_ns: None, violators: [] }`
///   — the floor row itself is missing; can't do any comparison.
///
/// Skips rows that aren't in `agg` (a row missing from the aggregated
/// data most likely means the per-config subprocess bailed; the main
/// driver logs that separately and this function doesn't re-diagnose).
pub fn check_obs_floor_sanity(
    matrix: &[ObsRow],
    agg: &BTreeMap<String, Aggregated>,
) -> ObsFloorSanity {
    let obs_none_p99 = match agg.get(OBS_NONE_NAME) {
        Some(a) => a.p99_ns,
        None => {
            return ObsFloorSanity {
                verdict: Err(format!(
                    "aggregated data missing obs-none floor row '{OBS_NONE_NAME}'; \
                     cannot validate observability floor invariant"
                )),
                obs_none_p99_ns: None,
                violators: Vec::new(),
            };
        }
    };

    let mut violators: Vec<(String, f64)> = Vec::new();
    let mut diagnostics: Vec<String> = Vec::new();
    for row in matrix {
        if row.config.name == OBS_NONE_NAME {
            continue;
        }
        let this = match agg.get(row.config.name) {
            Some(a) => a,
            None => continue, // missing — caller diagnoses separately
        };
        if let Err(msg) = check_observability_invariant(this.p99_ns, row.config.name, obs_none_p99)
        {
            violators.push((row.config.name.to_string(), this.p99_ns));
            diagnostics.push(msg);
        }
    }

    let verdict = if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(diagnostics.join("; "))
    };
    ObsFloorSanity {
        verdict,
        obs_none_p99_ns: Some(obs_none_p99),
        violators,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix::OBS_MATRIX;

    fn agg_of(pairs: &[(&str, f64)]) -> BTreeMap<String, Aggregated> {
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

    #[test]
    fn sanity_ok_when_every_row_above_floor() {
        let agg = agg_of(&[
            ("obs-none", 78.3),
            ("poll-saturation-only", 86.1),
            ("byte-counters-only", 103.2),
            ("obs-all-no-none", 112.5),
            ("default", 86.2),
        ]);
        let s = check_obs_floor_sanity(OBS_MATRIX, &agg);
        assert!(s.verdict.is_ok(), "every row >= floor → ok");
        assert_eq!(s.obs_none_p99_ns, Some(78.3));
        assert!(s.violators.is_empty());
    }

    #[test]
    fn sanity_ok_on_equality() {
        // Every row ties the floor — still ok.
        let agg = agg_of(&[
            ("obs-none", 78.3),
            ("poll-saturation-only", 78.3),
            ("byte-counters-only", 78.3),
            ("obs-all-no-none", 78.3),
            ("default", 78.3),
        ]);
        let s = check_obs_floor_sanity(OBS_MATRIX, &agg);
        assert!(s.verdict.is_ok());
    }

    #[test]
    fn sanity_violation_when_any_row_below_floor() {
        // poll-saturation-only is BELOW obs-none — impossible if obs is
        // actually adding cost. Flag.
        let agg = agg_of(&[
            ("obs-none", 78.3),
            ("poll-saturation-only", 74.0),
            ("byte-counters-only", 103.2),
            ("obs-all-no-none", 112.5),
            ("default", 86.2),
        ]);
        let s = check_obs_floor_sanity(OBS_MATRIX, &agg);
        let err = s.verdict.unwrap_err();
        assert!(
            err.contains("poll-saturation-only"),
            "violator name in err: {err}"
        );
        assert_eq!(s.obs_none_p99_ns, Some(78.3));
        assert_eq!(s.violators.len(), 1);
        assert_eq!(s.violators[0].0, "poll-saturation-only");
        assert_eq!(s.violators[0].1, 74.0);
    }

    #[test]
    fn sanity_collects_multiple_violators() {
        // Two rows undercut the floor → verdict mentions both.
        let agg = agg_of(&[
            ("obs-none", 78.3),
            ("poll-saturation-only", 70.0),
            ("byte-counters-only", 75.0),
            ("obs-all-no-none", 90.0),
            ("default", 85.0),
        ]);
        let s = check_obs_floor_sanity(OBS_MATRIX, &agg);
        let err = s.verdict.unwrap_err();
        assert!(err.contains("poll-saturation-only"));
        assert!(err.contains("byte-counters-only"));
        assert_eq!(s.violators.len(), 2);
    }

    #[test]
    fn sanity_errors_when_obs_none_row_missing_from_agg() {
        // obs-none missing from aggregated data — the whole check is
        // undefined (no floor reference).
        let agg = agg_of(&[
            ("poll-saturation-only", 74.0),
            ("byte-counters-only", 80.0),
        ]);
        let s = check_obs_floor_sanity(OBS_MATRIX, &agg);
        let err = s.verdict.unwrap_err();
        assert!(
            err.contains("missing obs-none"),
            "err should call out missing floor row: {err}"
        );
        assert!(s.obs_none_p99_ns.is_none());
        assert!(s.violators.is_empty());
    }

    /// Missing aggregated row for a non-floor config is tolerated —
    /// the driver logs that separately upstream.
    #[test]
    fn sanity_tolerates_missing_non_floor_row() {
        let agg = agg_of(&[
            ("obs-none", 78.3),
            ("poll-saturation-only", 86.1),
            // byte-counters-only, obs-all-no-none, default missing
        ]);
        let s = check_obs_floor_sanity(OBS_MATRIX, &agg);
        assert!(s.verdict.is_ok(), "missing non-floor rows aren't flagged here");
    }
}
