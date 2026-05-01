//! Observability-overhead Markdown writer. Spec §10.
//!
//! The obs-overhead report has a different column shape from the spec
//! §9 offload-ab report:
//!
//! ```text
//! | Config | Features | p50 | p99 | p999 | delta_p99 vs obs-none | Decision | Default | Action (if fail) |
//! ```
//!
//! — specifically:
//!
//! - `delta_p99` is measured against `obs-none` (the floor), not a
//!   `baseline` row;
//! - a `Default` column surfaces each row's production-default state so
//!   a reviewer can tell at a glance whether a Signal demands a
//!   remediation action;
//! - an `Action (if fail)` column is emitted empty in the generated
//!   report — it's a **human-filled** field, surfaced as a placeholder
//!   so the reviewer knows where to write their `batch` / `remove` /
//!   `flip default` / `move off hot path` decision.
//!
//! Every other pipeline stage (CSV aggregation, decision rule,
//! noise-floor source) reuses `bench-offload-ab`'s library surface.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use bench_offload_ab::decision::{classify, DecisionRule, Outcome};
use bench_offload_ab::report::Aggregated;

use crate::decision::ObsFloorSanity;
use crate::matrix::{ObsRow, DEFAULT_NAME, OBS_NONE_NAME};

/// One rendered row in the obs-overhead Markdown table.
///
/// The floor row (`obs-none`) has `delta_p99_vs_obs_none_ns = None` and
/// `outcome = None` — the driver renders those as `—` (U+2014 em dash,
/// matching T10). Every other row carries a signed delta and a
/// classify-verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct ObsReportRow {
    pub config_name: String,
    pub features: String,
    pub p50_ns: f64,
    pub p99_ns: f64,
    pub p999_ns: f64,
    /// `Some(delta)` for non-floor rows; `None` for the `obs-none` row
    /// itself. Sign convention: `delta = row_p99 - obs_none_p99` —
    /// positive means the row is SLOWER than the floor (the expected
    /// direction for an observability cost).
    pub delta_p99_vs_obs_none_ns: Option<f64>,
    /// `Some(Outcome)` for non-floor rows; `None` for the floor itself.
    pub outcome: Option<Outcome>,
    /// Rendered as-is under the "Default" column.
    pub default_label: &'static str,
    /// True iff this row's corresponding production feature(s) ship
    /// default-ON AND the row `outcome` is `Signal`. The reviewer uses
    /// this to decide whether the "Action (if fail)" cell demands a
    /// remediation choice (batch / remove / flip default / move off
    /// hot path). Stored on the row so the Markdown writer doesn't
    /// have to re-derive it from `default_label` + `outcome`.
    pub needs_action: bool,
}

/// Full obs-overhead run report. Mirrors T10's `RunReport` layout but
/// swaps in obs-specific sanity fields.
#[derive(Debug, Clone, PartialEq)]
pub struct ObsRunReport {
    pub run_id: String,
    pub date_iso8601: String,
    pub commit_sha: String,
    /// Clamped noise floor fed into the decision rule.
    pub noise_floor_ns: f64,
    /// Pre-clamp noise floor — surfaced so the reviewer can tell when
    /// a clamp fired (a quiet machine can collapse raw noise to ~0).
    pub noise_floor_raw_ns: f64,
    pub rule: DecisionRule,
    /// One entry per config in matrix order (obs-none first, default last).
    pub rows: Vec<ObsReportRow>,
    /// `Ok(())` if the obs-floor invariant held, `Err(diagnostic)` if
    /// any row undercut the floor. See
    /// [`crate::decision::check_obs_floor_sanity`].
    pub sanity_invariant: Result<(), String>,
    /// `obs-none` p99, ns. `None` if the aggregated data was missing
    /// the `obs-none` row (hard failure — the whole report is nearly
    /// meaningless in that case).
    pub obs_none_p99_ns: Option<f64>,
    /// Config names that undercut the `obs-none` floor and their p99s.
    /// Empty on a clean run.
    pub violators: Vec<(String, f64)>,
    /// Workload string — `"128 B / 128 B request-response, N=..., warmup=..."`.
    pub workload: String,
    /// Git log of commits in the sweep (oneline). Empty string → no
    /// repo / command failure.
    pub git_log: String,
    /// Path (relative or absolute) to the accumulated CSV.
    pub csv_path: String,
}

/// Turn a `(matrix, agg, rule, sanity)` quadruple into `ObsReportRow`s in
/// matrix order. `obs-none`'s row has `delta_p99_vs_obs_none_ns = None`;
/// every other row carries the signed delta.
///
/// Returns `Err` if `obs-none` is missing from `agg` (cannot compute
/// deltas without a floor). Missing non-floor rows are silently skipped
/// in the output (the upstream driver logs the skip separately).
pub fn build_obs_report_rows(
    matrix: &[ObsRow],
    agg: &BTreeMap<String, Aggregated>,
    rule: &DecisionRule,
) -> Result<Vec<ObsReportRow>, String> {
    let obs_none_agg = agg
        .get(OBS_NONE_NAME)
        .ok_or_else(|| format!("aggregated data missing obs-none floor row '{OBS_NONE_NAME}'"))?;
    let floor_p99 = obs_none_agg.p99_ns;

    let mut out = Vec::with_capacity(matrix.len());
    for row in matrix {
        let a = match agg.get(row.config.name) {
            Some(a) => a,
            None => continue,
        };
        let (delta, outcome) = if row.config.name == OBS_NONE_NAME {
            (None, None)
        } else {
            // Sign convention: delta_p99 = row - obs-none. Positive =
            // observability adds cost (expected direction). Negative =
            // row is CHEAPER than obs-none (floor violation — caught
            // separately by check_obs_floor_sanity, reported here as
            // a negative delta for the reviewer to see).
            let delta = a.p99_ns - floor_p99;
            // The T10 `classify` takes (baseline_p99, with_offload_p99)
            // where `delta = baseline - with_offload` and Signal fires
            // when the offload `REDUCES` cost. For obs we want the
            // OPPOSITE direction: Signal fires when observability ADDS
            // cost, i.e. when `delta = row - obs_none > 3*noise_floor`.
            // Pass `(row_p99, obs_none_p99)` so `classify` computes
            // `delta = row - obs_none` and fires Signal on the correct
            // sign.
            let out = classify(a.p99_ns, floor_p99, rule);
            (Some(delta), Some(out))
        };
        let needs_action = matches!(
            (row.default_state, outcome),
            (crate::matrix::DefaultState::On, Some(Outcome::Signal))
        );
        out.push(ObsReportRow {
            config_name: row.config.name.to_string(),
            features: if row.config.features.is_empty() {
                if row.config.name == DEFAULT_NAME {
                    "(prod default)".to_string()
                } else {
                    "(none)".to_string()
                }
            } else {
                row.config.features.join(",")
            },
            p50_ns: a.p50_ns,
            p99_ns: a.p99_ns,
            p999_ns: a.p999_ns,
            delta_p99_vs_obs_none_ns: delta,
            outcome,
            default_label: row.default_state.label(),
            needs_action,
        });
    }
    Ok(out)
}

/// Emit the spec §10 Markdown report to `path`. Overwrites any
/// existing file.
pub fn write_obs_markdown_report(path: &Path, report: &ObsRunReport) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::File::create(path)?;
    render_obs(&mut f, report)
}

/// Render `report` as Markdown into `w`. Split from
/// `write_obs_markdown_report` so tests can render to a `Vec<u8>`
/// without a tempfile.
pub fn render_obs<W: Write>(w: &mut W, report: &ObsRunReport) -> std::io::Result<()> {
    writeln!(w, "# Observability Overhead Report")?;
    writeln!(w)?;
    writeln!(w, "Run: {}", report.run_id)?;
    writeln!(w, "Date: {}", report.date_iso8601)?;
    writeln!(w, "Commit: {}", report.commit_sha)?;
    writeln!(w, "Workload: {}", report.workload)?;
    writeln!(w)?;
    writeln!(w, "## Summary Table")?;
    writeln!(w)?;
    writeln!(
        w,
        "| Config | Features | p50 (ns) | p99 (ns) | p999 (ns) | delta_p99 vs obs-none | Decision | Default | Action (if fail) |"
    )?;
    writeln!(w, "|---|---|---|---|---|---|---|---|---|")?;
    for row in &report.rows {
        let delta_str = match row.delta_p99_vs_obs_none_ns {
            Some(d) => format!("{d:.2} ns"),
            None => "—".to_string(),
        };
        let decision_str = match row.outcome {
            Some(Outcome::Signal) => "**Signal**".to_string(),
            Some(Outcome::NoSignal) => "NoSignal".to_string(),
            None => "—".to_string(),
        };
        // Action cell is always rendered empty in the generated report
        // — it's a human-filled field. The reviewer writes one of
        // `batch` / `remove` / `flip default` / `move off hot path`
        // in a follow-up commit when `needs_action` is true. When
        // `needs_action` is false the cell stays `—`.
        let action_str = if row.needs_action {
            "(fill in)".to_string()
        } else {
            "—".to_string()
        };
        writeln!(
            w,
            "| {} | {} | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} |",
            row.config_name,
            row.features,
            row.p50_ns,
            row.p99_ns,
            row.p999_ns,
            delta_str,
            decision_str,
            row.default_label,
            action_str,
        )?;
    }
    writeln!(w)?;
    writeln!(
        w,
        "Noise floor (2 back-to-back obs-none runs, |p99 delta|): {:.2} ns (raw); {:.2} ns (clamped)",
        report.noise_floor_raw_ns, report.noise_floor_ns
    )?;
    writeln!(
        w,
        "Decision threshold (3 × clamped noise floor): {:.2} ns",
        3.0 * report.noise_floor_ns
    )?;
    writeln!(w)?;
    writeln!(w, "## Sanity Invariant")?;
    writeln!(w)?;
    match &report.obs_none_p99_ns {
        Some(floor) => {
            writeln!(w, "Lowest p99 (obs-none): {floor:.2} ns")?;
            if report.violators.is_empty() {
                writeln!(w, "Any p99 < {floor:.2} ns? NO -> OK")?;
            } else {
                writeln!(
                    w,
                    "Any p99 < {:.2} ns? YES -> VIOLATION (an observable \
                     is either dead code, a regression, or inside the noise floor)",
                    floor
                )?;
                for (name, p99) in &report.violators {
                    writeln!(w, "- {name}: p99 = {p99:.2} ns")?;
                }
                if let Err(msg) = &report.sanity_invariant {
                    writeln!(w)?;
                    writeln!(w, "Diagnostic: {msg}")?;
                }
            }
        }
        None => {
            writeln!(
                w,
                "n/a (aggregated data missing `obs-none` floor row — cannot validate the floor invariant)"
            )?;
        }
    }
    writeln!(w)?;
    writeln!(w, "## Decision → Action Recommendations")?;
    writeln!(w)?;
    writeln!(
        w,
        "For each Signal with default=ON, the implementer reviews the \
         table and picks one of the action-taxonomy options in a \
         follow-up commit, NOT automated by the harness:"
    )?;
    writeln!(w)?;
    writeln!(w, "- **batch** — accumulate the increment in a per-poll local and `fetch_add` once per `poll_once`")?;
    writeln!(w, "- **remove** — eliminate the counter entirely")?;
    writeln!(w, "- **flip default** — move the feature from default-ON to default-OFF (opt-in)")?;
    writeln!(w, "- **move off hot path** — relocate the emission to a slow-path decision point")?;
    writeln!(w)?;
    // Surface the exact rows that need an action so the reviewer has a
    // checklist to work from.
    let needing_action: Vec<&ObsReportRow> = report.rows.iter().filter(|r| r.needs_action).collect();
    if needing_action.is_empty() {
        writeln!(w, "No Signal + default=ON rows this run — no action required.")?;
    } else {
        writeln!(w, "Rows demanding an action this run:")?;
        for r in &needing_action {
            let d = r
                .delta_p99_vs_obs_none_ns
                .map(|d| format!("{d:.2} ns"))
                .unwrap_or_else(|| "n/a".to_string());
            writeln!(
                w,
                "- **{}** (delta_p99 = {d}) — features `{}`",
                r.config_name, r.features,
            )?;
        }
    }
    writeln!(w)?;
    writeln!(w, "## Commit History")?;
    writeln!(w)?;
    if report.git_log.is_empty() {
        writeln!(w, "(git log unavailable)")?;
    } else {
        writeln!(w, "```")?;
        writeln!(w, "{}", report.git_log.trim_end())?;
        writeln!(w, "```")?;
    }
    writeln!(w)?;
    writeln!(w, "## Full CSV")?;
    writeln!(w)?;
    writeln!(w, "See `{}`.", report.csv_path)?;
    Ok(())
}

/// Combine `sanity` + `rows` into an `ObsRunReport`, plus all the
/// per-run metadata. Thin constructor so the main-binary code stays
/// declarative.
#[allow(clippy::too_many_arguments)]
pub fn assemble_run_report(
    run_id: String,
    date_iso8601: String,
    commit_sha: String,
    noise_floor_raw_ns: f64,
    noise_floor_ns: f64,
    rule: DecisionRule,
    rows: Vec<ObsReportRow>,
    sanity: ObsFloorSanity,
    workload: String,
    git_log: String,
    csv_path: String,
) -> ObsRunReport {
    ObsRunReport {
        run_id,
        date_iso8601,
        commit_sha,
        noise_floor_ns,
        noise_floor_raw_ns,
        rule,
        rows,
        sanity_invariant: sanity.verdict,
        obs_none_p99_ns: sanity.obs_none_p99_ns,
        violators: sanity.violators,
        workload,
        git_log,
        csv_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::check_obs_floor_sanity;
    use crate::matrix::OBS_MATRIX;

    fn agg_of(pairs: &[(&str, f64, f64, f64)]) -> BTreeMap<String, Aggregated> {
        pairs
            .iter()
            .map(|(n, p50, p99, p999)| {
                (
                    (*n).to_string(),
                    Aggregated {
                        p50_ns: *p50,
                        p99_ns: *p99,
                        p999_ns: *p999,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn build_rows_places_obs_none_first_and_marks_delta_none() {
        let agg = agg_of(&[
            ("obs-none", 50.0, 78.0, 150.0),
            ("poll-saturation-only", 52.0, 86.0, 160.0),
            ("byte-counters-only", 60.0, 100.0, 180.0),
            ("obs-all-no-none", 65.0, 110.0, 200.0),
            ("default", 55.0, 86.0, 165.0),
        ]);
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let rows = build_obs_report_rows(OBS_MATRIX, &agg, &rule).unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].config_name, "obs-none");
        assert!(rows[0].delta_p99_vs_obs_none_ns.is_none());
        assert!(rows[0].outcome.is_none());
        // poll-saturation-only: delta = 86 - 78 = 8; 3*noise = 15; 8 < 15 → NoSignal.
        assert_eq!(rows[1].config_name, "poll-saturation-only");
        assert_eq!(rows[1].delta_p99_vs_obs_none_ns, Some(8.0));
        assert_eq!(rows[1].outcome, Some(Outcome::NoSignal));
        assert_eq!(rows[1].default_label, "ON");
        assert!(!rows[1].needs_action, "8ns NoSignal → no action");
        // byte-counters-only: delta = 100 - 78 = 22; 22 > 15 → Signal; default=OFF → no action.
        assert_eq!(rows[2].config_name, "byte-counters-only");
        assert_eq!(rows[2].outcome, Some(Outcome::Signal));
        assert_eq!(rows[2].default_label, "OFF");
        assert!(
            !rows[2].needs_action,
            "Signal with default=OFF is informational only"
        );
    }

    #[test]
    fn build_rows_marks_needs_action_on_default_on_signal() {
        // Force poll-saturation-only (default=ON) over the threshold → Signal → needs_action.
        let agg = agg_of(&[
            ("obs-none", 50.0, 78.0, 150.0),
            ("poll-saturation-only", 60.0, 120.0, 200.0),
            ("byte-counters-only", 60.0, 100.0, 180.0),
            ("obs-all-no-none", 65.0, 130.0, 220.0),
            ("default", 55.0, 120.0, 200.0),
        ]);
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let rows = build_obs_report_rows(OBS_MATRIX, &agg, &rule).unwrap();
        let poll = rows
            .iter()
            .find(|r| r.config_name == "poll-saturation-only")
            .unwrap();
        assert_eq!(poll.outcome, Some(Outcome::Signal));
        assert_eq!(poll.default_label, "ON");
        assert!(
            poll.needs_action,
            "default=ON + Signal must mark needs_action"
        );
    }

    #[test]
    fn build_rows_errors_on_missing_floor() {
        let agg = agg_of(&[("poll-saturation-only", 52.0, 86.0, 160.0)]);
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let err = build_obs_report_rows(OBS_MATRIX, &agg, &rule).unwrap_err();
        assert!(
            err.contains("obs-none"),
            "missing floor err must mention obs-none: {err}"
        );
    }

    #[test]
    fn render_contains_all_spec_sections() {
        let agg = agg_of(&[
            ("obs-none", 50.0, 78.0, 150.0),
            ("poll-saturation-only", 52.0, 86.0, 160.0),
            ("byte-counters-only", 60.0, 103.0, 180.0),
            ("obs-all-no-none", 65.0, 112.0, 200.0),
            ("default", 55.0, 86.0, 165.0),
        ]);
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let rows = build_obs_report_rows(OBS_MATRIX, &agg, &rule).unwrap();
        let sanity = check_obs_floor_sanity(OBS_MATRIX, &agg);
        let report = assemble_run_report(
            "rid".into(),
            "2026-04-22T03:14:07Z".into(),
            "abc".into(),
            3.0,
            5.0,
            rule,
            rows,
            sanity,
            "128 B / 128 B request-response, N=10000, warmup=1000".into(),
            "abc hello".into(),
            "out.csv".into(),
        );
        let mut buf = Vec::new();
        render_obs(&mut buf, &report).unwrap();
        let md = std::str::from_utf8(&buf).unwrap();

        // Header + summary table exist.
        assert!(md.contains("# Observability Overhead Report"));
        assert!(md.contains("## Summary Table"));
        // Column header uses obs-none (not baseline).
        assert!(md.contains("delta_p99 vs obs-none"));
        assert!(md.contains("Default"));
        assert!(md.contains("Action (if fail)"));
        // Every config name appears in a table row.
        assert!(md.contains("| obs-none | obs-none |"));
        assert!(md.contains("| poll-saturation-only | obs-poll-saturation |"));
        assert!(md.contains("| byte-counters-only | obs-byte-counters |"));
        assert!(md.contains("| obs-all-no-none | obs-all |"));
        assert!(md.contains("| default | (prod default) |"));
        // Noise floor + clamp.
        assert!(md.contains("Noise floor"));
        assert!(md.contains("raw"));
        assert!(md.contains("clamped"));
        // Decision threshold.
        assert!(md.contains("Decision threshold (3 × clamped noise floor): 15.00 ns"));
        // Sanity section with floor-vs-minimum check.
        assert!(md.contains("## Sanity Invariant"));
        assert!(md.contains("Lowest p99 (obs-none):"));
        assert!(md.contains("NO -> OK"));
        // Action recommendations block.
        assert!(md.contains("## Decision → Action Recommendations"));
        assert!(md.contains("batch"));
        assert!(md.contains("remove"));
        assert!(md.contains("flip default"));
        assert!(md.contains("move off hot path"));
    }

    #[test]
    fn render_marks_violation_section() {
        // poll-saturation-only UNDER floor → violation.
        let agg = agg_of(&[
            ("obs-none", 50.0, 78.0, 150.0),
            ("poll-saturation-only", 40.0, 70.0, 100.0),
            ("byte-counters-only", 60.0, 103.0, 180.0),
            ("obs-all-no-none", 65.0, 112.0, 200.0),
            ("default", 55.0, 86.0, 165.0),
        ]);
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let rows = build_obs_report_rows(OBS_MATRIX, &agg, &rule).unwrap();
        let sanity = check_obs_floor_sanity(OBS_MATRIX, &agg);
        assert!(sanity.verdict.is_err(), "fixture violates floor");
        let report = assemble_run_report(
            "rid".into(),
            "d".into(),
            "c".into(),
            5.0,
            5.0,
            rule,
            rows,
            sanity,
            "w".into(),
            String::new(),
            "out.csv".into(),
        );
        let mut buf = Vec::new();
        render_obs(&mut buf, &report).unwrap();
        let md = std::str::from_utf8(&buf).unwrap();
        assert!(md.contains("VIOLATION"), "violation header missing:\n{md}");
        assert!(
            md.contains("poll-saturation-only"),
            "violator name missing:\n{md}"
        );
    }

    #[test]
    fn render_lists_rows_needing_action() {
        // poll-saturation-only (default=ON) shows Signal → must appear in the action checklist.
        let agg = agg_of(&[
            ("obs-none", 50.0, 78.0, 150.0),
            ("poll-saturation-only", 60.0, 120.0, 200.0),
            ("byte-counters-only", 60.0, 103.0, 180.0),
            ("obs-all-no-none", 65.0, 130.0, 220.0),
            ("default", 55.0, 120.0, 200.0),
        ]);
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let rows = build_obs_report_rows(OBS_MATRIX, &agg, &rule).unwrap();
        let sanity = check_obs_floor_sanity(OBS_MATRIX, &agg);
        let report = assemble_run_report(
            "rid".into(),
            "d".into(),
            "c".into(),
            3.0,
            5.0,
            rule,
            rows,
            sanity,
            "w".into(),
            String::new(),
            "out.csv".into(),
        );
        let mut buf = Vec::new();
        render_obs(&mut buf, &report).unwrap();
        let md = std::str::from_utf8(&buf).unwrap();
        assert!(
            md.contains("Rows demanding an action this run:"),
            "action-list header missing:\n{md}"
        );
        assert!(
            md.contains("**poll-saturation-only**"),
            "poll-sat row in action list missing:\n{md}"
        );
    }

    #[test]
    fn render_reports_clean_run_when_no_actions_needed() {
        let agg = agg_of(&[
            ("obs-none", 50.0, 78.0, 150.0),
            ("poll-saturation-only", 52.0, 86.0, 160.0),
            ("byte-counters-only", 60.0, 103.0, 180.0),
            ("obs-all-no-none", 65.0, 112.0, 200.0),
            ("default", 55.0, 86.0, 165.0),
        ]);
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let rows = build_obs_report_rows(OBS_MATRIX, &agg, &rule).unwrap();
        let sanity = check_obs_floor_sanity(OBS_MATRIX, &agg);
        let report = assemble_run_report(
            "rid".into(),
            "d".into(),
            "c".into(),
            3.0,
            5.0,
            rule,
            rows,
            sanity,
            "w".into(),
            String::new(),
            "out.csv".into(),
        );
        let mut buf = Vec::new();
        render_obs(&mut buf, &report).unwrap();
        let md = std::str::from_utf8(&buf).unwrap();
        assert!(
            md.contains("No Signal + default=ON rows this run"),
            "clean-run message missing:\n{md}"
        );
    }
}
