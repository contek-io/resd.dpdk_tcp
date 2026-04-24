//! Report aggregation + Markdown writer. Spec §9 output.
//!
//! Input: a `Vec<CsvRow>` accumulated across all per-config runner
//! invocations. Each `(feature_set, metric_aggregation)` pair yields
//! one row in the eventual table; the driver selected
//! `metric_name = "rtt_ns"` so every row in the input belongs to the
//! same metric.
//!
//! Pipeline:
//!
//! 1. [`aggregate_by_config`] — group rows by `feature_set` and pick
//!    out p50 / p99 / p999. The `bench-ab-runner` emits seven rows
//!    per config (p50 / p99 / p999 / mean / stddev / ci95_lo / ci95_hi);
//!    we keep the three percentiles.
//! 2. [`compute_deltas`] — for every non-baseline config, compute
//!    `delta_p99 = baseline_p99 − with_offload_p99`.
//! 3. [`classify_all`] — apply the spec §9 decision rule per non-
//!    baseline config.
//! 4. [`check_full_sanity`] — locate the `full` row and the best
//!    single-feature row; run [`decision::check_sanity_invariant`].
//! 5. [`write_markdown_report`] — emit the final committed report.
//!
//! Pure-data in and out of each step so the unit-test surface is
//! large and the orchestration in `main.rs` stays a thin sequence of
//! function calls.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use bench_common::csv_row::{CsvRow, MetricAggregation};

use crate::decision::{check_sanity_invariant, classify, DecisionRule, Outcome};
use crate::matrix::Config;

/// Per-config aggregated percentiles. One record per `feature_set`.
///
/// Kept minimal — p50/p99/p999 is what the report renders. Adding
/// mean/stddev later is a matter of expanding `aggregate_by_config`;
/// the CSV carries them already.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Aggregated {
    pub p50_ns: f64,
    pub p99_ns: f64,
    pub p999_ns: f64,
}

/// Report line for one non-baseline config — the row shape that
/// lands in the Markdown table.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportRow {
    pub config_name: String,
    pub features: String,
    pub p50_ns: f64,
    pub p99_ns: f64,
    pub p999_ns: f64,
    /// `Some(delta)` for non-baseline rows; `None` for the baseline
    /// row itself. The Markdown writer renders `None` as `—`.
    pub delta_p99_vs_baseline_ns: Option<f64>,
    /// `Some(Outcome)` for non-baseline rows; `None` for baseline
    /// (no comparison against itself).
    pub outcome: Option<Outcome>,
}

/// Summary of the run: every row, decision threshold, noise floor,
/// and the sanity invariant verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct RunReport {
    pub run_id: String,
    pub date_iso8601: String,
    pub commit_sha: String,
    /// The clamped noise floor fed into the decision rule. See
    /// [`noise_floor_raw_ns`] for the pre-clamp value — when the raw
    /// value is below [`crate::decision::DecisionRule`]'s lower bound
    /// the two differ and the report surfaces both to the operator.
    pub noise_floor_ns: f64,
    /// Pre-clamp noise floor (`|p99(baseline-noise-1) - p99(baseline-noise-2)|`)
    /// — the empirically observed p99 spread of two back-to-back baseline runs.
    /// On a quiet machine this can collapse to near zero, which would make
    /// `3 * noise_floor ~= 0` and every positive `delta_p99` read as Signal;
    /// the driver clamps to `MIN_NOISE_FLOOR_NS` before building the rule.
    /// Reporting both is how the reviewer sees that a clamp fired.
    pub noise_floor_raw_ns: f64,
    pub rule: DecisionRule,
    /// One entry per config in matrix order.
    pub rows: Vec<ReportRow>,
    /// `Ok(())` if the invariant held or the matrix had no `full`
    /// row. `Err(msg)` on violation — the caller uses this to flip
    /// the report's "Sanity Invariant" section to `VIOLATION`.
    pub sanity_invariant: Result<(), String>,
    /// The full-offload p99 used in the sanity check (if the matrix
    /// had a full row).
    pub full_p99_ns: Option<f64>,
    /// The best single-feature p99 used in the sanity check and the
    /// name of the config that produced it. `None` if the matrix
    /// had no non-baseline non-full rows.
    pub best_individual: Option<(String, f64)>,
    /// Workload string — `"128 B / 128 B request-response, N=..., warmup=..."`.
    pub workload: String,
    /// Git log of commits in the sweep (oneline). Empty string → no
    /// repo / command failure; the caller prints that verbatim.
    pub git_log: String,
    /// Path (relative or absolute) to the accumulated CSV, for the
    /// "Full CSV" reference section.
    pub csv_path: String,
}

/// Bucket `rows` by `feature_set` and pick p50 / p99 / p999 out of
/// the seven aggregations the runner emits per config.
///
/// Unknown aggregations (`Mean`, `Stddev`, `Ci95Lower`, `Ci95Upper`)
/// are skipped — they don't feed the report table today. Missing
/// percentiles → the config is dropped from the result with a
/// diagnostic so the caller fails loudly instead of silently
/// reporting on an incomplete sweep.
pub fn aggregate_by_config(
    rows: &[CsvRow],
) -> Result<BTreeMap<String, Aggregated>, String> {
    // (feature_set, aggregation) → value. Duplicate keys would mean
    // the runner emitted two percentiles for the same feature-set;
    // we keep the last, which matches the file-order behaviour of
    // csv::Reader.
    let mut p50_by: BTreeMap<String, f64> = BTreeMap::new();
    let mut p99_by: BTreeMap<String, f64> = BTreeMap::new();
    let mut p999_by: BTreeMap<String, f64> = BTreeMap::new();

    for row in rows {
        match row.metric_aggregation {
            MetricAggregation::P50 => {
                p50_by.insert(row.feature_set.clone(), row.metric_value);
            }
            MetricAggregation::P99 => {
                p99_by.insert(row.feature_set.clone(), row.metric_value);
            }
            MetricAggregation::P999 => {
                p999_by.insert(row.feature_set.clone(), row.metric_value);
            }
            _ => {}
        }
    }

    // Every config needs all three percentiles to make a row.
    let mut out: BTreeMap<String, Aggregated> = BTreeMap::new();
    for (name, p99) in p99_by.iter() {
        let p50 = match p50_by.get(name) {
            Some(v) => *v,
            None => return Err(format!("config {name} missing p50 row")),
        };
        let p999 = match p999_by.get(name) {
            Some(v) => *v,
            None => return Err(format!("config {name} missing p999 row")),
        };
        out.insert(
            name.clone(),
            Aggregated {
                p50_ns: p50,
                p99_ns: *p99,
                p999_ns: p999,
            },
        );
    }
    Ok(out)
}

/// Build the per-matrix report-row vector. Rows follow `matrix`
/// order (baseline first, full last). Any config that is missing
/// from the aggregated input is skipped with a diagnostic so the
/// caller can decide whether to abort.
///
/// Returns `Err` if the baseline row itself is missing — we cannot
/// compute deltas without it.
pub fn build_report_rows(
    matrix: &[Config],
    agg: &BTreeMap<String, Aggregated>,
    rule: &DecisionRule,
) -> Result<Vec<ReportRow>, String> {
    let baseline_cfg = matrix
        .iter()
        .find(|c| c.is_baseline)
        .ok_or_else(|| "matrix has no baseline row".to_string())?;
    let baseline_agg = agg
        .get(baseline_cfg.name)
        .ok_or_else(|| format!("aggregated data missing baseline {}", baseline_cfg.name))?;
    let baseline_p99 = baseline_agg.p99_ns;

    let mut rows = Vec::with_capacity(matrix.len());
    for cfg in matrix {
        let a = match agg.get(cfg.name) {
            Some(a) => a,
            None => continue, // missing config — skip; caller emits a diagnostic elsewhere
        };
        let (delta, outcome) = if cfg.is_baseline {
            (None, None)
        } else {
            let delta = baseline_p99 - a.p99_ns;
            let out = classify(baseline_p99, a.p99_ns, rule);
            (Some(delta), Some(out))
        };
        rows.push(ReportRow {
            config_name: cfg.name.to_string(),
            features: if cfg.features.is_empty() {
                "(none)".to_string()
            } else {
                cfg.features.join(",")
            },
            p50_ns: a.p50_ns,
            p99_ns: a.p99_ns,
            p999_ns: a.p999_ns,
            delta_p99_vs_baseline_ns: delta,
            outcome,
        });
    }
    Ok(rows)
}

/// Outcome of [`check_full_sanity`] — the verdict plus the p99
/// values that produced it, so the caller can surface them in the
/// report table even when the invariant held.
///
/// Named-struct form (vs. a triple) because the type-tuple triggered
/// clippy's `type_complexity` and because the main driver passes
/// every field verbatim into [`RunReport`] — the struct lets that
/// assignment read as `dest = src` per field instead of manual
/// positional unpacking.
#[derive(Debug, Clone, PartialEq)]
pub struct SanityReport {
    /// `Ok(())` if the invariant held (including the trivial cases:
    /// no `full` row in the matrix, or no single-feature rows to
    /// compare against). `Err(msg)` on violation.
    pub verdict: Result<(), String>,
    /// The `full` config's p99 (if the matrix had a full row).
    pub full_p99_ns: Option<f64>,
    /// `(config_name, p99)` of the best single-feature row. `None`
    /// if the matrix had no single-feature rows (trivially-ok case).
    pub best_individual: Option<(String, f64)>,
}

/// Apply the sanity invariant — locate the `full` row and the best
/// single-feature row, call [`check_sanity_invariant`], and return
/// a [`SanityReport`] with the verdict plus both p99s.
///
/// "Best single-feature" = min p99 over every matrix config that is
/// NOT baseline and NOT full. If the matrix has no full row the
/// check is skipped (returns `Ok(())`) — `obs-*` matrices (T11) may
/// not define a `full` row.
pub fn check_full_sanity(
    matrix: &[Config],
    agg: &BTreeMap<String, Aggregated>,
) -> SanityReport {
    let full_cfg = match matrix.iter().find(|c| c.is_full) {
        Some(c) => c,
        None => {
            return SanityReport {
                verdict: Ok(()),
                full_p99_ns: None,
                best_individual: None,
            };
        }
    };
    let full_agg = match agg.get(full_cfg.name) {
        Some(a) => a,
        None => {
            return SanityReport {
                verdict: Err(format!(
                    "aggregated data missing full config {}",
                    full_cfg.name
                )),
                full_p99_ns: None,
                best_individual: None,
            };
        }
    };
    let full_p99 = full_agg.p99_ns;

    // Best single-feature p99.
    let mut best: Option<(String, f64)> = None;
    for cfg in matrix {
        if cfg.is_baseline || cfg.is_full {
            continue;
        }
        if let Some(a) = agg.get(cfg.name) {
            match &best {
                None => best = Some((cfg.name.to_string(), a.p99_ns)),
                Some((_, b)) if a.p99_ns < *b => {
                    best = Some((cfg.name.to_string(), a.p99_ns));
                }
                _ => {}
            }
        }
    }

    match &best {
        Some((_, best_p99)) => SanityReport {
            verdict: check_sanity_invariant(full_p99, *best_p99),
            full_p99_ns: Some(full_p99),
            best_individual: best.clone(),
        },
        // No single-feature rows: matrix only has baseline + full,
        // which means the invariant trivially holds (nothing to
        // violate). Equivalent to Ok(()).
        None => SanityReport {
            verdict: Ok(()),
            full_p99_ns: Some(full_p99),
            best_individual: None,
        },
    }
}

/// Bucket `rows` by feature_set and compute `p99` per config. Useful
/// helper for the noise-floor computation in main.rs (two baseline
/// runs → the driver picks the two baseline p99 values out).
pub fn p99_by_feature_set(rows: &[CsvRow]) -> BTreeMap<String, Vec<f64>> {
    let mut by: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for row in rows {
        if matches!(row.metric_aggregation, MetricAggregation::P99) {
            by.entry(row.feature_set.clone())
                .or_default()
                .push(row.metric_value);
        }
    }
    by
}

/// Emit the spec §9 Markdown report to `path`. Overwrites any
/// existing file.
///
/// The shape mirrors the task brief: summary header, summary table
/// with one row per config, noise floor + threshold lines, sanity
/// invariant verdict, commit history, CSV reference.
pub fn write_markdown_report(path: &Path, report: &RunReport) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::File::create(path)?;
    render(&mut f, report)
}

/// Render `report` as Markdown into `w`. Split from
/// `write_markdown_report` so tests can render to a `Vec<u8>`
/// without a tempfile.
pub fn render<W: Write>(w: &mut W, report: &RunReport) -> std::io::Result<()> {
    writeln!(w, "# Offload A/B Report")?;
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
        "| Config | Features | p50 (ns) | p99 (ns) | p999 (ns) | delta_p99 vs baseline | Decision |"
    )?;
    writeln!(
        w,
        "|---|---|---|---|---|---|---|"
    )?;
    for row in &report.rows {
        let delta_str = match row.delta_p99_vs_baseline_ns {
            Some(d) => format!("{d:.2} ns"),
            None => "—".to_string(),
        };
        let decision_str = match row.outcome {
            Some(Outcome::Signal) => "**Signal**".to_string(),
            Some(Outcome::NoSignal) => "NoSignal".to_string(),
            None => "—".to_string(),
        };
        writeln!(
            w,
            "| {} | {} | {:.2} | {:.2} | {:.2} | {} | {} |",
            row.config_name,
            row.features,
            row.p50_ns,
            row.p99_ns,
            row.p999_ns,
            delta_str,
            decision_str,
        )?;
    }
    writeln!(w)?;
    writeln!(
        w,
        "Noise floor (2 back-to-back baselines, |p99 delta|): {:.2} ns (raw); {:.2} ns (clamped)",
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
    match (&report.full_p99_ns, &report.best_individual) {
        (Some(full_p99), Some((name, best_p99))) => {
            writeln!(w, "full p99: {full_p99:.2} ns")?;
            writeln!(w, "Best individual p99: {best_p99:.2} ns ({name})")?;
            match &report.sanity_invariant {
                Ok(()) => writeln!(w, "-> OK")?,
                Err(msg) => writeln!(w, "-> VIOLATION: {msg}")?,
            }
        }
        (Some(full_p99), None) => {
            writeln!(w, "full p99: {full_p99:.2} ns")?;
            writeln!(w, "Best individual p99: n/a (no single-feature configs in matrix)")?;
            writeln!(w, "-> OK (trivially)")?;
        }
        (None, _) => {
            writeln!(w, "n/a (no `full` config in matrix)")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use bench_common::preconditions::{PreconditionMode, Preconditions};
    use bench_common::run_metadata::RunMetadata;

    fn mk_row(feature_set: &str, agg: MetricAggregation, value: f64) -> CsvRow {
        CsvRow {
            run_metadata: RunMetadata {
                run_id: uuid::Uuid::nil(),
                run_started_at: "2026-04-22T03:14:07Z".into(),
                commit_sha: "abc".into(),
                branch: "phase-a10".into(),
                host: "h".into(),
                instance_type: "t".into(),
                cpu_model: "cpu".into(),
                dpdk_version: "23.11".into(),
                kernel: "k".into(),
                nic_model: "ena".into(),
                nic_fw: String::new(),
                ami_id: "ami".into(),
                precondition_mode: PreconditionMode::Strict,
                preconditions: Preconditions::default(),
            },
            tool: "bench-offload-ab".into(),
            test_case: "request_response_rtt".into(),
            feature_set: feature_set.into(),
            dimensions_json: "{}".into(),
            metric_name: "rtt_ns".into(),
            metric_unit: "ns".into(),
            metric_value: value,
            metric_aggregation: agg,
            cpu_family: None,
            cpu_model_name: None,
            dpdk_version_pkgconfig: None,
            worktree_branch: None,
            uprof_session_id: None,
        }
    }

    #[test]
    fn aggregate_picks_p50_p99_p999() {
        let rows = vec![
            mk_row("baseline", MetricAggregation::P50, 50.0),
            mk_row("baseline", MetricAggregation::P99, 100.0),
            mk_row("baseline", MetricAggregation::P999, 150.0),
            mk_row("baseline", MetricAggregation::Mean, 55.0), // ignored
            mk_row("tx-cksum-only", MetricAggregation::P50, 48.0),
            mk_row("tx-cksum-only", MetricAggregation::P99, 80.0),
            mk_row("tx-cksum-only", MetricAggregation::P999, 140.0),
        ];
        let agg = aggregate_by_config(&rows).unwrap();
        assert_eq!(agg.len(), 2);
        assert_eq!(
            agg["baseline"],
            Aggregated {
                p50_ns: 50.0,
                p99_ns: 100.0,
                p999_ns: 150.0,
            }
        );
        assert_eq!(
            agg["tx-cksum-only"],
            Aggregated {
                p50_ns: 48.0,
                p99_ns: 80.0,
                p999_ns: 140.0,
            }
        );
    }

    #[test]
    fn aggregate_errors_on_missing_percentile() {
        // Only a p99 row — no p50, no p999 — should fail.
        let rows = vec![mk_row("baseline", MetricAggregation::P99, 100.0)];
        let err = aggregate_by_config(&rows).unwrap_err();
        assert!(err.contains("missing p50"), "err: {err}");
    }

    #[test]
    fn build_rows_places_baseline_first_and_fills_delta() {
        let matrix = &[
            Config {
                name: "baseline",
                features: &[],
                is_baseline: true,
                is_full: false,
            },
            Config {
                name: "tx",
                features: &["hw-offload-tx-cksum"],
                is_baseline: false,
                is_full: false,
            },
        ];
        let mut agg = BTreeMap::new();
        agg.insert(
            "baseline".into(),
            Aggregated {
                p50_ns: 50.0,
                p99_ns: 100.0,
                p999_ns: 150.0,
            },
        );
        agg.insert(
            "tx".into(),
            Aggregated {
                p50_ns: 45.0,
                p99_ns: 80.0,
                p999_ns: 140.0,
            },
        );
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let rows = build_report_rows(matrix, &agg, &rule).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].config_name, "baseline");
        assert!(rows[0].delta_p99_vs_baseline_ns.is_none());
        assert_eq!(rows[1].config_name, "tx");
        // delta = 100 - 80 = 20; threshold 3*5 = 15; 20 > 15 → Signal.
        assert_eq!(rows[1].delta_p99_vs_baseline_ns, Some(20.0));
        assert_eq!(rows[1].outcome, Some(Outcome::Signal));
    }

    #[test]
    fn build_rows_errors_when_baseline_aggregated_data_missing() {
        let matrix = &[Config {
            name: "baseline",
            features: &[],
            is_baseline: true,
            is_full: false,
        }];
        let agg = BTreeMap::new(); // empty — no rows at all.
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let err = build_report_rows(matrix, &agg, &rule).unwrap_err();
        assert!(err.contains("baseline"), "err: {err}");
    }

    #[test]
    fn check_full_sanity_ok_when_full_le_best() {
        let matrix = &[
            Config {
                name: "baseline",
                features: &[],
                is_baseline: true,
                is_full: false,
            },
            Config {
                name: "tx",
                features: &["hw-offload-tx-cksum"],
                is_baseline: false,
                is_full: false,
            },
            Config {
                name: "rx",
                features: &["hw-offload-rx-cksum"],
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
        let mut agg = BTreeMap::new();
        agg.insert(
            "baseline".into(),
            Aggregated { p50_ns: 0.0, p99_ns: 100.0, p999_ns: 0.0 },
        );
        agg.insert(
            "tx".into(),
            Aggregated { p50_ns: 0.0, p99_ns: 95.0, p999_ns: 0.0 },
        );
        agg.insert(
            "rx".into(),
            Aggregated { p50_ns: 0.0, p99_ns: 92.0, p999_ns: 0.0 },
        );
        agg.insert(
            "full".into(),
            Aggregated { p50_ns: 0.0, p99_ns: 90.0, p999_ns: 0.0 },
        );

        let sanity = check_full_sanity(matrix, &agg);
        assert!(sanity.verdict.is_ok());
        assert_eq!(sanity.full_p99_ns, Some(90.0));
        let (best_name, best_p99) = sanity.best_individual.unwrap();
        assert_eq!(best_name, "rx");
        assert_eq!(best_p99, 92.0);
    }

    #[test]
    fn check_full_sanity_violation_when_full_gt_best() {
        let matrix = &[
            Config {
                name: "baseline",
                features: &[],
                is_baseline: true,
                is_full: false,
            },
            Config {
                name: "rx",
                features: &["hw-offload-rx-cksum"],
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
        let mut agg = BTreeMap::new();
        agg.insert("baseline".into(), Aggregated { p50_ns: 0.0, p99_ns: 100.0, p999_ns: 0.0 });
        agg.insert("rx".into(), Aggregated { p50_ns: 0.0, p99_ns: 80.0, p999_ns: 0.0 });
        agg.insert("full".into(), Aggregated { p50_ns: 0.0, p99_ns: 85.0, p999_ns: 0.0 });

        let sanity = check_full_sanity(matrix, &agg);
        let err = sanity.verdict.unwrap_err();
        assert!(err.contains("violated"), "err: {err}");
        assert_eq!(sanity.full_p99_ns, Some(85.0));
        assert_eq!(sanity.best_individual, Some(("rx".into(), 80.0)));
    }

    #[test]
    fn check_full_sanity_no_full_row_is_ok() {
        // T11 obs-* matrix won't have a `full` row → verdict Ok.
        let matrix = &[Config {
            name: "baseline",
            features: &[],
            is_baseline: true,
            is_full: false,
        }];
        let agg = BTreeMap::new();
        let sanity = check_full_sanity(matrix, &agg);
        assert!(sanity.verdict.is_ok());
        assert!(sanity.full_p99_ns.is_none());
        assert!(sanity.best_individual.is_none());
    }

    #[test]
    fn render_markdown_includes_every_section() {
        let rule = DecisionRule { noise_floor_ns: 4.8 };
        let rows = vec![
            ReportRow {
                config_name: "baseline".into(),
                features: "(none)".into(),
                p50_ns: 50.0,
                p99_ns: 100.0,
                p999_ns: 150.0,
                delta_p99_vs_baseline_ns: None,
                outcome: None,
            },
            ReportRow {
                config_name: "tx-cksum-only".into(),
                features: "hw-offload-tx-cksum".into(),
                p50_ns: 45.0,
                p99_ns: 80.0,
                p999_ns: 140.0,
                delta_p99_vs_baseline_ns: Some(20.0),
                outcome: Some(Outcome::Signal),
            },
        ];
        let report = RunReport {
            run_id: "rid".into(),
            date_iso8601: "2026-04-22T03:14:07Z".into(),
            commit_sha: "abc".into(),
            noise_floor_ns: rule.noise_floor_ns,
            noise_floor_raw_ns: rule.noise_floor_ns,
            rule,
            rows,
            sanity_invariant: Ok(()),
            full_p99_ns: Some(82.0),
            best_individual: Some(("tx-cksum-only".into(), 80.0)),
            workload: "128 B / 128 B request-response, N=10000, warmup=1000".into(),
            git_log: "abc hello".into(),
            csv_path: "out.csv".into(),
        };

        let mut buf = Vec::new();
        render(&mut buf, &report).unwrap();
        let md = std::str::from_utf8(&buf).unwrap();
        assert!(md.contains("# Offload A/B Report"));
        assert!(md.contains("## Summary Table"));
        assert!(md.contains("| baseline | (none) |"));
        assert!(md.contains("| tx-cksum-only | hw-offload-tx-cksum |"));
        assert!(md.contains("**Signal**"));
        assert!(md.contains("Noise floor"));
        assert!(md.contains("raw"));
        assert!(md.contains("clamped"));
        assert!(md.contains("Decision threshold (3 × clamped noise floor): 14.40 ns"));
        assert!(md.contains("## Sanity Invariant"));
        assert!(md.contains("full p99: 82.00 ns"));
        assert!(md.contains("Best individual p99: 80.00 ns (tx-cksum-only)"));
        assert!(md.contains("OK"));
        assert!(md.contains("## Commit History"));
        assert!(md.contains("abc hello"));
        assert!(md.contains("## Full CSV"));
    }

    #[test]
    fn render_markdown_marks_violation() {
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        let report = RunReport {
            run_id: "rid".into(),
            date_iso8601: "d".into(),
            commit_sha: "c".into(),
            noise_floor_ns: 5.0,
            noise_floor_raw_ns: 5.0,
            rule,
            rows: Vec::new(),
            sanity_invariant: Err("full p99 94 > best individual p99 92".into()),
            full_p99_ns: Some(94.0),
            best_individual: Some(("rx".into(), 92.0)),
            workload: "w".into(),
            git_log: String::new(),
            csv_path: "out.csv".into(),
        };
        let mut buf = Vec::new();
        render(&mut buf, &report).unwrap();
        let md = std::str::from_utf8(&buf).unwrap();
        assert!(md.contains("VIOLATION"), "missing VIOLATION in md:\n{md}");
    }

    #[test]
    fn p99_by_feature_set_groups_samples() {
        let rows = vec![
            mk_row("baseline", MetricAggregation::P99, 100.0),
            mk_row("baseline", MetricAggregation::P99, 105.0),
            mk_row("tx", MetricAggregation::P99, 80.0),
            // non-p99 must be ignored.
            mk_row("baseline", MetricAggregation::P50, 50.0),
        ];
        let got = p99_by_feature_set(&rows);
        assert_eq!(got.len(), 2);
        assert_eq!(got["baseline"], vec![100.0, 105.0]);
        assert_eq!(got["tx"], vec![80.0]);
    }
}
