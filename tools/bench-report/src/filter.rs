//! Precondition-mode + pass/fail filtering. Spec §12.
//!
//! Three modes:
//!
//! - `StrictOnly` (default for published reports): retains rows where
//!   `precondition_mode == strict` AND every one of the 14 precondition
//!   values is `Pass` (or `NotApplicable` — the bench-micro carve-out; see
//!   spec §4.1 line 222).
//! - `IncludeLenient`: retains every row regardless of `precondition_mode`,
//!   but still requires every precondition to be `Pass` or `NotApplicable`.
//!   Rows that pass their checks but were run under a lenient regime get
//!   a visual mark in the HTML writer.
//! - `All`: no filtering. Every row in the input is kept; the HTML and
//!   Markdown writers colour-code failures.
//!
//! The predicate is intentionally pure data — no side effects. bench-report
//! routes rows through this filter before handing them to the emitters; the
//! full original set (for debugging) is still written by the JSON writer
//! when `All` is selected.

use bench_common::csv_row::CsvRow;
use bench_common::preconditions::PreconditionMode;

/// Filter mode selected by the `--filter` CLI argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Filter {
    /// Only keep rows with `precondition_mode == strict` AND every
    /// precondition passes (or is n/a). This is the default used for
    /// published reports.
    #[value(name = "strict-only")]
    StrictOnly,
    /// Keep rows under either mode, but still require every precondition
    /// to pass. Lenient-mode rows are marked in the HTML emitter so a
    /// reviewer can spot them at a glance.
    #[value(name = "include-lenient")]
    IncludeLenient,
    /// No filtering. Every row in the input is retained. The HTML and
    /// Markdown emitters colour-code precondition failures.
    #[value(name = "all")]
    All,
}

impl Filter {
    /// `true` iff the row should be retained under this filter mode.
    pub fn retain(self, row: &CsvRow) -> bool {
        match self {
            Self::StrictOnly => {
                row.run_metadata.precondition_mode == PreconditionMode::Strict
                    && row_has_no_failed_preconditions(row)
            }
            Self::IncludeLenient => row_has_no_failed_preconditions(row),
            Self::All => true,
        }
    }
}

/// `true` iff every precondition on `row` is Pass or NotApplicable (no Fail).
///
/// We intentionally treat `NotApplicable` as passing — the bench-micro
/// carve-out (spec §4.1 line 222) means `precondition_wc_active` is `n/a`
/// for runs that don't bring up DPDK, and those rows are not failures.
pub fn row_has_no_failed_preconditions(row: &CsvRow) -> bool {
    let p = &row.run_metadata.preconditions;
    !(p.isolcpus.is_fail()
        || p.nohz_full.is_fail()
        || p.rcu_nocbs.is_fail()
        || p.governor.is_fail()
        || p.cstate_max.is_fail()
        || p.tsc_invariant.is_fail()
        || p.coalesce_off.is_fail()
        || p.tso_off.is_fail()
        || p.lro_off.is_fail()
        || p.rss_on.is_fail()
        || p.thermal_throttle.is_fail()
        || p.hugepages_reserved.is_fail()
        || p.irqbalance_off.is_fail()
        || p.wc_active.is_fail())
}

/// Apply the filter to a slice of rows, producing a new owned `Vec`.
pub fn apply(filter: Filter, rows: &[CsvRow]) -> Vec<CsvRow> {
    rows.iter()
        .filter(|r| filter.retain(r))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bench_common::csv_row::{MetricAggregation, PreconditionValue};
    use bench_common::preconditions::Preconditions;
    use bench_common::run_metadata::RunMetadata;

    fn row_with(mode: PreconditionMode, isolcpus: PreconditionValue) -> CsvRow {
        CsvRow {
            run_metadata: RunMetadata {
                run_id: uuid::Uuid::nil(),
                run_started_at: "2026-04-22T03:14:07Z".into(),
                commit_sha: "deadbeef".into(),
                branch: "phase-a10".into(),
                host: "h".into(),
                instance_type: "c6a.2xlarge".into(),
                cpu_model: "AMD EPYC 7R13".into(),
                dpdk_version: "23.11.2".into(),
                kernel: "6.17".into(),
                nic_model: "ENA".into(),
                nic_fw: String::new(),
                ami_id: "ami-test".into(),
                precondition_mode: mode,
                preconditions: Preconditions {
                    isolcpus,
                    ..Preconditions::default()
                },
            },
            tool: "bench-micro".into(),
            test_case: "t".into(),
            feature_set: "default".into(),
            dimensions_json: "{}".into(),
            metric_name: "m".into(),
            metric_unit: "ns".into(),
            metric_value: 1.0,
            metric_aggregation: MetricAggregation::P99,
        }
    }

    #[test]
    fn strict_only_excludes_lenient_mode() {
        let r = row_with(PreconditionMode::Lenient, PreconditionValue::pass());
        assert!(!Filter::StrictOnly.retain(&r));
    }

    #[test]
    fn strict_only_excludes_any_failed_precondition() {
        let r = row_with(PreconditionMode::Strict, PreconditionValue::fail());
        assert!(!Filter::StrictOnly.retain(&r));
    }

    #[test]
    fn strict_only_keeps_strict_mode_all_pass() {
        let r = row_with(PreconditionMode::Strict, PreconditionValue::pass());
        assert!(Filter::StrictOnly.retain(&r));
    }

    #[test]
    fn include_lenient_keeps_lenient_all_pass() {
        let r = row_with(PreconditionMode::Lenient, PreconditionValue::pass());
        assert!(Filter::IncludeLenient.retain(&r));
    }

    #[test]
    fn include_lenient_still_excludes_failures() {
        let r = row_with(PreconditionMode::Lenient, PreconditionValue::fail());
        assert!(!Filter::IncludeLenient.retain(&r));
    }

    #[test]
    fn all_keeps_every_row() {
        let lenient_fail = row_with(PreconditionMode::Lenient, PreconditionValue::fail());
        assert!(Filter::All.retain(&lenient_fail));
        let strict_pass = row_with(PreconditionMode::Strict, PreconditionValue::pass());
        assert!(Filter::All.retain(&strict_pass));
    }

    #[test]
    fn not_applicable_counts_as_passing() {
        let r = row_with(
            PreconditionMode::Strict,
            PreconditionValue::not_applicable(),
        );
        assert!(Filter::StrictOnly.retain(&r));
    }
}
