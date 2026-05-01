//! JSON writer — full long-form archival output.
//!
//! Emits the filtered row set as a pretty-printed `serde_json::Value::Array`
//! where each element is the already-flat 35-column `CsvRow` map shape
//! produced by the `bench_common::csv_row::Serialize` impl. Downstream
//! consumers (notebook / pandas) can read the file directly with no
//! further schema lookup.

use std::path::Path;

use anyhow::Context;
use bench_common::csv_row::CsvRow;

/// Serialise `rows` to `path` as a pretty-printed JSON array.
///
/// Creates the parent directory if it doesn't exist — useful because the
/// CLI default routes output under `target/bench-results/report/` which
/// the operator typically doesn't create by hand.
pub fn write_json(rows: &[CsvRow], path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    let file = std::fs::File::create(path)
        .with_context(|| format!("creating {}", path.display()))?;
    serde_json::to_writer_pretty(file, rows)
        .with_context(|| format!("serialising JSON to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bench_common::csv_row::MetricAggregation;
    use bench_common::preconditions::{PreconditionMode, Preconditions};
    use bench_common::run_metadata::RunMetadata;

    fn tiny_row() -> CsvRow {
        CsvRow {
            run_metadata: RunMetadata {
                run_id: uuid::Uuid::nil(),
                run_started_at: "2026-04-22T00:00:00Z".into(),
                commit_sha: "deadbeef".into(),
                branch: "phase-a10".into(),
                host: "h".into(),
                instance_type: "c6a.2xlarge".into(),
                cpu_model: "cpu".into(),
                dpdk_version: "23.11".into(),
                kernel: "6.17".into(),
                nic_model: "ENA".into(),
                nic_fw: String::new(),
                ami_id: "ami".into(),
                precondition_mode: PreconditionMode::Strict,
                preconditions: Preconditions::default(),
            },
            tool: "bench-micro".into(),
            test_case: "t".into(),
            feature_set: "default".into(),
            dimensions_json: "{}".into(),
            metric_name: "ns_per_iter".into(),
            metric_unit: "ns".into(),
            metric_value: 28.3,
            metric_aggregation: MetricAggregation::P50,
        }
    }

    #[test]
    fn write_json_round_trips_via_serde() {
        let base = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("target"));
        std::fs::create_dir_all(&base).ok();
        let path = base.join(format!("bench-report-json-{}.json", uuid::Uuid::new_v4()));
        let rows = vec![tiny_row(), tiny_row()];
        write_json(&rows, &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let parsed: Vec<CsvRow> = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, rows);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_json_creates_parent_dir() {
        let base = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("target"));
        std::fs::create_dir_all(&base).ok();
        let parent = base.join(format!("bench-report-parent-{}", uuid::Uuid::new_v4()));
        let path = parent.join("nested").join("report.json");
        let rows = vec![tiny_row()];
        write_json(&rows, &path).unwrap();
        assert!(path.exists());
        std::fs::remove_dir_all(&parent).ok();
    }
}
