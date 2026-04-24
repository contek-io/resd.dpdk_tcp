//! Round-trip integration test: construct synthetic CsvRow samples for
//! each of the seven bench tools listed in spec §12, write them via the
//! bench-common `write_with_header` helper to CSV files under a scratch
//! directory, then drive `ingest` → `filter` → JSON / HTML / Markdown
//! writers and assert each output contains the expected per-tool section
//! marker.
//!
//! This exercises the full pipeline end-to-end in one test:
//!
//!   7 synthetic CsvRow (one per tool)
//!     → 7 per-tool CSV files
//!     → ingest_dir walks them all back
//!     → apply(Filter::StrictOnly) keeps the passing rows
//!     → write_json + write_html + write_md
//!     → each output file mentions every expected tool name
//!
//! One row per tool is the contract; if a future bench tool is added the
//! `TOOLS` list below grows and the round-trip automatically covers it.

use std::path::PathBuf;

use bench_common::csv_row::{CsvRow, MetricAggregation};
use bench_common::preconditions::{PreconditionMode, Preconditions};
use bench_common::run_metadata::RunMetadata;

use bench_report::filter::{apply, Filter};
use bench_report::html_writer::write_html;
use bench_report::ingest::ingest_dir;
use bench_report::json_writer::write_json;
use bench_report::md_writer::write_md;

/// The seven bench tools whose CSV outputs `bench-report` is expected to
/// ingest. Matches spec §12 exactly.
const TOOLS: &[&str] = &[
    "bench-micro",
    "bench-e2e",
    "bench-stress",
    "bench-vs-linux",
    "bench-vs-mtcp",
    "bench-offload-ab",
    "bench-obs-overhead",
];

/// Per-test scratch directory under `target/` — avoids a tempfile dep and
/// uses a UUID suffix to prevent collisions under `cargo test -j N`.
fn scratch_dir(tag: &str) -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    let path = base.join(format!(
        "bench-report-it-{tag}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn row_for_tool(tool: &str) -> CsvRow {
    CsvRow {
        run_metadata: RunMetadata {
            run_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000042").unwrap(),
            run_started_at: "2026-04-22T03:14:07Z".into(),
            commit_sha: "7f70ea50000000000000000000000000000000ab".into(),
            branch: "phase-a10".into(),
            host: "ip-10-0-0-42".into(),
            instance_type: "c6a.2xlarge".into(),
            cpu_model: "AMD EPYC 7R13".into(),
            dpdk_version: "23.11.2".into(),
            kernel: "6.17.0-1009-generic".into(),
            nic_model: "Elastic Network Adapter (ENA)".into(),
            nic_fw: String::new(),
            ami_id: "ami-0123456789abcdef0".into(),
            precondition_mode: PreconditionMode::Strict,
            preconditions: Preconditions::default(),
        },
        tool: tool.to_string(),
        test_case: format!("{tool}_case"),
        feature_set: "default".into(),
        dimensions_json: "{}".into(),
        metric_name: format!("{tool}_metric"),
        metric_unit: "ns".into(),
        metric_value: 100.0 + TOOLS.iter().position(|t| *t == tool).unwrap() as f64,
        metric_aggregation: MetricAggregation::P99,
        cpu_family: None,
        cpu_model_name: None,
        dpdk_version_pkgconfig: None,
        worktree_branch: None,
        uprof_session_id: None,
    }
}

fn write_tool_csv(root: &std::path::Path, tool: &str, row: &CsvRow) {
    let sub = root.join(tool);
    std::fs::create_dir_all(&sub).unwrap();
    let csv_path = sub.join(format!("{}.csv", uuid::Uuid::new_v4()));
    let mut wtr = csv::Writer::from_path(&csv_path).unwrap();
    row.write_with_header(&mut wtr).unwrap();
}

#[test]
fn end_to_end_all_seven_tools_appear_in_each_output() {
    let dir = scratch_dir("e2e");
    let input = dir.join("input");
    std::fs::create_dir_all(&input).unwrap();

    // 1. Write 7 per-tool CSVs.
    for tool in TOOLS {
        let row = row_for_tool(tool);
        write_tool_csv(&input, tool, &row);
    }

    // 2. Ingest.
    let rows = ingest_dir(&input).unwrap();
    assert_eq!(rows.len(), TOOLS.len());

    // 3. Filter — default strict-only; every row has PreconditionMode::Strict
    //    + Preconditions::default() which deserialises back as all-pass.
    let kept = apply(Filter::StrictOnly, &rows);
    assert_eq!(kept.len(), TOOLS.len());

    // 4. JSON.
    let json_path = dir.join("out.json");
    write_json(&rows, &json_path).unwrap();
    let json_text = std::fs::read_to_string(&json_path).unwrap();
    let parsed: Vec<CsvRow> = serde_json::from_str(&json_text).unwrap();
    assert_eq!(parsed.len(), TOOLS.len());
    for tool in TOOLS {
        assert!(
            json_text.contains(tool),
            "JSON output must mention tool {tool}"
        );
    }

    // 5. HTML.
    let html_path = dir.join("out.html");
    write_html(&kept, &html_path).unwrap();
    let html_text = std::fs::read_to_string(&html_path).unwrap();
    assert!(html_text.starts_with("<!DOCTYPE html>"));
    for tool in TOOLS {
        // Each tool has its own <section id="tool-...">
        assert!(
            html_text.contains(&format!("id=\"tool-{tool}\"")),
            "HTML output missing <section> for tool {tool}"
        );
    }
    // Spec §12: no external CDN.
    assert!(!html_text.contains("http://"), "HTML must not reference http URLs");
    assert!(
        !html_text.contains("https://"),
        "HTML must not reference https URLs"
    );

    // 6. Markdown.
    let md_path = dir.join("out.md");
    write_md(&kept, &md_path).unwrap();
    let md_text = std::fs::read_to_string(&md_path).unwrap();
    assert!(md_text.starts_with("# resd.dpdk_tcp A10 Bench Report"));
    for tool in TOOLS {
        assert!(
            md_text.contains(&format!("## {tool}")),
            "Markdown output missing `## {tool}` section"
        );
    }
    // Run metadata present in header.
    assert!(md_text.contains("phase-a10"));
    assert!(md_text.contains("ip-10-0-0-42"));

    // Cleanup.
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn strict_only_excludes_lenient_rows() {
    let dir = scratch_dir("strict");
    let input = dir.join("input");
    std::fs::create_dir_all(&input).unwrap();

    // Mix: 3 strict + 1 lenient row (under bench-micro). strict-only should
    // keep 3, include-lenient should keep 4, all should keep 4.
    let mut rows: Vec<CsvRow> = TOOLS.iter().take(3).map(|t| row_for_tool(t)).collect();
    let mut lenient_row = row_for_tool("bench-micro");
    lenient_row.run_metadata.precondition_mode = PreconditionMode::Lenient;
    lenient_row.test_case = "lenient_case".into();
    rows.push(lenient_row);

    for (i, row) in rows.iter().enumerate() {
        let csv_path = input.join(format!("r{i}.csv"));
        let mut wtr = csv::Writer::from_path(&csv_path).unwrap();
        row.write_with_header(&mut wtr).unwrap();
    }

    let all_rows = ingest_dir(&input).unwrap();
    assert_eq!(all_rows.len(), 4);
    assert_eq!(apply(Filter::StrictOnly, &all_rows).len(), 3);
    assert_eq!(apply(Filter::IncludeLenient, &all_rows).len(), 4);
    assert_eq!(apply(Filter::All, &all_rows).len(), 4);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn filter_exclusion_for_failed_precondition() {
    let dir = scratch_dir("fail");
    let input = dir.join("input");
    std::fs::create_dir_all(&input).unwrap();

    let mut failed = row_for_tool("bench-e2e");
    failed.run_metadata.preconditions.isolcpus =
        bench_common::csv_row::PreconditionValue::fail();

    let ok = row_for_tool("bench-micro");

    for (i, row) in [ok.clone(), failed].iter().enumerate() {
        let csv_path = input.join(format!("r{i}.csv"));
        let mut wtr = csv::Writer::from_path(&csv_path).unwrap();
        row.write_with_header(&mut wtr).unwrap();
    }

    let all_rows = ingest_dir(&input).unwrap();
    assert_eq!(all_rows.len(), 2);
    // strict-only + include-lenient exclude the failing row; all keeps both.
    assert_eq!(apply(Filter::StrictOnly, &all_rows).len(), 1);
    assert_eq!(apply(Filter::IncludeLenient, &all_rows).len(), 1);
    assert_eq!(apply(Filter::All, &all_rows).len(), 2);

    // Render HTML with All — the failing row should have the highlight class.
    let html = bench_report::html_writer::render_html(&apply(Filter::All, &all_rows));
    assert!(html.contains("precondition-fail"));

    std::fs::remove_dir_all(&dir).ok();
}
