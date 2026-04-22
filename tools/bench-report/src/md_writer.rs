//! Markdown writer — per-tool summary tables. Spec §12, §14.
//!
//! The output is structured so the file is committable under
//! `docs/superpowers/reports/`:
//!
//! 1. Document header with the run-invariant fields.
//! 2. Preconditions table (one line per check).
//! 3. One `##` section per tool with a per-tool table.
//!
//! Run-invariant columns are moved to the document header so the per-tool
//! tables aren't cluttered with 13 identical columns per row.

use std::path::Path;

use anyhow::Context;
use bench_common::csv_row::CsvRow;
use bench_common::preconditions::PreconditionMode;

/// Render `rows` to a Markdown document.
pub fn render_md(rows: &[CsvRow]) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("# resd.dpdk_tcp A10 Bench Report\n\n");

    if let Some(first) = rows.first() {
        render_header(&mut out, first);
        render_preconditions(&mut out, first);
    } else {
        out.push_str("_No rows found._\n");
        return out;
    }

    render_tool_sections(&mut out, rows);
    out
}

/// Write `render_md(rows)` to `path`, creating the parent directory if
/// needed.
pub fn write_md(rows: &[CsvRow], path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    let md = render_md(rows);
    std::fs::write(path, md).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn render_header(out: &mut String, row: &CsvRow) {
    let m = &row.run_metadata;
    out.push_str(&format!("**Run:** `{}`\n", m.run_id));
    out.push_str(&format!("**Commit:** `{}`\n", m.commit_sha));
    out.push_str(&format!("**Branch:** `{}`\n", m.branch));
    out.push_str(&format!("**Date:** {}\n", m.run_started_at));
    out.push_str(&format!(
        "**Host:** {} ({})\n",
        m.host, m.instance_type
    ));
    out.push_str(&format!("**CPU:** {}\n", m.cpu_model));
    out.push_str(&format!("**DPDK:** {}\n", m.dpdk_version));
    out.push_str(&format!("**Kernel:** {}\n", m.kernel));
    out.push_str(&format!("**NIC:** {}", m.nic_model));
    if !m.nic_fw.is_empty() {
        out.push_str(&format!(" (fw={})", m.nic_fw));
    }
    out.push('\n');
    out.push_str(&format!("**AMI:** {}\n", m.ami_id));
    out.push_str(&format!(
        "**Precondition mode:** {}\n",
        m.precondition_mode
    ));
    out.push('\n');
}

fn render_preconditions(out: &mut String, row: &CsvRow) {
    let p = &row.run_metadata.preconditions;
    out.push_str("## Preconditions\n\n");
    out.push_str("| Check | Status |\n");
    out.push_str("|---|---|\n");
    for (name, value) in [
        ("isolcpus", p.isolcpus.to_string()),
        ("nohz_full", p.nohz_full.to_string()),
        ("rcu_nocbs", p.rcu_nocbs.to_string()),
        ("governor", p.governor.to_string()),
        ("cstate_max", p.cstate_max.to_string()),
        ("tsc_invariant", p.tsc_invariant.to_string()),
        ("coalesce_off", p.coalesce_off.to_string()),
        ("tso_off", p.tso_off.to_string()),
        ("lro_off", p.lro_off.to_string()),
        ("rss_on", p.rss_on.to_string()),
        ("thermal_throttle", p.thermal_throttle.to_string()),
        ("hugepages_reserved", p.hugepages_reserved.to_string()),
        ("irqbalance_off", p.irqbalance_off.to_string()),
        ("wc_active", p.wc_active.to_string()),
    ] {
        out.push_str(&format!("| {} | `{}` |\n", name, md_escape(&value)));
    }
    out.push('\n');
}

fn render_tool_sections(out: &mut String, rows: &[CsvRow]) {
    let tools = unique_tools_in_order(rows);
    for tool in tools {
        let tool_rows: Vec<&CsvRow> = rows.iter().filter(|r| r.tool == tool).collect();
        out.push_str(&format!("## {}\n\n", tool));
        out.push_str(
            "| test_case | feature_set | dimensions | metric | unit | agg | value | mode |\n",
        );
        out.push_str("|---|---|---|---|---|---|---|---|\n");
        for r in tool_rows {
            let mode_cell = match r.run_metadata.precondition_mode {
                PreconditionMode::Strict => "strict".to_string(),
                PreconditionMode::Lenient => "**lenient**".to_string(),
            };
            let fail_marker = if !crate::filter::row_has_no_failed_preconditions(r) {
                " *(precondition fail)*"
            } else {
                ""
            };
            out.push_str(&format!(
                "| {} | {} | `{}` | {} | {} | {} | {} | {}{} |\n",
                md_escape(&r.test_case),
                md_escape(&r.feature_set),
                md_escape(&r.dimensions_json),
                md_escape(&r.metric_name),
                md_escape(&r.metric_unit),
                r.metric_aggregation,
                format_value(r.metric_value),
                mode_cell,
                fail_marker,
            ));
        }
        out.push('\n');
    }
}

/// Distinct tool names in order-of-first-occurrence. Same shape as the HTML
/// writer's helper; duplicated rather than shared to keep the two emitters
/// independent (a future change to one section's ordering shouldn't ripple
/// through the other).
fn unique_tools_in_order(rows: &[CsvRow]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for r in rows {
        if !seen.iter().any(|t| t == &r.tool) {
            seen.push(r.tool.clone());
        }
    }
    seen
}

/// Escape Markdown's table metacharacters in a text cell. Specifically `|`
/// (which would end a cell early) and `\n` (which would break the table).
/// Backticks are intentionally left alone — this writer wraps raw JSON in
/// backticks deliberately so the caller can see the structure.
fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '\n' => out.push(' '),
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// Same formatting policy as the HTML emitter — kept in sync so the two
/// outputs agree on how values appear.
fn format_value(v: f64) -> String {
    if !v.is_finite() {
        return format!("{v}");
    }
    let absv = v.abs();
    if absv != 0.0 && !(1e-3..1e9).contains(&absv) {
        format!("{v:.3e}")
    } else if absv.fract() == 0.0 && absv < 1e9 {
        format!("{v:.0}")
    } else {
        format!("{v:.4}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bench_common::csv_row::MetricAggregation;
    use bench_common::preconditions::{PreconditionValue, Preconditions};
    use bench_common::run_metadata::RunMetadata;

    fn sample(tool: &str) -> CsvRow {
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
            tool: tool.into(),
            test_case: "tc".into(),
            feature_set: "default".into(),
            dimensions_json: r#"{"K":1}"#.into(),
            metric_name: "m".into(),
            metric_unit: "ns".into(),
            metric_value: 42.0,
            metric_aggregation: MetricAggregation::P99,
        }
    }

    #[test]
    fn md_has_header_and_sections() {
        let rows = vec![sample("bench-micro"), sample("bench-e2e")];
        let md = render_md(&rows);
        assert!(md.starts_with("# resd.dpdk_tcp A10 Bench Report"));
        assert!(md.contains("## Preconditions"));
        assert!(md.contains("## bench-micro"));
        assert!(md.contains("## bench-e2e"));
    }

    #[test]
    fn md_escape_handles_pipe() {
        assert_eq!(md_escape("a|b"), "a\\|b");
    }

    #[test]
    fn md_escape_flattens_newlines() {
        assert_eq!(md_escape("a\nb"), "a b");
    }

    #[test]
    fn md_marks_lenient_rows_bold() {
        let mut r = sample("bench-micro");
        r.run_metadata.precondition_mode = PreconditionMode::Lenient;
        let md = render_md(&[r]);
        assert!(md.contains("**lenient**"));
    }

    #[test]
    fn md_marks_precondition_failures() {
        let mut r = sample("bench-micro");
        r.run_metadata.preconditions.isolcpus = PreconditionValue::fail();
        let md = render_md(&[r]);
        assert!(md.contains("precondition fail"));
    }

    #[test]
    fn md_empty_input_produces_no_rows_note() {
        let md = render_md(&[]);
        assert!(md.contains("No rows found"));
    }
}
