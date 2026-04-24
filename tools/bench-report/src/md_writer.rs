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
    // Backtick-wrapped values (`run_id`, `commit_sha`, `branch`) use the code-
    // cell escape so an unexpected backtick inside the value can't close the
    // inline-code span prematurely. Plain-text values use the inline escape
    // so `*`, `_`, `#`, `\`, and newlines can't mangle the header.
    out.push_str(&format!("**Run:** `{}`\n", md_escape(&m.run_id.to_string())));
    out.push_str(&format!("**Commit:** `{}`\n", md_escape(&m.commit_sha)));
    out.push_str(&format!("**Branch:** `{}`\n", md_escape(&m.branch)));
    out.push_str(&format!("**Date:** {}\n", md_escape_inline(&m.run_started_at)));
    out.push_str(&format!(
        "**Host:** {} ({})\n",
        md_escape_inline(&m.host),
        md_escape_inline(&m.instance_type)
    ));
    out.push_str(&format!("**CPU:** {}\n", md_escape_inline(&m.cpu_model)));
    out.push_str(&format!("**DPDK:** {}\n", md_escape_inline(&m.dpdk_version)));
    out.push_str(&format!("**Kernel:** {}\n", md_escape_inline(&m.kernel)));
    out.push_str(&format!("**NIC:** {}", md_escape_inline(&m.nic_model)));
    if !m.nic_fw.is_empty() {
        out.push_str(&format!(" (fw={})", md_escape_inline(&m.nic_fw)));
    }
    out.push('\n');
    out.push_str(&format!("**AMI:** {}\n", md_escape_inline(&m.ami_id)));
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
/// (which would end a cell early), `\n` (which would break the table), and
/// `` ` `` (which, when the cell content is wrapped in single backticks by the
/// caller, would terminate the inline-code span early and corrupt the row).
///
/// CommonMark allows a literal backtick inside a single-backtick code span via
/// the `\`` escape — most renderers honour it. Any caller that emits this
/// output inside a backtick wrapper still produces a valid row.
fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '\n' => out.push(' '),
            '\r' => {}
            '`' => out.push_str("\\`"),
            other => out.push(other),
        }
    }
    out
}

/// Escape Markdown metacharacters for interpolation outside of code spans —
/// e.g. header values like `**Branch:** {}`. A branch containing `_` would
/// otherwise render italic; `*`, `#`, and `\` are similarly reinterpreted.
/// Newlines must also be flattened so a stray one can't promote the next
/// header field into list / heading syntax.
///
/// Backslash is escaped first so the subsequent `\`-prefixed escapes don't
/// accidentally double-escape.
fn md_escape_inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '*' => out.push_str("\\*"),
            '_' => out.push_str("\\_"),
            '#' => out.push_str("\\#"),
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
            cpu_family: None,
            cpu_model_name: None,
            dpdk_version_pkgconfig: None,
            worktree_branch: None,
            uprof_session_id: None,
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
    fn md_escape_handles_backtick_in_cell_content() {
        // A backtick inside an inline-code cell (which this writer renders as
        // `{dimensions_json}`) used to terminate the span early and corrupt the
        // row. It must now be escaped to a literal backtick.
        assert_eq!(md_escape("a`b"), "a\\`b");
    }

    #[test]
    fn md_renders_row_intact_when_dimensions_json_has_backtick() {
        // End-to-end guard: a dimensions_json value with a stray backtick must
        // not break the 8-column structure of the per-tool table row. The
        // rendered row should still contain exactly 9 pipes (one opening, 7
        // inter-cell, one closing).
        let mut r = sample("bench-micro");
        r.dimensions_json = r#"{"cmd":"echo `uname`"}"#.into();
        let md = render_md(&[r]);
        let row_line = md
            .lines()
            .find(|l| l.starts_with("| tc "))
            .expect("per-tool row should be present");
        assert_eq!(
            row_line.matches('|').count(),
            9,
            "row must have 9 pipes (8 cells) even when dimensions_json contains a backtick; got: {row_line}"
        );
    }

    #[test]
    fn md_escape_inline_escapes_markdown_metacharacters() {
        // Underscore and asterisk would otherwise render italic / bold.
        assert_eq!(md_escape_inline("feat_test_harness"), "feat\\_test\\_harness");
        assert_eq!(md_escape_inline("a*b"), "a\\*b");
        assert_eq!(md_escape_inline("# hdr"), "\\# hdr");
        // Backslash escaped first so the subsequent \x escapes aren't
        // doubled accidentally.
        assert_eq!(md_escape_inline("a\\b"), "a\\\\b");
        assert_eq!(md_escape_inline("line\nbreak"), "line break");
    }

    #[test]
    fn md_header_values_with_underscores_do_not_render_italic() {
        // Regression guard for I2: header values that are NOT wrapped in
        // backticks (host, cpu_model, kernel, nic_model, etc.) used to be
        // interpolated raw, and most CommonMark renderers (GitHub's included)
        // would treat the `_..._` pair as emphasis. After the escape fix the
        // host / kernel lines must carry escaped underscores.
        let mut r = sample("bench-micro");
        r.run_metadata.host = "ip_10_0_0_42".into();
        r.run_metadata.kernel = "6.17_generic".into();
        r.run_metadata.cpu_model = "AMD*EPYC#7R13".into();
        let md = render_md(&[r]);
        assert!(
            md.contains("**Host:** ip\\_10\\_0\\_0\\_42"),
            "header host value should be inline-escaped; got:\n{md}"
        );
        assert!(
            md.contains("**Kernel:** 6.17\\_generic"),
            "header kernel value should be inline-escaped; got:\n{md}"
        );
        assert!(
            md.contains("**CPU:** AMD\\*EPYC\\#7R13"),
            "header cpu_model should inline-escape *, # metacharacters; got:\n{md}"
        );
    }

    #[test]
    fn md_header_backticked_values_escape_embedded_backtick() {
        // Regression guard for I1 on the header side: the run_id / commit_sha /
        // branch fields are wrapped in backticks. A value carrying a stray
        // backtick used to terminate the inline-code span early and corrupt
        // the header line. The escape fix must protect that with `\``.
        let mut r = sample("bench-micro");
        r.run_metadata.commit_sha = "abc`def".into();
        r.run_metadata.branch = "br`anch".into();
        let md = render_md(&[r]);
        assert!(
            md.contains("**Commit:** `abc\\`def`"),
            "header commit_sha value should escape embedded backtick; got:\n{md}"
        );
        assert!(
            md.contains("**Branch:** `br\\`anch`"),
            "header branch value should escape embedded backtick; got:\n{md}"
        );
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
