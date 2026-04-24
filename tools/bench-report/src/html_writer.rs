//! HTML writer — single-page static dashboard. Spec §12.
//!
//! # Why hand-written, not maud
//!
//! `maud` is a compile-time HTML macro that would give us type-safe tag
//! nesting and automatic escaping. The decision here is to hand-write a
//! string builder instead for three reasons:
//!
//! 1. The output is genuinely static (no conditionals on arbitrary
//!    user input beyond escaping text cells) so the type-safety payoff
//!    of maud is small.
//! 2. One fewer proc-macro dep keeps the build graph tight. Every other
//!    bench-* crate already pays for clap's proc-macros; this one is
//!    lean.
//! 3. The spec allows either approach explicitly — the requested shape
//!    is plain HTML with inline CSS and no JS fetch.
//!
//! We still rigorously escape every string cell before emitting it; see
//! [`escape_html`] + the tests below.
//!
//! # Output shape
//!
//! Single `<!DOCTYPE html>` page. Inline `<style>` block (no external CDN
//! or stylesheet). Contents:
//!
//! - `<h1>` header
//! - `<section class="run-metadata">` — key/value table of run-invariant
//!   columns (commit, branch, host, DPDK, kernel, etc.)
//! - `<section class="preconditions">` — one row per precondition with a
//!   pass/fail/n/a pill and the observed-value if any
//! - One `<section>` per tool with a `<h2>` and a `<table>` listing every
//!   row for that tool. Rows with any precondition `Fail` are given a
//!   `.precondition-fail` class; the CSS paints them with `background: #fdd`.
//! - Rows that ran under `precondition_mode == lenient` get a
//!   `.lenient-mode` marker class + a visual suffix next to `feature_set`.

use std::path::Path;

use anyhow::Context;
use bench_common::csv_row::CsvRow;
use bench_common::preconditions::{PreconditionMode, PreconditionValue};

/// Render `rows` to an HTML string. Pure function: no I/O.
///
/// The caller is responsible for handling the case `rows.is_empty()` — we
/// still produce a valid HTML document with empty tool sections, so a
/// zero-row run is harmless to render.
pub fn render_html(rows: &[CsvRow]) -> String {
    let run_id = rows
        .first()
        .map(|r| r.run_metadata.run_id.to_string())
        .unwrap_or_else(|| "<no rows>".into());

    let mut out = String::with_capacity(4096);
    out.push_str("<!DOCTYPE html>\n");
    out.push_str("<html lang=\"en\">\n<head>\n");
    out.push_str("  <meta charset=\"UTF-8\">\n");
    out.push_str(&format!(
        "  <title>resd.dpdk_tcp A10 bench report — {}</title>\n",
        escape_html(&run_id)
    ));
    out.push_str("  <style>\n");
    out.push_str(INLINE_CSS);
    out.push_str("  </style>\n");
    out.push_str("</head>\n<body>\n");

    out.push_str("  <h1>resd.dpdk_tcp A10 Bench Report</h1>\n");

    // Run-metadata section: take the first row as the source of truth
    // (every row in one run shares these columns).
    if let Some(first) = rows.first() {
        render_run_metadata(&mut out, first);
        render_preconditions(&mut out, first);
    } else {
        out.push_str("  <p><em>No rows found.</em></p>\n");
    }

    render_tool_sections(&mut out, rows);

    out.push_str("</body>\n</html>\n");
    out
}

/// Write `render_html(rows)` to `path`, creating the parent directory if
/// needed.
pub fn write_html(rows: &[CsvRow], path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }
    let html = render_html(rows);
    std::fs::write(path, html).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Collect the distinct tool names from `rows` in stable order of first
/// occurrence. Each tool gets its own `<section>` in the rendered output.
fn unique_tools_in_order(rows: &[CsvRow]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for r in rows {
        if !seen.iter().any(|t| t == &r.tool) {
            seen.push(r.tool.clone());
        }
    }
    seen
}

fn render_run_metadata(out: &mut String, row: &CsvRow) {
    let m = &row.run_metadata;
    out.push_str("  <section class=\"run-metadata\">\n");
    out.push_str("    <h2>Run metadata</h2>\n");
    out.push_str("    <table class=\"metadata\">\n");
    for (key, value) in [
        ("run_id", m.run_id.to_string()),
        ("run_started_at", m.run_started_at.clone()),
        ("commit_sha", m.commit_sha.clone()),
        ("branch", m.branch.clone()),
        ("host", m.host.clone()),
        ("instance_type", m.instance_type.clone()),
        ("cpu_model", m.cpu_model.clone()),
        ("dpdk_version", m.dpdk_version.clone()),
        ("kernel", m.kernel.clone()),
        ("nic_model", m.nic_model.clone()),
        ("nic_fw", m.nic_fw.clone()),
        ("ami_id", m.ami_id.clone()),
        ("precondition_mode", m.precondition_mode.to_string()),
    ] {
        out.push_str("      <tr><th>");
        out.push_str(&escape_html(key));
        out.push_str("</th><td>");
        out.push_str(&escape_html(&value));
        out.push_str("</td></tr>\n");
    }
    out.push_str("    </table>\n");
    out.push_str("  </section>\n");
}

fn render_preconditions(out: &mut String, row: &CsvRow) {
    let p = &row.run_metadata.preconditions;
    out.push_str("  <section class=\"preconditions\">\n");
    out.push_str("    <h2>Preconditions</h2>\n");
    out.push_str("    <table class=\"preconditions\">\n");
    out.push_str("      <tr><th>Check</th><th>Status</th></tr>\n");
    for (name, value) in [
        ("isolcpus", &p.isolcpus),
        ("nohz_full", &p.nohz_full),
        ("rcu_nocbs", &p.rcu_nocbs),
        ("governor", &p.governor),
        ("cstate_max", &p.cstate_max),
        ("tsc_invariant", &p.tsc_invariant),
        ("coalesce_off", &p.coalesce_off),
        ("tso_off", &p.tso_off),
        ("lro_off", &p.lro_off),
        ("rss_on", &p.rss_on),
        ("thermal_throttle", &p.thermal_throttle),
        ("hugepages_reserved", &p.hugepages_reserved),
        ("irqbalance_off", &p.irqbalance_off),
        ("wc_active", &p.wc_active),
    ] {
        out.push_str("      <tr><td>");
        out.push_str(&escape_html(name));
        out.push_str("</td><td>");
        out.push_str(&pill_for(value));
        out.push_str("</td></tr>\n");
    }
    out.push_str("    </table>\n");
    out.push_str("  </section>\n");
}

fn render_tool_sections(out: &mut String, rows: &[CsvRow]) {
    for tool in unique_tools_in_order(rows) {
        let tool_rows: Vec<&CsvRow> = rows.iter().filter(|r| r.tool == tool).collect();
        out.push_str(&format!(
            "  <section class=\"tool\" id=\"tool-{}\">\n",
            escape_html(&tool)
        ));
        out.push_str(&format!("    <h2>{}</h2>\n", escape_html(&tool)));
        out.push_str("    <table class=\"rows\">\n");
        out.push_str(
            "      <tr><th>test_case</th><th>feature_set</th><th>dimensions</th>\
             <th>metric</th><th>unit</th><th>agg</th><th>value</th><th>mode</th></tr>\n",
        );
        for r in tool_rows {
            let row_fail = !crate::filter::row_has_no_failed_preconditions(r);
            let lenient = r.run_metadata.precondition_mode == PreconditionMode::Lenient;
            let mut classes: Vec<&str> = Vec::new();
            if row_fail {
                classes.push("precondition-fail");
            }
            if lenient {
                classes.push("lenient-mode");
            }
            let class_attr = if classes.is_empty() {
                String::new()
            } else {
                format!(" class=\"{}\"", classes.join(" "))
            };
            out.push_str(&format!("      <tr{class_attr}>"));
            out.push_str(&format!("<td>{}</td>", escape_html(&r.test_case)));
            // Feature_set column: append a small visual marker for lenient-
            // mode rows so they're distinguishable even when no precondition
            // actually failed. Keeps the filter=include-lenient output
            // reviewable.
            let feature_cell = if lenient {
                format!(
                    "{} <span class=\"lenient-mark\">(lenient)</span>",
                    escape_html(&r.feature_set)
                )
            } else {
                escape_html(&r.feature_set)
            };
            out.push_str(&format!("<td>{feature_cell}</td>"));
            out.push_str(&format!(
                "<td><code>{}</code></td>",
                escape_html(&r.dimensions_json)
            ));
            out.push_str(&format!("<td>{}</td>", escape_html(&r.metric_name)));
            out.push_str(&format!("<td>{}</td>", escape_html(&r.metric_unit)));
            out.push_str(&format!("<td>{}</td>", escape_html(&r.metric_aggregation.to_string())));
            out.push_str(&format!("<td>{}</td>", format_value(r.metric_value)));
            out.push_str(&format!(
                "<td>{}</td>",
                escape_html(&r.run_metadata.precondition_mode.to_string())
            ));
            out.push_str("</tr>\n");
        }
        out.push_str("    </table>\n");
        out.push_str("  </section>\n");
    }
}

/// Format a precondition value as a coloured pill: pass (green), fail
/// (red), n/a (grey). Observed value, if any, is appended in `<code>`.
fn pill_for(v: &PreconditionValue) -> String {
    let (class, label, detail) = match v {
        PreconditionValue::Pass(None) => ("pill pass", "pass", None),
        PreconditionValue::Pass(Some(d)) => ("pill pass", "pass", Some(d.clone())),
        PreconditionValue::Fail(None) => ("pill fail", "fail", None),
        PreconditionValue::Fail(Some(d)) => ("pill fail", "fail", Some(d.clone())),
        PreconditionValue::NotApplicable => ("pill na", "n/a", None),
    };
    match detail {
        Some(d) => format!(
            "<span class=\"{}\">{}</span> <code>{}</code>",
            class,
            escape_html(label),
            escape_html(&d)
        ),
        None => format!("<span class=\"{}\">{}</span>", class, escape_html(label)),
    }
}

/// Format an `f64` in a human-readable way. Very-small and very-large
/// values use scientific notation; mid-range values use up to four
/// decimal digits. No locale separators — the report is committed and
/// eyeballed, not consumed by spreadsheet import.
fn format_value(v: f64) -> String {
    if !v.is_finite() {
        return escape_html(&format!("{v}"));
    }
    let absv = v.abs();
    if absv != 0.0 && !(1e-3..1e9).contains(&absv) {
        format!("{v:.3e}")
    } else if absv.fract() == 0.0 && absv < 1e9 {
        // Integer-valued — print without trailing `.0` for readability.
        format!("{v:.0}")
    } else {
        format!("{v:.4}")
    }
}

/// Minimal HTML escape for text content. Handles `<`, `>`, `&`, `"`, `'`.
/// Sufficient for the closed-content CsvRow fields (no user-controllable
/// HTML expected) but applied uniformly so a malformed dimensions_json
/// or tool name doesn't break the render.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Inline CSS used by every bench-report HTML page. Kept inside the
/// binary (no external file) so the page renders correctly when opened
/// straight from disk with no server.
const INLINE_CSS: &str = r#"
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      max-width: 1200px;
      margin: 2em auto;
      padding: 0 1em;
      color: #222;
    }
    h1, h2 { color: #111; }
    h2 { border-bottom: 1px solid #ccc; padding-bottom: 0.2em; margin-top: 2em; }
    table { border-collapse: collapse; width: 100%; margin: 0.5em 0 1.5em 0; }
    th, td {
      border: 1px solid #bbb;
      padding: 4px 8px;
      text-align: left;
      vertical-align: top;
      font-size: 13px;
    }
    th { background: #f2f2f2; }
    table.rows td, table.rows th {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    table.metadata th { width: 14em; }
    tr.precondition-fail td { background: #fdd; }
    tr.lenient-mode td { border-left: 3px solid #e89c00; }
    span.pill { padding: 2px 6px; border-radius: 4px; font-weight: bold; }
    span.pill.pass { background: #c9f0c9; color: #0a4f0a; }
    span.pill.fail { background: #f5baba; color: #5a0b0b; }
    span.pill.na { background: #e0e0e0; color: #555; }
    span.lenient-mark { color: #8a5500; font-size: 11px; }
    code { background: #f6f6f6; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use bench_common::csv_row::MetricAggregation;
    use bench_common::preconditions::Preconditions;
    use bench_common::run_metadata::RunMetadata;

    fn row(tool: &str, mode: PreconditionMode, isolcpus: PreconditionValue) -> CsvRow {
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
                precondition_mode: mode,
                preconditions: Preconditions {
                    isolcpus,
                    ..Preconditions::default()
                },
            },
            tool: tool.into(),
            test_case: "tc".into(),
            feature_set: "default".into(),
            dimensions_json: "{}".into(),
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
    fn html_is_well_formed_doctype() {
        let html = render_html(&[row(
            "bench-micro",
            PreconditionMode::Strict,
            PreconditionValue::pass(),
        )]);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn html_contains_one_section_per_tool() {
        let rows = vec![
            row("bench-micro", PreconditionMode::Strict, PreconditionValue::pass()),
            row("bench-e2e", PreconditionMode::Strict, PreconditionValue::pass()),
        ];
        let html = render_html(&rows);
        assert!(html.contains("id=\"tool-bench-micro\""));
        assert!(html.contains("id=\"tool-bench-e2e\""));
    }

    #[test]
    fn failed_preconditions_get_highlight_class() {
        let html = render_html(&[row(
            "bench-micro",
            PreconditionMode::Strict,
            PreconditionValue::fail(),
        )]);
        assert!(html.contains("precondition-fail"));
    }

    #[test]
    fn lenient_mode_gets_marker() {
        let html = render_html(&[row(
            "bench-micro",
            PreconditionMode::Lenient,
            PreconditionValue::pass(),
        )]);
        assert!(html.contains("lenient-mode"));
        assert!(html.contains("(lenient)"));
    }

    #[test]
    fn escape_html_handles_metacharacters() {
        assert_eq!(
            escape_html("<script>&\"'"),
            "&lt;script&gt;&amp;&quot;&#39;"
        );
    }

    #[test]
    fn no_external_cdn_references() {
        let html = render_html(&[row(
            "bench-micro",
            PreconditionMode::Strict,
            PreconditionValue::pass(),
        )]);
        // Spec §12: no external CDN, no JS fetch. Guard against accidental
        // regressions that pull in a remote stylesheet or script.
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn empty_input_still_produces_valid_html() {
        let html = render_html(&[]);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("No rows found"));
    }

    #[test]
    fn format_value_renders_common_cases() {
        assert_eq!(format_value(42.0), "42");
        assert_eq!(format_value(28.25), "28.2500");
        assert!(format_value(1.0e10).contains('e'));
        assert!(format_value(1.0e-5).contains('e'));
    }

    #[test]
    fn pill_for_each_precondition_variant() {
        assert!(pill_for(&PreconditionValue::pass()).contains("pill pass"));
        assert!(pill_for(&PreconditionValue::fail()).contains("pill fail"));
        assert!(pill_for(&PreconditionValue::not_applicable()).contains("pill na"));
        let detailed = pill_for(&PreconditionValue::pass_with("2-7"));
        assert!(detailed.contains("pass"));
        assert!(detailed.contains("2-7"));
    }
}
