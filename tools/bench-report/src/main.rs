//! bench-report — CSV → JSON + HTML + Markdown. Spec §12 + §14.
//!
//! Reads every CSV under `--input` (default `target/bench-results/`),
//! applies the `--filter` (default `strict-only`), and writes zero or
//! more of `--output-json`, `--output-html`, `--output-md`.
//!
//! # Non-goals
//!
//! This binary never opens a NIC, never calls DPDK. It's a pure file
//! transformer: CSV in, text out.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

use bench_report::filter::{apply, Filter};
use bench_report::html_writer::write_html;
use bench_report::ingest::ingest_dir;
use bench_report::json_writer::write_json;
use bench_report::md_writer::write_md;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "bench-report — CSV → JSON + HTML + Markdown (spec §12 / §14)"
)]
struct Args {
    /// Input directory. Walked recursively for `*.csv`.
    #[arg(long, default_value = "target/bench-results")]
    input: PathBuf,

    /// Optional JSON output path. Pretty-printed; full long-form archival.
    #[arg(long)]
    output_json: Option<PathBuf>,

    /// Optional HTML output path. Single-page static dashboard — inline
    /// CSS, no external CDN, no JS fetch.
    #[arg(long)]
    output_html: Option<PathBuf>,

    /// Optional Markdown output path. Committable summary tables.
    #[arg(long)]
    output_md: Option<PathBuf>,

    /// Filter mode. Defaults to `strict-only` for published reports.
    #[arg(long, value_enum, default_value_t = Filter::StrictOnly)]
    filter: Filter,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    eprintln!(
        "bench-report: reading CSVs under {} (filter={:?})",
        args.input.display(),
        args.filter,
    );
    let all_rows = ingest_dir(&args.input)
        .with_context(|| format!("ingesting {}", args.input.display()))?;
    eprintln!("bench-report: read {} rows total", all_rows.len());

    let kept = apply(args.filter, &all_rows);
    eprintln!(
        "bench-report: {} rows pass filter {:?}",
        kept.len(),
        args.filter,
    );

    // If the caller asked for no outputs we still surface a row count as
    // a dry-run. At least one output path is expected in the common path.
    if args.output_json.is_none() && args.output_html.is_none() && args.output_md.is_none() {
        eprintln!(
            "bench-report: no output paths specified (--output-json / --output-html / --output-md); \
             dry-run only"
        );
        return Ok(());
    }

    if let Some(path) = &args.output_json {
        // The JSON emitter intentionally receives the full row set, not
        // the filtered one — the JSON is the archival / debugging feed
        // and spec §12 calls out that failing-precondition rows should
        // still appear in JSON for debugging, even with `strict-only`.
        write_json(&all_rows, path)
            .with_context(|| format!("writing JSON to {}", path.display()))?;
        eprintln!("bench-report: JSON -> {}", path.display());
    }

    if let Some(path) = &args.output_html {
        write_html(&kept, path)
            .with_context(|| format!("writing HTML to {}", path.display()))?;
        eprintln!("bench-report: HTML -> {}", path.display());
    }

    if let Some(path) = &args.output_md {
        write_md(&kept, path)
            .with_context(|| format!("writing Markdown to {}", path.display()))?;
        eprintln!("bench-report: Markdown -> {}", path.display());
    }

    Ok(())
}
