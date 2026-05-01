//! bench-report — library surface for the A10 Plan B Task 14 CSV reporter.
//!
//! Reads every CSV under `target/bench-results/**/*.csv`, deserialises via
//! `bench_common::csv_row::CsvRow`, applies a strict/lenient/all filter, and
//! produces JSON + HTML + Markdown outputs. Spec §12 + §14.
//!
//! # Module layout
//!
//! - [`ingest`] — walks the input directory, deserialises each CSV into a
//!   flat `Vec<CsvRow>`. Errors bubble up per-file with the offending path
//!   so a schema-drift in one CSV doesn't hide the rest.
//! - [`filter`] — applies the `strict-only` / `include-lenient` / `all`
//!   filter against `precondition_mode` + per-precondition pass/fail state.
//! - [`json_writer`] — serialises `Vec<CsvRow>` to pretty-printed JSON.
//! - [`html_writer`] — hand-written string builder that emits a single-page
//!   HTML dashboard: inline CSS, per-tool `<section>`, per-row table, and a
//!   colour-coded highlight on rows with any failed precondition.
//! - [`md_writer`] — per-tool Markdown tables with the run metadata in a
//!   document header. Committable under `docs/superpowers/reports/`.
//!
//! # Non-goals
//!
//! No DPDK, no live engine. This crate is pure CSV → text.

pub mod filter;
pub mod html_writer;
pub mod ingest;
pub mod json_writer;
pub mod md_writer;
