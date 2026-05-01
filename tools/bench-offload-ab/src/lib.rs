//! bench-offload-ab — library surface for the feature-matrix A/B driver.
//!
//! The binary (`main.rs`) composes these modules into a rebuild-run-
//! aggregate-report loop. Each module is exported so T11 (`bench-obs-
//! overhead`) can reuse the rebuild-loop / decision / reporting pieces
//! without copy-paste — the only T11-specific bit is the feature matrix
//! itself (`obs-*` flags instead of `hw-*`). See spec §9 and §10.
//!
//! Module layout:
//!
//! - [`matrix`] — the spec §9 eight-config feature matrix + the generic
//!   `Config` type T11 uses to describe its own `obs-*` matrix.
//! - [`decision`] — the `classify` + `check_sanity_invariant` functions
//!   that formalise the §9 decision rule and sanity invariant.
//! - [`report`] — CSV accumulation, per-offload delta computation, and
//!   the Markdown report writer.

pub mod decision;
pub mod matrix;
pub mod report;
