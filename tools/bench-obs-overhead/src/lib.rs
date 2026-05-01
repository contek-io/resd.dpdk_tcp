//! bench-obs-overhead — library surface for the observability-cost A/B
//! driver. Spec §10.
//!
//! T11 reuses everything generic from `bench-offload-ab`:
//!
//! - `bench_offload_ab::matrix::Config` — the matrix row type (name +
//!   features + marker bits).
//! - `bench_offload_ab::decision::{classify, DecisionRule, Outcome}` —
//!   the `delta_p99 > 3 × noise_floor` rule.
//! - `bench_offload_ab::decision::check_observability_invariant` —
//!   added in T11 as the symmetric sibling of `check_sanity_invariant`
//!   (spec §10: obs-none is the floor; every other config must be
//!   `>= obs-none`).
//! - `bench_offload_ab::report::{aggregate_by_config, render}` + friends
//!   — CSV aggregation and the per-row Markdown helpers.
//!
//! The only T11-specific pieces live here:
//!
//! - [`matrix`] — the spec §10 five-config observability matrix.
//! - [`decision`] — the obs-specific sanity wrapper that locates the
//!   `obs-none` row and validates every other row against it.
//! - [`report`] — the obs-overhead Markdown writer (spec §10 format,
//!   different columns than spec §9: `delta_p99 vs obs-none`, `Default`,
//!   `Action (if fail)`).

pub mod decision;
pub mod matrix;
pub mod report;
