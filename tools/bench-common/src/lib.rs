//! bench-common — shared types + helpers across tools/bench-*.
//!
//! See docs/superpowers/specs/2026-04-21-stage1-phase-a10-benchmark-harness-design.md
//! §4.1, §4.3 (preconditions) and §14 (CSV schema) for the authoritative field
//! list. This crate is pure data + math: no DPDK FFI, no engine state.

pub mod csv_row;
pub mod percentile;
pub mod preconditions;
pub mod run_metadata;
