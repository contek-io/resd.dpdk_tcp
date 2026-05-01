//! Stage 1 Phase A10.5 — Layer H correctness gate.
//!
//! See `docs/superpowers/specs/2026-05-01-stage1-phase-a10-5-layer-h-
//! correctness-design.md`.
//!
//! The lib façade exposes the matrix, assertion engine, and observation
//! primitives so the integration tests in `tests/*` can import them
//! without going through the binary.

pub mod assertions;
pub mod counters_snapshot;
pub mod observation;
pub mod scenarios;
