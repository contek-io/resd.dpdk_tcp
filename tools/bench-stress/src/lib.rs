//! bench-stress — library façade for the binary.
//!
//! A10 Plan B Task 7: netem + FaultInjector scenario matrix runner. See
//! `docs/superpowers/specs/2026-04-21-stage1-phase-a10-benchmark-harness-design.md`
//! §7 and parent spec §11.4.
//!
//! The lib-façade lives alongside the binary so
//! `tests/scenario_parse.rs` can pull in `scenarios` + `netem` without
//! going through the binary entry. The binary consumes the same modules
//! via `use bench_stress::*`.

pub mod counters_snapshot;
pub mod netem;
pub mod scenarios;
