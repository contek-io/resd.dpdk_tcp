//! bench-e2e — library façade for the binary.
//!
//! Plan B Task 6: end-to-end request/response RTT with attribution
//! buckets + A-HW Task 18 offload-counter assertions. See spec §6 +
//! parent spec §11.3 (attribution buckets), §8.2 (offload counters),
//! §10.5 (`rx_hw_ts_ns=0` on ENA).
//!
//! The lib-façade exists so the integration test
//! `tests/attribution_unit.rs` can pull `attribution`, `sum_identity`,
//! and `hw_task_18` in without going through the binary entry. The
//! binary consumes the same modules via `use bench_e2e::*`.

pub mod attribution;
pub mod hw_task_18;
pub mod sum_identity;
pub mod workload;
