//! bench-micro::timer — spec §11.2 target 11 (`bench_timer_add_cancel`).
//!
//! Measures the cost of a single `TimerWheel::add` + `TimerWheel::cancel`
//! round trip via `EngineNoEalHarness`. The harness wires directly to
//! `dpdk_net_core::tcp_timer_wheel`, so this bench exercises real code
//! rather than a stand-in — the wheel's hashed-bucket insert path and
//! tombstone-on-cancel semantics are both on the critical path.
//!
//! Unblocked in T2.6 (replacing the earlier pure-Rust stub). Now
//! exercises real code via the `bench-internals` feature gate
//! (spec §4.3).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dpdk_net_core::engine::test_support::EngineNoEalHarness;
use std::time::Duration;

fn bench_timer_add_cancel(c: &mut Criterion) {
    c.bench_function("bench_timer_add_cancel", |b| {
        let mut h = EngineNoEalHarness::new(64, 1_000_000);
        b.iter(|| {
            let id = h.timer_add(black_box(10_000_000), black_box(0));
            let _cancelled = h.timer_cancel(id);
            black_box(&h);
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = bench_timer_add_cancel
}
criterion_main!(benches);
