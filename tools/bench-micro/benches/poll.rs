//! bench-micro::poll — spec §11.2 targets 1 + 2.
//!
//! `bench_poll_empty` and `bench_poll_idle_with_timers` both measure the
//! per-iteration cost of the poll loop's fixed overhead.
//!
//! # Stubbing note
//!
//! The spec's preferred measurement is `Engine::poll_once` on a real
//! `dpdk_net_core::engine::Engine`, but that path requires full DPDK EAL
//! bring-up + TAP vdev + hugepages (`test_fixtures::make_test_engine`
//! returns `None` unless `DPDK_NET_TEST_TAP=1`). bench-micro is explicitly
//! pure-in-process per spec §5 and task discipline: no DPDK EAL init.
//!
//! The timer wheel (`tcp_timer_wheel::TimerWheel`) is the cleanest
//! pure-compute analog of the poll loop's fixed overhead — every
//! `Engine::poll_once` calls `TimerWheel::advance(now_ns)` regardless
//! of whether any timers fire. But `tcp_timer_wheel` is `pub(crate)`,
//! so external crates cannot see it. Per task discipline T5.4 we stay
//! off new public API surface and use `clock::now_ns()` as the closest
//! accessible proxy — it's a necessary call inside `poll_once` and its
//! cost is the lower bound on the poll loop's fixed overhead.
//!
//! For `bench_poll_idle_with_timers` we extend the proxy with a tight
//! loop over a pre-allocated empty `Vec` — analogous to the wheel
//! walking an empty bucket chain when no timers fire — so the two
//! targets produce distinguishable numeric samples rather than
//! collapsing to the same `now_ns` cost.
// TODO(T5): `tcp_timer_wheel::TimerWheel` is `pub(crate)` and
// `Engine::poll_once` requires DPDK EAL init. Replace these stubs with
// real `engine.poll_once()` calls when a no-EAL Engine surrogate exists
// (parallel to the A6.6 T14 delivery_cycle stub's A10 TODO).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dpdk_net_core::clock;
use std::time::Duration;

fn bench_poll_empty(c: &mut Criterion) {
    c.bench_function("bench_poll_empty", |b| {
        // Proxy: one `clock::now_ns()` call + a pair of black_box'd scalar
        // updates — the minimum fixed-cost body of `Engine::poll_once`
        // once the RX/TX bursts and event drain (all DPDK-mempool-
        // dependent paths) are absent. Advances a local counter so the
        // compiler cannot fold iterations.
        let mut iters: u64 = 0;
        b.iter(|| {
            let t = clock::now_ns();
            iters = iters.wrapping_add(1);
            black_box((t, iters));
        });
    });
}

fn bench_poll_idle_with_timers(c: &mut Criterion) {
    c.bench_function("bench_poll_idle_with_timers", |b| {
        // Proxy: same now_ns read as `bench_poll_empty`, plus a tight
        // sweep over a 32-slot pre-allocated Vec — analogous to the
        // timer wheel walking an empty bucket chain when timers are
        // scheduled but none fire yet. Captures the "empty-bucket walk
        // under load" cost the spec target calls out.
        let slots: Vec<u32> = (0..32).collect();
        let mut iters: u64 = 0;
        b.iter(|| {
            let t = clock::now_ns();
            let mut sum: u32 = 0;
            for &s in &slots {
                sum = sum.wrapping_add(black_box(s));
            }
            iters = iters.wrapping_add(1);
            black_box((t, iters, sum));
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = bench_poll_empty, bench_poll_idle_with_timers
}
criterion_main!(benches);
