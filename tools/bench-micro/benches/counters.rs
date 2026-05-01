//! bench-micro::counters — spec §11.2 target 12.
//!
//! `bench_counters_read` measures the cost of reading every counter
//! group on a `Counters` struct via `Atomic*::load(Ordering::Relaxed)`.
//! This is the hot path the FFI `dpdk_net_counters` call exposes —
//! applications snapshot the whole struct periodically (≤ 1 Hz in
//! practice) and aggregate externally.
//!
//! # Stubbing note
//!
//! `dpdk_net_counters(engine)` returns a `*const dpdk_net_counters_t`
//! pointing at the Engine's owned `Counters`. Without a live Engine we
//! construct a standalone `Counters` directly and measure the read
//! cost. The FFI entry adds only pointer validation (benchmarked
//! elsewhere) so this proxy matches the spec's "read of all counter
//! groups" intent.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dpdk_net_core::counters::Counters;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn bench_counters_read(c: &mut Criterion) {
    let counters = Counters::new();
    c.bench_function("bench_counters_read", |b| {
        b.iter(|| {
            // Read one representative counter per group. In production
            // applications snapshot all counters; here we touch one
            // atomic per group to surface the memory-ordering + atomic
            // load cost consistently. Black-boxing the accumulator
            // forces the reads to actually happen.
            let eth = counters.eth.rx_pkts.load(Ordering::Relaxed);
            let ip = counters.ip.rx_tcp.load(Ordering::Relaxed);
            let tcp = counters.tcp.tx_data.load(Ordering::Relaxed);
            let poll = counters.poll.iters.load(Ordering::Relaxed);
            let obs = counters.obs.events_dropped.load(Ordering::Relaxed);
            let fi = counters.fault_injector.drops.load(Ordering::Relaxed);
            black_box(
                eth.wrapping_add(ip)
                    .wrapping_add(tcp)
                    .wrapping_add(poll)
                    .wrapping_add(obs)
                    .wrapping_add(fi),
            );
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = bench_counters_read
}
criterion_main!(benches);
