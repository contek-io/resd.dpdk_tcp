//! bench-micro::send — spec §11.2 targets 9 + 10.
//!
//! `bench_send_small` and `bench_send_large_chain` measure the
//! `dpdk_net_send` → `Engine::send_bytes` → `SendQueue::push` ingress
//! path for a 128 B single-mbuf payload vs a 64 KiB multi-mbuf chain.
//!
//! # Stubbing note
//!
//! `dpdk_net_send` requires a live `Engine` which in turn requires DPDK
//! EAL bring-up — outside bench-micro's scope (pure in-process, no EAL
//! init). The closest no-EAL proxy is `SendQueue::push(bytes)`, which
//! is the hot-path body of `Engine::send_bytes` once the flow-table
//! lookup (benchmarked separately as `bench_flow_lookup_hot`) resolves
//! to the target conn's send buffer. Segmentation/mbuf-chain construction
//! happens inside the TX-flush path, not `send_bytes`, so `SendQueue::push`
//! captures the measured work — the difference between `small` and
//! `large_chain` here is the copy-into-VecDeque cost scaling with
//! payload length.
// TODO(T5): swap `SendQueue::push` for `Engine::send_bytes` when a
// no-EAL Engine surrogate exists. The mbuf-chain segmentation cost
// (for `bench_send_large_chain`) is not exercised by this stub since
// it lives in the TX flush path, which depends on a live mempool.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dpdk_net_core::tcp_conn::SendQueue;
use std::time::Duration;

fn bench_send_small(c: &mut Criterion) {
    c.bench_function("bench_send_small", |b| {
        let payload = [0x42u8; 128];
        // 256 KiB send buffer — matches EngineConfig::send_buffer_bytes
        // default. Per-iteration fresh queue so we always exercise the
        // push-into-empty path.
        b.iter_batched_ref(
            || SendQueue::new(256 * 1024),
            |q| {
                let n = q.push(black_box(&payload));
                black_box(n);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_send_large_chain(c: &mut Criterion) {
    c.bench_function("bench_send_large_chain", |b| {
        // 64 KiB payload — spans many mbufs in the real send path (each
        // mbuf holds 2 KiB data by default). With 64 KiB and a 64 KiB
        // buffer the queue fills exactly once.
        let payload = vec![0x42u8; 64 * 1024];
        b.iter_batched_ref(
            || SendQueue::new(64 * 1024),
            |q| {
                let n = q.push(black_box(&payload));
                black_box(n);
            },
            criterion::BatchSize::LargeInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = bench_send_small, bench_send_large_chain
}
criterion_main!(benches);
