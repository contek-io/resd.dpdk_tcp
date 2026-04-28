//! bench-micro::tsc_read — spec §11.2 targets 3 + 4.
//!
//! `bench_tsc_read_ffi` measures the FFI call cost of `dpdk_net_now_ns`
//! (the public C ABI entry point). `bench_tsc_read_inline` measures the
//! fastest possible TSC-read path (`clock::rdtsc` — raw RDTSC with no
//! conversion).
//!
//! # Stubbing note — `bench_tsc_read_inline`
//!
//! The spec targets `dpdk_net_now_ns_inline` (header-inline). No such
//! C-header-inline FFI exists today — `dpdk_net_now_ns` is the only
//! public entry point for TSC reads. The closest pure-Rust proxy is
//! `dpdk_net_core::clock::rdtsc()` (raw RDTSC, ~1 ns on modern x86_64),
//! which is what a future `dpdk_net_now_ns_inline` would wrap before
//! the ns-per-tsc conversion. We measure `rdtsc` + conversion
//! (`clock::now_ns`) under the inline name as the closest no-FFI-boundary
//! analog. When a future task adds a true header-inline FFI variant,
//! swap in `dpdk_net_now_ns_inline` here.
// TODO(T5): `dpdk_net_now_ns_inline` does not exist today — bench uses
// `clock::now_ns` (pure Rust, no FFI boundary) as the closest proxy.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::{Duration, Instant};

// Batching factor for `iter_custom`. At sub-10ns workloads, criterion's
// per-iter closure-call + sample-bookkeeping overhead can dominate the
// measured cost. Calling the workload BATCH times inside one closure
// invocation, then dividing the total elapsed by BATCH before returning,
// amortizes that fixed cost. With BATCH=128 the per-call accuracy is
// limited only by Instant::now() resolution (~1-3 ns on this host) +
// loop-overhead (~1 cycle), both << 10 ns observed cost.
const BATCH: u64 = 128;

fn bench_tsc_read_ffi(c: &mut Criterion) {
    c.bench_function("bench_tsc_read_ffi", |b| {
        // `dpdk_net_now_ns` accepts a nullable `*mut dpdk_net_engine` and
        // ignores it (the clock is process-global). Passing null exercises
        // the full FFI call overhead without any Engine state.
        //
        // `iter_custom`: we measure BATCH calls per closure invocation and
        // return `elapsed / BATCH`. Criterion treats the returned Duration
        // as the "per-iter" cost, so the reported median IS per-call cost.
        // XOR-fold the results into a single accumulator and `black_box`
        // it once at end-of-batch so the per-call cost is the FFI hop +
        // rdtsc + scaled-multiply, not BATCH stack roundtrips.
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let mut acc: u64 = 0;
                for _ in 0..BATCH {
                    acc ^= unsafe {
                        dpdk_net::dpdk_net_now_ns(black_box(std::ptr::null_mut()))
                    };
                }
                black_box(acc);
            }
            start.elapsed() / (BATCH as u32)
        });
    });
}

fn bench_tsc_read_inline(c: &mut Criterion) {
    c.bench_function("bench_tsc_read_inline", |b| {
        // `clock::now_ns` is a pure Rust call — no FFI boundary, no
        // function-pointer indirection. rustc with LTO may inline
        // rdtsc + the scaled-multiply conversion. This is the
        // closest analog to a future header-inline FFI variant.
        //
        // `iter_custom`: see `bench_tsc_read_ffi` for batching rationale.
        // To probe H2 (black_box stack roundtrip overhead), accumulate the
        // results into a single XOR-folded sum and consume it with a single
        // `black_box` at the end of the batch. This eliminates BATCH-1 of
        // the per-call store/load pairs.
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let mut acc: u64 = 0;
                for _ in 0..BATCH {
                    acc ^= dpdk_net_core::clock::now_ns();
                }
                black_box(acc);
            }
            start.elapsed() / (BATCH as u32)
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = bench_tsc_read_ffi, bench_tsc_read_inline
}
criterion_main!(benches);
