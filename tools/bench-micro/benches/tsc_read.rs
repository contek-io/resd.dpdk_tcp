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
use std::time::Duration;

fn bench_tsc_read_ffi(c: &mut Criterion) {
    c.bench_function("bench_tsc_read_ffi", |b| {
        // `dpdk_net_now_ns` accepts a nullable `*mut dpdk_net_engine` and
        // ignores it (the clock is process-global). Passing null exercises
        // the full FFI call overhead without any Engine state.
        b.iter(|| {
            let ns = unsafe { dpdk_net::dpdk_net_now_ns(black_box(std::ptr::null_mut())) };
            black_box(ns);
        });
    });
}

fn bench_tsc_read_inline(c: &mut Criterion) {
    c.bench_function("bench_tsc_read_inline", |b| {
        // `clock::now_ns` is a pure Rust call — no FFI boundary, no
        // function-pointer indirection. rustc with LTO may inline
        // rdtsc + the scaled-multiply conversion. This is the
        // closest analog to a future header-inline FFI variant.
        b.iter(|| {
            let ns = dpdk_net_core::clock::now_ns();
            black_box(ns);
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
