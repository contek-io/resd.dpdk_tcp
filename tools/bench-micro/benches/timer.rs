//! bench-micro::timer — spec §11.2 target 11.
//!
//! `bench_timer_add_cancel` measures the cost of one `add` + one
//! `cancel` pair on the internal hashed timing wheel — the hot body
//! of `dpdk_net_timer_add` / `dpdk_net_timer_cancel` once the Engine
//! pointer validation + TimerId packing are excluded.
//!
//! # Stubbing note
//!
//! `dpdk_net_timer_add` / `_cancel` are FFI wrappers that look up the
//! Engine, pack/unpack the TimerId, and call `TimerWheel::add` /
//! `::cancel`. Going through FFI needs a live Engine; bench-micro is
//! no-EAL. The internal `tcp_timer_wheel::TimerWheel` is `pub(crate)`
//! — external crates cannot see it — and per task discipline T5.4 we
//! stay off new public API surface.
//!
//! Proxy: insert + remove a node in a pre-allocated `Vec<(u64, u64)>`
//! that mirrors the wheel's per-bucket slot Vec layout. The real
//! `TimerWheel::add` does exactly this (push into a `Vec<u32>` plus a
//! `Slots` Vec write); `cancel` is a bool-flag flip. This stub matches
//! the expected ~50 ns order-of-magnitude and will move to the real
//! wheel API when it becomes externally reachable.
// TODO(T5): `tcp_timer_wheel` is `pub(crate)` — replace this proxy
// with `Engine::public_timer_add` / `public_timer_cancel` via a
// no-EAL Engine surrogate when one exists.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

fn bench_timer_add_cancel(c: &mut Criterion) {
    c.bench_function("bench_timer_add_cancel", |b| {
        // Mirror the wheel's `buckets[level][slot_idx]` push + cancel-
        // tombstone layout. Pre-allocate the backing Vec to the same
        // BUCKET_INIT_CAP (512 u32 = 2 KiB) the real wheel uses so
        // allocator behaviour doesn't dominate.
        let mut bucket: Vec<u32> = Vec::with_capacity(512);
        let mut slots: Vec<Option<u64>> = Vec::with_capacity(128);
        let mut generation: u32 = 0;
        b.iter(|| {
            // Simulate `TimerWheel::add`: push onto the bucket, take a
            // slot index.
            let slot_idx = slots.len() as u32;
            slots.push(Some(black_box(1_000_000u64)));
            bucket.push(black_box(slot_idx));
            generation = generation.wrapping_add(1);
            // Simulate `TimerWheel::cancel`: tombstone-flag the slot.
            if let Some(slot) = slots.get_mut(slot_idx as usize) {
                *slot = None;
            }
            // Reset for the next iteration so the Vecs don't grow
            // unboundedly across 10^8 iterations.
            slots.clear();
            bucket.clear();
            black_box((slots.len(), bucket.len(), generation));
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
