//! bench-micro::flow_lookup — spec §11.2 targets 5 + 6.
//!
//! `bench_flow_lookup_hot` measures `FlowTable::lookup_by_tuple` with the
//! table's internal HashMap + slot Vec cache-resident. `bench_flow_lookup_cold`
//! measures the same call with the owning cache lines evicted between
//! iterations.
//!
//! # ARM portability
//!
//! `_mm_clflush` is x86_64-only. The cold bench gates its cache-flush
//! loop with `#[cfg(target_arch = "x86_64")]`; on other architectures
//! it falls back to displacing cache via a scan through a large buffer
//! (~L3 size) so the numeric target stays meaningful cross-platform.
//! Per `project_arm_roadmap`: don't bake x86_64-only assumptions into
//! the measurement surface.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dpdk_net_core::flow_table::{FlowTable, FourTuple};
use dpdk_net_core::tcp_conn::TcpConn;
use std::time::Duration;

const N_ENTRIES: usize = 16;

fn build_populated_table() -> (FlowTable, Vec<FourTuple>) {
    let mut ft = FlowTable::new(64);
    let mut tuples = Vec::with_capacity(N_ENTRIES);
    for i in 0..N_ENTRIES {
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40_000 + i as u16,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5_000 + i as u16,
        };
        // Same knobs as the in-tree TcpConn unit tests — pure-Rust
        // constructor; no DPDK state touched.
        let c = TcpConn::new_client(t, 1_000 + i as u32, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        ft.insert(c).expect("slot available");
        tuples.push(t);
    }
    (ft, tuples)
}

fn bench_flow_lookup_hot(c: &mut Criterion) {
    let (ft, tuples) = build_populated_table();
    // Always look up the same 4-tuple — keeps its bucket + slot entry
    // hot in L1.
    let target = tuples[0];
    c.bench_function("bench_flow_lookup_hot", |b| {
        b.iter(|| {
            let h = ft.lookup_by_tuple(black_box(&target));
            black_box(h);
        });
    });
}

fn bench_flow_lookup_cold(c: &mut Criterion) {
    let (ft, tuples) = build_populated_table();
    let target = tuples[0];

    // Cache-displacement buffer sized around a typical L2 (~1 MiB) so a
    // single full scan knocks the `FlowTable`'s HashMap + slot Vec out
    // of L1+L2. L3 displacement is out of reach here without making the
    // bench overhead dominate — L2-cold is sufficient for the "cold
    // cache" intent (200 ns target vs 40 ns hot).
    const CACHE_SCRUB_BYTES: usize = 1 << 20; // 1 MiB
    let mut scrub: Vec<u8> = vec![0u8; CACHE_SCRUB_BYTES];
    // Initialize so the pages are really committed (not just reserved)
    // — Linux zero-COW would otherwise fault-in on first write.
    for (i, b) in scrub.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }

    c.bench_function("bench_flow_lookup_cold", |b| {
        // `iter_batched_ref` gives us a setup closure whose cost Criterion
        // excludes from the measurement window. That's the only way to
        // pay the 1 MiB scrub cost without having it dominate the
        // measured lookup — `b.iter(...)` would lump them together and
        // produce ~15.8 µs instead of the ~200 ns target.
        b.iter_batched_ref(
            || {
                #[cfg(target_arch = "x86_64")]
                {
                    // SAFETY: CLFLUSH on cache lines is always well-defined —
                    // it only invalidates cache state, not the backing memory.
                    unsafe {
                        let ptr = scrub.as_ptr();
                        // Flush stride-spaced lines to kick the prefetcher
                        // off-pattern.
                        for off in (0..1024).step_by(64) {
                            core::arch::x86_64::_mm_clflush(ptr.add(off));
                        }
                    }
                }
                // Cross-arch displacement: scan every cacheline of the
                // scrub buffer. This evicts the ~1 KiB of FlowTable
                // hot-path state from L1+L2.
                let mut sum: u64 = 0;
                let mut i = 0usize;
                while i < CACHE_SCRUB_BYTES {
                    sum = sum.wrapping_add(scrub[i] as u64);
                    i += 64;
                }
                black_box(sum)
            },
            |_scrub_sum| {
                // Measured region: one cold lookup.
                let h = ft.lookup_by_tuple(black_box(&target));
                black_box(h);
            },
            // PerIteration: setup (scrub) runs before EACH measured lookup.
            // LargeInput would run setup N times then measure N times, warming
            // cache after the first measured iter — observed cold < hot which
            // is physically impossible. PerIteration adds ~350 ns criterion
            // overhead to every sample; the expected lookup cost (~200 ns per
            // spec §11.2) stays clearly distinguishable from the hot path
            // (~40 ns) after subtracting a stable overhead floor.
            criterion::BatchSize::PerIteration,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = bench_flow_lookup_hot, bench_flow_lookup_cold
}
criterion_main!(benches);
