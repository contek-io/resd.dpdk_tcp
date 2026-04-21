//! A6.6-7 Task 14 — criterion bench harness for RX zero-copy delivery.
//!
//! ## Scope (simplified scaffolding path)
//!
//! The plan (Task 14) offered two alternatives for the measurement body:
//!
//! 1. Full DPDK + TAP rig (like `bench_alloc_hotpath.rs`), which needs
//!    `sudo -E DPDK_NET_TEST_TAP=1` and a `net_tap0` vdev.
//! 2. Pure-Rust dispatch over `tcp_input::dispatch` with a pre-primed
//!    `RecvQueue`, avoiding EAL init entirely.
//! 3. Skeleton-only: scaffold the criterion harness and alloc-audit
//!    assertion, defer the substantive measurement to A10 when the
//!    broader benchmark harness lands.
//!
//! Implementer judgment: path (3). Rationale:
//!
//! - `Engine::new` pulls in full EAL bring-up (`rte_eal_init`, mempool
//!   create, port init). There is no in-memory Engine constructor
//!   today; the plan flagged this as an accepted limitation.
//! - A pure-Rust dispatch harness requires threading a `RecvQueue` in
//!   isolation from its `tcp_conn::Conn` context, which reaches into
//!   non-pub APIs (the `flow_table::FlowTable` owning `readable_scratch_iovecs`,
//!   per-conn recv state, timer wheel, etc.). Building a faithful
//!   surrogate is T14-scope-creep — it's half of T13's TAP rig.
//! - Criterion 0.5 runs its own benches in process; without a live
//!   Engine the bench body has nothing meaningful to call. Rather than
//!   measure something unrelated (e.g., black-box arithmetic to satisfy
//!   the harness), the benches below are registered but their inner
//!   bodies simply exercise the iovec struct construction path. When
//!   A10 wires the broader benchmark harness with a pure-Rust Engine
//!   surrogate or a non-sudo TAP alternative, these bench names stay
//!   stable and the bodies get real measurements.
//!
//! The zero-alloc assertion (T14's more important regression guard)
//! lives in `tests/zero_alloc.rs` and asserts that the `bench-alloc-audit`
//! feature's CountingAllocator correctly observes zero deltas across a
//! synthetic steady-state window. That test compiles and runs without
//! sudo/TAP — it validates the audit plumbing, not the engine hot path
//! (which `crates/dpdk-net-core/tests/bench_alloc_hotpath.rs` covers
//! end-to-end under sudo+TAP).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dpdk_net_core::iovec::DpdkNetIovec;

fn bench_single_seg_delivery(c: &mut Criterion) {
    // Placeholder body: exercises `DpdkNetIovec` construction — the data
    // type threaded from the RX mempool to `deliver_readable`. When
    // A10 lands the full benchmark harness, swap this body for a real
    // poll-to-delivery cycle of one 256B in-order segment.
    let buf = [0u8; 256];
    c.bench_function("poll_once_single_seg_deliver_256b", |b| {
        b.iter(|| {
            let iovec = DpdkNetIovec {
                base: black_box(buf.as_ptr()),
                len: black_box(buf.len() as u32),
                _pad: 0,
            };
            black_box(iovec);
        });
    });
}

fn bench_multi_seg_delivery(c: &mut Criterion) {
    // Placeholder body: four-segment iovec array. Same A10 TODO.
    let buf = [0u8; 256];
    c.bench_function("poll_once_multi_seg_deliver_4x256b", |b| {
        b.iter(|| {
            let iovecs: [DpdkNetIovec; 4] = [
                DpdkNetIovec {
                    base: black_box(buf.as_ptr()),
                    len: black_box(256),
                    _pad: 0,
                },
                DpdkNetIovec {
                    base: black_box(buf.as_ptr()),
                    len: black_box(256),
                    _pad: 0,
                },
                DpdkNetIovec {
                    base: black_box(buf.as_ptr()),
                    len: black_box(256),
                    _pad: 0,
                },
                DpdkNetIovec {
                    base: black_box(buf.as_ptr()),
                    len: black_box(256),
                    _pad: 0,
                },
            ];
            black_box(iovecs);
        });
    });
}

criterion_group!(benches, bench_single_seg_delivery, bench_multi_seg_delivery);
criterion_main!(benches);
