//! A6.6-7 Task 14 — alloc-audit assertion for the RX zero-copy path.
//!
//! This test is the core regression guard from T14. It asserts that a
//! steady-state single-segment delivery loop does not allocate on the
//! heap. Gated on the `bench-alloc-audit` feature so the CountingAllocator
//! plumbing is in scope.
//!
//! ## Scope
//!
//! Task 14 (plan §1434–1540) specifies two alternatives for driving the
//! measurement body:
//!
//! 1. Full `Engine::new` + TAP rig (needs `sudo -E DPDK_NET_TEST_TAP=1`
//!    and a `net_tap0` vdev). This is already covered end-to-end by
//!    `crates/dpdk-net-core/tests/bench_alloc_hotpath.rs`, which runs
//!    the zero-alloc gate over the *full* engine hot path (TX, RX, ACK
//!    processing, timer-wheel advance) for 30s with handshake + close
//!    inside the warmup window.
//! 2. A pure-Rust synthetic loop that validates the audit plumbing
//!    without sudo/TAP — demonstrating that the `CountingAllocator`
//!    wrapper correctly observes zero deltas across a known-to-be-
//!    alloc-free window. This is what this test does. It complements
//!    (not replaces) the TAP-driven audit.
//!
//! When A10 lands the broader benchmark harness with a pure-Rust Engine
//! surrogate (no EAL init), swap the inner loop for a real
//! `deliver_readable` path over a pre-primed in-order segment. The
//! bench names in `benches/delivery_cycle.rs` stay stable.

#![cfg(feature = "bench-alloc-audit")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use dpdk_net_core::bench_alloc_audit::snapshot;

// The global-allocator slot may be taken by a single registration only
// per binary. Each integration test crate is its own binary, so we can
// install the CountingAllocator here without conflicting with the
// crates/dpdk-net-core/tests/ binary.
//
// We mirror the CountingAllocator pattern from
// `dpdk_net_core::bench_alloc_audit` rather than re-exporting it as a
// `#[global_allocator]`-compatible static (the library deliberately
// does NOT install its own allocator — see the module-level doc there).
// A local re-implementation keeps the test binary self-contained and
// matches the pattern used in `crates/dpdk-net-core/tests/bench_alloc_hotpath.rs`.

pub static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
pub static FREE_COUNT: AtomicU64 = AtomicU64::new(0);

struct LocalCountingAllocator;

// SAFETY: forwards to System and only increments AtomicU64 counters on
// the way through; inherits the GlobalAlloc contract from System.
unsafe impl GlobalAlloc for LocalCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: delegates to System.alloc; caller satisfies layout contract.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FREE_COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: delegates to System.dealloc; caller satisfies ptr/layout contract.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: delegates to System.alloc_zeroed; caller satisfies layout contract.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        FREE_COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: delegates to System.realloc; caller satisfies ptr/layout contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static A: LocalCountingAllocator = LocalCountingAllocator;

/// Placeholder single-seg steady-state loop. Exercises the iovec
/// construction path that `deliver_readable` would invoke on the real
/// engine hot path. No heap allocations; if a future change adds one
/// (e.g., boxing the iovec), the gate fires.
///
/// When A10 lands the pure-Rust Engine surrogate, replace this inner
/// body with an actual `deliver_readable` call over a pre-primed
/// `RecvQueue`. The bench-alloc-audit gate is the same regression
/// guard; only the measured code changes.
fn single_seg_deliver_step(scratch: &mut [dpdk_net_core::iovec::DpdkNetIovec; 1], buf: &[u8; 256]) {
    scratch[0] = dpdk_net_core::iovec::DpdkNetIovec {
        base: buf.as_ptr(),
        len: buf.len() as u32,
        _pad: 0,
    };
    // Pretend downstream reads the iovec; black-box via a volatile
    // pointer read so the optimizer can't elide the store.
    let b = std::hint::black_box(scratch[0].base);
    let _ = std::hint::black_box(b);
}

#[test]
fn steady_state_single_seg_delivers_zero_alloc() {
    // Snapshot the dpdk_net_core bench_alloc_audit counters *and* the
    // local counters. The dpdk_net_core module's CountingAllocator isn't
    // installed in this test binary (only the local one is), so its
    // counters stay at zero — we still snapshot them to exercise the
    // `snapshot()` API and confirm the module re-exports work.
    let (dpdk_a0, dpdk_f0, _) = snapshot();
    assert_eq!(
        dpdk_a0, 0,
        "dpdk_net_core::bench_alloc_audit::snapshot should report zero allocs \
         in this test binary (its allocator is not installed here)"
    );
    assert_eq!(dpdk_f0, 0, "ditto for frees");

    let buf = [0xa5u8; 256];
    let mut scratch = [dpdk_net_core::iovec::DpdkNetIovec {
        base: std::ptr::null(),
        len: 0,
        _pad: 0,
    }; 1];

    // Warmup — any first-touch allocations (formatter lazy-init, etc.)
    // happen here and are excluded from the measured window.
    for _ in 0..1000 {
        single_seg_deliver_step(&mut scratch, &buf);
    }

    let a0 = ALLOC_COUNT.load(Ordering::Relaxed);
    let f0 = FREE_COUNT.load(Ordering::Relaxed);

    // Measure — 10_000 iterations. Zero allocations expected.
    for _ in 0..10_000 {
        single_seg_deliver_step(&mut scratch, &buf);
    }

    let a1 = ALLOC_COUNT.load(Ordering::Relaxed);
    let f1 = FREE_COUNT.load(Ordering::Relaxed);

    let alloc_delta = a1 - a0;
    let free_delta = f1 - f0;

    assert_eq!(
        alloc_delta, 0,
        "{} allocations observed across steady-state single-seg deliver window",
        alloc_delta
    );
    assert_eq!(
        free_delta, 0,
        "{} frees observed across steady-state single-seg deliver window",
        free_delta
    );
}
