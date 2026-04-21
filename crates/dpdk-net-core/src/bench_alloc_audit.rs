//! A6.5 Group 5: counting GlobalAlloc wrapper.
//!
//! Installation: the integration test binary declares
//! `#[global_allocator] static A: CountingAllocator = CountingAllocator;`.
//! Library code does NOT install the allocator globally — that would
//! affect every downstream consumer of resd-net-core.
//!
//! Counters are `AtomicU64` with Relaxed ordering. Stage 1 is single-
//! lcore so acq/rel is unnecessary; the wrapper is a measurement probe
//! not a correctness gate.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

pub static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
pub static FREE_COUNT: AtomicU64 = AtomicU64::new(0);
pub static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

pub struct CountingAllocator;

// SAFETY: CountingAllocator forwards every allocate/deallocate call to
// the process-default `System` allocator unchanged; the wrapper only
// side-effects three `AtomicU64` counters. `System` satisfies the
// `GlobalAlloc` contract, so the wrapper inherits that contract.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        #[cfg(feature = "bench-alloc-audit-backtrace")]
        dump_backtrace_if_enabled(layout);
        // SAFETY: delegating to the System allocator with the caller's
        // layout; caller is responsible for `layout` validity per the
        // `GlobalAlloc::alloc` contract.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FREE_COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: ptr + layout originated from a prior `System.alloc` /
        // `System.alloc_zeroed` / `System.realloc` call (the wrapper
        // installs System as the backing allocator); caller satisfies
        // the `GlobalAlloc::dealloc` contract.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        #[cfg(feature = "bench-alloc-audit-backtrace")]
        dump_backtrace_if_enabled(layout);
        // SAFETY: delegating to System; caller is responsible for
        // `layout` validity per the `GlobalAlloc::alloc_zeroed` contract.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Count realloc as one alloc + one free + `new_size` bytes. This
        // matches what System.realloc actually does underneath (it may
        // malloc/memcpy/free) and keeps the counters consistent with the
        // "any heap traffic is a regression" property the audit enforces.
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        FREE_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        #[cfg(feature = "bench-alloc-audit-backtrace")]
        dump_backtrace_if_enabled(Layout::from_size_align(new_size, layout.align()).unwrap_or(layout));
        // SAFETY: ptr + layout originated from a prior System allocation;
        // caller satisfies the `GlobalAlloc::realloc` contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Snapshot the three counters. Returned as `(allocs, frees, bytes)`.
pub fn snapshot() -> (u64, u64, u64) {
    (
        ALLOC_COUNT.load(Ordering::Relaxed),
        FREE_COUNT.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}

/// Controls whether backtrace capture is actively running. The
/// counting wrapper is always live under `bench-alloc-audit`, but the
/// (very expensive, itself-allocating) backtrace sampler only fires
/// when this flag is true AND under `bench-alloc-audit-backtrace`.
///
/// The test binary sets this to `true` for a short sampling window
/// around the measurement loop, then clears it — otherwise the
/// backtrace log would drown every allocation from the test setup.
pub static BACKTRACE_ENABLED: AtomicU64 = AtomicU64::new(0);

/// How many backtrace lines have been emitted under the current
/// sampling window. The wrapper caps at a small ceiling (see
/// `BACKTRACE_SAMPLE_CAP`) so a repro run doesn't write gigabytes.
pub static BACKTRACE_SAMPLED: AtomicU64 = AtomicU64::new(0);

pub const BACKTRACE_SAMPLE_CAP: u64 = 32;

// Re-entry guard thread-local for the backtrace sampler. See
// `dump_backtrace_if_enabled` below for the reasoning.
#[cfg(feature = "bench-alloc-audit-backtrace")]
thread_local! {
    static IN_SAMPLER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Opt-in backtrace sampler; no-op unless `bench-alloc-audit-backtrace`
/// is enabled AND `BACKTRACE_ENABLED` is non-zero AND the sample count
/// is under the cap AND we aren't already inside a sampler call (the
/// sampler itself allocates — backtrace capture, `eprintln!` buffer
/// setup — so without a re-entry guard we'd livelock). Restricting
/// activation also keeps the counts interpretable.
#[cfg(feature = "bench-alloc-audit-backtrace")]
fn dump_backtrace_if_enabled(layout: Layout) {
    if BACKTRACE_ENABLED.load(Ordering::Relaxed) == 0 {
        return;
    }
    // Re-entry guard. `Backtrace::force_capture` + `eprintln!` both
    // allocate; without this, each sampled allocation would call back
    // into the sampler recursively, and stderr's mutex deadlocks
    // against itself. The thread-local access itself can allocate on
    // first touch — but `const` init + `Cell` avoid that.
    let already_in = IN_SAMPLER.with(|f| {
        let v = f.get();
        f.set(true);
        v
    });
    if already_in {
        return;
    }
    // Check cap AFTER the re-entry guard, so the cap counts actual
    // sampled call sites (not allocations inside the sampler's own
    // frame that would otherwise inflate the count past 32).
    let n = BACKTRACE_SAMPLED.fetch_add(1, Ordering::Relaxed);
    if n < BACKTRACE_SAMPLE_CAP {
        use std::backtrace::Backtrace;
        let bt = Backtrace::force_capture();
        eprintln!(
            "[alloc-audit] sample={} size={} backtrace:\n{}",
            n,
            layout.size(),
            bt
        );
    }
    IN_SAMPLER.with(|f| f.set(false));
}
