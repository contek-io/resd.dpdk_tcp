use dpdk_net_sys as sys;
use std::cell::Cell;
use std::ffi::CString;
use std::ptr::NonNull;

use crate::Error;

// Per-thread pointer to the active engine's counters. Set by
// `Engine::new` (start of construction) and cleared by `Engine::drop`
// (very end of teardown). `MbufHandle::Drop` reads this on its hot
// path to bump `mbuf_refcnt_drop_unexpected` when the post-dec
// refcount is suspiciously high. Pointer is null iff no engine is
// bound on this thread; in that case the diagnostic is silently
// skipped.
//
// SAFETY: callers must store a pointer to a `Counters` whose
// lifetime outlives every `MbufHandle::Drop` on the same thread.
// `Engine` owns its `Counters` in a `Box`; setting / clearing in
// pair with engine construction / destruction satisfies the
// invariant.
thread_local! {
    pub(crate) static THREAD_COUNTERS_PTR: Cell<*const crate::counters::Counters> =
        const { Cell::new(std::ptr::null()) };
}

/// Threshold above which a post-dec refcount in `MbufHandle::Drop`
/// surfaces as `mbuf_refcnt_drop_unexpected`. No production path
/// holds more than 8 handles to one mbuf concurrently — the maximum
/// observed in code review of `delivered_segments` / `recv.bytes` /
/// `OooSegment` / `snd_retrans` overlap is ~4. The 8-handle threshold
/// gives 2× headroom over reality so a slow monotonic refcount climb
/// (rate < 1 per leak event but cumulative) surfaces faster than the
/// prior 32-handle ceiling. False positives on the legitimate path
/// remain zero.
pub(crate) const MBUF_DROP_UNEXPECTED_THRESHOLD: u16 = 8;

/// RAII wrapper around an `rte_mempool*`.
/// Dropped pool calls `rte_mempool_free` on the inner pointer.
///
/// `data_room_size` is stashed at construction time so callers can query
/// the per-mbuf payload capacity without dereferencing the opaque
/// `rte_mempool` struct (`struct rte_mempool` is `_address: u8` in bindgen
/// because its nested anonymous unions defeat bindgen's layout engine).
pub struct Mempool {
    ptr: NonNull<sys::rte_mempool>,
    name: CString,
    data_room_size: u16,
}

impl Mempool {
    /// Create a packet-mbuf pool with DPDK defaults + configurable headroom.
    pub fn new_pktmbuf(
        name: &str,
        n_elements: u32,
        cache_size: u32,
        priv_size: u16,
        data_room_size: u16,
        socket_id: i32,
    ) -> Result<Self, Error> {
        let cname = CString::new(name).map_err(|_| Error::MempoolCreate("name contains NUL"))?;
        // Safety: passing valid parameters to an FFI function; DPDK must be initialized
        // (EAL) before this. Caller responsibility.
        let p = unsafe {
            sys::rte_pktmbuf_pool_create(
                cname.as_ptr(),
                n_elements,
                cache_size,
                priv_size,
                data_room_size,
                socket_id,
            )
        };
        let ptr = NonNull::new(p).ok_or(Error::MempoolCreate(
            "rte_pktmbuf_pool_create returned NULL",
        ))?;
        Ok(Self { ptr, name: cname, data_room_size })
    }

    /// Create an RX-shaped mbuf pool sized for the given mbuf count.
    ///
    /// Thin wrapper around `new_pktmbuf` that hardcodes the same
    /// per-mbuf shape used by `Engine::new` for the primary RX mempool
    /// (default 2048 data-room + RTE_PKTMBUF_HEADROOM, cache_size=256,
    /// priv_size=0). Used by the A9 `test-inject` hook to conjure a
    /// dedicated mempool for synthetic frames so inject traffic never
    /// contends with the production RX mempool.
    ///
    /// Elements carry a `data_room_size` of `2048 + RTE_PKTMBUF_HEADROOM`
    /// — matches the `EngineConfig` default so single-seg inject frames
    /// up to 2048 bytes (MTU 1500 + options) always fit. If a future test
    /// needs jumbo inject frames, extend the signature with a
    /// `data_room_size` knob; for A9's property + fuzz coverage the
    /// default covers every Scapy-generated pattern.
    pub fn new_rx_mempool(
        name: &str,
        elt_count: u32,
        socket_id: i32,
    ) -> Result<Self, Error> {
        const DEFAULT_DATA_ROOM: u16 = 2048;
        Self::new_pktmbuf(
            name,
            elt_count,
            256,
            0,
            DEFAULT_DATA_ROOM + sys::RTE_PKTMBUF_HEADROOM as u16,
            socket_id,
        )
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut sys::rte_mempool {
        self.ptr.as_ptr()
    }

    pub fn name(&self) -> &std::ffi::CStr {
        &self.name
    }

    /// Per-mbuf data-room capacity (bytes) this pool was configured with.
    ///
    /// Matches the `data_room_size` argument passed to
    /// `rte_pktmbuf_pool_create` — i.e., the maximum single-segment
    /// payload + headroom an mbuf from this pool can hold. Returned as
    /// `u16` to match the underlying DPDK `rte_pktmbuf_pool_private`
    /// field width (and the `uint16_t` accepted by
    /// `rte_pktmbuf_append`), which prevents silent truncation at any
    /// append-style call site that casts the value back to `u16`.
    #[inline]
    pub fn elt_size(&self) -> u16 {
        self.data_room_size
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        // Safety: we own the mempool; no other references should exist because
        // we hold NonNull and never handed it out beyond &mut self.
        unsafe { sys::rte_mempool_free(self.ptr.as_ptr()) };
    }
}

// Pools are created on one lcore but passed between lcores at setup time;
// mempool operations themselves are thread-safe per DPDK docs.
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

/// Non-owning handle to an rte_mbuf. Does NOT manage refcount — the engine
/// explicitly alloc/frees and increments refcnt when stashing into
/// `SendRetrans`. Per spec §7.2 design: keep unsafe pointer work in
/// `engine.rs` so this module stays safe-code-only.
///
/// `Clone` is cheap (pointer copy) but does NOT refcnt_inc; the caller must
/// call `rte_mbuf_refcnt_update` explicitly where refcount ownership is
/// transferred. Tests use `null_for_test()` — the null pointer is never
/// dereferenced in unit tests (SendRetrans just stores it).
#[derive(Clone, Copy)]
pub struct Mbuf {
    ptr: *mut sys::rte_mbuf,
}

impl Mbuf {
    /// Wrap a raw pointer. Caller owns the refcount responsibility.
    #[inline]
    pub fn from_ptr(ptr: *mut sys::rte_mbuf) -> Self {
        Self { ptr }
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut sys::rte_mbuf {
        self.ptr
    }

    /// Test-only null handle. The pointer is never dereferenced in tests.
    #[cfg(test)]
    pub fn null_for_test() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
        }
    }
}

// Safety: mbuf pointers are moved between threads only in ways the engine
// serializes; `SendRetrans` lives per-conn inside `TcpConn`, which is
// accessed by one engine lcore at a time. Matches `Mempool`'s Send impl.
unsafe impl Send for Mbuf {}

/// A6.5 Task 4c: RAII wrapper for a DPDK mbuf reference. Decrements
/// refcount on drop, returning the mbuf to its mempool when the count
/// reaches zero.
///
/// Used by `TcpConn::delivered_segments` (A6.6 T7) to pin mbufs across
/// an event emission window: the engine bumps refcount + wraps in
/// `MbufHandle` when a READABLE event is queued; clearing
/// `delivered_segments` at the start of the next poll drops every
/// handle, releasing the pins.
///
/// Ownership contract: construction via `from_raw` transfers one
/// refcount from the caller to the handle. Drop decrements that one
/// refcount. The pointer is never null (caller must bump refcount
/// before constructing, so the pointed-to mbuf is live). Cloning is
/// NOT supported — that would require a refcount bump at clone time,
/// which callers can do explicitly via `shim_rte_mbuf_refcnt_update`
/// + another `from_raw` if needed.
pub struct MbufHandle {
    ptr: NonNull<sys::rte_mbuf>,
}

impl MbufHandle {
    /// Wrap an already-refcount-bumped mbuf pointer. The caller transfers
    /// one unit of refcount ownership to this handle; dropping the
    /// handle decrements the refcount by one.
    ///
    /// # Safety
    /// Caller guarantees `ptr` points to a live mbuf with at least one
    /// refcount owned by the caller (which this handle takes ownership
    /// of). After this call, the caller MUST NOT release that refcount
    /// on its own — it's the handle's responsibility now.
    #[inline]
    pub unsafe fn from_raw(ptr: NonNull<sys::rte_mbuf>) -> Self {
        Self { ptr }
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut sys::rte_mbuf {
        self.ptr.as_ptr()
    }

    #[inline]
    pub fn as_non_null(&self) -> NonNull<sys::rte_mbuf> {
        self.ptr
    }

    /// Create a second owning handle over the same underlying rte_mbuf by
    /// bumping its refcount. The returned handle has its own Drop that
    /// decrements on drop — so the underlying mbuf is freed only when ALL
    /// handles have been dropped.
    ///
    /// Refcount-bookkeeping invariant: the `shim_rte_mbuf_refcnt_update(+1)`
    /// MUST be the last fallible-or-allocating call before the infallible
    /// `Self::from_raw`. Otherwise a failure between the bump and the
    /// handle construction would leak the refcount.
    ///
    /// Explicit method (not `Clone` derive) so accidental copies don't
    /// silently bump the refcount at call sites that only intended a borrow.
    ///
    /// Primary caller: partial-segment splits in `deliver_readable` — the
    /// delivered portion gets a fresh refcount via this clone; the
    /// in-queue portion retains its existing refcount.
    #[inline]
    pub fn try_clone(&self) -> Self {
        // SAFETY: self.ptr is a valid NonNull<rte_mbuf> (invariant of MbufHandle).
        // The refcount bump is the last operation before the infallible from_raw;
        // no intervening allocations or panickable calls.
        unsafe {
            sys::shim_rte_mbuf_refcnt_update(self.ptr.as_ptr(), 1);
            Self::from_raw(self.ptr)
        }
    }
}

impl Drop for MbufHandle {
    fn drop(&mut self) {
        // SAFETY: `ptr` was validated at construction and the handle
        // owns exactly one refcount.
        //
        // We read the refcount BEFORE decrementing so we can deterministically
        // compute the post-dec value as `pre - 1` without re-reading after the
        // dec. Reading after the dec would be UAF when pre==1: the dec returns
        // the mbuf to its mempool, and the pool may have recycled the slot
        // before our read lands. Computing post-dec from the pre-dec read is
        // sound because the engine serializes mbuf operations on its lcore
        // (no other thread mutates the refcount concurrently).
        // A10 Stage B fix: use rte_pktmbuf_free_seg, NOT
        // rte_mbuf_refcnt_update(-1). The refcnt_update primitive only
        // decrements the atomic; it does NOT return the mbuf to its
        // mempool when the count reaches 0. The pktmbuf_free_seg
        // primitive checks the refcount and properly returns to pool
        // on last-ref drop. The leak surfaced as a 1-mbuf-per-iteration
        // RX-mempool drain in bench-e2e/bench-stress; the cliff hit at
        // iteration ~11151 (capacity=12288) when the pool exhausted.
        let pre = unsafe { sys::shim_rte_mbuf_refcnt_read(self.ptr.as_ptr()) };
        unsafe {
            sys::shim_rte_pktmbuf_free_seg(self.ptr.as_ptr());
        }
        let post = pre.saturating_sub(1);
        // Diagnostic fires on:
        // - High refcount leak: post > MBUF_DROP_UNEXPECTED_THRESHOLD
        //   (currently 8 — see the constant for the rationale; more
        //   handles outstanding than any legitimate path holds
        //   simultaneously).
        // - Double-dec / saturating-underflow: pre == 0 (a Drop
        //   ran on a handle whose mbuf was already freed by another
        //   path — symmetric leak signal, same forensic value).
        if pre == 0 || post > MBUF_DROP_UNEXPECTED_THRESHOLD {
            // Diagnostic: post-dec count above legitimate-handle ceiling
            // = unbalanced refcount. Bump only when an engine is bound
            // on this thread (THREAD_COUNTERS_PTR is set in
            // Engine::new / cleared in Engine::drop).
            THREAD_COUNTERS_PTR.with(|cell| {
                let p = cell.get();
                if !p.is_null() {
                    // SAFETY: pointer set by Engine::new and not yet
                    // cleared (Engine::drop hasn't fired) → still valid.
                    unsafe {
                        (*p).tcp
                            .mbuf_refcnt_drop_unexpected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        }
    }
}

impl std::fmt::Debug for MbufHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MbufHandle")
            .field("ptr", &self.ptr.as_ptr())
            .finish()
    }
}

// SAFETY: MbufHandle holds a raw mbuf pointer but the engine serializes
// access on one lcore. Matches the `Send` story on `Mbuf` / `Mempool`.
unsafe impl Send for MbufHandle {}

#[cfg(test)]
mod try_clone_tests {
    use super::*;
    // Note: real mempool tests need DPDK EAL; we test the refcount logic using
    // a synthetic mbuf allocated via rte_pktmbuf_alloc. If tests cannot reach
    // the DPDK runtime, guard with #[ignore] — the actual verification happens
    // via the TAP integration tests in Task 13.
    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    #[ignore = "requires DPDK EAL + mempool; covered by tests/rx_close_drains_mbufs.rs"]
    fn try_clone_bumps_refcount() {
        // Placeholder: integration test in Task 13 asserts the real refcount
        // contract end-to-end. This stub documents intent and forces a
        // compile-check on the `try_clone` signature.
        let _check: fn(&MbufHandle) -> MbufHandle = MbufHandle::try_clone;
    }
}
