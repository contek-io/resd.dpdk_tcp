use dpdk_net_sys as sys;
use std::ffi::CString;
use std::ptr::NonNull;

use crate::Error;

/// RAII wrapper around an `rte_mempool*`.
/// Dropped pool calls `rte_mempool_free` on the inner pointer.
pub struct Mempool {
    ptr: NonNull<sys::rte_mempool>,
    name: CString,
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
        Ok(Self { ptr, name: cname })
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut sys::rte_mempool {
        self.ptr.as_ptr()
    }

    pub fn name(&self) -> &std::ffi::CStr {
        &self.name
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
/// Used by `TcpConn::recv::last_read_mbufs` to pin mbufs across an event
/// emission window: the engine bumps refcount + wraps in `MbufHandle`
/// when a READABLE event is queued; clearing `last_read_mbufs` at the
/// start of the next poll drops every handle, releasing the pins.
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
        // owns exactly one refcount. The decrement may take the count
        // to zero and return the mbuf to its mempool, which is the
        // intended end-of-life behaviour.
        unsafe {
            sys::shim_rte_mbuf_refcnt_update(self.ptr.as_ptr(), -1);
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
    #[test]
    #[ignore = "requires DPDK EAL + mempool; covered by tests/rx_close_drains_mbufs.rs"]
    fn try_clone_bumps_refcount() {
        // Placeholder: integration test in Task 13 asserts the real refcount
        // contract end-to-end. This stub documents intent and forces a
        // compile-check on the `try_clone` signature.
        let _check: fn(&MbufHandle) -> MbufHandle = MbufHandle::try_clone;
    }
}
