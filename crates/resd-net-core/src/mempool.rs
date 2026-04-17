use resd_net_sys as sys;
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
        let ptr = NonNull::new(p).ok_or(Error::MempoolCreate("rte_pktmbuf_pool_create returned NULL"))?;
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
