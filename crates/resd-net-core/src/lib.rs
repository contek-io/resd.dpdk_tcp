//! Pure-Rust internals of the resd.dpdk_tcp stack.
//! The public `extern "C"` surface lives in the `resd-net` crate.

pub mod tcp_seq;
pub mod tcp_state;
pub mod flow_table;
pub mod tcp_conn;
pub mod tcp_output;
pub mod tcp_events;
pub mod tcp_input;
pub mod tcp_options;
pub mod tcp_reassembly;
pub mod iss;
pub mod arp;
pub mod clock;
pub mod counters;
pub mod engine;
pub mod error;
pub mod icmp;
pub mod l2;
pub mod l3_ip;
pub mod mempool;

pub use error::Error;

/// Helper exposed for unit tests and the poll loop.
/// Returns the byte slice backing the mbuf's first (and in Stage A2, only)
/// segment. The caller must not outlive the mbuf.
///
/// # Safety
///
/// `m` must be a valid non-null mbuf pointer. Uses the C-shim
/// accessors from `resd-net-sys` because `rte_mbuf` is opaque to bindgen
/// (packed anonymous unions) — see Task 9 for the shim wiring.
pub unsafe fn mbuf_data_slice<'a>(m: *mut resd_net_sys::rte_mbuf) -> &'a [u8] {
    let ptr = unsafe { resd_net_sys::resd_rte_pktmbuf_data(m) } as *const u8;
    let len = unsafe { resd_net_sys::resd_rte_pktmbuf_data_len(m) } as usize;
    unsafe { std::slice::from_raw_parts(ptr, len) }
}
