//! Pure-Rust internals of the resd.dpdk_tcp stack.
//! The public `extern "C"` surface lives in the `dpdk-net` crate.

pub mod arp;
#[cfg(feature = "bench-alloc-audit")]
pub mod bench_alloc_audit;
pub mod clock;
pub mod counters;
pub mod dpdk_consts;
pub mod engine;
pub mod error;
#[cfg(feature = "fault-injector")]
pub mod fault_injector;
pub mod flow_table;
pub mod icmp;
pub mod iss;
pub mod l2;
pub mod l3_ip;
#[cfg(feature = "hw-verify-llq")]
pub mod llq_verify;
pub mod wc_verify;
pub mod ena_xstats;
pub mod iovec;
pub mod mempool;
pub mod rtt_histogram;
pub mod siphash24;
pub mod tcp_conn;
pub mod tcp_events;
pub mod tcp_input;
pub mod tcp_options;
pub mod tcp_output;
pub mod tcp_rack;
pub mod tcp_reassembly;
pub mod tcp_retrans;
pub mod tcp_rtt;
pub mod tcp_sack;
pub mod tcp_seq;
pub mod tcp_state;
// a10-perf-23.11 T2.2: module is `pub(crate)` by default; `bench-internals`
// promotes it to `pub` so tools/bench-micro (external crate) can reach
// `TimerWheel`, `TimerId`, `TimerNode`, `TimerKind`, and the `TICK_NS` /
// `LEVELS` / `BUCKETS` constants. Every item inside is already `pub`;
// only the module's outer visibility changes. Production builds (default
// features) continue to see `pub(crate)` — identical compiled output.
#[cfg(not(feature = "bench-internals"))]
pub(crate) mod tcp_timer_wheel;
#[cfg(feature = "bench-internals")]
pub mod tcp_timer_wheel;
pub mod tcp_tlp;
#[cfg(feature = "test-inject")]
pub mod test_fixtures;
#[cfg(feature = "test-server")]
pub mod test_server;
#[cfg(feature = "test-server")]
pub mod test_tx_intercept;

pub use error::Error;

// a10-perf-23.11 T2.3: feature-gated convenience re-export so
// `tools/bench-micro` (and T2.4 unit tests) can `use dpdk_net_core::EngineNoEalHarness`
// without poking through the `engine::test_support::` path.
#[cfg(feature = "bench-internals")]
pub use engine::test_support::EngineNoEalHarness;

/// Helper exposed for unit tests and the poll loop.
/// Returns the byte slice backing the mbuf's first (and in Stage A2, only)
/// segment. The caller must not outlive the mbuf.
///
/// # Safety
///
/// `m` must be a valid non-null mbuf pointer. Uses the C-shim
/// accessors from `dpdk-net-sys` because `rte_mbuf` is opaque to bindgen
/// (packed anonymous unions) — see Task 9 for the shim wiring.
pub unsafe fn mbuf_data_slice<'a>(m: *mut dpdk_net_sys::rte_mbuf) -> &'a [u8] {
    let ptr = unsafe { dpdk_net_sys::shim_rte_pktmbuf_data(m) } as *const u8;
    let len = unsafe { dpdk_net_sys::shim_rte_pktmbuf_data_len(m) } as usize;
    unsafe { std::slice::from_raw_parts(ptr, len) }
}
