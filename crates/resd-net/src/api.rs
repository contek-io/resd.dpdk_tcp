//! Public C ABI type definitions.
//!
//! These are all `#[repr(C)]` structs / `#[repr(u32)]` enums so cbindgen
//! lays them out identically in C. Keep in sync with spec §4.
//!
//! Counters are emitted as plain `u64` fields on the C ABI even though the
//! stack writes them via `AtomicU64` internally — `AtomicU64` has identical
//! size and alignment as `u64` on x86_64, and cbindgen cannot emit an
//! atomic C type. See the layout assertion at the bottom of the file.

#[repr(C)]
pub struct resd_net_engine {
    _opaque: [u8; 0],
}

pub type resd_net_conn_t = u64;
pub type resd_net_timer_id_t = u64;

#[repr(C)]
pub struct resd_net_engine_config_t {
    pub port_id: u16,
    pub rx_queue_id: u16,
    pub tx_queue_id: u16,
    pub max_connections: u32,
    pub recv_buffer_bytes: u32,
    pub send_buffer_bytes: u32,
    pub tcp_mss: u32,
    pub tcp_timestamps: bool,
    pub tcp_sack: bool,
    pub tcp_ecn: bool,
    pub tcp_nagle: bool,
    pub tcp_delayed_ack: bool,
    pub cc_mode: u8,
    pub tcp_min_rto_ms: u32,
    pub tcp_initial_rto_ms: u32,
    pub tcp_msl_ms: u32,
    pub tcp_per_packet_events: bool,
    pub preset: u8,
}

#[repr(C)]
pub struct resd_net_connect_opts_t {
    pub peer_addr: u32, // network byte order IPv4
    pub peer_port: u16,
    pub local_addr: u32,
    pub local_port: u16,
    pub connect_timeout_ms: u32,
    pub idle_keepalive_sec: u32,
}

#[repr(u32)]
pub enum resd_net_event_kind_t {
    RESD_NET_EVT_CONNECTED = 1,
    RESD_NET_EVT_READABLE = 2,
    RESD_NET_EVT_WRITABLE = 3,
    RESD_NET_EVT_CLOSED = 4,
    RESD_NET_EVT_ERROR = 5,
    RESD_NET_EVT_TIMER = 6,
    RESD_NET_EVT_TCP_RETRANS = 7,
    RESD_NET_EVT_TCP_LOSS_DETECTED = 8,
    RESD_NET_EVT_TCP_STATE_CHANGE = 9,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct resd_net_event_readable_t {
    pub data: *const u8,
    pub data_len: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct resd_net_event_error_t {
    pub err: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct resd_net_event_timer_t {
    pub timer_id: u64,
    pub user_data: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct resd_net_event_tcp_retrans_t {
    pub seq: u32,
    pub rtx_count: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct resd_net_event_tcp_loss_t {
    pub first_seq: u32,
    pub trigger: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct resd_net_event_tcp_state_t {
    pub from_state: u8,
    pub to_state: u8,
}

/// Union-of-payloads approach: we lay out the union as a byte array and
/// expose accessor helpers. cbindgen emits it as a C union.
#[repr(C)]
pub union resd_net_event_payload_t {
    pub readable: resd_net_event_readable_t,
    pub error: resd_net_event_error_t,
    pub closed: resd_net_event_error_t,
    pub timer: resd_net_event_timer_t,
    pub tcp_retrans: resd_net_event_tcp_retrans_t,
    pub tcp_loss: resd_net_event_tcp_loss_t,
    pub tcp_state: resd_net_event_tcp_state_t,
    pub _pad: [u8; 16],
}

#[repr(C)]
pub struct resd_net_event_t {
    pub kind: resd_net_event_kind_t,
    pub conn: resd_net_conn_t,
    pub rx_hw_ts_ns: u64,
    pub enqueued_ts_ns: u64,
    pub u: resd_net_event_payload_t,
}

/// Close flags — bitmask for resd_net_close.
pub const RESD_NET_CLOSE_FORCE_TW_SKIP: u32 = 1 << 0;

/// Counters struct — exposed to application via resd_net_counters().
/// Fields are plain u64 on the C ABI for clean cbindgen emission, but
/// internally the stack writes them as AtomicU64 (Relaxed). AtomicU64
/// has identical size and alignment as u64 on x86_64 so pointer-casting
/// between resd_net_core::Counters and resd_net_counters_t is sound.
/// C/C++ readers should use `__atomic_load_n(&field, __ATOMIC_RELAXED)`
/// (or `std::atomic_ref<uint64_t>`) for strictly correct reads; on x86_64
/// this compiles to a plain `mov` so there's no runtime cost.
#[repr(C, align(64))]
pub struct resd_net_eth_counters_t {
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub rx_drop_miss_mac: u64,
    pub rx_drop_nomem: u64,
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    pub tx_drop_full_ring: u64,
    pub tx_drop_nomem: u64,
    // Phase A2 additions
    pub rx_drop_short: u64,
    pub rx_drop_unknown_ethertype: u64,
    pub rx_arp: u64,
    pub tx_arp: u64,
    pub _pad: [u64; 4],
}
#[repr(C, align(64))]
pub struct resd_net_ip_counters_t {
    pub rx_csum_bad: u64,
    pub rx_ttl_zero: u64,
    pub rx_frag: u64,
    pub rx_icmp_frag_needed: u64,
    pub pmtud_updates: u64,
    // Phase A2 additions
    pub rx_drop_short: u64,
    pub rx_drop_bad_version: u64,
    pub rx_drop_bad_hl: u64,
    pub rx_drop_not_ours: u64,
    pub rx_drop_unsupported_proto: u64,
    pub rx_tcp: u64,
    pub rx_icmp: u64,
    pub _pad: [u64; 4],
}
#[repr(C, align(64))]
pub struct resd_net_tcp_counters_t {
    pub rx_syn_ack: u64,
    pub rx_data: u64,
    pub rx_ack: u64,
    pub rx_rst: u64,
    pub rx_out_of_order: u64,
    pub tx_retrans: u64,
    pub tx_rto: u64,
    pub tx_tlp: u64,
    pub conn_open: u64,
    pub conn_close: u64,
    pub conn_rst: u64,
    pub send_buf_full: u64,
    pub recv_buf_delivered: u64,
    pub _pad: [u64; 3],
}
#[repr(C, align(64))]
pub struct resd_net_poll_counters_t {
    pub iters: u64,
    pub iters_with_rx: u64,
    pub iters_with_tx: u64,
    pub iters_idle: u64,
    pub _pad: [u64; 12],
}
#[repr(C)]
pub struct resd_net_counters_t {
    pub eth: resd_net_eth_counters_t,
    pub ip: resd_net_ip_counters_t,
    pub tcp: resd_net_tcp_counters_t,
    pub poll: resd_net_poll_counters_t,
}

// Compile-time checks: the public counters struct must have the same
// size AND alignment as resd_net_core::Counters (AtomicU64 has the same
// layout as u64 on targets we support). If either diverges, the
// pointer-cast in resd_net_counters() is unsound and this is a bug.
const _: () = {
    use resd_net_core::counters::{
        Counters as CoreCounters, EthCounters as CoreEth, IpCounters as CoreIp,
        PollCounters as CorePoll, TcpCounters as CoreTcp,
    };
    use std::mem::{align_of, size_of};
    assert!(size_of::<resd_net_counters_t>() == size_of::<CoreCounters>());
    assert!(align_of::<resd_net_eth_counters_t>() == align_of::<CoreEth>());
    assert!(align_of::<resd_net_ip_counters_t>() == align_of::<CoreIp>());
    assert!(align_of::<resd_net_tcp_counters_t>() == align_of::<CoreTcp>());
    assert!(align_of::<resd_net_poll_counters_t>() == align_of::<CorePoll>());
    assert!(size_of::<resd_net_eth_counters_t>() == size_of::<CoreEth>());
    assert!(size_of::<resd_net_ip_counters_t>() == size_of::<CoreIp>());
    assert!(size_of::<resd_net_tcp_counters_t>() == size_of::<CoreTcp>());
    assert!(size_of::<resd_net_poll_counters_t>() == size_of::<CorePoll>());
};
