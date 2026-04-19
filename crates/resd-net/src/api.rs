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
    // A5 Task 21: RTO config in µs. `tcp_initial_rto_ms` was removed
    // in favor of `tcp_initial_rto_us`; the surrounding `_us` fields
    // replace the A3 single-value knob with a full floor/initial/max
    // tuple plus the per-segment retransmit budget.
    pub tcp_min_rto_us: u32,
    pub tcp_initial_rto_us: u32,
    pub tcp_max_rto_us: u32,
    pub tcp_max_retrans_count: u32,
    pub tcp_msl_ms: u32,
    pub tcp_per_packet_events: bool,
    pub preset: u8,
    // Phase A2 additions (host byte order for ints, raw bytes for MAC)
    pub local_ip: u32,
    pub gateway_ip: u32,
    pub gateway_mac: [u8; 6],
    pub garp_interval_sec: u32,
    /// A5.5 event-queue overflow guard (§3.2 / §5.1). Default 4096;
    /// must be >= 64. Queue drops oldest on overflow.
    pub event_queue_soft_cap: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct resd_net_connect_opts_t {
    pub peer_addr: u32, // network byte order IPv4
    pub peer_port: u16,
    pub local_addr: u32,
    pub local_port: u16,
    pub connect_timeout_ms: u32,
    pub idle_keepalive_sec: u32,
    // A5 Task 19: per-connect opt-ins. Appended at the tail so zero-init
    // of existing callers keeps both disabled (A5 baseline). See
    // `resd_net_core::engine::ConnectOpts` for field semantics.
    pub rack_aggressive: bool,
    pub rto_no_backoff: bool,
    /// A5.5 Task 10: per-connect RFC 8985 §7.2 PTO floor (µs).
    /// `0` (default) inherits engine `tcp_min_rto_us`; `u32::MAX`
    /// is the explicit "no-floor" sentinel (yields `floor_us = 0`
    /// in the projected `TlpConfig`). Any other value must be
    /// `<= tcp_max_rto_us`, else `resd_net_connect` returns `-EINVAL`.
    pub tlp_pto_min_floor_us: u32,
    /// A5.5 Task 10: per-connect SRTT multiplier (×100) for PTO base.
    /// Default (`0` → `200` at `resd_net_connect` entry) matches RFC
    /// 8985 `2·SRTT`. Valid range post-substitution: `[100, 200]`.
    /// Values outside that range cause `resd_net_connect` to return
    /// `-EINVAL`.
    pub tlp_pto_srtt_multiplier_x100: u16,
    /// A5.5 Task 10: when `true`, suppresses the RFC 8985 §7.2
    /// FlightSize==1 `+max(WCDelAckT, SRTT/4)` penalty (trading-
    /// latency opt-out; accepts a small spurious-TLP risk on
    /// delayed-ACK receivers).
    pub tlp_skip_flight_size_gate: bool,
    /// A5.5 Task 10: per-connect cap on consecutive TLP probes before
    /// falling through to RTO. Default (`0` → `1` at `resd_net_connect`
    /// entry) matches A5 / RFC 8985 §7.1 single-probe behavior. Valid
    /// range post-substitution: `[1, 5]`. Out-of-range causes `-EINVAL`.
    pub tlp_max_consecutive_probes: u8,
    /// A5.5 Task 10: when `true`, suppresses the "require an RTT sample
    /// since last TLP" gate in TLP scheduling (trading-latency opt-out;
    /// permits back-to-back TLPs even if no peer ACK has produced a
    /// fresh RTT sample).
    pub tlp_skip_rtt_sample_gate: bool,
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
    /// ns timestamp (engine monotonic clock) sampled at event emission
    /// inside the stack. Unrelated to `rx_hw_ts_ns`. For packet-triggered
    /// events, emission time is when the stack processed the triggering
    /// packet, not when the NIC received it — use `rx_hw_ts_ns` for
    /// NIC-arrival time. For timer-triggered events (RTO fire, RACK / TLP
    /// loss-detected), emission time is the fire instant.
    pub enqueued_ts_ns: u64,
    pub u: resd_net_event_payload_t,
}

/// Close flags — bitmask for resd_net_close.
pub const RESD_NET_CLOSE_FORCE_TW_SKIP: u32 = 1 << 0;

/// A5.5 per-connection observable state snapshot (spec §5.3, §7.2.3–7.2.6).
/// Slow-path projection mirroring `resd_net_core::tcp_conn::ConnStats`; all
/// values are in application-useful units — bytes for the send-buffer
/// fields, microseconds (`_us`) for the RTT estimator fields. Before the
/// first RTT sample has been absorbed, `srtt_us`, `rttvar_us`, and
/// `min_rtt_us` all report 0 and `rto_us` reports the engine's configured
/// `tcp_initial_rto_us`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct resd_net_conn_stats_t {
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub send_buf_bytes_pending: u32,
    pub send_buf_bytes_free: u32,
    pub srtt_us: u32,
    pub rttvar_us: u32,
    pub min_rtt_us: u32,
    pub rto_us: u32,
}

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
    // Phase A3 additions
    pub tx_syn: u64,
    pub tx_ack: u64,
    pub tx_data: u64,
    pub tx_fin: u64,
    pub tx_rst: u64,
    pub rx_fin: u64,
    pub rx_unmatched: u64,
    pub rx_bad_csum: u64,
    pub rx_bad_flags: u64,
    pub rx_short: u64,
    /// Phase A3: bytes peer sent beyond our current recv buffer free_space.
    /// See `feedback_performance_first_flow_control.md` — we don't shrink
    /// rcv_wnd to throttle the peer; we keep accepting at full capacity and
    /// expose pressure here so the application can diagnose a slow consumer.
    pub recv_buf_drops: u64,
    // Phase A4 additions — see core counters.rs for the full field doc.
    pub rx_paws_rejected: u64,
    pub rx_bad_option: u64,
    pub rx_reassembly_queued: u64,
    pub rx_reassembly_hole_filled: u64,
    pub tx_sack_blocks: u64,
    pub rx_sack_blocks: u64,
    pub rx_bad_seq: u64,
    pub rx_bad_ack: u64,
    pub rx_dup_ack: u64,
    pub rx_zero_window: u64,
    pub rx_urgent_dropped: u64,
    pub tx_zero_window: u64,
    pub tx_window_update: u64,
    pub conn_table_full: u64,
    pub conn_time_wait_reaped: u64,
    /// HOT-PATH, feature-gated by `obs-byte-counters` (default OFF).
    /// Per-burst-batched TCP payload byte counters. See core counters.rs.
    pub tx_payload_bytes: u64,
    pub rx_payload_bytes: u64,
    pub state_trans: [[u64; 11]; 11],
    // Phase A5 additions — slow-path only. Declaration order must match
    // `resd_net_core::counters::TcpCounters` exactly. Field docs live on
    // the core struct (see counters.rs).
    pub conn_timeout_retrans: u64,
    pub conn_timeout_syn_sent: u64,
    pub rtt_samples: u64,
    pub tx_rack_loss: u64,
    pub rack_reo_wnd_override_active: u64,
    pub rto_no_backoff_active: u64,
    pub rx_ws_shift_clamped: u64,
    pub rx_dsack: u64,
    /// A5.5 Task 11/12 — see core counters.rs for the full field doc.
    pub tx_tlp_spurious: u64,
    pub _pad: [u64; 1],
}
#[repr(C, align(64))]
pub struct resd_net_poll_counters_t {
    pub iters: u64,
    pub iters_with_rx: u64,
    pub iters_with_tx: u64,
    pub iters_idle: u64,
    /// HOT-PATH, feature-gated by `obs-poll-saturation` (default ON).
    /// See core counters.rs for the full field doc.
    pub iters_with_rx_burst_max: u64,
    pub _pad: [u64; 11],
}
#[repr(C)]
pub struct resd_net_counters_t {
    pub eth: resd_net_eth_counters_t,
    pub ip: resd_net_ip_counters_t,
    pub tcp: resd_net_tcp_counters_t,
    pub poll: resd_net_poll_counters_t,
    // A5.5 obs group (slow-path). Appended — no mid-struct insertion.
    // Mirrors `resd_net_core::counters::ObsCounters`; field docs live on
    // the core struct (see counters.rs).
    pub obs_events_dropped: u64,
    pub obs_events_queue_high_water: u64,
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

// A5.5 Task 7: `resd_net_conn_stats_t` is a field-for-field ABI mirror of
// `resd_net_core::tcp_conn::ConnStats` (both are `#[repr(C)]` with the
// same 9 `u32` fields in the same order). If either side changes, the
// field-copy in `resd_net_conn_stats` silently goes wrong; guard the
// shape at compile time.
const _: () = {
    use resd_net_core::tcp_conn::ConnStats as CoreConnStats;
    use std::mem::{align_of, size_of};
    assert!(size_of::<resd_net_conn_stats_t>() == size_of::<CoreConnStats>());
    assert!(align_of::<resd_net_conn_stats_t>() == align_of::<CoreConnStats>());
};
