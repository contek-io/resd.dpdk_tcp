use std::sync::atomic::{AtomicU64, Ordering};

/// Per-lcore counter struct. Cacheline-grouped.
/// Hot-path increments use Relaxed stores on the owning lcore;
/// cross-lcore snapshot reads use Relaxed loads. Per spec §9.1.
#[repr(C, align(64))]
pub struct EthCounters {
    pub rx_pkts: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rx_drop_miss_mac: AtomicU64,
    pub rx_drop_nomem: AtomicU64,
    pub tx_pkts: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub tx_drop_full_ring: AtomicU64,
    pub tx_drop_nomem: AtomicU64,
    // Phase A2 additions
    pub rx_drop_short: AtomicU64,
    pub rx_drop_unknown_ethertype: AtomicU64,
    pub rx_arp: AtomicU64,
    pub tx_arp: AtomicU64,
    // A-HW additions — all slow-path per spec §9.1.1. Fields always
    // allocated regardless of feature flags (C-ABI stability). Feature-off
    // builds never bump the offload_missing_* counters because the
    // corresponding offload requests are compile-gated away entirely.
    // See docs/superpowers/specs/2026-04-19-stage1-phase-a-hw-ena-offload-design.md §11.
    /// Offload advertised-request-mismatch counters (one-shot at bring-up).
    pub offload_missing_rx_cksum_ipv4: AtomicU64,
    pub offload_missing_rx_cksum_tcp: AtomicU64,
    pub offload_missing_rx_cksum_udp: AtomicU64,
    pub offload_missing_tx_cksum_ipv4: AtomicU64,
    pub offload_missing_tx_cksum_tcp: AtomicU64,
    pub offload_missing_tx_cksum_udp: AtomicU64,
    pub offload_missing_mbuf_fast_free: AtomicU64,
    pub offload_missing_rss_hash: AtomicU64,
    /// Fires only when driver is net_ena AND LLQ advertised-but-not-activated.
    /// Expected 0 on ENA with default enable_llq=1.
    pub offload_missing_llq: AtomicU64,
    /// Expected 1 on ENA (documented steady state — ENA does not register
    /// the rte_dynfield_timestamp dynfield). 0 on mlx5/ice/future-gen ENA.
    pub offload_missing_rx_timestamp: AtomicU64,
    /// Per-packet drop counter for RX segments the NIC classified as
    /// RTE_MBUF_F_RX_IP_CKSUM_BAD or RTE_MBUF_F_RX_L4_CKSUM_BAD. Expected 0
    /// on well-formed traffic. Not an offload-missing counter.
    pub rx_drop_cksum_bad: AtomicU64,
    _pad: [AtomicU64; 9],
}

#[repr(C, align(64))]
pub struct IpCounters {
    pub rx_csum_bad: AtomicU64,
    pub rx_ttl_zero: AtomicU64,
    pub rx_frag: AtomicU64,
    pub rx_icmp_frag_needed: AtomicU64,
    pub pmtud_updates: AtomicU64,
    // Phase A2 additions
    pub rx_drop_short: AtomicU64,
    pub rx_drop_bad_version: AtomicU64,
    pub rx_drop_bad_hl: AtomicU64,
    pub rx_drop_not_ours: AtomicU64,
    pub rx_drop_unsupported_proto: AtomicU64,
    pub rx_tcp: AtomicU64,
    pub rx_icmp: AtomicU64,
    _pad: [u64; 4],
}

#[repr(C, align(64))]
pub struct TcpCounters {
    pub rx_syn_ack: AtomicU64,
    pub rx_data: AtomicU64,
    pub rx_ack: AtomicU64,
    pub rx_rst: AtomicU64,
    pub rx_out_of_order: AtomicU64,
    pub tx_retrans: AtomicU64,
    pub tx_rto: AtomicU64,
    pub tx_tlp: AtomicU64,
    pub conn_open: AtomicU64,
    pub conn_close: AtomicU64,
    pub conn_rst: AtomicU64,
    pub send_buf_full: AtomicU64,
    pub recv_buf_delivered: AtomicU64,
    // Phase A3 additions
    pub tx_syn: AtomicU64,
    pub tx_ack: AtomicU64,
    pub tx_data: AtomicU64,
    pub tx_fin: AtomicU64,
    pub tx_rst: AtomicU64,
    pub rx_fin: AtomicU64,
    pub rx_unmatched: AtomicU64,
    pub rx_bad_csum: AtomicU64,
    pub rx_bad_flags: AtomicU64,
    pub rx_short: AtomicU64,
    /// Phase A3: bytes peer sent beyond our current recv buffer free_space.
    /// See `feedback_performance_first_flow_control.md` — we don't shrink
    /// rcv_wnd to throttle the peer; we keep accepting at full capacity and
    /// expose pressure here so the application can diagnose a slow consumer.
    pub recv_buf_drops: AtomicU64,
    // Phase A4 additions — slow-path only per spec §9.1.1.
    /// PAWS (RFC 7323 §5): segment dropped because `SEG.TSval < TS.Recent`.
    pub rx_paws_rejected: AtomicU64,
    /// TCP option decoder rejected a malformed option (runaway len, zero
    /// optlen on unknown kind, known-option wrong length). Extends A3's
    /// defensive posture (plan I-9) to WSCALE / TS / SACK-permitted / SACK.
    pub rx_bad_option: AtomicU64,
    /// OOO segment placed on the reassembly queue (fires on reorder/loss).
    pub rx_reassembly_queued: AtomicU64,
    /// Hole closed; contiguous prefix drained from reassembly into recv.
    pub rx_reassembly_hole_filled: AtomicU64,
    /// SACK blocks encoded in an outbound ACK (RFC 2018; fires only when
    /// recv.reorder is non-empty).
    pub tx_sack_blocks: AtomicU64,
    /// SACK blocks decoded from an inbound ACK (RFC 2018; fires only on
    /// peer-side loss).
    pub rx_sack_blocks: AtomicU64,
    // Cross-phase slow-path backfill — sites exist from earlier phases but
    // had no counter until A4 wired them.
    /// Segment with seq outside `rcv_wnd`; was silently dropped pre-A4.
    pub rx_bad_seq: AtomicU64,
    /// ACK acking nothing new or acking future data.
    pub rx_bad_ack: AtomicU64,
    /// Duplicate ACK (baseline for A5 fast-retransmit consumer).
    pub rx_dup_ack: AtomicU64,
    /// Peer advertised `rwnd=0` — critical trading signal ("exchange is slow").
    pub rx_zero_window: AtomicU64,
    /// URG flag segment; Stage 1 doesn't support URG, dropped.
    pub rx_urgent_dropped: AtomicU64,
    /// We advertised `rwnd=0` (our recv buffer full).
    pub tx_zero_window: AtomicU64,
    /// We emitted a pure window-update segment.
    pub tx_window_update: AtomicU64,
    /// `resd_net_connect` rejected because flow table at `max_connections`.
    pub conn_table_full: AtomicU64,
    /// TIME_WAIT deadline expired, connection reclaimed.
    pub conn_time_wait_reaped: AtomicU64,
    /// HOT-PATH, feature-gated by `obs-byte-counters` (default OFF).
    /// Per-burst-batched — see spec §9.1.1. Increment site lives in
    /// engine.rs, gated by `#[cfg(feature = "obs-byte-counters")]`.
    /// Answers: "how many TCP payload bytes did this engine move?"
    /// Irreducible to eth.tx_bytes (which includes L2/L3 overhead).
    pub tx_payload_bytes: AtomicU64,
    /// HOT-PATH, feature-gated by `obs-byte-counters` (default OFF).
    /// Same rationale as `tx_payload_bytes`, applied to RX.
    pub rx_payload_bytes: AtomicU64,
    /// 11×11 state transition matrix, indexed [from][to] where from/to are
    /// `TcpState as u8`. Per spec §9.1. Unused cells stay at zero.
    pub state_trans: [[AtomicU64; 11]; 11],
    // A5 additions (slow-path only; hot-path additions need compile-time
    // feature gate per spec §9.1.1).
    /// Task 13: data-retransmit budget exhausted → conn ETIMEDOUT.
    pub conn_timeout_retrans: AtomicU64,
    /// Task 18: SYN retransmit budget exhausted → conn ETIMEDOUT.
    pub conn_timeout_syn_sent: AtomicU64,
    /// Task 26 (from Task 11): RTT sample taken (TS or Karn's).
    pub rtt_samples: AtomicU64,
    /// Task 15: RACK detect-lost identified a segment as lost.
    pub tx_rack_loss: AtomicU64,
    /// Task 19 diagnostic: conn has rack_aggressive=true.
    pub rack_reo_wnd_override_active: AtomicU64,
    /// Task 19 diagnostic: conn has rto_no_backoff=true.
    pub rto_no_backoff_active: AtomicU64,
    /// Task 22: peer offered WS>14; clamped to 14 per RFC 7323 §2.3.
    pub rx_ws_shift_clamped: AtomicU64,
    /// Task 16: DSACK observed (RFC 2883; visibility only).
    pub rx_dsack: AtomicU64,
    /// A5.5 Task 11/12: TLP probe retroactively classified as spurious via
    /// DSACK (RFC 8985 §7.4 / spec §3.4). Declared here; wired in Task 12.
    pub tx_tlp_spurious: AtomicU64,
    // --- A6 additions (all slow-path per §9.1.1 rule 1) ---
    /// A6: public-timer-API fire. Incremented once per `ApiPublic`
    /// wheel node firing through `advance_timer_wheel` — a slow-path
    /// boundary (not per-segment / per-burst / per-poll).
    pub tx_api_timers_fired: AtomicU64,
    /// A6: RFC 7323 §5.5 24-day `TS.Recent` expiration fired on an
    /// inbound segment's PAWS gate. Effectively zero on healthy
    /// trading traffic; nonzero is operationally interesting.
    pub ts_recent_expired: AtomicU64,
    /// A6: `drain_tx_pending_data` called `rte_eth_tx_burst`. One
    /// fetch_add per drain (per end-of-poll + per `resd_net_flush`).
    pub tx_flush_bursts: AtomicU64,
    /// A6: aggregate `sent` count summed across every `tx_flush_bursts`
    /// call. Useful to compute mean-batch-size = tx_flush_batched_pkts
    /// / tx_flush_bursts; values near 1 mean the data path isn't
    /// actually batching.
    pub tx_flush_batched_pkts: AtomicU64,
}

#[repr(C, align(64))]
pub struct PollCounters {
    pub iters: AtomicU64,
    pub iters_with_rx: AtomicU64,
    pub iters_with_tx: AtomicU64,
    pub iters_idle: AtomicU64,
    /// HOT-PATH, feature-gated by `obs-poll-saturation` (default ON).
    /// Bumped on every poll iteration where `rx_burst` returned
    /// `max_burst` — signals "we may be falling behind the NIC". No
    /// cheap alternative; batching pattern is a single conditional
    /// `fetch_add` per poll.
    pub iters_with_rx_burst_max: AtomicU64,
    _pad: [u64; 11],
}

/// Engine-internal observability counters (A5.5).
///
/// All slow-path per §9.1.1 — fires only when observability pressure exists
/// (event-queue overflow). No RX/TX hot-path increments.
#[repr(C)]
pub struct ObsCounters {
    /// Count of events dropped from `EventQueue` due to soft-cap overflow.
    /// Nonzero = app poll cadence cannot keep up + some events were lost.
    pub events_dropped: AtomicU64,
    /// Latched max observed queue depth since engine start.
    /// High value with events_dropped == 0 = close call;
    /// high value with nonzero events_dropped = actual loss.
    pub events_queue_high_water: AtomicU64,
}

#[repr(C)]
pub struct Counters {
    pub eth: EthCounters,
    pub ip: IpCounters,
    pub tcp: TcpCounters,
    pub poll: PollCounters,
    pub obs: ObsCounters,
}

impl Counters {
    pub fn new() -> Self {
        // Default impl from derive not available for atomics; explicit init.
        Self {
            eth: EthCounters::default(),
            ip: IpCounters::default(),
            tcp: TcpCounters::default(),
            poll: PollCounters::default(),
            obs: ObsCounters::default(),
        }
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for EthCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
impl Default for IpCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
impl Default for TcpCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
impl Default for PollCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
impl Default for ObsCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// Hot-path increment: atomic RMW with Relaxed ordering.
/// On x86_64 this is `lock xadd` — a few cycles slower than a plain store,
/// but sound under any producer layout and prevents lost-update races
/// if a counter is ever written from a non-owning thread by mistake.
#[inline(always)]
pub fn inc(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

#[inline(always)]
pub fn add(a: &AtomicU64, n: u64) {
    a.fetch_add(n, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_construct() {
        let c = Counters::new();
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.conn_open.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inc_works() {
        let c = Counters::new();
        inc(&c.eth.rx_pkts);
        inc(&c.eth.rx_pkts);
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cross_thread_inc_correct_under_contention() {
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(Counters::new());
        let producers: Vec<_> = (0..4)
            .map(|_| {
                let c = Arc::clone(&c);
                thread::spawn(move || {
                    for _ in 0..25_000 {
                        inc(&c.eth.rx_pkts);
                    }
                })
            })
            .collect();
        for p in producers {
            p.join().unwrap();
        }
        // Would fail if inc() were load-modify-store (lost increments).
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 100_000);
    }

    #[test]
    fn counters_group_alignment() {
        // Ensure each group is its own cacheline.
        assert_eq!(std::mem::align_of::<EthCounters>(), 64);
        assert_eq!(std::mem::align_of::<IpCounters>(), 64);
        assert_eq!(std::mem::align_of::<TcpCounters>(), 64);
        assert_eq!(std::mem::align_of::<PollCounters>(), 64);
    }

    #[test]
    fn a2_new_counters_exist_and_zero() {
        let c = Counters::new();
        // eth additions
        assert_eq!(c.eth.rx_drop_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_drop_unknown_ethertype.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_arp.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.tx_arp.load(Ordering::Relaxed), 0);
        // ip additions
        assert_eq!(c.ip.rx_drop_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_bad_version.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_bad_hl.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_not_ours.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_unsupported_proto.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_tcp.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_icmp.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a3_new_tcp_counters_exist_and_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.tx_syn.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_ack.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_data.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_fin.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_rst.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_fin.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_unmatched.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_bad_csum.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_bad_flags.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.recv_buf_drops.load(Ordering::Relaxed), 0);
        // Transition matrix is 11×11 = 121 u64s; all zero at construction.
        for row in &c.tcp.state_trans {
            for cell in row {
                assert_eq!(cell.load(Ordering::Relaxed), 0);
            }
        }
    }

    /// Every named AtomicU64 on EthCounters is zero at construction.
    /// Fields: A1 = rx_pkts, rx_bytes, rx_drop_miss_mac, rx_drop_nomem,
    /// tx_pkts, tx_bytes, tx_drop_full_ring, tx_drop_nomem; A2 = the
    /// rx_drop_{short,unknown_ethertype} + rx_arp/tx_arp pair.
    #[test]
    fn all_eth_counters_zero_at_construction() {
        let c = Counters::new();
        // A1
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_drop_miss_mac.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_drop_nomem.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.tx_pkts.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.tx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.tx_drop_full_ring.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.tx_drop_nomem.load(Ordering::Relaxed), 0);
        // A2
        assert_eq!(c.eth.rx_drop_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_drop_unknown_ethertype.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_arp.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.tx_arp.load(Ordering::Relaxed), 0);
    }

    /// Every named AtomicU64 on IpCounters is zero at construction.
    #[test]
    fn all_ip_counters_zero_at_construction() {
        let c = Counters::new();
        assert_eq!(c.ip.rx_csum_bad.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_ttl_zero.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_frag.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_icmp_frag_needed.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.pmtud_updates.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_bad_version.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_bad_hl.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_not_ours.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_unsupported_proto.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_tcp.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_icmp.load(Ordering::Relaxed), 0);
    }

    /// Every named AtomicU64 on PollCounters is zero at construction.
    /// `iters_with_tx` is declared but not incremented until A6.
    #[test]
    fn all_poll_counters_zero_at_construction() {
        let c = Counters::new();
        assert_eq!(c.poll.iters.load(Ordering::Relaxed), 0);
        assert_eq!(c.poll.iters_with_rx.load(Ordering::Relaxed), 0);
        assert_eq!(c.poll.iters_with_tx.load(Ordering::Relaxed), 0);
        assert_eq!(c.poll.iters_idle.load(Ordering::Relaxed), 0);
    }

    /// A5 TX retransmit counters (tx_retrans, tx_rto, tx_tlp) start at
    /// zero at construction. They're wired in Tasks 9/12/17 (retransmit
    /// primitive, on_rto_fire, on_tlp_fire).
    #[test]
    fn tx_retrans_counters_zero_at_construction() {
        let c = Counters::new();
        assert_eq!(c.tcp.rx_out_of_order.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_retrans.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_rto.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_tlp.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a4_hotpath_fields_declared_and_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.tx_payload_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_payload_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(c.poll.iters_with_rx_burst_max.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a4_new_tcp_counters_exist_and_zero() {
        let c = Counters::new();
        // A4 scope
        assert_eq!(c.tcp.rx_paws_rejected.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_bad_option.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_reassembly_queued.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_reassembly_hole_filled.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_sack_blocks.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_sack_blocks.load(Ordering::Relaxed), 0);
        // Cross-phase backfill
        assert_eq!(c.tcp.rx_bad_seq.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_bad_ack.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_dup_ack.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_zero_window.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_urgent_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_zero_window.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_window_update.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.conn_table_full.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.conn_time_wait_reaped.load(Ordering::Relaxed), 0);
    }

    /// A5 pre-declared slow-path fields. Task 13 wires
    /// `conn_timeout_retrans`; the rest are wired in later A5 tasks
    /// (15/16/18/19/22/26) but the fields live here now to avoid
    /// re-touching counters.rs on every task.
    #[test]
    fn a5_new_tcp_counters_exist_and_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.conn_timeout_retrans.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.conn_timeout_syn_sent.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rtt_samples.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_rack_loss.load(Ordering::Relaxed), 0);
        assert_eq!(
            c.tcp.rack_reo_wnd_override_active.load(Ordering::Relaxed),
            0
        );
        assert_eq!(c.tcp.rto_no_backoff_active.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_ws_shift_clamped.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_dsack.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod a5_5_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn engine_counters_has_obs_group_zero_initialized() {
        let c = Counters::new();
        assert_eq!(c.obs.events_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(c.obs.events_queue_high_water.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn tlp_counters_tx_tlp_spurious_exists_and_zero_initialized() {
        let c = Counters::new();
        assert_eq!(c.tcp.tx_tlp_spurious.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a6_new_tcp_counters_exist_and_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.tx_api_timers_fired.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.ts_recent_expired.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_flush_bursts.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_flush_batched_pkts.load(Ordering::Relaxed), 0);
    }
}
