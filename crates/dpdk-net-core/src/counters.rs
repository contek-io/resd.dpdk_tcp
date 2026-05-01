use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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
    // A-HW+ additions (this plan) — all slow-path per spec §9.1.1.
    // Always allocated for C-ABI stability. Writes are conditional in
    // later tasks (wc_verify.rs, ena_xstats.rs, engine bring-up). Order
    // below is H1 → M1 → H2 cluster → M3 cluster (logical grouping;
    // mirror in api.rs must match verbatim). See the plan at
    // docs/superpowers/plans/2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md
    // and the review at docs/references/ena-dpdk-review-2026-04-20.md.
    // H1 — WC BAR mapping verification (upstream ENA README §6.1).
    /// One-shot at bring-up: bumped via `fetch_add(1, Relaxed)` when the
    /// driver is net_ena AND `/sys/kernel/debug/x86/pat_memtype_list`
    /// does NOT show write-combining for the prefetchable BAR. WARN-only
    /// by default — LLQ TX degrades to UC-aligned 8-byte stores. Written
    /// by `wc_verify.rs` (Task 5). Expected 0 on a correctly-mapped ENA.
    pub llq_wc_missing: AtomicU64,
    // M1 — LLQ header overflow risk (upstream ENA README §5.1).
    /// One-shot at bring-up: bumped via `fetch_add(1, Relaxed)` when the
    /// worst-case TCP header stack (Eth + IP + TCP + opts) would exceed
    /// the LLQ default 96 B header limit AND the `ena_large_llq_hdr`
    /// devarg knob is 0. Written by the engine_create bring-up path
    /// (Task 8). Expected 0 once the knob defaults to 1 (Task 7).
    pub llq_header_overflow_risk: AtomicU64,
    // H2 — ENI allowance-exceeded xstats (upstream ENA README §8.2.2).
    // Snapshot semantics: `store(value, Relaxed)` overwrites with the
    // last-scraped value. Written by `ena_xstats.rs` (Task 10) on each
    // `dpdk_net_scrape_xstats` call. xstats names below are the literal
    // rte_eth_xstats strings resolved once at engine_create.
    /// ENA xstat: `bw_in_allowance_exceeded` (PPS-normalized bytes/s
    /// ingress that AWS shaped). Nonzero = VPC rate-limiter hit.
    pub eni_bw_in_allowance_exceeded: AtomicU64,
    /// ENA xstat: `bw_out_allowance_exceeded` (egress counterpart).
    pub eni_bw_out_allowance_exceeded: AtomicU64,
    /// ENA xstat: `pps_allowance_exceeded` (aggregate packets/s cap).
    pub eni_pps_allowance_exceeded: AtomicU64,
    /// ENA xstat: `conntrack_allowance_exceeded` (VPC conntrack table).
    pub eni_conntrack_allowance_exceeded: AtomicU64,
    /// ENA xstat: `linklocal_allowance_exceeded` (IMDS/DNS/NTP cap).
    pub eni_linklocal_allowance_exceeded: AtomicU64,
    // M3 — Per-queue ENA xstats, queue 0 only (upstream ENA README
    // §8.2.3–4). Stage 1 runs a single queue; when we scale to multi-
    // queue the snapshot set widens to q1..qN. Snapshot semantics:
    // `store(value, Relaxed)` on the same scrape tick as H2 above.
    /// ENA xstat: `tx_q0_linearize` — TX mbuf chains we rebuilt into a
    /// single segment because driver/LLQ couldn't consume the chain.
    pub tx_q0_linearize: AtomicU64,
    /// ENA xstat: `tx_q0_doorbells` — TX doorbell writes for queue 0.
    pub tx_q0_doorbells: AtomicU64,
    /// ENA xstat: `tx_q0_missed_tx` — AENQ "missing TX completion"
    /// watchdog (miss_txc_to timeout, see Task 12 knob).
    pub tx_q0_missed_tx: AtomicU64,
    /// ENA xstat: `tx_q0_bad_req_id` — TX completion with unknown req_id;
    /// HW/driver correctness signal. Expected 0.
    pub tx_q0_bad_req_id: AtomicU64,
    /// ENA xstat: `rx_q0_refill_partial` — RX refill gave the driver
    /// fewer mbufs than it asked for (mbuf pool pressure).
    pub rx_q0_refill_partial: AtomicU64,
    /// ENA xstat: `rx_q0_bad_desc_num` — RX descriptor count anomaly.
    pub rx_q0_bad_desc_num: AtomicU64,
    /// ENA xstat: `rx_q0_bad_req_id` — RX completion with unknown req_id.
    pub rx_q0_bad_req_id: AtomicU64,
    /// ENA xstat: `rx_q0_mbuf_alloc_fail` — RX mbuf allocation failed at
    /// refill time. Correlates with `rx_drop_nomem`.
    pub rx_q0_mbuf_alloc_fail: AtomicU64,
    // _pad sized to keep the struct on a 64-byte multiple.
    // 12 (pre-A-HW) + 11 (A-HW) + 15 (A-HW+) = 38 u64s → 304 B;
    // next 64-multiple is 320 B → pad with 2 u64s.
    _pad: [AtomicU64; 2],
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
    /// `dpdk_net_connect` rejected because flow table at `max_connections`.
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
    /// fetch_add per drain (per end-of-poll + per `dpdk_net_flush`).
    pub tx_flush_bursts: AtomicU64,
    /// A6: aggregate `sent` count summed across every `tx_flush_bursts`
    /// call. Useful to compute mean-batch-size = tx_flush_batched_pkts
    /// / tx_flush_bursts; values near 1 mean the data path isn't
    /// actually batching.
    pub tx_flush_batched_pkts: AtomicU64,
    // --- A6.6-7 Task 11: RX zero-copy event-shape counters (slow-path) ---
    // All three are bumped exactly once per emitted `Event::Readable`
    // from `deliver_readable` (never per-byte, never per-segment-loop).
    // See spec §9.1.1 — slow-path, batched `fetch_add`, no hot-path cost.
    /// A6.6-7: cumulative count of iovec segments emitted across every
    /// READABLE event. Incremented once per event via `fetch_add(n_segs,
    /// Relaxed)` (batched — a single RMW even when a READABLE covers N
    /// segments). Mean-segs-per-event = rx_iovec_segs_total / (count of
    /// READABLE events since start); values near 1 mean the reorder
    /// queue rarely carries multiple contiguous segments.
    pub rx_iovec_segs_total: AtomicU64,
    /// A6.6-7: count of READABLE events whose iovec slice covered more
    /// than one segment (`n_segs > 1`). Delta from
    /// `rx_iovec_segs_total - rx_multi_seg_events = single-seg events`;
    /// useful for reasoning about consumer loop shape.
    pub rx_multi_seg_events: AtomicU64,
    /// A6.6-7: count of READABLE events that required splitting the
    /// front reorder-queue segment (partial pop via `try_clone` +
    /// offset/len adjust). Incremented EXACTLY ONCE per event with a
    /// split — not per split segment, not per byte. Nonzero = the
    /// consumer is draining non-segment-aligned byte counts, which is
    /// the common case for byte-stream protocols.
    pub rx_partial_read_splits: AtomicU64,
    // --- A10 deferred-fix Stage A: RX-side leak diagnostics (slow-path) ---
    // Forensic-only: intentionally NOT mirrored in `dpdk_net_tcp_counters_t`
    // (crates/dpdk-net/src/api.rs). Consumed by the Rust-side bench-stress
    // counters_snapshot table + MbufHandle::Drop hook only. The size_of
    // const assertion at api.rs:503 holds because the 12 new bytes fit
    // inside the existing tail-padding of the #[repr(C, align(64))] struct;
    // mirroring these on the C side would break that invariant silently.
    /// Most-recently-sampled value of `rte_mempool_avail_count(rx_mp)`.
    /// Sampled at most once per second inside `poll_once`. A monotonically
    /// decreasing trend across a long run is the leading indicator of an
    /// RX mempool leak (root-cause hypothesis for the iteration-7050
    /// retransmit cliff documented in
    /// `docs/superpowers/reports/a10-ab-driver-debug.md` §3).
    pub rx_mempool_avail: AtomicU32,
    /// Cumulative count of `MbufHandle::Drop` invocations that observed
    /// a post-decrement refcount above the legitimate-handle threshold.
    /// Threshold rationale: no production path holds more than 32 handles
    /// to one mbuf concurrently (max in-flight conns × max simultaneous
    /// READABLE pins); a higher post-dec count is unequivocally a leak.
    pub mbuf_refcnt_drop_unexpected: AtomicU64,
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

// Pinned by phase-a-hw-plus Task 1 — `EthCounters` must stay on a
// cacheline-multiple size with cacheline alignment so the C-ABI mirror
// in dpdk-net/src/api.rs can hold byte-identical layout. Future
// additions MUST adjust `_pad` to keep this assertion true. Paired with
// the `size_of::<dpdk_net_eth_counters_t>() == size_of::<CoreEth>()`
// mirror-equality assertion in `crates/dpdk-net/src/api.rs`.
const _: () = {
    use std::mem::{align_of, size_of};
    assert!(align_of::<EthCounters>() == 64);
    assert!(size_of::<EthCounters>().is_multiple_of(64));
};

// A8-t2-drift-detect-pin: if any of these size pins becomes stale, a new
// AtomicU64 field has been added to the corresponding *Counters struct
// without updating ALL_COUNTER_NAMES + KNOWN_COUNTER_COUNT + lookup_counter.
// Update all three list sites AND this pin together.
//
// Every field in these structs is 8 bytes (AtomicU64 or u64 _pad). A new
// field shifts the struct size by at least 8 bytes — and for the
// cacheline-aligned groups, by a full 64 bytes once the tail padding is
// consumed. Either way, this pin breaks at compile time. That closes the
// scenario the two `a8_tests` runtime tests cannot see: new field present
// on Counters, absent from ALL_COUNTER_NAMES.
//
// To update: insert the new field in the matching *Counters struct (+
// adjust _pad, if any, so the struct stays cacheline-multiple), add a
// "group.field" entry to ALL_COUNTER_NAMES, extend the `lookup_counter`
// match arm, bump KNOWN_COUNTER_COUNT, then update the byte-count on the
// line below whose struct you changed.
const _: () = {
    use std::mem::size_of;
    // EthCounters: 38 named AtomicU64 + _pad: [AtomicU64; 2] = 40 * 8 = 320 bytes.
    assert!(size_of::<EthCounters>() == 320);
    // IpCounters: 12 named AtomicU64 + _pad: [u64; 4] = 16 * 8 = 128 bytes.
    assert!(size_of::<IpCounters>() == 128);
    // TcpCounters: 56 named scalar AtomicU64 + state_trans[11][11] matrix of
    // 121 AtomicU64 = 177 u64s = 1416 bytes; cacheline-align tail pads to
    // next 64-byte multiple = 1472 bytes.
    assert!(size_of::<TcpCounters>() == 1472);
    // PollCounters: 5 named AtomicU64 + _pad: [u64; 11] = 16 * 8 = 128 bytes.
    assert!(size_of::<PollCounters>() == 128);
    // ObsCounters: 2 named AtomicU64, repr(C) without align → 16 bytes.
    assert!(size_of::<ObsCounters>() == 16);
    // FaultInjectorCounters (A9): 4 named AtomicU64, repr(C, align(64)) →
    // 32 bytes of fields, padded to 64-byte multiple = 64 bytes.
    assert!(size_of::<FaultInjectorCounters>() == 64);
};

#[repr(C)]
pub struct Counters {
    pub eth: EthCounters,
    pub ip: IpCounters,
    pub tcp: TcpCounters,
    pub poll: PollCounters,
    pub obs: ObsCounters,
    /// A9 fault-injector group. Struct is always present on the C ABI
    /// (matching the `obs_events_dropped`/`tx_retrans` pre-declared
    /// pattern); cargo feature `fault-injector` only controls whether
    /// the FaultInjector middleware runs and populates these. cbindgen
    /// doesn't honour `#[cfg(feature=...)]` when scanning module trees,
    /// so feature-gated fields would leak into the default-build header.
    /// Keeping the field unconditional + populated-when-feature-on avoids
    /// that footgun (same pattern used for the A5 deferred tx_retrans /
    /// tx_rto / tx_tlp counters).
    pub fault_injector: FaultInjectorCounters,
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
            fault_injector: FaultInjectorCounters::default(),
        }
    }
}

/// Canonical source-of-truth list of every declared counter path.
/// Consumed by:
///   - tests/counter-coverage.rs (dynamic audit: one scenario per counter)
///   - scripts/counter-coverage-static.sh (static audit: every name must
///     have >= 1 increment site in default OR all-features build)
///   - tests/obs_smoke.rs (fail-loud: every non-zero counter must be in
///     the expected table)
///
/// Fields are listed in struct declaration order per group. When adding
/// or removing a counter: update this list + lookup_counter + bump
/// KNOWN_COUNTER_COUNT.
///
/// `fault_injector.*` counters are included (added on the A8-into-master
/// merge). They are feature-gated by the `fault-injector` cargo feature —
/// see `tests/feature-gated-counters.txt`; the static audit permits them
/// to have zero increment sites in the default build.
pub const ALL_COUNTER_NAMES: &[&str] = &[
    // --- eth (pre-A-HW + A-HW + A-HW+; _pad excluded) ---
    "eth.rx_pkts",
    "eth.rx_bytes",
    "eth.rx_drop_miss_mac",
    "eth.rx_drop_nomem",
    "eth.tx_pkts",
    "eth.tx_bytes",
    "eth.tx_drop_full_ring",
    "eth.tx_drop_nomem",
    "eth.rx_drop_short",
    "eth.rx_drop_unknown_ethertype",
    "eth.rx_arp",
    "eth.tx_arp",
    "eth.offload_missing_rx_cksum_ipv4",
    "eth.offload_missing_rx_cksum_tcp",
    "eth.offload_missing_rx_cksum_udp",
    "eth.offload_missing_tx_cksum_ipv4",
    "eth.offload_missing_tx_cksum_tcp",
    "eth.offload_missing_tx_cksum_udp",
    "eth.offload_missing_mbuf_fast_free",
    "eth.offload_missing_rss_hash",
    "eth.offload_missing_llq",
    "eth.offload_missing_rx_timestamp",
    "eth.rx_drop_cksum_bad",
    "eth.llq_wc_missing",
    "eth.llq_header_overflow_risk",
    "eth.eni_bw_in_allowance_exceeded",
    "eth.eni_bw_out_allowance_exceeded",
    "eth.eni_pps_allowance_exceeded",
    "eth.eni_conntrack_allowance_exceeded",
    "eth.eni_linklocal_allowance_exceeded",
    "eth.tx_q0_linearize",
    "eth.tx_q0_doorbells",
    "eth.tx_q0_missed_tx",
    "eth.tx_q0_bad_req_id",
    "eth.rx_q0_refill_partial",
    "eth.rx_q0_bad_desc_num",
    "eth.rx_q0_bad_req_id",
    "eth.rx_q0_mbuf_alloc_fail",
    // --- ip (_pad excluded) ---
    "ip.rx_csum_bad",
    "ip.rx_ttl_zero",
    "ip.rx_frag",
    "ip.rx_icmp_frag_needed",
    "ip.pmtud_updates",
    "ip.rx_drop_short",
    "ip.rx_drop_bad_version",
    "ip.rx_drop_bad_hl",
    "ip.rx_drop_not_ours",
    "ip.rx_drop_unsupported_proto",
    "ip.rx_tcp",
    "ip.rx_icmp",
    // --- tcp (pre-A5 + A5 + A5.5 + A6 + A6.6-7; rx_out_of_order removed in T1) ---
    "tcp.rx_syn_ack",
    "tcp.rx_data",
    "tcp.rx_ack",
    "tcp.rx_rst",
    "tcp.tx_retrans",
    "tcp.tx_rto",
    "tcp.tx_tlp",
    "tcp.conn_open",
    "tcp.conn_close",
    "tcp.conn_rst",
    "tcp.send_buf_full",
    "tcp.recv_buf_delivered",
    "tcp.tx_syn",
    "tcp.tx_ack",
    "tcp.tx_data",
    "tcp.tx_fin",
    "tcp.tx_rst",
    "tcp.rx_fin",
    "tcp.rx_unmatched",
    "tcp.rx_bad_csum",
    "tcp.rx_bad_flags",
    "tcp.rx_short",
    "tcp.recv_buf_drops",
    "tcp.rx_paws_rejected",
    "tcp.rx_bad_option",
    "tcp.rx_reassembly_queued",
    "tcp.rx_reassembly_hole_filled",
    "tcp.tx_sack_blocks",
    "tcp.rx_sack_blocks",
    "tcp.rx_bad_seq",
    "tcp.rx_bad_ack",
    "tcp.rx_dup_ack",
    "tcp.rx_zero_window",
    "tcp.rx_urgent_dropped",
    "tcp.tx_zero_window",
    "tcp.tx_window_update",
    "tcp.conn_table_full",
    "tcp.conn_time_wait_reaped",
    "tcp.tx_payload_bytes",
    "tcp.rx_payload_bytes",
    // state_trans is the 11x11 matrix — handled separately (see comment on
    // KNOWN_COUNTER_COUNT below).
    "tcp.conn_timeout_retrans",
    "tcp.conn_timeout_syn_sent",
    "tcp.rtt_samples",
    "tcp.tx_rack_loss",
    "tcp.rack_reo_wnd_override_active",
    "tcp.rto_no_backoff_active",
    "tcp.rx_ws_shift_clamped",
    "tcp.rx_dsack",
    "tcp.tx_tlp_spurious",
    "tcp.tx_api_timers_fired",
    "tcp.ts_recent_expired",
    "tcp.tx_flush_bursts",
    "tcp.tx_flush_batched_pkts",
    "tcp.rx_iovec_segs_total",
    "tcp.rx_multi_seg_events",
    "tcp.rx_partial_read_splits",
    // A10 deferred-fix Stage A: leak-detect diagnostic. Forensic-only,
    // not mirrored on the C-ABI side. tcp.rx_mempool_avail is AtomicU32
    // (last-sampled value) and is intentionally absent from this list —
    // the lookup mechanism is u64-typed; the avail counter is read
    // directly via `engine.counters().tcp.rx_mempool_avail.load(...)`.
    "tcp.mbuf_refcnt_drop_unexpected",
    // --- poll (_pad excluded) ---
    "poll.iters",
    "poll.iters_with_rx",
    "poll.iters_with_tx",
    "poll.iters_idle",
    "poll.iters_with_rx_burst_max",
    // --- obs (A5.5) ---
    "obs.events_dropped",
    "obs.events_queue_high_water",
    // --- fault_injector (A9) — feature-gated; listed in feature-gated-counters.txt ---
    "fault_injector.drops",
    "fault_injector.dups",
    "fault_injector.reorders",
    "fault_injector.corrupts",
];

/// Number of names in `ALL_COUNTER_NAMES`.
///
/// **Critical contract**: this count MUST be updated whenever a counter
/// is added or removed. The `all_counter_names_count_pinned` test fails
/// loudly when `ALL_COUNTER_NAMES.len() != KNOWN_COUNTER_COUNT`.
///
/// Count excludes state_trans (the 121-cell matrix is handled by a
/// dedicated coverage table in tests/counter-coverage.rs, not by a flat
/// name list). A9's `fault_injector.*` group IS present in the list
/// (4 entries) and is feature-gated by `fault-injector` per
/// `tests/feature-gated-counters.txt`.
///
/// **Scenario caught:** counter added to `ALL_COUNTER_NAMES` without
/// bumping this constant (or vice-versa) → count-pinned test fails.
///
/// **Scenario NOT caught by this constant alone:** a new `AtomicU64`
/// field added to a `*Counters` struct without also updating
/// `ALL_COUNTER_NAMES` + this count. The two `a8_tests` tests pass
/// cleanly in that scenario; the new counter becomes invisible to
/// every downstream M2 / M1 audit. That scenario IS caught by the
/// compile-time `size_of::<*Counters>()` pins above — they fail at
/// compile time when a new field shifts struct size past the pinned
/// byte count.
pub const KNOWN_COUNTER_COUNT: usize = 118;

/// Resolve a counter path from ALL_COUNTER_NAMES to a live &AtomicU64
/// on the given Counters. Returns None for typos or paths that have
/// been removed. The match is exhaustive over the name list; adding a
/// name to ALL_COUNTER_NAMES without a matching arm here will cause
/// `all_counter_names_lookup_valid` to fail at runtime with "name X
/// does not resolve".
///
/// Match-arm order mirrors `ALL_COUNTER_NAMES` so a reviewer can diff
/// the two by eye.
///
/// **`tcp.state_trans[11][11]` is NOT addressable via this function.**
/// The 121-cell matrix is a separate audit concern (see T8 in the A8
/// plan + `tests/counter-coverage.rs::state_trans_coverage_exhaustive`).
/// Callers that need cell-level access read `c.tcp.state_trans[from][to]`
/// directly by index. Do NOT extend this match with a
/// `"tcp.state_trans[X][Y]"` parser — the grammar is deliberately flat.
pub fn lookup_counter<'a>(c: &'a Counters, name: &str) -> Option<&'a AtomicU64> {
    Some(match name {
        // --- eth ---
        "eth.rx_pkts" => &c.eth.rx_pkts,
        "eth.rx_bytes" => &c.eth.rx_bytes,
        "eth.rx_drop_miss_mac" => &c.eth.rx_drop_miss_mac,
        "eth.rx_drop_nomem" => &c.eth.rx_drop_nomem,
        "eth.tx_pkts" => &c.eth.tx_pkts,
        "eth.tx_bytes" => &c.eth.tx_bytes,
        "eth.tx_drop_full_ring" => &c.eth.tx_drop_full_ring,
        "eth.tx_drop_nomem" => &c.eth.tx_drop_nomem,
        "eth.rx_drop_short" => &c.eth.rx_drop_short,
        "eth.rx_drop_unknown_ethertype" => &c.eth.rx_drop_unknown_ethertype,
        "eth.rx_arp" => &c.eth.rx_arp,
        "eth.tx_arp" => &c.eth.tx_arp,
        "eth.offload_missing_rx_cksum_ipv4" => &c.eth.offload_missing_rx_cksum_ipv4,
        "eth.offload_missing_rx_cksum_tcp" => &c.eth.offload_missing_rx_cksum_tcp,
        "eth.offload_missing_rx_cksum_udp" => &c.eth.offload_missing_rx_cksum_udp,
        "eth.offload_missing_tx_cksum_ipv4" => &c.eth.offload_missing_tx_cksum_ipv4,
        "eth.offload_missing_tx_cksum_tcp" => &c.eth.offload_missing_tx_cksum_tcp,
        "eth.offload_missing_tx_cksum_udp" => &c.eth.offload_missing_tx_cksum_udp,
        "eth.offload_missing_mbuf_fast_free" => &c.eth.offload_missing_mbuf_fast_free,
        "eth.offload_missing_rss_hash" => &c.eth.offload_missing_rss_hash,
        "eth.offload_missing_llq" => &c.eth.offload_missing_llq,
        "eth.offload_missing_rx_timestamp" => &c.eth.offload_missing_rx_timestamp,
        "eth.rx_drop_cksum_bad" => &c.eth.rx_drop_cksum_bad,
        "eth.llq_wc_missing" => &c.eth.llq_wc_missing,
        "eth.llq_header_overflow_risk" => &c.eth.llq_header_overflow_risk,
        "eth.eni_bw_in_allowance_exceeded" => &c.eth.eni_bw_in_allowance_exceeded,
        "eth.eni_bw_out_allowance_exceeded" => &c.eth.eni_bw_out_allowance_exceeded,
        "eth.eni_pps_allowance_exceeded" => &c.eth.eni_pps_allowance_exceeded,
        "eth.eni_conntrack_allowance_exceeded" => &c.eth.eni_conntrack_allowance_exceeded,
        "eth.eni_linklocal_allowance_exceeded" => &c.eth.eni_linklocal_allowance_exceeded,
        "eth.tx_q0_linearize" => &c.eth.tx_q0_linearize,
        "eth.tx_q0_doorbells" => &c.eth.tx_q0_doorbells,
        "eth.tx_q0_missed_tx" => &c.eth.tx_q0_missed_tx,
        "eth.tx_q0_bad_req_id" => &c.eth.tx_q0_bad_req_id,
        "eth.rx_q0_refill_partial" => &c.eth.rx_q0_refill_partial,
        "eth.rx_q0_bad_desc_num" => &c.eth.rx_q0_bad_desc_num,
        "eth.rx_q0_bad_req_id" => &c.eth.rx_q0_bad_req_id,
        "eth.rx_q0_mbuf_alloc_fail" => &c.eth.rx_q0_mbuf_alloc_fail,
        // --- ip ---
        "ip.rx_csum_bad" => &c.ip.rx_csum_bad,
        "ip.rx_ttl_zero" => &c.ip.rx_ttl_zero,
        "ip.rx_frag" => &c.ip.rx_frag,
        "ip.rx_icmp_frag_needed" => &c.ip.rx_icmp_frag_needed,
        "ip.pmtud_updates" => &c.ip.pmtud_updates,
        "ip.rx_drop_short" => &c.ip.rx_drop_short,
        "ip.rx_drop_bad_version" => &c.ip.rx_drop_bad_version,
        "ip.rx_drop_bad_hl" => &c.ip.rx_drop_bad_hl,
        "ip.rx_drop_not_ours" => &c.ip.rx_drop_not_ours,
        "ip.rx_drop_unsupported_proto" => &c.ip.rx_drop_unsupported_proto,
        "ip.rx_tcp" => &c.ip.rx_tcp,
        "ip.rx_icmp" => &c.ip.rx_icmp,
        // --- tcp ---
        "tcp.rx_syn_ack" => &c.tcp.rx_syn_ack,
        "tcp.rx_data" => &c.tcp.rx_data,
        "tcp.rx_ack" => &c.tcp.rx_ack,
        "tcp.rx_rst" => &c.tcp.rx_rst,
        "tcp.tx_retrans" => &c.tcp.tx_retrans,
        "tcp.tx_rto" => &c.tcp.tx_rto,
        "tcp.tx_tlp" => &c.tcp.tx_tlp,
        "tcp.conn_open" => &c.tcp.conn_open,
        "tcp.conn_close" => &c.tcp.conn_close,
        "tcp.conn_rst" => &c.tcp.conn_rst,
        "tcp.send_buf_full" => &c.tcp.send_buf_full,
        "tcp.recv_buf_delivered" => &c.tcp.recv_buf_delivered,
        "tcp.tx_syn" => &c.tcp.tx_syn,
        "tcp.tx_ack" => &c.tcp.tx_ack,
        "tcp.tx_data" => &c.tcp.tx_data,
        "tcp.tx_fin" => &c.tcp.tx_fin,
        "tcp.tx_rst" => &c.tcp.tx_rst,
        "tcp.rx_fin" => &c.tcp.rx_fin,
        "tcp.rx_unmatched" => &c.tcp.rx_unmatched,
        "tcp.rx_bad_csum" => &c.tcp.rx_bad_csum,
        "tcp.rx_bad_flags" => &c.tcp.rx_bad_flags,
        "tcp.rx_short" => &c.tcp.rx_short,
        "tcp.recv_buf_drops" => &c.tcp.recv_buf_drops,
        "tcp.rx_paws_rejected" => &c.tcp.rx_paws_rejected,
        "tcp.rx_bad_option" => &c.tcp.rx_bad_option,
        "tcp.rx_reassembly_queued" => &c.tcp.rx_reassembly_queued,
        "tcp.rx_reassembly_hole_filled" => &c.tcp.rx_reassembly_hole_filled,
        "tcp.tx_sack_blocks" => &c.tcp.tx_sack_blocks,
        "tcp.rx_sack_blocks" => &c.tcp.rx_sack_blocks,
        "tcp.rx_bad_seq" => &c.tcp.rx_bad_seq,
        "tcp.rx_bad_ack" => &c.tcp.rx_bad_ack,
        "tcp.rx_dup_ack" => &c.tcp.rx_dup_ack,
        "tcp.rx_zero_window" => &c.tcp.rx_zero_window,
        "tcp.rx_urgent_dropped" => &c.tcp.rx_urgent_dropped,
        "tcp.tx_zero_window" => &c.tcp.tx_zero_window,
        "tcp.tx_window_update" => &c.tcp.tx_window_update,
        "tcp.conn_table_full" => &c.tcp.conn_table_full,
        "tcp.conn_time_wait_reaped" => &c.tcp.conn_time_wait_reaped,
        "tcp.tx_payload_bytes" => &c.tcp.tx_payload_bytes,
        "tcp.rx_payload_bytes" => &c.tcp.rx_payload_bytes,
        "tcp.conn_timeout_retrans" => &c.tcp.conn_timeout_retrans,
        "tcp.conn_timeout_syn_sent" => &c.tcp.conn_timeout_syn_sent,
        "tcp.rtt_samples" => &c.tcp.rtt_samples,
        "tcp.tx_rack_loss" => &c.tcp.tx_rack_loss,
        "tcp.rack_reo_wnd_override_active" => &c.tcp.rack_reo_wnd_override_active,
        "tcp.rto_no_backoff_active" => &c.tcp.rto_no_backoff_active,
        "tcp.rx_ws_shift_clamped" => &c.tcp.rx_ws_shift_clamped,
        "tcp.rx_dsack" => &c.tcp.rx_dsack,
        "tcp.tx_tlp_spurious" => &c.tcp.tx_tlp_spurious,
        "tcp.tx_api_timers_fired" => &c.tcp.tx_api_timers_fired,
        "tcp.ts_recent_expired" => &c.tcp.ts_recent_expired,
        "tcp.tx_flush_bursts" => &c.tcp.tx_flush_bursts,
        "tcp.tx_flush_batched_pkts" => &c.tcp.tx_flush_batched_pkts,
        "tcp.rx_iovec_segs_total" => &c.tcp.rx_iovec_segs_total,
        "tcp.rx_multi_seg_events" => &c.tcp.rx_multi_seg_events,
        "tcp.rx_partial_read_splits" => &c.tcp.rx_partial_read_splits,
        // A10 deferred-fix Stage A leak-detect (rx_mempool_avail is
        // AtomicU32, absent from this u64-typed lookup — see
        // ALL_COUNTER_NAMES site comment).
        "tcp.mbuf_refcnt_drop_unexpected" => &c.tcp.mbuf_refcnt_drop_unexpected,
        // --- poll ---
        "poll.iters" => &c.poll.iters,
        "poll.iters_with_rx" => &c.poll.iters_with_rx,
        "poll.iters_with_tx" => &c.poll.iters_with_tx,
        "poll.iters_idle" => &c.poll.iters_idle,
        "poll.iters_with_rx_burst_max" => &c.poll.iters_with_rx_burst_max,
        // --- obs ---
        "obs.events_dropped" => &c.obs.events_dropped,
        "obs.events_queue_high_water" => &c.obs.events_queue_high_water,
        "fault_injector.drops" => &c.fault_injector.drops,
        "fault_injector.dups" => &c.fault_injector.dups,
        "fault_injector.reorders" => &c.fault_injector.reorders,
        "fault_injector.corrupts" => &c.fault_injector.corrupts,
        _ => return None,
    })
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

/// A9 fault-injector counter group. Slow-path per §9.1.1 — one `fetch_add`
/// per fault-decision branch (drop / dup / reorder / corrupt). Struct is
/// ALWAYS present on the C ABI (the `fault-injector` cargo feature only
/// gates whether the FaultInjector middleware runs and populates these;
/// release builds with the feature off carry zero-valued counters, same
/// pattern as the A5 deferred tx_retrans / tx_rto / tx_tlp counters).
#[repr(C, align(64))]
#[derive(Default)]
pub struct FaultInjectorCounters {
    pub drops: AtomicU64,
    pub dups: AtomicU64,
    pub reorders: AtomicU64,
    pub corrupts: AtomicU64,
}

impl FaultInjectorCounters {
    pub const fn new() -> Self {
        Self {
            drops: AtomicU64::new(0),
            dups: AtomicU64::new(0),
            reorders: AtomicU64::new(0),
            corrupts: AtomicU64::new(0),
        }
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
    /// `iters_with_tx` wired in A8 T3.5 follow-up (engine.rs poll_once
    /// end-of-iteration bump, snapshot-vs-post-drain compare on
    /// `eth.tx_pkts`). Starts at zero until the first TX fires.
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

    /// A9 fault-injector counter group is zero at construction.
    /// Struct is always present on the C ABI (feature only gates
    /// population). Guards the per-group size+align asserts in
    /// dpdk-net/src/api.rs from drifting silently.
    #[test]
    fn fault_injector_counters_zero_at_construction() {
        let c = Counters::new();
        assert_eq!(c.fault_injector.drops.load(Ordering::Relaxed), 0);
        assert_eq!(c.fault_injector.dups.load(Ordering::Relaxed), 0);
        assert_eq!(c.fault_injector.reorders.load(Ordering::Relaxed), 0);
        assert_eq!(c.fault_injector.corrupts.load(Ordering::Relaxed), 0);
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

mod a10_diagnostic_counter_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn rx_mempool_avail_default_is_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.rx_mempool_avail.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn mbuf_refcnt_drop_unexpected_default_is_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.mbuf_refcnt_drop_unexpected.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod a8_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// Every name in ALL_COUNTER_NAMES resolves to a valid counter path.
    #[test]
    fn all_counter_names_lookup_valid() {
        let c = Counters::new();
        for name in ALL_COUNTER_NAMES {
            let atomic = lookup_counter(&c, name)
                .unwrap_or_else(|| panic!("name {name} does not resolve"));
            assert_eq!(atomic.load(Ordering::Relaxed), 0);
        }
    }

    /// Pinned count: drifts whenever a counter is added or removed.
    /// Update this number when adding/removing counters + update the
    /// ALL_COUNTER_NAMES list + update lookup_counter. A mismatch
    /// means one of the three is out of sync.
    #[test]
    fn all_counter_names_count_pinned() {
        assert_eq!(
            ALL_COUNTER_NAMES.len(),
            KNOWN_COUNTER_COUNT,
            "ALL_COUNTER_NAMES count drifted; update KNOWN_COUNTER_COUNT if intentional"
        );
    }

    /// Sanity: nonexistent names return None, not a spurious reference.
    /// Protects against a future refactor replacing the `_ => return None`
    /// arm with a default-resolving arm. Also re-asserts the architectural
    /// decision (documented on `lookup_counter`) that state_trans cells
    /// are NOT addressable via this flat grammar — callers index the
    /// matrix directly.
    #[test]
    fn lookup_counter_unknown_returns_none() {
        let c = Counters::new();
        assert!(lookup_counter(&c, "nonexistent.counter").is_none());
        assert!(lookup_counter(&c, "").is_none());
        assert!(
            lookup_counter(&c, "tcp.state_trans[0][0]").is_none(),
            "state_trans cells are NOT addressable via lookup_counter — see doc comment"
        );
    }
}
