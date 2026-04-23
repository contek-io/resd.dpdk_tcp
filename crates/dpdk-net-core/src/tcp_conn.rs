//! Per-connection state (spec §6.2, subset for Phase A3).
//! Fields deferred to A4/A5 are NOT here yet; the struct grows
//! additively. Keeping the struct small also keeps the `Vec<Option<TcpConn>>`
//! slot array cacheline-sparse — the per-slot size today is ~128 bytes.

use std::collections::VecDeque;

use crate::flow_table::FourTuple;
use crate::tcp_state::TcpState;

/// A8 T17 (spec §5.2): static drift detector for the M3 knob-coverage audit.
///
/// Every `pub` field on `engine::ConnectOpts` (which mirrors the C ABI
/// `dpdk_net_connect_opts_t`) listed here MUST either:
///   - appear as a scenario entry in `tests/knob-coverage.rs` (behavioral
///     knob: a non-default value produces an observable consequence), OR
///   - appear in `tests/knob-coverage-informational.txt` (informational-
///     only: identity / sizing field with no branching behavior).
///
/// Adding a field to `ConnectOpts` without updating one of those trips
/// `knob_coverage_enumerates_every_behavioral_field` in CI. The runtime
/// value of this slice is never read — the literal string list is parsed
/// by the drift-detect test. Exposed on `tcp_conn.rs` (not `engine.rs`)
/// per the A8 T17 plan so the connect-side knob registry lives beside
/// the per-conn state type; `ConnectOpts` itself is in `engine.rs` for
/// historical reasons (pre-A5.5 it was an inline argument bundle).
pub const CONNECT_OPTS_FIELD_NAMES: &[&str] = &[
    // A5: RACK / RTO aggressiveness knobs.
    "rack_aggressive",
    "rto_no_backoff",
    // A5.5 Task 10: per-connect TLP tuning set.
    "tlp_pto_min_floor_us",
    "tlp_pto_srtt_multiplier_x100",
    "tlp_skip_flight_size_gate",
    "tlp_max_consecutive_probes",
    "tlp_skip_rtt_sample_gate",
    // bug_010 → feature: per-connection source IP (host byte order; 0 =
    // engine primary). Informational — validation routes through
    // `engine::select_source_ip`, which is covered by its own unit tests.
    "local_addr",
];

/// Per-connection send buffer. In A3 this is a raw byte ring; A4 will
/// gain a SACK scoreboard + in-flight tracking per spec §6.2.
pub struct SendQueue {
    /// User-submitted bytes not yet handed to `rte_eth_tx_burst`. Pop
    /// from the front in MSS-sized chunks; bytes remain here until ACKed
    /// (A3 drops on ACK; A5 will retain for retransmit).
    pub pending: VecDeque<u8>,
    pub cap: u32,
}

impl SendQueue {
    pub fn new(cap: u32) -> Self {
        Self {
            pending: VecDeque::with_capacity(cap as usize),
            cap,
        }
    }

    pub fn free_space(&self) -> u32 {
        self.cap.saturating_sub(self.pending.len() as u32)
    }

    /// Append up to `free_space` bytes; returns how many were accepted.
    pub fn push(&mut self, bytes: &[u8]) -> u32 {
        let take = bytes.len().min(self.free_space() as usize);
        self.pending.extend(&bytes[..take]);
        take as u32
    }
}

/// One contiguous in-order payload segment backed by a refcount-pinned mbuf.
/// Each segment references a live DPDK mbuf (via `MbufHandle` that owns
/// exactly one refcount) and a `[offset, offset+len)` window into the
/// mbuf's data region. The window is the TCP payload slice; `offset`
/// starts at the first TCP payload byte (post-header).
///
/// Ownership contract: at most one `InOrderSegment` holds each refcount
/// unit. A split on partial-read produces two `InOrderSegment`s both
/// referencing the same underlying `rte_mbuf` with refcount bumped once
/// via `MbufHandle::try_clone()` — both halves own independent refcounts.
#[derive(Debug)]
pub struct InOrderSegment {
    pub mbuf: crate::mempool::MbufHandle,
    pub offset: u16,
    pub len: u16,
}

impl InOrderSegment {
    #[inline]
    pub fn data_ptr(&self) -> *const u8 {
        // SAFETY: mbuf is refcount-pinned for the lifetime of this segment;
        // offset/len were bounds-checked at construction (see tcp_reassembly.rs).
        unsafe {
            let base = dpdk_net_sys::shim_rte_pktmbuf_data(self.mbuf.as_ptr()) as *const u8;
            base.add(self.offset as usize)
        }
    }

    #[inline]
    pub fn len_bytes(&self) -> u32 {
        self.len as u32
    }
}

/// Per-connection receive buffer. A4 co-locates the out-of-order
/// reassembly queue (`reorder`) with the in-order ring (`bytes`); both
/// share the same cap, so `free_space_total` reports combined room.
///
/// A6.6 Task 3: `bytes` is now a queue of `InOrderSegment` descriptors
/// pinning mbuf-resident payload windows, not a flattened `VecDeque<u8>`
/// byte ring. Flow-control accounting reads `buffered_bytes()` which
/// sums `seg.len` over the queue.
pub struct RecvQueue {
    pub bytes: VecDeque<InOrderSegment>,
    pub cap: u32,
    /// A4: out-of-order segments buffered past the in-order point.
    /// Shares `cap` with `bytes`; `free_space_total` reports combined room.
    pub reorder: crate::tcp_reassembly::ReorderQueue,
}

impl RecvQueue {
    pub fn new(cap: u32) -> Self {
        Self {
            bytes: VecDeque::new(),
            cap,
            reorder: crate::tcp_reassembly::ReorderQueue::new(cap),
        }
    }

    /// Total bytes currently pinned in the in-order queue (sum of segment
    /// lengths). Used by flow-control accounting (free_space / free_space_total).
    #[inline]
    pub fn buffered_bytes(&self) -> u32 {
        self.bytes.iter().map(|s| s.len as u32).sum()
    }

    /// In-order free-space only (matches A3's semantic).
    pub fn free_space(&self) -> u32 {
        self.cap.saturating_sub(self.buffered_bytes())
    }

    /// Combined free-space across in-order bytes + reorder queue.
    pub fn free_space_total(&self) -> u32 {
        self.cap
            .saturating_sub(self.buffered_bytes())
            .saturating_sub(self.reorder.total_bytes())
    }
}

/// Per-connection observable state snapshot (A5.5). Pure projection.
/// All values in application-useful units (bytes or µs); no engine-
/// internal tickers exposed.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnStats {
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

/// A5.5 Task 10: recent-TLP-probe record, consumed by Task 12's DSACK
/// spurious-TLP attribution path. Five slots per conn (`tlp_recent_probes`
/// on `TcpConn`) form a ring; the most-recent-probe-wins overwrite
/// policy keeps attribution bounded even under a burst of probes.
#[derive(Debug, Clone, Copy)]
pub struct RecentProbe {
    pub seq: u32,
    pub len: u16,
    pub tx_ts_ns: u64,
    pub attributed: bool,
}

pub struct TcpConn {
    four_tuple: FourTuple,
    pub state: TcpState,

    // Sequence space (RFC 9293 §3.3.1). All host byte order.
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub snd_wl1: u32,
    pub snd_wl2: u32,
    pub iss: u32,

    pub rcv_nxt: u32,
    pub rcv_wnd: u32,
    pub irs: u32,

    /// MSS negotiated on SYN-ACK (peer's advertised MSS option). Defaults
    /// to 536 if the peer omits the option (RFC 9293 §3.7.1 / RFC 6691).
    pub peer_mss: u16,

    // Phase A4: option-negotiated fields per spec §6.2.
    /// Our outbound window-scale shift (applied to `rcv_wnd` when writing
    /// the TCP header's window field). `0` = no scaling (RFC 7323
    /// pre-negotiation default). Negotiated on SYN-ACK: if the peer's
    /// SYN-ACK carries a Window Scale option, we set `ws_shift_out` to
    /// our advertised shift (typically 7 for 256 KiB recv buffer).
    pub ws_shift_out: u8,
    /// Peer's window-scale shift (applied when READING inbound windows
    /// into our `snd_wnd`). Negotiated on SYN-ACK; `0` otherwise.
    pub ws_shift_in: u8,
    /// True iff both sides sent the Timestamps option in the SYN/SYN-ACK
    /// exchange (RFC 7323 §2). When true, every non-SYN segment MUST
    /// carry Timestamps (RFC 7323 §3, MUST-22).
    pub ts_enabled: bool,
    /// Last in-sequence TSval we saw from the peer (RFC 7323 §3.2
    /// TS.Recent). Used as the TSecr we echo on outbound segments.
    pub ts_recent: u32,
    /// Our `now_ns()` reading when `ts_recent` was last updated. Used
    /// by RFC 7323 §5.5 "ts_recent expiration" — we invalidate ts_recent
    /// after 24 days of idle to prevent PAWS from rejecting legitimate
    /// long-idle-flow resumes. Stage 1 trading flows rarely idle that
    /// long; the check is cheap and future-proof.
    pub ts_recent_age: u64,
    /// True iff the SYN exchange negotiated SACK-permitted. When true,
    /// outbound ACKs carry SACK blocks for recv-side gaps, and inbound
    /// ACKs may carry SACK blocks the decoder feeds into
    /// `sack_scoreboard` for A5 retransmit consumption.
    pub sack_enabled: bool,

    /// A4: received-SACK scoreboard. Populated by `tcp_input` from
    /// inbound-ACK SACK blocks; pruned on snd_una advance. A5 consumes
    /// via `is_sacked(seq)` in RACK-TLP retransmit decisions.
    pub sack_scoreboard: crate::tcp_sack::SackScoreboard,

    pub snd: SendQueue,
    pub recv: RecvQueue,

    /// Snapshot of the sequence number *we* used for our FIN, so
    /// `ProcessACK` can detect "FIN has been ACKed" unambiguously.
    /// `None` when no FIN has been emitted yet.
    pub our_fin_seq: Option<u32>,

    /// `tcp_msl_ms`-derived deadline when this connection entered
    /// TIME_WAIT. `None` in all other states. Engine's tick reaps the
    /// connection once `clock::now_ns() >= time_wait_deadline_ns`.
    pub time_wait_deadline_ns: Option<u64>,

    /// A4: window value (raw 16-bit field, post-WS-scale) last advertised
    /// in an outbound ACK. Used to detect the `0 → nonzero` transition
    /// that bumps `tcp.tx_window_update` (A4 cross-phase backfill). `None`
    /// means no ACK has been emitted yet on this conn.
    pub last_advertised_wnd: Option<u16>,

    /// A4 / F-8 RFC 2018 §4 MUST-26: `(left, right)` seq range of the
    /// most-recent OOO segment that caused an ACK to be emitted. Used by
    /// `build_ack_outcome` to satisfy the "first SACK block MUST specify
    /// the contiguous block containing the segment that triggered this
    /// ACK" rule. Cleared after consumption. `None` between triggers
    /// (in-order data + pure ACKs don't set it).
    pub last_sack_trigger: Option<(u32, u32)>,

    /// A5: wheel-timer handles owned by this conn (RTO, TLP, SYN).
    /// `close_conn` walks this list on close; spec §7.4.
    pub timer_ids: Vec<crate::tcp_timer_wheel::TimerId>,

    // Phase A5 additions:
    /// In-flight (TX'd but unacked) segments — spec §7.2 snd_retrans.
    pub snd_retrans: crate::tcp_retrans::SendRetrans,
    /// RFC 6298 Jacobson/Karels RTT estimator.
    pub rtt_est: crate::tcp_rtt::RttEstimator,
    /// Handle of the conn's RTO timer on the engine wheel (lazy re-arm per §6.5).
    pub rto_timer_id: Option<crate::tcp_timer_wheel::TimerId>,
    /// Handle of the conn's TLP timer (RFC 8985 §7).
    pub tlp_timer_id: Option<crate::tcp_timer_wheel::TimerId>,
    /// How many SYN retransmits have been issued (spec §6.5; max 3).
    pub syn_retrans_count: u8,
    /// Handle of the SYN retrans timer.
    pub syn_retrans_timer_id: Option<crate::tcp_timer_wheel::TimerId>,
    /// A8 T11: true when this conn originated from a `LISTEN + peer SYN`
    /// (see `new_passive`), false for the client-side active-open path
    /// (see `new_client`). The `SynRetrans` timer-wheel fire handler
    /// dispatches on this flag to retransmit the correct handshake
    /// shape: plain `SYN` for active-open, `SYN|ACK` for passive-open
    /// (RFC 9293 §3.8.1 + RFC 6298 §2). Retires AD-A7-no-syn-ack-retransmit
    /// and mTCP AD-3 from the A7 review set.
    pub is_passive_open: bool,
    /// Per-connect opt: when true, RACK `reo_wnd` forced to 0.
    pub rack_aggressive: bool,
    /// Per-connect opt: when true, RTO does not double on retransmit.
    pub rto_no_backoff: bool,
    /// A5: RFC 8985 RACK state.
    pub rack: crate::tcp_rack::RackState,

    // A5.5 Task 10: per-connect TLP tuning (ABI mirror of the five
    // `dpdk_net_connect_opts_t::tlp_*` fields). Zero-init substitution
    // is applied at `dpdk_net_connect` entry (multiplier 0 → 200,
    // max_probes 0 → 1, floor 0 → engine `tcp_min_rto_us`) so these
    // fields hold post-substitution values by the time they land here.
    pub tlp_pto_min_floor_us: u32,
    pub tlp_pto_srtt_multiplier_x100: u16,
    pub tlp_skip_flight_size_gate: bool,
    pub tlp_max_consecutive_probes: u8,
    pub tlp_skip_rtt_sample_gate: bool,

    // A5.5 Task 10: runtime TLP state (NOT in the ABI; private to the
    // core crate). Task 11 reads/mutates these when arming / firing /
    // resetting the TLP multi-probe budget.
    /// Count of consecutive TLPs fired without an intervening RTT
    /// sample or new-data ACK. Reset by the ACK path; compared against
    /// `tlp_max_consecutive_probes` before arming the next probe.
    pub tlp_consecutive_probes_fired: u8,
    /// Set by the ACK path whenever a fresh RTT sample or new-data ACK
    /// is absorbed; cleared on TLP fire. Gate for TLP scheduling when
    /// `tlp_skip_rtt_sample_gate == false`.
    pub tlp_rtt_sample_seen_since_last_tlp: bool,
    /// Five-slot ring of recently-transmitted TLP probes, consumed by
    /// Task 12's DSACK spurious-TLP attribution path.
    pub tlp_recent_probes: [Option<RecentProbe>; 5],
    /// Next-slot index into `tlp_recent_probes` (wraps mod 5).
    pub tlp_recent_probes_next_slot: u8,

    // A5.5 Task 13 pre-announce: our SYN TX timestamp (ns, engine
    // monotonic clock). Zero-init here; Task 13 populates it at SYN
    // emission so `handle_syn_sent` can seed SRTT from the SYN-ACK
    // RTT sample.
    pub syn_tx_ts_ns: u64,
    /// A6 (spec §3.3): set when a prior `send_bytes` returned
    /// `accepted < len`. Cleared when `WRITABLE` hysteresis fires
    /// on `in_flight <= send_buffer_bytes / 2`.
    pub send_refused_pending: bool,
    /// A6 (spec §3.4): caller passed `DPDK_NET_CLOSE_FORCE_TW_SKIP`
    /// to `dpdk_net_close` AND the connection had `ts_enabled=true`
    /// at close time. `reap_time_wait` short-circuits the 2×MSL wait
    /// when this is set.
    pub force_tw_skip: bool,
    /// A6 (spec §3.8): per-connection RTT histogram — 16 × u32
    /// buckets on one cacheline. Updated after each `rtt_est.sample()`
    /// in `tcp_input.rs` (Task 15). Slow-path update (~5–10 ns).
    pub rtt_histogram: crate::rtt_histogram::RttHistogram,

    /// A6.6 Task 7: segments popped from `recv.bytes` during the most
    /// recent poll's `deliver_readable`, refcount-pinned until the NEXT
    /// poll drains them at the top of `poll_once`. Backs the iovec
    /// slice pointed at by the READABLE event. Full `InOrderSegment`
    /// is retained (mbuf + offset + len), not just the mbuf handle —
    /// the offset/len window is what `data_ptr()` reads at iovec
    /// materialization time.
    pub delivered_segments: smallvec::SmallVec<[InOrderSegment; 4]>,
    /// A6.6 Task 7: scratch for iovec array materialization in
    /// `deliver_readable`. Cleared at the top of each `deliver_readable`
    /// call for the conn (before pushing new iovecs) and again at the
    /// top of the NEXT `poll_once`. Capacity retained across polls.
    /// Uses the core-side `DpdkNetIovec`; the FFI crate's
    /// `dpdk_net_iovec_t` has identical `#[repr(C)]` layout (layout-
    /// asserted in `crates/dpdk-net/src/api.rs`).
    pub readable_scratch_iovecs: Vec<crate::iovec::DpdkNetIovec>,
}

impl TcpConn {
    /// Create a fresh client-side connection ready to emit SYN.
    /// State = SYN_SENT; `snd_una = snd_nxt = iss`; our SYN will consume
    /// one seq (bumped to `iss+1` by the caller after successful TX).
    ///
    /// `min_rto_us` / `initial_rto_us` / `max_rto_us` are plumbed from
    /// `EngineConfig::tcp_min_rto_us` / `tcp_initial_rto_us` /
    /// `tcp_max_rto_us` (Task 21) so the RTT estimator construction
    /// reflects engine-wide RTO policy. Unit tests outside the Engine
    /// pass the defaults directly (5_000, 5_000, 1_000_000).
    #[allow(clippy::too_many_arguments)]
    pub fn new_client(
        tuple: FourTuple,
        iss: u32,
        our_mss: u16,
        recv_buf_bytes: u32,
        send_buf_bytes: u32,
        min_rto_us: u32,
        initial_rto_us: u32,
        max_rto_us: u32,
    ) -> Self {
        let rcv_wnd = recv_buf_bytes.min(u16::MAX as u32); // A3: no WSCALE, so ≤ 65535.
        Self {
            four_tuple: tuple,
            state: TcpState::Closed, // engine transitions to SynSent once SYN is TX'd.
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            iss,
            rcv_nxt: 0,
            rcv_wnd,
            irs: 0,
            peer_mss: our_mss, // placeholder until SYN-ACK; our_mss is a sane floor.
            // A4 options — default "not negotiated"; Task 15 sets them
            // from the SYN-ACK options.
            ws_shift_out: 0,
            ws_shift_in: 0,
            ts_enabled: false,
            ts_recent: 0,
            ts_recent_age: 0,
            sack_enabled: false,
            sack_scoreboard: crate::tcp_sack::SackScoreboard::new(),
            snd: SendQueue::new(send_buf_bytes),
            recv: RecvQueue::new(recv_buf_bytes),
            our_fin_seq: None,
            time_wait_deadline_ns: None,
            last_advertised_wnd: None,
            last_sack_trigger: None,
            // Pre-size to cover the live-timer ceiling per conn under
            // sustained TX. Live distinct timers per conn are RTO +
            // TLP + (transient) SYN-retrans, but `retain` is O(n) and
            // doesn't shrink the Vec — so the steady-state high-water
            // mark is what matters. Empirically the no-alloc audit
            // observes the Vec briefly straddling 16+ entries during
            // overlapped restart windows (RTO cancel + TLP fire +
            // re-arm in adjacent ACKs); pre-sizing to 32 covers that
            // P99 without the geometric-doubling grow surfacing in
            // the audit's measurement window. 32 × 8 B = 256 B per
            // conn — negligible footprint at `max_connections=1024`.
            timer_ids: Vec::with_capacity(32),
            // Pre-size the in-flight deque to the steady-state ceiling
            // (`send_buf_bytes / our_mss`, +1 to absorb partial-segment
            // rounding). `send_bytes` caps `room_in_peer_wnd` and
            // `send_buf_room` so `snd_retrans` can never exceed this
            // bound; pre-sizing here keeps the no-alloc-on-hot-path
            // audit honest under sustained TX (otherwise the inner
            // VecDeque doubles 1→4→…→256 during ramp and surfaces
            // multiple hot-path allocs in the audit measurement window).
            snd_retrans: crate::tcp_retrans::SendRetrans::with_capacity(
                (send_buf_bytes / our_mss.max(1) as u32 + 1) as usize,
            ),
            rtt_est: crate::tcp_rtt::RttEstimator::new(min_rto_us, initial_rto_us, max_rto_us),
            rto_timer_id: None,
            tlp_timer_id: None,
            syn_retrans_count: 0,
            syn_retrans_timer_id: None,
            // A8 T11: active-open by default. `new_passive` overrides
            // this to `true` so the SynRetrans fire handler retransmits
            // `SYN|ACK` instead of plain `SYN`.
            is_passive_open: false,
            rack_aggressive: false,
            rto_no_backoff: false,
            rack: crate::tcp_rack::RackState::new(),
            // A5.5 Task 10: TLP tuning fields + runtime state zero-init.
            // `dpdk_net_connect` (or `connect_with_opts`) overrides the five
            // ABI-mirror fields with post-substitution values right after
            // inserting the conn into the flow table.
            //
            // A5.5 Task 11 fixup: default-init the two gate-relevant knobs
            // (`tlp_pto_srtt_multiplier_x100`, `tlp_max_consecutive_probes`)
            // to their A5-compatible constants so direct-construct paths
            // (unit tests, future accept-side code) that never go through
            // `connect_with_opts` still produce a working
            // `tlp_arm_gate_passes()` budget check (a `0` budget would
            // reject every arm). `connect_with_opts` still overwrites
            // these with the post-substitution caller values — which are
            // either the same defaults (zero-init caller) or validated
            // user-supplied values.
            tlp_pto_min_floor_us: 0,
            tlp_pto_srtt_multiplier_x100: crate::tcp_tlp::DEFAULT_MULTIPLIER_X100,
            tlp_skip_flight_size_gate: false,
            tlp_max_consecutive_probes: crate::tcp_tlp::DEFAULT_MAX_CONSECUTIVE_PROBES,
            tlp_skip_rtt_sample_gate: false,
            tlp_consecutive_probes_fired: 0,
            tlp_rtt_sample_seen_since_last_tlp: false,
            tlp_recent_probes: [None; 5],
            tlp_recent_probes_next_slot: 0,
            syn_tx_ts_ns: 0,
            send_refused_pending: false,
            force_tw_skip: false,
            rtt_histogram: crate::rtt_histogram::RttHistogram::default(),
            // A6.6 Task 7: per-conn scratch for READABLE iovec
            // materialization + segment-ref holding. Both cleared at
            // top of each `poll_once`; capacity retained across polls.
            delivered_segments: smallvec::SmallVec::new(),
            readable_scratch_iovecs: Vec::new(),
        }
    }

    /// A7 Task 5: construct a server-side connection in SYN_RCVD from a
    /// freshly-arrived inbound SYN. Delegates to `new_client` and then
    /// overrides only the fields that differ on the passive path:
    ///   - state is `SynReceived` (not `Closed`),
    ///   - `rcv_nxt = iss_peer + 1` and `irs = iss_peer` (peer's SYN consumes
    ///     one seq),
    ///   - peer options (MSS / WS / Timestamps / SACK-permitted) are absorbed
    ///     from the SYN's `TcpOpts` so the later ESTABLISHED transition
    ///     doesn't need a second parse.
    ///
    /// `iss` is our ISS for this flow — the caller derives it via the
    /// engine's `IssGen::next`, matching the active path's shape. Snd_nxt
    /// is bumped past our SYN-ACK by the caller post-TX (mirroring the
    /// active path's post-TX `snd_nxt += 1`).
    ///
    /// Behind `feature = "test-server"`: there is no production code path
    /// that builds a passive-open conn today (A6.6 is client-only).
    #[cfg(feature = "test-server")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_passive(
        tuple: FourTuple,
        iss: u32,
        iss_peer: u32,
        opts: crate::tcp_options::TcpOpts,
        our_mss: u16,
        recv_buf_bytes: u32,
        send_buf_bytes: u32,
        min_rto_us: u32,
        initial_rto_us: u32,
        max_rto_us: u32,
    ) -> Self {
        let mut c = Self::new_client(
            tuple,
            iss,
            our_mss,
            recv_buf_bytes,
            send_buf_bytes,
            min_rto_us,
            initial_rto_us,
            max_rto_us,
        );
        // Deltas from the active-open seed:
        c.state = TcpState::SynReceived;
        // A8 T11: flag the conn as passive-open so the SynRetrans fire
        // handler retransmits `SYN|ACK` on this tuple (not plain `SYN`).
        c.is_passive_open = true;
        c.rcv_nxt = iss_peer.wrapping_add(1);
        c.irs = iss_peer;
        // Absorb peer options from the SYN.
        // RFC 9293 §3.7.1 / RFC 6691 (MUST-15): if peer SYN omits the MSS
        // option, send-MSS MUST fall back to 536 (the IPv4 default). Mirrors
        // the active-open path in `handle_syn_sent` (tcp_input.rs ~632) which
        // applies the same `unwrap_or(536)` on the SYN-ACK's MSS option.
        // Before A8 T19 the passive path left `peer_mss` at the `our_mss`
        // seed when MSS was absent, which violated MUST-15.
        c.peer_mss = opts.mss.unwrap_or(536);
        c.ws_shift_in = opts.wscale.unwrap_or(0).min(14);
        c.ts_enabled = opts.timestamps.is_some();
        if let Some((tsval, _)) = opts.timestamps {
            c.ts_recent = tsval;
            c.ts_recent_age = crate::clock::now_ns();
        }
        c.sack_enabled = opts.sack_permitted;
        c
    }

    /// A5.5 Task 10: project the per-connect TLP tuning into the
    /// pure-function `TlpConfig` consumed by `pto_us`. By the time we
    /// reach here, `tlp_pto_min_floor_us` has already been substituted
    /// from `0` → engine `tcp_min_rto_us` at `dpdk_net_connect` entry;
    /// the `u32::MAX` check handles only the explicit no-floor case.
    pub fn tlp_config(&self, _engine_min_rto_us: u32) -> crate::tcp_tlp::TlpConfig {
        let floor = if self.tlp_pto_min_floor_us == u32::MAX {
            0
        } else {
            self.tlp_pto_min_floor_us
        };
        crate::tcp_tlp::TlpConfig {
            floor_us: floor,
            multiplier_x100: self.tlp_pto_srtt_multiplier_x100,
            skip_flight_size_gate: self.tlp_skip_flight_size_gate,
        }
    }

    /// A5.5 Task 11: RFC 8985 §7 + spec §3.4 multi-probe gate. Returns
    /// true iff a TLP probe should be armed now given per-conn state +
    /// knobs. Called by both arm-on-ACK (Task 11) and arm-on-send
    /// (Task 15).
    ///
    /// A5.5 Task 15: added SRTT-present gate. PTO computation needs a
    /// valid SRTT — post Task 13 SYN-seed this holds from ESTABLISHED
    /// onward; the gate then only rejects in pathological pre-sample
    /// states (Karn's-rule skip on SYN retransmit) where RTO covers
    /// the first burst until the next data-ACK seeds SRTT.
    #[inline]
    pub fn tlp_arm_gate_passes(&self) -> bool {
        if self.snd_retrans.is_empty() {
            return false;
        }
        if self.tlp_timer_id.is_some() {
            return false;
        }
        if self.tlp_consecutive_probes_fired >= self.tlp_max_consecutive_probes {
            return false;
        }
        if !self.tlp_skip_rtt_sample_gate && !self.tlp_rtt_sample_seen_since_last_tlp {
            return false;
        }
        if self.rtt_est.srtt_us().is_none() {
            return false;
        }
        true
    }

    /// A5.5 Task 11: record probe emission + bump budget + clear
    /// sample-seen. Slot overwrite is most-recent-wins (mod 5) per
    /// spec §3.4; bounded memory under a burst of probes.
    #[inline]
    pub fn on_tlp_probe_fired(&mut self, seq: u32, len: u16, tx_ts_ns: u64) {
        let slot = self.tlp_recent_probes_next_slot as usize;
        self.tlp_recent_probes[slot] = Some(RecentProbe {
            seq,
            len,
            tx_ts_ns,
            attributed: false,
        });
        self.tlp_recent_probes_next_slot = ((slot + 1) % self.tlp_recent_probes.len()) as u8;
        self.tlp_consecutive_probes_fired = self.tlp_consecutive_probes_fired.saturating_add(1);
        self.tlp_rtt_sample_seen_since_last_tlp = false;
    }

    /// A5.5 Task 11: called from the ACK path when an RTT sample is
    /// absorbed. Resets the TLP budget + sets `sample-seen`, satisfying
    /// the RFC 8985 §7.4 gate.
    #[inline]
    pub fn on_rtt_sample_tlp_hook(&mut self) {
        self.tlp_consecutive_probes_fired = 0;
        self.tlp_rtt_sample_seen_since_last_tlp = true;
    }

    /// A5.5 Task 11: called from the ACK path when `snd_una` advances
    /// (new-data cum-ACK) without an RTT sample. Resets the TLP budget
    /// only; does NOT flip `sample-seen` (that remains gated on an
    /// actual RTT sample).
    #[inline]
    pub fn on_new_data_ack_tlp_hook(&mut self) {
        self.tlp_consecutive_probes_fired = 0;
    }

    /// A5.5 Task 13: seed SRTT from the SYN handshake round-trip per
    /// RFC 6298 §3.3 MAY ("The RTT of the SYN segment MAY be used as
    /// the first SRTT"). Karn's rule: skip when `syn_retrans_count != 0`
    /// — the SYN-ACK could be for the original OR a retransmit, and the
    /// ambiguity breaks the sample. Also skip when `syn_tx_ts_ns == 0`
    /// (accept-side paths never set it). Bounds `(1..60_000_000)` match
    /// A5's data-ACK sampler so clock anomalies are rejected uniformly.
    /// Returns `true` iff the sample was absorbed.
    ///
    /// A6 Task 15 (spec §3.8): on absorption, update the per-conn RTT
    /// histogram under the engine-wide `rtt_histogram_edges`. Kept on
    /// the sample site so every sample-taking path (timestamp, Karn's,
    /// SYN-seed) updates uniformly.
    #[inline]
    pub fn maybe_seed_srtt_from_syn(
        &mut self,
        now_ns: u64,
        rtt_histogram_edges: &[u32; 15],
    ) -> bool {
        if self.syn_retrans_count != 0 {
            return false;
        }
        if self.syn_tx_ts_ns == 0 {
            return false;
        }
        let rtt_us = ((now_ns / 1_000) as u32).wrapping_sub((self.syn_tx_ts_ns / 1_000) as u32);
        if !(1..60_000_000).contains(&rtt_us) {
            return false;
        }
        self.rtt_est.sample(rtt_us);
        self.rack.update_min_rtt(rtt_us);
        // A6 Task 15 (spec §3.8): per-conn RTT histogram update. Slow-path
        // at sample cadence (not per-segment). 15-comparison ladder
        // + one wrapping_add on cache-resident state.
        self.rtt_histogram.update(rtt_us, rtt_histogram_edges);
        true
    }

    /// A5.5 Task 12: attribute a DSACK block `[left, right)` to a recent
    /// TLP probe. Returns `true` iff a previously-unattributed probe was
    /// matched; caller increments `tcp.tx_tlp_spurious` on a `true` return.
    ///
    /// The 4·SRTT plausibility window prevents wrap-around mis-attribution
    /// across the 32-bit seq space. Before any RTT sample exists, we fall
    /// through to a defensive 1s window (DSACK can fire on the very first
    /// dup-ACK of a flow, so a zero-sample guard would drop legitimate
    /// attributions on cold conns).
    #[inline]
    pub fn attribute_dsack_to_recent_tlp_probe(
        &mut self,
        block_left: u32,
        block_right: u32,
        now_ns: u64,
    ) -> bool {
        let srtt_us = self.rtt_est.srtt_us().unwrap_or(self.rack.min_rtt_us);
        let effective_srtt_us = if srtt_us == 0 { 1_000_000 } else { srtt_us };
        let window_ns = (effective_srtt_us as u64)
            .saturating_mul(1_000)
            .saturating_mul(4);

        for probe_slot in self.tlp_recent_probes.iter_mut() {
            let Some(probe) = probe_slot.as_mut() else {
                continue;
            };
            if probe.attributed {
                continue;
            }
            let probe_end = probe.seq.wrapping_add(probe.len as u32);
            if !crate::tcp_seq::seq_le(block_left, probe.seq) {
                continue;
            }
            if !crate::tcp_seq::seq_le(probe_end, block_right) {
                continue;
            }
            if now_ns.saturating_sub(probe.tx_ts_ns) >= window_ns {
                continue;
            }
            probe.attributed = true;
            return true;
        }
        false
    }

    pub fn four_tuple(&self) -> FourTuple {
        self.four_tuple
    }

    /// Slow-path snapshot for forensics / per-order tagging. Called
    /// from the app via `dpdk_net_conn_stats`; not on any hot path.
    pub fn stats(&self, send_buffer_bytes: u32) -> ConnStats {
        let pending = self.snd.pending.len() as u32;
        ConnStats {
            snd_una: self.snd_una,
            snd_nxt: self.snd_nxt,
            snd_wnd: self.snd_wnd,
            send_buf_bytes_pending: pending,
            send_buf_bytes_free: send_buffer_bytes.saturating_sub(pending),
            srtt_us: self.rtt_est.srtt_us().unwrap_or(0),
            rttvar_us: self.rtt_est.rttvar_us(),
            min_rtt_us: self.rack.min_rtt_us,
            rto_us: self.rtt_est.rto_us(),
        }
    }

    /// True iff our FIN has been sent and ACKed (i.e. ACK covers
    /// `our_fin_seq + 1`). Implementations use this to decide FIN_WAIT_1
    /// → FIN_WAIT_2 and CLOSING → TIME_WAIT transitions.
    pub fn fin_has_been_acked(&self, ack_seq: u32) -> bool {
        match self.our_fin_seq {
            Some(fs) => {
                let required = fs.wrapping_add(1);
                // Treat ack_seq covering `required` as "FIN acked".
                !crate::tcp_seq::seq_lt(ack_seq, required)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple() -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        }
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn new_client_sets_iss_both_una_and_nxt() {
        let c = TcpConn::new_client(
            tuple(),
            0xDEAD_BEEF,
            1460,
            1024,
            2048,
            5000,
            5000,
            1_000_000,
        );
        assert_eq!(c.snd_una, 0xDEAD_BEEF);
        assert_eq!(c.snd_nxt, 0xDEAD_BEEF);
        assert_eq!(c.iss, 0xDEAD_BEEF);
        assert_eq!(c.state, TcpState::Closed);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn rcv_wnd_clamped_to_u16_max_without_wscale() {
        let c = TcpConn::new_client(tuple(), 0, 1460, 1_000_000, 1024, 5000, 5000, 1_000_000);
        assert_eq!(c.rcv_wnd, u16::MAX as u32);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn send_queue_push_respects_cap() {
        let mut sq = SendQueue::new(4);
        assert_eq!(sq.push(b"hello"), 4);
        assert_eq!(sq.pending.len(), 4);
        assert_eq!(sq.free_space(), 0);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn recv_queue_buffered_bytes_starts_zero_and_matches_free_space() {
        // A6.6 Task 3: `RecvQueue::append` is retired (the VecDeque<u8>
        // ring was replaced by VecDeque<InOrderSegment>). The ingest
        // path in `tcp_input.rs` now pushes mbuf-backed segments
        // directly; this test retains the flow-control accounting
        // check that pre-dated the ingest rework.
        let rq = RecvQueue::new(3);
        assert_eq!(rq.buffered_bytes(), 0);
        assert_eq!(rq.free_space(), 3);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn fin_acked_checks_fin_seq_plus_one() {
        let mut c = TcpConn::new_client(tuple(), 100, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(!c.fin_has_been_acked(150));
        c.our_fin_seq = Some(200);
        assert!(!c.fin_has_been_acked(200));
        assert!(c.fin_has_been_acked(201));
        assert!(c.fin_has_been_acked(500));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn recv_queue_has_reorder_field_and_shares_cap() {
        let rq = RecvQueue::new(1024);
        assert_eq!(rq.cap, 1024);
        assert!(rq.reorder.is_empty());
        assert_eq!(rq.reorder.total_bytes(), 0);
        assert_eq!(rq.free_space_total(), 1024);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a4_options_fields_default_to_not_negotiated() {
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        // No WS negotiated: no left shift on either direction.
        assert_eq!(c.ws_shift_out, 0);
        assert_eq!(c.ws_shift_in, 0);
        // TS disabled until SYN-ACK confirms it.
        assert!(!c.ts_enabled);
        assert_eq!(c.ts_recent, 0);
        assert_eq!(c.ts_recent_age, 0);
        // SACK disabled until SYN-ACK confirms it.
        assert!(!c.sack_enabled);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a4_sack_scoreboard_starts_empty() {
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(c.sack_scoreboard.is_empty());
        assert_eq!(c.sack_scoreboard.len(), 0);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a4_last_sack_trigger_starts_none() {
        // F-8 RFC 2018 §4 MUST-26: conn.last_sack_trigger is set by
        // tcp_input on OOO-insert and cleared by emit_ack after use.
        // Starts `None` on a fresh client connection.
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(c.last_sack_trigger.is_none());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn new_client_timer_ids_starts_empty() {
        let c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(c.timer_ids.is_empty());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a5_conn_starts_with_empty_snd_retrans_and_default_rtt() {
        let c = TcpConn::new_client(tuple(), 100, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(c.snd_retrans.is_empty());
        assert_eq!(c.rtt_est.rto_us(), crate::tcp_rtt::DEFAULT_INITIAL_RTO_US);
        assert!(c.rto_timer_id.is_none());
        assert!(c.tlp_timer_id.is_none());
        assert_eq!(c.syn_retrans_count, 0);
        assert!(c.syn_retrans_timer_id.is_none());
        assert!(!c.rack_aggressive);
        assert!(!c.rto_no_backoff);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a5_conn_has_default_rack_state() {
        let c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert_eq!(c.rack.xmit_ts_ns, 0);
        assert_eq!(c.rack.end_seq, 0);
        assert_eq!(c.rack.min_rtt_us, 0);
        assert!(!c.rack.dsack_seen);
    }

    // A5.5 Task 10: per-connect TLP tuning + runtime state + syn_tx_ts_ns.
    //
    // A5.5 Task 11 fixup: the two gate-relevant knobs
    // (`tlp_pto_srtt_multiplier_x100`, `tlp_max_consecutive_probes`) are
    // default-initialized to their A5-compatible constants so a
    // direct-construct conn (bypassing `connect_with_opts`) has a working
    // `tlp_arm_gate_passes()` budget. All other TLP fields remain
    // zero/false/None (that still maps to A5 behavior).
    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a5_5_tlp_tuning_fields_default_init_on_new_client() {
        let c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert_eq!(c.tlp_pto_min_floor_us, 0);
        assert_eq!(
            c.tlp_pto_srtt_multiplier_x100,
            crate::tcp_tlp::DEFAULT_MULTIPLIER_X100
        );
        assert!(!c.tlp_skip_flight_size_gate);
        assert_eq!(
            c.tlp_max_consecutive_probes,
            crate::tcp_tlp::DEFAULT_MAX_CONSECUTIVE_PROBES
        );
        assert!(!c.tlp_skip_rtt_sample_gate);
        assert_eq!(c.tlp_consecutive_probes_fired, 0);
        assert!(!c.tlp_rtt_sample_seen_since_last_tlp);
        assert!(c.tlp_recent_probes.iter().all(|s| s.is_none()));
        assert_eq!(c.tlp_recent_probes_next_slot, 0);
        assert_eq!(c.syn_tx_ts_ns, 0);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a5_5_tlp_config_projects_fields() {
        let mut c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.tlp_pto_min_floor_us = 7_500;
        c.tlp_pto_srtt_multiplier_x100 = 150;
        c.tlp_skip_flight_size_gate = true;
        let cfg = c.tlp_config(5_000);
        assert_eq!(cfg.floor_us, 7_500);
        assert_eq!(cfg.multiplier_x100, 150);
        assert!(cfg.skip_flight_size_gate);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a5_5_tlp_config_u32_max_means_no_floor() {
        let mut c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.tlp_pto_min_floor_us = u32::MAX;
        c.tlp_pto_srtt_multiplier_x100 = 200;
        let cfg = c.tlp_config(5_000);
        assert_eq!(cfg.floor_us, 0, "u32::MAX sentinel must project to 0");
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn a6_new_fields_zero_init_after_new_client() {
        let c = TcpConn::new_client(
            FourTuple {
                local_ip: 0x0a000002,
                local_port: 40000,
                peer_ip: 0x0a000001,
                peer_port: 5000,
            },
            0, 1460, 1024, 2048, 5_000, 5_000, 1_000_000,
        );
        assert!(!c.send_refused_pending);
        assert!(!c.force_tw_skip);
        for b in c.rtt_histogram.buckets.iter() {
            assert_eq!(*b, 0);
        }
    }
}

#[cfg(test)]
mod a5_5_stats_tests {
    use super::*;

    fn tuple() -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        }
    }

    pub(super) fn make_test_conn() -> TcpConn {
        TcpConn::new_client(tuple(), 0, 1460, 1024, 2048, 5000, 5000, 1_000_000)
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn stats_projects_send_path_fields() {
        let mut c = make_test_conn();
        c.snd_una = 100;
        c.snd_nxt = 200;
        c.snd_wnd = 65535;
        let s = c.stats(1_048_576);
        assert_eq!(s.snd_una, 100);
        assert_eq!(s.snd_nxt, 200);
        assert_eq!(s.snd_wnd, 65535);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn stats_before_any_rtt_sample_returns_zero_except_rto() {
        let c = make_test_conn();
        let s = c.stats(1_048_576);
        assert_eq!(s.srtt_us, 0);
        assert_eq!(s.rttvar_us, 0);
        assert_eq!(s.min_rtt_us, 0);
        assert_eq!(s.rto_us, c.rtt_est.rto_us());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn stats_send_buf_bytes_free_saturates_at_zero() {
        let mut c = make_test_conn();
        c.snd.pending.extend(std::iter::repeat_n(0u8, 128));
        let s = c.stats(64);
        assert_eq!(s.send_buf_bytes_pending, 128);
        assert_eq!(s.send_buf_bytes_free, 0);
    }
}

#[cfg(test)]
mod a5_5_tlp_hook_tests {
    use super::a5_5_stats_tests::make_test_conn;
    use crate::tcp_retrans::RetransEntry;

    fn prime_retrans(c: &mut super::TcpConn, seq: u32, len: u16) {
        c.snd_retrans.push_after_tx(RetransEntry {
            seq,
            len,
            mbuf: crate::mempool::Mbuf::null_for_test(),
            first_tx_ts_ns: 0,
            xmit_count: 1,
            sacked: false,
            lost: false,
            xmit_ts_ns: 0,
            hdrs_len: 0,
        });
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn tlp_arm_gate_rejects_when_retrans_empty() {
        let mut c = make_test_conn();
        c.tlp_max_consecutive_probes = 3;
        c.tlp_rtt_sample_seen_since_last_tlp = true;
        assert!(!c.tlp_arm_gate_passes());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn tlp_arm_gate_rejects_when_timer_already_armed() {
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_max_consecutive_probes = 3;
        c.tlp_rtt_sample_seen_since_last_tlp = true;
        c.tlp_timer_id = Some(crate::tcp_timer_wheel::TimerId {
            slot: 1,
            generation: 0,
        });
        assert!(!c.tlp_arm_gate_passes());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn tlp_arm_gates_reject_when_budget_exhausted() {
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_max_consecutive_probes = 3;
        c.tlp_consecutive_probes_fired = 3;
        c.tlp_rtt_sample_seen_since_last_tlp = true;
        assert!(!c.tlp_arm_gate_passes());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn tlp_arm_gates_pass_when_under_budget_and_sample_seen() {
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_max_consecutive_probes = 3;
        c.tlp_consecutive_probes_fired = 1;
        c.tlp_rtt_sample_seen_since_last_tlp = true;
        // A5.5 Task 15: gate now requires SRTT to be present.
        c.rtt_est.sample(5_000);
        assert!(c.tlp_arm_gate_passes());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn tlp_arm_gate_rejects_without_rtt_sample_seen_when_not_skipped() {
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_skip_rtt_sample_gate = false;
        c.tlp_rtt_sample_seen_since_last_tlp = false;
        c.tlp_max_consecutive_probes = 3;
        c.tlp_consecutive_probes_fired = 0;
        assert!(!c.tlp_arm_gate_passes());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn tlp_arm_gate_bypasses_rtt_sample_check_when_skip_flag_set() {
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_skip_rtt_sample_gate = true;
        c.tlp_rtt_sample_seen_since_last_tlp = false;
        c.tlp_max_consecutive_probes = 3;
        c.tlp_consecutive_probes_fired = 0;
        // A5.5 Task 15: gate now also requires SRTT regardless of the
        // RTT-sample-seen skip flag (PTO math still needs SRTT).
        c.rtt_est.sample(5_000);
        assert!(c.tlp_arm_gate_passes());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn tlp_arm_gate_rejects_when_srtt_absent() {
        // A5.5 Task 15: gate rejects when SRTT is unavailable. Post
        // Task 13 SYN-seed this only fires in pathological states
        // (Karn's-rule skip on SYN retransmit); RTO covers the first
        // burst until the next data-ACK seeds SRTT.
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_max_consecutive_probes = 3;
        c.tlp_consecutive_probes_fired = 0;
        c.tlp_rtt_sample_seen_since_last_tlp = true;
        // rtt_est holds no sample → srtt_us() is None.
        assert!(c.rtt_est.srtt_us().is_none());
        assert!(!c.tlp_arm_gate_passes());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn on_tlp_fire_records_probe_bumps_counter_clears_flag() {
        let mut c = make_test_conn();
        c.tlp_consecutive_probes_fired = 0;
        c.tlp_rtt_sample_seen_since_last_tlp = true;

        c.on_tlp_probe_fired(1000, 512, 12_345);

        assert_eq!(c.tlp_consecutive_probes_fired, 1);
        assert!(!c.tlp_rtt_sample_seen_since_last_tlp);
        assert!(c.tlp_recent_probes[0].is_some());
        let probe = c.tlp_recent_probes[0].unwrap();
        assert_eq!(probe.seq, 1000);
        assert_eq!(probe.len, 512);
        assert_eq!(probe.tx_ts_ns, 12_345);
        assert!(!probe.attributed);
        assert_eq!(c.tlp_recent_probes_next_slot, 1);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn on_tlp_fire_wraps_ring_at_slot_5() {
        let mut c = make_test_conn();
        for i in 0..6u32 {
            c.on_tlp_probe_fired(i, 1, i as u64);
        }
        assert_eq!(c.tlp_recent_probes_next_slot, 1);
        assert_eq!(c.tlp_recent_probes[0].unwrap().seq, 5);
        assert_eq!(c.tlp_recent_probes[1].unwrap().seq, 1);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn on_tlp_fire_budget_saturates_at_u8_max() {
        let mut c = make_test_conn();
        c.tlp_consecutive_probes_fired = u8::MAX;
        c.on_tlp_probe_fired(0, 1, 0);
        assert_eq!(c.tlp_consecutive_probes_fired, u8::MAX);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn on_rtt_sample_tlp_hook_resets_budget_and_sets_sample_seen() {
        let mut c = make_test_conn();
        c.tlp_consecutive_probes_fired = 3;
        c.tlp_rtt_sample_seen_since_last_tlp = false;

        c.on_rtt_sample_tlp_hook();

        assert_eq!(c.tlp_consecutive_probes_fired, 0);
        assert!(c.tlp_rtt_sample_seen_since_last_tlp);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn on_new_data_ack_tlp_hook_resets_budget_only() {
        let mut c = make_test_conn();
        c.tlp_consecutive_probes_fired = 3;
        c.tlp_rtt_sample_seen_since_last_tlp = false;

        c.on_new_data_ack_tlp_hook();

        assert_eq!(c.tlp_consecutive_probes_fired, 0);
        assert!(!c.tlp_rtt_sample_seen_since_last_tlp);
    }
}

#[cfg(test)]
mod a5_5_dsack_attribution {
    use super::a5_5_stats_tests::make_test_conn;
    use super::RecentProbe;

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn attribute_dsack_matches_recent_probe_within_window() {
        let mut c = make_test_conn();
        c.tlp_recent_probes[0] = Some(RecentProbe {
            seq: 1000,
            len: 100,
            tx_ts_ns: 1_000_000,
            attributed: false,
        });
        c.tlp_recent_probes_next_slot = 1;
        c.rtt_est.sample(100_000); // 100ms; window = 400ms
        let now_ns = 1_000_000 + 50_000_000; // 50ms later; within window

        let attributed = c.attribute_dsack_to_recent_tlp_probe(1000, 1100, now_ns);
        assert!(attributed);
        assert!(c.tlp_recent_probes[0].as_ref().unwrap().attributed);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn attribute_dsack_outside_window_skips_probe() {
        let mut c = make_test_conn();
        c.tlp_recent_probes[0] = Some(RecentProbe {
            seq: 1000,
            len: 100,
            tx_ts_ns: 1_000_000,
            attributed: false,
        });
        c.rtt_est.sample(100_000); // 100ms → window 400ms
        let now_ns = 1_000_000 + 500_000_000; // 500ms later; outside window

        let attributed = c.attribute_dsack_to_recent_tlp_probe(1000, 1100, now_ns);
        assert!(!attributed);
        assert!(!c.tlp_recent_probes[0].as_ref().unwrap().attributed);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn attribute_dsack_does_not_double_count_same_probe() {
        let mut c = make_test_conn();
        c.tlp_recent_probes[0] = Some(RecentProbe {
            seq: 1000,
            len: 100,
            tx_ts_ns: 1_000_000,
            attributed: false,
        });
        c.rtt_est.sample(100_000);
        let now_ns = 1_000_000 + 50_000_000;

        let first = c.attribute_dsack_to_recent_tlp_probe(1000, 1100, now_ns);
        let second = c.attribute_dsack_to_recent_tlp_probe(1000, 1100, now_ns);
        assert!(first);
        assert!(!second); // already attributed
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn attribute_dsack_partial_block_coverage_skips_probe() {
        let mut c = make_test_conn();
        c.tlp_recent_probes[0] = Some(RecentProbe {
            seq: 1000,
            len: 100,
            tx_ts_ns: 1_000_000,
            attributed: false,
        });
        c.rtt_est.sample(100_000);
        let now_ns = 1_000_000 + 50_000_000;

        // Block only covers [1050, 1100) — partial overlap; spec requires full coverage.
        let attributed = c.attribute_dsack_to_recent_tlp_probe(1050, 1100, now_ns);
        assert!(!attributed);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn attribute_dsack_with_no_probes_in_ring_returns_false() {
        let mut c = make_test_conn();
        c.rtt_est.sample(100_000);
        let now_ns = 1_000_000;

        let attributed = c.attribute_dsack_to_recent_tlp_probe(1000, 1100, now_ns);
        assert!(!attributed);
    }
}

#[cfg(test)]
mod a5_5_syn_srtt_seed {
    use super::a5_5_stats_tests::make_test_conn;
    use crate::engine::DEFAULT_RTT_HISTOGRAM_EDGES_US;

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn syn_rtt_seed_absorbs_first_sample() {
        let mut c = make_test_conn();
        c.syn_tx_ts_ns = 1_000_000_000; // 1s in ns
        c.syn_retrans_count = 0;
        let now_ns = 1_000_000_000 + 50_000_000; // 50ms later

        assert!(c.maybe_seed_srtt_from_syn(now_ns, &DEFAULT_RTT_HISTOGRAM_EDGES_US));
        assert!(c.rtt_est.srtt_us().is_some());
        assert!(c.rack.min_rtt_us > 0);
        // A6 Task 15: histogram absorbed the 50ms sample (bucket 12 per
        // default edges: 50000us > edges[11]=25000, ≤ edges[12]=50000).
        assert_eq!(c.rtt_histogram.buckets[12], 1);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn syn_rtt_seed_karns_rule_skips_retransmits() {
        let mut c = make_test_conn();
        c.syn_tx_ts_ns = 1_000_000_000;
        c.syn_retrans_count = 1; // SYN was retransmitted
        let now_ns = 1_000_000_000 + 50_000_000;

        assert!(!c.maybe_seed_srtt_from_syn(now_ns, &DEFAULT_RTT_HISTOGRAM_EDGES_US));
        assert!(c.rtt_est.srtt_us().is_none());
        assert_eq!(c.rack.min_rtt_us, 0);
        // A6 Task 15: skipped sample → histogram untouched.
        assert!(c.rtt_histogram.buckets.iter().all(|&b| b == 0));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn syn_rtt_seed_rejects_zero_syn_tx_ts() {
        let mut c = make_test_conn();
        c.syn_tx_ts_ns = 0; // never set (accept-side path, for instance)
        c.syn_retrans_count = 0;
        let now_ns = 1_000_000_000;

        assert!(!c.maybe_seed_srtt_from_syn(now_ns, &DEFAULT_RTT_HISTOGRAM_EDGES_US));
        assert!(c.rtt_est.srtt_us().is_none());
        assert_eq!(c.rack.min_rtt_us, 0);
        assert!(c.rtt_histogram.buckets.iter().all(|&b| b == 0));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn syn_rtt_seed_rejects_out_of_bounds_rtt() {
        let mut c = make_test_conn();
        c.syn_tx_ts_ns = 1_000_000_000;
        c.syn_retrans_count = 0;
        // 61s later — above 60s upper bound.
        let now_ns = 1_000_000_000 + 61_000_000_000;

        assert!(!c.maybe_seed_srtt_from_syn(now_ns, &DEFAULT_RTT_HISTOGRAM_EDGES_US));
        assert!(c.rtt_est.srtt_us().is_none());
        assert_eq!(c.rack.min_rtt_us, 0);
        assert!(c.rtt_histogram.buckets.iter().all(|&b| b == 0));
    }
}
