//! Per-connection state (spec §6.2, subset for Phase A3).
//! Fields deferred to A4/A5 are NOT here yet; the struct grows
//! additively. Keeping the struct small also keeps the `Vec<Option<TcpConn>>`
//! slot array cacheline-sparse — the per-slot size today is ~128 bytes.

use std::collections::VecDeque;

use crate::flow_table::FourTuple;
use crate::tcp_state::TcpState;

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

/// Per-connection receive buffer. A4 co-locates the out-of-order
/// reassembly queue (`reorder`) with the in-order ring (`bytes`); both
/// share the same cap, so `free_space_total` reports combined room.
pub struct RecvQueue {
    pub bytes: VecDeque<u8>,
    pub cap: u32,
    /// A4: out-of-order segments buffered past the in-order point.
    /// Shares `cap` with `bytes`; `free_space_total` reports combined room.
    pub reorder: crate::tcp_reassembly::ReorderQueue,
    /// Scratch buffer for the borrow-view exposed to
    /// `RESD_NET_EVT_READABLE.data`. Cleared at the start of each
    /// `resd_net_poll` on the owning engine (not here).
    pub last_read_buf: Vec<u8>,
}

impl RecvQueue {
    pub fn new(cap: u32) -> Self {
        Self {
            bytes: VecDeque::with_capacity(cap as usize),
            cap,
            reorder: crate::tcp_reassembly::ReorderQueue::new(cap),
            last_read_buf: Vec::new(),
        }
    }

    /// In-order free-space only (matches A3's semantic).
    pub fn free_space(&self) -> u32 {
        self.cap.saturating_sub(self.bytes.len() as u32)
    }

    /// Combined free-space across in-order bytes + reorder queue.
    pub fn free_space_total(&self) -> u32 {
        self.cap
            .saturating_sub(self.bytes.len() as u32)
            .saturating_sub(self.reorder.total_bytes())
    }

    /// Append `payload` to the in-order queue, up to in-order free-space.
    /// Returns the number of bytes accepted (may be < payload.len() if
    /// the in-order half would overflow).
    pub fn append(&mut self, payload: &[u8]) -> u32 {
        let take = payload.len().min(self.free_space() as usize);
        self.bytes.extend(&payload[..take]);
        take as u32
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
    /// Per-connect opt: when true, RACK `reo_wnd` forced to 0.
    pub rack_aggressive: bool,
    /// Per-connect opt: when true, RTO does not double on retransmit.
    pub rto_no_backoff: bool,
    /// A5: RFC 8985 RACK state.
    pub rack: crate::tcp_rack::RackState,

    // A5.5 Task 10: per-connect TLP tuning (ABI mirror of the five
    // `resd_net_connect_opts_t::tlp_*` fields). Zero-init substitution
    // is applied at `resd_net_connect` entry (multiplier 0 → 200,
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
            timer_ids: Vec::new(),
            snd_retrans: crate::tcp_retrans::SendRetrans::new(),
            rtt_est: crate::tcp_rtt::RttEstimator::new(min_rto_us, initial_rto_us, max_rto_us),
            rto_timer_id: None,
            tlp_timer_id: None,
            syn_retrans_count: 0,
            syn_retrans_timer_id: None,
            rack_aggressive: false,
            rto_no_backoff: false,
            rack: crate::tcp_rack::RackState::new(),
            // A5.5 Task 10: TLP tuning fields + runtime state zero-init.
            // `resd_net_connect` (or `connect_with_opts`) overrides the five
            // ABI-mirror fields with post-substitution values right after
            // inserting the conn into the flow table.
            tlp_pto_min_floor_us: 0,
            tlp_pto_srtt_multiplier_x100: 0,
            tlp_skip_flight_size_gate: false,
            tlp_max_consecutive_probes: 0,
            tlp_skip_rtt_sample_gate: false,
            tlp_consecutive_probes_fired: 0,
            tlp_rtt_sample_seen_since_last_tlp: false,
            tlp_recent_probes: [None; 5],
            tlp_recent_probes_next_slot: 0,
            syn_tx_ts_ns: 0,
        }
    }

    /// A5.5 Task 10: project the per-connect TLP tuning into the
    /// pure-function `TlpConfig` consumed by `pto_us`. By the time we
    /// reach here, `tlp_pto_min_floor_us` has already been substituted
    /// from `0` → engine `tcp_min_rto_us` at `resd_net_connect` entry;
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

    pub fn four_tuple(&self) -> FourTuple {
        self.four_tuple
    }

    /// Slow-path snapshot for forensics / per-order tagging. Called
    /// from the app via `resd_net_conn_stats`; not on any hot path.
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

    #[test]
    fn rcv_wnd_clamped_to_u16_max_without_wscale() {
        let c = TcpConn::new_client(tuple(), 0, 1460, 1_000_000, 1024, 5000, 5000, 1_000_000);
        assert_eq!(c.rcv_wnd, u16::MAX as u32);
    }

    #[test]
    fn send_queue_push_respects_cap() {
        let mut sq = SendQueue::new(4);
        assert_eq!(sq.push(b"hello"), 4);
        assert_eq!(sq.pending.len(), 4);
        assert_eq!(sq.free_space(), 0);
    }

    #[test]
    fn recv_queue_append_respects_cap() {
        let mut rq = RecvQueue::new(3);
        assert_eq!(rq.append(b"hello"), 3);
        assert_eq!(rq.bytes.len(), 3);
    }

    #[test]
    fn fin_acked_checks_fin_seq_plus_one() {
        let mut c = TcpConn::new_client(tuple(), 100, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(!c.fin_has_been_acked(150));
        c.our_fin_seq = Some(200);
        assert!(!c.fin_has_been_acked(200));
        assert!(c.fin_has_been_acked(201));
        assert!(c.fin_has_been_acked(500));
    }

    #[test]
    fn recv_queue_has_reorder_field_and_shares_cap() {
        let rq = RecvQueue::new(1024);
        assert_eq!(rq.cap, 1024);
        assert!(rq.reorder.is_empty());
        assert_eq!(rq.reorder.total_bytes(), 0);
        assert_eq!(rq.free_space_total(), 1024);
    }

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

    #[test]
    fn a4_sack_scoreboard_starts_empty() {
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(c.sack_scoreboard.is_empty());
        assert_eq!(c.sack_scoreboard.len(), 0);
    }

    #[test]
    fn a4_last_sack_trigger_starts_none() {
        // F-8 RFC 2018 §4 MUST-26: conn.last_sack_trigger is set by
        // tcp_input on OOO-insert and cleared by emit_ack after use.
        // Starts `None` on a fresh client connection.
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(c.last_sack_trigger.is_none());
    }

    #[test]
    fn new_client_timer_ids_starts_empty() {
        let c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(c.timer_ids.is_empty());
    }

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

    #[test]
    fn a5_conn_has_default_rack_state() {
        let c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert_eq!(c.rack.xmit_ts_ns, 0);
        assert_eq!(c.rack.end_seq, 0);
        assert_eq!(c.rack.min_rtt_us, 0);
        assert!(!c.rack.dsack_seen);
    }

    // A5.5 Task 10: per-connect TLP tuning + runtime state + syn_tx_ts_ns.
    #[test]
    fn a5_5_tlp_tuning_fields_zero_init_on_new_client() {
        let c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert_eq!(c.tlp_pto_min_floor_us, 0);
        assert_eq!(c.tlp_pto_srtt_multiplier_x100, 0);
        assert!(!c.tlp_skip_flight_size_gate);
        assert_eq!(c.tlp_max_consecutive_probes, 0);
        assert!(!c.tlp_skip_rtt_sample_gate);
        assert_eq!(c.tlp_consecutive_probes_fired, 0);
        assert!(!c.tlp_rtt_sample_seen_since_last_tlp);
        assert!(c.tlp_recent_probes.iter().all(|s| s.is_none()));
        assert_eq!(c.tlp_recent_probes_next_slot, 0);
        assert_eq!(c.syn_tx_ts_ns, 0);
    }

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

    #[test]
    fn a5_5_tlp_config_u32_max_means_no_floor() {
        let mut c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.tlp_pto_min_floor_us = u32::MAX;
        c.tlp_pto_srtt_multiplier_x100 = 200;
        let cfg = c.tlp_config(5_000);
        assert_eq!(cfg.floor_us, 0, "u32::MAX sentinel must project to 0");
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

    #[test]
    fn stats_before_any_rtt_sample_returns_zero_except_rto() {
        let c = make_test_conn();
        let s = c.stats(1_048_576);
        assert_eq!(s.srtt_us, 0);
        assert_eq!(s.rttvar_us, 0);
        assert_eq!(s.min_rtt_us, 0);
        assert_eq!(s.rto_us, c.rtt_est.rto_us());
    }

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
        });
    }

    #[test]
    fn tlp_arm_gate_rejects_when_retrans_empty() {
        let mut c = make_test_conn();
        c.tlp_max_consecutive_probes = 3;
        c.tlp_rtt_sample_seen_since_last_tlp = true;
        assert!(!c.tlp_arm_gate_passes());
    }

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

    #[test]
    fn tlp_arm_gates_reject_when_budget_exhausted() {
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_max_consecutive_probes = 3;
        c.tlp_consecutive_probes_fired = 3;
        c.tlp_rtt_sample_seen_since_last_tlp = true;
        assert!(!c.tlp_arm_gate_passes());
    }

    #[test]
    fn tlp_arm_gates_pass_when_under_budget_and_sample_seen() {
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_max_consecutive_probes = 3;
        c.tlp_consecutive_probes_fired = 1;
        c.tlp_rtt_sample_seen_since_last_tlp = true;
        assert!(c.tlp_arm_gate_passes());
    }

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

    #[test]
    fn tlp_arm_gate_bypasses_rtt_sample_check_when_skip_flag_set() {
        let mut c = make_test_conn();
        prime_retrans(&mut c, 1000, 512);
        c.tlp_skip_rtt_sample_gate = true;
        c.tlp_rtt_sample_seen_since_last_tlp = false;
        c.tlp_max_consecutive_probes = 3;
        c.tlp_consecutive_probes_fired = 0;
        assert!(c.tlp_arm_gate_passes());
    }

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

    #[test]
    fn on_tlp_fire_budget_saturates_at_u8_max() {
        let mut c = make_test_conn();
        c.tlp_consecutive_probes_fired = u8::MAX;
        c.on_tlp_probe_fired(0, 1, 0);
        assert_eq!(c.tlp_consecutive_probes_fired, u8::MAX);
    }

    #[test]
    fn on_rtt_sample_tlp_hook_resets_budget_and_sets_sample_seen() {
        let mut c = make_test_conn();
        c.tlp_consecutive_probes_fired = 3;
        c.tlp_rtt_sample_seen_since_last_tlp = false;

        c.on_rtt_sample_tlp_hook();

        assert_eq!(c.tlp_consecutive_probes_fired, 0);
        assert!(c.tlp_rtt_sample_seen_since_last_tlp);
    }

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
