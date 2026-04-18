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
}

impl TcpConn {
    /// Create a fresh client-side connection ready to emit SYN.
    /// State = SYN_SENT; `snd_una = snd_nxt = iss`; our SYN will consume
    /// one seq (bumped to `iss+1` by the caller after successful TX).
    pub fn new_client(
        tuple: FourTuple,
        iss: u32,
        our_mss: u16,
        recv_buf_bytes: u32,
        send_buf_bytes: u32,
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
        }
    }

    pub fn four_tuple(&self) -> FourTuple {
        self.four_tuple
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
        let c = TcpConn::new_client(tuple(), 0xDEAD_BEEF, 1460, 1024, 2048);
        assert_eq!(c.snd_una, 0xDEAD_BEEF);
        assert_eq!(c.snd_nxt, 0xDEAD_BEEF);
        assert_eq!(c.iss, 0xDEAD_BEEF);
        assert_eq!(c.state, TcpState::Closed);
    }

    #[test]
    fn rcv_wnd_clamped_to_u16_max_without_wscale() {
        let c = TcpConn::new_client(tuple(), 0, 1460, 1_000_000, 1024);
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
        let mut c = TcpConn::new_client(tuple(), 100, 1460, 1024, 2048);
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
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048);
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
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048);
        assert!(c.sack_scoreboard.is_empty());
        assert_eq!(c.sack_scoreboard.len(), 0);
    }
}
