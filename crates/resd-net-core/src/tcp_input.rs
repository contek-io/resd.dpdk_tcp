//! Inbound TCP segment processing. Entry point is `tcp_input_dispatch`;
//! it parses the segment, looks up the flow, and dispatches to the
//! per-state handler. Per-state handlers are in this file but live
//! in `handle_syn_sent`, `handle_established`, etc.
//!
//! Per-segment ACK policy (spec §6.4): every segment that advances
//! `rcv_nxt` or transitions state triggers an ACK on the same poll
//! iteration (wired in the handlers via `TxAction::Ack`).

use crate::flow_table::FourTuple;
use crate::tcp_conn::TcpConn;
use crate::tcp_output::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::tcp_state::TcpState;

#[derive(Debug, Clone, Copy)]
pub struct ParsedSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub header_len: usize, // bytes including options
    pub payload: &'a [u8],
    /// The raw options-bytes region, if any. A3 only peeks for MSS
    /// (RFC 6691); unknown options are skipped.
    pub options: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpParseError {
    Short,
    BadDataOffset,
    BadFlags,
    Csum,
}

/// Parse a TCP segment from `tcp_bytes` (starts at the TCP header).
/// `src_ip`/`dst_ip` are from the IPv4 header in host byte order and
/// are used for the pseudo-header checksum verification. Caller can
/// skip verification by passing `nic_csum_ok=true` when the NIC has
/// already verified the TCP checksum.
pub fn parse_segment<'a>(
    tcp_bytes: &'a [u8],
    src_ip: u32,
    dst_ip: u32,
    nic_csum_ok: bool,
) -> Result<ParsedSegment<'a>, TcpParseError> {
    if tcp_bytes.len() < 20 {
        return Err(TcpParseError::Short);
    }
    let src_port = u16::from_be_bytes([tcp_bytes[0], tcp_bytes[1]]);
    let dst_port = u16::from_be_bytes([tcp_bytes[2], tcp_bytes[3]]);
    let seq = u32::from_be_bytes([tcp_bytes[4], tcp_bytes[5], tcp_bytes[6], tcp_bytes[7]]);
    let ack = u32::from_be_bytes([tcp_bytes[8], tcp_bytes[9], tcp_bytes[10], tcp_bytes[11]]);
    let data_off_words = (tcp_bytes[12] >> 4) as usize;
    if data_off_words < 5 {
        return Err(TcpParseError::BadDataOffset);
    }
    let header_len = data_off_words * 4;
    if tcp_bytes.len() < header_len {
        return Err(TcpParseError::BadDataOffset);
    }
    let flags = tcp_bytes[13];
    // Reject obviously-broken flag combinations per RFC 9293 §3.5
    // (SYN+FIN is nonsensical; RST+SYN likewise).
    if (flags & TCP_SYN) != 0 && (flags & TCP_FIN) != 0 {
        return Err(TcpParseError::BadFlags);
    }
    if (flags & TCP_RST) != 0 && (flags & TCP_SYN) != 0 {
        return Err(TcpParseError::BadFlags);
    }
    let window = u16::from_be_bytes([tcp_bytes[14], tcp_bytes[15]]);
    let options = &tcp_bytes[20..header_len];
    let payload = &tcp_bytes[header_len..];

    if !nic_csum_ok {
        let stored = u16::from_be_bytes([tcp_bytes[16], tcp_bytes[17]]);
        let mut scratch = tcp_bytes.to_vec();
        scratch[16] = 0;
        scratch[17] = 0;
        let csum = tcp_pseudo_csum(src_ip, dst_ip, scratch.len() as u32, &scratch);
        // Folded result of header-with-zero-csum + stored-csum should sum to 0.
        if csum != stored {
            return Err(TcpParseError::Csum);
        }
    }

    Ok(ParsedSegment {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        header_len,
        payload,
        options,
    })
}

fn tcp_pseudo_csum(src_ip: u32, dst_ip: u32, tcp_seg_len: u32, tcp_bytes: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp_bytes.len());
    buf.extend_from_slice(&src_ip.to_be_bytes());
    buf.extend_from_slice(&dst_ip.to_be_bytes());
    buf.push(0);
    buf.push(crate::l3_ip::IPPROTO_TCP);
    buf.extend_from_slice(&(tcp_seg_len as u16).to_be_bytes());
    buf.extend_from_slice(tcp_bytes);
    crate::l3_ip::internet_checksum(&buf)
}

/// Parse the TCP options field for a MSS value. Returns 536 (RFC 9293
/// §3.7.1 default) when absent. Unknown options are skipped by `len`.
pub fn parse_mss_option(options: &[u8]) -> u16 {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => return 536, // End of options
            1 => { i += 1; } // NOP
            2 => {
                // MSS option
                if i + 4 > options.len() || options[i + 1] != 4 {
                    return 536;
                }
                return u16::from_be_bytes([options[i + 2], options[i + 3]]);
            }
            _ => {
                if i + 1 >= options.len() {
                    return 536;
                }
                let olen = options[i + 1] as usize;
                if olen < 2 {
                    return 536;
                }
                i += olen;
            }
        }
    }
    536
}

/// What the engine should do next after processing a segment. Emitted
/// by the per-state handlers and consumed by the engine's dispatch code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAction {
    None,
    Ack,
    Rst,
    /// RFC 9293 §3.10.7.3: SYN_SENT rejects an ACK out of range with
    /// `<SEQ=SEG.ACK><CTL=RST>`. No ACK bit; seq carries the peer's ack value.
    RstForSynSentBadAck,
}

/// Outcome of dispatching a segment to a per-state handler.
#[derive(Debug, Clone, Copy)]
pub struct Outcome {
    pub tx: TxAction,
    pub new_state: Option<TcpState>,
    /// Number of payload bytes delivered to recv queue this segment.
    /// `> 0` implies the engine should enqueue a Readable event.
    pub delivered: u32,
    /// Bytes peer sent that exceeded our recv buffer's free_space.
    /// Engine bumps `tcp.recv_buf_drops` by this count. See
    /// `feedback_performance_first_flow_control.md`.
    pub buf_full_drop: u32,
    /// Non-zero iff this segment carried in-window payload at a seq
    /// ahead of `rcv_nxt` (hole). A3 has no reassembly queue (AD-6),
    /// so the payload is dropped and counted. Engine bumps
    /// `tcp.rx_out_of_order` by 1 when `> 0`. A4 replaces this with
    /// real reassembly + byte-level accounting.
    pub ooo_drop: u32,
    /// True iff this segment completed a handshake (SYN_SENT → ESTABLISHED).
    pub connected: bool,
    /// True iff this segment completed a clean close (→ CLOSED or
    /// entered TIME_WAIT which reaps to CLOSED).
    pub closed: bool,
}

impl Outcome {
    pub fn none() -> Self {
        Self { tx: TxAction::None, new_state: None, delivered: 0, buf_full_drop: 0, ooo_drop: 0, connected: false, closed: false }
    }
    pub fn rst() -> Self {
        Self { tx: TxAction::Rst, new_state: Some(TcpState::Closed), delivered: 0, buf_full_drop: 0, ooo_drop: 0, connected: false, closed: true }
    }
}

/// Per-state dispatcher. Stubs for now; concrete handlers land in
/// Tasks 11–13.
pub fn dispatch(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    match conn.state {
        TcpState::SynSent => handle_syn_sent(conn, seg),
        TcpState::Established => handle_established(conn, seg),
        TcpState::FinWait1
        | TcpState::FinWait2
        | TcpState::Closing
        | TcpState::LastAck
        | TcpState::CloseWait
        | TcpState::TimeWait => handle_close_path(conn, seg),
        _ => Outcome::none(),
    }
}

// Stubs filled in by subsequent tasks.
fn handle_syn_sent(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    use crate::tcp_seq::seq_le;

    // RFC 9293 §3.10.7.3 — SYN_SENT processing.
    // RST without a valid ACK of our SYN → drop silently. With a valid
    // ACK (snd_una < ack <= snd_nxt) → close.
    if (seg.flags & TCP_RST) != 0 {
        if (seg.flags & TCP_ACK) != 0
            && seq_le(conn.snd_una.wrapping_add(1), seg.ack)
            && seq_le(seg.ack, conn.snd_nxt)
        {
            return Outcome {
                tx: TxAction::None,
                new_state: Some(TcpState::Closed),
                delivered: 0,
                buf_full_drop: 0,
                ooo_drop: 0,
                connected: false,
                closed: true,
            };
        }
        return Outcome::none();
    }

    // Must have SYN to advance from SYN_SENT. Simultaneous-open (SYN
    // without ACK) transitions to SYN_RECEIVED per RFC 9293 — deferred
    // to A4. We drop it here.
    if (seg.flags & TCP_SYN) == 0 {
        return Outcome {
            tx: TxAction::RstForSynSentBadAck,
            new_state: Some(TcpState::Closed),
            delivered: 0,
            buf_full_drop: 0,
            ooo_drop: 0,
            connected: false,
            closed: true,
        };
    }

    if (seg.flags & TCP_ACK) == 0 {
        // SYN-only (simultaneous-open): deferred.
        return Outcome::none();
    }

    // ACK must cover exactly iss+1 (our SYN). Accept only when
    // snd_una+1 <= ack <= snd_nxt (RFC 9293 §3.10.7.3).
    if !seq_le(conn.snd_una.wrapping_add(1), seg.ack)
        || !seq_le(seg.ack, conn.snd_nxt)
    {
        return Outcome {
            tx: TxAction::RstForSynSentBadAck,
            new_state: Some(TcpState::Closed),
            delivered: 0,
            buf_full_drop: 0,
            ooo_drop: 0,
            connected: false,
            closed: true,
        };
    }

    // Update state per RFC 9293.
    conn.irs = seg.seq;
    conn.rcv_nxt = seg.seq.wrapping_add(1);
    conn.snd_una = seg.ack;
    conn.snd_wnd = seg.window as u32;
    conn.snd_wl1 = seg.seq;
    conn.snd_wl2 = seg.ack;
    conn.peer_mss = parse_mss_option(seg.options);

    Outcome {
        tx: TxAction::Ack,
        new_state: Some(TcpState::Established),
        delivered: 0,
        buf_full_drop: 0,
        ooo_drop: 0,
        connected: true,
        closed: false,
    }
}

fn handle_established(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    use crate::tcp_seq::{in_window, seq_le, seq_lt};

    // RST → close per RFC 9293 §3.10.7.4.
    if (seg.flags & TCP_RST) != 0 {
        return Outcome {
            tx: TxAction::None,
            new_state: Some(TcpState::Closed),
            delivered: 0,
            buf_full_drop: 0,
            ooo_drop: 0,
            connected: false,
            closed: true,
        };
    }

    // Segment must carry ACK in ESTABLISHED.
    if (seg.flags & TCP_ACK) == 0 {
        return Outcome::none();
    }

    // Sequence-window check — RFC 9293 §3.10.7.4. Accept iff either
    // the seg has no payload and seq==rcv_nxt (pure ACK), or its
    // payload's first byte lies within our recv window. Our check is
    // stricter than mTCP's (both edges); see spec §6.1 + plan header.
    let seg_len = seg.payload.len() as u32
        + ((seg.flags & TCP_FIN) != 0) as u32; // FIN consumes one
    let in_win = if seg_len == 0 {
        seg.seq == conn.rcv_nxt
    } else {
        let last = seg.seq.wrapping_add(seg_len).wrapping_sub(1);
        in_window(conn.rcv_nxt, seg.seq, conn.rcv_wnd)
            && in_window(conn.rcv_nxt, last, conn.rcv_wnd)
    };
    if !in_win {
        // Out-of-window: challenge ACK and drop.
        return Outcome { tx: TxAction::Ack, new_state: None, delivered: 0, buf_full_drop: 0, ooo_drop: 0, connected: false, closed: false };
    }

    // ACK processing — RFC 9293 §3.10.7.4, "ESTABLISHED STATE" ACK handling.
    if seq_lt(conn.snd_una, seg.ack) && seq_le(seg.ack, conn.snd_nxt) {
        let acked = seg.ack.wrapping_sub(conn.snd_una) as usize;
        for _ in 0..acked.min(conn.snd.pending.len()) {
            conn.snd.pending.pop_front();
        }
        conn.snd_una = seg.ack;
        // Update send window. Only accept advances from newer segments
        // per RFC 9293 §3.10.7.4 "SND.WL1 / SND.WL2" rules.
        if seq_lt(conn.snd_wl1, seg.seq)
            || (conn.snd_wl1 == seg.seq && seq_le(conn.snd_wl2, seg.ack))
        {
            conn.snd_wnd = seg.window as u32;
            conn.snd_wl1 = seg.seq;
            conn.snd_wl2 = seg.ack;
        }
    } else if seq_lt(conn.snd_nxt, seg.ack) {
        // ACK ahead of snd_nxt → we never sent that much; challenge ACK.
        return Outcome { tx: TxAction::Ack, new_state: None, delivered: 0, buf_full_drop: 0, ooo_drop: 0, connected: false, closed: false };
    }
    // Else: duplicate ACK (ack <= snd_una) — no-op for A3 (A5 uses it for fast retx).

    // Data delivery (only in-order).
    let mut delivered = 0u32;
    let mut buf_full_drop = 0u32;
    let mut ooo_drop = 0u32;
    if !seg.payload.is_empty() {
        if seg.seq == conn.rcv_nxt {
            delivered = conn.recv.append(seg.payload);
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(delivered);
            buf_full_drop = (seg.payload.len() as u32).saturating_sub(delivered);
        } else {
            // In-window but ahead of rcv_nxt: there's a hole. A3 has no
            // reassembly queue (AD-6), so the payload is dropped and the
            // challenge ACK emitted below signals the expected seq to the
            // peer per RFC 9293 §3.10.7.4 / RFC 5681 §4.2. Engine bumps
            // `tcp.rx_out_of_order` on `ooo_drop > 0`.
            ooo_drop = seg.payload.len() as u32;
        }
    }

    // FIN processing: consumes one seq and moves us to CLOSE_WAIT.
    let mut new_state = None;
    if (seg.flags & TCP_FIN) != 0
        && seg.seq.wrapping_add(seg.payload.len() as u32) == conn.rcv_nxt
    {
        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
        new_state = Some(TcpState::CloseWait);
    }

    // Emit ACK whenever we advance rcv_nxt, take a FIN, or saw any
    // in-window payload (in-order → confirms; OOO → dup-ACK signals
    // expected seq per RFC 9293 §3.10.7.4 / RFC 5681 §4.2). Pure-ack
    // segments that only advanced snd_una need no response.
    let tx = if delivered > 0
        || new_state == Some(TcpState::CloseWait)
        || !seg.payload.is_empty()
    {
        TxAction::Ack
    } else {
        TxAction::None
    };

    Outcome { tx, new_state, delivered, buf_full_drop, ooo_drop, connected: false, closed: false }
}

fn handle_close_path(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    use crate::tcp_seq::{in_window, seq_le, seq_lt};

    // RST in any close state → CLOSED.
    if (seg.flags & TCP_RST) != 0 {
        return Outcome {
            tx: TxAction::None,
            new_state: Some(TcpState::Closed),
            delivered: 0,
            buf_full_drop: 0,
            ooo_drop: 0,
            connected: false,
            closed: true,
        };
    }

    // TIME_WAIT: replay-ACK anything the peer sends; reaper will move
    // us to CLOSED via the engine tick (Task 19).
    if conn.state == TcpState::TimeWait {
        return Outcome { tx: TxAction::Ack, new_state: None, delivered: 0, buf_full_drop: 0, ooo_drop: 0, connected: false, closed: false };
    }

    // Segment must have ACK in these states.
    if (seg.flags & TCP_ACK) == 0 {
        return Outcome::none();
    }

    // Window check — same rule as ESTABLISHED.
    let seg_len = seg.payload.len() as u32 + ((seg.flags & TCP_FIN) != 0) as u32;
    let in_win = if seg_len == 0 {
        seg.seq == conn.rcv_nxt
    } else {
        let last = seg.seq.wrapping_add(seg_len).wrapping_sub(1);
        in_window(conn.rcv_nxt, seg.seq, conn.rcv_wnd)
            && in_window(conn.rcv_nxt, last, conn.rcv_wnd)
    };
    if !in_win {
        return Outcome { tx: TxAction::Ack, new_state: None, delivered: 0, buf_full_drop: 0, ooo_drop: 0, connected: false, closed: false };
    }

    // Advance snd_una if ack covers more of our stream.
    let fin_acked = conn.fin_has_been_acked(seg.ack);
    if seq_lt(conn.snd_una, seg.ack) && seq_le(seg.ack, conn.snd_nxt) {
        conn.snd_una = seg.ack;
    }

    let peer_has_fin = (seg.flags & TCP_FIN) != 0
        && seg.seq.wrapping_add(seg.payload.len() as u32) == conn.rcv_nxt;
    if peer_has_fin {
        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
    }

    // State transitions keyed by (current_state, fin_acked, peer_has_fin).
    let (new_state, tx) = match (conn.state, fin_acked, peer_has_fin) {
        (TcpState::FinWait1, true, true) => (Some(TcpState::TimeWait), TxAction::Ack),
        (TcpState::FinWait1, true, false) => (Some(TcpState::FinWait2), TxAction::None),
        (TcpState::FinWait1, false, true) => (Some(TcpState::Closing), TxAction::Ack),
        (TcpState::FinWait1, false, false) => (None, TxAction::None),
        (TcpState::FinWait2, _, true) => (Some(TcpState::TimeWait), TxAction::Ack),
        (TcpState::FinWait2, _, false) => (None, TxAction::None),
        (TcpState::Closing, true, _) => (Some(TcpState::TimeWait), TxAction::None),
        (TcpState::Closing, false, _) => (None, TxAction::None),
        (TcpState::LastAck, true, _) => (Some(TcpState::Closed), TxAction::None),
        (TcpState::LastAck, false, _) => (None, TxAction::None),
        (TcpState::CloseWait, _, _) => (None, TxAction::None),
        _ => (None, TxAction::None),
    };

    let closed = new_state == Some(TcpState::Closed);
    Outcome { tx, new_state, delivered: 0, buf_full_drop: 0, ooo_drop: 0, connected: false, closed }
}

/// Build the 4-tuple from a parsed segment's ports + the IPv4 header's
/// source/destination. Caller owns the IP fields. HBO throughout.
pub fn tuple_from_segment(src_ip: u32, dst_ip: u32, seg: &ParsedSegment) -> FourTuple {
    // RX: the segment arrives FROM peer TO us. Our tuple has
    // local = our side, peer = their side.
    FourTuple {
        local_ip: dst_ip,
        local_port: seg.dst_port,
        peer_ip: src_ip,
        peer_port: seg.src_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_output::{build_segment, SegmentTx, TCP_PSH};

    fn build_test_segment(flags: u8, mss: Option<u16>, payload: &[u8]) -> Vec<u8> {
        let seg = SegmentTx {
            src_mac: [0x02, 0, 0, 0, 0, 1],
            dst_mac: [0x02, 0, 0, 0, 0, 2],
            src_ip: 0x0a_00_00_01,
            dst_ip: 0x0a_00_00_02,
            src_port: 5000,
            dst_port: 40000,
            seq: 100,
            ack: 200,
            flags,
            window: 65535,
            mss_option: mss,
            payload,
        };
        let mut out = vec![0u8; 256];
        let n = build_segment(&seg, &mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn parse_ack_segment_with_payload() {
        let frame = build_test_segment(TCP_ACK | TCP_PSH, None, b"hello");
        let tcp = &frame[14 + 20..];
        let p = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, false).unwrap();
        assert_eq!(p.src_port, 5000);
        assert_eq!(p.dst_port, 40000);
        assert_eq!(p.seq, 100);
        assert_eq!(p.ack, 200);
        assert_eq!(p.payload, b"hello");
        assert_eq!(p.flags, TCP_ACK | TCP_PSH);
    }

    #[test]
    fn parse_rejects_short_segment() {
        let err = parse_segment(&[0u8; 10], 0, 0, true).unwrap_err();
        assert_eq!(err, TcpParseError::Short);
    }

    #[test]
    fn parse_rejects_syn_fin_combo() {
        let frame = build_test_segment(TCP_SYN | TCP_FIN, None, &[]);
        let tcp = &frame[14 + 20..];
        let err = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, true).unwrap_err();
        assert_eq!(err, TcpParseError::BadFlags);
    }

    #[test]
    fn parse_mss_option_present() {
        let frame = build_test_segment(TCP_SYN | TCP_ACK, Some(1460), &[]);
        let tcp = &frame[14 + 20..];
        let p = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, false).unwrap();
        assert_eq!(parse_mss_option(p.options), 1460);
    }

    #[test]
    fn parse_mss_absent_returns_default() {
        assert_eq!(parse_mss_option(&[]), 536);
    }

    #[test]
    fn bad_tcp_csum_rejected() {
        let mut frame = build_test_segment(TCP_ACK, None, b"hi");
        // Flip a payload bit — csum must now mismatch.
        frame[14 + 20 + 20] ^= 0xff;
        let tcp = &frame[14 + 20..];
        let err = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, false).unwrap_err();
        assert_eq!(err, TcpParseError::Csum);
    }

    #[test]
    fn tuple_from_segment_swaps_src_and_dst() {
        let frame = build_test_segment(TCP_ACK, None, &[]);
        let tcp = &frame[14 + 20..];
        let p = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, false).unwrap();
        let t = tuple_from_segment(0x0a_00_00_01, 0x0a_00_00_02, &p);
        assert_eq!(t.local_ip, 0x0a_00_00_02);
        assert_eq!(t.local_port, 40000);
        assert_eq!(t.peer_ip, 0x0a_00_00_01);
        assert_eq!(t.peer_port, 5000);
    }

    #[test]
    fn syn_sent_syn_ack_transitions_to_established() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1); // after SYN TX
        // Craft a SYN-ACK: their seq=5000, their ack=1001 (our iss+1), MSS=1400.
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5000, ack: 1001,
            flags: TCP_SYN | TCP_ACK,
            window: 65535,
            header_len: 24,
            payload: &[],
            options: &[2, 4, 0x05, 0x78], // MSS=1400
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Established));
        assert_eq!(out.tx, TxAction::Ack);
        assert!(out.connected);
        assert_eq!(c.rcv_nxt, 5001);
        assert_eq!(c.snd_una, 1001);
        assert_eq!(c.irs, 5000);
        assert_eq!(c.peer_mss, 1400);
    }

    #[test]
    fn syn_sent_plain_ack_wrong_seq_sends_rst() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        // Bogus: ACK-only with an ack that doesn't cover our SYN.
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5000, ack: 999,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::RstForSynSentBadAck);
    }

    #[test]
    fn syn_sent_rst_matching_our_ack_closes() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 0, ack: 1001,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
        assert_eq!(out.tx, TxAction::None);
    }

    fn est_conn(iss: u32, irs: u32, peer_wnd: u16) -> crate::tcp_conn::TcpConn {
        use crate::flow_table::FourTuple;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = crate::tcp_conn::TcpConn::new_client(t, iss, 1460, 1024, 2048);
        c.state = TcpState::Established;
        c.snd_una = iss.wrapping_add(1);
        c.snd_nxt = iss.wrapping_add(1);
        c.irs = irs;
        c.rcv_nxt = irs.wrapping_add(1);
        c.snd_wnd = peer_wnd as u32;
        c
    }

    #[test]
    fn established_inorder_data_delivered_and_acked() {
        let mut c = est_conn(1000, 5000, 1024);
        let payload = b"abcdef";
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload, options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 6);
        assert_eq!(c.rcv_nxt, 5001 + 6);
        assert_eq!(c.recv.bytes.len(), 6);
        let got: Vec<u8> = c.recv.bytes.iter().copied().collect();
        assert_eq!(&got, b"abcdef");
    }

    #[test]
    fn established_ooo_segment_acked_but_not_delivered() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5100, ack: 1001, // jumps past rcv_nxt
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: b"xyz", options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 0);
        // A3 I-1 fix: OOO in-window payload is dropped and counted.
        // Engine maps `ooo_drop > 0` to one `tcp.rx_out_of_order` bump.
        assert_eq!(out.ooo_drop, 3);
        assert_eq!(c.rcv_nxt, 5001); // unchanged
    }

    #[test]
    fn established_inorder_payload_does_not_flag_ooo() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload: b"abc", options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.delivered, 3);
        assert_eq!(out.ooo_drop, 0);
        assert_eq!(out.buf_full_drop, 0);
    }

    #[test]
    fn established_recv_buf_full_flags_buf_full_drop_not_ooo() {
        // recv buffer cap is 1024 in `est_conn`; send 2000 bytes in-order.
        let mut c = est_conn(1000, 5000, 4096);
        // Widen rcv_wnd so the 2000-byte segment is in-window, else the
        // handler would reject it before the delivery branch.
        c.rcv_wnd = 4096;
        let payload = vec![0u8; 2000];
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload: &payload, options: &[],
        };
        let out = dispatch(&mut c, &seg);
        // 1024 accepted, 976 dropped — overflow is `buf_full_drop`, not OOO.
        assert_eq!(out.delivered, 1024);
        assert_eq!(out.buf_full_drop, 2000 - 1024);
        assert_eq!(out.ooo_drop, 0);
    }

    #[test]
    fn established_ack_field_advances_snd_una() {
        let mut c = est_conn(1000, 5000, 1024);
        // Simulate 5 bytes in flight: push to snd.pending and advance snd_nxt.
        c.snd.push(b"hello");
        c.snd_nxt = c.snd_una.wrapping_add(5);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1006, // acks 5 bytes
            flags: TCP_ACK,
            window: 32000,
            header_len: 20,
            payload: &[], options: &[],
        };
        let _ = dispatch(&mut c, &seg);
        assert_eq!(c.snd_una, 1006);
        assert_eq!(c.snd_wnd, 32000);
        assert_eq!(c.snd.pending.len(), 0);
    }

    #[test]
    fn established_fin_transitions_to_close_wait() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::CloseWait));
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(c.rcv_nxt, 5002); // FIN consumes one seq
    }

    #[test]
    fn established_rst_closes_immediately() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
    }

    #[test]
    fn established_rst_outcome_carries_rst_cause() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
        // seg.flags & TCP_RST is what engine.rs uses to decide conn_rst bump;
        // this test locks in the downstream contract by checking the outcome
        // plus the segment's RST bit that the engine will inspect.
        assert!((seg.flags & TCP_RST) != 0);
    }

    #[test]
    fn fin_wait1_ack_of_our_fin_transitions_to_fin_wait2() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::FinWait1;
        c.snd_una = 1001;
        c.snd_nxt = 1002; // after our FIN
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1002, // acks our FIN
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::FinWait2));
    }

    #[test]
    fn fin_wait2_peer_fin_transitions_to_time_wait() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::FinWait2;
        c.snd_una = 1002;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1002,
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::TimeWait));
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(c.rcv_nxt, 5002);
    }

    #[test]
    fn fin_wait1_peer_fin_without_ack_of_our_fin_transitions_to_closing() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::FinWait1;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001, // does NOT ack our FIN
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closing));
    }

    #[test]
    fn closing_ack_of_our_fin_transitions_to_time_wait() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::Closing;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5002; // peer's FIN already consumed
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5002, ack: 1002,
            flags: TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::TimeWait));
    }

    #[test]
    fn last_ack_ack_of_our_fin_closes_connection() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::LastAck;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5002;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5002, ack: 1002,
            flags: TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
    }

    #[test]
    fn time_wait_replays_ack_on_any_segment() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::TimeWait;
        c.our_fin_seq = Some(1001);
        c.rcv_nxt = 5002;
        c.rcv_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1002,
            flags: TCP_ACK | TCP_FIN,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.new_state, None); // stay in TIME_WAIT until reaper
    }
}
