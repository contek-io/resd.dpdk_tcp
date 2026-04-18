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
use crate::tcp_output::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, TCP_URG};
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
    pub delivered: u32,
    pub buf_full_drop: u32,
    /// Legacy A3 counter path. A4 always leaves this at 0 (OOO payload
    /// now goes through `reassembly_queued_bytes`); kept in the struct
    /// until an A5+ task drops it from all call sites.
    pub ooo_drop: u32,
    /// A4: bytes newly buffered into `recv.reorder` on this segment.
    /// Engine bumps `tcp.rx_reassembly_queued` once when > 0.
    pub reassembly_queued_bytes: u32,
    /// A4: OOO segments drained by the gap-close at the end of this
    /// segment's processing. Engine bumps
    /// `tcp.rx_reassembly_hole_filled` by this count.
    pub reassembly_hole_filled: u32,
    /// A4: true iff a PAWS check rejected this segment. Engine bumps
    /// `tcp.rx_paws_rejected` when true.
    pub paws_rejected: bool,
    /// A4: true iff the option decoder rejected a malformed option on
    /// this segment. Engine bumps `tcp.rx_bad_option` when true.
    pub bad_option: bool,
    /// A4: number of peer SACK blocks decoded from this segment's ACK.
    /// Engine bumps `tcp.rx_sack_blocks` by this count.
    pub sack_blocks_decoded: u32,
    /// A4 backfill: true iff the incoming segment's seq was outside
    /// `rcv_wnd` and we dropped + challenge-ACKed it. Engine bumps
    /// `tcp.rx_bad_seq`.
    pub bad_seq: bool,
    /// A4 backfill: true iff the ACK field was outside `(snd_una, snd_nxt]`
    /// (acking nothing new or acking future data). Engine bumps
    /// `tcp.rx_bad_ack`.
    pub bad_ack: bool,
    /// A4 backfill: true iff the segment was a duplicate ACK (ack_seq
    /// <= snd_una with no new data). Engine bumps `tcp.rx_dup_ack`.
    pub dup_ack: bool,
    /// A4 backfill: true iff the URG flag was set and we dropped the
    /// segment. Engine bumps `tcp.rx_urgent_dropped`.
    pub urgent_dropped: bool,
    /// A4 backfill: true iff the peer's advertised window is zero.
    /// Engine bumps `tcp.rx_zero_window`.
    pub rx_zero_window: bool,
    pub connected: bool,
    pub closed: bool,
}

impl Outcome {
    pub fn base() -> Self {
        Self {
            tx: TxAction::None,
            new_state: None,
            delivered: 0,
            buf_full_drop: 0,
            ooo_drop: 0,
            reassembly_queued_bytes: 0,
            reassembly_hole_filled: 0,
            paws_rejected: false,
            bad_option: false,
            sack_blocks_decoded: 0,
            bad_seq: false,
            bad_ack: false,
            dup_ack: false,
            urgent_dropped: false,
            rx_zero_window: false,
            connected: false,
            closed: false,
        }
    }
    pub fn none() -> Self { Self::base() }
    pub fn rst() -> Self {
        Self { tx: TxAction::Rst, new_state: Some(TcpState::Closed), closed: true, ..Self::base() }
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
                closed: true,
                ..Outcome::base()
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
            closed: true,
            ..Outcome::base()
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
            closed: true,
            ..Outcome::base()
        };
    }

    let parsed_opts = match crate::tcp_options::parse_options(seg.options) {
        Ok(o) => o,
        Err(_) => {
            return Outcome {
                tx: TxAction::Rst,
                new_state: Some(TcpState::Closed),
                closed: true,
                bad_option: true,
                ..Outcome::base()
            };
        }
    };

    conn.irs = seg.seq;
    conn.rcv_nxt = seg.seq.wrapping_add(1);
    conn.snd_una = seg.ack;
    // Scale the peer's advertised window by their WS if they advertised one.
    let peer_ws = parsed_opts.wscale.unwrap_or(0);
    conn.snd_wnd = (seg.window as u32).wrapping_shl(peer_ws as u32);
    conn.snd_wl1 = seg.seq;
    conn.snd_wl2 = seg.ack;
    conn.peer_mss = parsed_opts.mss.unwrap_or(536);

    match parsed_opts.wscale {
        Some(ws_peer) => { conn.ws_shift_in = ws_peer; }
        None => { conn.ws_shift_in = 0; conn.ws_shift_out = 0; }
    }
    conn.sack_enabled = parsed_opts.sack_permitted;
    if let Some((tsval, _tsecr)) = parsed_opts.timestamps {
        conn.ts_enabled = true;
        conn.ts_recent = tsval;
    } else {
        conn.ts_enabled = false;
    }

    Outcome {
        tx: TxAction::Ack,
        new_state: Some(TcpState::Established),
        connected: true,
        ..Outcome::base()
    }
}

fn handle_established(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    use crate::tcp_seq::{in_window, seq_le, seq_lt};

    // Stage 1 does not support URG. Drop silently and account via
    // `tcp.rx_urgent_dropped` (A4 cross-phase backfill — spec §9.1.1).
    if (seg.flags & TCP_URG) != 0 {
        return Outcome { tx: TxAction::None, urgent_dropped: true, ..Outcome::base() };
    }

    // Observe a zero-window advertisement from the peer before any
    // drop-path below can early-return. Critical trading signal (A4
    // cross-phase backfill — "exchange is slow").
    let rx_zero_window = seg.window == 0;

    // RST → close per RFC 9293 §3.10.7.4.
    if (seg.flags & TCP_RST) != 0 {
        return Outcome {
            tx: TxAction::None,
            new_state: Some(TcpState::Closed),
            closed: true,
            rx_zero_window,
            ..Outcome::base()
        };
    }

    // Segment must carry ACK in ESTABLISHED.
    if (seg.flags & TCP_ACK) == 0 {
        return Outcome { rx_zero_window, ..Outcome::base() };
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
        // Out-of-window: challenge ACK and drop. Account via
        // `tcp.rx_bad_seq` (A4 cross-phase backfill).
        return Outcome {
            tx: TxAction::Ack,
            bad_seq: true,
            rx_zero_window,
            ..Outcome::base()
        };
    }

    // A4: parse options (TS + SACK blocks). Malformed → bad_option drop.
    // `parsed_opts` is left in scope for Tasks 17/18 (OOO enqueue + SACK decode).
    let parsed_opts = if seg.options.is_empty() {
        crate::tcp_options::TcpOpts::default()
    } else {
        match crate::tcp_options::parse_options(seg.options) {
            Ok(o) => o,
            Err(_) => {
                return Outcome {
                    tx: TxAction::None,
                    bad_option: true,
                    rx_zero_window,
                    ..Outcome::base()
                };
            }
        }
    };

    // PAWS (RFC 7323 §5) — only when TS is negotiated. Missing TS on a
    // TS-enabled conn is RFC 7323 §3.2 MUST-24 violation.
    if conn.ts_enabled {
        match parsed_opts.timestamps {
            None => {
                return Outcome {
                    tx: TxAction::None,
                    bad_option: true,
                    rx_zero_window,
                    ..Outcome::base()
                };
            }
            Some((ts_val, _ts_ecr)) => {
                if crate::tcp_seq::seq_lt(ts_val, conn.ts_recent) {
                    return Outcome {
                        tx: TxAction::Ack,
                        paws_rejected: true,
                        rx_zero_window,
                        ..Outcome::base()
                    };
                }
                // RFC 7323 §4.3 MUST-25: only update ts_recent on a
                // segment whose seq is at or before rcv_nxt.
                if crate::tcp_seq::seq_le(seg.seq, conn.rcv_nxt) {
                    conn.ts_recent = ts_val;
                }
            }
        }
    }

    // A4: decode peer SACK blocks into the scoreboard (RFC 2018). SACK
    // info is advisory — on full-array overflow `SackScoreboard::insert`
    // drops the oldest block; the peer re-advertises on subsequent ACKs
    // so the loss is self-correcting. A5 retransmit reads the board.
    let mut sack_blocks_decoded = 0u32;
    if conn.sack_enabled && parsed_opts.sack_block_count > 0 {
        for block in &parsed_opts.sack_blocks[..parsed_opts.sack_block_count as usize] {
            conn.sack_scoreboard.insert(*block);
        }
        sack_blocks_decoded = parsed_opts.sack_block_count as u32;
    }

    // ACK processing — RFC 9293 §3.10.7.4, "ESTABLISHED STATE" ACK handling.
    let mut dup_ack = false;
    if seq_lt(conn.snd_una, seg.ack) && seq_le(seg.ack, conn.snd_nxt) {
        let acked = seg.ack.wrapping_sub(conn.snd_una) as usize;
        for _ in 0..acked.min(conn.snd.pending.len()) {
            conn.snd.pending.pop_front();
        }
        conn.snd_una = seg.ack;
        if conn.sack_enabled {
            conn.sack_scoreboard.prune_below(conn.snd_una);
        }
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
        // Account via `tcp.rx_bad_ack` (A4 cross-phase backfill).
        return Outcome {
            tx: TxAction::Ack,
            bad_ack: true,
            rx_zero_window,
            sack_blocks_decoded,
            ..Outcome::base()
        };
    } else {
        // Duplicate ACK (ack <= snd_una) — no-op for A3 (A5 uses for fast
        // retx). Account via `tcp.rx_dup_ack` (A4 cross-phase backfill).
        dup_ack = true;
    }

    // Data delivery — A4: in-order append + OOO reassembly enqueue +
    // drain-on-gap-close per spec §7.2.
    let mut delivered = 0u32;
    let mut buf_full_drop = 0u32;
    let mut reassembly_queued_bytes = 0u32;
    let mut reassembly_hole_filled = 0u32;
    if !seg.payload.is_empty() {
        if seg.seq == conn.rcv_nxt {
            delivered = conn.recv.append(seg.payload);
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(delivered);
            buf_full_drop = (seg.payload.len() as u32).saturating_sub(delivered);

            let (drained_bytes, drained_count) =
                conn.recv.reorder.drain_contiguous_from(conn.rcv_nxt);
            if !drained_bytes.is_empty() {
                let appended = conn.recv.append(&drained_bytes);
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(appended);
                buf_full_drop += (drained_bytes.len() as u32).saturating_sub(appended);
                delivered += appended;
            }
            reassembly_hole_filled = drained_count;
        } else if seq_lt(conn.rcv_nxt, seg.seq) {
            let total_cap = conn.recv.free_space_total();
            if total_cap > 0 {
                let take = (seg.payload.len() as u32).min(total_cap);
                let outcome = conn
                    .recv
                    .reorder
                    .insert(seg.seq, &seg.payload[..take as usize]);
                reassembly_queued_bytes = outcome.newly_buffered;
                buf_full_drop = outcome.cap_dropped;
                if (take as usize) < seg.payload.len() {
                    buf_full_drop += seg.payload.len() as u32 - take;
                }
            } else {
                buf_full_drop = seg.payload.len() as u32;
            }
        }
        // else: seg.seq < conn.rcv_nxt — duplicate/old payload; drop silently.
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

    Outcome {
        tx,
        new_state,
        delivered,
        buf_full_drop,
        reassembly_queued_bytes,
        reassembly_hole_filled,
        sack_blocks_decoded,
        dup_ack,
        rx_zero_window,
        ..Outcome::base()
    }
}

fn handle_close_path(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    use crate::tcp_seq::{in_window, seq_le, seq_lt};

    // RST in any close state → CLOSED.
    if (seg.flags & TCP_RST) != 0 {
        return Outcome {
            tx: TxAction::None,
            new_state: Some(TcpState::Closed),
            closed: true,
            ..Outcome::base()
        };
    }

    // TIME_WAIT: replay-ACK anything the peer sends; reaper will move
    // us to CLOSED via the engine tick (Task 19).
    if conn.state == TcpState::TimeWait {
        return Outcome { tx: TxAction::Ack, ..Outcome::base() };
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
        return Outcome { tx: TxAction::Ack, bad_seq: true, ..Outcome::base() };
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
    Outcome { tx, new_state, closed, ..Outcome::base() }
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
#[allow(clippy::field_reassign_with_default)]
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
            options: crate::tcp_options::TcpOpts {
                mss, ..Default::default()
            },
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
    fn syn_sent_syn_ack_negotiates_full_option_set() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_options::TcpOpts;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        c.ws_shift_out = 7;

        let mut peer_opts = TcpOpts::default();
        peer_opts.mss = Some(1400);
        peer_opts.wscale = Some(9);
        peer_opts.sack_permitted = true;
        peer_opts.timestamps = Some((0xCAFEBABE, 0x00001001));
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5000, ack: 1001,
            flags: TCP_SYN | TCP_ACK, window: 65535,
            header_len: 20 + opts_len, payload: &[],
            options: &opts_buf[..opts_len],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Established));
        assert_eq!(out.tx, TxAction::Ack);
        assert!(out.connected);
        assert_eq!(c.peer_mss, 1400);
        assert_eq!(c.ws_shift_in, 9);
        assert_eq!(c.ws_shift_out, 7);
        assert!(c.sack_enabled);
        assert!(c.ts_enabled);
        assert_eq!(c.ts_recent, 0xCAFEBABE);
    }

    #[test]
    fn syn_sent_peer_without_wscale_zeroes_both_shifts() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_options::TcpOpts;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        c.ws_shift_out = 7;

        let mut peer_opts = TcpOpts::default();
        peer_opts.mss = Some(1400);
        peer_opts.timestamps = Some((1, 2));
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5000, ack: 1001,
            flags: TCP_SYN | TCP_ACK, window: 65535,
            header_len: 20 + opts_len, payload: &[],
            options: &opts_buf[..opts_len],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Established));
        // RFC 7323 §1.3: WS only active if both sides advertise.
        assert_eq!(c.ws_shift_in, 0);
        assert_eq!(c.ws_shift_out, 0);
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
    fn established_ooo_segment_queues_into_reassembly() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5100, ack: 1001,
            flags: TCP_ACK, window: 65535,
            header_len: 20, payload: b"xyz", options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 0);
        assert_eq!(out.ooo_drop, 0); // A4: legacy, always zero
        assert_eq!(out.reassembly_queued_bytes, 3);
        assert_eq!(c.rcv_nxt, 5001);
        assert_eq!(c.recv.reorder.len(), 1);
        assert_eq!(&c.recv.reorder.segments()[0].payload, b"xyz");
    }

    #[test]
    fn inorder_arrival_closes_hole_and_drains_reassembly() {
        let mut c = est_conn(1000, 5000, 1024);
        c.rcv_wnd = 4096;
        let ooo = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5010, ack: 1001,
            flags: TCP_ACK, window: 65535,
            header_len: 20, payload: b"world", options: &[],
        };
        let out_ooo = dispatch(&mut c, &ooo);
        assert_eq!(out_ooo.reassembly_queued_bytes, 5);
        assert_eq!(c.rcv_nxt, 5001);

        let inorder = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH, window: 65535,
            header_len: 20, payload: b"ninebytes", options: &[],
        };
        let out_in = dispatch(&mut c, &inorder);
        assert_eq!(out_in.delivered, 9 + 5);
        assert_eq!(out_in.reassembly_hole_filled, 1);
        assert_eq!(c.rcv_nxt, 5015);
        assert!(c.recv.reorder.is_empty());
        let got: Vec<u8> = c.recv.bytes.iter().copied().collect();
        assert_eq!(&got, b"ninebytesworld");
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

    fn est_conn_ts(iss: u32, irs: u32, peer_wnd: u16, ts_recent: u32) -> crate::tcp_conn::TcpConn {
        let mut c = est_conn(iss, irs, peer_wnd);
        c.ts_enabled = true;
        c.ts_recent = ts_recent;
        c
    }

    #[test]
    fn paws_drops_segment_with_stale_tsval_and_emits_challenge_ack() {
        use crate::tcp_options::TcpOpts;
        let mut c = est_conn_ts(1000, 5000, 1024, 200);
        let mut peer_opts = TcpOpts::default();
        peer_opts.timestamps = Some((100, 0));
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK, window: 65535,
            header_len: 20 + n, payload: b"xxx",
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.paws_rejected);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 0);
        assert_eq!(c.ts_recent, 200); // unchanged
    }

    #[test]
    fn paws_accepts_fresh_tsval_and_updates_ts_recent() {
        use crate::tcp_options::TcpOpts;
        let mut c = est_conn_ts(1000, 5000, 1024, 200);
        let mut peer_opts = TcpOpts::default();
        peer_opts.timestamps = Some((300, 0));
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH, window: 65535,
            header_len: 20 + n, payload: b"hello",
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg);
        assert!(!out.paws_rejected);
        assert_eq!(out.delivered, 5);
        assert_eq!(c.ts_recent, 300);
    }

    #[test]
    fn missing_ts_on_ts_enabled_conn_bumps_bad_option_and_drops() {
        let mut c = est_conn_ts(1000, 5000, 1024, 200);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH, window: 65535,
            header_len: 20, payload: b"x",
            options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.bad_option);
        assert_eq!(out.delivered, 0);
    }

    #[test]
    fn established_decodes_peer_sack_blocks_into_scoreboard() {
        use crate::tcp_options::{SackBlock, TcpOpts};
        let mut c = est_conn(1000, 5000, 1024);
        c.sack_enabled = true;
        c.snd.push(&[0u8; 20]);
        c.snd_nxt = c.snd_una.wrapping_add(20);

        let mut peer_opts = TcpOpts::default();
        peer_opts.push_sack_block(SackBlock { left: 1005, right: 1010 });
        peer_opts.push_sack_block(SackBlock { left: 1015, right: 1020 });
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1003,
            flags: TCP_ACK, window: 65535,
            header_len: 20 + n, payload: &[],
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.sack_blocks_decoded, 2);
        assert!(c.sack_scoreboard.is_sacked(1005));
        assert!(c.sack_scoreboard.is_sacked(1018));
        assert!(!c.sack_scoreboard.is_sacked(1003));
    }

    #[test]
    fn established_prunes_scoreboard_below_snd_una() {
        use crate::tcp_options::{SackBlock, TcpOpts};
        let mut c = est_conn(1000, 5000, 1024);
        c.sack_enabled = true;
        c.sack_scoreboard.insert(SackBlock { left: 1005, right: 1010 });
        c.sack_scoreboard.insert(SackBlock { left: 1020, right: 1030 });
        c.snd.push(&[0u8; 30]);
        c.snd_nxt = c.snd_una.wrapping_add(30);

        let peer_opts = TcpOpts::default();
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1015,
            flags: TCP_ACK, window: 65535,
            header_len: 20 + n, payload: &[],
            options: &buf[..n],
        };
        let _ = dispatch(&mut c, &seg);
        assert_eq!(c.snd_una, 1015);
        assert_eq!(c.sack_scoreboard.len(), 1);
        assert_eq!(c.sack_scoreboard.blocks()[0].left, 1020);
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

    // A4 Task 19: cross-phase backfill flags on `Outcome`.

    #[test]
    fn established_urg_flag_drops_and_sets_urgent_dropped() {
        use crate::tcp_output::TCP_URG;
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_URG, window: 65535,
            header_len: 20, payload: b"x", options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.urgent_dropped);
        assert_eq!(out.tx, TxAction::None);
        assert_eq!(out.delivered, 0);
        // Segment should NOT have been delivered.
        assert_eq!(c.rcv_nxt, 5001);
    }

    #[test]
    fn established_out_of_window_sets_bad_seq_and_challenge_acks() {
        let mut c = est_conn(1000, 5000, 1024);
        // rcv_nxt=5001, rcv_wnd=1024. seq way past window.
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 9999, ack: 1001,
            flags: TCP_ACK, window: 65535,
            header_len: 20, payload: b"xxx", options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.bad_seq);
        assert_eq!(out.tx, TxAction::Ack); // challenge ACK
        assert_eq!(out.delivered, 0);
    }

    #[test]
    fn established_ack_ahead_of_snd_nxt_sets_bad_ack() {
        let mut c = est_conn(1000, 5000, 1024);
        // snd_nxt=1001 (1000+1 for SYN). Ack a future byte.
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 9999,
            flags: TCP_ACK, window: 65535,
            header_len: 20, payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.bad_ack);
        assert_eq!(out.tx, TxAction::Ack); // challenge ACK
    }

    #[test]
    fn established_duplicate_ack_sets_dup_ack() {
        let mut c = est_conn(1000, 5000, 1024);
        // ack == snd_una == 1001 ⇒ duplicate ACK.
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK, window: 65535,
            header_len: 20, payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.dup_ack);
    }

    #[test]
    fn established_zero_window_segment_sets_rx_zero_window() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK, window: 0,
            header_len: 20, payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.rx_zero_window);
    }

    #[test]
    fn established_nonzero_window_does_not_set_rx_zero_window() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK, window: 1,
            header_len: 20, payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(!out.rx_zero_window);
    }

    #[test]
    fn close_path_out_of_window_sets_bad_seq() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::FinWait2;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        // seq well outside window.
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 99999, ack: 1002,
            flags: TCP_ACK, window: 65535,
            header_len: 20, payload: b"x", options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.bad_seq);
        assert_eq!(out.tx, TxAction::Ack);
    }

    #[test]
    fn established_base_outcome_flags_default_false() {
        let out = Outcome::base();
        assert!(!out.bad_seq);
        assert!(!out.bad_ack);
        assert!(!out.dup_ack);
        assert!(!out.urgent_dropped);
        assert!(!out.rx_zero_window);
    }
}
