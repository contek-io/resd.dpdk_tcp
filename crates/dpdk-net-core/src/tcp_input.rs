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

/// A6 (spec §3.7): RFC 7323 §5.5 24-day `TS.Recent` expiration window
/// in nanoseconds. Applied lazily at the PAWS gate — no timer, no
/// hot-path cost on fresh connections.
const TS_RECENT_EXPIRY_NS: u64 = 24 * 86_400 * 1_000_000_000;

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
        // Fold pseudo-header + TCP bytes (with the 2-byte csum field
        // zeroed) directly as a slice-of-slices, avoiding a scratch copy.
        // Caller guarantees tcp_bytes.len() >= 20 (checked above at the
        // header-length gate), so the split around offset 16..18 is safe.
        const CSUM_OFFSET: usize = 16;
        const CSUM_LEN: usize = 2;
        let head = &tcp_bytes[..CSUM_OFFSET];
        let tail = &tcp_bytes[CSUM_OFFSET + CSUM_LEN..];
        let zero_csum: [u8; CSUM_LEN] = [0, 0];

        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src_ip.to_be_bytes());
        pseudo[4..8].copy_from_slice(&dst_ip.to_be_bytes());
        pseudo[8] = 0;
        pseudo[9] = crate::l3_ip::IPPROTO_TCP;
        pseudo[10..12].copy_from_slice(&(tcp_bytes.len() as u16).to_be_bytes());

        let csum = crate::l3_ip::internet_checksum(&[&pseudo, head, &zero_csum, tail]);
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
#[derive(Debug, Clone)]
pub struct Outcome {
    pub tx: TxAction,
    pub new_state: Option<TcpState>,
    pub delivered: u32,
    pub buf_full_drop: u32,
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
    /// A6 Task 14 (spec §3.7): true iff the RFC 7323 §5.5 24-day
    /// `TS.Recent` lazy expiration fired on this segment. Engine bumps
    /// `tcp.ts_recent_expired` when true. Slow-path — fires at most
    /// once per 24-day-plus idle event per conn.
    pub ts_recent_expired: bool,
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
    /// A5 Task 22: peer advertised WS shift > 14 on handshake; parser
    /// clamped to 14 per RFC 7323 §2.3 MUST. Engine bumps
    /// `tcp.rx_ws_shift_clamped` + emits a one-shot stderr log.
    pub ws_shift_clamped: bool,
    /// A5: if the ACK advanced snd.una, this is the new snd.una value.
    /// Engine uses this to prune snd_retrans and potentially cancel RTO.
    pub snd_una_advanced_to: Option<u32>,
    /// A5: true iff a valid RTT sample was taken from this ACK. Counter
    /// wiring lives in Task 26 (counter batch); this field is observable here.
    pub rtt_sample_taken: bool,
    /// A5 Task 15: indexes into `conn.snd_retrans.entries` that RACK
    /// marked lost this ACK. Engine retransmits each and bumps
    /// `tcp.tx_rack_loss`. Vec<u16> chosen to allow ≥4 simultaneous
    /// losses while keeping the Outcome small (a fresh Vec is allocated
    /// per ACK — at typical rates ≤1k ACKs/sec per conn, this is
    /// acceptable; a Stage-2 optimization could use an inline
    /// fixed-size array).
    pub rack_lost_indexes: Vec<u16>,
    /// A5 Task 16: RFC 2883 DSACK blocks detected this ACK. Engine
    /// bumps `tcp.rx_dsack` by this count. Visibility only — A5 does
    /// not adapt reo_wnd or scoreboard prune based on DSACK.
    pub rx_dsack_count: u32,
    /// A5.5 Task 12: count of recent TLP probes retroactively classified
    /// as spurious by DSACK blocks on this ACK (RFC 8985 §7.4 / spec
    /// §3.4). Engine bumps `tcp.tx_tlp_spurious` by this count.
    pub tx_tlp_spurious_count: u32,
    /// A5 Task 18: the SYN-retransmit timer id to cancel on the engine's
    /// side. Set by `handle_syn_sent` when a valid SYN-ACK lands — the
    /// conn's `syn_retrans_timer_id` field is `.take()`n here so the
    /// engine can `timer_wheel.cancel()` it post-dispatch and prune it
    /// from `conn.timer_ids`. `None` on every other segment / state.
    pub syn_retrans_timer_to_cancel: Option<crate::tcp_timer_wheel::TimerId>,
    /// A6 Task 16 (spec §3.3): send-buffer drained to ≤ `send_buffer_bytes/2`
    /// after a prior `send_bytes` refusal. When true, the engine translator
    /// pushes `InternalEvent::Writable` for this conn. Level-triggered,
    /// single-edge-per-refusal-cycle: the ACK-prune site also clears
    /// `conn.send_refused_pending` when setting this, so subsequent ACKs
    /// won't re-fire until a fresh `send_bytes` refusal restarts the cycle.
    pub writable_hysteresis_fired: bool,
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
            reassembly_queued_bytes: 0,
            reassembly_hole_filled: 0,
            paws_rejected: false,
            ts_recent_expired: false,
            bad_option: false,
            sack_blocks_decoded: 0,
            bad_seq: false,
            bad_ack: false,
            dup_ack: false,
            urgent_dropped: false,
            rx_zero_window: false,
            ws_shift_clamped: false,
            snd_una_advanced_to: None,
            rtt_sample_taken: false,
            rack_lost_indexes: Vec::new(),
            rx_dsack_count: 0,
            tx_tlp_spurious_count: 0,
            syn_retrans_timer_to_cancel: None,
            writable_hysteresis_fired: false,
            connected: false,
            closed: false,
        }
    }
    pub fn none() -> Self {
        Self::base()
    }
    pub fn rst() -> Self {
        Self {
            tx: TxAction::Rst,
            new_state: Some(TcpState::Closed),
            closed: true,
            ..Self::base()
        }
    }
}

/// Per-state dispatcher. Stubs for now; concrete handlers land in
/// Tasks 11–13.
///
/// A6 Task 15 (spec §3.8): `rtt_histogram_edges` threads the engine-wide
/// histogram edges down to each RTT-sample-taking handler so the per-conn
/// `TcpConn::rtt_histogram` is updated on the same site as `rtt_est.sample`.
///
/// A6 Task 16 (spec §3.3): `send_buffer_bytes` threads the engine-wide
/// send-buffer capacity down to the ACK-prune site in `handle_established`
/// so the WRITABLE hysteresis (`in_flight ≤ send_buffer_bytes/2`) can be
/// evaluated there without an extra engine-side borrow round-trip.
pub fn dispatch(
    conn: &mut TcpConn,
    seg: &ParsedSegment,
    rtt_histogram_edges: &[u32; 15],
    send_buffer_bytes: u32,
) -> Outcome {
    match conn.state {
        TcpState::SynSent => handle_syn_sent(conn, seg, rtt_histogram_edges),
        TcpState::Established => {
            handle_established(conn, seg, rtt_histogram_edges, send_buffer_bytes)
        }
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
fn handle_syn_sent(
    conn: &mut TcpConn,
    seg: &ParsedSegment,
    rtt_histogram_edges: &[u32; 15],
) -> Outcome {
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
    if !seq_le(conn.snd_una.wrapping_add(1), seg.ack) || !seq_le(seg.ack, conn.snd_nxt) {
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
    // F-3 RFC 7323 §2.2: the window field in a <SYN,ACK> MUST NOT be scaled.
    // Both ends have not yet agreed on WS; the handshake carries unscaled
    // windows. Scaling begins with the first post-handshake segment (see
    // the established-state branch below).
    conn.snd_wnd = seg.window as u32;
    conn.snd_wl1 = seg.seq;
    conn.snd_wl2 = seg.ack;
    conn.peer_mss = parsed_opts.mss.unwrap_or(536);

    match parsed_opts.wscale {
        Some(ws_peer) => {
            // F-1 RFC 7323 §2.3: "If a Window Scale option is received with
            // a shift.cnt value larger than 14, the TCP SHOULD log the error
            // but MUST use 14 instead of the specified value." Clamp at 14
            // before the shift flows into any subsequent `snd_wnd` left-shift
            // (F-2 path below).
            conn.ws_shift_in = ws_peer.min(14);
        }
        None => {
            conn.ws_shift_in = 0;
            conn.ws_shift_out = 0;
        }
    }
    conn.sack_enabled = parsed_opts.sack_permitted;
    if let Some((tsval, _tsecr)) = parsed_opts.timestamps {
        conn.ts_enabled = true;
        conn.ts_recent = tsval;
        // A6 Task 14: every `ts_recent` write sets `ts_recent_age` so the
        // RFC 7323 §5.5 24-day lazy expiration (PAWS gate) has accurate
        // idle tracking from the first TS exchange onward.
        conn.ts_recent_age = crate::clock::now_ns();
    } else {
        conn.ts_enabled = false;
    }

    // A5 Task 22: parser-layer clamp signal — the peer advertised a WS
    // shift > 14 and the decoder clamped it to 14 already (see
    // `tcp_options.rs::parse_options`). The handshake site above is the
    // defense-in-depth fallback; here we fulfill the RFC 7323 §2.3 SHOULD
    // by logging once per-conn (the flag only latches on a valid SYN-ACK
    // that reached this point, so each conn emits at most one line) and
    // hand the engine an Outcome flag to bump `tcp.rx_ws_shift_clamped`.
    let ws_shift_clamped = parsed_opts.ws_clamped;
    if ws_shift_clamped {
        eprintln!(
            "dpdk_net: peer advertised WS shift > 14 on conn {:?}; clamped to 14 per RFC 7323 §2.3",
            conn.four_tuple()
        );
    }

    // A5.5 Task 13: seed SRTT from the SYN handshake round-trip
    // (RFC 6298 §3.3 MAY). Karn's rule + bounds are inside the helper.
    // A6 Task 15 (spec §3.8): on absorption the helper updates the
    // per-conn RTT histogram under the engine-wide edges.
    conn.maybe_seed_srtt_from_syn(crate::clock::now_ns(), rtt_histogram_edges);

    // A5 Task 18: SYN-ACK accepted — hand the engine the SYN-retransmit
    // timer id so it can cancel the pending fire (we can't touch the
    // engine's timer wheel from here). `take()` zeros the field so a
    // subsequent fire observes the cancelled-without-id path.
    let syn_retrans_timer_to_cancel = conn.syn_retrans_timer_id.take();

    Outcome {
        tx: TxAction::Ack,
        new_state: Some(TcpState::Established),
        connected: true,
        syn_retrans_timer_to_cancel,
        ws_shift_clamped,
        ..Outcome::base()
    }
}

/// RFC 2883 §4 DSACK detection (receive side). Returns true iff `block`
/// is a duplicate-SACK report, meaning either:
///   (a) `block.right <= snd_una` — block covers already-cumulatively-ACKed
///       data, OR
///   (b) `block` is fully enclosed by some entry already in `scoreboard` —
///       the peer is re-reporting a range we've already recorded as SACKed.
/// A5 uses this for visibility only (`tcp.rx_dsack` + `rack.dsack_seen`);
/// Stage 2 may add reo_wnd adaptation (RFC 8985 §7).
pub(crate) fn is_dsack(
    block: &crate::tcp_options::SackBlock,
    snd_una: u32,
    scoreboard: &crate::tcp_sack::SackScoreboard,
) -> bool {
    if crate::tcp_seq::seq_le(block.right, snd_una) {
        return true;
    }
    scoreboard.blocks().iter().any(|existing| {
        crate::tcp_seq::seq_le(existing.left, block.left)
            && crate::tcp_seq::seq_le(block.right, existing.right)
    })
}

fn handle_established(
    conn: &mut TcpConn,
    seg: &ParsedSegment,
    rtt_histogram_edges: &[u32; 15],
    send_buffer_bytes: u32,
) -> Outcome {
    use crate::tcp_seq::{in_window, seq_le, seq_lt};

    // Stage 1 does not support URG. Drop silently and account via
    // `tcp.rx_urgent_dropped` (A4 cross-phase backfill — spec §9.1.1).
    if (seg.flags & TCP_URG) != 0 {
        return Outcome {
            tx: TxAction::None,
            urgent_dropped: true,
            ..Outcome::base()
        };
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
        return Outcome {
            rx_zero_window,
            ..Outcome::base()
        };
    }

    // Sequence-window check — RFC 9293 §3.10.7.4. Accept iff either
    // the seg has no payload and seq==rcv_nxt (pure ACK), or its
    // payload's first byte lies within our recv window. Our check is
    // stricter than mTCP's (both edges); see spec §6.1 + plan header.
    let seg_len = seg.payload.len() as u32 + ((seg.flags & TCP_FIN) != 0) as u32; // FIN consumes one
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
    let mut ts_recent_expired = false;
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
                // A6 Task 14 (spec §3.7): RFC 7323 §5.5 24-day `TS.Recent`
                // lazy expiration. If the connection has been idle for more
                // than 24 days, treat `TS.Recent` as absent for this segment:
                // adopt `ts_val`, reset the age clock, and skip the PAWS
                // drop compare. Sentinel `ts_recent_age == 0` is "never
                // touched" (fresh conn pre-first-TS-update) — not expired.
                // Zero hot-path cost on fresh conns; no timer wheel needed.
                let now_ns = crate::clock::now_ns();
                let idle_ns = now_ns.saturating_sub(conn.ts_recent_age);
                let paws_skip_this_seg =
                    conn.ts_recent_age != 0 && idle_ns > TS_RECENT_EXPIRY_NS;
                if paws_skip_this_seg {
                    conn.ts_recent = ts_val;
                    conn.ts_recent_age = now_ns;
                    ts_recent_expired = true;
                } else if crate::tcp_seq::seq_lt(ts_val, conn.ts_recent) {
                    return Outcome {
                        tx: TxAction::Ack,
                        paws_rejected: true,
                        rx_zero_window,
                        ..Outcome::base()
                    };
                }
                // RFC 7323 §4.3 MUST-25: only update ts_recent on a
                // segment whose seq is at or before rcv_nxt. Also update
                // `ts_recent_age` whenever `ts_recent` is written so the
                // §5.5 24-day idle check above has accurate age data
                // (A6 Task 14 contract).
                if !paws_skip_this_seg && crate::tcp_seq::seq_le(seg.seq, conn.rcv_nxt) {
                    conn.ts_recent = ts_val;
                    conn.ts_recent_age = now_ns;
                }
            }
        }
    }

    // A4: decode peer SACK blocks into the scoreboard (RFC 2018). SACK
    // info is advisory — on full-array overflow `SackScoreboard::insert`
    // drops the oldest block; the peer re-advertises on subsequent ACKs
    // so the loss is self-correcting. A5 retransmit reads the board.
    // A5 Task 15: also mark matching snd_retrans entries sacked so the
    // RACK pass below sees them (RFC 8985 §6.1 treats SACKed entries as
    // delivered for RACK.xmit_ts update purposes).
    // A5 Task 16: classify each SACK block as DSACK (RFC 2883 §4) before
    // insert. DSACK blocks cover already-acked data — skip the scoreboard
    // insert/mark_sacked (would waste the 4-slot scoreboard budget and
    // mark_sacked on pruned data is a no-op anyway). Count goes to
    // `tcp.rx_dsack` via Outcome; `rack.dsack_seen` latches for Stage 2.
    // Ordering note: the DSACK check must run BEFORE `insert` for the
    // same block, otherwise condition (b) "fully covered by existing"
    // would falsely match the block we just inserted.
    let mut sack_blocks_decoded = 0u32;
    let mut rx_dsack_count = 0u32;
    let mut tx_tlp_spurious_count = 0u32;
    if conn.sack_enabled && parsed_opts.sack_block_count > 0 {
        for block in &parsed_opts.sack_blocks[..parsed_opts.sack_block_count as usize] {
            if is_dsack(block, conn.snd_una, &conn.sack_scoreboard) {
                rx_dsack_count += 1;
                conn.rack.dsack_seen = true;
                // A5.5 Task 12: attribute this DSACK block to a recent
                // TLP probe if one falls wholly inside the block's seq
                // range and within the 4·SRTT plausibility window.
                let now_ns = crate::clock::now_ns();
                if conn.attribute_dsack_to_recent_tlp_probe(block.left, block.right, now_ns) {
                    tx_tlp_spurious_count += 1;
                }
                continue;
            }
            conn.sack_scoreboard.insert(*block);
            conn.snd_retrans.mark_sacked(*block);
        }
        sack_blocks_decoded = parsed_opts.sack_block_count as u32;
    }

    // ACK processing — RFC 9293 §3.10.7.4, "ESTABLISHED STATE" ACK handling.
    let mut dup_ack = false;
    let mut snd_una_advanced_to: Option<u32> = None;
    let mut rtt_sample_taken = false;
    let mut writable_hysteresis_fired = false;
    if seq_lt(conn.snd_una, seg.ack) && seq_le(seg.ack, conn.snd_nxt) {
        let acked = seg.ack.wrapping_sub(conn.snd_una) as usize;
        for _ in 0..acked.min(conn.snd.pending.len()) {
            conn.snd.pending.pop_front();
        }
        conn.snd_una = seg.ack;
        snd_una_advanced_to = Some(conn.snd_una);

        // A5 RTT sampling (spec §3.2 + RFC 6298 §3 Karn's). TS source is
        // preferred; Karn's fallback only when the front entry was sent
        // exactly once AND the ACK covers it end-to-end.
        let now_us = (crate::clock::now_ns() / 1_000) as u32;
        let ts_sample: Option<u32> = if conn.ts_enabled {
            parsed_opts.timestamps.and_then(|(_tsval, tsecr)| {
                if tsecr == 0 {
                    return None;
                }
                let rtt = now_us.wrapping_sub(tsecr);
                // Sanity: 1 ≤ rtt < 60s (wrap produces unboundedly large values).
                if (1..60_000_000).contains(&rtt) {
                    Some(rtt)
                } else {
                    None
                }
            })
        } else {
            None
        };
        if let Some(rtt) = ts_sample {
            conn.rtt_est.sample(rtt);
            conn.rack.update_min_rtt(rtt);
            rtt_sample_taken = true;
            // A5.5 Task 11: RTT sample absorbed → reset TLP budget + set
            // sample-seen (satisfies RFC 8985 §7.4 gate).
            conn.on_rtt_sample_tlp_hook();
            // A6 Task 15 (spec §3.8): per-conn RTT histogram update. Slow-path
            // at sample cadence (not per-segment). 15-comparison ladder
            // + one wrapping_add on cache-resident state.
            conn.rtt_histogram.update(rtt, rtt_histogram_edges);
        } else if let Some(front) = conn.snd_retrans.front() {
            let front_end = front.seq.wrapping_add(front.len as u32);
            if front.xmit_count == 1 && seq_le(front_end, conn.snd_una) {
                let rtt = now_us.wrapping_sub((front.first_tx_ts_ns / 1_000) as u32);
                if (1..60_000_000).contains(&rtt) {
                    conn.rtt_est.sample(rtt);
                    conn.rack.update_min_rtt(rtt);
                    rtt_sample_taken = true;
                    // A5.5 Task 11: same hook on the Karn's-fallback branch.
                    conn.on_rtt_sample_tlp_hook();
                    // A6 Task 15 (spec §3.8): per-conn RTT histogram update.
                    // Same cost + rationale as the timestamp-path branch above.
                    conn.rtt_histogram.update(rtt, rtt_histogram_edges);
                }
            }
        }
        if !rtt_sample_taken {
            // A5.5 Task 11: new-data cum-ACK without an RTT sample → still
            // reset the TLP budget; do NOT flip sample-seen (that remains
            // gated on an actual RTT sample).
            conn.on_new_data_ack_tlp_hook();
        }

        if conn.sack_enabled {
            conn.sack_scoreboard.prune_below(conn.snd_una);
        }
        // Update send window. Only accept advances from newer segments
        // per RFC 9293 §3.10.7.4 "SND.WL1 / SND.WL2" rules.
        if seq_lt(conn.snd_wl1, seg.seq)
            || (conn.snd_wl1 == seg.seq && seq_le(conn.snd_wl2, seg.ack))
        {
            // F-2 RFC 7323 §2.3: on non-SYN segments the receiver MUST
            // left-shift SEG.WND by Snd.Wind.Shift bits before updating
            // SND.WND. `ws_shift_in` is bounded at 14 (F-1), so wrapping_shl
            // is safe and deterministic.
            conn.snd_wnd = (seg.window as u32).wrapping_shl(conn.ws_shift_in as u32);
            conn.snd_wl1 = seg.seq;
            conn.snd_wl2 = seg.ack;
        }

        // A6 Task 16 (spec §3.3): WRITABLE hysteresis. If a prior
        // `send_bytes` refused bytes (`send_refused_pending` latched by
        // the engine on short accept — Task 12), and this ACK's advance
        // drained the in-flight window to ≤ `send_buffer_bytes / 2`,
        // fire a single WRITABLE event by flipping the Outcome flag and
        // clearing the pending bit. Level-triggered, one-shot per
        // refusal cycle — a subsequent refusal restarts the cycle via
        // `send_bytes` re-setting `send_refused_pending`. Placed after
        // the `snd.una` advance so `in_flight` (= snd_nxt - snd_una)
        // reflects the post-ACK window; the `/2` half-drain threshold
        // matches the spec §3.3 hysteresis gate. `snd_retrans` pruning
        // runs engine-side post-dispatch (Task 11) but does not affect
        // this seq-arithmetic accounting.
        if conn.send_refused_pending {
            let in_flight = conn.snd_nxt.wrapping_sub(conn.snd_una);
            let threshold = send_buffer_bytes / 2;
            if in_flight <= threshold {
                conn.send_refused_pending = false;
                writable_hysteresis_fired = true;
            }
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
        // RFC 5681 §2 strict duplicate-ACK: all 5 conditions must hold.
        // A4 used a loose `ack <= snd_una` test; A5 Task 23 tightens to
        // spec so diagnostic `tcp.rx_dup_ack` only fires on real dup ACKs.
        //   c1: seg.ack == snd.una    (ACK of largest seen ACK)
        //   c2: seg.payload.is_empty() (no data)
        //   c3: seg.window unchanged   (no window update)
        //   c4: snd.una != snd.nxt     (outstanding data)
        //   c5: SYN and FIN flags both off (RFC 5681 §2 (c))
        //
        // c3 window comparison: on-wire `seg.window` is pre-scale (u16);
        // `conn.snd_wnd` is post-scale (u32). Right-shift snd_wnd back by
        // `ws_shift_in` to compare against the u16 on-wire value. When
        // ws_shift_in == 0 this reduces to plain u16 equality.
        let c1 = seg.ack == conn.snd_una;
        let c2 = seg.payload.is_empty();
        let c3 = (seg.window as u32) == (conn.snd_wnd >> conn.ws_shift_in);
        let c4 = conn.snd_una != conn.snd_nxt;
        let c5 = (seg.flags & (TCP_SYN | TCP_FIN)) == 0;
        dup_ack = c1 && c2 && c3 && c4 && c5;
    }

    // A5 Task 15: RACK detect-lost pass (RFC 8985 §6.2).
    //
    // Pre-reqs: `conn.snd_retrans` entries have had `sacked` flags set
    // from this segment's SACK blocks above, and `conn.snd_una` has
    // advanced for the cumulative-ACKed portion. (Entry pruning below
    // `snd_una` runs later in the engine; we still detect lost entries
    // that lie above `snd_una` — the intended RACK scope.)
    //
    // Runs regardless of whether this ACK advanced `snd_una` — a
    // SACK-only ACK with no cumulative advance can still trigger RACK.
    let mut rack_lost_indexes: Vec<u16> = Vec::new();
    if !conn.snd_retrans.is_empty() {
        let now_ns = crate::clock::now_ns();
        // Update RACK state from newly-acked-or-sacked entries.
        // `update_on_ack` is newest-wins, so iteration order doesn't matter.
        for e_ in conn.snd_retrans.iter_for_rack() {
            let end_seq = e_.seq.wrapping_add(e_.len as u32);
            let cum_acked = seq_le(end_seq, conn.snd_una);
            if e_.sacked || cum_acked {
                conn.rack.update_on_ack(e_.xmit_ts_ns, end_seq);
            }
        }
        // Compute reo_wnd from current conn state. `conn.rack.min_rtt_us`
        // is wired by the RTT sampling block above (TS-source + Karn's
        // fallback); until the first sample lands, `compute_reo_wnd_us`
        // tolerates a zero min_rtt via the 1ms floor.
        let reo_wnd_us = crate::tcp_rack::compute_reo_wnd_us(
            conn.rack_aggressive,
            conn.rack.min_rtt_us,
            conn.rtt_est.srtt_us(),
        );
        conn.rack.reo_wnd_us = reo_wnd_us;
        // Walk entries for loss detection. Collect indexes first, then
        // mark lost=true in a second pass to keep the iter-immutable.
        // RFC 8985 §6.2 runs only over packets not yet acknowledged; we
        // skip sacked/already-lost AND cum-ACKed entries (the engine's
        // prune_below runs after dispatch — cum-ACKed entries are
        // transiently visible here and we must not flag them lost since
        // the index would become stale after the prune shifts the deque).
        for (i, e_) in conn.snd_retrans.entries.iter().enumerate() {
            if e_.sacked || e_.lost {
                continue;
            }
            let end_seq = e_.seq.wrapping_add(e_.len as u32);
            if seq_le(end_seq, conn.snd_una) {
                continue;
            }
            if conn
                .rack
                .detect_lost(e_.xmit_ts_ns, end_seq, now_ns, reo_wnd_us)
            {
                rack_lost_indexes.push(i as u16);
            }
        }
        for i in &rack_lost_indexes {
            conn.snd_retrans.entries[*i as usize].lost = true;
        }
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
                // F-8 RFC 2018 §4 MUST-26: record the seq range that
                // triggered this OOO-insert so `build_ack_outcome` emits
                // it as the first SACK block. `emit_ack` clears the
                // trigger after consuming it.
                if outcome.newly_buffered > 0 {
                    conn.last_sack_trigger = Some((seg.seq, seg.seq.wrapping_add(take)));
                }
            } else {
                buf_full_drop = seg.payload.len() as u32;
            }
        }
        // else: seg.seq < conn.rcv_nxt — duplicate/old payload; drop silently.
    }

    // FIN processing: consumes one seq and moves us to CLOSE_WAIT.
    let mut new_state = None;
    if (seg.flags & TCP_FIN) != 0 && seg.seq.wrapping_add(seg.payload.len() as u32) == conn.rcv_nxt
    {
        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
        new_state = Some(TcpState::CloseWait);
    }

    // Emit ACK whenever we advance rcv_nxt, take a FIN, or saw any
    // in-window payload (in-order → confirms; OOO → dup-ACK signals
    // expected seq per RFC 9293 §3.10.7.4 / RFC 5681 §4.2). Pure-ack
    // segments that only advanced snd_una need no response.
    let tx = if delivered > 0 || new_state == Some(TcpState::CloseWait) || !seg.payload.is_empty() {
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
        snd_una_advanced_to,
        rtt_sample_taken,
        rack_lost_indexes,
        rx_dsack_count,
        tx_tlp_spurious_count,
        ts_recent_expired,
        writable_hysteresis_fired,
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
        return Outcome {
            tx: TxAction::Ack,
            ..Outcome::base()
        };
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
        return Outcome {
            tx: TxAction::Ack,
            bad_seq: true,
            ..Outcome::base()
        };
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
    Outcome {
        tx,
        new_state,
        closed,
        ..Outcome::base()
    }
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

    // A6 Task 15: default RTT histogram edges for tests that drive
    // `dispatch` directly. Matches the engine-side defaults so tests
    // exercise the same bucketing the runtime uses.
    const TEST_EDGES: [u32; 15] = crate::engine::DEFAULT_RTT_HISTOGRAM_EDGES_US;

    // A6 Task 16: default send-buffer capacity for tests that drive
    // `dispatch` directly. Matches `EngineConfig::send_buffer_bytes`'s
    // 256 KiB default so the WRITABLE hysteresis threshold sits far
    // above any in-flight value the existing tests produce (none of
    // these tests exercise the hysteresis path — dedicated tests land
    // in Task 21's integration suite).
    const TEST_SEND_BUF_BYTES: u32 = 256 * 1024;

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
                mss,
                ..Default::default()
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

        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 5000,
            ack: 1001,
            flags: TCP_SYN | TCP_ACK,
            window: 65535,
            header_len: 20 + opts_len,
            payload: &[],
            options: &opts_buf[..opts_len],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
    fn handle_syn_sent_wires_maybe_seed_srtt_from_syn() {
        // A5.5 Task 13 wiring gate: the 4 unit tests on
        // `TcpConn::maybe_seed_srtt_from_syn` only exercise the helper in
        // isolation. This test drives the real `handle_syn_sent` code path
        // with a valid SYN-ACK and asserts the helper actually got invoked
        // — catches a future refactor that drops the call site.
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_options::TcpOpts;

        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        // Arrange: pre-stamp `syn_tx_ts_ns` to `now - 10ms` so the RTT
        // sample computed inside `handle_syn_sent` (via `clock::now_ns()`)
        // lands squarely inside the `[1µs, 60s)` acceptance window.
        // `syn_retrans_count == 0` per `new_client` default — Karn's guard
        // won't block us.
        let ten_ms_ns: u64 = 10_000_000;
        c.syn_tx_ts_ns = crate::clock::now_ns().saturating_sub(ten_ms_ns);
        assert_eq!(c.syn_retrans_count, 0, "pre: Karn's guard must not apply");
        assert!(c.rtt_est.srtt_us().is_none(), "pre: no RTT sample yet");
        assert_eq!(c.rack.min_rtt_us, 0, "pre: no min_rtt yet");

        // Build a valid SYN-ACK matching this conn.
        let mut peer_opts = TcpOpts::default();
        peer_opts.mss = Some(1400);
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).unwrap();
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5000,
            ack: 1001,
            flags: TCP_SYN | TCP_ACK,
            window: 65535,
            header_len: 20 + opts_len,
            payload: &[],
            options: &opts_buf[..opts_len],
        };

        // Act: drive the full dispatcher so we exercise the real call
        // site inside `handle_syn_sent`.
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);

        // Assert: SYN-ACK was accepted AND the helper got invoked.
        assert_eq!(out.new_state, Some(TcpState::Established));
        assert!(
            c.rtt_est.srtt_us().is_some(),
            "handle_syn_sent must call maybe_seed_srtt_from_syn on SYN-ACK"
        );
        assert!(
            c.rack.min_rtt_us > 0,
            "maybe_seed_srtt_from_syn must bump rack.min_rtt_us"
        );
    }

    #[test]
    fn syn_sent_peer_without_wscale_zeroes_both_shifts() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_options::TcpOpts;

        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        c.ws_shift_out = 7;

        let mut peer_opts = TcpOpts::default();
        peer_opts.mss = Some(1400);
        peer_opts.timestamps = Some((1, 2));
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5000,
            ack: 1001,
            flags: TCP_SYN | TCP_ACK,
            window: 65535,
            header_len: 20 + opts_len,
            payload: &[],
            options: &opts_buf[..opts_len],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.new_state, Some(TcpState::Established));
        // RFC 7323 §1.3: WS only active if both sides advertise.
        assert_eq!(c.ws_shift_in, 0);
        assert_eq!(c.ws_shift_out, 0);
    }

    #[test]
    fn syn_ack_window_is_not_ws_scaled_per_rfc7323_2_2() {
        // F-3 RFC 7323 §2.2: SYN/SYN-ACK window fields MUST NOT be scaled.
        // Peer advertises WS=7 and window=65535; we must interpret snd_wnd
        // as 65535, not 65535<<7.
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_options::TcpOpts;

        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        c.ws_shift_out = 7;

        let mut peer_opts = TcpOpts::default();
        peer_opts.mss = Some(1400);
        peer_opts.wscale = Some(7);
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5000,
            ack: 1001,
            flags: TCP_SYN | TCP_ACK,
            window: 65535,
            header_len: 20 + opts_len,
            payload: &[],
            options: &opts_buf[..opts_len],
        };
        let _out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(c.snd_wnd, 65535, "SYN-ACK window must be unscaled");
        assert_eq!(c.ws_shift_in, 7, "peer's WS is recorded for post-handshake");
    }

    #[test]
    fn syn_ack_ws_shift_clamped_at_14_per_rfc7323_2_3() {
        // F-1 RFC 7323 §2.3: peer's shift.cnt > 14 MUST be clamped to 14.
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_options::TcpOpts;

        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);

        let mut peer_opts = TcpOpts::default();
        peer_opts.wscale = Some(20); // illegal; must clamp to 14
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5000,
            ack: 1001,
            flags: TCP_SYN | TCP_ACK,
            window: 65535,
            header_len: 20 + opts_len,
            payload: &[],
            options: &opts_buf[..opts_len],
        };
        let _out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(
            c.ws_shift_in, 14,
            "peer's WS shift MUST be clamped at 14 per RFC 7323 §2.3"
        );
    }

    #[test]
    fn established_post_handshake_snd_wnd_is_ws_scaled_per_rfc7323_2_3() {
        // F-2 RFC 7323 §2.3: on post-handshake segments, receiver MUST
        // left-shift SEG.WND by `ws_shift_in` before storing into SND.WND.
        let mut c = est_conn(1000, 5000, 1024);
        c.ws_shift_in = 7;
        // Simulate 5 bytes in flight.
        c.snd.push(b"hello");
        c.snd_nxt = c.snd_una.wrapping_add(5);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1006,
            flags: TCP_ACK,
            window: 512, // scaled form; peer means 512 << 7 = 65_536
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let _ = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(
            c.snd_wnd,
            512u32 << 7,
            "snd_wnd must be left-shifted by ws_shift_in"
        );
    }

    #[test]
    fn syn_sent_plain_ack_wrong_seq_sends_rst() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;

        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        // Bogus: ACK-only with an ack that doesn't cover our SYN.
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5000,
            ack: 999,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.tx, TxAction::RstForSynSentBadAck);
    }

    #[test]
    fn syn_sent_rst_matching_our_ack_closes() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;

        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 0,
            ack: 1001,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
        assert_eq!(out.tx, TxAction::None);
    }

    fn est_conn(iss: u32, irs: u32, peer_wnd: u16) -> crate::tcp_conn::TcpConn {
        use crate::flow_table::FourTuple;
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c =
            crate::tcp_conn::TcpConn::new_client(t, iss, 1460, 1024, 2048, 5000, 5000, 1_000_000);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload,
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 5100,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: b"xyz",
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 0);
        assert_eq!(out.reassembly_queued_bytes, 3);
        assert_eq!(c.rcv_nxt, 5001);
        assert_eq!(c.recv.reorder.len(), 1);
        assert_eq!(&c.recv.reorder.segments()[0].payload, b"xyz");
        // F-8 RFC 2018 §4 MUST-26: triggering OOO range recorded for
        // the upcoming ACK's first SACK block.
        assert_eq!(c.last_sack_trigger, Some((5100, 5103)));
    }

    #[test]
    fn inorder_arrival_closes_hole_and_drains_reassembly() {
        let mut c = est_conn(1000, 5000, 1024);
        c.rcv_wnd = 4096;
        let ooo = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5010,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: b"world",
            options: &[],
        };
        let out_ooo = dispatch(&mut c, &ooo, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out_ooo.reassembly_queued_bytes, 5);
        assert_eq!(c.rcv_nxt, 5001);

        let inorder = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload: b"ninebytes",
            options: &[],
        };
        let out_in = dispatch(&mut c, &inorder, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload: b"abc",
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.delivered, 3);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload: &payload,
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        // 1024 accepted, 976 dropped — overflow is `buf_full_drop`, not OOO.
        assert_eq!(out.delivered, 1024);
        assert_eq!(out.buf_full_drop, 2000 - 1024);
    }

    #[test]
    fn established_ack_field_advances_snd_una() {
        let mut c = est_conn(1000, 5000, 1024);
        // Simulate 5 bytes in flight: push to snd.pending and advance snd_nxt.
        c.snd.push(b"hello");
        c.snd_nxt = c.snd_una.wrapping_add(5);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1006, // acks 5 bytes
            flags: TCP_ACK,
            window: 32000,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let _ = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(c.snd_una, 1006);
        assert_eq!(c.snd_wnd, 32000);
        assert_eq!(c.snd.pending.len(), 0);
    }

    #[test]
    fn established_fin_transitions_to_close_wait() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.new_state, Some(TcpState::CloseWait));
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(c.rcv_nxt, 5002); // FIN consumes one seq
    }

    #[test]
    fn established_rst_closes_immediately() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
    }

    #[test]
    fn established_rst_outcome_carries_rst_cause() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::FinWait1;
        c.snd_una = 1001;
        c.snd_nxt = 1002; // after our FIN
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1002, // acks our FIN
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.new_state, Some(TcpState::FinWait2));
    }

    #[test]
    fn fin_wait2_peer_fin_transitions_to_time_wait() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::FinWait2;
        c.snd_una = 1002;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1002,
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.new_state, Some(TcpState::TimeWait));
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(c.rcv_nxt, 5002);
    }

    #[test]
    fn fin_wait1_peer_fin_without_ack_of_our_fin_transitions_to_closing() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::FinWait1;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001, // does NOT ack our FIN
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.new_state, Some(TcpState::Closing));
    }

    #[test]
    fn closing_ack_of_our_fin_transitions_to_time_wait() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::Closing;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5002; // peer's FIN already consumed
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5002,
            ack: 1002,
            flags: TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.new_state, Some(TcpState::TimeWait));
    }

    #[test]
    fn last_ack_ack_of_our_fin_closes_connection() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::LastAck;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5002;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5002,
            ack: 1002,
            flags: TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20 + n,
            payload: b"xxx",
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20 + n,
            payload: b"hello",
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(!out.paws_rejected);
        assert_eq!(out.delivered, 5);
        assert_eq!(c.ts_recent, 300);
    }

    #[test]
    fn missing_ts_on_ts_enabled_conn_bumps_bad_option_and_drops() {
        let mut c = est_conn_ts(1000, 5000, 1024, 200);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload: b"x",
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
        peer_opts.push_sack_block(SackBlock {
            left: 1005,
            right: 1010,
        });
        peer_opts.push_sack_block(SackBlock {
            left: 1015,
            right: 1020,
        });
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1003,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20 + n,
            payload: &[],
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
        c.sack_scoreboard.insert(SackBlock {
            left: 1005,
            right: 1010,
        });
        c.sack_scoreboard.insert(SackBlock {
            left: 1020,
            right: 1030,
        });
        c.snd.push(&[0u8; 30]);
        c.snd_nxt = c.snd_una.wrapping_add(30);

        let peer_opts = TcpOpts::default();
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1015,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20 + n,
            payload: &[],
            options: &buf[..n],
        };
        let _ = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(c.snd_una, 1015);
        assert_eq!(c.sack_scoreboard.len(), 1);
        assert_eq!(c.sack_scoreboard.blocks()[0].left, 1020);
    }

    // A5 Task 16: RFC 2883 DSACK detection. Visibility only — no behavior
    // change; the block is skipped from the scoreboard and counted.

    #[test]
    fn is_dsack_below_snd_una() {
        // Condition (a): block.right <= snd_una — the peer is reporting a
        // range the cumulative ACK has already covered.
        let scoreboard = crate::tcp_sack::SackScoreboard::new();
        assert!(super::is_dsack(
            &crate::tcp_options::SackBlock {
                left: 150,
                right: 180
            },
            200,
            &scoreboard
        ));
        // Equality at the right edge (RFC 2883 "S2 ≤ cumulative ACK"):
        // block.right == snd_una still qualifies.
        assert!(super::is_dsack(
            &crate::tcp_options::SackBlock {
                left: 150,
                right: 200
            },
            200,
            &scoreboard
        ));
    }

    #[test]
    fn is_dsack_covered_by_existing_scoreboard_block() {
        // Condition (b): block is fully enclosed by an existing scoreboard
        // entry — the peer is re-reporting an already-SACKed range.
        let mut scoreboard = crate::tcp_sack::SackScoreboard::new();
        scoreboard.insert(crate::tcp_options::SackBlock {
            left: 100,
            right: 200,
        });
        assert!(super::is_dsack(
            &crate::tcp_options::SackBlock {
                left: 120,
                right: 180
            },
            50, // snd_una far below; not the deciding condition
            &scoreboard
        ));
        // Exact equal-bounds also "fully covered".
        assert!(super::is_dsack(
            &crate::tcp_options::SackBlock {
                left: 100,
                right: 200
            },
            50,
            &scoreboard
        ));
    }

    #[test]
    fn is_dsack_rejects_block_reporting_new_data() {
        // Block above snd_una and not covered by any existing scoreboard
        // block → not DSACK, legitimate new SACK.
        let scoreboard = crate::tcp_sack::SackScoreboard::new();
        assert!(!super::is_dsack(
            &crate::tcp_options::SackBlock {
                left: 500,
                right: 600
            },
            300,
            &scoreboard
        ));
    }

    #[test]
    fn is_dsack_rejects_partial_overlap_with_existing() {
        // Block overlaps but is NOT fully covered by the existing entry —
        // the peer is reporting a SACK that extends what we knew. Not DSACK.
        let mut scoreboard = crate::tcp_sack::SackScoreboard::new();
        scoreboard.insert(crate::tcp_options::SackBlock {
            left: 100,
            right: 200,
        });
        assert!(!super::is_dsack(
            &crate::tcp_options::SackBlock {
                left: 150,
                right: 250
            },
            50,
            &scoreboard
        ));
    }

    #[test]
    fn established_dsack_below_snd_una_counted_and_skipped() {
        use crate::tcp_options::{SackBlock, TcpOpts};
        // est_conn: snd_una = 1001. SACK decode runs BEFORE the ACK
        // processing advances snd_una, so the DSACK check sees the
        // pre-advance snd_una (1001). Block (995, 1000) has right <=
        // snd_una → DSACK (a).
        let mut c = est_conn(1000, 5000, 1024);
        c.sack_enabled = true;
        c.snd.push(&[0u8; 30]);
        c.snd_nxt = c.snd_una.wrapping_add(30);
        let mut peer_opts = TcpOpts::default();
        peer_opts.push_sack_block(SackBlock {
            left: 995,
            right: 1000,
        });
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20 + n,
            payload: &[],
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.rx_dsack_count, 1);
        assert_eq!(out.sack_blocks_decoded, 1);
        // DSACK block was skipped — scoreboard remains empty, no
        // snd_retrans entry got marked sacked.
        assert_eq!(c.sack_scoreboard.len(), 0);
        assert!(c.rack.dsack_seen);
    }

    #[test]
    fn established_dsack_covered_by_existing_counted_and_skipped() {
        use crate::tcp_options::{SackBlock, TcpOpts};
        let mut c = est_conn(1000, 5000, 1024);
        c.sack_enabled = true;
        c.snd.push(&[0u8; 30]);
        c.snd_nxt = c.snd_una.wrapping_add(30);
        // Pre-seed the scoreboard with (1010, 1020); a re-report of
        // (1012, 1018) is DSACK (b): fully covered by an existing block.
        c.sack_scoreboard.insert(SackBlock {
            left: 1010,
            right: 1020,
        });
        let mut peer_opts = TcpOpts::default();
        peer_opts.push_sack_block(SackBlock {
            left: 1012,
            right: 1018,
        });
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20 + n,
            payload: &[],
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.rx_dsack_count, 1);
        assert!(c.rack.dsack_seen);
        // Scoreboard unchanged — the DSACK block was skipped, original
        // (1010, 1020) remains.
        assert_eq!(c.sack_scoreboard.len(), 1);
        assert_eq!(c.sack_scoreboard.blocks()[0].left, 1010);
        assert_eq!(c.sack_scoreboard.blocks()[0].right, 1020);
    }

    #[test]
    fn established_mixed_dsack_plus_live_sack_handled_separately() {
        use crate::tcp_options::{SackBlock, TcpOpts};
        let mut c = est_conn(1000, 5000, 1024);
        c.sack_enabled = true;
        c.snd.push(&[0u8; 40]);
        c.snd_nxt = c.snd_una.wrapping_add(40);
        // SACK decode runs pre-ACK-advance, so snd_una here is 1001.
        // First block (990, 1000) has right <= 1001 → DSACK. Second
        // block (1015, 1020) is live SACK → inserted into the scoreboard.
        let mut peer_opts = TcpOpts::default();
        peer_opts.push_sack_block(SackBlock {
            left: 990,
            right: 1000,
        });
        peer_opts.push_sack_block(SackBlock {
            left: 1015,
            right: 1020,
        });
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1005,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20 + n,
            payload: &[],
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.rx_dsack_count, 1);
        assert_eq!(out.sack_blocks_decoded, 2);
        assert!(c.rack.dsack_seen);
        // Only the live SACK block entered the scoreboard.
        assert_eq!(c.sack_scoreboard.len(), 1);
        assert_eq!(c.sack_scoreboard.blocks()[0].left, 1015);
    }

    #[test]
    fn time_wait_replays_ack_on_any_segment() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        c.state = TcpState::TimeWait;
        c.our_fin_seq = Some(1001);
        c.rcv_nxt = 5002;
        c.rcv_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1002,
            flags: TCP_ACK | TCP_FIN,
            window: 0,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.new_state, None); // stay in TIME_WAIT until reaper
    }

    // A4 Task 19: cross-phase backfill flags on `Outcome`.

    #[test]
    fn established_urg_flag_drops_and_sets_urgent_dropped() {
        use crate::tcp_output::TCP_URG;
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_URG,
            window: 65535,
            header_len: 20,
            payload: b"x",
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 9999,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: b"xxx",
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(out.bad_seq);
        assert_eq!(out.tx, TxAction::Ack); // challenge ACK
        assert_eq!(out.delivered, 0);
    }

    #[test]
    fn established_ack_ahead_of_snd_nxt_sets_bad_ack() {
        let mut c = est_conn(1000, 5000, 1024);
        // snd_nxt=1001 (1000+1 for SYN). Ack a future byte.
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 9999,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(out.bad_ack);
        assert_eq!(out.tx, TxAction::Ack); // challenge ACK
    }

    #[test]
    fn established_duplicate_ack_sets_dup_ack() {
        let mut c = est_conn(1000, 5000, 1024);
        // RFC 5681 §2 strict dup_ack — all 5 conditions must hold.
        // Advance snd_nxt so there is outstanding data (c4), and pick a
        // segment whose window matches the current snd_wnd (c3).
        c.snd_nxt = c.snd_una.wrapping_add(100);
        c.snd_wnd = 65535;
        c.ws_shift_in = 0;
        // ack == snd_una (c1), empty payload (c2), window == snd_wnd (c3),
        // snd_una != snd_nxt (c4), state Established (c5) → dup_ack.
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(out.dup_ack);
    }

    #[test]
    fn dup_ack_ignored_when_seg_has_data() {
        // c2 violated: payload non-empty.
        let mut c = est_conn(1000, 5000, 1024);
        c.snd_nxt = c.snd_una.wrapping_add(100);
        c.snd_wnd = 65535;
        c.ws_shift_in = 0;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: b"xxx",
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(!out.dup_ack);
    }

    #[test]
    fn dup_ack_ignored_when_seg_updates_window() {
        // c3 violated: seg.window differs from conn.snd_wnd (no-shift).
        let mut c = est_conn(1000, 5000, 1024);
        c.snd_nxt = c.snd_una.wrapping_add(100);
        c.snd_wnd = 65535;
        c.ws_shift_in = 0;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 30000,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(!out.dup_ack);
    }

    #[test]
    fn dup_ack_ignored_when_no_outstanding_data() {
        // c4 violated: snd_una == snd_nxt (nothing in flight).
        let mut c = est_conn(1000, 5000, 1024);
        // est_conn already sets snd_una == snd_nxt == 1001.
        c.snd_wnd = 65535;
        c.ws_shift_in = 0;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(!out.dup_ack);
    }

    #[test]
    fn dup_ack_set_when_all_five_conditions_hold_with_ws_shift() {
        // Parallel to `established_duplicate_ack_sets_dup_ack`, but with a
        // non-zero ws_shift_in to exercise the right-shift in c3.
        let mut c = est_conn(1000, 5000, 1024);
        c.snd_nxt = c.snd_una.wrapping_add(100);
        c.ws_shift_in = 4;
        // snd_wnd is post-scale; pick a value evenly divisible by 1<<4 so
        // (snd_wnd >> 4) round-trips back to a u16 on-wire value.
        c.snd_wnd = 65535u32 << 4; // 0x000F_FFF0
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535, // matches snd_wnd >> 4
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(out.dup_ack);
    }

    #[test]
    fn dup_ack_ignored_when_fin_flag_set() {
        // c5 violated: FIN flag set. All other conditions (c1-c4) hold,
        // so a correct RFC 5681 §2 (c) implementation must NOT classify
        // this segment as a duplicate ACK.
        let mut c = est_conn(1000, 5000, 1024);
        c.snd_nxt = c.snd_una.wrapping_add(100);
        c.snd_wnd = 65535;
        c.ws_shift_in = 0;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(!out.dup_ack);
    }

    #[test]
    fn dup_ack_ignored_when_syn_flag_set() {
        // c5 violated: SYN flag set. Mirrors the FIN case — RFC 5681 §2 (c)
        // requires both SYN and FIN bits off for a segment to be a dup_ack.
        let mut c = est_conn(1000, 5000, 1024);
        c.snd_nxt = c.snd_una.wrapping_add(100);
        c.snd_wnd = 65535;
        c.ws_shift_in = 0;
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK | TCP_SYN,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(!out.dup_ack);
    }

    #[test]
    fn established_zero_window_segment_sets_rx_zero_window() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(out.rx_zero_window);
    }

    #[test]
    fn established_nonzero_window_does_not_set_rx_zero_window() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 1,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(!out.rx_zero_window);
    }

    #[test]
    fn close_path_out_of_window_sets_bad_seq() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048, 5000, 5000, 1_000_000);
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
            src_port: 5000,
            dst_port: 40000,
            seq: 99999,
            ack: 1002,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: b"x",
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
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

    #[test]
    fn outcome_snd_una_advanced_to_field_defaults() {
        let o = Outcome::base();
        assert!(o.snd_una_advanced_to.is_none());
        assert!(!o.rtt_sample_taken);
    }

    #[test]
    fn outcome_rack_lost_indexes_defaults_empty() {
        let o = Outcome::base();
        assert!(o.rack_lost_indexes.is_empty());
    }

    // A5 Task 15: a RACK detect-lost pass runs inside handle_established.
    // Construct a conn with two in-flight entries: A (older xmit) and B
    // (newer xmit, SACKed by the incoming ACK). After the ACK, A's
    // xmit_ts is older than RACK.xmit_ts + age exceeds reo_wnd, so it's
    // marked lost and its index is surfaced via Outcome.rack_lost_indexes.
    #[test]
    fn rack_detects_older_entry_as_lost_when_newer_sacked_and_beyond_reo_wnd() {
        use crate::mempool::Mbuf;
        use crate::tcp_retrans::RetransEntry;
        let mut c = est_conn(1000, 5000, 1024);
        c.sack_enabled = true;
        // Bump snd_nxt so both entries sit within (snd_una, snd_nxt].
        c.snd_nxt = 2000;
        // A: seq=1001, len=50, xmit_ts very old.
        c.snd_retrans.push_after_tx(RetransEntry {
            seq: 1001,
            len: 50,
            mbuf: Mbuf::null_for_test(),
            first_tx_ts_ns: 0,
            xmit_count: 1,
            sacked: false,
            lost: false,
            xmit_ts_ns: 0,
        });
        // B: seq=1051, len=50, xmit_ts = now (much later than A).
        let now_ns = crate::clock::now_ns();
        c.snd_retrans.push_after_tx(RetransEntry {
            seq: 1051,
            len: 50,
            mbuf: Mbuf::null_for_test(),
            first_tx_ts_ns: now_ns,
            xmit_count: 1,
            sacked: false,
            lost: false,
            xmit_ts_ns: now_ns,
        });
        // Build an ACK segment carrying a SACK block covering B (1051..1101).
        // `parse_options` expects the raw options bytes; construct them
        // directly: SACK option kind=5, len=2+8=10, one block big-endian.
        let mut opts = Vec::new();
        opts.push(5u8); // kind
        opts.push(10u8); // len
        opts.extend_from_slice(&1051u32.to_be_bytes());
        opts.extend_from_slice(&1101u32.to_be_bytes());
        // Pad to 4-byte boundary with NOPs.
        while opts.len() % 4 != 0 {
            opts.push(1u8); // NOP
        }
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001, // cumulative-ack unchanged (dup-ACK path)
            flags: TCP_ACK,
            window: 65535,
            header_len: 20 + opts.len(),
            payload: &[],
            options: &opts,
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        // A (index 0) should be marked lost; B (index 1) is SACKed.
        assert!(
            out.rack_lost_indexes.contains(&0),
            "entry A (older xmit) should be RACK-lost, got {:?}",
            out.rack_lost_indexes
        );
        assert!(c.snd_retrans.entries[0].lost);
        assert!(c.snd_retrans.entries[1].sacked);
    }

    // Empty snd_retrans → RACK pass is a no-op, rack_lost_indexes stays empty.
    #[test]
    fn rack_pass_noop_when_no_inflight_segments() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000,
            dst_port: 40000,
            seq: 5001,
            ack: 1001,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[],
            options: &[],
        };
        let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES);
        assert!(out.rack_lost_indexes.is_empty());
    }
}
