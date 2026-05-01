//! A10 Plan B Task 9 — pcap divergence-normalisation for mode B.
//!
//! Mode B (spec §8) verifies that dpdk_net with `preset=rfc_compliance`
//! emits byte-identical wire traffic to Linux TCP with defaults, given
//! the same workload. Two free values diverge by design and must be
//! rewritten before a byte-diff can succeed:
//!
//! 1. **Initial sequence number (ISS).** RFC 6528 host-chosen; both
//!    stacks pick their own random ISS per direction. We pin each
//!    direction to a canonical ISS so downstream seq / ack numbers
//!    fall into a known range.
//! 2. **TCP Timestamp base (TSval).** RFC 7323 makes TSval a free-
//!    running clock starting at any host-chosen offset. Both stacks
//!    pick independently. We pin each direction's observed base
//!    TSval (the first TSval seen on that direction) to a canonical
//!    value; TSecr mirrors the peer's base.
//! 3. **MAC addresses.** Capture happens on different hosts so the
//!    source MAC of the DUT side vs. the Linux side is physically
//!    different. Normalise both to canonical bytes, direction-aware.
//!
//! Anything else that diverges after this normalisation is an actual
//! wire-behaviour divergence and the byte-diff will flag it.
//!
//! # Scope — packets we canonicalise
//!
//! Only Ethernet / IPv4 / TCP packets with a well-formed header chain
//! are rewritten. Non-IPv4 frames, non-TCP IPv4 datagrams, and packets
//! too short to parse pass through unchanged (their bytes are still
//! included in the diff; they just aren't touched).
//!
//! # Scope — what we do NOT touch
//!
//! - IPv4 Identification field (`ip_id`): not rewritten. Linux uses a
//!   per-destination PRNG; A10 hasn't decided on dpdk_net's ID policy.
//!   Divergence here is expected; operators should explicitly decide
//!   whether to include ip_id in the canonical set (follow-up to T9).
//! - TCP window (`window`): not rewritten. A wire-diff mismatch here
//!   is meaningful (window-scaling divergence) so we preserve it.
//! - TCP MSS option (kind=2): not rewritten. MSS depends on MTU; spec
//!   §8 explicitly documents it as an expected divergence until the
//!   operator pins both stacks to a matching MTU.
//! - Urgent pointer: pass-through.
//! - IP DSCP/ECN: pass-through.
//! - IP flags / fragmentation offset: pass-through (fragmented TCP is
//!   out of scope for the A10 workload).
//! - Pcap timestamps: the pcap record header's `ts_sec` / `ts_frac`
//!   are preserved verbatim. They're wall-clock capture timestamps,
//!   not wire bytes, and the diff operates on wire bytes only.
//!
//! # Direction identification
//!
//! A TCP connection has two directions. We identify each direction by
//! the (src_ip, src_port, dst_ip, dst_port) 4-tuple and build a pair
//! of state slots: one for the lex-smaller side, one for the larger.
//! This lets us consistently assign canonical MACs and pin canonical
//! ISS / TS bases without knowing in advance which host (DUT vs. peer)
//! captured which direction.
//!
//! # Checksum recompute
//!
//! After any rewrite that affects the IPv4 or TCP header, we recompute
//! the IPv4 header checksum and the TCP checksum (which covers the
//! pseudo-header). This means normalised captures are *always* valid
//! wire-format traffic; they're not just memory-diffable blobs.

use std::collections::HashMap;
use std::io::Cursor;
use std::net::Ipv4Addr;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapReader, PcapWriter};

/// Options controlling canonicalisation. All fields have trading-
/// latency-sensible defaults matching the Task 9 plan.
#[derive(Debug, Clone)]
pub struct CanonicalizationOptions {
    /// Fixed ISS replacement for each direction. `(observed_seq -
    /// observed_iss) + canonical_iss` becomes the new seq number.
    pub canonical_iss: u32,
    /// Fixed TSval base replacement. `(observed_tsval -
    /// observed_tsval_base) + canonical_ts_base` becomes the new
    /// TSval. TSecr tracks the peer's base the same way.
    pub canonical_ts_base: u32,
    /// Canonical MAC for the direction whose source IP + port sort
    /// lex-smaller. The reverse direction gets `canonical_dst_mac`.
    pub canonical_src_mac: [u8; 6],
    /// Canonical MAC for the direction whose source IP + port sort
    /// lex-larger.
    pub canonical_dst_mac: [u8; 6],
}

impl Default for CanonicalizationOptions {
    fn default() -> Self {
        Self {
            canonical_iss: 0x1234_5678,
            canonical_ts_base: 0xAABB_CCDD,
            canonical_src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            canonical_dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        }
    }
}

/// Canonicalisation errors. Internal to the normalize module; surface
/// to callers as `anyhow::Error` via `?` in the runner.
#[derive(Debug, thiserror::Error)]
pub enum CanonError {
    #[error("pcap parse error: {0}")]
    Pcap(#[from] pcap_file::PcapError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A SACK option block walker encountered an option whose length
    /// byte is malformed. SACK option bodies (after the 2-byte kind/len
    /// header) are a multiple of 8 bytes (one or more `(left, right)`
    /// 4+4-byte blocks). `len - 2` not divisible by 8 is an on-wire bug.
    #[error("malformed SACK option: body length {body_len} is not a multiple of 8")]
    MalformedSackOption { body_len: usize },
}

/// Parsed Ethernet + IPv4 + TCP offsets and header fields for a single
/// frame. Produced by [`parse_l2l3l4`] and consumed by both the pin-
/// discovery pass and the rewrite pass — sharing the parser eliminates
/// the bounds-check duplication that used to live in each walker.
#[derive(Debug)]
pub(crate) struct FrameOffsets {
    /// Byte offset of the TCP header within the frame.
    pub tcp_off: usize,
    /// Byte length of the TCP header (20..60, always a multiple of 4).
    pub tcp_data_off: usize,
    /// IPv4 source address.
    pub src_ip: Ipv4Addr,
    /// TCP source port.
    pub src_port: u16,
    /// IPv4 destination address.
    pub dst_ip: Ipv4Addr,
    /// TCP destination port.
    pub dst_port: u16,
    /// IPv4 total length in bytes (including IP header).
    pub ip_total_len: usize,
    /// TCP flags byte (at `tcp_off + 13`).
    pub flags: u8,
    /// TCP sequence number.
    pub seq: u32,
    /// TCP acknowledgement number.
    pub ack: u32,
}

/// Shared Ethernet + IPv4 + TCP parser. Returns `Some(FrameOffsets)`
/// when the frame has a well-formed L2/L3/L4 chain, `None` otherwise.
/// Non-IPv4 ethertypes, non-TCP IPv4 payloads, and any bounds-check
/// failure produce `None`; callers skip such frames (pass-1 doesn't
/// pin anything from them, pass-2 leaves them byte-identical).
pub(crate) fn parse_l2l3l4(data: &[u8]) -> Option<FrameOffsets> {
    // 14-byte Ethernet header — anything shorter is a truncated capture.
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    // IPv4 header starts at offset 14.
    if data.len() < 14 + 20 {
        return None;
    }
    let ihl = (data[14] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < 14 + ihl {
        return None;
    }
    let proto = data[14 + 9];
    if proto != IPPROTO_TCP {
        return None;
    }
    let src_ip = Ipv4Addr::new(data[14 + 12], data[14 + 13], data[14 + 14], data[14 + 15]);
    let dst_ip = Ipv4Addr::new(data[14 + 16], data[14 + 17], data[14 + 18], data[14 + 19]);
    let ip_total_len = u16::from_be_bytes([data[14 + 2], data[14 + 3]]) as usize;
    if 14 + ip_total_len > data.len() {
        return None;
    }
    // TCP header at offset 14 + ihl.
    let tcp_off = 14 + ihl;
    if tcp_off + 20 > data.len() {
        return None;
    }
    let src_port = u16::from_be_bytes([data[tcp_off], data[tcp_off + 1]]);
    let dst_port = u16::from_be_bytes([data[tcp_off + 2], data[tcp_off + 3]]);
    let tcp_data_off = ((data[tcp_off + 12] >> 4) & 0x0F) as usize * 4;
    if tcp_data_off < 20 || tcp_off + tcp_data_off > 14 + ip_total_len {
        return None;
    }
    let flags = data[tcp_off + 13];
    let seq = u32::from_be_bytes([
        data[tcp_off + 4],
        data[tcp_off + 5],
        data[tcp_off + 6],
        data[tcp_off + 7],
    ]);
    let ack = u32::from_be_bytes([
        data[tcp_off + 8],
        data[tcp_off + 9],
        data[tcp_off + 10],
        data[tcp_off + 11],
    ]);
    Some(FrameOffsets {
        tcp_off,
        tcp_data_off,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        ip_total_len,
        flags,
        seq,
        ack,
    })
}

/// Rewrite every IPv4 / TCP packet in `pcap_bytes` per `opts`,
/// returning the canonicalised pcap as a `Vec<u8>`. Non-IPv4 or
/// non-TCP packets pass through unchanged.
///
/// The implementation is two-pass: the first pass scans every packet
/// to discover per-direction ISS and TSval-base pins (the first
/// packet seen on that direction), the second pass rewrites using the
/// fully-populated pin table. Two passes are required for mid-stream
/// captures where a direction's first observed packet is an ACK
/// whose ack-number belongs to a direction we haven't seen yet:
/// without pre-scan we'd leave that ACK number unchanged and produce
/// a spurious divergence on byte-diff. Memory cost is bounded by the
/// number of directions in the capture, which is at most 2×(flow
/// count) — small and not a concern for the A10 workload scale.
pub fn canonicalize_pcap(
    pcap_bytes: &[u8],
    opts: &CanonicalizationOptions,
) -> Result<Vec<u8>, CanonError> {
    // Pass 1: discover pins.
    let mut state = FlowState::default();
    {
        let cursor = Cursor::new(pcap_bytes);
        let mut reader = PcapReader::new(cursor)?;
        while let Some(pkt) = reader.next_packet() {
            let pkt = pkt?;
            discover_pins(&pkt.data, &mut state)?;
        }
    }

    // Pass 2: rewrite using the populated pin table.
    let cursor = Cursor::new(pcap_bytes);
    let mut reader = PcapReader::new(cursor)?;
    let in_header: PcapHeader = reader.header();

    let mut out_buf: Vec<u8> = Vec::with_capacity(pcap_bytes.len());
    {
        let mut writer = PcapWriter::with_header(&mut out_buf, in_header)?;
        // Pass-2 replays the connection-instance counter by tracking how
        // many SYNs we've seen on each sorted 4-tuple up to (and
        // including) the current packet — matching the pass-1 walk
        // order so each (tuple, instance) lookup resolves to the same
        // FlowInstance row.
        let mut pass2_instance_counter: HashMap<ConnTuple, u32> = HashMap::new();
        while let Some(pkt) = reader.next_packet() {
            let pkt = pkt?;
            let ts = pkt.timestamp;
            let orig_len = pkt.orig_len;
            let mut data = pkt.data.into_owned();
            rewrite_frame(&mut data, opts, &state, &mut pass2_instance_counter)?;
            let out_pkt = PcapPacket::new_owned(ts, orig_len, data);
            writer.write_packet(&out_pkt)?;
        }
    }
    Ok(out_buf)
}

/// A per-tuple pass-1 final instance-counter readout. `endpoints` is
/// the sorted 4-tuple `(low_ip, low_port, high_ip, high_port)` as
/// pass-1 key-builds it; `final_instance` is the `syn_count[tuple]`
/// value after pass-1 walks the whole capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass1InstanceCount {
    /// Sorted 4-tuple endpoints, lex-smaller endpoint first.
    pub endpoints: (Ipv4Addr, u16, Ipv4Addr, u16),
    /// Final value of `syn_count[tuple]` after pass-1 completes — the
    /// number of distinct SYN openings that pass-1 counted.
    pub final_instance: u32,
}

/// Test-only probe: run pass-1 and return the per-tuple final SYN
/// instance counter. Used by the `normalize_roundtrip` suite to pin
/// the invariant "SYN retransmits do not bump the instance counter"
/// (I-1). Returns sorted endpoints as a plain tuple so tests don't
/// need visibility on the private `ConnTuple`/`FlowState` internals.
pub fn probe_pass1_instance_counts(
    pcap_bytes: &[u8],
) -> Result<Vec<Pass1InstanceCount>, CanonError> {
    let mut state = FlowState::default();
    let cursor = Cursor::new(pcap_bytes);
    let mut reader = PcapReader::new(cursor)?;
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        discover_pins(&pkt.data, &mut state)?;
    }
    Ok(state
        .syn_count
        .into_iter()
        .map(|(t, n)| Pass1InstanceCount {
            endpoints: (t.low_ip, t.low_port, t.high_ip, t.high_port),
            final_instance: n,
        })
        .collect())
}

/// Pass 1 walker: note the ISS (first seq seen per direction +
/// connection instance) and TS base (first TSval seen per direction)
/// without rewriting.
///
/// Connection-instance discrimination (T9-I2): the sorted 4-tuple
/// alone is insufficient — if the same 4-tuple is reused in the same
/// pcap (e.g. TIME-WAIT port reuse, or two back-to-back flows that
/// happen to reuse the same source port), the first-seen SYN's ISS
/// would pin every subsequent SYN's seq and produce garbage rewrites.
/// We bump a per-tuple SYN-observation counter: every SYN increments
/// the instance counter for that tuple, and the key becomes
/// `(tuple, instance)`. Packets without a SYN preceding them on the
/// tuple (e.g. mid-stream captures, or the first flow's data segments
/// before its SYN has been accounted for) bind to the current instance
/// for the tuple (0 if none yet).
fn discover_pins(data: &[u8], state: &mut FlowState) -> Result<(), CanonError> {
    // Any failed guard drops the packet from the pin-discovery walk
    // (consistent with the rewrite path skipping it too).
    let Some(frame) = parse_l2l3l4(data) else {
        return Ok(());
    };
    let (tuple, is_low) = classify_direction(
        frame.src_ip,
        frame.src_port,
        frame.dst_ip,
        frame.dst_port,
    );

    // SYN observations bump the per-tuple instance counter *before*
    // recording the ISS, so each SYN lands in its own slot. A pure
    // SYN that repeats the current instance's ISS (i.e. a SYN
    // retransmit) MUST NOT bump — otherwise every retransmit wastes a
    // state slot and, worse, pass-1 and pass-2 desync because pass-2
    // replays the walk and would land on a different instance for the
    // retransmit vs. the original SYN.
    if (frame.flags & TCP_FLAG_SYN) != 0 && (frame.flags & TCP_FLAG_ACK) == 0 {
        // A pure SYN opens a new connection instance. Bump for every
        // active-opener SYN with a *new* ISS; passive-side SYN-ACKs do
        // NOT bump (they belong to the opener's existing instance),
        // and SYN retransmits with the same ISS as the current
        // instance do NOT bump either.
        let current_instance = state.syn_count.get(&tuple).copied().unwrap_or(0);
        let current_key = FlowKey {
            tuple,
            instance: current_instance,
            is_low,
        };
        let existing_iss = state.iss.get(&current_key).copied();
        if existing_iss != Some(frame.seq) {
            *state.syn_count.entry(tuple).or_insert(0) += 1;
        }
    }
    let instance = state.syn_count.get(&tuple).copied().unwrap_or(0);

    let inst_key = FlowKey {
        tuple,
        instance,
        is_low,
    };
    // First seq observed on this direction + instance pins the ISS.
    // We don't privilege SYN here — a mid-stream capture has no SYN
    // for at least one side, and anchoring to the first-seen seq
    // gives a deterministic pin for both inputs.
    state.iss.entry(inst_key).or_insert(frame.seq);

    // Walk options for TSval — only needed to pin the base.
    if frame.tcp_data_off > 20 {
        let opts_slice = &data[frame.tcp_off + 20..frame.tcp_off + frame.tcp_data_off];
        walk_options(opts_slice, |kind, body| {
            if kind == OptionKind::Timestamps && body.len() == 8 {
                let tsval =
                    u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                state.ts_base.entry(inst_key).or_insert(tsval);
            }
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-flow state — observed ISS + TSval base per direction + connection
// instance.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FlowState {
    /// Per-direction + per-instance observed-ISS pins. The key
    /// bundles the sorted 4-tuple, the connection-instance counter
    /// (bumped on each pure SYN for the tuple), and the side flag.
    /// See [`FlowKey`] for the exact key shape.
    iss: HashMap<FlowKey, u32>,
    /// Per-direction + per-instance observed-TSval base.
    ts_base: HashMap<FlowKey, u32>,
    /// Per-tuple SYN-observation counter. The value reflects the
    /// *current* instance number for the tuple; incremented on each
    /// pure SYN observed during pass 1. Used as the `instance` field
    /// when building [`FlowKey`]. Pass-2 replays this in
    /// `canonicalize_pcap` using a separate counter keyed by the same
    /// tuple shape.
    syn_count: HashMap<ConnTuple, u32>,
}

/// Full flow-state key: sorted 4-tuple + instance counter + side flag.
///
/// Separated from [`ConnTuple`] so the map value lookup is bit-wise
/// identical to "the ISS / TS base for *this* connection instance on
/// *this* side", and so pass-2's instance counter only needs the
/// tuple key shape.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct FlowKey {
    tuple: ConnTuple,
    /// 0-based connection-instance counter — how many pure SYNs on
    /// this tuple have been observed at or before this packet.
    instance: u32,
    /// `true` means the packet was sent by the lex-smaller endpoint
    /// (source matches `low`).
    is_low: bool,
}

/// Connection identifier independent of direction. Built by sorting
/// the two `(ip, port)` endpoints lex-smallest-first. A flag passed
/// alongside this key indicates which side of the sorted pair the
/// packet originates from.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct ConnTuple {
    /// Lex-smaller (src_ip, src_port) pair, in host order via
    /// `Ipv4Addr`.
    low_ip: Ipv4Addr,
    low_port: u16,
    /// Lex-larger (dst_ip, dst_port) pair.
    high_ip: Ipv4Addr,
    high_port: u16,
}

/// Build the tuple + `is_low` flag. `is_low = true` means the packet
/// was sent by the lex-smaller endpoint (source matches `low`).
fn classify_direction(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> (ConnTuple, bool) {
    let s = (src_ip.octets(), src_port);
    let d = (dst_ip.octets(), dst_port);
    if s <= d {
        (
            ConnTuple {
                low_ip: src_ip,
                low_port: src_port,
                high_ip: dst_ip,
                high_port: dst_port,
            },
            true,
        )
    } else {
        (
            ConnTuple {
                low_ip: dst_ip,
                low_port: dst_port,
                high_ip: src_ip,
                high_port: src_port,
            },
            false,
        )
    }
}

// ---------------------------------------------------------------------------
// TCP options walker — shared by pass-1 (discovery) and pass-2 (rewrite).
// ---------------------------------------------------------------------------

/// Option-kind tags for the TCP options walker. Only the kinds we
/// actually look at by name are listed; unknown kinds flow through
/// untouched via their length byte.
#[allow(dead_code)] // surface for future kinds; MSS/WS/SACKPerm aren't rewritten today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionKind {
    EndOfOptions,
    Nop,
    Mss,
    WindowScale,
    SackPermitted,
    Sack,
    Timestamps,
    Other(u8),
}

const OPT_KIND_EOL: u8 = 0;
const OPT_KIND_NOP: u8 = 1;
const OPT_KIND_MSS: u8 = 2;
const OPT_KIND_WSCALE: u8 = 3;
const OPT_KIND_SACK_PERM: u8 = 4;
const OPT_KIND_SACK: u8 = 5;
const OPT_KIND_TIMESTAMPS: u8 = 8;

impl OptionKind {
    fn from_raw(kind: u8) -> Self {
        match kind {
            OPT_KIND_EOL => OptionKind::EndOfOptions,
            OPT_KIND_NOP => OptionKind::Nop,
            OPT_KIND_MSS => OptionKind::Mss,
            OPT_KIND_WSCALE => OptionKind::WindowScale,
            OPT_KIND_SACK_PERM => OptionKind::SackPermitted,
            OPT_KIND_SACK => OptionKind::Sack,
            OPT_KIND_TIMESTAMPS => OptionKind::Timestamps,
            other => OptionKind::Other(other),
        }
    }
}

/// Walk an immutable TCP options slice and invoke `visitor` on each
/// variable-length option's body (the bytes *after* the 2-byte
/// kind/len header). No-op options (`NOP = kind 1`) and the end-of-
/// options marker (`EOL = kind 0`) are handled here; they never call
/// the visitor. Truncated option tails silently stop the walk
/// (matches the legacy behaviour; option parsers MUST NOT crash on
/// garbage input).
///
/// SACK blocks are the one option we surface a hard error for: if
/// the body length isn't a multiple of 8, we return
/// `CanonError::MalformedSackOption` rather than silently truncating,
/// because mis-parsed SACK blocks produce garbage seq-space rewrites
/// downstream (T9 minor).
fn walk_options<F>(opts_slice: &[u8], mut visitor: F) -> Result<(), CanonError>
where
    F: FnMut(OptionKind, &[u8]),
{
    let mut i = 0;
    while i < opts_slice.len() {
        let kind = opts_slice[i];
        if kind == OPT_KIND_EOL {
            break;
        }
        if kind == OPT_KIND_NOP {
            i += 1;
            continue;
        }
        if i + 1 >= opts_slice.len() {
            break;
        }
        let len = opts_slice[i + 1] as usize;
        if len < 2 || i + len > opts_slice.len() {
            break;
        }
        let body = &opts_slice[i + 2..i + len];
        if kind == OPT_KIND_SACK && !body.len().is_multiple_of(8) {
            return Err(CanonError::MalformedSackOption {
                body_len: body.len(),
            });
        }
        visitor(OptionKind::from_raw(kind), body);
        i += len;
    }
    Ok(())
}

/// Mutable-slice variant of [`walk_options`]. The visitor receives a
/// `&mut [u8]` view of each option's body and can rewrite in place.
fn walk_options_mut<F>(opts_slice: &mut [u8], mut visitor: F) -> Result<(), CanonError>
where
    F: FnMut(OptionKind, &mut [u8]),
{
    let mut i = 0;
    while i < opts_slice.len() {
        let kind = opts_slice[i];
        if kind == OPT_KIND_EOL {
            break;
        }
        if kind == OPT_KIND_NOP {
            i += 1;
            continue;
        }
        if i + 1 >= opts_slice.len() {
            break;
        }
        let len = opts_slice[i + 1] as usize;
        if len < 2 || i + len > opts_slice.len() {
            break;
        }
        if kind == OPT_KIND_SACK && !(len - 2).is_multiple_of(8) {
            return Err(CanonError::MalformedSackOption {
                body_len: len - 2,
            });
        }
        let body = &mut opts_slice[i + 2..i + len];
        visitor(OptionKind::from_raw(kind), body);
        i += len;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Frame rewriter.
// ---------------------------------------------------------------------------

const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_SYN: u8 = 0x02;

fn rewrite_frame(
    data: &mut [u8],
    opts: &CanonicalizationOptions,
    state: &FlowState,
    instance_counter: &mut HashMap<ConnTuple, u32>,
) -> Result<(), CanonError> {
    let Some(frame) = parse_l2l3l4(data) else {
        return Ok(());
    };
    let FrameOffsets {
        tcp_off,
        tcp_data_off,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        ip_total_len,
        flags,
        seq,
        ack,
    } = frame;

    let (tuple, is_low) = classify_direction(src_ip, src_port, dst_ip, dst_port);

    // Replay the per-SYN instance bump the same way pass-1 did. A
    // pure SYN opens a new instance; a SYN+ACK (or any other flag
    // combination) does not. A SYN retransmit of the current
    // instance's ISS MUST NOT bump — mirrors pass-1 so (tuple,
    // instance) FlowKey lookups resolve to the same pin rows as
    // pass-1 recorded.
    if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0 {
        let current_instance = instance_counter.get(&tuple).copied().unwrap_or(0);
        let current_key = FlowKey {
            tuple,
            instance: current_instance,
            is_low,
        };
        let existing_iss = state.iss.get(&current_key).copied();
        if existing_iss != Some(seq) {
            *instance_counter.entry(tuple).or_insert(0) += 1;
        }
    }
    let instance = instance_counter.get(&tuple).copied().unwrap_or(0);

    let inst_key = FlowKey {
        tuple,
        instance,
        is_low,
    };
    let reverse_key = FlowKey {
        tuple,
        instance,
        is_low: !is_low,
    };

    // Pass 1 has already populated the ISS/TS-base pins for every
    // direction + instance observed in the capture. Any direction
    // without a pin here means pass 1 saw no packet for it — which
    // is only possible if this packet itself was skipped during
    // pass 1 (malformed frame), and we already bailed above.
    let Some(&iss) = state.iss.get(&inst_key) else {
        return Ok(());
    };
    let reverse_iss = state.iss.get(&reverse_key);

    // Rewrite seq: (seq - iss) + canonical_iss, wrapping.
    let new_seq = opts.canonical_iss.wrapping_add(seq.wrapping_sub(iss));
    data[tcp_off + 4..tcp_off + 8].copy_from_slice(&new_seq.to_be_bytes());

    // Rewrite ACK if the reverse direction's ISS is known AND the ACK
    // flag is set. A SYN without ACK carries ack=0 by convention; we
    // leave that alone so the canonical stream's SYN also has ack=0
    // (not `canonical_iss`, which would be a divergence).
    if (flags & TCP_FLAG_ACK) != 0 {
        if let Some(&reverse_iss) = reverse_iss {
            let new_ack = opts.canonical_iss.wrapping_add(ack.wrapping_sub(reverse_iss));
            data[tcp_off + 8..tcp_off + 12].copy_from_slice(&new_ack.to_be_bytes());
        }
    }

    // Walk TCP options. Options live at [tcp_off + 20, tcp_off + tcp_data_off).
    rewrite_tcp_options(
        &mut data[tcp_off + 20..tcp_off + tcp_data_off],
        opts,
        state,
        inst_key,
        reverse_key,
    )?;

    // Rewrite MAC addresses direction-aware. Lex-smaller side always
    // uses canonical_src_mac as its L2 source; the other side uses
    // canonical_dst_mac. Destination MACs are swapped accordingly so
    // each packet's (src, dst) is a consistent pair.
    let (our_mac, their_mac) = if is_low {
        (opts.canonical_src_mac, opts.canonical_dst_mac)
    } else {
        (opts.canonical_dst_mac, opts.canonical_src_mac)
    };
    data[0..6].copy_from_slice(&their_mac); // dst
    data[6..12].copy_from_slice(&our_mac); // src

    // Recompute IPv4 header checksum.
    let ihl = tcp_off - 14;
    data[14 + 10] = 0;
    data[14 + 11] = 0;
    let ip_csum = internet_checksum(&data[14..14 + ihl]);
    data[14 + 10..14 + 12].copy_from_slice(&ip_csum.to_be_bytes());

    // Recompute TCP checksum over [pseudo-header, TCP header, TCP payload].
    let tcp_len = ip_total_len - ihl;
    let tcp_slice_end = tcp_off + tcp_len;
    // Zero the checksum field first.
    data[tcp_off + 16] = 0;
    data[tcp_off + 17] = 0;
    let tcp_csum = tcp_checksum(
        src_ip.octets(),
        dst_ip.octets(),
        tcp_len as u16,
        &data[tcp_off..tcp_slice_end],
    );
    data[tcp_off + 16..tcp_off + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    Ok(())
}

/// Rewrite TCP options in-place. Handles kind=8 (Timestamps) +
/// kind=5 (SACK) + kind=0 (EOL) / kind=1 (NOP) / kind=2 (MSS) /
/// kind=3 (Window Scale) / kind=4 (SACK Permitted). Unknown kinds
/// are skipped via their length byte.
fn rewrite_tcp_options(
    opts_slice: &mut [u8],
    canon: &CanonicalizationOptions,
    state: &FlowState,
    inst_key: FlowKey,
    reverse_key: FlowKey,
) -> Result<(), CanonError> {
    walk_options_mut(opts_slice, |kind, body| match kind {
        OptionKind::Timestamps if body.len() == 8 => {
            // Timestamps option: TSval(4) + TSecr(4).
            let tsval = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let tsecr = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            // Pass 1 has already recorded the per-direction TS base.
            // Missing entry = no TS option ever seen on this
            // direction pre-this-packet (only possible on malformed
            // input); fall through to "this packet's tsval *is* the
            // base" to keep output deterministic.
            let base = *state.ts_base.get(&inst_key).unwrap_or(&tsval);
            let new_tsval = canon.canonical_ts_base.wrapping_add(tsval.wrapping_sub(base));
            body[0..4].copy_from_slice(&new_tsval.to_be_bytes());
            // TSecr echoes the peer's TSval. If we've pinned the
            // peer's base, apply the same shift. Otherwise echo the
            // raw value (zero on SYN per RFC 7323; non-zero only
            // after peer speaks).
            if tsecr != 0 {
                if let Some(&reverse_base) = state.ts_base.get(&reverse_key) {
                    let new_tsecr = canon
                        .canonical_ts_base
                        .wrapping_add(tsecr.wrapping_sub(reverse_base));
                    body[4..8].copy_from_slice(&new_tsecr.to_be_bytes());
                }
            }
        }
        OptionKind::Sack => {
            // SACK option: blocks of (left_edge, right_edge) from the
            // peer's seq space. Rewrite using the reverse direction's
            // ISS pin. walk_options_mut has already validated
            // body.len() % 8 == 0.
            if let Some(&reverse_iss) = state.iss.get(&reverse_key) {
                let blocks = body.len() / 8;
                for b in 0..blocks {
                    let base_off = b * 8;
                    let left = u32::from_be_bytes([
                        body[base_off],
                        body[base_off + 1],
                        body[base_off + 2],
                        body[base_off + 3],
                    ]);
                    let right = u32::from_be_bytes([
                        body[base_off + 4],
                        body[base_off + 5],
                        body[base_off + 6],
                        body[base_off + 7],
                    ]);
                    let new_left =
                        canon.canonical_iss.wrapping_add(left.wrapping_sub(reverse_iss));
                    let new_right =
                        canon.canonical_iss.wrapping_add(right.wrapping_sub(reverse_iss));
                    body[base_off..base_off + 4].copy_from_slice(&new_left.to_be_bytes());
                    body[base_off + 4..base_off + 8].copy_from_slice(&new_right.to_be_bytes());
                }
            }
        }
        // kind=2 (MSS), kind=3 (Window Scale), kind=4 (SACK
        // Permitted), and any unknown kind: pass through unchanged.
        // MSS divergence is expected per spec §8 and we explicitly do
        // not rewrite it here.
        _ => {}
    })
}

// ---------------------------------------------------------------------------
// Checksum helpers.
// ---------------------------------------------------------------------------

/// RFC 1071 internet checksum over an even-or-odd-length byte slice.
/// Returns the 16-bit complement ready to drop into the checksum field.
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]])));
        i += 2;
    }
    if i < bytes.len() {
        // Pad the trailing odd byte with zero.
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([bytes[i], 0])));
    }
    // Fold carries.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP checksum: pseudo-header (src_ip, dst_ip, zero, proto, tcp_len)
/// + TCP header + payload.
fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_len: u16, tcp_bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // src_ip + dst_ip
    sum = sum
        .wrapping_add(u32::from(u16::from_be_bytes([src_ip[0], src_ip[1]])))
        .wrapping_add(u32::from(u16::from_be_bytes([src_ip[2], src_ip[3]])))
        .wrapping_add(u32::from(u16::from_be_bytes([dst_ip[0], dst_ip[1]])))
        .wrapping_add(u32::from(u16::from_be_bytes([dst_ip[2], dst_ip[3]])));
    // zero + proto
    sum = sum.wrapping_add(u32::from(IPPROTO_TCP));
    // tcp_len
    sum = sum.wrapping_add(u32::from(tcp_len));
    // TCP header + payload.
    let mut i = 0;
    while i + 1 < tcp_bytes.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([
            tcp_bytes[i],
            tcp_bytes[i + 1],
        ])));
        i += 2;
    }
    if i < tcp_bytes.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([tcp_bytes[i], 0])));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// Byte-diff helper — exposed as pub so mode_wire_diff can reuse it.
// ---------------------------------------------------------------------------

/// Compute the number of byte positions at which two slices differ.
/// Length mismatch counts every trailing byte as a divergence.
pub fn byte_diff_count(a: &[u8], b: &[u8]) -> usize {
    let common = a.len().min(b.len());
    let mut count = 0usize;
    for i in 0..common {
        if a[i] != b[i] {
            count += 1;
        }
    }
    count + a.len().abs_diff(b.len())
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internet_checksum_known_vector() {
        // RFC 1071 example: 0001 f203 f4f5 f6f7 → 220d
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn internet_checksum_handles_odd_length() {
        let data = [0x12u8, 0x34, 0x56];
        // manually compute: 0x1234 + 0x5600 = 0x6834 → !0x6834 = 0x97CB
        assert_eq!(internet_checksum(&data), !0x6834);
    }

    #[test]
    fn byte_diff_count_identical_is_zero() {
        assert_eq!(byte_diff_count(&[1, 2, 3, 4], &[1, 2, 3, 4]), 0);
    }

    #[test]
    fn byte_diff_count_length_mismatch_counts_trailing() {
        assert_eq!(byte_diff_count(&[1, 2, 3], &[1, 2, 3, 4, 5]), 2);
    }

    #[test]
    fn byte_diff_count_counts_substitutions() {
        assert_eq!(byte_diff_count(&[1, 2, 3, 4], &[1, 9, 3, 9]), 2);
    }

    #[test]
    fn classify_direction_is_stable() {
        // swap src/dst: same key, opposite `is_low`.
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 0, 2);
        let (k1, l1) = classify_direction(a, 1000, b, 2000);
        let (k2, l2) = classify_direction(b, 2000, a, 1000);
        assert_eq!(k1.low_ip, k2.low_ip);
        assert_eq!(k1.high_ip, k2.high_ip);
        assert_eq!(k1.low_port, k2.low_port);
        assert_eq!(k1.high_port, k2.high_port);
        assert!(l1 && !l2);
    }

    #[test]
    fn walk_options_rejects_malformed_sack() {
        // SACK kind=5 with body len 7 (not multiple of 8) — MUST error.
        let slice = [5u8, 9, 0, 0, 0, 1, 0, 0, 0];
        let err = walk_options(&slice, |_, _| {}).unwrap_err();
        assert!(matches!(
            err,
            CanonError::MalformedSackOption { body_len: 7 }
        ));
    }

    #[test]
    fn walk_options_skips_nop_and_eol() {
        // NOP, NOP, EOL, garbage — visitor must never be called.
        let slice = [1u8, 1, 0, 9, 9, 9];
        let mut calls = 0;
        walk_options(&slice, |_, _| calls += 1).unwrap();
        assert_eq!(calls, 0);
    }

    #[test]
    fn walk_options_visits_timestamps_body() {
        // NOP, NOP, Timestamps(kind=8, len=10, TSval=1, TSecr=2).
        let mut slice = [1u8, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
        let mut saw_ts = false;
        walk_options(&slice, |kind, body| {
            if kind == OptionKind::Timestamps {
                saw_ts = true;
                assert_eq!(body.len(), 8);
                assert_eq!(u32::from_be_bytes([body[0], body[1], body[2], body[3]]), 1);
                assert_eq!(u32::from_be_bytes([body[4], body[5], body[6], body[7]]), 2);
            }
        })
        .unwrap();
        assert!(saw_ts, "Timestamps option not seen");
        // walk_options_mut must visit the same body as a mutable ref.
        saw_ts = false;
        walk_options_mut(&mut slice, |kind, _body| {
            if kind == OptionKind::Timestamps {
                saw_ts = true;
            }
        })
        .unwrap();
        assert!(saw_ts);
    }

    #[test]
    fn parse_l2l3l4_rejects_truncated_ethernet() {
        let data = [0u8; 10];
        assert!(parse_l2l3l4(&data).is_none());
    }

    #[test]
    fn parse_l2l3l4_rejects_non_ipv4() {
        // ARP ethertype 0x0806; valid Ethernet but non-IPv4.
        let mut data = [0u8; 64];
        data[12] = 0x08;
        data[13] = 0x06;
        assert!(parse_l2l3l4(&data).is_none());
    }

    #[test]
    fn canonicalization_options_default_matches_plan() {
        let opts = CanonicalizationOptions::default();
        assert_eq!(opts.canonical_iss, 0x1234_5678);
        assert_eq!(opts.canonical_ts_base, 0xAABB_CCDD);
        assert_eq!(opts.canonical_src_mac, [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(opts.canonical_dst_mac, [0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    }
}
