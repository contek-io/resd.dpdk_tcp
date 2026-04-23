//! Options probes — RFC 9293 §3.1 MUST-4 / MUST-6 / MUST-7.
//! Ported from tcpreq/tests/options.py
//! (OptionSupportTest / UnknownOptionTest / IllegalLengthOptionTest).
//!
//! All three probes share the frame-crafting skeleton:
//!   1. Build a SYN with the baseline MSS option via
//!      `test_packet::build_tcp_syn` (4-byte options block).
//!   2. Splice extra option bytes into the options region (4 bytes at a
//!      time to keep the TCP header 4-byte word-aligned).
//!   3. Widen the TCP DataOffset nibble by +1 per 4-byte splice, widen
//!      the IPv4 total-length by the same, then recompute both the IPv4
//!      header checksum and the TCP pseudo-header checksum.
//!
//! One file, three `pub fn <name>() -> ProbeResult` entrypoints:
//!   * `option_support` (MUST-4) — SYN carries MSS + NOP + EOL. Assert
//!     the engine accepts all three kinds by completing the 3WHS.
//!   * `unknown_option`  (MUST-6) — SYN carries MSS + an unknown option
//!     kind (253, len=4, 2 bytes payload). Assert unknown option is
//!     silently ignored (3WHS completes, SYN-ACK emitted).
//!   * `illegal_length`  (MUST-7) — SYN carries MSS + a malformed TS
//!     option (kind=8, len=0 — always illegal; TS is 10 bytes) padded
//!     with 2 NOPs. Assert the engine does NOT crash. The LISTEN path
//!     tolerantly falls back to `TcpOpts::default()` on option-parse
//!     error and still emits a SYN-ACK with the config's default MSS
//!     (536 fallback), which is the spec-compliant "options ignored"
//!     behavior — NOT "malformed options accepted". Either silent-drop
//!     OR tolerant-emit is fine for MUST-7; we only require no crash +
//!     no semantic absorption of the malformed TS values.

use crate::{
    recompute_ip_csum, recompute_tcp_csum, ProbeResult, ProbeStatus, TcpreqHarness, OUR_IP,
    PEER_IP, TCP_HDR_OFFSET,
};

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::TCP_ACK;
use dpdk_net_core::test_server::test_packet::{build_tcp_frame, build_tcp_syn, parse_syn_ack};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

const LOCAL_PORT: u16 = 5555;
const PEER_PORT: u16 = 40_000;
const PEER_ISS: u32 = 0x10_00_00_00;
const PEER_MSS: u16 = 1460;

/// Byte 12 of the TCP header holds the DataOffset nibble in its high
/// four bits (low nibble is reserved, which is always 0 on our TX path).
const DO_BYTE_OFFSET: usize = TCP_HDR_OFFSET + 12;

// ----------------------------- MUST-4 ------------------------------------

/// OptionSupport (MUST-4): SYN carries MSS + NOP + EOL. The parser MUST
/// accept all three option kinds; the 3WHS MUST complete.
///
/// Baseline: `build_tcp_syn` emits 4 bytes of options = `[MSS=2, 4, hi,
/// lo]`. We splice a second 4-byte word `[NOP=1, EOL=0, NOP=1, NOP=1]`
/// onto the end. The EOL kind terminates option processing and the
/// trailing NOPs are word-alignment padding — together this exercises
/// all three basic option kinds in one SYN.
pub fn option_support() -> ProbeResult {
    let h = TcpreqHarness::new();

    let listen = match h.eng.listen(OUR_IP, LOCAL_PORT) {
        Ok(l) => l,
        Err(e) => return fail("MUST-4", "OptionSupport", format!("listen: {e:?}")),
    };

    set_virt_ns(1_000_000);
    let base = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, LOCAL_PORT, PEER_ISS, PEER_MSS);
    // Splice MSS + NOP + EOL + NOP + NOP. The trailing NOPs keep the
    // option region 4-byte word-aligned so DataOffset stays integral.
    let syn = match splice_options(&base, &[0x01, 0x00, 0x01, 0x01]) {
        Ok(s) => s,
        Err(e) => return fail("MUST-4", "OptionSupport", e),
    };

    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail("MUST-4", "OptionSupport", format!("inject SYN: {e:?}"));
    }

    let frames = drain_tx_frames();
    let synack = match frames.first() {
        Some(f) => f,
        None => {
            return fail(
                "MUST-4",
                "OptionSupport",
                "no SYN-ACK emitted after MSS+NOP+EOL SYN".into(),
            );
        }
    };
    let (our_iss, _ack) = match parse_syn_ack(synack) {
        Some(v) => v,
        None => {
            return fail(
                "MUST-4",
                "OptionSupport",
                "first TX frame post-SYN is not a SYN-ACK".into(),
            );
        }
    };

    // Final ACK to complete the handshake — confirms the engine fully
    // accepted the SYN (SYN-ACK alone would still be emitted if the
    // engine had silently downgraded to zero-option processing; running
    // the 3WHS to completion proves the path is clean end-to-end).
    set_virt_ns(2_000_000);
    let final_ack = build_tcp_frame(
        PEER_IP,
        PEER_PORT,
        OUR_IP,
        LOCAL_PORT,
        PEER_ISS.wrapping_add(1),
        our_iss.wrapping_add(1),
        TCP_ACK,
        u16::MAX,
        TcpOpts::default(),
        &[],
    );
    if let Err(e) = h.eng.inject_rx_frame(&final_ack) {
        return fail("MUST-4", "OptionSupport", format!("inject final ACK: {e:?}"));
    }
    let _ = drain_tx_frames();

    if h.eng.accept_next(listen).is_none() {
        return fail(
            "MUST-4",
            "OptionSupport",
            "accept queue empty post-3WHS (engine rejected MSS+NOP+EOL SYN)".into(),
        );
    }

    ProbeResult {
        clause_id: "MUST-4",
        probe_name: "OptionSupport",
        status: ProbeStatus::Pass,
        message: "SYN with MSS + NOP + EOL options accepted; 3WHS completed".into(),
    }
}

// ----------------------------- MUST-6 ------------------------------------

/// UnknownOption (MUST-6): SYN carries MSS + an unknown experimental
/// option kind (253) with valid length (4) and arbitrary payload. The
/// parser MUST skip over the unknown kind by its declared length and
/// process the remainder normally. Engine MUST emit a SYN-ACK and the
/// 3WHS MUST complete.
pub fn unknown_option() -> ProbeResult {
    let h = TcpreqHarness::new();

    let listen = match h.eng.listen(OUR_IP, LOCAL_PORT) {
        Ok(l) => l,
        Err(e) => return fail("MUST-6", "UnknownOption", format!("listen: {e:?}")),
    };

    set_virt_ns(1_000_000);
    let base = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, LOCAL_PORT, PEER_ISS, PEER_MSS);
    // Splice unknown kind 253, len=4, 2 bytes payload. 4 bytes total
    // keeps the TCP header 4-byte word-aligned.
    let syn = match splice_options(&base, &[253, 4, 0xAB, 0xCD]) {
        Ok(s) => s,
        Err(e) => return fail("MUST-6", "UnknownOption", e),
    };

    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail("MUST-6", "UnknownOption", format!("inject SYN: {e:?}"));
    }

    let frames = drain_tx_frames();
    let synack = match frames.first() {
        Some(f) => f,
        None => {
            return fail(
                "MUST-6",
                "UnknownOption",
                "no SYN-ACK emitted after unknown-option SYN — parser rejected the unknown kind \
                 (MUST-6 violation)"
                    .into(),
            );
        }
    };
    let (our_iss, _ack) = match parse_syn_ack(synack) {
        Some(v) => v,
        None => {
            return fail(
                "MUST-6",
                "UnknownOption",
                "first TX frame post-SYN is not a SYN-ACK".into(),
            );
        }
    };

    set_virt_ns(2_000_000);
    let final_ack = build_tcp_frame(
        PEER_IP,
        PEER_PORT,
        OUR_IP,
        LOCAL_PORT,
        PEER_ISS.wrapping_add(1),
        our_iss.wrapping_add(1),
        TCP_ACK,
        u16::MAX,
        TcpOpts::default(),
        &[],
    );
    if let Err(e) = h.eng.inject_rx_frame(&final_ack) {
        return fail("MUST-6", "UnknownOption", format!("inject final ACK: {e:?}"));
    }
    let _ = drain_tx_frames();

    if h.eng.accept_next(listen).is_none() {
        return fail(
            "MUST-6",
            "UnknownOption",
            "accept queue empty post-3WHS (engine rejected unknown-option SYN)".into(),
        );
    }

    ProbeResult {
        clause_id: "MUST-6",
        probe_name: "UnknownOption",
        status: ProbeStatus::Pass,
        message: "SYN with unknown option kind=253 silently ignored; 3WHS completed".into(),
    }
}

// ----------------------------- MUST-7 ------------------------------------

/// IllegalLength (MUST-7): SYN carries MSS + a malformed Timestamp
/// option (kind=8, len=0 — always illegal; TS is always 10 bytes on the
/// wire) padded with 2 NOPs for word alignment. The engine MUST NOT
/// crash. Spec-compliant engine behaviors are:
///   (a) drop the segment silently (no SYN-ACK emitted), OR
///   (b) treat the option block as absent and emit a SYN-ACK with the
///       config's default MSS (our Stage 1 engine's current LISTEN-path
///       behavior — `parse_options().unwrap_or_default()` in
///       engine.rs's SYN→LISTEN dispatch).
///
/// Both are spec-compliant: neither absorbs the malformed TS values.
/// The probe asserts the engine did not crash and, if a SYN-ACK was
/// emitted, that the 3WHS runs cleanly with `peer_mss == 536`
/// (MUST-15 fallback on an absent / invalid MSS option — here the
/// engine treats the entire options block as absent after the TS error,
/// so MSS is also considered absent). This composite assertion covers
/// both spec-compliant outcomes while guaranteeing the engine did not
/// semantically absorb the illegal TS values.
pub fn illegal_length() -> ProbeResult {
    let h = TcpreqHarness::new();

    let listen = match h.eng.listen(OUR_IP, LOCAL_PORT) {
        Ok(l) => l,
        Err(e) => return fail("MUST-7", "IllegalLength", format!("listen: {e:?}")),
    };

    set_virt_ns(1_000_000);
    let base = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, LOCAL_PORT, PEER_ISS, PEER_MSS);
    // Splice malformed TS(kind=8, len=0) + two NOPs for word alignment.
    // The parser returns `Err(OptionParseError::ShortUnknown)` on
    // `len < 2` for any non-NOP/EOL kind, so the entire options block
    // is rejected and the LISTEN path falls back to `TcpOpts::default()`.
    let syn = match splice_options(&base, &[0x08, 0x00, 0x01, 0x01]) {
        Ok(s) => s,
        Err(e) => return fail("MUST-7", "IllegalLength", e),
    };

    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail("MUST-7", "IllegalLength", format!("inject SYN: {e:?}"));
    }

    // Implicit crash assertion: we're still running.
    let frames = drain_tx_frames();
    match frames.first() {
        None => {
            // Silent drop — MUST-7 compliant path (a). No further action
            // required; the engine rejected the malformed segment and
            // emitted nothing.
            ProbeResult {
                clause_id: "MUST-7",
                probe_name: "IllegalLength",
                status: ProbeStatus::Pass,
                message: "SYN with malformed TS(len=0) silently dropped; engine did not crash"
                    .into(),
            }
        }
        Some(f) => {
            // Path (b): engine tolerated the malformed option and emitted
            // a SYN-ACK. The SYN-ACK must be well-formed AND the engine
            // must NOT have absorbed the malformed TS values (we verify
            // by completing the 3WHS and checking `peer_mss == 536`,
            // proving the entire options block — including MSS — was
            // treated as absent, not semantically applied).
            let synack = f.clone();
            let (our_iss, _ack) = match parse_syn_ack(&synack) {
                Some(v) => v,
                None => {
                    return fail(
                        "MUST-7",
                        "IllegalLength",
                        "first TX frame post-malformed-option SYN is not a SYN-ACK \
                         (engine emitted something else — possibly a crash artefact)"
                            .into(),
                    );
                }
            };

            set_virt_ns(2_000_000);
            let final_ack = build_tcp_frame(
                PEER_IP,
                PEER_PORT,
                OUR_IP,
                LOCAL_PORT,
                PEER_ISS.wrapping_add(1),
                our_iss.wrapping_add(1),
                TCP_ACK,
                u16::MAX,
                TcpOpts::default(),
                &[],
            );
            if let Err(e) = h.eng.inject_rx_frame(&final_ack) {
                return fail("MUST-7", "IllegalLength", format!("inject final ACK: {e:?}"));
            }
            let _ = drain_tx_frames();

            let conn = match h.eng.accept_next(listen) {
                Some(c) => c,
                None => {
                    return fail(
                        "MUST-7",
                        "IllegalLength",
                        "accept queue empty post-3WHS after tolerant-accept of malformed-option SYN"
                            .into(),
                    );
                }
            };
            // Engine's LISTEN path defaults `parse_options` failures to
            // `TcpOpts::default()` (no mss) → `new_passive` applies the
            // MUST-15 fallback → `peer_mss = 536`. If the engine instead
            // semantically absorbed the malformed TS bytes (e.g. read
            // 0x0504 = 1284 from the options block as a bogus MSS), the
            // `peer_mss` value would be non-536 and this check would
            // fire — catching a regression where the parser stops short
            // of the TS error but keeps the preceding MSS.
            match h.eng.conn_peer_mss(conn) {
                Some(536) => ProbeResult {
                    clause_id: "MUST-7",
                    probe_name: "IllegalLength",
                    status: ProbeStatus::Pass,
                    message: "SYN with malformed TS(len=0) accepted; options block treated as \
                              absent (peer_mss=536 fallback); engine did not crash"
                        .into(),
                },
                Some(n) => fail(
                    "MUST-7",
                    "IllegalLength",
                    format!(
                        "engine absorbed malformed options: peer_mss = {n}, expected 536 fallback \
                         (malformed TS should have invalidated the entire options block)"
                    ),
                ),
                None => fail(
                    "MUST-7",
                    "IllegalLength",
                    "conn not found after accept_next (malformed-option path)".into(),
                ),
            }
        }
    }
}

// ----------------------------- helpers -----------------------------------

fn fail(clause_id: &'static str, probe_name: &'static str, reason: String) -> ProbeResult {
    ProbeResult {
        clause_id,
        probe_name,
        status: ProbeStatus::Fail(reason),
        message: String::new(),
    }
}

/// Append `extra` (MUST be a 4-byte multiple) onto the TCP options
/// region of a `build_tcp_syn`-style Ethernet frame and recompute the
/// TCP header's DataOffset nibble, the IPv4 header's total-length
/// field, the IPv4 header checksum, and the TCP pseudo-header checksum.
///
/// Why 4-byte multiple? TCP's DataOffset is measured in 4-byte words,
/// so any non-multiple would require additional NOP padding to
/// re-align. Every caller in this module passes exactly 4 bytes so we
/// enforce the invariant with a simple length check.
///
/// Returns the mutated frame as an owned `Vec<u8>`; callers then pass
/// it to `Engine::inject_rx_frame` as-is.
fn splice_options(base: &[u8], extra: &[u8]) -> Result<Vec<u8>, String> {
    if !extra.len().is_multiple_of(4) {
        return Err(format!(
            "splice_options: extra.len() must be 4-byte multiple; got {}",
            extra.len()
        ));
    }
    if base.len() < TCP_HDR_OFFSET + 20 {
        return Err(format!(
            "splice_options: frame too short for TCP header: {}",
            base.len()
        ));
    }

    // Current TCP header length from the DataOffset nibble.
    let do_words = (base[DO_BYTE_OFFSET] >> 4) as usize;
    let old_tcp_hdr_len = do_words * 4;

    let mut out = Vec::with_capacity(base.len() + extra.len());
    // Preamble up through the END of the current TCP header (L2 + IP +
    // TCP header with existing options).
    out.extend_from_slice(&base[..TCP_HDR_OFFSET + old_tcp_hdr_len]);
    // Splice the extra option bytes.
    out.extend_from_slice(extra);
    // Tail (payload, if any — empty for SYNs).
    out.extend_from_slice(&base[TCP_HDR_OFFSET + old_tcp_hdr_len..]);

    // Update DataOffset nibble: +1 per 4-byte splice. Keep the low
    // nibble (reserved) intact.
    let new_do_words = do_words + (extra.len() / 4);
    if new_do_words > 15 {
        return Err(format!(
            "splice_options: DataOffset would exceed 15 words (have {new_do_words})"
        ));
    }
    let low_nibble = out[DO_BYTE_OFFSET] & 0x0F;
    out[DO_BYTE_OFFSET] = ((new_do_words as u8) << 4) | low_nibble;

    // Update IPv4 total-length (bytes 16..18 of the frame, big-endian).
    // Existing length + splice = new length.
    let ip_total_len_offset = 14 + 2;
    let old_ip_total =
        u16::from_be_bytes([out[ip_total_len_offset], out[ip_total_len_offset + 1]]) as usize;
    let new_ip_total = old_ip_total + extra.len();
    if new_ip_total > u16::MAX as usize {
        return Err(format!(
            "splice_options: IP total length would overflow u16 ({new_ip_total})"
        ));
    }
    out[ip_total_len_offset..ip_total_len_offset + 2]
        .copy_from_slice(&(new_ip_total as u16).to_be_bytes());

    // Recompute IPv4 header checksum (the old one is stale after the
    // total-length update) and TCP pseudo-header checksum (the TCP
    // header's option region changed).
    recompute_ip_csum(&mut out);
    recompute_tcp_csum(&mut out, TCP_HDR_OFFSET);
    Ok(out)
}
