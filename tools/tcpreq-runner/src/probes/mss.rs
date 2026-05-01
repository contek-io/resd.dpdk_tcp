//! MissingMSS (RFC 793bis MUST-15) and LateOption (MUST-5) probes.
//! Ported from tcpreq/tests/mss.py (Python → Rust, engine-driven).
//!
//! Both probes drive a fresh engine through the test-server bypass
//! (`port_id = u16::MAX`): inject crafted Ethernet frames via
//! `Engine::inject_rx_frame`, drain TX frames via `drain_tx_frames`,
//! and inspect internal state (`peer_mss`, counters, TX shape) to
//! validate the MUST-clause.

use crate::{ProbeResult, ProbeStatus, TcpreqHarness, OUR_IP, PEER_IP, TCP_HDR_OFFSET};

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::{TCP_ACK, TCP_RST, TCP_SYN};
use dpdk_net_core::test_server::test_packet::{build_tcp_frame, build_tcp_syn, parse_syn_ack};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

/// Canonical local port for passive-open probes. Matches the port the
/// counter-coverage harness uses (5555); no semantic significance
/// beyond "some free port on the test-server bypass".
const LOCAL_PORT: u16 = 5555;
/// Canonical peer source port for probes.
const PEER_PORT: u16 = 40_000;
/// Peer ISS seed. Must match the final-ACK `seq` we inject so the
/// handshake's rcv_nxt math stays consistent.
const PEER_ISS: u32 = 0x10_00_00_00;

/// MissingMSS (RFC 9293 §3.7.1 / RFC 6691, MUST-15).
///
/// If the peer's SYN omits the MSS option, the send-MSS MUST fall back
/// to 536 bytes (the IPv4 default). Probe steps:
///   1. LISTEN on `(OUR_IP, LOCAL_PORT)`.
///   2. Inject a SYN with NO MSS option (and no other options).
///   3. Drain the SYN-ACK.
///   4. Inject the final ACK to complete the handshake.
///   5. Accept the conn, read `peer_mss` via `Engine::conn_peer_mss`.
///   6. PASS iff `peer_mss == 536`.
pub fn missing_mss() -> ProbeResult {
    let h = TcpreqHarness::new();

    let listen = match h.eng.listen(OUR_IP, LOCAL_PORT) {
        Ok(l) => l,
        Err(e) => return fail("MUST-15", "MissingMSS", format!("listen: {e:?}")),
    };

    // Craft SYN with NO MSS option — TcpOpts::default() leaves every
    // field unset, including mss. parse_options on the engine side then
    // returns Ok(TcpOpts::default()) for the empty options block; the
    // new_passive path (post-A8-T19) applies unwrap_or(536).
    set_virt_ns(1_000_000);
    let syn = build_tcp_frame(
        PEER_IP,
        PEER_PORT,
        OUR_IP,
        LOCAL_PORT,
        PEER_ISS,
        0,
        TCP_SYN,
        u16::MAX,
        TcpOpts::default(), // NO MSS, NO anything.
        &[],
    );
    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail("MUST-15", "MissingMSS", format!("inject SYN: {e:?}"));
    }

    // Drain our SYN-ACK.
    let frames = drain_tx_frames();
    let synack = match frames.first() {
        Some(f) => f,
        None => {
            return fail(
                "MUST-15",
                "MissingMSS",
                "no SYN-ACK emitted after injecting MSS-less SYN".into(),
            );
        }
    };
    let (our_iss, _ack) = match parse_syn_ack(synack) {
        Some(v) => v,
        None => {
            return fail(
                "MUST-15",
                "MissingMSS",
                "TX frame post-SYN is not a valid SYN-ACK".into(),
            );
        }
    };

    // Final ACK to complete the handshake.
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
        return fail("MUST-15", "MissingMSS", format!("inject final ACK: {e:?}"));
    }
    let _ = drain_tx_frames();

    let conn = match h.eng.accept_next(listen) {
        Some(c) => c,
        None => {
            return fail(
                "MUST-15",
                "MissingMSS",
                "accept queue empty after final ACK".into(),
            );
        }
    };

    match h.eng.conn_peer_mss(conn) {
        Some(536) => ProbeResult {
            clause_id: "MUST-15",
            probe_name: "MissingMSS",
            status: ProbeStatus::Pass,
            message: "peer SYN omitted MSS; peer_mss correctly set to 536 (RFC 9293 §3.7.1)".into(),
        },
        Some(n) => fail(
            "MUST-15",
            "MissingMSS",
            format!("peer_mss = {n}, expected 536 per MUST-15"),
        ),
        None => fail(
            "MUST-15",
            "MissingMSS",
            "conn not found after accept_next".into(),
        ),
    }
}

/// LateOption (RFC 9293 §3.2, MUST-5).
///
/// TCP options MUST be acceptable in any segment (not just SYN). Probe:
///   1. Complete a normal 3WHS (SYN carries MSS option; no TS).
///   2. Snapshot `rx_bad_option` counter.
///   3. Inject a post-ESTABLISHED ACK carrying a Timestamps option.
///   4. Verify:
///       - no `rx_bad_option` bump (parser accepts the late option);
///       - engine emits NO RST in response.
///
/// Since the handshake did NOT negotiate Timestamps (`ts_enabled == false`),
/// `handle_established` parses the options but ignores the TS field —
/// MUST-5 is the "parser accepts, no error" half; whether the TS is
/// semantically absorbed is subordinate to that.
pub fn late_option() -> ProbeResult {
    let h = TcpreqHarness::new();

    let listen = match h.eng.listen(OUR_IP, LOCAL_PORT) {
        Ok(l) => l,
        Err(e) => return fail("MUST-5", "LateOption", format!("listen: {e:?}")),
    };

    // Normal 3WHS with MSS-bearing SYN.
    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, LOCAL_PORT, PEER_ISS, 1460);
    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail("MUST-5", "LateOption", format!("inject SYN: {e:?}"));
    }
    let frames = drain_tx_frames();
    let synack = match frames.first() {
        Some(f) => f,
        None => {
            return fail(
                "MUST-5",
                "LateOption",
                "no SYN-ACK emitted after 3WHS SYN".into(),
            );
        }
    };
    let (our_iss, _ack) = match parse_syn_ack(synack) {
        Some(v) => v,
        None => return fail("MUST-5", "LateOption", "first TX frame is not SYN-ACK".into()),
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
        return fail("MUST-5", "LateOption", format!("inject final ACK: {e:?}"));
    }
    let _ = drain_tx_frames();

    if h.eng.accept_next(listen).is_none() {
        return fail("MUST-5", "LateOption", "accept queue empty post-handshake".into());
    }

    // Snapshot rx_bad_option BEFORE the late-option injection so we can
    // detect a bump attributable solely to the late-option segment.
    let counters = h.eng.counters();
    let pre_bad_opt = counters
        .tcp
        .rx_bad_option
        .load(std::sync::atomic::Ordering::Relaxed);

    // Post-ESTABLISHED ACK with a Timestamps option attached.
    // seq == rcv_nxt (peer's next unused seq) so handle_established's
    // in-window check passes. ack == our_iss+1 (ACK of our SYN-ACK; no
    // new data yet on this conn).
    set_virt_ns(3_000_000);
    let opts = TcpOpts {
        timestamps: Some((0x12_34_56, 0)),
        ..Default::default()
    };
    let late_ack = build_tcp_frame(
        PEER_IP,
        PEER_PORT,
        OUR_IP,
        LOCAL_PORT,
        PEER_ISS.wrapping_add(1),
        our_iss.wrapping_add(1),
        TCP_ACK,
        u16::MAX,
        opts,
        &[],
    );
    if let Err(e) = h.eng.inject_rx_frame(&late_ack) {
        return fail(
            "MUST-5",
            "LateOption",
            format!("inject late-option ACK: {e:?}"),
        );
    }

    let post_bad_opt = counters
        .tcp
        .rx_bad_option
        .load(std::sync::atomic::Ordering::Relaxed);
    if post_bad_opt > pre_bad_opt {
        return fail(
            "MUST-5",
            "LateOption",
            format!(
                "rx_bad_option bumped on late-option ACK: pre={pre_bad_opt} post={post_bad_opt} \
                 — parser rejected a TS option on ESTABLISHED conn"
            ),
        );
    }

    // The engine MUST NOT emit a RST in response to a well-formed
    // late-option ACK (MUST-5 semantic: option is tolerated). A bare-ACK
    // response is fine (dup-ACK path); only a RST indicates rejection.
    let post_frames = drain_tx_frames();
    for f in &post_frames {
        if is_rst_frame(f) {
            return fail(
                "MUST-5",
                "LateOption",
                "engine emitted RST in response to late-option ACK".into(),
            );
        }
    }

    ProbeResult {
        clause_id: "MUST-5",
        probe_name: "LateOption",
        status: ProbeStatus::Pass,
        message: "late-option TS accepted on ESTABLISHED conn; no rx_bad_option bump; no RST emitted".into(),
    }
}

// ----------------------------- MUST-14 -----------------------------------

/// MSSSupport (RFC 9293 §3.7.1, MUST-14).
///
/// TCP endpoints MUST implement both sending and receiving the MSS option.
/// The parser side (peer→us) is already covered by `missing_mss`; this
/// probe validates the emission side (us→peer): when the peer's SYN
/// carries a valid MSS option, our SYN-ACK response MUST also carry an
/// MSS option.
///
/// Steps:
///   1. LISTEN on `(OUR_IP, LOCAL_PORT)`.
///   2. Inject a SYN with MSS=1460 (standard case).
///   3. Drain the SYN-ACK.
///   4. Walk the TCP option region TLVs from `TCP + 20` to
///      `TCP + 4 * DataOffset`:
///        - kind 0 (EOL) → stop.
///        - kind 1 (NOP) → skip 1 byte.
///        - kind 2 (MSS) → verify `len == 4`; record as found.
///        - other → read length byte, skip `len` bytes.
///
///      Truncated options are detected and reported as failures rather
///      than silently ignored.
///   5. PASS iff an MSS option (kind=2, len=4) was found.
pub fn mss_support() -> ProbeResult {
    let h = TcpreqHarness::new();

    if let Err(e) = h.eng.listen(OUR_IP, LOCAL_PORT) {
        return fail("MUST-14", "MSSSupport", format!("listen: {e:?}"));
    }

    // Inject a well-formed SYN with MSS=1460 (the universal default).
    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, LOCAL_PORT, PEER_ISS, 1460);
    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail("MUST-14", "MSSSupport", format!("inject SYN: {e:?}"));
    }

    // Drain our SYN-ACK.
    let frames = drain_tx_frames();
    let synack = match frames.first() {
        Some(f) => f,
        None => {
            return fail(
                "MUST-14",
                "MSSSupport",
                "no SYN-ACK emitted after MSS-bearing SYN".into(),
            );
        }
    };
    // parse_syn_ack gates on SYN|ACK bits, so a Some here doubles as a
    // predicate that the drained TX frame is indeed a SYN-ACK.
    if parse_syn_ack(synack).is_none() {
        return fail(
            "MUST-14",
            "MSSSupport",
            "first TX frame post-SYN is not a SYN-ACK".into(),
        );
    }

    // Locate the TCP header and its option region. SYN-ACKs from the
    // test-server always use the 14+20 fixed L2+IP layout (no IP options).
    if synack.len() < TCP_HDR_OFFSET + 20 {
        return fail(
            "MUST-14",
            "MSSSupport",
            format!("SYN-ACK too short for TCP header: {} bytes", synack.len()),
        );
    }
    // DataOffset nibble lives in the high 4 bits of TCP byte 12.
    let data_offset_words = (synack[TCP_HDR_OFFSET + 12] >> 4) as usize;
    let tcp_hdr_len = data_offset_words * 4;
    if tcp_hdr_len < 20 {
        return fail(
            "MUST-14",
            "MSSSupport",
            format!("SYN-ACK TCP DataOffset < 5 words ({data_offset_words})"),
        );
    }
    if synack.len() < TCP_HDR_OFFSET + tcp_hdr_len {
        return fail(
            "MUST-14",
            "MSSSupport",
            format!(
                "SYN-ACK truncated: DataOffset claims {tcp_hdr_len} TCP bytes but frame has {}",
                synack.len() - TCP_HDR_OFFSET
            ),
        );
    }
    // Options region: bytes [TCP_HDR_OFFSET + 20 .. TCP_HDR_OFFSET + tcp_hdr_len).
    let opts_start = TCP_HDR_OFFSET + 20;
    let opts_end = TCP_HDR_OFFSET + tcp_hdr_len;
    let opts = &synack[opts_start..opts_end];

    // TLV walk. 0=EOL (stop), 1=NOP (1-byte), 2=MSS (len=4, mark found),
    // other=read length byte & skip `len` bytes (defends against
    // truncation by checking cursor+len <= opts.len() on every iteration).
    let mut i = 0usize;
    let mut found_mss = false;
    while i < opts.len() {
        let kind = opts[i];
        match kind {
            0 => break, // EOL
            1 => {
                i += 1;
            }
            2 => {
                // MSS: TLV kind=2, len=4, 2-byte value. Bounds check the
                // length byte AND the declared length fits in the region.
                if i + 1 >= opts.len() {
                    return fail(
                        "MUST-14",
                        "MSSSupport",
                        format!(
                            "truncated MSS option: no length byte at offset {i}; opts={opts:?}"
                        ),
                    );
                }
                let len = opts[i + 1] as usize;
                if len != 4 {
                    return fail(
                        "MUST-14",
                        "MSSSupport",
                        format!(
                            "MSS option has illegal length: expected 4, got {len}; opts={opts:?}"
                        ),
                    );
                }
                if i + len > opts.len() {
                    return fail(
                        "MUST-14",
                        "MSSSupport",
                        format!(
                            "MSS option truncated: declares {len} bytes at offset {i} \
                             but only {} bytes remain; opts={opts:?}",
                            opts.len() - i
                        ),
                    );
                }
                found_mss = true;
                i += len;
            }
            _ => {
                // Unknown multi-byte option: read length byte and skip.
                if i + 1 >= opts.len() {
                    return fail(
                        "MUST-14",
                        "MSSSupport",
                        format!(
                            "truncated option kind={kind}: no length byte at offset {i}; \
                             opts={opts:?}"
                        ),
                    );
                }
                let len = opts[i + 1] as usize;
                // RFC 9293 §3.1: every non-NOP/EOL option has len>=2 (kind byte + len byte).
                if len < 2 {
                    return fail(
                        "MUST-14",
                        "MSSSupport",
                        format!(
                            "option kind={kind} declares illegal length {len}<2 at offset {i}; \
                             opts={opts:?}"
                        ),
                    );
                }
                if i + len > opts.len() {
                    return fail(
                        "MUST-14",
                        "MSSSupport",
                        format!(
                            "option kind={kind} truncated: declares {len} bytes at offset {i} \
                             but only {} bytes remain; opts={opts:?}",
                            opts.len() - i
                        ),
                    );
                }
                i += len;
            }
        }
    }

    if !found_mss {
        return fail(
            "MUST-14",
            "MSSSupport",
            format!(
                "our SYN-ACK carries NO MSS option — MUST-14 violation (emission side). \
                 Options region bytes: {opts:?}"
            ),
        );
    }

    ProbeResult {
        clause_id: "MUST-14",
        probe_name: "MSSSupport",
        status: ProbeStatus::Pass,
        message: "peer SYN MSS accepted; our SYN-ACK carries MSS option".into(),
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

/// `true` if the TX frame's TCP header has the RST flag set. Uses the
/// same L2+IP-header-length parse as `parse_tcp_seq_ack` to locate the
/// TCP flags byte at offset 13.
fn is_rst_frame(frame: &[u8]) -> bool {
    if frame.len() < 14 + 20 + 20 {
        return false;
    }
    let ip_ihl = (frame[14] & 0x0f) as usize * 4;
    let tcp_off = 14 + ip_ihl;
    if frame.len() < tcp_off + 20 {
        return false;
    }
    let flags = frame[tcp_off + 13];
    flags & TCP_RST != 0
}

