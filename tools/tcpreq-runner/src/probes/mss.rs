//! MissingMSS (RFC 793bis MUST-15) and LateOption (MUST-5) probes.
//! Ported from tcpreq/tests/mss.py (Python → Rust, engine-driven).
//!
//! Both probes drive a fresh engine through the test-server bypass
//! (`port_id = u16::MAX`): inject crafted Ethernet frames via
//! `Engine::inject_rx_frame`, drain TX frames via `drain_tx_frames`,
//! and inspect internal state (`peer_mss`, counters, TX shape) to
//! validate the MUST-clause.

use crate::{ProbeResult, ProbeStatus, TcpreqHarness, OUR_IP, PEER_IP};

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

