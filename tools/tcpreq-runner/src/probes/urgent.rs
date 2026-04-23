//! Urgent probe — RFC 9293 §3.8.2 / MUST-30/31.
//! Ported from tcpreq/tests/urgent.py (Python → Rust, engine-driven).
//!
//! Pins the A8 documented deviation AD-A8-urg-dropped (spec §6.4): the
//! Stage 1 stack does NOT implement the URG mechanism. A URG-flagged
//! inbound segment on an ESTABLISHED connection is dropped silently
//! (tx = `TxAction::None`, no bytes delivered, no response segment)
//! and `tcp.rx_urgent_dropped` is bumped once.
//!
//! Probe flow:
//!   1. LISTEN on (OUR_IP, LOCAL_PORT); complete the 3WHS.
//!   2. Snapshot `tcp.rx_urgent_dropped` and `tcp.recv_buf_delivered`.
//!   3. Inject an ESTABLISHED data segment with `URG | ACK | PSH` flags,
//!      a non-zero urgent pointer, and an 8-byte payload.
//!   4. Assert: `tcp.rx_urgent_dropped` bumped by exactly 1.
//!   5. Assert: `tcp.recv_buf_delivered` did NOT bump (payload not in
//!      the readable queue).
//!   6. Assert: engine emitted no frame at all (no URG echo, no ACK,
//!      no RST).
//!
//! Result: `ProbeStatus::Deviation("AD-A8-urg-dropped")` — passes the
//! documented-deviation assertion rather than MUST-30/31 conformance.
//! The cite string must match the spec §6.4 row id.

use std::sync::atomic::Ordering;

use crate::{ProbeResult, ProbeStatus, TcpreqHarness, OUR_IP, PEER_IP};

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::l3_ip::{internet_checksum, IPPROTO_TCP};
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH, TCP_URG};
use dpdk_net_core::test_server::test_packet::{build_tcp_frame, build_tcp_syn, parse_syn_ack};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

const LOCAL_PORT: u16 = 5555;
const PEER_PORT: u16 = 40_000;
/// Peer ISS seed. `PEER_ISS + 1` is the seq of the first post-3WHS byte
/// the peer would send (the SYN consumes one seq).
const PEER_ISS: u32 = 0x10_00_00_00;
const PEER_MSS: u16 = 1460;

/// L2 Ethernet header (14) + IPv4 header (20, no IP options) — the
/// test-server `build_segment` always emits this exact layout. TCP
/// header starts at byte 34. Urgent pointer field sits at TCP + 18..20.
const TCP_HDR_OFFSET: usize = 14 + 20;
const URG_PTR_OFFSET: usize = TCP_HDR_OFFSET + 18;

pub fn urgent_dropped() -> ProbeResult {
    let h = TcpreqHarness::new();

    let listen = match h.eng.listen(OUR_IP, LOCAL_PORT) {
        Ok(l) => l,
        Err(e) => return fail(format!("listen: {e:?}")),
    };

    // Normal 3WHS with MSS-bearing SYN (same shape as the MSS + Reserved
    // probes). This drives the passive side to ESTABLISHED so the URG
    // segment exercises `established_rx` — the code path that actually
    // implements the AD-A8-urg-dropped branch (tcp_input.rs:~730).
    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, LOCAL_PORT, PEER_ISS, PEER_MSS);
    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail(format!("inject 3WHS SYN: {e:?}"));
    }
    let frames = drain_tx_frames();
    let synack = match frames.first() {
        Some(f) => f,
        None => return fail("no SYN-ACK emitted after 3WHS SYN".into()),
    };
    let (our_iss, _ack) = match parse_syn_ack(synack) {
        Some(v) => v,
        None => return fail("first TX frame is not a SYN-ACK".into()),
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
        return fail(format!("inject final ACK: {e:?}"));
    }
    let _ = drain_tx_frames();

    if h.eng.accept_next(listen).is_none() {
        return fail("accept queue empty post-3WHS".into());
    }

    // Snapshot both the URG-drop counter and the delivery counter so we
    // can assert the (+1, +0) delta attributable solely to the URG
    // segment. `recv_buf_delivered` tracks bytes that `deliver_readable`
    // pushed onto the readable queue; zero delta proves the payload was
    // NOT delivered.
    let counters = h.eng.counters();
    let pre_urg = counters.tcp.rx_urgent_dropped.load(Ordering::Relaxed);
    let pre_delivered = counters.tcp.recv_buf_delivered.load(Ordering::Relaxed);

    // Build the URG-bearing data segment. Flag set: `URG | ACK | PSH`
    // — a realistic out-of-band data carrier (matches tcpreq urgent.py's
    // pattern). `build_tcp_frame` writes the 20-byte TCP header with
    // urgent-pointer field zeroed; we overlay the urgent pointer at
    // bytes 18..20 of the TCP header AFTER build (the field sits
    // outside `TcpOpts`), then recompute the TCP checksum since those
    // bytes are inside the checksummed span.
    set_virt_ns(3_000_000);
    const URG_PAYLOAD: &[u8] = b"urgbytes"; // 8 bytes
    let mut urg_seg = build_tcp_frame(
        PEER_IP,
        PEER_PORT,
        OUR_IP,
        LOCAL_PORT,
        PEER_ISS.wrapping_add(1),         // next peer byte post-3WHS
        our_iss.wrapping_add(1),          // ACK of our SYN-ACK
        TCP_ACK | TCP_PSH | TCP_URG,
        u16::MAX,
        TcpOpts::default(),
        URG_PAYLOAD,
    );

    // Patch the urgent pointer (TCP header bytes 18..20). Choose the
    // payload length — a common convention for URG pointer semantics —
    // though the engine's URG-drop gate doesn't inspect this field.
    let urg_pointer: u16 = URG_PAYLOAD.len() as u16;
    if urg_seg.len() < URG_PTR_OFFSET + 2 {
        return fail(format!(
            "built URG frame too short: len={} need>={}",
            urg_seg.len(),
            URG_PTR_OFFSET + 2
        ));
    }
    urg_seg[URG_PTR_OFFSET..URG_PTR_OFFSET + 2].copy_from_slice(&urg_pointer.to_be_bytes());
    recompute_tcp_csum(&mut urg_seg, TCP_HDR_OFFSET);

    if let Err(e) = h.eng.inject_rx_frame(&urg_seg) {
        return fail(format!("inject URG segment: {e:?}"));
    }

    // (1) `tcp.rx_urgent_dropped` must bump by exactly 1.
    let post_urg = counters.tcp.rx_urgent_dropped.load(Ordering::Relaxed);
    if post_urg != pre_urg + 1 {
        return fail(format!(
            "tcp.rx_urgent_dropped did not bump by 1: pre={pre_urg} post={post_urg}"
        ));
    }

    // (2) `tcp.recv_buf_delivered` must NOT bump (payload dropped, not
    // delivered). Using a counter delta rather than a direct recv-buffer
    // accessor avoids threading a new #[cfg(feature = "test-server")]
    // accessor through the engine for a one-bit assertion.
    let post_delivered = counters.tcp.recv_buf_delivered.load(Ordering::Relaxed);
    if post_delivered != pre_delivered {
        return fail(format!(
            "URG payload was delivered to recv buffer: \
             tcp.recv_buf_delivered pre={pre_delivered} post={post_delivered}"
        ));
    }

    // (3) Engine MUST NOT emit any frame (no URG-echo, no ACK, no RST).
    // The URG-drop branch in `established_rx` sets `TxAction::None` and
    // bails before any TX path runs; this check pins that behavior.
    let post_tx = drain_tx_frames();
    if !post_tx.is_empty() {
        // Peek at the first frame's flags for diagnosability. If any
        // frame carries URG we'd flag that explicitly; but any TX at
        // all on this path is a spec-behavior drift.
        let first = &post_tx[0];
        return fail(format!(
            "engine emitted {} frame(s) in response to URG segment; first-frame TCP flags byte = 0x{:02X}",
            post_tx.len(),
            tcp_flags_byte(first).unwrap_or(0)
        ));
    }

    ProbeResult {
        clause_id: "MUST-30/31",
        probe_name: "Urgent",
        status: ProbeStatus::Deviation("AD-A8-urg-dropped"),
        message: "URG segment dropped; tcp.rx_urgent_dropped bumped by 1; no delivery, no response \
                  — pins spec §6.4 AD-A8-urg-dropped".into(),
    }
}

fn fail(detail: String) -> ProbeResult {
    ProbeResult {
        clause_id: "MUST-30/31",
        probe_name: "Urgent",
        status: ProbeStatus::Fail(detail),
        message: String::new(),
    }
}

/// `Some(flags_byte)` from the TCP header at the standard L2+L3
/// offset; `None` when the frame is too short. `tcp_flags_byte` is
/// diagnostic-only (error-path); locating the TCP header via the
/// IP-IHL field keeps it tolerant of any IP-options frame shape.
fn tcp_flags_byte(frame: &[u8]) -> Option<u8> {
    if frame.len() < 14 + 20 + 20 {
        return None;
    }
    let ip_ihl = (frame[14] & 0x0f) as usize * 4;
    let tcp_off = 14 + ip_ihl;
    if frame.len() < tcp_off + 20 {
        return None;
    }
    Some(frame[tcp_off + 13])
}

/// Recompute the TCP checksum in place after mutating the TCP header /
/// payload of an Ethernet-framed IPv4/TCP packet built by
/// `test_packet::build_tcp_frame`.
///
/// Mirrors the helper in `probes::reserved` (same layout assumptions +
/// pseudo-header fold); kept per-probe to avoid a shared framing
/// submodule for two call sites. See `probes::reserved::recompute_tcp_csum`
/// for the rationale on pseudo-header construction — the logic is
/// identical because the Ethernet + IPv4 layout is identical across
/// all `build_tcp_frame`-sourced frames.
///
/// `tcp_hdr_offset` is the byte offset of the TCP header within `frame`
/// (always 14 + 20 = 34 for the test-server path; parameterized for
/// symmetry with the reserved.rs helper).
fn recompute_tcp_csum(frame: &mut [u8], tcp_hdr_offset: usize) {
    // Zero the csum field (TCP offset 16..18) before folding.
    frame[tcp_hdr_offset + 16] = 0;
    frame[tcp_hdr_offset + 17] = 0;

    // Extract src/dst IPs from the IPv4 header at bytes [14..34].
    let mut src_ip_bytes = [0u8; 4];
    src_ip_bytes.copy_from_slice(&frame[14 + 12..14 + 16]);
    let mut dst_ip_bytes = [0u8; 4];
    dst_ip_bytes.copy_from_slice(&frame[14 + 16..14 + 20]);

    let tcp_seg_len = (frame.len() - tcp_hdr_offset) as u16;

    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip_bytes);
    pseudo[4..8].copy_from_slice(&dst_ip_bytes);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    pseudo[10..12].copy_from_slice(&tcp_seg_len.to_be_bytes());

    let tcp_body = &frame[tcp_hdr_offset..];
    let csum = internet_checksum(&[&pseudo, tcp_body]);
    frame[tcp_hdr_offset + 16] = (csum >> 8) as u8;
    frame[tcp_hdr_offset + 17] = (csum & 0xff) as u8;
}

