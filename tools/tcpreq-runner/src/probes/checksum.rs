//! ZeroChecksum probe — RFC 9293 §3.1 (MUST-2/3).
//! Ported from tcpreq/tests/checksum.py::ZeroChecksumTest.
//!
//! The probe crafts a SYN with a correctly-computed TCP checksum via
//! `test_packet::build_tcp_syn`, then overwrites the 2-byte TCP
//! checksum field with zeros. On injection the engine MUST drop the
//! segment:
//!   - no TX frame emitted (no SYN-ACK, no RST);
//!   - `tcp.rx_bad_csum` counter bumps by exactly 1.
//!
//! This pins the Layer-A equivalence claim recorded in
//! `tools/tcpreq-runner/SKIPPED.md` for MUST-2/3: if the engine ever
//! started accepting a zero-csum SYN, the claim would be wrong and the
//! regression must be fixed at
//! `crates/dpdk-net-core/src/l3_ip.rs::validate_tcp_csum` (the path
//! `parse_segment` calls in `tcp_input.rs`) rather than by relaxing
//! this probe.
//!
//! Note on edge cases: a well-formed SYN whose true TCP checksum
//! happens to fold to 0x0000 (≈1-in-65 536 odds for a random input)
//! would technically pass validation even after the zero-field
//! overwrite. The canonical values used here (`PEER_ISS = 0x1000`,
//! fixed ports, ISN, and MSS option) produce a non-zero checksum, so
//! the overwrite reliably corrupts the segment.

use std::sync::atomic::Ordering;

use crate::{ProbeResult, ProbeStatus, TcpreqHarness, OUR_IP, PEER_IP};

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::test_server::test_packet::build_tcp_syn;
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

const LOCAL_PORT: u16 = 5555;
const PEER_PORT: u16 = 40_000;
/// Peer ISS seed. Canonical small value; folds to a non-zero checksum
/// together with the rest of the SYN header + MSS option, so zeroing
/// the csum field reliably yields a mismatch.
const PEER_ISS: u32 = 0x0000_1000;
const PEER_MSS: u16 = 1460;

/// L2 Ethernet header (14) + IPv4 header (20, no IP options) — the
/// test-server `build_segment` always emits this exact layout. TCP
/// header starts at byte 34; the TCP checksum field sits at TCP +
/// 16..18.
const TCP_HDR_OFFSET: usize = 14 + 20;
const TCP_CSUM_OFFSET: usize = TCP_HDR_OFFSET + 16;

pub fn zero_checksum() -> ProbeResult {
    let h = TcpreqHarness::new();

    if let Err(e) = h.eng.listen(OUR_IP, LOCAL_PORT) {
        return fail(format!("listen: {e:?}"));
    }

    // Snapshot `tcp.rx_bad_csum` BEFORE injecting so we can assert the
    // +1 delta is attributable solely to this probe's zero-csum SYN.
    let counters = h.eng.counters();
    let pre_bad_csum = counters.tcp.rx_bad_csum.load(Ordering::Relaxed);

    // Craft a valid SYN with MSS=1460 via the wire-identical test_packet
    // helper; `build_tcp_syn` sets a correct TCP checksum. Then we zero
    // the 2-byte checksum field at TCP header offset 16..18 — deliberately
    // leaving the folded sum stale so `parse_segment`'s software verify
    // returns `TcpParseError::Csum` and the engine bumps `rx_bad_csum`.
    set_virt_ns(1_000_000);
    let mut syn = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, LOCAL_PORT, PEER_ISS, PEER_MSS);

    if syn.len() < TCP_CSUM_OFFSET + 2 {
        return fail(format!(
            "built SYN too short to patch TCP checksum: len={} need>={}",
            syn.len(),
            TCP_CSUM_OFFSET + 2
        ));
    }
    syn[TCP_CSUM_OFFSET] = 0;
    syn[TCP_CSUM_OFFSET + 1] = 0;

    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail(format!("inject zero-csum SYN: {e:?}"));
    }

    // (1) Engine MUST NOT emit any frame in response. A SYN-ACK, an ACK,
    // or an RST here would indicate the zero-csum SYN slipped past the
    // validator — i.e. the Layer-A claim is wrong.
    let post_tx = drain_tx_frames();
    if !post_tx.is_empty() {
        let first = &post_tx[0];
        return fail(format!(
            "engine emitted {} frame(s) in response to zero-csum SYN; expected silent drop. \
             first TX frame (up to 32 bytes): {:02x?}",
            post_tx.len(),
            &first[..std::cmp::min(first.len(), 32)]
        ));
    }

    // (2) `tcp.rx_bad_csum` MUST bump by exactly 1. This is the
    // affirmative side of the assertion — a silent no-op (zero TX +
    // zero counter bump) would mean the segment was dropped for some
    // other reason (e.g. a routing / IP-check failure) and the csum
    // path never ran.
    let post_bad_csum = counters.tcp.rx_bad_csum.load(Ordering::Relaxed);
    if post_bad_csum != pre_bad_csum + 1 {
        return fail(format!(
            "tcp.rx_bad_csum did not bump by 1: pre={pre_bad_csum} post={post_bad_csum}"
        ));
    }

    ProbeResult {
        clause_id: "MUST-2/3",
        probe_name: "ZeroChecksum",
        status: ProbeStatus::Pass,
        message: "zero-csum SYN dropped; tcp.rx_bad_csum bumped by 1; no TX response"
            .into(),
    }
}

fn fail(detail: String) -> ProbeResult {
    ProbeResult {
        clause_id: "MUST-2/3",
        probe_name: "ZeroChecksum",
        status: ProbeStatus::Fail(detail),
        message: String::new(),
    }
}
