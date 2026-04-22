//! AD-A7-rst-in-syn-rcvd-close-not-relisten promotion (A8 T13, S1(c)).
//!
//! RFC 9293 §3.10.7.4 First: on RST received in SYN_RCVD for a
//! passive-opened conn, the conn returns to the LISTEN state. A8 T12
//! (S1(b)) merely cleared `listen_slot.in_progress`; T13 extends that by
//! ALSO recording a synthetic `SYN_RCVD → LISTEN` state transition in
//! `counters.tcp.state_trans[3][1]` so the T8 audit sees the edge. The
//! listen slot remains live and accepts fresh SYNs — even on the SAME
//! 4-tuple — which T12 alone did not guarantee (T12 verified
//! different-tuple retries).
//!
//! Scope: `feature = "test-server"` only. Production build has no
//! listen path, so the spec §6 "Never transition to LISTEN in
//! production" invariant is preserved by construction.

#![cfg(feature = "test-server")]

mod common;

use std::sync::atomic::Ordering;

use common::{
    build_tcp_frame, build_tcp_syn, CovHarness, OUR_IP, PEER_IP,
};
use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::TCP_RST;
use dpdk_net_core::tcp_state::TcpState;
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

/// Verify a frame is a SYN-ACK (flags byte has SYN|ACK bits set). Mirrors
/// the helper in `ad_a7_slot_cleanup.rs`; duplicated here to keep the
/// T13 test self-contained rather than extending `common` for a single
/// reuse.
fn is_syn_ack(frame: &[u8]) -> bool {
    if frame.len() < 14 + 20 + 20 {
        return false;
    }
    let ip_ihl = (frame[14] & 0x0f) as usize * 4;
    let tcp_off = 14 + ip_ihl;
    if frame.len() < tcp_off + 14 {
        return false;
    }
    let flags = frame[tcp_off + 13];
    (flags & 0x12) == 0x12 // SYN|ACK = 0x02 | 0x10
}

/// Drive listen → inject peer SYN → drain SYN-ACK. Returns the emitted
/// SYN-ACK frame.
fn listen_and_drive_first_syn(h: &mut CovHarness, peer_iss: u32) -> Vec<u8> {
    let _listen_h = h.eng.listen(OUR_IP, 5555).expect("listen");
    let _ = drain_tx_frames();
    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, 40_000, OUR_IP, 5555, peer_iss, 1460);
    h.eng.inject_rx_frame(&syn).expect("inject peer SYN");
    let tx = drain_tx_frames();
    assert_eq!(tx.len(), 1, "exactly one SYN-ACK expected after peer SYN");
    tx.into_iter().next().unwrap()
}

#[test]
fn rst_in_syn_rcvd_returns_to_listen_and_accepts_same_tuple_retry() {
    let mut h = CovHarness::new();
    let peer_iss = 0x10000000;
    let _synack = listen_and_drive_first_syn(&mut h, peer_iss);

    // Peer sends RST in-window instead of the final ACK → SYN_RCVD
    // "returns to LISTEN" per RFC 9293 §3.10.7.4 First.
    set_virt_ns(2_000_000);
    let rst = build_tcp_frame(
        PEER_IP,
        40_000,
        OUR_IP,
        5555,
        peer_iss.wrapping_add(1), // seq == rcv_nxt
        0,
        TCP_RST,
        0,
        TcpOpts::default(),
        &[],
    );
    h.eng.inject_rx_frame(&rst).expect("inject peer RST");
    let _ = drain_tx_frames(); // no wire frame expected; drain defensively

    // (a) state_trans[SynReceived][Listen] must have incremented.
    // T12 alone would have left cell [3][1] at zero (only [3][0] fires).
    let syn_rcvd_idx = TcpState::SynReceived as usize;
    let listen_idx = TcpState::Listen as usize;
    let closed_idx = TcpState::Closed as usize;
    let ctrs = h.eng.counters();
    assert_eq!(
        ctrs.tcp.state_trans[syn_rcvd_idx][listen_idx].load(Ordering::Relaxed),
        1,
        "S1(c): SYN_RCVD→LISTEN must be recorded in state_trans[3][1]"
    );
    // Option-B design choice: the RST arm skips the SYN_RCVD→Closed
    // transition when a re-listen fires, so [3][0] stays at zero for
    // this branch. A stray [3][0] bump would indicate a double-fire bug.
    assert_eq!(
        ctrs.tcp.state_trans[syn_rcvd_idx][closed_idx].load(Ordering::Relaxed),
        0,
        "S1(c): SYN_RCVD→Closed must NOT fire when re-listen path takes over"
    );

    // (b) A fresh SYN with the SAME 4-tuple + a new ISS is accepted.
    // T12's test verifies different-tuple retries; T13 additionally
    // requires the SAME-tuple retry to succeed, which is the unique
    // observable signature of "return to LISTEN" (vs. "just cleaned up").
    let _ = drain_tx_frames();
    set_virt_ns(3_000_000);
    let peer_iss2 = 0x20000000;
    let syn2 = build_tcp_syn(PEER_IP, 40_000, OUR_IP, 5555, peer_iss2, 1460);
    h.eng.inject_rx_frame(&syn2).expect("inject same-tuple SYN retry");
    let tx = drain_tx_frames();
    assert_eq!(
        tx.len(),
        1,
        "same-4-tuple SYN after RST-in-SYN_RCVD must succeed (return-to-LISTEN); got {} frames",
        tx.len()
    );
    assert!(
        is_syn_ack(&tx[0]),
        "same-tuple SYN retry must receive a SYN-ACK, not RST"
    );
}
