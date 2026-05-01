//! AD-A7-listen-slot-leak-on-failed-handshake promotion (S1(b) / A8 T12).
//!
//! Every SYN_RCVD→Closed transition must clear the listen slot's
//! `in_progress` so subsequent SYNs on the same listen can land. Without
//! the fix, `handle_inbound_syn_listen` keeps rejecting with RST because
//! `in_progress.is_some()` stays true forever after a failed handshake.
//!
//! Three failure modes must all clear the slot:
//!   1. Bad-ACK in SYN_RCVD → RST + Closed (tcp_input.rs:395–401).
//!   2. RST in SYN_RCVD → Closed (tcp_input.rs:373–380).
//!   3. SYN-retrans budget exhaust → ETIMEDOUT (on_syn_retrans_fire at
//!      engine.rs:2773 — T11's S1(a) landing that triggers force-close).
//!
//! Each test drives one failure mode and then issues a *fresh* SYN from a
//! different peer 4-tuple; the listen slot must accept the fresh SYN
//! (engine emits a SYN-ACK). The pre-fix behavior wedges the slot: the
//! fresh SYN would be rejected with RST+ACK.

#![cfg(feature = "test-server")]

mod common;

use common::{
    build_tcp_frame, build_tcp_syn, parse_syn_ack, CovHarness, OUR_IP, PEER_IP,
};
use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::{TCP_ACK, TCP_RST};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

/// Default engine `tcp_initial_rto_us` is 5_000 µs = 5 ms = 5_000_000 ns.
const INITIAL_RTO_NS: u64 = 5_000_000;

/// Peer-2 (second-handshake) IP + port. Distinct from `PEER_IP` so the
/// two handshakes land on different 4-tuples but the same listen slot.
const PEER2_IP: u32 = 0x0a_63_02_03; // 10.99.2.3
const PEER2_PORT: u16 = 40_001;

/// Drive listen → inject peer SYN → drain SYN-ACK. Returns the emitted
/// SYN-ACK frame for follow-up helpers that need its `(our_iss, ack)`.
fn listen_and_drive_first_syn(h: &mut CovHarness) -> Vec<u8> {
    let _listen_h = h.eng.listen(OUR_IP, 5555).expect("listen");
    let _ = drain_tx_frames();
    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, 40_000, OUR_IP, 5555, 0x10000000, 1460);
    h.eng.inject_rx_frame(&syn).expect("inject peer SYN");
    let tx = drain_tx_frames();
    assert_eq!(tx.len(), 1, "exactly one SYN-ACK expected after peer 1 SYN");
    tx.into_iter().next().unwrap()
}

/// Issue a fresh SYN from peer-2 onto the same listen slot.
fn inject_peer2_syn(h: &mut CovHarness) {
    let _ = drain_tx_frames();
    let syn = build_tcp_syn(PEER2_IP, PEER2_PORT, OUR_IP, 5555, 0x20000000, 1460);
    h.eng.inject_rx_frame(&syn).expect("inject peer-2 SYN");
}

/// Verify a frame is a SYN-ACK (flags byte has SYN|ACK bits set).
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

#[test]
fn listen_slot_cleared_after_bad_ack_in_syn_rcvd() {
    let mut h = CovHarness::new();
    let _ = listen_and_drive_first_syn(&mut h);

    // Peer sends ACK with wrong ack number (outside SND.UNA..SND.NXT).
    // `handle_syn_received` returns TxAction::Rst + new_state=Closed;
    // without S1(b), the listen slot's `in_progress` stays set forever.
    set_virt_ns(2_000_000);
    let bad_ack = build_tcp_frame(
        PEER_IP,
        40_000,
        OUR_IP,
        5555,
        0x10000001, // seq == rcv_nxt
        0xdeadbeef, // ack WAY past snd_nxt
        TCP_ACK,
        u16::MAX,
        TcpOpts::default(),
        &[],
    );
    h.eng.inject_rx_frame(&bad_ack).expect("inject bad ACK");
    let _ = drain_tx_frames(); // drain the RST we emit

    // Peer-2 fresh SYN from a DIFFERENT 4-tuple, on the same listen slot.
    // S1(b) must have cleared `in_progress`, so this must succeed.
    inject_peer2_syn(&mut h);
    let tx = drain_tx_frames();
    assert_eq!(
        tx.len(),
        1,
        "fresh SYN must get a SYN-ACK after listen-slot cleanup (got {} frames)",
        tx.len()
    );
    assert!(
        is_syn_ack(&tx[0]),
        "emitted frame must be SYN-ACK, not RST"
    );
    assert!(
        parse_syn_ack(&tx[0]).is_some(),
        "emitted frame must parse as SYN-ACK"
    );
}

#[test]
fn listen_slot_cleared_after_rst_in_syn_rcvd() {
    let mut h = CovHarness::new();
    let _synack = listen_and_drive_first_syn(&mut h);

    // Peer sends RST instead of final ACK → SYN_RCVD → Closed.
    set_virt_ns(2_000_000);
    let rst = build_tcp_frame(
        PEER_IP,
        40_000,
        OUR_IP,
        5555,
        0x10000001, // seq == rcv_nxt (in-window)
        0,
        TCP_RST,
        0,
        TcpOpts::default(),
        &[],
    );
    h.eng.inject_rx_frame(&rst).expect("inject peer RST");
    let _ = drain_tx_frames(); // no frame expected, but drain defensively

    // Fresh SYN from peer-2 must succeed — slot must be empty.
    inject_peer2_syn(&mut h);
    let tx = drain_tx_frames();
    assert_eq!(
        tx.len(),
        1,
        "fresh SYN must get a SYN-ACK after RST-in-SYN_RCVD cleanup (got {} frames)",
        tx.len()
    );
    assert!(is_syn_ack(&tx[0]), "emitted frame must be SYN-ACK");
}

#[test]
fn listen_slot_cleared_after_syn_retrans_budget_exhaust() {
    // T11 S1(a) + T12 S1(b) composed: passive SYN-ACK retransmits
    // through the budget; on budget exhaust (`> 3` fires), the fire
    // handler calls `force_close_etimedout` which must clear the listen
    // slot's `in_progress` so a fresh SYN can land.
    let mut h = CovHarness::new();
    let _ = listen_and_drive_first_syn(&mut h);

    // Drive the full budget window — 4 fires at 5/10/20/40 ms backoff.
    // Pump in 1 ms steps so each fire lands under the timer-wheel
    // advance cap. 200 ms well past the full budget envelope.
    for i in 2..=200 {
        let now_ns = (i as u64) * 1_000_000;
        set_virt_ns(now_ns);
        let _ = h.eng.pump_timers(now_ns);
        let _ = drain_tx_frames();
    }

    // Fresh SYN must succeed — slot must be cleared after ETIMEDOUT.
    inject_peer2_syn(&mut h);
    let tx = drain_tx_frames();
    assert_eq!(
        tx.len(),
        1,
        "fresh SYN must get a SYN-ACK after budget-exhaust cleanup (got {} frames)",
        tx.len()
    );
    assert!(is_syn_ack(&tx[0]), "emitted frame must be SYN-ACK");
}

// Silence dead-code warning for `INITIAL_RTO_NS` — kept for docs / future
// scenarios even though the budget-exhaust loop uses fixed 1 ms steps.
#[allow(dead_code)]
const _INITIAL_RTO_NS_UNUSED: u64 = INITIAL_RTO_NS;
