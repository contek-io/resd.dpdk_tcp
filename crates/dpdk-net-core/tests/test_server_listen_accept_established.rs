//! A7 Task 5: minimal server-FSM passive-open integration test.
//!
//! Drives, end-to-end, the LISTEN → SYN_RCVD → ESTABLISHED transition
//! through the engine's test-server in-memory rig (no real NIC).
//!
//! Flow:
//!   set_virt_ns(0) → eal_init(test_eal_args) → Engine::new(test_server_config)
//!   eng.listen(OUR_IP, 5555) → listen_h
//!   set_virt_ns(1_000_000); inject SYN → drain TX; parse one SYN-ACK
//!   set_virt_ns(2_000_000); inject final ACK → assert no TX response
//!   accept_next(listen_h) == Some(conn_h)
//!   state_of(conn_h) == Established

#![cfg(feature = "test-server")]

mod common;

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine};
use dpdk_net_core::tcp_state::TcpState;

#[test]
fn listen_accept_established_full_handshake() {
    set_virt_ns(0);
    eal_init(&common::test_eal_args()).expect("eal_init");
    let eng = Engine::new(common::test_server_config()).expect("Engine::new");

    let listen_h = eng.listen(common::OUR_IP, 5555).expect("listen");

    // Step 1: inbound SYN.
    set_virt_ns(1_000_000);
    let peer_iss: u32 = 0x1111_0000;
    let syn = common::build_tcp_syn(
        common::PEER_IP,
        40_000,
        common::OUR_IP,
        5555,
        peer_iss,
        1460,
    );
    // Drain any stale frames that might be lingering from prior test runs.
    let _ = dpdk_net_core::test_tx_intercept::drain_tx_frames();
    eng.inject_rx_frame(&syn).expect("inject SYN");

    let frames = dpdk_net_core::test_tx_intercept::drain_tx_frames();
    assert_eq!(
        frames.len(),
        1,
        "expected exactly one SYN-ACK frame, got {}",
        frames.len()
    );

    let (server_iss, ack_val) = common::parse_syn_ack(&frames[0])
        .expect("parse SYN-ACK");
    assert_eq!(ack_val, peer_iss.wrapping_add(1), "SYN-ACK ack must be peer_iss + 1");

    // Step 2: final ACK from peer completing the handshake.
    set_virt_ns(2_000_000);
    let final_ack = common::build_tcp_ack(
        common::PEER_IP,
        40_000,
        common::OUR_IP,
        5555,
        peer_iss.wrapping_add(1),
        server_iss.wrapping_add(1),
    );
    eng.inject_rx_frame(&final_ack).expect("inject ACK");

    let post_frames = dpdk_net_core::test_tx_intercept::drain_tx_frames();
    assert_eq!(
        post_frames.len(),
        0,
        "ESTABLISHED transition must not emit a TX frame (got {})",
        post_frames.len()
    );

    // Step 3: accept queue populated.
    let conn_h = eng.accept_next(listen_h).expect("accept_next yields conn");
    // Step 4: state is ESTABLISHED.
    assert_eq!(
        eng.state_of(conn_h),
        Some(TcpState::Established),
        "post-handshake conn must be Established"
    );
}
