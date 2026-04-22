//! A7 Task 6: passive close path — peer FINs first, server transitions
//! ESTABLISHED → CLOSE_WAIT on receipt of the FIN, LAST_ACK once the
//! server calls `close_conn`, and finally CLOSED (slot released) once
//! the peer's ACK for our FIN arrives. No TIME_WAIT on the passive side.
//!
//! Drives end-to-end through the test-server in-memory rig (no real NIC).
//!
//! Flow:
//!   set_virt_ns(0) → eal_init → Engine::new → listen
//!   drive_passive_handshake → (conn_h, our_iss)
//!   set_virt_ns(10ms); inject peer FIN → assert one TX frame (bare ACK)
//!       and state_of(conn_h) == CloseWait
//!   set_virt_ns(20ms); eng.close_conn(conn_h) → assert one TX frame
//!       (server FIN); state_of(conn_h) == LastAck; parse our_fin_seq
//!   set_virt_ns(30ms); inject peer's final ACK → assert state_of(conn_h)
//!       is None (slot released, no TIME_WAIT on passive side)

#![cfg(feature = "test-server")]

mod common;

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine};
use dpdk_net_core::tcp_state::TcpState;
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

#[test]
fn passive_close_path() {
    set_virt_ns(0);
    eal_init(&common::test_eal_args()).expect("eal_init");
    let eng = Engine::new(common::test_server_config()).expect("Engine::new");
    let lh = eng.listen(common::OUR_IP, 5555).expect("listen");

    // Phase 1: three-way handshake → ESTABLISHED.
    let (conn_h, our_iss) = common::drive_passive_handshake(&eng, lh);
    // Any stray TX from the handshake is already drained inside the helper.

    // Phase 2: peer FINs first.
    set_virt_ns(10_000_000);
    let fin = common::build_tcp_fin(
        common::PEER_IP,
        40_000,
        common::OUR_IP,
        5555,
        /*seq*/ 0x10000001,
        /*ack*/ our_iss.wrapping_add(1),
    );
    eng.inject_rx_frame(&fin).expect("inject peer FIN");

    // Server emits exactly one TX frame — the bare ACK that covers the
    // FIN. CLOSE_WAIT is the expected post-FIN state.
    let after_fin = drain_tx_frames();
    assert_eq!(
        after_fin.len(),
        1,
        "expected exactly one bare ACK after peer FIN, got {}",
        after_fin.len()
    );
    assert_eq!(
        eng.state_of(conn_h),
        Some(TcpState::CloseWait),
        "post-peer-FIN state must be CLOSE_WAIT"
    );

    // Phase 3: server closes → FIN egress, LAST_ACK.
    set_virt_ns(20_000_000);
    eng.close_conn(conn_h).expect("close_conn");

    let our_fin_frames = drain_tx_frames();
    assert_eq!(
        our_fin_frames.len(),
        1,
        "expected exactly one server-FIN TX frame after close_conn, got {}",
        our_fin_frames.len()
    );
    let (our_fin_seq, _ack) = common::parse_tcp_seq_ack(&our_fin_frames[0]);
    assert_eq!(
        eng.state_of(conn_h),
        Some(TcpState::LastAck),
        "post-close_conn state must be LAST_ACK"
    );

    // Phase 4: peer's ACK of our FIN → CLOSED, slot released.
    set_virt_ns(30_000_000);
    let final_ack = common::build_tcp_ack(
        common::PEER_IP,
        40_000,
        common::OUR_IP,
        5555,
        /*seq*/ 0x10000002,
        /*ack*/ our_fin_seq.wrapping_add(1),
    );
    eng.inject_rx_frame(&final_ack).expect("inject peer ACK of our FIN");

    // No TIME_WAIT on the passive side — the slot must be gone.
    assert!(
        eng.state_of(conn_h).is_none(),
        "conn slot expected released after LAST_ACK + peer final ACK; got {:?}",
        eng.state_of(conn_h)
    );
}
