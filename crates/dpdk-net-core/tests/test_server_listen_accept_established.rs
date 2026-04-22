//! A7 Task 5: minimal server-FSM passive-open integration test.
//!
//! Drives, end-to-end, the LISTEN → SYN_RCVD → ESTABLISHED transition
//! through the engine's test-server in-memory rig (no real NIC). The
//! SYN/SYN-ACK/ACK sequence is encapsulated in
//! `common::drive_passive_handshake`; this test asserts the core claim
//! that after the handshake the accepted conn is in `Established`.

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
    let (conn_h, _our_iss) = common::drive_passive_handshake(&eng, listen_h);

    assert_eq!(
        eng.state_of(conn_h),
        Some(TcpState::Established),
        "post-handshake conn must be Established"
    );
}
