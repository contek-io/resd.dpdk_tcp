#![cfg(feature = "test-server")]
//! A7 Task 7: active close from server side.
//! Server calls close() first. FIN_WAIT_1 → FIN_WAIT_2 on ACK of FIN
//! → TIME_WAIT on peer FIN. TIME_WAIT is bounded by existing timer.

mod common;
use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine};
use dpdk_net_core::tcp_state::TcpState;
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

#[test]
fn active_close_from_server_side() {
    set_virt_ns(0);
    eal_init(&common::test_eal_args()).unwrap();
    let eng = Engine::new(common::test_server_config()).unwrap();
    let lh = eng.listen(common::OUR_IP, 5555).unwrap();

    let (conn_h, _our_iss) = common::drive_passive_handshake(&eng, lh);
    let _ = drain_tx_frames();

    // Server closes first.
    set_virt_ns(10_000_000);
    eng.close_conn(conn_h).unwrap();
    assert_eq!(eng.state_of(conn_h).unwrap(), TcpState::FinWait1);

    // Drain the server's FIN.
    let fin_frames = drain_tx_frames();
    assert_eq!(fin_frames.len(), 1);
    let (our_fin_seq, _) = common::parse_tcp_seq_ack(&fin_frames[0]);

    // Peer ACKs the FIN → FIN_WAIT_2.
    set_virt_ns(20_000_000);
    let ack = common::build_tcp_ack(
        common::PEER_IP,
        40000,
        common::OUR_IP,
        5555,
        /*seq*/ 0x10000001,
        /*ack*/ our_fin_seq.wrapping_add(1),
    );
    eng.inject_rx_frame(&ack).unwrap();
    assert_eq!(eng.state_of(conn_h).unwrap(), TcpState::FinWait2);

    // Peer FINs → TIME_WAIT.
    set_virt_ns(30_000_000);
    let peer_fin = common::build_tcp_fin(
        common::PEER_IP,
        40000,
        common::OUR_IP,
        5555,
        /*seq*/ 0x10000001,
        /*ack*/ our_fin_seq.wrapping_add(1),
    );
    eng.inject_rx_frame(&peer_fin).unwrap();
    assert_eq!(eng.state_of(conn_h).unwrap(), TcpState::TimeWait);
}
