//! A7 Task 12: Rust-level round-trip self-test for the test-FFI.
//!
//! Exercises the test-server in-memory rig without going through the
//! `packetdrill` shim binary. Proves the `inject_rx_frame` → engine →
//! `drain_tx_frames` hook is wired correctly at the Rust API level: we
//! listen, inject a bare SYN, drain the engine's response, and verify
//! the SYN-ACK shape. A precondition for any shim-binary test — if the
//! in-memory frame roundtrip breaks at the Rust level, every packetdrill
//! script likewise fails. Keeping this check at the Rust level gives us
//! a deterministic failure mode without the cost (or noise) of a
//! shim-binary process fork.

#![cfg(feature = "test-server")]

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::test_server::test_packet::{build_tcp_syn, parse_syn_ack};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

const OUR_IP: u32 = 0x0a_63_02_02; // 10.99.2.2
const PEER_IP: u32 = 0x0a_63_02_01; // 10.99.2.1
const PEER_PORT: u16 = 40_000;
const OUR_PORT: u16 = 5555;
const PEER_ISS: u32 = 0x10_00_00_00;

fn test_eal_args() -> Vec<&'static str> {
    vec![
        "dpdk-net-test-server",
        "--in-memory",
        "--no-pci",
        "-l",
        "0-1",
        "--log-level=3",
    ]
}

fn test_server_config() -> EngineConfig {
    EngineConfig {
        port_id: u16::MAX,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        ..Default::default()
    }
}

#[test]
fn syn_in_synack_out() {
    set_virt_ns(0);
    eal_init(&test_eal_args()).expect("eal_init");
    let eng = Engine::new(test_server_config()).expect("Engine::new");

    let _lh = eng.listen(OUR_IP, OUR_PORT).expect("listen");

    // Drain any lingering frames from concurrent tests in the same process.
    let _ = drain_tx_frames();

    // t=1ms: inject a bare SYN with an MSS option (matches the shape
    // the engine's `handle_inbound_syn_listen` expects).
    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, OUR_PORT, PEER_ISS, 1460);
    eng.inject_rx_frame(&syn).expect("inject SYN");

    // Exactly one SYN-ACK must land in the TX intercept queue.
    let frames = drain_tx_frames();
    assert_eq!(
        frames.len(),
        1,
        "exactly one SYN-ACK expected, got {} frames",
        frames.len()
    );

    // The parsed SYN-ACK's ack field must equal PEER_ISS + 1.
    let (_our_iss, ack) = parse_syn_ack(&frames[0]).expect("parse SYN-ACK");
    assert_eq!(
        ack,
        PEER_ISS.wrapping_add(1),
        "SYN-ACK ack must be peer_iss + 1"
    );
}
