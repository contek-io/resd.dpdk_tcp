//! A7 Task 12: virtual-clock + timer-wheel determinism self-test.
//!
//! Exercises the test-server in-memory rig's ability to deterministically
//! fire an RTO-driven SYN retransmit by advancing the thread-local
//! virtual clock past the retransmit deadline without ever injecting the
//! peer's SYN-ACK. Proves: (1) the virt-clock swap in `now_ns` is
//! effective for the retrans scheduling path, and (2) `pump_timers`
//! dispatches fired timers through the same per-kind handlers
//! `advance_timer_wheel` uses. A precondition for every packetdrill
//! script that advances `now_ns` past a timer deadline — if the
//! virtual-time retrans fires are broken at the Rust level, every
//! loss-scenario script fails.

#![cfg(feature = "test-server")]

use dpdk_net_core::clock::{now_ns, set_virt_ns};
use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

const OUR_IP: u32 = 0x0a_63_02_02; // 10.99.2.2
const PEER_IP: u32 = 0x0a_63_02_01; // 10.99.2.1
const PEER_PORT: u16 = 40_000;
const LOCAL_PORT_HINT: u16 = 50_000;

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
fn syn_retransmit_at_virtual_rto_deadline() {
    set_virt_ns(0);
    eal_init(&test_eal_args()).expect("eal_init");
    let eng = Engine::new(test_server_config()).expect("Engine::new");

    // Drain any lingering frames from concurrent tests in the same process.
    let _ = drain_tx_frames();

    // Active-open: this emits the initial SYN and arms the SYN retrans
    // timer. With `EngineConfig::default()` values `tcp_initial_rto_us`
    // = `tcp_min_rto_us` = 5_000 µs (= 5 ms = 5_000_000 ns), so the
    // initial arm fires at t=5ms.
    let _ch = eng
        .connect(PEER_IP, PEER_PORT, LOCAL_PORT_HINT)
        .expect("connect");

    // Drain the initial SYN so the retransmit is the only post-pump frame.
    let initial = drain_tx_frames();
    assert_eq!(
        initial.len(),
        1,
        "initial SYN expected in TX queue, got {} frames",
        initial.len()
    );

    // Advance virtual time past the 5ms RTO deadline. Pumping the timer
    // wheel must fire the SYN retrans handler, which calls back into
    // `emit_syn` and pushes a fresh SYN onto the TX intercept queue.
    set_virt_ns(5_500_000); // 5.5 ms — 500 µs past the initial RTO.
    let fired = eng.pump_timers(now_ns());
    assert!(
        fired >= 1,
        "pump_timers must fire at least the SYN retrans timer at t=5.5ms; fired={fired}"
    );

    let frames = drain_tx_frames();
    assert!(
        !frames.is_empty(),
        "SYN retransmit frame expected at virtual RTO deadline, got 0 frames"
    );
}
