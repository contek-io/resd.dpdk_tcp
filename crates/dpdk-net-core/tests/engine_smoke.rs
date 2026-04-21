//! Integration test that brings up an engine against a TAP virtual device
//! (no real NIC needed). Runs only when DPDK_NET_TEST_TAP=1 in env.

#[test]
fn engine_lifecycle_on_tap() {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run");
        return;
    }

    // EAL args: in-memory, use vdev TAP so no real NIC is required.
    let args = [
        "dpdk-net-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=dpdktap0",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    dpdk_net_core::engine::eal_init(&args).expect("EAL init");

    let cfg = dpdk_net_core::engine::EngineConfig {
        port_id: 0,
        ..Default::default()
    };
    let engine = dpdk_net_core::engine::Engine::new(cfg).expect("engine new");

    // Poll a few times on an idle link; expect 0 packets.
    for _ in 0..10 {
        engine.poll_once();
    }
    let c = engine.counters();
    assert!(c.poll.iters.load(std::sync::atomic::Ordering::Relaxed) >= 10);
    // rx_pkts may be >0 if stray ARP arrived; that's fine, we just don't assert 0.
    drop(engine);
}
