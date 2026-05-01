//! Regression test for the `Engine::drop` ordering bug class
//! (commit `a1d2c56`: "drop-order: mbuf owners released after mempools").
//!
//! Background: the original `Engine` relied on Rust's struct-field forward
//! drop order to tear down its state. Mempool fields are declared early in
//! the struct, so they would `rte_mempool_free` first; the still-live
//! `flow_table` / `tx_pending_data` / `fault_injector` fields would then
//! drop their `MbufHandle`s, whose `Drop` calls
//! `shim_rte_mbuf_refcnt_update` against memzones already munmap'd. The
//! result was a SIGSEGV inside `Engine::drop`, observed in
//! `bench-ab-runner` run br32yx9a7 on 2026-04-28.
//!
//! The fix (`a1d2c56`) added an explicit `impl Drop for Engine` that
//! drains every mbuf-holding field in steps 1-4 BEFORE the mempools fall
//! out of scope (see `engine.rs:5751`).
//!
//! This test pins the contract:
//!   1. Open an engine, populate at least one of the four mbuf-holding
//!      categories (`flow_table` via an outstanding TX entry on
//!      `snd_retrans`), let the engine drop, assert no segfault.
//!   2. After the engine drops, allocate fresh mempools on the same EAL
//!      session under the SAME names that `Engine::new` uses
//!      (`rx_mp_{lcore}`, `tx_hdr_mp_{lcore}`, `tx_data_mp_{lcore}`). If
//!      pass-1 didn't `rte_mempool_free` its pools, these creates would
//!      fail with `EEXIST` — the assertion proves the cleanup walked
//!      every pool, not just the first.
//!
//! Note: we do NOT attempt to bring up a second `Engine` on the same
//! `port_id` after pass 1. `Engine::drop` step 4 calls
//! `rte_eth_dev_close`, which for hotplug-capable PMDs (incl. `net_tap`)
//! permanently releases the port — `rte_eth_dev_info_get` then returns
//! -ENODEV. That's correct DPDK semantics, not a drop-order bug; it
//! simply rules out the "two engines, one EAL session, same port" idiom
//! as a regression check.
//!
//! The OOO `recv.reorder.segments` arm is already covered by
//! `rx_reassembly_mempool_no_leak.rs`; we exercise the simpler in-order +
//! retrans + tx-pending arms here.
//!
//! Gated on `DPDK_NET_TEST_TAP=1` + sudo (matches the existing TAP-test
//! pattern; the engine refuses to bring up without a usable port).

use std::process::Command;
use std::thread;
use std::time::Duration;

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::mempool::Mempool;

const TAP_IFACE: &str = "resdtap18";
const OUR_IP: u32 = 0x0a_63_12_02; // 10.99.18.2
const PEER_IP: u32 = 0x0a_63_12_01; // 10.99.18.1
const PEER_PORT: u16 = 5018;

fn skip_if_not_tap() -> bool {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run (requires sudo for TAP vdev)");
        return true;
    }
    false
}

fn read_kernel_tap_mac(iface: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"));
    let mut out = [0u8; 6];
    for (i, part) in s.trim().split(':').enumerate() {
        out[i] = u8::from_str_radix(part, 16).expect("hex mac");
    }
    out
}

fn bring_up_tap(iface: &str) {
    let _ = Command::new("ip")
        .args(["link", "set", iface, "up"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.18.1/24", "dev", iface])
        .status();
}

#[test]
fn engine_drop_releases_resources_safely() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a10-engine-drop-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap18",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    // PASS 1: bring up engine, populate at least one mbuf-holding
    // category, drop. This is the segfault-class regression: prior to
    // commit `a1d2c56` the implicit Drop order would free mempools before
    // the flow_table / tx_pending_data fields' MbufHandles released
    // their refcounts, causing a use-after-free segfault inside
    // `shim_rte_mbuf_refcnt_update`.
    {
        let cfg = EngineConfig {
            port_id: 0,
            local_ip: OUR_IP,
            gateway_ip: PEER_IP,
            gateway_mac: kernel_mac,
            tcp_mss: 1460,
            max_connections: 4,
            tcp_msl_ms: 100,
            ..Default::default()
        };
        let engine = Engine::new(cfg).expect("engine 1");

        // Open a connection. There's no kernel listener on PEER_PORT —
        // that's fine; we just want SYN to land in `snd_retrans` and a
        // TcpConn to land in `flow_table`. The handshake won't complete,
        // but the conn state is enough to exercise the drop chain that
        // crashed pre-fix.
        let _conn = engine
            .connect(PEER_IP, PEER_PORT, 0)
            .expect("connect (no peer needed; we only need state to drop)");

        // Drive a few polls so the engine emits the SYN (populates
        // `snd_retrans`) and any RX path runs through `recv.bytes`.
        // The handshake won't complete but per-step state will populate.
        for _ in 0..20 {
            engine.poll_once();
            thread::sleep(Duration::from_millis(2));
        }

        // engine drops here at scope exit — must not segfault.
        eprintln!("[engine_drop_safe] pass 1: dropping engine 1...");
    }
    eprintln!("[engine_drop_safe] pass 1: engine 1 dropped cleanly (no segfault)");

    // PASS 2: directly verify pass-1's mempools were freed.
    //
    // `Engine::new` creates three named pools per `EngineConfig.lcore_id`
    // (default 0): `rx_mp_0`, `tx_hdr_mp_0`, `tx_data_mp_0`. DPDK pool
    // names are unique per-EAL-session — if pass-1's `Engine::drop`
    // didn't call `rte_mempool_free` on every pool, attempting to
    // create a fresh pool with the same name would fail (NULL return
    // from `rte_pktmbuf_pool_create`, EEXIST inside DPDK), surfaced
    // here as `Error::MempoolCreate`.
    //
    // We size these tiny — we only care about the name uniqueness
    // check, not actually using them.
    let names = ["rx_mp_0", "tx_hdr_mp_0", "tx_data_mp_0"];
    for name in names {
        let pool = Mempool::new_pktmbuf(name, 64, 0, 0, 256, 0).unwrap_or_else(|e| {
            panic!(
                "mempool '{name}' create failed after Engine drop: {e:?} \
                 — proves pass-1 didn't free its mempools cleanly"
            )
        });
        eprintln!("[engine_drop_safe] pass 2: re-allocated '{name}' OK ({pool:p})", pool = pool.as_ptr());
        // Drop the test pool immediately so re-runs of this test under
        // the same EAL session (e.g. `cargo test` re-execution) keep
        // the names available.
        drop(pool);
    }
    eprintln!("[engine_drop_safe] pass 2: every Engine pool re-allocatable — clean cleanup confirmed");
}
