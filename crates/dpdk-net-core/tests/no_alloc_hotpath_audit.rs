#![cfg(feature = "bench-alloc-audit")]

//! A6.6+A6.7 Task 20: iteration-bounded no-alloc-on-hot-path audit.
//!
//! Companion to `bench_alloc_hotpath.rs` (A6.5 Task 10). The earlier
//! test runs a wall-clock-bounded measurement window (30 s); this test
//! runs an iteration-bounded window (10_000 iters of `send_bytes` +
//! `poll_once` drain post-warmup) and asserts strict
//! `(alloc_delta, free_delta) == (0, 0)` over that window.
//!
//! The two together give complementary coverage:
//! - bench_alloc_hotpath: long wall-clock window catches slow leaks.
//! - this test: deterministic iteration count gives a tighter,
//!   reproducible signal on every run that the standard `send +
//!   poll_once + drain_events` cycle is alloc-free.
//!
//! Build + run:
//!   DPDK_NET_TEST_TAP=1 sudo -E cargo test -p dpdk-net-core \
//!     --features bench-alloc-audit --test no_alloc_hotpath_audit \
//!     -- --nocapture
//!
//! ## Setup-helper duplication note
//!
//! Per Task 20 plan, this test was supposed to share helpers with
//! `bench_alloc_hotpath.rs` via `tests/common/mod.rs`. The existing
//! `tests/common/mod.rs` is a different shared module
//! (`TapPeerMode` for fault-injection scenarios) with no engine-setup
//! helpers. Rather than retro-fit a second purpose onto that module
//! (or refactor `bench_alloc_hotpath.rs` into shared helpers — risky
//! during phase A6.6+A6.7's tight scope), the engine-setup pattern is
//! duplicated inline here. Source-of-truth for the pattern is
//! `bench_alloc_hotpath.rs:65-217`. If a third allocator-instrumented
//! TAP test gets added, factoring should happen then.
//!
//! Subnet `10.99.20.0/24` and iface `resdtap20` are unique to this
//! test to avoid colliding with existing TAP tests
//! (`resdtap2`/`resdtap6`/`resdtap10`).

use dpdk_net_core::bench_alloc_audit::{snapshot, CountingAllocator, BACKTRACE_ENABLED};
use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;
use std::io::Read as IoRead;
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[global_allocator]
static A: CountingAllocator = CountingAllocator;

const TAP_IFACE: &str = "resdtap20";
const OUR_IP: u32 = 0x0a_63_14_02; // 10.99.20.2
const PEER_IP: u32 = 0x0a_63_14_01; // 10.99.20.1
const PEER_PORT: u16 = 5020;

// Iteration counts. Both are well above the steady-state saturation
// point for engine scratches (recv mempool, tx pending-data ring,
// SmallVec spills, prune_mbufs_scratch, rack_lost_idxs_scratch,
// timer-wheel buckets). Empirically, the wall-clock companion test
// uses ~10s warmup at ~31K iters/s ≈ 310k iters; 1000 here is safe
// because we drain the event queue every poll, but if any future
// scratch needs more growth we'd see allocations in the measurement
// window and the test will fail loudly.
const WARMUP_ITERS: u64 = 1_000;
const MEASURE_ITERS: u64 = 10_000;

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
    let _ = Command::new("ip").args(["link", "set", iface, "up"]).status();
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.20.1/24", "dev", iface])
        .status();
}

fn pin_arp(iface: &str, ip: &str, mac: &str) {
    let _ = Command::new("ip")
        .args([
            "neigh", "replace", ip, "lladdr", mac, "dev", iface, "nud", "permanent",
        ])
        .status();
}

fn mac_hex(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Kernel-side sink server: accept-once + read-and-discard. Same
/// rationale as `bench_alloc_hotpath::spawn_sink_server` — discarding
/// (not echoing) keeps the kernel's RX window wide so our TX path runs
/// continuously.
fn spawn_sink_server(stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = TcpListener::bind("10.99.20.1:5020").expect("listener bind");
        listener
            .set_nonblocking(true)
            .expect("listener set_nonblocking");
        let stream = loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();
        drop(listener);
        let mut buf = [0u8; 65536];
        let mut s = stream;
        while !stop.load(Ordering::Relaxed) {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => { /* discard */ }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
    })
}

#[test]
fn poll_once_and_send_bytes_allocate_zero_post_warmup() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "resd-net-a6-6-7-no-alloc-audit",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap20",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    let cfg = EngineConfig {
        port_id: 0,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: kernel_mac,
        tcp_mss: 1460,
        max_connections: 8,
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();
    pin_arp(TAP_IFACE, "10.99.20.2", &mac_hex(our_mac));

    let stop = Arc::new(AtomicBool::new(false));
    let server = spawn_sink_server(Arc::clone(&stop));
    thread::sleep(Duration::from_millis(200));

    // HANDSHAKE — pre-measurement, so its allocations (per-conn one-
    // shot setup, timer-wheel insert) are excluded from the gate.
    let handle = engine.connect(PEER_IP, PEER_PORT, 0).expect("connect");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            if matches!(ev, InternalEvent::Connected { conn, .. } if *conn == handle) {
                connected = true;
            }
        });
        thread::sleep(Duration::from_millis(5));
    }
    assert!(connected, "did not receive CONNECTED within deadline");

    // WARMUP — grow all scratches to steady-state. Per the plan, 1000
    // iters is the target. We pace lightly for the same reason as the
    // wall-clock companion: bursty unmetered TX can trip the kernel
    // TAP driver into RST'ing.
    let payload = [0xa5u8; 1400];
    let mut warmup_sent: u64 = 0;
    for i in 0..WARMUP_ITERS {
        if let Ok(n) = engine.send_bytes(handle, &payload) {
            warmup_sent += n as u64;
        }
        engine.poll_once();
        engine.drain_events(32, |_ev, _| {});
        if i % 64 == 63 {
            thread::sleep(Duration::from_micros(50));
        }
    }
    let warmup_state = {
        let ft = engine.flow_table();
        ft.get(handle).map(|c| c.state)
    };
    let c0 = engine.counters();
    eprintln!(
        "[no-alloc-audit] warmup end: sent={} state={:?} \
         rx_rst={} tx_rst={} conn_rst={} conn_close={} \
         tx_rto={} tx_retrans={} rx_fin={} tx_fin={}",
        warmup_sent,
        warmup_state,
        c0.tcp.rx_rst.load(Ordering::Relaxed),
        c0.tcp.tx_rst.load(Ordering::Relaxed),
        c0.tcp.conn_rst.load(Ordering::Relaxed),
        c0.tcp.conn_close.load(Ordering::Relaxed),
        c0.tcp.tx_rto.load(Ordering::Relaxed),
        c0.tcp.tx_retrans.load(Ordering::Relaxed),
        c0.tcp.rx_fin.load(Ordering::Relaxed),
        c0.tcp.tx_fin.load(Ordering::Relaxed),
    );
    assert!(
        warmup_sent > 0,
        "warmup produced zero accepted-bytes via send_bytes"
    );
    assert!(
        warmup_state.is_some(),
        "handle has no conn after warmup (peer closed or reaped)"
    );

    BACKTRACE_ENABLED.store(1, Ordering::Relaxed);

    // SNAPSHOT pre-measurement.
    let (a0, f0, b0) = snapshot();

    let c = engine.counters();
    let tx_data_pre = c.tcp.tx_data.load(Ordering::Relaxed);
    let rx_ack_pre = c.tcp.rx_ack.load(Ordering::Relaxed);
    let poll_iters_pre = c.poll.iters.load(Ordering::Relaxed);
    let tx_retrans_pre = c.tcp.tx_retrans.load(Ordering::Relaxed);
    let rx_rst_pre = c.tcp.rx_rst.load(Ordering::Relaxed);
    let tx_rst_pre = c.tcp.tx_rst.load(Ordering::Relaxed);

    // MEASURE — exactly MEASURE_ITERS iterations of the standard
    // hot-path cycle: send_bytes → poll_once → drain_events. Same
    // light pacing as warmup.
    let mut measure_sent: u64 = 0;
    for i in 0..MEASURE_ITERS {
        if let Ok(n) = engine.send_bytes(handle, &payload) {
            measure_sent += n as u64;
        }
        engine.poll_once();
        engine.drain_events(32, |_ev, _| {});
        if i % 64 == 63 {
            thread::sleep(Duration::from_micros(50));
        }
    }

    let tx_data_delta = c.tcp.tx_data.load(Ordering::Relaxed) - tx_data_pre;
    let rx_ack_delta = c.tcp.rx_ack.load(Ordering::Relaxed) - rx_ack_pre;
    let poll_iters_delta = c.poll.iters.load(Ordering::Relaxed) - poll_iters_pre;
    let tx_retrans_delta = c.tcp.tx_retrans.load(Ordering::Relaxed) - tx_retrans_pre;
    let rx_rst_delta = c.tcp.rx_rst.load(Ordering::Relaxed) - rx_rst_pre;
    let tx_rst_delta = c.tcp.tx_rst.load(Ordering::Relaxed) - tx_rst_pre;

    let (a1, f1, b1) = snapshot();
    BACKTRACE_ENABLED.store(0, Ordering::Relaxed);

    let conn_gone = {
        let ft = engine.flow_table();
        ft.get(handle).is_none()
    };
    let alloc_delta = a1.saturating_sub(a0);
    let free_delta = f1.saturating_sub(f0);
    let byte_delta = b1.saturating_sub(b0);

    let peer_rst_during_measure = conn_gone || rx_rst_delta > 0 || tx_rst_delta > 0;
    if peer_rst_during_measure {
        eprintln!(
            "[no-alloc-audit] WARNING: peer RST during measurement. The \
             alloc-delta gate (the audit's core property) still applies; \
             the free-delta gate is relaxed because per-connection \
             teardown is out-of-scope per design spec §1."
        );
    }

    eprintln!(
        "[no-alloc-audit] steady-state: {} measure iters, {} sent-bytes, \
         tx_data+={}, rx_ack+={}, poll_iters+={}, \
         tx_retrans+={}, rx_rst+={}, tx_rst+={} | \
         allocs={}, frees={}, bytes={}",
        MEASURE_ITERS,
        measure_sent,
        tx_data_delta,
        rx_ack_delta,
        poll_iters_delta,
        tx_retrans_delta,
        rx_rst_delta,
        tx_rst_delta,
        alloc_delta,
        free_delta,
        byte_delta
    );

    // Tear down so the test doesn't leave state behind.
    engine.close_conn(handle).ok();
    let teardown_end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < teardown_end {
        engine.poll_once();
        thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    drop(engine);
    let _ = server.join();

    // Sanity: hot path actually ran during the measurement window.
    assert!(
        tx_data_delta > 0 || rx_ack_delta > 0,
        "hot path did not run during measurement (tx_data+={}, rx_ack+={})",
        tx_data_delta,
        rx_ack_delta
    );
    // CORE PROPERTY: zero allocs across measurement window.
    assert_eq!(
        alloc_delta, 0,
        "{} hot-path allocations across {} measurement iters",
        alloc_delta, MEASURE_ITERS
    );
    assert_eq!(byte_delta, 0, "{} bytes allocated", byte_delta);
    // Free gate only applies to the clean (no-RST) path. Per-conn
    // teardown frees mbufs; spec §1 places those out of scope.
    if peer_rst_during_measure {
        eprintln!(
            "[no-alloc-audit] NOTE: kernel peer RST during measurement \
             surfaced {} per-conn-teardown frees (out of scope per spec §1). \
             alloc_delta=0 so hot-path property still holds.",
            free_delta
        );
    } else {
        assert_eq!(
            free_delta, 0,
            "{} hot-path frees across {} measurement iters",
            free_delta, MEASURE_ITERS
        );
    }
}
