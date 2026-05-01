//! A10 deferred-fix follow-up: comprehensive long-soak stability test.
//!
//! Goal — for the 24×7 trading deployment that doesn't restart, prove the
//! engine maintains all five resource invariants in lock-step under
//! sustained workload. Single-iter or single-invariant tests
//! (`rx_mempool_no_leak`, `connect_close_cycle`, `no_alloc_hotpath_audit`)
//! catch one regression class each. This test catches the *combination* —
//! a leak that hides in one pool because it's compensated by drain in
//! another, or a slow timer-wheel slot grow under arm/cancel churn that
//! would surface only after thousands of seconds in production.
//!
//! Invariants asserted post-soak (all 5 in one go):
//!   * RX mempool drift           ≤ 32  (existing class, broader iter count)
//!   * TX-data mempool drift      ≤ 32  (NEW — control-frame leak class)
//!   * TX-hdr mempool drift       ≤ 32  (NEW — data-frame leak class)
//!   * timer_wheel slots growth   ≤ 64  (NEW — slot-recycle regression)
//!   * events_queue_high_water    < 100 (NEW — drain cadence is healthy)
//!   * events_dropped             == 0  (NEW — soft-cap was never exceeded)
//!
//! Per-1000-iter samples are eprintln!'d so a regression's "cliff curve"
//! (when the metric starts deviating) is visible in CI logs without
//! needing to repro locally.
//!
//! Modeled on `rx_mempool_no_leak.rs`. Gated on `DPDK_NET_TEST_TAP=1` +
//! sudo (matches the existing TAP-test pattern).

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap23";
const OUR_IP: u32 = 0x0a_63_17_02; // 10.99.23.2
const PEER_IP: u32 = 0x0a_63_17_01; // 10.99.23.1
const PEER_IP_STR: &str = "10.99.23.1";
const OUR_IP_STR: &str = "10.99.23.2";
const PEER_PORT: u16 = 5023;
const ITERATIONS: u32 = 100_000;
const PAYLOAD: usize = 128;

// All four mempools are intended to balance to the lcore-cache + NIC
// ring residue, which empirically lands well under 32 mbufs.
const POOL_DRIFT_TOLERANCE: i64 = 32;
// Timer-wheel slots are NEVER deallocated — `slots_len()` reports the
// all-time peak in-flight depth. A leak that adds slots without
// recycling them via `free_list` would push this monotonically upward
// over the 100k-iter run; healthy operation reaches a steady-state
// peak within the first few thousand iters and stays there.
//
// The assertion uses a TWO-baseline approach to separate "warm-up
// peak" growth (legitimate) from "post-warm-up" growth (regression
// signal). The warm-up baseline is sampled at `WARMUP_ITERS` after the
// connection has stabilized; the assertion is `slots_at_end -
// slots_at_warmup ≤ 64`. Empirically, post-warmup growth is in single
// digits (sometimes from cascade events that sweep a previously-empty
// level into use). Allow 64 to absorb a transient cascade-driven
// spike without flagging.
const TIMER_WHEEL_POST_WARMUP_GROWTH_TOLERANCE: usize = 64;
const WARMUP_ITERS: u32 = 5_000;
// Soft-cap events queue should drain on every poll; high-water in a
// healthy run stays well below 100 even under 100k iters.
const EVENTS_HIGH_WATER_TOLERANCE: u64 = 100;

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
        .args(["addr", "add", "10.99.23.1/24", "dev", iface])
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

#[derive(Debug, Clone, Copy)]
struct Sample {
    iter: u32,
    rx_avail: u32,
    tx_data_avail: u32,
    tx_hdr_avail: u32,
    timer_slots: usize,
    events_high_water: u64,
    events_dropped: u64,
}

fn snapshot(engine: &Engine, iter: u32) -> Sample {
    let rx_avail = unsafe {
        dpdk_net_sys::shim_rte_mempool_avail_count(engine.rx_mempool_ptr())
    };
    let tx_data_avail = unsafe {
        dpdk_net_sys::shim_rte_mempool_avail_count(engine.tx_data_mempool_ptr())
    };
    let tx_hdr_avail = unsafe {
        dpdk_net_sys::shim_rte_mempool_avail_count(engine.tx_hdr_mempool_ptr())
    };
    let c = engine.counters();
    Sample {
        iter,
        rx_avail,
        tx_data_avail,
        tx_hdr_avail,
        timer_slots: engine.timer_wheel_slots_len(),
        events_high_water: c.obs.events_queue_high_water.load(Ordering::Relaxed),
        events_dropped: c.obs.events_dropped.load(Ordering::Relaxed),
    }
}

fn log_sample(tag: &str, s: &Sample) {
    eprintln!(
        "[long-soak] {} iter={} rx={} tx_data={} tx_hdr={} timer_slots={} \
         events_hw={} events_dropped={}",
        tag, s.iter, s.rx_avail, s.tx_data_avail, s.tx_hdr_avail,
        s.timer_slots, s.events_high_water, s.events_dropped
    );
}

#[test]
fn long_soak_100k_rtt_all_invariants_stable() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a10-long-soak-stability",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap23",
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
        tcp_msl_ms: 100,
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();
    pin_arp(TAP_IFACE, OUR_IP_STR, &mac_hex(our_mac));

    // Echo peer on the kernel side. Single long-lived connection; kernel
    // reads PAYLOAD, writes PAYLOAD, ITERATIONS times.
    let listener = TcpListener::bind((PEER_IP_STR, PEER_PORT)).expect("bind echo");
    let (peer_done_tx, peer_done_rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        sock.set_nodelay(true).ok();
        let mut buf = [0u8; PAYLOAD];
        for _ in 0..ITERATIONS {
            if sock.read_exact(&mut buf).is_err() {
                break;
            }
            if sock.write_all(&buf).is_err() {
                break;
            }
        }
        let _ = peer_done_tx.send(());
    });

    // BASELINE snapshot: all five metrics, AFTER engine bring-up but
    // BEFORE workload. The connection isn't open yet, so any RX-ring +
    // bring-up mbufs are already accounted for.
    let baseline = snapshot(&engine, 0);
    log_sample("baseline", &baseline);
    eprintln!(
        "[long-soak] pool sizes: rx_mempool_size={}",
        engine.rx_mempool_size()
    );

    // Open the long-lived conn.
    let conn = engine.connect(PEER_IP, PEER_PORT, 0).expect("connect");
    let connect_deadline = Instant::now() + Duration::from_secs(10);
    let mut connected = false;
    while Instant::now() < connect_deadline && !connected {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            if matches!(ev, InternalEvent::Connected { conn: c, .. } if *c == conn) {
                connected = true;
            }
        });
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "connect timeout");

    let payload = vec![0xABu8; PAYLOAD];
    // Warm-up snapshot is captured separately below at iter ==
    // WARMUP_ITERS so we can separate "peak-in-flight" growth (warmup
    // climb) from "post-warmup leak" growth (regression signal).
    let mut warmup: Option<Sample> = None;
    let loop_start = Instant::now();
    for i in 0..ITERATIONS {
        // Per-1000-iter sample so the cliff curve is visible. The
        // sample call is cheap (3 atomic loads + a borrow + a Vec::len).
        if i > 0 && i.is_multiple_of(1_000) {
            let s = snapshot(&engine, i);
            log_sample("sample", &s);
        }
        if i == WARMUP_ITERS {
            let s = snapshot(&engine, i);
            log_sample("warmup", &s);
            warmup = Some(s);
        }

        // Send the request.
        let mut sent: u32 = 0;
        let send_deadline = Instant::now() + Duration::from_secs(5);
        while (sent as usize) < PAYLOAD {
            match engine.send_bytes(conn, &payload[sent as usize..]) {
                Ok(n) => sent = sent.saturating_add(n),
                Err(e) => {
                    if Instant::now() >= send_deadline {
                        panic!("send_bytes iter {i}: {e:?}");
                    }
                }
            }
            engine.poll_once();
            engine.drain_events(16, |_ev, _| {});
        }

        // Drain echo: wait for PAYLOAD bytes echoed back.
        let mut recv_total: u32 = 0;
        let iter_deadline = Instant::now() + Duration::from_secs(5);
        while (recv_total as usize) < PAYLOAD {
            engine.poll_once();
            engine.drain_events(32, |ev, _| {
                if let InternalEvent::Readable { total_len, conn: c, .. } = ev {
                    if *c == conn {
                        recv_total = recv_total.saturating_add(*total_len);
                    }
                }
            });
            assert!(Instant::now() < iter_deadline, "iter {i} drain timeout");
        }
    }
    let loop_elapsed = loop_start.elapsed();

    // Wait for the kernel echo thread to finish.
    let _ = peer_done_rx.recv_timeout(Duration::from_secs(5));

    // Final settle — pump for 50 polls so any in-flight mbufs (NIC RX
    // ring, lcore cache, FIN/ACK in flight) drain before snapshot.
    for _ in 0..50 {
        engine.poll_once();
        engine.drain_events(32, |_ev, _| {});
        thread::sleep(Duration::from_millis(2));
    }

    let post = snapshot(&engine, ITERATIONS);
    log_sample("post", &post);
    eprintln!(
        "[long-soak] {} iters in {:?} ({:.3}ms/iter)",
        ITERATIONS,
        loop_elapsed,
        (loop_elapsed.as_millis() as f64) / (ITERATIONS as f64)
    );

    // ---- Invariant 1: RX mempool drift ≤ 32 ----
    let rx_drift = (baseline.rx_avail as i64) - (post.rx_avail as i64);
    eprintln!(
        "[long-soak] rx drift = {rx_drift} (baseline {} post {})",
        baseline.rx_avail, post.rx_avail
    );
    assert!(
        rx_drift.abs() <= POOL_DRIFT_TOLERANCE,
        "RX mempool drift {rx_drift} exceeds tolerance ±{POOL_DRIFT_TOLERANCE} \
         (baseline {}, post {}, {ITERATIONS} iters) — RX leak class",
        baseline.rx_avail, post.rx_avail
    );

    // ---- Invariant 2: TX-data mempool drift ≤ 32 ----
    let tx_data_drift = (baseline.tx_data_avail as i64) - (post.tx_data_avail as i64);
    eprintln!(
        "[long-soak] tx_data drift = {tx_data_drift} (baseline {} post {})",
        baseline.tx_data_avail, post.tx_data_avail
    );
    assert!(
        tx_data_drift.abs() <= POOL_DRIFT_TOLERANCE,
        "TX-data mempool drift {tx_data_drift} exceeds tolerance ±{POOL_DRIFT_TOLERANCE} \
         (baseline {}, post {}, {ITERATIONS} iters) — TX-data leak class",
        baseline.tx_data_avail, post.tx_data_avail
    );

    // ---- Invariant 3: TX-hdr mempool drift ≤ 32 ----
    let tx_hdr_drift = (baseline.tx_hdr_avail as i64) - (post.tx_hdr_avail as i64);
    eprintln!(
        "[long-soak] tx_hdr drift = {tx_hdr_drift} (baseline {} post {})",
        baseline.tx_hdr_avail, post.tx_hdr_avail
    );
    assert!(
        tx_hdr_drift.abs() <= POOL_DRIFT_TOLERANCE,
        "TX-hdr mempool drift {tx_hdr_drift} exceeds tolerance ±{POOL_DRIFT_TOLERANCE} \
         (baseline {}, post {}, {ITERATIONS} iters) — TX-hdr leak class",
        baseline.tx_hdr_avail, post.tx_hdr_avail
    );

    // ---- Invariant 4: timer-wheel slots POST-WARMUP growth ≤ 64 ----
    // Slots are never freed; the wheel reports all-time peak depth.
    // Healthy operation reaches a steady-state peak within the first
    // few thousand iters and stays there. A regression that adds slots
    // without recycling would push the count monotonically upward
    // *past* the warmup peak. We compare warmup-snapshot vs final and
    // assert the post-warmup window is essentially flat.
    let warmup = warmup.expect("warmup snapshot captured at WARMUP_ITERS");
    let timer_post_warmup_growth = post.timer_slots.saturating_sub(warmup.timer_slots);
    eprintln!(
        "[long-soak] timer_slots post-warmup growth = {timer_post_warmup_growth} \
         (warmup {} post {}); pre-warmup peak = {}",
        warmup.timer_slots, post.timer_slots, warmup.timer_slots
    );
    assert!(
        timer_post_warmup_growth <= TIMER_WHEEL_POST_WARMUP_GROWTH_TOLERANCE,
        "timer_wheel slots grew {timer_post_warmup_growth} after the \
         {WARMUP_ITERS}-iter warmup (warmup {}, post {}) — exceeds \
         tolerance {TIMER_WHEEL_POST_WARMUP_GROWTH_TOLERANCE}; likely \
         slot-recycle regression",
        warmup.timer_slots, post.timer_slots
    );

    // ---- Invariant 5a: events_queue_high_water reasonable ----
    assert!(
        post.events_high_water < EVENTS_HIGH_WATER_TOLERANCE,
        "events_queue_high_water = {} exceeds tolerance {} — \
         drain cadence is too slow under {ITERATIONS} iters",
        post.events_high_water, EVENTS_HIGH_WATER_TOLERANCE
    );

    // ---- Invariant 5b: events_dropped == 0 ----
    assert_eq!(
        post.events_dropped, 0,
        "events_dropped = {} > 0 over {ITERATIONS} iters — soft-cap \
         overflow occurred; observability lost coverage",
        post.events_dropped
    );

    // Forensic gate: zero mbufs hit the unexpected-refcnt-drop guard.
    let drop_unexpected = engine
        .counters()
        .tcp
        .mbuf_refcnt_drop_unexpected
        .load(Ordering::Relaxed);
    assert_eq!(
        drop_unexpected, 0,
        "mbuf_refcnt_drop_unexpected fired {drop_unexpected}× during \
         {ITERATIONS} iters — leak signal"
    );
}
