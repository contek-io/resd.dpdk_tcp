//! A10 deferred-fix Stage B+ regression test: TX-side mempool drift
//! under sustained retransmits.
//!
//! Targets a specific class of refcount-imbalance regressions on the
//! retransmit path — most notably the chain-fail rollback in
//! `engine.rs:5838`:
//!
//! ```ignore
//! unsafe { sys::shim_rte_pktmbuf_free(hdr_mbuf) };
//! unsafe { sys::shim_rte_mbuf_refcnt_update(data_mbuf_ptr, -1) };
//! ```
//!
//! That pair must run together — if the `refcnt_update(-1)` is dropped,
//! every chain-fail rollback leaks one TX-data mbuf. Under sustained RTOs
//! the `tx_data_mempool` slowly drains and (eventually) the engine starves
//! its TX queue. This test forces enough RTO retransmits that any such
//! per-RTO imbalance manifests as observable mempool drift, without
//! needing to wait minutes for the leak to become large.
//!
//! ## Forcing RTOs
//!
//! Kernel-side `tc qdisc netem loss N%` on the TAP iface drops a fraction
//! of outgoing data segments deterministically. With `tcp_min_rto_us`
//! tuned LOW (2ms) and a moderate loss rate (5%), the engine's RTO timer
//! fires repeatedly across a 500-iter request/response loop, exercising
//! the full retransmit code path including the chain-fail rollback.
//!
//! ## Assertions
//!   1. `tx_retrans` (or `tx_rto`) > MIN_RETRANS_OBSERVATIONS — proves
//!      we actually exercised the retransmit branch. Without this gate
//!      the drift assertion would pass vacuously if the loss rate
//!      degenerated to zero (e.g., a future netem semantics change).
//!   2. `rx_mempool` drift within tolerance (regression-detector for the
//!      RX path under heavy retrans-induced churn).
//!   3. `tx_data_mempool` drift within tolerance — primary signal for
//!      the targeted retrans-rollback regression class.
//!   4. `tx_hdr_mempool` drift within tolerance — sister signal for the
//!      header-mbuf side of the chain-fail rollback.
//!
//! Gated on `DPDK_NET_TEST_TAP=1` + sudo (matches the existing TAP-test
//! pattern).

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap25";
const OUR_IP: u32 = 0x0a_63_19_02; // 10.99.25.2
const PEER_IP: u32 = 0x0a_63_19_01; // 10.99.25.1
const PEER_PORT: u16 = 5025;

// 1500 iters x 128B is enough to drive RTOs at 5% loss while keeping the
// overall wall-clock under 60s (per task budget). With a 2ms min RTO the
// engine retransmits within 2-4ms of a drop, so each drop is amortized
// fast enough that we don't stall the kernel echo thread for long.
//
// Iter count tuned so that under the deliberate-leak regression
// (Phase-4 +1 → +2 in engine.rs near line 5820), the resulting mempool
// drift is well above POOL_DRIFT_TOLERANCE. Empirically: 500 iters →
// ~90 retrans → drift ~19 (BELOW tolerance 32 — vacuously passes!).
// 1500 iters → ~270 retrans → drift ~57+ (catches the leak).
const ITERATIONS: u32 = 1500;
const PAYLOAD: usize = 128;
const POOL_DRIFT_TOLERANCE: i64 = 32;
// The kernel echo thread reads/writes ITERATIONS pairs sequentially. With
// 5% packet loss in BOTH directions, end-to-end iter completion gets
// expensive — we lose data segments and ACKs alike, plus the kernel's TCP
// retransmit timer kicks in for echoes too. Cap the per-iter wait at 5s
// so a stuck iter doesn't blow past the test budget.
const ITER_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
// Defence-in-depth gate: prove the netem loss spec actually drove the
// retransmit path. With loss=5% and 500 iters of single-segment 128B
// requests/responses, expected retrans count is on the order of ~50-150
// per direction. A regression that turns netem loss into a no-op would
// produce zero retransmits and silently pass the drift assertion (which
// vacuously passes when no retrans fired). Set the gate at 50 to leave
// headroom for kernel-level netem variance while still catching a true
// no-op.
const MIN_RETRANS_OBSERVATIONS: u64 = 50;

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
        .args(["addr", "add", "10.99.25.1/24", "dev", iface])
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

/// RAII guard for `tc qdisc add dev <iface> root netem <spec>` on the
/// local kernel TAP iface. Modeled on `rx_mempool_no_leak_ooo_netem.rs`'s
/// `NetemGuard`. Drop best-effort issues `tc qdisc del dev <iface> root`
/// so a panic in the test body doesn't leave the iface with a stale
/// netem qdisc that would corrupt subsequent runs.
struct NetemGuard {
    iface: &'static str,
}

impl NetemGuard {
    fn apply(iface: &'static str, spec: &str) -> Self {
        // Best-effort: pre-clean any leftover qdisc from a previous run
        // that crashed before its Drop fired.
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "root"])
            .stderr(std::process::Stdio::null())
            .status();
        let mut args = vec!["qdisc", "add", "dev", iface, "root", "netem"];
        args.extend(spec.split_whitespace());
        let status = Command::new("tc")
            .args(&args)
            .status()
            .expect("invoke tc");
        assert!(
            status.success(),
            "tc qdisc add netem failed (exit {:?}); is iproute2 installed and is the test running as sudo?",
            status.code()
        );
        eprintln!("[tx-retrans] applied netem on {iface}: {spec}");
        Self { iface }
    }
}

impl Drop for NetemGuard {
    fn drop(&mut self) {
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", self.iface, "root"])
            .stderr(std::process::Stdio::null())
            .status();
        eprintln!("[tx-retrans] removed netem on {}", self.iface);
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    rx_avail: u32,
    tx_data_avail: u32,
    tx_hdr_avail: u32,
    tx_retrans: u64,
    tx_rto: u64,
}

fn snapshot(engine: &Engine) -> Sample {
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
        rx_avail,
        tx_data_avail,
        tx_hdr_avail,
        tx_retrans: c.tcp.tx_retrans.load(Ordering::Relaxed),
        tx_rto: c.tcp.tx_rto.load(Ordering::Relaxed),
    }
}

#[test]
fn tx_mempool_no_leak_under_sustained_retrans() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a10-tx-retrans-no-leak",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap25",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    // Apply netem loss 5% AFTER `eal_init` because the TAP iface is
    // created by the `net_tap0` vdev. Spec: `loss 5%` drops 5% of egress
    // packets uniformly. On a request/response 128B workload at MSS=1460
    // each request/response is one segment, so each drop is one full
    // round-trip's worth of data — the engine's RTO timer fires before
    // the next request can complete. With `tcp_min_rto_us=2000` (2ms)
    // we get fast RTO bursts.
    let _netem_guard = NetemGuard::apply(TAP_IFACE, "loss 5%");

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    let cfg = EngineConfig {
        port_id: 0,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: kernel_mac,
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        // Aggressive RTO: 2ms minimum + 2ms initial. With netem dropping
        // 5% of segments, this firing rate guarantees the retransmit
        // path runs ≥50 times across 500 iters.
        tcp_min_rto_us: 2_000,
        tcp_initial_rto_us: 2_000,
        // Default tcp_max_retrans_count=15 — leave alone. We don't want
        // to disconnect the conn under sustained RTO; we want the
        // retrans path to keep firing. 15 retries per RTO before giving
        // up gives plenty of headroom even if a single iter takes
        // unusually long to recover.
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();
    pin_arp(TAP_IFACE, "10.99.25.2", &mac_hex(our_mac));

    // Echo peer on the kernel side. Reads PAYLOAD, writes PAYLOAD,
    // ITERATIONS times. With 5% loss the kernel side will also retransmit
    // (kernel's own TCP RTO), so effective throughput is reduced — that's
    // fine; the test goal is mempool drift under retrans, not iter rate.
    let listener = TcpListener::bind(("10.99.25.1", PEER_PORT)).expect("bind echo");
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

    // Snapshot baselines for all three mempools + retrans counters
    // AFTER engine bring-up but BEFORE the workload.
    let baseline = snapshot(&engine);
    eprintln!(
        "[tx-retrans] baseline rx={} tx_data={} tx_hdr={} tx_retrans={} tx_rto={}",
        baseline.rx_avail,
        baseline.tx_data_avail,
        baseline.tx_hdr_avail,
        baseline.tx_retrans,
        baseline.tx_rto,
    );
    eprintln!(
        "[tx-retrans] pool sizes: rx_mempool={}",
        engine.rx_mempool_size()
    );

    let conn = engine.connect(PEER_IP, PEER_PORT, 0).expect("connect");

    // Pump until Connected. With 5% loss the SYN handshake itself may
    // need a retrans — extend the connect deadline accordingly.
    let connect_deadline = Instant::now() + Duration::from_secs(15);
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
    assert!(connected, "connect timeout under 5% loss");

    let payload = vec![0xCDu8; PAYLOAD];
    let loop_start = Instant::now();
    let mut iters_completed = 0u32;
    for i in 0..ITERATIONS {
        // Send the request. With 5% loss `send_bytes` itself is local
        // (just enqueue) so it doesn't fail per-loss; the segment goes
        // out, gets dropped by netem, the RTO timer fires, and a retrans
        // segment goes out from the engine's retransmit path. We only
        // see the loss as an iter latency hit.
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

        // Drain echo: wait for PAYLOAD bytes echoed back. With 5% loss in
        // both directions, individual iters can take many RTOs to
        // complete. We bound per-iter at ITER_DRAIN_TIMEOUT — if an iter
        // truly stalls beyond that, we break out, accept that iter as
        // "not-completed", and continue. The mempool-drift assertion
        // doesn't require iter-perfection; it requires bounded refcount.
        let mut recv_total: u32 = 0;
        let iter_deadline = Instant::now() + ITER_DRAIN_TIMEOUT;
        let mut iter_stalled = false;
        while (recv_total as usize) < PAYLOAD {
            engine.poll_once();
            engine.drain_events(32, |ev, _| {
                if let InternalEvent::Readable { total_len, conn: c, .. } = ev {
                    if *c == conn {
                        recv_total = recv_total.saturating_add(*total_len);
                    }
                }
            });
            if Instant::now() >= iter_deadline {
                iter_stalled = true;
                break;
            }
        }
        if iter_stalled {
            // Iter stalled — skip remaining iters to avoid blowing past
            // budget. The retransmit path has fired plenty by now (see
            // the MIN_RETRANS_OBSERVATIONS gate); break out and let the
            // assertions evaluate what actually happened.
            eprintln!(
                "[tx-retrans] iter {i} stalled past {:?}; stopping early at {} iters",
                ITER_DRAIN_TIMEOUT, iters_completed
            );
            break;
        }
        iters_completed += 1;
    }
    let loop_elapsed = loop_start.elapsed();
    eprintln!(
        "[tx-retrans] {iters_completed}/{ITERATIONS} iters completed in {loop_elapsed:?}"
    );

    // Wait for the kernel echo thread to finish (or time out).
    let _ = peer_done_rx.recv_timeout(Duration::from_secs(15));

    // Remove netem BEFORE the final drain so any in-flight retransmits
    // can complete cleanly without being lost. NetemGuard's Drop will
    // also tear it down at the end of the test, but pulling it manually
    // here lets the engine quiesce naturally.
    drop(_netem_guard);

    // Final settle. With sustained RTO bursts there's likely in-flight
    // retransmit mbufs; give the engine extra cycles to release them.
    for _ in 0..200 {
        engine.poll_once();
        engine.drain_events(64, |_ev, _| {});
        thread::sleep(Duration::from_millis(5));
    }

    let post = snapshot(&engine);
    let rx_drift = (baseline.rx_avail as i64) - (post.rx_avail as i64);
    let tx_data_drift = (baseline.tx_data_avail as i64) - (post.tx_data_avail as i64);
    let tx_hdr_drift = (baseline.tx_hdr_avail as i64) - (post.tx_hdr_avail as i64);
    let retrans_delta = post.tx_retrans.saturating_sub(baseline.tx_retrans);
    let rto_delta = post.tx_rto.saturating_sub(baseline.tx_rto);
    eprintln!(
        "[tx-retrans] post rx={} tx_data={} tx_hdr={} tx_retrans={} tx_rto={}",
        post.rx_avail, post.tx_data_avail, post.tx_hdr_avail,
        post.tx_retrans, post.tx_rto,
    );
    eprintln!(
        "[tx-retrans] drift rx={rx_drift} tx_data={tx_data_drift} tx_hdr={tx_hdr_drift} \
         retrans_delta={retrans_delta} rto_delta={rto_delta}"
    );

    // ---- Gate 1: prove the retrans path actually fired ----
    // tx_retrans counts every retransmit (RTO, RACK, TLP, SYN-retrans).
    // With 5% loss + 2ms min RTO over hundreds of iters, RTO retrans
    // should fire ≥ MIN_RETRANS_OBSERVATIONS times. If it doesn't, either
    // the netem spec degenerated to a no-op or the test loop didn't run
    // long enough — fail loudly so the regression-detector doesn't
    // silently pass on a vacuous run.
    assert!(
        retrans_delta > MIN_RETRANS_OBSERVATIONS,
        "tx_retrans delta {retrans_delta} ≤ MIN {MIN_RETRANS_OBSERVATIONS} — \
         retransmit path did not fire enough times to exercise this regression \
         test. Either the netem `loss 5%` spec is no-op'd or the test loop \
         is too short. Adjust loss rate or iteration count. \
         (rto_delta={rto_delta}, iters_completed={iters_completed})"
    );

    // ---- Gate 2: RX mempool drift within tolerance ----
    // The RX path shouldn't leak under retrans-induced churn either.
    // This is a regression-detector sister-assertion to the primary
    // TX assertions below.
    assert!(
        rx_drift.abs() <= POOL_DRIFT_TOLERANCE,
        "RX mempool drift {rx_drift} exceeds tolerance ±{POOL_DRIFT_TOLERANCE} \
         under {retrans_delta} retransmits (baseline {}, post {}) — RX leak class",
        baseline.rx_avail, post.rx_avail
    );

    // ---- Gate 3: TX-data mempool drift within tolerance ----
    // PRIMARY TARGET: this is the assertion that catches a regression in
    // `engine.rs:5838` (chain-fail rollback `refcnt_update(-1)` skipped)
    // or any other refcount-imbalance on the data-mbuf side of the
    // retransmit path.
    assert!(
        tx_data_drift.abs() <= POOL_DRIFT_TOLERANCE,
        "TX-data mempool drift {tx_data_drift} exceeds tolerance ±{POOL_DRIFT_TOLERANCE} \
         under {retrans_delta} retransmits (baseline {}, post {}) — \
         likely refcount imbalance on retransmit path; check \
         crates/dpdk-net-core/src/engine.rs around line 5838 \
         (chain-fail rollback) and the Phase 4 refcnt-bump pairing",
        baseline.tx_data_avail, post.tx_data_avail
    );

    // ---- Gate 4: TX-hdr mempool drift within tolerance ----
    // Sister-assertion to Gate 3 covering the header-mbuf side. A
    // chain-fail rollback that frees `hdr_mbuf` correctly but skips the
    // data-mbuf decrement (or vice versa) shows up as imbalance on
    // exactly one of these two pools.
    assert!(
        tx_hdr_drift.abs() <= POOL_DRIFT_TOLERANCE,
        "TX-hdr mempool drift {tx_hdr_drift} exceeds tolerance ±{POOL_DRIFT_TOLERANCE} \
         under {retrans_delta} retransmits (baseline {}, post {}) — \
         likely header-mbuf refcount imbalance on retransmit path",
        baseline.tx_hdr_avail, post.tx_hdr_avail
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
         {retrans_delta} retransmits — leak signal"
    );
}
