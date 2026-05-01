//! A10 deferred-fix follow-up: sustained connect+close cycles regression test.
//!
//! Goal: prove the engine correctly recycles FlowTable slots and releases
//! every mempool ref across many connection lifecycles. Catches:
//!
//! 1. Slot generation-counter bugs (stale handles re-bound to a fresh slot).
//! 2. `MbufHandle` leaks via the close path (refs pinned in `recv.bytes` /
//!    `delivered_segments` / send-retrans queue not released on FIN).
//! 3. Per-conn-lifecycle resource accumulation (timers, scratch buffers,
//!    secondary-state allocations) that survives TIME_WAIT reaping.
//!
//! Pattern combines:
//!  * `rx_close_drains_mbufs.rs` — close-path mempool drain (single iter).
//!  * `rx_mempool_no_leak.rs`     — sustained workload (10k iters / 1 conn).
//!
//! Difference: instead of one long-lived conn, this test opens a FRESH conn
//! every iteration and closes it. Asserts mempool drift returns to ±32 of
//! baseline after `ITERATIONS` lifecycles.
//!
//! `CLOSE_FLAG_FORCE_TW_SKIP` is used so each iter's TIME_WAIT reaps on the
//! next poll instead of waiting 2×MSL — keeps wall-clock manageable while
//! still exercising the same drain path on close.
//!
//! Gated on `DPDK_NET_TEST_TAP=1` + sudo (matches the existing TAP-test
//! pattern).

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig, CLOSE_FLAG_FORCE_TW_SKIP};
use dpdk_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap19";
const OUR_IP: u32 = 0x0a_63_13_02; // 10.99.19.2
const PEER_IP: u32 = 0x0a_63_13_01; // 10.99.19.1
const PEER_IP_STR: &str = "10.99.19.1";
const OUR_IP_STR: &str = "10.99.19.2";
const PEER_PORT: u16 = 5019;
const ITERATIONS: u32 = 1_000;
const PAYLOAD: usize = 128;
const DRIFT_TOLERANCE: i64 = 32;

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
        .args(["addr", "add", "10.99.19.1/24", "dev", iface])
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

#[test]
fn connect_close_cycle_no_pool_drift() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a10-connect-close-cycle",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap19",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    // Short MSL keeps any TIME_WAIT slot (in case FORCE_TW_SKIP is dropped
    // due to ts_enabled=false on a given iter) from blocking flow-table
    // slot reuse longer than ~20ms.
    let cfg = EngineConfig {
        port_id: 0,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: kernel_mac,
        tcp_mss: 1460,
        max_connections: 4,
        tcp_msl_ms: 10,
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();
    pin_arp(TAP_IFACE, OUR_IP_STR, &mac_hex(our_mac));

    let pool = engine.rx_mempool_ptr();
    assert!(!pool.is_null(), "rx mempool pointer is null");

    // Multi-accept echo peer: handles ITERATIONS connections back-to-back.
    // Each accepted socket reads PAYLOAD bytes, echoes them, closes.
    let listener = TcpListener::bind((PEER_IP_STR, PEER_PORT)).expect("bind echo");
    listener
        .set_nonblocking(false)
        .expect("listener blocking-mode");
    let (peer_done_tx, peer_done_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        for _ in 0..ITERATIONS {
            let (mut sock, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => break,
            };
            sock.set_nodelay(true).ok();
            let mut buf = [0u8; PAYLOAD];
            if sock.read_exact(&mut buf).is_err() {
                continue;
            }
            let _ = sock.write_all(&buf);
            // Drop `sock` → kernel-side close. The engine sees FIN; our
            // `close_conn_with_flags` issues our FIN and FORCE_TW_SKIP
            // reaps on the next reap_time_wait pass.
        }
        let _ = peer_done_tx.send(());
    });

    // Snapshot the mempool baseline AFTER engine bring-up but BEFORE
    // the workload. Bring-up consumes a small fixed number of mbufs for
    // the RX descriptor ring; everything beyond that is workload-attributable.
    let avail_baseline = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    eprintln!(
        "[a10-conn-cycle] baseline avail={} pool_size={}",
        avail_baseline,
        engine.rx_mempool_size()
    );

    let payload = vec![0xABu8; PAYLOAD];
    let loop_start = Instant::now();
    for i in 0..ITERATIONS {
        // 1. Connect (retry on PeerUnreachable for the first few iters
        //    while the kernel-side ARP entry is still warming up — pin_arp
        //    above already pins it, but the very first connect can still
        //    race the kernel's TAP RX path.)
        let conn = {
            let connect_deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match engine.connect(PEER_IP, PEER_PORT, 0) {
                    Ok(h) => break h,
                    Err(_) => {
                        engine.poll_once();
                        engine.drain_events(8, |_, _| {});
                        if Instant::now() >= connect_deadline {
                            panic!("iter {i}: connect retries exhausted");
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                }
            }
        };

        // 2. Drive handshake to Connected.
        let mut connected = false;
        let connect_deadline = Instant::now() + Duration::from_secs(5);
        while !connected && Instant::now() < connect_deadline {
            engine.poll_once();
            engine.drain_events(16, |ev, _| {
                if matches!(ev, InternalEvent::Connected { conn: c, .. } if *c == conn) {
                    connected = true;
                }
            });
            // Don't sleep between every poll — keep the hot path tight.
            // A short yield prevents pure spin-burn but keeps RTT < 5ms.
            std::hint::spin_loop();
        }
        assert!(connected, "iter {i}: connect timeout");

        // 3. Send PAYLOAD bytes; pump send_bytes until accepted.
        let mut sent: u32 = 0;
        let send_deadline = Instant::now() + Duration::from_secs(3);
        while (sent as usize) < PAYLOAD {
            match engine.send_bytes(conn, &payload[sent as usize..]) {
                Ok(n) => sent = sent.saturating_add(n),
                Err(_) => {}
            }
            engine.poll_once();
            engine.drain_events(8, |_, _| {});
            assert!(Instant::now() < send_deadline, "iter {i}: send_bytes timeout");
        }

        // 4. Drain echo: wait for PAYLOAD bytes back as Readable events.
        let mut recv_total: u32 = 0;
        let recv_deadline = Instant::now() + Duration::from_secs(5);
        while (recv_total as usize) < PAYLOAD {
            engine.poll_once();
            engine.drain_events(32, |ev, _| {
                if let InternalEvent::Readable { total_len, conn: c, .. } = ev {
                    if *c == conn {
                        recv_total = recv_total.saturating_add(*total_len);
                    }
                }
            });
            assert!(Instant::now() < recv_deadline, "iter {i}: drain timeout");
        }

        // 5. Close the conn. Use FORCE_TW_SKIP so the FlowTable slot reaps
        //    on the next poll instead of waiting 2×MSL — required for
        //    1000-iter throughput. ts_enabled is true after the kernel-
        //    negotiated handshake (Linux always advertises TS), so the
        //    flag is honored.
        engine
            .close_conn_with_flags(conn, CLOSE_FLAG_FORCE_TW_SKIP)
            .expect("close_conn_with_flags");

        // 6. Drain the close-state machine. Pump until we see Closed for
        //    this handle (or a small timeout — peer-close-first paths can
        //    short-circuit through CLOSE_WAIT → LAST_ACK without us even
        //    needing to issue our FIN, so Closed always arrives).
        let mut closed = false;
        let close_deadline = Instant::now() + Duration::from_secs(2);
        while !closed && Instant::now() < close_deadline {
            engine.poll_once();
            engine.drain_events(32, |ev, _| {
                if matches!(ev, InternalEvent::Closed { conn: c, .. } if *c == conn) {
                    closed = true;
                }
            });
            // Tight pump; FORCE_TW_SKIP + tcp_msl_ms=10 means reaping
            // typically happens within a few polls.
        }
        assert!(closed, "iter {i}: did not observe Closed event");
    }
    let loop_elapsed = loop_start.elapsed();

    // Wait for the kernel echo thread to finish (drains any final accept).
    let _ = peer_done_rx.recv_timeout(Duration::from_secs(5));
    let _ = server.join();

    // Final settle — pump for ~250ms so any in-flight close-path mbufs
    // (NIC RX ring, lcore cache) drain before the mempool snapshot. The
    // 25 × 10ms cadence is intentionally generous: this is the test's
    // "is the drain genuinely done" gate, not its hot path.
    for _ in 0..25 {
        engine.poll_once();
        engine.drain_events(32, |_, _| {});
        thread::sleep(Duration::from_millis(10));
    }

    let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    let drift = (avail_baseline as i64) - (avail_post as i64);
    eprintln!(
        "[a10-conn-cycle] {} iters in {:?} ({:.2}ms/iter); post avail={} drift={} (baseline {})",
        ITERATIONS,
        loop_elapsed,
        (loop_elapsed.as_millis() as f64) / (ITERATIONS as f64),
        avail_post,
        drift,
        avail_baseline
    );

    // Surface counters for forensic visibility.
    let c = engine.counters();
    let conn_open = c
        .tcp
        .conn_open
        .load(std::sync::atomic::Ordering::Relaxed);
    let conn_close = c
        .tcp
        .conn_close
        .load(std::sync::atomic::Ordering::Relaxed);
    let drop_unexpected = c
        .tcp
        .mbuf_refcnt_drop_unexpected
        .load(std::sync::atomic::Ordering::Relaxed);
    eprintln!(
        "[a10-conn-cycle] conn_open={} conn_close={} mbuf_refcnt_drop_unexpected={}",
        conn_open, conn_close, drop_unexpected
    );

    // Core assertion: post-loop occupancy returns to baseline ±32. This
    // tolerance absorbs lcore mempool cache + NIC ring residue. A real
    // per-iter leak at the ~1k-iter scale would land FAR above this
    // budget (tens to hundreds of mbufs).
    assert!(
        drift.abs() <= DRIFT_TOLERANCE,
        "RX mempool drift {drift} exceeds tolerance ±{DRIFT_TOLERANCE} \
         (baseline {avail_baseline}, post {avail_post}, {ITERATIONS} iters) \
         — likely per-conn-lifecycle leak"
    );
    // Forensic gate: zero mbufs hit the unexpected-refcnt-drop guard.
    assert_eq!(
        drop_unexpected, 0,
        "mbuf_refcnt_drop_unexpected fired {drop_unexpected}× during \
         {ITERATIONS} connect+close cycles — leak signal"
    );
    // Sanity: we actually exercised the path. conn_open/conn_close should
    // each be ≥ ITERATIONS (each iter does exactly one of each, possibly
    // plus aborted retries the engine cleanly RST'd).
    assert!(
        conn_open >= ITERATIONS as u64,
        "conn_open={conn_open} < ITERATIONS={ITERATIONS} — handshakes didn't complete"
    );
    assert!(
        conn_close >= ITERATIONS as u64,
        "conn_close={conn_close} < ITERATIONS={ITERATIONS} — closes didn't complete"
    );

    drop(engine);
}
