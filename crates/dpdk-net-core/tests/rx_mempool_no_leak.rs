//! A10 deferred-fix Stage B regression test: 10000 RTT iterations
//! against a kernel TCP echo peer over TAP. Asserts that the RX mempool's
//! free-mbuf count returns to within ±32 of the pre-test baseline after
//! the run completes, proving no per-iteration mbuf leak on the RX path.
//!
//! Models on `tests/rx_close_drains_mbufs.rs`. Gated on
//! `DPDK_NET_TEST_TAP=1` + sudo (matches the existing TAP-test pattern).

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap16";
const OUR_IP: u32 = 0x0a_63_10_02; // 10.99.16.2
const PEER_IP: u32 = 0x0a_63_10_01; // 10.99.16.1
const PEER_PORT: u16 = 5016;
const ITERATIONS: u32 = 10_000;
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
        .args(["addr", "add", "10.99.16.1/24", "dev", iface])
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
fn rx_mempool_steady_under_10k_rtt() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a10-rx-mempool-no-leak",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap16",
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
    pin_arp(TAP_IFACE, "10.99.16.2", &mac_hex(our_mac));

    let pool = engine.rx_mempool_ptr();
    assert!(!pool.is_null(), "rx mempool pointer is null");

    // Echo peer on the kernel side.
    let listener = TcpListener::bind(("10.99.16.1", PEER_PORT)).expect("bind echo");
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

    // Snapshot the mempool baseline AFTER engine bring-up but BEFORE
    // the workload. Bring-up consumes a small fixed number of mbufs for
    // the RX ring; everything beyond that is workload-attributable.
    let avail_baseline = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    eprintln!(
        "[a10-no-leak] baseline avail={} pool_size={}",
        avail_baseline,
        engine.rx_mempool_size()
    );

    // Open conn + drive ITERATIONS RTT round-trips.
    let conn = engine.connect(PEER_IP, PEER_PORT, 0).expect("connect");

    // Pump until Connected.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
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
    for i in 0..ITERATIONS {
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
                if let InternalEvent::Readable { total_len, .. } = ev {
                    recv_total = recv_total.saturating_add(*total_len);
                }
            });
            assert!(Instant::now() < iter_deadline, "iter {i} drain timeout");
        }
    }

    // Wait for the kernel echo thread to finish.
    let _ = peer_done_rx.recv_timeout(Duration::from_secs(5));

    // Final drain — push poll events through to give the engine a few
    // extra cycles to release any in-flight mbufs.
    for _ in 0..50 {
        engine.poll_once();
        engine.drain_events(32, |_ev, _| {});
        thread::sleep(Duration::from_millis(2));
    }

    let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    let drift = (avail_baseline as i64) - (avail_post as i64);
    eprintln!(
        "[a10-no-leak] post avail={} drift={} (baseline {})",
        avail_post, drift, avail_baseline
    );
    assert!(
        drift.abs() <= DRIFT_TOLERANCE,
        "RX mempool drift {drift} exceeds tolerance ±{DRIFT_TOLERANCE} \
         (baseline {avail_baseline}, post {avail_post}) — likely leak in \
         RX path; see docs/superpowers/reports/a10-ab-driver-debug.md §3"
    );

    // Surface the diagnostic counter for forensic visibility.
    let drop_unexpected = engine
        .counters()
        .tcp
        .mbuf_refcnt_drop_unexpected
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        drop_unexpected, 0,
        "mbuf_refcnt_drop_unexpected fired during 10k RTT — leak signal"
    );
}
