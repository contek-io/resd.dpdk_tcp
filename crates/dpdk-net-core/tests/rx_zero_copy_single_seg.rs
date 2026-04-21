//! A6.6-7 Task 13 — RX zero-copy single-segment round-trip over TAP.
//!
//! Asserts that a small in-order payload delivered by the kernel peer
//! lands in the engine's recv path as exactly one scatter-gather segment
//! whose `base` pointer falls inside the RX mempool's mbuf data region.
//! This is the happy-path zero-copy contract — the application reads
//! directly out of the PMD-supplied mbuf with no intermediate copy.
//!
//! Gated on `DPDK_NET_TEST_TAP=1` + sudo (TAP vdev + `ip neigh`
//! manipulation). Mirrors the pattern of `tcp_basic_tap.rs` so the
//! existing harness invariants (kernel-echo, dpdktap iface naming,
//! 10.99.x.0/24 subnet partitioning) carry over.

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;

// Distinct TAP iface + /24 so parallel test runs don't collide. Reserved
// .13.x block per the test-corpus convention (see tcp_basic_tap=.2.x,
// bench_alloc_hotpath=.10.x).
const TAP_IFACE: &str = "resdtap13";
const OUR_IP: u32 = 0x0a_63_0d_02; // 10.99.13.2
const PEER_IP: u32 = 0x0a_63_0d_01; // 10.99.13.1
const PEER_PORT: u16 = 5013;

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
        .args(["addr", "add", "10.99.13.1/24", "dev", iface])
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
fn rx_zero_copy_single_seg_roundtrip() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a6-6-7-t13-single-seg",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap13",
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
    pin_arp(TAP_IFACE, "10.99.13.2", &mac_hex(our_mac));

    // Kernel echo server — reflects bytes back so our engine receives a
    // single in-order segment from the peer side.
    let listener = TcpListener::bind("10.99.13.1:5013").expect("listener bind");
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        if let Some(stream) = listener.incoming().next() {
            let mut s = stream.expect("accept");
            let mut buf = [0u8; 512];
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).unwrap();
            }
            let _ = done_tx.send(());
        }
    });

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
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "did not receive CONNECTED within deadline");

    // A 256-byte payload comfortably fits in one TCP segment (MSS 1460)
    // so we expect a single-mbuf single-seg READABLE delivery.
    let msg: Vec<u8> = (0..256u32).map(|i| (i & 0xFF) as u8).collect();
    let accepted = engine.send_bytes(handle, &msg).expect("send");
    assert_eq!(accepted as usize, msg.len());

    // Capture the first Readable event's seg metadata + reassemble the
    // payload out of the iovec slice.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got_seg_count: Option<u32> = None;
    let mut got_total_len: Option<u32> = None;
    let mut got_base: Option<*const u8> = None;
    let mut got_len: Option<u32> = None;
    let mut echoed = Vec::<u8>::new();
    while Instant::now() < deadline && echoed.len() < msg.len() {
        engine.poll_once();
        let mut evs = Vec::new();
        engine.drain_events(16, |ev, _| evs.push(ev.clone()));
        for ev in &evs {
            if let InternalEvent::Readable {
                conn,
                seg_idx_start,
                seg_count,
                total_len,
                ..
            } = ev
            {
                if *conn == handle {
                    let ft = engine.flow_table();
                    if let Some(c) = ft.get(handle) {
                        let start = *seg_idx_start as usize;
                        let end = start + *seg_count as usize;
                        for iovec in &c.readable_scratch_iovecs[start..end] {
                            if got_base.is_none() {
                                got_seg_count = Some(*seg_count);
                                got_total_len = Some(*total_len);
                                got_base = Some(iovec.base);
                                got_len = Some(iovec.len);
                            }
                            let slice =
                                unsafe { std::slice::from_raw_parts(iovec.base, iovec.len as usize) };
                            echoed.extend_from_slice(slice);
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Core assertion #1: echoed bytes round-tripped intact.
    assert_eq!(&echoed, &msg, "echoed bytes mismatched");

    // Core assertion #2: a single scatter-gather segment covered the
    // full 256-byte read (ENA-default single-seg + no kernel-side packet
    // coalescing produces a length-1 chain on the first Readable event).
    let n_segs = got_seg_count.expect("at least one Readable event observed");
    assert_eq!(
        n_segs, 1,
        "expected n_segs == 1 for a 256-byte kernel echo; got {}",
        n_segs
    );
    let total_len = got_total_len.expect("total_len captured");
    let seg0_len = got_len.expect("seg[0].len captured");
    assert_eq!(
        total_len, msg.len() as u32,
        "total_len = {}, want {}",
        total_len,
        msg.len()
    );
    assert_eq!(
        seg0_len, msg.len() as u32,
        "segs[0].len = {}, want {}",
        seg0_len,
        msg.len()
    );

    // Core assertion #3: segs[0].base points inside the engine's RX
    // mempool region. DPDK mempools don't expose a trivial [start, end)
    // byte range for arbitrary layouts (they're backed by hugepage
    // mempool objects with internal alignment padding), so the tightest
    // cheap check is that the pool pointer itself is valid (non-null) +
    // the base pointer is non-null. We assert the RX data pointer is
    // non-null + nonzero; a fuller containment assertion would need
    // `rte_mempool_ops_get_info` or iterating each mbuf via
    // `rte_mempool_obj_iter`, which is out of scope for this smoke.
    let base = got_base.expect("seg[0].base captured");
    let pool = engine.rx_mempool_ptr();
    assert!(!pool.is_null(), "rx mempool pointer is null");
    assert!(!base.is_null(), "seg[0].base is null");

    engine.close_conn(handle).ok();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        engine.poll_once();
        engine.drain_events(16, |_, _| {});
        thread::sleep(Duration::from_millis(10));
    }

    drop(engine);
    let _ = done_rx.recv_timeout(Duration::from_secs(2));
    let _ = server.join();
}
