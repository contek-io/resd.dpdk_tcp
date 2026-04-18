//! Phase A3 TCP handshake + echo + close integration test.
//!
//! Requires RESD_NET_TEST_TAP=1 AND root (DPDK TAP vdev + `ip neigh`
//! manipulation). Brings up `resdtap2` on the kernel side with
//! 10.99.2.1/24, starts a std `TcpListener` on 10.99.2.1:5000 that
//! echoes bytes back, and walks the engine through connect / send /
//! receive / close.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use resd_net_core::engine::{eal_init, Engine, EngineConfig};
use resd_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap2";
// Use 10.99.2.0/24 instead of 10.99.1.0/24 to dodge collisions with
// container/sandbox veth pairs that often use the .1.x block; if our
// OUR_IP is already a local addr on another interface, the kernel
// silently drops our SYN under accept_local=0.
const OUR_IP: u32 = 0x0a_63_02_02; // 10.99.2.2
const PEER_IP: u32 = 0x0a_63_02_01; // 10.99.2.1
const PEER_PORT: u16 = 5000;

fn skip_if_not_tap() -> bool {
    if std::env::var("RESD_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set RESD_NET_TEST_TAP=1 to run");
        return true;
    }
    false
}

fn read_kernel_tap_mac(iface: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("read {path}"));
    let mut out = [0u8; 6];
    for (i, part) in s.trim().split(':').enumerate() {
        out[i] = u8::from_str_radix(part, 16).expect("hex mac");
    }
    out
}

fn bring_up_tap(iface: &str) {
    let _ = Command::new("ip").args(["link", "set", iface, "up"]).status();
    let _ = Command::new("ip").args(["addr", "add", "10.99.2.1/24", "dev", iface]).status();
}

fn pin_arp(iface: &str, ip: &str, mac: &str) {
    let _ = Command::new("ip")
        .args(["neigh", "replace", ip, "lladdr", mac, "dev", iface, "nud", "permanent"])
        .status();
}

fn mac_hex(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

#[test]
fn handshake_echo_close_over_tap() {
    if skip_if_not_tap() { return; }

    let args = [
        "resd-net-a3-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap2",
        "-l", "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    // Default MSL is 30s → 2×MSL=60s before TIME_WAIT reap. The test only
    // budgets 5s for CLOSED. Use a 100ms MSL so the reaper fires fast.
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
    pin_arp(TAP_IFACE, "10.99.2.2", &mac_hex(our_mac));

    let listener = TcpListener::bind("10.99.2.1:5000").expect("listener bind");
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        if let Some(stream) = listener.incoming().next() {
            let mut s = stream.expect("accept");
            let mut buf = [0u8; 64];
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                if n == 0 { break; }
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
        let mut evs = Vec::new();
        engine.drain_events(16, |ev, _| evs.push(ev.clone()));
        for ev in &evs {
            if matches!(ev, InternalEvent::Connected { conn, .. } if *conn == handle) {
                connected = true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "did not receive CONNECTED within deadline");

    let msg = b"resd-net phase a3 smoke\n";
    let accepted = engine.send_bytes(handle, msg).expect("send");
    assert_eq!(accepted as usize, msg.len());

    let mut echoed = Vec::<u8>::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && echoed.len() < msg.len() {
        engine.poll_once();
        let mut evs = Vec::new();
        engine.drain_events(16, |ev, _| evs.push(ev.clone()));
        for ev in &evs {
            if let InternalEvent::Readable { conn, byte_offset, byte_len, .. } = ev {
                if *conn == handle {
                    let ft = engine.flow_table();
                    if let Some(c) = ft.get(handle) {
                        let off = *byte_offset as usize;
                        let len = *byte_len as usize;
                        echoed.extend_from_slice(&c.recv.last_read_buf[off..off + len]);
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(&echoed, msg, "echoed bytes mismatched");

    engine.close_conn(handle).expect("close");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut closed = false;
    while Instant::now() < deadline && !closed {
        engine.poll_once();
        let mut evs = Vec::new();
        engine.drain_events(16, |ev, _| evs.push(ev.clone()));
        for ev in &evs {
            if matches!(ev, InternalEvent::Closed { conn, .. } if *conn == handle) {
                closed = true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(closed, "did not receive CLOSED within deadline");

    let c = engine.counters();
    assert!(c.tcp.tx_syn.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_syn_ack.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_data.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_open.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_close.load(Ordering::Relaxed) >= 1);

    drop(engine);
    let _ = done_rx.recv_timeout(Duration::from_secs(2));
    let _ = server.join();
}
