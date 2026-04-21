//! Phase A3 TCP handshake + echo + close integration test.
//!
//! Requires DPDK_NET_TEST_TAP=1 AND root (DPDK TAP vdev + `ip neigh`
//! manipulation). Brings up `dpdktap2` on the kernel side with
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

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;
use dpdk_net_core::tcp_state::TcpState;

const TAP_IFACE: &str = "dpdktap2";
// Use 10.99.2.0/24 instead of 10.99.1.0/24 to dodge collisions with
// container/sandbox veth pairs that often use the .1.x block; if our
// OUR_IP is already a local addr on another interface, the kernel
// silently drops our SYN under accept_local=0.
const OUR_IP: u32 = 0x0a_63_02_02; // 10.99.2.2
const PEER_IP: u32 = 0x0a_63_02_01; // 10.99.2.1
const PEER_PORT: u16 = 5000;

fn skip_if_not_tap() -> bool {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run");
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
        .args(["addr", "add", "10.99.2.1/24", "dev", iface])
        .status();
}

fn pin_arp(iface: &str, ip: &str, mac: &str) {
    let _ = Command::new("ip")
        .args([
            "neigh",
            "replace",
            ip,
            "lladdr",
            mac,
            "dev",
            iface,
            "nud",
            "permanent",
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
fn handshake_echo_close_over_tap() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a3-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=dpdktap2",
        "-l",
        "0-1",
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

    let msg = b"dpdk-net phase a3 smoke\n";
    let accepted = engine.send_bytes(handle, msg).expect("send");
    assert_eq!(accepted as usize, msg.len());

    let mut echoed = Vec::<u8>::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && echoed.len() < msg.len() {
        engine.poll_once();
        let mut evs = Vec::new();
        engine.drain_events(16, |ev, _| evs.push(ev.clone()));
        for ev in &evs {
            if let InternalEvent::Readable {
                conn,
                seg_idx_start,
                seg_count,
                ..
            } = ev
            {
                if *conn == handle {
                    let ft = engine.flow_table();
                    if let Some(c) = ft.get(handle) {
                        // A6.6 T7/T8: iovec slice lives in the conn's
                        // `readable_scratch_iovecs`; each entry's
                        // `base`/`len` is the delivered payload window.
                        let start = *seg_idx_start as usize;
                        let end = start + *seg_count as usize;
                        for iovec in &c.readable_scratch_iovecs[start..end] {
                            let slice = unsafe {
                                std::slice::from_raw_parts(iovec.base, iovec.len as usize)
                            };
                            echoed.extend_from_slice(slice);
                        }
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
    // --- TCP-event counters (A3 presence checks preserved) ---
    assert!(c.tcp.tx_syn.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_syn_ack.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_data.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_open.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_close.load(Ordering::Relaxed) >= 1);

    // --- eth / ip layers ---
    // Expected inbound segment shape for a SYN/echo/FIN cycle against the
    // kernel peer: SYN-ACK, ACK of our data, echoed-data, peer FIN-ACK,
    // peer's ACK of our FIN. ARP replies may bring the count higher.
    let eth_rx = c.eth.rx_pkts.load(Ordering::Relaxed);
    assert!(eth_rx >= 5, "eth.rx_pkts = {}, want >= 5", eth_rx);
    // Outbound: SYN, ACK of SYN-ACK, data w/ PSH|ACK, FIN+ACK.
    let eth_tx = c.eth.tx_pkts.load(Ordering::Relaxed);
    assert!(eth_tx >= 4, "eth.tx_pkts = {}, want >= 4", eth_tx);
    // Every inbound TCP segment gets counted here before dispatch.
    let ip_rx_tcp = c.ip.rx_tcp.load(Ordering::Relaxed);
    assert!(ip_rx_tcp >= 4, "ip.rx_tcp = {}, want >= 4", ip_rx_tcp);

    // --- TCP TX/RX accounting (beyond basic presence checks) ---
    // At minimum: our ACK of the peer's SYN-ACK.
    assert!(c.tcp.tx_ack.load(Ordering::Relaxed) >= 1);
    // At least msg.len() bytes delivered into our recv buffer.
    let delivered = c.tcp.recv_buf_delivered.load(Ordering::Relaxed);
    assert!(
        delivered >= msg.len() as u64,
        "tcp.recv_buf_delivered = {}, want >= {}",
        delivered,
        msg.len()
    );
    // --- Clean-path correctness invariants ---
    // 24-byte echo against a 256KB recv buffer → no overflow.
    assert_eq!(c.tcp.recv_buf_drops.load(Ordering::Relaxed), 0);
    // Every segment should have matched our one flow.
    assert_eq!(c.tcp.rx_unmatched.load(Ordering::Relaxed), 0);
    // Kernel TCP doesn't send malformed frames at us.
    assert_eq!(c.tcp.rx_bad_csum.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_bad_flags.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_short.load(Ordering::Relaxed), 0);

    // --- state_trans[from][to] matrix for the client-side walk ---
    let st = &c.tcp.state_trans;
    let closed = TcpState::Closed as usize;
    let syn_sent = TcpState::SynSent as usize;
    let established = TcpState::Established as usize;
    let fin_wait1 = TcpState::FinWait1 as usize;
    let fin_wait2 = TcpState::FinWait2 as usize;
    let closing = TcpState::Closing as usize;
    let time_wait = TcpState::TimeWait as usize;

    assert!(
        st[closed][syn_sent].load(Ordering::Relaxed) >= 1,
        "state_trans[Closed][SynSent] = {}, want >= 1",
        st[closed][syn_sent].load(Ordering::Relaxed)
    );
    assert!(
        st[syn_sent][established].load(Ordering::Relaxed) >= 1,
        "state_trans[SynSent][Established] = {}, want >= 1",
        st[syn_sent][established].load(Ordering::Relaxed)
    );
    assert!(
        st[established][fin_wait1].load(Ordering::Relaxed) >= 1,
        "state_trans[Established][FinWait1] = {}, want >= 1",
        st[established][fin_wait1].load(Ordering::Relaxed)
    );
    // Exit from FinWait1 — three RFC 9293 paths:
    //   • FinWait1→FinWait2 (our FIN ACKed, peer FIN deferred)
    //   • FinWait1→Closing  (peer FIN arrives first, our FIN not yet ACKed — simultaneous close)
    //   • FinWait1→TimeWait (peer piggy-backs FIN+ACK-of-our-FIN in one segment)
    // The kernel TCP usually does path 3 here. All three are valid.
    let fw1_to_fw2 = st[fin_wait1][fin_wait2].load(Ordering::Relaxed);
    let fw1_to_closing = st[fin_wait1][closing].load(Ordering::Relaxed);
    let fw1_to_tw = st[fin_wait1][time_wait].load(Ordering::Relaxed);
    assert!(
        fw1_to_fw2 + fw1_to_closing + fw1_to_tw >= 1,
        "state_trans[FinWait1][FinWait2|Closing|TimeWait] = {}+{}+{}, want sum >= 1",
        fw1_to_fw2,
        fw1_to_closing,
        fw1_to_tw
    );
    // TIME_WAIT reaper ran within the test's deadline (MSL=100ms).
    assert!(
        st[time_wait][closed].load(Ordering::Relaxed) >= 1,
        "state_trans[TimeWait][Closed] = {}, want >= 1",
        st[time_wait][closed].load(Ordering::Relaxed)
    );

    // Clean FIN close — no RST involved. conn_rst must remain zero.
    assert_eq!(c.tcp.conn_rst.load(Ordering::Relaxed), 0);

    drop(engine);
    let _ = done_rx.recv_timeout(Duration::from_secs(2));
    let _ = server.join();
}
