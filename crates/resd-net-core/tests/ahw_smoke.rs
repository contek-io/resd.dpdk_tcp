//! A-HW Tasks 16/17: smoke tests on the A3 TAP-pair harness.
//!
//! Run via: `RESD_NET_TEST_TAP=1 cargo test --release --test ahw_smoke`
//! (gated on RESD_NET_TEST_TAP=1 because the harness requires CAP_NET_ADMIN
//! and a freshly-initialized DPDK EAL, same preconditions as the A3/A4/A5
//! TAP tests).
//!
//! Task 16: SW-fallback under default features. net_tap advertises only
//! some of the hw-offload capabilities our default feature set requests,
//! so the runtime-fallback software paths exercise for the missing bits;
//! counter assertions pin what net_tap's advertised mask produces when
//! AND-ed against the compile-requested mask at DPDK 23.11.
//!
//! Task 17: SW-only under `--no-default-features`. Appended as a second
//! `#[cfg(all(not(...)))]`-gated test in the same file.

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use resd_net_core::engine::{eal_init, Engine, EngineConfig};
use resd_net_core::tcp_events::InternalEvent;

// Distinct TAP iface name (`resdtap6`) + subnet (`10.99.6.0/24`) avoid
// collision with the A3/A4/A5 TAP tests when they run in the same EAL
// process. Pattern mirrors `tcp_basic_tap.rs` / `tcp_options_paws_*`.
const TAP_IFACE: &str = "resdtap6";
const OUR_IP: u32 = 0x0a_63_06_02; // 10.99.6.2
const PEER_IP: u32 = 0x0a_63_06_01; // 10.99.6.1
const PEER_IP_STR: &str = "10.99.6.1";
const OUR_IP_STR: &str = "10.99.6.2";
const PEER_PORT: u16 = 5000;

fn skip_if_not_tap() -> bool {
    if std::env::var("RESD_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("ahw_smoke: RESD_NET_TEST_TAP not set; skipping");
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
        .args(["addr", "add", "10.99.6.1/24", "dev", iface])
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

// ---------------------------------------------------------------------------
// Task 16: SW-fallback under default features
// ---------------------------------------------------------------------------
//
// Default feature set = all A-HW compile-time gates ON
// (hw-verify-llq, hw-offload-tx-cksum, hw-offload-rx-cksum,
//  hw-offload-mbuf-fast-free, hw-offload-rss-hash, hw-offload-rx-timestamp).
//
// Against `net_tap` at DPDK 23.11 the PMD advertises:
//   rx_offload_capa = SCATTER | IPV4_CKSUM | UDP_CKSUM | TCP_CKSUM
//   tx_offload_capa = MULTI_SEGS | IPV4_CKSUM | UDP_CKSUM | TCP_CKSUM | TSO
// (see drivers/net/tap/rte_eth_tap.c, `TAP_{RX,TX}_OFFLOAD` macros).
//
// The per-counter expectations below follow directly from AND-ing the
// compile-requested bit against `dev_info.*_offload_capa`:
//
//   rx_cksum_ipv4, rx_cksum_tcp, rx_cksum_udp  → advertised → counter stays 0
//   tx_cksum_ipv4, tx_cksum_tcp, tx_cksum_udp  → advertised → counter stays 0
//   mbuf_fast_free                             → NOT advertised → counter == 1
//   rss_hash                                   → NOT advertised → counter == 1
//   llq                                        → driver != net_ena → short-circuit → counter stays 0
//   rx_timestamp                               → rte_dynfield_timestamp not registered → counter == 1
//
// rx_drop_cksum_bad stays 0 against the host-kernel TCP peer (well-formed
// traffic). rx_hw_ts_ns on every emitted event is 0 because the dynfield
// isn't registered — `Engine::hw_rx_ts_ns` returns 0.
//
// Compile-gated on the full default feature set: the counter assertions
// below are calibrated against `TAP_{RX,TX}_OFFLOAD` AND-ed against the
// compile-requested bits, and they'd be wrong under any other feature
// configuration. Task 17 covers the `--no-default-features` case.
#[test]
#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
fn ahw_sw_fallback_counters_and_correctness() {
    if skip_if_not_tap() {
        return;
    }

    // EAL is process-global; eal_init() guards against double-init, so
    // running this test in the same process as other TAP tests is safe.
    let args = [
        "resd-net-a-hw-smoke",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap6",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    // Short MSL so the TIME_WAIT reaper fires fast enough for the test
    // budget — same trick as the A3 harness.
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

    // Kernel echo server, same shape as `tcp_basic_tap.rs`.
    let listener =
        TcpListener::bind(format!("{PEER_IP_STR}:{PEER_PORT}")).expect("listener bind");
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

    // --- Drive a full request-response cycle (A3 oracle pattern) --------
    //
    // Collect every event across the whole cycle so the rx_hw_ts_ns check
    // at the bottom sees Connected + Readable + Closed.
    let mut all_events: Vec<InternalEvent> = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if matches!(ev, InternalEvent::Connected { conn, .. } if *conn == handle) {
                connected = true;
            }
        });
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "did not receive CONNECTED within deadline");

    let msg = b"resd-net a-hw sw-fallback smoke\n";
    let accepted = engine.send_bytes(handle, msg).expect("send");
    assert_eq!(accepted as usize, msg.len());

    let mut echoed = Vec::<u8>::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && echoed.len() < msg.len() {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if let InternalEvent::Readable {
                conn,
                byte_offset,
                byte_len,
                ..
            } = ev
            {
                if *conn == handle {
                    let ft = engine.flow_table();
                    if let Some(c) = ft.get(handle) {
                        let off = *byte_offset as usize;
                        let len = *byte_len as usize;
                        echoed.extend_from_slice(&c.recv.last_read_buf[off..off + len]);
                    }
                }
            }
        });
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(&echoed, msg, "echoed bytes mismatched");

    engine.close_conn(handle).expect("close");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut closed = false;
    while Instant::now() < deadline && !closed {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if matches!(ev, InternalEvent::Closed { conn, .. } if *conn == handle) {
                closed = true;
            }
        });
        thread::sleep(Duration::from_millis(10));
    }
    assert!(closed, "did not receive CLOSED within deadline");

    // --- A3 oracle: correctness invariants ---
    let c = engine.counters();
    assert!(c.tcp.tx_syn.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_syn_ack.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_data.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_open.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_close.load(Ordering::Relaxed) >= 1);
    assert_eq!(c.tcp.rx_bad_csum.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_bad_flags.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_short.load(Ordering::Relaxed), 0);
    assert_eq!(
        c.tcp.recv_buf_drops.load(Ordering::Relaxed),
        0,
        "{}-byte echo against a 256KB recv buffer must not overflow",
        msg.len()
    );
    assert_eq!(
        c.tcp.rx_unmatched.load(Ordering::Relaxed),
        0,
        "every segment must match our one flow"
    );
    assert_eq!(
        c.tcp.conn_rst.load(Ordering::Relaxed),
        0,
        "clean FIN close — no RST involved"
    );
    assert!(
        c.tcp.recv_buf_delivered.load(Ordering::Relaxed) >= msg.len() as u64,
        "recv_buf_delivered must reflect at least msg.len() bytes"
    );

    // --- A-HW offload-missing counter assertions ---
    //
    // Calibration source: DPDK 23.11 net_tap PMD advertised capability
    // macros `TAP_RX_OFFLOAD` / `TAP_TX_OFFLOAD` in
    // drivers/net/tap/rte_eth_tap.c (lines 76-85). Values derived from the
    // AND of compile-time requested bits against these masks.
    //
    // A future PMD update that adds RSS_HASH or MBUF_FAST_FREE (or that
    // registers `rte_dynfield_timestamp`) would require recalibrating the
    // expected constants below.

    // RX checksum offloads: ADVERTISED by net_tap → counters must stay 0.
    assert_eq!(
        c.eth.offload_missing_rx_cksum_ipv4.load(Ordering::Relaxed),
        0,
        "net_tap advertises RTE_ETH_RX_OFFLOAD_IPV4_CKSUM (see TAP_RX_OFFLOAD)"
    );
    assert_eq!(
        c.eth.offload_missing_rx_cksum_tcp.load(Ordering::Relaxed),
        0,
        "net_tap advertises RTE_ETH_RX_OFFLOAD_TCP_CKSUM (see TAP_RX_OFFLOAD)"
    );
    assert_eq!(
        c.eth.offload_missing_rx_cksum_udp.load(Ordering::Relaxed),
        0,
        "net_tap advertises RTE_ETH_RX_OFFLOAD_UDP_CKSUM (see TAP_RX_OFFLOAD)"
    );

    // TX checksum offloads: ADVERTISED by net_tap → counters must stay 0.
    assert_eq!(
        c.eth.offload_missing_tx_cksum_ipv4.load(Ordering::Relaxed),
        0,
        "net_tap advertises RTE_ETH_TX_OFFLOAD_IPV4_CKSUM (see TAP_TX_OFFLOAD)"
    );
    assert_eq!(
        c.eth.offload_missing_tx_cksum_tcp.load(Ordering::Relaxed),
        0,
        "net_tap advertises RTE_ETH_TX_OFFLOAD_TCP_CKSUM (see TAP_TX_OFFLOAD)"
    );
    assert_eq!(
        c.eth.offload_missing_tx_cksum_udp.load(Ordering::Relaxed),
        0,
        "net_tap advertises RTE_ETH_TX_OFFLOAD_UDP_CKSUM (see TAP_TX_OFFLOAD)"
    );

    // MBUF_FAST_FREE: NOT advertised by net_tap → counter bumps exactly 1
    // at bring-up (one-shot per engine_create per spec §11).
    assert_eq!(
        c.eth.offload_missing_mbuf_fast_free.load(Ordering::Relaxed),
        1,
        "net_tap does NOT advertise RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE"
    );

    // RSS_HASH: NOT advertised by net_tap → counter bumps exactly 1.
    assert_eq!(
        c.eth.offload_missing_rss_hash.load(Ordering::Relaxed),
        1,
        "net_tap does NOT advertise RTE_ETH_RX_OFFLOAD_RSS_HASH"
    );

    // LLQ: driver != net_ena → short-circuited in llq_verify, counter stays 0.
    assert_eq!(
        c.eth.offload_missing_llq.load(Ordering::Relaxed),
        0,
        "net_tap driver short-circuits LLQ verification"
    );

    // RX timestamp: net_tap does not register rte_dynfield_timestamp →
    // the feature's dynfield-lookup branch bumps the counter once.
    assert_eq!(
        c.eth.offload_missing_rx_timestamp.load(Ordering::Relaxed),
        1,
        "net_tap doesn't register rte_dynfield_timestamp; feature is on by default"
    );

    // No BAD-cksum drops on well-formed traffic. Covers both the
    // NIC-classified path (when rx_cksum_offload_active is true and
    // net_tap stamps IP_CKSUM_GOOD / L4_CKSUM_GOOD) and the software
    // verify path.
    assert_eq!(
        c.eth.rx_drop_cksum_bad.load(Ordering::Relaxed),
        0,
        "kernel TCP peer sends well-formed frames — no BAD cksum classification expected"
    );

    // --- hw_rx_ts_ns is 0 on every event ---
    //
    // The `rte_dynfield_timestamp` dynfield isn't registered on net_tap
    // (this is also what drove `offload_missing_rx_timestamp == 1` above).
    // The engine's `hw_rx_ts_ns` accessor therefore returns 0 for every
    // RX mbuf, and every event's `rx_hw_ts_ns` field is 0.
    //
    // Connected / Readable carry the field directly. Closed / StateChange
    // don't have one — they only carry `emitted_ts_ns`. Iterate over the
    // variants that CARRY an `rx_hw_ts_ns` and assert.
    let mut checked = 0usize;
    for ev in &all_events {
        match ev {
            InternalEvent::Connected { rx_hw_ts_ns, .. }
            | InternalEvent::Readable { rx_hw_ts_ns, .. } => {
                assert_eq!(
                    *rx_hw_ts_ns, 0,
                    "net_tap hw_rx_ts_ns accessor must return 0 (dynfield absent)"
                );
                checked += 1;
            }
            _ => {}
        }
    }
    assert!(
        checked >= 2,
        "expected at least 1 Connected + 1 Readable to carry rx_hw_ts_ns; checked {checked}"
    );

    drop(engine);
    let _ = done_rx.recv_timeout(Duration::from_secs(2));
    let _ = server.join();
}

// ============================================================================
// Task 17: SW-only smoke test — --no-default-features build.
// ============================================================================
//
// This test compiles ONLY in a build where every hw-* feature is off.
// Invocation:
//
//   RESD_NET_TEST_TAP=1 cargo test --release --test ahw_smoke \
//       --no-default-features --features obs-poll-saturation
//
// With no hw-* feature compiled in: the offload code paths are entirely
// absent, hw_rx_ts_ns is a const fn returning 0, and no offload bits are
// requested — so every offload_missing_* counter stays at 0 (no request
// → no miss).
//
// Harness setup is duplicated verbatim from the Task 16 test above rather
// than factored into a shared helper — the two tests are mutually
// exclusive compile-time feature builds (never both in the same process),
// the counter-assertion blocks are what actually differ between them, and
// Stage 1 with 2 test sites doesn't justify the extra indirection.

#[test]
#[cfg(all(
    not(feature = "hw-verify-llq"),
    not(feature = "hw-offload-tx-cksum"),
    not(feature = "hw-offload-rx-cksum"),
    not(feature = "hw-offload-mbuf-fast-free"),
    not(feature = "hw-offload-rss-hash"),
    not(feature = "hw-offload-rx-timestamp"),
))]
fn ahw_sw_only_counters_and_correctness() {
    if skip_if_not_tap() {
        return;
    }

    // EAL is process-global; eal_init() guards against double-init, so
    // running this test in the same process as other TAP tests is safe.
    let args = [
        "resd-net-a-hw-smoke",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap6",
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

    // Kernel echo server, same shape as Task 16.
    let listener =
        TcpListener::bind(format!("{PEER_IP_STR}:{PEER_PORT}")).expect("listener bind");
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

    // --- Drive a full request-response cycle (A3 oracle pattern) --------
    let mut all_events: Vec<InternalEvent> = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if matches!(ev, InternalEvent::Connected { conn, .. } if *conn == handle) {
                connected = true;
            }
        });
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "did not receive CONNECTED within deadline");

    let msg = b"resd-net a-hw sw-only smoke\n";
    let accepted = engine.send_bytes(handle, msg).expect("send");
    assert_eq!(accepted as usize, msg.len());

    let mut echoed = Vec::<u8>::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && echoed.len() < msg.len() {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if let InternalEvent::Readable {
                conn,
                byte_offset,
                byte_len,
                ..
            } = ev
            {
                if *conn == handle {
                    let ft = engine.flow_table();
                    if let Some(c) = ft.get(handle) {
                        let off = *byte_offset as usize;
                        let len = *byte_len as usize;
                        echoed.extend_from_slice(&c.recv.last_read_buf[off..off + len]);
                    }
                }
            }
        });
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(&echoed, msg, "echoed bytes mismatched");

    engine.close_conn(handle).expect("close");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut closed = false;
    while Instant::now() < deadline && !closed {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if matches!(ev, InternalEvent::Closed { conn, .. } if *conn == handle) {
                closed = true;
            }
        });
        thread::sleep(Duration::from_millis(10));
    }
    assert!(closed, "did not receive CLOSED within deadline");

    // --- A3 oracle: correctness invariants (same as Task 16) ---
    let c = engine.counters();
    assert!(c.tcp.tx_syn.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_syn_ack.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_data.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_open.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_close.load(Ordering::Relaxed) >= 1);
    assert_eq!(c.tcp.rx_bad_csum.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_bad_flags.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_short.load(Ordering::Relaxed), 0);
    assert_eq!(
        c.tcp.recv_buf_drops.load(Ordering::Relaxed),
        0,
        "{}-byte echo against a 256KB recv buffer must not overflow",
        msg.len()
    );
    assert_eq!(
        c.tcp.rx_unmatched.load(Ordering::Relaxed),
        0,
        "every segment must match our one flow"
    );
    assert_eq!(
        c.tcp.conn_rst.load(Ordering::Relaxed),
        0,
        "clean FIN close — no RST involved"
    );
    assert!(
        c.tcp.recv_buf_delivered.load(Ordering::Relaxed) >= msg.len() as u64,
        "recv_buf_delivered must reflect at least msg.len() bytes"
    );

    // --- A-HW SW-only counter assertions ---
    //
    // No hw-* feature compiled in ⇒ every offload_missing_* bump site is
    // cfg'd out at the source. Counter bumps can only happen inside a
    // feature gate, so all 11 counters MUST stay at 0.
    //
    // This is structurally stronger than Task 16: there, some counters
    // stayed at 0 because net_tap happened to advertise the requested
    // bit. Here, the absence of any request — at compile time — makes a
    // bump impossible. The test confirms the fully-compile-gated-off
    // build matches the A3 correctness oracle.

    assert_eq!(
        c.eth.offload_missing_rx_cksum_ipv4.load(Ordering::Relaxed),
        0,
        "no hw-offload-rx-cksum ⇒ bit not requested ⇒ no miss counted"
    );
    assert_eq!(
        c.eth.offload_missing_rx_cksum_tcp.load(Ordering::Relaxed),
        0,
        "no hw-offload-rx-cksum ⇒ bit not requested ⇒ no miss counted"
    );
    assert_eq!(
        c.eth.offload_missing_rx_cksum_udp.load(Ordering::Relaxed),
        0,
        "no hw-offload-rx-cksum ⇒ bit not requested ⇒ no miss counted"
    );
    assert_eq!(
        c.eth.offload_missing_tx_cksum_ipv4.load(Ordering::Relaxed),
        0,
        "no hw-offload-tx-cksum ⇒ bit not requested ⇒ no miss counted"
    );
    assert_eq!(
        c.eth.offload_missing_tx_cksum_tcp.load(Ordering::Relaxed),
        0,
        "no hw-offload-tx-cksum ⇒ bit not requested ⇒ no miss counted"
    );
    assert_eq!(
        c.eth.offload_missing_tx_cksum_udp.load(Ordering::Relaxed),
        0,
        "no hw-offload-tx-cksum ⇒ bit not requested ⇒ no miss counted"
    );
    assert_eq!(
        c.eth.offload_missing_mbuf_fast_free.load(Ordering::Relaxed),
        0,
        "no hw-offload-mbuf-fast-free ⇒ bit not requested ⇒ no miss counted"
    );
    assert_eq!(
        c.eth.offload_missing_rss_hash.load(Ordering::Relaxed),
        0,
        "no hw-offload-rss-hash ⇒ bit not requested ⇒ no miss counted"
    );
    assert_eq!(
        c.eth.offload_missing_llq.load(Ordering::Relaxed),
        0,
        "no hw-verify-llq ⇒ verification code path compiled out"
    );
    assert_eq!(
        c.eth.offload_missing_rx_timestamp.load(Ordering::Relaxed),
        0,
        "no hw-offload-rx-timestamp ⇒ dynfield lookup compiled out"
    );
    assert_eq!(
        c.eth.rx_drop_cksum_bad.load(Ordering::Relaxed),
        0,
        "kernel TCP peer sends well-formed frames — no BAD cksum classification expected"
    );

    // --- hw_rx_ts_ns is 0 on every event (const fn accessor) ---
    //
    // Under --no-default-features the `Engine::hw_rx_ts_ns` accessor is a
    // const fn returning 0 (see spec §8.4 — the dynfield-lookup branch is
    // compiled out entirely). Every event's `rx_hw_ts_ns` field is
    // therefore 0 by construction.
    let mut checked = 0usize;
    for ev in &all_events {
        match ev {
            InternalEvent::Connected { rx_hw_ts_ns, .. }
            | InternalEvent::Readable { rx_hw_ts_ns, .. } => {
                assert_eq!(
                    *rx_hw_ts_ns, 0,
                    "SW-only build: hw_rx_ts_ns is a const fn returning 0"
                );
                checked += 1;
            }
            _ => {}
        }
    }
    assert!(
        checked >= 2,
        "expected at least 1 Connected + 1 Readable to carry rx_hw_ts_ns; checked {checked}"
    );

    drop(engine);
    let _ = done_rx.recv_timeout(Duration::from_secs(2));
    let _ = server.join();
}
