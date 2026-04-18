//! Phase A4 TCP options-negotiation smoke test (TAP).
//!
//! Brings up `resdtap4` on the kernel side with `10.99.4.1/24`, opens a
//! plain `std::net::TcpListener` on `10.99.4.1:5000`, and walks the engine
//! through `connect` against it. After the handshake, asserts that the
//! kernel negotiated all four Stage-1 options (MSS + Window Scale + SACK-
//! permitted + Timestamps) — Linux always offers them by default, so a
//! healthy negotiation is `ws_shift_in > 0`, `ws_shift_out > 0`,
//! `ts_enabled = true`, `sack_enabled = true`, and `peer_mss > 536`.
//!
//! Gated behind `RESD_NET_TEST_TAP=1` (DPDK TAP vdev + `ip` commands need
//! root). A distinct TAP iface name (`resdtap4`) and subnet (`10.99.4.0/24`)
//! avoid collision with the A3 test (`resdtap2`, `10.99.2.0/24`) when both
//! are run sequentially in the same EAL process.

use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use resd_net_core::engine::{eal_init, Engine, EngineConfig};
use resd_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap4";
// 10.99.4.0/24 — distinct from the A3 test's 10.99.2.0/24 so the two
// tests can coexist (e.g. `cargo test -- --test-threads=1`) without the
// kernel routing table treating either as a duplicate local.
const OUR_IP: u32 = 0x0a_63_04_02; // 10.99.4.2
const PEER_IP: u32 = 0x0a_63_04_01; // 10.99.4.1
const PEER_IP_STR: &str = "10.99.4.1";
const OUR_IP_STR: &str = "10.99.4.2";
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
        .args(["addr", "add", "10.99.4.1/24", "dev", iface])
        .status();
}

fn pin_arp(iface: &str, ip: &str, mac: &str) {
    let _ = Command::new("ip")
        .args(["neigh", "replace", ip, "lladdr", mac, "dev", iface, "nud", "permanent"])
        .status();
}

fn mac_hex(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[test]
fn option_negotiation_smoke_against_kernel_listener() {
    if skip_if_not_tap() {
        return;
    }

    // EAL is process-global; eal_init() guards against double-init, so
    // running this test in the same process as `tcp_basic_tap` is safe.
    let args = [
        "resd-net-a4-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap4",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    // Short MSL keeps the test bounded if we ever extend it to cover
    // close. For Task 20's smoke we don't reach TIME_WAIT, but the
    // setting is harmless and matches A3 for consistency.
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

    // Kernel listener — accepts the connection, but we do not exchange
    // any data for the smoke test (the option-negotiation assertion is
    // what we care about). The thread loops on accept and exits when the
    // connection is dropped.
    let listener = TcpListener::bind(format!("{PEER_IP_STR}:{PEER_PORT}")).expect("listener bind");
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        if let Some(stream) = listener.incoming().next() {
            let s = stream.expect("accept");
            // Hold the connection open until the engine closes its side
            // (or the test drops the engine, which closes the TAP and
            // drops the kernel-side socket). No data exchanged.
            drop(s);
            let _ = done_tx.send(());
        }
    });

    let handle = engine.connect(PEER_IP, PEER_PORT, 0).expect("connect");

    // Drive the engine until we see the Connected event for our handle.
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

    // --- Option-negotiation assertions (Task 20 core) ---
    //
    // Linux 4+ negotiates MSS + WS + SACK-permitted + Timestamps on every
    // SYN-ACK by default (see net.ipv4.tcp_window_scaling, tcp_sack,
    // tcp_timestamps — all default 1 since 2.6.x). We assert that all
    // four landed in the per-conn state after handshake, which is the
    // only externally observable consequence of correct option parsing
    // in the SYN-ACK handler.
    {
        let ft = engine.flow_table();
        let conn = ft.get(handle).expect("conn slot populated");

        // peer_mss: Linux on a 1500-MTU TAP advertises MSS=1460. Our
        // SYN-ACK handler clamps to the option value (or stays at the
        // 536 RFC default if the peer omitted MSS). Linux never omits
        // MSS, so we expect a real MSS strictly above the 536 floor.
        assert!(
            conn.peer_mss > 536,
            "peer MSS = {}, want > 536 (RFC default floor); Linux must have advertised MSS",
            conn.peer_mss
        );
        assert!(
            conn.peer_mss <= 1460,
            "peer MSS = {}, want <= 1460 (TAP MTU=1500 → MSS=1460 ceiling)",
            conn.peer_mss
        );

        // Window Scale: both sides must have non-zero shifts. Our shift
        // (`ws_shift_out`) was computed at connect-time from the recv
        // buffer (256 KiB → shift 7); the inbound shift (`ws_shift_in`)
        // is whatever the kernel offered. Linux defaults to shift 7 on
        // most modern kernels.
        assert!(
            conn.ws_shift_out > 0,
            "ws_shift_out = {}, want > 0 (we advertised WS for 256 KiB recv buf)",
            conn.ws_shift_out
        );
        assert!(
            conn.ws_shift_in > 0,
            "ws_shift_in = {}, want > 0 (Linux always offers WS)",
            conn.ws_shift_in
        );

        // Timestamps: enabled iff both sides sent the TS option in the
        // SYN/SYN-ACK. We send TS unconditionally; Linux echoes.
        assert!(
            conn.ts_enabled,
            "ts_enabled = false, want true (Linux always offers Timestamps)"
        );

        // SACK-permitted: same story. Both sides offered the option in
        // the SYN/SYN-ACK exchange; the per-conn flag must reflect this.
        assert!(
            conn.sack_enabled,
            "sack_enabled = false, want true (Linux always offers SACK-permitted)"
        );
    }

    // Clean up — close from our side. We don't gate the test on a
    // Closed event because the option-negotiation assertion has already
    // passed; the close is purely so the kernel listener thread exits
    // without a TIME_WAIT lingering. If close_conn fails for any
    // reason we don't care — the engine is about to be dropped anyway.
    let _ = engine.close_conn(handle);

    // Pump a few times so the FIN exchange flushes; ignore failures.
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        engine.poll_once();
        engine.drain_events(16, |_, _| {});
        thread::sleep(Duration::from_millis(10));
    }

    drop(engine);
    let _ = done_rx.recv_timeout(Duration::from_secs(2));
    let _ = server.join();
}
