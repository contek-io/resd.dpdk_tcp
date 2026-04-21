//! A9 Task 2 smoke test: `Engine::inject_rx_frame` dispatches through the
//! production RX path.
//!
//! Builds a minimal Ethernet II frame carrying an IPv4 ICMP echo-request,
//! injects it, and asserts the engine's `ip.rx_icmp` counter advances by
//! at least 1. The counter field in `counters.rs` is `rx_icmp` (not the
//! `icmp_rx` name suggested in the phase-a9 plan) — adopted here verbatim
//! so the assertion reads naturally against the real counter struct.
//!
//! Gating:
//!   - Requires the `test-inject` cargo feature (hook API).
//!   - Runtime-gated on `DPDK_NET_TEST_TAP=1` + sudo + hugepages via
//!     `common::make_test_engine`; when the gate is unmet the test logs
//!     a "skipping" message and returns cleanly (matches the behaviour
//!     of every other TAP-gated test in this crate).

#![cfg(feature = "test-inject")]

mod common;
use common::make_test_engine;

#[test]
fn inject_single_seg_ethernet_frame_runs_rx_dispatch() {
    let Some(engine) = make_test_engine() else {
        return;
    };

    let our_mac = engine.our_mac();
    let peer_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];

    // Ethernet II header: dst=our_mac, src=peer_mac, ethertype=0x0800 (IPv4).
    // IPv4 header: 20 bytes, proto=1 (ICMP). Destination IP is the engine's
    // `local_ip`, converted to network byte order for the header.
    // ICMP payload: 8-byte echo request (type=8, code=0, rest zeroed) — the
    // engine drops it on `IcmpResult::OtherDropped` but `ip.rx_icmp` is
    // bumped unconditionally on ingress (see `handle_ipv4`).
    let our_ip_he = engine.our_ip();
    let dst_ip_be = our_ip_he.to_be_bytes();

    let mut frame = Vec::with_capacity(14 + 20 + 8);
    // L2 header
    frame.extend_from_slice(&our_mac);
    frame.extend_from_slice(&peer_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header
    frame.push(0x45); // version=4, ihl=5
    frame.push(0x00); // tos
    frame.extend_from_slice(&(20u16 + 8u16).to_be_bytes()); // total_len
    frame.extend_from_slice(&0u16.to_be_bytes()); // id
    frame.extend_from_slice(&0u16.to_be_bytes()); // flags+frag
    frame.push(64); // ttl
    frame.push(1); // proto = ICMP
    frame.extend_from_slice(&0u16.to_be_bytes()); // cksum placeholder
    // source IP (10.0.0.2) — arbitrary peer
    frame.extend_from_slice(&[10, 0, 0, 2]);
    frame.extend_from_slice(&dst_ip_be);
    // Recompute IPv4 cksum so the engine's IP decode accepts the header.
    let cksum = dpdk_net_core::l3_ip::internet_checksum(&[&frame[14..14 + 20]]);
    frame[14 + 10] = (cksum >> 8) as u8;
    frame[14 + 11] = (cksum & 0xff) as u8;
    // ICMP echo request body
    frame.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]);

    let icmp_before = engine
        .counters()
        .ip
        .rx_icmp
        .load(std::sync::atomic::Ordering::Relaxed);
    engine
        .inject_rx_frame(&frame)
        .expect("inject_rx_frame should succeed on well-formed frame");
    let icmp_after = engine
        .counters()
        .ip
        .rx_icmp
        .load(std::sync::atomic::Ordering::Relaxed);

    assert!(
        icmp_after > icmp_before,
        "ip.rx_icmp did not advance after inject (before={icmp_before}, after={icmp_after})"
    );
}
