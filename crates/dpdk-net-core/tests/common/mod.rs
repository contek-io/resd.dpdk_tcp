//! Shared TAP harness helpers for A5 integration tests.
//!
//! The existing TAP tests (tcp_basic_tap.rs, l2_l3_tap.rs, etc.) use the
//! host kernel's TCP stack on the peer side of the TAP interface. That
//! design works for sunny-day handshake + data scenarios but can't inject:
//!   - selective segment drops,
//!   - SACK blocks covering seq > snd.una + N,
//!   - total peer silence (blackhole).
//!
//! To exercise A5's RTO / RACK / TLP paths end-to-end, Tasks 28-30 need
//! synthetic peer control. Full implementation would require a second
//! TCP state machine on the peer side of the TAP (e.g., via smoltcp or a
//! hand-rolled mini-stack). That's out of scope for Stage 1 delivery —
//! the corresponding scenarios are documented as expected-behavior tests
//! that MAY be implemented via raw AF_PACKET later.
//!
//! This module provides the type surface (`TapPeerMode`) that those
//! future tests will consume, plus a helper that describes the intended
//! setup for each mode.

#![allow(dead_code)]

/// A process-wide lock for tests that mutate `DPDK_NET_FAULT_INJECTOR`.
/// Cargo runs tests in a binary in parallel by default; without this guard,
/// two env-var-mutating tests can race and one will pick up the other's
/// config when constructing the Engine.
#[cfg(feature = "test-inject")]
pub static FAULT_INJECTOR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Peer-behavior modes for A5 fault-injection integration tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct TapPeerMode {
    /// If true, the peer discards the next frame our stack emits
    /// (simulates a lost segment). Tasks 28/29 use this for RTO / TLP.
    pub drop_next_tx: bool,
    /// If set to Some(n), the peer's next ACK carries a SACK block
    /// covering seq > (our_snd_una + n) instead of cum-ACKing.
    /// Used by Task 28's RACK reorder scenario.
    pub sack_gap_at: Option<u32>,
    /// If true, the peer never responds to anything (simulates a
    /// disconnected peer). Task 29's SYN-retrans ETIMEDOUT + Task 13's
    /// data-retrans ETIMEDOUT scenarios use this.
    pub blackhole: bool,
}

impl TapPeerMode {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_drop_next_tx(mut self) -> Self {
        self.drop_next_tx = true;
        self
    }

    pub fn with_sack_gap_at(mut self, n: u32) -> Self {
        self.sack_gap_at = Some(n);
        self
    }

    pub fn with_blackhole(mut self) -> Self {
        self.blackhole = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_disabled() {
        let m = TapPeerMode::new();
        assert!(!m.drop_next_tx);
        assert!(m.sack_gap_at.is_none());
        assert!(!m.blackhole);
    }

    #[test]
    fn builder_chain_composes() {
        let m = TapPeerMode::new()
            .with_drop_next_tx()
            .with_sack_gap_at(1460)
            .with_blackhole();
        assert!(m.drop_next_tx);
        assert_eq!(m.sack_gap_at, Some(1460));
        assert!(m.blackhole);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// A9 Task 2: shared test-engine constructor for `test-inject` smoke tests.
//
// The helper itself was hoisted into the library as
// `dpdk_net_core::test_fixtures::make_test_engine` (A9 Task 20) so both
// integration tests and the `engine_inject` cargo-fuzz target can reuse
// it without duplicating the EAL / vdev / EngineConfig boilerplate. We
// re-export it here so pre-hoist `common::make_test_engine` call-sites
// keep compiling unchanged.
// ─────────────────────────────────────────────────────────────────────────

#[cfg(feature = "test-inject")]
#[allow(unused_imports)]
pub use dpdk_net_core::test_fixtures::make_test_engine;

// ─────────────────────────────────────────────────────────────────────────
// A9 Task 3: head-segment builder for multi-seg inject chain smoke tests.
//
// Assembles the L2+L3+TCP-SYN header bytes + `payload` into the first
// segment of what will become an mbuf chain. Follow-up tail segments are
// appended as raw payload continuation — the host stack does not treat
// them as separate SDU boundaries, so the resulting mbuf chain mirrors
// an LRO-merged coalesce-on-NIC shape.
// ─────────────────────────────────────────────────────────────────────────

/// A9 Task 6 smoke helper: build a minimal Ethernet+IPv4+ICMP echo-request
/// frame addressed to the engine. Same shape as `inject_rx_frame_smoke.rs`
/// — dst=our_mac, src=synthetic peer, ethertype=0x0800, IPv4/ICMP with a
/// valid IPv4 checksum so the L3 decode accepts the header. Used by the
/// `fault_injector_smoke` tests as a cheap "any well-formed frame" payload
/// for drop/pass assertions (the ICMP body is discarded after rx_bytes is
/// bumped; the counter of interest is `eth.rx_bytes` / `fault_injector.drops`).
#[cfg(feature = "test-inject")]
pub fn build_icmp_echo_frame(engine: &dpdk_net_core::engine::Engine) -> Vec<u8> {
    let our_mac = engine.our_mac();
    let peer_mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
    let dst_ip_be = engine.our_ip().to_be_bytes();

    let mut frame = Vec::with_capacity(14 + 20 + 8);
    // Ethernet II: dst=our_mac, src=peer_mac, ethertype=0x0800 (IPv4)
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
    frame.extend_from_slice(&[10, 0, 0, 2]); // source IP (arbitrary peer)
    frame.extend_from_slice(&dst_ip_be);
    // Recompute IPv4 cksum so the engine's IP decode accepts the header.
    let cksum = dpdk_net_core::l3_ip::internet_checksum(&[&frame[14..14 + 20]]);
    frame[14 + 10] = (cksum >> 8) as u8;
    frame[14 + 11] = (cksum & 0xff) as u8;
    // ICMP echo request body (type=8, code=0, rest zeroed).
    frame.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]);
    frame
}

/// Build a synthetic Ethernet+IPv4+TCP-SYN frame header + `payload` bytes.
/// Returns the assembled bytes ready to feed `inject_rx_chain`'s first
/// segment. The destination MAC + IP match the engine's configured
/// address; the source MAC/IP are a synthetic peer. `payload` is appended
/// verbatim after the TCP header; IPv4 `total_length` reflects the full
/// IP+TCP+payload span so the length-consistency checks in the engine's
/// IP decode accept the frame. Both checksums are left zero — the
/// inject-smoke assertions only verify chain-walk reaches dispatch, not
/// that TCP actually processes the SYN (`handle_ipv4` stops before the
/// TCP checksum check on an already-invalid L3 csum; on TAP-backed
/// engines we don't care about a SYN-ACK reply).
#[cfg(feature = "test-inject")]
pub fn build_tcp_syn_head(
    engine: &dpdk_net_core::engine::Engine,
    payload: &[u8],
) -> Vec<u8> {
    let our_mac = engine.our_mac();
    let peer_mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xAB];
    let dst_ip_be = engine.our_ip().to_be_bytes();
    let src_ip_be: [u8; 4] = [10, 99, 90, 99];
    let total_len: u16 = 20 + 20 + payload.len() as u16; // IP + TCP + payload
    let mut frame = Vec::with_capacity(14 + total_len as usize);
    // Ethernet II: dst=our_mac, src=peer_mac, ethertype=0x0800 (IPv4)
    frame.extend_from_slice(&our_mac);
    frame.extend_from_slice(&peer_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 (csum=0; engine's rx_cksum path either software-verifies or
    // treats as HW-GOOD under the offload latch; for smoke we don't care
    // whether the packet is dropped post-dispatch, only that dispatch ran)
    frame.push(0x45); // version=4, ihl=5
    frame.push(0x00); // tos
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // id
    frame.extend_from_slice(&0u16.to_be_bytes()); // flags+frag
    frame.push(64); // ttl
    frame.push(6);  // proto = TCP
    frame.extend_from_slice(&0u16.to_be_bytes()); // ip csum
    frame.extend_from_slice(&src_ip_be);
    frame.extend_from_slice(&dst_ip_be);
    // TCP SYN: sport=12345 dport=54321 seq=1000 ack=0 dataoff=5 flags=SYN window=8192
    frame.extend_from_slice(&12345u16.to_be_bytes());
    frame.extend_from_slice(&54321u16.to_be_bytes());
    frame.extend_from_slice(&1000u32.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.push(0x50); // dataoff=5*4=20, no options
    frame.push(0x02); // SYN flag
    frame.extend_from_slice(&8192u16.to_be_bytes()); // window
    frame.extend_from_slice(&0u16.to_be_bytes());    // tcp csum
    frame.extend_from_slice(&0u16.to_be_bytes());    // urg ptr
    // Payload
    frame.extend_from_slice(payload);
    frame
}

// -----------------------------------------------------------------------
// A7 Task 5: test-server harness helpers. Behind `feature = "test-server"`
// because the `Engine::new(cfg.port_id = u16::MAX)` bypass AND the
// `inject_rx_frame` / `drain_tx_frames` APIs they depend on only exist in
// that build.
// -----------------------------------------------------------------------

#[cfg(feature = "test-server")]
pub const OUR_IP: u32 = 0x0a_63_02_02; // 10.99.2.2
#[cfg(feature = "test-server")]
pub const PEER_IP: u32 = 0x0a_63_02_01; // 10.99.2.1

/// In-memory EAL args that bring up DPDK without a PCI NIC or TAP vdev.
/// The test-server bypass (`port_id = u16::MAX`) skips every `rte_eth_*`
/// call so we only need the EAL itself up to register the mempool for
/// `inject_rx_frame`'s mbuf alloc.
#[cfg(feature = "test-server")]
pub fn test_eal_args() -> Vec<&'static str> {
    vec![
        "dpdk-net-test-server",
        "--in-memory",
        "--no-pci",
        "-l",
        "0-1",
        "--log-level=3",
    ]
}

/// `EngineConfig` for the test-server bypass path. `port_id = u16::MAX`
/// triggers `Engine::new`'s `test_server_bypass_port` branch which skips
/// port/queue/start + synthesizes a MAC. All other knobs use defaults
/// that match the existing TAP harness (1460 MSS, 8 conns).
#[cfg(feature = "test-server")]
pub fn test_server_config() -> dpdk_net_core::engine::EngineConfig {
    dpdk_net_core::engine::EngineConfig {
        port_id: u16::MAX,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        // Synthesized by the bypass path; but the builder writes these
        // into `SegmentTx::dst_mac` so any well-formed value works.
        gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        ..Default::default()
    }
}

/// Build an Ethernet-framed IPv4/TCP packet using the same `build_segment`
/// the engine emits on the wire. Thin forwarder to the public helper so
/// out-of-crate test consumers (tools/packetdrill-shim-runner) share the
/// exact same builder logic.
#[cfg(feature = "test-server")]
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_frame(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: dpdk_net_core::tcp_options::TcpOpts,
    payload: &[u8],
) -> Vec<u8> {
    dpdk_net_core::test_server::test_packet::build_tcp_frame(
        src_ip, src_port, dst_ip, dst_port, seq, ack, flags, window, options, payload,
    )
}

#[cfg(feature = "test-server")]
pub fn build_tcp_syn(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    iss: u32,
    peer_mss: u16,
) -> Vec<u8> {
    dpdk_net_core::test_server::test_packet::build_tcp_syn(
        src_ip, src_port, dst_ip, dst_port, iss, peer_mss,
    )
}

#[cfg(feature = "test-server")]
pub fn build_tcp_ack(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    dpdk_net_core::test_server::test_packet::build_tcp_ack(
        src_ip, src_port, dst_ip, dst_port, seq, ack,
    )
}

/// Parse a just-emitted frame from `drain_tx_frames`; extract the
/// SYN-ACK's server ISS (= seq field) + the ack-value (which must be
/// peer_iss + 1). Thin forwarder to the public helper.
#[cfg(feature = "test-server")]
pub fn parse_syn_ack(frame: &[u8]) -> Option<(u32, u32)> {
    dpdk_net_core::test_server::test_packet::parse_syn_ack(frame)
}

/// A7 Task 6: build a bare FIN+ACK segment (flags 0x11). Thin forwarder
/// to the public helper.
#[cfg(feature = "test-server")]
pub fn build_tcp_fin(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    dpdk_net_core::test_server::test_packet::build_tcp_fin(
        src_ip, src_port, dst_ip, dst_port, seq, ack,
    )
}

/// A7 Task 16: build a bare ACK carrying a single SACK block +
/// Timestamps option, for forcing a RACK-driven retransmit of the
/// first segment in the in-memory multi-seg I-8 regression.
/// Thin forwarder to the public helper.
#[cfg(feature = "test-server")]
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_ack_with_sack(
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq: u32,
    ack: u32,
    sack_left: u32,
    sack_right: u32,
    tsval: u32,
) -> Vec<u8> {
    dpdk_net_core::test_server::test_packet::build_tcp_ack_with_sack(
        src_ip, src_port, dst_ip, dst_port, seq, ack, sack_left, sack_right, tsval,
    )
}

/// A7 Task 6: extract `(seq, ack)` from a wire-format TCP frame produced
/// by `drain_tx_frames`. Thin forwarder to the public helper.
#[cfg(feature = "test-server")]
pub fn parse_tcp_seq_ack(frame: &[u8]) -> (u32, u32) {
    dpdk_net_core::test_server::test_packet::parse_tcp_seq_ack(frame)
}

/// A7 Task 6: run a SYN → SYN-ACK → final-ACK three-way handshake against
/// a live `Engine` under the test-server bypass. Returns the accepted
/// `ConnHandle` and our server-side ISS so the caller can craft
/// subsequent segments with correct seq/ack values. Uses `set_virt_ns`
/// to seed the clock for SYN (t=1ms) and the final ACK (t=2ms) — close
/// tests then advance the clock from there.
#[cfg(feature = "test-server")]
pub fn drive_passive_handshake(
    eng: &dpdk_net_core::engine::Engine,
    listen_h: dpdk_net_core::test_server::ListenHandle,
) -> (dpdk_net_core::flow_table::ConnHandle, u32) {
    use dpdk_net_core::clock::set_virt_ns;
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;

    // Drain anything lingering from previous tests.
    let _ = drain_tx_frames();

    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, 40_000, OUR_IP, 5555, 0x10000000, 1460);
    eng.inject_rx_frame(&syn).expect("inject SYN");
    let frames = drain_tx_frames();
    assert_eq!(frames.len(), 1, "exactly one SYN-ACK expected");
    let (our_iss, _ack) = parse_syn_ack(&frames[0]).expect("parse SYN-ACK");

    set_virt_ns(2_000_000);
    let final_ack = build_tcp_ack(
        PEER_IP,
        40_000,
        OUR_IP,
        5555,
        0x10000001,
        our_iss.wrapping_add(1),
    );
    eng.inject_rx_frame(&final_ack).expect("inject final ACK");
    // ESTABLISHED transition must not emit a TX frame.
    let post = drain_tx_frames();
    assert_eq!(
        post.len(),
        0,
        "ESTABLISHED transition must not emit a TX frame"
    );

    let conn = eng.accept_next(listen_h).expect("accept_next yields conn");
    (conn, our_iss)
}
