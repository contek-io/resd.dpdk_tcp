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

// -----------------------------------------------------------------------
// A8 Task 4: counter-coverage harness. Parallel to `tests/knob-coverage.rs`
// but for counters instead of behavioral knobs. Each `cover_<group>_<field>`
// scenario in `tests/counter-coverage.rs` acquires a `CovHarness`, drives
// the minimal packet/call sequence to exercise the counter's increment
// site, and asserts the counter > 0.
//
// **Why a serialization Mutex?** `Engine::new` allocates three DPDK
// mempools whose names embed `lcore_id` (engine.rs ~860). Two concurrent
// `Engine::new` calls in one process collide on the mempool name and the
// second returns `Error::MempoolCreate`. Cargo's default test harness
// runs tests in parallel, so scenarios would race. We serialize all
// counter-coverage tests behind one binary-wide Mutex<()>: each scenario
// constructs a fresh `Engine`, runs, then drops it — mempools are freed
// before the next scenario claims the name. `Engine` itself is
// `!Send + !Sync` by design (the flow table holds `RefCell` + raw
// `NonNull<rte_mbuf>`), so sharing the engine across threads is not an
// option — serialization + per-scenario construction is.
//
// The harness wraps `Engine` directly — there is intentionally no
// `TestEngine` wrapper type. Follows the `eal_init` + `Engine::new` +
// `inject_rx_frame` pattern established by A7's test-server integration
// tests (see `test_server_listen_accept_established.rs`,
// `test_server_passive_close.rs`).
//
// `eal_init` itself guards against repeated initialization via a
// `Mutex<bool>` in `engine.rs` — the `eal_init` call below is a no-op
// after the first scenario that runs.
// -----------------------------------------------------------------------

/// Binary-wide serialization lock for counter-coverage scenarios.
/// Held by `CovHarness` for the duration of one scenario so the
/// Engine-construction → inject → drop cycle is serial across cargo's
/// parallel test workers.
#[cfg(feature = "test-server")]
static ENGINE_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Harness for counter-coverage scenarios. Owns one fresh `Engine` for
/// the scenario under the test-server bypass (`port_id = u16::MAX`);
/// zero-state counters on construction. The serialization `MutexGuard`
/// ensures no other scenario in this binary is constructing or holding
/// an `Engine` concurrently.
#[cfg(feature = "test-server")]
pub struct CovHarness {
    // Fields drop in declaration order: `eng` first (frees mempools),
    // then `_serialize_guard` (releases the binary-wide lock). Holding
    // the guard across `Engine` drop guarantees the mempool names are
    // back in DPDK's pool before the next scenario's `Engine::new`.
    pub eng: dpdk_net_core::engine::Engine,
    _serialize_guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(feature = "test-server")]
impl CovHarness {
    /// Take the binary-wide serialization lock, spin up a fresh engine,
    /// seed the virt-clock at 0, and drain any lingering TX frames
    /// from a previous scenario (the intercept queue is thread-local;
    /// serial-running tests on the same thread share the queue).
    pub fn new() -> Self {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::engine::{eal_init, Engine};
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        // Lock before any DPDK interaction so parallel cargo-test
        // workers funnel through here one at a time. Propagate poison
        // so a panicked prior scenario surfaces in CI logs.
        let guard = ENGINE_SERIALIZE
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        set_virt_ns(0);
        eal_init(&test_eal_args()).expect("eal_init");
        let eng = Engine::new(test_server_config()).expect("Engine::new");
        // Thread-local TX intercept queue may contain stale frames from
        // a previous scenario on this same thread. Drain so any post-
        // inject `drain_tx_frames` sees only this scenario's frames.
        let _ = drain_tx_frames();
        Self {
            eng,
            _serialize_guard: guard,
        }
    }

    /// Inject a well-formed SYN targeting a port the engine is NOT
    /// listening on. The engine routes it into the unmatched-segment
    /// path → bumps `tcp.rx_unmatched` + emits an RST (→ `eth.tx_pkts`,
    /// `tcp.tx_rst`). `inject_rx_frame` itself bumps `eth.rx_pkts` /
    /// `eth.rx_bytes` (mirroring `poll_once`'s per-burst rx counters on
    /// the inject path) so dynamic counter-coverage assertions against
    /// those counters exercise genuine engine-internal code.
    pub fn inject_valid_syn_to_closed_port(&mut self) {
        let frame = build_tcp_syn(
            PEER_IP, 40_000, OUR_IP, /*unlistened port*/ 5999, /*iss*/ 0x1000, 1460,
        );
        // inject_rx_frame drives the L2/L3/TCP decode chain (same entry
        // point poll_once invokes per-mbuf) and bumps eth.rx_pkts /
        // eth.rx_bytes from within the engine. Ignore the Result —
        // malformed frames return Err but still advance the counters we
        // care about for this audit.
        let _ = self.eng.inject_rx_frame(&frame);
    }

    /// Inject an arbitrary byte buffer (may be malformed). Used by
    /// scenarios that assert on early-drop counters (e.g. 10-byte frame
    /// → `eth.rx_drop_short`). `inject_rx_frame` bumps `eth.rx_pkts` /
    /// `eth.rx_bytes` on every successful mbuf-alloc+append (those
    /// bumps are inside the engine now, not the harness), then drives
    /// `rx_frame` where the L2-decode short-frame drop arm bumps the
    /// counter under test.
    pub fn inject_raw_bytes(&mut self, buf: &[u8]) {
        // inject_rx_frame errors on frame.len() > u16::MAX or mempool
        // exhaustion; for malformed-short frames (the T4 warm-up use
        // case) it completes the mbuf alloc/append successfully and
        // hits the L2Drop::Short arm inside rx_frame.
        let _ = self.eng.inject_rx_frame(buf);
    }

    /// Assert the named counter (`group.field` path, e.g.
    /// `"eth.rx_drop_short"`) is strictly greater than zero. Panics
    /// with the counter name and observed value on failure so CI
    /// failures map directly to the uncovered counter.
    pub fn assert_counter_gt_zero(&self, name: &str) {
        use std::sync::atomic::Ordering;
        let c = dpdk_net_core::counters::lookup_counter(self.eng.counters(), name)
            .unwrap_or_else(|| panic!("unknown counter path: {name}"));
        let v = c.load(Ordering::Relaxed);
        assert!(v > 0, "counter {name} expected > 0, got {v}");
    }

    // -----------------------------------------------------------------
    // A8 Task 5: hardware-path-only counter bump helper + injection
    // helpers used by `tests/counter-coverage.rs` to drive the remaining
    // counters in eth.*, ip.*, and poll.* groups.
    // -----------------------------------------------------------------

    /// For counters whose real bump site fires only on live NIC
    /// bring-up (ENA xstats, LLQ verification, per-queue ENA xstats)
    /// or on paths the test-server bypass cannot reach (TX-ring-full
    /// in the interceptor, `rte_eth_rx_burst` on port_id=u16::MAX).
    ///
    /// The static audit (T3 / `scripts/counter-coverage-static.sh`)
    /// has already verified the source has an increment site in the
    /// default OR all-features build. This helper demonstrates the
    /// counter-path is addressable via `lookup_counter` (closes the
    /// "renamed but not rewired" bug class), not that the production
    /// path fires end-to-end. Each scenario using this helper also
    /// carries a doc-comment pointing at the real bump site per spec
    /// §3.3 acceptability clause.
    pub fn bump_counter_one_shot(&self, name: &str) {
        use std::sync::atomic::Ordering;
        let c = dpdk_net_core::counters::lookup_counter(self.eng.counters(), name)
            .unwrap_or_else(|| panic!("unknown counter path: {name}"));
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Inject a 14-byte Ethernet frame whose dst MAC matches neither
    /// `our_mac` (synthesized to `02:00:00:00:00:01` by the test-server
    /// bypass — see engine.rs:1028) nor the broadcast address. L2
    /// decoder returns `L2Drop::MissMac` → `eth.rx_drop_miss_mac` bump.
    pub fn inject_frame_wrong_dst_mac(&mut self) {
        // dst = 0xaa:0xaa:0xaa:0xaa:0xaa:0xaa (not us, not broadcast)
        // src = arbitrary; ethertype = IPv4 (0x0800); no payload needed —
        // l2_decode rejects on dst-MAC before reading ethertype.
        let frame: [u8; 14] = [
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, // dst
            0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src (arbitrary)
            0x08, 0x00, // ethertype IPv4
        ];
        let _ = self.eng.inject_rx_frame(&frame);
    }

    /// Inject a 14-byte Ethernet frame whose ethertype is IPv6
    /// (0x86DD) — not IPv4 / not ARP. L2 decoder returns
    /// `L2Drop::UnknownEthertype` → `eth.rx_drop_unknown_ethertype`
    /// bump.
    pub fn inject_frame_unknown_ethertype(&mut self) {
        // dst = our MAC (otherwise MissMac drops first); src = peer;
        // ethertype = IPv6 = 0x86DD.
        let frame: [u8; 14] = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // dst = our_mac
            0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // src
            0x86, 0xdd, // IPv6 ethertype
        ];
        let _ = self.eng.inject_rx_frame(&frame);
    }

    /// Inject an ARP REQUEST frame targeting OUR_IP. `handle_arp`
    /// bumps `eth.rx_arp` on decode; the subsequent `build_arp_reply`
    /// + `tx_frame` path then bumps `eth.tx_arp` + `eth.tx_pkts` +
    /// `eth.tx_bytes`. Reuses the ARP wire shape from
    /// `tests/l2_l3_tap.rs` (Case 7).
    pub fn inject_arp_request_to_us(&mut self) {
        let peer_mac: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let mut frame = Vec::with_capacity(14 + 28);
        // L2: broadcast dst, peer src, ARP ethertype.
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&peer_mac);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        // ARP body (28 bytes): htype=1, ptype=0x0800, hlen=6, plen=4,
        // op=REQUEST, sender_mac, sender_ip, target_mac=0, target_ip=us.
        frame.extend_from_slice(&1u16.to_be_bytes()); // htype ETH
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype IPv4
        frame.push(6); // hlen
        frame.push(4); // plen
        frame.extend_from_slice(&1u16.to_be_bytes()); // op=REQUEST
        frame.extend_from_slice(&peer_mac); // sender_mac
        frame.extend_from_slice(&PEER_IP.to_be_bytes()); // sender_ip
        frame.extend_from_slice(&[0u8; 6]); // target_mac (unknown)
        frame.extend_from_slice(&OUR_IP.to_be_bytes()); // target_ip
        // handle_arp checks `target_ip == cfg.local_ip` (= OUR_IP) and
        // `cfg.local_ip != 0`; our config sets local_ip = OUR_IP so
        // this satisfies both conditions — engine builds + tx's the
        // ARP reply, which drives the tx_arp counter.
        let _ = self.eng.inject_rx_frame(&frame);
    }

    /// Build an Ethernet+IPv4 frame with the given IP-header bytes +
    /// payload. Caller supplies an already-valid or deliberately-bad
    /// IP header; this helper just wraps L2 around it and injects.
    /// dst MAC = our MAC so L2 accept, src MAC arbitrary.
    ///
    /// Used by IP-decode drop scenarios (short, bad_version, bad_hl,
    /// bad_total_len, ttl_zero, csum_bad, fragment, not_ours,
    /// unsupported_proto) — each sets a specific IP-header byte to a
    /// bad value and relies on `ip_decode` to return the matching
    /// `L3Drop` arm, which bumps the corresponding counter.
    pub fn inject_eth_ip_frame(&mut self, ip_bytes: &[u8]) {
        let mut frame = Vec::with_capacity(14 + ip_bytes.len());
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // dst = us
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // src = peer
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
        frame.extend_from_slice(ip_bytes);
        let _ = self.eng.inject_rx_frame(&frame);
    }

    /// Build a minimal well-formed IPv4 header (20 bytes, no options,
    /// DF set, checksum computed) with caller-supplied protocol /
    /// src_ip / dst_ip / ttl / payload. Used by IP-decode scenarios
    /// that need to pass the structural checks but mutate specific
    /// fields (e.g., ttl=0 → TtlZero, proto=17 → UnsupportedProto,
    /// dst != OUR_IP → NotOurs).
    pub fn build_ipv4_header(
        proto: u8,
        src: u32,
        dst: u32,
        ttl: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut v = vec![
            0x45,                       // version=4, IHL=5
            0x00,                       // DSCP/ECN
            (total >> 8) as u8,
            (total & 0xff) as u8,       // total_length
            0x00, 0x01,                 // identification
            0x40, 0x00,                 // flags=DF, frag_off=0
            ttl,                        // TTL
            proto,                      // protocol
            0x00, 0x00,                 // checksum placeholder
        ];
        v.extend_from_slice(&src.to_be_bytes());
        v.extend_from_slice(&dst.to_be_bytes());
        let c = dpdk_net_core::l3_ip::internet_checksum(&[&v]);
        v[10] = (c >> 8) as u8;
        v[11] = (c & 0xff) as u8;
        v.extend_from_slice(payload);
        v
    }
}

