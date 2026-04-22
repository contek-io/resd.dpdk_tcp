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
    /// A8 T6: our server-side ISS captured from the SYN-ACK during
    /// `do_passive_open`. Zero outside of a live handshake.
    pub our_iss: std::cell::Cell<u32>,
    /// A8 T6: next peer seq-number to use on injected segments; each
    /// helper (`inject_peer_data`, `inject_peer_fin`) advances this
    /// by `seg_len` so the consumer doesn't have to thread it.
    pub peer_seq: std::cell::Cell<u32>,
    _serialize_guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(feature = "test-server")]
impl Drop for CovHarness {
    /// A8 T6: ensure pinned RX mbuf refcounts are released BEFORE the
    /// engine's inner `_rx_mempool` field drops. Rust drops fields in
    /// declaration order, so `Engine._rx_mempool` (line ~406 in
    /// engine.rs) is freed before `Engine.flow_table` (line ~426) ever
    /// runs its `TcpConn::drop` → `MbufHandle::Drop` chain. Any scenario
    /// that injects a payload-carrying segment leaves a live refcount
    /// on an RX mbuf inside `conn.delivered_segments`, so the drop-time
    /// `shim_rte_mbuf_refcnt_update(-1)` would touch a released mempool
    /// (UAF → SIGSEGV). This Drop hook runs before any Engine field
    /// drops, replicating the production top-of-poll drain sequence.
    fn drop(&mut self) {
        self.eng.test_clear_pinned_rx_mbufs();
    }
}

#[cfg(feature = "test-server")]
impl CovHarness {
    /// Take the binary-wide serialization lock, spin up a fresh engine,
    /// seed the virt-clock at 0, and drain any lingering TX frames
    /// from a previous scenario (the intercept queue is thread-local;
    /// serial-running tests on the same thread share the queue).
    pub fn new() -> Self {
        Self::new_with_config(test_server_config())
    }

    /// Like `new` but with a caller-supplied `EngineConfig`. Used by
    /// T6 scenarios that need to override `max_connections` (e.g. to
    /// trigger `tcp.conn_table_full`) or other knobs.
    pub fn new_with_config(cfg: dpdk_net_core::engine::EngineConfig) -> Self {
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
        let eng = Engine::new(cfg).expect("Engine::new");
        // Thread-local TX intercept queue may contain stale frames from
        // a previous scenario on this same thread. Drain so any post-
        // inject `drain_tx_frames` sees only this scenario's frames.
        let _ = drain_tx_frames();
        Self {
            eng,
            our_iss: std::cell::Cell::new(0),
            peer_seq: std::cell::Cell::new(0),
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

    // -----------------------------------------------------------------
    // A8 Task 6: TCP connection-lifecycle helpers. Drive the real TCP
    // state machine paths so `tcp.conn_*` / `tcp.rx_*` / `tcp.tx_*`
    // counters bump via production code (not one-shot). All helpers
    // use `PEER_IP:40000 → OUR_IP:5555` as the canonical tuple so
    // scenarios compose (listen on 5555, handshake, inject further
    // segments on the same tuple).
    // -----------------------------------------------------------------

    /// Drive a full passive-open handshake: listen on 5555, inject SYN,
    /// drain SYN-ACK, inject final ACK. Returns the accepted
    /// `ConnHandle` + our server-side ISS so follow-up helpers
    /// (`inject_peer_fin`, `inject_rst_to_established`, etc.) can
    /// craft segments with correct seq/ack values.
    ///
    /// Counter bumps exercised by this path (per spec §6 FSM):
    ///   - `tcp.rx_syn_ack` (line 3314: peer SYN observed in LISTEN)
    ///   - `tcp.tx_syn` (line 5570: SYN-ACK emission)
    ///   - `tcp.rx_ack` (line 3340: final ACK bit)
    ///   - `tcp.conn_open` (line 3721: Connected event)
    pub fn do_passive_open(&mut self) -> dpdk_net_core::flow_table::ConnHandle {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        let listen_h = self.eng.listen(OUR_IP, 5555).expect("listen");
        // Drain any lingering TX from earlier steps.
        let _ = drain_tx_frames();
        set_virt_ns(1_000_000);
        let syn = build_tcp_syn(PEER_IP, 40_000, OUR_IP, 5555, 0x10000000, 1460);
        self.eng.inject_rx_frame(&syn).expect("inject SYN");
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
        self.eng.inject_rx_frame(&final_ack).expect("inject final ACK");
        let _ = drain_tx_frames();
        let conn = self
            .eng
            .accept_next(listen_h)
            .expect("accept_next yields conn");
        self.our_iss.set(our_iss);
        self.peer_seq.set(0x10000001);
        conn
    }

    /// Inject a payload-carrying segment from peer to us on the
    /// 3WHS-established conn. Uses the tuple from `do_passive_open`.
    /// Counter bumps: `tcp.rx_data` (payload non-empty) + `tcp.rx_ack`
    /// (ACK bit always set in non-SYN segments from a live peer) +
    /// `tcp.tx_ack` (our emit_ack response covers the received data).
    pub fn inject_peer_data(&mut self, payload: &[u8]) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH};

        set_virt_ns(3_000_000);
        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            u16::MAX,
            TcpOpts::default(),
            payload,
        );
        self.eng.inject_rx_frame(&frame).expect("inject data");
        self.peer_seq
            .set(peer_seq.wrapping_add(payload.len() as u32));
    }

    /// Inject a peer FIN (flags 0x11) on the ESTABLISHED conn. The
    /// engine replies with a bare ACK (→ `tcp.tx_ack` bump) and moves
    /// the conn to CLOSE_WAIT. Counter bumps: `tcp.rx_fin` (line 3343)
    /// + `tcp.rx_ack`.
    pub fn inject_peer_fin(&mut self) {
        use dpdk_net_core::clock::{now_ns, set_virt_ns};
        // A8 T8: monotonic-safe advance — some T8 scenarios stack
        // inject_peer_fin AFTER an inject_peer_ack_our_fin (which
        // advanced virt to 30 ms), so a fixed `set_virt_ns(10_000_000)`
        // would panic. `max(now, 10 ms)` preserves the original 10-ms
        // floor for T6 scenarios while letting T8 compose.
        let t = now_ns().max(10_000_000);
        set_virt_ns(t);
        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let fin = build_tcp_fin(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
        );
        self.eng.inject_rx_frame(&fin).expect("inject peer FIN");
        self.peer_seq.set(peer_seq.wrapping_add(1));
    }

    /// Inject a peer RST on the ESTABLISHED conn. The engine closes
    /// the conn without replying. Counter bumps: `tcp.rx_rst` (line
    /// 3346) + `tcp.conn_close` (line 3753) + `tcp.conn_rst` (line
    /// 3761 — the rst_close branch).
    pub fn inject_rst_to_established(&mut self) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_RST};

        set_virt_ns(10_000_000);
        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let rst = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_RST | TCP_ACK,
            0,
            TcpOpts::default(),
            &[],
        );
        self.eng.inject_rx_frame(&rst).expect("inject peer RST");
    }

    /// Drive a full passive-close sequence on an ESTABLISHED conn:
    /// peer FIN → CLOSE_WAIT → server close_conn → LAST_ACK → peer
    /// final ACK → CLOSED (conn slot released). Counter bump:
    /// `tcp.conn_close` at the LAST_ACK → Closed transition (line
    /// 3753, outcome.closed=true) + `tcp.tx_fin` on our close_conn.
    pub fn do_passive_close(&mut self, conn: dpdk_net_core::flow_table::ConnHandle) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        // Peer FINs first → CLOSE_WAIT.
        self.inject_peer_fin();
        let _ = drain_tx_frames();

        // Server closes → LAST_ACK, FIN in flight.
        set_virt_ns(20_000_000);
        self.eng.close_conn(conn).expect("close_conn");
        let fin_frames = drain_tx_frames();
        assert_eq!(fin_frames.len(), 1, "server FIN frame expected");
        let (our_fin_seq, _) = parse_tcp_seq_ack(&fin_frames[0]);

        // Peer ACKs our FIN → CLOSED + conn_close++.
        set_virt_ns(30_000_000);
        let peer_seq = self.peer_seq.get();
        let final_ack = build_tcp_ack(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_fin_seq.wrapping_add(1),
        );
        self.eng.inject_rx_frame(&final_ack).expect("inject peer final ACK");
    }

    /// Active-open path: call `eng.connect()` to a peer that never
    /// responds, then advance the virt-clock past 4 SYN retrans
    /// budget-exhaust fires (`> 3` hits `conn_timeout_syn_sent`
    /// bump at engine.rs:2753). Uses `pump_timers` to drive the
    /// timer wheel — `poll_once` is UB on `port_id == u16::MAX`.
    ///
    /// The timer wheel (`tcp_timer_wheel.rs`) caps each `advance()`
    /// call at `BUCKETS * LEVELS = 2048` ticks (20.48 ms at the default
    /// 10 µs `TICK_NS`). We therefore pump in small steps: 1 ms per
    /// step for 200 steps covers 200 ms of virt-time, well past the
    /// base 5 ms default `tcp_initial_rto_us` × 2^4 = 80 ms backoff.
    ///
    /// Counter bumps: `tcp.tx_syn` (initial + each re-emit) →
    /// `tcp.conn_timeout_syn_sent` (after the 4th retrans budget
    /// exhaust).
    pub fn do_blackhole_active_open(&mut self) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        set_virt_ns(0);
        let _ = self.eng.connect(PEER_IP, 7777, 0).expect("connect");
        // Drain the initial SYN emission so intercept queue doesn't
        // grow unbounded across retrans fires.
        let _ = drain_tx_frames();

        // Walk the virt-clock in 1 ms steps. SYN retrans fires at
        // t = base * 2^n; default base 5 ms → fires at 5/10/20/40/80 ms.
        // 200 steps = 200 ms total covers the full 4-fire budget with
        // wide margin. Each step advances under the 20.48 ms advance()
        // cap, so each pump_timers call fires any timers in-range.
        for i in 1..=200 {
            let now_ns = (i as u64) * 1_000_000; // 1 ms per step
            set_virt_ns(now_ns);
            let _ = self.eng.pump_timers(now_ns);
            // Drain each SYN re-emit so the intercept queue doesn't
            // hold stale frames from prior steps.
            let _ = drain_tx_frames();
        }
    }

    // -----------------------------------------------------------------
    // A8 Task 7: helpers for the TCP protocol-features group
    // (PAWS / SACK / DSACK / retrans / RACK / TLP / windows /
    // reassembly / validation / iovec). Each helper sets up a specific
    // segment / call sequence that lights one bump site inside
    // `tcp_input::dispatch` or `engine::emit_ack` / `send_bytes` /
    // `deliver_readable` / `fire_timers_at`.
    // -----------------------------------------------------------------

    /// Like `do_passive_open` but the SYN we inject carries the full
    /// option bundle (MSS + WS + SACK-perm + Timestamps). This flips
    /// `conn.ts_enabled = true` + `conn.sack_enabled = true` on the
    /// accepted conn, so subsequent scenarios can drive PAWS,
    /// `ts_recent_expired`, `rtt_samples`, and DSACK.
    pub fn do_passive_open_with_ts(&mut self) -> dpdk_net_core::flow_table::ConnHandle {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_SYN};
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        let listen_h = self.eng.listen(OUR_IP, 5555).expect("listen");
        let _ = drain_tx_frames();

        set_virt_ns(1_000_000);
        let mut opts = TcpOpts::default();
        opts.mss = Some(1460);
        opts.wscale = Some(7);
        opts.sack_permitted = true;
        opts.timestamps = Some((1_000u32, 0));
        let syn = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            0x10000000,
            0,
            TCP_SYN,
            u16::MAX,
            opts,
            &[],
        );
        self.eng.inject_rx_frame(&syn).expect("inject SYN");
        let frames = drain_tx_frames();
        assert_eq!(frames.len(), 1, "one SYN-ACK expected");
        let (our_iss, _ack) = parse_syn_ack(&frames[0]).expect("parse SYN-ACK");

        set_virt_ns(2_000_000);
        // Final ACK mirrors the TS option (engine echoes its own TSval
        // on the SYN-ACK; we pass zero for simplicity — handle_syn_received
        // tolerates it).
        let mut ack_opts = TcpOpts::default();
        ack_opts.timestamps = Some((1_001u32, 0));
        let final_ack = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            0x10000001,
            our_iss.wrapping_add(1),
            TCP_ACK,
            u16::MAX,
            ack_opts,
            &[],
        );
        self.eng.inject_rx_frame(&final_ack).expect("inject final ACK");
        let _ = drain_tx_frames();
        let conn = self.eng.accept_next(listen_h).expect("accept_next");
        self.our_iss.set(our_iss);
        self.peer_seq.set(0x10000001);
        conn
    }

    /// Inject a peer data segment carrying the Timestamps option with a
    /// caller-supplied (tsval, tsecr). Used by PAWS + `ts_recent_expired`
    /// scenarios to advance / rewind ts values relative to `conn.ts_recent`.
    /// Requires the conn to have been established with
    /// `do_passive_open_with_ts` (so `conn.ts_enabled == true`).
    pub fn inject_peer_data_with_ts(&mut self, payload: &[u8], tsval: u32, tsecr: u32) {
        use dpdk_net_core::clock::now_ns;
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH};

        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let mut opts = TcpOpts::default();
        opts.timestamps = Some((tsval, tsecr));
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            u16::MAX,
            opts,
            payload,
        );
        // Touch the virt-clock so `now_ns()` reads a stable value (the
        // caller manages the clock for expiration-based scenarios; we
        // avoid perturbing it here).
        let _ = now_ns();
        self.eng.inject_rx_frame(&frame).expect("inject TS data");
        self.peer_seq
            .set(peer_seq.wrapping_add(payload.len() as u32));
    }

    /// Inject a peer ACK carrying one SACK block. The ACK number stays
    /// at `our_iss + 1` (no cum-ACK advance); the SACK range is a
    /// byte-stream seq range. Exercises `tcp.rx_sack_blocks` on decode
    /// and populates the scoreboard.
    ///
    /// TS value is `1_002` — monotonically after the handshake's
    /// last-seen tsval (final ACK carries `1_001`), so PAWS does not
    /// reject. `do_passive_open_with_ts` sets `ts_recent = 1_001` via
    /// the final ACK before releasing the connection to the scenario.
    pub fn inject_peer_ack_with_sack(&mut self, sack_left: u32, sack_right: u32) {
        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let frame = build_tcp_ack_with_sack(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            sack_left,
            sack_right,
            /*tsval*/ 1_002,
        );
        self.eng.inject_rx_frame(&frame).expect("inject SACK ACK");
    }

    /// Inject a peer ACK carrying a DSACK block (covers already-ACKed
    /// data). DSACK is recognized when the SACK block lies entirely
    /// below `snd_una` — see `is_dsack` at tcp_input.rs ~570. The block
    /// falls inside the initial 1-byte region `[our_iss, our_iss+1)`
    /// which `snd_una` has already advanced past after the handshake,
    /// so `is_dsack` returns true and `tcp.rx_dsack` bumps.
    pub fn inject_peer_ack_with_dsack(&mut self) {
        let our_iss = self.our_iss.get();
        // DSACK covers [our_iss, our_iss+1) — a single byte before snd_una.
        self.inject_peer_ack_with_sack(our_iss, our_iss.wrapping_add(1));
    }

    /// Inject a SYN carrying a malformed/unknown option (kind=99 with
    /// len=0). `parse_options` returns `BadKnownLen` on any unrecognized
    /// kind whose length byte is <2; `handle_syn_sent` / `handle_listen`
    /// both propagate that into `Outcome.bad_option` → `tcp.rx_bad_option`.
    ///
    /// NOTE: this path targets `tcp.rx_bad_option` via the established
    /// PAWS-gate code path. The simpler approach: send a TS-bearing data
    /// segment to a non-TS-enabled conn AFTER establishing without TS
    /// — but we can more directly force it by constructing a raw TCP
    /// header with a bad options block and letting `parse_options` fail
    /// during `handle_established`. See
    /// `inject_peer_data_with_bad_option` below.
    pub fn inject_peer_data_with_bad_option(&mut self, payload: &[u8]) {
        use dpdk_net_core::l3_ip::internet_checksum;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH};

        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        // Build a minimal TCP header + 4-byte bad options block. Opts
        // layout: [kind=99 (unknown), len=1 (<2 → BadKnownLen), nop, nop]
        // Data offset = (20 + 4) / 4 = 6 words.
        let mut tcp = Vec::with_capacity(24 + payload.len());
        tcp.extend_from_slice(&40_000u16.to_be_bytes()); // src_port
        tcp.extend_from_slice(&5555u16.to_be_bytes()); // dst_port
        tcp.extend_from_slice(&peer_seq.to_be_bytes()); // seq
        tcp.extend_from_slice(&our_iss.wrapping_add(1).to_be_bytes()); // ack
        tcp.push(6u8 << 4); // data offset = 6
        tcp.push(TCP_ACK | TCP_PSH); // flags
        tcp.extend_from_slice(&u16::MAX.to_be_bytes()); // window
        tcp.extend_from_slice(&[0, 0]); // csum placeholder
        tcp.extend_from_slice(&[0, 0]); // urg ptr
        // Bad options: kind=99, len=1 (invalid, < 2) → parse_options
        // bails with BadKnownLen on the first unrecognized kind's len
        // byte, which triggers `bad_option = true`.
        tcp.extend_from_slice(&[99, 1, 0, 0]);
        tcp.extend_from_slice(payload);

        // TCP pseudo-header + csum.
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&PEER_IP.to_be_bytes());
        pseudo[4..8].copy_from_slice(&OUR_IP.to_be_bytes());
        pseudo[8] = 0;
        pseudo[9] = 6; // TCP
        pseudo[10..12].copy_from_slice(&(tcp.len() as u16).to_be_bytes());
        let csum = internet_checksum(&[&pseudo, &tcp]);
        tcp[16] = (csum >> 8) as u8;
        tcp[17] = (csum & 0xff) as u8;

        // Wrap in IP + L2.
        let ip_hdr = Self::build_ipv4_header(6, PEER_IP, OUR_IP, 64, &tcp);
        self.inject_eth_ip_frame(&ip_hdr);
        self.peer_seq
            .set(peer_seq.wrapping_add(payload.len() as u32));
    }

    /// Drive an active-open whose peer SYN-ACK carries Window Scale = 15
    /// (> RFC 7323's max of 14). `handle_syn_sent` consumes
    /// `parsed_opts.ws_clamped == true` and sets
    /// `outcome.ws_shift_clamped`, which bumps `tcp.rx_ws_shift_clamped`.
    ///
    /// `TcpOpts::encode` writes the wscale raw byte, so setting
    /// `wscale = Some(15)` on the injected SYN-ACK lands the out-of-range
    /// value on the wire.
    pub fn do_active_open_with_ws_clamp(&mut self) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_SYN};
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        set_virt_ns(0);
        let _ = self.eng.connect(PEER_IP, 7777, 0).expect("connect");
        // Drain our active-open SYN so the intercept queue has only the
        // response frame after we inject.
        let frames = drain_tx_frames();
        assert_eq!(frames.len(), 1, "one active-open SYN expected");
        let (_our_src_port, our_iss_plus_one) =
            parse_tcp_seq_ack(&frames[0]);
        // seq in our SYN = our ISS. We injected it; no reliable way to
        // parse back src_port without a richer parser, but the engine
        // currently uses the next ephemeral port. We cheat: the test
        // only needs ws_shift_clamped to bump — we don't need to reach
        // ESTABLISHED. handle_syn_sent processes the SYN-ACK based on
        // the conn's four_tuple; since we don't know the src_port easily,
        // parse it from the emitted SYN.
        let emitted = &frames[0];
        // Ethernet(14) + IPv4 (min 20); TCP starts at 14 + ihl*4.
        let ihl = (emitted[14] & 0x0f) as usize;
        let tcp_off = 14 + ihl * 4;
        let our_src_port = u16::from_be_bytes([emitted[tcp_off], emitted[tcp_off + 1]]);
        let our_iss = u32::from_be_bytes([
            emitted[tcp_off + 4],
            emitted[tcp_off + 5],
            emitted[tcp_off + 6],
            emitted[tcp_off + 7],
        ]);
        let _ = our_iss_plus_one;

        // Build SYN-ACK with WS = 15 (triggers clamp).
        set_virt_ns(1_000_000);
        let peer_iss: u32 = 0x20000000;
        let mut opts = TcpOpts::default();
        opts.mss = Some(1460);
        opts.wscale = Some(15); // > 14 → ws_clamped on peer-side parse
        let syn_ack = build_tcp_frame(
            PEER_IP,
            7777,
            OUR_IP,
            our_src_port,
            peer_iss,
            our_iss.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            u16::MAX,
            opts,
            &[],
        );
        self.eng.inject_rx_frame(&syn_ack).expect("inject SYN-ACK");
        // Drain any responses; we only care about the counter bump.
        let _ = drain_tx_frames();
    }

    /// Inject a peer data segment whose advertised window is 0. Drives
    /// `outcome.rx_zero_window = true` in `handle_established` → bumps
    /// `tcp.rx_zero_window`.
    pub fn inject_peer_zero_window(&mut self, payload: &[u8]) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH};

        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            /*window=*/ 0,
            TcpOpts::default(),
            payload,
        );
        self.eng.inject_rx_frame(&frame).expect("inject zero-wnd");
        self.peer_seq
            .set(peer_seq.wrapping_add(payload.len() as u32));
    }

    /// Inject an OOO (out-of-order) data segment from the peer at
    /// `rcv_nxt + offset`. Lands in `conn.recv.reorder` → bumps
    /// `tcp.rx_reassembly_queued` and parks bytes against the reorder
    /// cap. Used by the zero-window / hole-fill / reassembly scenarios.
    ///
    /// Includes a TS option with `tsval = 1_002 > ts_recent=1_001`
    /// (the handshake final ACK's tsval) so scenarios built on
    /// `do_passive_open_with_ts` pass PAWS. Plain `do_passive_open`
    /// conns have `ts_enabled=false` and ignore the option.
    pub fn inject_peer_ooo_data(&mut self, offset: u32, payload: &[u8]) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH};

        let peer_seq = self.peer_seq.get().wrapping_add(offset);
        let our_iss = self.our_iss.get();
        let mut opts = TcpOpts::default();
        opts.timestamps = Some((1_002u32, 0));
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            u16::MAX,
            opts,
            payload,
        );
        self.eng.inject_rx_frame(&frame).expect("inject OOO");
        // Do NOT advance peer_seq — OOO data doesn't move the in-order
        // pointer; the caller may follow up with a hole-filler.
    }

    /// Inject a segment whose seq is far outside the receive window
    /// (`rcv_nxt + 1_000_000`). `handle_established`'s `in_window` check
    /// rejects → `bad_seq = true` → `tcp.rx_bad_seq` bump + challenge ACK.
    pub fn inject_oob_seq_segment(&mut self) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH};

        let peer_seq = self.peer_seq.get().wrapping_add(1_000_000);
        let our_iss = self.our_iss.get();
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_ACK | TCP_PSH,
            u16::MAX,
            TcpOpts::default(),
            b"x",
        );
        self.eng.inject_rx_frame(&frame).expect("inject oob-seq");
    }

    /// Inject a segment with the URG flag set. `handle_established`
    /// short-circuits to `urgent_dropped = true` → `tcp.rx_urgent_dropped`
    /// bump.
    pub fn inject_segment_with_urg(&mut self) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_URG};

        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_ACK | TCP_URG,
            u16::MAX,
            TcpOpts::default(),
            b"x",
        );
        self.eng.inject_rx_frame(&frame).expect("inject URG");
    }

    /// Inject an ACK whose ack-number is ahead of our `snd_nxt`.
    /// `handle_established` returns `bad_ack = true` → bumps
    /// `tcp.rx_bad_ack`.
    pub fn inject_segment_with_bad_ack(&mut self) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::TCP_ACK;

        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1_000_000), // way ahead of snd_nxt
            TCP_ACK,
            u16::MAX,
            TcpOpts::default(),
            &[],
        );
        self.eng.inject_rx_frame(&frame).expect("inject bad-ack");
    }

    /// Inject a duplicate-ACK sequence (RFC 5681 §2 strict dup). The 5
    /// conditions are: ack==snd_una, no payload, window unchanged,
    /// snd_una != snd_nxt, no SYN/FIN. The caller must have already
    /// moved `snd_una != snd_nxt` by calling `send_bytes` on the conn
    /// prior to this injection.
    pub fn inject_dup_ack(&mut self) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::TCP_ACK;

        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        // Bare ACK with no payload, ack == snd_una (= our_iss+1, since
        // the handshake final ACK left snd_una at iss+1 and our send_bytes
        // advanced snd_nxt past it). Window u16::MAX matches what the
        // prior ACK carried.
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_ACK,
            u16::MAX,
            TcpOpts::default(),
            &[],
        );
        self.eng.inject_rx_frame(&frame).expect("inject dup-ack");
    }

    /// Inject a TCP frame with a deliberately corrupted checksum. `tcp_input`
    /// returns `TcpParseError::Csum` → bumps `tcp.rx_bad_csum`. The
    /// wire layout is ETH(14) + IP(20) + TCP(20)... and the TCP csum
    /// lives at offset 14+20+16 = 50.
    pub fn inject_tcp_frame_bad_csum(&mut self) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::TCP_ACK;

        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let mut frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_ACK,
            u16::MAX,
            TcpOpts::default(),
            &[],
        );
        // TCP csum bytes live at offset eth(14) + ip(20) + tcp_header[16..18].
        frame[14 + 20 + 16] ^= 0xff;
        frame[14 + 20 + 17] ^= 0xff;
        let _ = self.eng.inject_rx_frame(&frame);
    }

    /// Inject a truncated TCP header (< 20 bytes). `parse_segment`
    /// returns `TcpParseError::Short` → bumps `tcp.rx_short`.
    pub fn inject_tcp_short_header(&mut self) {
        // 10-byte TCP "header" — below the 20-byte minimum.
        let tcp_bytes: &[u8] = &[0u8; 10];
        let ip_hdr = Self::build_ipv4_header(6, PEER_IP, OUR_IP, 64, tcp_bytes);
        self.inject_eth_ip_frame(&ip_hdr);
    }

    /// Inject a TCP segment with bad flag combination (SYN + FIN).
    /// `parse_segment` returns `TcpParseError::BadFlags` → bumps
    /// `tcp.rx_bad_flags`.
    pub fn inject_tcp_bad_flags(&mut self) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_FIN, TCP_SYN};

        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            our_iss.wrapping_add(1),
            TCP_SYN | TCP_FIN, // illegal combo per RFC 9293 §3.5
            u16::MAX,
            TcpOpts::default(),
            &[],
        );
        let _ = self.eng.inject_rx_frame(&frame);
    }

    /// Advance the virt-clock by more than the 24-day RFC 7323 §5.5
    /// `TS.Recent` expiration threshold. `TS_RECENT_EXPIRY_NS` =
    /// 24 × 86400 × 1e9 ≈ 2.07e15 ns; we jump 25 days to be safe. The
    /// next TS-bearing segment on a TS-enabled conn takes the expiration
    /// branch, bumping `tcp.ts_recent_expired`.
    pub fn advance_virt_past_ts_recent_expiration(&self) {
        use dpdk_net_core::clock::set_virt_ns;
        const DAY_NS: u64 = 86_400u64 * 1_000_000_000;
        set_virt_ns(25 * DAY_NS);
    }

    /// Inject a peer ACK carrying a TS option with (tsval, tsecr). The
    /// ack number is `new_ack` so the caller can advance `snd_una` to
    /// trigger the RTT-sample path. Used by `cover_tcp_rtt_samples`.
    pub fn inject_peer_ack_with_ts(&mut self, new_ack: u32, tsval: u32, tsecr: u32) {
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::TCP_ACK;

        let peer_seq = self.peer_seq.get();
        let mut opts = TcpOpts::default();
        opts.timestamps = Some((tsval, tsecr));
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            peer_seq,
            new_ack,
            TCP_ACK,
            u16::MAX,
            opts,
            &[],
        );
        self.eng.inject_rx_frame(&frame).expect("inject ts-ack");
    }

    // -----------------------------------------------------------------
    // A8 Task 8: state_trans coverage helpers. Drive specific edges of
    // the 11-state TCP FSM so each `Reached` cell in the 121-cell
    // `state_trans[from][to]` matrix lights up under a targeted scenario.
    // All helpers use the canonical tuple (PEER_IP:40000 → OUR_IP:5555)
    // for passive-open derived scenarios; active-open helpers parse the
    // emitted SYN to recover our ephemeral src_port + ISS.
    // -----------------------------------------------------------------

    /// A8 T8: active-open kickoff — `connect()` inserts a fresh conn in
    /// `Closed`, emits SYN, then transition_conn fires
    /// `Closed → SynSent` (bumps `state_trans[0][2]`). We drain the
    /// emitted SYN frame + stash our src_port + ISS so follow-up helpers
    /// (`inject_rst_to_syn_sent`, `inject_peer_syn_ack_complete_3whs`)
    /// can craft correct peer responses.
    ///
    /// Returns `(our_src_port, our_iss)`.
    pub fn do_active_open_only(&mut self) -> (u16, u32) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        set_virt_ns(0);
        let _ = drain_tx_frames();
        let _handle = self.eng.connect(PEER_IP, 7777, 0).expect("connect");
        let frames = drain_tx_frames();
        assert_eq!(frames.len(), 1, "exactly one active-open SYN expected");
        let emitted = &frames[0];
        let ihl = (emitted[14] & 0x0f) as usize;
        let tcp_off = 14 + ihl * 4;
        let our_src_port = u16::from_be_bytes([emitted[tcp_off], emitted[tcp_off + 1]]);
        let our_iss = u32::from_be_bytes([
            emitted[tcp_off + 4],
            emitted[tcp_off + 5],
            emitted[tcp_off + 6],
            emitted[tcp_off + 7],
        ]);
        self.our_iss.set(our_iss);
        (our_src_port, our_iss)
    }

    /// A8 T8: inject a peer RST to our SynSent conn. Must carry a valid
    /// ACK of our SYN (`ack = our_iss + 1`) per RFC 9293 §3.10.7.3 so
    /// `handle_syn_sent` takes the RST-with-ACK → Closed branch, firing
    /// `state_trans[2][0]`. Takes `(our_src_port, our_iss)` from
    /// `do_active_open_only`.
    pub fn inject_rst_to_syn_sent(&mut self, our_src_port: u16, our_iss: u32) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_RST};

        set_virt_ns(1_000_000);
        // peer_iss arbitrary; ack must cover our SYN (= our_iss + 1).
        let frame = build_tcp_frame(
            PEER_IP,
            7777,
            OUR_IP,
            our_src_port,
            0x20000000,
            our_iss.wrapping_add(1),
            TCP_RST | TCP_ACK,
            u16::MAX,
            TcpOpts::default(),
            &[],
        );
        self.eng
            .inject_rx_frame(&frame)
            .expect("inject RST to SynSent");
    }

    /// A8 T8: active-open complete 3WHS. `connect()` → SYN-ACK injected →
    /// final ACK emitted → ESTABLISHED. Drives both `state_trans[0][2]`
    /// (Closed→SynSent) and `state_trans[2][4]` (SynSent→Established).
    pub fn do_active_open_full(&mut self) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::{TCP_ACK, TCP_SYN};
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        let (our_src_port, our_iss) = self.do_active_open_only();
        set_virt_ns(1_000_000);
        let peer_iss: u32 = 0x20000000;
        let mut opts = TcpOpts::default();
        opts.mss = Some(1460);
        let syn_ack = build_tcp_frame(
            PEER_IP,
            7777,
            OUR_IP,
            our_src_port,
            peer_iss,
            our_iss.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            u16::MAX,
            opts,
            &[],
        );
        self.eng
            .inject_rx_frame(&syn_ack)
            .expect("inject SYN-ACK");
        // Drain our final ACK.
        let _ = drain_tx_frames();
    }

    /// A8 T8: passive-open stopped at SYN_RCVD (listen + peer SYN →
    /// engine emits SYN-ACK but final ACK not injected). Useful for
    /// scenarios that need to inject a malformed segment while the conn
    /// sits in SYN_RCVD. Returns the `ListenHandle` + our server-side
    /// ISS so the caller can craft follow-up segments.
    pub fn do_passive_open_syn_ack_only(
        &mut self,
    ) -> (dpdk_net_core::test_server::ListenHandle, u32) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        let listen_h = self.eng.listen(OUR_IP, 5555).expect("listen");
        let _ = drain_tx_frames();
        set_virt_ns(1_000_000);
        let syn = build_tcp_syn(PEER_IP, 40_000, OUR_IP, 5555, 0x10000000, 1460);
        self.eng.inject_rx_frame(&syn).expect("inject SYN");
        let frames = drain_tx_frames();
        assert_eq!(frames.len(), 1, "one SYN-ACK expected");
        let (our_iss, _ack) = parse_syn_ack(&frames[0]).expect("parse SYN-ACK");
        self.our_iss.set(our_iss);
        self.peer_seq.set(0x10000001);
        (listen_h, our_iss)
    }

    /// A8 T8: inject a final-ACK with a bad ack value while conn is in
    /// SYN_RCVD. `handle_syn_received` returns `TxAction::Rst` +
    /// `new_state = Closed` → `state_trans[3][0]` bumps. Ack is way
    /// ahead of `snd_nxt` so the range check `snd_una+1 <= ack <= snd_nxt`
    /// fails.
    pub fn inject_peer_bad_ack_to_syn_rcvd(&mut self) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::tcp_options::TcpOpts;
        use dpdk_net_core::tcp_output::TCP_ACK;

        set_virt_ns(2_000_000);
        let frame = build_tcp_frame(
            PEER_IP,
            40_000,
            OUR_IP,
            5555,
            0x10000001,
            0xdeadbeef, // way past our snd_nxt
            TCP_ACK,
            u16::MAX,
            TcpOpts::default(),
            &[],
        );
        self.eng
            .inject_rx_frame(&frame)
            .expect("inject bad-ACK to SYN_RCVD");
    }

    /// A8 T8: our-side close — `close_conn` drives Established → FinWait1
    /// or CloseWait → LastAck depending on current state. Bumps
    /// `state_trans[4][5]` (Est→FW1) or `state_trans[7][9]` (CW→LastAck).
    pub fn close_conn(&mut self, conn: dpdk_net_core::flow_table::ConnHandle) {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        set_virt_ns(20_000_000);
        self.eng.close_conn(conn).expect("close_conn");
        // Drain our FIN so subsequent drain_tx_frames in peer-ACK
        // helpers sees only the response.
        let _ = drain_tx_frames();
    }

    /// A8 T8: peer ACK covering our FIN seq. Must follow `close_conn`
    /// which emitted a FIN at our `snd_nxt`; after FIN emission
    /// `snd_nxt = our_fin_seq + 1`. Peer ACK carries
    /// `ack = our_fin_seq + 1` so `fin_has_been_acked` returns true.
    ///
    /// In FinWait1: → FinWait2 (if no FIN) or TimeWait (if FIN set).
    /// In Closing: → TimeWait.
    /// In LastAck: → Closed.
    pub fn inject_peer_ack_our_fin(&mut self) {
        use dpdk_net_core::clock::set_virt_ns;

        set_virt_ns(30_000_000);
        let peer_seq = self.peer_seq.get();
        // our FIN seq lived at our_iss+1 + data; after close our_fin_seq
        // is snd_nxt_before_fin. With no data on conn, FIN was emitted
        // at seq = our_iss + 1 so ack = our_iss + 2 ACKs it.
        let our_iss = self.our_iss.get();
        let ack = our_iss.wrapping_add(2);
        let frame = build_tcp_ack(PEER_IP, 40_000, OUR_IP, 5555, peer_seq, ack);
        self.eng
            .inject_rx_frame(&frame)
            .expect("inject peer-ACK-our-FIN");
    }

    /// A8 T8: peer FIN that does NOT ACK our pending FIN (simultaneous
    /// close: peer's FIN crosses ours in flight). `handle_close_path` in
    /// FinWait1 sees `fin_acked=false, peer_has_fin=true` → transitions
    /// to Closing. Ack value is left at our `snd_una` (still = our_iss+1)
    /// so `fin_has_been_acked` returns false (our FIN at our_iss+1 NOT
    /// covered by ack = our_iss+1; RFC says `<=` but our FIN seq is
    /// snd_una's value, not beyond it).
    pub fn inject_peer_fin_no_ack_of_our_fin(&mut self) {
        use dpdk_net_core::clock::set_virt_ns;

        set_virt_ns(25_000_000);
        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        // Ack only our SYN (= our_iss + 1), not our FIN.
        let ack = our_iss.wrapping_add(1);
        let fin = build_tcp_fin(PEER_IP, 40_000, OUR_IP, 5555, peer_seq, ack);
        self.eng
            .inject_rx_frame(&fin)
            .expect("inject peer FIN no ACK");
        self.peer_seq.set(peer_seq.wrapping_add(1));
    }

    /// A8 T8: peer FIN that also ACKs our FIN. Used to drive FinWait1 →
    /// TimeWait in one segment (fin_acked=true, peer_has_fin=true).
    pub fn inject_peer_fin_ack_combined(&mut self) {
        use dpdk_net_core::clock::set_virt_ns;

        set_virt_ns(25_000_000);
        let peer_seq = self.peer_seq.get();
        let our_iss = self.our_iss.get();
        let ack = our_iss.wrapping_add(2); // covers our FIN
        let fin = build_tcp_fin(PEER_IP, 40_000, OUR_IP, 5555, peer_seq, ack);
        self.eng
            .inject_rx_frame(&fin)
            .expect("inject peer FIN+ACK");
        self.peer_seq.set(peer_seq.wrapping_add(1));
    }

    /// A8 T8: advance the virt-clock past 2×MSL and drive
    /// `reap_time_wait`. Uses the test-server-only `test_reap_time_wait`
    /// shim so we don't need `poll_once` (which is UB on
    /// `port_id == u16::MAX`). Transitions all eligible TIME_WAIT conns
    /// to CLOSED, bumping `state_trans[10][0]`.
    pub fn advance_virt_past_2msl_and_reap(&self) {
        use dpdk_net_core::clock::set_virt_ns;
        // Default tcp_msl_ms is 100 ms (test_server_config); 2×MSL =
        // 200 ms. Jump a full second past our last set_virt_ns
        // checkpoint (which sits at ≤ 30 ms in close_conn sequences) to
        // ensure `now >= deadline`.
        set_virt_ns(5_000_000_000);
        self.eng.test_reap_time_wait();
    }

    /// A8 T9: send `buf` on `conn` and drain the pending-data ring. The
    /// `tcp.tx_payload_bytes` accumulator bump lives inside `send_bytes`
    /// itself (engine.rs:4739, flushed as a single `fetch_add` per
    /// `send_bytes` invocation), so the flush is not strictly required
    /// for the counter — but we drain the ring so any follow-on
    /// `drain_tx_frames()` in the scenario sees only subsequent frames.
    /// Gated on `obs-byte-counters` because the only scenario using it
    /// lives under the same gate.
    #[cfg(feature = "obs-byte-counters")]
    pub fn send_bytes_and_flush(
        &mut self,
        conn: dpdk_net_core::flow_table::ConnHandle,
        buf: &[u8],
    ) {
        let _ = self.eng.send_bytes(conn, buf);
        self.eng.flush_tx_pending_data();
    }
}

