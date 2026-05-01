//! tcpreq-runner — Layer C RFC 793bis MUST/SHOULD probe suite (narrow port).
//!
//! Spec §3.1: 4 probes ported from https://github.com/TheJokr/tcpreq
//! (2020 Python codebase): MissingMSS, LateOption, Reserved-RX, Urgent.
//! Probes that duplicate Layer A coverage are NOT ported; see SKIPPED.md
//! for the per-module justification with Layer A / Layer B citations.
//!
//! Each probe constructs a fresh engine via common test-server infra,
//! injects crafted Ethernet frames into the engine via the test-FFI,
//! drains TX frames, asserts compliance. Report lines reference the
//! RFC 793bis MUST clause id so the M5 compliance matrix can cite
//! the probe by one stable handle.

pub mod probes;

// -------------------------------------------------------------------------
// Shared frame-mutation helpers. Two checksum recompute helpers + a
// constant for the test-server wire layout. Used by probes that splice
// bytes into the TCP options region (options.rs) and/or mutate the TCP
// header (reserved.rs, urgent.rs). Kept here so probes don't duplicate
// the pseudo-header fold; the logic is identical across every
// `test_packet::build_tcp_frame`-derived frame because the L2+L3
// layout is fixed (14-byte Ethernet + 20-byte IPv4, no IP options).
// -------------------------------------------------------------------------

/// L2 Ethernet header (14) + IPv4 header (20, no IP options) — the
/// test-server `build_segment` always emits this exact layout. TCP
/// header starts at this byte offset within any frame built via
/// `test_packet::build_tcp_frame` or `build_tcp_syn`.
pub const TCP_HDR_OFFSET: usize = 14 + 20;

/// Recompute the IPv4 header checksum in place after mutating any
/// field in the 20-byte IPv4 header (typically `total_length` after
/// growing the TCP option region). Standard RFC 1071 one's-complement
/// fold over the 20 header bytes with the checksum field zeroed.
///
/// Layout assumed: `frame[0..14]` = Ethernet header, `frame[14..34]` =
/// IPv4 header (no IP options). Callers MUST have written the updated
/// IPv4 fields before this call; this helper only zeros+folds the
/// checksum.
pub fn recompute_ip_csum(frame: &mut [u8]) {
    let ip_off = 14usize;
    frame[ip_off + 10] = 0;
    frame[ip_off + 11] = 0;
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        sum += ((frame[ip_off + i] as u32) << 8) | (frame[ip_off + i + 1] as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let csum = !(sum as u16);
    frame[ip_off + 10] = (csum >> 8) as u8;
    frame[ip_off + 11] = (csum & 0xFF) as u8;
}

/// Recompute the TCP checksum in place after mutating any byte within
/// the TCP header or payload (including the options region) of an
/// Ethernet-framed IPv4/TCP packet produced by
/// `test_packet::build_tcp_frame`.
///
/// Re-uses `dpdk_net_core::l3_ip::internet_checksum` for the
/// pseudo-header fold so the byte-for-byte result matches what
/// `build_segment` would have produced had the mutation been present
/// from the start.
///
/// * `tcp_hdr_offset` MUST equal the byte offset of the TCP header —
///   always `TCP_HDR_OFFSET` (34) for test-server frames; parameterized
///   so probes that need to recompute against an unusual layout can do
///   so explicitly.
pub fn recompute_tcp_csum(frame: &mut [u8], tcp_hdr_offset: usize) {
    use dpdk_net_core::l3_ip::{internet_checksum, IPPROTO_TCP};

    // Zero the csum field (TCP offset 16..18) before folding.
    frame[tcp_hdr_offset + 16] = 0;
    frame[tcp_hdr_offset + 17] = 0;

    // Extract src/dst IPs from the IPv4 header at bytes [14..34].
    let mut src_ip_bytes = [0u8; 4];
    src_ip_bytes.copy_from_slice(&frame[14 + 12..14 + 16]);
    let mut dst_ip_bytes = [0u8; 4];
    dst_ip_bytes.copy_from_slice(&frame[14 + 16..14 + 20]);

    let tcp_seg_len = (frame.len() - tcp_hdr_offset) as u16;

    // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_len(2).
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip_bytes);
    pseudo[4..8].copy_from_slice(&dst_ip_bytes);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    pseudo[10..12].copy_from_slice(&tcp_seg_len.to_be_bytes());

    let tcp_body = &frame[tcp_hdr_offset..];
    let csum = internet_checksum(&[&pseudo, tcp_body]);
    frame[tcp_hdr_offset + 16] = (csum >> 8) as u8;
    frame[tcp_hdr_offset + 17] = (csum & 0xff) as u8;
}

/// Probe result — one row per RFC clause id.
#[derive(Debug)]
pub struct ProbeResult {
    pub clause_id: &'static str,   // e.g. "MUST-15"
    pub probe_name: &'static str,  // e.g. "MissingMSS"
    pub status: ProbeStatus,
    pub message: String,
}

#[derive(Debug)]
pub enum ProbeStatus {
    Pass,
    /// Documented deviation. Cite the spec §6.4 row id (e.g. "AD-A8-urg-dropped").
    Deviation(&'static str),
    Fail(String),
}

/// Run every ported probe. Returns one ProbeResult per probe.
/// Consumed by M5's compliance matrix reporter.
pub fn run_all_probes() -> Vec<ProbeResult> {
    vec![
        probes::mss::missing_mss(),
        probes::mss::late_option(),
        probes::reserved::reserved_rx(),
        probes::urgent::urgent_dropped(),
        probes::checksum::zero_checksum(),  // A8.5 T1
        probes::options::option_support(),  // A8.5 T2
        probes::options::unknown_option(),  // A8.5 T2
        probes::options::illegal_length(),  // A8.5 T2
        probes::mss::mss_support(),         // A8.5 T3
        probes::rst_ack::rst_ack_processing(),  // A8.5 T4
    ]
}

// -------------------------------------------------------------------------
// A8 T19: test-server harness for probe execution. Parallel to
// `crates/dpdk-net-core/tests/common::CovHarness` (counter-coverage).
//
// Why a serialization Mutex?  `Engine::new` allocates DPDK mempools whose
// names embed `lcore_id` (engine.rs ~860). Two concurrent `Engine::new`
// calls in one process collide on the mempool name and the second returns
// `Error::MempoolCreate`. Cargo's test harness runs tests in parallel, so
// probes would race. We serialize all probes behind one crate-wide Mutex:
// each probe constructs a fresh `Engine`, runs, then drops it — mempools
// are freed before the next probe claims the name. `Engine` itself is
// `!Send + !Sync`, so serialization + per-probe construction is the only
// option.
//
// `eal_init` itself guards against repeated initialization via a
// `Mutex<bool>` in `engine.rs` — the `eal_init` call here is a no-op
// after the first probe.
// -------------------------------------------------------------------------

/// Canonical local IP for probe-facing listen sockets. Matches `OUR_IP`
/// in `crates/dpdk-net-core/tests/common/mod.rs` so the test-server
/// bypass wire-format stays byte-identical to the counter-coverage rig.
pub const OUR_IP: u32 = 0x0a_63_02_02; // 10.99.2.2
/// Canonical peer IP for probe-origin frames. Matches `PEER_IP` in
/// `tests/common/mod.rs`.
pub const PEER_IP: u32 = 0x0a_63_02_01; // 10.99.2.1

/// Binary-wide serialization lock for tcpreq-runner probes. Held by
/// `TcpreqHarness` for the duration of one probe so the Engine-
/// construction → inject → drop cycle is serial across cargo's
/// parallel test workers.
static ENGINE_SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// EAL args for the test-server bypass (no PCI NIC, no TAP vdev). The
/// bypass path (`port_id = u16::MAX`) skips every `rte_eth_*` call so we
/// only need the EAL itself up to register the mempool for
/// `inject_rx_frame`'s mbuf alloc. Duplicated from
/// `tests/common::test_eal_args` since the tests module is not
/// reachable from out-of-crate consumers.
fn tcpreq_test_eal_args() -> Vec<&'static str> {
    vec![
        "tcpreq-runner-test-server",
        "--in-memory",
        "--no-pci",
        "-l",
        "0-1",
        "--log-level=3",
    ]
}

/// `EngineConfig` for the test-server bypass path. `port_id = u16::MAX`
/// triggers the `test_server_bypass_port` branch in `Engine::new` which
/// skips port/queue/start + synthesizes a MAC. Duplicated from
/// `tests/common::test_server_config`.
fn tcpreq_test_server_config() -> dpdk_net_core::engine::EngineConfig {
    dpdk_net_core::engine::EngineConfig {
        port_id: u16::MAX,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        ..Default::default()
    }
}

/// Per-probe harness. Owns a fresh `Engine` under the test-server bypass.
/// Zero-state counters on construction. The serialization `MutexGuard`
/// ensures no other probe in this binary is constructing or holding an
/// `Engine` concurrently.
pub struct TcpreqHarness {
    /// Field drop order matters: `eng` first (frees mempools), then
    /// `_serialize_guard` (releases the binary-wide lock). Holding the
    /// guard across Engine drop guarantees the mempool names are back
    /// in DPDK's pool before the next probe's `Engine::new`.
    pub eng: dpdk_net_core::engine::Engine,
    _serialize_guard: std::sync::MutexGuard<'static, ()>,
}

impl Drop for TcpreqHarness {
    /// Mirror `CovHarness::Drop`: release pinned RX mbuf refcounts
    /// BEFORE `Engine._rx_mempool` drops. Without this, a probe that
    /// injected a payload-carrying segment would leave a live refcount
    /// on an RX mbuf inside `conn.delivered_segments`; the drop-time
    /// `shim_rte_mbuf_refcnt_update(-1)` would then touch a released
    /// mempool (UAF → SIGSEGV). No harm done if the probe never pinned
    /// a mbuf — the clear call is idempotent.
    fn drop(&mut self) {
        self.eng.test_clear_pinned_rx_mbufs();
    }
}

impl TcpreqHarness {
    /// Take the crate-wide serialization lock, spin up a fresh engine,
    /// seed the virt-clock at 0, and drain any lingering TX frames
    /// from a previous probe (the intercept queue is thread-local;
    /// serial-running probes on the same thread share the queue).
    pub fn new() -> Self {
        use dpdk_net_core::clock::set_virt_ns;
        use dpdk_net_core::engine::{eal_init, Engine};
        use dpdk_net_core::test_tx_intercept::drain_tx_frames;

        let guard = ENGINE_SERIALIZE
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        set_virt_ns(0);
        eal_init(&tcpreq_test_eal_args()).expect("eal_init");
        let eng = Engine::new(tcpreq_test_server_config()).expect("Engine::new");
        // Thread-local TX intercept queue may contain stale frames from
        // a previous probe on this same thread. Drain so any post-inject
        // `drain_tx_frames` sees only this probe's frames.
        let _ = drain_tx_frames();
        Self {
            eng,
            _serialize_guard: guard,
        }
    }
}

impl Default for TcpreqHarness {
    fn default() -> Self {
        Self::new()
    }
}
