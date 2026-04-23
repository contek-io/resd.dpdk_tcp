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
        probes::checksum::zero_checksum(), // A8.5 T1
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
