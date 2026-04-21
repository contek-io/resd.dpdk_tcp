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

// ─────────────────────────────────────────────────────────────────────────
// A9 Task 2: shared test-engine constructor for `test-inject` smoke tests.
//
// Stands up a minimal `Engine` backed by a DPDK TAP vdev. Requires
// `DPDK_NET_TEST_TAP=1` + sudo + hugepages (same gate as every other TAP
// test in this crate). Returns `None` when the gate is unmet so the
// caller can skip cleanly without taking down the test run.
//
// The returned `Engine` is the caller's to keep alive — mempool + port
// handles drop when it goes out of scope.
// ─────────────────────────────────────────────────────────────────────────

/// Per-process latch so multiple inject tests can share one EAL init
/// (rte_eal_init is idempotent-rejected once called; the `engine::eal_init`
/// wrapper handles that, but we also avoid racing tests that call it
/// concurrently). `Mutex<bool>` mirrors the existing EAL_INIT in engine.rs.
#[cfg(feature = "test-inject")]
static TEST_INJECT_EAL_INIT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// Build a minimal `Engine` suitable for `test-inject` hook smoke tests.
///
/// Returns `None` when `DPDK_NET_TEST_TAP` is not `1` so the caller
/// (test) can early-return and skip. Panics on environment failures
/// that the test harness should surface loudly (EAL init fail,
/// port setup fail, hugepage exhaustion) rather than silently
/// skip — matches the behaviour of the other TAP-gated tests.
///
/// Follows the same EAL args + vdev pattern as `tcp_basic_tap.rs`
/// (`net_tap0` + a unique iface name so concurrent inject tests
/// don't collide with the production-path TAP tests).
#[cfg(feature = "test-inject")]
pub fn make_test_engine() -> Option<dpdk_net_core::engine::Engine> {
    use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};

    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!(
            "make_test_engine: DPDK_NET_TEST_TAP unset; skipping. \
             Set DPDK_NET_TEST_TAP=1 (and run with sudo + hugepages) \
             to exercise the test-inject hook end-to-end."
        );
        return None;
    }

    {
        let mut guard = TEST_INJECT_EAL_INIT.lock().unwrap();
        if !*guard {
            let args = [
                "dpdk-net-a9-inject-test",
                "--in-memory",
                "--no-pci",
                // Unique iface so the inject tests can coexist with
                // the L2/L3/TCP TAP suites. dpdktap9x range is reserved
                // for A9 test-inject.
                "--vdev=net_tap0,iface=dpdktap90",
                "-l",
                "0-1",
                "--log-level=3",
            ];
            eal_init(&args).expect("EAL init (test-inject smoke)");
            *guard = true;
        }
    }

    // Use 10.99.90.2 so the inject tests don't collide with any of the
    // existing /24s (the TAP suite carves 10.99.[0..30].0/24).
    let cfg = EngineConfig {
        port_id: 0,
        local_ip: 0x0a_63_5a_02, // 10.99.90.2
        gateway_ip: 0x0a_63_5a_01, // 10.99.90.1
        // Static gateway MAC; the inject smoke test does not emit
        // TX traffic, so this value is inert.
        gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        garp_interval_sec: 0,
        tcp_msl_ms: 100,
        max_connections: 8,
        ..Default::default()
    };
    Some(Engine::new(cfg).expect("engine new (test-inject smoke)"))
}
