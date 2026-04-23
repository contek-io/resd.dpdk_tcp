//! A9 Task 20: shared test-harness fixtures for `test-inject` consumers.
//!
//! Hoisted from `tests/common/mod.rs` into the crate so both the
//! integration-test `common` helper and the `cargo-fuzz` `engine_inject`
//! target can build an `Engine` without duplicating the DPDK / EAL
//! setup boilerplate. Gated behind `#[cfg(feature = "test-inject")]`
//! so release builds never ship the fixture helpers.
//!
//! Runtime behaviour matches the pre-hoist `common::make_test_engine`
//! exactly: returns `None` when `DPDK_NET_TEST_TAP != "1"` so the
//! caller can skip cleanly, panics on environmental failures we want
//! surfaced loudly (EAL init fail, port init fail, hugepage
//! exhaustion).

#![cfg(feature = "test-inject")]

use crate::engine::{eal_init, Engine, EngineConfig};

/// Per-process latch so multiple inject callers (tests + fuzz target)
/// can share one EAL init. `eal_init` itself has an idempotency guard;
/// this local mutex prevents two concurrent callers from interleaving
/// the vdev string — kept for parity with the pre-hoist behaviour.
static TEST_INJECT_EAL_INIT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// Build a minimal [`Engine`] suitable for `test-inject` callers
/// (A9 integration tests + the `engine_inject` cargo-fuzz target).
///
/// Returns `None` when `DPDK_NET_TEST_TAP` is not `"1"` so callers can
/// early-return and skip. Panics on environment failures that the
/// harness should surface loudly (EAL init fail, port setup fail,
/// hugepage exhaustion) rather than silently skip — matches the
/// behaviour of the other TAP-gated tests in this crate.
///
/// Follows the same EAL-args + vdev pattern as `tcp_basic_tap.rs`
/// (`net_tap0` + a unique iface name so concurrent inject callers
/// do not collide with the production-path TAP tests). The
/// `dpdktap9x` range is reserved for A9 test-inject use.
pub fn make_test_engine() -> Option<Engine> {
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
                // Unique iface so the inject callers can coexist with
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

    // 10.99.90.2 so the inject callers do not collide with any of the
    // existing /24s (the TAP suite carves 10.99.[0..30].0/24).
    let cfg = EngineConfig {
        port_id: 0,
        local_ip: 0x0a_63_5a_02,   // 10.99.90.2
        gateway_ip: 0x0a_63_5a_01, // 10.99.90.1
        // Static gateway MAC; the inject callers do not emit TX
        // traffic, so this value is inert.
        gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        garp_interval_sec: 0,
        tcp_msl_ms: 100,
        max_connections: 8,
        ..Default::default()
    };
    Some(Engine::new(cfg).expect("engine new (test-inject smoke)"))
}
