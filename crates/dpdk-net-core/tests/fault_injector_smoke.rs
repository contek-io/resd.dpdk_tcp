//! A9 Task 6 smoke tests: `FaultInjector::process` is wired into the
//! engine's `dispatch_one_rx_mbuf` so injected frames get drop / dup /
//! reorder / corrupt mutations applied per the configured rates.
//!
//! Three scenarios:
//!   - `drop=1.0` → every injected frame is dropped; `eth.rx_bytes` never
//!     advances and `fault_injector.drops` advances by the inject count.
//!     This is the load-bearing assertion that the FaultInjector sits
//!     BEFORE the rest of the decode pipeline (rx_bytes is bumped inside
//!     `dispatch_one_rx_mbuf` AFTER the FaultInjector middleware, so a
//!     dropped mbuf must not reach that counter).
//!   - `drop=0.0` → every injected frame passes through; `eth.rx_bytes`
//!     advances. Asserts the pass-through fast path still functions when
//!     the fault-injector is constructed but idle.
//!   - No env var → no FaultInjector is constructed (`Option::None`), so
//!     `process()` is never called and `fault_injector.drops` stays at 0
//!     across inject calls. Regression guard against accidentally wiring
//!     the FaultInjector unconditionally.
//!
//! All three scenarios are TAP-gated via `common::make_test_engine`; when
//! the gate is unmet (no `DPDK_NET_TEST_TAP=1` + sudo + hugepages) the
//! test returns cleanly, matching every other TAP-gated test in this crate.

#![cfg(all(feature = "test-inject", feature = "fault-injector"))]

mod common;
use common::{build_icmp_echo_frame, make_test_engine};

#[test]
fn drop_rate_one_means_all_frames_dropped() {
    let _env_guard = common::FAULT_INJECTOR_ENV_LOCK.lock().unwrap();
    std::env::set_var("DPDK_NET_FAULT_INJECTOR", "drop=1.0,seed=123");
    let Some(engine) = make_test_engine() else {
        std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
        eprintln!("skipped (DPDK_NET_TEST_TAP not set)");
        return;
    };

    let frame = build_icmp_echo_frame(&engine);

    let rx_bytes_before = engine
        .counters()
        .eth
        .rx_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    let drops_before = engine
        .counters()
        .fault_injector
        .drops
        .load(std::sync::atomic::Ordering::Relaxed);

    for _ in 0..100 {
        engine.inject_rx_frame(&frame).unwrap();
    }

    let rx_bytes_after = engine
        .counters()
        .eth
        .rx_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    let drops_after = engine
        .counters()
        .fault_injector
        .drops
        .load(std::sync::atomic::Ordering::Relaxed);

    assert_eq!(
        rx_bytes_after, rx_bytes_before,
        "rx_bytes advanced despite drop=1.0"
    );
    assert_eq!(
        drops_after - drops_before,
        100,
        "drops counter did not advance by 100"
    );

    std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
}

#[test]
fn drop_rate_zero_passes_all_frames() {
    let _env_guard = common::FAULT_INJECTOR_ENV_LOCK.lock().unwrap();
    std::env::set_var("DPDK_NET_FAULT_INJECTOR", "drop=0.0,seed=7");
    let Some(engine) = make_test_engine() else {
        std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
        return;
    };
    let frame = build_icmp_echo_frame(&engine);

    let rx_bytes_before = engine
        .counters()
        .eth
        .rx_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    for _ in 0..10 {
        engine.inject_rx_frame(&frame).unwrap();
    }
    let rx_bytes_after = engine
        .counters()
        .eth
        .rx_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        rx_bytes_after > rx_bytes_before,
        "rx_bytes did not advance (before={rx_bytes_before}, after={rx_bytes_after})"
    );

    std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
}

#[test]
fn no_env_var_means_no_fault_injection_active() {
    let _env_guard = common::FAULT_INJECTOR_ENV_LOCK.lock().unwrap();
    // Without DPDK_NET_FAULT_INJECTOR set, FaultInjector is None on Engine
    // and process() is never called. Frames pass through cleanly.
    std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
    let Some(engine) = make_test_engine() else {
        return;
    };
    let frame = build_icmp_echo_frame(&engine);
    engine.inject_rx_frame(&frame).unwrap();
    assert_eq!(
        engine
            .counters()
            .fault_injector
            .drops
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}
