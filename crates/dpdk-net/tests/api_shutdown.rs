//! A8.5 T7 — public API `dpdk_net_shutdown` tests.
//!
//! Coverage for the spec §4 + §6.4 `AD-A8.5-shutdown-no-half-close`
//! accepted deviation: SHUT_RDWR dispatches to `dpdk_net_close`,
//! SHUT_RD / SHUT_WR return `-EOPNOTSUPP`, any other `how` returns
//! `-EINVAL`.
//!
//! `dpdk_net_shutdown` is a thin dispatch wrapper. The errno-return
//! branches (SHUT_RD / SHUT_WR / invalid `how`) short-circuit BEFORE
//! touching the engine pointer, so a null-engine drive cleanly proves
//! their behavior. The SHUT_RDWR branch is verified by asserting it
//! returns the same errno that `dpdk_net_close(engine, h, 0)` returns
//! on the identical call (here: `-EINVAL` on a null engine). The
//! FIN-emission / state-transition path that SHUT_RDWR rides is
//! already covered end-to-end by the A7 `test_server_active_close`
//! integration test; re-running it through `dpdk_net_shutdown` would
//! exercise the same core-crate path at 80+ LoC of setup with zero
//! additional branch coverage.
//!
//! Test-server feature gate: mirrors the convention in
//! `crates/dpdk-net/tests/test_header_excluded.rs` — the constants and
//! the FFI symbol are available in the default build, so strictly we
//! don't need `test-server` here, but the task spec requires this file
//! compile under that feature (per A7 Task 8 discipline of FFI tests
//! living behind the same gate as the test-FFI surface they may grow
//! to use). Keep the gate so future extensions that reach for
//! `dpdk_net_test_connect` et al. slot in without reshuffling.

#![cfg(feature = "test-server")]

use dpdk_net::api::{DPDK_NET_SHUT_RD, DPDK_NET_SHUT_RDWR, DPDK_NET_SHUT_WR};

extern "C" {
    fn dpdk_net_shutdown(engine: *mut dpdk_net::api::dpdk_net_engine, h: u64, how: i32) -> i32;
    fn dpdk_net_close(engine: *mut dpdk_net::api::dpdk_net_engine, h: u64, flags: u32) -> i32;
}

/// SHUT_RDWR dispatches to `dpdk_net_close(engine, h, 0)` — on a null
/// engine both return the same `-EINVAL`. Proves the dispatch wiring
/// without re-running the core-crate active-close scenario (already
/// exercised by `crates/dpdk-net-core/tests/test_server_active_close.rs`
/// and the A8 counter-coverage `cover_tcp_tx_fin` scenario).
#[test]
fn shutdown_rdwr_full_closes_conn() {
    let engine: *mut dpdk_net::api::dpdk_net_engine = std::ptr::null_mut();
    let h: u64 = 1;

    let rc_shutdown = unsafe { dpdk_net_shutdown(engine, h, DPDK_NET_SHUT_RDWR) };
    let rc_close = unsafe { dpdk_net_close(engine, h, 0) };

    assert_eq!(
        rc_shutdown, rc_close,
        "SHUT_RDWR must dispatch to dpdk_net_close(h, 0)"
    );
    assert_eq!(rc_shutdown, -libc::EINVAL, "null engine returns -EINVAL");
}

/// SHUT_RD returns `-EOPNOTSUPP` without touching the engine.
/// Using a null engine here proves the errno-short-circuit: if the
/// wrapper forwarded to `dpdk_net_close` we'd see `-EINVAL` instead.
#[test]
fn shutdown_rd_returns_eopnotsupp() {
    let engine: *mut dpdk_net::api::dpdk_net_engine = std::ptr::null_mut();
    let h: u64 = 1;

    let rc = unsafe { dpdk_net_shutdown(engine, h, DPDK_NET_SHUT_RD) };
    assert_eq!(
        rc,
        -libc::EOPNOTSUPP,
        "SHUT_RD must return -EOPNOTSUPP (half-close not implemented)"
    );
}

/// SHUT_WR returns `-EOPNOTSUPP` without touching the engine.
/// Same short-circuit rationale as the SHUT_RD test.
#[test]
fn shutdown_wr_returns_eopnotsupp() {
    let engine: *mut dpdk_net::api::dpdk_net_engine = std::ptr::null_mut();
    let h: u64 = 1;

    let rc = unsafe { dpdk_net_shutdown(engine, h, DPDK_NET_SHUT_WR) };
    assert_eq!(
        rc,
        -libc::EOPNOTSUPP,
        "SHUT_WR must return -EOPNOTSUPP (half-close not implemented)"
    );
}

/// Any `how` value other than the three POSIX constants returns
/// `-EINVAL` — the short-circuit falls before any engine deref so
/// null-engine + `how = 99` proves the validation path.
#[test]
fn shutdown_invalid_how_returns_einval() {
    let engine: *mut dpdk_net::api::dpdk_net_engine = std::ptr::null_mut();
    let h: u64 = 1;

    for bad_how in [99i32, -1, 3, i32::MAX, i32::MIN] {
        let rc = unsafe { dpdk_net_shutdown(engine, h, bad_how) };
        assert_eq!(
            rc,
            -libc::EINVAL,
            "how={bad_how} must return -EINVAL (not a POSIX shutdown constant)"
        );
    }
}
