//! Test-only FFI entry points, gated behind the `test-panic-entry`
//! feature. NOT included in the public dpdk_net.h (cbindgen excludes).

/// Force a Rust panic reached through the C ABI. Used by
/// tests/panic_firewall.rs to verify panic = "abort" is correctly
/// configured (a misconfiguration would let the panic unwind into
/// the C caller — Undefined Behavior).
///
/// This symbol has the C calling convention but is NOT exposed in
/// dpdk_net.h.
///
/// # Safety
/// Panics. The process aborts via SIGABRT under panic = abort.
#[no_mangle]
pub extern "C" fn dpdk_net_panic_for_test() -> ! {
    panic!("dpdk_net panic firewall test");
}

/// Returns the address of the test-only panic entry as an `extern "C"`
/// function pointer. Integration tests call this and invoke the
/// pointer to exercise the panic firewall through the C ABI calling
/// convention.
///
/// **Why this exists:** integration tests link against `dpdk-net` as
/// an `rlib`, and the linker garbage-collects `#[no_mangle] extern`
/// symbols that aren't reachable through Rust call graphs. Returning
/// a function pointer creates a Rust-visible reference that anchors
/// the symbol and lets the test invoke the entry through indirect
/// `extern "C"` dispatch — exactly the same calling convention a
/// real C caller would use.
pub fn panic_for_test_fn() -> extern "C" fn() -> ! {
    dpdk_net_panic_for_test
}
