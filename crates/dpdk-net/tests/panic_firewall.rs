#![cfg(feature = "test-panic-entry")]

// Resolve the test-only FFI entry through a Rust accessor (anchors the
// symbol against rlib dead-code stripping). The returned function
// pointer carries the C calling convention, so invoking it exercises
// the same code path a C caller would hit.
use dpdk_net::test_only::panic_for_test_fn;

#[test]
fn panic_aborts_process_via_sigabrt() {
    if std::env::var_os("DPDK_NET_PANIC_FIREWALL_CHILD").is_some() {
        // Child process: invoke FFI panic; aborts under panic = abort.
        let panic_entry = panic_for_test_fn();
        panic_entry();
    }

    let exe = std::env::current_exe().expect("current_exe");
    let out = std::process::Command::new(exe)
        .env("DPDK_NET_PANIC_FIREWALL_CHILD", "1")
        .args(["--exact", "panic_aborts_process_via_sigabrt", "--test-threads=1"])
        .output()
        .expect("spawn child");

    use std::os::unix::process::ExitStatusExt;
    let sig = out.status.signal().unwrap_or(0);
    assert_eq!(
        sig, libc::SIGABRT,
        "expected SIGABRT, got signal={}, status={:?}, stderr={}",
        sig, out.status, String::from_utf8_lossy(&out.stderr)
    );
}
