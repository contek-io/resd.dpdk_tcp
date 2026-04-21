//! Compile-only smoke — verifies the runner binary builds.
//!
//! Presence of the `CARGO_BIN_EXE_bench-ab-runner` env var at test-
//! compile time implies Cargo successfully built the binary target; the
//! const deref below promotes that presence check to a link-time
//! dependency. No DPDK is touched — the binary itself requires a bound
//! ENA VF + peer host, so real runs happen on the bench host.
//!
//! Follow-on tests could spawn the binary with `--help` and assert
//! exit 0 plus the expected args surface; this file keeps the bar at
//! "compiles + linkable" per the plan's Step 2.5.

#[test]
fn binary_builds() {
    const BIN_PATH: &str = env!("CARGO_BIN_EXE_bench-ab-runner");
    assert!(
        !BIN_PATH.is_empty(),
        "CARGO_BIN_EXE_bench-ab-runner must resolve to a non-empty path"
    );
}
