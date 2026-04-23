//! Compile-only sanity: with `--features test-server`, the feature-gated
//! hooks compile, and without it the default build is unchanged.

#[cfg(feature = "test-server")]
#[test]
fn test_server_feature_is_on() {
    // Feature-gate path — if this compiles under --features test-server,
    // later tasks' #[cfg(feature = "test-server")] hunks will compile too.
    let _ = dpdk_net_core::tcp_state::TcpState::Listen;
}

#[cfg(not(feature = "test-server"))]
#[test]
fn default_build_compiles() {
    let _ = dpdk_net_core::tcp_state::TcpState::Closed;
}
