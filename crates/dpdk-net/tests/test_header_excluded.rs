//! A7 Task 8: prove no dpdk_net_test_* symbol leaks into dpdk_net.h
//! across any feature combination.

#[test]
fn default_header_has_no_test_symbols() {
    let header = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../include/dpdk_net.h"),
    ).expect("read dpdk_net.h");
    for bad in [
        "dpdk_net_test_",
        "dpdk_net_listen_handle_t",
        "dpdk_net_test_frame_t",
    ] {
        assert!(!header.contains(bad),
            "dpdk_net.h unexpectedly contains `{bad}`");
    }
}

#[cfg(feature = "test-server")]
#[test]
fn test_header_present_when_feature_on() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../include/dpdk_net_test.h");
    let h = std::fs::read_to_string(path).expect("read dpdk_net_test.h");
    for expected in [
        "dpdk_net_test_set_time_ns",
        "dpdk_net_test_inject_frame",
        "dpdk_net_test_drain_tx_frames",
        "dpdk_net_test_listen",
        "dpdk_net_test_accept_next",
        "dpdk_net_test_connect",
        "dpdk_net_test_send",
        "dpdk_net_test_recv",
        "dpdk_net_test_close",
        "dpdk_net_test_conn_peer",
    ] {
        assert!(h.contains(expected),
            "dpdk_net_test.h missing `{expected}`");
    }
}
