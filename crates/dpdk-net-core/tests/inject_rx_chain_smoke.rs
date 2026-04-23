//! A9 Task 3 smoke test: `Engine::inject_rx_chain` builds a multi-seg
//! mbuf chain (LRO-shape) and dispatches the head through the production
//! RX path.
//!
//! `inject_empty_chain_returns_empty_chain_err` runs unconditionally
//! against `make_test_engine`'s TAP gate — when the gate is unmet we
//! skip cleanly. `inject_multi_seg_chain_advances_rx_bytes` requires
//! `DPDK_NET_TEST_TAP=1` + sudo + hugepages to actually drive the inject
//! through DPDK.
//!
//! Counter-choice note: the plan-doc named `eth.rx_pkts`, but that
//! counter is bumped exclusively by `Engine::poll_once` (per-burst,
//! batched) — the inject path bypasses `poll_once` and dispatches one
//! mbuf at a time via `dispatch_one_rx_mbuf`. The first counter
//! `dispatch_one_rx_mbuf` increments is `eth.rx_bytes` (by the head
//! segment's data-len, before any L2 / L3 decode), which gives us a
//! deterministic "the chain reached dispatch" signal. We assert on
//! that instead.
//!
//! Frame-validity note: the SYN frame's IPv4 + TCP checksums are zero,
//! so `handle_ipv4` will drop the packet at the IP-csum check (bumping
//! `ip.rx_csum_bad`). That's intentional: the smoke test verifies
//! chain-walk reaches dispatch without panicking, NOT that TCP processes
//! the SYN — the synthetic peer would also need to consume a SYN-ACK.

#![cfg(feature = "test-inject")]

mod common;
use common::{build_tcp_syn_head, make_test_engine};

#[test]
fn inject_multi_seg_chain_advances_rx_bytes() {
    let Some(engine) = make_test_engine() else {
        return;
    };

    // 3-segment chain: head carries L2+L3+TCP-SYN headers + 100 B payload,
    // tail segments carry 100 B + 50 B payload continuations. Total payload
    // bytes across all segments = 250.
    let head = build_tcp_syn_head(&engine, &[0x41u8; 100]);
    let mid: Vec<u8> = vec![0x42u8; 100];
    let tail: Vec<u8> = vec![0x43u8; 50];

    let head_len = head.len() as u64;
    let bytes_before = engine
        .counters()
        .eth
        .rx_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    engine
        .inject_rx_chain(&[&head, &mid, &tail])
        .expect("inject_rx_chain should succeed");
    let bytes_after = engine
        .counters()
        .eth
        .rx_bytes
        .load(std::sync::atomic::Ordering::Relaxed);

    // dispatch_one_rx_mbuf bumps eth.rx_bytes by the head segment's
    // data_len (it reads the slice off the head, not the chain). So
    // the delta should be exactly the head segment's length.
    assert_eq!(
        bytes_after - bytes_before,
        head_len,
        "eth.rx_bytes did not advance by head-segment length after chain inject \
         (before={bytes_before}, after={bytes_after}, head_len={head_len})"
    );
}

#[test]
fn inject_empty_chain_returns_empty_chain_err() {
    let Some(engine) = make_test_engine() else {
        return;
    };
    let err = engine
        .inject_rx_chain(&[])
        .expect_err("empty chain must error");
    assert_eq!(err, dpdk_net_core::engine::InjectErr::EmptyChain);
}
