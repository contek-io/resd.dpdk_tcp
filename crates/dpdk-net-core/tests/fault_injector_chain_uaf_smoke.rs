//! Two end-of-scope mbuf-lifecycle invariants for the FaultInjector
//! middleware:
//!
//! * **dup-on-chain refcount balance** — a duplicated multi-segment
//!   mbuf chain must balance per-segment, not just on the head. The
//!   downstream double-free via `rte_pktmbuf_free` walks the chain via
//!   `m->next` and decrements each segment independently; head-only
//!   refcount bumps leave the tail segments freed after the first walk
//!   and the second walk reading recycled mempool memory.
//!   `dup_chain_drains_cleanly_through_engine_drop` runs `dup=1.0`
//!   against a 3-segment `inject_rx_chain` and drops the engine.
//!
//! * **engine-drop ordering** — when `Engine` falls, the FaultInjector's
//!   reorder-ring mbufs must be freed back to their mempools while the
//!   pools are still alive. `reorder_ring_full_on_engine_drop` runs
//!   `reorder=1.0` past the depth-16 ring ceiling so the ring is full
//!   at drop time.
//!
//! Both invariants are observable as use-after-free under
//! ASAN/valgrind. Plain `cargo test` may absorb the violation silently
//! through mempool free-list reuse — these tests still exercise the
//! code paths and assert the surrounding counter contract holds, but
//! catching a regression deterministically requires a sanitizer pass.
//!
//! Both tests TAP-gate via `common::make_test_engine` and skip cleanly
//! when `DPDK_NET_TEST_TAP=1` is not set.

#![cfg(all(feature = "test-inject", feature = "fault-injector"))]

mod common;
use common::{build_tcp_syn_head, make_test_engine};

#[test]
fn dup_chain_drains_cleanly_through_engine_drop() {
    let _env_guard = common::FAULT_INJECTOR_ENV_LOCK.lock().unwrap();
    // dup=1.0 → every injected chain duplicates exactly once. seed pinned
    // for reproducibility. corrupt/drop/reorder=0 so the dup-walk is the
    // only mutation under test.
    std::env::set_var("DPDK_NET_FAULT_INJECTOR", "dup=1.0,seed=1337");
    let Some(engine) = make_test_engine() else {
        std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
        return;
    };

    let dups_before = engine
        .counters()
        .fault_injector
        .dups
        .load(std::sync::atomic::Ordering::Relaxed);

    // 3-segment chain (head + 2 tails). Chain semantics + the dup branch's
    // chain-walk-refcount-bump are the load-bearing test surface.
    let head = build_tcp_syn_head(&engine, &[0x55u8; 64]);
    let mid: Vec<u8> = vec![0x66u8; 64];
    let tail: Vec<u8> = vec![0x77u8; 32];

    for _ in 0..16 {
        engine
            .inject_rx_chain(&[&head, &mid, &tail])
            .expect("inject_rx_chain should succeed");
    }

    let dups_after = engine
        .counters()
        .fault_injector
        .dups
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        dups_after - dups_before,
        16,
        "dups counter did not advance by 16 (before={dups_before}, after={dups_after})"
    );

    // End-of-scope drop is the load-bearing invariant: every chain
    // duplicated above must complete two full chain free walks without
    // touching recycled tail-segment memory. A regression surfaces as
    // a UAF under ASAN/valgrind.
    drop(engine);
    std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
}

#[test]
fn reorder_ring_full_on_engine_drop() {
    let _env_guard = common::FAULT_INJECTOR_ENV_LOCK.lock().unwrap();
    // reorder=1.0 → every injected frame is held in the ring. Ring depth
    // is 16; 32 injects guarantees full occupancy at drop time and several
    // FIFO evictions along the way.
    std::env::set_var("DPDK_NET_FAULT_INJECTOR", "reorder=1.0,seed=2024");
    let Some(engine) = make_test_engine() else {
        std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
        return;
    };

    let reorders_before = engine
        .counters()
        .fault_injector
        .reorders
        .load(std::sync::atomic::Ordering::Relaxed);

    let head = build_tcp_syn_head(&engine, &[0x99u8; 32]);
    for _ in 0..32 {
        engine
            .inject_rx_chain(&[&head])
            .expect("inject_rx_chain should succeed");
    }

    let reorders_after = engine
        .counters()
        .fault_injector
        .reorders
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        reorders_after - reorders_before,
        32,
        "reorders counter did not advance by 32 (before={reorders_before}, after={reorders_after})"
    );

    // End-of-scope drop is the load-bearing invariant: 16 live chain
    // heads still sit in the ring at this point, allocated from
    // `test_inject_mempool`. They must be freed back to that pool before
    // the pool itself is destroyed. A regression surfaces as a UAF
    // (read of `m->pool` from a torn-down allocation) under
    // ASAN/valgrind.
    drop(engine);
    std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
}
