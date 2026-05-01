//! Direct unit-style regression test for `MbufHandle::try_clone` (the
//! partial-read split primitive in `mempool.rs`).
//!
//! `try_clone` bumps the underlying `rte_mbuf` refcount via
//! `shim_rte_mbuf_refcnt_update(p, +1)` and wraps the result in a fresh
//! `MbufHandle`. The receiver `MbufHandle::Drop` decrements via
//! `shim_rte_pktmbuf_free_seg`. Net: balanced — alloc gives refcount=1,
//! `try_clone` brings it to 2, and the two `Drop`s bring it back to 0,
//! returning the mbuf to its mempool.
//!
//! ## Why TAP-gated, not in-process unit?
//!
//! The bookkeeping under test only matters when refcount transitions
//! actually return mbufs to a pool — which requires a real DPDK mempool.
//! `mempool.rs::try_clone_tests` already provides a compile-check stub;
//! this file is the real-runtime asserter.
//!
//! ## Why this test exists despite the path being latent today
//!
//! The independent code review for A10 flagged that `try_clone` is
//! currently latent in steady state — the partial-read split path in
//! `engine.rs:4130` never fires today because `outcome.delivered` always
//! equals push-len. If a future delivery-path change activates the
//! split (e.g. a backpressure-aware reader that consumes a prefix), a
//! refcount imbalance in `try_clone` would be invisible until pool
//! exhaustion. This test exercises the primitive directly so that any
//! regression that breaks the bump+drop pairing surfaces immediately.
//!
//! ## Verification of regression-detecting power
//!
//! Removing the `shim_rte_mbuf_refcnt_update(self.ptr.as_ptr(), 1);` line
//! in `MbufHandle::try_clone` (so clone returns a second handle without
//! bumping refcount) MUST cause this test to fail — either via
//! `mbuf_refcnt_drop_unexpected` firing (saturating-underflow when the
//! second drop sees pre==0) or via a pool-drift signal. We document
//! the observed signal in the commit so future readers know which arm
//! catches the regression.
//!
//! Gated on `DPDK_NET_TEST_TAP=1` + sudo (matches the existing TAP-test
//! pattern; we need a real DPDK mempool to exercise the pool-return
//! semantics).

use std::process::Command;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::mempool::MbufHandle;

const TAP_IFACE: &str = "resdtap26";
const OUR_IP: u32 = 0x0a_63_1a_02; // 10.99.26.2
const PEER_IP: u32 = 0x0a_63_1a_01; // 10.99.26.1

fn skip_if_not_tap() -> bool {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run (requires sudo for TAP vdev)");
        return true;
    }
    false
}

fn read_kernel_tap_mac(iface: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"));
    let mut out = [0u8; 6];
    for (i, part) in s.trim().split(':').enumerate() {
        out[i] = u8::from_str_radix(part, 16).expect("hex mac");
    }
    out
}

fn bring_up_tap(iface: &str) {
    let _ = Command::new("ip").args(["link", "set", iface, "up"]).status();
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.26.1/24", "dev", iface])
        .status();
}

#[test]
fn try_clone_drop_balance_under_sustained_use() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a10-mbuf-try-clone-balance",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap26",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    std::thread::sleep(Duration::from_millis(500));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);
    let cfg = EngineConfig {
        port_id: 0,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: kernel_mac,
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("Engine::new");
    let pool = engine.rx_mempool_ptr();

    // Baseline: count free mbufs after engine bring-up. RX ring + ARP
    // probe + handshake have already taken their share. Subsequent
    // test-only alloc + clone + drop cycles must net to zero against
    // this baseline.
    let avail_baseline = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    eprintln!(
        "[try_clone-balance] baseline avail={} pool_size={}",
        avail_baseline,
        engine.rx_mempool_size(),
    );

    // Path 1: simple bump-and-drop balance.
    //
    // Allocate N mbufs, build N MbufHandle pairs (`h0` from `from_raw` of
    // the alloc, `h1` from `h0.try_clone()`). Drop all 2N handles, assert
    // pool drift = 0. Each pair's two `Drop`s must bring refcount 2 → 1
    // → 0, returning the mbuf to the pool on the final dec.
    {
        const N: usize = 1000;
        let avail_pre = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let mut handles: Vec<(MbufHandle, MbufHandle)> = Vec::with_capacity(N);
        for _ in 0..N {
            let m = unsafe { dpdk_net_sys::shim_rte_pktmbuf_alloc(pool) };
            let nn = NonNull::new(m).expect("alloc");
            // alloc gives refcount=1 — the handle takes ownership of that 1.
            let h0 = unsafe { MbufHandle::from_raw(nn) };
            // try_clone bumps to 2, returns a second handle owning the
            // new ref.
            let h1 = h0.try_clone();
            handles.push((h0, h1));
        }
        // Drop every pair — for each pair the two MbufHandle::Drop
        // invocations bring refcount 2 → 1 → 0; the final dec returns
        // the mbuf to the pool via shim_rte_pktmbuf_free_seg.
        drop(handles);
        let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let drift = (avail_pre as i64) - (avail_post as i64);
        eprintln!(
            "[try_clone-balance] Path 1 (simple): pre={} post={} drift={}",
            avail_pre, avail_post, drift
        );
        assert!(
            drift.abs() <= 4,
            "Path 1 (simple bump-and-drop) leaked {drift} mbufs (pre={avail_pre} post={avail_post})"
        );
    }

    // Path 2: chained clones (depth 3). One alloc, then clone the clone.
    //
    // Per iter: alloc → h0 (refcount=1), h0.try_clone() → h1 (refcount=2),
    // h1.try_clone() → h2 (refcount=3). Drop in reverse order: h2 (3→2),
    // h1 (2→1), h0 (1→0; returns to pool).
    //
    // This exercises `try_clone` called on a handle whose underlying
    // refcount is already > 1 — the bump-and-from_raw pairing must still
    // balance regardless of pre-existing refcount.
    {
        const N: usize = 500;
        let avail_pre = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        for _ in 0..N {
            let m = unsafe { dpdk_net_sys::shim_rte_pktmbuf_alloc(pool) };
            let nn = NonNull::new(m).expect("alloc");
            let h0 = unsafe { MbufHandle::from_raw(nn) };
            let h1 = h0.try_clone();
            let h2 = h1.try_clone();
            // Drop in reverse construction order — the last refcount
            // dec returns the mbuf to the pool.
            drop(h2);
            drop(h1);
            drop(h0);
        }
        let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let drift = (avail_pre as i64) - (avail_post as i64);
        eprintln!(
            "[try_clone-balance] Path 2 (chained depth=3): pre={} post={} drift={}",
            avail_pre, avail_post, drift
        );
        assert!(
            drift.abs() <= 4,
            "Path 2 (chained clones) leaked {drift} mbufs (pre={avail_pre} post={avail_post})"
        );
    }

    // Final: overall drift against the post-engine-bring-up baseline.
    let avail_final = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    let overall_drift = (avail_baseline as i64) - (avail_final as i64);
    eprintln!(
        "[try_clone-balance] OVERALL: post avail={} drift={} (baseline {})",
        avail_final, overall_drift, avail_baseline
    );
    assert!(
        overall_drift.abs() <= 4,
        "try_clone exercise leaked {overall_drift} mbufs overall (baseline {avail_baseline}, post {avail_final})"
    );

    // Diagnostic counter: any saturating-underflow or above-threshold
    // post-dec refcount during the exercise would have bumped this. A
    // bug that drops the +1 bump in try_clone would land here as the
    // second handle's Drop sees pre==0 → triggers the diagnostic.
    let unexpected = engine
        .counters()
        .tcp
        .mbuf_refcnt_drop_unexpected
        .load(Ordering::Relaxed);
    eprintln!("[try_clone-balance] mbuf_refcnt_drop_unexpected={unexpected}");
    assert_eq!(
        unexpected, 0,
        "mbuf_refcnt_drop_unexpected fired during try_clone exercise (count={unexpected})"
    );
}
