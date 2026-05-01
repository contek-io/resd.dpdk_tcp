//! A10 deferred-fix follow-up regression test: OOO reassembly path
//! returns mbufs to the mempool on stale-drop, cap-drop, and queue-Drop.
//!
//! Sister to `rx_mempool_no_leak.rs`, which exercises the in-order
//! `MbufHandle::Drop` path. This test exercises the analogous OOO path
//! through `ReorderQueue::insert` + `drain_contiguous_into` (stale
//! branch) + `Drop`.
//!
//! The cliff-class bug surfaced first in `MbufHandle::Drop` (commit
//! `f3139f6`); the same primitive class was found in
//! `ReorderQueue::drop_segment_mbuf_ref` by the post-fix audit. This
//! test fails on the buggy `rte_mbuf_refcnt_update(-1)` primitive and
//! passes on the corrected `rte_pktmbuf_free_seg` primitive.
//!
//! Gated on `DPDK_NET_TEST_TAP=1` + sudo (matches the existing TAP
//! test pattern; we need a real DPDK mempool to exercise the
//! pool-return semantics that `m->pool == NULL` falls back away from).
//!
//! Direct-style: this test does NOT drive network traffic. It allocates
//! mbufs from the engine's RX mempool, inserts them into a fresh
//! `ReorderQueue`, triggers each of the three drop paths in turn, and
//! asserts the pool's free-mbuf count returns to baseline. Network-
//! traffic-driven OOO testing belongs to `bench-stress` reorder
//! scenarios (which already use the fixed engine path post-`f3139f6`).

use std::process::Command;
use std::time::Duration;

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};

const TAP_IFACE: &str = "resdtap17";
const OUR_IP: u32 = 0x0a_63_11_02; // 10.99.17.2
const PEER_IP: u32 = 0x0a_63_11_01; // 10.99.17.1

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
    let _ = Command::new("ip")
        .args(["link", "set", iface, "up"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.17.1/24", "dev", iface])
        .status();
}

#[test]
fn ooo_drop_paths_return_mbufs_to_pool() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a10-rx-reassembly-no-leak",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap17",
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

    // Baseline: count free mbufs after engine bring-up. This is the
    // post-startup floor — RX ring + ARP probe + handshake have already
    // taken their share. Subsequent test-only mbuf alloc+drop cycles
    // must net to zero against this baseline.
    let avail_baseline =
        unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    eprintln!(
        "[a10-no-leak-ooo] baseline avail={} pool_size={}",
        avail_baseline,
        engine.rx_mempool_size(),
    );

    // Path 1: queue-Drop releases all stored segments.
    //
    // Allocate N mbufs, insert each into a fresh queue at non-overlapping
    // OOO seqs, drop the queue, assert pool drift == 0. The queue's
    // Drop calls drop_segment_mbuf_ref on each stored OooSegment, which
    // now uses the pool-aware shim_rte_pktmbuf_free_seg primitive.
    {
        const N: usize = 256;
        let avail_pre = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let mut allocated: Vec<std::ptr::NonNull<dpdk_net_sys::rte_mbuf>> =
            Vec::with_capacity(N);
        for _ in 0..N {
            let m = unsafe { dpdk_net_sys::shim_rte_pktmbuf_alloc(pool) };
            allocated.push(std::ptr::NonNull::new(m).expect("alloc"));
        }
        let mut q =
            dpdk_net_core::tcp_reassembly::ReorderQueue::new(1_000_000);
        // Insert at non-overlapping seqs so each becomes its own
        // OooSegment. ReorderQueue::insert assumes the caller has
        // already bumped refcount by +1 — we simulate by NOT bumping
        // first, but accepting that the queue's ref takes the alloc's
        // refcount=1. That matches the dispatch path semantics where
        // the engine bump is rolled back when mbuf_ref_retained=true,
        // leaving the queue holding the only refcount.
        let mut payload_buf = [0u8; 64];
        for (i, m) in allocated.iter().enumerate() {
            let seq = (i as u32) * 1024 + 1;
            // Build a 64-byte slice for the payload (queue copies the
            // length, not the bytes; offset is into the mbuf data).
            payload_buf[0] = i as u8;
            let _ = q.insert(seq, &payload_buf[..64], *m, 0);
        }
        // Drop the queue — should release every stored OooSegment.
        drop(q);
        let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let drift = (avail_pre as i64) - (avail_post as i64);
        eprintln!(
            "[a10-no-leak-ooo] queue-Drop path: pre={} post={} drift={}",
            avail_pre, avail_post, drift
        );
        assert!(
            drift.abs() <= 4,
            "queue-Drop path leaked {drift} mbufs (pre={avail_pre} post={avail_post})"
        );
    }

    // Path 2: stale-drop via drain_contiguous_into when rcv_nxt is past
    // every stored seg.
    //
    // Same pattern as Path 1, but instead of dropping the queue, we
    // drain it with rcv_nxt advanced past every segment. The drain's
    // stale branch calls drop_segment_mbuf_ref directly.
    {
        const N: usize = 128;
        let avail_pre = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let mut allocated: Vec<std::ptr::NonNull<dpdk_net_sys::rte_mbuf>> =
            Vec::with_capacity(N);
        for _ in 0..N {
            let m = unsafe { dpdk_net_sys::shim_rte_pktmbuf_alloc(pool) };
            allocated.push(std::ptr::NonNull::new(m).expect("alloc"));
        }
        let mut q =
            dpdk_net_core::tcp_reassembly::ReorderQueue::new(1_000_000);
        let mut payload_buf = [0u8; 64];
        let mut max_seq_end: u32 = 0;
        for (i, m) in allocated.iter().enumerate() {
            let seq = (i as u32) * 1024 + 1;
            payload_buf[0] = i as u8;
            let _ = q.insert(seq, &payload_buf[..64], *m, 0);
            max_seq_end = max_seq_end.max(seq.wrapping_add(64));
        }
        // Drain with rcv_nxt past every segment → every segment is
        // stale and goes through drop_segment_mbuf_ref.
        let mut out: std::collections::VecDeque<dpdk_net_core::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        let _ = q.drain_contiguous_into(max_seq_end + 1024, 0, &mut out);
        // Anything that ended up in `out` (shouldn't, since rcv_nxt is
        // way past all seqs and they're stale) has its own MbufHandle
        // which will Drop. Drop the queue (now empty) — no-op for
        // refcounts.
        drop(q);
        // Drop the out queue (should be empty, but defensive).
        drop(out);
        let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let drift = (avail_pre as i64) - (avail_post as i64);
        eprintln!(
            "[a10-no-leak-ooo] stale-drop path: pre={} post={} drift={}",
            avail_pre, avail_post, drift
        );
        assert!(
            drift.abs() <= 4,
            "stale-drop path leaked {drift} mbufs (pre={avail_pre} post={avail_post})"
        );
    }

    // Path 3: cap-drop via insert into a too-small queue.
    //
    // ReorderQueue::insert with cap exhausted returns
    // mbuf_ref_retained=false; the caller must release the +1 bump.
    // Here we mirror the full sequence the engine performs on cap-
    // exhaustion: alloc, insert (rejected by cap), then we manually
    // free via the pool-aware shim — the queue does NOT call
    // drop_segment_mbuf_ref here because the segment was never
    // stored.
    //
    // (This path doesn't directly exercise the bug we fixed, but it's
    // the third arm of the OOO drop matrix and worth covering for
    // completeness — a future cap-drop refactor that pulled the helper
    // back in would be caught.)
    {
        const N: usize = 32;
        let avail_pre = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let mut allocated: Vec<std::ptr::NonNull<dpdk_net_sys::rte_mbuf>> =
            Vec::with_capacity(N);
        for _ in 0..N {
            let m = unsafe { dpdk_net_sys::shim_rte_pktmbuf_alloc(pool) };
            allocated.push(std::ptr::NonNull::new(m).expect("alloc"));
        }
        // Cap=0 → every insert is fully cap-dropped.
        let mut q = dpdk_net_core::tcp_reassembly::ReorderQueue::new(0);
        let mut payload_buf = [0u8; 64];
        for (i, m) in allocated.iter().enumerate() {
            let seq = (i as u32) * 1024 + 1;
            payload_buf[0] = i as u8;
            let outcome = q.insert(seq, &payload_buf[..64], *m, 0);
            assert!(
                !outcome.mbuf_ref_retained,
                "cap=0 should reject every insert; outcome={outcome:?}"
            );
        }
        // Manually release the mbufs via the pool-aware shim — the
        // engine would do this through shim_rte_pktmbuf_free at
        // dispatch_one_real_mbuf:3056 plus the rollback at engine.rs:3518.
        for m in allocated {
            unsafe { dpdk_net_sys::shim_rte_pktmbuf_free_seg(m.as_ptr()) };
        }
        drop(q);
        let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
        let drift = (avail_pre as i64) - (avail_post as i64);
        eprintln!(
            "[a10-no-leak-ooo] cap-drop path: pre={} post={} drift={}",
            avail_pre, avail_post, drift
        );
        assert!(
            drift.abs() <= 4,
            "cap-drop path leaked {drift} mbufs (pre={avail_pre} post={avail_post})"
        );
    }

    let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    let drift = (avail_baseline as i64) - (avail_post as i64);
    eprintln!(
        "[a10-no-leak-ooo] OVERALL: post avail={} drift={} (baseline {})",
        avail_post, drift, avail_baseline
    );
    assert!(
        drift.abs() <= 4,
        "OOO drop paths leaked {drift} mbufs overall (baseline {avail_baseline}, post {avail_post})"
    );
}
