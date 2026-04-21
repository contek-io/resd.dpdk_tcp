//! A6.6-7 Task 13 — synthetic chained-mbuf multi-segment ingest.
//!
//! ENA does NOT advertise `RX_OFFLOAD_SCATTER` today, so the
//! `rte_mbuf.next` chain walk in `tcp_input::handle_established` is
//! never exercised by a real RX burst. Instead of waiting for a PMD
//! that enables scatter, this test:
//!
//! 1. Initializes EAL + creates a small mempool (no NIC, no TAP).
//! 2. Allocates two mbufs from the mempool.
//! 3. Appends known payload bytes to each mbuf's data region.
//! 4. Chains them via `shim_rte_pktmbuf_chain` (head ← head → tail).
//! 5. Direct-constructs a `TcpConn` in ESTABLISHED state.
//! 6. Calls `tcp_input::dispatch` with a `MbufInsertCtx` pointing at
//!    the chain head + a `ParsedSegment` whose payload slice covers
//!    the head link's bytes.
//! 7. Asserts: `recv.bytes.len() == 2` (head + tail are separate
//!    InOrderSegments), `Σ seg.len == total_payload_len`, segments
//!    are in correct order, + the `outcome.delivered` matches.
//!
//! This faithfully exercises the multi-seg branch of `handle_established`
//! without needing a TAP peer. The test is still gated on
//! `DPDK_NET_TEST_TAP=1` because EAL init requires hugepages-or-
//! `--in-memory` + `--no-pci` + `--no-huge`, all root-friendly flags
//! the existing TAP harnesses already exercise.

use dpdk_net_core::engine::{
    eal_init, DEFAULT_RTT_HISTOGRAM_EDGES_US,
};
use dpdk_net_core::flow_table::FourTuple;
use dpdk_net_core::mempool::Mempool;
use dpdk_net_core::tcp_conn::TcpConn;
use dpdk_net_core::tcp_input::{dispatch, MbufInsertCtx, ParsedSegment};
use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH};
use dpdk_net_core::tcp_state::TcpState;

const TEST_EDGES: [u32; 15] = DEFAULT_RTT_HISTOGRAM_EDGES_US;
const TEST_SEND_BUF_BYTES: u32 = 256 * 1024;

fn skip_if_not_tap() -> bool {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping; set DPDK_NET_TEST_TAP=1 to run (EAL init + DPDK mempool \
             allocation require hugepages / --in-memory + sudo)"
        );
        return true;
    }
    false
}

fn est_conn(iss: u32, irs: u32, peer_wnd: u16) -> TcpConn {
    let tuple = FourTuple {
        local_ip: 0x0a_00_00_02,
        local_port: 40000,
        peer_ip: 0x0a_00_00_01,
        peer_port: 5000,
    };
    let mut c = TcpConn::new_client(
        tuple,
        iss,
        1460,
        64 * 1024,
        TEST_SEND_BUF_BYTES,
        5_000,
        5_000,
        1_000_000,
    );
    c.state = TcpState::Established;
    c.snd_una = iss.wrapping_add(1);
    c.snd_nxt = iss.wrapping_add(1);
    c.irs = irs;
    c.rcv_nxt = irs.wrapping_add(1);
    c.snd_wnd = peer_wnd as u32;
    c
}

#[test]
fn rx_zero_copy_multi_seg_manual_chain() {
    if skip_if_not_tap() {
        return;
    }

    // Minimal EAL init — no NIC, no TAP required. `--in-memory`
    // bypasses hugepages metadata, `--no-pci` disables device probe,
    // `-l 0` allocates a single lcore. Matches the flags that other
    // TAP tests in this crate use, so running alongside them reuses
    // the one-shot `eal_init` guard.
    let args = [
        "dpdk-net-a6-6-7-t13-multi-seg",
        "--in-memory",
        "--no-pci",
        "-l",
        "0",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    // Small 2KB-data-room pool with 32 mbufs is ample for this test.
    // SOCKET_ID_ANY = -1 lets DPDK pick a NUMA socket.
    let pool = Mempool::new_pktmbuf(
        "t13-multi-seg-pool",
        32,
        0,
        0,
        2048,
        -1,
    )
    .expect("mempool create");

    // Alloc the two chain links.
    let head_ptr =
        unsafe { dpdk_net_sys::shim_rte_pktmbuf_alloc(pool.as_ptr()) };
    assert!(!head_ptr.is_null(), "alloc head mbuf");
    let tail_ptr =
        unsafe { dpdk_net_sys::shim_rte_pktmbuf_alloc(pool.as_ptr()) };
    assert!(!tail_ptr.is_null(), "alloc tail mbuf");

    // Payload layout: head holds 200 bytes `0xAA * 100 + 0xBB * 100`,
    // tail holds 100 bytes `0xCC * 100`. Total 300 distinguishable
    // bytes that assert chain-walk ordering + length aggregation.
    let head_bytes: Vec<u8> = std::iter::repeat(0xAAu8)
        .take(100)
        .chain(std::iter::repeat(0xBBu8).take(100))
        .collect();
    let tail_bytes: Vec<u8> = std::iter::repeat(0xCCu8).take(100).collect();

    let head_append = unsafe {
        dpdk_net_sys::shim_rte_pktmbuf_append(head_ptr, head_bytes.len() as u16)
    };
    assert!(!head_append.is_null(), "head append");
    let tail_append = unsafe {
        dpdk_net_sys::shim_rte_pktmbuf_append(tail_ptr, tail_bytes.len() as u16)
    };
    assert!(!tail_append.is_null(), "tail append");

    unsafe {
        std::ptr::copy_nonoverlapping(
            head_bytes.as_ptr(),
            head_append as *mut u8,
            head_bytes.len(),
        );
        std::ptr::copy_nonoverlapping(
            tail_bytes.as_ptr(),
            tail_append as *mut u8,
            tail_bytes.len(),
        );
    }

    // Attach tail to head. After this call head.nb_segs==2,
    // head.pkt_len == head.data_len + tail.data_len.
    let chain_rc =
        unsafe { dpdk_net_sys::shim_rte_pktmbuf_chain(head_ptr, tail_ptr) };
    assert_eq!(chain_rc, 0, "chain failed: {}", chain_rc);
    assert_eq!(
        unsafe { dpdk_net_sys::shim_rte_pktmbuf_nb_segs(head_ptr) },
        2,
        "head nb_segs after chain"
    );

    // Prepare the conn + segment. `payload_offset = 0` since we wrote
    // raw bytes (no TCP/IP/ETH header prefix). The `ParsedSegment.payload`
    // slice must cover the HEAD link's data (tcp_input's head_take code
    // sizes from `seg.payload.len()`, then the chain walk contributes
    // the tail's `data_len` independently).
    let head_data_ptr = unsafe { dpdk_net_sys::shim_rte_pktmbuf_data(head_ptr) };
    let head_data_len =
        unsafe { dpdk_net_sys::shim_rte_pktmbuf_data_len(head_ptr) } as usize;
    assert_eq!(head_data_len, head_bytes.len());
    let head_slice =
        unsafe { std::slice::from_raw_parts(head_data_ptr as *const u8, head_data_len) };
    assert_eq!(head_slice, head_bytes.as_slice());

    let mut c = est_conn(1000, 5000, u16::MAX);
    let seg = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: 1001,
        flags: TCP_ACK | TCP_PSH,
        window: 65535,
        header_len: 20,
        payload: head_slice,
        options: &[],
    };
    let mbuf_ctx = MbufInsertCtx {
        mbuf: unsafe { std::ptr::NonNull::new_unchecked(head_ptr) },
        payload_offset: 0,
    };

    // Bump head refcount once before dispatch per the MbufInsertCtx
    // contract (tcp_input transfers one refcount unit per retained
    // InOrderSegment; we bump once for the head here and rely on the
    // chain-walk's own +1 per tail link that path performs internally).
    unsafe {
        dpdk_net_sys::shim_rte_mbuf_refcnt_update(head_ptr, 1);
    }

    let out = dispatch(
        &mut c,
        &seg,
        &TEST_EDGES,
        TEST_SEND_BUF_BYTES,
        Some(mbuf_ctx),
    );

    // Core assertions: both chain links delivered as separate
    // InOrderSegment entries, ordering preserved, total length matches
    // head+tail payload bytes.
    let total_len = head_bytes.len() + tail_bytes.len();
    assert_eq!(
        out.delivered as usize, total_len,
        "outcome.delivered = {}, want {}",
        out.delivered, total_len
    );
    assert_eq!(
        c.recv.bytes.len(),
        2,
        "recv.bytes.len() = {}, want 2 (one seg per chain link)",
        c.recv.bytes.len()
    );
    let seg0 = &c.recv.bytes[0];
    let seg1 = &c.recv.bytes[1];
    assert_eq!(
        seg0.len as usize,
        head_bytes.len(),
        "seg[0].len = {}, want {}",
        seg0.len,
        head_bytes.len()
    );
    assert_eq!(
        seg1.len as usize,
        tail_bytes.len(),
        "seg[1].len = {}, want {}",
        seg1.len,
        tail_bytes.len()
    );
    // Σ seg.len == total_len
    assert_eq!(
        seg0.len as usize + seg1.len as usize,
        total_len,
        "Σ seg.len != total_len"
    );
    // rcv_nxt advanced by total bytes.
    assert_eq!(
        c.rcv_nxt,
        5001u32.wrapping_add(total_len as u32),
        "rcv_nxt must advance by total chained bytes"
    );

    // Content verification — read through each seg's data_ptr + len
    // and concatenate, expect head_bytes then tail_bytes.
    let mut concat = Vec::with_capacity(total_len);
    let s0_slice = unsafe {
        std::slice::from_raw_parts(seg0.data_ptr() as *const u8, seg0.len as usize)
    };
    let s1_slice = unsafe {
        std::slice::from_raw_parts(seg1.data_ptr() as *const u8, seg1.len as usize)
    };
    concat.extend_from_slice(s0_slice);
    concat.extend_from_slice(s1_slice);
    let mut expected = Vec::with_capacity(total_len);
    expected.extend_from_slice(&head_bytes);
    expected.extend_from_slice(&tail_bytes);
    assert_eq!(
        concat, expected,
        "chained content order / bytes must match head||tail layout"
    );

    // Drop the conn (and its held segment refcounts) before the pool
    // goes out of scope so the refcount decrement on segment Drop lands
    // in live mempool storage.
    drop(c);
    drop(pool);
}
