//! Regression test for I-8 (phase-a6-6-7-rfc-compliance.md FYI):
//! FIN piggybacked on a multi-seg chain (or, equivalently, on an
//! in-order segment whose delivery triggers an OOO-drain) must transition
//! the connection to CLOSE_WAIT.
//!
//! Pre-fix, `tcp_input::handle_established` compares
//! `seg.seq + seg.payload.len()` against `conn.rcv_nxt`. On any path
//! where the chain-total bytes accepted exceed the head-link payload
//! length (multi-seg chain OR in-order seg that drains a previously
//! queued OOO segment), the equality fails and the FIN is silently
//! dropped — the FSM stays in ESTABLISHED, breaking RFC 9293 §3.10.7.4.
//!
//! Post-fix, the equality compares `seg.seq + delivered` (the total
//! bytes accepted for this segment, including the OOO drain), so the
//! FIN is honored on both single-seg and multi-seg / drain paths.
//!
//! Test approach (pragmatic deviation from plan): rather than driving
//! the bug through the `inject_rx_chain` hook (which requires a real
//! peer-side TCP handshake to land the conn in ESTABLISHED — heavy
//! infrastructure for one assertion), we exercise it via the
//! semantically-equivalent OOO-drain path — pre-staging an OOO segment
//! at `rcv_nxt + head_payload.len()` so dispatching the in-order head
//! triggers the drain. The drained bytes accumulate into `delivered`
//! exactly as multi-seg chain-tail bytes would, so the FIN-piggyback
//! equality at line 1208 is exercised in the same buggy/fixed regime.
//! The fallback-to-unit-test option in the plan is what we used here.

use std::ptr::NonNull;

use dpdk_net_core::engine::DEFAULT_RTT_HISTOGRAM_EDGES_US;
use dpdk_net_core::flow_table::FourTuple;
use dpdk_net_core::tcp_conn::TcpConn;
use dpdk_net_core::tcp_input::{dispatch, MbufInsertCtx, ParsedSegment, TxAction};
use dpdk_net_core::tcp_output::{TCP_ACK, TCP_FIN};
use dpdk_net_core::tcp_state::TcpState;

const TEST_SEND_BUF_BYTES: u32 = 256 * 1024;

/// Build a synthetic ESTABLISHED-state `TcpConn`. Mirrors the
/// inline-test `est_conn` helper in `tcp_input.rs`.
fn est_conn(iss: u32, irs: u32, peer_wnd: u16) -> TcpConn {
    let t = FourTuple {
        local_ip: 0x0a_00_00_02,
        local_port: 40000,
        peer_ip: 0x0a_00_00_01,
        peer_port: 5000,
    };
    let mut c = TcpConn::new_client(t, iss, 1460, 1024, 2048, 5000, 5000, 1_000_000);
    c.state = TcpState::Established;
    c.snd_una = iss.wrapping_add(1);
    c.snd_nxt = iss.wrapping_add(1);
    c.irs = irs;
    c.rcv_nxt = irs.wrapping_add(1);
    c.snd_wnd = peer_wnd as u32;
    c
}

/// Multi-seg-chain analogue: an in-order segment with FIN whose
/// delivery triggers a drain of a previously queued OOO segment.
/// Pre-fix the FIN-piggyback equality fails because `delivered`
/// (head + drained) exceeds `seg.payload.len()`. Post-fix it succeeds.
#[cfg_attr(miri, ignore = "touches DPDK sys::*")]
#[test]
fn fin_piggyback_with_chain_total_advances_to_close_wait() {
    // Use a real backing buffer for the fake mbuf. The `shim_rte_mbuf_refcnt_update`
    // shim derefs the pointer to read+write `m->refcnt`; a heap-backed
    // 256-byte buffer keeps every refcount op landing in valid memory.
    // No mempool / no rte_pktmbuf_free path is reached: refcounts net to
    // zero across the test (insert +1, in-order-append +1, then 2× drop -1).
    let mut fake_mbuf_storage: Box<[u8; 256]> = Box::new([0u8; 256]);
    let fake_mbuf: NonNull<dpdk_net_sys::rte_mbuf> = unsafe {
        NonNull::new_unchecked(fake_mbuf_storage.as_mut_ptr() as *mut dpdk_net_sys::rte_mbuf)
    };

    let mut c = est_conn(1000, 5000, 1024);
    let rcv_nxt_before = c.rcv_nxt; // 5001

    // Stage 1: pre-insert an OOO segment at seq=5004 with 7 payload bytes.
    // The reorder queue's `insert` contract requires the caller to bump
    // the mbuf refcount by 1 before calling. The queue holds that one
    // ref until drain transfers it into the constructed `InOrderSegment`.
    unsafe {
        dpdk_net_sys::shim_rte_mbuf_refcnt_update(fake_mbuf.as_ptr(), 1);
    }
    let ooo_payload: &[u8] = b"OOOdata"; // 7 bytes at seq [5004, 5011)
    let outcome = c.recv.reorder.insert(5004, ooo_payload, fake_mbuf, 64);
    assert!(
        outcome.mbuf_ref_retained,
        "reorder.insert must retain the staged ref"
    );
    assert_eq!(outcome.newly_buffered, 7);

    // Stage 2: dispatch an in-order segment carrying:
    //   - 3 bytes of head payload at seq=5001 (fills the gap before the
    //     pre-staged OOO at seq=5004),
    //   - the FIN flag (the I-8 bug site).
    // Post-dispatch, `delivered` should be 3 (head) + 7 (drained OOO) = 10.
    // The FIN-piggyback equality must match against `rcv_nxt = 5001 + 10 = 5011`.
    let head_payload: &[u8] = b"abc"; // 3 bytes at seq [5001, 5004)
    let mbuf_ctx = MbufInsertCtx {
        mbuf: fake_mbuf,
        payload_offset: 54,
    };
    let seg = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: 1001,
        flags: TCP_ACK | TCP_FIN,
        window: 65535,
        header_len: 20,
        payload: head_payload,
        options: &[],
    };

    let out = dispatch(
        &mut c,
        &seg,
        &DEFAULT_RTT_HISTOGRAM_EDGES_US,
        TEST_SEND_BUF_BYTES,
        Some(mbuf_ctx),
    );

    // ── Pre-fix fail-mode: `delivered` would still equal 10 (the in-order
    //    drain accumulator works correctly), but the FIN-piggyback equality
    //    at line 1208 compared `seg.seq + seg.payload.len() (= 5001 + 3 = 5004)`
    //    against `conn.rcv_nxt (= 5011)`, mismatched, so the FIN was silently
    //    dropped and the FSM never advanced.
    // ── Post-fix success-mode: the equality compares against `delivered`
    //    (= 10), matches `rcv_nxt`, and the FIN advances the FSM to CLOSE_WAIT.

    assert_eq!(
        out.delivered, 10,
        "delivered must include head (3) + drained OOO (7); got {}",
        out.delivered
    );
    assert_eq!(
        out.new_state,
        Some(TcpState::CloseWait),
        "I-8 regression: FIN piggybacked on a chain-total-bytes-aware delivery \
         must advance the FSM to CLOSE_WAIT (delivered={}, rcv_nxt={})",
        out.delivered,
        c.rcv_nxt
    );
    assert_eq!(
        c.rcv_nxt,
        rcv_nxt_before.wrapping_add(10 + 1),
        "rcv_nxt must advance by chain total (10) + 1 for the consumed FIN seq"
    );
    // FIN consumed → ACK is mandatory (RFC 9293 §3.10.7.4 / RFC 5681 §4.2).
    assert_eq!(out.tx, TxAction::Ack);

    // Drop conn so each `InOrderSegment`'s `MbufHandle::Drop` runs
    // (refcount -1 on the fake mbuf storage). With the +1 we added and
    // dispatch's +1 for the in-order head, the refcount sequence is
    // 0 → 1 (insert pre-bump) → 2 (in-order append) → drained (no
    // change; ref transfers from OooSegment to InOrderSegment) → 1 → 0
    // on the two drops. No mempool free path is invoked.
    drop(c);
    let _ = &mut fake_mbuf_storage;
}

/// Single-seg sanity: when there is no OOO drain (chain length 1, head
/// payload covers the whole delivery), `delivered == seg.payload.len()`
/// so the substituted equality must behave identically to the original.
/// This guards against the fix accidentally regressing the common path.
#[cfg_attr(miri, ignore = "touches DPDK sys::*")]
#[test]
fn fin_piggyback_single_seg_unchanged_after_fix() {
    let mut c = est_conn(1000, 5000, 1024);
    // Bare FIN with no payload — the existing `established_fin_transitions_to_close_wait`
    // covers this; we re-cover it from outside the crate to assert the
    // post-fix behaviour is identical.
    let seg = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: 1001,
        flags: TCP_ACK | TCP_FIN,
        window: 65535,
        header_len: 20,
        payload: &[],
        options: &[],
    };
    let out = dispatch(
        &mut c,
        &seg,
        &DEFAULT_RTT_HISTOGRAM_EDGES_US,
        TEST_SEND_BUF_BYTES,
        None,
    );
    assert_eq!(out.delivered, 0);
    assert_eq!(out.new_state, Some(TcpState::CloseWait));
    assert_eq!(out.tx, TxAction::Ack);
    assert_eq!(c.rcv_nxt, 5002); // FIN consumes one seq.
}
