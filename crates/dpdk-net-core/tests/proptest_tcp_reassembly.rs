//! Property tests for `tcp_reassembly::ReorderQueue` — the OOO segment
//! store used by the TCP receive path (see `src/tcp_reassembly.rs`).
//!
//! Scope: STRUCTURAL invariants over the queue under arbitrary sequences
//! of `insert` / `drain_contiguous_into` calls. Refcount correctness is
//! exercised by the real-mbuf TAP integration tests + ahw_smoke + the
//! directed I-8 test (see Task 4 I-8 fin_piggyback_chain); these
//! properties cover the in-queue bookkeeping (seq ordering, disjointness,
//! total_bytes consistency, cap enforcement, drain contiguity, and
//! gap-byte monotonicity) that does not require a live DPDK mempool.
//!
//! Invariants asserted:
//!   I1. Segments are strictly seq-ordered and pairwise disjoint. The
//!       carve-on-insert path skips bytes already covered by existing
//!       entries; adjacent entries are kept as separate (no coalescing
//!       across mbufs per the zero-copy contract) but never overlap.
//!   I2. `total_bytes()` equals the sum of all stored `OooSegment.len`.
//!   I3. `total_bytes() <= cap` always.
//!   I4. `newly_buffered + cap_dropped <= payload.len()` for every
//!       `insert` call: the outcome accounts for every input byte as
//!       either buffered, capped, or skipped-due-to-overlap.
//!   I5. Drain is contiguous + in-order: when drain returns N bytes at
//!       `rcv_nxt`, all remaining queued segments have seq strictly
//!       greater than `rcv_nxt + N` (non-empty) OR the queue is empty.
//!   I6. Drain byte-count bound: `drained + cap_dropped` never exceeds
//!       the pre-drain `total_bytes()`.
//!   I7. Gap-bytes monotonicity: for a sequence of inserts whose union
//!       lives within a fixed [lo, hi) span, `gap_bytes = (hi - lo) -
//!       total_bytes()` is monotonically NON-INCREASING as more inserts
//!       arrive (insert never removes bytes from the queue — it only
//!       adds or caps).
//!
//! Seq values are drawn from `0..100_000` so wrap-safe comparators reduce
//! to plain `<` / `<=` for these cases — the wrap semantics are covered
//! by `proptest_tcp_seq.rs`.
//!
//! Test-mbuf storage: every `OooSegment` stores a `NonNull<rte_mbuf>` that
//! the queue's refcount bookkeeping derefs (via `shim_rte_mbuf_refcnt_update`
//! on carve-fanout in insert, drain-handoff, stale-drop, and
//! `ReorderQueue::Drop`). We back the fake pointer with a zeroed
//! `Box<[u8; 256]>` that outlives the queue — matches the pattern used
//! by the inline `drain_mbuf_past_end_of_segment_drops_entirely` and
//! `insert_spanning_multiple_existing_segments_produces_three_gap_slices`
//! tests in `src/tcp_reassembly.rs`. The shim only reads/writes the
//! refcnt field (first cache line, <32 bytes in), so 256 bytes of
//! aligned zero storage is ample.

use std::collections::VecDeque;

use dpdk_net_core::tcp_conn::InOrderSegment;
use dpdk_net_core::tcp_reassembly::ReorderQueue;
use dpdk_net_sys as sys;
use proptest::prelude::*;

/// Owns a zeroed backing buffer for one fake `rte_mbuf` pointer. The
/// buffer must outlive the `ReorderQueue` that stores the pointer so
/// the Drop-impl's refcnt decrement lands in valid memory.
struct FakeMbuf {
    storage: Box<[u8; 256]>,
}

impl FakeMbuf {
    fn new() -> Self {
        Self {
            storage: Box::new([0u8; 256]),
        }
    }

    fn as_ptr(&mut self) -> std::ptr::NonNull<sys::rte_mbuf> {
        // SAFETY: `storage` is a valid, aligned non-null allocation of
        // 256 bytes. We cast to `rte_mbuf*` so that
        // `shim_rte_mbuf_refcnt_update` (which only touches the refcnt
        // field in the first cache line) reads/writes land inside
        // `storage`. The fake mbuf's contents (payload area / headers)
        // are never dereferenced by the reassembly code under test.
        unsafe {
            std::ptr::NonNull::new_unchecked(self.storage.as_mut_ptr() as *mut sys::rte_mbuf)
        }
    }
}

/// A single `(seq, payload_len)` insert descriptor. Payload bytes
/// themselves are never inspected by the reassembly code (it records
/// only `(seq, offset, len)` and a mbuf pointer) so we don't bother
/// generating real payload content — we allocate a zero byte slice of
/// the requested length at use site.
#[derive(Debug, Clone, Copy)]
struct Insert {
    seq: u32,
    len: u16,
}

fn arb_insert() -> impl Strategy<Value = Insert> {
    // Keep seq well away from u32 wrap so wrap-safe comparators reduce
    // to plain ordering. `len` bounded by 1..=256 keeps total bytes in
    // a single test case below ~4 KiB even at the 16-insert upper
    // bound.
    (0u32..100_000, 1u16..=256).prop_map(|(seq, len)| Insert { seq, len })
}

/// Drive a `ReorderQueue` through `inserts` with a single shared fake
/// mbuf. Capacity is chosen large enough to never hit cap-drop for the
/// bounded input, so cap-drop semantics are covered separately.
fn build_queue(
    cap: u32,
    fake: &mut FakeMbuf,
    inserts: &[Insert],
) -> (ReorderQueue, u32 /* total_newly_buffered */) {
    let mbuf = fake.as_ptr();
    let mut q = ReorderQueue::new(cap);
    let mut total_newly = 0u32;
    for ins in inserts {
        let payload = vec![0u8; ins.len as usize];
        let out = q.insert(ins.seq, &payload, mbuf, 0);
        total_newly += out.newly_buffered;
    }
    (q, total_newly)
}

/// Sum of stored segment lengths — internal consistency check against
/// `total_bytes()`.
fn sum_segment_lens(q: &ReorderQueue) -> u32 {
    q.segments().iter().map(|s| s.len as u32).sum()
}

/// Fully drain `q` into `out` by advancing `rcv_nxt` to the max end-seq
/// of everything inserted. Caller is responsible for forgetting `out`
/// (see test bodies) to disarm `MbufHandle::Drop` on the fake pointer.
fn drain_all(q: &mut ReorderQueue, rcv_nxt: u32, out: &mut VecDeque<InOrderSegment>) -> (u32, u32) {
    q.drain_contiguous_into(rcv_nxt, u32::MAX, out)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// I1 + I2 + I3: after arbitrary inserts, segments are strictly
    /// seq-ordered and pairwise disjoint; `total_bytes()` matches the
    /// sum of stored lengths; `total_bytes() <= cap`.
    #[test]
    fn insert_preserves_structural_invariants(
        inserts in proptest::collection::vec(arb_insert(), 0..16),
    ) {
        let mut fake = FakeMbuf::new();
        let cap = 1_000_000u32;
        let (q, _) = build_queue(cap, &mut fake, &inserts);

        // I1a: seq-ordered (ascending, non-strict-ok for zero-len which
        // never occurs since arb_insert has len >= 1 — with len >= 1
        // and disjointness from I1b, the order is strict).
        let segs = q.segments();
        for pair in segs.windows(2) {
            prop_assert!(
                pair[0].seq < pair[1].seq,
                "segments not strictly seq-ordered: {:?} vs {:?}",
                pair[0], pair[1],
            );
        }

        // I1b: pairwise disjoint half-open ranges. No shared byte.
        for i in 0..segs.len() {
            for j in (i + 1)..segs.len() {
                let a_end = segs[i].seq + segs[i].len as u32;
                let b_start = segs[j].seq;
                prop_assert!(
                    a_end <= b_start,
                    "segments {:?} and {:?} overlap",
                    segs[i], segs[j],
                );
            }
        }

        // I2: total_bytes == sum of segment lens.
        prop_assert_eq!(q.total_bytes(), sum_segment_lens(&q));

        // I3: total_bytes <= cap.
        prop_assert!(q.total_bytes() <= cap);

        // Fully drain to a seq past all data so segments leave via the
        // stale branch; this exercises Drop via drop_segment_mbuf_ref
        // on the live backing storage. Collect into `out` and forget
        // to disarm MbufHandle::Drop on the fake pointer.
        let mut q = q;
        let mut out: VecDeque<InOrderSegment> = VecDeque::new();
        let _ = drain_all(&mut q, u32::MAX / 2, &mut out);
        std::mem::forget(out);
        // `q` now empty; Drop is a no-op.
    }

    /// I4: each `insert` outcome accounts for every input byte as one
    /// of (buffered | cap-dropped | overlap-skipped). Since the outcome
    /// exposes only `newly_buffered` and `cap_dropped`, we assert the
    /// weaker sum bound: both are non-negative and together don't
    /// exceed the payload length.
    #[test]
    fn insert_outcome_byte_accounting_bounded(
        inserts in proptest::collection::vec(arb_insert(), 0..16),
    ) {
        let mut fake = FakeMbuf::new();
        let mbuf = fake.as_ptr();
        let cap = 1_000_000u32;
        let mut q = ReorderQueue::new(cap);
        for ins in &inserts {
            let payload = vec![0u8; ins.len as usize];
            let out = q.insert(ins.seq, &payload, mbuf, 0);
            prop_assert!(
                out.newly_buffered + out.cap_dropped <= ins.len as u32,
                "byte accounting exceeds payload: newly={} cap_dropped={} len={}",
                out.newly_buffered, out.cap_dropped, ins.len,
            );
            // Empty payload is filtered out by arb_insert (len >= 1),
            // so `mbuf_ref_retained == false` implies every byte was
            // overlap-skipped.
            if !out.mbuf_ref_retained {
                prop_assert_eq!(out.newly_buffered, 0);
            }
        }
        let mut out: VecDeque<InOrderSegment> = VecDeque::new();
        let _ = drain_all(&mut q, u32::MAX / 2, &mut out);
        std::mem::forget(out);
    }

    /// I5 + I6: drain is contiguous + in-order, and the returned byte
    /// count is bounded by the pre-drain `total_bytes()`.
    #[test]
    fn drain_contiguous_and_bounded(
        inserts in proptest::collection::vec(arb_insert(), 0..16),
        rcv_nxt_bias in 0u32..50_000,
    ) {
        let mut fake = FakeMbuf::new();
        let cap = 1_000_000u32;
        let (mut q, _) = build_queue(cap, &mut fake, &inserts);
        let pre_total = q.total_bytes();
        // Pick rcv_nxt inside the range that the seed could occupy so
        // some drains hit the contiguous branch and some hit the stale
        // / gap branch.
        let rcv_nxt = rcv_nxt_bias;
        let mut out: VecDeque<InOrderSegment> = VecDeque::new();
        let (drained, cap_dropped) = q.drain_contiguous_into(rcv_nxt, u32::MAX, &mut out);

        // I6: drained + cap_dropped <= pre_drain total_bytes. (cap_dropped
        // is 0 here since we passed cap_room = u32::MAX, but the bound
        // holds generally.)
        prop_assert!(
            drained.checked_add(cap_dropped).map(|s| s <= pre_total).unwrap_or(false),
            "drained={} + cap_dropped={} exceeds pre_total={}",
            drained, cap_dropped, pre_total,
        );

        // I5: every remaining segment in the queue has seq strictly
        // after where the drained prefix ended — i.e. there is a seq
        // gap at or before rcv_nxt+drained that stopped the drain.
        // Since the drain pops seq-sorted segments from the front and
        // ONLY advances rcv_nxt by actually-appended bytes, any
        // remaining segment satisfies either:
        //   (a) its seq is > rcv_nxt + drained (gap stopped drain), or
        //   (b) its seq is exactly rcv_nxt + drained AND cap_room
        //       exhausted before appending it — impossible here since
        //       cap_room was u32::MAX.
        let remaining = q.segments();
        if !remaining.is_empty() {
            let frontier = rcv_nxt.wrapping_add(drained);
            prop_assert!(
                remaining[0].seq > frontier,
                "drain left a segment at seq {} but drained up to {}",
                remaining[0].seq, frontier,
            );
        }

        // Structural invariants survive the drain.
        prop_assert_eq!(q.total_bytes(), sum_segment_lens(&q));
        prop_assert!(q.total_bytes() <= cap);

        // Cleanup: fully drain residue and forget the output queue.
        let mut tail_out: VecDeque<InOrderSegment> = VecDeque::new();
        let _ = drain_all(&mut q, u32::MAX / 2, &mut tail_out);
        std::mem::forget(out);
        std::mem::forget(tail_out);
    }

    /// I7: gap-bytes within a fixed seq-span is monotonically
    /// non-increasing across inserts — insert never removes bytes from
    /// the queue, only adds or caps. Capacity is set so cap-drop cannot
    /// fire for the bounded input.
    #[test]
    fn gap_bytes_monotonically_non_increasing(
        inserts in proptest::collection::vec(arb_insert(), 1..16),
    ) {
        let mut fake = FakeMbuf::new();
        let mbuf = fake.as_ptr();
        let cap = 1_000_000u32;
        let mut q = ReorderQueue::new(cap);

        // Track total_bytes after each insert and assert it is
        // non-decreasing (equivalent to gap-bytes non-increasing over
        // any fixed enclosing span, since `gap_bytes = span - total_bytes`
        // and `span` is fixed by the enclosing [lo, hi) boundary).
        let mut prev_total = 0u32;
        for ins in &inserts {
            let payload = vec![0u8; ins.len as usize];
            let out = q.insert(ins.seq, &payload, mbuf, 0);
            // `newly_buffered` is the delta that just landed — never
            // negative (u32).
            let cur_total = q.total_bytes();
            prop_assert!(
                cur_total >= prev_total,
                "total_bytes regressed: {} -> {} (insert outcome: {:?})",
                prev_total, cur_total, out,
            );
            // Increment consistency: cur_total == prev_total + newly_buffered.
            prop_assert_eq!(
                cur_total,
                prev_total + out.newly_buffered,
                "total_bytes delta mismatch with outcome.newly_buffered",
            );
            prev_total = cur_total;
        }

        // Cleanup.
        let mut out: VecDeque<InOrderSegment> = VecDeque::new();
        let _ = drain_all(&mut q, u32::MAX / 2, &mut out);
        std::mem::forget(out);
    }

    /// Cap enforcement: with a tight cap, `total_bytes()` never exceeds
    /// `cap` across any insert sequence. Each insert's cap_dropped
    /// accumulates overflow beyond the cap; sum of newly_buffered
    /// stays <= cap.
    #[test]
    fn cap_is_hard_limit(
        inserts in proptest::collection::vec(arb_insert(), 0..16),
        cap in 0u32..1024,
    ) {
        let mut fake = FakeMbuf::new();
        let mbuf = fake.as_ptr();
        let mut q = ReorderQueue::new(cap);
        for ins in &inserts {
            let payload = vec![0u8; ins.len as usize];
            let _ = q.insert(ins.seq, &payload, mbuf, 0);
            prop_assert!(
                q.total_bytes() <= cap,
                "total_bytes {} exceeds cap {}",
                q.total_bytes(), cap,
            );
        }
        let mut out: VecDeque<InOrderSegment> = VecDeque::new();
        let _ = drain_all(&mut q, u32::MAX / 2, &mut out);
        std::mem::forget(out);
    }
}
