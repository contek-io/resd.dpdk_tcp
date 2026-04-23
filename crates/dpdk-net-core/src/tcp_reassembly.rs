//! Out-of-order segment reassembly. Zero-copy since A6.5 Task 4d:
//! every stored segment is a reference to payload bytes living inside
//! a DPDK mbuf, and insert/drain/eviction participate in explicit
//! per-segment mbuf-refcount bookkeeping (see `OooSegment` for the
//! ownership contract).
//!
//! Insertion is O(N) where N is the number of OOO segments currently
//! buffered (bounded by `recv_buffer_bytes / peer_mss`, typically < 180
//! with a 256 KiB cap and 1460-byte MSS — acceptable under trading
//! workload where OOO is rare to begin with). Merge on insert carves
//! the incoming mbuf-slice into gap-slices that don't overlap any
//! existing stored segment. Adjacent `OooSegment` entries do NOT
//! coalesce (zero-copy contract: no payload concatenation across mbufs);
//! they stay as separate seq-sorted entries and drain together when
//! `rcv_nxt` matches each one's start seq in turn.

use dpdk_net_sys as sys;
use smallvec::SmallVec;

use crate::tcp_seq::{seq_le, seq_lt};

/// An out-of-order reassembly segment: a reference to payload bytes
/// living inside a DPDK mbuf, with the segment's TCP seq + the byte
/// offset/length inside the mbuf's data region. `ReorderQueue` holds
/// one refcount per `OooSegment`; bumped at `insert`, dropped when the
/// segment leaves the queue (drain handoff / stale-drop /
/// `ReorderQueue::Drop`).
///
/// When a single mbuf is carved into N gap-slices, N separate
/// `OooSegment` entries reference the same mbuf and the queue holds N
/// refcounts on it; each is decremented independently as the matching
/// segment leaves.
///
/// Cloning `OooSegment` duplicates the raw pointer WITHOUT bumping the
/// refcount; callers must uphold the invariant that a cloned ref
/// either (a) replaces the original in the queue, or (b) is only used
/// for inspection before the original is dropped. `Clone` is retained
/// for the gap-carve + eviction borrow patterns inside this module
/// rather than forcing manual refcount bookkeeping at every ownership
/// move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OooSegment {
    pub seq: u32,
    pub mbuf: std::ptr::NonNull<sys::rte_mbuf>,
    pub offset: u16,
    pub len: u16,
}

// SAFETY: raw pointer stored but `ReorderQueue` is single-lcore.
// Matches the `Send` story on `Mbuf` / `Mempool`.
unsafe impl Send for OooSegment {}

impl OooSegment {
    pub fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(self.len as u32)
    }

    /// Byte length of the segment's payload window inside the mbuf.
    /// Returned as `u32` to match the counter-math call shape used
    /// elsewhere (e.g. `total_bytes`).
    pub fn len_bytes(&self) -> u32 {
        self.len as u32
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Outcome of `ReorderQueue::insert`. The caller uses it to decide
/// whether to bump `tcp.rx_reassembly_queued` (true when new bytes
/// were actually buffered) and how many bytes were dropped due to
/// the cap (feeds `tcp.recv_buf_drops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsertOutcome {
    /// Bytes of new (not-already-buffered) payload actually stored.
    pub newly_buffered: u32,
    /// Bytes dropped because inserting them would push
    /// `total_bytes()` past `cap`.
    pub cap_dropped: u32,
    /// A6.5 Task 4b: true iff at least one segment derived from the
    /// caller's mbuf was actually retained in the queue. When false,
    /// the caller should roll back the refcount up-bump they did prior
    /// to calling `insert` (via `rte_mbuf_refcnt_update(mbuf, -1)`).
    /// When true, the caller's pre-bump is consumed by the queue; if
    /// the carve produced multiple gap-slices, `insert` has
    /// already bumped the refcount internally by `(stored_count - 1)`
    /// so that every stored `OooSegment` owns exactly one reference.
    pub mbuf_ref_retained: bool,
}

pub struct ReorderQueue {
    segments: Vec<OooSegment>,
    cap: u32,
    total_bytes: u32,
}

impl ReorderQueue {
    pub fn new(cap: u32) -> Self {
        Self {
            segments: Vec::new(),
            cap,
            total_bytes: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
    pub fn len(&self) -> usize {
        self.segments.len()
    }
    pub fn total_bytes(&self) -> u32 {
        self.total_bytes
    }
    pub fn segments(&self) -> &[OooSegment] {
        &self.segments
    }

    /// A8 T7: release all queued segments' mbuf refcounts and empty the
    /// queue without going through Drop. Used by the test-server teardown
    /// helper (`Engine::test_clear_pinned_rx_mbufs`) so a conn holding
    /// OOO-pinned mbuf refs at teardown doesn't UAF its mempool (Drop
    /// order: `Engine._rx_mempool` frees before `Engine.flow_table` runs
    /// conn drops). No-op when empty.
    pub fn clear(&mut self) {
        for seg in &self.segments {
            Self::drop_segment_mbuf_ref(seg);
        }
        self.segments.clear();
        self.total_bytes = 0;
    }

    /// A6.5 Task 4b: insert a range of payload bytes as `OooSegment`
    /// entries, referencing the supplied mbuf with offset/length.
    /// Caller MUST have bumped the mbuf refcount by 1 before calling;
    /// the queue holds one ref for every stored segment and, when a
    /// carve produces multiple gap-slices, bumps the refcount
    /// internally by `(stored_count - 1)` to match. Returns
    /// `mbuf_ref_retained = true` iff at least one gap-slice was
    /// actually stored; otherwise caller should roll back the up-bump.
    ///
    /// Gap-slice carve preserves standard overlap / merge semantics:
    /// bytes that fall inside an existing stored segment are skipped
    /// (no duplicate store), and non-overlapping sub-ranges are stored
    /// as separate seq-sorted `OooSegment` entries. Adjacent entries
    /// do NOT coalesce physically (no payload concatenation across
    /// mbufs); they stay as separate entries and drain together.
    pub fn insert(
        &mut self,
        seq: u32,
        payload: &[u8],
        mbuf: std::ptr::NonNull<sys::rte_mbuf>,
        mbuf_payload_offset: u16,
    ) -> InsertOutcome {
        if payload.is_empty() {
            return InsertOutcome {
                newly_buffered: 0,
                cap_dropped: 0,
                mbuf_ref_retained: false,
            };
        }
        let incoming_end = seq.wrapping_add(payload.len() as u32);
        let mut cursor = seq;
        let mut newly_buffered = 0u32;
        let mut cap_dropped = 0u32;

        // A6.5 Task 7 fix (C1): deferred-insert pattern. Collect pending
        // `(cursor_seq, sub_offset, take_len)` triples while scanning
        // the existing segments with an immutable borrow; apply the
        // actual `insert_merged` mutations in a second pass after the
        // scan completes. This avoids the index-shift bug where
        // mid-iteration inserts caused later existing segments to be
        // skipped. A `SmallVec` keeps the zero-alloc steady state:
        // multi-segment-span reorder is rare and almost always fits
        // within 4 gap-slices; anything larger falls back to one heap
        // alloc on this slow path (gap-filling), which is acceptable.
        let mut to_insert: SmallVec<[(u32, u16, u16); 4]> = SmallVec::new();

        for existing in &self.segments {
            let existing_seq = existing.seq;
            let existing_end = existing.end_seq();
            if seq_le(incoming_end, existing_seq) {
                break;
            }
            if seq_le(existing_end, cursor) {
                continue;
            }
            if seq_lt(cursor, existing_seq) {
                let gap_len = existing_seq.wrapping_sub(cursor) as usize;
                let off = cursor.wrapping_sub(seq) as usize;
                let take_end = off + gap_len.min(payload.len() - off);
                let remaining_cap = self.cap.saturating_sub(self.total_bytes + newly_buffered);
                let take = (take_end - off).min(remaining_cap as usize);
                if take > 0 {
                    let sub_offset = mbuf_payload_offset + off as u16;
                    to_insert.push((cursor, sub_offset, take as u16));
                    newly_buffered += take as u32;
                }
                if take < take_end - off {
                    cap_dropped += (take_end - off - take) as u32;
                }
                cursor = cursor.wrapping_add((take_end - off) as u32);
            }
            if seq_lt(cursor, existing_end) {
                cursor = existing_end;
            }
        }
        if seq_lt(cursor, incoming_end) {
            let off = cursor.wrapping_sub(seq) as usize;
            let tail_len = payload.len() - off;
            let remaining_cap = self.cap.saturating_sub(self.total_bytes + newly_buffered);
            let take = tail_len.min(remaining_cap as usize);
            if take > 0 {
                let sub_offset = mbuf_payload_offset + off as u16;
                to_insert.push((cursor, sub_offset, take as u16));
                newly_buffered += take as u32;
            }
            if take < tail_len {
                cap_dropped += (tail_len - take) as u32;
            }
        }

        // Second phase: apply the collected inserts. Each push shifts
        // following indices, but we no longer iterate over
        // `self.segments` so the shift is inconsequential —
        // `insert_merged` positions each new entry by seq order within
        // the current state of `self.segments`.
        let stored_count = to_insert.len() as u32;
        for (cursor_seq, sub_offset, take_len) in to_insert {
            self.insert_merged(cursor_seq, mbuf, sub_offset, take_len);
        }

        self.total_bytes += newly_buffered;
        // Caller bumped the refcount by +1 pre-call. The queue needs
        // one ref per stored segment. If the carve produced >1 stored
        // entries, bump the refcount by `(stored_count - 1)` to cover
        // the extras. Each `drop_segment_mbuf_ref` call will eventually
        // decrement once per stored segment, returning the refcount to
        // its caller-side baseline when the last segment leaves.
        if stored_count > 1 {
            let extra = (stored_count - 1) as i16;
            // SAFETY: the caller asserts that `mbuf` is a live pointer
            // and that its refcount has been bumped to at least 1 prior
            // to calling. We are bumping by a positive delta here,
            // which is always safe.
            unsafe {
                sys::shim_rte_mbuf_refcnt_update(mbuf.as_ptr(), extra);
            }
        }
        InsertOutcome {
            newly_buffered,
            cap_dropped,
            mbuf_ref_retained: stored_count > 0,
        }
    }

    /// Insert an `OooSegment` at (seq, offset, len). Caller has already
    /// carved out overlap upstream. Adjacent entries do NOT physically
    /// merge (zero-copy contract: no payload concatenation across
    /// mbufs); they stay as separate seq-sorted entries.
    fn insert_merged(
        &mut self,
        seq: u32,
        mbuf: std::ptr::NonNull<sys::rte_mbuf>,
        offset: u16,
        len: u16,
    ) {
        let mut idx = self.segments.len();
        for (i, s) in self.segments.iter().enumerate() {
            if seq_lt(seq, s.seq) {
                idx = i;
                break;
            }
        }
        self.segments.insert(
            idx,
            OooSegment {
                seq,
                mbuf,
                offset,
                len,
            },
        );
    }

    /// A6.5 Task 4b: drop the mbuf refcount held for an `OooSegment`
    /// that is leaving the queue (drain, stale-drop).
    /// SAFETY: caller guarantees `seg`'s mbuf pointer is still valid,
    /// which holds as long as the queue's stored refcount has not been
    /// decremented — this helper IS the decrement, so it runs at most
    /// once per stored segment.
    fn drop_segment_mbuf_ref(seg: &OooSegment) {
        // SAFETY: `seg.mbuf` was validated at `insert` time; the queue
        // has held a refcount on it since then, so the pointer is still
        // live. The decrement may take the refcount to zero and return
        // the mbuf to its mempool, which is the intended end-of-life
        // behavior.
        unsafe {
            sys::shim_rte_mbuf_refcnt_update(seg.mbuf.as_ptr(), -1);
        }
    }

    /// A6.6 Task 4: zero-copy drain with output-param form. Pops the
    /// contiguous prefix of segments whose seq range starts at or before
    /// `rcv_nxt` and appends each popped segment as one `InOrderSegment`
    /// to the caller-owned `out` VecDeque (one drained segment per
    /// appended entry — zero-copy contract: no payload concatenation
    /// across mbufs). Returns `(bytes_appended, cap_dropped)` where
    /// `cap_dropped` sums the overshoot-per-segment when `cap_room`
    /// runs out mid-drain; the caller adds it to its `buf_full_drop`
    /// accumulator.
    ///
    /// `cap_room` is the remaining in-order buffer space — the reorder
    /// queue and the in-order queue share `recv_buffer_bytes` but track
    /// caps independently, so the drain site must enforce the in-order
    /// queue's room here. This mirrors the pre-T4 behaviour where the
    /// caller truncated each `DrainedMbuf` by `cap_room`, advanced
    /// `rcv_nxt` by the truncated byte count only, and let the
    /// drain-loop keep popping subsequent contiguous segments (each
    /// getting fully cap-dropped once room was exhausted).
    ///
    /// Refcount ownership: each stored `OooSegment` owns exactly one
    /// mbuf refcount. For each kept-in-full or partially-kept segment,
    /// that refcount transfers directly into the newly constructed
    /// `InOrderSegment`'s `MbufHandle` — the queue neither bumps nor
    /// decrements on the kept path. Stale segments fully behind
    /// `rcv_nxt` and fully cap-dropped segments (appended == 0) have
    /// their refcount released via `drop_segment_mbuf_ref`.
    pub fn drain_contiguous_into(
        &mut self,
        mut rcv_nxt: u32,
        mut cap_room: u32,
        out: &mut std::collections::VecDeque<crate::tcp_conn::InOrderSegment>,
    ) -> (u32, u32) {
        let mut total = 0u32;
        let mut cap_dropped = 0u32;

        while !self.segments.is_empty() {
            let seg_seq = self.segments[0].seq;
            if seq_lt(rcv_nxt, seg_seq) {
                break;
            }
            let seg_end = self.segments[0].end_seq();
            let seg_len = self.segments[0].len_bytes();
            if seq_le(seg_end, rcv_nxt) {
                // Entire segment behind rcv_nxt — drop + decrement the
                // queue's held refcount.
                Self::drop_segment_mbuf_ref(&self.segments[0]);
                self.total_bytes = self.total_bytes.saturating_sub(seg_len);
                self.segments.remove(0);
                continue;
            }
            let skip = rcv_nxt.wrapping_sub(seg_seq) as u16;
            let kept_bytes = seg_len - skip as u32;
            let appended = kept_bytes.min(cap_room) as u16;
            let overshoot = kept_bytes - appended as u32;

            let seg = self.segments.remove(0);
            self.total_bytes = self.total_bytes.saturating_sub(seg_len);

            if appended > 0 {
                let mbuf = seg.mbuf;
                let offset = seg.offset + skip;
                // Refcount-ownership transfer: `OooSegment` owns one
                // refcount on `seg.mbuf`. We hand that refcount
                // directly to the `MbufHandle` constructed here (no
                // bump/decrement). `OooSegment` has no `Drop` impl —
                // refcount release happens via `drop_segment_mbuf_ref`
                // on the stale / fully-cap-dropped paths, via
                // `ReorderQueue::Drop` at teardown, or via the
                // transfer here into `MbufHandle` whose own `Drop`
                // will later decrement. So the local `seg` going out
                // of scope after this move is a refcount-neutral
                // no-op; no `mem::forget` needed.
                //
                // SAFETY: the queue held exactly one refcount on this
                // pointer since `insert` time. That refcount is now
                // transferred to the handle we construct here; no
                // other reference survives past this move.
                // `MbufHandle::Drop` will release the refcount when
                // the `InOrderSegment` is popped and dropped
                // downstream.
                let handle = unsafe { crate::mempool::MbufHandle::from_raw(mbuf) };
                out.push_back(crate::tcp_conn::InOrderSegment {
                    mbuf: handle,
                    offset,
                    len: appended,
                });
                total = total.wrapping_add(appended as u32);
                cap_room -= appended as u32;
            } else {
                // Zero bytes kept (cap exhausted) — no
                // `InOrderSegment` to transfer the refcount into, so
                // release it via `drop_segment_mbuf_ref` to preserve
                // the queue's refcount accounting.
                Self::drop_segment_mbuf_ref(&seg);
            }

            cap_dropped = cap_dropped.wrapping_add(overshoot);
            // Mirror the pre-T4 caller's behaviour: advance `rcv_nxt`
            // only by the bytes actually appended, not the full kept
            // extent. This keeps subsequent contiguous segments on the
            // "behind rcv_nxt" path so the next drain iteration takes
            // the stale branch (dropping their refcount via
            // `drop_segment_mbuf_ref`).
            rcv_nxt = rcv_nxt.wrapping_add(appended as u32);
        }
        (total, cap_dropped)
    }
}

impl Drop for ReorderQueue {
    /// A6.5 Task 7 fix (C3): decrement mbuf refcount on every stored
    /// `OooSegment` when the queue is dropped. Prevents refcount leaks
    /// when a `TcpConn` is dropped mid-reassembly (RST, reaper,
    /// force-close) with OOO segments still queued.
    fn drop(&mut self) {
        for seg in &self.segments {
            Self::drop_segment_mbuf_ref(seg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn empty_queue_is_empty() {
        let q = ReorderQueue::new(1024);
        assert!(q.is_empty());
        assert_eq!(q.total_bytes(), 0);
    }

    // A6.6 Task 4: `drain_contiguous_into` unit tests. These tests
    // exercise drain logic with `OooSegment` entries, appending into a
    // caller-owned `VecDeque<InOrderSegment>`. Structural assertions
    // only — the payload window `(offset, len)` is checked without
    // dereferencing the fake mbuf pointer (which would be UB on
    // `NonNull::dangling()`). Real-mbuf lifecycle is covered by the TAP
    // integration tests + ahw_smoke.
    //
    // Each `InOrderSegment` owns an `MbufHandle` whose `Drop` decrements
    // the refcount; tests that drain into `out` backed by
    // `NonNull::dangling()` call `std::mem::forget(out)` at the end to
    // disarm those drops. Tests that leave entries in the queue also
    // `std::mem::forget(q)` to bypass `ReorderQueue::Drop`.

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn drain_mbuf_with_no_contiguous_front_returns_empty() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert(200, b"zzz", fake_mbuf, 64);
        let mut out: std::collections::VecDeque<crate::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        let (drained_bytes, cap_dropped) = q.drain_contiguous_into(100, 1024, &mut out);
        assert_eq!(drained_bytes, 0);
        assert_eq!(cap_dropped, 0);
        assert!(out.is_empty());
        assert_eq!(q.len(), 1);
        std::mem::forget(q);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn drain_mbuf_single_adjacent_segment() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert(100, b"abc", fake_mbuf, 64);
        let mut out: std::collections::VecDeque<crate::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        let (drained_bytes, cap_dropped) = q.drain_contiguous_into(100, 1024, &mut out);
        assert_eq!(drained_bytes, 3);
        assert_eq!(cap_dropped, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].offset, 64);
        assert_eq!(out[0].len, 3);
        assert!(q.is_empty());
        assert_eq!(q.total_bytes(), 0);
        // Refcount handoff: drain transferred one ref into each
        // InOrderSegment's MbufHandle. Forget `out` to bypass
        // MbufHandle::Drop on the dangling pointer; forget `q` for
        // consistency (empty, so Drop is a no-op but harmless).
        std::mem::forget(out);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn drain_mbuf_stops_at_gap() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert(100, b"aaa", fake_mbuf, 10);
        q.insert(200, b"zzz", fake_mbuf, 20);
        let mut out: std::collections::VecDeque<crate::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        let (drained_bytes, cap_dropped) = q.drain_contiguous_into(100, 1024, &mut out);
        // Only the seq-100 entry drains; there's a gap [103, 200).
        assert_eq!(drained_bytes, 3);
        assert_eq!(cap_dropped, 0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].offset, 10);
        assert_eq!(out[0].len, 3);
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq, 200);
        std::mem::forget(out);
        // One entry still in the queue; skip Drop to avoid UB deref.
        std::mem::forget(q);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn drain_mbuf_chains_through_touching_segments() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        // Adjacent entries do NOT coalesce on insert (zero-copy
        // contract), but DO drain together when rcv_nxt matches each
        // one's start seq in turn.
        q.insert(100, b"aaa", fake_mbuf, 10);
        q.insert(103, b"bbb", fake_mbuf, 20);
        q.insert(200, b"zzz", fake_mbuf, 30);
        let mut out: std::collections::VecDeque<crate::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        let (drained_bytes, cap_dropped) = q.drain_contiguous_into(100, 1024, &mut out);
        assert_eq!(drained_bytes, 6);
        assert_eq!(cap_dropped, 0);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].offset, 10);
        assert_eq!(out[0].len, 3);
        assert_eq!(out[1].offset, 20);
        assert_eq!(out[1].len, 3);
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq, 200);
        std::mem::forget(out);
        std::mem::forget(q);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn drain_mbuf_with_rcv_nxt_inside_segment_skips_prefix() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert(100, b"abcdef", fake_mbuf, 50);
        let mut out: std::collections::VecDeque<crate::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        let (drained_bytes, cap_dropped) = q.drain_contiguous_into(103, 1024, &mut out);
        assert_eq!(drained_bytes, 3);
        assert_eq!(cap_dropped, 0);
        assert_eq!(out.len(), 1);
        // skip = 3; offset bumps from 50 → 53; len shrinks from 6 → 3.
        assert_eq!(out[0].offset, 53);
        assert_eq!(out[0].len, 3);
        std::mem::forget(out);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn drain_mbuf_past_end_of_segment_drops_entirely() {
        // When rcv_nxt is past the segment's end, the segment is stale
        // and dropped via drop_segment_mbuf_ref — that call would deref
        // the mbuf pointer to decrement the refcount. Use a real
        // backing storage so the deref lands in valid memory.
        let mut fake_mbuf_storage: Box<[u8; 256]> = Box::new([0u8; 256]);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = unsafe {
            std::ptr::NonNull::new_unchecked(
                fake_mbuf_storage.as_mut_ptr() as *mut sys::rte_mbuf,
            )
        };
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abc", fake_mbuf, 10);
        let mut out: std::collections::VecDeque<crate::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        let (drained_bytes, cap_dropped) = q.drain_contiguous_into(200, 1024, &mut out);
        // Stale segment dropped (behind rcv_nxt), nothing handed off.
        assert_eq!(drained_bytes, 0);
        assert_eq!(cap_dropped, 0);
        assert!(out.is_empty());
        assert!(q.is_empty());
        drop(q);
        // Force a read of the mutable binding so the compiler knows the
        // storage was used; `_` suppresses the warning.
        let _ = &mut fake_mbuf_storage;
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn drain_mbuf_empty_queue_is_noop() {
        let mut q = ReorderQueue::new(1024);
        let mut out: std::collections::VecDeque<crate::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        let (drained_bytes, cap_dropped) = q.drain_contiguous_into(500, 1024, &mut out);
        assert_eq!(drained_bytes, 0);
        assert_eq!(cap_dropped, 0);
        assert!(out.is_empty());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn drain_mbuf_cap_exhausted_mid_segment_reports_cap_dropped() {
        // Build a real mbuf-backed pointer so `drop_segment_mbuf_ref`
        // (which would fire on the zero-append path of a subsequent
        // contiguous segment) lands in valid memory if we go that far.
        let mut fake_mbuf_storage: Box<[u8; 256]> = Box::new([0u8; 256]);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = unsafe {
            std::ptr::NonNull::new_unchecked(
                fake_mbuf_storage.as_mut_ptr() as *mut sys::rte_mbuf,
            )
        };
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abcdef", fake_mbuf, 10);
        let mut out: std::collections::VecDeque<crate::tcp_conn::InOrderSegment> =
            std::collections::VecDeque::new();
        // cap_room=4 → appended=4, overshoot=2. Single-segment drain,
        // so no follow-on zero-append iteration.
        let (drained_bytes, cap_dropped) = q.drain_contiguous_into(100, 4, &mut out);
        assert_eq!(drained_bytes, 4);
        assert_eq!(cap_dropped, 2);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].offset, 10);
        assert_eq!(out[0].len, 4);
        // Segment popped from queue; refcount transferred into `out`
        // (will fire MbufHandle::Drop → shim_rte_mbuf_refcnt_update(-1)
        // on the real backing storage, harmless).
        assert!(q.is_empty());
        drop(q);
        drop(out);
        let _ = &mut fake_mbuf_storage;
    }

    // A6.5 Task 4b (Task 7): `insert` unit tests. These tests exercise
    // insert logic only — they do NOT call drain (which would deref the
    // dangling pointer). The TAP integration tests + ahw_smoke exercise
    // the full real-mbuf lifecycle. SAFETY: A6.5 Task 7's Drop impl on
    // ReorderQueue would deref `OooSegment` pointers at queue drop, so
    // every test below that stores an entry backed by
    // `NonNull::dangling()` calls `std::mem::forget(q)` at the end to
    // bypass the Drop impl. Refcount-decrement bookkeeping is exercised
    // via the TAP integration tests with real mbufs.

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn insert_produces_ooo_segment() {
        let mut q = ReorderQueue::new(1024);
        // SAFETY: test-only; insert only stores the pointer, does not
        // deref. See module-level comment above about Drop safety.
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        let payload = b"hello";
        let out = q.insert(100, payload, fake_mbuf, 64);
        assert_eq!(out.newly_buffered, payload.len() as u32);
        assert_eq!(out.cap_dropped, 0);
        assert!(out.mbuf_ref_retained);
        assert_eq!(q.len(), 1);
        let seg = &q.segments()[0];
        assert_eq!(seg.seq, 100);
        assert_eq!(seg.offset, 64);
        assert_eq!(seg.len, 5);
        // Skip Drop to avoid UB deref on the fake mbuf pointer.
        std::mem::forget(q);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn insert_cap_overflow_signals_no_retained_ref() {
        let mut q = ReorderQueue::new(3);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        let payload = b"hello";
        let out = q.insert(100, payload, fake_mbuf, 0);
        assert_eq!(out.newly_buffered, 3);
        assert_eq!(out.cap_dropped, 2);
        assert!(out.mbuf_ref_retained);

        let mut q2 = ReorderQueue::new(0);
        let out2 = q2.insert(100, payload, fake_mbuf, 0);
        assert_eq!(out2.newly_buffered, 0);
        assert_eq!(out2.cap_dropped, 5);
        assert!(!out2.mbuf_ref_retained);
        // q stored 1 entry; skip Drop to avoid UB deref.
        std::mem::forget(q);
        // q2 stored nothing (cap=0 dropped it), but forget anyway for
        // consistency.
        std::mem::forget(q2);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn insert_empty_payload_returns_not_retained() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        let out = q.insert(100, b"", fake_mbuf, 0);
        assert_eq!(out.newly_buffered, 0);
        assert_eq!(out.cap_dropped, 0);
        assert!(!out.mbuf_ref_retained);
        assert_eq!(q.len(), 0);
        // No entries stored, Drop would be a no-op. forget() is not
        // strictly required but is kept for consistency across
        // dangling-pointer tests.
        std::mem::forget(q);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn insert_inserts_sort_by_seq() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert(200, b"bbb", fake_mbuf, 100);
        q.insert(100, b"aaa", fake_mbuf, 200);
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(q.segments()[1].seq, 200);
        // Adjacent entries do NOT coalesce even when adjacent
        // (zero-copy contract: no payload concatenation).
        q.insert(103, b"ccc", fake_mbuf, 300);
        assert_eq!(q.len(), 3);
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(q.segments()[1].seq, 103);
        assert_eq!(q.segments()[2].seq, 200);
        // Skip Drop: queue holds 3 entries backed by a fake ptr.
        std::mem::forget(q);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn insert_two_disjoint_stay_separate() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert(100, b"aaa", fake_mbuf, 0);
        q.insert(200, b"bbb", fake_mbuf, 32);
        assert_eq!(q.len(), 2);
        assert_eq!(q.total_bytes(), 6);
        std::mem::forget(q);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn insert_overlap_with_existing_is_deduplicated() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        // Existing: [100..106).
        q.insert(100, b"abcdef", fake_mbuf, 0);
        // Retransmit: [103..107). Overlap [103..106); new [106..107).
        let out = q.insert(103, b"defg", fake_mbuf, 100);
        assert_eq!(out.newly_buffered, 1);
        assert_eq!(out.cap_dropped, 0);
        assert!(out.mbuf_ref_retained);
        // Two entries: original [100..106) and new tail slice
        // [106..107) — no coalescing across mbuf-backed segments.
        assert_eq!(q.len(), 2);
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(q.segments()[0].len, 6);
        assert_eq!(q.segments()[1].seq, 106);
        assert_eq!(q.segments()[1].len, 1);
        std::mem::forget(q);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn insert_spanning_multiple_existing_segments_produces_three_gap_slices() {
        // Bug repro for A6.5 Task 7 C1: insert with payload spanning
        // two existing segments used to skip the tail due to
        // mid-iteration index shifts.
        //
        // This test calls insert with stored_count == 3, which
        // triggers the `(stored_count - 1)` internal refcount bump AND
        // the ReorderQueue Drop impl's per-segment decrement. Both paths
        // deref the mbuf pointer, so we can't use `NonNull::dangling()`
        // here — we back the fake mbuf with a boxed byte buffer that
        // lives longer than `q`. rte_mbuf's refcnt field lives at a
        // small offset (<32 bytes) inside its first cacheline, so 256
        // aligned bytes is plenty for the refcnt_update path. We must
        // declare `fake_mbuf_storage` BEFORE `q` so that `q` drops
        // first and its Drop impl reads from still-live storage.
        let mut fake_mbuf_storage: Box<[u8; 256]> = Box::new([0u8; 256]);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = unsafe {
            std::ptr::NonNull::new_unchecked(
                fake_mbuf_storage.as_mut_ptr() as *mut sys::rte_mbuf,
            )
        };

        let mut q = ReorderQueue::new(10_000);
        // Seed with two disjoint segments at seqs 150 and 200.
        q.insert(150, &[0xaa; 10], fake_mbuf, 0);
        q.insert(200, &[0xbb; 10], fake_mbuf, 32);
        assert_eq!(q.len(), 2);

        // Insert an mbuf-backed payload that covers [100..300), i.e.,
        // wraps both existing segments and has tail beyond them.
        let payload = vec![0xcc; 200]; // 100..300
        let out = q.insert(100, &payload, fake_mbuf, 0);
        // Expected carve: [100..150), [160..200), [210..300) — three
        // gap-slices, each stored as a separate entry. Total new
        // bytes: 50 + 40 + 90 = 180.
        assert_eq!(out.newly_buffered, 180);
        assert_eq!(out.cap_dropped, 0);
        assert!(out.mbuf_ref_retained);
        // 2 seed + 3 new = 5 segments.
        assert_eq!(q.len(), 5);
        // Verify interleaved order by seq.
        let seqs: Vec<u32> = q.segments().iter().map(|s| s.seq).collect();
        assert_eq!(seqs, vec![100, 150, 160, 200, 210]);
        // Verify lens at the newly-inserted indices (0, 2, 4).
        assert_eq!(q.segments()[0].len, 50);
        assert_eq!(q.segments()[2].len, 40);
        assert_eq!(q.segments()[4].len, 90);
        // `q` drops here before `fake_mbuf_storage`, so the Drop impl's
        // refcnt decrements land in valid backing storage.
        drop(q);
        // Suppress unused-mut warning on fake_mbuf_storage; it was
        // written to via the refcnt path.
        let _ = &mut fake_mbuf_storage;
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn insert_fully_covered_by_existing_returns_not_retained() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert(100, &[0u8; 200], fake_mbuf, 0); // covers [100..300)
        // Payload fully covered by existing segment.
        let payload = vec![0xcc; 50]; // [150..200)
        let out = q.insert(150, &payload, fake_mbuf, 0);
        assert_eq!(out.newly_buffered, 0);
        assert!(!out.mbuf_ref_retained);
        std::mem::forget(q);
    }
}
