//! Out-of-order segment reassembly. Spec §7.2 envisions mbuf-chain
//! zero-copy storage; we continue A3's AD-7 copy-based model by holding
//! `Vec<u8>` payloads per OOO segment. See AD-A4-reassembly in the plan
//! header.
//!
//! Insertion is O(N) where N is the number of OOO segments currently
//! buffered (bounded by `recv_buffer_bytes / peer_mss`, typically < 180
//! with a 256 KiB cap and 1460-byte MSS — acceptable under trading
//! workload where OOO is rare to begin with). Merge on insert uses
//! mTCP-style `CanMerge` / `MergeFragments` semantics applied to
//! copy-based `(seq, Vec<u8>)` entries.

use dpdk_net_sys as sys;
use smallvec::SmallVec;

use crate::tcp_seq::{seq_le, seq_lt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OooSegment {
    Bytes(OooBytes),
    MbufRef(OooMbufRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OooBytes {
    pub seq: u32,
    pub payload: Vec<u8>,
}

/// A reassembly-held reference to a range of payload bytes living inside
/// a DPDK mbuf. The reassembly queue holds one refcount per stored
/// `OooMbufRef` — bumped at insert, decremented when the segment leaves
/// the queue (drain / cap-drop / segment-reap). When a single mbuf is
/// carved into N gap-slices, N separate `OooMbufRef` entries reference
/// the same mbuf and the queue holds N refcounts on it; each is
/// decremented independently as the matching segment leaves.
/// Cloning `OooMbufRef` duplicates the raw pointer WITHOUT bumping the
/// refcount; callers must uphold the invariant that a cloned ref
/// either (a) replaces the original in the queue, or (b) is only used
/// for inspection before the original is dropped. `Clone` is kept
/// deliberately for Task 7/8's transitional code (gap-carve +
/// eviction borrows) rather than forcing manual refcount bookkeeping
/// at every ownership move. Task 9 (4d) collapses the enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OooMbufRef {
    pub seq: u32,
    pub mbuf: std::ptr::NonNull<sys::rte_mbuf>,
    pub offset: u16,
    pub len: u16,
}

// MbufRef's raw pointer is not Send/Sync. ReorderQueue is single-
// lcore, so we add the marker impls to satisfy any container
// bounds downstream.
unsafe impl Send for OooMbufRef {}

/// A6.5 Task 4c: drain return element. Carries one unit of refcount
/// ownership transferred from the queue to the caller (the queue's
/// per-segment ref becomes the caller's ref; no refcount op happens
/// inside the drain on the kept path). Caller is responsible for
/// releasing the refcount once the payload window is no longer needed
/// — typically by wrapping the handed-off pointer in a
/// [`crate::mempool::MbufHandle`] whose `Drop` decrements the count
/// at the end of the event-emit window.
///
/// The `(offset, len)` pair describes the payload window within the
/// mbuf's data region: `offset` is bytes from the start of the data
/// area; `len` is the number of payload bytes that were retained past
/// the drain's `rcv_nxt` cursor.
#[derive(Debug)]
pub struct DrainedMbuf {
    pub mbuf: std::ptr::NonNull<sys::rte_mbuf>,
    pub offset: u16,
    pub len: u16,
}

// SAFETY: DrainedMbuf wraps a raw mbuf pointer; engine serializes
// access on one lcore. Matches the `Send` story on `OooMbufRef` /
// `Mbuf` / `Mempool`.
unsafe impl Send for DrainedMbuf {}

impl Drop for DrainedMbuf {
    /// A6.5 Task 8 leak-safety: if a DrainedMbuf is dropped without
    /// being consumed (e.g., via `into_handle()`), release its
    /// refcount handoff. Consuming the handoff into an MbufHandle
    /// disarms this Drop via `std::mem::forget`.
    fn drop(&mut self) {
        // SAFETY: the queue handed this entry exactly one refcount
        // unit at drain time (see `drain_contiguous_from_mbuf`). The
        // pointer remained live across that handoff. If we reach Drop
        // the caller never consumed the entry, so we release that
        // refcount here to keep the accounting balanced.
        unsafe {
            sys::resd_rte_mbuf_refcnt_update(self.mbuf.as_ptr(), -1);
        }
    }
}

impl DrainedMbuf {
    /// A6.5 Task 8: consume the refcount handoff into an MbufHandle
    /// without double-decrement. Intended use:
    /// ```ignore
    /// for d in outcome.drained_mbufs.drain(..) {
    ///     let handle = d.into_handle();
    ///     conn.recv.last_read_mbufs.push(handle);
    /// }
    /// ```
    pub fn into_handle(self) -> crate::mempool::MbufHandle {
        let p = self.mbuf;
        std::mem::forget(self); // disarm Drop
        // SAFETY: the queue handed us one refcount; forget(self) prevents
        // our Drop from dropping it; MbufHandle now owns it.
        unsafe { crate::mempool::MbufHandle::from_raw(p) }
    }
}

impl OooSegment {
    pub fn seq(&self) -> u32 {
        match self {
            OooSegment::Bytes(b) => b.seq,
            OooSegment::MbufRef(m) => m.seq,
        }
    }

    pub fn end_seq(&self) -> u32 {
        match self {
            OooSegment::Bytes(b) => b.seq.wrapping_add(b.payload.len() as u32),
            OooSegment::MbufRef(m) => m.seq.wrapping_add(m.len as u32),
        }
    }

    pub fn len(&self) -> u32 {
        match self {
            OooSegment::Bytes(b) => b.payload.len() as u32,
            OooSegment::MbufRef(m) => m.len as u32,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    /// to calling `insert_mbuf` (via `rte_mbuf_refcnt_update(mbuf, -1)`).
    /// When true, the caller's pre-bump is consumed by the queue; if
    /// the carve produced multiple gap-slices, `insert_mbuf` has
    /// already bumped the refcount internally by `(stored_count - 1)`
    /// so that every stored `OooMbufRef` owns exactly one reference.
    /// The field is set to `false` by the legacy `insert` (Bytes-variant)
    /// path, since that path does not involve refcount handoff.
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

    /// Insert a new OOO segment. Merges with neighbours where ranges
    /// overlap or touch; drops payload past `cap`. Returns an outcome
    /// summary that the caller feeds into counters.
    pub fn insert(&mut self, seq: u32, payload: &[u8]) -> InsertOutcome {
        if payload.is_empty() {
            return InsertOutcome {
                newly_buffered: 0,
                cap_dropped: 0,
                mbuf_ref_retained: false,
            };
        }
        let incoming_end = seq.wrapping_add(payload.len() as u32);

        // Carve the incoming payload into gap-slices that don't overlap
        // any existing segment. Each gap-slice is then inserted and
        // merged with its neighbours.
        let mut cursor = seq;
        let mut newly_buffered = 0u32;
        let mut cap_dropped = 0u32;
        let mut to_insert: Vec<(u32, Vec<u8>)> = Vec::new();

        for existing in &self.segments {
            if seq_le(incoming_end, existing.seq()) {
                break;
            }
            if seq_le(existing.end_seq(), cursor) {
                continue;
            }
            if seq_lt(cursor, existing.seq()) {
                let gap_len = existing.seq().wrapping_sub(cursor) as usize;
                let off = cursor.wrapping_sub(seq) as usize;
                let take_end = off + gap_len.min(payload.len() - off);
                let remaining_cap = self.cap.saturating_sub(self.total_bytes + newly_buffered);
                let take = (take_end - off).min(remaining_cap as usize);
                if take > 0 {
                    to_insert.push((cursor, payload[off..off + take].to_vec()));
                    newly_buffered += take as u32;
                }
                if take < take_end - off {
                    cap_dropped += (take_end - off - take) as u32;
                }
                cursor = cursor.wrapping_add((take_end - off) as u32);
            }
            if seq_lt(cursor, existing.end_seq()) {
                cursor = existing.end_seq();
            }
        }

        if seq_lt(cursor, incoming_end) {
            let off = cursor.wrapping_sub(seq) as usize;
            let tail_len = payload.len() - off;
            let remaining_cap = self.cap.saturating_sub(self.total_bytes + newly_buffered);
            let take = tail_len.min(remaining_cap as usize);
            if take > 0 {
                to_insert.push((cursor, payload[off..off + take].to_vec()));
                newly_buffered += take as u32;
            }
            if take < tail_len {
                cap_dropped += (tail_len - take) as u32;
            }
        }

        for (s, p) in to_insert {
            self.insert_merged(s, p);
        }

        self.total_bytes += newly_buffered;
        InsertOutcome {
            newly_buffered,
            cap_dropped,
            mbuf_ref_retained: false,
        }
    }

    /// Insert `(seq, payload)` which is guaranteed not to overlap any
    /// existing segment. Merges on touch (adjacent ranges coalesce).
    fn insert_merged(&mut self, seq: u32, payload: Vec<u8>) {
        let end = seq.wrapping_add(payload.len() as u32);

        let mut idx = self.segments.len();
        for (i, s) in self.segments.iter().enumerate() {
            if seq_lt(seq, s.seq()) {
                idx = i;
                break;
            }
        }

        let mut merged_left = false;
        if idx > 0 && self.segments[idx - 1].end_seq() == seq {
            match &mut self.segments[idx - 1] {
                OooSegment::Bytes(b) => {
                    b.payload.extend_from_slice(&payload);
                    merged_left = true;
                }
                OooSegment::MbufRef(_) => {
                    // Cross-variant merge not supported; fall through to insert.
                    // Task 4a's MbufRef variant is unreachable so this arm is dead
                    // until Task 7. Guarded here to avoid a cross-variant merge
                    // bug when 4b lands.
                }
            }
        }

        if idx < self.segments.len() && self.segments[idx].seq() == end {
            if merged_left {
                // Merge right into (idx-1). Only works Bytes+Bytes.
                let right = self.segments.remove(idx);
                match (&mut self.segments[idx - 1], right) {
                    (OooSegment::Bytes(left_b), OooSegment::Bytes(right_b)) => {
                        left_b.payload.extend_from_slice(&right_b.payload);
                    }
                    (_, right) => {
                        // Cross-variant: restore right and skip merge.
                        self.segments.insert(idx, right);
                    }
                }
            } else {
                match &mut self.segments[idx] {
                    OooSegment::Bytes(right_b) => {
                        let mut new_payload = payload;
                        new_payload.extend_from_slice(&right_b.payload);
                        right_b.seq = seq;
                        right_b.payload = new_payload;
                    }
                    OooSegment::MbufRef(_) => {
                        // Cross-variant: insert as new Bytes entry.
                        self.segments
                            .insert(idx, OooSegment::Bytes(OooBytes { seq, payload }));
                    }
                }
            }
        } else if !merged_left {
            self.segments
                .insert(idx, OooSegment::Bytes(OooBytes { seq, payload }));
        }
    }

    /// A6.5 Task 4b: insert a range of payload bytes as `MbufRef` entries,
    /// referencing the supplied mbuf with offset/length. Caller MUST have
    /// bumped the mbuf refcount by 1 before calling; the queue holds one
    /// ref for every stored segment and, when a carve produces multiple
    /// gap-slices, bumps the refcount internally by `(stored_count - 1)`
    /// to match. Returns `mbuf_ref_retained = true` iff at least one
    /// gap-slice was actually stored; otherwise caller should roll back
    /// the up-bump.
    ///
    /// Gap-slice carve preserves the same overlap / merge semantics as
    /// the Bytes-variant `insert`, but produces `OooSegment::MbufRef`
    /// entries for gap-slice stores. Adjacent MbufRef entries do NOT
    /// coalesce (that would require concatenating payload which is
    /// impossible with mbuf refs); they stay as separate seq-sorted
    /// entries. Cross-variant adjacency (Bytes <-> MbufRef) also does
    /// not merge.
    pub fn insert_mbuf(
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
        // `(cursor_seq, sub_offset, take_len)` triples while scanning the
        // existing segments with an immutable borrow; apply the actual
        // `insert_merged_mbuf_ref` mutations in a second pass after the
        // scan completes. This mirrors the proven pattern in the legacy
        // `insert` path (see `to_insert: Vec<(u32, Vec<u8>)>` above) and
        // avoids the index-shift bug where mid-iteration inserts caused
        // later existing segments to be skipped. A `SmallVec` keeps the
        // zero-alloc steady state: multi-segment-span reorder is rare and
        // almost always fits within 4 gap-slices; anything larger falls
        // back to one heap alloc on this slow path (gap-filling), which
        // is acceptable.
        let mut to_insert: SmallVec<[(u32, u16, u16); 4]> = SmallVec::new();

        for existing in &self.segments {
            let existing_seq = existing.seq();
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
        // following indices, but we no longer iterate over `self.segments`
        // so the shift is inconsequential — `insert_merged_mbuf_ref`
        // positions each new entry by seq order within the current state
        // of `self.segments`.
        let stored_count = to_insert.len() as u32;
        for (cursor_seq, sub_offset, take_len) in to_insert {
            self.insert_merged_mbuf_ref(cursor_seq, mbuf, sub_offset, take_len);
        }

        self.total_bytes += newly_buffered;
        // Caller bumped the refcount by +1 pre-call. The queue needs one
        // ref per stored segment. If the carve produced >1 stored entries,
        // bump the refcount by `(stored_count - 1)` to cover the extras.
        // Each `drop_segment_mbuf_ref` call will eventually decrement once
        // per stored segment, returning the refcount to its caller-side
        // baseline when the last segment leaves.
        if stored_count > 1 {
            let extra = (stored_count - 1) as i16;
            // SAFETY: the caller asserts that `mbuf` is a live pointer and
            // that its refcount has been bumped to at least 1 prior to
            // calling. We are bumping by a positive delta here, which is
            // always safe.
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

    /// Insert a MbufRef segment at seq/len. Caller has already carved out
    /// overlap upstream. Adjacent MbufRef entries do NOT physically
    /// merge (zero-copy contract: no payload concatenation); they stay
    /// as separate seq-sorted entries.
    fn insert_merged_mbuf_ref(
        &mut self,
        seq: u32,
        mbuf: std::ptr::NonNull<sys::rte_mbuf>,
        offset: u16,
        len: u16,
    ) {
        let mut idx = self.segments.len();
        for (i, s) in self.segments.iter().enumerate() {
            if seq_lt(seq, s.seq()) {
                idx = i;
                break;
            }
        }
        self.segments.insert(
            idx,
            OooSegment::MbufRef(OooMbufRef {
                seq,
                mbuf,
                offset,
                len,
            }),
        );
    }

    /// A6.5 Task 4b: drop the mbuf refcount held for an `OooSegment` that
    /// is leaving the queue (drain, stale-drop). No-op for the Bytes
    /// variant. SAFETY: caller guarantees `seg`'s mbuf pointer is still
    /// valid, which holds as long as the queue's stored refcount has not
    /// been decremented — this helper IS the decrement, so it runs at
    /// most once per stored segment.
    fn drop_segment_mbuf_ref(seg: &OooSegment) {
        if let OooSegment::MbufRef(m) = seg {
            // SAFETY: `m.mbuf` was validated at `insert_mbuf` time; the
            // queue has held a refcount on it since then, so the pointer
            // is still live. The decrement may take the refcount to zero
            // and return the mbuf to its mempool, which is the intended
            // end-of-life behavior.
            unsafe {
                sys::shim_rte_mbuf_refcnt_update(m.mbuf.as_ptr(), -1);
            }
        }
    }

    /// A6.5 Task 4c: zero-copy drain. Pop the contiguous prefix of
    /// segments whose seq range starts at or before `rcv_nxt`. Returns
    /// a `SmallVec` of `DrainedMbuf` refs; each entry transfers one
    /// refcount from the queue to the caller (the queue's ref becomes
    /// the caller's ref — no refcount bump or decrement happens inside
    /// this function on the kept path; only stale segments fully
    /// behind `rcv_nxt` decrement via `drop_segment_mbuf_ref`).
    ///
    /// Panics if a stored segment is the legacy `Bytes` variant — the
    /// `Bytes` path is retired in Task 4d. Task 4c requires every
    /// drain-producing path to go through `insert_mbuf`, which produces
    /// `MbufRef` entries exclusively.
    pub fn drain_contiguous_from_mbuf(
        &mut self,
        mut rcv_nxt: u32,
    ) -> SmallVec<[DrainedMbuf; 4]> {
        let mut out: SmallVec<[DrainedMbuf; 4]> = SmallVec::new();

        while !self.segments.is_empty() {
            let seg_seq = self.segments[0].seq();
            if seq_lt(rcv_nxt, seg_seq) {
                break;
            }
            let seg_end = self.segments[0].end_seq();
            let seg_len = self.segments[0].len();
            if seq_le(seg_end, rcv_nxt) {
                // Entire segment behind rcv_nxt — drop. MbufRef variant
                // also requires a refcount decrement; Bytes is a no-op.
                Self::drop_segment_mbuf_ref(&self.segments[0]);
                self.total_bytes = self.total_bytes.saturating_sub(seg_len);
                self.segments.remove(0);
                continue;
            }
            let skip = rcv_nxt.wrapping_sub(seg_seq) as u16;
            let seg = self.segments.remove(0);
            self.total_bytes = self.total_bytes.saturating_sub(seg_len);
            match seg {
                OooSegment::MbufRef(m) => {
                    // Refcount handoff: queue's ref becomes caller's
                    // ref. No refcount op here.
                    out.push(DrainedMbuf {
                        mbuf: m.mbuf,
                        offset: m.offset + skip,
                        len: m.len - skip,
                    });
                }
                OooSegment::Bytes(_b) => {
                    // The Bytes variant is still produced by the legacy
                    // `insert()` path used by tcp_reassembly unit tests;
                    // all engine-reachable drain paths go through
                    // `insert_mbuf()` in Task 4b, which produces
                    // `MbufRef` exclusively. Task 4d removes the Bytes
                    // variant entirely. Panic here surfaces any
                    // unexpected Bytes straggler in the drain path.
                    panic!(
                        "drain_contiguous_from_mbuf reached Bytes variant; \
                         Task 4d not yet applied"
                    );
                }
            }
            rcv_nxt = seg_end;
        }
        out
    }
}

impl Drop for ReorderQueue {
    /// A6.5 Task 7 fix (C3): decrement mbuf refcount on every stored
    /// `OooMbufRef` segment when the queue is dropped. Prevents refcount
    /// leaks when a `TcpConn` is dropped mid-reassembly (RST, reaper,
    /// force-close) with OOO segments still queued.
    fn drop(&mut self) {
        for seg in &self.segments {
            Self::drop_segment_mbuf_ref(seg);
        }
    }
}

/// Test helper: project an `OooSegment` back to its `OooBytes`
/// variant, panicking if it's the MbufRef variant. Only the Bytes
/// variant is reachable in Task 6 (4a); Task 7 (4b) flips the
/// insert path.
#[cfg(test)]
pub(crate) fn expect_bytes(seg: &OooSegment) -> &OooBytes {
    match seg {
        OooSegment::Bytes(b) => b,
        _ => panic!("expected Bytes variant, got {:?}", seg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queue_is_empty() {
        let q = ReorderQueue::new(1024);
        assert!(q.is_empty());
        assert_eq!(q.total_bytes(), 0);
    }

    #[test]
    fn single_insert_buffers_payload() {
        let mut q = ReorderQueue::new(1024);
        let out = q.insert(100, b"abcde");
        assert_eq!(out.newly_buffered, 5);
        assert_eq!(out.cap_dropped, 0);
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq(), 100);
        assert_eq!(&expect_bytes(&q.segments()[0]).payload, b"abcde");
    }

    #[test]
    fn two_disjoint_inserts_stay_separate() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"aaa");
        q.insert(200, b"bbb");
        assert_eq!(q.len(), 2);
        assert_eq!(q.total_bytes(), 6);
    }

    #[test]
    fn inserts_sort_by_seq_even_if_arrival_order_reverses() {
        let mut q = ReorderQueue::new(1024);
        q.insert(200, b"bbb");
        q.insert(100, b"aaa");
        assert_eq!(q.segments()[0].seq(), 100);
        assert_eq!(q.segments()[1].seq(), 200);
    }

    #[test]
    fn adjacent_inserts_merge_into_one() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abc");
        q.insert(103, b"def");
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq(), 100);
        assert_eq!(&expect_bytes(&q.segments()[0]).payload, b"abcdef");
    }

    #[test]
    fn adjacent_insert_collapses_both_sides() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"aaa");
        q.insert(106, b"ccc");
        q.insert(103, b"bbb");
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq(), 100);
        assert_eq!(&expect_bytes(&q.segments()[0]).payload, b"aaabbbccc");
    }

    #[test]
    fn overlap_with_existing_is_deduplicated() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abcdef");
        // Existing range: [100..106). Retransmit: [103..107).
        // Overlap: [103..106). New: [106..107) — one byte.
        let out = q.insert(103, b"defg");
        assert_eq!(out.newly_buffered, 1);
        assert_eq!(out.cap_dropped, 0);
        assert_eq!(q.len(), 1);
        assert_eq!(&expect_bytes(&q.segments()[0]).payload, b"abcdefg");
    }

    #[test]
    fn cap_truncates_excess_and_reports_drop() {
        let mut q = ReorderQueue::new(4);
        let out = q.insert(100, b"abcdef");
        assert_eq!(out.newly_buffered, 4);
        assert_eq!(out.cap_dropped, 2);
        assert_eq!(&expect_bytes(&q.segments()[0]).payload, b"abcd");
    }

    #[test]
    fn empty_payload_insert_is_noop() {
        let mut q = ReorderQueue::new(1024);
        let out = q.insert(100, b"");
        assert_eq!(out.newly_buffered, 0);
        assert!(q.is_empty());
    }

    // A6.5 Task 4c: `drain_contiguous_from_mbuf` unit tests. These tests
    // exercise drain logic with MbufRef-variant segments only (the Bytes
    // variant is retired from the drain path in Task 4c; panics on Bytes
    // are caught here). Structural assertions only — the payload window
    // `(offset, len)` is checked without dereferencing the fake mbuf
    // pointer (which would be UB on `NonNull::dangling()`). Real-mbuf
    // lifecycle is covered by the TAP integration tests + ahw_smoke.
    //
    // As with the `insert_mbuf_*` tests below, tests that store an
    // `MbufRef` entry backed by `NonNull::dangling()` call
    // `std::mem::forget(q)` at the end to bypass the `Drop` impl (which
    // would decrement the refcount and thus deref the dangling pointer).

    #[test]
    fn drain_mbuf_with_no_contiguous_front_returns_empty() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert_mbuf(200, b"zzz", fake_mbuf, 64);
        let drained = q.drain_contiguous_from_mbuf(100);
        assert!(drained.is_empty());
        assert_eq!(q.len(), 1);
        std::mem::forget(q);
    }

    #[test]
    fn drain_mbuf_single_adjacent_segment() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert_mbuf(100, b"abc", fake_mbuf, 64);
        let drained = q.drain_contiguous_from_mbuf(100);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].offset, 64);
        assert_eq!(drained[0].len, 3);
        assert!(q.is_empty());
        assert_eq!(q.total_bytes(), 0);
        // Refcount handoff: drain transferred one ref to the caller.
        // Forget `drained` so the caller's side of the handoff doesn't
        // try to decrement; forget `q` so the Drop impl (which now has
        // no segments) is a no-op. std::mem::forget on the SmallVec is
        // safe because DrainedMbuf holds no owned resources itself.
        std::mem::forget(drained);
    }

    #[test]
    fn drain_mbuf_stops_at_gap() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert_mbuf(100, b"aaa", fake_mbuf, 10);
        q.insert_mbuf(200, b"zzz", fake_mbuf, 20);
        let drained = q.drain_contiguous_from_mbuf(100);
        // Only the seq-100 entry drains; there's a gap [103, 200).
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].offset, 10);
        assert_eq!(drained[0].len, 3);
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq(), 200);
        std::mem::forget(drained);
        // One MbufRef still in the queue; skip Drop to avoid UB deref.
        std::mem::forget(q);
    }

    #[test]
    fn drain_mbuf_chains_through_touching_segments() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        // Adjacent MbufRef entries do NOT coalesce on insert (zero-copy
        // contract), but DO drain together when rcv_nxt matches each
        // one's start seq in turn.
        q.insert_mbuf(100, b"aaa", fake_mbuf, 10);
        q.insert_mbuf(103, b"bbb", fake_mbuf, 20);
        q.insert_mbuf(200, b"zzz", fake_mbuf, 30);
        let drained = q.drain_contiguous_from_mbuf(100);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].offset, 10);
        assert_eq!(drained[0].len, 3);
        assert_eq!(drained[1].offset, 20);
        assert_eq!(drained[1].len, 3);
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq(), 200);
        std::mem::forget(drained);
        std::mem::forget(q);
    }

    #[test]
    fn drain_mbuf_with_rcv_nxt_inside_segment_skips_prefix() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert_mbuf(100, b"abcdef", fake_mbuf, 50);
        let drained = q.drain_contiguous_from_mbuf(103);
        assert_eq!(drained.len(), 1);
        // skip = 3; offset bumps from 50 → 53; len shrinks from 6 → 3.
        assert_eq!(drained[0].offset, 53);
        assert_eq!(drained[0].len, 3);
        std::mem::forget(drained);
    }

    #[test]
    fn drain_mbuf_past_end_of_segment_drops_entirely() {
        // When rcv_nxt is past the segment's end, the segment is stale
        // and dropped via drop_segment_mbuf_ref — that call would deref
        // the mbuf pointer to decrement the refcount. Use a real backing
        // storage so the deref lands in valid memory (pattern mirrored
        // from `insert_mbuf_spanning_multiple_existing_segments_...`).
        let mut fake_mbuf_storage: Box<[u8; 256]> = Box::new([0u8; 256]);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = unsafe {
            std::ptr::NonNull::new_unchecked(
                fake_mbuf_storage.as_mut_ptr() as *mut sys::rte_mbuf,
            )
        };
        let mut q = ReorderQueue::new(1024);
        q.insert_mbuf(100, b"abc", fake_mbuf, 10);
        let drained = q.drain_contiguous_from_mbuf(200);
        // Stale segment dropped (behind rcv_nxt), nothing handed off.
        assert!(drained.is_empty());
        assert!(q.is_empty());
        drop(q);
        // Force a read of the mutable binding so the compiler knows
        // the storage was used; `_` suppresses the warning.
        let _ = &mut fake_mbuf_storage;
    }

    #[test]
    fn drain_mbuf_empty_queue_is_noop() {
        let mut q = ReorderQueue::new(1024);
        let drained = q.drain_contiguous_from_mbuf(500);
        assert!(drained.is_empty());
    }

    #[test]
    #[should_panic(expected = "Bytes variant")]
    fn drain_mbuf_panics_on_bytes_variant() {
        // Task 4c contract: the drain rejects any straggler Bytes
        // segments. The legacy `insert` path (Bytes variant) is used
        // only in A6.5 Task 6/7 unit tests that don't drain; any caller
        // reaching drain with a Bytes entry has bypassed the MbufRef
        // conversion and is a bug. Task 4d removes the Bytes variant
        // entirely.
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abc");
        let _drained = q.drain_contiguous_from_mbuf(100);
    }

    // A6.5 Task 4b (Task 7): insert_mbuf unit tests. These tests exercise
    // insert logic only — they do NOT call drain (which would deref the
    // dangling pointer). The TAP integration tests + ahw_smoke exercise
    // the full real-mbuf lifecycle. SAFETY: A6.5 Task 7's Drop impl on
    // ReorderQueue would deref MbufRef pointers at queue drop, so every
    // test below that stores an MbufRef entry backed by
    // `NonNull::dangling()` calls `std::mem::forget(q)` at the end to
    // bypass the Drop impl. Refcount-decrement bookkeeping is exercised
    // via the TAP integration tests with real mbufs.

    #[test]
    fn insert_mbuf_produces_mbuf_ref_variant() {
        let mut q = ReorderQueue::new(1024);
        // SAFETY: test-only; insert_mbuf only stores the pointer, does not
        // deref. See module-level comment above about Drop safety.
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        let payload = b"hello";
        let out = q.insert_mbuf(100, payload, fake_mbuf, 64);
        assert_eq!(out.newly_buffered, payload.len() as u32);
        assert_eq!(out.cap_dropped, 0);
        assert!(out.mbuf_ref_retained);
        assert_eq!(q.len(), 1);
        match &q.segments()[0] {
            OooSegment::MbufRef(m) => {
                assert_eq!(m.seq, 100);
                assert_eq!(m.offset, 64);
                assert_eq!(m.len, 5);
            }
            _ => panic!("expected MbufRef variant"),
        }
        // Skip Drop to avoid UB deref on the fake mbuf pointer.
        std::mem::forget(q);
    }

    #[test]
    fn insert_mbuf_cap_overflow_signals_no_retained_ref() {
        let mut q = ReorderQueue::new(3);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        let payload = b"hello";
        let out = q.insert_mbuf(100, payload, fake_mbuf, 0);
        assert_eq!(out.newly_buffered, 3);
        assert_eq!(out.cap_dropped, 2);
        assert!(out.mbuf_ref_retained);

        let mut q2 = ReorderQueue::new(0);
        let out2 = q2.insert_mbuf(100, payload, fake_mbuf, 0);
        assert_eq!(out2.newly_buffered, 0);
        assert_eq!(out2.cap_dropped, 5);
        assert!(!out2.mbuf_ref_retained);
        // q stored 1 MbufRef entry; skip Drop to avoid UB deref.
        std::mem::forget(q);
        // q2 stored nothing (cap=0 dropped it), but forget anyway for
        // consistency.
        std::mem::forget(q2);
    }

    #[test]
    fn insert_mbuf_empty_payload_returns_not_retained() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        let out = q.insert_mbuf(100, b"", fake_mbuf, 0);
        assert_eq!(out.newly_buffered, 0);
        assert_eq!(out.cap_dropped, 0);
        assert!(!out.mbuf_ref_retained);
        assert_eq!(q.len(), 0);
        // No MbufRef entries stored, Drop would be a no-op. forget() is
        // not strictly required but is kept for consistency across
        // dangling-pointer tests.
        std::mem::forget(q);
    }

    #[test]
    fn insert_mbuf_inserts_sort_by_seq() {
        let mut q = ReorderQueue::new(1024);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        q.insert_mbuf(200, b"bbb", fake_mbuf, 100);
        q.insert_mbuf(100, b"aaa", fake_mbuf, 200);
        assert_eq!(q.segments()[0].seq(), 100);
        assert_eq!(q.segments()[1].seq(), 200);
        // MbufRef entries do NOT coalesce even when adjacent (zero-copy
        // contract: no payload concatenation).
        q.insert_mbuf(103, b"ccc", fake_mbuf, 300);
        assert_eq!(q.len(), 3);
        assert_eq!(q.segments()[0].seq(), 100);
        assert_eq!(q.segments()[1].seq(), 103);
        assert_eq!(q.segments()[2].seq(), 200);
        // Skip Drop: queue holds 3 MbufRef entries backed by a fake ptr.
        std::mem::forget(q);
    }

    #[test]
    fn insert_mbuf_spanning_multiple_existing_segments_produces_three_gap_slices() {
        // Bug repro for A6.5 Task 7 C1: insert_mbuf with payload spanning
        // two existing Bytes segments used to skip the tail due to
        // mid-iteration index shifts.
        //
        // This test calls insert_mbuf with stored_count == 3, which
        // triggers the `(stored_count - 1)` internal refcount bump AND
        // the ReorderQueue Drop impl's per-segment decrement. Both paths
        // deref the mbuf pointer, so we can't use `NonNull::dangling()`
        // here — we back the fake mbuf with a boxed byte buffer that
        // lives longer than `q`. rte_mbuf's refcnt field lives at a
        // small offset (<32 bytes) inside its first cacheline, so 256
        // aligned bytes is plenty for the refcnt_update path. We must
        // declare `fake_mbuf_storage` BEFORE `q` so that `q` drops first
        // and its Drop impl reads from still-live storage.
        let mut fake_mbuf_storage: Box<[u8; 256]> = Box::new([0u8; 256]);
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = unsafe {
            std::ptr::NonNull::new_unchecked(
                fake_mbuf_storage.as_mut_ptr() as *mut sys::rte_mbuf,
            )
        };

        let mut q = ReorderQueue::new(10_000);
        // Seed with two disjoint Bytes segments at seqs 150 and 200.
        q.insert(150, &[0xaa; 10]);
        q.insert(200, &[0xbb; 10]);
        assert_eq!(q.len(), 2);

        // Insert an mbuf-backed payload that covers [100..300), i.e., wraps
        // both existing segments and has tail beyond them.
        let payload = vec![0xcc; 200]; // 100..300
        let out = q.insert_mbuf(100, &payload, fake_mbuf, 0);
        // Expected carve: [100..150), [160..200), [210..300) — three
        // gap-slices, each stored as a separate MbufRef.
        // Total new bytes: 50 + 40 + 90 = 180.
        assert_eq!(out.newly_buffered, 180);
        assert_eq!(out.cap_dropped, 0);
        assert!(out.mbuf_ref_retained);
        // 2 seed Bytes + 3 new MbufRef = 5 segments.
        assert_eq!(q.len(), 5);
        // Verify interleaved order by seq.
        let seqs: Vec<u32> = q.segments().iter().map(|s| s.seq()).collect();
        assert_eq!(seqs, vec![100, 150, 160, 200, 210]);
        // Verify MbufRef lens.
        assert_eq!(q.segments()[0].len(), 50);
        assert_eq!(q.segments()[2].len(), 40);
        assert_eq!(q.segments()[4].len(), 90);
        // `q` drops here before `fake_mbuf_storage`, so the Drop impl's
        // refcnt decrements land in valid backing storage.
        drop(q);
        // Suppress unused-mut warning on fake_mbuf_storage; it was
        // written to via the refcnt path.
        let _ = &mut fake_mbuf_storage;
    }

    #[test]
    fn insert_mbuf_fully_covered_by_existing_returns_not_retained() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, &[0u8; 200]);  // covers [100..300)
        let fake_mbuf: std::ptr::NonNull<sys::rte_mbuf> = std::ptr::NonNull::dangling();
        // Payload fully covered by existing segment.
        let payload = vec![0xcc; 50]; // [150..200)
        let out = q.insert_mbuf(150, &payload, fake_mbuf, 0);
        assert_eq!(out.newly_buffered, 0);
        assert!(!out.mbuf_ref_retained);
        std::mem::forget(q);
    }
}
