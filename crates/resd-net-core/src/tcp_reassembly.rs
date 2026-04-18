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

use crate::tcp_seq::{seq_le, seq_lt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OooSegment {
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl OooSegment {
    pub fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(self.payload.len() as u32)
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
}

pub struct ReorderQueue {
    segments: Vec<OooSegment>,
    cap: u32,
    total_bytes: u32,
}

impl ReorderQueue {
    pub fn new(cap: u32) -> Self {
        Self { segments: Vec::new(), cap, total_bytes: 0 }
    }

    pub fn is_empty(&self) -> bool { self.segments.is_empty() }
    pub fn len(&self) -> usize { self.segments.len() }
    pub fn total_bytes(&self) -> u32 { self.total_bytes }
    pub fn segments(&self) -> &[OooSegment] { &self.segments }

    /// Insert a new OOO segment. Merges with neighbours where ranges
    /// overlap or touch; drops payload past `cap`. Returns an outcome
    /// summary that the caller feeds into counters.
    pub fn insert(&mut self, seq: u32, payload: &[u8]) -> InsertOutcome {
        if payload.is_empty() {
            return InsertOutcome { newly_buffered: 0, cap_dropped: 0 };
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
            if seq_le(incoming_end, existing.seq) { break; }
            if seq_le(existing.end_seq(), cursor) { continue; }
            if seq_lt(cursor, existing.seq) {
                let gap_len = existing.seq.wrapping_sub(cursor) as usize;
                let off = cursor.wrapping_sub(seq) as usize;
                let take_end = off + gap_len.min(payload.len() - off);
                let remaining_cap = self.cap.saturating_sub(self.total_bytes + newly_buffered);
                let take = (take_end - off).min(remaining_cap as usize);
                if take > 0 {
                    to_insert.push((cursor, payload[off..off+take].to_vec()));
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
                to_insert.push((cursor, payload[off..off+take].to_vec()));
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
        InsertOutcome { newly_buffered, cap_dropped }
    }

    /// Insert `(seq, payload)` which is guaranteed not to overlap any
    /// existing segment. Merges on touch (adjacent ranges coalesce).
    fn insert_merged(&mut self, seq: u32, payload: Vec<u8>) {
        let end = seq.wrapping_add(payload.len() as u32);

        let mut idx = self.segments.len();
        for (i, s) in self.segments.iter().enumerate() {
            if seq_lt(seq, s.seq) { idx = i; break; }
        }

        let mut merged_left = false;
        if idx > 0 && self.segments[idx - 1].end_seq() == seq {
            self.segments[idx - 1].payload.extend_from_slice(&payload);
            merged_left = true;
        }

        if idx < self.segments.len() && self.segments[idx].seq == end {
            if merged_left {
                let right = self.segments.remove(idx);
                self.segments[idx - 1].payload.extend_from_slice(&right.payload);
            } else {
                let mut new_payload = payload;
                new_payload.extend_from_slice(&self.segments[idx].payload);
                self.segments[idx].seq = seq;
                self.segments[idx].payload = new_payload;
            }
        } else if !merged_left {
            self.segments.insert(idx, OooSegment { seq, payload });
        }
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
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(&q.segments()[0].payload, b"abcde");
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
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(q.segments()[1].seq, 200);
    }

    #[test]
    fn adjacent_inserts_merge_into_one() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abc");
        q.insert(103, b"def");
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(&q.segments()[0].payload, b"abcdef");
    }

    #[test]
    fn adjacent_insert_collapses_both_sides() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"aaa");
        q.insert(106, b"ccc");
        q.insert(103, b"bbb");
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(&q.segments()[0].payload, b"aaabbbccc");
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
        assert_eq!(&q.segments()[0].payload, b"abcdefg");
    }

    #[test]
    fn cap_truncates_excess_and_reports_drop() {
        let mut q = ReorderQueue::new(4);
        let out = q.insert(100, b"abcdef");
        assert_eq!(out.newly_buffered, 4);
        assert_eq!(out.cap_dropped, 2);
        assert_eq!(&q.segments()[0].payload, b"abcd");
    }

    #[test]
    fn empty_payload_insert_is_noop() {
        let mut q = ReorderQueue::new(1024);
        let out = q.insert(100, b"");
        assert_eq!(out.newly_buffered, 0);
        assert!(q.is_empty());
    }
}
