//! Per-conn in-flight-segment tracker. Holds `Mbuf` ref per TX'd-but-unACKed
//! segment; the engine's retransmit primitive allocates a fresh header mbuf
//! from `tx_hdr_mempool` and `rte_pktmbuf_chain()`s it to the held data mbuf.
//!
//! Spec §7.2: `snd_retrans: (seq, mbuf_ref, first_tx_ts)` list. We also
//! carry `len`, `xmit_count`, `sacked`, `lost`, `xmit_ts_ns` for RACK/RTO
//! state (RFC 8985 §6.1 uses xmit_ts).
//!
//! `Mbuf` is a non-owning handle (see mempool.rs) — the engine manages
//! alloc/free/refcnt; `prune_below` returns dropped entries so the engine
//! can decrement refcounts in one place.

use std::collections::VecDeque;

use crate::mempool::Mbuf;
use crate::tcp_options::SackBlock;
use crate::tcp_seq::{seq_le, seq_lt};

pub struct RetransEntry {
    pub seq: u32,
    pub len: u16,
    pub mbuf: Mbuf,
    pub first_tx_ts_ns: u64,
    pub xmit_count: u16,
    pub sacked: bool,
    pub lost: bool,
    /// Last-xmit time (first_tx_ts_ns on first send; updated on retransmit).
    /// RACK uses this as `xmit_ts` per RFC 8985 §6.1 definition.
    pub xmit_ts_ns: u64,
}

#[derive(Default)]
pub struct SendRetrans {
    pub entries: VecDeque<RetransEntry>,
}

impl SendRetrans {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// FlightSize per RFC 8985 §7 — count of unacked, unsacked segments.
    /// TLP's PTO uses this to decide whether to apply the FlightSize==1
    /// +max(WCDelAckT, SRTT/4) penalty (§7.2).
    pub fn flight_size(&self) -> usize {
        self.entries.iter().filter(|e| !e.sacked).count()
    }

    /// Push a newly TX'd segment. Caller must have already incremented the
    /// mbuf refcount so the held ref is valid.
    pub fn push_after_tx(&mut self, entry: RetransEntry) {
        self.entries.push_back(entry);
    }

    /// Drop all entries whose `seq + len` ≤ `snd_una`. Returns dropped entries
    /// so the caller can `refcnt_dec` each mbuf (keeps unsafe ptr work in the engine).
    pub fn prune_below(&mut self, snd_una: u32) -> Vec<RetransEntry> {
        let mut dropped = Vec::new();
        while let Some(front) = self.entries.front() {
            let end_seq = front.seq.wrapping_add(front.len as u32);
            if seq_le(end_seq, snd_una) {
                dropped.push(self.entries.pop_front().unwrap());
            } else {
                break;
            }
        }
        dropped
    }

    /// Mark entries overlapping `block` as sacked. Partial overlap at the
    /// edges is handled conservatively (whole entry marked sacked if any
    /// byte is covered); the precise per-byte tracking is unnecessary since
    /// RACK consumes sacked-or-not, not sacked-ranges.
    pub fn mark_sacked(&mut self, block: SackBlock) {
        for e in &mut self.entries {
            let e_end = e.seq.wrapping_add(e.len as u32);
            // entry overlaps block iff (e.seq < block.right) AND (block.left < e_end)
            if seq_lt(e.seq, block.right) && seq_lt(block.left, e_end) {
                e.sacked = true;
            }
        }
    }

    pub fn front(&self) -> Option<&RetransEntry> {
        self.entries.front()
    }
    pub fn back(&self) -> Option<&RetransEntry> {
        self.entries.back()
    }

    /// Iterate in seq-order for the RACK detect-lost pass.
    pub fn iter_for_rack(&self) -> impl Iterator<Item = &RetransEntry> {
        self.entries.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut RetransEntry> {
        self.entries.iter_mut()
    }

    /// Oldest unacked seq (front entry's `seq`), or None if empty.
    pub fn oldest_unacked_seq(&self) -> Option<u32> {
        self.entries.front().map(|e| e.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::Mbuf;

    fn entry(seq: u32, len: u16, ts: u64) -> RetransEntry {
        RetransEntry {
            seq,
            len,
            mbuf: Mbuf::null_for_test(),
            first_tx_ts_ns: ts,
            xmit_count: 1,
            sacked: false,
            lost: false,
            xmit_ts_ns: ts,
        }
    }

    #[test]
    fn empty_is_empty() {
        let r = SendRetrans::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.oldest_unacked_seq().is_none());
    }

    #[test]
    fn push_grows() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        assert_eq!(r.len(), 1);
        assert_eq!(r.oldest_unacked_seq(), Some(100));
    }

    #[test]
    fn prune_below_drops_fully_acked() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        r.push_after_tx(entry(120, 20, 2));
        let dropped = r.prune_below(120);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].seq, 100);
        assert_eq!(r.len(), 1);
        assert_eq!(r.oldest_unacked_seq(), Some(120));
    }

    #[test]
    fn prune_below_stops_at_first_not_fully_acked() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        r.push_after_tx(entry(120, 20, 2));
        // snd_una = 130 — second entry only partially acked, not removed.
        let dropped = r.prune_below(130);
        assert_eq!(dropped.len(), 1);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn mark_sacked_flags_overlapping_entries() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        r.push_after_tx(entry(120, 20, 2));
        r.push_after_tx(entry(140, 20, 3));
        r.mark_sacked(SackBlock {
            left: 120,
            right: 140,
        });
        let sacked: Vec<_> = r.iter_for_rack().map(|e| e.sacked).collect();
        assert_eq!(sacked, vec![false, true, false]);
    }

    #[test]
    fn mark_sacked_partial_overlap_flags_whole_entry() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        r.mark_sacked(SackBlock {
            left: 105,
            right: 115,
        });
        assert!(r.front().unwrap().sacked);
    }
}
