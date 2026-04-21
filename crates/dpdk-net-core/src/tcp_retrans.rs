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

use smallvec::SmallVec;

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
    /// Bytes of L2+L3+TCP header (Ethernet+IPv4+TCP including options) at
    /// the front of `mbuf`'s data region from the original TX. The mbuf
    /// holds the WHOLE on-wire frame (headers || payload) because Stage 1
    /// builds a single contiguous mbuf in `send_bytes`. The retransmit
    /// primitive strips these bytes via `rte_pktmbuf_adj` before chaining
    /// a fresh header mbuf, so the on-wire retrans frame is well-formed
    /// (single L2+L3+TCP header) and `data_len == len` thereafter. Once
    /// stripped (first retrans), this field is set to 0 so subsequent
    /// retrans for the same entry skip the adj.
    pub hdrs_len: u16,
}

#[derive(Default)]
pub struct SendRetrans {
    pub entries: VecDeque<RetransEntry>,
}

impl SendRetrans {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-size variant. Steady-state in-flight is bounded above by
    /// `send_buffer_bytes / mss` (the `send_buf_room` cap inside
    /// `send_bytes`); pre-sizing the VecDeque to that ceiling once at
    /// connection construction eliminates the geometric-doubling
    /// reallocs the audit harness would otherwise observe under
    /// sustained TX (a 256 KiB send buffer at 1460-byte MSS holds
    /// ~180 in-flight segments — without pre-size, push_after_tx
    /// grows the inner Vec at 1, 4, 8, 16, 32, 64, 128, 256 entries,
    /// which surfaces as 8 hot-path allocations during ramp). Slack
    /// in caller-side rounding (next power-of-two) absorbs the
    /// brief overshoot when an ACK lags a push.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(cap),
        }
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
    /// A6.5 Task 4: `SmallVec<[_; 8]>` inline buffer — typical per-ACK
    /// prune count is 1-2, so this is effectively alloc-free.
    ///
    /// A6.5 Task 10: the engine hot path uses
    /// `prune_below_into_mbufs` instead — it drains raw mbuf pointers
    /// into an engine-scoped scratch so the allocation is reused
    /// across polls. `prune_below` is kept for tests and any non-
    /// hot-path caller that prefers the owning-SmallVec ergonomics.
    pub fn prune_below(&mut self, snd_una: u32) -> SmallVec<[RetransEntry; 8]> {
        let mut dropped: SmallVec<[RetransEntry; 8]> = SmallVec::new();
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

    /// Hot-path variant of `prune_below`. Drains the mbuf pointers of
    /// every pruned entry into `out` (the caller's engine-scoped
    /// scratch). The RetransEntry itself is dropped inside this
    /// function, which is safe: `Mbuf` is a pointer-copy with no
    /// Drop, and the caller retains the refcount responsibility by
    /// consuming the pushed pointers.
    ///
    /// Allocation property (A6.5 Task 10 audit): when `out` already
    /// has sufficient heap capacity from prior polls, this routine
    /// performs zero allocations regardless of prune count.
    pub fn prune_below_into_mbufs(
        &mut self,
        snd_una: u32,
        out: &mut SmallVec<[std::ptr::NonNull<dpdk_net_sys::rte_mbuf>; 16]>,
    ) {
        while let Some(front) = self.entries.front() {
            let end_seq = front.seq.wrapping_add(front.len as u32);
            if seq_le(end_seq, snd_una) {
                let e = self.entries.pop_front().unwrap();
                if let Some(p) = std::ptr::NonNull::new(e.mbuf.as_ptr()) {
                    out.push(p);
                }
                drop(e);
            } else {
                break;
            }
        }
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
            hdrs_len: 0,
        }
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn empty_is_empty() {
        let r = SendRetrans::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.oldest_unacked_seq().is_none());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn push_grows() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        assert_eq!(r.len(), 1);
        assert_eq!(r.oldest_unacked_seq(), Some(100));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
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

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
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

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
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

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
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
