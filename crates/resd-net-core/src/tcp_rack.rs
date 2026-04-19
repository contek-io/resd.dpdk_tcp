//! RFC 8985 RACK state + loss detection.
//! Consumed by the Task 15 RACK detect-lost pass in `tcp_input.rs`.

use std::collections::VecDeque;

use crate::tcp_retrans::RetransEntry;

#[derive(Debug, Clone, Default)]
pub struct RackState {
    /// RFC 8985 §6.1 RACK.xmit_ts — latest transmit timestamp of any
    /// acknowledged segment.
    pub xmit_ts_ns: u64,
    /// RFC 8985 §6.1 RACK.end_seq — end-seq of the segment with xmit_ts.
    pub end_seq: u32,
    /// Current reordering window (µs). Updated per-ACK via compute_reo_wnd_us.
    pub reo_wnd_us: u32,
    /// Minimum RTT observed on this conn. 0 until the first sample.
    pub min_rtt_us: u32,
    /// Whether we've observed a DSACK from the peer (RFC 2883). A5 tracks
    /// this for visibility (tcp.rx_dsack); Stage 2 may use it for reo_wnd
    /// adaptation per RFC 8985 §7.
    pub dsack_seen: bool,
}

impl RackState {
    pub fn new() -> Self {
        Self::default()
    }

    /// RFC 8985 §6.1: update RACK.xmit_ts / RACK.end_seq when an ACK newly
    /// covers `entry` such that entry's xmit is later than the current
    /// RACK, OR equal with higher end_seq.
    pub fn update_on_ack(&mut self, entry_xmit_ts_ns: u64, entry_end_seq: u32) {
        if entry_xmit_ts_ns > self.xmit_ts_ns
            || (entry_xmit_ts_ns == self.xmit_ts_ns
                && crate::tcp_seq::seq_lt(self.end_seq, entry_end_seq))
        {
            self.xmit_ts_ns = entry_xmit_ts_ns;
            self.end_seq = entry_end_seq;
        }
    }

    /// Track min RTT seen on this conn. RFC 8985 §6.2 uses this as half
    /// of the reo_wnd upper bound.
    pub fn update_min_rtt(&mut self, rtt_us: u32) {
        if self.min_rtt_us == 0 || rtt_us < self.min_rtt_us {
            self.min_rtt_us = rtt_us;
        }
    }

    /// RFC 8985 §6.2 detect-lost rule for `entry`.
    /// Returns true iff:
    /// - entry.xmit_ts < RACK.xmit_ts (or equal with lower end_seq), AND
    /// - now - entry.xmit_ts > reo_wnd_us.
    pub fn detect_lost(
        &self,
        entry_xmit_ts_ns: u64,
        entry_end_seq: u32,
        now_ns: u64,
        reo_wnd_us: u32,
    ) -> bool {
        let newer_ack_exists = entry_xmit_ts_ns < self.xmit_ts_ns
            || (entry_xmit_ts_ns == self.xmit_ts_ns
                && crate::tcp_seq::seq_lt(entry_end_seq, self.end_seq));
        if !newer_ack_exists {
            return false;
        }
        let age_ns = now_ns.saturating_sub(entry_xmit_ts_ns);
        age_ns > (reo_wnd_us as u64) * 1_000
    }
}

/// Compute reo_wnd per RFC 8985 §6.2.
/// - When `rack_aggressive` is true, returns 0 (per-connect opt).
/// - Otherwise min(SRTT/4, min_rtt/2), floored at 1000µs (1ms) to avoid
///   spurious loss signals when RTTs are sub-millisecond.
pub fn compute_reo_wnd_us(rack_aggressive: bool, min_rtt_us: u32, srtt_us: Option<u32>) -> u32 {
    if rack_aggressive {
        return 0;
    }
    match srtt_us {
        None => (min_rtt_us / 2).max(1_000),
        Some(srtt) => {
            let a = srtt / 4;
            let b = min_rtt_us / 2;
            a.min(b).max(1_000)
        }
    }
}

/// RFC 8985 §6.3 `RACK_mark_losses_on_RTO`. Returns indexes of entries
/// that are newly lost under the §6.3 formula; caller flips the `lost`
/// flag and feeds the list to the retransmit loop.
///
/// An entry `e` is lost iff:
/// - `e` is NOT sacked, NOT already lost, AND still in flight
///   (`e.end_seq > snd_una`), AND
/// - `e.seq == snd_una` (the front entry always retransmits) OR
///   `e.xmit_us + RACK.rtt + RACK.reo_wnd <= now_us` (age expired).
///
/// `rtt_us` maps to `rtt_est.srtt_us().unwrap_or(rack.min_rtt_us)` at
/// the call site — RFC 8985 calls this `RACK.rtt`, but we do not carry
/// a dedicated `rack.rtt_us` field. Saturating arithmetic keeps the
/// age check sound across the monotonic-clock wraparound boundary
/// (u32 µs wraps ~71 min).
pub fn rack_mark_losses_on_rto(
    entries: &VecDeque<RetransEntry>,
    snd_una: u32,
    rtt_us: u32,
    reo_wnd_us: u32,
    now_us: u32,
) -> Vec<u16> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if e.sacked || e.lost {
            continue;
        }
        let end_seq = e.seq.wrapping_add(e.len as u32);
        if crate::tcp_seq::seq_le(end_seq, snd_una) {
            // Already cum-ACKed; prune_below will drop it shortly.
            continue;
        }
        let xmit_us = (e.xmit_ts_ns / 1_000) as u32;
        let age_expired = xmit_us.saturating_add(rtt_us).saturating_add(reo_wnd_us) <= now_us;
        if e.seq == snd_una || age_expired {
            out.push(i as u16);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_on_ack_keeps_newest() {
        let mut r = RackState::new();
        r.update_on_ack(100, 500);
        r.update_on_ack(50, 400); // older xmit — ignored
        assert_eq!((r.xmit_ts_ns, r.end_seq), (100, 500));
        r.update_on_ack(200, 600); // newer xmit — taken
        assert_eq!((r.xmit_ts_ns, r.end_seq), (200, 600));
        r.update_on_ack(200, 700); // same xmit, greater seq — taken
        assert_eq!((r.xmit_ts_ns, r.end_seq), (200, 700));
    }

    #[test]
    fn detect_lost_fires_when_entry_older_and_beyond_reo_wnd() {
        let mut r = RackState::new();
        r.update_on_ack(1_000_000, 600);
        // Entry with xmit_ts=500_000 — older than RACK.xmit_ts=1_000_000.
        // now=2_000_000, reo_wnd_us=500 → age=1_500_000 ns = 1500µs > 500µs.
        assert!(r.detect_lost(500_000, 400, 2_000_000, 500));
    }

    #[test]
    fn detect_lost_false_when_within_reo_wnd() {
        let mut r = RackState::new();
        r.update_on_ack(1_000_000, 600);
        // Entry xmit_ts=500_000, now=1_000_100, reo_wnd_us=500_000 (500ms).
        // age=500_100 ns = 500.1µs << 500_000µs → not lost.
        assert!(!r.detect_lost(500_000, 400, 1_000_100, 500_000));
    }

    #[test]
    fn detect_lost_false_when_no_newer_ack() {
        let mut r = RackState::new();
        r.update_on_ack(500_000, 400);
        // Entry xmit_ts=1_000_000 — newer than RACK.xmit_ts=500_000.
        // No newer-ack-exists → not lost regardless of age.
        assert!(!r.detect_lost(1_000_000, 600, 10_000_000, 1));
    }

    #[test]
    fn aggressive_reo_wnd_is_zero() {
        assert_eq!(compute_reo_wnd_us(true, 100_000, Some(200_000)), 0);
    }

    #[test]
    fn non_aggressive_reo_wnd_min_of_srtt4_and_minrtt2() {
        // srtt/4 = 50_000, min_rtt/2 = 30_000 → min = 30_000.
        assert_eq!(compute_reo_wnd_us(false, 60_000, Some(200_000)), 30_000);
    }

    #[test]
    fn reo_wnd_floored_at_1ms() {
        // Sub-millisecond min_rtt + tiny srtt — floor at 1000µs.
        assert_eq!(compute_reo_wnd_us(false, 100, Some(400)), 1_000);
    }

    #[test]
    fn update_min_rtt_tracks_minimum() {
        let mut r = RackState::new();
        r.update_min_rtt(100);
        assert_eq!(r.min_rtt_us, 100);
        r.update_min_rtt(200); // larger — ignored
        assert_eq!(r.min_rtt_us, 100);
        r.update_min_rtt(50); // smaller — taken
        assert_eq!(r.min_rtt_us, 50);
    }

    // ---- RFC 8985 §6.3 RACK_mark_losses_on_RTO helper tests ----

    /// Build a `RetransEntry` for the pure-helper tests. `xmit_ts_ns`
    /// feeds the age formula; `sacked`/`lost` flags drive the skip
    /// rules. The null `Mbuf` is never dereferenced by the helper.
    fn make_entry(seq: u32, len: u16, xmit_ts_ns: u64, sacked: bool, lost: bool) -> RetransEntry {
        RetransEntry {
            seq,
            len,
            mbuf: crate::mempool::Mbuf::null_for_test(),
            first_tx_ts_ns: xmit_ts_ns,
            xmit_count: 1,
            sacked,
            lost,
            xmit_ts_ns,
        }
    }

    fn deque(v: Vec<RetransEntry>) -> VecDeque<RetransEntry> {
        VecDeque::from(v)
    }

    #[test]
    fn rack_rto_marks_front_entry_at_snd_una() {
        // Front entry (seq == snd_una) is always marked lost regardless
        // of age — §6.3's "fire retrans for the front unacked" clause.
        let entries = deque(vec![make_entry(100, 50, u64::MAX, false, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 0);
        assert_eq!(lost, vec![0]);
    }

    #[test]
    fn rack_rto_marks_aged_out_entries() {
        // xmit_us=1_000 (from xmit_ts_ns=1_000_000 ns), rtt=50_000,
        // reo_wnd=1_000, now=52_100 → 1_000 + 50_000 + 1_000 = 52_000
        // ≤ 52_100 → lost. snd_una differs from entry.seq to isolate
        // the age clause.
        let entries = deque(vec![make_entry(100, 50, 1_000_000, false, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 50, 50_000, 1_000, 52_100);
        assert_eq!(lost, vec![0]);
    }

    #[test]
    fn rack_rto_skips_sacked_entries() {
        // Sacked entry — skipped even at seq == snd_una and ancient age.
        let entries = deque(vec![make_entry(100, 50, 0, true, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 1_000_000);
        assert!(lost.is_empty());
    }

    #[test]
    fn rack_rto_skips_already_lost_entries() {
        // Already-lost entry — skipped so we don't double-mark.
        let entries = deque(vec![make_entry(100, 50, 0, false, true)]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 1_000_000);
        assert!(lost.is_empty());
    }

    #[test]
    fn rack_rto_skips_cum_acked_entries() {
        // Entry range is [100, 150); snd_una=200 has advanced past 150.
        // Not in flight — prune_below handles it; helper must not touch.
        let entries = deque(vec![make_entry(100, 50, 0, false, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 200, 50_000, 1_000, 1_000_000);
        assert!(lost.is_empty());
    }

    #[test]
    fn rack_rto_multi_segment_marks_all_eligible() {
        // Five back-to-back segments, all unacked, all past the age
        // window (xmit_us=1_000, now_us=1_100_000 → age well beyond
        // rtt+reo_wnd). All five must be marked; this is the A5 fix
        // that stops tail recovery from dribbling one-segment-per-ACK.
        let entries = deque(vec![
            make_entry(100, 50, 1_000_000, false, false),
            make_entry(150, 50, 1_000_000, false, false),
            make_entry(200, 50, 1_000_000, false, false),
            make_entry(250, 50, 1_000_000, false, false),
            make_entry(300, 50, 1_000_000, false, false),
        ]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 1_100_000);
        assert_eq!(lost, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn rack_rto_fresh_entries_not_aged_out_not_marked() {
        // Entry xmitted 1µs ago (xmit_us=49_999, now_us=50_000) —
        // age=1, rtt=50_000, reo_wnd=1_000 → 49_999 + 50_000 + 1_000
        // = 100_999, not ≤ 50_000. snd_una differs from entry.seq so
        // the front-entry clause is also inert. Must NOT be marked.
        let entries = deque(vec![make_entry(150, 50, 49_999_000, false, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 50_000);
        assert!(lost.is_empty());
    }
}
