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
///   `now - e.xmit_ts >= RACK.rtt + RACK.reo_wnd` (age expired).
///
/// `rtt_us` maps to `rtt_est.srtt_us().unwrap_or(rack.min_rtt_us)` at
/// the call site — RFC 8985 calls this `RACK.rtt`, but we do not carry
/// a dedicated `rack.rtt_us` field. Arithmetic is done in u64 ns to
/// match sibling `RackState::detect_lost`; u64 ns wraps only every
/// ~584 years so the age check stays sound across any realistic
/// monotonic-clock range (vs. the ~71-min horizon of a u32 µs space).
pub fn rack_mark_losses_on_rto(
    entries: &VecDeque<RetransEntry>,
    snd_una: u32,
    rtt_us: u32,
    reo_wnd_us: u32,
    now_ns: u64,
) -> Vec<u16> {
    let mut out = Vec::new();
    rack_mark_losses_on_rto_into(entries, snd_una, rtt_us, reo_wnd_us, now_ns, &mut out);
    out
}

/// A6.5 Task 10: alloc-free variant of `rack_mark_losses_on_rto`.
/// Appends lost-segment indexes into `out` (caller-provided,
/// typically an Engine-scoped scratch). Kept narrowly scoped: the
/// RTO-fire path is not the steady-state hot path in the A6.5 audit
/// (RTOs are rare-event handlers), but surfacing one-shot Vec allocs
/// here still muddies the "zero per second" property across long
/// runs with occasional RTO backups, so we thread a scratch instead.
pub fn rack_mark_losses_on_rto_into(
    entries: &VecDeque<RetransEntry>,
    snd_una: u32,
    rtt_us: u32,
    reo_wnd_us: u32,
    now_ns: u64,
    out: &mut Vec<u16>,
) {
    for (i, e) in entries.iter().enumerate() {
        if e.sacked || e.lost {
            continue;
        }
        let end_seq = e.seq.wrapping_add(e.len as u32);
        if crate::tcp_seq::seq_le(end_seq, snd_una) {
            // Already cum-ACKed; prune_below will drop it shortly.
            continue;
        }
        if e.seq == snd_una || rto_age_expired(e.xmit_ts_ns, now_ns, rtt_us, reo_wnd_us) {
            out.push(i as u16);
        }
    }
}

/// Pure arithmetic for the §6.3 age clause.
///
/// Returns true iff the entry's age (`now_ns - xmit_ns`) has reached
/// `rtt_us + reo_wnd_us` (both promoted to ns). Uses u64 ns throughout
/// to avoid the u32 µs wrap (~71 min) that previously bit
/// long-lived trading flows via silent dropped age expirations.
/// `saturating_sub` preserves correctness for the (practically
/// impossible but defensible) case where `now_ns < xmit_ns` — the
/// age saturates to 0 and the clause returns false.
#[inline]
pub(crate) fn rto_age_expired(
    xmit_ns: u64,
    now_ns: u64,
    rtt_us: u32,
    reo_wnd_us: u32,
) -> bool {
    let rtt_ns = (rtt_us as u64) * 1_000;
    let reo_ns = (reo_wnd_us as u64) * 1_000;
    let age_ns = now_ns.saturating_sub(xmit_ns);
    age_ns >= rtt_ns + reo_ns
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
            hdrs_len: 0,
        }
    }

    fn deque(v: Vec<RetransEntry>) -> VecDeque<RetransEntry> {
        VecDeque::from(v)
    }

    #[test]
    fn rack_rto_marks_front_entry_at_snd_una() {
        // Front entry (seq == snd_una) is always marked lost regardless
        // of age — §6.3's "fire retrans for the front unacked" clause.
        // xmit_ts_ns=u64::MAX with now_ns=0 means saturating_sub yields
        // 0 age; the front-entry clause still fires regardless.
        let entries = deque(vec![make_entry(100, 50, u64::MAX, false, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 0);
        assert_eq!(lost, vec![0]);
    }

    #[test]
    fn rack_rto_marks_aged_out_entries() {
        // xmit_ts_ns=1_000_000 (1 ms), rtt=50_000 µs, reo_wnd=1_000 µs,
        // now_ns=52_100_000 (52.1 ms) → age_ns=51_100_000, threshold_ns
        // = 51_000_000 → age >= threshold → lost. snd_una differs from
        // entry.seq to isolate the age clause.
        let entries = deque(vec![make_entry(100, 50, 1_000_000, false, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 50, 50_000, 1_000, 52_100_000);
        assert_eq!(lost, vec![0]);
    }

    #[test]
    fn rack_rto_skips_sacked_entries() {
        // Sacked entry — skipped even at seq == snd_una and ancient age.
        let entries = deque(vec![make_entry(100, 50, 0, true, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 1_000_000_000);
        assert!(lost.is_empty());
    }

    #[test]
    fn rack_rto_skips_already_lost_entries() {
        // Already-lost entry — skipped so we don't double-mark.
        let entries = deque(vec![make_entry(100, 50, 0, false, true)]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 1_000_000_000);
        assert!(lost.is_empty());
    }

    #[test]
    fn rack_rto_skips_cum_acked_entries() {
        // Entry range is [100, 150); snd_una=200 has advanced past 150.
        // Not in flight — prune_below handles it; helper must not touch.
        let entries = deque(vec![make_entry(100, 50, 0, false, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 200, 50_000, 1_000, 1_000_000_000);
        assert!(lost.is_empty());
    }

    #[test]
    fn rack_rto_multi_segment_marks_all_eligible() {
        // Five back-to-back segments, all unacked, all past the age
        // window (xmit_ts_ns=1 ms, now_ns=1.1 s → age well beyond
        // rtt+reo_wnd=51 ms). All five must be marked; this is the A5
        // fix that stops tail recovery from dribbling one-segment-per-
        // ACK.
        let entries = deque(vec![
            make_entry(100, 50, 1_000_000, false, false),
            make_entry(150, 50, 1_000_000, false, false),
            make_entry(200, 50, 1_000_000, false, false),
            make_entry(250, 50, 1_000_000, false, false),
            make_entry(300, 50, 1_000_000, false, false),
        ]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 1_100_000_000);
        assert_eq!(lost, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn rack_rto_fresh_entries_not_aged_out_not_marked() {
        // Entry xmitted 1µs ago (xmit_ts_ns=49_999_000, now_ns=
        // 50_000_000) — age_ns=1_000, rtt+reo threshold_ns=51_000_000 →
        // age < threshold. snd_una differs from entry.seq so the
        // front-entry clause is also inert. Must NOT be marked.
        let entries = deque(vec![make_entry(150, 50, 49_999_000, false, false)]);
        let lost = rack_mark_losses_on_rto(&entries, 100, 50_000, 1_000, 50_000_000);
        assert!(lost.is_empty());
    }

    // ---- u32-µs wraparound regression (bug_008) ----

    #[test]
    fn rack_rto_age_expired_across_u32_us_wrap() {
        // bug_008 regression: before the fix, `rack_mark_losses_on_rto`
        // coerced `xmit_ts_ns / 1_000` into u32 µs and used saturating
        // arithmetic to compare against `now_us`. Saturating add clamps
        // at u32::MAX rather than wrapping correctly, so a xmit that
        // lands just before the u32 µs rollover (~2^32 µs ≈ 71m35s) and
        // a `now` that has rolled over would never mark the entry lost
        // — silently breaking RACK RTO tail-loss recovery every ~71
        // minutes. A long-lived trading session (market-data 6.5h+)
        // would hit this several times per day at the worst possible
        // moment.
        //
        // Case A: near-wrap, stuck entry.
        //   xmit_ns = 4_294_000_000_000  (≈ 4_294_000_000 µs, just
        //                                 under 2^32 µs)
        //   now_ns  = 4_295_000_000_000  (age = 1 s)
        //   rtt+reo = 1_250 µs → entry MUST be marked lost.
        //
        // Under the old u32-µs formula, `now_us = 32_704` (wrapped) and
        // `xmit_us + rtt + reo = 4_294_001_250`, which trivially fails
        // the `<=` check → entry silently not marked.
        let entries = deque(vec![make_entry(
            100,
            50,
            4_294_000_000_000,
            false,
            false,
        )]);
        let lost = rack_mark_losses_on_rto(
            &entries,
            50, // snd_una differs from entry.seq — isolate age clause
            1_000, // rtt_us
            250,   // reo_wnd_us
            4_295_000_000_000,
        );
        assert_eq!(
            lost,
            vec![0],
            "age across u32-µs wrap must still be detected",
        );

        // Case B: recent entry (100 µs old), rtt+reo=1_250 µs → NOT
        // expired. Exercises the near-threshold side of the helper.
        let entries = deque(vec![make_entry(
            100,
            50,
            4_295_000_000_000 - 100_000,
            false,
            false,
        )]);
        let lost = rack_mark_losses_on_rto(
            &entries,
            50, // isolate age clause
            1_000,
            250,
            4_295_000_000_000,
        );
        assert!(
            lost.is_empty(),
            "100 µs age must not trip rtt+reo=1250 µs threshold",
        );

        // Case C: clock appears to run backwards (xmit_ns > now_ns).
        // `saturating_sub` → age_ns=0 → NOT expired. Helper must not
        // panic and must not falsely mark the entry lost.
        let entries = deque(vec![make_entry(100, 50, 2_000_000_000, false, false)]);
        let lost = rack_mark_losses_on_rto(
            &entries,
            50, // isolate age clause
            1_000,
            250,
            1_000_000_000,
        );
        assert!(
            lost.is_empty(),
            "now_ns < xmit_ns must saturate to age 0 (not panic)",
        );
    }

    #[test]
    fn rto_age_expired_pure_helper() {
        // Direct coverage for the pure arithmetic helper; mirrors the
        // three cases in rack_rto_age_expired_across_u32_us_wrap but
        // without a retransmit-queue fixture.

        // Case A: 1 s old, 1_250 µs threshold → expired.
        assert!(rto_age_expired(
            4_294_000_000_000,
            4_295_000_000_000,
            1_000,
            250,
        ));

        // Case B: 100 µs old, 1_250 µs threshold → not expired.
        assert!(!rto_age_expired(
            4_295_000_000_000 - 100_000,
            4_295_000_000_000,
            1_000,
            250,
        ));

        // Case C: now before xmit → saturates to 0 age → not expired.
        assert!(!rto_age_expired(2_000_000_000, 1_000_000_000, 1_000, 250));

        // Boundary: age exactly equals threshold → expired (>= in
        // the age clause, matching the inclusive §6.3 encoding).
        assert!(rto_age_expired(0, 1_250_000, 1_000, 250));
    }
}
