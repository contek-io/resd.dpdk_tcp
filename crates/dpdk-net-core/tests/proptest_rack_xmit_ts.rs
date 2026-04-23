//! RFC 8985 §6.1 RACK-TLP `xmit_ts` properties.
//!
//! # Scope / API note
//!
//! The `xmit_ts` field lives on `RetransEntry` (see `src/tcp_retrans.rs`) and
//! the RACK state rules are embodied by three pure helpers in
//! `src/tcp_rack.rs`:
//!
//!   * `RackState::update_on_ack(entry_xmit_ts_ns, entry_end_seq)` — RFC 8985
//!     §6.1 "update RACK.xmit_ts when a newly-ack'd segment is later than
//!     the current RACK, OR equal with higher end_seq".
//!   * `RackState::detect_lost(entry_xmit_ts_ns, entry_end_seq, now_ns,
//!     reo_wnd_us)` — RFC 8985 §6.2 detect-lost rule.
//!   * `tcp_rack::rack_mark_losses_on_rto(...)` — RFC 8985 §6.3
//!     RACK_mark_losses_on_RTO.
//!
//! All three are pure functions (no clock, no I/O, no hidden state); they
//! are the ideal level to pin the §6.1 contract without synthesizing a
//! full `TcpConn` + parsed-segment + mbuf context.
//!
//! The "xmit_ts bumped forward on retransmit" behavior lives in
//! `engine.rs`:
//!
//! ```text
//!     entry.xmit_count = entry.xmit_count.saturating_add(1);
//!     entry.xmit_ts_ns = crate::clock::now_ns();
//! ```
//!
//! We model that update here as a 1-liner (`retransmit_update(entry, now)`)
//! to drive the monotonicity property over a sequence of retransmits with
//! a monotonically non-decreasing clock — mirroring `crate::clock::now_ns`,
//! which is the CLOCK_MONOTONIC_COARSE source used in the engine hot path.
//!
//! Properties (RFC 8985 §§6.1-6.3):
//!
//!   P1. `xmit_ts` is monotonic across a sequence of retransmit-updates
//!       driven by a monotone clock. Pins the §6.1 "each retransmit bumps
//!       xmit_ts forward" invariant.
//!   P2. `RackState::update_on_ack` is monotone in `RACK.xmit_ts_ns`:
//!       `RACK.xmit_ts_ns` never moves backward under any sequence of
//!       calls. Pins the §6.1 "RACK.xmit_ts tracks the latest transmit
//!       timestamp of any acknowledged segment" rule.
//!   P3. `detect_lost` respects the §6.1 ordering rule: an entry whose
//!       `xmit_ts > RACK.xmit_ts` (i.e. newer than the most-recently-
//!       delivered segment) is NEVER marked lost. This is the exact
//!       "newer by delivery order" guard.
//!   P4. `detect_lost` is idempotent — same args yield the same answer
//!       on repeat calls (no hidden state). Pins the §6.2 rule as pure.
//!   P5. `rack_mark_losses_on_rto` is idempotent — same state yields the
//!       same lost-index list on repeat calls. Pins the §6.3 rule as
//!       pure.

use std::collections::VecDeque;

use dpdk_net_core::mempool::Mbuf;
use dpdk_net_core::tcp_rack::{rack_mark_losses_on_rto, RackState};
use dpdk_net_core::tcp_retrans::RetransEntry;
use proptest::prelude::*;

/// Build a `RetransEntry` for the §6.3 `rack_mark_losses_on_rto` test.
///
/// Integration-test builds don't see `cfg(test)`, so the crate-internal
/// `Mbuf::null_for_test()` isn't visible — `Mbuf::from_ptr(null_mut())`
/// is the public spelling. The entry is never TX'd; the RACK helper
/// reads only `seq`, `len`, `sacked`, `lost`, `xmit_ts_ns` — never
/// dereferences `mbuf`.
fn make_entry(seq: u32, len: u16, xmit_ts_ns: u64, sacked: bool, lost: bool) -> RetransEntry {
    RetransEntry {
        seq,
        len,
        mbuf: Mbuf::from_ptr(std::ptr::null_mut()),
        first_tx_ts_ns: xmit_ts_ns,
        xmit_count: 1,
        sacked,
        lost,
        xmit_ts_ns,
        hdrs_len: 0,
    }
}

/// Model of the `engine.rs` retransmit-update clause (lines ~5206-5208):
///
/// ```text
///     entry.xmit_count = entry.xmit_count.saturating_add(1);
///     entry.xmit_ts_ns = crate::clock::now_ns();
/// ```
///
/// `now_ns` is drawn from CLOCK_MONOTONIC_COARSE, which by construction
/// only moves forward, so every retransmit "bumps xmit_ts forward" in the
/// RFC 8985 §6.1 sense. We model that by threading a monotone `now` here.
fn retransmit_update(entry: &mut RetransEntry, now_ns: u64) {
    entry.xmit_count = entry.xmit_count.saturating_add(1);
    entry.xmit_ts_ns = now_ns;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// P1: `xmit_ts` monotonic across a sequence of retransmits driven by
    /// a monotone clock.
    ///
    /// RFC 8985 §6.1: each retransmission replaces the segment's
    /// `xmit_ts` with the current transmit timestamp. Our engine's
    /// clock source (`CLOCK_MONOTONIC_COARSE`) is non-decreasing, so the
    /// effective invariant is: given a non-decreasing sequence of
    /// `now_ns`, the entry's `xmit_ts_ns` is also non-decreasing after
    /// each retransmit-update.
    ///
    /// We drive this with a sequence of u32 "deltas" summed into a u64
    /// tick stream — the cumulative sum is monotone by construction and
    /// cannot overflow u64 in the 16-step fold (16 * u32::MAX ≈ 6.9e10,
    /// well under 2^64).
    #[test]
    fn xmit_ts_monotonic_across_retransmits(
        initial_ts: u64,
        deltas in prop::collection::vec(0u32..=1_000_000_000_u32, 1..=16),
    ) {
        let mut entry = make_entry(100, 50, initial_ts, false, false);
        let mut prev = entry.xmit_ts_ns;
        let mut now = initial_ts;
        for d in deltas {
            now = now.saturating_add(d as u64);
            retransmit_update(&mut entry, now);
            // The core §6.1 invariant: xmit_ts never moves backward.
            prop_assert!(
                entry.xmit_ts_ns >= prev,
                "xmit_ts went backward: prev={} new={}",
                prev,
                entry.xmit_ts_ns,
            );
            prev = entry.xmit_ts_ns;
        }
        // And xmit_count was bumped once per retransmit (saturating_add
        // means a true retransmit storm past u16::MAX still doesn't
        // panic — a forensic accounting invariant worth pinning).
        prop_assert!(entry.xmit_count >= 1);
    }

    /// P2: `RackState::update_on_ack` is monotone in `RACK.xmit_ts_ns`.
    ///
    /// RFC 8985 §6.1 says `RACK.xmit_ts` is updated only to a strictly
    /// later transmit time (or equal time with a larger end_seq). So
    /// across any sequence of `update_on_ack` calls, `RACK.xmit_ts_ns`
    /// must be non-decreasing.
    ///
    /// We generate arbitrary `(xmit_ts, end_seq)` pairs so half of them
    /// are "older" and should be ignored — pinning the §6.1 newest-wins
    /// rule as a global monotonicity property.
    #[test]
    fn rack_update_on_ack_xmit_ts_monotonic(
        acks in prop::collection::vec((any::<u64>(), any::<u32>()), 0..=16),
    ) {
        let mut rack = RackState::new();
        let mut prev = rack.xmit_ts_ns;
        for (xmit_ts, end_seq) in acks {
            rack.update_on_ack(xmit_ts, end_seq);
            prop_assert!(
                rack.xmit_ts_ns >= prev,
                "RACK.xmit_ts_ns went backward: prev={} new={}",
                prev,
                rack.xmit_ts_ns,
            );
            prev = rack.xmit_ts_ns;
        }
    }

    /// P3: §6.1 ordering rule — an entry with `xmit_ts > RACK.xmit_ts`
    /// (newer than the most-recently-delivered segment) is NEVER marked
    /// lost.
    ///
    /// This is the purest transcription of the §6.1 "newer by delivery
    /// order is not lost" clause. `detect_lost`'s first gate is
    /// `newer_ack_exists = entry.xmit_ts < RACK.xmit_ts || (==, end_seq
    /// older)`; for `entry.xmit_ts > RACK.xmit_ts`, the gate is false
    /// and the function short-circuits to `false` regardless of age or
    /// reo_wnd — which is exactly the property we want.
    #[test]
    fn detect_lost_false_when_entry_newer_than_rack(
        rack_xmit_ts in 0u64..=u64::MAX / 2,
        rack_end_seq: u32,
        forward_delta in 1u64..=1_000_000_000_u64,
        entry_end_seq: u32,
        now_ns: u64,
        reo_wnd_us: u32,
    ) {
        let mut rack = RackState::new();
        rack.update_on_ack(rack_xmit_ts, rack_end_seq);
        // Entry is strictly newer than RACK.xmit_ts — the §6.1 guard.
        let entry_xmit_ts = rack_xmit_ts.saturating_add(forward_delta);
        prop_assert!(
            !rack.detect_lost(entry_xmit_ts, entry_end_seq, now_ns, reo_wnd_us),
            "entry newer than RACK.xmit_ts must not be marked lost: \
             entry_xmit_ts={} rack.xmit_ts={}",
            entry_xmit_ts,
            rack.xmit_ts_ns,
        );
    }

    /// P4: `detect_lost` is idempotent (pure, no hidden state).
    ///
    /// Pins that §6.2's detect-lost rule is a pure function — repeated
    /// application with the same arguments yields the same answer.
    /// Complements P3 by guarding against accidental state mutation on
    /// a read-only helper.
    #[test]
    fn detect_lost_idempotent(
        rack_xmit_ts: u64,
        rack_end_seq: u32,
        entry_xmit_ts: u64,
        entry_end_seq: u32,
        now_ns: u64,
        reo_wnd_us: u32,
    ) {
        let mut rack = RackState::new();
        rack.update_on_ack(rack_xmit_ts, rack_end_seq);
        let a = rack.detect_lost(entry_xmit_ts, entry_end_seq, now_ns, reo_wnd_us);
        let b = rack.detect_lost(entry_xmit_ts, entry_end_seq, now_ns, reo_wnd_us);
        let c = rack.detect_lost(entry_xmit_ts, entry_end_seq, now_ns, reo_wnd_us);
        prop_assert_eq!(a, b);
        prop_assert_eq!(b, c);
    }

    /// P5: `rack_mark_losses_on_rto` is idempotent across a fixed input.
    ///
    /// RFC 8985 §6.3 is a pure function over `(entries, snd_una, rtt,
    /// reo_wnd, now)`; calling it twice on the same state must return
    /// the same index list. We construct a fresh VecDeque each call so
    /// mutable mis-aliasing is ruled out up front.
    ///
    /// `xmit_ts_ns` values are bounded at `u64::MAX / 2` and `now_ns`
    /// held at `u64::MAX / 2` too — the saturating_sub inside
    /// `rto_age_expired` handles any ordering, so the idempotence
    /// property holds regardless of which branch fires.
    #[test]
    fn rack_mark_losses_on_rto_idempotent(
        snd_una: u32,
        rtt_us in 0u32..=u32::MAX / 2,
        reo_wnd_us in 0u32..=u32::MAX / 2,
        now_ns in 0u64..=u64::MAX / 2,
        entries in prop::collection::vec(
            (any::<u32>(), 1u16..=1500, 0u64..=u64::MAX / 2, any::<bool>(), any::<bool>()),
            0..=8,
        ),
    ) {
        // First invocation on a fresh deque.
        let mut deque_a = VecDeque::new();
        for (seq, len, xmit_ts_ns, sacked, lost) in &entries {
            deque_a.push_back(make_entry(*seq, *len, *xmit_ts_ns, *sacked, *lost));
        }
        let a = rack_mark_losses_on_rto(&deque_a, snd_una, rtt_us, reo_wnd_us, now_ns);

        // Second invocation on an equivalent fresh deque.
        let mut deque_b = VecDeque::new();
        for (seq, len, xmit_ts_ns, sacked, lost) in &entries {
            deque_b.push_back(make_entry(*seq, *len, *xmit_ts_ns, *sacked, *lost));
        }
        let b = rack_mark_losses_on_rto(&deque_b, snd_una, rtt_us, reo_wnd_us, now_ns);

        prop_assert_eq!(a, b);
    }

    /// P3 cross-check: `update_on_ack` with a newer entry sets
    /// `RACK.xmit_ts_ns` to exactly that entry's `xmit_ts` — the "RACK
    /// tracks the latest acked xmit" contract.
    ///
    /// Covers the same §6.1 clause P2 does but pins the EXACT value
    /// rather than the one-sided inequality, catching any future
    /// regression that preserves monotonicity while dropping the
    /// equality (e.g. a smoothing pass that averages).
    #[test]
    fn rack_update_on_ack_adopts_newer_xmit_ts(
        initial_xmit_ts in 0u64..=u64::MAX / 2,
        initial_end_seq: u32,
        forward_delta in 1u64..=1_000_000_000_u64,
        new_end_seq: u32,
    ) {
        let mut rack = RackState::new();
        rack.update_on_ack(initial_xmit_ts, initial_end_seq);
        let new_xmit_ts = initial_xmit_ts.saturating_add(forward_delta);
        rack.update_on_ack(new_xmit_ts, new_end_seq);
        prop_assert_eq!(rack.xmit_ts_ns, new_xmit_ts);
        prop_assert_eq!(rack.end_seq, new_end_seq);
    }
}
