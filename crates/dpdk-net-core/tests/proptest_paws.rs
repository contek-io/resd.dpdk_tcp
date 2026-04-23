//! PAWS (RFC 7323 §5) properties: TS.Recent monotonicity + accept/reject
//! consistency + idempotence under repeated same-input application.
//!
//! # Scope / API note
//!
//! In this crate the PAWS gate is NOT a standalone pure function: it lives
//! inline inside `tcp_input::dispatch()` (see `src/tcp_input.rs` around line
//! 627), where it reads `conn.ts_recent` and the negotiated-TS flag,
//! consults the §5.5 24-day idle-expiry sidecar (`ts_recent_age`), and
//! emits `Outcome { paws_rejected, ts_recent_expired, ... }`. Driving that
//! from a proptest would require synthesizing a full `TcpConn` + parsed-
//! segment + mbuf context per case — essentially a state-machine proptest,
//! which is out of scope for the §5 core rule we want to pin here.
//!
//! Per the A9 Task 11 plan, we take option (b): test the PAWS rule
//! DIRECTLY via the wrap-aware sequence comparator (`tcp_seq::seq_lt`),
//! which is the exact primitive `dispatch()` uses for the PAWS gate
//! (`src/tcp_input.rs`: `crate::tcp_seq::seq_lt(ts_val, conn.ts_recent)`).
//! A tiny local wrapper `paws_accept(ts_recent, ts_val)` mirrors that rule:
//! accept iff NOT `seq_lt(ts_val, ts_recent)`. If the PAWS gate is ever
//! refactored to diverge from this 1-line rule, the local wrapper must be
//! updated in lockstep; the tap tests in `tcp_input.rs`
//! (`paws_drops_segment_with_stale_tsval_and_emits_challenge_ack`,
//! `paws_accepts_fresh_tsval_and_updates_ts_recent`) anchor the full
//! end-to-end contract. The properties below pin the PURE rule.
//!
//! Properties (RFC 7323 §5):
//!
//!   P1. Accept implies not-strictly-less: if `paws_accept(ts_recent, ts)`
//!       holds, then `ts_recent` is NOT strictly after `ts` in 2^31
//!       wrap-safe seq space — i.e. accepted timestamps are monotone in
//!       the same comparator `dispatch()` uses.
//!   P2. Reject is idempotent: repeated calls with the same
//!       (ts_recent, stale_ts) pair always reject. (`paws_accept` is a
//!       pure function with no hidden state, so idempotence falls out of
//!       determinism; we still assert it explicitly to pin the contract.)
//!   P3. Accept is idempotent: same argument pair re-accepts on repeat
//!       calls. Same rationale as P2.
//!   P4. Strictly-older is rejected: if `seq_lt(ts, ts_recent)`, then
//!       `paws_accept` rejects. This is the literal §5 rule.
//!   P5. Equal is accepted (`ts == ts_recent`): §5 rejects only strictly
//!       older; equal is fine. This is the boundary case that "strictly"
//!       in RFC 7323 §5 pins.
//!   P6. Within-window fresh is accepted: for any `ts_recent` and any
//!       forward step `delta in 0..2^31`, `paws_accept(ts_recent,
//!       ts_recent + delta (mod 2^32))` is true — covers the wrap-safe
//!       forward half-window including zero (boundary).
//!   P7. Outside-window stale is rejected: for any `ts_recent` and any
//!       backward step `delta in 1..=2^31`, `paws_accept(ts_recent,
//!       ts_recent - delta (mod 2^32))` is false — covers the wrap-safe
//!       backward half-window including the 2^31 boundary (which is
//!       "strictly less" under the asymmetric-window rule since
//!       `0u32.wrapping_sub(2^31) as i32 == i32::MIN < 0`).
//!
//! Seq-space comparator properties themselves (irreflexive <, le reflexive,
//! asymmetric <, in_window boundary) are covered by `proptest_tcp_seq.rs`.
//! Here we only pin the PAWS rule on top of that comparator.

use dpdk_net_core::tcp_seq::seq_lt;
use proptest::prelude::*;

/// Pure PAWS accept rule (RFC 7323 §5). Mirrors the check at
/// `src/tcp_input.rs`:
/// ```text
///     } else if crate::tcp_seq::seq_lt(ts_val, conn.ts_recent) {
///         return Outcome { paws_rejected: true, ... };
///     }
/// ```
/// Accept iff `ts_val` is NOT strictly less-than `ts_recent` in the 2^31
/// wrap-safe seq comparator. The §5.5 24-day idle-expiry branch is
/// orthogonal (it adopts `ts_val` unconditionally before the compare) and
/// not modeled here — it has its own directed coverage in `tcp_input.rs`.
#[inline]
fn paws_accept(ts_recent: u32, ts_val: u32) -> bool {
    !seq_lt(ts_val, ts_recent)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// P1 + P4 (contrapositive of P1 == P4): accept implies `ts_recent`
    /// is not strictly after `ts_val`. Equivalently: if we accepted,
    /// `seq_lt(ts_val, ts_recent)` must be false.
    #[test]
    fn accept_implies_not_strictly_less(ts_recent: u32, ts_val: u32) {
        if paws_accept(ts_recent, ts_val) {
            prop_assert!(!seq_lt(ts_val, ts_recent));
        }
    }

    /// P2: reject is idempotent. Calling `paws_accept` again on the same
    /// stale pair yields the same (false) answer. Pins determinism /
    /// statelessness of the gate rule.
    #[test]
    fn reject_is_idempotent(ts_recent: u32, ts_val: u32) {
        let a = paws_accept(ts_recent, ts_val);
        let b = paws_accept(ts_recent, ts_val);
        let c = paws_accept(ts_recent, ts_val);
        prop_assert_eq!(a, b);
        prop_assert_eq!(b, c);
    }

    /// P3: accept is idempotent. Dual of P2 — same pair, re-evaluated,
    /// yields the same (true) answer when the rule accepts. The two
    /// properties are functionally the same once P2 holds, but keeping
    /// them separate matches the task statement and makes the contract
    /// explicit for a reader.
    #[test]
    fn accept_is_idempotent_when_accepted(ts_recent: u32, ts_val: u32) {
        if paws_accept(ts_recent, ts_val) {
            prop_assert!(paws_accept(ts_recent, ts_val));
            prop_assert!(paws_accept(ts_recent, ts_val));
        }
    }

    /// P4: strictly-older timestamps are rejected. Direct transcription
    /// of RFC 7323 §5: "If SEG.TSval < TS.Recent, [...] the segment is
    /// not acceptable". `<` here is the wrap-safe seq comparator.
    #[test]
    fn strictly_older_is_rejected(ts_recent: u32, ts_val: u32) {
        if seq_lt(ts_val, ts_recent) {
            prop_assert!(!paws_accept(ts_recent, ts_val));
        }
    }

    /// P5: equal timestamps are accepted. §5 rejects only strictly older;
    /// `ts_val == ts_recent` is fine (retransmits often echo the same
    /// TSval).
    #[test]
    fn equal_is_accepted(ts_recent: u32) {
        prop_assert!(paws_accept(ts_recent, ts_recent));
    }

    /// P6: within the 2^31 forward half-window, everything is accepted.
    /// `delta == 0` covers P5 as a boundary case; `delta == 2^31 - 1` is
    /// the far end of the forward half-window (still "not strictly less"
    /// under the asymmetric-window rule since
    /// `(2^31-1).wrapping_sub(0) as i32 > 0`). Wraps are exercised by
    /// varying `ts_recent` across its full u32 range.
    #[test]
    fn forward_half_window_is_accepted(
        ts_recent: u32,
        delta in 0u32..=0x7FFF_FFFF_u32,
    ) {
        let ts_val = ts_recent.wrapping_add(delta);
        prop_assert!(paws_accept(ts_recent, ts_val));
    }

    /// P7: within the 2^31 backward half-window, everything is rejected.
    /// `delta == 1` is the minimal strictly-older case; `delta == 2^31`
    /// is the boundary where `wrapping_sub` produces `i32::MIN`, which
    /// is `< 0` under the asymmetric-window rule — so `seq_lt` returns
    /// true and PAWS rejects.
    ///
    /// Note the asymmetry with P6: the forward window is `[0, 2^31)`
    /// (inclusive-exclusive) but the backward window is `[1, 2^31]`
    /// (inclusive-inclusive) because `i32::MIN < 0` falls on the
    /// "backward" side of the 2^31 partition per `src/tcp_seq.rs`.
    #[test]
    fn backward_half_window_is_rejected(
        ts_recent: u32,
        delta in 1u32..=0x8000_0000_u32,
    ) {
        let ts_val = ts_recent.wrapping_sub(delta);
        prop_assert!(!paws_accept(ts_recent, ts_val));
    }

    /// Cross-check: `paws_accept` is the boolean negation of `seq_lt`
    /// on the reversed argument order. Pins the 1-line rule directly
    /// against the primitive the in-tree gate uses.
    #[test]
    fn accept_is_exactly_not_seq_lt(ts_recent: u32, ts_val: u32) {
        prop_assert_eq!(paws_accept(ts_recent, ts_val), !seq_lt(ts_val, ts_recent));
    }
}
