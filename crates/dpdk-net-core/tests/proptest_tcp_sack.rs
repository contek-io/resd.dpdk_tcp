//! Properties of the SACK scoreboard (`tcp_sack.rs`, RFC 2018 §3).
//!
//! Invariants held after an arbitrary sequence of `insert` calls:
//!
//!   I1. Capacity is respected: `len() <= MAX_SACK_SCOREBOARD_ENTRIES` (4).
//!       The scoreboard is a fixed-size array; overflow evicts the oldest
//!       block (see AD-A4-sack-scoreboard-size and the `overflow_evicts_oldest`
//!       inline test).
//!
//!   I2. Pairwise blocks are disjoint AND non-touching: `insert` merges any
//!       block that touches-or-overlaps an existing block, and `collapse`
//!       re-runs the merge loop to a fixed point. So for all i != j, the
//!       half-open ranges `[left, right)` must share no point AND not abut.
//!       (Note: this scoreboard does NOT store blocks sorted by `left` — a
//!       disjoint insert is appended at `blocks[count]` in arrival order.
//!       Sortedness is not an invariant, so we do not assert it.)
//!
//!   I3. Coverage is a subset of the input union — no phantom bytes: every
//!       sequence number reported as SACKed by `is_sacked` must lie inside
//!       some input block. (Equality to the input union does NOT hold in
//!       general because overflow can evict blocks; we assert equality only
//!       when the input is small enough to fit.)
//!
//! Input blocks are generated well away from u32 wrap (start in `0..1_000_000`,
//! len in `1..1000`) so the scoreboard's wrap-safe comparators reduce to
//! plain integer order for these test cases. Byte-set sizes stay small: at
//! most 16 blocks × 999 bytes = ~16 kB per case, which keeps the
//! `HashSet<u32>` memory footprint trivial across all 256 cases.

use std::collections::HashSet;

use dpdk_net_core::tcp_options::SackBlock;
use dpdk_net_core::tcp_sack::{SackScoreboard, MAX_SACK_SCOREBOARD_ENTRIES};
use proptest::prelude::*;

/// Arbitrary non-empty, non-wrapping SACK block with bounded byte range.
///
/// `[left, right)` is half-open (matches `is_sacked`: `left <= seq < right`).
fn arb_block() -> impl Strategy<Value = SackBlock> {
    (0u32..1_000_000, 1u32..1000).prop_map(|(start, len)| SackBlock {
        left: start,
        right: start + len, // `start + len <= 1_001_000` — no u32 wrap.
    })
}

/// Build a scoreboard from `blocks` by feeding them in in order.
fn build_scoreboard(blocks: &[SackBlock]) -> SackScoreboard {
    let mut sb = SackScoreboard::new();
    for b in blocks {
        sb.insert(*b);
    }
    sb
}

/// Expand a slice of half-open `[left, right)` ranges into a byte set.
fn expand_to_byte_set(blocks: &[SackBlock]) -> HashSet<u32> {
    let mut set = HashSet::new();
    for b in blocks {
        for s in b.left..b.right {
            set.insert(s);
        }
    }
    set
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// I1. Scoreboard never exceeds its fixed capacity.
    #[test]
    fn capacity_is_bounded(blocks in proptest::collection::vec(arb_block(), 0..16)) {
        let sb = build_scoreboard(&blocks);
        prop_assert!(sb.len() <= MAX_SACK_SCOREBOARD_ENTRIES);
    }

    /// I2. After arbitrary inserts, no two stored blocks overlap OR touch.
    ///     (Touching blocks must have been merged by `insert`.)
    #[test]
    fn no_overlapping_or_touching_blocks(
        blocks in proptest::collection::vec(arb_block(), 0..16),
    ) {
        let sb = build_scoreboard(&blocks);
        let snap: Vec<SackBlock> = sb.blocks().to_vec();
        for i in 0..snap.len() {
            for j in (i + 1)..snap.len() {
                let a = snap[i];
                let b = snap[j];
                // Half-open ranges with no shared point AND no abutment:
                // either `a` ends strictly before `b` begins, or vice versa.
                let disjoint_with_gap = a.right < b.left || b.right < a.left;
                prop_assert!(
                    disjoint_with_gap,
                    "blocks {:?} and {:?} overlap or touch (merge did not fire)",
                    a, b,
                );
            }
        }
    }

    /// I3a. Coverage is a subset of the input union — the scoreboard never
    ///      reports a seq as SACKed unless some input block covered it.
    ///      Holds even when overflow evicts older blocks.
    #[test]
    fn coverage_is_subset_of_input_union(
        blocks in proptest::collection::vec(arb_block(), 0..16),
    ) {
        let sb = build_scoreboard(&blocks);
        let input_union = expand_to_byte_set(&blocks);
        let covered = expand_to_byte_set(sb.blocks());
        prop_assert!(
            covered.is_subset(&input_union),
            "scoreboard covers bytes not present in any input block",
        );
    }

    /// I3b. Coverage equals the input union when no overflow is even
    ///      possible. Eviction fires only when an insert appends a
    ///      fully-disjoint block while `count == MAX`. With at most
    ///      `MAX_SACK_SCOREBOARD_ENTRIES` input blocks total, `count` never
    ///      exceeds the input length, so eviction cannot fire and every
    ///      input byte must remain covered.
    #[test]
    fn no_lost_bytes_when_input_fits(
        blocks in proptest::collection::vec(arb_block(), 0..=MAX_SACK_SCOREBOARD_ENTRIES),
    ) {
        let sb = build_scoreboard(&blocks);
        let input_union = expand_to_byte_set(&blocks);
        let covered = expand_to_byte_set(sb.blocks());
        prop_assert_eq!(
            covered,
            input_union,
            "input-fits run lost bytes (eviction cannot fire here)",
        );
    }
}
