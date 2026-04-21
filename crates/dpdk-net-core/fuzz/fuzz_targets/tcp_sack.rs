#![no_main]
use libfuzzer_sys::fuzz_target;
use dpdk_net_core::tcp_options::SackBlock;
use dpdk_net_core::tcp_sack::{SackScoreboard, MAX_SACK_SCOREBOARD_ENTRIES};

// Coverage-guided fuzz of SackScoreboard invariants (pairs with
// tests/proptest_tcp_sack.rs). After each insert of an arbitrary, non-empty,
// non-wrapping `[left, right)` block, the scoreboard must satisfy:
//
//   I1. len() <= MAX_SACK_SCOREBOARD_ENTRIES (4) — fixed-size array.
//   I2. Stored blocks are pairwise disjoint AND non-touching — any touching
//       or overlapping block should have been merged by `insert`. We check
//       all pairs (n <= 4) rather than windows(2) because blocks are stored
//       in arrival order, not sorted by `left`.
fuzz_target!(|data: &[u8]| {
    let mut sb = SackScoreboard::new();
    for chunk in data.chunks_exact(8) {
        let left = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let right = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        // Skip degenerate / wrap-crossing ranges; the proptest also excludes
        // these. Keeps the fuzz target focused on the bounded input space
        // where the scoreboard's wrap-safe comparators reduce to plain order.
        if right <= left {
            continue;
        }
        if (right - left) > 100_000 {
            continue;
        }
        let _ = sb.insert(SackBlock { left, right });

        let snap = sb.blocks();
        assert!(
            snap.len() <= MAX_SACK_SCOREBOARD_ENTRIES,
            "exceeded MAX_SACK_SCOREBOARD_ENTRIES: len={}",
            snap.len(),
        );
        for i in 0..snap.len() {
            for j in (i + 1)..snap.len() {
                let a = snap[i];
                let b = snap[j];
                // Half-open [left, right): disjoint-with-gap means one ends
                // strictly before the other begins, in either order.
                assert!(
                    a.right < b.left || b.right < a.left,
                    "overlap or adjacency between {:?} and {:?}",
                    a,
                    b,
                );
            }
        }
    }
});
