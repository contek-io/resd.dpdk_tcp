//! Per-connection RTT histogram (spec §3.8). 16 × u32 buckets, exactly
//! 64 B / one cacheline via `repr(C, align(64))`. Update cost: 15-
//! comparison ladder + one `wrapping_add` on cache-resident state.
//! No atomics — per-conn state in the single-lcore RTC model.

/// 16 × u32 buckets aligned to exactly one cacheline. Exposed as a
/// field on `TcpConn`; `dpdk_net_conn_rtt_histogram` memcpys the
/// inner `[u32; 16]` out to caller memory (Task 18).
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, Default)]
pub struct RttHistogram {
    pub buckets: [u32; 16],
}

// Pin size + alignment at compile time. A future TcpConn layout change
// cannot silently drop the one-cacheline invariant.
const _: () = {
    use std::mem::{align_of, size_of};
    assert!(size_of::<RttHistogram>() == 64);
    assert!(align_of::<RttHistogram>() == 64);
};

/// Select the bucket index `[0, 15]` for an RTT sample under a given
/// edge set. Linear ladder; at N=16, LLVM is free to lower to either
/// linear or binary search and the branch predictor handles stable
/// distributions effectively for free.
#[inline]
pub fn select_bucket(rtt_us: u32, edges: &[u32; 15]) -> usize {
    for i in 0..15 {
        if rtt_us <= edges[i] {
            return i;
        }
    }
    15
}

impl RttHistogram {
    /// Record one RTT sample. Wraparound via `wrapping_add(1)` is
    /// intentional — the application's snapshot-delta math uses
    /// `wrapping_sub` to recover correct per-bucket counts as long as
    /// no single bucket accumulates > 2^32 samples between polls.
    #[inline]
    pub fn update(&mut self, rtt_us: u32, edges: &[u32; 15]) {
        let b = select_bucket(rtt_us, edges);
        self.buckets[b] = self.buckets[b].wrapping_add(1);
    }

    /// Snapshot the 64-byte bucket array into caller memory. Used by
    /// the `dpdk_net_conn_rtt_histogram` getter (Task 18).
    #[inline]
    pub fn snapshot(&self) -> [u32; 16] {
        self.buckets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_one_cacheline() {
        assert_eq!(std::mem::size_of::<RttHistogram>(), 64);
        assert_eq!(std::mem::align_of::<RttHistogram>(), 64);
    }

    #[test]
    fn select_bucket_default_edges() {
        let edges: [u32; 15] = [
            50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
            10000, 25000, 50000, 100000, 500000,
        ];
        // Spec §3.8.1 expected mapping.
        assert_eq!(select_bucket(10, &edges), 0);
        assert_eq!(select_bucket(50, &edges), 0);
        assert_eq!(select_bucket(75, &edges), 1);
        assert_eq!(select_bucket(150, &edges), 2);
        assert_eq!(select_bucket(1000, &edges), 6);
        assert_eq!(select_bucket(2000, &edges), 7);
        // 30000 > edges[11]=25000, 30000 <= edges[12]=50000 → bucket 12.
        // Spec §7.1 mapping says "11" but the defaults from §3.2 give 12;
        // treating the code's algorithm result against the §3.2 edges as
        // the source of truth for this assertion.
        assert_eq!(select_bucket(30000, &edges), 12);
        assert_eq!(select_bucket(600000, &edges), 15);
    }

    #[test]
    fn update_increments_selected_bucket() {
        let edges: [u32; 15] = [
            50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
            10000, 25000, 50000, 100000, 500000,
        ];
        let mut h = RttHistogram::default();
        h.update(150, &edges);
        h.update(150, &edges);
        assert_eq!(h.buckets[2], 2);
        // All other buckets still zero.
        for i in 0..16 {
            if i != 2 {
                assert_eq!(h.buckets[i], 0, "bucket {i}");
            }
        }
    }

    #[test]
    fn wraparound_via_wrapping_add() {
        let edges: [u32; 15] = [
            50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
            10000, 25000, 50000, 100000, 500000,
        ];
        let mut h = RttHistogram::default();
        // Pre-load to just below u32::MAX, then drive 5 more to wrap past 0.
        h.buckets[0] = u32::MAX - 4;
        for _ in 0..10 {
            h.update(10, &edges);  // rtt=10 → bucket 0
        }
        // 10 increments from (u32::MAX - 4): wraps at 4, ends at 5.
        assert_eq!(h.buckets[0], 5);
    }

    #[test]
    fn snapshot_returns_bucket_copy() {
        let mut h = RttHistogram::default();
        h.buckets[3] = 100;
        h.buckets[7] = 200;
        let snap = h.snapshot();
        assert_eq!(snap[3], 100);
        assert_eq!(snap[7], 200);
        // Snapshot is a copy; mutating source doesn't change snapshot.
        h.buckets[3] = 999;
        assert_eq!(snap[3], 100);
    }
}
