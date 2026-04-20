//! A6 sibling audit — per-connection RTT histogram coverage
//! (A6 design spec §7.4).
//!
//! The engine-wide counter audit in `knob-coverage.rs` does NOT reach
//! per-connection state: a `TcpConn` is not a counter and the A8 audit
//! pattern (each feature-gated counter observable under a default or
//! `obs-all` feature build) does not map to per-conn buckets. This
//! sibling file pins the same "every observable slot must be reachable
//! by at least one scenario" invariant for the 16-bucket per-conn RTT
//! histogram under the default edge set.
//!
//! Fails the build if a default bucket is unreachable — guards against
//! edge-tuning regressions where a future edit to
//! `DEFAULT_RTT_HISTOGRAM_EDGES_US` introduces a gap or an
//! unreachable catch-all.

use resd_net_core::engine::DEFAULT_RTT_HISTOGRAM_EDGES_US;
use resd_net_core::rtt_histogram::{select_bucket, RttHistogram};

/// Drive one sample into each of the 16 default buckets and assert
/// every bucket records exactly one hit. Each sample is chosen to sit
/// strictly inside its bucket interval `(edges[i-1], edges[i]]`
/// (interior points; the bucket-boundary case is covered by
/// `edge_exact_values_land_in_low_bucket` below).
#[test]
fn every_default_bucket_reachable() {
    let edges = DEFAULT_RTT_HISTOGRAM_EDGES_US;
    // Samples picked at roughly the midpoint of each bucket interval;
    // the last one is >>edges[14]=500_000 to exercise the catch-all.
    let samples: [u32; 16] = [
        25,      // b0:  (0,       50]
        75,      // b1:  (50,      100]
        150,     // b2:  (100,     200]
        250,     // b3:  (200,     300]
        400,     // b4:  (300,     500]
        625,     // b5:  (500,     750]
        875,     // b6:  (750,     1000]
        1500,    // b7:  (1000,    2000]
        2500,    // b8:  (2000,    3000]
        4000,    // b9:  (3000,    5000]
        7500,    // b10: (5000,    10000]
        17500,   // b11: (10000,   25000]
        37500,   // b12: (25000,   50000]
        75000,   // b13: (50000,   100000]
        300000,  // b14: (100000,  500000]
        1000000, // b15: catch-all > 500000
    ];
    let mut h = RttHistogram::default();
    for (i, &rtt) in samples.iter().enumerate() {
        h.update(rtt, &edges);
        assert_eq!(
            h.buckets[i], 1,
            "sample {rtt} µs failed to land in bucket {i}"
        );
    }
    // Second pass: every bucket must have exactly one hit — no
    // accidental cross-bucket leakage.
    for (i, &count) in h.buckets.iter().enumerate() {
        assert_eq!(count, 1, "bucket {i} count = {count} (expected 1)");
    }
}

/// The `select_bucket` ladder uses `rtt_us <= edges[i]` — exactly-on
/// an edge must land in the LOW bucket (the interval is closed on the
/// right). Verify for every edge in the default set.
#[test]
fn edge_exact_values_land_in_low_bucket() {
    let edges = DEFAULT_RTT_HISTOGRAM_EDGES_US;
    for i in 0..15 {
        assert_eq!(
            select_bucket(edges[i], &edges), i,
            "rtt == edges[{i}] = {} failed edge-exact test", edges[i]
        );
    }
}

/// A sample strictly greater than the largest edge must land in the
/// catch-all bucket (index 15). Exercised at `edges[14] + 1` and at
/// `u32::MAX` to cover both the just-over case and the ABI ceiling.
#[test]
fn beyond_last_edge_lands_in_catchall() {
    let edges = DEFAULT_RTT_HISTOGRAM_EDGES_US;
    assert_eq!(select_bucket(edges[14] + 1, &edges), 15);
    assert_eq!(select_bucket(u32::MAX, &edges), 15);
}
