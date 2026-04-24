//! Maxtp-grid runner — spec §11.2 W × C = 28 buckets.
//!
//! | Axis                        | Values                                           |
//! |-----------------------------|--------------------------------------------------|
//! | Application write size W    | 64 B, 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB |
//! | Connection count C          | 1, 4, 16, 64                                     |
//!
//! Grid enumeration + CSV row emission for the max-sustained-throughput
//! workload. The per-stack implementation lives in
//! [`crate::dpdk_maxtp`] (dpdk_net side) and [`crate::mtcp`] (stub).
//!
//! # Measurement contract (spec §11.2)
//!
//! - Persistent connection(s); application writes in a tight loop for
//!   T = 60 s per bucket post-warmup.
//! - Warmup: 10 s pumping before measurement window.
//! - Primary metric: sustained goodput = bytes ACKed in `[t_warmup_end,
//!   t_warmup_end + T]` / T, bytes/sec.
//! - Secondary metric: packet rate = `eth.tx_pkts_delta / T`, pps.
//!   (Spec §11.2 asks for `tcp.tx_pkts`; that counter does not exist
//!   in `dpdk-net-core` today. `eth.tx_pkts` is the closest available
//!   proxy — the ARP/ICMP floor is <<< TCP data volume across a 60 s
//!   steady-state pump, so the bias is negligible. Follow-up at T15
//!   can expose the TCP-only variant if needed — tracked in
//!   `dpdk_maxtp.rs` module doc.)
//!
//! # CSV dimensions
//!
//! Each row's `dimensions_json` is
//! `{"workload":"maxtp","W_bytes":<int>,"C":<int>,"stack":<str>,
//!  "tx_ts_mode":<str>}` per spec §11.3 + T12 fixup. `tx_ts_mode`
//! remains in the CSV schema for consistency with T12; on the maxtp
//! path its value is informational — the sustained-rate window is
//! delimited by TSC timestamps not per-burst HW-TS reads — but CSV
//! consumers expect the column on every dpdk_net row.
//!
//! # Aggregation
//!
//! Unlike burst (which samples ≥10 k bursts per bucket), maxtp yields
//! **one sample per bucket** — goodput + pps measured over a single
//! 60 s window. We emit two rows per bucket (one `Mean` aggregation
//! per metric) when `Ok`, one marker row when `Invalid`. This matches
//! spec §11.2's single-value-per-bucket design.

use bench_common::csv_row::{CsvRow, MetricAggregation};
use bench_common::run_metadata::RunMetadata;

use crate::dpdk_maxtp::TxTsMode;
use crate::preflight::BucketVerdict;
use crate::Stack;

/// Per spec §11.2: application write size W in bytes.
pub const W_BYTES: &[u64] = &[64, 256, 1024, 4096, 16_384, 65_536, 262_144];

/// Per spec §11.2: connection count C.
pub const C_CONNS: &[u64] = &[1, 4, 16, 64];

/// Number of (W, C) buckets in the maxtp grid — spec §11.2
/// "Product = 28 buckets".
pub const BUCKET_COUNT: usize = 28;

/// Per spec §11.2: warmup window duration before the measurement
/// window starts. Exposed as a const so unit tests and the runner use
/// the same value.
pub const WARMUP_SECS: u64 = 10;

/// Per spec §11.2: measurement window duration.
pub const DURATION_SECS: u64 = 60;

/// One bucket in the W × C grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bucket {
    /// Application write size in bytes.
    pub write_bytes: u64,
    /// Concurrent connection count.
    pub conn_count: u64,
}

impl Bucket {
    pub const fn new(write_bytes: u64, conn_count: u64) -> Self {
        Self {
            write_bytes,
            conn_count,
        }
    }

    /// Short human label for logging. Not used in CSV — dimensions
    /// use the JSON shape.
    pub fn label(&self) -> String {
        format!("W={}B,C={}", self.write_bytes, self.conn_count)
    }
}

/// Enumerate the full W × C grid in spec order — W outer, C inner.
/// Stable ordering so downstream reports can index by position.
pub fn enumerate_grid() -> Vec<Bucket> {
    let mut out = Vec::with_capacity(W_BYTES.len() * C_CONNS.len());
    for &w in W_BYTES {
        for &c in C_CONNS {
            out.push(Bucket::new(w, c));
        }
    }
    out
}

/// A single bucket post-subset-filter, guarding against empty
/// selections in unit tests. Returns `Err` if the subset filter
/// rejects every cell.
pub fn enumerate_filtered_grid(
    w_filter: Option<&[u64]>,
    c_filter: Option<&[u64]>,
) -> Result<Vec<Bucket>, String> {
    let ws: Vec<u64> = match w_filter {
        Some(f) => W_BYTES.iter().copied().filter(|w| f.contains(w)).collect(),
        None => W_BYTES.to_vec(),
    };
    let cs: Vec<u64> = match c_filter {
        Some(f) => C_CONNS.iter().copied().filter(|c| f.contains(c)).collect(),
        None => C_CONNS.to_vec(),
    };
    if ws.is_empty() {
        return Err(format!(
            "maxtp grid: no W values match filter {w_filter:?} (valid: {W_BYTES:?})"
        ));
    }
    if cs.is_empty() {
        return Err(format!(
            "maxtp grid: no C values match filter {c_filter:?} (valid: {C_CONNS:?})"
        ));
    }
    let mut out = Vec::with_capacity(ws.len() * cs.len());
    for w in &ws {
        for c in &cs {
            out.push(Bucket::new(*w, *c));
        }
    }
    Ok(out)
}

/// One bucket's raw measurement product for maxtp.
///
/// - `goodput_bps` = primary metric (ACKed bytes / T, in bits/sec).
///   Stored as bytes/sec → converted to bits/sec via the `*8` rule the
///   spec uses on the burst grid; emitted into CSV as `bits_per_sec`
///   for unit consistency with burst.
/// - `pps` = secondary metric (tx_pkts_delta / T).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MaxtpSample {
    /// Sustained goodput in bits-per-second (spec §11.2 metric,
    /// converted from bytes/sec by the constructor).
    pub goodput_bps: f64,
    /// Segments transmitted per second.
    pub pps: f64,
}

impl MaxtpSample {
    /// Construct a sample from counter deltas + window duration.
    ///
    /// `acked_bytes_in_window` is the sum of bytes the peer has ACKed
    /// during `[t_warmup_end, t_warmup_end + duration_ns]`.
    /// `tx_pkts_in_window` is the `eth.tx_pkts` counter delta across
    /// the same window. Spec §11.2 references `tcp.tx_pkts` — that
    /// counter is not surfaced in `dpdk-net-core` today; we use
    /// `eth.tx_pkts` as a close proxy because ARP/ICMP volume is
    /// <<< TCP data volume across the 60 s steady-state pump.
    /// `duration_ns` must be strictly positive.
    ///
    /// Panics if `duration_ns == 0`.
    pub fn from_window(
        acked_bytes_in_window: u64,
        tx_pkts_in_window: u64,
        duration_ns: u64,
    ) -> Self {
        assert!(
            duration_ns > 0,
            "MaxtpSample::from_window: duration_ns must be > 0"
        );
        let duration_s = (duration_ns as f64) / 1_000_000_000.0;
        let goodput_bytes_per_s = (acked_bytes_in_window as f64) / duration_s;
        let goodput_bps = goodput_bytes_per_s * 8.0;
        let pps = (tx_pkts_in_window as f64) / duration_s;
        Self { goodput_bps, pps }
    }
}

/// Aggregation for one bucket's single measurement sample.
///
/// Unlike burst's percentile-summariser, maxtp's one-sample-per-bucket
/// shape just carries the raw sample + verdict through to CSV emit.
#[derive(Debug, Clone)]
pub struct BucketAggregate {
    pub bucket: Bucket,
    pub stack: Stack,
    pub verdict: BucketVerdict,
    /// `None` if the verdict is `Invalid` (skipped measurement) or if
    /// the stack didn't produce a sample (e.g. mTCP stub marker row).
    pub sample: Option<MaxtpSample>,
    /// TX-TS mode the runner used. `None` on mTCP stub rows. Mirrors
    /// the `burst::BucketAggregate.tx_ts_mode` field for CSV schema
    /// uniformity.
    pub tx_ts_mode: Option<TxTsMode>,
}

impl BucketAggregate {
    /// Construct an aggregate from a single sample + context. If the
    /// verdict is `Invalid`, `sample` is dropped so the CSV emit path
    /// produces a single marker row instead of untrustworthy metrics.
    pub fn from_sample(
        bucket: Bucket,
        stack: Stack,
        sample: Option<MaxtpSample>,
        verdict: BucketVerdict,
        tx_ts_mode: Option<TxTsMode>,
    ) -> Self {
        let sample = if verdict.is_ok() { sample } else { None };
        Self {
            bucket,
            stack,
            verdict,
            sample,
            tx_ts_mode,
        }
    }

    /// Post-run verdict override — e.g. NIC-saturation flip. Drops
    /// `sample` so the CSV emit path produces a marker row instead of
    /// untrustworthy metrics.
    pub fn override_verdict(&mut self, verdict: BucketVerdict) {
        self.verdict = verdict;
        if !self.verdict.is_ok() {
            self.sample = None;
        }
    }
}

/// Build `dimensions_json` string for a bucket row per spec §11.3.
///
/// `{"workload":"maxtp","W_bytes":<int>,"C":<int>,"stack":<str>}` —
/// plus `"tx_ts_mode":<str>` when the row's runner records it (dpdk_net
/// side; mTCP stub leaves it unset) and `"bucket_invalid":<str>` when
/// the bucket is invalidated.
pub fn build_dimensions_json(
    bucket: Bucket,
    stack: Stack,
    invalid_reason: Option<&str>,
    tx_ts_mode: Option<&str>,
) -> String {
    let mut v = serde_json::json!({
        "workload": "maxtp",
        "W_bytes": bucket.write_bytes as i64,
        "C": bucket.conn_count as i64,
        "stack": stack.as_dimension(),
    });
    if let Some(m) = v.as_object_mut() {
        if let Some(r) = invalid_reason {
            m.insert(
                "bucket_invalid".to_string(),
                serde_json::Value::String(r.to_string()),
            );
        }
        if let Some(mode) = tx_ts_mode {
            m.insert(
                "tx_ts_mode".to_string(),
                serde_json::Value::String(mode.to_string()),
            );
        }
    }
    v.to_string()
}

/// Emit all CSV rows for one bucket aggregate — 2 metrics × 1
/// aggregation (`Mean`) = 2 rows when the verdict is `Ok`, or a single
/// marker row when the verdict is `Invalid`.
pub fn emit_bucket_rows<W: std::io::Write>(
    writer: &mut csv::Writer<W>,
    metadata: &RunMetadata,
    tool: &str,
    feature_set: &str,
    aggregate: &BucketAggregate,
) -> Result<(), csv::Error> {
    let dims = build_dimensions_json(
        aggregate.bucket,
        aggregate.stack,
        aggregate.verdict.reason(),
        aggregate.tx_ts_mode.map(|m| m.as_str()),
    );

    match &aggregate.sample {
        Some(sample) => {
            // Primary: sustained goodput in bits_per_sec (matches
            // burst's unit-column spelling per T12 I1 / spec §14.1).
            let row = CsvRow {
                run_metadata: metadata.clone(),
                tool: tool.to_string(),
                test_case: "maxtp".to_string(),
                feature_set: feature_set.to_string(),
                dimensions_json: dims.clone(),
                metric_name: "sustained_goodput_bps".to_string(),
                metric_unit: "bits_per_sec".to_string(),
                metric_value: sample.goodput_bps,
                metric_aggregation: MetricAggregation::Mean,
                // Task 2.8 host/dpdk/worktree identification columns — only
                // the bench-micro summariser currently populates these; the
                // macrobench tools emit blank cells for now (spec §3 / §4.4
                // cross-worktree rejection is keyed on bench-micro rows).
                cpu_family: None,
                cpu_model_name: None,
                dpdk_version_pkgconfig: None,
                worktree_branch: None,
                uprof_session_id: None,
            };
            writer.serialize(&row)?;

            // Secondary: packet rate.
            let row = CsvRow {
                run_metadata: metadata.clone(),
                tool: tool.to_string(),
                test_case: "maxtp".to_string(),
                feature_set: feature_set.to_string(),
                dimensions_json: dims,
                metric_name: "tx_pps".to_string(),
                metric_unit: "pps".to_string(),
                metric_value: sample.pps,
                metric_aggregation: MetricAggregation::Mean,
                cpu_family: None,
                cpu_model_name: None,
                dpdk_version_pkgconfig: None,
                worktree_branch: None,
                uprof_session_id: None,
            };
            writer.serialize(&row)?;
        }
        None => {
            // Bucket invalidated or no sample — emit a single marker
            // row with metric_value = 0.0 + Mean aggregation so the
            // row is not silently dropped by downstream tooling. The
            // `bucket_invalid` key in `dims` carries the reason.
            let row = CsvRow {
                run_metadata: metadata.clone(),
                tool: tool.to_string(),
                test_case: "maxtp".to_string(),
                feature_set: feature_set.to_string(),
                dimensions_json: dims,
                metric_name: "sustained_goodput_bps".to_string(),
                metric_unit: "bits_per_sec".to_string(),
                metric_value: 0.0,
                metric_aggregation: MetricAggregation::Mean,
                cpu_family: None,
                cpu_model_name: None,
                dpdk_version_pkgconfig: None,
                worktree_branch: None,
                uprof_session_id: None,
            };
            writer.serialize(&row)?;
        }
    }
    Ok(())
}

/// Check the §11.2 sanity invariant: ACKed bytes during the window
/// equal the `stack_tx_bytes_counter_delta` during the window, **minus
/// any bytes still in-flight at `t_end`** (bounded by cwnd + rwnd).
///
/// The check is non-trivial because the window closes mid-ACK-stream:
/// the stack may have pushed K bytes on the wire but only received
/// ACKs for K − ε by the time `t_end` fires. The bound on ε is
/// `cwnd + rwnd` per connection; spec §11.2 says "minus any bytes
/// still in-flight at `t_end`, bounded by cwnd + rwnd".
///
/// Signature accepts the observed deltas + the in-flight bound; returns
/// `Ok(())` if `acked ≤ tx_payload ≤ acked + inflight_bound`, else an
/// `Err` describing the divergence. The runner propagates `Err` as a
/// hard failure (spec §11.2 "Sanity invariant").
pub fn check_sanity_invariant(
    acked_bytes_in_window: u64,
    tx_payload_bytes_in_window: u64,
    inflight_bound_bytes: u64,
) -> Result<(), String> {
    if tx_payload_bytes_in_window < acked_bytes_in_window {
        return Err(format!(
            "maxtp sanity invariant violated: ACKed bytes ({acked_bytes_in_window} B) \
             exceed tx_payload_bytes counter delta ({tx_payload_bytes_in_window} B) — \
             impossible unless counters lie"
        ));
    }
    let unacked = tx_payload_bytes_in_window - acked_bytes_in_window;
    if unacked > inflight_bound_bytes {
        return Err(format!(
            "maxtp sanity invariant violated: unacked bytes at window close \
             ({unacked} B) exceed cwnd+rwnd bound ({inflight_bound_bytes} B)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // Grid enumeration
    // ----------------------------------------------------------------

    #[test]
    fn grid_constants_match_spec_11_2() {
        assert_eq!(W_BYTES, &[64, 256, 1024, 4096, 16_384, 65_536, 262_144]);
        assert_eq!(C_CONNS, &[1, 4, 16, 64]);
        assert_eq!(W_BYTES.len() * C_CONNS.len(), BUCKET_COUNT);
        assert_eq!(BUCKET_COUNT, 28);
    }

    #[test]
    fn warmup_and_duration_match_spec_11_2() {
        // Spec §11.2: "Warmup: 10 s pumping before the measurement
        // window starts." + "tight loop for T = 60 s per bucket".
        assert_eq!(WARMUP_SECS, 10);
        assert_eq!(DURATION_SECS, 60);
    }

    #[test]
    fn enumerate_grid_produces_28_buckets() {
        let grid = enumerate_grid();
        assert_eq!(grid.len(), BUCKET_COUNT);
    }

    #[test]
    fn enumerate_grid_is_w_outer_c_inner() {
        let grid = enumerate_grid();
        // First four entries: W=64 with all four connection counts.
        assert_eq!(grid[0], Bucket::new(64, 1));
        assert_eq!(grid[1], Bucket::new(64, 4));
        assert_eq!(grid[2], Bucket::new(64, 16));
        assert_eq!(grid[3], Bucket::new(64, 64));
        // Fifth entry: W=256 with C=1.
        assert_eq!(grid[4], Bucket::new(256, 1));
        // Last entry: W=256 KiB with C=64.
        assert_eq!(grid[BUCKET_COUNT - 1], Bucket::new(262_144, 64));
    }

    #[test]
    fn enumerate_grid_has_no_duplicates() {
        let grid = enumerate_grid();
        let unique: std::collections::HashSet<_> = grid.iter().collect();
        assert_eq!(unique.len(), grid.len());
    }

    #[test]
    fn enumerate_filtered_grid_w_subset_only() {
        // Run only W=1 KiB and W=4 KiB, all four C values each → 2×4 = 8.
        let grid = enumerate_filtered_grid(Some(&[1024, 4096]), None).unwrap();
        assert_eq!(grid.len(), 8);
        for b in &grid {
            assert!(b.write_bytes == 1024 || b.write_bytes == 4096);
        }
    }

    #[test]
    fn enumerate_filtered_grid_c_subset_only() {
        // Single-connection only (C=1) → 7 × 1 = 7.
        let grid = enumerate_filtered_grid(None, Some(&[1])).unwrap();
        assert_eq!(grid.len(), 7);
        for b in &grid {
            assert_eq!(b.conn_count, 1);
        }
    }

    #[test]
    fn enumerate_filtered_grid_no_match_errors() {
        let err = enumerate_filtered_grid(Some(&[123]), None).unwrap_err();
        assert!(err.contains("no W values match"));
    }

    #[test]
    fn enumerate_filtered_grid_empty_c_match_errors() {
        let err = enumerate_filtered_grid(None, Some(&[2])).unwrap_err();
        assert!(err.contains("no C values match"));
    }

    #[test]
    fn bucket_label_human_readable() {
        assert_eq!(Bucket::new(64, 1).label(), "W=64B,C=1");
        assert_eq!(Bucket::new(262_144, 64).label(), "W=262144B,C=64");
    }

    // ----------------------------------------------------------------
    // MaxtpSample::from_window
    // ----------------------------------------------------------------

    #[test]
    fn sample_from_window_computes_bits_per_sec() {
        // 10 Gbits in 60s = 10e9 / 60 ≈ 166.67 Mbps.
        // bytes = 10e9 / 8 = 1.25e9 bytes over 60s
        // Actually compute the expected values cleanly:
        // If we ACKed 1_250_000_000 bytes in 60e9 ns:
        //   goodput_bytes_per_s = 1.25e9 / 60 = 20_833_333.333
        //   goodput_bps (bits/s) = 166_666_666.666
        let s = MaxtpSample::from_window(1_250_000_000, 1_000_000, 60_000_000_000);
        assert!(
            (s.goodput_bps - 166_666_666.666).abs() < 10.0,
            "goodput = {}",
            s.goodput_bps
        );
        // 1M packets in 60s = 16_666.67 pps
        assert!((s.pps - 16_666.666).abs() < 1.0, "pps = {}", s.pps);
    }

    #[test]
    fn sample_from_window_zero_acked_yields_zero_goodput() {
        // Peer never ACKed during the window — goodput is 0 bps.
        let s = MaxtpSample::from_window(0, 0, 60_000_000_000);
        assert_eq!(s.goodput_bps, 0.0);
        assert_eq!(s.pps, 0.0);
    }

    #[test]
    #[should_panic(expected = "duration_ns must be > 0")]
    fn sample_from_window_rejects_zero_duration() {
        let _ = MaxtpSample::from_window(1_000_000, 100, 0);
    }

    // ----------------------------------------------------------------
    // BucketAggregate::from_sample
    // ----------------------------------------------------------------

    #[test]
    fn bucket_aggregate_happy_path_keeps_sample() {
        let bucket = Bucket::new(4096, 4);
        let sample = MaxtpSample::from_window(1_000_000_000, 500_000, 60_000_000_000);
        let agg = BucketAggregate::from_sample(
            bucket,
            Stack::DpdkNet,
            Some(sample),
            BucketVerdict::Ok,
            Some(TxTsMode::TscFallback),
        );
        assert!(agg.verdict.is_ok());
        assert!(agg.sample.is_some());
    }

    #[test]
    fn bucket_aggregate_invalid_verdict_drops_sample() {
        let bucket = Bucket::new(4096, 4);
        let sample = MaxtpSample::from_window(1_000_000_000, 500_000, 60_000_000_000);
        let agg = BucketAggregate::from_sample(
            bucket,
            Stack::DpdkNet,
            Some(sample),
            BucketVerdict::Invalid("NIC-bound".to_string()),
            Some(TxTsMode::TscFallback),
        );
        assert!(!agg.verdict.is_ok());
        assert!(agg.sample.is_none());
    }

    #[test]
    fn bucket_aggregate_override_verdict_flips_and_clears_sample() {
        let bucket = Bucket::new(65_536, 16);
        let sample = MaxtpSample::from_window(10_000_000_000, 5_000_000, 60_000_000_000);
        let mut agg = BucketAggregate::from_sample(
            bucket,
            Stack::DpdkNet,
            Some(sample),
            BucketVerdict::Ok,
            Some(TxTsMode::TscFallback),
        );
        assert!(agg.sample.is_some());
        agg.override_verdict(BucketVerdict::Invalid("NIC-bound".to_string()));
        assert!(!agg.verdict.is_ok());
        assert!(agg.sample.is_none());
    }

    // ----------------------------------------------------------------
    // build_dimensions_json
    // ----------------------------------------------------------------

    #[test]
    fn dimensions_json_shape_matches_spec_11_3() {
        let dims = build_dimensions_json(Bucket::new(4096, 4), Stack::DpdkNet, None, None);
        let parsed: serde_json::Value = serde_json::from_str(&dims).unwrap();
        assert_eq!(parsed["workload"], "maxtp");
        assert_eq!(parsed["W_bytes"], 4096i64);
        assert_eq!(parsed["C"], 4i64);
        assert_eq!(parsed["stack"], "dpdk_net");
        assert!(parsed.get("bucket_invalid").is_none());
        assert!(parsed.get("tx_ts_mode").is_none());
    }

    #[test]
    fn dimensions_json_carries_invalid_reason_when_present() {
        let dims = build_dimensions_json(
            Bucket::new(262_144, 64),
            Stack::Mtcp,
            Some("mtcp stub"),
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&dims).unwrap();
        assert_eq!(parsed["stack"], "mtcp");
        assert_eq!(parsed["bucket_invalid"], "mtcp stub");
    }

    #[test]
    fn dimensions_json_emits_tx_ts_mode_when_provided() {
        let hw = build_dimensions_json(
            Bucket::new(64, 1),
            Stack::DpdkNet,
            None,
            Some(TxTsMode::HwTs.as_str()),
        );
        let parsed: serde_json::Value = serde_json::from_str(&hw).unwrap();
        assert_eq!(parsed["tx_ts_mode"], "hw_ts");
        let tsc = build_dimensions_json(
            Bucket::new(64, 1),
            Stack::DpdkNet,
            None,
            Some(TxTsMode::TscFallback.as_str()),
        );
        let parsed: serde_json::Value = serde_json::from_str(&tsc).unwrap();
        assert_eq!(parsed["tx_ts_mode"], "tsc_fallback");
    }

    #[test]
    fn dimensions_json_is_stable_across_calls() {
        // bench-report groups rows by the verbatim string; serialisation
        // must be deterministic.
        let a = build_dimensions_json(Bucket::new(1024, 4), Stack::Mtcp, None, None);
        let b = build_dimensions_json(Bucket::new(1024, 4), Stack::Mtcp, None, None);
        assert_eq!(a, b);
    }

    // ----------------------------------------------------------------
    // check_sanity_invariant
    // ----------------------------------------------------------------

    #[test]
    fn sanity_invariant_passes_when_acked_equals_tx_payload() {
        // All bytes sent were ACKed — unacked = 0 is always within any
        // sensible inflight bound.
        assert!(check_sanity_invariant(1_000_000, 1_000_000, 64 * 1024).is_ok());
    }

    #[test]
    fn sanity_invariant_passes_when_unacked_within_inflight_bound() {
        // 1 MiB sent, 512 KiB ACKed → unacked = 512 KiB. With cwnd+rwnd
        // = 1 MiB the 512 KiB gap is well within bound.
        let sent = 1 << 20;
        let acked = 1 << 19;
        let inflight_bound = 1 << 20;
        assert!(check_sanity_invariant(acked, sent, inflight_bound).is_ok());
    }

    #[test]
    fn sanity_invariant_fails_when_acked_exceeds_tx_payload() {
        // Counter says we sent 1 KiB but we have 2 KiB ACKed — impossible.
        let err =
            check_sanity_invariant(2 * 1024, 1024, 64 * 1024).unwrap_err();
        assert!(
            err.contains("exceed tx_payload_bytes"),
            "err = {err}"
        );
    }

    #[test]
    fn sanity_invariant_fails_when_unacked_exceeds_inflight_bound() {
        // 2 MiB sent, 0 ACKed, but cwnd+rwnd only 1 MiB — gap is too big.
        let sent = 2 << 20;
        let acked = 0;
        let inflight_bound = 1 << 20;
        let err = check_sanity_invariant(acked, sent, inflight_bound).unwrap_err();
        assert!(
            err.contains("exceed cwnd+rwnd bound"),
            "err = {err}"
        );
    }

    // ----------------------------------------------------------------
    // CSV row emission.
    // ----------------------------------------------------------------

    fn sample_metadata() -> RunMetadata {
        use bench_common::preconditions::{PreconditionMode, Preconditions};
        RunMetadata {
            run_id: uuid::Uuid::nil(),
            run_started_at: "2026-04-21T00:00:00Z".to_string(),
            commit_sha: "0".repeat(40),
            branch: "phase-a10".to_string(),
            host: "test-host".to_string(),
            instance_type: "c6in.metal".to_string(),
            cpu_model: "test-cpu".to_string(),
            dpdk_version: "23.11.2".to_string(),
            kernel: "6.8.0".to_string(),
            nic_model: "ENA".to_string(),
            nic_fw: String::new(),
            ami_id: String::new(),
            precondition_mode: PreconditionMode::Strict,
            preconditions: Preconditions::default(),
        }
    }

    fn count_csv_rows(buf: &[u8]) -> usize {
        let text = std::str::from_utf8(buf).unwrap();
        text.lines().count().saturating_sub(1)
    }

    #[test]
    fn emit_bucket_rows_happy_path_emits_2_rows() {
        let bucket = Bucket::new(4096, 4);
        let sample = MaxtpSample::from_window(1_000_000_000, 500_000, 60_000_000_000);
        let agg = BucketAggregate::from_sample(
            bucket,
            Stack::DpdkNet,
            Some(sample),
            BucketVerdict::Ok,
            Some(TxTsMode::TscFallback),
        );
        let mut buf = Vec::new();
        {
            let mut writer = csv::Writer::from_writer(&mut buf);
            emit_bucket_rows(&mut writer, &sample_metadata(), "bench-vs-mtcp", "trading-latency", &agg)
                .unwrap();
            writer.flush().unwrap();
        }
        // 2 metrics × 1 aggregation = 2 rows.
        assert_eq!(count_csv_rows(&buf), 2);
    }

    #[test]
    fn emit_bucket_rows_invalid_verdict_emits_single_marker_row() {
        let bucket = Bucket::new(262_144, 64);
        let agg = BucketAggregate::from_sample(
            bucket,
            Stack::DpdkNet,
            None,
            BucketVerdict::Invalid("NIC-bound".to_string()),
            Some(TxTsMode::TscFallback),
        );
        let mut buf = Vec::new();
        {
            let mut writer = csv::Writer::from_writer(&mut buf);
            emit_bucket_rows(&mut writer, &sample_metadata(), "bench-vs-mtcp", "trading-latency", &agg)
                .unwrap();
            writer.flush().unwrap();
        }
        assert_eq!(count_csv_rows(&buf), 1);
    }

    #[test]
    fn emit_bucket_rows_tags_tx_ts_mode_in_dimensions_json() {
        let bucket = Bucket::new(64, 1);
        let sample = MaxtpSample::from_window(1_000_000, 1_000, 60_000_000_000);
        let agg = BucketAggregate::from_sample(
            bucket,
            Stack::DpdkNet,
            Some(sample),
            BucketVerdict::Ok,
            Some(TxTsMode::TscFallback),
        );
        let mut buf = Vec::new();
        {
            let mut writer = csv::Writer::from_writer(&mut buf);
            emit_bucket_rows(&mut writer, &sample_metadata(), "bench-vs-mtcp", "trading-latency", &agg)
                .unwrap();
            writer.flush().unwrap();
        }
        // Parse and inspect the first data row.
        let mut reader = csv::Reader::from_reader(buf.as_slice());
        let headers = reader.headers().unwrap().clone();
        let dims_idx = headers
            .iter()
            .position(|h| h == "dimensions_json")
            .unwrap();
        let rec = reader.records().next().unwrap().unwrap();
        let dims: serde_json::Value =
            serde_json::from_str(rec.get(dims_idx).unwrap()).unwrap();
        assert_eq!(dims["tx_ts_mode"], "tsc_fallback");
        assert_eq!(dims["workload"], "maxtp");
    }

    #[test]
    fn emit_bucket_rows_omits_tx_ts_mode_for_mtcp_stub() {
        let bucket = Bucket::new(64, 1);
        let agg = BucketAggregate::from_sample(
            bucket,
            Stack::Mtcp,
            None,
            BucketVerdict::Invalid("mtcp stub".to_string()),
            None,
        );
        let mut buf = Vec::new();
        {
            let mut writer = csv::Writer::from_writer(&mut buf);
            emit_bucket_rows(&mut writer, &sample_metadata(), "bench-vs-mtcp", "trading-latency", &agg)
                .unwrap();
            writer.flush().unwrap();
        }
        let mut reader = csv::Reader::from_reader(buf.as_slice());
        let headers = reader.headers().unwrap().clone();
        let dims_idx = headers
            .iter()
            .position(|h| h == "dimensions_json")
            .unwrap();
        let rec = reader.records().next().unwrap().unwrap();
        let dims: serde_json::Value =
            serde_json::from_str(rec.get(dims_idx).unwrap()).unwrap();
        assert!(
            dims.get("tx_ts_mode").is_none(),
            "expected tx_ts_mode absent for mtcp stub row; got {dims}"
        );
    }

    #[test]
    fn emit_bucket_rows_metric_names_and_units_are_stable() {
        let bucket = Bucket::new(1024, 16);
        let sample = MaxtpSample::from_window(1_000_000, 1_000, 60_000_000_000);
        let agg = BucketAggregate::from_sample(
            bucket,
            Stack::DpdkNet,
            Some(sample),
            BucketVerdict::Ok,
            Some(TxTsMode::TscFallback),
        );
        let mut buf = Vec::new();
        {
            let mut writer = csv::Writer::from_writer(&mut buf);
            emit_bucket_rows(&mut writer, &sample_metadata(), "bench-vs-mtcp", "trading-latency", &agg)
                .unwrap();
            writer.flush().unwrap();
        }
        let mut reader = csv::Reader::from_reader(buf.as_slice());
        let headers = reader.headers().unwrap().clone();
        let metric_name_idx = headers.iter().position(|h| h == "metric_name").unwrap();
        let metric_unit_idx = headers.iter().position(|h| h == "metric_unit").unwrap();
        let metric_agg_idx = headers
            .iter()
            .position(|h| h == "metric_aggregation")
            .unwrap();
        let mut seen_goodput = false;
        let mut seen_pps = false;
        for rec in reader.records() {
            let rec = rec.unwrap();
            let name = rec.get(metric_name_idx).unwrap();
            let unit = rec.get(metric_unit_idx).unwrap();
            let agg = rec.get(metric_agg_idx).unwrap();
            // Only `mean` is emitted for maxtp — one sample per bucket.
            assert_eq!(agg, "mean");
            match name {
                "sustained_goodput_bps" => {
                    assert_eq!(unit, "bits_per_sec");
                    seen_goodput = true;
                }
                "tx_pps" => {
                    assert_eq!(unit, "pps");
                    seen_pps = true;
                }
                other => panic!("unexpected metric_name {other}"),
            }
        }
        assert!(seen_goodput);
        assert!(seen_pps);
    }
}
