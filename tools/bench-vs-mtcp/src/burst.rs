//! Burst-grid runner — spec §11.1 K × G = 20 buckets.
//!
//! | Axis                   | Values                                        |
//! |------------------------|-----------------------------------------------|
//! | Burst size K (bytes)   | 64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB          |
//! | Idle gap G (ms)        | 0 (back-to-back), 1, 10, 100                   |
//!
//! Grid enumeration + CSV row emission + aggregation of per-burst
//! throughput samples live here. The per-stack implementation lives
//! in [`crate::dpdk_burst`] (dpdk_net side) and [`crate::mtcp`]
//! (stub).
//!
//! # CSV dimensions
//!
//! Each row's `dimensions_json` is
//! `{"workload": "burst", "K_bytes": <int>, "G_ms": <float>, "stack": <str>}`
//! per spec §11.3. `G_ms` is emitted as `f64` (not integer) because
//! the spec uses `<float>` in the dimension schema; the harness feeds
//! integer millisecond values from the grid and the JSON emits them
//! as `0.0`, `1.0`, ....
//!
//! # Aggregation
//!
//! One bucket → summarise p50/p99/p999/mean/stddev/ci95_lo/ci95_hi →
//! emit 7 CSV rows tagged with the bucket's dimensions. Throughput is
//! bits-per-second (spec §11.1 explicit); the CSV `metric_unit` column
//! is `"bits_per_sec"` (not the ambiguous `"bps"` — in IT tooling
//! "bps" often means bytes-per-sec, so we spell the unit out per spec
//! §14.1's unit-column convention).
//!
//! Secondary decomposition (t_first_wire, initiation, steady) per
//! spec §11.1 is captured by the per-burst sample collector in
//! [`BurstSample`] and emitted as additional metric rows (with
//! `metric_name = "burst_initiation_ns"` / `"burst_steady_bps"`) so
//! bench-report can pivot on either.

use bench_common::csv_row::{CsvRow, MetricAggregation};
use bench_common::percentile::{summarize, Summary};
use bench_common::run_metadata::RunMetadata;

use crate::dpdk_burst::TxTsMode;
use crate::preflight::BucketVerdict;
use crate::Stack;

/// Per spec §11.1: burst sizes K in bytes.
pub const K_BYTES: &[u64] = &[64 * 1024, 256 * 1024, 1 << 20, 4 << 20, 16 << 20];

/// Per spec §11.1: idle gaps G in milliseconds.
pub const G_MS: &[u64] = &[0, 1, 10, 100];

/// Number of K × G buckets — spec §11.1 "Product = 20 buckets".
pub const BUCKET_COUNT: usize = 20;

/// One bucket in the K × G grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bucket {
    pub burst_bytes: u64,
    pub gap_ms: u64,
}

impl Bucket {
    pub const fn new(burst_bytes: u64, gap_ms: u64) -> Self {
        Self { burst_bytes, gap_ms }
    }

    /// Short human label for logging. Not used in CSV — dimensions
    /// use the JSON shape.
    pub fn label(&self) -> String {
        format!("K={}B,G={}ms", self.burst_bytes, self.gap_ms)
    }
}

/// Enumerate the full K × G grid in spec order — K outer, G inner.
/// Stable ordering so downstream reports can index by position.
pub fn enumerate_grid() -> Vec<Bucket> {
    let mut out = Vec::with_capacity(K_BYTES.len() * G_MS.len());
    for &k in K_BYTES {
        for &g in G_MS {
            out.push(Bucket::new(k, g));
        }
    }
    out
}

/// A single bucket post-subset-filter, guarding against empty
/// selections in unit tests. Returns `Err` if the subset filter
/// rejects every cell.
pub fn enumerate_filtered_grid(
    k_filter: Option<&[u64]>,
    g_filter: Option<&[u64]>,
) -> Result<Vec<Bucket>, String> {
    let ks: Vec<u64> = match k_filter {
        Some(f) => K_BYTES.iter().copied().filter(|k| f.contains(k)).collect(),
        None => K_BYTES.to_vec(),
    };
    let gs: Vec<u64> = match g_filter {
        Some(f) => G_MS.iter().copied().filter(|g| f.contains(g)).collect(),
        None => G_MS.to_vec(),
    };
    if ks.is_empty() {
        return Err(format!(
            "burst grid: no K values match filter {k_filter:?} (valid: {K_BYTES:?})"
        ));
    }
    if gs.is_empty() {
        return Err(format!(
            "burst grid: no G values match filter {g_filter:?} (valid: {G_MS:?})"
        ));
    }
    let mut out = Vec::with_capacity(ks.len() * gs.len());
    for k in &ks {
        for g in &gs {
            out.push(Bucket::new(*k, *g));
        }
    }
    Ok(out)
}

/// One burst's raw measurement product. All times in TSC-ns units
/// (the `dpdk_burst` runner converts TSC cycles to ns before passing).
///
/// - `throughput_bps` = primary metric (K / (t1 − t0) in bits/s).
/// - `initiation_ns` = t_first_wire − t0, the wall-clock from the
///   inline TSC pre-first-send to the first segment's wire timestamp.
/// - `steady_bps` = K / (t1 − t_first_wire), the steady-state rate
///   after initiation is subtracted off.
///
/// `initiation_ns` may be zero on ENA if both t_first_wire and t0
/// fall within a single TSC cycle; the harness still emits the row
/// so bench-report can see it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BurstSample {
    pub throughput_bps: f64,
    pub initiation_ns: f64,
    pub steady_bps: f64,
}

impl BurstSample {
    /// Compute a BurstSample from raw timestamps. `t0_ns`, `t_first_wire_ns`
    /// and `t1_ns` are absolute-time nanosecond values on a monotonic
    /// clock (TSC converted to ns, or HW TX timestamp converted to ns —
    /// the two agree because both originate from the same clock domain
    /// per spec §11.1 when HW TS is available, and both are TSC-derived
    /// in the ENA fallback).
    ///
    /// `burst_bytes` is K for this bucket.
    ///
    /// Panics if `t1_ns <= t0_ns` or `t_first_wire_ns < t0_ns` or
    /// `t1_ns < t_first_wire_ns` — the harness validates monotonicity
    /// before constructing the sample; if those invariants are violated
    /// the sample is corrupt and must be dropped upstream.
    pub fn from_timestamps(
        burst_bytes: u64,
        t0_ns: u64,
        t_first_wire_ns: u64,
        t1_ns: u64,
    ) -> Self {
        assert!(t1_ns > t0_ns, "t1 must be strictly > t0");
        assert!(
            t_first_wire_ns >= t0_ns,
            "t_first_wire must be >= t0"
        );
        assert!(
            t1_ns >= t_first_wire_ns,
            "t1 must be >= t_first_wire"
        );
        let k_bits = (burst_bytes as f64) * 8.0;
        let elapsed_s = (t1_ns - t0_ns) as f64 / 1_000_000_000.0;
        let throughput_bps = k_bits / elapsed_s;
        let initiation_ns = (t_first_wire_ns - t0_ns) as f64;
        let steady_bps = if t1_ns > t_first_wire_ns {
            let steady_elapsed_s = (t1_ns - t_first_wire_ns) as f64 / 1_000_000_000.0;
            k_bits / steady_elapsed_s
        } else {
            // t1 == t_first_wire: entire burst measured to the same
            // timestamp → steady rate undefined; report 0 so the row
            // stays present (bench-report filters NaN rows).
            0.0
        };
        Self {
            throughput_bps,
            initiation_ns,
            steady_bps,
        }
    }
}

/// Aggregation across a bucket's measurement samples. One instance
/// per bucket; feeds the CSV emit helpers below.
#[derive(Debug, Clone)]
pub struct BucketAggregate {
    pub bucket: Bucket,
    pub stack: Stack,
    pub verdict: BucketVerdict,
    pub throughput_bps: Option<Summary>,
    pub initiation_ns: Option<Summary>,
    pub steady_bps: Option<Summary>,
    /// Raw sample count — not the same as samples consumed, which
    /// equals `len - warmup`. Useful for the sanity invariant check.
    pub measurement_sample_count: usize,
    /// TX-TS mode the runner used. `None` on rows produced by non-
    /// dpdk_net stacks (e.g. the mTCP stub) where the concept does not
    /// apply; `Some(mode)` on dpdk_net rows. Emitted into
    /// `dimensions_json.tx_ts_mode` so downstream reports can
    /// distinguish HW-TS rows from TSC-fallback rows on the same NIC /
    /// across NICs.
    pub tx_ts_mode: Option<TxTsMode>,
}

impl BucketAggregate {
    /// Construct an aggregate from raw `BurstSample`s + bucket
    /// context. Warmup must already be stripped by caller.
    ///
    /// `verdict` = the preflight verdict for this bucket. If the
    /// verdict is `Invalid`, we still build the aggregate so the CSV
    /// row carries a record (samples may still be present — caller
    /// decides whether to summarise them) but the Summary slots are
    /// skipped to avoid writing untrustworthy percentiles.
    ///
    /// `tx_ts_mode` is `None` on rows that don't involve the dpdk_net
    /// TX path (e.g. mTCP stub marker rows).
    pub fn from_samples(
        bucket: Bucket,
        stack: Stack,
        samples: &[BurstSample],
        verdict: BucketVerdict,
        tx_ts_mode: Option<TxTsMode>,
    ) -> Self {
        let count = samples.len();
        let (t, i, s) = if verdict.is_ok() && !samples.is_empty() {
            let thrs: Vec<f64> = samples.iter().map(|s| s.throughput_bps).collect();
            let inits: Vec<f64> = samples.iter().map(|s| s.initiation_ns).collect();
            let steadies: Vec<f64> = samples.iter().map(|s| s.steady_bps).collect();
            (
                Some(summarize(&thrs)),
                Some(summarize(&inits)),
                Some(summarize(&steadies)),
            )
        } else {
            (None, None, None)
        };
        Self {
            bucket,
            stack,
            verdict,
            throughput_bps: t,
            initiation_ns: i,
            steady_bps: s,
            measurement_sample_count: count,
            tx_ts_mode,
        }
    }

    /// Aggregate verdict for post-run override. After a bucket runs to
    /// completion, the harness may flip the verdict based on a post-
    /// run check (e.g. NIC saturation). This swaps in the new verdict
    /// and nukes the Summary slots if it's an Invalid so the emit path
    /// produces a marker row instead of untrustworthy percentiles.
    pub fn override_verdict(&mut self, verdict: BucketVerdict) {
        self.verdict = verdict;
        if !self.verdict.is_ok() {
            self.throughput_bps = None;
            self.initiation_ns = None;
            self.steady_bps = None;
        }
    }
}

/// Build `dimensions_json` string for a bucket row per spec §11.3.
///
/// The spec schema is
/// `{"workload":"burst","K_bytes":<int>,"G_ms":<float>,"stack":<str>}`;
/// we additionally append `"tx_ts_mode": <str>` when the row's runner
/// knows which TX-TS source it used (dpdk_net side) so downstream
/// reports can filter HW-TS rows from TSC-fallback rows. The mTCP stub
/// leaves it unset.
/// `G_ms` is emitted as `f64` (0.0, 1.0, 10.0, 100.0) to match the
/// `<float>` designation; downstream bench-report parses it as
/// `serde_json::Value::Number` so either integer or float form works
/// to round-trip, but the emit side locks the float shape.
///
/// If the bucket's verdict is `Invalid`, we attach the reason under
/// `bucket_invalid` so downstream reports can filter invalidated
/// rows without needing a second CSV column.
pub fn build_dimensions_json(
    bucket: Bucket,
    stack: Stack,
    invalid_reason: Option<&str>,
    tx_ts_mode: Option<&str>,
) -> String {
    let mut v = serde_json::json!({
        "workload": "burst",
        "K_bytes": bucket.burst_bytes as i64,
        "G_ms": bucket.gap_ms as f64,
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

/// Emit the seven-row aggregation tuple for one (Summary, metric) pair.
/// Factored out so throughput / initiation / steady all share the shape.
#[allow(clippy::too_many_arguments)]
fn emit_summary_rows<W: std::io::Write>(
    writer: &mut csv::Writer<W>,
    metadata: &RunMetadata,
    tool: &str,
    feature_set: &str,
    dims: &str,
    metric_name: &str,
    metric_unit: &str,
    summary: &Summary,
) -> Result<(), csv::Error> {
    let rows: [(MetricAggregation, f64); 7] = [
        (MetricAggregation::P50, summary.p50),
        (MetricAggregation::P99, summary.p99),
        (MetricAggregation::P999, summary.p999),
        (MetricAggregation::Mean, summary.mean),
        (MetricAggregation::Stddev, summary.stddev),
        (MetricAggregation::Ci95Lower, summary.ci95_lower),
        (MetricAggregation::Ci95Upper, summary.ci95_upper),
    ];
    for (agg, value) in rows {
        let row = CsvRow {
            run_metadata: metadata.clone(),
            tool: tool.to_string(),
            test_case: "burst".to_string(),
            feature_set: feature_set.to_string(),
            dimensions_json: dims.to_string(),
            metric_name: metric_name.to_string(),
            metric_unit: metric_unit.to_string(),
            metric_value: value,
            metric_aggregation: agg,
            // Task 2.8 host/dpdk/worktree identification — only bench-micro's
            // summariser populates these for now. Blank cells here.
            cpu_family: None,
            cpu_model_name: None,
            dpdk_version_pkgconfig: None,
            worktree_branch: None,
            uprof_session_id: None,
        };
        writer.serialize(&row)?;
    }
    Ok(())
}

/// Emit all CSV rows for one bucket aggregate — three metrics × seven
/// aggregations = 21 rows when the verdict is `Ok`, or a single
/// bucket-invalid marker row when the verdict is `Invalid`.
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

    match &aggregate.throughput_bps {
        Some(summary) => {
            emit_summary_rows(
                writer,
                metadata,
                tool,
                feature_set,
                &dims,
                "throughput_per_burst_bps",
                "bits_per_sec",
                summary,
            )?;
        }
        None => {
            // Bucket invalidated or no samples — emit a single marker
            // row with metric_value = 0.0 + Mean aggregation so the
            // row is not silently dropped by downstream tooling. The
            // `bucket_invalid` key in `dims` carries the reason.
            let row = CsvRow {
                run_metadata: metadata.clone(),
                tool: tool.to_string(),
                test_case: "burst".to_string(),
                feature_set: feature_set.to_string(),
                dimensions_json: dims.clone(),
                metric_name: "throughput_per_burst_bps".to_string(),
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
            return Ok(());
        }
    }
    if let Some(summary) = &aggregate.initiation_ns {
        emit_summary_rows(
            writer,
            metadata,
            tool,
            feature_set,
            &dims,
            "burst_initiation_ns",
            "ns",
            summary,
        )?;
    }
    if let Some(summary) = &aggregate.steady_bps {
        emit_summary_rows(
            writer,
            metadata,
            tool,
            feature_set,
            &dims,
            "burst_steady_bps",
            "bits_per_sec",
            summary,
        )?;
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
    fn grid_constants_match_spec_11_1() {
        assert_eq!(K_BYTES, &[64 * 1024, 256 * 1024, 1 << 20, 4 << 20, 16 << 20]);
        assert_eq!(G_MS, &[0, 1, 10, 100]);
        assert_eq!(K_BYTES.len() * G_MS.len(), BUCKET_COUNT);
        assert_eq!(BUCKET_COUNT, 20);
    }

    #[test]
    fn enumerate_grid_produces_20_buckets() {
        let grid = enumerate_grid();
        assert_eq!(grid.len(), BUCKET_COUNT);
    }

    #[test]
    fn enumerate_grid_is_k_outer_g_inner() {
        let grid = enumerate_grid();
        // First four entries: K=64 KiB with all four gaps.
        assert_eq!(grid[0], Bucket::new(64 * 1024, 0));
        assert_eq!(grid[1], Bucket::new(64 * 1024, 1));
        assert_eq!(grid[2], Bucket::new(64 * 1024, 10));
        assert_eq!(grid[3], Bucket::new(64 * 1024, 100));
        // Fifth entry: K=256 KiB with G=0.
        assert_eq!(grid[4], Bucket::new(256 * 1024, 0));
        // Last entry: K=16 MiB with G=100ms.
        assert_eq!(grid[BUCKET_COUNT - 1], Bucket::new(16 << 20, 100));
    }

    #[test]
    fn enumerate_grid_has_no_duplicates() {
        let grid = enumerate_grid();
        let unique: std::collections::HashSet<_> = grid.iter().collect();
        assert_eq!(unique.len(), grid.len());
    }

    #[test]
    fn enumerate_filtered_grid_k_subset_only() {
        // Run only K=1MiB and K=4MiB, all four gaps each → 2 × 4 = 8.
        let grid = enumerate_filtered_grid(Some(&[1 << 20, 4 << 20]), None).unwrap();
        assert_eq!(grid.len(), 8);
        for b in &grid {
            assert!(matches!(b.burst_bytes, 0x10_0000 | 0x40_0000));
        }
    }

    #[test]
    fn enumerate_filtered_grid_g_subset_only() {
        // Back-to-back only (G=0) → 5 × 1 = 5.
        let grid = enumerate_filtered_grid(None, Some(&[0])).unwrap();
        assert_eq!(grid.len(), 5);
        for b in &grid {
            assert_eq!(b.gap_ms, 0);
        }
    }

    #[test]
    fn enumerate_filtered_grid_no_match_errors() {
        // K value not in grid.
        let err = enumerate_filtered_grid(Some(&[123]), None).unwrap_err();
        assert!(err.contains("no K values match"));
    }

    #[test]
    fn enumerate_filtered_grid_empty_g_match_errors() {
        let err = enumerate_filtered_grid(None, Some(&[50])).unwrap_err();
        assert!(err.contains("no G values match"));
    }

    // ----------------------------------------------------------------
    // BurstSample::from_timestamps
    // ----------------------------------------------------------------

    #[test]
    fn burst_sample_primary_and_secondary_computation() {
        // 1 MiB burst in 1 ms: throughput_bps = 8 Gbps.
        // t_first_wire = t0 + 100 µs → initiation = 100_000 ns.
        // steady = 1 MiB / (1 ms - 100 µs) = 1 MiB / 900 µs.
        let k = 1 << 20;
        let t0 = 1_000_000_000u64;
        let t_first_wire = t0 + 100_000;
        let t1 = t0 + 1_000_000;
        let s = BurstSample::from_timestamps(k, t0, t_first_wire, t1);
        // Primary: 1 MiB = 8_388_608 bits; elapsed = 1 ms = 0.001 s.
        // throughput_bps = 8_388_608 / 0.001 = 8_388_608_000 bps ≈ 8.39 Gbps.
        let expect_throughput = 8_388_608f64 / 0.001;
        assert!(
            (s.throughput_bps - expect_throughput).abs() < 1.0,
            "got {}",
            s.throughput_bps
        );
        // Initiation = 100 µs = 100_000 ns.
        assert_eq!(s.initiation_ns, 100_000.0);
        // Steady = 8_388_608 / 0.0009.
        let expect_steady = 8_388_608f64 / 0.0009;
        assert!(
            (s.steady_bps - expect_steady).abs() < 10.0,
            "got {}",
            s.steady_bps
        );
    }

    #[test]
    fn burst_sample_t1_equals_t_first_wire_yields_zero_steady() {
        // Single-segment burst → t_first_wire == t1.
        let s = BurstSample::from_timestamps(1500, 0, 1_000, 1_000);
        assert_eq!(s.steady_bps, 0.0);
        // Primary still computes.
        assert!(s.throughput_bps > 0.0);
    }

    #[test]
    #[should_panic(expected = "t1 must be strictly > t0")]
    fn burst_sample_rejects_non_monotonic_t1() {
        let _ = BurstSample::from_timestamps(1500, 1_000, 1_000, 1_000);
    }

    #[test]
    #[should_panic(expected = "t_first_wire must be >= t0")]
    fn burst_sample_rejects_t_first_wire_before_t0() {
        let _ = BurstSample::from_timestamps(1500, 1_000, 500, 2_000);
    }

    #[test]
    #[should_panic(expected = "t1 must be >= t_first_wire")]
    fn burst_sample_rejects_t1_before_t_first_wire() {
        let _ = BurstSample::from_timestamps(1500, 0, 2_000, 1_000);
    }

    // ----------------------------------------------------------------
    // BucketAggregate::from_samples
    // ----------------------------------------------------------------

    fn synthetic_samples(n: usize) -> Vec<BurstSample> {
        (0..n)
            .map(|i| {
                let bytes = 64 * 1024;
                let t0 = 1_000_000u64 + i as u64 * 1_000_000;
                let t_first_wire = t0 + 1_000;
                // Vary the tail so the summary has spread.
                let t1 = t_first_wire + 1_000 + (i as u64 % 100);
                BurstSample::from_timestamps(bytes, t0, t_first_wire, t1)
            })
            .collect()
    }

    #[test]
    fn bucket_aggregate_happy_path_summarises_all_three_metrics() {
        let bucket = Bucket::new(64 * 1024, 0);
        let samples = synthetic_samples(10_000);
        let agg = BucketAggregate::from_samples(
            bucket,
            Stack::DpdkNet,
            &samples,
            BucketVerdict::Ok,
            Some(TxTsMode::TscFallback),
        );
        assert!(agg.verdict.is_ok());
        assert!(agg.throughput_bps.is_some());
        assert!(agg.initiation_ns.is_some());
        assert!(agg.steady_bps.is_some());
        assert_eq!(agg.measurement_sample_count, 10_000);
        // Percentiles: p50 <= p99 <= p999, and mean within stddev of p50
        let t = agg.throughput_bps.unwrap();
        assert!(t.p50 <= t.p99);
        assert!(t.p99 <= t.p999);
    }

    #[test]
    fn bucket_aggregate_invalid_verdict_skips_summary() {
        let bucket = Bucket::new(64 * 1024, 0);
        let samples = synthetic_samples(100);
        let agg = BucketAggregate::from_samples(
            bucket,
            Stack::DpdkNet,
            &samples,
            BucketVerdict::Invalid("NIC-bound".to_string()),
            Some(TxTsMode::TscFallback),
        );
        assert!(!agg.verdict.is_ok());
        assert!(agg.throughput_bps.is_none());
        assert!(agg.initiation_ns.is_none());
        assert!(agg.steady_bps.is_none());
        assert_eq!(agg.measurement_sample_count, 100);
    }

    #[test]
    fn bucket_aggregate_empty_samples_skips_summary() {
        let bucket = Bucket::new(64 * 1024, 0);
        let agg = BucketAggregate::from_samples(
            bucket,
            Stack::DpdkNet,
            &[],
            BucketVerdict::Ok,
            Some(TxTsMode::TscFallback),
        );
        assert!(agg.throughput_bps.is_none());
    }

    // ----------------------------------------------------------------
    // build_dimensions_json
    // ----------------------------------------------------------------

    #[test]
    fn dimensions_json_shape_matches_spec_11_3() {
        let dims = build_dimensions_json(
            Bucket::new(64 * 1024, 0),
            Stack::DpdkNet,
            None,
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&dims).unwrap();
        assert_eq!(parsed["workload"], "burst");
        assert_eq!(parsed["K_bytes"], 65_536i64);
        // G_ms serialises as a JSON number (0.0 or 0 — serde_json collapses
        // integer-valued f64 to a plain int in the Display form; accept
        // either so we're not brittle on serde-json releases).
        assert!(
            parsed["G_ms"] == serde_json::json!(0.0)
                || parsed["G_ms"] == serde_json::json!(0),
            "got G_ms = {:?}",
            parsed["G_ms"]
        );
        assert_eq!(parsed["stack"], "dpdk_net");
        assert!(parsed.get("bucket_invalid").is_none());
        assert!(parsed.get("tx_ts_mode").is_none());
    }

    #[test]
    fn dimensions_json_carries_invalid_reason_when_present() {
        let dims = build_dimensions_json(
            Bucket::new(1 << 20, 100),
            Stack::Mtcp,
            Some("NIC-bound"),
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&dims).unwrap();
        assert_eq!(parsed["stack"], "mtcp");
        assert_eq!(parsed["bucket_invalid"], "NIC-bound");
    }

    #[test]
    fn dimensions_json_is_stable_across_calls() {
        // bench-report groups rows by the verbatim string; serialisation
        // must be deterministic.
        let a = build_dimensions_json(Bucket::new(256 * 1024, 10), Stack::Mtcp, None, None);
        let b = build_dimensions_json(Bucket::new(256 * 1024, 10), Stack::Mtcp, None, None);
        assert_eq!(a, b);
    }

    #[test]
    fn dimensions_json_emits_tx_ts_mode_when_provided() {
        let hw = build_dimensions_json(
            Bucket::new(64 * 1024, 0),
            Stack::DpdkNet,
            None,
            Some(TxTsMode::HwTs.as_str()),
        );
        let parsed: serde_json::Value = serde_json::from_str(&hw).unwrap();
        assert_eq!(parsed["tx_ts_mode"], "hw_ts");
        let tsc = build_dimensions_json(
            Bucket::new(64 * 1024, 0),
            Stack::DpdkNet,
            None,
            Some(TxTsMode::TscFallback.as_str()),
        );
        let parsed: serde_json::Value = serde_json::from_str(&tsc).unwrap();
        assert_eq!(parsed["tx_ts_mode"], "tsc_fallback");
    }

    // ----------------------------------------------------------------
    // CSV row emission end-to-end: verify we emit the expected number
    // of rows per bucket. (Full CsvRow shape is tested elsewhere.)
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
        // Header + data rows. Subtract the header line to get data
        // count.
        let text = std::str::from_utf8(buf).unwrap();
        text.lines().count().saturating_sub(1)
    }

    #[test]
    fn emit_bucket_rows_happy_path_emits_21_rows() {
        let bucket = Bucket::new(64 * 1024, 0);
        let samples = synthetic_samples(1_000);
        let agg = BucketAggregate::from_samples(
            bucket,
            Stack::DpdkNet,
            &samples,
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
        // 3 metrics × 7 aggregations = 21 rows.
        assert_eq!(count_csv_rows(&buf), 21);
    }

    #[test]
    fn emit_bucket_rows_invalid_verdict_emits_single_marker_row() {
        let bucket = Bucket::new(16 << 20, 100);
        let agg = BucketAggregate::from_samples(
            bucket,
            Stack::DpdkNet,
            &[],
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

    // ----------------------------------------------------------------
    // CSV emit: HW-TS vs TSC-fallback tagging in dimensions_json.
    // Proves the tx_ts_mode wire path from BucketRun → BucketAggregate
    // → emit_bucket_rows → CSV column. Future-proofs the HW-TS row
    // being distinguishable once Engine::last_tx_hw_ts lands.
    // ----------------------------------------------------------------

    /// Read back a rendered CSV and extract the `dimensions_json`
    /// column from the first data row. The CSV writer escapes inner
    /// double quotes, so inspecting the raw buffer for
    /// `"tx_ts_mode":"hw_ts"` needs to go through the CSV parser.
    fn first_row_dimensions_json(buf: &[u8]) -> serde_json::Value {
        let mut reader = csv::Reader::from_reader(buf);
        let headers = reader.headers().unwrap().clone();
        let idx = headers
            .iter()
            .position(|h| h == "dimensions_json")
            .expect("dimensions_json column present");
        let row = reader
            .records()
            .next()
            .expect("at least one data row")
            .unwrap();
        serde_json::from_str(row.get(idx).unwrap()).unwrap()
    }

    #[test]
    fn emit_bucket_rows_tags_hw_ts_rows_in_dimensions_json() {
        let bucket = Bucket::new(64 * 1024, 0);
        let samples = synthetic_samples(100);
        let agg = BucketAggregate::from_samples(
            bucket,
            Stack::DpdkNet,
            &samples,
            BucketVerdict::Ok,
            Some(TxTsMode::HwTs),
        );
        let mut buf = Vec::new();
        {
            let mut writer = csv::Writer::from_writer(&mut buf);
            emit_bucket_rows(&mut writer, &sample_metadata(), "bench-vs-mtcp", "trading-latency", &agg)
                .unwrap();
            writer.flush().unwrap();
        }
        let dims = first_row_dimensions_json(&buf);
        assert_eq!(dims["tx_ts_mode"], "hw_ts");
    }

    #[test]
    fn emit_bucket_rows_tags_tsc_fallback_rows_in_dimensions_json() {
        let bucket = Bucket::new(64 * 1024, 0);
        let samples = synthetic_samples(100);
        let agg = BucketAggregate::from_samples(
            bucket,
            Stack::DpdkNet,
            &samples,
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
        let dims = first_row_dimensions_json(&buf);
        assert_eq!(dims["tx_ts_mode"], "tsc_fallback");
    }

    #[test]
    fn emit_bucket_rows_omits_tx_ts_mode_when_none() {
        // mTCP stub rows don't carry a tx_ts_mode; absence = downstream
        // reports group them separately from the dpdk_net rows.
        let bucket = Bucket::new(64 * 1024, 0);
        let agg = BucketAggregate::from_samples(
            bucket,
            Stack::Mtcp,
            &[],
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
        let dims = first_row_dimensions_json(&buf);
        assert!(
            dims.get("tx_ts_mode").is_none(),
            "expected dimensions_json to omit tx_ts_mode when None; got {dims}"
        );
    }
}
