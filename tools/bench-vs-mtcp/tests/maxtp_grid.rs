//! Integration tests for the `maxtp` sub-workload (spec §11.2).
//!
//! These tests don't touch DPDK / a live peer / libmtcp. They cover
//! the pure-Rust primitives: grid enumeration, per-window sample
//! construction, preflight check helpers, sanity-invariant math, and
//! the mTCP stub's config validation.

use bench_vs_mtcp::dpdk_maxtp::TxTsMode;
use bench_vs_mtcp::maxtp::{
    self, check_sanity_invariant, enumerate_filtered_grid, enumerate_grid, Bucket,
    BucketAggregate, MaxtpSample, BUCKET_COUNT, C_CONNS, DURATION_SECS, WARMUP_SECS, W_BYTES,
};
use bench_vs_mtcp::mtcp::{self, MaxtpConfig};
use bench_vs_mtcp::preflight::BucketVerdict;
use bench_vs_mtcp::Stack;

// ---------------------------------------------------------------------------
// Grid enumeration — spec §11.2 W × C = 28 buckets.
// ---------------------------------------------------------------------------

#[test]
fn grid_has_exactly_28_buckets_per_spec() {
    assert_eq!(BUCKET_COUNT, 28);
    assert_eq!(W_BYTES.len() * C_CONNS.len(), 28);
    let grid = enumerate_grid();
    assert_eq!(grid.len(), 28);
}

#[test]
fn grid_w_axis_values_match_spec_11_2() {
    // 64 B, 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB.
    assert_eq!(W_BYTES.len(), 7);
    assert_eq!(W_BYTES[0], 64);
    assert_eq!(W_BYTES[1], 256);
    assert_eq!(W_BYTES[2], 1024);
    assert_eq!(W_BYTES[3], 4096);
    assert_eq!(W_BYTES[4], 16_384);
    assert_eq!(W_BYTES[5], 65_536);
    assert_eq!(W_BYTES[6], 262_144);
}

#[test]
fn grid_c_axis_values_match_spec_11_2() {
    // 1, 4, 16, 64.
    assert_eq!(C_CONNS, &[1, 4, 16, 64]);
}

#[test]
fn grid_warmup_and_duration_match_spec_11_2() {
    assert_eq!(WARMUP_SECS, 10);
    assert_eq!(DURATION_SECS, 60);
}

#[test]
fn grid_has_no_duplicate_buckets() {
    let grid = enumerate_grid();
    let unique: std::collections::HashSet<_> = grid.iter().collect();
    assert_eq!(unique.len(), grid.len(), "duplicate bucket in grid");
}

#[test]
fn grid_subset_filter_accepts_partial_w() {
    // Run only W=4 KiB — all 4 C values → 4 buckets.
    let grid = enumerate_filtered_grid(Some(&[4096]), None).unwrap();
    assert_eq!(grid.len(), 4);
    for b in &grid {
        assert_eq!(b.write_bytes, 4096);
    }
}

#[test]
fn grid_subset_filter_accepts_partial_c() {
    // Single-connection only → 7 W values × 1 = 7 buckets.
    let grid = enumerate_filtered_grid(None, Some(&[1])).unwrap();
    assert_eq!(grid.len(), 7);
    for b in &grid {
        assert_eq!(b.conn_count, 1);
    }
}

#[test]
fn grid_subset_filter_accepts_intersection() {
    // Run only W=64 KiB and C=64 → 1 bucket.
    let grid = enumerate_filtered_grid(Some(&[65_536]), Some(&[64])).unwrap();
    assert_eq!(grid.len(), 1);
    assert_eq!(grid[0], Bucket::new(65_536, 64));
}

#[test]
fn grid_subset_filter_rejects_unknown_w() {
    let err = enumerate_filtered_grid(Some(&[8192]), None).unwrap_err();
    assert!(err.contains("no W values match"));
}

#[test]
fn grid_subset_filter_rejects_unknown_c() {
    let err = enumerate_filtered_grid(None, Some(&[32])).unwrap_err();
    assert!(err.contains("no C values match"));
}

#[test]
fn grid_is_w_outer_c_inner() {
    let grid = enumerate_grid();
    // First four entries: W=64 B × all four C values in order.
    assert_eq!(grid[0], Bucket::new(64, 1));
    assert_eq!(grid[1], Bucket::new(64, 4));
    assert_eq!(grid[2], Bucket::new(64, 16));
    assert_eq!(grid[3], Bucket::new(64, 64));
    // Fifth entry: W=256 B, C=1.
    assert_eq!(grid[4], Bucket::new(256, 1));
    // Last entry: W=256 KiB, C=64.
    assert_eq!(grid[BUCKET_COUNT - 1], Bucket::new(262_144, 64));
}

// ---------------------------------------------------------------------------
// Sample math — MaxtpSample::from_window.
// ---------------------------------------------------------------------------

#[test]
fn sample_goodput_matches_spec_11_2_definition() {
    // Spec: sustained goodput = (bytes ACKed in window) / T, bytes/sec.
    // We emit bits_per_sec (×8 for CSV unit consistency with burst).
    // 1 GiB ACKed in 60 s = 17_895_697 bytes/s = 143_165_576 bps.
    let one_gib: u64 = 1 << 30;
    let one_min_ns: u64 = 60 * 1_000_000_000;
    let s = MaxtpSample::from_window(one_gib, 1_000_000, one_min_ns);
    let expected_bps = (one_gib as f64) * 8.0 / 60.0;
    assert!(
        (s.goodput_bps - expected_bps).abs() / expected_bps < 1e-9,
        "goodput_bps = {} expected {expected_bps}",
        s.goodput_bps
    );
    // pps = 1M packets / 60 s ≈ 16_666.67.
    assert!((s.pps - 16_666.666).abs() < 1.0, "pps = {}", s.pps);
}

#[test]
fn sample_zero_bytes_yields_zero_goodput() {
    let s = MaxtpSample::from_window(0, 0, 60_000_000_000);
    assert_eq!(s.goodput_bps, 0.0);
    assert_eq!(s.pps, 0.0);
}

#[test]
#[should_panic(expected = "duration_ns must be > 0")]
fn sample_rejects_zero_duration() {
    let _ = MaxtpSample::from_window(1_000_000, 100, 0);
}

// ---------------------------------------------------------------------------
// BucketAggregate
// ---------------------------------------------------------------------------

#[test]
fn bucket_aggregate_happy_path_keeps_sample() {
    let sample = MaxtpSample::from_window(1_000_000, 100, 60_000_000_000);
    let agg = BucketAggregate::from_sample(
        Bucket::new(4096, 4),
        Stack::DpdkNet,
        Some(sample),
        BucketVerdict::Ok,
        Some(TxTsMode::TscFallback),
    );
    assert!(agg.sample.is_some());
}

#[test]
fn bucket_aggregate_invalid_verdict_drops_sample() {
    let sample = MaxtpSample::from_window(1_000_000, 100, 60_000_000_000);
    let agg = BucketAggregate::from_sample(
        Bucket::new(4096, 4),
        Stack::DpdkNet,
        Some(sample),
        BucketVerdict::Invalid("precondition fail".to_string()),
        Some(TxTsMode::TscFallback),
    );
    assert!(agg.sample.is_none());
}

#[test]
fn bucket_aggregate_override_verdict_flips() {
    let sample = MaxtpSample::from_window(1_000_000_000, 500_000, 60_000_000_000);
    let mut agg = BucketAggregate::from_sample(
        Bucket::new(65_536, 64),
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

// ---------------------------------------------------------------------------
// Sanity invariant logic — spec §11.2.
// ---------------------------------------------------------------------------

#[test]
fn sanity_invariant_passes_when_sent_equals_acked() {
    // Entire stack flush ACKed by window close → unacked = 0.
    assert!(check_sanity_invariant(1_000_000, 1_000_000, 1 << 20).is_ok());
}

#[test]
fn sanity_invariant_passes_when_gap_is_within_inflight_bound() {
    // 512 KiB unacked at window close, cwnd+rwnd = 1 MiB → ok.
    let sent = 1u64 << 20;
    let acked = 1u64 << 19;
    let inflight_bound = 1u64 << 20;
    assert!(check_sanity_invariant(acked, sent, inflight_bound).is_ok());
}

#[test]
fn sanity_invariant_fails_when_acked_greater_than_sent() {
    // Impossible: can't ACK more than was sent.
    let err = check_sanity_invariant(2048, 1024, 64 * 1024).unwrap_err();
    assert!(err.contains("exceed tx_payload_bytes"), "err = {err}");
}

#[test]
fn sanity_invariant_fails_when_unacked_exceeds_inflight_bound() {
    // 2 MiB sent, 0 ACKed, but cwnd+rwnd only 1 MiB — ε exceeds bound.
    let sent = 2u64 << 20;
    let acked = 0u64;
    let inflight_bound = 1u64 << 20;
    let err = check_sanity_invariant(acked, sent, inflight_bound).unwrap_err();
    assert!(err.contains("exceed cwnd+rwnd bound"), "err = {err}");
}

// ---------------------------------------------------------------------------
// CSV row shape — one bucket's emit path produces the expected tuples.
// ---------------------------------------------------------------------------

#[test]
fn emit_bucket_rows_dimensions_json_matches_spec_11_3_shape() {
    let bucket = Bucket::new(65_536, 16);
    let sample = MaxtpSample::from_window(10_000_000, 50_000, 60_000_000_000);
    let agg = BucketAggregate::from_sample(
        bucket,
        Stack::DpdkNet,
        Some(sample),
        BucketVerdict::Ok,
        Some(TxTsMode::TscFallback),
    );
    let metadata = sample_metadata();
    let mut buf = Vec::new();
    {
        let mut w = csv::Writer::from_writer(&mut buf);
        maxtp::emit_bucket_rows(&mut w, &metadata, "bench-vs-mtcp", "trading-latency", &agg)
            .unwrap();
        w.flush().unwrap();
    }
    // Parse back and verify the dimensions_json shape.
    let mut reader = csv::Reader::from_reader(buf.as_slice());
    let headers = reader.headers().unwrap().clone();
    let dims_idx = headers
        .iter()
        .position(|h| h == "dimensions_json")
        .expect("dimensions_json column present");
    let metric_name_idx = headers.iter().position(|h| h == "metric_name").unwrap();
    let metric_unit_idx = headers.iter().position(|h| h == "metric_unit").unwrap();
    let metric_agg_idx = headers
        .iter()
        .position(|h| h == "metric_aggregation")
        .unwrap();
    let mut seen_goodput = false;
    let mut seen_pps = false;
    let mut row_count = 0;
    for rec in reader.records() {
        let rec = rec.unwrap();
        row_count += 1;
        let dims: serde_json::Value =
            serde_json::from_str(rec.get(dims_idx).unwrap()).unwrap();
        assert_eq!(dims["workload"], "maxtp");
        assert_eq!(dims["W_bytes"], serde_json::json!(65_536i64));
        assert_eq!(dims["C"], serde_json::json!(16i64));
        assert_eq!(dims["stack"], "dpdk_net");
        assert!(dims.get("bucket_invalid").is_none());
        // CSV schema consistency with T12 fixup — every dpdk_net row
        // tags the TX-TS measurement source.
        assert_eq!(dims["tx_ts_mode"], "tsc_fallback");
        let metric_name = rec.get(metric_name_idx).unwrap();
        let metric_unit = rec.get(metric_unit_idx).unwrap();
        let metric_agg = rec.get(metric_agg_idx).unwrap();
        // Maxtp emits only `mean` aggregation — one sample per bucket.
        assert_eq!(metric_agg, "mean");
        match metric_name {
            "sustained_goodput_bps" => {
                assert_eq!(metric_unit, "bits_per_sec");
                seen_goodput = true;
            }
            "tx_pps" => {
                assert_eq!(metric_unit, "pps");
                seen_pps = true;
            }
            other => panic!("unexpected metric_name {other}"),
        }
    }
    assert_eq!(row_count, 2, "happy-path bucket emits 2 rows");
    assert!(seen_goodput);
    assert!(seen_pps);
}

#[test]
fn emit_bucket_rows_invalid_bucket_emits_single_marker() {
    let bucket = Bucket::new(262_144, 64);
    let agg = BucketAggregate::from_sample(
        bucket,
        Stack::DpdkNet,
        None,
        BucketVerdict::Invalid("NIC-bound".to_string()),
        Some(TxTsMode::TscFallback),
    );
    let metadata = sample_metadata();
    let mut buf = Vec::new();
    {
        let mut w = csv::Writer::from_writer(&mut buf);
        maxtp::emit_bucket_rows(&mut w, &metadata, "bench-vs-mtcp", "trading-latency", &agg)
            .unwrap();
        w.flush().unwrap();
    }
    let row_count = std::str::from_utf8(&buf).unwrap().lines().count() - 1;
    assert_eq!(row_count, 1);
    let mut reader = csv::Reader::from_reader(buf.as_slice());
    let headers = reader.headers().unwrap().clone();
    let dims_idx = headers
        .iter()
        .position(|h| h == "dimensions_json")
        .unwrap();
    let rec = reader.records().next().unwrap().unwrap();
    let dims: serde_json::Value =
        serde_json::from_str(rec.get(dims_idx).unwrap()).unwrap();
    assert_eq!(dims["bucket_invalid"], "NIC-bound");
}

// ---------------------------------------------------------------------------
// mTCP maxtp stub — config validation surface.
// ---------------------------------------------------------------------------

fn good_mtcp_maxtp_cfg() -> MaxtpConfig<'static> {
    MaxtpConfig {
        peer_ip: "10.0.0.42",
        peer_port: 10_001,
        peer_binary: "/opt/mtcp-peer/bench-peer",
        write_bytes: 4096,
        conn_count: 4,
        warmup_secs: 10,
        duration_secs: 60,
        mss: 1460,
    }
}

#[test]
fn mtcp_maxtp_stub_accepts_good_shape() {
    assert!(mtcp::validate_maxtp_config(&good_mtcp_maxtp_cfg()).is_ok());
}

#[test]
fn mtcp_maxtp_stub_run_returns_unimplemented() {
    match mtcp::run_maxtp_workload(&good_mtcp_maxtp_cfg()) {
        Err(mtcp::Error::Unimplemented) => {}
        other => panic!("expected Unimplemented, got {other:?}"),
    }
}

#[test]
fn mtcp_maxtp_stub_rejects_zero_write_bytes() {
    let mut c = good_mtcp_maxtp_cfg();
    c.write_bytes = 0;
    assert!(mtcp::validate_maxtp_config(&c).is_err());
}

#[test]
fn mtcp_maxtp_stub_rejects_zero_conn_count() {
    let mut c = good_mtcp_maxtp_cfg();
    c.conn_count = 0;
    assert!(mtcp::validate_maxtp_config(&c).is_err());
}

#[test]
fn mtcp_maxtp_stub_rejects_zero_duration() {
    let mut c = good_mtcp_maxtp_cfg();
    c.duration_secs = 0;
    assert!(mtcp::validate_maxtp_config(&c).is_err());
}

#[test]
fn mtcp_maxtp_stub_rejects_relative_peer_binary() {
    let mut c = good_mtcp_maxtp_cfg();
    c.peer_binary = "bench-peer";
    let err = mtcp::validate_maxtp_config(&c).unwrap_err();
    assert!(err.contains("absolute path"));
}

fn sample_metadata() -> bench_common::run_metadata::RunMetadata {
    use bench_common::preconditions::{PreconditionMode, Preconditions};
    bench_common::run_metadata::RunMetadata {
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
