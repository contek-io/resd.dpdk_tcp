//! Integration tests for the `burst` sub-workload (spec §11.1).
//!
//! These tests don't touch DPDK / a live peer / libmtcp. They cover
//! the pure-Rust primitives: grid enumeration, per-burst sample
//! aggregation, preflight check helpers, and the mTCP stub's config
//! validation. The real end-to-end smoke (dpdk_net + kernel peer +
//! mTCP peer) lives post-AMI bake (Plan A T6+T7).

use bench_vs_mtcp::burst::{
    enumerate_filtered_grid, enumerate_grid, Bucket, BucketAggregate, BurstSample, BUCKET_COUNT,
    G_MS, K_BYTES,
};
use bench_vs_mtcp::dpdk_burst::TxTsMode;
use bench_vs_mtcp::maxtp;
use bench_vs_mtcp::mtcp::{self, MtcpConfig};
use bench_vs_mtcp::preflight::{
    check_mss_and_burst_agreement, check_nic_saturation_bps, check_peer_window,
    check_sanity_invariant, BucketVerdict,
};
use bench_vs_mtcp::{Stack, Workload};

// ---------------------------------------------------------------------------
// Stack + Workload enums.
// ---------------------------------------------------------------------------

#[test]
fn stack_parse_covers_both_stacks() {
    assert_eq!(Stack::parse("dpdk").unwrap(), Stack::DpdkNet);
    assert_eq!(Stack::parse("dpdk_net").unwrap(), Stack::DpdkNet);
    assert_eq!(Stack::parse("mtcp").unwrap(), Stack::Mtcp);
    assert!(Stack::parse("linux").is_err());
}

#[test]
fn stack_as_dimension_is_the_documented_string() {
    assert_eq!(Stack::DpdkNet.as_dimension(), "dpdk_net");
    assert_eq!(Stack::Mtcp.as_dimension(), "mtcp");
}

#[test]
fn workload_parse_accepts_burst_and_maxtp() {
    assert_eq!(Workload::parse("burst").unwrap(), Workload::Burst);
    assert_eq!(Workload::parse("maxtp").unwrap(), Workload::Maxtp);
    assert!(Workload::parse("loopback").is_err());
}

// ---------------------------------------------------------------------------
// Grid enumeration — spec §11.1 K × G = 20 buckets.
// ---------------------------------------------------------------------------

#[test]
fn grid_has_exactly_20_buckets_per_spec() {
    assert_eq!(BUCKET_COUNT, 20);
    assert_eq!(K_BYTES.len() * G_MS.len(), 20);
    let grid = enumerate_grid();
    assert_eq!(grid.len(), 20);
}

#[test]
fn grid_k_axis_values_match_spec_11_1() {
    // 64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB.
    assert_eq!(K_BYTES.len(), 5);
    assert_eq!(K_BYTES[0], 64 * 1024);
    assert_eq!(K_BYTES[1], 256 * 1024);
    assert_eq!(K_BYTES[2], 1 << 20);
    assert_eq!(K_BYTES[3], 4 << 20);
    assert_eq!(K_BYTES[4], 16 << 20);
}

#[test]
fn grid_g_axis_values_match_spec_11_1() {
    // 0 ms, 1 ms, 10 ms, 100 ms.
    assert_eq!(G_MS, &[0, 1, 10, 100]);
}

#[test]
fn grid_has_no_duplicate_buckets() {
    let grid = enumerate_grid();
    let unique: std::collections::HashSet<_> = grid.iter().collect();
    assert_eq!(unique.len(), grid.len(), "duplicate bucket in grid");
}

#[test]
fn grid_subset_filter_accepts_partial_k() {
    // Run only K=1MiB — 4 buckets.
    let grid = enumerate_filtered_grid(Some(&[1 << 20]), None).unwrap();
    assert_eq!(grid.len(), 4);
    for b in &grid {
        assert_eq!(b.burst_bytes, 1 << 20);
    }
}

#[test]
fn grid_subset_filter_accepts_partial_g() {
    // Run only G=0ms (back-to-back) — 5 buckets.
    let grid = enumerate_filtered_grid(None, Some(&[0])).unwrap();
    assert_eq!(grid.len(), 5);
    for b in &grid {
        assert_eq!(b.gap_ms, 0);
    }
}

#[test]
fn grid_subset_filter_accepts_intersection() {
    // Run only K=1MiB and G=100ms — 1 bucket.
    let grid = enumerate_filtered_grid(Some(&[1 << 20]), Some(&[100])).unwrap();
    assert_eq!(grid.len(), 1);
    assert_eq!(grid[0], Bucket::new(1 << 20, 100));
}

#[test]
fn grid_subset_filter_rejects_unknown_k() {
    let err = enumerate_filtered_grid(Some(&[12345]), None).unwrap_err();
    assert!(err.contains("no K values match"));
}

#[test]
fn grid_subset_filter_rejects_unknown_g() {
    let err = enumerate_filtered_grid(None, Some(&[5])).unwrap_err();
    assert!(err.contains("no G values match"));
}

// ---------------------------------------------------------------------------
// Sample aggregation.
// ---------------------------------------------------------------------------

#[test]
fn burst_sample_from_timestamps_matches_spec_11_1_contract() {
    // 4 MiB burst in exactly 1 ms. t_first_wire = t0 + 50 µs.
    let k = 4 << 20;
    let t0 = 10u64 * 1_000_000_000;
    let t_first_wire = t0 + 50_000;
    let t1 = t0 + 1_000_000;
    let s = BurstSample::from_timestamps(k, t0, t_first_wire, t1);
    // throughput_bps = K·8 / (t1 - t0 in seconds).
    let expect = (k as f64) * 8.0 / 0.001;
    assert!(
        (s.throughput_bps - expect).abs() < 1.0,
        "throughput = {}",
        s.throughput_bps
    );
    // initiation = t_first_wire - t0 = 50_000 ns.
    assert_eq!(s.initiation_ns, 50_000.0);
    // steady > throughput since the initiation portion is excluded.
    assert!(s.steady_bps > s.throughput_bps);
}

#[test]
fn bucket_aggregate_happy_path_summarises_all_metrics() {
    let bucket = Bucket::new(64 * 1024, 0);
    let samples: Vec<BurstSample> = (0..10_000)
        .map(|i| {
            let t0 = 1_000_000u64 + i as u64 * 1_000_000;
            let t_first_wire = t0 + 500;
            let t1 = t_first_wire + 500 + (i as u64 % 50);
            BurstSample::from_timestamps(64 * 1024, t0, t_first_wire, t1)
        })
        .collect();
    let agg = BucketAggregate::from_samples(
        bucket,
        Stack::DpdkNet,
        &samples,
        BucketVerdict::Ok,
        Some(TxTsMode::TscFallback),
    );
    assert!(agg.throughput_bps.is_some());
    assert!(agg.initiation_ns.is_some());
    assert!(agg.steady_bps.is_some());
    let t = agg.throughput_bps.unwrap();
    assert!(t.p50 <= t.p99);
    assert!(t.p99 <= t.p999);
}

#[test]
fn bucket_aggregate_invalid_verdict_skips_all_summaries() {
    let bucket = Bucket::new(16 << 20, 100);
    let samples: Vec<BurstSample> = vec![];
    let agg = BucketAggregate::from_samples(
        bucket,
        Stack::DpdkNet,
        &samples,
        BucketVerdict::Invalid("NIC-bound".to_string()),
        Some(TxTsMode::TscFallback),
    );
    assert!(agg.throughput_bps.is_none());
    assert!(agg.initiation_ns.is_none());
    assert!(agg.steady_bps.is_none());
}

// ---------------------------------------------------------------------------
// Pre-run check logic.
// ---------------------------------------------------------------------------

#[test]
fn preflight_peer_window_gate_matches_spec() {
    // Pass: peer rwnd ≥ K.
    assert!(check_peer_window(64 * 1024, 64 * 1024).is_ok());
    assert!(check_peer_window(1 << 20, 64 * 1024).is_ok());
    // Fail: peer rwnd < K.
    assert!(!check_peer_window(32 * 1024, 64 * 1024).is_ok());
}

#[test]
fn preflight_mss_and_burst_agreement_gate_matches_spec() {
    // Both stacks at MSS=1460, TX burst=32 → pass.
    assert!(check_mss_and_burst_agreement(1460, 1460, 32, 32).is_ok());
    // MSS mismatch → fail.
    assert!(!check_mss_and_burst_agreement(1460, 1500, 32, 32).is_ok());
    // TX burst mismatch → fail.
    assert!(!check_mss_and_burst_agreement(1460, 1460, 32, 64).is_ok());
}

#[test]
fn preflight_nic_saturation_gate_uses_70pct_ceiling_per_spec() {
    // 69% utilization → pass.
    assert!(check_nic_saturation_bps(69_000_000_000, 100_000_000_000).is_ok());
    // Exactly 70% → pass (spec says ≤ 70%).
    assert!(check_nic_saturation_bps(70_000_000_000, 100_000_000_000).is_ok());
    // 71% → fail.
    assert!(!check_nic_saturation_bps(71_000_000_000, 100_000_000_000).is_ok());
}

#[test]
fn preflight_sanity_invariant_gate_enforces_exact_equality() {
    assert!(check_sanity_invariant(1_048_576_000, 1_048_576_000).is_ok());
    assert!(check_sanity_invariant(1_048_576_000, 1_048_575_999).is_err());
    assert!(check_sanity_invariant(1_048_576_000, 1_048_576_001).is_err());
}

// ---------------------------------------------------------------------------
// mTCP stub — config validation surface.
// ---------------------------------------------------------------------------

fn good_mtcp_cfg() -> MtcpConfig<'static> {
    MtcpConfig {
        peer_ip: "10.0.0.42",
        peer_port: 10_001,
        peer_binary: "/opt/mtcp-peer/bench-peer",
        burst_bytes: 64 * 1024,
        gap_ms: 0,
        bursts: 10_000,
        warmup: 100,
        mss: 1460,
    }
}

#[test]
fn mtcp_stub_validate_config_accepts_good_shape() {
    assert!(mtcp::validate_config(&good_mtcp_cfg()).is_ok());
}

#[test]
fn mtcp_stub_run_burst_workload_returns_unimplemented() {
    let cfg = good_mtcp_cfg();
    match mtcp::run_burst_workload(&cfg) {
        Err(mtcp::Error::Unimplemented) => {}
        other => panic!("expected Error::Unimplemented, got {other:?}"),
    }
}

#[test]
fn mtcp_stub_rejects_malformed_peer_binary() {
    let mut c = good_mtcp_cfg();
    c.peer_binary = "bench-peer"; // relative — must be absolute.
    let err = mtcp::validate_config(&c).unwrap_err();
    assert!(err.contains("absolute path"), "err = {err}");
}

#[test]
fn mtcp_stub_rejects_empty_peer_ip() {
    let mut c = good_mtcp_cfg();
    c.peer_ip = "";
    let err = mtcp::validate_config(&c).unwrap_err();
    assert!(err.contains("peer-ip"));
}

#[test]
fn mtcp_stub_rejects_zero_port() {
    let mut c = good_mtcp_cfg();
    c.peer_port = 0;
    assert!(mtcp::validate_config(&c).is_err());
}

#[test]
fn mtcp_stub_rejects_zero_k() {
    let mut c = good_mtcp_cfg();
    c.burst_bytes = 0;
    assert!(mtcp::validate_config(&c).is_err());
}

#[test]
fn mtcp_stub_rejects_zero_bursts() {
    let mut c = good_mtcp_cfg();
    c.bursts = 0;
    assert!(mtcp::validate_config(&c).is_err());
}

#[test]
fn mtcp_stub_rejects_zero_mss() {
    let mut c = good_mtcp_cfg();
    c.mss = 0;
    assert!(mtcp::validate_config(&c).is_err());
}

// ---------------------------------------------------------------------------
// maxtp placeholder — grid constants only; runner is todo!() in T13.
// ---------------------------------------------------------------------------

#[test]
fn maxtp_placeholder_grid_constants_match_spec_11_2() {
    assert_eq!(maxtp::W_BYTES, &[64, 256, 1024, 4096, 16_384, 65_536, 262_144]);
    assert_eq!(maxtp::C_CONNS, &[1, 4, 16, 64]);
    assert_eq!(maxtp::BUCKET_COUNT, 28);
    assert_eq!(maxtp::W_BYTES.len() * maxtp::C_CONNS.len(), 28);
}

// ---------------------------------------------------------------------------
// CSV row shape — one bucket's emit path produces the expected
// (dimensions_json, metric_name, metric_unit) tuples.
// ---------------------------------------------------------------------------

#[test]
fn emit_bucket_rows_dimensions_json_matches_spec_11_3_shape() {
    let bucket = Bucket::new(1 << 20, 10);
    let samples: Vec<BurstSample> = (0..100)
        .map(|i| {
            let t0 = i as u64 * 1_000;
            BurstSample::from_timestamps(1 << 20, t0, t0 + 100, t0 + 1_000)
        })
        .collect();
    let agg = BucketAggregate::from_samples(
        bucket,
        Stack::DpdkNet,
        &samples,
        BucketVerdict::Ok,
        Some(TxTsMode::TscFallback),
    );
    let metadata = sample_metadata();
    let mut buf = Vec::new();
    {
        let mut w = csv::Writer::from_writer(&mut buf);
        bench_vs_mtcp::burst::emit_bucket_rows(&mut w, &metadata, "bench-vs-mtcp", "trading-latency", &agg)
            .unwrap();
        w.flush().unwrap();
    }
    // Parse back and verify the dimensions_json shape on at least one row.
    let mut reader = csv::Reader::from_reader(buf.as_slice());
    let headers = reader.headers().unwrap().clone();
    let dims_idx = headers
        .iter()
        .position(|h| h == "dimensions_json")
        .expect("dimensions_json column present");
    let metric_name_idx = headers.iter().position(|h| h == "metric_name").unwrap();
    let metric_unit_idx = headers.iter().position(|h| h == "metric_unit").unwrap();
    let mut seen_throughput = false;
    let mut seen_initiation = false;
    let mut seen_steady = false;
    for rec in reader.records() {
        let rec = rec.unwrap();
        let dims: serde_json::Value = serde_json::from_str(rec.get(dims_idx).unwrap()).unwrap();
        assert_eq!(dims["workload"], "burst");
        assert_eq!(dims["K_bytes"], serde_json::json!(1_048_576i64));
        // G_ms: either 10.0 or 10 (serde_json collapses integer-valued
        // f64 in Display, accept both).
        assert!(
            dims["G_ms"] == serde_json::json!(10.0)
                || dims["G_ms"] == serde_json::json!(10),
            "G_ms = {:?}",
            dims["G_ms"]
        );
        assert_eq!(dims["stack"], "dpdk_net");
        assert!(dims.get("bucket_invalid").is_none());
        // I3: every dpdk_net row tags the TX-TS measurement source so
        // CSV consumers can filter HW-TS vs TSC-fallback rows.
        assert_eq!(dims["tx_ts_mode"], "tsc_fallback");
        let metric_name = rec.get(metric_name_idx).unwrap();
        let metric_unit = rec.get(metric_unit_idx).unwrap();
        match metric_name {
            "throughput_per_burst_bps" => {
                // I1: throughput unit is spelled out as `bits_per_sec`
                // (not the ambiguous `bps`) per spec §14.1.
                assert_eq!(metric_unit, "bits_per_sec");
                seen_throughput = true;
            }
            "burst_initiation_ns" => {
                assert_eq!(metric_unit, "ns");
                seen_initiation = true;
            }
            "burst_steady_bps" => {
                assert_eq!(metric_unit, "bits_per_sec");
                seen_steady = true;
            }
            other => panic!("unexpected metric_name {other}"),
        }
    }
    assert!(seen_throughput, "throughput_per_burst_bps row missing");
    assert!(seen_initiation, "burst_initiation_ns row missing");
    assert!(seen_steady, "burst_steady_bps row missing");
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
