//! bench-micro::summarize — reads `target/criterion/**/new/sample.json`
//! emitted by cargo-criterion and produces a summarized CSV matching
//! `bench-common`'s `CsvRow` schema, ready for `bench-report` ingest.
//!
//! Criterion's native JSON remains the authoritative sidecar (flame-graph
//! and regression-diff consumers read it directly, per spec §13); the
//! CSV here is the unified-schema projection for the cross-tool report.
//!
//! # Why `sample.json` and not `estimates.json`
//!
//! `estimates.json` carries only the summary estimators Criterion fits
//! from the linear-regression model: `mean`, `median`, `std_dev`,
//! `median_abs_dev`, `slope`. It does NOT expose percentile point
//! estimates (p99, p999) that spec §5 line 270 requires. `sample.json`
//! carries the raw per-sample iteration timings; we flatten them to
//! per-iter costs and run `bench_common::percentile::summarize` to
//! emit all seven aggregations (p50, p99, p999, mean, stddev,
//! ci95_lower, ci95_upper).
//!
//! `sample.json`'s layout follows Criterion's native schema:
//!
//! ```json
//! {"sampling_mode":"Linear","iters":[10,20,...],"times":[1234.5,2345.6,...]}
//! ```
//!
//! `times[i]` is the total wall time (ns, as f64) for a sampling batch
//! that ran `iters[i]` iterations — per-iter cost is `times[i] / iters[i]`.
//!
//! If `sample.json` is absent for any reason (e.g. older cached
//! criterion output), fall back to `estimates.json` and emit the
//! four aggregations we can recover (mean/stddev/ci95_lower/ci95_upper)
//! — percentile cells are simply omitted, not fabricated.
//!
//! # Usage
//!
//! ```text
//! summarize [input_root] [output_csv]
//! ```
//!
//! Defaults:
//! - input_root = `target/criterion`
//! - output_csv = `target/bench-results/bench-micro/<YYYYmmddTHHMMSSZ>.csv`
//!
//! Empty / missing input root produces a header-only CSV and "wrote 0
//! rows" on stderr — matches the spec §5.5 smoke test.

use bench_common::csv_row::{CsvRow, MetricAggregation, COLUMNS};
use bench_common::percentile::summarize;
use bench_common::preconditions::{PreconditionMode, PreconditionValue, Preconditions};
use bench_common::run_metadata::RunMetadata;

/// Host / DPDK / worktree identification — captured once per `summarize`
/// run and stamped onto every emitted `CsvRow`. Task 2.8 columns:
/// `cpu_family`, `cpu_model_name`, `dpdk_version_pkgconfig`,
/// `worktree_branch`, `uprof_session_id`. Every field is `Option` because
/// any of the probes (reading `/proc/cpuinfo`, spawning `pkg-config`, etc.)
/// can fail on a minimal CI box — in which case the CSV emits the empty
/// cell per spec §3 / §4.4.
#[derive(Debug, Clone)]
struct HostMetadata {
    cpu_family: Option<u32>,
    cpu_model_name: Option<String>,
    dpdk_version_pkgconfig: Option<String>,
    worktree_branch: Option<String>,
    uprof_session_id: Option<String>,
}

impl HostMetadata {
    fn capture() -> Self {
        let (cpu_family, cpu_model_name) = cpu_family_model();
        Self {
            cpu_family,
            cpu_model_name,
            dpdk_version_pkgconfig: dpdk_version_pkgconfig(),
            worktree_branch: worktree_branch(),
            uprof_session_id: uprof_session_id(),
        }
    }
}

/// Parse `/proc/cpuinfo` to extract the numeric `cpu family` and the
/// `model name` marketing string. Both fields are present on Linux/x86 and
/// absent on other platforms — a returned `(None, None)` is a valid
/// outcome (e.g. ARM64, or a container without `/proc` mounted).
fn cpu_family_model() -> (Option<u32>, Option<String>) {
    let text = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let family = text
        .lines()
        .find_map(|l| l.strip_prefix("cpu family\t: "))
        .and_then(|s| s.trim().parse().ok());
    let name = text
        .lines()
        .find_map(|l| l.strip_prefix("model name\t: "))
        .map(|s| s.trim().to_string());
    (family, name)
}

/// Shell out to `pkg-config --modversion libdpdk` and return the version
/// string (e.g. `23.11.2`). Returns `None` if `pkg-config` is absent, fails
/// (non-zero exit), or emits empty output.
fn dpdk_version_pkgconfig() -> Option<String> {
    let out = std::process::Command::new("pkg-config")
        .args(["--modversion", "libdpdk"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// `git rev-parse --abbrev-ref HEAD` — current branch name. Returns `None`
/// when the tool is run outside a git checkout (e.g. from an extracted
/// tarball) or git is absent.
fn worktree_branch() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Read the `UPROF_SESSION_ID` env var if the operator set one. Used to
/// correlate a CSV row to a concurrent AMD uProf profiling session so
/// downstream analysis can join counter data against the profile.
fn uprof_session_id() -> Option<String> {
    std::env::var("UPROF_SESSION_ID").ok().filter(|s| !s.is_empty())
}

/// Targets that still proxy with a pure-Rust stub instead of exercising
/// the real Engine code-path (EAL init / public API gaps). Tagging these
/// with `feature_set = "stub"` prevents phantom regression diffs when
/// they're later swapped for real calls: the regression walker will see
/// a `(test_case, feature_set=default)` pair appear rather than a 50x
/// speed change against a `feature_set=default` baseline.
///
/// Keep in sync with each stub bench's module-level doc comment. When
/// a stub is replaced with a real call, remove its entry here.
const STUB_TARGETS: &[&str] = &[
    "bench_poll_empty",
    "bench_poll_idle_with_timers",
    "bench_send_small",
    "bench_send_large_chain",
    "bench_timer_add_cancel",
];

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let input_root = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "target/criterion".into());
    let output_path = args.get(2).cloned().unwrap_or_else(|| {
        format!(
            "target/bench-results/bench-micro/{}.csv",
            chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
        )
    });

    if let Some(parent) = std::path::Path::new(&output_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let metadata = build_run_metadata()?;
    // Task 2.8: capture host / DPDK / worktree identification once up front so
    // every emitted row carries the same snapshot. Doing this per-row would
    // shell out 5× count times — wasteful and produces flicker if the
    // operator happens to switch branches mid-run.
    let host_meta = HostMetadata::capture();

    let mut wtr = csv::Writer::from_path(&output_path)?;
    let mut count = 0usize;

    // Criterion lays out its output as:
    //   target/criterion/<benchmark_id>/new/sample.json
    //   target/criterion/<benchmark_id>/new/estimates.json
    //   ... (plus base/, change/, report/, etc.)
    //
    // We walk the whole tree looking for `*/new/sample.json` (primary)
    // and fall back to `*/new/estimates.json` (best-effort) per-target.
    // The `<benchmark_id>` is the criterion target name (e.g.
    // `bench_poll_empty`), which becomes the CSV's `test_case` column.
    if std::path::Path::new(&input_root).exists() {
        // Dedupe per-target so we emit at most one CSV cluster per
        // criterion benchmark — walkdir surfaces both sample.json and
        // estimates.json under the same `new/` dir.
        let mut seen_targets: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for entry in walkdir::WalkDir::new(&input_root)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let filename = path.file_name();
            if filename != Some(std::ffi::OsStr::new("sample.json"))
                && filename != Some(std::ffi::OsStr::new("estimates.json"))
            {
                continue;
            }
            // Parent chain must be `.../<target_name>/new/`.
            let Some(parent) = path.parent() else { continue };
            if parent.file_name() != Some(std::ffi::OsStr::new("new")) {
                continue;
            }
            let Some(target_dir) = parent.parent() else {
                continue;
            };
            let target_name = match target_dir.file_name().and_then(|s| s.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };
            if !seen_targets.insert(target_name.clone()) {
                continue;
            }

            // Prefer sample.json (full 7 aggregations) over estimates.json.
            let sample_path = parent.join("sample.json");
            let est_path = parent.join("estimates.json");
            let feature_set = if STUB_TARGETS.contains(&target_name.as_str()) {
                "stub"
            } else {
                "default"
            };

            let aggregations: Vec<(MetricAggregation, f64)> = if sample_path.exists() {
                match read_sample_aggregations(&sample_path) {
                    Ok(aggs) => aggs,
                    Err(e) => {
                        eprintln!(
                            "warning: failed to parse sample.json for {}: {} — falling back to estimates.json",
                            target_name, e
                        );
                        read_estimates_aggregations(&est_path).unwrap_or_default()
                    }
                }
            } else if est_path.exists() {
                read_estimates_aggregations(&est_path).unwrap_or_default()
            } else {
                Vec::new()
            };

            for (agg, value) in aggregations {
                let row = CsvRow {
                    run_metadata: metadata.clone(),
                    tool: "bench-micro".into(),
                    test_case: target_name.clone(),
                    feature_set: feature_set.into(),
                    dimensions_json: "{}".into(),
                    metric_name: "ns_per_iter".into(),
                    metric_unit: "ns".into(),
                    metric_value: value,
                    metric_aggregation: agg,
                    cpu_family: host_meta.cpu_family,
                    cpu_model_name: host_meta.cpu_model_name.clone(),
                    dpdk_version_pkgconfig: host_meta.dpdk_version_pkgconfig.clone(),
                    worktree_branch: host_meta.worktree_branch.clone(),
                    uprof_session_id: host_meta.uprof_session_id.clone(),
                };
                wtr.serialize(&row)?;
                count += 1;
            }
        }
    }

    wtr.flush()?;

    // When the input tree held no recognisable criterion output, `wtr`
    // never serialised a record and csv never emitted the header. The
    // spec §5.5 smoke test expects a header-only CSV in that case —
    // mirror `bench_common::csv_row::COLUMNS` so downstream readers
    // that inspect the file still see the schema even on a zero-row run.
    if count == 0 {
        let mut wtr = csv::Writer::from_path(&output_path)?;
        wtr.write_record(COLUMNS)?;
        wtr.flush()?;
    }

    eprintln!("wrote {} rows to {}", count, output_path);
    Ok(())
}

/// Parse criterion's `sample.json` into per-iter cost samples, then run
/// `bench_common::percentile::summarize` to emit all seven
/// `MetricAggregation` variants.
fn read_sample_aggregations(
    path: &std::path::Path,
) -> anyhow::Result<Vec<(MetricAggregation, f64)>> {
    #[derive(serde::Deserialize)]
    struct SampleJson {
        iters: Vec<f64>,
        times: Vec<f64>,
    }
    let raw = std::fs::read_to_string(path)?;
    let sj: SampleJson = serde_json::from_str(&raw)?;
    if sj.times.len() != sj.iters.len() || sj.iters.is_empty() {
        anyhow::bail!(
            "sample.json: iters/times length mismatch or empty (iters={}, times={})",
            sj.iters.len(),
            sj.times.len()
        );
    }
    // Per-iter cost = total batch time / batch iter count.
    let samples: Vec<f64> = sj
        .times
        .iter()
        .zip(sj.iters.iter())
        .map(|(t, n)| t / n)
        .collect();
    let s = summarize(&samples);
    Ok(vec![
        (MetricAggregation::P50, s.p50),
        (MetricAggregation::P99, s.p99),
        (MetricAggregation::P999, s.p999),
        (MetricAggregation::Mean, s.mean),
        (MetricAggregation::Stddev, s.stddev),
        (MetricAggregation::Ci95Lower, s.ci95_lower),
        (MetricAggregation::Ci95Upper, s.ci95_upper),
    ])
}

/// Fallback when `sample.json` is absent. `estimates.json` carries only
/// mean/median/std_dev + confidence-interval — no percentile point
/// estimates. Emit what we can (P50 from median, plus Mean / Stddev /
/// Ci95{Lower,Upper}); percentile cells are omitted.
fn read_estimates_aggregations(
    path: &std::path::Path,
) -> anyhow::Result<Vec<(MetricAggregation, f64)>> {
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let pe = |node: &str| -> Option<f64> {
        json.get(node)
            .and_then(|v| v.get("point_estimate"))
            .and_then(|v| v.as_f64())
    };
    let ci = |node: &str, bound: &str| -> Option<f64> {
        json.get(node)
            .and_then(|v| v.get("confidence_interval"))
            .and_then(|v| v.get(bound))
            .and_then(|v| v.as_f64())
    };
    let mut out = Vec::with_capacity(5);
    if let Some(v) = pe("median") {
        out.push((MetricAggregation::P50, v));
    }
    if let Some(v) = pe("mean") {
        out.push((MetricAggregation::Mean, v));
    }
    if let Some(v) = pe("std_dev") {
        out.push((MetricAggregation::Stddev, v));
    }
    if let Some(v) = ci("mean", "lower_bound") {
        out.push((MetricAggregation::Ci95Lower, v));
    }
    if let Some(v) = ci("mean", "upper_bound") {
        out.push((MetricAggregation::Ci95Upper, v));
    }
    Ok(out)
}

fn build_run_metadata() -> anyhow::Result<RunMetadata> {
    let commit_sha = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let branch = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let kernel = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    // bench-micro's `precondition_wc_active` is `n/a` (spec §4.1 line 222):
    // wc_active reads a DPDK-side memtype list which requires EAL init.
    // All other preconditions default to `Pass(None)` for in-process benches
    // — lenient mode documents that we aren't enforcing any of them.
    let preconditions = Preconditions {
        wc_active: PreconditionValue::not_applicable(),
        ..Default::default()
    };

    Ok(RunMetadata {
        run_id: uuid::Uuid::new_v4(),
        run_started_at: chrono::Utc::now().to_rfc3339(),
        commit_sha,
        branch,
        host: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default(),
        instance_type: std::env::var("INSTANCE_TYPE").unwrap_or_default(),
        cpu_model: std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name"))
                    .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
            })
            .unwrap_or_default(),
        dpdk_version: String::new(), // bench-micro doesn't init DPDK
        kernel,
        nic_model: String::new(),
        nic_fw: String::new(),
        ami_id: std::env::var("AMI_ID").unwrap_or_default(),
        precondition_mode: PreconditionMode::Lenient, // in-process benches; lenient
        preconditions,
    })
}
