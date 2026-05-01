//! bench-obs-overhead — feature-matrix A/B driver over `obs-*` cargo flags.
//!
//! Spec §10. For each `ObsRow` in [`matrix::OBS_MATRIX`]:
//!
//! 1. Rebuild `bench-ab-runner` with the row's feature set.
//! 2. Spawn the runner; capture its CSV stdout.
//! 3. Append the CSV rows to `$output_dir/<run_id>.csv`.
//!
//! After the matrix runs, two extra back-to-back `obs-none` rebuilds +
//! runs compute the noise floor (spec §9 convention, spec §10 inherits
//! the same discipline), then the driver computes `delta_p99 vs obs-none`,
//! classifies via the T10 decision rule, validates the observability-
//! floor invariant, and writes the Markdown report to
//! `docs/superpowers/reports/obs-overhead.md`.
//!
//! # Reuse vs. copy strategy
//!
//! The subprocess plumbing in `bench-offload-ab::main` isn't a library
//! surface — it's binary-local (private `fn rebuild_runner`, `fn
//! run_config`, `fn append_runner_output`). Rather than lift those
//! functions and break T10's commit, this binary duplicates the
//! subprocess scaffolding verbatim (~170 lines) and consumes every
//! OTHER piece through the `bench_offload_ab` library:
//!
//! - [`DecisionRule`] and `classify` — pure predicates,
//! - [`aggregate_by_config`] — CSV → per-config percentiles,
//! - [`p99_by_feature_set`] — noise-floor source,
//! - [`Aggregated`] — the shared percentile tuple,
//! - [`check_observability_invariant`] — new in T11 (symmetric with
//!   `check_sanity_invariant`).
//!
//! The subprocess scaffolding is worth lifting into a `bench_offload_ab::
//! runner` module in a future refactor PR; see the task-brief's
//! "discipline" section. Duplicating it here keeps T11 scoped and
//! leaves T10 unchanged beyond the single `check_observability_invariant`
//! addition.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use wait_timeout::ChildExt;

use bench_common::csv_row::{CsvRow, COLUMNS};

use bench_offload_ab::decision::DecisionRule;
use bench_offload_ab::matrix::Config;
use bench_offload_ab::report::{aggregate_by_config, p99_by_feature_set};

use bench_obs_overhead::decision::check_obs_floor_sanity;
use bench_obs_overhead::matrix::{ObsRow, OBS_MATRIX, OBS_NONE_NAME};
use bench_obs_overhead::report::{
    assemble_run_report, build_obs_report_rows, write_obs_markdown_report,
};

// MIN_NOISE_FLOOR_NS: identical rationale + value to bench-offload-ab.
// p99 jitter of back-to-back runs can degenerate to ~0 on a quiet
// machine (intel_idle.max_cstate=1, isolated core). Without a floor,
// threshold = 3*noise_floor ~= 0 and every positive delta reads as
// Signal.
const MIN_NOISE_FLOOR_NS: f64 = 5.0;

/// Number of rows the `bench-ab-runner` emits per invocation — one per
/// `MetricAggregation` variant (p50 / p99 / p999 / mean / stddev /
/// ci95_lo / ci95_hi). Identical to the T10 constant; kept local so
/// this binary stays self-contained even if T10's is ever lifted to
/// the library.
const EXPECTED_DATA_ROWS: usize = 7;

/// Absolute wall-clock budget for one bench-ab-runner invocation —
/// same rationale as T10.
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Parser, Debug)]
#[command(
    version,
    about = "bench-obs-overhead — feature-matrix A/B driver over obs-* cargo flags (spec §10)"
)]
struct Args {
    /// Peer IP (dotted-quad IPv4).
    #[arg(long)]
    peer_ip: String,

    /// Peer TCP port.
    #[arg(long, default_value_t = 10_001)]
    peer_port: u16,

    /// Iterations per config (post-warmup). Spec §10 minimum: 10_000.
    #[arg(long, default_value_t = 10_000)]
    iterations: u64,

    /// Warmup iterations per config (discarded). Spec §10: drop first 1_000.
    #[arg(long, default_value_t = 1_000)]
    warmup: u64,

    /// EAL args, whitespace-separated. Passed verbatim to the runner.
    #[arg(long, allow_hyphen_values = true)]
    eal_args: String,

    /// Local IP (dotted-quad IPv4). Passed to each runner.
    #[arg(long)]
    local_ip: String,

    /// Gateway IP (dotted-quad IPv4). Passed to each runner.
    #[arg(long)]
    gateway_ip: String,

    /// Precondition mode: `strict` or `lenient`. Passed to each runner.
    #[arg(long, default_value = "strict")]
    precondition_mode: String,

    /// Lcore id to pin the runner engine to.
    #[arg(long, default_value_t = 2)]
    lcore: u32,

    /// Output directory for the accumulated CSV. Defaults to
    /// `target/bench-results/bench-obs-overhead/`.
    #[arg(long, default_value = "target/bench-results/bench-obs-overhead")]
    output_dir: PathBuf,

    /// Report output path. Defaults to `docs/superpowers/reports/obs-overhead.md`.
    #[arg(long, default_value = "docs/superpowers/reports/obs-overhead.md")]
    report_path: PathBuf,

    /// Skip the rebuild step per config. Useful for replay runs — when
    /// a report is being regenerated from an existing CSV the driver
    /// skips cargo entirely.
    #[arg(long, default_value_t = false)]
    skip_rebuild: bool,

    /// Path to the `bench-ab-runner` binary (post-build). Defaults to
    /// `target/release/bench-ab-runner`, which is where a release
    /// build under the workspace `target/` lands.
    #[arg(long, default_value = "target/release/bench-ab-runner")]
    runner_bin: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    std::fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("creating {}", args.output_dir.display()))?;

    let run_id = uuid::Uuid::new_v4();
    let csv_path = args.output_dir.join(format!("{run_id}.csv"));
    eprintln!("bench-obs-overhead: run_id={run_id} csv={}", csv_path.display());

    let mut csv_file = std::fs::File::create(&csv_path)
        .with_context(|| format!("creating CSV {}", csv_path.display()))?;
    writeln!(csv_file, "{}", COLUMNS.join(","))?;

    // 1. Run every config in the matrix.
    for row in OBS_MATRIX {
        run_row(&args, row, &mut csv_file)?;
    }

    // 2. Run two extra `obs-none` rebuilds for noise-floor computation.
    //    The obs floor (`obs-none`) plays the same role here that the
    //    `baseline` row plays for bench-offload-ab: the reference that
    //    anchors noise-floor measurement.
    let obs_none_row = OBS_MATRIX
        .iter()
        .find(|r| r.config.name == OBS_NONE_NAME)
        .expect("matrix must contain an obs-none config");
    let noise_rows = [
        ObsRow {
            config: Config {
                name: "obs-none-noise-1",
                features: obs_none_row.config.features,
                is_baseline: false,
                is_full: false,
            },
            default_state: obs_none_row.default_state,
            is_default: false,
        },
        ObsRow {
            config: Config {
                name: "obs-none-noise-2",
                features: obs_none_row.config.features,
                is_baseline: false,
                is_full: false,
            },
            default_state: obs_none_row.default_state,
            is_default: false,
        },
    ];
    for row in &noise_rows {
        run_row(&args, row, &mut csv_file)?;
    }
    drop(csv_file);

    // 3. Load accumulated CSV, compute deltas + apply decision rule.
    let all_rows = load_csv(&csv_path)?;
    let agg = aggregate_by_config(&all_rows)
        .map_err(|e| anyhow::anyhow!("aggregate_by_config: {e}"))?;

    // noise_floor = |p99(obs-none-noise-1) - p99(obs-none-noise-2)|
    let p99s = p99_by_feature_set(&all_rows);
    let n1 = p99s
        .get("obs-none-noise-1")
        .and_then(|v| v.first().copied())
        .context("missing obs-none-noise-1 p99")?;
    let n2 = p99s
        .get("obs-none-noise-2")
        .and_then(|v| v.first().copied())
        .context("missing obs-none-noise-2 p99")?;
    let noise_floor_raw = (n1 - n2).abs();
    let noise_floor = clamp_noise_floor(noise_floor_raw);
    eprintln!(
        "bench-obs-overhead: noise_floor = |{n1:.2} - {n2:.2}| = {noise_floor_raw:.2} ns \
         (clamped to {noise_floor:.2} ns)"
    );
    if noise_floor_raw < MIN_NOISE_FLOOR_NS {
        eprintln!(
            "bench-obs-overhead: WARN raw noise-floor {:.2} ns clamped to {:.2} ns \
             (obs-none baselines too close — a quieter run shifts the decision \
             threshold down; signals within {:.2} ns of obs-none should be \
             treated as noise).",
            noise_floor_raw, noise_floor, MIN_NOISE_FLOOR_NS
        );
    }

    let rule = DecisionRule {
        noise_floor_ns: noise_floor,
    };
    let rows = build_obs_report_rows(OBS_MATRIX, &agg, &rule)
        .map_err(|e| anyhow::anyhow!("build_obs_report_rows: {e}"))?;

    // 4. Sanity invariant: obs-floor.
    let sanity = check_obs_floor_sanity(OBS_MATRIX, &agg);
    if let Err(msg) = &sanity.verdict {
        eprintln!("bench-obs-overhead: obs-floor invariant FAILED: {msg}");
    }
    let had_sanity_err = sanity.verdict.is_err();

    // 5. Assemble + write the Markdown report.
    let workload = format!(
        "128 B / 128 B request-response, N={} per config, warmup={}",
        args.iterations, args.warmup
    );
    let commit_sha = git_rev_parse_head();
    let git_log = git_log_oneline(20);
    let report = assemble_run_report(
        run_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        commit_sha,
        noise_floor_raw,
        noise_floor,
        rule,
        rows,
        sanity,
        workload,
        git_log,
        csv_path.display().to_string(),
    );
    write_obs_markdown_report(&args.report_path, &report)
        .with_context(|| format!("writing report {}", args.report_path.display()))?;
    eprintln!(
        "bench-obs-overhead: report written to {}",
        args.report_path.display()
    );

    // 6. Propagate sanity failure as non-zero exit so CI flags the run.
    if had_sanity_err {
        std::process::exit(2);
    }
    Ok(())
}

/// Rebuild (optionally) + run one row; append the runner's CSV output
/// (minus its header line) to `csv_file`.
///
/// Mirrors `bench_offload_ab::main::run_config` — duplicated verbatim
/// rather than lifted into the library (see module-level rationale).
fn run_row(
    args: &Args,
    row: &ObsRow,
    csv_file: &mut std::fs::File,
) -> anyhow::Result<()> {
    eprintln!(
        "bench-obs-overhead: running config {} (features=[{}])",
        row.config.name,
        row.config.features.join(",")
    );
    if !args.skip_rebuild {
        rebuild_runner(row)?;
    }

    let runner_path = if args.runner_bin.is_absolute() {
        args.runner_bin.clone()
    } else {
        std::env::current_dir()?.join(&args.runner_bin)
    };
    if !runner_path.exists() {
        anyhow::bail!(
            "runner binary not found at {} \
             (try running without --skip-rebuild, or pass --runner-bin)",
            runner_path.display()
        );
    }

    let mut child = Command::new(&runner_path)
        .args([
            "--peer-ip",
            &args.peer_ip,
            "--peer-port",
            &args.peer_port.to_string(),
            "--iterations",
            &args.iterations.to_string(),
            "--warmup",
            &args.warmup.to_string(),
            "--feature-set",
            row.config.name,
            "--tool",
            "bench-obs-overhead",
            "--precondition-mode",
            &args.precondition_mode,
            "--lcore",
            &args.lcore.to_string(),
            "--local-ip",
            &args.local_ip,
            "--gateway-ip",
            &args.gateway_ip,
            "--eal-args",
            &args.eal_args,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", runner_path.display()))?;

    // Drain stdout on a helper thread — same rationale as T10: avoid a
    // pipe-buffer wedge during wait_timeout polling.
    let mut stdout = child
        .stdout
        .take()
        .expect("stdout piped above, must be Some");
    let (tx, rx) = mpsc::channel::<std::io::Result<Vec<u8>>>();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let res = stdout.read_to_end(&mut buf).map(|_| buf);
        let _ = tx.send(res);
    });

    let status = match child
        .wait_timeout(SUBPROCESS_TIMEOUT)
        .with_context(|| format!("wait_timeout on runner for config {}", row.config.name))?
    {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "bench-ab-runner exceeded {}s timeout for config '{}' (killed)",
                SUBPROCESS_TIMEOUT.as_secs(),
                row.config.name
            );
        }
    };
    if !status.success() {
        anyhow::bail!(
            "bench-ab-runner config {} exited with status {:?}",
            row.config.name,
            status
        );
    }

    let stdout_bytes = rx
        .recv()
        .context("runner stdout-drain thread dropped its sender")?
        .with_context(|| format!("reading stdout from runner for {}", row.config.name))?;

    append_runner_output(csv_file, &stdout_bytes, row.config.name)?;
    Ok(())
}

/// `cargo build [--no-default-features] --features <…> -p bench-ab-runner --release`.
///
/// Unlike bench-offload-ab (which ALWAYS passes `--no-default-features`),
/// the `default` row in [`OBS_MATRIX`] is supposed to build WITH defaults
/// — that row represents "what the production build actually does". The
/// row's `is_default` marker toggles whether we pass the flag.
///
/// # Shared `target/` — single-operator assumption
///
/// Same as bench-offload-ab: every row rebuilds into the workspace-
/// default `target/release/`; we share that directory so incremental
/// compilation only touches the crates whose feature set actually
/// changed. Two drivers running in parallel would stomp each other's
/// incremental cache — the A10 nightly script enforces single-operator
/// via a lock file.
fn rebuild_runner(row: &ObsRow) -> anyhow::Result<()> {
    let features = row.config.features_as_cli_string();
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "-p", "bench-ab-runner", "--release"]);
    if !row.is_default {
        cmd.arg("--no-default-features");
    }
    if !features.is_empty() {
        cmd.args(["--features", &features]);
    }
    let status = cmd
        .status()
        .with_context(|| format!("spawning cargo for config {}", row.config.name))?;
    if !status.success() {
        anyhow::bail!("cargo build for config {} failed ({:?})", row.config.name, status);
    }
    Ok(())
}

/// Append `runner_stdout` to `csv_file`, skipping the header. Bails on
/// malformed (non-UTF-8, missing header, wrong row count) payload —
/// same rationale as T10.
fn append_runner_output(
    csv_file: &mut std::fs::File,
    runner_stdout: &[u8],
    config_name: &str,
) -> anyhow::Result<()> {
    let text = std::str::from_utf8(runner_stdout)
        .with_context(|| format!("runner stdout for {config_name} is not UTF-8"))?;
    let mut lines = text.lines();
    let header = lines
        .next()
        .with_context(|| format!("runner {config_name} emitted empty stdout"))?;
    let expected = COLUMNS.join(",");
    if header.trim() != expected.trim() {
        anyhow::bail!(
            "runner {config_name} emitted unexpected CSV header.\n  expected: {expected}\n  got:      {header}"
        );
    }
    let mut data_lines = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        writeln!(csv_file, "{line}")?;
        data_lines += 1;
    }
    if data_lines != EXPECTED_DATA_ROWS {
        anyhow::bail!(
            "bench-ab-runner for config '{config_name}' emitted {data_lines} data rows \
             (expected {EXPECTED_DATA_ROWS} — one per MetricAggregation variant: \
             p50 / p99 / p999 / mean / stddev / ci95_lo / ci95_hi); \
             subprocess likely crashed mid-emit or stdout was truncated"
        );
    }
    Ok(())
}

/// Clamp `raw` to at least [`MIN_NOISE_FLOOR_NS`].
fn clamp_noise_floor(raw: f64) -> f64 {
    raw.max(MIN_NOISE_FLOOR_NS)
}

fn load_csv(path: &Path) -> anyhow::Result<Vec<CsvRow>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(path)
        .with_context(|| format!("opening CSV {}", path.display()))?;
    let mut out = Vec::new();
    for (i, rec) in rdr.deserialize::<CsvRow>().enumerate() {
        let row = rec.with_context(|| format!("parsing CSV {} row {i}", path.display()))?;
        out.push(row);
    }
    Ok(out)
}

fn git_rev_parse_head() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn git_log_oneline(n: usize) -> String {
    Command::new("git")
        .args(["log", "--oneline", &format!("-{n}")])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_noise_floor_passes_through_above_min() {
        assert_eq!(clamp_noise_floor(5.0), 5.0);
        assert_eq!(clamp_noise_floor(7.5), 7.5);
        assert_eq!(clamp_noise_floor(100.0), 100.0);
    }

    #[test]
    fn clamp_noise_floor_raises_below_min_to_min() {
        assert_eq!(clamp_noise_floor(0.0), MIN_NOISE_FLOOR_NS);
        assert_eq!(clamp_noise_floor(0.5), MIN_NOISE_FLOOR_NS);
        assert_eq!(clamp_noise_floor(4.999), MIN_NOISE_FLOOR_NS);
    }

    #[test]
    fn clamp_noise_floor_exactly_at_min_is_identity() {
        assert_eq!(clamp_noise_floor(MIN_NOISE_FLOOR_NS), MIN_NOISE_FLOOR_NS);
    }

    /// Per config name → `data_row_count` CSV bytes in bench-ab-runner's
    /// shape (same fixture helper as T10, scoped down).
    fn fake_runner_csv(feature_set: &str, data_row_count: usize) -> Vec<u8> {
        let header = COLUMNS.join(",");
        let mut out = String::new();
        out.push_str(&header);
        out.push('\n');
        for i in 0..data_row_count {
            let fields: Vec<String> = COLUMNS
                .iter()
                .enumerate()
                .map(|(idx, col)| match *col {
                    "feature_set" => feature_set.to_string(),
                    "metric_value" => format!("{}", 100 + i),
                    "metric_aggregation" => "p99".into(),
                    "metric_name" => "rtt_ns".into(),
                    "metric_unit" => "ns".into(),
                    _ => format!("v{idx}-{col}"),
                })
                .collect();
            out.push_str(&fields.join(","));
            out.push('\n');
        }
        out.into_bytes()
    }

    #[test]
    fn append_runner_output_accepts_exactly_expected_rows() {
        let tmp = tempfile_in_target();
        let mut f = std::fs::File::create(&tmp).unwrap();
        let csv = fake_runner_csv("obs-none", EXPECTED_DATA_ROWS);
        append_runner_output(&mut f, &csv, "obs-none").unwrap();
        drop(f);

        let mut got = String::new();
        std::fs::File::open(&tmp)
            .unwrap()
            .read_to_string(&mut got)
            .unwrap();
        let lines_written = got.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(lines_written, EXPECTED_DATA_ROWS);
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn append_runner_output_bails_on_short_payload() {
        let tmp = tempfile_in_target();
        let mut f = std::fs::File::create(&tmp).unwrap();
        let csv = fake_runner_csv("obs-none", EXPECTED_DATA_ROWS - 1);
        let err = append_runner_output(&mut f, &csv, "obs-none").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("emitted {} data rows", EXPECTED_DATA_ROWS - 1)),
            "err should mention short row count: {msg}"
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn append_runner_output_bails_on_long_payload() {
        let tmp = tempfile_in_target();
        let mut f = std::fs::File::create(&tmp).unwrap();
        let csv = fake_runner_csv("obs-none", EXPECTED_DATA_ROWS + 1);
        let err = append_runner_output(&mut f, &csv, "obs-none").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!("emitted {} data rows", EXPECTED_DATA_ROWS + 1)),
            "err should mention long row count: {msg}"
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn append_runner_output_bails_on_empty_stdout() {
        let tmp = tempfile_in_target();
        let mut f = std::fs::File::create(&tmp).unwrap();
        let err = append_runner_output(&mut f, b"", "obs-none").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("emitted empty stdout"), "err: {msg}");
        std::fs::remove_file(&tmp).ok();
    }

    fn tempfile_in_target() -> std::path::PathBuf {
        let base = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("target"));
        std::fs::create_dir_all(&base).ok();
        base.join(format!(
            "bench-obs-overhead-test-{}.csv",
            uuid::Uuid::new_v4()
        ))
    }
}
