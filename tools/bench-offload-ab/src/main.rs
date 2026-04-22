//! bench-offload-ab — feature-matrix A/B driver over `hw-*` cargo flags.
//!
//! Spec §9. For each `Config` in the [`matrix::HW_OFFLOAD_MATRIX`]:
//!
//! 1. Rebuild `bench-ab-runner` with the matching feature set.
//! 2. Spawn the runner; capture its CSV stdout.
//! 3. Append the CSV rows to `$output_dir/<run_id>.csv`.
//!
//! After the matrix runs, the driver runs two extra back-to-back
//! baseline rebuilds + runs to compute the noise floor (spec §9:
//! `noise_floor = p99 of two back-to-back baseline runs`), then
//! computes per-offload `delta_p99`, classifies under the decision
//! rule, checks the sanity invariant, and writes the Markdown report
//! to `docs/superpowers/reports/offload-ab.md`.
//!
//! # No live DPDK here
//!
//! This binary never opens a DPDK port, never calls `rte_eal_init`,
//! never touches a NIC. The rebuild + subprocess plumbing is the
//! whole surface; `bench-ab-runner` owns the live engine. That means
//! the driver build must NOT depend on `dpdk-net-core` or
//! `dpdk-net-sys` — it's a pure orchestrator.
//!
//! # T11 reuse
//!
//! T11 (`bench-obs-overhead`) will reuse every public function in
//! `bench_offload_ab::{decision,report}` and the `Config` type from
//! `bench_offload_ab::matrix`. The only T11-specific code is its own
//! matrix slice + the CLI wrapper.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;
use clap::Parser;

use bench_common::csv_row::{CsvRow, COLUMNS};

use bench_offload_ab::decision::DecisionRule;
use bench_offload_ab::matrix::{Config, HW_OFFLOAD_MATRIX};
use bench_offload_ab::report::{
    aggregate_by_config, build_report_rows, check_full_sanity, p99_by_feature_set,
    write_markdown_report, RunReport,
};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "bench-offload-ab — feature-matrix A/B driver over hw-* cargo flags (spec §9)"
)]
struct Args {
    /// Peer IP (dotted-quad IPv4).
    #[arg(long)]
    peer_ip: String,

    /// Peer TCP port.
    #[arg(long, default_value_t = 10_001)]
    peer_port: u16,

    /// Iterations per config (post-warmup). Spec §9 minimum: 10_000.
    #[arg(long, default_value_t = 10_000)]
    iterations: u64,

    /// Warmup iterations per config (discarded). Spec §9: drop first 1_000.
    #[arg(long, default_value_t = 1_000)]
    warmup: u64,

    /// EAL args, comma-separated. Passed verbatim to the runner.
    #[arg(long)]
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
    /// `target/bench-results/bench-offload-ab/`.
    #[arg(long, default_value = "target/bench-results/bench-offload-ab")]
    output_dir: PathBuf,

    /// Report output path. Defaults to `docs/superpowers/reports/offload-ab.md`.
    #[arg(long, default_value = "docs/superpowers/reports/offload-ab.md")]
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
    eprintln!("bench-offload-ab: run_id={run_id} csv={}", csv_path.display());

    // Open the accumulated CSV with the header row pre-written so the
    // per-config runner output (which is csv::Writer-produced and
    // therefore emits its own header every time) can be appended with
    // the header lines stripped. Simpler than pre-parsing every row.
    let mut csv_file = std::fs::File::create(&csv_path)
        .with_context(|| format!("creating CSV {}", csv_path.display()))?;
    writeln!(csv_file, "{}", COLUMNS.join(","))?;

    // 1. Run every config in the matrix.
    for cfg in HW_OFFLOAD_MATRIX {
        run_config(&args, cfg, &mut csv_file)?;
    }

    // 2. Run two extra baseline rebuilds for noise-floor computation.
    //    Spec §9: noise_floor = p99 of two back-to-back baseline runs.
    //    We label them with distinct feature_set names so the
    //    post-matrix aggregator can tell them apart from the baseline
    //    row already in the matrix.
    let baseline_cfg = HW_OFFLOAD_MATRIX
        .iter()
        .find(|c| c.is_baseline)
        .expect("matrix must contain a baseline config");
    let noise_cfgs = [
        Config {
            name: "baseline-noise-1",
            features: baseline_cfg.features,
            is_baseline: false,
            is_full: false,
        },
        Config {
            name: "baseline-noise-2",
            features: baseline_cfg.features,
            is_baseline: false,
            is_full: false,
        },
    ];
    for cfg in &noise_cfgs {
        run_config(&args, cfg, &mut csv_file)?;
    }
    drop(csv_file);

    // 3. Load accumulated CSV, compute deltas + apply decision rule.
    let all_rows = load_csv(&csv_path)?;
    let agg = aggregate_by_config(&all_rows)
        .map_err(|e| anyhow::anyhow!("aggregate_by_config: {e}"))?;

    // noise_floor = |p99(baseline-noise-1) - p99(baseline-noise-2)|
    let p99s = p99_by_feature_set(&all_rows);
    let n1 = p99s
        .get("baseline-noise-1")
        .and_then(|v| v.first().copied())
        .context("missing baseline-noise-1 p99")?;
    let n2 = p99s
        .get("baseline-noise-2")
        .and_then(|v| v.first().copied())
        .context("missing baseline-noise-2 p99")?;
    let noise_floor = (n1 - n2).abs();
    eprintln!(
        "bench-offload-ab: noise_floor = |{n1:.2} - {n2:.2}| = {noise_floor:.2} ns"
    );

    let rule = DecisionRule {
        noise_floor_ns: noise_floor,
    };
    let rows = build_report_rows(HW_OFFLOAD_MATRIX, &agg, &rule)
        .map_err(|e| anyhow::anyhow!("build_report_rows: {e}"))?;

    // 4. Sanity invariant.
    let sanity = check_full_sanity(HW_OFFLOAD_MATRIX, &agg);
    if let Err(msg) = &sanity.verdict {
        eprintln!("bench-offload-ab: sanity invariant FAILED: {msg}");
    }

    // 5. Build + write the Markdown report.
    let workload = format!(
        "128 B / 128 B request-response, N={} per config, warmup={}",
        args.iterations, args.warmup
    );
    let commit_sha = git_rev_parse_head();
    let git_log = git_log_oneline(20);
    let report = RunReport {
        run_id: run_id.to_string(),
        date_iso8601: chrono::Utc::now().to_rfc3339(),
        commit_sha,
        noise_floor_ns: noise_floor,
        rule,
        rows,
        sanity_invariant: sanity.verdict.clone(),
        full_p99_ns: sanity.full_p99_ns,
        best_individual: sanity.best_individual.clone(),
        workload,
        git_log,
        csv_path: csv_path.display().to_string(),
    };
    write_markdown_report(&args.report_path, &report)
        .with_context(|| format!("writing report {}", args.report_path.display()))?;
    eprintln!(
        "bench-offload-ab: report written to {}",
        args.report_path.display()
    );

    // 6. Propagate sanity-invariant failure as non-zero exit so CI
    //    flags the run. The report is still on disk for the reviewer.
    if sanity.verdict.is_err() {
        std::process::exit(2);
    }
    Ok(())
}

/// Rebuild (optionally) + run one config; append the runner's CSV
/// output (minus its header line) to `csv_file`.
fn run_config(
    args: &Args,
    cfg: &Config,
    csv_file: &mut std::fs::File,
) -> anyhow::Result<()> {
    eprintln!(
        "bench-offload-ab: running config {} (features=[{}])",
        cfg.name,
        cfg.features.join(",")
    );
    if !args.skip_rebuild {
        rebuild_runner(cfg)?;
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

    let out = Command::new(&runner_path)
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
            cfg.name,
            "--tool",
            "bench-offload-ab",
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
        .output()
        .with_context(|| format!("spawning {}", runner_path.display()))?;
    if !out.status.success() {
        anyhow::bail!(
            "bench-ab-runner config {} exited with status {:?}",
            cfg.name,
            out.status
        );
    }

    append_runner_output(csv_file, &out.stdout, cfg.name)?;
    Ok(())
}

/// `cargo build --no-default-features --features <…> -p bench-ab-runner --release`.
///
/// Empty-feature case (baseline): omit the `--features` flag entirely
/// (cargo rejects `--features ""`).
fn rebuild_runner(cfg: &Config) -> anyhow::Result<()> {
    let features = cfg.features_as_cli_string();
    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "--no-default-features",
        "-p",
        "bench-ab-runner",
        "--release",
    ]);
    if !features.is_empty() {
        cmd.args(["--features", &features]);
    }
    let status = cmd
        .status()
        .with_context(|| format!("spawning cargo for config {}", cfg.name))?;
    if !status.success() {
        anyhow::bail!("cargo build for config {} failed ({:?})", cfg.name, status);
    }
    Ok(())
}

/// Append `runner_stdout` (raw bytes; expected to be a CSV with a
/// header line and seven data rows) to `csv_file`, skipping the
/// header. If the runner somehow emits an empty stdout, error loudly
/// — that's a runner bug and we don't want to silently accept it.
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
    // Minimal sanity check — the runner's CSV header must be our
    // COLUMNS.join(","). Catches an accidental stdout contamination.
    let expected = COLUMNS.join(",");
    if header.trim() != expected.trim() {
        anyhow::bail!(
            "runner {config_name} emitted unexpected CSV header.\n  expected: {expected}\n  got:      {header}"
        );
    }
    for line in lines {
        if line.is_empty() {
            continue;
        }
        writeln!(csv_file, "{line}")?;
    }
    Ok(())
}

/// Load every `CsvRow` from `path` into memory.
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
