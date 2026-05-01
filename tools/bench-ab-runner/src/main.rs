//! bench-ab-runner — one process, one feature-set, one EAL init.
//!
//! Invoked as a sub-process by the A/B harnesses (`bench-offload-ab`,
//! `bench-obs-overhead`). Each invocation is a fresh rebuild with a
//! distinct `--features` set; the process performs exactly one
//! measurement run and exits, so that `rte_eal_init` is called at most
//! once per PID lifetime. This avoids DPDK 23.11's EAL re-init quirks.
//!
//! Contract (spec §D3):
//! 1. Precondition check (shell out to `check-bench-preconditions`).
//! 2. `dpdk_net_core::engine::eal_init` (wraps `rte_eal_init` with the
//!    LLQ log-capture window + process-global once-init Mutex).
//! 3. `Engine::new` from `dpdk-net-core`.
//! 4. Warmup iterations (discarded).
//! 5. Measurement window (collect raw RTT samples).
//! 6. Emit CSV rows to stdout.
//! 7. Drop engine; `rte_eal_cleanup` (via `EalGuard` RAII).
//! 8. Exit.

use anyhow::Context;
use clap::Parser;

use bench_common::csv_row::{CsvRow, MetricAggregation};
use bench_common::percentile::{summarize, Summary};
use bench_common::preconditions::{PreconditionMode, PreconditionValue, Preconditions};
use bench_common::run_metadata::RunMetadata;

mod workload;

/// Command-line arguments for `bench-ab-runner`. Consumed by
/// `bench-offload-ab` and `bench-obs-overhead` via `std::process::Command`.
#[derive(Parser, Debug)]
#[command(version, about = "bench-ab-runner — one A/B config per process")]
pub struct Args {
    /// Peer IP address (dotted-quad IPv4, e.g. 10.0.0.42).
    #[arg(long)]
    pub peer_ip: String,

    /// Peer TCP port.
    #[arg(long, default_value_t = 10_001)]
    pub peer_port: u16,

    /// Measurement iteration count (after warmup).
    #[arg(long, default_value_t = 10_000)]
    pub iterations: u64,

    /// Warmup iteration count (discarded).
    #[arg(long, default_value_t = 1_000)]
    pub warmup: u64,

    /// Request payload size in bytes.
    #[arg(long, default_value_t = 128)]
    pub request_bytes: usize,

    /// Response payload size in bytes.
    #[arg(long, default_value_t = 128)]
    pub response_bytes: usize,

    /// Feature-set label (emitted as the `feature_set` CSV column).
    #[arg(long)]
    pub feature_set: String,

    /// Tool name label (emitted as the `tool` CSV column).
    #[arg(long)]
    pub tool: String,

    /// Precondition mode: `strict` aborts on any precondition failure;
    /// `lenient` warns and continues.
    #[arg(long, default_value = "strict")]
    pub precondition_mode: String,

    /// Lcore id to pin the engine to. EngineConfig.lcore_id is u16, so
    /// values above u16::MAX are rejected.
    #[arg(long, default_value_t = 2)]
    pub lcore: u32,

    /// Local IP (dotted-quad IPv4, e.g. 10.0.0.42).
    #[arg(long)]
    pub local_ip: String,

    /// Local gateway IP (dotted-quad IPv4).
    #[arg(long)]
    pub gateway_ip: String,

    /// EAL args, whitespace-separated. Passed verbatim after an implicit
    /// argv[0] = "bench-ab-runner" prefix. Whitespace split preserves
    /// PCI devarg inner commas (e.g. `-a 0000:00:06.0,large_llq_hdr=1`
    /// stays as two argv slots: `-a` and `0000:00:06.0,large_llq_hdr=1`).
    /// `allow_hyphen_values` lets the value start with `-` (e.g. `-l`).
    #[arg(long, allow_hyphen_values = true)]
    pub eal_args: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mode = parse_mode(&args.precondition_mode)?;

    // 1. Precondition check.
    let preconditions = run_preconditions_check(mode)?;
    if mode == PreconditionMode::Strict && !preconditions_all_pass(&preconditions) {
        eprintln!("bench-ab-runner: precondition failure in strict mode:");
        for (name, value) in preconditions_as_pairs(&preconditions) {
            if !(value.is_pass() || value.is_not_applicable()) {
                eprintln!("  {name} = {value}");
            }
        }
        std::process::exit(1);
    }

    // 2. EAL init. Routed through `dpdk_net_core::engine::eal_init` (NOT
    //    the raw `rte_eal_init` FFI) so the LLQ log-capture window
    //    inside that wrapper fires. Building `--features hw-verify-llq`
    //    without this routing silently yields a "not captured" verdict.
    eal_init(&args)?;

    // Install RAII so `rte_eal_cleanup` runs on every exit path —
    // including `?`-propagated errors below. The guard drops AFTER the
    // engine because it's declared later in this scope.
    let _eal_guard = EalGuard;

    // 3. Engine::new.
    let engine = build_engine(&args)?;

    // 4. Workload (warmup + measurement).
    let samples = workload::run(&engine, &args)?;

    // 5. Summarize + CSV emit.
    let metadata = build_run_metadata(mode, preconditions)?;
    emit_csv(&args, &metadata, &samples)?;

    // 6. Drop the engine (releases mempools, queues, event queue)
    //    before `_eal_guard` runs rte_eal_cleanup — the EAL must
    //    outlive any live `Engine`. Rust drops locals in reverse
    //    declaration order, so this is automatic (engine declared
    //    after `_eal_guard` → engine drops first).
    Ok(())
}

/// RAII guard that calls `rte_eal_cleanup` on drop. Instantiated after
/// `eal_init` succeeds so that every error path out of `main` (via `?`)
/// still unwinds the EAL cleanly.
///
/// Best-effort per DPDK 23.11 — some paths (e.g. VFIO-based PMDs) don't
/// fully unwind. Ignored on failure so a late cleanup error does not
/// obscure the primary run result.
struct EalGuard;

impl Drop for EalGuard {
    fn drop(&mut self) {
        // Safety: we're the only caller of `rte_eal_init` in this
        // process (single-invocation contract per file-level comment),
        // and by drop order we've already dropped the `Engine`
        // (declared later in main). No outstanding mbuf / queue
        // references remain.
        unsafe {
            let _ = dpdk_net_sys::rte_eal_cleanup();
        }
    }
}

/// Parse the `--precondition-mode` string into the typed enum. Fails
/// loudly on garbage so the caller gets a clear error instead of a
/// silent fall-through to Strict.
fn parse_mode(s: &str) -> anyhow::Result<PreconditionMode> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

/// Invoke `check-bench-preconditions` (T3) as a sub-process and parse
/// its JSON into a `Preconditions` struct. Until T3 lands, the shim
/// path here uses `BENCH_PRECONDITIONS_JSON` env var (the JSON blob a
/// harness would pass through) as a fallback:
///
/// - If `check-bench-preconditions` is executable on `$PATH` it is
///   preferred; else the env var is read.
/// - If neither is available, under `lenient` mode we emit a warning
///   and return all-pass defaults (so subsequent code can still run
///   against a pre-populated host); under `strict` mode we error.
///
/// TODO(T3): remove the env-var shim once `check-bench-preconditions`
/// is guaranteed on the bench host. Leave the command path only.
fn run_preconditions_check(mode: PreconditionMode) -> anyhow::Result<Preconditions> {
    // Attempt the real sub-process first.
    let cmd_out = std::process::Command::new("check-bench-preconditions")
        .args(["--mode", &mode.to_string(), "--json"])
        .output();

    let json_bytes: Vec<u8> = match cmd_out {
        Ok(output) if output.status.success() => output.stdout,
        Ok(output) => {
            // Non-zero exit: the script ran but judged failure. That's
            // legitimate information — pass its JSON through, do not
            // treat it as a tool-missing fallback.
            output.stdout
        }
        Err(_) => {
            // `check-bench-preconditions` not on $PATH.
            match std::env::var("BENCH_PRECONDITIONS_JSON") {
                Ok(v) => v.into_bytes(),
                Err(_) => {
                    match mode {
                        PreconditionMode::Strict => {
                            anyhow::bail!(
                                "check-bench-preconditions not found on $PATH and \
                                 BENCH_PRECONDITIONS_JSON not set; strict mode cannot \
                                 proceed without a verdict"
                            );
                        }
                        PreconditionMode::Lenient => {
                            eprintln!(
                                "bench-ab-runner: check-bench-preconditions missing; \
                                 lenient mode, assuming all-pass"
                            );
                            return Ok(all_pass_preconditions());
                        }
                    }
                }
            }
        }
    };

    parse_preconditions_json(&json_bytes)
        .context("parsing check-bench-preconditions JSON output")
}

/// Deserialize the JSON check body into a populated `Preconditions`.
///
/// Expected shape (spec §4.2):
/// ```json
/// {
///   "checks": {
///     "isolcpus":      { "pass": true,  "value": "2-7" },
///     "nohz_full":     { "pass": true,  "value": "2-7" },
///     "wc_active":     { "pass": false, "value": "C6" },
///     "rss_on":        { "na":   true                 },
///     ...
///   }
/// }
/// ```
///
/// A field may be absent, in which case the default (`PreconditionValue::default()`,
/// which is `Pass(None)`) is left in place. Runners MUST populate every
/// field explicitly when they know the verdict — otherwise missing
/// checks silently "pass". T14 (bench-report) will add `require()`-style
/// Deserialize enforcement; until then, the write path here is the
/// canonical shape.
fn parse_preconditions_json(bytes: &[u8]) -> anyhow::Result<Preconditions> {
    let json: serde_json::Value = serde_json::from_slice(bytes)?;
    let checks = json.get("checks").ok_or_else(|| {
        anyhow::anyhow!("preconditions JSON missing top-level `checks` object")
    })?;
    let mut p = Preconditions::default();

    macro_rules! set_field {
        ($field:ident, $key:literal) => {
            if let Some(c) = checks.get($key) {
                p.$field = parse_check(c);
            }
        };
    }

    set_field!(isolcpus, "isolcpus");
    set_field!(nohz_full, "nohz_full");
    set_field!(rcu_nocbs, "rcu_nocbs");
    set_field!(governor, "governor");
    set_field!(cstate_max, "cstate_max");
    set_field!(tsc_invariant, "tsc_invariant");
    set_field!(coalesce_off, "coalesce_off");
    set_field!(tso_off, "tso_off");
    set_field!(lro_off, "lro_off");
    set_field!(rss_on, "rss_on");
    set_field!(thermal_throttle, "thermal_throttle");
    set_field!(hugepages_reserved, "hugepages_reserved");
    set_field!(irqbalance_off, "irqbalance_off");
    set_field!(wc_active, "wc_active");

    Ok(p)
}

/// Decode a single `{ "pass": true, "value": "2-7" }` / `{ "na": true }`
/// object into a `PreconditionValue`. Missing-or-malformed `pass` field
/// + no `na` flag → treat as failed (safer than pass-on-garbage; strict
///   mode will then abort).
fn parse_check(c: &serde_json::Value) -> PreconditionValue {
    if c.get("na").and_then(|v| v.as_bool()).unwrap_or(false) {
        return PreconditionValue::NotApplicable;
    }
    let pass = c.get("pass").and_then(|v| v.as_bool()).unwrap_or(false);
    let value = c
        .get("value")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if pass {
        match value {
            Some(v) if !v.is_empty() => PreconditionValue::Pass(Some(v)),
            _ => PreconditionValue::Pass(None),
        }
    } else {
        match value {
            Some(v) if !v.is_empty() => PreconditionValue::Fail(Some(v)),
            _ => PreconditionValue::Fail(None),
        }
    }
}

/// Default-all-pass Preconditions struct. Used only on the lenient-mode
/// tool-missing fallback path (see `run_preconditions_check`). Every
/// field is explicitly set so no silent `Default::default()` "pass"
/// slips through.
fn all_pass_preconditions() -> Preconditions {
    Preconditions {
        isolcpus: PreconditionValue::pass(),
        nohz_full: PreconditionValue::pass(),
        rcu_nocbs: PreconditionValue::pass(),
        governor: PreconditionValue::pass(),
        cstate_max: PreconditionValue::pass(),
        tsc_invariant: PreconditionValue::pass(),
        coalesce_off: PreconditionValue::pass(),
        tso_off: PreconditionValue::pass(),
        lro_off: PreconditionValue::pass(),
        rss_on: PreconditionValue::pass(),
        thermal_throttle: PreconditionValue::pass(),
        hugepages_reserved: PreconditionValue::pass(),
        irqbalance_off: PreconditionValue::pass(),
        wc_active: PreconditionValue::pass(),
    }
}

/// Returns true iff every precondition is `Pass(_)` or `NotApplicable`.
/// `NotApplicable` counts as non-blocking because it means the tool did
/// not ask the question (spec §4.1 bench-micro carve-out for `wc_active`).
fn preconditions_all_pass(p: &Preconditions) -> bool {
    preconditions_as_pairs(p)
        .iter()
        .all(|(_, v)| v.is_pass() || v.is_not_applicable())
}

/// Zip every precondition field with its column-name label. Used by the
/// strict-mode failure reporter (`main`) and `preconditions_all_pass`.
///
/// The column names match the spec §14.1 `precondition_*` prefix so the
/// stderr enumeration reads the same as the CSV header the downstream
/// bench-report consumer sees.
fn preconditions_as_pairs(p: &Preconditions) -> [(&'static str, &PreconditionValue); 14] {
    [
        ("precondition_isolcpus", &p.isolcpus),
        ("precondition_nohz_full", &p.nohz_full),
        ("precondition_rcu_nocbs", &p.rcu_nocbs),
        ("precondition_governor", &p.governor),
        ("precondition_cstate_max", &p.cstate_max),
        ("precondition_tsc_invariant", &p.tsc_invariant),
        ("precondition_coalesce_off", &p.coalesce_off),
        ("precondition_tso_off", &p.tso_off),
        ("precondition_lro_off", &p.lro_off),
        ("precondition_rss_on", &p.rss_on),
        ("precondition_thermal_throttle", &p.thermal_throttle),
        ("precondition_hugepages_reserved", &p.hugepages_reserved),
        ("precondition_irqbalance_off", &p.irqbalance_off),
        ("precondition_wc_active", &p.wc_active),
    ]
}

/// Parse a dotted-quad IPv4 into a host-byte-order `u32` (the form
/// `EngineConfig.local_ip` / `gateway_ip` expect).
///
/// Exposed via `pub(crate)` because `workload.rs` needs it to parse
/// the peer address; `main.rs` needs it for local / gateway.
pub(crate) fn parse_ip_host_order(s: &str) -> anyhow::Result<u32> {
    let addr: std::net::Ipv4Addr = s
        .parse()
        .with_context(|| format!("invalid IPv4 address: {s}"))?;
    Ok(u32::from_be_bytes(addr.octets()))
}

/// Bring up the DPDK EAL via `dpdk_net_core::engine::eal_init`.
///
/// Routed through the core-crate wrapper (not `rte_eal_init` directly)
/// so the LLQ log-capture window fires under `--features hw-verify-llq`
/// and the once-per-process Mutex guard in `eal_init` runs. Calling the
/// bindgen symbol directly compiles fine but silently bypasses both.
fn eal_init(args: &Args) -> anyhow::Result<()> {
    // EAL argv: argv[0] = binary name; rest comes from --eal-args.
    // Whitespace-split so the harness can pass things like
    //   --eal-args="-l 2-3 -n 4 -a 0000:00:06.0,large_llq_hdr=1,miss_txc_to=3"
    // — each shell-word becomes one argv slot, and PCI devarg inner
    // commas stay intact inside the last word. `split_whitespace` already
    // skips empty segments, so `--eal-args=""` produces a lone argv[0]
    // and EAL rejects with a usage error, which is the right behavior.
    let mut eal_argv: Vec<String> = vec!["bench-ab-runner".to_string()];
    eal_argv.extend(
        args.eal_args
            .split_whitespace()
            .map(|s| s.to_string()),
    );
    let argv_refs: Vec<&str> = eal_argv.iter().map(String::as_str).collect();
    dpdk_net_core::engine::eal_init(&argv_refs)
        .map_err(|e| anyhow::anyhow!("eal_init failed: {e:?}"))
}

/// Construct an `Engine` from parsed args. Requires `eal_init` to have
/// already succeeded.
fn build_engine(args: &Args) -> anyhow::Result<dpdk_net_core::engine::Engine> {
    if args.lcore > u16::MAX as u32 {
        anyhow::bail!(
            "--lcore {} exceeds u16::MAX (EngineConfig.lcore_id)",
            args.lcore
        );
    }

    let cfg = dpdk_net_core::engine::EngineConfig {
        lcore_id: args.lcore as u16,
        local_ip: parse_ip_host_order(&args.local_ip)?,
        gateway_ip: parse_ip_host_order(&args.gateway_ip)?,
        ..dpdk_net_core::engine::EngineConfig::default()
    };

    dpdk_net_core::engine::Engine::new(cfg)
        .map_err(|e| anyhow::anyhow!("Engine::new failed: {e:?}"))
}

/// Populate `RunMetadata` from the usual sources — `git`, `hostname`,
/// `/proc/cpuinfo`, `uname -r`, `pkg-config --modversion libdpdk`.
/// Command-not-found / empty-output is absorbed into empty strings
/// rather than hard-failing, because the bench-report path can still
/// consume rows with partial metadata (it surfaces the gap as an
/// "incomplete provenance" flag rather than dropping the run).
fn build_run_metadata(
    mode: PreconditionMode,
    preconditions: Preconditions,
) -> anyhow::Result<RunMetadata> {
    let commit_sha = git_rev_parse(&["rev-parse", "HEAD"]);
    let branch = git_rev_parse(&["rev-parse", "--abbrev-ref", "HEAD"]);
    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();

    let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1).map(|v| v.trim().to_string()))
        })
        .unwrap_or_default();

    let kernel = run_capture(&["uname", "-r"]).unwrap_or_default();

    let dpdk_version = run_capture(&["pkg-config", "--modversion", "libdpdk"])
        .unwrap_or_default();

    Ok(RunMetadata {
        run_id: uuid::Uuid::new_v4(),
        run_started_at: chrono::Utc::now().to_rfc3339(),
        commit_sha,
        branch,
        host,
        instance_type: std::env::var("INSTANCE_TYPE").unwrap_or_default(),
        cpu_model,
        dpdk_version,
        kernel,
        nic_model: std::env::var("NIC_MODEL").unwrap_or_default(),
        nic_fw: std::env::var("NIC_FW").unwrap_or_default(),
        ami_id: std::env::var("AMI_ID").unwrap_or_default(),
        precondition_mode: mode,
        preconditions,
    })
}

/// Run `git <args>` and return stdout trimmed; empty string on any
/// failure (not-a-repo, git not installed, etc.).
fn git_rev_parse(args: &[&str]) -> String {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Generic `argv[0] <rest>` capture; `None` on non-success or spawn error.
fn run_capture(argv: &[&str]) -> Option<String> {
    let (cmd, rest) = argv.split_first()?;
    let out = std::process::Command::new(cmd).args(rest).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Summarise the raw samples into the 7-way `Summary` and emit one CSV
/// row per aggregation to stdout. The header is emitted automatically
/// by `csv::Writer` on the first `serialize` call (see
/// `bench_common::csv_row` for the exact column list).
fn emit_csv(args: &Args, meta: &RunMetadata, samples: &[f64]) -> anyhow::Result<()> {
    if samples.is_empty() {
        anyhow::bail!("emit_csv: no samples to summarise (iterations=0?)");
    }
    let summary: Summary = summarize(samples);
    let mut wtr = csv::Writer::from_writer(std::io::stdout());

    let dims = serde_json::json!({
        "request_bytes": args.request_bytes,
        "response_bytes": args.response_bytes,
    })
    .to_string();

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
            run_metadata: meta.clone(),
            tool: args.tool.clone(),
            test_case: "request_response_rtt".to_string(),
            feature_set: args.feature_set.clone(),
            dimensions_json: dims.clone(),
            metric_name: "rtt_ns".to_string(),
            metric_unit: "ns".to_string(),
            metric_value: value,
            metric_aggregation: agg,
        };
        wtr.serialize(&row)?;
    }
    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_accepts_strict_and_lenient() {
        assert_eq!(parse_mode("strict").unwrap(), PreconditionMode::Strict);
        assert_eq!(parse_mode("lenient").unwrap(), PreconditionMode::Lenient);
    }

    #[test]
    fn parse_mode_rejects_garbage() {
        assert!(parse_mode("loose").is_err());
    }

    #[test]
    fn parse_ip_host_order_roundtrip() {
        // 10.0.0.42 → 0x0A_00_00_2A in big-endian (host-order).
        assert_eq!(parse_ip_host_order("10.0.0.42").unwrap(), 0x0A00_002A);
        assert!(parse_ip_host_order("not.an.ip.addr").is_err());
    }

    #[test]
    fn parse_check_pass_fail_na() {
        // pass with value.
        let pv = parse_check(&serde_json::json!({"pass": true, "value": "2-7"}));
        assert_eq!(pv, PreconditionValue::pass_with("2-7"));
        // pass without value.
        let pv = parse_check(&serde_json::json!({"pass": true}));
        assert_eq!(pv, PreconditionValue::pass());
        // fail with value.
        let pv = parse_check(&serde_json::json!({"pass": false, "value": "C6"}));
        assert_eq!(pv, PreconditionValue::fail_with("C6"));
        // fail without value.
        let pv = parse_check(&serde_json::json!({"pass": false}));
        assert_eq!(pv, PreconditionValue::fail());
        // n/a.
        let pv = parse_check(&serde_json::json!({"na": true}));
        assert_eq!(pv, PreconditionValue::NotApplicable);
    }

    #[test]
    fn preconditions_all_pass_matches_all_pass_default() {
        let p = all_pass_preconditions();
        assert!(preconditions_all_pass(&p));
    }

    #[test]
    fn preconditions_all_pass_accepts_na() {
        let mut p = all_pass_preconditions();
        p.wc_active = PreconditionValue::not_applicable();
        assert!(preconditions_all_pass(&p));
    }

    #[test]
    fn preconditions_all_pass_rejects_any_fail() {
        let mut p = all_pass_preconditions();
        p.governor = PreconditionValue::fail_with("powersave");
        assert!(!preconditions_all_pass(&p));
    }

    #[test]
    fn parse_preconditions_json_partial_populates_known_fields() {
        let body = serde_json::json!({
            "checks": {
                "governor":  { "pass": true,  "value": "performance" },
                "wc_active": { "na":   true },
                "cstate_max": { "pass": false, "value": "C6" },
            }
        });
        let p = parse_preconditions_json(body.to_string().as_bytes()).unwrap();
        assert_eq!(p.governor, PreconditionValue::pass_with("performance"));
        assert!(p.wc_active.is_not_applicable());
        assert_eq!(p.cstate_max, PreconditionValue::fail_with("C6"));
        // Unset field stays at the default (Pass(None)) — this is the
        // silent-pass edge T14 will tighten.
        assert_eq!(p.isolcpus, PreconditionValue::pass());
    }

    #[test]
    fn parse_preconditions_json_missing_checks_errors() {
        let body = serde_json::json!({ "verdict": "ok" });
        assert!(parse_preconditions_json(body.to_string().as_bytes()).is_err());
    }
}
