//! bench-stress — netem + FaultInjector scenario matrix runner. A10
//! Plan B Task 7 (spec §7, parent spec §11.4).
//!
//! Drives the 8-row matrix from `scenarios.rs`. For each scenario:
//!
//! 1. Install netem on the peer (if the scenario has a netem spec) via
//!    SSH — a `NetemGuard` reverts the qdisc on drop.
//! 2. Snapshot counters.
//! 3. Run the bench-e2e request/response RTT workload over a fresh TCP
//!    connection (same inner loop as bench-e2e; see
//!    `bench_e2e::workload`).
//! 4. Snapshot counters again.
//! 5. Assert counter deltas against the scenario's
//!    `counter_expectations`.
//! 6. Compute scenario p999, divide by the idle-baseline p999, assert
//!    against `p999_ceiling_ratio`.
//! 7. Emit one CSV row per aggregation (p50, p99, p999, mean, stddev,
//!    ci95_lower, ci95_upper), `dimensions_json` carrying
//!    `{scenario, netem_config, fault_injector_config}`.
//!
//! # FaultInjector runtime configuration
//!
//! The A9 FaultInjector reads `DPDK_NET_FAULT_INJECTOR` once at engine
//! bring-up (see `fault_injector.rs::FaultConfig::from_env`). To sweep
//! different FI specs in one process we'd need to re-create the engine
//! per scenario, which means re-EAL-init — and EAL init is
//! once-per-process. The approved shape for Stage 1 is therefore
//! "one FI spec per process invocation": the driver sets the env var
//! before EAL init, runs the FI-only scenarios that match, and
//! netem-only scenarios run on the same engine with the env var unset.
//!
//! In practice the caller invokes bench-stress twice: once with
//! `--scenarios random_loss_01pct_10ms,correlated_burst_loss_1pct,...`
//! (netem-only) and once per FaultInjector scenario. The driver
//! enforces the invariant at startup (single FI spec, matches the
//! intersection of requested scenarios).
//!
//! # Preset
//!
//! Trading-latency default (spec §7 note). Not RFC compliance.

use anyhow::Context;
use clap::Parser;

use bench_common::csv_row::{CsvRow, MetricAggregation};
use bench_common::percentile::{summarize, Summary};
use bench_common::preconditions::{PreconditionMode, PreconditionValue, Preconditions};
use bench_common::run_metadata::RunMetadata;

use bench_e2e::workload::{open_connection, run_rtt_workload};

use dpdk_net_core::counters::Counters;
use dpdk_net_core::engine::Engine;

use bench_stress::counters_snapshot::{
    assert_delta, collect_names_from_matrix, snapshot, Relation, Snapshot,
};
use bench_stress::netem::NetemGuard;
use bench_stress::scenarios::{is_stage2_placeholder, Scenario, MATRIX};

#[derive(Parser, Debug)]
#[command(version, about = "bench-stress — netem + FaultInjector scenario matrix")]
struct Args {
    /// SSH target for the peer host (e.g. `ubuntu@10.0.0.43`). Used for
    /// `tc qdisc` installs; unused for FaultInjector-only scenarios.
    #[arg(long)]
    peer_ssh: String,

    /// Peer iface name for netem (e.g. `ens6`).
    #[arg(long)]
    peer_iface: String,

    /// Peer IP (dotted-quad IPv4).
    #[arg(long)]
    peer_ip: String,

    /// Peer TCP port.
    #[arg(long, default_value_t = 10_001)]
    peer_port: u16,

    /// Output CSV path. One row per (scenario, aggregation); 7
    /// aggregations per scenario (p50/p99/p999/mean/stddev/ci95_lo/hi).
    #[arg(long)]
    output_csv: std::path::PathBuf,

    /// Comma-separated list of scenario names to run. Empty = all
    /// non-Stage-2 scenarios. Unknown names error at startup.
    #[arg(long, default_value = "")]
    scenarios: String,

    /// Iterations per scenario. Spec §7 defers the exact count to the
    /// plan — we default to 10_000 which is enough for a stable p999
    /// and fast enough that the 8-row sweep completes in a few
    /// minutes. Operators override for longer sweeps.
    #[arg(long, default_value_t = 10_000)]
    iterations: u64,

    /// Warmup iterations per scenario (discarded).
    #[arg(long, default_value_t = 500)]
    warmup: u64,

    /// Request payload size in bytes (same shape as bench-e2e).
    #[arg(long, default_value_t = 128)]
    request_bytes: usize,

    /// Response payload size in bytes.
    #[arg(long, default_value_t = 128)]
    response_bytes: usize,

    /// Local IP (dotted-quad IPv4).
    #[arg(long)]
    local_ip: String,

    /// Local gateway IP (dotted-quad IPv4).
    #[arg(long)]
    gateway_ip: String,

    /// EAL args, comma-separated. Same shape as bench-e2e.
    #[arg(long)]
    eal_args: String,

    /// Lcore to pin the engine to.
    #[arg(long, default_value_t = 2)]
    lcore: u32,

    /// Precondition mode: `strict` aborts on any precondition failure;
    /// `lenient` warns and continues.
    #[arg(long, default_value = "strict")]
    precondition_mode: String,

    /// Tool label emitted as the `tool` CSV column.
    #[arg(long, default_value = "bench-stress")]
    tool: String,

    /// Feature-set label emitted as the `feature_set` CSV column.
    #[arg(long, default_value = "trading-latency")]
    feature_set: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mode = parse_mode(&args.precondition_mode)?;

    // 1. Resolve which scenarios to run.
    let selected = resolve_scenarios(&args.scenarios)?;
    if selected.is_empty() {
        anyhow::bail!("no scenarios selected after filter + Stage-2 skip");
    }

    // 2. Invariant: at most one distinct FI spec across the selection
    // (see main-module doc: EAL is once-per-process, FI config is read
    // at engine bring-up).
    enforce_single_fi_spec(&selected)?;

    // 3. Precondition check.
    let preconditions = run_preconditions_check(mode)?;
    if mode == PreconditionMode::Strict && !preconditions_all_pass(&preconditions) {
        eprintln!("bench-stress: precondition failure in strict mode:");
        for (name, value) in preconditions_as_pairs(&preconditions) {
            if !(value.is_pass() || value.is_not_applicable()) {
                eprintln!("  {name} = {value}");
            }
        }
        std::process::exit(1);
    }

    // 4. Determine the FI spec (if any) and set the env var BEFORE EAL
    // init. `DPDK_NET_FAULT_INJECTOR` is read once by
    // `FaultConfig::from_env`; setting after bring-up is a no-op.
    if let Some(spec) = fi_spec(&selected) {
        std::env::set_var("DPDK_NET_FAULT_INJECTOR", spec);
    }

    // 5. EAL + engine bring-up (once per process).
    eal_init(&args)?;
    let _eal_guard = EalGuard;
    let engine = build_engine(&args)?;
    let tsc_hz = unsafe { dpdk_net_sys::rte_get_tsc_hz() };
    if tsc_hz == 0 {
        anyhow::bail!("rte_get_tsc_hz() returned 0 — EAL not initialised?");
    }

    // 6. Build the global counter-name set once.
    let counter_names = collect_names_from_matrix(selected.iter().copied());
    // Sanity: all names must resolve now. A missing wire surfaces as an
    // UnknownCounter error at startup rather than mid-sweep.
    let _ = snapshot(engine.counters(), &counter_names)?;

    // 7. Idle baseline — no netem, no FI spec. Skipped if FI is enabled
    // because there's no "FI-off" path on the same engine; the p999
    // ratio in FI scenarios compares to whatever the caller had set as
    // a prior idle run. Driver emits a diagnostic row so consumers
    // downstream can tell.
    let idle_baseline = if fi_spec(&selected).is_none() {
        Some(run_idle_baseline(&engine, &args, tsc_hz)?)
    } else {
        eprintln!(
            "bench-stress: FI spec is set for this run; \
             idle baseline skipped (p999 ratio checks short-circuit on idle_p999=None)"
        );
        None
    };

    // 8. Sweep scenarios.
    let metadata = build_run_metadata(mode, preconditions)?;
    let mut writer = csv::Writer::from_path(&args.output_csv)
        .with_context(|| format!("creating output CSV {:?}", args.output_csv))?;

    for scenario in &selected {
        run_one_scenario(
            &engine,
            &args,
            tsc_hz,
            scenario,
            &counter_names,
            idle_baseline,
            &metadata,
            &mut writer,
        )?;
    }
    writer.flush()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-scenario driver.
// ---------------------------------------------------------------------------

/// Drive one scenario to completion and emit its 7 CSV rows. Returns
/// the scenario's p999 so a future caller could compute cross-scenario
/// aggregates; the in-process p999-ratio check runs inline here.
#[allow(clippy::too_many_arguments)]
fn run_one_scenario<W: std::io::Write>(
    engine: &Engine,
    args: &Args,
    tsc_hz: u64,
    scenario: &Scenario,
    counter_names: &[&'static str],
    idle_baseline: Option<f64>,
    metadata: &RunMetadata,
    writer: &mut csv::Writer<W>,
) -> anyhow::Result<f64> {
    eprintln!("bench-stress: scenario {}", scenario.name);

    // 1. Install netem if the scenario needs it. Dropped on scope exit.
    let _netem_guard = match scenario.netem {
        Some(spec) => Some(
            NetemGuard::apply(&args.peer_ssh, &args.peer_iface, spec)
                .with_context(|| format!("applying netem for scenario {}", scenario.name))?,
        ),
        None => None,
    };

    // 2. Pre-run counter snapshot.
    let pre: Snapshot = snapshot(engine.counters(), counter_names)?;

    // 3. Open a fresh connection and run the workload. Each scenario
    // uses a fresh connection so state (cwnd, RACK history, RTO state)
    // doesn't leak across scenarios.
    let peer_ip = parse_ip_host_order(&args.peer_ip)?;
    let conn = open_connection(engine, peer_ip, args.peer_port)?;
    let samples = run_rtt_workload(
        engine,
        conn,
        args.request_bytes,
        args.response_bytes,
        tsc_hz,
        args.warmup,
        args.iterations,
    )?;
    if samples.is_empty() {
        anyhow::bail!("scenario {} produced no samples", scenario.name);
    }

    // 4. Post-run counter snapshot.
    let post: Snapshot = snapshot(engine.counters(), counter_names)?;

    // 5. Assert counter expectations.
    for (counter, rel_str) in scenario.counter_expectations {
        let rel = Relation::parse(rel_str).with_context(|| {
            format!("parsing relation for counter {counter} in scenario {}", scenario.name)
        })?;
        assert_delta(&pre, &post, counter, rel).map_err(|e| {
            anyhow::anyhow!(
                "scenario {} counter check failed: {e}",
                scenario.name
            )
        })?;
    }

    // 6. Summarise + p999 ratio check.
    let summary = summarize(&samples);
    if let (Some(ratio), Some(baseline)) = (scenario.p999_ceiling_ratio, idle_baseline) {
        let observed = summary.p999 / baseline;
        if observed > ratio {
            anyhow::bail!(
                "scenario {} p999 ratio {:.3} exceeded ceiling {:.3} \
                 (scenario p999 = {:.1} ns, idle p999 = {:.1} ns)",
                scenario.name,
                observed,
                ratio,
                summary.p999,
                baseline
            );
        }
    }

    // 7. Emit CSV rows.
    emit_scenario_rows(writer, args, metadata, scenario, &summary)?;

    Ok(summary.p999)
}

/// Run the RTT workload against an idle peer (no netem, no FI) to
/// establish the baseline p999 that per-scenario ratio checks divide
/// against. Same shape as a scenario run, minus the pre/post counter
/// assertions.
fn run_idle_baseline(engine: &Engine, args: &Args, tsc_hz: u64) -> anyhow::Result<f64> {
    eprintln!("bench-stress: idle baseline");
    let peer_ip = parse_ip_host_order(&args.peer_ip)?;
    let conn = open_connection(engine, peer_ip, args.peer_port)?;
    let samples = run_rtt_workload(
        engine,
        conn,
        args.request_bytes,
        args.response_bytes,
        tsc_hz,
        args.warmup,
        args.iterations,
    )?;
    if samples.is_empty() {
        anyhow::bail!("idle baseline produced no samples");
    }
    let summary = summarize(&samples);
    Ok(summary.p999)
}

// ---------------------------------------------------------------------------
// Scenario selection + FI spec invariant.
// ---------------------------------------------------------------------------

/// Resolve the CLI `--scenarios` filter into a list of Scenario refs.
/// Empty filter → all non-Stage-2 scenarios. Unknown names error.
fn resolve_scenarios(filter: &str) -> anyhow::Result<Vec<&'static Scenario>> {
    if filter.is_empty() {
        return Ok(MATRIX.iter().filter(|s| !is_stage2_placeholder(s)).collect());
    }
    let mut out = Vec::new();
    for name in filter.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let s = bench_stress::scenarios::find(name).ok_or_else(|| {
            anyhow::anyhow!("unknown scenario name: {name}")
        })?;
        if is_stage2_placeholder(s) {
            anyhow::bail!(
                "scenario {name} is a Stage-2 placeholder; \
                 cannot be selected in Stage 1 runs"
            );
        }
        out.push(s);
    }
    Ok(out)
}

/// The FI spec for this run, or `None` if the selection has no FI
/// scenarios. Caller invokes before EAL init.
fn fi_spec(selected: &[&Scenario]) -> Option<&'static str> {
    selected.iter().find_map(|s| s.fault_injector)
}

/// Enforce: at most one distinct FI spec across the selection.
/// Rationale: EAL init is once-per-process, FaultConfig is read once at
/// engine bring-up. Two different FI specs in one sweep are a no-go.
fn enforce_single_fi_spec(selected: &[&Scenario]) -> anyhow::Result<()> {
    let mut seen: Option<&'static str> = None;
    for s in selected {
        if let Some(spec) = s.fault_injector {
            match seen {
                None => seen = Some(spec),
                Some(prev) if prev == spec => {}
                Some(prev) => {
                    anyhow::bail!(
                        "multiple distinct FaultInjector specs in selected scenarios: \
                         {prev:?} vs {spec:?}. Re-run per spec (see main-module doc).",
                    );
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CSV emit.
// ---------------------------------------------------------------------------

fn emit_scenario_rows<W: std::io::Write>(
    writer: &mut csv::Writer<W>,
    args: &Args,
    metadata: &RunMetadata,
    scenario: &Scenario,
    summary: &Summary,
) -> anyhow::Result<()> {
    let dims = serde_json::json!({
        "scenario": scenario.name,
        "netem_config": scenario.netem.unwrap_or(""),
        "fault_injector_config": scenario.fault_injector.unwrap_or(""),
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
            run_metadata: metadata.clone(),
            tool: args.tool.clone(),
            test_case: "stress_rtt".to_string(),
            feature_set: args.feature_set.clone(),
            dimensions_json: dims.clone(),
            metric_name: "rtt_ns".to_string(),
            metric_unit: "ns".to_string(),
            metric_value: value,
            metric_aggregation: agg,
        };
        writer.serialize(&row)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EAL + engine bring-up + preconditions + metadata.
// Same shape as bench-e2e — duplicated rather than pulled into a shared
// crate because each bench tool's metadata captures its own tool label
// and bench-common stays pure-data.
// ---------------------------------------------------------------------------

struct EalGuard;

impl Drop for EalGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = dpdk_net_sys::rte_eal_cleanup();
        }
    }
}

fn parse_mode(s: &str) -> anyhow::Result<PreconditionMode> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn parse_ip_host_order(s: &str) -> anyhow::Result<u32> {
    let addr: std::net::Ipv4Addr = s
        .parse()
        .with_context(|| format!("invalid IPv4 address: {s}"))?;
    Ok(u32::from_be_bytes(addr.octets()))
}

fn eal_init(args: &Args) -> anyhow::Result<()> {
    let mut eal_argv: Vec<String> = vec!["bench-stress".to_string()];
    eal_argv.extend(
        args.eal_args
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
    );
    let argv_refs: Vec<&str> = eal_argv.iter().map(String::as_str).collect();
    dpdk_net_core::engine::eal_init(&argv_refs)
        .map_err(|e| anyhow::anyhow!("eal_init failed: {e:?}"))
}

fn build_engine(args: &Args) -> anyhow::Result<Engine> {
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
    Engine::new(cfg).map_err(|e| anyhow::anyhow!("Engine::new failed: {e:?}"))
}

fn run_preconditions_check(mode: PreconditionMode) -> anyhow::Result<Preconditions> {
    let cmd_out = std::process::Command::new("check-bench-preconditions")
        .args(["--mode", &mode.to_string(), "--json"])
        .output();

    let json_bytes: Vec<u8> = match cmd_out {
        Ok(output) if output.status.success() => output.stdout,
        Ok(output) => output.stdout,
        Err(_) => match std::env::var("BENCH_PRECONDITIONS_JSON") {
            Ok(v) => v.into_bytes(),
            Err(_) => match mode {
                PreconditionMode::Strict => {
                    anyhow::bail!(
                        "check-bench-preconditions not found on $PATH and \
                         BENCH_PRECONDITIONS_JSON not set; strict mode cannot \
                         proceed without a verdict"
                    );
                }
                PreconditionMode::Lenient => {
                    eprintln!(
                        "bench-stress: check-bench-preconditions missing; \
                         lenient mode, assuming all-pass"
                    );
                    return Ok(all_pass_preconditions());
                }
            },
        },
    };

    parse_preconditions_json(&json_bytes)
        .context("parsing check-bench-preconditions JSON output")
}

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

fn preconditions_all_pass(p: &Preconditions) -> bool {
    preconditions_as_pairs(p)
        .iter()
        .all(|(_, v)| v.is_pass() || v.is_not_applicable())
}

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
    let dpdk_version = run_capture(&["pkg-config", "--modversion", "libdpdk"]).unwrap_or_default();

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

fn git_rev_parse(args: &[&str]) -> String {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn run_capture(argv: &[&str]) -> Option<String> {
    let (cmd, rest) = argv.split_first()?;
    let out = std::process::Command::new(cmd).args(rest).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// -- Silence unused-code warnings on tests path --
#[allow(dead_code)]
fn _unused_counters_ref(_: &Counters) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_scenarios_empty_filter_returns_non_stage2_only() {
        let selected = resolve_scenarios("").unwrap();
        // Non-Stage-2 count = MATRIX.len() - 1 (just the pmtu placeholder).
        assert_eq!(selected.len(), MATRIX.len() - 1);
        assert!(selected.iter().all(|s| !is_stage2_placeholder(s)));
    }

    #[test]
    fn resolve_scenarios_filter_matches_names() {
        let selected =
            resolve_scenarios("random_loss_01pct_10ms,duplication_2x").unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].name, "random_loss_01pct_10ms");
        assert_eq!(selected[1].name, "duplication_2x");
    }

    #[test]
    fn resolve_scenarios_rejects_unknown_name() {
        assert!(resolve_scenarios("garbage_name").is_err());
    }

    #[test]
    fn resolve_scenarios_rejects_stage2_placeholder() {
        let err = resolve_scenarios("pmtu_blackhole_STAGE2").unwrap_err();
        assert!(err.to_string().contains("Stage-2 placeholder"));
    }

    #[test]
    fn resolve_scenarios_handles_whitespace_and_empty_entries() {
        // Defensive parse: leading/trailing whitespace, empty entries.
        let selected = resolve_scenarios(" random_loss_01pct_10ms , ,duplication_2x ").unwrap();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn enforce_single_fi_spec_accepts_all_netem_only() {
        let selected: Vec<_> = MATRIX
            .iter()
            .filter(|s| s.fault_injector.is_none() && !is_stage2_placeholder(s))
            .collect();
        assert!(enforce_single_fi_spec(&selected).is_ok());
    }

    #[test]
    fn enforce_single_fi_spec_accepts_same_spec() {
        // Construct the same scenario twice to simulate a repeat.
        let s1 = bench_stress::scenarios::find("fault_injector_drop_1pct").unwrap();
        let selected = vec![s1, s1];
        assert!(enforce_single_fi_spec(&selected).is_ok());
    }

    #[test]
    fn enforce_single_fi_spec_rejects_two_different_specs() {
        let s1 = bench_stress::scenarios::find("fault_injector_drop_1pct").unwrap();
        let s2 = bench_stress::scenarios::find("fault_injector_reorder_05pct").unwrap();
        let selected = vec![s1, s2];
        assert!(enforce_single_fi_spec(&selected).is_err());
    }

    #[test]
    fn fi_spec_returns_none_for_netem_only_selection() {
        let selected: Vec<_> = MATRIX
            .iter()
            .filter(|s| s.netem.is_some())
            .collect();
        assert!(fi_spec(&selected).is_none());
    }

    #[test]
    fn fi_spec_returns_the_spec_when_present() {
        let s = bench_stress::scenarios::find("fault_injector_drop_1pct").unwrap();
        let selected = vec![s];
        assert_eq!(fi_spec(&selected), Some("drop=0.01"));
    }

    #[test]
    fn parse_ip_host_order_roundtrip() {
        assert_eq!(parse_ip_host_order("10.0.0.42").unwrap(), 0x0A00_002A);
        assert!(parse_ip_host_order("not.an.ip.addr").is_err());
    }

    #[test]
    fn parse_mode_accepts_strict_and_lenient() {
        assert_eq!(parse_mode("strict").unwrap(), PreconditionMode::Strict);
        assert_eq!(parse_mode("lenient").unwrap(), PreconditionMode::Lenient);
    }
}
