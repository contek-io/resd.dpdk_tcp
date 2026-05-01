//! layer-h-correctness binary. Spec §7 (CLI), §3.4 (process model),
//! §5.4 (per-scenario lifecycle).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser;
use uuid::Uuid;

use bench_common::preconditions::{PreconditionMode, Preconditions};
use bench_stress::netem::NetemGuard;

use dpdk_net_core::engine::{Engine, EngineConfig};

use layer_h_correctness::counters_snapshot;
use layer_h_correctness::observation::Verdict;
use layer_h_correctness::report::{
    bundle_path, write_failure_bundle, write_markdown_report, ReportHeader,
};
use layer_h_correctness::scenarios::{find as find_scenario, MATRIX};
use layer_h_correctness::workload::{
    run_one_scenario, select_counter_names,
};

const SMOKE_SET: &[&str] = &[
    "delay_50ms_jitter_10ms",
    "loss_1pct",
    "dup_2pct",
    "reorder_depth_3",
    "corruption_001pct",
];

#[derive(Parser, Debug)]
#[command(version, about = "layer-h-correctness — Stage 1 Phase A10.5 correctness gate")]
struct Args {
    /// SSH target for the peer host. Required unless `--external-netem`.
    #[arg(long)]
    peer_ssh: Option<String>,

    /// Peer iface name for netem. Required unless `--external-netem`.
    #[arg(long)]
    peer_iface: Option<String>,

    /// Peer data-plane IP (dotted-quad).
    #[arg(long)]
    peer_ip: String,

    /// Peer TCP port.
    #[arg(long, default_value_t = 10_001)]
    peer_port: u16,

    /// Local data-plane IP.
    #[arg(long)]
    local_ip: String,

    /// Local gateway IP.
    #[arg(long)]
    gateway_ip: String,

    /// EAL args, whitespace-separated.
    #[arg(long, allow_hyphen_values = true)]
    eal_args: String,

    /// Lcore to pin the engine to.
    #[arg(long, default_value_t = 2)]
    lcore: u32,

    #[arg(long, default_value = "strict")]
    precondition_mode: String,

    /// Skip in-process netem install (operator-side orchestration).
    #[arg(long, default_value_t = false)]
    external_netem: bool,

    /// Comma-separated scenario names. Empty = all pure-netem rows.
    /// Mutually exclusive with --smoke.
    #[arg(long, default_value = "", conflicts_with = "smoke")]
    scenarios: String,

    /// Resolve to the 5-scenario CI smoke set.
    #[arg(long, default_value_t = false)]
    smoke: bool,

    /// Print the resolved selection and exit (no EAL init).
    #[arg(long, default_value_t = false)]
    list_scenarios: bool,

    /// Markdown report destination. Required.
    #[arg(long)]
    report_md: PathBuf,

    /// Overwrite --report-md if it exists.
    #[arg(long, default_value_t = false)]
    force: bool,

    /// Per-failed-scenario JSON bundle directory.
    #[arg(long)]
    bundle_dir: Option<PathBuf>,

    /// Override every row's duration (debugging convenience).
    #[arg(long)]
    duration_override: Option<u64>,

    /// Request payload size for the RTT workload.
    #[arg(long, default_value_t = 128)]
    request_bytes: usize,

    /// Response payload size for the RTT workload.
    #[arg(long, default_value_t = 128)]
    response_bytes: usize,
}

fn main() {
    match run() {
        Ok(0) => std::process::exit(0),
        Ok(n) => std::process::exit(n),
        Err(e) => {
            eprintln!("layer-h-correctness: {e:#}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<i32> {
    let args = Args::parse();

    // 0. --report-md clobber check (before EAL init so a clobber doesn't
    //    waste a fleet-bring-up cycle).
    if args.report_md.exists() && !args.force {
        anyhow::bail!(
            "report path {} already exists; pass --force to overwrite",
            args.report_md.display()
        );
    }

    // 1. Resolve scenario selection.
    let selection = resolve_selection(&args)?;
    if selection.is_empty() {
        anyhow::bail!("no scenarios selected after filter");
    }

    // 2. Single-FI-spec invariant. Runs before the --list-scenarios
    //    short-circuit so the operator surfaces a multi-FI-spec mistake
    //    even when listing (the listing is a planning aid; if the
    //    selection wouldn't run, listing it is misleading).
    enforce_single_fi_spec(&selection)?;

    // 3. --list-scenarios short-circuits before EAL init.
    if args.list_scenarios {
        for s in &selection {
            println!("{}", s.name);
        }
        return Ok(0);
    }

    // 4. Validate netem-required-args invariant.
    let needs_peer_ssh = !args.external_netem
        && selection.iter().any(|s| s.netem.is_some());
    if needs_peer_ssh && (args.peer_ssh.is_none() || args.peer_iface.is_none()) {
        anyhow::bail!(
            "--peer-ssh and --peer-iface required for in-process netem; \
             pass --external-netem if the operator orchestrates netem"
        );
    }

    // 5. Pre-flight: parse all relations + resolve all counter names.
    pre_flight_validate(&selection)?;

    // 6. Set FI env-var (must be before EAL init; FaultConfig::from_env
    //    is read once at engine bring-up).
    let fi_spec_for_run = selection.iter().find_map(|s| s.fault_injector);
    if let Some(spec) = fi_spec_for_run {
        std::env::set_var("DPDK_NET_FAULT_INJECTOR", spec);
    }

    // 7. EAL + engine bring-up.
    eal_init(&args)?;
    let _eal_guard = EalGuard;
    let engine = build_engine(&args)?;
    let tsc_hz = unsafe { dpdk_net_sys::rte_get_tsc_hz() };
    if tsc_hz == 0 {
        anyhow::bail!("rte_get_tsc_hz() returned 0 — EAL not initialised?");
    }

    // 8. Counter names + run-id + bundle dir.
    let counter_names = select_counter_names(&selection);
    let run_id = Uuid::new_v4();
    let bundle_dir = args
        .bundle_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("target/layer-h-bundles/{run_id}")));

    // 9. Sweep.
    let peer_ip_h = parse_ip_host_order(&args.peer_ip)?;
    let duration_override = args.duration_override.map(Duration::from_secs);

    let mut results = Vec::with_capacity(selection.len());
    for scenario in &selection {
        // Install netem (skipped under --external-netem).
        let _netem_guard = match (scenario.netem, args.external_netem) {
            (Some(spec), false) => Some(
                NetemGuard::apply(
                    args.peer_ssh.as_deref().unwrap(),
                    args.peer_iface.as_deref().unwrap(),
                    spec,
                )
                .with_context(|| format!("apply netem for scenario {}", scenario.name))?,
            ),
            (Some(_), true) | (None, _) => None,
        };

        let result = run_one_scenario(
            &engine,
            scenario,
            &counter_names,
            peer_ip_h,
            args.peer_port,
            args.request_bytes,
            args.response_bytes,
            tsc_hz,
            duration_override,
        )?;

        if let Verdict::Fail { failures } = &result.verdict {
            let path = bundle_path(&bundle_dir, scenario.name);
            let mut ring = result.event_ring.clone_for_bundle();
            let truncated = ring.truncated();
            let events = ring.drain_into_vec();
            write_failure_bundle(
                &path,
                scenario.name,
                scenario.netem,
                scenario.fault_injector,
                result.duration_observed.as_secs_f64(),
                &result.snapshot_pre,
                &result.snapshot_post,
                failures,
                events,
                truncated,
            )?;
        }
        results.push(result);
    }

    // 10. Write Markdown report.
    let header = build_header(&engine, run_id, fi_spec_for_run);
    write_markdown_report(&args.report_md, &header, &results, args.force)
        .with_context(|| format!("write report {}", args.report_md.display()))?;

    let any_fail = results
        .iter()
        .any(|r| matches!(r.verdict, Verdict::Fail { .. }));
    Ok(if any_fail { 1 } else { 0 })
}

fn resolve_selection(args: &Args) -> Result<Vec<&'static layer_h_correctness::scenarios::LayerHScenario>> {
    if args.smoke {
        let mut out = Vec::with_capacity(SMOKE_SET.len());
        for n in SMOKE_SET {
            let s = find_scenario(n)
                .ok_or_else(|| anyhow::anyhow!("smoke scenario {n} missing from MATRIX"))?;
            out.push(s);
        }
        return Ok(out);
    }
    if args.scenarios.trim().is_empty() {
        // Default = all pure-netem rows (exclude composed). Composed
        // rows require explicit selection (they each carry a distinct
        // FI spec; the single-FI-spec invariant excludes mixing).
        return Ok(MATRIX
            .iter()
            .filter(|s| s.fault_injector.is_none())
            .collect());
    }
    let mut out = Vec::new();
    for name in args.scenarios.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let s = find_scenario(name).ok_or_else(|| {
            anyhow::anyhow!("unknown scenario name: {name}")
        })?;
        out.push(s);
    }
    Ok(out)
}

fn enforce_single_fi_spec(
    selection: &[&'static layer_h_correctness::scenarios::LayerHScenario],
) -> Result<()> {
    let mut seen: Option<&'static str> = None;
    for s in selection {
        if let Some(spec) = s.fault_injector {
            match seen {
                None => seen = Some(spec),
                Some(prev) if prev == spec => {}
                Some(prev) => {
                    anyhow::bail!(
                        "two distinct FaultInjector specs in selection: \
                         {prev:?} vs {spec:?}. EAL is once-per-process; \
                         re-run per FI spec (see scripts/layer-h-nightly.sh)."
                    );
                }
            }
        }
    }
    Ok(())
}

fn pre_flight_validate(
    selection: &[&'static layer_h_correctness::scenarios::LayerHScenario],
) -> Result<()> {
    use layer_h_correctness::assertions::Relation;

    let dummy_counters = dpdk_net_core::counters::Counters::new();
    for s in selection {
        for (name, rel_str) in s.counter_expectations {
            Relation::parse(rel_str).with_context(|| {
                format!("scenario {}: relation {rel_str:?}", s.name)
            })?;
            counters_snapshot::read(&dummy_counters, name).ok_or_else(|| {
                anyhow::anyhow!(
                    "scenario {}: counter {name:?} not in lookup_counter",
                    s.name
                )
            })?;
        }
        for (group, rel_str) in s.disjunctive_expectations {
            Relation::parse(rel_str).with_context(|| {
                format!("scenario {}: disjunctive relation {rel_str:?}", s.name)
            })?;
            for n in *group {
                counters_snapshot::read(&dummy_counters, n).ok_or_else(|| {
                    anyhow::anyhow!(
                        "scenario {}: disjunctive counter {n:?} not in lookup_counter",
                        s.name
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn parse_ip_host_order(s: &str) -> Result<u32> {
    let addr: std::net::Ipv4Addr =
        s.parse().with_context(|| format!("invalid IPv4 address: {s}"))?;
    Ok(u32::from_be_bytes(addr.octets()))
}

struct EalGuard;
impl Drop for EalGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = dpdk_net_sys::rte_eal_cleanup();
        }
    }
}

fn eal_init(args: &Args) -> Result<()> {
    let mut eal_argv: Vec<String> = vec!["layer-h-correctness".to_string()];
    eal_argv.extend(args.eal_args.split_whitespace().map(String::from));
    let argv_refs: Vec<&str> = eal_argv.iter().map(String::as_str).collect();
    dpdk_net_core::engine::eal_init(&argv_refs)
        .map_err(|e| anyhow::anyhow!("eal_init failed: {e:?}"))
}

fn build_engine(args: &Args) -> Result<Engine> {
    if args.lcore > u16::MAX as u32 {
        anyhow::bail!("--lcore {} exceeds u16::MAX", args.lcore);
    }
    let cfg = EngineConfig {
        lcore_id: args.lcore as u16,
        local_ip: parse_ip_host_order(&args.local_ip)?,
        gateway_ip: parse_ip_host_order(&args.gateway_ip)?,
        ..EngineConfig::default()
    };
    Engine::new(cfg).map_err(|e| anyhow::anyhow!("Engine::new failed: {e:?}"))
}

fn build_header(engine: &Engine, run_id: Uuid, fi_spec: Option<&str>) -> ReportHeader {
    let cfg = engine.config();
    // The header's hw_offload_rx_cksum / fault_injector flags reflect the
    // dpdk-net-core dep's compile-time feature set. Those features live on
    // the dep crate, not this one; cfg!() over them in *this* crate's
    // build returns false unless we declare local forwarders. The
    // `#[allow]` keeps the report fields wired to the spec-defined slots
    // while the future-cleanup task lands the forwarder features.
    #[allow(unexpected_cfgs)]
    let hw_offload_rx_cksum = cfg!(feature = "hw-offload-rx-cksum");
    #[allow(unexpected_cfgs)]
    let fault_injector = cfg!(feature = "fault-injector");
    ReportHeader {
        run_id: run_id.to_string(),
        commit_sha: git_rev_parse(),
        branch: git_branch(),
        host: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default(),
        nic_model: std::env::var("NIC_MODEL").unwrap_or_default(),
        dpdk_version: pkg_config_dpdk_version(),
        preset: "trading-latency",
        tcp_max_retrans_count: cfg.tcp_max_retrans_count,
        hw_offload_rx_cksum,
        fault_injector,
        fi_spec: fi_spec.map(String::from),
    }
}

fn git_rev_parse() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn git_branch() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn pkg_config_dpdk_version() -> String {
    std::process::Command::new("pkg-config")
        .args(["--modversion", "libdpdk"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

// Suppress unused-import lint when the harness binary's unit tests grow
// later; for now the bin has no #[cfg(test)] mod.
#[allow(dead_code)]
fn _swallow_unused_imports() {
    let _ = PreconditionMode::Strict;
    let _ = Preconditions::default();
}
