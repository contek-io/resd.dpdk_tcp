//! bench-vs-linux — dual-stack latency comparison vs. Linux TCP.
//!
//! A10 Plan B Task 8 (spec §8, parent spec §11.5). Mode A only: RTT
//! distribution across up to three stacks (dpdk_net, linux_kernel,
//! afpacket) under the trading-latency preset. Mode B (wire-diff,
//! rfc_compliance preset) lands in T9 — `--mode wire-diff` routes to
//! the T9 stub and errors with a pointer.
//!
//! # Preset
//!
//! Trading-latency default on both stacks. The engine is built via
//! `EngineConfig::default()` — same config shape as bench-e2e /
//! bench-stress. `preset=rfc_compliance` is exclusive to mode B per
//! spec §8.
//!
//! # Process shape
//!
//! One EAL init per process (DPDK 23.11 constraint; matches bench-
//! ab-runner / bench-e2e / bench-stress). If dpdk_net is not in the
//! selected stacks, EAL init is skipped entirely so operators can
//! run a linux-kernel-only comparison without a DPDK-capable host.
//!
//! # CSV output
//!
//! One set of 7 rows (p50/p99/p999/mean/stddev/ci95_lo/hi) per
//! (stack, workload) tuple, written to `--output-csv`.
//! `dimensions_json` tags each row with `{preset, mode, stack}` so
//! bench-report can group by stack without averaging across presets.

use anyhow::Context;
use clap::Parser;

use bench_common::preconditions::{PreconditionMode, PreconditionValue, Preconditions};
use bench_common::run_metadata::RunMetadata;

use bench_vs_linux::mode_rtt::{run_mode_rtt, ModeRttCfg};
use bench_vs_linux::mode_wire_diff;
use bench_vs_linux::{Mode, Stack};

use dpdk_net_core::engine::Engine;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "bench-vs-linux — dual-stack latency comparison vs. Linux TCP"
)]
struct Args {
    /// Mode selector: `rtt` (T8 — trading-latency preset, RTT across
    /// three stacks) or `wire-diff` (T9 — rfc_compliance preset,
    /// pcap canonicalise + byte-diff).
    #[arg(long, default_value = "rtt")]
    mode: String,

    /// Peer IP (dotted-quad IPv4).
    #[arg(long)]
    peer_ip: String,

    /// Peer TCP port.
    #[arg(long, default_value_t = 10_001)]
    peer_port: u16,

    /// Peer iface name — used by the AF_PACKET path (unused on the
    /// dpdk + linux_kernel paths; still required for uniform CLI).
    #[arg(long, default_value = "")]
    peer_iface: String,

    /// CSV of stacks to run. Tokens: `dpdk`, `linux`, `afpacket`.
    /// Default is all three; the AF_PACKET path errors at startup in
    /// T8 (see src/afpacket.rs module docs) so real T8 runs pass
    /// `--stacks dpdk,linux` unless lenient mode is set.
    #[arg(long, default_value = "dpdk,linux,afpacket")]
    stacks: String,

    /// Request payload size in bytes (same default as bench-e2e).
    #[arg(long, default_value_t = 128)]
    request_bytes: usize,

    /// Response payload size in bytes.
    #[arg(long, default_value_t = 128)]
    response_bytes: usize,

    /// Measurement iteration count (per stack).
    #[arg(long, default_value_t = 100_000)]
    iterations: u64,

    /// Warmup iteration count (per stack, discarded).
    #[arg(long, default_value_t = 1_000)]
    warmup: u64,

    /// Output CSV path.
    #[arg(long)]
    output_csv: std::path::PathBuf,

    /// Precondition mode: `strict` aborts on precondition failure OR
    /// on a selected stack failing bring-up (e.g. the AF_PACKET stub
    /// error); `lenient` warns and skips the stack.
    #[arg(long, default_value = "strict")]
    precondition_mode: String,

    /// Local IP (dotted-quad IPv4). Required iff dpdk_net is in the
    /// stacks list.
    #[arg(long, default_value = "")]
    local_ip: String,

    /// Local gateway IP (dotted-quad IPv4). Required iff dpdk_net is
    /// in the stacks list.
    #[arg(long, default_value = "")]
    gateway_ip: String,

    /// EAL args, whitespace-separated. Only consumed if dpdk_net is in the
    /// stacks list — same shape as bench-e2e.
    #[arg(long, default_value = "", allow_hyphen_values = true)]
    eal_args: String,

    /// Lcore to pin the dpdk_net engine to.
    #[arg(long, default_value_t = 2)]
    lcore: u32,

    /// Tool label emitted as the `tool` CSV column.
    #[arg(long, default_value = "bench-vs-linux")]
    tool: String,

    /// Feature-set label emitted as the `feature_set` CSV column.
    /// Default `trading-latency` matches spec §8 mode A. Operators
    /// should pass `--feature-set rfc-compliance` for mode B runs so
    /// downstream reports group cleanly by (preset, feature_set).
    #[arg(long, default_value = "trading-latency")]
    feature_set: String,

    // -------- Mode B (T9, wire-diff) inputs --------
    /// Mode B — path to the local (DUT) pcap. Required iff
    /// `--mode wire-diff`. In T9 MVP this is a pre-captured file;
    /// future live-capture orchestration (Task 15 nightly) will pass
    /// the tcpdump output path here.
    #[arg(long, default_value = "")]
    local_pcap: String,

    /// Mode B — path to the peer pcap. Required iff `--mode wire-diff`.
    #[arg(long, default_value = "")]
    peer_pcap: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mode = parse_precondition_mode(&args.precondition_mode)?;
    let run_mode = Mode::parse(&args.mode).map_err(|e| anyhow::anyhow!(e))?;

    // Mode B dispatch — diff-from-pcaps MVP. No EAL init required in
    // MVP mode; the preset-applied engine is the *source* of the local
    // pcap, which is captured out-of-band in T9 and fed in here via
    // `--local-pcap` / `--peer-pcap`. Live tcpdump+SSH orchestration
    // is a Task 15 follow-up.
    if matches!(run_mode, Mode::WireDiff) {
        return run_wire_diff_mode(&args, mode);
    }

    // Mode A: parse stack selection first so we can decide whether EAL
    // init is needed.
    let mut stacks = parse_stacks(&args.stacks)?;

    // In lenient mode, drop AF_PACKET from the selection with a warning
    // — its implementation is deferred. Strict mode keeps it and lets
    // the per-stack bring-up surface the `Unimplemented` error.
    if matches!(mode, PreconditionMode::Lenient) {
        let before = stacks.len();
        stacks.retain(|s| !matches!(s, Stack::AfPacket));
        if stacks.len() != before {
            eprintln!(
                "bench-vs-linux: WARN dropping afpacket stack in lenient mode \
                 (Plan B T8 stub — see src/afpacket.rs)"
            );
        }
    }

    if stacks.is_empty() {
        anyhow::bail!("no stacks selected (--stacks resolved to empty)");
    }

    // 1. Precondition check.
    let preconditions = run_preconditions_check(mode)?;
    if mode == PreconditionMode::Strict && !preconditions_all_pass(&preconditions) {
        eprintln!("bench-vs-linux: precondition failure in strict mode:");
        for (name, value) in preconditions_as_pairs(&preconditions) {
            if !(value.is_pass() || value.is_not_applicable()) {
                eprintln!("  {name} = {value}");
            }
        }
        std::process::exit(1);
    }

    // 2. EAL init + engine bring-up — only if dpdk_net is selected.
    //
    // Drop-order invariant: engine must drop BEFORE _eal_guard so
    // Engine's Drop impl can safely call DPDK APIs (e.g.
    // rte_eth_dev_stop) before rte_eal_cleanup fires in
    // EalGuard::drop. Rust drops local `let` bindings in reverse
    // declaration order, so declare _eal_guard first, engine second.
    // Do NOT tuple-wrap — tuple field drop is declaration-order
    // (forward), which would invert this invariant and cause
    // use-after-cleanup on any error path.
    // Ref: bench-e2e/src/main.rs for the same pattern.
    let needs_dpdk = stacks.contains(&Stack::DpdkNet);
    let mut _eal_guard: Option<EalGuard> = None;
    let mut engine: Option<Engine> = None;
    let mut tsc_hz: u64 = 0;
    if needs_dpdk {
        validate_dpdk_args(&args)?;
        eal_init(&args)?;
        _eal_guard = Some(EalGuard);
        engine = Some(build_engine(&args)?);
        tsc_hz = unsafe { dpdk_net_sys::rte_get_tsc_hz() };
        if tsc_hz == 0 {
            anyhow::bail!("rte_get_tsc_hz() returned 0 — EAL not initialised?");
        }
    }

    // 3. Build run metadata + CSV writer.
    let metadata = build_run_metadata(mode, preconditions)?;
    let mut writer = csv::Writer::from_path(&args.output_csv)
        .with_context(|| format!("creating output CSV {:?}", args.output_csv))?;

    // 4. Resolve peer IP once.
    let peer_ip = parse_ip_host_order(&args.peer_ip)?;

    // 5. Run.
    let cfg = ModeRttCfg {
        peer_ip_host_order: peer_ip,
        peer_port: args.peer_port,
        peer_iface: &args.peer_iface,
        request_bytes: args.request_bytes,
        response_bytes: args.response_bytes,
        iterations: args.iterations,
        warmup: args.warmup,
        tool: &args.tool,
        feature_set: &args.feature_set,
        stacks: &stacks,
        tsc_hz,
    };
    run_mode_rtt(&cfg, engine.as_ref(), &metadata, &mut writer)?;
    writer.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Mode B — wire-diff dispatch. MVP: requires --local-pcap + --peer-pcap
// paths. Runs preconditions in the same strict/lenient shape as mode A
// so downstream reports can filter wire-diff rows identically.
// ---------------------------------------------------------------------------

fn run_wire_diff_mode(args: &Args, mode: PreconditionMode) -> anyhow::Result<()> {
    if args.local_pcap.is_empty() || args.peer_pcap.is_empty() {
        anyhow::bail!(
            "--mode wire-diff requires both --local-pcap and --peer-pcap. \
             T9 MVP consumes pre-captured pcaps; live tcpdump+SSH orchestration \
             is a Task 15 follow-up (see src/mode_wire_diff.rs module docs)."
        );
    }
    let preconditions = run_preconditions_check(mode)?;
    if mode == PreconditionMode::Strict && !preconditions_all_pass(&preconditions) {
        eprintln!("bench-vs-linux: precondition failure in strict mode (wire-diff):");
        for (name, value) in preconditions_as_pairs(&preconditions) {
            if !(value.is_pass() || value.is_not_applicable()) {
                eprintln!("  {name} = {value}");
            }
        }
        std::process::exit(1);
    }
    let metadata = build_run_metadata(mode, preconditions)?;
    let code = mode_wire_diff::run_mode_wire_diff_from_paths(
        std::path::PathBuf::from(&args.local_pcap),
        std::path::PathBuf::from(&args.peer_pcap),
        args.output_csv.clone(),
        &args.tool,
        &args.feature_set,
        &metadata,
    )?;
    // Exit codes per mode_wire_diff docs: 0 = empty-diff; 1 = divergence.
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stack selection parser.
// ---------------------------------------------------------------------------

fn parse_stacks(csv: &str) -> anyhow::Result<Vec<Stack>> {
    let mut out: Vec<Stack> = Vec::new();
    for token in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let s = Stack::parse(token).map_err(|e| anyhow::anyhow!(e))?;
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// DPDK bring-up — duplicated from bench-e2e / bench-stress. Same rationale
// as bench-stress: each bench tool owns its own tool label + metadata
// capture; bench-common stays pure-data.
// ---------------------------------------------------------------------------

struct EalGuard;

impl Drop for EalGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = dpdk_net_sys::rte_eal_cleanup();
        }
    }
}

fn validate_dpdk_args(args: &Args) -> anyhow::Result<()> {
    if args.local_ip.is_empty() {
        anyhow::bail!("--local-ip is required when dpdk stack is selected");
    }
    if args.gateway_ip.is_empty() {
        anyhow::bail!("--gateway-ip is required when dpdk stack is selected");
    }
    if args.eal_args.is_empty() {
        anyhow::bail!("--eal-args is required when dpdk stack is selected");
    }
    Ok(())
}

fn parse_precondition_mode(s: &str) -> anyhow::Result<PreconditionMode> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn parse_ip_host_order(s: &str) -> anyhow::Result<u32> {
    let addr: std::net::Ipv4Addr = s
        .parse()
        .with_context(|| format!("invalid IPv4 address: {s}"))?;
    Ok(u32::from_be_bytes(addr.octets()))
}

fn eal_init(args: &Args) -> anyhow::Result<()> {
    let mut eal_argv: Vec<String> = vec!["bench-vs-linux".to_string()];
    eal_argv.extend(
        args.eal_args
            .split_whitespace()
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

// ---------------------------------------------------------------------------
// Preconditions plumbing — same shape as bench-e2e / bench-stress.
// ---------------------------------------------------------------------------

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
                        "bench-vs-linux: WARN lenient mode — check-bench-preconditions \
                         not found and BENCH_PRECONDITIONS_JSON unset; emitting \
                         preconditions as n/a (unverified)"
                    );
                    return Ok(all_unknown_preconditions());
                }
            },
        },
    };

    parse_preconditions_json(&json_bytes).context("parsing check-bench-preconditions JSON output")
}

fn parse_preconditions_json(bytes: &[u8]) -> anyhow::Result<Preconditions> {
    let json: serde_json::Value = serde_json::from_slice(bytes)?;
    let checks = json
        .get("checks")
        .ok_or_else(|| anyhow::anyhow!("preconditions JSON missing top-level `checks` object"))?;
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

/// Lenient-mode fallback when `check-bench-preconditions` is missing
/// and `BENCH_PRECONDITIONS_JSON` is unset: emit every precondition
/// as `n/a` (unverified) rather than falsely claiming pass. Bench-
/// report treats `n/a` as neither pass nor fail in its verdict
/// aggregation so this stays truthful.
fn all_unknown_preconditions() -> Preconditions {
    Preconditions {
        isolcpus: PreconditionValue::NotApplicable,
        nohz_full: PreconditionValue::NotApplicable,
        rcu_nocbs: PreconditionValue::NotApplicable,
        governor: PreconditionValue::NotApplicable,
        cstate_max: PreconditionValue::NotApplicable,
        tsc_invariant: PreconditionValue::NotApplicable,
        coalesce_off: PreconditionValue::NotApplicable,
        tso_off: PreconditionValue::NotApplicable,
        lro_off: PreconditionValue::NotApplicable,
        rss_on: PreconditionValue::NotApplicable,
        thermal_throttle: PreconditionValue::NotApplicable,
        hugepages_reserved: PreconditionValue::NotApplicable,
        irqbalance_off: PreconditionValue::NotApplicable,
        wc_active: PreconditionValue::NotApplicable,
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

// ---------------------------------------------------------------------------
// Run metadata.
// ---------------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_precondition_mode_accepts_strict_and_lenient() {
        assert_eq!(
            parse_precondition_mode("strict").unwrap(),
            PreconditionMode::Strict
        );
        assert_eq!(
            parse_precondition_mode("lenient").unwrap(),
            PreconditionMode::Lenient
        );
    }

    #[test]
    fn parse_precondition_mode_rejects_garbage() {
        assert!(parse_precondition_mode("loose").is_err());
    }

    #[test]
    fn parse_ip_host_order_roundtrip() {
        assert_eq!(parse_ip_host_order("10.0.0.42").unwrap(), 0x0A00_002A);
        assert!(parse_ip_host_order("not.an.ip.addr").is_err());
    }

    #[test]
    fn parse_stacks_default_is_all_three() {
        let out = parse_stacks("dpdk,linux,afpacket").unwrap();
        assert_eq!(
            out,
            vec![Stack::DpdkNet, Stack::LinuxKernel, Stack::AfPacket]
        );
    }

    #[test]
    fn parse_stacks_dedupes() {
        let out = parse_stacks("dpdk,dpdk,linux,dpdk").unwrap();
        assert_eq!(out, vec![Stack::DpdkNet, Stack::LinuxKernel]);
    }

    #[test]
    fn parse_stacks_handles_whitespace_and_empty_entries() {
        let out = parse_stacks(" dpdk , , linux ").unwrap();
        assert_eq!(out, vec![Stack::DpdkNet, Stack::LinuxKernel]);
    }

    #[test]
    fn parse_stacks_rejects_unknown_token() {
        assert!(parse_stacks("dpdk,garbage").is_err());
    }

    #[test]
    fn parse_stacks_empty_returns_empty() {
        // Empty selection is allowed at parse time; main.rs rejects it
        // after lenient-mode AF_PACKET pruning so the error message is
        // localised.
        let out = parse_stacks("").unwrap();
        assert!(out.is_empty());
    }
}
