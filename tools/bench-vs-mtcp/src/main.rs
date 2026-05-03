//! bench-vs-mtcp — dpdk_net vs. mTCP comparison harness.
//!
//! A10 Plan B Task 12 (spec §11.1, parent spec §11.5.1) +
//! Task 13 (spec §11.2, parent spec §11.5.2) — same binary
//! dispatches on `--workload burst` (K × G = 20 grid) or
//! `--workload maxtp` (W × C = 28 grid).
//!
//! # MVP scope flex (T12)
//!
//! The mTCP stack is stubbed (see `src/mtcp.rs` module docs) because
//! the AMI bake that installs `/opt/mtcp/` + `/opt/mtcp-peer/` does
//! not exist yet. The dpdk_net side is fully wired. When the AMI is
//! available, swapping the stub for a real driver is the only change.
//!
//! # Preset
//!
//! Trading-latency default — `EngineConfig::default()` has `cc_mode=0`
//! (latency) and `tcp_nagle=false`, which is what spec §11.1 asks for
//! ("`cc_mode=off` on both stacks"). We still set `cc_mode = 0`
//! explicitly on the engine config so the setting is visible in the
//! binary's source of truth for the preset.
//!
//! # CSV output
//!
//! Per bucket: 3 metrics × 7 aggregations = 21 data rows
//! (`throughput_per_burst_bps`, `burst_initiation_ns`,
//! `burst_steady_bps`) tagged with
//! `dimensions_json = {"workload":"burst","K_bytes":<int>,"G_ms":<float>,"stack":<str>}`.
//!
//! # Peer
//!
//! Per spec §11 + §11.1: kernel-side TCP sink (receives + ACKs, no
//! echo) at `/opt/bench-peer-linux/bench-peer` on the baked AMI.
//! Harness does not SSH; it expects the peer to be already running
//! and listening on `--peer-ip:--peer-port`. The live nightly driver
//! (Task 15) starts the peer.

use anyhow::Context;
use clap::Parser;

use bench_common::preconditions::{PreconditionMode, PreconditionValue, Preconditions};
use bench_common::run_metadata::RunMetadata;

use bench_vs_mtcp::burst::{
    emit_bucket_rows, enumerate_filtered_grid, BucketAggregate,
};
use bench_vs_mtcp::dpdk_burst::{self, DpdkBurstCfg, TxTsMode};
use bench_vs_mtcp::dpdk_maxtp::{self, DpdkMaxtpCfg};
use bench_vs_mtcp::maxtp;
use bench_vs_mtcp::preflight::{
    check_mss_and_burst_agreement, check_nic_saturation_bps, check_peer_window,
    check_sanity_invariant, BucketVerdict,
};
use bench_vs_mtcp::{mtcp, Stack, Workload};

use dpdk_net_core::engine::Engine;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "bench-vs-mtcp — burst-grid comparison vs. mTCP (spec §11.1)"
)]
struct Args {
    /// Peer IP (dotted-quad IPv4).
    #[arg(long)]
    peer_ip: String,

    /// Peer TCP port.
    #[arg(long, default_value_t = 10_001)]
    peer_port: u16,

    /// Workload selector: `burst` (T12) or `maxtp` (T13).
    #[arg(long, default_value = "burst")]
    workload: String,

    /// CSV of stacks to run. Tokens: `dpdk`, `mtcp`, `linux`. Default
    /// runs `dpdk` + `linux` (mTCP stays opt-in while the AMI rebuild
    /// is blocked on libmtcp / gcc 13). The mTCP path errors at
    /// startup in strict mode (see src/mtcp.rs module docs); the Linux
    /// path is wired for the `maxtp` workload only — `burst` skips
    /// it with a warning.
    #[arg(long, default_value = "dpdk,linux")]
    stacks: String,

    /// Bursts per bucket post-warmup. Spec §11.1 requires ≥10 k per
    /// bucket for the aggregation to be statistically stable.
    #[arg(long, default_value_t = 10_000)]
    bursts_per_bucket: u64,

    /// Warmup bursts per bucket (discarded). Spec §11.1 locks this
    /// at 100.
    #[arg(long, default_value_t = 100)]
    warmup: u64,

    /// MSS in bytes. Spec §11.1 locks this at 1460.
    #[arg(long, default_value_t = 1460)]
    mss: u16,

    /// Output CSV path.
    #[arg(long)]
    output_csv: std::path::PathBuf,

    /// Precondition mode: `strict` aborts on precondition failure or
    /// on a selected stack failing bring-up (e.g. mTCP stub);
    /// `lenient` warns and continues.
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

    /// EAL args, whitespace-separated. Required iff dpdk_net is in the
    /// stacks list — same shape as bench-e2e / bench-vs-linux.
    #[arg(long, default_value = "", allow_hyphen_values = true)]
    eal_args: String,

    /// Lcore to pin the dpdk_net engine to.
    #[arg(long, default_value_t = 2)]
    lcore: u32,

    /// Tool label emitted as the `tool` CSV column.
    #[arg(long, default_value = "bench-vs-mtcp")]
    tool: String,

    /// Feature-set label emitted as the `feature_set` CSV column.
    #[arg(long, default_value = "trading-latency")]
    feature_set: String,

    /// Grid subset filter — comma-separated K values in bytes to run.
    /// Empty = run all 5 K values. Must match a subset of spec §11.1's
    /// {65536, 262144, 1048576, 4194304, 16777216}.
    /// Applies when `--workload burst` is selected.
    #[arg(long, default_value = "")]
    burst_sizes: String,

    /// Grid subset filter — comma-separated G values in ms to run.
    /// Empty = run all 4 G values. Applies when `--workload burst`.
    #[arg(long, default_value = "")]
    gap_mss: String,

    /// Maxtp grid subset — comma-separated W values in bytes.
    /// Empty = run all 7 W values.
    #[arg(long, default_value = "")]
    write_sizes: String,

    /// Maxtp grid subset — comma-separated C values (connection counts).
    /// Empty = run all 4 C values.
    #[arg(long, default_value = "")]
    conn_counts: String,

    /// Maxtp warmup duration in seconds. Spec §11.2 locks at 10.
    #[arg(long, default_value_t = maxtp::WARMUP_SECS)]
    maxtp_warmup_secs: u64,

    /// Maxtp measurement duration in seconds. Spec §11.2 locks at 60.
    #[arg(long, default_value_t = maxtp::DURATION_SECS)]
    maxtp_duration_secs: u64,

    /// mTCP peer binary absolute path on the baked AMI. Default
    /// tracks spec §11 ("`/opt/mtcp-peer/bench-peer` pre-installed").
    /// Used only when mTCP stack is selected; stub returns
    /// `Unimplemented` but validates the shape.
    #[arg(long, default_value = "/opt/mtcp-peer/bench-peer")]
    mtcp_peer_binary: String,

    /// NIC line-rate cap (bits-per-second) for the post-run
    /// NIC-saturation check (spec §11.1 check 3 — "achieved rate ≤
    /// 70% of NIC max bps"). Buckets whose mean achieved throughput
    /// exceeds 70% of this value are flipped to `Invalid` post-run.
    ///
    /// Defaults to the `NIC_MAX_BPS` env var if set; otherwise the
    /// check is skipped with a warning. On c6in.metal (100 Gbps ENA),
    /// pass `--nic-max-bps 100000000000`.
    #[arg(long)]
    nic_max_bps: Option<u64>,

    /// Peer SSH target (e.g. `ubuntu@10.0.0.2`) for pre-run peer
    /// receive-window introspection (`ss -ti | rcv_space`). When
    /// unset, the pre-run `peer_rwnd` guard degrades to the T12
    /// placebo (peer_rwnd := bucket burst/write size) — a WARN is
    /// emitted on stderr so nightly runs record the degraded check
    /// rather than silently passing. Supplying this argument wires
    /// the real introspection path (A10 Plan B T15-B / T12-I4).
    #[arg(long)]
    peer_ssh: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mode = parse_precondition_mode(&args.precondition_mode)?;
    let workload = Workload::parse(&args.workload).map_err(|e| anyhow::anyhow!(e))?;

    let mut stacks = parse_stacks(&args.stacks)?;

    // In lenient mode, drop mTCP from the selection with a warning —
    // its implementation is deferred. Strict mode keeps it so the
    // per-stack bring-up surfaces the `Unimplemented` error.
    if matches!(mode, PreconditionMode::Lenient) {
        let before = stacks.len();
        stacks.retain(|s| !matches!(s, Stack::Mtcp));
        if stacks.len() != before {
            eprintln!(
                "bench-vs-mtcp: WARN dropping mtcp stack in lenient mode \
                 (Plan B T12 stub — see src/mtcp.rs)"
            );
        }
    }
    if stacks.is_empty() {
        anyhow::bail!("no stacks selected (--stacks resolved to empty)");
    }

    // Host preconditions.
    let preconditions = run_preconditions_check(mode)?;
    if mode == PreconditionMode::Strict && !preconditions_all_pass(&preconditions) {
        eprintln!("bench-vs-mtcp: precondition failure in strict mode:");
        for (name, value) in preconditions_as_pairs(&preconditions) {
            if !(value.is_pass() || value.is_not_applicable()) {
                eprintln!("  {name} = {value}");
            }
        }
        std::process::exit(1);
    }

    // EAL init + engine bring-up — only if dpdk_net is selected.
    //
    // Drop-order invariant: engine must drop BEFORE _eal_guard so
    // Engine's Drop impl can safely call DPDK APIs (e.g.
    // rte_eth_dev_stop) before rte_eal_cleanup fires in
    // EalGuard::drop. Rust drops local `let` bindings in reverse
    // declaration order, so declare _eal_guard first, engine second.
    // Same pattern as bench-vs-linux / bench-e2e.
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

    let metadata = build_run_metadata(mode, preconditions)?;
    let mut writer = csv::Writer::from_path(&args.output_csv)
        .with_context(|| format!("creating output CSV {:?}", args.output_csv))?;

    let peer_ip = parse_ip_host_order(&args.peer_ip)?;
    let nic_max_bps = resolve_nic_max_bps(args.nic_max_bps);
    if nic_max_bps.is_none() {
        eprintln!(
            "bench-vs-mtcp: WARN --nic-max-bps unset and NIC_MAX_BPS env var \
             unset; skipping post-run NIC-saturation check (spec §11.1 check 3). \
             Pass `--nic-max-bps <bps>` or export `NIC_MAX_BPS=<bps>` to enable."
        );
    }

    match workload {
        Workload::Burst => {
            // Parse burst-specific grid subset filters.
            let k_filter = parse_u64_list(&args.burst_sizes)?;
            let g_filter = parse_u64_list(&args.gap_mss)?;
            let grid = enumerate_filtered_grid(k_filter.as_deref(), g_filter.as_deref())
                .map_err(|e| anyhow::anyhow!(e))?;
            for stack in stacks {
                match stack {
                    Stack::DpdkNet => {
                        let engine = engine.as_ref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "DpdkNet stack selected but engine not provided — main.rs invariant violated"
                            )
                        })?;
                        run_burst_grid_dpdk(
                            engine,
                            peer_ip,
                            args.peer_port,
                            &grid,
                            &args,
                            &metadata,
                            tsc_hz,
                            nic_max_bps,
                            &mut writer,
                        )?;
                    }
                    Stack::Mtcp => {
                        run_burst_grid_mtcp_stub(&args, &grid, &metadata, mode, &mut writer)?;
                    }
                    Stack::Linux => {
                        // Linux burst arm is out of scope for the
                        // 2026-05-03 follow-up — user only asked for
                        // maxtp comparison. Skip with a warning so
                        // `--stacks dpdk,linux --workload burst` doesn't
                        // wedge the operator's pipeline; the dpdk burst
                        // arm still runs.
                        eprintln!(
                            "bench-vs-mtcp: WARN linux stack is wired for `maxtp` only; \
                             skipping burst grid for Linux"
                        );
                    }
                }
            }
        }
        Workload::Maxtp => {
            // Parse maxtp-specific grid subset filters.
            let w_filter = parse_u64_list(&args.write_sizes)?;
            let c_filter = parse_u64_list(&args.conn_counts)?;
            let grid = maxtp::enumerate_filtered_grid(w_filter.as_deref(), c_filter.as_deref())
                .map_err(|e| anyhow::anyhow!(e))?;
            for stack in stacks {
                match stack {
                    Stack::DpdkNet => {
                        let engine = engine.as_ref().ok_or_else(|| {
                            anyhow::anyhow!(
                                "DpdkNet stack selected but engine not provided — main.rs invariant violated"
                            )
                        })?;
                        run_maxtp_grid_dpdk(
                            engine,
                            peer_ip,
                            args.peer_port,
                            &grid,
                            &args,
                            &metadata,
                            nic_max_bps,
                            &mut writer,
                        )?;
                    }
                    Stack::Mtcp => {
                        run_maxtp_grid_mtcp_stub(&args, &grid, &metadata, mode, &mut writer)?;
                    }
                    Stack::Linux => {
                        run_maxtp_grid_linux(
                            peer_ip,
                            args.peer_port,
                            &grid,
                            &args,
                            &metadata,
                            nic_max_bps,
                            &mut writer,
                        )?;
                    }
                }
            }
        }
    }
    writer.flush()?;
    Ok(())
}

/// Resolve the NIC line-rate cap from CLI flag → `NIC_MAX_BPS` env
/// var. `None` means the post-run NIC-saturation check is skipped.
///
/// Split out so unit tests can exercise it without re-parsing
/// clap args.
fn resolve_nic_max_bps(flag: Option<u64>) -> Option<u64> {
    if let Some(v) = flag {
        return Some(v);
    }
    match std::env::var("NIC_MAX_BPS") {
        Ok(s) => s.trim().parse::<u64>().ok(),
        Err(_) => None,
    }
}

/// Resolve the peer's advertised receive window for the pre-run guard.
///
/// A10 Plan B T15-B / T12-I4: when `peer_ssh` is supplied, shell out
/// and parse `ss -ti | rcv_space` on the peer host. If the arg is
/// unset OR the SSH probe fails (network glitch, ss returns nothing
/// yet because the connection setup races the probe, malformed
/// output), fall back to the T12 placebo `placebo_rwnd` (caller passes
/// the bucket's K/W in bytes) and emit a WARN to stderr. The WARN
/// line is what nightly log captures so operators can distinguish
/// "guard really passed" from "guard degraded to placebo".
///
/// Returns u64 to match `check_peer_window`'s signature; the u32
/// result from the parser is widened to avoid any u32→u64 conversion
/// at the call sites.
fn resolve_peer_rwnd_bytes(
    peer_ssh: Option<&str>,
    dut_ip: std::net::Ipv4Addr,
    peer_port: u16,
    placebo_rwnd: u64,
) -> u64 {
    let Some(ssh) = peer_ssh else {
        eprintln!(
            "bench-vs-mtcp: WARN --peer-ssh unset; peer_rwnd pre-run check \
             degraded to placebo ({placebo_rwnd} B)"
        );
        return placebo_rwnd;
    };
    match bench_vs_mtcp::peer_introspect::fetch_peer_rwnd_bytes(ssh, dut_ip, peer_port) {
        Ok(v) => v as u64,
        Err(e) => {
            eprintln!(
                "bench-vs-mtcp: WARN peer_rwnd introspection via `ss -ti` \
                 on {ssh}:{peer_port} failed: {e}; falling back to placebo \
                 ({placebo_rwnd} B)"
            );
            placebo_rwnd
        }
    }
}

// ---------------------------------------------------------------------------
// dpdk_net grid driver.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn run_burst_grid_dpdk<W: std::io::Write>(
    engine: &Engine,
    peer_ip: u32,
    peer_port: u16,
    grid: &[bench_vs_mtcp::burst::Bucket],
    args: &Args,
    metadata: &RunMetadata,
    tsc_hz: u64,
    nic_max_bps: Option<u64>,
    writer: &mut csv::Writer<W>,
) -> anyhow::Result<()> {
    // One persistent connection, reused for all buckets. Spec §11.1:
    // "One connection per lcore, established once, reused for the
    // whole run".
    eprintln!(
        "bench-vs-mtcp: opening persistent connection to {}:{}",
        args.peer_ip, peer_port
    );
    let conn = dpdk_burst::open_persistent_connection(engine, peer_ip, peer_port)?;

    // T15-B I-2: parse the DUT's local IP once for the `ss -ti`
    // filter. `validate_dpdk_args` already bailed if `local_ip` was
    // empty, so the parse only fails on truly invalid input — we want
    // the whole run to abort in that case rather than silently fall
    // back to the placebo bucket-after-bucket.
    let dut_ip: std::net::Ipv4Addr = args
        .local_ip
        .parse()
        .with_context(|| format!("parsing --local-ip `{}` for peer rwnd probe", args.local_ip))?;

    // Pre-allocate one payload buffer per K (reused across bursts
    // within a bucket to keep the inner loop allocation-free).
    let mut payload_cache: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();

    for bucket in grid {
        eprintln!("bench-vs-mtcp: running dpdk_net bucket {}", bucket.label());

        let payload = payload_cache
            .entry(bucket.burst_bytes)
            .or_insert_with(|| vec![0u8; bucket.burst_bytes as usize]);

        // Pre-run check (2): MSS + TX burst size agreement. We drive
        // our MSS from EngineConfig; peer MSS is fixed at the same
        // value (spec locks it at 1460 on both stacks). For the burst
        // size (mTCP's `nb_pkts` vs. our `TX_BURST_SIZE`), we use the
        // engine's configured ring size as a proxy since the
        // `rte_eth_tx_burst`-level batch size is a compile-time
        // constant in our stack; mTCP stub records its intent only.
        let mss_verdict =
            check_mss_and_burst_agreement(args.mss, args.mss, 32, 32);

        // Pre-run check (1): peer receive window.
        //
        // A10 Plan B T15-B / T12-I4: if `--peer-ssh` is set, shell out
        // to the peer and parse `ss -ti | rcv_space` for the real
        // kernel-side advertised receive window. If unset OR the SSH
        // probe fails, fall back to the T12 placebo (peer_rwnd := K)
        // and emit a WARN — nightly runs record the degraded check
        // rather than silently passing.
        let peer_rwnd = resolve_peer_rwnd_bytes(
            args.peer_ssh.as_deref(),
            dut_ip,
            peer_port,
            bucket.burst_bytes,
        );
        let rwnd_verdict = check_peer_window(peer_rwnd, bucket.burst_bytes);

        // Pre-run check (3): NIC saturation is only knowable post-
        // run; we run the bucket and check after (see
        // `check_nic_saturation_bps` call further down).
        let verdict = if !mss_verdict.is_ok() {
            mss_verdict
        } else if !rwnd_verdict.is_ok() {
            rwnd_verdict
        } else {
            BucketVerdict::Ok
        };

        // ENA does not advertise the TX HW-TS dynfield — so the
        // dpdk_net side always runs with TscFallback in T12. Hoisted
        // out of the DpdkBurstCfg block so we can thread it into the
        // aggregate builder for invalidated-pre-run rows too (I3: CSV
        // consumers should see the mode tag on every dpdk_net row,
        // not just the happy-path ones).
        let tx_ts_mode = TxTsMode::TscFallback;

        if !verdict.is_ok() {
            eprintln!(
                "bench-vs-mtcp: bucket {} invalidated pre-run: {}",
                bucket.label(),
                verdict.reason().unwrap_or("<unknown>")
            );
            let agg = BucketAggregate::from_samples(
                *bucket,
                Stack::DpdkNet,
                &[],
                verdict,
                Some(tx_ts_mode),
            );
            emit_bucket_rows(writer, metadata, &args.tool, &args.feature_set, &agg)
                .context("emit invalidated bucket row")?;
            continue;
        }

        // Snapshot the TCP payload byte counter pre-run.
        let tx_payload_pre = engine
            .counters()
            .tcp
            .tx_payload_bytes
            .load(std::sync::atomic::Ordering::Relaxed);

        let cfg = DpdkBurstCfg {
            engine,
            conn,
            bucket: *bucket,
            warmup: args.warmup,
            bursts: args.bursts_per_bucket,
            tsc_hz,
            payload,
            tx_ts_mode,
        };
        let run = dpdk_burst::run_bucket(&cfg).with_context(|| {
            format!("dpdk_burst::run_bucket for {}", bucket.label())
        })?;

        // Snapshot the counter post-run + assert sanity invariant.
        let tx_payload_post = engine
            .counters()
            .tcp
            .tx_payload_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let counter_delta = tx_payload_post.saturating_sub(tx_payload_pre);
        // `obs-byte-counters` feature is OFF by default → counter
        // does not increment → delta will be 0 regardless of sent
        // bytes. Only assert when we actually have a non-zero delta
        // (i.e. the operator built with `--features obs-byte-counters`).
        if counter_delta > 0 {
            if let Err(e) = check_sanity_invariant(run.sum_over_bursts_bytes, counter_delta) {
                eprintln!(
                    "bench-vs-mtcp: sanity invariant violated for bucket {}: {e}",
                    bucket.label()
                );
                anyhow::bail!(e);
            }
        } else {
            eprintln!(
                "bench-vs-mtcp: sanity invariant check skipped for bucket {} \
                 (tx_payload_bytes counter is 0 — build with \
                 `--features obs-byte-counters` to enable)",
                bucket.label()
            );
        }

        // Post-run check (spec §11.1 check 3): NIC saturation. If the
        // achieved mean throughput exceeds 70% of the NIC line rate,
        // the bucket is NIC-bound and its stack-attributable
        // percentiles are untrustworthy — flip the verdict to
        // Invalid before emitting. Skipped with a warn if --nic-max-
        // bps / NIC_MAX_BPS is unset.
        let mut agg = BucketAggregate::from_samples(
            *bucket,
            Stack::DpdkNet,
            &run.samples,
            BucketVerdict::Ok,
            Some(tx_ts_mode),
        );
        if let Some(max_bps) = nic_max_bps {
            let achieved_bps = mean_throughput_bps(&run) as u64;
            let sat_verdict = check_nic_saturation_bps(achieved_bps, max_bps);
            if !sat_verdict.is_ok() {
                eprintln!(
                    "bench-vs-mtcp: bucket {} NIC-bound post-run: {}",
                    bucket.label(),
                    sat_verdict.reason().unwrap_or("<unknown>")
                );
                agg.override_verdict(sat_verdict);
            }
        }
        emit_bucket_rows(writer, metadata, &args.tool, &args.feature_set, &agg)
            .context("emit bucket rows")?;
    }
    Ok(())
}

/// Mean throughput (bits-per-second) across a bucket's per-burst
/// samples. Returns 0.0 when there are no samples. Split out so the
/// NIC-saturation post-run check is independently testable.
fn mean_throughput_bps(run: &dpdk_burst::BucketRun) -> f64 {
    if run.samples.is_empty() {
        return 0.0;
    }
    let sum: f64 = run.samples.iter().map(|s| s.throughput_bps).sum();
    sum / (run.samples.len() as f64)
}

// ---------------------------------------------------------------------------
// mTCP stub driver.
// ---------------------------------------------------------------------------

fn run_burst_grid_mtcp_stub<W: std::io::Write>(
    args: &Args,
    grid: &[bench_vs_mtcp::burst::Bucket],
    metadata: &RunMetadata,
    mode: PreconditionMode,
    writer: &mut csv::Writer<W>,
) -> anyhow::Result<()> {
    for bucket in grid {
        let cfg = mtcp::MtcpConfig {
            peer_ip: &args.peer_ip,
            peer_port: args.peer_port,
            peer_binary: &args.mtcp_peer_binary,
            burst_bytes: bucket.burst_bytes,
            gap_ms: bucket.gap_ms,
            bursts: args.bursts_per_bucket,
            warmup: args.warmup,
            mss: args.mss,
        };
        // Validate shape first so a bad CLI combo fails loudly even
        // in lenient mode (strict mode handles the Unimplemented
        // below).
        if let Err(reason) = mtcp::validate_config(&cfg) {
            anyhow::bail!("mTCP config validation failed: {reason}");
        }
        match mtcp::run_burst_workload(&cfg) {
            Ok(_) => {
                unreachable!(
                    "mtcp::run_burst_workload should return Unimplemented in T12"
                );
            }
            Err(e) => match mode {
                PreconditionMode::Strict => {
                    anyhow::bail!(
                        "mTCP stack is stubbed in T12: {e}. Pass \
                         `--precondition-mode lenient` to skip with a CSV \
                         marker, or wait for Plan A AMI T6+T7 to land."
                    );
                }
                PreconditionMode::Lenient => {
                    // Emit an invalidated-bucket marker row so
                    // bench-report sees the intent (and doesn't just
                    // lose the run). `bucket_invalid` carries the
                    // stub reason. `tx_ts_mode = None` — the mTCP
                    // stack doesn't expose TX-TS measurement modes to
                    // the harness yet, so we don't tag the row with a
                    // possibly-misleading dpdk_net mode.
                    let agg = BucketAggregate::from_samples(
                        *bucket,
                        Stack::Mtcp,
                        &[],
                        BucketVerdict::Invalid(format!("mtcp stub: {e}")),
                        None,
                    );
                    emit_bucket_rows(writer, metadata, &args.tool, &args.feature_set, &agg)
                        .context("emit mtcp-stub marker row")?;
                }
            },
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// dpdk_net maxtp grid driver (spec §11.2).
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn run_maxtp_grid_dpdk<W: std::io::Write>(
    engine: &Engine,
    peer_ip: u32,
    peer_port: u16,
    grid: &[maxtp::Bucket],
    args: &Args,
    metadata: &RunMetadata,
    nic_max_bps: Option<u64>,
    writer: &mut csv::Writer<W>,
) -> anyhow::Result<()> {
    // Pre-allocate one payload buffer per W (reused across the bucket).
    let mut payload_cache: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();

    // T15-B I-2: same `dut_ip` derivation as the burst driver — see
    // `run_burst_grid_dpdk` above for rationale. Bail here rather
    // than per-bucket.
    let dut_ip: std::net::Ipv4Addr = args
        .local_ip
        .parse()
        .with_context(|| format!("parsing --local-ip `{}` for peer rwnd probe", args.local_ip))?;

    for bucket in grid {
        eprintln!("bench-vs-mtcp: running dpdk_net maxtp bucket {}", bucket.label());

        let payload = payload_cache
            .entry(bucket.write_bytes)
            .or_insert_with(|| vec![0u8; bucket.write_bytes as usize]);

        // Pre-run check (2): MSS + TX burst size agreement.
        let mss_verdict =
            check_mss_and_burst_agreement(args.mss, args.mss, 32, 32);

        // Pre-run check (1): peer receive window. A10 Plan B T15-B /
        // T12-I4 wires real peer-side introspection — see the mirror
        // call in `run_burst_grid_dpdk` above for the contract.
        let peer_rwnd = resolve_peer_rwnd_bytes(
            args.peer_ssh.as_deref(),
            dut_ip,
            peer_port,
            bucket.write_bytes,
        );
        let rwnd_verdict = check_peer_window(peer_rwnd, bucket.write_bytes);

        let verdict = if !mss_verdict.is_ok() {
            mss_verdict
        } else if !rwnd_verdict.is_ok() {
            rwnd_verdict
        } else {
            BucketVerdict::Ok
        };

        // Same rationale as burst: ENA does not advertise the TX HW-TS
        // dynfield; tag rows with TscFallback. For maxtp the tag is
        // informational only (the measurement window is delimited by
        // TSC reads at the window boundaries; there's no per-iteration
        // HW TS used in the sample math).
        let tx_ts_mode = dpdk_maxtp::TxTsMode::TscFallback;

        if !verdict.is_ok() {
            eprintln!(
                "bench-vs-mtcp: maxtp bucket {} invalidated pre-run: {}",
                bucket.label(),
                verdict.reason().unwrap_or("<unknown>")
            );
            let agg = maxtp::BucketAggregate::from_sample(
                *bucket,
                Stack::DpdkNet,
                None,
                verdict,
                Some(tx_ts_mode),
            );
            maxtp::emit_bucket_rows(writer, metadata, &args.tool, &args.feature_set, &agg)
                .context("emit invalidated maxtp bucket row")?;
            continue;
        }

        // Open C persistent connections.
        let conns = dpdk_maxtp::open_persistent_connections(
            engine,
            peer_ip,
            peer_port,
            bucket.conn_count,
        )?;

        let cfg = DpdkMaxtpCfg {
            engine,
            conns: &conns,
            bucket: *bucket,
            warmup: std::time::Duration::from_secs(args.maxtp_warmup_secs),
            duration: std::time::Duration::from_secs(args.maxtp_duration_secs),
            payload,
            tx_ts_mode,
        };
        // Per-bucket soft-fail: a single bucket erroring (e.g. SendBufferFull
        // at high C) should NOT abort the entire grid. Log and continue so
        // every other bucket — and every other stack — gets to produce data.
        let run = match dpdk_maxtp::run_bucket(&cfg).with_context(|| {
            format!("dpdk_maxtp::run_bucket for {}", bucket.label())
        }) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "bench-vs-mtcp: dpdk_maxtp bucket {} failed: {e:#}",
                    bucket.label()
                );
                continue;
            }
        };

        // Sanity invariant (spec §11.2): ACKed bytes during window ==
        // `tx_payload_bytes` delta, minus in-flight bound. The
        // `tx_payload_bytes` counter only increments with the
        // `obs-byte-counters` feature (OFF by default) — when it's off
        // the delta is 0 and we skip the check with a log line.
        if run.tx_payload_bytes_delta > 0 {
            if let Err(e) = maxtp::check_sanity_invariant(
                run.acked_bytes_in_window,
                run.tx_payload_bytes_delta,
                run.inflight_bytes_at_end,
            ) {
                eprintln!(
                    "bench-vs-mtcp: maxtp sanity invariant violated for bucket {}: {e}",
                    bucket.label()
                );
                anyhow::bail!(e);
            }
        } else {
            eprintln!(
                "bench-vs-mtcp: maxtp sanity invariant check skipped for bucket {} \
                 (tx_payload_bytes counter is 0 — build with \
                 `--features obs-byte-counters` to enable)",
                bucket.label()
            );
        }

        // Post-run check (spec §11.1 check 3, reused for §11.2): NIC
        // saturation. Same 70% ceiling.
        let mut agg = maxtp::BucketAggregate::from_sample(
            *bucket,
            Stack::DpdkNet,
            Some(run.sample),
            BucketVerdict::Ok,
            Some(tx_ts_mode),
        );
        if let Some(max_bps) = nic_max_bps {
            let sat_verdict =
                check_nic_saturation_bps(run.sample.goodput_bps as u64, max_bps);
            if !sat_verdict.is_ok() {
                eprintln!(
                    "bench-vs-mtcp: maxtp bucket {} NIC-bound post-run: {}",
                    bucket.label(),
                    sat_verdict.reason().unwrap_or("<unknown>")
                );
                agg.override_verdict(sat_verdict);
            }
        }
        maxtp::emit_bucket_rows(writer, metadata, &args.tool, &args.feature_set, &agg)
            .context("emit maxtp bucket rows")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux kernel-TCP maxtp grid driver — comparator arm landed
// 2026-05-03 while the mTCP arm stays stubbed (AMI rebuild blocked).
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn run_maxtp_grid_linux<W: std::io::Write>(
    peer_ip: u32,
    peer_port: u16,
    grid: &[maxtp::Bucket],
    args: &Args,
    metadata: &RunMetadata,
    nic_max_bps: Option<u64>,
    writer: &mut csv::Writer<W>,
) -> anyhow::Result<()> {
    use bench_vs_mtcp::linux_maxtp::{self, LinuxMaxtpCfg};

    for bucket in grid {
        eprintln!(
            "bench-vs-mtcp: running linux maxtp bucket {}",
            bucket.label()
        );

        // Pre-run check (1): peer receive window mirrors the dpdk
        // path so a row's verdict reflects the same pre-run gate
        // across stacks. The Linux runner doesn't consume the value
        // for back-pressure handling (kernel non-blocking writes
        // already report `WouldBlock`), but we still surface the
        // verdict so CSV consumers see consistent invalidation.
        let dut_ip: std::net::Ipv4Addr = args.local_ip.parse().with_context(|| {
            format!("parsing --local-ip `{}` for peer rwnd probe", args.local_ip)
        })?;
        let peer_rwnd = resolve_peer_rwnd_bytes(
            args.peer_ssh.as_deref(),
            dut_ip,
            peer_port,
            bucket.write_bytes,
        );
        let rwnd_verdict = check_peer_window(peer_rwnd, bucket.write_bytes);

        // Linux maxtp doesn't have a meaningful TX-TS mode (the runner
        // doesn't read NIC HW timestamps) — emit `n/a` so bench-report
        // can filter Linux rows out of pps / TX-TS pivots.
        let tx_ts_mode_str = "n/a";

        if !rwnd_verdict.is_ok() {
            eprintln!(
                "bench-vs-mtcp: linux maxtp bucket {} invalidated pre-run: {}",
                bucket.label(),
                rwnd_verdict.reason().unwrap_or("<unknown>")
            );
            // Build the marker row directly; we don't have a TxTsMode
            // to attach (the field is dpdk-specific) so we hand-roll
            // the dimensions JSON so it carries `tx_ts_mode = "n/a"`.
            let agg = maxtp::BucketAggregate::from_sample(
                *bucket,
                Stack::Linux,
                None,
                rwnd_verdict,
                None,
            );
            emit_linux_bucket_rows(
                writer,
                metadata,
                &args.tool,
                &args.feature_set,
                &agg,
                tx_ts_mode_str,
            )
            .context("emit invalidated linux maxtp bucket row")?;
            continue;
        }

        // Open C kernel-TCP connections.
        let mut conns = linux_maxtp::open_persistent_connections(
            peer_ip,
            peer_port,
            bucket.conn_count,
        )
        .with_context(|| {
            format!(
                "linux_maxtp open_persistent_connections (C={})",
                bucket.conn_count
            )
        })?;

        let cfg = LinuxMaxtpCfg {
            bucket: *bucket,
            warmup: std::time::Duration::from_secs(args.maxtp_warmup_secs),
            duration: std::time::Duration::from_secs(args.maxtp_duration_secs),
            peer_ip_host_order: peer_ip,
            peer_port,
            payload: vec![0u8; bucket.write_bytes as usize],
        };
        // Per-bucket soft-fail (mirror dpdk_maxtp grid): a single bucket
        // erroring should not abort the grid.
        let run = match linux_maxtp::run_bucket(&cfg, &mut conns).with_context(|| {
            format!("linux_maxtp::run_bucket for {}", bucket.label())
        }) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "bench-vs-mtcp: linux_maxtp bucket {} failed: {e:#}",
                    bucket.label()
                );
                continue;
            }
        };

        // Post-run NIC-saturation check (mirror dpdk path) — same 70%
        // ceiling using the same mean throughput in bps.
        let mut agg = maxtp::BucketAggregate::from_sample(
            *bucket,
            Stack::Linux,
            Some(run.sample),
            BucketVerdict::Ok,
            None,
        );
        if let Some(max_bps) = nic_max_bps {
            let sat_verdict =
                check_nic_saturation_bps(run.sample.goodput_bps as u64, max_bps);
            if !sat_verdict.is_ok() {
                eprintln!(
                    "bench-vs-mtcp: linux maxtp bucket {} NIC-bound post-run: {}",
                    bucket.label(),
                    sat_verdict.reason().unwrap_or("<unknown>")
                );
                agg.override_verdict(sat_verdict);
            }
        }
        emit_linux_bucket_rows(
            writer,
            metadata,
            &args.tool,
            &args.feature_set,
            &agg,
            tx_ts_mode_str,
        )
        .context("emit linux maxtp bucket rows")?;

        // Drop conns explicitly so the next bucket's open isn't racing
        // an OS-level close on the kernel side.
        drop(conns);
    }
    Ok(())
}

/// Emit Linux maxtp bucket rows with `tx_ts_mode = "n/a"` overlaid on
/// the standard maxtp dimensions JSON. The pure dpdk path uses
/// `maxtp::emit_bucket_rows` which only writes `tx_ts_mode` when the
/// aggregate carries one (None on Linux); we want the field present
/// with the explicit "n/a" string so CSV consumers can filter Linux
/// rows symmetrically with dpdk_net rows.
fn emit_linux_bucket_rows<W: std::io::Write>(
    writer: &mut csv::Writer<W>,
    metadata: &RunMetadata,
    tool: &str,
    feature_set: &str,
    aggregate: &maxtp::BucketAggregate,
    tx_ts_mode: &str,
) -> anyhow::Result<()> {
    use bench_common::csv_row::{CsvRow, MetricAggregation};

    // Build dimensions JSON manually so we can splice in the explicit
    // `"tx_ts_mode": "n/a"` field. This mirrors what
    // `maxtp::build_dimensions_json` produces but with a different
    // tx_ts_mode source.
    let mut dims_value = serde_json::json!({
        "workload": "maxtp",
        "W_bytes": aggregate.bucket.write_bytes as i64,
        "C": aggregate.bucket.conn_count as i64,
        "stack": aggregate.stack.as_dimension(),
        "tx_ts_mode": tx_ts_mode,
    });
    if let Some(reason) = aggregate.verdict.reason() {
        if let Some(m) = dims_value.as_object_mut() {
            m.insert(
                "bucket_invalid".to_string(),
                serde_json::Value::String(reason.to_string()),
            );
        }
    }
    let dims = dims_value.to_string();

    match &aggregate.sample {
        Some(sample) => {
            // Primary: sustained goodput in bits_per_sec.
            let row = CsvRow {
                run_metadata: metadata.clone(),
                tool: tool.to_string(),
                test_case: "maxtp".to_string(),
                feature_set: feature_set.to_string(),
                dimensions_json: dims.clone(),
                metric_name: "sustained_goodput_bps".to_string(),
                metric_unit: "bits_per_sec".to_string(),
                metric_value: sample.goodput_bps,
                metric_aggregation: MetricAggregation::Mean,
                cpu_family: None,
                cpu_model_name: None,
                dpdk_version_pkgconfig: None,
                worktree_branch: None,
                uprof_session_id: None,
            };
            writer.serialize(&row)?;

            // Secondary: pps. The Linux runner leaves pps at 0 — see
            // `linux_maxtp.rs` module doc for why. Emit the row anyway
            // so the schema stays uniform.
            let row = CsvRow {
                run_metadata: metadata.clone(),
                tool: tool.to_string(),
                test_case: "maxtp".to_string(),
                feature_set: feature_set.to_string(),
                dimensions_json: dims,
                metric_name: "tx_pps".to_string(),
                metric_unit: "pps".to_string(),
                metric_value: sample.pps,
                metric_aggregation: MetricAggregation::Mean,
                cpu_family: None,
                cpu_model_name: None,
                dpdk_version_pkgconfig: None,
                worktree_branch: None,
                uprof_session_id: None,
            };
            writer.serialize(&row)?;
        }
        None => {
            let row = CsvRow {
                run_metadata: metadata.clone(),
                tool: tool.to_string(),
                test_case: "maxtp".to_string(),
                feature_set: feature_set.to_string(),
                dimensions_json: dims,
                metric_name: "sustained_goodput_bps".to_string(),
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
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// mTCP maxtp stub driver.
// ---------------------------------------------------------------------------

fn run_maxtp_grid_mtcp_stub<W: std::io::Write>(
    args: &Args,
    grid: &[maxtp::Bucket],
    metadata: &RunMetadata,
    mode: PreconditionMode,
    writer: &mut csv::Writer<W>,
) -> anyhow::Result<()> {
    for bucket in grid {
        let cfg = mtcp::MaxtpConfig {
            peer_ip: &args.peer_ip,
            peer_port: args.peer_port,
            peer_binary: &args.mtcp_peer_binary,
            write_bytes: bucket.write_bytes,
            conn_count: bucket.conn_count,
            warmup_secs: args.maxtp_warmup_secs,
            duration_secs: args.maxtp_duration_secs,
            mss: args.mss,
        };
        if let Err(reason) = mtcp::validate_maxtp_config(&cfg) {
            anyhow::bail!("mTCP maxtp config validation failed: {reason}");
        }
        match mtcp::run_maxtp_workload(&cfg) {
            Ok(_) => {
                unreachable!(
                    "mtcp::run_maxtp_workload should return Unimplemented in T13"
                );
            }
            Err(e) => match mode {
                PreconditionMode::Strict => {
                    anyhow::bail!(
                        "mTCP stack is stubbed in T13: {e}. Pass \
                         `--precondition-mode lenient` to skip with a CSV \
                         marker, or wait for Plan A AMI T6+T7 to land."
                    );
                }
                PreconditionMode::Lenient => {
                    let agg = maxtp::BucketAggregate::from_sample(
                        *bucket,
                        Stack::Mtcp,
                        None,
                        BucketVerdict::Invalid(format!("mtcp stub: {e}")),
                        None,
                    );
                    maxtp::emit_bucket_rows(writer, metadata, &args.tool, &args.feature_set, &agg)
                        .context("emit mtcp-stub maxtp marker row")?;
                }
            },
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI parse helpers + DPDK bring-up (duplicated from bench-vs-linux /
// bench-e2e). Same rationale — each bench tool owns its own tool label +
// metadata capture; bench-common stays pure-data.
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

/// Parse an optional comma-separated u64 list. Empty → `None`.
fn parse_u64_list(csv: &str) -> anyhow::Result<Option<Vec<u64>>> {
    let tokens: Vec<&str> = csv.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if tokens.is_empty() {
        return Ok(None);
    }
    let mut out: Vec<u64> = Vec::with_capacity(tokens.len());
    for t in tokens {
        let v: u64 = t.parse().with_context(|| format!("parsing `{t}` as u64"))?;
        out.push(v);
    }
    Ok(Some(out))
}

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
    let mut eal_argv: Vec<String> = vec!["bench-vs-mtcp".to_string()];
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
        tcp_mss: args.mss as u32,
        // Spec §11.1: cc_mode=off on both stacks (trading-latency).
        // Default is already 0 but we set it explicitly to pin intent.
        cc_mode: 0,
        // Maxtp grid (`maxtp::C_CONNS`) tops out at C=64 connections
        // per cell. The default `max_connections=16` is too small —
        // the 2026-05-03 bench-pair run hit `engine.connect failed:
        // TooManyConns` at conn 11 on a higher-C cell because earlier
        // buckets' connections still occupy slots while a new bucket
        // is bringing up its own. 512 gives us 8× headroom over the
        // grid's max C, plenty of cushion for stale connections from
        // earlier buckets that haven't fully torn down by the time
        // the next bucket opens its connections. Burst grid only needs
        // 1 connection so the bump is harmless there. The cost is a
        // larger flow_table allocation + timer wheel, both
        // proportional to `max_connections` — small relative to the
        // mempool / mbuf footprint.
        max_connections: 512,
        ..dpdk_net_core::engine::EngineConfig::default()
    };
    Engine::new(cfg).map_err(|e| anyhow::anyhow!("Engine::new failed: {e:?}"))
}

// ---------------------------------------------------------------------------
// Preconditions plumbing — same shape as bench-vs-linux / bench-e2e.
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
                        "bench-vs-mtcp: WARN lenient mode — check-bench-preconditions \
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
    fn parse_stacks_default_is_both() {
        let out = parse_stacks("dpdk,mtcp").unwrap();
        assert_eq!(out, vec![Stack::DpdkNet, Stack::Mtcp]);
    }

    #[test]
    fn parse_stacks_accepts_linux() {
        // The 2026-05-03 follow-up added a Linux maxtp arm. Confirm the
        // CLI parser routes both `linux` and `linux_kernel` aliases to
        // the same Stack::Linux variant.
        let out = parse_stacks("dpdk,linux").unwrap();
        assert_eq!(out, vec![Stack::DpdkNet, Stack::Linux]);
        let out = parse_stacks("linux_kernel").unwrap();
        assert_eq!(out, vec![Stack::Linux]);
    }

    #[test]
    fn parse_stacks_accepts_three_stacks() {
        let out = parse_stacks("dpdk,mtcp,linux").unwrap();
        assert_eq!(out, vec![Stack::DpdkNet, Stack::Mtcp, Stack::Linux]);
    }

    #[test]
    fn parse_stacks_dedupes() {
        let out = parse_stacks("dpdk,dpdk,mtcp,dpdk").unwrap();
        assert_eq!(out, vec![Stack::DpdkNet, Stack::Mtcp]);
    }

    #[test]
    fn parse_stacks_handles_whitespace_and_empty_entries() {
        let out = parse_stacks(" dpdk , , mtcp ").unwrap();
        assert_eq!(out, vec![Stack::DpdkNet, Stack::Mtcp]);
    }

    #[test]
    fn parse_stacks_rejects_unknown_token() {
        assert!(parse_stacks("dpdk,garbage").is_err());
    }

    #[test]
    fn parse_stacks_empty_returns_empty() {
        let out = parse_stacks("").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_u64_list_empty_is_none() {
        assert_eq!(parse_u64_list("").unwrap(), None);
        assert_eq!(parse_u64_list("  ").unwrap(), None);
    }

    #[test]
    fn parse_u64_list_accepts_one_value() {
        assert_eq!(parse_u64_list("65536").unwrap(), Some(vec![65536]));
    }

    #[test]
    fn parse_u64_list_accepts_multiple_values() {
        assert_eq!(
            parse_u64_list("65536,1048576,16777216").unwrap(),
            Some(vec![65536, 1_048_576, 16_777_216])
        );
    }

    #[test]
    fn parse_u64_list_rejects_non_numeric() {
        assert!(parse_u64_list("abc").is_err());
    }

    // ------------------------------------------------------------------
    // resolve_nic_max_bps: CLI flag > env var > None (skip).
    // Env-var handling is global to the process; we set + unset the
    // NIC_MAX_BPS var inside the test. Tests don't run in parallel
    // when they mutate the same env var, but there's only one here and
    // cargo's default --test-threads doesn't interfere with flag-only
    // calls that don't read the var.
    // ------------------------------------------------------------------

    #[test]
    fn resolve_nic_max_bps_prefers_cli_flag() {
        // Set env var — CLI flag should still win.
        std::env::set_var("NIC_MAX_BPS", "42");
        let got = resolve_nic_max_bps(Some(100_000_000_000));
        std::env::remove_var("NIC_MAX_BPS");
        assert_eq!(got, Some(100_000_000_000));
    }

    #[test]
    fn resolve_nic_max_bps_falls_back_to_env() {
        std::env::set_var("NIC_MAX_BPS", "100000000000");
        let got = resolve_nic_max_bps(None);
        std::env::remove_var("NIC_MAX_BPS");
        assert_eq!(got, Some(100_000_000_000));
    }

    #[test]
    fn resolve_nic_max_bps_none_when_both_unset() {
        std::env::remove_var("NIC_MAX_BPS");
        assert_eq!(resolve_nic_max_bps(None), None);
    }

    // ------------------------------------------------------------------
    // mean_throughput_bps: simple arithmetic mean over samples.
    // ------------------------------------------------------------------

    #[test]
    fn mean_throughput_bps_empty_is_zero() {
        let run = dpdk_burst::BucketRun {
            samples: vec![],
            sum_over_bursts_bytes: 0,
            tx_ts_mode: TxTsMode::TscFallback,
        };
        assert_eq!(mean_throughput_bps(&run), 0.0);
    }

    #[test]
    fn mean_throughput_bps_averages_samples() {
        use bench_vs_mtcp::burst::BurstSample;
        let run = dpdk_burst::BucketRun {
            samples: vec![
                BurstSample {
                    throughput_bps: 8_000_000_000.0,
                    initiation_ns: 100.0,
                    steady_bps: 8_000_000_000.0,
                },
                BurstSample {
                    throughput_bps: 10_000_000_000.0,
                    initiation_ns: 200.0,
                    steady_bps: 10_000_000_000.0,
                },
            ],
            sum_over_bursts_bytes: 2 * 64 * 1024,
            tx_ts_mode: TxTsMode::TscFallback,
        };
        let m = mean_throughput_bps(&run);
        assert!((m - 9_000_000_000.0).abs() < 1.0, "m = {m}");
    }

    // ------------------------------------------------------------------
    // Post-run NIC-saturation flip on the aggregate's verdict.
    //
    // Proves that `check_nic_saturation_bps(achieved, max)` with
    // achieved > 70% of max returns Invalid, and
    // `BucketAggregate::override_verdict` nukes the Summary slots so
    // `emit_bucket_rows` produces the single-marker-row shape
    // downstream reports expect.
    // ------------------------------------------------------------------

    #[test]
    fn post_run_nic_saturation_flips_aggregate_verdict() {
        use bench_vs_mtcp::burst::{Bucket, BucketAggregate, BurstSample};

        // Synthetic run: 100 Gbps NIC max, all samples at 80 Gbps =
        // 80% of line rate → fails the 70% ceiling.
        let samples: Vec<BurstSample> = (0..10)
            .map(|_| BurstSample {
                throughput_bps: 80_000_000_000.0,
                initiation_ns: 100.0,
                steady_bps: 80_000_000_000.0,
            })
            .collect();
        let run = dpdk_burst::BucketRun {
            samples: samples.clone(),
            sum_over_bursts_bytes: 10 * 64 * 1024,
            tx_ts_mode: TxTsMode::TscFallback,
        };
        let mut agg = BucketAggregate::from_samples(
            Bucket::new(64 * 1024, 0),
            Stack::DpdkNet,
            &samples,
            BucketVerdict::Ok,
            Some(TxTsMode::TscFallback),
        );
        // Pre-flip: verdict ok, summaries present.
        assert!(agg.verdict.is_ok());
        assert!(agg.throughput_bps.is_some());

        // Run the post-bucket saturation check (same path main.rs
        // takes).
        let achieved = mean_throughput_bps(&run) as u64;
        let sat = check_nic_saturation_bps(achieved, 100_000_000_000);
        assert!(!sat.is_ok(), "expected NIC-bound fail; got {sat:?}");
        agg.override_verdict(sat);

        // Post-flip: verdict invalid, summaries cleared — the CSV
        // emit path will produce a single marker row.
        assert!(!agg.verdict.is_ok());
        assert!(agg.throughput_bps.is_none());
        assert!(agg.initiation_ns.is_none());
        assert!(agg.steady_bps.is_none());
        assert!(
            agg.verdict
                .reason()
                .unwrap()
                .contains("NIC-bound"),
            "reason was {:?}",
            agg.verdict.reason()
        );
    }
}
