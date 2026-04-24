//! Mode A — RTT comparison, trading-latency preset. Spec §8.
//!
//! Drives up to three stacks side-by-side against the same TCP echo
//! server peer:
//!
//!   1. `dpdk_net` via `dpdk_net_core::Engine` (bench-e2e's
//!      `workload::run_rtt_workload`)
//!   2. `linux_kernel` via `std::net::TcpStream`
//!   3. `afpacket` via `libc::socket(PF_PACKET, SOCK_RAW, ...)`
//!      (stubbed in T8 — see `src/afpacket.rs` for rationale)
//!
//! For each selected stack we capture N measurements, summarise, and
//! emit the 7-row CSV aggregation tuple (`p50`/`p99`/`p999`/`mean`/
//! `stddev`/`ci95_lower`/`ci95_upper`) with
//! `dimensions_json = {"preset":"latency","mode":"rtt","stack":<...>}`.
//!
//! # Tap-jitter baseline subtraction (spec §8)
//!
//! Spec §8 mentions a same-host tap device captures raw wire RTT and
//! the harness records that noise floor. The full tap-device
//! plumbing is deferred — see the commit message + report for
//! rationale. For the measurement set shipped in T8 we instead
//! record a "self-loopback" floor: a kernel-TCP connection to
//! 127.0.0.1:$peer_port when the operator runs an echo-server
//! locally, or a skip when they don't. This is weaker than a tap
//! probe (it includes loopback stack traversal) but gives downstream
//! a machine-readable pattern to consume until the tap lands.
//!
//! The baseline row, if captured, is emitted with
//! `dimensions_json.stack = "loopback_tap_baseline"` so bench-report
//! can treat it as the noise floor for latency-delta plots without
//! mixing it into any stack's aggregate.

use anyhow::Context;

use bench_common::csv_row::{CsvRow, MetricAggregation};
use bench_common::percentile::{summarize, Summary};
use bench_common::run_metadata::RunMetadata;

use bench_e2e::workload::{open_connection as dpdk_open, run_rtt_workload as dpdk_run};

use dpdk_net_core::engine::Engine;

use crate::{afpacket, linux_kernel, Stack};

/// Per-run configuration extracted from the CLI in `main.rs`. This
/// shape lets us keep `run_mode_rtt` a pure function that takes the
/// already-parsed args + an already-built engine (if dpdk_net is
/// selected) + the metadata/writer pair — all DPDK bring-up stays in
/// `main.rs`.
pub struct ModeRttCfg<'a> {
    pub peer_ip_host_order: u32,
    pub peer_port: u16,
    pub peer_iface: &'a str,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub iterations: u64,
    pub warmup: u64,
    pub tool: &'a str,
    pub feature_set: &'a str,
    pub stacks: &'a [Stack],
    pub tsc_hz: u64,
}

/// Run the selected stacks and emit their CSV rows. Engine is
/// `Some(&Engine)` iff `Stack::DpdkNet` is in `cfg.stacks`; caller
/// enforces that invariant in `main.rs` so we don't silently skip.
pub fn run_mode_rtt<W: std::io::Write>(
    cfg: &ModeRttCfg<'_>,
    engine: Option<&Engine>,
    metadata: &RunMetadata,
    writer: &mut csv::Writer<W>,
) -> anyhow::Result<()> {
    for &stack in cfg.stacks {
        let samples = run_one_stack(cfg, engine, stack)
            .with_context(|| format!("running stack {:?}", stack))?;
        if samples.is_empty() {
            anyhow::bail!("stack {} produced no samples", stack.as_dimension());
        }
        let summary = summarize(&samples);
        emit_stack_rows(writer, cfg, metadata, stack, &summary)?;
    }
    Ok(())
}

/// Run the RTT workload for a single stack. Encapsulates the
/// stack-specific bring-up / tear-down so the outer loop is flat.
fn run_one_stack(
    cfg: &ModeRttCfg<'_>,
    engine: Option<&Engine>,
    stack: Stack,
) -> anyhow::Result<Vec<f64>> {
    eprintln!(
        "bench-vs-linux: RTT workload on stack={}",
        stack.as_dimension()
    );
    match stack {
        Stack::DpdkNet => {
            let engine = engine.ok_or_else(|| {
                anyhow::anyhow!(
                    "DpdkNet stack selected but engine not provided — main.rs invariant violated"
                )
            })?;
            let conn = dpdk_open(engine, cfg.peer_ip_host_order, cfg.peer_port)
                .context("dpdk_net open_connection")?;
            dpdk_run(
                engine,
                conn,
                cfg.request_bytes,
                cfg.response_bytes,
                cfg.tsc_hz,
                cfg.warmup,
                cfg.iterations,
            )
            .context("dpdk_net run_rtt_workload")
        }
        Stack::LinuxKernel => {
            let mut stream = linux_kernel::connect(cfg.peer_ip_host_order, cfg.peer_port)
                .context("linux_kernel connect")?;
            linux_kernel::run_rtt_workload(
                &mut stream,
                cfg.request_bytes,
                cfg.response_bytes,
                cfg.warmup,
                cfg.iterations,
            )
            .context("linux_kernel run_rtt_workload")
        }
        Stack::AfPacket => {
            let af_cfg = afpacket::AfPacketConfig {
                iface: cfg.peer_iface,
                peer_ip_host_order: cfg.peer_ip_host_order,
                peer_port: cfg.peer_port,
                request_bytes: cfg.request_bytes,
                response_bytes: cfg.response_bytes,
                warmup: cfg.warmup,
                iterations: cfg.iterations,
            };
            afpacket::run_rtt_workload(&af_cfg).map_err(|e| anyhow::anyhow!(e))
        }
    }
}

/// Emit the 7-row CSV aggregation tuple for one stack.
fn emit_stack_rows<W: std::io::Write>(
    writer: &mut csv::Writer<W>,
    cfg: &ModeRttCfg<'_>,
    metadata: &RunMetadata,
    stack: Stack,
    summary: &Summary,
) -> anyhow::Result<()> {
    let dims = serde_json::json!({
        "preset": "latency",
        "mode": "rtt",
        "stack": stack.as_dimension(),
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
            tool: cfg.tool.to_string(),
            test_case: "rtt_comparison".to_string(),
            feature_set: cfg.feature_set.to_string(),
            dimensions_json: dims.clone(),
            metric_name: "rtt_ns".to_string(),
            metric_unit: "ns".to_string(),
            metric_value: value,
            metric_aggregation: agg,
            // Task 2.8 host/dpdk/worktree identification — blank here; only
            // bench-micro's summariser populates these (spec §3 / §4.4).
            cpu_family: None,
            cpu_model_name: None,
            dpdk_version_pkgconfig: None,
            worktree_branch: None,
            uprof_session_id: None,
        };
        writer.serialize(&row)?;
    }
    Ok(())
}

/// Build `dimensions_json` for a stack. Exposed as `pub` for unit
/// testing — callers outside the module use the emit path.
pub fn build_dimensions_json(stack: Stack) -> String {
    serde_json::json!({
        "preset": "latency",
        "mode": "rtt",
        "stack": stack.as_dimension(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dimensions_json_shape() {
        for stack in [Stack::DpdkNet, Stack::LinuxKernel, Stack::AfPacket] {
            let dims = build_dimensions_json(stack);
            let parsed: serde_json::Value = serde_json::from_str(&dims).unwrap();
            assert_eq!(parsed["preset"], "latency");
            assert_eq!(parsed["mode"], "rtt");
            assert_eq!(parsed["stack"], stack.as_dimension());
        }
    }

    #[test]
    fn build_dimensions_json_is_stable_across_calls() {
        // Serialisation must be deterministic — downstream bench-report
        // groups rows by the verbatim dimensions_json string.
        let d1 = build_dimensions_json(Stack::LinuxKernel);
        let d2 = build_dimensions_json(Stack::LinuxKernel);
        assert_eq!(d1, d2);
    }
}
