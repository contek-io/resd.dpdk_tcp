//! dpdk_net burst-workload runner — spec §11.1.
//!
//! Drives the K × G grid against a live kernel-TCP sink peer using one
//! persistent TCP connection (established once, reused for all
//! measurement bursts + warmup).
//!
//! # Measurement contract (spec §11.1)
//!
//! Per burst:
//! - `t0` = inline TSC read immediately before the first
//!   `engine.send_bytes(..)` of the burst.
//! - `t_first_wire` = NIC HW TX timestamp on segment 1 of the burst.
//!   On ENA, no TX-TS dynfield is advertised; fall back to the TSC
//!   captured right after the first `engine.send_bytes` call returns
//!   (which is the closest observable point to "segment 1 hit the
//!   NIC" that user-space gets without HW TS).
//! - `t1` = NIC HW TX timestamp on the last segment of the burst. On
//!   ENA, fall back to TSC captured at the end of the drain when
//!   `drain_tx_pending_data` has flushed the final segment through
//!   `rte_eth_tx_burst`.
//!
//! Throughput per burst = K / (t1 − t0), emitted in bps (bench-common's
//! summariser aggregates across ≥10 k bursts per bucket).
//!
//! # TX-TS availability
//!
//! ENA does not expose the `rte_mbuf::tx_timestamp` dynfield (confirmed
//! by the A-HW Task 18 offload-counter profile: `offload_missing_rx_
//! timestamp = 1` and the same hardware gap applies to TX). On
//! mlx5/ice and future-gen ENA, the HW TS dynfield will be available;
//! a future enhancement swaps the TSC fallback for the HW TS read.
//! `TxTsMode` below records which path was taken so CSV consumers can
//! filter out TSC-only rows when diffing against HW-TS rows on a
//! different NIC.
//!
//! # Warmup + sanity invariant
//!
//! `warmup` bursts are pumped without recording samples. After the
//! measurement bursts, the runner snapshots
//! `counters.tcp.tx_payload_bytes` and calls
//! [`crate::preflight::check_sanity_invariant`] against
//! `sum_over_bursts(K)`. Any divergence surfaces as `Err` — harness
//! is lying about what it sent.
//!
//! # Gap enforcement
//!
//! Between bursts, sleep for `G` milliseconds (`G = 0` → no sleep,
//! back-to-back). The sleep is `std::thread::sleep` — coarse enough
//! that the 1ms / 10ms / 100ms gaps are honored within a few µs on a
//! tuned host, and the 0ms gap is exactly zero (no syscall).

use std::time::Duration;

use anyhow::Context;

use bench_e2e::workload::{drain_and_accumulate_readable, open_connection, tsc_delta_to_ns};

use dpdk_net_core::engine::Engine;
use dpdk_net_core::flow_table::ConnHandle;

use crate::burst::{BurstSample, Bucket};

/// Source of the TX-side timestamps used to close a burst.
///
/// Recorded per-run so downstream reports can filter rows by the
/// measurement source — a `HwTs` row on mlx5 and a `TscFallback` row
/// on ENA are not directly comparable at the sub-µs scale (TSC drift
/// on a DPDK-isolated core is well under 1 µs/s on an invariant-TSC
/// CPU, but we still flag the measurement source so the difference is
/// visible in bench-report).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxTsMode {
    /// Read `rte_mbuf::tx_timestamp` dynfield. Unavailable on ENA;
    /// selected by the operator (via `DpdkBurstCfg.tx_ts_mode`) on
    /// NICs that advertise the dynfield (mlx5/ice). The variant is
    /// live once `Engine::last_tx_hw_ts(conn)` lands; today the
    /// enum value still participates in `dimensions_json.tx_ts_mode`
    /// so CSV consumers can filter rows by measurement source.
    HwTs,
    /// TSC captured at `rte_eth_tx_burst` return (ENA fallback).
    TscFallback,
}

impl TxTsMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            TxTsMode::HwTs => "hw_ts",
            TxTsMode::TscFallback => "tsc_fallback",
        }
    }
}

/// Per-bucket runner configuration — assembled by main.rs.
pub struct DpdkBurstCfg<'a> {
    pub engine: &'a Engine,
    pub conn: ConnHandle,
    pub bucket: Bucket,
    pub warmup: u64,
    pub bursts: u64,
    pub tsc_hz: u64,
    /// Payload template. Caller allocates once at bucket entry (one
    /// vec per bucket) so the inner loop doesn't allocate.
    pub payload: &'a [u8],
    /// The TX-TS mode the harness will report into CSV; caller picks
    /// `TscFallback` on ENA and `HwTs` on mlx5/ice.
    pub tx_ts_mode: TxTsMode,
}

/// One bucket's raw measurement product.
pub struct BucketRun {
    /// Per-burst samples (warmup already stripped).
    pub samples: Vec<BurstSample>,
    /// Sum of `bucket.burst_bytes` across measurement bursts only
    /// (warmup excluded). Caller feeds this to
    /// `preflight::check_sanity_invariant` along with the
    /// `counters.tcp.tx_payload_bytes` delta.
    pub sum_over_bursts_bytes: u64,
    /// TX-TS mode actually used (propagated from cfg).
    pub tx_ts_mode: TxTsMode,
}

/// Drive one bucket on the dpdk_net side. One connection is reused;
/// caller is responsible for opening it via [`open_connection`] and
/// passing the handle in.
///
/// This function is separate from [`run_bucket`] for the single-
/// connection, persistent-reuse path described in spec §11.1 "One
/// connection per lcore, established once, reused for the whole run".
/// The caller owns the connection lifetime and iterates buckets.
pub fn run_bucket(cfg: &DpdkBurstCfg<'_>) -> anyhow::Result<BucketRun> {
    if cfg.payload.len() as u64 != cfg.bucket.burst_bytes {
        anyhow::bail!(
            "dpdk_burst: payload length ({}) does not match K ({}) for bucket {}",
            cfg.payload.len(),
            cfg.bucket.burst_bytes,
            cfg.bucket.label()
        );
    }

    // Warmup — pump N bursts without recording samples.
    for i in 0..cfg.warmup {
        send_one_burst_and_drain_acks(cfg.engine, cfg.conn, cfg.payload)
            .with_context(|| format!("warmup burst {i} ({}))", cfg.bucket.label()))?;
        maybe_sleep_gap(cfg.bucket.gap_ms);
    }

    // Measurement — record one sample per burst.
    let mut samples: Vec<BurstSample> = Vec::with_capacity(cfg.bursts as usize);
    let mut sum: u64 = 0;
    for i in 0..cfg.bursts {
        // t0 = inline TSC pre-first-send.
        let t0_tsc = dpdk_net_core::clock::rdtsc();

        // First segment — block on peer-window / send-buffer pressure
        // until the stack accepts ≥1 byte, then capture t_first_wire.
        let (initial_accepted, t_first_wire_tsc) =
            send_first_segment_and_capture_wire_time(cfg.engine, cfg.conn, cfg.payload)
                .with_context(|| format!("burst {i} first-segment ({})", cfg.bucket.label()))?;

        // Remaining bytes — push them, drive poll, drain until the
        // stack has accepted the full K bytes + the TX ring has
        // flushed the final segment through `rte_eth_tx_burst`. The
        // helper captures `t1_tsc` immediately on return of that
        // final `rte_eth_tx_burst` (spec §11.1: TSC-at-
        // `rte_eth_tx_burst`-return) so poll/drain noise doesn't
        // bias the (t1 − t0) window.
        //
        // Once `Engine::last_tx_hw_ts(conn)` lands, swap this line
        // for the HW-TS read at the same point.
        let t1_tsc = drive_burst_remainder_to_completion(
            cfg.engine,
            cfg.conn,
            cfg.payload,
            initial_accepted,
        )
        .with_context(|| format!("burst {i} drain ({})", cfg.bucket.label()))?;

        let t0_ns = tsc_to_absolute_ns(t0_tsc, cfg.tsc_hz);
        let t_first_wire_ns = tsc_to_absolute_ns(t_first_wire_tsc, cfg.tsc_hz);
        let t1_ns = tsc_to_absolute_ns(t1_tsc, cfg.tsc_hz);

        // Guard against clock hiccups (shouldn't happen on invariant
        // TSC) — drop malformed samples rather than let them poison
        // the aggregate.
        if t1_ns <= t0_ns
            || t_first_wire_ns < t0_ns
            || t1_ns < t_first_wire_ns
        {
            eprintln!(
                "bench-vs-mtcp: WARN dropping burst {i} — non-monotonic TSC \
                 (t0={t0_ns} t_first_wire={t_first_wire_ns} t1={t1_ns})"
            );
            continue;
        }

        let sample = BurstSample::from_timestamps(
            cfg.bucket.burst_bytes,
            t0_ns,
            t_first_wire_ns,
            t1_ns,
        );
        samples.push(sample);
        sum = sum.saturating_add(cfg.bucket.burst_bytes);

        maybe_sleep_gap(cfg.bucket.gap_ms);
    }

    Ok(BucketRun {
        samples,
        sum_over_bursts_bytes: sum,
        tx_ts_mode: cfg.tx_ts_mode,
    })
}

/// Open a single persistent connection to the peer. Returns the
/// connection handle to be reused across every bucket in the run.
/// Thin wrapper over `bench_e2e::workload::open_connection` so the
/// bench-vs-mtcp call sites don't have to know about that dependency
/// shape.
pub fn open_persistent_connection(
    engine: &Engine,
    peer_ip_host_order: u32,
    peer_port: u16,
) -> anyhow::Result<ConnHandle> {
    open_connection(engine, peer_ip_host_order, peer_port).context("dpdk_net open_connection")
}

/// Send the full burst payload. Accepts carry-back partial-accepts by
/// looping `send_bytes` + `poll_once` until every byte is queued.
///
/// Used only during warmup; the measurement path uses the more
/// detailed split send that captures `t_first_wire` separately.
fn send_one_burst_and_drain_acks(
    engine: &Engine,
    conn: ConnHandle,
    payload: &[u8],
) -> anyhow::Result<()> {
    // Forward-progress watchdog rather than absolute deadline (parity
    // with `drive_burst_remainder_to_completion`): we only fail on
    // genuine wedge ("no byte accepted in 60s"), not on slow-but-
    // steady big bursts that legitimately exceed a flat 60s budget.
    const STALL_TIMEOUT: Duration = Duration::from_secs(180);
    let mut sent: usize = 0;
    let mut last_progress = std::time::Instant::now();
    while sent < payload.len() {
        let remaining = &payload[sent..];
        match engine.send_bytes(conn, remaining) {
            Ok(0) => {
                // No byte accepted — drive poll/drain and check the
                // stall watchdog. Falls through to the post-loop poll
                // / drain on the next iteration.
            }
            Ok(n) => {
                sent += n as usize;
                last_progress = std::time::Instant::now();
            }
            Err(e) => anyhow::bail!("send_bytes failed mid-burst: {e:?}"),
        }
        engine.poll_once();
        // Drain any ACK-driven Readable (peer may echo/ACK) so the
        // event queue doesn't back up. Kernel sink won't emit
        // Readable, but the engine still emits state transitions.
        let mut _last_rx: Option<u64> = None;
        let _drained = drain_and_accumulate_readable(engine, conn, &mut _last_rx)
            .context("warmup drain")?;
        if last_progress.elapsed() >= STALL_TIMEOUT {
            anyhow::bail!(
                "warmup burst stalled with {sent}/{} bytes accepted \
                 (no forward progress in {:?})",
                payload.len(),
                STALL_TIMEOUT,
            );
        }
    }
    Ok(())
}

/// Send the first segment of the burst. Returns `(accepted_bytes,
/// t_first_wire_tsc)`: the count of bytes the stack accepted on the
/// first successful `send_bytes` call (for the caller to slide past
/// when driving the remainder) and the TSC value captured
/// immediately after that call returned.
///
/// For the HW-TS mode, the real implementation would consult the
/// engine's per-conn TX HW TS (via a future `Engine::last_tx_hw_ts`
/// hook) and return that instead. T12 captures the TSC in both modes
/// since the HW TS hook doesn't exist today; the mode tag on the
/// cfg still records intent so CSV consumers can flag the ENA
/// fallback shape.
fn send_first_segment_and_capture_wire_time(
    engine: &Engine,
    conn: ConnHandle,
    payload: &[u8],
) -> anyhow::Result<(usize, u64)> {
    // Bumped from 30s to 60s for symmetry with the drain watchdog
    // (parity with `drive_burst_remainder_to_completion`'s
    // STALL_TIMEOUT). On a healthy peer this fires sub-millisecond;
    // the deadline is for the wedged-peer surface only.
    const STALL_TIMEOUT: Duration = Duration::from_secs(180);
    let start = std::time::Instant::now();
    loop {
        match engine.send_bytes(conn, payload) {
            Ok(0) => {
                // TX buffer / peer window full — drive poll + retry.
                // No TSC capture yet; we want to capture only after
                // the first byte is actually accepted.
                engine.poll_once();
                if start.elapsed() >= STALL_TIMEOUT {
                    anyhow::bail!(
                        "first-segment send did not accept any byte within {:?}",
                        STALL_TIMEOUT,
                    );
                }
            }
            Ok(n) => {
                // Accepted ≥1 byte — capture TSC now.
                let t_first_wire_tsc = dpdk_net_core::clock::rdtsc();
                // Drive a poll to push the accepted segment onto the
                // TX ring + drain any Readable ACK-side traffic.
                engine.poll_once();
                return Ok((n as usize, t_first_wire_tsc));
            }
            Err(e) => anyhow::bail!("first-segment send_bytes failed: {e:?}"),
        }
    }
}

/// Drive the rest of the burst to completion. Loops `send_bytes` +
/// `poll_once` + `drain_and_accumulate_readable` starting from byte
/// offset `already_sent` (the count returned by
/// `send_first_segment_and_capture_wire_time`) until the full K bytes
/// have been handed to the stack, then issues a final flush `poll_once`
/// (which invokes `rte_eth_tx_burst` for the last segment), captures
/// `t1_tsc` immediately on return, and only then drains any residual
/// Readable events.
///
/// Returns `t1_tsc`: the TSC value sampled right after the final
/// `rte_eth_tx_burst` (the closest observable point to "segment N hit
/// the wire" without HW TS — spec §11.1: "TSC-at-`rte_eth_tx_burst`-
/// return"). Capturing here — BEFORE the post-flush drain — keeps the
/// t1−t0 window tight to what the TX path actually spent; capturing
/// after the drain would fold poll-loop / Readable-drain noise into
/// the throughput denominator and bias throughput low.
///
/// Once `Engine::last_tx_hw_ts(conn)` lands, the HW-TS path reads the
/// exact NIC timestamp instead. Error on drain timeout (no forward
/// progress within `STALL_TIMEOUT`) so a jammed peer produces a
/// visible failure, but a slow-but-steady transfer is not killed
/// purely on absolute wall-clock — the 2026-05-03 bench-pair run hit
/// `K=1MiB G=10ms` burst 244 stalling at 151_552/1_048_576 bytes
/// after the previous fixed-60s ceiling expired. The new model: we
/// reset the deadline whenever `send_bytes` accepts ≥1 byte, so the
/// failure surface is "no byte accepted in `STALL_TIMEOUT`", not
/// "this big burst couldn't finish in 60s flat".
fn drive_burst_remainder_to_completion(
    engine: &Engine,
    conn: ConnHandle,
    payload: &[u8],
    already_sent: usize,
) -> anyhow::Result<u64> {
    /// Stall timeout — how long we tolerate zero forward progress
    /// before declaring the connection wedged. 60s is generous for
    /// any healthy peer (the kernel sink at 100Gbps drains a 1 MiB
    /// burst in <100µs); the deadline is here for the wedged-peer
    /// case where the operator wants a visible failure instead of an
    /// indefinite hang.
    const STALL_TIMEOUT: Duration = Duration::from_secs(180);

    let mut sent = already_sent;
    let mut last_progress = std::time::Instant::now();
    let mut last_rx: Option<u64> = None;
    while sent < payload.len() {
        let remaining = &payload[sent..];
        match engine.send_bytes(conn, remaining) {
            Ok(0) => {
                engine.poll_once();
                let _ = drain_and_accumulate_readable(engine, conn, &mut last_rx)
                    .context("burst drain mid-flight")?;
                if last_progress.elapsed() >= STALL_TIMEOUT {
                    anyhow::bail!(
                        "burst drain stalled with {sent}/{} bytes accepted \
                         (no forward progress in {:?})",
                        payload.len(),
                        STALL_TIMEOUT,
                    );
                }
            }
            Ok(n) => {
                sent += n as usize;
                // Reset the stall watchdog on any forward progress.
                last_progress = std::time::Instant::now();
            }
            Err(e) => anyhow::bail!("send_bytes failed mid-burst: {e:?}"),
        }
    }
    // Final flush poll → `rte_eth_tx_burst` pushes the last segment.
    // Capture t1_tsc IMMEDIATELY on return so the throughput window
    // is bounded at the closest-to-wire observable point. Any work
    // that comes after (the Readable drain below) is excluded from
    // (t1 − t0) — see spec §11.1 "TSC-at-`rte_eth_tx_burst`-return".
    engine.poll_once();
    let t1_tsc = dpdk_net_core::clock::rdtsc();
    let _ = drain_and_accumulate_readable(engine, conn, &mut last_rx)
        .context("burst final drain")?;
    Ok(t1_tsc)
}

/// Absolute-time conversion: TSC cycles → nanoseconds, anchored at
/// boot (or whenever the TSC started). We only diff these values so
/// the anchor cancels out; the `tsc_delta_to_ns` helper takes two
/// TSCs and gives a delta, but we need an absolute so the
/// `BurstSample::from_timestamps` constructor (which also takes
/// absolutes) gets a coherent triple.
///
/// The u128 intermediate prevents overflow at typical TSC values
/// (TSC on a 3 GHz CPU after ~190 years is still fine for u128).
fn tsc_to_absolute_ns(tsc: u64, tsc_hz: u64) -> u64 {
    // Delta from 0 — the absolute timeline is arbitrary, we just need
    // monotonic consistency within a burst.
    tsc_delta_to_ns(0, tsc, tsc_hz)
}

fn maybe_sleep_gap(gap_ms: u64) {
    if gap_ms > 0 {
        std::thread::sleep(Duration::from_millis(gap_ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_ts_mode_as_str_is_stable() {
        assert_eq!(TxTsMode::HwTs.as_str(), "hw_ts");
        assert_eq!(TxTsMode::TscFallback.as_str(), "tsc_fallback");
    }

    #[test]
    fn tsc_to_absolute_ns_monotonic() {
        let a = tsc_to_absolute_ns(1_000_000_000, 3_000_000_000);
        let b = tsc_to_absolute_ns(2_000_000_000, 3_000_000_000);
        assert!(b > a);
        // 1 billion TSC cycles at 3 GHz ≈ 333_333_333 ns.
        assert!((a as i128 - 333_333_333i128).abs() < 100);
    }

    #[test]
    fn maybe_sleep_gap_zero_is_noop() {
        // Should return immediately — we just verify it doesn't panic.
        let start = std::time::Instant::now();
        maybe_sleep_gap(0);
        assert!(start.elapsed() < Duration::from_millis(1));
    }
}
