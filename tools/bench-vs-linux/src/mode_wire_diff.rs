//! Mode B — wire-level byte-diff, `preset=rfc_compliance`. Spec §8.
//!
//! Task 9 delivers the **divergence-normalisation + diff engine** and
//! an MVP runner that consumes pre-captured pcap files via CLI flags
//! (`--local-pcap` / `--peer-pcap`). The end-to-end pipeline would
//! additionally drive tcpdump on both ends of a live paired-host run,
//! SCP the peer capture, and loop. That orchestration is deferred:
//! it needs the live bench-pair fleet that only `scripts/bench-
//! nightly.sh` (Task 15) has access to, and testing it requires a
//! running peer. The MVP unblocks development + offline analysis of
//! captures produced by any other means (manually-driven tcpdump +
//! scp, a capture collected by the full T15 orchestrator, etc).
//!
//! # Preset
//!
//! Mode B calls `dpdk_net::apply_preset(DPDK_NET_PRESET_RFC_COMPLIANCE,
//! &mut cfg)` before `Engine::new(cfg)` when dpdk_net is actively
//! driving traffic. In MVP mode (pre-captured pcaps) we don't build
//! an Engine at all — the preset flip runs at the data-source side
//! (the capturing operator). We still expose a helper that builds a
//! preset-applied config so follow-up live-capture work can pick it
//! up without rewriting this module.
//!
//! # CSV output
//!
//! Three rows per run, all with `metric_unit = "bytes"` / `"packets"`
//! respectively and `dimensions_json = {"preset":"rfc_compliance",
//! "mode":"wire_diff", "local":<name>,"peer":<name>}`:
//!   - `diff_bytes` (Mean) — number of byte positions that diverge
//!     between the two canonicalised captures.
//!   - `local_packets` (Mean) — packet count in the local canonicalised
//!     stream (sanity-check the normalisation didn't drop frames).
//!   - `peer_packets` (Mean) — packet count in the peer canonicalised
//!     stream.
//!
//! Mean is used (instead of P99) because there's one summary per run
//! — no per-sample distribution to percentile. Bench-report treats
//! `Mean` as the scalar for single-value metrics.
//!
//! # Process exit code
//!
//! - `0` — diff empty (wire-identical after canonicalisation).
//! - `1` — divergences found. Summary printed to stderr.
//! - `2` — runner error (bad args, pcap unparseable, etc).

use std::path::{Path, PathBuf};

use anyhow::Context;

use bench_common::csv_row::{CsvRow, MetricAggregation};
use bench_common::run_metadata::RunMetadata;

use crate::normalize::{byte_diff_count, canonicalize_pcap, CanonicalizationOptions};

/// Mode B configuration extracted from the CLI in `main.rs`.
///
/// `tool` / `feature_set` come from the CLI; the defaults in `main.rs`
/// are set so the default CSV dimensions tag `preset=rfc_compliance`
/// even though `feature_set` is free-form operator-provided.
pub struct ModeWireDiffCfg<'a> {
    /// Path to the local (DUT) pcap — captured on the dpdk_net side.
    pub local_pcap: &'a Path,
    /// Path to the peer pcap — captured on the Linux side.
    pub peer_pcap: &'a Path,
    /// Output CSV path. Three rows emitted.
    pub output_csv: &'a Path,
    /// Tool label for CSV.
    pub tool: &'a str,
    /// Feature-set label for CSV.
    pub feature_set: &'a str,
}

/// Run mode B. MVP path: two pcap files in, diff summary out.
///
/// Returns `0` for empty-diff, `1` for divergence-found. Callers in
/// `main.rs` pass the return code to `std::process::exit`. Hard
/// errors (bad args, pcap parse failure) return `Err` which becomes
/// exit code `2` via anyhow's default process-exit convention.
pub fn run_mode_wire_diff(
    cfg: &ModeWireDiffCfg<'_>,
    metadata: &RunMetadata,
) -> anyhow::Result<i32> {
    // 1. Read both pcaps. Short-circuit with a clear error if either
    //    path is missing — operators routinely mistype these.
    let local_bytes = std::fs::read(cfg.local_pcap)
        .with_context(|| format!("reading local pcap {:?}", cfg.local_pcap))?;
    let peer_bytes = std::fs::read(cfg.peer_pcap)
        .with_context(|| format!("reading peer pcap {:?}", cfg.peer_pcap))?;

    // 2. Canonicalise both using the same CanonicalizationOptions so
    //    the same ISS / TS base pins apply to both captures.
    let opts = CanonicalizationOptions::default();
    let local_canon = canonicalize_pcap(&local_bytes, &opts)
        .context("canonicalising local pcap")?;
    let peer_canon = canonicalize_pcap(&peer_bytes, &opts)
        .context("canonicalising peer pcap")?;

    // 3. Count diff bytes + packets.
    let diff = byte_diff_count(&local_canon, &peer_canon);
    let local_packets = count_packets(&local_canon).context("counting local canonicalised packets")?;
    let peer_packets = count_packets(&peer_canon).context("counting peer canonicalised packets")?;

    eprintln!(
        "bench-vs-linux: mode=wire-diff local={:?} ({} pkts) peer={:?} ({} pkts) diff_bytes={}",
        cfg.local_pcap, local_packets, cfg.peer_pcap, peer_packets, diff
    );

    // 4. Emit CSV rows.
    let mut writer = csv::Writer::from_path(cfg.output_csv)
        .with_context(|| format!("creating output CSV {:?}", cfg.output_csv))?;
    emit_wire_diff_rows(&mut writer, cfg, metadata, diff, local_packets, peer_packets)?;
    writer.flush()?;

    // 5. Return 0 for empty-diff, 1 for divergence.
    if diff == 0 {
        Ok(0)
    } else {
        eprintln!(
            "bench-vs-linux: divergences found after canonicalisation — \
             {} byte positions differ",
            diff
        );
        Ok(1)
    }
}

/// Emit the three summary rows for a wire-diff run. Exposed as `pub` so
/// future live-capture orchestration + any integration test can call
/// the same row emission without going through the full pipeline.
pub fn emit_wire_diff_rows<W: std::io::Write>(
    writer: &mut csv::Writer<W>,
    cfg: &ModeWireDiffCfg<'_>,
    metadata: &RunMetadata,
    diff_bytes: usize,
    local_packets: u64,
    peer_packets: u64,
) -> anyhow::Result<()> {
    let dims = build_dimensions_json(cfg.local_pcap, cfg.peer_pcap);
    let rows: [(&str, &str, f64); 3] = [
        ("diff_bytes", "bytes", diff_bytes as f64),
        ("local_packets", "packets", local_packets as f64),
        ("peer_packets", "packets", peer_packets as f64),
    ];
    for (name, unit, value) in rows {
        let row = CsvRow {
            run_metadata: metadata.clone(),
            tool: cfg.tool.to_string(),
            test_case: "wire_diff".to_string(),
            feature_set: cfg.feature_set.to_string(),
            dimensions_json: dims.clone(),
            metric_name: name.to_string(),
            metric_unit: unit.to_string(),
            metric_value: value,
            metric_aggregation: MetricAggregation::Mean,
        };
        writer.serialize(&row)?;
    }
    Ok(())
}

/// Build the `dimensions_json` tag for a mode-B run. Tags `preset =
/// rfc_compliance` per spec §8 (distinct from mode A's
/// `preset = latency` tag so bench-report never mixes presets).
pub fn build_dimensions_json(local_pcap: &Path, peer_pcap: &Path) -> String {
    serde_json::json!({
        "preset": "rfc_compliance",
        "mode": "wire_diff",
        "local_pcap": path_display(local_pcap),
        "peer_pcap": path_display(peer_pcap),
    })
    .to_string()
}

fn path_display(p: &Path) -> String {
    p.file_name()
        .map(|o| o.to_string_lossy().to_string())
        .unwrap_or_else(|| p.display().to_string())
}

/// Count the number of packet records in a canonicalised pcap. Used
/// as a sanity-check alongside the byte diff — if the two captures
/// disagree on packet count the diff is meaningless.
pub fn count_packets(pcap_bytes: &[u8]) -> anyhow::Result<u64> {
    use pcap_file::pcap::PcapReader;
    let mut reader = PcapReader::new(std::io::Cursor::new(pcap_bytes))
        .context("parsing pcap header for packet count")?;
    let mut count = 0u64;
    while let Some(pkt) = reader.next_packet() {
        pkt.context("parsing pcap packet during count")?;
        count += 1;
    }
    Ok(count)
}

/// Build a `dpdk_net_core::engine::EngineConfig` with
/// `preset=rfc_compliance` applied. Follow-up live-capture orchestration
/// will call this plus `Engine::new(cfg)` before driving traffic; MVP
/// mode doesn't touch DPDK so this helper stays unused in T9 but is
/// exercised by a unit test to keep the preset-flip invariant under
/// test.
pub fn build_engine_config_rfc_compliance(
    local_ip_host_order: u32,
    gateway_ip_host_order: u32,
) -> anyhow::Result<dpdk_net_core::engine::EngineConfig> {
    let mut cfg = dpdk_net_core::engine::EngineConfig {
        local_ip: local_ip_host_order,
        gateway_ip: gateway_ip_host_order,
        ..dpdk_net_core::engine::EngineConfig::default()
    };
    dpdk_net::apply_preset(dpdk_net::DPDK_NET_PRESET_RFC_COMPLIANCE, &mut cfg)
        .map_err(|()| anyhow::anyhow!("apply_preset(rfc_compliance) rejected"))?;
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Compatibility shim — T8 `main.rs` called `run_mode_wire_diff()` (no
// args) expecting a stub that bails with a T9 pointer. T9 replaces the
// stub; `main.rs` now passes the CLI-parsed paths through the
// `ModeWireDiffCfg` API. No zero-arg form is preserved — callers must
// go through the new entry point. This keeps the call site honest: a
// mode-B invocation with no captures is a programmer error, not a
// runtime surprise.
// ---------------------------------------------------------------------------

/// Opaque wrapper carrying the same exit-code contract as the MVP
/// runner. Used by `main.rs` to keep the top-level control flow flat.
pub fn run_mode_wire_diff_from_paths(
    local_pcap: PathBuf,
    peer_pcap: PathBuf,
    output_csv: PathBuf,
    tool: &str,
    feature_set: &str,
    metadata: &RunMetadata,
) -> anyhow::Result<i32> {
    let cfg = ModeWireDiffCfg {
        local_pcap: &local_pcap,
        peer_pcap: &peer_pcap,
        output_csv: &output_csv,
        tool,
        feature_set,
    };
    run_mode_wire_diff(&cfg, metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dimensions_json_tags_preset_and_mode() {
        let local = Path::new("/tmp/local.pcap");
        let peer = Path::new("/tmp/peer.pcap");
        let dims = build_dimensions_json(local, peer);
        let v: serde_json::Value = serde_json::from_str(&dims).unwrap();
        assert_eq!(v["preset"], "rfc_compliance");
        assert_eq!(v["mode"], "wire_diff");
        assert_eq!(v["local_pcap"], "local.pcap");
        assert_eq!(v["peer_pcap"], "peer.pcap");
    }

    #[test]
    fn build_dimensions_json_is_stable_across_calls() {
        let a = build_dimensions_json(Path::new("x.pcap"), Path::new("y.pcap"));
        let b = build_dimensions_json(Path::new("x.pcap"), Path::new("y.pcap"));
        assert_eq!(a, b);
    }

    #[test]
    fn preset_builder_flips_five_fields() {
        // Invariant guard: the RFC-compliance preset writes the five
        // fields documented in parent spec §4. If any of these
        // invariants break, the A6 preset definition has changed
        // under us and mode B is no longer doing what it claims.
        let cfg = build_engine_config_rfc_compliance(0, 0).expect("apply_preset must succeed");
        assert!(cfg.tcp_nagle, "preset must enable Nagle");
        assert!(cfg.tcp_delayed_ack, "preset must enable delayed-ACK");
        assert_eq!(cfg.cc_mode, 1, "preset must set cc_mode = Reno");
        assert_eq!(cfg.tcp_min_rto_us, 200_000, "preset must set min RTO to 200ms");
        assert_eq!(
            cfg.tcp_initial_rto_us, 1_000_000,
            "preset must set initial RTO to 1s"
        );
    }
}
