//! A10 Plan B T15-B / T9-I5 — integration test for differing pcap
//! packet counts.
//!
//! When a mode-B wire-diff run lands two pcaps whose packet counts
//! disagree (e.g. local stack crashed mid-run, peer tcpdump restarted,
//! or one side retransmitted extra frames), the diff must surface the
//! discrepancy rather than silently masking it. Contract:
//!
//! - Canonicalised diff > 0 (at least all trailing bytes of the longer
//!   canonical stream count against the shorter one).
//! - `count_packets` reports the per-side packet count faithfully.
//! - `run_mode_wire_diff` returns exit code `1` (divergence found) and
//!   emits three CSV rows tagged with the right `metric_name` +
//!   `metric_value`.
//!
//! The CSV assertion is the important one — T15-A's nightly driver
//! consumes this CSV, and bench-report filters on the `diff_bytes` row.

use std::path::PathBuf;

use bench_common::preconditions::{PreconditionMode, Preconditions};
use bench_common::run_metadata::RunMetadata;
use bench_vs_linux::mode_wire_diff::{
    count_packets, run_mode_wire_diff, ModeWireDiffCfg,
};
use bench_vs_linux::normalize::{
    byte_diff_count, canonicalize_pcap, CanonicalizationOptions,
};

mod common;
use common::synth::{
    build_pcap, mac, SynthIpv4, SynthPacket, SynthTcp, TCP_FLAG_ACK, TCP_FLAG_SYN,
};

/// Build a synthetic pcap containing `n` post-handshake ACK-with-data
/// segments (plus the 3-way handshake itself). Returns the raw pcap
/// bytes. Useful for driving the canonicaliser with a known packet
/// count.
fn build_n_packet_flow(n_data_segments: usize, a_iss: u32, b_iss: u32) -> Vec<u8> {
    let a_ip = [10, 0, 0, 1];
    let b_ip = [10, 0, 0, 2];
    let a_port: u16 = 40000;
    let b_port: u16 = 10001;
    let a_mac = mac(0x01);
    let b_mac = mac(0x02);

    let mut packets = Vec::with_capacity(3 + n_data_segments);
    packets.push(SynthPacket {
        eth_src: a_mac,
        eth_dst: b_mac,
        ethertype: 0x0800,
        ipv4: Some(SynthIpv4 {
            src_ip: a_ip,
            dst_ip: b_ip,
            ip_id: 0,
            proto: 6,
            tcp: Some(SynthTcp {
                src_port: a_port,
                dst_port: b_port,
                seq: a_iss,
                ack: 0,
                data_offset: 20,
                flags: TCP_FLAG_SYN,
                window: 64240,
                options: Vec::new(),
                payload: Vec::new(),
            }),
        }),
        raw_payload: Vec::new(),
    });
    packets.push(SynthPacket {
        eth_src: b_mac,
        eth_dst: a_mac,
        ethertype: 0x0800,
        ipv4: Some(SynthIpv4 {
            src_ip: b_ip,
            dst_ip: a_ip,
            ip_id: 0,
            proto: 6,
            tcp: Some(SynthTcp {
                src_port: b_port,
                dst_port: a_port,
                seq: b_iss,
                ack: a_iss.wrapping_add(1),
                data_offset: 20,
                flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                window: 64240,
                options: Vec::new(),
                payload: Vec::new(),
            }),
        }),
        raw_payload: Vec::new(),
    });
    packets.push(SynthPacket {
        eth_src: a_mac,
        eth_dst: b_mac,
        ethertype: 0x0800,
        ipv4: Some(SynthIpv4 {
            src_ip: a_ip,
            dst_ip: b_ip,
            ip_id: 0,
            proto: 6,
            tcp: Some(SynthTcp {
                src_port: a_port,
                dst_port: b_port,
                seq: a_iss.wrapping_add(1),
                ack: b_iss.wrapping_add(1),
                data_offset: 20,
                flags: TCP_FLAG_ACK,
                window: 64240,
                options: Vec::new(),
                payload: Vec::new(),
            }),
        }),
        raw_payload: Vec::new(),
    });
    // Data segments: side A pushes 4 bytes per segment, ACK flag set.
    for i in 0..n_data_segments {
        let seq_off = 1u32 + (i as u32) * 4;
        packets.push(SynthPacket {
            eth_src: a_mac,
            eth_dst: b_mac,
            ethertype: 0x0800,
            ipv4: Some(SynthIpv4 {
                src_ip: a_ip,
                dst_ip: b_ip,
                ip_id: 0,
                proto: 6,
                tcp: Some(SynthTcp {
                    src_port: a_port,
                    dst_port: b_port,
                    seq: a_iss.wrapping_add(seq_off),
                    ack: b_iss.wrapping_add(1),
                    data_offset: 20,
                    flags: TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: vec![0xA1, 0xB2, 0xC3, 0xD4],
                }),
            }),
            raw_payload: Vec::new(),
        });
    }
    build_pcap(&packets)
}

fn make_metadata() -> RunMetadata {
    RunMetadata {
        run_id: uuid::Uuid::new_v4(),
        run_started_at: "2026-04-23T00:00:00Z".to_string(),
        commit_sha: "deadbeef".to_string(),
        branch: "phase-a10".to_string(),
        host: "test".to_string(),
        instance_type: String::new(),
        cpu_model: String::new(),
        dpdk_version: String::new(),
        kernel: String::new(),
        nic_model: String::new(),
        nic_fw: String::new(),
        ami_id: String::new(),
        precondition_mode: PreconditionMode::Lenient,
        preconditions: Preconditions::default(),
    }
}

#[test]
fn differing_packet_counts_produce_nonzero_diff() {
    // Local pcap has 3 packets (handshake only, 0 data segments);
    // peer pcap has 4 packets (handshake + 1 data segment).
    let local_pcap = build_n_packet_flow(0, 0xDEAD_BEEF, 0xFACE_F00D);
    let peer_pcap = build_n_packet_flow(1, 0x0000_0007, 0x9000_0000);

    let opts = CanonicalizationOptions::default();
    let local_canon = canonicalize_pcap(&local_pcap, &opts).expect("canon local");
    let peer_canon = canonicalize_pcap(&peer_pcap, &opts).expect("canon peer");

    let diff = byte_diff_count(&local_canon, &peer_canon);
    assert!(diff > 0, "byte_diff_count must be > 0 when packet counts differ");

    let local_pkts = count_packets(&local_canon).expect("count local");
    let peer_pkts = count_packets(&peer_canon).expect("count peer");
    assert_eq!(local_pkts, 3, "local expected 3 (handshake only)");
    assert_eq!(peer_pkts, 4, "peer expected 4 (handshake + 1 data)");
}

#[test]
fn run_mode_wire_diff_emits_expected_csv_rows_on_count_mismatch() {
    // Stage two differing-count pcaps into a temp dir, run the full
    // wire-diff runner, read the output CSV, assert the three summary
    // rows are present with the expected values. Also assert the
    // runner returns exit-code 1 (divergence).
    let tmp = tempdir_abs();
    let local_path = tmp.join("local.pcap");
    let peer_path = tmp.join("peer.pcap");
    let csv_path = tmp.join("wire-diff.csv");

    let local_bytes = build_n_packet_flow(2, 0xDEAD_BEEF, 0xFACE_F00D);
    let peer_bytes = build_n_packet_flow(3, 0x0000_0007, 0x9000_0000);
    std::fs::write(&local_path, &local_bytes).unwrap();
    std::fs::write(&peer_path, &peer_bytes).unwrap();

    let cfg = ModeWireDiffCfg {
        local_pcap: &local_path,
        peer_pcap: &peer_path,
        output_csv: &csv_path,
        tool: "bench-vs-linux-test",
        feature_set: "rfc-compliance",
    };
    let metadata = make_metadata();
    let code = run_mode_wire_diff(&cfg, &metadata).expect("runner");
    assert_eq!(code, 1, "differing packet counts must return divergence exit code 1");

    // Parse CSV: expect exactly 3 rows (diff_bytes, local_packets,
    // peer_packets), all tagged Mean, with the expected numeric
    // values.
    let mut rdr = csv::Reader::from_path(&csv_path).expect("csv reader");
    let headers = rdr.headers().expect("headers").clone();
    let metric_name_idx = headers
        .iter()
        .position(|h| h == "metric_name")
        .expect("metric_name column");
    let metric_value_idx = headers
        .iter()
        .position(|h| h == "metric_value")
        .expect("metric_value column");
    let metric_unit_idx = headers
        .iter()
        .position(|h| h == "metric_unit")
        .expect("metric_unit column");

    let mut seen: std::collections::HashMap<String, (f64, String)> =
        std::collections::HashMap::new();
    for rec in rdr.records() {
        let rec = rec.expect("csv record");
        let name = rec.get(metric_name_idx).unwrap().to_string();
        let value: f64 = rec
            .get(metric_value_idx)
            .unwrap()
            .parse()
            .expect("metric_value parses");
        let unit = rec.get(metric_unit_idx).unwrap().to_string();
        seen.insert(name, (value, unit));
    }
    let (diff_bytes_val, diff_bytes_unit) = seen
        .get("diff_bytes")
        .expect("diff_bytes row missing");
    assert!(*diff_bytes_val > 0.0, "diff_bytes must be > 0");
    assert_eq!(diff_bytes_unit, "bytes");

    let (local_val, local_unit) = seen
        .get("local_packets")
        .expect("local_packets row missing");
    assert_eq!(*local_val, 5.0, "local_packets = 3 handshake + 2 data = 5");
    assert_eq!(local_unit, "packets");

    let (peer_val, peer_unit) = seen
        .get("peer_packets")
        .expect("peer_packets row missing");
    assert_eq!(*peer_val, 6.0, "peer_packets = 3 handshake + 3 data = 6");
    assert_eq!(peer_unit, "packets");
}

/// Build an absolute temp dir for the test. `tempdir` is avoided so
/// we don't pull a new dep in just for tests; cargo's CARGO_TARGET_TMPDIR
/// gives us a workspace-local scratch path.
fn tempdir_abs() -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let unique = format!(
        "bench-vs-linux-diff-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let dir = base.join(unique);
    std::fs::create_dir_all(&dir).expect("mkdir tmp");
    dir
}
