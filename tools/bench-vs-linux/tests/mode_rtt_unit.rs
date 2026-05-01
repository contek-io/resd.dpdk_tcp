//! Integration tests for mode A (RTT comparison) pure-Rust primitives.
//!
//! These tests don't touch DPDK or a live peer — they validate the
//! library façade (`Stack`, `Mode`, dimensions JSON shape, AF_PACKET
//! stub surface) so they run on any host without an ENA VF, EAL
//! init, or peer echo-server.
//!
//! The real end-to-end smoke (dpdk + linux + peer) lives post-AMI
//! bake (Plan A T6+T7); see the parent plan for the sister IaC
//! project that provisions the sister peer instance.

use bench_vs_linux::{
    afpacket::{self, AfPacketConfig, AfPacketError},
    mode_rtt, mode_wire_diff, Mode, Stack,
};

// ---------------------------------------------------------------------------
// Mode selector + stack parser.
// ---------------------------------------------------------------------------

#[test]
fn mode_rtt_and_wire_diff_both_parse() {
    assert_eq!(Mode::parse("rtt").unwrap(), Mode::Rtt);
    assert_eq!(Mode::parse("wire-diff").unwrap(), Mode::WireDiff);
    assert_eq!(Mode::parse("wire_diff").unwrap(), Mode::WireDiff);
    assert!(Mode::parse("garbage").is_err());
}

#[test]
fn stack_parse_covers_all_three_canonical_tokens() {
    assert_eq!(Stack::parse("dpdk").unwrap(), Stack::DpdkNet);
    assert_eq!(Stack::parse("linux").unwrap(), Stack::LinuxKernel);
    assert_eq!(Stack::parse("afpacket").unwrap(), Stack::AfPacket);
}

#[test]
fn stack_as_dimension_is_the_documented_string() {
    // Bench-report groups by the verbatim dimensions_json.stack value,
    // so any rename here is a breaking schema change.
    assert_eq!(Stack::DpdkNet.as_dimension(), "dpdk_net");
    assert_eq!(Stack::LinuxKernel.as_dimension(), "linux_kernel");
    assert_eq!(Stack::AfPacket.as_dimension(), "afpacket");
}

// ---------------------------------------------------------------------------
// AF_PACKET stub — validate the frame-shape primitives + stub error.
// ---------------------------------------------------------------------------

#[test]
fn afpacket_stub_run_rtt_workload_returns_unimplemented() {
    let cfg = AfPacketConfig {
        iface: "ens6",
        peer_ip_host_order: 0x0A00_002A,
        peer_port: 10_001,
        request_bytes: 128,
        response_bytes: 128,
        warmup: 10,
        iterations: 100,
    };
    match afpacket::run_rtt_workload(&cfg) {
        Err(AfPacketError::Unimplemented) => {}
        other => panic!("expected AfPacketError::Unimplemented, got {other:?}"),
    }
}

#[test]
fn afpacket_validate_config_rejects_malformed_inputs() {
    // Each field gets an isolated failure test in the module-side unit
    // tests; here we sanity-check the public validator is exposed.
    let ok = AfPacketConfig {
        iface: "ens6",
        peer_ip_host_order: 0x0A00_002A,
        peer_port: 10_001,
        request_bytes: 128,
        response_bytes: 128,
        warmup: 10,
        iterations: 100,
    };
    assert!(afpacket::validate_config(&ok).is_ok());

    let bad = AfPacketConfig { iface: "", ..ok };
    assert!(afpacket::validate_config(&bad).is_err());
}

#[test]
fn afpacket_min_frame_len_matches_ethernet_plus_min_ip_tcp() {
    // Ethernet II (14) + IPv4 min (20) + TCP min (20) = 54.
    assert_eq!(afpacket::min_frame_len(), 54);
}

// ---------------------------------------------------------------------------
// Mode B — wire-diff. T9 lands the full runner; T8's stub assertion is
// replaced with invariant checks on the public API surface + the
// dimensions tag so bench-report groups rfc_compliance rows cleanly.
// ---------------------------------------------------------------------------

#[test]
fn mode_wire_diff_dimensions_json_tags_preset_and_mode() {
    let dims = mode_wire_diff::build_dimensions_json(
        std::path::Path::new("/tmp/local.pcap"),
        std::path::Path::new("/tmp/peer.pcap"),
    );
    let parsed: serde_json::Value = serde_json::from_str(&dims).unwrap();
    assert_eq!(parsed["preset"], "rfc_compliance");
    assert_eq!(parsed["mode"], "wire_diff");
    assert_eq!(parsed["local_pcap"], "local.pcap");
    assert_eq!(parsed["peer_pcap"], "peer.pcap");
}

#[test]
fn mode_wire_diff_preset_builder_flips_five_fields() {
    // Mode B's engine must run with preset=rfc_compliance — verify the
    // builder flips the exact five fields `apply_preset(1, ...)`
    // documents in crates/dpdk-net/src/lib.rs:30.
    let cfg = mode_wire_diff::build_engine_config_rfc_compliance(
        0x0A00_0001, // 10.0.0.1
        0x0A00_00FE, // 10.0.0.254
    )
    .expect("preset apply must succeed");
    assert!(cfg.tcp_nagle);
    assert!(cfg.tcp_delayed_ack);
    assert_eq!(cfg.cc_mode, 1);
    assert_eq!(cfg.tcp_min_rto_us, 200_000);
    assert_eq!(cfg.tcp_initial_rto_us, 1_000_000);
}

#[test]
fn mode_wire_diff_missing_pcaps_surface_as_bail() {
    // A mode-B run with non-existent pcap paths must fail cleanly
    // (not panic, not silently emit empty CSV).
    let tmp = std::env::temp_dir().join("bench-vs-linux-t9-does-not-exist");
    let _ = std::fs::remove_file(&tmp); // best-effort cleanup
    let out = std::env::temp_dir().join("bench-vs-linux-t9-out.csv");
    let metadata = dummy_metadata();
    let err = mode_wire_diff::run_mode_wire_diff_from_paths(
        tmp.clone(),
        tmp.clone(),
        out,
        "bench-vs-linux",
        "rfc-compliance",
        &metadata,
    )
    .unwrap_err();
    let s = format!("{err:#}");
    assert!(s.contains("reading"), "expected an io-style error: {s}");
}

fn dummy_metadata() -> bench_common::run_metadata::RunMetadata {
    bench_common::run_metadata::RunMetadata {
        run_id: uuid::Uuid::nil(),
        run_started_at: "2026-04-21T00:00:00Z".into(),
        commit_sha: String::new(),
        branch: String::new(),
        host: String::new(),
        instance_type: String::new(),
        cpu_model: String::new(),
        dpdk_version: String::new(),
        kernel: String::new(),
        nic_model: String::new(),
        nic_fw: String::new(),
        ami_id: String::new(),
        precondition_mode: bench_common::preconditions::PreconditionMode::Lenient,
        preconditions: bench_common::preconditions::Preconditions::default(),
    }
}

// ---------------------------------------------------------------------------
// mode_rtt dimensions_json shape.
// ---------------------------------------------------------------------------

#[test]
fn mode_rtt_dimensions_json_tags_preset_mode_stack() {
    for stack in [Stack::DpdkNet, Stack::LinuxKernel, Stack::AfPacket] {
        let dims = mode_rtt::build_dimensions_json(stack);
        let parsed: serde_json::Value = serde_json::from_str(&dims).unwrap();
        assert_eq!(parsed["preset"], "latency");
        assert_eq!(parsed["mode"], "rtt");
        assert_eq!(parsed["stack"], stack.as_dimension());
    }
}

#[test]
fn mode_rtt_dimensions_json_is_deterministic() {
    // Deterministic output is required — bench-report groups by the
    // verbatim string, so a reordered JSON would fragment aggregates.
    let a = mode_rtt::build_dimensions_json(Stack::DpdkNet);
    let b = mode_rtt::build_dimensions_json(Stack::DpdkNet);
    assert_eq!(a, b);
}
