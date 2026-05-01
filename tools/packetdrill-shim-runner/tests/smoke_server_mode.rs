#![cfg(feature = "test-server")]
//! A8 T15 S2 smoke: a ligurio listen-incoming-* script now runs end-to-end.
//!
//! Pre-S2 the shim's inject/drain paths sent frames with the engine's
//! fixed test IPs (10.99.2.x), but packetdrill generates frames using its
//! own per-script live_local_ip / live_remote_ip (defaults to
//! 192.168.x.x/192.0.2.1). The engine silently dropped the mismatched
//! inbound frames, so every `listen()`-based script timed out at the
//! first expected outbound segment.
//!
//! Post-S2 the shim rewrites IP headers at the boundary so packetdrill's
//! script IPs line up with the engine's configured IPs, and the server
//! lifecycle (listen, accept, SYN->SYN-ACK->ACK, close) now completes
//! end-to-end. This smoke test pins one ligurio listen-incoming script
//! as the S2 canary.

use std::path::PathBuf;

use packetdrill_shim_runner::invoker;

#[test]
fn listen_incoming_syn_ack_script_runs() {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    assert!(
        bin.exists(),
        "shim binary missing at {}; run tools/packetdrill-shim/build.sh",
        bin.display()
    );
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../third_party/packetdrill-testcases/testcases/tcp/listen/listen-incoming-syn-ack.pkt",
    );
    assert!(script.exists(), "ligurio script missing at {}", script.display());
    let out = invoker::run_script(&bin, &script);
    assert_eq!(
        out.exit, 0,
        "listen-incoming-syn-ack.pkt expected exit 0; got exit={}\nstdout:\n{}\nstderr:\n{}",
        out.exit, out.stdout, out.stderr
    );
}
