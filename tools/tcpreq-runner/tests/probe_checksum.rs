//! A8.5 T1: integration test for the ZeroChecksum probe (RFC 9293 §3.1
//! MUST-2/3).
//!
//! Ported from tcpreq/tests/checksum.py::ZeroChecksumTest. The probe
//! injects a SYN whose TCP checksum field has been zeroed and asserts
//! the engine drops the segment: no SYN-ACK emitted and
//! `tcp.rx_bad_csum` bumps by exactly 1. This pins the Layer-A
//! equivalence claim for MUST-2/3 — if the engine were to accept the
//! zero-csum segment, the claim recorded in SKIPPED.md would be wrong
//! and the regression must be fixed at
//! `crates/dpdk-net-core/src/l3_ip.rs` rather than by relaxing this
//! test.
//!
//! The harness's crate-wide `ENGINE_SERIALIZE` Mutex funnels parallel
//! cargo-test workers so this probe cannot race on DPDK mempool-name
//! collisions during `Engine::new`.

use tcpreq_runner::probes::checksum::zero_checksum;
use tcpreq_runner::ProbeStatus;

#[test]
fn zero_checksum_syn_rejected() {
    let r = zero_checksum();
    assert_eq!(r.clause_id, "MUST-2/3");
    assert_eq!(r.probe_name, "ZeroChecksum");
    assert!(
        matches!(r.status, ProbeStatus::Pass),
        "ZeroChecksumTest must PASS — engine must drop zero-csum SYN; got {:?}",
        r
    );
}
