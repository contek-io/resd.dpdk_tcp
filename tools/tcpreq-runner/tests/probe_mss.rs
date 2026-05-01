//! A8 T19: integration test for the MissingMSS (MUST-15) + LateOption
//! (MUST-5) probes. Each test constructs a fresh `TcpreqHarness` via the
//! probe body itself, drives the probe to completion, and asserts
//! `ProbeStatus::Pass` against the current A8 engine.
//!
//! The harness's internal serialization Mutex (crate-wide `ENGINE_SERIALIZE`)
//! funnels parallel cargo-test workers so the two probes cannot race on
//! DPDK mempool-name collisions during `Engine::new`.

use tcpreq_runner::probes::mss::{late_option, missing_mss, mss_support};
use tcpreq_runner::ProbeStatus;

#[test]
fn missing_mss_passes_on_a8_engine() {
    let r = missing_mss();
    assert_eq!(r.clause_id, "MUST-15");
    assert_eq!(r.probe_name, "MissingMSS");
    assert!(
        matches!(r.status, ProbeStatus::Pass),
        "MissingMSS must pass on A8 engine; got {:?}",
        r
    );
}

#[test]
fn late_option_passes_on_a8_engine() {
    let r = late_option();
    assert_eq!(r.clause_id, "MUST-5");
    assert_eq!(r.probe_name, "LateOption");
    assert!(
        matches!(r.status, ProbeStatus::Pass),
        "LateOption must pass on A8 engine; got {:?}",
        r
    );
}

#[test]
fn mss_support_bidirectional() {
    let r = mss_support();
    assert!(
        matches!(r.status, ProbeStatus::Pass),
        "MSSSupportTest must PASS; got {r:?}"
    );
    assert_eq!(r.clause_id, "MUST-14");
}
