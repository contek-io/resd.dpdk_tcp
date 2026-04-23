//! A8.5 T2: integration tests for the tcpreq options probes
//! (RFC 9293 §3.1 MUST-4 / MUST-6 / MUST-7).
//!
//! Three probes, three MUST clauses:
//!   - MUST-4 (option_support): EOL + NOP + MSS MUST be supported.
//!   - MUST-6 (unknown_option): unknown option kinds MUST be ignored.
//!   - MUST-7 (illegal_length): illegal option lengths MUST not crash.
//!
//! Ported from tcpreq/tests/options.py (OptionSupportTest,
//! UnknownOptionTest, IllegalLengthOptionTest). Share the crate-wide
//! `ENGINE_SERIALIZE` serialization Mutex so cargo-test's parallel
//! workers can't race on DPDK mempool-name collisions.
#[test]
fn option_support_all_three() {
    let r = tcpreq_runner::probes::options::option_support();
    assert!(
        matches!(r.status, tcpreq_runner::ProbeStatus::Pass),
        "OptionSupportTest must PASS; got {r:?}"
    );
    assert_eq!(r.clause_id, "MUST-4");
}

#[test]
fn unknown_option_ignored() {
    let r = tcpreq_runner::probes::options::unknown_option();
    assert!(
        matches!(r.status, tcpreq_runner::ProbeStatus::Pass),
        "UnknownOptionTest must PASS; got {r:?}"
    );
    assert_eq!(r.clause_id, "MUST-6");
}

#[test]
fn illegal_length_option_handled() {
    let r = tcpreq_runner::probes::options::illegal_length();
    assert!(
        matches!(r.status, tcpreq_runner::ProbeStatus::Pass),
        "IllegalLengthOptionTest must PASS; got {r:?}"
    );
    assert_eq!(r.clause_id, "MUST-7");
}
