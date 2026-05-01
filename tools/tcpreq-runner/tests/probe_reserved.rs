//! A8 T20: integration test for the Reserved-RX probe (RFC 9293 §3.1).
//!
//! Constructs a fresh `TcpreqHarness` via the probe body itself, drives
//! the probe to completion, and asserts `ProbeStatus::Pass` against the
//! current A8 engine. The harness's crate-wide `ENGINE_SERIALIZE` Mutex
//! funnels parallel cargo-test workers so this probe cannot race on
//! DPDK mempool-name collisions during `Engine::new`.

use tcpreq_runner::probes::reserved::reserved_rx;
use tcpreq_runner::ProbeStatus;

#[test]
fn reserved_bits_ignored_on_rx() {
    let r = reserved_rx();
    assert_eq!(r.clause_id, "Reserved-RX");
    assert_eq!(r.probe_name, "ReservedBitsRx");
    assert!(
        matches!(r.status, ProbeStatus::Pass),
        "Reserved-RX must pass on A8 engine; got {:?}",
        r
    );
}
