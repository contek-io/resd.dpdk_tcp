//! A8.5 T4: integration test for the RstAckTest probe (RFC 9293 §3.10.7
//! Reset processing).
//!
//! Ported from tcpreq/tests/rst_ack.py::RstAckTest. The probe exercises
//! two scenarios in one run:
//!   A. Plain RST|ACK in ESTABLISHED — conn closes and `tcp.rx_rst`
//!      bumps by exactly 1.
//!   B. RST|ACK|URG in ESTABLISHED — still processed as RST (flags are
//!      independent), `tcp.rx_rst` bumps by another 1.
//!
//! The Spec §1.1 A invariant "RST is processed independently of other
//! flags" is the load-bearing assertion — if scenario B fails while A
//! passes, the engine is rejecting RST when URG is co-set, which is a
//! real Reset-Processing gap at `tcp_input.rs::handle_established`.
//!
//! The harness's crate-wide `ENGINE_SERIALIZE` Mutex funnels parallel
//! cargo-test workers so this probe cannot race on DPDK mempool-name
//! collisions during `Engine::new`.

#[test]
fn rst_ack_processing_independent() {
    let r = tcpreq_runner::probes::rst_ack::rst_ack_processing();
    assert!(
        matches!(r.status, tcpreq_runner::ProbeStatus::Pass),
        "RstAckTest must PASS; got {r:?}"
    );
    assert_eq!(r.clause_id, "Reset-Processing");
}
