//! AD-A7-no-syn-ack-retransmit promotion (A8 S1(a) / T11).
//!
//! A7 left `emit_syn_ack_for_passive` as a one-shot emit with no timer
//! arm (see docs/superpowers/reviews/phase-a7-rfc-compliance.md
//! AD-A7-no-syn-ack-retransmit and docs/superpowers/reviews/phase-a7-
//! mtcp-compare.md AD-3). RFC 9293 §3.8.1 + RFC 6298 §2 require
//! retransmit-on-RTO for SYN-ACK just like SYN. T11 wires the existing
//! `SynRetrans` timer wheel (which the active-open path already uses)
//! for the passive side.
//!
//! Two scenarios:
//!
//! Scenario 1: listen → peer SYN → engine emits SYN-ACK → peer never
//! ACKs → virt-clock advances past RTO → engine retransmits SYN-ACK
//! (same shape as the first emission). `tcp.tx_retrans` counter bumps.
//!
//! Scenario 2: same setup but the peer stays silent indefinitely. We
//! exhaust the SYN-retransmit budget (same hardcoded `> 3` cap used by
//! active-open; shared budget). Conn transitions to Closed;
//! `tcp.conn_timeout_syn_sent` bumps; an `Error{err=-ETIMEDOUT}` event
//! is pushed so the application can observe the failure.

#![cfg(feature = "test-server")]

mod common;

use std::sync::atomic::Ordering;

use common::{build_tcp_syn, parse_syn_ack, CovHarness, OUR_IP, PEER_IP};
use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::tcp_events::InternalEvent;
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

/// Drive listen → inject peer SYN → expect SYN-ACK on the wire. Returns
/// the `(listen_handle, our_iss)` pair so follow-up assertions can match
/// the retransmit's shape against the original.
fn do_listen_then_peer_syn(h: &mut CovHarness) -> (dpdk_net_core::test_server::ListenHandle, u32) {
    let listen_h = h.eng.listen(OUR_IP, 5555).expect("listen");
    // Drain any lingering TX from previous scenarios.
    let _ = drain_tx_frames();
    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, 40_000, OUR_IP, 5555, 0x10000000, 1460);
    h.eng.inject_rx_frame(&syn).expect("inject peer SYN");
    let tx = drain_tx_frames();
    assert_eq!(tx.len(), 1, "exactly one SYN-ACK expected");
    let (our_iss, _ack) = parse_syn_ack(&tx[0]).expect("parse SYN-ACK");
    (listen_h, our_iss)
}

/// Default engine `tcp_initial_rto_us` is 5_000 µs = 5 ms = 5_000_000 ns.
const INITIAL_RTO_NS: u64 = 5_000_000;

#[test]
fn passive_syn_ack_retransmits_on_missing_final_ack() {
    let mut h = CovHarness::new();
    let (_listen_h, our_iss_first) = do_listen_then_peer_syn(&mut h);

    // Advance virt clock past the initial RTO. We seeded the listen at
    // t=1 ms; fire deadline = 1 ms + 5 ms = 6 ms. Jump to 7 ms with
    // margin.
    set_virt_ns(1_000_000 + INITIAL_RTO_NS + 1_000_000);
    let _ = h.eng.pump_timers(1_000_000 + INITIAL_RTO_NS + 1_000_000);

    let tx2 = drain_tx_frames();
    assert_eq!(
        tx2.len(),
        1,
        "expected exactly one SYN-ACK retransmit after RTO; got {} frames",
        tx2.len()
    );
    let (our_iss_retrans, _ack_retrans) =
        parse_syn_ack(&tx2[0]).expect("parse retransmitted SYN-ACK");
    assert_eq!(
        our_iss_retrans, our_iss_first,
        "retransmit must carry identical ISS to first emission"
    );

    // Counter check: tx_retrans bumped by 1 (per-retransmit semantics
    // shared with active-open + data-RTO paths).
    let tx_retrans = h
        .eng
        .counters()
        .tcp
        .tx_retrans
        .load(Ordering::Relaxed);
    assert_eq!(
        tx_retrans, 1,
        "tcp.tx_retrans must bump once on SYN-ACK retransmit; got {tx_retrans}"
    );
}

#[test]
fn passive_syn_ack_retransmit_budget_exhaust_emits_etimedout() {
    let mut h = CovHarness::new();
    let (_listen_h, _our_iss) = do_listen_then_peer_syn(&mut h);

    // Budget semantics match active-open: initial SYN-ACK + 3 retransmits,
    // the 4th fire crosses the budget and transitions the conn to
    // ETIMEDOUT (engine.rs ~2752: `if new_count > 3`). Backoff doubles
    // each fire — 5ms, 10ms, 20ms, 40ms — so 100ms covers the full
    // budget window with margin. We pump at 1 ms granularity (well under
    // the timer wheel's 20.48 ms advance cap) and let each fire land.
    for i in 2..=200 {
        let now_ns = (i as u64) * 1_000_000; // 2 ms → 200 ms, step 1 ms
        set_virt_ns(now_ns);
        let _ = h.eng.pump_timers(now_ns);
        let _ = drain_tx_frames();
    }

    // Assertion 1: conn_timeout_syn_sent bumped. The SynRetrans fire
    // handler's `> 3` budget-exhaust arm bumps this counter before
    // calling `force_close_etimedout` — shared with active-open.
    let timeout_count = h
        .eng
        .counters()
        .tcp
        .conn_timeout_syn_sent
        .load(Ordering::Relaxed);
    assert!(
        timeout_count >= 1,
        "tcp.conn_timeout_syn_sent must bump on passive SYN-ACK budget exhaust; got {timeout_count}"
    );

    // Assertion 2: an Error{err=-ETIMEDOUT} event was emitted (so the
    // application can observe the failure). `force_close_etimedout`
    // pushes it via `InternalEvent::Error` with `err = -libc::ETIMEDOUT`.
    let mut saw_etimedout = false;
    h.eng.drain_events(64, |ev, _eng| {
        if let InternalEvent::Error { err, .. } = ev {
            if *err == -libc::ETIMEDOUT {
                saw_etimedout = true;
            }
        }
    });
    assert!(
        saw_etimedout,
        "expected an Error{{err=-ETIMEDOUT}} event after passive SYN-ACK budget exhaust"
    );
}
