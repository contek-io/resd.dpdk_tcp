//! A8 Task 10: M1 observability smoke test — Stage 1 ship-gate
//! counter-drift tripwire.
//!
//! Single scripted scenario: connect → 3WHS → 4 sends (one RTO-
//! retransmitted) → active close → 2×MSL reap. Exhaustive assertions
//! over every declared `AtomicU64` counter (exact value; non-listed
//! MUST be 0), every reached cell of `tcp.state_trans[11][11]`, and
//! event emission order.
//!
//! **Fail-loud tripwire.** The final assertion walks every name in
//! `ALL_COUNTER_NAMES`; any counter not in `EXPECTED_COUNTERS` must
//! read zero. Removing any `fetch_add` across the stack's scenario
//! path drops a pinned value — test fails. Adding a stray bump in
//! the scenario path raises a value or introduces a non-zero counter
//! that isn't in the expected table — test fails. Either direction
//! breaks this test loudly, which is the point.
//!
//! Expected values were calibrated during T10 implementation via a
//! (now-removed) `obs_smoke_dump_actual_counters` diagnostic helper
//! that ran the scenario and emitted every non-zero counter +
//! state-trans cell to stderr. Values below reflect the observed
//! baseline on the default-features build.
//!
//! **Events.** The scenario runs with `tcp_per_packet_events` at its
//! default (OFF), so `TcpRetrans` / `TcpLossDetected` events are NOT
//! emitted on the RTO retransmit. The expected event list covers only
//! state-change + lifecycle events (Connected, StateChange, Closed,
//! Writable).

#![cfg(feature = "test-server")]

mod common;
use common::CovHarness;
use dpdk_net_core::counters::{lookup_counter, ALL_COUNTER_NAMES};
use dpdk_net_core::tcp_events::InternalEvent;
use dpdk_net_core::tcp_state::TcpState;
use std::collections::HashMap;
use std::sync::atomic::Ordering;

#[test]
fn obs_smoke_scripted_scenario() {
    let mut h = CovHarness::new();
    let conn = h.obs_do_active_open();
    h.run_obs_smoke_scenario(conn);

    // Drain events after the scenario so we can assert over the sequence.
    let mut events: Vec<InternalEvent> = Vec::new();
    h.eng
        .drain_events(256, |ev, _| events.push(ev.clone()));

    assert_expected_counters(&h);
    assert_expected_state_trans(&h);
    assert_expected_events(&events, conn);
    assert_no_unexpected_counters(&h);
}

/// `(counter-path, expected-exact-value)` for every counter the M1
/// scenario exercises. Pinned during T10 implementation via a
/// diagnostic helper (now removed) — any code change that drifts a
/// value fails the test. Counters NOT in this list must be zero
/// (enforced by `assert_no_unexpected_counters`).
///
/// Expected frame flow:
///   TX (9): SYN, final-3WHS-ACK, 4 data, 1 retrans, FIN, ACK-of-peer-FIN
///   RX (6): SYN-ACK, 4 cum-ACKs, peer FIN+ACK (combined — peer's FIN
///           ACKs our FIN in one frame, so FinWait1 → TimeWait is direct)
///
/// `eth.offload_missing_rx_timestamp = 1` is a one-shot at Engine::new
/// on ENA (expected steady state; pinned here per spec §10.5).
/// `obs.events_queue_high_water = 7` is the latched max queue depth
/// observed during the scenario.
static EXPECTED_COUNTERS: &[(&str, u64)] = &[
    // --- eth.* ---
    ("eth.rx_pkts", 6),
    ("eth.rx_bytes", 328),
    ("eth.tx_pkts", 9),
    ("eth.tx_bytes", 586),
    ("eth.offload_missing_rx_timestamp", 1), // engine bring-up one-shot
    // --- ip.* ---
    ("ip.rx_tcp", 6),
    // --- tcp.* lifecycle ---
    ("tcp.rx_syn_ack", 1),
    ("tcp.tx_syn", 1),
    // tx_ack: 1 final-3WHS-ACK + 1 ACK-of-peer-FIN (data-seg ACK bit is
    // carried on the data frame, no separate tx_ack bump per send).
    ("tcp.tx_ack", 2),
    // rx_ack: SYN-ACK + 4 cum-ACKs + peer FIN+ACK = 6 (every non-SYN
    // segment from a live peer carries the ACK bit).
    ("tcp.rx_ack", 6),
    ("tcp.rx_fin", 1),
    ("tcp.tx_fin", 1),
    // tx_data: 4 original sends. The RTO retransmit bumps tx_retrans,
    // NOT tx_data (separate code path in engine).
    ("tcp.tx_data", 4),
    ("tcp.tx_retrans", 1),
    ("tcp.tx_rto", 1),
    ("tcp.conn_open", 1),
    ("tcp.conn_close", 1),
    ("tcp.conn_time_wait_reaped", 1),
    // --- tcp.* RTT + flush ---
    // rtt_samples: 3 observed (SYN-ACK handshake + 2 of the 4 cum-ACKs
    // satisfy the RTT sampling gates; the others are rejected by the
    // "one sample per RTT" throttle or Karn's rule around the retrans).
    ("tcp.rtt_samples", 3),
    // tx_flush_bursts: 4 calls to flush_tx_pending_data under the 4
    // send-and-flush cycles. The RTO retransmit fires tx_burst inline
    // via tx_tcp_frame (not drain_tx_pending_data) so it doesn't bump.
    ("tcp.tx_flush_bursts", 4),
    // tx_flush_batched_pkts: summed `sent` across those 4 bursts. Each
    // burst carried 1 data mbuf at push time, but the 3rd flush also
    // included the next-segment-push path's prior queued mbuf, so the
    // total is 5.
    ("tcp.tx_flush_batched_pkts", 5),
    // --- obs.* ---
    // Latched max observed queue depth. 7 reflects the peak depth at
    // the 2×MSL reap point (multiple StateChange events pile up before
    // this test calls drain_events).
    ("obs.events_queue_high_water", 7),
    // poll.* — poll_once never invoked in test-server mode.
    // obs.events_dropped — queue never overflowed.
];

/// Feature-gated expected counters — only non-empty when the
/// corresponding compile-time feature is enabled. Appended to
/// `EXPECTED_COUNTERS` via `expected_counter_map()` so the fail-loud
/// walk covers the extra entries under their feature.
///
/// `tcp.tx_payload_bytes` (obs-byte-counters): 4 sends × 16 bytes = 64.
/// `tcp.rx_payload_bytes` stays 0 because the peer sends only ACK /
/// FIN (no data payload).
static EXPECTED_COUNTERS_OBS_BYTE: &[(&str, u64)] = &[
    #[cfg(feature = "obs-byte-counters")]
    ("tcp.tx_payload_bytes", 64),
];

fn expected_counter_map() -> HashMap<&'static str, u64> {
    let mut m: HashMap<&str, u64> = EXPECTED_COUNTERS.iter().copied().collect();
    m.extend(EXPECTED_COUNTERS_OBS_BYTE.iter().copied());
    m
}

/// `(from_state, to_state, expected_count)` for every reached cell of
/// the 11×11 state_trans matrix. Cells not listed MUST be zero
/// (enforced by `assert_expected_state_trans`).
///
/// Expected trajectory: Closed(0) → SynSent(2) → Established(4) →
/// FinWait1(5) → TimeWait(10) → Closed(0). Note the direct 5→10 edge
/// (no FinWait2): our `obs_peer_fin_and_ack_our_fin` helper carries
/// both peer's FIN and ACK-of-our-FIN in one frame, so FinWait1 takes
/// the `fin_acked && peer_fin` branch straight to TimeWait per
/// RFC 9293 §3.10.7.4. M=5 state transitions total.
static EXPECTED_STATE_TRANS: &[(usize, usize, u64)] = &[
    (0, 2, 1),  // Closed → SynSent (active-open connect)
    (2, 4, 1),  // SynSent → Established (SYN-ACK + final ACK)
    (4, 5, 1),  // Established → FinWait1 (our close_conn)
    (5, 10, 1), // FinWait1 → TimeWait (peer FIN+ACK combined)
    (10, 0, 1), // TimeWait → Closed (2×MSL reap)
];

fn assert_expected_counters(h: &CovHarness) {
    for (name, expected) in expected_counter_map() {
        let atomic = lookup_counter(h.eng.counters(), name)
            .unwrap_or_else(|| panic!("unknown counter in table: {name}"));
        let got = atomic.load(Ordering::Relaxed);
        assert_eq!(
            got, expected,
            "counter {name}: expected {expected}, got {got}"
        );
    }
}

fn assert_expected_state_trans(h: &CovHarness) {
    let ctrs = h.eng.counters();
    for (from, to, expected) in EXPECTED_STATE_TRANS {
        let got = ctrs.tcp.state_trans[*from][*to].load(Ordering::Relaxed);
        assert_eq!(
            got, *expected,
            "state_trans[{from}][{to}]: expected {expected}, got {got}"
        );
    }
    // Catch-all: any cell not listed must be zero.
    for from in 0..11usize {
        for to in 0..11usize {
            if EXPECTED_STATE_TRANS
                .iter()
                .any(|(f, t, _)| *f == from && *t == to)
            {
                continue;
            }
            let v = ctrs.tcp.state_trans[from][to].load(Ordering::Relaxed);
            assert_eq!(
                v, 0,
                "unexpected state_trans[{from}][{to}] = {v} (not in EXPECTED_STATE_TRANS)"
            );
        }
    }
}

/// Walk the drained event list + verify each expected kind/conn pair
/// appears in order. Extra events between expected-list elements are
/// tolerated ONLY if they match a known "acceptable interstitial" set
/// (empty for this scenario — state-change + lifecycle only). The
/// event list from `drain_events` reflects final order in the engine's
/// FIFO queue (emit-time order).
fn assert_expected_events(
    events: &[InternalEvent],
    conn: dpdk_net_core::flow_table::ConnHandle,
) {
    // Expected event sequence (observed order in the FIFO queue):
    //   [0] StateChange Closed      → SynSent      (connect())
    //   [1] StateChange SynSent     → Established  (SYN-ACK handling)
    //   [2] Connected                               (3WHS completes)
    //   [3] StateChange Established → FinWait1     (our close_conn)
    //   [4] StateChange FinWait1    → TimeWait     (peer FIN+ACK combined)
    //   [5] StateChange TimeWait    → Closed       (2×MSL reap)
    //   [6] Closed                                  (reap also emits Closed)
    //
    // Exact length pinned below; drift in event-emission policy breaks
    // this test together with EXPECTED_COUNTERS / EXPECTED_STATE_TRANS.

    assert_eq!(
        events.len(),
        7,
        "expected 7 events in FIFO, got {} — sequence: {events:?}",
        events.len()
    );

    // Assert each event's conn matches `conn` (single-conn scenario).
    for (i, ev) in events.iter().enumerate() {
        let ev_conn = match ev {
            InternalEvent::Connected { conn: c, .. } => *c,
            InternalEvent::StateChange { conn: c, .. } => *c,
            InternalEvent::Closed { conn: c, .. } => *c,
            InternalEvent::Readable { conn: c, .. } => *c,
            InternalEvent::Writable { conn: c, .. } => *c,
            InternalEvent::Error { conn: c, .. } => *c,
            InternalEvent::TcpRetrans { conn: c, .. } => *c,
            InternalEvent::TcpLossDetected { conn: c, .. } => *c,
            InternalEvent::ApiTimer { .. } => {
                panic!("unexpected ApiTimer event at [{i}]: {ev:?}");
            }
        };
        assert_eq!(
            ev_conn, conn,
            "event[{i}] conn mismatch: got {ev_conn}, expected {conn} — ev: {ev:?}"
        );
    }

    // Assert the ordered state-change chain.
    let state_changes: Vec<(TcpState, TcpState)> = events
        .iter()
        .filter_map(|ev| match ev {
            InternalEvent::StateChange { from, to, .. } => Some((*from, *to)),
            _ => None,
        })
        .collect();
    let expected_chain = vec![
        (TcpState::Closed, TcpState::SynSent),
        (TcpState::SynSent, TcpState::Established),
        (TcpState::Established, TcpState::FinWait1),
        (TcpState::FinWait1, TcpState::TimeWait),
        (TcpState::TimeWait, TcpState::Closed),
    ];
    assert_eq!(
        state_changes, expected_chain,
        "state-change event sequence mismatch"
    );

    // Assert Connected + Closed event counts (lifecycle bookends).
    let connected_count = events
        .iter()
        .filter(|ev| matches!(ev, InternalEvent::Connected { .. }))
        .count();
    assert_eq!(
        connected_count, 1,
        "expected exactly one Connected event, got {connected_count}"
    );
    let closed_count = events
        .iter()
        .filter(|ev| matches!(ev, InternalEvent::Closed { .. }))
        .count();
    assert_eq!(
        closed_count, 1,
        "expected exactly one Closed event, got {closed_count}"
    );
}

fn assert_no_unexpected_counters(h: &CovHarness) {
    let expected = expected_counter_map();
    for name in ALL_COUNTER_NAMES {
        let atomic = lookup_counter(h.eng.counters(), name)
            .unwrap_or_else(|| panic!("unknown counter path: {name}"));
        let got = atomic.load(Ordering::Relaxed);
        let want = expected.get(name).copied().unwrap_or(0);
        assert_eq!(
            got, want,
            "fail-loud: counter {name} = {got}, expected {want} \
             (if intentional, add to EXPECTED_COUNTERS with the expected value)"
        );
    }
}

