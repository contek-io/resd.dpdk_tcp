//! Spec §5.2 + §5.3: observation primitives.
//!
//! Three exports:
//!   1. [`EventRing`] — bounded, oldest-evicted ring buffer for the last
//!      `EVENT_RING_CAPACITY` events drained during the assertion
//!      window. Used by the failure bundle.
//!   2. [`FailureReason`] — the verdict's failure-discriminant enum,
//!      with `serde::Serialize` for the JSON failure bundle.
//!   3. `observe_batch` (lands in Task 5) — the per-batch poll + event
//!      replay + RX-mempool-floor + per-batch obs.events_dropped check.

use std::collections::VecDeque;

use serde::Serialize;

use dpdk_net_core::tcp_events::InternalEvent;
use dpdk_net_core::tcp_state::TcpState;

use crate::assertions::Relation;

/// Spec §5.4 constants. `MAX_DRAIN_PER_BATCH` matches `EVENT_RING_CAPACITY`
/// so a worst-case full drain still fits the ring without truncating.
pub const EVENT_RING_CAPACITY: usize = 256;
pub const MAX_DRAIN_PER_BATCH: u32 = EVENT_RING_CAPACITY as u32;

/// Bounded ring buffer of last-N events for the failure bundle. Pushes
/// past capacity evict the oldest entry; the `truncated` flag records
/// whether any eviction occurred during the run, so the bundle can
/// disclose that the window is partial.
#[derive(Debug, Default)]
pub struct EventRing {
    buf: VecDeque<EventRecord>,
    next_seq: usize,
    truncated: bool,
}

/// Captured event with the runner-side ordinal at the moment of capture.
/// `ord` is the runner sequence number (not the engine's `emitted_ts_ns`)
/// so consumers can correlate IllegalTransition's `at_event_idx` against
/// a specific record.
#[derive(Debug, Clone, Serialize)]
pub struct EventRecord {
    pub ord: usize,
    pub kind: EventKind,
    pub conn_idx: u32,
    pub emitted_ts_ns: u64,
    /// Populated on `StateChange` only; otherwise `None`.
    pub from: Option<TcpStateName>,
    /// Populated on `StateChange` only; otherwise `None`.
    pub to: Option<TcpStateName>,
    /// Populated on `Error` / `Closed` only.
    pub err: Option<i32>,
    /// Populated on `TcpRetrans` only.
    pub seq: Option<u32>,
}

/// JSON-friendly event kind discriminator. Only the subset we serialise
/// for the failure bundle; non-observed variants land under `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum EventKind {
    Connected,
    StateChange,
    Closed,
    Error,
    TcpRetrans,
    TcpLossDetected,
    Other,
}

/// `serde::Serialize`-friendly TcpState alias. Mirrors `TcpState::name`
/// (`tcp_state.rs:31`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TcpStateName {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl From<TcpState> for TcpStateName {
    fn from(s: TcpState) -> Self {
        match s {
            TcpState::Closed => Self::Closed,
            TcpState::Listen => Self::Listen,
            TcpState::SynSent => Self::SynSent,
            TcpState::SynReceived => Self::SynReceived,
            TcpState::Established => Self::Established,
            TcpState::FinWait1 => Self::FinWait1,
            TcpState::FinWait2 => Self::FinWait2,
            TcpState::CloseWait => Self::CloseWait,
            TcpState::Closing => Self::Closing,
            TcpState::LastAck => Self::LastAck,
            TcpState::TimeWait => Self::TimeWait,
        }
    }
}

impl EventRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Next ordinal to assign on push. Used by callers that want to
    /// record an `at_event_idx` for a failure reason before the event
    /// is actually pushed.
    pub fn next_seq(&self) -> usize {
        self.next_seq
    }

    /// Append an event. Evicts the oldest entry if at capacity and sets
    /// the `truncated` flag.
    pub fn push(&mut self, ev: &InternalEvent, ord: usize) {
        let rec = record_from_event(ev, ord);
        if self.buf.len() == EVENT_RING_CAPACITY {
            self.buf.pop_front();
            self.truncated = true;
        }
        self.buf.push_back(rec);
        self.next_seq = ord + 1;
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn iter(&self) -> impl Iterator<Item = &EventRecord> {
        self.buf.iter()
    }

    /// Drain into an owned Vec for failure-bundle serialisation. Leaves
    /// the ring empty but preserves the `truncated` flag.
    pub fn drain_into_vec(&mut self) -> Vec<EventRecord> {
        self.next_seq = 0;
        self.buf.drain(..).collect()
    }

    /// Snapshot the ring into a new owned ring with the same contents
    /// and truncated flag. Used by the bundle writer so the original
    /// `ScenarioResult` remains intact (the verdict still references
    /// failures that mention `at_event_idx` into this window).
    pub fn clone_for_bundle(&self) -> Self {
        Self {
            buf: self.buf.clone(),
            next_seq: self.next_seq,
            truncated: self.truncated,
        }
    }
}

fn record_from_event(ev: &InternalEvent, ord: usize) -> EventRecord {
    use InternalEvent as IE;
    match ev {
        IE::Connected { conn, emitted_ts_ns, .. } => EventRecord {
            ord,
            kind: EventKind::Connected,
            conn_idx: conn_to_idx(*conn),
            emitted_ts_ns: *emitted_ts_ns,
            from: None,
            to: None,
            err: None,
            seq: None,
        },
        IE::StateChange { conn, from, to, emitted_ts_ns } => EventRecord {
            ord,
            kind: EventKind::StateChange,
            conn_idx: conn_to_idx(*conn),
            emitted_ts_ns: *emitted_ts_ns,
            from: Some((*from).into()),
            to: Some((*to).into()),
            err: None,
            seq: None,
        },
        IE::Closed { conn, err, emitted_ts_ns } => EventRecord {
            ord,
            kind: EventKind::Closed,
            conn_idx: conn_to_idx(*conn),
            emitted_ts_ns: *emitted_ts_ns,
            from: None,
            to: None,
            err: Some(*err),
            seq: None,
        },
        IE::Error { conn, err, emitted_ts_ns } => EventRecord {
            ord,
            kind: EventKind::Error,
            conn_idx: conn_to_idx(*conn),
            emitted_ts_ns: *emitted_ts_ns,
            from: None,
            to: None,
            err: Some(*err),
            seq: None,
        },
        IE::TcpRetrans { conn, seq, emitted_ts_ns, .. } => EventRecord {
            ord,
            kind: EventKind::TcpRetrans,
            conn_idx: conn_to_idx(*conn),
            emitted_ts_ns: *emitted_ts_ns,
            from: None,
            to: None,
            err: None,
            seq: Some(*seq),
        },
        // `TcpLossDetected` carries `cause` + `conn` + `emitted_ts_ns` only;
        // the underlying segment seq isn't on the variant, so `seq` stays
        // `None` here.
        IE::TcpLossDetected { conn, emitted_ts_ns, .. } => EventRecord {
            ord,
            kind: EventKind::TcpLossDetected,
            conn_idx: conn_to_idx(*conn),
            emitted_ts_ns: *emitted_ts_ns,
            from: None,
            to: None,
            err: None,
            seq: None,
        },
        // The full set is enumerated in tcp_events.rs; for ones we do not
        // pattern-match on, fall through to `Other` so the failure bundle
        // still records that some event landed at this position. The
        // `_emitted_ts_ns` reach is best-effort: every InternalEvent
        // variant carries a `emitted_ts_ns` field per the engine's
        // observability contract; we extract zero on the fallthrough so
        // the bundle remains stable across future tcp_events additions.
        _ => EventRecord {
            ord,
            kind: EventKind::Other,
            conn_idx: 0,
            emitted_ts_ns: 0,
            from: None,
            to: None,
            err: None,
            seq: None,
        },
    }
}

fn conn_to_idx(conn: dpdk_net_core::flow_table::ConnHandle) -> u32 {
    // ConnHandle is currently `pub type ConnHandle = u32` (alias). The
    // `into()` is a no-op today; we keep it so a Stage-2 newtype migration
    // is a one-line change. See the `#[allow(clippy::useless_conversion)]`
    // below.
    #[allow(clippy::useless_conversion)]
    let raw: u32 = conn.into();
    raw
}

/// Per-scenario verdict.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail { failures: Vec<FailureReason> },
}

/// Failure discriminants surfaced in the verdict and JSON bundle.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum FailureReason {
    ConnectFailed { error: String },
    FsmDeparted { observed: Option<TcpStateName> },
    IllegalTransition { from: TcpStateName, to: TcpStateName, at_event_idx: usize },
    CounterRelation {
        counter: String,
        relation: String,
        observed_delta: i128,
        message: String,
    },
    DisjunctiveCounterRelation {
        counters: Vec<String>,
        relation: String,
        observed_deltas: Vec<i128>,
        message: String,
    },
    LiveCounterBelowMin {
        counter: &'static str,
        observed: u64,
        min: u64,
    },
    EventsDropped { count: u64 },
    WorkloadError { error: String },
}

impl FailureReason {
    /// Build a `CounterRelation` failure from the assertion-engine's
    /// inputs. Centralised so the message format stays consistent
    /// across call sites (delta-loop in `workload.rs`, side-check loop
    /// in `assertions.rs`).
    pub fn counter_relation(counter: &str, relation: Relation, delta: i128) -> Self {
        Self::CounterRelation {
            counter: counter.to_string(),
            relation: relation.to_string(),
            observed_delta: delta,
            message: format!(
                "{counter}: expected delta {relation}, got {delta}"
            ),
        }
    }

    pub fn disjunctive(
        counters: &[&str],
        relation: Relation,
        deltas: &[i128],
    ) -> Self {
        Self::DisjunctiveCounterRelation {
            counters: counters.iter().map(|s| (*s).to_string()).collect(),
            relation: relation.to_string(),
            observed_deltas: deltas.to_vec(),
            message: format!(
                "{counters:?}: expected at least one delta {relation}, got {deltas:?}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpdk_net_core::flow_table::ConnHandle;
    use dpdk_net_core::tcp_events::InternalEvent;

    fn synth_state_change(from: TcpState, to: TcpState) -> InternalEvent {
        InternalEvent::StateChange {
            conn: ConnHandle::from(0u32),
            from,
            to,
            emitted_ts_ns: 0,
        }
    }

    #[test]
    fn ring_starts_empty_with_zero_seq() {
        let r = EventRing::new();
        assert!(r.is_empty());
        assert_eq!(r.next_seq(), 0);
        assert!(!r.truncated());
    }

    #[test]
    fn ring_push_records_event_and_advances_seq() {
        let mut r = EventRing::new();
        let ev = synth_state_change(TcpState::Established, TcpState::FinWait1);
        r.push(&ev, 0);
        assert_eq!(r.len(), 1);
        assert_eq!(r.next_seq(), 1);
        let rec = r.iter().next().unwrap();
        assert_eq!(rec.ord, 0);
        assert_eq!(rec.kind, EventKind::StateChange);
        assert_eq!(rec.from, Some(TcpStateName::Established));
        assert_eq!(rec.to, Some(TcpStateName::FinWait1));
    }

    #[test]
    fn ring_evicts_oldest_at_capacity() {
        let mut r = EventRing::new();
        for i in 0..(EVENT_RING_CAPACITY + 50) {
            let ev = synth_state_change(TcpState::Established, TcpState::Established);
            r.push(&ev, i);
        }
        assert_eq!(r.len(), EVENT_RING_CAPACITY);
        assert!(r.truncated());
        // Oldest preserved is ord=50, newest is ord=305.
        let first = r.iter().next().unwrap();
        let last = r.iter().last().unwrap();
        assert_eq!(first.ord, 50);
        assert_eq!(last.ord, EVENT_RING_CAPACITY + 49);
    }

    #[test]
    fn failure_reason_counter_relation_serialises() {
        let f = FailureReason::counter_relation(
            "tcp.tx_retrans",
            Relation::LessOrEqualThan(10_000),
            51_234,
        );
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["kind"], "CounterRelation");
        assert_eq!(json["counter"], "tcp.tx_retrans");
        assert_eq!(json["relation"], "<=10000");
        assert_eq!(json["observed_delta"], 51234);
    }

    #[test]
    fn failure_reason_live_counter_below_min_serialises() {
        let f = FailureReason::LiveCounterBelowMin {
            counter: "tcp.rx_mempool_avail",
            observed: 12,
            min: 32,
        };
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["kind"], "LiveCounterBelowMin");
        assert_eq!(json["counter"], "tcp.rx_mempool_avail");
        assert_eq!(json["observed"], 12);
        assert_eq!(json["min"], 32);
    }

    #[test]
    fn failure_reason_illegal_transition_serialises() {
        let f = FailureReason::IllegalTransition {
            from: TcpStateName::Established,
            to: TcpStateName::CloseWait,
            at_event_idx: 178,
        };
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["kind"], "IllegalTransition");
        assert_eq!(json["from"], "ESTABLISHED");
        assert_eq!(json["to"], "CLOSE_WAIT");
        assert_eq!(json["at_event_idx"], 178);
    }

    #[test]
    fn verdict_pass_and_fail_serialise() {
        let pass = Verdict::Pass;
        let json = serde_json::to_value(&pass).unwrap();
        assert_eq!(json["verdict"], "pass");

        let fail = Verdict::Fail {
            failures: vec![FailureReason::EventsDropped { count: 5 }],
        };
        let json = serde_json::to_value(&fail).unwrap();
        assert_eq!(json["verdict"], "fail");
        assert_eq!(json["failures"][0]["kind"], "EventsDropped");
        assert_eq!(json["failures"][0]["count"], 5);
    }

    #[test]
    fn drain_into_vec_clears_ring_but_preserves_truncated_flag() {
        let mut r = EventRing::new();
        for i in 0..(EVENT_RING_CAPACITY + 1) {
            let ev = synth_state_change(TcpState::Established, TcpState::Established);
            r.push(&ev, i);
        }
        assert!(r.truncated());
        let drained = r.drain_into_vec();
        assert_eq!(drained.len(), EVENT_RING_CAPACITY);
        assert!(r.is_empty());
        assert!(r.truncated()); // flag preserved across drain
    }

    #[test]
    fn fsm_replay_passes_with_no_illegal_transitions() {
        let mut r = EventRing::new();
        let events = vec![
            synth_state_change(TcpState::Established, TcpState::Established),
        ];
        match fsm_replay_batch(Some(TcpState::Established), &events, &mut r) {
            ObserveOutcome::Ok => {}
            ObserveOutcome::Fail(f) => panic!("expected Ok, got {f:?}"),
        }
    }

    #[test]
    fn fsm_replay_fails_on_state_departure() {
        let mut r = EventRing::new();
        match fsm_replay_batch(Some(TcpState::CloseWait), &[], &mut r) {
            ObserveOutcome::Fail(FailureReason::FsmDeparted { observed }) => {
                assert_eq!(observed, Some(TcpStateName::CloseWait));
            }
            other => panic!("expected FsmDeparted, got {other:?}"),
        }
    }

    #[test]
    fn fsm_replay_fails_on_illegal_state_change() {
        let mut r = EventRing::new();
        let events = vec![synth_state_change(TcpState::Established, TcpState::CloseWait)];
        match fsm_replay_batch(Some(TcpState::Established), &events, &mut r) {
            ObserveOutcome::Fail(FailureReason::IllegalTransition { from, to, at_event_idx }) => {
                assert_eq!(from, TcpStateName::Established);
                assert_eq!(to, TcpStateName::CloseWait);
                assert_eq!(at_event_idx, 0);
            }
            other => panic!("expected IllegalTransition, got {other:?}"),
        }
    }

    #[test]
    fn fsm_replay_records_first_illegal_index_with_multiple_events() {
        let mut r = EventRing::new();
        let events = vec![
            synth_state_change(TcpState::Established, TcpState::Established),
            synth_state_change(TcpState::Established, TcpState::CloseWait),
            synth_state_change(TcpState::Established, TcpState::Established),
        ];
        match fsm_replay_batch(Some(TcpState::Established), &events, &mut r) {
            ObserveOutcome::Fail(FailureReason::IllegalTransition { at_event_idx, .. }) => {
                assert_eq!(at_event_idx, 1);
            }
            other => panic!("expected IllegalTransition at idx 1, got {other:?}"),
        }
    }

    #[test]
    fn rx_mempool_floor_passes_above_min() {
        match check_rx_mempool_floor(33) {
            ObserveOutcome::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        match check_rx_mempool_floor(32) {
            ObserveOutcome::Ok => {}
            other => panic!("expected Ok at boundary, got {other:?}"),
        }
    }

    #[test]
    fn rx_mempool_floor_fails_below_min() {
        match check_rx_mempool_floor(31) {
            ObserveOutcome::Fail(FailureReason::LiveCounterBelowMin {
                counter, observed, min,
            }) => {
                assert_eq!(counter, "tcp.rx_mempool_avail");
                assert_eq!(observed, 31);
                assert_eq!(min, 32);
            }
            other => panic!("expected LiveCounterBelowMin, got {other:?}"),
        }
    }

    #[test]
    fn events_dropped_delta_passes_when_unchanged() {
        match check_events_dropped_delta(5, 5) {
            ObserveOutcome::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn events_dropped_delta_fails_when_advanced() {
        match check_events_dropped_delta(5, 12) {
            ObserveOutcome::Fail(FailureReason::EventsDropped { count }) => {
                assert_eq!(count, 7);
            }
            other => panic!("expected EventsDropped, got {other:?}"),
        }
    }
}

/// Outcome of a single observation batch. Either liveness + event
/// replay all passed, or a single fail-fast failure was raised.
#[derive(Debug)]
pub enum ObserveOutcome {
    Ok,
    Fail(FailureReason),
}

/// Pure-function FSM oracle: walk a slice of `InternalEvent`s and the
/// current state, return the first illegal transition (if any) plus
/// the running ordinal advance. `state_now` is `state_of(handle)`'s
/// most recent return; `event_window` is appended to.
///
/// Separated from the engine-driven `observe_batch` so the FSM oracle
/// is unit-testable without DPDK.
pub fn fsm_replay_batch(
    state_now: Option<TcpState>,
    events: &[InternalEvent],
    event_window: &mut EventRing,
) -> ObserveOutcome {
    if state_now != Some(TcpState::Established) {
        return ObserveOutcome::Fail(FailureReason::FsmDeparted {
            observed: state_now.map(Into::into),
        });
    }
    let mut idx = event_window.next_seq();
    let mut illegal: Option<(TcpState, TcpState, usize)> = None;
    // Counter-tracked for-loop kept for symmetry with the closure form
    // inside `observe_batch` below; both update `idx` alongside other
    // per-event state.
    #[allow(clippy::explicit_counter_loop)]
    for ev in events {
        if illegal.is_none() {
            if let InternalEvent::StateChange { from, to, .. } = ev {
                if *from == TcpState::Established && *to != TcpState::Established {
                    illegal = Some((*from, *to, idx));
                }
            }
        }
        event_window.push(ev, idx);
        idx += 1;
    }
    if let Some((from, to, at_event_idx)) = illegal {
        return ObserveOutcome::Fail(FailureReason::IllegalTransition {
            from: from.into(),
            to: to.into(),
            at_event_idx,
        });
    }
    ObserveOutcome::Ok
}

/// RX-mempool floor side-check (spec §5.4: MIN_RX_MEMPOOL_AVAIL = 32).
/// Pure-function form for unit tests.
pub fn check_rx_mempool_floor(avail: u32) -> ObserveOutcome {
    if avail < crate::counters_snapshot::MIN_RX_MEMPOOL_AVAIL {
        ObserveOutcome::Fail(FailureReason::LiveCounterBelowMin {
            counter: "tcp.rx_mempool_avail",
            observed: avail as u64,
            min: crate::counters_snapshot::MIN_RX_MEMPOOL_AVAIL as u64,
        })
    } else {
        ObserveOutcome::Ok
    }
}

/// Per-batch obs.events_dropped delta side-check.
pub fn check_events_dropped_delta(pre: u64, now: u64) -> ObserveOutcome {
    if now > pre {
        ObserveOutcome::Fail(FailureReason::EventsDropped { count: now - pre })
    } else {
        ObserveOutcome::Ok
    }
}

/// Engine-driven observation batch (spec §5.2). Calls `state_of`,
/// drains up to MAX_DRAIN_PER_BATCH events via the callback API, and
/// runs the three side-checks. Returns `Ok` to continue or a single
/// fail-fast `FailureReason`.
///
/// Caller passes `obs_events_dropped_pre` from before the batch (read
/// off `engine.counters().obs.events_dropped` after the previous batch
/// completed).
#[cfg(not(test))]
pub fn observe_batch(
    engine: &dpdk_net_core::engine::Engine,
    conn: dpdk_net_core::flow_table::ConnHandle,
    event_window: &mut EventRing,
    obs_events_dropped_pre: u64,
) -> ObserveOutcome {
    use std::sync::atomic::Ordering;

    // 1. Liveness: state_of must read Established.
    let state_now = engine.state_of(conn);
    if state_now != Some(TcpState::Established) {
        return ObserveOutcome::Fail(FailureReason::FsmDeparted {
            observed: state_now.map(Into::into),
        });
    }

    // 2. Event-stream replay. The closure walks the FSM oracle and
    //    pushes into the failure-bundle ring. `from == to` self-
    //    transitions are filtered at engine-side push time
    //    (engine.rs:4348), so the oracle never sees Established→
    //    Established events.
    let mut illegal: Option<(TcpState, TcpState, usize)> = None;
    let mut idx = event_window.next_seq();
    engine.drain_events(MAX_DRAIN_PER_BATCH, |evt, _engine| {
        if illegal.is_none() {
            if let InternalEvent::StateChange { from, to, .. } = evt {
                if *from == TcpState::Established && *to != TcpState::Established {
                    illegal = Some((*from, *to, idx));
                }
            }
        }
        event_window.push(evt, idx);
        idx += 1;
    });
    if let Some((from, to, at_event_idx)) = illegal {
        return ObserveOutcome::Fail(FailureReason::IllegalTransition {
            from: from.into(),
            to: to.into(),
            at_event_idx,
        });
    }

    // 3. RX-mempool floor side-check. tcp.rx_mempool_avail is
    //    AtomicU32 and intentionally absent from lookup_counter.
    let avail = engine.counters().tcp.rx_mempool_avail.load(Ordering::Relaxed);
    if let ObserveOutcome::Fail(f) = check_rx_mempool_floor(avail) {
        return ObserveOutcome::Fail(f);
    }

    // 4. Per-batch obs.events_dropped delta side-check.
    let obs_dropped_now = engine
        .counters()
        .obs
        .events_dropped
        .load(Ordering::Relaxed);
    check_events_dropped_delta(obs_events_dropped_pre, obs_dropped_now)
}
