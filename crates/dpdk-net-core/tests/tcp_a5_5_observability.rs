use dpdk_net_core::flow_table::ConnHandle;
use dpdk_net_core::tcp_events::{EventQueue, InternalEvent, LossCause};
use dpdk_net_core::tcp_state::TcpState;

#[test]
fn internal_event_carries_emitted_ts_ns_on_every_variant() {
    let ev_connected = InternalEvent::Connected {
        conn: ConnHandle::default(),
        rx_hw_ts_ns: 0,
        emitted_ts_ns: 42,
    };
    let ev_readable = InternalEvent::Readable {
        conn: ConnHandle::default(),
        seg_idx_start: 0,
        seg_count: 0,
        total_len: 0,
        rx_hw_ts_ns: 0,
        emitted_ts_ns: 42,
    };
    let ev_closed = InternalEvent::Closed {
        conn: ConnHandle::default(),
        err: 0,
        emitted_ts_ns: 42,
    };
    let ev_state = InternalEvent::StateChange {
        conn: ConnHandle::default(),
        from: TcpState::SynSent,
        to: TcpState::Established,
        emitted_ts_ns: 42,
    };
    let ev_error = InternalEvent::Error {
        conn: ConnHandle::default(),
        err: -1,
        emitted_ts_ns: 42,
    };
    let ev_retrans = InternalEvent::TcpRetrans {
        conn: ConnHandle::default(),
        seq: 0,
        rtx_count: 1,
        emitted_ts_ns: 42,
    };
    let ev_loss = InternalEvent::TcpLossDetected {
        conn: ConnHandle::default(),
        cause: LossCause::Rack,
        emitted_ts_ns: 42,
    };
    for e in [
        ev_connected,
        ev_readable,
        ev_closed,
        ev_state,
        ev_error,
        ev_retrans,
        ev_loss,
    ] {
        assert_eq!(emitted_ts_ns_of(&e), 42);
    }
    let _ = EventQueue::new();
}

fn emitted_ts_ns_of(ev: &InternalEvent) -> u64 {
    match ev {
        InternalEvent::Connected { emitted_ts_ns, .. }
        | InternalEvent::Readable { emitted_ts_ns, .. }
        | InternalEvent::Closed { emitted_ts_ns, .. }
        | InternalEvent::StateChange { emitted_ts_ns, .. }
        | InternalEvent::Error { emitted_ts_ns, .. }
        | InternalEvent::TcpRetrans { emitted_ts_ns, .. }
        | InternalEvent::TcpLossDetected { emitted_ts_ns, .. }
        | InternalEvent::ApiTimer { emitted_ts_ns, .. }
        | InternalEvent::Writable { emitted_ts_ns, .. } => *emitted_ts_ns,
    }
}

// A10 D4 (G1): under `obs-none` `EventQueue::push` is a no-op, so
// overflow/drop/counter semantics are not exercised. Skip this test in
// that feature config — default builds (the ones that ship to consumers)
// still pin the drop-oldest contract.
#[cfg(not(feature = "obs-none"))]
#[test]
fn event_queue_overflow_drops_oldest_preserves_newest() {
    use dpdk_net_core::counters::Counters;
    use std::sync::atomic::Ordering;

    let counters = Counters::new();
    let mut q = EventQueue::with_cap(64);

    for i in 0..66u64 {
        q.push(
            InternalEvent::Connected {
                conn: ConnHandle::default(),
                rx_hw_ts_ns: 0,
                emitted_ts_ns: i * 100,
            },
            &counters,
        );
    }

    assert_eq!(q.len(), 64);
    assert_eq!(counters.obs.events_dropped.load(Ordering::Relaxed), 2);
    assert_eq!(
        counters.obs.events_queue_high_water.load(Ordering::Relaxed),
        64
    );

    let mut expected = (200u64..=6500).step_by(100);
    while let Some(ev) = q.pop() {
        let InternalEvent::Connected { emitted_ts_ns, .. } = ev else {
            unreachable!()
        };
        assert_eq!(Some(emitted_ts_ns), expected.next());
    }
    assert_eq!(expected.next(), None);
}

#[test]
fn event_queue_with_cap_rejects_below_64() {
    let result = std::panic::catch_unwind(|| EventQueue::with_cap(32));
    assert!(result.is_err(), "with_cap(<64) should panic or return Err");
}

// A5.5 Task 7: `flow_table::get_stats` is the projection layer wrapped by
// `dpdk_net_conn_stats`. The C ABI maps `None` → -ENOENT; exercising the
// `None` branch here pins the projection contract that the ABI relies on
// without needing a live DPDK/EAL engine. Happy-path + `-ENOENT` via the
// extern are TAP-gated follow-ups (see Task 8 + Task 7 plan §5.3).
#[test]
fn flow_table_get_stats_returns_none_for_invalid_handle() {
    use dpdk_net_core::flow_table::{FlowTable, INVALID_HANDLE};

    let ft = FlowTable::new(4);
    assert!(ft.get_stats(INVALID_HANDLE, 262_144).is_none());
    // Any handle past `capacity` is also unknown.
    assert!(ft.get_stats(999, 262_144).is_none());
}

// A5.5 Task 8: spec §7.2.1 — emission-time timestamp correctness. Full
// TAP-pair "inject a known-latency delay between emission and poll" needs
// a synthetic peer harness that doesn't exist (see tests/common/mod.rs).
// The translation-layer proof that all 7 variants copy `emitted_ts_ns`
// through to `enqueued_ts_ns` lives at the C ABI boundary as
// `drain_reads_emitted_ts_ns_through_not_drain_clock` in
// `crates/dpdk-net/src/lib.rs`. Here we cover the complementary storage-
// layer contract: once `push()`-stored, the `emitted_ts_ns` field is
// preserved verbatim across FIFO pops regardless of how many events sit
// between push and pop. That rules out any drain-time clock re-sampling
// in the queue itself. Together with Task 2's test, this pins the
// emission-time contract end-to-end for the Tasks 1-3 machinery.
// A10 D4 (G1): push is no-op under `obs-none` — emitted_ts_ns preservation
// across the queue is irrelevant when nothing ever enters the queue. Skip
// in that feature config; default builds still exercise the FIFO-span
// preservation contract.
#[cfg(not(feature = "obs-none"))]
#[test]
fn integration_event_queue_preserves_emitted_ts_ns_across_fifo_span() {
    use dpdk_net_core::counters::Counters;
    use dpdk_net_core::tcp_events::{EventQueue, InternalEvent, LossCause};
    use dpdk_net_core::tcp_state::TcpState;

    let counters = Counters::new();
    let mut q = EventQueue::with_cap(64);

    // Emit one of each variant, each with a distinct `emitted_ts_ns`
    // chosen so no accidental drain-time sample could yield these values
    // (wildly spaced, not sequential ns ticks). Queue them all, then
    // drain and assert every variant's timestamp survived intact.
    let ts = [111u64, 22_000, 3_333_333, 999, 5, 77_777, 1_000_000_000];

    q.push(
        InternalEvent::Connected {
            conn: 1,
            rx_hw_ts_ns: 0,
            emitted_ts_ns: ts[0],
        },
        &counters,
    );
    q.push(
        InternalEvent::Readable {
            conn: 1,
            seg_idx_start: 0,
            seg_count: 0,
            total_len: 1,
            rx_hw_ts_ns: 0,
            emitted_ts_ns: ts[1],
        },
        &counters,
    );
    q.push(
        InternalEvent::StateChange {
            conn: 1,
            from: TcpState::SynSent,
            to: TcpState::Established,
            emitted_ts_ns: ts[2],
        },
        &counters,
    );
    q.push(
        InternalEvent::Error {
            conn: 1,
            err: -1,
            emitted_ts_ns: ts[3],
        },
        &counters,
    );
    q.push(
        InternalEvent::TcpRetrans {
            conn: 1,
            seq: 42,
            rtx_count: 2,
            emitted_ts_ns: ts[4],
        },
        &counters,
    );
    q.push(
        InternalEvent::TcpLossDetected {
            conn: 1,
            cause: LossCause::Tlp,
            emitted_ts_ns: ts[5],
        },
        &counters,
    );
    q.push(
        InternalEvent::Closed {
            conn: 1,
            err: 0,
            emitted_ts_ns: ts[6],
        },
        &counters,
    );

    assert_eq!(q.len(), 7);

    let mut got: Vec<u64> = Vec::with_capacity(7);
    while let Some(ev) = q.pop() {
        let t = match ev {
            InternalEvent::Connected { emitted_ts_ns, .. }
            | InternalEvent::Readable { emitted_ts_ns, .. }
            | InternalEvent::Closed { emitted_ts_ns, .. }
            | InternalEvent::StateChange { emitted_ts_ns, .. }
            | InternalEvent::Error { emitted_ts_ns, .. }
            | InternalEvent::TcpRetrans { emitted_ts_ns, .. }
            | InternalEvent::TcpLossDetected { emitted_ts_ns, .. }
            | InternalEvent::ApiTimer { emitted_ts_ns, .. }
            | InternalEvent::Writable { emitted_ts_ns, .. } => emitted_ts_ns,
        };
        got.push(t);
    }
    assert_eq!(got, ts, "emitted_ts_ns must survive FIFO storage verbatim");
}

// A5.5 Task 8: spec §7.2.2 — queue overflow drop-oldest + counters under
// a realistic burst that drops MANY events, not just 2. Complements the
// Task 3 unit test (`event_queue_overflow_drops_oldest_preserves_newest`,
// which pushes 66 events at cap 64 → 2 dropped). Here we push 200 events
// at cap 64 → 136 dropped, 64 preserved. This exercises the sustained-
// overflow regime where `events_dropped` materially exceeds `soft_cap`
// (forensic signal: "queue saturated, many events lost"), and pins the
// `emitted_ts_ns` ordering of the drained survivors against the
// most-recent 64 by construction.
// A10 D4 (G1): sustained-overflow drop-count contract depends on `push`
// enqueueing events. Under `obs-none` every push is a no-op (zero
// allocations, zero counter bumps) so the assertion set here is vacuous.
// Skip in that feature config.
#[cfg(not(feature = "obs-none"))]
#[test]
fn integration_queue_overflow_many_events_preserves_newest_and_counts() {
    use dpdk_net_core::counters::Counters;
    use dpdk_net_core::tcp_events::{EventQueue, InternalEvent};
    use std::sync::atomic::Ordering;

    let counters = Counters::new();
    let mut q = EventQueue::with_cap(64);

    for i in 0..200u64 {
        q.push(
            InternalEvent::Connected {
                conn: 1,
                rx_hw_ts_ns: 0,
                emitted_ts_ns: i * 1000,
            },
            &counters,
        );
    }

    assert_eq!(q.len(), 64);
    assert_eq!(counters.obs.events_dropped.load(Ordering::Relaxed), 136);
    assert_eq!(
        counters.obs.events_queue_high_water.load(Ordering::Relaxed),
        64
    );

    // Drain and confirm the `emitted_ts_ns` sequence is monotonic and
    // covers the most-recent 64 values (i = 136..=199) in FIFO order.
    let mut prev = 0u64;
    let mut first_ts = 0u64;
    let mut last_ts = 0u64;
    let mut count = 0u32;
    while let Some(ev) = q.pop() {
        let InternalEvent::Connected { emitted_ts_ns, .. } = ev else {
            unreachable!()
        };
        if count == 0 {
            first_ts = emitted_ts_ns;
        }
        last_ts = emitted_ts_ns;
        assert!(
            emitted_ts_ns >= prev,
            "FIFO drain order broken: {emitted_ts_ns} < {prev}"
        );
        prev = emitted_ts_ns;
        count += 1;
    }
    assert_eq!(count, 64);
    assert_eq!(first_ts, 136 * 1000);
    assert_eq!(last_ts, 199 * 1000);
}
