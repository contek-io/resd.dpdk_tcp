use resd_net_core::flow_table::ConnHandle;
use resd_net_core::tcp_events::{EventQueue, InternalEvent, LossCause};
use resd_net_core::tcp_state::TcpState;

#[test]
fn internal_event_carries_emitted_ts_ns_on_every_variant() {
    let ev_connected = InternalEvent::Connected {
        conn: ConnHandle::default(),
        rx_hw_ts_ns: 0,
        emitted_ts_ns: 42,
    };
    let ev_readable = InternalEvent::Readable {
        conn: ConnHandle::default(),
        byte_offset: 0,
        byte_len: 0,
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
    for e in [ev_connected, ev_readable, ev_closed, ev_state, ev_error, ev_retrans, ev_loss] {
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
        | InternalEvent::TcpLossDetected { emitted_ts_ns, .. } => *emitted_ts_ns,
    }
}
