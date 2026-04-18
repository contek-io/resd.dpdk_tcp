//! Internal FIFO event queue. Populated by FSM transitions and data
//! delivery; drained at the top of `resd_net_poll` into the caller's
//! `events_out[]` array.

use std::collections::VecDeque;

use crate::flow_table::ConnHandle;
use crate::tcp_state::TcpState;

/// Event kinds internal to the engine. Translated to public
/// `resd_net_event_t` values at the C ABI boundary.
#[derive(Debug, Clone)]
pub enum InternalEvent {
    Connected {
        conn: ConnHandle,
        rx_hw_ts_ns: u64,
    },
    /// `byte_len` bytes are available starting at the connection's
    /// `recv.last_read_buf` scratch region. The caller promotes this
    /// to a `(data, data_len)` view at the ABI boundary.
    Readable {
        conn: ConnHandle,
        byte_len: u32,
        rx_hw_ts_ns: u64,
    },
    Closed {
        conn: ConnHandle,
        err: i32, // 0 = clean close; negative errno otherwise
    },
    StateChange {
        conn: ConnHandle,
        from: TcpState,
        to: TcpState,
    },
    Error {
        conn: ConnHandle,
        err: i32,
    },
}

pub struct EventQueue {
    q: VecDeque<InternalEvent>,
}

impl EventQueue {
    pub fn new() -> Self {
        Self { q: VecDeque::with_capacity(64) }
    }

    pub fn push(&mut self, ev: InternalEvent) {
        self.q.push_back(ev);
    }

    pub fn pop(&mut self) -> Option<InternalEvent> {
        self.q.pop_front()
    }

    pub fn len(&self) -> usize {
        self.q.len()
    }

    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
}

impl Default for EventQueue {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_ordering() {
        let mut q = EventQueue::new();
        q.push(InternalEvent::Connected { conn: 1, rx_hw_ts_ns: 0 });
        q.push(InternalEvent::Closed { conn: 1, err: 0 });
        match q.pop() {
            Some(InternalEvent::Connected { conn, .. }) => assert_eq!(conn, 1),
            other => panic!("expected Connected, got {other:?}"),
        }
        assert!(matches!(q.pop(), Some(InternalEvent::Closed { .. })));
        assert!(q.pop().is_none());
    }

    #[test]
    fn len_tracks_outstanding() {
        let mut q = EventQueue::new();
        assert!(q.is_empty());
        q.push(InternalEvent::Error { conn: 1, err: -5 });
        assert_eq!(q.len(), 1);
        let _ = q.pop();
        assert!(q.is_empty());
    }
}
