//! Internal FIFO event queue. Populated by FSM transitions and data
//! delivery; drained at the top of `resd_net_poll` into the caller's
//! `events_out[]` array.

use std::collections::VecDeque;

use crate::flow_table::ConnHandle;
use crate::tcp_state::TcpState;

/// A5 Task 20: which loss detector fired. Carried on
/// `InternalEvent::TcpLossDetected` for observability; the C ABI layer
/// narrows this to a `u8` trigger on `resd_net_event_tcp_loss_t`.
///
/// Order matches the `u8` encoding at the ABI boundary:
/// `Rack = 0`, `Tlp = 1`, `Rto = 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossCause {
    Rack,
    Tlp,
    Rto,
}

/// Event kinds internal to the engine. Translated to public
/// `resd_net_event_t` values at the C ABI boundary.
#[derive(Debug, Clone)]
pub enum InternalEvent {
    Connected {
        conn: ConnHandle,
        rx_hw_ts_ns: u64,
        emitted_ts_ns: u64,
    },
    /// `byte_len` bytes are available starting at the connection's
    /// `recv.last_read_buf` scratch region. The caller promotes this
    /// to a `(data, data_len)` view at the ABI boundary.
    Readable {
        conn: ConnHandle,
        /// Offset within `conn.recv.last_read_buf` where this event's bytes begin.
        /// Multiple Readable events can fire per poll iteration; each one
        /// describes a contiguous slice `last_read_buf[byte_offset..byte_offset+byte_len]`.
        /// The buffer is cleared at the top of each `resd_net_poll`.
        byte_offset: u32,
        byte_len: u32,
        rx_hw_ts_ns: u64,
        emitted_ts_ns: u64,
    },
    Closed {
        conn: ConnHandle,
        err: i32, // 0 = clean close; negative errno otherwise
        emitted_ts_ns: u64,
    },
    StateChange {
        conn: ConnHandle,
        from: TcpState,
        to: TcpState,
        emitted_ts_ns: u64,
    },
    Error {
        conn: ConnHandle,
        err: i32,
        emitted_ts_ns: u64,
    },
    /// A5 Task 20: retransmit observability. Emitted from each fire
    /// handler (RTO, RACK, TLP) per-retransmitted segment, gated on
    /// `EngineConfig::tcp_per_packet_events`. `seq` is the segment
    /// start sequence number; `rtx_count` is the entry's `xmit_count`
    /// after the retransmit (≥ 2 for RTO/TLP; ≥ 2 for RACK-driven).
    /// `emitted_ts_ns`: engine-monotonic-clock ns sampled at event emission.
    TcpRetrans {
        conn: ConnHandle,
        seq: u32,
        rtx_count: u32,
        emitted_ts_ns: u64,
    },
    /// A5 Task 20: loss-detection observability. Emitted once per
    /// detected-loss event (one per fire for RTO/TLP; one per
    /// `rack_lost_indexes` entry for RACK). Gated on
    /// `EngineConfig::tcp_per_packet_events`.
    /// `emitted_ts_ns`: engine-monotonic-clock ns sampled at event emission.
    TcpLossDetected {
        conn: ConnHandle,
        cause: LossCause,
        emitted_ts_ns: u64,
    },
}

pub struct EventQueue {
    q: VecDeque<InternalEvent>,
}

impl EventQueue {
    pub fn new() -> Self {
        Self {
            q: VecDeque::with_capacity(64),
        }
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
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_ordering() {
        let mut q = EventQueue::new();
        q.push(InternalEvent::Connected {
            conn: 1,
            rx_hw_ts_ns: 0,
            emitted_ts_ns: 0,
        });
        q.push(InternalEvent::Closed {
            conn: 1,
            err: 0,
            emitted_ts_ns: 0,
        });
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
        q.push(InternalEvent::Error {
            conn: 1,
            err: -5,
            emitted_ts_ns: 0,
        });
        assert_eq!(q.len(), 1);
        let _ = q.pop();
        assert!(q.is_empty());
    }

    #[test]
    fn tcp_retrans_event_variant_exists() {
        let _e = InternalEvent::TcpRetrans {
            conn: 0,
            seq: 0,
            rtx_count: 0,
            emitted_ts_ns: 0,
        };
    }

    #[test]
    fn tcp_loss_detected_event_with_each_cause() {
        let _rack = InternalEvent::TcpLossDetected {
            conn: 0,
            cause: LossCause::Rack,
            emitted_ts_ns: 0,
        };
        let _tlp = InternalEvent::TcpLossDetected {
            conn: 0,
            cause: LossCause::Tlp,
            emitted_ts_ns: 0,
        };
        let _rto = InternalEvent::TcpLossDetected {
            conn: 0,
            cause: LossCause::Rto,
            emitted_ts_ns: 0,
        };
    }
}
