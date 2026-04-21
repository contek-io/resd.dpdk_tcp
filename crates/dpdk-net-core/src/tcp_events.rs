//! Internal FIFO event queue. Populated by FSM transitions and data
//! delivery; drained at the top of `dpdk_net_poll` into the caller's
//! `events_out[]` array.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use crate::counters::Counters;
use crate::flow_table::ConnHandle;
use crate::tcp_state::TcpState;

/// A5 Task 20: which loss detector fired. Carried on
/// `InternalEvent::TcpLossDetected` for observability; the C ABI layer
/// narrows this to a `u8` trigger on `dpdk_net_event_tcp_loss_t`.
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
/// `dpdk_net_event_t` values at the C ABI boundary.
#[derive(Debug, Clone)]
pub enum InternalEvent {
    Connected {
        conn: ConnHandle,
        rx_hw_ts_ns: u64,
        emitted_ts_ns: u64,
    },
    /// A6.6 T9: scatter-gather view over an in-order delivery window.
    /// `seg_idx_start` / `seg_count` reference a slice of the owning
    /// `TcpConn.readable_scratch_iovecs` Vec. At the ABI boundary,
    /// `dpdk_net_poll` materializes the corresponding `dpdk_net_iovec_t`
    /// pointer + length onto the `dpdk_net_event_readable_t` payload.
    ///
    /// Lifetime: the scratch Vec (and the mbufs referenced by each
    /// iovec's `base` pointer) stay valid until the next `dpdk_net_poll`
    /// on the owning engine — top-of-poll clears `delivered_segments`
    /// (dropping refcounts) and `readable_scratch_iovecs` for every live
    /// conn before any fresh RX dispatch.
    Readable {
        conn: ConnHandle,
        /// A6.6 T9: start index into the owning
        /// `TcpConn.readable_scratch_iovecs` for this event's iovec
        /// slice. Per-conn scratch, so always 0 at emit time (the full
        /// scratch is cleared and rebuilt per event for that conn).
        seg_idx_start: u32,
        /// Number of iovec entries this event covers.
        seg_count: u32,
        /// Sum of `segs[i].len` across
        /// `[seg_idx_start, seg_idx_start + seg_count)`.
        total_len: u32,
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
    /// A6: public-timer-API fire. Emitted when an `ApiPublic` wheel node
    /// fires via `advance_timer_wheel`. `timer_id` re-packs the wheel's
    /// `TimerId`; `user_data` round-trips the caller's opaque payload.
    /// No `conn` field — public timers are engine-level, not connection-
    /// bound. `emitted_ts_ns` is sampled at fire (same convention as
    /// RTO-fire per A5.5 §3.1).
    ApiTimer {
        timer_id: crate::tcp_timer_wheel::TimerId,
        user_data: u64,
        emitted_ts_ns: u64,
    },
    /// A6: send-buffer drained to ≤ `send_buffer_bytes / 2` after a
    /// prior `send_bytes` refusal. Level-triggered, single-edge-per-
    /// refusal-cycle. No payload.
    Writable {
        conn: ConnHandle,
        emitted_ts_ns: u64,
    },
}

pub struct EventQueue {
    q: VecDeque<InternalEvent>,
    soft_cap: usize,
}

impl EventQueue {
    /// Minimum queue cap. Prevents pathological configs from producing
    /// a queue smaller than one realistic poll burst worth of events.
    pub const MIN_SOFT_CAP: usize = 64;

    /// Default cap per spec §3.2 — 4096 events × ~32 B/event ≈ 128 KiB per engine.
    pub const DEFAULT_SOFT_CAP: usize = 4096;

    pub fn new() -> Self {
        Self::with_cap(Self::DEFAULT_SOFT_CAP)
    }

    pub fn with_cap(cap: usize) -> Self {
        assert!(
            cap >= Self::MIN_SOFT_CAP,
            "EventQueue::with_cap: cap {} below MIN_SOFT_CAP {}",
            cap,
            Self::MIN_SOFT_CAP
        );
        Self {
            q: VecDeque::with_capacity(cap.min(Self::DEFAULT_SOFT_CAP)),
            soft_cap: cap,
        }
    }

    /// Push an event. If the queue is at `soft_cap`, drop the oldest entry
    /// and increment `obs.events_dropped`. Always latches `obs.events_queue_high_water`
    /// to max observed depth.
    pub fn push(&mut self, ev: InternalEvent, counters: &Counters) {
        if self.q.len() >= self.soft_cap {
            let _ = self.q.pop_front();
            counters.obs.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.q.push_back(ev);
        let depth = self.q.len() as u64;
        counters
            .obs
            .events_queue_high_water
            .fetch_max(depth, Ordering::Relaxed);
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
        let counters = Counters::new();
        let mut q = EventQueue::new();
        q.push(
            InternalEvent::Connected {
                conn: 1,
                rx_hw_ts_ns: 0,
                emitted_ts_ns: 0,
            },
            &counters,
        );
        q.push(
            InternalEvent::Closed {
                conn: 1,
                err: 0,
                emitted_ts_ns: 0,
            },
            &counters,
        );
        match q.pop() {
            Some(InternalEvent::Connected { conn, .. }) => assert_eq!(conn, 1),
            other => panic!("expected Connected, got {other:?}"),
        }
        assert!(matches!(q.pop(), Some(InternalEvent::Closed { .. })));
        assert!(q.pop().is_none());
    }

    #[test]
    fn len_tracks_outstanding() {
        let counters = Counters::new();
        let mut q = EventQueue::new();
        assert!(q.is_empty());
        q.push(
            InternalEvent::Error {
                conn: 1,
                err: -5,
                emitted_ts_ns: 0,
            },
            &counters,
        );
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

    #[test]
    fn api_timer_event_variant_shape() {
        let id = crate::tcp_timer_wheel::TimerId { slot: 7, generation: 42 };
        let e = InternalEvent::ApiTimer {
            timer_id: id,
            user_data: 0xABCD_1234_5678_BEEF,
            emitted_ts_ns: 9_000,
        };
        match e {
            InternalEvent::ApiTimer { timer_id, user_data, emitted_ts_ns } => {
                assert_eq!(timer_id, id);
                assert_eq!(user_data, 0xABCD_1234_5678_BEEF);
                assert_eq!(emitted_ts_ns, 9_000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn writable_event_variant_shape() {
        let e = InternalEvent::Writable {
            conn: ConnHandle::default(),
            emitted_ts_ns: 11_000,
        };
        match e {
            InternalEvent::Writable { conn, emitted_ts_ns } => {
                assert_eq!(conn, ConnHandle::default());
                assert_eq!(emitted_ts_ns, 11_000);
            }
            _ => panic!("wrong variant"),
        }
    }
}
