//! RFC 9293 §3.3.2 eleven-state TCP FSM. States are numbered so the
//! `state_trans[from][to]` counter matrix in `counters.rs` can be
//! indexed by `state as usize` without collisions. Also exposed as
//! `u8` for the public `DPDK_NET_EVT_TCP_STATE_CHANGE` event.
//!
//! We never transition to LISTEN in production (spec §6.1); it's
//! present only so the enum covers the full RFC set and so the
//! test-only loopback-server feature (A7) can drive it.

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
}

impl TcpState {
    pub const COUNT: usize = 11;

    /// Short fixed-width label for debug logging. No allocation.
    pub fn label(self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECEIVED",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eleven_states_with_consecutive_u8_values() {
        assert_eq!(TcpState::COUNT, 11);
        assert_eq!(TcpState::Closed as u8, 0);
        assert_eq!(TcpState::TimeWait as u8, 10);
    }

    #[test]
    fn label_is_stable_for_every_state() {
        for s in [
            TcpState::Closed,
            TcpState::Listen,
            TcpState::SynSent,
            TcpState::SynReceived,
            TcpState::Established,
            TcpState::FinWait1,
            TcpState::FinWait2,
            TcpState::CloseWait,
            TcpState::Closing,
            TcpState::LastAck,
            TcpState::TimeWait,
        ] {
            assert!(!s.label().is_empty());
        }
    }
}
