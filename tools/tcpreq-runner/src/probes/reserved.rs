//! Reserved-RX probe (RFC 793bis "reserved bits ignored on RX").
//! Filled in Phase A8 T20.

use crate::{ProbeResult, ProbeStatus};

pub fn reserved_rx() -> ProbeResult {
    ProbeResult {
        clause_id: "Reserved-RX",
        probe_name: "ReservedBitsRx",
        status: ProbeStatus::Fail("not yet implemented (A8 T20 pending)".into()),
        message: String::new(),
    }
}
