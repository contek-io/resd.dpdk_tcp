//! Urgent probe (RFC 9293 MUST-30/31) — pins AD-A8-urg-dropped.
//! Filled in Phase A8 T21.

use crate::{ProbeResult, ProbeStatus};

pub fn urgent_dropped() -> ProbeResult {
    ProbeResult {
        clause_id: "MUST-30/31",
        probe_name: "Urgent",
        status: ProbeStatus::Fail("not yet implemented (A8 T21 pending)".into()),
        message: String::new(),
    }
}
