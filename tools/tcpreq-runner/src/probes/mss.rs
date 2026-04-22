//! MissingMSS (MUST-15) and LateOption (MUST-5) probes.
//! Filled in Phase A8 T19.

use crate::{ProbeResult, ProbeStatus};

pub fn missing_mss() -> ProbeResult {
    ProbeResult {
        clause_id: "MUST-15",
        probe_name: "MissingMSS",
        status: ProbeStatus::Fail("not yet implemented (A8 T19 pending)".into()),
        message: String::new(),
    }
}

pub fn late_option() -> ProbeResult {
    ProbeResult {
        clause_id: "MUST-5",
        probe_name: "LateOption",
        status: ProbeStatus::Fail("not yet implemented (A8 T19 pending)".into()),
        message: String::new(),
    }
}
