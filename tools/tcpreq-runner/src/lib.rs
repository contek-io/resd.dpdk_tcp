//! tcpreq-runner — Layer C RFC 793bis MUST/SHOULD probe suite (narrow port).
//!
//! Spec §3.1: 4 probes ported from https://github.com/TheJokr/tcpreq
//! (2020 Python codebase): MissingMSS, LateOption, Reserved-RX, Urgent.
//! Probes that duplicate Layer A coverage are NOT ported; see SKIPPED.md
//! for the per-module justification with Layer A / Layer B citations.
//!
//! Each probe constructs a fresh engine via common test-server infra,
//! injects crafted Ethernet frames into the engine via the test-FFI,
//! drains TX frames, asserts compliance. Report lines reference the
//! RFC 793bis MUST clause id so the M5 compliance matrix can cite
//! the probe by one stable handle.

pub mod probes;

/// Probe result — one row per RFC clause id.
#[derive(Debug)]
pub struct ProbeResult {
    pub clause_id: &'static str,   // e.g. "MUST-15"
    pub probe_name: &'static str,  // e.g. "MissingMSS"
    pub status: ProbeStatus,
    pub message: String,
}

#[derive(Debug)]
pub enum ProbeStatus {
    Pass,
    /// Documented deviation. Cite the spec §6.4 row id (e.g. "AD-A8-urg-dropped").
    Deviation(&'static str),
    Fail(String),
}

/// Run every ported probe. Returns one ProbeResult per probe.
/// Consumed by M5's compliance matrix reporter.
pub fn run_all_probes() -> Vec<ProbeResult> {
    vec![
        probes::mss::missing_mss(),
        probes::mss::late_option(),
        probes::reserved::reserved_rx(),
        probes::urgent::urgent_dropped(),
    ]
}
