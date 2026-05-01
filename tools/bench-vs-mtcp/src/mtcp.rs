//! mTCP stack driver — **stub** in T12 (spec §11).
//!
//! # Scope deferral — Stage 1 Task 12
//!
//! The spec's two-stack comparison (dpdk_net vs. mTCP) requires a
//! running mTCP installation on the DUT — driver, its DPDK PMD, its
//! ioengine, and the peer-side `bench-peer` binary — all of which
//! Plan A's sister plan bakes into the benchmark AMI at `/opt/mtcp/`
//! and `/opt/mtcp-peer/`. That AMI does not exist yet, so T12 cannot
//! run an mTCP comparison end-to-end. Mirroring T8's AF_PACKET
//! deferral pattern, T12 ships with the mTCP path stubbed to
//! [`Error::Unimplemented`] and the dpdk_net side fully wired.
//!
//! # What is shipped in T12
//!
//! - [`MtcpConfig`] — the shape of the config block the real
//!   implementation will consume. Fixed now so the CLI can build it
//!   up from flags and fail fast on invalid shapes.
//! - [`validate_config`] — pure-data shape validation; does not touch
//!   libmtcp. Safe in unit tests and invoked from `main.rs` before the
//!   stub `run_burst_workload` returns `Unimplemented`.
//! - [`run_burst_workload`] — stub entry point. Validates the config
//!   then returns `Error::Unimplemented`. Returns `Vec<f64>` of raw
//!   throughput samples in bits-per-second when real, matching the
//!   dpdk_burst runner's shape.
//! - [`MaxtpConfig`] + [`validate_maxtp_config`] + [`run_maxtp_workload`]
//!   — T13 analogue for the maxtp workload. Same stub shape;
//!   configures the W × C grid's per-bucket parameters
//!   (write size + connection count + warmup + duration).
//!
//! # Follow-up
//!
//! The implementation lands as part of:
//! - A10 follow-up task (outside Plan B's 14-task scope), once the
//!   sister-plan T6 (first AMI bake + first bench-pair bring-up) is
//!   complete and the harness can drive `/opt/mtcp-peer/bench-peer`
//!   via SSH.
//!
//! The CSV shape (`dimensions_json.stack = "mtcp"`) is fixed by
//! `Stack::Mtcp.as_dimension()` and will not change when the real
//! implementation lands — so bench-report already knows how to bucket
//! mtcp rows even before they exist.

/// Marker error returned by [`run_burst_workload`] while the stack is
/// stubbed. Caller surfaces this as a hard error in strict
/// precondition mode and as a skip + warn in lenient mode.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mTCP stack is stubbed in Plan B T12 — see src/mtcp.rs module docs")]
    Unimplemented,
}

/// Configuration for an mTCP burst run. Fields are filled in by
/// `main.rs` and validated by [`validate_config`] so the stub rejects
/// invalid configs before it surfaces the deferral error, matching
/// what the real implementation will do.
///
/// `peer_binary` is the absolute path to the mTCP peer binary on the
/// AMI — per spec §11 the pre-installed location is
/// `/opt/mtcp-peer/bench-peer`. The real implementation will SSH to
/// the peer host and start this binary; the shape is already here so
/// downstream orchestration doesn't need a schema bump.
#[derive(Debug, Clone)]
pub struct MtcpConfig<'a> {
    /// Peer host — SSH target + IPv4 address for data-plane traffic.
    pub peer_ip: &'a str,
    pub peer_port: u16,
    /// Absolute path to the pre-installed mTCP peer binary on the AMI.
    pub peer_binary: &'a str,
    /// Burst size K in bytes.
    pub burst_bytes: u64,
    /// Idle gap G in milliseconds.
    pub gap_ms: u64,
    /// Burst count (post-warmup).
    pub bursts: u64,
    /// Warmup burst count (discarded).
    pub warmup: u64,
    /// MSS — must match dpdk_net side for the comparison to be valid.
    pub mss: u16,
}

/// Validate an [`MtcpConfig`] at the shape level. Returns `Err` with a
/// human-readable reason on any malformed field. Does NOT touch
/// libmtcp or SSH — safe to call in unit tests.
pub fn validate_config(cfg: &MtcpConfig<'_>) -> Result<(), String> {
    if cfg.peer_ip.is_empty() {
        return Err("mtcp: --peer-ip must be a non-empty address".to_string());
    }
    if cfg.peer_port == 0 {
        return Err("mtcp: --peer-port must be non-zero".to_string());
    }
    if cfg.peer_binary.is_empty() {
        return Err(
            "mtcp: --mtcp-peer-binary must be a non-empty path (expected \
             /opt/mtcp-peer/bench-peer on the baked AMI)"
                .to_string(),
        );
    }
    if !cfg.peer_binary.starts_with('/') {
        return Err(format!(
            "mtcp: --mtcp-peer-binary must be an absolute path, got `{}`",
            cfg.peer_binary
        ));
    }
    if cfg.burst_bytes == 0 {
        return Err("mtcp: burst_bytes (K) must be non-zero".to_string());
    }
    if cfg.bursts == 0 {
        return Err("mtcp: bursts must be non-zero".to_string());
    }
    if cfg.mss == 0 {
        return Err("mtcp: mss must be non-zero".to_string());
    }
    Ok(())
}

/// Stub entry point for the mTCP burst workload. Returns
/// `Error::Unimplemented` until the real implementation lands — see
/// the module docs for rationale + follow-up plan.
pub fn run_burst_workload(cfg: &MtcpConfig<'_>) -> Result<Vec<f64>, Error> {
    // Validate shape so the error surface matches what the real impl
    // will expose. Shape-validation failure still returns
    // `Unimplemented` to keep the caller's error flow flat — the real
    // impl will return a distinct error kind for malformed config.
    if validate_config(cfg).is_err() {
        return Err(Error::Unimplemented);
    }
    Err(Error::Unimplemented)
}

/// Configuration for an mTCP maxtp (W × C) run. Mirrors
/// [`MtcpConfig`] for the burst workload — the real implementation
/// will SSH to the peer host and start `/opt/mtcp-peer/bench-peer`.
#[derive(Debug, Clone)]
pub struct MaxtpConfig<'a> {
    /// Peer host — SSH target + IPv4 address for data-plane traffic.
    pub peer_ip: &'a str,
    pub peer_port: u16,
    /// Absolute path to the pre-installed mTCP peer binary on the AMI.
    pub peer_binary: &'a str,
    /// Application write size W in bytes.
    pub write_bytes: u64,
    /// Concurrent connection count C.
    pub conn_count: u64,
    /// Warmup window in seconds (spec §11.2: 10 s).
    pub warmup_secs: u64,
    /// Measurement window in seconds (spec §11.2: 60 s).
    pub duration_secs: u64,
    /// MSS — must match dpdk_net side for the comparison to be valid.
    pub mss: u16,
}

/// Validate a [`MaxtpConfig`] at the shape level. Returns `Err` with a
/// human-readable reason on any malformed field. Does NOT touch
/// libmtcp or SSH — safe to call in unit tests.
pub fn validate_maxtp_config(cfg: &MaxtpConfig<'_>) -> Result<(), String> {
    if cfg.peer_ip.is_empty() {
        return Err("mtcp: --peer-ip must be a non-empty address".to_string());
    }
    if cfg.peer_port == 0 {
        return Err("mtcp: --peer-port must be non-zero".to_string());
    }
    if cfg.peer_binary.is_empty() {
        return Err(
            "mtcp: --mtcp-peer-binary must be a non-empty path (expected \
             /opt/mtcp-peer/bench-peer on the baked AMI)"
                .to_string(),
        );
    }
    if !cfg.peer_binary.starts_with('/') {
        return Err(format!(
            "mtcp: --mtcp-peer-binary must be an absolute path, got `{}`",
            cfg.peer_binary
        ));
    }
    if cfg.write_bytes == 0 {
        return Err("mtcp: write_bytes (W) must be non-zero".to_string());
    }
    if cfg.conn_count == 0 {
        return Err("mtcp: conn_count (C) must be non-zero".to_string());
    }
    if cfg.duration_secs == 0 {
        return Err("mtcp: duration_secs (T) must be non-zero".to_string());
    }
    if cfg.mss == 0 {
        return Err("mtcp: mss must be non-zero".to_string());
    }
    Ok(())
}

/// Stub entry point for the mTCP maxtp workload. Returns
/// `Error::Unimplemented` until the real implementation lands — see
/// the module docs for rationale + follow-up plan.
///
/// Signature returns `Result<(f64, f64), Error>` — `(goodput_bps,
/// pps)` to match the `MaxtpSample` shape that
/// `crate::maxtp::BucketAggregate` expects.
pub fn run_maxtp_workload(cfg: &MaxtpConfig<'_>) -> Result<(f64, f64), Error> {
    if validate_maxtp_config(cfg).is_err() {
        return Err(Error::Unimplemented);
    }
    Err(Error::Unimplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_cfg() -> MtcpConfig<'static> {
        MtcpConfig {
            peer_ip: "10.0.0.42",
            peer_port: 10_001,
            peer_binary: "/opt/mtcp-peer/bench-peer",
            burst_bytes: 64 * 1024,
            gap_ms: 0,
            bursts: 10_000,
            warmup: 100,
            mss: 1460,
        }
    }

    #[test]
    fn validate_config_accepts_good_cfg() {
        assert!(validate_config(&good_cfg()).is_ok());
    }

    #[test]
    fn validate_config_rejects_empty_peer_ip() {
        let mut c = good_cfg();
        c.peer_ip = "";
        let err = validate_config(&c).unwrap_err();
        assert!(err.contains("peer-ip"));
    }

    #[test]
    fn validate_config_rejects_zero_port() {
        let mut c = good_cfg();
        c.peer_port = 0;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_empty_peer_binary() {
        let mut c = good_cfg();
        c.peer_binary = "";
        let err = validate_config(&c).unwrap_err();
        assert!(err.contains("peer-binary"));
    }

    #[test]
    fn validate_config_rejects_relative_peer_binary() {
        let mut c = good_cfg();
        c.peer_binary = "bench-peer";
        let err = validate_config(&c).unwrap_err();
        assert!(err.contains("absolute path"));
    }

    #[test]
    fn validate_config_rejects_zero_burst_bytes() {
        let mut c = good_cfg();
        c.burst_bytes = 0;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_zero_bursts() {
        let mut c = good_cfg();
        c.bursts = 0;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_zero_mss() {
        let mut c = good_cfg();
        c.mss = 0;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn stub_returns_unimplemented_for_good_cfg() {
        let c = good_cfg();
        let err = run_burst_workload(&c).unwrap_err();
        assert!(matches!(err, Error::Unimplemented));
    }

    #[test]
    fn stub_returns_unimplemented_for_bad_cfg() {
        let mut c = good_cfg();
        c.peer_ip = "";
        let err = run_burst_workload(&c).unwrap_err();
        assert!(matches!(err, Error::Unimplemented));
    }

    // -----------------------------------------------------------------
    // Maxtp stub — T13 analogue of the burst stub.
    // -----------------------------------------------------------------

    fn good_maxtp_cfg() -> MaxtpConfig<'static> {
        MaxtpConfig {
            peer_ip: "10.0.0.42",
            peer_port: 10_001,
            peer_binary: "/opt/mtcp-peer/bench-peer",
            write_bytes: 4096,
            conn_count: 4,
            warmup_secs: 10,
            duration_secs: 60,
            mss: 1460,
        }
    }

    #[test]
    fn validate_maxtp_config_accepts_good_cfg() {
        assert!(validate_maxtp_config(&good_maxtp_cfg()).is_ok());
    }

    #[test]
    fn validate_maxtp_config_rejects_empty_peer_ip() {
        let mut c = good_maxtp_cfg();
        c.peer_ip = "";
        assert!(validate_maxtp_config(&c).is_err());
    }

    #[test]
    fn validate_maxtp_config_rejects_zero_port() {
        let mut c = good_maxtp_cfg();
        c.peer_port = 0;
        assert!(validate_maxtp_config(&c).is_err());
    }

    #[test]
    fn validate_maxtp_config_rejects_relative_peer_binary() {
        let mut c = good_maxtp_cfg();
        c.peer_binary = "bench-peer";
        let err = validate_maxtp_config(&c).unwrap_err();
        assert!(err.contains("absolute path"));
    }

    #[test]
    fn validate_maxtp_config_rejects_zero_write_bytes() {
        let mut c = good_maxtp_cfg();
        c.write_bytes = 0;
        assert!(validate_maxtp_config(&c).is_err());
    }

    #[test]
    fn validate_maxtp_config_rejects_zero_conn_count() {
        let mut c = good_maxtp_cfg();
        c.conn_count = 0;
        assert!(validate_maxtp_config(&c).is_err());
    }

    #[test]
    fn validate_maxtp_config_rejects_zero_duration() {
        let mut c = good_maxtp_cfg();
        c.duration_secs = 0;
        assert!(validate_maxtp_config(&c).is_err());
    }

    #[test]
    fn validate_maxtp_config_rejects_zero_mss() {
        let mut c = good_maxtp_cfg();
        c.mss = 0;
        assert!(validate_maxtp_config(&c).is_err());
    }

    #[test]
    fn run_maxtp_workload_returns_unimplemented_for_good_cfg() {
        let c = good_maxtp_cfg();
        let err = run_maxtp_workload(&c).unwrap_err();
        assert!(matches!(err, Error::Unimplemented));
    }

    #[test]
    fn run_maxtp_workload_returns_unimplemented_for_bad_cfg() {
        let mut c = good_maxtp_cfg();
        c.peer_ip = "";
        let err = run_maxtp_workload(&c).unwrap_err();
        assert!(matches!(err, Error::Unimplemented));
    }
}
