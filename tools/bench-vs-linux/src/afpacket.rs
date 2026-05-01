//! AF_PACKET mmap stack path (spec §8, parent spec §11.5).
//!
//! # Scope deferral — Stage 1 Task 8
//!
//! The spec's three-way comparison (dpdk_net, linux_kernel, afpacket)
//! requires an AF_PACKET mmap client that speaks full TCP to the peer
//! — the peer runs a standard TCP echo-server, so the AF_PACKET side
//! must generate its own SYN/SYN-ACK/ACK handshake, track seq/ack,
//! reply to the peer's MAC ARPs if needed, and verify each echoed
//! segment matches the request payload. That's a mini TCP client, not
//! a measurement primitive, and is substantially more scope than
//! T8 can absorb without delaying T9 (wire-diff) and T10-onwards.
//!
//! T8 therefore ships with the AF_PACKET path stubbed to
//! `Unimplemented`. Caller's `--stacks` arg must omit `afpacket` in
//! T8 runs (or the CLI errors at startup). The stub is wired through
//! the same return shape as the other stacks so the caller-side
//! plumbing is already in place for a drop-in implementation.
//!
//! # Follow-up
//!
//! The implementation lands as part of either:
//! - A10 follow-up task (outside Plan B's 14-task scope), or
//! - Stage 2, once the production wire-diff path (T9) is stable and a
//!   vetted TCP state machine is available to reuse rather than
//!   handcrafting a parallel one here.
//!
//! Both options keep the AF_PACKET baseline as a single-binary
//! deliverable so nightly bench runs can invoke it with `--stacks
//! afpacket` once available. The CSV shape (`dimensions_json.stack =
//! "afpacket"`) is fixed by `Stack::AfPacket.as_dimension()` and
//! won't change when the implementation lands.

/// Marker error returned by [`run_rtt_workload`] while the stack is
/// stubbed. Caller surfaces this as a hard error in strict
/// precondition mode and as a skip + warn in lenient mode.
#[derive(Debug, thiserror::Error)]
pub enum AfPacketError {
    #[error("AF_PACKET stack is stubbed in Plan B T8 — see src/afpacket.rs module docs")]
    Unimplemented,
}

/// Configuration for an AF_PACKET RTT run. Fields are filled in by
/// `main.rs` and validated by the helper below so the stub rejects
/// invalid configs (e.g. empty iface name) before it surfaces the
/// deferral error, matching what the real implementation will do.
#[derive(Debug, Clone)]
pub struct AfPacketConfig<'a> {
    pub iface: &'a str,
    pub peer_ip_host_order: u32,
    pub peer_port: u16,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub warmup: u64,
    pub iterations: u64,
}

/// Validate an [`AfPacketConfig`] at the shape level. Returns `Err`
/// with a human-readable reason on any malformed field. Does NOT
/// touch the kernel — safe to call in unit tests.
pub fn validate_config(cfg: &AfPacketConfig<'_>) -> Result<(), String> {
    if cfg.iface.is_empty() {
        return Err("afpacket: --peer-iface must be a non-empty iface name".to_string());
    }
    if cfg.iface.len() > libc::IFNAMSIZ {
        return Err(format!(
            "afpacket: --peer-iface `{}` exceeds IFNAMSIZ={}",
            cfg.iface,
            libc::IFNAMSIZ
        ));
    }
    if cfg.peer_port == 0 {
        return Err("afpacket: --peer-port must be non-zero".to_string());
    }
    if cfg.request_bytes == 0 {
        return Err("afpacket: --request-bytes must be non-zero".to_string());
    }
    if cfg.response_bytes == 0 {
        return Err("afpacket: --response-bytes must be non-zero".to_string());
    }
    if cfg.iterations == 0 {
        return Err("afpacket: --iterations must be non-zero".to_string());
    }
    Ok(())
}

/// Stub entry point for the AF_PACKET RTT workload. Returns
/// `AfPacketError::Unimplemented` until the real implementation
/// lands — see the module docs for rationale + follow-up plan.
pub fn run_rtt_workload(cfg: &AfPacketConfig<'_>) -> Result<Vec<f64>, AfPacketError> {
    // Validate shape so the error message matches what the real impl
    // will surface. Validation failure is still reported as
    // `Unimplemented` — the real impl would return a different error
    // kind for malformed config, but here we keep the surface flat.
    if validate_config(cfg).is_err() {
        return Err(AfPacketError::Unimplemented);
    }
    Err(AfPacketError::Unimplemented)
}

/// Compose a minimal Ethernet + IPv4 + TCP header triplet for the
/// future wire-level implementation. Currently unused by the stub;
/// exposed so unit tests can validate the frame layout that the real
/// impl will generate, and to pin the layout byte counts for Stage 2.
///
/// Returns the total frame length (Ethernet + IPv4 + TCP, no payload).
/// The sizes are the fixed portions only: IPv4 with no options
/// (20 B), TCP with no options (20 B). Real SYN frames will add
/// MSS/SACK-permitted/WS options; that's deferred to the impl.
pub const fn min_frame_len() -> usize {
    // Ethernet II = 14, IPv4 min = 20, TCP min = 20.
    14 + 20 + 20
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_cfg() -> AfPacketConfig<'static> {
        AfPacketConfig {
            iface: "ens6",
            peer_ip_host_order: 0x0A00_002A,
            peer_port: 10_001,
            request_bytes: 128,
            response_bytes: 128,
            warmup: 100,
            iterations: 10_000,
        }
    }

    #[test]
    fn validate_config_accepts_good_cfg() {
        assert!(validate_config(&good_cfg()).is_ok());
    }

    #[test]
    fn validate_config_rejects_empty_iface() {
        let mut c = good_cfg();
        c.iface = "";
        let err = validate_config(&c).unwrap_err();
        assert!(err.contains("non-empty iface"));
    }

    #[test]
    fn validate_config_rejects_overlong_iface() {
        let long_name = "x".repeat(libc::IFNAMSIZ + 1);
        let c = AfPacketConfig {
            iface: &long_name,
            ..good_cfg()
        };
        let err = validate_config(&c).unwrap_err();
        assert!(err.contains("IFNAMSIZ"));
    }

    #[test]
    fn validate_config_rejects_zero_port() {
        let mut c = good_cfg();
        c.peer_port = 0;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_rejects_zero_bytes() {
        let mut c = good_cfg();
        c.request_bytes = 0;
        assert!(validate_config(&c).is_err());

        let mut c2 = good_cfg();
        c2.response_bytes = 0;
        assert!(validate_config(&c2).is_err());
    }

    #[test]
    fn validate_config_rejects_zero_iterations() {
        let mut c = good_cfg();
        c.iterations = 0;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn stub_returns_unimplemented_for_good_cfg() {
        let c = good_cfg();
        let err = run_rtt_workload(&c).unwrap_err();
        assert!(matches!(err, AfPacketError::Unimplemented));
    }

    #[test]
    fn stub_returns_unimplemented_for_bad_cfg() {
        let mut c = good_cfg();
        c.iface = "";
        let err = run_rtt_workload(&c).unwrap_err();
        assert!(matches!(err, AfPacketError::Unimplemented));
    }

    #[test]
    fn min_frame_len_is_54_bytes() {
        // Ethernet (14) + IPv4 (20) + TCP (20) = 54.
        assert_eq!(min_frame_len(), 54);
    }
}
