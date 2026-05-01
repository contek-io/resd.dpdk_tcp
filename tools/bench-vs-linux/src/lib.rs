//! bench-vs-linux — library façade for the binary.
//!
//! A10 Plan B Task 8 (spec §8, parent spec §11.5). Exposes the mode
//! modules + stack-specific helpers so integration tests in `tests/`
//! can validate the pure-Rust primitives without touching DPDK/EAL.
//! The binary consumes the same modules via `use bench_vs_linux::*`.

pub mod afpacket;
pub mod linux_kernel;
pub mod mode_rtt;
pub mod mode_wire_diff;
// A10 Plan B Task 9: pcap divergence-normalisation for mode B.
pub mod normalize;

/// Stack identifier for CSV `dimensions_json` + mode-A iteration.
///
/// Three values for mode A (spec §8): `dpdk_net` (our stack),
/// `linux_kernel` (standard socket path), `afpacket` (AF_PACKET mmap
/// user-space delivery). The enum serialises to the lowercase string
/// form emitted into `dimensions_json.stack`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stack {
    DpdkNet,
    LinuxKernel,
    AfPacket,
}

impl Stack {
    /// CSV `dimensions_json.stack` string form. Stable, used by
    /// downstream bench-report to bucket rows by stack.
    pub const fn as_dimension(self) -> &'static str {
        match self {
            Stack::DpdkNet => "dpdk_net",
            Stack::LinuxKernel => "linux_kernel",
            Stack::AfPacket => "afpacket",
        }
    }

    /// Parse a single token from the `--stacks` CSV arg. Unknown
    /// tokens error; the parser in `main.rs` aggregates the errors.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "dpdk" | "dpdk_net" => Ok(Stack::DpdkNet),
            "linux" | "linux_kernel" | "kernel" => Ok(Stack::LinuxKernel),
            "afpacket" | "af_packet" => Ok(Stack::AfPacket),
            other => Err(format!(
                "unknown stack `{other}` (valid: dpdk, linux, afpacket)"
            )),
        }
    }
}

/// Mode selector: mode A (RTT, Task 8) vs. mode B (wire-diff, Task 9).
/// Task 9 delivers the pcap canonicalise + byte-diff engine and an
/// MVP runner that consumes pre-captured pcaps via `--local-pcap` /
/// `--peer-pcap`; live tcpdump+SSH capture orchestration is a Task 15
/// follow-up (see `src/mode_wire_diff.rs` module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Rtt,
    WireDiff,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "rtt" => Ok(Mode::Rtt),
            "wire-diff" | "wire_diff" => Ok(Mode::WireDiff),
            other => Err(format!("unknown mode `{other}` (valid: rtt, wire-diff)")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_parse_accepts_all_aliases() {
        assert_eq!(Stack::parse("dpdk").unwrap(), Stack::DpdkNet);
        assert_eq!(Stack::parse("dpdk_net").unwrap(), Stack::DpdkNet);
        assert_eq!(Stack::parse("linux").unwrap(), Stack::LinuxKernel);
        assert_eq!(Stack::parse("linux_kernel").unwrap(), Stack::LinuxKernel);
        assert_eq!(Stack::parse("kernel").unwrap(), Stack::LinuxKernel);
        assert_eq!(Stack::parse("afpacket").unwrap(), Stack::AfPacket);
        assert_eq!(Stack::parse("af_packet").unwrap(), Stack::AfPacket);
    }

    #[test]
    fn stack_parse_rejects_unknown() {
        let err = Stack::parse("garbage").unwrap_err();
        assert!(err.contains("unknown stack"));
    }

    #[test]
    fn stack_as_dimension_is_stable() {
        assert_eq!(Stack::DpdkNet.as_dimension(), "dpdk_net");
        assert_eq!(Stack::LinuxKernel.as_dimension(), "linux_kernel");
        assert_eq!(Stack::AfPacket.as_dimension(), "afpacket");
    }

    #[test]
    fn mode_parse_accepts_both_forms() {
        assert_eq!(Mode::parse("rtt").unwrap(), Mode::Rtt);
        assert_eq!(Mode::parse("wire-diff").unwrap(), Mode::WireDiff);
        assert_eq!(Mode::parse("wire_diff").unwrap(), Mode::WireDiff);
    }

    #[test]
    fn mode_parse_rejects_garbage() {
        assert!(Mode::parse("loopback").is_err());
    }
}
