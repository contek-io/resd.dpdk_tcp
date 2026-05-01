//! Peer receive-window introspection via SSH + `ss -ti`.
//!
//! A10 Plan B T15-B / T12-I4 — replaces the `peer_rwnd = K`
//! placebo-pass with a real read of the peer-side kernel TCP socket's
//! advertised receive window.
//!
//! # Transport choice
//!
//! We shell out to `ssh <peer> "ss -ti state established '( sport = :<N>
//! and dst = <dut_ip> )'"` and parse the textual output. The filter
//! uses `sport` (the peer's source port is the listen port our DUT
//! connected to) and pins on `dst = <dut_ip>` so a side-channel
//! socket bound to the same listen port on the peer cannot confuse
//! the scrape (I-2). `ss`'s kernel interface (netlink
//! INET_DIAG) is not exposed through a stable Rust binding at the
//! moment, and pulling a new crate (`netlink-packet-*` or `tokio-diag`)
//! into the benchmark harness would bloat the DPDK build closure. The
//! per-bucket overhead of an SSH invocation is ~100 ms which is
//! negligible against the per-bucket workload time (seconds to
//! minutes). The same SSH-shell-out trade-off is already made in
//! `bench-stress/src/netem.rs`, so we mirror its pattern:
//! `StrictHostKeyChecking=no` + absolute command string + bail on
//! non-zero exit.
//!
//! # `ss -ti` field shape
//!
//! The per-connection `ss -ti` block looks (condensed, one connection)
//! like:
//!
//! ```text
//! ESTAB 0 0 10.0.0.2:10001 10.0.0.1:40000
//!     ts sack cubic wscale:7,7 rto:204 rtt:0.06/0.03 ato:40 mss:1460 \
//!     pmtu:1500 rcvmss:1460 advmss:1460 cwnd:10 ssthresh:7 \
//!     bytes_sent:0 bytes_acked:1 segs_out:1 segs_in:2 send 1947Mbps \
//!     lastsnd:12 lastrcv:12 lastack:12 pacing_rate 3895Mbps \
//!     delivered:1 app_limited rcv_space:14480 rcv_ssthresh:64088 \
//!     minrtt:0.06 snd_wnd:64256
//! ```
//!
//! We key on the `rcv_space:<N>` field and (optionally) clamp against
//! `rcv_ssthresh:<N>` — `rcv_space` is the kernel's current estimate of
//! the receive window that it is advertising (same units: bytes); the
//! peer-side receive window seen on-wire is
//! `min(rcv_space, rcv_ssthresh)` post the slow-start-expansion guard.
//! Either field missing is treated as "parsing failed, do not report a
//! value" — the caller decides whether to fall back to the placebo.
//!
//! # Retry shape
//!
//! A just-established connection may not show up in `ss` immediately
//! (race between `accept()` return on peer and the socket becoming
//! visible in `/proc/net/tcp`). We retry up to 3 times with 500 ms
//! backoff, which empirically covers the connection-setup window on
//! c6in.metal.

use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, Context};

/// Fetch the peer-side advertised receive window for the single
/// established connection matching `peer_port` and our DUT's IP.
///
/// Returns the clamped window `min(rcv_space, rcv_ssthresh)` if both
/// fields are parseable. If only `rcv_space` is available, returns
/// that. If neither is available, returns an error.
///
/// # Arguments
///
/// - `peer_ssh` — SSH target (e.g. `ubuntu@10.0.0.2`).
/// - `dut_ip` — the DUT's IPv4 address. Used as `dst = <dut_ip>` in
///   the `ss` filter so side-channel sockets bound to the same listen
///   port on the peer cannot confuse the rwnd scrape (T15-B I-2).
/// - `peer_port` — the TCP source-port on the peer side (the peer's
///   listen port, i.e. the DUT's dest port). Used to filter `ss`
///   output down to our connection.
///
/// # Retries
///
/// Retries up to 3 times with 500 ms sleep between attempts on
/// SSH-process-level failure or empty `ss` output (connection not yet
/// visible).
pub fn fetch_peer_rwnd_bytes(
    peer_ssh: &str,
    dut_ip: Ipv4Addr,
    peer_port: u16,
) -> anyhow::Result<u32> {
    const MAX_ATTEMPTS: usize = 3;
    const BACKOFF: Duration = Duration::from_millis(500);

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match fetch_peer_rwnd_bytes_once(peer_ssh, dut_ip, peer_port) {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                if attempt < MAX_ATTEMPTS {
                    std::thread::sleep(BACKOFF);
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("fetch_peer_rwnd_bytes: no error recorded")))
}

/// One-shot (no retry) SSH round-trip. Split out of the retry loop so
/// the retry policy is testable in isolation of the parser.
fn fetch_peer_rwnd_bytes_once(
    peer_ssh: &str,
    dut_ip: Ipv4Addr,
    peer_port: u16,
) -> anyhow::Result<u32> {
    let cmd = build_ss_command(dut_ip, peer_port);
    let out = Command::new("ssh")
        .args(["-o", "StrictHostKeyChecking=no", peer_ssh, &cmd])
        .output()
        .with_context(|| format!("spawning ssh to {peer_ssh}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "ss on peer failed (exit={:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_rcv_window(&stdout)
}

/// Build the `ss -ti` filter string. Extracted for unit-test
/// visibility: the filter body is the load-bearing I-2 fix and the
/// test suite pins it end-to-end (sport + dst, both required).
fn build_ss_command(dut_ip: Ipv4Addr, peer_port: u16) -> String {
    format!(
        "ss -tni state established '( sport = :{peer_port} and dst = {dut_ip} )'",
    )
}

/// Parse the `rcv_space` (and optionally `rcv_ssthresh`) numeric field
/// out of an `ss -ti` output blob. The two fields may appear on any
/// continuation line of any connection block; we take the first match.
///
/// Returns `Err` if `rcv_space` is absent.
pub fn parse_rcv_window(ss_output: &str) -> anyhow::Result<u32> {
    let rcv_space = extract_numeric_field(ss_output, "rcv_space:")?;
    let rcv_ssthresh = extract_numeric_field(ss_output, "rcv_ssthresh:").ok();
    let val = match rcv_ssthresh {
        Some(ssthresh) => rcv_space.min(ssthresh),
        None => rcv_space,
    };
    Ok(val)
}

/// Extract the first `<prefix><u32>` hit from `text`. Prefix is the
/// full token including the trailing colon (e.g. `"rcv_space:"`). The
/// number is read as decimal digits terminated by whitespace or any
/// non-digit; `ss`'s default output doesn't emit suffixes on these
/// fields (unlike `cwnd` in some builds), so this is sufficient.
fn extract_numeric_field(text: &str, prefix: &str) -> anyhow::Result<u32> {
    let start = text
        .find(prefix)
        .ok_or_else(|| anyhow!("`{prefix}` field not found in ss output"))?;
    let rest = &text[start + prefix.len()..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return Err(anyhow!("`{prefix}` present but empty"));
    }
    rest[..end]
        .parse::<u32>()
        .with_context(|| format!("parsing `{prefix}<N>` as u32 from ss output"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exemplary `ss -ti` output for a single established connection
    /// with a kernel peer that has already emitted a few ACKs.
    /// Captured from a real `ss -tni state established` run on Ubuntu
    /// 22.04 with kernel 5.15, trimmed to the minimum fields we rely on
    /// plus surrounding cruft to prove the extractor is robust.
    const SAMPLE: &str = "ESTAB 0 0 10.0.0.2:10001 10.0.0.1:40000\n\
         \t ts sack cubic wscale:7,7 rto:204 rtt:0.06/0.03 ato:40 \
         mss:1460 pmtu:1500 rcvmss:1460 advmss:1460 cwnd:10 ssthresh:7 \
         bytes_sent:0 bytes_acked:1 segs_out:1 segs_in:2 send 1947Mbps \
         lastsnd:12 lastrcv:12 lastack:12 pacing_rate 3895Mbps \
         delivered:1 app_limited rcv_space:14480 rcv_ssthresh:64088 \
         minrtt:0.06 snd_wnd:64256\n";

    #[test]
    fn parse_clamps_rcv_space_against_rcv_ssthresh() {
        // rcv_space = 14480, rcv_ssthresh = 64088 → min = 14480.
        let w = parse_rcv_window(SAMPLE).expect("parse");
        assert_eq!(w, 14480);
    }

    #[test]
    fn parse_returns_rcv_space_when_ssthresh_absent() {
        let txt = "ESTAB 0 0 x y\n\t foo:1 rcv_space:8192 bar:2\n";
        let w = parse_rcv_window(txt).expect("parse");
        assert_eq!(w, 8192);
    }

    #[test]
    fn parse_prefers_smaller_of_space_and_ssthresh() {
        let txt = "rcv_space:65535 rcv_ssthresh:1024 other:99\n";
        let w = parse_rcv_window(txt).expect("parse");
        assert_eq!(w, 1024);
    }

    #[test]
    fn parse_errors_when_rcv_space_missing() {
        let txt = "ESTAB 0 0 x y\n\t advmss:1460 cwnd:10\n";
        let err = parse_rcv_window(txt).unwrap_err();
        assert!(format!("{err}").contains("rcv_space"));
    }

    #[test]
    fn parse_errors_when_rcv_space_has_no_digits() {
        let txt = "rcv_space: extra";
        let err = parse_rcv_window(txt).unwrap_err();
        assert!(
            format!("{err}").contains("rcv_space"),
            "expected rcv_space diagnostic, got `{err}`"
        );
    }

    #[test]
    fn parse_takes_first_match_with_multiple_connections() {
        // Two connections; only the first should be read. This keeps
        // the extractor predictable when ss returns >1 socket that
        // matches the filter (e.g. TIME_WAIT lingering).
        let txt = "ESTAB 0 0 x y\n\t rcv_space:16384 rcv_ssthresh:32768\n\
             ESTAB 0 0 a b\n\t rcv_space:999 rcv_ssthresh:999\n";
        let w = parse_rcv_window(txt).expect("parse");
        assert_eq!(w, 16384);
    }

    #[test]
    fn extract_numeric_field_terminates_on_whitespace() {
        let v = extract_numeric_field("rcv_space:1234 other:5", "rcv_space:").expect("extract");
        assert_eq!(v, 1234);
    }

    #[test]
    fn extract_numeric_field_terminates_on_non_digit() {
        let v = extract_numeric_field("rcv_space:1234,other", "rcv_space:").expect("extract");
        assert_eq!(v, 1234);
    }

    #[test]
    fn extract_numeric_field_terminates_at_eof() {
        let v = extract_numeric_field("rcv_space:7777", "rcv_space:").expect("extract");
        assert_eq!(v, 7777);
    }

    #[test]
    fn ss_command_includes_sport_and_dst_filter() {
        // T15-B I-2: the filter MUST pin both `sport = :<peer_port>`
        // AND `dst = <dut_ip>`. If a side-channel socket on the peer
        // happens to share the listen port but talks to a different
        // peer, the `dst` clause forces `ss` to show only the
        // DUT-originated connection we care about.
        let dut_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let cmd = build_ss_command(dut_ip, 10_001);
        assert!(
            cmd.contains("sport = :10001"),
            "expected sport filter, got `{cmd}`"
        );
        assert!(
            cmd.contains("dst = 10.0.0.1"),
            "expected dst-IP filter, got `{cmd}`"
        );
        // Also confirm the `and` conjunction is present — a stray
        // comma or OR would defeat the purpose of the pinning.
        assert!(
            cmd.contains(" and "),
            "expected `and` between filters, got `{cmd}`"
        );
    }
}
