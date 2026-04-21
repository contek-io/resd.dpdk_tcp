//! SSH-to-peer netem driver.
//!
//! Spec §7 describes the two fault-injection paths:
//!
//! - **netem** — `tc qdisc add dev <iface> root netem <spec>` on the peer
//!   host. Applies at the wire level before the peer echoes the response.
//! - **FaultInjector** — A9's post-PMD-RX middleware on our side. Handled
//!   via the engine's `DPDK_NET_FAULT_INJECTOR` env var in `main.rs`.
//!
//! This module handles only the netem path. The public shape is a RAII
//! guard: `NetemGuard::apply(...)` installs the qdisc, `Drop` reverts it
//! (`tc qdisc del dev IFACE root`). We never rely on a signal handler —
//! if the process panics or is killed mid-run, a Stage 2 operator-side
//! janitor cron is the mitigation (spec §16); Stage 1 just gets the
//! happy path + panic-on-drop via Rust's normal unwind.
//!
//! SSH shell-out is chosen over a native netlink binding because:
//!
//! 1. netem is peer-side, not our host — netlink would need to reach
//!    the peer's network namespace, which is already a privileged
//!    concern regardless of transport.
//! 2. The driver runs once per scenario (matrix size = 8), so the
//!    few-hundred-ms SSH overhead is negligible against the per-scenario
//!    ≥100k-iteration RTT workload.
//! 3. Keeps the bench harness free of a `netlink-rs`/`rtnetlink` crate
//!    dependency — the bench tools deliberately stay pure-Rust + std +
//!    `bench_common`.

use std::process::Command;

/// RAII guard for a `tc qdisc add dev <iface> root netem <spec>` that
/// reverts to the clean qdisc state on drop. See module-level docs for
/// the rationale behind the SSH shell-out transport.
///
/// # Invariants
///
/// - `peer_ssh` is the SSH target (e.g. `ubuntu@10.0.0.43`) with keys
///   already configured in the caller's environment.
/// - `iface` is a peer-local network interface (e.g. `ens6`).
/// - `apply` blocks until the SSH command completes; on non-zero exit,
///   it returns an error and does NOT construct a guard (no cleanup is
///   attempted because no qdisc was installed).
/// - `Drop` runs the cleanup command but deliberately does not check its
///   result — on SSH failure during cleanup there is nothing the caller
///   can usefully do, and panicking in `Drop` would mask the original
///   error. Operators are expected to have the janitor cron from spec
///   §16 clean up orphan qdiscs.
#[derive(Debug)]
pub struct NetemGuard {
    /// SSH target (e.g. `user@host`).
    peer_ssh: String,
    /// Peer-local iface name (e.g. `ens6`).
    iface: String,
}

impl NetemGuard {
    /// Install a `tc qdisc add dev <iface> root netem <spec>` on the
    /// peer over SSH. Returns a `NetemGuard` that reverts on drop.
    ///
    /// `StrictHostKeyChecking=no` is set so bench runs in fresh AMIs
    /// don't block on the interactive host-key prompt — the peer
    /// identity is already constrained by the VPC + SG, which is the
    /// trust boundary for the bench run.
    pub fn apply(peer_ssh: &str, iface: &str, spec: &str) -> anyhow::Result<Self> {
        let cmd = format!("sudo tc qdisc add dev {iface} root netem {spec}");
        let out = Command::new("ssh")
            .args(["-o", "StrictHostKeyChecking=no", peer_ssh, &cmd])
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "netem apply failed (exit={:?}): {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(Self {
            peer_ssh: peer_ssh.to_string(),
            iface: iface.to_string(),
        })
    }

    /// Accessor for tests and the driver log line.
    pub fn peer_ssh(&self) -> &str {
        &self.peer_ssh
    }

    /// Accessor for tests and the driver log line.
    pub fn iface(&self) -> &str {
        &self.iface
    }
}

impl Drop for NetemGuard {
    fn drop(&mut self) {
        let cmd = format!("sudo tc qdisc del dev {} root", self.iface);
        // Best-effort: ignore the exit status. See invariant note on the
        // struct. We emit a stderr warning on non-success so operators
        // notice drifted qdisc state; this is not a panic because that
        // would mask the outer error.
        match Command::new("ssh")
            .args(["-o", "StrictHostKeyChecking=no", &self.peer_ssh, &cmd])
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!(
                    "bench-stress: NetemGuard drop: tc qdisc del returned {:?} \
                     on {}; peer may retain netem qdisc",
                    s.code(),
                    self.iface
                );
            }
            Err(e) => {
                eprintln!(
                    "bench-stress: NetemGuard drop: ssh failed: {e}; \
                     peer may retain netem qdisc on {}",
                    self.iface
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NetemGuard::apply` shells out to `ssh` which we don't have in the
    /// cargo test sandbox — verifying the Drop-on-failure contract here
    /// exercises only the fields, not a real SSH round-trip.
    #[test]
    fn netem_guard_field_accessors_reflect_constructor_args() {
        // Use the public fields directly because the constructor shells
        // out to ssh. Ugly but keeps the test hermetic; the real apply
        // path is exercised in the AMI-baked integration run.
        let g = NetemGuard {
            peer_ssh: "user@10.0.0.43".into(),
            iface: "ens6".into(),
        };
        assert_eq!(g.peer_ssh(), "user@10.0.0.43");
        assert_eq!(g.iface(), "ens6");
        // Drop will shell out to ssh and emit a stderr warning. The test
        // keeps running; we just assert construction + accessors work.
        drop(g);
    }
}
