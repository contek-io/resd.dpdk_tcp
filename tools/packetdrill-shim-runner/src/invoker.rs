//! A7: invoke the patched packetdrill binary on one .pkt script.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub struct RunOutcome {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Run one script through the shim binary. Each script runs in its own
/// subprocess per A7 spec §3 — anchors virtual-clock thread-local reset
/// and panic-abort isolation.
///
/// `wall_timeout` is the hard real-time bound on the subprocess. Virtual
/// time inside the script is unrelated. 30 s is plenty for any
/// single ligurio script.
pub fn run_script(shim_binary: &Path, script: &Path) -> RunOutcome {
    run_script_with_timeout(shim_binary, script, Duration::from_secs(30))
}

pub fn run_script_with_timeout(
    shim_binary: &Path,
    script: &Path,
    wall_timeout: Duration,
) -> RunOutcome {
    let _ = wall_timeout;  // T11+ wires a real timeout via wait_timeout / kill.
    let o = Command::new(shim_binary)
        .arg(script)
        .output()
        .expect("spawn shim binary");
    RunOutcome {
        exit: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
        timed_out: false,
    }
}
