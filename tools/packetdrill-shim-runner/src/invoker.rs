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
    // A8.5 T6: chdir into the script's directory before spawning the
    // shim. packetdrill's backtick init blocks use relative paths
    // (e.g. `../common/defaults.sh` in the google corpus, `scripts/
    // defaults.sh` in ligurio/shivansh) that real invocations resolve
    // against the script dir. Passing the script path through as
    // absolute keeps the binary's file-open working regardless of cwd.
    let script_abs = std::fs::canonicalize(script)
        .unwrap_or_else(|_| script.to_path_buf());
    let mut cmd = Command::new(shim_binary);
    cmd.arg(&script_abs);
    if let Some(parent) = script_abs.parent() {
        cmd.current_dir(parent);
    }
    let o = cmd.output().expect("spawn shim binary");
    RunOutcome {
        exit: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
        timed_out: false,
    }
}
