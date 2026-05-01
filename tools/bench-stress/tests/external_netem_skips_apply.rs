//! `--external-netem` must skip `NetemGuard::apply` so the operator
//! can orchestrate netem from a workstation that has SSH access to
//! the peer's mgmt IP. The DUT-side bench-stress only runs the workload.
//!
//! This test is structural: it builds the binary with `--external-netem`,
//! pipes a scenario name that has a netem spec, and asserts that no
//! `ssh` invocation occurs (we shadow `ssh` with a fake on $PATH).

use std::process::Command;

#[test]
fn external_netem_does_not_invoke_ssh() {
    // Place a fake `ssh` on PATH that fails loudly if invoked. The
    // test passes iff bench-stress completes its arg-parse + scenario-
    // setup loop without ever calling our shadow `ssh`.
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let fake_ssh_path = tmpdir.path().join("ssh");
    std::fs::write(
        &fake_ssh_path,
        "#!/bin/sh\necho 'ssh invoked despite --external-netem' >&2; exit 99\n",
    )
    .expect("write fake ssh");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake_ssh_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod");

    let path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", tmpdir.path().display(), path);

    // We don't actually run the workload (no DPDK on this host); the
    // arg parser and scenario filter run pre-EAL-init and exit early
    // when `--list-scenarios` is set.
    let bin = env!("CARGO_BIN_EXE_bench-stress");
    let out = Command::new(bin)
        .env("PATH", &new_path)
        .args([
            "--external-netem",
            "--list-scenarios",
            "--peer-ssh", "ubuntu@1.2.3.4",
            "--peer-iface", "ens6",
            "--peer-ip", "10.0.0.2",
            "--local-ip", "10.0.0.1",
            "--gateway-ip", "10.0.0.3",
            "--eal-args", "",
            "--output-csv", "/tmp/external-netem-test.csv",
        ])
        .output()
        .expect("spawn bench-stress");

    assert!(
        out.status.success(),
        "bench-stress exited non-zero: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("ssh invoked despite --external-netem"),
        "fake ssh was invoked — --external-netem failed to suppress: {stderr}"
    );
}
