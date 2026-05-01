//! CLI parse + selection smoke tests. No DPDK / EAL — exercises only
//! arg parsing, scenario filter, single-FI-spec invariant, --force
//! semantics, and --list-scenarios short-circuit.

use std::process::Command;
use std::path::PathBuf;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_layer-h-correctness"))
}

fn cmd() -> Command {
    Command::new(binary_path())
}

fn must_args() -> Vec<&'static str> {
    vec![
        "--peer-ip", "10.0.0.43",
        "--local-ip", "10.0.0.42",
        "--gateway-ip", "10.0.0.1",
        "--eal-args", "-l 2-3 -n 4",
        "--report-md", "/tmp/__layer-h-test-report.md",
        "--external-netem",
    ]
}

#[test]
fn list_scenarios_prints_all_pure_netem_rows_by_default() {
    let mut c = cmd();
    c.args(must_args());
    c.arg("--list-scenarios");
    let out = c.output().expect("run binary");
    assert!(out.status.success(), "{:?}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Empty --scenarios resolves to the 14 pure-netem rows (composed
    // excluded by the single-FI-spec invariant).
    let lines = stdout.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(lines, 14, "expected 14, got:\n{stdout}");
    assert!(stdout.contains("delay_20ms"));
    assert!(stdout.contains("corruption_001pct"));
    assert!(!stdout.contains("composed_loss_1pct_50ms_fi_drop"));
}

#[test]
fn smoke_resolves_to_five_scenarios() {
    let mut c = cmd();
    c.args(must_args());
    c.args(["--smoke", "--list-scenarios"]);
    let out = c.output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<_> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 5, "expected 5 smoke scenarios, got:\n{stdout}");
    for n in [
        "delay_50ms_jitter_10ms",
        "loss_1pct",
        "dup_2pct",
        "reorder_depth_3",
        "corruption_001pct",
    ] {
        assert!(lines.contains(&n), "missing {n} in {lines:?}");
    }
}

#[test]
fn explicit_scenarios_filter_resolves_named_subset() {
    let mut c = cmd();
    c.args(must_args());
    c.args(["--scenarios", "delay_20ms,loss_1pct", "--list-scenarios"]);
    let out = c.output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("delay_20ms"));
    assert!(stdout.contains("loss_1pct"));
    let lines = stdout.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(lines, 2);
}

#[test]
fn smoke_and_scenarios_are_mutually_exclusive() {
    let mut c = cmd();
    c.args(must_args());
    c.args(["--smoke", "--scenarios", "delay_20ms"]);
    let out = c.output().unwrap();
    // clap's conflicts_with surfaces as a parse failure (exit 2 by clap).
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("the argument") && stderr.contains("cannot be used with"),
        "expected clap conflict message, got:\n{stderr}"
    );
}

#[test]
fn unknown_scenario_name_exits_two() {
    let mut c = cmd();
    c.args(must_args());
    c.args(["--scenarios", "this_scenario_does_not_exist", "--list-scenarios"]);
    let out = c.output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn two_distinct_fi_specs_in_selection_exits_two() {
    // composed_loss_1pct_50ms_fi_drop has FI spec drop=0.005;
    // composed_loss_1pct_50ms_fi_dup  has FI spec dup=0.005.
    // Selecting both in one process invocation violates the
    // single-FI-spec invariant.
    let mut c = cmd();
    c.args(must_args());
    c.args([
        "--scenarios",
        "composed_loss_1pct_50ms_fi_drop,composed_loss_1pct_50ms_fi_dup",
        "--list-scenarios",
    ]);
    let out = c.output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("FaultInjector") || stderr.contains("FI spec"),
        "expected FI-spec error message, got:\n{stderr}"
    );
}

#[test]
fn report_md_clobber_without_force_exits_two() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.md");
    std::fs::write(&report, "preexisting").unwrap();

    let mut c = cmd();
    c.args(["--peer-ip", "10.0.0.43"]);
    c.args(["--local-ip", "10.0.0.42"]);
    c.args(["--gateway-ip", "10.0.0.1"]);
    c.args(["--eal-args", "-l 2-3 -n 4"]);
    c.arg("--external-netem");
    c.args(["--report-md", report.to_str().unwrap()]);
    c.arg("--list-scenarios");
    let out = c.output().unwrap();
    // Clobber is checked even on --list-scenarios? Spec §7 says "path
    // exists without --force ⇒ exit 2", and the check runs at startup
    // before --list-scenarios takes its short-circuit. Verify the
    // documented contract.
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn report_md_clobber_with_force_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.md");
    std::fs::write(&report, "preexisting").unwrap();

    let mut c = cmd();
    c.args(["--peer-ip", "10.0.0.43"]);
    c.args(["--local-ip", "10.0.0.42"]);
    c.args(["--gateway-ip", "10.0.0.1"]);
    c.args(["--eal-args", "-l 2-3 -n 4"]);
    c.arg("--external-netem");
    c.args(["--report-md", report.to_str().unwrap()]);
    c.arg("--force");
    c.arg("--list-scenarios");
    let out = c.output().unwrap();
    assert!(out.status.success(), "{:?}", String::from_utf8_lossy(&out.stderr));
}
