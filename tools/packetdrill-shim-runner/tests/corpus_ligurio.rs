#![cfg(feature = "test-server")]
//! A7 T14: ligurio corpus runner. T15 pins counts; T14 lays the scaffold.
//!
//! A8.5 T9: extended with the "runnable-no-crash" verdict (spec §1.1 G +
//! §7 crash-safety corpus). Scripts under that verdict assert only that
//! the shim exits with a non-signal status (exit < 128) — signal kills
//! / SIGSEGV / SIGABRT produce exit codes > 128 and fail the gate.

use packetdrill_shim_runner::{
    classifier::{Classifier, Verdict},
    invoker,
    counts,
};
use std::path::PathBuf;
use walkdir::WalkDir;

const CORPUS_ROOT: &str = "../../third_party/packetdrill-testcases";

#[test]
fn ligurio_runnable_subset_passes() {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    let classifier = Classifier::load();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT);
    let mut runnable: Vec<PathBuf> = vec![];
    let mut no_crash: Vec<PathBuf> = vec![];
    let mut skip_untrans: Vec<(PathBuf, String)> = vec![];
    let mut skip_oos:    Vec<(PathBuf, String)> = vec![];

    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let path = entry.into_path();
        if path.extension().and_then(|e| e.to_str()) != Some("pkt") { continue; }
        match classifier.classify(&path) {
            Verdict::Runnable => runnable.push(path),
            Verdict::RunnableNoCrash(_) => no_crash.push(path),
            Verdict::SkippedUntranslatable(r) =>
                skip_untrans.push((path, r)),
            Verdict::SkippedOutOfScope(r) =>
                skip_oos.push((path, r)),
        }
    }

    // Orphan-skip check: every skipped script must appear in SKIPPED.md.
    let skipped_md = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/packetdrill-shim/SKIPPED.md")
    ).expect("read SKIPPED.md");
    for (p, _) in skip_untrans.iter().chain(skip_oos.iter()) {
        let key = p.strip_prefix(&root).unwrap().to_string_lossy();
        assert!(skipped_md.contains(&*key),
            "orphan skip: {} not documented in SKIPPED.md", key);
    }

    // Run every runnable script (exit-0 gate).
    let mut failed: Vec<(PathBuf, invoker::RunOutcome)> = vec![];
    for s in &runnable {
        let out = invoker::run_script(&bin, s);
        if out.exit != 0 { failed.push((s.clone(), out)); }
    }
    assert!(failed.is_empty(),
        "{} of {} runnable scripts failed. Examples:\n{}",
        failed.len(), runnable.len(),
        failed.iter().take(5).map(|(p, o)|
            format!("- {}: exit={} stderr={}", p.display(), o.exit, o.stderr)
        ).collect::<Vec<_>>().join("\n"));

    // A8.5 T9: run every runnable-no-crash script and assert non-
    // signal exit (exit in 0..=128). Exit 1 is expected because the
    // engine does not model the behavior under test (ICMP ingress,
    // PMTU state, bad-arg error shapes); the gate catches SIGSEGV /
    // SIGABRT / signal kills, which manifest as exit > 128.
    let mut crashed: Vec<(PathBuf, invoker::RunOutcome)> = vec![];
    for s in &no_crash {
        let out = invoker::run_script(&bin, s);
        if out.exit > 128 || out.exit < 0 || out.timed_out {
            crashed.push((s.clone(), out));
        }
    }
    assert!(crashed.is_empty(),
        "{} of {} runnable-no-crash scripts crashed (exit > 128 / timed out). Examples:\n{}",
        crashed.len(), no_crash.len(),
        crashed.iter().take(5).map(|(p, o)|
            format!("- {}: exit={} timed_out={} stderr={}",
                p.display(), o.exit, o.timed_out, o.stderr)
        ).collect::<Vec<_>>().join("\n"));

    // Pinned-count check (T15 fills in the real values).
    assert_eq!(runnable.len(),     counts::LIGURIO_RUNNABLE_COUNT,
        "runnable count drift — update counts::LIGURIO_RUNNABLE_COUNT");
    assert_eq!(no_crash.len(),     counts::LIGURIO_NO_CRASH_COUNT,
        "no-crash count drift — update counts::LIGURIO_NO_CRASH_COUNT");
    assert_eq!(skip_untrans.len(), counts::LIGURIO_SKIP_UNTRANSLATABLE);
    assert_eq!(skip_oos.len(),     counts::LIGURIO_SKIP_OUT_OF_SCOPE);
}

/// A8.5 T9: soak-test the crash-safety corpus under CI control.
///
/// The main `ligurio_runnable_subset_passes` test runs each no-crash
/// script exactly once per `cargo test` invocation. That catches a
/// deterministic SIGSEGV but not a low-rate flake. This `#[ignore]`
/// test loops `LIGURIO_SOAK_ITERS` (env, default 100) per no-crash
/// script and gates on signal-kill the same way. Run via:
///
///   LIGURIO_SOAK_ITERS=100 cargo test -p packetdrill-shim-runner \
///     --features test-server --test corpus_ligurio -- --ignored \
///     ligurio_no_crash_soak
///
/// Zero crashes across N × 6 iterations proves the invariant at a
/// higher confidence than single-run CI.
#[test]
#[ignore]
fn ligurio_no_crash_soak() {
    let iters: usize = std::env::var("LIGURIO_SOAK_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    let classifier = Classifier::load();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT);

    let mut no_crash: Vec<PathBuf> = vec![];
    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let path = entry.into_path();
        if path.extension().and_then(|e| e.to_str()) != Some("pkt") { continue; }
        if let Verdict::RunnableNoCrash(_) = classifier.classify(&path) {
            no_crash.push(path);
        }
    }
    assert_eq!(no_crash.len(), counts::LIGURIO_NO_CRASH_COUNT);

    let mut crashes: Vec<(PathBuf, usize, invoker::RunOutcome)> = vec![];
    for script in &no_crash {
        for i in 0..iters {
            let out = invoker::run_script(&bin, script);
            if out.exit > 128 || out.exit < 0 || out.timed_out {
                crashes.push((script.clone(), i, out));
                break;
            }
        }
    }
    assert!(crashes.is_empty(),
        "{} crash(es) observed across {} × {} iterations. Examples:\n{}",
        crashes.len(), no_crash.len(), iters,
        crashes.iter().take(5).map(|(p, i, o)|
            format!("- {} (iter {}): exit={} timed_out={} stderr={}",
                p.display(), i, o.exit, o.timed_out, o.stderr)
        ).collect::<Vec<_>>().join("\n"));
}
