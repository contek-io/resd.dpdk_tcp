#![cfg(feature = "test-server")]
//! A7 T14: ligurio corpus runner. T15 pins counts; T14 lays the scaffold.
//!
//! Currently runs every classifier-runnable script through the shim
//! binary and asserts each exits 0. Also asserts LIGURIO_RUNNABLE_COUNT
//! and LIGURIO_SKIP_* match the pinned constants in counts.rs.

use packetdrill_shim_runner::{
    classifier::{Classifier, Verdict},
    invoker,
    counts,
};
use std::path::PathBuf;
use walkdir::WalkDir;

const CORPUS_ROOT: &str = "../../third_party/packetdrill-testcases";

#[test]
#[ignore = "T15 pins counts; enable when classify/ligurio.toml + counts.rs are final"]
fn ligurio_runnable_subset_passes() {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    let classifier = Classifier::load();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT);
    let mut runnable: Vec<PathBuf> = vec![];
    let mut skip_untrans: Vec<(PathBuf, String)> = vec![];
    let mut skip_oos:    Vec<(PathBuf, String)> = vec![];

    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let path = entry.into_path();
        if path.extension().and_then(|e| e.to_str()) != Some("pkt") { continue; }
        match classifier.classify(&path) {
            Verdict::Runnable => runnable.push(path),
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

    // Run every runnable script.
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

    // Pinned-count check (T15 fills in the real values).
    assert_eq!(runnable.len(),     counts::LIGURIO_RUNNABLE_COUNT,
        "runnable count drift — update counts::LIGURIO_RUNNABLE_COUNT");
    assert_eq!(skip_untrans.len(), counts::LIGURIO_SKIP_UNTRANSLATABLE);
    assert_eq!(skip_oos.len(),     counts::LIGURIO_SKIP_OUT_OF_SCOPE);
}
