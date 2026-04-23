#![cfg(feature = "test-server")]
//! A8 T16: Google upstream packetdrill tests corpus runner.
//!
//! Mirrors tests/corpus_ligurio.rs. Classifier TOML lives at
//! tools/packetdrill-shim/classify/google.toml and is read at
//! test-runtime (not `include_str!`, because `include_str!` requires a
//! literal path and can't be parameterized across corpora).
//!
//! The Google corpus lives *inside* the packetdrill submodule at
//! third_party/packetdrill/gtests/ — the corpus root is the entire
//! submodule root; the classifier regex matches on
//! `gtests/net/tcp/<category>/<script>.pkt` paths. 167 scripts total,
//! 0 runnable at A8 (the pragmatic floor; 163 need defaults.sh host-env,
//! 4 need engine-feature gaps).

use packetdrill_shim_runner::{
    classifier::{Classifier, Verdict},
    invoker,
    counts,
};
use std::path::PathBuf;
use walkdir::WalkDir;

const CORPUS_ROOT: &str = "../../third_party/packetdrill";
const CLASSIFY_TOML: &str =
    "../../tools/packetdrill-shim/classify/google.toml";

#[test]
fn google_runnable_subset_passes() {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    let toml_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(CLASSIFY_TOML);
    let classifier = Classifier::from_toml_path(&toml_path)
        .expect("load google.toml");

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT);
    let mut runnable: Vec<PathBuf> = vec![];
    let mut skip_untrans: Vec<(PathBuf, String)> = vec![];
    let mut skip_oos:    Vec<(PathBuf, String)> = vec![];

    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let path = entry.into_path();
        if path.extension().and_then(|e| e.to_str()) != Some("pkt") { continue; }
        // Skip non-corpus tests (there's no other .pkt in the submodule
        // but be defensive in case upstream adds non-gtests scripts).
        let rel = match path.strip_prefix(&root) {
            Ok(r) => r.to_string_lossy().into_owned(),
            Err(_) => continue,
        };
        if !rel.starts_with("gtests/") { continue; }
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

    // Pinned-count check (T16 pins these at the pragmatic floor).
    assert_eq!(runnable.len(),     counts::GOOGLE_RUNNABLE_COUNT,
        "runnable count drift — update counts::GOOGLE_RUNNABLE_COUNT");
    assert_eq!(skip_untrans.len(), counts::GOOGLE_SKIP_UNTRANSLATABLE);
    assert_eq!(skip_oos.len(),     counts::GOOGLE_SKIP_OUT_OF_SCOPE);
}
