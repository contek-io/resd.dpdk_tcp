//! A7 T15 helper: classify every .pkt under a corpus root and print
//! bucket counts + full verdict list. Output is consumed during T15/T16
//! iteration to pick final counts.
//!
//! Usage:
//!   cargo run -p packetdrill-shim-runner --bin dry-classify
//!   CORPUS_ROOT=/abs/path cargo run ... --bin dry-classify
//!   CLASSIFY_TOML=/abs/path cargo run ... --bin dry-classify
//!   VERBOSE=1 cargo run ... --bin dry-classify     # list every file + verdict
//!
//! A8 T16: CLASSIFY_TOML selects per-corpus rules (ligurio / shivansh /
//! google). Default is the baked-in ligurio.toml (matches A7 T15 behavior).

use packetdrill_shim_runner::classifier::{Classifier, Verdict};
use std::path::PathBuf;
use walkdir::WalkDir;

fn main() {
    let corpus = std::env::var("CORPUS_ROOT").unwrap_or_else(|_| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest
            .join("../../third_party/packetdrill-testcases")
            .to_string_lossy()
            .into_owned()
    });
    let verbose = std::env::var("VERBOSE").map(|v| v == "1").unwrap_or(false);
    let c = match std::env::var("CLASSIFY_TOML") {
        Ok(p) => Classifier::from_toml_path(std::path::Path::new(&p))
            .expect("load CLASSIFY_TOML"),
        Err(_) => Classifier::load(),
    };
    let mut runnable = Vec::new();
    let mut no_crash: Vec<(String, String)> = Vec::new();
    let mut skip_u: Vec<(String, String)> = Vec::new();
    let mut skip_o: Vec<(String, String)> = Vec::new();
    for entry in WalkDir::new(&corpus).into_iter().filter_map(Result::ok) {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("pkt") {
            continue;
        }
        let rel = p
            .strip_prefix(&corpus)
            .unwrap_or(p)
            .to_string_lossy()
            .into_owned();
        match c.classify(p) {
            Verdict::Runnable => runnable.push(rel),
            Verdict::RunnableNoCrash(r) => no_crash.push((rel, r)),
            Verdict::SkippedUntranslatable(r) => skip_u.push((rel, r)),
            Verdict::SkippedOutOfScope(r) => skip_o.push((rel, r)),
        }
    }
    println!(
        "runnable={} no_crash={} skip_untrans={} skip_oos={}",
        runnable.len(),
        no_crash.len(),
        skip_u.len(),
        skip_o.len()
    );
    if verbose {
        println!("# RUNNABLE");
        for r in &runnable {
            println!("R\t{}", r);
        }
        println!("# RUNNABLE-NO-CRASH");
        for (r, why) in &no_crash {
            println!("N\t{}\t{}", r, why);
        }
        println!("# SKIP-UNTRANS");
        for (r, why) in &skip_u {
            println!("U\t{}\t{}", r, why);
        }
        println!("# SKIP-OOS");
        for (r, why) in &skip_o {
            println!("O\t{}\t{}", r, why);
        }
    }
}
