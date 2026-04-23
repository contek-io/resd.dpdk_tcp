//! A7 T15 helper: run every classifier-runnable script through the shim
//! binary and bucket failures by first-line-of-stderr. Output is consumed
//! by T15 iteration to find classifier-rule candidates.
//!
//! Usage (needs the shim binary built separately):
//!   cargo run --release -p packetdrill-shim-runner --bin dry-run
//!   DPDK_NET_SHIM_BIN=/abs/path CORPUS_ROOT=/abs/path cargo run ... --bin dry-run

use packetdrill_shim_runner::{
    classifier::{Classifier, Verdict},
    invoker,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use walkdir::WalkDir;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = std::env::var("DPDK_NET_SHIM_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join("../../target/packetdrill-shim/packetdrill"));
    let root = std::env::var("CORPUS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join("../../third_party/packetdrill-testcases"));

    if !bin.exists() {
        eprintln!("shim binary missing at {}", bin.display());
        std::process::exit(2);
    }
    let c = Classifier::load();

    let mut pass = 0usize;
    let mut fail: Vec<(String, i32, String)> = Vec::new();
    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("pkt") {
            continue;
        }
        if !matches!(c.classify(p), Verdict::Runnable) {
            continue;
        }
        let o = invoker::run_script(&bin, p);
        let rel = p
            .strip_prefix(&root)
            .unwrap_or(p)
            .to_string_lossy()
            .into_owned();
        if o.exit == 0 {
            pass += 1;
        } else {
            // Scan stderr for the most useful one-line signal. We prefer
            // lines that look like packetdrill verdicts ("error handling
            // packet:", "did not see...", "bad file descriptor", etc.).
            let first_err = o
                .stderr
                .lines()
                .find(|l| {
                    let low = l.to_ascii_lowercase();
                    low.contains("error")
                        || low.contains("runtime")
                        || low.contains("timed out")
                        || low.contains("no such")
                        || low.contains("mismatch")
                        || low.contains("bad ")
                        || low.contains("assertion")
                        || low.contains("syntax")
                })
                .unwrap_or_else(|| o.stderr.lines().next().unwrap_or(""))
                .to_string();
            fail.push((rel, o.exit, first_err));
        }
    }

    println!("pass={} fail={}", pass, fail.len());

    // Group failures by first-error-line so we can see patterns.
    let mut by_err: BTreeMap<String, Vec<(String, i32)>> = BTreeMap::new();
    for (p, code, e) in &fail {
        // Strip path/line prefixes from packetdrill's "script.pkt:123: ..." format.
        let normalized = normalize(e);
        by_err
            .entry(normalized)
            .or_default()
            .push((p.clone(), *code));
    }
    let mut buckets: Vec<(&String, &Vec<(String, i32)>)> = by_err.iter().collect();
    buckets.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    for (e, paths) in buckets {
        println!("--- [{}] ({} scripts) ---", e, paths.len());
        for (p, code) in paths.iter().take(8) {
            println!("  exit={} {}", code, p);
        }
        if paths.len() > 8 {
            println!("  ... and {} more", paths.len() - 8);
        }
    }

    if fail.is_empty() {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

fn normalize(line: &str) -> String {
    // Turn "foo/bar.pkt:12: error handling X" into ".pkt:N: error handling X"
    // so that the same underlying failure groups across scripts.
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() {
            out.push('N');
            while let Some(&nc) = chars.peek() {
                if nc.is_ascii_digit() {
                    chars.next();
                } else {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    // Collapse paths (everything before the first ': ') to "<path>" so
    // per-script prefixes group together.
    if let Some(colon) = out.find(':') {
        let (_path, rest) = out.split_at(colon);
        format!("<path>{}", rest)
    } else {
        out
    }
}
