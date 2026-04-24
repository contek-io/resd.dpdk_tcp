//! A7 T13: ligurio-corpus classifier. Regex-based rules from
//! `tools/packetdrill-shim/classify/ligurio.toml`.
//!
//! A8 T16: extended to per-corpus TOMLs (shivansh, google). The original
//! `Classifier::load()` still hard-codes ligurio.toml via `include_str!`
//! (baked into the binary). The new `from_toml_path` reads at runtime so
//! each corpus test can point at its own TOML without touching
//! `include_str!` — the latter requires a string literal and can't be
//! parameterized across corpora.

use regex::Regex;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct Config { rule: Vec<RuleRaw> }

#[derive(Deserialize)]
struct RuleRaw {
    matches_regex: String,
    verdict: String,
    reason: String,
}

struct Rule { re: Regex, verdict: Verdict }

#[derive(Debug, Clone)]
pub enum Verdict {
    Runnable,
    /// A8.5 T9 (G): crash-safety-only corpus. Script exercises an
    /// engine-crash-safety invariant ("no SIGSEGV / SIGABRT / signal
    /// kill on unexpected peer behavior"). The engine is not expected
    /// to reproduce the scripted wire shape (because the behavior
    /// under test — ICMP, bad syscall args, PMTU — isn't modeled), so
    /// the script reliably exits 1 on assertion failure but never
    /// crashes. The test gate accepts any exit code 0..=128 and fails
    /// only on signal kills (exit > 128) or timeouts.
    RunnableNoCrash(String),
    SkippedUntranslatable(String),
    SkippedOutOfScope(String),
}

pub struct Classifier { rules: Vec<Rule> }

impl Classifier {
    /// A7 T13: load the baked-in ligurio classifier TOML.
    pub fn load() -> Self {
        let raw = include_str!(
            "../../packetdrill-shim/classify/ligurio.toml");
        Self::from_toml_str(raw)
    }

    /// A8 T16: load a classifier TOML from disk (per-corpus tests).
    /// Path is absolute or cwd-relative at test-runtime.
    pub fn from_toml_path(path: &Path) -> std::io::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(Self::from_toml_str(&raw))
    }

    /// A8 T16: parse a classifier TOML source into a Classifier.
    pub fn from_toml_str(raw: &str) -> Self {
        let cfg: Config = toml::from_str(raw).expect("parse classifier toml");
        let rules = cfg.rule.into_iter().map(|r| {
            let v = match r.verdict.as_str() {
                "runnable" => Verdict::Runnable,
                "runnable-no-crash" =>
                    Verdict::RunnableNoCrash(r.reason),
                "skipped-untranslatable" =>
                    Verdict::SkippedUntranslatable(r.reason),
                "skipped-out-of-scope" =>
                    Verdict::SkippedOutOfScope(r.reason),
                other => panic!("unknown verdict {other}"),
            };
            Rule { re: Regex::new(&r.matches_regex).unwrap(), verdict: v }
        }).collect();
        Self { rules }
    }

    pub fn classify(&self, path: &Path) -> Verdict {
        let s = path.to_string_lossy();
        for r in &self.rules {
            if r.re.is_match(&s) { return r.verdict.clone(); }
        }
        panic!("no rule matched {s} (add a default .*\\.pkt rule)");
    }
}
