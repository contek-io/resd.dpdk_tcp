//! A7 T13: ligurio-corpus classifier. Regex-based rules from
//! `tools/packetdrill-shim/classify/ligurio.toml`.

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
    SkippedUntranslatable(String),
    SkippedOutOfScope(String),
}

pub struct Classifier { rules: Vec<Rule> }

impl Classifier {
    pub fn load() -> Self {
        let raw = include_str!(
            "../../packetdrill-shim/classify/ligurio.toml");
        let cfg: Config = toml::from_str(raw).expect("parse ligurio.toml");
        let rules = cfg.rule.into_iter().map(|r| {
            let v = match r.verdict.as_str() {
                "runnable" => Verdict::Runnable,
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
