//! Precondition-check data plumbing. Spec §4.1 + §4.3.
//!
//! Each host-level precondition resolves to a `PreconditionValue` which encodes
//! the verdict (pass/fail/not-applicable) and, for pass/fail, an optional
//! observed-value string (e.g. `pass=2-7` for an `isolcpus` mask, `fail=C6`
//! for a wrong c-state). The string form `"pass"` / `"fail"` / `"pass=X"` /
//! `"fail=X"` / `"n/a"` is what we emit into the CSV and what we parse back
//! when a downstream tool (bench-report) re-reads the file.
//!
//! The `n/a` variant exists because spec §4.1 line 222 carves out a
//! `bench-micro` exception: that tool does not bring up the DPDK engine, so
//! the `precondition_wc_active` check is unreachable and the CSV column is
//! marked `n/a` rather than `pass`/`fail`.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

/// Enforcement regime for precondition checks. Spec §4.3.
///
/// `Strict`: any fail aborts the run; `Lenient`: failures are recorded but the
/// run continues (rows are still flagged via the per-precondition columns).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PreconditionMode {
    #[default]
    Strict,
    Lenient,
}

impl std::fmt::Display for PreconditionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Lenient => write!(f, "lenient"),
        }
    }
}

impl FromStr for PreconditionMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict" => Ok(Self::Strict),
            "lenient" => Ok(Self::Lenient),
            other => Err(format!("unknown precondition mode: {other}")),
        }
    }
}

/// A single precondition result — pass/fail/not-applicable, with an optional
/// observed value (e.g. `isolcpus=2-7` or `cstate=C6`) attached to the
/// pass/fail arms. Spec §4.3; `NotApplicable` covers the bench-micro carve-out
/// from §4.1.
///
/// Serde impl is hand-written so the value appears as a single CSV cell
/// (`"pass=2-7"`, `"fail=C6"`, `"pass"`, `"fail"`, `"n/a"`) rather than as
/// two sub-columns. This is what csv::Writer expects from each struct field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreconditionValue {
    /// Check passed, optionally with an observed value (e.g. `Some("2-7")`
    /// for an isolcpus mask).
    Pass(Option<String>),
    /// Check failed, optionally with an observed value.
    Fail(Option<String>),
    /// Check is not applicable for this tool invocation (e.g. bench-micro
    /// skips `wc_active` because it does not bring up DPDK).
    NotApplicable,
}

impl Default for PreconditionValue {
    fn default() -> Self {
        Self::Pass(None)
    }
}

impl PreconditionValue {
    /// Pass with no observed value.
    pub fn pass() -> Self {
        Self::Pass(None)
    }

    /// Fail with no observed value.
    pub fn fail() -> Self {
        Self::Fail(None)
    }

    /// Pass with an observed value (e.g. `"2-7"` for an isolcpus mask).
    pub fn pass_with(value: impl Into<String>) -> Self {
        Self::Pass(Some(value.into()))
    }

    /// Fail with an observed value (e.g. `"C6"` for a wrong c-state).
    pub fn fail_with(value: impl Into<String>) -> Self {
        Self::Fail(Some(value.into()))
    }

    /// Not-applicable marker for checks skipped by a particular tool (e.g.
    /// bench-micro's `wc_active`).
    pub fn not_applicable() -> Self {
        Self::NotApplicable
    }

    /// `true` iff this value represents a successful check. `NotApplicable`
    /// does not count as a pass — it means the question was not asked.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass(_))
    }

    /// `true` iff this value represents a failed check.
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail(_))
    }

    /// `true` iff this value is the `n/a` marker.
    pub fn is_not_applicable(&self) -> bool {
        matches!(self, Self::NotApplicable)
    }
}

impl FromStr for PreconditionValue {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "n/a" {
            return Ok(Self::NotApplicable);
        }
        if s == "pass" {
            return Ok(Self::Pass(None));
        }
        if s == "fail" {
            return Ok(Self::Fail(None));
        }
        if let Some(rest) = s.strip_prefix("pass=") {
            return Ok(Self::Pass(Some(rest.into())));
        }
        if let Some(rest) = s.strip_prefix("fail=") {
            return Ok(Self::Fail(Some(rest.into())));
        }
        Err(format!("unparseable precondition value: {s}"))
    }
}

impl std::fmt::Display for PreconditionValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplicable => write!(f, "n/a"),
            Self::Pass(None) => write!(f, "pass"),
            Self::Fail(None) => write!(f, "fail"),
            Self::Pass(Some(v)) => write!(f, "pass={v}"),
            Self::Fail(Some(v)) => write!(f, "fail={v}"),
        }
    }
}

impl Serialize for PreconditionValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PreconditionValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(D::Error::custom)
    }
}

/// The full set of 14 host-level preconditions checked at run start. Spec §4.1.
///
/// Each field carries the `precondition_*` column-name prefix defined in
/// spec §14.1 via `#[serde(rename = "...")]`, so when this struct is flattened
/// into `RunMetadata` via `#[serde(flatten)]` the CSV header comes out with
/// exactly the schema columns. (We pay the bookkeeping cost here instead of
/// in a custom flatten module because `csv::Writer` does not support the
/// `serialize_map` pathway that a `with = "..."` flatten helper would need.)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preconditions {
    #[serde(rename = "precondition_isolcpus")]
    pub isolcpus: PreconditionValue,
    #[serde(rename = "precondition_nohz_full")]
    pub nohz_full: PreconditionValue,
    #[serde(rename = "precondition_rcu_nocbs")]
    pub rcu_nocbs: PreconditionValue,
    #[serde(rename = "precondition_governor")]
    pub governor: PreconditionValue,
    #[serde(rename = "precondition_cstate_max")]
    pub cstate_max: PreconditionValue,
    #[serde(rename = "precondition_tsc_invariant")]
    pub tsc_invariant: PreconditionValue,
    #[serde(rename = "precondition_coalesce_off")]
    pub coalesce_off: PreconditionValue,
    #[serde(rename = "precondition_tso_off")]
    pub tso_off: PreconditionValue,
    #[serde(rename = "precondition_lro_off")]
    pub lro_off: PreconditionValue,
    #[serde(rename = "precondition_rss_on")]
    pub rss_on: PreconditionValue,
    #[serde(rename = "precondition_thermal_throttle")]
    pub thermal_throttle: PreconditionValue,
    #[serde(rename = "precondition_hugepages_reserved")]
    pub hugepages_reserved: PreconditionValue,
    #[serde(rename = "precondition_irqbalance_off")]
    pub irqbalance_off: PreconditionValue,
    #[serde(rename = "precondition_wc_active")]
    pub wc_active: PreconditionValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_display_round_trips() {
        for (s, expect) in [
            ("pass", PreconditionValue::pass()),
            ("fail", PreconditionValue::fail()),
            ("pass=2-7", PreconditionValue::pass_with("2-7")),
            ("fail=C6", PreconditionValue::fail_with("C6")),
        ] {
            let parsed: PreconditionValue = s.parse().unwrap();
            assert_eq!(parsed, expect);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn value_rejects_garbage() {
        let err = "unknown".parse::<PreconditionValue>();
        assert!(err.is_err());
    }

    #[test]
    fn mode_round_trips() {
        assert_eq!("strict".parse::<PreconditionMode>().unwrap(), PreconditionMode::Strict);
        assert_eq!("lenient".parse::<PreconditionMode>().unwrap(), PreconditionMode::Lenient);
        assert_eq!(PreconditionMode::Strict.to_string(), "strict");
        assert_eq!(PreconditionMode::Lenient.to_string(), "lenient");
    }

    #[test]
    fn value_serde_is_single_string() {
        let v = PreconditionValue::pass_with("2-7");
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"pass=2-7\"");
        let back: PreconditionValue = serde_json::from_str("\"pass=2-7\"").unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn precondition_value_parses_na() {
        // FromStr accepts "n/a".
        let parsed: PreconditionValue = "n/a".parse().unwrap();
        assert_eq!(parsed, PreconditionValue::NotApplicable);
        assert!(parsed.is_not_applicable());
        assert!(!parsed.is_pass());
        assert!(!parsed.is_fail());

        // Display round-trips.
        assert_eq!(parsed.to_string(), "n/a");

        // Serde round-trips (single-cell string shape, same as pass/fail).
        let json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, "\"n/a\"");
        let back: PreconditionValue = serde_json::from_str("\"n/a\"").unwrap();
        assert_eq!(back, PreconditionValue::NotApplicable);
    }
}
