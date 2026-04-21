//! A9 fault-injector — smoltcp-pattern, post-PMD-RX / pre-L2 middleware.
//!
//! Sits between `rte_eth_rx_burst` and the L2 decoder, intercepting each
//! mbuf and (with configured probability) dropping it, duplicating it,
//! reordering it via a short ring, or corrupting a byte. Every decision
//! is slow-path: a single `fetch_add` on the matching `FaultInjectorCounters`
//! field, with the hot path staying inside the PRNG-sample + branch.
//!
//! The module is behind `#[cfg(feature = "fault-injector")]` so default and
//! release builds carry zero of it — no struct, no allocator pressure, no
//! extra cbindgen symbols. The cbindgen header is generated without the
//! feature, so this code never reaches `dpdk_net.h`.
//!
//! # Configuration
//!
//! Configuration is env-var driven: `DPDK_NET_FAULT_INJECTOR` holds a spec
//! of comma-separated `key=value` pairs. Keys: `drop`, `dup`, `reorder`,
//! `corrupt` (all `f32` rates in `[0.0, 1.0]`), and `seed` (u64).
//!
//! ```text
//! DPDK_NET_FAULT_INJECTOR=drop=0.01,dup=0.005,reorder=0.002,corrupt=0.001,seed=42
//! ```
//!
//! Empty / unset env var → fault injection disabled (all rates 0.0, seed 0).
//! Parse error → stderr warning + injector construction skipped.
//!
//! # Shape
//!
//! - `FaultConfig::parse` / `FaultConfig::from_env` — the env-var parser.
//! - `FaultConfig` — the plain-data config struct (all f32 rates + u64 seed).
//! - `FaultInjector` — owns the config, a `SmallRng`, and a lazily-allocated
//!   reorder ring (bounded `ArrayVec<_, 16>`).
//! - `FaultInjector::process` — the middleware entry. Task 5 stubs the body;
//!   Task 6 implements drop / dup / reorder / corrupt.

use core::ptr::NonNull;
use dpdk_net_sys::rte_mbuf;
use rand::{rngs::SmallRng, SeedableRng};

/// Parsed config for the A9 fault injector. All fields default to 0 /
/// disabled — constructing `FaultInjector` with this default is a no-op
/// pass-through. Built either by `FaultConfig::parse` from an explicit spec
/// string or by `FaultConfig::from_env` reading `DPDK_NET_FAULT_INJECTOR`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FaultConfig {
    /// Probability (0.0..=1.0) that an incoming mbuf is dropped.
    pub drop_rate: f32,
    /// Probability (0.0..=1.0) that an incoming mbuf is duplicated.
    pub dup_rate: f32,
    /// Probability (0.0..=1.0) that an incoming mbuf is held back in the
    /// reorder ring to be emitted after the next non-reordered mbuf.
    pub reorder_rate: f32,
    /// Probability (0.0..=1.0) that a single byte of the mbuf is flipped.
    pub corrupt_rate: f32,
    /// PRNG seed. `0` = "use caller-provided boot-nonce at construction".
    pub seed: u64,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            drop_rate: 0.0,
            dup_rate: 0.0,
            reorder_rate: 0.0,
            corrupt_rate: 0.0,
            seed: 0,
        }
    }
}

/// Errors surfaced by `FaultConfig::parse`.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum FaultConfigParseError {
    /// A key not in {drop,dup,reorder,corrupt,seed} appeared.
    #[error("unknown fault-injector key: {0}")]
    UnknownKey(String),
    /// A value failed to parse as f32 / u64.
    #[error("invalid value for {key}: {value}")]
    InvalidValue { key: String, value: String },
    /// An f32 rate parsed but fell outside `[0.0, 1.0]`.
    #[error("rate out of range for {key}: {value}")]
    RateOutOfRange { key: String, value: String },
}

impl FaultConfig {
    /// Parse a `drop=0.01,dup=0.005,reorder=0.002,corrupt=0.001,seed=42`
    /// spec string into a `FaultConfig`. Empty string → `Default`.
    pub fn parse(spec: &str) -> Result<Self, FaultConfigParseError> {
        let mut cfg = Self::default();
        let spec = spec.trim();
        if spec.is_empty() {
            return Ok(cfg);
        }
        for entry in spec.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (key, value) = match entry.split_once('=') {
                Some(kv) => kv,
                // Bare key without `=` → InvalidValue (empty value).
                None => {
                    return Err(FaultConfigParseError::InvalidValue {
                        key: entry.to_string(),
                        value: String::new(),
                    });
                }
            };
            let key = key.trim();
            let value = value.trim();
            match key {
                "drop" => cfg.drop_rate = parse_rate(key, value)?,
                "dup" => cfg.dup_rate = parse_rate(key, value)?,
                "reorder" => cfg.reorder_rate = parse_rate(key, value)?,
                "corrupt" => cfg.corrupt_rate = parse_rate(key, value)?,
                "seed" => {
                    cfg.seed = value.parse::<u64>().map_err(|_| {
                        FaultConfigParseError::InvalidValue {
                            key: key.to_string(),
                            value: value.to_string(),
                        }
                    })?;
                }
                other => {
                    return Err(FaultConfigParseError::UnknownKey(other.to_string()));
                }
            }
        }
        Ok(cfg)
    }

    /// Read `DPDK_NET_FAULT_INJECTOR` from the environment and parse.
    /// Returns `None` if the env var is unset / empty, or if parsing failed
    /// (a warning is printed to stderr in the failure case).
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("DPDK_NET_FAULT_INJECTOR").ok()?;
        if raw.trim().is_empty() {
            return None;
        }
        match Self::parse(&raw) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                eprintln!(
                    "warning: DPDK_NET_FAULT_INJECTOR parse error: {e}; fault injection disabled"
                );
                None
            }
        }
    }
}

fn parse_rate(key: &str, value: &str) -> Result<f32, FaultConfigParseError> {
    let parsed: f32 =
        value
            .parse::<f32>()
            .map_err(|_| FaultConfigParseError::InvalidValue {
                key: key.to_string(),
                value: value.to_string(),
            })?;
    if !parsed.is_finite() || !(0.0..=1.0).contains(&parsed) {
        return Err(FaultConfigParseError::RateOutOfRange {
            key: key.to_string(),
            value: value.to_string(),
        });
    }
    Ok(parsed)
}

/// Post-PMD-RX / pre-L2 middleware that applies the configured fault
/// distribution to each incoming mbuf. Owned exclusively by the engine's
/// RX path on a single lcore — no internal locking.
pub struct FaultInjector {
    cfg: FaultConfig,
    rng: SmallRng,
    /// Lazily initialised on first reorder decision; bounded at 16 entries
    /// so a pathological reorder_rate can't grow memory without bound.
    reorder_ring: Option<arrayvec::ArrayVec<NonNull<rte_mbuf>, 16>>,
}

impl FaultInjector {
    /// Construct a new injector. If `cfg.seed == 0`, use `boot_nonce_seed`
    /// so every engine boot still gets a distinct reproducible stream.
    pub fn new(cfg: FaultConfig, boot_nonce_seed: u64) -> Self {
        let seed = if cfg.seed != 0 {
            cfg.seed
        } else {
            boot_nonce_seed
        };
        Self {
            cfg,
            rng: SmallRng::seed_from_u64(seed),
            reorder_ring: None,
        }
    }

    /// Accessor for the active config (diagnostics / tests).
    pub fn cfg(&self) -> &FaultConfig {
        &self.cfg
    }

    /// Middleware entry. Returns the list of mbufs to forward onto the L2
    /// decoder (0..=N items — a drop returns empty, a dup returns two, the
    /// reorder path returns 0 or 2 depending on ring state).
    ///
    /// STUB: Task 5 only scaffolds; Task 6 implements the body.
    pub fn process(
        &mut self,
        _mbuf: NonNull<rte_mbuf>,
        _counters: &crate::counters::FaultInjectorCounters,
    ) -> smallvec::SmallVec<[NonNull<rte_mbuf>; 4]> {
        // Silence unused-field warnings on the scaffolded-but-unused state
        // without disabling the lint globally. Task 6 deletes these lines.
        let _ = &self.rng;
        let _ = &self.reorder_ring;
        unimplemented!("Task 6: FaultInjector::process body")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_keys() {
        let cfg = FaultConfig::parse("drop=0.01,dup=0.005,reorder=0.002,corrupt=0.001,seed=42")
            .expect("spec parses");
        assert_eq!(cfg.drop_rate, 0.01_f32);
        assert_eq!(cfg.dup_rate, 0.005_f32);
        assert_eq!(cfg.reorder_rate, 0.002_f32);
        assert_eq!(cfg.corrupt_rate, 0.001_f32);
        assert_eq!(cfg.seed, 42);
    }

    #[test]
    fn parse_empty_is_default() {
        assert_eq!(FaultConfig::parse("").unwrap(), FaultConfig::default());
        assert_eq!(FaultConfig::parse("   ").unwrap(), FaultConfig::default());
    }

    #[test]
    fn rate_out_of_range_rejected() {
        let err = FaultConfig::parse("drop=1.5").unwrap_err();
        assert_eq!(
            err,
            FaultConfigParseError::RateOutOfRange {
                key: "drop".to_string(),
                value: "1.5".to_string(),
            }
        );
        // Negative also rejected.
        let err = FaultConfig::parse("dup=-0.1").unwrap_err();
        assert!(matches!(err, FaultConfigParseError::RateOutOfRange { .. }));
    }

    #[test]
    fn unknown_key_rejected() {
        let err = FaultConfig::parse("foo=0.1").unwrap_err();
        assert_eq!(err, FaultConfigParseError::UnknownKey("foo".to_string()));
    }

    /// Locks in the parser's whitespace + empty-entry tolerance (the
    /// trim + `if entry.is_empty() { continue; }` behaviour). Rejecting
    /// these later would be a behaviour change.
    #[test]
    fn parse_tolerates_whitespace_and_empty_entries() {
        let cfg = FaultConfig::parse(" drop = 0.1 , , dup=0.05 ,  ").unwrap();
        assert_eq!(cfg.drop_rate, 0.1_f32);
        assert_eq!(cfg.dup_rate, 0.05_f32);
    }
}
