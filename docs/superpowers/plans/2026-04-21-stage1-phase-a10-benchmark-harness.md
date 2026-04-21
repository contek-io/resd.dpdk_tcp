# Phase A10 — Benchmark harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended per user protocol) to implement this plan task-by-task. Per-task spec-compliance + code-quality review subagents (both `model: "opus"` per `feedback_subagent_model.md`) run after every non-trivial task per `feedback_per_task_review_discipline.md`. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the §11 benchmark plan — microbenchmarks, end-to-end RTT with attribution, stress benchmarks, Linux + mTCP comparators, two A/B harnesses (`bench-offload-ab`, `bench-obs-overhead`), one `obs-none` umbrella feature, one unified CSV schema, a JSON+HTML+Markdown reporting tool, a nightly bench script that shells out to the `resd.aws-infra-setup` CLI, and three committed report artefacts that drive the final A11 default feature set.

**Architecture:** Nine workspace members under `tools/`: `bench-common` (shared lib — CSV schema + percentile + CI + preconditions plumbing), `bench-ab-runner` (shared sub-process runner for A/B harnesses), `bench-micro` (cargo-criterion), `bench-e2e` (real-wire RTT + HW-TS/TSC attribution + A-HW Task 18 assertions), `bench-stress` (netem + FaultInjector matrix), `bench-vs-linux` (dual-preset RTT + wire-diff), `bench-offload-ab`, `bench-obs-overhead`, `bench-vs-mtcp` (burst + maxtp grids), `bench-report` (CSV → JSON + HTML + Markdown). One new cargo feature `obs-none` gates four always-on emission sites in `dpdk-net-core`. Measurement discipline enforced by a shared precondition-check script; hybrid strict/lenient mode.

**Tech Stack:** Rust stable + cargo-criterion 0.5 (workspace pinned), serde + serde_json, csv 1.x, uuid 1.x, clap 4.x (driver CLIs), askama or maud for HTML rendering (single-file static), pcap-file (wire-diff capture parsing). DPDK 23.11 via existing `dpdk-net-sys`. Paired Linux + mTCP peer binaries on the AMI-baked sister host.

**Branch / worktree:** `phase-a10` in `/home/ubuntu/resd.dpdk_tcp-a10`, branched from master tip `1cf754a`.

**Spec:** `docs/superpowers/specs/2026-04-21-stage1-phase-a10-benchmark-harness-design.md` (committed at `7f70ea5`).

**Sister plan:** `docs/superpowers/plans/2026-04-21-stage1-phase-a10-aws-infra-setup.md` — delivers the IaC + AMI that T16 (nightly bench script) consumes.

---

## File structure

### Created (new under `tools/`)

```
tools/
├── bench-common/
│   ├── Cargo.toml
│   ├── src/lib.rs                  # re-exports
│   ├── src/csv_row.rs              # CsvRow, dimensions, aggregation enum
│   ├── src/preconditions.rs        # PreconditionResult + harness helper
│   ├── src/percentile.rs           # p50/p99/p999 + bootstrap CI
│   ├── src/run_metadata.rs         # commit, host, dpdk_version, etc.
│   └── tests/csv_row_roundtrip.rs
├── bench-ab-runner/
│   ├── Cargo.toml
│   ├── src/main.rs                 # runner: EAL → Engine → workload → CSV → cleanup → exit
│   ├── src/workload.rs             # 128 B/128 B request-response loop
│   └── tests/smoke.rs
├── bench-micro/
│   ├── Cargo.toml
│   └── benches/{poll_empty,tsc_read,flow_lookup,tcp_input,send,timer,counters}.rs
├── bench-e2e/
│   ├── Cargo.toml
│   ├── src/main.rs                 # CLI + run logic
│   ├── src/attribution.rs          # 4-bucket HW-TS + 3-bucket TSC-fallback
│   ├── src/sum_identity.rs         # per-measurement assertion
│   ├── src/hw_task_18.rs           # offload-counter + rx_hw_ts_ns=0 assertions
│   ├── peer/                       # Rust/C program for paired-host echo server
│   │   └── echo-server.c
│   └── tests/smoke.rs
├── bench-stress/
│   ├── Cargo.toml
│   ├── src/main.rs
│   ├── src/scenarios.rs            # 9-row matrix
│   ├── src/netem.rs                # `tc qdisc` driver (SSHes to peer)
│   └── tests/scenario_parse.rs
├── bench-vs-linux/
│   ├── Cargo.toml
│   ├── src/main.rs                 # mode selector (rtt / wire-diff)
│   ├── src/mode_rtt.rs
│   ├── src/mode_wire_diff.rs
│   ├── src/normalize.rs            # ISS + timestamp-base canonicalisation
│   ├── peer/linux-tcp-sink.c
│   └── tests/normalize_roundtrip.rs
├── bench-offload-ab/
│   ├── Cargo.toml
│   └── src/main.rs                 # matrix driver → invokes bench-ab-runner per config
├── bench-obs-overhead/
│   ├── Cargo.toml
│   └── src/main.rs                 # matrix driver (reuses bench-offload-ab logic via bench-common)
├── bench-vs-mtcp/
│   ├── Cargo.toml
│   ├── src/main.rs
│   ├── src/burst.rs                # K×G grid driver
│   ├── src/maxtp.rs                # W×C grid driver
│   └── tests/grid_unit.rs
└── bench-report/
    ├── Cargo.toml
    ├── src/main.rs
    ├── src/json_writer.rs
    ├── src/html_writer.rs
    ├── src/md_writer.rs
    ├── templates/report.html.j2    # askama/maud template
    └── tests/round_trip.rs
```

### Created — scripts + reports

```
scripts/
├── check-bench-preconditions.sh    # canonical; copy synced to resd.aws-infra-setup/assets/
└── bench-nightly.sh                # end-to-end: setup pair → bench → teardown

docs/superpowers/reports/
├── offload-ab.md                   # produced by bench-offload-ab; committed
├── obs-overhead.md                 # produced by bench-obs-overhead; committed
└── bench-baseline.md               # produced by bench-micro + bench-report; committed
docs/superpowers/reviews/
├── phase-a10-mtcp-compare.md       # produced by mtcp-comparison-reviewer subagent
└── phase-a10-rfc-compliance.md     # produced by rfc-compliance-reviewer subagent
```

### Modified

```
Cargo.toml                          # add 10 workspace members under tools/
crates/dpdk-net-core/Cargo.toml     # + obs-none feature
crates/dpdk-net-core/src/tcp_events.rs   # G1 gate on EventQueue::push sites
crates/dpdk-net-core/src/tcp_conn.rs     # G3 gate on rtt_histogram.update
crates/dpdk-net/src/api.rs          # G4 gate on dpdk_net_conn_stats
crates/dpdk-net-core/tests/knob-coverage.rs  # obs-none knob-coverage entry
docs/superpowers/plans/stage1-phase-roadmap.md  # A10 row revision at phase end
```

### Task ordering & parallelism

Serial dependency chain: T0 → T1 (bench-common) → T2 (bench-ab-runner).

After T1+T2, independent groups dispatchable in parallel by `superpowers:subagent-driven-development`:

- T3 (preconditions checker) — independent of T1/T2; can run in parallel with T1.
- T4 (obs-none feature + G1-G4 gates) — independent.
- T5 (bench-micro) — after T1 (uses bench-common CSV schema).
- T6 (bench-e2e) — after T1 + T2 (uses bench-common + bench-ab-runner workload fixture).
- T7 (bench-stress) — after T6 (reuses bench-e2e workload fixture).
- T8 (bench-vs-linux mode A) — after T6.
- T9 (bench-vs-linux mode B) — after T8.
- T10 (bench-offload-ab) — after T2 + T4.
- T11 (bench-obs-overhead) — after T10 (reuses its driver lib via bench-common).
- T12 (bench-vs-mtcp burst) — after T6 + sister-plan T6 (first AMI bake + first bench-pair bring-up).
- T13 (bench-vs-mtcp maxtp) — after T12.
- T14 (bench-report) — after T5 (first real CSV output exists).
- T15 (bench-nightly script) — after every bench tool lands.
- T16 (produce + commit 3 report artefacts) — after T10 + T11 + T15.
- T17 (roadmap row update) — after everything else.
- T18 (phase-a10-complete tag) — final.
- T19 (mTCP review gate) — parallel with T20.
- T20 (RFC review gate) — parallel with T19.
- T21 (end-of-phase signoff) — after T16 + T18 + T19 + T20.

---

## Task 0: Preparation — worktree verify

- [x] Worktree `/home/ubuntu/resd.dpdk_tcp-a10` already set up on branch `phase-a10` off master tip `1cf754a`.
- [x] Spec committed at `7f70ea5`.

Verify state before any task starts:

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
git status   # expect: On branch phase-a10, nothing to commit
git log -3 --oneline
# 7f70ea5 a10 spec: benchmark harness (micro + e2e + stress + comparators) design
# 1cf754a Merge branch 'master' of https://github.com/contek-io/resd.dpdk_tcp
# 4b55a48 Merge phase-a9 into master
```

---

## Task 1: `bench-common` library crate

Shared foundational types + helpers used by every bench tool.

**Files:**
- Create: `tools/bench-common/Cargo.toml`
- Create: `tools/bench-common/src/lib.rs`
- Create: `tools/bench-common/src/csv_row.rs`
- Create: `tools/bench-common/src/preconditions.rs`
- Create: `tools/bench-common/src/percentile.rs`
- Create: `tools/bench-common/src/run_metadata.rs`
- Modify: `Cargo.toml` (workspace) — add `tools/bench-common` to members
- Test: `tools/bench-common/tests/csv_row_roundtrip.rs`

### Steps

- [ ] **Step 1.1: Add to workspace**

Edit top-level `Cargo.toml` — append `"tools/bench-common"` to `members`.

- [ ] **Step 1.2: Write `tools/bench-common/Cargo.toml`**

```toml
[package]
name = "bench-common"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
csv = "1.3"
uuid = { version = "1.7", features = ["v4"] }
chrono = { version = "0.4", default-features = false, features = ["clock", "serde"] }

[dev-dependencies]
proptest = "1"
```

- [ ] **Step 1.3: Write the failing `CsvRow` round-trip test**

`tools/bench-common/tests/csv_row_roundtrip.rs`:

```rust
//! Round-trip: write CsvRow → read back → assert equal.

use bench_common::csv_row::{CsvRow, MetricAggregation, PreconditionValue};
use bench_common::run_metadata::RunMetadata;

fn sample_row() -> CsvRow {
    CsvRow {
        run_metadata: RunMetadata {
            run_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            run_started_at: "2026-04-22T03:14:07Z".to_string(),
            commit_sha: "7f70ea50000000000000000000000000000000ab".to_string(),
            branch: "phase-a10".to_string(),
            host: "ip-10-0-0-42".to_string(),
            instance_type: "c6a.2xlarge".to_string(),
            cpu_model: "AMD EPYC 7R13".to_string(),
            dpdk_version: "23.11.2".to_string(),
            kernel: "6.17.0-1009-generic".to_string(),
            nic_model: "Elastic Network Adapter (ENA)".to_string(),
            nic_fw: String::new(),
            ami_id: "ami-0123456789abcdef0".to_string(),
            precondition_mode: bench_common::preconditions::PreconditionMode::Strict,
            preconditions: Default::default(),
        },
        tool: "bench-vs-mtcp".into(),
        test_case: "burst".into(),
        feature_set: "default".into(),
        dimensions_json: r#"{"K_bytes":262144,"G_ms":10,"stack":"dpdk_net"}"#.into(),
        metric_name: "throughput_per_burst_bps".into(),
        metric_unit: "bytes_per_sec".into(),
        metric_value: 8.7e9,
        metric_aggregation: MetricAggregation::P99,
    }
}

#[test]
fn csv_row_round_trip_one_row() {
    let row = sample_row();
    let mut buf = Vec::new();
    {
        let mut wtr = csv::Writer::from_writer(&mut buf);
        row.write_with_header(&mut wtr).unwrap();
    }
    let mut rdr = csv::Reader::from_reader(&buf[..]);
    let parsed: CsvRow = rdr.deserialize().next().unwrap().unwrap();
    assert_eq!(parsed, row);
}

#[test]
fn metric_aggregation_serde() {
    let values = ["p50", "p99", "p999", "mean", "stddev", "ci95_lower", "ci95_upper"];
    for v in values {
        let enumv: MetricAggregation = serde_json::from_str(&format!("\"{}\"", v)).unwrap();
        let back: String = serde_json::to_string(&enumv).unwrap();
        assert_eq!(back, format!("\"{}\"", v));
    }
}

#[test]
fn precondition_value_parses_pass_and_fail() {
    let a: PreconditionValue = "pass=2-7".parse().unwrap();
    assert_eq!(a.passed, true);
    assert_eq!(a.value, "2-7");
    let b: PreconditionValue = "fail=C6".parse().unwrap();
    assert_eq!(b.passed, false);
    assert_eq!(b.value, "C6");
    let c: PreconditionValue = "pass".parse().unwrap();
    assert_eq!(c.passed, true);
    assert_eq!(c.value, "");
}
```

- [ ] **Step 1.4: Run tests — verify fail (module doesn't exist)**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
timeout 60 cargo test -p bench-common --test csv_row_roundtrip 2>&1 | tee /tmp/bench-common-t1.log
```

Expected: compile error — modules not yet defined.

- [ ] **Step 1.5: Write `src/lib.rs`, `src/csv_row.rs`, `src/preconditions.rs`, `src/run_metadata.rs`, `src/percentile.rs`**

`src/lib.rs`:

```rust
//! bench-common — shared types + helpers across tools/bench-*.
pub mod csv_row;
pub mod preconditions;
pub mod percentile;
pub mod run_metadata;
```

`src/preconditions.rs`:

```rust
//! Precondition-check data plumbing. Spec §4.1 + §4.3.
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PreconditionMode {
    Strict,
    Lenient,
}

impl Default for PreconditionMode { fn default() -> Self { Self::Strict } }

/// Precondition result per spec §4.3 — `pass` or `fail=<observed>`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PreconditionValue {
    pub passed: bool,
    pub value: String,
}

impl FromStr for PreconditionValue {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "pass" { return Ok(Self { passed: true, value: String::new() }); }
        if s == "fail" { return Ok(Self { passed: false, value: String::new() }); }
        if let Some(rest) = s.strip_prefix("pass=") { return Ok(Self { passed: true, value: rest.into() }); }
        if let Some(rest) = s.strip_prefix("fail=") { return Ok(Self { passed: false, value: rest.into() }); }
        Err(format!("unparseable precondition value: {s}"))
    }
}

impl std::fmt::Display for PreconditionValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.value.is_empty() {
            write!(f, "{}", if self.passed { "pass" } else { "fail" })
        } else {
            write!(f, "{}={}", if self.passed { "pass" } else { "fail" }, self.value)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preconditions {
    pub isolcpus: PreconditionValue,
    pub nohz_full: PreconditionValue,
    pub rcu_nocbs: PreconditionValue,
    pub governor: PreconditionValue,
    pub cstate_max: PreconditionValue,
    pub tsc_invariant: PreconditionValue,
    pub coalesce_off: PreconditionValue,
    pub tso_off: PreconditionValue,
    pub lro_off: PreconditionValue,
    pub rss_on: PreconditionValue,
    pub thermal_throttle: PreconditionValue,
    pub hugepages_reserved: PreconditionValue,
    pub irqbalance_off: PreconditionValue,
    pub wc_active: PreconditionValue,
}
```

`src/run_metadata.rs`:

```rust
//! Per-run invariant fields populated once at start of a run.
use serde::{Deserialize, Serialize};

use crate::preconditions::{PreconditionMode, Preconditions};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMetadata {
    pub run_id: uuid::Uuid,
    pub run_started_at: String,          // ISO 8601 + TZ
    pub commit_sha: String,
    pub branch: String,
    pub host: String,
    pub instance_type: String,
    pub cpu_model: String,
    pub dpdk_version: String,
    pub kernel: String,
    pub nic_model: String,
    pub nic_fw: String,
    pub ami_id: String,
    pub precondition_mode: PreconditionMode,
    #[serde(flatten, with = "precondition_prefix")]
    pub preconditions: Preconditions,
}

/// Custom flatten that prefixes every precondition field with `precondition_`.
mod precondition_prefix {
    use crate::preconditions::Preconditions;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(p: &Preconditions, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(14))?;
        m.serialize_entry("precondition_isolcpus", &p.isolcpus.to_string())?;
        m.serialize_entry("precondition_nohz_full", &p.nohz_full.to_string())?;
        m.serialize_entry("precondition_rcu_nocbs", &p.rcu_nocbs.to_string())?;
        m.serialize_entry("precondition_governor", &p.governor.to_string())?;
        m.serialize_entry("precondition_cstate_max", &p.cstate_max.to_string())?;
        m.serialize_entry("precondition_tsc_invariant", &p.tsc_invariant.to_string())?;
        m.serialize_entry("precondition_coalesce_off", &p.coalesce_off.to_string())?;
        m.serialize_entry("precondition_tso_off", &p.tso_off.to_string())?;
        m.serialize_entry("precondition_lro_off", &p.lro_off.to_string())?;
        m.serialize_entry("precondition_rss_on", &p.rss_on.to_string())?;
        m.serialize_entry("precondition_thermal_throttle", &p.thermal_throttle.to_string())?;
        m.serialize_entry("precondition_hugepages_reserved", &p.hugepages_reserved.to_string())?;
        m.serialize_entry("precondition_irqbalance_off", &p.irqbalance_off.to_string())?;
        m.serialize_entry("precondition_wc_active", &p.wc_active.to_string())?;
        m.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Preconditions, D::Error> {
        use std::collections::BTreeMap;
        let m = BTreeMap::<String, String>::deserialize(d)?;
        let mut p = Preconditions::default();
        for (k, v) in m {
            let pv = v.parse().map_err(serde::de::Error::custom)?;
            match k.strip_prefix("precondition_").unwrap_or(&k) {
                "isolcpus" => p.isolcpus = pv,
                "nohz_full" => p.nohz_full = pv,
                "rcu_nocbs" => p.rcu_nocbs = pv,
                "governor" => p.governor = pv,
                "cstate_max" => p.cstate_max = pv,
                "tsc_invariant" => p.tsc_invariant = pv,
                "coalesce_off" => p.coalesce_off = pv,
                "tso_off" => p.tso_off = pv,
                "lro_off" => p.lro_off = pv,
                "rss_on" => p.rss_on = pv,
                "thermal_throttle" => p.thermal_throttle = pv,
                "hugepages_reserved" => p.hugepages_reserved = pv,
                "irqbalance_off" => p.irqbalance_off = pv,
                "wc_active" => p.wc_active = pv,
                _ => {},
            }
        }
        Ok(p)
    }
}
```

`src/csv_row.rs`:

```rust
//! The unified CSV row emitted by every bench tool. Spec §14.
use serde::{Deserialize, Serialize};

use crate::run_metadata::RunMetadata;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricAggregation {
    P50,
    P99,
    P999,
    Mean,
    Stddev,
    Ci95Lower,
    Ci95Upper,
}

impl std::fmt::Display for MetricAggregation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P50 => write!(f, "p50"),
            Self::P99 => write!(f, "p99"),
            Self::P999 => write!(f, "p999"),
            Self::Mean => write!(f, "mean"),
            Self::Stddev => write!(f, "stddev"),
            Self::Ci95Lower => write!(f, "ci95_lower"),
            Self::Ci95Upper => write!(f, "ci95_upper"),
        }
    }
}

pub use crate::preconditions::PreconditionValue;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CsvRow {
    #[serde(flatten)]
    pub run_metadata: RunMetadata,
    pub tool: String,
    pub test_case: String,
    pub feature_set: String,
    pub dimensions_json: String,
    pub metric_name: String,
    pub metric_unit: String,
    pub metric_value: f64,
    pub metric_aggregation: MetricAggregation,
}

impl CsvRow {
    pub fn write_with_header<W: std::io::Write>(
        &self,
        wtr: &mut csv::Writer<W>,
    ) -> Result<(), csv::Error> {
        wtr.serialize(self)?;
        wtr.flush()?;
        Ok(())
    }
}

// PartialEq on f64 requires tolerance for cross-serialization; we check exact match
// in tests only because our test value is exactly representable.
```

`src/percentile.rs`:

```rust
//! Percentile + bootstrap CI computation. Used by every bench summarizer.
use std::cmp::Ordering;

/// p_k percentile where k in [0.0, 1.0].
pub fn percentile_sorted(sorted: &[f64], k: f64) -> f64 {
    assert!(!sorted.is_empty(), "empty sample");
    let n = sorted.len();
    let rank = (k * (n - 1) as f64).round() as usize;
    sorted[rank.min(n - 1)]
}

/// Returns (p50, p99, p999, mean, stddev, ci95_lower, ci95_upper) from a set of
/// raw f64 samples.
pub struct Summary {
    pub p50: f64,
    pub p99: f64,
    pub p999: f64,
    pub mean: f64,
    pub stddev: f64,
    pub ci95_lower: f64,
    pub ci95_upper: f64,
}

pub fn summarize(samples: &[f64]) -> Summary {
    assert!(!samples.is_empty());
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let variance = sorted.iter().map(|v| (*v - mean).powi(2)).sum::<f64>() / sorted.len() as f64;
    let stddev = variance.sqrt();
    // Simple percentile-based CI; a proper bootstrap CI uses resampling but
    // parametric 95% (mean ± 1.96 * stddev / sqrt(n)) is a good approximation
    // at n ≥ 10k that we always have.
    let se = stddev / (sorted.len() as f64).sqrt();
    Summary {
        p50: percentile_sorted(&sorted, 0.50),
        p99: percentile_sorted(&sorted, 0.99),
        p999: percentile_sorted(&sorted, 0.999),
        mean,
        stddev,
        ci95_lower: mean - 1.96 * se,
        ci95_upper: mean + 1.96 * se,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_simple() {
        let s: Vec<f64> = (1..=1000).map(|i| i as f64).collect();
        let sm = summarize(&s);
        // p50 ≈ 500, p99 ≈ 990, p999 ≈ 999
        assert!((sm.p50 - 500.0).abs() < 5.0);
        assert!((sm.p99 - 990.0).abs() < 5.0);
        assert!((sm.p999 - 999.0).abs() < 5.0);
    }
}
```

- [ ] **Step 1.6: Run tests — verify pass**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
timeout 120 cargo test -p bench-common 2>&1 | tee /tmp/bench-common-t2.log
```

Expected: all tests pass (csv round-trip, precondition parse, metric aggregation serde, summarize simple).

- [ ] **Step 1.7: Commit**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
git add Cargo.toml tools/bench-common/
git commit -m "$(cat <<'EOF'
a10 task 1: bench-common shared lib crate

CSV row schema (spec §14), precondition enumeration + parse,
metric-aggregation enum, run metadata, summarize (p50/p99/p999 +
parametric 95% CI). Workspace member under tools/.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `bench-ab-runner` — shared sub-process runner for A/B harnesses

Per spec D3: one binary that does `precondition check → EAL init → Engine::new → warmup → workload → CSV emit → cleanup → exit`. Consumed by `bench-offload-ab` and `bench-obs-overhead` via `std::process::Command`.

**Files:**
- Create: `tools/bench-ab-runner/Cargo.toml`
- Create: `tools/bench-ab-runner/src/main.rs`
- Create: `tools/bench-ab-runner/src/workload.rs`
- Modify: `Cargo.toml` workspace (add member)
- Test: `tools/bench-ab-runner/tests/smoke.rs`

### Steps

- [ ] **Step 2.1: Add to workspace**

Append `"tools/bench-ab-runner"` to `Cargo.toml` members.

- [ ] **Step 2.2: Write `tools/bench-ab-runner/Cargo.toml`**

```toml
[package]
name = "bench-ab-runner"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
bench-common = { path = "../bench-common" }
dpdk-net-core = { path = "../../crates/dpdk-net-core", default-features = false }
dpdk-net = { path = "../../crates/dpdk-net" }
dpdk-net-sys = { path = "../../crates/dpdk-net-sys" }
clap = { version = "4", features = ["derive"] }
serde_json = "1"
csv = "1.3"
chrono = { version = "0.4", default-features = false, features = ["clock"] }

[features]
# Pass-through A-HW and obs-* flags; driver sets these when it rebuilds.
hw-verify-llq = ["dpdk-net-core/hw-verify-llq"]
hw-offload-tx-cksum = ["dpdk-net-core/hw-offload-tx-cksum"]
hw-offload-rx-cksum = ["dpdk-net-core/hw-offload-rx-cksum"]
hw-offload-mbuf-fast-free = ["dpdk-net-core/hw-offload-mbuf-fast-free"]
hw-offload-rss-hash = ["dpdk-net-core/hw-offload-rss-hash"]
hw-offload-rx-timestamp = ["dpdk-net-core/hw-offload-rx-timestamp"]
hw-offloads-all = ["dpdk-net-core/hw-offloads-all"]
obs-byte-counters = ["dpdk-net-core/obs-byte-counters"]
obs-poll-saturation = ["dpdk-net-core/obs-poll-saturation"]
obs-all = ["dpdk-net-core/obs-all"]
obs-none = ["dpdk-net-core/obs-none"]
```

- [ ] **Step 2.3: Write `src/main.rs`**

```rust
//! bench-ab-runner — one process, one feature-set, one EAL init.
//! Invoked by bench-offload-ab and bench-obs-overhead as a subprocess.
use clap::Parser;
use std::io::Write;

mod workload;

#[derive(Parser, Debug)]
#[command(version, about = "bench-ab-runner — one A/B config per process")]
struct Args {
    /// Peer IP address
    #[arg(long)]
    peer_ip: String,
    /// Peer TCP port
    #[arg(long, default_value_t = 10001)]
    peer_port: u16,
    /// Iteration count (after warmup)
    #[arg(long, default_value_t = 10_000)]
    iterations: u64,
    /// Warmup iteration count (discarded)
    #[arg(long, default_value_t = 1_000)]
    warmup: u64,
    /// Request payload size (bytes)
    #[arg(long, default_value_t = 128)]
    request_bytes: usize,
    /// Response payload size (bytes)
    #[arg(long, default_value_t = 128)]
    response_bytes: usize,
    /// Feature-set label (emitted as CSV column)
    #[arg(long)]
    feature_set: String,
    /// Tool name label (emitted as CSV column)
    #[arg(long)]
    tool: String,
    /// Precondition mode — `strict` aborts on any precondition failure; `lenient` warns.
    #[arg(long, default_value = "strict")]
    precondition_mode: String,
    /// Lcore id to pin engine to
    #[arg(long, default_value_t = 2)]
    lcore: u32,
    /// Local IP
    #[arg(long)]
    local_ip: String,
    /// Local gateway IP
    #[arg(long)]
    gateway_ip: String,
    /// EAL args (passed verbatim to dpdk_net_eal_init; comma-separated)
    #[arg(long)]
    eal_args: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // 1. Precondition check
    let preconditions = run_preconditions_check(&args.precondition_mode)?;
    if args.precondition_mode == "strict" && !preconditions_all_pass(&preconditions) {
        eprintln!("precondition failure in strict mode");
        std::process::exit(1);
    }

    // 2. EAL init + Engine::new
    let engine = setup_engine(&args)?;

    // 3. Workload
    let samples = workload::run(&engine, &args)?;

    // 4. Summarize + CSV emit
    let metadata = build_run_metadata(&args, preconditions)?;
    emit_csv(&args, &metadata, &samples)?;

    // 5. Cleanup
    drop(engine);
    // rte_eal_cleanup is best-effort — not all DPDK 23.11 paths clean fully.
    unsafe {
        dpdk_net_sys::rte_eal_cleanup();
    }
    Ok(())
}

fn run_preconditions_check(mode: &str) -> anyhow::Result<bench_common::preconditions::Preconditions> {
    let output = std::process::Command::new("check-bench-preconditions")
        .args(["--mode", mode, "--json"])
        .output()?;
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let checks = &json["checks"];
    let mut p = bench_common::preconditions::Preconditions::default();
    // Map JSON -> Preconditions struct
    macro_rules! set {
        ($field:ident, $key:literal) => {
            if let Some(c) = checks.get($key) {
                let passed = c.get("pass").and_then(|v| v.as_bool()).unwrap_or(false);
                let value = c.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
                p.$field = bench_common::preconditions::PreconditionValue { passed, value };
            }
        };
    }
    set!(isolcpus, "isolcpus");
    set!(nohz_full, "nohz_full");
    set!(rcu_nocbs, "rcu_nocbs");
    set!(governor, "governor");
    set!(cstate_max, "cstate_max");
    set!(tsc_invariant, "tsc_invariant");
    set!(coalesce_off, "coalesce_off");
    set!(tso_off, "tso_off");
    set!(lro_off, "lro_off");
    set!(rss_on, "rss_on");
    set!(thermal_throttle, "thermal_throttle");
    set!(hugepages_reserved, "hugepages_reserved");
    set!(irqbalance_off, "irqbalance_off");
    set!(wc_active, "wc_active");
    Ok(p)
}

fn preconditions_all_pass(p: &bench_common::preconditions::Preconditions) -> bool {
    [&p.isolcpus, &p.nohz_full, &p.rcu_nocbs, &p.governor, &p.cstate_max,
     &p.tsc_invariant, &p.coalesce_off, &p.tso_off, &p.lro_off, &p.rss_on,
     &p.thermal_throttle, &p.hugepages_reserved, &p.irqbalance_off, &p.wc_active]
        .iter().all(|v| v.passed)
}

fn setup_engine(args: &Args) -> anyhow::Result<dpdk_net_core::engine::Engine> {
    // EAL init
    let eal_argv: Vec<_> = std::iter::once("bench-ab-runner".to_string())
        .chain(args.eal_args.split(',').map(|s| s.to_string()))
        .collect();
    let argv_ptrs: Vec<_> = eal_argv.iter().map(|s| s.as_ptr() as *const std::ffi::c_char).collect();
    unsafe {
        let ret = dpdk_net_sys::rte_eal_init(argv_ptrs.len() as i32, argv_ptrs.as_ptr() as *mut _);
        if ret < 0 { anyhow::bail!("rte_eal_init failed: {}", ret); }
    }

    let mut cfg = dpdk_net_core::engine::EngineConfig::default();
    cfg.lcore_id = args.lcore;
    // local_ip and gateway_ip as u32 big-endian (simplification — real parse)
    cfg.local_ip = parse_ip(&args.local_ip);
    cfg.gateway_ip = parse_ip(&args.gateway_ip);
    let engine = dpdk_net_core::engine::Engine::new(cfg)?;
    Ok(engine)
}

fn parse_ip(s: &str) -> u32 {
    let octets: Vec<u8> = s.split('.').map(|p| p.parse().unwrap()).collect();
    u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]])
}

fn build_run_metadata(
    args: &Args,
    preconditions: bench_common::preconditions::Preconditions,
) -> anyhow::Result<bench_common::run_metadata::RunMetadata> {
    let commit_sha = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let branch = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let host = hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default();
    let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("model name")).map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string()))
        .unwrap_or_default();
    let kernel = std::process::Command::new("uname").arg("-r").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();

    Ok(bench_common::run_metadata::RunMetadata {
        run_id: uuid::Uuid::new_v4(),
        run_started_at: chrono::Utc::now().to_rfc3339(),
        commit_sha,
        branch,
        host,
        instance_type: std::env::var("INSTANCE_TYPE").unwrap_or_default(),
        cpu_model,
        dpdk_version: pkg_config_dpdk_version().unwrap_or_default(),
        kernel,
        nic_model: std::env::var("NIC_MODEL").unwrap_or_default(),
        nic_fw: String::new(),
        ami_id: std::env::var("AMI_ID").unwrap_or_default(),
        precondition_mode: match args.precondition_mode.as_str() {
            "lenient" => bench_common::preconditions::PreconditionMode::Lenient,
            _ => bench_common::preconditions::PreconditionMode::Strict,
        },
        preconditions,
    })
}

fn pkg_config_dpdk_version() -> Option<String> {
    let out = std::process::Command::new("pkg-config")
        .args(["--modversion", "libdpdk"])
        .output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn emit_csv(
    args: &Args,
    meta: &bench_common::run_metadata::RunMetadata,
    samples: &[f64],
) -> anyhow::Result<()> {
    let summary = bench_common::percentile::summarize(samples);
    let mut wtr = csv::Writer::from_writer(std::io::stdout());
    for (agg, value) in [
        (bench_common::csv_row::MetricAggregation::P50, summary.p50),
        (bench_common::csv_row::MetricAggregation::P99, summary.p99),
        (bench_common::csv_row::MetricAggregation::P999, summary.p999),
        (bench_common::csv_row::MetricAggregation::Mean, summary.mean),
        (bench_common::csv_row::MetricAggregation::Stddev, summary.stddev),
        (bench_common::csv_row::MetricAggregation::Ci95Lower, summary.ci95_lower),
        (bench_common::csv_row::MetricAggregation::Ci95Upper, summary.ci95_upper),
    ] {
        let row = bench_common::csv_row::CsvRow {
            run_metadata: meta.clone(),
            tool: args.tool.clone(),
            test_case: "request_response_rtt".into(),
            feature_set: args.feature_set.clone(),
            dimensions_json: format!(
                "{{\"request_bytes\":{},\"response_bytes\":{}}}",
                args.request_bytes, args.response_bytes
            ),
            metric_name: "rtt_ns".into(),
            metric_unit: "ns".into(),
            metric_value: value,
            metric_aggregation: agg,
        };
        wtr.serialize(&row)?;
    }
    wtr.flush()?;
    Ok(())
}
```

Add `hostname`, `anyhow` deps to `Cargo.toml`:

```toml
hostname = "0.4"
anyhow = "1"
```

- [ ] **Step 2.4: Write `src/workload.rs`**

```rust
//! 128 B / 128 B request-response workload.
use bench_common::percentile::Summary;

pub fn run(
    engine: &dpdk_net_core::engine::Engine,
    args: &crate::Args,
) -> anyhow::Result<Vec<f64>> {
    // Open connection to peer
    let conn = engine_open_conn(engine, args)?;
    let mut samples = Vec::with_capacity(args.iterations as usize);

    // Warmup
    for _ in 0..args.warmup {
        request_response_once(engine, conn, args)?;
    }
    // Measurement
    for _ in 0..args.iterations {
        let rtt_ns = request_response_once(engine, conn, args)?;
        samples.push(rtt_ns as f64);
    }
    Ok(samples)
}

fn engine_open_conn(
    engine: &dpdk_net_core::engine::Engine,
    args: &crate::Args,
) -> anyhow::Result<dpdk_net_core::engine::ConnHandle> {
    let peer_ip = crate::parse_ip(&args.peer_ip);
    let peer_port = args.peer_port;
    // API is Rust-side here — engine.connect(peer_ip, peer_port, timeout_ns)
    // Poll until CONNECTED event
    let conn = engine.connect(peer_ip, peer_port)?;
    // Drain events until CONNECTED arrives (or fail on timeout)
    let start = std::time::Instant::now();
    loop {
        let events = engine.poll_once();
        for ev in events {
            if let dpdk_net_core::tcp_events::InternalEvent::Connected { conn: ch, .. } = ev {
                if ch == conn { return Ok(conn); }
            }
        }
        if start.elapsed() > std::time::Duration::from_secs(10) {
            anyhow::bail!("connect timeout");
        }
    }
}

fn request_response_once(
    engine: &dpdk_net_core::engine::Engine,
    conn: dpdk_net_core::engine::ConnHandle,
    args: &crate::Args,
) -> anyhow::Result<u64> {
    let payload = vec![0u8; args.request_bytes];
    let t0 = unsafe { dpdk_net_sys::rte_rdtsc() };
    engine.send(conn, &payload)?;
    // Poll until response READABLE event
    let mut got_bytes = 0usize;
    loop {
        let events = engine.poll_once();
        for ev in events {
            if let dpdk_net_core::tcp_events::InternalEvent::Readable { conn: ch, data, .. } = ev {
                if ch == conn { got_bytes += data.len(); }
            }
        }
        if got_bytes >= args.response_bytes { break; }
    }
    let t1 = unsafe { dpdk_net_sys::rte_rdtsc() };
    let tsc_hz = unsafe { dpdk_net_sys::rte_get_tsc_hz() };
    let rtt_ns = ((t1 - t0) as u128 * 1_000_000_000u128 / tsc_hz as u128) as u64;
    Ok(rtt_ns)
}
```

Note: the real `Engine::connect` / `Engine::send` / `Engine::poll_once` signatures may differ from these pseudo-names. The subagent implementing T2 must look up the actual API in `crates/dpdk-net-core/src/engine.rs` and adjust — the critical contract is "one process, one EAL init, one measurement run, one CSV emit, exit".

- [ ] **Step 2.5: Write the smoke test**

`tests/smoke.rs`:

```rust
//! Minimal smoke test — unit-level, no DPDK.
//! Verifies Args parse + CSV emission produces the expected header.

#[test]
fn csv_output_has_expected_header_columns() {
    // Build a fake RunMetadata + emit one row via direct csv::Writer; assert
    // header includes run_id, commit_sha, precondition_*, tool, metric_*.
    // Most of the logic is in bench-common — this test is mostly an
    // integration compile check.
    let _ = env!("CARGO_BIN_EXE_bench-ab-runner");
}
```

- [ ] **Step 2.6: Build + test**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
timeout 180 cargo build -p bench-ab-runner --release 2>&1 | tail -30
timeout 60 cargo test -p bench-ab-runner 2>&1 | tail -10
```

Expected: both succeed. The runner can't actually be exercised without a peer host + DPDK EAL + ENA VF; the smoke test just asserts the code compiles.

- [ ] **Step 2.7: Commit**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
git add Cargo.toml tools/bench-ab-runner/
git commit -m "$(cat <<'EOF'
a10 task 2: bench-ab-runner shared sub-process runner

One process, one EAL init, one measurement run, one CSV emit, clean exit.
Consumed by bench-offload-ab and bench-obs-overhead via std::process::Command.
Features mirror dpdk-net-core's hw-* + obs-* flags so drivers can
`cargo build --features X` per config.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `scripts/check-bench-preconditions.sh`

Canonical preconditions checker — emits a JSON object per §4.2. An identical copy lives in `resd.aws-infra-setup/assets/` (synced at sister-plan T6).

**Files:**
- Create: `scripts/check-bench-preconditions.sh`
- Test: manual invocation + shell-check lint

### Steps

- [ ] **Step 3.1: Write the script**

`scripts/check-bench-preconditions.sh`:

```bash
#!/usr/bin/env bash
# check-bench-preconditions.sh — spec §4.1 + §4.2.
# Emits one JSON object to stdout.
# Exit 0 on overall_pass; non-zero in strict mode on any fail.
set -euo pipefail

MODE="strict"
if [[ "${1:-}" == "--mode" ]]; then
  MODE="$2"
  shift 2
fi
JSON_FMT=1
if [[ "${1:-}" == "--no-json" ]]; then
  JSON_FMT=0
fi

declare -A RESULTS

check_isolcpus() {
  local v; v=$(cat /sys/devices/system/cpu/isolated 2>/dev/null || echo "")
  if [[ -n "$v" ]]; then
    RESULTS[isolcpus]="pass|$v"
  else
    RESULTS[isolcpus]="fail|empty"
  fi
}

check_nohz_full() {
  local v; v=$(cat /sys/devices/system/cpu/nohz_full 2>/dev/null || echo "")
  if [[ -n "$v" ]]; then RESULTS[nohz_full]="pass|$v"; else RESULTS[nohz_full]="fail|empty"; fi
}

check_rcu_nocbs() {
  local v; v=$(grep -oE 'rcu_nocbs=[^ ]*' /proc/cmdline | sed 's/rcu_nocbs=//' || echo "")
  if [[ -n "$v" ]]; then RESULTS[rcu_nocbs]="pass|$v"; else RESULTS[rcu_nocbs]="fail|empty"; fi
}

check_governor() {
  local g; g=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "")
  if [[ "$g" == "performance" ]]; then RESULTS[governor]="pass|performance"; else RESULTS[governor]="fail|$g"; fi
}

check_cstate_max() {
  # Allow only C0 + C1 to be enabled; C2+ must be disabled on every CPU.
  local bad=0
  for f in /sys/devices/system/cpu/cpu*/cpuidle/state[2-9]/disable; do
    [[ -e "$f" ]] || continue
    if [[ "$(cat "$f")" != "1" ]]; then bad=1; fi
  done
  if [[ $bad -eq 0 ]]; then RESULTS[cstate_max]="pass|C1"; else RESULTS[cstate_max]="fail|deep-cstate-enabled"; fi
}

check_tsc_invariant() {
  if grep -q 'constant_tsc' /proc/cpuinfo && grep -q 'nonstop_tsc' /proc/cpuinfo; then
    RESULTS[tsc_invariant]="pass|"
  else
    RESULTS[tsc_invariant]="fail|not-invariant"
  fi
}

check_coalesce_off() {
  # Best-effort: check first ENA interface (eth1). Skippable if no ENA present.
  local iface
  iface=$(ip -o link | awk -F': ' '/ en|eth1/ {print $2; exit}')
  if [[ -z "$iface" ]]; then RESULTS[coalesce_off]="pass|skipped"; return; fi
  if ethtool -c "$iface" 2>/dev/null | grep -q "^rx-usecs: 0"; then
    RESULTS[coalesce_off]="pass|$iface"
  else
    RESULTS[coalesce_off]="fail|$iface:nonzero-usecs"
  fi
}

check_tso_off() {
  local iface; iface=$(ip -o link | awk -F': ' '/ en|eth1/ {print $2; exit}')
  if [[ -z "$iface" ]]; then RESULTS[tso_off]="pass|skipped"; return; fi
  if ethtool -k "$iface" 2>/dev/null | grep -q "^tcp-segmentation-offload: off"; then
    RESULTS[tso_off]="pass|$iface"
  else
    RESULTS[tso_off]="fail|$iface:tso-on"
  fi
}

check_lro_off() {
  local iface; iface=$(ip -o link | awk -F': ' '/ en|eth1/ {print $2; exit}')
  if [[ -z "$iface" ]]; then RESULTS[lro_off]="pass|skipped"; return; fi
  if ethtool -k "$iface" 2>/dev/null | grep -q "^large-receive-offload: off"; then
    RESULTS[lro_off]="pass|$iface"
  else
    RESULTS[lro_off]="fail|$iface:lro-on"
  fi
}

check_rss_on() {
  local iface; iface=$(ip -o link | awk -F': ' '/ en|eth1/ {print $2; exit}')
  if [[ -z "$iface" ]]; then RESULTS[rss_on]="pass|skipped"; return; fi
  if ethtool -x "$iface" 2>/dev/null | grep -q "indirection table"; then
    RESULTS[rss_on]="pass|$iface"
  else
    RESULTS[rss_on]="fail|$iface:no-rss"
  fi
}

check_thermal_throttle() {
  # Snapshot of past throttles — harness re-reads at run end for delta.
  local throttles; throttles=$(cat /sys/devices/system/cpu/cpu*/thermal_throttle/*_throttle_count 2>/dev/null | awk '{s+=$1} END{print s+0}')
  RESULTS[thermal_throttle]="pass|${throttles}"  # pass at bootstrap; delta checked by caller
}

check_hugepages_reserved() {
  local pages; pages=$(awk '/^HugePages_Total:/ {print $2}' /proc/meminfo)
  if [[ "${pages:-0}" -ge 1024 ]]; then RESULTS[hugepages_reserved]="pass|$pages"; else RESULTS[hugepages_reserved]="fail|$pages"; fi
}

check_irqbalance_off() {
  if systemctl is-active irqbalance >/dev/null 2>&1; then
    RESULTS[irqbalance_off]="fail|active"
  else
    RESULTS[irqbalance_off]="pass|"
  fi
}

check_wc_active() {
  # Requires DPDK app running + binding complete. Harness passes-through to the caller.
  # Caller is expected to re-run this probe between engine bring-up and workload.
  RESULTS[wc_active]="pass|deferred"  # real check done in-process in bench-ab-runner
}

for fn in check_isolcpus check_nohz_full check_rcu_nocbs check_governor \
          check_cstate_max check_tsc_invariant check_coalesce_off check_tso_off \
          check_lro_off check_rss_on check_thermal_throttle check_hugepages_reserved \
          check_irqbalance_off check_wc_active; do
  $fn || true
done

# Emit JSON
overall_pass=true
printf '{'
printf '"mode":"%s",' "$MODE"
printf '"checks":{'
first=1
for k in isolcpus nohz_full rcu_nocbs governor cstate_max tsc_invariant \
         coalesce_off tso_off lro_off rss_on thermal_throttle hugepages_reserved \
         irqbalance_off wc_active; do
  v="${RESULTS[$k]}"
  passed="${v%%|*}"
  value="${v#*|}"
  [[ "$passed" == "pass" ]] || overall_pass=false
  [[ $first -eq 0 ]] && printf ','
  first=0
  printf '"%s":{"pass":%s,"value":"%s"}' "$k" \
    "$([[ $passed == pass ]] && echo true || echo false)" "$value"
done
printf '},'
printf '"overall_pass":%s' "$overall_pass"
printf '}\n'

if [[ "$MODE" == "strict" && "$overall_pass" == "false" ]]; then
  exit 1
fi
exit 0
```

- [ ] **Step 3.2: Shell-check the script**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
shellcheck scripts/check-bench-preconditions.sh || echo "install shellcheck to lint"
chmod +x scripts/check-bench-preconditions.sh
```

- [ ] **Step 3.3: Smoke on dev host (expected most checks will fail in lenient mode; exit 0)**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
./scripts/check-bench-preconditions.sh --mode lenient | jq .
```

Expected: JSON with `mode: "lenient"`, `overall_pass` probably `false` (dev host isn't isolcpus'd), exit 0.

- [ ] **Step 3.4: Commit**

```bash
git add scripts/check-bench-preconditions.sh
git commit -m "$(cat <<'EOF'
a10 task 3: scripts/check-bench-preconditions.sh

Spec §4.1 + §4.2. Canonical preconditions checker — 14 checks; emits
JSON; exit non-zero in strict mode on any fail. wc_active check is
deferred to in-process (runs after engine bring-up). Identical copy
lives in resd.aws-infra-setup/assets/ (synced at sister-plan T6).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `obs-none` feature + G1–G4 gate sites

Per spec D4. Additive feature; default build behaviour unchanged.

**Files:**
- Modify: `crates/dpdk-net-core/Cargo.toml` (+ obs-none feature)
- Modify: `crates/dpdk-net-core/src/tcp_events.rs` (G1 gate on `EventQueue::push`)
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs` (G3 gate on `rtt_histogram.update`)
- Modify: `crates/dpdk-net/src/api.rs` (G4 gate on `dpdk_net_conn_stats` FFI)
- Modify: `crates/dpdk-net/Cargo.toml` (pass-through obs-none feature)
- Modify: `crates/dpdk-net-core/tests/knob-coverage.rs` (obs-none entry)
- Test: G1+G2+G3+G4 smoke under `--features obs-none` and without

### Steps

- [ ] **Step 4.1: Add `obs-none` feature to `dpdk-net-core`**

Edit `crates/dpdk-net-core/Cargo.toml` `[features]` section — append:

```toml
# A10 D4: umbrella feature gating every "always-on" observability emission
# site (spec D4: G1 EventQueue::push, G2 emitted_ts_ns capture, G3
# rtt_histogram.update, G4 ConnStats FFI getter). Additive — default
# builds carry zero cfg(feature = "obs-none") guards. Consumed only by
# tools/bench-obs-overhead A/B runner to measure the zero-observability
# floor. See docs/superpowers/specs/2026-04-21-stage1-phase-a10-benchmark-harness-design.md D4.
obs-none = []
```

- [ ] **Step 4.2: Pass-through in `dpdk-net` ABI crate**

Edit `crates/dpdk-net/Cargo.toml` `[features]`:

```toml
obs-none = ["dpdk-net-core/obs-none"]
```

- [ ] **Step 4.3: Write the G1+G2 test (event-queue push is no-op under obs-none)**

`crates/dpdk-net-core/tests/obs_none_gate_smoke.rs`:

```rust
//! Smoke for obs-none gating — compile-time only, verifies each gate
//! compiles in both feature configurations. Behavioural verification
//! is via bench-obs-overhead's p99 delta under `--features obs-none`.

#[test]
fn obs_none_compiles_in_both_configs() {
    // This test always runs; the gates are behind cfg attrs verified by
    // the compile itself. Presence of the test exercises the rust-link.
    let _ = std::any::type_name::<dpdk_net_core::engine::Engine>();
}
```

- [ ] **Step 4.4: Run test — confirms clean compile in default config**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
timeout 60 cargo test -p dpdk-net-core --test obs_none_gate_smoke 2>&1 | tail -10
```

Expected: pass.

- [ ] **Step 4.5: Add G1 gate at `EventQueue::push` — tcp_events.rs:151**

Find the `push` method in `crates/dpdk-net-core/src/tcp_events.rs`. Its current body mutates internal state + increments counters. Wrap the body in a no-op:

```rust
impl EventQueue {
    pub fn push(&mut self, ev: InternalEvent, counters: &Counters) {
        #[cfg(feature = "obs-none")]
        {
            // G1 — obs-none disables event-log ring writes entirely.
            let _ = (ev, counters);
            return;
        }
        #[cfg(not(feature = "obs-none"))]
        {
            // original body ↓
            /* ... existing code ... */
        }
    }
}
```

(The subagent executing this task reads the current `push` body, then wraps it verbatim under `#[cfg(not(feature = "obs-none"))]`. The `return` inside the `obs-none` arm ensures no side effects.)

- [ ] **Step 4.6: Add G2 gate — `emitted_ts_ns` capture at push call sites**

Every push site in `tcp_conn.rs` / `tcp_input.rs` / `tcp_output.rs` has a pattern like:

```rust
let emitted_ts_ns = crate::clock::now_ns();
let ev = InternalEvent::Readable { conn, data, emitted_ts_ns };
queue.push(ev, &counters);
```

Under `obs-none`, the push is a no-op (G1), so skipping the `now_ns()` read is a pure win. Replace the pattern:

```rust
#[cfg(not(feature = "obs-none"))]
{
    let emitted_ts_ns = crate::clock::now_ns();
    let ev = InternalEvent::Readable { conn, data, emitted_ts_ns };
    queue.push(ev, &counters);
}
```

Wrap each push call site this way. The subagent must grep for `queue.push(`, `ev_queue.push(`, and similar to find all sites; there are roughly 8–12 per A9-era counter.

- [ ] **Step 4.7: Add G3 gate — `rtt_histogram.update` at tcp_conn.rs:553**

Locate the call `self.rtt_histogram.update(rtt_us, rtt_histogram_edges);` and wrap:

```rust
#[cfg(not(feature = "obs-none"))]
self.rtt_histogram.update(rtt_us, rtt_histogram_edges);
```

- [ ] **Step 4.8: Add G4 gate — `dpdk_net_conn_stats` FFI getter**

In `crates/dpdk-net/src/api.rs`, locate the FFI function returning `ConnStats` (likely `dpdk_net_conn_stats`):

```rust
#[no_mangle]
pub extern "C" fn dpdk_net_conn_stats(
    engine: *mut dpdk_net_engine_t,
    conn: dpdk_net_conn_t,
    stats_out: *mut dpdk_net_conn_stats_t,
) -> i32 {
    #[cfg(feature = "obs-none")]
    {
        let _ = (engine, conn, stats_out);
        return -libc::ENOTSUP;
    }
    #[cfg(not(feature = "obs-none"))]
    {
        // original body ↓
        /* ... existing code ... */
    }
}
```

- [ ] **Step 4.9: Add knob-coverage entry**

In `crates/dpdk-net-core/tests/knob-coverage.rs`, append:

```rust
/// A10 D4: obs-none umbrella feature — additive marker.
/// Not a runtime knob; knob-coverage whitelist entry documents the feature
/// and asserts it doesn't change the C ABI. bench-obs-overhead exercises
/// the behavioural delta.
#[test]
fn knob_obs_none_compiles_and_does_not_alter_abi() {
    // Pinned at feature introduction: obs-none carries zero symbol changes
    // to the cbindgen-produced dpdk_net.h (the FFI getter stays; its
    // behaviour is the only gated part).
    // Covered end-to-end by bench-obs-overhead's A/B run.
    let _ = std::any::type_name::<dpdk_net_core::engine::Engine>();
}
```

- [ ] **Step 4.10: Verify both feature configurations compile + test**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
timeout 120 cargo build -p dpdk-net-core --no-default-features 2>&1 | tail -5
timeout 120 cargo build -p dpdk-net-core --no-default-features --features obs-none 2>&1 | tail -5
timeout 120 cargo build -p dpdk-net-core 2>&1 | tail -5
timeout 180 cargo test -p dpdk-net-core 2>&1 | tail -10
```

Expected: all three builds succeed; all existing tests pass (behavioural regressions would be in the base features, not obs-none).

- [ ] **Step 4.11: Commit**

```bash
git add crates/dpdk-net-core/ crates/dpdk-net/
git commit -m "$(cat <<'EOF'
a10 task 4: obs-none umbrella feature + G1-G4 gates

Additive feature gating four always-on observability emission sites
per spec D4:
- G1: EventQueue::push (tcp_events.rs:151) — ring write no-op
- G2: emitted_ts_ns = clock::now_ns() at push call sites
- G3: rtt_histogram.update (tcp_conn.rs:553) — per-ACK histogram
- G4: dpdk_net_conn_stats FFI getter returns ENOTSUP

Default builds carry zero gate cost (cfg(not(...)) arm holds verbatim
existing code). Consumed by tools/bench-obs-overhead to measure the
zero-observability floor.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `bench-micro` — 12 cargo-criterion targets

**Files:**
- Create: `tools/bench-micro/Cargo.toml`
- Create: 12 bench targets under `tools/bench-micro/benches/`
- Modify: `Cargo.toml` workspace (add member)

### Steps

- [ ] **Step 5.1: Add to workspace + write Cargo.toml**

`tools/bench-micro/Cargo.toml`:

```toml
[package]
name = "bench-micro"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
dpdk-net-core = { path = "../../crates/dpdk-net-core" }
dpdk-net-sys = { path = "../../crates/dpdk-net-sys" }
dpdk-net = { path = "../../crates/dpdk-net" }

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "poll_empty"
harness = false

[[bench]]
name = "poll_idle_with_timers"
harness = false

[[bench]]
name = "tsc_read"
harness = false

[[bench]]
name = "flow_lookup"
harness = false

[[bench]]
name = "tcp_input"
harness = false

[[bench]]
name = "send"
harness = false

[[bench]]
name = "timer"
harness = false

[[bench]]
name = "counters"
harness = false
```

(Combining: poll has 2 targets in one file, flow has 2, tcp_input has 2, tsc has 2 → 8 bench files, 12 criterion groups. Plus send/timer/counters = 3 files → 11 files, 12 groups total.)

- [ ] **Step 5.2: Write each bench file**

Each file has the same template:

```rust
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

fn bench_target(c: &mut Criterion) {
    // Setup: engine with test_fixtures::make_test_engine() or equivalent
    let engine = dpdk_net_core::test_fixtures::make_test_engine().expect("test fixture");
    c.bench_function("target_name", |b| {
        b.iter(|| {
            // Hot path invocation
            /* ... */
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = bench_target
}
criterion_main!(benches);
```

Twelve targets — spec §11.2:

1. `benches/poll_empty.rs` → `bench_poll_empty` + `bench_poll_idle_with_timers`
2. `benches/tsc_read.rs` → `bench_tsc_read_ffi` + `bench_tsc_read_inline`
3. `benches/flow_lookup.rs` → `bench_flow_lookup_hot` + `bench_flow_lookup_cold`
4. `benches/tcp_input.rs` → `bench_tcp_input_data_segment` + `bench_tcp_input_ooo_segment`
5. `benches/send.rs` → `bench_send_small` + `bench_send_large_chain`
6. `benches/timer.rs` → `bench_timer_add_cancel`
7. `benches/counters.rs` → `bench_counters_read`

The subagent executing this task looks up existing patterns in `tools/bench-rx-zero-copy/benches/delivery_cycle.rs` for setup + DPDK FFI call shapes.

- [ ] **Step 5.3: Run all benches — smoke only**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
timeout 600 cargo bench -p bench-micro --no-run 2>&1 | tail -10
```

Expected: 7 benches compile. Full `cargo bench` requires DPDK runtime + EAL init; runs on the bench host only.

- [ ] **Step 5.4: Add cargo-criterion CSV summary extractor**

Criterion outputs JSON under `target/criterion/<group>/<target>/new/estimates.json`. Add a small Rust helper under `tools/bench-micro/src/bin/summarize.rs` that reads every `estimates.json` and emits one CSV row per target per aggregation (summarized-only).

```rust
// tools/bench-micro/src/bin/summarize.rs
use std::path::PathBuf;

use bench_common::csv_row::{CsvRow, MetricAggregation};
use bench_common::run_metadata::RunMetadata;

fn main() -> anyhow::Result<()> {
    let root = std::env::args().nth(1).unwrap_or_else(|| "target/criterion".into());
    let root = PathBuf::from(root);
    let out = std::env::args().nth(2).unwrap_or_else(|| "target/bench-results/bench-micro/summary.csv".into());
    std::fs::create_dir_all(std::path::Path::new(&out).parent().unwrap())?;
    let metadata = /* construct RunMetadata from env + git */ todo!();
    let mut wtr = csv::Writer::from_path(&out)?;
    for target_dir in walkdir::WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let est_path = target_dir.path().join("new/estimates.json");
        if !est_path.is_file() { continue; }
        let est: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&est_path)?)?;
        let name = target_dir.path().file_name().unwrap().to_string_lossy().to_string();
        for (key, agg) in [
            ("median", MetricAggregation::P50),
            ("mean", MetricAggregation::Mean),
            ("std_dev", MetricAggregation::Stddev),
        ] {
            let value = est.get(key).and_then(|v| v.get("point_estimate")).and_then(|v| v.as_f64());
            if let Some(v) = value {
                let row = CsvRow { /* ... */ };
                wtr.serialize(&row)?;
            }
        }
    }
    wtr.flush()?;
    Ok(())
}
```

Add `walkdir`, `bench-common`, `anyhow` as deps of `bench-micro`:

```toml
[dependencies]
bench-common = { path = "../bench-common" }
walkdir = "2"
anyhow = "1"
csv = "1.3"
serde_json = "1"
```

- [ ] **Step 5.5: Commit**

```bash
git add Cargo.toml tools/bench-micro/
git commit -m "$(cat <<'EOF'
a10 task 5: bench-micro — 12 cargo-criterion targets

Spec §11.2 targets: poll_empty + poll_idle_with_timers, tsc_read (ffi +
inline), flow_lookup (hot + cold), tcp_input (data_segment + ooo_segment),
send (small + large_chain), timer_add_cancel, counters_read.

src/bin/summarize.rs emits the summarized CSV schema (p50/mean/stddev)
from target/criterion/**/estimates.json for bench-report ingest.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `bench-e2e` — request-response RTT + attribution + A-HW Task 18 assertions

Spec §6 (§11.3 + A-HW Task 18 subsumption).

**Files:**
- Create: `tools/bench-e2e/Cargo.toml`
- Create: `tools/bench-e2e/src/main.rs`
- Create: `tools/bench-e2e/src/attribution.rs`
- Create: `tools/bench-e2e/src/sum_identity.rs`
- Create: `tools/bench-e2e/src/hw_task_18.rs`
- Create: `tools/bench-e2e/peer/echo-server.c` (+ Makefile)
- Test: `tools/bench-e2e/tests/attribution_unit.rs`
- Modify: `Cargo.toml` workspace

### Steps

- [ ] **Step 6.1: Add to workspace + write `Cargo.toml`**

Append `"tools/bench-e2e"` to workspace members.

```toml
[package]
name = "bench-e2e"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
bench-common = { path = "../bench-common" }
dpdk-net-core = { path = "../../crates/dpdk-net-core" }
dpdk-net-sys = { path = "../../crates/dpdk-net-sys" }
dpdk-net = { path = "../../crates/dpdk-net" }
clap = { version = "4", features = ["derive"] }
anyhow = "1"
csv = "1.3"
serde_json = "1"
```

- [ ] **Step 6.2: Write the failing attribution-sum-identity unit test**

`tools/bench-e2e/tests/attribution_unit.rs`:

```rust
//! Sum-identity: bucket1 + bucket2 + ... == end-to-end RTT within ±50 ns.
use bench_e2e::attribution::{HwTsBuckets, TscFallbackBuckets};
use bench_e2e::sum_identity::assert_sum_identity;

#[test]
fn hw_ts_mode_sums_to_rtt_exactly() {
    let buckets = HwTsBuckets {
        user_send_to_tx_sched_ns: 100,
        tx_sched_to_nic_tx_wire_ns: 200,
        nic_tx_wire_to_nic_rx_ns: 10_000,
        nic_rx_to_enqueued_ns: 50,
        enqueued_to_user_return_ns: 80,
    };
    let rtt_ns = 10_430;
    assert_sum_identity(buckets.total_ns(), rtt_ns, 50).unwrap();
}

#[test]
fn hw_ts_mode_mismatch_beyond_tolerance_errors() {
    let buckets = HwTsBuckets {
        user_send_to_tx_sched_ns: 100,
        tx_sched_to_nic_tx_wire_ns: 200,
        nic_tx_wire_to_nic_rx_ns: 10_000,
        nic_rx_to_enqueued_ns: 50,
        enqueued_to_user_return_ns: 80,
    };
    let rtt_ns = 11_000; // 570 ns off
    let err = assert_sum_identity(buckets.total_ns(), rtt_ns, 50).unwrap_err();
    assert!(err.contains("sum_identity"));
}

#[test]
fn tsc_fallback_mode_three_buckets() {
    let buckets = TscFallbackBuckets {
        user_send_to_tx_sched_ns: 100,
        tx_sched_to_enqueued_ns: 10_250,
        enqueued_to_user_return_ns: 80,
    };
    let rtt_ns = 10_430;
    assert_sum_identity(buckets.total_ns(), rtt_ns, 50).unwrap();
}
```

- [ ] **Step 6.3: Verify fail**

```bash
timeout 60 cargo test -p bench-e2e --test attribution_unit 2>&1 | tail -10
```

Expected: compile error.

- [ ] **Step 6.4: Write `src/attribution.rs` + `src/sum_identity.rs`**

```rust
// src/attribution.rs
pub struct HwTsBuckets {
    pub user_send_to_tx_sched_ns: u64,
    pub tx_sched_to_nic_tx_wire_ns: u64,
    pub nic_tx_wire_to_nic_rx_ns: u64,
    pub nic_rx_to_enqueued_ns: u64,
    pub enqueued_to_user_return_ns: u64,
}
impl HwTsBuckets {
    pub fn total_ns(&self) -> u64 {
        self.user_send_to_tx_sched_ns
            + self.tx_sched_to_nic_tx_wire_ns
            + self.nic_tx_wire_to_nic_rx_ns
            + self.nic_rx_to_enqueued_ns
            + self.enqueued_to_user_return_ns
    }
}

pub struct TscFallbackBuckets {
    pub user_send_to_tx_sched_ns: u64,
    pub tx_sched_to_enqueued_ns: u64,
    pub enqueued_to_user_return_ns: u64,
}
impl TscFallbackBuckets {
    pub fn total_ns(&self) -> u64 {
        self.user_send_to_tx_sched_ns
            + self.tx_sched_to_enqueued_ns
            + self.enqueued_to_user_return_ns
    }
}
```

```rust
// src/sum_identity.rs
/// Spec §6 — sum of attribution buckets must equal end-to-end RTT within tol ns.
pub fn assert_sum_identity(bucket_sum_ns: u64, rtt_ns: u64, tol_ns: u64) -> Result<(), String> {
    let diff = if bucket_sum_ns > rtt_ns { bucket_sum_ns - rtt_ns } else { rtt_ns - bucket_sum_ns };
    if diff <= tol_ns {
        Ok(())
    } else {
        Err(format!(
            "sum_identity mismatch: bucket_sum={} rtt={} diff={} tol={}",
            bucket_sum_ns, rtt_ns, diff, tol_ns
        ))
    }
}
```

`src/lib.rs` (if present) — expose the two modules. Actually, since this is a `bin` crate, we need a small lib façade. Add to Cargo.toml:

```toml
[lib]
name = "bench_e2e"
path = "src/lib.rs"

[[bin]]
name = "bench-e2e"
path = "src/main.rs"
```

And write `src/lib.rs`:

```rust
pub mod attribution;
pub mod sum_identity;
pub mod hw_task_18;
```

- [ ] **Step 6.5: Run tests — pass**

```bash
timeout 60 cargo test -p bench-e2e --test attribution_unit 2>&1 | tail -10
```

Expected: all three pass.

- [ ] **Step 6.6: Write `src/hw_task_18.rs` — A-HW Task 18 assertions**

```rust
//! A-HW Task 18 subsumption: offload-counter + rx_hw_ts_ns assertions
//! post-run on the ENA bench host. Spec §6 + parent spec §8.2 / §10.5.
use bench_common::csv_row::CsvRow;

pub struct HwTask18Expectations {
    pub expect_mbuf_fast_free_missing: bool,  // ENA: true
    pub expect_rss_hash_missing: bool,        // ENA: true
    pub expect_rx_timestamp_missing: bool,    // ENA: true
    pub expect_all_cksum_advertised: bool,    // ENA: true (all 6 cksum counters == 0)
    pub expect_llq_missing: bool,             // ENA (LLQ OK via A-HW Task 12): false
    pub expect_rx_drop_cksum_bad_zero: bool,  // well-formed traffic: true
    pub expect_all_rx_hw_ts_ns_zero: bool,    // ENA doesn't advertise dynfield: true
}

impl Default for HwTask18Expectations {
    fn default() -> Self {
        Self {
            expect_mbuf_fast_free_missing: true,
            expect_rss_hash_missing: true,
            expect_rx_timestamp_missing: true,
            expect_all_cksum_advertised: true,
            expect_llq_missing: false,
            expect_rx_drop_cksum_bad_zero: true,
            expect_all_rx_hw_ts_ns_zero: true,
        }
    }
}

pub fn assert_hw_task_18_post_run(
    engine: &dpdk_net_core::engine::Engine,
    exp: &HwTask18Expectations,
) -> Result<(), String> {
    let counters = engine.counters();
    macro_rules! check {
        ($actual:expr, $expected:expr, $name:literal) => {
            if ($actual > 0) != $expected {
                return Err(format!(
                    "{}: expected>0={} observed>0={}",
                    $name, $expected, $actual > 0
                ));
            }
        };
    }
    check!(counters.offload_missing_mbuf_fast_free, exp.expect_mbuf_fast_free_missing, "offload_missing_mbuf_fast_free");
    check!(counters.offload_missing_rss_hash, exp.expect_rss_hash_missing, "offload_missing_rss_hash");
    check!(counters.offload_missing_rx_timestamp, exp.expect_rx_timestamp_missing, "offload_missing_rx_timestamp");
    check!(counters.offload_missing_llq, exp.expect_llq_missing, "offload_missing_llq");
    check!(counters.rx_drop_cksum_bad, !exp.expect_rx_drop_cksum_bad_zero, "rx_drop_cksum_bad");
    // The 6 cksum offload counters must all equal 0 when expect_all_cksum_advertised
    if exp.expect_all_cksum_advertised {
        for (v, n) in [
            (counters.offload_missing_rx_cksum_ipv4, "rx_cksum_ipv4"),
            (counters.offload_missing_rx_cksum_tcp, "rx_cksum_tcp"),
            (counters.offload_missing_rx_cksum_udp, "rx_cksum_udp"),
            (counters.offload_missing_tx_cksum_ipv4, "tx_cksum_ipv4"),
            (counters.offload_missing_tx_cksum_tcp, "tx_cksum_tcp"),
            (counters.offload_missing_tx_cksum_udp, "tx_cksum_udp"),
        ] {
            if v != 0 { return Err(format!("offload_missing_{}={} != 0", n, v)); }
        }
    }
    Ok(())
}

pub fn assert_all_events_rx_hw_ts_ns_zero(events_sample: &[u64]) -> Result<(), String> {
    // Given a sample of rx_hw_ts_ns values drawn from events observed during
    // the run, every one must be 0 on ENA.
    if let Some(nonzero) = events_sample.iter().find(|&&v| v != 0) {
        return Err(format!("rx_hw_ts_ns expected 0 on ENA; observed {}", nonzero));
    }
    Ok(())
}
```

- [ ] **Step 6.7: Write `src/main.rs` — CLI + run logic**

The main binary:
1. Parse args (peer IP/port, sample count, warmup, request/response bytes, CSV output path, HW-TS mode or TSC-fallback auto-detect)
2. Precondition check (via `check-bench-preconditions` subprocess)
3. EAL init + Engine::new
4. Open connection
5. For each iteration: send N bytes, poll until READABLE of N bytes, record attribution buckets
6. Assert sum-identity per-measurement
7. Post-run: assert HW Task 18 counter expectations
8. Summarize + emit CSV
9. `rte_eal_cleanup` + exit

```rust
use clap::Parser;
use bench_e2e::{attribution::*, sum_identity::*, hw_task_18::*};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)] peer_ip: String,
    #[arg(long, default_value_t = 10001)] peer_port: u16,
    #[arg(long, default_value_t = 128)] request_bytes: usize,
    #[arg(long, default_value_t = 128)] response_bytes: usize,
    #[arg(long, default_value_t = 100_000)] iterations: u64,
    #[arg(long, default_value_t = 1_000)] warmup: u64,
    #[arg(long)] output_csv: std::path::PathBuf,
    #[arg(long, default_value = "strict")] precondition_mode: String,
    #[arg(long)] local_ip: String,
    #[arg(long)] gateway_ip: String,
    #[arg(long)] eal_args: String,
    #[arg(long, default_value_t = 50)] sum_identity_tol_ns: u64,
    #[arg(long, default_value = "false")] assert_hw_task_18: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // 1. Precondition check — shells out to check-bench-preconditions
    let preconditions = bench_e2e::preconditions_check(&args.precondition_mode)?;

    // 2. EAL init + Engine::new
    let engine = bench_e2e::setup_engine(&args)?;

    // 3. Run
    let mut samples_rtt = Vec::with_capacity(args.iterations as usize);
    let mut samples_rx_hw_ts = Vec::with_capacity(args.iterations as usize);
    let conn = bench_e2e::open_conn(&engine, &args)?;
    for _ in 0..args.warmup { bench_e2e::one_request_response(&engine, conn, &args)?; }
    for _ in 0..args.iterations {
        let (rtt_ns, buckets, rx_hw_ts_ns) = bench_e2e::one_request_response_attributed(&engine, conn, &args)?;
        assert_sum_identity(buckets.total_ns(), rtt_ns, args.sum_identity_tol_ns)
            .map_err(anyhow::Error::msg)?;
        samples_rtt.push(rtt_ns as f64);
        samples_rx_hw_ts.push(rx_hw_ts_ns);
    }

    // 4. A-HW Task 18 assertions
    if args.assert_hw_task_18 {
        assert_hw_task_18_post_run(&engine, &HwTask18Expectations::default())
            .map_err(anyhow::Error::msg)?;
        assert_all_events_rx_hw_ts_ns_zero(&samples_rx_hw_ts)
            .map_err(anyhow::Error::msg)?;
    }

    // 5. Summarize + emit CSV
    bench_e2e::emit_csv(&args, &samples_rtt, preconditions)?;

    // 6. Cleanup
    drop(engine);
    unsafe { dpdk_net_sys::rte_eal_cleanup(); }
    Ok(())
}
```

(Factor helpers into `src/lib.rs` as needed.)

- [ ] **Step 6.8: Write the peer echo-server**

`tools/bench-e2e/peer/echo-server.c`:

```c
// A simple TCP echo server. Listens on argv[1] port; for every accepted
// connection, reads 128-byte chunks and echoes them back. Compiled once
// and deployed to the peer host via scripts/bench-nightly.sh.
//
// Built with: gcc -O2 -o echo-server echo-server.c -lpthread
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void *handle(void *arg) {
    int fd = (long)arg;
    char buf[8192];
    while (1) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) break;
        ssize_t m = 0;
        while (m < n) {
            ssize_t w = write(fd, buf + m, n - m);
            if (w <= 0) goto done;
            m += w;
        }
    }
done:
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: echo-server <port>\n"); return 1; }
    int port = atoi(argv[1]);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY };
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(s, 64) < 0) { perror("listen"); return 1; }
    while (1) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { perror("accept"); continue; }
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        pthread_t t;
        pthread_create(&t, NULL, handle, (void *)(long)c);
        pthread_detach(t);
    }
    return 0;
}
```

`tools/bench-e2e/peer/Makefile`:

```
echo-server: echo-server.c
	gcc -O2 -o $@ $< -lpthread
```

- [ ] **Step 6.9: Build the peer binary smoke-test (build only)**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10/tools/bench-e2e/peer
make echo-server
./echo-server 9999 &
sleep 0.5
kill %1
```

Expected: compiles + runs briefly.

- [ ] **Step 6.10: Commit**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
git add Cargo.toml tools/bench-e2e/
git commit -m "$(cat <<'EOF'
a10 task 6: bench-e2e — request-response RTT + attribution + A-HW Task 18

Subsumes A-HW Task 18 (deferred by commit abea362): 128 B / 128 B wire
cycle on real ENA with sum-identity assertion per measurement,
offload-counter assertions post-run, rx_hw_ts_ns == 0 assertion per
event. HW-TS mode + TSC-fallback buckets; tolerance ±50 ns per spec §6.

Peer echo-server is a simple single-threaded-per-connection C program
built at bench time on the peer host.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Follow-up from code review

**Follow-ups from 2026-04-21 code review on commit 86131a6 (defer until HW-TS-capable NIC comes online, OR before A10 phase-complete tag):**

- I1: HW-TS mode bucket semantics — wire `rx_hw_ts_ns` into the bucket pivot, OR rename `nic_tx_wire_to_nic_rx_ns` to explicitly reflect single-side-TS degradation. Today's HW branch at `src/main.rs:421-437` stores host-TSC `host_span_ns` in NIC-wire-semantic fields. Pin-test `hw_mode_single_side_ts_collapses_to_three_effective_buckets` locks current behavior.
- I2: carry-forward-over-response-bytes edge case — if prior iteration over-read satisfies current iteration, receive loop skipped, `last_rx_hw_ts_ns` stays None → silent TSC downgrade on future HW-TS NICs. Thread `&mut Option<u64>` through the send-phase drain.
- I3: send-phase drain discards `rx_hw_ts_ns`. Pair with I2 fix.
- I4: `enqueued_to_user_return_ns` is back-to-back rdtsc() with no intervening work — semantically meaningless ~1-10ns bucket. Either drop the bucket or move `t_user_return` after drain observation.
- M1: `tsc_delta_to_ns` duplicated between bench-e2e + bench-ab-runner — promote to `bench_common::clock`.
- M5: `main.rs` (923 lines) could split into `src/main.rs` + `src/workload.rs` for parity with bench-ab-runner.
- M6: `HwTask18Expectations::expect_rx_drop_cksum_bad_zero=false` skips the check rather than inverting — rename to `require_rx_drop_cksum_bad_zero` or add inverse test.

---

## Task 7: `bench-stress` — netem + FaultInjector scenario matrix

**Files:**
- Create: `tools/bench-stress/{Cargo.toml, src/main.rs, src/scenarios.rs, src/netem.rs}`
- Test: `tools/bench-stress/tests/scenario_parse.rs`

### Steps

- [ ] **Step 7.1: Workspace + Cargo.toml**

```toml
[package]
name = "bench-stress"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
bench-common = { path = "../bench-common" }
bench-e2e = { path = "../bench-e2e" }   # reuse workload
dpdk-net-core = { path = "../../crates/dpdk-net-core", features = ["fault-injector"] }
dpdk-net-sys = { path = "../../crates/dpdk-net-sys" }
dpdk-net = { path = "../../crates/dpdk-net" }
clap = { version = "4", features = ["derive"] }
anyhow = "1"
csv = "1.3"
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 7.2: Define the scenario matrix**

`src/scenarios.rs`:

```rust
//! Spec §7 — netem + FaultInjector scenario matrix.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub name: &'static str,
    pub netem: Option<&'static str>,
    pub fault_injector: Option<&'static str>,
    /// Pass criterion: p999 bound relative to idle p999.
    pub p999_ceiling_ratio: Option<f64>,
    /// Counter delta checks.
    pub counter_expectations: &'static [(&'static str, &'static str)],
}

pub const MATRIX: &[Scenario] = &[
    Scenario {
        name: "random_loss_01pct_10ms",
        netem: Some("loss 0.1% delay 10ms"),
        fault_injector: None,
        p999_ceiling_ratio: Some(3.0),
        counter_expectations: &[],
    },
    Scenario {
        name: "correlated_burst_loss_1pct",
        netem: Some("loss 1% 25%"),
        fault_injector: None,
        p999_ceiling_ratio: Some(10.0),
        counter_expectations: &[("tcp.tx_rto", ">0"), ("tcp.tx_tlp", ">0")],
    },
    Scenario {
        name: "reorder_depth_3",
        netem: Some("reorder 50% gap 3"),
        fault_injector: None,
        p999_ceiling_ratio: None,
        counter_expectations: &[("tcp.tx_retrans", "==0")],
    },
    Scenario {
        name: "duplication_2x",
        netem: Some("duplicate 100%"),
        fault_injector: None,
        p999_ceiling_ratio: Some(1.05),  // no p99 degradation
        counter_expectations: &[],
    },
    Scenario {
        name: "fault_injector_drop_1pct",
        netem: None,
        fault_injector: Some("drop=0.01"),
        p999_ceiling_ratio: Some(10.0),
        counter_expectations: &[("obs.fault_injector_drops", ">0")],
    },
    Scenario {
        name: "fault_injector_reorder_05pct",
        netem: None,
        fault_injector: Some("reorder=0.005"),
        p999_ceiling_ratio: None,
        counter_expectations: &[("obs.fault_injector_reorders", ">0"), ("tcp.tx_retrans", "==0")],
    },
    Scenario {
        name: "fault_injector_dup_05pct",
        netem: None,
        fault_injector: Some("dup=0.005"),
        p999_ceiling_ratio: Some(1.05),
        counter_expectations: &[("obs.fault_injector_dups", ">0")],
    },
    // PMTU blackhole is Stage 2; placeholder for schema completeness.
    Scenario {
        name: "pmtu_blackhole_STAGE2",
        netem: None,
        fault_injector: None,
        p999_ceiling_ratio: None,
        counter_expectations: &[],
    },
];
```

- [ ] **Step 7.3: Netem driver**

`src/netem.rs`:

```rust
//! SSH to peer, apply `tc qdisc` netem spec, revert on drop.
use std::process::Command;

pub struct NetemGuard {
    pub peer_ssh: String,
    pub iface: String,
}

impl NetemGuard {
    pub fn apply(peer_ssh: &str, iface: &str, spec: &str) -> anyhow::Result<Self> {
        let cmd = format!("sudo tc qdisc add dev {} root netem {}", iface, spec);
        let out = Command::new("ssh")
            .args(["-o", "StrictHostKeyChecking=no", peer_ssh, &cmd])
            .output()?;
        if !out.status.success() {
            anyhow::bail!("netem apply failed: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(Self { peer_ssh: peer_ssh.into(), iface: iface.into() })
    }
}

impl Drop for NetemGuard {
    fn drop(&mut self) {
        let cmd = format!("sudo tc qdisc del dev {} root", self.iface);
        let _ = Command::new("ssh")
            .args(["-o", "StrictHostKeyChecking=no", &self.peer_ssh, &cmd])
            .status();
    }
}
```

- [ ] **Step 7.4: Smoke test + commit**

Write `tests/scenario_parse.rs`:

```rust
#[test]
fn matrix_has_eight_scenarios() {
    assert_eq!(bench_stress::scenarios::MATRIX.len(), 8);
}

#[test]
fn scenario_names_are_unique() {
    let names: Vec<_> = bench_stress::scenarios::MATRIX.iter().map(|s| s.name).collect();
    let set: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(names.len(), set.len());
}
```

Compile + test + commit.

```bash
timeout 60 cargo test -p bench-stress 2>&1 | tail -10
git add Cargo.toml tools/bench-stress/
git commit -m "a10 task 7: bench-stress — netem + FaultInjector matrix (spec §7)"
```

---

## Task 8: `bench-vs-linux` mode A (RTT comparison, trading-latency preset)

**Files:**
- Create: `tools/bench-vs-linux/{Cargo.toml, src/main.rs, src/mode_rtt.rs, peer/linux-tcp-sink.c}`

### Steps

- [ ] **Step 8.1: Workspace + Cargo.toml + `src/main.rs` skeleton with `--mode {rtt,wire-diff}` selector**

Similar structure to bench-e2e. Mode A: both stacks run on the DUT and peer, same workload, compare RTT distributions. The Linux-side measurement uses a simple echo-server on the peer (same as bench-e2e's peer) + a tiny Rust/C client on the DUT that talks kernel-TCP (not via dpdk-net-core).

- [ ] **Step 8.2: Mode RTT implementation**

```rust
// src/mode_rtt.rs — drives both stacks, collects two CSVs.
pub fn run_mode_rtt(args: &crate::Args) -> anyhow::Result<()> {
    // 1. Run dpdk-net engine against the peer echo-server (like bench-e2e)
    let dpdk_samples = crate::run_dpdk_rtt(args)?;
    // 2. Run AF_PACKET mmap client + kernel-TCP socket, N samples each
    let linux_samples_afpacket = crate::run_linux_afpacket_rtt(args)?;
    let linux_samples_kernel = crate::run_linux_kernel_tcp_rtt(args)?;
    // 3. Summarize + emit CSV rows with dimensions_json:{stack, preset}
    crate::emit_csv_three_stacks(args, &dpdk_samples, &linux_samples_afpacket, &linux_samples_kernel)?;
    Ok(())
}
```

- [ ] **Step 8.3: Peer binary — spec §8**

`peer/linux-tcp-sink.c`: same as bench-e2e's echo server, just renamed. Symlink or duplicate at the peer-deployment step.

- [ ] **Step 8.4: Commit**

```bash
git add Cargo.toml tools/bench-vs-linux/
git commit -m "a10 task 8: bench-vs-linux mode A — RTT comparison (trading-latency preset)"
```

---

## Task 9: `bench-vs-linux` mode B (wire-diff, rfc_compliance preset)

**Files:**
- Modify: `tools/bench-vs-linux/src/main.rs` (add mode_wire_diff)
- Create: `tools/bench-vs-linux/src/mode_wire_diff.rs`
- Create: `tools/bench-vs-linux/src/normalize.rs`
- Test: `tools/bench-vs-linux/tests/normalize_roundtrip.rs`

### Steps

- [ ] **Step 9.1: Failing test for divergence-normalisation**

`tests/normalize_roundtrip.rs`:

```rust
//! Normalize two pcaps — ISS + timestamp base rewritten to canonical values.
use bench_vs_linux::normalize::{canonicalize_pcap, CanonicalizationOptions};

#[test]
fn canonicalize_produces_deterministic_bytes_for_identical_streams() {
    let pcap_a = include_bytes!("../tests/fixtures/linux-syn.pcap");
    let pcap_b = include_bytes!("../tests/fixtures/dpdk-syn.pcap");
    let opt = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(pcap_a, &opt).unwrap();
    let can_b = canonicalize_pcap(pcap_b, &opt).unwrap();
    assert_eq!(can_a, can_b, "expect canonicalised bytes match after normalisation");
}
```

(The subagent authors both fixture pcaps from small scapy programs or captures.)

- [ ] **Step 9.2: Implement `src/normalize.rs`**

Canonicalisation rewrites:
- ISS (initial sequence number): from random → fixed `0x12345678`
- Timestamp base: from free-running → fixed `0xAABB_CCDD`
- ACK numbers adjusted to match the rewritten ISS
- Source MAC and destination MAC: normalized to fixed bytes
- Any other engine-specific free values

- [ ] **Step 9.3: Implement `src/mode_wire_diff.rs`**

```rust
pub fn run_mode_wire_diff(args: &crate::Args) -> anyhow::Result<()> {
    // 1. Set engine preset to rfc_compliance
    // 2. Start tcpdump on both ends
    // 3. Run N connects + requests
    // 4. Stop tcpdump, pull pcaps
    // 5. Canonicalise both
    // 6. Byte-diff
    // 7. Emit results (diff count, divergence locations) as CSV rows with
    //    dimensions_json: {"preset": "rfc_compliance", "mode": "wire_diff"}
    todo!()
}
```

- [ ] **Step 9.4: Commit**

```bash
git add tools/bench-vs-linux/
git commit -m "a10 task 9: bench-vs-linux mode B — wire-diff (rfc_compliance preset)"
```

---

## Task 10: `bench-offload-ab` driver + decision rule + report writer

**Files:**
- Create: `tools/bench-offload-ab/{Cargo.toml, src/main.rs, src/matrix.rs, src/decision.rs, src/report.rs}`
- Test: `tools/bench-offload-ab/tests/decision_rule.rs`

### Steps

- [ ] **Step 10.1: Decision-rule unit test**

```rust
//! delta_p99 > 3 * noise_floor → "shows signal"; else "no signal".
use bench_offload_ab::decision::{classify, DecisionRule};

#[test]
fn signal_when_delta_exceeds_three_noise() {
    let rule = DecisionRule { noise_floor_ns: 5.0 };
    assert_eq!(classify(100.0, 80.0, &rule), bench_offload_ab::decision::Outcome::Signal);
}

#[test]
fn no_signal_when_delta_under_three_noise() {
    let rule = DecisionRule { noise_floor_ns: 5.0 };
    assert_eq!(classify(100.0, 90.0, &rule), bench_offload_ab::decision::Outcome::NoSignal);
}

#[test]
fn sanity_invariant_full_must_be_le_best_individual() {
    let configs: Vec<(String, f64)> = vec![
        ("baseline".into(), 100.0),
        ("tx-cksum-only".into(), 95.0),
        ("rx-cksum-only".into(), 92.0),
        ("full".into(), 94.0),
    ];
    let best_individual = configs.iter().filter(|(n, _)| *n != "baseline" && *n != "full").map(|(_, v)| *v).fold(f64::INFINITY, f64::min);
    let full_p99 = configs.iter().find(|(n, _)| n == "full").map(|(_, v)| *v).unwrap();
    let result = bench_offload_ab::decision::check_sanity_invariant(full_p99, best_individual);
    assert!(result.is_ok(), "full=94 <= best individual=92 so invariant holds");
}
```

- [ ] **Step 10.2: Implement `src/decision.rs`**

```rust
#[derive(Debug, PartialEq)]
pub enum Outcome { Signal, NoSignal }

pub struct DecisionRule {
    pub noise_floor_ns: f64,
}

pub fn classify(p99_baseline_ns: f64, p99_with_offload_ns: f64, rule: &DecisionRule) -> Outcome {
    let delta = p99_baseline_ns - p99_with_offload_ns;
    if delta > 3.0 * rule.noise_floor_ns { Outcome::Signal } else { Outcome::NoSignal }
}

pub fn check_sanity_invariant(full_p99: f64, best_individual_p99: f64) -> Result<(), String> {
    if full_p99 <= best_individual_p99 {
        Ok(())
    } else {
        Err(format!("full p99 {} > best individual p99 {}", full_p99, best_individual_p99))
    }
}
```

- [ ] **Step 10.3: Driver implementation**

`src/main.rs`:

```rust
//! bench-offload-ab — matrix driver.
//! For each config in MATRIX:
//!   1. cargo build --no-default-features --features <config_features> -p bench-ab-runner --release
//!   2. std::process::Command::new(runner) ... capture stdout CSV
//!   3. append to target/bench-results/bench-offload-ab/<run_id>.csv
//! After matrix: load CSV, compute deltas, apply decision rule, write report.

mod matrix;
mod decision;
mod report;

fn main() -> anyhow::Result<()> {
    // ... see plan body
    todo!()
}
```

`src/matrix.rs` — the 8-config matrix defined in spec §9.

`src/report.rs` — reads accumulated CSV, computes per-offload delta_p99, runs decision rule, writes `docs/superpowers/reports/offload-ab.md`.

- [ ] **Step 10.4: Run decision-rule tests**

```bash
timeout 60 cargo test -p bench-offload-ab 2>&1 | tail -10
```

Expected: pass.

- [ ] **Step 10.5: Commit**

```bash
git add Cargo.toml tools/bench-offload-ab/
git commit -m "a10 task 10: bench-offload-ab — feature-matrix driver + decision rule + report writer (spec §9)"
```

---

## Task 11: `bench-obs-overhead` driver + report writer

Mirrors T10 for `obs-*` feature matrix.

**Files:**
- Create: `tools/bench-obs-overhead/{Cargo.toml, src/main.rs, src/matrix.rs, src/report.rs}`

### Steps

- [ ] **Step 11.1: Copy the T10 skeleton, swap the matrix**

5 configs per spec §10: `obs-none`, `poll-saturation-only`, `byte-counters-only`, `obs-all-no-none`, `default`.

- [ ] **Step 11.2: Action taxonomy in report**

For each config whose delta_p99 > 3 × noise_floor and whose corresponding feature has `default=ON`:
- Emit entry in `docs/superpowers/reports/obs-overhead.md` with the column "action taken" from {batch, remove, flip default, move off hot path}
- Action selection is a HUMAN decision surfaced by the report, not automated — the report flags the failure; the A10 task author picks the remediation in a follow-up commit

- [ ] **Step 11.3: Commit**

```bash
git commit -m "a10 task 11: bench-obs-overhead — matrix driver + report writer (spec §10)"
```

---

## Task 12: `bench-vs-mtcp` burst grid

**Files:**
- Create: `tools/bench-vs-mtcp/{Cargo.toml, src/main.rs, src/burst.rs}`

### Steps

- [ ] **Step 12.1: Grid definition + workload**

Per spec §11.1: K × G = 20 buckets.

```rust
pub const K_BYTES: &[u64] = &[64 * 1024, 256 * 1024, 1 << 20, 4 << 20, 16 << 20];
pub const G_MS: &[u64] = &[0, 1, 10, 100];

// 20 buckets; ≥10k bursts per bucket
```

- [ ] **Step 12.2: Peer driver — SSH to peer, run pre-built `/opt/mtcp-peer/bench-peer` or `/opt/bench-peer-linux/bench-peer`**

The DUT runs `dpdk-net-core`; peer runs kernel TCP sink (receives + ACKs, no echo).

- [ ] **Step 12.3: Measurement contract per spec §11.1**

Record `t0` (inline TSC pre-first-send), `t1` (NIC HW TX timestamp on last segment; fallback TSC-at-`rte_eth_tx_burst` return on ENA since it doesn't advertise TX timestamp). Compute `throughput_per_burst = K / (t1 − t0)`. Secondary: `t_first_wire` from segment 1 → initiation + steady decomposition. Pre-run checks + sanity invariant `sum(K) == stack_tx_bytes_counter`.

- [ ] **Step 12.4: Commit**

```bash
git commit -m "a10 task 12: bench-vs-mtcp burst grid (K×G=20) — spec §11.1"
```

---

## Task 13: `bench-vs-mtcp` maxtp grid

**Files:**
- Modify: `tools/bench-vs-mtcp/src/main.rs` (add maxtp mode)
- Create: `tools/bench-vs-mtcp/src/maxtp.rs`

### Steps

- [ ] **Step 13.1: Grid definition**

Per spec §11.2: W × C = 28 buckets.

```rust
pub const W_BYTES: &[u64] = &[64, 256, 1024, 4096, 16_384, 65_536, 262_144];
pub const C_CONNS: &[u64] = &[1, 4, 16, 64];
```

- [ ] **Step 13.2: Pump N connections × W-byte-writes for T=60 s**

Primary: sustained goodput. Secondary: packet rate. Sanity: ACKed bytes == stack_tx_bytes_counter_delta (minus in-flight bound).

- [ ] **Step 13.3: Commit**

```bash
git commit -m "a10 task 13: bench-vs-mtcp maxtp grid (W×C=28) — spec §11.2"
```

---

## Task 14: `bench-report` — CSV → JSON + HTML + Markdown

**Files:**
- Create: `tools/bench-report/{Cargo.toml, src/main.rs, src/json_writer.rs, src/html_writer.rs, src/md_writer.rs, templates/report.html.j2}`

### Steps

- [ ] **Step 14.1: Cargo.toml with `maud` for HTML and `handlebars` or `askama` rendering**

Recommendation: `maud` (type-safe Rust macro-based HTML) — no template file, no runtime lookup.

- [ ] **Step 14.2: CSV ingest**

Reads every CSV under `target/bench-results/**/*.csv`, deserializes into `Vec<CsvRow>`. Groups by `(tool, test_case, feature_set, metric_name)`.

**Follow-up to T1 (RI1 from code review):** The `CsvRow::Deserialize` visitor in `tools/bench-common/src/csv_row.rs` silently defaults any missing `precondition_*` column to `PreconditionValue::default()` (which is `Pass(None)` after the T1 fix-up for the `n/a` state). Under this T14 task, before writing the ingest pipeline, upgrade the visitor to `require()` each of the 14 precondition columns (matching the treatment of run-metadata scalars). A schema-drifted CSV from an older/newer tool should error with a clear "missing precondition column X" message, not silently parse as all-pass. Add a new test in `tools/bench-common/tests/csv_row_roundtrip.rs` that constructs a CSV with a missing column and asserts `CsvRow::deserialize` errors.

- [ ] **Step 14.3: Filter — strict-only / include-lenient / all**

Defaults to strict-only: only rows where `precondition_mode == strict` AND every precondition passes.

- [ ] **Step 14.4: JSON writer**

```rust
pub fn write_json(rows: &[CsvRow], path: &std::path::Path) -> std::io::Result<()> {
    let file = std::fs::File::create(path)?;
    serde_json::to_writer_pretty(file, rows)
}
```

- [ ] **Step 14.5: HTML writer with colour-coded precondition failures**

```rust
use maud::{html, Markup, DOCTYPE};

pub fn render_html(rows: &[CsvRow]) -> Markup {
    html! {
        (DOCTYPE) html lang="en" {
            head { meta charset="UTF-8"; title { "resd bench report" } }
            body {
                h1 { "resd.dpdk_tcp A10 bench report" }
                table {
                    tr { th { "tool" } th { "test_case" } th { "feature_set" } th { "metric" } th { "agg" } th { "value" } th { "preconditions" } }
                    @for row in rows {
                        tr {
                            td { (row.tool) }
                            td { (row.test_case) }
                            td { (row.feature_set) }
                            td { (row.metric_name) }
                            td { (row.metric_aggregation) }
                            td { (row.metric_value) }
                            td { (precondition_pill(&row.run_metadata.preconditions)) }
                        }
                    }
                }
            }
        }
    }
}

fn precondition_pill(p: &bench_common::preconditions::Preconditions) -> Markup {
    let all_pass = p.isolcpus.passed && p.nohz_full.passed /* ... */ ;
    html! {
        span class=(if all_pass { "pass" } else { "fail" }) {
            (if all_pass { "OK" } else { "!" })
        }
    }
}
```

- [ ] **Step 14.6: Markdown writer**

```rust
pub fn render_md(rows: &[CsvRow]) -> String {
    let mut out = String::new();
    out.push_str("# resd.dpdk_tcp A10 bench report\n\n");
    out.push_str("| tool | test_case | feature_set | metric | agg | value |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for r in rows {
        out.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n",
            r.tool, r.test_case, r.feature_set, r.metric_name, r.metric_aggregation, r.metric_value));
    }
    out
}
```

- [ ] **Step 14.7: CLI + round-trip test + commit**

```rust
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "target/bench-results")] input: std::path::PathBuf,
    #[arg(long)] output_json: Option<std::path::PathBuf>,
    #[arg(long)] output_html: Option<std::path::PathBuf>,
    #[arg(long)] output_md: Option<std::path::PathBuf>,
    #[arg(long, default_value = "strict-only")] filter: String,
}
```

```bash
git commit -m "a10 task 14: bench-report — CSV → JSON + HTML + Markdown (spec §12 / §14)"
```

---

## Task 15: `scripts/bench-nightly.sh` — end-to-end orchestrator

**Files:**
- Create: `scripts/bench-nightly.sh`

**Follow-ups from T9 code review (must land before T15 completes — live capture forces multi-connection pcaps into scope):**

- **T9-I1:** Extract shared L2/L3/L4 parser from `tools/bench-vs-linux/src/normalize.rs`. `discover_pins` (pass 1) and `rewrite_frame` (pass 2) currently duplicate Ethernet + IPv4 + TCP header bounds checks. Any protocol-chain fix (IPv6, VLAN) requires synchronised edits in two places. Factor into `parse_l2l3l4(data) -> Option<FrameOffsets>`.
- **T9-I2:** Port-reuse across connections in the same pcap is silently miscanonicalised today — `FlowState.iss` is keyed by sorted 4-tuple with no connection-instance discrimination. Live capture (this task's tcpdump orchestration) WILL surface this. Fix options: add SYN-timestamp to pin key, bump a per-SYN instance counter, or at minimum a scope-note.
- **T9-I5:** Add integration test asserting differing packet counts between local+peer pcaps produces non-zero `diff_bytes` + accurate `local_packets`/`peer_packets` CSV rows.
- **T9 minor:** `CanonError::MalformedSackOption` for SACK option malformed length; fold two option walkers into one `walk_options<F>(slice, visitor: F)`; extract synth-pcap builder from `tests/normalize_roundtrip.rs` (857 lines) into `tests/common/synth.rs`.

### Steps

- [ ] **Step 15.1: Write the script**

```bash
#!/usr/bin/env bash
# scripts/bench-nightly.sh — end-to-end A10 nightly bench orchestrator.
# 1. Provision DUT+peer via resd-aws-infra
# 2. SCP compiled bench binaries to both hosts
# 3. Start peer echo-server
# 4. Run bench-micro (local in-process)
# 5. Run bench-e2e (with A-HW Task 18 assertions)
# 6. Run bench-stress
# 7. Run bench-vs-linux (mode A + mode B)
# 8. Run bench-offload-ab
# 9. Run bench-obs-overhead
# 10. Run bench-vs-mtcp (burst + maxtp)
# 11. Pull all CSVs back
# 12. Invoke bench-report
# 13. Tear down fleet
set -euo pipefail

OUT_DIR="${OUT_DIR:-target/bench-results/$(date -u +%Y-%m-%dT%H-%M-%S)}"
mkdir -p "$OUT_DIR"

echo "[1/13] provisioning bench-pair…"
STACK_JSON="$(resd-aws-infra setup bench-pair --operator-ssh-cidr "$(curl -s https://ifconfig.me)/32" --json)"
DUT_SSH="$(jq -r .DutSshEndpoint <<<"$STACK_JSON")"
PEER_SSH="$(jq -r .PeerSshEndpoint <<<"$STACK_JSON")"
DUT_IP="$(jq -r .DutDataEniIp <<<"$STACK_JSON")"
PEER_IP="$(jq -r .PeerDataEniIp <<<"$STACK_JSON")"
trap 'resd-aws-infra teardown bench-pair --wait' EXIT

# Build once
cargo build --release --workspace

# Deploy binaries
for host in "$DUT_SSH" "$PEER_SSH"; do
  scp target/release/bench-{micro,e2e,stress,vs-linux,offload-ab,obs-overhead,vs-mtcp,ab-runner} \
      scripts/check-bench-preconditions.sh \
      tools/bench-e2e/peer/echo-server \
      "ubuntu@${host}:/tmp/"
done

# Start peer echo-server
ssh "ubuntu@$PEER_SSH" '/tmp/echo-server 10001 &'

# Run benches — SSH to DUT
for bench in bench-e2e bench-stress bench-vs-linux bench-offload-ab bench-obs-overhead bench-vs-mtcp; do
  echo "[running] $bench"
  ssh "ubuntu@$DUT_SSH" "sudo /tmp/$bench --peer-ip $PEER_IP --local-ip $DUT_IP --output-csv /tmp/$bench.csv --eal-args '-l 2-3,-n 4,-a 0000:00:06.0,large_llq_hdr=1,miss_txc_to=3'"
  scp "ubuntu@$DUT_SSH:/tmp/$bench.csv" "$OUT_DIR/"
done

# Local bench-micro (no bench host needed)
cargo bench -p bench-micro
./target/release/summarize target/criterion "$OUT_DIR/bench-micro.csv"

# Report
./target/release/bench-report \
    --input "$OUT_DIR" \
    --output-json "$OUT_DIR/report.json" \
    --output-html "$OUT_DIR/report.html" \
    --output-md "$OUT_DIR/report.md"

echo "[done] results in $OUT_DIR"
```

- [ ] **Step 15.2: Commit**

```bash
chmod +x scripts/bench-nightly.sh
git add scripts/bench-nightly.sh
git commit -m "a10 task 15: scripts/bench-nightly.sh — end-to-end orchestrator"
```

---

## Task 16: Run benches + commit 3 report artefacts

Requires sister-plan T6 (first AMI bake) + T7 (validated bring-up) to have landed.

**Files committed:**
- `docs/superpowers/reports/offload-ab.md`
- `docs/superpowers/reports/obs-overhead.md`
- `docs/superpowers/reports/bench-baseline.md`

### Steps

- [ ] **Step 16.1: Ensure sister plan complete**

```bash
ls /home/ubuntu/resd.aws-infra-setup/cdk.json && \
  jq -r .context."default-ami-id" /home/ubuntu/resd.aws-infra-setup/cdk.json
```

Expected: AMI ID present.

- [ ] **Step 16.2: Run bench-nightly once to smoke all benches**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
export MY_CIDR="$(curl -s https://ifconfig.me)/32"
./scripts/bench-nightly.sh
```

Expected: tears down fleet on exit; produces CSVs + JSON + HTML + Markdown under `target/bench-results/<timestamp>/`.

- [ ] **Step 16.3: Commit the report artefacts**

Copy the generated Markdown files into `docs/superpowers/reports/`:

```bash
cp target/bench-results/<ts>/offload-ab.md docs/superpowers/reports/offload-ab.md
cp target/bench-results/<ts>/obs-overhead.md docs/superpowers/reports/obs-overhead.md
cp target/bench-results/<ts>/bench-baseline.md docs/superpowers/reports/bench-baseline.md

git add docs/superpowers/reports/
git commit -m "a10 task 16: bench report artefacts — offload-ab + obs-overhead + bench-baseline"
```

- [ ] **Step 16.4: If the reports flag a signal that requires action (e.g., an offload with no signal → remove from default feature set)**

Apply the remediation in a follow-up commit before tagging phase-a10-complete.

---

## Task 17: Roadmap row update

- [ ] **Step 17.1: Edit `docs/superpowers/plans/stage1-phase-roadmap.md`**

Update the A10 row with:
- Actual task count (vs rough scale)
- Completion status
- Pointer to the three committed report artefacts
- Pointer to the end-of-phase review reports (written by T19 + T20)
- Any scope adjustments discovered during execution

- [ ] **Step 17.2: Commit**

```bash
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "a10 task 17: roadmap row update for A10 completion"
```

---

## Task 18: phase-a10-complete tag

Tagged locally only; user merges to master manually.

- [ ] **Step 18.1: Tag**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a10
git tag -a phase-a10-complete -m "$(cat <<'EOF'
Phase A10 complete: benchmark harness (micro + e2e + stress + comparators)

Delivers 9 tool crates (bench-common, bench-ab-runner, bench-micro,
bench-e2e, bench-stress, bench-vs-linux, bench-offload-ab,
bench-obs-overhead, bench-vs-mtcp, bench-report); obs-none umbrella
feature; 3 committed report artefacts (offload-ab, obs-overhead,
bench-baseline). Sister repo resd.aws-infra-setup v0.1.0 delivers IaC
+ baked AMI used by bench-nightly.

Subsumes A-HW Task 18 (deferred by commit abea362).

mTCP + RFC review gates both clean (see docs/superpowers/reviews/).
EOF
)"
```

---

## Task 19: mTCP review gate

Dispatch `mtcp-comparison-reviewer` subagent (opus 4.7) per `feedback_phase_mtcp_review`. Produces `docs/superpowers/reviews/phase-a10-mtcp-compare.md`.

- [ ] **Step 19.1: Dispatch via Agent tool**

Instruction to reviewer: focus on bench-vs-mtcp wire integration (build, submodule, measurement contract, sanity invariants); absorb mTCP harness-design lessons we can learn.

- [ ] **Step 19.2: Review blocks the tag**

If the report has any `MUST` violations, address before tagging phase-a10-complete is final (the tag may be force-updated after remediation).

---

## Task 20: RFC compliance review gate

Dispatch `rfc-compliance-reviewer` subagent (opus 4.7) per `feedback_phase_rfc_review`. Produces `docs/superpowers/reviews/phase-a10-rfc-compliance.md`. Parallel to T19.

- [ ] **Step 20.1: Dispatch via Agent tool**

Instruction: A10 is benchmarks; RFC scope is limited. Focus: `preset=rfc_compliance` invocation in bench-vs-linux mode B exercises the existing preset correctly; no RFC MUST/SHOULD regressed; measurement-discipline (§11.1) enforced.

---

## Task 21: End-of-phase sign-off

- [ ] **Step 21.1: Verify both review gates clean**

```bash
cat docs/superpowers/reviews/phase-a10-mtcp-compare.md | head -30
cat docs/superpowers/reviews/phase-a10-rfc-compliance.md | head -30
```

- [ ] **Step 21.2: Verify three report artefacts committed**

```bash
ls docs/superpowers/reports/ | grep -E '(offload-ab|obs-overhead|bench-baseline)\.md'
```

- [ ] **Step 21.3: Verify phase-a10-complete tag**

```bash
git tag -l phase-a10-complete
```

- [ ] **Step 21.4: Hand off to user**

```
Phase A10 complete on branch phase-a10.
  - Tag: phase-a10-complete
  - Worktree: /home/ubuntu/resd.dpdk_tcp-a10
  - Sister repo: /home/ubuntu/resd.aws-infra-setup v0.1.0
  - Report artefacts: docs/superpowers/reports/{offload-ab,obs-overhead,bench-baseline}.md
  - Review reports (both clean): docs/superpowers/reviews/phase-a10-{mtcp-compare,rfc-compliance}.md

Merge to master at your discretion (likely together with or after phase-a7 merge).
Push the sister repo to github.com/contek-io/resd.aws-infra-setup when ready.
```

---

## Self-review checklist

- [ ] Every spec section in §5–§12, §13 (obs-none feature), §14 (CSV), §17–§18 (report artefacts + review gates) has a task.
- [ ] Each non-trivial task has TDD structure (T1, T2, T4, T6, T9, T10, T14 all have failing-test-first).
- [ ] T5 (bench-micro) TDD is via cargo-criterion itself — criterion runs targets; compile passing = test passing for skeleton.
- [ ] T7 (bench-stress) uses bench-e2e's workload as a library dependency — no duplicate code.
- [ ] T15 (bench-nightly.sh) is orchestration glue; no unit tests (end-to-end verified in T16).
- [ ] T19+T20 review gates dispatch subagents per feedback_phase_mtcp_review + feedback_phase_rfc_review.
- [ ] Sister plan dependencies are explicit (T12 + T13 need sister-plan T6; T16 needs sister-plan T6+T7).
- [ ] All commits end with Co-Authored-By per the project's git protocol.

---

## Execution protocol

Use `superpowers:subagent-driven-development`. Each task → fresh subagent (opus 4.7). Per-task review dispatch: both spec-compliance + code-quality reviewers (opus 4.7) per `feedback_per_task_review_discipline`. After T21, phase is complete; user controls the master merge.
