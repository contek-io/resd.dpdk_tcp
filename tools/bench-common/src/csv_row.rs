//! The unified CSV row emitted by every bench tool. Spec §14.
//!
//! Layout: the run-invariant fields from `RunMetadata` come first, followed by
//! the per-row fields `tool`, `test_case`, `feature_set`, `dimensions_json`,
//! `metric_name`, `metric_unit`, `metric_value`, `metric_aggregation`, and
//! finally the optional host/dpdk/worktree identification fields used by
//! cross-worktree A/B analysis (§3 / §4.4).
//!
//! # Why a hand-written `Serialize`/`Deserialize`
//!
//! `csv::Writer` only supports struct serialisation via `SerializeStruct` — it
//! rejects `SerializeMap`, which is what both plain `#[serde(flatten)]` and
//! custom flatten-helper modules (`with = "..."`) compile into under the
//! hood. The design sketch in the plan warned about this exact trade-off and
//! explicitly authorised the fallback: flatten manually.
//!
//! The approach here:
//!
//! - Keep `RunMetadata` and `Preconditions` as ergonomic nested structs for
//!   callers populating a row — they stay strongly typed and easy to build.
//! - Implement `Serialize` on `CsvRow` by hand, writing one `SerializeStruct`
//!   with all 40 columns as flat scalar fields. The breakdown is
//!   13 run-metadata columns (12 scalars + `precondition_mode`) +
//!   14 precondition-value columns + 8 per-row columns + 5 host/dpdk/worktree
//!   identification columns = 40. That shape is exactly what csv expects.
//! - Implement `Deserialize` on `CsvRow` via a `Visitor` that walks the
//!   matching set of field keys and rebuilds the nested structs.
//!
//! The 5 appended identification columns are `Option`-typed and tolerated as
//! absent at deserialisation time so older CSVs written before these columns
//! existed still round-trip. They land at the END of the row so an older
//! `bench-report` binary reading a newer CSV sees them as "unknown column —
//! skip" via the visitor's `IgnoredAny` fallthrough.
//!
//! `metric_value` is a raw `f64`. Values chosen in the round-trip test are
//! exactly representable so bit-exact `PartialEq` compares work. Real runs
//! never compare values for equality, only aggregate.

use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::preconditions::{PreconditionMode, Preconditions};
use crate::run_metadata::RunMetadata;

/// The 14 precondition column names in spec §14.1 order. Used by the
/// `Deserialize` visitor to emit a "missing precondition column X" error
/// if an older/newer tool writes a schema-drifted CSV that omits one.
///
/// Exported for test-side construction of deliberately-dropped-column fixtures
/// (see `tools/bench-common/tests/csv_row_roundtrip.rs`) so the list stays in
/// sync with the actual visitor keys.
pub const PRECONDITION_COLUMNS: &[&str] = &[
    "precondition_isolcpus",
    "precondition_nohz_full",
    "precondition_rcu_nocbs",
    "precondition_governor",
    "precondition_cstate_max",
    "precondition_tsc_invariant",
    "precondition_coalesce_off",
    "precondition_tso_off",
    "precondition_lro_off",
    "precondition_rss_on",
    "precondition_thermal_throttle",
    "precondition_hugepages_reserved",
    "precondition_irqbalance_off",
    "precondition_wc_active",
];

pub use crate::preconditions::PreconditionValue;

/// Aggregation bucket a `metric_value` represents. Spec §14.2.
///
/// No `raw` variant — raw samples live in sidecar files (spec §14.3).
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

impl fmt::Display for MetricAggregation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// The full list of CSV columns in spec order (§14.1). Kept as a module-level
/// constant so the `Serialize` impl and the `Deserialize` visitor use exactly
/// the same ordering — if a column is added / removed it only changes here.
///
/// Exported so downstream summariser binaries (bench-micro's `summarize`,
/// etc.) can emit a header-only CSV without duplicating the column list.
pub const COLUMNS: &[&str] = &[
    // Run-invariant columns
    "run_id",
    "run_started_at",
    "commit_sha",
    "branch",
    "host",
    "instance_type",
    "cpu_model",
    "dpdk_version",
    "kernel",
    "nic_model",
    "nic_fw",
    "ami_id",
    "precondition_mode",
    // 14 precondition columns
    "precondition_isolcpus",
    "precondition_nohz_full",
    "precondition_rcu_nocbs",
    "precondition_governor",
    "precondition_cstate_max",
    "precondition_tsc_invariant",
    "precondition_coalesce_off",
    "precondition_tso_off",
    "precondition_lro_off",
    "precondition_rss_on",
    "precondition_thermal_throttle",
    "precondition_hugepages_reserved",
    "precondition_irqbalance_off",
    "precondition_wc_active",
    // Per-row columns
    "tool",
    "test_case",
    "feature_set",
    "dimensions_json",
    "metric_name",
    "metric_unit",
    "metric_value",
    "metric_aggregation",
    // Host / DPDK / worktree identification columns (Task 2.8, spec §3 / §4.4).
    // Appended at the end so older `bench-report` binaries that don't know
    // about them skip via the visitor's `IgnoredAny` fallthrough. Every column
    // is `Option` and tolerated as absent at deserialisation time so older
    // CSVs still round-trip cleanly.
    "cpu_family",
    "cpu_model_name",
    "dpdk_version_pkgconfig",
    "worktree_branch",
    "uprof_session_id",
];

/// One row in the unified benchmark CSV. Spec §14.1.
///
/// The five `Option`-typed fields at the end carry host / DPDK / worktree
/// identification (Task 2.8, spec §3 / §4.4). They let cross-worktree A/B
/// analysis reject mismatched-host rows. Populated by the summariser tool
/// from `/proc/cpuinfo`, `pkg-config --modversion libdpdk`, `git rev-parse
/// --abbrev-ref HEAD`, and the `UPROF_SESSION_ID` env var respectively — any
/// of which may fail on a minimal CI box, in which case `None` is emitted as
/// an empty cell.
#[derive(Debug, Clone, PartialEq)]
pub struct CsvRow {
    pub run_metadata: RunMetadata,
    pub tool: String,
    pub test_case: String,
    pub feature_set: String,
    pub dimensions_json: String,
    pub metric_name: String,
    pub metric_unit: String,
    pub metric_value: f64,
    pub metric_aggregation: MetricAggregation,
    /// `cpu family` field from `/proc/cpuinfo` — integer CPU family id
    /// (e.g. `25` for AMD Zen 3 EPYC). `None` if the file is absent or the
    /// line is missing / unparseable (e.g. a non-x86 host).
    pub cpu_family: Option<u32>,
    /// `model name` field from `/proc/cpuinfo` — the full marketing string
    /// (e.g. `AMD EPYC 7R13 Processor`). `None` if the file is absent or the
    /// line is missing.
    pub cpu_model_name: Option<String>,
    /// DPDK version reported by `pkg-config --modversion libdpdk`. `None` if
    /// `pkg-config` is not installed or the `libdpdk` module is not on the
    /// pkg-config path (CI boxes that don't link DPDK).
    pub dpdk_version_pkgconfig: Option<String>,
    /// Current git worktree branch (`git rev-parse --abbrev-ref HEAD`). `None`
    /// if not inside a git checkout. Used to identify which worktree a row
    /// originated from when comparing A vs. B baselines.
    pub worktree_branch: Option<String>,
    /// `UPROF_SESSION_ID` environment variable if set — correlates a CSV row
    /// to an AMD uProf profiling session so the same run produces aligned
    /// counter + profile data.
    pub uprof_session_id: Option<String>,
}

impl CsvRow {
    /// Serialise this row into a `csv::Writer` and flush. If the writer has
    /// no records yet, csv emits the header automatically on the first call.
    pub fn write_with_header<W: std::io::Write>(
        &self,
        wtr: &mut csv::Writer<W>,
    ) -> Result<(), csv::Error> {
        wtr.serialize(self)?;
        wtr.flush()?;
        Ok(())
    }
}

// -- Serialize ---------------------------------------------------------------

impl Serialize for CsvRow {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let m = &self.run_metadata;
        let p = &m.preconditions;
        let mut st = s.serialize_struct("CsvRow", COLUMNS.len())?;
        st.serialize_field("run_id", &m.run_id)?;
        st.serialize_field("run_started_at", &m.run_started_at)?;
        st.serialize_field("commit_sha", &m.commit_sha)?;
        st.serialize_field("branch", &m.branch)?;
        st.serialize_field("host", &m.host)?;
        st.serialize_field("instance_type", &m.instance_type)?;
        st.serialize_field("cpu_model", &m.cpu_model)?;
        st.serialize_field("dpdk_version", &m.dpdk_version)?;
        st.serialize_field("kernel", &m.kernel)?;
        st.serialize_field("nic_model", &m.nic_model)?;
        st.serialize_field("nic_fw", &m.nic_fw)?;
        st.serialize_field("ami_id", &m.ami_id)?;
        st.serialize_field("precondition_mode", &m.precondition_mode)?;
        st.serialize_field("precondition_isolcpus", &p.isolcpus)?;
        st.serialize_field("precondition_nohz_full", &p.nohz_full)?;
        st.serialize_field("precondition_rcu_nocbs", &p.rcu_nocbs)?;
        st.serialize_field("precondition_governor", &p.governor)?;
        st.serialize_field("precondition_cstate_max", &p.cstate_max)?;
        st.serialize_field("precondition_tsc_invariant", &p.tsc_invariant)?;
        st.serialize_field("precondition_coalesce_off", &p.coalesce_off)?;
        st.serialize_field("precondition_tso_off", &p.tso_off)?;
        st.serialize_field("precondition_lro_off", &p.lro_off)?;
        st.serialize_field("precondition_rss_on", &p.rss_on)?;
        st.serialize_field("precondition_thermal_throttle", &p.thermal_throttle)?;
        st.serialize_field("precondition_hugepages_reserved", &p.hugepages_reserved)?;
        st.serialize_field("precondition_irqbalance_off", &p.irqbalance_off)?;
        st.serialize_field("precondition_wc_active", &p.wc_active)?;
        st.serialize_field("tool", &self.tool)?;
        st.serialize_field("test_case", &self.test_case)?;
        st.serialize_field("feature_set", &self.feature_set)?;
        st.serialize_field("dimensions_json", &self.dimensions_json)?;
        st.serialize_field("metric_name", &self.metric_name)?;
        st.serialize_field("metric_unit", &self.metric_unit)?;
        st.serialize_field("metric_value", &self.metric_value)?;
        st.serialize_field("metric_aggregation", &self.metric_aggregation)?;
        // Host / DPDK / worktree identification columns (Task 2.8). Options emit
        // as the empty cell when `None` — csv's Serialize derive handles that
        // via `Serialize::serialize` on the inner `Option<T>`, which writes no
        // characters for `None`.
        st.serialize_field("cpu_family", &self.cpu_family)?;
        st.serialize_field("cpu_model_name", &self.cpu_model_name)?;
        st.serialize_field("dpdk_version_pkgconfig", &self.dpdk_version_pkgconfig)?;
        st.serialize_field("worktree_branch", &self.worktree_branch)?;
        st.serialize_field("uprof_session_id", &self.uprof_session_id)?;
        st.end()
    }
}

// -- Deserialize -------------------------------------------------------------

impl<'de> Deserialize<'de> for CsvRow {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_struct("CsvRow", COLUMNS, CsvRowVisitor)
    }
}

struct CsvRowVisitor;

impl<'de> Visitor<'de> for CsvRowVisitor {
    type Value = CsvRow;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a CsvRow record with the spec §14 column set")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        // Optional field buffers — we build each up as we see the matching key.
        let mut run_id: Option<uuid::Uuid> = None;
        let mut run_started_at: Option<String> = None;
        let mut commit_sha: Option<String> = None;
        let mut branch: Option<String> = None;
        let mut host: Option<String> = None;
        let mut instance_type: Option<String> = None;
        let mut cpu_model: Option<String> = None;
        let mut dpdk_version: Option<String> = None;
        let mut kernel: Option<String> = None;
        let mut nic_model: Option<String> = None;
        let mut nic_fw: Option<String> = None;
        let mut ami_id: Option<String> = None;
        let mut precondition_mode: Option<PreconditionMode> = None;

        // RI1 follow-up (T14): track each precondition column individually so
        // a schema-drifted CSV that silently omits one fails with a clear
        // "missing precondition column X" error rather than defaulting the
        // missing cell to `PreconditionValue::default()` (= `Pass(None)`) and
        // reporting a false green.
        let mut isolcpus: Option<PreconditionValue> = None;
        let mut nohz_full: Option<PreconditionValue> = None;
        let mut rcu_nocbs: Option<PreconditionValue> = None;
        let mut governor: Option<PreconditionValue> = None;
        let mut cstate_max: Option<PreconditionValue> = None;
        let mut tsc_invariant: Option<PreconditionValue> = None;
        let mut coalesce_off: Option<PreconditionValue> = None;
        let mut tso_off: Option<PreconditionValue> = None;
        let mut lro_off: Option<PreconditionValue> = None;
        let mut rss_on: Option<PreconditionValue> = None;
        let mut thermal_throttle: Option<PreconditionValue> = None;
        let mut hugepages_reserved: Option<PreconditionValue> = None;
        let mut irqbalance_off: Option<PreconditionValue> = None;
        let mut wc_active: Option<PreconditionValue> = None;

        let mut tool: Option<String> = None;
        let mut test_case: Option<String> = None;
        let mut feature_set: Option<String> = None;
        let mut dimensions_json: Option<String> = None;
        let mut metric_name: Option<String> = None;
        let mut metric_unit: Option<String> = None;
        let mut metric_value: Option<f64> = None;
        let mut metric_aggregation: Option<MetricAggregation> = None;

        // Task 2.8 host / DPDK / worktree identification columns. Unlike the
        // required columns above, these default to `None` if the CSV does not
        // contain the column at all — older CSVs written before Task 2.8 still
        // round-trip. An explicitly-empty cell also deserialises to `None`
        // because `Option::<String>::deserialize` via the csv crate treats an
        // empty field as `None`.
        let mut cpu_family: Option<Option<u32>> = None;
        let mut cpu_model_name: Option<Option<String>> = None;
        let mut dpdk_version_pkgconfig: Option<Option<String>> = None;
        let mut worktree_branch: Option<Option<String>> = None;
        let mut uprof_session_id: Option<Option<String>> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "run_id" => run_id = Some(map.next_value()?),
                "run_started_at" => run_started_at = Some(map.next_value()?),
                "commit_sha" => commit_sha = Some(map.next_value()?),
                "branch" => branch = Some(map.next_value()?),
                "host" => host = Some(map.next_value()?),
                "instance_type" => instance_type = Some(map.next_value()?),
                "cpu_model" => cpu_model = Some(map.next_value()?),
                "dpdk_version" => dpdk_version = Some(map.next_value()?),
                "kernel" => kernel = Some(map.next_value()?),
                "nic_model" => nic_model = Some(map.next_value()?),
                "nic_fw" => nic_fw = Some(map.next_value()?),
                "ami_id" => ami_id = Some(map.next_value()?),
                "precondition_mode" => precondition_mode = Some(map.next_value()?),
                "precondition_isolcpus" => isolcpus = Some(map.next_value()?),
                "precondition_nohz_full" => nohz_full = Some(map.next_value()?),
                "precondition_rcu_nocbs" => rcu_nocbs = Some(map.next_value()?),
                "precondition_governor" => governor = Some(map.next_value()?),
                "precondition_cstate_max" => cstate_max = Some(map.next_value()?),
                "precondition_tsc_invariant" => tsc_invariant = Some(map.next_value()?),
                "precondition_coalesce_off" => coalesce_off = Some(map.next_value()?),
                "precondition_tso_off" => tso_off = Some(map.next_value()?),
                "precondition_lro_off" => lro_off = Some(map.next_value()?),
                "precondition_rss_on" => rss_on = Some(map.next_value()?),
                "precondition_thermal_throttle" => thermal_throttle = Some(map.next_value()?),
                "precondition_hugepages_reserved" => hugepages_reserved = Some(map.next_value()?),
                "precondition_irqbalance_off" => irqbalance_off = Some(map.next_value()?),
                "precondition_wc_active" => wc_active = Some(map.next_value()?),
                "tool" => tool = Some(map.next_value()?),
                "test_case" => test_case = Some(map.next_value()?),
                "feature_set" => feature_set = Some(map.next_value()?),
                "dimensions_json" => dimensions_json = Some(map.next_value()?),
                "metric_name" => metric_name = Some(map.next_value()?),
                "metric_unit" => metric_unit = Some(map.next_value()?),
                "metric_value" => metric_value = Some(map.next_value()?),
                "metric_aggregation" => metric_aggregation = Some(map.next_value()?),
                "cpu_family" => cpu_family = Some(map.next_value()?),
                "cpu_model_name" => cpu_model_name = Some(map.next_value()?),
                "dpdk_version_pkgconfig" => dpdk_version_pkgconfig = Some(map.next_value()?),
                "worktree_branch" => worktree_branch = Some(map.next_value()?),
                "uprof_session_id" => uprof_session_id = Some(map.next_value()?),
                _ => {
                    // Unknown column — skip. Forward-compat with future
                    // schema additions that older tools don't know about.
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
            }
        }

        fn require<T, E: serde::de::Error>(v: Option<T>, name: &'static str) -> Result<T, E> {
            v.ok_or_else(|| E::missing_field(name))
        }

        let preconditions = Preconditions {
            isolcpus: require(isolcpus, "precondition_isolcpus")?,
            nohz_full: require(nohz_full, "precondition_nohz_full")?,
            rcu_nocbs: require(rcu_nocbs, "precondition_rcu_nocbs")?,
            governor: require(governor, "precondition_governor")?,
            cstate_max: require(cstate_max, "precondition_cstate_max")?,
            tsc_invariant: require(tsc_invariant, "precondition_tsc_invariant")?,
            coalesce_off: require(coalesce_off, "precondition_coalesce_off")?,
            tso_off: require(tso_off, "precondition_tso_off")?,
            lro_off: require(lro_off, "precondition_lro_off")?,
            rss_on: require(rss_on, "precondition_rss_on")?,
            thermal_throttle: require(thermal_throttle, "precondition_thermal_throttle")?,
            hugepages_reserved: require(hugepages_reserved, "precondition_hugepages_reserved")?,
            irqbalance_off: require(irqbalance_off, "precondition_irqbalance_off")?,
            wc_active: require(wc_active, "precondition_wc_active")?,
        };

        let run_metadata = RunMetadata {
            run_id: require(run_id, "run_id")?,
            run_started_at: require(run_started_at, "run_started_at")?,
            commit_sha: require(commit_sha, "commit_sha")?,
            branch: require(branch, "branch")?,
            host: require(host, "host")?,
            instance_type: require(instance_type, "instance_type")?,
            cpu_model: require(cpu_model, "cpu_model")?,
            dpdk_version: require(dpdk_version, "dpdk_version")?,
            kernel: require(kernel, "kernel")?,
            nic_model: require(nic_model, "nic_model")?,
            nic_fw: require(nic_fw, "nic_fw")?,
            ami_id: require(ami_id, "ami_id")?,
            precondition_mode: require(precondition_mode, "precondition_mode")?,
            preconditions,
        };

        Ok(CsvRow {
            run_metadata,
            tool: require(tool, "tool")?,
            test_case: require(test_case, "test_case")?,
            feature_set: require(feature_set, "feature_set")?,
            dimensions_json: require(dimensions_json, "dimensions_json")?,
            metric_name: require(metric_name, "metric_name")?,
            metric_unit: require(metric_unit, "metric_unit")?,
            metric_value: require(metric_value, "metric_value")?,
            metric_aggregation: require(metric_aggregation, "metric_aggregation")?,
            // Task 2.8 identification columns — tolerated as absent. The
            // `unwrap_or(None)` collapses both "column never seen" and
            // "column present but empty" into `None`.
            cpu_family: cpu_family.unwrap_or(None),
            cpu_model_name: cpu_model_name.unwrap_or(None),
            dpdk_version_pkgconfig: dpdk_version_pkgconfig.unwrap_or(None),
            worktree_branch: worktree_branch.unwrap_or(None),
            uprof_session_id: uprof_session_id.unwrap_or(None),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a sample row used for drift-guard tests. Values are arbitrary;
    /// what matters is that every field is present so the Serialize impl must
    /// emit every column.
    fn sample_row() -> CsvRow {
        CsvRow {
            run_metadata: RunMetadata {
                run_id: uuid::Uuid::nil(),
                run_started_at: "2026-04-22T03:14:07Z".into(),
                commit_sha: "7f70ea50000000000000000000000000000000ab".into(),
                branch: "phase-a10".into(),
                host: "ip-10-0-0-42".into(),
                instance_type: "c6a.2xlarge".into(),
                cpu_model: "AMD EPYC 7R13".into(),
                dpdk_version: "23.11.2".into(),
                kernel: "6.17.0-1009-generic".into(),
                nic_model: "Elastic Network Adapter (ENA)".into(),
                nic_fw: String::new(),
                ami_id: "ami-0123456789abcdef0".into(),
                precondition_mode: PreconditionMode::Strict,
                preconditions: Preconditions::default(),
            },
            tool: "bench-vs-mtcp".into(),
            test_case: "burst".into(),
            feature_set: "default".into(),
            dimensions_json: "{}".into(),
            metric_name: "metric".into(),
            metric_unit: "unit".into(),
            metric_value: 1.0,
            metric_aggregation: MetricAggregation::P99,
            cpu_family: Some(25),
            cpu_model_name: Some("AMD EPYC 7R13 Processor".into()),
            dpdk_version_pkgconfig: Some("23.11.2".into()),
            worktree_branch: Some("a10-perf-23.11".into()),
            uprof_session_id: None,
        }
    }

    #[test]
    fn metric_aggregation_display_matches_serde() {
        for v in [
            MetricAggregation::P50,
            MetricAggregation::P99,
            MetricAggregation::P999,
            MetricAggregation::Mean,
            MetricAggregation::Stddev,
            MetricAggregation::Ci95Lower,
            MetricAggregation::Ci95Upper,
        ] {
            let disp = v.to_string();
            let ser = serde_json::to_string(&v).unwrap();
            assert_eq!(ser, format!("\"{}\"", disp));
        }
    }

    /// Invariance guard: the column count must match the spec. Breakdown:
    /// 13 run-metadata, 14 precondition, 8 per-row, 5 host/dpdk/worktree
    /// identification (Task 2.8) — 40 total. If this fires, a column was
    /// added/removed without updating the companion tests and the Serialize
    /// impl.
    #[test]
    fn columns_len_is_expected() {
        assert_eq!(COLUMNS.len(), 40);
    }

    /// Invariance guard: the header row that csv::Writer emits when it
    /// serialises a `CsvRow` must match `COLUMNS.join(",")` exactly. Catches
    /// any drift between the hand-written `Serialize::serialize_field` calls
    /// and `COLUMNS`.
    #[test]
    fn serialised_header_matches_columns() {
        let row = sample_row();
        let mut buf = Vec::new();
        {
            let mut wtr = csv::Writer::from_writer(&mut buf);
            wtr.serialize(&row).unwrap();
            wtr.flush().unwrap();
        }
        let text = std::str::from_utf8(&buf).unwrap();
        let header = text.lines().next().unwrap();
        assert_eq!(header, COLUMNS.join(","));
    }

    /// Invariance guard: when the `Serialize` impl is dispatched to a
    /// map-producing serialiser (serde_json → Map), the resulting object must
    /// have exactly `COLUMNS.len()` keys. Catches drift between the column
    /// set actually emitted and `COLUMNS`.
    #[test]
    fn serialised_keys_match_columns() {
        let row = sample_row();
        let value = serde_json::to_value(&row).unwrap();
        let map = value.as_object().expect("CsvRow must serialise to a map");
        assert_eq!(map.len(), COLUMNS.len());
        for col in COLUMNS {
            assert!(map.contains_key(*col), "missing column {col}");
        }
    }
}
