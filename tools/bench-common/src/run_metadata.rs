//! Per-run invariant fields populated once at start of a run. Spec §14.1
//! ("run-invariant columns").
//!
//! The 14 individual precondition results (spec §4.1) are serialised as
//! columns named `precondition_isolcpus`, `precondition_nohz_full`, ... . The
//! `precondition_*` prefix is carried on the `Preconditions` struct's field
//! attributes (see `preconditions.rs`) rather than via a custom flatten
//! module — `csv::Writer` does not support `SerializeMap`, so the natural
//! serde-flatten path via `serialize_map` (which the design sketch called
//! out as the "tricky bit") does not work end-to-end with csv. Using per-field
//! renames lets every field stay a scalar column, which is what `csv::Writer`
//! handles correctly.
//!
//! Tradeoff: callers that want a prefix-free `Preconditions` struct for
//! internal use pay one extra attribute per field; in exchange the CSV
//! round-trip works without pulling in a map-aware CSV serialiser.

use serde::{Deserialize, Serialize};

use crate::preconditions::{PreconditionMode, Preconditions};

/// Per-run invariant metadata — values constant for every row within a single
/// run. Emitted as the first block of columns in the CSV.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunMetadata {
    pub run_id: uuid::Uuid,
    /// ISO 8601 with timezone, e.g. `2026-04-22T03:14:07Z`.
    pub run_started_at: String,
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
    #[serde(flatten)]
    pub preconditions: Preconditions,
}
