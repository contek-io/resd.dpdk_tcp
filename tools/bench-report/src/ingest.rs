//! CSV ingestion. Walks a root directory recursively, deserialises every
//! file with a `.csv` extension into `bench_common::csv_row::CsvRow` rows,
//! and concatenates the result into a flat `Vec<CsvRow>`.
//!
//! The input tree is expected to mirror `target/bench-results/<tool>/<run>.csv`
//! but we don't enforce that layout — any `.csv` under the root is ingested.
//! A future sidecar (`*.bin`, `*.json` from criterion) is ignored by
//! extension filter.
//!
//! Errors carry the offending path so a malformed CSV from one tool
//! doesn't hide the rest.

use std::path::{Path, PathBuf};

use anyhow::Context;
use bench_common::csv_row::CsvRow;
use walkdir::WalkDir;

/// Walk `root` recursively, read every `*.csv` file, deserialise its rows
/// into `CsvRow` and return a flat `Vec`. File order is the iteration
/// order produced by `walkdir::WalkDir` (sorted = deterministic per
/// platform; we sort explicitly in [`discover_csv_files`] for a stable
/// contract across platforms and filesystems).
pub fn ingest_dir(root: &Path) -> anyhow::Result<Vec<CsvRow>> {
    let files = discover_csv_files(root)?;
    let mut out = Vec::new();
    for path in files {
        let rows = read_csv_file(&path)
            .with_context(|| format!("reading CSV {}", path.display()))?;
        out.extend(rows);
    }
    Ok(out)
}

/// Recursively enumerate `root`, returning the sorted list of files whose
/// extension is exactly `csv` (case-sensitive). Any other extension or
/// non-file entry is skipped.
///
/// The sort is deterministic (lexicographic on `PathBuf`) so repeat runs
/// against the same tree produce the same ordering — useful for JSON diff
/// and cache-key stability.
pub fn discover_csv_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if !root.exists() {
        anyhow::bail!("input directory {} does not exist", root.display());
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        if path.extension().and_then(|s| s.to_str()) == Some("csv") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Deserialise every row in `path` into a `CsvRow`. Returns a per-file
/// error if any row fails to parse (carries the row index for debugging).
pub fn read_csv_file(path: &Path) -> anyhow::Result<Vec<CsvRow>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(path)
        .with_context(|| format!("opening CSV {}", path.display()))?;
    let mut out = Vec::new();
    for (i, rec) in rdr.deserialize::<CsvRow>().enumerate() {
        let row = rec.with_context(|| format!("parsing row {i} of {}", path.display()))?;
        out.push(row);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a unique scratch directory for a test. Uses `target/` to avoid
    /// needing a `tempfile` dep; the cargo-test harness always has
    /// write access here. UUID suffix prevents parallel-test collisions.
    fn scratch_dir(tag: &str) -> PathBuf {
        let base = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target"));
        let path = base.join(format!(
            "bench-report-test-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn discover_ignores_non_csv() {
        let dir = scratch_dir("discover");
        fs::write(dir.join("a.csv"), "").unwrap();
        fs::write(dir.join("b.bin"), "").unwrap();
        fs::write(dir.join("c.CSV"), "").unwrap(); // uppercase is rejected on purpose
        let got = discover_csv_files(&dir).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].ends_with("a.csv"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_recurses_subdirectories() {
        let dir = scratch_dir("recurse");
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("x.csv"), "").unwrap();
        let got = discover_csv_files(&dir).unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].ends_with("x.csv"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_errors_on_missing_root() {
        let dir = scratch_dir("missing").join("does-not-exist");
        let err = discover_csv_files(&dir).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }
}
