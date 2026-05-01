//! Round-trip: write CsvRow → read back → assert equal.

use bench_common::csv_row::{
    CsvRow, MetricAggregation, PreconditionValue, COLUMNS, PRECONDITION_COLUMNS,
};
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
    let values = [
        "p50",
        "p99",
        "p999",
        "mean",
        "stddev",
        "ci95_lower",
        "ci95_upper",
    ];
    for v in values {
        let enumv: MetricAggregation = serde_json::from_str(&format!("\"{}\"", v)).unwrap();
        let back: String = serde_json::to_string(&enumv).unwrap();
        assert_eq!(back, format!("\"{}\"", v));
    }
}

#[test]
fn precondition_value_parses_pass_and_fail() {
    let a: PreconditionValue = "pass=2-7".parse().unwrap();
    assert!(a.is_pass());
    assert_eq!(a, PreconditionValue::pass_with("2-7"));
    let b: PreconditionValue = "fail=C6".parse().unwrap();
    assert!(b.is_fail());
    assert_eq!(b, PreconditionValue::fail_with("C6"));
    let c: PreconditionValue = "pass".parse().unwrap();
    assert!(c.is_pass());
    assert_eq!(c, PreconditionValue::pass());
}

/// Round-trips a `CsvRow` whose `precondition_wc_active` column is the
/// `n/a` marker — the bench-micro carve-out from spec §4.1 line 222.
/// Before C1 this test failed at the read step because `FromStr` did not
/// accept the `n/a` token.
#[test]
fn csv_row_round_trip_bench_micro_na() {
    let mut row = sample_row();
    row.run_metadata.preconditions.wc_active = PreconditionValue::not_applicable();

    let mut buf = Vec::new();
    {
        let mut wtr = csv::Writer::from_writer(&mut buf);
        row.write_with_header(&mut wtr).unwrap();
    }
    // Sanity: the cell for precondition_wc_active must read "n/a".
    let text = std::str::from_utf8(&buf).unwrap();
    assert!(
        text.contains(",n/a,"),
        "expected n/a cell in serialised row, got: {text}"
    );

    let mut rdr = csv::Reader::from_reader(&buf[..]);
    let parsed: CsvRow = rdr.deserialize().next().unwrap().unwrap();
    assert_eq!(parsed, row);
    assert!(parsed
        .run_metadata
        .preconditions
        .wc_active
        .is_not_applicable());
}

/// RI1 follow-up (T14): a schema-drifted CSV that omits one of the 14
/// `precondition_*` columns must fail deserialisation with a clear
/// `missing field precondition_X` error.
///
/// Before the T14 visitor upgrade, a missing precondition column silently
/// defaulted to `PreconditionValue::default()` (= `Pass(None)`) — which
/// turned a schema-drifted CSV into a false-green row where the dropped
/// check was reported as passing.
///
/// This test constructs a CSV with the `precondition_cstate_max` column
/// removed from both header and data row, then asserts `CsvRow::deserialize`
/// returns an error that mentions the dropped column name.
#[test]
fn csv_row_deserialize_errors_on_missing_precondition_column() {
    // First serialise a known-good row, then strip one column from header +
    // data. Using the live Serialize impl (instead of a hand-written CSV
    // literal) keeps this test robust to future non-precondition column
    // additions — only the dropped column's index shifts.
    let row = sample_row();
    let mut buf = Vec::new();
    {
        let mut wtr = csv::Writer::from_writer(&mut buf);
        row.write_with_header(&mut wtr).unwrap();
    }
    let text = std::str::from_utf8(&buf).unwrap();
    let mut lines = text.lines();
    let header_line = lines.next().unwrap();
    let data_line = lines.next().unwrap();

    let dropped_col = "precondition_cstate_max";
    let drop_index = COLUMNS
        .iter()
        .position(|c| *c == dropped_col)
        .expect("dropped column must exist in COLUMNS");

    let header_fields: Vec<&str> = header_line.split(',').collect();
    let data_fields: Vec<&str> = data_line.split(',').collect();
    assert_eq!(
        header_fields.len(),
        COLUMNS.len(),
        "header arity must match COLUMNS before drop"
    );
    assert_eq!(
        header_fields[drop_index], dropped_col,
        "drop_index must land on the column we intended to strip"
    );

    let mut drifted_header: Vec<&str> = header_fields.clone();
    drifted_header.remove(drop_index);
    let mut drifted_data: Vec<&str> = data_fields.clone();
    drifted_data.remove(drop_index);

    let mut drifted_csv = String::new();
    drifted_csv.push_str(&drifted_header.join(","));
    drifted_csv.push('\n');
    drifted_csv.push_str(&drifted_data.join(","));
    drifted_csv.push('\n');

    let mut rdr = csv::Reader::from_reader(drifted_csv.as_bytes());
    let parsed: Result<CsvRow, _> = rdr.deserialize().next().unwrap();
    let err = parsed.expect_err("schema-drifted CSV must fail to deserialise");
    let msg = err.to_string();
    assert!(
        msg.contains(dropped_col),
        "error message should mention the missing column {dropped_col}, got: {msg}"
    );
}

/// I3 (T14 code-quality review): the single-column drift-guard above covers
/// one representative precondition column. This test iterates over every
/// entry in `PRECONDITION_COLUMNS` so a future refactor that drops the
/// missing-field error on any of the 14 can't regress silently — the list
/// is the single source of truth exported for exactly this purpose.
#[test]
fn csv_row_deserialize_errors_on_any_missing_precondition_column() {
    // Serialise a known-good row once — we strip one column per iteration
    // and feed the drifted CSV back through the visitor.
    let row = sample_row();
    let mut buf = Vec::new();
    {
        let mut wtr = csv::Writer::from_writer(&mut buf);
        row.write_with_header(&mut wtr).unwrap();
    }
    let text = std::str::from_utf8(&buf).unwrap();
    let mut lines = text.lines();
    let header_line = lines.next().unwrap();
    let data_line = lines.next().unwrap();
    let header_fields: Vec<&str> = header_line.split(',').collect();
    let data_fields: Vec<&str> = data_line.split(',').collect();
    assert_eq!(
        header_fields.len(),
        COLUMNS.len(),
        "header arity must match COLUMNS before drop"
    );

    for missing_col in PRECONDITION_COLUMNS {
        let drop_index = COLUMNS
            .iter()
            .position(|c| c == missing_col)
            .unwrap_or_else(|| panic!("precondition column {missing_col} missing from COLUMNS"));
        assert_eq!(
            header_fields[drop_index], *missing_col,
            "drop_index must land on the column we intended to strip ({missing_col})"
        );

        let mut drifted_header: Vec<&str> = header_fields.clone();
        drifted_header.remove(drop_index);
        let mut drifted_data: Vec<&str> = data_fields.clone();
        drifted_data.remove(drop_index);

        let mut drifted_csv = String::new();
        drifted_csv.push_str(&drifted_header.join(","));
        drifted_csv.push('\n');
        drifted_csv.push_str(&drifted_data.join(","));
        drifted_csv.push('\n');

        let mut rdr = csv::Reader::from_reader(drifted_csv.as_bytes());
        let parsed: Result<CsvRow, _> = rdr.deserialize().next().unwrap();
        let err = parsed.expect_err(&format!(
            "drifted CSV missing {missing_col} unexpectedly deserialised OK"
        ));
        let msg = err.to_string();
        assert!(
            msg.contains(missing_col),
            "error message for missing {missing_col} should mention the column name; got: {msg}"
        );
    }
}
