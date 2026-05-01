//! Sum-identity validation.
//!
//! Spec §6: the sum of attribution buckets on any single round-trip
//! measurement MUST equal the end-to-end wall-clock RTT (also a u64
//! ns) within a caller-supplied tolerance. Default tolerance is
//! ±50 ns (CLI default on `main.rs`), chosen to span TSC quantization
//! plus independent clock-source drift across the NIC/host boundary
//! without admitting a truly drifted measurement.
//!
//! A mismatch invalidates the measurement. Under strict mode the
//! run-loop propagates the error out of the per-iteration call;
//! lenient mode is reserved for future debug runs and is not yet
//! wired (spec §6 note: "strict-mode-only for Stage 1").

/// Assert that the sum of attribution buckets equals the measured RTT
/// within `tol_ns`. Returns `Ok(())` on match, `Err(String)` on
/// mismatch with a diagnostic string including both values and the
/// absolute delta.
///
/// Uses saturating arithmetic on the delta so a u64 underflow on a
/// pathological programming error produces a diagnostic instead of
/// wrapping. Both `bucket_sum_ns` and `rtt_ns` arrive from the
/// caller as u64 — no TSC wrap is possible here because the caller
/// converts to ns via the cached `tsc_hz` before calling.
pub fn assert_sum_identity(
    bucket_sum_ns: u64,
    rtt_ns: u64,
    tol_ns: u64,
) -> Result<(), String> {
    let diff = bucket_sum_ns.abs_diff(rtt_ns);
    if diff <= tol_ns {
        Ok(())
    } else {
        Err(format!(
            "sum_identity mismatch: bucket_sum={bucket_sum_ns} rtt={rtt_ns} \
             diff={diff} tol={tol_ns}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_passes() {
        assert!(assert_sum_identity(1_000, 1_000, 0).is_ok());
    }

    #[test]
    fn within_tolerance_passes_above() {
        assert!(assert_sum_identity(1_050, 1_000, 50).is_ok());
    }

    #[test]
    fn within_tolerance_passes_below() {
        assert!(assert_sum_identity(950, 1_000, 50).is_ok());
    }

    #[test]
    fn at_tolerance_boundary_passes() {
        assert!(assert_sum_identity(1_050, 1_000, 50).is_ok());
        assert!(assert_sum_identity(950, 1_000, 50).is_ok());
    }

    #[test]
    fn beyond_tolerance_errors() {
        let err = assert_sum_identity(2_000, 1_000, 50).unwrap_err();
        assert!(err.contains("sum_identity"));
        assert!(err.contains("diff=1000"));
        assert!(err.contains("tol=50"));
    }

    #[test]
    fn zero_tolerance_rejects_any_drift() {
        assert!(assert_sum_identity(1_001, 1_000, 0).is_err());
    }

    #[test]
    fn error_message_includes_both_values() {
        let err = assert_sum_identity(11_000, 10_430, 50).unwrap_err();
        assert!(err.contains("bucket_sum=11000"));
        assert!(err.contains("rtt=10430"));
    }
}
