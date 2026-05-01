//! Pre-run check helpers (spec §11.1 "Pre-run checks").
//!
//! Spec §11.1 requires each bucket to pass four pre-run checks before
//! the bucket's samples count; any failure invalidates the bucket
//! (not the run):
//!
//! 1. Peer advertised receive window ≥ K.
//! 2. Identical MSS (1460) and TX burst size on both stacks.
//! 3. Achieved rate ≤ 70% of NIC max pps/bps (not NIC-bound).
//! 4. §11.1 measurement-discipline green.
//!
//! (1)–(3) are the bucket-scoped checks handled by this module. (4) is
//! the run-scoped host precondition set already handled by
//! `bench_common::preconditions` + the `check-bench-preconditions`
//! helper; this module does not duplicate that logic.
//!
//! All functions here are pure-data over `u64` / `u16` inputs so they
//! can be unit-tested without a running DPDK engine or live peer.

/// Outcome of a bucket's pre-run check set. `Ok` counts samples
/// toward the aggregation; any [`Self::Invalid`] arm drops the bucket
/// and surfaces the reason for the CSV dimensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketVerdict {
    /// All checks passed — bucket is valid.
    Ok,
    /// Bucket invalidated — carries a human-readable reason string
    /// that gets written into `dimensions_json.bucket_invalid` so
    /// bench-report can filter and surface the reason without losing
    /// the row's metadata.
    Invalid(String),
}

impl BucketVerdict {
    pub fn is_ok(&self) -> bool {
        matches!(self, BucketVerdict::Ok)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            BucketVerdict::Invalid(r) => Some(r.as_str()),
            BucketVerdict::Ok => None,
        }
    }
}

/// Spec §11.1 check (1): peer advertised receive window ≥ K.
///
/// `peer_rwnd_bytes` is the peer's advertised window (already
/// window-scaled if WS is in use on the connection). `burst_bytes`
/// is K for the bucket. The guard is `>=` per spec.
pub fn check_peer_window(peer_rwnd_bytes: u64, burst_bytes: u64) -> BucketVerdict {
    if peer_rwnd_bytes >= burst_bytes {
        BucketVerdict::Ok
    } else {
        BucketVerdict::Invalid(format!(
            "peer rwnd ({peer_rwnd_bytes} B) < K ({burst_bytes} B) — peer-window stall"
        ))
    }
}

/// Spec §11.1 check (2): identical MSS and TX burst size on both stacks.
///
/// Both values are operator-configured — the harness builds EngineConfig
/// with `tcp_mss = 1460` and the mTCP peer configures its MSS similarly.
/// This helper asserts agreement.
pub fn check_mss_and_burst_agreement(
    our_mss: u16,
    peer_mss: u16,
    our_tx_burst_size: u32,
    peer_tx_burst_size: u32,
) -> BucketVerdict {
    if our_mss != peer_mss {
        return BucketVerdict::Invalid(format!(
            "MSS mismatch: dpdk_net={our_mss} B, peer/mtcp={peer_mss} B"
        ));
    }
    if our_tx_burst_size != peer_tx_burst_size {
        return BucketVerdict::Invalid(format!(
            "TX burst size mismatch: dpdk_net={our_tx_burst_size}, peer/mtcp={peer_tx_burst_size}"
        ));
    }
    BucketVerdict::Ok
}

/// Spec §11.1 check (3): achieved rate ≤ 70% of NIC max pps/bps.
///
/// `achieved_bps` is the bucket's observed sustained throughput; the
/// caller passes `nic_max_bps` from the NIC's advertised line rate (or
/// from the AMI's recorded instance-type cap — e.g. 100 Gbps for a
/// c6in.metal). The `70%` ceiling is a spec constant; parameterised
/// here for testability.
///
/// NOTE: The threshold is the spec's 70%. This is the *upper* bound:
/// if achieved rate is ≥ 70% the bucket is likely NIC-saturation-
/// bound and its measured throughput is not stack-attributable.
pub fn check_nic_saturation_bps(achieved_bps: u64, nic_max_bps: u64) -> BucketVerdict {
    check_nic_saturation_bps_with_ratio(achieved_bps, nic_max_bps, 0.7)
}

/// Parameterised helper for [`check_nic_saturation_bps`]. `ratio` is
/// the saturation ceiling as a unit fraction (0.70 per spec).
pub fn check_nic_saturation_bps_with_ratio(
    achieved_bps: u64,
    nic_max_bps: u64,
    ratio: f64,
) -> BucketVerdict {
    if nic_max_bps == 0 {
        return BucketVerdict::Invalid(
            "NIC max bps is zero — caller did not pass a valid line-rate ceiling".to_string(),
        );
    }
    let ceiling_bps = (nic_max_bps as f64 * ratio) as u64;
    if achieved_bps <= ceiling_bps {
        BucketVerdict::Ok
    } else {
        BucketVerdict::Invalid(format!(
            "achieved {achieved_bps} bps > {:.0}% of NIC line rate ({nic_max_bps} bps); bucket is NIC-bound",
            ratio * 100.0
        ))
    }
}

/// Sanity invariant at run end per spec §11.1:
/// `sum_over_bursts(K) == stack_tx_bytes_counter`.
///
/// Divergence = harness is lying about what it sent. Returns
/// `Ok(())` if the two sides agree exactly; otherwise returns `Err`
/// with a detailed diff message the caller can bubble up.
///
/// The `stack_tx_bytes_counter` argument should be the delta on the
/// TCP payload counter (`counters.tcp.tx_payload_bytes`), captured
/// pre-warmup and again post-run — `sum_over_bursts(K)` includes
/// only the measurement bursts (warmup excluded).
pub fn check_sanity_invariant(
    sum_over_measurement_bursts_bytes: u64,
    stack_tx_payload_bytes_delta: u64,
) -> Result<(), String> {
    if sum_over_measurement_bursts_bytes == stack_tx_payload_bytes_delta {
        Ok(())
    } else {
        Err(format!(
            "sanity invariant violated: sum_over_bursts(K) = {sum_over_measurement_bursts_bytes} B, \
             stack_tx_bytes_counter delta = {stack_tx_payload_bytes_delta} B \
             (difference: {} B)",
            (sum_over_measurement_bursts_bytes as i128 - stack_tx_payload_bytes_delta as i128).abs()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------
    // check_peer_window
    // ----------------------------------------------------------------

    #[test]
    fn peer_window_accepts_equal() {
        let v = check_peer_window(64 * 1024, 64 * 1024);
        assert!(v.is_ok(), "got {v:?}");
    }

    #[test]
    fn peer_window_accepts_larger() {
        let v = check_peer_window(1 << 20, 64 * 1024);
        assert!(v.is_ok());
    }

    #[test]
    fn peer_window_rejects_smaller() {
        let v = check_peer_window(32 * 1024, 64 * 1024);
        assert!(!v.is_ok());
        let reason = v.reason().unwrap();
        assert!(reason.contains("peer-window stall"), "reason = {reason}");
    }

    // ----------------------------------------------------------------
    // check_mss_and_burst_agreement
    // ----------------------------------------------------------------

    #[test]
    fn mss_and_burst_agreement_passes_when_equal() {
        let v = check_mss_and_burst_agreement(1460, 1460, 32, 32);
        assert!(v.is_ok());
    }

    #[test]
    fn mss_and_burst_agreement_rejects_mss_mismatch() {
        let v = check_mss_and_burst_agreement(1460, 1440, 32, 32);
        assert!(!v.is_ok());
        assert!(v.reason().unwrap().contains("MSS mismatch"));
    }

    #[test]
    fn mss_and_burst_agreement_rejects_burst_mismatch() {
        let v = check_mss_and_burst_agreement(1460, 1460, 32, 64);
        assert!(!v.is_ok());
        assert!(v.reason().unwrap().contains("TX burst size mismatch"));
    }

    // ----------------------------------------------------------------
    // check_nic_saturation_bps
    // ----------------------------------------------------------------

    #[test]
    fn nic_saturation_accepts_below_70pct() {
        // 25 Gbps observed, 100 Gbps NIC max → 25% — well below 70%.
        let v = check_nic_saturation_bps(25_000_000_000, 100_000_000_000);
        assert!(v.is_ok());
    }

    #[test]
    fn nic_saturation_accepts_exactly_70pct() {
        let v = check_nic_saturation_bps(70_000_000_000, 100_000_000_000);
        assert!(v.is_ok(), "70% exactly is the ceiling; got {v:?}");
    }

    #[test]
    fn nic_saturation_rejects_above_70pct() {
        let v = check_nic_saturation_bps(80_000_000_000, 100_000_000_000);
        assert!(!v.is_ok());
        assert!(v.reason().unwrap().contains("NIC-bound"));
    }

    #[test]
    fn nic_saturation_rejects_zero_max() {
        let v = check_nic_saturation_bps(1_000, 0);
        assert!(!v.is_ok());
        assert!(v.reason().unwrap().contains("NIC max bps is zero"));
    }

    #[test]
    fn nic_saturation_parametrized_ratio() {
        // Custom 50% ceiling — operator might want stricter bounds.
        let v = check_nic_saturation_bps_with_ratio(60_000_000_000, 100_000_000_000, 0.5);
        assert!(!v.is_ok());
        let reason = v.reason().unwrap();
        assert!(reason.contains("50%"), "reason = {reason}");
    }

    // ----------------------------------------------------------------
    // check_sanity_invariant
    // ----------------------------------------------------------------

    #[test]
    fn sanity_invariant_passes_when_exact_match() {
        // 10_000 bursts of 64 KiB each.
        let sum = 10_000u64 * 64 * 1024;
        let counter = sum;
        assert!(check_sanity_invariant(sum, counter).is_ok());
    }

    #[test]
    fn sanity_invariant_fails_on_divergence() {
        let err = check_sanity_invariant(10_000 * 64 * 1024, 10_000 * 64 * 1024 - 1).unwrap_err();
        assert!(
            err.contains("sanity invariant violated"),
            "err = {err}"
        );
    }

    #[test]
    fn sanity_invariant_prints_bidirectional_diff() {
        // Harness claims more than the counter recorded — should still
        // report the magnitude of the difference.
        let err = check_sanity_invariant(100, 50).unwrap_err();
        assert!(err.contains("50 B"), "err = {err}");
    }
}
