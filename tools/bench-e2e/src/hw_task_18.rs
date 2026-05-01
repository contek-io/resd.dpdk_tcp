//! A-HW Task 18 subsumption: offload-counter + per-event
//! `rx_hw_ts_ns` assertions that validate the ENA-steady-state
//! offload surface after a run.
//!
//! Spec §6 + parent spec §8.2 (offload counters) + §10.5
//! (`rx_hw_ts_ns == 0` on ENA). A10 Plan B subsumes the standalone
//! A-HW Task 18 (deferred by commit abea362): rather than a dedicated
//! assertion binary, the bench-e2e harness runs a real 128 B / 128 B
//! request-response cycle on the bound ENA VF and checks that the
//! observed counter deltas + event-field populations match the ENA
//! steady-state expectations.
//!
//! # Counter semantics recap
//!
//! The `offload_missing_*` family is one-shot at bring-up: the engine
//! bumps each counter exactly once during `Engine::new` iff it asked
//! the driver to advertise the corresponding offload capability and
//! the driver declined. On ENA (spec §10.5), three of the six are
//! expected to be bumped:
//!
//! - `offload_missing_mbuf_fast_free` — ENA does not advertise the
//!   `RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE` capability (upstream ENA
//!   PMD: not in the `DEV_TX_OFFLOAD` bitmask).
//! - `offload_missing_rss_hash` — ENA does not advertise
//!   `RTE_ETH_RX_OFFLOAD_RSS_HASH` on single-queue configurations.
//! - `offload_missing_rx_timestamp` — ENA does not register the
//!   `rte_dynfield_timestamp` dynamic mbuf field; the engine cannot
//!   populate per-packet `rx_hw_ts_ns` so every Readable event
//!   carries the literal 0.
//!
//! The six cksum offload counters (`rx_cksum_{ipv4,tcp,udp}` +
//! `tx_cksum_{ipv4,tcp,udp}`) must all remain 0 because ENA DOES
//! advertise those — see parent spec §8.2.
//!
//! `offload_missing_llq` is 0 on ENA via A-HW Task 12 (LLQ activated
//! successfully). `rx_drop_cksum_bad` is 0 on well-formed traffic
//! (we drive only the bench-e2e loop which produces clean frames).
//!
//! # rx_hw_ts_ns event-field assertion
//!
//! Complements the one-shot counter: spec §10.5 mandates that the
//! `InternalEvent::Readable.rx_hw_ts_ns` field is literally 0 on
//! every event during a run, because the engine passes `0` to
//! `deliver_readable` when `rte_dynfield_timestamp` is not
//! registered (see `engine.rs:4184` — the field is threaded through
//! verbatim from `hw_rx_ts` which stays 0 for the whole RX path on
//! ENA).

use std::sync::atomic::Ordering;

use dpdk_net_core::counters::Counters;

/// Expected steady-state verdict for each A-HW Task 18 check. A
/// `true` value means "the counter is expected to have been bumped"
/// for the "missing" checks, or "the counter is expected to stay 0"
/// for the non-missing checks (see individual field docs below).
///
/// `Default` returns the ENA steady-state profile. Callers MAY
/// override fields (e.g. an mlx5 smoke run would set
/// `expect_rx_timestamp_missing = false`), but on ENA + default
/// engine config the defaults are the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwTask18Expectations {
    /// Expect `offload_missing_mbuf_fast_free > 0`. True on ENA.
    pub expect_mbuf_fast_free_missing: bool,
    /// Expect `offload_missing_rss_hash > 0`. True on ENA (single-
    /// queue; multi-queue ENA also doesn't advertise until the RSS
    /// hash is explicitly requested + supported).
    pub expect_rss_hash_missing: bool,
    /// Expect `offload_missing_rx_timestamp > 0`. True on ENA (does
    /// not register the dynfield_timestamp dynamic mbuf field).
    pub expect_rx_timestamp_missing: bool,
    /// Expect ALL SIX cksum-offload counters to be == 0 (i.e. ENA
    /// advertises and the engine used it). True on ENA.
    pub expect_all_cksum_advertised: bool,
    /// Expect `offload_missing_llq > 0`. False on ENA — LLQ OK via
    /// A-HW Task 12.
    pub expect_llq_missing: bool,
    /// Expect `rx_drop_cksum_bad == 0`. True on well-formed traffic
    /// (bench-e2e drives only clean request-response frames).
    pub expect_rx_drop_cksum_bad_zero: bool,
    /// Expect every `InternalEvent::Readable.rx_hw_ts_ns == 0`. True
    /// on ENA.
    pub expect_all_rx_hw_ts_ns_zero: bool,
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

/// Assert the post-run A-HW Task 18 expectations against the engine's
/// observed counter state. Does NOT drive any I/O — caller must have
/// completed the run-loop already so the engine's counters are in
/// their final state.
///
/// Returns the first mismatch encountered; on a clean run every
/// expectation is satisfied and the result is `Ok(())`. The error
/// string names the mismatched counter + both observed-greater-than-
/// zero flags so a failed run bisects quickly.
pub fn assert_hw_task_18_post_run(
    counters: &Counters,
    exp: &HwTask18Expectations,
) -> Result<(), String> {
    let e = &counters.eth;

    check_missing(
        e.offload_missing_mbuf_fast_free.load(Ordering::Relaxed),
        exp.expect_mbuf_fast_free_missing,
        "offload_missing_mbuf_fast_free",
    )?;
    check_missing(
        e.offload_missing_rss_hash.load(Ordering::Relaxed),
        exp.expect_rss_hash_missing,
        "offload_missing_rss_hash",
    )?;
    check_missing(
        e.offload_missing_rx_timestamp.load(Ordering::Relaxed),
        exp.expect_rx_timestamp_missing,
        "offload_missing_rx_timestamp",
    )?;
    check_missing(
        e.offload_missing_llq.load(Ordering::Relaxed),
        exp.expect_llq_missing,
        "offload_missing_llq",
    )?;

    // rx_drop_cksum_bad is a per-packet counter rather than a one-shot
    // offload-missing flag. If the caller expects it zero, a non-zero
    // observation is a failure; if the caller doesn't expect it zero
    // we skip the check entirely (no current caller passes false).
    if exp.expect_rx_drop_cksum_bad_zero {
        let v = e.rx_drop_cksum_bad.load(Ordering::Relaxed);
        if v != 0 {
            return Err(format!("rx_drop_cksum_bad={v} != 0 on well-formed traffic"));
        }
    }

    if exp.expect_all_cksum_advertised {
        assert_cksum_counters_all_zero(counters)?;
    }

    Ok(())
}

/// Check one `offload_missing_*` counter against its expected-bumped
/// flag. The counter value is cast to `> 0` before comparison because
/// the one-shot semantics mean "0 if not missing, else N ≥ 1" — we
/// only care about the zero/nonzero axis, not the magnitude.
fn check_missing(actual: u64, expected_missing: bool, name: &str) -> Result<(), String> {
    let observed_missing = actual > 0;
    if observed_missing != expected_missing {
        return Err(format!(
            "{name}: expected_missing={expected_missing} observed_missing={observed_missing} \
             (raw={actual})"
        ));
    }
    Ok(())
}

/// Assert all six cksum-offload-missing counters are 0. Called only
/// when `expect_all_cksum_advertised` is true — on ENA, that's the
/// contract.
fn assert_cksum_counters_all_zero(counters: &Counters) -> Result<(), String> {
    let e = &counters.eth;
    for (v, name) in [
        (e.offload_missing_rx_cksum_ipv4.load(Ordering::Relaxed), "rx_cksum_ipv4"),
        (e.offload_missing_rx_cksum_tcp.load(Ordering::Relaxed), "rx_cksum_tcp"),
        (e.offload_missing_rx_cksum_udp.load(Ordering::Relaxed), "rx_cksum_udp"),
        (e.offload_missing_tx_cksum_ipv4.load(Ordering::Relaxed), "tx_cksum_ipv4"),
        (e.offload_missing_tx_cksum_tcp.load(Ordering::Relaxed), "tx_cksum_tcp"),
        (e.offload_missing_tx_cksum_udp.load(Ordering::Relaxed), "tx_cksum_udp"),
    ] {
        if v != 0 {
            return Err(format!("offload_missing_{name}={v} != 0"));
        }
    }
    Ok(())
}

/// Assert every observed `rx_hw_ts_ns` value is literally 0. Called
/// post-run against the collected sample. On ENA the dynfield is not
/// registered, so `deliver_readable` threads 0 through to the event;
/// a non-zero observation means either the driver started advertising
/// (unexpected) or a bug in the engine's RX timestamp path.
pub fn assert_all_events_rx_hw_ts_ns_zero(events_sample: &[u64]) -> Result<(), String> {
    if let Some(&nonzero) = events_sample.iter().find(|&&v| v != 0) {
        return Err(format!(
            "rx_hw_ts_ns expected 0 on ENA; observed {nonzero} among {} samples",
            events_sample.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expectations_default_is_ena_profile() {
        let d = HwTask18Expectations::default();
        assert!(d.expect_mbuf_fast_free_missing);
        assert!(d.expect_rss_hash_missing);
        assert!(d.expect_rx_timestamp_missing);
        assert!(d.expect_all_cksum_advertised);
        assert!(!d.expect_llq_missing);
        assert!(d.expect_rx_drop_cksum_bad_zero);
        assert!(d.expect_all_rx_hw_ts_ns_zero);
    }

    #[test]
    fn check_missing_expected_zero_observed_zero_ok() {
        assert!(check_missing(0, false, "x").is_ok());
    }

    #[test]
    fn check_missing_expected_nonzero_observed_nonzero_ok() {
        assert!(check_missing(1, true, "x").is_ok());
        assert!(check_missing(42, true, "x").is_ok());
    }

    #[test]
    fn check_missing_expected_zero_observed_nonzero_errors() {
        let err = check_missing(5, false, "offload_missing_llq").unwrap_err();
        assert!(err.contains("offload_missing_llq"));
        assert!(err.contains("expected_missing=false"));
        assert!(err.contains("observed_missing=true"));
        assert!(err.contains("raw=5"));
    }

    #[test]
    fn check_missing_expected_nonzero_observed_zero_errors() {
        let err = check_missing(0, true, "offload_missing_rss_hash").unwrap_err();
        assert!(err.contains("offload_missing_rss_hash"));
        assert!(err.contains("expected_missing=true"));
        assert!(err.contains("observed_missing=false"));
    }

    #[test]
    fn all_events_rx_hw_ts_ns_zero_passes_on_empty() {
        assert!(assert_all_events_rx_hw_ts_ns_zero(&[]).is_ok());
    }

    #[test]
    fn all_events_rx_hw_ts_ns_zero_passes_on_all_zero() {
        assert!(assert_all_events_rx_hw_ts_ns_zero(&[0, 0, 0, 0]).is_ok());
    }

    #[test]
    fn all_events_rx_hw_ts_ns_zero_errors_on_any_nonzero() {
        let err = assert_all_events_rx_hw_ts_ns_zero(&[0, 0, 42, 0]).unwrap_err();
        assert!(err.contains("42"));
        assert!(err.contains("rx_hw_ts_ns"));
    }

    #[test]
    fn all_events_rx_hw_ts_ns_error_reports_sample_size() {
        // An all-zero slice still passes regardless of size.
        assert!(assert_all_events_rx_hw_ts_ns_zero(&[0u64; 99]).is_ok());
        // With one contaminated entry at index 100, the error message
        // must report the 101-element total sample count so a bench
        // operator can tell apart "drifted once" from "drifted pervasively".
        let mut samples: Vec<u64> = vec![0; 100];
        samples.push(7);
        let err = assert_all_events_rx_hw_ts_ns_zero(&samples).unwrap_err();
        assert!(err.contains("101"));
    }

    // assert_hw_task_18_post_run operates on a `Counters`, which holds
    // AtomicU64s. We can build a default Counters (all zeros) and then
    // manually bump the three counters that ENA steady-state requires.

    #[test]
    fn post_run_passes_on_ena_steady_state() {
        let counters = Counters::new();
        // Bump the three one-shot counters that ENA doesn't advertise.
        counters
            .eth
            .offload_missing_mbuf_fast_free
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rss_hash
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rx_timestamp
            .fetch_add(1, Ordering::Relaxed);
        let exp = HwTask18Expectations::default();
        assert!(assert_hw_task_18_post_run(&counters, &exp).is_ok());
    }

    #[test]
    fn post_run_errors_when_expected_missing_is_missing_but_was_not() {
        let counters = Counters::new();
        // ENA profile expects mbuf_fast_free_missing = true, but we did
        // not bump it.
        counters
            .eth
            .offload_missing_rss_hash
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rx_timestamp
            .fetch_add(1, Ordering::Relaxed);
        let err = assert_hw_task_18_post_run(&counters, &HwTask18Expectations::default())
            .unwrap_err();
        assert!(err.contains("offload_missing_mbuf_fast_free"));
    }

    #[test]
    fn post_run_errors_on_unexpected_cksum_missing() {
        let counters = Counters::new();
        // Start from ENA steady state...
        counters
            .eth
            .offload_missing_mbuf_fast_free
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rss_hash
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rx_timestamp
            .fetch_add(1, Ordering::Relaxed);
        // ...then regress on one cksum offload.
        counters
            .eth
            .offload_missing_rx_cksum_tcp
            .fetch_add(1, Ordering::Relaxed);
        let err = assert_hw_task_18_post_run(&counters, &HwTask18Expectations::default())
            .unwrap_err();
        assert!(err.contains("rx_cksum_tcp"));
    }

    #[test]
    fn post_run_errors_on_nonzero_rx_drop_cksum_bad() {
        let counters = Counters::new();
        counters
            .eth
            .offload_missing_mbuf_fast_free
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rss_hash
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rx_timestamp
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .rx_drop_cksum_bad
            .fetch_add(3, Ordering::Relaxed);
        let err = assert_hw_task_18_post_run(&counters, &HwTask18Expectations::default())
            .unwrap_err();
        assert!(err.contains("rx_drop_cksum_bad"));
    }

    #[test]
    fn post_run_errors_on_llq_missing_when_expected_zero() {
        let counters = Counters::new();
        counters
            .eth
            .offload_missing_mbuf_fast_free
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rss_hash
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_rx_timestamp
            .fetch_add(1, Ordering::Relaxed);
        counters
            .eth
            .offload_missing_llq
            .fetch_add(1, Ordering::Relaxed);
        let err = assert_hw_task_18_post_run(&counters, &HwTask18Expectations::default())
            .unwrap_err();
        assert!(err.contains("offload_missing_llq"));
    }
}
