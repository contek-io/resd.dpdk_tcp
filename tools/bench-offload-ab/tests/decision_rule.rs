//! Integration tests for the spec §9 decision rule + sanity invariant.
//!
//! Mirrors the test cases listed in the task brief:
//!
//! - `signal_when_delta_exceeds_three_noise` — Signal verdict when
//!   `delta_p99 > 3 × noise_floor`.
//! - `no_signal_when_delta_under_three_noise` — NoSignal when
//!   `delta_p99 ≤ 3 × noise_floor`.
//! - `sanity_invariant_full_le_best_individual` — violation case
//!   (full > best) → `Err`.
//! - `sanity_invariant_full_le_best_individual_ok` — ok case
//!   (full < best) → `Ok`.
//!
//! These live as integration tests (against the `bench_offload_ab`
//! library) rather than unit tests so any future refactor that
//! privates `classify` / `check_sanity_invariant` breaks the build
//! loudly rather than silently hiding the contract.

use bench_offload_ab::decision::{
    check_observability_invariant, check_sanity_invariant, classify, DecisionRule, Outcome,
};

#[test]
fn signal_when_delta_exceeds_three_noise() {
    // baseline=100, with=80 → delta=20; 3*noise=15; 20 > 15 → Signal.
    let rule = DecisionRule { noise_floor_ns: 5.0 };
    assert_eq!(classify(100.0, 80.0, &rule), Outcome::Signal);
}

#[test]
fn no_signal_when_delta_under_three_noise() {
    // baseline=100, with=90 → delta=10; 3*noise=15; 10 < 15 → NoSignal.
    let rule = DecisionRule { noise_floor_ns: 5.0 };
    assert_eq!(classify(100.0, 90.0, &rule), Outcome::NoSignal);
}

#[test]
fn sanity_invariant_full_le_best_individual() {
    // full=110, best_individual=92 → violation (full > best by 19.6%
    // — well outside the 5% COMPOSE_NOISE_FRAC band).
    let result = check_sanity_invariant(110.0, 92.0);
    assert!(
        result.is_err(),
        "full=110 vs best individual=92 (19.6% over) must trigger violation"
    );
    let msg = result.unwrap_err();
    assert!(msg.contains("110"), "err should mention full p99: {msg}");
    assert!(msg.contains("92"), "err should mention best individual: {msg}");
}

#[test]
fn sanity_invariant_full_le_best_individual_ok() {
    // full=90, best_individual=92 → ok (full < best).
    let result = check_sanity_invariant(90.0, 92.0);
    assert!(result.is_ok(), "full=90 <= best individual=92 → ok");
}

#[test]
fn sanity_invariant_within_noise_band_does_not_flag() {
    // 1.2% overshoot (37 880 ns / 37 440 ns) — the exact 2026-05-03
    // bench-pair shape on c6a.12xlarge. Inside the 5% noise band → ok.
    let result = check_sanity_invariant(37_880.0, 37_440.0);
    assert!(
        result.is_ok(),
        "1.2% overshoot must be inside the 5% noise band: {:?}",
        result
    );
}

#[test]
fn observability_invariant_floor_violation() {
    // obs-none=78, poll-saturation-only=74 → violation (other < floor).
    // Observability supposedly-free but ran faster than obs-none — flag.
    let result = check_observability_invariant(74.0, "poll-saturation-only", 78.0);
    assert!(
        result.is_err(),
        "other p99 74 < obs-none p99 78 must trigger violation"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("poll-saturation-only"),
        "err should name offending config: {msg}"
    );
    assert!(msg.contains("74"), "err should mention other p99: {msg}");
    assert!(msg.contains("78"), "err should mention obs-none p99: {msg}");
}

#[test]
fn observability_invariant_floor_ok() {
    // obs-none=78, byte-counters-only=82 → ok (other >= floor).
    let result = check_observability_invariant(82.0, "byte-counters-only", 78.0);
    assert!(result.is_ok(), "other p99 82 >= obs-none p99 78 → ok");
}
