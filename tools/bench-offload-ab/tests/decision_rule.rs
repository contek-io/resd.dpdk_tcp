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
    check_sanity_invariant, classify, DecisionRule, Outcome,
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
    // full=94, best_individual=92 → violation (full > best).
    let result = check_sanity_invariant(94.0, 92.0);
    assert!(
        result.is_err(),
        "full=94 > best individual=92 must trigger violation"
    );
    let msg = result.unwrap_err();
    assert!(msg.contains("94"), "err should mention full p99: {msg}");
    assert!(msg.contains("92"), "err should mention best individual: {msg}");
}

#[test]
fn sanity_invariant_full_le_best_individual_ok() {
    // full=90, best_individual=92 → ok (full < best).
    let result = check_sanity_invariant(90.0, 92.0);
    assert!(result.is_ok(), "full=90 <= best individual=92 → ok");
}
