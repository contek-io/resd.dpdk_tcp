//! Decision rule + sanity invariant from spec §9.
//!
//! An offload "shows signal" iff `delta_p99 > 3 × noise_floor`, where
//! - `delta_p99 = p99_baseline − p99_with_offload` (smaller-is-better:
//!   the offload *reduces* hot-path cost, so a positive delta is the
//!   win direction).
//! - `noise_floor = p99 of two back-to-back baseline runs` — the
//!   smallest difference we can distinguish from natural p99 drift
//!   across identical runs.
//!
//! The 3× multiplier is the spec's "meaningfully above noise" gate —
//! anything at or below that is treated as a non-signal and the offload
//! loses its default-on justification unless a correctness case keeps
//! it (e.g. `hw-offload-mbuf-fast-free` stays on for defense in depth).
//!
//! The sanity invariant `p99(full) ≤ best p99 of any single-offload
//! config` catches composition regressions — if turning on *all* hw-*
//! features together is worse than the best single-feature run, we
//! have contention / false-sharing to investigate before A10 can sign
//! off. The evaluator returns a `Result` so the main driver can print
//! a clear diagnostic and flag the report rather than silently
//! proceeding.
//!
//! Both functions are pure — no I/O, no globals — which is why the
//! unit tests in `tests/decision_rule.rs` can exercise them without
//! DPDK, without a peer, without anything.

/// Signal classification for a single (offload-on vs. baseline) A/B
/// slot. See module-level comment for the threshold.
///
/// No `Ambiguous` / `Noise` variant: the spec intentionally collapses
/// every "below threshold" reading to `NoSignal` so a reviewer looking
/// at the report never has to interpret a third category. An offload
/// with `NoSignal` AND no documented correctness justification → gets
/// removed from the default feature set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// `delta_p99 > 3 × noise_floor` — the offload measurably helps.
    Signal,
    /// `delta_p99 ≤ 3 × noise_floor` — no measurable benefit above
    /// the noise floor. Unless kept for correctness, default → OFF.
    NoSignal,
}

/// Parameters for the decision rule.
///
/// `noise_floor_ns` is the p99 of two back-to-back baseline runs —
/// i.e. the empirical "how much does p99 move between two identical
/// runs". The main driver computes it once at the top of the matrix
/// run and passes it to every `classify` call.
///
/// Struct-form rather than a bare f64 so a future multiplier / window
/// tweak lands in one place, and so test call sites read clearly
/// (`DecisionRule { noise_floor_ns: 5.0 }` vs. a bare 5.0).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecisionRule {
    /// p99 spread of two back-to-back baseline runs, in nanoseconds.
    pub noise_floor_ns: f64,
}

/// Classify a single (baseline, with-offload) p99 pair under `rule`.
///
/// The spec writes the rule over the *delta* rather than the ratio on
/// purpose — ratios compress at high p99 and expand at low p99, which
/// would let a 5-ns cost on a 1000-ns baseline hide behind the noise
/// floor even though a 5-ns cost on the hot path is exactly what we
/// care about.
///
/// # Sign convention
///
/// `delta = baseline − with_offload`. Positive = the offload *reduces*
/// cost (win direction); negative = the offload *increases* cost
/// (regression). The `> 3 × noise_floor` test deliberately uses
/// signed comparison so a regression reads as `NoSignal` — the
/// reviewer sees the negative `delta_p99` in the report and can make
/// the "remove" / "correctness-justified" call explicitly.
pub fn classify(
    p99_baseline_ns: f64,
    p99_with_offload_ns: f64,
    rule: &DecisionRule,
) -> Outcome {
    let delta = p99_baseline_ns - p99_with_offload_ns;
    if delta > 3.0 * rule.noise_floor_ns {
        Outcome::Signal
    } else {
        Outcome::NoSignal
    }
}

/// Enforce the §9 sanity invariant: the full-offload configuration's
/// p99 must be no worse than the best individual single-offload
/// configuration's p99.
///
/// Rationale: offloads are supposed to compose. If `full` > any
/// single-offload p99, turning on more features made things worse —
/// typical causes are false-sharing on a struct that grew hot writes
/// under `hw-*` enablement, or a latent contention path that only one
/// offload worked around by accident. The driver fails loudly and the
/// reviewer investigates before A10 signs off.
///
/// Tie is OK (`full == best_individual`): a compose-to-equal result
/// still says the features compose.
pub fn check_sanity_invariant(
    full_p99_ns: f64,
    best_individual_p99_ns: f64,
) -> Result<(), String> {
    if full_p99_ns <= best_individual_p99_ns {
        Ok(())
    } else {
        Err(format!(
            "sanity invariant violated: full p99 {full_p99_ns} > \
             best individual p99 {best_individual_p99_ns} \
             (offloads did not compose; investigate contention / false-sharing)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_when_delta_large() {
        // baseline 100, with_offload 80 → delta 20; 3×noise = 15; 20 > 15 → Signal.
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        assert_eq!(classify(100.0, 80.0, &rule), Outcome::Signal);
    }

    #[test]
    fn no_signal_when_delta_small() {
        // baseline 100, with_offload 90 → delta 10; 3×noise = 15; 10 < 15 → NoSignal.
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        assert_eq!(classify(100.0, 90.0, &rule), Outcome::NoSignal);
    }

    #[test]
    fn no_signal_at_exact_threshold_boundary() {
        // Boundary: delta == 3×noise → NoSignal per `> 3×noise` rule.
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        // delta 15, threshold 15 → NOT strictly greater → NoSignal.
        assert_eq!(classify(100.0, 85.0, &rule), Outcome::NoSignal);
    }

    #[test]
    fn regression_reads_as_no_signal() {
        // Offload made things worse: baseline 100, with_offload 110 →
        // delta = −10. Negative is nowhere near `> 3×noise = 15`,
        // so the classifier reports NoSignal. The report surface
        // shows the signed delta so a reviewer sees the regression.
        let rule = DecisionRule { noise_floor_ns: 5.0 };
        assert_eq!(classify(100.0, 110.0, &rule), Outcome::NoSignal);
    }

    #[test]
    fn sanity_invariant_full_le_best_individual_ok() {
        // full 90 <= best_individual 92 → ok.
        assert!(check_sanity_invariant(90.0, 92.0).is_ok());
    }

    #[test]
    fn sanity_invariant_equality_ok() {
        // Tie case — "compose to exactly equal" is still a valid
        // compose. Ok.
        assert!(check_sanity_invariant(92.0, 92.0).is_ok());
    }

    #[test]
    fn sanity_invariant_violation_errors() {
        // full 94 > best_individual 92 → violation.
        let err = check_sanity_invariant(94.0, 92.0).unwrap_err();
        assert!(err.contains("full p99 94"), "err should mention full p99: {err}");
        assert!(err.contains("92"), "err should mention best individual p99: {err}");
    }
}
