//! Percentile + confidence-interval helpers. Used by every bench summariser.
//!
//! Not the final bootstrap CI the plan eventually wants: we use a parametric
//! 95% CI (`mean ± 1.96 * stddev / sqrt(n)`) here because every bench in
//! phase A10 samples n >= 10_000, where the parametric approximation is
//! within well under 1% of a bootstrap-resampled CI and avoids the
//! per-row resampling cost. If a test case lands with small-n where this
//! matters, a downstream crate can override this module.

use std::cmp::Ordering;

/// Nearest-rank percentile on an already-sorted ascending slice. `k` is in
/// `[0.0, 1.0]`; caller is responsible for feeding a sorted slice — avoids a
/// redundant sort on hot paths where the caller already has sorted data.
///
/// Panics on empty input (callers never pass empty slices in the summariser).
pub fn percentile_sorted(sorted: &[f64], k: f64) -> f64 {
    assert!(!sorted.is_empty(), "empty sample");
    assert!((0.0..=1.0).contains(&k), "k={k} out of [0,1]");
    let n = sorted.len();
    let rank = (k * (n - 1) as f64).round() as usize;
    sorted[rank.min(n - 1)]
}

/// Aggregated summary over a sample set. Mirrors the 7 variants of
/// `MetricAggregation` one-for-one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub p50: f64,
    pub p99: f64,
    pub p999: f64,
    pub mean: f64,
    pub stddev: f64,
    pub ci95_lower: f64,
    pub ci95_upper: f64,
}

/// Compute the seven-way summary over `samples`. Sorts internally — does not
/// mutate the caller's slice. Uses population variance (divisor = n) because
/// every bench in A10 has n well above any meaningful Bessel correction.
///
/// Panics on empty input.
pub fn summarize(samples: &[f64]) -> Summary {
    assert!(!samples.is_empty(), "summarize: empty sample");
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let n = sorted.len() as f64;
    let mean = sorted.iter().sum::<f64>() / n;
    let variance = sorted.iter().map(|v| (*v - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();
    // Parametric 95% CI. At n >= 10k the 1.96 z-value is indistinguishable
    // from the t-critical value for practical purposes.
    let se = stddev / n.sqrt();
    Summary {
        p50: percentile_sorted(&sorted, 0.50),
        p99: percentile_sorted(&sorted, 0.99),
        p999: percentile_sorted(&sorted, 0.999),
        mean,
        stddev,
        ci95_lower: mean - 1.96 * se,
        ci95_upper: mean + 1.96 * se,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_simple() {
        let s: Vec<f64> = (1..=1000).map(|i| i as f64).collect();
        let sm = summarize(&s);
        // p50 ≈ 500, p99 ≈ 990, p999 ≈ 999
        assert!((sm.p50 - 500.0).abs() < 5.0, "p50 = {}", sm.p50);
        assert!((sm.p99 - 990.0).abs() < 5.0, "p99 = {}", sm.p99);
        assert!((sm.p999 - 999.0).abs() < 5.0, "p999 = {}", sm.p999);
        // mean of 1..=1000 = 500.5
        assert!((sm.mean - 500.5).abs() < 1e-9, "mean = {}", sm.mean);
        // CI must bracket mean
        assert!(sm.ci95_lower <= sm.mean && sm.mean <= sm.ci95_upper);
    }

    #[test]
    fn percentile_extremes() {
        let s: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        // k=0 → first element, k=1 → last element.
        assert_eq!(percentile_sorted(&s, 0.0), 1.0);
        assert_eq!(percentile_sorted(&s, 1.0), 100.0);
    }

    #[test]
    fn single_sample() {
        let s = [42.0];
        let sm = summarize(&s);
        assert_eq!(sm.p50, 42.0);
        assert_eq!(sm.mean, 42.0);
        assert_eq!(sm.stddev, 0.0);
        assert_eq!(sm.ci95_lower, 42.0);
        assert_eq!(sm.ci95_upper, 42.0);
    }
}
