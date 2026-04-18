//! RFC 6298 Jacobson/Karels RTT estimator.
//!
//! - RFC 6298 §2.2: on first sample R, SRTT=R, RTTVAR=R/2, RTO=SRTT+K·RTTVAR with K=4.
//! - RFC 6298 §2.3: on subsequent sample R, RTTVAR = (1-β)·RTTVAR + β·|SRTT-R|; SRTT = (1-α)·SRTT + α·R.
//! - α=1/8, β=1/4 (RFC 6298 §2.3 exact).
//! - RTO floor = min_rto_us (spec §6.4 default 5ms; configurable per engine).
//! - RTO ceiling = max_rto_us (spec §6.4 new row, default 1_000_000 = 1s).
//! - `apply_backoff`: RTO *= 2, capped at max_rto_us. Caller decides whether to call.
//! - Karn's algorithm (RFC 6298 §3): the caller must not feed a sample drawn
//!   from a retransmitted segment. `sample()` trusts the caller.

pub const DEFAULT_MIN_RTO_US: u32 = 5_000;
pub const DEFAULT_INITIAL_RTO_US: u32 = 5_000;
pub const DEFAULT_MAX_RTO_US: u32 = 1_000_000;

#[derive(Debug, Clone)]
pub struct RttEstimator {
    srtt_us: Option<u32>,
    rttvar_us: u32,
    rto_us: u32,
    min_rto_us: u32,
    max_rto_us: u32,
}

impl RttEstimator {
    pub fn new(min_rto_us: u32, initial_rto_us: u32, max_rto_us: u32) -> Self {
        debug_assert!(min_rto_us <= initial_rto_us);
        debug_assert!(initial_rto_us <= max_rto_us);
        Self {
            srtt_us: None,
            rttvar_us: 0,
            rto_us: initial_rto_us.max(min_rto_us),
            min_rto_us,
            max_rto_us,
        }
    }

    pub fn sample(&mut self, rtt_us: u32) {
        let rtt = rtt_us.max(1);
        match self.srtt_us {
            None => {
                self.srtt_us = Some(rtt);
                self.rttvar_us = rtt / 2;
            }
            Some(srtt) => {
                let delta = srtt.abs_diff(rtt);
                self.rttvar_us = (self.rttvar_us - (self.rttvar_us >> 2)).wrapping_add(delta >> 2);
                self.srtt_us = Some((srtt - (srtt >> 3)).wrapping_add(rtt >> 3));
            }
        }
        let srtt = self.srtt_us.unwrap();
        let rto = srtt.saturating_add(self.rttvar_us.saturating_mul(4));
        self.rto_us = rto.clamp(self.min_rto_us, self.max_rto_us);
    }

    pub fn apply_backoff(&mut self) {
        self.rto_us = self.rto_us.saturating_mul(2).min(self.max_rto_us);
    }

    pub fn rto_us(&self) -> u32 {
        self.rto_us
    }
    pub fn srtt_us(&self) -> Option<u32> {
        self.srtt_us
    }
    pub fn rttvar_us(&self) -> u32 {
        self.rttvar_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_rto_honors_floor() {
        let est = RttEstimator::new(5_000, 10_000, 1_000_000);
        assert_eq!(est.rto_us(), 10_000);
    }

    #[test]
    fn first_sample_rfc_22() {
        let mut est = RttEstimator::new(0, 5_000, 1_000_000);
        est.sample(100);
        assert_eq!(est.srtt_us(), Some(100));
        assert_eq!(est.rttvar_us(), 50);
        assert_eq!(est.rto_us(), 300);
    }

    #[test]
    fn second_sample_rfc_23() {
        let mut est = RttEstimator::new(0, 5_000, 1_000_000);
        est.sample(100);
        est.sample(200);
        assert_eq!(est.srtt_us(), Some(113));
        assert_eq!(est.rttvar_us(), 63);
        assert_eq!(est.rto_us(), 365);
    }

    #[test]
    fn rto_floored_at_min() {
        let mut est = RttEstimator::new(50_000, 50_000, 1_000_000);
        est.sample(100);
        assert!(est.rto_us() >= 50_000);
    }

    #[test]
    fn apply_backoff_doubles_up_to_max() {
        let mut est = RttEstimator::new(0, 100_000, 500_000);
        est.apply_backoff();
        assert_eq!(est.rto_us(), 200_000);
        est.apply_backoff();
        assert_eq!(est.rto_us(), 400_000);
        est.apply_backoff();
        assert_eq!(est.rto_us(), 500_000);
        est.apply_backoff();
        assert_eq!(est.rto_us(), 500_000);
    }

    #[test]
    fn fresh_sample_overwrites_backoff() {
        let mut est = RttEstimator::new(0, 10_000, 1_000_000);
        est.apply_backoff();
        est.apply_backoff();
        assert_eq!(est.rto_us(), 40_000);
        est.sample(100);
        assert_eq!(est.rto_us(), 300);
    }
}
