//! RFC 8985 §7 Tail Loss Probe.
//!
//! Schedules a probe at `PTO = max(2·SRTT, min_rto_us)` past the last TX.
//! On fire: probes via new data (if any) or retransmits the last in-flight
//! segment, soliciting a SACK that might reveal a tail loss not yet
//! discoverable via RACK's reordering window.

/// Worst-case delayed-ACK timer (µs). RFC 8985 §7.2 uses `WCDelAckT` as the
/// lower bound of the FlightSize==1 penalty (max(WCDelAckT, SRTT/4)) so a
/// delayed-ACK receiver can't silently absorb the sole in-flight segment's
/// ACK beyond the probe deadline. 200ms matches the RFC default.
pub const WCDELACK_US: u32 = 200_000;

/// Default SRTT multiplier (× 100) for TLP PTO when the caller
/// zero-inits `dpdk_net_connect_opts_t`. 2.0× matches RFC 8985 §7.2.
pub const DEFAULT_MULTIPLIER_X100: u16 = 200;

/// Default maximum consecutive TLP probes. 1 matches RFC 8985 §7
/// (single probe before falling back to RTO).
pub const DEFAULT_MAX_CONSECUTIVE_PROBES: u8 = 1;

/// Tunable PTO pieces extracted from the A5 formula (`max(2·SRTT, min_rto)`).
///
/// `a5_compat(min_rto)` and `default()` preserve A5 behavior exactly so pre-A5.5
/// tests / call-sites keep working. A5.5 call-sites can override any field:
/// - `floor_us`: PTO floor (A5.5 can tune below `tcp_min_rto_us`).
/// - `multiplier_x100`: SRTT multiplier × 100 (integer; 200 = 2.0×, 100 = 1.0×).
/// - `skip_flight_size_gate`: when `true`, suppresses the RFC 8985 §7.2
///   FlightSize==1 `+max(WCDelAckT, SRTT/4)` penalty (trading-latency opt-out).
#[derive(Debug, Clone, Copy)]
pub struct TlpConfig {
    pub floor_us: u32,
    pub multiplier_x100: u16,
    pub skip_flight_size_gate: bool,
}

impl TlpConfig {
    pub fn a5_compat(default_floor_us: u32) -> Self {
        Self {
            floor_us: default_floor_us,
            multiplier_x100: 200,
            skip_flight_size_gate: false,
        }
    }
}

impl Default for TlpConfig {
    fn default() -> Self {
        Self::a5_compat(5_000)
    }
}

/// Compute PTO (Probe Timeout) per RFC 8985 §7.2.
///
/// A5 was `max(2·SRTT, min_rto_us)`. A5.5 parametrizes the three pieces:
/// - Base = `srtt · cfg.multiplier_x100 / 100` (A5 = 2·srtt when 200).
/// - Penalty: when `FlightSize == 1` and the gate isn't opted-out, add
///   `max(WCDELACK_US, SRTT/4)` (RFC 8985 §7.2) so a delayed-ACK receiver
///   can't swallow the last segment's ACK past the probe deadline.
/// - Clamp at `cfg.floor_us` after the penalty.
///
/// If SRTT is unavailable (no RTT sample yet), PTO = `cfg.floor_us`.
pub fn pto_us(srtt_us: Option<u32>, cfg: &TlpConfig, flight_size: u32) -> u32 {
    let Some(srtt) = srtt_us else {
        return cfg.floor_us;
    };
    let base = ((srtt as u64) * (cfg.multiplier_x100 as u64) / 100) as u32;
    let with_penalty = if flight_size == 1 && !cfg.skip_flight_size_gate {
        base.saturating_add(std::cmp::max(WCDELACK_US, srtt / 4))
    } else {
        base
    };
    std::cmp::max(with_penalty, cfg.floor_us)
}

/// TLP probe selection per RFC 8985 §7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// New data is available in snd.pending — probe with it (MSS-sized).
    NewData,
    /// No new data — probe by retransmitting the last in-flight segment.
    LastSegmentRetransmit,
}

/// Select a probe per RFC 8985 §7.3. Returns None when there's nothing
/// to probe (no in-flight data).
pub fn select_probe(snd_pending_nonempty: bool, snd_retrans_nonempty: bool) -> Option<Probe> {
    if !snd_retrans_nonempty {
        return None;
    }
    if snd_pending_nonempty {
        Some(Probe::NewData)
    } else {
        Some(Probe::LastSegmentRetransmit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pto_uses_min_rto_when_no_srtt() {
        let cfg = TlpConfig::a5_compat(5_000);
        assert_eq!(pto_us(None, &cfg, 5), 5_000);
    }

    #[test]
    fn pto_is_2_srtt_when_srtt_present() {
        let cfg = TlpConfig::a5_compat(5_000);
        assert_eq!(pto_us(Some(100_000), &cfg, 5), 200_000);
    }

    #[test]
    fn pto_floors_at_min_rto() {
        let cfg = TlpConfig::a5_compat(5_000);
        assert_eq!(pto_us(Some(1_000), &cfg, 5), 5_000);
    }

    #[test]
    fn select_probe_new_data_when_pending_nonempty() {
        assert_eq!(select_probe(true, true), Some(Probe::NewData));
    }

    #[test]
    fn select_probe_last_seg_when_no_pending() {
        assert_eq!(
            select_probe(false, true),
            Some(Probe::LastSegmentRetransmit)
        );
    }

    #[test]
    fn select_probe_none_when_no_retrans() {
        assert!(select_probe(true, false).is_none());
        assert!(select_probe(false, false).is_none());
    }
}

#[cfg(test)]
mod a5_5_tests {
    use super::*;

    #[test]
    fn pto_default_matches_a5_formula_flight_size_ge_2() {
        let cfg = TlpConfig::default();
        assert_eq!(pto_us(Some(100_000), &cfg, 5), 200_000);
        assert_eq!(pto_us(Some(1_000), &cfg, 5), cfg.floor_us);
    }

    #[test]
    fn pto_flight_size_1_adds_max_wcdelack_or_rtt_over_4() {
        let cfg = TlpConfig {
            floor_us: 0,
            multiplier_x100: 200,
            skip_flight_size_gate: false,
        };
        assert_eq!(pto_us(Some(400), &cfg, 1), 200_800);
    }

    #[test]
    fn pto_skip_flight_size_gate_suppresses_penalty() {
        let cfg = TlpConfig {
            floor_us: 0,
            multiplier_x100: 200,
            skip_flight_size_gate: true,
        };
        assert_eq!(pto_us(Some(400), &cfg, 1), 800);
    }

    #[test]
    fn pto_configurable_multiplier_below_2x() {
        let cfg = TlpConfig {
            floor_us: 0,
            multiplier_x100: 100,
            skip_flight_size_gate: true,
        };
        assert_eq!(pto_us(Some(400), &cfg, 1), 400);
    }

    #[test]
    fn pto_configurable_floor_zero() {
        let cfg = TlpConfig {
            floor_us: 0,
            multiplier_x100: 200,
            skip_flight_size_gate: true,
        };
        assert_eq!(pto_us(Some(1), &cfg, 5), 2);
    }
}
