//! RFC 8985 §7 Tail Loss Probe.
//!
//! Schedules a probe at `PTO = max(2·SRTT, min_rto_us)` past the last TX.
//! On fire: probes via new data (if any) or retransmits the last in-flight
//! segment, soliciting a SACK that might reveal a tail loss not yet
//! discoverable via RACK's reordering window.

/// Compute PTO (Probe Timeout) per RFC 8985 §7.2.
/// PTO = max(2·SRTT, min_rto_us). If SRTT is unavailable (no RTT sample
/// yet), PTO = min_rto_us.
pub fn pto_us(srtt_us: Option<u32>, min_rto_us: u32) -> u32 {
    match srtt_us {
        None => min_rto_us,
        Some(srtt) => srtt.saturating_mul(2).max(min_rto_us),
    }
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
        assert_eq!(pto_us(None, 5_000), 5_000);
    }

    #[test]
    fn pto_is_2_srtt_when_srtt_present() {
        assert_eq!(pto_us(Some(100_000), 5_000), 200_000);
    }

    #[test]
    fn pto_floors_at_min_rto() {
        assert_eq!(pto_us(Some(1_000), 5_000), 5_000);
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
