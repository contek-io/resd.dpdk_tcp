//! Attribution buckets for the end-to-end request-response RTT.
//!
//! Spec §6 decomposes one 128 B / 128 B round-trip into five
//! attribution buckets when NIC hardware receive-timestamps are
//! available (HW-TS mode), and into three collapsed buckets when they
//! are not (TSC-fallback mode).
//!
//! # HW-TS mode (5 buckets)
//!
//! Requires the peer NIC to populate `rx_hw_ts_ns` on the received
//! ACK/response mbuf via the `rte_dynfield_timestamp` dynamic field.
//! The sum of all five buckets equals the wall-clock RTT measured
//! from `rdtsc()` at `send_bytes` entry to `rdtsc()` at the Readable
//! event's caller observation, within ±50 ns (spec §6 sum-identity).
//!
//! - `user_send_to_tx_sched_ns` — application `send_bytes()` entry to
//!   the moment the engine pushes the outgoing frame onto the TX
//!   descriptor ring (pre-rte_eth_tx_burst).
//! - `tx_sched_to_nic_tx_wire_ns` — descriptor-ring push to the moment
//!   the NIC places the first bit on the wire. On mlx5/ice this can be
//!   read directly from the NIC's TX timestamp; on ENA (which does not
//!   populate TX-TS) this sums into `user_send_to_tx_sched_ns`.
//! - `nic_tx_wire_to_nic_rx_ns` — over-the-wire round-trip time, bit-
//!   on-wire at local NIC to bit-off-wire at local NIC. Includes peer
//!   echo-server processing.
//! - `nic_rx_to_enqueued_ns` — local NIC RX to the moment the engine
//!   delivers the Readable event (post-TCP-reassembly, post-
//!   `deliver_readable`).
//! - `enqueued_to_user_return_ns` — engine-side Readable emit to the
//!   application's observation of the event via `engine.events()`.
//!
//! # TSC-fallback mode (3 buckets)
//!
//! On ENA the NIC does NOT populate `rx_hw_ts_ns` — see parent spec
//! §10.5 (`offload_missing_rx_timestamp` bumped one-shot at bring-up;
//! every per-event `rx_hw_ts_ns == 0`). The wire + full-RX path is
//! merged into one `tx_sched_to_enqueued_ns` bucket derived from
//! `rdtsc()` deltas inside the engine's RX dispatch.
//!
//! - `user_send_to_tx_sched_ns` — same as HW-TS mode.
//! - `tx_sched_to_enqueued_ns` — collapsed wire + peer-echo + local-
//!   NIC-RX + engine reassembly.
//! - `enqueued_to_user_return_ns` — same as HW-TS mode.
//!
//! # Invariants
//!
//! - Every field is `u64` nanoseconds. TSC-derived deltas use the
//!   process-wide `tsc_epoch()` calibration (spec §7.5) so rollover +
//!   wrap semantics match `dpdk_net_core::clock::now_ns()`.
//! - `total_ns()` uses saturating addition. Attribution buckets are
//!   small (typically microseconds on a well-tuned host), so
//!   saturation fires only on programming errors; the explicit
//!   saturation keeps overflow from silently poisoning a run.
//! - Bucket-ordering is not implicit in the sum — the Readable event's
//!   `rx_hw_ts_ns` and the engine's `emitted_ts_ns` are produced by
//!   independent sources (NIC clock vs. host TSC) and can disagree
//!   under calibration drift. The caller composes the buckets from
//!   raw timestamps; `total_ns()` only arithmetic-sums.

/// Five-bucket attribution vector for the HW-TS mode. See the module-
/// level doc comment for the field semantics. All buckets are u64 ns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HwTsBuckets {
    pub user_send_to_tx_sched_ns: u64,
    pub tx_sched_to_nic_tx_wire_ns: u64,
    pub nic_tx_wire_to_nic_rx_ns: u64,
    pub nic_rx_to_enqueued_ns: u64,
    pub enqueued_to_user_return_ns: u64,
}

impl HwTsBuckets {
    /// Sum of all five buckets in ns. Saturating addition — see the
    /// module-level note on invariants.
    pub fn total_ns(&self) -> u64 {
        self.user_send_to_tx_sched_ns
            .saturating_add(self.tx_sched_to_nic_tx_wire_ns)
            .saturating_add(self.nic_tx_wire_to_nic_rx_ns)
            .saturating_add(self.nic_rx_to_enqueued_ns)
            .saturating_add(self.enqueued_to_user_return_ns)
    }
}

/// Three-bucket attribution vector for the TSC-fallback mode (used on
/// ENA where `rx_hw_ts_ns` is always 0). The middle bucket collapses
/// the over-the-wire + peer-echo + local-NIC-RX + engine-reassembly
/// segments into one measurable span, derived from host-TSC deltas.
/// All buckets are u64 ns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TscFallbackBuckets {
    pub user_send_to_tx_sched_ns: u64,
    pub tx_sched_to_enqueued_ns: u64,
    pub enqueued_to_user_return_ns: u64,
}

impl TscFallbackBuckets {
    /// Sum of all three buckets in ns. Saturating addition — see the
    /// module-level note on invariants.
    pub fn total_ns(&self) -> u64 {
        self.user_send_to_tx_sched_ns
            .saturating_add(self.tx_sched_to_enqueued_ns)
            .saturating_add(self.enqueued_to_user_return_ns)
    }
}

/// Discriminator for which attribution bucket set was used on a given
/// round-trip. `Hw` iff the Readable event carried a non-zero
/// `rx_hw_ts_ns`; `Tsc` otherwise. Exposed to the CSV emitter so a
/// downstream consumer can tell the two schemas apart without peeking
/// at values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributionMode {
    /// NIC hardware receive-timestamp observed — 5 buckets.
    Hw,
    /// NIC did not populate `rx_hw_ts_ns` — 3 buckets.
    Tsc,
}

impl AttributionMode {
    /// Select the mode based on the observed `rx_hw_ts_ns` on the
    /// Readable event. `0` → `Tsc` (ENA steady state); any non-zero
    /// value → `Hw` (mlx5 / ice / future-gen ENA).
    pub fn from_rx_hw_ts(rx_hw_ts_ns: u64) -> Self {
        if rx_hw_ts_ns == 0 {
            AttributionMode::Tsc
        } else {
            AttributionMode::Hw
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hw_buckets_total_sums_all_five() {
        let b = HwTsBuckets {
            user_send_to_tx_sched_ns: 100,
            tx_sched_to_nic_tx_wire_ns: 200,
            nic_tx_wire_to_nic_rx_ns: 10_000,
            nic_rx_to_enqueued_ns: 50,
            enqueued_to_user_return_ns: 80,
        };
        assert_eq!(b.total_ns(), 10_430);
    }

    #[test]
    fn tsc_buckets_total_sums_all_three() {
        let b = TscFallbackBuckets {
            user_send_to_tx_sched_ns: 100,
            tx_sched_to_enqueued_ns: 10_250,
            enqueued_to_user_return_ns: 80,
        };
        assert_eq!(b.total_ns(), 10_430);
    }

    #[test]
    fn hw_buckets_default_is_zero() {
        assert_eq!(HwTsBuckets::default().total_ns(), 0);
    }

    #[test]
    fn tsc_buckets_default_is_zero() {
        assert_eq!(TscFallbackBuckets::default().total_ns(), 0);
    }

    #[test]
    fn hw_buckets_saturate_on_overflow() {
        // If any caller programming error pushes a per-bucket u64 high,
        // total_ns must saturate at u64::MAX rather than silently wrap.
        let b = HwTsBuckets {
            user_send_to_tx_sched_ns: u64::MAX,
            tx_sched_to_nic_tx_wire_ns: 1,
            nic_tx_wire_to_nic_rx_ns: 0,
            nic_rx_to_enqueued_ns: 0,
            enqueued_to_user_return_ns: 0,
        };
        assert_eq!(b.total_ns(), u64::MAX);
    }

    #[test]
    fn attribution_mode_selects_on_rx_hw_ts_zero() {
        assert_eq!(AttributionMode::from_rx_hw_ts(0), AttributionMode::Tsc);
        assert_eq!(AttributionMode::from_rx_hw_ts(1), AttributionMode::Hw);
        assert_eq!(
            AttributionMode::from_rx_hw_ts(u64::MAX),
            AttributionMode::Hw
        );
    }
}
