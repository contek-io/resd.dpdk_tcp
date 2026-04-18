//! RFC 6528 §3 ISS generator — SipHash-of-4-tuple + secret + boot_nonce,
//! offset by a monotonic clock so reconnects to the same 4-tuple within
//! MSL yield monotonically-increasing ISS.
//!
//! A3 ships a skeleton using `std::collections::hash_map::DefaultHasher`
//! (SipHash-1-3) for the keyed hash. A5 will finalize per spec §6.5:
//!   - explicit SipHash-2-4 implementation (not from std)
//!   - `boot_nonce` from `/proc/sys/kernel/random/boot_id`
//!   - 4µs-tick monotonic clock (A3 uses 1µs)
//! The call signature `IssGen::next(&FourTuple)` stays the same.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::clock;
use crate::flow_table::FourTuple;

pub struct IssGen {
    /// 128-bit per-process random secret. Seeded once per engine from
    /// the best-effort entropy source (clock-derived in A3 skeleton;
    /// `getrandom` in A5 once we audit the extra dep).
    secret: [u64; 2],
}

impl IssGen {
    /// Create a new generator with a per-engine random secret. The
    /// argument is used only to seed reproducibility in tests; production
    /// code passes `0` and we derive the secret from the TSC.
    pub fn new(test_seed: u64) -> Self {
        let tsc = clock::now_ns();
        let secret = [
            tsc.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(test_seed),
            tsc.wrapping_mul(0xBF58_476D_1CE4_E5B9)
                .wrapping_add(test_seed)
                .wrapping_add(0x6A09_E667_F3BC_C908),
        ];
        Self { secret }
    }

    /// Compute ISS for `tuple`. Peer cannot predict unless they know
    /// our `secret`; within the same 4-tuple and process, consecutive
    /// calls monotonically increase because the µs clock is added last.
    pub fn next(&self, tuple: &FourTuple) -> u32 {
        let mut h = DefaultHasher::new();
        self.secret.hash(&mut h);
        tuple.hash(&mut h);
        let hash_low32 = h.finish() as u32;
        // A3: use 1µs clock low 32 bits (A5 spec calls for 4µs ticks).
        let clock_us = (clock::now_ns() / 1_000) as u32;
        hash_low32.wrapping_add(clock_us)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(peer_port: u16) -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port,
        }
    }

    #[test]
    fn two_engines_produce_different_iss_for_same_tuple() {
        let g1 = IssGen::new(1);
        let g2 = IssGen::new(2);
        // Not strictly required by RFC, but sanity: with two different
        // secrets on the same tuple the ISS should essentially never collide.
        let t = tuple(5000);
        // Poll a few times to let the clocks diverge; even the hash alone
        // should differ because the secret is different.
        assert_ne!(g1.next(&t), g2.next(&t));
    }

    #[test]
    fn sequential_calls_monotonic_for_same_tuple() {
        let g = IssGen::new(42);
        let t = tuple(5000);
        let a = g.next(&t);
        // Spin a few ns so the µs clock advances at least once.
        for _ in 0..10_000 {
            std::hint::spin_loop();
        }
        let b = g.next(&t);
        // Monotonic in the wrap-space sense (b >= a for small deltas).
        let delta = b.wrapping_sub(a);
        assert!(delta < 1_000_000, "delta too large: {delta}"); // sanity; same µs-ish.
    }

    #[test]
    fn different_tuples_give_different_iss() {
        let g = IssGen::new(42);
        let a = g.next(&tuple(5000));
        let b = g.next(&tuple(5001));
        assert_ne!(a, b);
    }
}
