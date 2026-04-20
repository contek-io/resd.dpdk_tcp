//! RFC 6528 §3 ISS generator — SipHash-2-4 keyed on a 128-bit per-process
//! secret, with a 128-bit boot_nonce mixed into the message so per-boot ISS
//! never collides across restarts. Monotonic 4µs-tick clock added OUTSIDE
//! the hash so reconnects to the same 4-tuple within MSL yield monotonically
//! increasing ISS.
//!
//! Formula (spec §6.5):
//!     ISS = (monotonic_time_4µs_ticks_low_32)
//!         + siphash24(key=secret, msg=tuple ‖ boot_nonce).low_32

use std::fs;
use std::io::Read;

use crate::clock;
use crate::flow_table::FourTuple;
use crate::siphash24::siphash24;

pub struct IssGen {
    /// SipHash-2-4 key: 128 bits of per-process random.
    secret: [u8; 16],
    /// 128-bit boot-unique nonce (read from /proc/sys/kernel/random/boot_id
    /// or a per-engine random fallback).
    boot_nonce: [u8; 16],
}

impl IssGen {
    /// Create a new generator. Secret is derived from process entropy
    /// (first attempt: /dev/urandom; fallback: TSC-seeded degraded mode
    /// with a one-time warning log). Boot nonce is read from
    /// /proc/sys/kernel/random/boot_id; fallback: per-engine random.
    pub fn new() -> Self {
        let secret = read_process_secret();
        let boot_nonce = read_boot_id().unwrap_or_else(|| {
            eprintln!(
                "dpdk_net: /proc/sys/kernel/random/boot_id unreadable; \
                 ISS boot_nonce falls back to per-engine random (degraded mode)"
            );
            read_process_secret() // independent random
        });
        Self { secret, boot_nonce }
    }

    /// Test-only deterministic ctor so the test suite can pin the secret
    /// and boot_nonce for reproducible assertions.
    #[cfg(test)]
    pub fn new_deterministic_for_test(secret: [u8; 16], boot_nonce: [u8; 16]) -> Self {
        Self { secret, boot_nonce }
    }

    /// Compute ISS for `tuple`. Peer cannot predict unless they know
    /// our `secret`; within the same 4-tuple and process, consecutive
    /// calls monotonically increase because the 4µs-tick clock is added last.
    pub fn next(&self, tuple: &FourTuple) -> u32 {
        // Pack tuple ‖ boot_nonce into a contiguous message buffer (20+16 = 36 bytes).
        let mut msg = [0u8; 36];
        msg[0..4].copy_from_slice(&tuple.local_ip.to_be_bytes());
        msg[4..6].copy_from_slice(&tuple.local_port.to_be_bytes());
        msg[6..10].copy_from_slice(&tuple.peer_ip.to_be_bytes());
        msg[10..12].copy_from_slice(&tuple.peer_port.to_be_bytes());
        // 8 bytes of zero padding before boot_nonce to keep field alignment
        // obvious; does not affect cryptographic properties.
        msg[20..36].copy_from_slice(&self.boot_nonce);

        let hash_low32 = siphash24(&self.secret, &msg) as u32;
        // 4µs-tick monotonic clock — spec §6.5.
        let clock_4us = (clock::now_ns() / 4_000) as u32;
        hash_low32.wrapping_add(clock_4us)
    }
}

impl Default for IssGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Read `/proc/sys/kernel/random/boot_id`. The file contains a UUID-style
/// 128-bit value (e.g. `550e8400-e29b-41d4-a716-446655440000\n`); we strip
/// dashes, hex-decode, return 16 bytes. `None` on any I/O or parse failure.
pub(crate) fn read_boot_id() -> Option<[u8; 16]> {
    let contents = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let trimmed = contents.trim();
    let hex_only: String = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_only.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex_only.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Read 16 bytes of process-random. Preferred path: /dev/urandom. Fallback:
/// TSC-seeded mixing (degraded but still unpredictable-to-peer for Stage 1).
/// Intentionally inline rather than a new crate dep.
///
/// `/dev/urandom` is a character device that returns unbounded data, so we
/// must use `read_exact` on a fixed-size buffer — `fs::read` would try to
/// read the whole "file" and exhaust memory.
fn read_process_secret() -> [u8; 16] {
    // Try /dev/urandom first (Linux path; no external dep).
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        let mut out = [0u8; 16];
        if f.read_exact(&mut out).is_ok() {
            return out;
        }
    }
    // Degraded fallback — mix multiple TSC reads at different offsets.
    let t1 = clock::now_ns();
    let t2 = t1.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let t3 = t1.wrapping_add(0xBF58_476D_1CE4_E5B9);
    let t4 = t1.wrapping_mul(0x6A09_E667_F3BC_C908);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&t2.to_le_bytes());
    out[8..16].copy_from_slice(&(t3 ^ t4).to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn tuple(peer_port: u16) -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port,
        }
    }

    #[cfg_attr(miri, ignore = "IssGen::next calls clock::now_ns (rdtsc inline asm)")]
    #[test]
    fn two_engines_produce_different_iss_for_same_tuple() {
        let g1 = IssGen::new();
        let g2 = IssGen::new();
        let t = tuple(5000);
        // Different process-random secrets → different hash components.
        // (Probabilistic: essentially never collides.)
        assert_ne!(g1.next(&t), g2.next(&t));
    }

    #[cfg_attr(miri, ignore = "IssGen::next calls clock::now_ns (rdtsc inline asm)")]
    #[test]
    fn sequential_calls_monotonic_for_same_tuple() {
        let g = IssGen::new_deterministic_for_test([0; 16], [0; 16]);
        let t = tuple(5000);
        let a = g.next(&t);
        for _ in 0..10_000 {
            std::hint::spin_loop();
        }
        let b = g.next(&t);
        let delta = b.wrapping_sub(a);
        assert!(delta < 1_000_000, "delta too large: {delta}");
    }

    #[cfg_attr(miri, ignore = "IssGen::next calls clock::now_ns (rdtsc inline asm)")]
    #[test]
    fn different_tuples_give_different_iss() {
        let g = IssGen::new_deterministic_for_test([0; 16], [0; 16]);
        let a = g.next(&tuple(5000));
        let b = g.next(&tuple(5001));
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod tests_a5 {
    use super::*;

    #[cfg_attr(miri, ignore = "IssGen::next calls clock::now_ns (rdtsc inline asm)")]
    #[test]
    fn a5_uses_4us_clock_ticks_for_monotonic_component() {
        // The spec §6.5 clock is 4µs ticks. Verify that two calls separated by
        // a small sleep produce a delta consistent with 4µs quantization: the
        // hash component is identical (same tuple, same secret, same boot_nonce),
        // so the ISS delta is purely the clock delta divided by 4µs.
        let g = IssGen::new_deterministic_for_test([0x11; 16], [0x22; 16]);
        let t = super::tests::tuple(5000);
        let a = g.next(&t);
        // Spin ~8µs of real time to cross at least one 4µs boundary.
        let target_ns = crate::clock::now_ns() + 8_000;
        while crate::clock::now_ns() < target_ns {
            std::hint::spin_loop();
        }
        let b = g.next(&t);
        // Monotonic; delta should be small positive (u32 wrap arithmetic).
        let delta = b.wrapping_sub(a);
        assert!(delta >= 1, "delta should reflect at least one 4µs tick");
        assert!(delta < 100_000, "delta should not be huge: {delta}");
    }

    #[cfg_attr(miri, ignore = "IssGen::next calls clock::now_ns (rdtsc inline asm)")]
    #[test]
    fn a5_different_boot_nonces_produce_different_iss_for_same_tuple() {
        let g1 = IssGen::new_deterministic_for_test([0xaa; 16], [0x01; 16]);
        let g2 = IssGen::new_deterministic_for_test([0xaa; 16], [0x02; 16]);
        let t = super::tests::tuple(5000);
        // Same tuple, same secret, different boot_nonce → different hash
        // component. Clock component is shared so the difference reflects hash.
        assert_ne!(g1.next(&t), g2.next(&t));
    }

    #[cfg_attr(miri, ignore = "IssGen::next calls clock::now_ns (rdtsc inline asm)")]
    #[test]
    fn a5_boot_id_readable_path_produces_nonzero_boot_nonce() {
        // When /proc/sys/kernel/random/boot_id exists (typical Linux host),
        // the nonce reader returns Some(nonce) with nonce != 0.
        if let Some(nonce) = read_boot_id() {
            assert_ne!(nonce, [0u8; 16], "boot_id must not be all zeros");
        }
        // On non-Linux / CI without /proc, `None` is an acceptable outcome;
        // IssGen::new falls back to a per-engine random and logs once.
    }
}
