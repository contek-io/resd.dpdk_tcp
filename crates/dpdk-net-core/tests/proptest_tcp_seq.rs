//! Properties of the wrap-safe TCP seq comparator (RFC 9293 §3.4).
//! Comparison is modulo 2^32 with the 2^31 asymmetric-window rule.

use dpdk_net_core::tcp_seq::{in_window, seq_le, seq_lt};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Reflexivity of seq_le: a <= a always.
    #[test]
    fn seq_le_reflexive(a: u32) {
        prop_assert!(seq_le(a, a));
    }

    /// Strict irreflexivity: a < a never.
    #[test]
    fn seq_lt_irreflexive(a: u32) {
        prop_assert!(!seq_lt(a, a));
    }

    /// Consistency: a < b implies a <= b.
    #[test]
    fn lt_implies_le(a: u32, b: u32) {
        if seq_lt(a, b) {
            prop_assert!(seq_le(a, b));
        }
    }

    /// Asymmetry: a < b and b < a cannot both hold.
    /// Excludes the 2^31 antipode where the RFC 1982 / RFC 9293 §3.4
    /// wrap-safe comparator is undefined (both diffs reinterpret to i32::MIN).
    #[test]
    fn lt_asymmetric(a: u32, b: u32) {
        if a.wrapping_sub(b) != 0x8000_0000 {
            prop_assert!(!(seq_lt(a, b) && seq_lt(b, a)));
        }
    }

    /// in_window boundary: seq in [start, start+len) mod 2^32.
    /// `len` is bounded by 2^31 — the RFC 9293 §3.4 asymmetric window limit.
    #[test]
    fn in_window_boundary(start: u32, len in 1u32..=0x8000_0000_u32) {
        prop_assert!(in_window(start, start, len));
        prop_assert!(in_window(start, start.wrapping_add(len - 1), len));
        prop_assert!(!in_window(start, start.wrapping_add(len), len));
    }
}
