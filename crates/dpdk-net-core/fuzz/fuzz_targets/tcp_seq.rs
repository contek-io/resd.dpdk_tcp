#![no_main]
use libfuzzer_sys::fuzz_target;
use dpdk_net_core::tcp_seq::{seq_le, seq_lt};

fuzz_target!(|data: &[u8]| {
    // Decode bytes into (a, b, _c) triples (12 bytes each); assert the
    // wrap-safe comparator's core invariants hold. Complements
    // proptest_tcp_seq.rs — libFuzzer drives deeper 2^32 coverage.
    for chunk in data.chunks_exact(12) {
        let a = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let b = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let _c = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);

        // Asymmetry
        // RFC 1982 / RFC 9293 §3.4: the wrap-safe comparator is UNDEFINED at the
        // exact 2^31 antipode (|a - b| == 0x8000_0000) because a - b and b - a
        // both reinterpret to i32::MIN (negative). Exclude that case from the
        // asymmetry invariant — callers avoid this regime by staying within a
        // 2^31 window, which is the protocol's window-size ceiling.
        if a.wrapping_sub(b) != 0x8000_0000 {
            assert!(!(seq_lt(a, b) && seq_lt(b, a)));
        }
        // lt ⇒ le
        if seq_lt(a, b) { assert!(seq_le(a, b)); }
        // Reflexivity
        assert!(seq_le(a, a));
        assert!(!seq_lt(a, a));
    }
});
