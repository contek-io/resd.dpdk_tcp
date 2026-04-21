//! SipHash-2-4 keyed hash (Aumasson/Bernstein 2012).
//! Used by `iss.rs` to generate RFC 6528 §3-compliant Initial Sequence Numbers.
//!
//! Reference implementation + test vectors:
//!   https://131002.net/siphash/siphash24.c
//!   https://131002.net/siphash/vectors.h
//! 64 test vectors; key = [0, 1, ..., 15]; message[i] = i (length 0..64).
//!
//! Hand-written so we don't pull a crate dep for ~60 LOC of arithmetic.

#[inline(always)]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Compute the SipHash-2-4 of `msg` keyed by the 16-byte `key`.
pub fn siphash24(key: &[u8; 16], msg: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let mut v0 = k0 ^ 0x736f6d6570736575_u64;
    let mut v1 = k1 ^ 0x646f72616e646f6d_u64;
    let mut v2 = k0 ^ 0x6c7967656e657261_u64;
    let mut v3 = k1 ^ 0x7465646279746573_u64;

    let mut i = 0;
    while i + 8 <= msg.len() {
        let m = u64::from_le_bytes(msg[i..i + 8].try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 8;
    }

    // Final block: remaining bytes + length byte in the high byte.
    let mut last: u64 = (msg.len() as u64 & 0xff) << 56;
    let remaining = &msg[i..];
    for (idx, byte) in remaining.iter().enumerate() {
        last |= (*byte as u64) << (idx * 8);
    }
    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^ v1 ^ v2 ^ v3
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference key from vectors.h: 00 01 02 ... 0f.
    fn ref_key() -> [u8; 16] {
        let mut k = [0u8; 16];
        for (i, slot) in k.iter_mut().enumerate() {
            *slot = i as u8;
        }
        k
    }

    /// Reference vectors from vectors.h (first 8 of 64). The canonical
    /// 64 u64 outputs are for message [0, 1, ..., n-1] for n in 0..64.
    /// Full table lives in tests/siphash24_vectors.rs.
    const REF_VECTORS_FIRST_8: [u64; 8] = [
        0x726fdb47dd0e0e31,
        0x74f839c593dc67fd,
        0x0d6c8009d9a94f5a,
        0x85676696d7fb7e2d,
        0xcf2794e0277187b7,
        0x18765564cd99a68d,
        0xcbc9466e58fee3ce,
        0xab0200f58b01d137,
    ];

    #[test]
    fn siphash24_reference_vectors_first_8() {
        let key = ref_key();
        for (i, expected) in REF_VECTORS_FIRST_8.iter().enumerate() {
            let msg: Vec<u8> = (0..i as u8).collect();
            let got = siphash24(&key, &msg);
            assert_eq!(
                got, *expected,
                "length {i}: got {got:016x}, expected {expected:016x}"
            );
        }
    }

    #[test]
    fn empty_message_with_zero_key_is_deterministic() {
        let key = [0u8; 16];
        assert_eq!(siphash24(&key, b""), siphash24(&key, b""));
    }

    #[test]
    fn different_keys_produce_different_outputs() {
        let k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        k2[0] = 1;
        assert_ne!(siphash24(&k1, b"hello"), siphash24(&k2, b"hello"));
    }

    #[test]
    fn different_messages_produce_different_outputs() {
        let key = ref_key();
        assert_ne!(siphash24(&key, b"abc"), siphash24(&key, b"abd"));
    }
}
