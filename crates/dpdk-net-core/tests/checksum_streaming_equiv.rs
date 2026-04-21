//! A6.5 Task 2: fuzz test proving the streaming `internet_checksum`
//! (slice-of-slices API) folds bit-for-bit identically to the
//! single-concatenated-buffer reference fold. Regression guard for
//! §7.6 hot-path checksum alloc retirement.

use dpdk_net_core::l3_ip::internet_checksum;

/// Reference fold: concatenates into a single Vec<u8>, then folds.
/// This is the pre-A6.5 behaviour, kept here as the oracle.
fn reference_fold(chunks: &[&[u8]]) -> u16 {
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    let mut concat = Vec::with_capacity(total);
    for c in chunks {
        concat.extend_from_slice(c);
    }
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < concat.len() {
        sum = sum.wrapping_add(u16::from_be_bytes([concat[i], concat[i + 1]]) as u32);
        i += 2;
    }
    if i < concat.len() {
        sum = sum.wrapping_add((concat[i] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn three_chunk_short_lengths_match_reference() {
    for a_len in 0..=15u8 {
        for b_len in 0..=15u8 {
            for c_len in 0..=15u8 {
                let a: Vec<u8> = (0..a_len).map(|i| i.wrapping_mul(7)).collect();
                let b: Vec<u8> = (0..b_len).map(|i| i.wrapping_mul(11).wrapping_add(3)).collect();
                let c: Vec<u8> = (0..c_len).map(|i| i.wrapping_mul(13).wrapping_add(17)).collect();
                let streaming = internet_checksum(&[&a, &b, &c]);
                let reference = reference_fold(&[&a, &b, &c]);
                assert_eq!(
                    streaming, reference,
                    "mismatch at lens=({}, {}, {})", a_len, b_len, c_len
                );
            }
        }
    }
}

#[test]
fn empty_and_singleton_edge_cases() {
    assert_eq!(internet_checksum(&[]), 0xffff);
    assert_eq!(internet_checksum(&[&[]]), 0xffff);
    assert_eq!(internet_checksum(&[&[], &[], &[]]), 0xffff);
    assert_eq!(internet_checksum(&[&[0u8; 1]]), reference_fold(&[&[0u8; 1]]));
    assert_eq!(internet_checksum(&[&[0xffu8; 1]]), reference_fold(&[&[0xffu8; 1]]));
}

#[test]
fn random_three_chunk_large_lengths_match_reference() {
    let mut seed: u64 = 0xc0ffee_u64;
    let mut next = || -> u8 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) as u8
    };
    for _ in 0..200 {
        let a_len = (next() as usize) & 0x7f;
        let b_len = ((next() as u16) << 2) as usize & 0x7ff;
        let c_len = ((next() as u16) << 3) as usize & 0x7ff;
        let a: Vec<u8> = (0..a_len).map(|_| next()).collect();
        let b: Vec<u8> = (0..b_len).map(|_| next()).collect();
        let c: Vec<u8> = (0..c_len).map(|_| next()).collect();
        assert_eq!(
            internet_checksum(&[&a, &b, &c]),
            reference_fold(&[&a, &b, &c]),
            "mismatch at lens=({}, {}, {})", a_len, b_len, c_len
        );
    }
}

#[test]
fn single_slice_wrapper_preserves_pre_a65_behaviour() {
    for len in 0..=1500 {
        let data: Vec<u8> = (0..len).map(|i| ((i * 31) ^ 0x5a) as u8).collect();
        assert_eq!(
            internet_checksum(&[&data]),
            reference_fold(&[&data]),
            "len={}", len
        );
    }
}
