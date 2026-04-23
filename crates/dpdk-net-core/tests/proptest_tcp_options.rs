//! Property tests for TCP options encode/decode (RFC 7323 + RFC 2018 + MSS).
//!
//! Properties:
//!   1. `parse_options` of arbitrary bytes never panics.
//!   2. `decode(encode(opts)) == opts` (round-trip identity for valid opts).
//!   3. `parse_options` is idempotent over re-encode
//!      (encode -> decode -> encode -> decode = same).
//!
//! The arbitrary-`TcpOpts` strategy generates only well-formed values:
//!   * `wscale` in `0..=14` so the parser never clamps + sets `ws_clamped`
//!     (which would break the round-trip equality since `ws_clamped` is a
//!     decode-side signal not present in the encoded bytes).
//!   * `sack_blocks` array layout matches what `parse_options` would
//!     produce: positions `[count..MAX_SACK_BLOCKS_DECODE]` are zeroed
//!     (`SackBlock::default()`), so derived `PartialEq` over the fixed-size
//!     array matches the decoded value.
//!   * `sack_block_count` in `0..=MAX_SACK_BLOCKS_DECODE` (4) — the `encode()`
//!     path emits whatever `sack_block_count` says (no internal cap), and the
//!     parser accepts up to 4 blocks per RFC 2018 §3.

use dpdk_net_core::tcp_options::{
    parse_options, SackBlock, TcpOpts, MAX_SACK_BLOCKS_DECODE,
};
use proptest::prelude::*;

fn arb_sack_block() -> impl Strategy<Value = SackBlock> {
    (any::<u32>(), any::<u32>()).prop_map(|(l, r)| SackBlock { left: l, right: r })
}

fn arb_tcp_opts() -> impl Strategy<Value = TcpOpts> {
    (
        proptest::option::of(536u16..=65535),                              // mss
        proptest::option::of(0u8..=14),                                    // wscale (no clamp)
        any::<bool>(),                                                     // sack_permitted
        proptest::option::of((any::<u32>(), any::<u32>())),                // timestamps
        proptest::collection::vec(arb_sack_block(), 0..=MAX_SACK_BLOCKS_DECODE),
    )
        .prop_map(|(mss, wscale, sack_permitted, timestamps, blocks)| {
            let mut opts = TcpOpts::default();
            opts.mss = mss;
            opts.wscale = wscale;
            opts.sack_permitted = sack_permitted;
            opts.timestamps = timestamps;
            // Fill the fixed-size array exactly as `parse_options` would:
            // first `count` slots populated, the rest left at default. This
            // is required for the derived `PartialEq` to match across the
            // round trip.
            opts.sack_block_count = blocks.len() as u8;
            for (i, b) in blocks.into_iter().enumerate() {
                opts.sack_blocks[i] = b;
            }
            opts
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// `parse_options` never panics on arbitrary bytes.
    #[test]
    fn decode_never_panics(data: Vec<u8>) {
        let _ = parse_options(&data);
    }

    /// Encode an arbitrary well-formed `TcpOpts`; if encode fits in the
    /// 40-byte option budget, decode must yield the exact same value.
    #[test]
    fn round_trip_identity(opts in arb_tcp_opts()) {
        let mut buf = [0u8; 40]; // RFC 9293 §3.1: TCP option space max.
        if let Some(n) = opts.encode(&mut buf) {
            let decoded = parse_options(&buf[..n])
                .expect("encoded opts must decode");
            prop_assert_eq!(decoded, opts);
        }
    }

    /// Encode -> decode -> encode -> decode of any byte sequence the parser
    /// accepts is fixed-point: the second decode equals the first.
    #[test]
    fn encode_decode_encode_idempotent(data: Vec<u8>) {
        if let Ok(first) = parse_options(&data) {
            let mut buf = [0u8; 40];
            if let Some(n1) = first.encode(&mut buf) {
                let redecoded = parse_options(&buf[..n1])
                    .expect("re-decode of just-encoded bytes");
                prop_assert_eq!(redecoded, first);
            }
        }
    }
}
