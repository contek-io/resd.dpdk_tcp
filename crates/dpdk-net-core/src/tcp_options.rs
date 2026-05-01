//! TCP option encode + decode for Stage 1 A4 scope:
//! MSS (RFC 6691), Window Scale + Timestamps (RFC 7323),
//! SACK-permitted + SACK blocks (RFC 2018).
//!
//! Encoder emits `<MSS, NOP+WScale, SACKP, TS, NOPs+SACK blocks>` to
//! match the shivansh + ligurio packetdrill corpus SYN-ACK wire shape
//! byte-for-byte. Per `AD-A8.5-tx-wscale-position` (spec §6.4), this
//! places WSCALE second (right after MSS) rather than last. Modern
//! Linux `net/ipv4/tcp_output.c::tcp_options_write`, Google packetdrill
//! upstream, and mTCP all emit WSCALE LAST in `<MSS, SACKP, TS, NOP+WSCALE>`
//! order — we deliberately chose the corpus-compatible order because
//! shivansh + ligurio are our Layer-B unlock path. RFC 9293 §3.2 is
//! receiver-order-agnostic, so both orderings are RFC-compliant. NOPs
//! are embedded where needed to land each group on a 4-byte word
//! boundary. Decoder (Task 4) parses bytes back into the same `TcpOpts`
//! representation and remains order-agnostic. Malformed input (runaway
//! len, wrong-length known options) is rejected at parse time and bumps
//! `tcp.rx_bad_option`; see `parse_options`'s return type
//! `Result<TcpOpts, OptionParseError>`.

// TCP option kinds per IANA.
pub const OPT_END: u8 = 0;
pub const OPT_NOP: u8 = 1;
pub const OPT_MSS: u8 = 2;
pub const OPT_WSCALE: u8 = 3;
pub const OPT_SACK_PERMITTED: u8 = 4;
pub const OPT_SACK: u8 = 5;
pub const OPT_TIMESTAMP: u8 = 8;

// Option total lengths (kind+len+value) per the respective RFCs.
pub const LEN_MSS: u8 = 4;
pub const LEN_WSCALE: u8 = 3;
pub const LEN_SACK_PERMITTED: u8 = 2;
pub const LEN_TIMESTAMP: u8 = 10;
// SACK block: 2 header + 8*N, N in 1..=4 per RFC 2018 §3.

/// Maximum number of SACK blocks we emit on an ACK. RFC 2018 §3 caps at
/// 3 when the Timestamps option is present (40-byte option budget: 10
/// for TS + 2 NOPs + at most 26 left for SACK = 3 blocks × 8 bytes
/// + 2 header). With Timestamps absent the cap is 4; we always emit
///   with Timestamps so 3 is the right ceiling.
pub const MAX_SACK_BLOCKS_EMIT: usize = 3;

/// Maximum number of SACK blocks we decode from an inbound ACK. RFC 2018
/// §3 allows up to 4 blocks on the wire when the peer omits Timestamps;
/// we widen our decode storage so we never silently drop the 4th block.
/// (Encode/emit stays at 3 since our outbound ACKs always carry TS.)
pub const MAX_SACK_BLOCKS_DECODE: usize = 4;

/// A single SACK block (RFC 2018 §3). Seqs are host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SackBlock {
    pub left: u32,
    pub right: u32,
}

/// Parsed TCP options + SACK blocks. Used for both RX decode and TX
/// build. `sack_blocks` is a fixed-size array to avoid allocation on
/// the hot path. The array is sized to `MAX_SACK_BLOCKS_DECODE` (4) so
/// we can receive the peer's 4-block ACKs without dropping the tail; the
/// encode path (`push_sack_block`) still caps at `MAX_SACK_BLOCKS_EMIT`
/// (3) since our outbound ACKs always include Timestamps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpOpts {
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_permitted: bool,
    /// TSval + TSecr per RFC 7323 §3.
    pub timestamps: Option<(u32, u32)>,
    pub sack_blocks: [SackBlock; MAX_SACK_BLOCKS_DECODE],
    pub sack_block_count: u8,
    /// RFC 7323 §2.3: set true when the parser clamps a WS>14 advertisement
    /// back down to 14. Engine observes + logs on handshake.
    pub ws_clamped: bool,
}

impl TcpOpts {
    /// Encode-path append: caps at `MAX_SACK_BLOCKS_EMIT` (3) so we never
    /// produce an outbound SACK option that exceeds the 40-byte option
    /// budget alongside Timestamps.
    pub fn push_sack_block(&mut self, block: SackBlock) -> bool {
        if (self.sack_block_count as usize) >= MAX_SACK_BLOCKS_EMIT {
            return false;
        }
        self.sack_blocks[self.sack_block_count as usize] = block;
        self.sack_block_count += 1;
        true
    }

    /// Decode-path append: caps at `MAX_SACK_BLOCKS_DECODE` (4) so the
    /// parser can record all blocks RFC 2018 §3 allows on the wire (up
    /// to 4 when the peer omits Timestamps). Only `parse_options` should
    /// call this; the encode path must go through `push_sack_block`.
    pub fn push_sack_block_decode(&mut self, block: SackBlock) -> bool {
        if (self.sack_block_count as usize) >= MAX_SACK_BLOCKS_DECODE {
            return false;
        }
        self.sack_blocks[self.sack_block_count as usize] = block;
        self.sack_block_count += 1;
        true
    }

    /// Byte length of the encoded option sequence, matching the Linux
    /// canonical emission order in `encode` below. Each "group" lands on
    /// a 4-byte word boundary without extra trailing NOP padding.
    pub fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        if self.mss.is_some() {
            n += LEN_MSS as usize; // 4
        }
        if self.wscale.is_some() {
            // NOP + WScale(3) = 4 bytes.
            n += 1 + LEN_WSCALE as usize;
        }
        match (self.sack_permitted, self.timestamps.is_some()) {
            (true, true) => {
                // SACKP(2) + TS(10) = 12 bytes, aligned.
                n += LEN_SACK_PERMITTED as usize + LEN_TIMESTAMP as usize;
            }
            (true, false) => {
                // NOP + NOP + SACKP(2) = 4 bytes.
                n += 2 + LEN_SACK_PERMITTED as usize;
            }
            (false, true) => {
                // NOP + NOP + TS(10) = 12 bytes.
                n += 2 + LEN_TIMESTAMP as usize;
            }
            (false, false) => {}
        }
        if self.sack_block_count > 0 {
            // NOP + NOP + SACK hdr(2) + N*8. Always 4-byte aligned for N>=1.
            n += 2 + 2 + 8 * (self.sack_block_count as usize);
        }
        // By construction every group above lands on a 4-byte boundary.
        debug_assert!(n % 4 == 0, "encoded_len must be 4-byte word aligned: {n}");
        n
    }

    /// Write the options to `out[..N]` in Linux canonical emission order:
    ///     MSS [NOP WScale] [SACKP | NOPs+SACKP | NOPs+TS | SACKP+TS]
    ///         [NOPs + SACK-blocks]
    /// Linux's kernel default encoding (per
    /// `net/ipv4/tcp_output.c::tcp_options_write`) is what packetdrill
    /// hand-crafted `tcp.opt(...)` assertions expect; RFC 9293 §3.2 is
    /// otherwise order-agnostic, so this is corpus-compatibility
    /// alignment, not a semantic change. Returns the number of bytes
    /// written, or `None` if `out` is too short.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let need = self.encoded_len();
        if out.len() < need {
            return None;
        }

        let mut i = 0usize;
        // 1. MSS first (4 bytes, aligned).
        if let Some(mss) = self.mss {
            out[i] = OPT_MSS;
            out[i + 1] = LEN_MSS;
            out[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
            i += LEN_MSS as usize;
        }
        // 2. NOP + WScale (4 bytes, aligned). NOP prefix is Linux's
        //    convention for packing the 3-byte WScale into a 4-byte word.
        if let Some(ws) = self.wscale {
            out[i] = OPT_NOP;
            out[i + 1] = OPT_WSCALE;
            out[i + 2] = LEN_WSCALE;
            out[i + 3] = ws;
            i += 1 + LEN_WSCALE as usize;
        }
        // 3. SACK-permitted + Timestamps block. Linux packs these together
        //    differently depending on presence to keep 4-byte alignment:
        //      - both:  SACKP(2) + TS(10)                 = 12 bytes
        //      - SACKP-only: NOP + NOP + SACKP(2)          = 4 bytes
        //      - TS-only:    NOP + NOP + TS(10)            = 12 bytes
        //    Order inside the block matches Linux's
        //    `tcp_options_write` so packetdrill scripts see the expected
        //    `<... sackOK, TS val X ecr Y>` sequence.
        match (self.sack_permitted, self.timestamps) {
            (true, Some((tsval, tsecr))) => {
                out[i] = OPT_SACK_PERMITTED;
                out[i + 1] = LEN_SACK_PERMITTED;
                i += LEN_SACK_PERMITTED as usize;
                out[i] = OPT_TIMESTAMP;
                out[i + 1] = LEN_TIMESTAMP;
                out[i + 2..i + 6].copy_from_slice(&tsval.to_be_bytes());
                out[i + 6..i + 10].copy_from_slice(&tsecr.to_be_bytes());
                i += LEN_TIMESTAMP as usize;
            }
            (true, None) => {
                out[i] = OPT_NOP;
                out[i + 1] = OPT_NOP;
                out[i + 2] = OPT_SACK_PERMITTED;
                out[i + 3] = LEN_SACK_PERMITTED;
                i += 2 + LEN_SACK_PERMITTED as usize;
            }
            (false, Some((tsval, tsecr))) => {
                out[i] = OPT_NOP;
                out[i + 1] = OPT_NOP;
                i += 2;
                out[i] = OPT_TIMESTAMP;
                out[i + 1] = LEN_TIMESTAMP;
                out[i + 2..i + 6].copy_from_slice(&tsval.to_be_bytes());
                out[i + 6..i + 10].copy_from_slice(&tsecr.to_be_bytes());
                i += LEN_TIMESTAMP as usize;
            }
            (false, None) => {}
        }
        // 4. SACK blocks (DSACK / selective-ACK, variable length). Linux
        //    emits with a leading 2-NOP prefix so the option header lands
        //    on a 4-byte boundary; blocks are always 8-byte multiples so
        //    the total group is 4 + 8*N — always aligned.
        if self.sack_block_count > 0 {
            let n = self.sack_block_count as usize;
            out[i] = OPT_NOP;
            out[i + 1] = OPT_NOP;
            out[i + 2] = OPT_SACK;
            out[i + 3] = (2 + 8 * n) as u8;
            i += 4;
            for block in &self.sack_blocks[..n] {
                out[i..i + 4].copy_from_slice(&block.left.to_be_bytes());
                out[i + 4..i + 8].copy_from_slice(&block.right.to_be_bytes());
                i += 8;
            }
        }
        debug_assert_eq!(i, need, "emitted byte count must match encoded_len");
        Some(i)
    }
}

/// Errors from `parse_options`. Every variant maps to one `tcp.rx_bad_option`
/// bump on the caller side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionParseError {
    /// `optlen < 2` on an unknown option kind (would underflow advance).
    ShortUnknown,
    /// `optlen` on a known-kind doesn't match the RFC value.
    BadKnownLen,
    /// Option would extend past the end of the options region.
    Truncated,
    /// SACK block count isn't in 1..=MAX_SACK_BLOCKS_DECODE (zero blocks
    /// or too many).
    BadSackBlockCount,
}

/// Parse TCP options per RFC 9293 §3.1. Returns the fully populated
/// `TcpOpts`; unknown option kinds are skipped by their declared length
/// (with the defensive `optlen >= 2` check that mTCP's `ParseTCPOptions`
/// lacks, see the mTCP I-6 note in A3's review).
pub fn parse_options(opts: &[u8]) -> Result<TcpOpts, OptionParseError> {
    let mut out = TcpOpts::default();
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i] {
            OPT_END => return Ok(out),
            OPT_NOP => {
                i += 1;
                continue;
            }
            kind => {
                if i + 1 >= opts.len() {
                    return Err(OptionParseError::Truncated);
                }
                let olen = opts[i + 1] as usize;
                if olen < 2 {
                    return Err(OptionParseError::ShortUnknown);
                }
                if i + olen > opts.len() {
                    return Err(OptionParseError::Truncated);
                }
                match kind {
                    OPT_MSS => {
                        if olen != LEN_MSS as usize {
                            return Err(OptionParseError::BadKnownLen);
                        }
                        out.mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                    }
                    OPT_WSCALE => {
                        if olen != LEN_WSCALE as usize {
                            return Err(OptionParseError::BadKnownLen);
                        }
                        // RFC 7323 §2.3 MUST: if shift.cnt > 14, use 14. The
                        // handshake site (handle_syn_sent) also clamps as
                        // defense-in-depth; we signal the clamp via
                        // `ws_clamped` so the engine can log + bump
                        // `tcp.rx_ws_shift_clamped`.
                        let shift = opts[i + 2];
                        if shift > 14 {
                            out.wscale = Some(14);
                            out.ws_clamped = true;
                        } else {
                            out.wscale = Some(shift);
                        }
                    }
                    OPT_SACK_PERMITTED => {
                        if olen != LEN_SACK_PERMITTED as usize {
                            return Err(OptionParseError::BadKnownLen);
                        }
                        out.sack_permitted = true;
                    }
                    OPT_TIMESTAMP => {
                        if olen != LEN_TIMESTAMP as usize {
                            return Err(OptionParseError::BadKnownLen);
                        }
                        let tsval = u32::from_be_bytes([
                            opts[i + 2],
                            opts[i + 3],
                            opts[i + 4],
                            opts[i + 5],
                        ]);
                        let tsecr = u32::from_be_bytes([
                            opts[i + 6],
                            opts[i + 7],
                            opts[i + 8],
                            opts[i + 9],
                        ]);
                        out.timestamps = Some((tsval, tsecr));
                    }
                    OPT_SACK => {
                        // len = 2 (hdr) + 8 * N, N in 1..=MAX_SACK_BLOCKS_DECODE.
                        let block_bytes = olen.saturating_sub(2);
                        if block_bytes == 0
                            || !block_bytes.is_multiple_of(8)
                            || block_bytes / 8 > MAX_SACK_BLOCKS_DECODE
                        {
                            return Err(OptionParseError::BadSackBlockCount);
                        }
                        // Decode every block the peer sent; array is sized
                        // to MAX_SACK_BLOCKS_DECODE so push_sack_block_decode
                        // never drops a valid on-wire block.
                        let mut bi = i + 2;
                        for _ in 0..(block_bytes / 8) {
                            let left = u32::from_be_bytes([
                                opts[bi],
                                opts[bi + 1],
                                opts[bi + 2],
                                opts[bi + 3],
                            ]);
                            let right = u32::from_be_bytes([
                                opts[bi + 4],
                                opts[bi + 5],
                                opts[bi + 6],
                                opts[bi + 7],
                            ]);
                            out.push_sack_block_decode(SackBlock { left, right });
                            bi += 8;
                        }
                    }
                    _ => {
                        // Unknown kind — skip by len. olen ≥ 2 guaranteed above.
                    }
                }
                i += olen;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn full_syn_options_encode_in_canonical_order() {
        let mut opts = TcpOpts::default();
        opts.mss = Some(1460);
        opts.sack_permitted = true;
        opts.timestamps = Some((0xdeadbeef, 0));
        opts.wscale = Some(7);
        let mut buf = [0u8; 40];
        let n = opts.encode(&mut buf).unwrap();
        // Linux canonical: MSS(4) + NOP+WS(4) + SACKP(2) + TS(10) = 20 bytes.
        assert_eq!(n, 20);
        // MSS.
        assert_eq!(&buf[..4], &[OPT_MSS, LEN_MSS, 0x05, 0xb4]);
        // NOP + Window Scale.
        assert_eq!(&buf[4..8], &[OPT_NOP, OPT_WSCALE, LEN_WSCALE, 7]);
        // SACK-permitted.
        assert_eq!(&buf[8..10], &[OPT_SACK_PERMITTED, LEN_SACK_PERMITTED]);
        // Timestamps.
        assert_eq!(buf[10], OPT_TIMESTAMP);
        assert_eq!(buf[11], LEN_TIMESTAMP);
        assert_eq!(&buf[12..16], &0xdeadbeefu32.to_be_bytes());
        assert_eq!(&buf[16..20], &0u32.to_be_bytes());
    }

    #[test]
    fn ack_with_timestamp_and_two_sack_blocks_word_aligned() {
        let mut opts = TcpOpts::default();
        opts.timestamps = Some((100, 200));
        opts.push_sack_block(SackBlock {
            left: 1000,
            right: 2000,
        });
        opts.push_sack_block(SackBlock {
            left: 3000,
            right: 4000,
        });
        let mut buf = [0u8; 40];
        let n = opts.encode(&mut buf).unwrap();
        // Linux canonical layout for ACK with TS + 2 SACK blocks:
        //   NOP+NOP+TS(12) + NOP+NOP+SACK hdr+16 = 12 + 4 + 16 = 32 bytes.
        assert_eq!(n, 32);
        // TS block: 2 leading NOPs, then TS kind/len/tsval/tsecr.
        assert_eq!(&buf[0..2], &[OPT_NOP, OPT_NOP]);
        assert_eq!(buf[2], OPT_TIMESTAMP);
        assert_eq!(buf[3], LEN_TIMESTAMP);
        assert_eq!(&buf[4..8], &100u32.to_be_bytes());
        assert_eq!(&buf[8..12], &200u32.to_be_bytes());
        // SACK block: 2 leading NOPs, then SACK kind/len + N*(left,right).
        assert_eq!(&buf[12..14], &[OPT_NOP, OPT_NOP]);
        assert_eq!(buf[14], OPT_SACK);
        assert_eq!(buf[15], 2 + 16); // len = hdr + 2×(8)
        assert_eq!(&buf[16..20], &1000u32.to_be_bytes());
        assert_eq!(&buf[20..24], &2000u32.to_be_bytes());
        assert_eq!(&buf[24..28], &3000u32.to_be_bytes());
        assert_eq!(&buf[28..32], &4000u32.to_be_bytes());
    }

    #[test]
    fn empty_options_encode_to_zero_bytes() {
        let opts = TcpOpts::default();
        let mut buf = [0u8; 4];
        let n = opts.encode(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn encode_returns_none_when_out_too_small() {
        let mut opts = TcpOpts::default();
        opts.mss = Some(1460);
        let mut buf = [0u8; 2];
        assert!(opts.encode(&mut buf).is_none());
    }

    #[test]
    fn sack_block_count_caps_at_max() {
        let mut opts = TcpOpts::default();
        assert!(opts.push_sack_block(SackBlock { left: 0, right: 1 }));
        assert!(opts.push_sack_block(SackBlock { left: 2, right: 3 }));
        assert!(opts.push_sack_block(SackBlock { left: 4, right: 5 }));
        assert!(!opts.push_sack_block(SackBlock { left: 6, right: 7 }));
        assert_eq!(opts.sack_block_count, 3);
    }

    #[test]
    fn parse_empty_options_returns_default() {
        let opts = parse_options(&[]).unwrap();
        assert_eq!(opts.mss, None);
        assert_eq!(opts.wscale, None);
        assert!(!opts.sack_permitted);
        assert_eq!(opts.timestamps, None);
        assert_eq!(opts.sack_block_count, 0);
    }

    #[test]
    fn parse_end_short_circuits() {
        let bytes = [OPT_MSS, LEN_MSS, 0x05, 0xb4, OPT_END, 0xff, 0xff];
        let opts = parse_options(&bytes).unwrap();
        assert_eq!(opts.mss, Some(1460));
    }

    #[test]
    fn parse_nop_advances_one_byte() {
        let bytes = [OPT_NOP, OPT_NOP, OPT_MSS, LEN_MSS, 0x05, 0xb4];
        let opts = parse_options(&bytes).unwrap();
        assert_eq!(opts.mss, Some(1460));
    }

    #[test]
    fn parse_full_syn_options_round_trips_encode() {
        let mut built = TcpOpts::default();
        built.mss = Some(1460);
        built.sack_permitted = true;
        built.timestamps = Some((0x1122_3344, 0x5566_7788));
        built.wscale = Some(7);
        let mut buf = [0u8; 40];
        let n = built.encode(&mut buf).unwrap();
        let parsed = parse_options(&buf[..n]).unwrap();
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.wscale, Some(7));
        assert!(parsed.sack_permitted);
        assert_eq!(parsed.timestamps, Some((0x1122_3344, 0x5566_7788)));
    }

    #[test]
    fn parse_sack_blocks_three_roundtrips() {
        let mut built = TcpOpts::default();
        built.timestamps = Some((0, 0));
        built.push_sack_block(SackBlock {
            left: 100,
            right: 200,
        });
        built.push_sack_block(SackBlock {
            left: 300,
            right: 400,
        });
        built.push_sack_block(SackBlock {
            left: 500,
            right: 600,
        });
        let mut buf = [0u8; 40];
        let n = built.encode(&mut buf).unwrap();
        let parsed = parse_options(&buf[..n]).unwrap();
        assert_eq!(parsed.sack_block_count, 3);
        assert_eq!(
            parsed.sack_blocks[0],
            SackBlock {
                left: 100,
                right: 200
            }
        );
        assert_eq!(
            parsed.sack_blocks[1],
            SackBlock {
                left: 300,
                right: 400
            }
        );
        assert_eq!(
            parsed.sack_blocks[2],
            SackBlock {
                left: 500,
                right: 600
            }
        );
    }

    #[test]
    fn parse_rejects_zero_optlen_unknown_kind() {
        // Kind 99 (unknown), len=0 — would infinite-loop in mTCP.
        let bytes = [99u8, 0u8, 0x42];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::ShortUnknown);
    }

    #[test]
    fn parse_rejects_wrong_mss_len() {
        // MSS with len=6 (A3's parse_mss_option would also reject).
        let bytes = [OPT_MSS, 6, 0x05, 0xb4, 0x00, 0x00];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadKnownLen);
    }

    #[test]
    fn parse_rejects_wrong_wscale_len() {
        let bytes = [OPT_WSCALE, 4, 7, 0];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadKnownLen);
    }

    #[test]
    fn parse_rejects_wrong_ts_len() {
        let bytes = [OPT_TIMESTAMP, 8, 0, 0, 0, 0, 0, 0];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadKnownLen);
    }

    #[test]
    fn parse_rejects_truncated_mss() {
        // MSS header claims 4 bytes but only 3 present.
        let bytes = [OPT_MSS, 4, 0x05];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::Truncated);
    }

    #[test]
    fn parse_rejects_sack_with_zero_blocks() {
        let bytes = [OPT_SACK, 2]; // header only, no blocks.
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadSackBlockCount);
    }

    #[test]
    fn parse_rejects_sack_with_odd_block_bytes() {
        // 2 + 7 = odd block region.
        let mut bytes = [0u8; 9];
        bytes[0] = OPT_SACK;
        bytes[1] = 9;
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadSackBlockCount);
    }

    #[test]
    fn parse_skips_unknown_kind_with_valid_len() {
        // Kind 99, len 4, two bytes of payload — skipped; MSS follows.
        let bytes = [99u8, 4, 0xaa, 0xbb, OPT_MSS, LEN_MSS, 0x05, 0xb4];
        let opts = parse_options(&bytes).unwrap();
        assert_eq!(opts.mss, Some(1460));
    }

    #[test]
    fn parse_sack_four_blocks_without_timestamps_all_captured() {
        // RFC 2018 §3: up to 4 SACK blocks on the wire when Timestamps
        // is absent. Hand-build the option rather than using encode()
        // (which caps emit at 3). Assert all 4 land in the array.
        let mut bytes = [0u8; 2 + 8 * 4];
        bytes[0] = OPT_SACK;
        bytes[1] = (2 + 8 * 4) as u8;
        let blocks = [(100u32, 200u32), (300, 400), (500, 600), (700, 800)];
        for (idx, (l, r)) in blocks.iter().enumerate() {
            let off = 2 + idx * 8;
            bytes[off..off + 4].copy_from_slice(&l.to_be_bytes());
            bytes[off + 4..off + 8].copy_from_slice(&r.to_be_bytes());
        }
        let parsed = parse_options(&bytes).unwrap();
        assert_eq!(parsed.sack_block_count, 4);
        for (idx, (l, r)) in blocks.iter().enumerate() {
            assert_eq!(
                parsed.sack_blocks[idx],
                SackBlock {
                    left: *l,
                    right: *r,
                }
            );
        }
    }

    #[test]
    fn parser_clamps_ws_shift_above_14_to_14_and_signals() {
        // NOP + WSCALE(15): [0x01, 0x03, 0x03, 0x0F]
        let buf = [0x01, 0x03, 0x03, 0x0F];
        let parsed = parse_options(&buf).unwrap();
        assert_eq!(parsed.wscale, Some(14));
        assert!(parsed.ws_clamped);
    }

    #[test]
    fn parser_does_not_flag_ws_shift_at_or_below_14() {
        let buf = [0x01, 0x03, 0x03, 0x0E]; // WS=14 exactly
        let parsed = parse_options(&buf).unwrap();
        assert_eq!(parsed.wscale, Some(14));
        assert!(!parsed.ws_clamped);

        let buf2 = [0x01, 0x03, 0x03, 0x07]; // WS=7
        let parsed2 = parse_options(&buf2).unwrap();
        assert_eq!(parsed2.wscale, Some(7));
        assert!(!parsed2.ws_clamped);
    }

    #[test]
    fn parse_rejects_sack_with_five_blocks() {
        // 2 + 8 * 5 = 42 bytes, which exceeds MAX_SACK_BLOCKS_DECODE = 4
        // and is also larger than the 40-byte option budget. Must reject
        // with BadSackBlockCount.
        let mut bytes = [0u8; 2 + 8 * 5];
        bytes[0] = OPT_SACK;
        bytes[1] = (2 + 8 * 5) as u8;
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadSackBlockCount);
    }
}
