//! TCP option encode + decode for Stage 1 A4 scope:
//! MSS (RFC 6691), Window Scale + Timestamps (RFC 7323),
//! SACK-permitted + SACK blocks (RFC 2018).
//!
//! Encoder (this file's first half) emits options in a fixed canonical
//! order with explicit NOP padding for 4-byte word alignment. Decoder
//! (Task 4) parses bytes back into the same `TcpOpts` representation.
//! Malformed input (runaway len, wrong-length known options) is rejected
//! at parse time and bumps `tcp.rx_bad_option`; see `parse_options`'s
//! return type `Result<TcpOpts, OptionParseError>`.

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

/// A single SACK block (RFC 2018 §3). Seqs are host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SackBlock {
    pub left: u32,
    pub right: u32,
}

/// Parsed TCP options + SACK blocks. Used for both RX decode and TX
/// build. `sack_blocks` is a fixed-size array to avoid allocation on
/// the hot path.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpOpts {
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_permitted: bool,
    /// TSval + TSecr per RFC 7323 §3.
    pub timestamps: Option<(u32, u32)>,
    pub sack_blocks: [SackBlock; MAX_SACK_BLOCKS_EMIT],
    pub sack_block_count: u8,
}

impl TcpOpts {
    pub fn push_sack_block(&mut self, block: SackBlock) -> bool {
        if (self.sack_block_count as usize) >= MAX_SACK_BLOCKS_EMIT {
            return false;
        }
        self.sack_blocks[self.sack_block_count as usize] = block;
        self.sack_block_count += 1;
        true
    }

    /// Byte length of the encoded option sequence, rounded up to the
    /// next 4-byte word via NOP padding.
    pub fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        if self.mss.is_some() { n += LEN_MSS as usize; }
        if self.sack_permitted { n += LEN_SACK_PERMITTED as usize; }
        if self.timestamps.is_some() { n += LEN_TIMESTAMP as usize; }
        if self.wscale.is_some() { n += LEN_WSCALE as usize; }
        if self.sack_block_count > 0 {
            n += 2 + 8 * (self.sack_block_count as usize);
        }
        // Word-align.
        let rem = n % 4;
        if rem != 0 { n += 4 - rem; }
        n
    }

    /// Write the options to `out[..N]` in canonical order
    /// (MSS, SACK-permitted, Timestamps, WS, SACK-blocks), padding with
    /// NOPs (kind=1) to reach a 4-byte word boundary. Returns the number
    /// of bytes written, or `None` if `out` is too short.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let need = self.encoded_len();
        if out.len() < need { return None; }

        let mut i = 0usize;
        if let Some(mss) = self.mss {
            out[i] = OPT_MSS; out[i+1] = LEN_MSS;
            out[i+2..i+4].copy_from_slice(&mss.to_be_bytes());
            i += LEN_MSS as usize;
        }
        if self.sack_permitted {
            out[i] = OPT_SACK_PERMITTED; out[i+1] = LEN_SACK_PERMITTED;
            i += LEN_SACK_PERMITTED as usize;
        }
        if let Some((tsval, tsecr)) = self.timestamps {
            out[i] = OPT_TIMESTAMP; out[i+1] = LEN_TIMESTAMP;
            out[i+2..i+6].copy_from_slice(&tsval.to_be_bytes());
            out[i+6..i+10].copy_from_slice(&tsecr.to_be_bytes());
            i += LEN_TIMESTAMP as usize;
        }
        if let Some(ws) = self.wscale {
            out[i] = OPT_WSCALE; out[i+1] = LEN_WSCALE; out[i+2] = ws;
            i += LEN_WSCALE as usize;
        }
        if self.sack_block_count > 0 {
            let n = self.sack_block_count as usize;
            out[i] = OPT_SACK; out[i+1] = (2 + 8 * n) as u8;
            i += 2;
            for block in &self.sack_blocks[..n] {
                out[i..i+4].copy_from_slice(&block.left.to_be_bytes());
                out[i+4..i+8].copy_from_slice(&block.right.to_be_bytes());
                i += 8;
            }
        }
        // NOP-pad to the next word boundary.
        while i < need {
            out[i] = OPT_NOP;
            i += 1;
        }
        Some(need)
    }
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
        // 4 MSS + 2 SACK-perm + 10 TS + 3 WS = 19, padded to 20.
        assert_eq!(n, 20);
        // MSS
        assert_eq!(&buf[..4], &[OPT_MSS, LEN_MSS, 0x05, 0xb4]);
        // SACK-permitted
        assert_eq!(&buf[4..6], &[OPT_SACK_PERMITTED, LEN_SACK_PERMITTED]);
        // Timestamps
        assert_eq!(buf[6], OPT_TIMESTAMP);
        assert_eq!(buf[7], LEN_TIMESTAMP);
        assert_eq!(&buf[8..12], &0xdeadbeefu32.to_be_bytes());
        assert_eq!(&buf[12..16], &0u32.to_be_bytes());
        // Window Scale
        assert_eq!(&buf[16..19], &[OPT_WSCALE, LEN_WSCALE, 7]);
        // NOP pad
        assert_eq!(buf[19], OPT_NOP);
    }

    #[test]
    fn ack_with_timestamp_and_two_sack_blocks_word_aligned() {
        let mut opts = TcpOpts::default();
        opts.timestamps = Some((100, 200));
        opts.push_sack_block(SackBlock { left: 1000, right: 2000 });
        opts.push_sack_block(SackBlock { left: 3000, right: 4000 });
        let mut buf = [0u8; 40];
        let n = opts.encode(&mut buf).unwrap();
        // 10 TS + 2 SACK-hdr + 16 SACK-blocks = 28, already word-aligned.
        assert_eq!(n, 28);
        assert_eq!(buf[10], OPT_SACK);
        assert_eq!(buf[11], 2 + 16); // len = hdr + 2×(8)
        assert_eq!(&buf[12..16], &1000u32.to_be_bytes());
        assert_eq!(&buf[16..20], &2000u32.to_be_bytes());
        assert_eq!(&buf[20..24], &3000u32.to_be_bytes());
        assert_eq!(&buf[24..28], &4000u32.to_be_bytes());
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
}
