//! TCP segment builders. Every builder emits a complete Ethernet + IPv4 +
//! TCP frame, ready to hand to `Engine::tx_frame` for burst TX. We compute
//! both the IPv4 header checksum (software — later phases will flip to NIC
//! offload) and the TCP pseudo-header checksum per RFC 9293 §3.1.
//!
//! No TCP options beyond MSS (2-byte NOP-pad appended to keep the header a
//! multiple of 4 bytes). WSCALE / TS / SACK-permitted land in Phase A4.

use crate::l2::{ETHERTYPE_IPV4, ETH_HDR_LEN};
use crate::l3_ip::{internet_checksum, IPPROTO_TCP};

pub const TCP_HDR_MIN: usize = 20;
pub const IPV4_HDR_MIN: usize = 20;
pub const FRAME_HDRS_MIN: usize = ETH_HDR_LEN + IPV4_HDR_MIN + TCP_HDR_MIN; // 54

// TCP flag bits.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// One-segment fields the caller controls. `payload` is appended after
/// the header (possibly empty).
pub struct SegmentTx<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: u32,  // host byte order
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss_option: Option<u16>,  // Some(mss) → append MSS option on SYN
    pub payload: &'a [u8],
}

/// Write the frame into `out`, returning the number of bytes written,
/// or `None` if `out` is too small. Minimum output size is
/// `FRAME_HDRS_MIN + mss_option.map_or(0, |_| 4) + payload.len()`.
pub fn build_segment(seg: &SegmentTx, out: &mut [u8]) -> Option<usize> {
    let opts_len = if seg.mss_option.is_some() { 4 } else { 0 };
    let tcp_hdr_len = TCP_HDR_MIN + opts_len;
    let total = ETH_HDR_LEN + IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len();
    if out.len() < total {
        return None;
    }

    // Ethernet
    out[0..6].copy_from_slice(&seg.dst_mac);
    out[6..12].copy_from_slice(&seg.src_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4
    let ip_start = ETH_HDR_LEN;
    let ip = &mut out[ip_start..ip_start + IPV4_HDR_MIN];
    let total_ip_len = (IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len()) as u16;
    ip[0] = 0x45; // ver=4, IHL=5
    ip[1] = 0x00;
    ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0x0000u16.to_be_bytes()); // identification
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, frag_off=0
    ip[8] = 64; // TTL
    ip[9] = IPPROTO_TCP;
    ip[10..12].copy_from_slice(&0x0000u16.to_be_bytes()); // csum placeholder
    ip[12..16].copy_from_slice(&seg.src_ip.to_be_bytes());
    ip[16..20].copy_from_slice(&seg.dst_ip.to_be_bytes());
    let ip_csum = internet_checksum(&out[ip_start..ip_start + IPV4_HDR_MIN]);
    out[ip_start + 10] = (ip_csum >> 8) as u8;
    out[ip_start + 11] = (ip_csum & 0xff) as u8;

    // TCP header + options + payload
    let tcp_start = ip_start + IPV4_HDR_MIN;
    let th = &mut out[tcp_start..tcp_start + tcp_hdr_len];
    th[0..2].copy_from_slice(&seg.src_port.to_be_bytes());
    th[2..4].copy_from_slice(&seg.dst_port.to_be_bytes());
    th[4..8].copy_from_slice(&seg.seq.to_be_bytes());
    th[8..12].copy_from_slice(&seg.ack.to_be_bytes());
    th[12] = ((tcp_hdr_len / 4) as u8) << 4; // data offset
    th[13] = seg.flags;
    th[14..16].copy_from_slice(&seg.window.to_be_bytes());
    th[16..18].copy_from_slice(&0u16.to_be_bytes()); // csum placeholder
    th[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent ptr
    if let Some(mss) = seg.mss_option {
        // MSS option: kind=2, len=4, 2-byte value.
        th[20] = 2;
        th[21] = 4;
        th[22..24].copy_from_slice(&mss.to_be_bytes());
    }
    // Copy payload
    let payload_start = tcp_start + tcp_hdr_len;
    out[payload_start..payload_start + seg.payload.len()].copy_from_slice(seg.payload);

    // Compute TCP checksum over pseudo-header + TCP header + payload.
    let tcp_seg_len = (tcp_hdr_len + seg.payload.len()) as u32;
    let csum = tcp_checksum(
        seg.src_ip,
        seg.dst_ip,
        tcp_seg_len,
        &out[tcp_start..payload_start + seg.payload.len()],
    );
    out[tcp_start + 16] = (csum >> 8) as u8;
    out[tcp_start + 17] = (csum & 0xff) as u8;

    Some(total)
}

/// Pseudo-header checksum per RFC 9293 §3.1. Reuses `internet_checksum`
/// by folding a scratch buffer of pseudo-header + tcp segment bytes.
fn tcp_checksum(src_ip: u32, dst_ip: u32, tcp_seg_len: u32, tcp_bytes: &[u8]) -> u16 {
    // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_len(2)
    let mut buf = Vec::with_capacity(12 + tcp_bytes.len());
    buf.extend_from_slice(&src_ip.to_be_bytes());
    buf.extend_from_slice(&dst_ip.to_be_bytes());
    buf.push(0);
    buf.push(IPPROTO_TCP);
    buf.extend_from_slice(&(tcp_seg_len as u16).to_be_bytes());
    buf.extend_from_slice(tcp_bytes);
    internet_checksum(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3_ip::ip_decode;

    fn base() -> SegmentTx<'static> {
        SegmentTx {
            src_mac: [0x02, 0, 0, 0, 0, 1],
            dst_mac: [0x02, 0, 0, 0, 0, 2],
            src_ip: 0x0a_00_00_02,
            dst_ip: 0x0a_00_00_01,
            src_port: 40000,
            dst_port: 5000,
            seq: 0x1000,
            ack: 0,
            flags: TCP_SYN,
            window: 65535,
            mss_option: Some(1460),
            payload: &[],
        }
    }

    #[test]
    fn syn_frame_has_mss_option_and_valid_sizes() {
        let seg = base();
        let mut out = [0u8; 128];
        let n = build_segment(&seg, &mut out).unwrap();
        // 14 eth + 20 ip + 20 tcp + 4 mss = 58.
        assert_eq!(n, 58);
        // MSS option lives at offset 14+20+20 .. +4.
        assert_eq!(out[14 + 20 + 20], 2); // kind
        assert_eq!(out[14 + 20 + 21], 4); // len
        let mss = u16::from_be_bytes([out[14 + 20 + 22], out[14 + 20 + 23]]);
        assert_eq!(mss, 1460);
    }

    #[test]
    fn frame_ipv4_header_parses_roundtrip() {
        let seg = base();
        let mut out = [0u8; 128];
        let n = build_segment(&seg, &mut out).unwrap();
        let dec = ip_decode(&out[ETH_HDR_LEN..n], 0, false).expect("ip decode");
        assert_eq!(dec.protocol, IPPROTO_TCP);
        assert_eq!(dec.src_ip, 0x0a_00_00_02);
        assert_eq!(dec.dst_ip, 0x0a_00_00_01);
    }

    #[test]
    fn data_segment_with_payload_has_correct_tcp_csum() {
        let mut seg = base();
        let payload = b"HELLO";
        seg.flags = TCP_ACK | TCP_PSH;
        seg.mss_option = None;
        seg.payload = payload;
        let mut out = [0u8; 128];
        let n = build_segment(&seg, &mut out).unwrap();
        // 14 + 20 + 20 + 5 = 59
        assert_eq!(n, 59);
        // Verify csum by recomputing: zero out the csum bytes and fold.
        let tcp_start = ETH_HDR_LEN + IPV4_HDR_MIN;
        let mut scratch = out[tcp_start..n].to_vec();
        scratch[16] = 0;
        scratch[17] = 0;
        let expected = tcp_checksum(seg.src_ip, seg.dst_ip, scratch.len() as u32, &scratch);
        let actual = u16::from_be_bytes([out[tcp_start + 16], out[tcp_start + 17]]);
        assert_eq!(expected, actual);
    }

    #[test]
    fn output_too_small_returns_none() {
        let seg = base();
        let mut out = [0u8; 50];
        assert!(build_segment(&seg, &mut out).is_none());
    }

    #[test]
    fn rst_frame_has_rst_flag_and_no_options() {
        let mut seg = base();
        seg.flags = TCP_RST | TCP_ACK;
        seg.mss_option = None;
        let mut out = [0u8; 64];
        let n = build_segment(&seg, &mut out).unwrap();
        assert_eq!(n, 54);
        assert_eq!(out[14 + 20 + 13], TCP_RST | TCP_ACK);
    }
}
