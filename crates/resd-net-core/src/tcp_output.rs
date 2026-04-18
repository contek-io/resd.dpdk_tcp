//! TCP segment builders. Every builder emits a complete Ethernet + IPv4 +
//! TCP frame with optional TCP options (MSS / WS / SACK-permitted / TS /
//! SACK blocks). IPv4 header checksum is computed in software; TCP
//! checksum uses the pseudo-header form per RFC 9293 §3.1.
//!
//! Option encoding is delegated to `tcp_options::TcpOpts::encode` (canonical
//! order + NOP-word-alignment).

use crate::l2::{ETHERTYPE_IPV4, ETH_HDR_LEN};
use crate::l3_ip::{internet_checksum, IPPROTO_TCP};
use crate::tcp_options::TcpOpts;

pub const TCP_HDR_MIN: usize = 20;
pub const IPV4_HDR_MIN: usize = 20;
pub const FRAME_HDRS_MIN: usize = ETH_HDR_LEN + IPV4_HDR_MIN + TCP_HDR_MIN;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
/// URG (urgent pointer) flag. Stage 1 does not support URG; inbound URG
/// segments are dropped and counted via `tcp.rx_urgent_dropped` (A4
/// cross-phase backfill — spec §9.1.1 / plan task 19).
pub const TCP_URG: u8 = 0x20;

pub struct SegmentTx<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// Any combination of options; use `TcpOpts::default()` for none.
    pub options: TcpOpts,
    pub payload: &'a [u8],
}

pub fn build_segment(seg: &SegmentTx, out: &mut [u8]) -> Option<usize> {
    let opts_len = seg.options.encoded_len();
    let tcp_hdr_len = TCP_HDR_MIN + opts_len;
    let total = ETH_HDR_LEN + IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len();
    if out.len() < total { return None; }

    // Ethernet
    out[0..6].copy_from_slice(&seg.dst_mac);
    out[6..12].copy_from_slice(&seg.src_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4
    let ip_start = ETH_HDR_LEN;
    let ip = &mut out[ip_start..ip_start + IPV4_HDR_MIN];
    let total_ip_len = (IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len()) as u16;
    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0x0000u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    ip[10..12].copy_from_slice(&0x0000u16.to_be_bytes());
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
    th[12] = ((tcp_hdr_len / 4) as u8) << 4;
    th[13] = seg.flags;
    th[14..16].copy_from_slice(&seg.window.to_be_bytes());
    th[16..18].copy_from_slice(&0u16.to_be_bytes());
    th[18..20].copy_from_slice(&0u16.to_be_bytes());
    if opts_len > 0 {
        seg.options
            .encode(&mut th[TCP_HDR_MIN..TCP_HDR_MIN + opts_len])
            .expect("pre-sized exactly; encode must fit");
    }

    let payload_start = tcp_start + tcp_hdr_len;
    out[payload_start..payload_start + seg.payload.len()].copy_from_slice(seg.payload);

    let tcp_seg_len = (tcp_hdr_len + seg.payload.len()) as u32;
    let csum = tcp_checksum(
        seg.src_ip, seg.dst_ip, tcp_seg_len,
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
            options: crate::tcp_options::TcpOpts {
                mss: Some(1460), ..Default::default()
            },
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
        seg.options = crate::tcp_options::TcpOpts::default();
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
        seg.options = crate::tcp_options::TcpOpts::default();
        let mut out = [0u8; 64];
        let n = build_segment(&seg, &mut out).unwrap();
        assert_eq!(n, 54);
        assert_eq!(out[14 + 20 + 13], TCP_RST | TCP_ACK);
    }
}
