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
    // The single-mbuf case: payload is inline in `seg.payload` — the
    // checksum is computed over the header + the same bytes we write
    // to `out`, and the IPv4 total-length / TCP pseudo-header length
    // fields use `seg.payload.len()`.
    build_segment_inner(seg, seg.payload, seg.payload.len() as u32, out)
}

/// Write L2+L3+TCP headers for a retransmit into `out`. The payload
/// itself lives in a separately-chained data mbuf downstream, so the
/// header mbuf contains NO payload bytes — but the IPv4 `total length`
/// field, the TCP pseudo-header checksum length, and the TCP checksum
/// itself MUST reflect the full on-wire segment.
///
/// Spec §6.5 "retransmit primitive": alloc fresh hdr mbuf, chain to the
/// original data mbuf, never edit the in-flight mbuf in place.
///
/// * `seg.payload` MUST be empty (`&[]`) — payload writes go into the
///   chained data mbuf, not `out`.
/// * `payload_for_csum` is the ACTUAL payload byte slice, read by the
///   caller from the held data mbuf via `resd_rte_pktmbuf_data` and
///   passed in only so the checksum folds in the payload contribution.
///
/// Returns the number of bytes written (header length only), or `None`
/// if `out` is too small or `payload_for_csum.len() > u16::MAX`.
///
/// Invariant: `build_retrans_header(seg_empty, p, out)` produces the
/// same L2/L3/TCP header bytes as `build_segment(seg_with_p, out)` —
/// specifically the IP total-length, TCP pseudo-header length, and TCP
/// checksum all match. Verified by unit test
/// `build_retrans_header_matches_build_segment_header_prefix`.
pub fn build_retrans_header(
    seg: &SegmentTx,
    payload_for_csum: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    debug_assert!(
        seg.payload.is_empty(),
        "build_retrans_header expects seg.payload == &[] — payload lives in chained data mbuf"
    );
    if payload_for_csum.len() > u16::MAX as usize {
        return None;
    }
    build_segment_inner(seg, payload_for_csum, payload_for_csum.len() as u32, out)
}

/// Shared implementation for `build_segment` and `build_retrans_header`.
///
/// * `seg.payload` is what actually gets WRITTEN to `out` after the TCP
///   header (may be empty for the retransmit-header case).
/// * `payload_for_csum` is what gets FOLDED into the TCP checksum. In
///   the single-mbuf case it is identical to `seg.payload`. In the
///   retransmit case it is the chained-data mbuf's bytes (so the
///   checksum matches what `build_segment` would produce on the
///   original TX).
/// * `declared_payload_len` is the IPv4 total-length / TCP pseudo-header
///   length field (always equals `payload_for_csum.len()` via the two
///   wrappers, but kept as a separate arg for clarity).
fn build_segment_inner(
    seg: &SegmentTx,
    payload_for_csum: &[u8],
    declared_payload_len: u32,
    out: &mut [u8],
) -> Option<usize> {
    let opts_len = seg.options.encoded_len();
    let tcp_hdr_len = TCP_HDR_MIN + opts_len;
    // Bytes we actually write to `out`: headers + (possibly empty) payload.
    let total_written = ETH_HDR_LEN + IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len();
    if out.len() < total_written {
        return None;
    }
    // Guard against a bogus declared_payload_len.
    let total_ip_len_u32 = (IPV4_HDR_MIN + tcp_hdr_len) as u32 + declared_payload_len;
    if total_ip_len_u32 > u16::MAX as u32 {
        return None;
    }

    // Ethernet
    out[0..6].copy_from_slice(&seg.dst_mac);
    out[6..12].copy_from_slice(&seg.src_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4 — total-length reflects the on-wire size (header + declared payload).
    let ip_start = ETH_HDR_LEN;
    let ip = &mut out[ip_start..ip_start + IPV4_HDR_MIN];
    let total_ip_len = total_ip_len_u32 as u16;
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

    // TCP header + options + (possibly empty) payload
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

    // TCP checksum: pseudo-header + TCP header + payload (folded from
    // `payload_for_csum`, which comes from either `seg.payload` or the
    // chained-mbuf bytes). tcp_seg_len in the pseudo-header matches
    // `declared_payload_len` + header length.
    let tcp_seg_len = tcp_hdr_len as u32 + declared_payload_len;
    let csum = tcp_checksum_split(
        seg.src_ip,
        seg.dst_ip,
        tcp_seg_len,
        &out[tcp_start..tcp_start + tcp_hdr_len],
        payload_for_csum,
    );
    out[tcp_start + 16] = (csum >> 8) as u8;
    out[tcp_start + 17] = (csum & 0xff) as u8;

    Some(total_written)
}

/// Pseudo-header checksum per RFC 9293 §3.1. Reuses `internet_checksum`
/// by folding a scratch buffer of pseudo-header + tcp segment bytes.
#[cfg(test)]
fn tcp_checksum(src_ip: u32, dst_ip: u32, tcp_seg_len: u32, tcp_bytes: &[u8]) -> u16 {
    tcp_checksum_split(src_ip, dst_ip, tcp_seg_len, tcp_bytes, &[])
}

/// Split-buffer variant: checksum = fold(pseudo-header || tcp_header_bytes
/// || payload_bytes). Used for the retransmit path where the TCP header
/// sits in the header mbuf but the payload lives in a separate chained
/// data mbuf. For the inline `build_segment` case the caller passes
/// `tcp_header_bytes` = the TCP header (including options) and
/// `payload_bytes` = `seg.payload`; the two-call result matches the old
/// single-buffer checksum bit-for-bit.
fn tcp_checksum_split(
    src_ip: u32,
    dst_ip: u32,
    tcp_seg_len: u32,
    tcp_header_bytes: &[u8],
    payload_bytes: &[u8],
) -> u16 {
    // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_len(2)
    let mut buf = Vec::with_capacity(12 + tcp_header_bytes.len() + payload_bytes.len());
    buf.extend_from_slice(&src_ip.to_be_bytes());
    buf.extend_from_slice(&dst_ip.to_be_bytes());
    buf.push(0);
    buf.push(IPPROTO_TCP);
    buf.extend_from_slice(&(tcp_seg_len as u16).to_be_bytes());
    buf.extend_from_slice(tcp_header_bytes);
    buf.extend_from_slice(payload_bytes);
    internet_checksum(&buf)
}

/// Pseudo-header-only TCP checksum per RFC 9293 §3.1. Used by A-HW's
/// TX offload path: software writes ONLY the 12-byte pseudo-header
/// fold into the TCP cksum field; the PMD folds in TCP header +
/// payload at wire time when `RTE_MBUF_F_TX_TCP_CKSUM` is set.
///
/// `tcp_seg_len` is the pseudo-header `tcp_length` field: the sum of
/// header-bytes and payload-bytes on the wire. For a 20-byte TCP header
/// with N bytes payload, tcp_seg_len = 20 + N.
pub fn tcp_pseudo_header_checksum(src_ip: u32, dst_ip: u32, tcp_seg_len: u32) -> u16 {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&src_ip.to_be_bytes());
    buf[4..8].copy_from_slice(&dst_ip.to_be_bytes());
    buf[8] = 0;
    buf[9] = IPPROTO_TCP;
    buf[10..12].copy_from_slice(&(tcp_seg_len as u16).to_be_bytes());
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
                mss: Some(1460),
                ..Default::default()
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

    // Task 9: retransmit primitive — the hdr-only builder must produce the
    // same L2/L3/TCP header bytes (including TCP checksum) as `build_segment`
    // would for the same SegmentTx if the payload were inline.
    #[test]
    fn build_retrans_header_matches_build_segment_header_prefix() {
        // Use an ACK+PSH data segment with a real payload. TS/SACK options
        // off keeps the header size aligned with the simplest case.
        let mut base = base();
        base.flags = TCP_ACK | TCP_PSH;
        base.options = crate::tcp_options::TcpOpts::default();
        let payload = b"hello-world";
        base.payload = payload;

        // Full segment with inline payload.
        let mut full_buf = [0u8; 128];
        let full_n = build_segment(&base, &mut full_buf).expect("build_segment");
        let hdr_len_expected = full_n - payload.len();

        // Retrans header: payload stripped from SegmentTx, payload_for_csum
        // carries the same bytes so the TCP checksum matches.
        let hdr_only_seg = SegmentTx {
            payload: &[],
            ..base
        };
        let mut hdr_buf = [0u8; 128];
        let hdr_n = build_retrans_header(&hdr_only_seg, payload, &mut hdr_buf)
            .expect("build_retrans_header");

        // Header length matches.
        assert_eq!(hdr_n, hdr_len_expected, "header length mismatch");
        // Byte-for-byte equality of the header region. This confirms:
        //   * IPv4 total-length field matches (uses declared payload len)
        //   * TCP checksum matches (pseudo-header payload len + payload
        //     bytes folded from `payload_for_csum`).
        assert_eq!(
            &full_buf[0..hdr_n],
            &hdr_buf[0..hdr_n],
            "header bytes should be identical across build_segment / build_retrans_header"
        );
    }

    #[test]
    fn build_retrans_header_with_options_matches_prefix() {
        // Same invariant with TS + SACK options present.
        let mut base = base();
        base.flags = TCP_ACK | TCP_PSH;
        base.options = crate::tcp_options::TcpOpts {
            timestamps: Some((0x1122_3344, 0xaabb_ccdd)),
            ..Default::default()
        };
        let payload = b"abcdefghij0123456789";
        base.payload = payload;

        let mut full_buf = [0u8; 160];
        let full_n = build_segment(&base, &mut full_buf).expect("build_segment");
        let hdr_len_expected = full_n - payload.len();

        let hdr_only_seg = SegmentTx {
            payload: &[],
            ..base
        };
        let mut hdr_buf = [0u8; 160];
        let hdr_n = build_retrans_header(&hdr_only_seg, payload, &mut hdr_buf)
            .expect("build_retrans_header");

        assert_eq!(hdr_n, hdr_len_expected);
        assert_eq!(&full_buf[0..hdr_n], &hdr_buf[0..hdr_n]);
    }

    #[test]
    fn build_retrans_header_returns_none_on_small_buf() {
        let seg = SegmentTx {
            payload: &[],
            ..base()
        };
        let mut out = [0u8; 30];
        assert!(build_retrans_header(&seg, b"payload", &mut out).is_none());
    }

    #[test]
    fn pseudo_header_only_cksum_matches_manual_fold() {
        use crate::l3_ip::internet_checksum;
        let src_ip: u32 = 0x0a000001;
        let dst_ip: u32 = 0x0a000002;
        let tcp_seg_len: u32 = 40;

        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&src_ip.to_be_bytes());
        pseudo.extend_from_slice(&dst_ip.to_be_bytes());
        pseudo.push(0);
        pseudo.push(crate::l3_ip::IPPROTO_TCP);
        pseudo.extend_from_slice(&(tcp_seg_len as u16).to_be_bytes());
        let manual = internet_checksum(&pseudo);

        let helper = tcp_pseudo_header_checksum(src_ip, dst_ip, tcp_seg_len);
        assert_eq!(helper, manual,
            "tcp_pseudo_header_checksum must match manual fold of the 12-byte pseudo-header");
    }
}
