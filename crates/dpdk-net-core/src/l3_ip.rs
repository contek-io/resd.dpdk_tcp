//! IPv4 decode. Operates on the Ethernet payload (slice starting at the IP
//! header). Returns the decoded header or a drop reason. Checksum is
//! verified only when the NIC didn't (caller passes `nic_csum_ok=true` to
//! skip). Fragments are never accepted — spec §6.3 defers IPv4 reassembly.

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L3Decoded {
    pub protocol: u8,
    pub src_ip: u32, // host byte order
    pub dst_ip: u32, // host byte order
    pub header_len: usize,
    pub total_len: usize,
    pub ttl: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3Drop {
    Short,            // fewer than 20 bytes
    BadVersion,       // version != 4
    BadHeaderLen,     // IHL < 5 or header extends past slice
    BadTotalLen,      // total_length < header_len or > slice
    CsumBad,          // checksum verify failed
    TtlZero,          // TTL == 0 on ingress (RFC 791; we drop rather than send ICMP)
    Fragment,         // MF=1 or frag_offset != 0
    NotOurs,          // dst_ip != our_ip (and our_ip != 0)
    UnsupportedProto, // protocol is not TCP and not ICMP
}

/// Compute the Internet checksum (RFC 1071) over a disjoint set of byte slices.
/// Folds each chunk in order, carrying an odd-boundary byte across chunk
/// transitions so the result is bit-for-bit identical to folding a single
/// concatenated buffer. A6.5 §7.6: callers pre-build pseudo-headers as
/// stack arrays and pass `&[&pseudo, tcp_hdr, payload]` without allocating.
pub fn internet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry: Option<u8> = None;
    for chunk in chunks {
        let mut i = 0usize;
        // Handle a carry-over odd byte from the previous chunk by pairing
        // it with the first byte of this chunk, if any.
        if let Some(high) = carry.take() {
            if let Some(&low) = chunk.first() {
                sum = sum.wrapping_add(u16::from_be_bytes([high, low]) as u32);
                i = 1;
            } else {
                carry = Some(high);
                continue;
            }
        }
        while i + 1 < chunk.len() {
            sum = sum.wrapping_add(u16::from_be_bytes([chunk[i], chunk[i + 1]]) as u32);
            i += 2;
        }
        if i < chunk.len() {
            carry = Some(chunk[i]);
        }
    }
    if let Some(tail) = carry {
        sum = sum.wrapping_add((tail as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Decode an IPv4 packet. `our_ip` in host byte order; 0 = accept any dst.
/// `nic_csum_ok`: when true the caller promises the NIC's HW csum passed.
pub fn ip_decode(pkt: &[u8], our_ip: u32, nic_csum_ok: bool) -> Result<L3Decoded, L3Drop> {
    if pkt.len() < 20 {
        return Err(L3Drop::Short);
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return Err(L3Drop::BadVersion);
    }
    let ihl = (pkt[0] & 0x0f) as usize;
    let header_len = ihl * 4;
    if ihl < 5 || header_len > pkt.len() {
        return Err(L3Drop::BadHeaderLen);
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < header_len || total_len > pkt.len() {
        return Err(L3Drop::BadTotalLen);
    }
    // Fragment detection: the flags+fragoffset field is bytes 6..8; bit 13
    // from the MSB is MF (More Fragments), low 13 bits are the offset.
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let mf = (flags_frag & 0x2000) != 0;
    let frag_off = flags_frag & 0x1fff;
    if mf || frag_off != 0 {
        return Err(L3Drop::Fragment);
    }
    let ttl = pkt[8];
    if ttl == 0 {
        return Err(L3Drop::TtlZero);
    }
    // Checksum: verify only when NIC didn't. Zero the checksum bytes in a
    // scratch copy and fold — the computed value should equal what's in the
    // header.
    if !nic_csum_ok {
        let mut scratch = [0u8; 60]; // max IP header length
        scratch[..header_len].copy_from_slice(&pkt[..header_len]);
        scratch[10] = 0;
        scratch[11] = 0;
        let computed = internet_checksum(&[&scratch[..header_len]]);
        let stored = u16::from_be_bytes([pkt[10], pkt[11]]);
        if computed != stored {
            return Err(L3Drop::CsumBad);
        }
    }
    let protocol = pkt[9];
    let src_ip = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    let dst_ip = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
    if our_ip != 0 && dst_ip != our_ip {
        return Err(L3Drop::NotOurs);
    }
    if protocol != IPPROTO_TCP && protocol != IPPROTO_ICMP {
        return Err(L3Drop::UnsupportedProto);
    }
    Ok(L3Decoded {
        protocol,
        src_ip,
        dst_ip,
        header_len,
        total_len,
        ttl,
    })
}

/// RX checksum classification from `mbuf.ol_flags`, per DPDK's 2-bit
/// encoding on the RTE_MBUF_F_RX_IP_CKSUM_MASK / L4_CKSUM_MASK bits.
/// Feature-gated on `hw-offload-rx-cksum`; absent from feature-off builds.
/// See spec §7.
#[cfg(feature = "hw-offload-rx-cksum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CksumOutcome {
    /// NIC did not verify — software verify required.
    Unknown,
    /// NIC verified and rejected — drop.
    Bad,
    /// NIC verified and accepted — skip software verify.
    Good,
    /// NIC explicitly signaled no verification — software verify required.
    None,
}

/// Map the IP-cksum bits in `ol_flags` (masked by
/// RTE_MBUF_F_RX_IP_CKSUM_MASK) to a `CksumOutcome`. See spec §7.
#[cfg(feature = "hw-offload-rx-cksum")]
pub fn classify_ip_rx_cksum(ol_flags: u64) -> CksumOutcome {
    use crate::dpdk_consts::{
        RTE_MBUF_F_RX_IP_CKSUM_BAD, RTE_MBUF_F_RX_IP_CKSUM_GOOD, RTE_MBUF_F_RX_IP_CKSUM_MASK,
        RTE_MBUF_F_RX_IP_CKSUM_NONE,
    };
    let m = ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK;
    if m == RTE_MBUF_F_RX_IP_CKSUM_GOOD {
        CksumOutcome::Good
    } else if m == RTE_MBUF_F_RX_IP_CKSUM_BAD {
        CksumOutcome::Bad
    } else if m == RTE_MBUF_F_RX_IP_CKSUM_NONE {
        CksumOutcome::None
    } else {
        CksumOutcome::Unknown
    }
}

/// Map the L4-cksum bits in `ol_flags` (masked by
/// RTE_MBUF_F_RX_L4_CKSUM_MASK) to a `CksumOutcome`. See spec §7.
#[cfg(feature = "hw-offload-rx-cksum")]
pub fn classify_l4_rx_cksum(ol_flags: u64) -> CksumOutcome {
    use crate::dpdk_consts::{
        RTE_MBUF_F_RX_L4_CKSUM_BAD, RTE_MBUF_F_RX_L4_CKSUM_GOOD, RTE_MBUF_F_RX_L4_CKSUM_MASK,
        RTE_MBUF_F_RX_L4_CKSUM_NONE,
    };
    let m = ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK;
    if m == RTE_MBUF_F_RX_L4_CKSUM_GOOD {
        CksumOutcome::Good
    } else if m == RTE_MBUF_F_RX_L4_CKSUM_BAD {
        CksumOutcome::Bad
    } else if m == RTE_MBUF_F_RX_L4_CKSUM_NONE {
        CksumOutcome::None
    } else {
        CksumOutcome::Unknown
    }
}

/// Offload-aware IP decode entry point for the RX path. Consumes
/// `mbuf.ol_flags` to decide whether software IP-cksum verify is
/// needed, and drops+counter-bumps on NIC-reported BAD. When
/// `hw-offload-rx-cksum` is compile-off OR the engine's runtime latch
/// `rx_cksum_offload_active` is false, forwards directly to
/// `ip_decode(.., nic_csum_ok=false)` — always software verify. See
/// spec §7.2 (runtime fallback on non-advertising PMDs).
pub fn ip_decode_offload_aware(
    pkt: &[u8],
    our_ip: u32,
    #[allow(unused_variables)] ol_flags: u64,
    #[allow(unused_variables)] rx_cksum_offload_active: bool,
    #[allow(unused_variables)] counters: &crate::counters::Counters,
) -> Result<L3Decoded, L3Drop> {
    #[cfg(feature = "hw-offload-rx-cksum")]
    {
        if !rx_cksum_offload_active {
            return ip_decode(pkt, our_ip, false);
        }
        use std::sync::atomic::Ordering;
        match classify_ip_rx_cksum(ol_flags) {
            CksumOutcome::Good => ip_decode(pkt, our_ip, true),
            CksumOutcome::Bad => {
                counters
                    .eth
                    .rx_drop_cksum_bad
                    .fetch_add(1, Ordering::Relaxed);
                counters.ip.rx_csum_bad.fetch_add(1, Ordering::Relaxed);
                Err(L3Drop::CsumBad)
            }
            _ => ip_decode(pkt, our_ip, false),
        }
    }
    #[cfg(not(feature = "hw-offload-rx-cksum"))]
    {
        let _ = ol_flags;
        let _ = rx_cksum_offload_active;
        let _ = counters;
        ip_decode(pkt, our_ip, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid IPv4 header with an optional wrong-checksum flag.
    fn build_ip_hdr(proto: u8, src: u32, dst: u32, payload_len: usize, bad_csum: bool) -> Vec<u8> {
        let total = 20 + payload_len;
        let mut v = vec![
            0x45, // version 4, IHL 5
            0x00, // DSCP/ECN
            (total >> 8) as u8,
            (total & 0xff) as u8, // total length
            0x00,
            0x01, // identification
            0x40,
            0x00,  // flags=DF, fragment offset 0
            0x40,  // TTL 64
            proto, // protocol
            0x00,
            0x00, // checksum placeholder
        ];
        v.extend_from_slice(&src.to_be_bytes());
        v.extend_from_slice(&dst.to_be_bytes());
        let cksum = internet_checksum(&[&v]);
        v[10] = (cksum >> 8) as u8;
        v[11] = (cksum & 0xff) as u8;
        if bad_csum {
            v[10] ^= 0xff; // corrupt
        }
        v.resize(total, 0);
        v
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn checksum_folds_correctly() {
        let h = build_ip_hdr(IPPROTO_TCP, 0x0a000001, 0x0a000002, 0, false);
        // Scratch-zero csum bytes, recompute, compare against stored.
        let mut s = h[..20].to_vec();
        s[10] = 0;
        s[11] = 0;
        let computed = internet_checksum(&[&s]);
        let stored = u16::from_be_bytes([h[10], h[11]]);
        assert_eq!(computed, stored);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn short_packet_dropped() {
        assert_eq!(ip_decode(&[0u8; 10], 0, true), Err(L3Drop::Short));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn bad_version_dropped() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[0] = 0x65; // version 6
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::BadVersion));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn bad_header_len_dropped() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[0] = 0x44; // IHL 4
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::BadHeaderLen));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn bad_total_len_dropped() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[2] = 0x00;
        h[3] = 0x10; // total_length=16 < header_len=20
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::BadTotalLen));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn fragment_dropped_mf() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[6] = 0x20; // set MF bit
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::Fragment));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn fragment_dropped_offset() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[6] = 0x00;
        h[7] = 0x01; // offset=1
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::Fragment));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn ttl_zero_dropped() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[8] = 0;
        // need to refresh csum after editing TTL
        h[10] = 0;
        h[11] = 0;
        let cks = internet_checksum(&[&h[..20]]);
        h[10] = (cks >> 8) as u8;
        h[11] = (cks & 0xff) as u8;
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::TtlZero));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn bad_csum_dropped_when_verifying() {
        let h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, true);
        assert_eq!(ip_decode(&h, 0, false), Err(L3Drop::CsumBad));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn bad_csum_passes_when_nic_ok() {
        let h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, true);
        assert!(ip_decode(&h, 0, true).is_ok());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn not_ours_dropped() {
        let h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        assert_eq!(ip_decode(&h, 99, true), Err(L3Drop::NotOurs));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn unsupported_proto_dropped() {
        let h = build_ip_hdr(17 /* UDP */, 1, 2, 0, false);
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::UnsupportedProto));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn tcp_accepted() {
        let h = build_ip_hdr(IPPROTO_TCP, 1, 2, 10, false);
        let d = ip_decode(&h, 0, true).expect("accepted");
        assert_eq!(d.protocol, IPPROTO_TCP);
        assert_eq!(d.header_len, 20);
        assert_eq!(d.total_len, 30);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn icmp_accepted() {
        let h = build_ip_hdr(IPPROTO_ICMP, 1, 2, 4, false);
        let d = ip_decode(&h, 0, true).expect("accepted");
        assert_eq!(d.protocol, IPPROTO_ICMP);
    }

    #[cfg(feature = "hw-offload-rx-cksum")]
    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_ip_cksum_from_ol_flags() {
        use crate::dpdk_consts::{
            RTE_MBUF_F_RX_IP_CKSUM_BAD, RTE_MBUF_F_RX_IP_CKSUM_GOOD,
            RTE_MBUF_F_RX_IP_CKSUM_NONE, RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN,
        };
        assert_eq!(
            classify_ip_rx_cksum(RTE_MBUF_F_RX_IP_CKSUM_GOOD),
            CksumOutcome::Good
        );
        assert_eq!(
            classify_ip_rx_cksum(RTE_MBUF_F_RX_IP_CKSUM_BAD),
            CksumOutcome::Bad
        );
        assert_eq!(
            classify_ip_rx_cksum(RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN),
            CksumOutcome::Unknown
        );
        assert_eq!(
            classify_ip_rx_cksum(RTE_MBUF_F_RX_IP_CKSUM_NONE),
            CksumOutcome::None
        );
    }

    #[cfg(feature = "hw-offload-rx-cksum")]
    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_l4_cksum_from_ol_flags() {
        use crate::dpdk_consts::{
            RTE_MBUF_F_RX_L4_CKSUM_BAD, RTE_MBUF_F_RX_L4_CKSUM_GOOD,
            RTE_MBUF_F_RX_L4_CKSUM_NONE, RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN,
        };
        assert_eq!(
            classify_l4_rx_cksum(RTE_MBUF_F_RX_L4_CKSUM_GOOD),
            CksumOutcome::Good
        );
        assert_eq!(
            classify_l4_rx_cksum(RTE_MBUF_F_RX_L4_CKSUM_BAD),
            CksumOutcome::Bad
        );
        assert_eq!(
            classify_l4_rx_cksum(RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN),
            CksumOutcome::Unknown
        );
        assert_eq!(
            classify_l4_rx_cksum(RTE_MBUF_F_RX_L4_CKSUM_NONE),
            CksumOutcome::None
        );
    }
}
