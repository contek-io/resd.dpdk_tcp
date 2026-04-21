//! L2 Ethernet frame decoder. Operates on a raw byte slice (typically the
//! mbuf data region). No allocation. Pure. Each decision is counter-grade
//! (one counter per drop reason) so the caller can attribute every drop.

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETH_HDR_LEN: usize = 14;
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Decoded {
    pub ethertype: u16,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub payload_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Drop {
    Short,            // frame shorter than 14 bytes
    MissMac,          // dst MAC is not us and not broadcast
    UnknownEthertype, // neither IPv4 nor ARP
}

/// Decode an Ethernet II frame. Accepts broadcast (ff:ff:ff:ff:ff:ff) for ARP.
/// Non-broadcast multicast is classified as MissMac (we don't join groups in Stage 1).
/// `our_mac = [0;6]` is test mode — accept any unicast destination.
pub fn l2_decode(frame: &[u8], our_mac: [u8; 6]) -> Result<L2Decoded, L2Drop> {
    if frame.len() < ETH_HDR_LEN {
        return Err(L2Drop::Short);
    }
    let mut dst = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    let mut src = [0u8; 6];
    src.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    let is_broadcast = dst == BROADCAST_MAC;
    let is_us = our_mac != [0u8; 6] && dst == our_mac;
    let is_any = our_mac == [0u8; 6]; // test/open-mode
    if !(is_broadcast || is_us || is_any) {
        return Err(L2Drop::MissMac);
    }

    if ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_ARP {
        return Err(L2Drop::UnknownEthertype);
    }

    Ok(L2Decoded {
        ethertype,
        src_mac: src,
        dst_mac: dst,
        payload_offset: ETH_HDR_LEN,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(dst: [u8; 6], src: [u8; 6], et: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(14 + payload.len());
        v.extend_from_slice(&dst);
        v.extend_from_slice(&src);
        v.extend_from_slice(&et.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn short_frame_dropped() {
        assert_eq!(l2_decode(&[0u8; 10], [1; 6]), Err(L2Drop::Short));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn wrong_dst_mac_dropped() {
        let us = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let wrong = [0xaa; 6];
        let f = frame(wrong, [0; 6], ETHERTYPE_IPV4, &[]);
        assert_eq!(l2_decode(&f, us), Err(L2Drop::MissMac));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn correct_dst_mac_accepted() {
        let us = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let f = frame(us, [0; 6], ETHERTYPE_IPV4, &[0xde, 0xad]);
        let d = l2_decode(&f, us).expect("accepted");
        assert_eq!(d.ethertype, ETHERTYPE_IPV4);
        assert_eq!(d.payload_offset, 14);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn broadcast_accepted_for_arp() {
        let us = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let f = frame(BROADCAST_MAC, [0; 6], ETHERTYPE_ARP, &[]);
        assert!(l2_decode(&f, us).is_ok());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn unknown_ethertype_dropped() {
        let us = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let f = frame(us, [0; 6], 0x86DD, &[]); // IPv6
        assert_eq!(l2_decode(&f, us), Err(L2Drop::UnknownEthertype));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn zero_our_mac_accepts_any() {
        let dst = [0x99; 6];
        let f = frame(dst, [0; 6], ETHERTYPE_IPV4, &[]);
        assert!(l2_decode(&f, [0; 6]).is_ok());
    }
}
