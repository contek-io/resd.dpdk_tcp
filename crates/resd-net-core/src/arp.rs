//! ARP (RFC 826) — static-gateway mode. We don't run a dynamic resolver on
//! the data path; the gateway MAC is supplied via config (or resolved
//! out-of-band). What this module provides:
//!   - decode inbound ARP (to recognize requests for our IP, and to read
//!     gratuitous replies that refresh the gateway's MAC)
//!   - build an ARP reply (so we remain reachable — peers' ARP caches
//!     expire ours if we never answer)
//!   - build a gratuitous ARP announcement (our periodic "I'm still here"
//!     per spec §8)
//!
//! All builders produce complete L2+ARP frames (42 bytes: 14 Eth + 28 ARP).

pub const ARP_HDR_LEN: usize = 28;
pub const ARP_FRAME_LEN: usize = 14 + ARP_HDR_LEN;
pub const ARP_HTYPE_ETH: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: u32,
    pub target_mac: [u8; 6],
    pub target_ip: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpDrop {
    Short,
    UnsupportedHardware,
    UnsupportedProtocol,
    UnsupportedOp,
}

/// Decode ARP starting at the Ethernet payload (28-byte ARP header).
pub fn arp_decode(eth_payload: &[u8]) -> Result<ArpPacket, ArpDrop> {
    if eth_payload.len() < ARP_HDR_LEN {
        return Err(ArpDrop::Short);
    }
    let htype = u16::from_be_bytes([eth_payload[0], eth_payload[1]]);
    let ptype = u16::from_be_bytes([eth_payload[2], eth_payload[3]]);
    let hlen = eth_payload[4];
    let plen = eth_payload[5];
    if htype != ARP_HTYPE_ETH || hlen != 6 {
        return Err(ArpDrop::UnsupportedHardware);
    }
    if ptype != ARP_PTYPE_IPV4 || plen != 4 {
        return Err(ArpDrop::UnsupportedProtocol);
    }
    let op = u16::from_be_bytes([eth_payload[6], eth_payload[7]]);
    if op != ARP_OP_REQUEST && op != ARP_OP_REPLY {
        return Err(ArpDrop::UnsupportedOp);
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&eth_payload[8..14]);
    let sender_ip = u32::from_be_bytes([
        eth_payload[14], eth_payload[15], eth_payload[16], eth_payload[17],
    ]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&eth_payload[18..24]);
    let target_ip = u32::from_be_bytes([
        eth_payload[24], eth_payload[25], eth_payload[26], eth_payload[27],
    ]);
    Ok(ArpPacket { op, sender_mac, sender_ip, target_mac, target_ip })
}

/// Build a complete Eth+ARP reply frame answering `request`.
/// Writes 42 bytes into `out`; returns 42 on success, or None if `out` is
/// too small.
pub fn build_arp_reply(
    our_mac: [u8; 6],
    our_ip: u32,
    request: &ArpPacket,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < ARP_FRAME_LEN {
        return None;
    }
    // Ethernet: dst = requester's MAC; src = us; type = ARP
    out[0..6].copy_from_slice(&request.sender_mac);
    out[6..12].copy_from_slice(&our_mac);
    out[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    // ARP body: reply announcing our_ip → our_mac
    write_arp_body(
        &mut out[14..],
        ARP_OP_REPLY,
        our_mac,
        our_ip,
        request.sender_mac,
        request.sender_ip,
    );
    Some(ARP_FRAME_LEN)
}

/// Build a gratuitous ARP request: sender = target = our IP; destination
/// MAC = broadcast. Peers update their ARP cache to our MAC on receipt.
pub fn build_gratuitous_arp(our_mac: [u8; 6], our_ip: u32, out: &mut [u8]) -> Option<usize> {
    if out.len() < ARP_FRAME_LEN {
        return None;
    }
    out[0..6].copy_from_slice(&[0xff; 6]); // broadcast
    out[6..12].copy_from_slice(&our_mac);
    out[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    write_arp_body(
        &mut out[14..],
        ARP_OP_REQUEST,
        our_mac,
        our_ip,
        [0u8; 6],   // target MAC unknown in gratuitous
        our_ip,     // target IP is us (that's what "gratuitous" means)
    );
    Some(ARP_FRAME_LEN)
}

fn write_arp_body(
    body: &mut [u8],
    op: u16,
    sender_mac: [u8; 6],
    sender_ip: u32,
    target_mac: [u8; 6],
    target_ip: u32,
) {
    body[0..2].copy_from_slice(&ARP_HTYPE_ETH.to_be_bytes());
    body[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    body[4] = 6;
    body[5] = 4;
    body[6..8].copy_from_slice(&op.to_be_bytes());
    body[8..14].copy_from_slice(&sender_mac);
    body[14..18].copy_from_slice(&sender_ip.to_be_bytes());
    body[18..24].copy_from_slice(&target_mac);
    body[24..28].copy_from_slice(&target_ip.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ArpPacket {
        ArpPacket {
            op: ARP_OP_REQUEST,
            sender_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            sender_ip: 0x0a_00_00_01,
            target_mac: [0u8; 6],
            target_ip: 0x0a_00_00_02,
        }
    }

    #[test]
    fn short_rejected() {
        assert_eq!(arp_decode(&[0u8; 10]), Err(ArpDrop::Short));
    }

    #[test]
    fn roundtrip_reply() {
        let req = sample_request();
        let mut buf = [0u8; ARP_FRAME_LEN];
        let n = build_arp_reply([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &req, &mut buf).unwrap();
        assert_eq!(n, ARP_FRAME_LEN);
        // Decode the ARP body portion back and verify.
        let decoded = arp_decode(&buf[14..]).expect("decode");
        assert_eq!(decoded.op, ARP_OP_REPLY);
        assert_eq!(decoded.sender_mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(decoded.sender_ip, 0x0a_00_00_02);
        assert_eq!(decoded.target_mac, req.sender_mac);
        assert_eq!(decoded.target_ip, req.sender_ip);
        // Ethernet header check
        assert_eq!(&buf[0..6], &req.sender_mac);
        assert_eq!(&buf[6..12], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&buf[12..14], &0x0806u16.to_be_bytes());
    }

    #[test]
    fn roundtrip_gratuitous() {
        let mut buf = [0u8; ARP_FRAME_LEN];
        let n = build_gratuitous_arp([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &mut buf).unwrap();
        assert_eq!(n, ARP_FRAME_LEN);
        let decoded = arp_decode(&buf[14..]).expect("decode");
        assert_eq!(decoded.op, ARP_OP_REQUEST);
        assert_eq!(decoded.sender_ip, 0x0a_00_00_02);
        assert_eq!(decoded.target_ip, 0x0a_00_00_02);
        // broadcast dst
        assert_eq!(&buf[0..6], &[0xff; 6]);
    }

    #[test]
    fn wrong_htype_rejected() {
        let mut body = [0u8; ARP_HDR_LEN];
        body[0..2].copy_from_slice(&5u16.to_be_bytes()); // bogus htype
        body[4] = 6;
        body[5] = 4;
        assert_eq!(arp_decode(&body), Err(ArpDrop::UnsupportedHardware));
    }

    #[test]
    fn wrong_op_rejected() {
        let req = sample_request();
        let mut buf = [0u8; ARP_FRAME_LEN];
        build_arp_reply([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &req, &mut buf).unwrap();
        buf[14 + 7] = 0x09; // corrupt op low byte
        assert_eq!(arp_decode(&buf[14..]), Err(ArpDrop::UnsupportedOp));
    }

    #[test]
    fn buffer_too_small_for_reply() {
        let req = sample_request();
        let mut buf = [0u8; 10];
        assert!(build_arp_reply([1; 6], 0, &req, &mut buf).is_none());
    }
}
