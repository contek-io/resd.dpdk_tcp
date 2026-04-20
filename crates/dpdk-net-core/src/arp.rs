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
//! All builders produce complete L2+ARP frames padded to the 60-byte
//! Ethernet minimum (14 Eth + 28 ARP + 18 pad). Without padding, peers'
//! MAC-layer RX is permitted by 802.3 to silently drop the runt frame.

pub const ARP_HDR_LEN: usize = 28;
/// Ethernet requires a minimum payload of 46 bytes (60-byte min frame
/// before FCS minus the 14-byte header). Our ARP body is only 28 bytes,
/// so we pad by 18 to avoid runt-frame drops at the receiver.
pub const ARP_PAD_LEN: usize = 18;
pub const ARP_FRAME_LEN: usize = 14 + ARP_HDR_LEN + ARP_PAD_LEN;
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
        eth_payload[14],
        eth_payload[15],
        eth_payload[16],
        eth_payload[17],
    ]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&eth_payload[18..24]);
    let target_ip = u32::from_be_bytes([
        eth_payload[24],
        eth_payload[25],
        eth_payload[26],
        eth_payload[27],
    ]);
    Ok(ArpPacket {
        op,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

/// Build a complete Eth+ARP reply frame answering `request`.
/// Writes `ARP_FRAME_LEN` (60) bytes into `out`, zero-padded to the
/// Ethernet minimum; returns 60 on success, or None if `out` is too small.
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
    // Pad to Ethernet minimum to avoid runt-frame drops at the receiver.
    out[14 + ARP_HDR_LEN..ARP_FRAME_LEN].fill(0);
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
        [0u8; 6], // target MAC unknown in gratuitous
        our_ip,   // target IP is us (that's what "gratuitous" means)
    );
    // Pad to Ethernet minimum to avoid runt-frame drops at the receiver.
    out[14 + ARP_HDR_LEN..ARP_FRAME_LEN].fill(0);
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

/// Parse one line of `/proc/net/arp` into (ip_host_order, mac_bytes).
/// Returns None for the header line or for entries with flags==0x0
/// (incomplete).
pub(crate) fn parse_proc_arp_line(line: &str) -> Option<(u32, [u8; 6])> {
    // Columns: IPaddress  HWtype  Flags  HWaddress  Mask  Device
    let mut fields = line.split_whitespace();
    let ip = fields.next()?;
    let _hw = fields.next()?;
    let flags = fields.next()?;
    let mac = fields.next()?;

    if !flags.starts_with("0x") {
        return None;
    }
    let flags_u = u32::from_str_radix(&flags[2..], 16).ok()?;
    if flags_u & 0x2 == 0 {
        // ATF_COM bit not set — entry isn't complete.
        return None;
    }

    let mut octets = ip.split('.');
    let a = octets.next()?.parse::<u8>().ok()?;
    let b = octets.next()?.parse::<u8>().ok()?;
    let c = octets.next()?.parse::<u8>().ok()?;
    let d = octets.next()?.parse::<u8>().ok()?;
    let ip_u = u32::from_be_bytes([a, b, c, d]);

    let mut mac_bytes = [0u8; 6];
    let mut parts = mac.split(':');
    for b in &mut mac_bytes {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    Some((ip_u, mac_bytes))
}

/// Read `/proc/net/arp` and return the MAC address for `ip`.
pub fn resolve_from_proc_arp(ip: u32) -> Result<[u8; 6], crate::Error> {
    let text = std::fs::read_to_string("/proc/net/arp")
        .map_err(|e| crate::Error::ProcArpRead(e.to_string()))?;
    for line in text.lines().skip(1) {
        if let Some((entry_ip, mac)) = parse_proc_arp_line(line) {
            if entry_ip == ip {
                return Ok(mac);
            }
        }
    }
    Err(crate::Error::GatewayMacNotFound(ip))
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

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn short_rejected() {
        assert_eq!(arp_decode(&[0u8; 10]), Err(ArpDrop::Short));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
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

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
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

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn reply_is_padded_to_ethernet_minimum() {
        let req = sample_request();
        let mut buf = [0u8; ARP_FRAME_LEN];
        let n = build_arp_reply([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &req, &mut buf).unwrap();
        assert_eq!(
            n, 60,
            "ARP reply must be Ethernet-min (60 bytes) to avoid runts"
        );
        assert_eq!(ARP_FRAME_LEN, 60);
        // Pad bytes (42..60) must be zero.
        for (i, &b) in buf[42..].iter().enumerate() {
            assert_eq!(b, 0, "pad byte {i} not zero");
        }
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn gratuitous_is_padded_to_ethernet_minimum() {
        let mut buf = [0u8; ARP_FRAME_LEN];
        let n = build_gratuitous_arp([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &mut buf).unwrap();
        assert_eq!(n, 60);
        for (i, &b) in buf[42..].iter().enumerate() {
            assert_eq!(b, 0, "pad byte {i} not zero");
        }
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn wrong_htype_rejected() {
        let mut body = [0u8; ARP_HDR_LEN];
        body[0..2].copy_from_slice(&5u16.to_be_bytes()); // bogus htype
        body[4] = 6;
        body[5] = 4;
        assert_eq!(arp_decode(&body), Err(ArpDrop::UnsupportedHardware));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn wrong_op_rejected() {
        let req = sample_request();
        let mut buf = [0u8; ARP_FRAME_LEN];
        build_arp_reply([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &req, &mut buf).unwrap();
        buf[14 + 7] = 0x09; // corrupt op low byte
        assert_eq!(arp_decode(&buf[14..]), Err(ArpDrop::UnsupportedOp));
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn buffer_too_small_for_reply() {
        let req = sample_request();
        let mut buf = [0u8; 10];
        assert!(build_arp_reply([1; 6], 0, &req, &mut buf).is_none());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn parse_proc_arp_line_sample() {
        let line = "10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
        let (ip, mac) = super::parse_proc_arp_line(line).expect("parsed");
        assert_eq!(ip, 0x0a_00_00_01);
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn parse_proc_arp_incomplete_entry_rejected() {
        // Flags 0x0 means entry is incomplete — don't use it.
        let line = "10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        assert!(super::parse_proc_arp_line(line).is_none());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn resolve_from_proc_arp_missing_returns_not_found() {
        // Address we are extremely unlikely to have — 0.0.0.1 is never
        // a valid gateway and will not appear in any /proc/net/arp.
        let err = super::resolve_from_proc_arp(0x0000_0001).unwrap_err();
        assert!(matches!(err, crate::Error::GatewayMacNotFound(_)));
    }
}
