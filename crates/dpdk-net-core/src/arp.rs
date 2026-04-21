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

/// Per-packet decision output of [`classify_arp`]. Pure policy; the
/// engine is responsible for executing it (building a reply, mutating
/// the learned-gateway cell). Split out so the classifier is unit-
/// testable without standing up an EAL / Engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpAction {
    /// No action required. Frame addressed to someone else, or the
    /// sender is not one we learn from.
    None,
    /// Inbound REQUEST targets our IP — answer it so peers' ARP caches
    /// don't expire us.
    SendReply,
    /// Sender is the configured gateway; learn (or refresh) its MAC.
    /// Fires on REPLY(sender_ip == gateway_ip) and on gratuitous
    /// REQUEST(sender_ip == target_ip == gateway_ip).
    UpdateGatewayMac([u8; 6]),
}

/// Decide what to do with a decoded inbound ARP packet.
///
/// Policy:
/// * Any REQUEST whose `target_ip == local_ip` (and `local_ip != 0`)
///   gets a reply. This branch short-circuits — even if the requester
///   is the gateway, we just answer and move on; the gateway's
///   subsequent cache update will not flow through the `UpdateGatewayMac`
///   path on this frame. That's fine: gateway MAC learning is already
///   handled on REPLY and gratuitous-REQUEST paths, and a unicast
///   REQUEST from the gateway is an uncommon trigger.
/// * Any REPLY whose `sender_ip == gateway_ip` updates our learned
///   gateway MAC (RFC 826 resolver response). We intentionally accept
///   overheard replies targeted at other hosts too — if the gateway
///   answered someone else's ARP, the sender_mac is still authoritative
///   for `gateway_ip`.
/// * A gratuitous REQUEST (sender_ip == target_ip == gateway_ip) also
///   updates the learned MAC. Useful when the gateway failover emits a
///   gratuitous announce.
/// * Otherwise no-op.
///
/// `gateway_ip == 0` disables learning entirely — we refuse to bind a
/// MAC to "some IP we don't know".
pub fn classify_arp(pkt: &ArpPacket, local_ip: u32, gateway_ip: u32) -> ArpAction {
    if pkt.op == ARP_OP_REQUEST && local_ip != 0 && pkt.target_ip == local_ip {
        return ArpAction::SendReply;
    }
    if gateway_ip != 0 && pkt.sender_ip == gateway_ip {
        let is_reply = pkt.op == ARP_OP_REPLY;
        let is_gratuitous = pkt.op == ARP_OP_REQUEST && pkt.target_ip == gateway_ip;
        if is_reply || is_gratuitous {
            return ArpAction::UpdateGatewayMac(pkt.sender_mac);
        }
    }
    ArpAction::None
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

/// Build an ARP REQUEST asking for `target_ip`'s MAC. Destination MAC
/// is broadcast (0xff…). Symmetric counterpart to [`build_gratuitous_arp`];
/// the engine emits this when the configured gateway IP is known but the
/// MAC has not yet been learned.
pub fn build_arp_request(
    our_mac: [u8; 6],
    our_ip: u32,
    target_ip: u32,
    out: &mut [u8],
) -> Option<usize> {
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
        [0u8; 6], // target MAC unknown — that's what we're asking
        target_ip,
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

// RTF flag bits (from <linux/route.h>): the two we care about for finding
// a usable default-route gateway entry in /proc/net/route.
const RTF_UP: u32 = 0x0001;
const RTF_GATEWAY: u32 = 0x0002;

/// Parse one data line of `/proc/net/route`. Returns `Some(gw_ip_host_order)`
/// iff this line is a *default route* (Destination==0, Mask==0) flagged
/// `RTF_UP | RTF_GATEWAY`.
///
/// The file's address fields (Destination, Gateway, Mask) are 8-char hex
/// strings in little-endian byte order — i.e. the bytes as they live in
/// kernel memory on a little-endian host. We reconstruct the host-order
/// u32 (MSB = first dotted-quad octet) with a single `swap_bytes()` after
/// the naive hex parse.
///
/// `iface_filter == Some(name)` restricts matches to that interface.
/// `iface_filter == None` accepts any interface.
pub(crate) fn parse_proc_route_line(line: &str, iface_filter: Option<&str>) -> Option<u32> {
    // Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
    // We read through Mask (field 8) and ignore MTU/Window/IRTT — they
    // don't affect whether this is a usable default-route gateway.
    let mut fields = line.split_whitespace();
    let iface = fields.next()?;
    let dest = fields.next()?;
    let gw = fields.next()?;
    let flags = fields.next()?;
    let _refcnt = fields.next()?;
    let _use = fields.next()?;
    let _metric = fields.next()?;
    let mask = fields.next()?;

    if let Some(want) = iface_filter {
        if iface != want {
            return None;
        }
    }
    // Data lines contain only hex digits in Destination/Gateway/Mask.
    // The header line fails the hex parse and yields None from the `?`s
    // below — no explicit header check needed.
    let dest_u = u32::from_str_radix(dest, 16).ok()?;
    let mask_u = u32::from_str_radix(mask, 16).ok()?;
    let flags_u = u32::from_str_radix(flags, 16).ok()?;
    if dest_u != 0 || mask_u != 0 {
        return None;
    }
    if flags_u & (RTF_UP | RTF_GATEWAY) != (RTF_UP | RTF_GATEWAY) {
        return None;
    }
    let gw_raw = u32::from_str_radix(gw, 16).ok()?;
    // File is LE-stored; swap to host-order where MSB is the first octet.
    Some(gw_raw.swap_bytes())
}

/// Read `/proc/net/route` and return the default-gateway IPv4 in host
/// byte order. `iface_filter == Some(name)` restricts the search to that
/// interface; `None` returns the first default-route line found.
///
/// This MUST be called while the kernel still owns the NIC — once DPDK
/// binds the port, the kernel route table no longer tracks it.
pub fn read_default_gateway_ip(iface_filter: Option<&str>) -> Result<u32, crate::Error> {
    let text = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| crate::Error::ProcRouteRead(e.to_string()))?;
    for line in text.lines() {
        if let Some(gw) = parse_proc_route_line(line, iface_filter) {
            return Ok(gw);
        }
    }
    Err(crate::Error::GatewayIpNotFound(
        iface_filter.map(|s| s.to_owned()),
    ))
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

    // /proc/net/route columns (tab-separated):
    //   Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
    // Addresses are hex strings in little-endian byte order. A default
    // route is Destination=0, Mask=0, flags & (UP|GATEWAY) == (UP|GATEWAY).
    const ROUTE_DEFAULT_ETH0: &str =
        "eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0";
    const ROUTE_SUBNET_ETH0: &str =
        "eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0";
    const ROUTE_DEFAULT_ETH1: &str =
        "eth1\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0";

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn parse_proc_route_default_gateway() {
        // Gateway field `0100000A` = LE-stored bytes [0x01,0x00,0x00,0x0A]
        // = IPv4 10.0.0.1 in host order = 0x0A000001.
        let got = super::parse_proc_route_line(ROUTE_DEFAULT_ETH0, None).expect("parsed");
        assert_eq!(got, 0x0a000001);
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn parse_proc_route_ignores_non_default() {
        // Mask != 0 means it's a subnet route, not a default route.
        assert!(super::parse_proc_route_line(ROUTE_SUBNET_ETH0, None).is_none());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn parse_proc_route_ignores_non_gateway_flag() {
        // Flags 0x1 = UP only (no GATEWAY bit). The kernel uses this for
        // directly-reachable routes — no gateway to learn. Use a
        // zero-Destination/zero-Mask line otherwise identical to the
        // default-route line so the *only* thing that changes is the
        // flags value.
        let line = "eth0\t00000000\t0100000A\t0001\t0\t0\t0\t00000000\t0\t0\t0";
        assert!(super::parse_proc_route_line(line, None).is_none());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn parse_proc_route_iface_filter() {
        // eth0 and eth1 each have a default route. Filter="eth1" selects
        // the eth1 line; filter="eth0" selects eth0; filter rejects the
        // other.
        let eth0 = super::parse_proc_route_line(ROUTE_DEFAULT_ETH0, Some("eth0"));
        assert_eq!(eth0, Some(0x0a000001));
        let eth1 = super::parse_proc_route_line(ROUTE_DEFAULT_ETH1, Some("eth1"));
        // 0101A8C0 LE → bytes [0x01,0x01,0xA8,0xC0] → 192.168.1.1 host
        assert_eq!(eth1, Some(0xc0a80101));
        assert!(super::parse_proc_route_line(ROUTE_DEFAULT_ETH0, Some("eth1")).is_none());
        assert!(super::parse_proc_route_line(ROUTE_DEFAULT_ETH1, Some("eth0")).is_none());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn parse_proc_route_header_rejected() {
        // The first line of /proc/net/route is the column header.
        let hdr = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";
        assert!(super::parse_proc_route_line(hdr, None).is_none());
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn read_default_gateway_ip_missing_iface_returns_not_found() {
        // A clearly-nonexistent interface name must yield
        // GatewayIpNotFound regardless of what the host's real route
        // table looks like.
        let err = super::read_default_gateway_ip(Some("nope_xxxxx")).unwrap_err();
        assert!(matches!(err, crate::Error::GatewayIpNotFound(_)));
    }

    const LOCAL_IP: u32 = 0x0a_00_00_02;
    const GATEWAY_IP: u32 = 0x0a_00_00_01;
    const PEER_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_arp_request_for_us_sends_reply() {
        let pkt = ArpPacket {
            op: ARP_OP_REQUEST,
            sender_mac: PEER_MAC,
            sender_ip: 0x0a_00_00_05,
            target_mac: [0u8; 6],
            target_ip: LOCAL_IP,
        };
        assert_eq!(
            super::classify_arp(&pkt, LOCAL_IP, GATEWAY_IP),
            super::ArpAction::SendReply
        );
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_arp_reply_from_gateway_updates_mac() {
        let pkt = ArpPacket {
            op: ARP_OP_REPLY,
            sender_mac: PEER_MAC,
            sender_ip: GATEWAY_IP,
            target_mac: [1, 2, 3, 4, 5, 6],
            target_ip: LOCAL_IP,
        };
        assert_eq!(
            super::classify_arp(&pkt, LOCAL_IP, GATEWAY_IP),
            super::ArpAction::UpdateGatewayMac(PEER_MAC)
        );
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_arp_gratuitous_from_gateway_updates_mac() {
        // Gratuitous ARP: op=REQUEST with sender_ip == target_ip.
        let pkt = ArpPacket {
            op: ARP_OP_REQUEST,
            sender_mac: PEER_MAC,
            sender_ip: GATEWAY_IP,
            target_mac: [0u8; 6],
            target_ip: GATEWAY_IP,
        };
        assert_eq!(
            super::classify_arp(&pkt, LOCAL_IP, GATEWAY_IP),
            super::ArpAction::UpdateGatewayMac(PEER_MAC)
        );
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_arp_overheard_reply_from_gateway_still_updates() {
        // Gateway replies to some other host, but we see the frame on
        // the shared L2 segment. RFC 826 permits learning from this
        // overheard reply: the sender_mac is authoritative for the
        // gateway IP regardless of who the reply was addressed to.
        let pkt = ArpPacket {
            op: ARP_OP_REPLY,
            sender_mac: PEER_MAC,
            sender_ip: GATEWAY_IP,
            target_mac: [9, 9, 9, 9, 9, 9],
            target_ip: 0x0a_00_00_07,
        };
        assert_eq!(
            super::classify_arp(&pkt, LOCAL_IP, GATEWAY_IP),
            super::ArpAction::UpdateGatewayMac(PEER_MAC)
        );
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_arp_reply_from_non_gateway_ignored() {
        // Reply from some random peer (not the gateway) must not rewrite
        // the gateway MAC. We accept gateway replies only from the
        // configured gateway IP.
        let pkt = ArpPacket {
            op: ARP_OP_REPLY,
            sender_mac: PEER_MAC,
            sender_ip: 0x0a_00_00_09,
            target_mac: [1, 2, 3, 4, 5, 6],
            target_ip: LOCAL_IP,
        };
        assert_eq!(
            super::classify_arp(&pkt, LOCAL_IP, GATEWAY_IP),
            super::ArpAction::None
        );
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_arp_zero_gateway_ip_never_updates() {
        // With no gateway configured, a plausible-looking reply must
        // still return None — we refuse to learn a MAC without knowing
        // which IP it belongs to.
        let pkt = ArpPacket {
            op: ARP_OP_REPLY,
            sender_mac: PEER_MAC,
            sender_ip: GATEWAY_IP,
            target_mac: [0u8; 6],
            target_ip: LOCAL_IP,
        };
        assert_eq!(
            super::classify_arp(&pkt, LOCAL_IP, 0),
            super::ArpAction::None
        );
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_arp_request_for_non_local_ignored() {
        // A request targeting some other host, and not a gateway
        // announce, is a no-op for us.
        let pkt = ArpPacket {
            op: ARP_OP_REQUEST,
            sender_mac: PEER_MAC,
            sender_ip: 0x0a_00_00_05,
            target_mac: [0u8; 6],
            target_ip: 0x0a_00_00_09,
        };
        assert_eq!(
            super::classify_arp(&pkt, LOCAL_IP, GATEWAY_IP),
            super::ArpAction::None
        );
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn classify_arp_zero_local_ip_does_not_send_reply_to_zero_target() {
        // An ARP request for target_ip == 0 must not trigger a reply
        // when local_ip is 0 — we're not a stand-in for the
        // unassigned-address stub.
        let pkt = ArpPacket {
            op: ARP_OP_REQUEST,
            sender_mac: PEER_MAC,
            sender_ip: 0x0a_00_00_05,
            target_mac: [0u8; 6],
            target_ip: 0,
        };
        assert_eq!(
            super::classify_arp(&pkt, 0, GATEWAY_IP),
            super::ArpAction::None
        );
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn build_arp_request_roundtrip() {
        // Builder must produce a standard ARP REQUEST with broadcast dst
        // MAC and the 60-byte Ethernet-min padding.
        let mut buf = [0u8; ARP_FRAME_LEN];
        let n = build_arp_request(
            [1, 2, 3, 4, 5, 6],
            LOCAL_IP,
            GATEWAY_IP,
            &mut buf,
        )
        .expect("built");
        assert_eq!(n, ARP_FRAME_LEN);
        // Ethernet header: dst = broadcast, src = our MAC, type = ARP
        assert_eq!(&buf[0..6], &[0xff; 6]);
        assert_eq!(&buf[6..12], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&buf[12..14], &0x0806u16.to_be_bytes());
        let decoded = arp_decode(&buf[14..]).expect("decode");
        assert_eq!(decoded.op, ARP_OP_REQUEST);
        assert_eq!(decoded.sender_mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(decoded.sender_ip, LOCAL_IP);
        // Target MAC is zeros because we don't know it yet — that's why
        // we're asking.
        assert_eq!(decoded.target_mac, [0u8; 6]);
        assert_eq!(decoded.target_ip, GATEWAY_IP);
        // Pad bytes (42..60) must be zero.
        for (i, &b) in buf[42..].iter().enumerate() {
            assert_eq!(b, 0, "pad byte {i} not zero");
        }
    }

    #[cfg_attr(miri, ignore = "touches DPDK sys::*")]
    #[test]
    fn build_arp_request_buffer_too_small() {
        let mut buf = [0u8; 10];
        assert!(build_arp_request([1; 6], LOCAL_IP, GATEWAY_IP, &mut buf).is_none());
    }
}
