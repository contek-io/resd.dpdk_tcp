//! ICMP input — we only react to Type 3 Code 4 (Fragmentation Needed /
//! DF Set) per RFC 1191. Everything else is silently dropped (spec §6.3 RFC
//! 792 row). The output is a PMTU update for the ORIGINAL destination (the
//! IP in the ICMP payload's embedded header's dst_ip field), NOT the ICMP
//! sender — the ICMP came from an intermediate router, so src_ip of the
//! outer packet is useless for PMTU attribution.

use std::collections::HashMap;

pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_CODE_FRAG_NEEDED: u8 = 4;

pub const IPV4_MIN_MTU: u16 = 68; // RFC 791: every host must accept ≥ 68-byte datagrams

#[derive(Debug, Default)]
pub struct PmtuTable {
    /// Key: destination IPv4 (host byte order) of the packet that triggered
    /// the ICMP. Value: next-hop MTU learned from the router's reply.
    entries: HashMap<u32, u16>,
}

impl PmtuTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, ip: u32) -> Option<u16> {
        self.entries.get(&ip).copied()
    }

    /// Update the PMTU for `ip`. Returns `true` if this updated or
    /// inserted an entry (caller bumps pmtud_updates counter).
    /// Floors at IPV4_MIN_MTU. Declines to grow (PMTU only shrinks).
    pub fn update(&mut self, ip: u32, mtu: u16) -> bool {
        let mtu = mtu.max(IPV4_MIN_MTU);
        match self.entries.get(&ip).copied() {
            Some(existing) if mtu >= existing => false,
            _ => {
                self.entries.insert(ip, mtu);
                true
            }
        }
    }
}

/// Result classification for the caller's counter path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpResult {
    FragNeededPmtuUpdated, // found, stored; caller bumps ip.rx_icmp_frag_needed + ip.pmtud_updates
    FragNeededNoShrink, // found, but no-op (MTU not smaller than existing); caller bumps ip.rx_icmp_frag_needed only
    OtherDropped,       // not dest-unreach-frag-needed, silently dropped
    Malformed,          // too short / inner header not recognizable
}

/// Parse ICMP starting at the IPv4 payload. `ip_payload` is the slice
/// beginning at the ICMP header (after IPv4 options). Returns the action
/// classification and mutates `pmtu` on match.
pub fn icmp_input(ip_payload: &[u8], pmtu: &mut PmtuTable) -> IcmpResult {
    // ICMP header: type(1) code(1) csum(2) rest_of_header(4) ...
    if ip_payload.len() < 8 {
        return IcmpResult::Malformed;
    }
    let ty = ip_payload[0];
    let code = ip_payload[1];
    if ty != ICMP_DEST_UNREACH || code != ICMP_CODE_FRAG_NEEDED {
        return IcmpResult::OtherDropped;
    }
    // RFC 1191 layout: bytes 4..6 reserved, bytes 6..8 next-hop MTU.
    let next_hop_mtu = u16::from_be_bytes([ip_payload[6], ip_payload[7]]);
    // After the 8-byte ICMP header, the embedded original IP header starts.
    // We need at least 20 bytes of IPv4 header + 8 bytes of original transport.
    if ip_payload.len() < 8 + 20 {
        return IcmpResult::Malformed;
    }
    let inner = &ip_payload[8..];
    let version = inner[0] >> 4;
    let ihl = (inner[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 || inner.len() < ihl * 4 {
        return IcmpResult::Malformed;
    }
    let inner_dst = u32::from_be_bytes([inner[16], inner[17], inner[18], inner[19]]);
    // next_hop_mtu == 0 means the router doesn't support RFC 1191 — fall back
    // to RFC 4821 PLPMTUD territory (out of Stage 1 scope). Spec §10.8 notes
    // this as Stage 2. For A2, we treat it as malformed.
    if next_hop_mtu == 0 {
        return IcmpResult::Malformed;
    }
    if pmtu.update(inner_dst, next_hop_mtu) {
        IcmpResult::FragNeededPmtuUpdated
    } else {
        IcmpResult::FragNeededNoShrink
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_inner_ip(dst: u32) -> Vec<u8> {
        let mut v = vec![
            0x45, 0x00, 0x00, 0x14, // total_length = 20
            0, 0, 0x40, 0x00, // DF
            0x40, 6, // TTL 64, proto TCP
            0, 0, // csum
            0, 0, 0, 0, // src
            0, 0, 0, 0, // dst
        ];
        v[16..20].copy_from_slice(&dst.to_be_bytes());
        v
    }

    fn build_icmp_frag(mtu: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = vec![
            ICMP_DEST_UNREACH,
            ICMP_CODE_FRAG_NEEDED,
            0x00,
            0x00, // csum (not verified by icmp_input)
            0x00,
            0x00, // unused
            (mtu >> 8) as u8,
            (mtu & 0xff) as u8,
        ];
        v.extend_from_slice(inner);
        v
    }

    #[test]
    fn pmtu_update_floors_to_min_mtu() {
        let mut t = PmtuTable::new();
        assert!(t.update(0x0a000001, 32));
        assert_eq!(t.get(0x0a000001), Some(IPV4_MIN_MTU));
    }

    #[test]
    fn pmtu_update_only_shrinks() {
        let mut t = PmtuTable::new();
        assert!(t.update(0x0a000001, 1400));
        assert!(!t.update(0x0a000001, 1500)); // grow rejected
        assert_eq!(t.get(0x0a000001), Some(1400));
        assert!(t.update(0x0a000001, 1280)); // shrink accepted
        assert_eq!(t.get(0x0a000001), Some(1280));
    }

    #[test]
    fn too_short_malformed() {
        let mut t = PmtuTable::new();
        assert_eq!(icmp_input(&[0u8; 4], &mut t), IcmpResult::Malformed);
    }

    #[test]
    fn other_icmp_dropped() {
        let mut t = PmtuTable::new();
        let payload = [8u8, 0, 0, 0, 0, 0, 0, 0]; // echo request
        assert_eq!(icmp_input(&payload, &mut t), IcmpResult::OtherDropped);
    }

    #[test]
    fn frag_needed_updates_pmtu() {
        let inner = build_inner_ip(0x0a000050);
        let pkt = build_icmp_frag(1400, &inner);
        let mut t = PmtuTable::new();
        assert_eq!(icmp_input(&pkt, &mut t), IcmpResult::FragNeededPmtuUpdated);
        assert_eq!(t.get(0x0a000050), Some(1400));
    }

    #[test]
    fn frag_needed_second_identical_is_no_shrink() {
        let inner = build_inner_ip(0x0a000050);
        let pkt = build_icmp_frag(1400, &inner);
        let mut t = PmtuTable::new();
        let _ = icmp_input(&pkt, &mut t);
        assert_eq!(icmp_input(&pkt, &mut t), IcmpResult::FragNeededNoShrink);
    }

    #[test]
    fn zero_mtu_malformed() {
        let inner = build_inner_ip(0x0a000050);
        let pkt = build_icmp_frag(0, &inner);
        let mut t = PmtuTable::new();
        assert_eq!(icmp_input(&pkt, &mut t), IcmpResult::Malformed);
    }

    #[test]
    fn pmtu_update_u16_max_first_entry_is_recorded_and_counted() {
        // Regression: previously, u16::MAX was used as a sentinel meaning
        // "no entry yet", causing a legit u16::MAX MTU on first update to
        // be silently dropped.
        let mut t = PmtuTable::new();
        assert!(t.update(0x0a000002, u16::MAX));
        assert_eq!(t.get(0x0a000002), Some(u16::MAX));
        // Second identical update should return false.
        assert!(!t.update(0x0a000002, u16::MAX));
    }

    #[test]
    fn inner_bad_version_malformed() {
        let mut inner = build_inner_ip(0x0a000050);
        inner[0] = 0x55; // version 5, IHL 5 — bad version
        let pkt = build_icmp_frag(1400, &inner);
        let mut t = PmtuTable::new();
        assert_eq!(icmp_input(&pkt, &mut t), IcmpResult::Malformed);
    }
}
