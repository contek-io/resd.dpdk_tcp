//! Synthetic pcap builder — Ethernet / IPv4 / TCP frames with the
//! operator-supplied seq/ack/ISS/TSval/etc knobs exposed so the
//! normalize-roundtrip + differing-counts tests can construct inputs
//! programmatically (rather than shipping opaque `.pcap` blobs).
//!
//! Extracted from the inline builder in
//! `tests/normalize_roundtrip.rs` by A10 T15-B.

use std::time::Duration;

use pcap_file::pcap::{PcapPacket, PcapWriter};

/// A single synthetic packet used by the test pcap builder.
#[derive(Clone)]
pub struct SynthPacket {
    pub eth_src: [u8; 6],
    pub eth_dst: [u8; 6],
    pub ethertype: u16,
    /// `None` for non-IPv4 frames — builder emits ethertype + opaque
    /// payload.
    pub ipv4: Option<SynthIpv4>,
    /// For non-IPv4 frames: the raw payload past ethertype.
    pub raw_payload: Vec<u8>,
}

#[derive(Clone)]
pub struct SynthIpv4 {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub ip_id: u16,
    pub proto: u8,
    /// TCP segment payload (may be empty). Absent fields imply a
    /// pure-TCP-header-only segment.
    pub tcp: Option<SynthTcp>,
}

#[derive(Clone)]
pub struct SynthTcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// Data offset in bytes (20 = no options, 32 = +TSopt, etc). Must
    /// be a multiple of 4 and >= 20.
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    /// Options bytes (NOP-padded to a multiple of 4, caller's job).
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}

pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_FIN: u8 = 0x01;

pub fn build_pcap(packets: &[SynthPacket]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut wr = PcapWriter::new(&mut buf).expect("PcapWriter::new");
        for (i, p) in packets.iter().enumerate() {
            let bytes = serialize_frame(p);
            let ts = Duration::from_nanos(1_000_000 * (i as u64 + 1));
            let pkt = PcapPacket::new_owned(ts, bytes.len() as u32, bytes);
            wr.write_packet(&pkt).expect("write_packet");
        }
    }
    buf
}

pub fn serialize_frame(p: &SynthPacket) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&p.eth_dst);
    out.extend_from_slice(&p.eth_src);
    out.extend_from_slice(&p.ethertype.to_be_bytes());
    if let Some(ip) = &p.ipv4 {
        let tcp_bytes = ip.tcp.as_ref().map(serialize_tcp).unwrap_or_default();
        let total_len = 20 + tcp_bytes.len();
        let mut ip_hdr = [0u8; 20];
        ip_hdr[0] = 0x45; // Version 4, IHL 5
        ip_hdr[1] = 0; // DSCP/ECN
        ip_hdr[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip_hdr[4..6].copy_from_slice(&ip.ip_id.to_be_bytes());
        ip_hdr[6..8].copy_from_slice(&0u16.to_be_bytes());
        ip_hdr[8] = 64; // TTL
        ip_hdr[9] = ip.proto;
        ip_hdr[10..12].copy_from_slice(&0u16.to_be_bytes()); // csum placeholder
        ip_hdr[12..16].copy_from_slice(&ip.src_ip);
        ip_hdr[16..20].copy_from_slice(&ip.dst_ip);
        let csum = rfc1071(&ip_hdr);
        ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());
        out.extend_from_slice(&ip_hdr);
        // TCP payload is appended; the TCP checksum needs the pseudo-
        // header so we recompute it here over the already-serialised
        // TCP bytes.
        if !tcp_bytes.is_empty() {
            let mut tcp_bytes = tcp_bytes;
            // Zero the checksum field (offset 16 within TCP header).
            tcp_bytes[16] = 0;
            tcp_bytes[17] = 0;
            let csum = synth_tcp_checksum(&ip.src_ip, &ip.dst_ip, &tcp_bytes);
            tcp_bytes[16..18].copy_from_slice(&csum.to_be_bytes());
            out.extend_from_slice(&tcp_bytes);
        }
    } else {
        out.extend_from_slice(&p.raw_payload);
    }
    out
}

pub fn serialize_tcp(t: &SynthTcp) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&t.src_port.to_be_bytes());
    buf.extend_from_slice(&t.dst_port.to_be_bytes());
    buf.extend_from_slice(&t.seq.to_be_bytes());
    buf.extend_from_slice(&t.ack.to_be_bytes());
    buf.push((t.data_offset / 4) << 4); // data_offset in 4-byte words, in high nibble
    buf.push(t.flags);
    buf.extend_from_slice(&t.window.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    buf.extend_from_slice(&0u16.to_be_bytes()); // urg ptr
    buf.extend_from_slice(&t.options);
    buf.extend_from_slice(&t.payload);
    buf
}

pub fn rfc1071(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]])));
        i += 2;
    }
    if i < bytes.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([bytes[i], 0])));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn synth_tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += u32::from(u16::from_be_bytes([src_ip[0], src_ip[1]]));
    sum += u32::from(u16::from_be_bytes([src_ip[2], src_ip[3]]));
    sum += u32::from(u16::from_be_bytes([dst_ip[0], dst_ip[1]]));
    sum += u32::from(u16::from_be_bytes([dst_ip[2], dst_ip[3]]));
    sum += 6u32; // proto TCP
    sum += tcp.len() as u32;
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([tcp[i], tcp[i + 1]])));
        i += 2;
    }
    if i < tcp.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([tcp[i], 0])));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn mac(v: u8) -> [u8; 6] {
    [0x00, 0x11, 0x22, 0x33, 0x44, v]
}

/// Build a 3-packet handshake (SYN, SYN-ACK, ACK) with TSopt. Returns
/// the pcap bytes.
///
/// `a_*` = active opener side (src_ip 10.0.0.1), `b_*` = passive
/// acceptor side (src_ip 10.0.0.2). Ports are fixed at 40000/10001.
#[allow(clippy::too_many_arguments)]
pub fn build_handshake_with_tsopt(
    a_mac: [u8; 6],
    b_mac: [u8; 6],
    a_iss: u32,
    b_iss: u32,
    a_tsval: u32,
    b_tsval: u32,
    include_ts_option: bool,
) -> Vec<u8> {
    let a_ip = [10, 0, 0, 1];
    let b_ip = [10, 0, 0, 2];
    let a_port: u16 = 40000;
    let b_port: u16 = 10001;
    let mk_tsopt = |tsval: u32, tsecr: u32| -> Vec<u8> {
        // NOP, NOP, Timestamps (kind=8), length=10, TSval(4), TSecr(4)
        // — 12 bytes total, 4-byte aligned for the 32-bit TCP option
        // word.
        let mut o = vec![1u8, 1, 8, 10];
        o.extend_from_slice(&tsval.to_be_bytes());
        o.extend_from_slice(&tsecr.to_be_bytes());
        o
    };
    let (opts_syn, opts_synack, opts_ack, d_off) = if include_ts_option {
        (
            mk_tsopt(a_tsval, 0),
            mk_tsopt(b_tsval, a_tsval),
            mk_tsopt(a_tsval.wrapping_add(1), b_tsval),
            32u8,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new(), 20u8)
    };
    let syn = SynthPacket {
        eth_src: a_mac,
        eth_dst: b_mac,
        ethertype: 0x0800,
        ipv4: Some(SynthIpv4 {
            src_ip: a_ip,
            dst_ip: b_ip,
            ip_id: 0,
            proto: 6,
            tcp: Some(SynthTcp {
                src_port: a_port,
                dst_port: b_port,
                seq: a_iss,
                ack: 0,
                data_offset: d_off,
                flags: TCP_FLAG_SYN,
                window: 64240,
                options: opts_syn,
                payload: Vec::new(),
            }),
        }),
        raw_payload: Vec::new(),
    };
    let synack = SynthPacket {
        eth_src: b_mac,
        eth_dst: a_mac,
        ethertype: 0x0800,
        ipv4: Some(SynthIpv4 {
            src_ip: b_ip,
            dst_ip: a_ip,
            ip_id: 0,
            proto: 6,
            tcp: Some(SynthTcp {
                src_port: b_port,
                dst_port: a_port,
                seq: b_iss,
                ack: a_iss.wrapping_add(1),
                data_offset: d_off,
                flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                window: 64240,
                options: opts_synack,
                payload: Vec::new(),
            }),
        }),
        raw_payload: Vec::new(),
    };
    let ack = SynthPacket {
        eth_src: a_mac,
        eth_dst: b_mac,
        ethertype: 0x0800,
        ipv4: Some(SynthIpv4 {
            src_ip: a_ip,
            dst_ip: b_ip,
            ip_id: 0,
            proto: 6,
            tcp: Some(SynthTcp {
                src_port: a_port,
                dst_port: b_port,
                seq: a_iss.wrapping_add(1),
                ack: b_iss.wrapping_add(1),
                data_offset: d_off,
                flags: TCP_FLAG_ACK,
                window: 64240,
                options: opts_ack,
                payload: Vec::new(),
            }),
        }),
        raw_payload: Vec::new(),
    };
    build_pcap(&[syn, synack, ack])
}
