//! A10 Plan B Task 9 — divergence-normalisation round-trip tests.
//!
//! Build two synthetic pcap streams with different random ISS + TSval
//! bases but otherwise identical wire behaviour, canonicalise both,
//! then byte-compare. The equal-after-normalisation invariant is the
//! whole contract for mode B — if it fails here, the wire-diff runner
//! will produce false positives and operators can't trust the tool.
//!
//! The synthetic pcap builder lives inline in this file rather than
//! as committed fixtures because generating them programmatically
//! keeps the test self-contained: a Scapy dependency would ship
//! opaque `.pcap` blobs that future me can't debug without running
//! Scapy too.
//!
//! # Test matrix
//!
//! - `canonicalize_produces_identical_bytes_for_same_flow` — two SYN/
//!   SYN-ACK/ACK streams with different random ISS + TSval should
//!   canonicalise to identical bytes.
//! - `canonicalize_survives_missing_ts_option` — no-TSopt streams
//!   still normalise (just seq/ack + MAC).
//! - `canonicalize_survives_window_scale_option` — window-scale
//!   option present should pass through unchanged and still match.
//! - `canonicalize_handles_sack_blocks` — SACK blocks must rewrite
//!   with the reverse direction's ISS pin.
//! - `canonicalize_handles_fin` — FIN doesn't need special rewrites
//!   but should still canonicalise cleanly (smoke test the flag
//!   path).
//! - `canonicalize_passes_through_non_ipv4` — ARP / other ethertypes
//!   pass through unchanged; the byte diff is exact on those bytes.

use std::io::Cursor;

use bench_vs_linux::normalize::{
    byte_diff_count, canonicalize_pcap, probe_pass1_instance_counts, CanonicalizationOptions,
};
use pcap_file::pcap::PcapWriter;

mod common;
use common::synth::{
    build_handshake_with_tsopt, build_pcap, mac, SynthIpv4, SynthPacket, SynthTcp,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_SYN,
};

#[test]
fn canonicalize_produces_identical_bytes_for_same_flow() {
    // Two pcaps with wildly different ISS + TSval but the same wire
    // behaviour. Canonicalisation should collapse them to identical
    // bytes.
    let pcap_a = build_handshake_with_tsopt(mac(0x01), mac(0x02), 0xDEAD_BEEF, 0xFACE_F00D, 100, 200, true);
    let pcap_b = build_handshake_with_tsopt(mac(0xAA), mac(0xBB), 0x0000_0007, 0x9000_0000, 42, 77, true);
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert_eq!(
        byte_diff_count(&can_a, &can_b),
        0,
        "canonicalised byte streams must match"
    );
    assert_eq!(can_a, can_b);
}

#[test]
fn canonicalize_survives_missing_ts_option() {
    let pcap_a = build_handshake_with_tsopt(mac(0x01), mac(0x02), 0xDEAD_BEEF, 0xFACE_F00D, 0, 0, false);
    let pcap_b = build_handshake_with_tsopt(mac(0xAA), mac(0xBB), 0x0000_0007, 0x9000_0000, 0, 0, false);
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert_eq!(can_a, can_b);
}

#[test]
fn canonicalize_survives_window_scale_option() {
    // Window-scale option (kind=3 len=3 shift=7) + NOP padding.
    // We build this manually because the helper above only emits TSopt.
    let mk_wscale_syn = |src_mac: [u8; 6], dst_mac: [u8; 6], seq: u32| SynthPacket {
        eth_src: src_mac,
        eth_dst: dst_mac,
        ethertype: 0x0800,
        ipv4: Some(SynthIpv4 {
            src_ip: [10, 0, 0, 1],
            dst_ip: [10, 0, 0, 2],
            ip_id: 0,
            proto: 6,
            tcp: Some(SynthTcp {
                src_port: 40000,
                dst_port: 10001,
                seq,
                ack: 0,
                data_offset: 24, // 20 + 4 bytes options
                flags: TCP_FLAG_SYN,
                window: 64240,
                options: vec![1, 3, 3, 7], // NOP, WS(3), len(3), shift(7)
                payload: Vec::new(),
            }),
        }),
        raw_payload: Vec::new(),
    };
    let pcap_a = build_pcap(&[mk_wscale_syn(mac(0x01), mac(0x02), 0xDEAD_BEEF)]);
    let pcap_b = build_pcap(&[mk_wscale_syn(mac(0xAA), mac(0xBB), 0x0000_0007)]);
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert_eq!(can_a, can_b);
}

#[test]
fn canonicalize_handles_sack_blocks() {
    // After the SYN-ACK-ACK handshake, the passive side emits an ACK
    // with a SACK block (kind=5 len=10 = one block of 8 bytes) covering
    // (a_iss+100, a_iss+200) in the active side's seq space.
    let a_iss_in_a = 0x1000_0000u32;
    let a_iss_in_b = 0x7000_0000u32;
    let b_iss_in_a = 0x2000_0000u32;
    let b_iss_in_b = 0x3000_0000u32;

    let make_flow = |a_iss: u32, b_iss: u32, a_mac: [u8; 6], b_mac: [u8; 6]| -> Vec<u8> {
        let a_ip = [10, 0, 0, 1];
        let b_ip = [10, 0, 0, 2];
        let a_port: u16 = 40000;
        let b_port: u16 = 10001;
        // Handshake.
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
                    data_offset: 20,
                    flags: TCP_FLAG_SYN,
                    window: 64240,
                    options: Vec::new(),
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
                    data_offset: 20,
                    flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        // NOP, NOP, SACK (kind=5), length=10, one 8-byte block.
        let mut sack_opts = vec![1u8, 1, 5, 10];
        let left = a_iss.wrapping_add(100);
        let right = a_iss.wrapping_add(200);
        sack_opts.extend_from_slice(&left.to_be_bytes());
        sack_opts.extend_from_slice(&right.to_be_bytes());
        let sack_ack = SynthPacket {
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
                    seq: b_iss.wrapping_add(1),
                    ack: a_iss.wrapping_add(1),
                    data_offset: 32, // 20 + 12 bytes options
                    flags: TCP_FLAG_ACK,
                    window: 64240,
                    options: sack_opts,
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        build_pcap(&[syn, synack, sack_ack])
    };
    let pcap_a = make_flow(a_iss_in_a, b_iss_in_a, mac(0x01), mac(0x02));
    let pcap_b = make_flow(a_iss_in_b, b_iss_in_b, mac(0xAA), mac(0xBB));
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert_eq!(can_a, can_b);
}

#[test]
fn canonicalize_handles_fin() {
    // SYN / SYN-ACK / ACK / FIN-ACK / FIN-ACK / ACK full close.
    // We exercise the FIN path to make sure flag-only packets still
    // canonicalise without tripping the "no ACK flag" guard.
    let flow = |a_iss: u32, b_iss: u32, a_mac: [u8; 6], b_mac: [u8; 6]| -> Vec<u8> {
        let a_ip = [10, 0, 0, 1];
        let b_ip = [10, 0, 0, 2];
        let a_port: u16 = 40000;
        let b_port: u16 = 10001;
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
                    data_offset: 20,
                    flags: TCP_FLAG_SYN,
                    window: 64240,
                    options: Vec::new(),
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
                    data_offset: 20,
                    flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
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
                    data_offset: 20,
                    flags: TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        let fin_a = SynthPacket {
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
                    data_offset: 20,
                    flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        let fin_b = SynthPacket {
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
                    seq: b_iss.wrapping_add(1),
                    ack: a_iss.wrapping_add(2),
                    data_offset: 20,
                    flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        let final_ack = SynthPacket {
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
                    seq: a_iss.wrapping_add(2),
                    ack: b_iss.wrapping_add(2),
                    data_offset: 20,
                    flags: TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        build_pcap(&[syn, synack, ack, fin_a, fin_b, final_ack])
    };
    let pcap_a = flow(0xDEAD_BEEF, 0xFACE_F00D, mac(0x01), mac(0x02));
    let pcap_b = flow(0x0000_0007, 0x9000_0000, mac(0xAA), mac(0xBB));
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert_eq!(can_a, can_b, "FIN-carrying flows must canonicalise identically");
}

#[test]
fn canonicalize_passes_through_non_ipv4() {
    // Emit an ARP frame (ethertype 0x0806) + a plain TCP packet.
    // The ARP frame should pass through unchanged in both captures;
    // the TCP packet should still canonicalise.
    let arp = |src_mac: [u8; 6], dst_mac: [u8; 6]| SynthPacket {
        eth_src: src_mac,
        eth_dst: dst_mac,
        ethertype: 0x0806,
        ipv4: None,
        raw_payload: vec![0u8; 28], // fake ARP body
    };
    let pcap_a = build_pcap(&[
        arp(mac(0x01), mac(0x02)),
        // Follow with a SYN so the canonicalisation still has something
        // to pin.
        SynthPacket {
            eth_src: mac(0x01),
            eth_dst: mac(0x02),
            ethertype: 0x0800,
            ipv4: Some(SynthIpv4 {
                src_ip: [10, 0, 0, 1],
                dst_ip: [10, 0, 0, 2],
                ip_id: 0,
                proto: 6,
                tcp: Some(SynthTcp {
                    src_port: 40000,
                    dst_port: 10001,
                    seq: 0xDEAD_BEEF,
                    ack: 0,
                    data_offset: 20,
                    flags: TCP_FLAG_SYN,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        },
    ]);
    let pcap_b = build_pcap(&[
        // Same ARP bytes (including same MACs — we want to verify the
        // ARP frame passes through unchanged)
        arp(mac(0x01), mac(0x02)),
        SynthPacket {
            eth_src: mac(0xAA),
            eth_dst: mac(0xBB),
            ethertype: 0x0800,
            ipv4: Some(SynthIpv4 {
                src_ip: [10, 0, 0, 1],
                dst_ip: [10, 0, 0, 2],
                ip_id: 0,
                proto: 6,
                tcp: Some(SynthTcp {
                    src_port: 40000,
                    dst_port: 10001,
                    seq: 0x0000_0007,
                    ack: 0,
                    data_offset: 20,
                    flags: TCP_FLAG_SYN,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        },
    ]);
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    // The MACs of the ARP frame differ between the two pcaps only if
    // they were built with different inputs — they're identical here,
    // so byte-for-byte the ARP regions must match. The TCP SYN region
    // is normalised, so it must also match.
    assert_eq!(can_a, can_b);
}

#[test]
fn canonicalize_mid_stream_capture_pins_first_seen_seq() {
    // No SYN observed — the first packet seen on each direction
    // pins ISS = seq at that packet. The two captures start mid-stream
    // with identical seq offsets post-pin, so they still canonicalise
    // to the same bytes.
    let mid = |a_seq: u32, b_seq: u32, a_mac: [u8; 6], b_mac: [u8; 6]| -> Vec<u8> {
        let a_ip = [10, 0, 0, 1];
        let b_ip = [10, 0, 0, 2];
        // First packet: side A sends ACK with data.
        let p1 = SynthPacket {
            eth_src: a_mac,
            eth_dst: b_mac,
            ethertype: 0x0800,
            ipv4: Some(SynthIpv4 {
                src_ip: a_ip,
                dst_ip: b_ip,
                ip_id: 0,
                proto: 6,
                tcp: Some(SynthTcp {
                    src_port: 40000,
                    dst_port: 10001,
                    seq: a_seq,
                    ack: b_seq,
                    data_offset: 20,
                    flags: TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: vec![0x11, 0x22, 0x33, 0x44],
                }),
            }),
            raw_payload: Vec::new(),
        };
        // Second packet: side B ACKs with seq + data.
        let p2 = SynthPacket {
            eth_src: b_mac,
            eth_dst: a_mac,
            ethertype: 0x0800,
            ipv4: Some(SynthIpv4 {
                src_ip: b_ip,
                dst_ip: a_ip,
                ip_id: 0,
                proto: 6,
                tcp: Some(SynthTcp {
                    src_port: 10001,
                    dst_port: 40000,
                    seq: b_seq,
                    ack: a_seq.wrapping_add(4),
                    data_offset: 20,
                    flags: TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        build_pcap(&[p1, p2])
    };
    let pcap_a = mid(0x5000_0000, 0x6000_0000, mac(0x01), mac(0x02));
    let pcap_b = mid(0xA000_0000, 0xB000_0000, mac(0xAA), mac(0xBB));
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert_eq!(can_a, can_b);
}

#[test]
fn canonicalize_diverging_behavior_shows_diff() {
    // Negative control: if the two streams diverge in real wire
    // behaviour (different payload bytes), canonicalisation must not
    // hide that.
    let flow = |a_iss: u32, payload: &[u8]| -> Vec<u8> {
        let a_mac = mac(0x01);
        let b_mac = mac(0x02);
        let a_ip = [10, 0, 0, 1];
        let b_ip = [10, 0, 0, 2];
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
                    src_port: 40000,
                    dst_port: 10001,
                    seq: a_iss,
                    ack: 0,
                    data_offset: 20,
                    flags: TCP_FLAG_SYN,
                    window: 64240,
                    options: Vec::new(),
                    payload: payload.to_vec(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        build_pcap(&[syn])
    };
    let pcap_a = flow(0xDEAD_BEEF, b"hello");
    let pcap_b = flow(0x0000_0007, b"world"); // different payload → divergence
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert!(
        byte_diff_count(&can_a, &can_b) > 0,
        "payload divergence must survive canonicalisation"
    );
}

#[test]
fn canonicalize_is_idempotent() {
    // Canonicalising an already-canonicalised pcap is a no-op.
    let pcap = build_handshake_with_tsopt(mac(0x01), mac(0x02), 0xDEAD_BEEF, 0xFACE_F00D, 100, 200, true);
    let opts = CanonicalizationOptions::default();
    let once = canonicalize_pcap(&pcap, &opts).expect("first pass");
    let twice = canonicalize_pcap(&once, &opts).expect("second pass");
    assert_eq!(once, twice, "canonicalise must be idempotent");
}

#[test]
fn canonicalize_rejects_garbage_pcap_cleanly() {
    // Not a pcap — should return Err, not panic.
    let garbage = vec![0u8; 8];
    let opts = CanonicalizationOptions::default();
    let err = canonicalize_pcap(&garbage, &opts);
    assert!(err.is_err(), "garbage input must error cleanly");
}

#[test]
fn canonicalize_matches_on_empty_pcap() {
    // Empty pcap (header only, no packets). Cursor reads will return
    // None immediately; canonicalisation should produce the same header.
    let mut buf = Vec::new();
    {
        let _ = PcapWriter::new(&mut buf).expect("PcapWriter::new");
    }
    let opts = CanonicalizationOptions::default();
    let canon = canonicalize_pcap(&buf, &opts).expect("empty pcap must roundtrip");
    // The canonicalised pcap may differ from the input if the writer
    // picks up different defaults — compare via parser instead.
    let mut r = pcap_file::pcap::PcapReader::new(Cursor::new(canon)).expect("reader");
    assert!(r.next_packet().is_none());
}

#[test]
fn canonicalize_port_reuse_preserves_per_instance_iss() {
    // T9-I2: two back-to-back connections on the same 4-tuple. Without
    // connection-instance discrimination, the first SYN's ISS pins both
    // handshakes, so the second connection's seq space gets garbage-
    // rewritten (offset by the delta between the two real ISSes).
    //
    // Invariant: each (tuple, instance) pair must pin its own ISS.
    // Two pcaps that reuse the same port with different underlying ISS
    // sequences MUST still canonicalise to identical bytes — proving
    // the per-instance slot hides the different random ISSes.
    let make_port_reuse_flow = |a_iss_1: u32,
                                b_iss_1: u32,
                                a_iss_2: u32,
                                b_iss_2: u32,
                                a_mac: [u8; 6],
                                b_mac: [u8; 6]|
     -> Vec<u8> {
        // Two full handshakes, same 4-tuple; we concatenate three-
        // packet handshakes into a single pcap.
        let hs1 = handshake_packets(a_iss_1, b_iss_1, a_mac, b_mac);
        let hs2 = handshake_packets(a_iss_2, b_iss_2, a_mac, b_mac);
        let all: Vec<_> = hs1.into_iter().chain(hs2).collect();
        build_pcap(&all)
    };
    let pcap_a = make_port_reuse_flow(
        0x1000_0000,
        0x2000_0000,
        0x3000_0000,
        0x4000_0000,
        mac(0x01),
        mac(0x02),
    );
    let pcap_b = make_port_reuse_flow(
        0xA000_0000,
        0xB000_0000,
        0xC000_0000,
        0xD000_0000,
        mac(0xAA),
        mac(0xBB),
    );
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert_eq!(
        can_a, can_b,
        "port-reuse flows must canonicalise identically under per-instance keying"
    );
}

#[test]
fn canonicalize_syn_retransmit_does_not_bump_instance() {
    // T15-B I-1: a SYN retransmit (pure SYN re-sending the same ISS
    // on the same 4-tuple) MUST NOT bump the per-tuple instance
    // counter. If it did, the retransmit would land on a fresh
    // instance slot that (a) wastes a state row and (b) desyncs
    // pass-1/pass-2 on port-reuse scenarios because pass-2 replays
    // the same walk order.
    //
    // Scenario: SYN at seq=X (instance=1), SYN at seq=X retransmit
    // (still instance=1), SYN-ACK, data. Assertions:
    //   1. Canonicalised first-direction segments all rewrite the
    //      same observed ISS (X) to the canonical ISS — so three
    //      segments (two SYNs + one data) whose seq is `a_iss + k`
    //      canonicalise to `canonical_iss + k` across both pcaps.
    //   2. The per-tuple final instance count is 1 after pass-1 (a
    //      single connection), not 2.
    let make = |a_iss: u32, b_iss: u32, a_mac: [u8; 6], b_mac: [u8; 6]| -> Vec<u8> {
        let a_ip = [10, 0, 0, 1];
        let b_ip = [10, 0, 0, 2];
        let a_port: u16 = 40000;
        let b_port: u16 = 10001;
        let mk_syn = |seq: u32| SynthPacket {
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
                    seq,
                    ack: 0,
                    data_offset: 20,
                    flags: TCP_FLAG_SYN,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        let syn1 = mk_syn(a_iss);
        // Retransmit: same seq (= ISS), same tuple, same flags.
        let syn2 = mk_syn(a_iss);
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
                    data_offset: 20,
                    flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: Vec::new(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        // Data segment from the opener side: seq = a_iss + 1.
        let data = SynthPacket {
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
                    data_offset: 20,
                    flags: TCP_FLAG_ACK,
                    window: 64240,
                    options: Vec::new(),
                    payload: b"hi".to_vec(),
                }),
            }),
            raw_payload: Vec::new(),
        };
        build_pcap(&[syn1, syn2, synack, data])
    };
    // Two pcaps with different ISS. Under the correct (no-bump)
    // behaviour they canonicalise byte-identical; under the buggy
    // (always-bump) behaviour they diverge on the second SYN and
    // the post-SYN data segment.
    let pcap_a = make(0xDEAD_BEEF, 0xFACE_F00D, mac(0x01), mac(0x02));
    let pcap_b = make(0x0000_0007, 0x9000_0000, mac(0xAA), mac(0xBB));
    let opts = CanonicalizationOptions::default();
    let can_a = canonicalize_pcap(&pcap_a, &opts).expect("canonicalise A");
    let can_b = canonicalize_pcap(&pcap_b, &opts).expect("canonicalise B");
    assert_eq!(
        can_a, can_b,
        "SYN retransmit must not perturb per-direction ISS rewrite"
    );
    // Confirm the per-tuple instance count is 1, not 2. Only one
    // tuple in this capture.
    let counts_a = probe_pass1_instance_counts(&pcap_a).expect("probe A");
    let counts_b = probe_pass1_instance_counts(&pcap_b).expect("probe B");
    assert_eq!(counts_a.len(), 1, "exactly one tuple expected in capture A");
    assert_eq!(counts_b.len(), 1, "exactly one tuple expected in capture B");
    assert_eq!(
        counts_a[0].final_instance, 1,
        "SYN retransmit must NOT bump syn_count (got {} for tuple {:?})",
        counts_a[0].final_instance, counts_a[0].endpoints
    );
    assert_eq!(
        counts_b[0].final_instance, 1,
        "SYN retransmit must NOT bump syn_count (got {} for tuple {:?})",
        counts_b[0].final_instance, counts_b[0].endpoints
    );
}

/// Build a 3-packet handshake (SYN, SYN-ACK, ACK) for the port-reuse
/// test. Keeps the packet list as `Vec<SynthPacket>` (not a pcap)
/// so the caller can concatenate multiple handshakes into one pcap.
fn handshake_packets(
    a_iss: u32,
    b_iss: u32,
    a_mac: [u8; 6],
    b_mac: [u8; 6],
) -> Vec<SynthPacket> {
    let a_ip = [10, 0, 0, 1];
    let b_ip = [10, 0, 0, 2];
    let a_port: u16 = 40000;
    let b_port: u16 = 10001;
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
                data_offset: 20,
                flags: TCP_FLAG_SYN,
                window: 64240,
                options: Vec::new(),
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
                data_offset: 20,
                flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                window: 64240,
                options: Vec::new(),
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
                data_offset: 20,
                flags: TCP_FLAG_ACK,
                window: 64240,
                options: Vec::new(),
                payload: Vec::new(),
            }),
        }),
        raw_payload: Vec::new(),
    };
    vec![syn, synack, ack]
}
