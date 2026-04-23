//! Reserved-RX probe (RFC 9293 §3.1 "reserved bits must be zero on TX /
//! ignored on RX"). Ported from tcpreq/tests/reserved.py.
//!
//! The 4-bit reserved field sits in the low nibble of the TCP header's
//! 13th byte (offset 12 within the TCP header, between data-offset and
//! the flags byte). Required behavior:
//!   * TX: reserved bits MUST be zero in generated segments.
//!   * RX: reserved bits MUST be ignored on received segments.
//!
//! This probe exercises the RX half: it crafts a SYN with reserved=0xF,
//! recomputes the TCP checksum (reserved bits are inside the checksummed
//! span), and injects it through the test-server bypass. It asserts:
//!   (a) the engine accepts the SYN (a SYN-ACK is emitted),
//!   (b) the emitted SYN-ACK has reserved=0 (the TX half),
//!   (c) the handshake completes normally after injecting the final ACK.

use crate::{ProbeResult, ProbeStatus, TcpreqHarness, OUR_IP, PEER_IP};

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::l3_ip::{internet_checksum, IPPROTO_TCP};
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::{TCP_ACK, TCP_SYN};
use dpdk_net_core::test_server::test_packet::{build_tcp_frame, parse_syn_ack};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

const LOCAL_PORT: u16 = 5555;
const PEER_PORT: u16 = 40_000;
const PEER_ISS: u32 = 0x10_00_00_00;
const PEER_MSS: u16 = 1460;

/// L2 Ethernet header is always 14 bytes; the test-server's `build_segment`
/// always emits a 20-byte IPv4 header (no IP options). TCP header starts
/// at byte 34; the data-offset / reserved byte is at TCP + 12 = 46.
const TCP_HDR_OFFSET: usize = 14 + 20;
const DO_RES_BYTE_OFFSET: usize = TCP_HDR_OFFSET + 12;

pub fn reserved_rx() -> ProbeResult {
    let h = TcpreqHarness::new();

    let listen = match h.eng.listen(OUR_IP, LOCAL_PORT) {
        Ok(l) => l,
        Err(e) => return fail(format!("listen: {e:?}")),
    };

    // Build a normal SYN with MSS=1460 via the wire-identical test_packet
    // helper; then patch the reserved nibble to 0xF and recompute the TCP
    // checksum. build_tcp_frame includes the MSS option, so data offset
    // is 6 (24-byte TCP header) → byte-12 is 0x60; after patching: 0x6F.
    set_virt_ns(1_000_000);
    let opts = TcpOpts {
        mss: Some(PEER_MSS),
        ..Default::default()
    };
    let mut syn = build_tcp_frame(
        PEER_IP, PEER_PORT, OUR_IP, LOCAL_PORT,
        PEER_ISS, 0, TCP_SYN, u16::MAX, opts, &[],
    );

    if syn.len() < DO_RES_BYTE_OFFSET + 1 {
        return fail(format!(
            "built SYN too short for reserved-bit patch: len={} need>={}",
            syn.len(),
            DO_RES_BYTE_OFFSET + 1
        ));
    }

    // Sanity: the high nibble (data offset) of byte 12 must be non-zero
    // so our patch doesn't accidentally zero it. build_tcp_frame with MSS
    // yields data_off = 6 → byte = 0x60.
    let original = syn[DO_RES_BYTE_OFFSET];
    if (original >> 4) < 5 {
        return fail(format!(
            "unexpected data offset in built SYN: byte12 = 0x{original:02X}"
        ));
    }

    // Set all 4 reserved bits. Keep the high nibble (data offset) intact.
    syn[DO_RES_BYTE_OFFSET] = (original & 0xF0) | 0x0F;
    recompute_tcp_csum(&mut syn, TCP_HDR_OFFSET);

    if let Err(e) = h.eng.inject_rx_frame(&syn) {
        return fail(format!("inject reserved SYN: {e:?}"));
    }

    // (a) Drain our SYN-ACK.
    let frames = drain_tx_frames();
    let synack = match frames.first() {
        Some(f) => f,
        None => {
            return fail(
                "no SYN-ACK emitted after reserved-bit SYN (engine rejected the \
                 segment; RFC 9293 §3.1 requires reserved bits be ignored on RX)"
                    .into(),
            );
        }
    };
    let (our_iss, _ack) = match parse_syn_ack(synack) {
        Some(v) => v,
        None => {
            return fail(format!(
                "first TX frame after reserved SYN is not a SYN-ACK: first 64 bytes {:02x?}",
                &synack[..std::cmp::min(synack.len(), 64)]
            ));
        }
    };

    // (b) Our emitted SYN-ACK MUST have reserved=0.
    if synack.len() < DO_RES_BYTE_OFFSET + 1 {
        return fail(format!(
            "emitted SYN-ACK too short for reserved-bit inspection: len={}",
            synack.len()
        ));
    }
    let reserved_in_synack = synack[DO_RES_BYTE_OFFSET] & 0x0F;
    if reserved_in_synack != 0 {
        return fail(format!(
            "RFC 9293 §3.1 TX violation: emitted SYN-ACK has non-zero reserved nibble 0x{reserved_in_synack:X} \
             (full byte = 0x{:02X})",
            synack[DO_RES_BYTE_OFFSET]
        ));
    }

    // (c) Complete the handshake to confirm the state machine isn't confused.
    set_virt_ns(2_000_000);
    let final_ack = build_tcp_frame(
        PEER_IP,
        PEER_PORT,
        OUR_IP,
        LOCAL_PORT,
        PEER_ISS.wrapping_add(1),
        our_iss.wrapping_add(1),
        TCP_ACK,
        u16::MAX,
        TcpOpts::default(),
        &[],
    );
    if let Err(e) = h.eng.inject_rx_frame(&final_ack) {
        return fail(format!("inject final ACK: {e:?}"));
    }
    let _ = drain_tx_frames();

    if h.eng.accept_next(listen).is_none() {
        return fail(
            "handshake did not complete after reserved-bit SYN: accept_next returned None"
                .into(),
        );
    }

    ProbeResult {
        clause_id: "Reserved-RX",
        probe_name: "ReservedBitsRx",
        status: ProbeStatus::Pass,
        message: "reserved-bit-set SYN accepted; emitted SYN-ACK has reserved=0; handshake completed"
            .into(),
    }
}

fn fail(detail: String) -> ProbeResult {
    ProbeResult {
        clause_id: "Reserved-RX",
        probe_name: "ReservedBitsRx",
        status: ProbeStatus::Fail(detail),
        message: String::new(),
    }
}

/// Recompute the TCP checksum in place after mutating the TCP header /
/// payload of an Ethernet-framed IPv4/TCP packet built by
/// `test_packet::build_tcp_frame`.
///
/// Layout assumed (matches `tcp_output::build_segment`):
///   - bytes [0..14] = Ethernet header
///   - bytes [14..34] = IPv4 header (20 bytes, no IP options)
///   - bytes [tcp_hdr_offset..] = TCP header + payload
///
/// Re-uses `dpdk_net_core::l3_ip::internet_checksum` for the one's-complement
/// fold so the byte-for-byte result matches what `build_segment` would
/// have produced had the reserved-bit patch been present from the start
/// (verified end-to-end: the engine's RX path checks `nic_csum_ok=false`
/// against a newly-folded csum and would Err::Csum on a mismatch).
fn recompute_tcp_csum(frame: &mut [u8], tcp_hdr_offset: usize) {
    // Zero the csum field (offset 16..18 within the TCP header) before folding.
    frame[tcp_hdr_offset + 16] = 0;
    frame[tcp_hdr_offset + 17] = 0;

    // Extract src/dst IPs from the IPv4 header at bytes [14..34].
    let mut src_ip_bytes = [0u8; 4];
    src_ip_bytes.copy_from_slice(&frame[14 + 12..14 + 16]);
    let mut dst_ip_bytes = [0u8; 4];
    dst_ip_bytes.copy_from_slice(&frame[14 + 16..14 + 20]);

    let tcp_seg_len = (frame.len() - tcp_hdr_offset) as u16;

    // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_len(2).
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip_bytes);
    pseudo[4..8].copy_from_slice(&dst_ip_bytes);
    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    pseudo[10..12].copy_from_slice(&tcp_seg_len.to_be_bytes());

    let tcp_body = &frame[tcp_hdr_offset..];
    let csum = internet_checksum(&[&pseudo, tcp_body]);
    frame[tcp_hdr_offset + 16] = (csum >> 8) as u8;
    frame[tcp_hdr_offset + 17] = (csum & 0xff) as u8;
}
