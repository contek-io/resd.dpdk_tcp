//! A7 Task 5: minimal server-FSM support behind the `test-server` feature.
//!
//! A `ListenSlot` holds a single local (ip, port) and an at-most-one
//! accept queue. `Engine::tcp_input` dispatches inbound SYNs whose
//! dst-(ip,port) matches a `ListenSlot` into `handle_inbound_syn_listen`,
//! which allocates a per-conn slot in SYN_RCVD, emits SYN-ACK via the
//! existing builder, and parks it until the final ACK arrives. Additional
//! SYNs that land while an accept is queued OR an in-progress SYN_RCVD
//! exists are rejected with RST + ACK.

use crate::flow_table::ConnHandle;

/// Opaque handle for a listening socket; `1`-based so `0` is available
/// as an "uninitialized" sentinel in caller code if desired.
pub type ListenHandle = u32;

/// A single listening endpoint. Capacity is intentionally one:
/// the phase-A7 scope is a single pending conn + a single accepted
/// conn, no multi-accept queue and no SO_REUSEPORT.
#[derive(Debug)]
pub struct ListenSlot {
    pub local_ip: u32,
    pub local_port: u16,
    /// At most one queued ESTABLISHED handle waiting on `accept_next`.
    pub accept_queue: Option<ConnHandle>,
    /// An in-progress SYN_RCVD handle tied to this listen; cleared when
    /// the final ACK transitions it to ESTABLISHED.
    pub in_progress: Option<ConnHandle>,
}

impl ListenSlot {
    pub fn new(local_ip: u32, local_port: u16) -> Self {
        Self {
            local_ip,
            local_port,
            accept_queue: None,
            in_progress: None,
        }
    }
}

/// A7 Task 12: packet-builder + parsing helpers exposed on the public
/// crate surface so out-of-crate test consumers (tools/packetdrill-shim-runner)
/// can build Ethernet/IPv4/TCP frames byte-identical to what the engine
/// parses at wire level. The in-crate integration tests'
/// `tests/common/mod.rs` re-exports these so behavior across both call
/// sites is guaranteed-identical (zero drift between shim-runner tests
/// and the existing A7 server FSM tests).
pub mod test_packet {
    use crate::tcp_options::{SackBlock, TcpOpts};
    use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_FIN, TCP_SYN};

    /// Build an Ethernet-framed IPv4/TCP packet using the same
    /// `build_segment` the engine emits on the wire. Reuses
    /// `tcp_output::build_segment` so the on-wire format stays
    /// byte-identical to what the engine would parse in production.
    /// Caller provides the flag set + options; the checksum is computed
    /// by `build_segment` itself.
    #[allow(clippy::too_many_arguments)]
    pub fn build_tcp_frame(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        options: TcpOpts,
        payload: &[u8],
    ) -> Vec<u8> {
        // MAC values are cosmetic for the test-server RX path; the engine
        // reads L2 to advance to L3 but doesn't validate src_mac.
        let seg = SegmentTx {
            src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            dst_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            options,
            payload,
        };
        let mut buf = vec![0u8; 14 + 20 + 60 + payload.len()];
        let n = build_segment(&seg, &mut buf).expect("build_segment fits");
        buf.truncate(n);
        buf
    }

    /// Bare SYN frame with an MSS option (peer_mss) for injection via
    /// `Engine::inject_rx_frame`.
    pub fn build_tcp_syn(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        iss: u32,
        peer_mss: u16,
    ) -> Vec<u8> {
        let mut opts = TcpOpts::default();
        opts.mss = Some(peer_mss);
        build_tcp_frame(
            src_ip, src_port, dst_ip, dst_port, iss, 0, TCP_SYN, u16::MAX, opts, &[],
        )
    }

    /// Bare ACK frame (no options, empty payload).
    pub fn build_tcp_ack(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        build_tcp_frame(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            seq,
            ack,
            TCP_ACK,
            u16::MAX,
            TcpOpts::default(),
            &[],
        )
    }

    /// Bare FIN+ACK frame (flags 0x11), no options, empty payload. For
    /// passive-close scenarios where the peer initiates FIN.
    pub fn build_tcp_fin(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        build_tcp_frame(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            seq,
            ack,
            TCP_FIN | TCP_ACK,
            u16::MAX,
            TcpOpts::default(),
            &[],
        )
    }

    /// A7 Task 16: bare ACK frame carrying a single SACK block + Timestamps
    /// option. The SACK block covers the half-open range
    /// `[sack_left, sack_right)` in TCP byte-stream seqs (host byte order);
    /// the peer Timestamps value `tsval` pairs with a `tsecr` equal to the
    /// engine's most recent advertised TSval (the caller passes both so
    /// the ack is RFC-7323-valid — a zero `tsecr` is acceptable because
    /// the engine accepts the initial ACK post-SYN with zero echo).
    ///
    /// SACK option wire shape: `[kind=5, len=2 + 8*N, left_be_u32,
    /// right_be_u32, ...]`. `TcpOpts::encode` (in `tcp_options.rs`) writes
    /// the option at the canonical position in the options block, so this
    /// helper just populates `opts.sack_blocks` + `opts.timestamps` and
    /// lets `build_tcp_frame` → `build_segment` take care of the wire
    /// layout.
    #[allow(clippy::too_many_arguments)]
    pub fn build_tcp_ack_with_sack(
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        seq: u32,
        ack: u32,
        sack_left: u32,
        sack_right: u32,
        tsval: u32,
    ) -> Vec<u8> {
        let mut opts = TcpOpts::default();
        opts.timestamps = Some((tsval, 0));
        opts.push_sack_block_decode(SackBlock {
            left: sack_left,
            right: sack_right,
        });
        build_tcp_frame(
            src_ip, src_port, dst_ip, dst_port, seq, ack, TCP_ACK, u16::MAX, opts, &[],
        )
    }

    /// Parse a just-emitted frame from `drain_tx_frames`; extract the
    /// SYN-ACK's server ISS (= seq field) + the ack-value (which must be
    /// peer_iss + 1). Ignores IP / L2 validation — the test-server TX
    /// frames are produced by our own `build_segment`, so they're
    /// trivially well-formed. Returns `None` if the frame is too short
    /// or the SYN|ACK bits aren't set.
    pub fn parse_syn_ack(frame: &[u8]) -> Option<(u32, u32)> {
        if frame.len() < 14 + 20 + 20 {
            return None;
        }
        // L2 = 14. Read IP header length to locate TCP header.
        let ip_ihl = (frame[14] & 0x0f) as usize * 4;
        let tcp_off = 14 + ip_ihl;
        if frame.len() < tcp_off + 20 {
            return None;
        }
        let tcp = &frame[tcp_off..];
        // Flags byte at offset 13 within the TCP header.
        let flags = tcp[13];
        // SYN|ACK = 0x12.
        if flags & 0x12 != 0x12 {
            return None;
        }
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        Some((seq, ack))
    }

    /// Extract `(seq, ack)` from a wire-format TCP frame produced by
    /// `drain_tx_frames`. Does not validate flags — callers already
    /// know what shape frame they just pulled off the TX ring.
    pub fn parse_tcp_seq_ack(frame: &[u8]) -> (u32, u32) {
        let ip_ihl = (frame[14] & 0x0f) as usize * 4;
        let tcp = &frame[14 + ip_ihl..];
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        (seq, ack)
    }
}
