#![cfg(feature = "test-server")]
//! A7 T16: I-8 multi-seg FIN-piggyback regression (A6.6-7 bug b4e8de9).
//!
//! The I-8 bug: `snd_retrans.data_len` used to reflect the full on-wire
//! frame size (ETH + IPv4 + TCP-with-options + payload) instead of the
//! TCP-payload length. A multi-seg TX chain with a trailing FIN would
//! miscount, causing the retransmitted segment's payload length to
//! differ from the originally-sent TCP payload. Fixed at commit b4e8de9.
//!
//! This test is a Rust-level in-memory port of the plan's
//! `tests/scripts/i8_multi_seg_fin_piggyback.pkt`, adapted to the
//! test-server bypass rig (port_id = u16::MAX) — same approach the T12
//! shim direct self-tests use — because the T10 packetdrill shim doesn't
//! yet run the scripts end-to-end (T15 pragmatic floor).
//!
//! Coverage relationship: `tests/multiseg_retrans_tap.rs` exercises the
//! same invariant (data_len == hdrs_len + entry_len) under a real TAP +
//! kernel peer with `DPDK_NET_TEST_TAP=1`. This in-memory variant makes
//! the regression part of the default (no-sudo, no-root) cargo-test pass
//! so every developer sees the post-fix invariant checked on every run,
//! not just the TAP-gated builds.
//!
//! Scenario shape:
//!   1. passive three-way handshake (via `common::drive_passive_handshake`)
//!      to bring the conn into ESTABLISHED.
//!   2. three writes (500 / 700 / 300 bytes) → 3 entries in `snd_retrans`,
//!      each with payload-only `len` (the I-8 contract).
//!   3. `close_conn` enqueues a bare FIN as its own segment.
//!   4. `eng.flush_tx_pending_data()` drains data + FIN onto the TX
//!      intercept queue; we capture original payload length of segment 0.
//!   5. invoke `engine.debug_retransmit_for_test(conn, 0)` — the same
//!      deterministic trigger `multiseg_retrans_tap.rs` uses — which
//!      walks the full retransmit primitive including the I-8 invariant
//!      `debug_assert` at engine.rs:5107-5121.
//!   6. drain TX, find the retransmitted frame, and assert its TCP
//!      payload length equals the originally-sent payload bytes.
//!
//! Pre-I-8-fix this test would fire the `data_len >= entry_len` or
//! `data_len <= hdrs_len + entry_len` debug_assert on the first
//! `debug_retransmit_for_test` call (debug builds) or produce a
//! malformed retransmit on release builds.

mod common;

use common::*;
use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

/// Extract the TCP payload length from a wire-format frame produced by
/// `drain_tx_frames`. Walks ETH(14) → IP(ihl*4) → TCP(doff*4); the
/// remainder is payload.
fn tcp_payload_len(frame: &[u8]) -> usize {
    let ip_ihl = (frame[14] & 0x0f) as usize * 4;
    let ip_total_len = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let tcp = &frame[14 + ip_ihl..];
    let tcp_doff = ((tcp[12] >> 4) & 0x0f) as usize * 4;
    ip_total_len - ip_ihl - tcp_doff
}

/// Extract the TCP flags byte from a wire-format frame.
fn tcp_flags(frame: &[u8]) -> u8 {
    let ip_ihl = (frame[14] & 0x0f) as usize * 4;
    let tcp = &frame[14 + ip_ihl..];
    tcp[13]
}

#[test]
fn i8_multi_seg_retrans_payload_len_is_exact() {
    set_virt_ns(0);
    eal_init(&test_eal_args()).expect("eal_init");
    let eng = Engine::new(test_server_config()).expect("Engine::new");

    // Passive three-way handshake → ESTABLISHED with known peer ISS.
    let lh = eng.listen(OUR_IP, 5555).expect("listen");
    let (conn_h, _our_iss) = drive_passive_handshake(&eng, lh);
    let _ = drain_tx_frames();

    // Three writes totalling 1500 bytes. `send_bytes` does not coalesce
    // across calls (each call builds at most MSS-sized segments from its
    // own buffer), so we get three separate segments: 500, 700, 300.
    // Each lands in `snd_retrans` as a separate entry with payload-only
    // `len` — the I-8 contract. The regression shape we test is:
    //   "more than one segment on the retrans queue, and the first
    //    segment's entry.len tracks the TCP payload, not the full-frame
    //    size"
    // — which is the minimum needed to force the retransmit path to
    // slice the payload bytes back out of the header-plus-payload mbuf
    // using the payload-only `len`.
    let w1 = vec![0xaau8; 500];
    let w2 = vec![0xbbu8; 700];
    let w3 = vec![0xccu8; 300];
    set_virt_ns(100_000_000);
    eng.send_bytes(conn_h, &w1).expect("send_bytes w1");
    eng.send_bytes(conn_h, &w2).expect("send_bytes w2");
    eng.send_bytes(conn_h, &w3).expect("send_bytes w3");
    // close_conn emits a bare FIN as its own frame; in the in-memory rig
    // the FIN-piggyback fast path doesn't apply (close_conn is the
    // dedicated FIN-emission site), but the multi-seg data that preceded
    // is still the object under test.
    eng.close_conn(conn_h).expect("close_conn");
    // send_bytes pushes data mbufs into `tx_pending_data`; the ring is
    // drained by `poll_once` (or an explicit flush). Without a flush the
    // TX intercept queue stays empty.
    eng.flush_tx_pending_data();

    let data_frames = drain_tx_frames();
    assert!(
        !data_frames.is_empty(),
        "at least one data + FIN frame expected"
    );

    // Identify the first data segment (non-empty TCP payload, no FIN bit).
    let first_data_idx = data_frames
        .iter()
        .position(|f| tcp_payload_len(f) > 0 && (tcp_flags(f) & 0x01) == 0)
        .expect("at least one data segment expected in TX burst");
    let first = &data_frames[first_data_idx];
    let first_payload_len = tcp_payload_len(first);
    let (first_seq, _) = parse_tcp_seq_ack(first);
    let original_payload_len = first_payload_len;
    assert!(
        original_payload_len > 0,
        "first data frame should carry non-zero payload"
    );

    // Sanity-check: snd_retrans should hold at least two entries — the
    // three send_bytes calls all fit under MSS=1460 as their own
    // segments, and close_conn enqueues a FIN which is handled as its
    // own entry too. The minimum shape we need for the I-8 regression
    // to be meaningful is two+ entries so the retrans slice logic has
    // to actually walk past the first.
    let snd_retrans_len = {
        let ft = eng.flow_table();
        ft.get(conn_h).map(|c| c.snd_retrans.len()).unwrap_or(0)
    };
    assert!(
        snd_retrans_len >= 2,
        "need ≥2 snd_retrans entries for meaningful I-8 regression shape; got {}",
        snd_retrans_len
    );
    eprintln!(
        "[i8-test] original_payload_len={} first_seq={:#x} snd_retrans_len={} num_data_frames={}",
        original_payload_len,
        first_seq,
        snd_retrans_len,
        data_frames.len(),
    );

    // Deterministic trigger: synthesize a retransmit on snd_retrans[0].
    // This is the same mechanism `multiseg_retrans_tap.rs` uses to
    // force the I-8 assertion path without racing natural RTO/RACK/TLP
    // timers. The full retransmit primitive walks the invariants
    // (data_len >= entry_len AND data_len <= entry_hdrs_len + entry_len
    // at engine.rs:5107-5121), chains hdr+data mbufs, and pushes onto
    // tx_pending_data. Pre-fix, `entry_len` carried the full-frame size,
    // so data_len (the mbuf payload size) < entry_len (the full-frame
    // size), firing the FIRST debug_assert. Post-fix, entry_len is
    // payload-only and the assert passes — the retrans emits a
    // well-formed frame whose TCP payload length matches the original.
    set_virt_ns(200_000_000);
    eng.debug_retransmit_for_test(conn_h, 0);
    eng.flush_tx_pending_data();

    // Drain TX; expect a retransmit of the first segment among the
    // frames (seq == first_seq).
    let retrans_frames = drain_tx_frames();
    let retrans = retrans_frames
        .iter()
        .find(|f| {
            let (seq, _) = parse_tcp_seq_ack(f);
            seq == first_seq && tcp_payload_len(f) > 0
        })
        .unwrap_or_else(|| {
            panic!(
                "expected retransmit of seq={:#x}; frames={:?}",
                first_seq,
                retrans_frames
                    .iter()
                    .map(|f| (
                        parse_tcp_seq_ack(f).0,
                        tcp_payload_len(f),
                        tcp_flags(f),
                    ))
                    .collect::<Vec<_>>()
            )
        });
    let retrans_len = tcp_payload_len(retrans);

    // THE CORE I-8 ASSERTION: the retransmit's TCP payload length must
    // equal the originally-sent TCP payload length, byte for byte. Pre-fix,
    // `snd_retrans[0].len` carried the full-frame size (ETH + IPv4 + TCP
    // + payload), so the retransmit would either trip the
    // `data_len >= entry_len` debug_assert or emit a frame with a wrong
    // (inflated) payload length. Post-fix, `entry_len` is payload-only
    // and the retransmit reconstructs the exact same payload.
    assert_eq!(
        retrans_len, original_payload_len,
        "retransmit payload len must equal original (not full-frame, not payload+1); \
         original={}, retrans={}",
        original_payload_len, retrans_len
    );
}
