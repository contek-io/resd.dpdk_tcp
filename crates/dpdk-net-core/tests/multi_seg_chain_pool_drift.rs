//! A10 follow-up: multi-segment mbuf chain pool-drift regression.
//!
//! ENA does NOT advertise `RTE_ETH_RX_OFFLOAD_SCATTER` so the chain-walk
//! paths in `tcp_input::handle_established` (in-order branch at
//! `tcp_input.rs:1187-1243`, OOO branch at `tcp_input.rs:1330-1398`) are
//! dormant under production traffic. Existing tests
//! (`i8_multi_seg_fin_piggyback.rs`, `rx_zero_copy_multi_seg.rs`,
//! `i8_fin_piggyback_chain.rs`) cover correctness on a single chain but
//! do NOT detect a per-iteration leak that only surfaces over many
//! iterations.
//!
//! This test sustains chain dispatch across N=100 iterations and
//! asserts the test-inject mempool's free-mbuf count returns to within
//! a tight tolerance of the pre-test baseline. A leak of one chain link
//! per iteration would surface as monotonic drift; a 100-iter run amplifies
//! the signal far beyond random per-iteration noise.
//!
//! Approach
//! --------
//! 1. Test-server bypass engine (`port_id == u16::MAX`, no PCI / TAP
//!    needed) — gives us `listen` + `inject_rx_frame` for the 3WHS.
//! 2. Drive a passive 3WHS to ESTABLISHED via `inject_rx_frame`.
//! 3. Per iteration: build a 3-segment mbuf chain via `inject_rx_chain`.
//!    Segment 0 carries ETH+IPv4+TCP+chunk1 with valid checksums;
//!    segments 1+2 carry chunk2 / chunk3 as raw payload continuation.
//!    The engine's L2/L3/L4 decode runs on segment 0 only (the IP
//!    `total_length` reflects the head-only payload + headers); the
//!    chain walk in `handle_established` then pulls bytes from links
//!    1 and 2 via `shim_rte_pktmbuf_data_len` / `shim_rte_pktmbuf_next`,
//!    transferring one refcount unit per link into `recv.bytes`.
//! 4. After each inject, drop the held refs via
//!    `test_clear_pinned_rx_mbufs` (mirrors the top-of-`poll_once`
//!    drain that releases the previous poll's `delivered_segments`).
//! 5. Inject one OOO chain (seq > rcv_nxt) so the OOO branch
//!    (tcp_input.rs:1330-1398) is also exercised; verify
//!    `tcp.rx_reassembly_queued` bumped.
//! 6. Final clear → assert `test_inject` pool drift ≤ ±8 mbufs and
//!    `tcp.mbuf_refcnt_drop_unexpected == 0`.
//!
//! Coverage relationship
//! ---------------------
//! - `i8_multi_seg_fin_piggyback.rs`: in-memory port without real-pool
//!   mbufs (uses the test-server bypass single-frame path).
//! - `rx_zero_copy_multi_seg.rs`: real-pool mbufs but ONE chain only
//!   and exits the engine entirely after dispatch — does NOT exercise
//!   sustained alloc/dispatch/free balance.
//! - `i8_fin_piggyback_chain.rs`: pure-unit OOO drain analogue of the
//!   chain-walk path; correctness, not pool drift.
//! - This test: real-pool mbufs, real chain dispatch, sustained N
//!   iterations, real chain-walk in-order delivery, plus
//!   `mbuf_refcnt_drop_unexpected = 0` assertion as the secondary
//!   leak-signal channel.
//!
//! Gating
//! ------
//! Requires both `test-server` (the bypass engine + the listen / accept
//! / inject_rx_frame + drain_tx_frames TX-intercept rig) and
//! `test-inject` (the `inject_rx_chain` API + `test_inject_pool_ptr`
//! accessor). Runtime-gated on `DPDK_NET_TEST_TAP=1` to match the
//! `make_test_engine` convention used by every other test that
//! interacts with DPDK pools.

#![cfg(all(feature = "test-inject", feature = "test-server"))]

use std::sync::atomic::Ordering;

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::{TCP_ACK, TCP_PSH};
use dpdk_net_core::test_server::test_packet::{
    build_tcp_ack, build_tcp_frame, build_tcp_syn, parse_syn_ack,
};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

const OUR_IP: u32 = 0x0a_63_1b_02; // 10.99.27.2
const PEER_IP: u32 = 0x0a_63_1b_01; // 10.99.27.1
const PORT: u16 = 5027;
const PEER_PORT: u16 = 40_027;

const ITERATIONS: usize = 100;
const HEAD_PAYLOAD_LEN: usize = 200;
const LINK1_PAYLOAD_LEN: usize = 100;
const LINK2_PAYLOAD_LEN: usize = 50;
const PAYLOAD_PER_ITER: u32 =
    (HEAD_PAYLOAD_LEN + LINK1_PAYLOAD_LEN + LINK2_PAYLOAD_LEN) as u32;
/// A6 / A8 history note: the `recv.bytes` deque + `delivered_segments`
/// scratch hold mbuf refcounts across `inject_rx_chain` returns until
/// the per-iter `test_clear_pinned_rx_mbufs` runs. The drift tolerance
/// covers minor allocator slack (DPDK per-lcore caches) without masking
/// a one-mbuf-per-iter leak (which over 100 iters at 3 links each
/// would manifest as drift ≥ 100, far exceeding ±8).
const DRIFT_TOLERANCE: i64 = 8;

fn skip_if_not_tap() -> bool {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!(
            "skipping; set DPDK_NET_TEST_TAP=1 to run (EAL init + DPDK mempool \
             allocation require hugepages / --in-memory + sudo)"
        );
        return true;
    }
    false
}

fn test_eal_args() -> Vec<&'static str> {
    vec![
        "dpdk-net-multi-seg-chain-pool-drift",
        "--in-memory",
        "--no-pci",
        "-l",
        "0-1",
        "--log-level=3",
    ]
}

fn engine_config() -> EngineConfig {
    EngineConfig {
        port_id: u16::MAX, // test-server bypass: no PMD bring-up
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        ..Default::default()
    }
}

/// Drive a passive 3WHS via `inject_rx_frame`. Returns
/// `(our_iss, initial_peer_seq)` so the data-injection loop knows the
/// starting seq + ack values for the chain head.
fn drive_passive_handshake(eng: &Engine) -> (u32, u32) {
    let listen_h = eng.listen(OUR_IP, PORT).expect("listen");
    let _ = drain_tx_frames();

    set_virt_ns(1_000_000);
    let initial_peer_iss: u32 = 0x10000000;
    let syn = build_tcp_syn(PEER_IP, PEER_PORT, OUR_IP, PORT, initial_peer_iss, 1460);
    eng.inject_rx_frame(&syn).expect("inject SYN");
    let frames = drain_tx_frames();
    assert_eq!(frames.len(), 1, "exactly one SYN-ACK expected");
    let (our_iss, _ack) = parse_syn_ack(&frames[0]).expect("parse SYN-ACK");

    set_virt_ns(2_000_000);
    let final_ack = build_tcp_ack(
        PEER_IP,
        PEER_PORT,
        OUR_IP,
        PORT,
        initial_peer_iss.wrapping_add(1),
        our_iss.wrapping_add(1),
    );
    eng.inject_rx_frame(&final_ack).expect("inject final ACK");
    let post = drain_tx_frames();
    assert_eq!(
        post.len(),
        0,
        "ESTABLISHED transition must not emit a TX frame"
    );

    let _conn = eng
        .accept_next(listen_h)
        .expect("accept_next yields conn");
    (our_iss, initial_peer_iss.wrapping_add(1))
}

#[test]
fn multi_seg_chain_pool_drift_zero_across_n_iters() {
    if skip_if_not_tap() {
        return;
    }

    set_virt_ns(0);
    eal_init(&test_eal_args()).expect("eal_init");
    let eng = Engine::new(engine_config()).expect("Engine::new");

    let (our_iss, mut peer_seq) = drive_passive_handshake(&eng);
    let our_ack = our_iss.wrapping_add(1);

    // Force the test-inject pool to materialize BEFORE we snapshot the
    // baseline. Touching `test_inject_pool_ptr` triggers
    // `OnceCell::get_or_init`; subsequent `inject_rx_chain` calls reuse
    // the same pool. Without this, the first inject would silently drop
    // a few mbufs from the freshly-created pool's per-lcore cache and
    // skew the drift number.
    let pool_ptr = eng.test_inject_pool_ptr();
    assert!(!pool_ptr.is_null(), "test-inject pool ptr is null");

    // Warm-up: do one inject + drain so any first-injection lazy state
    // (per-lcore cache prefill, RX-mbuf scratch growth) settles before
    // we snapshot. Mirrors the convention `rx_mempool_no_leak.rs` uses
    // (baseline taken AFTER bring-up consumes its fixed quota).
    {
        let head = build_chain_head_frame(peer_seq, our_ack, &[0xa0; HEAD_PAYLOAD_LEN]);
        let link1 = vec![0xa1u8; LINK1_PAYLOAD_LEN];
        let link2 = vec![0xa2u8; LINK2_PAYLOAD_LEN];
        eng.inject_rx_chain(&[&head, &link1, &link2])
            .expect("warm-up chain inject");
        peer_seq = peer_seq.wrapping_add(PAYLOAD_PER_ITER);
        // Drop any TX (window updates / data-acks) the engine emitted.
        let _ = drain_tx_frames();
        // Release pinned refs (mirror top-of-poll drain).
        eng.test_clear_pinned_rx_mbufs();
    }

    let avail_baseline = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool_ptr) };
    let drop_unexpected_baseline = eng
        .counters()
        .tcp
        .mbuf_refcnt_drop_unexpected
        .load(Ordering::Relaxed);
    let rx_data_baseline = eng.counters().tcp.rx_data.load(Ordering::Relaxed);
    let eth_rx_bytes_baseline = eng.counters().eth.rx_bytes.load(Ordering::Relaxed);
    let recv_buf_delivered_baseline = eng
        .counters()
        .tcp
        .recv_buf_delivered
        .load(Ordering::Relaxed);
    eprintln!(
        "[multi-seg-chain-pool-drift] baseline avail={} mbuf_refcnt_drop_unexpected={} \
         tcp.rx_data={} eth.rx_bytes={} tcp.recv_buf_delivered={}",
        avail_baseline,
        drop_unexpected_baseline,
        rx_data_baseline,
        eth_rx_bytes_baseline,
        recv_buf_delivered_baseline
    );

    // Steady-state loop. Each iteration: build chain, inject, release
    // pinned refs. If a chain-walk path leaks one mbuf per iter the pool
    // will visibly drain across the N=100 iters.
    for i in 0..ITERATIONS {
        // Distinct payload patterns per iter so a stuck/replayed mbuf
        // is forensically obvious in any post-hoc dump.
        let head_byte = (0x40 + (i & 0x0f) as u8) | 0x80;
        let link1_byte = (0x40 + (i & 0x0f) as u8) | 0xa0;
        let link2_byte = (0x40 + (i & 0x0f) as u8) | 0xc0;

        let head = build_chain_head_frame(
            peer_seq,
            our_ack,
            &vec![head_byte; HEAD_PAYLOAD_LEN],
        );
        let link1 = vec![link1_byte; LINK1_PAYLOAD_LEN];
        let link2 = vec![link2_byte; LINK2_PAYLOAD_LEN];

        eng.inject_rx_chain(&[&head, &link1, &link2])
            .unwrap_or_else(|e| panic!("iter {i}: inject_rx_chain: {e:?}"));

        peer_seq = peer_seq.wrapping_add(PAYLOAD_PER_ITER);
        let _ = drain_tx_frames();
        eng.test_clear_pinned_rx_mbufs();

        // Mid-run sanity: check pool once at the halfway mark so a
        // catastrophic leak surfaces quickly with a useful iter index.
        if i == ITERATIONS / 2 {
            let avail_mid = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool_ptr) };
            let drift_mid = (avail_baseline as i64) - (avail_mid as i64);
            eprintln!(
                "[multi-seg-chain-pool-drift] mid (iter {i}) avail={} drift={}",
                avail_mid, drift_mid
            );
        }
    }

    // OOO chain-walk coverage (tcp_input.rs:1330-1398).
    // ─────────────────────────────────────────────────────────────────────
    // The in-order loop above only exercises the in-order branch
    // (tcp_input.rs:1187-1243). The OOO chain walk shares the same
    // alloc / refcount lifecycle but takes the `seq_lt(rcv_nxt, seq)`
    // arm, which calls `reorder.insert` per link instead of
    // `recv.bytes.push_back`. We exercise it once with a 3-segment OOO
    // chain at seq + gap (so it stays buffered), then send a single
    // gap-filling chunk that drains everything into in-order.
    let rx_reassembly_queued_before_ooo = eng
        .counters()
        .tcp
        .rx_reassembly_queued
        .load(Ordering::Relaxed);

    // OOO chain: gap before the head so seq > rcv_nxt. Place it 1000
    // bytes ahead so any future in-order drain has a single, well-known
    // hole to fill. peer_seq is the next-expected in-order seq; the OOO
    // head sits at peer_seq + 1000.
    let ooo_head_seq = peer_seq.wrapping_add(1000);
    let ooo_head = build_chain_head_frame(ooo_head_seq, our_ack, &[0xee; HEAD_PAYLOAD_LEN]);
    let ooo_link1 = vec![0xefu8; LINK1_PAYLOAD_LEN];
    let ooo_link2 = vec![0xf0u8; LINK2_PAYLOAD_LEN];
    eng.inject_rx_chain(&[&ooo_head, &ooo_link1, &ooo_link2])
        .expect("OOO chain inject");
    let _ = drain_tx_frames();

    let rx_reassembly_queued_after_ooo = eng
        .counters()
        .tcp
        .rx_reassembly_queued
        .load(Ordering::Relaxed);
    assert_eq!(
        rx_reassembly_queued_after_ooo,
        rx_reassembly_queued_before_ooo + 1,
        "tcp.rx_reassembly_queued must bump exactly once per OOO chain inject \
         — proves OOO branch (tcp_input.rs:1280-1399) was reached + \
         `outcome.reassembly_queued_bytes > 0` after the link walk"
    );

    // Don't try to drain the OOO chain via gap fill — the gap is 1000
    // bytes wide and `inject_rx_frame` would need that many filler
    // bytes worth of in-order data; building+injecting that is more
    // complexity than it buys for the structural guard. Instead,
    // `test_clear_pinned_rx_mbufs` releases the reorder queue's pinned
    // refs (it calls `reorder.clear()` per engine.rs:6814), which
    // returns those mbufs to the pool — the pool-drift assertion
    // covers the OOO refcount accounting structurally.

    // Final clear (defense in depth — should already be clear from the
    // last iter's inject loop) before sampling the pool.
    eng.test_clear_pinned_rx_mbufs();

    let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool_ptr) };
    let drift = (avail_baseline as i64) - (avail_post as i64);
    let drop_unexpected_post = eng
        .counters()
        .tcp
        .mbuf_refcnt_drop_unexpected
        .load(Ordering::Relaxed);
    let rx_data_post = eng.counters().tcp.rx_data.load(Ordering::Relaxed);
    let eth_rx_bytes_post = eng.counters().eth.rx_bytes.load(Ordering::Relaxed);
    let recv_buf_delivered_post = eng
        .counters()
        .tcp
        .recv_buf_delivered
        .load(Ordering::Relaxed);
    let rx_data_delta = rx_data_post - rx_data_baseline;
    let eth_rx_bytes_delta = eth_rx_bytes_post - eth_rx_bytes_baseline;
    let recv_buf_delivered_delta = recv_buf_delivered_post - recv_buf_delivered_baseline;
    eprintln!(
        "[multi-seg-chain-pool-drift] post avail={} drift={} drop_unexpected={} \
         tcp.rx_data delta={} eth.rx_bytes delta={} tcp.recv_buf_delivered delta={}",
        avail_post,
        drift,
        drop_unexpected_post,
        rx_data_delta,
        eth_rx_bytes_delta,
        recv_buf_delivered_delta
    );

    // Coverage check: `tcp.rx_data` bumps ONCE per non-empty-payload TCP
    // segment that reaches `tcp_input::dispatch`. We injected
    // `ITERATIONS` in-order chains plus 1 OOO chain (= total
    // `EXPECTED_NON_EMPTY_DISPATCHES`), each with payload, so the delta
    // MUST equal that exactly if every chain landed in
    // `handle_established` and reached either the in-order chain-walk
    // (tcp_input.rs:1187) or the OOO chain-walk (tcp_input.rs:1330).
    // A delta significantly less means the engine dropped chains
    // earlier (IP/TCP cksum mismatch, four-tuple miss, etc.) and the
    // chain-walk paths were NOT exercised — the drift assertion below
    // would still pass on a vacuous run, hence this gating coverage
    // check.
    const EXPECTED_NON_EMPTY_DISPATCHES: u64 = ITERATIONS as u64 + 1; // +1 for OOO
    assert_eq!(
        rx_data_delta, EXPECTED_NON_EMPTY_DISPATCHES,
        "expected exactly {EXPECTED_NON_EMPTY_DISPATCHES} tcp.rx_data bumps \
         (one per chain dispatch reaching `handle_established`); got \
         {rx_data_delta}. Chain-walk paths likely NOT exercised — \
         pool-drift assertion would pass vacuously."
    );
    // `eth.rx_bytes` bumps by head segment data_len per `inject_rx_chain`
    // call (one bump per head, NOT per chain link). Lower bound check:
    // (ITERATIONS + 1) * head_frame_bytes (each iter's head frame is
    // fixed size = ETH(14) + IP(20) + TCP(20) + HEAD_PAYLOAD_LEN, plus
    // the OOO chain's head).
    let expected_head_frame_bytes = (14 + 20 + 20 + HEAD_PAYLOAD_LEN) as u64;
    assert!(
        eth_rx_bytes_delta >= EXPECTED_NON_EMPTY_DISPATCHES * expected_head_frame_bytes,
        "eth.rx_bytes delta {eth_rx_bytes_delta} < {EXPECTED_NON_EMPTY_DISPATCHES} * \
         head_frame_bytes({expected_head_frame_bytes}); chains may have been \
         truncated before dispatch"
    );

    // CHAIN-WALK PROOF: `tcp.recv_buf_delivered` adds `outcome.delivered`
    // per `deliver_readable` call (engine.rs:4769). `outcome.delivered`
    // is the sum of bytes that became `InOrderSegment` entries — head
    // payload PLUS each chain-link's `data_len`. If the chain-walk in
    // `tcp_input.rs:1187-1243` did NOT fire (e.g. mbuf_ctx was None,
    // head_take==0, or some refactor regression skipped the
    // `while !cur.is_null()` loop), only the head's bytes would land
    // and we'd see `ITERATIONS * HEAD_PAYLOAD_LEN` instead of
    // `ITERATIONS * PAYLOAD_PER_ITER`. Exact equality (not lower bound)
    // because the test-server bypass means no concurrent traffic.
    let expected_recv_bytes = ITERATIONS as u64 * PAYLOAD_PER_ITER as u64;
    assert_eq!(
        recv_buf_delivered_delta, expected_recv_bytes,
        "tcp.recv_buf_delivered delta {recv_buf_delivered_delta} != \
         ITERATIONS({ITERATIONS}) * PAYLOAD_PER_ITER({PAYLOAD_PER_ITER}) = \
         {expected_recv_bytes}. The chain-walk path in \
         `tcp_input::handle_established` (tcp_input.rs:1187-1243) was NOT \
         exercised — the in-order branch processed only the head's \
         payload, not the chained links."
    );

    assert!(
        drift.abs() <= DRIFT_TOLERANCE,
        "test-inject pool drift {drift} exceeds tolerance ±{DRIFT_TOLERANCE} \
         after {ITERATIONS} chain iterations (baseline={avail_baseline}, \
         post={avail_post}) — likely leak in `tcp_input::handle_established` \
         chain-walk paths (in-order tcp_input.rs:1187-1243 / OOO 1330-1398)"
    );
    assert_eq!(
        drop_unexpected_post, drop_unexpected_baseline,
        "tcp.mbuf_refcnt_drop_unexpected fired during chain-dispatch loop \
         — refcount went below zero on a chain-link mbuf, signaling a \
         double-free or rollback-bookkeeping bug in the chain-walk path"
    );
}

/// Build a synthetic chain-head frame: ETH + IPv4 + TCP + `payload`. The
/// IPv4 `total_length` reflects head-only headers + payload (NOT the
/// chain-aggregate); the TCP checksum covers head-only payload too.
/// Subsequent chain links carry raw payload continuation that the
/// `tcp_input` chain walk picks up via `shim_rte_pktmbuf_data_len`.
fn build_chain_head_frame(seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    build_tcp_frame(
        PEER_IP,
        PEER_PORT,
        OUR_IP,
        PORT,
        seq,
        ack,
        TCP_ACK | TCP_PSH,
        u16::MAX,
        TcpOpts::default(),
        payload,
    )
}
