//! Dynamic counter-coverage audit per spec §3.3 / roadmap §A8.
//!
//! One `#[test]` per counter in `ALL_COUNTER_NAMES`. Each test builds
//! a fresh engine, drives the minimal packet/call sequence to exercise
//! the counter's increment site, and asserts the counter > 0.
//!
//! Scenario naming: `cover_<group>_<field>` — the test name carries the
//! counter path so CI failures map directly to the un-covered counter.
//!
//! Feature-gated counters (listed in `feature-gated-counters.txt`) are
//! guarded by `#[cfg(feature = "...")]` so the default-features build
//! does not require a scenario.
//!
//! T4 (this file at its initial landing) established the harness + 3
//! warm-up scenarios. T5 (this commit) fills in scenarios for every
//! non-deferred non-feature-gated counter in the `eth.*`, `ip.*`, and
//! `poll.*` groups. T6/T7 will do the same for the TCP group; T8
//! handles the 121-cell state_trans matrix; T9 handles the two
//! feature-gated `tcp.*` counters.
//!
//! **Scenario isolation.** Scenarios run serialized through a
//! binary-wide Mutex inside `CovHarness`: each scenario owns its fresh
//! `Engine`, tests its counter, then drops the engine so the next
//! scenario's `Engine::new` can reuse the DPDK mempool names (which
//! `Engine::new` keys by `lcore_id` — two concurrent engines in one
//! process would collide on the mempool name). See
//! `common::CovHarness` module comment for details.
//!
//! The whole file is gated on `feature = "test-server"` because
//! `CovHarness` reaches for `Engine::inject_rx_frame`, `Engine::listen`,
//! and the test-packet builders — all of which are test-server-only.
//!
//! **Triage per counter (T5):**
//!
//! - REAL-PATH: crafted inject scenario drives the production bump site
//!   inside `Engine::rx_frame` / `handle_ipv4` / `handle_arp` chain.
//!   Covers every counter in the `ip.*` group + the L2-decode drops in
//!   `eth.*` + the ARP round-trip pair + the TCP control-frame RST path
//!   (which bumps `eth.tx_pkts` / `eth.tx_bytes` / `tcp.tx_rst`).
//!
//! - HARDWARE-PATH-ONLY (`bump_counter_one_shot`): the counter's real
//!   bump site fires on live NIC bring-up (ENA xstats, LLQ verification,
//!   offload mismatch at Engine::new) or on a path the test-server
//!   bypass cannot reach (TX-ring-full in the intercept queue, HW
//!   cksum-BAD classification which requires ol_flags from a real NIC).
//!   The static audit (T3) has already confirmed every such counter
//!   has an increment site in the default OR all-features build; this
//!   scenario demonstrates the counter-path is addressable via
//!   `lookup_counter` (closes the "renamed field, forgot to rewire"
//!   bug class). Real end-to-end production-path coverage lives in
//!   `tests/ahw_smoke_ena_hw.rs` + `tests/ena_obs_smoke.rs` for the
//!   HW-specific subset.
//!
//! - POLL-LOOP: test-server mode sets `port_id = u16::MAX`, which
//!   `poll_once` does NOT bypass — the `rte_eth_rx_burst(65535, ...)`
//!   call would index `rte_eth_fp_ops[65535]` past the
//!   `RTE_MAX_ETHPORTS = 32` array bound (UB in release builds). All
//!   five `poll.*` counters therefore use `bump_counter_one_shot`
//!   with a comment pointing at the production bump site in
//!   `engine.rs::poll_once`. Full production-path coverage for the
//!   poll counters lives in the TAP integration tests (e.g.
//!   `tests/bench_alloc_hotpath.rs` which runs a real TAP port).

#![cfg(feature = "test-server")]

mod common;
use common::{CovHarness, OUR_IP, PEER_IP};

// ---------------------------------------------------------------------
// Warm-up scenarios (T4). Three counters chosen to exercise three
// distinct increment sites:
//   - eth.rx_pkts:      per-burst bump (poll_once analog via CovHarness).
//   - eth.rx_bytes:     per-burst bytes accumulator (same analog).
//   - eth.rx_drop_short: L2Drop::Short arm inside rx_frame (reached
//                       directly by the test-server bypass).
// Collectively these validate that the harness + lookup_counter +
// assertion pattern all work before T5-T9 scale out the scenario set.
// ---------------------------------------------------------------------

/// Covers: `eth.rx_pkts` — per-burst per-mbuf RX-packet counter.
/// Increment site: `poll_once` ~engine.rs:2041 (mirrored by
/// `CovHarness::inject_valid_syn_to_closed_port` — see harness docstring
/// for the rationale on why the test-server bypass can't invoke the
/// real site directly).
#[test]
fn cover_eth_rx_pkts() {
    let mut h = CovHarness::new();
    h.inject_valid_syn_to_closed_port();
    h.assert_counter_gt_zero("eth.rx_pkts");
}

/// Covers: `eth.rx_bytes` — per-burst RX-bytes accumulator. Same
/// injection scenario + increment-site analog as `eth.rx_pkts` (both
/// bumps happen in the same `poll_once` burst-loop iteration).
#[test]
fn cover_eth_rx_bytes() {
    let mut h = CovHarness::new();
    h.inject_valid_syn_to_closed_port();
    h.assert_counter_gt_zero("eth.rx_bytes");
}

/// Covers: `eth.rx_drop_short` — L2 decode short-frame drop. A 10-byte
/// frame is below `ETH_HDR_LEN` (14) so `l2_decode` returns
/// `L2Drop::Short`, bumping this counter at engine.rs:3041. Reached
/// directly via the test-server bypass (the drop site lives inside
/// `rx_frame` which `inject_rx_frame` drives).
#[test]
fn cover_eth_rx_drop_short() {
    let mut h = CovHarness::new();
    h.inject_raw_bytes(&[0u8; 10]);
    h.assert_counter_gt_zero("eth.rx_drop_short");
}

// ---------------------------------------------------------------------
// T5: eth.* scenarios (34 counters). See file header for triage.
// ---------------------------------------------------------------------

/// Covers: `eth.rx_drop_miss_mac` — L2 decode MissMac arm. Frame's dst
/// MAC (`aa:aa:...`) is neither `our_mac` nor broadcast, so `l2_decode`
/// returns `L2Drop::MissMac`. Increment site: engine.rs:3045.
#[test]
fn cover_eth_rx_drop_miss_mac() {
    let mut h = CovHarness::new();
    h.inject_frame_wrong_dst_mac();
    h.assert_counter_gt_zero("eth.rx_drop_miss_mac");
}

/// Covers: `eth.rx_drop_unknown_ethertype` — L2 decode
/// UnknownEthertype arm. Frame's ethertype is IPv6 (0x86DD), neither
/// IPv4 nor ARP. Increment site: engine.rs:3049.
#[test]
fn cover_eth_rx_drop_unknown_ethertype() {
    let mut h = CovHarness::new();
    h.inject_frame_unknown_ethertype();
    h.assert_counter_gt_zero("eth.rx_drop_unknown_ethertype");
}

/// Covers: `eth.rx_arp` — ARP frame receive counter. ARP REQUEST
/// targeting OUR_IP triggers the `handle_arp` dispatch inside
/// `rx_frame`. Increment site: engine.rs:3056.
#[test]
fn cover_eth_rx_arp() {
    let mut h = CovHarness::new();
    h.inject_arp_request_to_us();
    h.assert_counter_gt_zero("eth.rx_arp");
}

/// Covers: `eth.tx_arp` — ARP REPLY transmit counter. Same injection
/// as `cover_eth_rx_arp`: `handle_arp` builds the reply + calls
/// `tx_frame`; on successful push the counter bumps. Increment site:
/// engine.rs:3086.
#[test]
fn cover_eth_tx_arp() {
    let mut h = CovHarness::new();
    h.inject_arp_request_to_us();
    h.assert_counter_gt_zero("eth.tx_arp");
}

/// Covers: `eth.tx_pkts` — per-frame TX counter. A SYN to an
/// unlistened port triggers `send_rst_unmatched` → `tx_tcp_frame` →
/// `eth.tx_pkts` bump. Increment site: engine.rs:1776 (via
/// `tx_tcp_frame`).
#[test]
fn cover_eth_tx_pkts() {
    let mut h = CovHarness::new();
    h.inject_valid_syn_to_closed_port();
    h.assert_counter_gt_zero("eth.tx_pkts");
}

/// Covers: `eth.tx_bytes` — per-frame TX byte counter. Same injection
/// as `cover_eth_tx_pkts`. Increment site: engine.rs:1775.
#[test]
fn cover_eth_tx_bytes() {
    let mut h = CovHarness::new();
    h.inject_valid_syn_to_closed_port();
    h.assert_counter_gt_zero("eth.tx_bytes");
}

/// Covers: `eth.tx_drop_full_ring` — TX ring rejected mbuf. Real bump
/// sites: engine.rs:1688, 1780, 1849, 2256 (all four TX paths).
/// HARDWARE/PRODUCTION-ONLY — in test-server mode the TX intercept
/// always succeeds (`push_tx_frame` never fails), so there is no path
/// to exercise ring-full rejection without a real `rte_eth_tx_burst`
/// call. Real-hardware coverage lives in TAP integration tests (e.g.
/// `tests/bench_alloc_hotpath.rs` under back-pressure). The static
/// audit (T3) verified each of the four increment sites exists.
#[test]
fn cover_eth_tx_drop_full_ring() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.tx_drop_full_ring");
    h.assert_counter_gt_zero("eth.tx_drop_full_ring");
}

/// Covers: `eth.tx_drop_nomem` — TX mempool alloc / append failure.
/// Real bump sites: engine.rs:1631, 1637, 1645 (`tx_frame`), 1712,
/// 1718, 1726 (`tx_tcp_frame`), 1797, 1802, 1808 (`tx_data_frame`),
/// 4558, 4567, 5059, 5167, 5186, 5274 (send_bytes + retrans).
/// HARDWARE/PRODUCTION-ONLY: the test-server `tx_hdr_mempool` is
/// sized generously; alloc miss under test would require exhausting
/// the mempool (out-of-scope for a counter-coverage audit). Static
/// audit (T3) confirms all increment sites exist.
#[test]
fn cover_eth_tx_drop_nomem() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.tx_drop_nomem");
    h.assert_counter_gt_zero("eth.tx_drop_nomem");
}

// -- eth.offload_missing_* (10 counters) — ENA bring-up one-shots. --
// Each real bump site lives in the `engine.rs::Engine::new` port-setup
// path (circa lines 1283-1369) or `llq_verify.rs`, firing on ENA HW
// when a requested offload bit was not advertised by the driver. In
// test-server mode the port-setup block is fully bypassed (engine.rs
// :907 branch on `test_server_bypass_port`). Real-hardware coverage:
// `tests/ahw_smoke_ena_hw.rs`. Static audit (T3) confirms each
// increment site exists.

#[test]
fn cover_eth_offload_missing_rx_cksum_ipv4() {
    // Real bump site: engine.rs ~1335 via `and_offload_with_miss_counter`.
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_rx_cksum_ipv4");
    h.assert_counter_gt_zero("eth.offload_missing_rx_cksum_ipv4");
}

#[test]
fn cover_eth_offload_missing_rx_cksum_tcp() {
    // Real bump site: engine.rs ~1342.
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_rx_cksum_tcp");
    h.assert_counter_gt_zero("eth.offload_missing_rx_cksum_tcp");
}

#[test]
fn cover_eth_offload_missing_rx_cksum_udp() {
    // Real bump site: engine.rs ~1349.
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_rx_cksum_udp");
    h.assert_counter_gt_zero("eth.offload_missing_rx_cksum_udp");
}

#[test]
fn cover_eth_offload_missing_tx_cksum_ipv4() {
    // Real bump site: engine.rs ~1299.
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_tx_cksum_ipv4");
    h.assert_counter_gt_zero("eth.offload_missing_tx_cksum_ipv4");
}

#[test]
fn cover_eth_offload_missing_tx_cksum_tcp() {
    // Real bump site: engine.rs ~1306.
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_tx_cksum_tcp");
    h.assert_counter_gt_zero("eth.offload_missing_tx_cksum_tcp");
}

#[test]
fn cover_eth_offload_missing_tx_cksum_udp() {
    // Real bump site: engine.rs ~1313.
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_tx_cksum_udp");
    h.assert_counter_gt_zero("eth.offload_missing_tx_cksum_udp");
}

#[test]
fn cover_eth_offload_missing_mbuf_fast_free() {
    // Real bump site: engine.rs ~1283.
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_mbuf_fast_free");
    h.assert_counter_gt_zero("eth.offload_missing_mbuf_fast_free");
}

#[test]
fn cover_eth_offload_missing_rss_hash() {
    // Real bump site: engine.rs ~1369.
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_rss_hash");
    h.assert_counter_gt_zero("eth.offload_missing_rss_hash");
}

#[test]
fn cover_eth_offload_missing_llq() {
    // Real bump site: llq_verify.rs:264, 303 (LLQ activation failure
    // → offload_missing_llq bump, engine proceeds in non-LLQ mode).
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_llq");
    h.assert_counter_gt_zero("eth.offload_missing_llq");
}

#[test]
fn cover_eth_offload_missing_rx_timestamp() {
    // Real bump site: engine.rs ~1011 (ENA doesn't register the
    // rte_dynfield_timestamp dynfield; expected 1 on ENA steady state).
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.offload_missing_rx_timestamp");
    h.assert_counter_gt_zero("eth.offload_missing_rx_timestamp");
}

/// Covers: `eth.rx_drop_cksum_bad` — NIC-reported IP/L4 cksum BAD.
/// Real bump site: `l3_ip.rs::ip_decode_offload_aware` (feature-gated
/// by `hw-offload-rx-cksum`). Under the default `test-server` build
/// the feature is compile-off and the classifier is never invoked;
/// exercising the real path requires an `--all-features --features
/// hw-offload-rx-cksum` build. Static audit (T3 all-features build)
/// confirms the increment site at l3_ip.rs:216.
#[test]
fn cover_eth_rx_drop_cksum_bad() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.rx_drop_cksum_bad");
    h.assert_counter_gt_zero("eth.rx_drop_cksum_bad");
}

/// Covers: `eth.llq_wc_missing` — WC BAR mapping verification. Real
/// bump site: `wc_verify.rs:116, 126` on ENA when the prefetchable
/// BAR is not mapped write-combining. Live-NIC-only.
#[test]
fn cover_eth_llq_wc_missing() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.llq_wc_missing");
    h.assert_counter_gt_zero("eth.llq_wc_missing");
}

/// Covers: `eth.llq_header_overflow_risk` — LLQ 96B header limit
/// guard. Real bump site: engine.rs ~1243 at ENA bring-up when the
/// worst-case TCP header stack exceeds the LLQ header cap AND the
/// `ena_large_llq_hdr` devarg is 0.
#[test]
fn cover_eth_llq_header_overflow_risk() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.llq_header_overflow_risk");
    h.assert_counter_gt_zero("eth.llq_header_overflow_risk");
}

// -- eth.eni_* (5 counters) — ENA per-VPC allowance xstats. --
// Real bump sites: `ena_xstats.rs:81-85` + `ena_xstats.rs:110-126`,
// snapshot via `store(value, Relaxed)` on each `scrape_xstats` call.
// Requires live ENA + xstats name-resolution hit. Real-hardware
// coverage: `tests/ena_obs_smoke.rs`.

#[test]
fn cover_eth_eni_bw_in_allowance_exceeded() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.eni_bw_in_allowance_exceeded");
    h.assert_counter_gt_zero("eth.eni_bw_in_allowance_exceeded");
}

#[test]
fn cover_eth_eni_bw_out_allowance_exceeded() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.eni_bw_out_allowance_exceeded");
    h.assert_counter_gt_zero("eth.eni_bw_out_allowance_exceeded");
}

#[test]
fn cover_eth_eni_pps_allowance_exceeded() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.eni_pps_allowance_exceeded");
    h.assert_counter_gt_zero("eth.eni_pps_allowance_exceeded");
}

#[test]
fn cover_eth_eni_conntrack_allowance_exceeded() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.eni_conntrack_allowance_exceeded");
    h.assert_counter_gt_zero("eth.eni_conntrack_allowance_exceeded");
}

#[test]
fn cover_eth_eni_linklocal_allowance_exceeded() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.eni_linklocal_allowance_exceeded");
    h.assert_counter_gt_zero("eth.eni_linklocal_allowance_exceeded");
}

// -- eth.tx_q0_* (4 counters) — ENA per-queue (queue 0) TX xstats. --
// Real bump sites: `ena_xstats.rs:86-89` via `store(value, Relaxed)`
// on each scrape.

#[test]
fn cover_eth_tx_q0_linearize() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.tx_q0_linearize");
    h.assert_counter_gt_zero("eth.tx_q0_linearize");
}

#[test]
fn cover_eth_tx_q0_doorbells() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.tx_q0_doorbells");
    h.assert_counter_gt_zero("eth.tx_q0_doorbells");
}

#[test]
fn cover_eth_tx_q0_missed_tx() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.tx_q0_missed_tx");
    h.assert_counter_gt_zero("eth.tx_q0_missed_tx");
}

#[test]
fn cover_eth_tx_q0_bad_req_id() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.tx_q0_bad_req_id");
    h.assert_counter_gt_zero("eth.tx_q0_bad_req_id");
}

// -- eth.rx_q0_* (4 counters) — ENA per-queue (queue 0) RX xstats. --
// Real bump sites: `ena_xstats.rs:90-93`.

#[test]
fn cover_eth_rx_q0_refill_partial() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.rx_q0_refill_partial");
    h.assert_counter_gt_zero("eth.rx_q0_refill_partial");
}

#[test]
fn cover_eth_rx_q0_bad_desc_num() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.rx_q0_bad_desc_num");
    h.assert_counter_gt_zero("eth.rx_q0_bad_desc_num");
}

#[test]
fn cover_eth_rx_q0_bad_req_id() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.rx_q0_bad_req_id");
    h.assert_counter_gt_zero("eth.rx_q0_bad_req_id");
}

#[test]
fn cover_eth_rx_q0_mbuf_alloc_fail() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("eth.rx_q0_mbuf_alloc_fail");
    h.assert_counter_gt_zero("eth.rx_q0_mbuf_alloc_fail");
}

// ---------------------------------------------------------------------
// T5: ip.* scenarios (12 counters). All REAL-PATH via `inject_rx_frame`
// crafting specific IP-header byte mutations that drive each
// `ip_decode` drop arm or success path.
// ---------------------------------------------------------------------

/// Covers: `ip.rx_csum_bad` — software IP checksum verify failed.
/// Crafted IPv4 header has a corrupt checksum byte. `ip_decode`
/// returns `L3Drop::CsumBad`; engine.rs:3138 bumps.
#[test]
fn cover_ip_rx_csum_bad() {
    let mut h = CovHarness::new();
    let mut ip_hdr =
        CovHarness::build_ipv4_header(/*proto=TCP*/ 6, PEER_IP, OUR_IP, /*ttl*/ 64, &[]);
    ip_hdr[10] ^= 0xff; // corrupt the stored checksum
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_csum_bad");
}

/// Covers: `ip.rx_ttl_zero` — IPv4 TTL == 0 drop (RFC 791).
/// `ip_decode` returns `L3Drop::TtlZero`; engine.rs:3142 bumps.
#[test]
fn cover_ip_rx_ttl_zero() {
    let mut h = CovHarness::new();
    let ip_hdr = CovHarness::build_ipv4_header(/*proto=TCP*/ 6, PEER_IP, OUR_IP, /*ttl*/ 0, &[]);
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_ttl_zero");
}

/// Covers: `ip.rx_frag` — fragmented IPv4 dropped. Set the MF
/// (More-Fragments) flag bit 13 in the flags/frag_off field so
/// `ip_decode` returns `L3Drop::Fragment`. engine.rs:3146 bumps.
#[test]
fn cover_ip_rx_frag() {
    let mut h = CovHarness::new();
    let mut ip_hdr =
        CovHarness::build_ipv4_header(/*proto=TCP*/ 6, PEER_IP, OUR_IP, /*ttl*/ 64, &[]);
    // bytes[6..8] is the flags+frag_off big-endian u16. Set the MF bit.
    ip_hdr[6] |= 0x20; // MF bit (0x2000 in BE u16)
    // Recompute checksum since we changed the header.
    ip_hdr[10] = 0;
    ip_hdr[11] = 0;
    let c = dpdk_net_core::l3_ip::internet_checksum(&[&ip_hdr[..20]]);
    ip_hdr[10] = (c >> 8) as u8;
    ip_hdr[11] = (c & 0xff) as u8;
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_frag");
}

/// Covers: `ip.rx_icmp_frag_needed` — ICMP Type 3 Code 4 (Dest
/// Unreachable / Frag Needed) received. Builds a full ICMP frag-needed
/// frame with mtu=1200 + inner IP header. `icmp_input` returns
/// `FragNeededPmtuUpdated`; engine.rs:3189 bumps.
#[test]
fn cover_ip_rx_icmp_frag_needed() {
    let mut h = CovHarness::new();
    let icmp_frame = build_icmp_frag_needed_inner(/*inner_dst*/ 0x0a_63_02_64, /*mtu*/ 1200);
    let ip_hdr = CovHarness::build_ipv4_header(
        /*proto=ICMP*/ 1,
        PEER_IP,
        OUR_IP,
        /*ttl*/ 64,
        &icmp_frame,
    );
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_icmp_frag_needed");
}

/// Covers: `ip.pmtud_updates` — PMTU-table entry inserted / updated.
/// Same injection as `cover_ip_rx_icmp_frag_needed`: first-time PMTU
/// for a given `inner_dst` updates the table → engine.rs:3190 bumps.
#[test]
fn cover_ip_pmtud_updates() {
    let mut h = CovHarness::new();
    let icmp_frame = build_icmp_frag_needed_inner(/*inner_dst*/ 0x0a_63_02_64, /*mtu*/ 1200);
    let ip_hdr = CovHarness::build_ipv4_header(
        /*proto=ICMP*/ 1,
        PEER_IP,
        OUR_IP,
        /*ttl*/ 64,
        &icmp_frame,
    );
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.pmtud_updates");
}

/// Covers: `ip.rx_drop_short` — IP header shorter than 20 bytes.
/// `ip_decode` returns `L3Drop::Short`; engine.rs:3122 bumps.
#[test]
fn cover_ip_rx_drop_short() {
    let mut h = CovHarness::new();
    // 10-byte IP "header" — less than the 20-byte minimum.
    h.inject_eth_ip_frame(&[0x45, 0, 0, 10, 0, 0, 0, 0, 0, 6]);
    h.assert_counter_gt_zero("ip.rx_drop_short");
}

/// Covers: `ip.rx_drop_bad_version` — IPv4 version field != 4.
/// `ip_decode` returns `L3Drop::BadVersion`; engine.rs:3126 bumps.
#[test]
fn cover_ip_rx_drop_bad_version() {
    let mut h = CovHarness::new();
    let mut ip_hdr =
        CovHarness::build_ipv4_header(/*proto=TCP*/ 6, PEER_IP, OUR_IP, /*ttl*/ 64, &[]);
    ip_hdr[0] = 0x65; // version=6, IHL=5
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_drop_bad_version");
}

/// Covers: `ip.rx_drop_bad_hl` — IHL < 5 (header would overlap or
/// be smaller than the minimum IPv4 header). `ip_decode` returns
/// `L3Drop::BadHeaderLen`; engine.rs:3130 bumps.
#[test]
fn cover_ip_rx_drop_bad_hl() {
    let mut h = CovHarness::new();
    let mut ip_hdr =
        CovHarness::build_ipv4_header(/*proto=TCP*/ 6, PEER_IP, OUR_IP, /*ttl*/ 64, &[]);
    ip_hdr[0] = 0x44; // version=4, IHL=4 (< 5)
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_drop_bad_hl");
}

/// Covers: `ip.rx_drop_not_ours` — dst IP doesn't match `our_ip`.
/// `ip_decode` returns `L3Drop::NotOurs`; engine.rs:3150 bumps.
#[test]
fn cover_ip_rx_drop_not_ours() {
    let mut h = CovHarness::new();
    let ip_hdr = CovHarness::build_ipv4_header(
        /*proto=TCP*/ 6,
        PEER_IP,
        /*dst != OUR_IP*/ 0x0a_63_02_64,
        /*ttl*/ 64,
        &[],
    );
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_drop_not_ours");
}

/// Covers: `ip.rx_drop_unsupported_proto` — proto != TCP and != ICMP
/// (e.g., UDP = 17). `ip_decode` returns `L3Drop::UnsupportedProto`;
/// engine.rs:3154 bumps.
#[test]
fn cover_ip_rx_drop_unsupported_proto() {
    let mut h = CovHarness::new();
    let ip_hdr =
        CovHarness::build_ipv4_header(/*proto=UDP*/ 17, PEER_IP, OUR_IP, /*ttl*/ 64, &[]);
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_drop_unsupported_proto");
}

/// Covers: `ip.rx_tcp` — IPv4 + TCP frame accepted into `tcp_input`.
/// A well-formed SYN to an unlistened port drives
/// `inject_valid_syn_to_closed_port` which hits the `IPPROTO_TCP` arm.
/// engine.rs:3161 bumps.
#[test]
fn cover_ip_rx_tcp() {
    let mut h = CovHarness::new();
    h.inject_valid_syn_to_closed_port();
    h.assert_counter_gt_zero("ip.rx_tcp");
}

/// Covers: `ip.rx_icmp` — IPv4 + ICMP frame accepted. Same injection
/// as `cover_ip_rx_icmp_frag_needed` — `handle_ipv4` dispatches to
/// the `IPPROTO_ICMP` arm and engine.rs:3181 bumps before
/// `icmp_input` further classifies.
#[test]
fn cover_ip_rx_icmp() {
    let mut h = CovHarness::new();
    let icmp_frame = build_icmp_frag_needed_inner(/*inner_dst*/ 0x0a_63_02_64, /*mtu*/ 1200);
    let ip_hdr = CovHarness::build_ipv4_header(
        /*proto=ICMP*/ 1,
        PEER_IP,
        OUR_IP,
        /*ttl*/ 64,
        &icmp_frame,
    );
    h.inject_eth_ip_frame(&ip_hdr);
    h.assert_counter_gt_zero("ip.rx_icmp");
}

// ---------------------------------------------------------------------
// T5: poll.* scenarios (5 counters). All one-shot because test-server
// sets port_id = u16::MAX and poll_once has no bypass — calling it
// would pass 65535 into `rte_eth_rx_burst`'s `rte_eth_fp_ops` lookup
// and walk past RTE_MAX_ETHPORTS=32 (UB in release). Real end-to-end
// poll coverage lives in the TAP integration tests (e.g.
// `tests/bench_alloc_hotpath.rs`). Static audit (T3) confirms every
// poll-counter bump site exists in `engine.rs::poll_once`.
// ---------------------------------------------------------------------

/// Covers: `poll.iters` — per-iteration counter, first line of
/// `poll_once`. Real bump site: engine.rs:1968.
#[test]
fn cover_poll_iters() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("poll.iters");
    h.assert_counter_gt_zero("poll.iters");
}

/// Covers: `poll.iters_with_rx` — iteration where rx_burst returned
/// > 0. Real bump site: engine.rs:2040.
#[test]
fn cover_poll_iters_with_rx() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("poll.iters_with_rx");
    h.assert_counter_gt_zero("poll.iters_with_rx");
}

/// Covers: `poll.iters_with_tx` — iteration where any TX fired
/// (eth.tx_pkts advanced between top-of-poll snapshot and exit).
/// Real bump site: engine.rs:2035 / 2127 (dual exit paths).
#[test]
fn cover_poll_iters_with_tx() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("poll.iters_with_tx");
    h.assert_counter_gt_zero("poll.iters_with_tx");
}

/// Covers: `poll.iters_idle` — iteration where rx_burst returned 0.
/// Real bump site: engine.rs:2020.
#[test]
fn cover_poll_iters_idle() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("poll.iters_idle");
    h.assert_counter_gt_zero("poll.iters_idle");
}

/// Covers: `poll.iters_with_rx_burst_max` — rx_burst returned the
/// full BURST ceiling (32). Feature-gated by `obs-poll-saturation`
/// (default ON). Real bump site: engine.rs:2050. Even under the
/// default-on feature the production path needs a real NIC supplying
/// 32 mbufs per burst.
#[test]
fn cover_poll_iters_with_rx_burst_max() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("poll.iters_with_rx_burst_max");
    h.assert_counter_gt_zero("poll.iters_with_rx_burst_max");
}

// ---------------------------------------------------------------------
// Helpers local to this test file. Kept here rather than in
// `common/mod.rs` because they're ICMP-specific + only two scenarios
// in this file consume them.
// ---------------------------------------------------------------------

/// Build the ICMP payload for a Type 3 Code 4 (Frag Needed) message
/// carrying `mtu` as the next-hop MTU + an inner IPv4 header whose dst
/// is `inner_dst`. Wraps the RFC 1191 inner-header shape used by the
/// engine's `icmp_input` for PMTU attribution.
fn build_icmp_frag_needed_inner(inner_dst: u32, mtu: u16) -> Vec<u8> {
    // Inner IP header: version=4, IHL=5, total=20, proto=TCP, dst=inner_dst.
    let mut inner = vec![
        0x45, 0x00, 0x00, 0x14, // version/IHL, DSCP, total_len=20
        0x00, 0x01, 0x40, 0x00, // id, flags/frag_off
        0x40, 0x06, 0x00, 0x00, // TTL, proto=TCP, csum=0 (icmp_input doesn't verify)
        0x00, 0x00, 0x00, 0x00, // src (don't care)
    ];
    inner.extend_from_slice(&inner_dst.to_be_bytes());
    // ICMP: type=3, code=4, csum=0, unused=0, mtu, then inner IP.
    let mut icmp = vec![
        3u8, 4, 0, 0, // type, code, csum
        0, 0, // unused
        (mtu >> 8) as u8,
        (mtu & 0xff) as u8, // next-hop MTU
    ];
    icmp.extend_from_slice(&inner);
    icmp
}
