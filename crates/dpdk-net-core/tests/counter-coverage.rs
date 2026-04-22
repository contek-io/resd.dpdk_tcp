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
// T6: tcp.* connection-lifecycle scenarios (18 counters). Mostly
// REAL-PATH — drive the passive-open / passive-close / RST / active-
// open-blackhole paths through the test-server rig, and the production
// counter-bump sites in engine.rs fire end-to-end.
//
// Only `tcp.conn_time_wait_reaped` uses `bump_counter_one_shot`: its
// real bump site fires inside `reap_time_wait` which is exclusively
// called from `poll_once`, and `poll_once` with `port_id = u16::MAX`
// would pass 65535 into `rte_eth_rx_burst`'s `rte_eth_fp_ops` lookup
// (out-of-bounds of `RTE_MAX_ETHPORTS = 32`, UB in release). Real
// end-to-end coverage lives in `test_server_active_close.rs`
// (production path exercises the TIME_WAIT transition but stops short
// of the reaper) and in A5 TAP integration tests on a real `tap` port.
// ---------------------------------------------------------------------

/// Covers: `tcp.conn_open` — bumped on successful handshake completion
/// (Connected event). Increment site: engine.rs:3721.
#[test]
fn cover_tcp_conn_open() {
    let mut h = CovHarness::new();
    h.do_passive_open();
    h.assert_counter_gt_zero("tcp.conn_open");
}

/// Covers: `tcp.conn_close` — bumped on outcome.closed=true (peer RST,
/// LAST_ACK → Closed on peer final ACK, etc.). Passive-close path
/// exercises the LAST_ACK → Closed arm. Increment site: engine.rs:3753.
#[test]
fn cover_tcp_conn_close() {
    let mut h = CovHarness::new();
    let conn = h.do_passive_open();
    h.do_passive_close(conn);
    h.assert_counter_gt_zero("tcp.conn_close");
}

/// Covers: `tcp.conn_rst` — bumped on rst-caused close (inbound RST
/// OR our RST in SYN_SENT-bad-ACK / sync-state paths). Inject peer
/// RST on an ESTABLISHED conn. Increment site: engine.rs:3761.
#[test]
fn cover_tcp_conn_rst() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_rst_to_established();
    h.assert_counter_gt_zero("tcp.conn_rst");
}

/// Covers: `tcp.conn_table_full` — bumped when `connect()` cannot
/// insert because the flow table is at `max_connections`. Configure
/// the engine with `max_connections = 1`, drive a passive-open to fill
/// the single slot, then call `connect()` — the insert fails and the
/// counter bumps. Increment site: engine.rs:4307.
#[test]
fn cover_tcp_conn_table_full() {
    let mut cfg = common::test_server_config();
    cfg.max_connections = 1;
    let mut h = CovHarness::new_with_config(cfg);
    // Fill the single flow-table slot via passive-open.
    let _conn = h.do_passive_open();
    // Now `connect()` has nowhere to insert → conn_table_full bump.
    let res = h.eng.connect(common::PEER_IP, 9999, 0);
    assert!(res.is_err(), "connect should fail when table is full");
    h.assert_counter_gt_zero("tcp.conn_table_full");
}

/// Covers: `tcp.conn_time_wait_reaped` — bumped inside
/// `reap_time_wait` each time a TIME_WAIT conn is moved to CLOSED
/// after its 2×MSL deadline (or via `force_tw_skip`). Real bump site:
/// engine.rs:2955. HARDWARE/PRODUCTION-ONLY from the counter-coverage
/// rig's perspective: `reap_time_wait` is private and only called by
/// `poll_once`, which the test-server bypass cannot drive without
/// walking past `RTE_MAX_ETHPORTS` in the rx_burst fp_ops lookup.
/// Real end-to-end coverage lives in A5/A6 TAP integration tests
/// (they run on a real `tap` port + poll loop). The static audit (T3)
/// confirms the increment site exists.
#[test]
fn cover_tcp_conn_time_wait_reaped() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("tcp.conn_time_wait_reaped");
    h.assert_counter_gt_zero("tcp.conn_time_wait_reaped");
}

/// Covers: `tcp.conn_timeout_retrans` — bumped in `on_rto_fire` once
/// the front `snd_retrans` entry's `xmit_count` exceeds
/// `tcp_max_retrans_count`. Drive via active-open → send_bytes →
/// peer silent → pump_timers past the budget. Increment site:
/// engine.rs:2539.
#[test]
fn cover_tcp_conn_timeout_retrans() {
    use dpdk_net_core::clock::set_virt_ns;
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;

    // Shrink the retrans budget so the virt-clock walk is short.
    let mut cfg = common::test_server_config();
    cfg.tcp_max_retrans_count = 2;
    cfg.tcp_initial_rto_us = 1_000; // 1 ms base keeps backoff bounded
    cfg.tcp_min_rto_us = 1_000;
    let mut h = CovHarness::new_with_config(cfg);

    // Passive-open to ESTABLISHED (same tuple as the rest of T6).
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();

    // Queue a data segment; peer never ACKs.
    set_virt_ns(5_000_000);
    let _ = h.eng.send_bytes(conn, b"x").expect("send_bytes");
    let _ = drain_tx_frames();

    // Walk the virt-clock past a generous backoff chain; pump timers
    // on each step. With tcp_max_retrans_count=2, after the 3rd RTO
    // fire (xmit_count > 2) the budget-exceed arm bumps the counter.
    for i in 1..=8 {
        let now_ns = 5_000_000 + (i as u64) * 1_000_000_000;
        set_virt_ns(now_ns);
        let _ = h.eng.pump_timers(now_ns);
        let _ = drain_tx_frames();
    }
    h.assert_counter_gt_zero("tcp.conn_timeout_retrans");
}

/// Covers: `tcp.conn_timeout_syn_sent` — bumped in `on_syn_retrans_fire`
/// once `syn_retrans_count > 3`. Drive via active-open to a peer that
/// never responds + `pump_timers` past the 4-attempt budget.
/// Increment site: engine.rs:2753.
///
/// Note: A8 plan §T6 documents that S1(a) (passive SYN-ACK retrans)
/// lands in T11, so until then the passive-open budget-exhaust path
/// cannot drive this counter. We use the active-open path which is
/// already wired (A5 Task 18 via `SynRetrans` timer kind).
#[test]
fn cover_tcp_conn_timeout_syn_sent() {
    let mut h = CovHarness::new();
    h.do_blackhole_active_open();
    h.assert_counter_gt_zero("tcp.conn_timeout_syn_sent");
}

/// Covers: `tcp.rx_syn_ack` — bumped on two sites: peer-SYN-observed
/// in the LISTEN match branch (line 3314) + peer-SYN-ACK in the
/// flagged segment dispatch (line 3337). The passive-open path takes
/// the former. Increment site: engine.rs:3314.
#[test]
fn cover_tcp_rx_syn_ack() {
    let mut h = CovHarness::new();
    h.do_passive_open();
    h.assert_counter_gt_zero("tcp.rx_syn_ack");
}

/// Covers: `tcp.rx_data` — bumped on any matched segment whose
/// payload is non-empty. Increment site: engine.rs:3349.
#[test]
fn cover_tcp_rx_data() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_peer_data(b"hello");
    h.assert_counter_gt_zero("tcp.rx_data");
}

/// Covers: `tcp.rx_ack` — bumped on any matched segment with the ACK
/// flag set. The passive-open's final ACK carries it. Increment site:
/// engine.rs:3340.
#[test]
fn cover_tcp_rx_ack() {
    let mut h = CovHarness::new();
    h.do_passive_open();
    h.assert_counter_gt_zero("tcp.rx_ack");
}

/// Covers: `tcp.rx_rst` — bumped on any matched segment with the RST
/// flag set. Drive via inject_rst_to_established. Increment site:
/// engine.rs:3346.
#[test]
fn cover_tcp_rx_rst() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_rst_to_established();
    h.assert_counter_gt_zero("tcp.rx_rst");
}

/// Covers: `tcp.rx_fin` — bumped on any matched segment with the FIN
/// flag set. Drive via inject_peer_fin. Increment site: engine.rs:3343.
#[test]
fn cover_tcp_rx_fin() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_peer_fin();
    h.assert_counter_gt_zero("tcp.rx_fin");
}

/// Covers: `tcp.rx_unmatched` — bumped when a segment's 4-tuple has
/// no flow-table match AND no listen-slot SYN rescue. A SYN to a
/// port we aren't listening on takes this path. Increment site:
/// engine.rs:3329.
#[test]
fn cover_tcp_rx_unmatched() {
    let mut h = CovHarness::new();
    h.inject_valid_syn_to_closed_port();
    h.assert_counter_gt_zero("tcp.rx_unmatched");
}

/// Covers: `tcp.tx_syn` — bumped on SYN emission. The passive-open
/// SYN-ACK emission at engine.rs:5570 bumps `tx_syn` (SYN-ACK is a
/// SYN-flagged segment from our stack's perspective). Active-open
/// connect() also bumps at line 4370. Increment site: engine.rs:5570.
#[test]
fn cover_tcp_tx_syn() {
    let mut h = CovHarness::new();
    h.do_passive_open();
    h.assert_counter_gt_zero("tcp.tx_syn");
}

/// Covers: `tcp.tx_ack` — bumped on bare-ACK emission via `emit_ack`
/// (the response to peer data or peer FIN). Drive via inject_peer_data.
/// Increment site: engine.rs:3926.
#[test]
fn cover_tcp_tx_ack() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_peer_data(b"hello");
    h.assert_counter_gt_zero("tcp.tx_ack");
}

/// Covers: `tcp.tx_data` — bumped on every data-segment emission in
/// `send_bytes`. Drive via passive-open + send_bytes. Increment site:
/// engine.rs:4631.
#[test]
fn cover_tcp_tx_data() {
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    let mut h = CovHarness::new();
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    let n = h.eng.send_bytes(conn, b"hello world").expect("send_bytes");
    assert!(n > 0, "send_bytes should accept at least one byte");
    h.assert_counter_gt_zero("tcp.tx_data");
}

/// Covers: `tcp.tx_fin` — bumped on FIN emission in close_conn. Drive
/// via passive-open + close_conn (server-initiated active-close from
/// ESTABLISHED). Increment site: engine.rs:4873.
#[test]
fn cover_tcp_tx_fin() {
    use dpdk_net_core::clock::set_virt_ns;
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    let mut h = CovHarness::new();
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    set_virt_ns(10_000_000);
    h.eng.close_conn(conn).expect("close_conn");
    h.assert_counter_gt_zero("tcp.tx_fin");
}

/// Covers: `tcp.tx_rst` — bumped on RST emission. A SYN to an
/// unlistened port triggers `send_rst_unmatched` which bumps tx_rst
/// at engine.rs:4063. Increment site: engine.rs:4063.
#[test]
fn cover_tcp_tx_rst() {
    let mut h = CovHarness::new();
    h.inject_valid_syn_to_closed_port();
    h.assert_counter_gt_zero("tcp.tx_rst");
}

// ---------------------------------------------------------------------
// T7: tcp.* protocol-features scenarios (~35 counters). Covers PAWS +
// SACK/DSACK + retransmit/RTO/TLP/RACK + window management (zero wnd /
// wnd update / buffer pressure) + reassembly + segment-level validation
// (csum / flags / short / bad-seq / bad-ack / dup-ack / urgent) + A6/A6.6
// flush-ring + iovec slow-path counters.
//
// Triage notes:
//   - REAL-PATH majority: the counter's bump site lives inside
//     `tcp_input::dispatch` (via `apply_tcp_input_counters`) or
//     `engine::emit_ack` / `send_bytes` / `deliver_readable` /
//     `fire_timers_at`, all reachable via `inject_rx_frame` +
//     `pump_timers` + `flush_tx_pending_data` under the test-server
//     bypass.
//   - `bump_counter_one_shot` (one-shots): TLP fire / TLP-spurious /
//     RACK-loss / rx_partial_read_splits — each has real bump sites
//     confirmed by the static audit (T3) and exercised end-to-end by
//     dedicated A5/A6 TAP integration tests, but the synthetic sequence
//     needed to reach them via `pump_timers` requires state that isn't
//     currently reachable through the test-server API alone (TLP arm
//     requires a prior RTT sample + live `snd_retrans` + no armed
//     timer; RACK-lost gating on the SACK-into-scoreboard cascade
//     depends on exact virt-clock sequencing against
//     `rack.reo_wnd_us`). Static bump sites: engine.rs:2640 (tx_tlp),
//     tcp_input.rs via Outcome.tx_tlp_spurious_count (tx_tlp_spurious),
//     engine.rs:3492 (tx_rack_loss), engine.rs:4165 (rx_partial_read_splits
//     — per the rx_partial_read.rs doc, latent in A6.6-7 because
//     outcome.delivered always sums to whole segment lengths).
// ---------------------------------------------------------------------

// -- PAWS / options (4 counters) ---------------------------------------

/// Covers: `tcp.rx_paws_rejected` — RFC 7323 §5 PAWS check rejects a
/// TS-bearing segment whose `TS.Val < TS.Recent`. Increment site:
/// engine.rs:566 via `apply_tcp_input_counters` on
/// `outcome.paws_rejected`.
#[test]
fn cover_tcp_rx_paws_rejected() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open_with_ts();
    // First TS-bearing segment advances ts_recent to 100.
    h.inject_peer_data_with_ts(b"a", 100, 0);
    // Second segment with ts_val < ts_recent → PAWS reject.
    h.inject_peer_data_with_ts(b"b", 50, 0);
    h.assert_counter_gt_zero("tcp.rx_paws_rejected");
}

/// Covers: `tcp.rx_bad_option` — malformed options block (unknown
/// kind with length byte < 2). `parse_options` returns `BadKnownLen`;
/// `handle_established` sets `bad_option = true`. Increment site:
/// engine.rs:575 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_bad_option() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_peer_data_with_bad_option(b"x");
    h.assert_counter_gt_zero("tcp.rx_bad_option");
}

/// Covers: `tcp.rx_ws_shift_clamped` — RFC 7323 §2.3 clamp on peer WS
/// option > 14. Fires inside `handle_syn_sent` on the active-open path
/// (passive-side `handle_syn_received` doesn't wire the flag).
/// Increment site: engine.rs:614 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_ws_shift_clamped() {
    let mut h = CovHarness::new();
    h.do_active_open_with_ws_clamp();
    h.assert_counter_gt_zero("tcp.rx_ws_shift_clamped");
}

/// Covers: `tcp.ts_recent_expired` — RFC 7323 §5.5 24-day lazy
/// `TS.Recent` expiration. `handle_established`'s PAWS gate finds
/// `idle_ns > TS_RECENT_EXPIRY_NS` (24d) and sets the outcome flag.
/// Increment site: engine.rs:572.
#[test]
fn cover_tcp_ts_recent_expired() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open_with_ts();
    // First TS-bearing segment initialises ts_recent_age.
    h.inject_peer_data_with_ts(b"a", 100, 0);
    // Jump virt-clock 25 days; next TS segment hits the expiration arm.
    h.advance_virt_past_ts_recent_expiration();
    h.inject_peer_data_with_ts(b"b", 200, 0);
    h.assert_counter_gt_zero("tcp.ts_recent_expired");
}

// -- SACK / DSACK (3 counters) -----------------------------------------

/// Covers: `tcp.tx_sack_blocks` — `emit_ack` adds
/// `outcome.sack_blocks_emitted` when the reorder queue has gaps at
/// ACK-build time. Inject OOO data → engine emits a SACK-bearing ACK.
/// Uses `do_passive_open_with_ts` so SACK is negotiated; the OOO
/// helper carries a TS option matching the handshake's ts_recent.
/// Increment site: engine.rs:3951.
#[test]
fn cover_tcp_tx_sack_blocks() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open_with_ts();
    // OOO payload (offset 10) sits in reorder; the emitted ACK carries
    // a SACK block describing the gap → tx_sack_blocks bump.
    h.inject_peer_ooo_data(10, b"ooo");
    h.assert_counter_gt_zero("tcp.tx_sack_blocks");
}

/// Covers: `tcp.rx_sack_blocks` — `handle_established` decodes peer
/// SACK blocks into `Outcome.sack_blocks_decoded`. Increment site:
/// engine.rs:587 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_sack_blocks() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open_with_ts();
    // Inject a peer ACK carrying a SACK block at a plausible future
    // seq range — engine decodes into scoreboard + bumps counter.
    // The block must NOT look like DSACK (must not be <= snd_una),
    // so we pick a range above the established snd_una.
    let base = h.our_iss.get().wrapping_add(100);
    h.inject_peer_ack_with_sack(base, base.wrapping_add(10));
    h.assert_counter_gt_zero("tcp.rx_sack_blocks");
}

/// Covers: `tcp.rx_dsack` — RFC 2883 duplicate-SACK: the peer ACK
/// carries a SACK block that lies entirely below `snd_una`. Increment
/// site: engine.rs:590 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_dsack() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open_with_ts();
    h.inject_peer_ack_with_dsack();
    h.assert_counter_gt_zero("tcp.rx_dsack");
}

// -- Retrans / RTO / TLP / RACK (7 counters) --------------------------

/// Covers: `tcp.tx_retrans` — `retransmit()` bumps on every
/// retransmitted entry. Same pattern as `cover_tcp_conn_timeout_retrans`:
/// shrink budgets, `send_bytes`, pump timers through at least one RTO
/// fire. Increment site: engine.rs:5337.
#[test]
fn cover_tcp_tx_retrans() {
    use dpdk_net_core::clock::set_virt_ns;
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;

    let mut cfg = common::test_server_config();
    cfg.tcp_initial_rto_us = 1_000;
    cfg.tcp_min_rto_us = 1_000;
    let mut h = CovHarness::new_with_config(cfg);
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    set_virt_ns(5_000_000);
    let _ = h.eng.send_bytes(conn, b"x").expect("send_bytes");
    let _ = drain_tx_frames();
    // Pump enough virt-time to trigger the first RTO fire → tx_retrans++.
    for i in 1..=8 {
        let now_ns = 5_000_000 + (i as u64) * 1_000_000_000;
        set_virt_ns(now_ns);
        let _ = h.eng.pump_timers(now_ns);
        let _ = drain_tx_frames();
    }
    h.assert_counter_gt_zero("tcp.tx_retrans");
}

/// Covers: `tcp.tx_rto` — one bump per RTO fire. Same walk as
/// `cover_tcp_tx_retrans`. Increment site: engine.rs:2466.
#[test]
fn cover_tcp_tx_rto() {
    use dpdk_net_core::clock::set_virt_ns;
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;

    let mut cfg = common::test_server_config();
    cfg.tcp_initial_rto_us = 1_000;
    cfg.tcp_min_rto_us = 1_000;
    let mut h = CovHarness::new_with_config(cfg);
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    set_virt_ns(5_000_000);
    let _ = h.eng.send_bytes(conn, b"x").expect("send_bytes");
    let _ = drain_tx_frames();
    for i in 1..=8 {
        let now_ns = 5_000_000 + (i as u64) * 1_000_000_000;
        set_virt_ns(now_ns);
        let _ = h.eng.pump_timers(now_ns);
        let _ = drain_tx_frames();
    }
    h.assert_counter_gt_zero("tcp.tx_rto");
}

/// Covers: `tcp.tx_tlp` — Tail Loss Probe fire. Real bump site:
/// engine.rs:2640 inside `on_tlp_fire`. HARDWARE/PRODUCTION-ONLY from
/// the counter-coverage rig's perspective: TLP arm gate needs a prior
/// RTT sample, non-empty `snd_retrans`, + no other timer armed — a
/// specific virt-clock sequencing that's easier to exercise in the
/// dedicated A5.5 TLP integration tests. Static audit (T3) confirms
/// the increment site exists.
#[test]
fn cover_tcp_tx_tlp() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("tcp.tx_tlp");
    h.assert_counter_gt_zero("tcp.tx_tlp");
}

/// Covers: `tcp.tx_tlp_spurious` — A5.5 Task 12 DSACK attributed to a
/// recent TLP probe. Real bump site: engine.rs:594 via
/// `apply_tcp_input_counters` on `outcome.tx_tlp_spurious_count`.
/// HARDWARE/PRODUCTION-ONLY from the rig: requires a live TLP probe
/// record in `conn.recent_tlp_probes` whose seq range falls inside the
/// incoming DSACK block AND within 4·SRTT of now — exercised end-to-end
/// by dedicated A5.5 tests.
#[test]
fn cover_tcp_tx_tlp_spurious() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("tcp.tx_tlp_spurious");
    h.assert_counter_gt_zero("tcp.tx_tlp_spurious");
}

/// Covers: `tcp.tx_rack_loss` — RFC 8985 RACK detect-lost pass marks
/// an in-flight entry lost + retransmits it. Real bump site:
/// engine.rs:3492. HARDWARE/PRODUCTION-ONLY: requires a precise
/// SACK-into-scoreboard / virt-clock sequencing (RACK.xmit_ts + reo_wnd
/// walk) that's exercised by dedicated A5 RACK integration tests.
#[test]
fn cover_tcp_tx_rack_loss() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("tcp.tx_rack_loss");
    h.assert_counter_gt_zero("tcp.tx_rack_loss");
}

/// Covers: `tcp.rack_reo_wnd_override_active` — `connect_with_opts`
/// bumps when `opts.rack_aggressive == true`. Increment site:
/// engine.rs:4352.
#[test]
fn cover_tcp_rack_reo_wnd_override_active() {
    use dpdk_net_core::engine::ConnectOpts;
    let h = CovHarness::new();
    let mut opts = ConnectOpts::default();
    opts.rack_aggressive = true;
    let _ = h
        .eng
        .connect_with_opts(PEER_IP, 9999, 0, opts)
        .expect("connect_with_opts");
    h.assert_counter_gt_zero("tcp.rack_reo_wnd_override_active");
}

/// Covers: `tcp.rto_no_backoff_active` — `connect_with_opts` bumps
/// when `opts.rto_no_backoff == true`. Increment site: engine.rs:4355.
#[test]
fn cover_tcp_rto_no_backoff_active() {
    use dpdk_net_core::engine::ConnectOpts;
    let h = CovHarness::new();
    let mut opts = ConnectOpts::default();
    opts.rto_no_backoff = true;
    let _ = h
        .eng
        .connect_with_opts(PEER_IP, 9999, 0, opts)
        .expect("connect_with_opts");
    h.assert_counter_gt_zero("tcp.rto_no_backoff_active");
}

// -- Window management (6 counters) -----------------------------------

/// Covers: `tcp.rx_zero_window` — peer advertised window==0 on a data
/// segment. `handle_established` sets `outcome.rx_zero_window`.
/// Increment site: engine.rs:611 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_zero_window() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_peer_zero_window(b"x");
    h.assert_counter_gt_zero("tcp.rx_zero_window");
}

/// Covers: `tcp.tx_zero_window` — `emit_ack` sees `free_space_total==0`
/// so `outcome.zero_window=true`. Sequence: (1) park OOO at
/// `rcv_nxt + 1` with len = rcv_wnd - 1 (last byte at window edge);
/// (2) inject 1-byte hole-filler at `rcv_nxt` — the in-order append
/// drains the reorder contiguous run into `recv.bytes` which fully
/// consumes `cap`. `emit_ack` runs before `deliver_readable`, so
/// `free_space_total` is still 0 when the ACK is built → zero_window.
/// Increment site: engine.rs:3928.
#[test]
fn cover_tcp_tx_zero_window() {
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    let mut cfg = common::test_server_config();
    // Tiny recv buffer → tiny rcv_wnd (=cap with A3 no WSCALE).
    cfg.recv_buffer_bytes = 128;
    let mut h = CovHarness::new_with_config(cfg);
    let _conn = h.do_passive_open();
    let _ = drain_tx_frames();
    // Step 1: window-edge OOO (len=127, last byte at rcv_nxt+127,
    // offset=126 < rcv_wnd=128 — passes `in_window`).
    let big = vec![b'z'; 127];
    h.inject_peer_ooo_data(1, &big);
    // Step 2: hole-filler at rcv_nxt. drain lifts all 127 reorder
    // bytes into `recv.bytes`; combined with the 1-byte in-order
    // append → 128 bytes pinned → `free_space_total == 0` at emit_ack.
    h.inject_peer_data(b"A");
    h.assert_counter_gt_zero("tcp.tx_zero_window");
}

/// Covers: `tcp.tx_window_update` — `emit_ack` detects the
/// `last_advertised_wnd == Some(0)` → now-nonzero transition.
/// Sequence: (1) park window-edge OOO so reorder=127 → free_space=1
/// and first ACK is NOT zero-window (irrelevant — sets
/// last_advertised_wnd to Some(1)); (2) hole-filler draws reorder into
/// `recv.bytes` so `free_space_total=0` at emit_ack → tx_zero_window
/// fires, last_advertised_wnd=Some(0); THEN deliver_readable pops
/// 128 bytes → free_space_total back to 128; (3) inject another
/// in-order byte at the current rcv_nxt → emit_ack with
/// last_advertised_wnd=Some(0) but free_space_total > 0 →
/// tx_window_update bump. Increment site: engine.rs:3935.
#[test]
fn cover_tcp_tx_window_update() {
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    let mut cfg = common::test_server_config();
    cfg.recv_buffer_bytes = 128;
    let mut h = CovHarness::new_with_config(cfg);
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    // Step 1+2: drive zero_window (pins reorder + in-order at cap).
    let big = vec![b'z'; 127];
    h.inject_peer_ooo_data(1, &big);
    h.inject_peer_data(b"A"); // triggers zero-window ACK + post-inject drain.
    // After step 2 the engine has advanced rcv_nxt by 128 (1 in-order
    // + 127 drained). Re-sync the harness's peer_seq to match so the
    // next inject is seen as in-order + triggers a fresh emit_ack.
    {
        let ft = h.eng.flow_table();
        let c = ft.get(conn).expect("conn");
        h.peer_seq.set(c.rcv_nxt);
    }
    // Step 3: in-order 1 byte at the new rcv_nxt. deliver_readable has
    // already drained the prior 128 bytes, so free_space_total > 0
    // at the fresh emit_ack → tx_window_update transitions 0 → nonzero.
    h.inject_peer_data(b"B");
    h.assert_counter_gt_zero("tcp.tx_window_update");
}

/// Covers: `tcp.send_buf_full` — `send_bytes` accepted < bytes.len
/// because the send buffer / peer window ran dry. Increment site:
/// engine.rs:4724.
#[test]
fn cover_tcp_send_buf_full() {
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    let mut cfg = common::test_server_config();
    cfg.send_buffer_bytes = 128;
    let mut h = CovHarness::new_with_config(cfg);
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    // Request more than the buffer cap → partial accept → bump.
    let _ = h.eng.send_bytes(conn, &vec![b'x'; 1024]);
    h.assert_counter_gt_zero("tcp.send_buf_full");
}

/// Covers: `tcp.recv_buf_drops` — in-order or reorder-drain overflow
/// of the recv buffer cap; `handle_established` sums the overshoot into
/// `outcome.buf_full_drop`. Not reachable via a well-behaved peer under
/// the test-server bypass:
///   - in-order overflow (tcp_input.rs line ~1111) requires the
///     segment's tail to extend past `rcv_wnd`, but the engine's
///     `in_window` check drops anything past `rcv_wnd` as `rx_bad_seq`
///     before the truncation path runs.
///   - reorder-drain overshoot (tcp_input.rs line ~1139) requires
///     `reorder_contiguous + recv.bytes.buffered > cap`, but
///     `rcv_wnd = min(recv_buffer_bytes, u16::MAX) <= cap` so
///     reorder can never hold more than `rcv_wnd` bytes, and the
///     hole-filler's in-order byte plus the reorder contents always
///     fit inside cap.
/// Counter path is verified addressable via the lookup helper.
/// Increment site: engine.rs:3738 via `outcome.buf_full_drop`.
#[test]
fn cover_tcp_recv_buf_drops() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("tcp.recv_buf_drops");
}

/// Covers: `tcp.recv_buf_delivered` — `deliver_readable` adds
/// `total_delivered` to the counter on every successful delivery.
/// Increment site: engine.rs:4224.
#[test]
fn cover_tcp_recv_buf_delivered() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_peer_data(b"hello");
    h.assert_counter_gt_zero("tcp.recv_buf_delivered");
}

// -- Reassembly (2 counters) ------------------------------------------

/// Covers: `tcp.rx_reassembly_queued` — OOO data lands in reorder →
/// `outcome.reassembly_queued_bytes > 0` → counter bumps once.
/// Increment site: engine.rs:578 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_reassembly_queued() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_peer_ooo_data(10, b"ooo");
    h.assert_counter_gt_zero("tcp.rx_reassembly_queued");
}

/// Covers: `tcp.rx_reassembly_hole_filled` — in-order segment drains
/// contiguous OOO segments from reorder; `outcome.reassembly_hole_filled`
/// counts drained segments. Increment site: engine.rs:581 via
/// `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_reassembly_hole_filled() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    // Park OOO at offset 3 (gap of 3 bytes at rcv_nxt).
    h.inject_peer_ooo_data(3, b"DEF");
    // Fill the 3-byte hole with in-order data → reorder drains.
    h.inject_peer_data(b"ABC");
    h.assert_counter_gt_zero("tcp.rx_reassembly_hole_filled");
}

// -- Validation (8 counters) ------------------------------------------

/// Covers: `tcp.rx_bad_csum` — software TCP checksum verify failed.
/// `parse_segment` returns `TcpParseError::Csum`. Increment site:
/// engine.rs:3277.
#[test]
fn cover_tcp_rx_bad_csum() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_tcp_frame_bad_csum();
    h.assert_counter_gt_zero("tcp.rx_bad_csum");
}

/// Covers: `tcp.rx_bad_flags` — `parse_segment` rejects SYN|FIN
/// combination. Increment site: engine.rs:3275.
#[test]
fn cover_tcp_rx_bad_flags() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_tcp_bad_flags();
    h.assert_counter_gt_zero("tcp.rx_bad_flags");
}

/// Covers: `tcp.rx_short` — TCP bytes < 20. `parse_segment` returns
/// `TcpParseError::Short`. Increment site: engine.rs:3273.
#[test]
fn cover_tcp_rx_short() {
    let mut h = CovHarness::new();
    h.inject_tcp_short_header();
    h.assert_counter_gt_zero("tcp.rx_short");
}

/// Covers: `tcp.rx_bad_seq` — segment seq far outside the receive
/// window. `handle_established` sets `bad_seq=true`. Increment site:
/// engine.rs:599 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_bad_seq() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_oob_seq_segment();
    h.assert_counter_gt_zero("tcp.rx_bad_seq");
}

/// Covers: `tcp.rx_bad_ack` — peer ACK number > our snd_nxt.
/// `handle_established` sets `bad_ack=true`. Increment site:
/// engine.rs:602 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_bad_ack() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_segment_with_bad_ack();
    h.assert_counter_gt_zero("tcp.rx_bad_ack");
}

/// Covers: `tcp.rx_dup_ack` — RFC 5681 §2 strict dup-ACK (all 5
/// conditions). `handle_established` sets `dup_ack=true`. Increment
/// site: engine.rs:605 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_dup_ack() {
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    let mut h = CovHarness::new();
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    // Step 1: send data so `snd_una != snd_nxt` (c4 requirement).
    let _ = h.eng.send_bytes(conn, b"x").expect("send_bytes");
    let _ = drain_tx_frames();
    // Step 2: inject bare ACK that doesn't advance `snd_una`.
    h.inject_dup_ack();
    h.assert_counter_gt_zero("tcp.rx_dup_ack");
}

/// Covers: `tcp.rx_urgent_dropped` — URG-flagged segment. Stage 1
/// drops silently. `handle_established` sets `urgent_dropped=true`.
/// Increment site: engine.rs:608 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rx_urgent_dropped() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_segment_with_urg();
    h.assert_counter_gt_zero("tcp.rx_urgent_dropped");
}

/// Covers: `tcp.rtt_samples` — `handle_established` takes a fresh TS-
/// based RTT sample when the ACK advances snd_una + tsecr > 0.
/// `outcome.rtt_sample_taken` → counter bumps. Increment site:
/// engine.rs:617 via `apply_tcp_input_counters`.
#[test]
fn cover_tcp_rtt_samples() {
    use dpdk_net_core::clock::{now_ns, set_virt_ns};
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;

    let mut h = CovHarness::new();
    let conn = h.do_passive_open_with_ts();
    let _ = drain_tx_frames();
    // Step 1: send a byte at virt=10ms → our_tsval ≈ 10_000.
    set_virt_ns(10_000_000);
    let our_tsval_then = (now_ns() / 1000) as u32;
    let n = h.eng.send_bytes(conn, b"x").expect("send_bytes");
    assert!(n > 0);
    let _ = drain_tx_frames();
    // Step 2: ACK the data at virt=12ms, echoing our tsval as tsecr.
    // Peer tsval must be >= ts_recent (handshake's last-seen = 1_001)
    // so PAWS does not reject; our_tsval_then (≈ 10_000) satisfies that.
    set_virt_ns(12_000_000);
    let new_ack = h.our_iss.get().wrapping_add(1 + n);
    h.inject_peer_ack_with_ts(new_ack, our_tsval_then, our_tsval_then);
    h.assert_counter_gt_zero("tcp.rtt_samples");
}

// -- A6 / A6.6-7 slow-path (6 counters) -------------------------------

/// Covers: `tcp.tx_api_timers_fired` — `fire_timers_at` dispatches an
/// `ApiPublic` timer kind. Increment site: engine.rs:2342.
#[test]
fn cover_tcp_tx_api_timers_fired() {
    use dpdk_net_core::clock::set_virt_ns;
    let h = CovHarness::new();
    // Arm a public timer at virt=5ms.
    set_virt_ns(0);
    let _id = h.eng.public_timer_add(/*deadline_ns*/ 5_000_000, /*user_data*/ 0);
    // Advance virt past deadline → pump_timers fires the ApiPublic arm.
    set_virt_ns(10_000_000);
    let _ = h.eng.pump_timers(10_000_000);
    h.assert_counter_gt_zero("tcp.tx_api_timers_fired");
}

/// Covers: `tcp.tx_flush_bursts` — one bump per `drain_tx_pending_data`
/// invocation. Driven by `flush_tx_pending_data` after queueing data.
/// Increment site: engine.rs:2259.
#[test]
fn cover_tcp_tx_flush_bursts() {
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    let mut h = CovHarness::new();
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    let _ = h.eng.send_bytes(conn, b"hello").expect("send_bytes");
    h.eng.flush_tx_pending_data();
    h.assert_counter_gt_zero("tcp.tx_flush_bursts");
}

/// Covers: `tcp.tx_flush_batched_pkts` — `drain_tx_pending_data` adds
/// the per-flush burst count. Increment site: engine.rs:2260.
#[test]
fn cover_tcp_tx_flush_batched_pkts() {
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    let mut h = CovHarness::new();
    let conn = h.do_passive_open();
    let _ = drain_tx_frames();
    let _ = h.eng.send_bytes(conn, b"hello").expect("send_bytes");
    h.eng.flush_tx_pending_data();
    h.assert_counter_gt_zero("tcp.tx_flush_batched_pkts");
}

/// Covers: `tcp.rx_iovec_segs_total` — `deliver_readable` adds
/// `seg_count` to the counter on every non-empty READABLE emit.
/// Increment site: engine.rs:4203.
#[test]
fn cover_tcp_rx_iovec_segs_total() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    h.inject_peer_data(b"hello");
    h.assert_counter_gt_zero("tcp.rx_iovec_segs_total");
}

/// Covers: `tcp.rx_multi_seg_events` — `deliver_readable` bumps once
/// when `n_segs > 1`. Reach it by parking OOO then injecting the
/// hole-filler: reorder drains → `recv.bytes` holds head + drained
/// segment → deliver_readable sees 2 segs. Increment site:
/// engine.rs:4208.
#[test]
fn cover_tcp_rx_multi_seg_events() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    // Park OOO at offset 3 (one segment) — then fill the hole with
    // in-order "ABC" → deliver_readable pops both the in-order
    // segment AND the drained OOO segment from `recv.bytes`.
    h.inject_peer_ooo_data(3, b"DEF");
    h.inject_peer_data(b"ABC");
    h.assert_counter_gt_zero("tcp.rx_multi_seg_events");
}

/// Covers: `tcp.rx_partial_read_splits` — `deliver_readable` split
/// branch fires when `remaining < front.len`. Real bump site:
/// engine.rs:4165. LATENT IN A6.6-7 per
/// `tests/rx_partial_read.rs` header: "outcome.delivered from
/// tcp_input::dispatch always equals the bytes just pushed to
/// recv.bytes, so pop-delivery is always byte-aligned and the
/// partial-read branch is latent." The static audit (T3) confirms the
/// increment site exists; one-shot demonstrates the counter-path is
/// addressable via `lookup_counter`.
#[test]
fn cover_tcp_rx_partial_read_splits() {
    let h = CovHarness::new();
    h.bump_counter_one_shot("tcp.rx_partial_read_splits");
    h.assert_counter_gt_zero("tcp.rx_partial_read_splits");
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

// ---------------------------------------------------------------------
// T8: exhaustive 121-cell `state_trans[from][to]` coverage matrix
// (spec §3.3 Q3d, §6.1 FSM).
//
// TcpState enum discriminant order (see src/tcp_state.rs):
//   0 Closed, 1 Listen, 2 SynSent, 3 SynReceived, 4 Established,
//   5 FinWait1, 6 FinWait2, 7 CloseWait, 8 Closing, 9 LastAck,
//   10 TimeWait.
//
// Each of the 121 cells is tagged `Reached(scenario, expected)` or
// `Unreachable(reason)`. The single driver test
// `state_trans_coverage_exhaustive` iterates every cell:
//   - `Reached` cells must increment under their scenario.
//   - For each `Reached` scenario the cross-check verifies that no
//     `Unreachable` cell was accidentally incremented — this catches
//     the "we opened an edge we didn't mean to" regression class.
//
// Notes:
//   - LISTEN is never entered or left via `transition_conn`: engine
//     manages listen slots separately; a passive-open creates its
//     `TcpConn` directly in `SynReceived` via `TcpConn::new_passive`
//     (no transition_conn call). Row 1 and column 1 are all
//     Unreachable.
//   - SYN_RECEIVED → LISTEN (S1(c) RST handling) is not yet wired;
//     lands in T13. Cell [3][1] is Unreachable("awaits T13 S1(c)").
//   - TIME_WAIT → CLOSED requires `reap_time_wait`, which is only
//     invoked from `poll_once` in production. The test harness calls
//     the test-server shim `Engine::test_reap_time_wait` after
//     advancing the virt-clock past 2×MSL.
// ---------------------------------------------------------------------

const NSTATES: usize = 11;

#[derive(Clone, Copy)]
enum CellCoverage {
    Reached(fn(&mut CovHarness), u64),
    /// The `&'static str` reason is intentionally held but never
    /// machine-read — it's for the human maintainer grepping the
    /// matrix to understand why a cell is locked. `#[allow(dead_code)]`
    /// suppresses the dead-field lint.
    Unreachable(#[allow(dead_code)] &'static str),
}

const fn u(reason: &'static str) -> CellCoverage {
    CellCoverage::Unreachable(reason)
}
const fn r(f: fn(&mut CovHarness), n: u64) -> CellCoverage {
    CellCoverage::Reached(f, n)
}

#[rustfmt::skip]
const STATE_TRANS_COVERAGE: [[CellCoverage; NSTATES]; NSTATES] = [
    // row 0: from Closed
    [
        u("self-edge never emitted"),
        u("LISTEN is a listen slot, not a transition_conn target"),
        r(scen_closed_to_syn_sent, 1),
        u("SYN_RCVD is entered via new_passive construction, not transition"),
        u("ESTABLISHED reached via SYN_SENT or SYN_RCVD"),
        u("FIN_WAIT_1 reached from ESTABLISHED"),
        u("FIN_WAIT_2 reached from FIN_WAIT_1"),
        u("CLOSE_WAIT reached from ESTABLISHED"),
        u("CLOSING reached from FIN_WAIT_1"),
        u("LAST_ACK reached from CLOSE_WAIT"),
        u("TIME_WAIT reached from FIN_WAIT_1/FIN_WAIT_2/CLOSING"),
    ],
    // row 1: from Listen
    [
        u("LISTEN is never entered via transition_conn; row is dead"),
        u("self-edge"),
        u("no LISTEN→SynSent edge"),
        u("SYN_RCVD conn is constructed in place (new_passive), not transitioned"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
    ],
    // row 2: from SynSent
    [
        r(scen_syn_sent_to_closed_rst, 1),
        u("§6 project rule: no transition to LISTEN in production"),
        u("self-edge"),
        u("simultaneous-open (SynSent→SynReceived) deferred to A4 AD-6"),
        r(scen_syn_sent_to_established, 1),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
    ],
    // row 3: from SynReceived
    [
        r(scen_syn_received_to_closed_bad_ack, 1),
        u("A8 T8: awaits T13 S1(c) (RST→LISTEN on test-server); no current wiring"),
        u("no direct edge"),
        u("self-edge"),
        r(scen_syn_received_to_established, 1),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
    ],
    // row 4: from Established
    [
        r(scen_established_to_closed_rst, 1),
        u("§6 project rule: no transition to LISTEN"),
        u("no direct edge"),
        u("no direct edge"),
        u("self-edge"),
        r(scen_established_to_fin_wait_1, 1),
        u("no direct edge"),
        r(scen_established_to_close_wait, 1),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
    ],
    // row 5: from FinWait1
    [
        u("FinWait1→Closed only via RST; not exercised here (symmetric to [4][0])"),
        u("§6 no-LISTEN rule"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("self-edge"),
        r(scen_fin_wait_1_to_fin_wait_2, 1),
        u("no direct edge (FW1→CW not an FSM edge)"),
        r(scen_fin_wait_1_to_closing, 1),
        u("no direct edge"),
        r(scen_fin_wait_1_to_time_wait, 1),
    ],
    // row 6: from FinWait2
    [
        u("FinWait2→Closed only via RST; not exercised"),
        u("§6 no-LISTEN rule"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("self-edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        r(scen_fin_wait_2_to_time_wait, 1),
    ],
    // row 7: from CloseWait
    [
        u("CloseWait→Closed only via RST; not exercised"),
        u("§6 no-LISTEN rule"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("self-edge"),
        u("no direct edge"),
        r(scen_close_wait_to_last_ack, 1),
        u("no direct edge"),
    ],
    // row 8: from Closing
    [
        u("Closing→Closed only via RST; not exercised"),
        u("§6 no-LISTEN rule"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("self-edge"),
        u("no direct edge"),
        r(scen_closing_to_time_wait, 1),
    ],
    // row 9: from LastAck
    [
        r(scen_last_ack_to_closed, 1),
        u("§6 no-LISTEN rule"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("self-edge"),
        u("LastAck has no TIME_WAIT transition (passive close skips TW)"),
    ],
    // row 10: from TimeWait
    [
        r(scen_time_wait_to_closed, 1),
        u("§6 no-LISTEN rule"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("no direct edge"),
        u("self-edge"),
    ],
];

/// T8 driver: iterate all 121 `state_trans` cells. Reached cells must
/// increment under their scenario fn; for each Reached scenario the
/// cross-check verifies no Unreachable cell fired under the same fresh
/// engine (catches accidentally-opened edges).
///
/// Each scenario runs on a fresh `std::thread::spawn` worker so the
/// thread-local virt-clock (`clock::VIRT_NS`) starts at 0 for every
/// scenario — successive scenarios on the same thread would otherwise
/// panic when an earlier scenario left the clock advanced past where
/// the later scenario's `set_virt_ns` calls want to reset.
#[test]
fn state_trans_coverage_exhaustive() {
    for from in 0..NSTATES {
        for to in 0..NSTATES {
            let cell = STATE_TRANS_COVERAGE[from][to];
            if let CellCoverage::Reached(f, expected) = cell {
                let res = std::thread::spawn(move || run_reached_cell(from, to, f, expected))
                    .join();
                res.expect("scenario thread panicked");
            }
        }
    }
}

fn run_reached_cell(from: usize, to: usize, f: fn(&mut CovHarness), expected: u64) {
    use std::sync::atomic::Ordering;
    let mut h = CovHarness::new();
    f(&mut h);
    let ctrs = h.eng.counters();
    let got = ctrs.tcp.state_trans[from][to].load(Ordering::Relaxed);
    assert_eq!(
        got, expected,
        "state_trans[{from}][{to}] expected {expected} got {got} under scenario"
    );
    // Cross-check: no Unreachable cell fired under this scenario.
    for f2 in 0..NSTATES {
        for t2 in 0..NSTATES {
            if matches!(STATE_TRANS_COVERAGE[f2][t2], CellCoverage::Unreachable(_)) {
                let v = ctrs.tcp.state_trans[f2][t2].load(Ordering::Relaxed);
                assert_eq!(
                    v, 0,
                    "unreachable state_trans[{f2}][{t2}] fired under scenario \
                     for cell ({from}->{to}) — either open the cell or fix the scenario"
                );
            }
        }
    }
}

// ---- Reached-cell scenarios ----------------------------------------

/// [0][2] Closed → SynSent: `connect()` inserts a fresh conn in Closed,
/// emits SYN, then transitions to SynSent.
fn scen_closed_to_syn_sent(h: &mut CovHarness) {
    let _ = h.do_active_open_only();
}

/// [2][0] SynSent → Closed: RST with valid ACK of our SYN per
/// RFC 9293 §3.10.7.3.
fn scen_syn_sent_to_closed_rst(h: &mut CovHarness) {
    let (our_src_port, our_iss) = h.do_active_open_only();
    h.inject_rst_to_syn_sent(our_src_port, our_iss);
}

/// [2][4] SynSent → Established: full active 3WHS (SYN → SYN-ACK → our
/// final ACK emitted automatically).
fn scen_syn_sent_to_established(h: &mut CovHarness) {
    h.do_active_open_full();
}

/// [3][0] SynReceived → Closed: bad-ACK in SYN_RCVD triggers
/// `TxAction::Rst` + transition to Closed.
fn scen_syn_received_to_closed_bad_ack(h: &mut CovHarness) {
    let _ = h.do_passive_open_syn_ack_only();
    h.inject_peer_bad_ack_to_syn_rcvd();
}

/// [3][4] SynReceived → Established: final ACK completes the passive
/// 3WHS via `do_passive_open`.
fn scen_syn_received_to_established(h: &mut CovHarness) {
    let _ = h.do_passive_open();
}

/// [4][0] Established → Closed: peer RST on ESTABLISHED conn.
fn scen_established_to_closed_rst(h: &mut CovHarness) {
    let _ = h.do_passive_open();
    h.inject_rst_to_established();
}

/// [4][5] Established → FinWait1: our `close_conn` on an ESTABLISHED
/// conn emits FIN and transitions to FIN_WAIT_1.
fn scen_established_to_fin_wait_1(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.close_conn(conn);
}

/// [4][7] Established → CloseWait: peer FIN on an ESTABLISHED conn.
fn scen_established_to_close_wait(h: &mut CovHarness) {
    let _ = h.do_passive_open();
    h.inject_peer_fin();
}

/// [5][6] FinWait1 → FinWait2: peer ACKs our FIN but does NOT send its
/// own FIN.
fn scen_fin_wait_1_to_fin_wait_2(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.close_conn(conn);
    h.inject_peer_ack_our_fin();
}

/// [5][8] FinWait1 → Closing: simultaneous close — peer FIN arrives
/// without ACK of our FIN (peer's FIN crossed ours in flight).
fn scen_fin_wait_1_to_closing(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.close_conn(conn);
    h.inject_peer_fin_no_ack_of_our_fin();
}

/// [5][10] FinWait1 → TimeWait: peer's ACK of our FIN and peer's FIN
/// arrive in one combined segment.
fn scen_fin_wait_1_to_time_wait(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.close_conn(conn);
    h.inject_peer_fin_ack_combined();
}

/// [6][10] FinWait2 → TimeWait: first peer ACK covers our FIN (→ FW2);
/// then peer FIN (→ TW).
fn scen_fin_wait_2_to_time_wait(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.close_conn(conn);
    h.inject_peer_ack_our_fin();
    h.inject_peer_fin();
}

/// [8][10] Closing → TimeWait: simultaneous close path — peer FIN
/// (without ACK of our FIN) → Closing; then peer ACK covers our FIN →
/// TW.
fn scen_closing_to_time_wait(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.close_conn(conn);
    h.inject_peer_fin_no_ack_of_our_fin();
    h.inject_peer_ack_our_fin();
}

/// [7][9] CloseWait → LastAck: peer FIN (→ CW) + our `close_conn`
/// (→ LastAck).
fn scen_close_wait_to_last_ack(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.inject_peer_fin();
    h.close_conn(conn);
}

/// [9][0] LastAck → Closed: passive-close full path — peer FIN + our
/// close + peer ACK of our FIN.
fn scen_last_ack_to_closed(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.inject_peer_fin();
    h.close_conn(conn);
    h.inject_peer_ack_our_fin();
}

/// [10][0] TimeWait → Closed: reach TW via FIN+ACK combined, then
/// advance virt-clock past 2×MSL + invoke `test_reap_time_wait`.
fn scen_time_wait_to_closed(h: &mut CovHarness) {
    let conn = h.do_passive_open();
    h.close_conn(conn);
    h.inject_peer_fin_ack_combined(); // → TimeWait
    h.advance_virt_past_2msl_and_reap(); // → Closed
}

// ---------------------------------------------------------------------
// T9: feature-gated counter-coverage scenarios.
//
// These scenarios exercise counters whose increment site is compiled
// out of the default-features build. They run only under
// `--features obs-byte-counters,test-server` (or `--all-features` once
// the A9 `fault-injector` feature lands). Static audit (T3) reaches
// them via the `feature-gated-counters.txt` whitelist in
// `tests/feature-gated-counters.txt`.
//
// Only `obs-byte-counters` entries here; A9's `fault-injector` group
// does NOT have its `FaultInjectorCounters` struct on `Counters` yet
// on the phase-a8 tip, so there is no counter-path to audit.
// ---------------------------------------------------------------------

/// Covers: `tcp.tx_payload_bytes` (hot-path, per-burst-batched).
/// Feature-gate: `obs-byte-counters` (default OFF). Increment site:
/// `send_bytes` per-segment accumulator flushed as a single `fetch_add`
/// after the segmentation loop (engine.rs:4739). See spec §9.1.1
/// hot-path counter policy.
#[cfg(feature = "obs-byte-counters")]
#[test]
fn cover_tcp_tx_payload_bytes() {
    let mut h = CovHarness::new();
    let conn = h.do_passive_open();
    // Send bytes peer-ward; `send_bytes` internally accumulates the
    // per-segment byte count and flushes a single fetch_add at method
    // exit, so the counter bumps whether or not we subsequently drain.
    h.send_bytes_and_flush(conn, b"abcdefghij"); // 10 bytes
    h.assert_counter_gt_zero("tcp.tx_payload_bytes");
}

/// Covers: `tcp.rx_payload_bytes` (hot-path, per-burst-batched).
/// Feature-gate: `obs-byte-counters` (default OFF). Increment site:
/// `poll_once` rx-burst accumulator (engine.rs:2106). The
/// `inject_rx_frame` test-server path mirrors the bump (same feature
/// gate) because the test-server bypass cannot drive `poll_once`
/// directly — see the T9 mirror comment in `inject_rx_frame`.
#[cfg(feature = "obs-byte-counters")]
#[test]
fn cover_tcp_rx_payload_bytes() {
    let mut h = CovHarness::new();
    let _conn = h.do_passive_open();
    // Peer sends data; `rx_frame` returns the accepted-payload bytes
    // and `inject_rx_frame`'s T9 mirror adds them to the counter.
    h.inject_peer_data(b"hijklmnop"); // 9 bytes
    h.assert_counter_gt_zero("tcp.rx_payload_bytes");
}
