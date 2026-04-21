//! Phase A6 integration tests (pure in-process; no TAP required).
//!
//! These exercise the public API surface additions from phase A6 end-to-end
//! at the `TcpConn` / `Engine` / `EventQueue` / pure-function level. The
//! `_tap` suffix matches the naming convention of the other integration
//! test files in this directory, even though nearly every test in this
//! file is pure in-process — see the scenario coverage map in the module
//! doc-comment.
//!
//! ## Coverage map vs. the plan's 17 scenarios
//!
//! * Plan #1 (timer ID pack/unpack roundtrip) — covered.
//! * Plan #2 (`align_up_to_tick_ns` boundary values) — covered.
//! * Plan #3 (`InternalEvent::ApiTimer` translation in `build_event_from_internal`)
//!   — deferred: `build_event_from_internal` is a private fn in
//!   `crates/dpdk-net/src/lib.rs`. Coverage of the `ApiTimer` variant
//!   shape + event-queue FIFO round-trip lives in the dpdk-net-core
//!   module tests (`tcp_events::tests::api_timer_event_variant_shape`) and
//!   in the `drain_reads_emitted_ts_ns_through_not_drain_clock` test in
//!   crates/dpdk-net/src/lib.rs (A5.5 Task 8). An ABI-level translator
//!   test belongs in crates/dpdk-net — flagged for Task 22/23 reviewers.
//! * Plan #4 (`InternalEvent::Writable` translation) — deferred, same
//!   rationale as #3.
//! * Plan #5 (`RttHistogram::update` distribution across known edges) —
//!   covered.
//! * Plan #6 (`RttHistogram` cross-conn isolation) — covered.
//! * Plan #7 (positive-path `dpdk_net_conn_rtt_histogram` via ABI) —
//!   deferred: requires a live DPDK/EAL Engine (negative-path / null-arg
//!   coverage lives in `dpdk_net_conn_rtt_histogram`'s existing unit tests
//!   in crates/dpdk-net/src/lib.rs — A6 Task 18).
//! * Plan #8 (TS.Recent 24-day lazy expiration) — PARTIALLY covered. The
//!   positive-path (idle > 24d → expired) requires a mock clock that does
//!   not exist; the real `clock::now_ns()` is TSC-backed and unmockable.
//!   The negative-path assertions pinned here (fresh-conn sentinel + small
//!   idle window both stay unfired) are what is reachable without waiting
//!   24 wall-clock days. Positive-path flagged for clock-injection follow-
//!   up (Task 22/23 reviewers).
//! * Plan #9 (WRITABLE hysteresis fires on ACK-prune) — covered.
//!   Additional tests pin the single-edge-per-refusal-cycle + negative
//!   (in_flight > threshold) contracts.
//! * Plan #10 (`force_tw_skip` short-circuits reap predicate) — not
//!   duplicated here; a canonical version lives in engine.rs (A6 Task 11)
//!   already. Adding a duplicate would not improve coverage.
//! * Plan #11 (event-queue FIFO overflow with A6 variants) — covered.
//! * Plan #12 (ABI layer null-guards) — already covered by null-arg tests
//!   in crates/dpdk-net/src/lib.rs (Tasks 17, 18, 20); not duplicated here.
//! * `validate_and_default_histogram_edges` (Task 6) — 3 positive/negative
//!   cases pinned here at the integration boundary so the Engine config
//!   validator can be confidently refactored without breaking Task 20's
//!   ABI plumbing contract.

use dpdk_net_core::counters::Counters;
use dpdk_net_core::engine::{
    align_up_to_tick_ns, pack_timer_id, unpack_timer_id,
    validate_and_default_histogram_edges, DEFAULT_RTT_HISTOGRAM_EDGES_US,
};
use dpdk_net_core::flow_table::FourTuple;
use dpdk_net_core::rtt_histogram::RttHistogram;
use dpdk_net_core::tcp_conn::TcpConn;
use dpdk_net_core::tcp_events::{EventQueue, InternalEvent, LossCause};
use dpdk_net_core::tcp_input::{dispatch, ParsedSegment};
use dpdk_net_core::tcp_state::TcpState;

// `tcp_timer_wheel` is `pub(crate)` — external integration tests can't
// name `TimerId` directly. `engine::unpack_timer_id` is the canonical
// external factory (the ABI layer itself uses the same helper — see
// `dpdk_net_timer_cancel` in crates/dpdk-net/src/lib.rs). Use it to
// fabricate TimerId values from known (slot, generation) pairs for the
// InternalEvent::ApiTimer variant without naming the private type.

// Test-side default edges matching the engine's. All hysteresis + PAWS
// dispatch tests pass this through so bucketing matches runtime behavior.
const TEST_EDGES: [u32; 15] = DEFAULT_RTT_HISTOGRAM_EDGES_US;

// Default send-buffer capacity matching `EngineConfig::send_buffer_bytes`
// (256 KiB). Hysteresis tests may override this per-call to drive the
// `in_flight <= send_buffer_bytes/2` threshold through observable edges.
const TEST_SEND_BUF_BYTES_256K: u32 = 256 * 1024;

// TCP flag bit constants mirrored from `tcp_input.rs` private consts.
// These are the on-wire bit positions per RFC 9293 §3.1.
const TCP_ACK: u8 = 0x10;

fn test_tuple() -> FourTuple {
    FourTuple {
        local_ip: 0x0a_00_00_02,
        local_port: 40000,
        peer_ip: 0x0a_00_00_01,
        peer_port: 5000,
    }
}

/// Build a fresh `TcpConn` already in ESTABLISHED. Mirrors the
/// `est_conn` helper inside `tcp_input.rs` tests so the dispatch entry
/// conditions match the runtime path exactly.
fn est_conn(iss: u32, irs: u32, peer_wnd: u16) -> TcpConn {
    let mut c = TcpConn::new_client(
        test_tuple(),
        iss,
        1460, // our_mss
        1024, // recv_buf_bytes
        2048, // send_buf_bytes
        5_000,
        5_000,
        1_000_000,
    );
    c.state = TcpState::Established;
    c.snd_una = iss.wrapping_add(1);
    c.snd_nxt = iss.wrapping_add(1);
    c.irs = irs;
    c.rcv_nxt = irs.wrapping_add(1);
    c.snd_wnd = peer_wnd as u32;
    c
}

// -------------------------------------------------------------------------
// Scenario #1: pack/unpack timer_id round-trip across engine helpers.
// -------------------------------------------------------------------------

#[test]
fn timer_id_pack_unpack_roundtrip_canonical() {
    // Build the canonical (slot=7, gen=42) TimerId via the unpack
    // factory since the TimerId struct's module is pub(crate).
    let id = unpack_timer_id(0x0000_0007_0000_002A);
    assert_eq!(id.slot, 7);
    assert_eq!(id.generation, 42);
    // Pack produces the expected u64 layout: slot in upper 32, gen in lower.
    assert_eq!(pack_timer_id(id), 0x0000_0007_0000_002A);

    let other = unpack_timer_id(0xAABB_CCDD_1122_3344);
    assert_eq!(other.slot, 0xAABB_CCDD);
    assert_eq!(other.generation, 0x1122_3344);
    // And roundtrip back unchanged.
    assert_eq!(pack_timer_id(other), 0xAABB_CCDD_1122_3344);
}

#[test]
fn timer_id_roundtrip_preserves_arbitrary_values() {
    // Pin the roundtrip over the extremal bit-patterns, including
    // all-ones and alternating-bits, so a future endianness or
    // shift-mask bug can't slip through.
    for (slot, generation) in [
        (0u32, 0u32),
        (u32::MAX, u32::MAX),
        (0x5555_5555, 0xAAAA_AAAA),
        (1, 0),
        (0, 1),
        (0xDEAD_BEEF, 0xCAFE_F00D),
    ] {
        // Pack manually to the expected bitpattern, then unpack →
        // pack-back must reproduce it byte-for-byte.
        let packed_want = ((slot as u64) << 32) | (generation as u64);
        let id = unpack_timer_id(packed_want);
        assert_eq!(
            id.slot, slot,
            "slot survives unpack at slot={slot:x} gen={generation:x}"
        );
        assert_eq!(
            id.generation, generation,
            "generation survives unpack at slot={slot:x} gen={generation:x}"
        );
        assert_eq!(
            pack_timer_id(id),
            packed_want,
            "pack round-trips to the original u64 at slot={slot:x} gen={generation:x}"
        );
    }
}

// -------------------------------------------------------------------------
// Scenario #2: `align_up_to_tick_ns` boundary values.
// -------------------------------------------------------------------------

#[test]
fn align_up_to_tick_ns_boundary_and_saturating_behavior() {
    // deadline_ns=0 stays 0 (fires on next poll).
    assert_eq!(align_up_to_tick_ns(0), 0);
    // 1 ns → rounds up to one full tick (10_000 ns).
    assert_eq!(align_up_to_tick_ns(1), 10_000);
    // Exactly on a tick boundary: preserved, no spurious advance.
    assert_eq!(align_up_to_tick_ns(10_000), 10_000);
    // Just past a boundary: advances to the next.
    assert_eq!(align_up_to_tick_ns(10_001), 20_000);
    // Just below next boundary: advances to that boundary.
    assert_eq!(align_up_to_tick_ns(19_999), 20_000);
    // Multi-tick rounding.
    assert_eq!(align_up_to_tick_ns(25_000), 30_000);
    // Very large value: saturating_mul prevents UB. The wheel will
    // never be asked to represent `u64::MAX` as a fire-at under any
    // plausible deadline — the helper must not panic when one is
    // coerced through. Post-saturation the result is capped at
    // u64::MAX (which is not itself 10 000-aligned: 18_446_744_073_709_551_615
    // mod 10_000 = 1_615). We accept the saturation rather than spin
    // in an attempt to re-align a value that can't fit.
    let huge = align_up_to_tick_ns(u64::MAX);
    assert_eq!(
        huge,
        u64::MAX,
        "saturating_mul must cap at u64::MAX, not panic or wrap"
    );
}

// -------------------------------------------------------------------------
// Scenarios #5 & #6: RttHistogram update distribution + isolation.
// -------------------------------------------------------------------------

#[test]
fn rtt_histogram_update_distributes_samples_to_expected_buckets() {
    // Spec §3.8.1 edge-set → known bucket indexes. Drive 5 distinct
    // RTTs that each land in a different bucket and assert the counts
    // end up where we expect.
    let mut h = RttHistogram::default();
    //   5 µs  -> bucket 0 (≤ 50)
    //   75 µs -> bucket 1 (≤ 100)
    //   400 µs -> bucket 4 (≤ 500)
    //   4000 µs -> bucket 9 (≤ 5000)
    //   600_000 µs -> bucket 15 (catch-all)
    h.update(5, &TEST_EDGES);
    h.update(75, &TEST_EDGES);
    h.update(400, &TEST_EDGES);
    h.update(4_000, &TEST_EDGES);
    h.update(600_000, &TEST_EDGES);

    assert_eq!(h.buckets[0], 1, "≤ 50 µs");
    assert_eq!(h.buckets[1], 1, "≤ 100 µs");
    assert_eq!(h.buckets[4], 1, "≤ 500 µs");
    assert_eq!(h.buckets[9], 1, "≤ 5000 µs");
    assert_eq!(h.buckets[15], 1, "catch-all bucket for > last edge");

    // Every other bucket stays zero.
    for (i, c) in h.buckets.iter().enumerate() {
        if ![0usize, 1, 4, 9, 15].contains(&i) {
            assert_eq!(*c, 0, "bucket {i} unexpectedly nonzero");
        }
    }
}

#[test]
fn rtt_histogram_cross_conn_isolation() {
    // Two independent histograms; updating one must not bleed into the
    // other. Pins the "per-conn state" contract — there are no shared
    // atomics / static storage under the histogram.
    let mut h_a = RttHistogram::default();
    let mut h_b = RttHistogram::default();

    for _ in 0..17 {
        h_a.update(150, &TEST_EDGES); // bucket 2
    }

    // All buckets on B remain zero.
    for (i, c) in h_b.buckets.iter().enumerate() {
        assert_eq!(*c, 0, "h_b.buckets[{i}] must be 0 after h_a-only updates");
    }
    // A's bucket-2 is what it should be.
    assert_eq!(h_a.buckets[2], 17);

    // And updating B doesn't touch A.
    for _ in 0..3 {
        h_b.update(2_500, &TEST_EDGES); // bucket 8
    }
    assert_eq!(h_b.buckets[8], 3);
    assert_eq!(h_a.buckets[8], 0, "A must stay 0 at b_b's bucket");
}

#[test]
fn rtt_histogram_snapshot_is_disconnected_copy() {
    // `dpdk_net_conn_rtt_histogram` memcpys the bucket array into
    // caller memory. Pin the "snapshot does not alias the live state"
    // contract at the ABI boundary: after snapshot, further updates
    // to the source MUST NOT change the snapshot array. This guards
    // against a future refactor that might accidentally return a view.
    let mut h = RttHistogram::default();
    h.update(50, &TEST_EDGES); // bucket 0
    let snap = h.snapshot();
    assert_eq!(snap[0], 1);
    // Mutate source heavily after snapshot; the snapshot is frozen.
    for _ in 0..1000 {
        h.update(50, &TEST_EDGES);
    }
    assert_eq!(snap[0], 1, "snapshot must not alias live histogram");
    assert_eq!(h.buckets[0], 1001, "source updates took effect");
}

// -------------------------------------------------------------------------
// Scenario #9: WRITABLE hysteresis fires on ACK-prune + ancillary edges.
// -------------------------------------------------------------------------

#[test]
fn writable_hysteresis_fires_when_ack_drains_below_half_send_buffer() {
    // Spec §3.3: after a prior `send_bytes` refusal set
    // `send_refused_pending = true`, a subsequent ACK that advances
    // `snd_una` such that `(snd_nxt - snd_una) <= send_buffer_bytes/2`
    // MUST flip `outcome.writable_hysteresis_fired` true AND clear
    // `conn.send_refused_pending` in one shot.
    let mut c = est_conn(1000, 5000, 65_535);
    c.send_refused_pending = true;

    // Simulate a 1000-byte in-flight segment before the ACK. With
    // `send_buffer_bytes = 256 KiB`, threshold = 128 KiB; any in_flight
    // <= 128 KiB drives the hysteresis, so 1000 qualifies.
    c.snd.push(&[0u8; 1000]);
    c.snd_nxt = c.snd_una.wrapping_add(1000);

    // Peer ACKs all 1000 bytes → snd_una advances to snd_nxt → in_flight=0.
    let seg = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: c.snd_nxt, // cum-ACK all in-flight
        flags: TCP_ACK,
        window: 65_535,
        header_len: 20,
        payload: &[],
        options: &[],
    };

    let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES_256K, None);
    assert!(
        out.writable_hysteresis_fired,
        "in_flight=0 post-ACK must flip writable_hysteresis_fired"
    );
    assert!(
        !c.send_refused_pending,
        "writable_hysteresis_fired must clear send_refused_pending"
    );
    assert_eq!(
        out.snd_una_advanced_to,
        Some(c.snd_una),
        "ACK must also propagate snd_una_advanced_to"
    );
}

#[test]
fn writable_hysteresis_silent_when_in_flight_above_threshold() {
    // Negative path: if the ACK's prune leaves in_flight *above*
    // `send_buffer_bytes/2`, the event does NOT fire and the pending
    // bit is NOT cleared. Pins the strict ≤ compare.
    let mut c = est_conn(1000, 5000, 65_535);
    c.send_refused_pending = true;

    // 10_000 in-flight, send_buffer=8_000 → threshold=4_000.
    // Partial ACK drops in_flight to 6_000 (> 4_000).
    c.snd.push(&[0u8; 10_000]);
    c.snd_nxt = c.snd_una.wrapping_add(10_000);

    let partial_ack = c.snd_una.wrapping_add(4_000);
    let seg = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: partial_ack,
        flags: TCP_ACK,
        window: 65_535,
        header_len: 20,
        payload: &[],
        options: &[],
    };

    // send_buffer_bytes = 8_000 → threshold = 4_000. in_flight after
    // the ACK = 10_000 - 4_000 = 6_000 > 4_000, so no WRITABLE.
    let out = dispatch(&mut c, &seg, &TEST_EDGES, 8_000, None);
    assert!(
        !out.writable_hysteresis_fired,
        "in_flight=6000 > threshold=4000 must NOT fire WRITABLE"
    );
    assert!(
        c.send_refused_pending,
        "pending bit must stay latched until we drain below threshold"
    );
}

#[test]
fn writable_hysteresis_single_edge_per_refusal_cycle() {
    // Spec §3.3: level-triggered, one-shot per refusal cycle. After the
    // first WRITABLE fires and clears `send_refused_pending`, subsequent
    // ACKs must NOT re-fire until a fresh `send_bytes` refusal re-sets
    // the pending bit. This is the single most important contract for
    // avoiding event-queue saturation on steady-state traffic.
    let mut c = est_conn(1000, 5000, 65_535);
    c.send_refused_pending = true;
    c.snd.push(&[0u8; 500]);
    c.snd_nxt = c.snd_una.wrapping_add(500);

    let first_ack_target = c.snd_nxt;
    let first = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: first_ack_target,
        flags: TCP_ACK,
        window: 65_535,
        header_len: 20,
        payload: &[],
        options: &[],
    };
    let out1 = dispatch(&mut c, &first, &TEST_EDGES, TEST_SEND_BUF_BYTES_256K, None);
    assert!(out1.writable_hysteresis_fired, "first edge must fire");
    assert!(!c.send_refused_pending, "first edge must clear pending");

    // Send more data, then ACK that too — still a draining pattern,
    // but NO refusal occurred, so `send_refused_pending` is false and
    // the hysteresis must stay silent.
    c.snd.push(&[0u8; 200]);
    c.snd_nxt = c.snd_una.wrapping_add(200);
    let second = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: c.snd_nxt,
        flags: TCP_ACK,
        window: 65_535,
        header_len: 20,
        payload: &[],
        options: &[],
    };
    let out2 = dispatch(&mut c, &second, &TEST_EDGES, TEST_SEND_BUF_BYTES_256K, None);
    assert!(
        !out2.writable_hysteresis_fired,
        "second ACK without re-refusal must NOT fire WRITABLE"
    );
    assert!(!c.send_refused_pending);

    // Finally: emulate a fresh `send_bytes` refusal (flip the bit back on),
    // and a follow-up draining ACK — the hysteresis must fire again.
    c.send_refused_pending = true;
    c.snd.push(&[0u8; 100]);
    c.snd_nxt = c.snd_una.wrapping_add(100);
    let third = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: c.snd_nxt,
        flags: TCP_ACK,
        window: 65_535,
        header_len: 20,
        payload: &[],
        options: &[],
    };
    let out3 = dispatch(&mut c, &third, &TEST_EDGES, TEST_SEND_BUF_BYTES_256K, None);
    assert!(
        out3.writable_hysteresis_fired,
        "fresh refusal cycle must re-enable the edge"
    );
    assert!(!c.send_refused_pending);
}

#[test]
fn writable_hysteresis_silent_when_pending_not_set() {
    // Negative-negative path: no prior refusal → even a fully-drained
    // send buffer post-ACK does NOT fire. This is the zero-cost
    // steady-state case — proves we don't spam WRITABLE per ACK on
    // a healthy flow.
    let mut c = est_conn(1000, 5000, 65_535);
    assert!(!c.send_refused_pending);
    c.snd.push(&[0u8; 500]);
    c.snd_nxt = c.snd_una.wrapping_add(500);

    let seg = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: c.snd_nxt,
        flags: TCP_ACK,
        window: 65_535,
        header_len: 20,
        payload: &[],
        options: &[],
    };
    let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES_256K, None);
    assert!(!out.writable_hysteresis_fired);
}

// -------------------------------------------------------------------------
// Scenario #8: TS.Recent lazy expiration — partial coverage (negative paths).
// -------------------------------------------------------------------------

#[test]
fn ts_recent_fresh_conn_sentinel_never_expires() {
    // Plan #8 positive-path (idle > 24 days → expired=true) requires a
    // mock clock this project doesn't have — `clock::now_ns()` is
    // TSC-backed and gives real wall-ish time since process start.
    // What we CAN pin is the sentinel contract: `ts_recent_age == 0`
    // is "never touched" and must NEVER fire expiration regardless of
    // how much wall time has accumulated.
    //
    // Build: TS-enabled conn fresh from new_client (ts_recent_age=0),
    // with a stale-looking ts_val in the segment. Should NOT set
    // ts_recent_expired because of the sentinel guard, even though the
    // comparison `idle_ns > 24d` is now over 24d × SECS_PER_DAY × 1e9
    // — which a real wall-clock WILL exceed after enough uptime, but
    // the `ts_recent_age != 0` guard short-circuits before we get there.
    let mut c = est_conn(1000, 5000, 65_535);
    c.ts_enabled = true;
    c.ts_recent = 100; // baseline
    c.ts_recent_age = 0; // sentinel — "never touched"

    let peer_opts = dpdk_net_core::tcp_options::TcpOpts {
        timestamps: Some((50, 0)), // < ts_recent -> PAWS would normally drop
        ..Default::default()
    };
    let mut buf = [0u8; 40];
    let n = peer_opts.encode(&mut buf).unwrap();

    let seg = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: 1001,
        flags: TCP_ACK,
        window: 65_535,
        header_len: 20 + n,
        payload: &[],
        options: &buf[..n],
    };
    let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES_256K, None);
    assert!(
        !out.ts_recent_expired,
        "age=0 sentinel must NEVER fire expiration even with stale ts_val"
    );
    // PAWS instead rejected the stale segment (normal compare).
    assert!(out.paws_rejected);
    // ts_recent must remain unchanged.
    assert_eq!(c.ts_recent, 100);
    assert_eq!(c.ts_recent_age, 0, "sentinel preserved on rejection");
}

#[test]
fn ts_recent_recent_age_does_not_spuriously_expire() {
    // Negative path on the non-sentinel branch: conn has a recent
    // `ts_recent_age` (≈ test-start time) → the idle delta is tiny,
    // the 24-day threshold is not exceeded, and a fresh ts_val passes
    // PAWS normally without triggering the lazy-expiration branch.
    let mut c = est_conn(1000, 5000, 65_535);
    c.ts_enabled = true;
    c.ts_recent = 100;
    // Mark `ts_recent_age` as "just updated" by pinning it to now_ns.
    // That makes `idle_ns ≈ 0`, definitively below the 24d threshold.
    c.ts_recent_age = dpdk_net_core::clock::now_ns();

    let peer_opts = dpdk_net_core::tcp_options::TcpOpts {
        timestamps: Some((200, 0)), // > ts_recent -> PAWS accepts
        ..Default::default()
    };
    let mut buf = [0u8; 40];
    let n = peer_opts.encode(&mut buf).unwrap();

    let seg = ParsedSegment {
        src_port: 5000,
        dst_port: 40000,
        seq: 5001,
        ack: 1001,
        flags: TCP_ACK,
        window: 65_535,
        header_len: 20 + n,
        payload: &[],
        options: &buf[..n],
    };
    let out = dispatch(&mut c, &seg, &TEST_EDGES, TEST_SEND_BUF_BYTES_256K, None);
    assert!(
        !out.ts_recent_expired,
        "recent age within 24d must NOT fire lazy expiration"
    );
    // Normal PAWS-accept path: ts_recent advances to the peer's tsval.
    assert_eq!(c.ts_recent, 200);
}

// -------------------------------------------------------------------------
// Scenario #11: event-queue FIFO contract preserved across A6's new variants.
// -------------------------------------------------------------------------

#[test]
fn event_queue_preserves_api_timer_and_writable_variants_fifo() {
    // A5.5 Tasks 5 & 8 pinned FIFO / emitted_ts_ns contracts across the
    // 7 pre-A6 variants. A6 added `ApiTimer` and `Writable` — prove the
    // queue treats them identically (FIFO order preserved, variant
    // payload survives, `emitted_ts_ns` comes out verbatim).
    let counters = Counters::new();
    let mut q = EventQueue::new();

    // Packed layout (slot=3, gen=9) = 0x0000_0003_0000_0009.
    let id = unpack_timer_id(0x0000_0003_0000_0009);
    q.push(
        InternalEvent::ApiTimer {
            timer_id: id,
            user_data: 0xFEED_F00D_1234_5678,
            emitted_ts_ns: 111,
        },
        &counters,
    );
    q.push(
        InternalEvent::Writable {
            conn: 7,
            emitted_ts_ns: 222,
        },
        &counters,
    );
    q.push(
        InternalEvent::TcpLossDetected {
            conn: 7,
            cause: LossCause::Rack,
            emitted_ts_ns: 333,
        },
        &counters,
    );

    // Drain in order. ApiTimer first.
    match q.pop() {
        Some(InternalEvent::ApiTimer {
            timer_id,
            user_data,
            emitted_ts_ns,
        }) => {
            assert_eq!(timer_id, id);
            assert_eq!(user_data, 0xFEED_F00D_1234_5678);
            assert_eq!(emitted_ts_ns, 111);
        }
        other => panic!("expected ApiTimer first, got {other:?}"),
    }
    // Writable second.
    match q.pop() {
        Some(InternalEvent::Writable {
            conn,
            emitted_ts_ns,
        }) => {
            assert_eq!(conn, 7);
            assert_eq!(emitted_ts_ns, 222);
        }
        other => panic!("expected Writable second, got {other:?}"),
    }
    // Pre-A6 variant still works after A6 variants.
    match q.pop() {
        Some(InternalEvent::TcpLossDetected {
            conn,
            cause,
            emitted_ts_ns,
        }) => {
            assert_eq!(conn, 7);
            assert_eq!(cause, LossCause::Rack);
            assert_eq!(emitted_ts_ns, 333);
        }
        other => panic!("expected TcpLossDetected third, got {other:?}"),
    }
    assert!(q.pop().is_none());
}

#[test]
fn event_queue_overflow_still_drops_oldest_with_a6_variants_mixed_in() {
    // Pins the A5.5 Task 3 / Task 8 drop-oldest contract under a
    // realistic burst that interleaves ApiTimer + Writable with the
    // pre-A6 variants. The most-recent 64 MUST survive, in FIFO order.
    use std::sync::atomic::Ordering;

    let counters = Counters::new();
    let mut q = EventQueue::with_cap(64);

    // 200 events: rotate through 4 variants so the tail (the surviving
    // 64) includes a healthy mix of A6 and pre-A6 variants.
    for i in 0..200u64 {
        let emitted_ts_ns = i * 1000;
        let ev = match i % 4 {
            0 => InternalEvent::ApiTimer {
                // (slot=i-low-32, gen=0)
                timer_id: unpack_timer_id((i & 0xFFFF_FFFF) << 32),
                user_data: i,
                emitted_ts_ns,
            },
            1 => InternalEvent::Writable {
                conn: 1,
                emitted_ts_ns,
            },
            2 => InternalEvent::Connected {
                conn: 1,
                rx_hw_ts_ns: 0,
                emitted_ts_ns,
            },
            _ => InternalEvent::Closed {
                conn: 1,
                err: 0,
                emitted_ts_ns,
            },
        };
        q.push(ev, &counters);
    }

    assert_eq!(q.len(), 64);
    assert_eq!(counters.obs.events_dropped.load(Ordering::Relaxed), 136);
    assert_eq!(
        counters.obs.events_queue_high_water.load(Ordering::Relaxed),
        64
    );

    // Drain and confirm the surviving emitted_ts_ns sequence covers
    // (i=136..=199) × 1000 in strict FIFO order regardless of variant.
    let mut got: Vec<u64> = Vec::with_capacity(64);
    while let Some(ev) = q.pop() {
        let ts = match ev {
            InternalEvent::Connected { emitted_ts_ns, .. }
            | InternalEvent::Readable { emitted_ts_ns, .. }
            | InternalEvent::Closed { emitted_ts_ns, .. }
            | InternalEvent::StateChange { emitted_ts_ns, .. }
            | InternalEvent::Error { emitted_ts_ns, .. }
            | InternalEvent::TcpRetrans { emitted_ts_ns, .. }
            | InternalEvent::TcpLossDetected { emitted_ts_ns, .. }
            | InternalEvent::ApiTimer { emitted_ts_ns, .. }
            | InternalEvent::Writable { emitted_ts_ns, .. } => emitted_ts_ns,
        };
        got.push(ts);
    }
    let expected: Vec<u64> = (136u64..=199).map(|i| i * 1000).collect();
    assert_eq!(got, expected);
}

// -------------------------------------------------------------------------
// `validate_and_default_histogram_edges` contract (Task 6 + Task 20).
// -------------------------------------------------------------------------

#[test]
fn histogram_edges_zero_init_substitutes_defaults() {
    // Spec §3.8.3 / Task 20: all-zero edges from the ABI caller MUST
    // substitute the engine's `DEFAULT_RTT_HISTOGRAM_EDGES_US` so
    // zero-init C++ callers (the common path) get sensible bucketing
    // without per-field ceremony.
    let validated = validate_and_default_histogram_edges(&[0u32; 15])
        .expect("all-zero input must validate and substitute defaults");
    assert_eq!(validated, DEFAULT_RTT_HISTOGRAM_EDGES_US);
}

#[test]
fn histogram_edges_monotonic_passes_through_unchanged() {
    // Caller-supplied strictly-monotonic edges MUST pass through
    // unchanged — this is the "advanced knob" path for callers with
    // known RTT distributions that don't match the defaults.
    let good: [u32; 15] = [
        10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 1000,
    ];
    let out = validate_and_default_histogram_edges(&good).unwrap();
    assert_eq!(out, good);
}

#[test]
fn histogram_edges_non_monotonic_rejected() {
    // Non-strictly-monotonic input (equal or decreasing adjacent edges)
    // MUST reject so the ABI layer can surface -EINVAL to the caller
    // instead of silently skewing bucket selection.
    let bad_equal: [u32; 15] = [
        50, 100, 100, 300, 500, 750, 1000, 2000, 3000, 5000, 10_000, 25_000, 50_000, 100_000,
        500_000,
    ];
    assert!(validate_and_default_histogram_edges(&bad_equal).is_err());

    let bad_decreasing: [u32; 15] = [
        50, 100, 200, 150, 500, 750, 1000, 2000, 3000, 5000, 10_000, 25_000, 50_000, 100_000,
        500_000,
    ];
    assert!(validate_and_default_histogram_edges(&bad_decreasing).is_err());
}
