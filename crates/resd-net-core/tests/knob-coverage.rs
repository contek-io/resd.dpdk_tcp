//! Knob-coverage audit per roadmap §A11.
//!
//! Each entry exercises a non-default value of one behavioral knob
//! and asserts an observable consequence that distinguishes the
//! non-default value from the default. This file is the A5.5 partial
//! slice: it covers the five new TLP-tuning knobs plus the engine-wide
//! `event_queue_soft_cap` plus the aggressive-order-entry preset
//! combination. A11 will absorb this into a full cross-phase audit
//! (likely replacing the flat `#[test]` structure with a `KnobScenario`
//! table + scenario-fn pointers).
//!
//! Scenario fns run at the Rust-helper / unit-test level so they do
//! not require a TAP harness. When a knob's observable consequence
//! needs timer-wheel stepping or peer control, the test asserts on
//! the same helper the engine's hot path invokes (`pto_us`,
//! `TcpConn::tlp_arm_gate_passes`, `EventQueue::push`, …).
//!
//! A5.5 canonical list (per plan §17):
//!   Engine-wide:
//!     event_queue_soft_cap
//!   Per-connect:
//!     tlp_pto_min_floor_us
//!     tlp_pto_srtt_multiplier_x100
//!     tlp_skip_flight_size_gate
//!     tlp_max_consecutive_probes
//!     tlp_skip_rtt_sample_gate
//!   Combination:
//!     aggressive_order_entry_preset

use std::sync::atomic::Ordering;

use resd_net_core::counters::Counters;
use resd_net_core::flow_table::{ConnHandle, FourTuple};
use resd_net_core::mempool::Mbuf;
use resd_net_core::tcp_conn::TcpConn;
use resd_net_core::tcp_events::{EventQueue, InternalEvent};
use resd_net_core::tcp_retrans::RetransEntry;
use resd_net_core::tcp_tlp::{pto_us, TlpConfig, WCDELACK_US};

// ---- shared test helpers ------------------------------------------------

fn tuple() -> FourTuple {
    FourTuple {
        local_ip: 0x0a_00_00_02,
        local_port: 40000,
        peer_ip: 0x0a_00_00_01,
        peer_port: 5000,
    }
}

fn make_conn() -> TcpConn {
    TcpConn::new_client(tuple(), 0, 1460, 1024, 2048, 5_000, 5_000, 1_000_000)
}

fn prime_retrans(c: &mut TcpConn, seq: u32, len: u16) {
    // Integration-test builds don't have `cfg(test)` on the library, so
    // the crate-internal `Mbuf::null_for_test()` isn't visible. Use the
    // public `from_ptr(null)` spelling — the retrans entry is never
    // TX'd, just staged so `snd_retrans.is_empty()` reports `false`
    // for the arm-gate check.
    c.snd_retrans.push_after_tx(RetransEntry {
        seq,
        len,
        mbuf: Mbuf::from_ptr(std::ptr::null_mut()),
        first_tx_ts_ns: 0,
        xmit_count: 1,
        sacked: false,
        lost: false,
        xmit_ts_ns: 0,
    });
}

// ---- knob 1: event_queue_soft_cap ---------------------------------------

/// Knob: `EngineConfig::event_queue_soft_cap`.
/// Non-default value: 64 (minimum soft cap; default is 4096).
/// Observable consequence: pushing > cap events increments
/// `obs.events_dropped`; the default cap would absorb the same burst
/// without drops.
#[test]
fn knob_event_queue_soft_cap_overflow_drops_events() {
    let counters = Counters::new();
    let mut q = EventQueue::with_cap(64);
    for i in 0..200u64 {
        q.push(
            InternalEvent::Connected {
                conn: ConnHandle::default(),
                rx_hw_ts_ns: 0,
                emitted_ts_ns: i,
            },
            &counters,
        );
    }
    let dropped = counters.obs.events_dropped.load(Ordering::Relaxed);
    assert!(
        dropped > 0,
        "non-default soft_cap=64 should produce drops under a 200-event burst; got {dropped}"
    );
    let high_water = counters.obs.events_queue_high_water.load(Ordering::Relaxed);
    assert_eq!(
        high_water, 64,
        "high-water latches at soft_cap under overflow"
    );
}

// ---- knob 2: tlp_pto_min_floor_us ---------------------------------------

/// Knob: `TcpConn::tlp_pto_min_floor_us`.
/// Non-default value: 0 (no floor), reached at the ABI boundary via the
/// `u32::MAX` sentinel (see `TcpConn::tlp_config`). Default is the
/// engine-wide `tcp_min_rto_us` (5_000 µs).
/// Observable consequence: PTO is NOT clamped to 5_000 µs; it equals
/// the raw `2·SRTT` base for a SRTT small enough that the default would
/// have floored.
#[test]
fn knob_tlp_pto_min_floor_us_no_floor_allows_sub_min_rto_pto() {
    let cfg = TlpConfig {
        floor_us: 0,
        multiplier_x100: 200,
        skip_flight_size_gate: true,
    };
    // SRTT = 1 µs → base = 2 µs. Default floor 5_000 would clamp to
    // 5_000; non-default 0 lets PTO drop to 2.
    let result = pto_us(Some(1), &cfg, 5);
    assert_eq!(
        result, 2,
        "non-default floor=0 must not clamp PTO to default 5_000 µs"
    );
    // And cross-check that the DEFAULT floor would have clamped here.
    let default_cfg = TlpConfig::a5_compat(5_000);
    assert_eq!(
        pto_us(Some(1), &default_cfg, 5),
        5_000,
        "sanity: default floor 5_000 does clamp the same tiny SRTT"
    );
}

/// Verifies the `u32::MAX` sentinel projection path. The ABI accepts
/// `u32::MAX` to mean "explicit no floor"; `TcpConn::tlp_config`
/// projects that to `floor_us=0` in `TlpConfig`.
#[test]
fn knob_tlp_pto_min_floor_us_max_sentinel_projects_to_zero() {
    let mut c = make_conn();
    c.tlp_pto_min_floor_us = u32::MAX;
    c.tlp_pto_srtt_multiplier_x100 = 200;
    let cfg = c.tlp_config(5_000);
    assert_eq!(
        cfg.floor_us, 0,
        "u32::MAX sentinel must project to floor_us=0 in TlpConfig"
    );
}

// ---- knob 3: tlp_pto_srtt_multiplier_x100 -------------------------------

/// Knob: `TcpConn::tlp_pto_srtt_multiplier_x100`.
/// Non-default value: 100 (1.0×). Default is 200 (2.0× per RFC 8985
/// §7.2).
/// Observable consequence: PTO base = SRTT, not 2·SRTT.
#[test]
fn knob_tlp_pto_srtt_multiplier_x100_one_srtt() {
    let cfg = TlpConfig {
        floor_us: 0,
        multiplier_x100: 100,
        skip_flight_size_gate: true,
    };
    assert_eq!(
        pto_us(Some(100_000), &cfg, 5),
        100_000,
        "multiplier=100 must give base = 1·SRTT"
    );
    // Sanity: same SRTT at default multiplier gives 2·SRTT.
    let default_cfg = TlpConfig {
        floor_us: 0,
        multiplier_x100: 200,
        skip_flight_size_gate: true,
    };
    assert_eq!(
        pto_us(Some(100_000), &default_cfg, 5),
        200_000,
        "sanity: default multiplier=200 gives 2·SRTT"
    );
}

// ---- knob 4: tlp_skip_flight_size_gate ----------------------------------

/// Knob: `TcpConn::tlp_skip_flight_size_gate`.
/// Non-default value: `true`. Default is `false` (RFC 8985 §7.2: when
/// FlightSize=1, add `+max(WCDelAckT, SRTT/4)` penalty so a delayed-ACK
/// receiver can't silently swallow the sole in-flight segment's ACK
/// past the probe deadline).
/// Observable consequence: at FlightSize=1, PTO base is NOT increased
/// by the WCDelAckT/SRTT-4 penalty.
#[test]
fn knob_tlp_skip_flight_size_gate_suppresses_penalty() {
    let skip_cfg = TlpConfig {
        floor_us: 0,
        multiplier_x100: 200,
        skip_flight_size_gate: true,
    };
    let result_skip = pto_us(Some(400_000), &skip_cfg, 1);
    // base = 2·SRTT = 800_000; skip=true means no penalty.
    assert_eq!(
        result_skip, 800_000,
        "skip_flight_size_gate=true must suppress the FlightSize=1 penalty"
    );

    // Contrast with default gate on: +max(WCDELACK, SRTT/4) kicks in.
    let default_cfg = TlpConfig {
        floor_us: 0,
        multiplier_x100: 200,
        skip_flight_size_gate: false,
    };
    let result_default = pto_us(Some(400_000), &default_cfg, 1);
    // WCDELACK = 200_000; SRTT/4 = 100_000; penalty = 200_000 → 1_000_000.
    assert_eq!(
        result_default,
        800_000 + WCDELACK_US,
        "sanity: default gate on adds max(WCDelAckT, SRTT/4) penalty"
    );
    assert!(
        result_skip < result_default,
        "skip_flight_size_gate=true must yield a strictly smaller PTO than default"
    );
}

// ---- knob 5: tlp_max_consecutive_probes ---------------------------------

/// Knob: `TcpConn::tlp_max_consecutive_probes`.
/// Non-default value: 3. Default is 1 (RFC 8985 §7: a single probe
/// before falling back to RTO).
/// Observable consequence: `tlp_arm_gate_passes` accepts `fired < 3`
/// (0, 1, 2) and rejects at `fired >= 3`. The default max=1 would
/// reject at `fired >= 1`, so non-default expands the budget.
#[test]
fn knob_tlp_max_consecutive_probes_expands_budget() {
    // Construct a conn that passes every other gate so the only var
    // under test is the budget check.
    let mut c = make_conn();
    prime_retrans(&mut c, 1000, 512);
    c.tlp_max_consecutive_probes = 3;
    c.tlp_skip_rtt_sample_gate = false;
    c.tlp_rtt_sample_seen_since_last_tlp = true;
    c.rtt_est.sample(5_000); // SRTT required by Task 15 gate.

    // Budget check: gate must PASS at fired=0, 1, 2 and REJECT at 3.
    for fired in 0u8..3 {
        c.tlp_consecutive_probes_fired = fired;
        assert!(
            c.tlp_arm_gate_passes(),
            "non-default max=3: gate must pass at fired={fired}"
        );
    }
    c.tlp_consecutive_probes_fired = 3;
    assert!(
        !c.tlp_arm_gate_passes(),
        "non-default max=3: gate must reject at fired=3"
    );

    // Contrast: default max=1 would reject at fired=1 — confirming the
    // knob's observable effect.
    c.tlp_max_consecutive_probes = 1;
    c.tlp_consecutive_probes_fired = 1;
    assert!(
        !c.tlp_arm_gate_passes(),
        "sanity: default max=1 rejects at fired=1 (scope that the non-default expands)"
    );
}

// ---- knob 6: tlp_skip_rtt_sample_gate -----------------------------------

/// Knob: `TcpConn::tlp_skip_rtt_sample_gate`.
/// Non-default value: `true`. Default is `false` (RFC 8985 §7.4: a TLP
/// probe must not be armed without an intervening RTT sample since the
/// last probe — otherwise multiple TLPs can fire on a single stale
/// SRTT).
/// Observable consequence: gate passes even when
/// `tlp_rtt_sample_seen_since_last_tlp == false`. The default would
/// reject the same state.
#[test]
fn knob_tlp_skip_rtt_sample_gate_bypasses_sample_requirement() {
    let mut c = make_conn();
    prime_retrans(&mut c, 1000, 512);
    c.tlp_max_consecutive_probes = 3;
    c.tlp_consecutive_probes_fired = 0;
    c.tlp_rtt_sample_seen_since_last_tlp = false; // key non-default condition
    c.rtt_est.sample(5_000); // Task 15: SRTT must still be present.

    // With skip=true: gate passes despite sample not seen.
    c.tlp_skip_rtt_sample_gate = true;
    assert!(
        c.tlp_arm_gate_passes(),
        "skip_rtt_sample_gate=true must let gate pass without a sample seen"
    );

    // With skip=false (default): gate rejects the same state.
    c.tlp_skip_rtt_sample_gate = false;
    assert!(
        !c.tlp_arm_gate_passes(),
        "sanity: skip_rtt_sample_gate=false rejects without a sample seen"
    );
}

// ---- combination: aggressive_order_entry_preset -------------------------

/// Combination: aggressive-order-entry preset.
/// Non-default values (all five TLP knobs at once):
///   `tlp_pto_min_floor_us = u32::MAX` (→ floor 0 via sentinel)
///   `tlp_pto_srtt_multiplier_x100 = 100`
///   `tlp_skip_flight_size_gate = true`
///   `tlp_max_consecutive_probes = 3`
///   `tlp_skip_rtt_sample_gate = true`
/// Observable consequence: the combination collapses PTO to `1·SRTT`
/// even at FlightSize=1, allows up to 3 probes without intervening
/// RTT samples, and — contrasted against the defaults — the same SRTT
/// produces a strictly smaller PTO AND the arm gate accepts in a state
/// (fired=2, sample_seen=false, FlightSize=1) where the defaults would
/// reject.
#[test]
fn knob_aggressive_order_entry_preset_combined_behavior() {
    let mut c = make_conn();
    // Apply the full aggressive preset.
    c.tlp_pto_min_floor_us = u32::MAX;
    c.tlp_pto_srtt_multiplier_x100 = 100;
    c.tlp_skip_flight_size_gate = true;
    c.tlp_max_consecutive_probes = 3;
    c.tlp_skip_rtt_sample_gate = true;

    // ---- (A) PTO formula: 1·SRTT, no FlightSize=1 penalty, no floor.
    let cfg = c.tlp_config(5_000);
    assert_eq!(cfg.floor_us, 0);
    assert_eq!(cfg.multiplier_x100, 100);
    assert!(cfg.skip_flight_size_gate);
    let preset_pto = pto_us(Some(100_000), &cfg, 1);
    assert_eq!(
        preset_pto, 100_000,
        "preset must yield 1·SRTT PTO even at FlightSize=1"
    );
    // Same SRTT, defaults: 2·SRTT + max(WCDELACK, SRTT/4) + floored.
    let default_cfg = TlpConfig::a5_compat(5_000);
    let default_pto = pto_us(Some(100_000), &default_cfg, 1);
    // 200_000 + max(200_000, 25_000) = 400_000.
    assert_eq!(default_pto, 400_000);
    assert!(
        preset_pto < default_pto,
        "preset PTO must be strictly smaller than default PTO for identical inputs"
    );

    // ---- (B) Arm-gate combination: fired=2, sample NOT seen must pass.
    prime_retrans(&mut c, 1000, 512);
    c.tlp_consecutive_probes_fired = 2;
    c.tlp_rtt_sample_seen_since_last_tlp = false;
    c.rtt_est.sample(5_000); // SRTT present (Task 15 hard requirement).
    assert!(
        c.tlp_arm_gate_passes(),
        "preset must let a 3rd probe arm with no intervening RTT sample"
    );

    // Budget ceiling is still 3: fired=3 must reject.
    c.tlp_consecutive_probes_fired = 3;
    assert!(
        !c.tlp_arm_gate_passes(),
        "preset must still reject once the 3-probe budget is exhausted"
    );

    // ---- (C) Cross-check: same (fired=2, sample=false) state under
    // the defaults rejects (budget cap is 1; sample gate still on),
    // distinguishing the preset's observable effect.
    c.tlp_pto_min_floor_us = 5_000;
    c.tlp_pto_srtt_multiplier_x100 = 200;
    c.tlp_skip_flight_size_gate = false;
    c.tlp_max_consecutive_probes = 1;
    c.tlp_skip_rtt_sample_gate = false;
    c.tlp_consecutive_probes_fired = 2;
    c.tlp_rtt_sample_seen_since_last_tlp = false;
    assert!(
        !c.tlp_arm_gate_passes(),
        "sanity: defaults reject the same (fired=2, sample=false) state"
    );
}
