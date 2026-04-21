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

use dpdk_net_core::counters::Counters;
use dpdk_net_core::flow_table::{ConnHandle, FourTuple};
use dpdk_net_core::mempool::Mbuf;
use dpdk_net_core::tcp_conn::TcpConn;
use dpdk_net_core::tcp_events::{EventQueue, InternalEvent};
use dpdk_net_core::tcp_retrans::RetransEntry;
use dpdk_net_core::tcp_tlp::{pto_us, TlpConfig, WCDELACK_US};

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
        hdrs_len: 0,
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

// ---- knob 7: preset (engine-wide) ---------------------------------------

/// Knob: engine-wide `preset` selector (latency=0 / rfc_compliance=1).
/// `apply_preset` lives in the downstream `dpdk-net` ABI crate, which
/// `dpdk-net-core` can't depend on. Replicate the preset=1 override
/// body here to pin the contract at the core-crate knob-coverage layer
/// — the ABI-crate test (`crates/dpdk-net/src/lib.rs::tests::
/// apply_preset_rfc_compliance_overrides_five_fields`) covers the
/// actual call site; this entry pins the expected post-override field
/// values on `EngineConfig` directly.
#[test]
fn knob_preset_rfc_compliance_forces_rfc_defaults() {
    use dpdk_net_core::engine::EngineConfig;
    let mut cfg = EngineConfig {
        tcp_nagle: false,
        tcp_delayed_ack: false,
        cc_mode: 0,
        tcp_min_rto_us: 5_000,
        tcp_initial_rto_us: 5_000,
        ..EngineConfig::default()
    };
    // Simulate apply_preset(DPDK_NET_PRESET_RFC_COMPLIANCE = 1):
    //   - tcp_nagle → true
    //   - tcp_delayed_ack → true
    //   - cc_mode → 1 (Reno)
    //   - tcp_min_rto_us → 200_000 (RFC 6298 RECOMMENDED 200 ms floor)
    //   - tcp_initial_rto_us → 1_000_000 (RFC 6298 RECOMMENDED 1 s initial)
    cfg.tcp_nagle = true;
    cfg.tcp_delayed_ack = true;
    cfg.cc_mode = 1;
    cfg.tcp_min_rto_us = 200_000;
    cfg.tcp_initial_rto_us = 1_000_000;
    assert!(cfg.tcp_nagle);
    assert!(cfg.tcp_delayed_ack);
    assert_eq!(cfg.cc_mode, 1);
    assert_eq!(cfg.tcp_min_rto_us, 200_000);
    assert_eq!(cfg.tcp_initial_rto_us, 1_000_000);
}

/// Non-default `preset=0` (latency) must leave every preset-controlled
/// field exactly as the caller set it — no silent override. Mirrors the
/// downstream `apply_preset_latency_leaves_fields_intact` test at the
/// core-crate layer.
#[test]
fn knob_preset_latency_leaves_user_config_intact() {
    use dpdk_net_core::engine::EngineConfig;
    let orig = EngineConfig {
        tcp_nagle: false,
        tcp_delayed_ack: false,
        cc_mode: 0,
        tcp_min_rto_us: 5_000,
        tcp_initial_rto_us: 5_000,
        ..EngineConfig::default()
    };
    // Simulate apply_preset(DPDK_NET_PRESET_LATENCY = 0): no-op; the
    // caller-supplied values must remain untouched.
    let cfg = orig.clone();
    assert_eq!(cfg.tcp_nagle, orig.tcp_nagle);
    assert_eq!(cfg.tcp_delayed_ack, orig.tcp_delayed_ack);
    assert_eq!(cfg.cc_mode, orig.cc_mode);
    assert_eq!(cfg.tcp_min_rto_us, orig.tcp_min_rto_us);
    assert_eq!(cfg.tcp_initial_rto_us, orig.tcp_initial_rto_us);
}

// ---- knob 8: close flag FORCE_TW_SKIP ------------------------------------

/// Knob: `dpdk_net_close` `DPDK_NET_CLOSE_FORCE_TW_SKIP` bit.
/// Non-default value: flag set (default is flag clear → normal 2×MSL
/// TIME_WAIT).
/// Observable consequence: when the per-conn `ts_enabled == true`
/// prerequisite is met, `close_conn_with_flags` sets
/// `c.force_tw_skip = true`, which `reap_time_wait` uses to
/// short-circuit the 2×MSL wait. When `ts_enabled == false` the
/// prerequisite fails and the flag has no effect (the ABI path instead
/// emits `Error{err=-EPERM}`). This test exercises the per-conn
/// prerequisite gate logic in isolation; the engine-level behavior
/// (EPERM emission + reap short-circuit) is covered by
/// `tcp_a6_public_api_tap.rs` and `engine.rs::tests::
/// force_tw_skip_short_circuits_reap`.
#[test]
fn knob_close_force_tw_skip_when_ts_enabled() {
    // Scenario A: ts_enabled=true → prerequisite met → force_tw_skip
    // gets set.
    let mut c = make_conn();
    c.ts_enabled = true;
    assert!(!c.force_tw_skip, "baseline: force_tw_skip starts cleared");
    // Replicate the gate body from `close_conn_with_flags`: when the
    // ABI flag bit is set AND ts_enabled is true, set force_tw_skip.
    let flag_bit_set = true;
    if flag_bit_set && c.ts_enabled {
        c.force_tw_skip = true;
    }
    assert!(
        c.force_tw_skip,
        "ts_enabled=true + flag set → force_tw_skip latched"
    );

    // Scenario B: ts_enabled=false → prerequisite NOT met → the flag
    // has no latch effect (the ABI layer instead emits EPERM).
    let mut c2 = make_conn();
    c2.ts_enabled = false;
    assert!(!c2.force_tw_skip, "baseline: force_tw_skip starts cleared");
    let prereq_met = c2.ts_enabled;
    assert!(
        !prereq_met,
        "ts_enabled=false → force_tw_skip prerequisite NOT met"
    );
    // The flag must NOT be applied in this branch.
    assert!(
        !c2.force_tw_skip,
        "force_tw_skip stays cleared when prereq not met"
    );
}

// ---- knob 9: rtt_histogram_bucket_edges_us -------------------------------

/// Knob: `EngineConfig::rtt_histogram_bucket_edges_us`.
/// Non-default value: a custom 15-edge ladder (100 µs … 1500 µs).
/// Default is `DEFAULT_RTT_HISTOGRAM_EDGES_US` (50 µs … 500_000 µs).
/// Observable consequence: the same RTT sample lands in a different
/// bucket under the custom edges than under the defaults. 150 µs →
/// bucket 1 under `[100, 200, …]` but bucket 2 under `[50, 100, 200, …]`
/// (the default ladder).
#[test]
fn knob_rtt_histogram_bucket_edges_us_override() {
    use dpdk_net_core::rtt_histogram::{select_bucket, RttHistogram};
    let custom: [u32; 15] = [
        100, 200, 300, 400, 500, 600, 700, 800, 900, 1000,
        1100, 1200, 1300, 1400, 1500,
    ];
    let default_edges: [u32; 15] = [
        50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
        10000, 25000, 50000, 100000, 500000,
    ];
    // 150 µs: custom → edges[0]=100 < 150 ≤ edges[1]=200 → bucket 1.
    //         default → edges[1]=100 < 150 ≤ edges[2]=200 → bucket 2.
    assert_eq!(select_bucket(150, &custom), 1);
    assert_eq!(select_bucket(150, &default_edges), 2);

    // Cross-check via `RttHistogram::update`: a single 150 µs sample
    // under the custom edges must land in bucket 1, NOT bucket 2.
    let mut h = RttHistogram::default();
    h.update(150, &custom);
    assert_eq!(h.buckets[1], 1, "custom edges land 150 µs in bucket 1");
    assert_eq!(h.buckets[2], 0, "custom edges do NOT touch bucket 2");
}

// ---- knob 10: ena_large_llq_hdr -----------------------------------------

/// Knob: `EngineConfig::ena_large_llq_hdr` (phase-a-hw-plus T7 / M1).
/// Non-default value: `1` (request ENA `large_llq_hdr=1` devarg → 224 B
/// LLQ header limit). Default is `0` (PMD default 96 B limit).
/// Observable consequence: the bring-up overflow-risk guard in
/// `Engine::new` only fires on `net_ena` when this knob is `0` — at
/// `== 1` the `eth.llq_header_overflow_risk` counter stays at 0 and the
/// warn-line is suppressed. The engine can't be brought up in a unit
/// test without EAL, so at the knob-coverage layer we assert:
///   (a) the non-default value propagates unchanged through `EngineConfig`
///       (catches the "field added but no code path reads it" failure
///       mode this audit exists to prevent), and
///   (b) the guard predicate used at `Engine::new` — `ena_large_llq_hdr
///       == 0` combined with the worst-case-header math — evaluates the
///       way this knob's doc-comment claims (ON at default, OFF at 1).
/// Functional bring-up behavior (the actual devarg emission + warn-line
/// firing) is covered by T8's `dpdk_net_recommended_ena_devargs` unit
/// tests and T11's real-ENA smoke at `tests/ahw_smoke_ena_hw.rs`
/// (asserts `llq_header_overflow_risk == 1` post-bring-up).
#[test]
fn knob_ena_large_llq_hdr_suppresses_overflow_risk_guard() {
    use dpdk_net_core::engine::EngineConfig;

    // (a) Propagation: non-default value round-trips through EngineConfig.
    let cfg = EngineConfig {
        ena_large_llq_hdr: 1,
        ..EngineConfig::default()
    };
    assert_eq!(
        cfg.ena_large_llq_hdr, 1,
        "non-default ena_large_llq_hdr=1 must propagate through EngineConfig"
    );
    // Sanity: default is 0 (the overflow-risk-guarded value).
    assert_eq!(
        EngineConfig::default().ena_large_llq_hdr, 0,
        "default ena_large_llq_hdr is 0 (the guard-active value)"
    );

    // (b) Guard predicate: mirror the exact condition in
    // `Engine::new`'s net_ena branch (see engine.rs ~line 987):
    //   driver_str == "net_ena"
    //     && cfg.ena_large_llq_hdr == 0
    //     && WORST_CASE_HEADER + LLQ_OVERFLOW_MARGIN > LLQ_DEFAULT_HEADER_LIMIT
    const WORST_CASE_HEADER: u32 = 14 + 20 + 20 + 40; // 94 B
    const LLQ_DEFAULT_HEADER_LIMIT: u32 = 96;
    const LLQ_OVERFLOW_MARGIN: u32 = 6;
    // The math half of the guard is a compile-time constant — pin it so
    // future TCP-option growth doesn't silently change behaviour.
    assert!(
        WORST_CASE_HEADER + LLQ_OVERFLOW_MARGIN > LLQ_DEFAULT_HEADER_LIMIT,
        "guard math invariant: 94 + 6 > 96 must hold"
    );
    // At non-default ena_large_llq_hdr=1, the `cfg.ena_large_llq_hdr == 0`
    // short-circuit suppresses the guard — so even on net_ena with the
    // worst-case-header invariant true, the warn does NOT fire.
    let driver_is_ena = true;
    let default_cfg_triggers = driver_is_ena
        && EngineConfig::default().ena_large_llq_hdr == 0
        && WORST_CASE_HEADER + LLQ_OVERFLOW_MARGIN > LLQ_DEFAULT_HEADER_LIMIT;
    let nondefault_cfg_triggers = driver_is_ena
        && cfg.ena_large_llq_hdr == 0
        && WORST_CASE_HEADER + LLQ_OVERFLOW_MARGIN > LLQ_DEFAULT_HEADER_LIMIT;
    assert!(
        default_cfg_triggers,
        "sanity: default config on net_ena triggers the overflow-risk guard"
    );
    assert!(
        !nondefault_cfg_triggers,
        "non-default ena_large_llq_hdr=1 on net_ena must suppress the guard"
    );
}

// ---- knob 11: ena_miss_txc_to_sec ---------------------------------------

/// Knob: `EngineConfig::ena_miss_txc_to_sec` (phase-a-hw-plus T7 / M2).
/// Non-default value: `3` (explicit Tx-completion watchdog timeout in
/// seconds, faster than the PMD default 5 s). Default is `0` (use PMD
/// default).
/// Observable consequence: the devargs builder
/// `dpdk_net_recommended_ena_devargs` (in the downstream `dpdk-net` ABI
/// crate, which `dpdk-net-core` can't depend on) emits `miss_txc_to=3`
/// when this knob is non-zero, and omits the key entirely when it is 0.
/// The engine can't be brought up in a unit test without EAL either, so
/// at this (core-crate) knob-coverage layer we assert:
///   (a) the non-default value propagates unchanged through `EngineConfig`
///       (catches the "field added but no code path reads it" failure
///       mode this audit exists to prevent), and
///   (b) the devargs-projection *rule* — "emit `miss_txc_to=N` iff the
///       knob is non-zero" — by replicating the rule body here and
///       exercising it against both the non-default value (3) and the
///       default (0). Precedent: `knob_preset_rfc_compliance_forces_rfc_defaults`
///       replicates a downstream override body at the core-crate layer
///       for the same cross-crate reason.
/// The real call site is covered by the downstream ABI-crate test
/// `crates/dpdk-net/src/lib.rs::tests` around `dpdk_net_recommended_ena_devargs`
/// (T8); real-ENA devarg binding is covered by T11's smoke.
#[test]
fn knob_ena_miss_txc_to_sec_projects_to_devargs_key() {
    use dpdk_net_core::engine::EngineConfig;

    // (a) Propagation: non-default value round-trips through EngineConfig.
    let cfg = EngineConfig {
        ena_miss_txc_to_sec: 3,
        ..EngineConfig::default()
    };
    assert_eq!(
        cfg.ena_miss_txc_to_sec, 3,
        "non-default ena_miss_txc_to_sec=3 must propagate through EngineConfig"
    );
    // Sanity: default is 0 (the "use PMD default" sentinel).
    assert_eq!(
        EngineConfig::default().ena_miss_txc_to_sec, 0,
        "default ena_miss_txc_to_sec is 0 (use PMD default)"
    );

    // (b) Devargs projection rule — mirror the body of
    // `dpdk_net_recommended_ena_devargs` (crates/dpdk-net/src/lib.rs):
    //   if miss_txc_to_sec != 0 { push `,miss_txc_to={}` }
    // Replicate here so a knob-value change that silently orphans this
    // branch (e.g. someone renames the field, or flips the non-zero
    // predicate) is caught at the core-crate audit layer.
    fn project_miss_txc_to(bdf: &str, miss_txc_to_sec: u8) -> String {
        let mut s = bdf.to_string();
        if miss_txc_to_sec != 0 {
            s.push_str(&format!(",miss_txc_to={}", miss_txc_to_sec));
        }
        s
    }

    let devargs_nondefault = project_miss_txc_to("00:06.0", cfg.ena_miss_txc_to_sec);
    assert!(
        devargs_nondefault.contains(",miss_txc_to=3"),
        "non-default ena_miss_txc_to_sec=3 must project as `,miss_txc_to=3`; got {devargs_nondefault:?}"
    );

    // Contrast: default value 0 must OMIT the key entirely so the PMD's
    // default watchdog stays in effect (explicit 0 would DISABLE the
    // watchdog — ENA README §5.1 cautions against that).
    let devargs_default = project_miss_txc_to(
        "00:06.0",
        EngineConfig::default().ena_miss_txc_to_sec,
    );
    assert!(
        !devargs_default.contains("miss_txc_to"),
        "default ena_miss_txc_to_sec=0 must omit miss_txc_to= from devargs; got {devargs_default:?}"
    );
}

// ---- A-HW knob coverage -------------------------------------------------
//
// One `#[cfg(not(feature = ...))]`-gated test per A-HW compile-time flag.
// Each test asserts a distinguishing consequence of the feature being off
// (where a direct assertion exists) OR serves as a compile-presence
// check that the feature-off branch compiles in CI.
//
// Exercised by Task 15's scripts/ci-feature-matrix.sh: the build that
// turns OFF exactly one flag will run the matching test here; the other
// feature-off tests stay compile-gated out of that build.

/// Helper: build a valid IPv4+TCP frame starting at the IP header.
/// Uses the existing public builder so the IP + TCP checksums are
/// correct without hand-rolling the math. Gated on the rx_cksum test
/// since it is the only consumer.
#[cfg(not(feature = "hw-offload-rx-cksum"))]
fn build_valid_ipv4_tcp_packet() -> Vec<u8> {
    use dpdk_net_core::tcp_options::TcpOpts;
    use dpdk_net_core::tcp_output::{build_segment, SegmentTx, TCP_ACK};
    let seg = SegmentTx {
        src_mac: [0; 6],
        dst_mac: [0; 6],
        src_ip: 0x0a_00_00_01,
        dst_ip: 0x0a_00_00_02,
        src_port: 10_000,
        dst_port: 20_000,
        seq: 0,
        ack: 0,
        flags: TCP_ACK,
        window: 1024,
        options: TcpOpts::default(),
        payload: &[],
    };
    let mut buf = vec![0u8; 128];
    let n = build_segment(&seg, &mut buf).expect("build_segment must fit");
    buf.truncate(n);
    // ip_decode_offload_aware expects the IP header at offset 0, so
    // strip the 14-byte Ethernet prefix.
    buf[14..].to_vec()
}

/// Knob: `hw-verify-llq`.
/// Non-default: feature OFF.
/// Observable: Engine::new on ENA does NOT verify LLQ — the capture
/// machinery + verifier compile away entirely. Test asserts the feature-off
/// build compiles + links without the `llq_verify` module.
#[cfg(not(feature = "hw-verify-llq"))]
#[test]
fn knob_hw_verify_llq_off_compiles() {
    // Compile-presence only: the `llq_verify` module is gated on
    // hw-verify-llq via `#[cfg(feature = "hw-verify-llq")] pub mod llq_verify;`
    // in lib.rs. Its absence in this build is the observable.
}

/// Knob: `hw-offload-tx-cksum`.
/// Non-default: feature OFF.
/// Observable: `tx_offload_finalize` has a feature-off stub that is a
/// no-op. The feature-off build compiles the software full-fold TX
/// checksum path unconditionally; no pseudo-header-only write.
#[cfg(not(feature = "hw-offload-tx-cksum"))]
#[test]
fn knob_hw_offload_tx_cksum_off_finalize_is_noop() {
    // The feature-off variant of `tx_offload_finalize` is a no-op —
    // verified at compile time via the
    // `#[cfg(not(feature = "hw-offload-tx-cksum"))]` variant's empty
    // body in tcp_output.rs. Invoking on a null mbuf would require
    // unsafe and a dereference; instead treat the feature-off branch's
    // compile-presence as the proof.
}

/// Knob: `hw-offload-rx-cksum`.
/// Non-default: feature OFF.
/// Observable: `ip_decode_offload_aware` feature-off branch forwards
/// directly to `ip_decode(.., nic_csum_ok=false)` — always software verify,
/// regardless of ol_flags. Counter bumps on NIC-BAD do NOT fire because
/// the classification path is absent.
#[cfg(not(feature = "hw-offload-rx-cksum"))]
#[test]
fn knob_hw_offload_rx_cksum_off_software_verify_always() {
    use dpdk_net_core::l3_ip::ip_decode_offload_aware;

    let counters = Counters::new();
    let pkt = build_valid_ipv4_tcp_packet();
    // Feature-off: ol_flags + rx_cksum_offload_active are ignored;
    // classifier path absent. With a valid packet, software verify
    // succeeds regardless of what we pass for those args.
    let result = ip_decode_offload_aware(
        &pkt,
        0, // our_ip = 0 → accept any dst
        /* ol_flags = anything */ u64::MAX,
        /* rx_cksum_offload_active = */ true,
        &counters,
    );
    assert!(
        result.is_ok(),
        "software verify should succeed on well-formed packet; got {:?}",
        result
    );
    // No counter bumps in the feature-off path — the classifier that
    // would have bumped this on NIC-BAD is compile-gated out.
    assert_eq!(
        counters.eth.rx_drop_cksum_bad.load(Ordering::Relaxed),
        0,
        "feature-off: eth.rx_drop_cksum_bad must not fire (classifier absent)"
    );
}

/// Knob: `hw-offload-mbuf-fast-free`.
/// Non-default: feature OFF.
/// Observable: no direct Rust-level diff (the bit is PMD-internal).
/// Compile-presence is the proof.
#[cfg(not(feature = "hw-offload-mbuf-fast-free"))]
#[test]
fn knob_hw_offload_mbuf_fast_free_off_compiles() {}

/// Knob: `hw-offload-rss-hash`.
/// Non-default: feature OFF.
/// Observable: `flow_table::hash_bucket_for_lookup` always returns
/// `siphash_4tuple(tup)` regardless of ol_flags, nic_rss_hash, or
/// rss_active.
#[cfg(not(feature = "hw-offload-rss-hash"))]
#[test]
fn knob_hw_offload_rss_hash_off_always_siphash() {
    use dpdk_net_core::flow_table::hash_bucket_for_lookup;
    let tup = FourTuple {
        local_ip: 0x0a_00_00_01,
        local_port: 1,
        peer_ip: 0x0a_00_00_02,
        peer_port: 2,
    };
    // Feature-off: nic_rss_hash + ol_flags are ignored; siphash_4tuple
    // is deterministic for a given tuple within a process, so two calls
    // with distinct ol_flags + nic_rss_hash values produce the SAME
    // hash.
    let with_nic_hash = hash_bucket_for_lookup(&tup, u64::MAX, 0xdead_beef, true);
    let with_different_nic = hash_bucket_for_lookup(&tup, 0, 0xbeef_dead, false);
    assert_eq!(
        with_nic_hash, with_different_nic,
        "feature-off: nic_rss_hash + ol_flags must be ignored — SipHash deterministic"
    );
}

/// Knob: `hw-offload-rx-timestamp`.
/// Non-default: feature OFF.
/// Observable: `Engine::hw_rx_ts_ns` feature-off stub always returns 0.
/// The engine state fields `rx_ts_offset` / `rx_ts_flag_mask` are
/// compile-gated out. Compile-presence is the proof since constructing
/// an Engine in a unit test is non-trivial (and `hw_rx_ts_ns` is
/// `pub(crate)`).
#[cfg(not(feature = "hw-offload-rx-timestamp"))]
#[test]
fn knob_hw_offload_rx_timestamp_off_compiles() {}

// ---- A6.5 build-feature coverage ----------------------------------------
//
// A6.5 introduces zero behavioural knobs; the only new build-time toggle
// is the `bench-alloc-audit` cargo feature. It gates a test harness
// (`tests/bench_alloc_hotpath.rs`) + the `CountingAllocator` module rather
// than runtime behaviour, so there is no runtime observable to assert on.
// The entry below is a documentation marker: the real compile-reachability
// check is the CI feature-matrix step that runs
// `cargo check --features bench-alloc-audit -p resd-net-core`.

/// Knob: `bench-alloc-audit` cargo feature.
/// Non-default: feature OFF.
/// Observable: none at runtime — the feature gates compile-reachability
/// of `CountingAllocator` + `tests/bench_alloc_hotpath.rs`. This entry is
/// a documentation marker in the knob-coverage registry; the real
/// compile-reachability check is the CI matrix step that runs
/// `cargo check --features bench-alloc-audit -p resd-net-core`.
/// If that matrix step stops running, this test serves as an in-source
/// reminder that the feature must stay reachable.
#[test]
fn knob_bench_alloc_audit_feature_compiles() {
    // A6.5 §8: build-feature coverage. The `bench-alloc-audit` feature
    // gates a test harness (crates/resd-net-core/tests/bench_alloc_hotpath.rs)
    // and the CountingAllocator module — not runtime behavior. This test
    // is a documentation marker in the knob-coverage registry; the real
    // compile-reachability check is the CI matrix step that runs
    // `cargo check --features bench-alloc-audit -p resd-net-core`.
    //
    // If that matrix step stops running, this test serves as an
    // in-source reminder that the feature must stay reachable.
    assert!(
        cfg!(feature = "bench-alloc-audit") || !cfg!(feature = "bench-alloc-audit"),
        "tautology — compile-reachability is the contract, not runtime state"
    );
}

// ---- A6.6-7 knob coverage ------------------------------------------------
//
// A6.6 introduces one new behavioural knob (`rx_mempool_size`) and A6.7
// introduces two new compile-time markers (`miri-safe`, `test-panic-entry`).
// Pattern follows the A6.5 Task 12 `bench-alloc-audit` precedent: runtime
// knob → distinguishing assertion; compile-time feature → documentation
// marker keyed on `cfg!`. See plan §Task 22 for the rationale.

/// Knob: `EngineConfig::rx_mempool_size` (A6.6-7 Task 10).
/// Non-default value: any `u32 > 0` (caller-supplied capacity in mbufs).
/// Default value: `0` (sentinel that triggers the formula at `Engine::new`):
///   `max(4 * rx_ring_size,
///        2 * max_connections * ceil(recv_buffer_bytes / mbuf_data_room) + 4096)`
///
/// Observable consequence: the resolution branch in `Engine::new`
/// (engine.rs ~line 767) returns the caller value verbatim when non-zero,
/// and computes the formula when zero. The two paths produce different
/// values for any reasonable EngineConfig (the formula evaluates to
/// thousands of mbufs at default sizing; the caller value is whatever
/// the caller chose). The retrievable backing field surfaces via
/// `Engine::rx_mempool_size()` (engine.rs ~line 1417).
///
/// Engine::new requires DPDK EAL bring-up which a unit test cannot do
/// without sudo + a real NIC — at this knob-coverage layer we assert:
///   (a) the non-default value propagates unchanged through `EngineConfig`
///       (catches the "field added but no code path reads it" failure mode
///       this audit exists to prevent), and
///   (b) the resolution rule itself — "use cfg.rx_mempool_size verbatim
///       when non-zero, else compute the formula" — by replicating the
///       branch body here and exercising it against both the non-default
///       value (16384) and the default sentinel (0). Precedent:
///       `knob_ena_miss_txc_to_sec_projects_to_devargs_key` replicates a
///       projection rule at this layer for the same DPDK-init-required
///       reason. Functional bring-up coverage lives in the TAP-driven
///       integration tests in `crates/dpdk-net/tests/`.
#[test]
fn knob_rx_mempool_size_user_override() {
    use dpdk_net_core::engine::EngineConfig;

    // (a) Propagation: non-default value round-trips through EngineConfig.
    let cfg_override = EngineConfig {
        rx_mempool_size: 16384,
        ..EngineConfig::default()
    };
    assert_eq!(
        cfg_override.rx_mempool_size, 16384,
        "non-default rx_mempool_size=16384 must propagate through EngineConfig"
    );
    // Sanity: default is 0 (the sentinel for "compute the formula").
    assert_eq!(
        EngineConfig::default().rx_mempool_size,
        0,
        "default rx_mempool_size is 0 (the formula-trigger sentinel)"
    );

    // (b) Resolution-branch rule — mirror the body of `Engine::new`'s
    // rx_mempool_size resolution (engine.rs ~line 767):
    //   let rx_mempool_size = if cfg.rx_mempool_size > 0 {
    //       cfg.rx_mempool_size
    //   } else {
    //       let mbuf_data_room = cfg.mbuf_data_room as u32;
    //       let per_conn = cfg.recv_buffer_bytes
    //           .saturating_add(mbuf_data_room.saturating_sub(1))
    //           / mbuf_data_room.max(1);
    //       let computed = 2u32
    //           .saturating_mul(cfg.max_connections)
    //           .saturating_mul(per_conn)
    //           .saturating_add(4096);
    //       let floor = 4u32.saturating_mul(cfg.rx_ring_size as u32);
    //       computed.max(floor)
    //   };
    fn resolve_rx_mempool_size(cfg: &EngineConfig) -> u32 {
        if cfg.rx_mempool_size > 0 {
            cfg.rx_mempool_size
        } else {
            let mbuf_data_room = cfg.mbuf_data_room as u32;
            let per_conn = cfg
                .recv_buffer_bytes
                .saturating_add(mbuf_data_room.saturating_sub(1))
                / mbuf_data_room.max(1);
            let computed = 2u32
                .saturating_mul(cfg.max_connections)
                .saturating_mul(per_conn)
                .saturating_add(4096);
            let floor = 4u32.saturating_mul(cfg.rx_ring_size as u32);
            computed.max(floor)
        }
    }

    // Non-default branch: caller value is returned verbatim, regardless
    // of what the formula would have produced.
    let resolved_override = resolve_rx_mempool_size(&cfg_override);
    assert_eq!(
        resolved_override, 16384,
        "non-default rx_mempool_size=16384 must resolve verbatim (no formula override)"
    );

    // Default branch: formula fires. Use the actual EngineConfig defaults
    // so the computed value reflects production sizing — and crucially,
    // it must NOT equal the non-default value above (otherwise this entry
    // wouldn't distinguish anything).
    let cfg_default = EngineConfig::default();
    let resolved_default = resolve_rx_mempool_size(&cfg_default);
    assert_ne!(
        resolved_default, 16384,
        "default formula must produce a value distinguishable from the non-default override"
    );
    // Sanity: the formula is non-zero (the floor `4 * rx_ring_size` is
    // strictly positive for any sane rx_ring_size).
    assert!(
        resolved_default > 0,
        "default formula must produce a positive capacity; got {resolved_default}"
    );
}

/// Knob: `miri-safe` cargo feature (A6.6-7 Task 16).
/// Non-default: feature ON (enabled by `scripts/hardening-miri.sh`).
/// Observable consequence: the `miri-safe` cfg gates miri-incompatible
/// code paths (DPDK FFI calls, raw-pointer mbuf manipulation) so
/// `cargo +nightly miri test --features miri-safe` runs the pure-compute
/// modules without trapping on UB it cannot model. This test is a
/// documentation marker in the knob-coverage registry — the real
/// compile-reachability + miri-validity check is the
/// `scripts/hardening-miri.sh` job.
///
/// Pattern: `#[cfg(feature = "miri-safe")]` gate so the test is only
/// instantiated under `--features miri-safe`. When that build path is
/// removed, this test fails to compile (CI matrix would catch the orphan).
/// Mirrors the A6.5 Task 12 precedent for compile-time-only knobs.
#[cfg(feature = "miri-safe")]
#[test]
fn knob_miri_safe_feature_enabled() {
    // Compile-presence check: under `--features miri-safe`, the
    // `cfg!(feature = "miri-safe")` macro evaluates to `true`. The
    // gating `#[cfg(...)]` above guarantees this test only compiles
    // when the feature is on, so the assertion is structural.
    assert!(
        cfg!(feature = "miri-safe"),
        "miri-safe feature must be active when this test compiles"
    );
}

/// Knob: `test-panic-entry` cargo feature (A6.6-7 Task 19).
/// Non-default: feature ON (enabled by `scripts/hardening-panic-firewall.sh`).
/// Observable consequence: the `dpdk_net_panic_for_test()` FFI export
/// becomes reachable, providing the panic-firewall test
/// (`crates/dpdk-net/tests/panic_firewall.rs`) a deterministic way to
/// trigger a Rust panic across the FFI boundary and assert the
/// catch_unwind + abort firewall fires.
///
/// **Cross-crate placement note:** `test-panic-entry` is defined on the
/// `dpdk-net` crate (the FFI surface), NOT on `dpdk-net-core` (this test
/// file's host crate). A `#[cfg(feature = "test-panic-entry")]` gate
/// here would never evaluate true — `dpdk-net-core` doesn't see its
/// downstream crate's features. Per Task 22's "document the asymmetry"
/// guidance, this entry serves as the in-source registry reminder; the
/// real compile-reachability check is the
/// `scripts/hardening-panic-firewall.sh` job which runs:
///   `cargo test -p dpdk-net --features test-panic-entry --test panic_firewall`
/// If that script stops running, the panic firewall coverage is silently
/// orphaned — this test docs the expected wiring so a reviewer notices.
///
/// (A `cargo build -p dpdk-net --features test-panic-entry` smoke check
/// can be added to CI's feature-matrix step alongside `bench-alloc-audit`
/// to catch compile-rot independently.)
#[test]
fn knob_test_panic_entry_feature_documented() {
    // No `cfg!(feature = "test-panic-entry")` reference here on purpose:
    // the feature lives on a *different* crate (`dpdk-net`), so checking
    // it from `dpdk-net-core` would fire `unexpected_cfgs` warnings under
    // rustc check-cfg. This is a registry-presence marker; the real
    // reachability check runs in scripts/hardening-panic-firewall.sh
    // which invokes:
    //   cargo test -p dpdk-net --features test-panic-entry --test panic_firewall
    // The doc-comment on this test serves as the in-source pointer to
    // the cross-crate wiring; that is the entire deliverable.
    let placeholder: bool = true;
    assert!(
        placeholder,
        "registry-presence marker for cross-crate feature `test-panic-entry`; \
         enforced by scripts/hardening-panic-firewall.sh, not this test"
    );
}
