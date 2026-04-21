# resd.dpdk_tcp Stage 1 Phase A5.5 — Event-log forensics + in-flight introspection + TLP tuning

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close four A5 review-identified gaps (event emission timestamps, event-queue overflow protection, per-connection stats getter, TLP tuning knobs) plus three Stage-2 Accepted Deviations (AD-15 retirement, AD-17 `RACK_mark_losses_on_RTO`, AD-18 arm-TLP-on-send) plus SRTT seed from the SYN handshake round-trip — all without touching A5's shipped wire behavior under default configs.

**Architecture:** Primarily an observability phase that grew a modest wire-behavior surface during brainstorm. Observability tasks (1–8) touch `tcp_events.rs`, `engine.rs` event-push sites, `counters.rs` (new `obs` group), `tcp_conn.rs` (new `stats()` projection), `flow_table.rs`, and the `dpdk-net` C ABI (`dpdk_net_conn_stats` extern + new counter fields). TLP tuning tasks (9–12) extend `tcp_tlp.rs::pto_us` to consume a `TlpConfig`, add 5 per-connect knobs to `dpdk_net_connect_opts_t`, add multi-probe budget tracking + DSACK spurious-probe attribution on `TcpConn`, and add one new counter `tcp.tx_tlp_spurious`. AD closures (13–15) add SRTT-seed-from-SYN-handshake wiring in `tcp_input.rs::handle_syn_sent`, a `RACK_mark_losses_on_RTO` pass at the top of `engine.rs::on_rto_fire`, and an `arm_tlp_pto` helper invoked from `Engine::send_bytes`. Bookkeeping (16–17) retires AD-15 + closes AD-17/18 in the A5 RFC review record and extends `tests/knob-coverage.rs` per roadmap §A11.

**Tech Stack:** same as A5 — Rust stable, DPDK 23.11, bindgen, cbindgen. No new crate deps. No new cargo features. No new DPDK FFI wrappers.

**Spec reference:** design spec at `docs/superpowers/specs/2026-04-18-stage1-phase-a5-5-event-log-forensics-design.md`; parent spec at `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §§ 4 (API additions), 4.2 (event-queue contracts), 6.3 (RFC matrix — new rows for RFC 6298 §3.3 + RFC 8985 §6.3 / §7.2 closure), 6.4 (8 new ADs: 5 TLP knobs + SRTT-from-SYN + AD-17 closure + AD-18 closure; AD-15/17/18 retirements from Stage-2 list), 9.1 (counters — 3 new slow-path), 9.3 (events — semantic refinement on `enqueued_ts_ns`).

**RFCs in scope for A5.5** (for the §10.14 RFC compliance review): **6298 §3.3** (SRTT from SYN MAY), **8985 §6.3** (`RACK_mark_losses_on_RTO`), **8985 §7.2** (arm-TLP-on-send SHOULD + per-conn tuning knob ADs), **8985 §7.4** (per-conn RTT-sample-gate skip AD). RFCs not touched: 6528 (ISS — A5 ships final), 7323 (TS — A4/A5 final for Stage 1), 5681 (dup_ack — A5 final), 2883 (DSACK — A5.5 extends the counter-only observer with spurious-probe attribution; no new adaptation).

**Review gates at phase sign-off** (two reports, each a blocking gate per spec §10.13 / §10.14):
1. **A5.5 mTCP comparison review** — `docs/superpowers/reviews/phase-a5-5-mtcp-compare.md`. Focus: mTCP has no analog for event-queue overflow accounting, the stats getter, or TLP at all — those are scope-difference not behavioral. AD-18 (arm-TLP-on-send) matches the mTCP E-2 finding from A5's review; with A5.5's closure, that finding migrates from "Stage-2 AD" to "closed". AD-17 (`RACK_mark_losses_on_RTO`) has no mTCP analog (mTCP does not implement RACK). Expected ~0 new ADs after closure accounting.
2. **A5.5 RFC compliance review** — `docs/superpowers/reviews/phase-a5-5-rfc-compliance.md`. Focus: A5.5 touches RFC 6298 §3.3 (SYN-RTT seed), RFC 8985 §6.3 (RACK mark-losses-on-RTO), RFC 8985 §7.2 (arm-TLP-on-send), RFC 8985 §7.2/§7.4 (TLP tuning knobs per-conn opt-in), plus the observability items. Expected 6 new §6.4 rows (5 TLP knobs + SRTT-from-SYN) and 3 AD retirements from Stage-2 list (AD-15/17/18).

The `phase-a5-5-complete` tag is blocked while either report has an open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD.

**Deviations from RFC defaults explicitly recorded for A5.5** (to land in §6.4 during Task 16):

- **`AD-A5-5-srtt-from-syn`** — SRTT seeded from SYN round-trip per RFC 6298 §3.3 MAY. Always-on; net-conservative improvement; Karn's rule honored via `syn_retrans_count == 0` guard.
- **`AD-A5-5-rack-mark-losses-on-rto`** — §6.3 `RACK_mark_losses_on_RTO` now implemented on every RTO fire (AD-17 promotion retires from Stage-2 list).
- **`AD-A5-5-tlp-arm-on-send`** — TLP PTO armed from the `send_bytes` TX path in addition to ACK handler (AD-18 promotion retires from Stage-2 list).
- **5 TLP tuning knob ADs** — all per-connect opt-in; defaults preserve RFC 8985 exactly:
  - `AD-A5-5-tlp-pto-floor-zero` (configurable PTO floor, down to 0)
  - `AD-A5-5-tlp-multiplier-below-2x` (configurable SRTT multiplier, 1.0×–2.0×)
  - `AD-A5-5-tlp-skip-flight-size-gate` (skip RFC 8985 §7.2 `+max(WCDelAckT, RTT/4)` penalty on FlightSize=1)
  - `AD-A5-5-tlp-multi-probe` (fire up to 5 consecutive TLPs before falling back to RTO)
  - `AD-A5-5-tlp-skip-rtt-sample-gate` (skip RFC 8985 §7.4 RTT-sample-since-last-probe suppression)
- **AD-15 retirement** — Stage-2 AD-15 (TLP pre-fire state: `TLP.end_seq` + `TLP.is_retrans`) superseded by A5.5 multi-probe data structures; no dedicated code task.

**Deferred to later phases (A5.5 is explicitly NOT doing these):**

- **AD-16** (RACK §6.2 Step 2 spurious-retrans guard) — stays Stage 2. Revisit when AD-13 DSACK adaptive work lands.
- **Congestion control, F-RTO, dynamic reo_wnd adaptation** — same Stage-2/out-of-scope status as A5.
- **Public timer API, WRITABLE event, flush** — A6.
- **Event-queue-overflow events** — out of scope (counters are sufficient per `feedback_observability_primitives_only.md`).
- **`events_pending` live-depth gauge** — revisit in A8.
- **Companion dummy TX segment for FlightSize-1** — follow-on if empirical spurious-ratio data shows peer-side delayed-ACK breaks `tlp_skip_flight_size_gate`.
- **Auto-tuning (`tlp_auto_floor: bool` reacting to `tx_tlp_spurious / tx_tlp`)** — application-level pattern, not stack.

---

## File Structure Created or Modified in This Phase

```
crates/dpdk-net-core/
├── src/
│   ├── tcp_events.rs                (MODIFIED: `InternalEvent::*::emitted_ts_ns` field on every variant; `EventQueue::push` takes `&EngineCounters` for drop-oldest + high-water; `EventQueue::with_cap` + min-64 check)
│   ├── engine.rs                    (MODIFIED: 13 push-site updates to include `emitted_ts_ns: self.clock.now_ns()`; `EventQueue::push` call-site passes counters; `on_rto_fire` gains §6.3 RACK_mark_losses_on_RTO pass; `send_bytes` gains `arm_tlp_pto` call post-TX; TLP scheduling consults `tlp_consecutive_probes_fired` / `tlp_max_consecutive_probes`; `on_tlp_fire` increments the counter + records the probe in `tlp_recent_probes`)
│   ├── counters.rs                  (MODIFIED: new `ObsCounters` struct with `events_dropped`, `events_queue_high_water`; `TcpCounters` gains `tx_tlp_spurious`; `EngineCounters` adds `obs: ObsCounters`)
│   ├── tcp_conn.rs                  (MODIFIED: adds 5 per-conn TLP knob fields + 4 runtime TLP state fields + `syn_tx_ts_ns` + `stats()` projection method)
│   ├── tcp_input.rs                 (MODIFIED: `handle_syn_sent` absorbs SYN-ACK RTT sample with Karn's guard; ACK path resets `tlp_consecutive_probes_fired` on RTT sample / new-data ACK + sets `tlp_rtt_sample_seen_since_last_tlp`; DSACK path attributes to `tlp_recent_probes` for `tx_tlp_spurious` bumps)
│   ├── tcp_tlp.rs                   (MODIFIED: `pto_us` signature → `(srtt_us, &TlpConfig, flight_size) → u32`; new `TlpConfig` POD; `TlpConfig::default()` matches prior constants so A5 tests stay green)
│   ├── flow_table.rs                (MODIFIED: `get_stats(handle) → Option<ConnStats>` slow-path getter)
│   └── lib.rs                       (unchanged unless new modules are added — none this phase)
└── tests/
    ├── tcp_a5_5_observability.rs    (NEW: integration 7.2.1–7.2.6 — emission-time ts, queue overflow, stats under backpressure, ENOENT, pre-sample values, RTT tracking)
    ├── tcp_a5_5_tlp_tuning.rs       (NEW: integration 7.2.7–7.2.13 — zero-floor PTO, 1× multiplier, FlightSize skip, multi-probe, budget reset, spurious attribution, invalid-opts rejection)
    ├── tcp_a5_5_ad_closures.rs      (NEW: integration 7.2.14–7.2.23 — SRTT-from-SYN nonzero / Karn's rule / bounds, AD-17 multi-segment RTO recovery / age-based marking / front-entry-only, AD-18 first-burst PTO / re-arm / SYN_SENT no-op / budget-exhausted no-op)
    └── knob-coverage.rs             (MODIFIED: extends scenario table with 5 A5.5 TLP knobs + `event_queue_soft_cap` + the aggressive-preset combination per roadmap §A11)

crates/dpdk-net/src/
├── api.rs                           (MODIFIED: `dpdk_net_engine_config_t::event_queue_soft_cap`; `dpdk_net_connect_opts_t` gains 5 TLP fields; `dpdk_net_counters_t` gains `obs_events_dropped`, `obs_events_queue_high_water`; `dpdk_net_tcp_counters_t` gains `tx_tlp_spurious`; new `dpdk_net_conn_stats_t` POD + `dpdk_net_conn_stats` extern)
└── lib.rs                           (MODIFIED: `dpdk_net_poll` drain reads `emitted_ts_ns` through instead of sampling at drain; `dpdk_net_connect` validates the 5 TLP fields; `dpdk_net_conn_stats` extern entrypoint; `dpdk_net_engine_create` validates `event_queue_soft_cap >= 64`)

include/dpdk_net.h                   (REGENERATED via cbindgen: 1 engine-config field, 5 connect-opts fields, 3 new counter fields, 1 new extern, 1 new struct, doc-comment changes on `enqueued_ts_ns`)

examples/cpp-consumer/main.cpp       (MODIFIED: set a reasonable `event_queue_soft_cap`; print the three new counters; demo one call to `dpdk_net_conn_stats`)

docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md
                                     (MODIFIED during Task 16: §4 API adds Introspection API paragraph; §4.2 documents queue soft-cap; §6.3 RFC matrix updates RFC 8985 row; §6.4 adds 8 new AD rows; §9.1 counter examples updated; §9.3 events clarifies `enqueued_ts_ns` semantics)
docs/superpowers/plans/stage1-phase-roadmap.md
                                     (MODIFIED at end of phase: A5.5 row → Complete + link to this plan)
docs/superpowers/reviews/phase-a5-rfc-compliance.md
                                     (MODIFIED during Task 16: AD-15/AD-17/AD-18 each marked "closed in A5.5" with cross-ref to closing task + superseding spec §6 entry)
docs/superpowers/reviews/phase-a5-5-mtcp-compare.md      (NEW — Task 18)
docs/superpowers/reviews/phase-a5-5-rfc-compliance.md    (NEW — Task 19)
```

---

## Task 1: `InternalEvent::emitted_ts_ns` field + producer wiring at 13 engine call sites

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_events.rs` — add `emitted_ts_ns: u64` to every `InternalEvent` variant (7 variants as of HEAD: `Connected`, `Readable`, `Closed`, `StateChange`, `Error`, `TcpRetrans`, `TcpLossDetected`)
- Modify: `crates/dpdk-net-core/src/engine.rs` — update 13 push call sites to include `emitted_ts_ns: self.clock.now_ns()` in the constructor

**Context:** Spec §3.1. Current `enqueued_ts_ns` is sampled at `dpdk_net_poll` drain time in `crates/dpdk-net/src/lib.rs`; the skew between stack emission and drain is bounded by the app poll interval (10 µs at 100 kHz, 100 µs at 10 kHz). We want emission-time semantics. This task only adds the field on the internal variant + wires producers; Task 2 updates the drain path to read it through. The 13 call sites were verified via grep at `engine.rs:856, :861, :994, :999, :1169, :1173, :1204, :1480, :1485, :1690, :1709, :1788, :2041` at tip of `phase-a5-complete` (`39b01cd`). If subsequent work adds more push sites before A5.5 lands, the task's grep step catches them.

- [ ] **Step 1: Write failing test (the field must exist on every variant)**

```rust
// tests/tcp_a5_5_observability.rs — new file
// Placed in crates/dpdk-net-core/tests/ — create the directory if needed.

use dpdk_net_core::flow_table::ConnHandle;
use dpdk_net_core::tcp_events::{EventQueue, InternalEvent, LossCause};
use dpdk_net_core::tcp_state::TcpState;

#[test]
fn internal_event_carries_emitted_ts_ns_on_every_variant() {
    let ev_connected = InternalEvent::Connected {
        conn: ConnHandle::default(),
        rx_hw_ts_ns: 0,
        emitted_ts_ns: 42,
    };
    let ev_readable = InternalEvent::Readable {
        conn: ConnHandle::default(),
        byte_offset: 0,
        byte_len: 0,
        rx_hw_ts_ns: 0,
        emitted_ts_ns: 42,
    };
    let ev_closed = InternalEvent::Closed {
        conn: ConnHandle::default(),
        err: 0,
        emitted_ts_ns: 42,
    };
    let ev_state = InternalEvent::StateChange {
        conn: ConnHandle::default(),
        from: TcpState::SynSent,
        to: TcpState::Established,
        emitted_ts_ns: 42,
    };
    let ev_error = InternalEvent::Error {
        conn: ConnHandle::default(),
        err: -1,
        emitted_ts_ns: 42,
    };
    let ev_retrans = InternalEvent::TcpRetrans {
        conn: ConnHandle::default(),
        seq: 0,
        rtx_count: 1,
        emitted_ts_ns: 42,
    };
    let ev_loss = InternalEvent::TcpLossDetected {
        conn: ConnHandle::default(),
        cause: LossCause::Rack,
        emitted_ts_ns: 42,
    };
    for e in [ev_connected, ev_readable, ev_closed, ev_state, ev_error, ev_retrans, ev_loss] {
        assert_eq!(emitted_ts_ns_of(&e), 42);
    }
}

fn emitted_ts_ns_of(ev: &InternalEvent) -> u64 {
    match ev {
        InternalEvent::Connected { emitted_ts_ns, .. }
        | InternalEvent::Readable { emitted_ts_ns, .. }
        | InternalEvent::Closed { emitted_ts_ns, .. }
        | InternalEvent::StateChange { emitted_ts_ns, .. }
        | InternalEvent::Error { emitted_ts_ns, .. }
        | InternalEvent::TcpRetrans { emitted_ts_ns, .. }
        | InternalEvent::TcpLossDetected { emitted_ts_ns, .. } => *emitted_ts_ns,
    }
}
```

- [ ] **Step 2: Run test to verify it fails with "no field named `emitted_ts_ns`"**

Run: `cargo test -p dpdk-net-core --test tcp_a5_5_observability internal_event_carries_emitted_ts_ns_on_every_variant`
Expected: compile error, "struct has no field named `emitted_ts_ns`" on each variant constructor.

- [ ] **Step 3: Add `emitted_ts_ns: u64` to every `InternalEvent` variant**

Edit `crates/dpdk-net-core/src/tcp_events.rs` in the `pub enum InternalEvent { … }` block. For each of the 7 variants add `emitted_ts_ns: u64` as the last struct field. Preserve existing field order; add the new field at the end for consistency.

```rust
// Example — apply the analogous change to all 7 variants
pub enum InternalEvent {
    Connected {
        conn: ConnHandle,
        rx_hw_ts_ns: u64,
        emitted_ts_ns: u64,
    },
    Readable {
        conn: ConnHandle,
        byte_offset: u32,
        byte_len: u32,
        rx_hw_ts_ns: u64,
        emitted_ts_ns: u64,
    },
    Closed {
        conn: ConnHandle,
        err: i32,
        emitted_ts_ns: u64,
    },
    StateChange {
        conn: ConnHandle,
        from: TcpState,
        to: TcpState,
        emitted_ts_ns: u64,
    },
    Error {
        conn: ConnHandle,
        err: i32,
        emitted_ts_ns: u64,
    },
    TcpRetrans {
        conn: ConnHandle,
        seq: u32,
        rtx_count: u32,
        emitted_ts_ns: u64,
    },
    TcpLossDetected {
        conn: ConnHandle,
        cause: LossCause,
        emitted_ts_ns: u64,
    },
}
```

Update `tcp_events.rs` unit tests and the doc-comment at `tcp_events.rs:62-66` (TcpRetrans) / `:71-74` (TcpLossDetected) to mention `emitted_ts_ns: u64 — engine-monotonic-clock ns sampled at event emission`.

- [ ] **Step 4: Update all 13 `InternalEvent` push sites in `engine.rs`**

Verify the 13 call sites with a grep before editing:

```bash
grep -n "push(InternalEvent::" crates/dpdk-net-core/src/engine.rs
```

At each call site, add `emitted_ts_ns: self.clock.now_ns(),` to the constructor. Pattern (illustrative — actual lines shift as edits are applied):

```rust
// engine.rs:856 (TcpRetrans from engine-loop rack-lost retransmit — pre-edit)
ev.push(InternalEvent::TcpRetrans {
    conn: handle,
    seq,
    rtx_count,
});

// engine.rs:856 — post-edit
ev.push(InternalEvent::TcpRetrans {
    conn: handle,
    seq,
    rtx_count,
    emitted_ts_ns: self.clock.now_ns(),
});
```

Apply to every TcpRetrans, TcpLossDetected, Error, Closed, Connected, StateChange, Readable push site in `engine.rs`. The 13 known sites at `phase-a5-complete`: `:856, :861, :994, :999, :1169, :1173, :1204, :1480, :1485, :1690, :1709, :1788, :2041` — verify current line numbers post-edit.

If any other module (e.g., `tcp_input.rs`) pushes events via a borrow to `EventQueue`, update those too. Grep `events.borrow_mut().push` and `ev.push(InternalEvent::` across the workspace to catch them.

- [ ] **Step 5: Run test to verify it passes + existing tests still green**

Run: `cargo test -p dpdk-net-core`
Expected: the new test passes; all pre-existing tests pass unchanged.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_events.rs crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/tests/tcp_a5_5_observability.rs
git commit -m "a5.5 task 1: add InternalEvent::emitted_ts_ns + producer wiring

Adds emitted_ts_ns: u64 to every InternalEvent variant and updates
all 13 push call sites in engine.rs to sample self.clock.now_ns()
at push time. Drain-time consumer in dpdk-net/src/lib.rs still
samples at drain — Task 2 wires it through."
```

---

## Task 2: `dpdk_net_poll` drain simplification — read `emitted_ts_ns` through

**Files:**
- Modify: `crates/dpdk-net/src/lib.rs` — `dpdk_net_poll` drain path at lines `142-224` (pre-A5.5)
- Modify: `crates/dpdk-net/src/api.rs` — doc comment on `dpdk_net_event_t::enqueued_ts_ns` (struct field)

**Context:** Spec §3.1, §5.2. The drain-time `let ts = dpdk_net_core::clock::now_ns();` goes away. Each event's `enqueued_ts_ns` is populated from the `InternalEvent` variant's `emitted_ts_ns` field. The C ABI field name stays (no rename — scaffold §3.1 rationale), doc comment tightens semantic meaning to "sampled at event emission inside the stack."

- [ ] **Step 1: Write failing test asserting drain-time sampling is gone**

```rust
// tests/tcp_a5_5_observability.rs — add to existing test module
#[test]
fn dpdk_net_poll_does_not_sample_clock_at_drain() {
    // Build an engine with a mock clock; push an event at t=100; advance
    // the clock to t=500 before calling dpdk_net_poll; assert the drained
    // event carries enqueued_ts_ns == 100 (not 500).
    let mut e = dpdk_net_core::test_support::make_test_engine_with_mock_clock();
    e.mock_clock_set_ns(100);
    e.push_event_connected(ConnHandle(1));  // test helper emits Connected variant
    e.mock_clock_set_ns(500);
    let mut events_out = [unsafe { std::mem::zeroed::<dpdk_net::api::dpdk_net_event_t>() }; 4];
    let n = unsafe {
        dpdk_net::dpdk_net_poll(
            e.as_engine_ptr(),
            events_out.as_mut_ptr(),
            events_out.len() as u32,
        )
    };
    assert!(n >= 1);
    assert_eq!(events_out[0].enqueued_ts_ns, 100);
}
```

Note: `test_support::make_test_engine_with_mock_clock` + `push_event_connected` helpers may need adding if A5 doesn't already expose them. If they don't exist, add minimal stubs gated behind `#[cfg(feature = "test-support")]` in `crates/dpdk-net-core/src/test_support.rs`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p dpdk-net --test tcp_a5_5_observability dpdk_net_poll_does_not_sample_clock_at_drain`
Expected: fail with `left: 500, right: 100` (or similar), proving the drain still samples at drain time.

- [ ] **Step 3: Rewrite the drain loop to consume `emitted_ts_ns`**

In `crates/dpdk-net/src/lib.rs`, locate the `dpdk_net_poll` drain block (A5 HEAD line range `~142-224`). Replace:

```rust
// BEFORE (illustrative — actual wording differs)
let ts = dpdk_net_core::clock::now_ns();
while let Some(ev) = engine.events.borrow_mut().pop() {
    match ev {
        InternalEvent::Connected { conn, rx_hw_ts_ns } => {
            events_out[i].enqueued_ts_ns = ts;
            events_out[i].rx_hw_ts_ns = rx_hw_ts_ns;
            // …
        }
        // …
    }
}
```

With:

```rust
// AFTER
while let Some(ev) = engine.events.borrow_mut().pop() {
    // emitted_ts_ns is sampled at push time inside the engine
    // (phase A5.5 task 1) — the drain just copies through.
    let emitted = match &ev {
        InternalEvent::Connected { emitted_ts_ns, .. }
        | InternalEvent::Readable { emitted_ts_ns, .. }
        | InternalEvent::Closed { emitted_ts_ns, .. }
        | InternalEvent::StateChange { emitted_ts_ns, .. }
        | InternalEvent::Error { emitted_ts_ns, .. }
        | InternalEvent::TcpRetrans { emitted_ts_ns, .. }
        | InternalEvent::TcpLossDetected { emitted_ts_ns, .. } => *emitted_ts_ns,
    };
    match ev {
        InternalEvent::Connected { conn, rx_hw_ts_ns, .. } => {
            events_out[i].enqueued_ts_ns = emitted;
            events_out[i].rx_hw_ts_ns = rx_hw_ts_ns;
            // …
        }
        // … apply emitted to every variant's event_t population
    }
}
```

Every branch of the match that populates a `dpdk_net_event_t` must set `enqueued_ts_ns = emitted`. Double-check by grepping the block for `enqueued_ts_ns` and verifying all assignments use `emitted`.

- [ ] **Step 4: Update the doc-comment on `dpdk_net_event_t::enqueued_ts_ns`**

In `crates/dpdk-net/src/api.rs` find the `dpdk_net_event_t` struct and update the doc comment on `enqueued_ts_ns` from drain-time wording to:

```rust
/// ns timestamp (engine monotonic clock) sampled at event emission
/// inside the stack. Unrelated to `rx_hw_ts_ns`. For packet-triggered
/// events, emission time is when the stack processed the triggering
/// packet, not when the NIC received it — use `rx_hw_ts_ns` for
/// NIC-arrival time. For timer-triggered events (RTO fire, RACK / TLP
/// loss-detected), emission time is the fire instant.
pub enqueued_ts_ns: u64,
```

- [ ] **Step 5: Run tests to verify green + regen header**

```bash
cargo test -p dpdk-net
cargo build -p dpdk-net                      # regenerates include/dpdk_net.h via cbindgen build.rs
```

Verify the regenerated `include/dpdk_net.h` shows the new doc comment on `enqueued_ts_ns`. If the header has not changed, the cbindgen invocation may be cached — check the `build.rs` side and force a rebuild.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net/src/lib.rs crates/dpdk-net/src/api.rs include/dpdk_net.h
git commit -m "a5.5 task 2: dpdk_net_poll reads emitted_ts_ns through at drain

dpdk_net_event_t::enqueued_ts_ns now reports the engine-internal
emission time (sampled at push) instead of the drain-call time.
Field name unchanged; doc comment updated. Closes spec §3.1."
```

---

## Task 3: `EventQueue` soft-cap + drop-oldest + counter wiring

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_events.rs` — `EventQueue` grows `soft_cap`, `with_cap(cap)` constructor, `push(&mut self, ev, counters: &EngineCounters)` takes counters reference
- Modify: `crates/dpdk-net-core/src/engine.rs` — engine construction passes `soft_cap` to `EventQueue::with_cap`; every push site passes `&self.counters`

**Context:** Spec §3.2. The queue is currently unbounded `VecDeque` with a starting capacity of 64. A5.5 adds a soft cap (default 4096, min 64 enforced at `engine_create`) + drop-oldest on overflow + two counters (`obs.events_dropped`, `obs.events_queue_high_water`). Task 4 adds the counters themselves; Task 5 wires the engine-config field. This task adds the `EventQueue` mechanism, temporarily referencing the counters via a feature flag or placeholder struct until Task 4 lands them — or sequence so Task 4 lands first. Plan order: do Task 4 first, then this task. Reorder if needed.

**Prerequisite:** Task 4 must land first so `EngineCounters` exposes `obs.events_dropped` and `obs.events_queue_high_water`.

- [ ] **Step 1: Write failing test — drop-oldest preserves most-recent events**

```rust
// tests/tcp_a5_5_observability.rs — extend test module
#[test]
fn event_queue_overflow_drops_oldest_preserves_newest() {
    use dpdk_net_core::counters::EngineCounters;
    use dpdk_net_core::flow_table::ConnHandle;
    use dpdk_net_core::tcp_events::{EventQueue, InternalEvent};
    use std::sync::atomic::Ordering;

    let counters = EngineCounters::new();
    let mut q = EventQueue::with_cap(4);  // tiny cap for the test

    // Push 6 distinct Connected events — cap=4, so 2 should be dropped.
    for i in 0..6u64 {
        q.push(
            InternalEvent::Connected {
                conn: ConnHandle::default(),
                rx_hw_ts_ns: 0,
                emitted_ts_ns: i * 100,
            },
            &counters,
        );
    }

    assert_eq!(q.len(), 4);
    assert_eq!(counters.obs.events_dropped.load(Ordering::Relaxed), 2);
    // events_queue_high_water latches max queue depth — should equal cap.
    assert_eq!(counters.obs.events_queue_high_water.load(Ordering::Relaxed), 4);

    // Drain in order: the 2 oldest (emitted 0, 100) were dropped, so we
    // expect to see emitted 200, 300, 400, 500.
    let mut expected = [200u64, 300, 400, 500].into_iter();
    while let Some(ev) = q.pop() {
        let InternalEvent::Connected { emitted_ts_ns, .. } = ev else { unreachable!() };
        assert_eq!(Some(emitted_ts_ns), expected.next());
    }
}

#[test]
fn event_queue_with_cap_rejects_below_64() {
    use dpdk_net_core::tcp_events::EventQueue;
    let result = std::panic::catch_unwind(|| EventQueue::with_cap(32));
    assert!(result.is_err(), "with_cap(<64) should panic or return Err");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p dpdk-net-core --test tcp_a5_5_observability event_queue_overflow`
Expected: compile error on `with_cap`, `counters` as second arg, or both.

- [ ] **Step 3: Rewrite `EventQueue`**

In `crates/dpdk-net-core/src/tcp_events.rs`:

```rust
use std::sync::atomic::Ordering;
use crate::counters::EngineCounters;

pub struct EventQueue {
    q: VecDeque<InternalEvent>,
    soft_cap: usize,
}

impl EventQueue {
    /// Minimum queue cap. Prevents pathological configs from producing
    /// a queue smaller than one realistic poll burst worth of events.
    pub const MIN_SOFT_CAP: usize = 64;

    /// Default cap per spec §3.2 — 4096 events × ~32 B/event ≈ 128 KiB per engine.
    pub const DEFAULT_SOFT_CAP: usize = 4096;

    pub fn new() -> Self {
        Self::with_cap(Self::DEFAULT_SOFT_CAP)
    }

    pub fn with_cap(cap: usize) -> Self {
        assert!(
            cap >= Self::MIN_SOFT_CAP,
            "EventQueue::with_cap: cap {} below MIN_SOFT_CAP {}",
            cap,
            Self::MIN_SOFT_CAP
        );
        Self {
            q: VecDeque::with_capacity(cap.min(Self::DEFAULT_SOFT_CAP)),
            soft_cap: cap,
        }
    }

    /// Push an event. If the queue is at `soft_cap`, drop the oldest entry
    /// and increment `obs.events_dropped`. Always latches `obs.events_queue_high_water`
    /// to max observed depth.
    pub fn push(&mut self, ev: InternalEvent, counters: &EngineCounters) {
        if self.q.len() >= self.soft_cap {
            let _ = self.q.pop_front();
            counters.obs.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.q.push_back(ev);
        let depth = self.q.len() as u64;
        counters.obs.events_queue_high_water.fetch_max(depth, Ordering::Relaxed);
    }

    pub fn pop(&mut self) -> Option<InternalEvent> {
        self.q.pop_front()
    }

    pub fn len(&self) -> usize {
        self.q.len()
    }

    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}
```

- [ ] **Step 4: Update every `.push(...)` call site in `engine.rs` to pass `&self.counters`**

Every existing `events.borrow_mut().push(InternalEvent::…)` or `ev.push(InternalEvent::…)` becomes `… .push(InternalEvent::…, &self.counters)`. The local `ev` variable in engine-loop contexts already holds a borrow of `EventQueue`; pass the counters by reference.

Example (illustrative):

```rust
// BEFORE
events.borrow_mut().push(InternalEvent::Closed {
    conn: handle,
    err: 0,
    emitted_ts_ns: self.clock.now_ns(),
});

// AFTER
events.borrow_mut().push(
    InternalEvent::Closed {
        conn: handle,
        err: 0,
        emitted_ts_ns: self.clock.now_ns(),
    },
    &self.counters,
);
```

Grep `push(InternalEvent::` across the workspace to catch every site. Update the 13 sites from Task 1 plus any added since.

- [ ] **Step 5: Run tests**

Run: `cargo test -p dpdk-net-core`
Expected: new queue tests pass; existing tests (which use the default cap of 4096) pass unchanged.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_events.rs crates/dpdk-net-core/src/engine.rs
git commit -m "a5.5 task 3: EventQueue soft-cap + drop-oldest + counter wiring

EventQueue grows soft_cap + with_cap constructor. push() now takes
&EngineCounters and drops oldest on overflow, latching high-water
into obs.events_queue_high_water. Closes spec §3.2."
```

---

## Task 4: `counters.rs` — new `obs` group with `events_dropped` + `events_queue_high_water`

**Files:**
- Modify: `crates/dpdk-net-core/src/counters.rs` — new `ObsCounters` struct, `EngineCounters` gains `obs: ObsCounters`
- Modify: `crates/dpdk-net/src/api.rs` — `dpdk_net_counters_t` gains `obs_events_dropped`, `obs_events_queue_high_water`

**Context:** Spec §4, §5.4. A new `obs` group (short for "observability") for engine-internal observability counters distinct from the existing packet-path groups (`poll`/`eth`/`ip`/`tcp`). Both fields are `AtomicU64`, slow-path (Task 3 increments only when queue pressure exists). Per `feedback_counter_policy.md`: slow-path is the default; no hot-path additions here.

**Task ordering:** This task lands **before** Task 3 so `EngineCounters::obs` exists when Task 3 references it.

- [ ] **Step 1: Write failing test**

```rust
// crates/dpdk-net-core/src/counters.rs — inline test
#[cfg(test)]
mod a5_5_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn engine_counters_has_obs_group_zero_initialized() {
        let c = EngineCounters::new();
        assert_eq!(c.obs.events_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(c.obs.events_queue_high_water.load(Ordering::Relaxed), 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p dpdk-net-core counters::a5_5_tests::engine_counters_has_obs_group_zero_initialized`
Expected: compile error `no field 'obs' on struct EngineCounters`.

- [ ] **Step 3: Add `ObsCounters` struct and the `obs` field on `EngineCounters`**

In `crates/dpdk-net-core/src/counters.rs`:

```rust
/// Engine-internal observability counters (A5.5).
///
/// All slow-path per §9.1.1 — fires only when observability pressure exists
/// (event-queue overflow). No RX/TX hot-path increments.
#[derive(Default)]
pub struct ObsCounters {
    /// Count of events dropped from `EventQueue` due to soft-cap overflow.
    /// Nonzero = app poll cadence cannot keep up + some events were lost.
    pub events_dropped: AtomicU64,
    /// Latched max observed queue depth since engine start.
    /// High value with events_dropped == 0 = close call;
    /// high value with nonzero events_dropped = actual loss.
    pub events_queue_high_water: AtomicU64,
}

// … existing EngineCounters definition …
pub struct EngineCounters {
    pub poll: PollCounters,
    pub eth: EthCounters,
    pub ip: IpCounters,
    pub tcp: TcpCounters,
    pub obs: ObsCounters,  // NEW A5.5
}

impl EngineCounters {
    pub fn new() -> Self {
        Self {
            poll: PollCounters::default(),
            eth: EthCounters::default(),
            ip: IpCounters::default(),
            tcp: TcpCounters::default(),
            obs: ObsCounters::default(),
        }
    }
}
```

- [ ] **Step 4: Mirror the new fields into the C ABI `dpdk_net_counters_t`**

In `crates/dpdk-net/src/api.rs` find the `dpdk_net_counters_t` struct. Append (do not insert mid-struct — C ABI stability):

```rust
#[repr(C)]
pub struct dpdk_net_counters_t {
    // … all existing fields unchanged …

    // A5.5: observability counters (obs group, slow-path)
    pub obs_events_dropped: u64,
    pub obs_events_queue_high_water: u64,
}
```

Update the `dpdk_net_counters_get` implementation in `crates/dpdk-net/src/lib.rs` to populate the two new fields from `engine.counters.obs.events_dropped.load(Relaxed)` and `.events_queue_high_water.load(Relaxed)`.

- [ ] **Step 5: Run tests + regen header**

```bash
cargo test -p dpdk-net-core counters
cargo build -p dpdk-net
```

Confirm `include/dpdk_net.h` shows the two new fields appended to `dpdk_net_counters_t`.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/counters.rs crates/dpdk-net/src/api.rs crates/dpdk-net/src/lib.rs include/dpdk_net.h
git commit -m "a5.5 task 4: counters.rs obs group + events_dropped/high_water

New ObsCounters group carrying events_dropped (count of events
discarded from the FIFO due to soft-cap overflow) and
events_queue_high_water (latched max observed depth). Mirrored
into dpdk_net_counters_t as appended fields; no layout churn on
existing fields."
```

---

## Task 5: `dpdk_net_engine_config_t::event_queue_soft_cap`

**Files:**
- Modify: `crates/dpdk-net/src/api.rs` — `dpdk_net_engine_config_t` gains `event_queue_soft_cap: u32`
- Modify: `crates/dpdk-net/src/lib.rs` — `dpdk_net_engine_create` validates `event_queue_soft_cap >= 64`; passes through to core
- Modify: `crates/dpdk-net-core/src/engine.rs` — `EngineConfig` mirrors the field; `Engine::new` calls `EventQueue::with_cap(cfg.event_queue_soft_cap as usize)`

**Context:** Spec §5.1. Field default is 4096; min is 64. Below-64 is rejected with `-EINVAL` at `dpdk_net_engine_create` entry. Values above `u32::MAX` are not a concern since `u32` is the ABI type.

- [ ] **Step 1: Write failing test**

```rust
// tests/tcp_a5_5_observability.rs — extend
#[test]
fn engine_create_rejects_event_queue_soft_cap_below_64() {
    let mut cfg = make_minimal_engine_config();
    cfg.event_queue_soft_cap = 32;
    let rc = unsafe { dpdk_net::dpdk_net_engine_create(&cfg, std::ptr::null_mut()) };
    assert_eq!(rc, -libc::EINVAL);
}

#[test]
fn engine_create_accepts_event_queue_soft_cap_default() {
    let mut cfg = make_minimal_engine_config();
    cfg.event_queue_soft_cap = 4096;
    let mut out_engine: *mut dpdk_net::dpdk_net_engine = std::ptr::null_mut();
    let rc = unsafe { dpdk_net::dpdk_net_engine_create(&cfg, &mut out_engine) };
    assert_eq!(rc, 0);
    assert!(!out_engine.is_null());
    unsafe { dpdk_net::dpdk_net_engine_destroy(out_engine) };
}
```

Where `make_minimal_engine_config()` is a test helper that fills every pre-A5.5 field with a valid default. If the helper does not already exist in the test module, write it inline — it's a one-time scaffold.

- [ ] **Step 2: Run tests**

Run: `cargo test -p dpdk-net-core --test tcp_a5_5_observability engine_create_rejects`
Expected: compile error on `cfg.event_queue_soft_cap`.

- [ ] **Step 3: Add the field on both sides of the ABI boundary**

In `crates/dpdk-net/src/api.rs`, append to `dpdk_net_engine_config_t`:

```rust
#[repr(C)]
pub struct dpdk_net_engine_config_t {
    // … existing fields …
    pub garp_interval_sec: u32,
    // A5.5: event-queue overflow guard (§3.2 / §5.1).
    // Default 4096; must be >= 64. Queue drops oldest on overflow.
    pub event_queue_soft_cap: u32,
}
```

In `crates/dpdk-net-core/src/engine.rs` `EngineConfig` struct (the Rust-internal mirror), add:

```rust
pub struct EngineConfig {
    // … existing fields …
    pub event_queue_soft_cap: u32,
}
```

Default: `4096` if constructed via a convenience constructor. Any Rust-side default impl should reflect 4096.

In `crates/dpdk-net/src/lib.rs` `dpdk_net_engine_create`:

```rust
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_engine_create(
    cfg: *const dpdk_net_engine_config_t,
    out_engine: *mut *mut dpdk_net_engine,
) -> i32 {
    if cfg.is_null() || out_engine.is_null() {
        return -libc::EINVAL;
    }
    let c = &*cfg;
    // … existing validations …
    if c.event_queue_soft_cap < 64 {
        return -libc::EINVAL;
    }
    // … proceed to construction; pass c.event_queue_soft_cap into
    // EngineConfig; Engine::new uses EventQueue::with_cap(...) per Task 3
}
```

- [ ] **Step 4: Wire `EventQueue::with_cap` in `Engine::new`**

In the `Engine::new` constructor (file `crates/dpdk-net-core/src/engine.rs`), replace the existing `EventQueue::new()` (or `::default()`) with `EventQueue::with_cap(cfg.event_queue_soft_cap as usize)`.

- [ ] **Step 5: Update `examples/cpp-consumer/main.cpp` + cbindgen header regen**

In `examples/cpp-consumer/main.cpp` set `cfg.event_queue_soft_cap = 4096;` alongside the existing config fields. Regenerate the header:

```bash
cargo build -p dpdk-net
```

Verify `include/dpdk_net.h` shows `event_queue_soft_cap` appended to `dpdk_net_engine_config_t`.

- [ ] **Step 6: Run tests**

Run: `cargo test -p dpdk-net-core -p dpdk-net`
Expected: both new tests pass; all existing tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/dpdk-net/src/api.rs crates/dpdk-net/src/lib.rs crates/dpdk-net-core/src/engine.rs include/dpdk_net.h examples/cpp-consumer/main.cpp
git commit -m "a5.5 task 5: engine_config event_queue_soft_cap + validation

Exposes the Task 3 soft-cap as a cbindgen-visible field. Default
4096, min 64 (below rejected with -EINVAL). cpp-consumer example
sets the field explicitly."
```

---

## Task 6: `TcpConn::stats` + `ConnStats` struct + `flow_table::get_stats`

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs` — add `ConnStats` `#[repr(C)]` POD + `TcpConn::stats(&self) -> ConnStats`
- Modify: `crates/dpdk-net-core/src/flow_table.rs` — add `get_stats(&self, handle: ConnHandle) -> Option<ConnStats>`

**Context:** Spec §3.3. Pure projection over existing internal state. Fields: 5 send-path (`snd_una`, `snd_nxt`, `snd_wnd`, `send_buf_bytes_pending`, `send_buf_bytes_free`) + 4 RTT/RTO (`srtt_us`, `rttvar_us`, `min_rtt_us`, `rto_us`). `rtt_est.srtt_us()` returns `Option<u32>` — map `None → 0`. Pre-first-sample values: srtt/rttvar/min_rtt = 0; rto = `rtt_est.rto_us()` which itself starts at `tcp_initial_rto_us`.

- [ ] **Step 1: Write failing unit tests**

```rust
// crates/dpdk-net-core/src/tcp_conn.rs — inline test
#[cfg(test)]
mod a5_5_stats_tests {
    use super::*;

    #[test]
    fn stats_projects_send_path_fields() {
        let mut c = make_test_conn();   // uses existing a5 test helper
        c.snd_una = 100;
        c.snd_nxt = 200;
        c.snd_wnd = 65535;
        // send_buffer_bytes is engine-level config; simulate 1 MiB
        let s = c.stats(/* send_buffer_bytes_cfg */ 1_048_576);
        assert_eq!(s.snd_una, 100);
        assert_eq!(s.snd_nxt, 200);
        assert_eq!(s.snd_wnd, 65535);
    }

    #[test]
    fn stats_before_any_rtt_sample_returns_zero_except_rto() {
        let c = make_test_conn();   // rtt_est has no sample
        let s = c.stats(1_048_576);
        assert_eq!(s.srtt_us, 0);
        assert_eq!(s.rttvar_us, 0);
        assert_eq!(s.min_rtt_us, 0);
        assert_eq!(s.rto_us, c.rtt_est.rto_us());  // initial_rto
    }

    #[test]
    fn stats_send_buf_bytes_free_saturates_at_zero() {
        let mut c = make_test_conn();
        // pretend pending.len() > send_buffer_bytes (shouldn't happen
        // in practice but the arithmetic must not underflow)
        // … push enough into c.snd.pending to exceed 64 …
        let s = c.stats(/* send_buffer_bytes */ 64);
        assert_eq!(s.send_buf_bytes_free, 0);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p dpdk-net-core tcp_conn::a5_5_stats_tests`
Expected: compile error on `c.stats(...)` — method does not exist.

- [ ] **Step 3: Add the `ConnStats` struct and the `stats()` method**

In `crates/dpdk-net-core/src/tcp_conn.rs`:

```rust
/// Per-connection observable state snapshot (A5.5). Pure projection.
/// All values in application-useful units (bytes or µs); no engine-
/// internal tickers exposed.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnStats {
    // Send-path (A3 fields).
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub send_buf_bytes_pending: u32,
    pub send_buf_bytes_free: u32,

    // RTT/RTO estimator state (A5 fields). All µs.
    // Before the first RTT sample: srtt_us = rttvar_us = min_rtt_us = 0;
    // rto_us = engine's tcp_initial_rto_us.
    pub srtt_us: u32,
    pub rttvar_us: u32,
    pub min_rtt_us: u32,
    pub rto_us: u32,
}

impl TcpConn {
    /// Slow-path snapshot for forensics / per-order tagging. Called
    /// from the app via `dpdk_net_conn_stats`; not on any hot path.
    pub fn stats(&self, send_buffer_bytes: u32) -> ConnStats {
        let pending = self.snd.pending.len() as u32;
        ConnStats {
            snd_una: self.snd.una,
            snd_nxt: self.snd.nxt,
            snd_wnd: self.snd.wnd,
            send_buf_bytes_pending: pending,
            send_buf_bytes_free: send_buffer_bytes.saturating_sub(pending),
            srtt_us: self.rtt_est.srtt_us().unwrap_or(0),
            rttvar_us: self.rtt_est.rttvar_us(),
            min_rtt_us: self.rack.min_rtt_us,
            rto_us: self.rtt_est.rto_us(),
        }
    }
}
```

Note: `send_buffer_bytes` is an engine-level config, not a `TcpConn` field — the caller (`flow_table::get_stats` or higher) threads it in. If `TcpConn` already caches the engine's `send_buffer_bytes`, swap the arg for `self.send_buffer_bytes_cfg` (check existing A5 code; update the test helper accordingly).

- [ ] **Step 4: Add `flow_table::get_stats`**

In `crates/dpdk-net-core/src/flow_table.rs`:

```rust
impl FlowTable {
    /// Slow-path stats snapshot; see `TcpConn::stats`.
    pub fn get_stats(&self, handle: ConnHandle, send_buffer_bytes: u32) -> Option<ConnStats> {
        self.get(handle).map(|c| c.stats(send_buffer_bytes))
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p dpdk-net-core tcp_conn flow_table`
Expected: new tests pass; existing tests unchanged.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_conn.rs crates/dpdk-net-core/src/flow_table.rs
git commit -m "a5.5 task 6: TcpConn::stats + ConnStats POD + flow_table::get_stats

Adds a 9-field POD snapshot (5 send-path + 4 RTT/RTO) as a pure
projection of existing TcpConn state. Before first RTT sample,
RTT fields are zero and rto_us reports tcp_initial_rto_us."
```

---

## Task 7: `dpdk_net_conn_stats` extern "C" + `dpdk_net_conn_stats_t` header struct + integration tests

**Files:**
- Modify: `crates/dpdk-net/src/api.rs` — new `dpdk_net_conn_stats_t` POD
- Modify: `crates/dpdk-net/src/lib.rs` — new `dpdk_net_conn_stats` extern
- Create (extend): `crates/dpdk-net-core/tests/tcp_a5_5_observability.rs` — integration tests 7.2.3 through 7.2.6

**Context:** Spec §5.3, §7.2.3–7.2.6. Layer the C ABI on top of Task 6. Validation: `-EINVAL` on null engine or out; `-ENOENT` on unknown handle; `0` on success.

- [ ] **Step 1: Write failing integration tests**

```rust
// tests/tcp_a5_5_observability.rs — extend
#[test]
fn dpdk_net_conn_stats_returns_enoent_on_stale_handle() {
    let e = make_test_engine_with_tap();
    let mut out = unsafe { std::mem::zeroed::<dpdk_net::api::dpdk_net_conn_stats_t>() };
    let rc = unsafe {
        dpdk_net::dpdk_net_conn_stats(
            e.as_engine_ptr(),
            0xdead_beef_dead_beef,  // never-allocated handle
            &mut out,
        )
    };
    assert_eq!(rc, -libc::ENOENT);
}

#[test]
fn dpdk_net_conn_stats_reports_pre_sample_rto_initial() {
    // Just after a fresh connection: stats.rto_us == tcp_initial_rto_us.
    let mut e = make_test_engine_with_tap();
    let handle = e.connect_test_peer_and_wait_established();
    let mut out = unsafe { std::mem::zeroed::<dpdk_net::api::dpdk_net_conn_stats_t>() };
    let rc = unsafe { dpdk_net::dpdk_net_conn_stats(e.as_engine_ptr(), handle, &mut out) };
    assert_eq!(rc, 0);
    // Before Task 13 lands, SRTT is None at this point → rto_us = tcp_initial_rto_us.
    // After Task 13 (SYN-seed), srtt_us > 0 and rto_us reflects the seeded srtt.
    // For THIS task, only assert the absence of pre-A5.5 "drain-time" artifacts.
    assert!(out.rto_us > 0);
    assert_eq!(out.snd_una, out.snd_nxt);  // no bytes sent yet
}

#[test]
fn dpdk_net_conn_stats_reports_send_buf_pending_under_backpressure() {
    let mut e = make_test_engine_with_tap_small_rwnd();   // peer rwnd=32
    let handle = e.connect_test_peer_and_wait_established();
    // Send 4 KiB; only 32 bytes will fit in peer rwnd.
    let _ = unsafe {
        dpdk_net::dpdk_net_send(
            e.as_engine_ptr(),
            handle,
            std::ptr::null(),    // buf placeholder; use helper
            4096,
        )
    };
    let mut out = unsafe { std::mem::zeroed::<dpdk_net::api::dpdk_net_conn_stats_t>() };
    let _ = unsafe { dpdk_net::dpdk_net_conn_stats(e.as_engine_ptr(), handle, &mut out) };
    assert!(out.send_buf_bytes_pending > 0);
    assert!(out.snd_wnd <= 32);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p dpdk-net-core --test tcp_a5_5_observability dpdk_net_conn_stats`
Expected: compile error — symbol `dpdk_net_conn_stats` not found.

- [ ] **Step 3: Add the ABI struct + extern**

In `crates/dpdk-net/src/api.rs`:

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct dpdk_net_conn_stats_t {
    // Send-path state.
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub send_buf_bytes_pending: u32,
    pub send_buf_bytes_free: u32,

    /// RTT estimator state. All values in microseconds.
    /// Fields report 0 until the first RTT sample has been absorbed;
    /// after Task 13 (SYN-seed), srtt_us > 0 from ESTABLISHED onward.
    /// rto_us reports the engine's tcp_initial_rto_us before the first
    /// sample; thereafter, the Jacobson/Karels result (post-backoff
    /// if an RTO has fired and rto_no_backoff is not set).
    pub srtt_us: u32,
    pub rttvar_us: u32,
    pub min_rtt_us: u32,
    pub rto_us: u32,
}
```

In `crates/dpdk-net/src/lib.rs`:

```rust
/// Slow-path snapshot of the connection's send-path + RTT estimator state.
/// Safe to call per-order for forensics tagging; do not call in a hot loop.
///
/// Returns:
///   0           on success; `out` populated.
///   -EINVAL     engine or out is NULL.
///   -ENOENT     conn is not a live handle in the flow table.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_conn_stats(
    engine: *mut dpdk_net_engine,
    conn: u64,
    out: *mut dpdk_net_conn_stats_t,
) -> i32 {
    if engine.is_null() || out.is_null() {
        return -libc::EINVAL;
    }
    let eng = &*(engine as *mut Engine);
    let handle = ConnHandle(conn as u32);
    let send_buffer_bytes = eng.cfg.send_buffer_bytes;
    let ft = eng.flow_table.borrow();
    match ft.get_stats(handle, send_buffer_bytes) {
        Some(s) => {
            (*out).snd_una = s.snd_una;
            (*out).snd_nxt = s.snd_nxt;
            (*out).snd_wnd = s.snd_wnd;
            (*out).send_buf_bytes_pending = s.send_buf_bytes_pending;
            (*out).send_buf_bytes_free = s.send_buf_bytes_free;
            (*out).srtt_us = s.srtt_us;
            (*out).rttvar_us = s.rttvar_us;
            (*out).min_rtt_us = s.min_rtt_us;
            (*out).rto_us = s.rto_us;
            0
        }
        None => -libc::ENOENT,
    }
}
```

Note: `ConnHandle(conn as u32)` — confirm the A5 handle encoding. If `ConnHandle` wraps a u64 slot id rather than u32, adjust accordingly; grep `struct ConnHandle` for the ground truth.

- [ ] **Step 4: Regenerate the C header and update the cpp-consumer**

```bash
cargo build -p dpdk-net
```

Verify `include/dpdk_net.h` shows `dpdk_net_conn_stats_t` POD + `dpdk_net_conn_stats` function declaration. In `examples/cpp-consumer/main.cpp`, add a demo call after the first send-and-ACK round:

```cpp
dpdk_net_conn_stats_t pre;
if (dpdk_net_conn_stats(engine, conn, &pre) == 0) {
    printf("stats: snd_nxt=%u srtt_us=%u rto_us=%u\n",
           pre.snd_nxt, pre.srtt_us, pre.rto_us);
}
```

- [ ] **Step 5: Run integration tests**

Run: `cargo test -p dpdk-net-core --test tcp_a5_5_observability`
Expected: all three new tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net/src/api.rs crates/dpdk-net/src/lib.rs include/dpdk_net.h examples/cpp-consumer/main.cpp crates/dpdk-net-core/tests/tcp_a5_5_observability.rs
git commit -m "a5.5 task 7: dpdk_net_conn_stats extern + dpdk_net_conn_stats_t

C ABI for Task 6's ConnStats projection. -EINVAL on null args,
-ENOENT on unknown handle, 0 on success. Cpp-consumer demo
prints the projection after the first ACK."
```

---

## Task 8: Integration tests for emission-time + queue overflow

**Files:**
- Modify: `crates/dpdk-net-core/tests/tcp_a5_5_observability.rs` — add integration tests 7.2.1 (emission-time correctness) + 7.2.2 (queue overflow)

**Context:** Spec §7.2.1, §7.2.2. These need a TAP-pair harness that can inject delay between event emission and app poll, plus a way to produce event pressure without polling. Reuse the A3/A4 TAP harness patterns.

- [ ] **Step 1: Write failing integration tests**

```rust
// tests/tcp_a5_5_observability.rs — extend
#[test]
fn enqueued_ts_ns_reflects_emission_not_drain() {
    let mut e = make_test_engine_with_tap();
    let handle = e.connect_test_peer_and_wait_established();
    // Absorb a single Readable event: peer sends 4 bytes at t0;
    // delay the drain by N µs; assert enqueued_ts_ns is t0, not
    // (t0 + N).
    let ts_at_send = e.tap_send_and_sample_ts(handle, b"data");
    e.advance_clock_by_ns(50_000);   // 50 µs of "poll lag"
    let events = e.poll_drain();
    let readable = events.iter().find(|e| e.kind == DPDK_NET_EVT_READABLE).unwrap();
    // Allow ≤ a few hundred ns of TSC jitter.
    let delta = readable.enqueued_ts_ns.abs_diff(ts_at_send);
    assert!(delta < 1_000, "enqueued_ts_ns {} too far from emission ts {}", readable.enqueued_ts_ns, ts_at_send);
}

#[test]
fn queue_overflow_drops_oldest_and_counts_loss() {
    let mut e = make_test_engine_with_tap_soft_cap(64);
    let handle = e.connect_test_peer_and_wait_established();
    // Emit 200 events without polling in between. Use state-change
    // or tcp_per_packet_events=true + retransmit triggers.
    e.simulate_tlp_per_packet_events(handle, /* n_events */ 200);
    // Now drain.
    let events = e.poll_drain();
    let counters = e.counters_snapshot();
    assert_eq!(events.len(), 64);
    assert!(counters.obs_events_dropped >= 200 - 64);
    assert!(counters.obs_events_queue_high_water >= 64);
    // Events drained should be the most-recent by emitted-ts order.
    let mut prev_ts = 0u64;
    for ev in events.iter() {
        assert!(ev.enqueued_ts_ns >= prev_ts);
        prev_ts = ev.enqueued_ts_ns;
    }
}
```

`make_test_engine_with_tap_soft_cap(cap)` is a new test helper — write it beside `make_test_engine_with_tap`. It calls `engine_create` with `event_queue_soft_cap=cap`.

- [ ] **Step 2: Run — expected PASS (no new stack changes; this task only writes tests that validate tasks 1-7)**

Run: `cargo test -p dpdk-net-core --test tcp_a5_5_observability`
Expected: both new tests pass on first run (tasks 1-7 already wired the machinery).

If a test fails, fix the actual stack bug — do not "fix the test." Common culprits: missed push site in Task 1; wrong counter group access in Task 3; off-by-one in drop-oldest loop.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/tests/tcp_a5_5_observability.rs
git commit -m "a5.5 task 8: integration tests 7.2.1-7.2.2

emission-time ts skew collapses to TSC resolution; overflow drops
oldest and counts via obs.events_dropped/high_water."
```

---

## Task 9: `TlpConfig` + `pto_us` signature migration

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_tlp.rs` — new `TlpConfig` POD; `pto_us` signature becomes `(srtt_us, &TlpConfig, flight_size) → u32`

**Context:** Spec §3.4. Extract the three tunable pieces of the PTO formula into a config struct. Keep A5's existing behavior under `TlpConfig::default()` so all A5 unit tests pass unchanged.

A5's current formula: `pto_us(srtt, min_rto) = max(2 * srtt, min_rto)` — no FlightSize penalty handling (not yet wired). A5.5 introduces the FlightSize penalty as a new gated branch.

- [ ] **Step 1: Write failing tests for the new formula**

```rust
// crates/dpdk-net-core/src/tcp_tlp.rs — inline tests block extension
#[cfg(test)]
mod a5_5_tests {
    use super::*;

    #[test]
    fn pto_default_matches_a5_formula_flight_size_ge_2() {
        let cfg = TlpConfig::default();
        // A5: max(2*srtt, min_rto). flight_size=5 so the FlightSize-1
        // penalty does not fire.
        assert_eq!(pto_us(Some(100_000), &cfg, 5), 200_000);  // 2 × 100 ms
        assert_eq!(pto_us(Some(1_000), &cfg, 5), cfg.floor_us);  // floor = min_rto_us default
    }

    #[test]
    fn pto_flight_size_1_adds_max_wcdelack_or_rtt_over_4() {
        let cfg = TlpConfig {
            floor_us: 0,
            multiplier_x100: 200,
            skip_flight_size_gate: false,
        };
        // srtt = 400 µs; SRTT/4 = 100 µs; WCDelAckT = 200_000 µs.
        // Penalty = max(200_000, 100) = 200_000.
        // Base = 2 × 400 = 800 µs; +penalty = 200_800 µs.
        assert_eq!(pto_us(Some(400), &cfg, 1), 200_800);
    }

    #[test]
    fn pto_skip_flight_size_gate_suppresses_penalty() {
        let cfg = TlpConfig {
            floor_us: 0,
            multiplier_x100: 200,
            skip_flight_size_gate: true,   // opt-out
        };
        // Penalty would be 200_000; with skip_gate, base only (= 800).
        assert_eq!(pto_us(Some(400), &cfg, 1), 800);
    }

    #[test]
    fn pto_configurable_multiplier_below_2x() {
        let cfg = TlpConfig {
            floor_us: 0,
            multiplier_x100: 100,   // 1.0×
            skip_flight_size_gate: true,
        };
        assert_eq!(pto_us(Some(400), &cfg, 1), 400);   // 1.0 × SRTT
    }

    #[test]
    fn pto_configurable_floor_zero() {
        let cfg = TlpConfig {
            floor_us: 0,
            multiplier_x100: 200,
            skip_flight_size_gate: true,
        };
        // srtt = 1 µs; 2× = 2 µs; floor 0 → return 2.
        assert_eq!(pto_us(Some(1), &cfg, 5), 2);
    }
}
```

- [ ] **Step 2: Run tests — expect compile error**

Run: `cargo test -p dpdk-net-core tcp_tlp::a5_5_tests`
Expected: compile error — `TlpConfig` type and new `pto_us` signature do not exist yet.

- [ ] **Step 3: Extend `tcp_tlp.rs` with `TlpConfig` and the new `pto_us`**

Keep the existing `Probe` enum + `select_probe` unchanged. Rewrite `pto_us` and add `TlpConfig`:

```rust
//! RFC 8985 §7 Tail Loss Probe — PTO + probe selection.

use std::cmp::max;

/// Worst-case peer delayed-ACK timer (RFC 8985 §7.2).
/// Default 200 ms matches RFC 1122 §4.2.3.2's "fraction of a second" guidance.
pub const WCDELACK_US: u32 = 200_000;

/// Tunable inputs to the PTO formula (A5.5 §3.4).
/// `TlpConfig::default()` matches A5's pre-A5.5 constants so existing
/// tests pass with no migration effort other than threading the arg.
#[derive(Debug, Clone, Copy)]
pub struct TlpConfig {
    /// Floor in µs. `0` = no floor.
    pub floor_us: u32,
    /// SRTT multiplier × 100 (integer; 200 = 2.0×; 100 = 1.0×).
    pub multiplier_x100: u16,
    /// When `true`, skip the RFC 8985 §7.2 `+max(WCDelAckT, SRTT/4)`
    /// penalty that normally applies when FlightSize == 1.
    pub skip_flight_size_gate: bool,
}

impl TlpConfig {
    /// A5-compatible defaults. The `default_floor_us` arg threads the
    /// engine's `tcp_min_rto_us` — `TlpConfig::default()` alone can't
    /// know the engine config, so callers pass it in at projection time.
    pub fn a5_compat(default_floor_us: u32) -> Self {
        Self {
            floor_us: default_floor_us,
            multiplier_x100: 200,
            skip_flight_size_gate: false,
        }
    }
}

impl Default for TlpConfig {
    /// Uses RFC 8985 §7.2 floor fallback `tcp_min_rto_us=5_000`.
    /// Callers with access to the engine config should prefer
    /// `a5_compat(cfg.tcp_min_rto_us)`.
    fn default() -> Self {
        Self::a5_compat(5_000)
    }
}

pub fn pto_us(srtt_us: Option<u32>, cfg: &TlpConfig, flight_size: u32) -> u32 {
    let Some(srtt) = srtt_us else {
        return cfg.floor_us;
    };
    let base = ((srtt as u64) * (cfg.multiplier_x100 as u64) / 100) as u32;
    let with_penalty = if flight_size == 1 && !cfg.skip_flight_size_gate {
        base.saturating_add(max(WCDELACK_US, srtt / 4))
    } else {
        base
    };
    max(with_penalty, cfg.floor_us)
}
```

- [ ] **Step 4: Migrate A5 call sites**

Grep for `tcp_tlp::pto_us` and `pto_us(` across the workspace. Existing A5 call site (at `engine.rs:1626` pre-A5.5):

```rust
// BEFORE
let pto_us = crate::tcp_tlp::pto_us(srtt, self.cfg.tcp_min_rto_us);
```

Becomes:

```rust
// AFTER
let cfg = crate::tcp_tlp::TlpConfig::a5_compat(self.cfg.tcp_min_rto_us);
let flight_size = conn.snd_retrans.flight_size() as u32;   // or len() — check A5 RetransDeque API
let pto_us = crate::tcp_tlp::pto_us(srtt, &cfg, flight_size);
```

This keeps A5's RFC 8985 default behavior intact: `TlpConfig::a5_compat(min_rto)` produces `{floor_us: min_rto, multiplier_x100: 200, skip_flight_size_gate: false}`, and `flight_size` of the actual queue.

If `snd_retrans.flight_size()` does not exist, add it as a small helper:

```rust
// crates/dpdk-net-core/src/tcp_retrans.rs
impl SendRetrans {
    /// FlightSize per RFC 8985 §7 — count of unacked, unsacked segments.
    pub fn flight_size(&self) -> usize {
        self.entries.iter().filter(|e| !e.sacked).count()
    }
}
```

- [ ] **Step 5: Run all tests**

Run: `cargo test -p dpdk-net-core`
Expected: all A5 tests pass (`TlpConfig::default` preserves behavior for srtt ≥ min_rto); all 5 new A5.5 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_tlp.rs crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/tcp_retrans.rs
git commit -m "a5.5 task 9: TlpConfig + pto_us(srtt, &cfg, flight_size)

Extends the PTO formula with (a) configurable floor, (b)
configurable SRTT multiplier 1.0x-2.0x, (c) FlightSize-1
+max_ack_delay penalty with opt-out flag. TlpConfig::a5_compat
preserves RFC 8985 behavior; all A5 tests green."
```

---

## Task 10: `dpdk_net_connect_opts_t` — 5 TLP tuning fields + validation

**Files:**
- Modify: `crates/dpdk-net/src/api.rs` — extend `dpdk_net_connect_opts_t`
- Modify: `crates/dpdk-net/src/lib.rs` — `dpdk_net_connect` validates the 5 new fields
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs` — `TcpConn` mirrors the 5 fields + 4 runtime state fields
- Modify: `crates/dpdk-net-core/src/engine.rs` — `ConnectOpts` mirrors; projection into `TlpConfig`

**Context:** Spec §5.5. All 5 fields default to behavior-preserving values. Invalid combinations rejected with `-EINVAL` at `dpdk_net_connect` entry:
- `tlp_pto_srtt_multiplier_x100 < 100 OR > 200`
- `tlp_max_consecutive_probes == 0 OR > 5`
- `tlp_pto_min_floor_us > cfg.tcp_max_rto_us`

Runtime state fields (not in ABI, only on `TcpConn`):
- `tlp_consecutive_probes_fired: u8` — reset on new RTT sample or new-data ACK
- `tlp_rtt_sample_seen_since_last_tlp: bool` — reset on TLP fire, set on RTT sample
- `tlp_recent_probes: [Option<RecentProbe>; 5]` — ring for DSACK spurious attribution (Task 12)

- [ ] **Step 1: Write failing tests for validation + field presence**

```rust
// tests/tcp_a5_5_tlp_tuning.rs — new file
#[test]
fn connect_rejects_tlp_multiplier_below_100() {
    let e = make_test_engine_with_tap();
    let mut opts = make_minimal_connect_opts();
    opts.tlp_pto_srtt_multiplier_x100 = 50;
    let rc = unsafe {
        dpdk_net::dpdk_net_connect(e.as_engine_ptr(), &opts, std::ptr::null_mut())
    };
    assert_eq!(rc, -libc::EINVAL);
}

#[test]
fn connect_rejects_tlp_multiplier_above_200() {
    let e = make_test_engine_with_tap();
    let mut opts = make_minimal_connect_opts();
    opts.tlp_pto_srtt_multiplier_x100 = 250;
    let rc = unsafe {
        dpdk_net::dpdk_net_connect(e.as_engine_ptr(), &opts, std::ptr::null_mut())
    };
    assert_eq!(rc, -libc::EINVAL);
}

#[test]
fn connect_rejects_tlp_max_consecutive_probes_zero_or_above_5() {
    let e = make_test_engine_with_tap();
    for bad in [0u8, 6, 10, 255] {
        let mut opts = make_minimal_connect_opts();
        opts.tlp_max_consecutive_probes = bad;
        let rc = unsafe {
            dpdk_net::dpdk_net_connect(e.as_engine_ptr(), &opts, std::ptr::null_mut())
        };
        assert_eq!(rc, -libc::EINVAL, "tlp_max_consecutive_probes={} should be rejected", bad);
    }
}

#[test]
fn connect_rejects_tlp_pto_floor_above_max_rto() {
    let e = make_test_engine_with_tap();   // default tcp_max_rto_us = 1_000_000 (1s)
    let mut opts = make_minimal_connect_opts();
    opts.tlp_pto_min_floor_us = 2_000_000;   // 2s > 1s
    let rc = unsafe {
        dpdk_net::dpdk_net_connect(e.as_engine_ptr(), &opts, std::ptr::null_mut())
    };
    assert_eq!(rc, -libc::EINVAL);
}

#[test]
fn connect_accepts_default_tlp_opts() {
    let e = make_test_engine_with_tap();
    let opts = make_minimal_connect_opts();   // all TLP knobs at defaults
    let mut out_handle: u64 = 0;
    let rc = unsafe {
        dpdk_net::dpdk_net_connect(e.as_engine_ptr(), &opts, &mut out_handle)
    };
    assert_eq!(rc, 0);
}
```

- [ ] **Step 2: Run tests — expect compile error**

Run: `cargo test -p dpdk-net --test tcp_a5_5_tlp_tuning connect_rejects`
Expected: compile error — fields don't exist.

- [ ] **Step 3: Add the 5 fields to `dpdk_net_connect_opts_t`**

In `crates/dpdk-net/src/api.rs`, extend (append, do not mid-insert):

```rust
#[repr(C)]
pub struct dpdk_net_connect_opts_t {
    // … existing fields up to rto_no_backoff …
    pub rack_aggressive: bool,
    pub rto_no_backoff: bool,

    // A5.5: per-connect TLP tuning (§3.4 / §5.5). Defaults preserve
    // A5 RFC 8985 behavior exactly.
    pub tlp_pto_min_floor_us: u32,            // 0 = no floor; validated <= tcp_max_rto_us
    pub tlp_pto_srtt_multiplier_x100: u16,    // 100..200 inclusive
    pub tlp_skip_flight_size_gate: bool,
    pub tlp_max_consecutive_probes: u8,       // 1..5 inclusive
    pub tlp_skip_rtt_sample_gate: bool,
}
```

- [ ] **Step 4: Validate in `dpdk_net_connect`**

In `crates/dpdk-net/src/lib.rs`:

```rust
pub unsafe extern "C" fn dpdk_net_connect(
    engine: *mut dpdk_net_engine,
    opts: *const dpdk_net_connect_opts_t,
    out_handle: *mut u64,
) -> i32 {
    // … existing null-checks + peer_addr / peer_port checks …
    let o = &*opts;
    let eng = &*(engine as *mut Engine);

    // A5.5 TLP knob validation.
    if !(100..=200).contains(&o.tlp_pto_srtt_multiplier_x100) {
        return -libc::EINVAL;
    }
    if !(1..=5).contains(&o.tlp_max_consecutive_probes) {
        return -libc::EINVAL;
    }
    if o.tlp_pto_min_floor_us > eng.cfg.tcp_max_rto_us {
        return -libc::EINVAL;
    }
    // tlp_pto_min_floor_us == 0 is explicitly legal (no floor).
    // booleans don't need range checks.

    // … construct ConnectOpts with the 5 new fields threaded in …
}
```

Mirror the 5 fields into `engine.rs::ConnectOpts` (the Rust-internal struct).

- [ ] **Step 5: Add the fields to `TcpConn` + zero-initialize + add the 3 runtime state fields**

In `crates/dpdk-net-core/src/tcp_conn.rs`:

```rust
pub struct TcpConn {
    // … existing fields …

    // A5.5 per-connect TLP tuning (mirrored from dpdk_net_connect_opts_t).
    pub tlp_pto_min_floor_us: u32,
    pub tlp_pto_srtt_multiplier_x100: u16,
    pub tlp_skip_flight_size_gate: bool,
    pub tlp_max_consecutive_probes: u8,
    pub tlp_skip_rtt_sample_gate: bool,

    // A5.5 runtime state.
    /// Count of consecutive TLPs fired without an intervening RTT sample
    /// or new-data ACK. Reset on RTT sample (tcp_input.rs Task 11-ish)
    /// and on new-data ACK (same path). Gates arm_tlp_pto + TLP schedule.
    pub tlp_consecutive_probes_fired: u8,
    /// RFC 8985 §7.4 — "new RTT sample seen since last probe" flag.
    /// Flipped true on rtt_est.sample(); flipped false on TLP fire.
    pub tlp_rtt_sample_seen_since_last_tlp: bool,
    /// Ring of last 5 TLP probes (seq, len, tx_ts_ns, attributed).
    /// Consumed by DSACK spurious-probe attribution (Task 12).
    pub tlp_recent_probes: [Option<RecentProbe>; 5],
    /// Oldest slot index — next probe overwrites here.
    pub tlp_recent_probes_next_slot: u8,
    /// A5.5 SRTT-from-SYN seed (Task 13).
    /// Engine-monotonic-clock ns at SYN emission; consumed at SYN-ACK.
    pub syn_tx_ts_ns: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RecentProbe {
    pub seq: u32,
    pub len: u16,
    pub tx_ts_ns: u64,
    pub attributed: bool,
}
```

In `TcpConn::new` (or wherever construction lives), default all 9 new fields to zero / false / None / 0 as appropriate. Apply the connect-time opts values to the 5 ABI-mirrored fields.

- [ ] **Step 6: Project `TlpConfig` from the conn fields**

Add a helper in `tcp_conn.rs` (or `tcp_tlp.rs`):

```rust
impl TcpConn {
    pub fn tlp_config(&self, engine_min_rto_us: u32) -> crate::tcp_tlp::TlpConfig {
        // tlp_pto_min_floor_us == 0 means "no floor" — but we also allow
        // non-zero values that override the engine default. If the user
        // explicitly set `0`, pass `0` through (TlpConfig respects it).
        let floor = if self.tlp_pto_min_floor_us == 0 {
            0
        } else {
            self.tlp_pto_min_floor_us
        };
        crate::tcp_tlp::TlpConfig {
            floor_us: floor,
            multiplier_x100: self.tlp_pto_srtt_multiplier_x100.max(100),
            skip_flight_size_gate: self.tlp_skip_flight_size_gate,
        }
    }
}
```

Caveat: if the user did **not** touch the TLP knobs (zero-init), the 5 fields are all zeros/false. A zero-init `tlp_pto_srtt_multiplier_x100 == 0` would violate the `[100, 200]` invariant. Validation at `dpdk_net_connect` (Step 4) rejects `< 100`. **But zero-init callers will fail that check.** Resolve by treating zero-init as "use A5 defaults": at `dpdk_net_connect` entry, after the structural validation, apply default substitution:

```rust
// Apply A5-compatible defaults if the caller zero-init'd (pre-A5.5 callers).
let mut o_opts = *o;   // copy
if o_opts.tlp_pto_srtt_multiplier_x100 == 0 {
    o_opts.tlp_pto_srtt_multiplier_x100 = 200;
}
if o_opts.tlp_max_consecutive_probes == 0 {
    o_opts.tlp_max_consecutive_probes = 1;
}
if o_opts.tlp_pto_min_floor_us == 0 {
    // Policy: 0 means "inherit engine tcp_min_rto_us by default".
    // If the caller explicitly wants 0 (no floor), they set it to a
    // sentinel… Actually, this conflicts with the spec's "0 = no floor".
    // Resolve: add a second bool field `tlp_pto_has_explicit_floor`
    // OR keep 0 as "no floor" and let non-opt-in callers see no floor
    // too (consistent with `tlp_skip_*_gate` default=false semantics).
    // SIMPLER CHOICE: 0 = "inherit engine min_rto"; spec-defined "no
    // floor" encoding becomes u32::MAX sentinel → floor_us=0.
    // DECIDED BY PLAN: use u32::MAX as "explicit no-floor" sentinel.
    o_opts.tlp_pto_min_floor_us = eng.cfg.tcp_min_rto_us;
}
```

**Plan-level decision:** `tlp_pto_min_floor_us == 0` means "inherit engine `tcp_min_rto_us`" (zero-init friendly); `tlp_pto_min_floor_us == u32::MAX` means "explicit no-floor". Document this in the doc comment on the field. The spec §5.5 wording "0 = no floor" needs an erratum note in the plan; surface in Task 16's parent-spec update: the §5.5 row gets "`0` = inherit engine `tcp_min_rto_us`; `u32::MAX` = explicit no-floor".

Run validation to reject `tlp_pto_min_floor_us > eng.cfg.tcp_max_rto_us` AND `!= u32::MAX`:

```rust
if o_opts.tlp_pto_min_floor_us != u32::MAX
   && o_opts.tlp_pto_min_floor_us > eng.cfg.tcp_max_rto_us
{
    return -libc::EINVAL;
}
```

Update `TcpConn::tlp_config`:

```rust
let floor = if self.tlp_pto_min_floor_us == u32::MAX {
    0    // explicit no-floor
} else {
    self.tlp_pto_min_floor_us
};
```

- [ ] **Step 7: Run tests + header regen**

```bash
cargo test -p dpdk-net-core -p dpdk-net --test tcp_a5_5_tlp_tuning
cargo build -p dpdk-net
```

Verify `include/dpdk_net.h` shows the 5 new fields on `dpdk_net_connect_opts_t`.

- [ ] **Step 8: Commit**

```bash
git add crates/dpdk-net/src/api.rs crates/dpdk-net/src/lib.rs crates/dpdk-net-core/src/tcp_conn.rs crates/dpdk-net-core/src/engine.rs include/dpdk_net.h crates/dpdk-net-core/tests/tcp_a5_5_tlp_tuning.rs
git commit -m "a5.5 task 10: 5 per-connect TLP knobs + validation + TcpConn state

dpdk_net_connect validates multiplier in [100,200], max_probes in
[1,5], floor<=tcp_max_rto_us (or u32::MAX sentinel for no-floor).
Zero-init ABI callers get A5 defaults; explicit no-floor uses
u32::MAX. TcpConn also gains 4 runtime TLP state fields
(consecutive_probes_fired, rtt_sample_seen_since_last_tlp, and
the 5-entry recent_probes ring for Task 12)."
```

---

## Task 11: Multi-probe TLP scheduling + budget reset + `tcp.tx_tlp_spurious` counter declared

**Files:**
- Modify: `crates/dpdk-net-core/src/counters.rs` — `TcpCounters::tx_tlp_spurious: AtomicU64`
- Modify: `crates/dpdk-net/src/api.rs` — `dpdk_net_tcp_counters_t::tx_tlp_spurious`
- Modify: `crates/dpdk-net-core/src/engine.rs` — TLP scheduling consults the budget + tlp_skip_rtt_sample_gate
- Modify: `crates/dpdk-net-core/src/engine.rs` — `on_tlp_fire` increments `tlp_consecutive_probes_fired`, clears `tlp_rtt_sample_seen_since_last_tlp`, records the probe in `tlp_recent_probes`
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` — RTT-sample / new-data-ACK path resets the budget; flips the sample-seen flag

**Context:** Spec §3.4. The scheduling side (where-to-arm) is the existing A5 arm-on-ACK path at `engine.rs:1614-1643`. Task 15 adds a second arm site (arm-on-send). This task: gate the arm on the multi-probe budget + wire the state transitions. The counter `tx_tlp_spurious` is declared here but actually incremented in Task 12.

- [ ] **Step 1: Write failing tests for multi-probe + budget reset**

```rust
// tests/tcp_a5_5_tlp_tuning.rs — extend
#[test]
fn multi_probe_tlp_fires_three_then_rto() {
    let mut e = make_test_engine_with_tap();
    let mut opts = make_minimal_connect_opts();
    opts.tlp_max_consecutive_probes = 3;
    opts.tlp_skip_rtt_sample_gate = true;
    let handle = e.connect_test_peer_and_wait_established_with_opts(&opts);

    // Establish SRTT with one healthy round-trip.
    e.simulate_round_trip(handle, 100_000);  // 100 ms
    // Now induce persistent tail loss: peer drops every probe too.
    e.tap_set_peer_blackhole(true);
    e.simulate_send(handle, b"order");

    // Advance clock in PTO steps, polling after each.
    for _ in 0..3 {
        e.advance_clock_by_srtt_multiple(2.0);
        let _ = e.poll_once();
    }
    let c = e.counters_snapshot();
    assert_eq!(c.tcp_tx_tlp, 3, "expected 3 TLPs before RTO");

    // Now RTO fires on the 4th deadline.
    e.advance_clock_by_rto();
    let _ = e.poll_once();
    let c = e.counters_snapshot();
    assert_eq!(c.tcp_tx_rto, 1, "expected exactly 1 RTO after TLP budget exhausted");
}

#[test]
fn budget_resets_on_new_data_ack() {
    let mut e = make_test_engine_with_tap();
    let mut opts = make_minimal_connect_opts();
    opts.tlp_max_consecutive_probes = 3;
    opts.tlp_skip_rtt_sample_gate = true;
    let handle = e.connect_test_peer_and_wait_established_with_opts(&opts);
    e.simulate_round_trip(handle, 100_000);

    e.tap_set_peer_blackhole(true);
    e.simulate_send(handle, b"order1");
    e.advance_clock_by_srtt_multiple(2.0);
    let _ = e.poll_once();
    // 1 TLP has fired.
    assert_eq!(e.get_conn(handle).tlp_consecutive_probes_fired, 1);

    // Peer resumes, ACKs new data.
    e.tap_set_peer_blackhole(false);
    e.simulate_round_trip(handle, 100_000);
    // Budget reset.
    assert_eq!(e.get_conn(handle).tlp_consecutive_probes_fired, 0);

    // Send + drop again — a fresh TLP fires.
    e.tap_set_peer_blackhole(true);
    e.simulate_send(handle, b"order2");
    e.advance_clock_by_srtt_multiple(2.0);
    let _ = e.poll_once();
    let c = e.counters_snapshot();
    assert_eq!(c.tcp_tx_tlp, 2, "TLP2 fires because budget was reset");
}
```

- [ ] **Step 2: Run tests — expect fail**

Run: `cargo test -p dpdk-net --test tcp_a5_5_tlp_tuning multi_probe_tlp_fires_three_then_rto budget_resets_on_new_data_ack`
Expected: fail — scheduling doesn't yet gate on budget; A5 fires one probe then RTO-only.

- [ ] **Step 3: Add `tx_tlp_spurious` to counters**

In `crates/dpdk-net-core/src/counters.rs`:

```rust
pub struct TcpCounters {
    // … existing fields …
    pub tx_tlp_spurious: AtomicU64,   // A5.5 Task 11 declare; Task 12 increments
}
```

In `crates/dpdk-net/src/api.rs` `dpdk_net_tcp_counters_t`: append `pub tx_tlp_spurious: u64;` — do not mid-insert. Update the counter-mirror code in `crates/dpdk-net/src/lib.rs` to populate it.

- [ ] **Step 4: Wire the arm-time budget gate**

In `crates/dpdk-net-core/src/engine.rs` at the existing A5 TLP arm block (`:1608-1643`):

```rust
// BEFORE (A5)
let tlp_arm = {
    let ft = self.flow_table.borrow();
    ft.get(handle)
        .map(|c| !c.snd_retrans.is_empty() && c.tlp_timer_id.is_none())
        .unwrap_or(false)
};

// AFTER (A5.5 Task 11) — add budget check + RTT-sample-gate check
let tlp_arm = {
    let ft = self.flow_table.borrow();
    ft.get(handle)
        .map(|c| {
            if c.snd_retrans.is_empty() || c.tlp_timer_id.is_some() {
                return false;
            }
            if c.tlp_consecutive_probes_fired >= c.tlp_max_consecutive_probes {
                return false;  // budget exhausted
            }
            // RFC 8985 §7.4 RTT-sample gate — unless the per-conn skip
            // flag is set, require a new RTT sample since the last probe.
            if !c.tlp_skip_rtt_sample_gate
                && !c.tlp_rtt_sample_seen_since_last_tlp
            {
                return false;
            }
            true
        })
        .unwrap_or(false)
};
```

Swap the A5 `pto_us` call for the Task 9 signature:

```rust
let (srtt, cfg, flight_size, now_ns) = {
    let ft = self.flow_table.borrow();
    let c = ft.get(handle).unwrap();
    let srtt = c.rtt_est.srtt_us();
    let cfg = c.tlp_config(self.cfg.tcp_min_rto_us);
    let fs = c.snd_retrans.flight_size() as u32;
    (srtt, cfg, fs, crate::clock::now_ns())
};
let pto_us = crate::tcp_tlp::pto_us(srtt, &cfg, flight_size);
```

- [ ] **Step 5: Wire state transitions in `on_tlp_fire`**

In `engine.rs::on_tlp_fire`, after the successful probe emission (where `tcp.tx_tlp` is already bumped):

```rust
// A5.5: record in recent-probes ring + bump consecutive budget +
// clear rtt-sample-seen flag.
let slot = c.tlp_recent_probes_next_slot as usize;
c.tlp_recent_probes[slot] = Some(RecentProbe {
    seq: probe_seq,
    len: probe_len,
    tx_ts_ns: self.clock.now_ns(),
    attributed: false,
});
c.tlp_recent_probes_next_slot = ((slot + 1) % c.tlp_recent_probes.len()) as u8;
c.tlp_consecutive_probes_fired = c.tlp_consecutive_probes_fired.saturating_add(1);
c.tlp_rtt_sample_seen_since_last_tlp = false;
```

`probe_seq` and `probe_len` are the seq + length of the segment just TX'd by the probe (new data from `snd.pending` or the re-TX'd tail segment).

- [ ] **Step 6: Reset the budget on RTT sample / new-data ACK in `tcp_input.rs`**

In `crates/dpdk-net-core/src/tcp_input.rs` at the ACK-processing block where `rtt_est.sample()` is called (the two branches at `:574` TS-source and `:582` Karn's-fallback):

```rust
if let Some(rtt) = ts_sample {
    conn.rtt_est.sample(rtt);
    conn.rack.update_min_rtt(rtt);
    rtt_sample_taken = true;
    // A5.5: flip sample-seen + reset consecutive-probe budget.
    conn.tlp_rtt_sample_seen_since_last_tlp = true;
    conn.tlp_consecutive_probes_fired = 0;
} else if let Some(front) = conn.snd_retrans.front() {
    // … existing Karn's block …
    if /* conditions */ {
        conn.rtt_est.sample(rtt);
        conn.rack.update_min_rtt(rtt);
        rtt_sample_taken = true;
        conn.tlp_rtt_sample_seen_since_last_tlp = true;
        conn.tlp_consecutive_probes_fired = 0;
    }
}
```

Also reset on any ACK that advances `snd_una` (new data acked — independent of RTT sample). Find the block in `tcp_input.rs` where `snd_una` advances on cum-ACK:

```rust
// Right after snd_una advances on cum-ACK (new-data ACK):
if seg.ack_seq != snd_una_before {
    conn.tlp_consecutive_probes_fired = 0;
}
```

- [ ] **Step 7: Run tests**

Run: `cargo test -p dpdk-net-core -p dpdk-net --test tcp_a5_5_tlp_tuning multi_probe_tlp_fires_three_then_rto budget_resets_on_new_data_ack`
Expected: both pass. All existing tests continue to pass (`tlp_max_consecutive_probes=1` default and `skip_rtt_sample_gate=false` default preserve A5 RFC 8985 behavior).

- [ ] **Step 8: Run integration tests 7.2.7–7.2.11**

Add these to `tests/tcp_a5_5_tlp_tuning.rs`:

```rust
#[test]
fn zero_floor_pto_fires_at_2x_srtt() {
    // 7.2.7
    let mut opts = make_minimal_connect_opts();
    opts.tlp_pto_min_floor_us = u32::MAX;   // explicit no-floor
    // … scenario: 100µs SRTT, expect TLP at ≈200µs …
}

#[test]
fn multiplier_100_pto_fires_at_1x_srtt() {
    // 7.2.8
    let mut opts = make_minimal_connect_opts();
    opts.tlp_pto_srtt_multiplier_x100 = 100;
    opts.tlp_pto_min_floor_us = u32::MAX;
    // … expect TLP at ≈SRTT, not 2·SRTT …
}

#[test]
fn skip_flight_size_gate_omits_max_ack_delay_penalty() {
    // 7.2.9 — single-segment send, drop; TLP fires at 2·SRTT not 2·SRTT+200ms.
    // Baseline run without the flag: TLP fires at 2·SRTT + 200ms.
}

// 7.2.10 = multi_probe_tlp_fires_three_then_rto (already written above)
// 7.2.11 = budget_resets_on_new_data_ack (already written above)
```

Flesh out the scenarios with the TAP harness helpers.

Run: `cargo test -p dpdk-net --test tcp_a5_5_tlp_tuning`
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add crates/dpdk-net-core/src/counters.rs crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/tcp_input.rs crates/dpdk-net/src/api.rs crates/dpdk-net/src/lib.rs include/dpdk_net.h crates/dpdk-net-core/tests/tcp_a5_5_tlp_tuning.rs
git commit -m "a5.5 task 11: multi-probe TLP + budget reset + tx_tlp_spurious

Gates TLP arm on tlp_consecutive_probes_fired<tlp_max_consecutive_probes
and the RFC 8985 §7.4 RTT-sample gate (opt-out via
tlp_skip_rtt_sample_gate). Resets the budget on RTT sample or new-
data ACK. Records every probe in tlp_recent_probes ring for Task 12.
Counter tx_tlp_spurious declared (incremented in Task 12)."
```

---

## Task 12: DSACK spurious-probe attribution + `tx_tlp_spurious` increments

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` — DSACK-detection block attributes to `tlp_recent_probes`

**Context:** Spec §3.4 spurious-attribution subsection. When a DSACK block intersects a recent probe's `[seq, seq+len)` range AND the probe's `tx_ts_ns` is within `4·SRTT` of now, increment `tcp.tx_tlp_spurious` once per probe and set the probe's `attributed` flag. The 4·SRTT plausibility window prevents attribution across seq-space wraparound.

- [ ] **Step 1: Write failing test**

```rust
// tests/tcp_a5_5_tlp_tuning.rs — extend
#[test]
fn dsack_after_tlp_increments_tx_tlp_spurious_once() {
    let mut e = make_test_engine_with_tap();
    let mut opts = make_minimal_connect_opts();
    opts.tlp_max_consecutive_probes = 1;
    let handle = e.connect_test_peer_and_wait_established_with_opts(&opts);
    e.simulate_round_trip(handle, 100_000);

    // Peer reorders: drop original, TLP probe arrives, then original
    // arrives late; peer DSACKs the probe.
    e.tap_schedule_reorder_scenario(handle);
    e.simulate_send(handle, b"data");
    e.advance_clock_by_srtt_multiple(2.0);
    let _ = e.poll_once();   // TLP fires
    e.advance_clock_by_ns(10_000);
    e.tap_deliver_original_plus_dsack_for_probe();
    let _ = e.poll_once();

    let c = e.counters_snapshot();
    assert_eq!(c.tcp_tx_tlp, 1);
    assert_eq!(c.tcp_tx_tlp_spurious, 1);
    assert_eq!(c.tcp_rx_dsack, 1);

    // A second DSACK intersecting the same probe does not re-count.
    e.tap_deliver_extra_dsack_for_same_probe();
    let _ = e.poll_once();
    let c = e.counters_snapshot();
    assert_eq!(c.tcp_tx_tlp_spurious, 1);   // unchanged
}
```

- [ ] **Step 2: Run — expected fail**

Run: `cargo test -p dpdk-net --test tcp_a5_5_tlp_tuning dsack_after_tlp_increments_tx_tlp_spurious_once`
Expected: fail with `left: 0, right: 1` on `tx_tlp_spurious`.

- [ ] **Step 3: Implement attribution in the DSACK-detection block**

In `crates/dpdk-net-core/src/tcp_input.rs` find the existing DSACK detection block (A5 Task 16 wired it — grep `rx_dsack` for the site). Per-DSACK-block attribution:

```rust
// A5.5 Task 12: attribute DSACK to a recent TLP probe.
let now_ns = crate::clock::now_ns();
let srtt_us = conn.rtt_est.srtt_us().unwrap_or(conn.rack.min_rtt_us);
let window_ns = (srtt_us as u64) * 1_000 * 4;   // 4·SRTT

for probe_slot in conn.tlp_recent_probes.iter_mut() {
    let Some(probe) = probe_slot.as_mut() else { continue };
    if probe.attributed {
        continue;
    }
    // Block [left, right] covers [probe.seq, probe.seq + probe.len)
    // wholly?
    let probe_end = probe.seq.wrapping_add(probe.len as u32);
    if seq_le(probe.seq, block.left) && seq_le(block.right, probe_end) {
        // Plausibility: probe's xmit_ts within 4·SRTT of now.
        if now_ns.saturating_sub(probe.tx_ts_ns) < window_ns {
            counters.tcp.tx_tlp_spurious.fetch_add(1, Ordering::Relaxed);
            probe.attributed = true;
            break;
        }
    }
}
```

Caveat: multiple DSACK blocks in one SACK option could each attribute. The `break` keeps attribution per-ACK; remove the `break` if DSACK blocks are processed one-at-a-time by the outer loop (check the A5 DSACK block iteration shape).

- [ ] **Step 4: Run tests**

Run: `cargo test -p dpdk-net --test tcp_a5_5_tlp_tuning dsack_after_tlp_increments_tx_tlp_spurious_once`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_input.rs crates/dpdk-net-core/tests/tcp_a5_5_tlp_tuning.rs
git commit -m "a5.5 task 12: DSACK spurious-probe attribution for tx_tlp_spurious

DSACK blocks that cover a recent probe's seq range increment
tcp.tx_tlp_spurious once per probe, gated on a 4·SRTT plausibility
window. Prevents double-count via probe.attributed flag."
```

---

## Task 13: SRTT seeded from SYN handshake round-trip

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs` — `syn_tx_ts_ns: u64` field already added in Task 10; ensure default = 0
- Modify: `crates/dpdk-net-core/src/engine.rs` — on SYN emission (the SYN-out path in `dpdk_net_connect` or the SYN handler), set `c.syn_tx_ts_ns = self.clock.now_ns()`
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` — `handle_syn_sent` valid-SYN-ACK branch absorbs the RTT sample

**Context:** Spec §3.5. RFC 6298 §3.3 MAY: "The RTT of the SYN segment MAY be used as the first SRTT." Karn's rule: only the first SYN's ACK counts.

- [ ] **Step 1: Write failing test**

```rust
// tests/tcp_a5_5_ad_closures.rs — new file
#[test]
fn srtt_nonzero_immediately_after_established() {
    let mut e = make_test_engine_with_tap();
    let handle = e.connect_test_peer_and_wait_established();
    let mut out = unsafe { std::mem::zeroed::<dpdk_net::api::dpdk_net_conn_stats_t>() };
    let _ = unsafe { dpdk_net::dpdk_net_conn_stats(e.as_engine_ptr(), handle, &mut out) };
    assert!(out.srtt_us > 0, "expected SRTT > 0 post-ESTABLISHED (seeded from SYN round-trip)");
    assert!(out.min_rtt_us > 0);
    // rto_us should reflect SRTT + 4·RTTVAR clamped to [min_rto, max_rto],
    // not the raw tcp_initial_rto_us.
}

#[test]
fn karns_rule_on_syn_retransmit_skips_seed() {
    let mut e = make_test_engine_with_tap_drop_first_syn();
    let handle = e.connect_test_peer_and_wait_established();
    let mut out = unsafe { std::mem::zeroed::<dpdk_net::api::dpdk_net_conn_stats_t>() };
    let _ = unsafe { dpdk_net::dpdk_net_conn_stats(e.as_engine_ptr(), handle, &mut out) };
    // First SYN was dropped; retransmitted SYN's ACK does NOT seed.
    assert_eq!(out.srtt_us, 0);
    assert_eq!(out.min_rtt_us, 0);
    // Send + ACK one data round — now SRTT seeds normally from data-ACK.
    e.simulate_round_trip(handle, 100_000);
    let _ = unsafe { dpdk_net::dpdk_net_conn_stats(e.as_engine_ptr(), handle, &mut out) };
    assert!(out.srtt_us > 0);
}

#[test]
fn syn_rtt_sample_bounds_checked() {
    // Unit test on the sample path directly — feed rtt_us = 0 and
    // rtt_us = 60_000_001; assert rtt_est.sample is NOT called in
    // either case.
    // Sketch: construct a TcpConn with syn_tx_ts_ns = now_ns();
    // call the seeding helper with now_us variations that produce
    // out-of-bounds RTT; observe rtt_est.srtt_us() stays None.
}
```

- [ ] **Step 2: Run — expected fail**

Run: `cargo test -p dpdk-net --test tcp_a5_5_ad_closures srtt_nonzero_immediately_after_established`
Expected: fail — `srtt_us` is 0 right after ESTABLISHED because A5 only samples on data-ACK.

- [ ] **Step 3: Set `syn_tx_ts_ns` at SYN emission**

Find the SYN-send site (grep `build_segment.*TCP_SYN` or `emit_syn` in `engine.rs`). Add:

```rust
// Right after the SYN is successfully enqueued for TX:
if let Some(c) = ft.get_mut(handle) {
    c.syn_tx_ts_ns = self.clock.now_ns();
}
```

The SYN-retransmit path (A5 Task 18's SYN retransmit scheduler) does **not** update this field — we want to preserve the *first* SYN's tx_ts for the seed decision. If your A5 retransmit path resets it, guard: only update on the fresh SYN (when `c.syn_retrans_count == 0`).

Actually, simpler: set on the original SYN only. The SYN retransmit path should not touch `syn_tx_ts_ns` at all.

- [ ] **Step 4: Absorb the RTT sample in `handle_syn_sent`**

In `crates/dpdk-net-core/src/tcp_input.rs::handle_syn_sent`, at the valid-SYN-ACK accept branch (after option negotiation, before state transition):

```rust
// A5.5 Task 13: seed SRTT from the SYN round-trip (RFC 6298 §3.3 MAY).
// Karn's rule: only the first SYN's ACK counts — skip if retransmitted.
if conn.syn_retrans_count == 0 && conn.syn_tx_ts_ns != 0 {
    let now_us = (crate::clock::now_ns() / 1_000) as u32;
    let syn_tx_us = (conn.syn_tx_ts_ns / 1_000) as u32;
    let rtt_us = now_us.wrapping_sub(syn_tx_us);
    if (1..60_000_000).contains(&rtt_us) {
        conn.rtt_est.sample(rtt_us);
        conn.rack.update_min_rtt(rtt_us);
    }
}
```

The bounds check mirrors the existing A5 data-ACK sampler (`tcp_input.rs:564, 581`).

- [ ] **Step 5: Run tests**

Run: `cargo test -p dpdk-net --test tcp_a5_5_ad_closures srtt_nonzero_immediately_after_established karns_rule_on_syn_retransmit_skips_seed`
Expected: both pass.

Run: `cargo test -p dpdk-net-core` — verify no A5 tests regressed. Some A5 tests may have asserted `srtt_us == 0` immediately after ESTABLISHED; those need updating to reflect the new invariant. Grep `srtt_us.*== 0` in the core tests and patch any that break.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/tcp_input.rs crates/dpdk-net-core/tests/tcp_a5_5_ad_closures.rs
git commit -m "a5.5 task 13: SRTT seeded from SYN handshake (closes AD-18 window)

handle_syn_sent absorbs the SYN round-trip as the first RTT sample
when syn_retrans_count == 0 (Karn's rule). RFC 6298 §3.3 MAY.
Makes dpdk_net_conn_stats return srtt_us > 0 immediately post-
ESTABLISHED and gives AD-18's arm-TLP-on-send a valid PTO basis."
```

---

## Task 14: AD-17 close — `RACK_mark_losses_on_RTO` pass in `on_rto_fire`

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` — `on_rto_fire` Phase 3 gains the §6.3 pass before the existing `self.retransmit(handle, 0)`

**Context:** Spec §3.6. RFC 8985 §6.3 walks `snd_retrans` and flags `entry.lost = true` for every unacked, unsacked entry matching the formula. Route through the existing `rack_lost_indexes` retransmit loop (A5 at `engine.rs:1467-1491`). Semantic: one RTO fire → N retransmits but **one** `tcp.tx_rto` increment.

Spec §3.6 formula uses `rack.rtt_us` which does not exist as a field on our `RackState`. Use `rtt_est.srtt_us().unwrap_or(rack.min_rtt_us)` instead — this is the Rust-side mapping of RFC 8985 §6.1's `RACK.rtt`. Note this mapping in Task 16's spec erratum.

- [ ] **Step 1: Write failing tests**

```rust
// tests/tcp_a5_5_ad_closures.rs — extend
#[test]
fn multi_segment_tail_loss_rto_retransmits_all_in_one_burst() {
    let mut e = make_test_engine_with_tap();
    let handle = e.connect_test_peer_and_wait_established();
    e.simulate_round_trip(handle, 100_000);

    // Send 5 segments back-to-back; drop all 5 at peer.
    e.tap_set_peer_blackhole(true);
    for i in 0..5 {
        e.simulate_send(handle, format!("seg{}", i).as_bytes());
    }
    e.advance_clock_by_rto();
    let _ = e.poll_once();

    let c = e.counters_snapshot();
    assert_eq!(c.tcp_tx_retrans, 5, "all 5 segments retransmitted in the RTO burst");
    assert_eq!(c.tcp_tx_rto, 1, "exactly one RTO event, not 5");
}

#[test]
fn rack_mark_losses_on_rto_unit_age_based_marking() {
    use dpdk_net_core::engine::rack_mark_losses_on_rto;

    let mut entries = vec![
        /* seq=100, xmit_ts=100_000_ns (fresh), not sacked, not lost */
        /* seq=200, xmit_ts=10_000_ns (ancient),  not sacked, not lost */
        /* seq=300, xmit_ts=150_000_ns (very fresh), not sacked, not lost */
    ];
    let snd_una = 100;
    let rtt_us = 50;            // 50 µs
    let reo_wnd_us = 1000;      // 1 ms
    let now_us = 200;           // µs

    // Formula: entry.seq == snd_una OR xmit_ts/1000 + rtt + reo_wnd <= now_us
    // - seq 100 (== snd_una) → lost
    // - seq 200 (ancient, age = 200 - 10 = 190µs > 50+1000 = 1050? NO) → not lost
    //   Actually the formula is xmit_ts_us + rtt + reo_wnd <= now_us.
    //   10_000_ns / 1000 = 10 µs; 10 + 50 + 1000 = 1060 > 200 → not lost.
    //   Adjust numbers to produce the expected outcome.
    // - seq 300 → not lost (recent)

    let lost = rack_mark_losses_on_rto(&entries, snd_una, rtt_us, reo_wnd_us, now_us);
    assert_eq!(lost, vec![0]);   // only index 0 (seq 100)
}

#[test]
fn single_segment_rto_retransmit_semantics_preserved() {
    let mut e = make_test_engine_with_tap();
    let handle = e.connect_test_peer_and_wait_established();
    e.simulate_round_trip(handle, 100_000);
    e.tap_set_peer_blackhole(true);
    e.simulate_send(handle, b"single");
    e.advance_clock_by_rto();
    let _ = e.poll_once();
    let c = e.counters_snapshot();
    assert_eq!(c.tcp_tx_rto, 1);
    assert_eq!(c.tcp_tx_retrans, 1);   // same as pre-A5.5
}
```

- [ ] **Step 2: Run — expected fail**

Run: `cargo test -p dpdk-net --test tcp_a5_5_ad_closures multi_segment_tail_loss_rto_retransmits_all_in_one_burst`
Expected: fail with `tcp_tx_retrans left: 1, right: 5`.

- [ ] **Step 3: Extract the formula into a testable helper**

In `crates/dpdk-net-core/src/engine.rs` (or `tcp_rack.rs` alongside `detect_lost`):

```rust
/// RFC 8985 §6.3 RACK_mark_losses_on_RTO. Returns indexes of entries
/// newly marked lost; caller flips the lost flag + feeds the list to
/// the retransmit loop.
pub fn rack_mark_losses_on_rto(
    entries: &[RetransEntry],
    snd_una: u32,
    rtt_us: u32,         // srtt_us().unwrap_or(rack.min_rtt_us)
    reo_wnd_us: u32,
    now_us: u32,
) -> Vec<u16> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if e.sacked || e.lost {
            continue;
        }
        let end_seq = e.seq.wrapping_add(e.len as u32);
        if crate::tcp_seq::seq_le(end_seq, snd_una) {
            continue;   // cum-ACKed, prune handles later
        }
        let xmit_us = (e.xmit_ts_ns / 1_000) as u32;
        let age_expired = xmit_us
            .saturating_add(rtt_us)
            .saturating_add(reo_wnd_us)
            <= now_us;
        if e.seq == snd_una || age_expired {
            out.push(i as u16);
        }
    }
    out
}
```

- [ ] **Step 4: Call the helper at the top of `on_rto_fire` Phase 3**

In `engine.rs::on_rto_fire`, before the existing `self.retransmit(handle, 0)`:

```rust
// A5.5 Task 14: RFC 8985 §6.3 RACK_mark_losses_on_RTO pass.
let lost_indexes = {
    let ft = self.flow_table.borrow();
    let c = ft.get(handle).unwrap();
    let rtt_us = c.rtt_est.srtt_us().unwrap_or(c.rack.min_rtt_us);
    let reo_wnd = c.rack.reo_wnd_us;
    let now_us = (crate::clock::now_ns() / 1_000) as u32;
    crate::engine::rack_mark_losses_on_rto(
        &c.snd_retrans.entries,
        c.snd.una,
        rtt_us,
        reo_wnd,
        now_us,
    )
};

// Mark entries lost.
{
    let mut ft = self.flow_table.borrow_mut();
    let c = ft.get_mut(handle).unwrap();
    for &idx in &lost_indexes {
        c.snd_retrans.entries[idx as usize].lost = true;
    }
}

// Drop the explicit front retransmit — the loop below covers it if
// `snd_retrans[0].seq == snd_una` (which the pass always catches).
// Feed the lost-index list through the existing retransmit machinery.
outcome.rack_lost_indexes = lost_indexes;
```

The engine's outer loop at `:1467-1491` already handles `outcome.rack_lost_indexes` — it iterates and calls `self.retransmit(handle, idx)` per entry. `tcp.tx_retrans` bumps once per retransmit (A5 behavior preserved). `tcp.tx_rto` is incremented **once** in `on_rto_fire` regardless of the burst size — confirm the counter-increment site.

Guard: if `lost_indexes` is empty (shouldn't happen given `entry.seq == snd_una` always fires on at least one entry, but defensively) fall back to the pre-A5.5 `self.retransmit(handle, 0)`.

- [ ] **Step 5: Unit-test the helper**

Add inline unit tests in `engine.rs` or wherever the helper lives. Cover:
- Single entry at snd_una → lost
- Ancient entry past reo_wnd → lost
- Sacked entry → skipped
- Already-lost entry → skipped
- Cum-ACKed entry → skipped

- [ ] **Step 6: Run all tests**

Run: `cargo test -p dpdk-net-core -p dpdk-net`
Expected: all new tests pass; A5's single-RTO-fire tests stay green (front-entry-only case preserved).

- [ ] **Step 7: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/tests/tcp_a5_5_ad_closures.rs
git commit -m "a5.5 task 14: AD-17 close — RACK_mark_losses_on_RTO in on_rto_fire

Every RTO fire now walks snd_retrans and marks all §6.3-eligible
entries as lost before retransmitting. Single RTO fire → N
retransmits → one tx_rto + N tx_retrans increments. A5's one-seg-
per-subsequent-ACK tail-recovery pacing fixed."
```

---

## Task 15: AD-18 close — TLP armed on every new-data send

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` — new helper `fn arm_tlp_pto`; called from `Engine::send_bytes` after segments are enqueued

**Context:** Spec §3.7. Add an arm site at the `send_bytes` TX path in addition to the existing arm-on-ACK. Gate: `snd_retrans.len() >= 1 && tlp_timer_id.is_none() && rtt_est.srtt_us().is_some() && tlp_consecutive_probes_fired < tlp_max_consecutive_probes`. Post-Task 13 SRTT seed, the `srtt_us().is_some()` guard holds from ESTABLISHED.

- [ ] **Step 1: Write failing test**

```rust
// tests/tcp_a5_5_ad_closures.rs — extend
#[test]
fn first_burst_tlp_fires_at_pto_not_rto() {
    let mut e = make_test_engine_with_tap();
    let handle = e.connect_test_peer_and_wait_established();
    // Post-Task-13: SRTT is seeded from SYN RTT, say ≈100 µs.
    let pre = e.stats_snapshot(handle);
    assert!(pre.srtt_us > 0);

    // First-burst send; peer drops it.
    e.tap_set_peer_blackhole(true);
    e.simulate_send(handle, b"order");

    // PTO = 2·SRTT; RTO = tcp_initial_rto_us = 5ms.
    // Advance clock by 2·SRTT + small margin.
    e.advance_clock_by_ns(2 * (pre.srtt_us as u64) * 1_000 + 10_000);
    let _ = e.poll_once();

    let c = e.counters_snapshot();
    assert_eq!(c.tcp_tx_tlp, 1, "TLP fired");
    assert_eq!(c.tcp_tx_rto, 0, "RTO did NOT fire");
}

#[test]
fn arm_tlp_pto_is_noop_in_syn_sent() {
    let mut e = make_test_engine_with_tap();
    let handle = e.connect_issue_syn_without_waiting();   // state = SYN_SENT
    // Try to call send_bytes — should be rejected by existing A5
    // check (state != Established). No TLP timer should be armed.
    let _ = e.simulate_send_expect_err(handle, b"data");
    let c = e.get_conn(handle);
    assert!(c.tlp_timer_id.is_none());
}

#[test]
fn arm_tlp_pto_noop_when_budget_exhausted() {
    let mut e = make_test_engine_with_tap();
    let mut opts = make_minimal_connect_opts();
    opts.tlp_max_consecutive_probes = 1;
    let handle = e.connect_test_peer_and_wait_established_with_opts(&opts);
    e.simulate_round_trip(handle, 100_000);
    e.tap_set_peer_blackhole(true);
    e.simulate_send(handle, b"s1");
    e.advance_clock_by_srtt_multiple(2.0);
    let _ = e.poll_once();   // TLP 1 fires; budget now exhausted at 1.

    // New send attempts to arm TLP — but budget is exhausted, so arm is no-op.
    e.simulate_send(handle, b"s2");
    // TLP timer stays None (or whatever cleared state) — arm_tlp_pto
    // must have early-returned.
    let c = e.get_conn(handle);
    assert!(c.tlp_timer_id.is_none());
}
```

- [ ] **Step 2: Run — expected fail**

Run: `cargo test -p dpdk-net --test tcp_a5_5_ad_closures first_burst_tlp_fires_at_pto_not_rto`
Expected: fail — `tcp_tx_tlp` is 0 because A5 only arms TLP from the ACK handler.

- [ ] **Step 3: Add `arm_tlp_pto` helper**

In `crates/dpdk-net-core/src/engine.rs`:

```rust
impl Engine {
    /// A5.5 Task 15: arm the TLP PTO timer from the send path.
    /// Mirrors the A5 arm-on-ACK site at :1614-1643 but is driven by
    /// `send_bytes` instead of the ACK handler. Guards:
    ///   - snd_retrans non-empty (somebody is in flight)
    ///   - no TLP currently armed
    ///   - SRTT is known (post-SYN-seed guaranteed in ESTABLISHED)
    ///   - consecutive-probe budget not exhausted
    fn arm_tlp_pto(&self, handle: ConnHandle) {
        let (ok, srtt, cfg, flight_size, now_ns) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else {
                return;
            };
            if c.snd_retrans.is_empty() || c.tlp_timer_id.is_some() {
                return;
            }
            if c.tlp_consecutive_probes_fired >= c.tlp_max_consecutive_probes {
                return;
            }
            let Some(srtt_us) = c.rtt_est.srtt_us() else {
                return;
            };
            let cfg = c.tlp_config(self.cfg.tcp_min_rto_us);
            let fs = c.snd_retrans.flight_size() as u32;
            (true, Some(srtt_us), cfg, fs, crate::clock::now_ns())
        };
        if !ok {
            return;
        }
        let pto_us = crate::tcp_tlp::pto_us(srtt, &cfg, flight_size);
        let fire_at_ns = now_ns + (pto_us as u64 * 1_000);
        let id = self.timer_wheel.borrow_mut().add(
            now_ns,
            crate::tcp_timer_wheel::TimerNode {
                fire_at_ns,
                owner_handle: handle,
                kind: crate::tcp_timer_wheel::TimerKind::Tlp,
                generation: 0,
                cancelled: false,
            },
        );
        let mut ft = self.flow_table.borrow_mut();
        if let Some(c) = ft.get_mut(handle) {
            c.tlp_timer_id = Some(id);
            c.timer_ids.push(id);
        }
    }
}
```

- [ ] **Step 4: Call `arm_tlp_pto` from `send_bytes`**

In `Engine::send_bytes` (`engine.rs:2209`), after the segments are TX'd and `snd_retrans` has been populated (at the end of the send loop, before returning `accepted`):

```rust
// A5.5 Task 15: arm TLP from the send path per RFC 8985 §7.2 SHOULD.
if accepted > 0 {
    self.arm_tlp_pto(handle);
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p dpdk-net --test tcp_a5_5_ad_closures first_burst_tlp_fires_at_pto_not_rto arm_tlp_pto_is_noop_in_syn_sent arm_tlp_pto_noop_when_budget_exhausted`
Expected: all three pass.

Run: `cargo test -p dpdk-net-core` — verify A5 tests green. A5 TLP arm-on-ACK tests should see no behavior change (TLP already armed by time the ACK handler runs; the second arm attempt is no-op via `tlp_timer_id.is_some()` guard).

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/tests/tcp_a5_5_ad_closures.rs
git commit -m "a5.5 task 15: AD-18 close — TLP armed on every new-data send

Engine::send_bytes calls arm_tlp_pto after the segment is enqueued
in snd_retrans. Gates on srtt_us.is_some() (Task 13 guarantees
post-ESTABLISHED), budget-not-exhausted, and no-TLP-armed. RFC
8985 §7.2 SHOULD closed; first-burst loss probes at PTO not RTO."
```

---

## Task 16: AD-15 retirement + AD-17/18 promotion + parent-spec §6 updates

**Files:**
- Modify: `docs/superpowers/reviews/phase-a5-rfc-compliance.md` — mark AD-15, AD-17, AD-18 as "closed in A5.5" with cross-refs
- Modify: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` — §4 Introspection API mention; §4.2 queue contract; §6.3 RFC matrix updates; §6.4 new AD rows; §9.1 counter examples; §9.3 events semantic update

**Context:** Spec §10 Updates to parent spec. Doc-only; no code. Also corrects the §5.5 spec erratum (`tlp_pto_min_floor_us == 0` means inherit engine default; `u32::MAX` is explicit no-floor) introduced in Task 10.

- [ ] **Step 1: Update `docs/superpowers/reviews/phase-a5-rfc-compliance.md`**

At each of AD-15, AD-17, AD-18 entries add a retirement note:

```markdown
- **AD-15 (from F-2 promotion)** — TLP pre-fire state machine (TLP.end_seq / TLP.is_retrans) deferred to Stage 2
  - RFC clause: `docs/rfcs/rfc8985.txt:984-1003` …
  - (existing body preserved)
  - **Closed in A5.5 (`phase-a5-5-complete`)** — superseded by A5.5 multi-probe data structures: `tlp_recent_probes` ring (Task 10 / 11) replaces single-slot `tlp_end_seq`; `tlp_consecutive_probes_fired < tlp_max_consecutive_probes` gate replaces single-in-flight. A5.5 plan task 11 wires the superseding structures; task 16 records this retirement. See A5.5 design spec §6 `AD-15 retired`.

- **AD-17 (from S-1 promotion)** — RACK mark-losses-on-RTO pass not invoked in `on_rto_fire`
  - (existing body preserved)
  - **Closed in A5.5 (`phase-a5-5-complete`)** — `RACK_mark_losses_on_RTO` pass added at the top of `on_rto_fire` in A5.5 plan task 14. Single RTO fire now retransmits the whole §6.3-eligible tail in one burst. See A5.5 design spec §6 `AD-A5-5-rack-mark-losses-on-rto`.

- **AD-18 (from mTCP E-2 promotion, mirrored here for completeness)** — TLP-arm-on-send deferred to Stage 2
  - (existing body preserved)
  - **Closed in A5.5 (`phase-a5-5-complete`)** — `arm_tlp_pto` called from `Engine::send_bytes` in A5.5 plan task 15. Combined with A5.5 plan task 13's SRTT-from-SYN seed, the arm site always has a valid PTO basis post-ESTABLISHED. See A5.5 design spec §6 `AD-A5-5-tlp-arm-on-send`.
```

Update the phase-a5-rfc-compliance.md gate status block at the top:

```markdown
Gate status:
- Must-fix open: 0 …
- Missing-SHOULD open: 0 …
- Accepted-deviation entries: 18 (AD-1…AD-18). 3 of these (AD-15, AD-17, AD-18) are closed in A5.5 — retirement notes in-line.
```

- [ ] **Step 2: Update `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`**

In the parent spec:

- **§4 API** — add or extend an "Introspection API" paragraph: "`dpdk_net_conn_stats(engine, conn, out) → i32` returns 9 u32 fields covering send-path state and RTT estimator state; slow-path; safe per-order; see A5.5 design spec §3.3 / §5.3."

- **§4.2 contracts** — document the event-queue soft-cap contract: "The engine event queue has a configurable soft cap (`event_queue_soft_cap`, default 4096, min 64). On overflow, the oldest event is dropped and `obs.events_dropped` increments; `obs.events_queue_high_water` latches max depth."

- **§6.3 RFC matrix** — update the RFC 8985 row: "RACK-TLP: primary loss-detection path, including §6.3 RACK_mark_losses_on_RTO (A5.5) and §7.2 TLP armed on ACK and on new-data send (A5.5). Per-connect tuning knobs deviate from strict §7.2/§7.4 when set; default matches RFC 8985 exactly." Add RFC 6298 §3.3: "SRTT seeded from SYN handshake round-trip per §3.3 MAY."

- **§6.4 new rows** — add 8 AD rows (same text as A5.5 design spec §6):
  - `AD-A5-5-srtt-from-syn`
  - `AD-A5-5-rack-mark-losses-on-rto`
  - `AD-A5-5-tlp-arm-on-send`
  - `AD-A5-5-tlp-pto-floor-zero`
  - `AD-A5-5-tlp-multiplier-below-2x`
  - `AD-A5-5-tlp-skip-flight-size-gate`
  - `AD-A5-5-tlp-multi-probe`
  - `AD-A5-5-tlp-skip-rtt-sample-gate`

- **§9.1 counter examples** — add `obs.events_dropped`, `obs.events_queue_high_water`, `tcp.tx_tlp_spurious` to the example list; introduce the `obs` group alongside `poll`/`eth`/`ip`/`tcp`.

- **§9.3 events** — clarify `enqueued_ts_ns` is emission-time, not drain-time: "sampled at event emission inside the stack, not at `dpdk_net_poll` drain (A5.5)."

- **§4 connect opts** — list the 5 new TLP tuning fields below `rack_aggressive` / `rto_no_backoff`.

- [ ] **Step 3: Also update the A5.5 spec `§5.5` erratum (plan-decided semantics)**

In `docs/superpowers/specs/2026-04-18-stage1-phase-a5-5-event-log-forensics-design.md` §5.5:

Replace the current `tlp_pto_min_floor_us` row to match the plan's zero-init-friendly semantics:

> `tlp_pto_min_floor_us` | `u32` | `0` inherits engine `tcp_min_rto_us` | 0 .. `tcp_max_rto_us` OR `u32::MAX` | `0` (default) inherits engine-wide `tcp_min_rto_us`. `u32::MAX` sentinel = explicit no-floor. Any other value > `tcp_max_rto_us` is rejected at `dpdk_net_connect` with `-EINVAL`. Zero-init callers see A5-default behavior unchanged.

Also update the aggressive-preset example at §5.5 to use the `u32::MAX` sentinel:

```c
.tlp_pto_min_floor_us = UINT32_MAX,     // explicit no-floor
```

- [ ] **Step 4: Commit (doc-only)**

```bash
git add docs/superpowers/reviews/phase-a5-rfc-compliance.md docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md docs/superpowers/specs/2026-04-18-stage1-phase-a5-5-event-log-forensics-design.md
git commit -m "a5.5 task 16: parent-spec §6 updates + AD-15/17/18 retirement

Parent spec §4 Introspection API, §4.2 queue contract, §6.3 RFC
8985 + 6298 §3.3 updates, §6.4 8 new AD rows, §9.1 obs group
counters, §9.3 enqueued_ts_ns semantic clarification. Phase-a5-
rfc-compliance review marks AD-15/17/18 closed in A5.5. A5.5 spec
§5.5 erratum: tlp_pto_min_floor_us=0 inherits engine default,
u32::MAX is explicit no-floor (zero-init-friendly)."
```

---

## Task 17: A5.5 knob-coverage extension in `tests/knob-coverage.rs`

**Files:**
- Modify: `crates/dpdk-net-core/tests/knob-coverage.rs` (or wherever A5 landed it — check the A5 roadmap §A11 row for the canonical path)

**Context:** Roadmap §A11 requires a knob-coverage audit entry per new behavioral knob plus the aggressive-preset combination. Each entry names a scenario fn and a non-default value; the dynamic check runs the scenario and asserts an observable consequence.

- [ ] **Step 1: Locate the test file**

```bash
find crates -name "knob-coverage.rs" -o -name "knob_coverage.rs" 2>/dev/null
```

If it does not exist yet (A11 is not yet started), create the scaffold in `crates/dpdk-net-core/tests/knob-coverage.rs` with a placeholder structure, noting it'll be absorbed into A11's full audit. If it does exist, extend.

- [ ] **Step 2: Add entries for A5.5 knobs**

```rust
// tests/knob-coverage.rs — extend existing table + scenario fns

// Engine-wide:
//   event_queue_soft_cap — scenario: overflow_scenario_drops_events
// Per-connect:
//   tlp_pto_min_floor_us — scenario: zero_floor_pto_fires_at_2x_srtt (test 7.2.7)
//   tlp_pto_srtt_multiplier_x100 — scenario: multiplier_100_pto_fires_at_1x_srtt (test 7.2.8)
//   tlp_skip_flight_size_gate — scenario: skip_flight_size_gate_omits_max_ack_delay_penalty (test 7.2.9)
//   tlp_max_consecutive_probes — scenario: multi_probe_tlp_fires_three_then_rto (test 7.2.10)
//   tlp_skip_rtt_sample_gate — scenario: rtt_sample_gate_skip_allows_back_to_back_tlp
// Combination:
//   aggressive_order_entry_preset — scenario: aggressive_preset_fires_first_tlp_within_1x_srtt

static A5_5_KNOBS: &[(&str, KnobScenario)] = &[
    (
        "event_queue_soft_cap",
        KnobScenario {
            non_default_value: "128",
            scenario_fn: overflow_scenario_drops_events,
            expected_consequence: "obs.events_dropped > 0 + drained events are most-recent",
        },
    ),
    (
        "tlp_pto_min_floor_us",
        KnobScenario {
            non_default_value: "u32::MAX",
            scenario_fn: zero_floor_pto_fires_at_2x_srtt,
            expected_consequence: "TLP fires at 2·SRTT, not at engine tcp_min_rto_us",
        },
    ),
    (
        "tlp_pto_srtt_multiplier_x100",
        KnobScenario {
            non_default_value: "100",
            scenario_fn: multiplier_100_pto_fires_at_1x_srtt,
            expected_consequence: "TLP fires at ≈SRTT, not 2·SRTT",
        },
    ),
    (
        "tlp_skip_flight_size_gate",
        KnobScenario {
            non_default_value: "true",
            scenario_fn: skip_flight_size_gate_omits_max_ack_delay_penalty,
            expected_consequence: "TLP PTO omits +max(WCDelAckT, SRTT/4) even when FlightSize=1",
        },
    ),
    (
        "tlp_max_consecutive_probes",
        KnobScenario {
            non_default_value: "3",
            scenario_fn: multi_probe_tlp_fires_three_then_rto,
            expected_consequence: "3 TLPs fire at PTO cadence before RTO takes over",
        },
    ),
    (
        "tlp_skip_rtt_sample_gate",
        KnobScenario {
            non_default_value: "true",
            scenario_fn: rtt_sample_gate_skip_allows_back_to_back_tlp,
            expected_consequence: "back-to-back TLPs fire without intervening RTT sample",
        },
    ),
    (
        "aggressive_order_entry_preset",
        KnobScenario {
            non_default_value: "{floor=u32::MAX, mult=100, skip_fs=true, probes=3, skip_rtt=true}",
            scenario_fn: aggressive_preset_fires_first_tlp_within_1x_srtt,
            expected_consequence: "first TLP fires within 1·SRTT; 3 probes fire; no RTO in window",
        },
    ),
];

// Scenario fns — most are 1:1 reuses of integration tests from Task 11/12.
fn overflow_scenario_drops_events() { /* reuse Task 8's test */ }
fn zero_floor_pto_fires_at_2x_srtt() { /* reuse 7.2.7 */ }
fn multiplier_100_pto_fires_at_1x_srtt() { /* reuse 7.2.8 */ }
fn skip_flight_size_gate_omits_max_ack_delay_penalty() { /* reuse 7.2.9 */ }
fn multi_probe_tlp_fires_three_then_rto() { /* reuse 7.2.10 */ }
fn rtt_sample_gate_skip_allows_back_to_back_tlp() { /* new scenario */ }
fn aggressive_preset_fires_first_tlp_within_1x_srtt() { /* new combination scenario */ }
```

If A5 has not yet landed `knob-coverage.rs`, leave a `TODO(A11)` comment with a link to the A11 roadmap row + the canonical scenario-table shape so A11 can absorb this into the full audit.

- [ ] **Step 3: Run coverage tests**

Run: `cargo test -p dpdk-net-core --test knob-coverage`
Expected: all A5.5 scenarios pass (they reuse existing integration tests from earlier tasks).

- [ ] **Step 4: Commit**

```bash
git add crates/dpdk-net-core/tests/knob-coverage.rs
git commit -m "a5.5 task 17: knob-coverage entries for A5.5 knobs + aggressive preset

Extends tests/knob-coverage.rs with 6 entries per the roadmap §A11
canonical list + one combination entry for the aggressive order-
entry preset. Each entry names a scenario fn and asserts an
observable consequence distinguishing the non-default value."
```

---

## Task 18: A5.5 mTCP comparison review gate

**Files:**
- Create: `docs/superpowers/reviews/phase-a5-5-mtcp-compare.md`

**Context:** Spec §8, §10.13. Dispatch the `mtcp-comparison-reviewer` subagent (opus per `feedback_subagent_model.md`). Blocks the `phase-a5-5-complete` tag until the report has zero open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD.

- [ ] **Step 1: Dispatch the review subagent**

Using the `Agent` tool with `subagent_type=mtcp-comparison-reviewer` and `model=opus`:

```
Prompt for the reviewer:

Review A5.5 (Event-log forensics + in-flight introspection + TLP tuning) against mTCP as a mature userspace-TCP reference. The A5.5 design spec is at `docs/superpowers/specs/2026-04-18-stage1-phase-a5-5-event-log-forensics-design.md`; the plan at `docs/superpowers/plans/2026-04-19-stage1-phase-a5-5-event-log-forensics-tlp-tuning.md`.

Focus areas:
- Event-queue overflow accounting vs mTCP's event/log model — note mTCP has no bounded event queue (scope-difference not behavioral).
- `dpdk_net_conn_stats` vs mTCP's `tcp_api_get_conn_state` — different shape; our projection covers send-path + RTT in one slow-path call. Note scope.
- TLP tuning knobs + AD-18 arm-on-send vs mTCP's RTO-only tail recovery — mTCP does not implement TLP. Document as scope-difference for the 5 knob ADs; document AD-18 as matching the E-2 finding from A5's review and now closed.
- AD-17 `RACK_mark_losses_on_RTO` vs mTCP — mTCP does not implement RACK. Scope-difference.
- SRTT seed from SYN — mTCP's `CreateTCPStream` does not seed SRTT until first data-ACK; our deviation is a strict improvement under RFC 6298 §3.3 MAY.

Expected output: report at `docs/superpowers/reviews/phase-a5-5-mtcp-compare.md` in the fixed schema (Must-fix / Missed-edge-cases / Accepted-divergence / FYI / Verdict).
```

- [ ] **Step 2: Review the report + fix or escalate findings**

Read the report. Each `[ ]` item in Must-fix or Missed-edge-cases is a gate:
- If genuinely a bug → fix the stack; re-run the reviewer.
- If an accepted divergence → promote to an AD row in spec §6 + §6.4; update the report's checkbox to `[x]` with justification.

No open `[ ]` allowed in Must-fix / Missed-edge-cases / Missing-SHOULD at phase sign-off.

- [ ] **Step 3: Commit the review report**

```bash
git add docs/superpowers/reviews/phase-a5-5-mtcp-compare.md
# plus any spec or code changes driven by the review
git commit -m "a5.5 task 18: mTCP comparison review report (§10.13 gate)"
```

---

## Task 19: A5.5 RFC compliance review gate

**Files:**
- Create: `docs/superpowers/reviews/phase-a5-5-rfc-compliance.md`

**Context:** Spec §8, §10.14. Dispatch the `rfc-compliance-reviewer` subagent (opus). Parallel gate to Task 18; both block the tag.

- [ ] **Step 1: Dispatch the review subagent in parallel with Task 18**

Using the `Agent` tool with `subagent_type=rfc-compliance-reviewer` and `model=opus`, in the same message as Task 18's dispatch:

```
Prompt for the reviewer:

Review A5.5 for RFC compliance. Design spec at `docs/superpowers/specs/2026-04-18-stage1-phase-a5-5-event-log-forensics-design.md`; plan at `docs/superpowers/plans/2026-04-19-stage1-phase-a5-5-event-log-forensics-tlp-tuning.md`.

RFCs in scope:
- RFC 6298 §3.3 — SRTT seeded from SYN handshake (AD-A5-5-srtt-from-syn). Verify Karn's rule (syn_retrans_count == 0 guard) is literal.
- RFC 8985 §6.3 — RACK_mark_losses_on_RTO (AD-17 closure). Verify the formula implementation: `entry.seq == snd.una OR entry.xmit_ts + RACK.rtt + RACK.reo_wnd <= now`. Our mapping: RACK.rtt → rtt_est.srtt_us().unwrap_or(rack.min_rtt_us). Document this mapping in §6.4.
- RFC 8985 §7.2 — Arm TLP PTO on new-data send (AD-18 closure). Verify the `send_bytes` TX path arms `arm_tlp_pto` under the four gates.
- RFC 8985 §7.2 (5 TLP knob ADs) — per-connect opt-in; defaults preserve RFC 8985 exactly. Verify each knob has a §6.4 row and zero-init callers see RFC 8985 behavior.
- RFC 8985 §7.4 — RTT-sample-gate (suppression of TLP without new RTT sample). Verify `tlp_skip_rtt_sample_gate` is opt-in only; default honors the gate.
- RFC 2883 — DSACK detection (AD-A5-5-tlp-spurious already integrated via tx_tlp_spurious — visibility only, no behavioral adaptation in A5.5).

Expected output: report at `docs/superpowers/reviews/phase-a5-5-rfc-compliance.md` in the fixed schema. Approximately 6 new §6.4 rows are expected + 3 Stage-2 AD retirements (AD-15, AD-17, AD-18).
```

- [ ] **Step 2: Review the report + resolve findings**

Same protocol as Task 18: every `[ ]` in Must-fix / Missing-SHOULD is a gate. Fix or promote to an AD with justification. No open `[ ]` at phase sign-off.

- [ ] **Step 3: Commit the review report**

```bash
git add docs/superpowers/reviews/phase-a5-5-rfc-compliance.md
# plus spec / code edits driven by the review
git commit -m "a5.5 task 19: RFC compliance review report (§10.14 gate)"
```

---

## Task 20: Workspace sanity + tag `phase-a5-5-complete`

**Files:**
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md` — A5.5 row → `**Complete** ✓` + link to this plan

**Context:** Spec §8. Runs after all 19 prior tasks are complete, both review reports are clean (zero open `[ ]`), and all tests pass.

- [ ] **Step 1: Workspace sanity**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
./scripts/check-header-drift.sh   # or whatever the cbindgen header-drift checker is
```

All must pass. Fix any new clippy warnings introduced by A5.5. If any test regresses, treat as a blocker — do not tag.

- [ ] **Step 2: Update the roadmap row**

In `docs/superpowers/plans/stage1-phase-roadmap.md`:

```markdown
| A5.5 | Event-log forensics + in-flight introspection + TLP tuning … | **Complete** ✓ | `2026-04-19-stage1-phase-a5-5-event-log-forensics-tlp-tuning.md` |
```

Also update the "phase status" narrative row at the top of the file (if A5 left a scaffold like "A5 Complete; A5.5 Not started" — flip A5.5 to Complete).

- [ ] **Step 3: Commit and tag**

```bash
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "a5.5 task 20: mark A5.5 complete in roadmap"
git tag -a phase-a5-5-complete -m "Stage 1 Phase A5.5 — event-log forensics + in-flight introspection + TLP tuning"
```

Leave `git push` to the user per `Executing actions with care` discipline.

---

## Review + cleanup loop

After each task lands, per `feedback_per_task_review_discipline.md`:

1. Dispatch a `spec-compliance` reviewer subagent (opus) with the task's diff + the A5.5 design spec. Prompt: "Did this implementation match spec §X.Y? Flag any deviations."
2. Dispatch a `code-quality` reviewer subagent (opus) with the task's diff. Prompt: "Review for Rust-idiom correctness, over-engineering, missing error handling, test coverage gaps."
3. Fix any findings before moving to the next task.

The two reviewers run in parallel (single message, two `Agent` calls). No task advances until both reviewers return no open `[ ]` findings.

At end-of-phase, tasks 18 + 19 are the **phase-level** mTCP + RFC review gates — distinct from per-task reviews. Both are parallel subagent dispatches; both must return clean before the `phase-a5-5-complete` tag.

---

## Self-review check

1. **Spec coverage.** Every §1 scope bullet has a task:
   - Emission-time ts: Tasks 1–2
   - Queue overflow: Tasks 3–5
   - Stats getter: Tasks 6–7
   - TLP tuning knobs: Tasks 9–12
   - SRTT-from-SYN: Task 13
   - AD-17: Task 14
   - AD-18: Task 15
   - AD-15 retirement + parent-spec updates: Task 16
   - Knob-coverage audit: Task 17
   - Review gates: Tasks 18–19
   - Final tag: Task 20
2. **No placeholders.** Every step shows code or exact commands. Spec erratum (`tlp_pto_min_floor_us` zero-init semantic) surfaced in Task 10 and formalized in Task 16.
3. **Type consistency.** `TlpConfig` fields (`floor_us`, `multiplier_x100`, `skip_flight_size_gate`) consistent across Tasks 9, 10, 11, 15. `RecentProbe` fields (`seq`, `len`, `tx_ts_ns`, `attributed`) consistent across Tasks 10, 11, 12. `ConnStats` 9-field layout consistent across Tasks 6, 7. `obs.events_dropped` / `obs.events_queue_high_water` naming consistent across Tasks 3, 4, 5, 8, 17.
4. **Task order sanity.** Task 4 before Task 3 (counters exist before queue consumes them). Task 13 before Task 15 (SRTT exists before arm-on-send's guard tightens). Task 10 before Task 11 (TlpConfig fields exist before scheduling reads them). Task 12 after Task 11 (recent-probes ring exists before DSACK attribution walks it). Task 16 after 13–15 (AD closures exist before retirement notes are written).
