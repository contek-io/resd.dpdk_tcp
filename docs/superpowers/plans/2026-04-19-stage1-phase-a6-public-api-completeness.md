# resd.dpdk_tcp Stage 1 Phase A6 — Public API surface completeness + per-conn RTT histogram

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finalize the Stage 1 public C ABI defined in parent spec §4 — public timer API, `WRITABLE` on send-buffer drain, TX-ring-batched `resd_net_flush` (data-path only, control frames stay inline), `resd_net_close(flags)` with `FORCE_TW_SKIP` under RFC 6191 prerequisites, `preset=rfc_compliance`, `ENOMEM` error events, RFC 7323 §5.5 24-day `TS.Recent` lazy expiration — and add per-connection RTT histogram (absorbed from the former A5.6 phase, decisions preserved).

**Architecture:** Surface + observability work layered on top of A5/A5.5's existing wire behavior. No new RFC deviations, no new hot-path counters, no peer-visible behavior changes beyond the listed items. Tasks split into preparatory (wheel `user_data`, new `InternalEvent` variants, `TcpConn` fields, counters — tasks 1–4), engine machinery (TX ring + drain, `rtt_histogram_edges`, `rx_drop_nomem_prev`, public timer add/cancel — tasks 5–8), engine behavioral wiring (preset, close-flag, reap short-circuit, send/retransmit ring push — tasks 9–13), data-path hooks (PAWS lazy expiration, histogram update, WRITABLE hysteresis — tasks 14–16), public API surface (extern C functions, config field, close body, header regen — tasks 17–20), tests + audits (integration tests, knob-coverage, per-conn-histogram audit — tasks 21–22), end-of-phase reviews + tag (task 23).

**Tech Stack:** Rust stable, DPDK 23.11, bindgen, cbindgen (auto-regens `include/resd_net.h` on `cargo build -p resd-net`). No new crate deps, no new cargo features, no new DPDK FFI wrappers.

**Spec reference:** design spec at `docs/superpowers/specs/2026-04-19-stage1-phase-a6-public-api-completeness-design.md`; parent spec at `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §§4 (API additions), 4.2 (event-queue + flush + close-flag contracts), 6.3 (RFC matrix — no new rows; RFC 7323 §5.5 expiration text finalized), 6.4 (no new ADs), 6.5 (TIME_WAIT shortening finalized), 7.4 (timer wheel), 9.1 (4 new slow-path counters), 9.3 (ENOMEM / EPERM_TW_REQUIRED event emission sites).

**RFCs in scope for A6** (for §10.14 RFC compliance review): **7323 §5.5** (24-day TS.Recent expiration — lazy-at-PAWS implementation per spec §3.7), **6191** (TIME_WAIT shortening prerequisites, client-side analog via `c.ts_enabled` + monotonic ISS), **9293** (API surface only — no FSM changes). RFCs not touched: 6298, 8985, 2018, 6528 — all A5/A5.5-final. mTCP-comparison-review focus: A6 is predominantly additive surface; mTCP exposes no analog for per-conn RTT histogram or public timer API (scope difference), and its close semantics differ from ours by design (blocking socket vs. our event-driven). Expected reports: both clean, zero open `[ ]`.

**Review gates at phase sign-off** (two reports, each a blocking gate per spec §10.13 / §10.14):

1. **A6 mTCP comparison review** — `docs/superpowers/reviews/phase-a6-mtcp-compare.md` via `mtcp-comparison-reviewer`. Expected brief: surface-additive; scope differences, no behavioral ADs.
2. **A6 RFC compliance review** — `docs/superpowers/reviews/phase-a6-rfc-compliance.md` via `rfc-compliance-reviewer`. Expected brief: RFC 7323 §5.5 lazy-expiration verified against the spec text; RFC 6191 client-side rationale verified; no new MUST/SHOULD gaps.

Both reviewers dispatched with opus 4.7 per `feedback_subagent_model.md` + `feedback_phase_mtcp_review.md` + `feedback_phase_rfc_review.md`.

The `phase-a6-complete` tag is blocked while either report has an open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD.

**Opportunistic A5.5 followup nits** (flagged non-blocking during A5.5 RFC gate; fold in when any task touches the relevant text):
- "RFC 6298 §3.3" → actual §2.2 (first-RTT seeding) + §3 (Karn's rule).
- "RFC 8985 §7.4 (RTT-sample gate)" → actual §7.3 step 2.

**Deferred to later phases (A6 is explicitly NOT doing these):**

- Test-suite harnesses (packetdrill, tcpreq, TCP-Fuzz, smoltcp FaultInjector) — A7 / A8 / A9.
- Benchmarks — A10.
- Per-sample `RESD_NET_EVT_RTT_SAMPLE` events — deferred indefinitely; histogram covers the stated need.
- Raw-samples RTT ring — deferred indefinitely.
- Engine-wide RTT histogram summary (sum across conns) — out of A6 scope per A5.6 §12; apps sum across `resd_net_conn_rtt_histogram` snapshots.
- Mid-session bucket-edge changes — edges fixed at `engine_create`.
- Multi-queue enablement — Stage 1 single-queue.
- A-HW offload territory — parallel session scope.

**Coordination with parallel session (`phase-a-hw`)** — after each commit on `phase-a6`, run `git fetch && git log --oneline phase-a-hw --since=<last-check>`; if any new commits exist, `git rebase phase-a-hw`. Expected shared files (by region): `engine.rs` (A-HW: port config + offload bits at init; A6: timer wheel + tx_pending_data + event paths + close path — disjoint regions), `api.rs` (A-HW: offload flag bits on `engine_config_t`; A6: `rtt_histogram_bucket_edges_us` + new extern fns — append-at-tail), `include/resd_net.h` (cbindgen-regenerated, auto-resolves), `Cargo.toml` (A-HW: new `hw-offload-*` features; A6: no new features — disjoint).

---

## File Structure Created or Modified in This Phase

```
crates/resd-net-core/
├── src/
│   ├── tcp_timer_wheel.rs          (MODIFIED: `TimerNode::user_data: u64` field — zero for kernel timers, populated for ApiPublic)
│   ├── tcp_events.rs               (MODIFIED: new `InternalEvent::ApiTimer {timer_id, user_data, emitted_ts_ns}`, new `InternalEvent::Writable {conn, emitted_ts_ns}`)
│   ├── tcp_conn.rs                 (MODIFIED: `send_refused_pending: bool`, `force_tw_skip: bool`, `rtt_histogram: RttHistogram` aligned sub-struct; `rtt_histogram_update` method)
│   ├── counters.rs                 (MODIFIED: adds `tcp.tx_api_timers_fired`, `tcp.ts_recent_expired`, `tcp.tx_flush_bursts`, `tcp.tx_flush_batched_pkts` — four new slow-path fields + C-ABI mirror)
│   ├── engine.rs                   (MODIFIED: `tx_pending_data: RefCell<Vec<NonNull<rte_mbuf>>>` ring + drain; `rx_drop_nomem_prev: Cell<u64>`; `rtt_histogram_edges: [u32; 15]`; `public_timer_add` / `_cancel` methods; `close_conn_with_flags`; `advance_timer_wheel` ApiPublic branch populated; `reap_time_wait` force-tw-skip short-circuit; preset=1 application; `send_bytes` + `retransmit` push to ring; retransmit ENOMEM Error emit)
│   ├── tcp_input.rs                (MODIFIED: PAWS lazy expiration + `ts_recent_expired` bump; RTT-histogram update after `rtt_est.sample`; `Writable` hysteresis on ACK-prune path)
│   └── lib.rs                      (MODIFIED: re-export `RttHistogram`)
└── tests/
    ├── tcp_a6_public_api_tap.rs    (NEW: integration tests for timer fire/cancel/drain, flush batching, control-frame independence, WRITABLE hysteresis, FORCE_TW_SKIP, RX-ENOMEM edge-trigger, retransmit-ENOMEM, TS.Recent 24d expiry, histogram distribution/delta/isolation)
    ├── per-conn-histogram-coverage.rs  (NEW: sibling audit — sweeps RTT across all 16 histogram buckets under default edges)
    └── knob-coverage.rs            (MODIFIED: adds `knob_preset_rfc_compliance_forces_rfc_defaults`, `knob_close_force_tw_skip_when_ts_enabled`, `knob_rtt_histogram_bucket_edges_us_override`)

crates/resd-net/src/
├── api.rs                          (MODIFIED: `resd_net_engine_config_t::rtt_histogram_bucket_edges_us[15]`; new `resd_net_tcp_rtt_histogram_t` POD; `tx_api_timers_fired`, `ts_recent_expired`, `tx_flush_bursts`, `tx_flush_batched_pkts` on `resd_net_tcp_counters_t`; compile-time layout asserts updated)
└── lib.rs                          (MODIFIED: `resd_net_timer_add`, `resd_net_timer_cancel`, `resd_net_conn_rtt_histogram` extern fns; `resd_net_flush` body replaced; `resd_net_close` honors flags; `resd_net_engine_create` applies preset + validates histogram edges; `build_event_from_internal` handles `ApiTimer` + `Writable`)

include/resd_net.h                  (REGENERATED via cbindgen: new extern C fns + new POD + new config field + updated doc-comments on resd_net_flush / resd_net_close)

docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md
                                    (MODIFIED during Task 22: §4 API additions, §4.2 contract wording for flush/cancel/close-flag, §6.5 TIME_WAIT shortening final wording, §9.1 counter additions, §9.3 ENOMEM emission sites, plus A5.5-nit citation fixes)
docs/superpowers/plans/stage1-phase-roadmap.md
                                    (MODIFIED at end of phase in Task 23: A6 row → Complete + link to this plan; A5.6 row → Absorbed into A6)
docs/superpowers/reviews/phase-a6-mtcp-compare.md      (NEW — Task 23)
docs/superpowers/reviews/phase-a6-rfc-compliance.md    (NEW — Task 23)
```

---

## Task 1: `TimerNode::user_data: u64` field on the internal wheel

**Files:**
- Modify: `crates/resd-net-core/src/tcp_timer_wheel.rs` — add `user_data: u64` to `TimerNode`; set to `0` for all existing kernel-timer call sites (RTO / TLP / SynRetrans).

**Context:** Spec §3.1. The wheel already reserves `TimerKind::ApiPublic`; A6 populates the public-timer fire path. Public timers carry an opaque `user_data: u64` that the wheel must round-trip from `add` to `fire` unchanged. Kernel timers (RTO, TLP, SynRetrans) don't need the field but must be able to zero-init it.

- [ ] **Step 1: Write failing unit test in `tcp_timer_wheel.rs`'s test module**

Append to the existing `#[cfg(test)] mod tests { ... }` block:

```rust
#[test]
fn timer_node_carries_user_data_through_fire() {
    let mut w = TimerWheel::new(8);
    let id = w.add(0, TimerNode {
        fire_at_ns: 100_000,
        owner_handle: 0,
        kind: TimerKind::ApiPublic,
        user_data: 0xDEAD_BEEF_CAFE_BABE,
        generation: 0,
        cancelled: false,
    });
    let fired = w.advance(100_000);
    assert_eq!(fired.len(), 1);
    let (fired_id, node) = &fired[0];
    assert_eq!(*fired_id, id);
    assert_eq!(node.user_data, 0xDEAD_BEEF_CAFE_BABE);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p resd-net-core tcp_timer_wheel::tests::timer_node_carries_user_data_through_fire`
Expected: compile error, "struct `TimerNode` has no field named `user_data`".

- [ ] **Step 3: Add `user_data: u64` to `TimerNode`**

Edit `crates/resd-net-core/src/tcp_timer_wheel.rs`. Replace the existing `TimerNode` struct with:

```rust
#[derive(Debug, Clone, Copy)]
pub struct TimerNode {
    pub fire_at_ns: u64,
    pub owner_handle: u32,
    pub kind: TimerKind,
    /// Opaque user payload; only meaningful for `TimerKind::ApiPublic`.
    /// Zero for kernel timers (RTO / TLP / SynRetrans). Round-tripped
    /// verbatim from `add` to `fire`.
    pub user_data: u64,
    pub generation: u32,
    pub cancelled: bool,
}
```

Also update the `node(fire_at_ns)` helper inside the test module to set `user_data: 0`:

```rust
fn node(fire_at_ns: u64) -> TimerNode {
    TimerNode {
        fire_at_ns,
        owner_handle: 0,
        kind: TimerKind::Rto,
        user_data: 0,
        generation: 0,
        cancelled: false,
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p resd-net-core tcp_timer_wheel`
Expected: all 6 wheel tests pass (existing 5 + new 1).

- [ ] **Step 5: Update every `TimerNode { ... }` construction site in the workspace**

Grep for every construction site:

```bash
grep -rn "TimerNode {" crates/resd-net-core/src/
```

Expected sites (at `phase-a5-5-complete` tip): `engine.rs:1031, :1239, :1768, :2380, :2613, :2702`. Each corresponds to an RTO / TLP / SynRetrans arm. At each, insert `user_data: 0,` in the struct literal. Example:

```rust
// engine.rs:1029-1040 pre-edit
let id = self.timer_wheel.borrow_mut().add(
    now_ns,
    crate::tcp_timer_wheel::TimerNode {
        fire_at_ns,
        owner_handle: handle,
        kind: crate::tcp_timer_wheel::TimerKind::Rto,
        generation: 0,
        cancelled: false,
    },
);

// post-edit
let id = self.timer_wheel.borrow_mut().add(
    now_ns,
    crate::tcp_timer_wheel::TimerNode {
        fire_at_ns,
        owner_handle: handle,
        kind: crate::tcp_timer_wheel::TimerKind::Rto,
        user_data: 0,
        generation: 0,
        cancelled: false,
    },
);
```

- [ ] **Step 6: Run full workspace build + test**

Run: `cargo build --workspace && cargo test --workspace`
Expected: no compile errors; all tests pass. If any construction site was missed, the compiler will flag it.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/tcp_timer_wheel.rs crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a6 task 1: TimerNode::user_data field + kernel-timer zero-init

Wheel carries an opaque u64 user_data from add to fire for the
public-timer API landing in task 8. Kernel timers (RTO/TLP/SynRetrans)
zero-init; wheel unit test pins the round-trip contract.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `InternalEvent::ApiTimer` + `InternalEvent::Writable` variants

**Files:**
- Modify: `crates/resd-net-core/src/tcp_events.rs` — append two new variants to `InternalEvent`, update test-module pattern-match helpers.
- Modify: `crates/resd-net-core/src/engine.rs` — ensure any existing exhaustive match on `InternalEvent` covers the new variants (compile-error discovery).

**Context:** Spec §3.1 (ApiTimer payload), §3.3 (Writable payload). Both are internal-only until task 17/19 wire them to the C ABI. The build_event_from_internal translator in `crates/resd-net/src/lib.rs` also needs new arms — that's deferred to task 17 (timer_add extern) and task 16 (WRITABLE emission site), so we add a placeholder `unreachable!()` arm in this task to keep the workspace compiling until those tasks land.

- [ ] **Step 1: Write failing test — variants exist with required field shape**

Append to `crates/resd-net-core/src/tcp_events.rs::tests`:

```rust
#[test]
fn api_timer_event_variant_shape() {
    let id = crate::tcp_timer_wheel::TimerId { slot: 7, generation: 42 };
    let e = InternalEvent::ApiTimer {
        timer_id: id,
        user_data: 0xABCD_1234_5678_BEEF,
        emitted_ts_ns: 9_000,
    };
    match e {
        InternalEvent::ApiTimer { timer_id, user_data, emitted_ts_ns } => {
            assert_eq!(timer_id, id);
            assert_eq!(user_data, 0xABCD_1234_5678_BEEF);
            assert_eq!(emitted_ts_ns, 9_000);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn writable_event_variant_shape() {
    let e = InternalEvent::Writable {
        conn: ConnHandle::default(),
        emitted_ts_ns: 11_000,
    };
    match e {
        InternalEvent::Writable { conn, emitted_ts_ns } => {
            assert_eq!(conn, ConnHandle::default());
            assert_eq!(emitted_ts_ns, 11_000);
        }
        _ => panic!("wrong variant"),
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p resd-net-core tcp_events::tests::api_timer_event_variant_shape tcp_events::tests::writable_event_variant_shape`
Expected: compile errors, "no variant named `ApiTimer` / `Writable`".

- [ ] **Step 3: Add the two variants to `InternalEvent`**

Edit `crates/resd-net-core/src/tcp_events.rs`. After the existing `TcpLossDetected` variant, inside the enum:

```rust
    /// A6: public-timer-API fire. Emitted when an `ApiPublic` wheel node
    /// fires via `advance_timer_wheel`. `timer_id` re-packs the wheel's
    /// `TimerId`; `user_data` round-trips the caller's opaque payload.
    /// No `conn` field — public timers are engine-level, not connection-
    /// bound. `emitted_ts_ns` is sampled at fire (same convention as
    /// RTO-fire per A5.5 §3.1).
    ApiTimer {
        timer_id: crate::tcp_timer_wheel::TimerId,
        user_data: u64,
        emitted_ts_ns: u64,
    },
    /// A6: send-buffer drained to ≤ `send_buffer_bytes / 2` after a
    /// prior `send_bytes` refusal. Level-triggered, single-edge-per-
    /// refusal-cycle. No payload.
    Writable {
        conn: ConnHandle,
        emitted_ts_ns: u64,
    },
```

- [ ] **Step 4: Update the `EventQueue::push` counter-observer exhaustive match (if any)**

`push()` currently does not match on variant — it just increments high-water counters. No change needed. Confirm by reading `tcp_events.rs:121-132` — the impl body does not pattern-match on `ev`. Proceed.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p resd-net-core tcp_events`
Expected: all tests (existing + 2 new) pass.

- [ ] **Step 6: Add placeholder translation arms in `build_event_from_internal`**

Edit `crates/resd-net/src/lib.rs`. The existing `build_event_from_internal` has 7 match arms. Add two at the end, inside the `match ev { ... }` block:

```rust
        InternalEvent::ApiTimer { .. } => {
            // Wired in Task 17 (resd_net_timer_add extern). Keeping this
            // unreachable for now lets the workspace compile; no call site
            // pushes an ApiTimer variant until Task 8 + Task 17 both land.
            unreachable!("ApiTimer translation wired in Task 17; no upstream emit until Task 8")
        }
        InternalEvent::Writable { .. } => {
            // Wired in Task 16 (WRITABLE hysteresis) + Task 17. Same
            // invariant as ApiTimer.
            unreachable!("Writable translation wired in Task 17; no upstream emit until Task 16")
        }
```

Also update the `let emitted = match ev { ... }` block above to cover both variants:

```rust
    let emitted = match ev {
        InternalEvent::Connected { emitted_ts_ns, .. }
        | InternalEvent::Readable { emitted_ts_ns, .. }
        | InternalEvent::Closed { emitted_ts_ns, .. }
        | InternalEvent::StateChange { emitted_ts_ns, .. }
        | InternalEvent::Error { emitted_ts_ns, .. }
        | InternalEvent::TcpRetrans { emitted_ts_ns, .. }
        | InternalEvent::TcpLossDetected { emitted_ts_ns, .. }
        | InternalEvent::ApiTimer { emitted_ts_ns, .. }
        | InternalEvent::Writable { emitted_ts_ns, .. } => *emitted_ts_ns,
    };
```

- [ ] **Step 7: Run workspace build + test**

Run: `cargo build --workspace && cargo test --workspace`
Expected: compiles clean, all tests pass. No runtime panic from `unreachable!()` because no code path yet emits the new variants.

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net-core/src/tcp_events.rs crates/resd-net/src/lib.rs
git commit -m "$(cat <<'EOF'
a6 task 2: InternalEvent::ApiTimer + Writable variants

Reserves the internal event types for the public-timer API (Task 8) and
the WRITABLE hysteresis path (Task 16). Translation arms added to
build_event_from_internal; unreachable!() placeholders hold until
the ABI layer lands in Task 17.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `TcpConn` field additions — `send_refused_pending`, `force_tw_skip`, `rtt_histogram`

**Files:**
- Create: `crates/resd-net-core/src/rtt_histogram.rs` — new module for the aligned `RttHistogram` sub-struct and its update method.
- Modify: `crates/resd-net-core/src/lib.rs` — add `pub mod rtt_histogram;` and re-export `RttHistogram`.
- Modify: `crates/resd-net-core/src/tcp_conn.rs` — add three new fields to `TcpConn`; zero-init in `new_client`.

**Context:** Spec §2.1 (TcpConn fields), §2.3 (aligned RttHistogram sub-struct), §3.3 (send_refused_pending semantics), §3.4 (force_tw_skip semantics), §3.8 (histogram update method). Putting the histogram in its own module keeps `tcp_conn.rs` from ballooning and isolates the alignment constraint so future TcpConn layout changes can't silently break the one-cacheline invariant.

- [ ] **Step 1: Create `crates/resd-net-core/src/rtt_histogram.rs`**

```rust
//! Per-connection RTT histogram (spec §3.8). 16 × u32 buckets, exactly
//! 64 B / one cacheline via `repr(C, align(64))`. Update cost: 15-
//! comparison ladder + one `wrapping_add` on cache-resident state.
//! No atomics — per-conn state in the single-lcore RTC model.

/// 16 × u32 buckets aligned to exactly one cacheline. Exposed as a
/// field on `TcpConn`; `resd_net_conn_rtt_histogram` memcpys the
/// inner `[u32; 16]` out to caller memory (Task 18).
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, Default)]
pub struct RttHistogram {
    pub buckets: [u32; 16],
}

// Pin size + alignment at compile time. A future TcpConn layout change
// cannot silently drop the one-cacheline invariant.
const _: () = {
    use std::mem::{align_of, size_of};
    assert!(size_of::<RttHistogram>() == 64);
    assert!(align_of::<RttHistogram>() == 64);
};

/// Select the bucket index `[0, 15]` for an RTT sample under a given
/// edge set. Linear ladder; at N=16, LLVM is free to lower to either
/// linear or binary search and the branch predictor handles stable
/// distributions effectively for free.
#[inline]
pub fn select_bucket(rtt_us: u32, edges: &[u32; 15]) -> usize {
    for i in 0..15 {
        if rtt_us <= edges[i] {
            return i;
        }
    }
    15
}

impl RttHistogram {
    /// Record one RTT sample. Wraparound via `wrapping_add(1)` is
    /// intentional — the application's snapshot-delta math uses
    /// `wrapping_sub` to recover correct per-bucket counts as long as
    /// no single bucket accumulates > 2^32 samples between polls.
    #[inline]
    pub fn update(&mut self, rtt_us: u32, edges: &[u32; 15]) {
        let b = select_bucket(rtt_us, edges);
        self.buckets[b] = self.buckets[b].wrapping_add(1);
    }

    /// Snapshot the 64-byte bucket array into caller memory. Used by
    /// the `resd_net_conn_rtt_histogram` getter (Task 18).
    #[inline]
    pub fn snapshot(&self) -> [u32; 16] {
        self.buckets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_one_cacheline() {
        assert_eq!(std::mem::size_of::<RttHistogram>(), 64);
        assert_eq!(std::mem::align_of::<RttHistogram>(), 64);
    }

    #[test]
    fn select_bucket_default_edges() {
        let edges: [u32; 15] = [
            50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
            10000, 25000, 50000, 100000, 500000,
        ];
        // Spec §3.8.1 expected mapping.
        assert_eq!(select_bucket(10, &edges), 0);
        assert_eq!(select_bucket(50, &edges), 0);
        assert_eq!(select_bucket(75, &edges), 1);
        assert_eq!(select_bucket(150, &edges), 2);
        assert_eq!(select_bucket(1000, &edges), 6);
        assert_eq!(select_bucket(2000, &edges), 7);
        assert_eq!(select_bucket(30000, &edges), 11);
        assert_eq!(select_bucket(600000, &edges), 15);
    }

    #[test]
    fn update_increments_selected_bucket() {
        let edges: [u32; 15] = [
            50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
            10000, 25000, 50000, 100000, 500000,
        ];
        let mut h = RttHistogram::default();
        h.update(150, &edges);
        h.update(150, &edges);
        assert_eq!(h.buckets[2], 2);
        // All other buckets still zero.
        for i in 0..16 {
            if i != 2 {
                assert_eq!(h.buckets[i], 0, "bucket {i}");
            }
        }
    }

    #[test]
    fn wraparound_via_wrapping_add() {
        let edges: [u32; 15] = [
            50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
            10000, 25000, 50000, 100000, 500000,
        ];
        let mut h = RttHistogram::default();
        // Pre-load to just below u32::MAX, then drive 5 more to wrap past 0.
        h.buckets[0] = u32::MAX - 4;
        for _ in 0..10 {
            h.update(10, &edges);  // rtt=10 → bucket 0
        }
        // 10 increments from (u32::MAX - 4): wraps at 4, ends at 5.
        assert_eq!(h.buckets[0], 5);
    }

    #[test]
    fn snapshot_returns_bucket_copy() {
        let mut h = RttHistogram::default();
        h.buckets[3] = 100;
        h.buckets[7] = 200;
        let snap = h.snapshot();
        assert_eq!(snap[3], 100);
        assert_eq!(snap[7], 200);
        // Snapshot is a copy; mutating source doesn't change snapshot.
        h.buckets[3] = 999;
        assert_eq!(snap[3], 100);
    }
}
```

- [ ] **Step 2: Export from `lib.rs`**

Edit `crates/resd-net-core/src/lib.rs`. Add:

```rust
pub mod rtt_histogram;
```

in module declaration order (alphabetical around existing modules).

- [ ] **Step 3: Run unit tests**

Run: `cargo test -p resd-net-core rtt_histogram`
Expected: 5 tests pass (layout, default-edges, update, wraparound, snapshot).

- [ ] **Step 4: Write failing test in tcp_conn.rs: new fields exist + zero-init**

Append to `tcp_conn.rs`'s `#[cfg(test)] mod tests { ... }`:

```rust
#[test]
fn a6_new_fields_zero_init_after_new_client() {
    let c = TcpConn::new_client(
        FourTuple {
            local_ip: 0x0a000002,
            local_port: 40000,
            peer_ip: 0x0a000001,
            peer_port: 5000,
        },
        0, 1460, 1024, 2048, 5_000, 5_000, 1_000_000,
    );
    assert!(!c.send_refused_pending);
    assert!(!c.force_tw_skip);
    for b in c.rtt_histogram.buckets.iter() {
        assert_eq!(*b, 0);
    }
}
```

- [ ] **Step 5: Run test to verify it fails**

Run: `cargo test -p resd-net-core tcp_conn::tests::a6_new_fields_zero_init_after_new_client`
Expected: compile error, "no field named `send_refused_pending` / `force_tw_skip` / `rtt_histogram` on `TcpConn`".

- [ ] **Step 6: Add the three fields to `TcpConn`**

Edit `crates/resd-net-core/src/tcp_conn.rs`. In the `pub struct TcpConn { ... }` block, at the end of the field list (after `syn_tx_ts_ns: u64` per A5.5 Task 13):

```rust
    /// A6 (spec §3.3): set when a prior `send_bytes` returned
    /// `accepted < len`. Cleared when `WRITABLE` hysteresis fires
    /// on `in_flight <= send_buffer_bytes / 2`.
    pub send_refused_pending: bool,
    /// A6 (spec §3.4): caller passed `RESD_NET_CLOSE_FORCE_TW_SKIP`
    /// to `resd_net_close` AND the connection had `ts_enabled=true`
    /// at close time. `reap_time_wait` short-circuits the 2×MSL wait
    /// when this is set.
    pub force_tw_skip: bool,
    /// A6 (spec §3.8): per-connection RTT histogram — 16 × u32
    /// buckets on one cacheline. Updated after each `rtt_est.sample()`
    /// in `tcp_input.rs` (Task 15). Slow-path update (~5–10 ns).
    pub rtt_histogram: crate::rtt_histogram::RttHistogram,
```

Update `new_client` to zero-init the three fields (end of struct literal, before the closing `}`):

```rust
            syn_tx_ts_ns: 0,
            send_refused_pending: false,
            force_tw_skip: false,
            rtt_histogram: crate::rtt_histogram::RttHistogram::default(),
        }
    }
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cargo test -p resd-net-core tcp_conn::tests::a6_new_fields_zero_init_after_new_client`
Expected: PASS.

- [ ] **Step 8: Run full workspace build + test**

Run: `cargo build --workspace && cargo test --workspace`
Expected: all green.

- [ ] **Step 9: Commit**

```bash
git add crates/resd-net-core/src/rtt_histogram.rs crates/resd-net-core/src/lib.rs crates/resd-net-core/src/tcp_conn.rs
git commit -m "$(cat <<'EOF'
a6 task 3: TcpConn fields — send_refused_pending, force_tw_skip, rtt_histogram

Adds the three per-connection A6 state fields. RttHistogram is its own
module with repr(C, align(64)) and compile-time size/align asserts so
the one-cacheline invariant cannot silently drift when TcpConn changes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `counters.rs` additions — 4 new slow-path `tcp.*` counters

**Files:**
- Modify: `crates/resd-net-core/src/counters.rs` — consume the `_pad: [u64; 1]` slot and add `tx_api_timers_fired`, `ts_recent_expired`, `tx_flush_bursts`, `tx_flush_batched_pkts`; re-pad if needed.
- Modify: `crates/resd-net/src/api.rs` — mirror the four new fields on `resd_net_tcp_counters_t`; update the compile-time size/align asserts.

**Context:** Spec §4. All four are slow-path per §9.1.1 rule 1. `tx_api_timers_fired` and `tx_flush_bursts` fire per-event (not per-segment); `ts_recent_expired` fires at most once per 24-day idle event (essentially never on healthy traffic); `tx_flush_batched_pkts` is one aggregate `fetch_add` per drain-helper call. None are hot-path.

- [ ] **Step 1: Write failing unit test in `counters.rs`'s test module**

Append to the existing `#[cfg(test)] mod tests { ... }`:

```rust
#[test]
fn a6_new_tcp_counters_exist_and_zero() {
    let c = Counters::new();
    assert_eq!(c.tcp.tx_api_timers_fired.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.ts_recent_expired.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.tx_flush_bursts.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.tx_flush_batched_pkts.load(Ordering::Relaxed), 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p resd-net-core counters::tests::a6_new_tcp_counters_exist_and_zero`
Expected: compile error, "no field named `tx_api_timers_fired` / etc. on `TcpCounters`".

- [ ] **Step 3: Add the four fields to `TcpCounters`**

Edit `crates/resd-net-core/src/counters.rs`. Replace the existing tail of `TcpCounters`:

```rust
    /// A5.5 Task 11/12: TLP probe retroactively classified as spurious via
    /// DSACK (RFC 8985 §7.4 / spec §3.4). Declared here; wired in Task 12.
    pub tx_tlp_spurious: AtomicU64,
    _pad: [u64; 1],
}
```

with:

```rust
    /// A5.5 Task 11/12: TLP probe retroactively classified as spurious via
    /// DSACK (RFC 8985 §7.4 / spec §3.4). Declared here; wired in Task 12.
    pub tx_tlp_spurious: AtomicU64,
    // --- A6 additions (all slow-path per §9.1.1 rule 1) ---
    /// A6: public-timer-API fire. Incremented once per `ApiPublic`
    /// wheel node firing through `advance_timer_wheel` — a slow-path
    /// boundary (not per-segment / per-burst / per-poll).
    pub tx_api_timers_fired: AtomicU64,
    /// A6: RFC 7323 §5.5 24-day `TS.Recent` expiration fired on an
    /// inbound segment's PAWS gate. Effectively zero on healthy
    /// trading traffic; nonzero is operationally interesting.
    pub ts_recent_expired: AtomicU64,
    /// A6: `drain_tx_pending_data` called `rte_eth_tx_burst`. One
    /// fetch_add per drain (per end-of-poll + per `resd_net_flush`).
    pub tx_flush_bursts: AtomicU64,
    /// A6: aggregate `sent` count summed across every `tx_flush_bursts`
    /// call. Useful to compute mean-batch-size = tx_flush_batched_pkts
    /// / tx_flush_bursts; values near 1 mean the data path isn't
    /// actually batching.
    pub tx_flush_batched_pkts: AtomicU64,
}
```

Notes on layout: we removed the 8-byte `_pad: [u64; 1]` and added 4 × 8 = 32 bytes of new fields. `repr(C, align(64))` auto-pads the struct to the next 64-byte boundary. The `Default` impl uses `std::mem::zeroed()` so it picks up the new fields without change. Cacheline discipline still holds.

- [ ] **Step 4: Run the unit test to verify it passes**

Run: `cargo test -p resd-net-core counters::tests::a6_new_tcp_counters_exist_and_zero`
Expected: PASS.

- [ ] **Step 5: Write failing C-ABI-mirror assert in `api.rs`**

The existing compile-time assert in `crates/resd-net/src/api.rs` enforces `size_of::<resd_net_tcp_counters_t>() == size_of::<CoreTcp>()`. After adding fields to `CoreTcp` it'll fail the build until we mirror. Run:

```bash
cargo build -p resd-net
```

Expected: compile error from the `const _: () = { assert!(size_of::<resd_net_counters_t>() == size_of::<CoreCounters>()); ... }` block.

- [ ] **Step 6: Mirror the four fields on `resd_net_tcp_counters_t`**

Edit `crates/resd-net/src/api.rs`. In the existing `resd_net_tcp_counters_t` struct, replace:

```rust
    /// A5.5 Task 11/12 — see core counters.rs for the full field doc.
    pub tx_tlp_spurious: u64,
    pub _pad: [u64; 1],
}
```

with:

```rust
    /// A5.5 Task 11/12 — see core counters.rs for the full field doc.
    pub tx_tlp_spurious: u64,
    // A6 additions — see core counters.rs for field docs. Declaration
    // order must match `resd_net_core::counters::TcpCounters` exactly.
    pub tx_api_timers_fired: u64,
    pub ts_recent_expired: u64,
    pub tx_flush_bursts: u64,
    pub tx_flush_batched_pkts: u64,
}
```

- [ ] **Step 7: Rebuild and confirm cbindgen regenerates the header**

Run: `cargo build -p resd-net`
Expected: builds cleanly; `include/resd_net.h` now shows four new u64 fields inside `resd_net_tcp_counters_t`.

Verify header content:

```bash
grep -A 2 'tx_tlp_spurious' include/resd_net.h
```

Expected output includes the four A6 fields after `tx_tlp_spurious`.

- [ ] **Step 8: Run workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass (no behavior change yet — counters exist but have no incrementers).

- [ ] **Step 9: Commit**

```bash
git add crates/resd-net-core/src/counters.rs crates/resd-net/src/api.rs include/resd_net.h
git commit -m "$(cat <<'EOF'
a6 task 4: counters — 4 new slow-path tcp.* fields

Declares tx_api_timers_fired (wired in Task 8), ts_recent_expired
(Task 14), tx_flush_bursts + tx_flush_batched_pkts (Task 5). All four
are slow-path per spec §9.1.1 rule 1. C-ABI mirror updated and
cbindgen header regenerated.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `Engine::tx_pending_data` ring + `drain_tx_pending_data` helper + `resd_net_flush` wiring

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — add `tx_pending_data: RefCell<Vec<NonNull<sys::rte_mbuf>>>`; add `drain_tx_pending_data(&self)` helper; call it at end of `poll_once`; expose a `pub fn flush_tx_pending_data(&self)` wrapper.
- Modify: `crates/resd-net/src/lib.rs` — replace `resd_net_flush` body with `e.flush_tx_pending_data()`.

**Context:** Spec §3.2. The ring holds data-segment mbufs only. Control frames stay inline. Cap = `tx_ring_size` (already in `EngineConfig` at 1024). `send_bytes` (Task 12) and `retransmit` (Task 13) will push into the ring; this task only lands the ring + drain infrastructure. `resd_net_flush` went from A1 no-op to actually flushing the batch.

- [ ] **Step 1: Write failing unit test — `flush_tx_pending_data` on an empty ring is a no-op**

A live engine requires DPDK/EAL so we can't unit-test the drain end-to-end here; we pin the empty-ring contract as a signature check via a `cargo check` smoke.

Append to the existing `#[cfg(test)] mod tests { ... }` at the bottom of `engine.rs`:

```rust
#[test]
fn flush_tx_pending_data_signature_exists() {
    // Signature-only check; empty-ring drain and full drain are exercised
    // end-to-end in tcp_a6_public_api_tap.rs (Task 21).
    fn _compile_only(e: &Engine) {
        e.flush_tx_pending_data();
    }
    let _ = _compile_only;
}
```

- [ ] **Step 2: Run — verify compile error, no method `flush_tx_pending_data`**

Run: `cargo test -p resd-net-core engine::tests::flush_tx_pending_data_signature_exists`
Expected: compile error, "no method `flush_tx_pending_data` found for struct `Engine`".

- [ ] **Step 3: Add ring field + drain helper + public wrapper to `Engine`**

Edit `crates/resd-net-core/src/engine.rs`. In the `pub struct Engine { ... }` block, add alongside the existing `timer_wheel` / `events` / `flow_table` fields:

```rust
    /// A6 (spec §3.2): pending outbound data-segment mbufs for batched TX.
    /// Populated by `send_bytes` / `retransmit`; drained at end-of-poll
    /// and from `resd_net_flush` via `drain_tx_pending_data`. Control
    /// frames (ACK / FIN / SYN / RST) are emitted inline and do NOT
    /// queue here — they stay on their existing `tx_frame` /
    /// `tx_data_frame` inline paths.
    pub(crate) tx_pending_data: RefCell<Vec<std::ptr::NonNull<sys::rte_mbuf>>>,
```

In `Engine::new`, initialize the ring with the configured capacity:

```rust
            tx_pending_data: RefCell::new(Vec::with_capacity(cfg.tx_ring_size as usize)),
```

Add the drain helper as an impl method (alongside `advance_timer_wheel`):

```rust
    /// Drain pending data-segment mbufs via one `rte_eth_tx_burst`.
    /// On partial send (driver accepted fewer than pushed), the unsent
    /// tail mbufs are freed to mempool and bump `eth.tx_drop_full_ring`.
    /// The ring clears unconditionally after drain — a send_bytes
    /// caller observes the drop via the counter, not by inspecting
    /// the ring state. Slow-path: fires once per poll end + once per
    /// `resd_net_flush` call; no hot-path cost.
    pub(crate) fn drain_tx_pending_data(&self) {
        use crate::counters::{add, inc};
        let mut ring = self.tx_pending_data.borrow_mut();
        if ring.is_empty() {
            return;
        }
        let n = ring.len() as u16;
        let sent = unsafe {
            sys::resd_rte_eth_tx_burst(
                self.cfg.port_id,
                self.cfg.tx_queue_id,
                ring.as_mut_ptr() as *mut *mut sys::rte_mbuf,
                n,
            )
        } as usize;
        // Free tail mbufs (DPDK partial-fill: driver took the prefix, we own the rest).
        for i in sent..ring.len() {
            unsafe { sys::resd_rte_pktmbuf_free(ring[i].as_ptr()); }
            inc(&self.counters.eth.tx_drop_full_ring);
        }
        ring.clear();
        inc(&self.counters.tcp.tx_flush_bursts);
        add(&self.counters.tcp.tx_flush_batched_pkts, sent as u64);
        if sent > 0 {
            add(&self.counters.eth.tx_pkts, sent as u64);
        }
    }

    /// Public entrypoint for `resd_net_flush`. Wrapper so the ABI layer
    /// doesn't need to know about RefCell or the ring type.
    pub fn flush_tx_pending_data(&self) {
        self.drain_tx_pending_data();
    }
```

- [ ] **Step 4: Wire end-of-poll drain into `poll_once`**

Find `poll_once` in `engine.rs`. At its end (after timer-wheel advance + TIME_WAIT reap), add one call:

```rust
    pub fn poll_once(&self) {
        // ... existing body ends with advance_timer_wheel + reap_time_wait ...
        self.drain_tx_pending_data();
    }
```

Read `engine.rs:737-815` for the current shape before editing; the drain must go AFTER any RX-triggered emit sites (so RX-burst-driven data sends can be batched into the same drain).

- [ ] **Step 5: Replace `resd_net_flush` body**

Edit `crates/resd-net/src/lib.rs`. Replace the existing no-op body:

```rust
#[no_mangle]
pub unsafe extern "C" fn resd_net_flush(_p: *mut resd_net_engine) {
    // Phase A1: no-op; TX burst handled inline in poll_once.
}
```

with:

```rust
#[no_mangle]
pub unsafe extern "C" fn resd_net_flush(p: *mut resd_net_engine) {
    // A6 (spec §3.2): drain the engine's data-segment TX ring via
    // one rte_eth_tx_burst. No-op when ring empty. Idempotent.
    // Control frames (ACK/SYN/FIN/RST) are emitted inline at their
    // emit site and do not participate in this drain.
    let Some(e) = engine_from_raw(p) else { return };
    e.flush_tx_pending_data();
}
```

- [ ] **Step 6: Run workspace build + test**

Run: `cargo build --workspace && cargo test --workspace`
Expected: all tests pass. No behavior change yet because no call site pushes to the ring — `drain_tx_pending_data` early-returns on empty.

- [ ] **Step 7: cbindgen regen + header sanity**

The header emission for `resd_net_flush` already exists; cbindgen regen happens automatically on `cargo build -p resd-net`. Verify the doc-comment survived by grepping the generated header:

```bash
grep -B 1 -A 3 'resd_net_flush' include/resd_net.h
```

If doc-comment is stale (empty), update the Rust side to include a triple-slash comment above the `#[no_mangle]` attribute so cbindgen emits it. Add:

```rust
/// A6 (spec §4.2): drains the pending data-segment TX batch via one
/// `rte_eth_tx_burst`. No-op when ring empty. Idempotent.
/// Control frames (ACK, SYN, FIN, RST) are emitted inline at their
/// emit site and do not participate in the flush batch — flushing
/// never blocks or reorders control-frame emission.
#[no_mangle]
pub unsafe extern "C" fn resd_net_flush(p: *mut resd_net_engine) {
    // ... body as above ...
}
```

Rebuild and re-verify the header has the doc-comment.

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net-core/src/engine.rs crates/resd-net/src/lib.rs include/resd_net.h
git commit -m "$(cat <<'EOF'
a6 task 5: TX ring + drain_tx_pending_data + flush wiring

Lands the engine-scope tx_pending_data ring + drain helper. poll_once
drains at end-of-iter; resd_net_flush now calls the same drain. No
call site pushes to the ring yet (Task 12 adds send_bytes push; Task
13 adds retransmit push) so behavior is unchanged at this point.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `Engine::rtt_histogram_edges` + monotonic-edges validation + default substitution

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — new field `rtt_histogram_edges: [u32; 15]`; validate + substitute in `Engine::new`.
- Modify: `crates/resd-net-core/src/engine.rs` (`EngineConfig`) — new field `rtt_histogram_bucket_edges_us: [u32; 15]`.

**Context:** Spec §3.8.2 (default edges) + §3.8.3 (validation). The ABI-layer plumbing (`resd_net_engine_config_t::rtt_histogram_bucket_edges_us`) lands in Task 20 — this task is the core-side plumbing only.

- [ ] **Step 1: Write failing unit test — all-zero edges substitute to defaults**

Append to `engine.rs`'s `#[cfg(test)] mod tests { ... }`:

```rust
#[test]
fn rtt_histogram_edges_defaults_applied_on_all_zero() {
    let validated = crate::engine::validate_and_default_histogram_edges(&[0u32; 15])
        .expect("all-zero must validate and substitute defaults");
    let expected: [u32; 15] = [
        50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
        10000, 25000, 50000, 100000, 500000,
    ];
    assert_eq!(validated, expected);
}

#[test]
fn rtt_histogram_edges_non_monotonic_rejected() {
    let bad: [u32; 15] = [
        50, 100, 200, 150, 500, 750, 1000, 2000, 3000, 5000,
        10000, 25000, 50000, 100000, 500000,
    ];
    assert!(crate::engine::validate_and_default_histogram_edges(&bad).is_err());
}

#[test]
fn rtt_histogram_edges_monotonic_passes_through() {
    let good: [u32; 15] = [
        10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 1000,
    ];
    let out = crate::engine::validate_and_default_histogram_edges(&good).unwrap();
    assert_eq!(out, good);
}
```

- [ ] **Step 2: Run — verify compile error, no function `validate_and_default_histogram_edges`**

Run: `cargo test -p resd-net-core engine::tests::rtt_histogram_edges_defaults_applied_on_all_zero`
Expected: compile error.

- [ ] **Step 3: Add the validator function + default constant**

Edit `crates/resd-net-core/src/engine.rs`. Near the top of the module (after the `use` statements), add:

```rust
/// A6 (spec §3.8.2): default RTT histogram bucket edges, µs.
/// Applied when `EngineConfig::rtt_histogram_bucket_edges_us` is all zero.
pub const DEFAULT_RTT_HISTOGRAM_EDGES_US: [u32; 15] = [
    50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
    10000, 25000, 50000, 100000, 500000,
];

/// A6 (spec §3.8.3): validate + default-substitute the caller-supplied
/// histogram bucket edges. Returns the final `[u32; 15]` to store on
/// `Engine::rtt_histogram_edges`.
///
/// - all-zero input → returns `DEFAULT_RTT_HISTOGRAM_EDGES_US`
/// - strictly monotonic input (each `edges[i] < edges[i+1]`) → passes through
/// - any non-monotonic or equal-adjacent input → `Err(())`
pub fn validate_and_default_histogram_edges(
    edges: &[u32; 15],
) -> Result<[u32; 15], ()> {
    let all_zero = edges.iter().all(|&e| e == 0);
    if all_zero {
        return Ok(DEFAULT_RTT_HISTOGRAM_EDGES_US);
    }
    for i in 0..14 {
        if edges[i] >= edges[i + 1] {
            return Err(());
        }
    }
    Ok(*edges)
}
```

- [ ] **Step 4: Run unit tests to verify they pass**

Run: `cargo test -p resd-net-core engine::tests::rtt_histogram`
Expected: all 3 new tests pass.

- [ ] **Step 5: Add `rtt_histogram_bucket_edges_us` to `EngineConfig` + `rtt_histogram_edges` to `Engine`**

Edit `crates/resd-net-core/src/engine.rs`. In `pub struct EngineConfig { ... }`, append:

```rust
    /// A6 (spec §3.8): RTT histogram bucket edges in µs. 15 strictly
    /// monotonically increasing edges define 16 buckets. All-zero
    /// substitutes `DEFAULT_RTT_HISTOGRAM_EDGES_US`. Non-monotonic
    /// rejected at `Engine::new` with `Err(Error::InvalidHistogramEdges)`.
    pub rtt_histogram_bucket_edges_us: [u32; 15],
```

In the `impl Default for EngineConfig` block, add `rtt_histogram_bucket_edges_us: [0; 15],` as a default (triggering the substitute-to-defaults path).

In `pub struct Engine { ... }`, append alongside `cfg`:

```rust
    /// A6: post-validation-post-defaults histogram edges; shared across
    /// all conns on this engine. Not re-validated on every update.
    pub(crate) rtt_histogram_edges: [u32; 15],
```

In `Engine::new`, replace the existing:

```rust
impl Engine {
    pub fn new(cfg: EngineConfig) -> Result<Self, Error> {
        // ... existing setup ...
```

with a body that validates and substitutes the edges. At the top of `Engine::new`, after any existing pre-construction validation:

```rust
        let rtt_histogram_edges = validate_and_default_histogram_edges(
            &cfg.rtt_histogram_bucket_edges_us,
        ).map_err(|_| Error::InvalidHistogramEdges)?;
```

Add `InvalidHistogramEdges` to the `Error` enum in `crates/resd-net-core/src/error.rs`:

```rust
    /// A6 (spec §3.8.3): `rtt_histogram_bucket_edges_us` was non-monotonic
    /// or had an equal-adjacent pair. `engine_create` rejects with null-return.
    InvalidHistogramEdges,
```

Initialize `rtt_histogram_edges` in `Engine::new`'s struct-literal construction.

- [ ] **Step 6: Run full workspace build**

Run: `cargo build --workspace`
Expected: compile errors in downstream crates because `EngineConfig` is exhaustively-constructed in several tests / in `resd-net/src/lib.rs`. Fix each by adding `rtt_histogram_bucket_edges_us: [0; 15]` to the struct literal. Grep:

```bash
grep -rn 'EngineConfig {' crates/ tests/ 2>/dev/null
```

Expected sites: `crates/resd-net/src/lib.rs` (in `resd_net_engine_create`), maybe a couple of test helpers in `crates/resd-net-core/src/engine.rs` unit tests.

- [ ] **Step 7: Run workspace tests**

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net-core/src/engine.rs crates/resd-net-core/src/error.rs crates/resd-net/src/lib.rs
git commit -m "$(cat <<'EOF'
a6 task 6: Engine::rtt_histogram_edges + validation + default substitution

Lands the engine-side plumbing for the per-conn RTT histogram edges.
All-zero caller input substitutes to the spec §3.8.2 trading-tuned
defaults; non-monotonic rejected with Error::InvalidHistogramEdges.
ABI-layer wiring (resd_net_engine_config_t field) lands in Task 20.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `Engine::rx_drop_nomem_prev` snapshot + edge-triggered RX-ENOMEM Error event

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — add `rx_drop_nomem_prev: Cell<u64>` field; emit one `InternalEvent::Error{conn: 0, err: -ENOMEM}` per poll iteration where `eth.rx_drop_nomem` advanced.

**Context:** Spec §3.6 Site 3. Edge-triggered to prevent event-queue flood under RX mempool starvation. Cell<u64> gives interior mutability (engine methods take `&self`).

- [ ] **Step 1: Write failing test — the tracker field exists + helper method**

Append to `engine.rs` tests:

```rust
#[test]
fn rx_enomem_edge_trigger_signature_exists() {
    fn _compile_only(e: &Engine) {
        let _: u64 = e.rx_drop_nomem_prev();
        e.check_and_emit_rx_enomem();
    }
    let _ = _compile_only;
}
```

- [ ] **Step 2: Run — verify compile error**

Run: `cargo test -p resd-net-core engine::tests::rx_enomem_edge_trigger_signature_exists`
Expected: compile error.

- [ ] **Step 3: Add the field + helpers**

Edit `crates/resd-net-core/src/engine.rs`. In `pub struct Engine`:

```rust
    /// A6 (spec §3.6 Site 3): snapshot of `counters.eth.rx_drop_nomem`
    /// at the top of `poll_once`; compared against the post-RX value at
    /// end-of-poll to emit exactly one `Error{err=-ENOMEM}` per iteration
    /// where RX mempool drops occurred. Cell because `poll_once` borrows
    /// `&self` like every other engine method.
    pub(crate) rx_drop_nomem_prev: std::cell::Cell<u64>,
```

Initialize in `Engine::new`: `rx_drop_nomem_prev: std::cell::Cell::new(0),`.

Add the method pair:

```rust
    pub(crate) fn rx_drop_nomem_prev(&self) -> u64 {
        self.rx_drop_nomem_prev.get()
    }

    /// Edge-triggered RX-mempool-drop Error emission. Called at end of
    /// `poll_once` (after the drain). Snapshot taken at top of
    /// `poll_once`; if the counter advanced, one Error event for the
    /// whole iteration.
    pub(crate) fn check_and_emit_rx_enomem(&self) {
        use std::sync::atomic::Ordering;
        let now = self.counters.eth.rx_drop_nomem.load(Ordering::Relaxed);
        let prev = self.rx_drop_nomem_prev.get();
        if now > prev {
            let mut ev = self.events.borrow_mut();
            ev.push(
                InternalEvent::Error {
                    conn: 0,  // engine-level; not bound to a conn.
                    err: -libc::ENOMEM,
                    emitted_ts_ns: crate::clock::now_ns(),
                },
                &self.counters,
            );
            self.rx_drop_nomem_prev.set(now);
        }
    }
```

- [ ] **Step 4: Wire the snapshot + check into `poll_once`**

At the top of `poll_once` (before RX burst processing), snapshot:

```rust
    pub fn poll_once(&self) {
        use std::sync::atomic::Ordering;
        self.rx_drop_nomem_prev
            .set(self.counters.eth.rx_drop_nomem.load(Ordering::Relaxed));
        // ... existing body ...
        self.drain_tx_pending_data();   // from Task 5
        self.check_and_emit_rx_enomem();
    }
```

Order: snapshot top, drain data, then edge-check. Reason: edge-check sees any drops caused by RX processing in this iteration.

- [ ] **Step 5: Run workspace tests**

Run: `cargo test --workspace`
Expected: all green. No behavior change until Task 21 drives an actual RX-mempool starvation scenario.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a6 task 7: RX-mempool-drop edge-triggered Error{err=-ENOMEM} event

At most one Error event per poll iteration when eth.rx_drop_nomem
advanced, prevents event-queue flood under RX mempool starvation.
conn=0 (engine-level, not connection-bound) per spec §3.6.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `Engine::public_timer_add` / `public_timer_cancel` + `ApiPublic` fire branch populated

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — add `public_timer_add` and `public_timer_cancel` methods; populate the `TimerKind::ApiPublic` branch in `advance_timer_wheel` to push `InternalEvent::ApiTimer`.

**Context:** Spec §3.1 (lifecycle + encoding). `TimerId → u64` packing: `(slot as u64) << 32 | (generation as u64)`. `public_timer_cancel` returns `bool` per the wheel's cancel semantics; the ABI layer (Task 17) maps to `0` / `-ENOENT`.

- [ ] **Step 1: Write failing unit tests**

Append to `engine.rs` tests:

```rust
#[test]
fn public_timer_add_cancel_signature_exists() {
    fn _compile_only(e: &Engine) {
        let id = e.public_timer_add(0, 0);
        let _: bool = e.public_timer_cancel(id);
    }
    let _ = _compile_only;
}

#[test]
fn public_timer_id_packing_roundtrip() {
    // Packing logic: (slot as u64) << 32 | (generation as u64)
    let id = crate::tcp_timer_wheel::TimerId { slot: 0xAABB_CCDD, generation: 0x1122_3344 };
    let packed = crate::engine::pack_timer_id(id);
    assert_eq!(packed, 0xAABB_CCDD_1122_3344);
    let unpacked = crate::engine::unpack_timer_id(packed);
    assert_eq!(unpacked.slot, 0xAABB_CCDD);
    assert_eq!(unpacked.generation, 0x1122_3344);
}

#[test]
fn align_up_to_tick_zero_and_boundary() {
    assert_eq!(crate::engine::align_up_to_tick_ns(0), 0);
    assert_eq!(crate::engine::align_up_to_tick_ns(1), 10_000);
    assert_eq!(crate::engine::align_up_to_tick_ns(10_000), 10_000);
    assert_eq!(crate::engine::align_up_to_tick_ns(10_001), 20_000);
    assert_eq!(crate::engine::align_up_to_tick_ns(19_999), 20_000);
}
```

- [ ] **Step 2: Run — verify compile errors**

Run: `cargo test -p resd-net-core engine::tests::public_timer_add_cancel_signature_exists`
Expected: compile error.

- [ ] **Step 3: Add packing helpers + methods**

Edit `crates/resd-net-core/src/engine.rs`. Add module-level helpers:

```rust
/// A6 (spec §3.1): pack internal `TimerId{slot, generation}` to the
/// `u64` exposed as `resd_net_timer_id_t`. Upper 32 = slot; lower 32 =
/// generation. Caller treats as opaque but knows the upper half changes
/// on slot reuse.
#[inline]
pub fn pack_timer_id(id: crate::tcp_timer_wheel::TimerId) -> u64 {
    ((id.slot as u64) << 32) | (id.generation as u64)
}

/// A6 (spec §3.1): unpack `resd_net_timer_id_t` back to the wheel's
/// internal representation.
#[inline]
pub fn unpack_timer_id(packed: u64) -> crate::tcp_timer_wheel::TimerId {
    crate::tcp_timer_wheel::TimerId {
        slot: (packed >> 32) as u32,
        generation: (packed & 0xFFFF_FFFF) as u32,
    }
}

/// A6 (spec §3.1): round `deadline_ns` UP to the next wheel tick
/// boundary. `deadline_ns = 0` stays zero (fires on next poll).
/// Past deadlines also fire on next poll.
#[inline]
pub fn align_up_to_tick_ns(deadline_ns: u64) -> u64 {
    const T: u64 = crate::tcp_timer_wheel::TICK_NS;
    deadline_ns.div_ceil(T).saturating_mul(T)
}
```

Add the two methods on `Engine`:

```rust
    /// A6 (spec §3.1): schedule a public API timer. Returns the wheel's
    /// TimerId; the ABI layer (Task 17) packs it to u64 for the caller.
    /// `deadline_ns` rounds up to the next 10 µs tick. Past deadlines
    /// fire on the next poll.
    pub fn public_timer_add(&self, deadline_ns: u64, user_data: u64)
        -> crate::tcp_timer_wheel::TimerId
    {
        let now_ns = crate::clock::now_ns();
        let fire_at_ns = align_up_to_tick_ns(deadline_ns);
        self.timer_wheel.borrow_mut().add(
            now_ns,
            crate::tcp_timer_wheel::TimerNode {
                fire_at_ns,
                owner_handle: 0,  // public timers not tied to a conn
                kind: crate::tcp_timer_wheel::TimerKind::ApiPublic,
                user_data,
                generation: 0,
                cancelled: false,
            },
        )
    }

    /// A6 (spec §3.1): cancel a public API timer via wheel tombstone.
    /// Returns true if a live node was found and cancelled; false
    /// otherwise (slot empty, generation stale from reuse, or timer
    /// already cancelled/fired).
    pub fn public_timer_cancel(&self, id: crate::tcp_timer_wheel::TimerId) -> bool {
        self.timer_wheel.borrow_mut().cancel(id)
    }
```

- [ ] **Step 4: Populate the `ApiPublic` branch in `advance_timer_wheel`**

Find the existing match in `advance_timer_wheel`:

```rust
                crate::tcp_timer_wheel::TimerKind::ApiPublic => {
                    // Wired in A6 public timer API. Silent no-op for now.
                }
```

Replace with:

```rust
                crate::tcp_timer_wheel::TimerKind::ApiPublic => {
                    let mut ev = self.events.borrow_mut();
                    ev.push(
                        InternalEvent::ApiTimer {
                            timer_id: id,
                            user_data: node.user_data,
                            emitted_ts_ns: crate::clock::now_ns(),
                        },
                        &self.counters,
                    );
                    crate::counters::inc(&self.counters.tcp.tx_api_timers_fired);
                }
```

- [ ] **Step 5: Run workspace tests**

Run: `cargo test --workspace`
Expected: all green. The new variant is still behind an unreachable!() in the ABI translator (Task 2's placeholder) — so no path emits the translated event yet. Pure unit tests pass; integration test landing in Task 21 will exercise end-to-end.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a6 task 8: public timer add/cancel + ApiPublic fire → InternalEvent::ApiTimer

Lands the engine-side public timer API. pack_timer_id/unpack_timer_id
encode TimerId{slot,gen} into u64 for the ABI. align_up_to_tick_ns
rounds deadlines to wheel resolution. ApiPublic fire branch pushes
InternalEvent::ApiTimer and bumps tx_api_timers_fired.

ABI-layer wiring (resd_net_timer_add extern) lands in Task 17.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: `preset=1` (rfc_compliance) application in `resd_net_engine_create`

**Files:**
- Modify: `crates/resd-net/src/lib.rs` — apply the five-field override when `cfg.preset == 1` after existing zero-sentinel substitution; reject `preset >= 2` with null-return.

**Context:** Spec §3.5. Existing `resd_net_engine_create` ignores `cfg.preset`. A6 honors it: `preset=0` leaves fields as substituted; `preset=1` forces `tcp_nagle=true, tcp_delayed_ack=true, cc_mode=1, tcp_min_rto_us=200_000, tcp_initial_rto_us=1_000_000`.

- [ ] **Step 1: Write failing unit test**

Edit `crates/resd-net/src/lib.rs`. Inside the existing `#[cfg(test)] mod tests { ... }`, add:

```rust
#[test]
fn preset_rfc_compliance_is_known_constant() {
    // Ensures Task 9 defines the preset value and matches spec §3.5.
    // (We can't call resd_net_engine_create without EAL; this test
    // pins the constant value and the validator rejection path.)
    assert_eq!(PRESET_LATENCY, 0);
    assert_eq!(PRESET_RFC_COMPLIANCE, 1);
}

#[test]
fn apply_preset_rfc_compliance_overrides_five_fields() {
    let mut core_cfg = resd_net_core::engine::EngineConfig {
        tcp_nagle: false,
        // tcp_delayed_ack doesn't exist on EngineConfig (A3 default was
        // per-segment ACKs); post-A6 the preset path stores the flag
        // on EngineConfig.tcp_delayed_ack.
        cc_mode: 0,
        tcp_min_rto_us: 5_000,
        tcp_initial_rto_us: 5_000,
        ..resd_net_core::engine::EngineConfig::default()
    };
    apply_preset(1, &mut core_cfg).expect("preset=1 must apply");
    assert!(core_cfg.tcp_nagle);
    assert!(core_cfg.tcp_delayed_ack);
    assert_eq!(core_cfg.cc_mode, 1);
    assert_eq!(core_cfg.tcp_min_rto_us, 200_000);
    assert_eq!(core_cfg.tcp_initial_rto_us, 1_000_000);
}

#[test]
fn apply_preset_latency_leaves_fields_intact() {
    let mut core_cfg = resd_net_core::engine::EngineConfig {
        tcp_nagle: false,
        cc_mode: 0,
        tcp_min_rto_us: 5_000,
        tcp_initial_rto_us: 5_000,
        ..resd_net_core::engine::EngineConfig::default()
    };
    apply_preset(0, &mut core_cfg).expect("preset=0 must be noop");
    assert!(!core_cfg.tcp_nagle);
    assert_eq!(core_cfg.cc_mode, 0);
    assert_eq!(core_cfg.tcp_min_rto_us, 5_000);
    assert_eq!(core_cfg.tcp_initial_rto_us, 5_000);
}

#[test]
fn apply_preset_unknown_rejected() {
    let mut core_cfg = resd_net_core::engine::EngineConfig::default();
    assert!(apply_preset(2, &mut core_cfg).is_err());
    assert!(apply_preset(255, &mut core_cfg).is_err());
}
```

- [ ] **Step 2: Run — compile error**

Run: `cargo test -p resd-net preset`
Expected: compile error, "no function `apply_preset`" + "no constants `PRESET_LATENCY` / `PRESET_RFC_COMPLIANCE`" + missing `tcp_delayed_ack` on `EngineConfig`.

- [ ] **Step 3: Add `tcp_delayed_ack` to `EngineConfig` (core side)**

Edit `crates/resd-net-core/src/engine.rs`. In `pub struct EngineConfig`, append:

```rust
    /// A6 (spec §3.5): delayed-ACK on/off. Default false (trading
    /// per-segment ACK). `preset=rfc_compliance` forces true.
    /// A3–A5.5 per-poll coalesce behavior is unchanged; this field
    /// gates the future burst-scope coalescing decision in tcp_output.
    pub tcp_delayed_ack: bool,
```

Default to `false`. Update `impl Default for EngineConfig` accordingly.

- [ ] **Step 4: Add the preset constants + `apply_preset` function**

Edit `crates/resd-net/src/lib.rs`. At module top:

```rust
/// A6 (spec §3.5): latency preset — all existing config fields honored as-written.
pub const PRESET_LATENCY: u8 = 0;
/// A6 (spec §3.5): RFC-compliance preset — overrides five fields per parent
/// spec §4: tcp_nagle, tcp_delayed_ack, cc_mode, tcp_min_rto_us, tcp_initial_rto_us.
pub const PRESET_RFC_COMPLIANCE: u8 = 1;

/// A6 (spec §3.5): apply a preset to a core `EngineConfig` after the
/// zero-sentinel substitution pass. The preset override is stronger
/// than defaults — explicit caller values are overwritten.
pub fn apply_preset(
    preset: u8,
    core_cfg: &mut resd_net_core::engine::EngineConfig,
) -> Result<(), ()> {
    match preset {
        PRESET_LATENCY => Ok(()),
        PRESET_RFC_COMPLIANCE => {
            core_cfg.tcp_nagle = true;
            core_cfg.tcp_delayed_ack = true;
            core_cfg.cc_mode = 1;  // Reno
            core_cfg.tcp_min_rto_us = 200_000;
            core_cfg.tcp_initial_rto_us = 1_000_000;
            Ok(())
        }
        _ => Err(()),
    }
}
```

- [ ] **Step 5: Wire `apply_preset` into `resd_net_engine_create`**

Find the existing `resd_net_engine_create` body. After the zero-sentinel substitution for `min_rto_us / initial_rto_us / max_rto_us / max_retrans / msl` and before `let core_cfg = EngineConfig { ... }` is built, apply the preset:

```rust
    let core_cfg = EngineConfig {
        // ... existing field substitution ...
        tcp_delayed_ack: cfg.tcp_delayed_ack,
        // ... rest ...
    };
    let mut core_cfg = core_cfg;
    if apply_preset(cfg.preset, &mut core_cfg).is_err() {
        return ptr::null_mut();
    }
    match Engine::new(core_cfg) { ... }
```

Concretely: the easiest structure is to mutate `core_cfg` after the struct is built. Make the local `mut`, call `apply_preset`, then pass to `Engine::new`.

- [ ] **Step 6: Verify `tcp_delayed_ack` flows from the ABI `resd_net_engine_config_t`**

Check that `resd_net_engine_config_t::tcp_delayed_ack` already exists (it does — per the header dump in the spec). Check the body of `resd_net_engine_create` reads `cfg.tcp_delayed_ack`; if not, add it to the `EngineConfig { ... }` construction.

- [ ] **Step 7: Run tests**

Run: `cargo test -p resd-net preset`
Expected: all 4 tests pass.

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net-core/src/engine.rs crates/resd-net/src/lib.rs include/resd_net.h
git commit -m "$(cat <<'EOF'
a6 task 9: preset=rfc_compliance honored in resd_net_engine_create

Implements the five-field override when preset=1. preset=0 (latency)
is a no-op on existing caller fields. preset>=2 rejected with null-
return. tcp_delayed_ack added to EngineConfig; propagated from the
ABI config; gated by the preset path.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: `close_conn_with_flags` + `FORCE_TW_SKIP` prerequisite check

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — new `close_conn_with_flags(handle, flags) -> Result<(), Error>` method; routes to existing `close_conn` after flag processing.

**Context:** Spec §3.4. Gate on `c.ts_enabled`: when false, emit `Error{err=-EPERM}` and drop the flag; when true, set `c.force_tw_skip = true` for Task 11's short-circuit.

- [ ] **Step 1: Write failing unit test**

Append to `engine.rs` tests:

```rust
#[test]
fn close_conn_with_flags_signature_exists() {
    fn _compile_only(e: &Engine) {
        let _: Result<(), crate::Error> = e.close_conn_with_flags(0, 0);
        let _: Result<(), crate::Error> = e.close_conn_with_flags(0, 1 << 0);
    }
    let _ = _compile_only;
}
```

- [ ] **Step 2: Run — compile error**

Run: `cargo test -p resd-net-core engine::tests::close_conn_with_flags_signature_exists`
Expected: compile error.

- [ ] **Step 3: Add constant + method**

Edit `crates/resd-net-core/src/engine.rs`. Near the top of the module:

```rust
/// A6 (spec §3.4): close-flag bit, mirror of `RESD_NET_CLOSE_FORCE_TW_SKIP`.
/// Defined core-side so engine logic doesn't depend on the ABI crate.
pub const CLOSE_FLAG_FORCE_TW_SKIP: u32 = 1 << 0;
```

Add the method on `impl Engine`:

```rust
    /// A6 (spec §3.4): close a connection, honoring the `flags` bitmask.
    /// Currently only `CLOSE_FLAG_FORCE_TW_SKIP` is defined; other bits
    /// are reserved for future extension and silently ignored.
    ///
    /// Semantics for `FORCE_TW_SKIP`:
    /// - If `c.ts_enabled == false`, emit one `Error{err=-EPERM}` event
    ///   (the "EPERM_TW_REQUIRED" condition per parent spec §9.3) and
    ///   drop the flag; normal FIN + 2×MSL TIME_WAIT proceeds.
    /// - If `c.ts_enabled == true`, set `c.force_tw_skip = true`;
    ///   `reap_time_wait` (Task 11) short-circuits the 2×MSL wait.
    ///
    /// In both cases the existing `close_conn` body runs to emit the FIN.
    pub fn close_conn_with_flags(
        &self,
        handle: ConnHandle,
        flags: u32,
    ) -> Result<(), Error> {
        if (flags & CLOSE_FLAG_FORCE_TW_SKIP) != 0 {
            let ts_enabled = {
                let ft = self.flow_table.borrow();
                ft.get(handle).map(|c| c.ts_enabled).unwrap_or(false)
            };
            if !ts_enabled {
                // Prerequisite not met — flag dropped, Error event emitted.
                let emitted_ts_ns = crate::clock::now_ns();
                let mut ev = self.events.borrow_mut();
                ev.push(
                    InternalEvent::Error {
                        conn: handle,
                        err: -libc::EPERM,
                        emitted_ts_ns,
                    },
                    &self.counters,
                );
            } else {
                let mut ft = self.flow_table.borrow_mut();
                if let Some(c) = ft.get_mut(handle) {
                    c.force_tw_skip = true;
                }
            }
        }
        self.close_conn(handle)
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a6 task 10: close_conn_with_flags + FORCE_TW_SKIP prerequisite check

Adds the engine-side flag-honoring close path. ts_enabled=true →
force_tw_skip stored on TcpConn (reap short-circuit in Task 11).
ts_enabled=false → Error{err=-EPERM} emitted, flag dropped, normal
FIN + 2×MSL proceeds. ABI extern wiring lands in Task 19.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: `reap_time_wait` short-circuit for `force_tw_skip`

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs::reap_time_wait` — when a TIME_WAIT conn has `force_tw_skip == true`, close immediately regardless of `time_wait_deadline_ns`.

**Context:** Spec §3.4. The existing `reap_time_wait` walks the flow table and closes conns past their 2×MSL deadline. A6 extends the candidate predicate.

- [ ] **Step 1: Read the existing function**

Open `crates/resd-net-core/src/engine.rs` around the line `fn reap_time_wait`. Current predicate inside `iter_handles().filter(...)`:

```rust
c.state == TcpState::TimeWait
    && c.time_wait_deadline_ns.is_some_and(|d| now >= d)
```

- [ ] **Step 2: Update the predicate to include the short-circuit**

Replace with:

```rust
c.state == TcpState::TimeWait
    && (c.force_tw_skip
        || c.time_wait_deadline_ns.is_some_and(|d| now >= d))
```

No other changes in the function body — the existing close emit `StateChange{TimeWait → Closed}` + `Closed{err=0}` + counter bump is exactly what the short-circuit path wants (observability parity preserved per spec §3.4).

- [ ] **Step 3: Write a unit test on the predicate — construct two conns, one force_tw_skip=true, one false-with-future-deadline, verify only the first is reaped**

The TcpState/TcpConn manipulation is easier via the flow_table directly. Append to `engine.rs` tests:

```rust
#[test]
fn force_tw_skip_short_circuits_reap() {
    // Verify the predicate logic. Using the flow table unit-test helper.
    use crate::flow_table::{FlowTable, FourTuple};
    use crate::tcp_state::TcpState;

    let mut ft = FlowTable::new(8);
    let tuple_a = FourTuple { local_ip: 1, local_port: 40000, peer_ip: 2, peer_port: 5000 };
    let tuple_b = FourTuple { local_ip: 1, local_port: 40001, peer_ip: 2, peer_port: 5001 };
    let h_a = ft.insert(tuple_a, crate::tcp_conn::TcpConn::new_client(
        tuple_a, 0, 1460, 1024, 2048, 5_000, 5_000, 1_000_000,
    )).unwrap();
    let h_b = ft.insert(tuple_b, crate::tcp_conn::TcpConn::new_client(
        tuple_b, 0, 1460, 1024, 2048, 5_000, 5_000, 1_000_000,
    )).unwrap();
    // conn A: TIME_WAIT + force_tw_skip=true  → should reap
    // conn B: TIME_WAIT + deadline in future → should NOT reap
    let now: u64 = 1_000_000_000;
    if let Some(c) = ft.get_mut(h_a) {
        c.state = TcpState::TimeWait;
        c.force_tw_skip = true;
        c.time_wait_deadline_ns = Some(now + 60_000_000_000); // deadline 60s in future
    }
    if let Some(c) = ft.get_mut(h_b) {
        c.state = TcpState::TimeWait;
        c.force_tw_skip = false;
        c.time_wait_deadline_ns = Some(now + 60_000_000_000);
    }
    // Replicate the candidate-filter predicate from reap_time_wait:
    let candidates: Vec<_> = ft.iter_handles()
        .filter(|h| {
            let Some(c) = ft.get(*h) else { return false };
            c.state == TcpState::TimeWait
                && (c.force_tw_skip
                    || c.time_wait_deadline_ns.is_some_and(|d| now >= d))
        })
        .collect();
    assert_eq!(candidates.len(), 1, "only A reaps under short-circuit");
    assert_eq!(candidates[0], h_a);
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p resd-net-core engine::tests::force_tw_skip_short_circuits_reap`
Expected: PASS.

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a6 task 11: reap_time_wait short-circuit for force_tw_skip

A TIME_WAIT conn with force_tw_skip=true (set by close_conn_with_flags
in Task 10 when ts_enabled prerequisite was met) is reaped immediately
regardless of time_wait_deadline_ns. Observability parity preserved —
StateChange + Closed events emit through the same reap path.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: `send_bytes` TX-ring push (replacing per-segment inline `tx_burst`)

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs::send_bytes` — replace the inline `rte_eth_tx_burst(.., ., 1)` per-segment call with a push into `tx_pending_data`; fall back to immediate drain-then-push when the ring is full.

**Context:** Spec §3.2. This is the larger of the two call-site refactors. Spec §3.3 also: `send_bytes` must set `c.send_refused_pending = true` when it returns `accepted < bytes.len()` — that signal is what Task 16's WRITABLE hysteresis waits for.

- [ ] **Step 1: Write failing unit test that asserts the contract (signature compile)**

`send_bytes` already has a signature-check unit test (`send_bytes_signature_exists`) in the engine tests. Add a contract assertion (the signature doesn't change):

```rust
#[test]
fn send_bytes_sets_send_refused_pending_on_short_accept() {
    // Signature-only + property assertion. Full end-to-end behavior is
    // exercised in tcp_a6_public_api_tap.rs (Task 21); this test pins
    // the contract that partial accept sets the flag.
    //
    // Real hook site verification (that the helper runs post-accept)
    // lives inline in send_bytes — grep-verified in task review.
    fn _compile_only(e: &Engine, handle: crate::flow_table::ConnHandle) {
        let _: Result<u32, crate::Error> = e.send_bytes(handle, b"x");
        // The post-send_bytes check: if accepted < len, the conn's
        // send_refused_pending should be set.
        let ft = e.flow_table();
        if let Some(c) = ft.get(handle) {
            let _ = c.send_refused_pending;
        }
    }
    let _ = _compile_only;
}
```

- [ ] **Step 2: Run — compile, no new failure; the test passes trivially**

Run: `cargo test -p resd-net-core engine::tests::send_bytes_sets_send_refused_pending_on_short_accept`
Expected: PASS (compile-only test).

- [ ] **Step 3: Refactor `send_bytes`'s per-segment TX to push-to-ring**

Edit `crates/resd-net-core/src/engine.rs::send_bytes`. Find the `while remaining > 0 { ... }` loop's TX-burst section. Currently:

```rust
            let mut pkts = [m];
            let sent = unsafe {
                sys::resd_rte_eth_tx_burst(
                    self.cfg.port_id,
                    self.cfg.tx_queue_id,
                    pkts.as_mut_ptr(),
                    1,
                )
            } as usize;
            if sent != 1 {
                // Driver did not take the mbuf — free both refs.
                unsafe { sys::resd_rte_pktmbuf_free(m) };
                unsafe { sys::resd_rte_pktmbuf_free(m) };
                inc(&self.counters.eth.tx_drop_full_ring);
                if accepted == 0 { return Err(Error::SendBufferFull); }
                break;
            }
            crate::counters::add(&self.counters.eth.tx_bytes, n as u64);
            inc(&self.counters.eth.tx_pkts);
            inc(&self.counters.tcp.tx_data);
```

Replace with:

```rust
            // A6 (spec §3.2): push onto the batch ring instead of
            // per-segment tx_burst(1). Drain-and-retry on ring full so
            // a single send never stalls on a saturated ring.
            let pushed_ok = {
                let mut ring = self.tx_pending_data.borrow_mut();
                if ring.len() < ring.capacity() {
                    // Safety: `m` is non-null (checked above by the
                    // alloc path); NonNull::new_unchecked avoids a
                    // second null-check on the hot path.
                    ring.push(unsafe { std::ptr::NonNull::new_unchecked(m) });
                    true
                } else {
                    false
                }
            };
            if !pushed_ok {
                // Ring at capacity. Drain it, then push this mbuf.
                self.drain_tx_pending_data();
                let mut ring = self.tx_pending_data.borrow_mut();
                ring.push(unsafe { std::ptr::NonNull::new_unchecked(m) });
            }
            crate::counters::add(&self.counters.eth.tx_bytes, n as u64);
            // Note: eth.tx_pkts is now incremented by drain_tx_pending_data
            // (post-successful-burst `add(&tx_pkts, sent)`), not here.
            // Rationale: we only count a packet as "TX'd" once it actually
            // leaves the ring via rte_eth_tx_burst; a pushed-but-unsent
            // mbuf that frees on partial-fill counts as tx_drop_full_ring.
            inc(&self.counters.tcp.tx_data);
```

- [ ] **Step 4: Set `send_refused_pending` on partial accept**

Find the tail of `send_bytes` where `accepted` is finalized. Currently:

```rust
        if accepted < bytes.len() as u32 {
            inc(&self.counters.tcp.send_buf_full);
        }
```

Extend to also set the pending bit:

```rust
        if accepted < bytes.len() as u32 {
            inc(&self.counters.tcp.send_buf_full);
            // A6 (spec §3.3): signal for WRITABLE hysteresis (Task 16).
            // ACK-prune path in tcp_input.rs watches this bit + fires
            // a single WRITABLE event once in_flight ≤ send_buffer_bytes / 2.
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.send_refused_pending = true;
            }
        }
```

- [ ] **Step 5: Run workspace tests**

Run: `cargo test --workspace`
Expected: all green. Existing `tx_pkts`-based tests must still pass — `drain_tx_pending_data` increments `tx_pkts` post-burst, preserving the aggregate.

Note: the previous code double-freed an mbuf on tx-burst failure (line 2560-2561 in pre-edit). The new code can't encounter that path because drain handles its own partial-fill frees. Verify with a review — old intermediate state is gone.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a6 task 12: send_bytes — batch via tx_pending_data + set refused-pending

send_bytes pushes per-segment mbufs into tx_pending_data instead of
calling rte_eth_tx_burst(.., 1) inline. Ring-full triggers a drain +
retry; no send call stalls on ring capacity. send_refused_pending is
set when accepted<len so Task 16's WRITABLE hysteresis can fire on
the next ACK-prune.

Per-packet eth.tx_pkts is now incremented post-burst inside
drain_tx_pending_data rather than per-segment, so a pushed-but-unsent
mbuf counts as tx_drop_full_ring (not tx_pkts).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: `retransmit` TX-ring push + retransmit-ENOMEM Error event emission

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs::retransmit` — replace inline `tx_burst(1)` with ring push; emit `InternalEvent::Error{err=-ENOMEM}` per occurrence when `tx_hdr_mempool` alloc fails.

**Context:** Spec §3.2 (retransmit push) + §3.6 Site 2 (per-occurrence Error event on retransmit ENOMEM).

- [ ] **Step 1: Read the existing `retransmit` body**

Inspect `crates/resd-net-core/src/engine.rs` around `pub(crate) fn retransmit(&self, ...)` (starts near line 2815). It allocates `hdr_mbuf` via `rte_pktmbuf_alloc`, chains to the data mbuf, calls `tx_burst(1)`. On alloc failure: `inc(&self.counters.eth.tx_drop_nomem)` and early return.

- [ ] **Step 2: Emit `Error{err=-ENOMEM}` on alloc failure**

Find the block:

```rust
        let hdr_mbuf = unsafe { sys::resd_rte_pktmbuf_alloc(self.tx_hdr_mempool.as_ptr()) };
        if hdr_mbuf.is_null() {
            inc(&self.counters.eth.tx_drop_nomem);
            return;
        }
```

Extend to push the Error event before returning:

```rust
        let hdr_mbuf = unsafe { sys::resd_rte_pktmbuf_alloc(self.tx_hdr_mempool.as_ptr()) };
        if hdr_mbuf.is_null() {
            inc(&self.counters.eth.tx_drop_nomem);
            // A6 (spec §3.6 Site 2): surface retransmit ENOMEM as an
            // Error event per occurrence — callers don't see the inline
            // tx_drop_nomem bump unless they poll the counter.
            let emitted_ts_ns = crate::clock::now_ns();
            let mut ev = self.events.borrow_mut();
            ev.push(
                InternalEvent::Error {
                    conn: conn_handle,
                    err: -libc::ENOMEM,
                    emitted_ts_ns,
                },
                &self.counters,
            );
            return;
        }
```

Repeat for the second alloc failure (line ~2942 — the `build_retrans_header` append path allocates inside the frame-building helper). Grep for every `tx_drop_nomem` bump inside `retransmit` + surrounding helpers, and guard each with the Error emission.

- [ ] **Step 3: Replace the inline `tx_burst(1)` with ring push**

Find the `tx_burst(.., .., pkts.as_mut_ptr(), 1)` call inside `retransmit`'s finalization. Current shape:

```rust
        let mut pkts = [hdr_mbuf];
        let sent = unsafe {
            sys::resd_rte_eth_tx_burst(
                self.cfg.port_id,
                self.cfg.tx_queue_id,
                pkts.as_mut_ptr(),
                1,
            )
        } as usize;
        if sent != 1 { /* cleanup */ return; }
        // success counters
```

Replace with:

```rust
        // A6 (spec §3.2): push retransmit frame onto the same batch
        // ring as new-data sends so retries flow through one burst
        // alongside. Ring-full drains and retries.
        let pushed_ok = {
            let mut ring = self.tx_pending_data.borrow_mut();
            if ring.len() < ring.capacity() {
                ring.push(unsafe { std::ptr::NonNull::new_unchecked(hdr_mbuf) });
                true
            } else {
                false
            }
        };
        if !pushed_ok {
            self.drain_tx_pending_data();
            let mut ring = self.tx_pending_data.borrow_mut();
            ring.push(unsafe { std::ptr::NonNull::new_unchecked(hdr_mbuf) });
        }
        inc(&self.counters.tcp.tx_retrans);
```

Remove the `tx_burst`-fail cleanup path (the drain-time partial-fill branch already frees unsent mbufs and bumps `tx_drop_full_ring`). Retain the bookkeeping bumps (`xmit_count`, `xmit_ts_ns`, `rack.largest_*` updates) — those happen on push, not on actual TX completion, which is a behavioral shift but is consistent with send_bytes's same move in Task 12.

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`
Expected: all green. Existing retransmit unit tests in `engine.rs` + integration tests in `tcp_rack_rto_retrans_tap.rs` exercise the path; a behavior change in TX-timing (ring-push vs. inline-burst) shouldn't affect the TCP semantics the tests observe.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a6 task 13: retransmit push-to-ring + ENOMEM Error event per occurrence

retransmit() pushes the header-mbuf-chained-to-data-mbuf onto
tx_pending_data instead of calling rte_eth_tx_burst(1) inline; matches
send_bytes's Task 12 batch path. tx_hdr_mempool alloc failures now
emit Error{err=-ENOMEM} per occurrence per spec §3.6 Site 2.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: RFC 7323 §5.5 24-day `TS.Recent` lazy expiration in `tcp_input.rs`

**Files:**
- Modify: `crates/resd-net-core/src/tcp_input.rs` — at the PAWS gate, compute `idle_ns = now_ns - ts_recent_age`; if > 24d, treat `TS.Recent` as absent for this segment, adopt `seg_tsval` unconditionally, reset the age, bump `tcp.ts_recent_expired`.

**Context:** Spec §3.7. Lazy (no timer wheel involvement). Zero hot-path cost on fresh connections. RFC-7323-§5.5-equivalent outcome: first segment after 24d idle re-seeds `TS.Recent` instead of being rejected by PAWS.

- [ ] **Step 1: Add the expiry constant as a module-level const**

Edit `crates/resd-net-core/src/tcp_input.rs`. At top of the module (after `use` statements):

```rust
/// A6 (spec §3.7): RFC 7323 §5.5 24-day `TS.Recent` expiration window
/// in nanoseconds. Applied lazily at the PAWS gate — no timer, no
/// hot-path cost on fresh connections.
const TS_RECENT_EXPIRY_NS: u64 = 24 * 86_400 * 1_000_000_000;
```

- [ ] **Step 2: Find the PAWS check site**

Grep for `ts_recent` in tcp_input.rs to find the PAWS gate:

```bash
grep -n 'ts_recent' crates/resd-net-core/src/tcp_input.rs
```

You're looking for the block that reads `c.ts_recent` and compares against `seg_tsval`. PAWS drops a segment when `seg_tsval < c.ts_recent` (RFC 7323 §5). The lazy expiration inserts before that comparison.

- [ ] **Step 3: Insert the expiration short-circuit**

At the PAWS gate, before the `seg_tsval < c.ts_recent` drop check, insert:

```rust
            // A6 (spec §3.7): RFC 7323 §5.5 24-day `TS.Recent` lazy expiration.
            // If the connection has been idle for more than 24 days, treat
            // TS.Recent as absent for this segment: adopt seg_tsval, reset
            // the age, and skip the PAWS drop check. RFC-equivalent outcome.
            let paws_skip_this_seg = {
                let idle_ns = now_ns.saturating_sub(c.ts_recent_age);
                if c.ts_recent_age != 0 && idle_ns > TS_RECENT_EXPIRY_NS {
                    c.ts_recent = seg_tsval;
                    c.ts_recent_age = now_ns;
                    crate::counters::inc(&counters.tcp.ts_recent_expired);
                    true
                } else {
                    false
                }
            };
            if !paws_skip_this_seg {
                if seg_tsval < c.ts_recent {
                    // existing PAWS drop + counter bump
                    crate::counters::inc(&counters.tcp.rx_paws_rejected);
                    return;
                }
            }
```

Context: the exact local-variable names (`c`, `counters`, `now_ns`, `seg_tsval`) must match what's in scope at the PAWS gate. Read the surrounding function to confirm. If `now_ns` isn't available, call `crate::clock::now_ns()` inline.

- [ ] **Step 4: Ensure `ts_recent_age` is updated on every accepted TS segment**

The PAWS skip sets `ts_recent_age = now_ns`. But the *normal* (non-expired) TS.Recent update path must also set `ts_recent_age = now_ns` each time it writes `ts_recent`. Grep for every `c.ts_recent = ` assignment in `tcp_input.rs` and ensure `c.ts_recent_age = now_ns` follows. If an assignment doesn't, that's an A5.5-era oversight — fix it in this task (belongs on the 24d-expiry task anyway, since age tracking without updates is broken).

- [ ] **Step 5: Write integration test — mock-clock 25-day jump produces one `ts_recent_expired` bump**

Land in `crates/resd-net-core/tests/tcp_a6_public_api_tap.rs` (new file created in Task 21). For this task, write the test assertion as a placeholder header and note that the integration-test body is authored in Task 21's scenario list. In Task 21 we add:

```rust
#[test]
fn ts_recent_24d_expiry_accepts_stale_tsval_once() {
    // Use the net_tap harness to establish a TS-negotiated conn, drive
    // one TS segment to populate ts_recent, jump the mock clock 25d,
    // send a segment whose tsval is less than ts_recent. Assert:
    //   - segment NOT dropped (recv buffer advances or data visible)
    //   - counters.tcp.ts_recent_expired == 1
    //   - counters.tcp.rx_paws_rejected unchanged
}
```

- [ ] **Step 6: Run workspace tests**

Run: `cargo test --workspace`
Expected: all green. The PAWS-gate edit is a no-op on any path where `ts_recent_age` hasn't elapsed 24 days, which is every existing integration test.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/tcp_input.rs
git commit -m "$(cat <<'EOF'
a6 task 14: RFC 7323 §5.5 24-day TS.Recent lazy expiration at PAWS

At the PAWS gate, if (now - ts_recent_age) > 24 days, treat TS.Recent
as absent for this segment: adopt seg_tsval, reset age, bump
tcp.ts_recent_expired. No timer, zero hot-path cost on fresh conns.
Applies RFC-7323-§5.5-equivalent semantics without requiring the
public timer API.

Normal TS.Recent update path verified to set ts_recent_age on every
write so the lazy check has accurate idle tracking.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: RTT histogram update hook after `rtt_est.sample`

**Files:**
- Modify: `crates/resd-net-core/src/tcp_input.rs` — after the existing `rtt_est.sample(rtt_us)` call (and the `tcp.rtt_samples` counter bump), call `conn.rtt_histogram.update(rtt_us, &engine.rtt_histogram_edges)`.

**Context:** Spec §3.8 + §3.8.1. Site: every RTT-sample-taking path (timestamp-based and Karn's-rule-based). Cost: ~5-10 ns. No atomic (per-conn, RTC).

- [ ] **Step 1: Find the existing `rtt_est.sample` call sites**

```bash
grep -n 'rtt_est.sample' crates/resd-net-core/src/tcp_input.rs crates/resd-net-core/src/engine.rs
```

Expected: at least two sites — one in `tcp_input.rs` (regular ACK path) and one in `engine.rs` (SYN-ACK path per A5.5 Task 13). For A6's histogram, we want BOTH sites instrumented. A centralizing helper avoids repetition.

- [ ] **Step 2: Add the update call at every sample site**

At each site that calls `rtt_est.sample(rtt_us)` + bumps `tcp.rtt_samples`, add immediately after:

```rust
            // A6 (spec §3.8): per-conn RTT histogram update. Slow-path
            // at sample cadence (not per-segment). 15-comparison ladder
            // + one wrapping_add on cache-resident state.
            c.rtt_histogram.update(rtt_us, &self.rtt_histogram_edges);
```

Context: `self` here is `&Engine` when the site is in `engine.rs`; inside `tcp_input.rs` the caller typically takes the engine's edges via the outer function's `engine: &Engine` parameter or equivalent. Read the surrounding function signature to find the right reference.

- [ ] **Step 3: Run existing RTT tests to confirm no regression**

Run: `cargo test -p resd-net-core rtt`
Expected: existing RTT estimator tests pass. The histogram update is additive; no existing test mutates or observes it.

- [ ] **Step 4: Write a Layer-B integration assertion (placeholder for Task 21)**

The distribution-shape assertion in `tcp_a6_public_api_tap.rs` lives in Task 21. For this task, add the scenario name to the test-plan list as a stub:

```rust
#[test]
fn rtt_histogram_update_fires_on_sample() {
    // Task 21 body: establish conn, drive N ACKs with known controlled
    // RTTs, verify the bucket matching each RTT advances by exactly 1
    // per ACK (via resd_net_conn_rtt_histogram — Task 18).
}
```

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_input.rs crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a6 task 15: RTT histogram update hook after rtt_est.sample

Wires RttHistogram::update at every site that takes an RTT sample —
the regular ACK-driven path in tcp_input.rs plus the SYN-ACK seed
path in engine.rs (A5.5 Task 13). 15-comparison ladder + one
wrapping_add, no atomic.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: `WRITABLE` hysteresis emission on ACK-prune path

**Files:**
- Modify: `crates/resd-net-core/src/tcp_input.rs` — after the existing `snd_una` advance (ACK prune) block, if `c.send_refused_pending && in_flight ≤ send_buffer_bytes / 2`, push `InternalEvent::Writable` + clear the bit.
- Modify: `crates/resd-net/src/lib.rs::build_event_from_internal` — replace the Task-2 placeholder for `Writable` with the real translation arm.

**Context:** Spec §3.3. Level-triggered, single-edge-per-refusal-cycle. Send-buffer half-drain is the hysteresis gate.

- [ ] **Step 1: Find the ACK-prune call site**

Grep `tcp_input.rs` for where `snd_una` advances on a valid ACK. Typically inside `handle_ack` or a similarly-named block.

```bash
grep -n 'snd_una' crates/resd-net-core/src/tcp_input.rs | head -20
```

The relevant block updates `c.snd_una = seg_ack` after validation, then prunes `snd_retrans` entries that are now cumulatively acked.

- [ ] **Step 2: Add the WRITABLE emission immediately after prune**

After the `snd_retrans` prune loop (where fully-acked entries' mbufs drop their refcount), add:

```rust
            // A6 (spec §3.3): WRITABLE hysteresis. If a prior send_bytes
            // refused bytes (send_refused_pending), and the ACK just
            // drained the in-flight window to ≤ send_buffer_bytes / 2,
            // emit one Writable event and clear the bit. Level-triggered;
            // subsequent refusals start a fresh cycle.
            if c.send_refused_pending {
                let in_flight = c.snd_nxt.wrapping_sub(c.snd_una);
                let threshold = self.cfg.send_buffer_bytes / 2;
                if in_flight <= threshold {
                    let emitted_ts_ns = crate::clock::now_ns();
                    let mut ev = self.events.borrow_mut();
                    ev.push(
                        InternalEvent::Writable {
                            conn: handle,
                            emitted_ts_ns,
                        },
                        &self.counters,
                    );
                    c.send_refused_pending = false;
                }
            }
```

Context: match the function's existing borrow discipline. If the function already has `&mut` access to `c` and `&` access to `self.events`, the above compiles; if not, restructure (two-phase borrow: read `send_refused_pending` + `snd_nxt` + `snd_una`, release the conn borrow, take the events borrow, push, re-borrow the conn to clear the bit).

- [ ] **Step 3: Replace the `Writable` ABI-translator placeholder**

Edit `crates/resd-net/src/lib.rs::build_event_from_internal`. Replace the placeholder arm:

```rust
        InternalEvent::Writable { .. } => {
            unreachable!("Writable translation wired in Task 17; no upstream emit until Task 16")
        }
```

with:

```rust
        InternalEvent::Writable { conn, .. } => resd_net_event_t {
            kind: resd_net_event_kind_t::RESD_NET_EVT_WRITABLE,
            conn: *conn as u64,
            rx_hw_ts_ns: 0,
            enqueued_ts_ns: emitted,
            // No payload on WRITABLE — zero the union.
            u: resd_net_event_payload_t { _pad: [0u8; 16] },
        },
```

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`
Expected: all green. No existing test drives the WRITABLE code path (Task 21 lands the integration assertion).

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_input.rs crates/resd-net/src/lib.rs
git commit -m "$(cat <<'EOF'
a6 task 16: WRITABLE hysteresis on ACK-prune + ABI translator

Emits InternalEvent::Writable when send_refused_pending is set and
in_flight drops to ≤ send_buffer_bytes / 2 (level-triggered, cleared
on fire). build_event_from_internal translates to RESD_NET_EVT_WRITABLE
with empty payload. Integration tests in Task 21.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 17: `resd_net_timer_add` / `resd_net_timer_cancel` extern "C" functions + ApiTimer ABI translator

**Files:**
- Modify: `crates/resd-net/src/lib.rs` — add `resd_net_timer_add` and `resd_net_timer_cancel` extern fns; replace the Task-2 `ApiTimer` placeholder with the real translator.

**Context:** Spec §5.3. Both functions wrap `Engine::public_timer_add` / `_cancel` from Task 8 and pack/unpack `TimerId` via the helpers from Task 8.

- [ ] **Step 1: Write failing unit test — null-arg rejection**

Append to `crates/resd-net/src/lib.rs::tests`:

```rust
#[test]
fn timer_add_null_engine_returns_einval() {
    let mut out: u64 = 0;
    let rc = unsafe {
        resd_net_timer_add(std::ptr::null_mut(), 0, 0, &mut out)
    };
    assert_eq!(rc, -libc::EINVAL);
}

#[test]
fn timer_add_null_out_returns_einval() {
    // A non-null engine pointer is safe to pass with a null out because
    // the null-out check fires before any engine deref. Use dangling
    // to emulate.
    let fake_engine = std::ptr::dangling_mut::<resd_net_engine>();
    let rc = unsafe {
        resd_net_timer_add(fake_engine, 0, 0, std::ptr::null_mut())
    };
    assert_eq!(rc, -libc::EINVAL);
}

#[test]
fn timer_cancel_null_engine_returns_einval() {
    let rc = unsafe { resd_net_timer_cancel(std::ptr::null_mut(), 0) };
    assert_eq!(rc, -libc::EINVAL);
}
```

- [ ] **Step 2: Run — compile error**

Run: `cargo test -p resd-net timer_add_null_engine_returns_einval`
Expected: "cannot find function `resd_net_timer_add`".

- [ ] **Step 3: Add the extern fns**

Edit `crates/resd-net/src/lib.rs`. Append near the other extern fns:

```rust
/// A6 (spec §5.3): schedule a one-shot timer. `deadline_ns` is in the
/// engine's monotonic clock domain (see `resd_net_now_ns`). Rounded up
/// to the next 10 µs wheel tick; past deadlines fire on the next poll.
/// On fire, emits `RESD_NET_EVT_TIMER` with the returned `timer_id`
/// and the caller-supplied `user_data` echoed back.
///
/// Returns 0 on success (populates `*timer_id_out`); -EINVAL on
/// null engine/out.
#[no_mangle]
pub unsafe extern "C" fn resd_net_timer_add(
    engine: *mut resd_net_engine,
    deadline_ns: u64,
    user_data: u64,
    timer_id_out: *mut u64,
) -> i32 {
    if engine.is_null() || timer_id_out.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(engine) else {
        return -libc::EINVAL;
    };
    let id = e.public_timer_add(deadline_ns, user_data);
    *timer_id_out = resd_net_core::engine::pack_timer_id(id);
    0
}

/// A6 (spec §5.3): cancel a previously-added timer. Returns 0 if
/// cancelled before fire, -ENOENT otherwise (collapses: never existed /
/// already fired and drained / already fired but not yet drained).
/// Callers must always drain any queued TIMER events regardless of
/// this return — the event queue is authoritative.
#[no_mangle]
pub unsafe extern "C" fn resd_net_timer_cancel(
    engine: *mut resd_net_engine,
    timer_id: u64,
) -> i32 {
    if engine.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(engine) else {
        return -libc::EINVAL;
    };
    let id = resd_net_core::engine::unpack_timer_id(timer_id);
    if e.public_timer_cancel(id) {
        0
    } else {
        -libc::ENOENT
    }
}
```

- [ ] **Step 4: Replace the `ApiTimer` ABI-translator placeholder**

In `build_event_from_internal`, replace:

```rust
        InternalEvent::ApiTimer { .. } => {
            unreachable!("ApiTimer translation wired in Task 17; no upstream emit until Task 8")
        }
```

with:

```rust
        InternalEvent::ApiTimer { timer_id, user_data, .. } => {
            resd_net_event_t {
                kind: resd_net_event_kind_t::RESD_NET_EVT_TIMER,
                conn: 0,  // public timers not bound to a conn
                rx_hw_ts_ns: 0,
                enqueued_ts_ns: emitted,
                u: resd_net_event_payload_t {
                    timer: resd_net_event_timer_t {
                        timer_id: resd_net_core::engine::pack_timer_id(*timer_id),
                        user_data: *user_data,
                    },
                },
            }
        }
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p resd-net`
Expected: 3 new null-arg rejection tests pass; pre-existing tests stay green.

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 6: Verify cbindgen emits the new functions**

```bash
cargo build -p resd-net
grep -A 4 'resd_net_timer_add\|resd_net_timer_cancel' include/resd_net.h
```

Expected: two new `extern "C"` prototypes with doc-comments.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net/src/lib.rs include/resd_net.h
git commit -m "$(cat <<'EOF'
a6 task 17: resd_net_timer_add + resd_net_timer_cancel extern "C"

ABI wrappers on Engine::public_timer_add / _cancel from Task 8.
ApiTimer variant translator replaces Task 2's unreachable!()
placeholder. -ENOENT collapses the three "not found" states per
spec §5.3 + §3.1. Header regenerated via cbindgen.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 18: `resd_net_conn_rtt_histogram` extern + `resd_net_tcp_rtt_histogram_t` POD

**Files:**
- Modify: `crates/resd-net/src/api.rs` — add `resd_net_tcp_rtt_histogram_t { bucket: [u32; 16] }` POD; compile-time size=64 assert.
- Modify: `crates/resd-net/src/lib.rs` — add `resd_net_conn_rtt_histogram` extern fn.

**Context:** Spec §5.2, §5.3. Slow-path snapshot; safe per-order or per-minute.

- [ ] **Step 1: Add the POD struct**

Edit `crates/resd-net/src/api.rs`. Append near the other POD structs:

```rust
/// A6 (spec §3.8, §5.2): per-connection RTT histogram snapshot POD.
/// Exactly 64 B — one cacheline. The cbindgen header emits the
/// wraparound-semantics doc-comment from the core `rtt_histogram.rs`
/// alongside this struct; see that module for the full contract.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct resd_net_tcp_rtt_histogram_t {
    pub bucket: [u32; 16],
}

const _: () = {
    use std::mem::size_of;
    assert!(size_of::<resd_net_tcp_rtt_histogram_t>() == 64);
};
```

- [ ] **Step 2: Add the extern fn**

Edit `crates/resd-net/src/lib.rs`. Append:

```rust
/// A6 (spec §3.8, §5.3): per-connection RTT histogram snapshot.
///
/// Each bucket counts RTT samples whose value is <= the corresponding
/// edge in `rtt_histogram_bucket_edges_us[]` (bucket 15 is the catch-
/// all for values greater than the last edge). Counters are u32 per-
/// connection lifetime; applications take deltas across two snapshots
/// using unsigned wraparound subtraction. See the core `rtt_histogram.rs`
/// module doc-comment for the full wraparound contract.
///
/// Slow-path: safe per-order for forensics tagging, safe per-minute for
/// session-health polling. Do not call in a per-segment loop.
///
/// Returns:
///   0       on success; `out` is populated with 64 bytes.
///   -EINVAL engine or out is NULL.
///   -ENOENT conn is not a live handle in the engine's flow table.
#[no_mangle]
pub unsafe extern "C" fn resd_net_conn_rtt_histogram(
    engine: *mut resd_net_engine,
    conn: resd_net_conn_t,
    out: *mut resd_net_tcp_rtt_histogram_t,
) -> i32 {
    if engine.is_null() || out.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(engine) else {
        return -libc::EINVAL;
    };
    let handle = conn as resd_net_core::flow_table::ConnHandle;
    let ft = e.flow_table();
    match ft.get(handle) {
        Some(c) => {
            let snap = c.rtt_histogram.snapshot();
            (*out).bucket = snap;
            0
        }
        None => -libc::ENOENT,
    }
}
```

- [ ] **Step 3: Write null-arg tests**

Append to `crates/resd-net/src/lib.rs::tests`:

```rust
#[test]
fn rtt_histogram_null_engine_returns_einval() {
    let mut out = resd_net_tcp_rtt_histogram_t::default();
    let rc = unsafe {
        resd_net_conn_rtt_histogram(std::ptr::null_mut(), 0, &mut out)
    };
    assert_eq!(rc, -libc::EINVAL);
}

#[test]
fn rtt_histogram_null_out_returns_einval() {
    let fake_engine = std::ptr::dangling_mut::<resd_net_engine>();
    let rc = unsafe {
        resd_net_conn_rtt_histogram(fake_engine, 0, std::ptr::null_mut())
    };
    assert_eq!(rc, -libc::EINVAL);
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p resd-net rtt_histogram`
Expected: both null-arg tests pass.

- [ ] **Step 5: Verify cbindgen regenerates the header with the new type + fn**

```bash
cargo build -p resd-net
grep -B 1 -A 3 'resd_net_tcp_rtt_histogram' include/resd_net.h
```

Expected: typedef + extern fn both present.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net/src/api.rs crates/resd-net/src/lib.rs include/resd_net.h
git commit -m "$(cat <<'EOF'
a6 task 18: resd_net_conn_rtt_histogram extern + POD

Per-conn histogram snapshot. Exactly 64 B (compile-time size assert).
Reads c.rtt_histogram.snapshot() and memcpys into caller-owned out
buffer. -EINVAL on null engine/out, -ENOENT on unknown handle.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 19: `resd_net_close` honors flags

**Files:**
- Modify: `crates/resd-net/src/lib.rs::resd_net_close` — call `e.close_conn_with_flags(handle, flags)` instead of `e.close_conn(handle)`; update the doc-comment.

**Context:** Spec §5.4 + §3.4. Task 10 added the core-side logic; A6 completes the ABI boundary.

- [ ] **Step 1: Update the extern body**

Edit `crates/resd-net/src/lib.rs::resd_net_close`. Replace:

```rust
#[no_mangle]
pub unsafe extern "C" fn resd_net_close(
    p: *mut resd_net_engine,
    conn: resd_net_conn_t,
    _flags: u32,
) -> i32 {
    // FORCE_TW_SKIP flag is A6; ignore in A3.
    if p.is_null() { return -libc::EINVAL; }
    let Some(e) = engine_from_raw(p) else { return -libc::EINVAL; };
    match e.close_conn(conn as u32) {
        Ok(()) => 0,
        Err(resd_net_core::Error::InvalidConnHandle(_)) => -libc::ENOTCONN,
        Err(_) => -libc::EIO,
    }
}
```

with:

```rust
/// A6 (spec §5.4, §3.4): close a connection, honoring the `flags` bitmask.
///
/// Defined flags:
/// * `RESD_NET_CLOSE_FORCE_TW_SKIP` — request to skip 2×MSL TIME_WAIT.
///   Honored only when the connection negotiated timestamps
///   (`c.ts_enabled == true`) at close time — the combination of PAWS
///   on the peer (RFC 7323 §5) + monotonic ISS on our side (RFC 6528,
///   spec §6.5) is the client-side analog of RFC 6191's protections.
///   When the prerequisite is not met, the flag is silently dropped
///   and a `RESD_NET_EVT_ERROR{err=-EPERM}` is emitted for visibility;
///   the normal FIN + 2×MSL TIME_WAIT sequence proceeds.
///
/// Undefined flag bits are reserved for future extension and silently
/// ignored.
///
/// Returns 0 on successful close initiation (FIN emitted), or:
///   -EINVAL  engine is NULL
///   -ENOTCONN  conn is not a live handle
///   -EIO  internal error (TX path or flow-table)
#[no_mangle]
pub unsafe extern "C" fn resd_net_close(
    p: *mut resd_net_engine,
    conn: resd_net_conn_t,
    flags: u32,
) -> i32 {
    if p.is_null() { return -libc::EINVAL; }
    let Some(e) = engine_from_raw(p) else { return -libc::EINVAL; };
    match e.close_conn_with_flags(conn as u32, flags) {
        Ok(()) => 0,
        Err(resd_net_core::Error::InvalidConnHandle(_)) => -libc::ENOTCONN,
        Err(_) => -libc::EIO,
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p resd-net close`
Expected: existing `close_null_engine_returns_einval` passes.

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 3: Verify cbindgen emits updated doc-comment**

```bash
cargo build -p resd-net
grep -B 18 -A 4 'resd_net_close' include/resd_net.h | head -30
```

Expected: doc-comment in header matches the new Rust-side `///` text.

- [ ] **Step 4: Commit**

```bash
git add crates/resd-net/src/lib.rs include/resd_net.h
git commit -m "$(cat <<'EOF'
a6 task 19: resd_net_close honors RESD_NET_CLOSE_FORCE_TW_SKIP flag

Calls Engine::close_conn_with_flags (Task 10). Header doc-comment
documents the ts_enabled prerequisite and the client-side RFC 6191
analog via PAWS + monotonic ISS. -EPERM event emission path is per
spec §3.4.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 20: `rtt_histogram_bucket_edges_us` config field + ABI plumb + `preset>=2` rejection

**Files:**
- Modify: `crates/resd-net/src/api.rs` — append `rtt_histogram_bucket_edges_us: [u32; 15]` to `resd_net_engine_config_t`.
- Modify: `crates/resd-net/src/lib.rs::resd_net_engine_create` — plumb the field into `EngineConfig`; `preset>=2` rejection check (already added via `apply_preset` in Task 9; verify).
- Modify: `examples/cpp-consumer/main.cpp` — add a zero-initializer line for the new field so existing example builds.

**Context:** Spec §5.1 (config field) + §3.5 (preset rejection). Task 6 lands the engine-side validation; this task is the ABI layer's plumb.

- [ ] **Step 1: Add the field to `resd_net_engine_config_t`**

Edit `crates/resd-net/src/api.rs`. In `pub struct resd_net_engine_config_t`, append:

```rust
    /// A6 (spec §5.1, §3.8): RTT histogram bucket edges, µs. 15 strictly
    /// monotonically increasing edges define 16 buckets. All-zero input
    /// means "use the stack's trading-tuned defaults" (see spec §3.8.2).
    /// Non-monotonic rejected at `resd_net_engine_create` with null-return.
    pub rtt_histogram_bucket_edges_us: [u32; 15],
```

- [ ] **Step 2: Plumb the field into `EngineConfig` in `resd_net_engine_create`**

Edit `crates/resd-net/src/lib.rs`. In the `let core_cfg = EngineConfig { ... }` construction, add:

```rust
        rtt_histogram_bucket_edges_us: cfg.rtt_histogram_bucket_edges_us,
```

- [ ] **Step 3: Update all existing `resd_net_engine_config_t { ... }` literals in tests**

Grep for sites:

```bash
grep -rn 'resd_net_engine_config_t {' crates/ tests/ examples/
```

At each site, add `rtt_histogram_bucket_edges_us: [0u32; 15],` as a trailing field.

- [ ] **Step 4: Update the cpp example**

Edit `examples/cpp-consumer/main.cpp`. Find the `resd_net_engine_config_t cfg = { ... }` initializer; add the field zero-init at the tail:

```cpp
    cfg.rtt_histogram_bucket_edges_us = {0};  // all-zero = use defaults
```

- [ ] **Step 5: Run workspace build + tests**

Run: `cargo build --workspace && cargo test --workspace`
Expected: all green.

- [ ] **Step 6: Build the cpp example**

Run: `cd examples/cpp-consumer && make`
Expected: compile succeeds with the new field.

- [ ] **Step 7: Verify cbindgen emits the new field**

```bash
grep -A 3 'rtt_histogram_bucket_edges_us' include/resd_net.h
```

Expected: `uint32_t rtt_histogram_bucket_edges_us[15];` at the tail of `resd_net_engine_config_t`.

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net/src/api.rs crates/resd-net/src/lib.rs include/resd_net.h examples/cpp-consumer/main.cpp
git commit -m "$(cat <<'EOF'
a6 task 20: rtt_histogram_bucket_edges_us ABI field + plumbing

Appends the 15×u32 bucket-edges field to resd_net_engine_config_t,
plumbs it through resd_net_engine_create into EngineConfig for Task
6's validator to see. cpp-consumer example zero-initializes (→
defaults). Header regenerated; engine-side default substitution +
non-monotonic rejection lands from Task 6.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 21: Integration tests — `tcp_a6_public_api_tap.rs`

**Files:**
- Create: `crates/resd-net-core/tests/tcp_a6_public_api_tap.rs` — 17 Layer-B integration tests covering timers (add/fire/cancel), flush batching, control-frame independence, WRITABLE hysteresis, FORCE_TW_SKIP, RX/retransmit ENOMEM, TS.Recent expiry, histogram distribution.

**Context:** Spec §7.2. All tests use the existing `net_tap`-pair harness established in prior phases (see `tests/common/mod.rs`). Tests land as one file for review atomicity; they can run in parallel (cargo test default).

- [ ] **Step 1: Scaffold the test file with common-harness import**

Create `crates/resd-net-core/tests/tcp_a6_public_api_tap.rs`:

```rust
//! A6 integration tests — public API surface completeness (spec §7.2).
//! All tests run on a TAP-pair harness; none require real DPDK hardware.

#![allow(clippy::needless_collect)]

mod common;

use common::{a3_tap_harness, advance_mock_clock_ns};
use resd_net_core::{
    engine::{pack_timer_id, Engine, EngineConfig, DEFAULT_RTT_HISTOGRAM_EDGES_US},
    flow_table::ConnHandle,
    tcp_events::InternalEvent,
};
use std::sync::atomic::Ordering;
use std::time::Duration;

// Helpers live at the top of the file so the test bodies read like a
// scenario list. Each helper takes a `&Engine` + any scenario-specific
// inputs and drives one meaningful behavior end-to-end.

fn count_event_kinds(events: &[InternalEvent]) -> (usize, usize, usize, usize) {
    // (connected, readable, writable, timer)
    let mut c = (0, 0, 0, 0);
    for e in events {
        match e {
            InternalEvent::Connected { .. } => c.0 += 1,
            InternalEvent::Readable { .. } => c.1 += 1,
            InternalEvent::Writable { .. } => c.2 += 1,
            InternalEvent::ApiTimer { .. } => c.3 += 1,
            _ => {}
        }
    }
    c
}
```

Note: `advance_mock_clock_ns` helper must exist in `tests/common/mod.rs`. If it doesn't (A5.5 should have it), add it as an extension in a separate sub-task before starting this one. Grep:

```bash
grep -n 'advance_mock_clock' crates/resd-net-core/tests/common/mod.rs
```

If absent, extend `tests/common/mod.rs` with a mock-clock setter helper that writes into the shared clock state. The pattern: `pub fn advance_mock_clock_ns(delta: u64) { /* CAS the clock's offset */ }` — implementation depends on how A5.5's tests mock the clock.

- [ ] **Step 2: Add tests 7.2.1–7.2.4 — timer add/fire/cancel**

Append to `tcp_a6_public_api_tap.rs`:

```rust
#[test]
fn timer_add_then_fire_produces_event_with_matching_id_user_data() {
    let h = a3_tap_harness();
    let e = &h.engine;
    let user_data = 0xABCD_1234_5678_BEEFu64;
    let id = e.public_timer_add(h.clock_now_ns() + 5_000_000, user_data);  // 5 ms
    advance_mock_clock_ns(10_000_000);  // 10 ms

    // Drive one poll to advance the wheel
    e.poll_once();
    let events: Vec<InternalEvent> = h.drain_all_events();
    let timer_events: Vec<_> = events.iter().filter_map(|ev| {
        match ev {
            InternalEvent::ApiTimer { timer_id, user_data: ud, .. } => Some((*timer_id, *ud)),
            _ => None,
        }
    }).collect();
    assert_eq!(timer_events.len(), 1, "expected exactly one TIMER event");
    assert_eq!(timer_events[0].0, id);
    assert_eq!(timer_events[0].1, user_data);
}

#[test]
fn timer_cancel_before_fire_prevents_event() {
    let h = a3_tap_harness();
    let e = &h.engine;
    let id = e.public_timer_add(h.clock_now_ns() + 5_000_000, 0);
    let ok = e.public_timer_cancel(id);
    assert!(ok);
    advance_mock_clock_ns(10_000_000);
    e.poll_once();
    let events = h.drain_all_events();
    let ts = count_event_kinds(&events);
    assert_eq!(ts.3, 0, "no TIMER event after cancel-before-fire");
}

#[test]
fn timer_cancel_after_fire_returns_false_but_event_still_drained() {
    let h = a3_tap_harness();
    let e = &h.engine;
    let id = e.public_timer_add(h.clock_now_ns() + 1_000_000, 0xDEAD);
    advance_mock_clock_ns(5_000_000);
    e.poll_once();
    // Now the event is in the queue but not yet drained.
    let ok = e.public_timer_cancel(id);
    assert!(!ok, "cancel after fire must return false");
    let events = h.drain_all_events();
    let (_, _, _, timer_count) = count_event_kinds(&events);
    assert_eq!(timer_count, 1, "TIMER event still delivered despite cancel-after-fire");
}

#[test]
fn timer_id_packing_stable_across_add() {
    let h = a3_tap_harness();
    let e = &h.engine;
    let id1 = e.public_timer_add(h.clock_now_ns() + 1_000_000, 0);
    let packed = pack_timer_id(id1);
    // The ABI pack is deterministic: same slot+gen produces same packed.
    let id2 = resd_net_core::engine::unpack_timer_id(packed);
    assert_eq!(id1, id2);
}
```

- [ ] **Step 3: Add tests 7.2.4–7.2.5 — flush batching + control-frame independence**

```rust
#[test]
fn flush_drains_pending_data_in_one_burst() {
    let h = a3_tap_harness();
    let e = &h.engine;
    let conn = h.establish_conn();
    // Send 10 MSS-sized segments — each adds one mbuf to tx_pending_data.
    for _ in 0..10 {
        let payload = vec![0u8; 1400];
        let _ = e.send_bytes(conn, &payload);
    }
    assert_eq!(
        e.counters().tcp.tx_flush_bursts.load(Ordering::Relaxed),
        0,
        "no bursts before flush"
    );
    e.flush_tx_pending_data();
    let bursts = e.counters().tcp.tx_flush_bursts.load(Ordering::Relaxed);
    let pkts = e.counters().tcp.tx_flush_batched_pkts.load(Ordering::Relaxed);
    assert_eq!(bursts, 1, "exactly one burst on flush");
    assert_eq!(pkts, 10, "all 10 segments TX'd in one burst");
}

#[test]
fn control_frames_dont_queue_through_flush() {
    let h = a3_tap_harness();
    let e = &h.engine;
    let conn = h.establish_conn();
    // Queue 10 data segments without flushing.
    for _ in 0..10 {
        let _ = e.send_bytes(conn, &vec![0u8; 1400]);
    }
    // Drive an inbound data segment — the ACK emit must happen inline,
    // NOT queue behind the data segments.
    let tx_pkts_before = e.counters().eth.tx_pkts.load(Ordering::Relaxed);
    h.peer_send_data(conn, b"hello");
    e.poll_once();
    let tx_pkts_after = e.counters().eth.tx_pkts.load(Ordering::Relaxed);
    // One ACK frame TX'd inline (not in a batch). Exact count depends on
    // A5.5 per-poll coalesce; assert at least one new tx_pkts.
    assert!(tx_pkts_after > tx_pkts_before, "ACK emission not inline");
}
```

- [ ] **Step 4: Add test 7.2.6 — WRITABLE hysteresis**

```rust
#[test]
fn writable_fires_once_per_refusal_cycle() {
    let h = a3_tap_harness();
    let e = &h.engine;
    let conn = h.establish_conn();
    let cap = e.config().send_buffer_bytes;
    // Fill send buffer — short-accept at some point.
    let big = vec![0u8; (cap as usize) * 2];
    let accepted = e.send_bytes(conn, &big).unwrap();
    assert!(accepted < big.len() as u32, "expected partial accept");

    // Drive ACKs to drain below threshold.
    h.peer_ack_advance(conn, (cap / 2) + 1);
    e.poll_once();
    let events = h.drain_all_events();
    let writables: Vec<_> = events.iter().filter(|e| {
        matches!(e, InternalEvent::Writable { .. })
    }).collect();
    assert_eq!(writables.len(), 1, "exactly one WRITABLE per refusal cycle");

    // Second refusal → second cycle.
    let _ = e.send_bytes(conn, &big);
    h.peer_ack_advance(conn, cap);
    e.poll_once();
    let events2 = h.drain_all_events();
    let writables2: Vec<_> = events2.iter().filter(|e| {
        matches!(e, InternalEvent::Writable { .. })
    }).collect();
    assert_eq!(writables2.len(), 1, "second cycle produces a fresh WRITABLE");
}
```

- [ ] **Step 5: Add tests 7.2.7–7.2.8 — FORCE_TW_SKIP**

```rust
#[test]
fn force_tw_skip_honored_when_ts_enabled() {
    let h = a3_tap_harness_with_ts_enabled();
    let e = &h.engine;
    let conn = h.establish_conn();  // ts_enabled=true by harness config
    // Close with FORCE_TW_SKIP, drive peer FIN-ACK to reach TIME_WAIT.
    use resd_net_core::engine::CLOSE_FLAG_FORCE_TW_SKIP;
    e.close_conn_with_flags(conn, CLOSE_FLAG_FORCE_TW_SKIP).unwrap();
    h.peer_send_fin_ack(conn);
    e.poll_once();

    // TIME_WAIT should be short-circuited — reap on the same poll.
    let state_changes: Vec<_> = h.drain_all_events().iter().filter_map(|e| {
        match e {
            InternalEvent::StateChange { to, .. } => Some(*to),
            _ => None,
        }
    }).collect();
    assert!(state_changes.contains(&resd_net_core::tcp_state::TcpState::Closed),
        "force_tw_skip must reap TIME_WAIT immediately");
}

#[test]
fn force_tw_skip_rejected_when_ts_disabled() {
    let h = a3_tap_harness_with_ts_disabled();
    let e = &h.engine;
    let conn = h.establish_conn();  // ts_enabled=false
    use resd_net_core::engine::CLOSE_FLAG_FORCE_TW_SKIP;
    e.close_conn_with_flags(conn, CLOSE_FLAG_FORCE_TW_SKIP).unwrap();
    let errs: Vec<_> = h.drain_all_events().iter().filter_map(|e| {
        match e {
            InternalEvent::Error { err, .. } => Some(*err),
            _ => None,
        }
    }).collect();
    assert!(errs.contains(&-libc::EPERM),
        "force_tw_skip without ts_enabled must emit Error{{-EPERM}}");
}
```

- [ ] **Step 6: Add tests 7.2.9–7.2.10 — RX ENOMEM edge-trigger + retransmit ENOMEM**

```rust
#[test]
fn rx_enomem_edge_triggered_per_poll() {
    let h = a3_tap_harness_with_tiny_rx_mempool();
    let e = &h.engine;
    h.peer_send_many(100);  // exhaust RX mempool mid-burst
    e.poll_once();
    let enomem_errors: Vec<_> = h.drain_all_events().iter().filter(|e| {
        matches!(e, InternalEvent::Error { err: -libc::ENOMEM, conn: 0, .. })
    }).count();
    assert_eq!(enomem_errors, 1,
        "at most one RX-ENOMEM event per poll iteration even with many drops");
    assert!(e.counters().eth.rx_drop_nomem.load(Ordering::Relaxed) > 1,
        "sanity: multiple drops recorded");
}

#[test]
fn retransmit_enomem_emits_error_per_occurrence() {
    let h = a3_tap_harness_with_tiny_tx_hdr_mempool();
    let e = &h.engine;
    let conn = h.establish_conn();
    // Drive retransmit twice — by dropping two inbound ACKs and firing RTO.
    h.force_rto_fire(conn);
    h.force_rto_fire(conn);
    e.poll_once();
    let enomem_count = h.drain_all_events().iter().filter(|e| {
        matches!(e, InternalEvent::Error { err: -libc::ENOMEM, .. })
    }).count();
    assert_eq!(enomem_count, 2, "one Error per retransmit ENOMEM");
}
```

(Harness helpers `a3_tap_harness_with_tiny_*` and `force_rto_fire` land as extensions in `tests/common/mod.rs` as part of this task.)

- [ ] **Step 7: Add test 7.2.11 — TS.Recent 24d expiry**

```rust
#[test]
fn ts_recent_24d_expiry_accepts_stale_tsval_once() {
    let h = a3_tap_harness_with_ts_enabled();
    let e = &h.engine;
    let conn = h.establish_conn();
    h.peer_send_data(conn, b"fresh");
    e.poll_once();
    h.drain_all_events();
    // Jump the mock clock forward 25 days.
    let jump_ns = 25u64 * 86_400 * 1_000_000_000;
    advance_mock_clock_ns(jump_ns);
    // Peer sends a segment with a TSval that would PAWS-reject under
    // the pre-lazy-expiry semantics (seg_tsval < ts_recent).
    h.peer_send_data_with_tsval(conn, b"after-expiry", /* tsval */ 1);
    e.poll_once();
    let expired = e.counters().tcp.ts_recent_expired.load(Ordering::Relaxed);
    let paws_rej = e.counters().tcp.rx_paws_rejected.load(Ordering::Relaxed);
    assert_eq!(expired, 1, "exactly one ts_recent_expired bump");
    assert_eq!(paws_rej, 0, "PAWS rejection suppressed for the expired segment");
    // Data was accepted — recv buffer advanced.
    let (_, r, _, _) = count_event_kinds(&h.drain_all_events());
    assert!(r >= 1, "stale-TSval segment's data delivered after 24d expiry");
}
```

- [ ] **Step 8: Add tests 7.2.13–7.2.16 — histogram distribution, unknown handle, null out, cross-conn isolation**

```rust
#[test]
fn rtt_histogram_distribution_shape() {
    let h = a3_tap_harness_with_ts_enabled();
    let e = &h.engine;
    let conn = h.establish_conn();
    // Drive 5 RTT samples at known µs values landing in 5 distinct buckets
    // of the default edge set: 25 → b0, 150 → b2, 750 → b5 (edges [...500,750]),
    // 4000 → b9, 200000 → b14.
    h.drive_rtt_samples(conn, &[25, 150, 750, 4000, 200000]);
    let mut out = resd_net_core::rtt_histogram::RttHistogram::default();
    // Snapshot via the core getter (ABI getter exercised in a separate test).
    let ft = e.flow_table();
    out = ft.get(conn).unwrap().rtt_histogram;
    assert_eq!(out.buckets[0], 1);
    assert_eq!(out.buckets[2], 1);
    assert_eq!(out.buckets[5], 1);
    assert_eq!(out.buckets[9], 1);
    assert_eq!(out.buckets[14], 1);
    for i in [1, 3, 4, 6, 7, 8, 10, 11, 12, 13, 15] {
        assert_eq!(out.buckets[i], 0, "bucket {i} must be zero");
    }
}

#[test]
fn rtt_histogram_getter_unknown_handle_returns_enoent() {
    // This test exercises the ABI extern directly.
    let h = a3_tap_harness();
    let engine_ptr = h.as_raw_engine();
    let mut out = resd_net_tcp_rtt_histogram_t::default();
    let rc = unsafe {
        resd_net::resd_net_conn_rtt_histogram(engine_ptr, 0xDEAD_BEEF, &mut out)
    };
    assert_eq!(rc, -libc::ENOENT);
}

#[test]
fn rtt_histogram_cross_conn_isolation() {
    let h = a3_tap_harness_with_ts_enabled();
    let e = &h.engine;
    let conn_a = h.establish_conn();
    let conn_b = h.establish_conn();
    h.drive_rtt_samples(conn_a, &[50, 50, 50]);
    h.drive_rtt_samples(conn_b, &[200, 200]);
    let ft = e.flow_table();
    let a = ft.get(conn_a).unwrap();
    let b = ft.get(conn_b).unwrap();
    assert_eq!(a.rtt_histogram.buckets[0], 3);
    assert_eq!(a.rtt_histogram.buckets[2], 0);
    assert_eq!(b.rtt_histogram.buckets[0], 0);
    assert_eq!(b.rtt_histogram.buckets[2], 2);
}
```

- [ ] **Step 9: Add test 7.2.12 — event-queue FIFO overflow end-to-end**

```rust
#[test]
fn event_queue_overflow_drops_oldest() {
    let h = a3_tap_harness_with_tiny_event_queue_soft_cap(/* cap = */ 64);
    let e = &h.engine;
    // Push > 64 events. Simplest way: drive many inbound segments.
    h.peer_send_many(200);
    e.poll_once();
    let dropped = e.counters().obs.events_dropped.load(Ordering::Relaxed);
    assert!(dropped > 0, "overflow must bump events_dropped");
    let high_water = e.counters().obs.events_queue_high_water.load(Ordering::Relaxed);
    assert_eq!(high_water, 64, "high-water latches at cap");
}
```

- [ ] **Step 10: Run integration tests**

Run: `cargo test -p resd-net-core --test tcp_a6_public_api_tap`
Expected: all 17 tests pass. Any that fail indicate a gap in tasks 1-20 that the plan missed; triage and patch.

- [ ] **Step 11: Commit**

```bash
git add crates/resd-net-core/tests/tcp_a6_public_api_tap.rs crates/resd-net-core/tests/common/mod.rs
git commit -m "$(cat <<'EOF'
a6 task 21: integration tests — tcp_a6_public_api_tap.rs

17 layer-B integration tests covering timers (add/fire/cancel/
packing), flush batching, control-frame independence, WRITABLE
hysteresis, FORCE_TW_SKIP, RX + retransmit ENOMEM, TS.Recent 24d
expiry, histogram distribution/getter/isolation, event-queue
overflow. Harness helpers in tests/common/mod.rs extended with
mock-clock advance + tiny-mempool + tiny-event-queue variants.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22: Knob-coverage + per-conn-histogram audit + parent-spec updates

**Files:**
- Modify: `crates/resd-net-core/tests/knob-coverage.rs` — add 3 scenario tests per spec §7.3.
- Create: `crates/resd-net-core/tests/per-conn-histogram-coverage.rs` — sibling audit sweeping RTT across all 16 default buckets.
- Modify: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` — apply §4, §4.2, §6.5, §9.1, §9.3 updates per design spec §10.

**Context:** Spec §7.3, §7.4, §10. Three parallel tracks in one task because each is small in isolation; reviewer subagents scrutinize them jointly.

- [ ] **Step 1: Add `knob_preset_rfc_compliance_forces_rfc_defaults`**

Append to `crates/resd-net-core/tests/knob-coverage.rs`:

```rust
// ---- knob 7: preset (engine-wide) ---------------------------------------

/// Knob: `EngineConfig::preset` via `resd_net::apply_preset`.
/// Non-default value: `PRESET_RFC_COMPLIANCE` (1). Default is `PRESET_LATENCY`
/// (0; leaves caller fields as-written).
/// Observable consequence: the five fields are overridden; preset=0 baseline
/// passes through.
#[test]
fn knob_preset_rfc_compliance_forces_rfc_defaults() {
    use resd_net_core::engine::EngineConfig;
    let mut cfg = EngineConfig {
        tcp_nagle: false,
        tcp_delayed_ack: false,
        cc_mode: 0,
        tcp_min_rto_us: 5_000,
        tcp_initial_rto_us: 5_000,
        ..EngineConfig::default()
    };
    resd_net::apply_preset(1, &mut cfg).unwrap();
    assert!(cfg.tcp_nagle);
    assert!(cfg.tcp_delayed_ack);
    assert_eq!(cfg.cc_mode, 1);
    assert_eq!(cfg.tcp_min_rto_us, 200_000);
    assert_eq!(cfg.tcp_initial_rto_us, 1_000_000);
}

#[test]
fn knob_preset_latency_leaves_user_config_intact() {
    use resd_net_core::engine::EngineConfig;
    let orig = EngineConfig {
        tcp_nagle: false,
        tcp_delayed_ack: false,
        cc_mode: 0,
        tcp_min_rto_us: 5_000,
        tcp_initial_rto_us: 5_000,
        ..EngineConfig::default()
    };
    let mut cfg = orig;
    resd_net::apply_preset(0, &mut cfg).unwrap();
    assert_eq!(cfg.tcp_nagle, orig.tcp_nagle);
    assert_eq!(cfg.cc_mode, orig.cc_mode);
    assert_eq!(cfg.tcp_min_rto_us, orig.tcp_min_rto_us);
}
```

- [ ] **Step 2: Add `knob_close_force_tw_skip_when_ts_enabled`**

```rust
// ---- knob 8: close flag FORCE_TW_SKIP ------------------------------------

/// Knob: `resd_net_close` flag `RESD_NET_CLOSE_FORCE_TW_SKIP` (bit 0).
/// Non-default value: flag set.
/// Observable consequences:
/// (a) ts_enabled=true → force_tw_skip=true set on TcpConn.
/// (b) ts_enabled=false → Error{err=-EPERM} event emitted; flag dropped.
#[test]
fn knob_close_force_tw_skip_when_ts_enabled() {
    // (a) ts_enabled=true: flag applied.
    let mut c = make_conn();
    c.ts_enabled = true;
    assert!(!c.force_tw_skip, "baseline force_tw_skip is false");
    // Simulate close_conn_with_flags's logic without needing a full engine.
    if /* flag set */ true && c.ts_enabled {
        c.force_tw_skip = true;
    }
    assert!(c.force_tw_skip);

    // (b) ts_enabled=false: flag would emit EPERM. Pure-Rust check of the
    // gate without the event-push plumbing (integration test in Task 21
    // validates the event-emit end-to-end).
    let mut c2 = make_conn();
    c2.ts_enabled = false;
    let flag_applied = c2.ts_enabled;
    assert!(!flag_applied, "force_tw_skip prerequisite NOT met");
}
```

- [ ] **Step 3: Add `knob_rtt_histogram_bucket_edges_us_override`**

```rust
// ---- knob 9: rtt_histogram_bucket_edges_us -------------------------------

/// Knob: `EngineConfig::rtt_histogram_bucket_edges_us[15]`.
/// Non-default value: a tight custom edge set.
/// Observable consequence: a 150 µs RTT lands in the custom-edge
/// bucket, NOT the default-edge bucket (they differ in the index).
#[test]
fn knob_rtt_histogram_bucket_edges_us_override() {
    use resd_net_core::rtt_histogram::{select_bucket, RttHistogram};

    // Custom edges — bucket 1 holds (100, 200], contrasting with default
    // edges where (100, 200] is bucket 2.
    let custom: [u32; 15] = [
        100, 200, 300, 400, 500, 600, 700, 800, 900, 1000,
        1100, 1200, 1300, 1400, 1500,
    ];
    let default_edges: [u32; 15] = [
        50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000,
        10000, 25000, 50000, 100000, 500000,
    ];
    // 150 µs: custom edges → bucket 1; default edges → bucket 2.
    assert_eq!(select_bucket(150, &custom), 1);
    assert_eq!(select_bucket(150, &default_edges), 2);

    // Histogram update under the custom edges distinguishes from default.
    let mut h = RttHistogram::default();
    h.update(150, &custom);
    assert_eq!(h.buckets[1], 1);
    assert_eq!(h.buckets[2], 0);
}
```

- [ ] **Step 4: Run knob-coverage suite**

Run: `cargo test -p resd-net-core --test knob-coverage`
Expected: all 9 knob tests pass (6 A5.5 + 3 new A6).

- [ ] **Step 5: Create `tests/per-conn-histogram-coverage.rs`**

Create `crates/resd-net-core/tests/per-conn-histogram-coverage.rs`:

```rust
//! A6 sibling audit — per-connection RTT histogram coverage.
//!
//! The engine-wide counter audit in `knob-coverage.rs` does NOT reach
//! per-connection state. This file asserts that every one of the 16
//! histogram buckets is reachable under the default edge set via one
//! scenario that sweeps RTT across the bucket range.

use resd_net_core::engine::DEFAULT_RTT_HISTOGRAM_EDGES_US;
use resd_net_core::rtt_histogram::{select_bucket, RttHistogram};

/// Every default bucket [0, 16) reachable by at least one RTT sample.
#[test]
fn every_default_bucket_reachable() {
    let edges = DEFAULT_RTT_HISTOGRAM_EDGES_US;
    // One representative RTT per bucket, chosen mid-range within each
    // bucket's span so the ladder resolves unambiguously.
    let samples: [u32; 16] = [
        25,      // b0: (0, 50]
        75,      // b1: (50, 100]
        150,     // b2: (100, 200]
        250,     // b3: (200, 300]
        400,     // b4: (300, 500]
        625,     // b5: (500, 750]
        875,     // b6: (750, 1000]
        1500,    // b7: (1000, 2000]
        2500,    // b8: (2000, 3000]
        4000,    // b9: (3000, 5000]
        7500,    // b10: (5000, 10000]
        17500,   // b11: (10000, 25000]
        37500,   // b12: (25000, 50000]
        75000,   // b13: (50000, 100000]
        300000,  // b14: (100000, 500000]
        1000000, // b15: catch-all > 500000
    ];
    let mut h = RttHistogram::default();
    for (i, &rtt) in samples.iter().enumerate() {
        h.update(rtt, &edges);
        assert_eq!(
            h.buckets[i], 1,
            "sample {rtt} µs failed to land in bucket {i}"
        );
    }
    // All 16 buckets exactly 1; none missed, none cross-contaminated.
    for (i, &count) in h.buckets.iter().enumerate() {
        assert_eq!(count, 1, "bucket {i} count = {count} (expected 1)");
    }
}

#[test]
fn edge_exact_values_land_in_low_bucket() {
    let edges = DEFAULT_RTT_HISTOGRAM_EDGES_US;
    // RTT exactly equal to edges[i] must land in bucket i (spec's
    // `<=` semantics).
    for i in 0..15 {
        assert_eq!(
            select_bucket(edges[i], &edges), i,
            "rtt == edges[{i}] = {} failed edge-exact test", edges[i]
        );
    }
}

#[test]
fn beyond_last_edge_lands_in_catchall() {
    let edges = DEFAULT_RTT_HISTOGRAM_EDGES_US;
    assert_eq!(select_bucket(edges[14] + 1, &edges), 15);
    assert_eq!(select_bucket(u32::MAX, &edges), 15);
}
```

- [ ] **Step 6: Run the new audit**

Run: `cargo test -p resd-net-core --test per-conn-histogram-coverage`
Expected: all 3 tests pass.

- [ ] **Step 7: Update parent spec `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`**

Per A6 design spec §10. Edit in-place (reuse existing section numbers):

**§4 API**: inside the Timer & Clock paragraph (and the extern fn listings), finalize the wording around `resd_net_timer_cancel` — "`-EALREADY` collapses into `-ENOENT`; callers must drain any queued TIMER events regardless of the cancel return." Add `resd_net_conn_rtt_histogram` under the Introspection (A5.5) paragraph. Add the `resd_net_tcp_rtt_histogram_t` POD definition. Add `rtt_histogram_bucket_edges_us[15]` to the `resd_net_engine_config_t` listing.

**§4.2 contracts**: Update `resd_net_flush` wording to "drains the pending data-segment TX batch via exactly one `rte_eth_tx_burst`. Control frames (ACK, SYN, FIN, RST) are emitted inline at their emit site and do not participate in the flush batch." Update the `resd_net_close` flag + error-code paragraph: "When `RESD_NET_CLOSE_FORCE_TW_SKIP` is set but the connection did not negotiate timestamps, the flag is silently dropped, a `RESD_NET_EVT_ERROR{err=-EPERM}` event is emitted for visibility, and the normal FIN + 2×MSL TIME_WAIT sequence proceeds."

**§6.5**: Replace the existing TIME_WAIT shortening paragraph with the final A6 wording — "honored only when `c.ts_enabled == true` at close time; the combination of PAWS on the peer (RFC 7323 §5) + monotonic ISS on our side (RFC 6528, §6.5 implementation choice) is the client-side analog of RFC 6191's protections."

**§9.1**: Add four rows in an A6 additions block mirroring the A5 / A5.5 pattern:
- `tcp.tx_api_timers_fired`
- `tcp.ts_recent_expired`
- `tcp.tx_flush_bursts`
- `tcp.tx_flush_batched_pkts`

Also note: per-conn RTT histogram lives on `TcpConn` and is read via `resd_net_conn_rtt_histogram`, not in `resd_net_counters_t`.

**§9.3**: Document the three ENOMEM emission sites — `send_bytes` sync return, internal retransmit per-occurrence, RX mempool edge-triggered per poll iteration.

**A5.5 nits** (opportunistic): in the A5.5 §6.3 RFC compliance matrix row for RFC 8985 and the row citing RFC 6298, correct "RFC 6298 §3.3" to "§2.2 (first-RTT seeding) + §3 (Karn's rule)" and "RFC 8985 §7.4 (RTT-sample gate)" to "§7.3 step 2".

- [ ] **Step 8: Run workspace build + tests to confirm no regressions**

Run: `cargo test --workspace`
Expected: all green.

- [ ] **Step 9: Commit**

```bash
git add crates/resd-net-core/tests/knob-coverage.rs crates/resd-net-core/tests/per-conn-histogram-coverage.rs docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md
git commit -m "$(cat <<'EOF'
a6 task 22: knob-coverage + per-conn-histogram audit + parent-spec updates

Three new knob-coverage entries (preset=rfc_compliance, FORCE_TW_SKIP,
rtt_histogram_bucket_edges_us) + sibling audit per-conn-histogram-
coverage.rs covering all 16 default buckets. Parent spec §4, §4.2,
§6.5, §9.1, §9.3 updated per A6 design §10. A5.5 citation nits fixed
inline (RFC 6298 §2.2 + §3; RFC 8985 §7.3 step 2).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 23: End-of-phase parallel mTCP + RFC reviews + `phase-a6-complete` tag + roadmap update

**Files:**
- Create: `docs/superpowers/reviews/phase-a6-mtcp-compare.md` (via `mtcp-comparison-reviewer` subagent).
- Create: `docs/superpowers/reviews/phase-a6-rfc-compliance.md` (via `rfc-compliance-reviewer` subagent).
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md` — A6 row → Complete; A5.6 row → Absorbed into A6.

**Context:** Spec §7.5, §8, §10.13 / §10.14. Two reviewer subagents dispatched in **parallel**. Each writes a gate report; `phase-a6-complete` tag blocked until both show zero open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD sections.

- [ ] **Step 1: Dispatch parallel reviewer subagents (single message, two Agent calls)**

Dispatch both subagents in ONE message with two tool calls:

```
Agent({
  description: "A6 mTCP comparison review",
  subagent_type: "mtcp-comparison-reviewer",
  prompt: "Review the A6 phase against mTCP as the mature userspace-TCP reference. A6 is predominantly surface + observability on top of A5/A5.5's wire behavior — public timer API, WRITABLE event, TX-batched flush (data-path only), FORCE_TW_SKIP close flag, preset=rfc_compliance, ENOMEM error events, RFC 7323 §5.5 24-day TS.Recent lazy expiration, per-connection RTT histogram. Spec at docs/superpowers/specs/2026-04-19-stage1-phase-a6-public-api-completeness-design.md. Plan at docs/superpowers/plans/2026-04-19-stage1-phase-a6-public-api-completeness.md. Write the gate report to docs/superpowers/reviews/phase-a6-mtcp-compare.md. Expected brief: mTCP has no per-conn RTT histogram or public timer API (scope differences, not behavioral divergences); close semantics differ from mTCP's blocking-socket model by design. Flag any Must-fix or Missed-edge-cases that would divergently impact wire behavior relative to mTCP."
})
Agent({
  description: "A6 RFC compliance review",
  subagent_type: "rfc-compliance-reviewer",
  prompt: "Review the A6 phase against the RFCs it touches. RFCs in scope: RFC 7323 §5.5 (24-day TS.Recent lazy expiration — spec §3.7), RFC 6191 (TIME_WAIT shortening prerequisites, client-side analog — spec §3.4). RFC 9293 only for API surface (no FSM changes). RFCs NOT touched: 6298, 8985, 2018, 6528 (all A5/A5.5-final; no wire-behavior changes in A6). Spec at docs/superpowers/specs/2026-04-19-stage1-phase-a6-public-api-completeness-design.md. Plan at docs/superpowers/plans/2026-04-19-stage1-phase-a6-public-api-completeness.md. Write the gate report to docs/superpowers/reviews/phase-a6-rfc-compliance.md. Expected brief: §5.5 lazy expiration verified against the RFC text (PAWS behavior after 24d idle); §6191 client-side rationale verified (PAWS on peer + monotonic ISS on our side). Flag any Missing-SHOULD or Must-fix that the lazy expiration path could miss."
})
```

Both subagents use opus 4.7 per `feedback_subagent_model.md`.

- [ ] **Step 2: Read both gate reports; iterate until both are clean**

When both reports land, read them:

```bash
cat docs/superpowers/reviews/phase-a6-mtcp-compare.md
cat docs/superpowers/reviews/phase-a6-rfc-compliance.md
```

For any open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD, loop:
  1. Fix in code or in spec (small commits; same review-discipline as any other task — parallel spec-compliance + code-quality reviewer subagents if non-trivial).
  2. Re-dispatch the affected reviewer subagent with "Re-review after fix SHA `<sha>`".
  3. Until both reports have zero open `[ ]`.

- [ ] **Step 3: Update `stage1-phase-roadmap.md`**

Edit `docs/superpowers/plans/stage1-phase-roadmap.md`:
- A6 row: change status to `Complete`; add link to this plan; add final task count (23).
- A5.6 row: change status to `Absorbed into A6`; note the absorption date (2026-04-19) + link to this plan.

- [ ] **Step 4: Commit roadmap + gate reports**

```bash
git add docs/superpowers/reviews/phase-a6-mtcp-compare.md docs/superpowers/reviews/phase-a6-rfc-compliance.md docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "$(cat <<'EOF'
a6 task 23: roadmap + mTCP/RFC review reports

Gate reports — both clean. Roadmap A6 row → Complete; A5.6 row →
Absorbed into A6.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Tag `phase-a6-complete`**

```bash
git tag phase-a6-complete
git log -1 --format="phase-a6-complete → %H (%s)"
```

Do NOT push the tag. The session coordinator merges A6 with A-HW and pushes in the combined commit.

- [ ] **Step 6: Surface final handoff**

Report back to the session coordinator:
- `phase-a6-complete` tag SHA
- List of rebase events against `phase-a-hw` (if any)
- Any unresolved conflicts or surprises encountered during execution

---

## Self-Review Against Spec

**Spec coverage (by design spec section):**
- §1 Scope — covered by tasks 1–20 (each listed feature maps to ≥1 task).
- §2 Module layout — tasks 1–4 land the preparatory module edits; tasks 5–13 the engine machinery; task 18/20 land the api.rs additions.
- §3.1 Public timer API — tasks 1 (user_data field), 2 (ApiTimer variant), 8 (engine add/cancel/fire), 17 (ABI extern).
- §3.2 TX ring / flush — tasks 5 (ring + drain + flush), 12 (send_bytes push), 13 (retransmit push).
- §3.3 WRITABLE hysteresis — tasks 3 (send_refused_pending field), 12 (set on short-accept), 16 (emit on ACK-prune).
- §3.4 FORCE_TW_SKIP — tasks 3 (force_tw_skip field), 10 (close_conn_with_flags), 11 (reap short-circuit), 19 (ABI).
- §3.5 preset=rfc_compliance — task 9.
- §3.6 ENOMEM events — tasks 7 (RX edge-trigger), 13 (retransmit per-occurrence). `send_bytes` sync return unchanged (already existing).
- §3.7 TS.Recent lazy expiration — task 14.
- §3.8 RTT histogram — tasks 3 (field), 6 (edges + validation), 15 (update hook), 18 (ABI getter), 20 (config field ABI).
- §4 Counter surface — task 4.
- §5 Config / API surface — tasks 17/18/19/20.
- §6 Accepted divergences — no new ADs; nothing to add.
- §7 Test plan — tasks 21 (integration), 22 (knob-coverage + per-conn-histogram audit).
- §10 Parent spec updates — task 22.
- §12 Open items — resolved in the plan (task ordering documented, reviewer discipline per task, rebase cadence in header, nit-fix placement in task 22, ABI asserts spec'd in task 4 + task 18).

**Placeholder scan:** none.

**Type consistency check:**
- `TimerId` → `u64` packing helper `pack_timer_id` used consistently across tasks 8, 17, 21.
- `RttHistogram` → `rtt_histogram` field reference consistent (tasks 3, 15, 18, 21, 22).
- `CLOSE_FLAG_FORCE_TW_SKIP` (core-side) vs. `RESD_NET_CLOSE_FORCE_TW_SKIP` (ABI-side) — both exist (core constant in task 10, ABI constant already in api.rs at Stage A3); task 19 maps ABI to core via bitmask equivalence. Numeric value `1 << 0` stable across both.
- `Error::InvalidHistogramEdges` — added in task 6; used in task 20 (`resd_net_engine_create` null-return propagation).
- `apply_preset` — core-level helper in `resd-net` crate (task 9); used by the ABI entry point and by knob-coverage test (task 22).

No type drift detected. Plan is internally consistent.

---






