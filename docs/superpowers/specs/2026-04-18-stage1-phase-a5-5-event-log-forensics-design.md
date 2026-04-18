# Phase A5.5 — Event-log forensics + in-flight introspection (Design Spec)

**Status:** draft for plan-writing.
**Parent spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` — A5.5.
**Branch:** `phase-a5-5` (off `phase-a5-complete` tag).
**Ships:** `phase-a5-5-complete` tag gated on mTCP + RFC review reports (lightweight — scope does not touch wire behavior).

---

## 1. Scope

A5.5 closes three forensics gaps identified during A5 design review. All three are small, independent, and driven by the order-entry post-mortem use case: "the trader saw a stall at T; tell me exactly what the stack was doing at T ± a few µs."

In scope:

- **Event emission-time stamping** — fix the current `enqueued_ts_ns` semantics from *poll-drain time* to *event-emission time*. The field name on the public ABI stays; only the sampling site moves. This eliminates the ±poll-interval skew (up to tens of µs at 10–100 kHz poll rates) on every event's apparent time. Matters for reconstructing per-order timelines at µs resolution.
- **Event-queue overflow protection** — current `EventQueue` is an unbounded `VecDeque` drained per poll. A slow or stopped poller accumulates events silently with no visibility and no upper bound on memory. A5.5 adds a configurable soft cap, drop-oldest policy on overflow, and two counters (`events_dropped`, `events_queue_high_water`). Preserves the "don't drop silently" property per `feedback_performance_first_flow_control.md`.
- **Per-connection stats getter** — expose send-path state (`snd_una`, `snd_nxt`, `snd_wnd`, `send_buf_bytes_pending`, `send_buf_bytes_free`) **plus RTT estimator state** (`srtt_us`, `rttvar_us`, `min_rtt_us`, `rto_us`) via a new slow-path extern "C" function. All fields already exist internally on `TcpConn` post-A5 (send-path since A3; RTT fields land in A5's `rtt_est` + `rack.min_rtt`); A5.5 just gives the application a read path. Enables per-order forensics tagging: "bytes in flight + current RTT + current RTO at send time." Closes two parallel gaps flagged in the A5 event-log review (send-state unreachable; RTT estimator unreachable even though counters advertise `rtt_samples` are being absorbed).

Out of scope:

- Any change to wire behavior, retransmit semantics, or congestion response. A5.5 is strictly an observability phase.
- Event-queue-overflow **events** (i.e., emitting an event when the queue is about to drop) — the counter + high-water pair is sufficient per `feedback_observability_primitives_only.md`. The app polls counters; no new event kind.
- A public timer API or WRITABLE event — those remain A6 scope.
- Changes to `rx_hw_ts_ns` semantics or plumbing — A-HW owns the hardware-timestamp path.
- Batched / ring-buffer event log with persistent storage. The app owns persistence; A5.5 just keeps the in-engine FIFO honest.

---

## 2. Module layout

### 2.1 Modified modules (`crates/resd-net-core/src/`)

| Module | Change |
|---|---|
| `tcp_events.rs` | Add `emitted_ts_ns: u64` to every `InternalEvent` variant. Add `EventQueue::soft_cap: usize` (configurable via engine config; default 4096). On `push`, if `q.len() >= soft_cap` drop `q.pop_front()` and `counters.events_dropped += 1` before the new push. Track `high_water: usize` as max observed queue depth, increment `counters.events_queue_high_water` transitions monotonically (latched). Producers at call sites pass `clock::now_ns()` sampled at push (not drain). |
| `engine.rs` | Every `self.events.borrow_mut().push(InternalEvent::…)` call site updates its `InternalEvent` constructor to include `emitted_ts_ns: self.clock.now_ns()`. Five existing call sites per earlier grep: `engine.rs:658` (Closed), `:908` (Connected), `:935` (Closed), `:985` (StateChange), `:1238` (Readable), plus any `Error` call sites. A5's new retransmit / loss-detected / ETIMEDOUT call sites land with `emitted_ts_ns` already wired (A5 plan adjusts before A5 closes, or A5.5 touches them if A5 has already shipped). |
| `counters.rs` | Add `events_dropped: AtomicU64` (slow-path) and `events_queue_high_water: AtomicU64` (slow-path; latched max). Both in the engine-group or a new `obs` group per §9.1 convention. |
| `tcp_conn.rs` | Expose a new getter method `stats(&self) → ConnStats` returning a POD struct with 9 `u32` fields: send-path (`snd_una`, `snd_nxt`, `snd_wnd`, `send_buf_bytes_pending`, `send_buf_bytes_free`) + RTT/RTO (`srtt_us`, `rttvar_us`, `min_rtt_us`, `rto_us`). Pure projection over existing internal state: send-path fields present since A3, RTT/RTO fields added by A5 on `rtt_est` and `rack`. |
| `flow_table.rs` | Add `get_stats(handle) → Option<ConnStats>` that wraps `get(handle).map(|c| c.stats())`. |

### 2.2 Modified modules (`crates/resd-net/src/`)

| Module | Change |
|---|---|
| `lib.rs` | At the `resd_net_poll` drain site (lib.rs:142–224): remove the `let ts = resd_net_core::clock::now_ns();` sample; read `emitted_ts_ns` from the `InternalEvent` variant into the `resd_net_event_t.enqueued_ts_ns` field. Field name stays; semantics tighten from "drain time" to "emission time." |
| `api.rs` | Document the semantics change on `resd_net_event_t::enqueued_ts_ns` (comment + doc-comment for cbindgen). Add new extern "C" function `resd_net_conn_stats(engine, conn, out_ptr) → i32` returning 0 on success, `-ENOENT` on unknown handle. Define `resd_net_conn_stats_t` POD struct in api.rs so cbindgen emits it into the header. |
| `include/resd_net.h` (cbindgen-regenerated) | `resd_net_event_t::enqueued_ts_ns` doc comment updates. New `resd_net_conn_stats_t` struct (9 `uint32_t` fields). New `resd_net_conn_stats` function. New counter fields `events_dropped` + `events_queue_high_water`. New engine config field `event_queue_soft_cap` (u32, default 4096). |

### 2.3 Dependencies introduced

None. No new crate deps, no new DPDK offload bits, no wire-format changes.

---

## 3. Data flow

### 3.1 Emission-time timestamp (the core fix)

**Before (current A4 behavior):**

```
engine ACK handler fires
  → events.push(InternalEvent::Readable { conn, byte_offset, byte_len, rx_hw_ts_ns })
  ... work continues, engine yields control back to poll loop ...
  ... some microseconds pass ...
  ... eventually app calls resd_net_poll ...
  → drain_events {
      let ts = clock::now_ns();           // ← sampled HERE, at drain time
      event_t.enqueued_ts_ns = ts;
    }
```

Result: every event's `enqueued_ts_ns` reports the time of the *poll call*, not the time of the *stack event*. Skew = (poll_call_ts − event_push_ts), bounded by the app's poll interval. At 100 kHz polling that's up to 10 µs of error; at 10 kHz polling up to 100 µs.

**After (A5.5):**

```
engine ACK handler fires
  → let now = clock::now_ns();            // ← sampled HERE, at push
  → events.push(InternalEvent::Readable {
        conn, byte_offset, byte_len, rx_hw_ts_ns,
        emitted_ts_ns: now,
    })
  ... later ...
  → drain_events {
      event_t.enqueued_ts_ns = ev.emitted_ts_ns();   // just copied through
    }
```

Skew collapses to clock-sample call cost (tens of ns on TSC). The field name on the public ABI stays `enqueued_ts_ns` (we don't want to invalidate existing C++ consumer code) — the semantic meaning tightens from "drain time" to "emission time" and the header comment is updated.

**Rationale for not adding a new field:** the current semantics are buggy, not a stable contract anyone depends on. No downstream user exists yet (pre-Stage-1-ship). Renaming to `emitted_ts_ns` at the ABI level is tempting but ADs proliferate; tighter to fix the sampling site and update the comment. If a consumer genuinely wants drain-time (unlikely — use case is unclear), they can sample `clock::now_ns()` themselves at poll return.

### 3.2 Queue overflow protection

**Push path:**

```rust
fn push(&mut self, ev: InternalEvent, counters: &EngineCounters) {
    if self.q.len() >= self.soft_cap {
        // drop-oldest policy: preserves most-recent events (better forensics on
        // the immediate-past episode) at cost of losing older ones
        let _dropped = self.q.pop_front();
        counters.events_dropped.fetch_add(1, Relaxed);
    }
    self.q.push_back(ev);
    let depth = self.q.len() as u64;
    // latched max — only updates if strictly greater
    counters.events_queue_high_water.fetch_max(depth, Relaxed);
}
```

**Why drop-oldest, not drop-newest:**
- For a slow poller that recovers, the most recent events are more useful (describe the current state).
- For a permanently-stopped poller, the distinction doesn't matter — counter goes nonzero and app is presumably already dead.
- Matches Linux kernel's `dmesg` ring buffer behavior (familiar mental model).

**Soft-cap default rationale:** 4096 events × ~32 bytes per event = ~128 KiB per engine — negligible memory, but covers ~40 ms of events at 100k events/s (way above expected rate). Tunable via `event_queue_soft_cap` on engine config if an app has a specific burst profile. Hard floor of 64 enforced to prevent pathological configs from producing a queue smaller than one poll's worth.

**Monotonic high-water caveat:** `events_queue_high_water` latches and does not decrement. Combined with `events_dropped`, the pair tells a clean story: "high_water tells you the worst backlog ever; dropped tells you whether any were lost." If a consumer wants a live depth gauge, add `events_pending` in a follow-on — not in A5.5 scope since it adds atomic-read cost per push for a secondary signal.

### 3.3 Connection-stats getter

```rust
// crates/resd-net-core/src/tcp_conn.rs
#[repr(C)]
pub struct ConnStats {
    // Send-path (present since A3)
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub send_buf_bytes_pending: u32,   // bytes accepted but not TX'd (snd.pending.len())
    pub send_buf_bytes_free: u32,      // send_buffer_bytes − pending

    // RTT/RTO estimator (present after A5 lands `rtt_est` + `rack.min_rtt`)
    pub srtt_us: u32,                  // RFC 6298 smoothed RTT; 0 until first sample
    pub rttvar_us: u32,                // RFC 6298 RTT variance; 0 until first sample
    pub min_rtt_us: u32,               // min RTT across all samples; 0 until first
    pub rto_us: u32,                   // current RTO (post-backoff if RTO fired); `tcp_initial_rto_us` before first sample
}

impl TcpConn {
    pub fn stats(&self) -> ConnStats {
        let pending = self.snd.pending.len() as u32;
        ConnStats {
            snd_una: self.snd.una,
            snd_nxt: self.snd.nxt,
            snd_wnd: self.snd.wnd,
            send_buf_bytes_pending: pending,
            send_buf_bytes_free: self.send_buffer_bytes.saturating_sub(pending),
            srtt_us: self.rtt_est.srtt_us(),   // 0 when no samples yet
            rttvar_us: self.rtt_est.rttvar_us(),
            min_rtt_us: self.rack.min_rtt_us(),
            rto_us: self.rtt_est.rto_us(),     // returns initial_rto before first sample
        }
    }
}
```

**Public ABI:**

```c
typedef struct resd_net_conn_stats {
    // Send-path state.
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;
    uint32_t send_buf_bytes_pending;
    uint32_t send_buf_bytes_free;

    // RTT estimator state. All values in microseconds. Fields report
    // 0 until the first RTT sample has been absorbed (check srtt_us > 0
    // for trustworthiness). rto_us reports the engine's tcp_initial_rto_us
    // before the first sample; thereafter, the Jacobson/Karels result
    // (post-backoff if an RTO has fired and rto_no_backoff is not set).
    uint32_t srtt_us;
    uint32_t rttvar_us;
    uint32_t min_rtt_us;
    uint32_t rto_us;
} resd_net_conn_stats_t;

// Returns 0 on success, -ENOENT if conn handle is not live.
// Slow path — safe to call per-order for forensics tagging; do not call in
// a hot loop (per-call cost is a flow-table lookup + nine u32 loads).
int resd_net_conn_stats(
    resd_net_engine* engine,
    uint64_t conn,
    resd_net_conn_stats_t* out
);
```

**Forensics use pattern:**

```c
// App pattern: tag each outbound order with a pre-send stats snapshot.
resd_net_conn_stats_t pre;
resd_net_conn_stats(engine, conn, &pre);
uint64_t tx_ts = clock_now_ns();
int n = resd_net_send(engine, conn, order_bytes, order_len);
// ... on ACK or fill, log:
//   order_id, tx_ts,
//   pre.snd_nxt, pre.snd_wnd, pre.send_buf_bytes_pending,   // send-path state
//   pre.srtt_us, pre.rttvar_us, pre.min_rtt_us, pre.rto_us  // path-health state
```

Diffs between consecutive snapshots answer:
- Send-path: "was my order actually going out fast, or sitting in `snd.pending` waiting on peer's rwnd?"
- RTT: "was the path steady at the time of my order, or was `srtt_us` rising / `rttvar_us` spiking?"
- Baseline-normal vs degraded: compare `srtt_us` to `min_rtt_us` — ratio near 1 means healthy, rising ratio means congestion building.
- RTO headroom: `rto_us` tells you how long the stack will wait before retransmitting if this order's segment is lost; useful to set application-level order-lifetime timers consistently with the stack's timing.

---

## 4. Counter surface (§9.1.1, all slow-path)

| Counter (group.name) | Semantics |
|---|---|
| `obs.events_dropped` | Incremented once per event dropped from the queue due to soft-cap overflow. **Nonzero = app poll cadence cannot keep up + some events were lost.** |
| `obs.events_queue_high_water` | Latched max of observed queue depth since engine start. **High value with `events_dropped == 0` = close call; high value with nonzero `events_dropped` = actual loss.** |

Both `AtomicU64`. Increment sites: `EventQueue::push` only — never on the drain path, never on any TCP or L3 path. Slow-path by strict definition (fires only when queue pressure exists).

**Group naming**: A new `obs` group is introduced (short for "observability") for engine-internal observability signals. Alternative would be to fold into the existing `poll` or `eth` group, but neither fits semantically — these are event-queue-specific. Group additions in `counters.rs` follow the same pattern as `poll`/`eth`/`ip`/`tcp`. Fields are also zero-init and match the cbindgen header layout.

---

## 5. Config / API surface changes

### 5.1 `resd_net_engine_config_t` (additions)

| Field | Type | Default | Notes |
|---|---|---|---|
| `event_queue_soft_cap` | `u32` | 4096 | Max queue depth before drop-oldest. Must be ≥ 64; configs with smaller values are rejected at `engine_create` with `-EINVAL`. |

### 5.2 `resd_net_event_t` (semantic change, no layout change)

- `enqueued_ts_ns` doc comment updates from:
  > "ns timestamp when this event was drained into the caller's array"

  to:
  > "ns timestamp (engine monotonic clock) sampled at event emission inside the stack. Unrelated to `rx_hw_ts_ns`. For packet-triggered events, emission time is when the stack processed the triggering packet, not when the NIC received it — use `rx_hw_ts_ns` for NIC-arrival time. For timer-triggered events (RTO fire, A5 loss-detected), emission time is the fire instant."

### 5.3 New extern "C" function

```c
int resd_net_conn_stats(
    resd_net_engine* engine,
    uint64_t conn,
    resd_net_conn_stats_t* out
);
```

Returns:
- `0` on success, `out` populated.
- `-EINVAL` if engine or out is null.
- `-ENOENT` if conn is not a live handle in the flow table.

Thread-safety: same as every other API in this stack — per §3 single-lcore engine model, no cross-thread calls, no locks needed. Calling from a different thread than the engine's poll thread is undefined behavior (same as all other APIs).

### 5.4 Public counter surface

- `resd_net_counters_t` gains `obs_events_dropped` and `obs_events_queue_high_water` fields (u64 each). Layout-wise, appended to the end of the struct. cbindgen regenerates; header-drift check enforces consistency.

---

## 6. Accepted divergences

None. A5.5 does not change wire behavior; no RFC clauses are touched. mTCP comparison produces no new ADs — mTCP does not maintain a public event-queue overflow counter or a send-state getter. Their absence there is just a scope difference, not a behavioral divergence to accept.

- `AD-A5-5-enqueued-ts-semantics`: the `enqueued_ts_ns` field semantics changes from drain-time to emission-time *without* a field rename. Strictly this is a pre-ship-tag ABI refinement, not a divergence from an RFC or mTCP. No AD entry needed. Noted in §13 parent-spec updates as a §9.3 events-table correction.

---

## 7. Test plan (Layer A + Layer B)

### 7.1 Unit tests (Layer A)

- `tcp_events.rs`:
  - `emitted_ts_ns` is recorded at push time, not read time (mock clock: push at t=100, pop at t=200, assert `emitted_ts_ns == 100`).
  - Queue overflow drops oldest: fill beyond soft_cap, pop all, assert first-popped is the element at index `excess_count`, not index 0.
  - `events_dropped` increments exactly by `push_count − soft_cap` when push_count > soft_cap.
  - `events_queue_high_water` reaches `soft_cap` (not `soft_cap + 1`) as max.
  - `soft_cap < 64` rejected by `EventQueue::with_cap`.
- `tcp_conn.rs`:
  - `stats()` returns current `snd.una`, `snd.nxt`, `snd.wnd` unchanged from the fields they project.
  - `send_buf_bytes_free` saturates at 0 when `pending.len() > send_buffer_bytes` (shouldn't happen in practice but arithmetic must not underflow).
  - Before any RTT sample: `stats().srtt_us == 0`, `rttvar_us == 0`, `min_rtt_us == 0`, and `rto_us == tcp_initial_rto_us` (engine config default, not 0).
  - After N RTT samples: `srtt_us` and `rttvar_us` follow the Jacobson/Karels arithmetic asserted in `tcp_rtt.rs` unit tests (same `α=1/8, β=1/4` numbers); `min_rtt_us` equals the minimum of the N samples; `rto_us = max(srtt + 4·rttvar, tcp_min_rto_us)`.
  - After an RTO fire with default `rto_no_backoff=false`: `rto_us` reports the backed-off value (`min(rto × 2, tcp_max_rto_us)`), not the pre-backoff computed value.

### 7.2 Integration (Layer B, TAP pair)

1. **Emission-time timestamp correctness** — on a TAP pair, inject a known-latency delay between event emission and app poll; assert the `enqueued_ts_ns` delta between two consecutive events matches the real inter-event stack delta (within TSC resolution), not the poll interval.
2. **Queue overflow forensics** — configure `event_queue_soft_cap = 64`; drive enough traffic to queue > 128 events without polling; then poll and assert `events_dropped ≥ 64`, `events_queue_high_water ≥ 64`, and the drained events are the most-recent 64 (by `emitted_ts_ns` comparison).
3. **Stats getter during backpressure** — send more than `send_buffer_bytes` while peer's rwnd is small; observe `stats()` reports nonzero `send_buf_bytes_pending` and small `snd_wnd`; close; observe reset state on a fresh connection.
4. **Stats getter on unknown handle** — `resd_net_conn_stats(engine, 0xdead_beef, &out)` returns `-ENOENT`, `out` unchanged.
5. **RTT fields before first sample** — on a freshly-connected socket, before any RTT sample lands, `stats()` returns `srtt_us == 0`, `rttvar_us == 0`, `min_rtt_us == 0`, `rto_us == tcp_initial_rto_us`. App code can check `srtt_us > 0` to gate on "RTT trusted."
6. **RTT fields track the stack** — drive enough ACKs through a TAP pair to establish an SRTT; call `stats()` and assert `srtt_us` + `rttvar_us` + `min_rtt_us` + `rto_us` match the values held in the engine's `RttEstimator` + `RackState` at the same instant (values projected, not recomputed). Follow-up: induce an RTO fire with default `rto_no_backoff=false`; assert `rto_us` reflects the post-backoff value.

### 7.3 Existing test updates

- A3/A4 TAP tests that implicitly depend on `enqueued_ts_ns` (if any — grep shows no current dependence) need no change.
- A5 TAP tests (if they land before A5.5) — the `emitted_ts_ns` timestamp semantic change propagates cleanly since A5 call sites are added fresh.

### 7.4 A8 counter-coverage entries

- `obs.events_dropped` — scenario: overflow test from 7.2.2.
- `obs.events_queue_high_water` — same scenario.

---

## 8. Review gates

Per `feedback_phase_mtcp_review.md` + `feedback_phase_rfc_review.md`:

- `docs/superpowers/reviews/phase-a5-5-mtcp-compare.md` — `mtcp-comparison-reviewer` subagent. Lightweight review: mTCP has no analog for event-queue overflow accounting or a send-state getter (their `tcp_api_get_conn_state` is different shape). Expected output: no ADs; brief confirmation that the gaps are scope-difference not behavioral.
- `docs/superpowers/reviews/phase-a5-5-rfc-compliance.md` — `rfc-compliance-reviewer` subagent. Lightweight: no wire behavior changes, no RFC clauses touched. Reviewer confirms that the emission-time timestamp semantic does not itself violate any RFC (it's an observability clarification on the application-facing API).

Per `feedback_per_task_review_discipline.md`, each implementation task gets spec-compliance + code-quality reviewer subagents before moving on (opus).

---

## 9. Rough task scale

~6–8 tasks:

1. `InternalEvent::emitted_ts_ns` field + producer wiring (5 existing call sites in engine.rs). (1)
2. `resd_net_poll` drain-time simplification: read `emitted_ts_ns` through, drop the sample at drain. Header-comment update. (1)
3. `EventQueue` soft_cap + drop-oldest + counter wiring. Unit tests for overflow + high-water. (1)
4. `counters.rs` `obs` group + `events_dropped` + `events_queue_high_water` fields + cbindgen header regen. (1)
5. `resd_net_engine_config_t::event_queue_soft_cap` field + validation (rejects `< 64`). (1)
6. `TcpConn::stats` method + `ConnStats` struct (9 fields: 5 send-path + 4 RTT/RTO) + `flow_table::get_stats`. Includes small `rtt_est.srtt_us()` / `rttvar_us()` / `rto_us()` and `rack.min_rtt_us()` accessor helpers if A5 hasn't already exposed them at the module boundary. (1)
7. `resd_net_conn_stats` extern "C" + `resd_net_conn_stats_t` header struct. Integration tests 7.2.3 through 7.2.6 (stats under backpressure + `-ENOENT` + pre-sample values + RTT tracking). (1)
8. Integration tests 7.2.1 + 7.2.2 (emission-time + overflow). mTCP + RFC review reports. (1)

Each task is surgical, touches one concern, carries its own tests.

---

## 10. Updates to parent spec `2026-04-17-dpdk-tcp-design.md`

Small edits in the same commit as this phase design doc:

- §9.3 events: clarify that `enqueued_ts_ns` is emission-time, not drain-time. One sentence.
- §9.1 counter examples: add `obs.events_dropped` and `obs.events_queue_high_water` to the example list. Note the `obs` group alongside `poll`/`eth`/`ip`/`tcp`.
- §4 API: brief mention of `resd_net_conn_stats` under the introspection paragraph (if one exists; otherwise add a one-paragraph "Introspection API" subsection). Note that it covers both send-path state and RTT estimator state in a single call.
- §4.2 contracts: document the `event_queue_soft_cap` / drop-oldest / counter triplet.

---

## 11. Performance notes

- **Event push hot path**: gains one `clock::now_ns()` call (TSC read, ~10–30 ns) + one `atomic::fetch_max` (for high-water) + one conditional `pop_front + fetch_add` only when the queue is at cap (rare). Net effect on the stack-internal "emit an event" micro-path: well under 100 ns per event on a TSC-calibrated clock. For context, events fire on per-segment, per-state-change, or per-connection boundaries — not per-byte — so this is dominated by segment-rate, not packet-rate.
- **Drain-path simplification**: removes one `clock::now_ns()` call per drained event (replaced by a field read from the variant). Small net positive for high-event-count polls.
- **Send-state getter**: flow-table lookup + 5 `u32` loads. Not on any hot path — called by the app on demand, typically once per order or once per forensic checkpoint.
- **Memory**: soft_cap=4096 × ~32 B/event = ~128 KiB per engine worst case. Trivial on a server-class node.
- **No new atomics on the packet hot path**: the two new counters live exclusively on the event-emission boundary, not on RX/TX segment handlers.

---

## 12. Open items for the plan-writing pass

- **Timing of A5.5 vs A5 ship**: A5.5 depends on the five A5 event call sites existing (retransmit, loss-detected, ETIMEDOUT). If A5.5 runs before A5 ships, it must coordinate with A5's in-flight work; if after, it cleanly rebases. Default plan order: A5 ships first, A5.5 follows. Can run in parallel with A-HW since no shared files.
- **Group naming** (`obs` vs folding into `poll`): plan-writing decides and documents. Current recommendation: new `obs` group — clean separation from packet-path counters and room to grow (future `obs.` entries like `poll_idle_ratio` fit naturally).
- **`events_pending` live-depth gauge**: intentionally deferred. If A8 observability audit finds apps want it, add in a follow-up. Not in A5.5 to keep the counter-addition discipline tight (`feedback_counter_policy.md`).
- **Field ordering in `resd_net_counters_t`**: new fields appended at end; header-drift check catches any mistaken reorder. No renumbering of existing fields.
