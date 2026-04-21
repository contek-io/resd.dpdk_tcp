# Phase A5.5 — Event-log forensics + in-flight introspection + TLP tuning (Design Spec)

**Status:** plan-ready (brainstorm closed 2026-04-19).
**Parent spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` — A5.5.
**Branch:** `phase-a5.5` (off `phase-a5-complete` tag `39b01cd`).
**Ships:** `phase-a5-5-complete` tag gated on mTCP + RFC review reports. Scope includes modest wire-behavior changes (TLP tuning knobs + three closures of Stage-2 ADs) — see §1 Scope note.

---

## 1. Scope

A5.5 closes four gaps identified during A5 design review — three forensics/observability and one TLP tuning pack for order-entry sockets — plus closes three Stage-2 Accepted Deviations (**AD-15 retirement**, **AD-17** `RACK_mark_losses_on_RTO`, **AD-18** arm-TLP-on-send) and seeds SRTT from the SYN handshake round-trip so AD-18's pre-first-data-ACK window has valid RTT state.

All items are driven by the order-entry post-mortem + fail-fast use case: "the trader saw a stall at T; tell me exactly what the stack was doing at T ± a few µs — and when the stack detects a tail loss, don't wait a full RTT-and-a-half to probe."

**Scope note**: A5.5 was originally framed as observability-only; the 2026-04-19 brainstorm widened the wire-behavior surface to include (a) the five TLP tuning knobs (per-connect opt-in; defaults preserve RFC 8985 exactly), (b) AD-17's `RACK_mark_losses_on_RTO` pass (a missing RFC 8985 SHOULD, affects every connection on RTO fire), (c) AD-18's arm-TLP-on-send (the RFC 8985 §7.2 SHOULD, affects every connection's new-data TX path), and (d) SRTT seeding from the SYN round-trip (RFC 6298 §3.3 MAY, affects every connection's ESTABLISHED transition). Items (b)-(d) are net-conservative improvements under their cited RFC clauses. The §6.3/§6.4 RFC matrix picks up new rows accordingly.

In scope:

- **Event emission-time stamping** — fix the current `enqueued_ts_ns` semantics from *poll-drain time* to *event-emission time*. The field name on the public ABI stays; only the sampling site moves. This eliminates the ±poll-interval skew (up to tens of µs at 10–100 kHz poll rates) on every event's apparent time. Matters for reconstructing per-order timelines at µs resolution.
- **Event-queue overflow protection** — current `EventQueue` is an unbounded `VecDeque` drained per poll. A slow or stopped poller accumulates events silently with no visibility and no upper bound on memory. A5.5 adds a configurable soft cap, drop-oldest policy on overflow, and two counters (`events_dropped`, `events_queue_high_water`). Preserves the "don't drop silently" property per `feedback_performance_first_flow_control.md`.
- **Per-connection stats getter** — expose send-path state (`snd_una`, `snd_nxt`, `snd_wnd`, `send_buf_bytes_pending`, `send_buf_bytes_free`) **plus RTT estimator state** (`srtt_us`, `rttvar_us`, `min_rtt_us`, `rto_us`) via a new slow-path extern "C" function. All fields already exist internally on `TcpConn` post-A5 (send-path since A3; RTT fields land in A5's `rtt_est` + `rack.min_rtt`); A5.5 just gives the application a read path. Enables per-order forensics tagging: "bytes in flight + current RTT + current RTO at send time." Closes two parallel gaps flagged in the A5 event-log review (send-state unreachable; RTT estimator unreachable even though counters advertise `rtt_samples` are being absorbed).
- **TLP tuning knobs for order-entry** (WB, per-connect opt-in; defaults preserve A5's RFC 8985 behavior): a pack of five configurable fields plus one new counter so the application can dial TLP more aggressively on order-entry sockets than defaults allow. Motivated by trading latency budgets where a half-RTT+ TLP schedule delay is a large fraction of the total order lifetime. The five knobs:
  1. **Configurable PTO floor** (down to 0 — no floor) — today inherits `tcp_min_rto_us` (5ms default after A5). Per-connect override to 0 or any value ≥0.
  2. **Configurable SRTT multiplier** in the PTO formula — today hard-coded 2.0×. Per-connect override in the range [1.0×, 2.0×], expressed as an integer `×100` field (so 200=2.0×, 150=1.5×, 100=1.0×) to keep config cbindgen-clean with no float in the C ABI.
  3. **Skip the FlightSize-1 `+max_ack_delay` penalty** — today RFC 8985 §7.2 adds `max(WCDelAckT, RTT/4)` to PTO when only one segment is in flight. Per-connect opt-out treats FlightSize as ≥2 for PTO purposes. Companion mechanism (actually emitting a keepalive-shaped companion segment so FlightSize is honestly ≥2 on the wire) noted as a deferred follow-on in §12 — the flag alone is sufficient for the timing goal in most cases and avoids a new TX path in A5.5.
  4. **Multiple consecutive TLP probes before falling back to RTO** — today A5 fires exactly one TLP then arms RTO. Per-connect override (`tlp_max_consecutive_probes`, default 1, range 1–5) lets the stack fire N consecutive probes each at PTO cadence before giving up to RTO-driven retransmit.
  5. **Skip the "no new RTT sample since last TLP" suppression gate** — RFC 8985 §7.4 prevents back-to-back TLPs without an intervening RTT sample (to avoid runaway spurious probing). Per-connect opt-out disables this gate for cases where the application wants maximum probe density.

  Plus one observability addition: new counter `tcp.tx_tlp_spurious` incremented when a prior TLP probe is confirmed spurious via DSACK (peer reports it already had the data). Paired with existing `tcp.tx_tlp` (probes fired), the app computes `spurious_ratio = tx_tlp_spurious / tx_tlp`. If this rises above a few percent the app's jitter budget is under-provisioned relative to real path jitter — application raises the PTO floor back up via the per-connect knob. Self-tuning recipe documented in A12's `13-order-entry-telemetry.md`.

Plus three items added by the 2026-04-19 brainstorm:

- **SRTT seeded from SYN handshake round-trip** — in `handle_syn_sent` after a valid SYN-ACK lands, compute `rtt_us = now_us - syn_tx_ts_us` and call `conn.rtt_est.sample(rtt_us)` + `conn.rack.update_min_rtt(rtt_us)`. Karn's rule: only the first SYN's ACK counts — skip if `syn_retransmit_count > 0`. RFC 6298 §3.3 allows ("The RTT of the SYN segment MAY be used as the first SRTT"). Closes AD-18's pre-first-data-ACK window; from ESTABLISHED onward, `srtt_us > 0` is invariant. Makes `dpdk_net_conn_stats` return nonzero RTT fields immediately post-handshake, and makes AD-18's arm-TLP-on-send always have a valid PTO basis.

- **AD-17 close — `RACK_mark_losses_on_RTO` pass in `on_rto_fire`** — Stage-2 AD-17 from the A5 RFC review. At the top of `on_rto_fire` (before the existing `self.retransmit(handle, 0)`), walk `snd_retrans.entries` and set `lost=true` on every unacked, unsacked entry where `entry.seq == snd.una` OR `entry.xmit_ts_ns/1_000 + rack.rtt_us + rack.reo_wnd_us <= now_us` per RFC 8985 §6.3. Route the lost-index list through the existing retransmit loop at `engine.rs:1467-1491` (already consumes `outcome.rack_lost_indexes`). Fixes A5's one-segment-per-RTO pacing on tail-loss recovery — a single RTO fire now retransmits the entire RACK-lost tail in one burst.

- **AD-18 close — TLP armed on every new-data send** — Stage-2 AD-18 from the A5 RFC review. In `dpdk_net_send`'s TX path, after successfully enqueuing new data into `snd_retrans`, call a new `arm_tlp_pto(conn)` helper when (a) `snd_retrans` has at least one entry, (b) no TLP is currently armed (`conn.tlp_timer_id.is_none()`), (c) `rtt_est.srtt_us().is_some()` (post-SYN-seed this is always true outside SYN_SENT), (d) `tlp_consecutive_probes_fired < tlp_max_consecutive_probes`. Closes the RFC 8985 §7.2 SHOULD ("the sender SHOULD start or restart a loss probe PTO timer after transmitting new data") and covers the pre-first-ACK first-burst window.

Plus one parent-spec bookkeeping item:

- **AD-15 retirement** — Stage-2 AD-15 (TLP pre-fire state `TLP.end_seq` + `TLP.is_retrans`) is superseded by A5.5's multi-probe data structures: the `tlp_recent_probes` ring (5 × `(seq, len, tx_ts_ns)`) replaces single-slot `tlp_end_seq`; the `tlp_consecutive_probes_fired < tlp_max_consecutive_probes` gate replaces the single-in-flight invariant. One-line update to `docs/superpowers/reviews/phase-a5-rfc-compliance.md` retires AD-15 from the Stage-2 AD list (the A5 RFC review is where AD-15/17/18 are defined by number).

Out of scope:

- Wire behavior beyond the TLP tuning knobs, AD-17 `RACK_mark_losses_on_RTO`, AD-18 arm-TLP-on-send, and SRTT-seed-from-SYN listed above. Congestion control, reassembly, and other paths stay as A5 ships them.
- **AD-16 (RACK Step 2 spurious-retrans guard)** — stays deferred to Stage 2. Minimal fix (2 LOC with `xmit_count==1` gate) is tangential to A5.5's forensics + TLP tuning focus; full TSecr / min_rtt-age guards require threading TSecr through the rack-update path (~40 LOC). Revisit when DSACK adaptive work (AD-13) lands.
- Event-queue-overflow **events** (i.e., emitting an event when the queue is about to drop) — the counter + high-water pair is sufficient per `feedback_observability_primitives_only.md`. The app polls counters; no new event kind.
- A public timer API or WRITABLE event — those remain A6 scope.
- Changes to `rx_hw_ts_ns` semantics or plumbing — A-HW owns the hardware-timestamp path.
- Batched / ring-buffer event log with persistent storage. The app owns persistence; A5.5 just keeps the in-engine FIFO honest.

---

## 2. Module layout

### 2.1 Modified modules (`crates/dpdk-net-core/src/`)

| Module | Change |
|---|---|
| `tcp_events.rs` | Add `emitted_ts_ns: u64` to every `InternalEvent` variant. Add `EventQueue::soft_cap: usize` (configurable via engine config; default 4096). On `push`, if `q.len() >= soft_cap` drop `q.pop_front()` and `counters.events_dropped += 1` before the new push. Track `high_water: usize` as max observed queue depth, increment `counters.events_queue_high_water` transitions monotonically (latched). Producers at call sites pass `clock::now_ns()` sampled at push (not drain). |
| `engine.rs` | Every `events.push(InternalEvent::…)` / `self.events.borrow_mut().push(…)` call site updates its `InternalEvent` constructor to include `emitted_ts_ns: self.clock.now_ns()`. Post-A5 count is **13 call sites** (revised from scaffold's stale 5): `:856` (TcpRetrans), `:861` (TcpLossDetected), `:994` (TcpRetrans from on_rto_fire), `:999` (TcpLossDetected from on_rto_fire), `:1169` (Error), `:1173` (Closed), `:1204` (Closed clean), `:1480` (TcpRetrans from engine-loop rack-lost retransmit), `:1485` (TcpLossDetected from engine-loop), `:1690` (Connected), `:1709` (Closed from error path), `:1788` (StateChange), `:2041` (Readable). Plan task 1 walks all 13 via grep verification to ensure no site is missed if A-HW or other in-flight work adds more before A5.5 lands. |
| `counters.rs` | Add `events_dropped: AtomicU64` (slow-path) and `events_queue_high_water: AtomicU64` (slow-path; latched max). Both in the engine-group or a new `obs` group per §9.1 convention. |
| `tcp_conn.rs` | Expose a new getter method `stats(&self) → ConnStats` returning a POD struct with 9 `u32` fields: send-path (`snd_una`, `snd_nxt`, `snd_wnd`, `send_buf_bytes_pending`, `send_buf_bytes_free`) + RTT/RTO (`srtt_us`, `rttvar_us`, `min_rtt_us`, `rto_us`). Pure projection over existing internal state: send-path fields present since A3, RTT/RTO fields added by A5 on `rtt_est` and `rack`. Also add per-conn TLP tuning fields (all mirrored from `dpdk_net_connect_opts_t`): `tlp_pto_min_floor_us: u32`, `tlp_pto_srtt_multiplier_x100: u16`, `tlp_skip_flight_size_gate: bool`, `tlp_max_consecutive_probes: u8`, `tlp_skip_rtt_sample_gate: bool`, plus runtime state `tlp_consecutive_probes_fired: u8` (reset on every new RTT sample / new data ACK). |
| `flow_table.rs` | Add `get_stats(handle) → Option<ConnStats>` that wraps `get(handle).map(|c| c.stats())`. |
| `tcp_tlp.rs` | Extend `pto_us` signature from `pto_us(srtt_us, min_rto_us) → u32` to `pto_us(srtt_us, &TlpConfig) → u32` where `TlpConfig` carries the floor, multiplier, and FlightSize-gate flags. Keep `select_probe` unchanged. Add a `TlpConfig` POD that `tcp_conn.rs` projects from the per-conn fields. Existing A5 unit tests keep passing when `TlpConfig::default()` matches the prior constants (`floor=tcp_min_rto_us`, `multiplier_x100=200`, `skip_flight_size_gate=false`). |
| `engine.rs` | TLP scheduling (§3.2 of A5 spec) consults `conn.tlp_consecutive_probes_fired`; if >= `conn.tlp_max_consecutive_probes`, skip TLP scheduling and let RTO own the recovery (same as A5's current one-probe behavior with the default value of 1). TLP fire handler increments `tlp_consecutive_probes_fired`. RTT sample absorption path (tcp_input.rs integration) resets `tlp_consecutive_probes_fired = 0` on every `rtt_est.sample()` call **and** clears it when new data is cumulatively ACKed (whichever ordering the A5 ACK path uses). RTT-sample-gate check consults `conn.tlp_skip_rtt_sample_gate` and suppresses only when the flag is false. DSACK detection in `tcp_input.rs` attributes DSACK'd ranges to prior TLP probes (tracked via a small fixed-size array on `TcpConn` of `(seq, len, tx_ts_ns)` for the last N probes, N = `tlp_max_consecutive_probes`'s max value = 5): if the DSACK range intersects a tracked probe's seq range, `tcp.tx_tlp_spurious++` once. |
| `counters.rs` | Add `tx_tlp_spurious: AtomicU64` in the `tcp` group, slow-path. Sits alongside the existing `tx_tlp`. Doc-comment notes the pairing for `spurious_ratio` computation. |
| `tcp_input.rs` (SRTT seed from SYN — §3.5) | In `handle_syn_sent` on the valid-SYN-ACK accept branch, after the existing option-negotiation block and before dispatching to engine, compute `rtt_us = now_us - (syn_tx_ts_ns / 1_000) as u32`, bounds-check to `[1, 60_000_000)`, and call `conn.rtt_est.sample(rtt_us)` + `conn.rack.update_min_rtt(rtt_us)`. Guard: skip if `conn.syn_retransmit_count > 0` (Karn's rule — only the first SYN's ACK counts). Adds one field `syn_tx_ts_ns: u64` to `TcpConn` to preserve the SYN-send timestamp across the ACK round-trip. |
| `engine.rs` (AD-17 — §3.6) | `on_rto_fire` Phase 3: add a new §6.3 `RACK_mark_losses_on_RTO` pass **before** `self.retransmit(handle, 0)`. Walk `snd_retrans.entries`; for each entry with `!entry.sacked && !entry.lost && !cum_acked`, set `entry.lost = true` if `entry.seq == snd.una` OR `(entry.xmit_ts_ns / 1_000) + rack.rtt_us + rack.reo_wnd_us <= now_us`. Collect the lost-index list and drive it through the same `rack_lost_indexes` retransmit loop at `engine.rs:1467-1491` that regular RACK detect-lost uses. Counter: increment `tcp.tx_retrans` once per additional segment retransmitted beyond the front. |
| `engine.rs` (AD-18 — §3.7) | New helper `fn arm_tlp_pto(&self, conn: &mut TcpConn)` called from `dpdk_net_send`'s TX path after the new-data segment is enqueued into `snd_retrans`. Arms the TLP timer if (a) `snd_retrans.len() >= 1`, (b) `conn.tlp_timer_id.is_none()`, (c) `conn.rtt_est.srtt_us().is_some()`, (d) `conn.tlp_consecutive_probes_fired < conn.tlp_max_consecutive_probes`. PTO computed via the (new §3.4) `pto_us(srtt_us, &TlpConfig, flight_size)`. If the `srtt_us` guard fails (only possible in SYN_SENT since §3.5 seeds from handshake), the helper is a no-op and RTO covers the segment. |
| `tcp_output.rs` / `tcp_conn.rs` (AD-18 wiring) | The caller of `arm_tlp_pto` is the `dpdk_net_send` path after it appends to `snd_retrans`. If `dpdk_net_send` is currently in `engine.rs` or a helper module, the call site is that module; no separate file need. Listed here to flag review of `dpdk_net_send`'s TX sequence. |

### 2.2 Modified modules (`crates/dpdk-net/src/`)

| Module | Change |
|---|---|
| `lib.rs` | At the `dpdk_net_poll` drain site (lib.rs:142–224): remove the `let ts = dpdk_net_core::clock::now_ns();` sample; read `emitted_ts_ns` from the `InternalEvent` variant into the `dpdk_net_event_t.enqueued_ts_ns` field. Field name stays; semantics tighten from "drain time" to "emission time." |
| `api.rs` | Document the semantics change on `dpdk_net_event_t::enqueued_ts_ns` (comment + doc-comment for cbindgen). Add new extern "C" function `dpdk_net_conn_stats(engine, conn, out_ptr) → i32` returning 0 on success, `-ENOENT` on unknown handle. Define `dpdk_net_conn_stats_t` POD struct in api.rs so cbindgen emits it into the header. Extend `dpdk_net_connect_opts_t` with 5 new TLP-tuning fields (see §5.3). Validation at `dpdk_net_connect` entry rejects illegal combinations (`tlp_pto_srtt_multiplier_x100 < 100`, `tlp_max_consecutive_probes == 0 \|\| > 5`). |
| `include/dpdk_net.h` (cbindgen-regenerated) | `dpdk_net_event_t::enqueued_ts_ns` doc comment updates. New `dpdk_net_conn_stats_t` struct (9 `uint32_t` fields). New `dpdk_net_conn_stats` function. New counter fields `events_dropped` + `events_queue_high_water` + `tx_tlp_spurious`. New engine config field `event_queue_soft_cap` (u32, default 4096). New `dpdk_net_connect_opts_t` fields: `tlp_pto_min_floor_us`, `tlp_pto_srtt_multiplier_x100`, `tlp_skip_flight_size_gate`, `tlp_max_consecutive_probes`, `tlp_skip_rtt_sample_gate`. |

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
  ... eventually app calls dpdk_net_poll ...
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
// crates/dpdk-net-core/src/tcp_conn.rs
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
typedef struct dpdk_net_conn_stats {
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
} dpdk_net_conn_stats_t;

// Returns 0 on success, -ENOENT if conn handle is not live.
// Slow path — safe to call per-order for forensics tagging; do not call in
// a hot loop (per-call cost is a flow-table lookup + nine u32 loads).
int dpdk_net_conn_stats(
    dpdk_net_engine* engine,
    uint64_t conn,
    dpdk_net_conn_stats_t* out
);
```

**Forensics use pattern:**

```c
// App pattern: tag each outbound order with a pre-send stats snapshot.
dpdk_net_conn_stats_t pre;
dpdk_net_conn_stats(engine, conn, &pre);
uint64_t tx_ts = clock_now_ns();
int n = dpdk_net_send(engine, conn, order_bytes, order_len);
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

### 3.4 TLP tuning behavior (per-conn knobs)

All knobs live on `dpdk_net_connect_opts_t` and are copied into `TcpConn` at `dpdk_net_connect`. Defaults preserve A5's RFC 8985 behavior exactly; enabling any knob is an opt-in divergence documented under §8 and §6.4 of the parent spec.

**PTO formula (new, §3.2 of A5 spec §6.2 TLP fire path consults this)**:

```
// TlpConfig projected from TcpConn fields once per PTO computation
struct TlpConfig {
    floor_us: u32,                  // from conn.tlp_pto_min_floor_us
    multiplier_x100: u16,           // from conn.tlp_pto_srtt_multiplier_x100
    skip_flight_size_gate: bool,    // from conn.tlp_skip_flight_size_gate
}

fn pto_us(srtt_us: u32, cfg: &TlpConfig, flight_size: u32) -> u32 {
    // New: configurable SRTT multiplier, default 200 (2.0×)
    let base = (srtt_us as u64 * cfg.multiplier_x100 as u64 / 100) as u32;

    // New: FlightSize-1 penalty now gated on the skip flag
    // (RFC 8985 §7.2: +max(WCDelAckT, RTT/4) when FlightSize == 1)
    let with_penalty = if flight_size == 1 && !cfg.skip_flight_size_gate {
        base.saturating_add(max(WCDelAckT_us, srtt_us / 4))
    } else {
        base
    };

    // New: floor is configurable, down to 0
    max(with_penalty, cfg.floor_us)
}
```

Previous A5 signature `pto_us(srtt, min_rto) = max(2 * srtt, min_rto)` is a special case: `TlpConfig { floor_us: min_rto, multiplier_x100: 200, skip_flight_size_gate: false }` with the `+max_ack_delay` branch preserved. Existing A5 unit tests migrate to construct this default `TlpConfig`.

**Multi-probe scheduling (new, §3.2 of A5 spec ACK path)**:

```
// On ACK that leaves snd_retrans non-empty:
if !snd_retrans.is_empty() && no TLP pending {
    if conn.tlp_consecutive_probes_fired < conn.tlp_max_consecutive_probes {
        let cfg = TlpConfig::from_conn(conn);
        schedule TLP at now + pto_us(srtt, &cfg, flight_size)
    }
    // else: exhausted probe budget; let RTO own recovery
}
```

**TLP fire path (new)**:

```
on_tlp_fire(handle, gen):
    if tombstone.gen != gen: no-op
    conn = flow_table.get_mut(handle)
    if snd_retrans.is_empty(): return

    // New: RTT-sample-gate suppression (RFC 8985 §7.4) now configurable.
    // conn.tlp_rtt_sample_seen_since_last_tlp is a bool flipped to true by
    // every rtt_est.sample() call and flipped to false on each TLP fire.
    if !conn.tlp_skip_rtt_sample_gate
       && !conn.tlp_rtt_sample_seen_since_last_tlp {
        // suppress this probe; no counter bump for suppressed probes
        return
    }

    // existing A5 probe selection + emission:
    if snd.pending nonempty: probe with next MSS of new data
    else: retransmit(snd_retrans.back())

    tcp.tx_tlp++
    conn.tlp_consecutive_probes_fired += 1
    conn.tlp_rtt_sample_seen_since_last_tlp = false
    record (seq, len, tx_ts_ns) in conn.tlp_recent_probes ring for spurious attribution
    if tcp_per_packet_events: emit DPDK_NET_EVT_TCP_LOSS_DETECTED { trigger: TLP }
```

**Probe-burden reset (tcp_input.rs integration)**:

```
on ACK:
    rtt_sample_taken = rtt_est.sample(...)   // existing A5 logic
    if rtt_sample_taken {
        conn.tlp_rtt_sample_seen_since_last_tlp = true
        conn.tlp_consecutive_probes_fired = 0    // fresh RTT evidence = fresh budget
    }
    if seg.ack_seq > prev_snd_una {
        // any new data ACKed also resets the consecutive-probe budget
        conn.tlp_consecutive_probes_fired = 0
    }
```

**Spurious-probe attribution (DSACK path in tcp_input.rs)**:

```
for block in sack_blocks:
    if dsack_block(block, snd.una, conn.sack_scoreboard):
        tcp.rx_dsack++
        // New: attribute to TLP if a recent probe covered this range
        for probe in conn.tlp_recent_probes {
            if probe.seq <= block.left && block.right <= probe.seq + probe.len
               && (now_ns - probe.tx_ts_ns) < 4 * srtt_us {    // plausibility window
                tcp.tx_tlp_spurious += 1
                probe.attributed = true
                break
            }
        }
```

Per-probe attribution fires at most once per probe — the `attributed` flag on the ring entry prevents re-counting if a later DSACK also intersects. Plausibility window (4·SRTT) prevents attribution to ancient probes that happen to share a seq range after wraparound.

**Why not literal companion dummy segments**: the flag `tlp_skip_flight_size_gate` achieves the same timing goal (tight PTO regardless of FlightSize) without adding a new TX path. A literal companion segment would require a keepalive-shape emission (`seq = snd.una - 1`, peer ACKs but does not deliver) which is straightforward but genuinely new TX code; if empirically a peer ignores the timing aggression and requires FlightSize to honestly be ≥2 on the wire, §12 tracks this as a follow-on.

### 3.5 SRTT seeded from SYN handshake round-trip (new)

**Current A5 behavior:** `RttEstimator::srtt_us()` returns `None` until the first data-ACK absorbs an RTT sample (`tcp_input.rs:574`). Between ESTABLISHED and the first data-ACK, `srtt_us`, `rttvar_us`, `min_rtt_us` are all zero/None. `rto_us` reports `tcp_initial_rto_us` (5 ms default).

**A5.5 behavior:** the first RTT sample is absorbed at the moment `handle_syn_sent` accepts the SYN-ACK:

```rust
// crates/dpdk-net-core/src/tcp_input.rs, handle_syn_sent valid-SYN-ACK branch
// AFTER option negotiation, BEFORE engine dispatch:
if conn.syn_retransmit_count == 0 {
    // Karn's rule: only sample the first SYN's ACK, not a retransmit's.
    // syn_tx_ts_ns was stashed on TcpConn at SYN-send time (new field).
    let rtt_us = now_us.wrapping_sub((conn.syn_tx_ts_ns / 1_000) as u32);
    if (1..60_000_000).contains(&rtt_us) {
        conn.rtt_est.sample(rtt_us);
        conn.rack.update_min_rtt(rtt_us);
    }
}
```

**New `TcpConn` field:** `syn_tx_ts_ns: u64` — set at the SYN emission site (connect path) to `clock::now_ns()`; consumed here. Adds 8 bytes per connection; negligible.

**RFC alignment:** RFC 6298 §3.3 explicitly permits ("MAY"): "The RTT of the SYN segment MAY be used as the first SRTT." Karn's rule is honored by the `syn_retransmit_count == 0` guard. The `(1..60_000_000)` bounds check matches the existing data-ACK RTT sampler (`tcp_input.rs:564, 581`) for consistency.

**Observability consequence:** from the moment the connection enters ESTABLISHED, `dpdk_net_conn_stats` returns a trustworthy `srtt_us` value — apps no longer need to wait for one data round-trip to tag orders with meaningful RTT state.

### 3.6 RACK mark-losses-on-RTO (AD-17, new)

**Current A5 behavior** (`engine.rs:803-922`, `on_rto_fire`): retransmit only the front entry at index 0; the rest of `snd_retrans` stays unmarked. Those entries are eventually flagged as lost by the regular §6.2 Step 5 detect-lost pass when the next ACK arrives — which is one RTT after the RTO fire.

**A5.5 behavior:** at the top of `on_rto_fire` Phase 3, before `self.retransmit(handle, 0)`, run the §6.3 `RACK_mark_losses_on_RTO` pass:

**Erratum (A5.5 Task 16): `RACK.rtt` mapping.** RFC 8985 §6.1 defines `RACK.rtt` as the RTT of the most recently delivered segment (data source for `RACK_mark_losses_on_RTO`). Our `RackState` struct (`crates/dpdk-net-core/src/tcp_rack.rs`) **does not carry a dedicated `rack.rtt_us` field** — we track `min_rtt_us` there and SRTT in the sibling `rtt_est: RttEstimator`. The Task 14 implementation therefore maps `RACK.rtt` → `conn.rtt_est.srtt_us().unwrap_or(conn.rack.min_rtt_us)`: prefer the smoothed RTT when available (post-SRTT-seed from Task 13 this is always available from ESTABLISHED), fall back to `min_rtt_us` for the degenerate pre-sample case, and tolerate 0 in the arithmetic below (the `seq == snd.una` disjunct still fires for the front entry regardless). The pseudocode below writes `rtt_us` as shorthand for this mapping.

```rust
// RFC 8985 §6.3 RACK_mark_losses_on_RTO (Stage-2 AD-17 close).
let now_us = (now_ns / 1_000) as u32;
// Erratum: RackState has no `rtt_us`; map RACK.rtt → SRTT (or min_rtt fallback).
let rtt_us = conn.rtt_est.srtt_us().unwrap_or(conn.rack.min_rtt_us);
let reo_wnd_us = conn.rack.reo_wnd_us;
let snd_una = conn.snd.una;
let mut rto_lost: Vec<u16> = Vec::new();
for (i, e_) in conn.snd_retrans.entries.iter().enumerate() {
    if e_.sacked || e_.lost { continue; }
    let end_seq = e_.seq.wrapping_add(e_.len as u32);
    if seq_le(end_seq, snd_una) { continue; }  // cum-ACKed, prune handles later
    let age_us = now_us.wrapping_sub((e_.xmit_ts_ns / 1_000) as u32);
    let mark_lost = e_.seq == snd_una
        || age_us >= rtt_us.saturating_add(reo_wnd_us);
    if mark_lost {
        rto_lost.push(i as u16);
    }
}
// Set lost=true in a second pass (borrow-checker avoidance).
for &idx in &rto_lost {
    conn.snd_retrans.entries[idx as usize].lost = true;
}
// Route through the existing retransmit loop that already handles
// rack_lost_indexes at engine.rs:1467-1491.
outcome.rack_lost_indexes = rto_lost;
```

**Interaction with existing RTO retransmit:** the front-index retransmit (`self.retransmit(handle, 0)`) becomes redundant in the case where `snd_retrans[0].seq == snd_una` (the §6.3 pass catches it). We drop the explicit front retransmit and let the `rack_lost_indexes` loop drive the whole burst; the loop already retransmits entries in index order and increments `tcp.tx_rto` once per RTO fire (not once per segment) to keep counter semantics stable. A unit test asserts the "single RTO fire → N retransmits → one `tx_rto` increment" contract.

**Why not gated on an opt-in**: RFC 8985 §6.3 is explicit SHOULD-equivalent guidance that complements RFC 6298 §5.4. A5's current behavior is a deviation listed in the A5 review's S-1 → AD-17 promotion; A5.5 closes it directly. No per-connect knob.

### 3.7 TLP armed on every new-data send (AD-18, new)

**Current A5 behavior:** TLP PTO is armed only from the ACK handler (`engine.rs:1549-1584`), after a data ACK that leaves `snd_retrans` non-empty. The first burst on a fresh connection — or the first segment after an idle period — is covered by RTO only.

**A5.5 behavior:** new helper `arm_tlp_pto(&self, handle, conn)` invoked from `dpdk_net_send`'s TX path after the new-data segment lands in `snd_retrans`:

```rust
// crates/dpdk-net-core/src/engine.rs helper (called from dpdk_net_send path)
fn arm_tlp_pto(&self, handle: ConnHandle, conn: &mut TcpConn) {
    // Gate conditions (all required):
    if conn.snd_retrans.is_empty() { return; }
    if conn.tlp_timer_id.is_some() { return; }    // already armed
    let Some(srtt_us) = conn.rtt_est.srtt_us() else {
        // No SRTT yet — only possible in SYN_SENT before §3.5 seed.
        // RTO covers the first burst; TLP arms once SYN-ACK seeds SRTT.
        return;
    };
    if conn.tlp_consecutive_probes_fired >= conn.tlp_max_consecutive_probes {
        return;                                   // budget exhausted
    }
    let cfg = TlpConfig::from_conn(conn);
    let flight_size = conn.snd_retrans.flight_size();
    let pto = crate::tcp_tlp::pto_us(srtt_us, &cfg, flight_size);
    conn.tlp_timer_id = Some(self.schedule_tlp(handle, pto));
}
```

**Call sites:** `dpdk_net_send`'s TX path calls `arm_tlp_pto` after the newly-emitted segment is appended to `snd_retrans`. The existing ACK-handler arm at `engine.rs:1549-1584` stays (reasserts PTO on ACKs that partially progress `snd_una`).

**Interaction with multi-probe budget (§3.4):** `arm_tlp_pto` checks `tlp_consecutive_probes_fired` so a completely-exhausted budget (RTO took over) does not re-arm TLP on every subsequent send until a fresh RTT sample or new-data ACK resets the counter.

**Interaction with SRTT seed (§3.5):** post-SYN-seed, `srtt_us().is_some()` holds from ESTABLISHED onward. The `None` branch fires only in SYN_SENT state (where `dpdk_net_send` rejects input anyway) or in a pathological case where §3.5's Karn's-rule guard skipped the sample; in that case the next data-ACK seeds SRTT and the next send arms TLP.

**RFC alignment:** RFC 8985 §7.2 says the sender SHOULD start/restart the PTO timer after transmitting new data. A5's ACK-only arm is a SHOULD violation tracked as AD-18; A5.5 closes it.

**Counter semantics:** existing `tcp.tx_tlp` counts probes fired (not arms). Arming from the send path does not bump any counter; the counter fires at `on_tlp_fire` time only. No new counter needed.

---

## 4. Counter surface (§9.1.1, all slow-path)

| Counter (group.name) | Semantics |
|---|---|
| `obs.events_dropped` | Incremented once per event dropped from the queue due to soft-cap overflow. **Nonzero = app poll cadence cannot keep up + some events were lost.** |
| `obs.events_queue_high_water` | Latched max of observed queue depth since engine start. **High value with `events_dropped == 0` = close call; high value with nonzero `events_dropped` = actual loss.** |
| `tcp.tx_tlp_spurious` | Incremented once per prior TLP probe confirmed spurious via DSACK (peer reports it already had the data). Paired with `tcp.tx_tlp`: `spurious_ratio = tx_tlp_spurious / tx_tlp`. **Above ~3–5% indicates jitter budget under-provisioned relative to path reality — application should raise `tlp_pto_min_floor_us` on affected sockets.** Attribution is per-probe (no double-counting) and within a 4·SRTT plausibility window to avoid false attribution across seq wrap. |

Both `AtomicU64`. Increment sites: `EventQueue::push` only — never on the drain path, never on any TCP or L3 path. Slow-path by strict definition (fires only when queue pressure exists).

**Group naming**: A new `obs` group is introduced (short for "observability") for engine-internal observability signals. Alternative would be to fold into the existing `poll` or `eth` group, but neither fits semantically — these are event-queue-specific. Group additions in `counters.rs` follow the same pattern as `poll`/`eth`/`ip`/`tcp`. Fields are also zero-init and match the cbindgen header layout.

---

## 5. Config / API surface changes

### 5.1 `dpdk_net_engine_config_t` (additions)

| Field | Type | Default | Notes |
|---|---|---|---|
| `event_queue_soft_cap` | `u32` | 4096 | Max queue depth before drop-oldest. Must be ≥ 64; configs with smaller values are rejected at `engine_create` with `-EINVAL`. |

### 5.2 `dpdk_net_event_t` (semantic change, no layout change)

- `enqueued_ts_ns` doc comment updates from:
  > "ns timestamp when this event was drained into the caller's array"

  to:
  > "ns timestamp (engine monotonic clock) sampled at event emission inside the stack. Unrelated to `rx_hw_ts_ns`. For packet-triggered events, emission time is when the stack processed the triggering packet, not when the NIC received it — use `rx_hw_ts_ns` for NIC-arrival time. For timer-triggered events (RTO fire, A5 loss-detected), emission time is the fire instant."

### 5.3 New extern "C" function

```c
int dpdk_net_conn_stats(
    dpdk_net_engine* engine,
    uint64_t conn,
    dpdk_net_conn_stats_t* out
);
```

Returns:
- `0` on success, `out` populated.
- `-EINVAL` if engine or out is null.
- `-ENOENT` if conn is not a live handle in the flow table.

Thread-safety: same as every other API in this stack — per §3 single-lcore engine model, no cross-thread calls, no locks needed. Calling from a different thread than the engine's poll thread is undefined behavior (same as all other APIs).

### 5.4 Public counter surface

- `dpdk_net_counters_t` gains `obs_events_dropped` and `obs_events_queue_high_water` fields (u64 each). `dpdk_net_tcp_counters_t` gains `tx_tlp_spurious`. Layout-wise all three are appended to their respective struct ends. cbindgen regenerates; header-drift check enforces consistency.

### 5.5 `dpdk_net_connect_opts_t` (additions, per-conn TLP tuning)

All default to behavior-preserving values so existing callers are unaffected. A5's `rack_aggressive` and `rto_no_backoff` knobs stay as-is; these are additional.

| Field | Type | Default | Valid range | Notes |
|---|---|---|---|---|
| `tlp_pto_min_floor_us` | `u32` | `0` inherits engine `tcp_min_rto_us` | `0` .. `tcp_max_rto_us` OR `u32::MAX` | **Erratum (A5.5 Task 16): zero-init-friendly semantics.** `0` (the zero-init default) inherits the engine-wide `tcp_min_rto_us` — callers that memset the struct get A5-default behavior unchanged. `u32::MAX` is the explicit "no floor" sentinel (e.g. aggressive-preset order-entry sockets that truly want no PTO floor). Any other value must be ≤ `tcp_max_rto_us`; values strictly above (and not equal to `u32::MAX`) are rejected at `dpdk_net_connect` with `-EINVAL`. Can be set above or below the engine-wide `tcp_min_rto_us` within this bound. |
| `tlp_pto_srtt_multiplier_x100` | `u16` | `200` | 100 .. 200 | Expressed as integer ×100 (100 = 1.0×, 150 = 1.5×, 200 = 2.0×). Values outside the range rejected with `-EINVAL`. Values above 2.0× rejected — that's RTO territory, not TLP. |
| `tlp_skip_flight_size_gate` | `bool` | `false` | — | When `true`, the `+max(WCDelAckT, RTT/4)` penalty in the PTO formula is skipped regardless of FlightSize. Trades spurious-probe risk (peer's delayed-ACK fires after our probe) for tighter PTO timing. |
| `tlp_max_consecutive_probes` | `u8` | `1` | 1 .. 5 | Number of TLP probes to fire consecutively before falling back to RTO-driven retransmit. Reset on any new RTT sample or newly-ACKed data. `0` and `>5` rejected with `-EINVAL`. |
| `tlp_skip_rtt_sample_gate` | `bool` | `false` | — | When `true`, the RFC 8985 §7.4 "no new RTT sample since last TLP" suppression is disabled. Enables back-to-back TLPs without an intervening RTT sample. Required alongside `tlp_max_consecutive_probes > 1` for the multi-probe feature to actually fire on consecutive schedules. |

**Composition note**: For genuinely-aggressive order-entry sockets, the typical combination is:

```c
dpdk_net_connect_opts_t opts = {
    // ... existing fields ...
    .rack_aggressive = true,
    .rto_no_backoff = true,
    .tlp_pto_min_floor_us = UINT32_MAX,       // explicit no-floor sentinel (A5.5 Task 16 erratum)
    .tlp_pto_srtt_multiplier_x100 = 100,      // 1.0 × SRTT
    .tlp_skip_flight_size_gate = true,
    .tlp_max_consecutive_probes = 3,
    .tlp_skip_rtt_sample_gate = true,
};
```

This configuration fires the first TLP at `SRTT` (not `2·SRTT + max_ack_delay`), up to 3 consecutive probes at `SRTT` cadence each, then falls back to RTO (which itself uses `tcp_initial_rto_us` = 5ms and no-backoff). Monitor `tcp.tx_tlp_spurious / tcp.tx_tlp` on the engine — target < 3–5%. If the ratio climbs, raise `tlp_pto_min_floor_us` incrementally until spurious rate stabilizes.

**Note (A5.5 Task 16 erratum):** the no-floor case uses `UINT32_MAX` as an explicit sentinel rather than `0`. The `0` value is reserved for zero-init callers and means "inherit engine `tcp_min_rto_us`" — this keeps memset-of-struct callers at the A5 safe default instead of accidentally opting them into no-floor behavior. Conservative pre-A5.5 examples that used `.tlp_pto_min_floor_us = 0` to mean "no floor" must migrate to `UINT32_MAX`.

---

## 6. Accepted divergences

Observability items: no ADs. mTCP comparison produces no new ADs for the event-queue overflow counter or the stats getter — absence there is scope difference, not behavioral.

- `AD-A5-5-enqueued-ts-semantics`: the `enqueued_ts_ns` field semantics changes from drain-time to emission-time *without* a field rename. Strictly a pre-ship-tag ABI refinement. Noted as a §9.3 events-table correction in the parent spec and in `docs/superpowers/reviews/phase-a5-5-rfc-compliance.md` as an informational observation.

SRTT seed from SYN handshake (new, affects every connection; net-conservative):

- `AD-A5-5-srtt-from-syn`: RFC 6298 §3.3 permits ("MAY"). The first SRTT sample comes from the SYN round-trip, rather than the first data-ACK. Karn's rule is honored via the `syn_retransmit_count == 0` guard — retransmitted SYNs do not produce a sample. Rationale: trader-latency use case requires valid RTT state from ESTABLISHED (so `dpdk_net_conn_stats` is trustworthy pre-first-data and AD-18's arm-TLP-on-send has a valid PTO). Risk: essentially none — the SYN round-trip is a well-defined RTT sample on the first SYN's ACK; bounds-checked to `[1, 60_000_000)` µs matching the existing data-ACK sampler. mTCP comparison: mTCP seeds `tp->srtt_us` on first data ACK only; our deviation is a strict improvement in RTT-estimator startup.

AD-17 (new, affects every connection; closes a Stage-1 Missing-SHOULD from A5 RFC review):

- `AD-A5-5-rack-mark-losses-on-rto`: RFC 8985 §6.3 `RACK_mark_losses_on_RTO` — A5's `on_rto_fire` retransmitted only the front entry (promoted to AD-17 in the A5 RFC review). A5.5 implements the §6.3 pass. From phase-a5-5-complete forward this row in the §6.3 RFC matrix reads "RACK-TLP: primary loss-detection path including §6.3 RACK_mark_losses_on_RTO"; the AD-17 row retires from §6.4.

AD-18 (new, affects every connection; closes a Stage-1 Missing-SHOULD from the A5 mTCP + RFC review):

- `AD-A5-5-tlp-arm-on-send`: RFC 8985 §7.2 — A5 armed TLP PTO from the ACK handler only (promoted to AD-18 in the A5 review, mirroring the mTCP E-2 finding). A5.5 adds an arm from the `dpdk_net_send` TX path. From phase-a5-5-complete forward this row reads "TLP PTO armed on ACK **and** on new-data send per RFC 8985 §7.2"; the AD-18 row retires from §6.4.

AD-15 retirement (pre-existing Stage-2 AD, superseded by A5.5 data structures):

- `AD-15 retired`: TLP pre-fire state (`TLP.end_seq`, `TLP.is_retrans`) is superseded by A5.5's multi-probe data structures — the `tlp_recent_probes` ring replaces single-slot `tlp_end_seq`, and `tlp_consecutive_probes_fired < tlp_max_consecutive_probes` replaces single-in-flight. A5.5 plan task 16 updates `docs/superpowers/reviews/phase-a5-rfc-compliance.md` with a one-line note retiring AD-15 from the Stage-2 AD list; no code for a dedicated AD-15 task is required because A5.5's multi-probe task already wires the superseding structures.

TLP tuning items (per-conn opt-in; defaults preserve RFC 8985 behavior exactly, so these are only ADs for sockets that opt in):

- `AD-A5-5-tlp-pto-floor-zero`: RFC 8985 §7.2 is silent on a PTO minimum; many implementations use 10ms (see earlier A5 analysis). Our per-conn opt-in allows `0` = no floor. Rationale: on a tight-jitter intra-region link the 10ms floor is multiple RTTs of wasted budget. Risk: spurious probes if jitter exceeds SRTT/4. Mitigation: `tx_tlp_spurious` counter lets the app self-correct the floor upward.
- `AD-A5-5-tlp-multiplier-below-2x`: RFC 8985 §7.2 hard-codes `2·SRTT`. We allow `1.0× .. 2.0×` per-conn. Rationale: `2·SRTT` is conservative for realistic delayed-ACK budgets the RFC assumes (≥40ms); trading peers do not use delayed ACKs in hot paths. Risk: probe-before-peer-ACK racing. Mitigation: same spurious counter.
- `AD-A5-5-tlp-skip-flight-size-gate`: RFC 8985 §7.2 PTO `+max(WCDelAckT, RTT/4)` penalty when FlightSize==1. We allow per-conn skip. Rationale: WCDelAckT default of 200ms is four orders of magnitude larger than our target order-entry RTT; the penalty blows any latency budget. Risk: if the peer has delayed-ACK on, the probe fires before the peer's ACK; detected as spurious via DSACK. Mitigation: same counter + optional companion-segment follow-on (§12).
- `AD-A5-5-tlp-multi-probe`: RFC 8985 §7.4 allows at most one pending probe at a time; does not explicitly address consecutive schedules after probe-ACK arrival. Our multi-probe knob fires up to N consecutive probes each at PTO cadence before giving up to RTO. Rationale: on a clean probe-ACK arrival, a second probe at PTO cadence is often cheaper than a full RTO wait for a separate tail-loss. Risk: probe amplification. Mitigation: `tlp_max_consecutive_probes` is capped at 5 and budget resets on any new-data ACK.
- `AD-A5-5-tlp-skip-rtt-sample-gate`: RFC 8985 §7.4 suppresses TLP when no new RTT sample has been seen since the last probe. Our opt-out disables the suppression. Rationale: on a quiescent path with occasional lost segments, consecutive probes without intervening samples is exactly the recovery we want. Risk: runaway probing if path is persistently broken. Mitigation: `tlp_max_consecutive_probes` bounds the burst; RTO handles persistent failure.

All five TLP tuning ADs carry zero impact when the per-conn flag is at its default (A5 RFC 8985 behavior). mTCP comparison produces no new ADs for these (mTCP does not implement TLP at all, per spec §10.13 review). RFC compliance review flags them explicitly under §6.4 as new rows citing the per-conn opt-in nature.

`AD-A5-5-srtt-from-syn`, `AD-A5-5-rack-mark-losses-on-rto`, and `AD-A5-5-tlp-arm-on-send` apply to **every** connection (not opt-in) but are each net-conservative under their cited RFC clause — they close SHOULD-level RFC compliance gaps that A5 explicitly deferred. Expected RFC compliance review posture: the three closures collapse three Stage-2 AD rows (AD-15, AD-17, AD-18) into nothing; the three new rows document the improvement. Net §6.4 row count is approximately unchanged.

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
4. **Stats getter on unknown handle** — `dpdk_net_conn_stats(engine, 0xdead_beef, &out)` returns `-ENOENT`, `out` unchanged.
5. **RTT fields before first sample** — on a freshly-connected socket, before any RTT sample lands, `stats()` returns `srtt_us == 0`, `rttvar_us == 0`, `min_rtt_us == 0`, `rto_us == tcp_initial_rto_us`. App code can check `srtt_us > 0` to gate on "RTT trusted."
6. **RTT fields track the stack** — drive enough ACKs through a TAP pair to establish an SRTT; call `stats()` and assert `srtt_us` + `rttvar_us` + `min_rtt_us` + `rto_us` match the values held in the engine's `RttEstimator` + `RackState` at the same instant (values projected, not recomputed). Follow-up: induce an RTO fire with default `rto_no_backoff=false`; assert `rto_us` reflects the post-backoff value.

TLP-tuning integration tests:

7. **Zero-floor PTO** — connect with `tlp_pto_min_floor_us=0`, establish SRTT ≈ 100µs; induce tail loss; assert TLP fires at ≈ 200µs (2·SRTT, no floor), not at `tcp_min_rto_us` = 5ms.
8. **1.0× multiplier** — connect with `tlp_pto_srtt_multiplier_x100=100`; induce tail loss; assert TLP fires at ≈ SRTT, not 2·SRTT.
9. **FlightSize=1 without penalty** — connect with `tlp_skip_flight_size_gate=true`; send a single segment and drop it; assert TLP fires at `2·SRTT` not `2·SRTT + max(WCDelAckT, RTT/4)`. Compare against a baseline run with the flag off to assert the penalty path is still honored when not opted out.
10. **Multi-probe TLP** — connect with `tlp_max_consecutive_probes=3`, `tlp_skip_rtt_sample_gate=true`; induce persistent tail loss (peer drops all probes); assert 3 probes fire at PTO cadence, then RTO takes over on the 4th attempt. Assert `tcp.tx_tlp == 3` and `tcp.tx_rto == 1` exactly.
11. **Probe budget reset on new data** — connect with `tlp_max_consecutive_probes=3`; fire one TLP successfully (peer ACKs new data covering the probe's seq); send more new data, induce tail loss again; assert a fresh TLP fires (budget was reset by the new-data ACK, not exhausted from the first probe).
12. **Spurious-probe attribution** — induce a reorder scenario where the original segment arrives just after the TLP probe (so peer DSACKs the probe); assert `tcp.tx_tlp_spurious == 1`, `tcp.rx_dsack == 1`, and the counter does not re-fire on subsequent DSACKs that do not correspond to an attributed probe.
13. **Invalid opts rejected** — `dpdk_net_connect` with `tlp_pto_srtt_multiplier_x100=50` returns `-EINVAL`; same for `=250`, `tlp_max_consecutive_probes=0`, `=6`, `tlp_pto_min_floor_us > tcp_max_rto_us`.

SRTT-seed-from-SYN tests (new, §3.5):

14. **SRTT nonzero immediately after ESTABLISHED** — on a TAP pair, establish a connection; call `dpdk_net_conn_stats` as the first API call after the `Connected` event; assert `srtt_us > 0`, `min_rtt_us > 0`, `rto_us ≈ srtt_us + 4·rttvar_us` clamped to `[tcp_min_rto_us, tcp_max_rto_us]` (no longer `tcp_initial_rto_us`).
15. **Karn's rule on SYN retransmit** — induce a SYN retransmit (drop the first SYN at the peer); let the retransmitted SYN get through; establish; assert `srtt_us == 0` immediately after ESTABLISHED (the guard `syn_retransmit_count == 0` skipped the seed); assert a subsequent data-ACK absorbs the first actual RTT sample normally.
16. **SYN-sample bounds check** — unit test: feed a SYN-ACK with `now_us - syn_tx_ts_us = 0` (clock skew) and with `= 60_000_001` (spurious); assert `rtt_est.sample` is not called in either case.

AD-17 RACK-mark-losses-on-RTO tests (new, §3.6):

17. **Multi-segment tail-loss RTO recovery** — on a TAP pair, send 5 segments; have the peer drop all 5 and never ACK; let RTO fire; assert all 5 entries in `snd_retrans` are retransmitted in one burst (not one-per-subsequent-ACK), `tcp.tx_retrans == 5`, `tcp.tx_rto == 1` (one RTO fire event, not five).
18. **§6.3 age-based marking** — unit test: construct an `snd_retrans` deque with entries at staggered `xmit_ts_ns`; set `rack.rtt_us` and `rack.reo_wnd_us` to known values; invoke `RACK_mark_losses_on_RTO` at a known `now_us`; assert the expected subset of entries is marked `lost=true` per the formula.
19. **Front-entry-only case preserved** — when `snd_retrans` contains one entry, RTO fires, the pass marks that entry lost, the retransmit loop retransmits exactly one segment (semantics equivalent to pre-A5.5 single-retransmit behavior). Counter: `tcp.tx_rto == 1`, `tcp.tx_retrans == 1`.

AD-18 arm-TLP-on-send tests (new, §3.7):

20. **First-burst TLP fires at PTO, not RTO** — on a TAP pair with `tcp_initial_rto_us = 5ms`, establish a connection (SRTT seeded from SYN at e.g. 100 µs), send a single segment, drop it at the peer; assert TLP fires at `≈ 2·srtt_us` (= 200 µs, per default PTO formula), not at 5ms; `tcp.tx_tlp == 1`, `tcp.tx_rto == 0`.
21. **New-data send re-arms TLP** — after a TLP ACK that does not fully drain `snd_retrans`, send more new data; assert `arm_tlp_pto` re-arms the timer (the single-armed-at-a-time invariant: only one arm at a time). Unit test on `arm_tlp_pto` conditions.
22. **SYN_SENT no-op** — unit test: `arm_tlp_pto` called while connection is in SYN_SENT state is a no-op (no timer scheduled). Guards against regressions where the helper is called before SRTT seed.
23. **Budget-exhausted no-op** — set `tlp_consecutive_probes_fired = tlp_max_consecutive_probes`; call `arm_tlp_pto`; assert no timer scheduled. Complements test 11 (budget reset on new-data ACK).

### 7.3 Existing test updates

- A3/A4 TAP tests that implicitly depend on `enqueued_ts_ns` (if any — grep shows no current dependence) need no change.
- A5 TAP tests (if they land before A5.5) — the `emitted_ts_ns` timestamp semantic change propagates cleanly since A5 call sites are added fresh.

### 7.4 A8 counter-coverage entries

- `obs.events_dropped` — scenario: overflow test from 7.2.2.
- `obs.events_queue_high_water` — same scenario.
- `tcp.tx_tlp_spurious` — scenario: spurious-probe attribution test from 7.2.12 (DSACK after TLP within 4·SRTT window).

---

## 8. Review gates

Per `feedback_phase_mtcp_review.md` + `feedback_phase_rfc_review.md`:

- `docs/superpowers/reviews/phase-a5-5-mtcp-compare.md` — `mtcp-comparison-reviewer` subagent. Moderate review: mTCP has no analog for event-queue overflow accounting, the stats getter, or TLP at all — those gaps are scope-difference not behavioral. Expected new findings: AD-18 (arm-TLP-on-send) matches the mTCP E-2 finding from A5 review, so that row migrates from "Stage-2 AD" to "Closed in A5.5". AD-17 (RACK_mark_losses_on_RTO) has no mTCP analog (mTCP does not implement RACK). Net: expected ~0 new ADs after closure accounting.
- `docs/superpowers/reviews/phase-a5-5-rfc-compliance.md` — `rfc-compliance-reviewer` subagent. Moderate review: A5.5 touches RFC 6298 §3.3 (SYN-RTT seed), RFC 8985 §6.3 (RACK mark-losses-on-RTO), RFC 8985 §7.2 (arm-TLP-on-send), RFC 8985 §7.2/§7.4 (TLP tuning knobs per-conn opt-in), plus the observability items. Reviewer verifies (a) the AD-17/18 closures fully satisfy the cited MUSTs/SHOULDs, (b) Karn's rule is honored in the SYN-RTT path, (c) TLP tuning ADs carry correct §6.4 rows with opt-in defaults. Net: 6 new §6.4 rows (5 TLP knobs + SRTT-from-SYN), 3 retirements from Stage-2 AD list (AD-15/17/18).

Per `feedback_per_task_review_discipline.md`, each implementation task gets spec-compliance + code-quality reviewer subagents before moving on (opus).

---

## 9. Rough task scale

~16–17 tasks:

Observability (tasks 1–8, matches prior scope):

1. `InternalEvent::emitted_ts_ns` field + producer wiring (13 call sites in `engine.rs` per §2.1 table; plan task walks all via grep to catch any new sites added between phase-a5-complete and phase-a5.5 start). (1)
2. `dpdk_net_poll` drain-time simplification: read `emitted_ts_ns` through, drop the sample at drain. Header-comment update. (1)
3. `EventQueue` soft_cap + drop-oldest + counter wiring. Unit tests for overflow + high-water. (1)
4. `counters.rs` `obs` group + `events_dropped` + `events_queue_high_water` fields + cbindgen header regen. (1)
5. `dpdk_net_engine_config_t::event_queue_soft_cap` field + validation (rejects `< 64`). (1)
6. `TcpConn::stats` method + `ConnStats` struct (9 fields: 5 send-path + 4 RTT/RTO) + `flow_table::get_stats`. Includes small `rtt_est.srtt_us()` / `rttvar_us()` / `rto_us()` and `rack.min_rtt_us()` accessor helpers if A5 hasn't already exposed them at the module boundary. (1)
7. `dpdk_net_conn_stats` extern "C" + `dpdk_net_conn_stats_t` header struct. Integration tests 7.2.3 through 7.2.6 (stats under backpressure + `-ENOENT` + pre-sample values + RTT tracking). (1)
8. Integration tests 7.2.1 + 7.2.2 (emission-time + overflow). (1)

TLP tuning (tasks 9–12, new):

9. `TlpConfig` struct + `pto_us` signature change + unit tests for floor / multiplier / FlightSize-gate combinations. Migrate existing A5 `tcp_tlp.rs` tests to construct `TlpConfig::default()`. (1)
10. `dpdk_net_connect_opts_t` extension (5 fields) + `dpdk_net_connect` validation rejecting out-of-range values + `TcpConn` field mirrors + projection into `TlpConfig`. Integration test 7.2.13 (invalid-opts rejection). (1)
11. Multi-probe TLP scheduling + fire-handler bookkeeping + budget reset on RTT sample / new-data ACK + RTT-sample-gate plumbing. `tcp.tx_tlp_spurious` counter add. Integration tests 7.2.7–7.2.11 (zero floor, 1× multiplier, FlightSize skip, multi-probe, budget reset). (1)
12. DSACK spurious-probe attribution: `tlp_recent_probes` ring on `TcpConn` (fixed-size 5-entry array), plausibility window (4·SRTT), per-probe `attributed` flag. Integration test 7.2.12. (1)

Stage-2 AD closures + knob coverage + bookkeeping (tasks 13–17, new):

13. **SRTT seeded from SYN handshake** (§3.5): add `syn_tx_ts_ns: u64` field to `TcpConn`; set at SYN emission; consume in `handle_syn_sent` on valid-SYN-ACK branch with Karn's-rule guard. Unit test 7.2.16 (bounds check) + integration tests 7.2.14 (SRTT nonzero post-ESTABLISHED) + 7.2.15 (Karn's rule on SYN retransmit). (1)
14. **AD-17 `RACK_mark_losses_on_RTO`** (§3.6): new pass at top of `on_rto_fire` Phase 3; route lost-index list through existing `rack_lost_indexes` retransmit loop; drop the explicit front retransmit once the pass owns it. Unit test 7.2.18 (age-based marking) + integration tests 7.2.17 (multi-segment tail-loss) + 7.2.19 (front-entry-only preserved). (1)
15. **AD-18 arm-TLP-on-send** (§3.7): new `arm_tlp_pto` helper; call from `dpdk_net_send` TX path after new-data enqueue; gate on SRTT-available + no-TLP-armed + budget-not-exhausted. Unit tests 7.2.21 (re-arm), 7.2.22 (SYN_SENT no-op), 7.2.23 (budget exhausted) + integration test 7.2.20 (first-burst PTO not RTO). (1)
16. **AD-15 retirement bookkeeping**: update `docs/superpowers/reviews/phase-a5-rfc-compliance.md` with one-line notes retiring AD-15 (superseded by A5.5 multi-probe data structures), AD-17 (closed — `RACK_mark_losses_on_RTO` implemented), and AD-18 (closed — TLP-arm-on-send implemented). Each retirement cites the closing A5.5 task number. No code; doc-only. (1)
17. **Knob-coverage extension** (per roadmap §A11): add the 5 TLP knobs + `event_queue_soft_cap` + the aggressive-preset combination to `tests/knob-coverage.rs`. Each knob entry names a scenario function and a non-default value; scenarios assert at least one observable consequence distinguishing the non-default behavior. Also add the A5.5 knobs to any informational-whitelist if a knob is explicitly not behavioral (none expected at this time). (1)

Ship gate (after task 17):

- Dispatch `mtcp-comparison-reviewer` + `rfc-compliance-reviewer` subagents in parallel. Reports to `docs/superpowers/reviews/phase-a5-5-mtcp-compare.md` and `phase-a5-5-rfc-compliance.md`. Tag `phase-a5-5-complete` only when both reports carry zero open `[ ]`.

Each task is surgical, touches one concern, carries its own tests. Ordering preserves independence: observability 1–8 first (no cross-dependency with TLP); TLP knob work 9–12 depends on task 6's `ConnStats` for forensics but not the other way; AD closures 13–15 are independent of each other (13 → unblocks 15, since 15's SRTT-available guard trivially holds post-13); bookkeeping 16–17 close out the phase.

---

## 10. Updates to parent spec `2026-04-17-dpdk-tcp-design.md`

Small edits in the same commit as this phase design doc:

- §9.3 events: clarify that `enqueued_ts_ns` is emission-time, not drain-time. One sentence.
- §9.1 counter examples: add `obs.events_dropped`, `obs.events_queue_high_water`, and `tcp.tx_tlp_spurious` to the example list. Note the `obs` group alongside `poll`/`eth`/`ip`/`tcp`.
- §4 API: brief mention of `dpdk_net_conn_stats` under the introspection paragraph (if one exists; otherwise add a one-paragraph "Introspection API" subsection). Note that it covers both send-path state and RTT estimator state in a single call.
- §4.2 contracts: document the `event_queue_soft_cap` / drop-oldest / counter triplet.
- §6.3 RFC matrix rows:
  - RFC 8985: update to "RACK-TLP: primary loss-detection path, including §6.3 `RACK_mark_losses_on_RTO` and §7.2 arm-on-send and arm-on-ACK. RACK-TLP tuning: per-connect opt-in knobs deviate from strict §7.2/§7.4 when set; default matches RFC 8985 exactly."
  - RFC 6298 §3.3: add mention of "SRTT seeded from SYN handshake round-trip per §3.3 MAY."
- §6.4 new rows:
  - Five per `AD-A5-5-tlp-*` TLP knob ADs (per-conn opt-in; rationale = trading fail-fast latency budgets).
  - `AD-A5-5-srtt-from-syn` — SRTT seeded from SYN handshake per RFC 6298 §3.3 MAY.
  - `AD-A5-5-rack-mark-losses-on-rto` — §6.3 RACK pass now implemented (promoted AD-17 retires).
  - `AD-A5-5-tlp-arm-on-send` — §7.2 arm-on-send now implemented (promoted AD-18 retires).
- §6.4 retirements: AD-17 and AD-18 removed from the Stage-2 Accepted Deviation list (absorbed into the two closure rows above). AD-15 retired — one-line note: "Superseded by A5.5 multi-probe data structures (`tlp_recent_probes` ring + `tlp_consecutive_probes_fired`)."
- §4 connect opts: list the 5 new TLP-tuning fields under the existing A5 `rack_aggressive` / `rto_no_backoff` section.
- `docs/superpowers/reviews/phase-a5-rfc-compliance.md` — AD-15 + AD-17 + AD-18 marked "closed in A5.5 (`phase-a5-5-complete`)" with a cross-reference to the closing A5.5 task number and the spec §6 entry that supersedes them. Historical preservation: retain the original AD text for traceability; add a "retirement note" suffix under each.

---

## 11. Performance notes

- **Event push hot path**: gains one `clock::now_ns()` call (TSC read, ~10–30 ns) + one `atomic::fetch_max` (for high-water) + one conditional `pop_front + fetch_add` only when the queue is at cap (rare). Net effect on the stack-internal "emit an event" micro-path: well under 100 ns per event on a TSC-calibrated clock. For context, events fire on per-segment, per-state-change, or per-connection boundaries — not per-byte — so this is dominated by segment-rate, not packet-rate.
- **Drain-path simplification**: removes one `clock::now_ns()` call per drained event (replaced by a field read from the variant). Small net positive for high-event-count polls.
- **Send-state getter**: flow-table lookup + 5 `u32` loads. Not on any hot path — called by the app on demand, typically once per order or once per forensic checkpoint.
- **Memory**: soft_cap=4096 × ~32 B/event = ~128 KiB per engine worst case. Trivial on a server-class node. `syn_tx_ts_ns` adds 8 bytes per `TcpConn`; `tlp_recent_probes` ring adds 5 × 24 bytes = 120 bytes per `TcpConn`; `tlp_consecutive_probes_fired` + misc TLP flags add ~4 bytes. Total per-conn growth: ~132 bytes — small vs the existing `TcpConn` size.
- **No new atomics on the packet hot path**: the three new counters (`obs.events_dropped`, `obs.events_queue_high_water`, `tcp.tx_tlp_spurious`) live exclusively on the event-emission, SACK-absorb, or DSACK boundaries, not on RX/TX segment handlers.
- **SRTT seed from SYN (§3.5)**: one extra `clock::now_ns()` call at SYN emission (saved to `syn_tx_ts_ns`) and one subtract/bounds-check at SYN-ACK absorption. Both on control-plane paths that run once per connection. Zero hot-path impact.
- **AD-17 RTO walk (§3.6)**: `on_rto_fire` gains a linear scan over `snd_retrans.entries` (bounded by the `tcp_max_window` / `tcp_mss` segment count, typically < 256). The scan fires once per RTO event, not per-packet. Counter-intuitive improvement: the loss-detection cost that A5 amortized across subsequent ACKs (one segment per ACK) is now done once upfront — fewer aggregate CPU cycles across the recovery episode.
- **AD-18 arm-TLP-on-send (§3.7)**: one additional helper call per `dpdk_net_send` invocation. The helper body is 4 boolean checks + (if all pass) one PTO compute + one timer-wheel insert (~20 ns on the existing hashed wheel). Sits on the data-TX path, not the packet-RX path — bounded by application-send rate which is typically orders of magnitude below per-segment rate.

---

## 12. Open items for the plan-writing pass

- **A5 is already shipped** (`phase-a5-complete` tag at `39b01cd`), so all 13 event push sites in `engine.rs` exist and the `rtt_est` / `rack.min_rtt` fields are in place. A5.5 rebases cleanly. Can run in parallel with A-HW since no shared files.
- **Group naming** (`obs` vs folding into `poll`): plan-writing decides and documents. Current recommendation: new `obs` group — clean separation from packet-path counters and room to grow (future `obs.` entries like `poll_idle_ratio` fit naturally).
- **`events_pending` live-depth gauge**: intentionally deferred. If A8 observability audit finds apps want it, add in a follow-up. Not in A5.5 to keep the counter-addition discipline tight (`feedback_counter_policy.md`).
- **Field ordering in `dpdk_net_counters_t`**: new fields appended at end; header-drift check catches any mistaken reorder. No renumbering of existing fields.
- **Companion dummy segment as a literal TX path**: the `tlp_skip_flight_size_gate` flag handles the timing goal by skipping the PTO penalty. If empirical measurement on a target peer shows that FlightSize-1 actually matters on the wire (peer delays ACK regardless of our PTO formula, causing spurious probes even with the skip-gate flag set), a follow-on phase or patch lands a literal keepalive-shaped companion emission: `seq = snd.una - 1`, 1-byte payload (the byte peer already has), ACK expected. Tracked as open; revisit after A5.5 ships and spurious-ratio data from real order-entry traffic is available.
- **Interaction with A6's timer API**: A5.5's TLP multi-probe scheduling reuses A5's internal timer wheel (no public API touch). When A6 adds the public `dpdk_net_timer_add` / `cancel` API, the multi-probe state (`tlp_consecutive_probes_fired`, `tlp_recent_probes`) stays on the wheel's internal slot; no changes needed at A6 time.
- **Self-tuning automation**: the spurious-ratio → floor-raise recipe in §1 item 4 is documented as an application pattern, not implemented by the stack. If experience shows most apps want it auto, a follow-on can add a `tlp_auto_floor: bool` that ramps `tlp_pto_min_floor_us` in response to spurious rate — deliberately not in A5.5 since the policy curve is app-specific.
- **Minimum counter-coverage wiring**: `tcp.tx_tlp_spurious` is the newest TCP counter; `obs.events_dropped` + `obs.events_queue_high_water` are the first entries in the new `obs` group. Plan task 3 wires the counter-coverage-audit entries per `tests/counter-coverage.rs` convention; same commit as the counter addition.
- **AD-17 test-pass retransmit-counter semantics**: confirmed in §7.2.17 that one RTO fire drives multiple retransmits but only one `tcp.tx_rto` increment. Plan task 14 implements the counter bookkeeping to keep the "RTO events" semantic distinct from "segments retransmitted in response".
