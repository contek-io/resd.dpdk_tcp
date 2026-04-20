# Phase A6 — Public API surface completeness + per-conn RTT histogram (Design Spec)

**Status:** draft for plan-writing.
**Parent spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.
**Absorbs:** `docs/superpowers/specs/2026-04-19-stage1-phase-a5-6-rtt-histogram-design.md` (A5.6 is not shipped as a standalone phase; its content is merged here — see §3.8. The locked A5.6 decisions — wraparound `u32×16`, 64 B / one cacheline, runtime-configurable edges — carry through unchanged; the three open items in A5.6 §12 are resolved here in §3.8.2, §3.8.3, §3.8.4).
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` — A6.
**Branch:** `phase-a6` (off `phase-a5-5-complete` tag, worktree at `/home/ubuntu/resd.dpdk_tcp-a6`).
**Ships:** `phase-a6-complete` tag gated on mTCP + RFC review reports.

---

## 1. Scope

A6 finalizes the public C ABI defined in parent spec §4 by implementing the surface pieces that A3–A5.5 had deferred. A6 is strictly surface + observability work layered on top of the existing wire behavior; no new RFC deviations are introduced, no new hot-path counters, no peer-visible behavior change beyond those already documented for the listed features.

In scope:

- **Public timer API** — `resd_net_timer_add(deadline_ns, user_data, *timer_id_out) → i32`, `resd_net_timer_cancel(timer_id) → i32`, new event `RESD_NET_EVT_TIMER {timer_id, user_data}` layered on A5's internal hashed timing wheel (parent spec §7.4). The wheel already reserves `TimerKind::ApiPublic`; A6 populates the fire path and the public-API plumbing.
- **Send-buffer backpressure event** — `RESD_NET_EVT_WRITABLE` emitted once per prior-refusal cycle when in-flight drains to ≤ `send_buffer_bytes / 2`.
- **TX-batched `resd_net_flush`** — engine-scope TX ring holds outbound data-segment mbufs; `resd_net_flush` drains the ring via exactly one `rte_eth_tx_burst`. Control frames (ACK / SYN / FIN / RST) remain emitted inline and do not participate in the ring. This is the (c) option chosen during brainstorm: latency-optimal for the data path, no ACK latency inversion. Parent spec §4.2 clarified in §10.2 of this doc to reflect the split.
- **`resd_net_close(flags)` with `FORCE_TW_SKIP`** — honored only when the closing connection negotiated timestamps (RFC 6191 / RFC 7323 §5 prerequisite for PAWS to protect 4-tuple reuse on the client side); otherwise the flag is ignored and a `RESD_NET_EVT_ERROR{err=-EPERM}` event is emitted (parent spec §9.3 lists this as the documented "EPERM_TW_REQUIRED" condition — we reuse `-EPERM` as the errno since no dedicated `EPERM_TW_REQUIRED` exists in `libc`; the contextual meaning is documented in the cbindgen header's `resd_net_close` doc-comment).
- **Engine event-queue FIFO overflow contract** — A5.5 already wired the soft-cap drop-oldest semantics + `obs.events_dropped` / `obs.events_queue_high_water` counters (parent spec §4.2). A6 finalizes the contract documentation (§10.2 here) and verifies it end-to-end via a Layer B integration test.
- **Mempool exhaustion → `RESD_NET_EVT_ERROR{err=-ENOMEM}`** — per-occurrence for internal retransmit ENOMEM; edge-triggered per poll iteration for RX mempool drops (one event per poll iteration where `eth.rx_drop_nomem` advanced). `resd_net_send` already returns `-ENOMEM` synchronously on TX-data-mempool exhaustion and stays unchanged.
- **`preset=rfc_compliance`** — new `resd_net_engine_config_t::preset` value `1` forces `tcp_nagle=true`, `tcp_delayed_ack=true`, `cc_mode=1` (Reno), `tcp_min_rto_us=200_000`, `tcp_initial_rto_us=1_000_000`. Other A5+ fields pass through. Applied post-zero-sentinel-substitution inside `resd_net_engine_create`. `preset >= 2` rejected with null-return.
- **RFC 7323 §5.5 24-day `TS.Recent` expiration** — lazy-at-PAWS implementation: the PAWS gate in `tcp_input.rs` computes `idle_ns = now - ts_recent_age` and if `> 24 days` treats `TS.Recent` as absent for this segment, adopting `seg_tsval` as the new `TS.Recent` unconditionally and resetting the age clock. Zero new timer overhead; no dependency on the public timer API (brainstorm Q1). Bumps new slow-path counter `tcp.ts_recent_expired` once per expiration event.
- **Per-connection RTT histogram (absorbed from A5.6)** — 16 × `u32` log-spaced buckets on `TcpConn`, exactly 64 B / one cacheline, runtime-configurable edges via `resd_net_engine_config_t::rtt_histogram_bucket_edges_us[15]`, wraparound via `wrapping_add` with app-side `wrapping_sub` on delta. New `resd_net_tcp_rtt_histogram_t { uint32_t bucket[16] }` POD. New extern "C" `resd_net_conn_rtt_histogram(engine, conn, *out) → i32`.
- **Knob-coverage audit entries** for the three new behavioral knobs: `preset=rfc_compliance`, `resd_net_close` flag `FORCE_TW_SKIP`, `rtt_histogram_bucket_edges_us`. Sibling `tests/per-conn-histogram-coverage.rs` file for the histogram's per-conn coverage (engine-wide audit doesn't reach per-conn state).
- **Opportunistic A5.5 followup nits** — correct the citations "RFC 6298 §3.3" → §2.2 + §3 (Karn's) and "RFC 8985 §7.4 (RTT-sample gate)" → §7.3 step 2 in text being touched for A6 spec updates.

Out of scope:

- Test-suite harnesses (packetdrill shim, tcpreq, TCP-Fuzz, smoltcp FaultInjector — A7 / A8 / A9).
- Benchmarks (A10).
- Per-sample `RESD_NET_EVT_RTT_SAMPLE` events or raw-samples ring — deferred indefinitely; histogram covers the stated observability need.
- Engine-wide RTT histogram summary (sum across conns) — deferred per A5.6 §12; apps sum across `resd_net_conn_rtt_histogram` snapshots on demand.
- Mid-session bucket-edge changes — edges fixed at `engine_create`.
- Any wire-behavior change beyond the WRITABLE / FORCE_TW_SKIP / preset items listed above.
- A-HW offload territory — offload bits, port config, feature flags. A6 and A-HW touch `engine.rs` / `api.rs` / `include/resd_net.h` but in disjoint regions (see parent plan's coordination note); rebase cadence covers overlap.
- ABI-breaking changes to existing surfaces; additions only.

---

## 2. Module layout

### 2.1 Modified modules (`crates/resd-net-core/src/`)

| Module | Change |
|---|---|
| `engine.rs` | Engine-scope `tx_pending_data: RefCell<Vec<NonNull<rte_mbuf>>>` (cap `tx_ring_size`, default 1024); new `drain_tx_pending_data(&self)` helper called from `poll_once` at end + from `resd_net_flush`. `advance_timer_wheel` `ApiPublic` branch emits `InternalEvent::ApiTimer`. New `public_timer_add(deadline_ns, user_data) -> TimerId` and `public_timer_cancel(TimerId) -> bool` methods. `rx_drop_nomem_prev: Cell<u64>` snapshot (interior mutability — `poll_once` borrows `&self` like every other engine method); `poll_once` emits one RX-ENOMEM `InternalEvent::Error` when `rx_drop_nomem` advances across an iteration. `Engine::new` applies `preset=1` after existing zero-sentinel substitution. `Engine::new` validates `cfg.rtt_histogram_bucket_edges_us` (strictly monotonic or all-zero) and stores `rtt_histogram_edges: [u32; 15]`. `close_conn` reads `flags` and, when `FORCE_TW_SKIP` is set without `ts_enabled`, emits `Error{err=-EPERM}` and drops the flag; when `ts_enabled`, sets `c.force_tw_skip = true`. `reap_time_wait` short-circuits the 2×MSL wait for any conn with `force_tw_skip == true`. |
| `tcp_timer_wheel.rs` | `TimerNode` gains `user_data: u64` (zero for kernel timers RTO / TLP / SynRetrans; populated for `ApiPublic`). 8 extra bytes per node; timer-wheel `slots` cost grows by 8 B × slot-capacity (~8 KB at 1024-slot initial capacity — negligible). |
| `tcp_events.rs` | New `InternalEvent::ApiTimer { timer_id: TimerId, user_data: u64, emitted_ts_ns: u64 }`. New `InternalEvent::Writable { conn: ConnHandle, emitted_ts_ns: u64 }`. Existing `EventQueue` `push` / drop-oldest semantics unchanged. |
| `tcp_conn.rs` | Fields: `send_refused_pending: bool` (default false), `force_tw_skip: bool` (default false), `rtt_histogram: RttHistogram` (new aligned sub-struct — see §2.3). New method `rtt_histogram_update(&mut self, rtt_us: u32, edges: &[u32; 15])` — 15-comparison bucket-selection ladder + `wrapping_add(1)`. New helper `rtt_histogram_snapshot(&self) -> [u32; 16]` — memcpy out of the aligned buckets array for the getter. |
| `tcp_input.rs` | **PAWS lazy expiration:** before `SEG.TSval < TS.Recent` check, compute `idle_ns = now_ns - ts_recent_age`; if `> 24 * 86_400 * 1_000_000_000`, accept `seg_tsval` unconditionally, reset `ts_recent_age = now_ns`, bump `tcp.ts_recent_expired`. **RTT histogram hook:** after the existing `rtt_est.sample(rtt_us)` call, call `conn.rtt_histogram_update(rtt_us, &engine.rtt_histogram_edges)`. Cost: one ladder + one `wrapping_add` on cache-resident state, ≈5–10 ns. **WRITABLE hysteresis:** after `snd_una` advances (ACK prune path already exists), if `c.send_refused_pending && in_flight(c) <= send_buffer_bytes / 2`, emit `InternalEvent::Writable`, clear the bit. |
| `tcp_output.rs` (and related emit sites in `engine.rs`) | `send_bytes`' per-segment TX changes from inline `rte_eth_tx_burst(.., 1)` to push into `tx_pending_data`; on push failure (ring full) fall back to inline `tx_burst` for that mbuf so correctness is preserved under adversarial sizing. `retransmit`'s chained mbuf push follows the same pattern. Control frames (ACK in `emit_ack` / FIN in `close_conn` / SYN in `send_syn` / RST in `reply_rst`) stay inline — separate code path, no change. |
| `counters.rs` | Four new slow-path `AtomicU64` fields: `tcp.tx_api_timers_fired`, `tcp.ts_recent_expired`, `tcp.tx_flush_bursts`, `tcp.tx_flush_batched_pkts`. All fire on boundaries that are already per-boundary (not per-segment / per-burst / per-poll), so they satisfy §9.1.1 rule 1 (slow-path only). No feature gates. |
| `error.rs` | No changes (ENOMEM emission uses existing `InternalEvent::Error` variant). |

### 2.2 Modified modules (`crates/resd-net/src/`)

| Module | Change |
|---|---|
| `api.rs` | New POD `resd_net_tcp_rtt_histogram_t { uint32_t bucket[16] }` (64 B, one cacheline, `#[repr(C)]`). New config field `resd_net_engine_config_t::rtt_histogram_bucket_edges_us: [u32; 15]` (appended). `resd_net_timer_id_t` (existing `u64` alias) contract documented: packed `(slot << 32) \| generation`. No change to existing public types' layout beyond the appended `rtt_histogram_bucket_edges_us` field. |
| `lib.rs` | Implementations: `resd_net_timer_add` (null checks → `engine.public_timer_add` → pack `TimerId` to `u64` → `*timer_id_out`); `resd_net_timer_cancel` (null check → `engine.public_timer_cancel` → `0` or `-ENOENT`); `resd_net_conn_rtt_histogram` (null checks → flow-table lookup → `std::ptr::write` the 16 bucket copies into the caller's out struct); `resd_net_flush` (already a no-op shell — replace body with `engine.drain_tx_pending_data()`); `resd_net_close` (extend to read the `flags` param, call `engine.close_conn_with_flags(handle, flags)`, map errors). `resd_net_engine_create` adds the preset application + histogram-edges validation + plumbs the edges into `EngineConfig`. `build_event_from_internal` handles the two new variants (`ApiTimer`, `Writable`). |
| `include/resd_net.h` (cbindgen-regenerated) | New struct `resd_net_tcp_rtt_histogram_t`. New extern "C" functions `resd_net_timer_add`, `resd_net_timer_cancel`, `resd_net_conn_rtt_histogram`. New config field `rtt_histogram_bucket_edges_us`. Updated doc-comments on `resd_net_flush` (explicit data-only drain semantics), `resd_net_close` (flag + error-code contract). |

### 2.3 New types

```rust
#[repr(C, align(64))]
pub struct RttHistogram {
    pub buckets: [u32; 16],
}

// compile-time verified in tcp_conn.rs
const _: () = {
    use std::mem::{align_of, size_of};
    assert!(size_of::<RttHistogram>() == 64);
    assert!(align_of::<RttHistogram>() == 64);
};
```

A `repr(C, align(64))` single-cacheline newtype guarantees the 16 × `u32` buckets live on exactly one cacheline regardless of the surrounding `TcpConn` layout. The snapshot getter returns a `[u32; 16]` memcpy (no pointer aliasing into the internal field — the caller's `resd_net_tcp_rtt_histogram_t` owns its own 64 B).

### 2.4 Dependencies introduced

None. No new crate dependencies, no new DPDK offload bits, no new wire-format elements.

---

## 3. Data flow per feature

### 3.1 Public timer API

**Add.** Caller passes `deadline_ns` in the engine monotonic-clock domain (`resd_net_now_ns`) and an opaque `user_data: u64`. The engine rounds `deadline_ns` up to the next 10 µs wheel tick boundary (the wheel's native resolution, parent spec §7.4); deadlines already in the past fire on the next `poll_once`. Internally:

```rust
pub fn public_timer_add(&self, deadline_ns: u64, user_data: u64) -> TimerId {
    let now_ns = clock::now_ns();
    let fire_at_ns = align_up_to_tick(deadline_ns);
    self.timer_wheel.borrow_mut().add(
        now_ns,
        TimerNode {
            fire_at_ns,
            owner_handle: 0,  // unused for ApiPublic
            kind: TimerKind::ApiPublic,
            user_data,
            generation: 0,
            cancelled: false,
        },
    )
}
```

The `TimerId` (slot:u32 + generation:u32) is packed into a `u64` at the ABI layer: `(slot as u64) << 32 | (generation as u64)`. Unpacking is the inverse. The packing is documented in the cbindgen header's `resd_net_timer_add` doc-comment so apps treat `resd_net_timer_id_t` as opaque but know the upper 32 bits change on slot reuse.

**Cancel.** The wheel's `cancel()` returns `true` iff a live, matching-generation node was tombstoned. The public API returns `0` when `cancel() == true`, `-ENOENT` otherwise. The `-EALREADY` spec-level distinction (timer fired, event queued, not yet drained) is collapsed into `-ENOENT` because:

1. The TIMER event sitting in the engine event queue is authoritative — the caller must drain it regardless of what `cancel()` returned.
2. Distinguishing "fired-but-not-drained" from "never existed" would require a separate per-engine `HashSet<TimerId>` tracking every `ApiPublic` fire pending drain, bumped on fire and removed on drain. Cost is hash lookups on a slow-path but the value to the app is nil — apps that have the timer_id in hand always drain and always observe any TIMER event it produces.
3. Collapsing preserves the contract documented in the header: "TIMER events must always be drained; cancel's return is advisory."

This differs from parent spec §4 literal wording (three return codes). The spec is updated at §10.2 to reflect the collapse.

**Fire.** When `advance_timer_wheel` pops a `TimerKind::ApiPublic` node from the wheel, it pushes `InternalEvent::ApiTimer { timer_id, user_data, emitted_ts_ns: now_ns }` onto the event queue. The `timer_id` re-packs the wheel's `TimerId` back to the caller's `u64`. `conn: 0` is used at the ABI-layer translation (public timers aren't bound to a connection); `rx_hw_ts_ns: 0`; `enqueued_ts_ns: now_ns` at fire (same convention as RTO-fire per A5.5 §3.1 — sampling at emission, not at drain).

Counter: `tcp.tx_api_timers_fired` increments once per fire (slow-path; fires on timer-deadline events, not per segment).

### 3.2 TX ring + `resd_net_flush`

The engine gains a single-engine TX ring for data segments only:

```rust
pub(crate) tx_pending_data: RefCell<Vec<NonNull<rte_mbuf>>>,  // cap = tx_ring_size
```

Capacity is `EngineConfig::tx_ring_size` (default 1024). At `poll_once`'s end (after RX processing + timer-wheel advance + TIME_WAIT reap), `drain_tx_pending_data` is called. `resd_net_flush` calls the same helper. Drain:

```rust
fn drain_tx_pending_data(&self) {
    let mut ring = self.tx_pending_data.borrow_mut();
    if ring.is_empty() { return; }
    let n_to_send = ring.len() as u16;
    let sent = unsafe { sys::resd_rte_eth_tx_burst(
        self.cfg.port_id,
        self.cfg.tx_queue_id,
        ring.as_mut_ptr() as *mut *mut rte_mbuf,
        n_to_send,
    ) } as usize;
    // Freed tail — unsent mbufs (from tx_burst partial fill) are not the engine's
    // problem to retry; they return to mempool via rte_pktmbuf_free since retransmit
    // owns the refcnt.
    for i in sent..ring.len() {
        unsafe { sys::resd_rte_pktmbuf_free(ring[i].as_ptr()); }
        counters::inc(&self.counters.eth.tx_drop_full_ring);
    }
    ring.clear();
    counters::inc(&self.counters.tcp.tx_flush_bursts);
    counters::add(&self.counters.tcp.tx_flush_batched_pkts, sent as u64);
}
```

**Push.** `send_bytes`' per-segment path was previously `rte_eth_tx_burst(.., ., 1)` inline. The new path tries to push onto `tx_pending_data`:

```rust
// After mbuf alloc + copy + refcnt bump:
if ring.len() < ring.capacity() {
    ring.push(NonNull::new(m).unwrap());
} else {
    // Ring full — drain it immediately and retry the push. This fall-back
    // guarantees no send_bytes call stalls on a full ring even in a
    // single-poll burst that exceeds tx_ring_size.
    drop(ring);  // release borrow
    self.drain_tx_pending_data();
    self.tx_pending_data.borrow_mut().push(NonNull::new(m).unwrap());
}
```

**Control frames unchanged.** `emit_ack`, `send_syn`, `reply_rst`, and `close_conn`'s FIN builder call `tx_frame` / direct `tx_burst(1)` inline. Rationale (brainstorm Q2 option c): control frames are rare + latency-critical + carry no payload coalescing benefit; they should not queue behind a pending data burst. This preserves ACK-emission latency for the existing per-poll coalesce (single ACK per conn per poll iteration). The cbindgen doc-comment on `resd_net_flush` documents the split explicitly:

> Drains the pending data-segment TX batch via one `rte_eth_tx_burst`. Control frames (ACK, SYN, FIN, RST) are emitted inline at their emit site and do not participate in the flush batch — flushing never blocks or reorders control-frame emission.

Counters: `tcp.tx_flush_bursts` (how many `tx_burst` calls the flush/drain path made), `tcp.tx_flush_batched_pkts` (aggregate successful packets across those calls). Both slow-path (per-poll, not per-segment).

### 3.3 `RESD_NET_EVT_WRITABLE` hysteresis

Per-conn state:

```rust
pub struct TcpConn {
    // ... existing fields ...
    /// True iff a prior `send_bytes` call on this conn accepted < len
    /// AND a WRITABLE event has not yet been emitted for that cycle.
    /// Cleared when the hysteresis threshold fires.
    pub send_refused_pending: bool,
}
```

`send_bytes` sets `send_refused_pending = true` whenever `accepted < bytes.len()`. The ACK-prune path in `tcp_input.rs` (where `snd_una` advances) runs this check after the prune:

```rust
if c.send_refused_pending {
    let in_flight = c.snd_nxt.wrapping_sub(c.snd_una);
    if (in_flight as usize) <= (self.cfg.send_buffer_bytes / 2) as usize {
        events.push(InternalEvent::Writable {
            conn: handle,
            emitted_ts_ns: now_ns,
        }, &self.counters);
        c.send_refused_pending = false;
    }
}
```

Level-triggered, single-edge-per-refusal-cycle. Subsequent refused sends re-arm the cycle. The threshold is a fixed `send_buffer_bytes / 2` (spec §4.2 literal). `ABI-layer translation produces `RESD_NET_EVT_WRITABLE` with no payload (`_pad: [0u8; 16]`).

### 3.4 `resd_net_close(FORCE_TW_SKIP)`

At `resd_net_close` entry:

```rust
pub fn close_conn_with_flags(&self, handle: ConnHandle, flags: u32) -> Result<(), Error> {
    let force_tw_skip = (flags & RESD_NET_CLOSE_FORCE_TW_SKIP) != 0;

    if force_tw_skip {
        let ts_enabled = {
            let ft = self.flow_table.borrow();
            ft.get(handle).map(|c| c.ts_enabled).unwrap_or(false)
        };
        if !ts_enabled {
            // Prerequisite not met — flag dropped, Error event emitted,
            // normal FIN proceeds.
            let mut ev = self.events.borrow_mut();
            ev.push(InternalEvent::Error {
                conn: handle,
                err: -libc::EPERM,
                emitted_ts_ns: clock::now_ns(),
            }, &self.counters);
        } else {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.force_tw_skip = true;
            }
        }
    }

    self.close_conn(handle)  // existing FIN builder + state transition
}
```

The existing `reap_time_wait` path walks TIME_WAIT conns and closes them when `now >= time_wait_deadline_ns`. A6 extends the predicate: a conn in `TimeWait` with `force_tw_skip == true` is closed immediately regardless of `time_wait_deadline_ns`. The close emits `StateChange{TimeWait → Closed}` + `Closed{err=0}` exactly as the normal reap path does — observability parity is preserved.

**Why this is RFC-6191-safe on a client-only stack.** RFC 6191 / RFC 1122 §4.2.2.13 target server-side inbound-SYN-in-TIME-WAIT semantics; Stage 1 is client-only (no LISTEN). The threat we're guarding against is an old duplicate segment from the just-closed connection being accepted by the peer's side of a new incarnation on the same 4-tuple. Two mitigations are already in place and gate `FORCE_TW_SKIP`:

1. `c.ts_enabled == true` — PAWS (RFC 7323 §5) on the peer's receiver rejects old-incarnation segments whose TSval is older than the new incarnation's TS.Recent, as long as both incarnations use timestamps.
2. Monotonic ISS (RFC 6528 § `ISS = TSC_low32 + SipHash(4-tuple || secret || boot_nonce)`, parent spec §6.5) guarantees the new incarnation's ISS is strictly greater than anything the old incarnation used on the wire, so sequence-number overlap is also avoided.

The combination is sufficient for a client-only stack. No explicit timestamp preservation across the close is needed on our side — the peer's TS.Recent does the PAWS work.

### 3.5 `preset=rfc_compliance`

`resd_net_engine_create` already does zero-sentinel substitution for `max_connections`, `recv_buffer_bytes`, `send_buffer_bytes`, `tcp_mss`, `tcp_min_rto_us`, `tcp_initial_rto_us`, `tcp_max_rto_us`, `tcp_max_retrans_count`, `tcp_msl_ms`. A6 adds a post-substitution preset pass:

```rust
match cfg.preset {
    0 => { /* latency — leave all substituted fields as-written */ }
    1 => {
        // rfc_compliance: five-knob override per parent spec §4.
        core_cfg.tcp_nagle = true;
        core_cfg.tcp_delayed_ack = true;
        core_cfg.cc_mode = 1;  // Reno
        core_cfg.tcp_min_rto_us = 200_000;
        core_cfg.tcp_initial_rto_us = 1_000_000;
    }
    _ => return ptr::null_mut(),
}
```

Other A5+ fields (`tcp_max_rto_us`, `tcp_max_retrans_count`, `tcp_msl_ms`, `tcp_per_packet_events`, `event_queue_soft_cap`) pass through. Applied after the zero-sentinel pass so explicit caller values are overwritten by the preset (the preset is stronger than "default" — it's an opt-in to RFC-compliant behavior overriding the latency defaults).

### 3.6 `RESD_NET_EVT_ERROR{err=-ENOMEM}` emission policy

Three emission sites:

**Site 1 — `send_bytes` return.** Already existing: `SendBufferFull → -ENOMEM`. Caller has the return code; no separate event.

**Site 2 — internal retransmit.** `retransmit()` allocates a fresh header mbuf from `tx_hdr_mempool` on each retry. If the alloc fails (`m.is_null()`), emit one `InternalEvent::Error { conn: handle, err: -libc::ENOMEM, emitted_ts_ns: now_ns }` per occurrence. Fires only under real mempool starvation, already a bug indicator (slow-path by construction).

**Site 3 — RX mempool drops.** Edge-triggered per poll iteration. At the top of `poll_once`, snapshot `self.rx_drop_nomem_prev = counters.eth.rx_drop_nomem.load(Relaxed)`. At the bottom (after drain_tx_pending_data), compare with the current value:

```rust
let rx_drop_nomem_now = counters.eth.rx_drop_nomem.load(Ordering::Relaxed);
if rx_drop_nomem_now > self.rx_drop_nomem_prev.get() {
    events.push(InternalEvent::Error {
        conn: 0,  // engine-level, no connection
        err: -libc::ENOMEM,
        emitted_ts_ns: clock::now_ns(),
    }, &counters);
    self.rx_drop_nomem_prev.set(rx_drop_nomem_now);
}
```

At most one RX-ENOMEM event per poll iteration, even if hundreds of mbufs dropped. Prevents event-queue flood under RX mempool starvation (which is the exact moment when the app is least able to keep up). Apps still see the counter climb if they want per-drop detail.

### 3.7 RFC 7323 §5.5 24-day `TS.Recent` lazy expiration

At the PAWS gate in `tcp_input.rs`, before `SEG.TSval < TS.Recent`:

```rust
const TS_RECENT_EXPIRY_NS: u64 = 24 * 86_400 * 1_000_000_000;  // 24 days in ns

let now_ns = clock::now_ns();
let idle_ns = now_ns.saturating_sub(c.ts_recent_age);
let paws_skip = if c.ts_recent_age != 0 && idle_ns > TS_RECENT_EXPIRY_NS {
    counters::inc(&self.counters.tcp.ts_recent_expired);
    c.ts_recent = seg_tsval;
    c.ts_recent_age = now_ns;
    true  // bypass PAWS for this segment
} else {
    false
};
if !paws_skip {
    // existing PAWS check
    if seg_tsval < c.ts_recent { /* drop + counter */ return; }
}
```

`ts_recent_age == 0` is the "never-touched" sentinel (fresh conn pre-first-TS-segment), which we do NOT treat as expired — existing behavior. The expiry only bites on a connection that had a `TS.Recent` populated then went idle >24d. Zero extra timer overhead. Zero hot-path cost on fresh connections. RFC-7323-§5.5-equivalent outcome: the first segment after 24d idle re-seeds `TS.Recent` instead of being rejected by PAWS.

Counter: `tcp.ts_recent_expired` (slow-path — fires at most once per 24-day-plus idle event, essentially never on healthy traffic; nonzero is operationally interesting).

### 3.8 Per-connection RTT histogram (absorbed from A5.6)

#### 3.8.1 Bucket selection + update

```rust
fn select_bucket(rtt_us: u32, edges: &[u32; 15]) -> usize {
    for i in 0..15 {
        if rtt_us <= edges[i] { return i; }
    }
    15   // catch-all for rtt_us > edges[14]
}

impl TcpConn {
    pub fn rtt_histogram_update(&mut self, rtt_us: u32, edges: &[u32; 15]) {
        let b = select_bucket(rtt_us, edges);
        self.rtt_histogram.buckets[b] =
            self.rtt_histogram.buckets[b].wrapping_add(1);
    }
}
```

Call site: inside `tcp_input.rs`'s RTT-sample path, immediately after `rtt_est.sample(rtt_us)` bumps `tcp.rtt_samples`. Cost: 15-comparison ladder + one `wrapping_add` on cache-resident state, ≈5–10 ns. No atomic (per-conn state; single-lcore RTC model).

#### 3.8.2 Default bucket edges

Locked from A5.6 spec §3.2 — keep as-is:

```
edges = { 50, 100, 200, 300, 500, 750,
        1000, 2000, 3000, 5000, 10000, 25000,
       50000, 100000, 500000 }  // µs
```

→ 16 buckets: `[0,50], (50,100], (100,200], (200,300], (300,500], (500,750], (750,1000], (1000,2000], (2000,3000], (3000,5000], (5000,10000], (10000,25000], (25000,50000], (50000,100000], (100000,500000], (500000,∞)`.

Dense in the 50 µs – 1 ms range (colo / same-region hot path), medium in 1–50 ms (same-region under load / cross-region), coarse >50 ms (pathological). Tune post-A10 if workload measurements warrant — it's a trivial default change, not an ABI change.

#### 3.8.3 Cacheline placement (A5.6 §12 resolution)

Wrap the buckets in an aligned sub-struct (see §2.3). This puts the 16 × `u32` array on its own cacheline regardless of the surrounding `TcpConn` layout. Compile-time asserts pin size=64, align=64. No change to apply if a future `TcpConn` refactor moves fields — the sub-struct's alignment is self-contained.

#### 3.8.4 Engine-wide summary (A5.6 §12 resolution)

Deferred. Apps that want engine-wide RTT distribution can sum per-conn snapshots at their own cadence:

```c
for (handle in live_conns) {
    resd_net_tcp_rtt_histogram_t h;
    resd_net_conn_rtt_histogram(engine, handle, &h);
    for (int i = 0; i < 16; ++i) agg[i] += h.bucket[i];
}
```

O(conns) per aggregation. At Stage 1 scale (≤100 conns per roadmap §1) this is 6.4 KB of reads and a 1600-op loop — sub-µs. Adding a dedicated `resd_net_engine_rtt_histogram` would require walking the flow table on each call (same cost as the above loop) plus the summing, so the user-space-does-it path is strictly cheaper for the engine and avoids adding machinery for a use case that doesn't have a concrete consumer yet.

#### 3.8.5 Wraparound contract (A5.6 locked)

```c
/// Per-connection RTT histogram. Each bucket counts RTT samples whose value
/// is <= the corresponding edge in rtt_histogram_bucket_edges_us[] (bucket 15
/// is the catch-all for values greater than the last edge).
///
/// Counters are per-connection lifetime and are u32. Wraparound is expected
/// on long-running connections at high sample rates; the application takes
/// deltas across two snapshots using unsigned wraparound subtraction:
///
///     uint32_t delta = (snap_t2.bucket[i] - snap_t1.bucket[i]);  // wraps correctly
///
/// Correctness caveat: works as long as NO SINGLE BUCKET accumulates more
/// than 2^32 samples between consecutive polls. At 1M samples/sec that's a
/// ~71-minute window; realistic order-entry sample rates (1k–10k samples per
/// connection per second) give > 50 days of headroom. Applications that poll
/// once per minute or finer cannot hit this limit.
///
/// The counter is NOT atomic from the application's perspective: readers
/// observe a consistent-enough 64-byte snapshot for histogram-delta math on
/// x86_64 (single-lcore engine model; the application reads from the same
/// thread that writes). Do not read from a different thread than the
/// engine's poll thread.
typedef struct resd_net_tcp_rtt_histogram {
    uint32_t bucket[16];
} resd_net_tcp_rtt_histogram_t;
```

Emitted verbatim to the cbindgen header as the doc-comment on the POD struct.

---

## 4. Counter surface

Four new slow-path `AtomicU64` fields, all per §9.1.1 rule 1:

| Field | Group | Fire boundary |
|---|---|---|
| `tcp.tx_api_timers_fired` | tcp | once per `ApiPublic` wheel fire |
| `tcp.ts_recent_expired` | tcp | once per RFC-7323-§5.5 24-day idle expiration event |
| `tcp.tx_flush_bursts` | tcp | once per `drain_tx_pending_data` call (per-poll + per-flush) |
| `tcp.tx_flush_batched_pkts` | tcp | once per drain (single `fetch_add` of the aggregate `sent` count) |

None extend `resd_net_counters_t`'s alignment / padding in a way that risks layout change — all land in the existing `tcp` cacheline block's `_pad` slots (the current `resd_net_tcp_counters_t` ends with `_pad: [u64; 1]` per the A5.5-era layout; A6 consumes the pad slot and adjusts as needed, with compile-time size/align asserts pinning the C-ABI invariant).

No new hot-path counters. No new feature gates.

**Observability-only events (not counters):** `ApiTimer`, `Writable` on `InternalEvent`; `RESD_NET_EVT_TIMER`, `RESD_NET_EVT_WRITABLE` at the ABI boundary. The TIMER event was already declared in the C header (layout reserved); A6 just populates it. WRITABLE was already declared as an enum variant; A6 adds the emit sites.

Counter-coverage audit (`tests/counter_coverage.rs` or its successor): the four new fields must each be reached by a scenario (trivially satisfied — all fire on the feature's happy path). A8 will enforce.

---

## 5. Config / API surface changes

### 5.1 `resd_net_engine_config_t` additions

| Field | Type | Default | Notes |
|---|---|---|---|
| `rtt_histogram_bucket_edges_us` | `uint32_t[15]` | all-zeros → stack applies §3.8.2 defaults | Strictly monotonically increasing edges define 16 buckets. Non-monotonic rejected at `engine_create` with null-return. |

Existing `preset: u8` is re-used (value `1` = `rfc_compliance`, per spec §4; A6 finally honors the field). `preset >= 2` rejected with null-return.

### 5.2 New POD struct

```c
typedef struct resd_net_tcp_rtt_histogram {
    uint32_t bucket[16];    // exactly 64 B / one cacheline
} resd_net_tcp_rtt_histogram_t;
```

### 5.3 New extern "C" functions

```c
/* Schedule a one-shot timer. `deadline_ns` is in the engine's monotonic
 * clock domain (resd_net_now_ns). Rounded up to the next 10 µs wheel tick;
 * past deadlines fire on the next poll. On fire, emits RESD_NET_EVT_TIMER
 * with the returned timer_id and the caller-supplied user_data echoed back.
 * Returns 0 on success and fills *timer_id_out; -EINVAL on null engine/out. */
int32_t resd_net_timer_add(
    resd_net_engine *engine,
    uint64_t deadline_ns,
    uint64_t user_data,
    uint64_t *timer_id_out);

/* Cancel a previously-added timer. Returns 0 if cancelled before fire,
 * -ENOENT if the timer was not found (collapses: never-existed /
 * already-fired-and-drained / already-fired-queued-but-not-drained).
 * Callers must always drain any queued TIMER events regardless of
 * this return. */
int32_t resd_net_timer_cancel(
    resd_net_engine *engine,
    uint64_t timer_id);

/* Per-connection RTT histogram snapshot. Slow-path; safe per-order for
 * forensics tagging, safe per-minute for session-health polling. Do not
 * call in a per-segment loop.
 *
 * Returns 0 on success (out populated with 64 bytes); -EINVAL on null
 * engine/out; -ENOENT if conn is not a live handle. */
int32_t resd_net_conn_rtt_histogram(
    resd_net_engine *engine,
    resd_net_conn_t conn,
    resd_net_tcp_rtt_histogram_t *out);
```

### 5.4 Behavior-change on existing functions

| Function | Pre-A6 | Post-A6 |
|---|---|---|
| `resd_net_flush` | No-op (A1 stub; A3 kept stubbed) | Drains the pending data-segment TX ring via one `rte_eth_tx_burst`. No-op when ring empty. Idempotent. |
| `resd_net_close` | `flags` ignored | Honors `RESD_NET_CLOSE_FORCE_TW_SKIP` per §3.4. `flags` still silently discarded for bits other than the defined `FORCE_TW_SKIP`; undefined bits reserved for future extension. |
| `resd_net_engine_create` | `cfg.preset` ignored | Applies `preset=1` per §3.5; rejects `preset >= 2` with null-return. Validates `cfg.rtt_histogram_bucket_edges_us` monotonicity. |

---

## 6. Accepted divergences

None beyond what A5 / A5.5 already carry. A6 is surface + observability on top of existing wire behavior; the FORCE_TW_SKIP flag with ts-enabled prerequisite is a spec-literal interpretation of parent spec §6.5 (not a new deviation), and the EALREADY→ENOENT collapse on `timer_cancel` is a practical simplification that strict spec text permits (the spec phrasing is a SHOULD-level suggestion; the drain-always contract is preserved). Neither warrants an AD-tag row in parent spec §6.4.

No new hot-path counters, no wire-format changes, no RFC MUST divergences.

---

## 7. Test plan

### 7.1 Layer A — unit tests

**Timer API:**
- `timer_id` packing round-trip: `pack(slot=0, gen=0) == 0`; `pack(slot=0xAABBCCDD, gen=0x11223344)` unpacks cleanly.
- `align_up_to_tick(0) == 0`; `align_up_to_tick(1) == 10_000`; `align_up_to_tick(10_000) == 10_000`; `align_up_to_tick(10_001) == 20_000`.
- Wheel fire of an `ApiPublic` node produces `InternalEvent::ApiTimer` with the right `user_data`.
- Cancel tombstone + stale-generation no-op (wheel unit tests already cover; add one for `ApiPublic` kind).

**Histogram:**
- `select_bucket` across default edges: `{ 10, 50, 75, 150, 1000, 2000, 30000, 600000 }` → `{ 0, 0, 1, 2, 6, 7, 12, 15 }`. (Under `DEFAULT_RTT_HISTOGRAM_EDGES_US`, `edges[11]=25000 < 30000 ≤ edges[12]=50000` puts 30000 µs in bucket 12, not 11.)
- `rtt_histogram_update` called 2³² + 5 times with the same RTT returns bucket value = 5 (wraparound).
- Monotonic-edges validation at `engine_create`: `[100, 200, 150, ...]` → null-return; `[100, 200, 300, ...]` accepted; all-zero accepted (defaults).
- `size_of::<RttHistogram>() == 64`, `align_of::<RttHistogram>() == 64`.

**Preset:**
- `preset=0` post-create: the five §3.5 fields match caller-supplied values.
- `preset=1` post-create: fields overridden to the RFC-compliance set.
- `preset=2` → null-return.

**Close flag:**
- `resd_net_close(handle, RESD_NET_CLOSE_FORCE_TW_SKIP)` on an ESTABLISHED conn with `ts_enabled=false` emits `Error{err=-EPERM}`; `force_tw_skip` unset.
- Same call with `ts_enabled=true` sets `c.force_tw_skip = true`; no Error emitted.

**ENOMEM events:**
- `rx_drop_nomem_prev` snapshot + edge-detect logic: multiple drops within one poll → at most one Error event pushed.
- Retransmit ENOMEM: mock `rte_pktmbuf_alloc` to return null → Error emitted per call.

**TS.Recent lazy expiration:**
- Mock clock advance of 25 days between two TS-carrying segments: second segment's seg_tsval unconditionally adopted; `ts_recent_expired` incremented; PAWS check skipped for that one segment.

### 7.2 Layer B — integration (TAP pair, `tests/`)

Land under `crates/resd-net-core/tests/tcp_a6_public_api_tap.rs`:

1. **Timer add/fire/drain:** `timer_add(now+5ms, user_data=0xABCD1234_5678_BEEF)` → poll loop → `RESD_NET_EVT_TIMER` delivered with matching `timer_id` + `user_data`; `enqueued_ts_ns` within ±1 tick (10 µs) of fire instant.
2. **Timer cancel-before-fire:** `cancel` returns `0`; no TIMER event delivered.
3. **Timer cancel-after-fire:** drive fire via clock advance, then cancel → returns `-ENOENT`; prior TIMER event is still in the queue and drained by the next poll.
4. **Flush batching:** send 10 MSS-sized segments; observe `tx_pending_data` grows to 10 on the send side; `resd_net_flush` drains in one `tx_burst`; `tcp.tx_flush_bursts == 1`, `tcp.tx_flush_batched_pkts == 10`; `tx_pending_data` empty after.
5. **Control-frame independence:** fill `tx_pending_data` with data (no flush); inbound packet triggers an ACK via `emit_ack` — the ACK frame is observed on the wire before the flush call, proving control stays inline.
6. **WRITABLE hysteresis:** fill send buffer via `send_bytes` returning accepted < len; drive ACKs until in_flight ≤ send_buffer_bytes/2; exactly one `RESD_NET_EVT_WRITABLE` event; subsequent partial-refusal produces a fresh WRITABLE cycle.
7. **FORCE_TW_SKIP honored:** `ts_enabled=true` conn, close with flag; drive the peer's FIN ACK to reach TIME_WAIT; reap short-circuits immediately (no 2×MSL wait); final events are `StateChange{TimeWait → Closed}` + `Closed{err=0}`.
8. **FORCE_TW_SKIP rejected:** `ts_enabled=false` conn, close with flag; `Error{err=-EPERM}` delivered; normal 2×MSL wait observed.
9. **RX ENOMEM edge-trigger:** `net_vdev` with tiny RX mempool; drive many RX packets in one poll → exactly one `Error{conn=0, err=-ENOMEM}` event even if `rx_drop_nomem` incremented by N.
10. **Retransmit ENOMEM:** force `tx_hdr_mempool` exhaustion; RTO fire triggers `retransmit` → `Error{err=-ENOMEM}` emitted per occurrence.
11. **TS.Recent 24-day expiry:** mock-clock jump of 25d between ACKs; next in-window segment adopts fresh TSval; `tcp.ts_recent_expired == 1`; PAWS not rejecting.
12. **Event-queue FIFO overflow:** push > `event_queue_soft_cap` events in one poll burst; `obs.events_dropped` increments; oldest events dropped (drop-oldest contract); `obs.events_queue_high_water` latches near cap. Already covered by A5.5 `knob_event_queue_soft_cap_overflow_drops_events` — A6 adds one complementary end-to-end drain-side assertion.
13. **Histogram distribution shape:** drive RTTs across 5 known buckets; `resd_net_conn_rtt_histogram` returns the expected counts; delta between two snapshots over a controlled interval matches.
14. **Histogram unknown handle:** `resd_net_conn_rtt_histogram(engine, 0xdead_beef, &out)` → `-ENOENT`; `out` unchanged.
15. **Histogram null out:** `resd_net_conn_rtt_histogram(engine, conn, NULL)` → `-EINVAL`; no crash.
16. **Histogram cross-conn isolation:** two concurrent conns accumulate independent histograms.
17. **Preset integration:** `preset=1` engine, establish a conn; observe delayed-ACK is on (per-poll ACK coalesce is bounded at 1 ACK per conn per poll — unchanged from A3 — but the *reason* A3 defaults to per-segment is that delayed_ack is off; with preset=1, per-RFC delayed-ACK behavior is exercised). Also observe `tcp_min_rto_us = 200_000` on a conn's projected RTO.

### 7.3 Knob-coverage additions (`crates/resd-net-core/tests/knob-coverage.rs`)

Three new scenario tests:

- **`knob_preset_rfc_compliance_forces_rfc_defaults`** — construct `resd_net_engine_config_t { preset: 1, tcp_nagle: false, tcp_delayed_ack: false, cc_mode: 0, tcp_min_rto_us: 5_000, tcp_initial_rto_us: 5_000, .. }`; post-`resd_net_engine_create`, assert the five §3.5 fields were overridden.
- **`knob_close_force_tw_skip_when_ts_enabled`** — two scenarios: (a) `ts_enabled=true` + FORCE_TW_SKIP → TIME_WAIT reaped immediately (observable: final state reached in < 2×MSL); (b) `ts_enabled=false` + FORCE_TW_SKIP → `Error{err=-EPERM}` event + normal 2×MSL wait.
- **`knob_rtt_histogram_bucket_edges_us_override`** — custom edges `[100, 200, ..., 1600]`; drive an RTT of 150 µs; assert `bucket[1]` incremented (not `bucket[2]` under default edges).

### 7.4 New sibling audit — `tests/per-conn-histogram-coverage.rs`

Per A5.6 §7.3: the existing engine-wide counter audit does NOT reach per-conn state. A6 adds a sibling audit file that requires at least one scenario driving each of the 16 histogram buckets > 0. Achievable with a single test that sweeps RTT across the default-edge range. Fails the build if a bucket is unreachable under the default-edge set — guards against edge-tuning errors.

### 7.5 End-of-phase gates

- `docs/superpowers/reviews/phase-a6-mtcp-compare.md` — `mtcp-comparison-reviewer`.
- `docs/superpowers/reviews/phase-a6-rfc-compliance.md` — `rfc-compliance-reviewer`.

Both opus 4.7 per `feedback_subagent_model.md`. Both run in parallel at end of phase per `feedback_phase_mtcp_review.md` / `feedback_phase_rfc_review.md`. `phase-a6-complete` tag gated on both showing zero open `[ ]` entries.

---

## 8. Review gates

(Covered in §7.5 above. Listed here for index compatibility with prior phase specs.)

---

## 9. Rough task scale

~23 tasks, matching the roadmap budget of "20 A6-core + 3 histogram":

**Preparatory (state + counters):**
1. `TimerNode::user_data` field addition (wheel + its unit tests).
2. `InternalEvent::ApiTimer` + `InternalEvent::Writable` variants + `build_event_from_internal` translation + drain test.
3. `TcpConn` field additions: `send_refused_pending`, `force_tw_skip`, `rtt_histogram: RttHistogram` + compile-time layout asserts.
4. `counters.rs` additions: `tcp.tx_api_timers_fired`, `tcp.ts_recent_expired`, `tcp.tx_flush_bursts`, `tcp.tx_flush_batched_pkts` + C-ABI mirror.

**Engine machinery:**
5. `Engine::tx_pending_data` ring + `drain_tx_pending_data` + `poll_once` end-of-iter drain + `resd_net_flush` wiring.
6. `Engine::rtt_histogram_edges` + `engine_create` monotonic-edges validation + default-edges substitution.
7. `Engine::rx_drop_nomem_prev` snapshot-and-emit edge-trigger for RX ENOMEM events.
8. `Engine::public_timer_add` / `public_timer_cancel` methods + wheel `ApiPublic` fire branch pushing `InternalEvent::ApiTimer`.

**Engine behavioral wiring:**
9. `preset=1` application in `resd_net_engine_create` + `preset>=2` rejection + layer-A test.
10. `close_conn_with_flags` + FORCE_TW_SKIP prerequisite check + `force_tw_skip` propagation into `TcpConn`.
11. `reap_time_wait` short-circuit for `force_tw_skip`.
12. `send_bytes` TX-ring push (replacing per-segment inline `tx_burst`); fall-back drain-and-retry on ring full.
13. `retransmit` TX-ring push (chained header + data mbuf push semantics); ENOMEM Error event emission on alloc failure.

**Data-path hooks:**
14. `tcp_input.rs` PAWS lazy expiration (24-day check + ts_recent reset + counter bump).
15. `tcp_input.rs` RTT-histogram update after `rtt_est.sample()`.
16. `tcp_input.rs` WRITABLE hysteresis on ACK-prune path.

**Public API surface:**
17. `resd_net_timer_add` + `resd_net_timer_cancel` extern "C" functions + `api.rs` type additions + cbindgen header regen.
18. `resd_net_conn_rtt_histogram` extern "C" function + POD struct + cbindgen header regen.
19. `resd_net_close` flag-honoring body (replace the `_flags` stub); cbindgen doc-comment on flag + error-code contract.
20. `resd_net_engine_config_t::rtt_histogram_bucket_edges_us` field + `resd_net_engine_create` plumb into `EngineConfig`.

**Tests + audits:**
21. Integration tests 7.2.1–7.2.17 (split across existing + new `tcp_a6_public_api_tap.rs`).
22. Knob-coverage entries 7.3 + new `tests/per-conn-histogram-coverage.rs`.

**Gate:**
23. End-of-phase mTCP + RFC parallel reviewer dispatch + report writing + `phase-a6-complete` tag.

Opportunistic A5.5 nit fixes ("RFC 6298 §3.3" → §2.2 + §3; "RFC 8985 §7.4" → §7.3 step 2) fold into whichever task touches the A5.5 spec / roadmap text for A6 §4 updates — not a standalone task.

Plan-writing pass will expand each row into sub-tasks with file-level diffs, review-subagent dispatch (spec-compliance + code-quality per `feedback_per_task_review_discipline.md`), and dependency graph.

---

## 10. Updates to parent spec `2026-04-17-dpdk-tcp-design.md`

Applied in the same commit as the A6 final task:

### 10.1 §4 API additions

- Add `resd_net_timer_add` / `resd_net_timer_cancel` under the "Timers & clock" paragraph (already present in the Stage 1 API listing at parent §4 — A6 finalizes the wording around `-EALREADY` → `-ENOENT` collapse).
- Add `resd_net_conn_rtt_histogram` under the "Introspection (A5.5)" paragraph alongside `resd_net_conn_stats`.
- Add `resd_net_tcp_rtt_histogram_t` POD definition.
- Add `rtt_histogram_bucket_edges_us[15]` to the `resd_net_engine_config_t` listing.

### 10.2 §4.2 contract wording updates

- `resd_net_flush` clarification: "drains the pending data-segment TX batch via exactly one `rte_eth_tx_burst`. Control frames (ACK, SYN, FIN, RST) are emitted inline at their emit site and do not participate in the flush batch."
- `resd_net_timer_cancel` wording: `-EALREADY` collapsed into `-ENOENT`; "callers must always drain any queued TIMER events regardless of this return."
- `resd_net_close` flag + error-code paragraph: "When `RESD_NET_CLOSE_FORCE_TW_SKIP` is set but the connection did not negotiate timestamps, the flag is silently dropped, a `RESD_NET_EVT_ERROR{err=-EPERM}` event is emitted for visibility, and the normal FIN + 2×MSL TIME_WAIT sequence proceeds."

### 10.3 §9.1 counter additions

- Add the four new `tcp.*` counters to the A6 section of the counter listing (under the existing A5 / A5.5 additions pattern).
- Note that per-conn RTT histogram is NOT in `resd_net_counters_t` — read via `resd_net_conn_rtt_histogram`.

### 10.4 §9.3 ENOMEM event emission

- Document the three emission sites: `send_bytes` sync return, internal retransmit per-occurrence, RX mempool edge-triggered per poll iteration.

### 10.5 §6.5 TIME_WAIT shortening

- Finalize the FORCE_TW_SKIP semantics text: "honored only when `c.ts_enabled == true` at close time; the combination of PAWS on the peer (RFC 7323 §5) + monotonic ISS on our side (RFC 6528, §6.5 implementation choice) is the client-side analog of RFC 6191's protections."

### 10.6 A5.5 nits

- "RFC 6298 §3.3" → "§2.2 (first-RTT seeding) + §3 (Karn's rule)".
- "RFC 8985 §7.4 (RTT-sample gate)" → "§7.3 step 2".

Both appear in parent spec §6.3 RFC compliance matrix row for RFC 8985 and in the A5.5 addition for RFC 6298; A6 corrects inline.

---

## 11. Performance notes

- **Timer add:** O(1) wheel insert + one `AtomicU64` increment for the fire counter (slow-path — fires per-timer-add). Not on a per-segment path.
- **Timer cancel:** O(1) wheel tombstone + return code synthesis.
- **Flush drain:** one `rte_eth_tx_burst(ring.len())` + O(unsent) free-loop for partial fills. Amortized cost per packet is lower than the A3-era per-segment `tx_burst(1)` because DPDK's doorbell-write and PCIe descriptor-ring path cost is constant-per-burst, not per-packet.
- **WRITABLE check:** one branch + one u32 compare on the ACK-prune path. Single-digit-cycles cost on the hot path.
- **TS.Recent expiration check:** two u64 subtractions + one compare at the PAWS gate. The gate only runs on TS-carrying segments; cost is negligible vs. the existing PAWS fold.
- **Histogram update:** 15-comparison ladder + one `wrapping_add` (≈5–10 ns; per A5.6 §11 numbers). Fires at RTT-sample rate, not per-segment.
- **Public timer memory:** 8 extra bytes per `TimerNode` for `user_data`. Wheel initial slot capacity 1024 → 8 KB extra per engine. Negligible.
- **Per-conn state additions:** two bools (`send_refused_pending`, `force_tw_skip`) + 64 B aligned `RttHistogram` = 66 B per conn; practical cost one extra cacheline per conn due to the aligned sub-struct. At ≤100 conns per §1, total = 6.4 KB extra per engine.
- **TX ring memory:** `tx_ring_size * size_of::<NonNull<rte_mbuf>>()` = 1024 × 8 B = 8 KB per engine.

No hot-path perf regressions expected. A10's bench harness will confirm the flush batching win on the data path empirically.

---

## 12. Open items for the plan-writing pass

- **Task ordering:** the dependency graph across the 23 tasks — obvious chains (state → machinery → surface → tests) but there's parallelism inside each group. Plan-writing pass should identify the critical path and call out independent streams that can be picked up in any order.
- **Per-task reviewer discipline** (`feedback_per_task_review_discipline.md`): every non-trivial task ends with parallel spec-compliance + code-quality reviewer subagents (opus 4.7). Plan needs to embed the dispatch commands per task.
- **Rebase cadence with phase-a-hw** (session coordinator brief): plan should state a cadence — rebase after each commit when phase-a-hw has advanced. Conflict surfaces (engine.rs port config vs. engine.rs timer/flush/close paths) are disjoint; cbindgen header auto-regenerates on both branches.
- **A5.5 nit fix placement:** the two citation corrections can fold into whichever A6 task touches A5.5 spec text — plan should call out the expected folding target explicitly, not leave it to task-author discretion.
- **ABI compile-time asserts:** plan should spell out the full set of `size_of` / `align_of` asserts needed post-field-additions so counter/conn-stats layout drift doesn't escape detection. A5.5's pattern (`const _: () = { ... assert!(...) }` blocks in `api.rs`) is the template.
- **Coverage for `preset` field:** the knob-coverage test covers `preset=1`; the plan should also confirm whether the existing `tcp_nagle=false` / `tcp_delayed_ack=false` default path is itself covered elsewhere (i.e., that the audit detects the preset=0 baseline as a distinct scenario from preset=1). If not, add a sibling `knob_preset_latency_leaves_user_config_intact` entry.

---

## 13. Durable memory references

All existing guidance still applies — no new entries proposed:

- `feedback_trading_latency_defaults` — prefer latency defaults; preset=rfc_compliance is opt-in.
- `feedback_observability_primitives_only` — histogram is a primitive; no in-stack aggregation beyond per-conn bucket counts.
- `feedback_subagent_model` — opus 4.7 for all reviewer dispatches.
- `feedback_per_task_review_discipline` — every non-trivial task gets paired reviewer subagents.
- `feedback_phase_mtcp_review` / `feedback_phase_rfc_review` — end-of-phase parallel gate.
- `feedback_counter_policy` — four new counters all slow-path, rule-1 compliant.
- `feedback_performance_first_flow_control` — WRITABLE is backpressure signal, not peer throttle.

---

## 14. End of phase

On all tasks complete + both review reports clean (zero open `[ ]`):

- Tag `phase-a6-complete` locally (do not push — session coordinator merges).
- Update `docs/superpowers/plans/stage1-phase-roadmap.md` A6 row with the complete marker + the final task count.
- Session handoff reports: tag SHA, rebase events against `phase-a-hw` (if any), unresolved surprises. Coordinator merges A6 + A-HW.
