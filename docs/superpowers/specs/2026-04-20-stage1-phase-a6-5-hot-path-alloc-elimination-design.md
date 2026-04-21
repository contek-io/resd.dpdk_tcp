# Phase A6.5 — Hot-path allocation elimination (Design Spec)

**Status:** Design approved; implementation plan to land in a separate file under `docs/superpowers/plans/`.
**Parent spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` row A6.5.
**Sibling (consumer):** `docs/superpowers/specs/2026-04-20-stage1-phase-a6-6-and-a6-7-rx-zero-copy-and-ffi-safety-audit-design.md` §1 (A6.6) explicitly depends on Group 4 of this phase; A6.7 reuses Group 5's `bench-alloc-audit` wrapper.

---

## 0. Why this phase

A6 delivered the public API and per-connection RTT histogram; A-HW delivered ENA offload wiring. Both landed without touching the per-segment allocation profile. Two hot paths still call `Vec::new` / `Vec::with_capacity` / `vec![0u8; 1600]` on every segment:

- **TX build.** `engine.rs:3526` allocates a 1600-byte frame scratch per segment.
- **Streaming checksum path.** `tcp_input.rs:108`, `tcp_output.rs:204` each allocate `Vec::with_capacity(12 + hdr + payload)` per segment to feed the concatenating `internet_checksum(&[u8])`.

Per-ACK and per-tick paths also leak:

- **Per-ACK.** `rack_lost_indexes: Vec<u16>` (tcp_input.rs:775), RACK loss-event tuples in the engine (engine.rs:1863), per-connection `timer_ids.to_vec()` (engine.rs:2190 and three siblings).
- **Per-tick.** `tcp_timer_wheel::advance` allocates a `Vec<(TimerId, TimerNode)>` for every advance (tcp_timer_wheel.rs:104,106). `tcp_retrans::prune_below` allocates a `Vec<RetransEntry>` for every ACK that retires segments (tcp_retrans.rs:64-65).

OOO reassembly still holds payload `Vec<u8>` per segment (tcp_reassembly.rs:18, 86, 102, 121) — a deliberate hold-over from A3 AD-7 that the reassembly module's doc-comment already flags as "§7.2 envisions mbuf-chain zero-copy".

A6.5 retires every one of these. Zero wire-behaviour changes, zero public-API changes, zero behavioural knobs. The phase is strictly internal performance work gated on a regression test that asserts the steady-state hot path allocates nothing.

## 1. Scope

### In scope

- **Group 1:** Reusable TX frame scratch buffer on `Engine`.
- **Group 2:** Streaming Internet checksum API (`internet_checksum(&[&[u8]]) -> u16`), three caller rewrites.
- **Group 3:** `SmallVec<[T; N]>` for per-ACK / per-tick small working sets; caller-owned timer-id scratch on `Engine`.
- **Group 4:** OOO reassembly mbuf-ref refactor (staged 4a→4d).
- **Group 5:** `bench-alloc-audit` feature + `tests/bench_alloc_hotpath.rs` integration test + report artifact.
- **Spec edits:** new §7.6 "Hot-path scratch reuse policy"; §7.3 update to retire the OOO-copy language.

### Out of scope (explicitly deferred)

- Per-connection `VecDeque<u8>` send/recv buffers and `Vec<TimerId> timer_ids` — one-shot per connection, not per-segment.
- Engine-creation allocations (`Box::new(Counters::new())`, DPDK mempools, timer-wheel slot vectors) — startup cost, not steady-state.
- Custom `GlobalAlloc` replacement (bump/arena allocator). Default `System` allocator stays once the hot path is alloc-free; the `bench-alloc-audit` wrapper is a counting probe, not a replacement.
- `String::` / `format!` in error-path `Error` variants and slow-path logging. Slow-path per §9.1.1.
- Public API surface changes. A6.6 owns scatter-gather iovec API evolution; A6.5 emits one event per drained mbuf exactly like A6 already does via `last_read_buf`.
- Wire behaviour. Zero bytes on the wire differ post-A6.5.
- A10 benchmark harness (criterion + latency distributions). A6.5 ships the alloc-audit regression test only; A10 imports the same wrapper alongside criterion's timing instrumentation.
- A6.7 FFI safety audit work. A6.7 reuses Group 5's wrapper; the audit itself (miri, cbindgen drift, panic firewall, sanitizers) is A6.7's deliverable.

### Success criterion

Under a 60-second steady-state send/recv loop post-warmup, the counting `GlobalAlloc` wrapper reports `(allocs_delta, frees_delta) == (0, 0)`. This is the phase gate. Any hot-path allocation surfaced by the wrapper either gets retired in this phase or gets a documented exception recorded in `docs/superpowers/reports/alloc-hotpath.md` with spec-compliant justification per the new §7.6 rule.

## 2. Groups

### 2.1 Group 1 — reusable TX frame scratch

**Call site retired:** `engine.rs:3526` `let mut frame = vec![0u8; 1600]`.

**Design.** `Engine` gains one field:

```rust
pub(crate) tx_frame_scratch: RefCell<Vec<u8>>,
```

Initial capacity at `engine_create`: `cfg.tcp_mss as usize + FRAME_HDRS_MIN + 40`. This covers every MSS-sized segment including the 40-byte TCP-options cushion (RFC 9293 §3.1 max options). Borrow contract mirrors the A6 `tx_pending_data: RefCell<Vec<NonNull<rte_mbuf>>>` pattern (engine.rs:368, 808):

```rust
let mut scratch = self.tx_frame_scratch.borrow_mut();
let needed = FRAME_HDRS_MIN + 40 + take;
if scratch.capacity() < needed {
    scratch.reserve(needed - scratch.capacity());
}
scratch.clear();
scratch.resize(needed, 0);
let Some(n) = build_segment(&seg, &mut scratch) else { break };
```

`resize(needed, 0)` is the correct zero-init primitive; `scratch.clear()` before it drops length to zero so `resize` writes zeros only for the currently-needed extent, not the entire capacity.

**Nested-borrow safety.** The enclosing TX loop does not borrow `tx_frame_scratch` through any helper; `build_segment` takes `&mut [u8]` (slice reborrow on the `RefMut`'s `deref_mut`). The `tx_offload_finalize` call downstream of `build_segment` operates on mbuf memory, not `scratch` — no conflict.

**Alternatives rejected.** Thread-local storage adds a second ownership model to Stage 1's single-lcore RTC engine for no benefit (the `RefCell` on `Engine` is already thread-local-effectively-by-construction). Stack-sized array with heap fallback adds branchy resize code for a path that's always going to need heap capacity at the MSS we target.

### 2.2 Group 2 — streaming Internet checksum

**API.**

```rust
pub fn internet_checksum(chunks: &[&[u8]]) -> u16
```

`chunks` is a slice of byte slices. The fold iterates chunks in order, maintaining a 32-bit accumulator and a 1-byte carry across chunk boundaries (needed when a chunk has odd length and the next chunk continues the 16-bit word). Final fold wraps carries into the low 16 bits and returns `!sum`.

**Implementation sketch.**

```rust
pub fn internet_checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut carry: Option<u8> = None;
    for chunk in chunks {
        let (start, first_pair_consumed) = if let Some(high) = carry.take() {
            if let Some(&low) = chunk.first() {
                sum = sum.wrapping_add(u16::from_be_bytes([high, low]) as u32);
                (1, true)
            } else {
                carry = Some(high);
                (0, false)
            }
        } else { (0, false) };
        let _ = first_pair_consumed;
        let mut i = start;
        while i + 1 < chunk.len() {
            sum = sum.wrapping_add(u16::from_be_bytes([chunk[i], chunk[i + 1]]) as u32);
            i += 2;
        }
        if i < chunk.len() {
            carry = Some(chunk[i]);
        }
    }
    if let Some(tail) = carry {
        sum = sum.wrapping_add((tail as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
```

**Callers updated.**

- `tcp_input::tcp_pseudo_csum` (tcp_input.rs:107–115). Drop `Vec::with_capacity(12 + tcp_bytes.len())`. Build a stack `[u8; 12]` pseudo-header locally, call `internet_checksum(&[&pseudo, tcp_bytes])`.
- `tcp_input.rs:84` `let mut scratch = tcp_bytes.to_vec()`. This copy exists so the pre-csum code can clear the csum-field bytes before folding (the fold includes the csum field, which must be treated as zero during verification). Replace with a fold that skips the csum-field offset inline: walk `tcp_bytes` as two sub-slices (before and after the 2-byte csum field) and call `internet_checksum(&[&pseudo, &tcp_bytes[..csum_off], &[0, 0], &tcp_bytes[csum_off + 2..]])`. Net: zero allocation on RX csum validation.
- `tcp_output::tcp_checksum_split` (tcp_output.rs:196–213). Drop `Vec::with_capacity(12 + hdr + payload)`. Build stack `[u8; 12]` pseudo-header, call `internet_checksum(&[&pseudo, tcp_header_bytes, payload_bytes])`.
- `tcp_output.rs:559` (test-only pseudo-header fold). Updated for consistency, but already on a test path.
- `l3_ip::ip_decode` IPv4-header csum verification (l3_ip.rs). The single-slice convenience wrapper becomes a one-liner: `internet_checksum(&[ip_header_bytes])`. No semantic change.

**Regression guard.** New fuzz test `crates/resd-net-core/tests/checksum_streaming_equiv.rs`:

- Generates pseudo-headers + tcp-header + payload byte strings with arbitrary lengths in `[0, 2048]`.
- Folds via (a) reference path (concatenate into a Vec, call old-shaped `internet_checksum(&[u8])`) and (b) new streaming path (`internet_checksum(&[&a, &b, &c])`).
- Asserts bit-for-bit equivalence.
- Includes explicit odd-boundary stress: every combination of chunk lengths in `{0, 1, 2, 3, ..., 15}` for the three-chunk case.

### 2.3 Group 3 — SmallVec for per-ACK / per-tick

**Dependency.** Add `smallvec = "1"` to workspace `Cargo.toml` (single new external dep, pulled by `resd-net-core` only).

**Replacements.**

| Location | Before | After | Inline N | Rationale |
|---|---|---|---|---|
| `tcp_input.rs:192, 239, 775, 902` | `rack_lost_indexes: Vec<u16>` | `SmallVec<[u16; 16]>` | 16 | RFC 8985 detect-lost; observed ≤ 4 in steady state; 16 covers reorder-heavy scenarios without spill. |
| `engine.rs:1863` | `vec![(e.seq, e.xmit_count as u32)]` | `SmallVec<[(u32, u32); 4]>` | 4 | RACK loss event tuples. Typically 0–2 per ACK. |
| `tcp_timer_wheel.rs:104, 106` `advance` return | `Vec<(TimerId, TimerNode)>` | `SmallVec<[(TimerId, TimerNode); 8]>` | 8 | Timer burst; advance window typically fires ≤ 4. |
| `tcp_retrans.rs:64-65` `prune_below` return | `Vec<RetransEntry>` | `SmallVec<[RetransEntry; 8]>` | 8 | ACK-coalesced pruning; ≤ 6 common. |

**Timer-id scratch.** `engine.rs:2190, 2298, 2936` each do `let mut ids: Vec<TimerId> = conn.timer_ids.to_vec()`. The `.to_vec()` exists to copy the list out of the `TcpConn`'s `RefCell` borrow before cancel operations that would need the borrow too. Retired via a per-Engine scratch:

```rust
pub(crate) timer_ids_scratch: RefCell<SmallVec<[TimerId; 8]>>,
```

Initial capacity 0 (inline). Call-site pattern:

```rust
let mut ids = self.timer_ids_scratch.borrow_mut();
ids.clear();
ids.extend_from_slice(&conn.timer_ids);
drop(conn); // release conn borrow
for id in ids.iter() { self.timer_wheel.borrow_mut().cancel(*id); }
```

Per-connection `timer_ids` storage stays `Vec<TimerId>` (not hot-path — timer-arm happens on connection state transitions, covered by the "one-shot per connection, not per-poll" out-of-scope boundary).

**Drop semantics.** `SmallVec` spills to heap on overflow beyond the inline N; the inline-N values above are sized so that overflow is a rare edge case, not the steady state. Overflow is correctness-neutral (it allocates once and continues), but the alloc-audit test guards that overflow does not happen on the normal workload. If it does, the fix is either a larger N or a documented per-connection burst that the test rig doesn't exercise.

### 2.4 Group 4 — OOO reassembly zero-copy (staged 4a → 4d)

Four sub-tasks. Each ends with two parallel reviewer subagents (spec-compliance + code-quality, opus 4.7) before the next starts.

**Task 4a — introduce the variant.**

```rust
pub enum OooSegment {
    Bytes(OooBytes),
    MbufRef(OooMbufRef),
}

pub struct OooBytes {
    pub seq: u32,
    pub payload: Vec<u8>,
}

pub struct OooMbufRef {
    pub seq: u32,
    pub mbuf: std::ptr::NonNull<sys::rte_mbuf>,
    pub offset: u16,
    pub len: u16,
}
```

Existing `insert` / `drain_contiguous_from` keep `Bytes` behaviour; `MbufRef` is unused downstream. Tests pass unchanged. This task lands the type-shape alone.

**Task 4b — insert produces mbuf refs.**

`ReorderQueue::insert(&mut self, seq: u32, payload: &[u8], source_mbuf: Option<OooMbufRef>) -> InsertOutcome`. When `source_mbuf` is `Some`, gap-slice carve stores `OooSegment::MbufRef { seq, mbuf, offset: seq_off, len: gap_len }` instead of `payload[off..off+take].to_vec()`. Refcount is bumped at insert. `drain_contiguous_from` still returns `(Vec<u8>, u32)` by walking the segment list and copying out from either variant (temporary shim). Engine call sites begin passing `source_mbuf`. Insert-time adjacent-touch merging is NOT done for `MbufRef` entries (would require concatenating payload, defeating zero-copy); merging is preserved only within same-variant runs for the `Bytes` path and becomes adjacency-only (no physical merge) for `MbufRef` runs.

Post-condition: `to_insert: Vec<(u32, Vec<u8>)>` at tcp_reassembly.rs:86 is retired. The two-phase "carve gap-slices, then merge" structure becomes a single-phase loop calling a local `insert_merged_mbuf_ref(&mut self, seq, mbuf, offset, len)` helper per carved gap, eliminating the interior accumulator entirely. No `SmallVec` workaround needed — the insert becomes allocation-free by construction.

**Task 4c — drain returns mbuf list.**

```rust
pub struct DrainedMbuf {
    pub mbuf: std::ptr::NonNull<sys::rte_mbuf>,
    pub offset: u16,
    pub len: u16,
}

pub fn drain_contiguous_from_mbuf(&mut self, rcv_nxt: u32) -> SmallVec<[DrainedMbuf; 4]>
```

Old `drain_contiguous_from` is deleted in this task. The engine's READABLE event path extended: `last_read_buf: Vec<u8>` → `last_read_mbufs: SmallVec<[std::ptr::NonNull<sys::rte_mbuf>; 4]>` pinned for the poll iteration's event-emission window.

**API impact (internal only).** `resd_net_poll` iterates the drained list and emits one `RESD_NET_EVT_READABLE` event per drained mbuf, each event's `data`/`len` pointing into one mbuf's payload area at the computed offset. This matches A6's in-order path exactly (which already emits one event per mbuf via `last_read_buf`); A6.6's scatter-gather API is not added here.

**Task 4d — retire the Bytes variant.**

Delete `OooSegment::Bytes` and `OooBytes`. `OooSegment` becomes a plain struct equal to the `OooMbufRef` content. Delete the drain_contiguous_from shim. Update `tests/tcp_options_paws_reassembly_sack_tap.rs`:

- OOO inserts: assert `ReorderQueue::segments()[i]` carries mbuf refs (not `Vec<u8>`).
- Drain: assert returned `SmallVec<DrainedMbuf>` points to the originally-inserted mbufs with correct `(offset, len)`.
- Refcount: test the refcount is bumped on insert, dropped exactly when the event consumer releases the pin or the connection closes.

### 2.5 Group 5 — alloc-audit regression test

**Cargo feature.** `crates/resd-net-core/Cargo.toml`:

```toml
[features]
bench-alloc-audit = []
bench-alloc-audit-backtrace = ["bench-alloc-audit"]
```

Default OFF. The base feature enables the counting wrapper and the integration test; the `-backtrace` sub-feature enables capturing allocation backtraces for repro-diagnostic runs.

**Wrapper.** New file `crates/resd-net-core/src/bench_alloc_audit.rs`:

```rust
#[cfg(feature = "bench-alloc-audit")]
pub struct CountingAllocator;

#[cfg(feature = "bench-alloc-audit")]
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(feature = "bench-alloc-audit")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "bench-alloc-audit")]
pub static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "bench-alloc-audit")]
pub static FREE_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "bench-alloc-audit")]
pub static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "bench-alloc-audit")]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FREE_COUNT.fetch_add(1, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
}

#[cfg(feature = "bench-alloc-audit")]
pub fn snapshot() -> (u64, u64, u64) {
    (
        ALLOC_COUNT.load(Ordering::Relaxed),
        FREE_COUNT.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
    )
}
```

`#[global_allocator]` installation lives in the integration test binary, not the library — installing in the library would affect every downstream dependency.

**Integration test.** `crates/resd-net-core/tests/bench_alloc_hotpath.rs` (feature-gated with `#![cfg(feature = "bench-alloc-audit")]`):

```rust
#[global_allocator]
static A: resd_net_core::bench_alloc_audit::CountingAllocator =
    resd_net_core::bench_alloc_audit::CountingAllocator;

#[test]
fn hot_path_allocates_zero_bytes_post_warmup() {
    // Setup: reuse the loopback rig used by a5_harness_smoke.rs.
    let rig = Rig::new();
    // Warmup: 1 second of bursty send/recv to amortize mempool/ring/scratch allocation.
    rig.run_for(Duration::from_secs(1));

    let (a0, f0, b0) = snapshot();
    // Steady state: 60 seconds of send/recv at MSS-sized payloads.
    rig.run_for(Duration::from_secs(60));
    let (a1, f1, b1) = snapshot();

    assert_eq!(a1 - a0, 0, "{} hot-path allocations across 60s", a1 - a0);
    assert_eq!(f1 - f0, 0, "{} hot-path frees across 60s", f1 - f0);
    assert_eq!(b1 - b0, 0, "{} bytes allocated", b1 - b0);
}
```

On failure under `bench-alloc-audit-backtrace`, the wrapper logs each allocation's backtrace so the offending call site is identifiable without re-running.

CI cadence: runs in nightly CI (not per-PR) via `cargo test --features bench-alloc-audit --test bench_alloc_hotpath`. Runtime ~75s (1s warmup + 60s steady state + ~15s setup/teardown).

**Report artifact.** `docs/superpowers/reports/alloc-hotpath.md`:

- Table: every call site retired, with `file:line` before / after / owning task.
- The final audit-run log lines showing the zero delta.
- Any hot-path allocations surfaced by the wrapper that were NOT in the roadmap's initial call-site list, with disposition (retired / exception).

## 3. New spec text

Two edits to the parent spec `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.

### 3.1 New §7.6 — Hot-path scratch reuse policy

Inserted after §7.5, before §8.

> ### 7.6 Hot-path scratch reuse policy
>
> Hot-path code — any function reachable from `engine::poll_once`, the RX / TX burst loops, the per-segment TCP state machine, per-ACK processing, or per-tick timer fire — MUST NOT call `Vec::new`, `Vec::with_capacity`, `Box::new`, `String::from`, `format!`, or any other heap allocator on a per-segment basis. The canonical patterns are:
>
> 1. **Engine-owned scratch.** `RefCell<Vec<T>>` (or `RefCell<SmallVec<[T; N]>>`) fields on `Engine` sized at `engine_create`. Hot-path borrows with `borrow_mut()`, clears, resizes only if capacity is insufficient, then fills. Mirrors the A6 `tx_pending_data` ring precedent. Typical examples: TX frame scratch, timer-id iteration scratch.
>
> 2. **Caller-provided `&mut` buffer.** Function takes `&mut Vec<T>` or `&mut SmallVec<[T; N]>` from the caller; clears + populates. Typical example: `timer_wheel::advance(now_ns, &mut fired)`.
>
> 3. **`SmallVec<[T; N]>` inline-stored.** For small working sets whose P99 size fits in N. Spill to heap is correctness-neutral but costs an allocation; N sized to cover observed P99. Typical examples: RACK lost-indexes, prune-below drop list, timer-fire burst.
>
> **Gate.** The `bench-alloc-audit` regression test (§10 — Testing) enforces zero allocations on the steady-state hot path. Any new hot-path site either satisfies one of the three patterns above, or the increment is a documented exception recorded in `docs/superpowers/reports/alloc-hotpath.md` with measured cost and reviewer sign-off — same structure as §9.1.1 rule 3 for hot-path counters.
>
> **Not governed by this rule.**
> - Per-connection one-shot allocations at `connect()` / `accept()` (send/recv VecDeques, `timer_ids` list). Per-connection, not per-segment.
> - Engine-creation allocations (mempools, timer-wheel slots, scratch sizing). Startup cost.
> - Error-path / slow-path `String::` / `format!` in logging, `Error` variants. Per §9.1.1 parallel: slow-path cost is fine.

### 3.2 §7.3 update — Zero-copy path

Replace the second copy-description bullet (currently: "**RX reassembly**: zero copies for in-order data (mbuf chain in `recv_queue`). Out-of-order segments are held as a linked list of mbufs; no copy unless we ever coalesce for contiguous delivery (which we don't — we fire one event per mbuf).") with:

> - **RX reassembly**: zero copies for both in-order data (mbuf chain in `recv_queue`) and out-of-order segments (mbuf refs with `(offset, len)` per segment in `ReorderQueue`). The READABLE event pins referenced mbufs until the poll iteration completes per §5.3's mbuf-lifetime contract. Drain to in-order delivery produces an mbuf list (one event per mbuf), not a concatenated byte buffer.

No other §7.3 changes.

## 4. Cargo dependency changes

Exactly one new external dependency.

- **Workspace root `Cargo.toml`:** add `smallvec = "1"` under `[workspace.dependencies]`.
- **`crates/resd-net-core/Cargo.toml`:** add `smallvec = { workspace = true }` to `[dependencies]`; add `bench-alloc-audit` and `bench-alloc-audit-backtrace` features under `[features]`.

No other crates are added. `smallvec` is battle-tested (core infrastructure for quinn, neqo, servo) and adds no further transitive deps at default features.

## 5. Knob-coverage audit

A6.5 introduces **zero** behavioural knobs. Wire behaviour and all config struct fields are unchanged.

`tests/knob-coverage.rs` grows one entry under a new "build-feature coverage" section (add section if none exists) asserting that `cargo check --features bench-alloc-audit` compiles. No runtime assertion is required; the build-compiles check is the knob-coverage contract for feature-gated code whose activation is a build decision rather than a runtime knob.

## 6. Testing strategy

- **Unit tests** (added/updated per task):
  - `tx_frame_scratch` borrow + reset correctness (engine.rs tests module).
  - SmallVec overflow spill for each Group 3 site — assert correctness-invariant hold on oversized input.
  - Each OOO variant transition in Group 4 (`tests/tcp_options_paws_reassembly_sack_tap.rs` extended).
- **Fuzz test.** `crates/resd-net-core/tests/checksum_streaming_equiv.rs` — streaming vs. reference checksum equivalence across random chunk lengths, with odd-boundary stress on small chunks.
- **Integration test.** `crates/resd-net-core/tests/bench_alloc_hotpath.rs` — steady-state alloc audit (the Group 5 deliverable).
- **Regression.** Existing loopback smoke (`a5_harness_smoke.rs`, `tcp_basic_tap.rs`, `tcp_rack_rto_retrans_tap.rs`) remains green.

## 7. End-of-phase review gates

Both reviewer subagents dispatched in parallel (opus 4.7):

- `mtcp-comparison-reviewer` → `docs/superpowers/reviews/phase-a6-5-mtcp-compare.md`. Expected brief: A6.5 is internal-perf only; no behavioural divergence from mTCP. Scratch/smallvec discipline mirrors mTCP's per-core scratch pattern.
- `rfc-compliance-reviewer` → `docs/superpowers/reviews/phase-a6-5-rfc-compliance.md`. Expected brief: no wire bytes changed; no MUST/SHOULD gaps introduced or resolved. Checksum fold algorithm is RFC 1071 equivalent by construction (the streaming test proves bit-exactness against the reference).

Tag `phase-a6-5-complete` only when both reports show zero open `[ ]`. Tag is NOT pushed to origin — coordinator handles merge and promotion.

## 8. Task summary (implementation plan will expand)

Approximate shape for the plan:

- Task 1 — Group 1 (TX frame scratch).
- Task 2 — Group 2a (`internet_checksum` API change + RFC-1071-equivalent streaming fold + equivalence fuzz test).
- Task 3 — Group 2b (three caller rewrites: `tcp_pseudo_csum`, `tcp_checksum_split`, `tcp_input` scratch-copy retirement).
- Task 4 — Group 3a (SmallVec dep + four inline-N call sites).
- Task 5 — Group 3b (engine timer-ids scratch field).
- Task 6 — Group 4a (OOO variant shape).
- Task 7 — Group 4b (insert path mbuf-ref).
- Task 8 — Group 4c (drain returns mbuf list; event path extended).
- Task 9 — Group 4d (retire Bytes variant + test updates).
- Task 10 — Group 5 (bench-alloc-audit wrapper + integration test + report).
- Task 11 — Spec edits (§7.6 new + §7.3 edit).
- Task 12 — Knob-coverage build-feature entry.
- Task 13 — End-of-phase review-gate dispatch + tag.

Every non-trivial task ends with two parallel reviewer subagents (spec-compliance + code-quality, opus 4.7) before the next task starts.
