# Phases A6.6 + A6.7 — RX zero-copy (scatter-gather) and FFI safety audit (Design Spec)

**Status:** Design approved; implementation plans pending (will land as two separate plan files under `docs/superpowers/plans/`).
**Parent spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` — to be inserted between A6.5 and A7.
**Sibling (prerequisite):** `docs/superpowers/plans/stage1-phase-roadmap.md` §A6.5 — "Hot-path allocation elimination" Group 4 delivers the OOO-path `tcp_reassembly.rs` mbuf-ref refactor and the READABLE-event mbuf-pinning bullet. A6.6 builds on top; A6.6 does **not** re-describe work A6.5 owns.

---

## 0. Why these two phases

Two distinct workstreams emerged from the FFI/memory-model brainstorm:

1. **Finish the zero-copy RX contract.** A6.5 Group 4 retires internal `Vec<u8>` copies in OOO reassembly and pins mbufs through the READABLE event — a strictly internal refactor. The *public* API still exposes single-pointer-plus-length (`data: *const u8, len: u32`), which works only for single-segment mbufs. With A-HW enabling LRO on ENA, the NIC will hand us chained mbufs under load; forfeiting LRO just to keep the API shape defeats the premise. A6.6 evolves the API to scatter-gather (`dpdk_net_iovec_t segs[]`), finishes the in-order delivery path, and adds pool sizing + bench validation.
2. **Audit the final FFI contract once.** Reviewing memory/panic safety *before* A6.6 would mean re-auditing after the scatter-gather change landed. A6.7 runs immediately after A6.6 so the contract is audited once, in its final Stage 1 shape, before A7's packetdrill harness and A8-A11's broader tests depend on it.

Sequencing: **A-HW → A6 → A6.5 → A6.6 → A6.7 → A7**. Both new phases are tagged non-integer to avoid renumbering A7–A14 references (same precedent as A5.5 / A-HW / A6.5).

---

## 1. Scope

### A6.6 — RX zero-copy (scatter-gather)

**In scope:**
- Public API evolution: `dpdk_net_event_readable_t` loses `data: *const uint8_t` + `len: uint32_t`; gains `segs: const dpdk_net_iovec_t*`, `n_segs: uint32_t`, `total_len: uint32_t`. Introduces new `dpdk_net_iovec_t { const uint8_t *base; uint32_t len; }`. Breaks the current header shape; pre-1.0 so acceptable, but consumers (including `examples/cpp-consumer/main.cpp`) must be updated in-phase.
- In-order delivery path rework: `RecvQueue.bytes: VecDeque<u8>` → `VecDeque<InOrderSegment { mbuf: Mbuf, offset: u16, len: u16 }>`. `last_read_buf: Vec<u8>` retired entirely — `dpdk_net_poll` builds the `segs` array on an engine-owned scratch from the live segments instead of copying bytes.
- Multi-segment mbuf ingest: LRO'd / jumbo / IP-defragmented chained mbufs propagate through reassembly and delivery as-is. Each `rte_mbuf` link in the chain becomes one `dpdk_net_iovec_t`. No flatten helper in this phase.
- `rx_mempool_size` knob exposed on `dpdk_net_engine_config_t`. Default computed from `recv_buffer_bytes × max_conns / avg_payload_bytes × safety_factor_2`. Documented in header. Existing `_rx_mempool` construction in `engine.rs` plumbed through.
- `bench-rx-zero-copy/` criterion harness: poll-to-delivery cycle cost + `bench-alloc-audit` assertion that the single-segment in-order delivery path allocates zero bytes post-warmup. Integrates into A10 when that phase lands.
- `examples/cpp-consumer/main.cpp` updated to loop over `segs[]`.

**Out of scope (explicitly deferred or already covered):**
- OOO reassembly mbuf-ref refactor — **A6.5 Group 4** owns it. A6.6 depends on it.
- TX zero-copy (user-held buffer passed to Rust without copy). TX remains copy-in via `tx_data_mempool`. Separate contract change.
- `dpdk_net_readable_flatten()` convenience helper — YAGNI. Consumers that want a contiguous copy call `memcpy` across segs themselves; the trading HTTP/WS parsers the library will front (A13/A14) already accept iovec input.
- WRITABLE event / backpressure semantics — owned by A6.
- cxx-bridge migration — stays cbindgen; current POD-shaped ABI is a bad fit for cxx's rich-type machinery.

### A6.7 — FFI safety audit & hardening

**In scope:**
- miri CI job over `dpdk-net-core` with DPDK-touching modules `#[cfg(miri)]`-skipped or shimmed. Covers the pure-Rust reassembly, timer-wheel, flow-table, event-queue logic — anywhere safe/unsafe-Rust UB could hide.
- cbindgen header-drift CI check: `cargo xtask check-header` regenerates `include/dpdk_net.h`, diffs against the committed copy, fails CI on drift. Generated header becomes a reviewable artifact, not a build byproduct.
- ABI-stability snapshot: `tests/abi/dpdk_net.h.expected` committed in the first A6.7 task. `check-header` diffs against it; drift requires an intentional snapshot update (semver-like discipline without a separate tool).
- Panic-firewall integration test: forced `panic!` reached through an ABI entry, asserts the process aborts with the expected code (via `panic = "abort"` + signal-catching harness). Regression guard if anyone ever changes panic strategy.
- No-alloc-on-hot-path audit: reuses A6.5 Group 5's `bench-alloc-audit` wrapper. Adds a dedicated unit test that exercises `poll_once`, `send_bytes`, and event-emit paths with `allocations == 0` assertion.
- C++ consumer under ASan + UBSan + LSan: `examples/cpp-consumer/main.cpp` built in a CI matrix with sanitizers enabled, runs a scripted connect → send → recv → close against a loopback peer. Catches ABI-boundary issues a pure-Rust build can't see.
- Panic audit: static pass (grep + manual review) over FFI-reachable code paths for `panic!`, `unwrap`, `expect`, unchecked indexing. FFI-reachable panics either eliminated (converted to errno returns) or documented in `docs/superpowers/reports/panic-audit.md` with unreachable-by-construction rationale.
- Counters data-race audit: the `dpdk_net_counters` header currently exposes `uint64_t` fields backed by Rust `AtomicU64`. Either regenerate the header with `_Atomic uint64_t` / `std::atomic<uint64_t>` guards (cbindgen config change), or add a compile-time static-assert in the C++ consumer example that reads must use `__atomic_load_n`. Document the chosen approach in the header.
- Report artifact: `docs/superpowers/reports/ffi-safety-audit.md` — lists every check, its evidence, and any residual risks carried forward.

**Out of scope:**
- TCP correctness fuzzing (A9 owns TCP-Fuzz differential + smoltcp FaultInjector).
- ABI-boundary fuzzing (arbitrary sequence of ABI calls via cargo-fuzz). Deferred — A9's differential harness is the natural home; repeating here would duplicate tooling.
- `cargo-semver-checks` / formal semver tooling — pre-1.0, the ABI snapshot is the contract.
- TSan. Single-lcore RTC model means no cross-thread data races exist by construction; adding TSan would exercise a zero-race codepath and add CI minutes without catching real issues. Documented as a non-goal in the report.

---

## 2. Module layout

### 2.1 A6.6 — Modified modules

**`crates/dpdk-net-core/src/`:**

| Module | Change |
|---|---|
| `tcp_conn.rs` | `RecvQueue.bytes: VecDeque<u8>` → `VecDeque<InOrderSegment>`. Introduce `struct InOrderSegment { mbuf: Mbuf, offset: u16, len: u16 }`. Drop struct retires `rte_pktmbuf_free` via `Mbuf::Drop`. Field `last_read_buf: Vec<u8>` retired. Byte-count accounting (`recv_buffered_bytes()`) sums `seg.len` across the VecDeque. |
| `tcp_reassembly.rs` | Already mbuf-ref after A6.5 Group 4. A6.6 changes the *draining* interface: `drain_contiguous_into(rcv_nxt: u32, out: &mut VecDeque<InOrderSegment>)` — appends mbuf-ref segments directly into `RecvQueue.bytes` without an intermediate collection. |
| `engine.rs` | `poll_once` RX path — no change to refcount-bump (already in A6.5) — but the post-reassembly drain yields `InOrderSegment`s that land in `RecvQueue.bytes`. READABLE emit: walks `RecvQueue.bytes` up to `max_read_bytes`, pops segments whose full length fits, splits the last segment if partial, and populates a per-conn `readable_scratch_iovecs: RefCell<Vec<dpdk_net_iovec_t>>` with `(mbuf.data_ptr() + offset, len)` pairs per popped segment. Scratch grown once, retained. Popped `InOrderSegment`s stored on a per-conn `delivered_segments: Vec<InOrderSegment>` until the *next* poll iteration drops them (mbuf refcount lifetime = "until next `dpdk_net_poll`"). |
| `engine.rs` — config | `EngineConfig` gains `rx_mempool_size: u32` (0 = compute default). |
| `mempool.rs` | No signature change. Pool sizing driven by new `EngineConfig` field at `engine_create`. |

**`crates/dpdk-net/src/`:**

| Module | Change |
|---|---|
| `api.rs` | Add `#[repr(C)] struct dpdk_net_iovec_t { const uint8_t *base; uint32_t len; uint32_t _pad; }` (12 bytes → padded to 16 B for alignment across 32/64-bit consumers). Change `dpdk_net_event_readable_t`: drop `data` + `len`; add `segs: *const dpdk_net_iovec_t`, `n_segs: u32`, `total_len: u32`. Add `dpdk_net_engine_config_t.rx_mempool_size: u32`. |
| `lib.rs` | `dpdk_net_poll` event-emit path writes `event.readable.segs = conn.readable_scratch_iovecs.borrow().as_ptr()`, `n_segs = iovec_count`, `total_len = Σ iovec_len`. Engine-owned scratch has lifetime = "until next `dpdk_net_poll`". |
| `include/dpdk_net.h` (cbindgen-regenerated) | New struct `dpdk_net_iovec_t`. Reshaped `dpdk_net_event_readable_t`. New config field `rx_mempool_size`. Doc comments on lifetime contract. |

**`examples/cpp-consumer/main.cpp`:** Updated to iterate `segs[0..n_segs]` instead of `data[0..len]`.

### 2.2 A6.7 — Modified/added modules

| Location | Change |
|---|---|
| `.github/workflows/ci.yml` (or equivalent) | New jobs: `miri`, `header-drift`, `cpp-sanitizer`. |
| `crates/dpdk-net-core/tests/miri_*.rs` | Subset of pure-core tests tagged to run under miri. |
| `xtask/src/check_header.rs` | New xtask: regen `include/dpdk_net.h` into tmp; `diff` against committed; exit non-zero on drift. |
| `tests/abi/dpdk_net.h.expected` | Committed snapshot of the locked header. |
| `crates/dpdk-net/tests/panic_firewall.rs` | Fork a child process, invoke a test-only `dpdk_net_panic_for_test()` ABI entry, assert child aborts with SIGABRT. |
| `crates/dpdk-net/tests/no_alloc_hotpath.rs` | Extends A6.5's `bench-alloc-audit` harness with a dedicated unit-test invocation. |
| `examples/cpp-consumer/Makefile` (or CMake) | Sanitizer matrix build. |
| `docs/superpowers/reports/panic-audit.md` | Committed deliverable. |
| `docs/superpowers/reports/ffi-safety-audit.md` | Committed deliverable summarizing all A6.7 checks + evidence. |
| `crates/dpdk-net/cbindgen.toml` | Optionally: emit `_Atomic uint64_t` guards for counter fields. |

No new runtime crate dependencies. `cargo +nightly miri` is a CI-only toolchain addition.

### 2.3 Dependencies introduced

- **A6.6 → A6.5 Group 4** (OOO reassembly mbuf-refs + READABLE event pin). Firm blocker.
- **A6.6 → A-HW** (LRO exercise path). Soft — A6.6 ships correct single-seg behavior regardless; A-HW validates the multi-seg path under realistic load.
- **A6.7 → A6.6** (audit the final contract).

---

## 3. Data flow

### 3.1 A6.6 — RX delivery path after change

```
ENA RX burst
  → DPDK driver (LRO may concatenate segs into chained mbuf)
  → engine.poll_once rx loop (refcount bump already happens per A6.5 Group 4)
  → tcp_input (header parse, checksum, flow lookup)
  → tcp_reassembly (OOO merge, mbuf-ref-held per A6.5 Group 4)
  → tcp_reassembly.drain_contiguous_into(rcv_nxt)        ← A6.6 changes signature
  → RecvQueue.bytes: VecDeque<InOrderSegment>            ← A6.6 new storage
                                                           (mbuf refs held here
                                                            until user consumes)
  → dpdk_net_poll event-emit:
      - Walk RecvQueue.bytes, pop up to max_read_bytes
        worth of segments (split tail if partial)
      - Move popped segs to TcpConn.delivered_segments    ← refs held here until
                                                           NEXT poll iteration
      - Write iovec views into TcpConn.readable_scratch_iovecs
      - Emit dpdk_net_event_readable_t with segs pointing
        into readable_scratch_iovecs
  → User reads segs[0..n_segs] — each iovec.base is a
    pointer into mempool-backed DMA memory
  → NEXT dpdk_net_poll: at top of poll_once, drain
    prev_delivered_segments across all conns
    (Mbuf::Drop → rte_pktmbuf_free). Reset
    readable_scratch_iovecs lengths to 0.
```

Validity window: **identical to A6.5's contract** — "valid until the next `dpdk_net_poll` on the same engine." Only the backing memory changes (mbuf-backed, not `Vec<u8>`).

### 3.2 Scatter-gather at the ABI

```c
// C++ consumer
dpdk_net_event_t ev;
if (dpdk_net_poll(eng, &ev, 1, 0) == 1 && ev.kind == DPDK_NET_EVT_READABLE) {
    auto &r = ev.readable;
    // Zero-copy: read each segment directly from DMA memory.
    for (uint32_t i = 0; i < r.n_segs; ++i) {
        parser.feed(r.segs[i].base, r.segs[i].len);
    }
    // r.total_len == Σ r.segs[i].len
    // Any pointer in r.segs is only valid until next dpdk_net_poll(eng, ...).
}
```

Single-segment hot path: `n_segs == 1`. Consumers can fast-path this check if they want contiguous-only processing.

### 3.3 A6.7 — Audit flow (not data flow)

Each check runs independently in CI; no runtime data-flow changes. Reports are static artifacts reviewed manually at phase-close.

---

## 4. API and configuration (A6.6)

### 4.1 New C types

```c
typedef struct dpdk_net_iovec_t {
    const uint8_t *base;   // 8 B (x86_64 only; project targets DPDK x86_64)
    uint32_t       len;    // 4 B
    uint32_t       _pad;   // 4 B, explicit for deterministic layout + zero-init
} dpdk_net_iovec_t;        // 16 B, naturally aligned

typedef struct dpdk_net_event_readable_t {
    dpdk_net_conn_t          conn;
    const dpdk_net_iovec_t  *segs;        // borrowed; valid until next dpdk_net_poll on this engine
    uint32_t                 n_segs;
    uint32_t                 total_len;   // Σ segs[i].len
} dpdk_net_event_readable_t;
```

### 4.2 Engine config addition

```c
typedef struct dpdk_net_engine_config_t {
    // ... existing fields ...
    uint32_t rx_mempool_size;   // 0 = compute default: recv_buffer_bytes
                                // × max_conns / avg_payload_bytes × 2.
                                // Clamped to >= 2 × RTE_ETH_RX_DESC_DEFAULT.
} dpdk_net_engine_config_t;
```

### 4.3 Removed fields

From `dpdk_net_event_readable_t`:
- `const uint8_t *data` — replaced by `segs[0].base` when `n_segs == 1`, or scatter-gather otherwise.
- `uint32_t len` — replaced by `total_len`.

ABI break flagged in A6.6's CHANGELOG entry and in cbindgen-generated header comment.

---

## 5. Invariants and edge cases (A6.6)

1. **Refcount safety.** Each `InOrderSegment` holds one `Mbuf`, which holds one DPDK mbuf refcount. When the segment drops (either via `RecvQueue.bytes.pop_front` landing in `delivered_segments`, or `delivered_segments` being cleared at next poll), `Mbuf::Drop` calls `rte_pktmbuf_free`, which decrements and frees if zero. No double-free possible because `Mbuf` is not `Copy`.
2. **Partial segment on delivery.** If the user's `max_read_bytes` boundary falls inside a segment, that segment is split: an `InOrderSegment { mbuf: split_ref, offset: new_offset, len: remaining }` stays on `RecvQueue.bytes`; the delivered portion `{ mbuf: original_ref, offset: original_offset, len: taken }` goes to `delivered_segments`. The split calls `rte_mbuf_refcnt_update(+1)` and builds a second `Mbuf` wrapper over the same underlying `rte_mbuf` (the `Mbuf` type needs an explicit `try_clone()` method added in A6.6 — a plain `Clone` derive would silently over-bump on accidental copies, so the API is intentionally explicit).
3. **Multi-segment mbuf chains.** Each link in an `rte_mbuf` chain maps to one `InOrderSegment` (and one `dpdk_net_iovec_t`). No flattening. Chain traversal happens inside `tcp_input` RX path where it's already needed for checksum verification and header parsing.
4. **Pool exhaustion.** RX mempool empty on next `rte_eth_rx_burst` → the NIC starts dropping; engine bumps `obs.rx_mempool_empty` counter (existing from A2). A6.6 does not change this behavior; it only increases the steady-state mbuf hold time by one poll iteration's worth, which the `rx_mempool_size` default accounts for (safety factor 2).
5. **Connection close with held mbufs.** `dpdk_net_close` → `Engine::close_conn` drains `RecvQueue.bytes` and `delivered_segments` immediately. No user action required. Existing `force_close_etimedout` path (`engine.rs:1271`) extended to match.
6. **Engine drop with held mbufs.** `Engine::Drop` stops the NIC, then the per-conn `Drop`s release mbufs, then mempools `Drop`. Order is enforced by struct-member declaration order (already the case).
7. **Scratch lifetime.** `readable_scratch_iovecs` is cleared (`len = 0`, capacity retained) at the top of each `poll_once`. If the user calls `poll_once` twice without reading the previous event's `segs[]`, those pointers become invalid — both because the scratch is reused *and* because the backing `delivered_segments` mbufs are released in the same top-of-poll step. Contract: "valid only until the next `dpdk_net_poll` on the same engine" — documented in the `dpdk_net_event_readable_t` header comment and repeated in `07-events.md` (A12 docs phase).
8. **Zero-length READABLE events.** Never emit. If no segments available, no event — same as today.

---

## 6. Testing

### 6.1 A6.6

- `tests/rx_zero_copy_single_seg.rs` — connect + send + recv, assert `n_segs == 1`, `base` points inside the RX mempool (DPDK `rte_mempool_in_use` check via `rte_mbuf_raw_alloc_bulk` inspection).
- `tests/rx_zero_copy_multi_seg.rs` — forces chained mbufs via a synthetic LRO-like injection (tap-level since A-HW isn't a hard dep). Asserts segments arrive in order, total_len matches.
- `tests/rx_partial_read.rs` — user reads N bytes where N crosses a segment boundary. Asserts split works, next event resumes from the partial segment, no byte is lost or duplicated.
- `tests/rx_close_drains_mbufs.rs` — held mbufs released on close; pool fill count returns to baseline.
- `tools/bench-rx-zero-copy/` — criterion harness: poll-to-delivery ns/op, alloc count, pool occupancy over a 60-second steady-state trace.
- Existing reassembly/SACK tests updated to assert mbuf-ref storage (reuse A6.5 Group 4's test updates).

### 6.2 A6.7

- `tests/abi/header_drift.rs` — xtask-style integration test, invoked by CI.
- `tests/panic_firewall.rs` — fork + SIGABRT assertion.
- `tests/no_alloc_hotpath.rs` — extends A6.5 Group 5 harness.
- `examples/cpp-consumer/ci-sanitizer.sh` — CI entry for ASan/UBSan/LSan matrix build and run.
- miri job target — `cargo +nightly miri test --package dpdk-net-core --features miri-stub`.
- No new runtime tests beyond those; the audit produces reports, not correctness harnesses.

---

## 7. Observability additions

- **A6.6:**
  - `obs.rx_iovec_segs_total` (cumulative count of iovec segments emitted) — slow-path counter, increments per-event (coarse granularity). Enables "average segs per READABLE" computation by application.
  - `obs.rx_multi_seg_events` — counts events where `n_segs > 1`. Visibility into LRO effectiveness.
  - `obs.rx_partial_read_splits` — counts partial-segment splits on delivery. Indicator for tuning `max_read_bytes`.
- **A6.7:** No runtime counters. Audit outputs are static reports.

Per the counter-addition policy memory: all three are slow-path (per-event, not per-byte), batched by nature. No compile-time feature gate required.

---

## 8. Roadmap edits required

After this spec is approved:

1. `docs/superpowers/plans/stage1-phase-roadmap.md` phase-status table: insert two new rows between A6.5 and A7 — A6.6 "RX zero-copy (scatter-gather, LRO-compatible)" and A6.7 "FFI safety audit & hardening".
2. Add `## A6.6 — RX zero-copy (scatter-gather, LRO-compatible)` body section following existing shape (goal → spec refs → scope → deliverables → dependencies → rough scale).
3. Add `## A6.7 — FFI safety audit & hardening` body section.
4. No edits to A6.5's body — its Group 4 is a prerequisite, not duplicated work.
5. No edits to already-committed per-phase plan files (A1–A5.5). The A4 plan's deferral language ("a later phase (probably A10 perf work or the A6 API surface completion)") is left as historical context; the roadmap's A6.6 row is the now-authoritative pin.

---

## 9. Rough scale

- **A6.6:** ~14 tasks — 3 for `InOrderSegment` + RecvQueue migration, 2 for reassembly drain signature, 3 for poll emit + scratch + delivered_segments lifecycle, 2 for API struct + cbindgen header, 1 for `rx_mempool_size` plumbing, 2 for bench harness + tests, 1 for cpp-consumer update.
- **A6.7:** ~8 tasks — 1 per deliverable enumerated in §1, plus the two report artifacts.

Both phases run serially; no parallelism across them (A6.7 audits A6.6's output).

---

## 10. Review gates

Per project memory (`feedback_phase_mtcp_review`, `feedback_phase_rfc_review`, `feedback_per_task_review_discipline`):

- Each phase closes with `mtcp-comparison-reviewer` + `rfc-compliance-reviewer` subagents before the phase-complete tag.
- Each non-trivial implementation task within each phase gets spec-compliance + code-quality review subagents before moving on.
- All subagent dispatches use opus 4.7 per `feedback_subagent_model`.

---

## 11. Non-goals / deferred

- TX zero-copy (user-held buffer consumed without copy) — possible A6.8 or folded into A10/A13 if bench shows the copy is measurable.
- `dpdk_net_readable_flatten()` convenience helper — add if a consumer asks.
- cxx-bridge migration — stays cbindgen.
- TSan — model is single-lcore RTC, no threads, no benefit.
- ABI-boundary fuzzing — A9 territory.
- Formal semver tooling — pre-1.0, snapshot is the contract.
