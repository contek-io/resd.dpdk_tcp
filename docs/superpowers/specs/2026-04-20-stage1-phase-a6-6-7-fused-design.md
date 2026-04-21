# Phase A6.6 + A6.7 Fused — RX zero-copy + FFI safety audit (Fused Design Spec)

**Status:** Design approved (brainstorm 2026-04-20). Implementation plan to land as a single fused plan file under `docs/superpowers/plans/`.
**Parent spec (combined, not mutated):** `docs/superpowers/specs/2026-04-20-stage1-phase-a6-6-and-a6-7-rx-zero-copy-and-ffi-safety-audit-design.md`.
**Parent spec (Stage 1 design):** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.
**Roadmap rows:** `docs/superpowers/plans/stage1-phase-roadmap.md` §§ A6.6 + A6.7 (both marked Complete with one shared tag at phase-close).
**Branch / worktree:** `phase-a6.6-7` in `/home/ubuntu/resd.dpdk_tcp-a6.6-7`, branched from `master` tip `fa3cfcd` (includes phase-a6, phase-a-hw, phase-a6.5 merged).
**End-of-phase tag:** `phase-a6-6-7-complete` (single tag covering both phases). No intermediate tags. Tag stays local.

---

## 0. Purpose of this fused spec

Two adjacent phases — A6.6 (RX zero-copy scatter-gather) and A6.7 (FFI safety audit) — share an execution context: A6.7 audits the ABI shape that A6.6 finalizes. Running them as separate plans would mean A6.7 snapshots the pre-A6.6 shape, then re-does the snapshot. The task description directed a fusion: one plan, one execution, one tag.

This fused spec:

1. **Layers on** the existing combined design spec (the "parent combined spec"), citing it for scope/rationale details that have not changed.
2. **Absorbs post-A6.5 deltas** that shift where A6.6 starts (the mbuf refcount path is partly zero-copy already; the combined spec's "replace VecDeque<u8> with VecDeque<InOrderSegment>" is still pending but the `last_read_mbufs` mechanism is in place).
3. **Records the eight design decisions** resolved during the 2026-04-20 brainstorm, each with a short rationale.
4. **Re-states the task groups** for both phases as they shape up after the decisions, and pins task-level ordering + dependencies.
5. Identifies the **single end-of-phase gate** (mTCP + RFC reviewers, parallel, opus 4.7) that tags the fused work complete.

The parent combined spec remains authoritative for unchanged detail (data-flow diagrams §3, invariants §5, etc.). Where this fused spec conflicts with the parent, this spec wins.

---

## 1. Baseline deltas absorbed (post-A6.5)

All citations are to the `/home/ubuntu/resd.dpdk_tcp-a6.6-7` worktree at commit `fa3cfcd` (master tip including the A6.5 merge).

### 1.1 `MbufHandle` is the owning type

Parent combined spec calls the owning RAII type `Mbuf`. In the code there are two distinct types:

- `Mbuf` at `crates/dpdk-net-core/src/mempool.rs:76-99` — non-owning, `Copy`, raw-pointer wrapper (A3 vintage). Used by `SendRetrans::RetransEntry.mbuf`. **Not** owning.
- `MbufHandle` at `crates/dpdk-net-core/src/mempool.rs:122-162` — owning RAII handle on `NonNull<rte_mbuf>`. `Drop` impl at line 159 calls `shim_rte_mbuf_refcnt_update(..., -1)`. Explicitly NOT `Clone` (doc comment at lines 120-121 directs callers to bump refcount + fresh `from_raw` if another reference is needed). Added in A6.5 Task 8.

**Resolution:** A6.6 uses `MbufHandle` throughout (not `Mbuf`). Parent combined spec's "Mbuf" is re-interpreted as "`MbufHandle`" without renaming the existing `Mbuf` type. A6.6 adds an **explicit** `MbufHandle::try_clone(&self) -> Self` method (refcount-bump + fresh `from_raw` wrapper) — not a `Clone` derive, per the existing type's comment policy.

### 1.2 `conn.recv.bytes: VecDeque<u8>` still present

`crates/dpdk-net-core/src/tcp_conn.rs:44-58` — `RecvQueue` today has both:
- `bytes: VecDeque<u8>` (line 45) — the in-order byte ring still exists.
- `last_read_mbufs: SmallVec<[MbufHandle; 4]>` (line 57) — the most-recently-delivered mbuf refs (A6.5 Task 8).

`engine.rs:3744-3746` still does `pop_front` `total_delivered` times on `conn.recv.bytes`, with a code comment naming A6.6 as the phase that retires the byte ring. **A6.6 Group 1 retires `bytes: VecDeque<u8>` and replaces it with `bytes: VecDeque<InOrderSegment>`.** Byte-count accounting switches from `bytes.len()` to `recv.buffered_bytes()` (helper that sums `seg.len`).

### 1.3 `Event::Readable` is already mbuf-indexed

`crates/dpdk-net-core/src/tcp_events.rs:41-55` — the internal `Event::Readable` variant carries `(conn, mbuf_idx, payload_offset, payload_len, rx_hw_ts_ns, emitted_ts_ns)`. **Not** byte-based. A6.6 reshapes this to `(conn, seg_idx_start, seg_count, total_len, ...)` indexing into `TcpConn.delivered_segments` (new).

### 1.4 `dpdk_net_poll` already resolves mbuf → ptr at the C ABI

`crates/dpdk-net/src/lib.rs:375-429` — `dpdk_net_poll` reads `c.recv.last_read_mbufs[mbuf_idx].as_ptr()`, computes `base + payload_offset`, and fills the current `readable.data` field. **The current single-seg READABLE path is already zero-copy at the C ABI boundary.** A6.6 is a shape evolution from `(data, data_len)` to `(segs, n_segs, total_len)`, not a first-ever zero-copy cutover.

### 1.5 `tcp_reassembly::drain_contiguous_from_mbuf` already exists

`crates/dpdk-net-core/src/tcp_reassembly.rs:357` — signature `pub fn drain_contiguous_from_mbuf(&mut self, rcv_nxt: u32) -> SmallVec<[DrainedMbuf; 4]>`. `OooSegment` (line 42) holds `NonNull<rte_mbuf>` + `offset: u16` + `len: u16`. **No `Vec<u8>` payload copies anywhere.**

A6.6 changes the *consumer* of this output (to append into `VecDeque<InOrderSegment>` rather than bridging through `bytes: VecDeque<u8>`), and changes the *ingress* (walk `rte_mbuf.next` chains to enqueue one `OooSegment` per link). The signature may evolve to an output-param form for alloc-free appending.

### 1.6 `scripts/check-header.sh` already exists; `build.rs` runs cbindgen

- `crates/dpdk-net/build.rs` regenerates `include/dpdk_net.h` on every `cargo build -p dpdk-net`.
- `scripts/check-header.sh` (existing, 10 lines) runs the build + `git diff --quiet include/dpdk_net.h` — exits non-zero on drift.

**A6.7 reuses, does not rebuild.** The header-drift check is effectively done; A6.7 only polishes the error message and wires it into the top-level hardening aggregator.

### 1.7 No `xtask/`, no `tools/`, no `bench-rx-zero-copy/`

The workspace (`Cargo.toml:3-8`) has exactly four members: `crates/dpdk-net-sys`, `crates/dpdk-net-core`, `crates/dpdk-net`, `tests/ffi-test`. No `xtask/` or `tools/` directories exist.

**Resolution:** A6.6 creates `tools/bench-rx-zero-copy/` as a new workspace member. A6.7 does **not** create `xtask/` — the header-drift check is already script-based (§1.6).

### 1.8 `examples/cpp-consumer/main.cpp` doesn't currently read events

`examples/cpp-consumer/main.cpp:66-70` — the poll loop discards events (`(void)n`). **A6.6's cpp-consumer update is a pure addition** (start reading events and iterate `readable.segs[0..n_segs]`), not a migration of existing code.

### 1.9 RX path does not walk `rte_mbuf.next` today

`crates/dpdk-net-core/src/lib.rs:50-54` (`mbuf_data_slice`) + `crates/dpdk-net-sys/shim.c:67-75` (shim) handle first-segment only. ENA does not advertise `RX_OFFLOAD_SCATTER` per spec §8.2. **A6.6's multi-seg ingest is new ground**, guarded behind "walks chains if present." A6.6 adds the missing shim (`shim_rte_pktmbuf_next` if not already exported) + the walk loop in `tcp_input`'s reassembly-enqueue path.

### 1.10 `dpdk_net_*` prefix stays

The task description used `resd_net_*` in several places, but the actual codebase uses `dpdk_net_*` prefix consistently. User confirmed during brainstorm that we keep matching the code — **no rename**. This spec uses `dpdk_net_*` throughout.

---

## 2. Design decisions resolved (2026-04-20 brainstorm)

Each decision lists: the chosen option, two-line rationale, and the parent-combined-spec language it supersedes (if any).

### Decision 1 — In-order queue shape

**Chosen: Option C — single `VecDeque<InOrderSegment>`, `bytes` retired, byte-count computed on demand.**

`RecvQueue.bytes: VecDeque<u8>` → `VecDeque<InOrderSegment>`. Add `impl RecvQueue { fn buffered_bytes(&self) -> u32 { self.bytes.iter().map(|s| s.len as u32).sum() } }`. Retire the parallel `Vec<u8>` ring entirely.

*Rationale:* Two-queue designs (parent spec's implicit shape, or explicit B in brainstorm) create a two-queues-must-stay-in-sync invariant with no perf win — `bytes.len()` call sites are all slow-path (flow-control accounting, close-drain). Single queue with `Σ seg.len` is simpler.

### Decision 2 — iovec type shape

**Chosen: Option A — `dpdk_net_iovec_t { const uint8_t *base; uint32_t len; uint32_t _pad; }`.**

16 bytes, explicit trailing `_pad` for deterministic layout. Matches parent combined spec verbatim.

*Rationale:* POSIX-compat (`void *iov_base; size_t iov_len`) would suit `writev(2)` but consumers here parse received bytes in-place; no value. `const uint8_t *` enforces read-only semantics on the C side. `uint32_t len` is plenty (MTU << 4 GB). `_pad` gives reproducible layout for ABI snapshot + consumer `static_assert`. 16 B total on 64-bit targets (x86_64 + ARM64 Graviton — the current Stage 1 targets); on 32-bit ARM the struct would be 12 B. The ABI is not 32-bit-compatible, which is an accepted scope bound: Stage 1 targets AWS ENA, which means x86_64 nitro or Graviton — both 64-bit.

### Decision 3 — `rx_mempool_size` default formula + queryable getter

**Chosen: Option B-generous, plus a new FFI getter.**

Default at `engine_create` when `cfg.rx_mempool_size == 0`:

```
rx_mempool_size = max(
    4 * rx_ring_desc,
    2 * max_conns * ceil(recv_buffer_bytes / 2048) + 4096
)
```

where `2048` is the DPDK-default mbuf data-area size (assumption documented in header + consumer-visible; matches `cfg.mbuf_data_room` default at `engine.rs:328`). The `+ 4096` constant is absolute slack in mbufs — tolerates one full RX-burst drain while the delivered-pending-drain mbufs from the previous poll are still held. Result sizes:

- 64 conns × 64 KB bufs → ~8 K mbufs ≈ 16 MB pool
- 64 conns × 256 KB bufs → ~20 K mbufs ≈ 40 MB pool
- 64 conns × 1 MB bufs → ~70 K mbufs ≈ 140 MB pool

New slow-path FFI getter:

```c
/* Returns the RX mempool capacity actually in use (user-supplied when
 * cfg.rx_mempool_size != 0, else the computed default). UINT32_MAX on null. */
uint32_t dpdk_net_rx_mempool_size(const struct dpdk_net_engine *p);
```

*Rationale:* Parent combined spec's formula `recv_buffer_bytes × max_conns / avg_payload_bytes × 2` with `avg_payload = 512` overshoots by ~100× in typical trading configs (1 MB × 64 / 512 × 2 = 256 K mbufs ≈ 512 MB). The descriptor-driven formula keeps pool size linearly proportional to actual in-flight bytes + 2× slack for delivered-pending-drain + 4 × rx-ring floor for burst bursts. The `× 2` "generous" factor on per-conn usage covers A6.6's new hold-until-next-poll semantic. User requested the value be queryable for operational visibility — new getter `dpdk_net_rx_mempool_size()`.

**Supersedes parent combined spec §4.2 formula.**

### Decision 4 — Multi-segment emission timing

**Chosen: Option A — walk `rte_mbuf.next` at reassembly-ingest (not at emit).**

When `tcp_input` enqueues a received segment into reassembly, it walks the chain. Each `rte_mbuf` link becomes one `OooSegment { mbuf_handle, offset, len }` entry. At emit, iovec materialization is a linear copy of descriptor fields — no chain traversal needed.

*Rationale:* DPDK chain mutation post-rx-burst is not part of any contract we rely on; refcount ownership is taken at RX. Walk-at-insert keeps `InOrderSegment.len: u16` trivially valid (each link ≤ MTU-ish, well under 64 KB). Walk-at-emit (parent combined spec's implicit shape) would force chain-structure awareness into reassembly/SACK boundary computation and would require `len: u32` (pkt_len). Simpler here to pay the walk once at ingest.

**Supersedes parent combined spec §3.1 "Walk happens at emit, not insert" (the brainstorm task-description hint).**

### Decision 5 — miri scope

**Chosen: Option A — pure-compute modules only; no synthetic `NonNull<rte_mbuf>` shims.**

miri-covered test modules: `siphash24`, `iss`, `rtt_histogram`, `tcp_rack`, `tcp_rtt`, `tcp_sack`, `tcp_seq`, `tcp_state`, `tcp_tlp`, `tcp_options`, `tcp_events` (internal-type invariants), `error`, `counters`, `clock`.

miri-ignored (any test touching sys::* or holding `NonNull<rte_mbuf>` in data): `arp`, `engine`, `l2`, `l3_ip`, `mempool`, `tcp_conn`, `tcp_input`, `tcp_output`, `tcp_reassembly`, `tcp_timer_wheel`, `tcp_retrans`, `flow_table`. Marked `#[cfg_attr(miri, ignore)]` on the test fns.

Gated behind new feature `miri-safe` on `dpdk-net-core` (compile-time marker; matches A6.5's `bench-alloc-audit` cargo-feature pattern).

*Rationale:* Aggressive coverage (option B with `NonNull::dangling()` shims) means tests don't exercise real pointer interactions — exactly the shim-divergence anti-pattern flagged in the task description. Pure-compute coverage catches what miri is best at (UB in arithmetic, aliasing in hashes, overflow in seq-space) at zero shim cost.

### Decision 6 — ABI snapshot format

**Chosen: Option A — single committed `include/dpdk_net.h`; no separate `.expected` file.**

The committed `include/dpdk_net.h` **IS** the snapshot. `scripts/check-header.sh` (existing) regenerates via `cargo build -p dpdk-net` and `git diff --quiet`. Drift = script exits non-zero. Intentional change: run build, `git add include/dpdk_net.h` — the `git diff` on the PR IS the ABI-change review artifact.

*Rationale:* Parent combined spec's `tests/abi/dpdk_net.h.expected` duplicates what the already-committed header provides, with no added review signal. cbindgen output is deterministic (stable whitelist order, no timestamps). One artifact, one place to read, one `git diff` for reviewers. Maintenance scenarios that would justify the dual-file design (cbindgen version bumps, normalizer changes) don't exist.

**Supersedes parent combined spec §2.2 `tests/abi/dpdk_net.h.expected` bullet.**

### Decision 7 — Counters atomic-load exposure

**Chosen: Option C — ship `include/dpdk_net_counters_load.h` helper header.**

New manually-written (not cbindgen-generated) header `include/dpdk_net_counters_load.h` next to `dpdk_net.h`. Inline static functions:

```c
static inline uint64_t dpdk_net_load_u64(const uint64_t *p) {
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}
```

Documented as the sanctioned API for reading counters on any target (x86_64, ARM64, ARM32). On x86_64 this compiles to a plain `mov` — zero runtime cost. On ARM32 it compiles to LDREXD/LDRD for atomic 64-bit load — required for correctness.

`dpdk_net.h` doc-comment at lines 175-184 sharpened to point at the helper as the required reader API. `examples/cpp-consumer/main.cpp` adds a compile-time `static_assert(sizeof(std::atomic<uint64_t>) == sizeof(uint64_t) && alignof(std::atomic<uint64_t>) == alignof(uint64_t))` — defense in depth against layout mismatches.

*Rationale:* User confirmed during brainstorm that **ARM is on the project roadmap** (saved as memory `project_arm_roadmap.md`). On ARM32, plain `uint64_t` loads are not atomic without LDREXD/LDRD; ARM64 has weaker memory-ordering semantics than x86. The helper header gives a single cross-platform correct reader; the `static_assert` catches layout regressions at build time.

**Supersedes parent combined spec §1 "cbindgen config change vs C++ consumer static_assert" bullet.**

### Decision 8 — Hardening runtime = scripts, not CI workflows

**Chosen: Option A — two natural script units (miri; asan+ubsan+lsan); no GitHub Actions wiring in this phase.**

Scripts under `scripts/hardening-*.sh`:

- `scripts/hardening-miri.sh` — Rust nightly, `cargo +nightly miri test -p dpdk-net-core --features miri-safe`.
- `scripts/hardening-cpp-sanitizers.sh` — clang-22, builds cpp-consumer with `-fsanitize=address,undefined` (LSan auto-enabled with ASan on Linux), runs scripted connect→send→recv→close (TAP-backed via existing `RESD_NET_TEST_TAP=1` flow).
- `scripts/hardening-panic-firewall.sh` — wraps `cargo test -p dpdk-net --features test-panic-entry --test panic_firewall`.
- `scripts/hardening-no-alloc.sh` — wraps the no-alloc-hotpath test run.
- `scripts/audit-panics.sh` — grep + classification for FFI-reachable panic/unwrap/expect sites.
- `scripts/hardening-all.sh` — top-level aggregator, runs all of the above sequentially, exits non-zero on first failure.

No `.github/workflows/*.yml` in this phase — user directive. A future phase may wire these scripts into CI.

*Rationale:* miri needs nightly Rust + `-Z miri` toolchain — distinct build from the sanitizer flow's clang-22. Combining them in one script would couple unrelated failures. asan+ubsan+lsan share one clang-22 build naturally — one script is the right granularity. Four-way split (miri, asan, ubsan, lsan each separate) wastes compile time on near-identical builds. The nightly-Rust dependency for miri is the single exception to the "latest stable Rust" rule from user memory, acceptable because miri is a CI-only audit tool, not a build-toolchain dependency.

**Supersedes parent combined spec §2.2 `.github/workflows/ci.yml` bullet.**

### Decision add-on — criterion dependency

**Chosen: Option 1 — add `criterion` to the workspace.**

`tools/bench-rx-zero-copy/` uses `criterion = "0.5"` (latest stable on crates.io at time of writing; confirm during task-1 setup). Becomes a `[dev-dependencies]` / workspace-level bench dep only; no runtime crates depend on it.

*Rationale:* User preference over hand-rolled timing during brainstorm. Standardized statistical output, HTML report generation, and A10-phase compatibility outweigh the added dep. This is one of the explicit exceptions carved out by the task description ("no Cargo deps beyond what miri/sanitizer/cbindgen-xtask require — confirm during brainstorm"); confirmed here.

---

## 3. A6.6 — Revised task groups (post-decisions)

Parent combined spec §1/§2 shape retained; this section re-states groups with the decisions applied. Deltas vs parent are flagged **[Δ]**.

### Group 1 — `MbufHandle::try_clone` + `InOrderSegment` + `RecvQueue` migration

- Add `impl MbufHandle { pub fn try_clone(&self) -> Self }` in `mempool.rs`. Explicit method call, not a `Clone` derive. Refcount-bump via `shim_rte_mbuf_refcnt_update(+1)` + fresh `MbufHandle::from_raw`. **[Δ vs parent — parent said `Mbuf::try_clone`]**
- **Refcount-bookkeeping invariant:** In `try_clone`, the `shim_rte_mbuf_refcnt_update(+1)` MUST be the last statement before the infallible `Self::from_raw(self.ptr)` — no intervening allocations, no panickable calls, no fallible operations. This guarantees that any path that returns before `from_raw` runs has not bumped the refcount; any path that bumps the refcount also constructs the `MbufHandle` that will decrement it on Drop. Post-split invariant: the same underlying `rte_mbuf` refcount equals the number of `(queue_entry | delivered_segments_entry)` that reference it — a partial read with split produces refcount N+1 (original on queue, split portion on delivered_segments), which drops back to N-1 at the next `poll_once` when delivered_segments is drained.
- New `pub struct InOrderSegment { pub mbuf: MbufHandle, pub offset: u16, pub len: u16 }` in `tcp_conn.rs`. Drop semantics inherited from `MbufHandle`.
- Audit-and-migrate step (grep-driven): every reader of `conn.recv.bytes: VecDeque<u8>` (`.len()`, `.push_back()`, `.pop_front()`, `.extend_from_slice()`, `.iter()`) identified and either:
  - flow-control accounting: rewrite to `recv.buffered_bytes()` helper (`Σ seg.len`), OR
  - byte-consumption in emit: rewrite to work on `InOrderSegment` entries.
- Flip `RecvQueue.bytes: VecDeque<u8>` → `VecDeque<InOrderSegment>`. Add `impl RecvQueue { pub fn buffered_bytes(&self) -> u32 }`. **[Δ vs parent — Decision 1]**
- Existing `RecvQueue.last_read_mbufs: SmallVec<[MbufHandle; 4]>` is subsumed by `TcpConn.delivered_segments: SmallVec<[InOrderSegment; 4]>` introduced in Group 3. Keep `last_read_mbufs` around during task-level transition if needed, retire by end of Group 3.

### Group 2 — Reassembly-drain + multi-seg ingest

- `tcp_reassembly::drain_contiguous_from_mbuf` signature evolves from `fn(&mut self, rcv_nxt: u32) -> SmallVec<[DrainedMbuf; 4]>` to `fn(&mut self, rcv_nxt: u32, out: &mut VecDeque<InOrderSegment>)` — appends directly, no intermediate collection. `DrainedMbuf::into_handle()` is inlined at the append site.
- On reassembly-ingest from a chained mbuf (`rte_mbuf.next != NULL`): walk the chain, `rte_mbuf_refcnt_update(+1)` per link, enqueue one `OooSegment` per link with that link's `data_off` + `data_len`. **[Δ vs parent — Decision 4, walk-at-insert not walk-at-emit]**
- Shim surface: confirm/add `shim_rte_pktmbuf_next` (if not already exported); update `shim.c:67` first-seg-only comment.
- `tcp_input` RX path `mbuf_data_slice(m)` usage audit — any site that assumed single-seg must either handle chain (for payload concat) or document its single-seg-only scope.

### Group 3 — Scatter-gather public ABI + poll-emit plumbing

- `api.rs`: add `#[repr(C)] pub struct dpdk_net_iovec_t { pub base: *const u8, pub len: u32, pub _pad: u32 }`. 16 bytes. **[Δ — Decision 2]**
- `api.rs`: reshape `dpdk_net_event_readable_t`:
  ```rust
  #[repr(C)]
  pub struct dpdk_net_event_readable_t {
      pub segs: *const dpdk_net_iovec_t,  // borrowed; valid until next poll
      pub n_segs: u32,
      pub total_len: u32,
  }
  ```
  Drops `data` + `data_len`.
- `api.rs`: add `pub rx_mempool_size: u32` to `dpdk_net_engine_config_t`. **[Δ — Decision 3]**
- **Per-conn** `TcpConn.readable_scratch_iovecs: Vec<dpdk_net_iovec_t>` (not flat-on-engine — see Invariant 7 in §10). Capacity grown on first delivery to cover the conn's worst-case iovec count. Cleared (`len = 0`, capacity retained) at the top of each `poll_once`'s per-conn emit, before any push.
- New `TcpConn.delivered_segments: SmallVec<[InOrderSegment; 4]>` holds popped segments until the **next** `poll_once` drains them (refcount lifetime = "until next `dpdk_net_poll`").
- Rationale for per-conn scratch (not flat on Engine): the C consumer reads `segs[]` AFTER `dpdk_net_poll` returns — the pointer must remain valid while subsequent events within the same poll (belonging to other conns) are emitted. A single flat scratch would force either "allocate all iovecs up front with known bounds" or "one big Vec with disjoint slices per event"; per-conn storage gives a clean lifetime (valid from emit-push until the next `poll_once` clears that conn's scratch).
- `dpdk_net_poll` emit rewrite (`crates/dpdk-net/src/lib.rs:381-419` region):
  - Pop up to `max_read_bytes` worth of segments from `conn.recv.bytes` into `conn.delivered_segments` (split the tail segment if partial; `MbufHandle::try_clone()` on the split).
  - For each `InOrderSegment` in `delivered_segments`, push `dpdk_net_iovec_t { base: mbuf.data_ptr() + offset, len, _pad: 0 }` into `engine.readable_scratch_iovecs`.
  - Write the event: `segs = scratch.as_ptr()`, `n_segs = scratch.len()`, `total_len = Σ seg.len`.
- `Event::Readable` internal shape (`tcp_events.rs:41-55`) evolves: `(conn, mbuf_idx, payload_offset, payload_len, ...)` → `(conn, seg_idx_start, seg_count, total_len, ...)` indexing into `delivered_segments`.
- `last_read_mbufs` retired at the end of Group 3.

### Group 4 — Pool sizing + query getter

- `EngineConfig.rx_mempool_size: u32` (Rust-side core) + matching `dpdk_net_engine_config_t.rx_mempool_size` (C ABI).
- `engine_create` computes default when `cfg.rx_mempool_size == 0` per Decision 3 formula. Stores computed value on Engine for later read-back.
- `dpdk_net_rx_mempool_size(engine: *const dpdk_net_engine) -> u32` FFI — slow-path; returns the stored computed/user-supplied value. `UINT32_MAX` on null engine.
- cbindgen header comment above the `rx_mempool_size` field documents the formula verbatim + the 2048 mbuf-data-area assumption.

### Group 5 — Observability counters (slow-path)

- `obs.rx_iovec_segs_total: u64` — cumulative iovec count emitted across all READABLE events. Incremented per-event by `n_segs`.
- `obs.rx_multi_seg_events: u64` — count of events with `n_segs > 1`.
- `obs.rx_partial_read_splits: u64` — count of times a partial-segment split was needed on delivery.

All three: slow-path per counter policy memory (per-event granularity, not per-byte). No feature gate. Exposed via `dpdk_net_tcp_counters_t` in `dpdk_net.h`.

### Group 6 — cpp-consumer update + TAP tests

- `examples/cpp-consumer/main.cpp` — replace the current throw-away poll loop (lines 66-70) with a real reader that iterates `event.u.readable.segs[0..n_segs]`. Adds a CRC-of-bytes accumulator or similar to demonstrate parse-in-place usage. **[Δ vs parent — pure addition, no migration since the current code drops events]**
- New TAP-backed integration tests in `crates/dpdk-net-core/tests/`:
  - `rx_zero_copy_single_seg.rs` — connect/send/recv, assert `n_segs == 1`, `base` inside rx mempool range.
  - `rx_zero_copy_multi_seg.rs` — synthetic chained-mbuf injection at the reassembly enqueue point (no NIC LRO needed; the test constructs a `rte_mbuf.next` chain manually and calls the reassembly enqueue). Assert segment ordering + `total_len == Σ seg.len`.
  - `rx_partial_read.rs` — consumer reads N bytes crossing a segment boundary. Assert split semantics; next READABLE event resumes from the split remainder; no byte lost or duplicated.
  - `rx_close_drains_mbufs.rs` — forced close with held mbufs; verify `dpdk_net_rx_mempool_size() - rte_mempool_avail_count()` returns to baseline. **Requires adding `shim_rte_mempool_avail_count` to `crates/dpdk-net-sys/shim.c` + `wrapper.h` (not currently exported).** Lands in this Group 6 task.

### Group 7 — Bench harness

- New workspace member `tools/bench-rx-zero-copy/` with `Cargo.toml` + `benches/delivery_cycle.rs` using `criterion = "0.5"`. **[Δ — Decision add-on]**
- Benches:
  - poll-to-delivery ns/op for single-seg path.
  - poll-to-delivery ns/op for 2-seg and 4-seg chained-mbuf paths.
  - `bench-alloc-audit`-gated assertion that single-seg in-order delivery path has zero allocations post-warmup.
- Integrates with A10's broader benchmark harness when that phase lands.

---

## 4. A6.7 — Revised task groups (post-decisions)

Parent combined spec §1/§2 shape retained; deltas flagged **[Δ]**.

### Group 1 — Header drift + ABI snapshot (mostly reuse)

- `scripts/check-header.sh` error-message polish: point at `cargo build -p dpdk-net && git add include/dpdk_net.h` as the canonical fix. **[Δ vs parent — the `xtask`/`tests/abi/.expected` design is retired, Decision 6]**
- After A6.6's reshape lands, `include/dpdk_net.h` IS the locked snapshot. No separate `tests/abi/` file created.
- `docs/superpowers/reports/ffi-safety-audit.md` § ABI snapshot documents: "snapshot = committed header; drift = `scripts/check-header.sh` non-zero exit; regenerated by `cargo build -p dpdk-net`."

### Group 2 — miri (pure-compute subset)

- Add feature `miri-safe = []` to `crates/dpdk-net-core/Cargo.toml` (compile-time marker). **[Δ — Decision 5]**
- `scripts/hardening-miri.sh`: install nightly toolchain, install miri, run `cargo +nightly miri test -p dpdk-net-core --features miri-safe`. Nightly is the sole exception to the latest-stable-Rust rule, CI-only.
- Tests in `crates/dpdk-net-core/tests/` that touch sys::* or `NonNull<rte_mbuf>` tagged `#[cfg_attr(miri, ignore)]`. Pure-compute-only modules (Decision 5 list) run without ignore marks.
- Knob-coverage entry for the `miri-safe` feature (compile-time marker, matches A6.5 Task 12 `bench-alloc-audit` entry pattern).

### Group 3 — cpp-consumer sanitizers

- `scripts/hardening-cpp-sanitizers.sh`: builds `examples/cpp-consumer/main.cpp` with `CXXFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'`. LSan auto-enabled by ASan on Linux. Runs the existing (post-A6.6-update) connect→send→recv→close scenario against a TAP peer (reusing existing TAP-backed test infrastructure).
- Static_assert addition to `main.cpp`:
  ```cpp
  static_assert(sizeof(std::atomic<uint64_t>) == sizeof(uint64_t) &&
                alignof(std::atomic<uint64_t>) == alignof(uint64_t),
                "dpdk_net counters layout requires std::atomic<uint64_t> POD-compat");
  ```
- `#include "dpdk_net_counters_load.h"` + one usage site as a demonstrator.

### Group 4 — Counters atomic-load helper header

- New manually-written `include/dpdk_net_counters_load.h`. **[Δ — Decision 7]**
- Contents:
  - `#include <stdint.h>` + `#pragma once` + include guard.
  - `static inline uint64_t dpdk_net_load_u64(const uint64_t *p)` implemented with `__atomic_load_n(p, __ATOMIC_RELAXED)`.
  - Doc comment explaining: ARM-correctness contract, no-op on x86_64, expected usage site.
- `dpdk_net.h` doc comment at lines 175-184 sharpened to point at the helper as **the sanctioned** reader API.

### Group 5 — Panic firewall + no-alloc runtime tests

- Add feature `test-panic-entry = []` to `crates/dpdk-net/Cargo.toml`.
- New `crates/dpdk-net/src/test_only.rs` (gated `#[cfg(feature = "test-panic-entry")]`): exports `pub extern "C" fn dpdk_net_panic_for_test() -> ! { panic!("dpdk_net panic firewall test"); }`. NOT added to `cbindgen.toml` whitelist — tests declare the C prototype themselves.
- New `crates/dpdk-net/tests/panic_firewall.rs` (gated): uses `std::process::Command` to fork a helper binary (or re-exec current test binary with an env marker) that calls `dpdk_net_panic_for_test()`, asserts the child exits via SIGABRT. Regression guard for the `panic = "abort"` setting.
- `scripts/hardening-panic-firewall.sh`: wraps `cargo test -p dpdk-net --features test-panic-entry --test panic_firewall`.
- New `crates/dpdk-net-core/tests/no_alloc_hotpath_audit.rs` (gated `#[cfg(feature = "bench-alloc-audit")]`): reuses the `bench_alloc_audit::CountingAllocator` wrapper from A6.5. Exercises `poll_once` / `send_bytes` / event-emit through a representative workload, asserts `(alloc_count_delta, free_count_delta) == (0, 0)` post-warmup.
- `scripts/hardening-no-alloc.sh`: wraps the cargo invocation.

### Group 6 — Panic audit (static + manual)

- `scripts/audit-panics.sh`: grep `panic!|\.unwrap\(\)|\.expect\(|\bunchecked_` in `crates/dpdk-net/src/**/*.rs` and FFI-reachable paths in `crates/dpdk-net-core/src/**/*.rs`. Output classified into:
  - test-only (inside `#[cfg(test)]` / `#[cfg(feature = "test-panic-entry")]`) → drop.
  - slow-path (engine_create, Error formatters, Display impls) → accept.
  - hot-path (poll_once-reachable) → must convert to errno or document unreachable-by-construction with `// SAFETY: ...` comment.
- Output → `docs/superpowers/reports/panic-audit.md`. Each finding records: file:line, classification, action taken (errno conversion / unreachable comment / accepted).
- Any hot-path findings that get converted to errno returns → code edit as part of this task.

### Group 7 — Aggregator + reports + knob-coverage

- `scripts/hardening-all.sh`: sequential runner for Groups 1-6 scripts. Exits non-zero on first failure. Single entry point.
- `docs/superpowers/reports/ffi-safety-audit.md`: comprehensive summary — every check + evidence path + residual risks + audit run date. Lists: header-drift script exit status, miri test count + modules, sanitizer run date + consumer coverage, counters helper header location, panic-firewall test ID, no-alloc test ID, panic-audit findings count.
- Knob-coverage entries:
  - `miri-safe` feature (compile-time marker, matches A6.5 Task 12 pattern).
  - `test-panic-entry` feature (same pattern).
  - `rx_mempool_size` knob (A6.6 Group 4 knob — lands in A6.6 Group 4's task; knob-coverage entry in A6.7 Group 7 for tracking purposes).

---

## 5. Task-level ordering

Numbering 1–22; commit prefix `a6.6-7 task N:`. Per-task two-stage reviewer discipline (opus 4.7 parallel subagents: spec-compliance + code-quality) applies to all non-trivial tasks.

**A6.6 block (tasks 1-14):**
1. `MbufHandle::try_clone()` + `InOrderSegment` struct
2. Grep-audit + migrate every `conn.recv.bytes` reader to `InOrderSegment`-friendly form
3. Flip `RecvQueue.bytes: VecDeque<u8>` → `VecDeque<InOrderSegment>` + `buffered_bytes()` helper
4. `drain_contiguous_from_mbuf` signature → output-param form
5. Multi-seg ingest: walk `rte_mbuf.next` in reassembly-enqueue; add shim if missing
6. `dpdk_net_iovec_t` + reshape `dpdk_net_event_readable_t` in `api.rs`
7. `readable_scratch_iovecs` on Engine + `delivered_segments` on TcpConn; retire `last_read_mbufs`
8. `dpdk_net_poll` emit rewrite (iovec materialization + scratch/delivered lifecycle)
9. `Event::Readable` internal shape → `(seg_idx_start, seg_count, total_len)`
10. `EngineConfig.rx_mempool_size` + Decision 3 formula + `dpdk_net_rx_mempool_size()` getter
11. `obs.rx_iovec_segs_total` / `rx_multi_seg_events` / `rx_partial_read_splits` counters
12. `examples/cpp-consumer/main.cpp` — read events, iterate `segs[]`
13. TAP tests — single_seg, multi_seg, partial_read, close_drains
14. `tools/bench-rx-zero-copy/` criterion harness + alloc-audit assertion

**A6.7 block (tasks 15-22):**
15. `scripts/check-header.sh` error-message polish
16. `miri-safe` feature + test ignore-marks + `scripts/hardening-miri.sh`
17. `include/dpdk_net_counters_load.h` + `dpdk_net.h` doc polish + cpp-consumer static_assert
18. `scripts/hardening-cpp-sanitizers.sh`
19. `test-panic-entry` feature + `dpdk_net_panic_for_test()` + `panic_firewall.rs` test + script
20. `no_alloc_hotpath_audit.rs` test + script
21. `scripts/audit-panics.sh` + `panic-audit.md` report + any errno conversions / unreachable-comments
22. Knob-coverage entries (`miri-safe`, `test-panic-entry`, `rx_mempool_size` tracking) + `scripts/hardening-all.sh` aggregator + `ffi-safety-audit.md` summary

### Hard ordering constraints

- Tasks 1→2→3 strictly serial (type exists → migrate readers → flip storage).
- Task 4 depends on task 1 (`InOrderSegment` type exists).
- Task 5 can land anytime after task 1 but before task 13 (multi-seg test needs the walk).
- Tasks 6→7→8→9 serial block (ABI struct → scratch/delivered → emit → internal event shape).
- Task 10 independent of 6-9; can land any time after task 3.
- Task 11 depends on task 8 (emit path counts events).
- Tasks 12-14 require 1-11 complete.
- Tasks 15-16 have no A6.6 dependency — can land after 14 (simpler commit log) or interleaved.
- Tasks 17-20 require 12 (cpp-consumer must read events for sanitizer to exercise real code).
- Task 21 can parallelize with 17-20 (grep is pure-audit); result can be referenced in the Group 7 report.
- Task 22 last.

---

## 6. Commit / review / tag discipline

### Commits
- All commits land on branch `phase-a6.6-7` in worktree `/home/ubuntu/resd.dpdk_tcp-a6.6-7`.
- Subject prefix: `a6.6-7 task N:` (N ∈ [1, 22]) covers both phases with one counter.
- No intermediate tags.
- No force-pushes, no branch-push, no tag-push — local only; coordinator handles integration.
- Task 15 (one-line error message polish) may batch with another small A6.7 task if desirable; otherwise land standalone.
- **Header regeneration discipline:** any task that touches `crates/dpdk-net/src/api.rs`, `crates/dpdk-net/src/lib.rs` (FFI entry additions), or `crates/dpdk-net/cbindgen.toml` MUST run `cargo build -p dpdk-net` and include the regenerated `include/dpdk_net.h` in the same commit. Otherwise `scripts/check-header.sh` breaks at the task boundary. Tasks affected: 6, 7, 8, 10 (api.rs touches); any other task that adds an FFI export.

### Per-task review gate (opus 4.7, parallel)
- `superpowers:code-reviewer` subagent — spec-compliance pass against this fused spec + parent combined spec + parent Stage 1 design.
- Second reviewer (generalist, opus 4.7) — code-quality pass.
- Dispatched in parallel after implementation completes; both must return zero-open-[ ] before commit.
- Tasks with purely-mechanical changes (task 15, maybe task 22 knob-coverage additions) may skip one of the reviewers at the discretion of the implementer, but not both.

### End-of-phase gate (single pass, covers both phases)
- `mtcp-comparison-reviewer` subagent (opus 4.7) reviews both A6.6 + A6.7 output. Report → `docs/superpowers/reviews/phase-a6-6-7-mtcp-compare.md`.
  - Expected focus: scatter-gather iovec shape vs mTCP's `tcp_stream_read_buf` / chained-mbuf contract; ownership/lifetime discipline; any divergences.
  - FFI-audit items are scope-adjacent — brief treatment expected.
- `rfc-compliance-reviewer` subagent (opus 4.7) reviews both. Report → `docs/superpowers/reviews/phase-a6-6-7-rfc-compliance.md`.
  - Expected focus: no wire bytes changed; no new MUST/SHOULD gaps; iovec materialization preserves segment ordering + byte semantics.
- Dispatched in parallel.
- Tag `phase-a6-6-7-complete` only when both reports show zero open `[ ]`.

### Tag
- `phase-a6-6-7-complete` on HEAD of `phase-a6.6-7` branch.
- Local only. Not pushed.

### Roadmap
- `docs/superpowers/plans/stage1-phase-roadmap.md`: both A6.6 and A6.7 rows marked **Complete** with tag `phase-a6-6-7-complete`. Entries share the same tag. This is a convention deviation (prior phases are one-row-one-tag) — the fusion mandate produces one tag for two rows; the A6.6 row gets a one-line note pointing at the shared tag so future readers don't think a tag was missed.

---

## 7. Out of scope (explicit)

Re-confirmed from the task description and parent combined spec:

- TX zero-copy (user-held buffer consumed without copy). Future phase.
- OOO reassembly mbuf-ref refactor — **A6.5 owns, done.**
- `dpdk_net_readable_flatten()` convenience helper — YAGNI. Add if a consumer asks.
- WRITABLE event / backpressure — owned by A6.
- cxx-bridge migration — stays cbindgen.
- TCP correctness fuzzing / differential harness — A9.
- `cargo-semver-checks` / formal semver tooling — pre-1.0, snapshot is the contract.
- TSan — single-lcore RTC has no cross-thread races by construction.
- Synthetic TAP peer for OOO end-to-end — carried forward from A6.5 to A10.
- GitHub Actions CI wiring — Decision 8; scripts only, no workflows.
- ABI-boundary fuzzing (cargo-fuzz-driven random ABI call sequences) — natural home is A9.

---

## 8. New Cargo features + dependencies introduced

### Features

| Feature | Crate | Purpose | Default | Lifetime |
|---|---|---|---|---|
| `miri-safe` | `dpdk-net-core` | Compile-time marker for miri test subset | OFF | A6.7 Group 2 |
| `test-panic-entry` | `dpdk-net` | Gates `dpdk_net_panic_for_test()` FFI export | OFF | A6.7 Group 5 |

Existing `bench-alloc-audit` (A6.5 Task 10) is reused by A6.7 Group 5 — no new feature for no-alloc test.

### Dependencies

| Crate | Where | Why | Decision ref |
|---|---|---|---|
| `criterion` | `tools/bench-rx-zero-copy/` (new workspace member) | A6.6 Group 7 bench harness | Decision add-on |

No other new runtime or dev deps. miri and sanitizers are toolchain-only (nightly Rust, clang-22 sanitizer runtime).

---

## 9. Observability additions (all slow-path, per counter policy)

- `obs.rx_iovec_segs_total` — cumulative iovec count emitted across all READABLE events.
- `obs.rx_multi_seg_events` — events with `n_segs > 1`.
- `obs.rx_partial_read_splits` — partial-segment splits on delivery.

All three: increment per-event (not per-byte). No feature gate. Land in A6.6 Group 5.

A6.7 adds no runtime counters — its outputs are static reports.

---

## 10. Invariants + edge cases (deltas from parent combined spec §5)

Parent §5 is retained. Deltas:

- Invariant 2 (partial segment on delivery): uses `MbufHandle::try_clone()` explicitly, not a `Clone` derive. Split call path: `MbufHandle::try_clone()` returns a refcount-bumped wrapper over the same underlying `rte_mbuf`; the split `InOrderSegment` stays on `RecvQueue.bytes`, the delivered portion goes to `delivered_segments`.
- Invariant 7 (scratch lifetime): `readable_scratch_iovecs: Vec<dpdk_net_iovec_t>` lives on `TcpConn` (per-conn; **not** flat-on-Engine). Cleared at the top of each `poll_once`'s per-conn emit path. `TcpConn.delivered_segments: SmallVec<[InOrderSegment; 4]>` holds the backing `MbufHandle` refs; drained at the top of each `poll_once` (before any new event emission this poll). Per-conn placement ensures that after `dpdk_net_poll` returns with multiple events, each event's `segs` pointer still references its own conn's scratch — subsequent conns' emits cannot overwrite it.
- New invariant — multi-seg reassembly: each `rte_mbuf` chain link becomes exactly one `OooSegment` / `InOrderSegment` entry (walk-at-insert per Decision 4). Chain link ordering preserved; reassembly `seq_cmp` uses per-link `seq = base_seq + Σ prior_link_len`.

---

## 11. Documentation touched

- `docs/superpowers/reports/ffi-safety-audit.md` — new, authored during A6.7 Group 7.
- `docs/superpowers/reports/panic-audit.md` — new, authored during A6.7 Group 6.
- `docs/superpowers/reviews/phase-a6-6-7-mtcp-compare.md` — new, authored at end-of-phase gate (mTCP reviewer).
- `docs/superpowers/reviews/phase-a6-6-7-rfc-compliance.md` — new, authored at end-of-phase gate (RFC reviewer).
- `docs/superpowers/plans/stage1-phase-roadmap.md` — A6.6 + A6.7 rows updated to Complete with shared tag.
- No changes to the parent combined spec (this fused spec layers on top).

Docs related to public API consumption (`07-events.md` lifetime contract etc.) are touched only if A12 docs-phase has not started; if they exist, they get a one-line update noting the iovec lifetime contract. Otherwise deferred to A12.

---

## 12. Durable guidance applied throughout

All user-memory rules apply:

- Slow-path counters only by default; hot-path counters require feature gate + batched increment + justification.
- Observability = primitives only (counters + event timestamps). Applications aggregate + route.
- No peer-side throttling for flow control — surface pressure via counters.
- Prefer latency-favoring defaults over RFC recommendations when they conflict.
- Build toolchain: clang-22 from llvm.org + libstdc++.
- Runtime toolchain: latest stable Rust via rustup. **Exception:** miri needs nightly — CI-only audit tool, not a build dependency (Decision 5 / Decision 8 note).
- Parent Stage 1 spec §7.6 hot-path scratch reuse policy governs `readable_scratch_iovecs`, `delivered_segments`, and any new scratch introduced in this phase.
- Per-task two-stage reviewer discipline — spec-compliance + code-quality subagents (opus 4.7, parallel) before moving on.
- End-of-phase mTCP + RFC parallel gate reviewers (opus 4.7).

---

## 13. Spec self-review pass

Written fresh-eyes after drafting §§ 0-12:

- **Placeholder scan:** No "TBD" / "TODO" / vague requirements remaining. Version number for criterion (`0.5`) has a confirm-during-task-1 caveat, which is fine — pin to latest on crates.io at implementation time.
- **Internal consistency:** Task numbering (§5) matches group structure (§§ 3-4). Decision references (Decision N) all point to valid entries in §2. No contradictions spotted between decisions and task descriptions.
- **Scope check:** 22 tasks, one phase tag, one end-of-phase gate. Focused. No subprojects hiding inside.
- **Ambiguity check:** "implementation choice in task 7" for `readable_scratch_iovecs` location (per-conn vs flat) is intentional — the implementer resolves based on code-reading at that point. "One of the explicit exceptions carved out by the task description" for the criterion dep is explicit — confirmed during brainstorm. No other ambiguities detected.

Ready for user review.
