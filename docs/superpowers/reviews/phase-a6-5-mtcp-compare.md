# Phase A6.5 — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent
- Date: 2026-04-20
- mTCP submodule SHA: `0463aad5ecb6b5bca85903156ce1e314a58efc19` (unchanged this phase; `third_party/mtcp/` not bumped)
- Our commit: `2bbb80053df6cf9933a0120df3ba004864d435e8` (branch `phase-a6.5`, worktree `/home/ubuntu/resd.dpdk_tcp-a6.5`, 14 commits / 13 tasks on top of `3fabd4d` master merge base)

## Summary

A6.5 is strictly internal-performance work: it retires every hot-path heap allocation on RX decode, TX build+emit, per-ACK processing, and per-tick timer fire. Wire bytes unchanged, public API unchanged, behavioural knobs unchanged. There is consequently zero expected behavioural divergence from mTCP's TCP state machine, and on review this holds up: every A6.5 change is either a direct mTCP-style pattern (per-core pool / pre-sized scratch) or an intentional Stage-1 architectural choice already recorded in the parent spec (mbuf-ref OOO model instead of mTCP's memcpy-into-ring-buffer model, no SACK OOO merge).

The one divergence worth calling out explicitly — A6.5 does NOT physically coalesce adjacent OOO segments on insert, where mTCP's `RBPut` DOES merge them into a single `fragment_ctx` — is an intentional consequence of the zero-copy contract (no payload concatenation across mbufs). It is documented in `tcp_reassembly.rs:10-15` and parent spec §7.3 as edited in this phase.

**Zero Must-fix.** Zero Missed-edge-cases. Two informational (FYI) notes around the OOO model's structural asymmetry with mTCP and the cascade-bucket audit surfacing. Three accepted-divergence entries drafted for human validation.

## Scope

Our files reviewed:
- `crates/resd-net-core/src/tcp_reassembly.rs` — `OooSegment` mbuf-ref struct, `ReorderQueue::insert` gap-carve + deferred-insert, `drain_contiguous_from_mbuf`, `ReorderQueue::Drop` refcount release, `DrainedMbuf::Drop` leak-safety.
- `crates/resd-net-core/src/engine.rs` — `tx_frame_scratch`, `timer_ids_scratch`, `conn_handles_scratch`, `pruned_mbufs_scratch`, `rack_lost_idxs_scratch` fields + usage in `poll_once` (L1554), `reap_time_wait` (L2380), TX data emit (L3909), ACK-prune (L2991).
- `crates/resd-net-core/src/mempool.rs` — `MbufHandle` RAII wrapper (refcnt_update(-1) on Drop).
- `crates/resd-net-core/src/tcp_timer_wheel.rs` — `BUCKET_INIT_CAP = 512` bucket pre-sizing, `drain_scratch` for cascade, `advance` index-loop + `clear()` to preserve bucket capacity.
- `crates/resd-net-core/src/l3_ip.rs` — `internet_checksum(&[&[u8]])` streaming fold with carry across chunks.
- `docs/superpowers/specs/2026-04-20-stage1-phase-a6-5-hot-path-alloc-elimination-design.md` (design spec, including new §7.6 scratch-reuse policy)
- `docs/superpowers/reports/alloc-hotpath.md` (audit evidence: 4.38M iters, 6.1 GiB, 138k ACKs, 206 retrans, allocs=0/frees=0/bytes=0 across the 30s measurement window)

mTCP files referenced (for pattern comparison; A6.5 is performance-only so no behavioural parity is expected):
- `third_party/mtcp/mtcp/src/tcp_ring_buffer.c:77-138` — `RBManagerCreate` + `RBInit`; per-core `rbm_pool_%u` + `frag_mp_%u` mempools.
- `third_party/mtcp/mtcp/src/tcp_ring_buffer.c:263-285` — `CanMerge` / `MergeFragments`.
- `third_party/mtcp/mtcp/src/tcp_ring_buffer.c:287-389` — `RBPut` merge-on-insert into pre-allocated `buff->head + putx` with linked-list of `fragment_ctx`.
- `third_party/mtcp/mtcp/src/tcp_ring_buffer.c:222-239` — `RBFree` walks `fctx` linked list on stream destroy.
- `third_party/mtcp/mtcp/src/tcp_send_buffer.c:28-94` — `SBManagerCreate` + `SBInit`; per-core `sbm_pool_%d` mempool + freeq of reused send-buffer shells.
- `third_party/mtcp/mtcp/src/tcp_send_buffer.c:113-120` — `SBFree` enqueues shell back to freeq instead of freeing.
- `third_party/mtcp/mtcp/src/tcp_out.c:137-221` — `SendTCPPacketStandalone`; builds TCP header + options + payload directly into `IPOutput`-returned mbuf pointer.
- `third_party/mtcp/mtcp/src/tcp_util.c:244-277` — `TCPCalcChecksum`; single-buffer fold (mbuf is always contiguous in mTCP).
- `third_party/mtcp/mtcp/src/memory_mgt.c:31-126` — `MPCreate` / `MPAllocateChunk` / `MPFreeChunk` slab pool (posix_memalign + mlock under root, stack freelist).
- `third_party/mtcp/mtcp/src/timer.c:17-144` — `InitRTOHashstore` / `AddtoRTOList`; hash-bucketed TAILQ with intrusive `timer_link` in `tcp_stream`.
- `third_party/mtcp/mtcp/src/tcp_stream.c:389-558` — `DestroyTCPStream`; calls `RBFree` + `SBFree` in fixed teardown order.

Spec sections in scope: parent spec §7.2 (zero-copy), §7.3 (RX reassembly, updated this phase), new §7.6 (hot-path scratch reuse policy), §10 (testing — alloc-audit gate).

## Findings

### Must-fix (correctness divergence)

*(none — 0 items)*

### Missed edge cases (mTCP handles, we don't)

*(none — 0 items)*

### Accepted divergence (intentional — draft for human review)

- **AD-1** — OOO reassembly: no physical merge on insert for mbuf-ref segments.
  - mTCP: `tcp_ring_buffer.c:287-389` (`RBPut`) memcpies payload into a single pre-allocated `buff->head + putx` ring-buffer slot, then walks the `fctx` linked list and *physically merges* adjacent `fragment_ctx` via `MergeFragments` at L275-285 (`b->seq = min_seq; b->len = max_seq - min_seq`). One stored fragment per contiguous run, regardless of how many arrival segments contributed.
  - Ours: `tcp_reassembly.rs:308-331` (`insert_merged`) inserts each carved gap-slice as a separate `OooSegment`. Module doc at L10-15 and parent-spec §7.3 explicitly record this: "Adjacent `OooSegment` entries do NOT coalesce (zero-copy contract: no payload concatenation across mbufs); they stay as separate seq-sorted entries and drain together when `rcv_nxt` matches each one's start seq in turn."
  - Suspected rationale: Zero-copy contract. mTCP's physical merge only works because `RBPut` already memcpies into one contiguous ring-buffer. Our model stores mbuf pointers + `(offset, len)` windows, so merging two segments that live in different mbufs would require concatenation (defeating zero-copy) or a chain structure (not present in `OooSegment`). The drain-time ordering invariant is preserved: `drain_contiguous_from_mbuf` walks adjacent entries in order when each one's `seq` satisfies the rcv_nxt cursor, so in-order delivery to the caller is identical in observable effect.
  - Spec/memory reference needed: parent spec §7.3 (edited this phase to describe the new model); `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §7.3 "RX reassembly".

- **AD-2** — Scratch lifecycle: per-engine `RefCell<Vec|SmallVec>` vs. mTCP's per-core mempools + freelists.
  - mTCP: `tcp_send_buffer.c:28-60` (`SBManagerCreate`) / `tcp_ring_buffer.c:77-138` (`RBManagerCreate`) allocate per-core DPDK mempools named `sbm_pool_%d` / `rbm_pool_%u` / `frag_mp_%u` and reuse chunks via an explicit `freeq` (e.g. `SBFree` at L113-120 enqueues the shell back; `SBInit` at L68-83 dequeues before falling back to `malloc`). `MPAllocateChunk` / `MPFreeChunk` (`memory_mgt.c:81-119` non-DPDK path, L181-196 DPDK path) are the underlying slab.
  - Ours: `engine.rs:852-870` pre-sizes each hot-path scratch (`tx_frame_scratch`, `timer_ids_scratch`, `conn_handles_scratch`, `pruned_mbufs_scratch`, `rack_lost_idxs_scratch`) at `Engine::new` with `Vec::with_capacity` / `SmallVec::with_capacity`. `RefCell<…>` borrow + `clear` + reuse at each call site (spec §7.6 rule 1).
  - Suspected rationale: Stage 1 is single-lcore per-Engine, so the entire process is essentially one "core". The `RefCell` is thread-local-effectively-by-construction (the engine is `!Send` for public API purposes and the RTC poll runs on one lcore). A full DPDK-style `rte_mempool` per scratch would buy nothing since there's no contention to amortize across, and would introduce a second ownership model. The resulting outcome is the same as mTCP's: zero steady-state heap churn once warmup completes.
  - Spec/memory reference needed: parent spec §7.6 rule 1 (added this phase); feedback memory `project_context.md` for RTC-single-lcore model.

- **AD-3** — `pruned_mbufs_scratch` initial capacity 256 vs. inline `SmallVec[16]` would spill once.
  - mTCP: Not a direct comparison — mTCP retransmit queue `sndvar->rtx_list` does not "prune into a scratch" because it frees mbufs inline inside its own list-walk (no RefCell-style FFI-outside-borrow constraint).
  - Ours: `engine.rs:865` `pruned_mbufs_scratch: RefCell::new(SmallVec::with_capacity(256))`. The audit (report L97-114) showed that without this pre-alloc, the first-doubling from inline-16 to heap-32 fired *inside the 30s measurement window*, not at warmup, because the in-flight depth reliably crosses 16 once RWND + send buffer settle.
  - Suspected rationale: Audit-driven (cited in the phase report). Pre-alloc at engine creation puts the heap spill before the `[alloc-audit] warmup end:` line in the test log. Capacity 256 is conservative versus typical in-flight depth (trading workload ≤ 64 in practice) but cheap — `NonNull<rte_mbuf>` is 8 bytes, so 256 × 8 = 2 KiB per engine. This is an intentional over-size, not an over-sight.
  - Spec/memory reference needed: `docs/superpowers/reports/alloc-hotpath.md` "Hot-path allocations surfaced NOT in the original roadmap list" (audit evidence).

### FYI (informational — no action required)

- **I-1** — Streaming-checksum fold with mid-chunk odd-byte carry is more general than anything mTCP needs.
  - mTCP: `tcp_util.c:244-277` (`TCPCalcChecksum`) takes a single `uint16_t *buf`, advances `while (nleft > 1) sum += *w++`, and handles a trailing odd byte with `sum += *w & ntohs(0xFF00)`. No multi-chunk fold, because the TCP header + options + payload are always laid out contiguously in the mbuf by construction (`SendTCPPacket` at `tcp_out.c:239-243` calls `IPOutput` which returns a contiguous write pointer into a single mbuf; `memcpy` at L317 fills the payload adjacent to the header).
  - Ours: `l3_ip.rs:37-68` (`internet_checksum(&[&[u8]])`) maintains a `carry: Option<u8>` across the `for chunk in chunks` boundary. Required by A6.5 because our path builds the 12-byte pseudo-header as a stack array, passes it as the first chunk alongside `[&tcp_header, &payload]`, and historically also had to skip the TCP-csum field offset (`tcp_input.rs` zero-split fold). A6.5's equivalence fuzz test (`tests/checksum_streaming_equiv.rs`) covers every combination of chunk lengths in `{0..15}` for the three-chunk case to prove carry correctness against a concatenation-then-fold reference. This is strictly a superset of mTCP's capability; no regression possible.

- **I-2** — Timer-wheel bucket pre-sizing reached through audit at cap=128 vs. 512.
  - mTCP: `timer.c:17-66` (`InitRTOHashstore` / `AddtoRTOList`). Intrusive TAILQ per bucket — `TAILQ_INSERT_TAIL(&mtcp->rto_store->rto_list[offset], cur_stream, sndvar->timer_link)` — embeds the list link directly in each `tcp_stream`. There is no "bucket capacity" concept because no array-backed storage exists; TAILQ insert is O(1) pointer assignment with no allocator call.
  - Ours: `tcp_timer_wheel.rs:90-97` Vec-backed buckets. A6.5 Task 10 sized `BUCKET_INIT_CAP = 512` after the audit at cap=128 caught 14 grows from cascade re-push in a 30s window (report L80-94). Choosing 512 was empirical, not RFC-prescribed. This is a consequence of our ownership-choice: a non-intrusive slot-table with `Vec<u32>` buckets cannot match mTCP's alloc-free intrusive TAILQ unless each bucket is over-sized at construction. The 4 MiB footprint (256 buckets × 8 levels × 2 KiB) is acceptable at Stage 1 (single engine, single lcore); if memory becomes a concern in Stage 2, per-level caps (level-0 high, level-7 low) could reclaim most of it. No behavioural divergence.

- **I-3** — `ReorderQueue::Drop` walks every held segment and decrements refcount — mirrors mTCP's `RBFree` pattern.
  - mTCP: `tcp_ring_buffer.c:222-239` (`RBFree`) → `FreeFragmentContext` at L149-163 iterates the linked list (`fctx = fctx->next`) and calls `FreeFragmentContextSingle`. Run from `DestroyTCPStream` at `tcp_stream.c:528-531` as part of stream teardown.
  - Ours: `tcp_reassembly.rs:394-404` (`impl Drop for ReorderQueue`) iterates `self.segments` and calls `drop_segment_mbuf_ref` (refcnt_update(-1)) per entry. Prevents refcount leak on RST / reaper / force-close while OOO is non-empty. Lifecycle parity with mTCP. Note the structural difference is visible in the `fctx` linked-list walk in mTCP vs. our `Vec<OooSegment>` iteration — both are correct.

- **I-4** — `DrainedMbuf::Drop` leak-safety for unconsumed handoffs.
  - mTCP: No direct analog. mTCP's RX path copies into the ring buffer (`RBPut` memcpy at `tcp_ring_buffer.c:322`), so "consuming" a drained range is just bumping `buff->head_offset`; there's no refcount to balance if the caller forgets. Our zero-copy model means every drain hands off exactly one refcount per returned mbuf entry, and a forgotten handoff would pin mbufs in the mempool until process exit.
  - Ours: `tcp_reassembly.rs:95-110` (`impl Drop for DrainedMbuf`) decrements refcount if `into_handle()` was never called. `tcp_reassembly.rs:121-127` (`into_handle`) uses `std::mem::forget(self)` to disarm the Drop when the mbuf has been transferred into an `MbufHandle`. This is a Rust idiom that has no C equivalent to compare against; it's listed here purely to note the lifecycle discipline that A6.5 added is a net improvement over "trust the caller".

- **I-5** — A6.5 does not touch per-connection `VecDeque<u8>` send/recv buffers.
  - Observation: Design spec §1 explicitly excludes per-connection one-shot allocations (send/recv queues, `timer_ids`) from A6.5 scope. mTCP's equivalent chunk allocation happens once at `SBInit` / `RBInit` (once per stream, then reused via `SBFree`/`RBFree` → freeq). Our per-connection `VecDeque` allocation also happens once per connection (at `TcpConn::new`), not per-segment. Both models pay one-shot-per-stream cost and neither surfaces in the steady-state audit. No finding.

## Verdict (draft)

**PASS-WITH-ACCEPTED**

Gate rule: phase cannot tag `phase-a6-5-complete` while any `[ ]` checkbox in Must-fix or Missed-edge-cases is open.

- Must-fix open checkboxes: **0**
- Missed-edge-case open checkboxes: **0**
- Accepted-divergence entries awaiting human annotation with concrete spec/memory citation: **3** (AD-1 OOO-no-physical-merge, AD-2 per-engine-RefCell-scratch vs. per-core-mempool, AD-3 pruned-mbufs-scratch pre-alloc=256).

All three ADs cite spec references already landed this phase (parent spec §7.3 edit, new §7.6, and `docs/superpowers/reports/alloc-hotpath.md` audit evidence). Human reviewer to confirm the citations are adequate and either (a) convert them to closed-AD entries in `docs/superpowers/reviews/accepted-deviations.md` or (b) demote to FYI if they are already documented to the reviewer's satisfaction in the parent spec + audit report combination.

No item in this review gates the phase-complete tag. The phase can tag once the parallel `phase-a6-5-rfc-compliance.md` review is also clean (which it is expected to be — zero wire bytes changed).
