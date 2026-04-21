# Phase A6.6 + A6.7 — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent (opus 4.7)
- Date: 2026-04-21
- mTCP submodule SHA: `e0ea9a8`
- Pre-audit commit: `b4e8de9` (phase-a6.6-7 branch)
- Worktree: `/home/ubuntu/resd.dpdk_tcp-a6.6-7`

## Scope

Files reviewed (this stack):
- `crates/dpdk-net/src/api.rs` — FFI iovec + readable event surface
- `crates/dpdk-net/src/lib.rs` — `dpdk_net_poll` per-conn scratch materialization
- `crates/dpdk-net-core/src/tcp_conn.rs` — `RecvQueue.bytes`, `delivered_segments`, `readable_scratch_iovecs`, `InOrderSegment`
- `crates/dpdk-net-core/src/engine.rs` — `poll_once` clear-at-top, `deliver_readable`, pre-bump/rollback at engine ingress
- `crates/dpdk-net-core/src/tcp_input.rs` — in-order vs OOO chain walk, per-link refcount bumps
- `crates/dpdk-net-core/src/tcp_reassembly.rs` — `OooSegment`, deferred-insert pattern, `drain_contiguous_into`
- `crates/dpdk-net-core/src/mempool.rs` — `MbufHandle` Drop, `try_clone` invariant
- `crates/dpdk-net-core/src/iovec.rs` — `DpdkNetIovec` core type
- `crates/dpdk-net-core/src/tcp_events.rs` — `InternalEvent::Readable { conn, seg_idx_start, seg_count, total_len }`
- `docs/superpowers/reports/ffi-safety-audit.md` — A6.7 audit summary
- `docs/superpowers/reports/panic-audit.md` — A6.7 panic-audit results

mTCP files referenced (`third_party/mtcp/mtcp/src/`):
- `api.c` — `mtcp_recv`, `mtcp_readv`, `CopyToUser`, `PeekForUser`
- `dpdk_module.c` — `dpdk_recv_pkts`, `dpdk_get_rptr`, `ip_reassemble`, LRO path
- `tcp_in.c` — `ProcessTCPPacket`, `ProcessTCPPayload`, `ValidateSequence`
- `tcp_ring_buffer.c` — `RBPut` (copy-stack core)
- `eventpoll.c` — `mtcp_epoll_wait` (event delivery, no buffer pointer)

Spec citations:
- A6.6+A6.7 fused design: `docs/superpowers/specs/2026-04-20-stage1-phase-a6-6-7-fused-design.md`

## Summary verdict

**ALIGNED (PASS-WITH-ACCEPTED).**

Phase A6.6+A6.7 introduces an architectural category — **zero-copy receive via refcount-pinned mbuf iovecs** — that has no direct mTCP analog. mTCP is a copy-stack throughout (`RBPut` does `memcpy` at ingest into a per-stream ring; `mtcp_recv`/`mtcp_readv` do another `memcpy` to user buffers; mbufs are freed at the start of every next RX burst by `dpdk_recv_pkts`). Comparing axis-by-axis, four of the five user-requested axes have **no mTCP equivalent to evaluate against**, and the fifth (chain-ingest) reveals that **mTCP has a latent bug we explicitly defend against**, not the other way around. No must-fix or missed-edge-case findings emerged.

## Findings

### Must-fix (correctness divergence)

_None._

### Missed edge cases (mTCP handles, we don't)

_None._

### Accepted divergence (intentional — citations attached)

- **AD-1** — Receive contract: zero-copy iovec vs copy-stack
  - mTCP: `api.c:1121` `CopyToUser` does `memcpy(buf, rcvvar->rcvbuf->head, copylen)` then `RBRemove`; `api.c:1294` `mtcp_readv` iterates iovec calling `CopyToUser` per entry. mbuf data has already been copied into ring buffer at ingest by `RBPut` (`tcp_ring_buffer.c:287`).
  - Ours: `crates/dpdk-net/src/api.rs:169` `dpdk_net_event_readable_t { segs, n_segs, total_len }` exposes refcount-pinned `dpdk_net_iovec_t` array directly into mbuf payload memory; valid until next `dpdk_net_poll`.
  - Citation: per `~/.claude/projects/-home-ubuntu-resd-dpdk-tcp/memory/feedback_trading_latency_defaults.md` (prefer latency-favoring defaults over RFC recommendations) + fused design spec §2 Decision 1 (in-order queue shape) + Decision 2 (iovec shape). Trading-latency goal eliminates two `memcpy` passes (RX-burst→ring + ring→user). Lifetime-by-poll-edge contract is the design choice that makes this safe at the C ABI.

- **AD-2** — Mbuf refcount discipline: hold-across-delivery vs free-at-next-burst
  - mTCP: `dpdk_module.c:451` `dpdk_recv_pkts` calls `free_pkts` at the start of every burst — mbufs are NEVER held past a single burst, eliminating any refcount discipline question.
  - Ours: `crates/dpdk-net-core/src/tcp_conn.rs` `delivered_segments: SmallVec<[InOrderSegment; 4]>` holds refcount-pinned mbufs across the FFI boundary; `crates/dpdk-net-core/src/engine.rs` `poll_once` clears these at the TOP of the next poll (RAII Drop fires `shim_rte_mbuf_refcnt_update(-1)`); partial-pop split uses `crates/dpdk-net-core/src/mempool.rs:169` `MbufHandle::try_clone` (refcount `+1` is the last fallible operation before infallible `from_raw`).
  - Citation: fused design spec §2 Decision 1 (in-order queue shape) + §10 Invariant 7 (per-conn scratch lifetime). The refcount-bookkeeping invariant is documented in §3 Group 1 of the fused spec ("per-segment refcount equals number of `(queue_entry | delivered_segments_entry)` that reference it"). Hold-across-delivery is required to give the C consumer a stable pointer; mTCP's free-at-next-burst is incompatible with the zero-copy iovec contract.

- **AD-3** — Out-of-order/in-order chain ingest: walk-at-INSERT
  - mTCP: `tcp_in.c:1205` `ProcessTCPPacket` derives payload as `(uint8_t *)tcph + (tcph->doff << 2)` — head-mbuf-only; `tcp_in.c:602` `ProcessTCPPayload` calls `RBPut` once with the entire payload as a single contiguous span; `dpdk_module.c:517` `dpdk_get_rptr` reads only the first segment via `rte_pktmbuf_mtod`. mTCP **never inspects `m->next` or `m->nb_segs` on RX**, even though `ip_reassemble` and the LRO path can produce chained mbufs.
  - Ours: `crates/dpdk-net-core/src/tcp_input.rs` (in-order branch ~ line 902-1031, OOO branch ~1066-1201) both walk `shim_rte_pktmbuf_next` and emit one `InOrderSegment` (or `OooSegment`) per link; per-link refcount bumps at `tcp_input.rs:947` (head) and `:1006` (chain-tail) for in-order, `:1136` for OOO.
  - Citation: fused design spec §2 Decision 4 (multi-segment emission timing — walk-at-insert). Defense-in-depth against IP-reassembly-produced chains and any future LRO-without-flatten path. mTCP gets away with head-only because it copies into the ring at ingest; we cannot, since we expose mbuf memory directly. The reviewer's note that mTCP has a "latent bug" here means our walk-at-INSERT is more correct, not less.

- **AD-4** — Per-conn scratch ownership for iovec arrays
  - mTCP: `eventpoll.c:363` `mtcp_epoll_wait` returns events that contain only fd + event-mask; users call `mtcp_recv` separately afterward. There is **no buffer-pointer lifetime contract on the event itself**, so there's no scratch storage to own.
  - Ours: `crates/dpdk-net-core/src/tcp_conn.rs` `readable_scratch_iovecs: Vec<DpdkNetIovec>` per-conn; `crates/dpdk-net/src/lib.rs:372` `dpdk_net_poll` builds the `readable.segs` pointer from `conn.readable_scratch_iovecs.as_ptr().add(seg_idx_start)`. Per-conn (not flat-on-engine) so that emitting events for conn A then conn B in the same poll does not invalidate conn A's `segs` pointer (which the user has not yet read).
  - Citation: fused design spec §3 Group 3 ("per-conn placement ensures that after `dpdk_net_poll` returns with multiple events, each event's `segs` pointer still references its own conn's scratch — subsequent conns' emits cannot overwrite it"). The §10 Invariant 7 cross-event-pointer-invalidation discussion pins this as the chosen ownership model.

- **AD-5** — FFI safety practices: miri/ASan/UBSan/LSan/panic-firewall vs no Rust safety story
  - mTCP: pure C; no equivalent safety verification surface. `panic = "abort"` and Rust's compile-time guarantees have no analog.
  - Ours: A6.7 audit (`docs/superpowers/reports/ffi-safety-audit.md`) covers 8 checks (header drift, single ABI snapshot, miri pure-compute, cpp-consumer ASan/UBSan/LSan, panic firewall via FFI catch-unwind, no-alloc hot-path test, panic audit with 0 hot-path conversions needed + 10 hot-path documented unreachable-by-construction, counters atomic-load helper for ARM-readiness).
  - Citation: per `~/.claude/projects/-home-ubuntu-resd-dpdk-tcp/memory/feedback_phase_mtcp_review.md` (mTCP-comparison gate), the FFI-safety axis is scope-adjacent — mTCP has no Rust safety story to compare against. Per fused design spec §2 Decision 5 (miri scope), this is intentionally an orthogonal hardening surface.

### FYI (informational — no action required)

- **I-1** — mTCP's `ValidateSequence` (`tcp_in.c:107`) drops segments that exceed `rcv_wnd`. Our stack accepts and surfaces backpressure via counters per `feedback_performance_first_flow_control.md`. Already a documented divergence; restated for completeness.

- **I-2** — mTCP's `tcp_in.c:126` carries a TODO comment about TS.Recent invalidation for long idle flows. Our stack implements RFC 7323 §5.5 24-day TS.Recent expiration. mTCP's TODO is unimplemented; ours is implemented.

- **I-3** — mTCP's `tcp_ring_buffer.c:301` silently drops bytes whose offset is below `head_seq`. Our `tcp_reassembly.rs` reorder queue carves overlap precisely via `OooSegment { seq, mbuf, offset, len }` and the deferred-insert SmallVec pattern. mTCP's coarse drop is acceptable in the copy-stack model; ours has to be precise because we expose mbuf memory directly.

- **I-4** — mTCP sets `m->nb_segs = 1; m->next = NULL` on every TX mbuf, indirectly confirming that mTCP's TX path never produces chained mbufs. We do the same on TX (single-segment); the difference is purely on RX-walk.

- **I-5** — mTCP's LRO path under `PKT_RX_TCP_LROSEG` flattens chained mbufs via `memcpy`. This is mTCP's only acknowledgement that chains exist, and it resolves the chain by copying — consistent with the rest of its copy-stack design. Our path doesn't enable LRO offload; if we add LRO later, we'd want to keep the walk-at-INSERT pattern rather than copy-flatten.

- **I-6** — mTCP's `api.c:1102` `PeekForUser` is a non-destructive copy. We have no peek primitive at the FFI surface; the iovec contract implicitly is peek-like (data remains valid until next poll regardless of whether the user reads it).

## Action items (gate phase tag)

_All previously-open `- [ ]` items have been resolved by attaching the requested spec/memory citations directly to AD-1 through AD-5 above._

### Must-fix
_None._

### Missed edge cases
_None._

### Accepted divergence — citations attached
- [x] **AD-1** — Citation attached: `feedback_trading_latency_defaults.md` + fused design spec §2 Decisions 1 & 2.
- [x] **AD-2** — Citation attached: fused design spec §2 Decision 1 + §10 Invariant 7 + §3 Group 1 refcount-bookkeeping invariant.
- [x] **AD-3** — Citation attached: fused design spec §2 Decision 4 (walk-at-INSERT).
- [x] **AD-4** — Citation attached: fused design spec §3 Group 3 + §10 Invariant 7 (cross-event-pointer-invalidation).
- [x] **AD-5** — Citation attached: `feedback_phase_mtcp_review.md` + fused design spec §2 Decision 5.

### FYI
_None require action._

## Verdict

**PASS**

Gate rule: Must-fix and Missed-edge-cases sections are empty (no `- [ ]` correctness items). Accepted-divergence section is fully cited; all 5 ADs `[x]` complete. Phase may tag `phase-a6-6-7-complete`.

The substance: A6.6+A6.7 introduces a fundamentally different receive contract (zero-copy iovec, refcount-pinned mbufs, lifetime-by-poll-edge) than mTCP's copy-stack. Our implementation is internally consistent with that contract and defends against an edge case (chained mbufs from IP reassembly) that mTCP has a latent bug in. The phase is not actionably divergent from mTCP; it is *intentionally orthogonal* to mTCP's design space.
