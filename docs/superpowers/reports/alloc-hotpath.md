# A6.5 Hot-path Allocation Audit — Report

**Phase:** A6.5 (Hot-path allocation elimination)
**Tag:** phase-a6-5-complete (pending review gates)
**Scope:** RX decode, TX build+emit, per-ACK processing, per-tick timer fire.

## Call-sites retired

| # | File:Line (before refactor) | Before | After | Task |
|---|---|---|---|---|
| 1 | `engine.rs` TX `build_segment` scratch | `let mut frame = vec![0u8; 1600];` per call | `RefCell<Vec<u8>>` (`tx_frame_scratch`) field on `Engine`; borrow + clear + resize-if-needed | Task 1 |
| 2 | `tcp_input.rs` RX checksum | `Vec::with_capacity(12 + tcp_bytes.len())` + copy for `tcp_pseudo_csum` | stack `[u8; 12]` pseudo-header + streaming `internet_checksum::Csum` fold (helper retired) | Task 3 |
| 3 | `tcp_input.rs` zeroed-cksum scratch | `let mut scratch = tcp_bytes.to_vec();` (whole-segment copy) | split-and-zero fold over `&[&pseudo, head, &[0,0], tail]`, no copy | Task 3 |
| 4 | `tcp_output.rs` TX checksum | `Vec::with_capacity(12 + hdr + payload)` per TX | stack `[u8; 12]` + streaming csum over header slice + payload slice | Task 3 |
| 5 | `tcp_input.rs` / engine RACK `lost_indexes` | `let mut out: Vec<u16> = Vec::new();` per RTO fire | `SmallVec<[u16; 16]>` inline (Task 4); replaced in Task 10 with Engine-owned `rack_lost_idxs_scratch: RefCell<Vec<u16>>` (pre-sized cap=64) | Tasks 4, 10 |
| 6 | `engine.rs` RACK loss-event tuples | `vec![(e.seq, e.xmit_count as u32)]` per RTO fire | `SmallVec<[(u32, u32); 4]>` inline | Task 4 |
| 7 | `tcp_timer_wheel.rs::advance` return | `advance() -> Vec<(TimerId, TimerNode)>` | `advance() -> SmallVec<[(TimerId, TimerNode); 8]>` | Task 4 |
| 8 | `tcp_retrans.rs::prune_below` return | `prune_below() -> Vec<RetransEntry>` | `prune_below() -> SmallVec<[RetransEntry; 8]>` (Task 4); engine hot-path now uses `prune_below_into_mbufs(&mut SmallVec<[NonNull<rte_mbuf>; 16]>)` draining into Engine-owned `pruned_mbufs_scratch` (Task 10) | Tasks 4, 10 |
| 9 | `engine.rs` timer-id list iteration (3 sites) | `conn.timer_ids.to_vec()` | `RefCell<SmallVec<[TimerId; 8]>>` (`timer_ids_scratch`) field on `Engine`; borrow + clear + extend-from-slice | Task 5 |
| 10 | `tcp_reassembly.rs` OOO segment storage | `OooSegment { payload: Vec<u8> }` (per-segment heap copy) | `OooSegment { mbuf: Mbuf, offset: u16, len: u16 }` via `OooSegment::MbufRef` (Tasks 6–9 land progressively; Task 9 retires the `Bytes` variant entirely) | Tasks 6–9 |
| 11 | `tcp_reassembly.rs` insert-path `to_insert` | `let mut to_insert: Vec<(u32, Vec<u8>)>` + per-gap `Vec::from(slice)` | deferred-insert using `SmallVec<[(u32, u16, u16); 4]>` of `(seq, off, len)` indices into the source mbuf, zero copy | Task 7 |
| 12 | `tcp_reassembly.rs::insert` edge-trim | `payload[off..].to_vec()` on left/right trim | `MbufRef { offset, len }` with adjusted `(off, len)`, still points into original mbuf | Task 7 |
| 13 | `tcp_reassembly.rs::drain_contiguous_from` | `drain_contiguous_from() -> (Vec<u8>, u32)` coalescing + copying into a new Vec | `drain_contiguous_from_mbuf() -> SmallVec<[DrainedMbuf; 4]>` returning mbuf refs with `(offset, len)` | Task 8 |
| 14 | `tcp_conn.rs` receiver-side byte buffer | `last_read_buf: Vec<u8>` (reallocated per READABLE event) | `last_read_mbufs: SmallVec<[Mbuf; 4]>` holding mbuf refs; event carries `(mbuf_idx, offset, len)` | Task 8 |
| 15 | `engine.rs::poll_once` per-poll handle list | `let handles: Vec<_> = ft.iter_handles().collect();` for per-conn `last_read_mbufs.clear()` | Engine-owned `conn_handles_scratch: RefCell<SmallVec<[ConnHandle; 8]>>`; borrow + clear + extend + drain | Task 10 |
| 16 | `engine.rs::reap_time_wait` candidate list | `let candidates: Vec<_> = { … iter_handles().filter(…).collect() };` per poll | reuse of `conn_handles_scratch`; filter-loop pushes, pop-drain with re-released borrow across `transition_conn` | Task 10 |
| 17 | `tcp_timer_wheel.rs` per-bucket storage | `const EMPTY_BUCKET: Vec<u32> = Vec::new();` → first-push reallocates on every fresh bucket | `Vec::with_capacity(BUCKET_INIT_CAP = 512)` per bucket (8 levels × 256 buckets = 2048 Vec<u32>), plus `drain_scratch: Vec<u32>` for cascade | Task 10 |
| 18 | `tcp_timer_wheel.rs::advance` bucket drain | `let bucket = std::mem::take(&mut self.buckets[0][cursor]);` (left bucket at zero-cap) | index-loop + `clear()` preserves heap capacity for next sweep | Task 10 |
| 19 | `tcp_timer_wheel.rs::cascade` bucket drain | `let bucket = std::mem::take(&mut self.buckets[level][cursor]);` | `std::mem::swap` with `drain_scratch`, index-loop, then `clear` + `swap` back; preserves both bucket and scratch cap across cascades | Task 10 |

## Audit-run evidence

`bench-alloc-audit` wraps the system allocator with atomic counters and installs
itself as `#[global_allocator]` only inside the integration test binary. The
test drives a single real `Engine` over a DPDK TAP vdev against a kernel-side
sink server (read-and-discard) to keep the peer's receive window wide open; the
client-side hot path sends MSS-sized segments as fast as `send_bytes` accepts
them, and `poll_once` runs the full RX/TX/ACK/timer-wheel cycle each
iteration.

```
$ RESD_NET_TEST_TAP=1 sudo -E cargo test -p resd-net-core \
    --features bench-alloc-audit --test bench_alloc_hotpath \
    --release -- --nocapture

running 1 test
resd_net: port 0 driver=net_tap rx_offload_capa=0x000000000000200e tx_offload_capa=0x000000000000802e dev_flags=0x00000042
resd_net: PMD on port 0 does not advertise RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE (0x0000000000004000); degrading to software path for this offload
resd_net: PMD on port 0 does not advertise RTE_ETH_RX_OFFLOAD_RSS_HASH (0x0000000000080000); degrading to software path for this offload
resd_net: port 0 configured rx_offloads=0x000000000000000e tx_offloads=0x000000000000800e
resd_net: RX timestamp dynfield/dynflag unavailable on port 0 (ENA steady state — see spec §10.5)
[alloc-audit] warmup end: sent=2049312552 conn state=Some(Established) rx_rst=0 tx_rst=0 conn_rst=0 conn_close=0 tx_rto=0 tx_retrans=78 rx_fin=0 tx_fin=0
[alloc-audit] steady-state: 4379152 iters, 6130812800 sent-bytes, \
    tx_data+=4379152, rx_ack+=137920, poll_iters+=4379152, \
    tx_retrans+=206, rx_rst+=0, tx_rst+=0 | allocs=0, frees=0, bytes=0
test hot_path_allocates_zero_bytes_post_warmup ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 42.94s
```

**Gate: PASS.** Across a 30-second post-warmup measurement window, with
4.38M poll iterations, 6.1 GiB transmitted, 4.38M data-segment emits, and
138k ACK-processing passes, the counting allocator recorded zero
allocations, zero frees, and zero bytes allocated.

`rx_rst=0`, `tx_rst=0` confirm the hot path ran without peer-initiated
teardown during the measurement window. `tx_retrans=206` across 4.38M
segments (≈0.005%) indicates the RACK/RTO retransmit path was exercised
in-window and remained alloc-free — retransmit emit reuses the
Engine-owned `tx_frame_scratch` and the SendRetrans mbufs, and the RTO
handler uses `rack_lost_idxs_scratch` (retirement table row 5) plus
`rack_mark_losses_on_rto_into` rather than the legacy Vec-returning
variant.

## Hot-path allocations surfaced NOT in the original roadmap list

Two allocation sites were surfaced by audit runs at the original caps and
retired before the final gate:

- **`tcp_timer_wheel.rs::add` bucket push** (rows 17–19 of the retirement
  table). The original design of Task 10 step-up in `tcp_timer_wheel.rs`
  pre-sized each bucket to `BUCKET_INIT_CAP = 128` based on steady-state
  arming rate (≈80 slots per level-0 bucket at the observed ~100K ACK/s
  arming rate). The audit ran cleanly for level-0 arrivals at that cap, but
  the first run caught 14 amortized grows in a 30-second window
  (`allocs=14, frees=14, bytes=14336` — 1024 B each, matching a
  `grow_amortized` from 128 to 256 × 4 B). The backtrace sampler under
  `bench-alloc-audit-backtrace` pinpointed the call site at
  `tcp_timer_wheel.rs:124` (`self.buckets[level][bucket_idx].push(slot)`)
  reached from `tcp_input` → ACK-path timer-arm. Disposition: the extra
  depth comes from **cascade re-push**, not from steady-state arming — when
  a level-1 bucket (655 ms of arms) cascades, its entries distribute into
  level-0 buckets that may see a transient spike well past 128.
  `BUCKET_INIT_CAP` was bumped to 512 to cover cascade's observed P99.
  Re-run audit surfaced the second site below.

- **`engine.rs::pruned_mbufs_scratch` first-doubling**. With the wheel-
  cap fix in place, a follow-up audit caught a single amortized grow:
  `allocs=1, frees=1, bytes=1024`. Backtrace under
  `bench-alloc-audit-backtrace` pinpointed
  `tcp_retrans.rs:107`
  (`SendRetrans::prune_below_into_mbufs` → `SmallVec::push` →
  `try_grow`). Root cause: the per-ACK pruned-mbuf drain scratch on
  `Engine` was declared as `SmallVec<[NonNull<rte_mbuf>; 16]>` with
  default (empty) capacity — the first poll whose prune count
  exceeded 16 triggered a one-shot spill from inline to heap (cap
  16 → 32 = 1024 B). In the audit workload, in-flight depth reliably
  crosses 16 once the send buffer and RWND settle, so this fired
  inside the measurement window rather than during warmup.
  Disposition: pre-allocate
  `pruned_mbufs_scratch: RefCell::new(SmallVec::with_capacity(256))`
  at engine construction so the heap spill happens at startup (still
  one-shot, now well outside the audit window). Re-run audit was
  clean (`allocs=0, frees=0, bytes=0`).

No other allocations were surfaced. The audit harness additionally
paces `poll_once` with a 50 µs `thread::sleep` every 64 iterations —
a workaround for an orthogonal issue: at the ~100 MB/s unthrottled
rate of the TAP→kernel sink, the kernel stack intermittently RSTs
mid-stream. The sleep does not mask allocations (the counter keeps
counting regardless); it just lowers the flake rate. Even so, the
test tolerates a peer-initiated RST during the measurement window
by relaxing the `frees == 0` assertion (per-connection teardown is
explicitly out-of-scope, spec §1); the `allocs == 0` assertion stays
strict.

## Carried forward

- The `bench_alloc_audit` module is reusable. A10 criterion harnesses
  import it directly. A6.7's no-alloc-on-hot-path test imports it.
- OOO end-to-end refcount verification (synthetic TAP peer) deferred to
  A6.6 / A10 integration work (see `tcp_input.rs` comment at the OOO insert
  site).
- Call-sites excluded from A6.5's scope (per-connection one-shot,
  engine-creation, slow-path error/logging) documented in the design spec
  §1 "Out of scope."
- `BUCKET_INIT_CAP = 512` trades 4 MiB of wheel-level heap
  (512 u32 × 4 B = 2 KiB per bucket; BUCKETS=256 × LEVELS=8 × 2 KiB
  = 4 MiB) against zero-alloc in steady state. If memory becomes a
  concern, per-level caps (level-0 high, level-7 low) could reclaim
  most of the budget.
- The audit test relaxes the `frees_delta == 0` assertion when a
  peer-initiated RST is observed during the measurement window
  (`rx_rst > 0`, `tx_rst > 0`, or the connection's flow-table entry
  is gone). Per-connection teardown is explicitly out-of-scope per
  spec §1 ("Out of scope: per-connection one-shot allocations,
  engine-creation, slow-path error/logging"). The `allocs_delta == 0`
  assertion stays strict under all conditions — teardown should drop
  existing mbufs and free the connection entry, not allocate new
  heap. If `tx_retrans > 0` we also expect frees from the
  pruned-mbufs drain path; that's accounted for by the same
  relaxation (an RST-driven teardown is effectively a bulk
  prune-all).

## Gate status

- Audit alloc-delta: **0 allocations / 0 frees / 0 bytes** across a
  30-second, 6.1 GiB, 4.38M-segment, 138k-ACK, 206-retrans measurement
  window.
- All integration tests pass:
  - `cargo test -p resd-net-core` (non-audit, default features):
    **374 lib tests pass; 0 failed.** All integration test suites pass
    under default (non-TAP) mode; TAP-gated integration tests that were
    hit in-session (`tcp_basic_tap`, `tcp_options_paws_reassembly_sack_tap`,
    `tcp_rack_rto_retrans_tap` non-ignored subset) re-verified ok after
    the wheel cap + pruned-mbufs scratch changes.
