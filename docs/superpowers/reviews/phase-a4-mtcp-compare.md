# Phase A4 — mTCP Comparison Review (RE-RUN 3, E-2 CLOSED)

- Reviewer: mtcp-comparison-reviewer subagent
- Date: 2026-04-18
- mTCP submodule SHA: 0463aad5ecb6b5bca85903156ce1e314a58efc19
- Our commit: 4e2c116 (branch `phase-a4`) — parent chain 34175d9 → ced49e2 → 7d5c8ee → 12f4bad → 4e2c116
- Prior reviews: same file, pre-fix snapshot at `ced49e23ea962d97102b0862d57298eab70e19f5`; post-F-fix snapshot at `12f4bad` (E-2 then still open)

## Scope

- Our files re-reviewed (delta since prior RE-RUN):
  - `crates/dpdk-net-core/src/tcp_options.rs` — E-2 fix commit (4e2c116):
    - New const `MAX_SACK_BLOCKS_DECODE = 4` (line 39)
    - `TcpOpts.sack_blocks: [SackBlock; MAX_SACK_BLOCKS_DECODE]` widened from 3 to 4 (line 61)
    - New method `push_sack_block_decode` (lines 82-89) — caps at 4 for decode path
    - Existing `push_sack_block` (lines 69-76) — still caps at 3 for encode path
    - `parse_options` SACK branch (lines 250-279) — guard tightened to `block_bytes / 8 > MAX_SACK_BLOCKS_DECODE`; loop uses `push_sack_block_decode`
    - Two new tests: `parse_sack_four_blocks_without_timestamps_all_captured` (lines 518-548) and `parse_rejects_sack_with_five_blocks` (lines 550-560)

- Files re-verified (no regression in prior fixes):
  - `crates/dpdk-net-core/src/tcp_input.rs` (F-1/F-2/F-3 lines 290-319, 409-435, 462-472; F-8 trigger set at 528)
  - `crates/dpdk-net-core/src/engine.rs` (F-4/F-5/F-6/F-7 lines 1419-1422, 1435-1446, 1548-1562; F-8 build_ack_outcome lines 86-167, trigger clear at 1096)
  - `crates/dpdk-net-core/src/tcp_conn.rs` (F-8 `last_sack_trigger` field lines 161-167, default init line 209)
  - Consumer sites for `TcpOpts.sack_blocks`:
    - `tcp_input.rs:443` — `for block in &parsed_opts.sack_blocks[..parsed_opts.sack_block_count as usize]` → length-bounded slice, no fixed-size assumption
    - `engine.rs:1841-1976` — test-only indexes bounded by `sack_block_count` checks, no regression
    - `counters.rs` — only scalar counter; no array shape dependency
  - Test count: 206 lib tests, matching prompt statement

- mTCP files re-referenced for parity confirmation:
  - `third_party/mtcp/mtcp/src/tcp_util.c:186-239` — `ParseSACKOption` re-read; confirmed `while (j < optlen - 2)` iterates every block with no upper cap, feeds `_update_sack_table` directly; our widened decode reaches identical coverage for the 4-block case
  - `third_party/mtcp/mtcp/src/include/tcp_stream.h:65` — `MAX_SACK_ENTRY = 8` scoreboard (unchanged AD under AD-A4-sack-scoreboard-size)
  - `third_party/mtcp/mtcp/src/tcp_in.c:1278-1283` — peer_wnd rule (F-1/F-3 parity, unchanged)
  - `third_party/mtcp/mtcp/src/tcp_out.c:80-134` — GenerateTCPOptions non-SYN TS emission (F-2/F-6/F-7 parity, unchanged)

- Spec sections in scope:
  - §6.2 option-negotiated TcpConn fields
  - §6.3 RFC matrix rows for **7323** (WS + TS + PAWS), **2018** (SACK)
  - §7.2 `recv_reorder` (AD-A4-reassembly)
  - §9.1 + §9.1.1 counter groups
  - §10.13 (this review's gate)

## Findings

### Must-fix (correctness divergence)

All three prior Must-fix items remain closed.

- [x] **F-1** — Post-handshake SND.WND updates drop the peer's window-scale shift. **CLOSED (commit 7d5c8ee).**
  - `tcp_input.rs:469`: `conn.snd_wnd = (seg.window as u32).wrapping_shl(conn.ws_shift_in as u32);` gated by SND.WL1/SND.WL2; `ws_shift_in` clamped at 14 (line 306).
  - mTCP parity: `tcp_in.c:1281-1282` — `peer_wnd = (uint32_t)window << wscale_peer;`. Identical.

- [x] **F-2** — Data segments and FIN frames omit Timestamps after TS negotiation. **CLOSED (commit 12f4bad).**
  - `engine.rs:1438-1446` (data) and `engine.rs:1554-1562` (FIN): `(ts_enabled, ts_recent)` snapshot'd at entry, `TcpOpts { timestamps: Some((tsval, ts_recent)), .. }` built when ts_enabled. TSval = `(clock::now_ns() / 1000) as u32` per RFC 7323 §4.1. 40-byte option budget covered by frame buf at line 1465 and 128-byte FIN buf at line 1582.
  - mTCP parity: `tcp_out.c:119-124` emits TS on every non-RST post-handshake segment. Identical.

- [x] **F-3** — SYN-ACK-parsed window was WS-scaled. **CLOSED (commit 7d5c8ee).**
  - `tcp_input.rs:294`: `conn.snd_wnd = seg.window as u32;` (raw). Comment at 290-293 cites RFC 7323 §2.2 MUST.
  - mTCP parity: `tcp_in.c:1278-1279` — `if (tcph->syn) peer_wnd = window;`. Identical.

### Missed edge cases (mTCP handles, we don't)

- [x] **E-1** — SYN-ACK WS-shift overstated peer's initial window. **CLOSED transitively by F-3.**
  - Same fix site as F-3 (`tcp_input.rs:294`).

- [x] **E-2** — Decoder accepts 4 SACK blocks on wire but silently drops 4th into emit-size storage. **NOW CLOSED (commit 4e2c116).**
  - Fix shape (Option (a) from prior review — widen storage, split emit/decode caps):
    - `tcp_options.rs:33`: `MAX_SACK_BLOCKS_EMIT = 3` — unchanged, still the 40-byte-budget ceiling for outbound (TS + 3 blocks).
    - `tcp_options.rs:39`: new `MAX_SACK_BLOCKS_DECODE = 4` — RFC 2018 §3 max when peer omits TS.
    - `tcp_options.rs:61`: `sack_blocks: [SackBlock; MAX_SACK_BLOCKS_DECODE]` — array widened to 4 slots.
    - `tcp_options.rs:69-76`: `push_sack_block` (encode path) caps at `MAX_SACK_BLOCKS_EMIT = 3` — unchanged.
    - `tcp_options.rs:82-89`: new `push_sack_block_decode` (decode path only) caps at `MAX_SACK_BLOCKS_DECODE = 4`.
    - `tcp_options.rs:255`: parser guard tightened to `block_bytes / 8 > MAX_SACK_BLOCKS_DECODE` (was: `> 4` hardcoded).
    - `tcp_options.rs:276`: parser loop calls `push_sack_block_decode` (was: `push_sack_block`).
  - mTCP parity: `tcp_util.c:194-239` — `while (j < optlen - 2)` with no cap and 8-slot scoreboard. Our decoder now accepts all 4 wire-legal blocks, matching mTCP's decode reach for the RFC 2018 §3 maximum case (TS absent).
  - Consumer safety audit — verified no code assumes `sack_blocks.len() == 3`:
    - `tcp_input.rs:443` uses `&parsed_opts.sack_blocks[..parsed_opts.sack_block_count as usize]` → length-bounded slice, grows naturally.
    - Tests at `engine.rs:1841+` iterate by index bounded by `sack_block_count`. No hardcoded `3`.
    - `counters.rs` holds a scalar `rx_sack_blocks` — no array dependency.
  - New test coverage (commit 4e2c116):
    - `parse_sack_four_blocks_without_timestamps_all_captured` (lines 519-548): builds a 4-block option, parses, asserts `sack_block_count == 4` and all four `(left, right)` pairs land in slots 0..=3.
    - `parse_rejects_sack_with_five_blocks` (lines 551-560): asserts `BadSackBlockCount` on a 5-block wire payload (also rejected by the 40-byte option budget).
  - Regression audit: all prior F-item sites spot-checked and intact; 206 tests still pass.
  - Verdict: closed cleanly. Parity with mTCP's decode-all-blocks semantics achieved.

- [x] **E-3** — Evict-oldest overflow policy on 4-entry SackScoreboard. **PROMOTED via AD-A4-sack-scoreboard-size.**
  - Handled by the pre-declared Accepted Divergence entry. Unchanged.

- [x] **E-4** — Arrival-index ordering vs. reverse-seq for SACK first-block. **CLOSED (commit 12f4bad / F-8).**
  - Set point `tcp_input.rs:528`: `conn.last_sack_trigger = Some((seg.seq, seg.seq.wrapping_add(take)))` on OOO-insert with `newly_buffered > 0`.
  - Clear point `engine.rs:1096`: trigger cleared on successful TX to prevent stale-trigger reuse.
  - Trigger-block emission `engine.rs:120-150`: when `trigger_range` is `Some`, find reorder block with `seq_le(l, t_left) && seq_lt(t_left, r)` and emit first; remaining blocks highest-seq-first. Fallback to highest-seq-first when trigger is `None`. Satisfies RFC 2018 §4 MUST-26.
  - mTCP has no SACK emit (`tcp_util.c:180-184` TODO); we are strictly RFC-more-correct here.

### Accepted divergence (intentional — draft for human review)

The six pre-declared ADs are unchanged. All still require a human-reviewer spec/memory citation before phase tag.

- **AD-A4-options-encoder** — canonical fixed-order emission + NOP padding (`tcp_options.rs:97-145`) vs. mTCP `tcp_out.c:80-134`.
- **AD-A4-reassembly** — `Vec<OooSegment>` copy-based (`tcp_reassembly.rs`) vs. mTCP `tcp_ring_buffer.c` linked-list mempool.
- **AD-A4-sack-generate** — we encode SACK blocks; mTCP `GenerateSACKOption` is a TODO stub (`tcp_util.c:180-184`).
- **AD-A4-sack-scoreboard-size** — 4-entry fixed array with evict-oldest (`tcp_sack.rs:11`) vs. mTCP 8-entry array with latent overflow past `sack_table[MAX_SACK_ENTRY=8]` (`include/tcp_stream.h:65`, `tcp_util.c:169`).
- **AD-A4-paws-challenge-ack** — inline `TxAction::Ack` (`tcp_input.rs:421-426`) vs. mTCP's `EnqueueACK(..., ACK_OPT_NOW)` (`tcp_in.c:131`).
- **AD-A4-option-strictness** — stricter decoder (reject `optlen<2`) at `tcp_options.rs:207-208` vs. mTCP's latent underflow-on-`optlen<2` in `tcp_util.c:31`.

### FYI (informational — no action required)

- **I-1** — `ts_recent_age` declared but not wired into RFC 7323 §5.5 24-day invalidation; deferred to A6 timer wheel. mTCP has the same TODO at `tcp_in.c:126-127`.
- **I-2** — RFC 2018 §4 "first SACK block is most recently received segment" is now first-class (via F-8). Approximation when `last_sack_trigger == None` is documented on `build_ack_outcome`.
- **I-3** — mTCP `_update_sack_table` has latent overflow past `sack_table[MAX_SACK_ENTRY=8]` (`tcp_util.c:169`); our evict-oldest is strictly safer.
- **I-4** — Our `ReorderQueue::insert` carves partial-overlap retransmits into gap-slices, accepting only genuinely-new bytes; mTCP `RBPut` drops the entire segment on `cur_seq < head_seq`.
- **I-5** — `ReorderQueue::insert` is O(N×M) worst-case; same class as mTCP's `RBPut` walk.
- **I-6** — mTCP `ParseSACKOption` accepts non-multiple-of-8 regions silently (`tcp_util.c:236-237`); our parser rejects via `!block_bytes.is_multiple_of(8)` at `tcp_options.rs:254`.
- **I-7** — mTCP `ACK_OPT_AGGREGATE` vs. `ACK_OPT_NOW` vs. our uniform per-segment emit in the same poll tick. Carried from A3 AD-4.
- **I-8** — mTCP `wscale_mine` compile-time constant; we compute `ws_shift_out` per-conn from `recv_buffer_bytes`.
- **I-9** — Spec §7.2 mbuf-chain zero-copy model deferred in both A3 and A4.
- **I-10** — `dup_ack` definition loose vs. RFC 5681 §2 5-condition strict. A5 RACK-TLP rewrites the call site under RFC 8985; slow-path counter inflation only.
- **I-11** — New: the split `MAX_SACK_BLOCKS_EMIT / MAX_SACK_BLOCKS_DECODE` is a minor code-quality asymmetry between encode and decode paths. The two helper methods (`push_sack_block` / `push_sack_block_decode`) are intentionally distinct to prevent accidental cap-mismatch at TX; documented in the module header comment (`tcp_options.rs:50-53`). mTCP has no analogue since it doesn't generate SACK.

## Verdict (draft)

**PASS-WITH-ACCEPTED**

Finding counts:
- Must-fix: **0 open / 3 closed**. F-1, F-2, F-3 verified in code with line citations.
- Missed edge cases: **0 open / 4 resolved**. E-1 closed transitively by F-3, E-2 closed by commit 4e2c116 (widened decode storage with split emit/decode caps), E-3 promoted to AD-A4-sack-scoreboard-size, E-4 closed by F-8.
- Accepted divergence: **6** pre-declared entries, all still need human-reviewer citations before tag.
- FYI: **11** (10 carried forward + I-11 new).

Gate rule per spec §10.13: no open `[ ]` checkbox in Must-fix or Missed-edge-cases. **All gates clear.**

Recommended next actions for the human:
1. **Fill the six AD citations** in the `AD-A4-*` entries so each `Spec/memory reference needed` line becomes concrete (e.g. `AD-A4-paws-challenge-ack` cites `feedback_trading_latency_defaults.md`; `AD-A4-reassembly` cites §7.2; `AD-A4-options-encoder` cites §6.2 encoder contract; `AD-A4-sack-scoreboard-size` cites the "safer than mTCP" I-3 observation; `AD-A4-sack-generate` is self-evident from mTCP TODO; `AD-A4-option-strictness` cites I-6 "stricter than RFC" rationale).
2. **Optional**: record I-10 as an AD-A4-dup-ack-loose entry if the code-quality reviewer's earlier concern should be persisted into memory for A5.
3. Once AD citations are filled, the phase is clear to tag `phase-a4-complete`.
