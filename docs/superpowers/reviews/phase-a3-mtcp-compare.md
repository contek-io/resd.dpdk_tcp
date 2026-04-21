# Phase A3 — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent (human-finalized 2026-04-18)
- Date: 2026-04-18
- mTCP submodule SHA: 0463aad5ecb6b5bca85903156ce1e314a58efc19
- Our commit: `phase-a3` branch HEAD at review finalization (after counter addition for E-1 acceptance)

## Scope

- Our files reviewed:
  - `crates/dpdk-net-core/src/tcp_seq.rs`
  - `crates/dpdk-net-core/src/tcp_state.rs`
  - `crates/dpdk-net-core/src/flow_table.rs`
  - `crates/dpdk-net-core/src/iss.rs`
  - `crates/dpdk-net-core/src/tcp_conn.rs`
  - `crates/dpdk-net-core/src/tcp_output.rs`
  - `crates/dpdk-net-core/src/tcp_events.rs`
  - `crates/dpdk-net-core/src/tcp_input.rs`
  - `crates/dpdk-net-core/src/engine.rs` (A3-added methods only)
  - `crates/dpdk-net-core/src/counters.rs` (A3 fields)
  - `crates/dpdk-net-core/tests/tcp_basic_tap.rs`
  - `crates/dpdk-net/src/lib.rs` (A3 extern "C" additions)
  - `crates/dpdk-net/src/api.rs` (A3 counter mirror)

- mTCP files referenced:
  - `third_party/mtcp/mtcp/src/tcp_in.c` (ProcessTCPPacket, ValidateSequence, ProcessACK, ProcessTCPPayload, Handle_TCP_ST_*, CreateNewFlowHTEntry, ProcessRST)
  - `third_party/mtcp/mtcp/src/tcp_out.c` (SendTCPPacket, SendTCPPacketStandalone, EnqueueACK)
  - `third_party/mtcp/mtcp/src/tcp_stream.c` (CreateTCPStream — ISS/iss init)
  - `third_party/mtcp/mtcp/src/tcp_util.c` (ParseTCPOptions, TCPCalcChecksum)
  - `third_party/mtcp/mtcp/src/tcp_ring_buffer.c` (RBPut, GetMinSeq)
  - `third_party/mtcp/mtcp/src/include/tcp_in.h` (TCP_SEQ_* macros, state enum)

- Spec sections in scope:
  - §4 (public API: `dpdk_net_connect`, `dpdk_net_send`, `dpdk_net_close`, `DPDK_NET_EVT_CONNECTED/READABLE/CLOSED/TCP_STATE_CHANGE`)
  - §5.2 (TX call chain)
  - §6.1 (RFC 9293 §3.3.2 eleven-state FSM, client-side)
  - §6.2 (`TcpConn` minimum fields)
  - §6.5 (ISS skeleton)
  - §9.1 (TCP counter group)

## Findings

### Must-fix (correctness divergence)

_None identified. All observed divergences from mTCP are either A4/A5/A6 scope (deliberately deferred), RFC-compliance improvements (we follow RFC 9293 where mTCP predates or deviates), or known accepted divergences from the plan header + spec §6.4._

### Missed edge cases (mTCP handles, we don't)

- [x] **E-1 → promoted to AD-9** — `rcv_wnd` never shrinks as recv buffer fills. Resolved by user directive: we deliberately do NOT shrink the ingress acceptance window. Throttling the peer to match local buffer occupancy would mask a slow-consumer problem as a protocol-layer artifact. Instead we expose `tcp.recv_buf_drops` so the application sees bytes dropped under buffer pressure. See spec §6.4 new "Receive-window shrinkage" row and `feedback_performance_first_flow_control.md`. Counter addition committed; see AD-9 below.

- [x] **E-2 → promoted to AD-10** — SYN-in-ESTABLISHED handled implicitly via challenge-ACK path rather than explicit RFC 5961 §4 check. RFC 5961 hardening is deferred to A6 per spec §6.3 (row "5961 — yes"); A3's scope is client-basic and the generic out-of-window path delivers an identical observable outcome (challenge ACK) for the realistic-attack cases.

- [x] **E-3 → promoted to AD-11** — Both-edges window check rejects retransmits whose right edge overlaps our window; we skip ACK-field processing on those. Accepted: A3 has no retransmit (A5 scope); kernel peers rarely retransmit already-ACKed data unless packets are lost. The divergence only costs a marginal snd_una advance delay under A5+ loss scenarios; will be revisited in A5 alongside RACK-TLP work.

- [x] **E-4 → promoted to AD-12** — `send_bytes` uses `in_flight = snd_nxt - snd_una` as a proxy for send-buffer occupancy rather than `snd.pending.len()`. In A3 these coincide (every accepted byte goes to snd.pending; every ACK pops); the divergence will surface in A5 when SACK / partial-ACK handling lands. The A5 plan will include a drive-by refactor to use `snd.free_space()` directly.

- [x] **E-5 → promoted to I-9** — MSS option validation stricter than mTCP (we reject `kind=2, len=6` as malformed; mTCP reads the first 2 value bytes). Our side is safer; noted for A4 to apply the same rigor to WSCALE/TS/SACK-permitted option parsers.

### Accepted divergence (intentional — human-finalized)

The plan header lists seven pre-emptive accepted divergences. This review confirms all seven match observed behavior, plus five additional items promoted from the Missed-edge-cases section after human review, plus one observation found during review.

- **AD-1** — ISS via RFC 6528 (SipHash of 4-tuple + secret + monotonic µs clock) vs mTCP's `rand_r() % 2^32`.
  - mTCP: `third_party/mtcp/mtcp/src/tcp_stream.c:310` — `stream->sndvar->iss = rand_r(&next_seed) % TCP_MAX_SEQ` (pure PRNG, no keyed hash of tuple).
  - Ours: `crates/dpdk-net-core/src/iss.rs:44-52` — SipHash of (per-engine secret, 4-tuple) + monotonic µs clock low-32, per RFC 6528 §3.
  - Rationale cited: spec §6.5 ISS formula.

- **AD-2** — Sequence-window validation checks both edges; mTCP checks right edge only.
  - mTCP: `third_party/mtcp/mtcp/src/tcp_in.c:149` — `TCP_SEQ_BETWEEN(seq + payloadlen, rcv_nxt, rcv_nxt + rcv_wnd)` (right-edge-only).
  - Ours: `crates/dpdk-net-core/src/tcp_input.rs:281-284` and `373-376` — both edges of segment must be in window.
  - Rationale cited: spec §6.1 / RFC 9293 §3.10.7.4. Related caveat in AD-11 below.

- **AD-3** — `snd_una = seg.ack` on SYN-ACK processing (rather than mTCP's `snd_una++`).
  - mTCP: `third_party/mtcp/mtcp/src/tcp_in.c:784` — `cur_stream->sndvar->snd_una++` after ACK validation.
  - Ours: `crates/dpdk-net-core/src/tcp_input.rs:238` — `conn.snd_una = seg.ack`.
  - Rationale cited: plan header — cleaner / identical result on well-formed SYN-ACK; RFC 9293 §3.10.7.3 permits either form.

- **AD-4** — Per-segment ACK rather than mTCP's aggregation.
  - mTCP: `third_party/mtcp/mtcp/src/tcp_in.c:924` + `tcp_out.c:1078-1100` — `EnqueueACK(..., ACK_OPT_AGGREGATE)` batches ACKs.
  - Ours: every segment that advances `rcv_nxt` or takes FIN fires `TxAction::Ack` and is transmitted in the same poll iteration (`engine.rs:580-582`).
  - Rationale cited: spec §6.4 row 1 (delayed-ACK, amended 2026-04-18 to explicitly document "A3 per-segment baseline; A6 finalizes burst-scope coalescing"); `feedback_trading_latency_defaults.md`. The per-segment baseline over-ACKs relative to RFC MUST-58 but is functionally correct — every ACK is individually valid.

- **AD-5** — MSS-only SYN options (no WSCALE/TS/SACK-permitted).
  - mTCP: `tcp_out.c` builds SYN options via `GenerateTCPOptions` with all four when enabled.
  - Ours: `crates/dpdk-net-core/src/tcp_output.rs:86-91` — only the MSS option is emitted.
  - Rationale cited: spec §6.3 A3 scope — WSCALE/TS/SACK-permitted are A4 work.

- **AD-6** — Flow-table layout (`Vec<Option<TcpConn>>` + `HashMap<FourTuple, u32>` ≤100 conns) vs mTCP's Jenkins-hash chained buckets with `NUM_BINS_FLOWS=131072`.
  - mTCP: `third_party/mtcp/mtcp/src/fhash.c` — chained hash, constant-size bucket count.
  - Ours: `crates/dpdk-net-core/src/flow_table.rs:31-45` — handle-indexed `Vec` + std `HashMap` for 4-tuple → slot lookup.
  - Rationale cited: spec §6.5 "Flow table" implementation choice — ≤100 connections target.

- **AD-7** — Recv buffer = `VecDeque<u8>` (true ring) vs mTCP's `memmove`-on-wrap buffer.
  - mTCP: `tcp_ring_buffer.c` (via `RBPut` plus merged-fragment tracking).
  - Ours: `crates/dpdk-net-core/src/tcp_conn.rs:44-74` (`RecvQueue` backed by `VecDeque<u8>`).
  - Rationale cited: plan header — A3 has no reassembly; `VecDeque` is a true O(1) ring, strictly better than mTCP's memmove.

- **AD-8** — Unmatched-flow RST reply uses `ack = seq + payload + syn_flag + fin_flag` (correct per RFC 9293 §3.10.7.1); mTCP uses `ack = seq + payload` only, missing the flag-length component.
  - mTCP: `third_party/mtcp/mtcp/src/tcp_in.c:740-743` — sends `ack = seq + payloadlen` (omits +1 for SYN or +1 for FIN of the incoming segment).
  - Ours: `crates/dpdk-net-core/src/engine.rs:700-709` — sums `payload_len + syn_len + fin_len` correctly.
  - Rationale cited: RFC 9293 §3.10.7.1 — we're strictly correct; mTCP has a latent bug here.

- **AD-9** (promoted from E-1) — `rcv_wnd` does NOT shrink with recv buffer occupancy; we accept at full capacity and count drops.
  - mTCP: `third_party/mtcp/mtcp/src/tcp_in.c:653` — `rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len` after each `RBPut`, keeping the validation window tight against the actual free ring-buffer space.
  - Ours: `crates/dpdk-net-core/src/tcp_conn.rs:121-132` sets `rcv_wnd` at construction; seq-window check in `tcp_input.rs:281-284` + `373-376` uses this static value. `RecvQueue::append()` clamps to `free_space`, and the excess bytes are counted in `tcp.recv_buf_drops` (added 2026-04-18). Our *advertised* window in outbound ACKs (`engine.rs:641`) is `recv.free_space()` — so well-behaved peers still throttle per their advertised-window; our wider ingress check just avoids being doubly-conservative.
  - Rationale cited: spec §6.4 "Receive-window shrinkage vs. buffer occupancy" row (added 2026-04-18); `feedback_performance_first_flow_control.md`. The trading workload is market-data ingress at peer line-rate — throttling the peer masks a slow-consumer problem as a protocol-layer artifact.

- **AD-10** (promoted from E-2) — SYN-in-ESTABLISHED handled implicitly via generic out-of-window challenge-ACK path rather than the explicit RFC 5961 §4 check.
  - mTCP: `third_party/mtcp/mtcp/src/tcp_in.c:910-918` detects in-ESTABLISHED SYN explicitly.
  - Ours: `handle_established` passes SYN through to the generic window check; the SYN's seq is typically `irs` < `rcv_nxt`, so `in_window()` returns false and the challenge-ACK path fires (`tcp_input.rs:286-287`). Net observable behavior matches RFC 5961 §4.
  - Rationale cited: spec §6.3 row "RFC 5961 — yes — challenge-ACK on out-of-window seqs" — A3 inherits RFC-5961-equivalent behavior via the generic path. Explicit RFC 5961 hardening (in-window SYN detection; challenge-ACK rate limit) is A6 scope.

- **AD-11** (promoted from E-3) — Segments that land entirely to the left of `rcv_nxt` (already-delivered retransmits) are rejected without running ACK-field processing.
  - mTCP: `tcp_in.c:148-150` — validates right-edge only; ACK-field advance happens even on left-of-window segments.
  - Ours: `tcp_input.rs:276-285` requires both edges in-window; left-of-window segments short-circuit to challenge-ACK.
  - Rationale cited: plan header "Accepted Divergence #2 — both-edges sequence-window validation". A3 has no retransmit (A5 scope); kernel peers rarely retransmit already-ACKed data. The marginal snd_una-advance-delay cost manifests only under A5+ loss scenarios and is revisited alongside RACK-TLP.

- **AD-12** (promoted from E-4) — `send_bytes` uses `in_flight = snd_nxt - snd_una` as send-buffer-room proxy rather than `snd.pending.len()`.
  - mTCP: `tcp_send_buffer.c:123` (`SBPut`) caps on actual buffered bytes.
  - Ours: `engine.rs:869-871`. In A3 these coincide; A5 SACK / partial-ACK will desync them.
  - Rationale cited: A5 plan — will refactor `send_bytes` to read `c.snd.free_space()` directly alongside the SACK scoreboard work.

### FYI (informational — no action required)

- **I-1** — Our `snd_wl1`/`snd_wl2` update rule uses `<=` on the ack field (matching RFC 9293 §3.10.7.4's "`SEG.ACK >= SND.WL2`") whereas mTCP uses strict `<` (`tcp_in.c:350`). Our code is RFC-compliant; mTCP is slightly stricter in a way that would occasionally miss window updates. No action.

- **I-2** — mTCP's `Handle_TCP_ST_ESTABLISHED` does NOT require the ACK flag to be set before processing payload (`tcp_in.c:920-928`). RFC 9293 §3.10.7.4 step 6 says "If the ACK bit is off, drop the segment and return". Our code at `tcp_input.rs:268-270` matches the RFC. No action.

- **I-3** — mTCP has no RACK-TLP, no ECN, no SACK-accept (A6 / later). We do not implement these in A3 either — out of scope. Noting for completeness so the A6 reviewer remembers that when RACK arrives there will be no mTCP reference to compare against.

- **I-4** — mTCP's `ProcessRST` (`tcp_in.c:195-252`) does NOT validate that the RST's seq is within the receive window — it just acts on the RST. RFC 5961 §3 says a RST is only accepted if its seq exactly matches `rcv_nxt` (or challenge-ACK otherwise). Our code in `handle_established` and `handle_close_path` performs the RST-closes-connection action without additional in-window gating. Matching mTCP's permissive behavior here is the A3 choice; tightening per RFC 5961 is A6 scope. No action.

- **I-5** — Our `tcp_checksum` / `tcp_pseudo_csum` functions (tcp_output.rs:112-122 and tcp_input.rs:102-111) allocate a scratch `Vec<u8>` for each segment. mTCP's `TCPCalcChecksum` (`tcp_util.c:245`) folds in-place. No correctness divergence; allocation is a small perf hit that A6/A7 vectorization can replace with `rte_raw_cksum_mbuf` when we drop to NIC offload. No action for A3.

- **I-6** — mTCP's `ParseTCPOptions` (`tcp_util.c:21-57`) has an infinite-loop bug on `optlen=0`/`optlen=1` for unknown options (`i += optlen - 2` underflows `size_t`). Our `parse_mss_option` (`tcp_input.rs:132-137`) defends with `if olen < 2 { return 536 }`. A4's TS/WSCALE parser should preserve the same defensive check.

- **I-7** — TIME_WAIT reap strategy: mTCP uses a sorted `timewait_list` walked from `timer.c:462`. We use an O(N) flow-table scan (`engine.rs:413-431`) capped at ≤100 connections. Spec-appropriate for A3; A6's timer wheel replaces this.

- **I-8** — `Engine::next_ephemeral_port` (`engine.rs:336-344`) is a monotonic counter in [49152, 65535] with no collision check against existing flows. At ≤100 connections the odds of reuse within MSL are negligible. Accepted; noting for A7 when we scale out.

- **I-9** (promoted from E-5) — Our `parse_mss_option` rejects known-but-malformed options like `kind=2, len=6, <4 bytes of garbage>` by returning 536, whereas mTCP reads the first 2 value bytes anyway. Our side is strictly stricter. Noted for A4 to apply the same rigor to WSCALE/TS/SACK-permitted parsers.

## Verdict

**PASS-WITH-ACCEPTED** — human-finalized 2026-04-18.

Finding counts after human review:
- Must-fix: 0
- Missed edge cases (open): 0
- Missed edge cases (resolved/promoted): 5 — E-1→AD-9 (counter added; rcv_wnd stays wide per trading philosophy), E-2→AD-10, E-3→AD-11, E-4→AD-12, E-5→I-9.
- Accepted divergence (with citations): 12 — AD-1 through AD-12. Seven from the plan header (AD-1..AD-7), AD-8 surfaced during review, AD-9..AD-12 promoted from E-1..E-4.
- FYI: 9 — I-1 through I-9 (E-5 demoted to I-9).

Gate rule satisfied: no open `[ ]` remains in Must-fix or Missed-edge-cases. All Accepted-divergence entries cite a concrete spec §ref or memory file. The `phase-a3-complete` tag may proceed pending the RFC compliance review gate.
