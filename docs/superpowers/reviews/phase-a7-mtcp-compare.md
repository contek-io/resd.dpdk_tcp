# Phase A7 — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent (opus 4.7)
- Date: 2026-04-21
- mTCP submodule SHA: `0463aad5`
- Phase base commit: `2c4e0b6`
- Phase tip commit: `41a79d8`
- Worktree: `/home/ubuntu/resd.dpdk_tcp-a6.6-7`

## Scope

Phase A7 introduces a loopback test server + packetdrill-shim surface so we can drive the transport with recorded/scripted TCP scenarios without a NIC. Scope is **server-side passive-open + passive/active close on the server side**, plus surrounding test infrastructure (virtual clock, TX intercept, test-only FFI header, runner crate, classified corpus). The review targets *algorithmic parity with mTCP's passive side* only; parser and shim wiring are orthogonal to mTCP's codebase.

### Ours — files reviewed

- `crates/dpdk-net-core/src/test_server.rs` — `ListenSlot { local_ip, local_port, accept_queue: Option<ConnHandle>, in_progress: Option<ConnHandle> }` capacity-1 accept, `pub mod test_packet` helpers.
- `crates/dpdk-net-core/src/engine.rs`
  - `listen_slots: RefCell<Vec<(ListenHandle, ListenSlot)>>` (line 547)
  - Passive-open fast-path in `poll` (line 3277-3303)
  - `outcome.connected → listen_promote_to_accept_queue` (line 3682-3688)
  - `Engine::listen` (line 5365-5379) — duplicate (ip,port) → InvalidArgument; monotonic ListenHandle allocation.
  - `Engine::accept_next` (line 5383-5390) — `take()` on accept_queue.
  - `match_listen_slot` (line 5451-5461) — linear search.
  - `handle_inbound_syn_listen` (line 5466-5529) — full/in-progress → `emit_rst_for_unsolicited_syn`; else new_passive → flow_table.insert → slot.in_progress = Some(h) → `emit_syn_ack_for_passive` → `snd_nxt += 1`.
  - `emit_syn_ack_for_passive` (line 5534-5541) — thin wrapper around `emit_syn_with_flags(handle, SYN|ACK, now_ns)`; **does NOT arm a SYN-ACK retransmit timer**.
  - `emit_rst_for_unsolicited_syn` (line 5547-5580) — RST+ACK, seq=0, ack=iss_peer+1, window=0, no options.
  - `emit_syn_with_flags` (line 1891-1927) — uses `build_connect_syn_opts`.
  - `build_connect_syn_opts` (line 100-114) — unconditional MSS + wscale + sack_permitted + timestamps.
- `crates/dpdk-net-core/src/tcp_conn.rs`
  - `new_passive` (line 455-493) — mirrors `new_client` then state=SynReceived; rcv_nxt=iss_peer+1; irs=iss_peer; absorbs peer MSS/WS (clamped to 14, RFC 7323 §2.3)/TS/SACK.
- `crates/dpdk-net-core/src/tcp_input.rs`
  - SynReceived dispatch arm (line 337-338)
  - `handle_syn_received` (line 364-423) — RST→Closed; any SYN (with or without ACK) → `Outcome::none()` silently; challenge-ACK on seg.seq ≠ rcv_nxt; RST+Close on bad ACK; absorbs peer window + TS on valid final-ACK → Established.
  - `handle_close_path` (line 1322-1401) — unified handler for FinWait1 / FinWait2 / Closing / LastAck / CloseWait / TimeWait.
- `crates/dpdk-net-core/tests/test_server_passive_close.rs` — full passive-close E2E.

### mTCP — files compared

- `third_party/mtcp/mtcp/src/tcp_in.c`
  - `FilterSYNPacket` (line 27-59) — listener lookup + ip/port match.
  - `HandlePassiveOpen` (line 61-82) — `CreateTCPStream`, irs=seq, peer_wnd, rcv_nxt=irs, cwnd=1, ParseTCPOptions.
  - `CreateNewFlowHTEntry` SYN path (line 684-714) — refuse/full → `SendTCPPacketStandalone(RST|ACK)`.
  - `Handle_TCP_ST_LISTEN` (line 749-764) — SYN → rcv_nxt++, state=SYN_RCVD, AddtoControlList.
  - `Handle_TCP_ST_SYN_RCVD` (line 838-903) — final-ACK → ESTABLISHED + StreamEnqueue; enqueue fail → close_reason=TCP_NOT_ACCEPTED. Else retransmit SYN-ACK via AddtoControlList.
  - `Handle_TCP_ST_LAST_ACK` (line 975-1030) — ACK of our FIN → CLOSED, DestroyTCPStream; **no TIME_WAIT on passive side**.
  - `ProcessTCPPacket` dispatch line 1308-1311: in SYN_RCVD, `if (tcph->syn && seq == irs)` → jump to `Handle_TCP_ST_LISTEN` (retransmit SYN-ACK).
- `third_party/mtcp/mtcp/src/tcp_out.c` `SendControlPacket` SYN_RCVD branch (line 617-625) — `snd_nxt = iss` SYN+ACK.
- `third_party/mtcp/mtcp/src/tcp_util.c` `ParseTCPOptions` (line 42-43) — **does NOT clamp wscale > 14**.
- `third_party/mtcp/mtcp/src/api.c` `mtcp_listen` (line 473-551) — real `CreateStreamQueue(backlog)` + `ListenerHTInsert`.
- `third_party/mtcp/mtcp/src/timer.c` — `AddtoTimewaitList` (line 85-108), `HandleRTO` (line 182-358), `CheckConnectionTimeout` (line 490-522).

Spec:
- A7 design spec: `docs/superpowers/specs/2026-04-21-stage1-phase-a7-loopback-test-server-packetdrill-shim.md`
- A7 plan: `docs/superpowers/plans/2026-04-21-stage1-phase-a7-loopback-test-server-packetdrill-shim.md`

## Summary verdict

**ALIGNED (PASS-WITH-ACCEPTED).**

Passive-open happy path is algorithmically aligned with mTCP: both allocate a conn on SYN match, emit SYN-ACK, await final ACK, transition to ESTABLISHED, and promote onto the listen slot. Passive-close is aligned exactly: ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED with **no TIME_WAIT** on the passive side (same rule mTCP enforces at `tcp_in.c:975-1030`). Where the two diverge, every divergence is a **narrowing of scope** that matches Stage-1's test-server goal — single-slot listen vs bucketed backlog, no SYN-ACK retransmit timer vs RTO-driven retransmit, RST-at-SYN vs RST-after-handshake for accept-queue-full. Each is defensible against spec (A7 §10.12, §12, explicit A8+ scope, RFC 9293 §3.10.7.1 latitude). One divergence goes the *other* direction — we clamp peer wscale to 14 (RFC 7323 §2.3), mTCP does not.

No must-fix or missed-edge-case findings emerged.

## Findings

### Must-fix (correctness divergence)

_None._

### Missed edge cases (mTCP handles, we don't)

_None._ (see AD-3 / AD-4 — retransmit scope is explicitly out of A7 per commit log and the T15 pragmatic-floor framing.)

### Accepted divergence (intentional — citations attached)

- **AD-1** — Listen-slot data structure: capacity-1 `Option<ConnHandle>` vs bucketed `StreamQueue(backlog)`
  - mTCP: `api.c:473-551` `mtcp_listen` allocates `StreamQueue(backlog)` via `CreateStreamQueue` + `ListenerHTInsert`. `tcp_in.c:877` `StreamEnqueue(listener->acceptq, cur_stream)` pushes each completed handshake onto the queue; overflow returns `-1` and sets `close_reason=TCP_NOT_ACCEPTED`.
  - Ours: `engine.rs:547` `listen_slots: RefCell<Vec<(ListenHandle, ListenSlot)>>`; `ListenSlot { accept_queue: Option<ConnHandle>, in_progress: Option<ConnHandle> }` carries one in-progress and one accept-ready conn. `match_listen_slot` at line 5451 is a linear search.
  - Citation: A7 spec §10.12 (listen-slot scope) — capacity-1 is sufficient for packetdrill-style sequential scripts; multi-slot accept + real backlog deferred to A8+. Linear search is O(N<sub>listeners</sub>) bounded by test-fixture size.

- **AD-2** — Accept-queue-full policy: RST+ACK at SYN arrival vs complete-handshake-then-RST
  - mTCP: `tcp_in.c:684-714` emits RST only when `FilterSYNPacket` fails or flow pool is exhausted. If the listener exists, mTCP **completes** the handshake, and *then* `Handle_TCP_ST_SYN_RCVD` (line 877-885) detects backlog overflow via `StreamEnqueue < 0` and tears down with `TCP_NOT_ACCEPTED` — RST emitted after SYN-ACK + final-ACK round-trip.
  - Ours: `engine.rs:5466-5486` `handle_inbound_syn_listen` checks `accept_queue.is_some() || in_progress.is_some()` at SYN arrival and emits RST+ACK immediately via `emit_rst_for_unsolicited_syn` (seq=0, ack=iss_peer+1, window=0, no options — RFC 9293 §3.10.7.1 shape).
  - Citation: RFC 9293 §3.10.7.1 is permissive about rejection timing. Both policies are spec-valid; ours is strictly earlier. Earlier-reject aligns with A7's capacity-1 scope (AD-1): we cannot afford to allocate a conn for a handshake we know will not be accepted. A8+ multi-slot backlog will evaluate mTCP-style post-handshake rejection.

- **AD-3** — No SYN-ACK retransmit timer vs mTCP's RTO-driven retransmit
  - mTCP: `tcp_in.c:759-764` `Handle_TCP_ST_LISTEN` ends with `AddtoControlList`; `tcp_out.c:617-625` `SendControlPacket` emits SYN+ACK with `snd_nxt = iss`. `tcp_in.c:896-902` (no-ACK in SYN_RCVD) re-enqueues via `AddtoControlList`. Combined with `timer.c:182-358` `HandleRTO`, a lost final-ACK triggers SYN-ACK retransmit.
  - Ours: `engine.rs:5534-5541` `emit_syn_ack_for_passive` is a one-shot emit — no equivalent of `AddtoRTOList` for passive SYN-ACK. If the final ACK is dropped, the peer's SYN retransmit hits `handle_syn_received` which silently drops it (AD-4); our conn stays in SYN_RCVD (no `CheckConnectionTimeout` wired for test-server conns either).
  - Citation: A7 commit message frames scope as a *pragmatic floor* for scripted packetdrill use where drops do not occur by design (virtual clock + in-memory TX intercept → deterministic delivery). T15 ("0 runnable scripts") is the accepted pragmatic floor per commit log. A8+ closes SYN-ACK retransmit + SYN_RCVD→LISTEN on peer-SYN-retransmit. Upgrade path is wiring (reuse existing RTO wheel infra used by active-open), not new algorithm.
  - **RETIRED 2026-04-22 (A8 T11):** passive SYN-ACK retransmit now reuses the active-open `SynRetrans` timer wheel — precisely the wiring upgrade anticipated above. `emit_syn_ack_for_passive` arms the wheel on successful TX, and the `on_syn_retrans_fire` handler branches on `TcpConn::is_passive_open` to retransmit `SYN|ACK` (passive) vs plain `SYN` (active) with identical ISS/ACK fields. Budget shared with active-open (hardcoded `> 3` cap, doubling backoff off `tcp_initial_rto_us`); budget exhaust closes the conn with `tcp.conn_timeout_syn_sent` + `InternalEvent::Error{err=-ETIMEDOUT}`. Matches mTCP `Handle_TCP_ST_LISTEN` + `HandleRTO` semantics for this path. Regression: `crates/dpdk-net-core/tests/ad_a7_syn_retrans.rs`. The companion AD-4 (peer-SYN-in-SYN_RCVD silent drop) remains open; AD-3 retires independently.

- **AD-4** — Retransmitted peer SYN in SYN_RCVD: silently dropped vs SYN-ACK resent
  - mTCP: `tcp_in.c:1308-1311` detects `tcph->syn && seq == cur_stream->rcvvar->irs` in SYN_RCVD and jumps to `Handle_TCP_ST_LISTEN`, retransmitting SYN-ACK via control list.
  - Ours: `tcp_input.rs:384-386` `handle_syn_received` returns `Outcome::none()` for any segment with SYN set — regardless of whether SEQ matches `irs`. No retransmit.
  - Citation: A7 plan T5 acceptance criterion is "final-ACK lands → ESTABLISHED"; retransmit-peer-SYN case is explicitly deferred to A8+ along with AD-3's timer wiring. Test-server loopback is deterministic; retransmitted-SYN arrives only if both sides are aware of a drop, which does not happen under the virtual-clock + TX-intercept design. RFC 9293 §3.10.7.3 does require retransmit-SYN-ACK under real-loss conditions — A8+ scope.

- **AD-5** — SYN-ACK option bundle: unconditional MSS+WS+SACK+TS vs peer-gated
  - mTCP: `tcp_in.c:79` `HandlePassiveOpen` calls `ParseTCPOptions`, setting sndvar fields only when the option was present; `tcp_out.c` `GenerateTCPOptions` then emits only peer-advertised options — RFC 7323 §1.3 / §2.2 gating.
  - Ours: `engine.rs:100-114` `build_connect_syn_opts` unconditionally sets MSS, wscale, sack_permitted=true, timestamps=true on every emitted SYN — including passive SYN-ACKs via `emit_syn_ack_for_passive` → `emit_syn_with_flags`. If the peer's SYN carried only MSS, our SYN-ACK will still advertise WS+TS+SACK.
  - Citation: A7 plan T5 scope is "handshake against peers that advertise MSS+WS+SACK+TS" (the packetdrill corpus + our unit tests all carry the full bundle). `tcp_conn.rs:455-493` `new_passive` absorbs peer options correctly (incl. WS clamp to 14), so if the peer doesn't advertise an option, our side does not *use* it — the option echo in SYN-ACK is cosmetically RFC-divergent but behaviourally inert. A8+ gates `build_connect_syn_opts` on a per-role `OptsPolicy`. State-machine-inert header-hygiene issue, not correctness.

### FYI (informational — no action required)

- **I-1** — mTCP does NOT clamp peer wscale to 14 (`tcp_util.c:42-43`, raw byte store). Our `tcp_conn.rs:455-493` `new_passive` clamps via RFC 7323 §2.3. We are more correct than mTCP.

- **I-2** — mTCP's `Handle_TCP_ST_LAST_ACK` (`tcp_in.c:975-1030`) transitions directly to CLOSED + DestroyTCPStream on ACK of our FIN — no TIME_WAIT on passive side. `tests/test_server_passive_close.rs` verifies the same behaviour in our stack. Aligned.

- **I-3** — mTCP's active-close TIME_WAIT uses `AddtoTimewaitList` (`timer.c:85-108`, `tcp_in.c:1352-1360`) with `CONFIG.tcp_timewait`. Our `handle_close_path` (`tcp_input.rs:1322-1401`) implements TIME_WAIT on the active-close side (A7 T7). Aligned.

- **I-4** — mTCP carries a TODO at `tcp_in.c:126` about TS.Recent invalidation for long idle flows; our stack implements RFC 7323 §5.5 24-day TS.Recent expiration. Ours is more complete; mTCP's TODO is unimplemented.

- **I-5** — Observability: mTCP uses TRACE_SACK/TRACE_STATE macros; we use `counters::inc` + test-only hooks. Purely observability; no correctness.

## Action items (gate phase tag)

All divergences are intentional and citation-attached. No open `- [ ]` items.

### Must-fix
_None._

### Missed edge cases
_None._

### Accepted divergence — citations attached
- [x] **AD-1** — Citation attached: A7 spec §10.12 (listen-slot scope) — capacity-1 is test-server goal; A8+ deferred.
- [x] **AD-2** — Citation attached: RFC 9293 §3.10.7.1 (RST latitude) + A7 AD-1 coupling.
- [x] **AD-3** — Citation attached: A7 commit message (pragmatic floor) + T15 0-script classification + A8+ retransmit hardening. **RETIRED 2026-04-22 (A8 T11).**
- [x] **AD-4** — Citation attached: A7 plan T5 acceptance + A8+ deferred + RFC 9293 §3.10.7.3 scope narrowing.
- [x] **AD-5** — Citation attached: A7 plan T5 option-bundle scope + RFC 7323 §1.3/§2.2 header-hygiene vs behavioural-inert.

### FYI
_None require action._

## Verdict

**PASS**

Gate rule: Must-fix and Missed-edge-cases sections are empty (no open `- [ ]` correctness items). Accepted-divergence section is fully cited; all 5 ADs `[x]` complete. Phase may tag `phase-a7-complete`.

Substance: A7's server-side passive path is algorithmically aligned with mTCP on the happy path (handshake, CLOSE_WAIT→LAST_ACK→CLOSED, no-TIME_WAIT-on-passive) and on active-close TIME_WAIT. Every divergence is a **narrowing** of mTCP's production generality that matches A7's test-server scope (capacity-1 listen, no SYN-ACK retransmit timer, no SYN-retransmit-in-SYN_RCVD handler, unconditional SYN-ACK options). The one divergence that goes the other direction — wscale-14 clamp and TS.Recent 24-day expiration — makes us *more* RFC-correct than mTCP. No correctness regressions; no missed edge cases A7 is responsible for per its declared scope.
