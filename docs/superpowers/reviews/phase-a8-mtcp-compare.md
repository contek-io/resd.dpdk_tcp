# Phase A8 — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent (opus 4.7)
- Date: 2026-04-22
- mTCP submodule SHA: `0463aad5` (unchanged from phase-a7-complete; no submodule bump in A8)
- Phase base commit: `9855e95` (`phase-a7-complete`)
- Phase tip commit: `2f5cfbff`
- Branch: `phase-a8`

## Scope

Phase A8 is a **test-correctness spine** phase. Behavior changes that intersect mTCP's codebase are concentrated in the four S1 AD-A7-* promotions (server-side passive path) and the T19 passive-MSS-default fix. The bulk of A8 (observability smoke M1, counter-coverage audits M2, knob audits M3, tcpreq narrow port M4, compliance matrix M5, shim passive drain S2, corpus classification S3, CI jobs T23) is **test-infrastructure** or **tooling** with no mTCP equivalent — mTCP has neither a packetdrill shim nor a counter-coverage audit. This review targets the wire-observable algorithmic changes only.

A7's mTCP review landed five Accepted Divergences (AD-1 .. AD-5). A8 retires two of them in full (AD-3, AD-4) and does not revisit the other three (AD-1, AD-2, AD-5 remain intentional carry-overs per A7 citations). A8 also introduces three **new** intentional divergences where we go more-RFC-correct than mTCP or stricter than mTCP.

### Ours — files reviewed

- `crates/dpdk-net-core/src/tcp_conn.rs`
  - `TcpConn.is_passive_open` flag (line 286) — A8 T11 addition, feeds the SynRetrans fire handler's active-vs-passive branch.
  - `new_passive` (line 499-544) — A8 T19 MSS fallback to 536 per RFC 9293 §3.7.1 / RFC 6691 MUST-15 (line 535).
- `crates/dpdk-net-core/src/tcp_input.rs`
  - `handle_syn_received` RST arm (line 451-468) — A8 T13 S1(c) return-to-LISTEN for passive-open, plus T12 S1(b) fallback.
  - `handle_syn_received` SYN-arm dispatch (line 485-500) — A8 T14 S1(d): SEG.SEQ==IRS → retransmit SYN-ACK; SEG.SEQ!=IRS → RST+Close+clear slot.
  - `handle_syn_received` bad-ACK arm (line 515-523) — A8 T12 S1(b) `clear_listen_slot_on_close`.
  - `handle_syn_received` success path (line 539-552) — A8 T11 `syn_retrans_timer_to_cancel` bubbled up on final-ACK.
  - `Outcome::clear_listen_slot_on_close`, `re_listen_if_passive`, `retransmit_syn_ack_for_passive` fields (line 284, 303, 323).
- `crates/dpdk-net-core/src/engine.rs`
  - `on_syn_retrans_fire` (line 2761-2891) — A8 T11 passive/active dispatch; Phase 3 is_passive guarded `clear_in_progress_for_conn` pre-force-close.
  - Outcome handler wiring for clear/re-listen/retransmit (line 3825-3869).
  - `emit_syn_ack_for_passive` (line 5767-5816) — A8 T11 SynRetrans arm + T14 idempotency guard.
  - `clear_in_progress_for_conn` (line 5888-5899) — A8 T12.
  - `re_listen_if_from_passive` (line 5927-5988) — A8 T13 S1(c) three-step return-to-LISTEN (clear slot + record state_trans[3][1] + tear down conn + cancel SynRetrans).
- `crates/dpdk-net-core/tests/ad_a7_syn_retrans.rs` — S1(a) regression.
- `crates/dpdk-net-core/tests/ad_a7_slot_cleanup.rs` — S1(b) regression.
- `crates/dpdk-net-core/tests/ad_a7_rst_relisten.rs` — S1(c) regression.
- `crates/dpdk-net-core/tests/ad_a7_dup_syn_retrans_synack.rs` — S1(d) regression.

### mTCP — files compared

- `third_party/mtcp/mtcp/src/tcp_in.c`
  - `HandlePassiveOpen` (line 61-82) — passive-open conn init; no per-RFC 536 fallback (mss seeded TCP_DEFAULT_MSS=1460 in `CreateTCPStream` at `tcp_stream.c:304`).
  - `ProcessRST` (line 196-252) — RST handling; SYN_RCVD → TCP_ST_CLOSED at line 213-219 (mTCP does NOT return-to-LISTEN on RST).
  - `Handle_TCP_ST_LISTEN` (line 749-764) — `rcv_nxt++` when coming from LISTEN, reused at `tcp_in.c:1311` dispatch from SYN_RCVD (skips rcv_nxt++ because state already SYN_RCVD).
  - `Handle_TCP_ST_SYN_RCVD` (line 840-903) — ACK=true path: handshake → Established + StreamEnqueue. ACK=false path (line 896-902): retransmit SYN-ACK via `AddtoControlList`.
  - `ProcessTCPPacket` SYN_RCVD dispatch (line 1308-1319) — `tcph->syn && seq == irs` → `Handle_TCP_ST_LISTEN` (SYN-ACK resend); else → `Handle_TCP_ST_SYN_RCVD` (only reacts on ACK; silent drop for non-ACK SYN-bearing segments with seq != irs).
- `third_party/mtcp/mtcp/src/timer.c`
  - `HandleRTO` (line 182-358) — SYN_RCVD branch at line 282-285 retransmits SYN-ACK via eventual re-control-list; budget `TCP_MAX_SYN_RETRY=7` at `tcp_in.h:70`.
- `third_party/mtcp/mtcp/src/tcp_util.c`
  - `ParseTCPOptions` (line 21-59) — no RFC-7323 wscale clamp; no 536 MSS fallback.
- `third_party/mtcp/mtcp/src/tcp_stream.c`
  - `CreateTCPStream` (line 224, `->mss = TCP_DEFAULT_MSS` at line 304) — default is 1460, not 536.
- `third_party/mtcp/mtcp/src/include/tcp_in.h`
  - `TCP_MAX_RTX=16`, `TCP_MAX_SYN_RETRY=7`, `TCP_MAX_BACKOFF=7` constants (line 69-71).

### Spec sections in scope

- Phase A8 design spec §4.1-4.5 (S1(a)-(d) behaviour changes + AD-A8-urg-dropped)
- Phase A8 plan T11, T12, T13, T14, T15, T16 (the mTCP-touching tasks)
- RFC 9293 §3.8.1 (retransmission), §3.10.7.4 First (RST in SYN_RCVD), §3.10.7.4 Fourth (SYN in SYN_RCVD), §3.7.1 (MSS)
- RFC 6298 §2 (RTO)
- RFC 6691 (MSS default fallback — MUST-15)

## Summary verdict

**PASS-WITH-ACCEPTED.**

A8's four S1 promotions retire two of the five A7 Accepted Divergences with mTCP (AD-3 and AD-4) in alignment with the spec §4 citations. The retirement of AD-3 is clean — the passive SYN-ACK retransmit now shares the active-open SynRetrans wheel with identical deadline/backoff/budget semantics, matching mTCP's `HandleRTO` SYN_RCVD branch (`timer.c:282-285`) algorithmically.

AD-4 retirement is **partial**: the benign case (dup-SYN with `SEG.SEQ == IRS`) now retransmits SYN-ACK, exactly matching mTCP's dispatch at `tcp_in.c:1308-1311`. The non-benign case (`SEG.SEQ != IRS`) goes stricter than mTCP — we RST+Close+clear-slot where mTCP silently drops. The stricter path is cited in spec §4.4 and is an RFC 9293 §3.10.7.4 Fourth legitimate reading; it is **newly divergent** from mTCP but documented.

S1(c) (AD-A7-rst-in-syn-rcvd-close-not-relisten) has no A7-mTCP-review predecessor and introduces a **new accepted divergence** where our code becomes more-RFC-correct than mTCP: we return-to-LISTEN per RFC 9293 §3.10.7.4 First, while mTCP transitions to CLOSED via `ProcessRST` (`tcp_in.c:213-219`). This is a project-rule-scoped divergence (feature-gated test-server-only; production still has no listen path).

A8 T19 (passive-MSS default 536) makes us more-RFC-correct than mTCP (which defaults to 1460 via `TCP_DEFAULT_MSS`). Added as a new accepted divergence for tracking.

No must-fix or missed-edge-case findings emerged. AD-1, AD-2, AD-5 from the A7 mTCP review remain open as carry-overs per their A7 citations; AD-3 and AD-4 are retired.

## Findings

### Must-fix (correctness divergence)

_None._

### Missed edge cases (mTCP handles, we don't)

_None._ Every mTCP edge case traced for S1(a)-(d) is now matched or exceeded by our code:

- SYN-ACK retransmit on lost final ACK (mTCP `Handle_TCP_ST_SYN_RCVD` line 896-902 + `HandleRTO` line 282-285) — matched by T11 passive SynRetrans wiring (`engine.rs:2852-2860`).
- Dup-peer-SYN with `seq == irs` → SYN-ACK resend (mTCP `tcp_in.c:1310-1311`) — matched by T14 `retransmit_syn_ack_for_passive` path.
- Budget exhaustion on SYN-ACK retransmits (mTCP `HandleRTO` `TCP_MAX_SYN_RETRY` line 266-278) — matched by our shared `> 3` cap in `on_syn_retrans_fire` Phase 3 (`engine.rs:2828-2838`), with `tcp.conn_timeout_syn_sent` counter bump + `ERROR{err=-ETIMEDOUT}` event emission.
- Listen-slot cleanup on every failure mode (mTCP has no direct equivalent — mTCP's StreamQueue-based backlog doesn't have the single-slot wedge problem we had) — matched by T12 three-site coverage (bad-ACK, RST-arm fallback for active-open, SYN-retrans budget exhaust).

### Accepted divergence (intentional — citations attached)

- **AD-1** *(carry-over from A7)* — Listen-slot data structure: capacity-1 `Option<ConnHandle>` vs bucketed `StreamQueue(backlog)`.
  - mTCP: `api.c:473-551` `mtcp_listen` allocates `StreamQueue(backlog)`; multi-slot acceptq.
  - Ours: `engine.rs:547` `listen_slots: Vec<(ListenHandle, ListenSlot)>`; each slot holds one in-progress + one accept-ready conn.
  - Citation: A7 spec §10.12 (listen-slot scope) + A8 spec §1.2 ("Multi-connection listen backlog (capacity > 1) ... deferred to whenever a future gate actually needs it").
  - A8 impact: unchanged. S1(a) SynRetrans + S1(b) slot-cleanup + S1(c) return-to-LISTEN all reinforce the single-slot design (the slot clears on every failure path so the next SYN lands cleanly) rather than pushing toward bucketed backlog.

- **AD-2** *(carry-over from A7)* — Accept-queue-full policy: RST+ACK at SYN arrival vs complete-handshake-then-RST.
  - mTCP: `tcp_in.c:877-885` emits RST only after handshake completes and `StreamEnqueue < 0`.
  - Ours: `engine.rs:5688-5690` `handle_inbound_syn_listen` rejects with RST+ACK at SYN arrival when slot is full.
  - Citation: RFC 9293 §3.10.7.1 + A7 AD-2 (permissive rejection timing).
  - A8 impact: unchanged.

- **AD-3** *(retired by A8 T11 — originally from A7)* — No SYN-ACK retransmit timer vs mTCP's RTO-driven retransmit.
  - mTCP: `tcp_in.c:759-764` `Handle_TCP_ST_LISTEN` + `tcp_in.c:896-902` SYN_RCVD no-ACK retransmit via `AddtoControlList`; `timer.c:182-358` `HandleRTO` drives the loss-detection; `TCP_MAX_SYN_RETRY=7` at `tcp_in.h:70`.
  - Ours (post-A8 T11): `engine.rs:5767-5816` `emit_syn_ack_for_passive` arms `SynRetrans` on the shared timer wheel on initial emit; `engine.rs:2761-2891` `on_syn_retrans_fire` dispatches on `conn.is_passive_open` to pick SYN|ACK (passive) vs SYN (active) retransmit shape; Phase 3 shared budget (`> 3` hardcoded cap — 3 retransmits + 1 initial) matches mTCP's budget semantics (different cap — we use 3, mTCP uses 7; budget-size difference is a deliberate trading-latency default, noted below).
  - Citation: A8 spec §4.1 (RFC 9293 §3.8.1 + RFC 6298 §2); tests `crates/dpdk-net-core/tests/ad_a7_syn_retrans.rs`.
  - **RETIRED 2026-04-22 (A8 T11).** Budget-size sub-divergence (3 vs 7) tracked under AD-5-new below.

- **AD-4** *(retired — partial — by A8 T14 — originally from A7)* — Retransmitted peer SYN in SYN_RCVD: silently dropped vs SYN-ACK resent.
  - mTCP: `tcp_in.c:1308-1311` detects `tcph->syn && seq == irs` in SYN_RCVD and jumps to `Handle_TCP_ST_LISTEN`, re-arming a SYN-ACK via control list. Non-matching (`seq != irs`) falls through to `Handle_TCP_ST_SYN_RCVD`, which only acts on `tcph->ack` — silent drop.
  - Ours (post-A8 T14):
    - `seg.seq == conn.irs` → `retransmit_syn_ack_for_passive = true` (`tcp_input.rs:485-492`) → engine calls `emit_syn_ack_for_passive` which retransmits with the same ISS via wheel-idempotent guard (`engine.rs:3856-3869`, `5778-5815`). **Matches mTCP exactly on this branch.**
    - `seg.seq != conn.irs` → `TxAction::Rst` + `new_state: Closed` + `clear_listen_slot_on_close` (`tcp_input.rs:493-499`). **Stricter than mTCP** (mTCP silent-drops).
  - Citation: A8 spec §4.4 ("RFC 9293 §3.10.7.4 Fourth strict reading"); tests `crates/dpdk-net-core/tests/ad_a7_dup_syn_retrans_synack.rs`.
  - **RETIRED 2026-04-22 (A8 T14)** for the benign case. The non-benign-seq case is a **new** divergence (stricter than mTCP); tracked under AD-4-strict-new below.

- **AD-5** *(carry-over from A7)* — SYN-ACK option bundle: unconditional MSS+WS+SACK+TS vs peer-gated.
  - mTCP: `tcp_in.c:79` `HandlePassiveOpen` parses peer options; `GenerateTCPOptions` in `tcp_out.c` emits only peer-advertised options.
  - Ours: `engine.rs:100-114` `build_connect_syn_opts` unconditional. Passive SYN-ACK retransmit via `emit_syn_ack_for_passive` carries the same full bundle.
  - Citation: A7 plan T5 + RFC 7323 §1.3 / §2.2 header-hygiene; A7 review AD-5.
  - A8 impact: unchanged. The passive SynRetrans wheel (T11) re-uses `emit_syn_with_flags` which preserves the full bundle, so every retransmitted SYN-ACK is byte-identical to the initial emission.

- **AD-3-new-bud** *(new with A8 T11 — divergence surfaces with the wiring)* — SYN retransmit budget: 3 (ours) vs 7 (mTCP).
  - mTCP: `TCP_MAX_SYN_RETRY=7` at `tcp_in.h:70`; `HandleRTO` line 266-278 gates with `cur_stream->sndvar->nrtx > TCP_MAX_SYN_RETRY`.
  - Ours: `engine.rs:2828` hardcoded `new_count > 3` — 3 retransmits plus the initial. Total budget window ≈ 75 ms with 5 ms `tcp_initial_rto_us` (5+10+20+40 ms).
  - Citation: `feedback_trading_latency_defaults.md` (prefer latency-favoring defaults over RFC recommendations). RFC 6298 §5.7 recommends "TCP SHOULD give up" at a value that yields at least 100 seconds of transmission effort — mTCP's 7 retries with exponential backoff = ~12.7 seconds with 100 ms base = well under 100s. Both stacks deviate from RFC-SHOULD; we deviate more aggressively in the trading-latency direction. No test in A8's corpus exercises >75 ms handshakes, so the tighter budget has no observable effect under the current test scope.
  - Promotion gate: any future phase whose corpus contains a scripted scenario that expects >3 retransmits revisits this.

- **AD-4-strict-new** *(new with A8 T14 — divergence vs mTCP, aligned with a strict RFC reading)* — Dup-SYN in SYN_RCVD with SEG.SEQ != IRS: RST+Close vs silent drop.
  - mTCP: `tcp_in.c:1313` falls through to `Handle_TCP_ST_SYN_RCVD` which ignores non-ACK segments (`tcp_in.c:845`). Silent drop.
  - Ours (post-A8 T14): `tcp_input.rs:493-499` returns `TxAction::Rst + new_state: Closed + clear_listen_slot_on_close`. Strictly more protective of our single-slot state against advanced-ISS confusion.
  - Citation: A8 spec §4.4 ("RFC 9293 §3.10.7.4 Fourth strict reading" — "send a reset segment, enter the CLOSED state"). RFC 9293 §3.10.7.4 Fourth actually prescribes **return-to-LISTEN for passive-OPEN** (not RST), so our behaviour is neither mTCP-aligned nor strict-RFC-aligned on the passive side. Spec §4.4 explicitly cites "mTCP reading" for the benign case and "strict RFC reading" for the non-benign case — these are NOT the same RFC paragraph being read differently; the spec is adopting a deliberately mixed policy.
  - Promotion gate: if the capacity > 1 listen slot ever lands (AD-1 retires), revisit whether return-to-LISTEN for non-IRS-matching SYN (the RFC prescription) is safer than RST+Close. For capacity-1 + test-server-only scope, RST+Close is defensible: advanced-ISS SYN on the same tuple is unambiguously adversarial (retry would need a fresh SYN with a fresh ISS, which our slot accepts after cleanup). **Note for human review: the spec's §4.4 citation for the non-benign branch ("RFC 9293 §3.10.7.4 Fourth") is selectively reading the `Otherwise, handle per the directions for synchronized states below` branch rather than the prior `passive OPEN → return to LISTEN` branch; this deserves a spec clarification.**

- **AD-5-relisten-new** *(new with A8 T13 — our behaviour matches RFC, mTCP's doesn't)* — RST in SYN_RCVD: return-to-LISTEN (ours, RFC-correct) vs close-to-CLOSED (mTCP).
  - mTCP: `tcp_in.c:213-219` `ProcessRST` in SYN_RCVD sets `state = TCP_ST_CLOSED` + `DestroyTCPStream`. No return-to-LISTEN; the conn is unconditionally destroyed. This is an mTCP **deviation** from RFC 9293 §3.10.7.4 First.
  - Ours (post-A8 T13): `engine.rs:5927-5988` `re_listen_if_from_passive` performs the three-step return-to-LISTEN (clear slot + record state_trans[3][1] + tear down flow-table entry) with test-server gating. RFC 9293 §3.10.7.4 First exactly.
  - Citation: RFC 9293 §3.10.7.4 First + A8 spec §4.3 + project rule spec §6 line 365 ("never transition to LISTEN in production" — preserved by `#[cfg(feature = "test-server")]` gate).
  - Ours is more-RFC-correct than mTCP. No promotion gate — this is an intentional improvement, not a deferred item.

- **AD-6-new-mss** *(new with A8 T19 — our behaviour matches RFC, mTCP's doesn't)* — Passive peer-MSS default when peer SYN omits MSS option: 536 (ours, RFC-correct) vs 1460 (mTCP).
  - mTCP: `tcp_stream.c:304` `stream->sndvar->mss = TCP_DEFAULT_MSS` where `TCP_DEFAULT_MSS = 1460` (`tcp_in.h:36`). If `ParseTCPOptions` doesn't find an MSS option, mss stays at 1460 — the initial value, not the RFC fallback.
  - Ours (post-A8 T19): `tcp_conn.rs:535` `c.peer_mss = opts.mss.unwrap_or(536)` — RFC 9293 §3.7.1 + RFC 6691 MUST-15.
  - Citation: A8 plan T19 + RFC 9293 §3.7.1 + RFC 6691 (MUST-15); tcpreq MissingMSS probe (`tools/tcpreq-runner/src/probes/mss.rs:missing_mss`) pins this.
  - Ours is more-RFC-correct than mTCP. No promotion gate.

### FYI (informational — no action required)

- **I-1** — mTCP carries a TODO at `tcp_in.c:198` "we need reset validation logic" inside `ProcessRST`. We implement in-window RST acceptance checks on each state's handler. Ours is more complete; mTCP's TODO is unimplemented.

- **I-2** — mTCP's `ProcessRST` for SYN_RCVD also only accepts the RST if `ack_seq == cur_stream->snd_nxt` (line 213-219). Our `handle_syn_received` RST arm does not gate on ack value — RFC 9293 §3.10.7.2 (acceptance of RST) requires the RST's seq number to be in-window; our sequence-number validation happens upstream in `tcp_input` before reaching `handle_syn_received`. Both stacks conform to RFC 9293 §3.10.7.2 via different placement; the observable behavior aligns.

- **I-3** — mTCP's SYN_RCVD retransmit budget via `TCP_MAX_SYN_RETRY=7` is ~12.7s with 100ms base RTO. Our `> 3` cap with 5ms base is ~75ms. Both stacks terminate handshakes that linger past a "reasonable" window; we prioritize latency, mTCP prioritizes connectivity. Tracked as AD-3-new-bud above.

- **I-4** — mTCP's `emit_syn_ack_for_passive` equivalent (`Handle_TCP_ST_SYN_RCVD` retransmit arm, line 896-902) emits via `AddtoControlList` which later batches SYN-ACK through `SendControlPacket` (`tcp_out.c:617-625`). Our engine emits inline via `emit_syn_with_flags`. Wire shape is identical; ordering within a burst may differ but no test in A8's suite measures burst ordering.

- **I-5** — mTCP has no per-conn `is_passive_open` flag — it distinguishes active vs passive via `socket ? passive : active` proxy checks (`tcp_stream.c:875 if (!cur_stream->socket)`), plus `TCP_ST_LISTEN → TCP_ST_SYN_RCVD` vs `TCP_ST_SYN_SENT → TCP_ST_ESTABLISHED` state-path. Our explicit boolean is both clearer and needed for the shared SynRetrans wheel dispatch. No correctness concern.

- **I-6** — A8 T14's idempotency guard in `emit_syn_ack_for_passive` (the `already_armed` check at `engine.rs:5778-5789`) cleanly handles the case where a dup-SYN arrives while the T11 SynRetrans wheel entry is still ticking — the retransmit TX counter is `tx_retrans` (not `tx_syn`) on the dup-SYN path, matching mTCP's retransmit semantics. mTCP's equivalent wheel re-arm in `HandleRTO` line 354 `AddtoControlList` is analogous; counter treatment is per-stack.

- **I-7** — mTCP's `HandlePassiveOpen` calls `ParseTCPOptions` which does NOT clamp wscale to 14 (noted in A7 FYI I-1). This remains true in A8; our `new_passive` at `tcp_conn.rs:536` still clamps via `.min(14)`. We are more-RFC-correct than mTCP.

- **I-8** — mTCP has no counter-coverage audit, no compile-time counter enumeration, no obs-smoke fail-loud test — the entire M1/M2/M3 deliverable set has no mTCP equivalent. mTCP uses TRACE_* macros (compile-time disabled by default); we use `AtomicU64` counters + event timestamps. The observability design is fundamentally different per project rule `feedback_observability_primitives_only.md`; not a comparable area.

- **I-9** — mTCP has no equivalent to our tcpreq narrow port (M4). mTCP predates tcpreq's 2020 publication and never incorporated MissingMSS / LateOption / Reserved-RX / Urgent probes. No comparison possible on this surface.

## Action items (gate phase tag)

### Must-fix
_None._

### Missed edge cases
_None._

### Accepted divergence — citations attached
- [x] **AD-1** *(carry-over)* — Citation attached: A7 spec §10.12 + A8 spec §1.2 ("Multi-connection listen backlog ... deferred").
- [x] **AD-2** *(carry-over)* — Citation attached: RFC 9293 §3.10.7.1 + A7 AD-2.
- [x] **AD-3** — **RETIRED 2026-04-22 (A8 T11).** Citation attached: A8 spec §4.1 + RFC 9293 §3.8.1 + RFC 6298 §2 + test `ad_a7_syn_retrans.rs`.
- [x] **AD-4** — **RETIRED (partial) 2026-04-22 (A8 T14).** Benign case retired; non-benign-seq case tracked under AD-4-strict-new. Citation attached: A8 spec §4.4 + RFC 9293 §3.10.7.4 Fourth (mTCP reading) + test `ad_a7_dup_syn_retrans_synack.rs`.
- [x] **AD-5** *(carry-over)* — Citation attached: A7 plan T5 + RFC 7323 §1.3/§2.2 (header hygiene vs behavioural inert).
- [x] **AD-3-new-bud** *(new — SYN-retrans budget size 3 vs 7)* — Citation attached: `feedback_trading_latency_defaults.md` + RFC 6298 §5.7 (both stacks deviate; ours in trading-latency direction). Promotion gate: any future phase corpus expecting >3 retransmits revisits this.
- [x] **AD-4-strict-new** *(new — dup-SYN seq != IRS: RST+Close vs silent drop)* — Citation attached: A8 spec §4.4 ("strict RFC reading" — with the caveat noted in the finding that the spec's §3.10.7.4 Fourth citation selectively reads the non-passive branch; human review should confirm whether this is intentional). Promotion gate: if AD-1 retires (multi-slot backlog), revisit vs RFC-prescribed return-to-LISTEN.
- [x] **AD-5-relisten-new** *(new — RST in SYN_RCVD: return-to-LISTEN vs close-to-CLOSED)* — Citation attached: RFC 9293 §3.10.7.4 First + A8 spec §4.3. Ours is more-RFC-correct; no promotion gate.
- [x] **AD-6-new-mss** *(new — passive peer-MSS default: 536 vs 1460)* — Citation attached: RFC 9293 §3.7.1 + RFC 6691 MUST-15 + A8 plan T19 + tcpreq MissingMSS probe. Ours is more-RFC-correct; no promotion gate.

### FYI
_None require action._

## Verdict

**PASS**

Gate rule: Must-fix and Missed-edge-cases sections are empty (no open `- [ ]` correctness items). Accepted-divergence section is fully citation-attached; all 9 ADs `[x]` complete (5 carry-overs + 4 new).

Substance: A8 retires two of five A7 mTCP Accepted Divergences cleanly (AD-3 full, AD-4 partial — the benign branch is now mTCP-aligned). A8 adds four new divergences: AD-3-new-bud (intentional trading-latency budget), AD-4-strict-new (intentional strict RFC-reading for capacity-1 listen-slot protection), AD-5-relisten-new (ours is more-RFC-correct than mTCP), and AD-6-new-mss (ours is more-RFC-correct than mTCP). None of the new divergences introduce correctness regressions; two of them make us strictly more RFC-conformant than the mTCP baseline.

The five Accepted Divergences that remain are all carry-overs with unchanged citations from the A7 review, per the dispatcher's note. A8's test scope (capacity-1 listen-slot, scripted packetdrill scenarios with deterministic delivery, shim passive drain) does not invalidate any of those citations; AD-1 / AD-2 / AD-5 remain valid deferrals for the same reasons they were valid at A7.

One item for human attention when editing: **AD-4-strict-new** — spec §4.4 cites "RFC 9293 §3.10.7.4 Fourth strict reading" for the SEG.SEQ != IRS → RST+Close branch, but the same RFC paragraph's first sentence ("If the connection was initiated with a passive OPEN, then return this connection to the LISTEN state and return") would prescribe return-to-LISTEN for a passive-open conn regardless of SEG.SEQ. The spec is adopting a mixed mTCP/RFC reading (mTCP for SEG.SEQ==IRS benign case, RFC's "Otherwise, handle per synchronized states" for SEG.SEQ!=IRS adversarial case). The selection is internally defensible and protective of our capacity-1 scope, but the review notes it for spec-author visibility — human may choose to annotate §4.4 with the mixed-reading rationale or relax to RFC-pure return-to-LISTEN when AD-1 retires.

Phase may tag `phase-a8-complete`.
