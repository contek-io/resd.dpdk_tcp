# Phase A10.5 mTCP Comparison Review

**Phase:** A10.5 — Layer H correctness under WAN-condition fault injection
**Reviewed at:** 2026-05-01
**Reviewer:** mtcp-comparison-reviewer subagent (opus 4.7)
**mTCP submodule SHA:** as vendored at `/home/ubuntu/resd.dpdk_tcp/third_party/mtcp/` (canonical submodule; the worktree at `/home/ubuntu/resd.dpdk_tcp-a10.5/third_party/mtcp/` was not initialized at review time, so all mTCP citations resolve against the canonical submodule path; functional equivalence guaranteed by the shared `.gitmodules` URL and pinned commit)
**Phase-scoped diff:** `git diff master..HEAD` on branch `phase-a10.5`
**Phase plan:** `docs/superpowers/plans/2026-05-01-stage1-phase-a10-5-layer-h-correctness.md`
**Spec refs claimed:** §10.8 (Stage 1 subset of Layer H netem matrix; PMTU-blackhole deferred), §10.10 (Stage 1 netem ship-gate smoke), §6.1 FSM legality (`Established` throughout assertion window, no illegal `StateChange`).

---

## Verdict

PROCEED

Two missed-edge-case items fall in scope of A10.5's "asserts against the existing observability surface only" mandate; both are about whether the assertion matrix is *catching* what the existing surface *can* surface, not about adding new counters. Beyond those, the algorithmic-parity surface here is mostly "mTCP doesn't have one" — A10.5 is a test-harness phase with no mTCP precedent — so the comparison is dominated by Accepted-divergence entries that the human will validate.

---

## Must-fix

(Items that block `phase-a10-5-complete` tag.)

*None.* No correctness divergences from mTCP in the assertion logic itself. The relation parser, FSM oracle, snapshot-delta machinery, and disjunctive evaluator are all internally consistent and don't conflict with anything mTCP would surface.

---

## Missed edge cases

(Behaviors mTCP handles or surfaces that this phase's matrix or assertions don't consider.)

- [x] **E-1** — `loss_correlated_burst_1pct` row asserts `tcp.tx_rto > 0` AND `tcp.tx_tlp > 0` together; mTCP's RTO-driven recovery (no TLP) is the closest precedent and produces RTO fires under correlated burst loss, but the conjunctive `tx_tlp > 0` requirement on this row is more aggressive than the mTCP-equivalent "loss happens during a tail; only RTO fires" pattern.
  - mTCP reference: `third_party/mtcp/mtcp/src/timer.c:200-260` (`HandleRTO`) increments `rstat.rto_cnt` on tail loss; mTCP has no TLP, so the closest equivalent is "RTO fires when fast retransmit can't unstick the burst". By comparison our row requires *both* signals, which assumes a specific interleaving (a burst that exhausts the dup-ACK window with at least one head-of-line tail-probe-eligible segment outstanding, then RTO escalating on a separate burst).
  - Our equivalent: `tools/layer-h-correctness/src/scenarios.rs:171-176` requires both counters strictly `>0`. For the `loss 1% 25%` correlated-burst spec, a 30-second window with a sufficiently small in-flight depth could plausibly produce only RTO fires (no TLP because the queue drains between bursts, no probe-eligible segment outstanding) — making the row spuriously fail.
  - Impact: medium. Realistic under low-throughput single-connection RTT workloads (which the layer-h harness uses). Not a stack-correctness issue; an over-constrained assertion.
  - Proposed fix: relax to disjunctive — `[tcp.tx_rto, tcp.tx_tlp] >0` — so the row passes when *either* loss-recovery mechanism fires. Keep `tcp.tx_retrans > 0` as the conjunctive anchor (any retransmit is required). The disjunctive form already exists in the engine (`disjunctive_expectations`) and is exercised by row 14, so the change is mechanical.
  - **Resolution:** Applied as-spec. Row 10 `counter_expectations` no longer carries individual `tx_rto > 0` / `tx_tlp > 0`; instead `disjunctive_expectations` carries `[tcp.tx_rto, tcp.tx_tlp] > 0`. `tcp.tx_retrans > 0` retained as the conjunctive anchor. Commit SHA recorded by the resolution commit on `phase-a10.5`.

- [x] **E-2** — Matrix has no row asserting "RST-on-the-wire under adversity does not silently move the FSM out of Established." mTCP processes RST in `Handle_TCP_ST_ESTABLISHED` via `ProcessRST` (`tcp_in.c:195-252`) which transitions to `CLOSE_WAIT` with `close_reason = TCP_RESET`. Under `corrupt 0.01%` netem, byte-level corruption of an in-flight ACK could land RFC-illegal RST flag bits ~1 in 4M segments; if the cksum offload misclassifies a corrupted segment as good (NIC offload false positive) and the random RST flag survives, the FSM departs Established. The phase's FSM oracle would catch this *if* the event queue surfaces the StateChange before the next observation tick — but the assertion table doesn't explicitly require `tcp.rx_rst == 0` on the corruption row, so a silent RST arrival that survived cksum validation would only surface as `FsmDeparted`/`IllegalTransition` in the same observation batch and not be cross-validated against the rx_rst counter delta.
  - mTCP reference: `third_party/mtcp/mtcp/src/tcp_in.c:1289-1296` (`if (tcph->rst) { cur_stream->have_reset = TRUE; if (cur_stream->state > TCP_ST_SYN_SENT) ProcessRST(...); }`) shows mTCP has no challenge-ACK / RFC 5961 RST validation gate — *any* in-window RST drops the connection. That's strictly weaker than RFC 5961, but it does mean a bad-RST under fault injection reliably moves the FSM.
  - Our equivalent: `tools/layer-h-correctness/src/scenarios.rs:225-235` (`corruption_001pct`) only checks the disjunctive cksum-bad counter and the implicit FSM oracle. No counter assertion for `tcp.rx_rst == 0` to cross-validate that an RST didn't slip through corrupted-but-classified-as-good (e.g., when cksum offload miscounts a corrupted ACK as good).
  - Impact: low-but-real. For the corruption row at 0.01%, with a full RTT load the likelihood is tiny per 30 s, but the FSM oracle / counter cross-check is *the* defense-in-depth signal at the assertion-window granularity.
  - Proposed fix: add `("tcp.rx_rst", "==0")` to the `corruption_001pct` row's `counter_expectations`. No engine change. This is purely an assertion-table strengthening and falls inside "asserts against the existing observability surface only" (`tcp.rx_rst` is already wired in `counters.rs:136`).
  - **Resolution:** Applied as-spec. Row 14 (`corruption_001pct`) now includes `("tcp.rx_rst", "==0")` alongside the existing `("obs.events_dropped", "==0")` in `counter_expectations`. Verified `tcp.rx_rst` resolves through `lookup_counter` at `counters.rs:653` (struct field at `counters.rs:136`); the `every_counter_name_resolves_via_lookup_counter` matrix-invariant test still passes. Commit SHA recorded by the resolution commit on `phase-a10.5`.

---

## Accepted divergence

(Conscious differences from mTCP, with concrete spec-section or memory-file citations.)

- **AD-1** — mTCP has no test harness or fault-injection module. There is no `third_party/mtcp/tests/`; the source tree has `mtcp/src/` (production stack), `apps/example/` (example servers), and `io_engine/`/`util/`. The closest mTCP precedent for "correctness under WAN conditions" is the reader's responsibility to run the example apps under external `tc netem`, with no scripted matrix and no liveness/invariant assertions. A10.5's existence as a test phase is therefore *strictly additive* over mTCP's surface — there is no parity check to fail.
  - Spec/memory citation: `docs/superpowers/specs/2026-05-01-stage1-phase-a10-5-layer-h-correctness-design.md` §1 ("Promote spec §10.10's informal 'end-to-end smoke under tc netem' to a named Layer H test phase. A formal netem matrix with **liveness + invariant assertions, not performance measurement**") + spec §10.13 (the gate's purpose is "algorithm/correctness parity and edge-case parity (explicitly *not* architecture parity)").

- **AD-2** — Counter granularity for checksum-bad differs. Row 14 (`corruption_001pct`) asserts disjunctively over `eth.rx_drop_cksum_bad` (NIC-offload-classified) and `ip.rx_csum_bad` (SW-path classified). mTCP's path has only an aggregate `nstat.rx_errors[ifidx]++` (`eth_in.c:50`) bumped from any `ProcessIPv4Packet` failure — bad cksum, bad version, fragment, etc. all roll into one device-scoped counter. A10.5's per-cause discrimination is strictly finer-grained than mTCP's.
  - Spec/memory citation: spec §4 row 14 + the offload-aware disjunction note explaining the `hw-offload-rx-cksum` cargo-feature interaction. mTCP's coarser `rx_errors` is documented in `third_party/mtcp/mtcp/src/include/stat.h:53`.

- **AD-3** — RACK-TLP detection is asserted in the matrix (rows 10, 15, 16, 17 reference `tcp.tx_tlp`, `tcp.rx_dup_ack`, `tcp.tx_rto`); mTCP has neither RACK nor TLP — only RFC 5681 fast-retransmit at `dup_acks == 3` (`tcp_in.c:417`) plus RTO from `tcp_in.c` / `timer.c`. Comparing our matrix's loss-recovery expectations against mTCP's as a baseline is therefore inappropriate; mTCP is the floor (RTO + 3-dup-ACK fast-retransmit), and our matrix tests RACK / TLP against the trading-latency preset's defaults.
  - Spec/memory citation: `feedback_trading_latency_defaults.md` — prefer latency-favoring defaults (RACK + TLP enabled) over RFC recommendations. mTCP's lack of RACK/TLP is confirmed by absence of those terms in `third_party/mtcp/mtcp/src/include/timer.h` and the source tree's `Makefile.in:117-121` SRCS list (no `rack.c` / `tlp.c`).

- **AD-4** — RX-mempool floor invariant (`tcp.rx_mempool_avail >= 32`) has no mTCP analog. mTCP uses `memory_mgt.c` allocators with no live-floor signal exposed to test harnesses; PR #9's RX-leak diagnostics (rx_mempool_avail + mbuf_refcnt_drop_unexpected) are dpdk-net-core-specific instrumentation tied to our DPDK mbuf model. The side-check is a defense against the precise iteration-7050 cliff documented in `docs/superpowers/reports/a10-ab-driver-debug.md`, which mTCP wouldn't see because it doesn't expose the leak-detect signal in the first place.
  - Spec/memory citation: spec §4 "Global side-checks" + spec §5.4 (`MIN_RX_MEMPOOL_AVAIL = 32`). mTCP's allocator API (`third_party/mtcp/mtcp/src/include/memory_mgt.h`) has no equivalent floor.

- **AD-5** — FSM legality oracle relies on engine-side `from == to` self-transition filter at push time (engine.rs:4348) so the oracle can short-circuit on `from == Established && to != Established`. mTCP emits no FSM event stream at all; FSM transitions are direct field writes (e.g., `tcp_in.c:756 cur_stream->state = TCP_ST_SYN_RCVD;`) with no event-queue equivalent. The "Established throughout assertion window" rule is enforceable in our stack via the InternalEvent::StateChange ring; mTCP would require source-instrumented `TRACE_STATE` log scraping to do the same. This is an enabling-feature-of-our-architecture divergence, not a correctness gap.
  - Spec/memory citation: spec §5.2 (engine-side filter at engine.rs:4348) + `feedback_observability_primitives_only.md` (libraries expose counters + event timestamps; application handles aggregation). mTCP's `TRACE_STATE` macro is `third_party/mtcp/mtcp/src/include/debug.h` — printf-style logging only, not an event stream.

---

## FYI

(Informational notes for future readers; not blocking.)

- **I-1** — mTCP processes ICMP "frag needed" (Type 3 Code 4) by logging only and returning `TRUE` without action (`third_party/mtcp/mtcp/src/icmp.c:127-129`: `case ICMP_DEST_UNREACH: TRACE_INFO("[INFO] ICMP Destination Unreachable message received\n"); break;`). mTCP has no PLPMTUD or ICMP-PMTU validation. A10.5's deferring PMTU-blackhole to Stage 2 is therefore not a regression vs. mTCP — they don't process it either.

- **I-2** — mTCP's dup-ACK counter is per-stream (`cur_stream->rcvvar->dup_acks` in `tcp_in.c:387`) and never aggregated. Our `tcp.rx_dup_ack` is engine-aggregate and is what rows 11, 12, 13, 16, 17 assert against. mTCP's per-stream counter resets on every non-duplicate ACK (`tcp_in.c:406`) — ours appears to monotonically increment (counter-only, never reset). Sanity-check that rows asserting `rx_dup_ack > 0` over a 30 s window with a single connection wouldn't be confused by reset semantics — they shouldn't be, since the assertion is on the delta over the assertion window, but worth noting that comparing "absolute counts" between mTCP and our stack would be misleading.

- **I-3** — Reorder gap=3 boundary case: our threshold for fast retransmit is the same RFC 5681 default (3) that mTCP enforces at `tcp_in.c:417` (`if (dup && cur_stream->rcvvar->dup_acks == 3)`). Spec §4 row 13's `tx_retrans == 0` assertion is correct for *both* stacks — netem `reorder gap 3 50%` produces dup-ACK runs that don't reliably exceed 2, so the threshold is not crossed. mTCP would produce the same result. The phase's note "RACK reorder window absorbs" is technically true only of our stack (mTCP has no RACK reorder window), but the conclusion happens to match. Worth surfacing to the human if the trading-latency preset later adds reorder-aggressive RACK that *would* trigger retransmit on gap=3 — that would be a row-13-needs-retuning case unique to our stack.

- **I-4** — `obs.events_dropped == 0` per-batch defensive check has no mTCP analog. mTCP's event-equivalent is the eventpoll queue (`eventpoll.c`); on overflow it doesn't drop, it just blocks `mtcp_epoll_wait` callers. A10.5's bounded-event-queue semantics + drop counter is ours-specific. The check is good practice and orthogonal to mTCP comparison.

- **I-5** — `TcpRetrans` and `TcpLossDetected` events are gated on `EngineConfig::tcp_per_packet_events` (default `false`). Under default config, the EventRing for the failure bundle won't carry per-retransmit events on rows 7-10, 15-17 even when those rows fire retransmits. This is intentional (per-packet events are for forensic sessions) but means a failure bundle for, say, `loss_5pct` will have less per-retransmit detail than an operator might expect — they'd need to run with `tcp_per_packet_events = true` to capture it. Surfacing because the spec doesn't call this out and a future operator chasing a layer-h failure could waste time looking for retrans events that aren't being emitted.

- **I-6** — `EventKind::Other` fallthrough in `record_from_event` (`observation.rs:240-249`) emits `emitted_ts_ns: 0` and `conn_idx: 0` for unhandled InternalEvent variants (notably `Readable`, `Writable`, `ApiTimer`). The fallthrough is documented as deliberate ("the bundle remains stable across future tcp_events additions"), and the FSM oracle / IllegalTransition logic only reads `StateChange` variants explicitly, so this doesn't affect correctness. But: under `corruption_001pct` if a partial-read split fires a `Readable` event with the corrupted payload before the cksum-bad counter increments, the bundle would carry an `Other` record with no `emitted_ts_ns`, which is unhelpful for forensic timing reconstruction. Low priority. mTCP not relevant here.

- **I-7** — No mTCP equivalent for the `enforce_single_fi_spec` invariant (main.rs:296-316). mTCP has no FaultInjector and no env-var-driven adversity injection. The invariant is correct for our once-per-process EAL constraint and ports-faithfully from `tools/bench-stress`.

---

## Verification trace

Files read in the working tree (`/home/ubuntu/resd.dpdk_tcp-a10.5/`):

- `docs/superpowers/plans/2026-05-01-stage1-phase-a10-5-layer-h-correctness.md` (lines 1-200; phase plan structure + matrix shape)
- `docs/superpowers/specs/2026-05-01-stage1-phase-a10-5-layer-h-correctness-design.md` (lines 1-512; matrix rows, observation loop, lifecycle, risk register)
- `tools/layer-h-correctness/src/scenarios.rs` (full file; 17-row MATRIX)
- `tools/layer-h-correctness/src/observation.rs` (full file; EventRing, FSM oracle, observe_batch, side-checks)
- `tools/layer-h-correctness/src/assertions.rs` (full file; Relation parse/check, evaluators)
- `tools/layer-h-correctness/src/counters_snapshot.rs` (full file; lookup_counter wrapper, side-check counter list, MIN_RX_MEMPOOL_AVAIL = 32)
- `tools/layer-h-correctness/src/workload.rs` (full file; per-scenario lifecycle)
- `tools/layer-h-correctness/src/main.rs` (full file; CLI, single-FI-spec invariant, pre-flight resolution)
- `tools/layer-h-correctness/src/report.rs` (lines 1-300; Markdown writer, JSON failure bundle, EventKind serialization)
- `tools/layer-h-correctness/src/lib.rs` (façade)
- `tools/layer-h-correctness/tests/scenario_parse.rs` (matrix invariants)
- `tools/layer-h-correctness/tests/external_netem_skips_apply.rs` (CLI smoke)
- `tools/bench-stress/src/scenarios.rs` (lines 1-100; cross-check the spec's "pre-existing bench-stress reorder bug" note — confirmed at line 72: bench-stress row 3 has no base delay)
- `crates/dpdk-net-core/src/tcp_events.rs` (lines 1-200; InternalEvent variants + EventQueue overflow semantics)
- `crates/dpdk-net-core/src/counters.rs` (lines 1-300; counter struct shape, including `rx_dup_ack`, `tx_rto`, `tx_tlp`, `rx_csum_bad`, `eth.rx_drop_cksum_bad`, `tcp.mbuf_refcnt_drop_unexpected`, `tcp.rx_mempool_avail`)
- `crates/dpdk-net-core/src/engine.rs` (around line 4348 — `from == to` self-transition filter at `transition_conn`; around lines 200-410 — `EngineConfig` defaults including `tcp_per_packet_events = false`, `tcp_max_retrans_count = 15`; around line 5400-5800 — retransmit primitive)

mTCP files inspected (canonical submodule at `/home/ubuntu/resd.dpdk_tcp/third_party/mtcp/`):

- `mtcp/src/tcp_in.c:1-1369`:
  - dup-ACK detection at lines 373-396 (`payload == 0`, `wnd unchanged`, `outstanding unacked`, `ack_seq == last_ack_seq`)
  - 3-dup-ACK fast-retransmit threshold at line 417 (`dup_acks == 3`)
  - cwnd inflation post-3rd dup at line 466 (`dup_acks > 3`)
  - PAWS gate at lines 111-145 (`saw_timestamp` + `TCP_SEQ_LT(ts.ts_val, ts_recent)`)
  - sequence validation at lines 149-184 (`TCP_SEQ_BETWEEN`)
  - RST handling at lines 195-252 (`ProcessRST` — moves to CLOSE_WAIT on in-state RST without challenge-ACK)
  - cksum verify at lines 1224-1241 (returns ERROR ⇒ caller bumps `rx_errors[ifidx]`)
  - FSM dispatch at lines 1296-1365 (no event emission, direct state writes)
- `mtcp/src/timer.c:200-358` (`HandleRTO`): RTO backoff doubling, ssthresh / cwnd reduction, `rstat.rto_cnt++` increment
- `mtcp/src/icmp.c:104-142` (`ProcessICMPPacket`): ICMP DEST_UNREACH logged only, no PMTU action
- `mtcp/src/eth_in.c:1-57`: rx_packets / rx_bytes / rx_errors per-iface counters
- `mtcp/src/ip_in.c:1-63`: IP cksum + version validation
- `mtcp/src/include/stat.h:1-85`: full mTCP counter surface — net_stat, run_stat, time_stat, bcast_stat, timeout_stat. Confirmed no `rx_dup_ack`, no `tx_tlp`, no `rx_csum_bad`, no `mempool_avail`, no event stream.
- `mtcp/src/include/timer.h:1-54`: RTO + timewait + timeout list APIs only — no TLP, no RACK
- `mtcp/src/Makefile.in:117-121`: complete SRCS list — confirms absence of rack.c / tlp.c / fault_injector.c
- `Makefile.am:1-3` + `configure.ac:1-50`: confirms absence of `tests/` subdirectory

Assertions evaluated:

- mTCP has no test harness for WAN-condition correctness ⇒ confirmed (AD-1).
- mTCP's checksum-bad counter is device-scoped aggregate (`rx_errors[ifidx]`), not per-cause ⇒ confirmed (AD-2).
- mTCP has neither RACK nor TLP ⇒ confirmed by absence in source tree + `timer.h` only exposing RTO + timewait (AD-3).
- mTCP's 3-dup-ACK fast-retransmit threshold matches our trading-latency default ⇒ confirmed (`tcp_in.c:417`); reorder-gap=3 expectation `tx_retrans == 0` would hold for both stacks (I-3).
- mTCP processes RST in ESTABLISHED without RFC 5961 challenge-ACK ⇒ confirmed (`tcp_in.c:1289-1296`); strengthens the case for E-2 (cross-validating `rx_rst == 0` on corruption row).
- Layer-H-correctness asserts conjunctively `tx_rto > 0 AND tx_tlp > 0` on row 10 ⇒ over-constrained vs. mTCP-precedent expectation that *some* loss-recovery mechanism fires (E-1).
- `tcp.rx_rst == 0` is wired in our counter surface and is reachable via lookup_counter, so the proposed E-2 fix is a one-line matrix edit, no engine change ⇒ verified at `counters.rs:136`.
- `MIN_RX_MEMPOOL_AVAIL = 32` floor invariant has no mTCP analog ⇒ confirmed (AD-4).
- FSM event stream + `from == to` filter is dpdk-net-core-specific ⇒ confirmed at `engine.rs:4348` (AD-5).

Items deliberately NOT reviewed (per spec §10.13 "explicitly *not* architecture parity"):

- mTCP's per-thread / multi-lcore model vs. our RTC model.
- mTCP's `mtcp_epoll_*` API vs. our event-stream callback API.
- mTCP's locking patterns vs. our single-lcore borrow-checked pattern.
- The orchestrator scripts (`scripts/layer-h-{smoke,nightly}.sh`) — operator-side bash + AWS provisioning, mTCP doesn't have an equivalent.
- The Markdown report format — presentation, not algorithm.
- `--external-netem` orchestration mode — bench-stress carry-forward, not TCP-stack logic.
