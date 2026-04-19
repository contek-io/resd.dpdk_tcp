# Phase A5.5 — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent
- Date: 2026-04-19
- mTCP submodule SHA: f9e2d1d80a84f8aef9de2fcc3a3ce25bd7c9d3ae (unchanged since phase-a5 review; `third_party/mtcp` not bumped this phase)
- Our commit: f72146b (branch `phase-a5.5`, 17 of 20 A5.5 tasks landed; review gate is task 18)

## Scope

Our files reviewed:
- `crates/resd-net-core/src/tcp_events.rs` (soft-cap + drop-oldest queue, `emitted_ts_ns` on every variant, counter wiring)
- `crates/resd-net-core/src/counters.rs` (`ObsCounters` group; `tcp.tx_tlp_spurious`)
- `crates/resd-net-core/src/tcp_tlp.rs` (`TlpConfig` POD; `pto_us(srtt, &cfg, flight_size)` with FlightSize-1 penalty per RFC 8985 §7.2)
- `crates/resd-net-core/src/tcp_conn.rs` (5 TLP knob fields; 4 runtime state fields; `syn_tx_ts_ns`; `ConnStats` POD + `stats()`; `tlp_arm_gate_passes`; `tlp_config`; `maybe_seed_srtt_from_syn`; `attribute_dsack_to_recent_tlp_probe`)
- `crates/resd-net-core/src/engine.rs` (`on_rto_fire` §6.3 `RACK_mark_losses_on_RTO` pass; `send_bytes` calls `arm_tlp_pto`; emission-time push wiring; `syn_tx_ts_ns` stamp in `emit_syn` gated by `syn_retrans_count == 0`)
- `crates/resd-net-core/src/tcp_input.rs` (`handle_syn_sent` seeds SRTT-from-SYN; DSACK path attributes to recent TLP probes)
- `crates/resd-net-core/src/tcp_rack.rs` (new `rack_mark_losses_on_rto` pure helper)
- `crates/resd-net-core/src/flow_table.rs` (`get_stats(handle, send_buffer_bytes)` slow-path getter)
- `crates/resd-net/src/api.rs` + `crates/resd-net/src/lib.rs` (`event_queue_soft_cap` validation; 5 `tlp_*` connect opts validation; `resd_net_conn_stats` extern + `resd_net_conn_stats_t` POD)

mTCP files referenced (for scope-comparison; no behavioral analog expected):
- `third_party/mtcp/mtcp/src/eventpoll.c` — fixed-size epoll event queue; overflow prints `TRACE_ERROR` and returns `-1` (no drop-oldest, no counter)
- `third_party/mtcp/mtcp/src/timer.c`, `tcp_in.c`, `tcp_stream.c` — no TLP, no RACK, no SYN-RTT seed
- `third_party/mtcp/mtcp/src/tcp_util.c` — RTT sampling on data ACK only; SYN handshake is not sampled

Spec sections in scope: design spec §3.1 (emission-time events), §3.2 (queue soft-cap), §3.3 (stats getter), §3.4 (TLP knobs), §4 (API additions), §6.3 RFC matrix, §6.4 ADs, §9.1 counters, §10.13 (mTCP review gate).

## Findings

### Topic 1 — Event-queue overflow accounting (A5.5 tasks 3-4-5)

- mTCP `eventpoll.c:596-602` (`raise_pending_streams`): on `eq->num_events >= eq->size`, emits `TRACE_ERROR` to stderr and returns `-1`. No drop-oldest, no counter, no high-water gauge.
- Ours `tcp_events.rs:121-132` (`EventQueue::push`): drops oldest event on overflow, bumps `obs.events_dropped`, latches `obs.events_queue_high_water` via `fetch_max`. `with_cap` asserts `cap >= 64` (mirrored by `-EINVAL` at `resd_net_engine_create` entry).
- **Classification: scope-difference.** mTCP has no analog; its overflow behaviour (hard error, fail the push, silent stderr line) is a known limitation of the reference code. No behavioral divergence finding; no AD needed — this is a net-positive addition in our stack.

### Topic 2 — Per-connection stats getter (A5.5 tasks 6-7)

- mTCP has no per-connection stats projection API. Introspection is confined to `TRACE_*` macros compiled out at release builds.
- Ours `flow_table.rs:87-89` + `resd-net/src/lib.rs:353-` (`resd_net_conn_stats`): slow-path 9-field POD (`snd_una`, `snd_nxt`, `snd_wnd`, `send_buf_bytes_pending`, `send_buf_bytes_free`, `srtt_us`, `rttvar_us`, `min_rtt_us`, `rto_us`). `-EINVAL` on null engine/out, `-ENOENT` on unknown handle, `0` on success.
- **Classification: scope-difference.** No AD needed.

### Topic 3 — TLP tuning knobs + multi-probe budget + DSACK spurious-probe attribution (A5.5 tasks 9-12)

- mTCP has no TLP at all — no PTO formula, no probe selection, no RACK/TLP interlocks. `third_party/mtcp/mtcp/src/timer.c` + `tcp_in.c` use only 3-dup-ACK fast-retransmit + RTO. Grep for `TLP`, `RACK`, `TailLoss` across `third_party/mtcp/mtcp/src` returns zero matches.
- Ours:
  - `tcp_tlp.rs:63-74` (`pto_us`) — now parameterized by `TlpConfig` (floor, multiplier, FlightSize-gate bypass); defaults preserve A5 RFC 8985 behavior exactly.
  - `tcp_conn.rs:373-391` (`tlp_arm_gate_passes`) — multi-probe budget, RTT-sample-since-last-probe guard, SRTT-present guard, `tlp_timer_id.is_some()` suppression.
  - `tcp_conn.rs:463-496` (`attribute_dsack_to_recent_tlp_probe`) — 4·SRTT plausibility window; most-recent-wins ring (5 slots) for spurious-probe accounting.
  - `tcp_input.rs:547-549` — DSACK path attributes to `tcp.tx_tlp_spurious` via the ring.
- **Classification: scope-difference.** Five TLP knobs + multi-probe ring + DSACK-spurious attribution are net additions over mTCP; no behavioral divergence finding.

### Topic 4 — AD-18 closure: arm TLP PTO on every new-data send (A5.5 task 15)

- This is the **closure of the mTCP review's E-2 finding** (phase-a5-mtcp-compare.md:49-54, promoted to AD-8 / AD-18 in the A5 RFC review).
- A5 behavior: TLP was armed only in the ACK-handler arm block (`engine.rs:1549-1584` at A5 HEAD); the pre-first-ACK tail-loss window relied on RTO fallback (≥5 ms default).
- A5.5 behavior: `engine.rs:2665-2667` — on every `send_bytes` path where `accepted > 0`, `self.arm_tlp_pto(handle)` is called. `arm_tlp_pto` at `engine.rs:2679-2715` consults `tlp_arm_gate_passes()` (rejects when nothing in flight, TLP already armed, budget exhausted, RTT-sample-gate closed, or no SRTT yet) and schedules the PTO via `timer_wheel.add`. After Task 13 (SRTT-from-SYN), SRTT is non-zero from ESTABLISHED onward, so the first data burst is now TLP-covered.
- **Classification: AD-18 retired (closed in A5.5).** The A5 RFC review already marks this "Closed in A5.5" (phase-a5-rfc-compliance.md:231); the A5 mTCP review's E-2 is now closed by virtue of this wiring. No new AD.

### Topic 5 — AD-17 closure: RFC 8985 §6.3 `RACK_mark_losses_on_RTO` (A5.5 task 14)

- mTCP has no RACK implementation at all; §6.3 has no mTCP analog. mTCP's RTO handler (`timer.c:HandleRTO`) does a go-back-N style single-segment retransmit and exponential backoff — no age-based RACK batch marking.
- A5 behavior: `on_rto_fire` retransmitted the front entry only; subsequent ACKs triggered RACK detect-lost for trailing losses (one-seg-per-ACK dribble).
- A5.5 behavior: `engine.rs:884-935` — on RTO fire, `tcp_rack::rack_mark_losses_on_rto` (`tcp_rack.rs:106-130`) walks `snd_retrans.entries` and returns every index matching the §6.3 formula (`seq == snd_una` OR `xmit_us + RTT + reo_wnd <= now_us`, minus sacked / already-lost / cum-acked). `on_rto_fire` retransmits ALL matches in one burst (bumping `tx_retrans` N times and `tx_rto` exactly once). Defensive fallback to front-only retransmit if the helper returns empty (impossible when `snd_retrans` is non-empty because `seq == snd_una` always matches the front).
- **Classification: no mTCP analog — AD-17 retired (closed in A5.5) against RFC 8985 §6.3.** No new AD for the mTCP comparison.

### Topic 6 — SRTT-from-SYN handshake round-trip (A5.5 task 13, RFC 6298 §3.3 MAY)

- mTCP does not sample RTT from the SYN handshake. Grep for `syn.*timestamp|first_ack|SeedSRTT|srtt.*syn` in `third_party/mtcp/mtcp/src` returns zero matches. mTCP's first RTT sample is taken on the first data-ACK.
- Ours: `engine.rs:694-702` stamps `c.syn_tx_ts_ns = now_ns` on the original SYN emission only (Karn's rule: guarded by `c.syn_retrans_count == 0`). `tcp_input.rs:372` calls `conn.maybe_seed_srtt_from_syn(clock::now_ns())` in `handle_syn_sent`; the helper at `tcp_conn.rs:437-451` rejects retransmit-ambiguous samples (`syn_retrans_count != 0`) and out-of-bounds values (`!(1..60_000_000).contains(rtt_us)`), and otherwise feeds `rtt_est.sample` + `rack.update_min_rtt`.
- **Classification: scope-difference.** mTCP doesn't do this optional seeding; we do, consistent with RFC 6298 §3.3 MAY and our trading-latency-defaults memory (earlier SRTT estimate improves RTO/TLP sizing on the first data burst). No new AD for the mTCP comparison — already covered by the RFC review's `AD-A5-5-srtt-from-syn` entry.

## AD retirements from A5 Stage-2 list

- **AD-15** (TLP pre-fire state: `TLP.end_seq` + `TLP.is_retrans`) — retired in A5.5 Task 10/11; superseded by the 5-slot `tlp_recent_probes` ring + `tlp_consecutive_probes_fired < tlp_max_consecutive_probes` budget gate. Already marked "Closed in A5.5" in phase-a5-rfc-compliance.md:150.
- **AD-17** (§6.3 `RACK_mark_losses_on_RTO` not invoked in `on_rto_fire`) — retired in A5.5 Task 14; see Topic 5 above. Already marked "AD-17 closed in A5.5" in phase-a5-rfc-compliance.md:231.
- **AD-18** (TLP-arm-on-send deferred to Stage 2; mirrors mTCP E-2) — retired in A5.5 Task 15; see Topic 4 above. The A5 mTCP review's E-2 is now closed by the `arm_tlp_pto` call in `send_bytes` (engine.rs:2665-2667).

No Stage-2 AD remains open after A5.5 in the categories A5.5 touched. (AD-13 adaptive `reo_wnd` via DSACK and AD-16 RACK §6.2 Step 2 spurious-retrans guard are explicitly Stage-2 per the A5.5 plan's "Deferred to later phases" section.)

## Must-fix (correctness divergence)

*(none — 0 items)*

## Missed edge cases (mTCP handles, we don't)

*(none — 0 items. mTCP has no analog for any A5.5 topic; every A5.5 addition is scope-positive.)*

## Missing SHOULD / MUST

*(none — 0 items. This gate is scoped to mTCP comparison; RFC MUST/SHOULD coverage lives in the parallel `phase-a5-5-rfc-compliance.md` review.)*

## Accepted divergence (intentional — draft for human review)

*(none new. All A5.5 additions are scope-positive vs mTCP; three previously-open Stage-2 ADs from the A5 review (AD-15 / AD-17 / AD-18) are retired above. No new AD needs a human signature.)*

## FYI (informational — no action required)

- **I-1** — mTCP's epoll event queue error path (`eventpoll.c:596-602`) prints a `TRACE_ERROR` and returns `-1` on overflow; downstream callers can silently lose events if they don't check the return. Our drop-oldest + counter approach is strictly more observable and aligns with `feedback_observability_primitives_only.md`.
- **I-2** — mTCP's fixed per-epoll-fd queue (`CreateEventQueue(size)` at `eventpoll.c:58-78`) is pre-allocated at create time; our `VecDeque::with_capacity(cap.min(DEFAULT_SOFT_CAP))` grows lazily up to the default 4096. At the same soft-cap (4096) both stacks consume ~128 KiB of event storage. No behavioral divergence.
- **I-3** — mTCP's RTT sampler (`tcp_in.c::EstimateRTT`) only runs on first-transmit ACKs (their Karn's-rule equivalent); RFC 6298 §3.3 SYN seeding is not attempted. Our seeding is an additive improvement covered by `AD-A5-5-srtt-from-syn`.
- **I-4** — RACK-TLP remains without an mTCP comparator (noted in phase-a5-mtcp-compare.md:I-7). All of A5.5's RACK/TLP additions (AD-17 closure, AD-18 closure, 5 TLP tuning knobs, DSACK-spurious attribution) are RFC-driven, not mTCP-divergence-driven.

## Verdict

**PASS** — gate clean.

- Must-fix: 0
- Missed edge cases: 0
- Missing SHOULD: 0
- New ADs: 0
- AD retirements recorded: 3 (AD-15, AD-17, AD-18 — see "AD retirements" section above)

No open `[ ]` checkboxes in Must-fix or Missed-edge-cases. The `phase-a5-5-complete` tag is not blocked by this review.
