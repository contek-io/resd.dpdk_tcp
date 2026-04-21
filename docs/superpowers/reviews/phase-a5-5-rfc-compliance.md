# Phase A5.5 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent
- Date: 2026-04-19
- RFCs in scope: 6298 §2.2 / §3 (Karn's), 8985 §6.3, 8985 §7.2, 8985 §7.3 step 2
- Our commit: `f72146b305e92b8c660519263c9eead1a7c2f8d3` (branch `phase-a5.5`, 17/20 A5.5 tasks landed)

## Scope

- Our files reviewed:
  - `crates/dpdk-net-core/src/tcp_tlp.rs` (migrated `pto_us` + `TlpConfig` POD)
  - `crates/dpdk-net-core/src/tcp_conn.rs` (5 TLP knobs, runtime TLP state, `syn_tx_ts_ns`, `tlp_arm_gate_passes`, `maybe_seed_srtt_from_syn`, `attribute_dsack_to_recent_tlp_probe`, `ConnStats`)
  - `crates/dpdk-net-core/src/tcp_input.rs` (`handle_syn_sent` SYN-seed site; DSACK-to-TLP-attribution site; ACK-path `on_rtt_sample_tlp_hook` / `on_new_data_ack_tlp_hook`)
  - `crates/dpdk-net-core/src/tcp_rack.rs` (new `rack_mark_losses_on_rto` helper)
  - `crates/dpdk-net-core/src/engine.rs` (`on_rto_fire` §6.3 pass, `arm_tlp_pto` helper + `send_bytes` call-site, `emit_syn` `syn_tx_ts_ns` stamping)
  - `crates/dpdk-net-core/src/tcp_events.rs` (`EventQueue` soft-cap + drop-oldest + counter wiring)
  - `crates/dpdk-net-core/src/counters.rs` (new `ObsCounters` group + `tx_tlp_spurious`)
  - `crates/dpdk-net/src/api.rs` + `crates/dpdk-net/src/lib.rs` (5 TLP ABI fields + validation, 3 new counter fields, `dpdk_net_conn_stats` extern)
  - `crates/dpdk-net-core/tests/knob-coverage.rs` (5 A5.5 TLP knobs + `event_queue_soft_cap`)

- Spec §6.3 rows verified:
  - RFC 6298 §3.3 (renamed from "yes" to "yes (A5.5)" with SYN-seed explanation — spec §6.3 line 387)
  - RFC 8985 row (§6.3 `RACK_mark_losses_on_RTO` + §7.2 arm-on-send closure notes; 5 new per-connect TLP tuning knobs enumerated — spec §6.3 line 386)

- Spec §6.4 deviations touched (new, all per Task 16):
  - `AD-A5-5-srtt-from-syn` (spec §6.4 line 409)
  - `AD-A5-5-rack-mark-losses-on-rto` (spec §6.4 line 410)
  - `AD-A5-5-tlp-arm-on-send` (spec §6.4 line 411)
  - `AD-A5-5-tlp-pto-floor-zero` (spec §6.4 line 412)
  - `AD-A5-5-tlp-multiplier-below-2x` (spec §6.4 line 413)
  - `AD-A5-5-tlp-skip-flight-size-gate` (spec §6.4 line 414)
  - `AD-A5-5-tlp-multi-probe` (spec §6.4 line 415)
  - `AD-A5-5-tlp-skip-rtt-sample-gate` (spec §6.4 line 416)

- Retirements recorded in `docs/superpowers/reviews/phase-a5-rfc-compliance.md`:
  - AD-15 (TLP pre-fire state machine) — superseded by `tlp_recent_probes` + `tlp_consecutive_probes_fired` budget (phase-a5-rfc-compliance.md:150)
  - AD-17 (RACK mark-losses-on-RTO) — closed by `rack_mark_losses_on_rto` helper call in `on_rto_fire` (phase-a5-rfc-compliance.md:163)
  - AD-18 (TLP-arm-on-send) — closed by `arm_tlp_pto` helper invocation from `Engine::send_bytes` TX path (phase-a5-rfc-compliance.md:170)

## Findings

### Must-fix (MUST/SHALL violation)

_(none — 0 open)_

### Missing SHOULD (not in §6.4 allowlist)

_(none — 0 open. The SHOULD at RFC 8985 §7.2 arm-on-send is now satisfied by `AD-A5-5-tlp-arm-on-send`; the RACK-§6.3 SHOULD-equivalent is satisfied by `AD-A5-5-rack-mark-losses-on-rto`.)_

### Accepted deviation (covered by spec §6.4)

- **AD-A5-5-srtt-from-syn** — SRTT seeded from SYN handshake round-trip on the first SYN's ACK.
  - RFC clause: `docs/rfcs/rfc6298.txt:133` — "(2.2) When the first RTT measurement R is made, the host MUST set SRTT <- R, RTTVAR <- R/2, RTO <- SRTT + max(G, K*RTTVAR)". `rfc6298.txt:184-191` — Karn's algorithm: "RTT samples MUST NOT be made using segments that were retransmitted (and thus for which it is ambiguous whether the reply was for the first instance of the packet or a later instance)."
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:409`
  - Our code behavior: `tcp_conn.rs:436-451` `maybe_seed_srtt_from_syn` gates on `syn_retrans_count == 0` (Karn) AND `syn_tx_ts_ns != 0` AND `rtt_us ∈ [1, 60_000_000)` before calling `rtt_est.sample(rtt_us)` (RFC 6298 §2.2 first-sample branch) and `rack.update_min_rtt`. Call site: `tcp_input.rs:372` inside `handle_syn_sent` post-option-parse. SYN TX timestamp stamped at `engine.rs:694-700` ONLY when `c.syn_retrans_count == 0`; the retransmit path at `engine.rs:1211` bumps the count _before_ re-entering `emit_syn`, so the initial-SYN guard is tight.

- **AD-A5-5-rack-mark-losses-on-rto** — `RACK_mark_losses_on_RTO` pass invoked at the top of `on_rto_fire` Phase 3.
  - RFC clause: `docs/rfcs/rfc8985.txt:907-919` — "Upon RTO timer expiration, RACK marks the first outstanding segment as lost (since it was sent an RTO ago); for all the other segments, RACK only marks the segment as lost if the time elapsed since the segment was transmitted is at least the sum of the recent RTT and the reordering window. RACK_mark_losses_on_RTO(): For each segment, Segment, not acknowledged yet: If SEG.SEQ == SND.UNA OR Segment.xmit_ts + RACK.rtt + RACK.reo_wnd - Now() <= 0: Segment.lost = TRUE".
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:410`
  - Our code behavior: `tcp_rack.rs:106-130` `rack_mark_losses_on_rto` encodes the exact RFC formula (skips already-sacked / already-lost / cum-acked entries; matches `seq == snd_una` OR `xmit_us + rtt + reo_wnd <= now_us`). Call site: `engine.rs:884-934` `on_rto_fire` Phase 3 collects eligible indexes, flips `entry.lost = true`, then retransmits each via the existing `retransmit(handle, idx)` helper. Defensive fallback to front-only retransmit if the helper returns empty (not reachable in practice since the front always matches the `seq == snd_una` clause). `tcp.tx_rto` still bumps exactly once per fire; `tcp.tx_retrans` bumps once per retransmitted segment.

- **AD-A5-5-tlp-arm-on-send** — TLP PTO armed from `Engine::send_bytes` TX path after new-data enters `snd_retrans`.
  - RFC clause: `docs/rfcs/rfc8985.txt:935-942` — "The sender SHOULD start or restart a loss probe PTO timer after transmitting new data (that was not itself a loss probe) or upon receiving an ACK that cumulatively acknowledges new data unless it is already in fast recovery, RTO recovery, or segments have been SACKed (i.e., RACK.segs_sacked is not zero)."
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:411`
  - Our code behavior: `engine.rs:2660-2667` `send_bytes` post-TX calls `self.arm_tlp_pto(handle)` when `accepted > 0`. `arm_tlp_pto` helper at `engine.rs:2679-2715` gates on `tlp_arm_gate_passes()` (snd_retrans non-empty, no TLP already armed, under per-conn probe budget, RTT-sample-gate passed unless opted-out, SRTT available). The arm-on-ACK site at `engine.rs:1794` shares the same helper — bit-identical arming semantics across both trigger paths. The `RACK.segs_sacked != 0` exclusion is still open as pre-existing AD-9 (not introduced by A5.5; `arm_tlp_pto` inherits the A5 omission unchanged).

- **AD-A5-5-tlp-pto-floor-zero** — per-connect `tlp_pto_min_floor_us` knob, `u32::MAX` sentinel = explicit no-floor, default 0 substitutes to engine `tcp_min_rto_us`.
  - RFC clause: `docs/rfcs/rfc8985.txt:932-981` §7.2 — silent on a PTO floor (the formula is `max(2·SRTT, ...) + penalty`, no minimum clamp). Linux-kernel TLP uses ~10 ms; the spec §6.4 row notes this.
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:412`
  - Our code behavior: `tcp_tlp.rs:63-74` `pto_us` clamps `with_penalty` at `cfg.floor_us`. `tcp_conn.rs:350-361` `tlp_config` maps `tlp_pto_min_floor_us == u32::MAX` to `floor_us = 0` (explicit no-floor), else passes the substituted value through. Validation at `dpdk-net/src/lib.rs:433-443` ensures `tlp_pto_min_floor_us == 0` → engine `tcp_min_rto_us` substitution (A5 behavior preserved) and otherwise `tlp_pto_min_floor_us == u32::MAX` OR `<= tcp_max_rto_us`.

- **AD-A5-5-tlp-multiplier-below-2x** — per-connect `tlp_pto_srtt_multiplier_x100` knob, integer ×100, default 200 (2.0×), valid `[100, 200]`.
  - RFC clause: `docs/rfcs/rfc8985.txt:947-953` §7.2 — "the default PTO interval is 2*SRTT. By that time, it is prudent to declare that an ACK is overdue since under normal circumstances, i.e., no losses, an ACK typically arrives in one SRTT. Choosing the PTO to be exactly an SRTT would risk causing spurious probes given that network and end-host delay variance can cause an ACK to be delayed beyond the SRTT. Hence, the PTO is conservatively chosen to be the next integral multiple of SRTT."
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:413`
  - Our code behavior: `tcp_tlp.rs:67` `base = srtt * multiplier_x100 / 100`. Default 200 matches RFC `2·SRTT` exactly. Validation at `dpdk-net/src/lib.rs:427-438` substitutes `0 → 200` (A5 preservation) and rejects `< 100` OR `> 200`. Spurious-probe counter `tcp.tx_tlp_spurious` gives the app self-correction signal.

- **AD-A5-5-tlp-skip-flight-size-gate** — per-connect `tlp_skip_flight_size_gate` bool; when true, skip the RFC 8985 §7.2 FlightSize==1 penalty.
  - RFC clause: `docs/rfcs/rfc8985.txt:959-962` §7.2 — "Third, when the FlightSize is one segment, the sender MAY inflate the PTO by TLP.max_ack_delay to accommodate a potentially delayed acknowledgment and reduce the risk of spurious retransmissions. The actual value of TLP.max_ack_delay is implementation specific."
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:414`
  - Our code behavior: `tcp_tlp.rs:68-72` — `if flight_size == 1 && !cfg.skip_flight_size_gate { base + max(WCDELACK_US, srtt/4) }`. `WCDELACK_US` constant is 200_000 µs (`tcp_tlp.rs:12`), matching the RFC default for `TLP.max_ack_delay`. When knob is set, penalty is suppressed. Defaults (knob = false) preserve RFC exactly. Note: RFC formulates the penalty as `+= TLP.max_ack_delay`; our code uses `max(WCDelAckT, SRTT/4)` — an implementation choice matching widely-deployed Linux TCP TLP. `TLP.max_ack_delay` is explicitly "implementation specific" per §7.2, so this is within RFC latitude.

- **AD-A5-5-tlp-multi-probe** — per-connect `tlp_max_consecutive_probes` (default 1, range `[1, 5]`). Budget resets on new RTT sample or newly-ACKed data.
  - RFC clause: `docs/rfcs/rfc8985.txt:984-993` §7.3 — "When the PTO timer expires, the sender MUST check whether both of the following conditions are met before sending a loss probe: 1. First, there is no other previous loss probe still in flight. This ensures that, at any given time, the sender has at most one additional packet in flight beyond the congestion window limit."
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:415`
  - Our code behavior: `tcp_conn.rs:374-391` `tlp_arm_gate_passes` checks `tlp_consecutive_probes_fired >= tlp_max_consecutive_probes`. With default `1`, the existing A5 single-probe-in-flight behavior holds. When opted up to `≥ 2`, consecutive probes may fire. `tlp_recent_probes` ring (5 slots, most-recent-wins) bounds memory. Budget reset hooks at `tcp_input.rs:596` (RTT sample) and `tcp_input.rs:614` (new-data cum-ACK) clear `tlp_consecutive_probes_fired`.

- **AD-A5-5-tlp-skip-rtt-sample-gate** — per-connect `tlp_skip_rtt_sample_gate` bool; when true, disable RFC 8985 §7.3 step 2 "RTT sample since last probe" suppression.
  - RFC clause: `docs/rfcs/rfc8985.txt:995-1003` §7.3 step 2 — "Second, the sender has obtained an RTT measurement since the last loss probe transmission... If either one of these two conditions is not met, then the sender MUST skip sending a loss probe and MUST proceed to re-arm the RTO timer".
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:416`
  - Our code behavior: `tcp_conn.rs:384-386` `tlp_arm_gate_passes` — `if !self.tlp_skip_rtt_sample_gate && !self.tlp_rtt_sample_seen_since_last_tlp { return false; }`. Default (knob = false) preserves RFC §7.3 step 2 gate via `tlp_rtt_sample_seen_since_last_tlp` latched on RTT sample at `tcp_input.rs:596`, cleared on TLP fire at `tcp_conn.rs:407`. When set, the gate is bypassed — required alongside `tlp_max_consecutive_probes > 1` for multi-probe cadence on quiescent paths.

### FYI (informational — no action)

- **I-1** — AD-15 retirement validated against code.
  A5's AD-15 was deferring the TLP pre-fire state machine (TLP.end_seq / TLP.is_retrans) to Stage 2. A5.5 supersedes the state machine with: `tlp_recent_probes[5]` ring (per-probe seq/len/tx_ts tracking for DSACK spurious attribution, `tcp_conn.rs:109-115 / 244-248`), `tlp_consecutive_probes_fired` budget replacing single-in-flight invariant (`tcp_conn.rs:238-240`), and `tlp_rtt_sample_seen_since_last_tlp` flag covering the §7.3 step 2 gate (`tcp_conn.rs:241-243`). The A5 AD-15 rationale "occasional redundant probe on overlapping ACK; no correctness issue" is now replaced by explicit budget + attribution — strictly more RFC-aligned. Retirement note at `docs/superpowers/reviews/phase-a5-rfc-compliance.md:150`.

- **I-2** — AD-17 retirement validated against code.
  A5's AD-17 deferred `RACK_mark_losses_on_RTO` to Stage 2. A5.5 implements the §6.3 helper in `tcp_rack.rs:106-130` and invokes it from `engine.rs:884-934` `on_rto_fire` Phase 3. Single RTO fire now restores the full §6.3-eligible tail in one burst. Retirement note at `docs/superpowers/reviews/phase-a5-rfc-compliance.md:163`.

- **I-3** — AD-18 retirement validated against code.
  A5's AD-18 deferred TLP arm-on-send to Stage 2. A5.5 wires `Engine::arm_tlp_pto` from `send_bytes` (`engine.rs:2660-2667`). Combined with AD-A5-5-srtt-from-syn, the arm site always has a valid PTO basis post-ESTABLISHED. Retirement note at `docs/superpowers/reviews/phase-a5-rfc-compliance.md:170`.

- **I-4** — Pre-existing A5 accepted deviations (AD-9 through AD-14, AD-16) unchanged by A5.5.
  - AD-9 (RFC 8985 §7.2 arm during RACK/SACK recovery gate omitted): `tlp_arm_gate_passes` still does not check `RACK.segs_sacked == 0`. Pre-existing. A5.5's `arm_tlp_pto` inherits this gap; if the gap is re-flagged in Stage 2, both the arm-on-ACK and arm-on-send sites will be fixed in one helper change.
  - AD-10 (RFC 8985 §7.3 MUST re-arm RTO after TLP fire): `on_tlp_fire` at `engine.rs:1066-1159` does not touch `rto_timer_id`. The existing RTO deadline is unaffected; behavior is observationally RFC-compatible as long as RTO was armed before the TLP fired (which it is — §5.1 arm-on-send places the RTO first). Pre-existing A5 scope.
  - AD-11 (NewData probe degrades to LastSegmentRetransmit): `on_tlp_fire` picks the last entry in both branches. Pre-existing A5 scope; not touched.
  - AD-12 (independent RTO + TLP timers, §8 SHOULD): multi-timer state persists. Pre-existing A5 scope.
  - AD-13 (DSACK visibility only): A5.5 extends with spurious-probe attribution (`tcp.tx_tlp_spurious`) but still does not drive reo_wnd adaptation. Still within the A5 "visibility only" AD.
  - AD-14 (data retransmit budget = 15): untouched.
  - AD-16 (RACK §6.2 Step 2 spurious-retrans guard): untouched, remains Stage 2.

- **I-5** — Karn's rule correctness under SYN retransmit race.
  `emit_syn` at `engine.rs:694-700` stamps `syn_tx_ts_ns` ONLY when `syn_retrans_count == 0`. `on_syn_retrans_fire` at `engine.rs:1211` bumps `syn_retrans_count` BEFORE calling `emit_syn`, so the guard is tight: retransmitted SYNs never re-stamp the timestamp, and `handle_syn_sent`'s `syn_retrans_count != 0` short-circuit at `tcp_conn.rs:438-440` also rejects the sample. Even under out-of-order SYN-ACK delivery (initial SYN retransmit fires, then the initial SYN-ACK arrives), Karn's rule is honored conservatively — the sample is dropped.

- **I-6** — `ConnStats` projection uses RFC-aligned units.
  `tcp_conn.rs:504-517` `stats()` projects SRTT / RTTVAR / min_rtt / RTO in µs (matching RFC 6298 §2.2 internal units), `snd_una/snd_nxt/snd_wnd` as raw wire sequence values, and `send_buf_bytes_{pending,free}` as bytes. No engine-internal ticker leakage.

- **I-7** — PTO formula matches widely-deployed Linux TCP TLP implementation.
  `tcp_tlp.rs:63-74` `pto_us` computes `base = srtt · multiplier / 100`, optional `+max(WCDelAckT, SRTT/4)` penalty at FlightSize==1, clamped at `cfg.floor_us`. The RFC text at `rfc8985.txt:971-981` specifies `PTO = 2·SRTT` + `TLP.max_ack_delay` at FlightSize==1, where `TLP.max_ack_delay` is "implementation specific". Our `max(WCDelAckT, SRTT/4)` choice (with `WCDelAckT = 200 ms`) is the Linux-tcp convention. The `SRTT/4` term exceeds `WCDelAckT` only when SRTT > 800 ms — outside normal operating regimes for trading clients; for trading SRTTs (sub-ms through ~100 ms) the penalty is effectively `WCDelAckT`, matching the RFC default.

- **I-8** — RFC 6298 §3.3 citation in spec / plan is mislabeled.
  Spec §6.3 line 387 and A5.5 plan header reference "RFC 6298 §3.3 MAY" as the authority for SYN-RTT seed. RFC 6298 has no §3.3 — §3 is "Taking RTT Samples" (Karn's rule) and does not formally contain a "SYN MAY be used" clause. The behavior is RFC-compliant via §2.2 "first RTT measurement R" + §3 "RTT samples MUST NOT be made using segments that were retransmitted" — our implementation satisfies both. Suggest tightening citations in a future spec edit to `rfc6298.txt:133` (§2.2) + `rfc6298.txt:184-191` (§3 Karn's). No code change required.

- **I-9** — Plan's RFC 8985 §7.4 gate citation is §7.3 step 2.
  Phase plan header lists "RFC 8985 §7.4 — per-connect RTT-sample-gate skip". The "RTT sample since last loss probe" gate is actually RFC 8985 §7.3 step 2 (`rfc8985.txt:995-1003`). §7.4 ("Detecting Losses Using the ACK of the Loss Probe", `rfc8985.txt:1067+`) is a different topic (DSACK/congestion-response post-probe). Our `AD-A5-5-tlp-skip-rtt-sample-gate` is correctly implemented against the §7.3 step 2 MUST. No code change required.

- **I-10** — `obs.events_queue_high_water` `fetch_max` runs on every event push (not only on overflow).
  `tcp_events.rs:126-131` `EventQueue::push` unconditionally calls `counters.obs.events_queue_high_water.fetch_max(depth, Relaxed)` on every push. This is not strictly "slow-path only" — every `Readable` event (post-poll in `handle_established`) bumps it. Not an RFC violation; flagged per `feedback_counter_policy.md` "hot-path counters require compile-time feature gate + documented justification". The single relaxed `fetch_max` is cheap but not batched; consider gating behind `obs-queue-depth` feature or batching at drain time if profiling shows overhead. Code-quality concern, not RFC gate concern.

- **I-11** — `attribute_dsack_to_recent_tlp_probe` 4·SRTT plausibility window correct.
  `tcp_conn.rs:462-496` — `window_ns = effective_srtt_us * 1000 * 4`. That's `4 * SRTT` expressed in ns correctly. Defensive 1 s window when SRTT is unavailable. Seq comparisons use `seq_le` for wrap-safe checks. Sound.

- **I-12** — `rack_mark_losses_on_rto` formula encoding matches RFC 8985 §6.3 exactly.
  `tcp_rack.rs:113-130`: skip `sacked || lost || cum_acked` (RFC implicit — "not acknowledged yet" + idempotence); mark if `seq == snd_una` (RFC "SEG.SEQ == SND.UNA") OR `xmit_us + rtt + reo_wnd <= now_us` (RFC "Segment.xmit_ts + RACK.rtt + RACK.reo_wnd - Now() <= 0"). Saturating arithmetic handles u32-µs wrap across ~71 min monotonic-clock boundary. `rtt_us` sourced as `rtt_est.srtt_us().unwrap_or(rack.min_rtt_us)` at call site (`engine.rs:899`) — equivalent to RFC `RACK.rtt` which our RACK state does not maintain as a separate field.

## Verdict (draft)

**PASS-WITH-DEVIATIONS**

Gate status:
- RFCs covered: 2 (RFC 6298, RFC 8985)
- New §6.4 rows validated: 8 (AD-A5-5-srtt-from-syn, AD-A5-5-rack-mark-losses-on-rto, AD-A5-5-tlp-arm-on-send, AD-A5-5-tlp-pto-floor-zero, AD-A5-5-tlp-multiplier-below-2x, AD-A5-5-tlp-skip-flight-size-gate, AD-A5-5-tlp-multi-probe, AD-A5-5-tlp-skip-rtt-sample-gate)
- Retirements recorded: 3 (AD-15, AD-17, AD-18 — each with cross-ref to superseding §6.4 row and closing A5.5 task)
- Must-fix open: 0
- Missing-SHOULD open: 0
- Missed-edge-cases open: 0

All A5.5 in-scope RFC clauses are either satisfied or covered by an §6.4 accepted-deviation row with RFC citation + rationale + default-preserves-RFC commitment + monitoring counter. Gate not blocked; `phase-a5-5-complete` tag may proceed pending (a) mTCP review gate and (b) the human's validation of the 8 new §6.4 entries.
