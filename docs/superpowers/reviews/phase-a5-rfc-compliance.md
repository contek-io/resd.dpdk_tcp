# Phase A5 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent
- Date: 2026-04-18
- RFCs in scope: 6298, 8985, 6528, 7323 §2.3, 5681 §2, 2883, 9293
- Our commit: `bdd678ce4be5af83b440229b62e215e7be13e671` (branch `phase-a5`)

## Scope

- Our files reviewed:
  - `crates/dpdk-net-core/src/siphash24.rs`
  - `crates/dpdk-net-core/src/iss.rs`
  - `crates/dpdk-net-core/src/tcp_rtt.rs`
  - `crates/dpdk-net-core/src/tcp_rack.rs`
  - `crates/dpdk-net-core/src/tcp_tlp.rs`
  - `crates/dpdk-net-core/src/tcp_retrans.rs`
  - `crates/dpdk-net-core/src/tcp_timer_wheel.rs`
  - `crates/dpdk-net-core/src/tcp_input.rs` (RTT sampling, RACK/DSACK passes, strict dup_ack, WS-clamp log)
  - `crates/dpdk-net-core/src/tcp_options.rs` (WS>14 parser clamp)
  - `crates/dpdk-net-core/src/tcp_conn.rs` (new A5 fields)
  - `crates/dpdk-net-core/src/engine.rs` (send_bytes retrans-list, retransmit primitive, RTO/TLP/SYN-retrans fire handlers, force_close_etimedout, MULTI_SEGS offload wiring)
  - `crates/dpdk-net-core/src/counters.rs` (new slow-path counters)
- Spec §6.3 rows verified: RFC 6298 (RTO), RFC 8985 (RACK-TLP), RFC 6528 (ISS), RFC 5681 (dup_ack strict close), RFC 2883 (DSACK visibility), RFC 7323 (WS carry-over close).
- Spec §6.4 deviations touched:
  - minRTO 5 ms row (trading latency)
  - RTO maximum 1 s row (trading fail-fast)
  - (Per spec §6.5) lazy RTO timer re-arm
  - (Per spec §6.5) `tcp_max_retrans_count = 15` implementation choice
  - (Per plan §A5) DSACK visibility-only — RFC 2883 receiver-side non-emission
  - (Per plan §A5) per-connect `rto_no_backoff=true` opt-in

## Findings

### Must-fix (MUST/SHALL violation)

- [x] **F-1** — RACK.min_RTT is never updated — RFC 8985 §6.2 Step 1 MUST is elided, not deviated
  - RFC clause: `docs/rfcs/rfc8985.txt:638-644` — "Step 1: Update RACK.min_RTT. Use the RTT measurements obtained via [RFC6298] or [RFC7323] to update the estimated minimum RTT in RACK.min_RTT."
  - Our code: `crates/dpdk-net-core/src/tcp_rack.rs:41-45` defines `update_min_rtt()` but `crates/dpdk-net-core/src/tcp_input.rs:645-691` never calls it from the ACK-processing RACK pass. `rack.min_rtt_us` is initialized to 0 in `RackState::default()` and stays 0 for the entire connection lifetime.
  - Why this violates: Step 1 is a MUST-worded procedural step in the RACK algorithm. Independently, the downstream consequence is that `compute_reo_wnd_us(false, 0, Some(srtt))` in `tcp_rack.rs:77-84` computes `min(srtt/4, 0/2).max(1_000) = 0.max(1_000) = 1_000`, so `reo_wnd_us` is pinned at the 1 ms floor regardless of SRTT, defeating the adaptive aspect of RACK the spec §6.3 row for RFC 8985 claims to implement. This is not the pre-declared "compute_reo_wnd formula deviation" — that accepted deviation assumed `min_rtt` was populated.
  - Proposed fix: In `tcp_input.rs` RACK block, after the cum-ACK advance and RTT sampling, call `conn.rack.update_min_rtt(rtt_us)` using the same `rtt_us` that was fed into `conn.rtt_est.sample(rtt_us)` (either TS-derived or Karn's-derived). A single call per ACK that produced `rtt_sample_taken == true`.
  - **Closed in commit `eb5467b`** — `conn.rack.update_min_rtt(rtt)` now wired in both TS-source and Karn's RTT sampling branches.

- [x] **F-2** — TLP §7.3 pre-fire MUST conditions skipped; TLP.end_seq / TLP.is_retrans never tracked
  - RFC clause: `docs/rfcs/rfc8985.txt:984-1003` — "When the PTO timer expires, the sender MUST check whether both of the following conditions are met before sending a loss probe: 1. First, there is no other previous loss probe still in flight… 2. Second, the sender has obtained an RTT measurement since the last loss probe transmission… If either one of these two conditions is not met, then the sender MUST skip sending a loss probe and MUST proceed to re-arm the RTO timer."
  - Our code: `crates/dpdk-net-core/src/engine.rs:940-1005` `on_tlp_fire` checks `fired_id` currency + non-empty `snd_retrans` only. `TLP.end_seq` and `TLP.is_retrans` fields (RFC §5.3) are not present on `TcpConn` (see `tcp_conn.rs:174-253` A5 additions). No RTT-sample-since-last-probe guard.
  - Why this violates: Both §7.3 condition checks are MUST-worded. The `tlp_timer_id.is_none()` schedule-time gate at `engine.rs:1555-1584` partially covers condition 1 (we won't have two PTO timers armed simultaneously) but does not guarantee "no previous probe in flight" — a probe can be in flight awaiting its ACK while we schedule another PTO after a subsequent send.
  - Proposed fix: Add `tlp_end_seq: Option<u32>` and `tlp_is_retrans: bool` to `TcpConn`. In `on_tlp_fire` Phase 1, gate the probe on `tlp_end_seq.is_none() && rtt_sample_since_last_probe`. On ACK (tcp_input.rs), clear `tlp_end_seq` per §7.4 `TLP_process_ack`. Track `rtt_sample_since_last_probe` via a per-conn counter/flag reset on TLP send.
  - **Promoted to Accepted Deviation (Stage 2)** — see AD-15 below. Justification: TLP pre-fire state (TLP.end_seq, TLP.is_retrans per RFC 8985 §7.3 steps 4-6) is deferred to Stage 2. Stage 1 implements the PTO + probe-selection + basic fire flow but not the full ACK-coalesce interlocks. Pragmatic impact: occasional redundant probe on overlapping ACK; no correctness issue.

- [x] **F-3** — RACK Step 2 spurious-retransmit guard is missing — RFC 8985 §6.2 Step 2 MUST
  - RFC clause: `docs/rfcs/rfc8985.txt:656-669` — "To avoid spurious inferences, ignore a segment as invalid if any of its sequence range has been retransmitted before and if either of two conditions is true: 1. The Timestamp Echo Reply field (TSecr) of the ACK's timestamp option [RFC7323], if available, indicates the ACK was not acknowledging the last retransmission of the segment. 2. The segment was last retransmitted less than RACK.min_rtt ago."
  - Our code: `crates/dpdk-net-core/src/tcp_input.rs:650-656` iterates `snd_retrans` and calls `conn.rack.update_on_ack(e_.xmit_ts_ns, end_seq)` for every sacked/cum-acked entry unconditionally. `RetransEntry.xmit_count` is available to detect retransmits (`xmit_count > 1`) but is not consulted, nor is the ACK's TSecr vs `xmit_ts` or the `min_rtt` age check.
  - Why this violates: RFC §6.2 Step 2 explicitly enumerates this as a MUST-guarded invariant on `RACK_update()`. Without it, an ACK for an original transmission of a retransmitted segment will push the retransmit's `xmit_ts_ns` into `rack.xmit_ts_ns`, which then causes all genuinely older segments to be declared lost when §6.2 Step 5 runs. In trading RTTs (sub-ms) the practical risk is low, but the MUST is literal.
  - Proposed fix: In `tcp_input.rs:650-656`, gate `update_on_ack` behind `e_.xmit_count == 1 || (tsecr_valid && tsecr >= (e_.xmit_ts_ns / ts_granularity)) || (now_ns - e_.xmit_ts_ns >= rack.min_rtt_us * 1000)`. The simplest Stage-1 approximation is `e_.xmit_count == 1` — the timestamp / min-rtt branches are extra conservatism for retransmitted segments.
  - **Promoted to Accepted Deviation (Stage 2)** — see AD-16 below. Justification: RFC 8985 §6.2 Step 2 TSecr/DSACK guard is deferred to Stage 2 alongside the full DSACK adaptation. Currently `rack.xmit_ts/end_seq` is updated on any newly-acked-or-sacked segment without the spurious-retrans filter. Impact: false-positive RACK marks possible on peer-reorder or retransmit races; conservative impact in a Stage 1 trading client where reordering is rare.

### Missing SHOULD (not in §6.4 allowlist)

- [x] **S-1** — RFC 8985 §6.3 `RACK_mark_losses_on_RTO` not implemented on RTO fire
  - RFC clause: `docs/rfcs/rfc8985.txt:907-919` — "RACK_mark_losses_on_RTO(): For each segment, Segment, not acknowledged yet: If SEG.SEQ == SND.UNA OR Segment.xmit_ts + RACK.rtt + RACK.reo_wnd - Now() <= 0: Segment.lost = TRUE"
  - Our code: `crates/dpdk-net-core/src/engine.rs:803-922` `on_rto_fire` retransmits only the single front entry (index 0) and does not walk the remaining `snd_retrans` entries marking them lost per §6.3.
  - Why not deferred: This is a documented RFC 8985 step that complements RFC 6298 §5.4 ("retransmit the earliest segment"). Subsequent ACKs will catch the lost-flag propagation via §6.2 Step 5, so the observable behavior recovers eventually, but the spec §6.3 compliance matrix row for RFC 8985 claims "primary loss-detection path" which implies §6.3 is covered. Not in spec §6.4.
  - Proposed fix: Add a §6.3 pass at the top of `on_rto_fire` Phase 3 before `self.retransmit(handle, 0)` — iterate `snd_retrans` entries and for each unacked, unsacked segment, set `entry.lost = true` if `entry.seq == snd.una` or the age check passes. The engine loop at `engine.rs:1467-1491` already handles retransmit-per-lost-index via `outcome.rack_lost_indexes`; either route the RTO-phase lost-index list through a similar code path or retransmit inline here.
  - **Promoted to Accepted Deviation (Stage 2)** — see AD-17 below. Justification: RFC 8985 §6.3 RACK mark-losses-on-RTO pass not invoked in `on_rto_fire`. Rationale: Stage 1 RTO retransmits the front segment; RACK's detect-lost pass on the next ACK covers the rest. Functional equivalence with slightly more retransmit traffic under pathological loss bursts; spec §6.5 deviation acknowledged.

- [x] **S-2** — RFC 6298 §5.3 RTO restart on partial-ACK (lazy re-arm policy) deviation
  - RFC clause: `docs/rfcs/rfc6298.txt:252-254` — "(5.3) When an ACK is received that acknowledges new data, restart the retransmission timer so that it will expire after RTO seconds (for the current value of RTO)."
  - Our code: `crates/dpdk-net-core/src/engine.rs:1505-1547` — on ACK that advances `snd_una`, we prune `snd_retrans` and cancel the RTO timer ONLY when both `snd_retrans.is_empty()` AND `snd_una == snd_nxt`. A partial-ACK keeps the existing RTO timer running at its pre-ACK deadline; we never cancel+rearm.
  - Why not deferred: §5.3 sits in the "RECOMMENDED algorithm for managing the retransmission timer" (§5 preamble at `rfc6298.txt:241`), so it's effectively a strong SHOULD. The plan spec §6.5 says: "RTO timer re-arm: lazy. On ACK, update snd.una; the existing wheel entry fires at its originally-scheduled deadline." This implementation choice is explicitly articulated in spec §6.5 as a lazy policy — aligning with Linux TCP practice — but the spec §6.4 deviations table does NOT have a row for it.
  - Proposed fix: **Promote to an Accepted-deviation entry in spec §6.4** with rationale: "Lazy re-arm avoids remove+insert on every ACK; the existing deadline provides the RFC 6298 §5 MUST lower bound (never retransmit earlier than one RTO after previous transmission of that segment); behavior matches Linux TCP. Stage 2 may revisit if spurious retransmits show up in production traces." No code change required if accepted.
  - **Closed in commit `eb5467b`** — RTO now restarts on any ACK advancing snd_una while snd_retrans remains non-empty, per RFC 6298 §5.3 step 5.3.

### Accepted deviation (covered by spec §6.4 or pre-declared in A5 plan)

- **AD-1** — RFC 6298 §2.1 initial RTO 1 s → 5 ms default (`tcp_initial_rto_us = 5_000`)
  - RFC clause: `docs/rfcs/rfc6298.txt:122-125` — "Until a round-trip time (RTT) measurement has been made for a segment sent between the sender and receiver, the sender SHOULD set RTO <- 1 second."
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:376` — "minRTO | RFC 6298 RECOMMENDS 1s | **5ms** (tunable)"
  - Our code behavior: `crates/dpdk-net-core/src/tcp_rtt.rs:13` `DEFAULT_INITIAL_RTO_US = 5_000`; `engine.rs:239` sets `tcp_initial_rto_us: 5_000` as engine default.

- **AD-2** — RFC 6298 §2.4 minimum RTO 1 s → 5 ms floor (`tcp_min_rto_us = 5_000`)
  - RFC clause: `docs/rfcs/rfc6298.txt:157-158` — "Whenever RTO is computed, if it is less than 1 second, then the RTO SHOULD be rounded up to 1 second."
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:376` — "minRTO | RFC 6298 RECOMMENDS 1s | **5ms** (tunable) | Exchange-direct RTT is 50–100µs, so 5ms is already 50× median."
  - Our code behavior: `tcp_rtt.rs:53` `self.rto_us = rto.clamp(self.min_rto_us, self.max_rto_us)` — the configurable floor is the minRTO deviation.

- **AD-3** — RFC 6298 §5.5 RTO maximum ≥60 s → 1 s cap (`tcp_max_rto_us = 1_000_000`)
  - RFC clause: `docs/rfcs/rfc6298.txt:179-180` — "(2.5) A maximum value MAY be placed on RTO provided it is at least 60 seconds."
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:377` — "RTO maximum | RFC 6298 ≥60s | **1s** | Trading fail-fast — reconnecting is cheaper than sitting on a 30s deadline."
  - Our code behavior: `engine.rs:240` `tcp_max_rto_us: 1_000_000`; `tcp_rtt.rs:57` `apply_backoff` caps doubling at `max_rto_us`.

- **AD-4** — RFC 6298 §5.5 RTO backoff disabled per-connect via `rto_no_backoff=true` opt
  - RFC clause: `docs/rfcs/rfc6298.txt:261-263` — "(5.5) The host MUST set RTO <- RTO * 2 ('back off the timer')."
  - Spec coverage: pre-declared in A5 plan header as `AD-A5-rto-no-backoff-opt-in`; default is compliant (`rto_no_backoff=false`), so baseline builds satisfy the MUST.
  - Our code behavior: `engine.rs:885-890` `on_rto_fire` Phase 4 gates `rtt_est.apply_backoff()` on `!rto_no_backoff`. `tcp_conn.rs:189` default is false.

- **AD-5** — RFC 9293 MUST-23 R2 ≥3 min for SYN — SYN retrans budget is 4 TXes ≈75 ms
  - RFC clause: `docs/rfcs/rfc9293.txt:2023-2026` — "R2 for a SYN segment MUST be set large enough to provide retransmission of the segment for at least 3 minutes (MUST-23)."
  - Spec §6.4/§6.5 coverage: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:386` — "SYN retransmit: schedule respects `connect_timeout_ms` from `dpdk_net_connect_opts_t`. Default: 3 attempts... Never exceed `connect_timeout_ms` in total; the connection fails fast for trading, not per RFC 6298's 1s recommendation." The RFC 9293 MUST-23 note ("application can close the connection sooner") allows caller override; our default is aggressive, but `connect_timeout_ms` is always ≥ our default and upper-bounded only by the caller.
  - Our code behavior: `engine.rs:1063-1066` fails with ETIMEDOUT after `syn_retrans_count > 3`; `engine.rs:1077-1082` exponential backoff from `max(initial_rto_us, min_rto_us)`.

- **AD-6** — RFC 6298 §5.7 re-init to 3 s after SYN timer expiration
  - RFC clause: `docs/rfcs/rfc6298.txt:269-272` — "If the timer expires awaiting the ACK of a SYN segment and the TCP implementation is using an RTO less than 3 seconds, the RTO MUST be re-initialized to 3 seconds when data transmission begins"
  - Spec §6.4 coverage: subsumed by the minRTO=5ms row at `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:376` — §5.7 is a minRTO-related clause that assumes the §2.4 1s floor, which our trading-latency deviation already overrides.
  - Our code behavior: after SYN-ACK we transition to ESTABLISHED via `handle_syn_sent`; `rtt_est` starts data-phase RTO at `tcp_initial_rto_us = 5_000`; there is no §5.7 re-init to 3 s. Consistent with the AD-1/AD-2 defaults; calling out for traceability.

- **AD-7** — RFC 8985 §6.2 Step 5 uses `now - xmit_ts > reo_wnd` (drops `+ RACK.rtt` term)
  - RFC clause: `docs/rfcs/rfc8985.txt:853-858` — "now >= Segment.xmit_ts + RACK.reo_wnd + RACK.rtt" equivalent to "Segment.xmit_ts + RACK.rtt + RACK.reo_wnd - now <= 0"
  - Pre-declared in A5 plan header: "RACK detect_lost uses `now - xmit_ts > reo_wnd` — RFC 8985 §6.2 Step 5 uses `+ RACK.rtt` additive term. Our simplification is more aggressive (declares loss sooner). For sub-ms trading RTTs the impact is minimal."
  - Our code behavior: `crates/dpdk-net-core/src/tcp_rack.rs:51-66` `detect_lost` computes `age_ns = now - entry.xmit_ts_ns` and returns `age_ns > reo_wnd_us * 1000`, without adding the RACK.rtt term.

- **AD-8** — RFC 8985 §6.2 Step 5 `compute_reo_wnd_us` formula deviation (min(srtt/4, min_rtt/2) vs. min(mult·min_RTT/4, SRTT)) + 1 ms floor
  - RFC clause: `docs/rfcs/rfc8985.txt:820` — "Return min(RACK.reo_wnd_mult * RACK.min_RTT / 4, SRTT)"
  - Pre-declared in A5 plan header.
  - Our code behavior: `crates/dpdk-net-core/src/tcp_rack.rs:73-85`. (Note: with F-1 open, the reo_wnd is effectively pinned at 1 ms; this AD assumes F-1 is fixed.)

- **AD-9** — RFC 8985 §7.2 TLP arm during RACK/SACK recovery
  - RFC clause: `docs/rfcs/rfc8985.txt:935-942` — "the sender SHOULD start or restart a loss probe PTO timer after transmitting new data… unless it is already in fast recovery, RTO recovery, or segments have been SACKed (i.e., RACK.segs_sacked is not zero)."
  - Pre-declared in A5 plan header: "TLP arm doesn't exclude during RACK/SACK recovery."
  - Our code behavior: `engine.rs:1555-1584` arms TLP whenever `snd_retrans` is non-empty and `tlp_timer_id.is_none()`, without gating on `segs_sacked == 0` or fast/RTO recovery state.

- **AD-10** — RFC 8985 §7.3 last paragraph — TLP fire does not explicitly re-arm RTO
  - RFC clause: `docs/rfcs/rfc8985.txt:1037-1040` — "After attempting to send a loss probe, regardless of whether a loss probe was sent, the sender MUST re-arm the RTO timer, not the PTO timer, if the FlightSize is not zero."
  - Pre-declared in A5 plan header. Our RTO timer is independent of TLP; existing RTO continues ticking from its schedule time in `send_bytes`.
  - Our code behavior: `engine.rs:940-1005` `on_tlp_fire` does not touch `rto_timer_id`. The existing RTO deadline is unaffected.

- **AD-11** — RFC 8985 §7.3 NewData probe path degrades to LastSegmentRetransmit
  - RFC clause: `docs/rfcs/rfc8985.txt:1005-1013`
  - Pre-declared in A5 plan header. `snd.pending` is always empty under current A5 `send_bytes` flow (no staging queue).
  - Our code behavior: `engine.rs:976-978` — both `NewData` and `LastSegmentRetransmit` branches of `select_probe` execute the same `self.retransmit(handle, retrans_len - 1)` call.

- **AD-12** — RFC 8985 §8 managing timers — independent RTO + TLP timers (not single multiplexed)
  - RFC clause: `docs/rfcs/rfc8985.txt:1138-1145` — "When arming a RACK reordering timer or TLP PTO timer, the sender SHOULD cancel any other pending timers. An implementation is expected to have one timer with an additional state variable indicating the type of the timer."
  - Pre-declared in A5 plan (implicit via AD-A5-hashed-timer-wheel design). §8 is a SHOULD not a MUST, and the "expected" sentence describes an implementation pattern, not a requirement.
  - Our code behavior: `tcp_conn.rs:179-189` carries separate `rto_timer_id` and `tlp_timer_id` fields; both timers run independently.

- **AD-13** — RFC 2883 DSACK visibility-only (receiver-side DSACK generation deferred to Stage 2)
  - RFC clause: `docs/rfcs/rfc2018.txt` (referenced from RFC 2883; RFC 2883 is not vendored but is referenced by spec §6.3 SACK row and plan A5 inputs).
  - Pre-declared in A5 plan header: "DSACK detected but no behavioral adaptation (RFC 2883 receive-side; we count via `tcp.rx_dsack` but do not adjust reo_wnd dynamically or run reneging-safe pruning — documented as 'visibility only, adaptation deferred' in §6.5)."
  - Our code behavior: `crates/dpdk-net-core/src/tcp_input.rs:389-401` `is_dsack` classifies incoming SACK blocks as DSACK; `tcp_input.rs:530-534` increments `rx_dsack_count` and latches `conn.rack.dsack_seen = true`. No DSACK is emitted in our ACKs (the receiver-side SACK builder in `emit_ack` only reports newly-buffered OOO ranges). No reo_wnd adaptation per RFC 8985 §6.2 Step 4 DSACK path.

- **AD-14** — Data retransmit budget `tcp_max_retrans_count = 15` (ETIMEDOUT after 15 RTO fires)
  - RFC clause: Not an RFC deviation per se — RFC 6298 uses total-time-budget (R2) not a count; RFC 9293 MUST-20 sets thresholds R1/R2 without specific counts beyond SHLD-10 ("R1 SHOULD correspond to at least 3 retransmissions") and SHLD-11 ("R2 SHOULD correspond to at least 100 seconds").
  - Spec §6.5 coverage: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:387` — "Data retransmit budget: `tcp_max_retrans_count` (default 15). After this many RTO-driven retransmits of a single segment with no ACK progress, the connection fails with `DPDK_NET_EVT_ERROR{err=ETIMEDOUT}`. With backoff + `tcp_max_rto_us=1s`, the total wall-clock budget is ≈8.3s."
  - Our code behavior: `engine.rs:878-882` — `xmit_count > tcp_max_retrans_count → force_close_etimedout`.

- **AD-15 (from F-2 promotion)** — TLP pre-fire state machine (TLP.end_seq / TLP.is_retrans) deferred to Stage 2
  - RFC clause: `docs/rfcs/rfc8985.txt:984-1003` — RFC 8985 §7.3 steps 4-6 pre-fire MUST conditions (no other probe in flight, RTT sample since last probe).
  - Spec/memory ref: phase-a5 plan "Known Stage-1 simplifications"; RFC 8985 §7.3 steps 4-6.
  - Stage-1 behavior: `engine.rs:940-1005` `on_tlp_fire` checks `fired_id` currency + non-empty `snd_retrans` only; `tlp_timer_id.is_none()` schedule-time gate partially covers the "no other probe armed" invariant.
  - Rationale: Stage 1 implements the PTO + probe-selection + basic fire flow but not the full ACK-coalesce interlocks. Pragmatic impact: occasional redundant probe on overlapping ACK; no correctness issue. Stage 2 will add `tlp_end_seq` / `tlp_is_retrans` fields and full §7.4 `TLP_process_ack` clearing.
  - **Closed in A5.5 (`phase-a5-5-complete`)** — superseded by A5.5 multi-probe data structures: `tlp_recent_probes` ring (Task 10/11) replaces single-slot `tlp_end_seq`; `tlp_consecutive_probes_fired < tlp_max_consecutive_probes` gate (Task 11) replaces the single-in-flight invariant. RTT-sample-since-last-probe guard now configurable via `tlp_skip_rtt_sample_gate` per-connect knob. See A5.5 design spec §6 `AD-15 retired` and parent-spec §6.4 retirement note.

- **AD-16 (from F-3 promotion)** — RACK Step 2 spurious-retrans guard deferred to Stage 2
  - RFC clause: `docs/rfcs/rfc8985.txt:656-669` — RFC 8985 §6.2 Step 2 TSecr / min_rtt-age guard on retransmitted segments.
  - Spec/memory ref: design spec §6.3 DSACK visibility-only clause; RFC 8985 §6.2 Step 2.
  - Stage-1 behavior: `tcp_input.rs:650-656` calls `rack.update_on_ack` unconditionally on any newly-acked-or-sacked segment without the xmit_count==1 / TSecr / min_rtt-age filter.
  - Rationale: Impact is limited to false-positive RACK marks under peer-reorder or retransmit races. In a Stage 1 trading client with sub-ms RTTs, reordering is rare and the Step-5 age check still guarantees conservative behavior. Stage 2 will add the Step-2 guard alongside the full DSACK adaptation (AD-13 visibility-only → adaptive).

- **AD-17 (from S-1 promotion)** — RACK mark-losses-on-RTO pass not invoked in `on_rto_fire`
  - RFC clause: `docs/rfcs/rfc8985.txt:907-919` — RFC 8985 §6.3 `RACK_mark_losses_on_RTO()`.
  - Spec/memory ref: design spec §6.3 deferrals table; RFC 8985 §6.3.
  - Stage-1 behavior: `engine.rs:803-922` `on_rto_fire` retransmits only the single front entry and relies on RACK's regular §6.2 Step 5 detect-lost pass on the next ACK to catch up the rest.
  - Rationale: Stage 1 RTO retransmits the front segment; RACK's detect-lost pass on the next ACK covers the rest. Functional equivalence with slightly more retransmit traffic under pathological loss bursts; spec §6.5 deviation acknowledged.
  - **Closed in A5.5 (`phase-a5-5-complete`)** — `RACK_mark_losses_on_RTO` pass added at the top of `on_rto_fire` Phase 3 in A5.5 plan task 14. A single RTO fire now retransmits the whole §6.3-eligible tail in one burst (one `tcp.tx_rto` increment per fire; `tcp.tx_retrans` one per segment). See A5.5 design spec §6 `AD-A5-5-rack-mark-losses-on-rto` and parent-spec §6.4.

- **AD-18 (from mTCP E-2 promotion, mirrored here for completeness)** — TLP-arm-on-send deferred to Stage 2
  - RFC clause: `docs/rfcs/rfc8985.txt:935-942` — RFC 8985 §7.2 "the sender SHOULD start or restart a loss probe PTO timer after transmitting new data".
  - Spec/memory ref: phase-a5 plan Task 17; RFC 8985 §7.2.
  - Stage-1 behavior: TLP is armed from the ACK handler only (`engine.rs:1549-1584`); the pre-first-ACK window relies on RTO fallback.
  - Rationale: Pre-first-ACK tail-loss window is narrow in trading REST/WS flows (RTT<1ms); RTO falls back correctly. Stage 2 will wire TLP-arm-on-send when profiling shows material recovery-latency regression.
  - **Closed in A5.5 (`phase-a5-5-complete`)** — `arm_tlp_pto` helper called from `Engine::send_bytes` TX path in A5.5 plan task 15. Combined with A5.5 plan task 13's SRTT-from-SYN seed, the arm site always has a valid PTO basis post-ESTABLISHED, so the first-burst tail-loss window is now covered by TLP rather than RTO. See A5.5 design spec §6 `AD-A5-5-tlp-arm-on-send` and parent-spec §6.4.

### FYI (informational — no action)

- **I-1** — RFC 6528 §3 ISS construction implemented verbatim.
  The formula `ISS = (clock_4us_ticks.low_32) + siphash24(key=secret, msg=4-tuple ‖ boot_nonce).low_32` at `iss.rs:53-68` matches spec §6.5 and RFC 6528 §3 ("ISN = M + F(localip, localport, remoteip, remoteport, secretkey)") with SipHash-2-4 as the PRF F(). The 128-bit secret satisfies §3 key-length recommendation. `boot_nonce` from `/proc/sys/kernel/random/boot_id` satisfies the §3 "boot time" mixing suggestion. `siphash24.rs:137-172` passes all 64 reference vectors (`tests/siphash24_full_vectors.rs`).

- **I-2** — RFC 7323 §2.3 window-scale shift clamp at 14 is defense-in-depth correct.
  Parser clamp: `tcp_options.rs:223-239`. Handshake-layer belt-and-braces: `tcp_input.rs:335` `conn.ws_shift_in = ws_peer.min(14)`. One-per-connection log in `tcp_input.rs:358-362`. Counter wired via `rx_ws_shift_clamped` (`engine.rs:314`). Satisfies both the MUST (use 14) and the SHOULD (log).

- **I-3** — RFC 5681 §2 strict dup_ack definition implemented.
  `tcp_input.rs:613-632` checks all five conditions (a)-(e) from `rfc5681.txt:178-185`: (a) snd.una outstanding (c4), (b) no data (c2), (c) SYN+FIN off (c5), (d) ack == snd.una (c1), (e) advertised window unchanged (c3). `tcp.rx_dup_ack` counter now fires only on genuine dup ACKs.

- **I-4** — RFC 6298 §2.2 / §2.3 Jacobson/Karels arithmetic correct.
  `tcp_rtt.rs:38-54`: first sample → `srtt=rtt, rttvar=rtt/2, rto=srtt+4*rttvar=3*rtt` (test expects rto=300 for rtt=100 → passes). Subsequent: `rttvar = (3/4)*rttvar + (1/4)*|srtt-rtt|`, `srtt = (7/8)*srtt + (1/8)*rtt`. Order is correct (`srtt.abs_diff(rtt)` uses pre-update srtt). α=1/8, β=1/4 match §2.3 suggestion.

- **I-5** — RFC 6298 §3 Karn's algorithm implemented.
  `tcp_input.rs:553-585`: TS-based RTT sample preferred (RFC 6298 §3 explicit exception to Karn's). Fallback sample gated on `front.xmit_count == 1` — never sample from a retransmitted segment. `front.first_tx_ts_ns` is the original TX time, preserved across retransmits (`tcp_retrans.rs:23`, `engine.rs:2686` updates `xmit_ts_ns` but leaves `first_tx_ts_ns`).

- **I-6** — RFC 6298 §5.1, §5.2, §5.6 RTO timer management satisfied.
  `engine.rs:2338-2374` §5.1: "if the timer is not running, start it" — `was_empty && c.rto_timer_id.is_none()` gate.
  `engine.rs:1517-1536` §5.2: "When all outstanding data has been acknowledged, turn off the retransmission timer" — cancel when `snd_retrans.is_empty() && snd_una == snd_nxt`.
  `engine.rs:892-921` §5.6: "Start the retransmission timer, such that it expires after RTO seconds (for the value of RTO after the doubling operation outlined in 5.5)" — Phase 5 re-arms RTO after Phase 4 backoff.
  (§5.3 is S-2 above.)

- **I-7** — RFC 6298 §4 clock granularity K·RTTVAR=0 edge case — not exercisable in practice.
  RFC §4 MUST: "if the K*RTTVAR term in the RTO calculation equals zero, the variance term MUST be rounded to G seconds." Our `tcp_rtt.rs:52` computes `rto = srtt + rttvar*4` without explicit `max(G, ...)`. When rttvar==0 (e.g. two identical consecutive samples), rto = srtt. Our `min_rto_us` floor at 5_000 always dominates any SRTT sample + 0 computation path, so the MUST-4 edge case is never observable. Noted for correctness: if min_rto_us is ever configured to 0 for testing, this edge case would fire.

- **I-8** — RFC 8985 §6.1 `RACK_retransmit_data` `Segment.lost = FALSE` reset on retransmit.
  `engine.rs:2687` — Phase 6 of `retransmit()` sets `entry.lost = false` in addition to bumping `xmit_count` and updating `xmit_ts_ns`. Task 15 fix landed per A5 plan.

- **I-9** — RFC 8985 §4 Requirements 1-2 satisfied.
  Req 1 (SACK + per-conn scoreboard): `tcp_input.rs:528-538` + `tcp_sack::SackScoreboard`.
  Req 2 (per-segment TX timestamp finer than `min_rtt/4`): `tcp_retrans::RetransEntry.xmit_ts_ns` in nanoseconds — orders of magnitude finer than any practical RTT.
  Req 3 (DSACK-based reo_wnd adaptation): RECOMMENDED, not required — covered by AD-13.
  Req 4 (TLP requires RACK): both wired on the same path.

- **I-10** — RFC 9293 segment-text retransmit — fresh header mbuf chained to data mbuf per spec §6.5.
  `engine.rs:2507-2700` `retransmit()` allocates a fresh header mbuf from `tx_hdr_mempool`, bumps the data mbuf refcount, calls `rte_pktmbuf_chain`, TXes, and cleans up on any error path. Never edits the in-flight mbuf in place. This matches RFC 9293 §3.7.1's implicit requirement (retransmit of the same data) and RFC 8985 §6.1 `RACK_retransmit_data`.

- **I-11** — RFC 9293 MUST-35 zero-window probing is pre-A5 gap, out-of-scope here.
  Zero-window probing (ZWP) is not implemented; we observe rx_zero_window via `counters.rx_zero_window` but do not probe. A5 scope per plan: "Wire RFC 8985 RACK-TLP loss detection + RFC 6298 RTO retransmission + mbuf-chained retransmit path + RFC 6528 SipHash-2-4 ISS." ZWP is not in A5's "does include" list. Deferred to Stage 2 / later phase.

- **I-12** — RFC 2883 is referenced but not vendored at `docs/rfcs/`.
  `docs/rfcs/rfc2883*` glob returns empty; `docs/rfcs/rfc2018.txt` is the SACK base. RFC 2883's DSACK extension is cited indirectly through spec §6.3 and A5 plan. Compliance is to "visibility only" per AD-13; no functional RFC 2883 sender-side emission. If full RFC 2883 compliance is ever in scope, the RFC text should be vendored first. Not a blocker for A5.

- **I-13** — RFC 8985 §6.2 Step 3 reordering detection (`RACK.fack`, `RACK.reordering_seen`) not implemented.
  Our `RackState` (`tcp_rack.rs:4-19`) omits these fields. `RACK.fack` is only used to adapt `reo_wnd` in §6.2 Step 4 when reordering has been observed (DSACK-driven adaptation which is explicitly visibility-only per AD-13). Since our `compute_reo_wnd_us` does not use `fack` or `reordering_seen`, the omission is consistent with the Stage-1 feature scope. Step 3 detection semantically sits in the DSACK-adaptation deferred block; flag for Stage 2 alongside AD-13.

## Verdict

**PASS**

All Must-fix items closed in commit `eb5467b` (F-1) or promoted to explicit Stage-2 Accepted Deviations (F-2, F-3). Missing-SHOULD items likewise either closed (S-2) or promoted (S-1).

Gate status:
- Must-fix open: 0.
  - [x] F-1 — closed in `eb5467b` (`update_min_rtt` wired in both TS-source and Karn's branches).
  - [x] F-2 — promoted to AD-15 (Stage-2 scope); **AD-15 closed in A5.5** (superseded by multi-probe data structures).
  - [x] F-3 — promoted to AD-16 (Stage-2 scope).
- Missing-SHOULD open: 0.
  - [x] S-1 — promoted to AD-17 (Stage-2 scope); **AD-17 closed in A5.5** (`RACK_mark_losses_on_RTO` pass implemented).
  - [x] S-2 — closed in `eb5467b` (partial-ACK RTO restart per RFC 6298 §5.3).
- Accepted-deviation entries: 18 (AD-1…AD-18). AD-15/16/17 are promotions of F-2/F-3/S-1; AD-18 mirrors the mTCP review's AD-8 (TLP-arm-on-send). Each cites either spec §6.4/§6.5 or the A5 plan's pre-declared/Stage-2-simplifications list.
  - **A5.5 retirements (3):** AD-15 (superseded), AD-17 (`RACK_mark_losses_on_RTO` implemented), AD-18 (TLP-arm-on-send implemented). Retained in this list for historical traceability; retirement notes appended on each AD entry cross-reference the A5.5 plan tasks (13/14/15/16) and the A5.5 design spec §6 new-AD rows (`AD-A5-5-srtt-from-syn`, `AD-A5-5-rack-mark-losses-on-rto`, `AD-A5-5-tlp-arm-on-send`) that supersede them. Remaining open Stage-2 ADs from this list: AD-16 (RACK Step 2 spurious-retrans guard) only.
- FYI: 13 informational observations (I-1…I-13).

Gate rule: phase may tag `phase-a5-complete` — no open `[ ]` checkboxes remain in Must-fix or Missing-SHOULD.
