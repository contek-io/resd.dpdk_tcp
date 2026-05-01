# Phase A10 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent (opus 4.7)
- Date: 2026-04-23
- RFCs in scope: 793 / 9293 (TCP), 7323 (TS options, window scale, PAWS), 2018 (SACK), 6528 (ISS randomization), 5681 (Reno CC), 6298 (RTO — incidental via preset)
- Our commit: branch `phase-a10` in worktree `/home/ubuntu/resd.dpdk_tcp-a10`, HEAD per dispatcher (phase-a10 tip)
- Branch point: `1cf754a` (master tip at A10 branch creation)

## Summary

A10 is **benchmark harness only** — 9 new tool crates under `tools/`, one additive `obs-none` compile-time feature with four gates (G1–G4), plus a reporting pipeline. The engine's TCP wire semantics are unchanged by the default build. The only RFC-relevant surfaces are:

1. **`obs-none` feature gates (D4).** Under `--features obs-none` the four observability emission sites (EventQueue::push, emitted_ts_ns capture, rtt_histogram.update, dpdk_net_conn_stats FFI) are compiled to no-ops / ENOTSUP. Verified that **wire behavior is identical across both feature configurations**: flow-table mutation, counter bumps (`tcp.conn_open`, `tcp.conn_close`, `tcp.conn_rst`, `tcp.recv_buf_delivered`, `tcp.recv_buf_drops`, `tcp.state_trans[from][to]`), RTT estimator (`rtt_est.sample`), RACK min-RTT (`rack.update_min_rtt`), TLP budget hooks (`on_rtt_sample_tlp_hook`, `on_new_data_ack_tlp_hook`), retransmit scheduling, and `transition_conn` all run unconditionally. Only the event-queue push + forensics histogram are gated. Default builds (the production shape) carry the full body verbatim.

2. **`bench-vs-linux` Mode B canonicalisation (T9).** `tools/bench-vs-linux/src/normalize.rs` rewrites ISS + TSval/TSecr base + MACs on pcap captures to canonicalise divergences that both RFCs 6528 (ISS is host-chosen) and 7323 (TSval base is host-chosen) explicitly allow. MSS (kind=2), Window Scale (kind=3), SACK (kind=5) are preserved under the pinned remap. TCP / IPv4 checksums are recomputed post-rewrite so the canonicalised captures remain valid wire-format. The production mode-B workload is not yet running live (pre-captured-pcap MVP per deferred T15-B); `build_engine_config_rfc_compliance` helper only exercises in unit tests. This is consistent with the phase plan's stated MVP scope flex.

3. **`bench-vs-mtcp` preset choice.** Uses `cc_mode=0` (trading-latency) explicitly per parent spec §11.5.1 ("cc_mode=off on both stacks"). This is a measurement-methodology choice — the comparison axis is fast-path stack, not congestion control. RFC 5681 does not mandate that implementations always run Reno; §1 only requires that TCPs using CC algorithms MUST implement §3. Our default is no-CC (permitted).

4. **A-HW Task 18 subsumption (bench-e2e HW assertions).** `tools/bench-e2e/src/hw_task_18.rs` asserts ENA steady-state (`offload_missing_rx_timestamp == 1`, `offload_missing_llq == 0`, `rx_drop_cksum_bad == 0`, all rx_hw_ts_ns == 0). These are correctness properties of the engine's offload surface, not RFC behavior; verified they do not mask RFC-relevant failures (e.g. a real TCP checksum error would still bump `rx_drop_cksum_bad` and fail the assertion).

No MUST or SHOULD RFC clauses are modified, regressed, or newly skipped by A10. The preset=rfc_compliance invocation path (only exercised in Mode B unit tests today) correctly flips the documented five fields and calls into the same A6-landed `apply_preset` helper — no new deviation surface.

## Scope

### Our files reviewed

**Engine (obs-none feature sites — wire-behavior invariance verification):**
- `/home/ubuntu/resd.dpdk_tcp-a10/crates/dpdk-net-core/src/tcp_events.rs` lines 119–198 (EventQueue::push G1 gate) + tests skipped under feature (200–264).
- `/home/ubuntu/resd.dpdk_tcp-a10/crates/dpdk-net-core/src/tcp_conn.rs` lines 540–562 (ts-sample RTT histogram update path G3) + 1200–1210 (Karn's-fallback RTT histogram).
- `/home/ubuntu/resd.dpdk_tcp-a10/crates/dpdk-net-core/src/tcp_input.rs` lines 510–525 (handle_established signature G3 threading) + 725–755 (histogram update sites inside ack-cumulative path).
- `/home/ubuntu/resd.dpdk_tcp-a10/crates/dpdk-net-core/src/engine.rs` lines 2050–2076 (rx_enomem edge-triggered emit) + 2320–2385 (per-packet RTO fire emission) + 2520–2555 (TLP fire emission) + 2725–2755 (SYN-retrans-timeout Error+Closed pair) + 2810–2825 (TIME_WAIT reap Closed) + 3405–3450 (WRITABLE + per-packet emission) + 3660–3720 (Connected/Closed on outcome) + 3785–3799 (transition_conn StateChange) + 4145–4196 (READABLE emission) + 4870–4900 (EPERM_TW_REQUIRED) + 5040–5280 (send/error Error emissions).
- `/home/ubuntu/resd.dpdk_tcp-a10/crates/dpdk-net/src/lib.rs` lines 675–719 (dpdk_net_conn_stats G4 gate) + 1325–1358 (feature-gated tests).
- `/home/ubuntu/resd.dpdk_tcp-a10/crates/dpdk-net-core/Cargo.toml` lines 94–100 (obs-none feature declaration).
- `/home/ubuntu/resd.dpdk_tcp-a10/crates/dpdk-net/Cargo.toml` lines 22–26 (obs-none pass-through).

**Benchmark tool crates (engine config + wire-preset surfaces):**
- `/home/ubuntu/resd.dpdk_tcp-a10/tools/bench-vs-linux/src/normalize.rs` — pcap canonicalisation (full file, 1002 lines).
- `/home/ubuntu/resd.dpdk_tcp-a10/tools/bench-vs-linux/src/mode_wire_diff.rs` — Mode B runner (285 lines).
- `/home/ubuntu/resd.dpdk_tcp-a10/tools/bench-vs-linux/src/mode_rtt.rs` — Mode A RTT harness (trading-latency preset).
- `/home/ubuntu/resd.dpdk_tcp-a10/tools/bench-vs-linux/src/main.rs` lines 352–366 (build_engine uses EngineConfig::default() — no preset override).
- `/home/ubuntu/resd.dpdk_tcp-a10/tools/bench-vs-mtcp/src/main.rs` lines 945–963 (build_engine — explicit `cc_mode=0`).
- `/home/ubuntu/resd.dpdk_tcp-a10/tools/bench-e2e/src/hw_task_18.rs` — A-HW Task 18 subsumption.
- `/home/ubuntu/resd.dpdk_tcp-a10/tools/bench-e2e/src/main.rs` lines 305–315 (build_engine uses default).
- `/home/ubuntu/resd.dpdk_tcp-a10/tools/bench-ab-runner/src/main.rs` lines 400–415 (build_engine uses default).

**Existing preset machinery (reused, not modified by A10):**
- `/home/ubuntu/resd.dpdk_tcp-a10/crates/dpdk-net/src/lib.rs` lines 15–46 (apply_preset — lands A6, unchanged by A10).

### Spec §6.3 rows verified

A10 does not claim coverage for any new §6.3 row. The phase's stated scope is benchmark-only. The matrix rows verified as unchanged by this phase:

- **RFC 793 / 9293 (TCP)** — client FSM: A10 adds no FSM transitions. `transition_conn` still bumps `state_trans[][]` and still reaches TIME_WAIT deadline logic under every feature configuration.
- **RFC 7323 (Timestamps + Window Scale)** — TS option handling in `tcp_input.rs` is unchanged. The `rtt_histogram.update` gate (G3) is downstream of the TS-based RTT sample (`rtt_est.sample`); gating the histogram does NOT drop the sample.
- **RFC 2018 (SACK)** — SACK scoreboard / option parsing unchanged. Mode B normalize correctly rewrites SACK block edges using the reverse-direction ISS pin.
- **RFC 6528 (ISS generation)** — ISS recipe unchanged by A10. Mode B canonicalisation uses the pin-first-seen heuristic which is correct for diff purposes regardless of the host's actual ISS algorithm.
- **RFC 5681 (Reno)** — Reno implementation unchanged; `bench-vs-mtcp` explicitly runs `cc_mode=0` per parent §11.5.1.
- **RFC 6298 (RTO)** — only touched transitively via `preset=rfc_compliance` flipping `tcp_min_rto_us=200_000` / `tcp_initial_rto_us=1_000_000`. The preset is exercised in one unit test (`preset_builder_flips_five_fields` in `mode_wire_diff.rs`) and the existing A6-landed production path. No new preset logic in A10.

### Spec §6.4 deviations touched

A10 introduces **no new accepted deviations**. All standing §6.4 entries remain unmodified:

- `AD-A5-5-srtt-from-syn`, `AD-A5-5-rack-mark-losses-on-rto`, `AD-A5-5-tlp-arm-on-send`, `AD-A5-5-tlp-pto-floor-zero`, `AD-A5-5-tlp-multiplier-below-2x`, `AD-A5-5-tlp-skip-flight-size-gate`, `AD-A5-5-tlp-multi-probe`, `AD-A5-5-tlp-skip-rtt-sample-gate`, `AD-A6-force-tw-skip`.
- Trading-latency defaults (Nagle off, delayed-ACK off, minRTO=5ms, maxRTO=1s, CC off-by-default, TFO disabled) all preserved in default builds.

## Findings

### Must-fix (MUST/SHALL violation)

_(none — 0 open)_

### Missing SHOULD (not in §6.4 allowlist)

_(none — 0 open)_

### Accepted deviation (covered by spec §6.4)

- **AD-1** — `obs-none` feature compiles `EventQueue::push` to a no-op; under this build the application never observes `DPDK_NET_EVT_*` events, though the FSM and counters still update.
  - RFC clause: RFC 9293 §3.10.2, `docs/rfcs/rfc9293.txt:2956` — the API surface is implementation-defined; the RFC does not mandate any specific event-delivery ABI.
  - Spec §6.4 line: n/a. This is an **additive compile-time marker**, not a RFC-level deviation. The feature is expressly for `bench-obs-overhead` measurement of the zero-observability floor (spec §13 / D4). Default builds are unchanged.
  - Our code behavior: default build runs the full emission body verbatim; under `--features obs-none` the four G1–G4 sites compile away. Wire behaviour identical. **No spec §6.4 row required** because the feature is never on in production builds — gated at the bench tool matrix, never as a library default.

### FYI (informational — no action)

- **I-1** — `bench-vs-linux` Mode B production workload deferred to T15-B (live-capture orchestration). The `build_engine_config_rfc_compliance` helper in `tools/bench-vs-linux/src/mode_wire_diff.rs:201-213` is currently test-only and exercised by `preset_builder_flips_five_fields` (lines 269–283), which correctly pins the five-field invariant (`tcp_nagle=true`, `tcp_delayed_ack=true`, `cc_mode=1/Reno`, `tcp_min_rto_us=200_000`, `tcp_initial_rto_us=1_000_000`). MVP consumes pre-captured pcaps; `scripts/bench-nightly.sh` will wire the live capture. This MVP scope flex is **spec-acceptable** for phase-a10-complete — the preset invocation contract is pinned by unit test and the A6-landed `apply_preset` is unchanged. When T15-B lands, it uses the already-tested helper.

- **I-2** — Mode B `normalize.rs` pin-first-seen ISS is correct for diff purposes even though it doesn't preserve the 4.4BSD-style monotonicity property of our native ISS recipe (`ticks_since_boot + SipHash(...)`). The canonicalisation's job is purely to make two captures byte-identical when they're semantically equivalent; our production ISS monotonicity (needed for the TIME_WAIT-skip deviation `AD-A6-force-tw-skip`) is not exercised by pcap-level byte-diff. Either stack's ISS algorithm satisfies RFC 6528 §3 (`rfc6528.txt:191` — "TCP SHOULD generate its Initial Sequence Numbers with the expression: ISN = M + F(localip, localport, remoteip, remoteport, secretkey)") so canonicalisation does not affect compliance verification.

- **I-3** — `bench-vs-mtcp` uses `cc_mode=0` (no congestion control) per parent spec §11.5.1. RFC 5681 §1, `docs/rfcs/rfc5681.txt:209` ("The slow start and congestion avoidance algorithms MUST be used by a TCP sender...") is scoped to "TCPs that use congestion control"; our trading-latency default does not run congestion control at all, which is documented as an accepted deviation at spec §6.4 line 436 ("Congestion control | RFC 5681 MUST | off-by-default"). The comparison methodology (stack-vs-stack with identical CC-off settings on both) is RFC-compliant given this pre-existing deviation.

- **I-4** — `tools/bench-e2e/src/hw_task_18.rs:102-153` asserts `rx_drop_cksum_bad == 0` on well-formed traffic. This is a correctness assertion against a real TCP checksum violation (which would bump the counter per RFC 9293 §3.1 — pseudo-header checksum covers all bytes), not an RFC deviation. Any legitimate checksum corruption during a bench-e2e run would fail the assertion, surfacing rather than masking the divergence.

- **I-5** — `tools/bench-vs-linux/src/normalize.rs:505-563` walk_options treats truncated option tails as silent-stop (matches the legacy tcp_input option parser behavior) but surfaces a hard error (`CanonError::MalformedSackOption`) on SACK blocks whose body length is not a multiple of 8. This is more strict than RFC 2018 requires — the RFC is silent on malformed SACK; smoltcp / mTCP also drop garbage silently. The stricter behavior is T9-scoped: a malformed SACK block during canonicalisation produces garbage seq-space rewrites downstream, so the harness bails rather than report a spurious diff. Correctness is preserved; a real-traffic malformed-SACK segment would still flow through the production path (tcp_input.rs parser) unchanged.

- **I-6** — `tools/bench-vs-linux/src/normalize.rs:679-688` leaves `ack=0` unchanged on SYN segments (SYN without ACK). Per RFC 9293 §3.1 `rfc9293.txt:335-339` ("If the ACK control bit is set, this field contains the value of the next sequence number..."), SYN-only segments don't carry a meaningful ack and leaving it at zero preserves the RFC-required wire shape on both sides. Confirmed correct.

- **I-7** — `tools/bench-vs-linux/src/normalize.rs:745-769` preserves `TSecr=0` on SYN (per RFC 7323 §3.2 `rfc7323.txt:652-654` — "If the ACK bit is not set in the outgoing TCP header, the sender of that segment SHOULD set the TSecr field to zero"). Non-zero TSecr is rewritten using the peer's pinned TS base, which correctly echoes the remap the peer's TSval experienced. This satisfies the RFC 7323 MUST at `rfc7323.txt:654-657` ("When the ACK bit is set in an outgoing segment, the sender MUST echo a recently received TSval sent by the remote TCP") because the canonical pair preserves the echo relationship under the linear remap.

- **I-8** — Under `obs-none`, `events_dropped` and `events_queue_high_water` counters remain at zero because all pushes are no-ops. This is intentional semantics (zero-observability baseline). The counter schema is preserved (the FFI structure has identical layout) so C callers see the field but always read 0. Not an RFC concern.

## Verdict (draft)

**PASS**

Gate rule: phase cannot tag `phase-a10-complete` while any `[ ]` checkbox in Must-fix or Missing-SHOULD is open. No open checkboxes; 0 Must-fix, 0 Missing-SHOULD, 1 Accepted-deviation (additive compile-time feature — not a §6.4 entry, covered by D4 in spec §13), 8 FYI observations.

**Rationale:**
- A10 is benchmark-only: no engine wire semantics changed. Confirmed by line-by-line inspection of every `cfg(feature = "obs-none")` gate site — each gates **only** observability emission, never wire TX, never FSM transitions, never counters that feed behaviour (RTT estimator, RACK, TLP budget, flow-table mutation).
- The `preset=rfc_compliance` invocation in Mode B correctly calls the A6-landed `apply_preset` helper. The five-field invariant is pinned by unit test `preset_builder_flips_five_fields` (mode_wire_diff.rs:269-283).
- The pcap canonicalisation choices in `normalize.rs` preserve RFC-relevant wire differences (MSS, window, ip_id, receive window) and only rewrite host-chosen-per-connection free values (ISS per RFC 6528 §3, TSval base per RFC 7323 §3.2, MAC per physical host).
- Live-capture Mode B workload deferred to T15-B is spec-acceptable per the phase plan's MVP scope flex; the preset activation contract is pinned by unit test today.
- `bench-vs-mtcp` `cc_mode=0` choice is methodologically justified by parent spec §11.5.1 and consistent with the pre-existing §6.4 "Congestion control off-by-default" deviation.
- A-HW Task 18 subsumption in `bench-e2e` asserts ENA steady-state counter values; any real TCP checksum violation or unexpected offload regression would fail the assertion rather than be silently masked.

Recommendation: the `phase-a10-complete` tag is **not blocked** by RFC compliance concerns. Proceed to merge pending the parallel mTCP comparison review.
