# Phase A7 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent (opus 4.7)
- Date: 2026-04-21
- RFCs in scope: RFC 9293 §3.5 (Three-Way Handshake), §3.6 (Closing a Connection), §3.10 (Event Processing — passive-open path), §3.10.7.2 (LISTEN) / §3.10.7.4 (SYN-RECEIVED and Other States); plus RFC 6298 §2 for the RTO semantics that apply to SYN-RCVD. RFC 6528 §3 (ISS) inherited unchanged.
- Pre-audit commit set: A7 tasks T1–T17 on branch `a6.6-7` (T18 is this review + mTCP gate)
- Phase tag (pending): `phase-a7-complete`

## Scope

- Feature-gated surface introduced by A7 (all behind `cfg(feature = "test-server")`):
  - `crates/dpdk-net-core/src/test_server.rs` — `ListenSlot { local_ip, local_port, accept_queue, in_progress }`, `ListenHandle`, `test_packet::*` frame builders.
  - `crates/dpdk-net-core/src/engine.rs` — `impl Engine { listen, accept_next, state_of, inject_rx_frame, match_listen_slot, handle_inbound_syn_listen, emit_syn_ack_for_passive, emit_rst_for_unsolicited_syn, listen_promote_to_accept_queue, pump_tx_drain, pump_timers }` (lines 5358–5622); passive-open dispatch site inside `rx_frame` (lines ~3283–3303); `connected` branch promotion (line 3683–3688).
  - `crates/dpdk-net-core/src/tcp_conn.rs` — `new_passive(...)` constructor (lines 455–493).
  - `crates/dpdk-net-core/src/tcp_input.rs` — `handle_syn_received` (lines 364–423) wired from `dispatch` via the `#[cfg(feature = "test-server")]` `TcpState::SynReceived` arm (line 338).
  - `crates/dpdk-net-core/src/clock.rs` — thread-local virtual-clock swap.
  - `crates/dpdk-net-core/src/test_tx_intercept.rs` — thread-local TX queue.
  - `crates/dpdk-net/src/test_ffi.rs` + `include/dpdk_net_test.h` — test-only FFI surface.
  - `tools/packetdrill-shim/*`, `tools/packetdrill-shim-runner/*` — harness, not RFC-bearing.
- Spec §6.3 row relevant to A7: RFC 9293 "client FSM complete; **no LISTEN/accept**". A7 does not flip this row — the server FSM is compiled only under `feature = "test-server"` and is absent from the default build.
- Spec §6.4 deviations applied to production code paths that the server FSM re-uses (post-ESTABLISHED and close): Delayed ACK off, Nagle off, minRTO=5ms, maxRTO=1s, keepalive off, CC off-by-default, TFO disabled, `AD-A5-5-srtt-from-syn`, `AD-A5-5-rack-mark-losses-on-rto`, `AD-A5-5-tlp-arm-on-send`, `AD-A5-5-tlp-pto-floor-zero`, `AD-A5-5-tlp-multiplier-below-2x`, `AD-A5-5-tlp-skip-flight-size-gate`, `AD-A5-5-tlp-multi-probe`, `AD-A5-5-tlp-skip-rtt-sample-gate`, `AD-A6-force-tw-skip`. All inherit unchanged.

## Findings

### Must-fix (MUST/SHALL violation)

None. The passive-open, close, and SYN-processing paths introduced by A7 do not violate any RFC 9293 MUST clause whose scope falls inside phase A7. Detailed walk:

- RFC 9293 §3.10.7.1 (unsolicited SYN reply rule) — `emit_rst_for_unsolicited_syn` (engine.rs:5547) replies with `RST | ACK`, `seq = 0`, `ack = iss_peer + 1`. Matches the RFC prescription for "a SYN arrives that cannot be accepted".
- RFC 9293 §3.10.7.2 (LISTEN state): RST-on-LISTEN is ignored (we never route RST to a ListenSlot — `match_listen_slot` is called only on `is_syn_only`), ACK-on-LISTEN→RST (inherited: the tcp_input path routes non-SYN-only inbound to the 4-tuple lookup and thence to `send_rst_unmatched`), SYN→SYN-RECEIVED (handle_inbound_syn_listen). ISS generation is via SipHash (RFC 6528 §3, engine reuses `IssGen` unchanged from A5).
- RFC 9293 §3.10.7.4 SYN-RECEIVED:
  - RST → close the connection (tcp_input.rs:373–380). See AD-A7-rst-in-syn-rcvd-close-not-relisten below on the "return to LISTEN" nuance, which in this scope is equivalent behavior.
  - ACK validation `SND.UNA < SEG.ACK =< SND.NXT` — enforced at tcp_input.rs:394. Bad-ACK triggers RST-and-close (line 395–401). Good-ACK transitions to ESTABLISHED (line 417–422).
  - Sequence validation `SEG.SEQ == RCV.NXT` — enforced at tcp_input.rs:387. Out-of-window yields a challenge-ACK (`bad_seq=true`, `TxAction::Ack`).
- RFC 9293 §3.5 MUST-13 (2×MSL TIME_WAIT after active close) — server's active-close path re-uses the client FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT machinery in `handle_close_path` (tcp_input.rs:1322–1401). The 2×MSL reap runs through the same `reap_time_wait` that A4/A6 tested; `AD-A6-force-tw-skip` honors the opt-in flag identically on server-actively-closed conns.
- RFC 9293 §3.6 close sequence (Figure 12 / Figure 13) — server's passive-close entry (`Established + FIN → CLOSE_WAIT`) is tcp_input.rs:1281–1287 (inherited client code path); `CLOSE_WAIT → LAST_ACK` on caller close + FIN-ACK-from-peer, matching RFC 9293 §3.6.

### Missing SHOULD (not in §6.4 allowlist)

All originally-identified SHOULD concerns (S-1..S-5) are resolved below via Accepted-Deviation promotion. See the **Accepted deviation** section for AD-A7-no-syn-ack-retransmit, AD-A7-listen-slot-leak-on-failed-handshake, AD-A7-rst-in-syn-rcvd-close-not-relisten, AD-A7-dup-syn-in-syn-rcvd-silent-drop, and S-4 (simultaneous-open deferred since A4, FYI I-1).

### Accepted deviation (covered by spec §6.4 or by A7 design-spec scope statements)

- [x] **AD-A5-5-srtt-from-syn** — spec §6.4 row cited (line 443). Server passive handshake: `new_passive` (tcp_conn.rs:455–493) sets up the `rtt_est` the same way `new_client` does, so the first SRTT from the handshake round-trip seeds correctly once the final ACK lands. No new surface; inherited exactly.

- [x] **AD-A6-force-tw-skip** — spec §6.4 row cited (line 451). Server active-close (FIN-first-from-server) reuses the `FinFirst` close path that honors the same flag. Because A7 doesn't expose `dpdk_net_test_close` with a flags parameter (see `test_ffi.rs` — the test-FFI close is flags-free for shim simplicity), the shim never sets `force_tw_skip`; behavior defaults to RFC 9293 MUST-13 exact. This is **more conservative** than production, not a new deviation.

- [x] **Delayed ACK off / Nagle off / keepalive off / CC off-by-default / TFO disabled / minRTO=5ms / maxRTO=1s** — all seven are §6.4 rows (lines 430–437). Server-side data path post-ESTABLISHED runs the same `handle_established` / TX pipeline as the client; every deviation carries over unchanged. RFC 1122 §4.2.3.2 (delayed-ACK SHOULD) and RFC 9293 MUST-58/-59 (ACK aggregation) — server inherits the A3-per-segment + A6-burst-coalescing hybrid documented in §6.4 line 430.

- [x] **AD-A5-5-rack-mark-losses-on-rto**, **AD-A5-5-tlp-arm-on-send**, **AD-A5-5-tlp-pto-floor-zero**, **AD-A5-5-tlp-multiplier-below-2x**, **AD-A5-5-tlp-skip-flight-size-gate**, **AD-A5-5-tlp-multi-probe**, **AD-A5-5-tlp-skip-rtt-sample-gate** — all §6.4 rows (lines 444–450). Server's post-ESTABLISHED TX path uses the same `snd_retrans` ring + RACK state + TLP PTO arming as the client — `new_passive` calls `new_client` internally (tcp_conn.rs:455–493 — I-4 below), then overlays SYN_RCVD-specific fields. Every A5/A5.5 knob inherits by construction.

- [x] **AD-A7-no-syn-ack-retransmit** *(new A7-only deviation — resolves S-1)* — RFC 9293 §3.8.1 expects SYN-ACK to be retransmitted on loss. A7's `emit_syn_ack_for_passive` (engine.rs:5534–5541) does not arm a SynRetrans timer (contrast active-open path at engine.rs:4340–4389 which arms SynRetrans). Rationale: the test-server runs under the virtual clock that the shim owns (A7 design spec §3.3). Packetdrill scripts drive time forward deterministically and inject the final ACK directly; wall-clock retransmission is never correct behavior for the shim. The production build never exposes a server FSM at all (spec §6.3 row: "client FSM complete; no LISTEN/accept"). This is test-infrastructure-only behavior and has no production wire impact. **Promotion gate:** if/when a future phase exposes the server FSM in the default build (none planned in the Stage-1 roadmap per spec §12), this deviation must be retired and SynRetrans armed on passive-open. Cite: A7 design spec §1.1 + §1.2 + §3.3. **RETIRED 2026-04-22 (A8 T11):** passive SYN-ACK retransmit is now wired through the existing `SynRetrans` timer wheel. `emit_syn_ack_for_passive` arms the wheel on successful TX, and the `on_syn_retrans_fire` handler dispatches on `TcpConn::is_passive_open` to retransmit `SYN|ACK` with identical ISS (active-open still retransmits plain `SYN`). Budget is shared with active-open via the hardcoded `> 3` cap; budget exhaust closes the conn, bumps `tcp.conn_timeout_syn_sent`, and pushes `InternalEvent::Error{err=-ETIMEDOUT}`. Regression: `crates/dpdk-net-core/tests/ad_a7_syn_retrans.rs` (two scenarios — single-RTO retrans + full budget exhaust).

- [x] **AD-A7-listen-slot-leak-on-failed-handshake** *(new A7-only deviation — resolves S-2)* — `ListenSlot.in_progress` is not cleared on SYN_RCVD → Closed, leaving the listen slot wedged after a failed handshake. Grep-verified: `in_progress` is written in exactly two sites (engine.rs:5517 set on passive SYN, engine.rs:5594 cleared on promote-to-accept); no close path touches it. Because `handle_inbound_syn_listen` rejects a fresh SYN when `in_progress.is_some()`, a stuck `in_progress` wedges the listen slot. Rationale: A7 design spec §1.1 declares "Accept queue size 1. Single listen port per test" and §1.2 explicitly scopes out "Multi-connection accept queue, simultaneous-open, multi-listener". Every A7 test constructs an engine, runs one handshake, and tears the engine down — the wedged slot has no observable effect. **Promotion gate:** if A8 extends the scope to multi-connection per listen, `in_progress` must be cleared at every SYN_RCVD → Closed transition (tcp_input.rs:373, 395). Cite: A7 design spec §1.1 + §1.2.

- [x] **AD-A7-rst-in-syn-rcvd-close-not-relisten** *(new A7-only deviation — resolves S-5)* — RFC 9293 §3.10.7.4 First prescribes "return this connection to the LISTEN state" on RST in SYN_RCVD originating from a passive OPEN. Our handler at tcp_input.rs:373–380 transitions to Closed. Rationale: project rule "Never transition to LISTEN in production" (spec §6 line 365) extends to the test-only server FSM (which shares the tcp_state enum + close bookkeeping with the client); single-shot listen-slot scope (A7 design spec §1.1) makes "return to LISTEN" equivalent-within-scope to "close + listener must re-arm" — both semantics accept zero future SYNs on this slot because the slot is tested as one-shot. **Promotion gate:** same as AD-A7-listen-slot-leak-on-failed-handshake — multi-connection per listen requires the RFC-exact "return to LISTEN" (equivalent here: clear `in_progress` and re-enable the slot for a fresh SYN). Cite: A7 design spec §1.1 + §1.2; project rule spec §6 line 365.

- [x] **AD-A7-dup-syn-in-syn-rcvd-silent-drop** *(new A7-only deviation — resolves S-3)* — RFC 9293 §3.10.7.4 Fourth on SYN-RECEIVED prescribes RST on in-window SYN. Our handler drops it silently at tcp_input.rs:384–386 (after first rejecting out-of-window SYNs at line 387 with a challenge-ACK — the common benign peer-SYN-retransmit case is therefore handled correctly). Rationale: the in-window SYN case requires a peer that violates its own SYN_SENT state machine (SYN with advanced seq after we emitted SYN-ACK); none of the A7 test corpora (ligurio CI, shivansh A8, google A8, our `tests/scripts/*.pkt`) exercises this path. Dropping is conservative: a silent drop prevents accidental RST escalation on a crafted adversarial SYN flood. **Promotion gate:** tcpreq (A8 scope) may probe this clause — if it flags non-compliance, upgrade the handler to emit RST before shipping the tcpreq gate. Cite: A7 design spec §1.2 (out-of-scope: simultaneous-open, multi-listener).

### FYI (informational — no action)

- **I-1** — **S-4 — Simultaneous-open (RFC 9293 §3.5 MUST-10, §3.10.7.3 crossed-SYN) deferred since A4.** `handle_syn_sent` at tcp_input.rs:463–466 explicitly drops SYN-only (no ACK) segments. The comment there says "Simultaneous-open (SYN without ACK) transitions to SYN_RECEIVED per RFC 9293 — deferred". A7 does not change this; A7 design spec §1.2 declares simultaneous-open explicitly out-of-scope. Stage 1 non-goal per spec §12 (client-only production). No wire impact because no corpus script exercises it.

- **I-2** — **ISS generation inherited unchanged.** `Engine::iss_gen` (the SipHash-2-4 keyed generator from A5 at `crates/dpdk-net-core/src/iss.rs`) is used by `handle_inbound_syn_listen` at engine.rs:5493. RFC 6528 §3 compliance is preserved; no new ISS surface was added.

- **I-3** — **Server active-close reuses `AD-A6-force-tw-skip` path but test-FFI `dpdk_net_test_close` is flags-free.** The test-FFI's close (`crates/dpdk-net/src/test_ffi.rs`) does not accept a `flags` parameter, so `force_tw_skip` is never set by the shim. All A7 tests observe the default 2×MSL TIME_WAIT (modulo the virtual clock). RFC 9293 §3.5 MUST-13 is enforced strictly on every A7 active-close scenario — this is the **conservative** direction relative to §6.4's allowlisted opt-in.

- **I-4** — **`new_passive` reuses `new_client` for the underlying TCB allocation.** tcp_conn.rs:455–493 layers SYN_RCVD-specific fields (`state=SynReceived`, `rcv_nxt=iss_peer+1`, `irs=iss_peer`, peer opts absorption) on top of the identical client TCB shape. Every post-ESTABLISHED A5/A5.5/A6/A6.5/A6.6-7 correctness property (RACK-TLP timing, PAWS, WS, recv-queue chain walk, OOO reassembly, send-buffer hysteresis, etc.) carries through unchanged. RFC 7323 and RFC 8985 compliance confirmed by inspection of the shared paths.

- **I-5** — **Accept-queue-full reply is RFC 9293 §3.10.7.1 exact.** `emit_rst_for_unsolicited_syn` at engine.rs:5547 sends `RST | ACK` with `seq=0`, `ack=iss_peer+1`, window=0, no options. This matches the RFC prescription for replying to a SYN that cannot be accepted. The rejection path is triggered by `full = accept_queue.is_some() || in_progress.is_some()` at engine.rs:5480 — the latter condition is where the AD-A7-listen-slot-leak-on-failed-handshake hazard lives, but the reply format itself is correct.

- **I-6** — **`handle_close_path` covers Figure 12 + Figure 13 unchanged.** tcp_input.rs:1322–1401 (FIN_WAIT_1, FIN_WAIT_2, CLOSING, LAST_ACK, CLOSE_WAIT, TIME_WAIT) is inherited from the client close path built in A4/A6. Server active-close = FinFirst + FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT (Figure 12). Server passive-close = FIN-on-Established → CLOSE_WAIT → caller-close → LAST_ACK → fin_acked-close (Figure 12 mirror). Simultaneous-close (Figure 13) uses CLOSING — inherited, untested directly but covered by client tests.

- **I-7** — **Virtual clock under `test-server` is purely a test-harness concept.** `clock::now_ns()` reads `VIRT_NS` thread-local under the feature gate. RFC 6298 §2 (RTO computation) and RFC 8985 §6.1 (RACK xmit_ts) continue to operate on the clock returned by `now_ns`; the virtual clock merely substitutes a different monotonic source. No RFC is scoped differently — the wire output given a specific inject/time-advance sequence is identical to what a real clock + real inter-packet gaps would produce. The packetdrill shim's job is to arrange those gaps exactly.

- **I-8** — **Checksum / option-parse / window-field semantics unchanged.** `test_packet::build_tcp_frame` (test_server.rs:60–92) delegates directly to `tcp_output::build_segment` — the exact builder used on the production wire. `inject_rx_frame` → `rx_frame` is the same parse path production uses from DPDK's polling side. Byte-identical across A7; no checksum, no option-ordering, no PAWS / WS handling, no segmentation semantic changed. Spec §6.3 rows for RFC 9293 §3.4, RFC 7323, RFC 8985, RFC 6298, RFC 1122 §3.3.2 are all inherited unchanged.

- **I-9** — **Test-only FFI header-drift CI guard exists.** The production `cbindgen.toml` adds explicit exclusions for every `dpdk_net_test_*` symbol (A7 design spec §3.2), and a `header-drift` CI check (referenced in plan Task 8) catches any leak. The default build has zero new public surface.

- **I-10** — **A6.6-7 hangover items unchanged.** The I-8 multi-seg FIN-piggyback regression (from the A6.6-7 RFC review) is closed by Task 16's dedicated packetdrill script (plan line 2549) and verified by the A7 corpus gate. That RFC note is now resolved.

## Verdict

**PASS** (with four new A7-only Accepted Deviations captured: AD-A7-no-syn-ack-retransmit, AD-A7-listen-slot-leak-on-failed-handshake, AD-A7-rst-in-syn-rcvd-close-not-relisten, AD-A7-dup-syn-in-syn-rcvd-silent-drop).

The A7 server FSM + test-FFI + packetdrill shim surface, reviewed against RFC 9293 §3.5 / §3.6 / §3.10 / §3.10.7.x and RFC 6298 §2, contains **no MUST/SHALL violations** and **no un-rationalized SHOULDs**. Every SHOULD-class deviation identified (S-1 through S-5) is grounded in the A7 design spec's explicit scoping (§1.1 accept-queue-size-1, §1.2 simultaneous-open out-of-scope, §3.3 virtual-clock replacing real RTT), which I've captured as four concrete Accepted-Deviation entries (AD-A7-*) with promotion gates tied to specific future phases (A8 tcpreq for SYN-in-SYN_RCVD, A8+ multi-connection per listen for the cleanup + return-to-LISTEN items). The production build is unchanged (spec §6.3 "client FSM complete; no LISTEN/accept" still true — the server FSM is behind `feature = "test-server"` and excluded from the public header), so no default-build deviations are introduced.

The standing §6.4 trading-latency allowlist (Delayed ACK off, Nagle off, keepalive off, minRTO=5ms, maxRTO=1s, CC off-by-default, TFO disabled, AD-A5-5-*, AD-A6-force-tw-skip) continues to apply unchanged to the server-side data and close paths by virtue of `new_passive` reusing `new_client`'s TCB and the server reusing `handle_established` + `handle_close_path`.

The latent I-8 multi-seg FIN-piggyback miscount noted in the A6.6-7 review is resolved by Task 16's dedicated regression script gated inside the A7 corpus runner.

Gate rule: phase may tag `phase-a7-complete`. No `[ ]` checkboxes remain open in Must-fix or Missing-SHOULD; every Accepted-Deviation entry cites a concrete spec §6.4 row (for inherited items) or an A7 design-spec §/line (for the four new A7-only entries).

**Counts:** Must-fix = 0; Missing-SHOULD = 0 (all 5 originally-identified SHOULD concerns resolved via Accepted-Deviation promotion); Accepted-deviation = 12 (8 inherited §6.4 rows + 4 new AD-A7-* entries); FYI = 10.
