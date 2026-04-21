# Phase A6 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent
- Date: 2026-04-19
- RFCs in scope: 7323 §5.5, 6191 (client-side analog), 9293 (API surface + MUST-13 intersect)
- Our commit: `804abf0ac1ada3d071f7a0b9245d2c9800c8af93` (worktree `/home/ubuntu/resd.dpdk_tcp-a6`, branch `phase-a6`, 22/22 A6 tasks landed)

## Summary

A6 is surface + observability on top of A5/A5.5 wire behavior. Only two clauses touch RFC text:

1. **RFC 7323 §5.5 (24-day `TS.Recent` expiration)** — implemented as zero-timer lazy-at-PAWS check in `tcp_input.rs` (spec §3.7). Verified: the idle-before-PAWS check order satisfies the RFC semantics (§5.5 re-seed outcome is met); sentinel `ts_recent_age == 0` correctly preserved; all three runtime `ts_recent` write sites (SYN-ACK parse, §5.5 lazy expiration, §4.3 MUST-25 update) also write `ts_recent_age`. The only `ts_recent` write without age update is a test helper (`tcp_input.rs:1834` inside `#[cfg(test)]`), not a runtime path — non-issue.
2. **RFC 6191 + RFC 9293 MUST-13 (2×MSL linger)** — `dpdk_net_close(FORCE_TW_SKIP)` opt-in early-reap of our own TIME_WAIT, gated on `c.ts_enabled == true`. Client-side analog of RFC 6191 via PAWS-on-peer + monotonic ISS (parent spec §6.5). The default path (no flag / flag dropped via EPERM) preserves RFC 9293 MUST-13 exactly. One finding: the opt-in early-reap is a MUST-13 deviation in semantic spirit and should have an AD-tag row in §6.4 for traceability; currently only §6.5 prose documents it.

All other A6 surface (public timer API, `dpdk_net_flush` batching, `DPDK_NET_EVT_WRITABLE`, `DPDK_NET_EVT_ERROR{err=-ENOMEM}` emission sites, `preset=rfc_compliance`, per-conn RTT histogram) sits below the RFC layer — no MUST/SHOULD clauses touched.

Expected outcome matches the design spec preface: brief report, no new MUST/SHOULD gaps, no new ADs beyond the A5/A5.5 set (one §6.4 tightening suggestion — non-blocking).

## RFCs reviewed

- `docs/rfcs/rfc7323.txt` §5.5 "Outdated Timestamps" (lines 1308–1342) — the `TS.Recent` 24-day invalidation mechanism.
- `docs/rfcs/rfc6191.txt` — server-side TIME-WAIT SYN-acceptance algorithm; reviewed for inverse reasoning about our client-side early-reap semantics.
- `docs/rfcs/rfc9293.txt` §3.5 TIME-WAIT (line 1653–1669) — MUST-13 linger requirement, and the MAY-2 carve-out that points to RFC 6191.

## Files reviewed

- `/home/ubuntu/resd.dpdk_tcp-a6/crates/dpdk-net-core/src/tcp_input.rs` — PAWS gate + 24-day lazy expiration (lines 540–588); SYN-ACK ts_recent write (389–393); MUST-25 ts_recent write (582–585).
- `/home/ubuntu/resd.dpdk_tcp-a6/crates/dpdk-net-core/src/tcp_conn.rs` — `ts_recent_age: u64` field (150–159); `force_tw_skip: bool` field (259–263); init both 0/false (311, 356).
- `/home/ubuntu/resd.dpdk_tcp-a6/crates/dpdk-net-core/src/engine.rs` — `close_conn_with_flags` (3880–3921); `reap_time_wait` short-circuit (2241–2265); `check_and_emit_rx_enomem` (1604–1620); poll-cycle snapshot (1466–1470).
- `/home/ubuntu/resd.dpdk_tcp-a6/crates/dpdk-net-core/src/counters.rs` — `tcp.ts_recent_expired` addition (170–173).
- `/home/ubuntu/resd.dpdk_tcp-a6/include/dpdk_net.h` — `DPDK_NET_CLOSE_FORCE_TW_SKIP` (34–36); `dpdk_net_close(flags)` doc-comment (478–499); timer ABI (501–525); histogram POD (330–338).
- `/home/ubuntu/resd.dpdk_tcp-a6/docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` — §6.3 row 8985 / 6298 (post-A5.5-nit fix); §6.4 AD table; §6.5 TIME_WAIT shortening rationale (line 462).

## Spec §6.3 rows verified

- RFC 7323 row (line 413) — TS.Recent 24-day expiration: finalized in A6 per spec §3.7 lazy-at-PAWS implementation; counter `tcp.ts_recent_expired` wired.
- RFC 9293 row (line 412) — client FSM complete, no LISTEN: A6 adds no FSM states. `close_conn_with_flags` reads `ts_enabled` but does not alter state transitions beyond the existing FIN path + conditional early-reap.
- RFC 6298 row (line 421) — A5.5 citation nit corrected inline ("§3.3" → "§2.2 + §3 Karn's rule").
- RFC 8985 row (line 420) — A5.5 citation nit corrected inline ("§7.4 RTT-sample gate" → "§7.3 step 2").

## Spec §6.4 deviations touched

- None of the A5/A5.5 AD rows are modified by A6.
- Proposed **new** AD tag `AD-A6-force-tw-skip` for §6.4 (see FYI-1 below) — currently lives as prose in §6.5; code is opt-in-behind-flag so default behavior is RFC 9293 MUST-13 compliant.

## Findings

### Must-fix (MUST/SHALL violation)

_(none — 0 open)_

### Missed edge-cases

_(none — 0 open)_

### Missing SHOULD (not in §6.4 allowlist)

_(none — 0 open)_

### Accepted deviation (covered by spec §6.4 or §6.5 prose)

- **AD-A6-force-tw-skip (proposed)** — `dpdk_net_close(FORCE_TW_SKIP)` opt-in early-reap of active-close TIME_WAIT.
  - RFC clause: `docs/rfcs/rfc9293.txt:1653–1654` — "When a connection is closed actively, it MUST linger in the TIME-WAIT state for a time 2xMSL (Maximum Segment Lifetime) (MUST-13)." Carve-out at lines 1665–1669 points to RFC 6191 ("This algorithm for reducing TIME-WAIT is a Best Current Practice that SHOULD be implemented"), but RFC 6191's algorithm is server-side SYN-on-TIME-WAIT acceptance.
  - Spec §6.5 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:462` — "The combination of PAWS on the peer (RFC 7323 §5) plus monotonic ISS on our side (RFC 6528) is the client-side analog of RFC 6191 §4.2's protections: any in-flight segment from the prior incarnation is rejected either by PAWS (peer-side TSval check) or by the ISS-monotonicity gate we maintain."
  - Our code behavior: `engine.rs:3892–3921` `close_conn_with_flags` — when `flags & CLOSE_FLAG_FORCE_TW_SKIP` and `c.ts_enabled == true`, sets `c.force_tw_skip = true`. `engine.rs:2244–2265` `reap_time_wait` short-circuits the 2×MSL wait when `c.force_tw_skip`. When prerequisite not met: `engine.rs:3902–3912` emits `Error{err=-EPERM}` + normal 2×MSL proceeds. Default (no flag) path is RFC 9293 MUST-13 exact.
  - Default preserves RFC: yes (caller must opt-in via `FORCE_TW_SKIP`).

### FYI (informational — no action required for tag)

- **I-1** — §6.4 tightening suggestion: FORCE_TW_SKIP deviation is only documented in §6.5 prose. For consistency with the AD-A5-5-* rows that formalize every opt-in deviation in the §6.4 table with AD tag / RFC stance / behavior / rationale columns, consider promoting FORCE_TW_SKIP to an `AD-A6-force-tw-skip` row. Non-blocking: the opt-in nature + the `ts_enabled` prerequisite + the EPERM visibility are already documented in the cbindgen header (dpdk_net.h:478–499) and in parent spec §6.5 — the behavior is well-specified. This is a traceability concern, not an RFC-conformance concern.

- **I-2** — RFC 7323 §5.5 order-of-check: the RFC text at line 1333–1334 suggests "The validity of TS.Recent needs to be checked only if the basic PAWS timestamp check fails, i.e., only if SEG.TSval < TS.Recent." Our implementation at `tcp_input.rs:562–576` checks `idle_ns > TS_RECENT_EXPIRY_NS` *before* the PAWS `SEG.TSval < TS.Recent` compare. Behavioral outcome is identical to the RFC order in all four sub-cases (PAWS-pass/fail × idle >/≤ 24d): when idle > 24d we re-seed `ts_recent` from the segment, when idle ≤ 24d we run the normal PAWS compare. The RFC's phrasing is an optimization hint ("only if... fails"), not a correctness requirement — §5.5 says the outcome must be "the segment is accepted, regardless of the failure of the timestamp check, and rule R3 updates TS.Recent". Our implementation produces that outcome. Non-issue; flagged for future maintainers who read the RFC literally.

- **I-3** — `ts_recent_age` sentinel correctness: sentinel `0` means "never touched". A fresh conn with no TS exchange has `ts_recent_age = 0` (tcp_conn.rs:311). `tcp_input.rs:564` gates the 24-day check on `ts_recent_age != 0`, so the sentinel is preserved. First TS write at `tcp_input.rs:389–393` (SYN-ACK parse) sets `ts_recent_age = now_ns`, ending the sentinel period. Subsequent updates via the 24-day lazy branch (566–568) or MUST-25 branch (582–585) keep age in lockstep with ts_recent. No missed write site.

- **I-4** — `dpdk_net_timer_cancel` `-EALREADY` → `-ENOENT` collapse: this is an API-contract simplification, not an RFC-layer concern. RFC 9293 defines no timer API. The parent spec §4.2 literal three-return-code wording is updated in §10.2 of the A6 design spec; the cbindgen header (dpdk_net.h:518–525) documents the collapse + the drain-always contract. Apps that always drain the event queue observe exactly-once TIMER event semantics — behaviorally safe.

- **I-5** — `dpdk_net_flush` data-only batching: no RFC MUST/SHOULD touched. RFC 9293 §3.8.3 specifies `push` semantics on the sender API; the data-segment TX batch is hidden behind `dpdk_net_send` / `poll_once` drain — no observable RFC contract is violated. Control frames (ACK/SYN/FIN/RST) continue to emit inline per their existing RFC-compliant paths (no delay introduced by flush batching).

- **I-6** — `FORCE_TW_SKIP` reserved-bit semantics: `engine.rs:3897` tests only `flags & CLOSE_FLAG_FORCE_TW_SKIP`. Other bits silently ignored. Future-compatible: a post-A6 phase can define additional bits without ABI break — apps passing `0` or `CLOSE_FLAG_FORCE_TW_SKIP` today will continue to work.

- **I-7** — `DPDK_NET_EVT_ERROR{err=-ENOMEM}` edge-triggering: `engine.rs:1466–1470` snapshots `rx_drop_nomem` at poll top; `engine.rs:1604–1620` compares and emits at most one Error per poll iteration. Prevents event-queue flood under sustained mempool starvation — per parent spec §9.3 and `feedback_performance_first_flow_control` guidance. No RFC tie-in.

## Conclusion

**PASS**

Gate status:
- RFCs covered: 3 (RFC 7323 §5.5 verified; RFC 6191 client-side-analog rationale verified; RFC 9293 MUST-13 opt-in deviation acknowledged)
- New §6.4 rows: 0 required, 1 proposed as traceability nit (AD-A6-force-tw-skip — non-blocking)
- Must-fix open: 0
- Missed-edge-cases open: 0
- Missing-SHOULD open: 0

All A6 in-scope RFC clauses are either satisfied (RFC 7323 §5.5 behavior verified end-to-end; ts_recent_age paired at every runtime write site), covered by opt-in gates with RFC-compliant defaults (RFC 9293 MUST-13 via `FORCE_TW_SKIP` guarded by `ts_enabled`), or out of scope (RFC 9293 API surface — no FSM changes; A5/A5.5 RFCs untouched). Gate not blocked; `phase-a6-complete` tag may proceed pending (a) mTCP review gate verdict and (b) the human's decision on the AD-A6-force-tw-skip §6.4 promotion (a text-only spec edit, not a code change).
