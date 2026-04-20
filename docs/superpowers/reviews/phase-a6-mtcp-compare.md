# Phase A6 — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent
- Date: 2026-04-19
- mTCP submodule SHA: `0463aad5ecb6b5bca85903156ce1e314a58efc19` (unchanged this phase; `third_party/mtcp/` not bumped)
- Our commit: `804abf0` (branch `phase-a6`, worktree `/home/ubuntu/resd.dpdk_tcp-a6`, 22 of 22 A6 implementation tasks landed; this review is Task 23)

## Summary

A6 is surface + observability work layered on top of A5/A5.5's wire behavior. The entire phase is either (a) additions with no mTCP analog (public timer API, per-conn RTT histogram, `resd_net_conn_rtt_histogram` getter, four new slow-path counters), (b) strict-superset improvements over mTCP (RX ENOMEM event emission, retransmit ENOMEM surfacing, event-queue soft-cap drop-oldest), or (c) intentional design divergences already documented in the spec (`FORCE_TW_SKIP` with `ts_enabled` prerequisite, split TX batching where control frames stay inline and only data-segments batch).

The only behavioral area where mTCP has an explicit `TODO` that we actually implement is RFC 7323 §5.5 24-day `TS.Recent` idle expiration (mTCP `tcp_in.c:126-127` literal comment: "TODO: ts_recent should be invalidated before timestamp wraparound for long idle flow" — we do this lazily at the PAWS gate per spec §3.7).

Zero new behavioral accepted-divergences. Zero Must-fix. Zero missed edge cases against mTCP.

## Scope comparison

Our files reviewed:
- `crates/resd-net-core/src/engine.rs` — public timer add/cancel, `close_conn_with_flags`, `reap_time_wait` force-tw-skip short-circuit, `drain_tx_pending_data`, `check_and_emit_rx_enomem`, `advance_timer_wheel` ApiPublic branch, retransmit ENOMEM Error emission, `rtt_histogram_edges` validation
- `crates/resd-net-core/src/tcp_input.rs` — PAWS lazy expiration (§3.7), WRITABLE hysteresis on ACK-prune path
- `crates/resd-net-core/src/tcp_events.rs` — new `InternalEvent::ApiTimer`, `InternalEvent::Writable` variants
- `crates/resd-net-core/src/tcp_timer_wheel.rs` — `TimerNode::user_data` field, `TimerKind::ApiPublic` variant wired
- `crates/resd-net-core/src/tcp_conn.rs` — `send_refused_pending`, `force_tw_skip`, `rtt_histogram`, `ts_recent_age`
- `crates/resd-net-core/src/rtt_histogram.rs` — 16×u32 cacheline-aligned histogram (new module)
- `crates/resd-net/src/api.rs` — `rtt_histogram_bucket_edges_us[15]`, `resd_net_tcp_rtt_histogram_t` POD
- `crates/resd-net/src/lib.rs` — `resd_net_timer_add`/`_cancel`, `resd_net_flush` body, `resd_net_close` flag plumbing, `apply_preset`, `resd_net_conn_rtt_histogram`

mTCP files referenced (for scope-comparison; no behavioral analog expected except where noted):
- `third_party/mtcp/mtcp/src/tcp_in.c:107-147` — `ValidateSequence` / PAWS; contains the `ts_recent` 24-day `TODO` comment at lines 126-127
- `third_party/mtcp/mtcp/src/tcp_stream.c:146-164` — `RaiseWriteEvent`; mTCP's edge-triggered peer-window-open WRITABLE analog
- `third_party/mtcp/mtcp/src/timer.c:450-487` — `CheckTimewaitExpire`; standard 2×MSL walk, no flag-based override
- `third_party/mtcp/mtcp/src/dpdk_module.c:315-397` — `dpdk_send_pkts`; single shared `wmbufs[]` ring, drains via `rte_eth_tx_burst` in a `do { } while (cnt > 0)` loop; no control/data split
- `third_party/mtcp/mtcp/src/core.c:677-701` — `WritePacketsToChunks`; separate `control_list`/`ack_list`/`send_list` queues all emitted per-poll (layered differently from our approach)
- `third_party/mtcp/mtcp/src/eventpoll.c` — fixed-size epoll queue; `CloseStreamSocket` with no flag parameter (no `FORCE_TW_SKIP` analog)
- `third_party/mtcp/mtcp/src/tcp_out.c:360-450` (`FlushTCPSendingBuffer`) + `tcp_out.c:137-222` (`SendTCPPacketStandalone`, `SendTCPPacket`) — send-buffer flush

Spec sections in scope: design spec §§3.1 (timer), 3.2 (flush), 3.3 (WRITABLE), 3.4 (close flag), 3.5 (preset), 3.6 (ENOMEM events), 3.7 (TS.Recent expiration), 3.8 (histogram), 4 (counter surface), 10.2 (flush/close contract wording).

## Behavioral divergences

### Accepted-by-design (no mTCP analog, intentional scope difference)

1. **Public timer API (`resd_net_timer_add` / `_cancel`) — no mTCP analog.** mTCP exposes no app-visible timer API; applications schedule their own via `mtcp_epoll_wait(timeout_ms)`. We add a first-class 10µs-resolution hashed-wheel-backed timer as `engine.rs:1676-1700` (`public_timer_add`/`_cancel`) + ABI at `resd-net/src/lib.rs:702-741`. Scope-additive; no mTCP equivalent to diverge from.

2. **Per-connection RTT histogram — no mTCP analog.** mTCP has no per-conn histogram primitive; it tracks per-stream `srtt`, `rttvar`, `rto` only. Our 16-bucket cacheline-aligned `RttHistogram` (`rtt_histogram.rs`) and `resd_net_conn_rtt_histogram` getter (`resd-net/src/lib.rs:491-512`) add a purely additive observability surface. Scope-additive; no mTCP equivalent.

3. **`RESD_NET_EVT_WRITABLE` level-triggered hysteresis at `send_buffer_bytes/2` — semantics differ from mTCP's edge-triggered `RaiseWriteEvent` on peer-window-update.** mTCP `tcp_in.c:362-370` raises `MTCP_EPOLLOUT` whenever `cwindow_prev < in_flight` AND `peer_wnd >= in_flight` — purely peer-driven, every window-opening event. Ours (`tcp_input.rs:725-732` + `engine.rs:2626-2645`) fires once per refusal cycle only when a prior `send_bytes` was short-accepted AND the ACK-prune drained in-flight to ≤ `send_buffer_bytes/2`. Different event model (our application-pull refusal bit vs. mTCP's peer-window spike), both defensible; our approach avoids WRITABLE storms during active send loops. Documented in spec §3.3.

4. **TX batching: data-only ring with control frames inline vs. mTCP's unified wmbufs.** mTCP `dpdk_module.c:375-380` drains one shared `wmbufs[ifidx]` ring via `do { ret = rte_eth_tx_burst(); pkts += ret; cnt -= ret; } while (cnt > 0)` — ACK / control / SYN / FIN / data all batch together. Ours (`engine.rs:1633-1663`) batches only data-segment mbufs on `tx_pending_data` and emits control frames (ACK, SYN, FIN, RST) inline at their emit site so ACK latency is never blocked behind a pending data flush. Documented in spec §3.2 (brainstorm option (c), latency-optimal for trading defaults). No mTCP wire-behavior divergence — both send successfully; ours optimizes ACK latency at the cost of two `rte_eth_tx_burst` calls per iteration instead of one.

5. **`resd_net_close(FORCE_TW_SKIP)` — no mTCP analog; client-side RFC-6191 analog.** mTCP `api.c:853` / `CloseStreamSocket` accepts no flags; TIME_WAIT is always 2×MSL via the `timewait_list` walk in `timer.c:453-487`. Ours (`engine.rs:3892-3921`, `reap_time_wait` short-circuit at `engine.rs:2261-2262`) honors `FORCE_TW_SKIP` only when `c.ts_enabled == true`; otherwise emits `Error{err=-EPERM}`. The client-only, PAWS-on-peer + monotonic-ISS argument is documented in spec §3.4. Scope-additive; no mTCP equivalent to diverge from.

6. **Retransmit ENOMEM → `Error{err=-ENOMEM}` event, per occurrence.** mTCP `dpdk_module.c:386-390` on wmbufs refill failure: `TRACE_ERROR` + `exit(EXIT_FAILURE)` — hard crash. Our retransmit (`engine.rs:4001-4018`, `:4080-4095`, `:4101-4113`, `:4154-4167`) emits an `InternalEvent::Error{err=-ENOMEM}` per-occurrence and continues the poll loop. Strictly superset — no behavioral divergence, just graceful degradation where mTCP aborts.

7. **RX mempool drops → edge-triggered `Error{err=-ENOMEM}` event per poll iteration.** mTCP has no equivalent surfacing; `ierrors`/`imissed` are logged via `ENABLE_STATS_IOCTL` every 1 sec (`dpdk_module.c:347`) but not delivered as events. Ours (`engine.rs:1604-1620`) snapshots `eth.rx_drop_nomem` at top of `poll_once` and emits one Error event per poll when it advanced. Scope-additive.

8. **Event-queue soft-cap with drop-oldest + counter.** Already documented in the A5.5 review as a positive addition over mTCP's `eventpoll.c:596-602` `TRACE_ERROR` + `return -1` (fail the push) model. A6 does not change this behavior; included here for completeness only.

### Problematic divergences

None.

## Must-fix (correctness divergence)

*(none — 0 items)*

## Missed edge cases (mTCP handles, we don't)

*(none — 0 items. For every A6 surface where mTCP has a comparable path, our implementation covers the same ground or more. The one mTCP-level improvement we inherit — §3.7 PAWS 24-day expiration — closes a defect mTCP explicitly flags with a TODO and does not implement.)*

## Missing-SHOULD

*(none — 0 items. This gate is scoped to mTCP comparison; RFC MUST/SHOULD coverage lives in the parallel `phase-a6-rfc-compliance.md` review.)*

## Accepted Deviations new / closed

- **New ADs:** none. A6 is surface + observability only; no new wire-behavior or RFC deviations introduced per design spec §6.
- **Closed ADs from prior phases:** none in this review. A5.5's review closed AD-15 / AD-17 / AD-18 (all retired in that phase). No further Stage-2 ADs come due in A6.
- **Notable mTCP-defect-closure:** RFC 7323 §5.5 24-day `TS.Recent` idle expiration — mTCP `tcp_in.c:126-127` explicitly has a `TODO: ts_recent should be invalidated before timestamp wraparound for long idle flow` comment and does not implement the expiration. A6 implements lazy-at-PAWS in `tcp_input.rs:562-576` (`paws_skip_this_seg` path) with `ts_recent_age` tracking in `tcp_conn.rs:159,311` and counter `tcp.ts_recent_expired`. This is noted here rather than as an AD because mTCP's behavior is the non-conformant one; implementing the expiration brings us into RFC compliance, not out of parity.

## FYI (informational — no action required)

- **I-1** — mTCP's send path (`dpdk_module.c:375-380`) drains `wmbufs[]` in a busy loop until all are sent, blocking the caller thread. Our `drain_tx_pending_data` (`engine.rs:1633-1663`) is fire-and-forget: one `rte_eth_tx_burst` call; partial-fill tail is freed and `eth.tx_drop_full_ring` is bumped. The rationale is that re-trying on a backpressured NIC adds latency with no throughput benefit at our ≤100-conn Stage 1 scale — the drop is the signal, and the next poll iteration resolves it. Not a divergence; stylistic preference documented in our `feedback_performance_first_flow_control.md` (don't throttle, surface pressure).
- **I-2** — mTCP's PAWS path (`tcp_in.c:135-141`) always updates `ts_recent` on any valid-TS segment, and also tracks `ts_last_ts_upd` for diagnostic rate logging. Our `ts_recent` update (`tcp_input.rs:582-585`) is gated by RFC 7323 §4.3 MUST-25 `seq <= rcv_nxt`, which mTCP's code does not apply — a subtle mTCP RFC deviation that we do not mirror. This is not a finding for this review because we do not diverge *from mTCP in a way that costs correctness* — we diverge in the direction of RFC compliance, the inverse of a Must-fix. Noted here so future A6.x work doesn't accidentally relax our gate to match mTCP.
- **I-3** — mTCP's `timewait_list` reaper (`timer.c:453-487`) uses a sorted TAILQ in `ts_tw_expire` order and breaks out of the scan as soon as it hits an unexpired entry (`break` at line 476). Our `reap_time_wait` (`engine.rs:2244-2308`) does a full O(N) scan per poll iteration — the 2×MSL + `force_tw_skip` predicate is evaluated per entry, no sort optimization. At our ≤100-conn Stage 1 cap (spec §1) this is acceptable (≤100 comparisons per poll). If connection counts grow, the mTCP approach is worth revisiting post-Stage 1; flagging for the roadmap, not a current finding.
- **I-4** — mTCP has no TLP, no RACK, no SACK-scoreboard — all A5/A5.5 territory confirmed in the prior mTCP reviews. A6 doesn't add or modify any of these; the observation stands.
- **I-5** — mTCP has no per-conn histogram surface; adding one would require either (a) a socket-level getter (their `mtcp_socket_getopt` pattern, blocking-socket style) or (b) a per-stream ring surfaced via `tcp_stream_t`. Neither exists. Our cacheline-aligned `RttHistogram` on `TcpConn` + `resd_net_conn_rtt_histogram` getter is a net-additive Stage 1 primitive with no mTCP equivalent.
- **I-6** — mTCP's `rte_pktmbuf_alloc` failure path in `dpdk_send_pkts` / `dpdk_init_wmbufs` (`dpdk_module.c:258-262, :386-390`) calls `exit(EXIT_FAILURE)`. Our retransmit ENOMEM path (`engine.rs:4001-4017`, plus two more sites in the retransmit function) and our RX mempool drop surfacing (`engine.rs:1604-1620`) both degrade gracefully with observability, never crash. Strictly superset vs. mTCP.

## Conclusion

**PASS** — gate clean.

- Must-fix: 0
- Missed edge cases: 0
- Missing SHOULD: 0
- New ADs: 0
- AD retirements recorded: 0 (none came due in A6; A5.5 closed the outstanding Stage-2 ADs)

No open `[ ]` checkboxes in Must-fix / Missed-edge-cases / Missing-SHOULD. The `phase-a6-complete` tag is not blocked by this review.

A6 introduced no behavioral divergences from mTCP — the phase is entirely surface + observability layered on A5/A5.5 wire behavior. Seven additions lack any mTCP analog (public timer API, per-conn RTT histogram, `resd_net_conn_rtt_histogram`, `FORCE_TW_SKIP`, RX-ENOMEM events, retransmit-ENOMEM events, event-queue drop-oldest) — all scope-additive, all rationales documented in the A6 design spec. One net-positive behavioral addition (RFC 7323 §5.5 24-day `TS.Recent` expiration) closes a defect mTCP marks with an explicit TODO but does not implement; the report notes this as a mTCP-defect-closure rather than an AD.
