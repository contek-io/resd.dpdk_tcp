# resd.dpdk_tcp Stage 1 — Phase Roadmap

**What this document is:** A living roadmap for Stage 1 implementation, decomposed into sequential phases. Each phase produces testable software and ships independently. Each phase gets its own plan file (`YYYY-MM-DD-stage1-phase-aN-<slug>.md`) with bite-sized tasks.

**How to use it:** Before starting a phase session, read this roadmap to get cold-start context, then read the per-phase plan file for task-level detail. After a phase ships, update the "Status" column and drop a link to the next plan file.

**Spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`

---

## Phase Status

| Phase | Slug | Status | Plan file |
|---|---|---|---|
| A1 | Workspace skeleton + DPDK init + empty engine | **Complete** ✓ | `2026-04-17-stage1-phase-a1-skeleton.md` |
| A2 | L2/L3 + static ARP + ICMP-in (PMTUD) | **Complete** ✓ | `2026-04-17-stage1-phase-a2-l2-l3.md` |
| A3 | TCP handshake + basic data transfer | **Complete** ✓ | `2026-04-18-stage1-phase-a3-tcp-basic.md` |
| A4 | TCP options + PAWS + reassembly + SACK scoreboard | Not started | — |
| A5 | RACK-TLP + RTO + retransmit + ISS | Not started | — |
| A6 | Public API surface completeness | Not started | — |
| A7 | Loopback test server + packetdrill-shim | Not started | — |
| A8 | tcpreq + observability gate | Not started | — |
| A9 | TCP-Fuzz differential + smoltcp FaultInjector | Not started | — |
| A10 | Benchmark harness (micro + e2e + stress) | Not started | — |
| A11 | Stage 1 ship gate verification | Not started | — |

---

## A1 — Workspace skeleton + DPDK init + empty engine

**Goal:** Bring repo from empty to a compiling Rust workspace + C++ consumer that creates an Engine, brings up DPDK EAL and NIC queues, allocates mempools, calibrates TSC, runs a `poll_once` that rx-bursts and drops everything.

**Spec refs:** §2, §2.2, §4 (lifecycle subset), §7.1, §7.5, §9.1.

**Deliverables:**
- Cargo workspace with `resd-net-sys` (DPDK FFI), `resd-net-core` (internals), `resd-net` (public C ABI).
- `include/resd_net.h` auto-generated via cbindgen.
- C++ consumer sample that creates + destroys an engine.
- CI: build + unit tests + header drift + C++ build + clippy + rustfmt.
- Integration test proving lifecycle over DPDK TAP.

**Does NOT include:** packet parsing, ARP, ICMP, TCP, connect, send, recv events, timers beyond `now_ns`, real mempool exhaustion paths.

**Dependencies:** none.

**Rough scale:** 14 tasks.

---

## A2 — L2/L3 + static ARP + ICMP-in (PMTUD)

**Goal:** Stack decodes incoming Ethernet + IPv4 packets from the RX burst. Non-TCP drops with counter. ARP/gateway-MAC resolved at engine setup via netlink helper. ICMP frag-needed updates PMTU; other ICMP dropped silently.

**Spec refs:** §5.1 (RX up through ip_decode), §6.3 RFC matrix rows for 791/792/1122/1191, §8 (ARP bullet).

**Deliverables:**
- `l2.rs` decodes Ethernet headers; verifies dst MAC equals our MAC; drops broadcast/multicast except ARP reply for gateway.
- `l3_ip.rs` decodes IPv4; verifies checksum (or trusts NIC flag); drops non-TCP/ICMP.
- `arp.rs` holds a static gateway-MAC table, populated via a one-shot netlink lookup at `engine_create`; gratuitous-ARP refresh timer every N seconds.
- ICMP frag-needed is parsed and its inner MTU value updates a PMTU state (per-peer IP).
- Counters in the `ip` group wired.
- Integration test that sends crafted Ethernet frames through a TAP pair and asserts counters.

**Does NOT include:** TCP input (routes to a stub `tcp_input` that just increments a counter), egress IP path (that's part of A3), DNS.

**Dependencies:** A1.

**Rough scale:** ~15 tasks.

---

## A3 — TCP handshake + basic data transfer

**Goal:** `resd_net_connect` to a remote peer, complete the SYN/SYN-ACK/ACK handshake, send and receive bytes, clean close (FIN/FIN-ACK). No TCP options beyond MSS yet, no reassembly, no SACK, no RACK, no retransmit.

**Spec refs:** §4 (`resd_net_connect`, `resd_net_send`, `RESD_NET_EVT_CONNECTED`, `RESD_NET_EVT_READABLE`, `RESD_NET_EVT_CLOSED`), §5.2 TX call chain, §6.1 FSM, §6.2 `TcpConn` struct (minimum fields for basic ops), §6.5 ISS (stub first — A5 finalizes).

**Deliverables:**
- `tcp/conn.rs` — `TcpConn` struct, minimum fields (sequence space, state, recv_queue, snd_retrans).
- `tcp/fsm.rs` — state machine for client side: CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → ... → CLOSED.
- `tcp/input.rs` — basic segment processing: SYN-ACK handling, ACK handling, data ingress → `recv_queue`.
- `tcp/output.rs` — SYN emission, ACK emission, data segmentation (MSS-sized chunks).
- Flow table (`flow_table.rs`) — 4-tuple hash lookup with a small pre-warmed array.
- `engine.rs` wires the TCP path into the poll loop; emits `RESD_NET_EVT_CONNECTED`, `RESD_NET_EVT_READABLE`, `RESD_NET_EVT_CLOSED`.
- `resd_net_connect` / `resd_net_send` / `resd_net_close` extern "C" functions implemented end-to-end.
- Integration test: connect to a netcat listener over a TAP pair, send + receive known bytes, close cleanly.

**Does NOT include:** TCP options beyond MSS, PAWS, SACK, retransmit, out-of-order reassembly, `WRITABLE` event (punt to A6), `FORCE_TW_SKIP`, TIME_WAIT short-circuit.

**Dependencies:** A1, A2.

**Rough scale:** ~25 tasks.

---

## A4 — TCP options + PAWS + reassembly + SACK scoreboard

**Goal:** Negotiate TCP options at handshake (window scale, timestamps, SACK-permitted, MSS). Honor PAWS (RFC 7323) to drop old-incarnation segments. Reassemble out-of-order segments via linked-mbuf-chain hole-filling. Track SACK blocks (RFC 2018) for the send side.

**Spec refs:** §6.2 (`ws_shift_*`, `ts_enabled`, `sack_enabled`), §6.3 matrix rows for 7323/2018/6691, §7.2 `recv_reorder`.

**Deliverables:**
- `tcp/options.rs` — TCP options encode/decode for MSS, WS, SACK-permitted, Timestamps.
- Handshake wires up negotiated options on both sides.
- `tcp/sack.rs` — SACK scoreboard struct + update rules.
- `tcp/reassembly.rs` — out-of-order segment list, merges into `recv_queue` as gaps close.
- PAWS check on input; stale segments dropped with counter.
- Segments emitted include TSecr + TSval; scaled windows in TCP header.
- Integration tests: out-of-order delivery, SACK-block encoding/decoding, PAWS rejection of replayed segment.

**Does NOT include:** retransmit (A5), RACK, congestion control.

**Dependencies:** A3.

**Rough scale:** ~20 tasks.

---

## A5 — RACK-TLP + RTO + retransmit + ISS

**Goal:** Loss detection via RACK-TLP (RFC 8985) as primary path; RFC 6298 RTO computation + retransmit timer; final RFC 6528 ISS recipe; RTO-driven retransmit with fresh-header-mbuf policy (no in-place edit).

**Spec refs:** §6.3 matrix rows for 6298/8985/6528, §6.5 (ISS formula, retransmit mbuf policy, lazy RTO re-arm), §7.4 (timer wheel for RTO/TLP scheduling).

**Deliverables:**
- `tcp/rack.rs` — RACK state + reorder-detection.
- `tcp/rto.rs` — SRTT/RTTVAR/RTO computation per RFC 6298; minRTO configurable.
- `tcp/iss.rs` — full SipHash-based ISS with boot_nonce + monotonic clock.
- Retransmit path: allocates fresh header mbuf from `tx_hdr_mempool`, chains to original data mbuf, never edits original in place.
- Lazy RTO timer re-arm (no remove+insert on every ACK).
- `RESD_NET_EVT_TCP_RETRANS` / `RESD_NET_EVT_TCP_LOSS_DETECTED` events emitted (gated by `tcp_per_packet_events`).
- Integration tests: loss-induced retransmit, RACK reorder detection, TLP probe firing, ISS monotonicity across reconnects.

**Does NOT include:** congestion control (off by default; Reno arrives in a dedicated follow-up if needed), ECN (separate flag, no delivery in Stage 1 gates).

**Dependencies:** A4.

**Rough scale:** ~20 tasks.

---

## A6 — Public API surface completeness

**Goal:** Finalize the public C ABI per §4: `resd_net_flush` actually flushes, `WRITABLE` events on send-buffer drain, timer API (`timer_add`/`cancel` + `TIMER` event), `resd_net_close(flags)` with `FORCE_TW_SKIP` + RFC 6191 guard, poll event-overflow queueing, mempool exhaustion error paths, `preset=rfc_compliance` runtime switch.

**Spec refs:** §4, §4.2 contracts, §6.5 TIME_WAIT shortening, §7.4 timer wheel + per-conn timer list + tombstone cancel, §9.3 error events.

**Deliverables:**
- Timer wheel implemented (hashed, 8 levels × 256 buckets, 10µs resolution).
- Per-conn timer list for O(k) cancel on close.
- `resd_net_timer_add` / `resd_net_timer_cancel` / `TIMER` event plumbed through.
- `resd_net_flush` drains TX batch via exactly one `rte_eth_tx_burst`.
- Send-buffer backpressure: `resd_net_send` returns partial; `RESD_NET_EVT_WRITABLE` on drain.
- `resd_net_close` accepts flags bitmask; `FORCE_TW_SKIP` honored only under RFC 6191 §4.2 conditions, otherwise emits `RESD_NET_EVT_ERROR{err=EPERM_TW_REQUIRED}`.
- Engine event queue with FIFO overflow semantics documented in §4.2.
- `preset` field on `engine_config` switches defaults (nagle on, delayed-ACK on, min_rto=200, initial_rto=1000, cc_mode=reno).
- Integration tests for each API contract edge case.

**Does NOT include:** test suite harnesses (those are A7/A8/A9).

**Dependencies:** A5.

**Rough scale:** ~20 tasks.

---

## A7 — Loopback test server + packetdrill-shim

**Goal:** Server-mode cargo feature `test-server` (accept on listening port, byte-stream echo). Luna-pattern packetdrill-shim that links `libresd_net` + socket-shim wrapper and runs curated packetdrill scripts.

**Spec refs:** §10.2, §10.12, §11 test-only loopback server is in scope.

**Deliverables:**
- `resd-net-testserver` crate behind feature flag `test-server`: implements `LISTEN` / `SYN-RECEIVED` / `ESTABLISHED` server path + byte-stream echo.
- `tools/packetdrill-shim/` — links `libresd_net.a`, redirects packetdrill's TUN read/write to stack rx/tx hooks, implements synchronous socket-shim wrapper for `connect`/`write`/`read`/`close`.
- `tools/packetdrill-shim/SKIPPED.md` enumerates untranslatable scripts (anything using `SIGIO`, `FIONREAD`, `SO_RCVLOWAT`, `MSG_PEEK`, delayed-ACK timing).
- Vendored or forked packetdrill in `third_party/packetdrill/`.
- CI job that runs the runnable subset of ligurio + shivansh + google/packetdrill corpora.
- Pass rate target: 100% on runnable TCP FSM scripts.

**Does NOT include:** tcpreq (A8), TCP-Fuzz (A9).

**Dependencies:** A6 (needs full API surface).

**Rough scale:** ~15 tasks (+ vendoring effort).

---

## A8 — tcpreq + observability gate

**Goal:** RFC 793bis MUST/SHOULD checklist via tcpreq, pointed at the loopback test server. Exact-counter observability smoke test as the Stage 1 gate.

**Spec refs:** §10.3, §10.10 Stage 1 ship criteria.

**Deliverables:**
- `tools/tcpreq-runner/` — wraps tcpreq against the loopback test server, parses output, emits a pass/fail table aligned to RFC 9293 requirement IDs.
- CI job that runs tcpreq MUST rules and fails on any deviation.
- Observability smoke test: a controlled scenario (N retransmits, M state transitions, K sends) asserts exact counter values and event order/count.

**Dependencies:** A7.

**Rough scale:** ~8 tasks.

---

## A9 — TCP-Fuzz differential + smoltcp FaultInjector

**Goal:** Differential fuzzing vs Linux TCP (in RFC-compliance-preset mode). Port smoltcp's `FaultInjector` pattern as a stackable RX middleware for local soak testing.

**Spec refs:** §10.5, §10.6.

**Deliverables:**
- `tools/tcp-fuzz-differential/` — TCP-Fuzz driver configured to run `libresd_net` in `preset=rfc_compliance` against Linux TCP as oracle.
- Regression-fuzz track: same inputs compared across `resd_net` releases.
- CI smoke run per merge; 72h continuous run on a dedicated box per stage cut.
- `FaultInjector` RX middleware — random drop/duplicate/reorder/corrupt with configurable rates, enabled via env var.
- Property tests (proptest) for TCP options encode/decode and reassembly invariants.
- cargo-fuzz targets: `tcp_input` with random pre-established state; IP/TCP header parser.
- Scapy-based adversarial test corpus for overlapping segments, malformed options, timestamp wraparound.

**Dependencies:** A6.

**Rough scale:** ~15 tasks.

---

## A10 — Benchmark harness (micro + e2e + stress)

**Goal:** Implement the §11 benchmark plan: microbenchmarks with order-of-magnitude targets, end-to-end RTT with HW-timestamp attribution, stability benchmarks under netem, comparative vs Linux in RFC-compliance preset. CI per-commit regression tracking.

**Spec refs:** §11 entire.

**Deliverables:**
- `tools/bench-micro/` — cargo-criterion harness for poll-empty, TSC read (FFI + inline), flow lookup hot/cold, `tcp_input` in/out-of-order, `send` small/chain, timer add/cancel, counters read.
- `tools/bench-e2e/` — request/response RTT harness with HW-timestamp attribution buckets and per-measurement sum-identity assertion.
- `tools/bench-stress/` — netem + FaultInjector scenario runner for §11.4 matrix.
- `tools/bench-vs-linux/` — dual-stack comparison with tap-jitter baseline subtraction.
- `tools/bench-report/` — CSV → dashboard feed.
- CI: cargo-criterion per commit with 5% regression gate; nightly e2e on dedicated host.
- Measurement-discipline precondition check script: `isolcpus`, `nohz_full`, governor, TSC invariant, thermal-throttle detection.

**Dependencies:** A6 (full API needed for meaningful e2e), A9 (FaultInjector used by bench-stress).

**Rough scale:** ~15 tasks.

---

## A11 — Stage 1 ship gate verification

**Goal:** Run every Stage 1 gate from spec §10.10 and §11.9. Publish the results as the Stage 1 ship artifact.

**Spec refs:** §10.10, §11.9.

**Deliverables:**
- Documented pass matrix: Layer A unit tests (100%), Layer B packetdrill runnable subset (100%), Layer C tcpreq MUST rules (100%), observability smoke, e2e smoke against chosen test peer (§13 nice-to-have resolved), §11 microbench targets met, §11.3 e2e p999 within documented bound of HW RTT, §11.4 stress matrix all green.
- `docs/superpowers/reports/stage1-ship-report.md` — signed off with commit SHAs and host/NIC/DPDK versions.
- Tagged release: `stage-1-ship`.

**Dependencies:** A1–A10 all complete.

**Rough scale:** ~5 tasks (mostly verification + reporting).

---

## Cross-phase process notes

- Each per-phase plan file gets its date-prefixed name: `YYYY-MM-DD-stage1-phase-aN-<slug>.md`. Prefix with the date the plan is written, not the phase number.
- **Phase review gates** before the `phase-aN-complete` tag:
  1. **mTCP comparison review (A2 onward, spec §10.13)** — dispatch `mtcp-comparison-reviewer` (`.claude/agents/mtcp-comparison-reviewer.md`); subagent writes `docs/superpowers/reviews/phase-aN-mtcp-compare.md`; human edits Accepted-divergence + verdict. First phase to run the review (A2) added `third_party/mtcp` as a one-time submodule prerequisite.
  2. **RFC compliance review (A3 onward, spec §10.14)** — dispatch `rfc-compliance-reviewer` (`.claude/agents/rfc-compliance-reviewer.md`); subagent writes `docs/superpowers/reviews/phase-aN-rfc-compliance.md`; human edits Accepted-deviation + verdict. One-time prerequisite: `scripts/fetch-rfcs.sh` has already vendored RFC text under `docs/rfcs/`. A2 is exempt because this gate was added after A2 shipped; optionally run a retroactive A2 RFC review at A3 kickoff.

  The tag is blocked while either applicable report has any unresolved `[ ]` item in its Must-fix / Missed-edge-cases / Missing-SHOULD sections.
- After a phase ships, tag: `git tag -a phase-aN-complete -m "Phase AN: <title>"`.
- Update the "Status" column in this file when a phase starts (→ In progress) or ships (→ Complete, link the plan file if not already there).
- The spec at `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` is the single source of truth for what Stage 1 actually needs. If a phase reveals a spec gap or contradiction, amend the spec first (in a separate commit), then the plan.
