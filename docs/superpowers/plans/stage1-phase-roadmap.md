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
| A12 | Documentation (user + maintainer + future-work) + Stage 1 release tag | Not started | — |

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

- **Counter additions (all slow-path per spec §9.1.1 — fire only on error / rare lifecycle / pathological paths; no measurable hot-path impact):**

  A4-scope counters (PAWS, options, reassembly, SACK — fire on their feature's specific paths):
  - `rx_paws_rejected` — PAWS check dropped a stale-timestamp segment (RFC 7323).
  - `rx_bad_option` — malformed TCP option on input (option decoder rejected).
  - `rx_reassembly_queued` — OOO segment placed on the reassembly list (fires only on reorder / loss).
  - `rx_reassembly_hole_filled` — gap closed, in-order data merged into recv queue.
  - `tx_sack_blocks` — SACK blocks encoded in an outbound ACK (fires only when we have recv-side gaps).
  - `rx_sack_blocks` — SACK blocks decoded from a peer ACK (fires only on peer-side loss).

  Cross-phase slow-path additions that fit naturally in A4's increment-site scope (backfill what A3 didn't cover + things A4's new paths pass through anyway):
  - `rx_bad_seq` — segment with seq outside `rcv_wnd`; silently dropped prior to this counter.
  - `rx_bad_ack` — ACK acking nothing new or acking future data; previously silent.
  - `rx_dup_ack` — duplicate ACK (baseline for A5 fast-retransmit consumer).
  - `rx_zero_window` — peer advertised `rwnd=0`; critical trading signal ("the exchange is slow").
  - `rx_urgent_dropped` — URG flag segment; Stage 1 doesn't support URG, dropped.
  - `tx_zero_window` — we advertised `rwnd=0` (our recv buffer full).
  - `tx_window_update` — we emitted a pure window-update segment.
  - `conn_time_wait_reaped` — TIME_WAIT deadline expired, connection reclaimed (A3's reaper has no counter).
  - `conn_table_full` — `resd_net_connect` rejected because flow table at `max_connections`.

  Explicitly **not** in A4 scope (owned by later phases — included here only as a note so nobody re-proposes them as A4 work):
  - `events_dropped_queue_full` / `events_error_enomem` / `events_error_eperm_tw_required` — per-engine event FIFO + `RESD_NET_EVT_ERROR` emissions (**A6**: depends on A6's real event-queue overflow semantics, `ENOMEM` mempool-exhaustion path, `FORCE_TW_SKIP` + RFC 6191 guard).
  - `conn_timeout_syn_sent` — SYN_SENT timeout (**A5**: depends on A5's real RTO timer + `connect_timeout_ms` enforcement).

  All of the above A4-scope increments live in existing slow-path sites (error branches, rare-event handlers, per-connection lifecycle). None are on the per-segment or per-poll hot path. A8 counter-coverage audit adds scenarios for each so zero fields stay unreachable.

- **Hot-path counters — compile-time gated per spec §9.1.1** (fields always allocated in the struct for C-ABI stability; `#[cfg(feature = ...)]` applies to the increment sites only):

  - `tcp.tx_payload_bytes` / `tcp.rx_payload_bytes` — gated by cargo feature `obs-byte-counters`, **default OFF**.
    - *Answers*: "how many TCP payload bytes did this engine move?" without the L2/L3 overhead baked into `eth.tx_bytes` / `rx_bytes`. Trading use case: separating market-data bytes consumed from order bytes emitted.
    - *Not derivable* from existing counters — `tx_data × MSS` is a guess since segments may carry less than MSS.
    - *Increment pattern*: per-burst, never per-segment. Stack-local `u64` accumulator inside the TX-burst loop / RX poll loop, single `add(&counter, burst_bytes)` after the burst drains. Doc the pattern at the increment site; reviewers reject per-segment variants.
    - *Turn on* with `--features obs-byte-counters` at build time.

  - `poll.iters_with_rx_burst_max` — gated by cargo feature `obs-poll-saturation`, **default ON** (listed in `[features] default`).
    - *Answers*: "is RX falling behind?" — increments on every poll iteration where `rx_burst` returned `max_burst` elements, meaning the NIC probably had more packets queued than we pulled. No other counter surfaces this.
    - *Not derivable* from `iters_with_rx` + `rx_pkts` — those give average burst size, not saturation frequency.
    - *Increment pattern*: single `if burst_size == max_burst { inc(counter); }` already inside the existing `iters_with_rx` branch. One extra comparison + conditional `fetch_add` per poll.
    - *Turn off* with `cargo build --no-default-features` (plus re-listing any other default features you want to keep) for absolute-minimum-overhead builds.

  Both flags live in `crates/resd-net-core/Cargo.toml` under `[features]`. The C header (`include/resd_net.h`) is regenerated without `#[cfg]` gating on the struct itself, so `resd_net_counters_t` layout is stable across feature sets — feature-off builds just leave the corresponding fields at zero. `docs/user-guide/04-configuration.md` (A12) documents the flags and their trade-offs; `docs/maintainer-guide/14-coding-conventions.md` enforces the inline-justification rule for any future hot-path counter additions.

**Does NOT include:** retransmit (A5), RACK, congestion control. Checksum-path split counters (`tx_csum_offload_used` / `_soft`) intentionally **not** added — one-shot startup log of the negotiated csum path is sufficient; runtime counters aren't worth the per-segment cost given offload state doesn't hot-swap.

**Dependencies:** A3.

**Rough scale:** ~25 tasks (+2 for the hot-path counters: feature-flag wiring + batched-increment sites; +3 for the slow-path counter batch: struct extension + layout assertion, slow-path increment sites, A8-audit scenario entries).

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
- **Counter-coverage audit** (catches declared-but-never-incremented fields; honours spec §9.1.1 counter-addition policy):
  - Static check: parse every `AtomicU64` field in `EthCounters` / `IpCounters` / `TcpCounters` / `PollCounters` and every `fetch_add` / `inc` / `add` call site; fail if any declared field has zero write sites in the crate.
  - **Explicit-deferred whitelist**: counters intentionally reserved for a later phase (currently `tx_retrans` / `tx_rto` / `tx_tlp` / `conn_rst` / `rx_out_of_order` — see `deferred_tcp_counters_zero_at_construction` in `counters.rs`) live in `tests/deferred-counters.txt` with a spec citation; static check ignores them.
  - **Feature-gated counters**: per §9.1.1, hot-path counters may live behind a cargo feature flag (default off). The audit runs twice — once with `--no-default-features` and once with `--all-features` — and each declared counter must be reachable in at least one of the two runs. Feature-gated counters outside the default build must be listed in `tests/feature-gated-counters.txt` with the flag name.
  - Dynamic check: for every counter, the test suite must include at least one scenario that drives it nonzero. Implemented as a table of (counter_name, scenario_fn) with a test that runs each scenario on a fresh engine and asserts the named counter ended > 0. Missing entries fail the audit.
  - `state_trans[from][to]`: every transition edge listed in spec §6.1 FSM must have a scenario that exercises it; unreachable edges are listed in an expected-unused file with a justification, reviewed at each phase sign-off.

**Dependencies:** A7.

**Rough scale:** ~10 tasks (+2 for the counter-coverage audit: static-check script + dynamic-scenario table).

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

## A10 — Benchmark harness (micro + e2e + stress + comparators)

**Goal:** Implement the §11 benchmark plan: microbenchmarks with order-of-magnitude targets, end-to-end RTT with HW-timestamp attribution, stability benchmarks under netem, comparative vs Linux in RFC-compliance preset, comparative vs mTCP on the burst-edge / long-connection workload. CI per-commit regression tracking.

**Spec refs:** §11 entire (§11.5.1 added for the mTCP comparator).

**Deliverables:**
- `tools/bench-micro/` — cargo-criterion harness for poll-empty, TSC read (FFI + inline), flow lookup hot/cold, `tcp_input` in/out-of-order, `send` small/chain, timer add/cancel, counters read.
- `tools/bench-e2e/` — request/response RTT harness with HW-timestamp attribution buckets and per-measurement sum-identity assertion.
- `tools/bench-stress/` — netem + FaultInjector scenario runner for §11.4 matrix.
- `tools/bench-vs-linux/` — dual-stack comparison vs Linux TCP with tap-jitter baseline subtraction.
- `tools/bench-vs-mtcp/` — dual-stack comparison vs mTCP, two sub-workloads:
  - `burst` (spec §11.5.1): K × G grid = 20 buckets. Burst size K ∈ {64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB}; idle gap G ∈ {0 ms, 1 ms, 10 ms, 100 ms}. Measurement: `t0` = inline TSC pre-send; `t1` = NIC HW TX timestamp on last segment of burst; per-burst throughput = K / (t1 − t0); aggregate p50/p99/p999 across ≥10k bursts/bucket. Secondary decomposition into initiation (spin-up) vs steady-state.
  - `maxtp` (spec §11.5.2): W × C grid = 28 buckets. Write size W ∈ {64 B, 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB}; connection count C ∈ {1, 4, 16, 64}. 60 s sustained pump per bucket post-warmup. Metrics: goodput (bytes/sec) and packet rate (pps) per (W, C).
  - Shared: kernel-side TCP sink as peer (reuses `bench-vs-linux` peer); `cc_mode=off`; pre-run checks (receive window, NIC headroom ≤70%, measurement-discipline); sanity invariants on TX-byte counters. mTCP built from `third_party/mtcp/` (already submoduled for the §10.13 review gate). CSV schema matches `bench-vs-linux` so `bench-report` handles all three.
- `tools/bench-report/` — CSV → dashboard feed.
- CI: cargo-criterion per commit with 5% regression gate; nightly e2e on dedicated host (includes `bench-vs-mtcp`).
- Measurement-discipline precondition check script: `isolcpus`, `nohz_full`, governor, TSC invariant, thermal-throttle detection.

**Dependencies:** A6 (full API needed for meaningful e2e), A9 (FaultInjector used by bench-stress). `third_party/mtcp` already present from the A2 review-gate setup — no new submodule work.

**Rough scale:** ~21 tasks (+6 for the mTCP comparator: build integration, peer wiring, `burst` grid runner, `maxtp` grid runner, measurement-contract harness with HW TX timestamps + TSC, result/CSV plumbing).

---

## A11 — Stage 1 ship gate verification

**Goal:** Run every Stage 1 gate from spec §10.10 and §11.9. Publish the results as the Stage 1 ship artifact.

**Spec refs:** §10.10, §11.9.

**Deliverables:**
- Documented pass matrix: Layer A unit tests (100%), Layer B packetdrill runnable subset (100%), Layer C tcpreq MUST rules (100%), observability smoke, e2e smoke against chosen test peer (§13 nice-to-have resolved), §11 microbench targets met, §11.3 e2e p999 within documented bound of HW RTT, §11.4 stress matrix all green.
- `docs/superpowers/reports/stage1-ship-report.md` — signed off with commit SHAs and host/NIC/DPDK versions.

**Does NOT include:** the `stage-1-ship` git tag — that moves to A12 after documentation lands.

**Dependencies:** A1–A10 all complete.

**Rough scale:** ~5 tasks (mostly verification + reporting).

---

## A12 — Documentation (user + maintainer + future-work) + Stage 1 release tag

**Goal:** Ship `libresd_net` with structured documentation sufficient for (a) users to integrate and operate, (b) future maintainers to extend and fix, and (c) a durable record of considered-but-deferred work. Each audience gets its own directory tree under `docs/` with one focused markdown file per topic, linked from a directory-level index. Places the `stage-1-ship` tag at the end of this phase.

**Spec refs:** §2.1 (stage scoping), §3 (threading), §4 (public API), §5–§9 (internals), §10 (testing), §11 (benchmarks), §12 (out of scope), §13 (open questions).

**Documentation tree:**

```
docs/
├── user-guide/
│   ├── README.md                 Index + when-to-read-what
│   ├── 01-overview.md            What it does, what it deliberately doesn't, positioning vs Linux TCP and vs mTCP
│   ├── 02-build-and-link.md      DPDK 23.11 + hugepage + VFIO prereqs, cargo build, cbindgen-generated header, C++ link
│   ├── 03-lifecycle.md           EAL init → engine_create → connect → poll → send/recv events → close → engine_destroy, with sequence diagram
│   ├── 04-configuration.md       Every `resd_net_engine_config_t` field from §4, trading-latency defaults vs preset=rfc_compliance, when to use which
│   ├── 05-threading-model.md     One-engine-per-lcore, RTC, pinning contract from §3, what breaks if violated
│   ├── 06-send-and-receive.md    `resd_net_send` semantics (copy-on-accept, partial accept, backpressure), READABLE event data-ptr lifetime, WRITABLE (A6)
│   ├── 07-close-and-timewait.md  FIN flow, TIME_WAIT duration, FORCE_TW_SKIP and RFC 6191 §4.2 gating
│   ├── 08-error-handling.md      Negative-errno conventions, RESD_NET_EVT_ERROR enumeration, mempool exhaustion, peer-unreachable
│   ├── 09-counters.md            Every counter from §9.1 — meaning, expected steady-state, red-flag patterns
│   ├── 10-events.md              Every event from §9.2 — when emitted, payload semantics, ordering guarantees
│   ├── 11-limitations.md         Wire-compat subset vs Linux, RFCs not implemented (index into phase RFC reviews), TIME_WAIT, stage bounds
│   └── 12-troubleshooting.md     "No SYN-ACK", "peer window zero", "stuck in SYN_SENT", "RST on unmatched", "TIME_WAIT exhaustion" — counter-symptom driven
│
├── maintainer-guide/
│   ├── README.md                 Index + reading order for new maintainers
│   ├── 01-architecture.md        Crate layout, module responsibility map, RX/TX call-chain diagrams (§5.1 / §5.2)
│   ├── 02-hot-path-invariants.md No panic across FFI, no alloc outside mempools, no cross-lcore ring, RTC — with the test that catches each regression
│   ├── 03-state-machine.md       TcpState enum (§6.1), state-transition matrix in `counters.rs`, how to add a new transition without regressing the matrix
│   ├── 04-tcp-options.md         `tcp/options.rs` encode/decode, handshake negotiation, how to add a new option end-to-end
│   ├── 05-flow-table.md          Handle-indexed slot array + 4-tuple hash, rehash and eviction policy, sizing decisions vs mTCP's chained buckets
│   ├── 06-timer-wheel.md         §7.4 — hashed wheel layout, add/cancel cost model, tombstone-cancel pattern, per-conn list rationale
│   ├── 07-iss.md                 §6.5 — SipHash layout, RFC 6528 guarantee, boot_nonce re-seed, monotonic clock source
│   ├── 08-mempool-layout.md      §7.1 tx_hdr vs tx_data vs rx mempools, sizing, exhaustion paths
│   ├── 09-ffi-and-abi.md         cbindgen contract, `panic = abort`, extern "C" discipline, header-drift check, ABI stability rules
│   ├── 10-test-layering.md       §10 Layers A/B/C/D — which layer a new feature must extend, how to run each locally, what CI runs
│   ├── 11-benchmark-harness.md   §11 tool layout, how to add a microbench, how to avoid gaming the 5%-regression gate
│   ├── 12-review-gates.md        `mtcp-comparison-reviewer` + `rfc-compliance-reviewer` subagents — how to invoke, interpret, and unblock the phase tag
│   ├── 13-debugging-playbook.md  Counter-symptom → likely root cause, pcap capture hooks, isolating bugs across tcp_input / flow_table / engine
│   └── 14-coding-conventions.md  Rust stable policy, clippy/rustfmt rules, error.rs variant discipline, `unsafe` + SAFETY-block policy, commit style
│
└── future-work/
    ├── README.md                 Index + policy on what lives here vs tickets vs code comments
    ├── 01-mtcp-divergences.md    Consolidated Accepted-divergence from every phase-aN-mtcp-compare review, with spec-§ citations
    ├── 02-rfc-deviations.md      Consolidated Accepted-deviation from every phase-aN-rfc-compliance review, with spec-§6.4 citations
    ├── 03-later-stages.md        Stage 2 hardening / 3 HTTP / 4 TLS / 5 WebSocket — with the flip-to-scoped criteria per stage
    ├── 04-out-of-scope.md        §12 classified: permanent-no (e.g., permessage-deflate) vs maybe-later (IPv6, TCP Fast Open, dynamic ARP)
    ├── 05-open-questions.md      §13 still-open at ship, with the decision path each would need
    ├── 06-codebase-todos.md      Regenerated by `scripts/audit-todos.sh` from TODO/FIXME/XXX markers, with a stated retention policy
    ├── 07-perf-opportunities.md  Mbuf pinning vs per-conn last_read_buf copy, lazy-vs-eager RTO re-arm, SACK-scoreboard layout, timer-wheel resolution
    └── 08-observability-gaps.md  Counters/events that would be valuable but didn't ship in Stage 1, with the use case motivating each
```

**Per-directory conventions:**
- Each `README.md` is an index with a one-line summary per section + a "read these first if you're new" ordering.
- Numeric `NN-slug.md` prefixes give intentional reading order while staying grep-friendly; numbers jump by 1 so renames are cheap.
- Cross-links use relative paths (`../user-guide/04-configuration.md`) so the tree stays movable.
- Every page opens with an "Audience" line and a "Prerequisites" line pointing at earlier sections, so cold-start readers aren't lost.

**Deliverables — supporting:**
- `README.md` (repo root) refresh: one-paragraph positioning + pointers to the three index READMEs.
- `CHANGELOG.md` baseline entry for the Stage 1 release (references the tag).
- `scripts/audit-todos.sh` — regenerates `docs/future-work/06-codebase-todos.md` from `TODO` / `FIXME` / `XXX` markers so refreshes are deterministic; runs in CI and fails if the committed file is stale.
- **Tag:** `git tag -a stage-1-ship -m "Stage 1 ship"` at tip of this phase (moved here from A11).

**Does NOT include:** per-function docstrings (written in source as code lands); generated Rust API docs from `cargo doc` (already in CI); generated C header docs (cbindgen already annotates).

**Dependencies:** A11 complete (ship report is the source for several sections in `future-work/`).

**Rough scale:** ~12 tasks — 3 for the user-guide tree (index + 12 sections grouped into ~3 commits by theme: overview/build/lifecycle, config/threading/send-recv/close, errors/counters/events/limitations/troubleshooting), 4 for the maintainer-guide tree (architecture+invariants, state+options+flow+timers+iss+mempool, ffi+tests+bench, reviews+debugging+conventions), 2 for the future-work tree (reviews-consolidation + remainder), 1 for the TODO-audit script, 1 for root README+CHANGELOG refresh, 1 for the tag.

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
