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
| A4 | TCP options + PAWS + reassembly + SACK scoreboard | **Complete** ✓ | `2026-04-18-stage1-phase-a4-options-paws-reassembly-sack.md` |
| A5 | RACK-TLP + RTO + retransmit + ISS | **Complete** ✓ | `2026-04-18-stage1-phase-a5-rack-rto-retransmit.md` |
| A5.5 | Event-log forensics + in-flight introspection + TLP tuning (emission-time ts, queue overflow counter, stats getter, per-conn TLP knobs) | **Complete** ✓ | `2026-04-19-stage1-phase-a5-5-event-log-forensics-tlp-tuning.md` |
| A-HW | ENA hardware offload enablement (LLQ verify + TX/RX checksum + MBUF_FAST_FREE + RSS-hash plumbing) | **Complete** ✓ | `2026-04-19-stage1-phase-a-hw-ena-offload.md` |
| A-HW+ | ENA observability + tuning knobs (WC verify + ENI xstats + per-queue xstats + large_llq_hdr / miss_txc_to knobs) | **Complete** ✓ | `2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md` |
| A6 | Public API surface completeness **+ per-connection RTT histogram** (merged from former A5.6) | **Complete** ✓ | `2026-04-19-stage1-phase-a6-public-api-completeness.md` |
| A6.5 | Hot-path allocation elimination (reusable scratch, streaming csum, SmallVec, zero-copy reassembly) | **Complete** ✓ | `phase-a6-5-complete` |
| A6.6 | RX zero-copy (scatter-gather iovec API, in-order delivery-path mbuf-ref rework, LRO-compatible multi-segment, `rx_mempool_size` knob) | **Complete** ✓[^a66fused] | `phase-a6-6-7-complete` |
| A6.7 | FFI safety audit & hardening (miri, cbindgen header-drift CI, ABI snapshot, panic-firewall test, no-alloc-on-hot-path audit, C++ consumer under ASan/UBSan/LSan) | **Complete** ✓ | `phase-a6-6-7-complete` |
| A7 | Loopback test server + packetdrill-shim | **Complete** ✓ | `2026-04-21-stage1-phase-a7-loopback-test-server-packetdrill-shim.md` |
| A8 | tcpreq + observability gate | **Complete** ✓ | `2026-04-22-stage1-phase-a8-tcpreq-observability-gate.md` |
| A9 | Property + bespoke fuzzing + smoltcp FaultInjector | **Complete** ✓ | `phase-a9-complete` |
| A10 | Benchmark harness (micro + e2e + stress) | Not started | — |
| A10.5 | Layer H correctness under WAN-condition fault injection (netem matrix) | Not started | — |
| A11 | Stage 1 ship gate verification | Not started | — |
| A12 | Documentation (user + maintainer + future-work) + Stage 1 release tag | Not started | — |
| A13 | HTTP/1.1 + TLS client integration + bench (via `contek-io/cpp_common`) | Not started | — |
| A14 | WebSocket + TLS client integration + bench (via `contek-io/cpp_common`) | Not started | — |

[^a66fused]: Shares end-of-phase tag with A6.7 per fused-execution model (spec §6 / §11 in `2026-04-20-stage1-phase-a6-6-7-fused-design.md`).

---

## A1 — Workspace skeleton + DPDK init + empty engine

**Goal:** Bring repo from empty to a compiling Rust workspace + C++ consumer that creates an Engine, brings up DPDK EAL and NIC queues, allocates mempools, calibrates TSC, runs a `poll_once` that rx-bursts and drops everything.

**Spec refs:** §2, §2.2, §4 (lifecycle subset), §7.1, §7.5, §9.1.

**Deliverables:**
- Cargo workspace with `dpdk-net-sys` (DPDK FFI), `dpdk-net-core` (internals), `dpdk-net` (public C ABI).
- `include/dpdk_net.h` auto-generated via cbindgen.
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

**Goal:** `dpdk_net_connect` to a remote peer, complete the SYN/SYN-ACK/ACK handshake, send and receive bytes, clean close (FIN/FIN-ACK). No TCP options beyond MSS yet, no reassembly, no SACK, no RACK, no retransmit.

**Spec refs:** §4 (`dpdk_net_connect`, `dpdk_net_send`, `DPDK_NET_EVT_CONNECTED`, `DPDK_NET_EVT_READABLE`, `DPDK_NET_EVT_CLOSED`), §5.2 TX call chain, §6.1 FSM, §6.2 `TcpConn` struct (minimum fields for basic ops), §6.5 ISS (stub first — A5 finalizes).

**Deliverables:**
- `tcp/conn.rs` — `TcpConn` struct, minimum fields (sequence space, state, recv_queue, snd_retrans).
- `tcp/fsm.rs` — state machine for client side: CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → ... → CLOSED.
- `tcp/input.rs` — basic segment processing: SYN-ACK handling, ACK handling, data ingress → `recv_queue`.
- `tcp/output.rs` — SYN emission, ACK emission, data segmentation (MSS-sized chunks).
- Flow table (`flow_table.rs`) — 4-tuple hash lookup with a small pre-warmed array.
- `engine.rs` wires the TCP path into the poll loop; emits `DPDK_NET_EVT_CONNECTED`, `DPDK_NET_EVT_READABLE`, `DPDK_NET_EVT_CLOSED`.
- `dpdk_net_connect` / `dpdk_net_send` / `dpdk_net_close` extern "C" functions implemented end-to-end.
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
  - `conn_table_full` — `dpdk_net_connect` rejected because flow table at `max_connections`.

  Explicitly **not** in A4 scope (owned by later phases — included here only as a note so nobody re-proposes them as A4 work):
  - `events_dropped_queue_full` / `events_error_enomem` / `events_error_eperm_tw_required` — per-engine event FIFO + `DPDK_NET_EVT_ERROR` emissions (**A6**: depends on A6's real event-queue overflow semantics, `ENOMEM` mempool-exhaustion path, `FORCE_TW_SKIP` + RFC 6191 guard).
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

  Both flags live in `crates/dpdk-net-core/Cargo.toml` under `[features]`. The C header (`include/dpdk_net.h`) is regenerated without `#[cfg]` gating on the struct itself, so `dpdk_net_counters_t` layout is stable across feature sets — feature-off builds just leave the corresponding fields at zero. `docs/user-guide/04-configuration.md` (A12) documents the flags and their trade-offs; `docs/maintainer-guide/14-coding-conventions.md` enforces the inline-justification rule for any future hot-path counter additions.

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
- `DPDK_NET_EVT_TCP_RETRANS` / `DPDK_NET_EVT_TCP_LOSS_DETECTED` events emitted (gated by `tcp_per_packet_events`).
- Integration tests: loss-induced retransmit, RACK reorder detection, TLP probe firing, ISS monotonicity across reconnects.

**Does NOT include:** congestion control (off by default; Reno arrives in a dedicated follow-up if needed), ECN (separate flag, no delivery in Stage 1 gates).

**Dependencies:** A4.

**Rough scale:** ~20 tasks.

---

## A5.5 — Event-log forensics + in-flight introspection + TLP tuning

**Numbering note:** Inserted after A5 as a focused forensics + order-entry-latency pack. Uses the decimal "A5.5" tag because the scope is genuinely downstream of A5 (extends A5's event producers, TLP module, and connect opts) and independent of both A-HW (no offload overlap) and A6 (no timer / flush / WRITABLE overlap). Can run serially after A5 or in parallel with A-HW.

**Scope widening note:** A5.5 started as observability-only; the TLP tuning knobs added after review are genuine wire-behavior changes. They're per-connection opt-in with defaults that preserve A5's RFC 8985 behavior exactly, so the phase still has zero impact on existing callers — but the §6.3/§6.4 RFC matrix needs new rows for the opt-in modes.

**Goal:** Close four gaps identified during A5 design review: (1) `enqueued_ts_ns` is currently sampled at poll-drain time rather than event-emission time (±poll-interval skew); (2) event queue is unbounded with no overflow visibility; (3) send-path state (`snd_una`/`snd_nxt`/`snd_wnd`/buffer pending+free) and RTT estimator state (`srtt_us`/`rttvar_us`/`min_rtt_us`/`rto_us`) are not readable by the application; (4) A5's TLP fires one probe at `max(2·SRTT, min_rto_us)` with the RFC 8985 `+max_ack_delay` penalty on FlightSize=1, all hard-coded — order-entry latency budgets need per-conn tuning.

**Spec refs:** §4 (public API surface addition), §4.2 (event-queue contract), §9.1 (counters), §9.3 (events).

**Deliverables:**

- `InternalEvent::emitted_ts_ns` field on every event variant, sampled at push time inside the engine (not at drain in `dpdk_net_poll`). `dpdk_net_event_t::enqueued_ts_ns` semantic tightens from "drain time" to "emission time" — field name unchanged, doc comment updated. Eliminates ±poll-interval skew (up to tens of µs at realistic poll rates) on every event's apparent time.
- `EventQueue` soft cap + drop-oldest policy on overflow. New slow-path counters `obs.events_dropped` (count of events discarded from the front) and `obs.events_queue_high_water` (latched max observed depth). New engine config field `event_queue_soft_cap` (u32, default 4096, min 64). Preserves "don't silently accumulate" without introducing head-of-line blocking on the producer side.
- New extern "C" function `dpdk_net_conn_stats(engine, conn, out) → i32` returning 9 `u32` fields: send-path (`snd_una`, `snd_nxt`, `snd_wnd`, `send_buf_bytes_pending`, `send_buf_bytes_free`) + RTT estimator (`srtt_us`, `rttvar_us`, `min_rtt_us`, `rto_us`). Enables per-order forensics tagging: "bytes in flight + current RTT + current RTO at send time." Slow-path; safe per-order, not per-segment. Pure projection — all fields already exist on `TcpConn` after A5 (send-path since A3; RTT fields from `rtt_est` and `rack.min_rtt`).
- Per-connection TLP tuning knobs (wire behavior; per-connect opt-in with defaults preserving RFC 8985). Five new `dpdk_net_connect_opts_t` fields: `tlp_pto_min_floor_us` (default inherits `tcp_min_rto_us`, range 0 .. `tcp_max_rto_us`), `tlp_pto_srtt_multiplier_x100` (default 200 = 2.0×, range 100..200 integer), `tlp_skip_flight_size_gate` (default false), `tlp_max_consecutive_probes` (default 1, range 1..5), `tlp_skip_rtt_sample_gate` (default false). Extends `tcp_tlp::pto_us` from fixed formula to `(srtt, &TlpConfig, flight_size) → u32`. Engine's TLP scheduler tracks a per-conn consecutive-probe counter that resets on every new RTT sample / newly-ACKed data. New slow-path counter `tcp.tx_tlp_spurious` incremented when DSACK confirms a prior TLP probe was unnecessary (attribution per probe via a fixed 5-entry ring on `TcpConn` with a 4·SRTT plausibility window). Spurious-ratio (`tx_tlp_spurious / tx_tlp`) is the app-side self-tuning signal — documented in A12's `13-order-entry-telemetry`.
- New `obs` counter group in `counters.rs` for engine-internal observability signals.
- Integration tests on TAP pair: emission-time correctness, overflow behavior (including that drained events are the most-recent, not the oldest), send-state getter under backpressure, `-ENOENT` on stale handle.

**Does NOT include:**
- Wire-behavior changes beyond the per-connect TLP tuning knobs listed above. Retransmit mechanics, RACK detect-lost rules, RTO formulas, congestion response, reassembly, and all other paths stay as A5 ships them.
- Event-queue-overflow events (i.e., emitting a new event on overflow) — per `feedback_observability_primitives_only.md` the counter + high-water pair is sufficient; app polls counters.
- `events_pending` live-depth gauge — intentionally deferred; revisit if A8 counter-coverage audit shows it's wanted.
- Persistent/ring-buffered event log — app owns persistence. A5.5 just keeps the in-engine FIFO honest.
- Changes to `rx_hw_ts_ns` semantics (owned by A-HW).
- WRITABLE event / timer API (owned by A6).

**Dependencies:** A5 (extends A5's event producers + `tcp_tlp.rs` + `rtt_est` + `rack.min_rtt`). **Independent of A-HW** — no shared files; can run in parallel.

**Ship gate:** `phase-a5-5-complete` tag requires (a) all integration tests green, (b) mTCP review report landed (expected no ADs for observability; TLP knobs flagged as scope-difference since mTCP does not implement TLP), (c) RFC compliance review landed (expected PASS-WITH-DEVIATIONS since the TLP knobs open 5 new §6.4 rows — all per-connect opt-in with defaults matching RFC 8985).

**Rough scale:** ~10–12 tasks. See `docs/superpowers/specs/2026-04-18-stage1-phase-a5-5-event-log-forensics-design.md` §9.

---

## A5.6 — Per-connection RTT histogram (ABSORBED INTO A6)

**Status:** Absorbed into A6 on 2026-04-19 — A5.6 did not ship as a standalone phase. All scoped content (16×u32 histogram on `TcpConn`, runtime-configurable edges, `dpdk_net_conn_rtt_histogram` getter, wraparound contract, cacheline placement, default edges) was folded into A6's design spec §3.8 and implementation plan tasks 3 (field + module), 6 (edges validation), 15 (update hook), 18 (ABI getter), 20 (ABI config field). See `docs/superpowers/specs/2026-04-19-stage1-phase-a6-public-api-completeness-design.md` and `docs/superpowers/plans/2026-04-19-stage1-phase-a6-public-api-completeness.md`. The original A5.6 design spec at `docs/superpowers/specs/2026-04-19-stage1-phase-a5-6-rtt-histogram-design.md` is retained as design-input reference only.

---

## A-HW — ENA hardware offload enablement

**Numbering note:** Inserted between A5 and A6 after the Stage 1 deployment environment was pinned down as AWS ENA on AMD EPYC Milan (spec §8.1–§8.5). Uses the non-numeric "A-HW" tag rather than renumbering A6–A12 because existing per-phase plan files (notably the in-progress A4 plan) already reference A5 / A6 / A8 / A10 by number.

**Goal:** Flip the port configuration from Phase A1's zeroed `rte_eth_conf` to the Stage 1 production-shape offload set: verify LLQ is active, enable TX+RX IPv4/TCP/UDP checksum offload, enable `MBUF_FAST_FREE`, and wire `RSS_HASH` plumbing (even on single-queue deployments) so the flow table can consume it once multi-queue lands. **Every offload is gated by a compile-time cargo feature flag** so that A10's benchmark harness can produce an on-vs-off A/B comparison per offload via rebuilds. Capability-gate every offload at runtime as well so `net_vdev` / `net_tap` test harnesses degrade to the software path even when the feature is compiled in.

**Spec refs:** §8.1–§8.5, §7.5 (dynfield lookup + inline accessor wired here), §9.2 (`rx_hw_ts_ns` plumbed end-to-end; stays 0 on ENA since ENA doesn't register the dynfield, but the code path is exercised and future-hardware-ready on mlx5 / newer-gen ENA), §11.1 (measurement-discipline preconditions reference offloads), §11.3 (TSC-only attribution fallback).

**Deliverables:**

- **Compile-time feature gates** in `crates/dpdk-net-core/Cargo.toml` — one per Tier 1 offload, all on by default:

  | Feature flag | Default | Gates |
  |---|---|---|
  | `hw-verify-llq` | ON | Engine verifies LLQ activation at EAL init via PMD log-scrape + `dev_info.default_rxportconf` / `default_txportconf` inspection; fails hard if ENA advertised LLQ capability but LLQ did not activate. The `enable_llq=X` devarg stays **application-owned** (ENA PMD default is `enable_llq=1`) — this flag controls the engine's verification discipline, not activation. With feature off, verification is skipped. See A-HW spec §5 |
  | `hw-offload-tx-cksum` | ON | TX IPv4+TCP+UDP checksum offload bits + pseudo-header-only checksum in `tcp_output.rs` / `l3_ip.rs`; with feature off, software full-fold stays on the TX path |
  | `hw-offload-rx-cksum` | ON | RX IPv4+TCP+UDP checksum offload bits + `mbuf.ol_flags` inspection in `tcp_input.rs` / `l3_ip.rs`; with feature off, software verify runs on the RX path |
  | `hw-offload-mbuf-fast-free` | ON | `RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE` bit in `txmode.offloads` |
  | `hw-offload-rss-hash` | ON | `RTE_ETH_RX_OFFLOAD_RSS_HASH` bit + `rss_conf` setup + `mbuf.hash.rss` consumption in `flow_table.rs` (SipHash fallback when feature off) |
  | `hw-offload-rx-timestamp` | ON | `rte_mbuf_dynfield_lookup("rte_dynfield_timestamp")` + `rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp")` at `engine_create`; inline RX accessor populates `event.rx_hw_ts_ns`; with feature off (or dynfield absent), accessor folds to constant 0, events carry 0, and callers fall back to `enqueued_ts_ns` per §7.5 |

  `[features]` table adds these as leaf features plus a convenience `hw-offloads-all` meta-feature that pulls in every `hw-offload-*` flag for explicit override. `default = [...all hw-offload-* flags...]`. Rebuilds with `--no-default-features --features hw-offloads-all` / `hw-offload-tx-cksum` / `<none>` / individual combinations are what A10's benchmark harness consumes to produce the A/B comparison.

  Each feature gate is placed at the **code site**, not the struct field, so the C ABI is unchanged across feature sets (same pattern as §9.1.1 for observability flags). A feature-off build compiles away the offload code path entirely; the binary is strictly smaller and does not execute any offload-path instructions.

- `engine.rs` port config upgraded:
  - Query `rte_eth_dev_info_get`; log one-line banner of `rx_offload_capa` / `tx_offload_capa` / `dev_flags`.
  - For each offload that is compile-time enabled, AND the requested bit against `dev_info.*_offload_capa`; WARN + one-shot counter per requested-but-unadvertised capability (`eth.offload_missing_<name>`); software path stays reachable (runtime capability gate per §8.5).
  - Populate `rte_eth_conf.rxmode.offloads` / `txmode.offloads` with bits that are both compile-time enabled AND runtime advertised.
  - When `hw-offload-rss-hash` is on: populate `rte_eth_conf.rx_adv_conf.rss_conf = { rss_hf: RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP, rss_key: NULL }` (NULL key → PMD default Toeplitz key); on single queue, program the RSS indirection table so every hash lands on queue 0.
- LLQ verification (when `hw-verify-llq` on): parse PMD startup log + read `dev_info.default_rxportconf` / `default_txportconf` signals; fail-hard if the device advertises LLQ capability but LLQ did not activate at bring-up.
- `tcp_output.rs` / `l3_ip.rs` TX checksum split, compile-gated by `hw-offload-tx-cksum`:
  - Feature ON: set `mbuf.ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM` (and UDP analog); set `mbuf.l2_len = 14`, `mbuf.l3_len = 20`, `mbuf.l4_len = tcp_hdr_len`; write **only** the TCP / UDP pseudo-header checksum per RFC 9293 §3.1. Runtime-fallback branch (if the PMD didn't advertise the capability) reverts to full-fold for that engine instance only.
  - Feature OFF: software full-fold on the TX path; no offload bits set.
- `tcp_input.rs` / `l3_ip.rs` RX checksum consumption, compile-gated by `hw-offload-rx-cksum`:
  - Feature ON: inspect `mbuf.ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK` / `RTE_MBUF_F_RX_L4_CKSUM_MASK`; `GOOD` → verified, `BAD` → drop with counter, `NONE` / `UNKNOWN` → fall back to software fold.
  - Feature OFF: software verify runs unconditionally on the RX path.
- RSS-hash plumbing in `flow_table.rs`, compile-gated by `hw-offload-rss-hash`:
  - Feature ON: read `mbuf.hash.rss` as the initial 4-tuple hash when `RTE_MBUF_F_RX_RSS_HASH` is set; fall back to SipHash otherwise.
  - Feature OFF: always compute SipHash locally.
- NIC RX timestamp plumbing in `engine.rs` + event-emission sites, compile-gated by `hw-offload-rx-timestamp`:
  - Feature ON: at `engine_create`, call `rte_mbuf_dynfield_lookup("rte_dynfield_timestamp")` → store `ts_offset: Option<i32>` on engine state; call `rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp")` → store `ts_flag_mask: Option<u64>`. Provide an always-inline accessor `hw_rx_ts_ns(mbuf) -> u64` that returns `*(uint64_t*)((char*)mbuf + ts_offset)` when **both** lookups succeeded **and** `mbuf.ol_flags & ts_flag_mask != 0`; returns 0 otherwise. RX paths that currently hardcode `rx_hw_ts_ns: 0` (`crates/dpdk-net-core/src/engine.rs:725`, `:995`; `crates/dpdk-net/src/lib.rs:161`, `:172`, `:185`) read the accessor from the originating mbuf instead. A3/A4 emission sites that have already dropped their source mbuf reference get the timestamp threaded through the internal event struct at the RX-decode boundary.
  - Feature OFF: accessor is `const fn hw_rx_ts_ns(_mbuf) -> u64 { 0 }`; no dynfield lookup at startup; all `rx_hw_ts_ns` fields stay 0.
  - On ENA (Stage 1 reference target): both dynfield and dynflag lookups return negative; accessor always yields 0; `rx_hw_ts_ns = 0` in every event as §8.3 / §9.2 already document. Callers use `enqueued_ts_ns` per §7.5. This is the exercised path in the Stage 1 smoke tests — the positive path is reachable but not asserted until a host with the dynfield is available (Stage 2 hardening).
- Counter additions (all slow-path per §9.1.1 — fire on bring-up + on `BAD` checksum only; fields always allocated for C-ABI stability even when the feature is off):
  - `eth.offload_missing_rx_cksum_ipv4`, `eth.offload_missing_rx_cksum_tcp`, `eth.offload_missing_rx_cksum_udp`, `eth.offload_missing_tx_cksum_ipv4`, `eth.offload_missing_tx_cksum_tcp`, `eth.offload_missing_tx_cksum_udp`, `eth.offload_missing_mbuf_fast_free`, `eth.offload_missing_rss_hash`, `eth.offload_missing_llq` — one-shot counters incremented once at `engine_create` per capability that was compile-time-enabled + runtime-requested but not advertised by the PMD. All zero in the reference ENA deployment; non-zero exposes a test-harness bring-up or a hardware change.
  - `eth.offload_missing_rx_timestamp` — one-shot counter incremented once at `engine_create` when `hw-offload-rx-timestamp` was compile-time-enabled but `rte_mbuf_dynfield_lookup` / `rte_mbuf_dynflag_lookup` returned negative. **Expected 1 on ENA** (dynfield not registered) — unlike the other `offload_missing_*` counters, this one being nonzero is the documented steady state for the Stage 1 target host, not an anomaly. 0 on hardware/PMDs that expose the dynfield (mlx5, ice on supporting NICs, future ENA generations).
  - `eth.rx_drop_cksum_bad` — drop count for segments where NIC reported `BAD` for IP or L4 checksum. Fires only on actual bad packets, not on offload misses.
- Software-fallback smoke test: build with default features AND run on `net_vdev` / `net_tap` where offloads are unavailable; assert the `offload_missing_*` counters are set as expected (including `offload_missing_rx_timestamp`) and that the runtime-fallback software checksum path correctly computes IP/TCP/UDP checksums end-to-end via the A3 TAP-pair harness; additionally assert every event's `rx_hw_ts_ns == 0` (dynfield-absent path). Second smoke run with `--no-default-features` asserts the compile-time-gated-off build also passes the same correctness harness (no offload path compiled in, pure software, `rx_hw_ts_ns = 0` by construction).
- Hardware-path smoke test: build with default features; bring the engine up on the actual ENA VF; log the negotiated offload banner; drive one full request-response cycle; assert all `offload_missing_*` counters are zero **except** `offload_missing_rx_timestamp == 1` (documented ENA steady state — the dynfield-absent path is the expected Stage 1 ground truth, not a failure); assert `eth.rx_drop_cksum_bad` is zero on well-formed traffic; assert every event's `rx_hw_ts_ns == 0`.
- **Measurement of actual offload benefit is deferred to A10** — A10's `tools/bench-offload-ab/` (added to A10's deliverables) will rebuild with each feature-flag combination and produce the p50/p99/p999 comparison that drives the final "keep/remove per offload" decision. A-HW's job is to make the code path switchable at compile time and correct under both settings; A10's job is to measure.

**Does NOT include:**
- Multi-queue enablement (Stage 1 single-queue per §12 — RSS indirection-table reprogramming for multiple queues is deferred, though the hash machinery is wired).
- Header/data split, TSO, GRO, GSO (explicitly excluded per §8.4 Tier 3).
- Any hot-path counter tracking "offload used" vs "software path" (startup log is authoritative per §8.5 / §9.1.1).
- Multi-segment RX/TX general enablement (A5's retransmit header-chained-to-data mbuf pattern keeps `MULTI_SEGS` enabled on TX, but the RX scatter offload stays off at MTU 1500).
- Validation of the HW-timestamp **positive** path on a PMD that actually registers `rte_dynfield_timestamp` (mlx5 / ice / future-gen ENA). The wiring is correct by construction + reviewed against the DPDK dynfield API, but end-to-end assertion on real timestamps is deferred to Stage 2 hardening when a target host with the dynfield is available. Stage 1 correctness gate is that the ENA dynfield-absent path works and `rx_hw_ts_ns = 0` propagates cleanly.
- **Wire-drive validation of Task 18's HW-path smoke** (128 B request-response cycle across a real ENA VF against a paired peer on the same subnet). A-HW ran `Engine::new` + LLQ verifier + port-config runtime validation on real ENA (2026-04-20) but the wire cycle itself was untestable inside the A-HW container because there was no routable peer on the ENA VF's subnet. **Deferred to A10 `tools/bench-e2e/`**, which runs on a dedicated EC2 host with a real paired peer — the wire-drive test is a natural subset of the e2e RTT harness, with explicit counter-value assertions folded in. No A-HW code change needed; the Task 18 test file stays `#[ignore]`d in A-HW so operators can still run it manually as a smoke pass.

**Dependencies:** A5 (retransmit path goes through the same `tcp_output.rs` checksum branch; doing A-HW before A5 would require two visits to that file).

**Ship gate:** phase-a-hw-complete tag requires (a) software-fallback smoke tests green with both `--default-features` (runtime-fallback path exercised) and `--no-default-features` (compile-gated-off path exercised), (b) hardware-path smoke test green on the ENA VF with default features, (c) CI matrix builds every per-offload feature combination (or a sampled subset documented in the report) to prevent bit-rot of the feature-off branches. Final kept-vs-removed decision per offload is **not** gated here — it's gated in A10 once the A/B benchmark data exists.

**Rough scale:** ~14 tasks (port-config upgrade, LLQ verify, TX checksum feature gate + branch, RX checksum feature gate + branch, RSS-hash feature gate + flow-table read, MBUF_FAST_FREE feature gate, LLQ feature gate, RX-timestamp feature gate + dynfield/dynflag lookup at `engine_create`, RX-timestamp inline accessor + threading through A3/A4 event-emission sites, capability-gated runtime fallback paths, software-fallback smoke × 2 build configs, hardware-path smoke, counter additions + coverage entries, startup-banner format + CI feature-matrix build).

**Status:** **Complete.** Plan: `docs/superpowers/plans/2026-04-19-stage1-phase-a-hw-ena-offload.md`. Tag: `phase-a-hw-complete` (set after Task 20's mTCP + RFC review gates).

---

## A-HW+ — ENA observability + tuning knobs

**Goal:** Close 5 gaps identified in `docs/references/ena-dpdk-review-2026-04-20.md` against the upstream ENA DPDK README — H1 WC verification, H2 ENI allowance xstats, M1 large_llq_hdr knob, M2 miss_txc_to knob, M3 per-queue xstats — without touching the wire path. All slow-path; 15 new always-allocated counter fields; 2 new EngineConfig knobs; 2 new extern "C" entry points (`dpdk_net_scrape_xstats`, `dpdk_net_recommended_ena_devargs`); no new feature flags.

**Spec refs:** `docs/references/ena-dpdk-readme.md` §5.1 (devargs), §6.1 + §6.2.3 (WC), §8.2.2–4 (xstats); parent spec §9.1.1 (counter policy); user memory `feedback_observability_primitives_only.md`.

**Deliverables:** see plan file `docs/superpowers/plans/2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md`.

**Does NOT include:**
- Device-reset / AENQ keepalive recovery (parent gap H3 — Stage 2 reliability phase).
- `RTE_ETHDEV_QUEUE_STAT_CNTRS` bump (Stage 2 multi-queue gap M4).
- MTU / jumbo frames (out of Stage 1 scope per A-HW).
- RSS symmetric key (AD-2 from A-HW review — Stage 2 multi-queue).

**Dependencies:** A-HW (sits on the `EthCounters` + offload-AND infrastructure).

**Ship gate:** `phase-a-hw-plus-complete` tag requires:
- `cargo test --workspace` green.
- `ena_obs_smoke` green (pure-unit cross-crate check).
- Real-ENA smoke green (`ahw_smoke_ena_hw.rs` `--ignored`).
- `knob-coverage` extended + green.
- mTCP review report `docs/superpowers/reviews/phase-a-hw-plus-mtcp-compare.md` with zero open `[ ]` in blocking sections.
- RFC review report `docs/superpowers/reviews/phase-a-hw-plus-rfc-compliance.md` with zero open `[ ]` in blocking sections.

**Status:** **Complete.** Plan: `docs/superpowers/plans/2026-04-20-stage1-phase-a-hw-plus-ena-obs-knobs.md`. Tag: `phase-a-hw-plus-complete` (coordinator merges + pushes per phase convention).

---

## A6 — Public API surface completeness + per-conn RTT histogram (COMPLETE)

**Status:** Complete 2026-04-20. Design spec: `docs/superpowers/specs/2026-04-19-stage1-phase-a6-public-api-completeness-design.md`. Implementation plan: `docs/superpowers/plans/2026-04-19-stage1-phase-a6-public-api-completeness.md`. Ship tag: `phase-a6-complete`. Review reports: `docs/superpowers/reviews/phase-a6-mtcp-compare.md` + `docs/superpowers/reviews/phase-a6-rfc-compliance.md` (both PASS, zero open `[ ]`). A5.6 absorbed into A6 (see row above). Final task count: 22 implementation tasks + 1 phase-gate task = 23.

**Goal:** Finalize the public C ABI per §4: `dpdk_net_flush` actually flushes via data-segment TX ring batching, `WRITABLE` events on send-buffer drain (level-triggered hysteresis at `send_buffer_bytes/2`), timer API (`timer_add`/`cancel` + `TIMER` event layered on the A5 wheel), `dpdk_net_close(flags)` with `FORCE_TW_SKIP` under `ts_enabled` prerequisite + `-EPERM` event when prereq not met, mempool exhaustion error paths (per-occurrence on retransmit; edge-triggered per-poll on RX), `preset=rfc_compliance` runtime switch. Also: per-connection RTT histogram (16×u32 cacheline-aligned buckets, runtime-configurable edges). RFC 7323 §5.5 24-day `TS.Recent` lazy expiration (no timer needed) landed from A5/A5.5 deferral list.

**Spec refs:** §4 (API), §4.2 contracts (flush data-only, timer_cancel -ENOENT-collapse, close EPERM event), §6.5 TIME_WAIT shortening (ts_enabled prerequisite + client-side RFC 6191 analog), §7.4 timer wheel (reused from A5), §9.1 four A6 counters, §9.3 ENOMEM emission sites, §6.4 `AD-A6-force-tw-skip` new accepted deviation.

**Deliverables (landed):**
- Public timer API extern fns + `InternalEvent::ApiTimer` wiring + `TimerKind::ApiPublic` fire branch.
- Engine-scope `tx_pending_data` ring + `drain_tx_pending_data` helper + `dpdk_net_flush` body; control frames stay inline per spec §3.2 option (c).
- `DPDK_NET_EVT_WRITABLE` hysteresis: `send_refused_pending` bit on `TcpConn`; ACK-prune path fires once per refusal cycle when in_flight ≤ send_buffer_bytes/2.
- `dpdk_net_close(flags)` honors `FORCE_TW_SKIP` bit; `ts_enabled==true` sets `c.force_tw_skip`; `reap_time_wait` short-circuits for force_tw_skip; `ts_enabled==false` emits `Error{err=-EPERM}` + normal 2×MSL.
- Engine event queue FIFO drop-oldest + soft-cap contract (reused from A5.5 Task 5; A6 verified A6 variants preserve FIFO).
- `preset=rfc_compliance` engine-create override: `tcp_nagle=true`, `tcp_delayed_ack=true`, `cc_mode=1` (Reno), `tcp_min_rto_us=200_000`, `tcp_initial_rto_us=1_000_000`; `preset>=2` rejected with null-return.
- `preset` constants `DPDK_NET_PRESET_LATENCY=0` / `DPDK_NET_PRESET_RFC_COMPLIANCE=1` emitted as C #defines.
- RX-mempool-drop edge-triggered `Error{err=-ENOMEM}` event (1/poll iteration max) via `rx_drop_nomem_prev` snapshot.
- Retransmit `Error{err=-ENOMEM}` emission at all 4 alloc-fail sites inside the retransmit function.
- Per-connection `RttHistogram` (16×u32, `#[repr(C, align(64))]`, compile-time size/align pinned to 64 B); update hook after every `rtt_est.sample` site (tcp_input.rs + SYN-ACK seed path); engine-wide edges config field with validation (non-monotonic → null-return); ABI POD `dpdk_net_tcp_rtt_histogram_t` + extern `dpdk_net_conn_rtt_histogram`; default edges tuned for trading-exchange RTT range (50µs–500ms log-spaced).
- RFC 7323 §5.5 24-day `TS.Recent` lazy expiration at PAWS gate + `ts_recent_age` backfilled at all 3 write sites (fixed latent A5-era debt).
- Four new slow-path `tcp.*` counters: `tx_api_timers_fired`, `ts_recent_expired`, `tx_flush_bursts`, `tx_flush_batched_pkts`.
- Integration test file `tests/tcp_a6_public_api_tap.rs` (17 pure in-process tests pinning the public-API contracts end-to-end at the TcpConn / Engine / EventQueue level).
- Knob-coverage audit extended (3 new entries: preset, FORCE_TW_SKIP, rtt_histogram_bucket_edges_us).
- Sibling audit `tests/per-conn-histogram-coverage.rs` covering all 16 default buckets.
- Parent-spec updates: §4, §4.2, §6.4 (new `AD-A6-force-tw-skip` row), §6.5, §9.1, §9.3. A5.5 citation nits corrected inline ("RFC 6298 §3.3" → "§2.2 + §3 (Karn's rule)"; "RFC 8985 §7.4 (RTT-sample gate)" → "§7.3 step 2").

Per-connection RTT histogram (merged from A5.6):
- Per-conn `rtt_histogram: [u32; 16]` field on `TcpConn` (exactly 64 B, one cacheline). Updated inside `rtt_est.sample()` via a 15-comparison bucket-selection ladder + `wrapping_add(1)`. Cost: ~5–10 ns per RTT sample; no atomic (single-lcore RTC model).
- Runtime-configurable bucket edges via `dpdk_net_engine_config_t::rtt_histogram_bucket_edges_us[15]` (15 × `uint32_t` = 60 B, strictly monotonically increasing). All-zero = stack applies trading-tuned defaults `{50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000, 10000, 25000, 50000, 100000, 500000}` µs (dense resolution in the 50µs–1ms colo/same-region range, coarser beyond). Non-monotonic edges rejected at `engine_create` with `-EINVAL`.
- New extern "C" getter `dpdk_net_conn_rtt_histogram(engine, conn, out) → i32` returning a 64-byte `dpdk_net_tcp_rtt_histogram_t { uint32_t bucket[16] }`. Slow-path, per-order or per-minute cadence.
- Wraparound semantics: per-bucket `u32` overflows silently; application takes deltas via unsigned wraparound subtraction. Correctness bound: no single bucket accumulates > 2³² samples between polls. At 1M samples/sec that's ~71 minutes; at 10k samples/sec typical for order-entry it's ~5 days. Documented in the cbindgen header's struct doc-comment.
- A8 audit integration: sibling per-conn-histogram coverage audit in `tests/per-conn-histogram-coverage.rs` (engine-wide counter audit doesn't reach per-conn state); scenario sweeps RTT across all 16 buckets. Knob-coverage audit picks up `rtt_histogram_bucket_edges_us` with a non-default-edges scenario.

**Does NOT include:**
- Test suite harnesses (A7/A8/A9).
- Per-sample `DPDK_NET_EVT_RTT_SAMPLE` events (deferred; histogram covers the stated minute-to-hour use case more cheaply).
- Raw-samples ring (deferred for the same reason).
- Engine-wide histogram aggregation (derive from per-conn on demand if needed).
- Mid-session edge changes (edges fixed at `engine_create`).

**Dependencies:** A5 + A5.5 (the histogram hooks into A5's `rtt_est.sample()` call site which A5.5 extended; public API additions build on A5.5's event + stats infrastructure).

**Final task count:** 22 implementation + 1 phase-gate = 23 tasks. Matches roadmap budget ("~20 A6-core + 3 histogram").

---

## A6.5 — Hot-path allocation elimination

**Numbering note:** Inserted after A6 as a focused perf pack. Uses the decimal "A6.5" tag (per the A5.5 precedent) because the scope is cross-cutting hot-path cleanup that does not change public API and does not justify an integer bump that would shift A7–A14 references. Can run serially between A6 and A7, or in parallel with A7/A8 since there are no API-surface changes.

**Goal:** Eliminate heap allocations on the RX, TX, per-ACK, and per-timer-tick hot paths so benchmark (A10) and steady-state production traffic do not allocate. Per-connection buffers sized at `connect()` remain; this phase targets allocations inside the poll loop.

**Spec refs:** §7 (Memory and Buffer Model) — extends with a new §7.6 "Hot-path scratch reuse policy". §7.3 "Zero-copy path" — the reassembly payload-copy TODO is retired here. §9.1.1 counter-addition policy — analogous discipline for memory: hot-path allocations require the same level of justification as hot-path counters (i.e. none ship by default).

**Deliverables:**

Group 1 — reusable scratch buffers on `Engine`:
- `Engine.tx_frame_scratch: RefCell<Vec<u8>>` with capacity retained across calls. `engine.rs:2472` `let mut frame = vec![0u8; 1600]` replaced by borrow + `clear()` + grow-if-smaller.
- Scratch sized once at `engine_create` from `cfg.tcp_mss` + `FRAME_HDRS_MIN` + 40-byte TCP-options cushion.

Group 2 — streaming Internet checksum (no concatenation buffer):
- `l3_ip::internet_checksum` accepts a disjoint-slice iterator (e.g. `&[&[u8]]`) so TCP pseudo-header + header + payload fold without building a concatenated buffer.
- `tcp_input::tcp_pseudo_csum` (`tcp_input.rs:102`) drops `Vec::with_capacity(12 + tcp_bytes.len())` and the preceding `scratch = tcp_bytes.to_vec()` (`tcp_input.rs:79`) — folds the pseudo-header + TCP bytes directly.
- `tcp_output::tcp_checksum_split` (`tcp_output.rs:204`) drops `Vec::with_capacity(...)` — header and payload are already separate, streams in place.
- Fuzz test (`tests/checksum_streaming_equiv.rs`): random byte sequences, reference (concatenating) implementation vs streaming fold match bit-for-bit across all alignments.

Group 3 — `SmallVec` / caller-buffer for per-ACK and per-tick scratch:
- `tcp_input.rs:675` `rack_lost_indexes: Vec<u16>` → `SmallVec<[u16; 16]>` (heap only on overflow; typical case ≤ a few losses).
- `tcp_timer_wheel::fire_due` takes `&mut Vec<TimerId>` (caller-owned, `clear()`-ed per tick). `Engine` parks the buffer; `tcp_timer_wheel.rs:100, 102` `Vec::new()` sites retired.
- `engine.rs:957` RACK loss-event tuple vec → `SmallVec<[(u32, u32); 4]>`.
- `tcp_retrans::prune_below` (`tcp_retrans.rs:65`) `let mut dropped = Vec::new()` → in-place `mbuf_free` loop or `&mut SmallVec` from caller (drop the intermediate collection entirely).

Group 4 — zero-copy RX reassembly (completes spec §7.3):
- `tcp_reassembly.rs` refactor: reassembly holds `Mbuf` refs + offsets instead of `Vec<u8>` payload copies.
- Removes `to_insert: Vec<(u32, Vec<u8>)>` (`tcp_reassembly.rs:86`) and the two `payload[off..off + take].to_vec()` copies (`tcp_reassembly.rs:102, 121`).
- READABLE event pins referenced mbufs until the next `dpdk_net_poll`, consistent with §5.3 mbuf-lifetime contract.
- Unit tests in `tests/tcp_options_paws_reassembly_sack_tap.rs` updated to assert ref-based reassembly (no byte copies observed via the alloc-audit harness from Group 5).

Group 5 — verification + regression guard:
- `tools/bench-alloc-hotpath/` — counting `GlobalAlloc` wrapper behind a new `bench-alloc-audit` cargo feature. 60-second steady-state send/recv loop post-warmup asserts `alloc_count_delta == 0`.
- `tools/bench-obs-overhead/` (from A10) adopts the same wrapper so any reintroduced hot-path allocation fails the A10 regression gate. Report artifact `docs/superpowers/reports/alloc-hotpath.md` lists every hot-path call-site that was retired + the audit-run evidence.

**Does NOT include:**
- Per-connection `VecDeque<u8>` send/recv buffers sized at `connect()` and `Vec<TimerId> timer_ids` grown on timer-arm (`tcp_conn.rs:24, 59, 307`). One-shot per connection, not per-poll — out of scope.
- Engine-creation allocations (`Box::new(Counters::new())`, DPDK mempools, timer-wheel slot vectors). Startup cost, irrelevant to steady state.
- Custom `GlobalAlloc` replacement (bump allocator, arena). Not needed once the hot path does not touch the allocator; default system allocator remains.
- `String::` / `format!` in error-path `Error` variants and slow-path logging. Slow-path by §9.1.1 classification.

**Dependencies:** A6 (stable public-API event + mbuf-lifetime semantics so the reassembly refactor does not collide with ongoing event-contract changes). **Must land before A10** so the benchmark harness measures the alloc-free hot path, not an interim shape.

**Rough scale:** ~15 tasks (~3 Group 1 + ~3 Group 2 + ~3 Group 3 + ~5 Group 4 + ~1 Group 5 bench-audit harness). Group 4 is the only structural refactor touching segment-lifetime invariants; the rest are mechanical.

---

## A6.6 — RX zero-copy (scatter-gather, LRO-compatible)

**Numbering note:** Inserted after A6.5 as the API-evolution half of the zero-copy RX story. A6.5 Group 4 retires internal `Vec<u8>` copies inside `tcp_reassembly.rs` (OOO path) and pins mbufs through the READABLE event — strictly internal. A6.6 evolves the *public* API to scatter-gather so chained mbufs (LRO / jumbo / IP-defragmented) deliver without a flatten copy, and finishes the in-order-delivery-path mbuf-ref rework that A6.5 Group 4 does not cover. Uses the "A6.6" decimal tag (A5.5 / A6.5 precedent) to avoid renumbering A7–A14.

**Goal:** Close the drift between spec §5.3 / §7.3 (mbuf-pinned zero-copy delivery) and the current delivery implementation. After A6.6 the `DPDK_NET_EVT_READABLE` event borrows directly into mempool-backed DMA memory via `dpdk_net_iovec_t segs[]`; no intermediate `Vec<u8>` on the RX hot path.

**Spec refs:** §4.2 (event contract — `readable.data` lifetime), §5.3 (mbuf lifetime), §7.2 / §7.3 (per-conn buffers + zero-copy path). §4.1 header evolves: `dpdk_net_event_readable_t` gains `segs` / `n_segs` / `total_len`, drops `data` / `len`. New POD struct `dpdk_net_iovec_t`.

**Design spec:** `docs/superpowers/specs/2026-04-20-stage1-phase-a6-6-and-a6-7-rx-zero-copy-and-ffi-safety-audit-design.md`.

**In scope:**

Group 1 — in-order delivery-path mbuf-ref migration:
- `RecvQueue.bytes: VecDeque<u8>` (`tcp_conn.rs`) → `VecDeque<InOrderSegment { mbuf: Mbuf, offset: u16, len: u16 }>`.
- `RecvQueue.last_read_buf: Vec<u8>` (`engine.rs`) retired entirely.
- `tcp_reassembly.drain_contiguous_into(rcv_nxt, out: &mut VecDeque<InOrderSegment>)` appends mbuf-ref segments directly into `RecvQueue.bytes` (no intermediate collection).
- Partial-segment split on delivery uses an explicit `Mbuf::try_clone()` method (refcount-bump + new wrapper) — intentionally not a `Clone` derive, to avoid silent over-bumps.

Group 2 — scatter-gather public API:
- Add `dpdk_net_iovec_t { const uint8_t *base; uint32_t len; uint32_t _pad; }` (16 B, x86_64).
- `dpdk_net_event_readable_t` reshaped: `segs: const dpdk_net_iovec_t*`, `n_segs: u32`, `total_len: u32`.
- Engine-owned per-conn `readable_scratch_iovecs: RefCell<Vec<dpdk_net_iovec_t>>` (capacity retained; cleared at top of each `poll_once`).
- `TcpConn.delivered_segments: Vec<InOrderSegment>` holds popped segments until the *next* `poll_once` drains them — backing the scatter-gather pointers.

Group 3 — multi-segment (LRO / jumbo) ingest:
- `tcp_input` RX path already walks mbuf chains for checksum / header parse; A6.6 extends reassembly enqueue to enqueue each link as its own `InOrderSegment` / reorder entry.
- No flatten helper in this phase. Consumers with contiguous-only processing call `memcpy` across `segs[]` themselves.

Group 4 — pool sizing:
- `dpdk_net_engine_config_t.rx_mempool_size: u32` (0 = compute default from `recv_buffer_bytes × max_conns / avg_payload_bytes × 2`, clamped to ≥ `2 × RTE_ETH_RX_DESC_DEFAULT`).
- Plumbed through `engine_create`; documented in cbindgen header.

Group 5 — verification:
- `tools/bench-rx-zero-copy/` — criterion harness: poll-to-delivery cycle cost + `bench-alloc-audit` assertion that the single-segment in-order delivery path allocates zero bytes post-warmup.
- `tests/rx_zero_copy_single_seg.rs`, `tests/rx_zero_copy_multi_seg.rs`, `tests/rx_partial_read.rs`, `tests/rx_close_drains_mbufs.rs`.
- `examples/cpp-consumer/main.cpp` updated to iterate `segs[]`.

**Observability additions (slow-path):**
- `obs.rx_iovec_segs_total` — cumulative iovec count emitted.
- `obs.rx_multi_seg_events` — events with `n_segs > 1` (LRO effectiveness).
- `obs.rx_partial_read_splits` — partial-segment splits on delivery (tune `max_read_bytes`).

**Does NOT include:**
- OOO reassembly mbuf-ref refactor — **A6.5 Group 4** owns it.
- TX zero-copy (user-held buffer consumed without copy) — separate contract change, deferred.
- `dpdk_net_readable_flatten()` convenience helper — YAGNI; add if a consumer asks.
- WRITABLE event / backpressure — A6.
- cxx-bridge migration — stays cbindgen.

**Dependencies:**
- **A6.5 Group 4** (firm) — OOO reassembly mbuf-refs + READABLE-event mbuf-pinning must land first.
- **A6** (firm) — final public-API event shape stable before A6.6 evolves `dpdk_net_event_readable_t`.
- **A-HW** (soft) — LRO enablement exercises the multi-segment path under realistic load; A6.6 ships correct single-seg behavior regardless.

**Rough scale:** ~14 tasks (~3 Group 1 + ~3 Group 2 + ~2 Group 3 + ~1 Group 4 + ~4 Group 5 + ~1 cpp-consumer update).

---

## A6.7 — FFI safety audit & hardening

**Numbering note:** Inserted immediately after A6.6 as a gate before A7's packetdrill harness. Audits the final FFI contract once, in its Stage 1 shape, rather than auditing then re-auditing after A6.6 evolves the event shape. Non-integer tag matches A5.5 / A6.5 / A6.6 precedent.

**Goal:** Certify FFI memory safety, panic safety, and ABI stability at the C ↔ Rust boundary before A7–A11 depend on it. Not about TCP correctness (A9 + A7 cover that) — specifically about what can go wrong when a C++ consumer calls into Rust and vice versa.

**Spec refs:** §2.5 (C ABI surface), §3.3 (panic discipline — `panic = abort`), §7.5 (mempool lifecycle + Drop ordering). This phase adds `docs/superpowers/reports/panic-audit.md` and `docs/superpowers/reports/ffi-safety-audit.md` as durable artifacts.

**Design spec:** `docs/superpowers/specs/2026-04-20-stage1-phase-a6-6-and-a6-7-rx-zero-copy-and-ffi-safety-audit-design.md`.

**In scope:**

Group 1 — static + compile-time checks:
- miri CI job over `dpdk-net-core` tests (DPDK-touching modules `#[cfg(miri)]`-skipped or shimmed). Covers safe/unsafe-Rust UB in pure-core logic.
- cbindgen header-drift CI check: `cargo xtask check-header` regenerates `include/dpdk_net.h` and diffs against committed; CI fails on drift.
- ABI-stability snapshot: `tests/abi/dpdk_net.h.expected` committed; `check-header` diffs against it; drift requires intentional snapshot update (semver-like discipline, pre-1.0 snapshot is the contract).
- Counters data-race audit: emit `_Atomic uint64_t` guards in cbindgen-generated `dpdk_net_counters_t`, or document atomic-load requirement with a compile-time assertion in the cpp-consumer.

Group 2 — runtime safety tests:
- Panic-firewall test: child-process fork + `dpdk_net_panic_for_test()` ABI entry + SIGABRT assertion. Regression guard if `panic = abort` is ever unchanged.
- No-alloc-on-hot-path: extends A6.5 Group 5's `bench-alloc-audit` wrapper with a dedicated unit-test asserting `allocations == 0` over a representative workload through `poll_once` / `send_bytes` / event-emit.
- C++ consumer under ASan + UBSan + LSan: `examples/cpp-consumer/main.cpp` in a CI sanitizer matrix, runs scripted connect → send → recv → close.

Group 3 — audit artifacts:
- Panic audit (grep + manual): `panic!` / `unwrap` / `expect` / unchecked indexing on FFI-reachable paths → either eliminated or documented unreachable-by-construction. Report: `docs/superpowers/reports/panic-audit.md`.
- Summary report: `docs/superpowers/reports/ffi-safety-audit.md` — every check + evidence + residual risks.

**Does NOT include:**
- TCP correctness fuzzing — **A9** owns TCP-Fuzz differential + smoltcp FaultInjector.
- ABI-boundary fuzzing (random sequence of ABI calls via cargo-fuzz) — natural home is A9.
- `cargo-semver-checks` / formal semver tooling — pre-1.0, snapshot is the contract.
- TSan — single-lcore RTC model has no cross-thread races by construction; TSan would exercise a zero-race codepath, add CI minutes without catching real issues.

**Dependencies:** A6.6 (audit the final contract once).

**Rough scale:** ~8 tasks (~4 Group 1 + ~3 Group 2 + ~1 Group 3 bundling the two reports).

---

## A7 — Loopback test server + packetdrill-shim

**Goal:** Server-mode cargo feature `test-server` (accept on listening port, byte-stream echo). Luna-pattern packetdrill-shim that links `libdpdk_net` + socket-shim wrapper and runs curated packetdrill scripts.

**Spec refs:** §10.2, §10.12, §11 test-only loopback server is in scope.

**Deliverables:**
- `dpdk-net-testserver` crate behind feature flag `test-server`: implements `LISTEN` / `SYN-RECEIVED` / `ESTABLISHED` server path + byte-stream echo.
- `tools/packetdrill-shim/` — links `libdpdk_net.a`, redirects packetdrill's TUN read/write to stack rx/tx hooks, implements synchronous socket-shim wrapper for `connect`/`write`/`read`/`close`.
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
  - Dynamic check: for every counter, the test suite must include at least one scenario that drives it nonzero. Implemented as a table of (counter_name, scenario_fn) with a test that runs each scenario on a fresh engine and asserts the named counter ended > 0. Missing entries fail the audit. A5.5 additions (`tcp.tx_tlp_spurious`, `obs.events_dropped`, `obs.events_queue_high_water`) are in-scope for this audit when A5.5 lands — the audit fails if A5.5 merged without adding the corresponding scenarios (DSACK-after-TLP spurious, queue-overflow, queue-high-water respectively).
  - `state_trans[from][to]`: every transition edge listed in spec §6.1 FSM must have a scenario that exercises it; unreachable edges are listed in an expected-unused file with a justification, reviewed at each phase sign-off.
- **Configuration-knob coverage audit** (catches behavioral knobs that land in the API but are never actually exercised with a non-default value — the configuration-surface analog of the counter-coverage audit):
  - Scope: every *behavioral* field on `dpdk_net_engine_config_t` and `dpdk_net_connect_opts_t` — fields whose non-default value changes observable wire behavior or observability output. Purely informational fields (e.g., `port_id`, `local_ip`, `gateway_mac`) and sizing fields without branching logic (e.g., `max_connections`) are out of scope; listed in `tests/knob-coverage-informational.txt` with justification.
  - Static check: parse the two config structs + their cbindgen-generated C counterparts; cross-reference against a table of (knob_name, scenario_fn, non_default_value) in `tests/knob-coverage.rs`. Any behavioral knob without a table entry fails the audit.
  - Dynamic check: each scenario constructs an engine or connection with the knob set to the non-default value listed in the table, drives a minimal workload, and asserts at least one behavioral consequence (counter delta, event kind, timing window, or state transition) that distinguishes the non-default from default behavior. Missing consequence assertions fail the audit.
  - Required coverage for A5 + A5.5 knobs (canonical list — extend as later phases add knobs):
    - A5 per-connect: `rack_aggressive=true` (scenario: single-SACK-hole triggers immediate retransmit with no reo_wnd grace), `rto_no_backoff=true` (scenario: multiple consecutive RTO fires, RTO value stays constant across fires).
    - A5 engine-wide: `tcp_per_packet_events=true` (scenario: induce one retransmit, assert `DPDK_NET_EVT_TCP_RETRANS` delivered); `tcp_max_retrans_count` at a small value like 2 (scenario: blackhole peer, assert ETIMEDOUT after exactly 2 retrans).
    - A5.5 per-connect TLP: `tlp_pto_min_floor_us=0` (scenario: assert TLP fires at `2·SRTT` rather than `max(2·SRTT, min_rto_us)`); `tlp_pto_srtt_multiplier_x100=100` (scenario: assert TLP fires at ≈ SRTT); `tlp_skip_flight_size_gate=true` (scenario: single-in-flight + drop, assert TLP at `2·SRTT` without the `+max_ack_delay` penalty); `tlp_max_consecutive_probes=3` paired with `tlp_skip_rtt_sample_gate=true` (scenario: persistent tail loss, assert 3 probes fire at PTO cadence before RTO takes over); `tlp_skip_rtt_sample_gate=true` solo (scenario: back-to-back TLPs without intervening RTT sample — probe 2 fires where default behavior would suppress it).
    - A5.5 engine-wide: `event_queue_soft_cap=128` (scenario: overflow the queue, assert `obs.events_dropped > 0` and drained events are the most-recent).
    - A5.5 knob combinations: the "aggressive order-entry preset" from A5.5 §5.5 (all five TLP knobs on their aggressive values simultaneously) gets its own scenario — assert the first TLP fires within `1·SRTT` of the drop, three probes fire in series, no RTO fires in that window.
  - Regression semantics: when a phase adds a new behavioral knob, the plan includes a task for extending `tests/knob-coverage.rs`. The audit fails in CI if a new field is added to either config struct without a corresponding table entry or an explicit informational-whitelist entry.

**Dependencies:** A7.

**Rough scale:** ~13 tasks (+2 for the counter-coverage audit: static-check script + dynamic-scenario table; +3 for the knob-coverage audit: static-parse of the two config structs, dynamic-scenario table with ~12 entries covering A5 + A5.5 knobs, CI integration that fails on unlisted new behavioral fields).

---

## A9 — Property + bespoke fuzzing + smoltcp FaultInjector

**Goal:** Land property + bespoke fuzz coverage of the Stage 1 TCP stack. proptest suites, cargo-fuzz targets (pure-module + one persistent-mode engine target), Scapy adversarial corpus driven through a test-inject RX hook, smoltcp-pattern FaultInjector RX middleware. Closes I-8 FYI from `docs/superpowers/reviews/phase-a6-6-7-rfc-compliance.md`.

**Spec refs:** §10.6. (§10.5 Layer E differential-vs-Linux deferred to new Stage-2 phase S2-A.)

**Deliverables:**
- 6 `proptest` suites under `crates/dpdk-net-core/tests/proptest_*.rs` (tcp_options, tcp_seq, tcp_sack, tcp_reassembly, paws, rack_xmit_ts)
- 7 cargo-fuzz targets under `crates/dpdk-net-core/fuzz/fuzz_targets/` (6 pure-module T1 + 1 persistent-mode engine T1.5)
- `crates/dpdk-net-core/src/fault_injector.rs` + counters + engine wiring, behind `fault-injector` cargo feature
- `Engine::inject_rx_frame` + `inject_rx_chain` (behind `test-inject` cargo feature) — A7 coordination contract
- `crates/dpdk-net-core/src/test_fixtures.rs` — hoisted `make_test_engine` for cross-crate test reuse
- `tools/scapy-corpus/` (6 Python Scapy scripts generating .pcap + .manifest.json pairs)
- `tools/scapy-fuzz-runner/` — Rust binary replaying pcap corpora via the test-inject hook
- `scripts/fuzz-smoke.sh` (per-merge CI, 30s per target × 7) + `scripts/fuzz-long-run.sh` (per-stage-cut, 72h dedicated box) + `scripts/scapy-corpus.sh` (regen)
- I-8 closure in `tcp_input.rs` + directed multi-seg regression test via dispatch
- `.github/workflows/a9-fuzz.yml` — three parallel CI jobs (fuzz-smoke, scapy-corpus-replay, fault-injector-compile)
- End-of-phase mTCP + RFC review reports

**Deferred to Stage 2 (S2-A):** differential-vs-Linux fuzz, `preset=rfc_compliance` engine knob, TCP-Fuzz vendor (zouyonghao/TCP-Fuzz), Linux netns oracle plumbing, divergence-normalisation layer. These combine with spec §10.7 Layer G WAN A/B in S2-A — both need the same Linux-oracle infrastructure.

**Dependencies:** A6 (full API surface stable), A6.6-7 (test-inject hook integrates with the chain-walk ingest + FFI shape).

**Rough scale:** ~26 tasks.

---

## A10 — Benchmark harness (micro + e2e + stress + comparators)

**Goal:** Implement the §11 benchmark plan: microbenchmarks with order-of-magnitude targets, end-to-end RTT with HW-timestamp attribution, stability benchmarks under netem, comparative vs Linux in RFC-compliance preset, comparative vs mTCP on the burst-edge / long-connection workload. CI per-commit regression tracking.

**Spec refs:** §11 entire (§11.5.1 added for the mTCP comparator).

**Deliverables:**
- `tools/bench-micro/` — cargo-criterion harness for poll-empty, TSC read (FFI + inline), flow lookup hot/cold, `tcp_input` in/out-of-order, `send` small/chain, timer add/cancel, counters read.
- `tools/bench-e2e/` — request/response RTT harness with HW-timestamp attribution buckets and per-measurement sum-identity assertion. **Subsumes A-HW Task 18's deferred wire-drive test**: A-HW shipped with Engine::new + LLQ verifier + port-config runtime-validated on real ENA, but the 128 B request-response wire cycle was untestable inside A-HW's container (no routable peer on the ENA VF's subnet). A10 runs on a dedicated EC2 host with a paired peer on the same VPC subnet, so this harness naturally completes the Task 18 matrix — adds explicit assertions for every `offload_missing_*` counter value per parent §8.2 (runtime-confirmed: `MBUF_FAST_FREE` + `RSS_HASH` not advertised → both = 1; `rx_timestamp` = 1; all cksum = 0; `llq` = 0 via Task 12 verifier), `rx_drop_cksum_bad = 0` on well-formed echo traffic, and every event's `rx_hw_ts_ns == 0` per spec §10.5.
- `tools/bench-stress/` — netem + FaultInjector scenario runner for §11.4 matrix.
- `tools/bench-vs-linux/` — dual-stack comparison vs Linux TCP with tap-jitter baseline subtraction.
- `tools/bench-offload-ab/` — per-offload A/B harness that consumes A-HW's feature flags (`hw-verify-llq`, `hw-offload-tx-cksum`, `hw-offload-rx-cksum`, `hw-offload-mbuf-fast-free`, `hw-offload-rss-hash`) by rebuilding the engine once per feature-combination and running a 128 B / 128 B request-response micro-workload on the ENA target host. Note `hw-verify-llq` is a verification-discipline gate, not an offload-enable gate — its A/B toggles whether the engine enforces LLQ-active at bring-up, not whether LLQ is configured (the ENA PMD's `enable_llq=X` devarg stays application-owned).
  - Config matrix: `baseline` (no features), per-offload-only (one feature each), `full` (all default features). Additional compositions optional if any single-offload result is ambiguous.
  - Workload: ≥ 10 000 round-trips per config post-warmup (drop first 1 000); fresh engine bring-up between configs with `rte_eal_cleanup`; same RNG seed across runs.
  - Measurement discipline: same preconditions as §11.1 (isolcpus, governor, C-states, TSC invariant, no thermal throttle during the run). Harness fails-fast on any precondition miss.
  - Report: p50 / p99 / p999 per config with bootstrap 95% CI; per-offload `delta_p99 = p99_baseline − p99_with_offload`; pass/fail per offload against the decision rule (`delta_p99 > 3 × noise_floor`, where noise_floor = p99 of two back-to-back baseline runs).
  - Report artifact: `docs/superpowers/reports/offload-ab.md` — CSV + decision table + rationale for any offload kept without signal (e.g. correctness defense-in-depth for `hw-offload-mbuf-fast-free`). Drives the final committed default feature set in `Cargo.toml`.
  - Sanity invariant: `full` config p99 not worse than the best individual-offload p99 (offloads compose). A violation blocks the A10 sign-off pending investigation.
- `tools/bench-obs-overhead/` — per-observable A/B harness that measures the hot-path cost of every counter, event-log field, and observability hook, so any that harm performance can be re-evaluated before the A11 ship gate. Reuses `bench-offload-ab`'s feature-matrix driver; toggles `obs-*` cargo feature flags (`obs-poll-saturation`, `obs-byte-counters`, plus any future additions) and a new `obs-none` umbrella feature that gates the always-on emission sites (event-log ring writes, `emitted_ts_ns` capture, per-conn `ConnStats` getter). Same workload, measurement discipline, and decision rule as `bench-offload-ab` (128 B / 128 B request-response; §11.1 preconditions; `delta_p99 > 3 × noise_floor` = fail). Report artifact: `docs/superpowers/reports/obs-overhead.md` — pass/fail per observable + the action taken for each failure (batch the increment, remove the counter, tighten or flip the feature-gate default, or move the emission off the hot path). Operationalises the spec §9.1.1 slow-path-counters-only policy by measurement rather than by review — any counter or event-log field claimed to be slow-path that shows hot-path signal here is re-evaluated before A11. Drives the committed default feature set for `obs-*` flags in `Cargo.toml`, mirroring `bench-offload-ab`'s role for `hw-offload-*`.
- `tools/bench-vs-mtcp/` — dual-stack comparison vs mTCP, two sub-workloads:
  - `burst` (spec §11.5.1): K × G grid = 20 buckets. Burst size K ∈ {64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB}; idle gap G ∈ {0 ms, 1 ms, 10 ms, 100 ms}. Measurement: `t0` = inline TSC pre-send; `t1` = NIC HW TX timestamp on last segment of burst; per-burst throughput = K / (t1 − t0); aggregate p50/p99/p999 across ≥10k bursts/bucket. Secondary decomposition into initiation (spin-up) vs steady-state.
  - `maxtp` (spec §11.5.2): W × C grid = 28 buckets. Write size W ∈ {64 B, 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB}; connection count C ∈ {1, 4, 16, 64}. 60 s sustained pump per bucket post-warmup. Metrics: goodput (bytes/sec) and packet rate (pps) per (W, C).
  - Shared: kernel-side TCP sink as peer (reuses `bench-vs-linux` peer); `cc_mode=off`; pre-run checks (receive window, NIC headroom ≤70%, measurement-discipline); sanity invariants on TX-byte counters. mTCP built from `third_party/mtcp/` (already submoduled for the §10.13 review gate). CSV schema matches `bench-vs-linux` so `bench-report` handles all three.
- `tools/bench-report/` — CSV → dashboard feed.
- CI: cargo-criterion per commit with 5% regression gate; nightly e2e on dedicated host (includes `bench-vs-mtcp`).
- Measurement-discipline precondition check script: `isolcpus`, `nohz_full`, governor, TSC invariant, thermal-throttle detection.

**Dependencies:** A6 (full API needed for meaningful e2e), A6.5 (hot path must be alloc-free so benchmarks measure production shape, not an interim allocator-touching path), A9 (FaultInjector used by bench-stress), A-HW (offloads must be enabled so benchmarks measure the production-shape hot path, not the Phase A1 zeroed-`eth_conf` path). `third_party/mtcp` already present from the A2 review-gate setup — no new submodule work.

**Rough scale:** ~21 tasks (+6 for the mTCP comparator: build integration, peer wiring, `burst` grid runner, `maxtp` grid runner, measurement-contract harness with HW TX timestamps + TSC, result/CSV plumbing; +5 for `bench-offload-ab`: feature-matrix rebuild driver, fresh-engine run loop, percentile + CI computation, per-offload decision-rule evaluator, report writer; +3 for `bench-obs-overhead`: introduce `obs-none` umbrella feature + gate the always-on emission sites, observability-specific matrix entries reusing `bench-offload-ab`'s driver, report writer with re-evaluation table).

---

## A10.5 — Layer H correctness under WAN-condition fault injection

**Numbering note:** Inserted after A10 as a focused correctness pack. Uses the decimal "A10.5" tag (per the A5.5 / A6.5 precedent) because the scope is correctness-assertion follow-on that reuses A10's netem plumbing without changing public API. Runs serially between A10 and A11.

**Goal:** Promote spec §10.10's informal "end-to-end smoke under `tc netem` loss/delay" to a named Layer H test phase: formal netem matrix with liveness + invariant assertions, not performance measurement. A10 measures *how fast* the stack runs under adversity; A10.5 asserts *that the stack stays correct* under the same adversity.

**Spec refs:** §10.8 (Layer H — Stage 1 subset only; PMTU-blackholing deferred to Stage 2), §10.10 (formalizes the Stage 1 netem ship-gate smoke).

**Deliverables:**
- `tools/layer-h-correctness/` — netem matrix runner producing pass/fail per scenario, not p50/p99/p999. Reuses A10's `bench-stress` netem scaffolding (driver, precondition checker, scenario harness) as a library; only the assertion layer is new.
- Netem matrix (Stage 1 subset of §10.8):
  - Delay: +20 ms, +50 ms, +200 ms (each with and without jitter)
  - Loss: 0.1%, 1%, 5% random; 1% correlated bursts
  - Duplication: 0.5%, 2%
  - Reordering: depth 3
  - Corruption: 0.01% (checksum-fail drops are expected behaviour; asserted via `rx_drop_cksum_bad` signal)
- Composable with A9's `FaultInjector` env-var side channel so RX-side and WAN-side adversity can be stacked for the most demanding scenarios.
- Assertion table (per scenario):
  - Connection stays in ESTABLISHED for the configured duration — no unexpected transition to CLOSED or ERROR
  - `tcp.tx_retrans` bounded by per-conn `max_retrans_count` knob; no unbounded retransmit storms
  - FSM state ∈ legal set per §6.1 throughout the run (sampled via `dpdk_net_conn_stats`)
  - `obs.events_dropped == 0` at steady load
  - Per-scenario expected counter-signals table (e.g. 1% loss → nonzero `tcp.tx_retrans`; correlated-burst loss → nonzero `tcp.tx_rack_loss`; reorder-3 → nonzero `rx_dup_ack` without crossing 3-dup-ACK fast-retransmit unless the active preset permits it)
- CI: Layer-H smoke (one representative bucket per netem dimension) per merge; full matrix per stage cut, report to `docs/superpowers/reports/layer-h-<date>.md`.
- End-of-phase mTCP + RFC review gates (same pattern as every A3-onward phase).

**Does NOT include:**
- PMTU-blackholing scenario (drop ICMP frag-needed) — requires PLPMTUD (RFC 8899), Stage 2 (§10.8 explicit).
- Performance / latency metrics under netem — owned by A10's `bench-stress`. Any perf regressions surfaced here are filed back as A10 follow-ups, not fixed in A10.5.
- Layer G WAN A/B vs Linux — Stage 2 (S2-A), needs HW tap + real exchange testnet + tap-jitter calibration.
- New counters or events — Layer H asserts against the existing observability surface. If a scenario reveals a gap, it's filed for a later phase, not smuggled into A10.5.
- Fuzzing or proptest coverage — A9 territory.

**Dependencies:** A10 (netem harness + `bench-stress` scaffolding), A9 (FaultInjector for composed RX + WAN adversity). Blocks A11.

**Rough scale:** ~6–8 tasks (netem matrix runner reusing A10 scaffolding, assertion-table framework, ~5 scenario implementations plus composed RX+WAN cases, CI smoke + per-stage-cut wiring, end-of-phase review reports).

---

## A11 — Stage 1 ship gate verification

**Goal:** Run every Stage 1 gate from spec §10.10 and §11.9. Publish the results as the Stage 1 ship artifact.

**Spec refs:** §10.10, §11.9.

**Deliverables:**
- Documented pass matrix: Layer A unit tests (100%), Layer B packetdrill runnable subset (100%), Layer C tcpreq MUST rules (100%), Layer H netem correctness matrix (100% of Stage 1 scenarios from A10.5), observability smoke, e2e smoke against chosen test peer (§13 nice-to-have resolved), §11 microbench targets met, §11.3 e2e p999 within documented bound of HW RTT, §11.4 stress matrix all green.
- `docs/superpowers/reports/stage1-ship-report.md` — signed off with commit SHAs and host/NIC/DPDK versions.

**Does NOT include:** the `stage-1-ship` git tag — that moves to A12 after documentation lands.

**Dependencies:** A1–A10.5 all complete.

**Rough scale:** ~5 tasks (mostly verification + reporting).

---

## A12 — Documentation (user + maintainer + future-work) + Stage 1 release tag

**Goal:** Ship `libdpdk_net` with structured documentation sufficient for (a) users to integrate and operate, (b) future maintainers to extend and fix, and (c) a durable record of considered-but-deferred work. Each audience gets its own directory tree under `docs/` with one focused markdown file per topic, linked from a directory-level index. Places the `stage-1-ship` tag at the end of this phase.

**Spec refs:** §2.1 (stage scoping), §3 (threading), §4 (public API), §5–§9 (internals), §10 (testing), §11 (benchmarks), §12 (out of scope), §13 (open questions).

**Documentation tree:**

```
docs/
├── user-guide/
│   ├── README.md                 Index + when-to-read-what
│   ├── 01-overview.md            What it does, what it deliberately doesn't, positioning vs Linux TCP and vs mTCP
│   ├── 02-build-and-link.md      DPDK 23.11 + hugepage + VFIO prereqs, cargo build, cbindgen-generated header, C++ link
│   ├── 03-lifecycle.md           EAL init → engine_create → connect → poll → send/recv events → close → engine_destroy, with sequence diagram
│   ├── 04-configuration.md       Every `dpdk_net_engine_config_t` field from §4, trading-latency defaults vs preset=rfc_compliance, when to use which
│   ├── 05-threading-model.md     One-engine-per-lcore, RTC, pinning contract from §3, what breaks if violated
│   ├── 06-send-and-receive.md    `dpdk_net_send` semantics (copy-on-accept, partial accept, backpressure), READABLE event data-ptr lifetime, WRITABLE (A6)
│   ├── 07-close-and-timewait.md  FIN flow, TIME_WAIT duration, FORCE_TW_SKIP and RFC 6191 §4.2 gating
│   ├── 08-error-handling.md      Negative-errno conventions, DPDK_NET_EVT_ERROR enumeration, mempool exhaustion, peer-unreachable
│   ├── 09-counters.md            Every counter from §9.1 — meaning, expected steady-state, red-flag patterns
│   ├── 10-events.md              Every event from §9.2 — when emitted, payload semantics, ordering guarantees
│   ├── 11-limitations.md         Wire-compat subset vs Linux, **features not implemented** (ECN, IPv6, keepalive, TFO, dynamic ARP, etc.), TIME_WAIT, stage bounds. Pairs with 14-rfc-deviations: this section covers what's absent; 14 covers what's implemented-but-deliberately-different.
│   ├── 12-troubleshooting.md     "No SYN-ACK", "peer window zero", "stuck in SYN_SENT", "RST on unmatched", "TIME_WAIT exhaustion" — counter-symptom driven
│   ├── 13-order-entry-telemetry.md  Playbook for trading apps: how to tag every outbound order with stack-state snapshots (counters + `dpdk_net_conn_stats` for per-conn send-path + RTT) and the event log, then reconstruct what happened during congestion episodes. Complements 09-counters (dictionary) and 10-events (dictionary) with end-to-end recipes. Sections: (a) per-order telemetry pattern — pre-send + on-ACK stats snapshot, `snd_nxt` / `snd_wnd` / `send_buf_bytes_pending` / `srtt_us` / `rttvar_us` / `min_rtt_us` / `rto_us` tagging, event-log capture; (b) congestion-episode reconstruction — the six canonical patterns (`rx_zero_window↑` = peer/exchange slow, `send_buf_full↑` + partial send = our buffer saturating, `tx_rto↑` / `tx_rack_loss↑` (A5) = path loss, `rx_dup_ack↑` + high `rx_sack_blocks` = reorder not loss, `conn_timeout_retrans↑` = session dying, `tx_zero_window↑` + `recv_buf_drops↑` = our consumer slow), each with a concrete counter+event trace, a companion `stats()`-snapshot trace showing SRTT/RTTVAR/min_RTT trajectories, and the "what to do about it" action (reconnect, parallel connection, `rack_aggressive=true`, app-side pacing); (c) leading vs lagging indicators — `srtt_us` rise and `rttvar_us` spike often precede `send_buf_full` or `rx_zero_window` crossing into pathological territory, so apps can trigger mitigation earlier by watching RTT ratios (`srtt_us / min_rtt_us`) alongside counters; (d) aggressive-retry strategies the library's primitives enable but do not implement (parallel sockets, duplicate-clOrdID across connections, A5's `rto_no_backoff`, A5.5's per-connect TLP knobs `tlp_pto_min_floor_us=0` / `tlp_pto_srtt_multiplier_x100=100` / `tlp_skip_flight_size_gate=true` / `tlp_max_consecutive_probes≤5` / `tlp_skip_rtt_sample_gate=true`), with explicit notes on where stack ends and app orchestration begins; (e) the `obs.events_dropped` / `obs.events_queue_high_water` signal (A5.5) and what it means when nonzero during an episode; (f) **TLP self-tuning recipe** — app tracks `tcp.tx_tlp_spurious / tcp.tx_tlp` across a rolling window; ratio above ~3–5% means the aggressive PTO floor is firing probes before peer ACKs realistically arrive, so the app raises `tlp_pto_min_floor_us` on the offending socket (re-connect with new opts, since this is a connect-time knob). Targets a steady-state spurious rate under 5% while keeping the fastest PTO the path tolerates. Worked example from a simulated stall: raw counter-snapshot stream + per-conn `stats()` trajectory + event log reconstructed into a human-readable timeline.
│   └── 14-rfc-deviations.md     Comprehensive reference for every deliberate divergence from the RFCs the stack claims to implement. Audience: integrators doing interop testing, users porting code from kernel TCP, anyone asking "is this stack RFC-compliant for purpose X?" Organized by RFC (one section per RFC, ordered by RFC number): each section lists every deviation as a small structured entry carrying RFC clause citation (e.g., "RFC 6298 §2.4"), the RFC's literal text (a single-sentence quote or paraphrase), our stack's behavior, rationale (usually "trading fail-fast latency" or "scope bound"), config knob if any (per-conn opt-in / opt-out or engine-wide), and a cross-link to the relevant per-phase RFC-compliance review report in `docs/superpowers/reviews/phase-aN-rfc-compliance.md`. A quick-scan summary table at the top lists every deviation in one-line form so readers can grep for an RFC or keyword; the per-RFC sections below provide the detail. Canonical RFCs covered at Stage 1 ship: RFC 791 (IP), 793bis (TCP core), 1122 (TCP requirements), 2018 (SACK), 2883 (DSACK), 5681 (CC — dup_ack strictness etc.), 6191 (TIME_WAIT assessment), 6298 (RTO: minRTO 5ms / maxRTO 1s / no-backoff opt-in via `rto_no_backoff`), 6528 (ISS: SipHash + boot_nonce + 4µs ticks), 7323 (WS>14 clamp + TS.Recent 24-day expiration deferred), 8985 (RACK-TLP: reo_wnd static baseline + per-conn `rack_aggressive` + all five A5.5 TLP knobs `tlp_pto_min_floor_us` / `tlp_pto_srtt_multiplier_x100` / `tlp_skip_flight_size_gate` / `tlp_max_consecutive_probes` / `tlp_skip_rtt_sample_gate`), 9293 (TCP requirements baseline). Each deviation table entry also marks whether the deviation is *default-on* (the stack behaves this way without opt-in) or *opt-in* (user must flip a knob to see the deviation); interop testers especially care about the default-on set. Update policy: this document is the single source of truth for RFC deviations going forward; `future-work/02-rfc-deviations.md` becomes a pointer here rather than a parallel consolidation. Maintenance: when a phase RFC-compliance review adds a new §6.4 row to the parent spec, a corresponding entry lands in this document as part of the same phase's doc-update commit; CI check diff-compares §6.4 row count against entry count in this document to catch drift.
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
    ├── 02-rfc-deviations.md      **Pointer** to the user-facing consolidation at `user-guide/14-rfc-deviations.md` (single source of truth), plus this file's own scope: per-phase-review historical record — each `docs/superpowers/reviews/phase-aN-rfc-compliance.md` is summarized here as a short section so a Stage 2 maintainer can scan "what was accepted in which phase and why" without reading every review report. The user-guide version is organized by RFC (reader-facing); this file is organized by phase (history-facing). Also hosts any *proposed* deviations under consideration for Stage 2 or later that haven't yet landed in the user-guide consolidation.
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

**Rough scale:** ~14 tasks — 5 for the user-guide tree (index + 14 sections grouped into ~5 commits by theme: overview/build/lifecycle, config/threading/send-recv/close, errors/counters/events/limitations/troubleshooting, a dedicated commit for 13-order-entry-telemetry since it pulls together counter + event + send-state material into a trading-specific forensics playbook with a worked example, and a dedicated commit for 14-rfc-deviations since it aggregates content from every phase RFC-compliance review + spec §6.4 and lands alongside the CI drift check), 4 for the maintainer-guide tree (architecture+invariants, state+options+flow+timers+iss+mempool, ffi+tests+bench, reviews+debugging+conventions), 2 for the future-work tree (reviews-consolidation + remainder), 1 for the TODO-audit script, 1 for root README+CHANGELOG refresh, 1 for the tag.

---

## A13 — HTTP/1.1 + TLS client integration + bench (via `contek-io/cpp_common`)

**Parallelism note:** A13 and A14 are **independent of each other** and can (and should) run in parallel once A12 is complete. Whichever starts first lands the `Transport` abstraction in `contek-io/cpp_common` (see shared groundwork below); the other rebases onto it. Both phases depend on A12 (ship tag) but not on each other.

**Framing:** This phase does not add HTTP, TLS, or WebSocket to `libdpdk_net` — Stage 1 stays raw-TCP (spec §1 / §2.1). Instead, it validates that the Stage 1 byte-stream API is fit-for-purpose for a real HTTP/1.1 + TLS client that lives **outside** the stack, in the user's existing C++ library `contek-io/cpp_common`. `libdpdk_net` sees only the encrypted byte stream; TLS handshake + record layer + HTTP/1.1 parsing all happen inside `cpp_common` as today.

**Goal:** Prove the byte-stream API is enough for a real HTTP/1.1 + TLS client. Build `cpp_common`'s HTTP client on top of a new `dpdk_net`-backed transport; run integration tests against a TLS HTTP server; benchmark p50 / p99 / p999 latency against the same client on kernel TCP as the comparator baseline.

**Spec refs:** §4 (public byte-stream API), §5.3 (buffer ownership — application owns TLS buffering), §6.4 (trading defaults like Nagle off / delayed-ACK off apply cleanly to encrypted byte streams), §11 (benchmark plan — this extends it with an HTTP+TLS bucket).

**Upstream prerequisite (shared with A14 — whichever phase starts first lands this):**

- `contek-io/cpp_common` PR: add a `Transport` abstraction (C++ interface) with two concrete impls:
  - `KernelTransport` — existing behavior, wraps POSIX `::send` / `::recv` / epoll on a kernel socket.
  - `DpdkNetTransport` — wraps `dpdk_net_connect` / `dpdk_net_send` / `dpdk_net_poll` (consumes `DPDK_NET_EVT_READABLE` / `WRITABLE` / `CLOSED` / `ERROR`) behind the same `Transport` interface.
- Existing HTTP/1.1 and WebSocket clients in `cpp_common` are ported to consume the `Transport` interface rather than the POSIX socket API directly.
- TLS layer in `cpp_common` (OpenSSL or rustls-backed, whichever cpp_common uses today) is unchanged except that its BIO / read-callback-write-callback pair sits on top of `Transport` instead of a raw socket FD. Both transports look identical to the TLS code.
- cpp_common unit tests: `Transport` contract tests pass on both impls; end-to-end `GET https://<server>/echo` yields byte-identical responses on both.

The PR is reviewed and merged in `contek-io/cpp_common`'s own process; this repo's phase depends on the merge landing but the PR itself is tracked out-of-tree.

**Deliverables (this repo):**

- `tools/bench-http-tls/` — C++ harness that uses `cpp_common`'s HTTP/1.1 + TLS client configured with `DpdkNetTransport`; drives a mixed request workload against a TLS HTTP server; measures end-to-end latency (`send_request` → `full_response_parsed`); writes CSV in the same schema as `tools/bench-vs-linux` so `tools/bench-report` (A10) handles it.
  - Workload mix (three independent sub-benches):
    1. `small-get`: 100 B request, 1 KB response, new connection per request — measures TLS handshake cost under the stack.
    2. `keep-alive-get`: same sizes but persistent connection, 10 000 sequential requests — measures steady-state request-response RTT.
    3. `post-body`: 4 KB request body, 200 response, keep-alive — measures TX chain + TLS write-path behavior.
  - Comparator runs: same harness, same server, `KernelTransport`. Reported per sub-bench as `dpdk_p99 − kernel_p99` (after the §11.1 measurement-discipline preconditions).
- `tools/bench-http-tls/SERVER.md` — documents the test server matrix:
  - Local CI server: `nginx` with a self-signed cert + TLS 1.3 enabled + `/echo`, `/small`, `/large` endpoints. Containerized so CI is reproducible. TLS cert pinning documented.
  - Release validation server: a real exchange REST testnet (venue TBD by the user; the doc enumerates which venues the cpp_common client already connects to today, and selects one for the published numbers).
- Integration test in `tests/` (cargo + cmake mixed crate): one end-to-end HTTP+TLS request/response exercising `dpdk_net_connect → send → poll → recv events → close`, asserting byte-identical response vs kernel transport.
- Results artifact: `docs/superpowers/reports/app-fit-http-tls.md` — CSV of p50 / p99 / p999 per sub-bench × per transport, delta vs kernel, plus a bug/gap section listing any issues found in `libdpdk_net` or `cpp_common` with links to the fix commits / upstream PRs.

**Does NOT include:**
- TLS, HTTP/1.1, or HTTP/2/3 implementations inside `libdpdk_net` — these stay in Stage 3 / Stage 4 (spec §2.1) and are explicitly out of Stage 1.
- Parsing HTTP inside the library (Stage 3).
- Server-side HTTP (spec §1 explicitly: no production server-side TCP).
- Benchmark-harness work that duplicates A10 — this reuses A10's measurement-discipline checker, CSV writer, and `bench-report` dashboard.

**Dependencies:** A12 (Stage 1 ship tag exists; documentation-level API contract frozen). **Not dependent on A14** — A13 and A14 run in parallel.

**Rough scale:** ~10 tasks (cpp_common `Transport` abstraction + upstream PR if not yet landed; cpp_common HTTP/1.1-on-Transport port; `bench-http-tls` harness + 3 sub-benches; test server setup + CI container; integration test; CSV writer wiring into `bench-report`; kernel-transport comparator run; p99-delta evaluator; report generator; any `libdpdk_net` bugfix cycles uncovered by the run).

---

## A14 — WebSocket + TLS client integration + bench (via `contek-io/cpp_common`)

**Parallelism note:** See A13 — A13 and A14 are independent of each other and run in parallel after A12. Shared `Transport` abstraction in `cpp_common` is a one-time groundwork landed by whichever phase starts first.

**Framing:** Mirror of A13 for the WebSocket + TLS client in `cpp_common`. Validates the byte-stream API under a long-lived, asymmetric-traffic (server-push) workload typical of market-data WebSocket feeds — a more demanding shape than HTTP/1.1 request-response, and the dominant real-world consumer of the stack in trading deployments.

**Goal:** Prove the byte-stream API is enough for a real WebSocket + TLS client under market-data-shaped traffic. Build `cpp_common`'s WS client on top of the `DpdkNetTransport`; run integration tests against a TLS WS echo server; benchmark server-push latency and echo RTT against the kernel-transport baseline.

**Spec refs:** §4, §5.3, §6.4, §11.

**Upstream prerequisite (shared with A13):** Same `Transport` abstraction in `cpp_common` as A13 describes. The WS client is ported to consume `Transport`; TLS layer unchanged. If A13 landed the PR first, A14 rebases; if A14 lands first, A13 rebases. The upstream PR covers both clients together unless the phases are genuinely interleaved.

**Deliverables (this repo):**

- `tools/bench-ws-tls/` — C++ harness using `cpp_common`'s WS + TLS client on `DpdkNetTransport`. Two independent sub-benches:
  1. `echo-rtt`: small (64 B) frames in a tight request → server echoes → measure RTT loop, 10 000 frames post-warmup. p50 / p99 / p999 RTT. Exercises the stack's per-segment TX/RX path under encrypted framing.
  2. `server-push`: connect, subscribe-pattern (configurable topic list), server pushes binary frames at sustained ~1 MB/s for 60 s with a realistic frame-size distribution (most 200 B, occasional 4 KB, rare 64 KB). Measure per-frame `server_push_send_ts → DPDK_NET_EVT_READABLE delivered` latency. Drives the canonical market-data shape.
- `tools/bench-ws-tls/SERVER.md` — documents the test server matrix:
  - Local CI server: `websocketd` or a small purpose-built server wrapping an echo + configurable-push endpoint, with TLS 1.3 + self-signed cert. Containerized. Push-rate and frame-size distribution configurable per bench run.
  - Release validation: a real exchange WebSocket market-data testnet (venue TBD; document which venues cpp_common connects to today and pick one).
- Integration test: WS handshake → subscribe → receive N frames → close cleanly; asserts byte-identical frame payloads vs kernel-transport run.
- Frame-size coverage: small (64 B), medium (1 KB), large (64 KB) — exercises WS frame fragmentation in cpp_common and `libdpdk_net`'s single-mbuf vs mbuf-chain paths.
- Results artifact: `docs/superpowers/reports/app-fit-ws-tls.md` — CSV + percentile table per sub-bench × per transport, delta vs kernel, per-frame-size decomposition for the large end, plus bug/gap section. Same schema as A13's report so both can be consumed by a single dashboard.

**Does NOT include:**
- WebSocket implementation inside `libdpdk_net` (spec §2.1 Stage 5, and §12 explicitly for `permessage-deflate` — that stays permanently out of scope).
- Server-side WebSocket (spec §1 no production server-side).
- TLS implementation inside `libdpdk_net`.
- HTTP/1.1 handshake upgrade path — cpp_common owns the WS upgrade; this repo only sees the encrypted byte stream after upgrade.

**Dependencies:** A12. **Not dependent on A13** — A14 and A13 run in parallel.

**Rough scale:** ~10 tasks (cpp_common WS-on-Transport port — shared upstream PR with A13 if it hasn't landed; `bench-ws-tls` harness + 2 sub-benches; test server setup + CI container; integration test with frame-size coverage; CSV writer wiring; kernel-transport comparator; p99-delta evaluator; report generator; bugfix cycles for any issues uncovered).

---

## S2-A — Differential-vs-Linux fuzz + Layer G WAN A/B

**Goal:** Differential-vs-Linux fuzzing (deferred from A9) + Layer G WAN A/B harness (spec §10.7). Both share Linux-oracle infrastructure; unified phase introduces it once.

**Spec refs:** §10.5 (Layer E), §10.7 (Layer G).

**Deliverables:**
- `preset=rfc_compliance` engine-wide knob (cc_mode=reno, delayed-ACK on ~40 ms, minRTO=200 ms, Nagle default) — ownership: this phase if A7 hasn't introduced it for packetdrill needs
- `third_party/tcp-fuzz/` submodule (zouyonghao/TCP-Fuzz)
- `tools/tcp-fuzz-differential/` driver running libdpdk_net + Linux TCP in same-host netns; divergence-normalisation layer (ISS, TSecr skew, etc.)
- `tools/wan-ab-bench/` — pcap replay + HW-timestamp tap harness + tap-jitter calibration
- §6.4 deviation row for `preset=rfc_compliance`; knob-coverage scenario in `tests/knob-coverage.rs` (if not already introduced by A7)
- CI smoke + per-stage-cut 72 h run extensions

**Dependencies:** A11 (Stage 1 ship). S2-A is the first Stage 2 hardening phase.

**Rough scale:** ~14 tasks (~6 differential + ~8 Layer G).

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

### Preset=rfc_compliance ownership

The `preset=rfc_compliance` engine-wide knob (cc_mode=reno, delayed-ACK on ~40 ms, minRTO=200 ms, Nagle default) is owned by whichever Stage-1 phase first needs it:

- If A7 curates a packetdrill subset that includes scripts requiring RFC behaviour, A7 introduces the preset.
- If A7's runnable subset matches trading-latency defaults (RFC-only scripts marked SKIPPED), Stage-1 ships without the preset; S2-A introduces it for differential + Layer G.

A9 does NOT introduce the preset (differential-vs-Linux deferred; all A9 fuzz/property tests operate against the engine's default config or override individual knobs per test case).
