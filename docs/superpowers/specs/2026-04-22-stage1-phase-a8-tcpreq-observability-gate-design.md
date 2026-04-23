# Stage 1 — Phase A8: tcpreq + observability gate (design)

Date: 2026-04-22
Status: Draft, pending user approval
Branch: `phase-a8` (off tag `phase-a7-complete`)
Parent spec: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` (§9.1.1, §10.3, §10.10)
Roadmap row: `docs/superpowers/plans/stage1-phase-roadmap.md` §A8 (L549–580)
Predecessor: `docs/superpowers/specs/2026-04-21-stage1-phase-a7-loopback-test-server-packetdrill-shim-design.md`

---

## 1. Purpose and scope

Phase A8 lands the Stage 1 **test-correctness spine**: the tcpreq
conformance gate (narrowed to the probes that add signal beyond Layer A),
an observability smoke test that pins every counter value + event
sequence in a known scenario, full counter and knob coverage audits,
and the follow-ups that clear every open A7-flagged promotion gate.

The phase is deliberately broad — it collects under one roof everything
A7's review subagents flagged for "A8+" promotion, everything
SKIPPED.md tagged "A8 owner", and the roadmap's mandatory A8
deliverables. The end-state is a Stage 1 ship-gate-ready test surface:
every `MUST` clause in RFC 793bis has a citation, every counter in
`counters.rs` has a scenario that proves it is reachable, every
behavioral knob has a scenario that proves it changes behavior, and
every A7 Accepted-Deviation with an A8 promotion gate is retired.

### 1.1 In scope

Eight parallel workstreams grouped into three tracks.

**Roadmap-mandatory track** (M1–M3 — the §A8 deliverables):

- **M1 — observability smoke** (`crates/dpdk-net-core/tests/obs_smoke.rs`).
  One scripted scenario (connect → 3WHS → 4 sends, withhold ACK on
  send 3, advance past RTO, observe 1 RTO-driven retransmit, deliver
  cumulative ACK, send 4, active close, advance past 2·MSL, observe
  TIME_WAIT reap). Exhaustive assertion table covering: every declared
  `AtomicU64` counter (exact value), every emitted event (kind +
  conn handle + ordinal), every `state_trans[from][to]` cell. Fail-loud
  discipline: walk every counter in the compile-time enumeration and
  fail if any non-zero counter is not in the expected table.

- **M2 — counter-coverage audit** (`scripts/counter-coverage-static.sh`,
  `crates/dpdk-net-core/tests/counter-coverage.rs`,
  `tests/deferred-counters.txt`, `tests/feature-gated-counters.txt`).
  Two-phase check:
  - *Static*: parse every `AtomicU64` field across `EthCounters` /
    `IpCounters` / `TcpCounters` / `PollCounters` / `ObsCounters` /
    `FaultInjectorCounters` via a compile-time enumeration emitted by
    a declarative macro; regex-sweep the `crates/` tree for
    `fetch_add`, `counters::inc`, `counters::add`, `.store` call sites
    matching each field path; fail if any declared counter has zero
    increment sites AND is not in the deferred or feature-gated
    whitelist. Runs twice: `--no-default-features` and `--all-features`;
    the union must cover every counter.
  - *Dynamic*: one `#[test]` per counter in `counter-coverage.rs` that
    drives the minimal packet sequence exercising that counter's
    increment site and asserts the counter ended `> 0`.
  - *`state_trans[11][11]` coverage*: exhaustive 121-cell table with
    each cell tagged `Reached(scenario_fn, expected_count)` or
    `Unreachable("§6.1 FSM — <reason>")`. Test iterates every cell;
    Reached cells must increment under their scenario; Unreachable
    cells must stay 0 across every Reached scenario (catches
    accidentally-opened edges).
  - Removes dead `rx_out_of_order` field (declared since A1, never
    incremented; A3 review I-1 flagged this; A4 reassembly superseded
    the original OOO-drop semantic). Default-build ABI churn; acceptable
    pre-Stage-1-ship.

- **M3 — knob-coverage audit extension** (`crates/dpdk-net-core/tests/
  knob-coverage.rs` + informational-whitelist + a new CI static-check).
  A7 introduced no new behavioral runtime knob (AD-A7-no-syn-ack-retrans
  fix in S1 reuses the existing active-open SynRetrans wheel; no new
  config field). A8 also introduces no new knob (per §4 Q4 decisions).
  Deliverable is a CI step that fails if any new field is added to
  `dpdk_net_engine_config_t` / `dpdk_net_connect_opts_t` without a
  knob-coverage or informational-whitelist entry.

**Layer-C + compliance-matrix track** (M4–M5 — Q1 B1 path):

- **M4 — tcpreq narrow port** (`tools/tcpreq-runner/`). New Rust crate
  depending on `dpdk-net`/`dpdk-net-core` with `test-server` feature.
  Four probes ported from the tcpreq 2020 Python codebase, selected
  because they add signal beyond what Layer A already covers:
  - `MissingMSS` (RFC 793bis MUST-15) — craft SYN with no MSS option,
    assert our `peer_mss` falls back to 536.
  - `LateOption` (MUST-5) — TCP option arriving in a non-SYN segment
    must be accepted. Exercises our post-ESTABLISHED option decoder.
  - `Reserved-RX` — reserved bits on inbound segment must be ignored.
    No coverage in existing suite; ~40 LoC gap.
  - `Urgent` (MUST-30/31) — URG-flagged segment with payload; asserts
    our documented deviation (URG dropped, `rx_urgent_dropped` bumps).
    The probe **passes** by pinning our dropped-with-counter behavior;
    the deviation itself is new spec §6.4 row `AD-A8-urg-dropped`.
  - `tools/tcpreq-runner/SKIPPED.md` enumerates tcpreq probes **not**
    ported (checksum, MSS-support, option-support, unknown-option,
    illegal-length, RST-flag, ISN-meta, liveness, ttl_coding) with
    the Layer A / Layer B citation that covers each.

- **M5 — compliance matrix** (`docs/superpowers/reports/
  stage1-rfc793bis-must-matrix.md`). One row per RFC 793bis / RFC 9293
  MUST clause in Stage 1 scope, columns for (clause id, clause text,
  RFC paragraph, test citation, status PASS/DEVIATION/DEFERRED). Drives
  the Stage 1 ship-gate "Layer C 100% MUST" claim in a reviewable
  artifact.

**A7-hangover track** (S1–S3 — A7 review + SKIPPED.md follow-ups):

- **S1 — AD-A7-\* promotions**. All four A7-flagged items fixed:
  - (a) passive SYN-ACK retransmit (AD-A7-no-syn-ack-retransmit,
    AD-3 mTCP) via the existing active-open SynRetrans wheel.
  - (b) listen-slot cleanup on SYN_RCVD→Closed
    (AD-A7-listen-slot-leak-on-failed-handshake).
  - (c) RST-in-SYN_RCVD → return-to-LISTEN per RFC 9293 §3.10.7.4 First
    (AD-A7-rst-in-syn-rcvd-close-not-relisten). Test-server scope only;
    production build still has no listen path.
  - (d) dup-SYN-in-SYN_RCVD with SEG.SEQ==IRS → SYN-ACK retransmit
    (mTCP AD-4 pattern, RFC 9293 §3.8.1 + §3.10.7.4 reading); SEG.SEQ
    != IRS → RST (AD-A7-dup-syn-in-syn-rcvd-silent-drop).
  Each fix adds a dedicated tap test; A7 review docs rewritten to
  mark each deviation retired.

- **S2 — shim passive drain**. Packetdrill-shim patch wiring the
  packetdrill main loop's `netdev_receive` to also drain
  `dpdk_net_test_drain_tx_frames` for server-side scripts, merging
  client and server TX intercept queues FIFO. Unlocks the ~36 ligurio
  `listen` / `close` / `shutdown` / `reset` scripts SKIPPED.md tags
  "A8+ server-side accept path not exercisable via shim".

- **S3 — corpus classification**. Run the A7 classifier against
  shivansh and google packetdrill corpora; pin runnable counts; replace
  SKIPPED.md's "_A8 owner_" placeholder stubs for both corpora with
  categorized entries identical in shape to the existing ligurio
  classification.

### 1.2 Out of scope

- TCP-Fuzz differential vs Linux (Stage 2 S2-A).
- Benchmark harness (A10); Layer H correctness under netem (A10.5);
  Stage 1 ship-gate verification (A11) — A8 contributes, does not
  complete.
- Multi-connection listen backlog (capacity > 1). ListenSlot stays
  capacity-1; no A8-scope test races multiple SYNs against one listener.
  Deferred to whenever a future gate actually needs it (not anticipated
  in Stage 1 — server FSM is test-only).
- Default-build server FSM promotion. Stays behind `feature =
  "test-server"`.
- URG implementation. Documented as `AD-A8-urg-dropped` in §6.4;
  Stage 1 byte-stream raw-TCP API has no URG consumer.
- Vendoring tcpreq as a Python submodule. Per Q1 B1, probes are ported
  to Rust for determinism + CI reliability + dropping the tracebox /
  middlebox detection which does not apply to an in-memory loopback.
- Any new runtime-behavioral config knob. All S1 fixes reuse existing
  fields. Stage 1 API surface stays stable across A7→A8.

---

## 2. Architecture

```
                   ┌────────────────────────────────────────────────┐
                   │  A8 test-correctness spine                     │
                   └────────────────────────────────────────────────┘

Roadmap track               Layer-C track              A7-hangover track
┌─────────────────┐         ┌──────────────────┐       ┌────────────────┐
│ M1 obs-smoke    │         │ M4 tcpreq-runner │       │ S1 AD-A7 fixes │
│ M2 counter      │         │    (4 probes)    │       │ (4 promotions) │
│    coverage     │         │                  │       │                │
│ M3 knob-extend  │         │ M5 compliance    │       │ S2 shim drain  │
│                 │         │    matrix        │       │ S3 shivansh +  │
│                 │         │    (RFC 793bis)  │       │    google      │
└────────┬────────┘         └────────┬─────────┘       └───────┬────────┘
         │                           │                         │
         ▼                           ▼                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  test-server cargo feature (A7) — server FSM, virt clock, TX        │
│  intercept, dpdk_net_test_* FFI                                     │
└─────────────────────────────────────────────────────────────────────┘
         │                           │                         │
         ▼                           ▼                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  dpdk-net-core engine (production build unchanged)                  │
└─────────────────────────────────────────────────────────────────────┘
```

**File layout additions:**

```
crates/dpdk-net-core/tests/
  obs_smoke.rs                       M1 — single scripted scenario
  counter-coverage.rs                M2 — dynamic per-counter table
  deferred-counters.txt              M2 — explicit-deferred whitelist
  feature-gated-counters.txt         M2 — per §9.1.1 feature-gated list
  ad_a7_syn_retrans.rs               S1(a) — passive SynRetrans
  ad_a7_slot_cleanup.rs              S1(b) — listen-slot-leak fix
  ad_a7_rst_relisten.rs              S1(c) — RST→LISTEN
  ad_a7_dup_syn_retrans_synack.rs    S1(d) — dup-SYN→SYN-ACK retrans

tools/tcpreq-runner/
  Cargo.toml
  SKIPPED.md
  src/lib.rs
  src/tests/mss.rs                   M4 — MissingMSS + LateOption
  src/tests/reserved.rs              M4 — Reserved-RX
  src/tests/urgent.rs                M4 — AD-A8-urg-dropped pin

tools/packetdrill-shim/
  patches/0006-server-drain.patch    S2 — new patch file
  SKIPPED.md (updated)               S1+S2+S3 — ligurio bucket moves +
                                       shivansh/google classification

scripts/
  counter-coverage-static.sh         M2 — two-build matrix driver
  ci-counter-coverage.sh             M2 — CI orchestrator

docs/superpowers/
  reports/stage1-rfc793bis-must-matrix.md   M5
  reviews/phase-a8-mtcp-compare.md          end-of-phase gate (parallel)
  reviews/phase-a8-rfc-compliance.md        end-of-phase gate (parallel)
```

**Modified production files (S1 + M2 behavior changes):**

```
crates/dpdk-net-core/src/
  engine.rs           S1 — passive SynRetrans arm, slot cleanup, RST→LISTEN,
                      dup-SYN dispatch
  tcp_input.rs        S1 — handle_syn_received RST and dup-SYN paths
  test_server.rs      S1 — clear_in_progress_for_conn helper
  counters.rs         M2 — remove rx_out_of_order, update _pad, emit
                      ALL_COUNTER_NAMES via macro
crates/dpdk-net/src/
  api.rs              M2 — remove rx_out_of_order mirror
include/
  dpdk_net.h          M2 — cbindgen regenerates; ABI consumers see removal
```

**New cargo features:** none. `test-server` stays as the only gate for
server FSM visibility. `tcpreq-runner` depends on
`dpdk-net/test-server`.

**FFI surface changes:** none in the default build. S1 changes are all
behind `test-server`. M2's `rx_out_of_order` removal is a default-build
ABI break — cbindgen regenerates; no external consumers exist at this
point on the roadmap.

---

## 3. Design decisions

This section records the Q&A decisions made during brainstorming. They
are load-bearing — the plan + implementation must honor them.

### 3.1 tcpreq integration: narrow Rust port (Q1 B1)

- **Rejected**: vendoring tcpreq as Python submodule + userspace bridge
  (raw-socket nondeterminism; tracebox/middlebox machinery irrelevant
  to in-memory loopback; Python+nftables prereqs for CI).
- **Rejected**: full Rust port of all 7 applicable probes (most
  duplicate Layer A coverage for zero marginal signal).
- **Chosen**: port only the 4 probes that add signal beyond Layer A —
  MissingMSS, LateOption, Reserved-RX, Urgent.
- **Consequence**: `SKIPPED.md` in `tools/tcpreq-runner/` enumerates
  the un-ported probes with Layer A / Layer B citations. The
  compliance matrix (M5) maps each RFC 793bis MUST clause to the
  test that actually covers it, not to a tcpreq probe we ported for
  show.

### 3.2 S1 fix readings (Q4)

- **(a) passive SYN-ACK retransmit**: reuse existing active-open
  SynRetrans wheel. No new config field. Budget shared with
  `tcp_max_retrans_count`.
- **(b) listen-slot cleanup**: clear `slot.in_progress` on every
  SYN_RCVD→Closed transition. No new API. No change to capacity-1
  slot shape.
- **(c) RST-in-SYN_RCVD → LISTEN**: return-to-LISTEN per RFC 9293
  §3.10.7.4 First, but only in the test-server path. Project rule
  "Never transition to LISTEN in production" (spec §6 line 365)
  preserved — production build has no listen path, so the rule is
  definitionally unbroken.
- **(d) dup-SYN-in-SYN_RCVD**: mTCP AD-4 pattern — SEG.SEQ == IRS →
  retransmit SYN-ACK (benign loss case); SEG.SEQ != IRS → RST. RFC
  9293 §3.10.7.4 Fourth "may" latitude.
- **No new knobs**: (a)–(d) all reuse existing config fields or no
  config at all. `dpdk_net_engine_config_t` / `dpdk_net_connect_opts_t`
  shapes unchanged.

### 3.3 Counter-audit machinery (Q3)

- **Rx_out_of_order**: removed (ABI churn before Stage 1 ship, ship-gate
  cleanliness wins).
- **Static audit**: regex-based call-site sweep + compile-time counter
  enumeration via a declarative macro. Syn-based parse rejected as
  heavier than needed; regex + macro-enum catches typo drift without
  a full parse.
- **Dynamic audit**: new `tests/counter-coverage.rs` parallel to
  `tests/knob-coverage.rs`. One `#[test]` per counter; shared helpers
  live in `tests/common/mod.rs`.
- **`state_trans`**: exhaustive 121-cell table. Reached cells keyed to
  scenario fns + expected counts; Unreachable cells cite §6.1 FSM for
  the reason; Unreachable cells must stay 0 across every Reached
  scenario (catches accidentally-opened edges).

### 3.4 Observability smoke shape (Q5)

- One big scripted scenario (not a suite of focused scenarios).
- Scenario shape: connect → 3WHS → 4 sends + 1 RTO retransmit →
  active close → 2·MSL reap. N=1 retransmits, M=6 state transitions,
  K=4 sends.
- Event assertions: kind + conn handle + ordinal position. No
  timestamp-equality (brittle vs virt-clock changes).
- Fail-loud-on-drift: iterate every declared counter; fail if any
  non-zero counter is not in the expected table.

---

## 4. Behavior changes — RFC citations

### 4.1 S1(a) passive SYN-ACK retransmit

`emit_syn_ack_for_passive` in `engine.rs` arms `SynRetrans` on the
existing timer wheel with deadline `now_ns + tcp_initial_rto_us`.
Wheel fire → retransmit via `emit_syn_ack_for_passive` again.
4th attempt budget-exhausted → conn ETIMEDOUT + `tcp.conn_timeout_syn_sent`
bumped + ERROR event emitted (matches active-open semantics).

- RFC 9293 §3.8.1 — segments in the retransmission queue MUST be
  retransmitted after an RTO interval.
- RFC 6298 §2 — RTO computation applies to SYN-ACK retransmit.
- Retires: AD-A7-no-syn-ack-retransmit (A7 review §Accepted deviation),
  mTCP AD-3 (A7 mTCP review §Accepted divergence).

### 4.2 S1(b) listen-slot cleanup

New helper `ListenSlot::clear_in_progress_for(&mut self, h: ConnHandle)`
called from every site that transitions a SYN_RCVD conn to Closed:
  - `handle_syn_received` RST arm (tcp_input.rs:373–380).
  - `handle_syn_received` bad-ACK arm (tcp_input.rs:395–401).
  - SYN_RCVD ETIMEDOUT path (new, added by (a) when budget exhausted).

- No direct RFC clause; promotion of A7-design-§1.1 scope narrowing.
  With S2 unlocking multi-probe corpora against a single listener,
  leaving `in_progress` stuck after a failed handshake wedges the
  listener for all subsequent SYNs.
- Retires: AD-A7-listen-slot-leak-on-failed-handshake (A7 review §Accepted
  deviation), mTCP AD-1-adjacent.

### 4.3 S1(c) RST-in-SYN_RCVD → LISTEN

`handle_syn_received` RST arm: set conn state to Closed as today, then
call new helper `Engine::re_listen_if_from_passive(conn_handle)`. Helper
locates the conn's originating listen slot by the conn's local
(ip, port), clears `slot.in_progress`, and leaves the slot ready to
accept a fresh SYN. Runs only when the engine is in test-server mode;
the helper is compile-gated on `feature = "test-server"`.

- RFC 9293 §3.10.7.4 First — "If the RST bit is set: If this connection
  was initiated with a passive OPEN, then return this connection to the
  LISTEN state and return."
- Spec §6 line 365 "Never transition to LISTEN in production" unchanged:
  production build has no listen path; the rule is scoped to production
  by construction.
- Retires: AD-A7-rst-in-syn-rcvd-close-not-relisten.

### 4.4 S1(d) dup-SYN-in-SYN_RCVD

`handle_syn_received`, on SYN-bit segment (current behavior drops
silently — tcp_input.rs:384–386):
  - If `seg.seq == conn.irs`: this is a benign peer-SYN-retransmit
    (peer's original SYN retransmitted because peer didn't see our
    SYN-ACK). Call `emit_syn_ack_for_passive(conn)` which will
    retransmit the SYN-ACK and reuse the existing wheel entry from
    (a). No state change.
  - Else (in-window SYN with SEG.SEQ != IRS): RFC says RST. Emit RST
    via `send_rst_unmatched(seg)` and transition conn to Closed
    (re-using the (b) cleanup path).

- RFC 9293 §3.10.7.4 Fourth — "If the SYN bit is set in these
  synchronized states, it may be either a legitimate new connection
  attempt [...] or an error [...]. For the TCP implementation supporting
  Simultaneous Open, [...]; otherwise, send a reset segment [...]".
  MTCP reads "legitimate new connection attempt" to include the
  benign SYN retransmit case (SEG.SEQ == IRS) and handles it by
  SYN-ACK retransmit per §3.8.1. A8 adopts the same reading.
- Retires: AD-A7-dup-syn-in-syn-rcvd-silent-drop, mTCP AD-4.

### 4.5 AD-A8-urg-dropped (new §6.4 row)

URG mechanism (RFC 9293 §3.8.2 + MUST-30/31) is not implemented;
URG-flagged inbound segments are dropped with `tcp.rx_urgent_dropped`
increment. Rationale: Stage 1 is a byte-stream raw-TCP API; exchange
venues do not use URG; implementing requires ~150 LoC of out-of-band-data
bookkeeping (segregated urgent-pointer buffer, `SO_OOBINLINE`-equivalent
semantics, URG-echo in TX) for zero trading value. Promotion gate: any
future phase that needs URG (not anticipated in Stage 1–5 per spec §1
non-goals) reopens this.

Citations: spec §1 non-goals + §6.3 deviation whitelist.
tcpreq's `urgent.py` probe pins this behavior (the probe passes by
asserting our documented drop).

---

## 5. Counters, knobs, events

### 5.1 Counters

**Removed** (M2):
- `tcp.rx_out_of_order` — declared since A1, never incremented,
  superseded by `rx_reassembly_queued` at A4.

**No new counters in A8.** All behavior changes use existing counters
(`conn_timeout_syn_sent`, `tx_syn`, `tx_rst`, `conn_rst`, `rx_unmatched`,
`state_trans` matrix).

**Deferred whitelist** (`tests/deferred-counters.txt`) post-A8: empty.
Every `AtomicU64` field has an increment site.

**Feature-gated whitelist** (`tests/feature-gated-counters.txt`):
- `tcp.tx_payload_bytes` — `obs-byte-counters` (default OFF).
- `tcp.rx_payload_bytes` — `obs-byte-counters` (default OFF).
- `poll.iters_with_rx_burst_max` — `obs-poll-saturation` (default ON,
  reachable in default build).
- `fault_injector.*` (drops, dups, reorders, corrupts) —
  `fault-injector` feature; reachable only in all-features build.

### 5.2 Knobs

**No new knobs in A8.** `dpdk_net_engine_config_t` and
`dpdk_net_connect_opts_t` shapes are byte-identical to phase-a7-complete.

New CI gate: any PR adding a field to either config struct must either
add an entry to `tests/knob-coverage.rs` or add to
`tests/knob-coverage-informational.txt`. The existing static-check
script is extended with this assertion.

### 5.3 Events

**No new event kinds.** S1(a)'s ETIMEDOUT emits the existing
`DPDK_NET_EVT_ERROR{err=-ETIMEDOUT}` from the conn_timeout_syn_sent
site. S1(c) and S1(d) emit `DPDK_NET_EVT_TCP_STATE_CHANGE` for the
transitions they induce.

---

## 6. Testing + CI gates

### 6.1 New CI jobs (`.github/workflows/a8-*.yml`)

- **`a8-counter-coverage.yml`**: runs `scripts/ci-counter-coverage.sh`
  which drives two `cargo` builds (`--no-default-features` and
  `--all-features`), then `cargo test --test counter-coverage` and
  `cargo test --test obs_smoke` under default features. Fails on any
  counter drift or un-exercised scenario.
- **`a8-tcpreq-gate.yml`**: runs `cargo test -p tcpreq-runner` with
  all 4 probes. Gate rule: 100% pass. URG probe passes by asserting
  documented deviation.
- **`a8-packetdrill-corpus.yml`**: shim-driven runs for ligurio,
  shivansh, google corpora with S2 server-mode support. Per-corpus
  `RUNNABLE.txt` pins expected counts; any script failing after being
  classified runnable fails CI.

### 6.2 Phase tag criteria (`phase-a8-complete`)

Gate must satisfy **all** of:

1. All 8 workstream acceptance criteria (§7) green.
2. Both end-of-phase review gates pass:
   - `mtcp-comparison-reviewer` subagent (opus 4.7) → zero open `- [ ]`
     in `docs/superpowers/reviews/phase-a8-mtcp-compare.md`.
   - `rfc-compliance-reviewer` subagent (opus 4.7) → zero open `- [ ]`
     in `docs/superpowers/reviews/phase-a8-rfc-compliance.md`.
3. Counter-coverage audit green in both feature builds.
4. `obs_smoke` green and proves "remove any single `fetch_add` breaks
   the test" (acceptance: reviewer mutates one site locally and
   verifies the test fails).
5. tcpreq gate 4/4 green.
6. Ligurio runnable count moved from A7 floor (0/122) to pinned A8
   count (estimate ~36 per S1+S2 unlock; exact number pinned when
   S2 lands).
7. Shivansh + google corpora SKIPPED.md stubs replaced with categorized
   entries; `RUNNABLE.txt` pinned for each.
8. All 4 AD-A7-\* items retired; new AD-A8-urg-dropped documented in
   spec §6.4.
9. Every declared counter has an increment site (deferred list empty).
10. Every behavioral knob has a knob-coverage entry (informational list
    accurate).

---

## 7. Acceptance criteria per workstream

| # | Criterion |
|---|---|
| M1 | `obs_smoke.rs` green; removing any `fetch_add` site in the stack causes the test to fail; adding a spurious hot-path `fetch_add` fails. |
| M2 | Static audit green in both feature builds. Dynamic audit: one scenario per counter, each proves counter > 0. 121-cell `state_trans` matrix exhaustively classified. `rx_out_of_order` removed; cbindgen regenerated; C ABI mirror in `dpdk-net/src/api.rs` updated. |
| M3 | No new knob-coverage entries. New CI static check fails if a new config-struct field lands without a coverage or informational-whitelist entry. |
| M4 | 4 probes green. URG probe pins documented deviation. `tools/tcpreq-runner/SKIPPED.md` cites the un-ported tcpreq modules with Layer A/B citations. |
| M5 | `stage1-rfc793bis-must-matrix.md` has a row per Stage 1-scope MUST clause; no "TODO" rows; every row has a PASS / DEVIATION / DEFERRED status with citation. |
| S1 | 4 dedicated tap tests green. At least one previously-skipped ligurio script moves from skipped to runnable per fix. A7 review docs rewritten to mark each AD retired with A8 commit SHA. |
| S2 | Shim patch lands in `tools/packetdrill-shim/patches/0006-server-drain.patch`. Runner in server-mode drains both client and server TX intercepts FIFO. Smoke test `tools/packetdrill-shim-runner/tests/smoke_server_mode.rs` proves a ligurio `listen-incoming-*.pkt` script now runs. |
| S3 | SKIPPED.md `## shivansh corpus` and `## google upstream` sections are categorized (no "_A8 owner_" placeholders). Per-corpus `RUNNABLE.txt` pinned. |

---

## 8. End-of-phase review gates

Both reviewers run in parallel as the final A8 task (per durable memory
`feedback_phase_mtcp_review` and `feedback_phase_rfc_review`), with
opus 4.7.

- `mtcp-comparison-reviewer` subagent: pull the shared third_party/mtcp
  submodule, compare A8's passive-path changes (S1 fixes) against
  mTCP's equivalent handlers. Expected findings: most A7 Accepted
  Divergences (AD-1 capacity-1 listen, AD-3 no-retransmit, AD-4 dup-SYN
  silent-drop) retire because S1 fixes them. AD-2 (accept-queue-full
  RST at SYN) and AD-5 (option-bundle unconditional) remain accepted
  for A8 (listen backlog stays capacity-1 per §1.2 out-of-scope;
  option bundle is still behavioral-inert per A7 I-1).

- `rfc-compliance-reviewer` subagent: pull the vendored RFCs from
  `docs/rfcs/`; verify the S1 behavior changes against RFC 9293 §3.8.1,
  §3.10.7.4, RFC 6298 §2. Verify the M4 URG deviation is documented in
  §6.4. Verify M5 compliance matrix rows match the current RFC text
  exactly. Expected to be PASS with 1 new AD (AD-A8-urg-dropped)
  captured.

Tag `phase-a8-complete` is cut only when both reports are clean (zero
open `- [ ]`).

---

## 9. References

- `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` — master spec
  §9.1.1 (counter-addition policy), §10.3 (Layer C tcpreq),
  §10.10 (Stage 1 ship criteria), §6.3 (deviation matrix),
  §6.4 (accepted-deviation rows).
- `docs/superpowers/specs/2026-04-21-stage1-phase-a7-loopback-test-server-packetdrill-shim-design.md`
  — A7 spec (§1.1, §1.2, §3.3 scope narrowing that S1 promotes).
- `docs/superpowers/reviews/phase-a7-rfc-compliance.md` — source of
  the 4 AD-A7-\* entries + promotion gates.
- `docs/superpowers/reviews/phase-a7-mtcp-compare.md` — source of the
  5 A7 mTCP Accepted Divergences; S1 retires AD-1-adjacent, AD-3, AD-4.
- `docs/superpowers/plans/stage1-phase-roadmap.md` §A8 (L549–580) —
  roadmap-mandatory deliverables (M1–M3).
- `tools/packetdrill-shim/SKIPPED.md` — SKIPPED.md ligurio A8+ buckets
  (S1+S2 unlock targets) and shivansh/google "_A8 owner_" stubs (S3).
- `github.com/TheJokr/tcpreq` — tcpreq 2020 Python codebase; 4 probes
  ported, 7 probes cited-but-unported in `tools/tcpreq-runner/SKIPPED.md`.
- `third_party/mtcp/` — mTCP reference implementation for comparison
  (used by end-of-phase mtcp-comparison-reviewer subagent).
- `docs/rfcs/` — vendored RFCs 9293, 6298, 793bis, consumed by
  end-of-phase rfc-compliance-reviewer subagent.
