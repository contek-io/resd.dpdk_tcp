# Stage 1 Phase A10.5 — Layer H correctness under WAN-condition fault injection

**Status:** Design (2026-05-01)
**Phase:** Stage 1, A10.5 (correctness gate; runs serially between A10 and A11)
**Spec refs:** §10.8 (Layer H — Stage 1 subset only; PMTU-blackholing deferred to Stage 2), §10.10 (formalises the Stage 1 netem ship-gate smoke).
**Roadmap entry:** `docs/superpowers/plans/stage1-phase-roadmap.md` § A10.5.
**Dependencies:** A10 (netem harness + bench-stress scaffolding), A9 (FaultInjector). Blocks A11.

---

## 1. Goal

Promote spec §10.10's informal "end-to-end smoke under `tc netem` loss/delay" to a named Layer H test phase. A formal netem matrix with **liveness + invariant assertions, not performance measurement** — A10's `bench-stress` measures *how fast* the stack runs under adversity; A10.5 asserts *that the stack stays correct* under the same adversity.

The deliverable is a new binary `tools/layer-h-correctness` plus orchestrator scripts that run a 17-scenario matrix (14 base + 3 composed netem×FaultInjector) and emit pass/fail per scenario into a Markdown report at `docs/superpowers/reports/layer-h-<date>.md`.

## 2. Scope

### In scope

- New crate `tools/layer-h-correctness/` reusing `bench-stress`'s netem RAII, `bench-e2e`'s RTT workload, and `dpdk-net-core`'s public counter/event/state surfaces — only the assertion engine is net-new code.
- Netem matrix (Stage 1 subset of §10.8):
  - Delay: +20 ms, +50 ms, +200 ms (each with and without jitter) — 6 scenarios.
  - Loss: 0.1 %, 1 %, 5 % random; 1 % correlated bursts — 4 scenarios.
  - Duplication: 0.5 %, 2 % — 2 scenarios.
  - Reordering: depth 3 — 1 scenario.
  - Corruption: 0.01 % — 1 scenario.
- Composed adversity: one stressful netem (`loss 1% delay 50ms`) crossed with each of the three FaultInjector dimensions (drop, dup, reorder) — 3 composed scenarios.
- Per-scenario assertion table: connection stays in `ESTABLISHED` for the configured duration, no illegal `StateChange` events, `obs.events_dropped == 0` at steady load, scenario-specific counter expectations against existing observability surface.
- CI smoke: 5-scenario subset (one representative per netem dimension) per merge.
- Full matrix: 4 process invocations per stage cut (one for the 14 pure-netem rows, plus one per FI spec for the 3 composed rows). Merged into the canonical Markdown report.
- End-of-phase mTCP comparison + RFC compliance review gates (per spec §10.13, §10.14).

### Out of scope

- **PMTU-blackhole scenario** — requires PLPMTUD (RFC 8899), Stage 2 only (§10.8 explicit).
- **Performance / latency under netem** — owned by A10's `bench-stress`. Any perf regressions surfaced here are filed back as A10 follow-ups, not fixed in A10.5.
- **Layer G WAN A/B vs Linux** — Stage 2 (S2-A); needs HW tap + real exchange testnet.
- **New counters or events** — A10.5 asserts against the existing observability surface. If a scenario reveals a gap, it's filed for a later phase, not smuggled into A10.5.
- **Fuzzing or proptest coverage** — A9 territory.
- **Modifications to `dpdk-net-core`, `bench-stress`, or `bench-e2e`** — all reuse is read-only; the assertion shape, scenario matrix, and runner CLI live entirely inside `tools/layer-h-correctness/`.

## 3. Architecture

### 3.1 Crate layout

```
tools/layer-h-correctness/
├── Cargo.toml
├── src/
│   ├── lib.rs                # façade so tests/scenario_parse.rs imports modules
│   ├── main.rs               # CLI, EAL bring-up, scenario sweep, report write
│   ├── scenarios.rs          # static MATRIX of LayerHScenario rows
│   ├── assertions.rs         # Relation enum (>0, ==0, <=N), FSM oracle
│   ├── observation.rs        # poll-loop + event-stream replay, runs alongside workload
│   ├── workload.rs           # deadline-driven wrap of bench_e2e::run_rtt_workload
│   ├── report.rs             # Markdown report writer; failure-bundle JSON serializer
│   └── counters_snapshot.rs  # thin wrapper around dpdk_net_core::counters::lookup_counter
└── tests/
    ├── scenario_parse.rs           # matrix invariants
    ├── assertions_unit.rs          # FSM oracle + Relation parse/check
    └── external_netem_skips_apply.rs  # CLI smoke (no DPDK)
```

### 3.2 Dependencies

- `bench-stress` (lib only) — `NetemGuard`, peer-iface validators.
- `bench-e2e` (lib) — `open_connection`, `run_rtt_workload` (called in deadline-driven outer loop, not modified).
- `bench-common` — `RunMetadata`, preconditions parser. No percentile/aggregation use.
- `dpdk-net-core` — `Engine`, `EngineConfig`, `counters::lookup_counter`, `Counters` (for direct access to the `AtomicU32` `tcp.rx_mempool_avail` field which is intentionally absent from `lookup_counter`'s `&AtomicU64` table), `tcp_state::TcpState`, `tcp_events::InternalEvent`.
- `dpdk-net-sys` — `rte_eal_cleanup` only.
- `clap`, `anyhow`, `serde`, `serde_json`, `chrono`, `uuid`.

**Required cargo features.** The crate's `dpdk-net-core` dependency must enable `features = ["fault-injector"]` so the FaultInjector counters increment on composed-scenario runs. The corruption-row counter selection (§4 row 14) is offload-aware: with `hw-offload-rx-cksum` enabled the NIC drops cksum-bad mbufs and bumps `eth.rx_drop_cksum_bad`; with that feature off the SW path bumps `ip.rx_csum_bad`. The matrix asserts disjunctively over both counters so the row passes under either build profile (see §4 row 14 + §5.1).

The crate consumes `bench-stress`'s lib façade, not its binary. `counters_snapshot.rs` calls `dpdk_net_core::counters::lookup_counter` directly (the public master read function) for `AtomicU64` counters, and reads the `AtomicU32` `tcp.rx_mempool_avail` via direct field access on `engine.counters().tcp.rx_mempool_avail`.

`bench-stress`'s `enforce_single_fi_spec` is private to its `main.rs` and bound to bench-stress's own `Scenario` type. The new crate reimplements the ~10-line invariant against `LayerHScenario` locally — there is nothing to import.

### 3.3 Runtime model

Single lcore, RTC, no extra threads. The workload and the observation loop share the engine's poll cycle:

```
for scenario in selected:
    install netem (skip if --external-netem)
    open_connection; wait until ESTABLISHED
    snapshot_pre = lookup_counter(...) for each named counter (incl. global side-checks)
    drain events on the floor (clear handshake queue, including warmup events)
    deadline = now + scenario.duration
    while now < deadline:
        run_rtt_workload(N small iterations)
        ok = observe_batch(engine, conn, event_window):
          - if state_of(handle) != Established: fail-fast (FsmDeparted)
          - drain_events(MAX_PER_BATCH, |evt, _| {
              if StateChange { from: Established, to: != Established }: mark IllegalTransition
              event_window.push(evt)
            })
          - if engine.counters().tcp.rx_mempool_avail < MIN_RX_MEMPOOL_AVAIL: fail-fast (LiveCounterBelowMin)
          - if (obs.events_dropped delta this batch) > 0: fail-fast (EventsDropped — defensive)
        if !ok: break
    snapshot_post = lookup_counter(...) for each named counter (incl. global side-checks)
    for (name, relation) in scenario.expectations: collect_failures(...)
    for (counters, relation) in scenario.disjunctive_expectations: collect_failures(...)
    apply global side-checks (mbuf_refcnt_drop_unexpected==0)
    initiate close (transition outside assertion window)
    record verdict; write JSON bundle on fail
```

Periodic `state_of` poll runs once per outer iteration (after each batch of N RTT iterations). Event drain runs on the same cadence via `Engine::drain_events(max, |evt, &Engine| { ... })` — a callback-form API; there is no `drain_events_into` form. The closure both walks the FSM oracle and pushes into a 256-entry ring for the failure bundle.

### 3.4 Process model

EAL is once-per-process and `FaultConfig::from_env` reads `DPDK_NET_FAULT_INJECTOR` once at engine bring-up — same constraint bench-stress works under. Distinct FI specs require distinct process invocations. The driver enforces "single FI spec per invocation" at startup (`enforce_single_fi_spec`, identical pattern to bench-stress).

Full matrix → 4 process invocations:
1. The 14 pure-netem rows (no FI env var).
2. `composed_loss_1pct_50ms_fi_drop` (`DPDK_NET_FAULT_INJECTOR=drop=0.005`).
3. `composed_loss_1pct_50ms_fi_dup` (`dup=0.005`).
4. `composed_loss_1pct_50ms_fi_reord` (`reorder=0.005`).

CI smoke is one invocation (5 pure-netem rows, no FI scenarios in the smoke set).

## 4. Scenario matrix

`LayerHScenario` is a static-data row:

```rust
pub struct LayerHScenario {
    pub name: &'static str,
    pub netem: Option<&'static str>,
    pub fault_injector: Option<&'static str>,
    pub duration: Duration,
    pub smoke: bool,
    pub counter_expectations: &'static [(&'static str, &'static str)],
    /// Disjunctive groups: at least one counter in the group must satisfy
    /// the relation. Used for offload-aware corruption-counter selection
    /// (row 14): with `hw-offload-rx-cksum` on, `eth.rx_drop_cksum_bad`
    /// fires; with it off, `ip.rx_csum_bad` fires. Asserting both with OR
    /// means the row passes under either build profile.
    pub disjunctive_expectations: &'static [(&'static [&'static str], &'static str)],
}
```

Relation strings carry the bound inline (`">0"`, `"==0"`, `"<=10000"`). Pre-flight at driver startup parses every relation and resolves every counter name (`AtomicU64` counters via `lookup_counter`; the one `AtomicU32` counter — `tcp.rx_mempool_avail` — is read directly off `Counters` in §5.2 and not name-resolved through `lookup_counter`); unknown literals or unresolved counters fail at startup, never mid-sweep.

FSM legality is implicit on every row: during the assertion window, `state_of(handle)` must return `Established`, and no `StateChange { from: Established, to: ≠ Established }` events may appear. No per-row config; it's a global invariant.

**Global side-checks (apply to every row, never carried in `counter_expectations`):**

- `tcp.mbuf_refcnt_drop_unexpected` delta `== 0` over the assertion window. PR #9 plumbed this counter as a leak-detect signal — any non-zero delta means the cliff-fix invariant broke under adversity.
- `tcp.rx_mempool_avail` (`AtomicU32`, read directly off `Counters`) ≥ `MIN_RX_MEMPOOL_AVAIL` (= 32) at every observation tick. Catches near-exhaustion of the RX mempool — the precise failure mode PR #9 was chasing. Below the threshold ⇒ fail-fast with `LiveCounterBelowMin`.
- `obs.events_dropped` delta `== 0` per batch (defensive; the engine's bounded event queue overflowing means the FSM oracle could miss a `StateChange` event). The `obs.events_dropped == 0` end-of-scenario check in `counter_expectations` catches the same condition; the per-batch check just surfaces it earlier.

These three side-checks are wired in `observation.rs` and `assertions.rs`, not duplicated across each matrix row's `counter_expectations`.

| # | name | netem | FI | duration | smoke | counter_expectations |
|---|------|-------|-----|----------|-------|----------------------|
| 1 | `delay_20ms` | `delay 20ms` | — | 30 s | no | `tcp.tx_retrans==0`, `tcp.tx_rto==0`, `obs.events_dropped==0` |
| 2 | `delay_20ms_jitter_5ms` | `delay 20ms 5ms` | — | 30 s | no | `tcp.tx_retrans<=10`, `obs.events_dropped==0` |
| 3 | `delay_50ms` | `delay 50ms` | — | 30 s | no | `tcp.tx_retrans==0`, `tcp.tx_rto==0`, `obs.events_dropped==0` |
| 4 | `delay_50ms_jitter_10ms` | `delay 50ms 10ms` | — | 30 s | **yes** | `tcp.tx_retrans<=10`, `obs.events_dropped==0` |
| 5 | `delay_200ms` | `delay 200ms` | — | 30 s | no | `tcp.tx_retrans==0`, `obs.events_dropped==0` |
| 6 | `delay_200ms_jitter_50ms` | `delay 200ms 50ms` | — | 30 s | no | `tcp.tx_retrans<=20`, `obs.events_dropped==0` |
| 7 | `loss_01pct` | `loss 0.1%` | — | 30 s | no | `tcp.tx_retrans>0`, `tcp.tx_retrans<=10000`, `obs.events_dropped==0` |
| 8 | `loss_1pct` | `loss 1%` | — | 30 s | **yes** | `tcp.tx_retrans>0`, `tcp.tx_retrans<=50000`, `obs.events_dropped==0` |
| 9 | `loss_5pct` | `loss 5%` | — | 30 s | no | `tcp.tx_retrans>0`, `tcp.tx_retrans<=200000`, `obs.events_dropped==0` |
| 10 | `loss_correlated_burst_1pct` | `loss 1% 25%` | — | 30 s | no | `tcp.tx_retrans>0`, `tcp.tx_rto>0`, `tcp.tx_tlp>0`, `obs.events_dropped==0` |
| 11 | `dup_05pct` | `duplicate 0.5%` | — | 30 s | no | `tcp.rx_dup_ack>0`, `tcp.tx_retrans==0`, `obs.events_dropped==0` |
| 12 | `dup_2pct` | `duplicate 2%` | — | 30 s | **yes** | `tcp.rx_dup_ack>0`, `tcp.tx_retrans==0`, `obs.events_dropped==0` |
| 13 | `reorder_depth_3` | `delay 5ms reorder 50% gap 3` | — | 30 s | **yes** | `tcp.rx_dup_ack>0`, `tcp.tx_retrans==0`, `obs.events_dropped==0` |
| 14 | `corruption_001pct` | `corrupt 0.01%` | — | 30 s | **yes** | `obs.events_dropped==0`; **disjunctive**: `[eth.rx_drop_cksum_bad, ip.rx_csum_bad] >0` (at least one fires depending on `hw-offload-rx-cksum`) |
| 15 | `composed_loss_1pct_50ms_fi_drop` | `loss 1% delay 50ms` | `drop=0.005` | 30 s | no | `fault_injector.drops>0`, `tcp.tx_retrans>0`, `obs.events_dropped==0` |
| 16 | `composed_loss_1pct_50ms_fi_dup` | `loss 1% delay 50ms` | `dup=0.005` | 30 s | no | `fault_injector.dups>0`, `tcp.rx_dup_ack>0`, `obs.events_dropped==0` |
| 17 | `composed_loss_1pct_50ms_fi_reord` | `loss 1% delay 50ms` | `reorder=0.005` | 30 s | no | `fault_injector.reorders>0`, `tcp.rx_dup_ack>0`, `obs.events_dropped==0` |

**Notes on the matrix:**

- **Row 13 reorder spec carries a base `delay 5ms`.** `man tc-netem`: "to use reordering, a delay option must be specified". netem silently no-ops a reorder qdisc that lacks a delay, so the row would assert against a no-op without it. 5 ms is just large enough for reorder to fire without distorting the rest of the assertion. (Note: bench-stress's row carries the same bare `reorder 50% gap 3` string; that is a pre-existing bench-stress bug filed separately, not a layer-h concern.)
- **Reorder gap=3 expects `tx_retrans==0`.** Trading-latency preset uses 3-dup-ACK fast-retransmit. netem `reorder gap 3` produces dup-ACKs but does not cross the 3-dup-ACK trigger because the reorder gap matches the threshold (boundary case; RACK reorder window absorbs). If the preset later relaxes the trigger, this assertion gets revisited.
- **Corruption assertion is disjunctive over both checksum-bad counters.** With NIC checksum offload enabled (default for trading-latency preset), the NIC drops corrupted segments and bumps `eth.rx_drop_cksum_bad`. With offload off (`--feature-set rfc-compliance` / `hw-offload-rx-cksum` cargo feature off), the SW path bumps `ip.rx_csum_bad`. The matrix asserts the OR of the two counters' deltas being `>0`, so the row passes under either build profile without requiring runtime introspection of `Engine`'s private offload-active flags. The assertion engine implements this via the `disjunctive_expectations` field on `LayerHScenario` (§5.1).
- **Upper bounds** (`<=10000`, `<=50000`, `<=200000`) are deliberately generous. Their job is to catch *exponential ladders* and *retransmit-budget runaway* (which manifest as millions or billions), not to enforce a tight retransmit budget. Tightening is a follow-up if a real regression slips under them.
- **CI smoke set** = exactly 5 scenarios (rows 4, 8, 12, 13, 14) — one representative per netem dimension, per roadmap. Composed scenarios run only at full matrix (stage cut); each requires a fresh process invocation, which is too heavy for per-merge CI.
- **Global side-checks (every row, every batch)**: `tcp.mbuf_refcnt_drop_unexpected == 0`, `tcp.rx_mempool_avail >= MIN_RX_MEMPOOL_AVAIL` (32), `obs.events_dropped` per-batch delta `== 0`. These are PR #9 RX-leak-diagnostic side-checks; not repeated in each row's `counter_expectations`. See §5.1 + §5.2.

## 5. Assertion engine

### 5.1 Relation

```rust
pub enum Relation {
    GreaterThanZero,        // ">0"
    EqualsZero,             // "==0"
    LessOrEqualThan(u64),   // "<=N", N parsed from the string literal
}
```

`Relation::parse(&str)` extends bench-stress's existing parser only inside layer-h-correctness; bench-stress's own `Relation` enum is left alone (it doesn't need `<=N`). Pre-flight startup parses every row's relation strings and resolves every counter name through `dpdk_net_core::counters::lookup_counter`; failures surface at driver bring-up, never mid-sweep.

### 5.2 Observation loop

Between every batch of `OBSERVATION_BATCH = 100` workload iterations, the runner runs:

```rust
fn observe_batch(
    engine: &Engine,
    conn: ConnHandle,
    event_window: &mut EventRing,
    obs_events_dropped_pre: u64,
) -> Result<(), FailureReason> {
    // 1. Liveness: state_of must read Established.
    if engine.state_of(conn) != Some(TcpState::Established) {
        return Err(FsmDeparted { observed: engine.state_of(conn) });
    }

    // 2. Event-stream replay via the callback-form API (only form available;
    //    there is no `drain_events_into` — the closure both walks the FSM
    //    oracle and pushes into the failure-bundle ring).
    let mut illegal: Option<(TcpState, TcpState, usize)> = None;
    let mut idx = event_window.next_seq();
    engine.drain_events(MAX_DRAIN_PER_BATCH, |evt, _engine| {
        if illegal.is_none() {
            if let InternalEvent::StateChange { from, to, .. } = evt {
                if *from == TcpState::Established && *to != TcpState::Established {
                    illegal = Some((*from, *to, idx));
                }
            }
        }
        event_window.push(evt.clone(), idx);
        idx += 1;
    });
    if let Some((from, to, at_event_idx)) = illegal {
        return Err(IllegalTransition { from, to, at_event_idx });
    }

    // 3. RX-leak side-check: rx_mempool_avail is AtomicU32 and intentionally
    //    NOT in lookup_counter — read directly off Counters.
    let avail = engine.counters().tcp.rx_mempool_avail.load(Ordering::Relaxed);
    if avail < MIN_RX_MEMPOOL_AVAIL {
        return Err(LiveCounterBelowMin {
            counter: "tcp.rx_mempool_avail",
            observed: avail as u64,
            min: MIN_RX_MEMPOOL_AVAIL as u64,
        });
    }

    // 4. Defensive per-batch obs.events_dropped check — fail-fast if the
    //    engine's bounded event queue overflowed during this batch (would
    //    mean the FSM oracle could miss a StateChange event).
    let obs_dropped_now = engine.counters().obs.events_dropped.load(Ordering::Relaxed);
    if obs_dropped_now > obs_events_dropped_pre {
        return Err(EventsDropped { count: obs_dropped_now - obs_events_dropped_pre });
    }

    Ok(())
}
```

`Engine::state_of` is an O(1) read (`engine.rs:6334`). `Engine::drain_events` is callback-form: `fn drain_events<F: FnMut(&InternalEvent, &Engine)>(&self, max: u32, mut sink: F) -> u32` (`engine.rs:3356`). The `from == to` self-transition filter is enforced at event push-time inside the engine (`engine.rs:4348`), so the oracle never sees `Established → Established` events. Both APIs exist; A10.5 makes no engine-side changes.

`MAX_DRAIN_PER_BATCH` defaults to `EVENT_RING_CAPACITY` (256) — the closure handles the ring's eviction internally so we never lose events in the bundle, and 256 events per ~10 ms batch is far above any realistic per-batch event rate at single-connection RTT workloads.

### 5.3 Failure semantics

Two classes:

- **Inside the observation loop** — FSM departure or illegal transition ⇒ **fail-fast** the scenario (abort the workload, capture the bundle, move to next scenario).
- **At end-of-scenario** — counter-delta assertion failures ⇒ **collect all** before producing the verdict.

Per-scenario verdict: `Pass` | `Fail(Vec<FailureReason>)`:

```rust
pub enum FailureReason {
    ConnectFailed { error: String },
    FsmDeparted { observed: Option<TcpState> },
    IllegalTransition { from: TcpState, to: TcpState, at_event_idx: usize },
    CounterRelation { counter: String, relation: Relation, observed_delta: i128, message: String },
    DisjunctiveCounterRelation { counters: Vec<String>, relation: Relation, observed_deltas: Vec<i128>, message: String },
    LiveCounterBelowMin { counter: &'static str, observed: u64, min: u64 },
    EventsDropped { count: u64 },
    WorkloadError { error: String },
}
```

The runner accumulates verdicts across the sweep; exit code is non-zero on any fail.

### 5.4 Per-scenario lifecycle

```
1. install netem (or skip if --external-netem)
2. open_connection; wait until ESTABLISHED (timeout = 10 s)
3. WARMUP_ITERS = 100 iterations, observation OFF.
   Drain events on the floor after warmup so handshake/cwnd-warmup events
   (Listen→SynSent→Established trail) don't leak into the assertion window.
4. snapshot_pre (named counters via lookup_counter + reads of obs.events_dropped
   for the per-batch defensive check baseline)
5. inner loop until deadline:
     - run_rtt_workload(OBSERVATION_BATCH iters)
     - observe_batch (poll + event replay + rx_mempool_avail floor +
       per-batch obs.events_dropped delta) — fail-fast on FSM violation,
       LiveCounterBelowMin, or events-dropped.
6. snapshot_post + evaluate:
     - row's counter_expectations (collect-all)
     - row's disjunctive_expectations (collect-all)
     - global side-checks (mbuf_refcnt_drop_unexpected delta == 0;
       end-of-scenario obs.events_dropped delta == 0 — both collect-not-fail-fast
       since they're delta checks against snapshot_pre)
7. close (transition out of ESTABLISHED is OK — assertion window closed)
8. emit verdict; write JSON bundle on fail
```

Constants:
- `WARMUP_ITERS = 100` — short warmup so the first real batch isn't dominated by handshake artefacts.
- `OBSERVATION_BATCH = 100` — between-batch granularity. ≈10 ms at typical RTT, fine-grained enough to catch FSM micro-flaps.
- `MAX_DRAIN_PER_BATCH = 256` — drain budget per `engine.drain_events` call (matches `EVENT_RING_CAPACITY`).
- `EVENT_RING_CAPACITY = 256` — last-N events for the failure bundle.
- `MIN_RX_MEMPOOL_AVAIL = 32` — RX mempool floor for the live-counter side-check. Below this ⇒ approaching the cliff PR #9 was chasing; fail-fast and dump the bundle.
- `CONNECT_TIMEOUT = 10 s`.

## 6. Reporting + diagnostics

### 6.1 Markdown report

Each invocation writes a per-invocation report. The merge step in `scripts/layer-h-nightly.sh` concatenates the four full-matrix reports into the canonical `docs/superpowers/reports/layer-h-<date>.md`.

```markdown
# Layer H Correctness Report — 2026-05-01

**Run ID:** <uuid>
**Commit:** <sha>
**Branch:** <branch>
**Host / NIC / DPDK:** <host> / <nic-model> / <dpdk-version>
**Preset:** trading-latency
**Active config knobs:**
- tcp_max_retrans_count = 15
- hw-offload-rx-cksum = on
- fault-injector = on
- (see `EngineConfig` for the full set; layer-h reports only knobs that
   affect assertion-table reasoning)
**Verdict:** PASS (17/17 scenarios) | FAIL (X/17 scenarios)

## Selected scenarios (this invocation)
...

## Per-scenario results

| # | Scenario | netem | FI | Duration | Verdict | Notes |
|---|----------|-------|-----|----------|---------|-------|
| 1 | delay_20ms | delay 20ms | — | 30.0 s | PASS | — |
| 8 | loss_1pct | loss 1% | — | 30.1 s | FAIL | tx_retrans=51234 exceeds <=50000 |
...

## Failure detail
...
```

The "Active config knobs" block is rendered by `report.rs` from `EngineConfig` directly; `bench_common::RunMetadata` does not carry knob values, and we don't perturb `bench_common` for this. Knob values matter because the assertion-table reasoning (e.g. row 13's 3-dup-ACK threshold; the upper-bound generosity argument) depends on the active knob defaults.

### 6.2 Per-failed-scenario JSON bundle

Path: `<bundle-dir>/<scenario>.json`, default `<bundle-dir>` = `target/layer-h-bundles/<run-id>/`.

```json
{
  "scenario": "loss_1pct",
  "netem": "loss 1%",
  "fault_injector": null,
  "duration_secs": 30.12,
  "verdict": "fail",
  "snapshot_pre": { "tcp.tx_retrans": 0, "obs.events_dropped": 0, "...": "..." },
  "snapshot_post": { "tcp.tx_retrans": 51234, "obs.events_dropped": 0, "...": "..." },
  "failures": [
    {
      "kind": "CounterRelation",
      "counter": "tcp.tx_retrans",
      "relation": "<=50000",
      "observed_delta": 51234,
      "message": "tx_retrans: expected delta <=50000, got 51234"
    }
  ],
  "event_window": [
    { "ord": 0, "kind": "StateChange", "from": "Established", "to": "Established", "emitted_ts_ns": 12345 },
    "..."
  ],
  "event_window_truncated": false
}
```

`event_window` carries the last 256 events (oldest-evicted on overflow). `snapshot_pre/post` cover only counters referenced by *this scenario's* expectations — narrow on purpose so the bundle is operator-readable.

## 7. CLI + execution model

```
layer-h-correctness
  --peer-ssh <user@host>          # required unless --external-netem
  --peer-iface <iface>            # required unless --external-netem
  --peer-ip <ipv4>                # required
  --peer-port <u16>               # default 10001
  --local-ip <ipv4>               # required
  --gateway-ip <ipv4>             # required
  --eal-args <ws-separated>       # required
  --lcore <u32>                   # default 2
  --precondition-mode <strict|lenient>  # default strict
  --external-netem                # ops-side netem orchestration

  --scenarios <csv-or-empty>      # empty = all rows compatible with FI invariant; unknown errors
  --smoke                         # shorthand for --scenarios <smoke set>; mutually exclusive with --scenarios
  --list-scenarios                # print resolved selection and exit (no EAL init)

  --report-md <path>              # required: Markdown report destination
  --force                         # overwrite --report-md if it exists; without
                                  # this flag, an existing path causes exit 2
  --bundle-dir <path>             # default: target/layer-h-bundles/<run-id>/

  --duration-override <secs>      # debugging convenience; overrides every row's duration
```

`--smoke` and `--scenarios` are mutually exclusive at the CLI level via clap's `conflicts_with` — passing both is a parse error, not a runtime check.

**Selection contract:**
- `--smoke` ⇒ exactly the 5 smoke-tagged scenarios.
- Empty `--scenarios` ⇒ all 14 pure-netem rows (composed scenarios are excluded by the single-FI-spec invariant; selecting them requires explicit `--scenarios`).
- Unknown scenario name ⇒ exit 2.
- Two distinct FI specs in the selection ⇒ exit 2 with the orchestrator-script hint.
- `--report-md` path exists without `--force` ⇒ exit 2; explicit clobber prevents accidental loss of a prior report.

**Exit codes:**
- `0` — all selected scenarios passed.
- `1` — at least one scenario failed (any `FailureReason`).
- `2` — startup error (unknown name, two FI specs, missing required arg, EAL init failure).

## 8. Orchestration scripts

Two new scripts under `scripts/`:

### 8.1 `scripts/layer-h-smoke.sh`

Single invocation. Runs `--smoke` against the existing bench-pair fleet (or provisions a fresh one via `resd-aws-infra`, same pattern as `bench-nightly.sh`). Time budget ≈ 3 minutes (5 scenarios × 30 s + setup). Triggered per merge by whichever CI surface owns the gate.

### 8.2 `scripts/layer-h-nightly.sh`

Full matrix in 4 invocations (one per FI spec, plus the pure-netem invocation). Time budget ≈ 12 minutes. Merge step concatenates the four per-invocation Markdown reports into `docs/superpowers/reports/layer-h-<date>.md` with a top-level summary across all 17 scenarios.

Both scripts share helper functions with `bench-nightly.sh` (EC2 Instance Connect grants, scp + ssh wrappers, EAL_ARGS preset) but stay separate top-level entry points so a layer-h failure doesn't blank a perf re-run and vice versa.

## 9. Testing

### 9.1 Unit tests (`src/*::tests`)

- `assertions::Relation::parse` round-trip for `>0`, `==0`, `<=N` with whitespace tolerance, parse errors on `<=`, `<= -1`, unknown literal, `<=18446744073709551615` (u64::MAX boundary).
- `assertions::Relation::check` truth tables across all three relations × {negative, zero, positive, large} deltas.
- `assertions::FailureReason` `Serialize` round-trip.
- `observation::EventRing` capacity + eviction.
- `report::write_failure_bundle` against a synthetic fixture (no engine).

### 9.2 Integration tests (`tests/*.rs`)

- `scenario_parse.rs`:
  - `matrix_has_seventeen_scenarios`
  - `scenario_names_are_unique`
  - `every_counter_name_resolves` — every counter in every row's `counter_expectations` and `disjunctive_expectations` resolves via `dpdk_net_core::counters::lookup_counter`.
  - `every_relation_parses` (covers both expectation arrays).
  - `smoke_set_is_correct` — exactly the 5 names from the roadmap.
  - `composed_scenarios_partition_by_fi_spec` — 3 distinct FI specs across the composed rows.
  - `pure_netem_scenarios_have_no_fi_spec`
  - `corruption_row_has_disjunctive_cksum_counters` — row 14's `disjunctive_expectations` references both `eth.rx_drop_cksum_bad` and `ip.rx_csum_bad`.
- `assertions_unit.rs` — synthetic event stream → FSM oracle pass/fail; disjunctive-relation evaluator pass/fail; live-counter-floor (`LiveCounterBelowMin`) pass/fail.
- `external_netem_skips_apply.rs` — `--list-scenarios`, `--smoke`, `--scenarios <subset>`, `--external-netem` arg-parsing without EAL; `--smoke` ⊕ `--scenarios` mutual-exclusion test (clap parse failure); `--report-md` clobber-without-`--force` exits 2.

### 9.3 No new TAP regression tests under `crates/dpdk-net-core/tests/`

A10.5 asserts against the existing observability surface; if a scenario reveals a gap, it's filed for a later phase, not retrofitted into A10.5.

### 9.4 Test timeout policy

Per project memory: every `cargo test` / `cargo bench` invocation in scripts and CI carries an explicit per-command timeout (`timeout 60s cargo test -p layer-h-correctness ...`). layer-h-correctness's own tests are CPU-bound and DPDK-free; 60 s is comfortable.

## 10. End-of-phase review gates

Per spec §10.13 + §10.14 and project memory:

- **mTCP comparison** — `mtcp-comparison-reviewer` subagent → `docs/superpowers/reviews/phase-a10-5-mtcp-compare.md`. Focus: mTCP's netem-equivalent test harness (or absence thereof); correctness-gate pattern parity.
- **RFC compliance** — `rfc-compliance-reviewer` subagent → `docs/superpowers/reviews/phase-a10-5-rfc-compliance.md`. Focus: RFC 9293 §3.10 (FSM legality), RFC 6298 (RTO), RFC 8985 (RACK reorder), RFC 5681 / 6675 (dup-ACK + SACK), RFC 5961 (challenge-ACK behavior under adversity).

Both gates block the `phase-a10-5-complete` git tag.

## 11. Risks + open questions

- **Counter-bound generosity vs catch rate.** Upper bounds like `<=200000` for 5 % loss catch only catastrophic ladders. A real "drowning in retransmits" regression that stays under 200 000 retransmits over 30 s would slip through. Tightening is a follow-up; A10.5 lands the framework.
- **Reorder gap=3 boundary case.** The assertion `tcp.tx_retrans==0` for `delay 5ms reorder 50% gap 3` depends on the trading-latency preset's 3-dup-ACK fast-retransmit threshold being exact. If the preset changes the threshold (or ducktyping pushes the dup-ACK count above 3 transiently), the assertion needs updating. Documented in §4 notes.
- **Corruption offload state.** Resolved by disjunctive-counter assertion (§4 row 14, §5.1). The matrix asserts `[eth.rx_drop_cksum_bad, ip.rx_csum_bad] >0`; whichever path fires under the active build profile satisfies the row. No runtime introspection of `Engine`'s private offload-active flags required; no engine-side change for a public accessor.
- **`MIN_RX_MEMPOOL_AVAIL = 32` threshold.** Picked to be near-but-not-at-empty. If a real bench-pair burst legitimately hits 31 mbufs available transiently the side-check fails; raising the floor reduces sensitivity. PR #9 is the reference for what the cliff looked like; if a layer-h scenario flakes on this side-check we tune up after looking at the bundle.
- **`reorder 50% gap 3` lacks a base delay in bench-stress's matrix.** That is a pre-existing bench-stress bug filed separately (`tools/bench-stress/src/scenarios.rs:72`). A10.5's row carries the corrected `delay 5ms reorder 50% gap 3`; bench-stress is left alone per §2.
- **CI surface ownership.** This design assumes whichever CI surface owns A10's perf gate (currently transitioning per the `jenkins-ci-migration` worktree) also owns A10.5. The orchestrator scripts are CI-surface-agnostic; the actual hookup is whatever the merge-time + stage-cut workflows do.

## 12. Implementation outline

Roughly 6–8 tasks, executed in a worktree off master with the per-task two-stage review discipline (spec-compliance + code-quality) followed by the end-of-phase mTCP + RFC review gates.

1. Crate skeleton — `Cargo.toml`, workspace member registration, `lib.rs`/`main.rs` stubs, the static `MATRIX` from §4 (no relation parsing yet).
2. `Relation` enum + parser (§5.1) with unit tests.
3. `counters_snapshot.rs` thin wrapper around `lookup_counter`; pre-flight name resolution.
4. `observation.rs` — periodic poll + event-stream replay + `EventRing`.
5. `workload.rs` — deadline-driven outer loop wrapping `bench_e2e::run_rtt_workload`.
6. `report.rs` — Markdown report writer + JSON failure-bundle serializer.
7. CLI + main wiring (§7), including `--list-scenarios`, `--smoke`, single-FI-spec invariant.
8. Integration tests (`scenario_parse.rs`, `assertions_unit.rs`, `external_netem_skips_apply.rs`).
9. `scripts/layer-h-smoke.sh` + `scripts/layer-h-nightly.sh`.
10. End-of-phase mTCP + RFC review reports + tag.

Detailed plan in the companion implementation-plan document (written via the writing-plans skill).
