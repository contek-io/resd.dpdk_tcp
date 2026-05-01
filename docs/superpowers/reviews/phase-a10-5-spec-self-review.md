# Phase A10.5 Spec Self-Review

**Spec:** docs/superpowers/specs/2026-05-01-stage1-phase-a10-5-layer-h-correctness-design.md
**Reviewer:** subagent self-review (opus 4.7)
**Reviewed at:** 2026-05-01

## Verdict

PROCEED-WITH-FIXES — three must-fixes (one user-flagged defect, two API mismatches that will fail to compile as written) plus a handful of should-fixes around tc-netem semantics and metadata.

## Must-fix (BLOCK)

- [ ] **`engine.drain_events_into(buf)` does not exist** — spec §3.3 and §5.2 reference this method. Actual API is `Engine::drain_events<F: FnMut(&InternalEvent, &Engine)>(&self, max: u32, mut sink: F) -> u32` (`crates/dpdk-net-core/src/engine.rs:3356`). The observation loop must be re-cast as `engine.drain_events(MAX_PER_BATCH, |ev, _| { ... })`. There is no buffer-into form. Affects §3.3 pseudocode, §5.2 `observe_batch` signature, and the FailureBundle event-window collection (the closure has to push into the ring rather than the caller appending a Vec).

- [ ] **`EngineConfig.checksum_offload` does not exist** — spec §4 (corruption-row note) and §11 (offload-state risk) say "the assertion engine reads `EngineConfig.checksum_offload` at startup and selects the right counter for that one row." There is no such field on `EngineConfig`. The active-checksum-offload signal is on the runtime `Engine` (`engine.rs:590,596` — `tx_cksum_offload_active`/`rx_cksum_offload_active`), set from `outcome` at engine bring-up, not from config. Even those fields are private. Selection is actually compile-time via the `hw-offload-rx-cksum`/`hw-offload-tx-cksum` cargo features (`Cargo.toml:43,44`). The spec must either (a) gate the corruption-row counter choice on `cfg!(feature = "hw-offload-rx-cksum")`, (b) add a public accessor and own that one-line `dpdk-net-core` change explicitly (which violates §2's "all reuse is read-only" promise), or (c) assert against both counters with `OR`-of-deltas so the runtime offload state is irrelevant.

- [ ] **PR #9 RX-leak diagnostic counters are not asserted as side-checks** — the brief explicitly requested `tcp.rx_mempool_avail` and `tcp.mbuf_refcnt_drop_unexpected` be asserted in every Layer H scenario. The spec's §4 matrix references neither and §3.3 doesn't mention them. Add a global side-check (per §5.2 lifecycle) that fails the scenario when `tcp.mbuf_refcnt_drop_unexpected` deltas above zero (or a small threshold matching `MBUF_DROP_UNEXPECTED_THRESHOLD`) and that `tcp.rx_mempool_avail` does not collapse to zero during the run. **Caveat for the implementer:** `tcp.rx_mempool_avail` is `AtomicU32` (`counters.rs:284`), comment at `counters.rs:533` says it is **deliberately not in `lookup_counter`** — must be read via `engine.counters().tcp.rx_mempool_avail.load(...)`. `tcp.mbuf_refcnt_drop_unexpected` IS in `lookup_counter` (`counters.rs:709`).

## Should-fix (PROCEED-WITH-FIXES)

- [ ] **`reorder 50% gap 3` is an invalid netem spec without a `delay`** — `man tc-netem` is explicit: "to use reordering, a delay option must be specified." Spec §4 row 13 omits delay. Bench-stress carries the same string in `tools/bench-stress/src/scenarios.rs:72`, so this is either a pre-existing bug shared with A10 or netem silently accepts it as a no-op (which would mean the row exercises nothing). Either way the spec should change row 13 to `delay 5ms reorder 50% gap 3` (or similar small base delay) and document the choice; if it stays as-is, the §4 note about the assertion `tx_retrans==0` is meaningless because no reordering happens.

- [ ] **bench-stress's `enforce_single_fi_spec` is not pub** — spec §3.4 says the new driver "enforces 'single FI spec per invocation' at startup (`enforce_single_fi_spec`, identical pattern to bench-stress)." The function is private to `tools/bench-stress/src/main.rs:435` and bound to bench-stress's own `Scenario` type. The new crate must reimplement against `LayerHScenario` (a fine, ~10-line copy) — flag explicitly so the implementer doesn't try to import.

- [ ] **`RunMetadata` does not record `tcp_max_retrans_count`** — §6.1 report header lists "preset" but the assertion-table reasoning in §4 notes (e.g. row 13's 3-dup-ACK threshold, the upper-bound generosity argument) depends on `EngineConfig.tcp_max_retrans_count` and the active feature-set. `bench_common::RunMetadata` (`tools/bench-common/src/run_metadata.rs:25-42`) does not carry knob values. Either extend the report header inside layer-h-correctness (recommended; no shared-crate change) or document explicitly that the report omits knob state and the verdict is only valid against the default preset.

- [ ] **CLI mutual-exclusion not enforced** — §7 says `--smoke` is mutually exclusive with `--scenarios` but the CLI section doesn't mandate a clap-level conflict. Add `conflicts_with = "scenarios"` (or equivalent) and a unit test in `external_netem_skips_apply.rs`.

- [ ] **`--report-md` clobber behavior unspecified** — four-invocation orchestration writes to distinct paths in the §8.2 example, but if the operator passes the same path twice the second invocation silently overwrites without warning. Either mandate `--force` to overwrite an existing path or document the clobber as intentional.

## Accepted-as-is / Discussed

- All other counter names in §4 (`tcp.tx_retrans`, `tcp.tx_rto`, `tcp.tx_tlp`, `tcp.rx_dup_ack`, `tcp.tx_rack_loss`, `eth.rx_drop_cksum_bad`, `ip.rx_csum_bad`, `obs.events_dropped`, `fault_injector.{drops,dups,reorders,corrupts}`) resolve via `dpdk_net_core::counters::lookup_counter` (`counters.rs:620-722`). Coverage is real.
- `Engine::state_of` exists with the assumed signature (`engine.rs:6334`, returns `Option<TcpState>`).
- `EngineConfig::tcp_max_retrans_count` exists, default 15 (`engine.rs:322,400`).
- `bench_e2e::workload::{open_connection, run_rtt_workload}` exist with usable signatures (`tools/bench-e2e/src/workload.rs:227,307`).
- `bench_stress::netem::NetemGuard::apply` exists; `bench_stress::lib.rs` re-exports `counters_snapshot`, `netem`, `scenarios` cleanly.
- Bench-stress's `Relation` enum is only `>0` / `==0` (`tools/bench-stress/src/counters_snapshot.rs:45-50`); spec's claim that `<=N` is layer-h-local is correct and avoids touching bench-stress.
- `FaultInjectorCounters` is always present on `Counters` (not feature-gated), so `lookup_counter` lookups for `fault_injector.*` always resolve. Increment sites are gated behind `fault-injector` feature, so the runner's own dpdk-net-core dep needs `features = ["fault-injector"]` for composed scenarios — spec doesn't currently say this; add a one-line note in §3.2 listing the required feature flags.
- `engine.close(conn)` in §3.3 pseudocode is informal; actual API is `close_conn` (`engine.rs:5348`). Pseudocode-level — not blocking.
- `from == to` self-transitions are filtered before push (`engine.rs:4348-4350`), so the FSM oracle in §3.3 / §5.2 will never see Established→Established events. Oracle is correctly stated as `from: Established, to: != Established`.
- §4 row 14 (corruption) wiring for the offload selection is the only place where the wire-level adversity is asserted via different counters depending on build config — see must-fix above.
- Scope hygiene against the roadmap "Does NOT include" list is clean: no PMTU, no perf metrics, no Layer G, no fuzzing, no engine-side counter additions (the spec correctly defers the missing rx-leak side-check assertion to existing counters).

## FYI / informational

- §3.1's `lib.rs` façade ("so tests/scenario_parse.rs imports modules") is good; copy bench-stress's pattern verbatim.
- §3.3 RTC pseudocode mixes `run_rtt_workload(N)` with the observation loop, but `run_rtt_workload` itself drives `engine.poll_once` internally and may consume events transparently. Verify in implementation that `drain_events` after `run_rtt_workload` returns the events queued during that batch — `EventQueue` is bounded with `obs.events_dropped` as the overflow signal, so a long burst could drop events before observation runs. The `OBSERVATION_BATCH = 100` choice (§5.4) is small enough that this should be fine, but worth a defensive `assert obs.events_dropped delta == 0` per batch (already implied by the global expectation `obs.events_dropped==0`, but local-per-batch would catch the FSM-event-lost case earlier).
- §5.4 lists `WARMUP_ITERS = 100` with "observation OFF" — make explicit in the implementation plan that warmup still polls + drains events to drop them on the floor (otherwise the first real `drain_events` call returns handshake StateChange events from `Listen→SynSent→Established` and the oracle will read the `to: Established` (legal) trailing edge but possibly emit confusing diagnostics).
- §9.4 says `timeout 60s cargo test -p layer-h-correctness ...`. The `external_netem_skips_apply.rs` test in §9.2 is CLI-arg-parse-only; 60 s is fine. The integration test inventory carries no DPDK init, so this is consistent with the timeout policy.
- §11 acknowledges the offload-state risk but the actual mitigation (must-fix above) is sharper than what §11 currently describes.
- §10's review-gate paths (`docs/superpowers/reviews/phase-a10-5-mtcp-compare.md`, `phase-a10-5-rfc-compliance.md`) match the existing `docs/superpowers/reviews/` naming (e.g. `a8.5-mtcp-compare.md`, `phase-a-hw-plus-rfc-compliance.md`). Use `phase-a10-5-...` consistently per the most recent precedent.

## Verification trace

Files read in full or in relevant ranges:

- `docs/superpowers/specs/2026-05-01-stage1-phase-a10-5-layer-h-correctness-design.md` (the spec, all 416 lines)
- `crates/dpdk-net-core/src/counters.rs` (lines 1-1080, focused on 280-720; verified `lookup_counter` arms for every matrix counter)
- `crates/dpdk-net-core/src/engine.rs` (greps + reads at 590, 1723, 2190, 2204, 3356, 4340-4370, 5348, 6325-6350; verified `state_of`, `drain_events`, `events`, `counters`, `transition_conn`, `close_conn`)
- `crates/dpdk-net-core/src/tcp_events.rs` (lines 25-117; `InternalEvent::StateChange` shape)
- `crates/dpdk-net-core/src/tcp_state.rs` (TcpState enum)
- `crates/dpdk-net-core/src/fault_injector.rs` (feature gating; `from_env` signature)
- `crates/dpdk-net-core/Cargo.toml` (features: `hw-offload-rx-cksum` etc., `fault-injector`)
- `crates/dpdk-net-core/tests/feature-gated-counters.txt` (confirms fault_injector counters always resolve, increments gated)
- `tools/bench-stress/src/{lib.rs, main.rs, scenarios.rs, counters_snapshot.rs, netem.rs}` (lib facade, `enforce_single_fi_spec` privacy, `Relation` shape, `validate_spec`, scenario carry of `reorder 50% gap 3`)
- `tools/bench-e2e/src/workload.rs` (lines 220-320; `open_connection`, `run_rtt_workload` signatures)
- `tools/bench-common/src/run_metadata.rs` (RunMetadata fields)
- `docs/superpowers/plans/stage1-phase-roadmap.md` § A10.5 (scope baseline)

Greps run:

- `pub fn lookup_counter|state_of|drain_events_into|close|counters` across `engine.rs`, `counters.rs`
- `tx_retrans|tx_rto|tx_tlp|rx_dup_ack|tx_rack_loss|rx_drop_cksum_bad|rx_csum_bad|events_dropped|fault_injector` in `counters.rs` (every matrix name verified at both `ALL_COUNTER_NAMES` and `lookup_counter` arm)
- `rx_mempool_avail|mbuf_refcnt_drop_unexpected|MBUF_DROP_UNEXPECTED` in `counters.rs` (PR #9 plumbing trace)
- `checksum_offload|cksum_offload` across all `crates/` and `tools/` (no `EngineConfig.checksum_offload`; only runtime `tx/rx_cksum_offload_active` private fields on Engine)
- `tc-netem` man page consulted for reorder semantics

Cross-checked spec §4 every row's counters resolve, §3.3 / §5.2 APIs against actual signatures, §6.1 metadata against `RunMetadata`, §11 risks against actual code paths.
