# A10-perf follow-on — bench-micro hot-path optimization + DPDK 24.11 adoption experiment (Design Spec)

**Status:** Design (brainstorm 2026-04-23). Implementation plan lands at `docs/superpowers/plans/2026-04-23-a10-microbench-perf-and-dpdk24-adopt.md`.
**Parent phase spec:** `docs/superpowers/specs/2026-04-21-stage1-phase-a10-benchmark-harness-design.md` (`A10`) — treat this as a post-A10 performance pass on already-shipped measurement harness.
**Grandparent spec (Stage 1 design):** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §11.2 supplies the per-family order-of-magnitude targets this effort must beat.
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` § A10 (L609–638). A10 stays `Complete`; this effort amends its line with a `→ A10-perf follow-on` note at end-of-effort.
**Landing policy:** **Exploratory.** Per-change mTCP / RFC / code-quality review is skipped during iteration. End-of-effort two-stage review (spec-compliance + code-quality reviewer subagents, opus 4.7 per `feedback_subagent_model` + `feedback_per_task_review_discipline`) on each branch's aggregate diff decides what cherry-picks onto master.
**Branches** (created once this spec is committed on master; both branch from `phase-a10` tip `132e42a`, independent of where the spec lands):
- `a10-perf-23.11` — DPDK 23.11 uProf-driven optimization
- `a10-dpdk24-adopt` — DPDK 24.11 LTS rebase + target-API adoption
**Worktrees:** `/home/ubuntu/resd.dpdk_tcp-a10-perf` and `/home/ubuntu/resd.dpdk_tcp-a10-dpdk24`. Both created via `git worktree add` (shared object DB, independent `target/`).
**Pinned host:** current dev EC2 instance — AMD EPYC 7R13 (Zen 3 / Milan), KVM. Both worktrees share this host; every bench CSV row carries the host-config metadata and is rejected at analysis time on any mismatch.
**Not a phase-letter bump.** Sits between A10 (complete) and A10.5 / A11 (not started). Not a Stage-1 ship gate.

---

## 0. Purpose of this spec

Drive the hot-path library latency numbers measured by `tools/bench-micro/` below their Stage-1-design §11.2 order-of-magnitude targets using **AMD uProf** as the profiler of record on the existing dev host. In parallel, run a **DPDK 24.11 LTS** rebase experiment from the same base commit, adopting 24.11 APIs expected to move our numbers (`rte_lcore_var`, `rte_ptr_compress`, `rte_bit_atomic_*`, ENA TX logger rework), and produce an evidence-based recommendation on whether 24.11 should become the new pinned DPDK target (replacing the current §8 / `project_context` pin on 23.11).

Bench-micro is the **instrument**, not the target. What we optimize is the underlying library: `tcp_input::dispatch`, `flow_table::lookup_by_tuple`, `tcp_output` send path, `engine::poll_once`, `tcp_timer_wheel::advance`, counter readers, TSC accessors. Wins landed here are measured by bench-micro but exercised by the actual engine, so they carry forward to `bench-e2e` / production whenever those run.

**This effort does not change production wire behavior.** `preset=rfc_compliance` stays opt-in; the trading-latency default stays the default; no new ABI surface ships in production builds (the `bench-internals` feature is off by default and feature-gates the test-only harness hook).

---

## 1. Brainstorm decisions

The 2026-04-23 brainstorm closed six decisions (D1–D6) plus one post-brainstorm clarification.

### D1 — Goal metric: hot-path library latency via bench-micro + uProf

"Optimize microbench" resolves as: bench-micro is the yardstick, uProf is the profiler, and the work optimizes the underlying library functions each bench covers. The bench code itself is not the optimization target. End-to-end `bench-e2e` RTT + throughput is explicitly out of scope for this effort (deferred to a potential follow-on).

### D2 — Landing policy: exploratory, aggregate end-of-effort review

No per-change mTCP/RFC/code-quality review during iteration (contrast A10, where every task ran those gates). Each landed optimization carries a family-report entry with before/after numbers + uProf evidence, rich enough that the end-of-effort two-stage review (spec-compliance + code-quality opus 4.7 subagents) accepts/rejects changes from evidence without re-profiling.

Worktree branches stay local as research references; they are **not** merged wholesale. What cherry-picks onto master is the subset that survives end-of-effort review.

### D3 — Stub handling: `bench-internals` cargo feature

bench-micro currently has partial stubs. `bench_poll_empty` and `bench_poll_idle_with_timers` use `clock::now_ns()` as a proxy because `TimerWheel` is `pub(crate)` and `Engine::poll_once` needs `rte_eal_init` + hugepages + a TAP vdev. That floor is acknowledged by the bench files' own `TODO(T5)` notes.

Resolution: add a `bench-internals` cargo feature on `crates/dpdk-net-core/Cargo.toml` (additive, off by default) that:
- Promotes `TimerWheel` (and related `pub(crate)` internals needed by `poll_once`) to `pub` via `#[cfg(feature = "bench-internals")]` or a `pub(crate)` + pub re-export under `engine::test_support`
- Adds `engine::test_support::EngineNoEalHarness` — a reduced-surface Engine simulacrum built without `rte_eal_init` that walks the same flow-table / timer-wheel / event-queue / conn-state code paths `poll_once` walks. Explicitly a bench-and-test harness; explicitly not a production Engine.

`tools/bench-micro/Cargo.toml` switches its `dpdk-net-core` dependency to `features = ["bench-internals"]`. Default `cargo build` and any consumer crate see zero difference. If the `bench-internals` feature lands in the final cherry-pick, the A10 parent spec's "pure-in-process per spec §5" note gets a one-paragraph amendment noting the harness hook.

### D4 — Bench families: systematic sweep across all 7

All 7 bench families (`poll`, `tsc_read`, `flow_lookup`, `tcp_input`, `send`, `timer`, `counters`) receive uProf + optimization attention. Order: `poll → tcp_input → send → flow_lookup → timer → tsc_read → counters` (highest-leverage first, reflecting trading-workload incidence: poll fixed overhead is paid every iteration; tcp_input and send every segment; flow_lookup every poll cycle that finds work; timer on RACK/RTO; tsc_read already near floor; counters is slow-path).

Per-family hard-stop conditions (§5.1) prevent death-by-one-more-try.

### D5 — Success criterion: beat §11.2 target, then 5% regression guard

Per family: criterion median ≤ upper bound of §11.2 range AND p99 ≤ 2× that upper bound AND top hotspot < 5% of cycles (or documented as a known floor). On success, the new baseline is locked with criterion's default 5% regression guard for future runs. (Single-value targets like `~5 ns` are treated as `upper = target`; ranges like `100–200 ns` use the high end.)

This is a concrete numeric gate, not "every hotspot addressed."

### D6 — DPDK 24.11 scope: parallel worktree, rebase + adopt target APIs + re-baseline

Second worktree `a10-dpdk24-adopt` runs in parallel from the same `132e42a` base. Three phases:
1. **Rebase.** Bump `atleast_version("23.11")` → `atleast_version("24.11")`, rerun bindgen, fix breakage, re-run full test sweep, re-baseline bench-micro.
2. **Adopt target APIs, one at a time, each an A/B measurement:**
   - `rte_lcore_var` (24.11) — per-lcore static storage replacing `__rte_cache_aligned` + `RTE_CACHE_GUARD` patterns
   - `rte_ptr_compress` (24.07) — pointer-array compression for mbuf burst loops
   - `rte_bit_atomic_*` (24.11) — lighter-weight atomic bit manipulation
   - ENA TX logger rework (24.07) — passive verification; no code change, just measurement
3. **Port Worktree-1 wins forward.** Cherry-pick or re-implement each proven 23.11 optimization on the 24.11 branch, re-measure.

Deferrals (documented, not silent):
- **Per-CPU PM QoS (24.11):** N/A — engine is busy-poll; no wake-up path to optimize
- **`rte_thash_gen_key` (24.11):** defer to Stage 2 — single-queue Stage 1 has no RSS imbalance to cure
- **Intel E830 / ice driver (24.07):** N/A — we run ENA on EC2
- **Event pre-scheduling (24.11):** N/A — no eventdev in the engine

End-of-effort outcome: recommendation on 24.11 adoption as the new pinned target, with rebase-delta + per-API-delta + ported-wins evidence.

### Post-brainstorm clarification (2026-04-23) — hot-path counters

User note: **new production hot-path counters are allowed** in either worktree if measurement justifies them. This is a clarification of existing `feedback_counter_policy` rule (compile-time feature gate + documented justification + batched increment), not a new exception. Any counter added in this effort must still satisfy that rule and log its justification in the family report.

---

## 2. Scope

### 2.1 In scope

**Worktree 1 (`a10-perf-23.11` on branch, `/home/ubuntu/resd.dpdk_tcp-a10-perf` on disk):**
- uProf-driven optimization of library hot-path functions covered by all 7 bench-micro families (§5)
- `bench-internals` cargo feature + `EngineNoEalHarness` surrogate on `crates/dpdk-net-core/` (feature-gated, additive, off by default)
- `scripts/check-perf-host.sh` — host-config precondition checker; invoked before every bench run
- `tools/bench-micro/` harness modifications: switch `bench_poll_*` to `EngineNoEalHarness`; add CSV columns (`cpu_family`, `dpdk_version`, `worktree_branch`, `uprof_session_id`); per-iteration RDTSC capture alongside criterion timing
- Per-family baseline + iteration reports under `docs/superpowers/reports/perf-23.11/`
- Hot-path counter additions if measurement justifies (per D6 clarification; still subject to `feedback_counter_policy` — compile-time gate + batched + justified)

**Worktree 2 (`a10-dpdk24-adopt` on branch, `/home/ubuntu/resd.dpdk_tcp-a10-dpdk24` on disk):**
- DPDK 24.11 LTS rebase: `crates/dpdk-net-sys/build.rs` bump, bindgen regen, compile fixes, full test sweep
- Post-rebase bench-micro baseline with side-by-side delta vs 23.11 (`docs/superpowers/reports/perf-dpdk24/baseline-rebase.md`)
- Target-API adoption tasks with per-API A/B reports (§6.2): `rte_lcore_var`, `rte_ptr_compress`, `rte_bit_atomic_*`, ENA TX logger verification
- Port Worktree-1 wins forward; re-measure; per-port reports
- `docs/superpowers/reports/perf-dpdk24/summary.md` with net recommendation on 24.11 pinning

**Cross-worktree:**
- Weekly sync reports under `docs/superpowers/reports/perf-sync/`
- End-of-effort two-stage review (spec-compliance + code-quality, opus 4.7 subagents) per branch
- Cross-worktree summary `docs/superpowers/reports/perf-a10-postphase.md`
- uProf install on the shared dev host (one-time setup; reused by both worktrees)

### 2.2 Out of scope

- `tools/bench-e2e/`, `tools/bench-stress/`, `tools/bench-offload-ab/`, `tools/bench-obs-overhead/`, `tools/bench-vs-linux/`, `tools/bench-vs-mtcp/` — bench-micro only, per D1
- Paired EC2 host work / AMI changes / `resd.aws-infra-setup` — untouched
- CI wiring — dev-host only during iteration; user wires CI later if desired
- Multi-queue RSS work (Stage 2)
- Per-CPU PM QoS / power-mode adoption (D6 deferral; busy-poll engine has no wake-up path)
- `rte_thash_gen_key` RSS key auto-generation (D6 deferral; single-queue Stage 1)
- Intel E830 / ice driver adoption (D6 deferral; we're ENA)
- Event pre-scheduling / eventdev (D6 deferral; run-to-completion engine)
- WAN / netem correctness (A10.5)
- `preset=rfc_compliance` wire-behavior changes (stays opt-in; default = trading-latency, per `feedback_trading_latency_defaults`)
- Parent-spec amendments for items that don't end up shipping — amendment deferred to end-of-effort decision

---

## 3. Worktree + branch layout

### 3.1 Layout table

| Path | Branch | Purpose | Touched by this effort |
|---|---|---|---|
| `/home/ubuntu/resd.dpdk_tcp` | `master` | Main repo; hosts this spec + end-of-effort cherry-picks | This spec commit; final cherry-picks |
| `/home/ubuntu/resd.dpdk_tcp-a10` | `phase-a10` (existing) | Reference for phase-a10 baseline numbers | **Untouched.** Pre-existing untracked/modified files (`test_tx_intercept.rs`, `virt_clock_monotonic.rs`, `build-sanitize/`, modified `tools/*/src/main.rs`) stay where they are |
| `/home/ubuntu/resd.dpdk_tcp-a10-perf` | `a10-perf-23.11` (new, from `132e42a`) | DPDK 23.11 uProf-driven optimization | Full iteration |
| `/home/ubuntu/resd.dpdk_tcp-a10-dpdk24` | `a10-dpdk24-adopt` (new, from `132e42a`) | DPDK 24.11 rebase + adoption | Full iteration |

### 3.2 Creation procedure

The implementation plan's first task creates both worktrees:

```
git worktree add -b a10-perf-23.11 /home/ubuntu/resd.dpdk_tcp-a10-perf 132e42a
git worktree add -b a10-dpdk24-adopt /home/ubuntu/resd.dpdk_tcp-a10-dpdk24 132e42a
```

`132e42a` is the tip of `phase-a10` on 2026-04-23. If `phase-a10` moves forward during the effort, the worktrees **do not** rebase — they stay rooted at the spec's base commit so all measurements remain apples-to-apples.

### 3.3 Isolation guardrails

- `target/` directories per worktree (cargo default)
- `target/criterion/` baselines per worktree — no cross-contamination of regression guards
- uProf output dirs per worktree (`profile/` at worktree root, gitignored via worktree-local `.gitignore` entry appended early)
- `.envrc` (or exported env vars in `scripts/check-perf-host.sh`) pins the worktree's `PKG_CONFIG_PATH` so the 24.11 worktree sees 24.11 and only 24.11

### 3.4 Git hygiene

- Linear commit series per worktree
- Conventional commit prefix: `a10-perf-23.11:` or `a10-dpdk24:` depending on worktree
- Revert-not-reset on failed hypotheses (keeps the measurement record)
- Spec commit on master lands before either worktree is created

---

## 4. Tooling + measurement discipline

### 4.1 uProf install (one-time, shared host)

```
sudo apt install /home/ubuntu/amduprof_5.2-606_amd64.deb
sudo modprobe amd_ibs
sudo modprobe msr
```

Sanity checks:
- `AMDuProfCLI info --system` reports AMD EPYC 7R13 / Family 25 / Model 1 (Zen 3 Milan)
- `AMDuProfCLI collect --config tbp -d 2 -o /tmp/uprof-probe /bin/echo hello` produces a non-empty `.caperf`

Any failure blocks the effort until resolved — no `--lenient` in the install path.

### 4.2 Host-config precondition checker — `scripts/check-perf-host.sh`

A new script in each worktree (not shared across worktrees via symlink — each worktree is a self-contained research branch). Called at the top of every bench run. Fails fast with a line-by-line diff against expected state:

- CPU governor = `performance` (`cpupower frequency-info` confirms)
- Turbo state documented (either fixed frequency or explicitly noted in CSV)
- `isolcpus`, `nohz_full`, `rcu_nocbs` cover bench cores
- IRQ affinity excludes bench cores (`/proc/irq/*/smp_affinity`)
- THP = `never` on engine cores
- 2 MiB hugepages mounted (`/mnt/huge`, expected mount flags)
- `kernel.nmi_watchdog = 0` on bench cores
- No `--lenient` flag exists during iteration — discipline-clean runs or no run

Expected state is hardcoded for the current dev host (no CLI override). Future host moves = spec amendment.

### 4.3 `bench-internals` cargo feature

On `crates/dpdk-net-core/Cargo.toml`:

```
[features]
bench-internals = []   # OFF by default; enables pub exposure of TimerWheel + EngineNoEalHarness for tools/bench-micro
```

Gate sites:
- `crates/dpdk-net-core/src/tcp_timer_wheel.rs` — flip `pub(crate)` → `pub` on `TimerWheel`, `TimerWheel::new`, `TimerWheel::advance`, related accessors under `#[cfg(feature = "bench-internals")]`
- `crates/dpdk-net-core/src/engine/test_support.rs` (new) — `pub struct EngineNoEalHarness { ... }` containing flow table + timer wheel + event queue + a fixed pool of `TcpConn` slots, sufficient to exercise the poll/dispatch/advance walk without calling `rte_eal_init`. Public API shape mirrors the real Engine's bench-visible surface.
- `tools/bench-micro/Cargo.toml` — `dpdk-net-core = { path = "../../crates/dpdk-net-core", features = ["bench-internals"] }`

Production `cargo build` (default features) sees none of this.

### 4.4 bench-micro harness modifications

- `bench_poll_empty` + `bench_poll_idle_with_timers`: switch from `clock::now_ns` proxy to `EngineNoEalHarness::poll_once()`; the idle-with-timers variant pre-populates the timer wheel so `advance` walks a real (but not-yet-firing) bucket chain
- All 7 bench families: add per-iteration `__rdtsc()` capture alongside criterion's internal timing. Criterion's measurement is the gate; RDTSC is the sanity-check tail in the CSV sidecar
- New CSV columns (added to `tools/bench-micro/src/bin/summarize.rs`): `cpu_family`, `cpu_model_name`, `dpdk_version`, `worktree_branch`, `uprof_session_id` (empty if not profiling)
- CSV schema remains compatible with A10's `tools/bench-report/` ingest (additive columns only)

### 4.5 uProf capture recipe (per bench family, per iteration)

For each family F and iteration N:

```
# 1. Top-Down / cycle attribution (hotspot survey)
AMDuProfCLI collect --config tbp -d 30 \
  --output profile/<F>-iter-<N>/tbp \
  cargo bench --bench <F> -- --measurement-time 30

# 2. IBS for retire-latency + L1/L2/L3 miss source lines
AMDuProfCLI collect --config ibs -d 30 \
  --output profile/<F>-iter-<N>/ibs \
  cargo bench --bench <F> -- --measurement-time 30

# 3. PCM memory bandwidth / L3 occupancy (run alongside a separate bench invocation)
AMDuProfPcm -m l3,memory -d 30 -o profile/<F>-iter-<N>/pcm.csv &
cargo bench --bench <F> -- --measurement-time 30
wait

# 4. Render HTML reports
AMDuProfCLI report --import-dir profile/<F>-iter-<N>/tbp \
  --report-output profile/<F>-iter-<N>/tbp.html
AMDuProfCLI report --import-dir profile/<F>-iter-<N>/ibs \
  --report-output profile/<F>-iter-<N>/ibs.html
```

HTML reports are committed alongside the per-iteration markdown report in `docs/superpowers/reports/perf-23.11/<F>-iter-<N>/` (filenames only; large `.caperf` blobs stay local under `profile/`).

---

## 5. Worktree 1 — uProf-driven optimization loop on DPDK 23.11

### 5.1 Per-family cycle

Applied to each of the 7 bench families in D4 priority order:

1. **Baseline lock.** Run bench 3×, criterion writes `target/criterion/<bench>/base`. Capture uProf TBP + IBS + PCM per §4.5. Commit `docs/superpowers/reports/perf-23.11/<family>-baseline.md` with: criterion median + p99 + stddev + §11.2 target + top 10 hotspots by cycle % + top 10 by IBS retire latency + top 10 by L1/L2 miss source lines.
2. **Hypothesize.** For each hotspot ≥ 5% cycles, write a one-paragraph hypothesis (site, suspected cause, proposed change, expected-ns-saved × confidence). Rank. Write into the baseline report's `Hypotheses` section.
3. **Implement top hypothesis.** Smallest change that tests the hypothesis; one file where possible. Conventional-message commit: `a10-perf-23.11: <family> — <change> (hypothesis: <one-liner>)`.
4. **Re-measure.** Rerun bench 3× against the criterion baseline (not against itself). **Pass** = criterion median ≥ noise-floor improvement AND p99 not worse AND §11.2 target still met. **Fail** = either metric significantly worse.
5. **If pass:** lock new baseline, re-capture uProf, commit `<family>-iter-N.md` with delta + new hotspot list. Loop to step 2 until the §11.2 exit gate hits (D5).
6. **If fail:** `git revert` the change (not `git reset` — we keep the measurement record), annotate the family report with "hypothesis H rejected by measurement", loop to step 2 with next hypothesis.

Hard stops (force family exit):
- §11.2 exit gate hit (criterion median ≤ §11.2 upper AND p99 ≤ 2× §11.2 upper AND top hotspot < 5% or floor) — see D5
- 3 consecutive rejected hypotheses — stop, document the wall, move to next family
- Change would require public-API / ABI surface modification — stop, file as future spec-change candidate, move on

### 5.2 Priority order (restates D4)

| Rank | Family | Rationale |
|---|---|---|
| 1 | `poll` | Every loop iteration; first user of `EngineNoEalHarness`; shakes out surrogate |
| 2 | `tcp_input` (data + OOO) | Every RX segment; biggest single hot-path cost per §11.2 |
| 3 | `send` (small + large chain) | Every TX segment; large-chain is memory-bound but worth a pass |
| 4 | `flow_lookup` (hot + cold) | Every poll cycle with RX work; cold is where cacheline layout matters |
| 5 | `timer` | RACK / RTO critical path |
| 6 | `tsc_read` (ffi + inline) | Already near floor; polish only |
| 7 | `counters` | Slow-path by policy; cap effort |

### 5.3 Hot-path counter additions (per post-brainstorm clarification)

If optimization evidence shows a useful observability gap (e.g. "we'd want to see how often the SACK-scoreboard fast-path is hit"), a new hot-path counter may be added. Must satisfy `feedback_counter_policy`:
- Compile-time feature gate (typically under `obs-*` or a new `obs-<name>` feature)
- Batched increment (once per burst / once per poll cycle, not per segment)
- Documented justification in the iteration report: what decision does this counter inform, and what measurement showed the hot-path cost fits

No unconditional hot-path counters.

### 5.4 Exit criteria

Worktree 1 is **done** when all of:
- Every §11.2 target beaten per D5 (criterion median ≤ upper bound, p99 ≤ 2× upper bound)
- Every family has a final `<family>-iter-N.md` whose top-hotspot list has no entry ≥ 5% cycles OR documents every such entry as a known floor
- Full bench suite runs clean (no `--lenient`, no discipline violations)
- `docs/superpowers/reports/perf-23.11/summary.md` committed with per-family before/after + retained optimizations list + rejected-hypotheses list

---

## 6. Worktree 2 — DPDK 24.11 LTS rebase + target-API adoption

### 6.1 Phase 1 — Rebase (single task)

1. Install DPDK 24.11 LTS side-by-side with 23.11 (`/usr/local/dpdk-24.11/`). Worktree's `scripts/check-perf-host.sh` (or a `.envrc`) pins `PKG_CONFIG_PATH` to see 24.11 only inside this worktree.
2. `crates/dpdk-net-sys/build.rs` — bump `atleast_version("23.11")` → `atleast_version("24.11")`. Rerun bindgen. Expect breakage around renamed `rte_eth_rx_offload_*` flags, `rte_flow` struct shape changes, `rte_mbuf` dynfield adjustments.
3. Audit A-HW-critical sites for API drift:
   - `crates/dpdk-net-core/src/port_config.rs` (ENA PMD runtime-probe, offload-capability reads)
   - `crates/dpdk-net-core/src/engine.rs` (EAL init, mempool creation, rte_eth_dev_* usage)
   - Any `rte_dynfield_*` consumers (RX timestamp dynfield)
4. Full test sweep — `cargo test` on every crate, `cargo bench --no-run` on every bench. Hard stop on any regression; fix before moving on.
5. **Re-baseline bench-micro** — 3× per family (5× for `send_small` + `send_large_chain` per §6.1.5 ENA TX note). Commit `docs/superpowers/reports/perf-dpdk24/baseline-rebase.md` with side-by-side delta vs 23.11.

**6.1.5 ENA TX regression check.** DPDK 24.07 reportedly regressed total ENA throughput (even though the TX logger was reworked favorably). `bench_send_small` and `bench_send_large_chain` get 5 runs at Phase 1 baseline. If median regresses > 10% vs 23.11, the regression is flagged in the baseline report and `rte_ptr_compress` adoption (§6.2 task 2.2) is promoted ahead of other target APIs to attempt remediation.

### 6.2 Phase 2 — Target-API adoption (one task per API)

Each task: read 24.11 doc + one reference example from `dpdk/examples/` → identify our code's analogous site → port → run affected bench families 3× → commit `docs/superpowers/reports/perf-dpdk24/adopt-<api>.md` with before/after + go/no-go verdict.

| # | API | DPDK version | Our likely sites | Bench families affected | Go/no-go rule |
|---|---|---|---|---|---|
| 2.1 | `rte_lcore_var` | 24.11 | Per-lcore state in `engine::Engine`; any `__rte_cache_aligned` + `RTE_CACHE_GUARD` in `crates/dpdk-net-core/` | `poll`, `counters`, `flow_lookup` | Adopt iff p50 improves on ≥ 1 family and p99 does not regress elsewhere; revert otherwise |
| 2.2 | `rte_ptr_compress` | 24.07 | TX mbuf-burst pointer arrays in `tcp_output`; RX burst arrays in `engine::poll_once` | `send` (both), `poll` | Adopt iff memory-bandwidth-bound benches improve; revert if small-segment bench regresses (compress overhead > bandwidth saved). `bench_send_large_chain` is the primary candidate |
| 2.3 | `rte_bit_atomic_*` | 24.11 | Any `AtomicU32 + bit-mask` pattern in `tcp_conn.rs`, `tcp_events.rs`, connection-state flags | `tcp_input`, `timer` | Adopt iff p99 tail improves; skip cleanly if no matching sites (some are already word-atomics) |
| 2.4 | ENA TX logger rework | 24.07 | Passive — no code change; verify via `rte_eth_dev_info` or log inspection | `send_small`, `send_large_chain` | Always-on with 24.11; this task is measurement confirmation only. If §6.1.5 flagged a regression, this task records whether the rework mitigated it |
| 2.5 | Per-CPU PM QoS | 24.11 | N/A — busy-poll engine | N/A | **Deferred.** Document "no wake-up path" and move on |
| 2.6 | `rte_thash_gen_key` | 24.11 | RSS key in `port_config.rs` | N/A | **Deferred** — single-queue Stage 1; no RSS imbalance. File as Stage 2 |

Tasks 2.5 and 2.6 ship as **documented deferrals**, not silent omissions.

### 6.3 Phase 3 — Port Worktree-1 wins forward

Runs only after Worktree 1 is through its exit criteria AND Worktree 2 Phase 2 is complete. For each Worktree-1 optimization, `git cherry-pick` onto Worktree 2 if trivial; otherwise re-implement against 24.11 API shape. Re-measure every ported change. Regressions get `git revert` + a per-port report entry documenting "optimization-X does not carry forward on 24.11 because Y".

Produces `docs/superpowers/reports/perf-dpdk24/port-forward-<change>.md` per ported optimization.

### 6.4 Exit criteria

Worktree 2 is **done** when:
- Phase 1 baseline committed (delta vs 23.11 known; ENA TX regression check noted)
- Phase 2 has a decision on every target API (adopted, reverted, or deferred-with-rationale) — each with its own report
- Phase 3 has re-measured every cherry-picked Worktree-1 win — each with a port-forward report
- `docs/superpowers/reports/perf-dpdk24/summary.md` committed with rebase delta + per-API deltas + ported-wins deltas + **net recommendation**: *stay on 23.11* or *promote 24.11 to the pinned target*

---

## 7. Weekly sync, exit, reports, final review

### 7.1 Weekly sync

Every 7 days (or whenever either worktree closes a family/API task, whichever comes first):

1. **Metadata check** — run `scripts/check-perf-host.sh` on both worktrees' most-recent baseline rows. Any host-config drift = both worktrees re-baseline before comparing.
2. **Number diff** — one-line table in `docs/superpowers/reports/perf-sync/sync-YYYY-MM-DD.md` showing per-family criterion median + p99 on both sides + §11.2 target + current gap.
3. **Cross-pollination** — if Worktree 1 lands an API-agnostic win (cacheline layout, branch prediction, slab reuse), cherry-pick onto Worktree 2 same day. Vice versa for any 24.11-only technique with a 23.11 back-port.
4. **Never cross** `crates/dpdk-net-sys/build.rs` — that's the DPDK-version boundary and stays split per worktree.
5. **Kill criterion** — if one worktree goes 3 weeks without beating §11.2 for a single family, stop that worktree and fold effort into the other. Documented, not silent.

### 7.2 End-of-effort two-stage review

Per branch, in parallel, opus 4.7 subagents (per `feedback_subagent_model` + `feedback_per_task_review_discipline`):

1. **Spec-compliance reviewer** (custom prompt — not the vendored `rfc-compliance-reviewer`): does the branch violate project-context scoping decisions, A10 design spec clauses, §11.2 targets, or `feedback_counter_policy`? Does it drag in public-API surface that wasn't approved (aside from the `bench-internals` feature)? Each flagged item blocks the cherry-pick until resolved or explicitly accepted.
2. **Code-quality reviewer** (`superpowers:code-reviewer`): repo style, dead code, hot-path regressions, missing tests, comment hygiene. Standard end-of-step checks.

Both pass → cherry-pick surviving commits onto a new integration branch off master, run full `cargo test` + `cargo bench --no-run` + hardening scripts (`scripts/hardening-all.sh` if available), fast-forward onto master once green.

### 7.3 Decision matrix — which worktree ships forward

| Outcome | 23.11 worktree | 24.11 worktree | Action |
|---|---|---|---|
| Both pass §11.2; 24.11 materially better | beats targets | beats targets + ≥ 5% additional win | Promote 24.11 to pinned target; amend `project_context` + Stage-1 spec §8 + roadmap |
| Both pass §11.2; 24.11 comparable or worse | beats targets | beats targets but not materially better, or ENA TX regression | Stay on 23.11; ship 23.11 optimizations; 24.11 stays as tagged reference branch |
| Only 23.11 passes | beats targets | rebase/port blockers | Stay on 23.11; ship 23.11 optimizations; file 24.11 blockers for future phase |
| Only 24.11 passes | walled off, can't hit §11.2 without 24.11 APIs | beats targets | Promote 24.11 (note: this outcome is unlikely given `rte_lcore_var` etc. have 23.11-shaped analogs via `__rte_cache_aligned`) |
| Neither passes | stuck | stuck | Stop; document walls; file follow-on phase |

### 7.4 Final artifact layout

```
docs/superpowers/reports/
├── perf-23.11/
│   ├── <family>-baseline.md         # 7 files
│   ├── <family>-iter-N.md           # N iterations per family
│   └── summary.md                   # Worktree 1 outcome
├── perf-dpdk24/
│   ├── baseline-rebase.md           # Post-rebase vs 23.11
│   ├── adopt-<api>.md               # Per target API (adopted / reverted / deferred)
│   ├── port-forward-<change>.md     # Per cherry-picked Worktree-1 win
│   └── summary.md                   # Worktree 2 outcome + 24.11 recommendation
├── perf-sync/
│   └── sync-YYYY-MM-DD.md           # One per weekly sync
└── perf-a10-postphase.md            # Final cross-worktree summary; merged onto master
```

---

## 8. Risks + mitigations

| Risk | Mitigation |
|---|---|
| uProf install fails on this AWS kernel (IBS/msr module issues under KVM) | Install is §4.1 first check; failure blocks everything else and is addressed before any code work. If IBS genuinely unavailable under KVM, fall back to TBP-only + perf_events, documented. |
| `EngineNoEalHarness` diverges from real `Engine::poll_once` behavior; optimizations we measure don't transfer | Cross-check: every Worktree-1 optimization that survives end-of-effort review gets a correctness run via existing `cargo test` on `dpdk-net-core`. Optimizations that alter `Engine`-proper code are validated by the existing test suite. |
| DPDK 24.11 rebase produces an ENA TX regression we can't fix | §6.1.5 flags this at Phase 1. If rework + `rte_ptr_compress` adoption can't recover the loss, Worktree 2 exits with "stay on 23.11" recommendation (decision matrix row 2). 23.11 worktree's optimizations are still the ship path. |
| Worktrees drift such that numbers aren't comparable | §7.1 weekly sync runs `check-perf-host.sh` on both sides; any metadata drift forces re-baseline. Criterion baselines are per-worktree but the §11.2 target table is shared and absolute. |
| Exploratory landing policy leaks changes to master that shouldn't ship | §7.2 two-stage review at end-of-effort is the gate. Worktree branches never merge wholesale. Every cherry-pick requires both reviewers pass. |
| Hot-path counter additions accrete past policy | `feedback_counter_policy` check is explicit in the spec-compliance reviewer prompt. Batched + feature-gated + justified — all three or no counter. |
| 24.11 API adoption requires changes too broad to be exploratory-only | If any 24.11 adoption needs public-API surface change, it becomes a spec-change candidate per §5.1 hard-stop rule; documented and deferred, not smuggled in. |
| Iteration thrash on one family; no progress | 3-consecutive-rejected-hypotheses hard stop (§5.1). Documented wall, move on. |

---

## 9. §11.2 microbench targets — reference table

Reproduced from Stage-1 design spec §11.2 for convenience. The **upper bound** is the D5 pass threshold per family.

| Bench | Measures | Target |
|---|---|---|
| `bench_poll_empty` | `Engine::poll_once` with no RX, no timers | tens of ns |
| `bench_poll_idle_with_timers` | `Engine::poll_once` with `tcp_tick` walking an empty wheel bucket | tens of ns |
| `bench_tsc_read_ffi` | `dpdk_net_now_ns` via FFI | ~5 ns |
| `bench_tsc_read_inline` | `dpdk_net_now_ns_inline` (header-inline) | ~1 ns |
| `bench_flow_lookup_hot` | 4-tuple hash lookup, all connections hot in cache | ~40 ns |
| `bench_flow_lookup_cold` | 4-tuple hash lookup, flow-table cacheline flushed | ~200 ns |
| `bench_tcp_input_data_segment` | `tcp_input` for a single in-order data segment, PAWS+SACK enabled | ~100–200 ns |
| `bench_tcp_input_ooo_segment` | `tcp_input` for an out-of-order segment that fills a hole | ~200–400 ns |
| `bench_send_small` | `dpdk_net_send` of 128 bytes (fits single mbuf) | ~150 ns |
| `bench_send_large_chain` | `dpdk_net_send` of 64 KiB (mbuf chain) | ~1–5 µs |
| `bench_timer_add_cancel` | `dpdk_net_timer_add` followed by `dpdk_net_timer_cancel` | ~50 ns |
| `bench_counters_read` | `dpdk_net_counters` + read of all counter groups | ~100 ns |

---

## 10. Follow-on work (not part of this effort)

Filed here as placeholders so future sessions don't re-ask:

- **End-to-end optimization via `bench-e2e`** — convert microbench wins to RTT/throughput numbers on the paired EC2 pair; would follow this effort if `bench-e2e` is promoted to a repeatable measurement.
- **Multi-queue RSS + `rte_thash_gen_key`** — Stage 2 item; only relevant when we multi-queue.
- **arm64 rebuild** — `project_arm_roadmap` says don't bake x86-only assumptions. The `bench-internals` feature must stay arch-neutral; `rte_lcore_var` adoption ditto.
- **CI wiring** — A10 delivered `scripts/bench-nightly.sh`; integrating the new host-config checker + per-family regression gates into nightly CI is left to the user.
- **`obs-*` feature-gate defaults revisit** — A10's `bench-obs-overhead` owns this question; if this effort discovers a counter default that should flip, file against A10's follow-on list.

---

**End of design.**
