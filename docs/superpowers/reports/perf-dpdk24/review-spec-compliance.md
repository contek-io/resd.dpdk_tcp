# Spec-compliance review — a10-dpdk24-adopt

**Reviewer:** opus 4.7 reviewer subagent (T6.3)
**Branch:** a10-dpdk24-adopt
**Worktree path:** `/home/ubuntu/resd.dpdk_tcp-a10-dpdk24`
**Branch HEAD:** `a1b909e` (`a10-dpdk24: T4.12 worktree-2 summary + 24.11 pinning recommendation`)
**Reviewed unique-to-W2 commits:** 9 (per `git log --cherry-pick --right-only a10-perf-23.11...HEAD`)
**Spec reference:** `docs/superpowers/specs/2026-04-23-a10-microbench-perf-and-dpdk24-adopt-design.md`
**Plan reference:** `docs/superpowers/plans/2026-04-23-a10-microbench-perf-and-dpdk24-adopt.md`

## Verdict

**PASS-WITH-CAVEATS**

The "stay on 23.11" recommendation is sound and correctly maps to spec §7.3 decision-matrix row 2. The four per-API deferral reports carry credible survey evidence. `deferrals.md` correctly enumerates all four pre-declared D6 deferrals. `baseline-rebase.md` claims match the data without overreach. `port-forward-poll-H1.md` correctly reports criterion p<0.05 with confidence interval. The commit list in `summary.md` matches the actual git log.

One low-severity caveat: documentation cross-reference filenames in `summary.md` and `deferrals.md` use underscores (`adopt-rte_lcore_var.md`) but actual files use hyphens (`adopt-rte-lcore-var.md`). Cosmetic — broken markdown links — not a spec violation.

## Findings

| # | Severity | Commit | File:line | Issue | Recommendation |
|---|---|---|---|---|---|
| 1 | LOW | a1b909e | `summary.md:51-54` | Cross-references `adopt-rte_lcore_var.md` / `adopt-rte_ptr_compress.md` / `adopt-rte_bit_atomic.md` (underscores), but actual files use hyphens. Broken links in markdown viewers that respect filename case. | Doc-only fix; not a block. Either rename the four files to underscore form, or fix the references in `summary.md` and `deferrals.md`. |
| 2 | LOW | b5399d7 | `deferrals.md:3, 45-47` | Same underscore/hyphen drift as #1 (the deferrals table cross-links to underscore-named adopt files). | Same fix as #1 (handle together). |

No blocking findings. All spec-compliance criteria met; the doc finding is cosmetic.

## Pinning-recommendation soundness check

**The "stay on 23.11" recommendation correctly maps to spec §7.3 decision-matrix row 2:** "Both pass §11.2; 24.11 comparable or worse" → "Stay on 23.11; ship 23.11 optimizations; 24.11 stays as tagged reference branch."

Evidence supporting row 2 vs other rows:

1. **Both worktrees pass §11.2 budgets at the same families.** `summary.md` Phase 3 table shows 9-of-10 measurable benches within budget on 24.11 post-port-forward — the same gate-met-rate as Worktree 1. `bench_tsc_read_*` is host-ceiling on KVM TSC virtualization regardless of DPDK version (10.18 ns ffi / 10.33 ns inline; would meet on bare-metal). `bench_send_*` is stub — N/A both sides.

2. **24.11 is "comparable or worse" within criterion noise on the rebase boundary.** `baseline-rebase.md` table shows 10 of 12 benches within ±5% of 23.11 medians. The two |Δ%|>10% rows (`bench_tcp_input_ooo_segment` -15.6%, `bench_counters_read` -38.5%) are improvements with plausible noise-floor explanations (bench-state allocator first-touch / sub-ns criterion overhead floor) — neither attributes to a real 24.11 mechanism. Direction is mixed across the rest. Net: no measurable advantage.

3. **0 of 4 target APIs adopted.** `summary.md` Phase 2 table: `rte_lcore_var` N/A (architectural mismatch), `rte_ptr_compress` deferred-to-e2e (no bench-micro reach), `rte_bit_atomic_*` N/A (no atomic-bit patterns in code), ENA TX logger deferred-pending-T3.3 (no real send wiring). This rules out row 1 ("24.11 materially better").

4. **Worktree 1's H1 + tsc_read H1+H2 cherry-pick cleanly to 24.11 with identical effect.** Both port-forwards (`fcd344f`, `c59a973`) verified -95% / methodology-improvement on 24.11; same magnitude as 23.11. This rules out row 4 ("Only 24.11 passes" — would require 23.11 to be walled off, which it is not — H1 lands cleanly on both).

5. **Re-visit triggers documented.** `summary.md:106-112` lists four conditions that would change the recommendation (Stage-1 ship done, T3.3 lands + bench-pair host, Stage 2 multi-queue, external pressure). Honest deferral with a re-evaluation gate, not a permanent rejection.

The recommendation is data-supported, conservatively framed (rebase is safe; option to upgrade later is preserved), and consistent with spec §7.3 + risk §8 row "DPDK 24.11 rebase produces an ENA TX regression we can't fix" → "Worktree 2 exits with stay-on-23.11 recommendation." The actual outcome was even cleaner than that risk path: no ENA TX regression because send is stubbed; the conclusion is the same.

## Per-API deferral rationale check

| API | Report | Deferral reason | Evidence credibility |
|---|---|---|---|
| `rte_lcore_var` | `adopt-rte-lcore-var.md` | N/A — 0 candidate sites; Stage-1 single-Engine-per-lcore architecture, not per-lcore-array. The 5 `repr(C, align(64))` sites are false-sharing isolation between counter groups (single-instance), not per-lcore-slab pattern. | **Credible.** Survey table at `adopt-rte-lcore-var.md:14-23` enumerates pattern-search counts; references to `engine.rs:533` and `EngineConfig` commentary at `engine.rs:401-405` ground the architectural claim. The distinction between cache-aligned-for-false-sharing and per-lcore-array is correctly drawn — these solve different problems and `rte_lcore_var` does not address the former. |
| `rte_ptr_compress` | `adopt-rte-ptr-compress.md` | Deferred-to-e2e — 1 candidate site at `engine.rs:2077` (`[*mut rte_mbuf; 32]` RX burst), but `EngineNoEalHarness::poll_once` doesn't call `shim_rte_eth_rx_burst` (no DPDK port allocation in harness); send is stubbed per T2.7 deferral. Bench-micro can't measure. | **Credible.** Site table at `adopt-rte-ptr-compress.md:14-22` enumerates all five candidate-relevant sites with line numbers, distinguishes the one viable RX-burst site from four 1-element TX scratches (where compression is principled-impossible) and the variable-length tx_pending_data ring. The "no bench-micro reach" claim is verifiable from harness source. The recommendation to re-evaluate when T3.3 + bench-pair host land matches plan §6.2 ("adopt iff measurement shows improvement"). |
| `rte_bit_atomic_*` | `adopt-rte-bit-atomic.md` | N/A — 0 candidate sites; codebase scan found 0 instances of `fetch_or` / `fetch_and` / `fetch_xor` / `fetch_nand`. Atomic surface is exclusively `fetch_add(_, Relaxed)` and `load(Relaxed)` on counters. | **Credible.** Pattern-search table at `adopt-rte-bit-atomic.md:14-22` is unambiguous: 0 fetch_or/and/xor/nand uses, AtomicU64 used only in counters arithmetic + load. The architectural claim that connection flags are scalar bools (single-lcore RTC, no atomicity) is consistent with the Stage-1 design that this entire effort is grounded in. |
| ENA TX logger rework (24.07) | `adopt-ena-tx-logger.md` | Deferred-pending-T3.3 + bench-pair host — passive driver-internal change, no application-side surface. Verification requires real `dpdk_net_send` execution + real ENA NIC; both are out-of-scope. | **Credible.** The deferral is structurally correct: there is no application-side adoption to perform regardless. The verification question is "did the rework deliver a measurable median+p99 reduction on real ENA send" — which by construction cannot be answered on a stub send path or a KVM host. Cross-references `baseline-rebase.md` §6.1.5's stub-noise-floor 5× run as a future-baseline reference; honest about why it's not a measurement. |

All four reports correctly distinguish:
- **N/A vs deferred-to-e2e:** N/A means "no candidate sites ever" (`rte_lcore_var`, `rte_bit_atomic_*`); deferred-to-e2e means "candidate exists but our test scope can't measure" (`rte_ptr_compress`, ENA TX logger).
- **Architectural mismatch vs scope-mismatch:** the `rte_lcore_var` and `rte_bit_atomic_*` reports correctly identify their N/A as architectural (Stage-1 design choice), while the other two are scope-mismatch (bench-micro can't reach the relevant code path).

This matches plan §6.2 discipline ("adopt iff measurement shows improvement") and avoids the temptation to ship a speculative adoption.

## Pre-declared deferrals (D6) enumeration check — `deferrals.md`

Spec §1 D6 lists four pre-declared deferrals:
- Per-CPU PM QoS (24.11)
- `rte_thash_gen_key` (24.11)
- Intel E830 / ice driver (24.07)
- Event pre-scheduling / eventdev (24.11)

`deferrals.md` enumerates all four:
- `deferrals.md:5-11` — Per-CPU PM QoS resume latency (24.11) ✓
- `deferrals.md:13-21` — `rte_thash_gen_key` (24.11) ✓
- `deferrals.md:23-29` — Intel E830 / `ice` driver (24.07) ✓
- `deferrals.md:31-37` — Event pre-scheduling / `eventdev` `preschedule_type` (24.11) ✓

None silently missed. Each carries a "Future revisit" pointer (Stage 4/5+ for PM QoS, Stage 2 multi-queue for `rte_thash_gen_key`, "only if Intel SmartNIC adopted" for ice, Stage 5+ pipeline for eventdev). Cross-link to T4.7-4.10 outcomes at `deferrals.md:39-50` is accurate.

## `baseline-rebase.md` claims-vs-data check

Cross-checked `baseline-rebase.md` claims against the data it cites:

- **Side-by-side table at `baseline-rebase.md:15-28`** — 12 rows with 23.11 / 24.11 medians + Δ + Δ%. The cited 23.11 source is `/home/ubuntu/resd.dpdk_tcp-a10-perf/docs/superpowers/reports/perf-23.11/opportunity-matrix.md` (T3.0 baseline, commit `acedb33`); the cited 24.11 source is `profile/full-suite-baseline-rebase/results.csv`. Numbers in the table match the same numbers reproduced in `summary.md`'s post-rebase table. No fabricated comparisons.
- **|Δ%|>10% flagging** at `baseline-rebase.md:30, 60-77` — both flagged rows (`bench_tcp_input_ooo_segment` -15.6%, `bench_counters_read` -38.5%) are correctly identified as improvements (not regressions) with plausible noise-floor explanations. The report avoids attributing them to a 24.11 mechanism that isn't there ("DPDK 24.11 doesn't touch the Rust-side TCP input path which is what this bench exercises").
- **ENA TX regression check** at `baseline-rebase.md:32-50` — correctly states "**N/A** for this baseline" with rationale that the stubs don't exercise `dpdk_net_send` or any DPDK TX path. The 5× variance numbers (3.2% / 1.5% relative stddev) are correctly framed as a "stub noise-floor reference for future T3.3 work that wires real send," not as an ENA TX measurement.
- **Verdict** at `baseline-rebase.md:54-56` — "neutral / mixed within noise" matches the data: 10 of 12 rows are within ±5% noise; 2 are improvements with noise-floor explanations.
- **Caveats** at `baseline-rebase.md:96-101` — diagnostic baseline (THP=madvise, no governor); sub-ns benches are noise-floor; stub send benches not ENA-bound; pre-optimization comparison; same-host comparison only. All five caveats are honest framings of the measurement's reach.

No claims overreach the data.

## `port-forward-poll-H1.md` criterion p<0.05 check

`port-forward-poll-H1.md:17`:
> Criterion verdict: `Performance has improved.` (p < 0.05). Confidence interval: `[-95.938% -95.196% -94.240%]` for `bench_poll_idle_with_timers`. The improvement matches the magnitude observed on 23.11 (T3.1: 1031 → 45.8 ns, 1165 → 50.7 ns).

This is correctly framed:
- Criterion's textual verdict format matches what the criterion harness emits.
- Confidence interval format `[low p50 high]` is criterion's standard `-95% [low high]` triple.
- Magnitude match between W2 (1039 → 46 ns / 1139 → 51.5 ns) and W1 (1031 → 45.8 / 1165 → 50.7) is ±1 ns absolute → indistinguishable at this noise floor; correct claim.
- §11.2 budget verification at lines 23-26 shows both poll benches within 100 ns upper.
- Caveats at lines 31-33 correctly note the diagnostic baseline noise-floor caveat.

The "DPDK-version-agnostic" framing at lines 35-37 is supported: H1 lives in pure-Rust harness code (`engine::test_support::EngineNoEalHarness`), no DPDK API surface touched, so a clean cherry-pick with identical effect is the expected outcome.

## Worktree-2 commit-list match check

`summary.md:130-145` lists Worktree-2 commits. Cross-referenced with `git log --cherry-pick --right-only a10-perf-23.11...HEAD`:

| `summary.md` listing | Actual SHA | Match |
|---|---|---|
| `<this commit>` (T4.12 summary) | `a1b909e` | ✓ self-reference |
| `c59a973` (tsc_read H1+H2 cherry-pick) | `c59a973` | ✓ |
| `d22e15b` (T5 port-forward poll H1) | `d22e15b` | ✓ |
| `fcd344f` (poll H1 cherry-pick) | `fcd344f` | ✓ |
| `b5399d7` (T4.11 deferrals) | `b5399d7` | ✓ |
| `de71de1` (ENA TX logger) | `de71de1` | ✓ |
| `38b6905` (rte_bit_atomic) | `38b6905` | ✓ |
| `84c9333` (rte_ptr_compress) | `84c9333` | ✓ |
| `803c549` (rte_lcore_var) | `803c549` | ✓ |
| `322cd60` (T4.5-4.6 baseline) | `322cd60` | ✓ |
| `<rebase>` (atleast_version bump) | `e4b02c1` | ✓ |

Cherry-pick mapping `5b8ee71 → fcd344f` (W1 → W2 for poll H1) and `2cc6829 → c59a973` (W1 → W2 for tsc_read H1+H2) are both verified — `5b8ee71` and `2cc6829` exist on `/home/ubuntu/resd.dpdk_tcp-a10-perf` as the originals. No phantom commits, no missed commits.

## Notes

- The single CODE change in W2's unique commits (build.rs version bump + new `scripts/use-dpdk24.sh`) is mechanical and out-of-scope for spec-compliance angle (covered by code-quality review T6.4). Spec D6's recipe ("Bump `atleast_version("23.11")` → `atleast_version("24.11")`, rerun bindgen, fix breakage, re-run full test sweep") is executed faithfully — `summary.md` Phase 1 reports clean rebase with zero application-side fix commits, 1064 tests pass, 5 harness tests pass, all 30+ benches compile.
- The `<rebase>` placeholder in `summary.md:141` for the version-bump commit is slightly imprecise (the actual SHA `e4b02c1` is what readers want); not a spec issue, just stylistic.
- The "Cherry-pick candidate set for Phase 6 master integration" guidance at `summary.md:120-127` correctly states no Worktree-2-specific code commits should ship to master directly; the survey reports may optionally land on master as documentation. This matches the exploratory-landing-policy framing in spec §7.2.
- Re-visit triggers at `summary.md:106-112` are well-defined and gate the future re-evaluation on concrete prerequisites (T3.3 + bench-pair host); nothing wishy-washy.
- The honesty discipline noted in the review prompt ("don't push for adoption that the data doesn't support") is met: 0/4 adoption is the honest outcome.
