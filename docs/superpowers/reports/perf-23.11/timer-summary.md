# timer family — A10-perf-23.11 — summary

## Final criterion numbers

| Bench                    | T3.0 baseline | Re-verified post-T3.1 | §11.2 upper | Within budget? |
|--------------------------|---------------|-----------------------|-------------|----------------|
| `bench_timer_add_cancel` | 25.02 ns      | 23.94 ns              | 50 ns       | ✓              |

Bench stays within budget (~48% of upper). Re-verified number is slightly
lower than T3.0 (Δ -4.3%) and within criterion's expected run-to-run variance
band on this KVM host. Note: T2.6 already showed ~28 ns; T3.0's 25 ns and the
post-T3.1 re-verification's 24 ns are all within criterion noise of each
other for this microbench.

## Optimizations applied

None — family already within §11.2 at baseline. Per Procedure P1 step 9 first
exit condition (gate met), the iteration cycle terminates at baseline.

## Caveats

- Diagnostic baseline (THP=madvise, governor unavailable on KVM); re-baseline
  after host re-tune. Numbers stayed within budget under noise; expect tighter /
  lower medians on the hardened host.
- uProf TBP could not resolve workload symbols on this short bench under KVM
  (1 ms sampling vs ~24 ns workload). Fortunately not needed — gate met
  without optimization.
- This bench reports a high outlier rate (30/100 in this re-verification, with
  19 low-severe). The criterion median is robust to such outliers; the
  outliers reflect KVM scheduling jitter rather than code-path variability and
  are expected to drop substantially after host re-tune.
- T3.1's H1 (EngineNoEalHarness::poll_once scratch reuse) does NOT touch the
  timer-add/cancel path. While `bench_timer_add_cancel` does call into
  `EngineNoEalHarness::timer_add` / `timer_cancel`, those methods delegate
  straight to `TimerWheel::add` / `cancel`; they do not go through `poll_once`
  and the `conn_handles_scratch` field is not touched. Re-verification
  confirmed numbers are unaffected.

## Exit reason

**gate-met-at-baseline** (P1 step 9 first condition).

## Future-work notes

If RACK / RTO patterns add fields to `TimerNode` (e.g. tracking enqueue
timestamps for SACK rangefinding, or new wheel-bucket metadata for
hierarchical wheels), re-run `cargo bench --bench timer` against
`--baseline base-pre-opt` to detect regression. The current ~24–25 ns range
is dominated by the hashed-wheel insertion + cancellation pair; growth of
`TimerNode` would primarily affect the cache footprint of the bucket linked
list and could push the bench toward the 50 ns upper.
