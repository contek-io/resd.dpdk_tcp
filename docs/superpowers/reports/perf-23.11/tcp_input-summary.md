# tcp_input family — A10-perf-23.11 — summary

## Final criterion numbers

| Bench                          | T3.0 baseline | Re-verified post-T3.1 | §11.2 upper | Within budget? |
|--------------------------------|---------------|-----------------------|-------------|----------------|
| `bench_tcp_input_data_segment` | 86.04 ns      | 86.53 ns              | 200 ns      | ✓              |
| `bench_tcp_input_ooo_segment`  | 84.86 ns      | 75.54 ns              | 400 ns      | ✓              |

Both benches are well within budget (data: ~43% of upper; ooo: ~19% of upper).
The data-segment number matches T3.0 within criterion noise (Δ +0.6%, p = 0.43,
"No change in performance detected"). The ooo-segment number is ~11% lower than
T3.0 (criterion verdict: "Performance has improved", p = 0.25 — i.e. statistically
weak) and is consistent with KVM-host run-to-run variance on a workload at this
scale; it does not indicate a real change in the dispatch path. The ooo bench
remains far below its upper.

## Optimizations applied

None — family already within §11.2 at baseline. Per Procedure P1 step 9 first
exit condition (gate met), the iteration cycle terminates at baseline.

## Caveats

- Diagnostic baseline (THP=madvise, governor unavailable on KVM); re-baseline
  after host re-tune. Numbers stayed within budget under noise; expect tighter /
  lower medians on the hardened host.
- uProf TBP could not resolve workload symbols on this short bench under KVM
  (1 ms sampling vs ~85 ns workload). Fortunately not needed — gate met without
  optimization.
- T3.1's H1 (EngineNoEalHarness::poll_once scratch reuse) does NOT touch this
  family's code path; tcp_input benches call `tcp_input::dispatch` directly via
  the bench-internals re-exports without going through the harness. Re-verification
  confirmed numbers are unaffected (data-segment effectively flat; ooo-segment
  improved within run-to-run noise band).

## Exit reason

**gate-met-at-baseline** (P1 step 9 first condition).

## Future-work notes

If a future change introduces hot-path code into `tcp_input::dispatch` (e.g.
SACK scoreboard expansion, additional PAWS validation, new option parsing),
re-run `cargo bench --bench tcp_input` against `--baseline base-pre-opt` to
detect regression. Both data-segment and ooo-segment benches are sensitive to
the receive-side path and will surface regressions early.
