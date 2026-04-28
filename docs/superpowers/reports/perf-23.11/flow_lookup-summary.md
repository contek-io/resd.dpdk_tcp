# flow_lookup family — A10-perf-23.11 — summary

## Final criterion numbers

| Bench                    | T3.0 baseline | Re-verified post-T3.1 | §11.2 upper | Within budget? |
|--------------------------|---------------|-----------------------|-------------|----------------|
| `bench_flow_lookup_hot`  | 27.07 ns      | 25.88 ns              | 40 ns       | ✓              |
| `bench_flow_lookup_cold` | 95.20 ns      | 89.64 ns              | 200 ns      | ✓              |

Both benches stay within budget (hot: ~65% of upper; cold: ~45% of upper).
Re-verified numbers are slightly lower than T3.0 (hot: Δ -4.4%; cold: Δ -5.8%)
and within criterion's expected run-to-run variance band on this KVM host. The
"Performance has improved" verdicts (p < 0.05) reflect statistical signal of
small drift, not a code-path change — T3.1 did not touch FlowTable.

## Optimizations applied

None — family already within §11.2 at baseline. Per Procedure P1 step 9 first
exit condition (gate met), the iteration cycle terminates at baseline.

## Caveats

- Diagnostic baseline (THP=madvise, governor unavailable on KVM); re-baseline
  after host re-tune. Numbers stayed within budget under noise; expect tighter /
  lower medians on the hardened host.
- uProf TBP could not resolve workload symbols on this short bench under KVM
  (1 ms sampling vs ~26 ns hot / ~90 ns cold workload). Fortunately not needed
  — gate met without optimization.
- T3.1's H1 (EngineNoEalHarness::poll_once scratch reuse) does NOT touch this
  family's code path; flow_lookup benches call `FlowTable::lookup_by_tuple`
  directly via the bench-internals re-exports without going through the harness.
  Re-verification confirmed numbers are unaffected (drift within KVM-host
  variance band).

## Exit reason

**gate-met-at-baseline** (P1 step 9 first condition).

## Future-work notes

Cache-line layout of `FlowTable::buckets` + `TcpConn` is a known optimization
vector if cold-variant degrades. Specifically, if `bench_flow_lookup_cold`
starts approaching its 200 ns upper, candidate work includes: (a) verifying
bucket-array stride is a multiple of cache-line size; (b) ensuring the
hot-cold split inside `TcpConn` keeps the lookup-key fields (5-tuple +
generation) in the first cache line; (c) considering a separate compact
fingerprint table for the lookup hash-bucket walk to reduce cold-line fetches
when the conn body itself isn't needed for the early reject path.

The hot-variant has a tighter ~14 ns headroom but is dominated by hash
computation + first-cache-line load — likely already near the theoretical
floor for this workload shape on this host. Any future regression on the hot
path would warrant re-running `cargo bench --bench flow_lookup` against
`--baseline base-pre-opt`.
