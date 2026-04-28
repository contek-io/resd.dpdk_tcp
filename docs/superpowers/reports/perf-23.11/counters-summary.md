# counters family — A10-perf-23.11 — summary

## Final criterion numbers

| Bench                 | T3.0 baseline | Re-verified post-T3.1 | §11.2 upper | Within budget? |
|-----------------------|---------------|-----------------------|-------------|----------------|
| `bench_counters_read` | 1.49 ns       | 0.92 ns               | 100 ns      | ✓ (109× under) |

Bench stays well within budget. The re-verified number (916.85 ps median) is
~38% lower than T3.0 (1.49 ns), but the absolute scale here is sub-nanosecond
so the criterion verdict ("Performance has regressed", p < 0.05, in the
opposite direction depending on which way criterion's reference is loaded) is
not meaningful as a code-path signal — both numbers are well below the noise
floor of any plausible workload-relevant target. Both are roughly ~100× under
the §11.2 upper.

## Optimizations applied

None — family already within §11.2 at baseline. Per Procedure P1 step 9 first
exit condition (gate met), the iteration cycle terminates at baseline. With
~100× margin, the family is so far below target that no optimization work is
warranted.

## Caveats

- Diagnostic baseline (THP=madvise, governor unavailable on KVM); re-baseline
  after host re-tune. The bench is so far below budget that host re-tune is
  not expected to materially alter the conclusion.
- uProf TBP cannot meaningfully sample at this scale (1 ms sampling vs ~1 ns
  workload). Not needed — gate met without optimization.
- T3.1's H1 (EngineNoEalHarness::poll_once scratch reuse) does NOT touch the
  counters path; the counters bench calls `dpdk_net_core::counters::*` atomic
  load helpers directly. Re-verification confirmed numbers are unaffected (any
  drift is below the meaningful-signal floor at this scale).

## Exit reason

**gate-met-at-baseline** (P1 step 9 first condition).

## Future-work notes

This is so far below target that even significant counter-struct growth would
still meet §11.2. The bench is essentially measuring the cost of a single
`AtomicU64::load(Ordering::Relaxed)` on an L1-resident cache line; absent a
fundamental change to counter storage (e.g. moving to a sharded /
per-core-replicated layout that adds aggregation overhead on read), the read
cost is already at the architectural floor.

If a per-counter `read` ever shows up >5% in any other family's TBP under the
hardened host, revisit. Otherwise no follow-up needed.
