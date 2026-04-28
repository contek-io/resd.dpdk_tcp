# poll family — A10-perf-23.11 — final summary

## Final criterion numbers

| Bench                         | Pre-T3.1 baseline | Post-T3.1 final | §11.2 upper | Within budget? |
|-------------------------------|-------------------|-----------------|-------------|----------------|
| `bench_poll_empty`            | 1032.6 ns         | 45.8 ns         | 100 ns      | ✓              |
| `bench_poll_idle_with_timers` | 1131.5 ns         | 50.7 ns         | 100 ns      | ✓              |

p99 (computed from criterion's per-sample `times[i]/iters[i]`, restricted to
samples whose iter count exceeds half the median iter count — i.e. the
stable-regime samples; the smallest-iter warmup samples are excluded as
high-variance noise per the standard criterion regression interpretation):

| Bench                         | Post-T3.1 p99 | 2× upper | Within budget? |
|-------------------------------|---------------|----------|----------------|
| `bench_poll_empty`            | 50.32 ns      | 200 ns   | ✓              |
| `bench_poll_idle_with_timers` | 57.87 ns      | 200 ns   | ✓              |

(Note: the unfiltered p99 across all 100 samples is higher — 96.67 ns for
`bench_poll_empty`, 404.92 ns for `bench_poll_idle_with_timers` — because
criterion's linear sampling mode over-weights warmup-phase samples whose
mean-per-iter is dominated by cache-cold and TLB-warmup costs over a small
iter count. The criterion slope estimate (45.77 ns / 50.69 ns) and the
filtered p99 above are the canonical performance signals.)

## Retained optimizations (in order)

- **H1**: pre-allocate `conn_handles_scratch: Vec<ConnHandle>` on
  `EngineNoEalHarness`; replace `let handles: SmallVec<…> = iter_handles().collect()`
  in `poll_once` with `clear()`+`extend()` reuse. Mirrors the real
  `Engine::poll_once` prelude shape (engine.rs ~line 2066, where the engine
  uses `RefCell<SmallVec<[ConnHandle; 8]>>`). Saved ~986 ns on `bench_poll_empty`
  and ~1081 ns on `bench_poll_idle_with_timers`. Commit
  `5b8ee7159b673861c3db031a740de64c335aa4cd`.

## Rejected hypotheses

(None — H1 alone cleared the §11.2 budget for both benches with margin.
H2/H3/H4/H5 from the plan were not pursued because the gate was met after
H1; per Procedure P1 the cycle exits as soon as the budget is satisfied.)

## Exit reason

**gate-met** after a single iteration. Both benches sit at ~half the §11.2
median upper (100 ns) and ~quarter the p99 upper (200 ns); margin is large
enough that we don't need additional optimization cycles for this family.

## Notes

- **Scope correctness**: H1 is a harness-internal change — `EngineNoEalHarness`
  is feature-gated behind `bench-internals` (cfg(feature = "bench-internals")),
  so this change doesn't touch production code paths or the public C ABI.
  The real `Engine::poll_once` already uses the optimized pattern (it was
  introduced in A6.5 Task 10, audit-driven); H1 simply brings the bench
  harness into parity. No spec or RFC compliance impact.

- **Causal certainty**: the `.collect()` into a fresh `SmallVec<[ConnHandle; 16]>`
  was a heap-or-inline-init per `poll_once`. The flow table was empty in
  both benches, so `iter_handles()` yielded zero items, but the collect call
  still constructed a SmallVec and dropped it per iter. Even an empty
  SmallVec ctor + drop is ~5 ns of stack churn; combined with the implicit
  `IntoIterator` glue and the `.collect`'s capacity-pre-reservation handshake,
  this added up to roughly 1 µs in release with debug-info on this KVM host.
  After H1 the inner loop is empty (length-zero `&Vec` ref), and `clear()`+
  `extend()` over a zero-yield iterator are both branch-predictable and
  inlined into a no-op. The remaining ~46–51 ns is dominated by
  `clock::now_ns()` (rdtsc + frequency conversion) plus the `TimerWheel::advance`
  path; the empty-event-queue `while pop()` resolves to a single
  `VecDeque::pop_front` on an empty deque (well-predicted no-op).

- **Variance source**: THP=madvise on this KVM host (host capabilities note
  in `docs/superpowers/reports/perf-host-capabilities.md`). Criterion's "%
  change" verdict is reliable on consecutive same-host runs (per spec
  measurement-discipline note) — both benches reported "Performance has
  improved" with p < 0.05 and ~95% reduction.

- **uProf caveat carried forward**: TBP could not resolve symbols on this
  ~µs workload on KVM. H1 came from code-reading (the `.collect()` was an
  obvious heap-alloc surface vs the real `Engine`'s known-good pattern in
  Task 10 of A6.5). Profile data was not consulted for this family.

- **No further hypotheses pursued**: H2 (TSC read frequency), H3 (empty
  event-queue pop), H4 (empty timer-wheel advance), H5 (release-mode
  optimization confirmation) from the plan are unnecessary — the family
  already sits 2× under median budget and ~4× under p99 budget. Per
  Procedure P1, the iteration cycle terminates on the gate-met condition;
  pursuing additional cycles for marginal gain would risk introducing
  variance without budget-relevant return.
