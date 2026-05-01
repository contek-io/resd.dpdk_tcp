# Observability Overhead Report

Run: d5fb7b85-55d8-4e31-8dea-17a40b1386e6
Date: 2026-04-29T13:58:38.063936493+00:00
Commit: 
Workload: 128 B / 128 B request-response, N=100000 per config, warmup=1000

## Summary Table

| Config | Features | p50 (ns) | p99 (ns) | p999 (ns) | delta_p99 vs obs-none | Decision | Default | Action (if fail) |
|---|---|---|---|---|---|---|---|---|
| obs-none | obs-none | 34609.00 | 42260.00 | 47629.00 | — | — | OFF | — |
| poll-saturation-only | obs-poll-saturation | 34360.00 | 40870.00 | 46840.00 | -1390.00 ns | NoSignal | ON | — |
| byte-counters-only | obs-byte-counters | 34600.00 | 42030.00 | 47480.00 | -230.00 ns | NoSignal | OFF | — |
| obs-all-no-none | obs-all | 34589.00 | 41520.00 | 46760.00 | -740.00 ns | NoSignal | (composite) | — |
| default | (prod default) | 34160.00 | 40830.00 | 45980.00 | -1430.00 ns | NoSignal | N/A | — |

Noise floor (2 back-to-back obs-none runs, |p99 delta|): 380.00 ns (raw); 380.00 ns (clamped)
Decision threshold (3 × clamped noise floor): 1140.00 ns

## Sanity Invariant

Lowest p99 (obs-none): 42260.00 ns
Any p99 < 42260.00 ns? YES -> VIOLATION (an observable is either dead code, a regression, or inside the noise floor)
- poll-saturation-only: p99 = 40870.00 ns
- byte-counters-only: p99 = 42030.00 ns
- obs-all-no-none: p99 = 41520.00 ns
- default: p99 = 40830.00 ns

Diagnostic: observability floor violated: config 'poll-saturation-only' p99 40870 < obs-none p99 42260 (observability can only add cost; either the observable is dead code, the implementation regressed, or the delta is within measurement noise); observability floor violated: config 'byte-counters-only' p99 42030 < obs-none p99 42260 (observability can only add cost; either the observable is dead code, the implementation regressed, or the delta is within measurement noise); observability floor violated: config 'obs-all-no-none' p99 41520 < obs-none p99 42260 (observability can only add cost; either the observable is dead code, the implementation regressed, or the delta is within measurement noise); observability floor violated: config 'default' p99 40830 < obs-none p99 42260 (observability can only add cost; either the observable is dead code, the implementation regressed, or the delta is within measurement noise)

## Decision → Action Recommendations

For each Signal with default=ON, the implementer reviews the table and picks one of the action-taxonomy options in a follow-up commit, NOT automated by the harness:

- **batch** — accumulate the increment in a per-poll local and `fetch_add` once per `poll_once`
- **remove** — eliminate the counter entirely
- **flip default** — move the feature from default-ON to default-OFF (opt-in)
- **move off hot path** — relocate the emission to a slow-path decision point

No Signal + default=ON rows this run — no action required.

## Commit History

(git log unavailable)

## Full CSV

See `/tmp/bench-obs-overhead-out/d5fb7b85-55d8-4e31-8dea-17a40b1386e6.csv`.
