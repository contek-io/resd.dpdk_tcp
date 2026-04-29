# Offload A/B Report

Run: e1a97f86-ce66-4c93-8566-3dcb06c2f7af
Date: 2026-04-29T13:57:39.912463516+00:00
Commit: 
Workload: 128 B / 128 B request-response, N=100000 per config, warmup=1000

## Summary Table

| Config | Features | p50 (ns) | p99 (ns) | p999 (ns) | delta_p99 vs baseline | Decision |
|---|---|---|---|---|---|---|
| baseline | (none) | 34449.00 | 41189.00 | 47640.00 | — | — |
| tx-cksum-only | hw-offload-tx-cksum | 34590.00 | 42709.00 | 47260.00 | -1520.00 ns | NoSignal |
| rx-cksum-only | hw-offload-rx-cksum | 35220.00 | 43969.00 | 49790.00 | -2780.00 ns | NoSignal |
| mbuf-fast-free-only | hw-offload-mbuf-fast-free | 34380.00 | 40740.00 | 46669.00 | 449.00 ns | **Signal** |
| rss-hash-only | hw-offload-rss-hash | 34630.00 | 42110.00 | 47049.00 | -921.00 ns | NoSignal |
| rx-timestamp-only | hw-offload-rx-timestamp | 34780.00 | 43480.00 | 48129.00 | -2291.00 ns | NoSignal |
| llq-verify-only | hw-verify-llq | 34600.00 | 42130.00 | 46849.00 | -941.00 ns | NoSignal |
| full | hw-offloads-all | 34260.00 | 40170.00 | 45970.00 | 1019.00 ns | **Signal** |

Noise floor (2 back-to-back baselines, |p99 delta|): 89.00 ns (raw); 89.00 ns (clamped)
Decision threshold (3 × clamped noise floor): 267.00 ns

## Sanity Invariant

full p99: 40170.00 ns
Best individual p99: 40740.00 ns (mbuf-fast-free-only)
-> OK

## Commit History

(git log unavailable)

## Full CSV

See `/tmp/bench-offload-ab-out/e1a97f86-ce66-4c93-8566-3dcb06c2f7af.csv`.
