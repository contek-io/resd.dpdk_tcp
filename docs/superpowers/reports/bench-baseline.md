# resd.dpdk_tcp A10 Bench Report

**Run:** `c8deba07-4b1f-4deb-963e-6f303d9976cf`
**Commit:** ``
**Branch:** ``
**Date:** 2026-04-29T13:18:48.862068781+00:00
**Host:** ip-10-0-0-175 ()
**CPU:** AMD EPYC 7R13 Processor
**DPDK:** 23.11.0
**Kernel:** 6.8.0-1052-aws
**NIC:** 
**AMI:** 
**Precondition mode:** strict

## Preconditions

| Check | Status |
|---|---|
| isolcpus | `pass=2-7` |
| nohz_full | `pass=2-7` |
| rcu_nocbs | `pass=2-7` |
| governor | `pass=no-cpufreq-subsystem` |
| cstate_max | `pass=C1` |
| tsc_invariant | `pass` |
| coalesce_off | `pass=skipped` |
| tso_off | `pass=skipped` |
| lro_off | `pass=skipped` |
| rss_on | `pass=skipped` |
| thermal_throttle | `pass=0` |
| hugepages_reserved | `pass=2048` |
| irqbalance_off | `pass` |
| wc_active | `pass=deferred` |

## bench-e2e

| test_case | feature_set | dimensions | metric | unit | agg | value | mode |
|---|---|---|---|---|---|---|---|
| request_response_rtt | trading-latency | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34260 | strict |
| request_response_rtt | trading-latency | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 41749 | strict |
| request_response_rtt | trading-latency | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 51710 | strict |
| request_response_rtt | trading-latency | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34766.4068 | strict |
| request_response_rtt | trading-latency | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 18251.9205 | strict |
| request_response_rtt | trading-latency | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34653.2802 | strict |
| request_response_rtt | trading-latency | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34879.5333 | strict |

## bench-obs-overhead

| test_case | feature_set | dimensions | metric | unit | agg | value | mode |
|---|---|---|---|---|---|---|---|
| request_response_rtt | obs-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34609 | strict |
| request_response_rtt | obs-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 42260 | strict |
| request_response_rtt | obs-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 47629 | strict |
| request_response_rtt | obs-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34938.4494 | strict |
| request_response_rtt | obs-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1916.0969 | strict |
| request_response_rtt | obs-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34926.5733 | strict |
| request_response_rtt | obs-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34950.3255 | strict |
| request_response_rtt | poll-saturation-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34360 | strict |
| request_response_rtt | poll-saturation-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 40870 | strict |
| request_response_rtt | poll-saturation-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 46840 | strict |
| request_response_rtt | poll-saturation-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34661.5173 | strict |
| request_response_rtt | poll-saturation-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1891.6963 | strict |
| request_response_rtt | poll-saturation-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34649.7925 | strict |
| request_response_rtt | poll-saturation-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34673.2422 | strict |
| request_response_rtt | byte-counters-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34600 | strict |
| request_response_rtt | byte-counters-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 42030 | strict |
| request_response_rtt | byte-counters-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 47480 | strict |
| request_response_rtt | byte-counters-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34940.1823 | strict |
| request_response_rtt | byte-counters-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1967.8593 | strict |
| request_response_rtt | byte-counters-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34927.9853 | strict |
| request_response_rtt | byte-counters-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34952.3792 | strict |
| request_response_rtt | obs-all-no-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34589 | strict |
| request_response_rtt | obs-all-no-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 41520 | strict |
| request_response_rtt | obs-all-no-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 46760 | strict |
| request_response_rtt | obs-all-no-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34892.4056 | strict |
| request_response_rtt | obs-all-no-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1935.9842 | strict |
| request_response_rtt | obs-all-no-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34880.4062 | strict |
| request_response_rtt | obs-all-no-none | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34904.4049 | strict |
| request_response_rtt | default | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34160 | strict |
| request_response_rtt | default | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 40830 | strict |
| request_response_rtt | default | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 45980 | strict |
| request_response_rtt | default | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34485.9199 | strict |
| request_response_rtt | default | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1881.8651 | strict |
| request_response_rtt | default | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34474.2559 | strict |
| request_response_rtt | default | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34497.5838 | strict |
| request_response_rtt | obs-none-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34320 | strict |
| request_response_rtt | obs-none-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 40789 | strict |
| request_response_rtt | obs-none-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 46460 | strict |
| request_response_rtt | obs-none-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34609.7494 | strict |
| request_response_rtt | obs-none-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1875.3487 | strict |
| request_response_rtt | obs-none-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34598.1258 | strict |
| request_response_rtt | obs-none-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34621.3729 | strict |
| request_response_rtt | obs-none-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34429 | strict |
| request_response_rtt | obs-none-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 41169 | strict |
| request_response_rtt | obs-none-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 46920 | strict |
| request_response_rtt | obs-none-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34721.5169 | strict |
| request_response_rtt | obs-none-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1923.3419 | strict |
| request_response_rtt | obs-none-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34709.5959 | strict |
| request_response_rtt | obs-none-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34733.4379 | strict |

## bench-offload-ab

| test_case | feature_set | dimensions | metric | unit | agg | value | mode |
|---|---|---|---|---|---|---|---|
| request_response_rtt | baseline | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34449 | strict |
| request_response_rtt | baseline | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 41189 | strict |
| request_response_rtt | baseline | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 47640 | strict |
| request_response_rtt | baseline | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34747.6727 | strict |
| request_response_rtt | baseline | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1973.6230 | strict |
| request_response_rtt | baseline | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34735.4401 | strict |
| request_response_rtt | baseline | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34759.9054 | strict |
| request_response_rtt | tx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34590 | strict |
| request_response_rtt | tx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 42709 | strict |
| request_response_rtt | tx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 47260 | strict |
| request_response_rtt | tx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34958.3659 | strict |
| request_response_rtt | tx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 2046.7253 | strict |
| request_response_rtt | tx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34945.6802 | strict |
| request_response_rtt | tx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34971.0516 | strict |
| request_response_rtt | rx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 35220 | strict |
| request_response_rtt | rx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 43969 | strict |
| request_response_rtt | rx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 49790 | strict |
| request_response_rtt | rx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 35760.6404 | strict |
| request_response_rtt | rx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 2682.0552 | strict |
| request_response_rtt | rx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 35744.0168 | strict |
| request_response_rtt | rx-cksum-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 35777.2639 | strict |
| request_response_rtt | mbuf-fast-free-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34380 | strict |
| request_response_rtt | mbuf-fast-free-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 40740 | strict |
| request_response_rtt | mbuf-fast-free-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 46669 | strict |
| request_response_rtt | mbuf-fast-free-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34685.9717 | strict |
| request_response_rtt | mbuf-fast-free-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1903.0800 | strict |
| request_response_rtt | mbuf-fast-free-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34674.1763 | strict |
| request_response_rtt | mbuf-fast-free-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34697.7671 | strict |
| request_response_rtt | rss-hash-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34630 | strict |
| request_response_rtt | rss-hash-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 42110 | strict |
| request_response_rtt | rss-hash-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 47049 | strict |
| request_response_rtt | rss-hash-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34972.3913 | strict |
| request_response_rtt | rss-hash-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1903.8100 | strict |
| request_response_rtt | rss-hash-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34960.5914 | strict |
| request_response_rtt | rss-hash-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34984.1913 | strict |
| request_response_rtt | rx-timestamp-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34780 | strict |
| request_response_rtt | rx-timestamp-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 43480 | strict |
| request_response_rtt | rx-timestamp-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 48129 | strict |
| request_response_rtt | rx-timestamp-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 35186.8276 | strict |
| request_response_rtt | rx-timestamp-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 2190.9613 | strict |
| request_response_rtt | rx-timestamp-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 35173.2479 | strict |
| request_response_rtt | rx-timestamp-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 35200.4074 | strict |
| request_response_rtt | llq-verify-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34600 | strict |
| request_response_rtt | llq-verify-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 42130 | strict |
| request_response_rtt | llq-verify-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 46849 | strict |
| request_response_rtt | llq-verify-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34927.2078 | strict |
| request_response_rtt | llq-verify-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1900.7393 | strict |
| request_response_rtt | llq-verify-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34915.4269 | strict |
| request_response_rtt | llq-verify-only | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34938.9887 | strict |
| request_response_rtt | full | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34260 | strict |
| request_response_rtt | full | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 40170 | strict |
| request_response_rtt | full | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 45970 | strict |
| request_response_rtt | full | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34537.3531 | strict |
| request_response_rtt | full | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1831.4370 | strict |
| request_response_rtt | full | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34526.0017 | strict |
| request_response_rtt | full | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34548.7045 | strict |
| request_response_rtt | baseline-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34229 | strict |
| request_response_rtt | baseline-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 40540 | strict |
| request_response_rtt | baseline-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 46130 | strict |
| request_response_rtt | baseline-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34536.6040 | strict |
| request_response_rtt | baseline-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1859.9177 | strict |
| request_response_rtt | baseline-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34525.0761 | strict |
| request_response_rtt | baseline-noise-1 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34548.1319 | strict |
| request_response_rtt | baseline-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p50 | 34420 | strict |
| request_response_rtt | baseline-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p99 | 40629 | strict |
| request_response_rtt | baseline-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | p999 | 46680 | strict |
| request_response_rtt | baseline-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | mean | 34705.5756 | strict |
| request_response_rtt | baseline-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | stddev | 1874.1984 | strict |
| request_response_rtt | baseline-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_lower | 34693.9592 | strict |
| request_response_rtt | baseline-noise-2 | `{"request_bytes":128,"response_bytes":128}` | rtt_ns | ns | ci95_upper | 34717.1920 | strict |

## bench-stress

| test_case | feature_set | dimensions | metric | unit | agg | value | mode |
|---|---|---|---|---|---|---|---|
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | p50 | 37729 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | p99 | 46280 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | p999 | 51289 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | mean | 38023.3290 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | stddev | 2523.9413 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | ci95_lower | 38007.6855 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | ci95_upper | 38038.9726 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | p50 | 10052369 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | p99 | 10096300 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | p999 | 10112389 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | mean | 10246140.1787 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | stddev | 6384894.3229 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | ci95_lower | 10206566.1937 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | ci95_upper | 10285714.1637 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | p50 | 10052369 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | p99 | 10096300 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | p999 | 10112389 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | mean | 10246140.1787 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | stddev | 6384894.3229 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | ci95_lower | 10206566.1937 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"loss 0.1% delay 10ms","scenario":"random_loss_01pct_10ms"}` | rtt_ns | ns | ci95_upper | 10285714.1637 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | p50 | 37729 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | p99 | 46280 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | p999 | 51289 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | mean | 38023.3290 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | stddev | 2523.9413 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | ci95_lower | 38007.6855 | strict |
| stress_rtt | trading-latency | `{"fault_injector_config":"","netem_config":"duplicate 100%","scenario":"duplication_2x"}` | rtt_ns | ns | ci95_upper | 38038.9726 | strict |

## bench-vs-linux

| test_case | feature_set | dimensions | metric | unit | agg | value | mode |
|---|---|---|---|---|---|---|---|
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"dpdk_net"}` | rtt_ns | ns | p50 | 35600 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"dpdk_net"}` | rtt_ns | ns | p99 | 44140 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"dpdk_net"}` | rtt_ns | ns | p999 | 51940 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"dpdk_net"}` | rtt_ns | ns | mean | 36122.4886 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"dpdk_net"}` | rtt_ns | ns | stddev | 2662.9182 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"dpdk_net"}` | rtt_ns | ns | ci95_lower | 36105.9837 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"dpdk_net"}` | rtt_ns | ns | ci95_upper | 36138.9935 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"linux_kernel"}` | rtt_ns | ns | p50 | 37172 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"linux_kernel"}` | rtt_ns | ns | p99 | 45531 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"linux_kernel"}` | rtt_ns | ns | p999 | 52232 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"linux_kernel"}` | rtt_ns | ns | mean | 37519.9524 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"linux_kernel"}` | rtt_ns | ns | stddev | 2094.1798 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"linux_kernel"}` | rtt_ns | ns | ci95_lower | 37506.9725 | strict |
| rtt_comparison | trading-latency | `{"mode":"rtt","preset":"latency","stack":"linux_kernel"}` | rtt_ns | ns | ci95_upper | 37532.9322 | strict |

## bench-vs-mtcp

| test_case | feature_set | dimensions | metric | unit | agg | value | mode |
|---|---|---|---|---|---|---|---|
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.739e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 1.058e10 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 1.065e10 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 4.371e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 1.502e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 4.342e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 4.401e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 30491 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 32571 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 37360 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 30520.3072 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 1472.2629 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 30491.4508 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 30549.1636 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 4.777e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 2.770e10 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 2.790e10 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 6.335e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 4.110e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 6.255e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 6.416e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 4.204e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 4.323e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 4.352e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 4.166e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 120831244.3295 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 4.163e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 4.168e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 30851 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 39171 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 40111 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 31627.7874 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 2276.8079 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 31583.1620 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 31672.4128 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 5.605e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 5.800e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 5.846e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 5.563e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 180725684.8292 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 5.560e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 5.567e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.927e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 4.064e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 4.103e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.894e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 117964533.2382 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.892e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.896e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 31029 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 40449 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 43520 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 31671.6874 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 2050.0414 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 31631.5066 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 31711.8682 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 5.132e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 5.351e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 5.418e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 5.092e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 175433875.3238 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 5.088e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 5.095e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.126e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.263e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.292e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.103e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 99849437.3190 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.101e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.105e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 37580 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 47300 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 50420 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 37962.9447 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 1793.1373 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 37927.7992 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 37998.0902 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 4.037e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 4.235e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 4.277e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 4.003e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 149806553.0808 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 4.000e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":65536,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 4.006e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.422e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 4.273e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 4.829e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.441e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 368788661.5061 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.434e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.449e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 32629 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 151900 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 204040 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 40182.5142 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 32094.0897 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 39553.4700 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 40811.5584 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.581e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 5.202e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 6.042e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.703e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 498485625.1955 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.694e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.713e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.694e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 4.250e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 4.806e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.629e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 239298370.2140 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.625e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.634e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 34340 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 153940 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 175740 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 49287.7879 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 34080.3415 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 48619.8132 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 49955.7626 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.944e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 5.069e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 5.489e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.976e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 334194378.6639 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.970e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.983e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.623e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 4.518e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 4.787e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.546e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 319592636.0201 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.540e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.552e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 35731 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 186049 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 525600 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 53080.1215 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 47993.1186 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 52139.4564 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 54020.7866 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.888e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 5.179e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 6.142e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.905e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 434152554.1641 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.897e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.914e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.012e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.474e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.767e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.003e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 174083303.4899 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 2.999e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.006e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 37800 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 158031 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 223700 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 48507.2136 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 35813.1927 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 47805.2750 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 49209.1522 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.241e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.930e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 4.501e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.235e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 256512106.7665 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.230e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":262144,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.240e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.662e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.962e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 4.106e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.670e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 105868725.9902 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.668e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.672e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 31009 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 158280 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 229080 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 36676.4744 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 30751.7199 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 36073.7407 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 37279.2081 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.725e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 4.056e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 4.201e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.731e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 119465923.3409 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.728e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.733e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.604e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.812e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.915e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.597e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 86469545.5061 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.595e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.599e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 31660 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 150771 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 187940 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 38830.9055 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 30887.4869 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 38225.5108 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 39436.3002 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.658e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.906e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 4.019e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.659e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 98465761.4613 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.657e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.661e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.596e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.875e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 4.011e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.546e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 206002204.3257 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.542e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.550e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 32191 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 410340 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 470140 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 45605.6763 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 61506.7453 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 44400.1441 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 46811.2085 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.657e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.967e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 4.113e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.614e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 203147993.8047 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.610e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.618e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.436e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.708e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.823e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.387e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 183314334.4166 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.384e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.391e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 35731 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 418969 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 482220 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 46189.0617 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 53526.5061 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 45139.9422 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 47238.1812 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.488e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.792e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.921e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.451e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 186467113.4739 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.448e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":1048576,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.455e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.622e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.688e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.714e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.623e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 25345666.0008 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.622e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.623e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 28280 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 74551 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 109251 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 29346.3762 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 17139.0983 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 29010.4499 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 29682.3025 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.633e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.706e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.732e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.634e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 28790036.1350 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.634e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.635e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.597e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.661e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.684e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.597e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 26340459.1600 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.597e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.598e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 28891 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 71309 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 114089 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 29681.7472 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 16412.3354 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 29360.0654 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 30003.4290 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.608e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.679e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.703e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.609e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 29379786.4942 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.608e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.609e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.588e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.662e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.682e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.578e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 49436118.0181 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.577e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.579e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 29109 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 72491 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 118400 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 29970.3358 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 17486.2074 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 29627.6061 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 30313.0655 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.598e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.678e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.698e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.589e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 50004688.4088 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.588e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.590e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.530e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.600e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.625e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.521e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 47310245.4599 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.520e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.522e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 31689 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 79320 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 124840 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 32994.2057 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 18297.0611 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 32635.5833 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 33352.8281 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.542e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.619e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.643e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.534e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 47754638.0547 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.533e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":4194304,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.534e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.604e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.632e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.640e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.605e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 11281417.1577 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.605e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.606e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 28320 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 69991 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 88951 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 29114.5660 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 16356.4936 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 28793.9787 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 29435.1533 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.607e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.636e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.645e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.608e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 11726909.0268 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.608e9 | strict |
| burst | trading-latency | `{"G_ms":0.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.608e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.594e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.616e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.631e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.593e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 12020167.1556 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.592e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.593e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 28740 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 71651 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 84071 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 29712.1323 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 16394.6832 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 29390.7965 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 30033.4681 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.597e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.620e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.633e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.596e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 12473359.5867 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.595e9 | strict |
| burst | trading-latency | `{"G_ms":1.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.596e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.591e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.616e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.625e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.587e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 16757125.6004 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.587e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.587e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 28860 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 72111 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 85640 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 29701.6616 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 16498.6599 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 29378.2879 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 30025.0353 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.593e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.619e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.630e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.590e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 16764485.2602 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.590e9 | strict |
| burst | trading-latency | `{"G_ms":10.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.590e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p50 | 3.581e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p99 | 3.607e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | p999 | 3.615e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | mean | 3.577e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | stddev | 17091149.2291 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_lower | 3.577e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | throughput_per_burst_bps | bits_per_sec | ci95_upper | 3.578e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p50 | 31800 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p99 | 77500 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | p999 | 96900 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | mean | 32846.7778 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | stddev | 17651.2128 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_lower | 32500.8140 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_initiation_ns | ns | ci95_upper | 33192.7416 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p50 | 3.584e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p99 | 3.610e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | p999 | 3.619e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | mean | 3.581e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | stddev | 17097695.6822 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_lower | 3.580e9 | strict |
| burst | trading-latency | `{"G_ms":100.0,"K_bytes":16777216,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"burst"}` | burst_steady_bps | bits_per_sec | ci95_upper | 3.581e9 | strict |
| maxtp | trading-latency | `{"C":1,"W_bytes":64,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"maxtp"}` | sustained_goodput_bps | bits_per_sec | mean | 455363522.0885 | strict |
| maxtp | trading-latency | `{"C":1,"W_bytes":64,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"maxtp"}` | tx_pps | pps | mean | 944771.1955 | strict |
| maxtp | trading-latency | `{"C":4,"W_bytes":64,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"maxtp"}` | sustained_goodput_bps | bits_per_sec | mean | 513325070.7026 | strict |
| maxtp | trading-latency | `{"C":4,"W_bytes":64,"stack":"dpdk_net","tx_ts_mode":"tsc_fallback","workload":"maxtp"}` | tx_pps | pps | mean | 1181364.2993 | strict |

