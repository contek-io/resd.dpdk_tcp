# Phase A10 — Benchmark harness (micro + e2e + stress + comparators) (Design Spec)

**Status:** Design approved (brainstorm 2026-04-21). Implementation plan to land at `docs/superpowers/plans/2026-04-21-stage1-phase-a10-benchmark-harness.md`.
**Parent spec (Stage 1 design):** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` — §11 entire (incl. §11.5.1 + §11.5.2).
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` § A10 (L609–638).
**Branch / worktree:** `phase-a10` in `/home/ubuntu/resd.dpdk_tcp-a10`, branched from master tip `1cf754a` (`Merge branch 'master' of …` — fast-forward merge of A9 + gateway-ARP PR #3 on top of `4b55a48 Merge phase-a9 into master`).
**End-of-phase tag:** `phase-a10-complete`. Stays local; user merges to master manually (likely together with or after the parallel `phase-a7` merge).
**Sister repo:** `resd.aws-infra-setup` — new Python CDK project. Delivers the IaC + EC2 Image Builder pipeline that A10 consumes for bench-fleet provisioning. Ships `v0.1.0` alongside A10's phase-complete tag.

---

## 0. Purpose of this spec

A10 lands the §11 benchmark plan of the Stage 1 design: microbenchmarks with order-of-magnitude targets, end-to-end RTT with HW-timestamp / TSC-fallback attribution, stability benchmarks under induced stress, comparative latency vs Linux TCP, and comparative throughput vs mTCP on the burst-edge / long-connection workload. A10 further delivers two A/B harnesses — `bench-offload-ab` and `bench-obs-overhead` — that operationalise `feedback_counter_policy` by measurement rather than by review: any counter / event-log field claimed slow-path that moves hot-path numbers is re-evaluated (batched, removed, feature-gated, moved off hot path) before A11.

A10 also subsumes A-HW's deferred Task 18 (128 B request-response wire cycle on real ENA; deferred by commit `abea362` because A-HW's container had no routable peer on the ENA VF's subnet). A10 runs on a dedicated EC2 pair provisioned by `resd.aws-infra-setup`, so the Task 18 matrix naturally closes inside `bench-e2e`.

The phase produces 9 tool crates under `tools/`, 3 committed benchmark-report artifacts, one new cargo feature (`obs-none`), and a sister IaC project that provisions and bakes the AMI. **No production wire-behavior changes; trading-latency defaults are preserved.** `preset=rfc_compliance` (landed in A6 Task 9) is consumed by exactly one sub-mode of one tool (`bench-vs-linux` wire-level diff) and stays opt-in everywhere else.

---

## 1. Brainstorm decisions

The 2026-04-21 brainstorm closed eight decisions.

### D1 — Preset usage per tool

`preset=rfc_compliance` (`DPDK_NET_PRESET_RFC_COMPLIANCE = 1`; `apply_preset()` in `crates/dpdk-net/src/lib.rs:30`) already exists. A10 consumes it unchanged for exactly one sub-mode of one tool. Every other tool runs with the trading-latency default (`DPDK_NET_PRESET_LATENCY = 0`).

| Tool | Preset | Rationale |
|---|---|---|
| `bench-micro` | trading-latency (default) | Measures production hot-path shape. RFC preset would exercise Reno+delayed-ACK+Nagle-on paths that aren't the operational target. |
| `bench-e2e` | trading-latency (default) | Measures trading RTT distribution + A-HW Task 18 wire cycle. Production shape. |
| `bench-stress` | trading-latency (default) | Our question is "does trading-mode fast-fail usefully under induced loss/reorder/corrupt", not "does RFC recovery meet compliance". |
| `bench-vs-linux` | **dual-mode**: (a) trading-latency for RTT comparison, (b) `preset=rfc_compliance` ONLY for the wire-level byte-identical diff sub-mode per parent §11.5 | Two questions, two presets. CSV dimension `preset` tags each row; bench-report never averages across presets. |
| `bench-offload-ab` | trading-latency (default) | Hot-path offload cost measured in production shape. |
| `bench-obs-overhead` | trading-latency (default) | Hot-path observability cost measured in production shape. |
| `bench-vs-mtcp` | `cc_mode=off` explicitly (equals trading-latency default) | Per parent §11.5.1 "cc_mode=off on both stacks; comparison axis is the fast-path stack, not congestion control". |

### D2 — Measurement-discipline gate: hybrid (fail-fast default + `--lenient`)

Parent §11.1 demands precondition enforcement AND "rejected at analysis time". A10 honours both: harness is fail-fast by default (CI + nightly); `--lenient` downgrades misses to CSV-column warnings (dev). Precondition columns are present in every row regardless of mode, so bench-report filtering at analysis time works for both.

### D3 — Fresh-engine-per-A/B-config: rebuild-per-feature-set + sub-process-per-run

Rust feature flags are compile-time; DPDK `rte_eal_cleanup → rte_eal_init` is brittle on 23.11. A10 sidesteps both: a Rust coordinator binary (`bench-ab-driver`) performs, per feature-set F in the matrix:

1. `cargo build --no-default-features --features F -p bench-ab-runner --release`
2. Spawn the freshly-built runner; capture CSV stdout.
3. Runner does exactly: precondition check → EAL init → `Engine::new` → warmup (drop first 1000 RT) → measurement window (workload-specific) → CSV emit → `Engine::drop` → `rte_eal_cleanup` → exit 0.
4. Driver concatenates per-config CSVs with `feature_set` as a column.

One EAL init per process lifetime. One shared runner binary (`tools/bench-ab-runner/`) is consumed by two driver entrypoints (`tools/bench-offload-ab/`, `tools/bench-obs-overhead/`) differing only by the feature-matrix passed to the driver.

### D4 — `obs-none` umbrella feature — four gates

`obs-none` is a new additive marker feature. Default builds (without `obs-none`) are unchanged; only `bench-obs-overhead` enables it to measure the "zero observability" floor. Four gate sites:

| # | Site | File (current ref) | Reason |
|---|---|---|---|
| G1 | `EventQueue::push` call sites (every state-transition emission) | `crates/dpdk-net-core/src/tcp_events.rs:151` + all call sites | Ring-buffer write + conditional overflow accounting per event |
| G2 | `emitted_ts_ns = clock::now_ns()` capture preceding every push | same call sites | TSC read + 64-bit store per event |
| G3 | Per-conn `rtt_histogram.update(rtt_us, edges)` on every ACK with a valid RTT sample | `crates/dpdk-net-core/src/tcp_conn.rs:553` | Bucket lookup + increment per ACK |
| G4 | `dpdk_net_conn_stats` FFI getter | `crates/dpdk-net/src/api.rs` (getter dispatch) | Returns `ENOTSUP`/null when `obs-none` is set. Slow-path so this primarily symmetry — measures the "zero observability" baseline cleanly. |

Any hot-path always-on emission site discovered by `bench-obs-overhead` that is NOT in this scope is a policy-violation-by-measurement (per `feedback_counter_policy`) and gets remediated inside A10 (gate it, batch it, or remove it) before A11.

### D5 — CSV schema: long-format + dimensions_json + common prefix; summarized-only; JSON+HTML+Markdown outputs

One unified row schema across all 8 tools. Common-prefix columns carry run metadata + §11.1 preconditions. Per-row `(tool, test_case, feature_set, dimensions_json, metric_name, metric_unit, metric_value, metric_aggregation)` tuple. `metric_aggregation ∈ {p50, p99, p999, mean, stddev, ci95_lower, ci95_upper}` — summarized-only. Raw samples (criterion's JSON, per-sample histogram dumps) stay in per-tool sidecar files that bench-report does NOT ingest. `bench-report` emits **JSON** (archive / programmatic), **HTML** (browser-openable dashboard), **Markdown** (committed-to-repo summaries). No Prometheus.

Full column list in §14.

### D6 — IaC separate repo `resd.aws-infra-setup` (Python CDK)

The IaC is its own repo, reusable for future `resd.*` projects. Python CDK (user preference for flexibility). A10 registers one preset (`bench-pair`); additional presets land as future consumers arrive. Defaults: `c6a.2xlarge`, new /24 subnet, cluster placement group. All inputs configurable via `--config <json>` or flags. CI wiring deferred — A10 delivers the script that shells out to the CLI; user wires CI later.

### D7 — Single AMI, production = benchmark

EC2 Image Builder pipeline (CDK-defined in the same IaC repo) bakes a single AMI used for both `resd.dpdk_tcp` production and A10 bench. Trade dormant mTCP footprint (~200 MB in `/opt/mtcp/`) for AMI-singleton + zero prod-vs-bench drift.

Base: **Ubuntu 24.04 LTS + HWE kernel 6.17** (supports AMD Zen5 / `c8a`). Toolchain: **clang-22 + libc++** from llvm.org (per `feedback_build_toolchain`, updated 2026-04-21). No-IOMMU mode (virtualized EC2 default); WC-patched vfio-pci baked in. Full component list in §16.

### D8 — mTCP baked into AMI

mTCP built from `third_party/mtcp/` submodule as an Image Builder component during AMI bake. Artifacts installed to `/opt/mtcp/`. Peer-side pre-built binary `/opt/mtcp-peer/bench-peer` in the AMI; no bench-time build. Patches (if any) live under the IaC repo's `image-components/install-mtcp/patches/`; if patches exceed ~50 lines total, escalation to drop `bench-vs-mtcp` from A10 scope.

---

## 2. Scope

### 2.1 In scope

**`resd.dpdk_tcp` phase-a10:**
- 9 tool crates under `tools/` (see §3.1)
- `crates/dpdk-net-core/Cargo.toml` adds `obs-none` feature + gate sites
- `scripts/check-bench-preconditions.sh` (dev-side precondition checker; AMI-side identical copy at `/usr/local/bin/check-bench-preconditions`)
- `scripts/bench-nightly.sh` — shells out to `resd-aws-infra` CLI, runs the bench set, pulls artefacts, invokes `bench-report`
- 3 committed report artefacts: `docs/superpowers/reports/offload-ab.md`, `obs-overhead.md`, `bench-baseline.md`
- Roadmap row update for A10 (completion summary + any scope adjustments discovered during execution)
- End-of-phase mTCP + RFC compliance review reports (parallel, opus 4.7)

**`resd.aws-infra-setup` (new repo):**
- Python CDK app with `bench-pair` preset
- EC2 Image Builder pipeline baking `resd-host-ubuntu-24.04-k6.17-<ver>` AMI
- CLI wrapper (`resd-aws-infra {setup|teardown|status}`)
- README covering presets, deploy/teardown, cost notes, troubleshooting
- One successful bake run — AMI ID committed as CDK parameter default
- First `bench-pair` stack bring-up validated via `resd.dpdk_tcp`'s `scripts/bench-nightly.sh`

### 2.2 Out of scope

- CI wiring (user builds later using `scripts/bench-nightly.sh`)
- WAN A/B harness — parent spec §10.7 Layer G (→ S2-A)
- arm64 AMI variant (c7gn/c8gn) — deferred per `project_arm_roadmap`
- Shadow-mode prod deployment — parent spec §10.9 (→ S2-B+)
- New unconditional hot-path counters — `bench-obs-overhead` SURFACES existing costs; A10 doesn't add counters (per `feedback_counter_policy`)
- Production wire-behaviour changes — `preset=rfc_compliance` stays opt-in
- tcpreq (A8), packetdrill (A7), HTTP/TLS/WS (Stage 3+)
- Full PTP / wall-clock discipline — TSC invariance suffices for A10

---

## 3. Architecture

### 3.1 Tool crates under `tools/`

```
tools/
├── bench-common/          NEW lib-crate  — CSV schema types, precondition-check bindings,
│                                           percentile + bootstrap-CI computation, ENV plumbing
├── bench-ab-runner/       NEW bin-crate  — shared runner for both A/B harnesses
│                                           (precondition check → EAL init → Engine → workload → CSV → cleanup → exit)
├── bench-micro/           NEW            — cargo-criterion harness, 12 targets
├── bench-e2e/             NEW bin-crate  — request/response RTT + HW-TS/TSC-fallback attribution
│                                           + sum-identity assertion; subsumes A-HW Task 18
├── bench-stress/          NEW bin-crate  — §11.4 matrix driver (netem + FaultInjector)
├── bench-vs-linux/        NEW bin-crate  — dual-preset runs; paired Linux peer
├── bench-offload-ab/      NEW bin-crate  — feature-matrix driver over `hw-*` flags
├── bench-obs-overhead/    NEW bin-crate  — feature-matrix driver over `obs-*` flags (incl. obs-none)
├── bench-vs-mtcp/         NEW bin-crate  — burst (K×G=20) + maxtp (W×C=28) grids
└── bench-report/          NEW bin-crate  — CSV → JSON + HTML + Markdown
```

All new crates are workspace members in the top-level `Cargo.toml`. None ship in the public C ABI; all are build-tools.

Existing crates touched:

```
crates/dpdk-net-core/
├── Cargo.toml             + `obs-none` feature (additive marker)
├── src/tcp_events.rs      + #[cfg(not(feature = "obs-none"))] guards at push call sites  (G1)
├── src/clock.rs           (G2 is call-site-local; applied at each push site where now_ns() is called for emitted_ts_ns)
├── src/tcp_conn.rs        + #[cfg(not(feature = "obs-none"))] guard at rtt_histogram.update() call  (G3)
└── ( G4 handled in crates/dpdk-net/src/api.rs at the ConnStats FFI getter )
crates/dpdk-net/
└── src/api.rs             + #[cfg(not(feature = "obs-none"))] guard at dpdk_net_conn_stats entry (G4)
```

### 3.2 IaC / AMI (sister repo `resd.aws-infra-setup`)

```
resd.aws-infra-setup/            NEW repo (contek-io/resd.aws-infra-setup)
├── README.md
├── pyproject.toml               python >=3.11; dependencies: aws-cdk-lib, constructs, click (CLI)
├── cdk.json                     CDK app entrypoint
├── app.py                       CDK app wiring
├── lib/
│   ├── presets/
│   │   └── bench_pair.py        DUT + peer + VPC + SG + IAM + outputs
│   └── image_builder/
│       └── bench_host_image.py  Image Builder pipeline + recipe + components
├── image-components/
│   ├── 01-install-llvm-toolchain.yaml   clang-22 + libc++ from llvm.org
│   ├── 02-install-dpdk-23-11.yaml       DPDK from source, CC=clang-22
│   ├── 03-install-wc-vfio-pci.yaml      amzn-drivers/enav2-vfio-patch
│   ├── 04-install-mtcp.yaml             third_party/mtcp submodule build
│   ├── 05-configure-grub.yaml           hugepages, isolcpus, nohz_full, rcu_nocbs, processor.max_cstate=1, transparent_hugepage=never
│   ├── 06-modprobe-config.yaml          vfio.enable_unsafe_noiommu_mode=1
│   ├── 07-systemd-units.yaml            governor=performance, irqbalance off, hugepages boot-verify
│   ├── 08-install-bench-tools.yaml      linux-tools-6.17, ethtool, pciutils, numactl, iproute2
│   └── 09-install-preconditions-checker.yaml  /usr/local/bin/check-bench-preconditions
├── cli/
│   └── resd_aws_infra/          click-based CLI entrypoint (`resd-aws-infra {setup|teardown|status}`)
└── tests/                       pytest; unit tests on preset builders
```

### 3.3 Engine integration points

No changes to the Rust engine's runtime behaviour. Additions are compile-time feature gates only:

- `obs-none` feature: additive `#[cfg(not(feature = "obs-none"))]` guards at G1–G4. Default builds retain current behaviour exactly.

All other benchmarking is done through the **existing** public API (`dpdk_net_engine_create`, `dpdk_net_connect`, `dpdk_net_poll`, `dpdk_net_send`, `dpdk_net_counters`, `dpdk_net_conn_stats`) and the existing test fixtures (`crates/dpdk-net-core/src/test_fixtures.rs`). `bench-e2e` drives the production FFI surface end-to-end; no internal APIs are exposed solely for benchmarks.

---

## 4. Measurement discipline

### 4.1 §11.1 preconditions enforced

The precondition check script runs at the top of every bench invocation. Each check emits pass/fail + observed value into the CSV row as a dedicated column. In **strict** mode (default), any fail exits the harness non-zero before starting measurement. In **lenient** mode (`--lenient`), misses are recorded as CSV warnings and the harness proceeds.

| Precondition | Command / probe | CSV column |
|---|---|---|
| `isolcpus` covers the engine lcore(s) | `cat /sys/devices/system/cpu/isolated` | `precondition_isolcpus` |
| `nohz_full` covers the engine lcore(s) | `cat /sys/devices/system/cpu/nohz_full` | `precondition_nohz_full` |
| `rcu_nocbs` covers the engine lcore(s) | `cat /proc/cmdline` pattern | `precondition_rcu_nocbs` |
| Governor = `performance` | `cpupower frequency-info` | `precondition_governor` |
| C-states disabled below C1 | `/sys/devices/system/cpu/cpu<N>/cpuidle/state*/disable` | `precondition_cstate_max` |
| TSC invariant | `grep -q constant_tsc && grep -q nonstop_tsc /proc/cpuinfo` | `precondition_tsc_invariant` |
| NIC interrupt coalescing off | `ethtool -c <iface>` | `precondition_coalesce_off` |
| NIC TSO / LRO off | `ethtool -k <iface>` | `precondition_tso_off`, `precondition_lro_off` |
| NIC RSS on | `ethtool -x <iface>` | `precondition_rss_on` |
| No thermal throttle during the run | `turbostat --quiet -i 1` background-monitored; harness polls at end | `precondition_thermal_throttle` (0 = no throttle) |
| Hugepages reserved | `grep HugePages /proc/meminfo` | `precondition_hugepages_reserved` |
| `irqbalance` stopped | `systemctl is-active irqbalance` | `precondition_irqbalance_off` |
| Write-Combining on ENA BAR (when app running) | `grep write-combining /sys/kernel/debug/x86/pat_memtype_list` | `precondition_wc_active` |

The Write-Combining probe requires the engine to be running; for precondition-check-only invocations (CI smoke of the checker), it runs a short-lived DPDK probe process that binds and immediately exits. For real bench invocations, the probe runs between engine bring-up and workload start.

**bench-micro exception:** `bench-micro` runs in-process microbenchmarks with no DPDK engine bring-up. The `precondition_wc_active` check is skipped for bench-micro rows (CSV column marked `n/a`); all other preconditions apply.

### 4.2 Validator script

`scripts/check-bench-preconditions.sh` emits one JSON object per invocation:

```json
{
  "mode": "strict|lenient",
  "checks": {
    "isolcpus": {"pass": true, "value": "2-7"},
    "nohz_full": {"pass": true, "value": "2-7"},
    "governor": {"pass": true, "value": "performance"},
    ...
  },
  "overall_pass": true
}
```

In strict mode, `overall_pass == false` → exit 1 (harness aborts). In lenient mode, `overall_pass == false` → exit 0 but every fail becomes a CSV warning column on subsequent rows. The AMI has an identical copy at `/usr/local/bin/check-bench-preconditions`; both trees ship the same code path.

### 4.3 CSV precondition columns

For every row, the same 13 precondition-value columns are populated. `precondition_mode ∈ {strict, lenient}` distinguishes the enforcement regime. bench-report's HTML dashboard colour-codes any row with a failed precondition.

---

## 5. Tool 1 — `bench-micro`

Pure in-process microbenchmarks via **cargo-criterion** (existing template: `tools/bench-rx-zero-copy/`, criterion 0.5 + html_reports).

Twelve targets, mapping parent §11.2:

| # | Criterion target | Measures | Expected order-of-magnitude |
|---|---|---|---|
| 1 | `bench_poll_empty` | `dpdk_net_poll` iteration with no RX, no timers | tens of ns |
| 2 | `bench_poll_idle_with_timers` | `dpdk_net_poll` with `tcp_tick` walking an empty wheel bucket | tens of ns |
| 3 | `bench_tsc_read_ffi` | `dpdk_net_now_ns` via FFI | ~5 ns |
| 4 | `bench_tsc_read_inline` | `dpdk_net_now_ns_inline` (header-inline) | ~1 ns |
| 5 | `bench_flow_lookup_hot` | 4-tuple hash lookup, hot cache | ~40 ns |
| 6 | `bench_flow_lookup_cold` | 4-tuple hash lookup, cacheline flushed | ~200 ns |
| 7 | `bench_tcp_input_data_segment` | `tcp_input` for a single in-order data segment, PAWS+SACK enabled | ~100–200 ns |
| 8 | `bench_tcp_input_ooo_segment` | `tcp_input` for an OoO segment that fills a hole | ~200–400 ns |
| 9 | `bench_send_small` | `dpdk_net_send` of 128 bytes (fits single mbuf) | ~150 ns |
| 10 | `bench_send_large_chain` | `dpdk_net_send` of 64 KiB (mbuf chain) | ~1–5 µs |
| 11 | `bench_timer_add_cancel` | `dpdk_net_timer_add` → `dpdk_net_timer_cancel` | ~50 ns |
| 12 | `bench_counters_read` | `dpdk_net_counters` + read of all counter groups | ~100 ns |

**Output:** criterion's native JSON in `target/criterion/` (sidecar, not ingested) + a summarized CSV under `target/bench-results/bench-micro/<run_id>.csv` with `(metric_name, metric_aggregation) ∈ {(ns_per_iter, p50), (ns_per_iter, p99), (ns_per_iter, p999), (ns_per_iter, mean), (ns_per_iter, ci95_lower), (ns_per_iter, ci95_upper)}` per target.

**Preset:** trading-latency default.
**CI:** per-commit (5% regression gate on any target's median). Nightly full matrix with bootstrap CIs.

**Baseline recorded in `docs/superpowers/reports/bench-baseline.md`** — p50/p99/p999 per target at phase-a10 merge; this becomes the regression-gate baseline the A11 ship-gate verifies against.

---

## 6. Tool 2 — `bench-e2e` (subsumes A-HW Task 18)

Request/response RTT harness on the dedicated EC2 bench pair.

**Workload:** single connection (established once), single outstanding request: `send(N) → recv(N)`. N ∈ {128 B, 1 KiB, 4 KiB, 16 KiB}; 128 B is the A-HW Task 18 trading-representative size.

**Attribution buckets** (per parent §11.3):
- When HW TX timestamp available AND `rx_hw_ts_ns != 0` (full HW-TS mode): 4 buckets — `tx_sched → nic_tx_wire`, `nic_tx → wire_peer`, `wire_peer → nic_rx`, `nic_rx → enqueued` + 2 software buckets (`user_send → tx_sched`, `enqueued → user_return`).
- When `rx_hw_ts_ns == 0` (**ENA production case** per parent §8.3, §10.5): 3 buckets — `tx_sched → enqueued` (wire + full RX collapsed), `enqueued → user_return`, `user_send → tx_sched`.

**Sum-identity assertion per-measurement:** sum of attribution buckets == end-to-end wall-clock RTT within ±50 ns tolerance. Any mismatch invalidates the measurement (marks row `precondition_sum_identity = fail`; in strict mode, aborts run).

**A-HW Task 18 closure — explicit assertions:**
- Every `offload_missing_*` counter value (per parent §8.2):
  - `offload_missing_mbuf_fast_free == 1` (MBUF_FAST_FREE not advertised by ENA)
  - `offload_missing_rss_hash == 1` (RSS_HASH not advertised)
  - `offload_missing_rx_timestamp == 1` (expected absent on ENA)
  - `offload_missing_rx_cksum_ipv4/tcp/udp == 0`, `offload_missing_tx_cksum_ipv4/tcp/udp == 0` (all cksum offloads advertised)
  - `offload_missing_llq == 0` (LLQ verifier green via A-HW Task 12)
- `rx_drop_cksum_bad == 0` on well-formed echo traffic
- Every event's `rx_hw_ts_ns == 0` (ENA doesn't advertise the `rte_dynflag_rx_timestamp` dynfield)
- `eth.llq_wc_missing == 0` (WC baked into AMI via component 03)

**Sample size:** ≥100 k round-trips per N post-warmup (drop first 1 000); single-connection throughput is NOT the metric — RTT distribution is.

**Preset:** trading-latency default.
**Output:** `target/bench-results/bench-e2e/<run_id>.csv` — per-bucket aggregated rows. Raw per-sample histogram sidecar to `target/bench-results/bench-e2e/<run_id>.samples.bin` (compact-binary; optional re-analysis only).

---

## 7. Tool 3 — `bench-stress`

Stability benchmarks under induced loss/reorder/corruption/duplication. Drives the parent §11.4 matrix.

**Fault injection paths (composable):**
- **netem** — on the peer host (`tc qdisc add dev <iface> root netem loss 1% delay 10ms 2ms distribution normal`). Applies at the wire level.
- **`FaultInjector`** — A9's post-PMD-RX middleware, enabled via `DPDK_NET_FAULT_INJECTOR=drop=0.01,dup=0.005,reorder=0.002,corrupt=0.001` and `--features fault-injector` on the engine build. Applies inside the stack.

The two mechanisms can compose: netem at wire level, FaultInjector at post-PMD-RX.

**Scenario matrix (parent §11.4):**

| Scenario | Config | Pass criteria |
|---|---|---|
| 0.1% random loss, 10 ms RTT | netem loss 0.1% delay 10 ms | p999 ≤ 3× idle p999; no stuck conn over 10 min |
| 1% correlated burst loss | netem loss 1% 25% | p999 ≤ 10× idle p999; `tcp.tx_rto` / `tcp.tx_tlp` delta > 0 |
| Reordering depth 3 | netem reorder 50% gap 3 | RACK detects reorder; `tcp.tx_retrans` delta == 0 |
| Duplication 2x | netem duplicate 100% | no observable degradation at p99 |
| Receiver zero-window stall → recovery | peer-side `SO_RCVBUF` manipulation | `DPDK_NET_EVT_WRITABLE` within 1 RTT of window open |
| Send-buffer-full under slow peer | peer-side slow `recv()` | `dpdk_net_send` returns partial; WRITABLE on drain |
| FaultInjector: 1% drop | `DPDK_NET_FAULT_INJECTOR=drop=0.01` | same counters check as netem 1% |
| FaultInjector: reorder 0.5% | `DPDK_NET_FAULT_INJECTOR=reorder=0.005` | RACK recovery; no spurious retrans |
| FaultInjector: dup 0.5% | `DPDK_NET_FAULT_INJECTOR=dup=0.005` | no degradation at p99 |

**PMTU blackhole** (parent §11.4 row 4) is Stage 2 only — explicitly skipped; test-case row stays in the runner but `#[ignore]`d with a comment.

**Preset:** trading-latency default.
**Output:** `target/bench-results/bench-stress/<run_id>.csv`; `dimensions_json` carries `{"scenario": "<name>", "netem_config": "...", "fault_injector_config": "..."}`.

---

## 8. Tool 4 — `bench-vs-linux`

Dual-stack latency comparison. **Dual-preset runs** per D1.

**Peer harness:** same paired EC2 host. Linux-side runner binary (C or Rust) uses `AF_PACKET` mmap for user-space-delivery baseline + standard socket path for kernel-TCP baseline. Our stack runs via `dpdk-net-core` as normal.

**Mode A — latency comparison (trading-latency preset):**
- RTT distribution at p50/p99/p999 across idle / loss / reorder conditions
- Connection-establishment time distribution (SYN to `DPDK_NET_EVT_CONNECTED`)
- Time-to-first-byte on fresh connections
- Tap-jitter baseline subtracted: a same-host tap device captures raw wire RTT and the harness records its noise floor so we don't over-attribute latency to the stack
- N = 100 k measurements per bucket

**Mode B — wire-level equivalence (`preset=rfc_compliance`):**
- Same traffic, engine runs with preset=1, Linux runs with defaults
- pcap capture on both; byte-level diff
- Expected identical on `apply_preset(1)` scope (`tcp_nagle=true`, `tcp_delayed_ack=true`, `cc_mode=1`/Reno, `tcp_min_rto_us=200_000`, `tcp_initial_rto_us=1_000_000`)
- Divergences expected on: ISS jitter (RFC 6528), timestamp base (free; A10 pins both to a known value for the diff run), MSS option (depends on MTU — documented)
- Divergence-normalisation layer: small tool that rewrites ISS + timestamp base to a canonical value in both captures before diff

**Preset:** mode A = latency; mode B = rfc_compliance. Tracked as `dimensions_json: {"preset": "latency"|"rfc_compliance", "mode": "rtt"|"wire_diff"}`.
**Output:** two CSV row-sets per run; bench-report never averages across preset.

---

## 9. Tool 5 — `bench-offload-ab`

Feature-matrix A/B harness over the `hw-*` cargo flags (`crates/dpdk-net-core/Cargo.toml:18-23`).

**Driver:** `tools/bench-offload-ab/` binary; spawns `bench-ab-runner` per config (D3).

**Feature matrix:**

| Config name | Features |
|---|---|
| `baseline` | none (`--no-default-features`) |
| `tx-cksum-only` | `hw-offload-tx-cksum` |
| `rx-cksum-only` | `hw-offload-rx-cksum` |
| `mbuf-fast-free-only` | `hw-offload-mbuf-fast-free` |
| `rss-hash-only` | `hw-offload-rss-hash` |
| `rx-timestamp-only` | `hw-offload-rx-timestamp` |
| `llq-verify-only` | `hw-verify-llq` |
| `full` | `hw-offloads-all` (all hw-* flags) |

Additional compositions added if any single-offload result is ambiguous.

`hw-verify-llq` is verification-discipline — its A/B toggles whether the engine enforces LLQ-active at bring-up, NOT whether LLQ itself is configured (the PMD `enable_llq=X` devarg stays application-owned).

**Workload:** 128 B / 128 B request-response micro-workload, same as `bench-e2e`. ≥10 000 round-trips per config post-warmup (drop first 1 000). Same RNG seed across runs.

**Measurement discipline:** §11.1 preconditions, strict mode. Run is rejected if any precondition fails OR if a thermal throttle event occurs.

**Report metrics:** p50 / p99 / p999 per config with bootstrap 95% CI. Per-offload `delta_p99 = p99_baseline − p99_with_offload`.

**Decision rule:** an offload "shows signal" iff `delta_p99 > 3 × noise_floor`, where `noise_floor = p99 of two back-to-back baseline runs`. No signal + no correctness justification → remove from default feature set.

**Sanity invariant:** `p99(full) ≤ best p99 of any single-offload config`. Offloads should compose. Violation blocks A10 sign-off pending investigation (likely a contention or false-sharing issue in the engine code).

**Preset:** trading-latency default.
**Output:** `docs/superpowers/reports/offload-ab.md` — CSV + decision table + per-offload rationale (including any offload kept without raw signal, e.g., `hw-offload-mbuf-fast-free` for correctness defense-in-depth). Drives the committed default feature set in `crates/dpdk-net-core/Cargo.toml`.

---

## 10. Tool 6 — `bench-obs-overhead`

Mirrors `bench-offload-ab` but across `obs-*` flags.

**Feature matrix:**

| Config name | Features |
|---|---|
| `obs-none` | `obs-none` (NEW, disables G1–G4 per D4) |
| `poll-saturation-only` | `obs-poll-saturation` |
| `byte-counters-only` | `obs-byte-counters` |
| `obs-all-no-none` | `obs-all` (= `obs-poll-saturation + obs-byte-counters`; no `obs-none`) |
| `default` | default features (equivalent to production build) |

**Workload / discipline / decision rule:** identical to `bench-offload-ab`. 128 B / 128 B workload; ≥10 k RT per config; strict preconditions; `delta_p99 > 3 × noise_floor` gates "shows signal".

**Action taxonomy per failure:** for any feature whose default is ON and that shows hot-path signal:
- **batch** — increment accumulated in a per-poll local and fetch_add once per `poll_once`
- **remove** — counter eliminated
- **flip default** — default-OFF, opt-in by user
- **move off hot path** — relocate to slow-path decision point

**Preset:** trading-latency default.
**Output:** `docs/superpowers/reports/obs-overhead.md` — pass/fail per observable + action taken. Drives the committed default feature set for `obs-*` flags in `crates/dpdk-net-core/Cargo.toml` (mirrors `bench-offload-ab`'s role for `hw-offload-*`).

**Operationalises `feedback_counter_policy`:** any counter or event-log field claimed slow-path that shows hot-path signal here is re-evaluated before A11. If a new hot-path emission site surfaces that's NOT in the D4 scope, that's a policy-violation-by-measurement — remediate in A10.

---

## 11. Tool 7 — `bench-vs-mtcp`

Two sub-workloads per parent §11.5.1 + §11.5.2.

**Peer:** mTCP built into AMI at `/opt/mtcp/`; peer-side binary `/opt/mtcp-peer/bench-peer` pre-installed. Kernel TCP sink binary (same as bench-vs-linux peer) at `/opt/bench-peer-linux/bench-peer`.

### 11.1 `burst` grid — parent §11.5.1

| Axis | Values |
|---|---|
| Burst size K | {64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB} |
| Idle gap G | {0 ms (back-to-back), 1 ms, 10 ms, 100 ms} |

Product = 20 buckets.

- One connection per lcore, established once, reused for the whole run
- Peer: the kernel-side TCP sink (receives + ACKs, no echo) — reuses `bench-vs-linux` peer binary
- `cc_mode=off` on both stacks (parent §11.5.1)

**Measurement contract** (identical instrumentation on both stacks):
- `t0` = inline TSC read immediately before the first `dpdk_net_send` / `mtcp_write` of the burst
- `t1` = NIC HW TX timestamp on the **last segment** of the burst (read from `rte_mbuf::tx_timestamp` once the burst drains). Where HW TX timestamps are unavailable (ENA doesn't advertise this dynfield either — same as RX), fall back to TSC-at-`rte_eth_tx_burst` return.
- `throughput_per_burst = K / (t1 − t0)`
- Secondary decomposition: `t_first_wire` = HW TX timestamp (or TSC fallback) on segment 1 → `initiation = t_first_wire − t0`, `steady = K / (t1 − t_first_wire)`

**Warmup:** first 100 bursts per bucket discarded.

**Pre-run checks (invalidate bucket if any fail):**
- Peer's advertised receive window ≥ K (no peer-window stall)
- Identical MSS (1460) and TX burst size on both stacks
- Achieved rate ≤ 70% of NIC max pps/bps (not NIC-bound)
- §11.1 measurement-discipline green

**Sanity invariant at run end:** `sum_over_bursts(K) == stack_tx_bytes_counter`. Divergence = the harness is lying about what it sent.

**Aggregation:** p50, p99, p999 of `throughput_per_burst` across ≥10 k bursts per bucket.

### 11.2 `maxtp` grid — parent §11.5.2

| Axis | Values |
|---|---|
| Application write size W | {64 B, 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB} |
| Connection count C | {1, 4, 16, 64} |

Product = 28 buckets.

- Persistent connection(s); application writes in a tight loop for T = 60 s per bucket post-warmup
- Peer: kernel-side TCP sink (same as burst grid)
- Same `cc_mode=off`, same MSS, same TX burst size, same pre-run checks as burst

**Metrics:**
- Primary: sustained goodput = `(bytes ACKed in [t_warmup_end, t_warmup_end + T]) / T`, bytes/sec
- Secondary: packet rate = `segments_tx_counter_delta / T`, pps

**Warmup:** 10 s pumping before the measurement window starts.

**Sanity invariant:** ACKed bytes during window == `stack_tx_bytes_counter_delta` during window (minus any bytes still in-flight at `t_end`, bounded by cwnd + rwnd).

### 11.3 Shared

- CSV `dimensions_json`: burst = `{"workload": "burst", "K_bytes": <int>, "G_ms": <float>, "stack": "dpdk_net"|"mtcp"}`; maxtp = `{"workload": "maxtp", "W_bytes": <int>, "C": <int>, "stack": "dpdk_net"|"mtcp"}`
- CSV schema matches §14 so bench-report handles both alongside `bench-vs-linux`
- Preset: trading-latency (cc_mode=off explicit in CSV)

**Output:** `target/bench-results/bench-vs-mtcp/<run_id>.csv`. Published sections in the nightly run's Markdown + HTML reports.

---

## 12. Tool 8 — `bench-report`

Reads every CSV under `target/bench-results/**/*.csv` and emits:
- **JSON** — full long-form data plus aggregated views; archivable
- **HTML** — single-page static dashboard (vanilla JS, no server, no external CDN); failed preconditions colour-coded
- **Markdown** — per-phase summary tables suitable for committing under `docs/superpowers/reports/`

CLI: `bench-report [--input target/bench-results/] [--output-json path] [--output-html path] [--output-md path] [--filter strict-only|include-lenient|all]`.

Filter defaults to `strict-only` for published reports — rows where `precondition_mode == lenient` OR any precondition fail are excluded from aggregation (but still appear in the JSON for debugging).

**No Prometheus output** (explicit decision per D5). Dashboard itself (Grafana / custom) is out of scope — bench-report emits feed files; the user wires consumers later.

---

## 13. Cargo feature matrix (A10 changes)

**New feature: `obs-none`** (additive marker, default OFF).

`crates/dpdk-net-core/Cargo.toml` additions:

```toml
# A10: when enabled, disables all "always-on" observability emission sites
# (event-log ring writes, emitted_ts_ns capture, rtt_histogram update,
# conn-stats FFI getter). Additive marker — default builds behave as before.
# Only consumed by tools/bench-obs-overhead to measure the zero-observability
# floor.
obs-none = []
```

**Existing feature-set defaults preserved.** Default `obs-poll-saturation=ON`, `obs-byte-counters=OFF`, all `hw-*` flags ON. The `bench-offload-ab` and `bench-obs-overhead` reports may recommend flipping defaults; if so, the flips land in A10 AFTER the reports are produced and reviewed. Default-flip commits reference the report row that justifies them.

**`hw-offloads-all` + `obs-all`** already present; A10 consumes unchanged.

---

## 14. CSV schema

### 14.1 Full column list

**Run-invariant columns (same for every row of one run):**

| Column | Type | Example |
|---|---|---|
| `run_id` | UUID v4 | `4f2c…9a` |
| `run_started_at` | ISO 8601 with TZ | `2026-04-22T03:14:07Z` |
| `commit_sha` | 40-char hex | `1cf754af26…` |
| `branch` | string | `phase-a10` |
| `host` | hostname | `ip-10-0-0-42` |
| `instance_type` | EC2 string | `c6a.2xlarge` |
| `cpu_model` | /proc/cpuinfo model name | `AMD EPYC 7R13 Processor` |
| `dpdk_version` | string | `23.11.2` |
| `kernel` | uname -r | `6.17.0-1009-generic` |
| `nic_model` | PMD string | `Elastic Network Adapter (ENA)` |
| `nic_fw` | PMD string if available | `` (ENA doesn't report) |
| `ami_id` | ami-* | `ami-0123456789abcdef0` |
| `precondition_mode` | `strict` / `lenient` | `strict` |
| `precondition_isolcpus` | `pass=2-7` / `fail=...` | `pass=2-7` |
| `precondition_nohz_full` | same shape | `pass=2-7` |
| `precondition_rcu_nocbs` | same shape | `pass=2-7` |
| `precondition_governor` | `pass=performance` / `fail=<observed>` | `pass=performance` |
| `precondition_cstate_max` | `pass=C1` / `fail=C6` | `pass=C1` |
| `precondition_tsc_invariant` | `pass` / `fail` | `pass` |
| `precondition_coalesce_off` | `pass` / `fail` | `pass` |
| `precondition_tso_off` | `pass` / `fail` | `pass` |
| `precondition_lro_off` | `pass` / `fail` | `pass` |
| `precondition_rss_on` | `pass` / `fail` | `pass` |
| `precondition_thermal_throttle` | `pass=0` / `fail=<events>` | `pass=0` |
| `precondition_hugepages_reserved` | `pass=<pages>` / `fail` | `pass=2048` |
| `precondition_irqbalance_off` | `pass` / `fail` | `pass` |
| `precondition_wc_active` | `pass` / `fail` | `pass` |

**Per-row columns:**

| Column | Type | Example |
|---|---|---|
| `tool` | string | `bench-vs-mtcp` |
| `test_case` | string | `burst` |
| `feature_set` | string | `default` / `hw-offloads-all` / `obs-none` / `baseline` |
| `dimensions_json` | JSON | `{"K_bytes": 262144, "G_ms": 10, "stack": "dpdk_net"}` |
| `metric_name` | string | `throughput_per_burst_bps` |
| `metric_unit` | string | `bytes_per_sec` |
| `metric_value` | float | `8.7e9` |
| `metric_aggregation` | enum | `p99` |

### 14.2 `metric_aggregation` enum

`p50`, `p99`, `p999`, `mean`, `stddev`, `ci95_lower`, `ci95_upper`. No `raw` — raw samples stay in sidecar files.

### 14.3 Sidecar files (not ingested by bench-report)

| Tool | Sidecar | Purpose |
|---|---|---|
| `bench-micro` | `target/criterion/**/*.json` | cargo-criterion native, for flame-graph + regression diff |
| `bench-e2e` | `<run_id>.samples.bin` | per-measurement raw RTT + attribution-bucket times (binary, compact) |
| `bench-stress` | `<run_id>.netem.log` | tc-netem config echoed + counter snapshot pre/post |
| `bench-vs-linux` | `<run_id>.pcap` (mode B only) | pcap captures for wire diff |
| `bench-vs-mtcp` | `<run_id>.bursts.bin` | per-burst raw throughput samples (binary) |

All sidecars kept under `target/bench-results/<tool>/<run_id>.*`; reviewable manually; no commit.

---

## 15. IaC project: `resd.aws-infra-setup`

Sister repo. Python CDK. Reusable across future projects; A10's `bench-pair` preset is the first consumer.

### 15.1 Presets

`bench-pair`: two instances in a cluster placement group, same subnet, same AMI, cross-SG allowing TCP in configured port range, SSH from operator CIDR, outputs: DUT & peer SSH endpoints, data-ENI MACs + IPs, hugepages config, ami_id consumed, `resd-aws-infra-version`.

Future presets (out of scope for A10 but designed for): `single-host`, `bench-triangle` (DUT + 2 peers for multi-endpoint tests), `prod-cluster`.

### 15.2 Per-stack inputs (configurable at `setup`-time)

| Input | Default | Notes |
|---|---|---|
| `instance_type` | `c6a.2xlarge` | c6a / c7a / c8a (x86 AMD), c6in / c7i (x86 Intel). arm64 (c7gn/c8gn) requires an arm64 AMI — deferred. |
| `subnet_cidr` | `10.0.0.0/24` | single /24 in the new VPC |
| `ami_id` | CDK parameter default pointing at the latest successfully-baked `resd-host-ubuntu-24.04-k6.17-<ver>` | overridable per stack |
| `placement_strategy` | `cluster` | `spread` available for unrelated presets |
| `operator_ssh_cidr` | unset (no default) | caller must pass real CIDR; refuses `setup` otherwise |
| `auto_tear_down_seconds` | `0` (disabled) | set to e.g. `3600` for nightly usage |

**Baked-in-AMI only (NOT per-stack configurable):** hugepage count, `isolcpus` / `nohz_full` / `rcu_nocbs` CPU ranges, transparent-hugepage setting, governor default, C-state cap, WC vfio-pci module, mTCP, DPDK, toolchain. These are fixed at AMI bake time (§16.3). To change any, rebake the AMI (`resd-aws-infra bake-image`) and point `ami_id` at the new image.

**Why baked, not per-stack:** GRUB boot args are applied at first boot; cloud-init could edit-and-reboot per stack but that adds ~60 s to every bring-up and introduces a boot-time failure mode. A10 prefers the simpler AMI-singleton model; caller bakes a second AMI if they need a different hugepage count or isolcpus range.

### 15.3 CLI API

`resd-aws-infra setup <preset> [--config path.json] [--instance-type ...] [--json]` — prints (or writes to stdout in JSON) the stack outputs. Non-zero exit on deploy failure.

`resd-aws-infra teardown <preset> [--wait]` — deletes the stack. `--wait` blocks until `DELETE_COMPLETE`.

`resd-aws-infra status <preset>` — prints current state (JSON).

`resd-aws-infra bake-image [--recipe latest]` — triggers the Image Builder pipeline, waits, and prints the new AMI ID. Committed to the CDK parameter default on success.

### 15.4 API contract consumed by A10

`scripts/bench-nightly.sh` reads `resd-aws-infra setup bench-pair --json` output (DUT + peer SSH endpoints, data-ENI IPs), SCPs compiled bench binaries, invokes the preconditions checker + bench runners, pulls CSVs back, invokes `bench-report`, then calls `resd-aws-infra teardown bench-pair --wait`.

---

## 16. AMI bake pipeline

EC2 Image Builder, CDK-defined in `resd.aws-infra-setup/lib/image_builder/bench_host_image.py`. Components authored as YAML under `resd.aws-infra-setup/image-components/`.

### 16.1 Base

- **OS:** Ubuntu 24.04 LTS (noble), official Canonical AMI
- **Kernel:** `linux-generic-hwe-24.04` pinned to 6.17 at bake time. If 6.17 isn't yet in the HWE track at bake time, pin the nearest ≥6.17 available and document in component 08's logs. Zen5 support (`c8a`) is why we're ≥6.17.
- **Architecture:** x86_64 only (A10). arm64 variant deferred.

### 16.2 Component order

| # | Component | Contents |
|---|---|---|
| 01 | `install-llvm-toolchain` | Add `https://apt.llvm.org/llvm.sh` repo → install `clang-22 libclang-22-dev libc++-22-dev libc++abi-22-dev lld-22`. Symlink `/usr/local/bin/cc → clang-22`, `/usr/local/bin/c++ → clang++-22`. Set `CXXFLAGS=-stdlib=libc++` in `/etc/profile.d/llvm.sh`. |
| 02 | `install-dpdk-23-11` | Pull DPDK 23.11 LTS source; `CC=clang-22 CXX=clang++-22 meson build && ninja -C build && ninja -C build install`; verify `pkg-config --exists libdpdk`. |
| 03 | `install-wc-vfio-pci` | Clone `amzn-drivers`; run `enav2-vfio-patch/get-vfio-with-wc.sh`; verify WC-capable `vfio-pci.ko` installed. |
| 04 | `install-mtcp` | Recursively init the project-local `third_party/mtcp` submodule SHA (staged in the component's assets); build its bundled DPDK fork; `autoreconf -if && ./configure --with-dpdk-lib=…/dpdk/x86_64-native-linuxapp-gcc && make`; install `libmtcp.a`+headers to `/opt/mtcp/`; build the bench-peer program against it to `/opt/mtcp-peer/bench-peer`. |
| 05 | `configure-grub` | Edit `/etc/default/grub`: `GRUB_CMDLINE_LINUX="default_hugepagesz=2M hugepagesz=2M hugepages=2048 isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7 processor.max_cstate=1 transparent_hugepage=never"`. **No** `iommu=on` / `intel_iommu=on` — no-IOMMU mode. `update-grub`. |
| 06 | `modprobe-config` | `/etc/modprobe.d/vfio.conf`: `options vfio enable_unsafe_noiommu_mode=1`. `/etc/modules-load.d/vfio.conf`: `vfio`, `vfio_pci`, `vfio_iommu_type1`. |
| 07 | `systemd-units` | Unit 1: `set-governor-performance.service` (at boot, `cpupower frequency-set -g performance` across all CPUs). Unit 2: `irqbalance-disable.service` (stops + masks `irqbalance`). Unit 3: `verify-hugepages-reserved.service` (fails boot if `HugePages_Total < 2048`). Unit 4: `install-linux-tools.service` (one-shot; `apt-get install -y linux-tools-$(uname -r)` on first boot since the package name depends on the running kernel). |
| 08 | `install-bench-tools` | `ethtool pciutils numactl iproute2 turbostat perf linux-tools-generic`. |
| 09 | `install-preconditions-checker` | Copy the `scripts/check-bench-preconditions.sh` script to `/usr/local/bin/check-bench-preconditions`. Identical copy to the repo-local script. |

**AMI tag:** `resd-host-ubuntu-24.04-k6.17-<sem-ver>`. Semver rule: `v<major>.<minor>.<patch>`, bump `patch` for component fixes, `minor` for component additions, `major` for base-OS or kernel bumps.

### 16.3 AMI-bake inputs (configurable at `bake-image`-time)

These are the GRUB-and-config knobs baked into the AMI. To change any, rebake via `resd-aws-infra bake-image --config bake-config.json` with the new values. The baked AMI ID then replaces the prior default for every stack that consumes it.

| Input | Default | Notes |
|---|---|---|
| `hugepage_count` | `2048` (= 4 GiB of 2 MiB pages) | GRUB: `hugepages=<N>` |
| `isolcpus_range` | `2-7` (fits c6a.2xlarge's 8 vCPU) | GRUB: `isolcpus=<range> nohz_full=<range> rcu_nocbs=<range>`; larger instance types need a wider range → rebake |
| `cstate_max` | `1` (only C0 + C1 allowed) | GRUB: `processor.max_cstate=<N>` (AMD variant; Intel would use `intel_idle.max_cstate`) |
| `transparent_hugepage` | `never` | GRUB: `transparent_hugepage=<value>` |
| `kernel_stream` | `hwe-6.17` | `linux-generic-hwe-24.04` pinned to ≥ 6.17; rebake lets you move to a newer kernel |
| `dpdk_version` | `23.11 LTS` | bumping means rebaking + validating the whole library |
| `clang_version` | `22` from llvm.org | bumping validates the full toolchain chain |

### 16.4 AMI-bake output captured by CDK

The pipeline tags the resulting AMI with `resd-infra:version=<sem-ver>`, `resd-infra:base=ubuntu-24.04`, `resd-infra:kernel=<kernel-stream>`, `resd-infra:isolcpus=<range>`, `resd-infra:hugepages=<count>`. The CDK parameter default for `ami_id` on the `bench-pair` preset is updated via `resd-aws-infra bake-image` → emits the new AMI ID + commits it to `lib/presets/bench_pair.py` (user reviews the commit).

---

## 17. Report artefacts

Three Markdown files published to `docs/superpowers/reports/` at A10 completion:

| Artefact | Content | Drives |
|---|---|---|
| `offload-ab.md` | per-offload decision table (signal / no signal / kept-for-correctness), p50/p99/p999/CI per config, full CSV embedded | Committed default feature set in `crates/dpdk-net-core/Cargo.toml` for `hw-*` flags |
| `obs-overhead.md` | per-observable decision table + action taken for each failure (batch/remove/flip/move) | Committed default feature set for `obs-*` flags (including possibly flipping `obs-poll-saturation` to OFF if measurement justifies, though current policy is keep-ON) |
| `bench-baseline.md` | p50/p99/p999/CI per bench-micro target; recorded at A10's phase-complete commit | A11 regression-gate baseline |

All three ingest the same long-form CSV format.

---

## 18. End-of-phase review gates

Per `feedback_phase_mtcp_review` + `feedback_phase_rfc_review`:

- Dispatch `mtcp-comparison-reviewer` (opus 4.7) → `docs/superpowers/reviews/phase-a10-mtcp-compare.md`
- Dispatch `rfc-compliance-reviewer` (opus 4.7) → `docs/superpowers/reviews/phase-a10-rfc-compliance.md`
- Parallel invocation; both block the `phase-a10-complete` tag

**RFC scope for A10:** limited — A10 is benchmarks, not new TCP behaviour. Reviewer focus: the `preset=rfc_compliance` invocation in `bench-vs-linux` mode B exercises the existing preset correctly; no RFC MUST/SHOULD coverage regressed; measurement discipline (§11.1) enforced.

**mTCP scope for A10:** `bench-vs-mtcp` wire integration (build, submodule, measurement contract, sanity invariants); any mTCP-pattern we can learn from their harness design.

---

## 19. Dependencies

**On `resd.dpdk_tcp` master:**
- A6 complete (public API stable; `preset=rfc_compliance` landed)
- A6.5 complete (hot-path alloc-free; benchmarks measure production shape)
- A9 complete (FaultInjector for bench-stress; `test-inject` hook not required by A10 but no conflict)
- A-HW complete (offloads enabled; A-HW Task 18 deferred here)

**On `resd.aws-infra-setup`:**
- Repo stood up with at least one successful bake run before A10's first bench invocation
- AMI ID committed as CDK parameter default

**Parallel:**
- `phase-a7` (packetdrill shim) runs independently; A10 does NOT consume `test-server` FSM, does NOT consume `test-inject` RX hook (A10's bench-vs-linux and bench-vs-mtcp use real wire traffic).

---

## 20. Rough task scale

### 20.1 `resd.dpdk_tcp` (target: ~21 tasks per roadmap)

| Group | Tasks |
|---|---|
| Scaffold | 1. Workspace members registration; `bench-common` lib crate; CSV schema types. 2. `bench-ab-runner` shared runner skeleton. 3. `scripts/check-bench-preconditions.sh` + matching `/usr/local/bin` copy. |
| Engine | 4. `obs-none` feature + G1–G4 gate sites. 5. Knob-coverage test for `obs-none` (documentation-only feature; no runtime wire behaviour). |
| bench-micro | 6. 12 criterion targets. 7. Cargo.toml + bench targets in workspace. |
| bench-e2e | 8. Request-response RTT harness, attribution buckets, sum-identity assertion. 9. A-HW Task 18 offload-counter assertions + ENA-specific `rx_hw_ts_ns == 0` assertion. |
| bench-stress | 10. Netem driver. 11. FaultInjector runtime config + scenario matrix runner. |
| bench-vs-linux | 12. Linux-side peer harness. 13. Mode-A RTT runner. 14. Mode-B wire-diff runner + divergence-normalisation layer. |
| bench-offload-ab | 15. Driver binary (feature matrix + sub-process spawn loop). 16. Decision-rule evaluator + report writer. |
| bench-obs-overhead | 17. Driver (reuse driver lib from 15). 18. Report writer (reuse 16). |
| bench-vs-mtcp | 19. Burst-grid runner. 20. Maxtp-grid runner. 21. mTCP peer-side driver (AMI-pre-installed binary). |
| bench-report | 22. CSV ingest. 23. JSON / HTML / Markdown emitters. |
| Scripts + reports | 24. `scripts/bench-nightly.sh`. 25. Report artefact generation + commit. |
| End-of-phase | 26. mTCP review gate dispatch. 27. RFC review gate dispatch. 28. Roadmap row update + phase-a10-complete tag. |

**Effective ~21 tasks** if we bundle related small tasks; plan lands the exact decomposition during `writing-plans`.

### 20.2 `resd.aws-infra-setup` (~8 tasks)

1. Repo init + pyproject + CDK app skeleton.
2. `bench-pair` preset (VPC + SG + DUT/peer + outputs).
3. Image Builder pipeline CDK construct.
4. Components 01–09 YAML authoring.
5. `resd-aws-infra` CLI wrapper (click-based).
6. First successful bake run; AMI ID captured.
7. `bench-pair` stack up-tear-down smoke; validate preconditions-checker passes.
8. README + cost notes + troubleshooting.

---

## 21. Open questions / risks

| # | Item | Mitigation |
|---|---|---|
| R1 | Kernel 6.17 availability in Ubuntu 24.04 HWE at bake time | Fall back to nearest ≥6.17 available; document in `bench-baseline.md`. |
| R2 | mTCP build breakage on clang-22 + kernel 6.17 | Patches under `resd.aws-infra-setup/image-components/install-mtcp/patches/`; >50 lines → escalate to drop `bench-vs-mtcp` from A10. |
| R3 | HW TX timestamp availability on ENA | ENA does not advertise it; `bench-e2e` + `bench-vs-mtcp` fall back to TSC-at-`rte_eth_tx_burst`. Documented in parent §11.3 + §11.5.1. |
| R4 | Sub-process rebuild latency on `bench-offload-ab` / `bench-obs-overhead` | ~15 min per matrix acceptable; not run per-commit. |
| R5 | c6a.2xlarge vs bare metal for TSC certainty | Preconditions-checker detects TSC-invariance; non-bare-metal still works if `constant_tsc + nonstop_tsc` pass. If they don't, upgrade to `c6a.metal` via `--instance-type` override. |
| R6 | Dormant mTCP footprint on production AMI | ~200 MB at `/opt/mtcp/`; disk footprint acceptable; `/opt/` not on any hot code path. |

---

## 22. References

- Parent spec: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §11 (esp. §11.1, §11.2, §11.3, §11.4, §11.5, §11.5.1, §11.5.2, §11.7, §11.8, §11.9).
- Roadmap row: `docs/superpowers/plans/stage1-phase-roadmap.md` § A10 (L609–638).
- A-HW Task 18 deferral: commit `abea362`.
- A6 preset landing: `crates/dpdk-net/src/lib.rs:30` (`apply_preset`), `crates/dpdk-net-core/tests/knob-coverage.rs:393` (preset-rfc-compliance coverage).
- A9 FaultInjector: `crates/dpdk-net-core/src/fault_injector.rs` (env `DPDK_NET_FAULT_INJECTOR=...`).
- mTCP upstream: `third_party/mtcp/` submodule (SHA `0463aad5ecb6b5bca85903156ce1e314a58efc19` at phase-a10 branch point).
- ENA host-config guide: user's 2026-04-21 message (Ubuntu 24.04 + k6.17 + libc++ + no-IOMMU + WC-patched vfio-pci).
- Memory durable items applied: `feedback_trading_latency_defaults`, `feedback_observability_primitives_only`, `feedback_subagent_model`, `feedback_per_task_review_discipline`, `feedback_phase_mtcp_review`, `feedback_phase_rfc_review`, `feedback_counter_policy`, `feedback_performance_first_flow_control`, `reference_tcp_test_suites`, `project_arm_roadmap`, `feedback_build_toolchain` (updated 2026-04-21 to libc++).
