# A10 bench-nightly reports

Real-hardware runs of the Phase A10 bench-nightly pipeline against
an AWS `bench-pair` fleet (c6a.2xlarge × 2, ap-south-1, AMI
`ami-05ae5cb6a9a7022b9`).

## Artefacts

| File | Status | Source |
|---|---|---|
| `bench-baseline.md` | ✅ Refreshed 2026-04-29 (cliff fixed, 100k iters) | `target/bench-results/2026-04-29T13-11-35Z/report.md` (run `c8deba07`) |
| `offload-ab.md` | ✅ Refreshed 2026-04-29 | `target/bench-results/2026-04-29T13-11-35Z/bench-offload-ab/offload-ab.md` |
| `obs-overhead.md` | ✅ Refreshed 2026-04-29 | `target/bench-results/2026-04-29T13-11-35Z/bench-obs-overhead/obs-overhead.md` |

## Headline results — full 100 000 iterations (post cliff fix)

### `bench-baseline.md` — DPDK vs Linux kernel TCP RTT

100 000 measurement iterations + 1 000 warmup, 128 B / 128 B payloads,
single long-lived TCP connection over the data ENI:

| Stack | p50 | p99 | p999 |
|---|---|---|---|
| dpdk_net | **35.6 µs** | 44.1 µs | 51.9 µs |
| linux_kernel | 37.2 µs | 45.5 µs | 52.2 µs |

DPDK userspace stack measurably faster than Linux kernel TCP at every
percentile under the same workload. The 100k-iteration run executes
through completion without errno=-110 — the iteration-7050 cliff is
fixed (commit `f3139f6`).

### `offload-ab.md` — hardware-offload A/B sweep

8 configs (baseline + 7 individual offload bits + `full`), each 100 000
iterations. Noise floor 89 ns; decision threshold 267 ns (much tighter
than the prior 5k-iter run's 371 ns / 1 113 ns). At this resolution,
two configs cross the threshold:

- **`mbuf-fast-free-only`**: p99 = 40 740 ns vs baseline 41 189 ns
  (delta +449 ns, **Signal**) — modest but real benefit on this NIC.
- **`full`** (all offloads): p99 = 40 170 ns vs baseline 41 189 ns
  (delta +1 019 ns, **Signal**).

The other 5 configs remain `NoSignal`. The 100k sample size revealed
real effects that the 5k run buried in noise.

### `obs-overhead.md` — observability-counter A/B sweep

5 configs (`obs-none` baseline + 3 counter groups + `default`), each
100 000 iterations. Noise floor 380 ns; decision threshold 1 140 ns.
All deltas `NoSignal`. Same observation as before: in-noise variations
across configs (some p99 below `obs-none`); under sustained measurement,
hot-path observability bumps are within sampling jitter.

## Closed deferred items

The three items deferred from T16 are now closed:

| Item | Status | Resolution |
|---|---|---|
| `bench-stress` netem-over-DUT-SSH | ✅ Fixed | Operator-side netem orchestration in `bench-nightly.sh` (commit `0cbc8d6`) + `--external-netem` flag in `bench-stress` (commit `cebcb61`). DUT runs the workload only; operator workstation applies/removes netem qdiscs via SSH to the peer's mgmt IP. Per-scenario CSV merge into a unified `bench-stress.csv`. |
| `bench-vs-mtcp` 0-row CSV | ✅ Fixed | Two-part: (a) `--peer-ssh` removed from invocation (commit `0ff8271`) so the peer_rwnd `ss -ti` SSH probe falls back to the placebo silently; (b) the iteration cliff (Bug 3) had been closing the persistent connection mid-bucket — fixing the cliff lets all 20 K×G burst buckets complete. **420 rows** emitted across the burst grid. |
| `BENCH_ITERATIONS=5000` workaround | ✅ Fixed | Root cause: `MbufHandle::Drop` called `rte_mbuf_refcnt_update(p, -1)`, which decrements but never returns the mbuf to its mempool when the count reaches 0. Fix: switch to `rte_pktmbuf_free_seg` via a new pool-guarded shim (commit `f3139f6`). The TAP-loopback regression test (`crates/dpdk-net-core/tests/rx_mempool_no_leak.rs`) drops mempool drift from 500/500 iters to 0/500 iters. The 100k iteration AWS run completes cleanly. |

## Companion documents

- `a10-ab-driver-debug.md` — v1 forensic pass (earlier engine-teardown
  bugs, with v2 + Codex revisions)
- `a10-ab-driver-debug-v2.md` — v2 deeper Claude pass (drop-order
  Hypothesis B)
- `a10-ab-driver-debug-codex.md` — codex second-opinion (drop-order
  invariant generalised; nailed the actual fix for the SIGSEGV)
- `bench-baseline.md` / `offload-ab.md` / `obs-overhead.md` — the three
  artefact files.

## Confirmed-fixed bugs along the way

| Commit | Bug | How surfaced |
|---|---|---|
| `726a411` | sshd race in wait_for_ssh probe | `kex_exchange_identification: Connection closed` after CDK CREATE_COMPLETE |
| `27a8044` | clap rejected hyphen-leading EAL args, comma split couldn't preserve PCI inner commas | "unexpected argument '-l' found" |
| `a24ef56` | rx/tx ring size 1024 default exceeds ENA cap (512) | "Invalid value for nb_tx_desc(=1024), should be: <= 512" |
| `35c490a` | peer data-NIC bound to vfio-pci by AMI; echo-server can't accept on Linux | DUT-side connect timeout |
| `1f9c407` | `set -e` aborted whole nightly on first per-bench failure | only first bench's CSV produced |
| `5d945f3` | wire-diff abort on missing pcap; bench-stress FaultInjector multi-spec collision | `chown: No such file`, "multiple distinct FaultInjector specs" |
| `d0a61ae` | bench-offload-ab/-obs-overhead `--output-dir` collided with the scp'd binary path | "Error: creating /tmp/bench-offload-ab" |
| `4394ed7` | every new process picked ephemeral port 49152 first → peer TIME_WAIT collision | `connection closed during handshake: err=0` |
| `715de88` | bench-micro panic-strategy mismatch on `cargo bench` profile | `crate dpdk_net_core requires panic strategy abort` |
| `671062a` | iteration-7051 retransmit cliff (workaround) | `tcp error during recv: errno=-110` at iter ~7051 |
| `585d647` | EAL hugepage state isolation (`--in-memory --huge-unlink`) | (didn't fix the real bug, but harmless) |
| `a1d2c56` | drop-order: mbuf owners released after mempools | gdb backtrace `shim_rte_mbuf_refcnt_update → MbufHandle::drop → ... → FlowTable::drop → Engine::drop`, mbuf in deleted memzone |
| `f8c1c13` | gdb wrapper deprecated-syntax warning corrupted bench-ab-runner stdout | bench-offload-ab "9 rows expected 7" |
| `8925b11` | shim_rte_mbuf_refcnt_read FFI accessor | needed by Stage A leak diagnostics |
| `38ec3b7` | rx_mempool_avail + mbuf_refcnt_drop_unexpected counters | A10 deferred-fix Stage A (forensic plumbing) |
| `d403989` | thread_local engine-counter pointer + leak-detect bump in MbufHandle::Drop | A10 deferred-fix Stage A wiring |
| `ec42232` | 1Hz rx_mempool_avail sampler in poll_once | A10 deferred-fix Stage A sampler |
| `cebcb61` | `--external-netem` + `--list-scenarios` flags in bench-stress | A10 deferred-fix Bug 1 |
| `e95a1ae` | per-bench stderr capture in run_dut_bench | A10 deferred-fix Bug 2 forensic |
| `0cbc8d6` | operator-side netem orchestration in bench-nightly.sh | A10 deferred-fix Bug 1 |
| `010b57b` | rx_mempool_size 4× per-conn term + TAP regression test | A10 deferred-fix Stage B defense in depth |
| `eeed5ae` | scp-on-failure + pre-loop netem cleanup + regen header | A10 deferred-fix code-review follow-ups |
| `64f8077` | force_close_etimedout DIAGNOSTIC stderr dump | A10 deferred-fix Stage B forensic surfaced cliff signature |
| `0ff8271` | drop `--peer-ssh` from bench-vs-mtcp invocation | A10 deferred-fix Bug 2 (peer_rwnd SSH timeout) |
| **`f3139f6`** | **MbufHandle::Drop: rte_pktmbuf_free_seg, not rte_mbuf_refcnt_update(-1)** | **A10 deferred-fix Stage B ROOT CAUSE: refcount_update only decs, doesn't free at 0; pool drained 1 mbuf/iter; cliff at iter 11151 (pool=12288)** |
