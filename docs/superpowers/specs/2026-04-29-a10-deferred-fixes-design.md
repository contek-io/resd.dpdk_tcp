# A10 Deferred Fixes Design

Date: 2026-04-29
Branch: `phase-a10`
Author: Claude (auto mode, dispatched on user instruction
  "fix the bugs and finish all deferred items")

## Scope

Three deferred items remain after the Phase A10 bench-nightly
sign-off (tag `phase-a10-complete` on commit `e044cd3`). They were
intentionally out of T16 scope but the user's explicit follow-up
instruction is to land fixes for all of them now.

| # | Bug | Source-of-truth observation |
|---|---|---|
| 1 | bench-stress netem `tc qdisc apply` over DUT→peer SSH times out | `docs/superpowers/reports/README.md` §"Open items" |
| 2 | bench-vs-mtcp burst + maxtp grids emit 0-row CSVs | same |
| 3 | `BENCH_ITERATIONS=5000` workaround for ~7051 retransmit cliff | same; root-cause hypothesis in `a10-ab-driver-debug.md` §3 |

Each bug is fixed on its own track. Bugs 1 and 3 have clear
diagnostic targets. Bug 2 needs stderr capture to pin its actual
failure mode and is plausibly subsumed by the Bug 3 fix.

## Item 1 — netem-over-DUT-SSH timeout

### Root cause

`bench-stress` runs on the DUT under `run_dut_bench`. Per scenario,
it calls `NetemGuard::apply(peer_ssh, peer_iface, spec)`
(`tools/bench-stress/src/netem.rs:111`), which shells out to:

```
ssh -o StrictHostKeyChecking=no $peer_ssh "sudo tc qdisc add ..."
```

`$peer_ssh` is `ubuntu@<peer-mgmt-public-ip>` — but `bench-stress` is
already running on the DUT, whose mgmt-ENI default route doesn't
reach the peer's mgmt IP through the operator's whitelist (the
peer's SG only allows port 22 from the operator's `MY_CIDR`, not
from the DUT's mgmt ENI). The connect hangs until OpenSSH's default
`ConnectTimeout` fires (the script logs report a multi-minute
timeout window).

### Fix

Move netem orchestration to the operator workstation, which already
has working SSH to both peer and DUT mgmt IPs.

1. **`bench-stress` opt-out flag.** Add `--external-netem` to
   `tools/bench-stress/src/main.rs` Args. When set, the per-scenario
   loop skips `NetemGuard::apply` / `Drop`; the scenario's `netem`
   field is logged for observability but no SSH is attempted.
2. **Operator-side orchestration in `bench-nightly.sh`.** Replace the
   single `bench-stress --scenarios <CSV>` call with a per-scenario
   loop:
   ```bash
   for scenario in random_loss_01pct_10ms correlated_burst_loss_1pct \
                   reorder_depth_3 duplication_2x; do
       ssh peer "sudo tc qdisc add dev ens6 root netem $(spec_for $scenario)"
       run_dut_bench bench-stress bench-stress-$scenario \
           "${DPDK_COMMON[@]}" \
           --scenarios "$scenario" \
           --external-netem \
           ...
       ssh peer "sudo tc qdisc del dev ens6 root || true"
   done
   ```
   The scenario→spec map lives in a small bash function reusing the
   string literals from `tools/bench-stress/src/scenarios.rs`.
3. **CSV merge.** Each per-scenario invocation writes to its own
   CSV; the wrapper concatenates them so downstream `bench-report`
   sees one bench-stress matrix.

### Validation
- `cargo test -p bench-stress -- --test-threads=1` — exercises new
  flag-parsing path.
- Live AWS run: confirm 4 scenarios produce 4×7 = 28 CSV rows + the
  idle baseline rows (current matrix).

## Item 2 — bench-vs-mtcp 0-row

### What we know

- The script logs `[11/12] bench-vs-mtcp burst grid` then
  `bench-vs-mtcp burst exited non-zero — continuing`.
- `run_dut_bench` runs the binary over SSH and captures stdout
  to a per-bench log; **it does not preserve stderr** beyond
  whatever scrolls past in the SSH session.
- The output CSV file exists (created by `csv::Writer::from_path`
  in `main.rs:253`) but contains zero rows past the header.

### Root cause hypothesis

Without preserved stderr we can only narrow. Most likely candidates:
1. **Class-shared with Bug 3.** Persistent connection opens; first
   bucket's warmup burst (`send_one_burst_and_drain_acks`) loops on
   `Ok(0)` because the RX path stalled. The 60s deadline in
   `dpdk_burst.rs:239` fires; the burst's `?` propagates; the
   per-bucket loop exits without writing CSV rows.
2. **Persistent-connection setup fails** — same kind of failure as
   the ephemeral-port collision (commit `4394ed7`) but on a
   different timing path, e.g. the `peer_rwnd` introspection step
   times out and surfaces an error that gets swallowed somewhere.
3. **Preflight check abort** — `check-bench-preconditions` returns
   a transient failure under strict mode; `std::process::exit(1)`
   fires before the writer flushes.

The README hints at #2 ("persistent-connection setup or peer-rwnd
sampling path"). Plumbing stderr capture is the right first step
either way.

### Fix

1. **Plumb stderr capture in `bench-nightly.sh`.** Modify
   `run_dut_bench` to redirect both stdout and stderr to a per-bench
   log file (`$OUT_DIR/<bench-name>/bench.log`) and only `tail` the
   trailing portion to the script's main log on non-zero exit. No
   behavior change in the happy path; first re-run captures the
   actual error.
2. **Re-run, diagnose, fix.** Three branches:
   - If hypothesis 1: the Stage-B Bug 3 fix lands and the warmup no
     longer stalls; bench-vs-mtcp passes.
   - If hypothesis 2: patch the specific timeout / fallback path.
   - If hypothesis 3: relax the precondition or extend the env-var
     fallback so the binary can run even when
     `check-bench-preconditions` is flaky.

### Validation
- AWS re-run with stderr captured. Acceptance: ≥1 burst row + ≥1
  maxtp row in the corresponding CSVs.

## Item 3 — iteration-7050 retransmit cliff

### Root cause hypothesis

(See `a10-ab-driver-debug.md` §3 — restated here.)

`rx_mempool_size` resolves to **8192** mbufs under stock
`EngineConfig` defaults (formula at `engine.rs:880-903`). The ENA
PMD pre-allocates 512 mbufs for the RX ring at queue setup,
leaving ~7680 mbufs for in-flight workload traffic. Observed cliff
values 7051 / 7055 / 7051 sit just inside that window after the
500-iter warmup and ARP/SYN startup transients (~100 mbufs).

A leak rate of ~1 mbuf per request/response iteration on the RX
path would drain the headroom on the observed schedule. The
deterministic symptom (`tcp error during recv: errno=-110`) is the
ETIMEDOUT force-close at `engine.rs:2422` after 15 RTO retransmits
without ACK progress — exactly what would happen once the RX path
can no longer accept incoming ACKs.

Strongest candidate sites for the leak (audit targets):
- `engine.rs:4130` — `split_mbuf = front.mbuf.try_clone()` partial-
  read split. Refcount bookkeeping looks symmetric on inspection
  (try_clone bumps once; both delivered handle and in-queue handle
  drop their refs eventually) — but if the handle escape path is
  ever subject to a slot reuse or skipped Drop, the bump leaks.
- `tcp_input.rs:962` / `:1022` — `MbufHandle::from_raw`
  constructions for delivered + reorder-queued segments. Each
  caller must already have bumped the refcount; missing-bump or
  double-bump here would leak.
- `tcp_reassembly.rs` OOO insert path — `OooSegment` -> `MbufHandle`
  conversion at `:370`.

### Fix

Two stages — diagnostics first, surgical fix second.

#### Stage A — diagnostic counters

Both slow-path; no hot-path cost. Both compile in unconditionally
(no feature gate — they're forensic primitives that should always
be readable).

1. **`tcp.rx_mempool_avail`** (`u32`, last-sampled value).

   Read inside `poll_once` once per second (gated on a TSC delta
   against a stored last-sample TSC) via
   `shim_rte_mempool_avail_count(self._rx_mempool.as_ptr())`. Stored
   into `Counters.tcp.rx_mempool_avail` with `Relaxed` store. Cost:
   one TSC read + branch per poll on the slow path; one shim FFI
   call per second.

2. **`tcp.mbuf_refcnt_drop_unexpected`** (`AtomicU64`).

   In `MbufHandle::Drop`, capture the post-dec count via a new
   `shim_rte_mbuf_refcnt_read` and compare to the expected value
   (0 if this was the last handle, ≥1 if other handles remain). On
   discrepancy beyond what's reachable via the legitimate
   try_clone-pairing, bump the counter. (Defining "expected" is
   tricky — we'll start with: "post-dec count > 32 is unequivocally
   a leak indicator, since no legitimate path would hold that many
   handles to one mbuf concurrently"; refine after the first run.)

3. **CSV emit.** `bench-e2e` / `bench-stress` already snapshot
   counters pre/post run. Plumb the two new counters into the
   per-bench summary (`bench_common::counters_snapshot`) so the
   nightly report shows them as deltas alongside the existing
   `tcp.recv_buf_drops` etc.

#### Stage B — root cause fix

Conditional on what Stage A surfaces:
- **If `rx_mempool_avail` decreases monotonically across iterations:**
  audit the suspected sites. Most likely fix is a one-line refcount
  pairing correction. Add a regression test: TAP-loopback
  RTT-workload integration test (`tests/rx_mempool_no_leak.rs`)
  modelled on `tests/rx_close_drains_mbufs.rs` — runs 10000 RTT
  iterations against the kernel echo peer and asserts mempool
  occupancy returns to within ±32 of the pre-test baseline.
- **If `rx_mempool_avail` is steady but the cliff still hits:**
  the root cause is elsewhere — could be a per-flow AWS-side limit
  (less likely at the observed pps), or a counter-saturation /
  arithmetic-overflow in the retransmit path. Diagnostic continues
  with a different counter set.
- **Defense in depth (regardless of diagnosis):** raise the default
  `rx_mempool_size` formula's per-conn term from `2 *
  max_connections * per_conn + 4096` to `4 * max_connections *
  per_conn + 4096`. Doubles the cliff threshold from ~7050 to
  ~14000+ even if the leak is unfixable. (Keeps the `4 *
  rx_ring_size` floor unchanged.)

### Validation
- `cargo test -p dpdk-net-core --test rx_mempool_no_leak -- --test-threads=1`
  with `DPDK_NET_TEST_TAP=1`. Asserts mempool drift ≤ 32 mbufs over
  10000 iterations.
- AWS bench-nightly re-run with `BENCH_ITERATIONS=100000` (spec
  value). Acceptance: bench-e2e / bench-stress / bench-offload-ab /
  bench-obs-overhead / bench-vs-mtcp all complete without errno=-110.
- Diagnostic counter values in CSV — `rx_mempool_avail` should stay
  in `[6500, 7700]` range across the run (ARP / SYN / FIN startup
  traffic accounts for the lower bound; full RX ring + partial
  reorder queue accounts for the upper bound).

## Order of operations

1. **Stage-A diagnostics for Bug 3** — quickest local code change;
   no AWS dependency until run time. Land first so subsequent AWS
   runs surface the cliff cause directly.
2. **stderr capture in `run_dut_bench`** for Bug 2.
3. **`--external-netem` flag + bench-nightly.sh update** for Bug 1.
4. **Build + ship.** `cargo test --workspace` locally; deploy to
   AWS bench-pair.
5. **Trigger AWS bench-nightly run with `BENCH_ITERATIONS=100000`.**
6. **Diagnose Bug 2 from captured stderr; apply Stage-B fix for Bug
   3 based on counter evidence. Re-run.**
7. **Roll up.** Update `docs/superpowers/reports/README.md`'s "Open
   items" section to "Closed" with confirmed-fixed commits in the
   bug table. Tag the closing commit so the deferred-items work has
   its own anchor (e.g. `phase-a10-deferred-fixed`).

## Out of scope

- New benchmark workloads (e.g. multi-flow stress, wire-diff mode B
  expansion).
- mTCP stack implementation (deferred to Plan A AMI bake — the
  bench-vs-mtcp `--stacks dpdk` path is sufficient for nightly).
- Stage 2 operator-side janitor for orphan netem qdiscs (spec §16).
- Migration to a metal instance type for higher per-flow caps.

## Risk register

| Risk | Mitigation |
|---|---|
| Bug 3 leak doesn't reproduce locally on TAP | Counter-driven AWS run gives ground truth; TAP test is regression catch only. |
| Stage-A diagnostics themselves mask the bug (e.g. by changing timing) | Counters are sub-µs slow-path; sampling rate is once-per-second. Negligible. |
| `--external-netem` orchestration is brittle (peer SSH transient failure mid-loop) | Wrapper logs SSH retry; `tc qdisc del` is `|| true`; the cleanup-on-drop pattern of NetemGuard is replaced by an outer-scope cleanup which is more robust. |
| Defense-in-depth doubling of rx_mempool_size doubles hugepage usage | Default `max_connections=16` × 256KiB recv buffer = small footprint either way. Bumped pool is still well under c6a.2xlarge's hugepage allocation. |

## Spec self-review

(Self-review per brainstorming skill checklist — fixed inline.)

- Placeholder scan: no TBDs.
- Internal consistency: order-of-ops references all three items;
  hypothesis-fix branches in Bug 2 align with hypotheses in §"Root
  cause hypothesis".
- Scope check: focused enough — three specific bugs, each with
  bounded fix. No decomposition needed.
- Ambiguity check: "expected" in `mbuf_refcnt_drop_unexpected` was
  ambiguous; pinned to "post-dec count > 32" with a refine-after-
  first-run note.
