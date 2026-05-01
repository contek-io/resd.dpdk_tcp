# A10 A/B-driver SIGSEGV — v2 forensic report

**Run:** `target/bench-results/2026-04-28T12-32-05Z` (post 585d647 + 4394ed7).
**Commit:** master @ `f6b3eed`.

## 0. Current state

Both shipped fixes did NOT eliminate the failure.

| Bench | Outcome |
|---|---|
| bench-e2e ([7/12], [9b/12]) | passed; rows in report.md |
| bench-vs-linux ([8/12]) | passed |
| bench-stress ([9/12]) | empty CSV (0 lines) |
| bench-offload-ab ([10/12]) | headers-only CSV; FIRST baseline config produced no rows |
| bench-obs-overhead ([10b/12]) | headers-only CSV; same |
| bench-vs-mtcp burst+maxtp ([11/12], [11b/12]) | empty CSV |
| bench-micro / report ([12/12]) | passed |

Empty CSVs reach `$OUT_DIR` because `bench-nightly.sh` writes the header before the bench runs (lines 549, 622 / `tools/bench-offload-ab/src/main.rs:151`) and tolerates non-zero exit with `||`. Failure mode: bench process aborts before producing its FIRST data row — earlier than v1 assumed.

## 1. Behavioural fingerprint

* The crashers are exactly the binaries linking `dpdk-net-core`+`dpdk-net-sys` AND running after bench-vs-linux. bench-e2e/bench-vs-linux (same crates) succeed because they run earlier.
* `bench-offload-ab` is a pure orchestrator (`tools/bench-offload-ab/src/main.rs:18-22`); the inner `bench-ab-runner` is the DPDK process. Its FIRST baseline config produced 0 rows, so the inner aborted on its first invocation — there is no "Nth surviving process". v1's "Nth process" framing is wrong.
* `--runner-bin /tmp/bench-ab-runner-gdb.sh` (`scripts/bench-nightly.sh:634`) wraps every `bench-ab-runner` exec under gdb (`scripts/bench-ab-runner-gdb.sh:43-64`), but no `bench-ab-runner-gdb.log` artefact ended up in the run dir. Either gdb-batch silently fell through to `exec /tmp/bench-ab-runner` at `bench-ab-runner-gdb.sh:34` (no gdb on PATH), or the entire `[10/12]` step was reaped before reaching the scp at `:671`.

## 2. Hypothesis A — Per-process EAL hugepage state still leaks across invocations

**Evidence**:
* `crates/dpdk-net-core/src/engine.rs:655-718` — `eal_init` is a single-shot `Mutex<bool>` per process; `rte_eal_cleanup` is never called anywhere in the dpdk-net-core tree. `Drop for Engine` (engine.rs:5643-5652) calls only `rte_eth_dev_stop` + `rte_eth_dev_close`. `Mempool::drop` (`mempool.rs:104-110`) calls `rte_mempool_free`, executed AFTER the Drop body via Rust struct-field forward order.
* `--in-memory --huge-unlink` (commit 585d647, `bench-nightly.sh:288`) addresses `/var/run/dpdk/rte/` and `/dev/hugepages/rtemap_*` filesystem persistence; it does NOT prevent allocator failure inside one process or exit-time leaks from prior processes.
* All currently-failing benches share: each spawns ≥1 fresh EAL process post-bench-vs-linux. The first such process (bench-stress at [9/12]) already fails — so the leak source is the prior bench-vs-linux exit, not the failing bench's own setup.

**Prediction**: `dmesg | grep -i 'hugepage\|page allocation'` from the DUT during the failing window shows kernel-side hugepage exhaustion / fragmentation. The next DPDK process can't get contiguous 2 MiB pages because prior processes mapped + unlinked but didn't fully release them at exit.

**Fix**: invoke `rte_eal_cleanup` on engine drop. Extend `Drop for Engine` (engine.rs:5643) to call `rte_eal_cleanup` after the per-port stop/close, gated by a process-local "is this the last engine" guard tracked in the same `EAL_INIT` Mutex.

**Verification**: rerun nightly. If A is right, all four currently-empty CSVs gain data rows in one shot, and the dmesg signal disappears.

## 3. Hypothesis B — Mempool drops after `rte_eth_dev_close`; ENA queue-release frees objects the engine still holds

**Evidence**:
* `Drop for Engine` (engine.rs:5645-5650) calls `rte_eth_dev_stop` then `rte_eth_dev_close`. `rte_eth_dev_close` synchronously fires ENA's `ena_rx_queue_release` and `ena_tx_queue_release` per queue. The `_rx_mempool` field declared at engine.rs:415 then drops next (forward struct-field order), invoking `rte_mempool_free` on a pool that ENA's release callback may still reference if the PMD did not zero its `queue->mb_pool` pointer.
* The `ena_rx/tx_queue_release` printk-style log lines were observed in the prior run preceding the SIGSEGV (per v1 §2). The ordering is a known DPDK-23.11 ENA pattern; upstream 24.x relaxed it. Our pinned DPDK is 23.11 (report.md:9).
* This explains why `Drop for Engine`'s `unsafe` body completing successfully still produces an exit-139: the SIGSEGV fires AFTER the close call returns, in mempool free or in DPDK's exit-time memzone walker.

**Prediction**: explicitly dropping the rx/tx mempools BEFORE `rte_eth_dev_close` (by promoting them to `Option<Mempool>` and `take()`+`drop()` on Engine drop), or AFTER inside the same `unsafe` block, eliminates the crash. Validate by adding `RTE_MALLOC_DEBUG=1` to EAL_ARGS and inspecting the crash backtrace for `ena_*_queue_release` frame above `rte_mempool_free`.

**Fix**: refactor `Drop for Engine` to (1) `rte_eth_dev_stop`, (2) `rte_eth_dev_close`, (3) explicitly take + drop mempools afterward inside the same `unsafe` block. Promote `_rx_mempool` (engine.rs:415), `tx_hdr_mempool` (:421), `tx_data_mempool` (:422) to `Option<Mempool>`.

**Verification**: same "next nightly produces non-empty CSVs" criterion. With `RTE_MALLOC_DEBUG=1`, no use-after-free reported in `ena_rx_queue_release`.

## 4. Hypothesis C — Peer-side TIME_WAIT / echo-server bind race

**Evidence**:
* Commit 4394ed7 randomised the source ephemeral-port seed via TSC mix. Two TSC reads on quiet AMD EPYC may yield <<14 bits of variation in practice; collision probability is not the claimed 1/16k.
* But: empty 0-row CSV means the runner died before it called `csv::Writer::write_record`. `bench-vs-mtcp` `dpdk_burst.rs:297` propagates a clean `anyhow::bail!("first-segment send_bytes failed: ...")` which is a clean Rust exit, AFTER `csv::Writer` started — so InvalidConnHandle alone would NOT yield a 0-row CSV. Runner died earlier than connect.

**Prediction**: peer-side echo-server access log shows zero new connections from DUT IP during `[9/12] bench-stress` first-scenario timestamp. If true, runner aborted in EAL or engine bring-up.

**Fix**: rule out by plumbing runner stderr through. Currently the `ssh` invocation at `bench-nightly.sh:622` and the gdb wrapper at `bench-ab-runner-gdb.sh:34/:64` both discard stderr to the SSH channel; under `--skip-rebuild` the parent `bench-offload-ab` inherits stderr (`tools/bench-offload-ab/src/main.rs:320`) but the ssh-channel framing eats it. Capture: `2>/tmp/bench-ab-runner-${cfg}.stderr` inside the gdb wrapper and scp at `bench-nightly.sh:672`.

**Verification**: stderr file containing an EAL/panic message before any csv-writer call kills C. Otherwise, A or B is the cause.

## 5. Recommendation

1. **Forensics first**: scp back DUT `dmesg` after `[10/12]`, plus runner stderr (currently dropped). Without these, A and B are observationally equivalent. Cost: append `2>/tmp/bench-ab-runner-${cfg}.stderr` to the gdb wrapper, add scp at `bench-nightly.sh:672`.
2. **Land Hypothesis B** (explicit mempool drop after `rte_eth_dev_close`). Cheapest source fix that aligns with the v1 ENA-release fingerprint AND would close any "Nth-process" residual even if A is also true.
3. **Only if (2) does not clear failures**, add `rte_eal_cleanup` per Hypothesis A. EAL cleanup is heavier and risks new failure modes (unfreed memzones in test-inject path, engine.rs:1149).

C is observationally inconsistent with empty CSVs (runner died pre-csv-header-flush) and should be deprioritised.
