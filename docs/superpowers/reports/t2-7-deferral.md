# T2.7 deferral — bench_send_* real-path wiring

**Status:** deferred from Phase 2 to Phase 3 T3.3 (send-family optimization).

**Why deferred:** the plan's T2.7 Option B chose "per-bench `rte_eal_init` in `criterion_main`" as the path forward. Execution surfaced three prerequisites we don't want to resolve in Phase 2 scaffolding:

1. Real `rte_eal_init` on this KVM dev host needs either `--no-huge` + adequate mempool config OR 2 MiB hugepages + `CAP_IPC_LOCK` / root privilege — neither trivial to run cleanly from `cargo bench` inside a subagent's non-interactive context.
2. Real send needs a `net_vdev` / `net_tap` engine — there is already a `test_fixtures::make_test_engine` path gated on `DPDK_NET_TEST_TAP=1`; re-using it for a criterion bench needs adapter code + careful `Once` guarding across the 100-sample criterion loop.
3. Measurement integrity: a bench that silently degrades to a stub when EAL init fails hides the signal. A bench that hard-fails on missing env blocks the rest of the suite.

**What survives from T2.7 into Phase 3 T3.3:**
- Option B (pre-criterion EAL init via `criterion_main` or a helper) is the chosen shape.
- `test_fixtures::make_test_engine` is the likely integration point.
- The `STUB_TARGETS` list in `tools/bench-micro/src/bin/summarize.rs` keeps `bench_send_small` + `bench_send_large_chain` entries through T2.9 until T3.3 lands real wiring.

**What unblocks T3.3's execution:**
- A hardened measurement host (or explicit env-var-gated local run) with hugepages + CAP.
- A clear decision on stub-skip vs hard-fail when the env is missing (resolved at T3.3 opening).

**What Phase 2 ships without this:** T2.5 (poll), T2.6 (timer_add_cancel), T2.8 (CSV), T2.9 (STUB_TARGETS minus unblocked benches) all land. Three of the five stubs (poll_empty, poll_idle_with_timers, timer_add_cancel) are now real code. `bench_send_small` + `bench_send_large_chain` remain stubs — explicitly scoped for T3.3.
