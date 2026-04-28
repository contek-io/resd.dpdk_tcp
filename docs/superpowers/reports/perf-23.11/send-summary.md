# send family — A10-perf-23.11 — summary

## Final criterion numbers

| Bench | T3.0 baseline | Post-T3.6 final | §11.2 upper | Within budget? |
|---|---|---|---|---|
| bench_send_small | 70.58 ns (STUB) | (STUB unchanged) | 150 ns | n/a |
| bench_send_large_chain | 1231.55 ns (STUB) | (STUB unchanged) | 5000 ns | n/a |

## Optimizations applied

**None — Phase 3 send work deferred.**

Per `docs/superpowers/reports/t2-7-deferral.md` (committed in Phase 2): real `dpdk_net_send` measurement requires:
- `rte_eal_init` with adequate mempool config (or `--no-huge` fallback)
- A `net_vdev` / `net_tap` engine for TX path execution (existing `test_fixtures::make_test_engine` is the integration point under `DPDK_NET_TEST_TAP=1`)
- Hugepages + `CAP_IPC_LOCK` or root privilege

These prerequisites couldn't be cleanly resolved inside the Phase 2 scaffolding work without stalling the rest of bench-micro unblock. The decision was to ship Phase 2 with `bench_send_small` + `bench_send_large_chain` staying in `STUB_TARGETS` (proxied via pure-Rust stubs), and resume real-path wiring as part of send-family optimization in Phase 3.

## Exit reason

**deferred-to-future-task** — real send-path measurement infrastructure not in place. The plan's task numbering (T3.3 = send) implied an iteration cycle here; the actual condition (no real-path benches) means there's nothing to iterate against. Exit equivalent to "gate-N/A".

## What's needed to revisit

A future maintenance task should:
1. Build a `init_eal_once()` shim in `tools/bench-micro/benches/send.rs` (or a shared helper) that calls `rte_eal_init` with a minimal-args vector (likely `--no-huge` for dev-host viability + `-l 0` for single-lcore).
2. Construct a bench-local `Engine` via `test_fixtures::make_test_engine` — gate behind env-var probe so the bench skips cleanly when prerequisites are absent.
3. Call `dpdk_net_send` against an established connection in the bench loop. Mbuf alloc + TCP-header build + checksum + chain-mbuf build are the hot work being measured.
4. Re-baseline bench_send_small (target ~150 ns) + bench_send_large_chain (target 1-5 µs).
5. Remove `bench_send_small` + `bench_send_large_chain` from `tools/bench-micro/src/bin/summarize.rs` `STUB_TARGETS` once real-path wiring lands.

## Caveats

- The DPDK-24 worktree (`a10-dpdk24-adopt`) inherits this same deferral. Whichever worktree first resumes send-family work picks up the EAL-init pattern; the other cherry-picks.
- If a future bare-metal verification host is provisioned with hugepages + CAP_IPC_LOCK, the bench can run in production-shape (real EAL, real port via vdev, real mempool). On the current KVM dev host, `--no-huge` is the workable path.
- The §11.2 ~150 ns target for `bench_send_small` assumes a hot mempool slot, an established conn, and inline checksum — rough numbers that bake in some hardware assist. On vdev-without-checksum-offload, the bench will measure higher; this is an attribution caveat to surface when numbers eventually land.

## Future-work refs

- `docs/superpowers/reports/t2-7-deferral.md` — full T2.7 deferral rationale.
- `crates/dpdk-net-core/src/test_fixtures.rs` — existing `make_test_engine` pattern under `DPDK_NET_TEST_TAP=1`.
- `tools/bench-micro/src/bin/summarize.rs::STUB_TARGETS` — list to update when real-path wiring lands.
- Plan §Phase 3 T3.3 — original task description with the EAL-init template.
