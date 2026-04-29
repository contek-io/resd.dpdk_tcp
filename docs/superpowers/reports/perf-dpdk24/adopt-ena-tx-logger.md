# ENA TX logger rework (DPDK 24.07) — measurement-only

**Worktree:** `a10-dpdk24-adopt` at `/home/ubuntu/resd.dpdk_tcp-a10-dpdk24`
**Branch HEAD at survey:** `322cd60` (T4.5-4.6 baseline).
**Reference:** https://doc.dpdk.org/guides/rel_notes/release_24_07.html

## What changed in DPDK 24.07

The ENA PMD reworked its TX-side logger usage to reduce per-packet log overhead. This is a driver-internal change inside `drivers/net/ena/`; it is automatically active whenever the ENA PMD is loaded, with no application-side code change required to benefit.

The intent of the rework is a small reduction in TX-burst median latency and a tighter p99 tail under sustained send workloads — log-call cost was previously paid per-mbuf in some hot-path branches.

## Status: **deferred-pending-T3.3**

Verification of this rework requires:

1. **Real `dpdk_net_send` execution.** Currently stubbed per the T2.7 deferral (`docs/superpowers/reports/t2-7-deferral.md`); `bench_send_small` and `bench_send_large_chain` are pure-Rust proxies that don't exercise `shim_rte_eth_tx_burst`, the ENA driver, or any DPDK TX path at all. T3.3 wires the real send path forward.
2. **Real ENA NIC.** The dev host (`dpdk-dev-box.canary.bom.aws`) is KVM with a `net_null` / `net_pcap` test-driver path — no ENA hardware reachable from this VM. The host-capabilities report (`docs/superpowers/reports/perf-host-capabilities.md`) calls this out as a baseline limitation. A bench-pair host with real Nitro / EC2 ENA is needed.

Both prerequisites are out-of-scope for the bench-micro phase (Phase 4). The rebase-baseline report's §6.1.5 ENA TX regression check (`docs/superpowers/reports/perf-dpdk24/baseline-rebase.md`) already documents that the 24.11 send-stub numbers don't speak to ENA TX behavior either way.

## Prior 5× send-stub reference (from baseline-rebase.md)

These numbers are NOT a measurement of the ENA TX logger rework — they're the variance floor of the pure-Rust send stub on this host. They're listed here so the future bench-pair re-measurement has a "what changed" reference:

| Bench | Pre-rebase median (23.11 stub) | Post-rebase median (24.11 stub) | 5× std (24.11) |
|---|---:|---:|---:|
| bench_send_small | 70.58 ns | 74.876 ns (5× mean) | 2.373 ns |
| bench_send_large_chain | 1231.55 ns | 1323.54 ns (5× mean) | 20.18 ns |

Stub variance is 1.5–3.2 % stddev/mean — the noise floor for a future bench-pair re-measurement of the *real* ENA path. The rework should show as a small reduction in median + a tighter p99 tail on send-burst workloads when run against real ENA + real send.

## Re-measurement criterion

When T3.3 (real send wiring) lands AND when bench measurement runs on a bench-pair with real ENA hardware:

```bash
# On bench-pair host with real ENA:
cd <worktree>
source scripts/use-dpdk24.sh
# Real-send build (with --features real-send or equivalent, post-T3.3):
timeout 600 cargo bench --bench send -- --measurement-time 5 --save-baseline ena-tx-logger-pre-24-07
# Then on a 23.11 worktree (or 24.11 worktree with the rework patched out, if practical):
timeout 600 cargo bench --bench send -- --measurement-time 5 --baseline ena-tx-logger-pre-24-07
```

Expectation: small median reduction (< 5 % on send_small, possibly larger on send_large_chain where the per-segment log overhead amortized differently in 23.11). The headline indicator is the p99 tail: the old per-packet logger path showed a long-tail signature when the kernel's syslog throttle kicked in.

## Decision

**deferred-to-e2e** (specifically: deferred-pending-T3.3 + bench-pair host).

No application-side code change exists or is required. This is a passive DPDK-rebase win that will land for free once we have the real send path on real ENA.

## Commits

- Port: n/a — no application-side change exists
- This report (deferral note): see `git log --oneline -- docs/superpowers/reports/perf-dpdk24/adopt-ena-tx-logger.md`

## Caveats / future-work

- **Stub send is not ENA TX.** Until T3.3, any "ENA TX" claim against bench-micro numbers is a category error — the stub never reaches a DPDK driver, ENA or otherwise.
- **Bench-pair host required.** Even with T3.3 wired, this dev box (KVM, no real NIC) cannot measure the rework. A bench-pair (loopback over real ENA between two EC2 hosts on the same placement-group) is the minimal verification environment.
- **Reference:** DPDK 24.07 release notes — https://doc.dpdk.org/guides/rel_notes/release_24_07.html (search "ena" for the ENA-specific changes; the TX-logger rework is one of several driver-internal updates in that release).
