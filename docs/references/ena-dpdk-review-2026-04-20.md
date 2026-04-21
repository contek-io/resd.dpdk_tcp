# ENA DPDK README review vs current implementation

Date: 2026-04-20
Reference: `docs/references/ena-dpdk-readme.md` (upstream `amzn-drivers/userspace/dpdk/README.md`, 1528 lines)
Scope: crates/dpdk-net-core, crates/dpdk-net-sys, crates/dpdk-net; Stage 1 phase-a-hw implementation + roadmap.

## Summary

Phase A-HW already covers the big correctness items the README cares about: LLQ verification, TX+RX IPv4/TCP cksum offload, `MBUF_FAST_FREE`, RSS plumbing with `RTE_ETH_MQ_RX_RSS`, and dynfield-based RX timestamping (known-0 on ENA).
Nothing in the current implementation is *wrong* against the README.
The gaps below are all "README calls out an ENA-specific lever that we don't yet use", either for reliability (device reset) or for observability/tuning (ENI limiter xstats, WC verification, `large_llq_hdr`, `miss_txc_to`). All are Stage 2 candidates; a subset is worth promoting earlier.

---

## What we already do correctly

| Topic | README §  | Our location | Status |
|---|---|---|---|
| LLQ enforced on 6th-gen+ (required for perf) | §6, §14 | `llq_verify.rs`, `engine.rs` `configure_port_offloads` | verified via PMD-log-scrape at `rte_eal_init` |
| RX cksum `ol_flags` 4-state consumption | §8.2.4 | `l3_ip.rs::classify_ip_rx_cksum`, `tcp_input.rs` `nic_csum_ok` | strictly more robust than mTCP (GOOD/BAD/NONE/UNKNOWN all distinct) |
| TX cksum pseudo-header-only + ol_flags | README implicit (standard DPDK) | `tcp_output.rs::tx_offload_finalize` | matches RFC 9293 §3.1 byte-for-byte |
| `MBUF_FAST_FREE` bit | §12.1 | `configure_port_offloads` | feature-gated; latched post-AND |
| `RTE_ETH_MQ_RX_RSS` + `rss_hf = NONFRAG_IPV4/IPV6_TCP` | §11 | `engine.rs:1061-1065` | correct; single-queue no-op today, forward-compat for Stage 2 |
| `rss_key = NULL` (PMD default Toeplitz) | §11.3 | `engine.rs:1064` | accepted divergence from mTCP's symmetric key; revisit at Stage 2 multi-queue (already tracked as AD-2) |
| `rte_eth_dev_rss_reta_update` after start | §11.2 | `program_rss_reta_single_queue` | explicit + tolerant of `reta_size == 0` for `net_tap` |
| `rte_mbuf_dynfield_lookup` + `dynflag_lookup` | README silent; parent spec §8.3 / §9.2 | `engine.rs:772-792` | correct; ENA returns `None`, counter `offload_missing_rx_timestamp = 1` is documented steady state |
| Capability-AND against `dev_info.*_offload_capa` | §5.1, §5.3 | `and_offload_with_miss_counter` | pure improvement over mTCP (which hard-fails on any request mismatch) |
| Startup negotiated-offload banner | §8.5 (parent spec) | `engine.rs:1086-1089` | one line per bring-up |

## Gaps and optimization opportunities

Ranked by latency/reliability impact for the trading-client target.

### H1 — Write-Combining BAR mapping not verified (README §6.1, §6.2.3, §14)

**Why it matters:** The README's single most emphatic warning is that running LLQ **without WC** on the prefetchable BAR causes "high CPU usage in `ena_com_prep_pkts`" and "huge performance degradation" on 6th-gen instances — this is the #1 ENA misconfiguration. Our `llq_verify.rs` checks that LLQ *activated* (Placement policy: Low latency); it does not check that the BAR got mapped write-combining.

**What the README prescribes:** `cat /sys/kernel/debug/x86/pat_memtype_list | grep <prefetchable BAR addr>` must show `write-combining`. With `igb_uio` loaded without `wc_activate=1`, or on the DPDK v21.11 regression (§15 known issues), the line will show `uncached-minus` instead.

**Proposed addition:** At `configure_port_offloads` on x86_64 Linux when driver is `net_ena`:
1. Read the prefetchable BAR address via `rte_pci_device->mem_resource[2]` or `lspci -s <bdf> -v`.
2. Read `/sys/kernel/debug/x86/pat_memtype_list`, grep for the BAR address.
3. If no `write-combining` line → bump new `eth.llq_wc_missing` one-shot counter + emit a WARN banner. Optionally fail-hard behind a feature flag paralleling `hw-verify-llq`.

Fits the existing "slow-path counter at bring-up, warn banner, fail-hard feature-flagged" pattern. Low complexity, catches a failure mode the current log-scrape misses silently.

### H2 — ENI allowance-exceeded xstats not surfaced (README §8.2.2)

**Why it matters:** AWS silently throttles EC2 network at multiple axes:
- `bw_in_allowance_exceeded`, `bw_out_allowance_exceeded` — aggregate bandwidth
- `pps_allowance_exceeded` — bidirectional PPS
- `conntrack_allowance_exceeded` — per-instance NAT conntrack table; **critical for a REST/WS client making many short-lived connections**
- `linklocal_allowance_exceeded` — IMDS/DNS/NTP

When any of these is nonzero, packets are queued or dropped by the hypervisor and the stack sees tail-latency spikes with no local cause. For an order-entry trading client these are the *most important* external-cause counters on EC2.

**What the README prescribes:** periodic `rte_eth_xstats_get_by_id()` scrape; available since ENA v2.2.0 (DPDK 21.02+).

**Proposed addition:** slow-path, engine-owned periodic scrape (once/sec, driven by application timer — matches the user's "observability primitives only" memory: library exposes counters, application drives the cadence). Expose 5 new `u64` fields on the `EthCounters` snapshot. One-time `rte_eth_xstats_get_names` lookup at `engine_create` caches the `xstat_id`s per name.

Cost: ~5 PCI reads per second per engine, slow-path by any definition.

### H3 — No device-reset recovery path (README §9)

**Why it matters:** ENA can wedge in four ways documented by the README: (a) HW unresponsive (no AENQ keep-alives), (b) admin queue faulty, (c) invalid IO-path descriptors, (d) missing Tx completions exceeding threshold. Without a reset handler the engine will silently hang forever. For a production trading client this is a reliability gap.

**What the README prescribes:**
1. `rte_timer_manage()` called ~1Hz (triggers `ena_timer_wd_callback` inside the PMD).
2. Register for `RTE_ETH_EVENT_INTR_RESET`.
3. On event, drain/prep + call `rte_eth_dev_reset()`.

**Proposed addition:** Roadmap entry — probably **Stage 2 hardening** (A11 or a new A-HW+ row). Requires design for how in-flight TCP connections behave across a reset (TIME_WAIT? abort-all? pause queue?). Not a correctness gap for Stage 1 bring-up but must exist before production.

Counter surface: `eth.dev_reset_count`, `eth.aenq_keepalive_missed`.

### M1 — `large_llq_hdr` devarg not plumbed (README §5.1)

**Why it matters:** Default LLQ header size is 96B. Our stack's max header stack is Ethernet 14 + IPv4 20 + TCP 20 + TCP options ≤ 40 = **94B worst case**. Right at the 96B edge. A TCP segment carrying full 40B options (TS + WS + SACK blocks + MSS + nops) will fit; any A4+A5.5 option layout change that nudges past 96B silently degrades TX to the non-LLQ path.

**What the README prescribes:** pass `large_llq_hdr=1` devarg; LLQ header grows to 224B. Cost: "reduces Tx queue size by half" — for single-queue at `tx_ring_size = 1024` this is 512 descriptors, still plenty for a trading client at <100 kpps.

**Proposed addition:**
- Expose on `EngineConfig` as `ena_large_llq_hdr: bool` (default false, behaviour parity with current; flip to true when enabling SACK or if A4+ measurements show header>96B).
- `eal_init` inserts `-a <bdf>,large_llq_hdr=1` when set. Alternatively document that operators pass it directly.
- Add a bring-up assertion: if `(eth + ip + tcp_max_hdr) > 96` and flag is off, bump `eth.llq_header_overflow_risk` + WARN.

### M2 — `miss_txc_to` devarg not surfaced (README §5.1)

**Why it matters:** Default 5s before PMD considers a Tx completion missing (reset condition). For a latency-sensitive app, a 5-second stall is already disastrous; we'd want to detect sooner. But disabling entirely ("Caution" in README) risks queue stall.

**Proposed addition:** expose as `EngineConfig.ena_miss_txc_to_sec: u8` (default 5, recommend 2–3 for trading). Plumb into the `-a <bdf>,miss_txc_to=N` devarg alongside `large_llq_hdr`. Slow-path only.

### M3 — Per-queue Tx/Rx xstats not surfaced (README §8.2.3–4)

**Why it matters:** Single-queue Stage 1 benefits less, but still useful signals:
- `tx_qX_linearize` — if >0, driver is copy-repacking (indicates suboptimal mbuf chains from our retrans path)
- `tx_qX_doorbells` — ratio of doorbells to packets (low = good batching)
- `tx_qX_missed_tx` — Tx completions that timed out (tied to `miss_txc_to`)
- `rx_qX_refill_partial` — Rx pool pressure (tied to `mbuf_alloc_fail`)
- `rx_qX_bad_desc_num` / `bad_req_id` — reset conditions

**Proposed addition:** folded into H2 xstats scrape; 5-10 extra u64s in the counter snapshot per queue. At single queue this is 5-10 scalars total. Slow-path.

### M4 — `RTE_ETHDEV_QUEUE_STAT_CNTRS` default is 16 (README §8.1)

Not a bug today (single queue), but a trap when Stage 2 multi-queue lands: per-queue stats stop updating for queues >16. Our `build.rs` does not raise this. Document in the Stage-2 multi-queue plan row of `stage1-phase-roadmap.md`.

### L1 — MTU / jumbo frames (README §12.1–2)

README recommends jumbo for bandwidth. Stage 1 is pinned to 1500 MTU by design (target is REST/WS behind LB). Already documented out-of-scope in A-HW. No change.

### L2 — Tx rate-limiting (README §12.1)

ENAv2 accepts packets beyond link limit and silently drops. For a trading client sending small order packets, the observed aggregate is tiny (<1 Gbps typical) — not a realistic concern. Document as a non-goal in the A10 benchmark plan.

### L3 — RSS hash key symmetric-vs-default (README §11.3, review AD-2)

Already tracked as accepted divergence AD-2 in `phase-a-hw-mtcp-compare.md`. Single-queue today → no behavioural impact. Revisit at Stage 2 multi-queue bring-up; if a symmetric key is chosen, the softrss fallback in `flow_table.rs` must use the same key.

### L4 — `ena_com_prep_pkts` hot-path profile check (README §14 perf FAQ Q1)

Related to H1 (WC mapping). If we ever see this function dominate a flame graph, WC is broken. Document in `docs/guide-maintainer/07-perf-opportunities.md` (pending from A12).

---

## Recommended follow-ups

Ordered by impact:

1. **New task under A11 or a new A-HW+ row** — H1 (WC verification) + H2 (ENI xstats) + M3 (per-queue xstats). Single phase, ~6 tasks, all slow-path counter additions.
2. **Stage 2 reliability phase** — H3 (device reset + AENQ keepalive handling). New row between A11 and A12.
3. **A5.6/A6-style small deliverable** — M1 (`large_llq_hdr` config), M2 (`miss_txc_to` config). Both are ~1 engine-config field + devarg injection + one assertion. Can ship alongside H1.

None of the above blocks the Stage 1 ship gate. All are production-readiness items the README flags as load-bearing for the Stage 1 target deployment (AWS ENA 6th-gen).

## Nothing is *wrong*

No misalignment found with:
- LLQ activation check (verified against `ena_ethdev.c:2273-2277`, correct markers).
- Offload AND semantics (strictly more robust than mTCP).
- RSS mq_mode + hash-fields choice (matches README guidance + parent spec §8.4).
- NIC RX timestamp fallback on ENA (matches documented ENA behaviour).
- `rss_hf` restricted to NONFRAG_IPV4/IPV6_TCP (matches "By default RSS hash calculation works only for the TCP and UDP packets" guidance; we scope to TCP since UDP-TX isn't yet plumbed).

The current A-HW code is a faithful superset of what the ENA README requires for correct offload bring-up.
