# Phase A-HW+ — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent (opus 4.7)
- Date: 2026-04-20
- mTCP submodule SHA: `0463aad5ecb6b5bca85903156ce1e314a58efc19` (`third_party/mtcp`; unchanged this phase)
- Our commit: `7c35aa813ff5d383224fcb6c74004812b8c520c5` (branch `phase-a-hw-ena-followups`, T13 complete)
- Base: `eb01e79` (`master`)

## Scope

A-HW+ closes the five highest-impact gaps against the upstream ENA DPDK README (H1 Write-Combining BAR mapping verification, H2 ENI allowance-exceeded xstats scrape, M1 `large_llq_hdr` knob + bring-up overflow-risk assertion, M2 `miss_txc_to` knob, M3 per-queue ENA xstats for q0). All deliverables are slow-path; no wire changes, no hot-path additions, no behavior change when running on non-ENA PMDs.

Our files reviewed:
- `crates/dpdk-net-core/src/wc_verify.rs` — NEW. `parse_pat_memtype_list` pure parser + `verify_wc_for_ena` bring-up helper (eprintln + counter-bump on miss; never fails hard).
- `crates/dpdk-net-core/src/ena_xstats.rs` — NEW. `XSTAT_NAMES` (13-entry slice), `XstatMap::from_lookup` / `apply`, `resolve_xstat_ids` (calls `rte_eth_xstats_get_names`), `scrape` (calls `rte_eth_xstats_get_by_id`).
- `crates/dpdk-net-core/src/engine.rs` — `Engine::new` now caches `xstat_map`; `configure_port_offloads` calls `shim_rte_eth_dev_prefetchable_bar_phys` + `wc_verify::verify_wc_for_ena` + the M1 bring-up overflow-risk guard (lines 956–1002); new `Engine::scrape_xstats(&self)` (lines 1282–1288); `EngineConfig` grows `ena_large_llq_hdr` + `ena_miss_txc_to_sec` (lines 298–314).
- `crates/dpdk-net-core/src/counters.rs` — 15 new `AtomicU64` fields on `EthCounters` (`llq_wc_missing`, `llq_header_overflow_risk`, 5 × `eni_*`, 8 × q0 per-queue); `_pad` shrunk to `[AtomicU64; 2]`. Const struct-size assertion added at end of file.
- `crates/dpdk-net-sys/shim.c` — new `shim_rte_eth_dev_prefetchable_bar_phys` (BAR2 phys-addr reader, dereferences `struct rte_pci_device`; requires driver-SDK headers).
- `crates/dpdk-net-sys/wrapper.h` — prototype appended.
- `crates/dpdk-net-sys/build.rs` — new `detect_dpdk_sdk_includes` helper + `DPDK_HAS_PCI_SDK` compile-def; fail-open (shim returns 0) when SDK headers absent.
- `crates/dpdk-net/src/api.rs` — 15-field mirror on `dpdk_net_eth_counters_t`; 2 knob fields on `dpdk_net_engine_config_t`; `_pad` shrunk to `[u64; 2]`.
- `crates/dpdk-net/src/lib.rs` — bridge for the 2 knob fields in `dpdk_net_engine_create`; `dpdk_net_scrape_xstats` (lines 452–460); `dpdk_net_recommended_ena_devargs` (lines 484–519) with `-EINVAL` / `-ERANGE` / `-ENOSPC` contract.
- `include/dpdk_net.h` — cbindgen-regenerated.
- `tests/ffi-test/tests/ffi_smoke.rs` — shadow-struct + literal-construction sites updated for the 2 new mirror fields.
- `crates/dpdk-net-core/tests/knob-coverage.rs` — 2 new `#[test]` fns for `ena_large_llq_hdr` and `ena_miss_txc_to_sec`.
- `crates/dpdk-net-core/tests/ahw_smoke_ena_hw.rs` — real-ENA WC + overflow-risk + scrape assertions (lines 488–534).
- `crates/dpdk-net-core/tests/ena_obs_smoke.rs` — NEW. Pure-unit coverage for `wc_verify::parse_pat_memtype_list` + `XstatMap::from_lookup`.

mTCP files referenced (for the "does mTCP have an analog?" question):
- `third_party/mtcp/mtcp/src/dpdk_module.c` — port config (`port_conf` 110-156), `dpdk_load_module` (643-803), stats ioctl path (291-372), `check_all_ports_link_status` (588-635).
- `third_party/mtcp/mtcp/src/io_module.c` — `rte_eal_init` invocation sites (334-348, 596-610).
- `third_party/mtcp/mtcp/src/onvm_module.c` — rte_eth_stats scrape (`rte_eth_stats_get` at 218) for comparison to our xstats path.

Gap-analysis source: `docs/references/ena-dpdk-review-2026-04-20.md`.

## Summary (for human reader)

Phase A-HW+ is entirely scope-additive versus mTCP. None of the five deliverables have any mTCP analog — mTCP's DPDK I/O module was written in 2014 targeting Intel 82599 / X710 / mlx4 / mlx5 NICs on igb_uio, predates AWS ENA by years, has no awareness of the prefetchable BAR / LLQ / WC-mapping requirement, never calls `rte_eth_xstats_*` (only the basic `rte_eth_stats_get` → custom kernel ioctl), and has no devarg intent layer for any PMD. The `grep` sweeps for `xstats`, `ena`, `ENA`, `large_llq`, `miss_txc`, `wc_activate`, `write-combining`, `prefetchable`, `pat_memtype`, `bus_pci_driver`, `mem_resource`, `RTE_DEV_TO_PCI` across the entire `third_party/mtcp/mtcp/src/` tree returned zero hits.

mTCP's bring-up health-check pattern is limited to `rte_eth_link_get_nowait` polling for link-up (`dpdk_module.c:588-635`) + a hard `rte_exit(EXIT_FAILURE, ...)` on `rte_eth_dev_configure` / `rte_eth_rx_queue_setup` / `rte_eth_tx_queue_setup` / `rte_eth_dev_start` failure. No PAT memtype reading, no xstats discovery, no devarg decisions. Every A-HW+ deliverable sits strictly in our incremental scope; the comparison sections below therefore all resolve to either "no mTCP analog" or "scope addition."

No Must-fix or Missed-edge-case findings against mTCP. The incremental surface is so far outside mTCP's design center that there are no behavioral divergences to flag against it. The FYI section records the observed mTCP patterns for forward traceability; one Accepted-divergence entry is preserved to make the "mTCP's stats model vs ours" decision explicit for future human sign-off.

## Findings

### Must-fix (correctness divergence)

None.

### Missed edge cases (mTCP handles, we don't)

None.

Specifically examined and confirmed we either handle the case independently (no mTCP precedent) or explicitly out of scope:
- **WC BAR mapping verification (H1).** mTCP has no analog — it does not support AWS ENA, does not know what a prefetchable BAR is, does not call `rte_eth_dev_info_get(...).device` → `rte_pci_device.mem_resource[2].phys_addr`, and does not open `/sys/kernel/debug/x86/pat_memtype_list`. Our `wc_verify.rs` defensively handles: non-Linux / non-x86_64 target (`cfg!` gate → silent skip); non-`net_ena` driver (string compare → silent skip); `bar_phys_addr == 0` (PMD didn't expose BAR2 → skip with eprintln); unreadable `/sys` (debugfs missing / non-root / containerized → skip with eprintln); line missing the `[mem 0x` prefix (`continue`); malformed `-` dash (`continue`); hex case variation (`eq_ignore_ascii_case`); fully empty input file (`NotFound`). `grep -i pat_memtype third_party/mtcp` → 0 hits confirms no omitted mTCP defense.
- **ENI allowance / per-queue xstats scrape (H2, M3).** mTCP's only DPDK-stats path is `rte_eth_stats_get(portid, &stats)` + a custom kernel ioctl `SEND_STATS` (`dpdk_module.c:291-370`), which reads only `rte_eth_stats` (imissed / ierrors / oerrors / byte counts) — NOT xstats. mTCP has no `rte_eth_xstats_get_names` call, no name→ID resolution, no snapshot-vs-accumulator semantics question. Our `ena_xstats.rs` defensively handles: `get_names` returning ≤ 0 (no advertised xstats → all slots `None`, scrape becomes a cheap no-op); PMD advertising a subset (individual `None` slots silently write 0 via `apply`); `get_by_id` returning `rc < expected` (leaves values at zero so "throttle cleared" transitions are observable); name-NUL truncation inside the fixed-64-byte `rte_eth_xstat_name.name` buffer (NUL-walk with `take_while`).
- **Bring-up overflow-risk counter (M1).** mTCP has no concept of LLQ and no notion of a "header-size ceiling enforced by the PMD." `grep LLQ third_party/mtcp` → 0 hits. Our `Engine::new` guard computes worst-case header = 14 + 20 + 20 + 40 = 94 B, compares against 96 B LLQ limit + 6 B margin, and fires a one-shot `fetch_add(1, Relaxed)` on `llq_header_overflow_risk` iff driver is net_ena AND `ena_large_llq_hdr == 0`. No missed mTCP case.
- **`miss_txc_to` / `large_llq_hdr` knobs (M1, M2).** mTCP does not construct devargs at all — it passes the entire EAL `argc/argv` through unmodified from the application's config file (`io_module.c:334-348`). `grep -i devarg third_party/mtcp` → 0 hits; `grep large_llq third_party/mtcp` → 0 hits; `grep miss_txc third_party/mtcp` → 0 hits. Our `dpdk_net_recommended_ena_devargs` (`crates/dpdk-net/src/lib.rs:484-519`) defensively handles null `bdf` / null `out` (`-EINVAL`), `miss_txc_to_sec > 60` (`-ERANGE` — matches ENA README §5.1 cap), small `out_cap` (`-ENOSPC`), and non-UTF-8 bdf (`-EINVAL` via `CStr::to_str` error branch). No missed mTCP case because there is no mTCP case.

### Accepted divergence (intentional — draft for human review)

- **AD-1** — **Stats-exposure model: ENA xstats (us) vs basic rte_eth_stats + custom kernel ioctl (mTCP).**
  - mTCP: `dpdk_module.c:291-372` reads `rte_eth_stats` (8 scalar fields: ipackets/opackets/ibytes/obytes/imissed/ierrors/oerrors/rx_nombuf) at ≈1 Hz when `ENABLE_STATS_IOCTL` is compiled in, packs them into `struct stats_struct`, and pushes via an `ioctl(SEND_STATS, &ss)` to a kernel-space consumer the application provides. Per-queue and per-PMD-specific counters are not accessible. `rte_eth_stats_reset(portid)` is called on every push, so the model is "delta since last tick."
  - Ours: `Engine::scrape_xstats` calls `rte_eth_xstats_get_by_id` against a pre-resolved name→ID map covering 13 ENA-specific PMD xstats (5 ENI allowances + 8 per-queue q0). The application drives the cadence via `dpdk_net_scrape_xstats`. Snapshot semantics (not delta) — a failed scrape writes 0, not "keep previous value," so a throttle-cleared transition is observable on the next successful scrape. The basic `rte_eth_stats` counters are intentionally NOT scraped here; the per-lcore `EthCounters` already carries `rx_pkts` / `tx_pkts` / `rx_drop_nomem` / etc. populated on the hot path from our own RX/TX loop, avoiding the extra PMD call entirely.
  - Suspected rationale:
    - `feedback_observability_primitives_only.md` — the stack exposes counter primitives + a scrape function, not aggregation or routing; mTCP's ioctl-to-kernel model is the opposite and is incompatible with our C-ABI / application-owned-cadence contract.
    - `feedback_performance_first_flow_control.md` — snapshot (not delta) semantics let the application diagnose when a throttle has cleared without the race inherent in reset-after-push.
    - ENA-specific scope: the ENI allowance counters (`bw_in_allowance_exceeded` etc.) are AWS hypervisor-level throttles that only surface via `rte_eth_xstats` — there is no `rte_eth_stats` field for them. mTCP simply cannot observe these on AWS because its stats model predates xstats.
  - Spec/memory reference needed: `docs/references/ena-dpdk-readme.md` §8.2.2 (ENI limiter xstats), `feedback_observability_primitives_only.md`, `feedback_performance_first_flow_control.md`. Human to confirm the three citations are sufficient and flag whether the phase docs should explicitly call out the snapshot-vs-delta choice.

### FYI (informational — no action required)

- **I-1** — **WC BAR mapping verification has no mTCP analog at all.**
  - `grep -r -i 'pat_memtype\|write.combining\|prefetchable\|bar\|igb_uio wc_activate' third_party/mtcp/mtcp/src` returns zero hits. mTCP targets NIC families (Intel 82599 / X710, mlx4, mlx5) whose DPDK bring-up does not depend on WC mapping correctness. Our `wc_verify.rs` is a pure scope addition for AWS ENAv2 LLQ (upstream README §6.1 + §6.2.3 + §14 FAQ Q1). No action; the absence of mTCP precedent is itself the data point.

- **I-2** — **ENA xstats scraping has no mTCP analog.**
  - mTCP reads basic `rte_eth_stats` only; see AD-1. `grep rte_eth_xstats third_party/mtcp` → 0 hits. The full ENA xstats surface (ENI allowances + 28 per-queue counters per queue) is simply unreachable via mTCP's stats path. Our `ena_xstats.rs` covers 13 of these (5 allowance + 8 per-queue q0). No action.

- **I-3** — **`large_llq_hdr` / `miss_txc_to` devarg knobs have no mTCP analog.**
  - mTCP's application supplies EAL args verbatim from its config file; there is no devarg construction library and no PMD-specific knob table. Our `dpdk_net_recommended_ena_devargs` exists because the ABI crate's natural interface is "give me a string I can splice" rather than requiring the application to know ENA-specific devarg syntax. No action.

- **I-4** — **mTCP's bring-up hard-fails on PMD config errors; ours counter-bumps + continues (WC + overflow-risk) OR hard-fails (dev_info_get).**
  - mTCP: `dpdk_module.c:716-751` calls `rte_exit(EXIT_FAILURE, ...)` on any of {`rte_eth_dev_configure`, `rte_eth_rx_queue_setup`, `rte_eth_tx_queue_setup`, `rte_eth_dev_start`} failure. No soft-fallback, no observability-only path.
  - Ours: `Engine::new` hard-fails (returns `Err(Error::PortInfo)`) if `rte_eth_dev_info_get` fails (spec §4 step 1 — same posture as mTCP for this call). Every downstream observability signal in A-HW+ (WC miss, overflow-risk, xstats resolve failure) instead bumps a counter + eprintln + continues. This honors `feedback_performance_first_flow_control.md` ("counters over fail-hard") and matches the pattern already established by A-HW's `offload_missing_*` counters. No action.

- **I-5** — **mTCP has no equivalent of `shim_rte_eth_dev_prefetchable_bar_phys`.**
  - `grep -r 'RTE_DEV_TO_PCI\|mem_resource\|bus_pci_driver' third_party/mtcp` → 0 hits. mTCP's single PMD interaction path is the public `rte_ethdev` API. Our shim reaches into the DPDK driver-SDK headers (`bus_pci_driver.h` + `dev_driver.h`) to deref `struct rte_pci_device` and read `mem_resource[2].phys_addr`. The build-time detection + fail-open fallback (return 0 → WC verification quietly skips) is the right posture because driver-SDK headers are not shipped with `libdpdk-dev` packages on most distros. No action.

- **I-6** — **mTCP's stats call is hot-path-adjacent (inside `dpdk_send_pkts`); ours is explicitly application-driven.**
  - `dpdk_module.c:347` triggers the stats push from inside the TX burst send loop gated on `abs(mtcp->cur_ts - dpc->cur_ts) >= 1000`. This couples stats cadence to TX activity — an idle port will never push stats. Our `scrape_xstats` is a top-level public ABI call the application invokes on whatever cadence it chooses (typically a timer or epoll wake), decoupling stats from traffic. This matches `feedback_observability_primitives_only.md` (application owns cadence). No action.

- **I-7** — **Snapshot-vs-delta semantics: mTCP resets after every push; we do not.**
  - `dpdk_module.c:369` calls `rte_eth_stats_reset(portid)` after each `SEND_STATS` ioctl. Any read between two pushes sees a partial-interval counter. Our snapshot semantics (a failed scrape writes 0; a successful scrape writes the PMD's cumulative/reset-tolerant value) let the application detect "throttle has cleared" without the race. No action; this is part of AD-1's rationale but worth calling out as an observable semantic difference.

- **I-8** — **`EngineConfig` fields are append-only; the two new knobs hold at the tail.**
  - New fields `ena_large_llq_hdr` + `ena_miss_txc_to_sec` are appended at the end of both the core `EngineConfig` (lines 298-314) and the ABI `dpdk_net_engine_config_t`. No field reordering, so pre-A-HW+ C callers that memset the struct to zero get the default-0 values automatically. mTCP has no equivalent stability constraint because its config is a compile-time C struct supplied as a header. No action.

- **I-9** — **The counter mirror (EthCounters ↔ dpdk_net_eth_counters_t) pads shrunk to `[_ ; 2]` to preserve size.**
  - Both sides now carry 38 u64-equivalent fields (12 pre-A-HW + 11 A-HW + 15 A-HW+) → 304 B → `[_ ; 2]` pad → 320 B = 64 × 5, matching the core-side `#[repr(C, align(64))]`. The `size_of::<dpdk_net_eth_counters_t>() == size_of::<CoreEth>()` const assertion at `crates/dpdk-net/src/api.rs:423` is the authoritative mechanical check. mTCP has no such assertion because its counters are C structs in one process with no cross-crate ABI requirement. No action; recorded for forward reference when Stage 2 widens M3 to multi-queue and re-shrinks `_pad`.

- **I-10** — **13 (not 14) xstat names in `XSTAT_NAMES`; plan text and `EthCounters` field count are both 15 observability fields but the xstat-scrape slice is 13.**
  - `XSTAT_NAMES.len() == 13` = 5 ENI allowances + 4 tx_q0 + 4 rx_q0. The remaining 2 observability counters (`llq_wc_missing`, `llq_header_overflow_risk`) are written by the bring-up path (wc_verify + engine) rather than by the xstats scraper. The plan header calls the total "14 new fields" but the inline count comment already flags the correction to 15. The smoke test at `ena_obs_smoke.rs:30` explicitly asserts `XSTAT_NAMES.len() == 13`. Consistent and documented. No action.

## Verdict (draft)

**PASS-WITH-ACCEPTED**

A-HW+ is scope-additive against mTCP; there are no behavioral divergences to surface because mTCP has no analog for any of the five deliverables. One Accepted-divergence entry (AD-1, stats-exposure model) preserved so the human can sign off on the "xstats + snapshot semantics + no kernel ioctl" decision against mTCP's opposite model. Zero Must-fix, zero Missed-edge-cases.

Open checkbox count:
- Must-fix: 0 open
- Missed-edge-cases: 0 open
- Accepted-divergence (awaiting human spec/memory reference confirmation): 1 (AD-1)
- FYI: 10 items — informational only, no gate

Gate rule satisfied: no open `[ ]` in Must-fix or Missed-edge-cases. Phase may proceed to the `phase-a-hw-plus-complete` tag after the human confirms the AD-1 citations (ENA README §8.2.2, `feedback_observability_primitives_only.md`, `feedback_performance_first_flow_control.md`) are sufficient.
