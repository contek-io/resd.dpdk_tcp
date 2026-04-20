# Phase A-HW — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent
- Date: 2026-04-19
- mTCP submodule SHA: `f9e2d1d80a84f8aef9de2fcc3a3ce25bd7c9d3ae` (unchanged since prior phase reviews; `third_party/mtcp` not bumped this phase)
- Our commit: `467a8f2` (branch `phase-a-hw`, cleanup commit atop Task 19)
- Base tag: `phase-a5-5-complete` (commit `957e9e5`)

## Scope

A-HW flips DPDK port configuration from Phase A1's zeroed `rte_eth_conf` (plus A5's `MULTI_SEGS` bit) to Stage 1's production-shape offloads. Every enablement gated by a cargo feature flag (all default ON) and capability-checked against `rte_eth_dev_info_get`. LLQ activation is verified via PMD-log-scrape around `rte_eal_init`. TX checksum uses pseudo-header-only fold when offload latches true; software full-fold otherwise. RX classification consumes `mbuf.ol_flags` with CKSUM_GOOD / CKSUM_BAD / CKSUM_NONE / CKSUM_UNKNOWN distinct branches. RSS is wired with `RTE_ETH_MQ_RX_RSS` mq_mode, `NONFRAG_IPV4_TCP | NONFRAG_IPV6_TCP` rss_hf, and explicit reta-program to queue 0 for forward-compat. RX timestamp uses `rte_mbuf_dynfield_lookup` / `rte_mbuf_dynflag_lookup` at engine_create; always-inline `hw_rx_ts_ns` accessor; threaded through the two production RX-origin event sites.

Our files reviewed:
- `crates/resd-net-core/Cargo.toml` — six `hw-*` features + `hw-offloads-all` meta + default list.
- `crates/resd-net-core/src/dpdk_consts.rs` — DPDK 23.11 bit-position constants (pinned).
- `crates/resd-net-core/src/engine.rs` — `configure_port_offloads`, `program_rss_reta_single_queue`, `hw_rx_ts_ns` accessor, LLQ verify call site, ol_flags + rss_hash + ts read at RX boundary, TX finalizer call sites in `tx_tcp_frame` + retrans chain.
- `crates/resd-net-core/src/llq_verify.rs` — `fmemopen` / `rte_openlog_stream` log-capture scaffolding, marker scanners, process-global `OnceLock<LlqVerdict>`.
- `crates/resd-net-core/src/tcp_output.rs` — `tcp_pseudo_header_checksum`, `tx_offload_rewrite_cksums`, `tx_offload_finalize` (feature-on + feature-off twin).
- `crates/resd-net-core/src/l3_ip.rs` — `classify_ip_rx_cksum`, `classify_l4_rx_cksum`, `ip_decode_offload_aware`, `CksumOutcome` enum.
- `crates/resd-net-core/src/flow_table.rs` — `hash_bucket_for_lookup` (feature-on + feature-off twin), `lookup_by_hash` forward-compat wrapper.
- `crates/resd-net-core/src/counters.rs` — 11 new `AtomicU64` fields on `EthCounters` (always allocated regardless of feature flags, for C-ABI stability).
- `crates/resd-net/src/api.rs` — 11 `u64` fields mirrored into `resd_net_eth_counters_t`; `_pad` shrunk to match.

mTCP files referenced:
- `third_party/mtcp/mtcp/src/dpdk_module.c` — port config (`port_conf` at lines 110-156), `dpdk_load_module` (643-803), `dpdk_get_rptr` with RX checksum drop (517-548), `dpdk_dev_ioctl` with TX checksum ioctls (805-928).
- `third_party/mtcp/mtcp/src/tcp_out.c` — `SendTCPPacket` with `PKT_TX_TCPIP_CSUM` call + software-fallback fold (180-357).
- `third_party/mtcp/mtcp/src/ip_out.c` — `IPOutput` and `EthernetOutput` with `PKT_TX_TCPIP_CSUM_PEEK` (70-175).
- `third_party/mtcp/mtcp/src/ip_in.c` — `ProcessIPv4Packet` with `PKT_RX_IP_CSUM` ioctl + software fallback (15-62).
- `third_party/mtcp/mtcp/src/tcp_in.c` — RX L4 cksum path (`PKT_RX_TCP_CSUM` ioctl + software fallback, 1215-1241).
- `third_party/mtcp/mtcp/src/rss.c` — Toeplitz key + softrss fallback.
- `third_party/mtcp/mtcp/src/include/io_module.h` — `PKT_TX_*` / `PKT_RX_*` ioctl command constants.

Spec sections in scope: A-HW spec §§ 3 (feature-flag matrix), 4 (port-config flow), 5 (LLQ verification), 6 (TX cksum), 7 (RX cksum), 8 (RSS), 9 (MBUF_FAST_FREE), 10 (RX timestamp), 11 (counters); parent spec §§ 7.5, 8.1–8.5, 9.1.1, 9.2, 11.1, 11.3.

## Summary (for human reader)

Phase A-HW implements a capability-gated superset of what mTCP does for DPDK offloads. The shared "skeleton" matches: request offloads in `port_conf.offloads`, query `rte_eth_dev_info_get`, AND against `tx_offload_capa` / `rx_offload_capa`, use `mbuf.ol_flags` at wire time for per-packet protocol signaling. The deviations from mTCP are deliberate and line up with three orthogonal themes:
1. Spec-advisory correctness improvements (RX classification uses the full 4-state enum, not just BAD-drop; pseudo-header fold is always-inline pure; TX offload is capability-AND-latched before hot path).
2. Scope additions mTCP does not cover (AWS ENA LLQ verification; `rte_mbuf_dynfield`-based NIC timestamping; `MBUF_FAST_FREE`).
3. Scope subtractions mTCP has and we do not (TSO / LRO / multi-queue RSS steering — deferred to Stage 2 per parent spec §8.4 Tier 3 and §12).

No Must-fix or Missed-edge-case findings. Two Accepted-divergence entries (scope differences) and a small FYI set.

## Findings

### Must-fix (correctness divergence)

None.

### Missed edge cases (mTCP handles, we don't)

None.

Specifically examined and confirmed we either handle or have an explicit superior approach:
- Zero-queue / queue-0 reta update on single-queue — both mTCP (implicit because `num_cores > 0` always) and our `program_rss_reta_single_queue` handle it; we additionally handle `reta_size == 0` (silent skip) which mTCP doesn't face because its `rte_eth_dev_configure` hard-fails on dev_info zero-reta PMDs.
- `dev_info.driver_name == NULL` during LLQ verification — our `configure_port_offloads` null-checks `dev_info.driver_name` before dereferencing; mTCP does not but only because LLQ is not a concept mTCP has to handle.
- `rte_mbuf_dynfield_lookup` returns negative — we handle via `Option<i32>` + one-shot counter bump; mTCP has no analog because no NIC timestamp path exists.
- `RTE_MBUF_F_RX_IP_CKSUM_NONE` vs `_UNKNOWN` vs `_GOOD` distinct branching — we route `NONE`/`UNKNOWN` to software verify and only skip on `_GOOD`. mTCP's pattern (described in FYI I-1 below) is weaker but not broken on ENA because ENA stamps `_GOOD` in the advertise path. Still a correctness delta in our favor, not a missed case.

### Accepted divergence (intentional — draft for human review)

- **AD-1** — **TSO / LRO / multi-queue RSS steering enabled in mTCP, disabled in A-HW.**
  - mTCP: `dpdk_module.c:124-127` enables `DEV_RX_OFFLOAD_TCP_LRO` via `#ifdef ENABLELRO` (default-on in many mTCP configs). `dpdk_module.c:716` passes `CONFIG.num_cores` as both rx- and tx-queue count to `rte_eth_dev_configure`, with `ETH_MQ_RX_RSS` steering traffic across queues. `dpdk_module.c:142-146` sets `rss_hf = TCP | UDP | IP | L2_PAYLOAD` — a broader rss_hf than ours.
  - Ours: No TSO, no LRO, no GRO / GSO (parent §8.4 Tier 3). Single-queue (parent §12). `rss_hf = NONFRAG_IPV4_TCP | NONFRAG_IPV6_TCP` only (A-HW spec §8.1).
  - Suspected rationale: `feedback_trading_latency_defaults.md` + parent §8.4 — Stage 1's target deployment is AWS ENA on a single-core trading client; batching offloads (TSO, LRO) add latency for throughput that is not the workload. Multi-queue RSS steering is Stage 2 scope. Narrow `rss_hf` avoids steering non-trading-flow traffic (e.g. ARP, ICMP) through the hash path.
  - Spec/memory reference needed: parent spec §§ 8.4 (Tier 3), 12 (multi-queue) — already cited; human to confirm no additional rationale needed.

- **AD-2** — **RSS key: mTCP pins an all-`0x05` symmetric key; we use PMD default (`rss_key = NULL`).**
  - mTCP: `dpdk_module.c:648-659` hardcodes a 52-byte 0x05-fill key and installs it into `rss_conf.rss_key`. Comment at `rss.c:17-24` calls it "Keys for system testing" and the `rss.c:BuildKeyCache` helper reproduces the same key for software-softrss. This choice is symmetric — `Hash(src,sport,dst,dport) == Hash(dst,dport,src,sport)` — so bidirectional packets for the same flow land on the same core.
  - Ours: `engine.rs:920-921` sets `rss_key = NULL` and `rss_key_len = 0`, which tells the PMD to use its default Toeplitz key.
  - Suspected rationale: Single-queue Stage 1 doesn't care about symmetry (both directions hit the same queue regardless). Stage 2 multi-queue will need this decision revisited — if the trading app cares about symmetric TX/RX core pinning, we'll need to install a symmetric key. Spec §8 does not address key choice.
  - Spec/memory reference needed: A-HW spec §8.1 (currently silent on key choice); should be updated with a Stage 2 note + memory entry, OR the default is explicitly documented as "PMD default; review at Stage 2 multi-queue bring-up."

### FYI (informational — no action required)

- **I-1** — **RX checksum classification: our 4-state enum is strictly more correct than mTCP's 2-state pattern.**
  - mTCP's `dpdk_module.c:537` unconditionally drops packets with `PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD` at `dpdk_get_rptr` time, then `ip_in.c:29-32` calls `PKT_RX_IP_CSUM` ioctl which only checks the advertised capability (returns -1 if PMD doesn't advertise), triggering software verify. mTCP therefore does NOT distinguish `PKT_RX_IP_CKSUM_NONE` or `UNKNOWN` — it trusts "advertised" as a proxy for "NIC verified". If a PMD advertises capability but stamps `UNKNOWN` on a packet (e.g. malformed, fragmented, non-IPv4), mTCP silently skips software verify.
  - Ours: `l3_ip.rs:134-148` routes GOOD → skip, BAD → drop+count, NONE/UNKNOWN → software verify. Distinct branch per 2-bit code. Strictly more robust against PMDs that stamp mixed outcomes on a single burst.
  - Impact: no behavioral drift on real ENA (ENA always stamps a definite state on advertised packets). Defensive hardening for non-ENA test harnesses (`net_tap`, `net_vdev`) and Stage 2 non-ENA HW paths.

- **I-2** — **LLQ verification: scope addition, no mTCP analog.**
  - Amazon ENA's Low-Latency Queue mode is AWS-specific and has no DPDK-API-visible state post-start. mTCP was written in 2014 and targets Intel 82599 / X710 / mlx5 NICs — none of which have an LLQ equivalent. Our PMD-log-scrape in `llq_verify.rs` is a phase A-HW scope addition, not a divergence.
  - No action.

- **I-3** — **NIC hardware RX timestamping: scope addition, no mTCP analog.**
  - mTCP's only timestamp handling is TCP Timestamp Option (RFC 7323) at `tcp_in.c:112-134` and `tcp_util.c:48`. `Grep` confirms zero occurrences of `rte_mbuf_dynfield` / `rte_dynflag_rx_timestamp` / `PKT_RX_TIMESTAMP` across `third_party/mtcp/mtcp/src/`. Our `hw_rx_ts_ns` accessor and the `engine.rs:631-660` dynfield/dynflag lookup are scope additions for parent spec §7.5 + §9.2 `rx_hw_ts_ns` plumbing.
  - No action.

- **I-4** — **`MBUF_FAST_FREE`: scope addition, no mTCP analog.**
  - `Grep MBUF_FAST_FREE | mbuf_fast_free | ETH_TX_OFFLOAD_MBUF` across mTCP returns zero hits. mTCP predates the PMD API that added this optimization (pre-DPDK 18.05 era). Our A-HW enablement is a net-new bit.
  - No action.

- **I-5** — **Per-ioctl dispatch (mTCP) vs direct mbuf manipulation (us).**
  - mTCP abstracts DPDK offload calls behind `iom->dev_ioctl(ctx, nif, PKT_TX_*_CSUM, iph)` (`dpdk_module.c:805-928`) which sets `m->ol_flags`, `m->l2_len`, `m->l3_len`, `m->l4_len`, and writes `rte_ipv4_phdr_cksum` into the TCP cksum field. Our `tx_offload_finalize` (`tcp_output.rs:310-365`) does the same work inline through our own `resd_rte_mbuf_or_ol_flags` + `resd_rte_mbuf_set_tx_lens` shims (bindgen can't expose `rte_mbuf` directly because of packed anonymous unions) and a hand-rolled `tcp_pseudo_header_checksum` helper. Result on the wire is bit-identical for the default single-queue IPv4-TCP path.
  - mTCP uses `rte_ipv4_phdr_cksum` (DPDK helper) which reads `ol_flags` to pick proto (TCP/UDP/SCTP) and zero-fills `tot_len` for TSO. Ours is TCP-only by construction; that is consistent with our no-TSO, no-UDP-TX-in-Stage-1 scope.
  - No action.

- **I-6** — **mTCP passes `dev_info` to `rte_eth_dev_configure` without AND; we AND explicitly.**
  - mTCP `dpdk_module.c:716` invokes `rte_eth_dev_configure(portid, ..., &port_conf)` with the statically-constructed `port_conf.{rx,tx}mode.offloads` — it does NOT AND against `dev_info[portid].{tx,rx}_offload_capa` before the call. mTCP's line 708 masks `rss_hf` against `dev_info.flow_type_rss_offloads`, but that's RSS-only; the cksum offload bits stay unmasked. If the PMD rejects an unsupported offload, mTCP fails hard at bring-up.
  - Ours: `configure_port_offloads` explicitly ANDs each requested bit against the advertised cap, bumps a one-shot `offload_missing_*` counter on mismatch, and proceeds with the reduced set. This lets `net_tap` / `net_vdev` CI harnesses succeed without a separate build.
  - Impact: pure-improvement on ours. mTCP's hard-fail is fine for its deployment target (production NICs always advertise); ours is friendlier to CI and enables the feature-matrix builds in plan §13.

- **I-7** — **Pseudo-header `tcp_seg_len` bound check.**
  - `tcp_output.rs:224-227` includes a `debug_assert!(tcp_seg_len <= u16::MAX as u32)` at the pseudo-header-fold helper. mTCP's `rte_ipv4_phdr_cksum` has no such check but also does not enter TSO territory in our Stage 1 scope (so the bound is trivially satisfied). The debug_assert is a defensive guard against future TSO-enabling callers that might pass a > 64K value — recorded here for forward traceability, not a divergence.
  - No action.

- **I-8** — **RSS reta explicit-program in single-queue case.**
  - mTCP does not call `rte_eth_dev_rss_reta_update` explicitly; it relies on the PMD's default reta (which after `rte_eth_dev_start` on mTCP-configured multi-queue is populated by PMD). Our `program_rss_reta_single_queue` explicitly zero-programs every reta slot to queue 0. At single queue this is a no-op from a steering perspective but it exercises the API path and makes the Stage 2 multi-queue transition a config change, not a code change. A-HW spec §8.1 calls this out. Also note: our call is tolerant of `reta_size == 0` (silent skip) for `net_tap` / `net_vdev` compatibility.
  - No action.

- **I-9** — **Counter-snapshot layout vs mTCP's stats ioctl.**
  - mTCP ships `rte_eth_stats` via an ioctl to a custom kernel module (`dpdk_module.c:291-372`, `ENABLE_STATS_IOCTL`). Its counter surface is host-OS-side; no concept of per-offload miss counters. Our `EthCounters.offload_missing_*` are in-process atomics exposed via `resd_net_counters_snapshot_t`. Different model per project scope; not a divergence to reconcile. We added 11 fields; the `_pad` on `EthCounters` shrunk from 20 to 9 to preserve the cacheline layout + struct size. No C-ABI break.
  - No action.

## Verdict (draft)

**PASS-WITH-ACCEPTED**

Two Accepted-divergence entries (AD-1 TSO/LRO/multi-queue, AD-2 RSS key) both map to published spec + memory guidance (parent §8.4, `feedback_trading_latency_defaults.md`, Stage 2 multi-queue deferral in parent §12). Zero Must-fix, zero Missed-edge-cases, zero open checkboxes in blocking sections.

Open checkbox count:
- Must-fix: 0 open
- Missed-edge-cases: 0 open
- Accepted-divergence (awaiting human spec/memory reference confirmation): 2 (AD-1, AD-2)
- FYI: 9 items — informational only, no gate

Gate rule satisfied: no open `[ ]` in Must-fix or Missed-edge-cases; phase may proceed to tag after human confirms the AD entries have the correct spec/memory citations.
