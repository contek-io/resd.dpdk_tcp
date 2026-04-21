# Phase A-HW+ — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent
- Date: 2026-04-20
- RFCs in scope: 9293 (primary — TCP); Stage 1 matrix rows (791, 792, 1122, 1191, 7323, 2018, 5681, 6298, 6582, 6691, 3168, 8985, 6528, 5961, 7413) all verified transparent (observability-only phase)
- Our commit: 7c35aa8 (worktree `/home/ubuntu/resd.dpdk_tcp/.worktrees/phase-a-hw-ena-followups`, branch `phase-a-hw-ena-followups`)
- Base: `master` @ `eb01e79`
- Prior-phase review: `docs/superpowers/reviews/phase-a-hw-rfc-compliance.md` (2026-04-19, A-HW offload, PASS)

## Scope

- Our files reviewed:
  - `crates/dpdk-net-core/src/wc_verify.rs` (new — pure PAT parser + engine-bring-up verify helper; counter bump on miss)
  - `crates/dpdk-net-core/src/ena_xstats.rs` (new — ENA rte_eth_xstats name→id resolver + slow-path scraper; `store(Relaxed)` snapshot semantics)
  - `crates/dpdk-net-core/src/engine.rs` (modify — +`ena_large_llq_hdr`/`ena_miss_txc_to_sec` config fields, +M1 header-overflow WARN, +`xstat_map` state + `scrape_xstats()` slow path, +WC verify call at bring-up)
  - `crates/dpdk-net-core/src/counters.rs` (modify — +15 always-allocated slow-path `AtomicU64` fields on `EthCounters`, `_pad` shrunk to preserve 64-B multiple size)
  - `crates/dpdk-net-core/src/lib.rs` (modify — add `pub mod wc_verify;` and `pub mod ena_xstats;`)
  - `crates/dpdk-net-sys/shim.c` (modify — add `shim_rte_eth_dev_prefetchable_bar_phys(port_id)`; no wire-path shim touched)
  - `crates/dpdk-net-sys/wrapper.h` (modify — prototype declaration for the new shim)
  - `crates/dpdk-net-sys/build.rs` (modify — probe for DPDK driver-SDK headers; feature-flag-free, fail-safe to `0`)
  - `crates/dpdk-net/src/api.rs` (modify — mirror the 15 new counter fields onto `dpdk_net_eth_counters_t`, append `ena_large_llq_hdr` + `ena_miss_txc_to_sec` to `dpdk_net_engine_config_t`; compile-time struct-size assertion unchanged)
  - `crates/dpdk-net/src/lib.rs` (modify — add `dpdk_net_scrape_xstats()` + `dpdk_net_recommended_ena_devargs()` extern "C" entry points)
  - `include/dpdk_net.h` (regenerate — cbindgen emits the new symbols + fields)
  - `tests/ffi-test/tests/ffi_smoke.rs` (modify — mirror new EngineConfig fields)
  - `crates/dpdk-net-core/tests/knob-coverage.rs` (modify — +`ena_large_llq_hdr`, +`ena_miss_txc_to_sec`)
  - `crates/dpdk-net-core/tests/ahw_smoke_ena_hw.rs` (modify — add WC + xstats assertions on real ENA)
  - `crates/dpdk-net-core/tests/ena_obs_smoke.rs` (new — pure-unit smoke covering `wc_verify` + `ena_xstats`)
- Spec §6.3 rows verified: every row (791, 792, 1122, 1191, 9293, 7323, 2018, 5681, 6298, 6582, 6691, 3168, 8985, 6528, 5961, 7413). No matrix row claim changes in A-HW+. Wire-path code (`tcp_input.rs`, `tcp_output.rs`, `tcp_state.rs`, `tcp_conn.rs`, `tcp_retrans.rs`, `tcp_rack.rs`, `tcp_tlp.rs`, `tcp_options.rs`, `tcp_reassembly.rs`, `tcp_rtt.rs`, `l3_ip.rs`, `l2.rs`, `icmp.rs`, `arp.rs`, `flow_table.rs`) was not touched in this phase (verified by `grep` of the new symbol set across every wire-path file — zero hits).
- Spec §6.4 deviations touched: none. Parent §6.4 block and the A5.5-additions block are unchanged; no new deviation row introduced.

## Findings

### Must-fix (MUST/SHALL violation)

None.

The two RFC 9293 §3.1 checksum MUSTs that the prior A-HW phase put on the table remain satisfied, and A-HW+ does not alter either side:

- **RFC 9293 §3.1 MUST-2 (sender generates TCP checksum)** — `docs/rfcs/rfc9293.txt:407-413` and pseudo-header layout at `docs/rfcs/rfc9293.txt:425-448`. The TX-side code lives in `crates/dpdk-net-core/src/tcp_output.rs` (software full-fold path + offload pseudo-header finalizer) and is byte-for-byte unchanged from A-HW. A-HW+ touches no file under `tcp_output.rs`; `grep` on the new module/knob names returns zero hits there.
- **RFC 9293 §3.1 MUST-3 (receiver checks TCP checksum)** — `docs/rfcs/rfc9293.txt:1891-1898`. RX-side code in `crates/dpdk-net-core/src/tcp_input.rs` + `crates/dpdk-net-core/src/l3_ip.rs` + `crates/dpdk-net-core/src/engine.rs` hot path is unchanged on its classification branches (software verify + NIC-GOOD skip + NIC-BAD drop). A-HW+ additions to `engine.rs` sit in `EngineConfig`, `configure_port_offloads` bring-up (pre-hot-path), and a new slow-path `scrape_xstats()` method; no RX hot-path branch is modified.

Every other RFC clause the Stage 1 matrix claims (§6.3 rows 791, 792, 1122, 1191, 7323, 2018, 5681, 6298, 6582, 6691, 3168, 8985, 6528, 5961, 7413) is equally wire-transparent here: none of the wire-path source files under `crates/dpdk-net-core/src/` were modified in this phase.

### Missing SHOULD (not in §6.4 allowlist)

None. No new SHOULD clause is introduced or dropped by A-HW+. The existing §6.4 deviations (delayed-ACK off, Nagle off, minRTO=5ms, RTO max=1s, CC off-by-default, TFO disabled) and the A5.5-additions block (AD-A5-5-*, AD-A6-force-tw-skip) are untouched.

### Accepted deviation (covered by spec §6.4)

None new in A-HW+. The phase adds:
- Two `EngineConfig` bring-up knobs (`ena_large_llq_hdr`, `ena_miss_txc_to_sec`) that affect ENA PMD devarg emission, not TCP protocol behavior.
- Two extern "C" entry points (`dpdk_net_scrape_xstats`, `dpdk_net_recommended_ena_devargs`) that are observability / config helpers.
- Fifteen slow-path `AtomicU64` counter fields (H1 llq_wc_missing; M1 llq_header_overflow_risk; H2 five `eni_*_allowance_exceeded`; M3 eight per-queue tx_q0_* / rx_q0_*). All are scrape snapshots or one-shot bring-up bumps.
- Two bring-up slow-path helpers (`wc_verify::verify_wc_for_ena`, `ena_xstats::resolve_xstat_ids` + `scrape`).

None of these affect TCP on-the-wire behavior, so no existing §6.4 row needs to be reopened and no new row is required. The A-HW review's AD table stays carried-forward unchanged.

### FYI (informational — no action)

- **I-1**: **Wire-path files are not modified in this phase.** Grep of `wc_verify|ena_xstats|ena_large_llq_hdr|ena_miss_txc_to|llq_wc_missing|llq_header_overflow_risk|eni_.*_allowance|tx_q0_|rx_q0_` across every TCP/IP/ICMP/ARP source file under `crates/dpdk-net-core/src/` returns zero matches. The new modules and knobs are reached only from `engine.rs` (bring-up path pre-first-packet) and from the ABI crate (slow-path entry points). The hot-path RX/TX sites in `engine.rs` are not extended. Treated as the core evidence that RFC 9293 §3 (state machine), §4 (data transfer), §5 (closing), §3.10 (event processing / SEG.ACK rules), §3.8 (retransmissions / ACK generation / checksum failure), and RFC 7323 / 2018 / 5681 / 8985 clauses all remain in their A-HW state.

- **I-2**: **H1 `llq_wc_missing` counter is a slow-path one-shot bring-up observable, not a protocol element.** `crates/dpdk-net-core/src/wc_verify.rs:76-134` — `verify_wc_for_ena` runs once per port, early-returns for non-ENA drivers / non-Linux / non-x86_64 / when `bar_phys_addr==0` / when `/sys/kernel/debug/x86/pat_memtype_list` is unreadable. On a NON-write-combining mapping the function does `counters.eth.llq_wc_missing.fetch_add(1, Relaxed)` and `eprintln!`s a WARN; on a verified WC mapping it is silent. No wire-side behavior change: the Rust-side code never rejects packets, never fails engine bring-up, and never alters any RX/TX classification. This satisfies the "observability primitives only" and "performance-first flow control" principles from user memory without touching any RFC-normative text.

- **I-3**: **H2 ENI-allowance xstats are scrape-driven snapshots under `store(Relaxed)` semantics.** `crates/dpdk-net-core/src/ena_xstats.rs:68-89` — `XstatMap::apply` uses `slot.store(v, Ordering::Relaxed)` (not `fetch_add`) so each scrape overwrites the prior snapshot. The five names (`bw_in_allowance_exceeded`, `bw_out_allowance_exceeded`, `pps_allowance_exceeded`, `conntrack_allowance_exceeded`, `linklocal_allowance_exceeded`) are pulled from ENA PMD xstats; they reflect AWS VPC-layer rate-limiter events. The scraper is called only via `dpdk_net_scrape_xstats` (application-driven cadence, slow-path). No RFC-normative semantics are involved — RFC 9293 does not speak to VPC rate limiters. Failed-scrape policy at `ena_xstats.rs:148-170` writes zeros rather than preserving stale values, which is the correct reading for snapshot-semantics gauges ("we don't know right now" vs. "the last nonzero value is still current").

- **I-4**: **M3 per-queue xstats (queue 0 only — Stage 1 single queue) are `store(Relaxed)` snapshots via the same path as H2.** `crates/dpdk-net-core/src/ena_xstats.rs:20-37` lists eight per-queue names. `tx_q0_doorbells` is the only one that can reach nonzero on healthy traffic; the rest fire on driver-level anomalies that are RFC-out-of-scope (mempool pressure, TX-completion miss, bad req_id). None of these influence TCP segmentation, ACKing, or retransmission. Same transparency argument as I-3.

- **I-5**: **M1 `ena_large_llq_hdr` + M2 `ena_miss_txc_to_sec` are config knobs for PMD devarg emission.** `crates/dpdk-net-core/src/engine.rs:307-314` + `crates/dpdk-net/src/lib.rs:484-519`. The devarg string is built by the application (or via `dpdk_net_recommended_ena_devargs`) before `rte_eal_init`; the stack itself does not interpret the devarg value beyond conditionally emitting the bring-up `llq_header_overflow_risk` WARN when `ena_large_llq_hdr==0` on an ENA port (`engine.rs:986-1002`). The M1 header-overflow math is pinned via `WORST_CASE_HEADER = 14 + 20 + 20 + 40 = 94 B` which matches the worst case for our emitted frames (Ethernet 14 + IPv4 20 + TCP 20 + options up to 40 = RFC 9293 §3.1 figure 1 + RFC 7323 full-options ceiling). The assertion at `knob-coverage.rs:577-580` pins this invariant against future option-stack growth. No on-the-wire consequence.

- **I-6**: **`dpdk_net_recommended_ena_devargs` input validation is correct but irrelevant to RFC compliance.** `crates/dpdk-net/src/lib.rs:484-519` — rejects `miss_txc_to_sec > 60` with `-ERANGE`, null `bdf`/`out` with `-EINVAL`, insufficient `out_cap` with `-ENOSPC`. The `miss_txc_to=0` (omitted from devargs) vs. `miss_txc_to=N` emission policy documented at `engine.rs:308-314` correctly maps "use PMD default 5 s" vs. "explicit override" without introducing a path that DISABLES the watchdog (which ENA README §5.1 cautions against). None of this is RFC-normative.

- **I-7**: **Counter struct-size assertion still holds after the 15-field extension.** `crates/dpdk-net-core/src/counters.rs:287-291` (`align_of::<EthCounters>() == 64` + size is a 64-multiple) and `crates/dpdk-net/src/api.rs:418-426` (core-vs-ABI size equality for all four groups). The `_pad: [AtomicU64; 2]` at `counters.rs:110` brings the struct to 304 + 16 = 320 bytes (an exact 64-multiple) on both sides; the ABI mirror `_pad: [u64; 2]` at `api.rs:293` matches. No wire-visible effect, but this is the compile-time guarantee that the C ABI shape stays synchronized.

- **I-8**: **New ABI fields are appended at the end of their respective structs.** `dpdk_net_engine_config_t` adds `ena_large_llq_hdr` + `ena_miss_txc_to_sec` at the tail (`api.rs:59-66`); `dpdk_net_eth_counters_t` adds the 15 new counters between the A-HW additions and the `_pad` tail (`api.rs:274-293`). Consistent with the A-HW append-only ABI discipline called out in the prior review's metadata. No structural break for existing callers.

- **I-9**: **BAR2 access shim is fail-safe under build-time missing driver-SDK headers.** `crates/dpdk-net-sys/shim.c:171-192` — when `DPDK_HAS_PCI_SDK` is not defined (driver-SDK headers unavailable at shim build time), `shim_rte_eth_dev_prefetchable_bar_phys` returns `0` unconditionally; the Rust-side `verify_wc_for_ena` at `wc_verify.rs:92-99` then prints a "BAR address unavailable" skip message and early-returns. No wire-path consequence; the `llq_wc_missing` counter simply stays at 0 in that build configuration. Matches the "WARN-only, observability-only" contract for this gap.

- **I-10**: **Pure-unit tests in `tests/ena_obs_smoke.rs` validate the new modules without invoking EAL or the TCP wire path.** `crates/dpdk-net-core/tests/ena_obs_smoke.rs:1-62` — three tests cover `parse_pat_memtype_list` verdicts, `XstatMap::from_lookup` round-trip, and the "unadvertised name → None slot" branch. None of these reach into `tcp_input`, `tcp_output`, `l3_ip`, or any other wire-path module. Similarly, `crates/dpdk-net-core/tests/knob-coverage.rs:528-675` adds M1/M2 entries that assert on `EngineConfig` projection only (no wire-side state change).

- **I-11**: **No change to the ECN, SACK, RACK-TLP, or PAWS code paths.** RFC 3168 (ECN), RFC 2018 (SACK), RFC 8985 (RACK-TLP), RFC 7323 §5 (PAWS) source files (`tcp_input.rs`, `tcp_output.rs`, `tcp_sack.rs`, `tcp_rack.rs`, `tcp_tlp.rs`, `tcp_options.rs`, `tcp_reassembly.rs`) were not touched in this phase. The A5/A5.5/A6 RFC reviews' claims carry forward unchanged.

## Verdict (draft)

**PASS**

Rationale: A-HW+ is wire-protocol-transparent by construction. The diff introduces:
- Two new slow-path modules (`wc_verify.rs`, `ena_xstats.rs`) that never inspect, generate, or modify a TCP/IP/Ethernet frame.
- Fifteen always-allocated `AtomicU64` counter fields written only at engine bring-up (H1, M1) or via the application-driven `dpdk_net_scrape_xstats` slow path (H2, M3).
- Two `EngineConfig` knobs that affect the application's EAL devarg string, not the TCP stack's segment construction.
- Two extern "C" entry points (scrape + devarg-builder) with null/range input validation.
- One DPDK PCI-SDK shim (fail-safe) for BAR2 physical-address lookup.

No RFC 9293 §3/§4/§5 clause is reachable by the new code. The prior A-HW review's analysis of §3.1 MUST-2/MUST-3 remains the binding compliance evidence for TCP checksum generation and verification; nothing in A-HW+ alters that. Every Stage 1 RFC (791, 792, 1122, 1191, 9293, 7323, 2018, 5681, 6298, 6582, 6691, 3168, 8985, 6528, 5961, 7413) is untouched at the source level in this phase. No new `[ ]` items under Must-fix or Missing SHOULD; no new Accepted-deviation rows.

Gate rule: phase cannot tag `phase-a-hw-plus-complete` while any `[ ]` checkbox in Must-fix or Missing-SHOULD is open. Zero such checkboxes. Accepted-deviation section contains no new entries because A-HW+ introduces no new wire-protocol deviations.

**Open-checkbox count (blocking sections):** Must-fix = 0, Missing SHOULD = 0.
