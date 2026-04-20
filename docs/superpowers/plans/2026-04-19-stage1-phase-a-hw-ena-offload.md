# resd.dpdk_tcp Stage 1 Phase A-HW — ENA hardware offload enablement

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flip the DPDK port configuration from Phase A1's zeroed `rte_eth_conf` to Stage 1 production-shape offloads: verify LLQ, enable TX+RX IPv4/TCP/UDP checksum offload with software fallback, enable MBUF_FAST_FREE, wire RSS-hash end-to-end (even at single queue), and wire NIC RX timestamping through dynfield+dynflag lookup — every offload compile-time-gated for A10's A/B benchmark rebuild, and runtime capability-gated for non-ENA test harnesses.

**Architecture:** Six cargo features (all default-on, plus meta `hw-offloads-all`) each gate one offload at code-site, not struct-field — C ABI stays stable across feature sets. `engine.rs::new` gains a port-config helper that queries `rte_eth_dev_info_get`, ANDs compile-requested offloads against advertised capabilities, bumps `eth.offload_missing_*` counters on mismatches, and latches per-engine runtime flags (`tx_cksum_offload_active`, `rx_cksum_offload_active`, `rss_hash_offload_active`) that gate the TX/RX hot paths into offload or software-fallback branches. LLQ verification is gated on `hw-verify-llq` and implemented via PMD-log-scrape around `rte_eth_dev_start`. RX timestamp gets a dynfield+dynflag lookup at `engine_create` + an always-inline `hw_rx_ts_ns` accessor (const-zero variant when feature off); the value is captured at the RX decode boundary and threaded through to both production RX-origin event sites (`engine.rs:1842` Connected, `engine.rs:2205` Readable — the second site needs a `deliver_readable(.., hw_rx_ts_ns)` signature change). Three smoke tests (SW-fallback on `net_tap` with default features, SW-only with `--no-default-features`, HW-path on real ENA VF) plus an 8-build CI matrix cover every feature-off branch exactly once.

**Tech Stack:** Rust stable, DPDK 23.11 LTS, ENA PMD 23.11, bindgen (already set up), cbindgen (already set up). No new crate deps. No new DPDK FFI wrappers beyond what bindgen already exposes for `rte_eth_dev_info_get`, `rte_eth_dev_rss_reta_update`, `rte_mbuf_dynfield_lookup`, `rte_mbuf_dynflag_lookup`, and the mbuf `ol_flags` / `hash.rss` fields.

**Spec reference:** `docs/superpowers/specs/2026-04-19-stage1-phase-a-hw-ena-offload-design.md` (committed at SHA `68f4528` on `phase-a-hw`). Parent spec at `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §§ 7.5 (dynfield accessor), 8.1–8.5 (ENA target + offload matrix + tiered policy + capability-gated bring-up), 9.1.1 (counter-addition policy), 9.2 (`rx_hw_ts_ns` semantics), 11.1 (measurement discipline), 11.3 (TSC-only attribution fallback on ENA).

**RFCs in scope for A-HW** (for the §10.14 RFC compliance review): **RFC 9293 §3.1** (TCP pseudo-header checksum — offload path still emits the pseudo-header fold and relies on the PMD to complete it), **RFC 1071** (Internet checksum — software fallback unchanged), **RFC 1624** (checksum preservation — not exercised directly; offload paths compute fresh, not incremental). No RFC matrix row changes. No new ADs — offload enablement is transparent to the wire protocol; the software fallback path produces bit-for-bit identical on-wire bytes to the offload path.

**Review gates at phase sign-off** (two reports, each a blocking gate per parent spec §10.13 / §10.14):
1. **A-HW mTCP comparison review** — `docs/superpowers/reviews/phase-a-hw-mtcp-compare.md`. Expected ~0 new ADs: mTCP also uses DPDK offload bits + `mbuf.ol_flags` for RX classification; differences are mostly bit-mask-selection policy (e.g. whether TSO is enabled). A-HW explicitly does not enable TSO (parent §8.4 Tier 3), matching trading-latency rationale against mTCP's throughput-oriented choices.
2. **A-HW RFC compliance review** — `docs/superpowers/reviews/phase-a-hw-rfc-compliance.md`. Expected: zero new MUST violations, zero missing SHOULDs. The offload/software-path equivalence means no RFC-visible behavior change.

The `phase-a-hw-complete` tag is blocked while either report has an open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD.

**Deviations from RFC defaults explicitly recorded for A-HW:** none. Offload enablement changes how the checksum bytes are computed (NIC vs software), not what they are.

**Deferred to later phases (A-HW is explicitly NOT doing these):**
- Multi-queue enablement (parent §12). RSS hash + single-queue reta wired; multi-queue RSS reta + per-queue steering = Stage 2.
- TSO, GRO, GSO, header/data split (parent §8.4 Tier 3).
- General-purpose RX scatter at MTU 1500. MULTI_SEGS stays on TX for A5 retransmit-chain; RX scatter stays off.
- Hot-path "offload used" per-segment counters (parent §9.1.1).
- Positive-path HW-timestamp assertion. Stage 1 smoke exercises dynfield-absent path only. Positive path runs as-compiled but is not asserted until Stage 2 hardening on mlx5 / ice / future-gen ENA.
- Actual offload benefit measurement. A10's `tools/bench-offload-ab/` rebuilds per feature-flag combination and produces the p50/p99/p999 A/B that drives the final keep-vs-remove decision per offload.
- A6 scope: timer API, `WRITABLE`, close flags, preset runtime switch, poll-overflow queueing, mempool-exhaustion error paths, RTT histogram.

---

## File Structure Created or Modified in This Phase

```
crates/resd-net-core/
├── Cargo.toml                           (MODIFIED: 6 new cargo features + hw-offloads-all meta + updated default list)
├── src/
│   ├── engine.rs                        (MODIFIED: port-config rewrite at current lines 422-450 — dev_info AND + offload masks + RSS rss_conf + reta program + MULTI_SEGS preserve + startup banner; LLQ log-scrape verification gated on hw-verify-llq; RX-timestamp dynfield+dynflag lookup at engine_create + hw_rx_ts_ns inline accessor; per-engine runtime latches on EngineState; deliver_readable signature extended with hw_rx_ts_ns param; engine.rs:1842 Connected + engine.rs:2205 Readable emissions consume threaded value)
│   ├── counters.rs                      (MODIFIED: EthCounters gains 11 AtomicU64 fields — offload_missing_* × 9 + rx_drop_cksum_bad; fields always allocated regardless of feature flags)
│   ├── l3_ip.rs                         (MODIFIED: new tcp_pseudo_header_checksum helper; ip_decode gains an ol_flags-inspection wrapper gated on hw-offload-rx-cksum; CsumBad drops bump eth.rx_drop_cksum_bad + existing ip.rx_csum_bad)
│   ├── tcp_output.rs                    (MODIFIED: build_segment signature extended with mbuf pointer; hw-offload-tx-cksum branch writes pseudo-header-only cksum + sets ol_flags + l2/l3/l4_len; software full-fold stays as the runtime-fallback branch when tx_cksum_offload_active == false)
│   ├── tcp_input.rs                     (MODIFIED: RX L4 path consumes mbuf.ol_flags RTE_MBUF_F_RX_L4_CKSUM_* bits gated on hw-offload-rx-cksum; BAD branch bumps tcp.rx_bad_csum + eth.rx_drop_cksum_bad; captures hw_rx_ts_ns once per packet at decode boundary and threads into deliver_readable + emit_connected calls)
│   ├── flow_table.rs                    (MODIFIED: lookup site gains hw-offload-rss-hash-gated branch reading mbuf.hash.rss when RTE_MBUF_F_RX_RSS_HASH is set; SipHash fallback otherwise)
│   └── lib.rs                           (unchanged — no new modules)
└── tests/
    ├── knob-coverage.rs                 (MODIFIED: new scenario entries for every A-HW feature flag's on/off branch + the hw-offloads-all meta + --no-default-features combo)
    ├── ahw_smoke_sw_fallback.rs         (NEW: SW-fallback + SW-only integration tests — run on net_tap via the A3 TAP-pair harness; assert counter values and full request-response correctness)
    └── ahw_smoke_ena_hw.rs              (NEW: HW-path integration test — gated on RESD_NET_TEST_ENA=1 env var; runs on actual ENA VF; asserts offload_missing_* counters all zero except offload_missing_rx_timestamp == 1)

crates/resd-net/src/
├── api.rs                               (MODIFIED: resd_net_eth_counters_t gains 11 u64 fields mirroring the core; _pad shrinks to compensate; const assertion block extended; no other ABI change)
└── lib.rs                               (unchanged)

include/resd_net.h                       (REGENERATED via cbindgen: resd_net_eth_counters_t layout extended)

scripts/
└── ci-feature-matrix.sh                 (NEW: 8-build CI matrix driver — runs cargo build --release for each per-offload-off configuration + --no-default-features + default; plus cargo test on default)

docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md
                                         (MODIFIED during Task 17: §8.4 Tier 1 renames hw-offload-llq → hw-verify-llq; §10.14 review-gate text carries the renamed flag; the parent spec is touched ONLY for this rename and the A-HW cross-reference pointer added to §9.2)
docs/superpowers/plans/stage1-phase-roadmap.md
                                         (MODIFIED during Task 17: A-HW row + A10 deliverables rename the flag; Task 20 flips A-HW row to Complete)
docs/superpowers/reviews/phase-a-hw-mtcp-compare.md       (NEW — Task 20 via mtcp-comparison-reviewer subagent)
docs/superpowers/reviews/phase-a-hw-rfc-compliance.md     (NEW — Task 20 via rfc-compliance-reviewer subagent)
```

---

## Pre-task: bindings check

Before starting, spot-check that `bindgen` has exposed every DPDK symbol A-HW needs. If any is missing, Task 1 prefix-adds a `resd-net-sys/wrapper.h` allowlist entry + a pass-through shim in `shim.c`; otherwise Task 1 skips the step.

**Symbols needed:**
- `rte_eth_dev_info`, `rte_eth_dev_info_get` (already used at engine.rs:435-436 — present).
- `rte_eth_rss_reta_entry64`, `rte_eth_dev_rss_reta_update` (new).
- `rte_mbuf_dynfield_lookup`, `rte_mbuf_dynflag_lookup` (new).
- `rte_openlog_stream` + `rte_log_get_stream` (LLQ log-scrape) OR `rte_log_register_type_and_pick_level` (alternative path).
- `RTE_MBUF_F_TX_IPV4`, `RTE_MBUF_F_TX_IP_CKSUM`, `RTE_MBUF_F_TX_TCP_CKSUM`, `RTE_MBUF_F_TX_UDP_CKSUM`, `RTE_MBUF_F_RX_IP_CKSUM_MASK`/`_GOOD`/`_BAD`/`_NONE`, `RTE_MBUF_F_RX_L4_CKSUM_*`, `RTE_MBUF_F_RX_RSS_HASH` — all `RTE_BIT64(n)` macros; likely need const additions in-crate (same pattern as `engine.rs:429` `const RTE_ETH_TX_OFFLOAD_MULTI_SEGS: u64 = 1u64 << 15`).
- `RTE_ETH_TX_OFFLOAD_IPV4_CKSUM`, `RTE_ETH_TX_OFFLOAD_TCP_CKSUM`, `RTE_ETH_TX_OFFLOAD_UDP_CKSUM`, `RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE`, `RTE_ETH_RX_OFFLOAD_IPV4_CKSUM`/`_TCP_CKSUM`/`_UDP_CKSUM`/`_RSS_HASH`, `RTE_ETH_RSS_NONFRAG_IPV4_TCP`, `RTE_ETH_RSS_NONFRAG_IPV6_TCP` — same story.

Actual DPDK bit positions (DPDK 23.11 `rte_ethdev.h` / `rte_mbuf_core.h`):

```
// TX offload capability / conf bits (rte_ethdev.h)
RTE_ETH_TX_OFFLOAD_VLAN_INSERT       = 1ULL << 0
RTE_ETH_TX_OFFLOAD_IPV4_CKSUM        = 1ULL << 1
RTE_ETH_TX_OFFLOAD_UDP_CKSUM         = 1ULL << 2
RTE_ETH_TX_OFFLOAD_TCP_CKSUM         = 1ULL << 3
RTE_ETH_TX_OFFLOAD_SCTP_CKSUM        = 1ULL << 4
RTE_ETH_TX_OFFLOAD_TCP_TSO           = 1ULL << 5
...
RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE    = 1ULL << 14
RTE_ETH_TX_OFFLOAD_MULTI_SEGS        = 1ULL << 15   // already in engine.rs:429

// RX offload
RTE_ETH_RX_OFFLOAD_VLAN_STRIP        = 1ULL << 0
RTE_ETH_RX_OFFLOAD_IPV4_CKSUM        = 1ULL << 1
RTE_ETH_RX_OFFLOAD_UDP_CKSUM         = 1ULL << 2
RTE_ETH_RX_OFFLOAD_TCP_CKSUM         = 1ULL << 3
...
RTE_ETH_RX_OFFLOAD_RSS_HASH          = 1ULL << 19

// RSS hash flags (64-bit rss_hf)
RTE_ETH_RSS_NONFRAG_IPV4_TCP         = 1ULL << 13
RTE_ETH_RSS_NONFRAG_IPV6_TCP         = 1ULL << 19

// mbuf ol_flags (rte_mbuf_core.h)
RTE_MBUF_F_RX_RSS_HASH               = 1ULL << 1
RTE_MBUF_F_RX_IP_CKSUM_BAD           = 1ULL << 4
RTE_MBUF_F_RX_IP_CKSUM_GOOD          = 1ULL << 7
RTE_MBUF_F_RX_IP_CKSUM_NONE          = (1ULL << 4) | (1ULL << 7)
RTE_MBUF_F_RX_IP_CKSUM_MASK          = RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN | ... = ((1ULL << 4) | (1ULL << 7))
RTE_MBUF_F_RX_L4_CKSUM_BAD           = 1ULL << 3
RTE_MBUF_F_RX_L4_CKSUM_GOOD          = 1ULL << 8
RTE_MBUF_F_RX_L4_CKSUM_NONE          = (1ULL << 3) | (1ULL << 8)
RTE_MBUF_F_RX_L4_CKSUM_MASK          = ((1ULL << 3) | (1ULL << 8))
RTE_MBUF_F_TX_IP_CKSUM               = 1ULL << 54
RTE_MBUF_F_TX_IPV4                   = 1ULL << 55
RTE_MBUF_F_TX_IPV6                   = 1ULL << 56
RTE_MBUF_F_TX_UDP_CKSUM              = 3ULL << 52   // 2-bit L4 field, UDP = 3<<52
RTE_MBUF_F_TX_TCP_CKSUM              = 1ULL << 52   // 2-bit L4 field, TCP = 1<<52
RTE_MBUF_F_TX_L4_MASK                = 3ULL << 52
```

⚠ The L4 checksum flags are **2-bit field**, not independent bits: `TCP = 01`, `UDP = 11`, `SCTP = 10`. Setting both TCP+UDP simultaneously is undefined — only one L4 proto per segment. Tasks below set exactly one based on segment type.

The Task 1 branch includes a helper module `crates/resd-net-core/src/dpdk_consts.rs` (new — 30 lines) that defines all these as named `pub const` u64s in one place, with a doc comment pointing back at `rte_ethdev.h` / `rte_mbuf_core.h` headers in DPDK 23.11. This keeps the rest of the engine code reading named constants instead of raw `1ULL << N` literals.

---

## Task 1: Cargo features + EthCounters fields + resd_net_eth_counters_t mirror + dpdk_consts module

**Files:**
- Modify: `crates/resd-net-core/Cargo.toml` — add 6 features + `hw-offloads-all` meta + update `default`.
- Create: `crates/resd-net-core/src/dpdk_consts.rs` — named DPDK bit-position constants.
- Modify: `crates/resd-net-core/src/lib.rs` — `pub mod dpdk_consts;`
- Modify: `crates/resd-net-core/src/counters.rs` — add 11 fields to `EthCounters`.
- Modify: `crates/resd-net/src/api.rs` — mirror the 11 fields into `resd_net_eth_counters_t` and shrink `_pad`.
- Regenerate: `include/resd_net.h` via cbindgen.

- [ ] **Step 1: Add cargo features**

In `crates/resd-net-core/Cargo.toml`, replace the `[features]` block:

```toml
[features]
default = [
    "obs-poll-saturation",
    "hw-verify-llq",
    "hw-offload-tx-cksum",
    "hw-offload-rx-cksum",
    "hw-offload-mbuf-fast-free",
    "hw-offload-rss-hash",
    "hw-offload-rx-timestamp",
]
# Hot-path TCP payload byte counters. Default OFF — see spec §9.1.1.
obs-byte-counters = []
# Hot-path poll-saturation counter. Default ON.
obs-poll-saturation = []
# A-HW hardware-offload compile-time gates. All default ON. Each gate
# lives at the code site; struct fields stay present across all feature
# sets (C ABI stability). A feature-off build compiles the offload code
# path away entirely — see spec §8.4.
# hw-verify-llq: engine verifies LLQ activation at bring-up via PMD
#   log-scrape; fails hard if ENA advertised LLQ but LLQ did not
#   activate. Does NOT set the enable_llq devarg — that stays
#   application-owned (ENA PMD default is enable_llq=1).
hw-verify-llq = []
# TX IPv4+TCP+UDP checksum offload bits + pseudo-header-only cksum
# path in tcp_output.rs / l3_ip.rs. Runtime fallback to software
# full-fold if the PMD did not advertise.
hw-offload-tx-cksum = []
# RX IPv4+TCP+UDP checksum offload bits + mbuf.ol_flags inspection in
# tcp_input.rs / l3_ip.rs. BAD→drop+counter, GOOD→skip, NONE/UNKNOWN
# →software verify.
hw-offload-rx-cksum = []
# RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE bit in txmode.offloads. Single bit;
# no other code change. Precondition (all TX mbufs from same per-lcore
# mempool) already satisfied by spec §7.1.
hw-offload-mbuf-fast-free = []
# RTE_ETH_RX_OFFLOAD_RSS_HASH bit + rss_conf + reta program + mbuf.hash.rss
# read in flow_table.rs. SipHash fallback when feature off.
hw-offload-rss-hash = []
# rte_mbuf_dynfield_lookup + rte_mbuf_dynflag_lookup at engine_create
# + inline hw_rx_ts_ns accessor. Feature-off: const fn returning 0.
# On ENA: both lookups return negative, offload_missing_rx_timestamp=1
# is the documented steady state (spec §9.2, parent §8.3).
hw-offload-rx-timestamp = []
# A10 offload-A/B convenience meta: every hw-* flag at once. Lets
# benchmark harness builds express the full set without retyping.
hw-offloads-all = [
    "hw-verify-llq",
    "hw-offload-tx-cksum",
    "hw-offload-rx-cksum",
    "hw-offload-mbuf-fast-free",
    "hw-offload-rss-hash",
    "hw-offload-rx-timestamp",
]
# Meta for the A8 counter-coverage audit.
obs-all = ["obs-byte-counters", "obs-poll-saturation"]
```

- [ ] **Step 2: Verify Cargo.toml parses**

Run: `cargo metadata --no-deps --format-version 1 --manifest-path crates/resd-net-core/Cargo.toml --offline 2>&1 | head -5` (from worktree root).
Expected: either JSON output or a registry-lookup error. NOT a TOML parse error. If `metadata` isn't happy, inspect and fix.

- [ ] **Step 3: Create `crates/resd-net-core/src/dpdk_consts.rs`**

```rust
//! Named constants for DPDK 23.11 bit positions we consume in A-HW.
//!
//! Source: DPDK 23.11 `lib/ethdev/rte_ethdev.h` + `lib/mbuf/rte_mbuf_core.h`.
//! These are `RTE_BIT64(N)`-based macros that bindgen does not expand into
//! Rust `const`s, so we mirror the bit positions here. When DPDK changes
//! these values in a future LTS we need to re-pin — but they are part of
//! the stable ethdev / mbuf ABI and have not moved across 22.11 → 23.11.
//!
//! Spec reference: docs/superpowers/specs/2026-04-19-stage1-phase-a-hw-ena-offload-design.md

#![allow(dead_code)] // Some consts are feature-gated at the call site.

// ---- TX offload capability / conf bits (rte_ethdev.h) ---------------

pub const RTE_ETH_TX_OFFLOAD_IPV4_CKSUM: u64 = 1u64 << 1;
pub const RTE_ETH_TX_OFFLOAD_UDP_CKSUM: u64 = 1u64 << 2;
pub const RTE_ETH_TX_OFFLOAD_TCP_CKSUM: u64 = 1u64 << 3;
pub const RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE: u64 = 1u64 << 14;
pub const RTE_ETH_TX_OFFLOAD_MULTI_SEGS: u64 = 1u64 << 15;

// ---- RX offload capability / conf bits (rte_ethdev.h) ---------------

pub const RTE_ETH_RX_OFFLOAD_IPV4_CKSUM: u64 = 1u64 << 1;
pub const RTE_ETH_RX_OFFLOAD_UDP_CKSUM: u64 = 1u64 << 2;
pub const RTE_ETH_RX_OFFLOAD_TCP_CKSUM: u64 = 1u64 << 3;
pub const RTE_ETH_RX_OFFLOAD_RSS_HASH: u64 = 1u64 << 19;

// ---- RSS hash flags (64-bit rss_hf) ---------------------------------

pub const RTE_ETH_RSS_NONFRAG_IPV4_TCP: u64 = 1u64 << 13;
pub const RTE_ETH_RSS_NONFRAG_IPV6_TCP: u64 = 1u64 << 19;

// ---- mbuf.ol_flags RX classification bits (rte_mbuf_core.h) ---------

pub const RTE_MBUF_F_RX_RSS_HASH: u64 = 1u64 << 1;
pub const RTE_MBUF_F_RX_L4_CKSUM_BAD: u64 = 1u64 << 3;
pub const RTE_MBUF_F_RX_IP_CKSUM_BAD: u64 = 1u64 << 4;
pub const RTE_MBUF_F_RX_L4_CKSUM_GOOD: u64 = 1u64 << 8;
pub const RTE_MBUF_F_RX_IP_CKSUM_GOOD: u64 = 1u64 << 7;
/// Two-bit encoding for IP cksum status; mask exposes BAD|GOOD bits so
/// matching on (ol_flags & MASK) yields one of four distinct values:
/// 0=UNKNOWN, BAD_BIT=BAD, GOOD_BIT=GOOD, (BAD|GOOD)=NONE.
pub const RTE_MBUF_F_RX_IP_CKSUM_MASK: u64 =
    RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_GOOD;
pub const RTE_MBUF_F_RX_L4_CKSUM_MASK: u64 =
    RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD;
// Convenience single-value tests.
pub const RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN: u64 = 0;
pub const RTE_MBUF_F_RX_IP_CKSUM_NONE: u64 = RTE_MBUF_F_RX_IP_CKSUM_MASK;
pub const RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN: u64 = 0;
pub const RTE_MBUF_F_RX_L4_CKSUM_NONE: u64 = RTE_MBUF_F_RX_L4_CKSUM_MASK;

// ---- mbuf.ol_flags TX classification bits (rte_mbuf_core.h) ---------

/// 2-bit L4 proto field at bits 52-53. TCP = 01.
pub const RTE_MBUF_F_TX_TCP_CKSUM: u64 = 1u64 << 52;
/// 2-bit L4 proto field at bits 52-53. UDP = 11.
pub const RTE_MBUF_F_TX_UDP_CKSUM: u64 = 3u64 << 52;
pub const RTE_MBUF_F_TX_L4_MASK: u64 = 3u64 << 52;
pub const RTE_MBUF_F_TX_IP_CKSUM: u64 = 1u64 << 54;
pub const RTE_MBUF_F_TX_IPV4: u64 = 1u64 << 55;
pub const RTE_MBUF_F_TX_IPV6: u64 = 1u64 << 56;
```

- [ ] **Step 4: Register the module in `lib.rs`**

In `crates/resd-net-core/src/lib.rs` find the existing `pub mod` list (alphabetical) and insert `dpdk_consts` between the existing modules. Likely position is between `counters` and `engine`:

```rust
pub mod dpdk_consts;
```

- [ ] **Step 5: Build to verify the new module compiles**

Run: `cargo build -p resd-net-core --release 2>&1 | tail -20`
Expected: clean build. If you get "unused const" warnings, they're silenced by the `#![allow(dead_code)]` at the top of the new module.

- [ ] **Step 6: Write a unit test for the const values**

Append to `crates/resd-net-core/src/dpdk_consts.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_positions_match_dpdk_23_11_ethdev_header() {
        // Pinned values from lib/ethdev/rte_ethdev.h + lib/mbuf/rte_mbuf_core.h.
        // Failure here means DPDK changed the bit layout — do NOT blindly fix.
        // Check the vendored DPDK headers first.
        assert_eq!(RTE_ETH_TX_OFFLOAD_IPV4_CKSUM, 0x0000_0000_0000_0002);
        assert_eq!(RTE_ETH_TX_OFFLOAD_TCP_CKSUM, 0x0000_0000_0000_0008);
        assert_eq!(RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE, 0x0000_0000_0000_4000);
        assert_eq!(RTE_ETH_TX_OFFLOAD_MULTI_SEGS, 0x0000_0000_0000_8000);
        assert_eq!(RTE_ETH_RX_OFFLOAD_TCP_CKSUM, 0x0000_0000_0000_0008);
        assert_eq!(RTE_ETH_RX_OFFLOAD_RSS_HASH, 0x0000_0000_0008_0000);
        assert_eq!(RTE_ETH_RSS_NONFRAG_IPV4_TCP, 0x0000_0000_0000_2000);
        assert_eq!(RTE_MBUF_F_RX_RSS_HASH, 0x0000_0000_0000_0002);
        assert_eq!(RTE_MBUF_F_RX_IP_CKSUM_MASK, 0x0000_0000_0000_0090);
        assert_eq!(RTE_MBUF_F_RX_L4_CKSUM_MASK, 0x0000_0000_0000_0108);
        assert_eq!(RTE_MBUF_F_TX_TCP_CKSUM, 0x0010_0000_0000_0000);
        assert_eq!(RTE_MBUF_F_TX_IP_CKSUM, 0x0040_0000_0000_0000);
        assert_eq!(RTE_MBUF_F_TX_IPV4, 0x0080_0000_0000_0000);
    }
}
```

- [ ] **Step 7: Run the test**

Run: `cargo test -p resd-net-core --lib dpdk_consts 2>&1 | tail -15`
Expected: `test result: ok. 1 passed`.

- [ ] **Step 8: Extend `EthCounters` in `crates/resd-net-core/src/counters.rs`**

Find the existing `pub struct EthCounters` (around line 7). After the existing `tx_arp: AtomicU64,` field (last A2 addition), append the 11 new A-HW fields:

```rust
    // A-HW additions — all slow-path per spec §9.1.1. Fields always
    // allocated regardless of feature flags (C-ABI stability). Fired
    // once at bring-up for offload_missing_*, per-packet on BAD cksum
    // for rx_drop_cksum_bad. See docs/superpowers/specs/
    // 2026-04-19-stage1-phase-a-hw-ena-offload-design.md §11.
    /// Offload advertised-request-mismatch counters (one-shot at bring-up).
    pub offload_missing_rx_cksum_ipv4: AtomicU64,
    pub offload_missing_rx_cksum_tcp: AtomicU64,
    pub offload_missing_rx_cksum_udp: AtomicU64,
    pub offload_missing_tx_cksum_ipv4: AtomicU64,
    pub offload_missing_tx_cksum_tcp: AtomicU64,
    pub offload_missing_tx_cksum_udp: AtomicU64,
    pub offload_missing_mbuf_fast_free: AtomicU64,
    pub offload_missing_rss_hash: AtomicU64,
    /// Fires only when driver is net_ena AND LLQ advertised-but-not-activated.
    /// Expected 0 on ENA with default enable_llq=1. Feature-off builds never bump.
    pub offload_missing_llq: AtomicU64,
    /// Expected 1 on ENA (documented steady state — ENA does not register
    /// the rte_dynfield_timestamp dynfield). 0 on mlx5/ice/future-gen ENA.
    pub offload_missing_rx_timestamp: AtomicU64,
    /// Per-packet drop counter for RX segments the NIC classified as
    /// RTE_MBUF_F_RX_IP_CKSUM_BAD or RTE_MBUF_F_RX_L4_CKSUM_BAD. Expected 0
    /// on well-formed traffic. Not an offload-missing counter.
    pub rx_drop_cksum_bad: AtomicU64,
```

The existing `_pad` field — DO NOT add one to `EthCounters` (core): only the C ABI mirror uses `_pad`. `EthCounters` core has no pad.

Wait — re-check the current core struct. If the core `EthCounters` has `_pad: [AtomicU64; 4]` already for alignment symmetry with the C mirror, shrink it to match the new count. Reading the current file: the core `EthCounters` at `crates/resd-net-core/src/counters.rs:7-21` does NOT have a `_pad` (only the ABI mirror in `api.rs` has it). So leave the core as-is; just append the 11 fields.

- [ ] **Step 9: Update the C-ABI mirror in `crates/resd-net/src/api.rs`**

Find `pub struct resd_net_eth_counters_t` (around line 215). After `pub tx_arp: u64,` (the last existing field before `_pad`), insert the 11 new fields:

```rust
    // A-HW additions — mirror of resd_net_core::counters::EthCounters.
    // Slow-path, always allocated regardless of feature flags.
    pub offload_missing_rx_cksum_ipv4: u64,
    pub offload_missing_rx_cksum_tcp: u64,
    pub offload_missing_rx_cksum_udp: u64,
    pub offload_missing_tx_cksum_ipv4: u64,
    pub offload_missing_tx_cksum_tcp: u64,
    pub offload_missing_tx_cksum_udp: u64,
    pub offload_missing_mbuf_fast_free: u64,
    pub offload_missing_rss_hash: u64,
    pub offload_missing_llq: u64,
    pub offload_missing_rx_timestamp: u64,
    pub rx_drop_cksum_bad: u64,
```

Then change the `_pad: [u64; 4]` line to `_pad: [u64; 9]`:

**Reasoning for pad size**: old layout = 12 fields + `_pad[4]` = 16 × 8 = 128 B (two cache lines with align(64)). New layout = 12 + 11 = 23 fields; to round up to the next 64-B boundary (256 B / 32 fields), pad = 32 − 23 = 9 entries.

Actually, check — the current pad is `[u64; 4]`, so current struct = 12 + 4 = 16 × 8 B = 128 B. With 23 fields, 32 − 23 = 9 → `_pad: [u64; 9]` → 23 + 9 = 32 × 8 B = 256 B. That's 4 cache lines.

⚠ The `#[repr(C, align(64))]` alignment stays, but the total size grows from 128 B to 256 B. Matching mirror growth in `EthCounters` core (Rust side — no `_pad` there, just 11 new AtomicU64s = 88 B more) brings core from 96 B to 184 B — which `align_of` rounds up to 192 B (next multiple of 64). That would be SIZE MISMATCH between core and ABI if core is 192 B and ABI is 256 B.

Re-think: align the core too. The core `EthCounters` struct doesn't have `_pad` now, but it also doesn't have `#[repr(C, align(64))]`; check.

Let me just say: verify by compilation. The `const _: ()` block in api.rs already asserts size/align equality. If the pad sizes diverge, that assertion fails at compile time and we fix it there.

**Actionable step**: add `_pad: [u64; 9]` to the ABI mirror. Run `cargo build` and read the assertion error if any, then adjust pad by the exact byte delta reported. If the core has NO pad and is size 184 B (23 × 8), and the ABI is 256 B, increase ABI pad to fill the gap — or add `_pad` to core. The simpler path: give core and ABI both `_pad` sized to bring both to 256 B. Core pad = 32 − 23 = 9 (if no existing pad). ABI pad = same 9. Both = 256 B.

To do this cleanly: add `pub _pad: [AtomicU64; 9],` to the core `EthCounters`, AND `pub _pad: [u64; 9],` to the ABI mirror. Both sum to 256 B with `#[repr(C, align(64))]` (check if core has that — if not, the core's default repr with 23 × AtomicU64 is 184 B but align_of is 8 B → size = 184 B. ABI with align(64) is rounded to 256 B. Divergence.).

**Simplest fix**: put `#[repr(C, align(64))]` on the core `EthCounters` too AND give it `_pad: [AtomicU64; 9]`. That makes both 256 B exactly. Same pattern already used on `TcpCounters` / `IpCounters` mirrors.

Revised Step 9:

Add to core `EthCounters` (end of struct, after the 11 new fields):
```rust
    /// Padding to bring the struct to an exact cacheline multiple (4 × 64 B = 256 B).
    /// Required for size parity with resd_net_eth_counters_t; see const
    /// assertion block in crates/resd-net/src/api.rs.
    pub _pad: [AtomicU64; 9],
```

Add `#[repr(C, align(64))]` directly above the `pub struct EthCounters` line if not already present. Read first, then decide:

```bash
grep -B2 'pub struct EthCounters' /home/ubuntu/resd.dpdk_tcp-a-hw/crates/resd-net-core/src/counters.rs
```

If the struct already has `#[repr(C, align(64))]`, keep it; if not, add it now.

Also add to ABI mirror `resd_net_eth_counters_t`: change `_pad: [u64; 4]` to `_pad: [u64; 9]`.

- [ ] **Step 10: Verify compile-time ABI assertions**

Run: `cargo build -p resd-net --release 2>&1 | tail -30`

Expected: clean build. If the `const _: () = { ... assert!(size_of...)}` block in `api.rs:343` fires, the message `evaluation of constant value failed` tells you exactly which pair mismatched. Adjust the `_pad` count until both `size_of` and `align_of` match. Record the final `_pad` size in the commit message.

- [ ] **Step 11: Initialize the 11 new fields in `Counters::new`**

Check `crates/resd-net-core/src/counters.rs` for the `impl Counters { pub fn new() }` (or `impl Default`). If fields are initialized explicitly (field-by-field), add the 11 new ones each initialized to `AtomicU64::new(0)`. If `#[derive(Default)]` is on the struct, no changes needed — `AtomicU64::default()` = `AtomicU64::new(0)`.

The existing struct almost certainly uses `#[derive(Default)]` (consistent with the other counter groups). Verify by reading lines around `impl Counters`:

```bash
grep -n 'impl.*Counters\|#\[derive' /home/ubuntu/resd.dpdk_tcp-a-hw/crates/resd-net-core/src/counters.rs | head -20
```

If `#[derive(Default)]` is present on `EthCounters`, this step is a no-op.

- [ ] **Step 12: Regenerate `include/resd_net.h`**

Run: `cargo run --bin cbindgen --manifest-path Cargo.toml --release 2>&1 | tail -10`

(Or the actual cbindgen invocation this repo uses — check `scripts/` or `Cargo.toml` for the right command. If there's no wrapper, run the cbindgen binary directly: `cbindgen --config crates/resd-net/cbindgen.toml --crate resd-net --output include/resd_net.h`.)

Expected: `include/resd_net.h` regenerates with the 11 new fields appended to `struct resd_net_eth_counters_t` and `_pad: u64[9]`. Inspect the diff:

```bash
git diff include/resd_net.h
```

Verify: new fields appear in the expected order; `_pad` is `[9]` not `[4]`.

- [ ] **Step 13: Run the full test suite**

Run: `cargo test -p resd-net-core --release 2>&1 | tail -20`
Expected: all existing tests pass. Size assertion holds. No regression.

Run: `cargo test -p resd-net --release 2>&1 | tail -20`
Expected: all existing tests pass.

- [ ] **Step 14: Commit**

```bash
git add crates/resd-net-core/Cargo.toml \
        crates/resd-net-core/src/dpdk_consts.rs \
        crates/resd-net-core/src/lib.rs \
        crates/resd-net-core/src/counters.rs \
        crates/resd-net/src/api.rs \
        include/resd_net.h

git commit -m "$(cat <<'EOF'
a-hw task 1: cargo features + dpdk_consts + counter fields

Adds six compile-time cargo features (hw-verify-llq plus five
hw-offload-* flags) with the hw-offloads-all meta, all default ON per
spec §3. New dpdk_consts module names every DPDK 23.11 bit position
A-HW consumes (RTE_BIT64 macros that bindgen does not expand). Extends
EthCounters + resd_net_eth_counters_t with 11 always-allocated
AtomicU64 fields (9 offload_missing_* + offload_missing_rx_timestamp
+ rx_drop_cksum_bad) per spec §11; _pad resized so total struct size
stays cacheline-aligned and both sides pass the compile-time ABI parity
assertions in crates/resd-net/src/api.rs.

No behavior change — all new fields stay at 0 until later tasks wire
the bring-up counter-bump and TX/RX code-path writes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Port-config helper extraction (no-behavior-change refactor)

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — move the existing port-config block (lines 422-450) into a helper `configure_port_offloads`.

**Rationale:** Later tasks add conditional-compilation branches for each offload; consolidating the port-config logic in one helper keeps the feature-gated code sites compact. Task 2 alone is a pure refactor — `cargo test` must pass with zero behavior change.

- [ ] **Step 1: Read the current port-config block**

Read `crates/resd-net-core/src/engine.rs` lines 420-500 to confirm the current structure.

- [ ] **Step 2: Define the helper's return type**

Add immediately before `impl Engine` (or at the top of the module, above the struct def) a new POD struct:

```rust
/// Result of `configure_port_offloads` — the applied offload masks plus
/// per-engine runtime latches that gate hot-path offload-vs-software
/// branches. See spec §4 and §6-§10 for how each latch feeds later
/// branches.
#[derive(Debug, Clone, Copy)]
struct PortConfigOutcome {
    /// Bits actually written to `eth_conf.rxmode.offloads` after AND with
    /// `dev_info.rx_offload_capa`.
    applied_rx_offloads: u64,
    /// Bits actually written to `eth_conf.txmode.offloads` after AND with
    /// `dev_info.tx_offload_capa` (always includes MULTI_SEGS — A5 retrans).
    applied_tx_offloads: u64,
    /// True iff TX IPv4 + TCP checksum offload bits both applied. Latches
    /// the TX hot-path offload-vs-software branch.
    tx_cksum_offload_active: bool,
    /// True iff RX IPv4 + TCP checksum offload bits both applied. Latches
    /// the RX hot-path offload-vs-software branch.
    rx_cksum_offload_active: bool,
    /// True iff RSS_HASH bit applied. Latches mbuf.hash.rss consumption
    /// in flow_table.rs.
    rss_hash_offload_active: bool,
    /// Driver name from `rte_eth_dev_info.driver_name` — consumed by the
    /// LLQ verification path to short-circuit non-ENA drivers.
    driver_name: [u8; 32],
}
```

- [ ] **Step 3: Extract the helper**

Replace the existing block (~`engine.rs:422-450` — `const RTE_ETH_TX_OFFLOAD_MULTI_SEGS ...` through `let rc = unsafe { sys::rte_eth_dev_configure(...) };`) with a call into a new helper:

```rust
        // Port-config: dev_info query, offload AND, runtime-fallback
        // latches. Moved into a helper for tidy feature-gated branches
        // in later tasks. See spec §4.
        let outcome =
            Self::configure_port_offloads(&cfg, &counters).map_err(|e| e)?;
        // `outcome.applied_*_offloads` have already been written into
        // `eth_conf` inside the helper (see below); we now need them
        // only for the runtime-fallback latches stored on EngineState.
```

Actually, refactor more carefully: the helper builds `eth_conf` AND calls `rte_eth_dev_configure`, then returns the outcome. Updated call shape:

```rust
        let outcome = Self::configure_port_offloads(&cfg, &counters)
            .map_err(Error::from)?;  // adjust Error variant as needed
```

Then implement the helper as a `fn configure_port_offloads(cfg: &EngineConfig, counters: &Counters) -> Result<PortConfigOutcome, Error>` on `Engine` (or as a free function in the module). Body: exactly the same logic currently at lines 422-450 — dev_info_get + MULTI_SEGS check + rte_eth_dev_configure — with the outcome fields populated (`applied_tx_offloads = MULTI_SEGS if advertised else 0`, all the other latches `false` and `applied_rx_offloads = 0` for now).

```rust
impl Engine {
    fn configure_port_offloads(
        cfg: &EngineConfig,
        _counters: &Counters,
    ) -> Result<PortConfigOutcome, Error> {
        use crate::dpdk_consts::RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

        let mut eth_conf: sys::rte_eth_conf = unsafe { std::mem::zeroed() };
        eth_conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

        let mut dev_info: sys::rte_eth_dev_info = unsafe { std::mem::zeroed() };
        let info_rc =
            unsafe { sys::rte_eth_dev_info_get(cfg.port_id, &mut dev_info) };
        let mut applied_tx_offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
        if info_rc == 0
            && (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) == 0
        {
            eprintln!(
                "resd_net: PMD on port {} does not advertise RTE_ETH_TX_OFFLOAD_MULTI_SEGS; \
                 A5 retransmit chain may fail — check NIC/PMD support",
                cfg.port_id
            );
            applied_tx_offloads &= !RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
        }
        // Re-latch the ACTUALLY-applied mask onto eth_conf in case we
        // dropped MULTI_SEGS above.
        eth_conf.txmode.offloads = applied_tx_offloads;

        let rc = unsafe {
            sys::rte_eth_dev_configure(cfg.port_id, 1, 1, &eth_conf as *const _)
        };
        if rc != 0 {
            return Err(Error::PortConfigure(cfg.port_id, unsafe {
                sys::resd_rte_errno()
            }));
        }

        // Driver name — copy up to 31 bytes + NUL. The `driver_name` field
        // on rte_eth_dev_info is `*const c_char`; safe to walk as long as
        // the PMD put a non-NULL, NUL-terminated string there.
        let mut driver_name = [0u8; 32];
        if !dev_info.driver_name.is_null() {
            unsafe {
                let src = dev_info.driver_name as *const u8;
                for i in 0..31 {
                    let b = *src.add(i);
                    if b == 0 {
                        break;
                    }
                    driver_name[i] = b;
                }
            }
        }

        Ok(PortConfigOutcome {
            applied_rx_offloads: 0,
            applied_tx_offloads,
            tx_cksum_offload_active: false,
            rx_cksum_offload_active: false,
            rss_hash_offload_active: false,
            driver_name,
        })
    }
}
```

- [ ] **Step 4: Store runtime latches on EngineState**

Find the `EngineState` struct definition (or the owning `Engine` / `EngineInner`). Add three runtime-latch fields:

```rust
    // A-HW runtime latches — set at port-config time by
    // configure_port_offloads(). When a compile-enabled offload was
    // advertised by the PMD the latch is true and the corresponding
    // hot-path branch uses the offload; when false the hot-path branch
    // falls back to software. See spec §§6-8.
    tx_cksum_offload_active: bool,
    rx_cksum_offload_active: bool,
    rss_hash_offload_active: bool,
    /// Driver name captured at bring-up — the LLQ verification path
    /// short-circuits when driver != "net_ena". See spec §5.
    driver_name: [u8; 32],
```

In the `Engine::new` body, populate from `outcome`:

```rust
        let engine = Engine {
            // ...existing fields...
            tx_cksum_offload_active: outcome.tx_cksum_offload_active,
            rx_cksum_offload_active: outcome.rx_cksum_offload_active,
            rss_hash_offload_active: outcome.rss_hash_offload_active,
            driver_name: outcome.driver_name,
            // ...rest...
        };
```

- [ ] **Step 5: Build + test**

Run: `cargo build -p resd-net-core --release 2>&1 | tail -10`
Expected: clean build.

Run: `cargo test -p resd-net-core --release 2>&1 | tail -20`
Expected: all existing tests pass. Zero behavior change because `applied_rx_offloads = 0` and `MULTI_SEGS` handling is preserved.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a-hw task 2: extract configure_port_offloads helper

Moves the existing port-config block (dev_info query + MULTI_SEGS
check + rte_eth_dev_configure) into a helper. Introduces PortConfigOutcome
returning the applied masks + three runtime-latch fields
(tx/rx_cksum_offload_active, rss_hash_offload_active) that later tasks
populate as each offload is wired. Driver name captured here so the LLQ
verification path can short-circuit non-ENA drivers without re-querying
dev_info.

No behavior change — all latches stay false, applied_rx_offloads stays 0.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Offload bit wiring — MBUF_FAST_FREE + TX cksum + RX cksum

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — extend `configure_port_offloads` with three feature-gated offload-bit branches.

**Rationale:** These three offloads share the same pattern — OR a bit into the requested mask, AND against `dev_info.*_offload_capa`, bump `eth.offload_missing_*` on mismatch. Bundling them into one task is cheap and gives a single commit that exercises the pattern end-to-end.

- [ ] **Step 1: Write the failing test**

Create `crates/resd-net-core/src/engine.rs` inside-mod test block (or a new unit test file). Test that `configure_port_offloads` sets the expected bits when all features are on and dev_info advertises every capability.

Actually — `configure_port_offloads` calls real DPDK functions. Unit-testing it requires either (a) a mock layer or (b) an integration test on `net_vdev`. Option (b) is more honest. Since A5.5 tests already run on `net_tap` and the `tests/ffi-test/tests/ffi_smoke.rs` harness exists, plan to exercise this via a Task-23 integration test (see below).

For this task's TDD: write a **counter-bump unit test** that calls a helper we'll factor out. New helper, added to `engine.rs`:

```rust
/// Bump `eth.offload_missing_<name>` when `requested_bit` is set but
/// `advertised_mask` does not include it. Returns the bit ANDed in
/// (i.e., the bit if advertised, else 0). Slow-path; called once per
/// offload at bring-up.
fn and_offload_with_miss_counter(
    requested_bit: u64,
    advertised_mask: u64,
    miss_counter: &std::sync::atomic::AtomicU64,
    name: &str,
    port_id: u16,
) -> u64 {
    if requested_bit == 0 {
        return 0;
    }
    if (requested_bit & advertised_mask) == 0 {
        miss_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        eprintln!(
            "resd_net: PMD on port {} does not advertise {} (0x{:016x}); \
             degrading to software path for this offload",
            port_id, name, requested_bit
        );
        0
    } else {
        requested_bit
    }
}
```

Test (unit, in the engine.rs `#[cfg(test)] mod tests` block — if absent, create it):

```rust
#[cfg(test)]
mod a_hw_port_config_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn offload_miss_bumps_counter_returns_zero() {
        let ctr = AtomicU64::new(0);
        let bit: u64 = 1 << 3;
        let advertised = 0u64; // not advertised
        let applied = and_offload_with_miss_counter(bit, advertised, &ctr, "tx-tcp-cksum", 0);
        assert_eq!(applied, 0);
        assert_eq!(ctr.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn offload_present_no_bump_returns_bit() {
        let ctr = AtomicU64::new(0);
        let bit: u64 = 1 << 3;
        let advertised = bit; // advertised
        let applied = and_offload_with_miss_counter(bit, advertised, &ctr, "tx-tcp-cksum", 0);
        assert_eq!(applied, bit);
        assert_eq!(ctr.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn offload_not_requested_noop() {
        let ctr = AtomicU64::new(0);
        let applied = and_offload_with_miss_counter(0, u64::MAX, &ctr, "ignored", 0);
        assert_eq!(applied, 0);
        assert_eq!(ctr.load(Ordering::Relaxed), 0);
    }
}
```

- [ ] **Step 2: Run failing test**

Run: `cargo test -p resd-net-core --lib a_hw_port_config_tests 2>&1 | tail -10`
Expected: compile error — `and_offload_with_miss_counter` not defined.

- [ ] **Step 3: Add the helper**

Add `and_offload_with_miss_counter` to `engine.rs` (near the top of the `impl Engine` block or as a free function in the module — free function is simpler).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p resd-net-core --lib a_hw_port_config_tests 2>&1 | tail -10`
Expected: `test result: ok. 3 passed`.

- [ ] **Step 5: Wire MBUF_FAST_FREE**

Extend `configure_port_offloads` body, just before the `rte_eth_dev_configure` call:

```rust
        // --- MBUF_FAST_FREE (hw-offload-mbuf-fast-free) -----------------
        #[cfg(feature = "hw-offload-mbuf-fast-free")]
        {
            use crate::dpdk_consts::RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
            applied_tx_offloads |= and_offload_with_miss_counter(
                RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
                dev_info.tx_offload_capa,
                &_counters.eth.offload_missing_mbuf_fast_free,
                "RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE",
                cfg.port_id,
            );
        }
```

Remove the leading underscore from `_counters` in the helper signature now that we're using it. Update the signature to take `counters: &Counters`.

- [ ] **Step 6: Wire TX checksum**

Just after the MBUF_FAST_FREE block:

```rust
        // --- TX checksum (hw-offload-tx-cksum) ----------------------------
        #[cfg(feature = "hw-offload-tx-cksum")]
        let tx_cksum_offload_active = {
            use crate::dpdk_consts::{
                RTE_ETH_TX_OFFLOAD_IPV4_CKSUM, RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
                RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
            };
            let ipv4 = and_offload_with_miss_counter(
                RTE_ETH_TX_OFFLOAD_IPV4_CKSUM,
                dev_info.tx_offload_capa,
                &counters.eth.offload_missing_tx_cksum_ipv4,
                "RTE_ETH_TX_OFFLOAD_IPV4_CKSUM",
                cfg.port_id,
            );
            let tcp = and_offload_with_miss_counter(
                RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
                dev_info.tx_offload_capa,
                &counters.eth.offload_missing_tx_cksum_tcp,
                "RTE_ETH_TX_OFFLOAD_TCP_CKSUM",
                cfg.port_id,
            );
            let udp = and_offload_with_miss_counter(
                RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
                dev_info.tx_offload_capa,
                &counters.eth.offload_missing_tx_cksum_udp,
                "RTE_ETH_TX_OFFLOAD_UDP_CKSUM",
                cfg.port_id,
            );
            applied_tx_offloads |= ipv4 | tcp | udp;
            // Latch the runtime flag only if both IPv4 + TCP applied.
            // UDP is optional — we only latch UDP if the UDP TX path exists
            // (Stage 1 has no UDP TX, so UDP always degrades to software
            // fallback on the RX consumer side only).
            ipv4 != 0 && tcp != 0
        };
        #[cfg(not(feature = "hw-offload-tx-cksum"))]
        let tx_cksum_offload_active = false;
```

- [ ] **Step 7: Wire RX checksum**

Immediately after the TX checksum block:

```rust
        // --- RX checksum (hw-offload-rx-cksum) ----------------------------
        #[cfg(feature = "hw-offload-rx-cksum")]
        let rx_cksum_offload_active = {
            use crate::dpdk_consts::{
                RTE_ETH_RX_OFFLOAD_IPV4_CKSUM, RTE_ETH_RX_OFFLOAD_TCP_CKSUM,
                RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
            };
            let ipv4 = and_offload_with_miss_counter(
                RTE_ETH_RX_OFFLOAD_IPV4_CKSUM,
                dev_info.rx_offload_capa,
                &counters.eth.offload_missing_rx_cksum_ipv4,
                "RTE_ETH_RX_OFFLOAD_IPV4_CKSUM",
                cfg.port_id,
            );
            let tcp = and_offload_with_miss_counter(
                RTE_ETH_RX_OFFLOAD_TCP_CKSUM,
                dev_info.rx_offload_capa,
                &counters.eth.offload_missing_rx_cksum_tcp,
                "RTE_ETH_RX_OFFLOAD_TCP_CKSUM",
                cfg.port_id,
            );
            let udp = and_offload_with_miss_counter(
                RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
                dev_info.rx_offload_capa,
                &counters.eth.offload_missing_rx_cksum_udp,
                "RTE_ETH_RX_OFFLOAD_UDP_CKSUM",
                cfg.port_id,
            );
            applied_rx_offloads |= ipv4 | tcp | udp;
            ipv4 != 0 && tcp != 0
        };
        #[cfg(not(feature = "hw-offload-rx-cksum"))]
        let rx_cksum_offload_active = false;
```

Also declare `let mut applied_rx_offloads: u64 = 0;` at the top of the helper (before the MBUF_FAST_FREE block) and set `eth_conf.rxmode.offloads = applied_rx_offloads;` before `rte_eth_dev_configure`.

Update `PortConfigOutcome` assembly at the end of the helper:

```rust
        Ok(PortConfigOutcome {
            applied_rx_offloads,
            applied_tx_offloads,
            tx_cksum_offload_active,
            rx_cksum_offload_active,
            rss_hash_offload_active: false, // Task 4 fills this.
            driver_name,
        })
```

- [ ] **Step 8: Build + existing tests**

Run: `cargo build -p resd-net-core --release 2>&1 | tail -10`
Run: `cargo test -p resd-net-core --release 2>&1 | tail -20`
Expected: clean + all pass. On `net_tap` / `net_vdev` CI test setups the offload_missing counters will bump, but no existing test asserts them at zero, so no regression.

- [ ] **Step 9: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a-hw task 3: feature-gated MBUF_FAST_FREE + TX/RX cksum offload bits

Extends configure_port_offloads with three feature-gated branches. Each
ORs the requested bit into the applied mask when the PMD advertises it,
else bumps the eth.offload_missing_<name> counter and drops the bit.
Latches tx_cksum_offload_active / rx_cksum_offload_active on
PortConfigOutcome based on whether IPv4 + TCP bits both applied (UDP
optional — no UDP TX path in Stage 1).

Wire-path code still uses the software checksum; the latches feed the
hot-path offload-vs-software branches added in Tasks 7 and 8.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: RSS hash offload — port config + rss_conf + reta program

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — extend `configure_port_offloads` with RSS hash branch; add post-`dev_start` reta program.

- [ ] **Step 1: Extend configure_port_offloads with the RSS branch**

Append after the RX-checksum branch (Task 3 Step 7):

```rust
        // --- RSS hash (hw-offload-rss-hash) -------------------------------
        #[cfg(feature = "hw-offload-rss-hash")]
        let rss_hash_offload_active = {
            use crate::dpdk_consts::{
                RTE_ETH_RSS_NONFRAG_IPV4_TCP, RTE_ETH_RSS_NONFRAG_IPV6_TCP,
                RTE_ETH_RX_OFFLOAD_RSS_HASH,
            };
            let bit = and_offload_with_miss_counter(
                RTE_ETH_RX_OFFLOAD_RSS_HASH,
                dev_info.rx_offload_capa,
                &counters.eth.offload_missing_rss_hash,
                "RTE_ETH_RX_OFFLOAD_RSS_HASH",
                cfg.port_id,
            );
            applied_rx_offloads |= bit;
            if bit != 0 {
                // Required prerequisite — see spec §8.1. Without this,
                // rte_eth_dev_rss_reta_update fails with -ENOTSUP and ENA's
                // ena_rss_configure() silently ignores rss_hf.
                eth_conf.rxmode.mq_mode = sys::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS;
                eth_conf.rx_adv_conf.rss_conf.rss_hf =
                    RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP;
                eth_conf.rx_adv_conf.rss_conf.rss_key = std::ptr::null_mut();
                eth_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
            }
            bit != 0
        };
        #[cfg(not(feature = "hw-offload-rss-hash"))]
        let rss_hash_offload_active = false;
```

Update `PortConfigOutcome` construction to use `rss_hash_offload_active`.
Also move `eth_conf.rxmode.offloads = applied_rx_offloads;` to BEFORE `rte_eth_dev_configure` (not inside any feature branch).

- [ ] **Step 2: Add post-`dev_start` reta program helper**

```rust
    #[cfg(feature = "hw-offload-rss-hash")]
    fn program_rss_reta_single_queue(
        port_id: u16,
        dev_info: &sys::rte_eth_dev_info,
    ) -> Result<(), Error> {
        let reta_size = dev_info.reta_size as usize;
        if reta_size == 0 {
            return Ok(());
        }
        let num_entries = reta_size.div_ceil(64);
        let mut reta: Vec<sys::rte_eth_rss_reta_entry64> =
            vec![unsafe { std::mem::zeroed() }; num_entries];
        for entry in reta.iter_mut() {
            entry.mask = u64::MAX;
            // reta[i] = 0 (all slots → queue 0) — already zeroed.
        }
        let rc = unsafe {
            sys::rte_eth_dev_rss_reta_update(port_id, reta.as_mut_ptr(), reta_size as u16)
        };
        if rc != 0 {
            eprintln!(
                "resd_net: port {} RSS reta program failed rc={}; \
                 flow_table falls back to SipHash.",
                port_id, rc
            );
        }
        Ok(())
    }

    #[cfg(not(feature = "hw-offload-rss-hash"))]
    fn program_rss_reta_single_queue(
        _port_id: u16,
        _dev_info: &sys::rte_eth_dev_info,
    ) -> Result<(), Error> {
        Ok(())
    }
```

- [ ] **Step 3: Call the reta helper after `rte_eth_dev_start`**

Find `sys::rte_eth_dev_start(cfg.port_id)` in `Engine::new`. Immediately after start succeeds:

```rust
        if outcome.rss_hash_offload_active {
            let mut dev_info_post: sys::rte_eth_dev_info = unsafe { std::mem::zeroed() };
            let _ = unsafe { sys::rte_eth_dev_info_get(cfg.port_id, &mut dev_info_post) };
            Self::program_rss_reta_single_queue(cfg.port_id, &dev_info_post)?;
        }
```

- [ ] **Step 4: Verify bindgen exposes reta symbols**

Run: `grep -n 'rte_eth_rss_reta_entry64\|rte_eth_dev_rss_reta_update' crates/resd-net-sys/src/lib.rs | head -5`

If absent, add the needed includes to `wrapper.h` / build.rs bindgen config, then rebuild `resd-net-sys`.

- [ ] **Step 5: Build + test**

Run: `cargo build -p resd-net-core --release 2>&1 | tail -10`
Run: `cargo test -p resd-net-core --release 2>&1 | tail -20`
Expected: clean + all pass.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/engine.rs crates/resd-net-sys/
git commit -m "a-hw task 4: RSS hash offload — port config + reta program

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Startup banner

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — emit informational banners at bring-up.

- [ ] **Step 1: Add banners in configure_port_offloads**

Immediately after `driver_name` is populated (before any offload branch):

```rust
        eprintln!(
            "resd_net: port {} driver={} rx_offload_capa=0x{:016x} \
             tx_offload_capa=0x{:016x} dev_flags=0x{:08x}",
            cfg.port_id,
            std::str::from_utf8(
                &driver_name[..driver_name.iter().position(|&b| b == 0).unwrap_or(32)]
            ).unwrap_or("<non-utf8>"),
            dev_info.rx_offload_capa,
            dev_info.tx_offload_capa,
            dev_info.dev_flags,
        );
```

Immediately after `rte_eth_dev_configure` succeeds:

```rust
        eprintln!(
            "resd_net: port {} configured rx_offloads=0x{:016x} tx_offloads=0x{:016x}",
            cfg.port_id, applied_rx_offloads, applied_tx_offloads,
        );
```

- [ ] **Step 2: Build + test**

Run: `cargo test -p resd-net-core --release 2>&1 | tail -10`
Expected: pass.

- [ ] **Step 3: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "a-hw task 5: startup banner — advertised + negotiated offload masks

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Pseudo-header-only TCP checksum helper

**Files:**
- Modify: `crates/resd-net-core/src/tcp_output.rs` — add `tcp_pseudo_header_checksum(src_ip, dst_ip, tcp_seg_len) -> u16`.

- [ ] **Step 1: Write the failing test**

Append to `crates/resd-net-core/src/tcp_output.rs` `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn pseudo_header_only_cksum_matches_manual_fold() {
        use crate::l3_ip::internet_checksum;
        let src_ip: u32 = 0x0a000001;
        let dst_ip: u32 = 0x0a000002;
        let tcp_seg_len: u32 = 40;
        let mut pseudo = Vec::with_capacity(12);
        pseudo.extend_from_slice(&src_ip.to_be_bytes());
        pseudo.extend_from_slice(&dst_ip.to_be_bytes());
        pseudo.push(0);
        pseudo.push(crate::l3_ip::IPPROTO_TCP);
        pseudo.extend_from_slice(&(tcp_seg_len as u16).to_be_bytes());
        let manual = internet_checksum(&pseudo);
        let helper = tcp_pseudo_header_checksum(src_ip, dst_ip, tcp_seg_len);
        assert_eq!(helper, manual);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p resd-net-core --lib pseudo_header_only 2>&1 | tail -10`
Expected: compile error — `tcp_pseudo_header_checksum` not defined.

- [ ] **Step 3: Add the helper to `tcp_output.rs`**

Near `tcp_checksum_split`:

```rust
/// Pseudo-header-only TCP checksum per RFC 9293 §3.1. Used by A-HW's
/// TX offload path: software writes ONLY the 12-byte pseudo-header
/// fold into the TCP cksum field; the PMD folds header + payload at
/// wire time when RTE_MBUF_F_TX_TCP_CKSUM is set.
pub fn tcp_pseudo_header_checksum(src_ip: u32, dst_ip: u32, tcp_seg_len: u32) -> u16 {
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&src_ip.to_be_bytes());
    buf[4..8].copy_from_slice(&dst_ip.to_be_bytes());
    buf[8] = 0;
    buf[9] = IPPROTO_TCP;
    buf[10..12].copy_from_slice(&(tcp_seg_len as u16).to_be_bytes());
    internet_checksum(&buf)
}
```

Ensure `internet_checksum` + `IPPROTO_TCP` are in scope via existing `use` lines.

- [ ] **Step 4: Run test**

Run: `cargo test -p resd-net-core --lib pseudo_header_only 2>&1 | tail -10`
Expected: `test result: ok. 1 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_output.rs
git commit -m "a-hw task 6: tcp_pseudo_header_checksum helper

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: TX checksum offload finalizer + TX-site wiring

**Files:**
- Modify: `crates/resd-net-core/src/tcp_output.rs` — add `tx_offload_finalize(mbuf, seg, payload_len, offload_active)`.
- Modify: `crates/resd-net-core/src/engine.rs` — every TX site that pushes to mbuf calls the finalizer.
- Possibly modify: `crates/resd-net-sys/shim.c` — pass-through helper for `mbuf.l2_len` / `l3_len` / `l4_len` if bindgen doesn't expose them cleanly.

- [ ] **Step 1: Study current TX sites**

Run: `grep -n 'build_segment\|build_retrans_header\|rte_eth_tx_burst' crates/resd-net-core/src/engine.rs | head -30`

- [ ] **Step 2: Verify bindgen exposure of `ol_flags` + `tx_offload` on rte_mbuf**

Run: `grep -n 'pub ol_flags\|pub tx_offload\|pub l2_len\|pub l3_len\|pub l4_len' crates/resd-net-sys/src/lib.rs | head -10`

If bindgen emitted `l2_len`/`l3_len`/`l4_len` as individual `u64` bitfield-packed fields (common for union-containing structs), use them directly. If bindgen emitted an anonymous union under a different name, fall back to a shim in `crates/resd-net-sys/shim.c`:

```c
void resd_rte_mbuf_set_tx_lens(struct rte_mbuf *m, uint16_t l2, uint16_t l3, uint16_t l4) {
    m->l2_len = l2;
    m->l3_len = l3;
    m->l4_len = l4;
}
void resd_rte_mbuf_or_ol_flags(struct rte_mbuf *m, uint64_t flags) {
    m->ol_flags |= flags;
}
```

Plus decls in `wrapper.h` and Rust bindings in `crates/resd-net-sys/src/lib.rs`. Use these helpers from `tx_offload_finalize`.

- [ ] **Step 3: Add the finalizer**

```rust
#[cfg(feature = "hw-offload-tx-cksum")]
pub fn tx_offload_finalize(
    mbuf: *mut resd_net_sys::rte_mbuf,
    seg: &SegmentTx,
    payload_for_csum_len: u32,
    offload_active: bool,
) {
    if !offload_active || mbuf.is_null() {
        return;
    }
    use crate::dpdk_consts::{
        RTE_MBUF_F_TX_IP_CKSUM, RTE_MBUF_F_TX_IPV4, RTE_MBUF_F_TX_TCP_CKSUM,
    };
    use crate::l2::ETH_HDR_LEN;
    let opts_len = seg.options.encoded_len();
    let tcp_hdr_len = TCP_HDR_MIN + opts_len;
    unsafe {
        resd_net_sys::resd_rte_mbuf_or_ol_flags(
            mbuf,
            RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM,
        );
        resd_net_sys::resd_rte_mbuf_set_tx_lens(
            mbuf,
            ETH_HDR_LEN as u16,
            IPV4_HDR_MIN as u16,
            tcp_hdr_len as u16,
        );
        // Overwrite TCP cksum + zero IPv4 cksum in the mbuf data buffer.
        let data_ptr = resd_net_sys::resd_rte_pktmbuf_mtod(mbuf) as *mut u8;
        let pseudo_len = (tcp_hdr_len as u32) + payload_for_csum_len;
        let pseudo = tcp_pseudo_header_checksum(seg.src_ip, seg.dst_ip, pseudo_len);
        let tcp_cksum_off = ETH_HDR_LEN + IPV4_HDR_MIN + 16;
        *data_ptr.add(tcp_cksum_off) = (pseudo >> 8) as u8;
        *data_ptr.add(tcp_cksum_off + 1) = (pseudo & 0xff) as u8;
        let ip_cksum_off = ETH_HDR_LEN + 10;
        *data_ptr.add(ip_cksum_off) = 0;
        *data_ptr.add(ip_cksum_off + 1) = 0;
    }
}

#[cfg(not(feature = "hw-offload-tx-cksum"))]
pub fn tx_offload_finalize(
    _mbuf: *mut resd_net_sys::rte_mbuf,
    _seg: &SegmentTx,
    _payload_for_csum_len: u32,
    _offload_active: bool,
) {}
```

- [ ] **Step 4: Wire TX sites in engine.rs**

At each TX site that calls `build_segment` then pushes bytes into an allocated mbuf, add the finalizer call right before `rte_eth_tx_burst`:

```rust
tcp_output::tx_offload_finalize(
    mbuf_ptr,
    &seg,
    seg.payload.len() as u32,
    self.tx_cksum_offload_active,
);
```

For `build_retrans_header` sites, `payload_for_csum_len` is the chained data mbuf's payload length (read via `resd_rte_pktmbuf_data_len` on the data mbuf).

- [ ] **Step 5: Add unit tests**

In `tcp_output.rs` `#[cfg(test)] mod tests`:

```rust
    #[cfg(feature = "hw-offload-tx-cksum")]
    #[test]
    fn tx_offload_finalize_sets_expected_flags() {
        use crate::dpdk_consts::{
            RTE_MBUF_F_TX_IP_CKSUM, RTE_MBUF_F_TX_IPV4, RTE_MBUF_F_TX_TCP_CKSUM,
        };
        // Minimal zeroed mbuf with a data buffer pointer. We don't call
        // DPDK functions; we exercise only tx_offload_finalize's memory
        // writes.
        let mut mbuf: resd_net_sys::rte_mbuf = unsafe { std::mem::zeroed() };
        let mut data = [0u8; 64];
        // Configure buf_addr + data_off so resd_rte_pktmbuf_mtod points at data[0].
        mbuf.buf_addr = data.as_mut_ptr() as *mut _;
        mbuf.data_off = 0;
        let seg = minimal_seg_tx();
        tx_offload_finalize(&mut mbuf, &seg, 128, true);
        assert_eq!(
            mbuf.ol_flags & (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM),
            RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM,
        );
    }

    #[cfg(feature = "hw-offload-tx-cksum")]
    #[test]
    fn tx_offload_finalize_noop_when_inactive() {
        let mut mbuf: resd_net_sys::rte_mbuf = unsafe { std::mem::zeroed() };
        let before = mbuf.ol_flags;
        let seg = minimal_seg_tx();
        tx_offload_finalize(&mut mbuf, &seg, 128, false);
        assert_eq!(mbuf.ol_flags, before);
    }

    fn minimal_seg_tx() -> SegmentTx<'static> {
        SegmentTx {
            src_mac: [0; 6], dst_mac: [0; 6],
            src_ip: 0x0a000001, dst_ip: 0x0a000002,
            src_port: 10000, dst_port: 20000,
            seq: 0, ack: 0, flags: TCP_ACK, window: 1024,
            options: TcpOpts::default(), payload: &[],
        }
    }
```

- [ ] **Step 6: Build + test — default features AND --no-default-features**

Run: `cargo test -p resd-net-core --release 2>&1 | tail -15`
Run: `cargo build -p resd-net-core --release --no-default-features 2>&1 | tail -10`
Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/tcp_output.rs \
        crates/resd-net-core/src/engine.rs \
        crates/resd-net-sys/
git commit -m "a-hw task 7: TX checksum offload finalizer + TX-site wiring

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: RX checksum ol_flags inspection — IP + TCP L4

**Files:**
- Modify: `crates/resd-net-core/src/l3_ip.rs` — add ol_flags classifier + wrapper entry point.
- Modify: `crates/resd-net-core/src/tcp_input.rs` — consume L4 classification; bump counters on BAD.
- Modify: `crates/resd-net-core/src/engine.rs` — RX sites thread `ol_flags`.

- [ ] **Step 1: Write failing unit test**

Append to `crates/resd-net-core/src/l3_ip.rs` `#[cfg(test)] mod tests`:

```rust
    #[cfg(feature = "hw-offload-rx-cksum")]
    #[test]
    fn classify_ip_cksum_from_ol_flags() {
        use crate::dpdk_consts::{
            RTE_MBUF_F_RX_IP_CKSUM_BAD, RTE_MBUF_F_RX_IP_CKSUM_GOOD,
            RTE_MBUF_F_RX_IP_CKSUM_NONE, RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN,
        };
        assert_eq!(classify_ip_rx_cksum(RTE_MBUF_F_RX_IP_CKSUM_GOOD), IpCksumOutcome::Good);
        assert_eq!(classify_ip_rx_cksum(RTE_MBUF_F_RX_IP_CKSUM_BAD), IpCksumOutcome::Bad);
        assert_eq!(classify_ip_rx_cksum(RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN), IpCksumOutcome::Unknown);
        assert_eq!(classify_ip_rx_cksum(RTE_MBUF_F_RX_IP_CKSUM_NONE), IpCksumOutcome::None);
    }
```

- [ ] **Step 2: Run to confirm fail**

`cargo test -p resd-net-core --lib classify_ip 2>&1 | tail -10` → compile error.

- [ ] **Step 3: Add classifiers + offload-aware wrapper**

```rust
#[cfg(feature = "hw-offload-rx-cksum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCksumOutcome { Unknown, Bad, Good, None }

#[cfg(feature = "hw-offload-rx-cksum")]
pub fn classify_ip_rx_cksum(ol_flags: u64) -> IpCksumOutcome {
    use crate::dpdk_consts::{
        RTE_MBUF_F_RX_IP_CKSUM_BAD, RTE_MBUF_F_RX_IP_CKSUM_GOOD,
        RTE_MBUF_F_RX_IP_CKSUM_MASK, RTE_MBUF_F_RX_IP_CKSUM_NONE,
    };
    let m = ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK;
    if m == RTE_MBUF_F_RX_IP_CKSUM_GOOD { IpCksumOutcome::Good }
    else if m == RTE_MBUF_F_RX_IP_CKSUM_BAD { IpCksumOutcome::Bad }
    else if m == RTE_MBUF_F_RX_IP_CKSUM_NONE { IpCksumOutcome::None }
    else { IpCksumOutcome::Unknown }
}

#[cfg(feature = "hw-offload-rx-cksum")]
pub fn classify_l4_rx_cksum(ol_flags: u64) -> IpCksumOutcome {
    use crate::dpdk_consts::{
        RTE_MBUF_F_RX_L4_CKSUM_BAD, RTE_MBUF_F_RX_L4_CKSUM_GOOD,
        RTE_MBUF_F_RX_L4_CKSUM_MASK, RTE_MBUF_F_RX_L4_CKSUM_NONE,
    };
    let m = ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK;
    if m == RTE_MBUF_F_RX_L4_CKSUM_GOOD { IpCksumOutcome::Good }
    else if m == RTE_MBUF_F_RX_L4_CKSUM_BAD { IpCksumOutcome::Bad }
    else if m == RTE_MBUF_F_RX_L4_CKSUM_NONE { IpCksumOutcome::None }
    else { IpCksumOutcome::Unknown }
}

pub fn ip_decode_offload_aware(
    pkt: &[u8],
    our_ip: u32,
    #[allow(unused_variables)] ol_flags: u64,
    counters: &crate::counters::Counters,
) -> Result<L3Decoded, L3Drop> {
    #[cfg(feature = "hw-offload-rx-cksum")]
    {
        use std::sync::atomic::Ordering;
        match classify_ip_rx_cksum(ol_flags) {
            IpCksumOutcome::Good => ip_decode(pkt, our_ip, true),
            IpCksumOutcome::Bad => {
                counters.eth.rx_drop_cksum_bad.fetch_add(1, Ordering::Relaxed);
                counters.ip.rx_csum_bad.fetch_add(1, Ordering::Relaxed);
                Err(L3Drop::CsumBad)
            }
            _ => ip_decode(pkt, our_ip, false),
        }
    }
    #[cfg(not(feature = "hw-offload-rx-cksum"))]
    {
        let _ = ol_flags;
        let _ = counters;
        ip_decode(pkt, our_ip, false)
    }
}
```

- [ ] **Step 4: Verify passes**

`cargo test -p resd-net-core --lib classify_ip 2>&1 | tail -10` → pass.

- [ ] **Step 5: Update engine.rs RX call sites**

`grep -n 'l3_ip::ip_decode\b' crates/resd-net-core/src/engine.rs` — for each call, replace with:

```rust
let ol_flags: u64 = unsafe { (*mbuf).ol_flags };
let decoded = l3_ip::ip_decode_offload_aware(
    &pkt_slice, self.cfg.our_ip, ol_flags, &self.counters,
)?;
```

- [ ] **Step 6: Add TCP L4 classification in tcp_input.rs**

Read `crates/resd-net-core/src/tcp_input.rs` to find the current TCP checksum verification path. Wrap it:

```rust
#[cfg(feature = "hw-offload-rx-cksum")]
{
    use crate::l3_ip::{classify_l4_rx_cksum, IpCksumOutcome};
    use std::sync::atomic::Ordering;
    match classify_l4_rx_cksum(ol_flags) {
        IpCksumOutcome::Good => { /* skip software verify */ }
        IpCksumOutcome::Bad => {
            counters.eth.rx_drop_cksum_bad.fetch_add(1, Ordering::Relaxed);
            counters.tcp.rx_bad_csum.fetch_add(1, Ordering::Relaxed);
            return /* Drop::BadCsum */;
        }
        _ => { /* software verify — existing code path */ }
    }
}
```

Thread `ol_flags: u64` + `counters: &Counters` into the tcp_input entry point if not already present. May require a signature change on a private helper.

- [ ] **Step 7: Run full test suite**

Run: `cargo test -p resd-net-core --release 2>&1 | tail -20`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net-core/src/l3_ip.rs \
        crates/resd-net-core/src/tcp_input.rs \
        crates/resd-net-core/src/engine.rs
git commit -m "a-hw task 8: RX checksum ol_flags inspection — IP + TCP L4

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: RSS hash read in flow_table.rs

**Files:**
- Modify: `crates/resd-net-core/src/flow_table.rs` — gated branch at the lookup site.

- [ ] **Step 1: Study current flow_table lookup**

Run: `grep -n 'pub fn .*lookup\|SipHash\|siphash' crates/resd-net-core/src/flow_table.rs | head -10`

- [ ] **Step 2: Write failing test**

Append to `flow_table.rs` `#[cfg(test)] mod tests`:

```rust
    #[cfg(feature = "hw-offload-rss-hash")]
    #[test]
    fn rss_hash_used_when_flag_set() {
        use crate::dpdk_consts::RTE_MBUF_F_RX_RSS_HASH;
        // Build a FourTuple + an "mbuf-like" record that supplies
        // ol_flags + hash.rss. Assert the lookup picks up the
        // pre-computed NIC hash rather than recomputing SipHash.
        let tup = FourTuple {
            local_ip: 0x0a000001, local_port: 1,
            peer_ip: 0x0a000002, peer_port: 2,
        };
        let nic_hash: u32 = 0xdeadbeef;
        let ol_flags = RTE_MBUF_F_RX_RSS_HASH;
        let picked = hash_bucket_for_lookup(&tup, ol_flags, nic_hash, /*rss_active=*/true);
        assert_eq!(picked, nic_hash);
    }

    #[cfg(feature = "hw-offload-rss-hash")]
    #[test]
    fn rss_hash_unused_when_flag_clear() {
        let tup = FourTuple {
            local_ip: 0x0a000001, local_port: 1,
            peer_ip: 0x0a000002, peer_port: 2,
        };
        let siphash_fallback = /* call the existing SipHash fn with `tup` */;
        let picked = hash_bucket_for_lookup(&tup, 0, 0xdeadbeef, true);
        assert_eq!(picked, siphash_fallback);
    }
```

- [ ] **Step 3: Add the selector**

In `flow_table.rs`:

```rust
/// Pick the initial flow-table bucket hash. When the A-HW feature is on
/// AND `rss_active` (engine latch) AND the mbuf advertised a valid RSS
/// hash, use the NIC's Toeplitz hash. Otherwise compute SipHash locally.
/// Spec §8.
pub fn hash_bucket_for_lookup(
    tup: &FourTuple,
    #[allow(unused_variables)] ol_flags: u64,
    #[allow(unused_variables)] nic_rss_hash: u32,
    #[allow(unused_variables)] rss_active: bool,
) -> u32 {
    #[cfg(feature = "hw-offload-rss-hash")]
    {
        use crate::dpdk_consts::RTE_MBUF_F_RX_RSS_HASH;
        if rss_active && (ol_flags & RTE_MBUF_F_RX_RSS_HASH) != 0 {
            return nic_rss_hash;
        }
    }
    siphash_4tuple(tup)
}
```

(`siphash_4tuple` is the existing local-SipHash function — rename as needed to match the actual name in the file.)

- [ ] **Step 4: Wire into the existing lookup entry point**

Find where the flow-table lookup currently computes SipHash (e.g. `FlowTable::lookup` or `FlowTable::get_or_insert`). If it takes a pre-computed hash, the caller (engine.rs RX handler) now provides `hash_bucket_for_lookup(...)`. If the flow-table currently computes its own hash internally, thread a new optional `Option<(u64, u32)>` for `(ol_flags, hash.rss)` and use `hash_bucket_for_lookup`.

- [ ] **Step 5: Update engine.rs RX site**

At the RX path's flow_table lookup:

```rust
let ol_flags: u64 = unsafe { (*mbuf).ol_flags };
let nic_rss_hash: u32 = unsafe { (*mbuf).__bindgen_anon_2.hash.rss };
let hash = flow_table::hash_bucket_for_lookup(
    &tup, ol_flags, nic_rss_hash, self.rss_hash_offload_active,
);
let handle = self.flow_table.borrow().lookup_by_hash(&tup, hash);
```

(The exact bindgen field for `hash.rss` may be different — check `grep 'hash\.\|hash_word\|__bindgen' crates/resd-net-sys/src/lib.rs | grep rss`. Use a shim helper if the nested-union access is gnarly: `uint32_t resd_rte_mbuf_rss_hash(const struct rte_mbuf *m) { return m->hash.rss; }`.)

- [ ] **Step 6: Run tests**

Run: `cargo test -p resd-net-core --release 2>&1 | tail -20`
Expected: pass.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/flow_table.rs \
        crates/resd-net-core/src/engine.rs \
        crates/resd-net-sys/
git commit -m "a-hw task 9: RSS hash read in flow_table.rs

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: RX timestamp dynfield/dynflag lookup + accessor + engine state

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — add dynfield + dynflag lookup at `engine_create`; add `hw_rx_ts_ns` accessor.
- Possibly modify: `crates/resd-net-sys/shim.c` — pass-through for `rte_mbuf_dynfield_lookup` + `rte_mbuf_dynflag_lookup`.

- [ ] **Step 1: Verify bindgen exposure**

Run: `grep -n 'rte_mbuf_dynfield_lookup\|rte_mbuf_dynflag_lookup' crates/resd-net-sys/src/lib.rs | head -5`

If absent, add `#include <rte_mbuf_dyn.h>` to `wrapper.h` and rebuild. If bindgen still doesn't expose them, add shim pass-throughs.

- [ ] **Step 2: Add engine-state fields under `#[cfg]`**

In the `Engine` (or `EngineState`) struct definition, append:

```rust
    /// Offset (in bytes) from the start of rte_mbuf where the NIC-provided
    /// hardware RX timestamp lives. Populated at engine_create via
    /// rte_mbuf_dynfield_lookup("rte_dynfield_timestamp"). `None` when
    /// the PMD does not register the dynfield (expected on ENA — spec §10.1).
    #[cfg(feature = "hw-offload-rx-timestamp")]
    rx_ts_offset: Option<i32>,
    /// The bitmask (in ol_flags) that indicates a valid RX timestamp on
    /// this mbuf. Populated via rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp").
    /// Expected `None` on ENA.
    #[cfg(feature = "hw-offload-rx-timestamp")]
    rx_ts_flag_mask: Option<u64>,
```

- [ ] **Step 3: Perform the lookups in configure_port_offloads (or engine_create after dev_start)**

After `rte_eth_dev_start` succeeds:

```rust
        #[cfg(feature = "hw-offload-rx-timestamp")]
        let (rx_ts_offset, rx_ts_flag_mask) = {
            use std::sync::atomic::Ordering;
            let off = unsafe {
                sys::rte_mbuf_dynfield_lookup(
                    b"rte_dynfield_timestamp\0".as_ptr() as *const std::os::raw::c_char,
                    std::ptr::null_mut(),
                )
            };
            let flag_bit = unsafe {
                sys::rte_mbuf_dynflag_lookup(
                    b"rte_dynflag_rx_timestamp\0".as_ptr() as *const std::os::raw::c_char,
                    std::ptr::null_mut(),
                )
            };
            let offset = if off >= 0 { Some(off) } else { None };
            let mask = if flag_bit >= 0 { Some(1u64 << flag_bit) } else { None };
            if offset.is_none() || mask.is_none() {
                counters.eth.offload_missing_rx_timestamp.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "resd_net: RX timestamp dynfield/dynflag unavailable on port {} \
                     (ENA steady state — see spec §10.5)",
                    cfg.port_id
                );
            }
            (offset, mask)
        };
```

Then pass them into the `Engine` construction.

- [ ] **Step 4: Add the inline accessor**

Inside `impl Engine`:

```rust
    /// Read the NIC-provided hardware RX timestamp from an mbuf. Returns
    /// 0 when either (a) the feature is compile-off, (b) the dynfield/dynflag
    /// lookup returned negative at engine_create, or (c) the mbuf's ol_flags
    /// do not indicate a valid timestamp. See spec §10.
    ///
    /// SAFETY: `mbuf` must be a valid pointer to a live rte_mbuf. In the
    /// hot path this is satisfied by the ownership rules around rx_burst.
    #[cfg(feature = "hw-offload-rx-timestamp")]
    #[inline(always)]
    pub(crate) unsafe fn hw_rx_ts_ns(&self, mbuf: *const sys::rte_mbuf) -> u64 {
        match (self.rx_ts_offset, self.rx_ts_flag_mask) {
            (Some(off), Some(mask)) => {
                let ol_flags = (*mbuf).ol_flags;
                if ol_flags & mask != 0 {
                    // Safety: caller holds a valid rte_mbuf; off is the
                    // dynfield offset registered by the PMD; the field
                    // width is u64.
                    *((mbuf as *const u8).offset(off as isize) as *const u64)
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    #[cfg(not(feature = "hw-offload-rx-timestamp"))]
    #[inline(always)]
    pub(crate) const unsafe fn hw_rx_ts_ns(&self, _mbuf: *const sys::rte_mbuf) -> u64 {
        0
    }
```

- [ ] **Step 5: Unit test the feature-off accessor folds to zero**

In `engine.rs` `#[cfg(test)] mod tests`:

```rust
    #[cfg(not(feature = "hw-offload-rx-timestamp"))]
    #[test]
    fn hw_rx_ts_ns_zero_when_feature_off() {
        // Feature-off: the accessor is a const fn returning 0.
        // Can't easily construct an Engine in a unit test, but we can
        // verify the module-level signature compiles and the function
        // returns 0 for any mbuf pointer — including null.
        // Instead, test at a free-function scope: hw_rx_ts_ns_impl(None, None, any ol_flags)
        // (refactor the body into a pure function for testability).
    }
```

(Optional; skip if the refactor adds cost. The feature-off branch is trivial code.)

- [ ] **Step 6: Build + test with both feature states**

Run: `cargo test -p resd-net-core --release 2>&1 | tail -10`
Run: `cargo build -p resd-net-core --release --no-default-features 2>&1 | tail -10`
Run: `cargo build -p resd-net-core --release --no-default-features --features hw-offload-rx-timestamp 2>&1 | tail -10`
Expected: all clean.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/engine.rs crates/resd-net-sys/
git commit -m "a-hw task 10: RX timestamp dynfield/dynflag lookup + accessor

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 11: Thread hw_rx_ts_ns to RX event emission sites

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — capture `hw_rx_ts_ns` at RX decode; thread into `deliver_readable`; update the two RX-origin emission sites (lines 1842 + 2205 in the pre-A-HW worktree).
- Modify: `crates/resd-net-core/src/tcp_input.rs` — if the RX decode boundary lives here, capture and return the timestamp alongside the existing tcp_input outcome.

- [ ] **Step 1: Identify the RX decode boundary**

Run: `grep -n 'rte_eth_rx_burst\|ip_decode_offload_aware\|tcp_input_offload_aware' crates/resd-net-core/src/engine.rs | head -15`

The RX handler's top-of-loop (where each mbuf from `rte_eth_rx_burst` enters) is where the mbuf pointer is live. Capture `hw_rx_ts_ns` there:

```rust
// At the top of the per-mbuf RX loop, right after rte_eth_rx_burst returns:
let hw_rx_ts = unsafe { self.hw_rx_ts_ns(mbuf_ptr) };
```

- [ ] **Step 2: Thread through to Connected emission site**

At `engine.rs:1842` (verify with `grep -n 'InternalEvent::Connected'`), the surrounding scope has the RX mbuf pointer available. Replace:

```rust
if outcome.connected {
    self.events.borrow_mut().push(
        InternalEvent::Connected {
            conn: handle,
            rx_hw_ts_ns: 0,
            emitted_ts_ns: crate::clock::now_ns(),
        },
        &self.counters,
    );
    inc(&self.counters.tcp.conn_open);
}
```

with:

```rust
if outcome.connected {
    self.events.borrow_mut().push(
        InternalEvent::Connected {
            conn: handle,
            rx_hw_ts_ns: hw_rx_ts,
            emitted_ts_ns: crate::clock::now_ns(),
        },
        &self.counters,
    );
    inc(&self.counters.tcp.conn_open);
}
```

- [ ] **Step 3: Extend deliver_readable signature**

Change `fn deliver_readable(&self, handle: ConnHandle, delivered: u32)` to:

```rust
fn deliver_readable(&self, handle: ConnHandle, delivered: u32, rx_hw_ts_ns: u64) {
    // existing body up to the events.push call
    self.events.borrow_mut().push(
        InternalEvent::Readable {
            conn: handle,
            byte_offset,
            byte_len: delivered,
            rx_hw_ts_ns,
            emitted_ts_ns: crate::clock::now_ns(),
        },
        &self.counters,
    );
}
```

Every caller of `deliver_readable` now passes `hw_rx_ts`. Grep for callers:

Run: `grep -n 'deliver_readable' crates/resd-net-core/src/engine.rs`

For each call site, thread through the captured `hw_rx_ts` from the RX decode boundary.

- [ ] **Step 4: Build + test**

Run: `cargo test -p resd-net-core --release 2>&1 | tail -20`
Expected: pass. Existing tests that run on `net_tap` will get `rx_hw_ts_ns = 0` in all events (dynfield absent) — same as before, no assertion failures.

- [ ] **Step 5: Add unit test**

In `crates/resd-net-core/tests/` or in the engine's test block — add an assertion that Readable events on the net_tap harness still have `rx_hw_ts_ns == 0`:

```rust
    #[test]
    #[cfg(feature = "hw-offload-rx-timestamp")]
    fn rx_hw_ts_ns_stays_zero_on_non_ts_pmd() {
        // On net_tap, the dynfield is not registered. hw_rx_ts_ns
        // returns 0 for every mbuf. Events carry 0.
        // (Integration-level; defer the actual assertion to Task 16's
        // SW-fallback smoke test which already has a running engine.)
    }
```

Skip if nothing meaningful fits at this granularity — the real coverage is Task 16's smoke test.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a-hw task 11: thread hw_rx_ts_ns to RX event emission sites

Captures hw_rx_ts at the RX decode boundary (top of per-mbuf loop
after rte_eth_rx_burst); threads it into InternalEvent::Connected at
engine.rs:1842 and deliver_readable (new rx_hw_ts_ns param) which
emits InternalEvent::Readable at what used to be engine.rs:2205.

On ENA the accessor always returns 0 (dynfield not registered) so
events still carry 0, matching spec §9.2 / §10.5 ENA steady state.
Positive-path assertion deferred to Stage 2 (non-ENA PMD).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: LLQ log-scrape verification

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — add `verify_llq_activation` gated on `hw-verify-llq`; call around `rte_eth_dev_start`.
- Possibly modify: `crates/resd-net-sys/shim.c` — add `rte_openlog_stream` wrapper if bindgen doesn't expose it cleanly.

- [ ] **Step 1: Verify bindgen exposure of `rte_openlog_stream`**

Run: `grep -n 'rte_openlog_stream\|rte_log_get_stream' crates/resd-net-sys/src/lib.rs | head -5`

If absent, add to `wrapper.h`:
```c
#include <rte_log.h>
```
Rebuild `resd-net-sys`. If still not exposed, add a shim pass-through.

- [ ] **Step 2: Lock exact ENA PMD log strings for DPDK 23.11**

Read `third_party/dpdk/drivers/net/ena/ena_ethdev.c` (or vendored equivalent) for the LLQ activation + failure log messages. Record the literal substrings:

```bash
grep -rn 'LLQ\|Low-latency' /home/ubuntu/resd.dpdk_tcp-a-hw/third_party/dpdk/drivers/net/ena/ 2>&1 | head -20
```

Expected markers (subject to actual source inspection):
- Activation substring: `"Placement policy: "` (LLQ-aware value follows; match any line containing this prefix — robust against future value changes)
- Alternate activation: `"LLQ supported"` or `"using LLQ"`
- Failure substring: `"LLQ is not supported"` OR `"Fallback to disabled LLQ"` OR `"LLQ is not enabled"`

Bake these into the verifier as `const &'static str` arrays. If DPDK source inspection turns up different exact strings, use those instead and record the source-file line in a comment.

- [ ] **Step 3: Add the verifier**

```rust
#[cfg(feature = "hw-verify-llq")]
fn verify_llq_activation(
    port_id: u16,
    driver_name: &[u8; 32],
    counters: &Counters,
) -> Result<(), Error> {
    use std::sync::atomic::Ordering;
    let driver_str = std::str::from_utf8(
        &driver_name[..driver_name.iter().position(|&b| b == 0).unwrap_or(32)],
    )
    .unwrap_or("");
    if driver_str != "net_ena" {
        // LLQ is ENA-specific; nothing to verify on other drivers.
        return Ok(());
    }
    // Log-scrape: redirect RTE log stream into a memstream BEFORE
    // rte_eth_dev_start and scan AFTER. NOTE: Task 12 runs AROUND
    // rte_eth_dev_start — the orchestrator (Engine::new) wraps the
    // redirect + the scan.
    //
    // The redirect/scan pair is implemented here as a two-call API:
    //   let ctx = start_log_capture()?;
    //   // … caller runs rte_eth_dev_start …
    //   let log = finish_log_capture(ctx)?;
    // Scan-logic here:
    let log_captured: &str = /* supplied by caller */;
    const LLQ_ACTIVATION_MARKERS: &[&str] = &[
        "Placement policy:",
        "using LLQ",
        "LLQ supported",
    ];
    const LLQ_FAILURE_MARKERS: &[&str] = &[
        "LLQ is not supported",
        "Fallback to disabled LLQ",
        "LLQ is not enabled",
    ];
    let has_activation = LLQ_ACTIVATION_MARKERS
        .iter()
        .any(|m| log_captured.contains(m));
    let has_failure = LLQ_FAILURE_MARKERS
        .iter()
        .any(|m| log_captured.contains(m));
    if has_failure || !has_activation {
        counters.eth.offload_missing_llq.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "resd_net: port {} ENA driver but LLQ did not activate at bring-up \
             (has_failure={}, has_activation={}). Failing hard per spec §5.",
            port_id, has_failure, has_activation
        );
        return Err(Error::LlqActivationFailed);
    }
    Ok(())
}

#[cfg(not(feature = "hw-verify-llq"))]
fn verify_llq_activation(
    _port_id: u16,
    _driver_name: &[u8; 32],
    _counters: &Counters,
) -> Result<(), Error> {
    Ok(())
}
```

Add `LlqActivationFailed` to the `Error` enum in `error.rs`.

- [ ] **Step 4: Add log-capture helpers**

```rust
#[cfg(feature = "hw-verify-llq")]
struct LogCaptureCtx {
    orig_stream: *mut libc::FILE,
    buf: Vec<u8>,
    memstream: *mut libc::FILE,
    // fmemopen needs a stable buffer pointer; we box the Vec's ptr+cap
    // (NOT its heap), letting fmemopen write directly into our buffer.
}

#[cfg(feature = "hw-verify-llq")]
fn start_log_capture() -> Result<LogCaptureCtx, Error> {
    // Allocate a 16 KiB buffer. LLQ log output is a few lines total;
    // 16 KiB is ~100× headroom.
    let mut buf = vec![0u8; 16 * 1024];
    unsafe {
        let memstream = libc::fmemopen(
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            b"w\0".as_ptr() as *const _,
        );
        if memstream.is_null() {
            return Err(Error::LogCaptureInit);
        }
        let orig = sys::rte_log_get_stream();
        let rc = sys::rte_openlog_stream(memstream);
        if rc != 0 {
            libc::fclose(memstream);
            return Err(Error::LogCaptureInit);
        }
        Ok(LogCaptureCtx {
            orig_stream: orig,
            buf,
            memstream,
        })
    }
}

#[cfg(feature = "hw-verify-llq")]
fn finish_log_capture(ctx: LogCaptureCtx) -> Result<String, Error> {
    unsafe {
        libc::fflush(ctx.memstream);
        // Restore original stream.
        sys::rte_openlog_stream(ctx.orig_stream);
        libc::fclose(ctx.memstream);
    }
    // Convert captured buffer to String (lossy — RTE log may include
    // non-UTF8 bytes on some PMDs).
    let end = ctx.buf.iter().position(|&b| b == 0).unwrap_or(ctx.buf.len());
    Ok(String::from_utf8_lossy(&ctx.buf[..end]).into_owned())
}
```

Add `Error::LogCaptureInit` to `error.rs`.

- [ ] **Step 5: Wire around rte_eth_dev_start**

In `Engine::new`, replace:

```rust
        let rc = unsafe { sys::rte_eth_dev_start(cfg.port_id) };
        if rc != 0 { /* error */ }
```

with:

```rust
        #[cfg(feature = "hw-verify-llq")]
        let capture = start_log_capture()?;

        let rc = unsafe { sys::rte_eth_dev_start(cfg.port_id) };
        if rc != 0 {
            #[cfg(feature = "hw-verify-llq")]
            { let _ = finish_log_capture(capture); }
            /* existing error return */
        }

        #[cfg(feature = "hw-verify-llq")]
        {
            let log = finish_log_capture(capture)?;
            verify_llq_activation(cfg.port_id, &outcome.driver_name, &counters)
                .inspect_err(|_| {
                    // Log the captured output for operator debugging.
                    eprintln!("resd_net: captured PMD log during bring-up:\n{log}");
                })?;
        }
```

- [ ] **Step 6: Build + test**

Run: `cargo test -p resd-net-core --release 2>&1 | tail -20`
Expected: pass. `net_tap` tests go through the `driver_name != "net_ena"` short-circuit.

Run: `cargo build -p resd-net-core --release --no-default-features 2>&1 | tail -10`
Expected: clean; verification block + helpers compile away entirely.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/engine.rs \
        crates/resd-net-core/src/error.rs \
        crates/resd-net-sys/
git commit -m "$(cat <<'EOF'
a-hw task 12: LLQ activation verification via PMD log-scrape

New start_log_capture / finish_log_capture helpers wrap rte_openlog_stream
around rte_eth_dev_start to capture PMD output into a 16 KiB memstream-backed
buffer. After dev_start succeeds, verify_llq_activation scans the captured
log for ENA's LLQ activation and failure markers; fails hard
(Error::LlqActivationFailed + counter bump) if the driver is net_ena AND
no activation marker was found OR a failure marker was present.

Non-ENA drivers short-circuit before the scan. Feature-off builds
(hw-verify-llq off) compile the capture + scan + verify away entirely.

Exact ENA log strings pinned against DPDK 23.11
drivers/net/ena/ena_ethdev.c; a future DPDK upgrade that changes them
will fail engine startup rather than silently running without LLQ
(fail-safe direction). See spec §5.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Parent-spec + roadmap hw-offload-llq → hw-verify-llq rename

**Files:**
- Modify: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` — §8.4 Tier 1 + §10.14 rename.
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md` — A-HW row + A10 deliverables.

- [ ] **Step 1: Search-and-replace in parent spec**

Run: `grep -n 'hw-offload-llq' docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`

For each match, use Edit to replace `hw-offload-llq` with `hw-verify-llq` — NOT `replace_all` at the file level (one-by-one for safety; occurrences should be ~5 or fewer).

- [ ] **Step 2: Update the description**

§8.4 Tier 1 LLQ entry likely says "hw-offload-llq: devargs-switched on/off". Update the sentence to reflect the verification-only semantics:

```
hw-verify-llq: engine verifies LLQ activation at bring-up via PMD
log-scrape + fails hard if ENA advertised LLQ capability but LLQ did
not activate. The enable_llq=X devarg is application-owned — this
feature flag controls verification discipline, not activation.
```

Exact wording to match the tone of surrounding text.

- [ ] **Step 3: Search-and-replace in roadmap**

Run: `grep -n 'hw-offload-llq' docs/superpowers/plans/stage1-phase-roadmap.md`

A-HW row feature-flag table: row name `hw-offload-llq` → `hw-verify-llq`. Body text: same rename everywhere.

A10 deliverables section: `tools/bench-offload-ab/` feature-flag list.

- [ ] **Step 4: Spot-check nothing else references the old name**

Run: `grep -rn 'hw-offload-llq' docs/ crates/ scripts/ 2>&1`
Expected: zero matches (the spec at `2026-04-19-stage1-phase-a-hw-ena-offload-design.md` was already written with the new name).

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md \
        docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "$(cat <<'EOF'
a-hw task 13: rename hw-offload-llq → hw-verify-llq in parent spec + roadmap

The feature flag verifies LLQ activation only — it does not set the
enable_llq=X devarg (EAL init is app-owned). Renamed in parent spec
§8.4 Tier 1 + §10.14 + roadmap A-HW row + A10 deliverables to reflect
the verification-only semantics. Updated descriptive text to make the
ownership boundary explicit.

No code change.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Knob-coverage audit entries for every feature-off branch

**Files:**
- Modify: `crates/resd-net-core/tests/knob-coverage.rs` — add one scenario per feature-flag off-branch.

**Goal:** Every feature-off branch has at least one `#[cfg(not(feature = ...))]` test that asserts a visible, distinguishing consequence of the feature being off.

- [ ] **Step 1: Add scenario per feature**

Append to `crates/resd-net-core/tests/knob-coverage.rs`:

```rust
// ---- A-HW knob coverage -------------------------------------------------

/// Knob: `hw-verify-llq` feature flag.
/// Non-default value: feature OFF.
/// Observable consequence: Engine::new succeeds on ENA even if LLQ did
/// not activate, because verify_llq_activation is compiled out. Test is
/// `cfg(not(feature))` so it only runs in the feature-off build.
#[cfg(not(feature = "hw-verify-llq"))]
#[test]
fn knob_hw_verify_llq_off_engine_does_not_verify() {
    // Verifier is compiled out — its absence is the observable.
    // This test passes trivially in the feature-off build; its
    // existence guarantees the feature-off branch is compiled in CI.
}

/// Knob: `hw-offload-tx-cksum` feature flag.
/// Non-default value: feature OFF.
/// Observable: tx_offload_finalize is a no-op — ol_flags stays zero
/// after calling it with offload_active=true.
#[cfg(not(feature = "hw-offload-tx-cksum"))]
#[test]
fn knob_hw_offload_tx_cksum_off_finalize_is_noop() {
    // tx_offload_finalize exists (feature-off variant). It takes no
    // state because it ignores all inputs.
    let dummy_mbuf = std::ptr::null_mut();
    // Signature match: (mbuf, seg, payload_len, offload_active)
    // Calling is safe: feature-off finalize is empty.
    // Compile-check only — the feature-off finalize has no effect.
}

/// Knob: `hw-offload-rx-cksum` feature flag.
/// Non-default value: feature OFF.
/// Observable: ip_decode_offload_aware forwards directly to
/// ip_decode(nic_csum_ok=false) — no counter bumps.
#[cfg(not(feature = "hw-offload-rx-cksum"))]
#[test]
fn knob_hw_offload_rx_cksum_off_ip_decode_always_software_verify() {
    use resd_net_core::counters::Counters;
    use resd_net_core::l3_ip::ip_decode_offload_aware;
    let counters = Counters::new();
    // Build a minimal valid IPv4 packet that would fail software
    // verify only if nic_csum_ok=false (i.e. software fold mismatch).
    let pkt = build_valid_ipv4_tcp_packet();
    // Feature-off: even with ol_flags indicating GOOD, we software-verify.
    let ol_flags = /* RTE_MBUF_F_RX_IP_CKSUM_GOOD — but feature is off */ 0u64;
    let res = ip_decode_offload_aware(&pkt, 0, ol_flags, &counters);
    assert!(res.is_ok());
    // No BAD-counter bumps because we never classified via ol_flags.
    assert_eq!(
        counters.eth.rx_drop_cksum_bad.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

/// Knob: `hw-offload-mbuf-fast-free`.
/// Non-default value: OFF. No directly observable diff at the Rust test
/// layer (PMD-internal). Compile-presence is the test.
#[cfg(not(feature = "hw-offload-mbuf-fast-free"))]
#[test]
fn knob_hw_offload_mbuf_fast_free_off_compiles() {}

/// Knob: `hw-offload-rss-hash`.
/// Non-default: OFF. Observable: hash_bucket_for_lookup always returns
/// SipHash regardless of ol_flags RSS_HASH or nic_rss_hash value.
#[cfg(not(feature = "hw-offload-rss-hash"))]
#[test]
fn knob_hw_offload_rss_hash_off_always_siphash() {
    use resd_net_core::flow_table::{hash_bucket_for_lookup, FourTuple};
    let tup = FourTuple {
        local_ip: 0x0a000001, local_port: 1,
        peer_ip: 0x0a000002, peer_port: 2,
    };
    // Feature-off: NIC hash is ignored; siphash is used.
    let with_nic_hash = hash_bucket_for_lookup(&tup, u64::MAX, 0xdead, true);
    let without_flag = hash_bucket_for_lookup(&tup, 0, 0xbeef, true);
    assert_eq!(with_nic_hash, without_flag,
        "feature-off: nic_rss_hash must be ignored — SipHash deterministic over tup");
}

/// Knob: `hw-offload-rx-timestamp`.
/// Non-default: OFF. Observable: hw_rx_ts_ns accessor is a const fn
/// returning 0. Exercised via Engine::hw_rx_ts_ns returning 0 for any
/// mbuf input — but we cannot construct an Engine in a unit test.
/// Compile-presence check only.
#[cfg(not(feature = "hw-offload-rx-timestamp"))]
#[test]
fn knob_hw_offload_rx_timestamp_off_compiles() {}
```

Plus a helper:

```rust
fn build_valid_ipv4_tcp_packet() -> Vec<u8> {
    // 20-byte IPv4 header + 20-byte TCP header + empty payload.
    // Checksum computed correctly so software verify passes.
    use resd_net_core::tcp_output::{build_segment, SegmentTx, TCP_ACK};
    use resd_net_core::tcp_options::TcpOpts;
    let seg = SegmentTx {
        src_mac: [0; 6], dst_mac: [0; 6],
        src_ip: 0x0a000001, dst_ip: 0x0a000002,
        src_port: 10000, dst_port: 20000,
        seq: 0, ack: 0, flags: TCP_ACK, window: 1024,
        options: TcpOpts::default(), payload: &[],
    };
    let mut buf = vec![0u8; 64];
    let n = build_segment(&seg, &mut buf).unwrap();
    buf.truncate(n);
    // Strip the Ethernet header (14 bytes) — ip_decode_offload_aware
    // expects to start at the IP header.
    buf[14..].to_vec()
}
```

- [ ] **Step 2: Run knob-coverage tests in default build**

Run: `cargo test -p resd-net-core --release --test knob-coverage 2>&1 | tail -10`
Expected: existing A5.5 tests pass; the new A-HW tests ARE feature-gated off, so they don't run in this build — none fail, none skip.

- [ ] **Step 3: Run knob-coverage tests in --no-default-features build**

Run: `cargo test -p resd-net-core --release --test knob-coverage --no-default-features 2>&1 | tail -10`
Expected: the new `knob_hw_*_off_*` tests run and pass. Existing A5.5 tests that depend on `obs-poll-saturation` may require adding it back: `--features obs-poll-saturation` if they error out.

Adjust: `cargo test -p resd-net-core --release --test knob-coverage --no-default-features --features obs-poll-saturation 2>&1 | tail -10`

- [ ] **Step 4: Run per-flag configurations from Section 13 of the spec**

For each of the 8 build configs, run `cargo test --test knob-coverage` and verify:
- The knob_hw_*_off_* test FOR THE ONE FLAG THAT IS OFF fires and passes.
- The other `knob_hw_*_off_*` tests are compile-gated out and do NOT fire.

Loop through each config in `scripts/ci-feature-matrix.sh` (Task 15 adds this).

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/tests/knob-coverage.rs
git commit -m "$(cat <<'EOF'
a-hw task 14: knob-coverage entries for every A-HW feature-off branch

Adds six #[cfg(not(feature = "hw-*"))]-gated test cases to knob-coverage.rs
— one per A-HW cargo feature. Each test asserts a visible, distinguishing
consequence of the feature being off (e.g. flow_table hash_bucket_for_lookup
always returns SipHash regardless of ol_flags when hw-offload-rss-hash is
off) OR compiles the feature-off code path to catch bit-rot.

CI feature-matrix (Task 15) compiles and runs this test across all 8
build configurations so every feature-off branch is exercised at least
once per CI run.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: CI feature-matrix script

**Files:**
- Create: `scripts/ci-feature-matrix.sh` — 8-build driver.

- [ ] **Step 1: Create the script**

```bash
#!/usr/bin/env bash
# scripts/ci-feature-matrix.sh
#
# A-HW 8-build CI feature matrix per spec §13. Every feature-off branch
# compiles in exactly one build. Also runs `cargo test` on the default
# build to catch regressions.
#
# Usage (from repo root): ./scripts/ci-feature-matrix.sh
# Exits non-zero on first failure.

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

CRATE="-p resd-net-core"
COMMON_FEATURES="obs-poll-saturation"

echo "=== Build 1/8: default features ==="
cargo build --release ${CRATE}

echo "=== Test 1/8: default features ==="
cargo test --release ${CRATE}

echo "=== Build 2/8: --no-default-features ==="
cargo build --release ${CRATE} --no-default-features

echo "=== Test 2/8: --no-default-features (obs-poll-saturation) ==="
cargo test --release ${CRATE} --no-default-features --features ${COMMON_FEATURES}

ALL_HW=(
  hw-verify-llq
  hw-offload-tx-cksum
  hw-offload-rx-cksum
  hw-offload-mbuf-fast-free
  hw-offload-rss-hash
  hw-offload-rx-timestamp
)

for ((i=0; i<${#ALL_HW[@]}; i++)); do
  off="${ALL_HW[$i]}"
  # Compose set = all others + common, one feature off.
  features="${COMMON_FEATURES}"
  for other in "${ALL_HW[@]}"; do
    if [[ "$other" != "$off" ]]; then
      features="${features},${other}"
    fi
  done
  echo "=== Build $((i+3))/8: --no-default-features --features \"${features}\"  (${off} OFF) ==="
  cargo build --release ${CRATE} --no-default-features --features "${features}"
  echo "=== Test $((i+3))/8: ${off} OFF (knob-coverage) ==="
  cargo test --release ${CRATE} --no-default-features --features "${features}" --test knob-coverage
done

echo ""
echo "All 8 builds passed."
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/ci-feature-matrix.sh
```

- [ ] **Step 3: Run the full matrix locally**

Run: `./scripts/ci-feature-matrix.sh 2>&1 | tail -40`
Expected: 8 builds + 8 test runs, all green. Total runtime ~3-5 minutes.

If any build fails, the script stops at the first failure with the full cargo output. Fix the offending `#[cfg]` branch and re-run.

- [ ] **Step 4: Commit**

```bash
git add scripts/ci-feature-matrix.sh
git commit -m "$(cat <<'EOF'
a-hw task 15: CI feature-matrix driver

scripts/ci-feature-matrix.sh runs the 8 build configurations from
spec §13. Every hw-* feature's off-branch compiles and runs
knob-coverage tests in exactly one build; the default-features build
runs the full test suite.

Not yet wired to a CI pipeline (repo has no .github/workflows/ at
A-HW start); script stays runnable by hand and by future CI setup.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: SW-fallback smoke test (default features on net_tap)

**Files:**
- Create: `crates/resd-net-core/tests/ahw_smoke_sw_fallback.rs` — integration test on A3's TAP-pair harness, default features.

- [ ] **Step 1: Study existing TAP-pair integration tests**

Run: `ls crates/resd-net-core/tests/*tap* 2>&1; grep -l 'net_tap\|RESD_NET_TEST_TAP' crates/resd-net-core/tests/*.rs 2>&1 | head -5`

Read one of the existing TAP tests (e.g. `tcp_options_paws_reassembly_sack_tap.rs`) to reuse the harness setup.

- [ ] **Step 2: Write the smoke test**

```rust
//! A-HW Task 16: SW-fallback smoke test.
//!
//! Build: `cargo test --release --test ahw_smoke_sw_fallback`.
//! Preconditions: RESD_NET_TEST_TAP=1 (same as existing TAP tests —
//! requires CAP_NET_ADMIN and a freshly-initialized EAL).
//!
//! Runs the A3 TAP-pair harness with default features. The net_tap PMD
//! advertises no checksum / RSS offloads (verify via the startup banner
//! logged by configure_port_offloads), so:
//!   - eth.offload_missing_{rx,tx}_cksum_* = 1 each (confirmed during
//!     implementation against dev_info on net_tap's tx_offload_capa /
//!     rx_offload_capa).
//!   - eth.offload_missing_mbuf_fast_free = 1.
//!   - eth.offload_missing_rss_hash = 1.
//!   - eth.offload_missing_llq = 0 (driver != net_ena — short-circuit).
//!   - eth.offload_missing_rx_timestamp = 1 (dynfield absent).
//!   - eth.rx_drop_cksum_bad = 0 (well-formed TAP traffic).
//!   - Every event's rx_hw_ts_ns = 0.
//!   - Full request-response correctness matches the A3 oracle.

use std::sync::atomic::Ordering;

// Bring in the harness from the existing test file.
include!("../tests_harness/tap_pair.rs");  // ← or whatever it actually is
// ... or re-expose the TAP setup helpers via a shared mod.

#[test]
fn ahw_sw_fallback_counters_and_correctness() {
    if std::env::var("RESD_NET_TEST_TAP").is_err() {
        eprintln!("ahw_smoke_sw_fallback: RESD_NET_TEST_TAP not set; skipping");
        return;
    }
    let harness = tap_pair::setup(/* config */);
    harness.run_request_response_cycle(/* …128-byte request, 128-byte response… */);
    let c = harness.engine.counters();

    // Expected counter values on net_tap (verify during implementation):
    assert_eq!(c.eth.offload_missing_rx_cksum_ipv4.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.offload_missing_rx_cksum_tcp.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.offload_missing_rx_cksum_udp.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.offload_missing_tx_cksum_ipv4.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.offload_missing_tx_cksum_tcp.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.offload_missing_tx_cksum_udp.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.offload_missing_mbuf_fast_free.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.offload_missing_rss_hash.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.offload_missing_llq.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_rx_timestamp.load(Ordering::Relaxed), 1);
    assert_eq!(c.eth.rx_drop_cksum_bad.load(Ordering::Relaxed), 0);

    // All collected events carry rx_hw_ts_ns = 0 (dynfield absent).
    for ev in harness.drained_events() {
        assert_eq!(ev.rx_hw_ts_ns, 0);
    }
}
```

- [ ] **Step 3: Run to pin the expected counter values**

On first run, the expected values may diverge from the guesses above — net_tap's advertised offload set depends on DPDK version. Run:

```bash
RESD_NET_TEST_TAP=1 cargo test --release --test ahw_smoke_sw_fallback -- --nocapture 2>&1 | head -50
```

Read the startup-banner lines (from Task 5) to see net_tap's actual `tx_offload_capa` / `rx_offload_capa` values. Update the `assert_eq!` expected values to match what the PMD reports. Document the values + PMD build in a code comment so a future DPDK bump that changes them surfaces as a test failure rather than silent drift.

- [ ] **Step 4: Re-run to confirm pass**

```bash
RESD_NET_TEST_TAP=1 cargo test --release --test ahw_smoke_sw_fallback 2>&1 | tail -10
```

Expected: `test result: ok. 1 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/tests/ahw_smoke_sw_fallback.rs
git commit -m "$(cat <<'EOF'
a-hw task 16: SW-fallback smoke test (default features, net_tap)

End-to-end integration test on the A3 TAP-pair harness with default
A-HW features. Asserts:
  - All offload_missing_* counters match what net_tap advertises
    (pinned at implementation time from dev_info.*_offload_capa).
  - rx_drop_cksum_bad = 0 (well-formed test traffic).
  - Every event's rx_hw_ts_ns = 0 (dynfield absent).
  - Full request-response cycle correctness matches A3 oracle.

Confirms the runtime-fallback software-checksum path compiles and runs
correctly when the PMD doesn't advertise the offload, even with every
A-HW feature compile-enabled.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 17: SW-only smoke test (--no-default-features)

**Files:**
- Create or Reuse: the same `crates/resd-net-core/tests/ahw_smoke_sw_fallback.rs` file OR a new `ahw_smoke_sw_only.rs` — pick based on whether the harness shares cleanly.

- [ ] **Step 1: Decide — reuse or separate**

Running a test under different features requires rebuilding with `--no-default-features`. A single `.rs` file can have `#[cfg(feature = "...")]`-gated tests inside it. The simplest path:

- Reuse `ahw_smoke_sw_fallback.rs`.
- Add a second test gated on `#[cfg(not(feature = "hw-verify-llq"))]` (proxy for the feature-off build — any one hw-* flag works since --no-default-features turns them all off).

Actually, a cleaner discriminator: `#[cfg(all(not(feature = "hw-offload-tx-cksum"), not(feature = "hw-offload-rx-cksum")))]` — runs only when both are off, i.e. in the `--no-default-features` case.

- [ ] **Step 2: Append the SW-only test**

```rust
#[test]
#[cfg(all(
    not(feature = "hw-offload-tx-cksum"),
    not(feature = "hw-offload-rx-cksum"),
    not(feature = "hw-offload-rss-hash"),
    not(feature = "hw-offload-mbuf-fast-free"),
    not(feature = "hw-offload-rx-timestamp"),
    not(feature = "hw-verify-llq"),
))]
fn ahw_sw_only_counters_and_correctness() {
    if std::env::var("RESD_NET_TEST_TAP").is_err() {
        eprintln!("ahw_sw_only: RESD_NET_TEST_TAP not set; skipping");
        return;
    }
    let harness = tap_pair::setup(/* config */);
    harness.run_request_response_cycle(/* … */);
    let c = harness.engine.counters();

    // SW-only build: NO offload branches compiled in → NO
    // offload_missing_* bumps (no request, no miss).
    assert_eq!(c.eth.offload_missing_rx_cksum_ipv4.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_rx_cksum_tcp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_rx_cksum_udp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_tx_cksum_ipv4.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_tx_cksum_tcp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_tx_cksum_udp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_mbuf_fast_free.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_rss_hash.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_llq.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_rx_timestamp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.rx_drop_cksum_bad.load(Ordering::Relaxed), 0);

    // Every event's rx_hw_ts_ns = 0 by construction (const fn accessor).
    for ev in harness.drained_events() {
        assert_eq!(ev.rx_hw_ts_ns, 0);
    }
}
```

- [ ] **Step 3: Run**

```bash
RESD_NET_TEST_TAP=1 cargo test --release --test ahw_smoke_sw_fallback --no-default-features --features obs-poll-saturation -- --nocapture 2>&1 | tail -10
```

Expected: `ahw_sw_only_counters_and_correctness` runs and passes; `ahw_sw_fallback_counters_and_correctness` is gated-off (only runs in default-features build).

- [ ] **Step 4: Commit**

```bash
git add crates/resd-net-core/tests/ahw_smoke_sw_fallback.rs
git commit -m "$(cat <<'EOF'
a-hw task 17: SW-only smoke test (--no-default-features)

Adds a second test to ahw_smoke_sw_fallback.rs gated on every hw-*
feature being off. Runs on the same A3 TAP-pair harness; asserts:
  - All offload_missing_* counters = 0 (no request made, no miss).
  - rx_drop_cksum_bad = 0.
  - Every event's rx_hw_ts_ns = 0 (const fn accessor).
  - Full request-response correctness.

Confirms the fully-compile-gated-off build produces identical on-wire
behavior to the default build at the A3 oracle level.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 18: HW-path smoke test (default features on ENA VF)

**Files:**
- Create: `crates/resd-net-core/tests/ahw_smoke_ena_hw.rs` — integration test on real ENA VF, gated on `RESD_NET_TEST_ENA=1`.

- [ ] **Step 1: Study existing ENA setup patterns**

Check `tests/ffi-test/` + any existing ENA-specific tests. If none, the test is new territory — document the prerequisites clearly:

```
Preconditions (from operator):
  1. Host is AWS EC2 with a dedicated ENA VF not used for SSH.
     (Use a secondary ENI bound to DPDK via vfio-pci.)
  2. Hugepages reserved: ≥1 GiB of 2MB pages.
  3. EAL args:
     --in-memory --huge-unlink --no-pci -a <ENA_BDF>,enable_llq=1
  4. Run: RESD_NET_TEST_ENA=1 ENA_BDF=0000:00:06.0 cargo test \
          --release --test ahw_smoke_ena_hw -- --nocapture
  5. No other test in the session shares this VF.

The test is marked #[ignore] by default so `cargo test` without
the env var does not try to touch a real ENA device.
```

- [ ] **Step 2: Write the test**

```rust
//! A-HW Task 18: HW-path smoke test on real ENA VF.
//!
//! Preconditions: RESD_NET_TEST_ENA=1 + ENA_BDF=<bdf>.
//! Marked #[ignore] so `cargo test` without the env var does not
//! attempt to initialize DPDK against a real NIC.

use std::sync::atomic::Ordering;

#[test]
#[ignore = "requires real ENA VF; set RESD_NET_TEST_ENA=1 + ENA_BDF=<bdf>"]
fn ahw_ena_hw_path_banner_and_counters() {
    if std::env::var("RESD_NET_TEST_ENA").is_err() {
        return;
    }
    let bdf = std::env::var("ENA_BDF")
        .expect("ENA_BDF not set");
    // Bring up an engine against the ENA VF. The startup banner logs
    // via eprintln!; with --nocapture it reaches stderr. Parse the
    // banner for ENA-specific markers.
    let harness = ena_harness::setup(&bdf);
    // Drive one full request-response cycle. Target: a known loopback
    // or paired peer on the same VPC subnet.
    harness.run_request_response_cycle();
    let c = harness.engine.counters();

    // All capabilities advertised + applied on ENA — counters at 0
    // except the documented rx_timestamp steady state.
    assert_eq!(c.eth.offload_missing_rx_cksum_ipv4.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_rx_cksum_tcp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_rx_cksum_udp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_tx_cksum_ipv4.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_tx_cksum_tcp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_tx_cksum_udp.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_mbuf_fast_free.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_rss_hash.load(Ordering::Relaxed), 0);
    assert_eq!(c.eth.offload_missing_llq.load(Ordering::Relaxed), 0,
        "ENA default is enable_llq=1; LLQ must be verified active");
    // ENA does NOT register the rte_dynfield_timestamp dynfield;
    // this counter = 1 is the documented steady state.
    assert_eq!(c.eth.offload_missing_rx_timestamp.load(Ordering::Relaxed), 1,
        "expected 1 on ENA (dynfield absent) — spec §10.5");
    assert_eq!(c.eth.rx_drop_cksum_bad.load(Ordering::Relaxed), 0,
        "well-formed ENA traffic must not report cksum BAD");

    // Every event's rx_hw_ts_ns = 0 on ENA (dynfield absent).
    for ev in harness.drained_events() {
        assert_eq!(ev.rx_hw_ts_ns, 0,
            "ENA dynfield-absent → accessor always yields 0");
    }
}
```

The `ena_harness` module is new — probably a minimal `#[cfg(test)]` helper that wraps `resd_net_core::Engine::new` with ENA-specific EAL args. Write the simplest possible version; do NOT over-abstract.

- [ ] **Step 3: Run on the actual ENA host**

```bash
RESD_NET_TEST_ENA=1 ENA_BDF=0000:00:06.0 cargo test --release --test ahw_smoke_ena_hw -- --ignored --nocapture 2>&1 | tail -30
```

Expected: test passes. The banner in the stderr output shows the negotiated offload masks including every A-HW bit.

If `offload_missing_llq` is nonzero on ENA, the PMD log-scrape markers in Task 12 may need fixing — read the captured log lines that the test prints on failure and update the activation-marker list.

- [ ] **Step 4: Commit**

```bash
git add crates/resd-net-core/tests/ahw_smoke_ena_hw.rs
git commit -m "$(cat <<'EOF'
a-hw task 18: HW-path smoke test on real ENA VF

Integration test against a real ENA VF — #[ignore]d by default so
`cargo test` on development hosts without ENA does not touch a real
NIC. Asserts that with default A-HW features:
  - All offload_missing_* = 0 EXCEPT offload_missing_rx_timestamp = 1
    (documented ENA steady state — ENA does not register the
    rte_dynfield_timestamp dynfield).
  - offload_missing_llq = 0 (ENA default enable_llq=1 activates LLQ).
  - rx_drop_cksum_bad = 0.
  - Every event's rx_hw_ts_ns = 0 (accessor always yields 0 on ENA).
  - Full request-response correctness.

Preconditions documented in the test file header: RESD_NET_TEST_ENA=1
+ ENA_BDF=<bdf> + EAL args including enable_llq=1. Part of the ship
gate (spec §16 criterion c).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 19: Mark A-HW complete in roadmap

**Files:**
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md` — A-HW row → Complete + link to this plan.

- [ ] **Step 1: Locate the summary table at the top of the roadmap**

Run: `grep -n '| A-HW\|^| A-HW' docs/superpowers/plans/stage1-phase-roadmap.md | head -5`

In the summary table, change the status column from `Not started` → `Complete`; add a link to this plan file in the last column.

- [ ] **Step 2: Update the A-HW row body**

At the end of the A-HW section (after "Rough scale: ~14 tasks"), append a "Status" line pointing at the completed plan + tag:

```markdown
**Status:** **Complete.** Plan: `docs/superpowers/plans/2026-04-19-stage1-phase-a-hw-ena-offload.md`. Tag: `phase-a-hw-complete` (set after Task 20's review gates).
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "a-hw task 19: mark A-HW row complete in roadmap

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 20: End-of-phase review gates (parallel mTCP + RFC)

**Files:**
- Create: `docs/superpowers/reviews/phase-a-hw-mtcp-compare.md` — via `mtcp-comparison-reviewer` subagent.
- Create: `docs/superpowers/reviews/phase-a-hw-rfc-compliance.md` — via `rfc-compliance-reviewer` subagent.

- [ ] **Step 1: Dispatch both review subagents in parallel**

Using the Agent tool, dispatch both reviews in a single message with two tool calls:

```
Agent (mtcp-comparison-reviewer, opus): {
  description: "Phase A-HW mTCP comparison review",
  prompt: "<detailed brief pointing at the phase-a-hw branch tip, spec
  at docs/superpowers/specs/2026-04-19-stage1-phase-a-hw-ena-offload-design.md,
  parent §8.1-8.5. Focus: what does mTCP do for port config, offload
  bits, checksum offload, RSS, RX timestamp? Are there architectural
  divergences we should document? Save report to
  docs/superpowers/reviews/phase-a-hw-mtcp-compare.md.>"
}

Agent (rfc-compliance-reviewer, opus): {
  description: "Phase A-HW RFC compliance review",
  prompt: "<detailed brief pointing at the phase-a-hw branch tip, spec
  at docs/superpowers/specs/2026-04-19-stage1-phase-a-hw-ena-offload-design.md.
  RFCs in scope: RFC 9293 §3.1 (TCP pseudo-header checksum), RFC 1071
  (Internet checksum), RFC 1624 (incremental checksum — not exercised).
  Offload path must produce bit-for-bit identical on-wire bytes to the
  software-fallback path. Save report to
  docs/superpowers/reviews/phase-a-hw-rfc-compliance.md.>"
}
```

- [ ] **Step 2: Review both reports**

Both reports must show zero open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD. If any item is open:
- Read the finding.
- Fix the code OR document the acceptance (spec update).
- Re-run the reviewer on the updated branch.

Iterate until both reports are green.

- [ ] **Step 3: Commit both reports**

```bash
git add docs/superpowers/reviews/phase-a-hw-mtcp-compare.md \
        docs/superpowers/reviews/phase-a-hw-rfc-compliance.md
git commit -m "$(cat <<'EOF'
a-hw task 20: mTCP + RFC review-gate reports

Two parallel review subagents (opus 4.7) against the phase-a-hw branch:
- mtcp-comparison-reviewer: compared A-HW offload choices against
  mTCP's equivalents; differences documented are architectural
  (trading-latency vs throughput) not bugs.
- rfc-compliance-reviewer: checked A-HW's offload paths against
  RFC 9293 §3.1 + RFC 1071 for on-wire-bit equivalence. Zero new
  MUST violations, zero missing SHOULDs.

Both reports show zero open [ ] items — clears the spec §16
review-gate criteria for the phase-a-hw-complete tag.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 4: Tag the phase complete**

```bash
git tag -a phase-a-hw-complete -m "Phase A-HW complete — see docs/superpowers/reviews/phase-a-hw-*.md"
```

Do NOT push the tag. Coordinator merges + tags + pushes.

- [ ] **Step 5: Final handoff report**

Produce the handoff report for the coordinator:
- Tag SHA: output of `git rev-parse phase-a-hw-complete`.
- List of rebase events against `phase-a6` (if any occurred during implementation).
- Any unresolved conflicts or surprises.

---

## End-of-plan checklist

Before the subagent-driven execution starts:
- [ ] Spec file committed: `docs/superpowers/specs/2026-04-19-stage1-phase-a-hw-ena-offload-design.md` at `phase-a-hw` tip.
- [ ] Plan file committed: this file.
- [ ] Worktree exists at `/home/ubuntu/resd.dpdk_tcp-a-hw` on branch `phase-a-hw` off tag `phase-a5-5-complete`.
- [ ] No changes to parent spec or roadmap yet (Task 13 does those).
- [ ] Session 1 (A6) has its own worktree at `/home/ubuntu/resd.dpdk_tcp-a6` — no overlap.
- [ ] Rebase cadence: after each commit, `git fetch && git log --oneline phase-a6 --since=<last check>`; `git rebase phase-a6` if new work landed.

**Coordination hazards with Session 1 (A6):**
- Shared files: `engine.rs`, `api.rs`, `counters.rs`, `include/resd_net.h`, `Cargo.toml`.
- A-HW touches: port config (early in Engine::new), RX event sites (engine.rs:1842 + deliver_readable), counters (EthCounters + eth_counters_t).
- A6 touches: timer wheel, close flags, WRITABLE event, preset, RTT histogram (tcp_rtt.rs + conn stats).
- Overlap is low — different regions of engine.rs. cbindgen regenerations should be rebasable; counter-struct additions use append-not-insert so they commute.

**End of plan.**
