# Phase A-HW — ENA hardware offload enablement (Design Spec)

**Status:** draft for plan-writing.
**Parent spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` — §8.1–§8.5 (target deployment + ENA offload matrix + tiered enablement policy + capability-gated bring-up), §7.5 (clock + dynfield accessor), §9.2 (`rx_hw_ts_ns` / `enqueued_ts_ns` semantics), §9.1.1 (counter-addition policy), §11.1 (measurement discipline preconditions), §11.3 (TSC-only attribution fallback on ENA).
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` — A-HW.
**Branch:** `phase-a-hw` (off `phase-a5-5-complete` tag; commit 957e9e5).
**Ships:** `phase-a-hw-complete` tag gated on three smoke runs green + 8-build CI matrix green + mTCP + RFC review reports both showing zero open `[ ]`.
**Parallel session:** Session 1 runs A6 (public-API completeness + former A5.6 merged in) on `phase-a6` off the same base. Coordination via periodic rebase of `phase-a-hw` onto `phase-a6`.

---

## 1. Scope

A-HW flips the port configuration from Phase A1's zeroed `rte_eth_conf` (plus A5's lone `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` bit) to the Stage 1 production-shape offload set: verify LLQ activated, enable TX+RX IPv4+TCP+UDP checksum offload, enable `MBUF_FAST_FREE`, wire RSS-hash plumbing end-to-end (even at single queue), and wire NIC RX timestamping end-to-end via DPDK dynfield+dynflag lookup. Every offload is gated by a compile-time cargo feature flag so A10's `tools/bench-offload-ab/` harness can produce an on-vs-off A/B benchmark per offload via rebuilds. Every compile-enabled offload is also capability-gated at runtime against `rte_eth_dev_info_get` so `net_vdev` / `net_tap` test harnesses degrade to the software path without a separate build.

**Motivation:** Stage 1 target deployment is AWS ENA on AMD EPYC Milan (parent spec §8.1). Phase A1's port config runs pure software-path cksum + no LLQ verification + no RSS-hash consumption + zeroed `rx_hw_ts_ns` on every event. A-HW makes the code path switchable at compile time + correct under both settings, so A10 can measure and pick the final kept-vs-removed set per offload.

In scope:
- Six cargo feature flags (Section 3) with a `hw-offloads-all` meta-feature and a convention-compatible `default = [...]` list.
- `engine.rs` port-config rewrite (Section 4): `dev_info` query, offload AND, startup banner, MULTI_SEGS preservation, RSS `rss_conf` + reta program.
- LLQ activation verification via PMD-log-scrape at bring-up (Section 5).
- TX checksum offload with pseudo-header-only software write + per-engine runtime-fallback latch (Section 6).
- RX checksum offload with `ol_flags` inspection + `BAD`→drop + `NONE`/`UNKNOWN`→software fallback (Section 7).
- RSS-hash read from `mbuf.hash.rss` in `flow_table.rs` with SipHash fallback (Section 8).
- `MBUF_FAST_FREE` bit on `txmode.offloads` (Section 9).
- RX timestamp dynfield+dynflag lookup at `engine_create`; always-inline accessor; threaded through `tcp_events.rs:164` — the single real RX-origin event site (Section 10).
- Slow-path counter additions for every `offload_missing_*` + `rx_drop_cksum_bad` (Section 11).
- Three smoke runs: SW-fallback with default features on non-ENA PMD, SW-only with `--no-default-features`, HW-path on real ENA VF (Section 12).
- 8-build CI feature-matrix sampled to cover every feature-off branch exactly once (Section 13).
- Knob-coverage audit entries for every build configuration (Section 14).

Out of scope (Section 15 restates):
- Multi-queue enablement (Stage 1 single-queue per parent §12).
- Header/data split, TSO, GRO, GSO (Tier 3 per parent §8.4).
- General-purpose RX scatter at MTU 1500.
- Hot-path "offload used" counters (startup log is authoritative per §8.5 / §9.1.1).
- Positive-path HW-timestamp assertion (requires a non-ENA PMD that registers `rte_dynfield_timestamp`; Stage 2 hardening).
- Measurement of actual offload benefit (A10 responsibility; A-HW ships the switch, A10 flips it and measures).
- Anything in A6 territory — timer API, `WRITABLE`, close flags + RFC 6191, preset runtime switch, poll-overflow queueing, mempool-exhaustion error paths, RTT histogram.

---

## 2. Module layout

### 2.1 Modified modules (`crates/resd-net-core/src/`)

| Module | Change |
|---|---|
| `engine.rs` | Port-config rewrite at current lines 422–450 (dev_info query + offload AND + RSS `rss_conf` + reta program + MULTI_SEGS preserve + startup banner); LLQ log-scrape + activation-verify block gated on `hw-verify-llq`; RX-timestamp dynfield+dynflag lookup at `engine_create` gated on `hw-offload-rx-timestamp` (new engine-state fields under `#[cfg]`); always-inline `hw_rx_ts_ns` accessor (const-zero variant when feature off); bring-up-time `offload_missing_*` / `offload_missing_rx_timestamp` / `offload_missing_llq` counter-bump calls. Two RX-origin event sites consume the accessor: line 1842 (`InternalEvent::Connected` after SYN-ACK parse) and line 2205 (`InternalEvent::Readable` in `deliver_readable`). Timestamp is captured at the RX-decode boundary (where the mbuf is still available) and threaded through the internal per-packet state to both emission sites — `deliver_readable` no longer has the mbuf pointer at line 2205, so the value must be carried in, not read. |
| `tcp_events.rs` | No production-code change. The `InternalEvent::Connected { ..., rx_hw_ts_ns, ... }` and `InternalEvent::Readable { ..., rx_hw_ts_ns, ... }` enum variants already carry the field (A5.5 added it); A-HW just changes the engine sites that construct them. Line 164 is inside a unit-test fixture (`#[cfg(test)] mod tests`) — stays at `rx_hw_ts_ns: 0`. |
| `tcp_output.rs` | `#[cfg(feature = "hw-offload-tx-cksum")]` branch: on engines with `tx_cksum_offload_active == true`, set `mbuf.ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM`; set `l2_len = 14`, `l3_len = 20`, `l4_len = tcp_hdr_len`; write only the 12-byte pseudo-header checksum into the TCP cksum field; IPv4 header cksum field = 0. Runtime-fallback branch (when `tx_cksum_offload_active == false`) stays with the current software full-fold. `#[cfg(not)]` build compiles away the offload branch entirely. |
| `l3_ip.rs` | Expose a new `tcp_pseudo_header_checksum(src_ip, dst_ip, tcp_seg_len)` helper for the pseudo-header-only path; RX path gains an `ol_flags`-inspection branch under `#[cfg(feature = "hw-offload-rx-cksum")]` that folds `RTE_MBUF_F_RX_IP_CKSUM_*` / `RTE_MBUF_F_RX_L4_CKSUM_*` into the existing `check_header`. |
| `tcp_input.rs` | Upstream caller of `l3_ip::check_header` — inherit the RX cksum path change; a single per-packet `BAD` branch bumps `eth.rx_drop_cksum_bad` + drops. |
| `flow_table.rs` | `#[cfg(feature = "hw-offload-rss-hash")]` branch at the lookup site: when `ol_flags & RTE_MBUF_F_RX_RSS_HASH` is set, use `mbuf.hash.rss` as the initial 32-bit bucket index; otherwise SipHash. `#[cfg(not)]` build = SipHash always. |
| `counters.rs` | New `AtomicU64` fields on `EthCounters` per Section 11. Always allocated, regardless of feature flags (C-ABI stability). |
| `lib.rs` | No change beyond anything picked up by `pub use` re-exports for the new counter field names. |

### 2.2 Modified modules (`crates/resd-net/src/`)

| Module | Change |
|---|---|
| `lib.rs` | RX-origin forwarder at lines 175–191 already threads `rx_hw_ts_ns` through from the internal event struct — **no change** once `tcp_events.rs:164` populates the real value. Lines 203, 212, 224, 241, 263, 712, 719 — non-RX-origin events (timer fires, state changes, synthesized) — `rx_hw_ts_ns: 0` remains correct by definition and does not change. |
| `api.rs` | No change. Public `rx_hw_ts_ns` field at line 171 stays — semantics match parent §9.2. |

### 2.3 Modified modules (`crates/resd-net-core/` top-level)

| File | Change |
|---|---|
| `Cargo.toml` | New features + updated `default = [...]` list + `hw-offloads-all` meta-feature (Section 3). |

### 2.4 No new files

A-HW adds no new modules or files. Every change is in-place in an existing file.

### 2.5 Test files

| File | Change |
|---|---|
| `tests/knob-coverage.rs` | New entries for each build configuration in the CI matrix (Section 14). |
| `tests/ahw-smoke-*.rs` (new) | Three smoke tests per Section 12. May live under `crates/resd-net-core/tests/` or `tests/ffi-test/tests/` depending on whether they need the full FFI surface (leaning: Rust-side integration tests under `crates/resd-net-core/tests/` since none of them exercise the FFI boundary). Plan decides the final location. |

---

## 3. Feature flag matrix

`crates/resd-net-core/Cargo.toml` `[features]` additions:

| Feature flag | Default | Gates |
|---|---|---|
| `hw-verify-llq` | **ON** | Engine verifies LLQ activation at `engine_create` via PMD-log-scrape (Section 5) + fails hard if ENA advertised LLQ but LLQ did not activate. Feature-off compiles the verification branch + log callback + counter bump away entirely. The `enable_llq=X` PMD devarg stays **application-owned** (default is `enable_llq=1` in ENA PMD 23.11); the feature flag controls only the engine's verification discipline. |
| `hw-offload-tx-cksum` | **ON** | `RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM` bits in `txmode.offloads` + mbuf `ol_flags` + pseudo-header-only cksum in `tcp_output.rs` / `l3_ip.rs`. Runtime-fallback if PMD didn't advertise. Feature-off = software full-fold, no ol_flags bits, no runtime latch. |
| `hw-offload-rx-cksum` | **ON** | `RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM` bits in `rxmode.offloads` + `ol_flags` consumption in `tcp_input.rs` / `l3_ip.rs`. Feature-off = software verify unconditional. |
| `hw-offload-mbuf-fast-free` | **ON** | `RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE` bit in `txmode.offloads`. Feature-off = bit not set; no other code change. Precondition (all TX mbufs from same per-lcore mempool) already satisfied by parent §7.1. |
| `hw-offload-rss-hash` | **ON** | `RTE_ETH_RX_OFFLOAD_RSS_HASH` bit in `rxmode.offloads` + `rx_adv_conf.rss_conf` populated with `rss_hf = NONFRAG_IPV4_TCP | NONFRAG_IPV6_TCP`, `rss_key = NULL` (PMD default Toeplitz) + explicit `rte_eth_dev_rss_reta_update` to queue 0 post-start (forward-compat with multi-queue, redundant at single queue) + `mbuf.hash.rss` consumption in `flow_table.rs`. Feature-off = SipHash locally, no RSS config. |
| `hw-offload-rx-timestamp` | **ON** | `rte_mbuf_dynfield_lookup("rte_dynfield_timestamp")` + `rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp")` at `engine_create` → stored as `#[cfg]`-gated engine state (`ts_offset: Option<i32>`, `ts_flag_mask: Option<u64>`); always-inline `hw_rx_ts_ns(mbuf) -> u64` accessor; `tcp_events.rs:164` calls the accessor. Feature-off = `const fn hw_rx_ts_ns(_) -> u64 { 0 }`; no lookup; no engine state; event field stays 0. |

### 3.1 Meta-feature

`hw-offloads-all = ["hw-verify-llq", "hw-offload-tx-cksum", "hw-offload-rx-cksum", "hw-offload-mbuf-fast-free", "hw-offload-rss-hash", "hw-offload-rx-timestamp"]` — convenience for the A10 A/B harness and for CI builds that want to be explicit about the full set.

### 3.2 `default` list

```toml
default = [
    "obs-poll-saturation",
    "hw-verify-llq",
    "hw-offload-tx-cksum",
    "hw-offload-rx-cksum",
    "hw-offload-mbuf-fast-free",
    "hw-offload-rss-hash",
    "hw-offload-rx-timestamp",
]
```

### 3.3 Gate placement discipline

Feature gates live at the **code site**, never on a public ABI struct field. The engine-internal `EngineState` is not C ABI — fields under `#[cfg(feature = "hw-offload-rx-timestamp")]` are acceptable there. Public structs exposed through `resd_net.h` (`resd_net_event_t`, counters snapshot) never gain conditional fields. `EthCounters` counter fields are always-allocated even when the feature that writes to them is off (see Section 11).

A feature-off build compiles the offload code path away entirely — the binary is strictly smaller and does not execute offload-path instructions. This is what makes A10's A/B measurement valid (the "off" side genuinely does not pay the offload-setup cost).

---

## 4. engine.rs port-config upgrade

Replaces the current block at `engine.rs:422-450`. New flow at `engine_create`, in order:

1. Call `rte_eth_dev_info_get(port_id, &mut dev_info)`. If rc != 0, return `Error::PortInfo`.
2. Log one banner line: `resd_net: port {port_id} driver={driver_name} rx_offload_capa=0x{X} tx_offload_capa=0x{X} dev_flags=0x{X}`.
3. Build `requested_tx_offloads: u64` by ORing compile-time-enabled TX offload bits. Always include `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` (A5 retransmit prerequisite — unchanged).
4. Build `requested_rx_offloads: u64` by ORing compile-time-enabled RX offload bits.
5. For each compile-enabled offload bit:
   - If `(requested_bit & dev_info.*_offload_capa) == 0` → bump the corresponding `eth.offload_missing_<name>` one-shot counter; emit a WARN log; drop the bit from the applied mask.
6. Apply the AND-ed masks:
   - `eth_conf.txmode.offloads = (requested_tx_offloads & dev_info.tx_offload_capa)`.
   - `eth_conf.rxmode.offloads = (requested_rx_offloads & dev_info.rx_offload_capa)`.
7. If `hw-offload-rss-hash` is compile-enabled and RSS was in the applied mask: populate `eth_conf.rx_adv_conf.rss_conf = { rss_hf: RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP, rss_key: NULL, rss_key_len: 0 }`.
8. Latch per-engine runtime flags from the applied mask: `tx_cksum_offload_active: bool`, `rx_cksum_offload_active: bool`, `rss_hash_offload_active: bool`. These feed the runtime fallback branches in Sections 6 / 7 / 8.
9. Call `rte_eth_dev_configure(port_id, 1, 1, &eth_conf)`. (One RX queue, one TX queue — Stage 1 single-queue.)
10. Call `rte_eth_rx_queue_setup` / `rte_eth_tx_queue_setup` as today.
11. `#[cfg(feature = "hw-verify-llq")]`: register the LLQ-verify log callback (Section 5) before `rte_eth_dev_start`.
12. Call `rte_eth_dev_start`.
13. `#[cfg(feature = "hw-verify-llq")]`: unregister the log callback + inspect captured lines + fail-hard or bump `offload_missing_llq` per Section 5.
14. `#[cfg(feature = "hw-offload-rss-hash")]` + RSS was in applied mask: call `rte_eth_dev_rss_reta_update` to program every reta slot to queue 0. (Single-queue no-op in practice but explicit for forward-compat.)
15. `#[cfg(feature = "hw-offload-rx-timestamp")]`: perform the dynfield + dynflag lookups per Section 10; store on engine state; bump `offload_missing_rx_timestamp` if either lookup returned negative.
16. Log the final negotiated offload banner: `resd_net: port {port_id} configured rx_offloads=0x{X} tx_offloads=0x{X}` per parent §8.5.

Step 2 and step 16 are both informational — parent §8.5 mandates the startup log is the authoritative "what offload set is active" record.

---

## 5. LLQ activation verification

LLQ activation is ENA-internal state, not exposed through a clean DPDK API. A-HW detects it via PMD-log-scrape at bring-up, gated on `hw-verify-llq`.

### 5.1 Detection mechanism

1. Before `rte_eth_dev_start`, register a log callback. Implementation options:
   - `rte_openlog_stream(custom_stream)` — redirect RTE log output to a custom `FILE*`-backed memstream for the duration of bring-up.
   - Custom `rte_log_register_type_and_pick_level` for the ENA PMD component — narrower scope.
   
   Plan picks one. Leaning `rte_openlog_stream` for simplicity (ENA PMD uses the default RTE log stream; `fmemopen` + `fflush` around `rte_eth_dev_start` gives a captured buffer).
2. After `rte_eth_dev_start` returns (success only — a start failure unwinds before verification anyway), restore the original log stream.
3. Scan the captured buffer for ENA PMD's activation / failure markers:
   - Activation (DPDK 23.11 format): `"PMD: Placement policy: LLQ-aware"` or `"PMD: ENA LLQ mode: ..."` depending on device. Plan refines exact strings by reading `drivers/net/ena/ena_ethdev.c` before implementation.
   - Failure: `"LLQ is not supported by the device"` / `"Fallback to disabled LLQ is allowed"` / similar.
4. If `dev_info.driver_name != "net_ena"` → skip verification entirely (LLQ is ENA-specific).
5. If the driver is `net_ena` AND a failure marker appeared OR no activation marker appeared:
   - Bump `eth.offload_missing_llq`.
   - Return `Error::LlqActivationFailed` from `engine_create` — fail-hard per parent §8.4 Tier 1 "LLQ verified via PMD log + runtime dev-info check; startup fails if dev_info reports LLQ-capable but it did not activate."

### 5.2 Fragility mitigation

- Log format stability — DPDK 22.11 LTS and 23.11 LTS use the same ENA LLQ log lines. A future breakage fails the engine startup rather than silently running without LLQ — fail-safe direction. Plan includes a comment in engine.rs pointing to the exact ENA source reference, so a future DPDK upgrade surfaces the dependency.
- Log-capture scope — the memstream captures only during `rte_eth_dev_start`; other RTE log traffic before / after is unaffected.
- Non-ENA drivers — `driver_name` check in step 4 short-circuits; `net_vdev` / `net_tap` / `net_af_packet` never hit the LLQ-verify branch.
- Performance — `rte_openlog_stream` redirect + scan runs once at bring-up. Zero hot-path cost.

### 5.3 When `hw-verify-llq` is off

Entire block 11+13 of Section 4 compiles away. `engine_create` does not register a log callback, does not scan, and does not bump `offload_missing_llq`. Operators who want LLQ active are trusted to leave the ENA PMD default `enable_llq=1` in place (or pass it explicitly).

---

## 6. TX checksum offload

`#[cfg(feature = "hw-offload-tx-cksum")]` branch in `tcp_output.rs` (TCP segments) and `l3_ip.rs` (IPv4 header).

### 6.1 Engine-latched runtime flag

Per-engine `EngineState.tx_cksum_offload_active: bool` — latched at that engine's `engine_create` from the AND result in Section 4 step 8. True iff every one of `TX_OFFLOAD_IPV4_CKSUM`, `TX_OFFLOAD_TCP_CKSUM` was advertised by that engine's port AND compile-enabled. (UDP enters only if the tree has a UDP TX path at A-HW time — see 6.3.) Two engines bound to different ports with different capability sets maintain independent latches.

### 6.2 Feature-on segment build path

When `tx_cksum_offload_active == true`:
- Set `mbuf.ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM`.
- Set `mbuf.l2_len = 14` (Ethernet), `mbuf.l3_len = 20` (IPv4 no options — Stage 1 constant), `mbuf.l4_len = tcp_hdr_len`.
- Write the IPv4 header cksum field as 0 (the PMD computes it).
- Write the TCP cksum field as `tcp_pseudo_header_checksum(src_ip, dst_ip, tcp_seg_len)` — new helper in `l3_ip.rs`, computes the fold over the 12-byte pseudo-header only. PMD will fold the TCP header + payload into it.

When `tx_cksum_offload_active == false` (runtime fallback, e.g. on `net_tap`):
- Revert to the current software full-fold path (`internet_checksum` for IP header + `tcp_checksum_split` for TCP).
- Branch cost: one boolean load + conditional on the TX hot path. Acceptable because this path is only reached in test harnesses; production ENA latches to `true` at bring-up and stays there.

### 6.3 UDP analog

Decision deferred to the plan-writing pass. A-HW's job is to wire the UDP branch only if a UDP TX path exists in the tree at A-HW time. If not, UDP offload bits are omitted from `requested_tx_offloads`; `eth.offload_missing_tx_cksum_udp` stays 0 and is informational only.

### 6.4 Feature-off branch

Entire conditional compiles away. TX path is unconditionally software full-fold. No `ol_flags` bits, no runtime latch, no branch. Binary is strictly smaller.

---

## 7. RX checksum offload

`#[cfg(feature = "hw-offload-rx-cksum")]` branch in `l3_ip.rs::check_header` and `tcp_input.rs` (for the TCP L4 outcome).

### 7.1 Per-packet classification

When the feature is compile-enabled and `rx_cksum_offload_active == true`:
- Inspect `mbuf.ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK`:
  - `RTE_MBUF_F_RX_IP_CKSUM_GOOD` → skip IP software verify.
  - `RTE_MBUF_F_RX_IP_CKSUM_BAD` → drop packet, bump `eth.rx_drop_cksum_bad`, bump `ip.rx_csum_bad` (existing counter).
  - `RTE_MBUF_F_RX_IP_CKSUM_NONE` / `RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN` → software verify (current path).
- Same pattern for `RTE_MBUF_F_RX_L4_CKSUM_MASK` on TCP (and UDP if UDP RX path exists).

### 7.2 Feature-off or runtime-fallback

Software verify always (current path). No `ol_flags` read. `rx_cksum_offload_active` latch is bypassed when the feature is off.

---

## 8. RSS hash offload

`#[cfg(feature = "hw-offload-rss-hash")]` branch in `flow_table.rs` at the lookup site (and `engine.rs` at port-config).

### 8.1 Port-config (Section 4 step 7 + step 14)

- `rx_adv_conf.rss_conf.rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP`.
- `rx_adv_conf.rss_conf.rss_key = NULL` (PMD default Toeplitz).
- `rx_adv_conf.rss_conf.rss_key_len = 0`.
- After `rte_eth_dev_start`, call `rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size)` with every slot pointing at queue 0. `reta_size` taken from `dev_info.reta_size`.
- At single queue this is a no-op from a traffic-steering perspective, but it makes the hashed value present on `mbuf.hash.rss` for flow-table consumption, and it's forward-compat for multi-queue (out of Stage 1 scope).

### 8.2 Per-packet read (`flow_table.rs`)

When `rss_hash_offload_active == true` AND `mbuf.ol_flags & RTE_MBUF_F_RX_RSS_HASH != 0`:
- Use `mbuf.hash.rss` as the initial 32-bit bucket index.

Otherwise (including feature-off build, runtime-fallback, or unset RSS flag):
- Compute SipHash over the 4-tuple locally (current path).

### 8.3 Feature-off branch

`rx_adv_conf.rss_conf` stays zeroed; `RSS_HASH` bit is not in `requested_rx_offloads`; reta is not programmed; `flow_table.rs` always uses SipHash.

---

## 9. MBUF_FAST_FREE

`#[cfg(feature = "hw-offload-mbuf-fast-free")]` is the narrowest feature. Single bit in `txmode.offloads`, no other code change.

- Port-config: `requested_tx_offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE`.
- If not advertised by PMD: bump `eth.offload_missing_mbuf_fast_free`, drop bit from applied mask.
- TX-completion path is unchanged; PMD consumes the bit internally.

Precondition (all TX mbufs from same per-lcore mempool) is already satisfied by parent §7.1.

Feature-off: bit never requested.

---

## 10. RX timestamp

`#[cfg(feature = "hw-offload-rx-timestamp")]` block in `engine.rs` + `tcp_events.rs`.

### 10.1 Lookup at `engine_create`

Section 4 step 15:
- `let ts_offset = rte_mbuf_dynfield_lookup(b"rte_dynfield_timestamp\0".as_ptr() as *const c_char, ptr::null_mut());` → `i32`. If `< 0`, store `None`.
- `let ts_flag_mask = rte_mbuf_dynflag_lookup(b"rte_dynflag_rx_timestamp\0".as_ptr() as *const c_char, ptr::null_mut());` — returns bit position; convert to `1 << pos` and store `Some(mask)`. If `< 0`, store `None`.
- If either returned `None`: bump `eth.offload_missing_rx_timestamp` once. **On ENA this is the expected steady state** — the counter being 1 on ENA is the documented ground truth, not an anomaly. Parent §8.3 + §9.2 establish this.
- Store on `EngineState` under `#[cfg(feature = "hw-offload-rx-timestamp")]`:
  ```rust
  #[cfg(feature = "hw-offload-rx-timestamp")]
  ts_offset: Option<i32>,
  #[cfg(feature = "hw-offload-rx-timestamp")]
  ts_flag_mask: Option<u64>,
  ```

### 10.2 Inline accessor

Always-inline method on the engine (or a free function that takes the two `Option`s):

```rust
#[cfg(feature = "hw-offload-rx-timestamp")]
#[inline(always)]
fn hw_rx_ts_ns(&self, mbuf: *const sys::rte_mbuf) -> u64 {
    match (self.ts_offset, self.ts_flag_mask) {
        (Some(off), Some(mask)) => unsafe {
            let ol_flags = (*mbuf).ol_flags;
            if ol_flags & mask != 0 {
                *((mbuf as *const u8).offset(off as isize) as *const u64)
            } else {
                0
            }
        },
        _ => 0,
    }
}

#[cfg(not(feature = "hw-offload-rx-timestamp"))]
#[inline(always)]
const fn hw_rx_ts_ns(_mbuf: *const sys::rte_mbuf) -> u64 { 0 }
```

Hot-path cost when feature is on: one conditional + one `u64` load. When feature is off: zero — the call is a const folded to 0.

### 10.3 Call sites

Two RX-originated event sites hardcode `rx_hw_ts_ns: 0` in production code today:

- **`engine.rs:1842`** — `InternalEvent::Connected` emitted after the SYN-ACK parse in the main RX handler. The parsed segment's originating mbuf is available in local scope at the emit site; a direct `self.hw_rx_ts_ns(mbuf)` call reads the NIC timestamp at this point.
- **`engine.rs:2205`** — `InternalEvent::Readable` emitted inside `deliver_readable(&self, handle, delivered: u32)`. The originating mbuf is NOT in scope here — data has already been moved from the mbuf into `conn.recv.bytes` VecDeque by the time this function is called. Therefore the `hw_rx_ts_ns` value must be captured at the RX-decode boundary (where the mbuf is live) and passed through as a new parameter to `deliver_readable(&self, handle, delivered, hw_rx_ts_ns)`.

The internal `InternalEvent::Connected` / `InternalEvent::Readable` enum variants already carry the `rx_hw_ts_ns: u64` field (A5.5 introduced it on the forwarder side). Only the two engine-side sites above need their hardcoded `0` replaced with the threaded-through value.

Other `rx_hw_ts_ns: 0` sites that stay unchanged:
- `tcp_events.rs:164` — unit-test fixture inside `#[cfg(test)] mod tests`, not production code.
- `crates/resd-net/src/lib.rs:175-191` — public-event forwarder, already threads from the internal event variant, no hardcoded zero.
- `crates/resd-net/src/lib.rs:203, 212, 224, 241, 263, 712, 719` — non-RX-origin events (timer fires, state changes, synthesized ARP exchange events). They stay 0 by definition; the accessor is not called from those sites.
- `crates/resd-net-core/tests/*.rs` — test fixtures, unchanged.

### 10.4 Feature-off branch

No dynfield lookup at `engine_create`. No engine state. `const fn hw_rx_ts_ns(_) -> u64 { 0 }` folds to constant at every call site. All `rx_hw_ts_ns` fields in every event stay 0 by construction. `offload_missing_rx_timestamp` counter is never incremented (but the field stays on `EthCounters` for C-ABI stability).

### 10.5 On ENA (reference Stage 1 target)

Both lookups return negative (ENA PMD does not register the dynfield). Accessor always yields 0. `rx_hw_ts_ns = 0` in every event. `eth.offload_missing_rx_timestamp = 1` after bring-up — documented steady state per parent §8.3 / §9.2. Callers use `enqueued_ts_ns` per parent §7.5. This is the exercised path in Stage 1 smoke tests; the positive path is reachable but not asserted until Stage 2 hardening on a PMD that registers the dynfield.

---

## 11. Counter surface

Additions to `EthCounters` in `crates/resd-net-core/src/counters.rs`. All slow-path per parent §9.1.1. Fields are **always allocated** regardless of feature flags (C-ABI stability of the counters snapshot).

| Counter | Fires when | Expected steady state |
|---|---|---|
| `eth.offload_missing_rx_cksum_ipv4` | `hw-offload-rx-cksum` compile-enabled AND `RX_OFFLOAD_IPV4_CKSUM` not advertised | 0 on ENA; 1 on `net_vdev` / `net_tap` |
| `eth.offload_missing_rx_cksum_tcp` | same, for TCP | 0 on ENA; 1 on non-advertising PMD |
| `eth.offload_missing_rx_cksum_udp` | same, for UDP | 0 on ENA; 1 on non-advertising PMD |
| `eth.offload_missing_tx_cksum_ipv4` | `hw-offload-tx-cksum` compile-enabled AND `TX_OFFLOAD_IPV4_CKSUM` not advertised | 0 on ENA; 1 on non-advertising PMD |
| `eth.offload_missing_tx_cksum_tcp` | same, for TCP | 0 on ENA; 1 on non-advertising PMD |
| `eth.offload_missing_tx_cksum_udp` | same, for UDP | 0 on ENA; 1 on non-advertising PMD |
| `eth.offload_missing_mbuf_fast_free` | `hw-offload-mbuf-fast-free` compile-enabled AND `TX_OFFLOAD_MBUF_FAST_FREE` not advertised | 0 on ENA; 1 on non-advertising PMD |
| `eth.offload_missing_rss_hash` | `hw-offload-rss-hash` compile-enabled AND `RX_OFFLOAD_RSS_HASH` not advertised | 0 on ENA; 1 on non-advertising PMD |
| `eth.offload_missing_llq` | `hw-verify-llq` compile-enabled AND driver is `net_ena` AND LLQ activation failure marker appeared in PMD log during `rte_eth_dev_start` | **0 on ENA** with default `enable_llq=1`; 1 on ENA when operator passed `enable_llq=0` OR on a device whose hardware does not support LLQ |
| `eth.offload_missing_rx_timestamp` | `hw-offload-rx-timestamp` compile-enabled AND (`rte_mbuf_dynfield_lookup` OR `rte_mbuf_dynflag_lookup` returned negative) | **1 on ENA** (documented steady state — ENA does not register the dynfield); 0 on mlx5 / ice / future-gen ENA |
| `eth.rx_drop_cksum_bad` | Per packet where NIC reported `RTE_MBUF_F_RX_IP_CKSUM_BAD` or `RTE_MBUF_F_RX_L4_CKSUM_BAD` | 0 on well-formed traffic; nonzero only under actual corruption — a real per-packet drop counter, not an offload-missing counter |

### 11.1 Hot-path classification

Only `eth.rx_drop_cksum_bad` is hot-path-eligible. It's still **slow-path-only** by policy (fires only on actual bad checksums, which is not the steady-state path) — a single `fetch_add` per bad packet is well below the noise floor on the RX path.

All `offload_missing_*` counters are one-shot bring-up counters — parent §9.1.1 slow-path category.

### 11.2 C-ABI stability

These fields appear on `EthCounters`, which is exposed through `resd_net_counters_snapshot` (follow-up: confirm the exact public snapshot struct layout during plan-writing). The struct layout must remain stable across all 8 builds in the CI matrix — a feature-off build must not change the field offsets. Implemented by making every new field `#[cfg]`-unconditional on the struct definition; only the **writes** to them are `#[cfg]`-gated.

---

## 12. Smoke tests

Three distinct runs, each with explicit counter-value assertions.

### 12.1 SW-fallback (default features on `net_tap`)

Build: `cargo build --release` (default features).
Run on: A3's TAP-pair harness (`net_tap` PMD).

Assertions:
- Full request-response cycle passes correctness (same oracle as A3 TAP-pair smoke).
- Every event's `rx_hw_ts_ns == 0` (`net_tap` doesn't register the dynfield, accessor yields 0).
- `eth.offload_missing_rx_cksum_*` = 1 each if net_tap doesn't advertise the capability (exact values pinned during plan-writing by running `dev_info_get` on the A3 TAP-pair harness and recording the advertised mask).
- `eth.offload_missing_tx_cksum_*` = 1 each under the same condition.
- `eth.offload_missing_mbuf_fast_free` = 1 if not advertised.
- `eth.offload_missing_rss_hash` = 1 if not advertised.
- `eth.offload_missing_llq` = 0 (driver is not `net_ena`, verification skipped).
- `eth.offload_missing_rx_timestamp` = 1 (dynfield absent).
- `eth.rx_drop_cksum_bad` = 0 (well-formed test traffic).

### 12.2 SW-only (`--no-default-features`)

Build: `cargo build --release --no-default-features`.
Run on: same A3 TAP-pair harness.

Assertions:
- Full request-response cycle passes correctness.
- Every event's `rx_hw_ts_ns == 0` (by construction — accessor is `const fn`).
- All `eth.offload_missing_*` = 0 (feature-off → no verification, no counter bump).
- `eth.rx_drop_cksum_bad` = 0.

Confirms the feature-off branch compiles + runs correctly.

### 12.3 HW-path (default features on ENA VF)

Build: `cargo build --release` (default features).
Run on: real ENA VF on the Stage 1 deployment host.

Assertions:
- Full request-response cycle passes correctness.
- Startup banner logged with advertised + negotiated offload masks.
- Every event's `rx_hw_ts_ns == 0` (ENA dynfield-absent steady state).
- All `eth.offload_missing_*` = 0 **except** `eth.offload_missing_rx_timestamp == 1`.
- `eth.offload_missing_llq = 0` (ENA default `enable_llq=1`).
- `eth.rx_drop_cksum_bad = 0`.

---

## 13. CI feature matrix (8 builds)

Every build is `cargo build --release`. Also runs `cargo test` where it doesn't require an ENA VF.

| Build | Features |
|---|---|
| 1 | default (all on) |
| 2 | `--no-default-features` |
| 3 | `--no-default-features --features "obs-poll-saturation,hw-offload-tx-cksum,hw-offload-rx-cksum,hw-offload-mbuf-fast-free,hw-offload-rss-hash,hw-offload-rx-timestamp"` (hw-verify-llq OFF; rest ON) |
| 4 | `--no-default-features --features "obs-poll-saturation,hw-verify-llq,hw-offload-rx-cksum,hw-offload-mbuf-fast-free,hw-offload-rss-hash,hw-offload-rx-timestamp"` (hw-offload-tx-cksum OFF) |
| 5 | `--no-default-features --features "obs-poll-saturation,hw-verify-llq,hw-offload-tx-cksum,hw-offload-mbuf-fast-free,hw-offload-rss-hash,hw-offload-rx-timestamp"` (hw-offload-rx-cksum OFF) |
| 6 | `--no-default-features --features "obs-poll-saturation,hw-verify-llq,hw-offload-tx-cksum,hw-offload-rx-cksum,hw-offload-rss-hash,hw-offload-rx-timestamp"` (hw-offload-mbuf-fast-free OFF) |
| 7 | `--no-default-features --features "obs-poll-saturation,hw-verify-llq,hw-offload-tx-cksum,hw-offload-rx-cksum,hw-offload-mbuf-fast-free,hw-offload-rx-timestamp"` (hw-offload-rss-hash OFF) |
| 8 | `--no-default-features --features "obs-poll-saturation,hw-verify-llq,hw-offload-tx-cksum,hw-offload-rx-cksum,hw-offload-mbuf-fast-free,hw-offload-rss-hash"` (hw-offload-rx-timestamp OFF) |

Every `#[cfg(not(feature = "hw-*"))]` branch compiles in exactly one build. `obs-poll-saturation` is always on in non-default-features builds to match the pre-A-HW `default`.

---

## 14. Knob-coverage audit

New entries in `crates/resd-net-core/tests/knob-coverage.rs` for every row in Section 13's CI matrix. Each entry asserts the expected feature-gating outcome (e.g. which struct fields exist on the engine, whether the RX-timestamp accessor is `const fn`, whether the RSS-hash code path is present). Same pattern as A5.5 knob-coverage entries.

---

## 15. Out of scope (explicit)

- Multi-queue enablement. RSS indirection-table reprogramming to spread across queues is deferred to Stage 2. RSS config + single-queue reta program are wired at A-HW for forward-compat.
- Header/data split, TSO, GRO, GSO — Tier 3 per parent §8.4.
- General RX scatter at MTU 1500. (Retransmit's header-mbuf-chained-to-data-mbuf pattern keeps `MULTI_SEGS` on TX — A5 dependency, unchanged by A-HW.)
- Hot-path "offload used" per-segment counters. Startup log is authoritative per parent §8.5 / §9.1.1.
- Positive-path HW-timestamp assertion. Stage 1 smoke exercises the dynfield-absent path only. Stage 2 hardening on a non-ENA PMD that registers the dynfield closes this.
- Measurement of actual offload benefit. A10's `tools/bench-offload-ab/` rebuilds with each feature-flag combination and produces the p50/p99/p999 A/B comparison that drives the final keep/remove decision per offload.
- A6 scope: timer API, `WRITABLE`, close flags with RFC 6191 guard, poll-overflow queueing, mempool-exhaustion error paths, preset runtime switch, RTT histogram.

---

## 16. Ship gate

`phase-a-hw-complete` tag requires **all** of the following:

1. `cargo test` green on default features (catches unit-test regressions).
2. Section 12.1 SW-fallback smoke green.
3. Section 12.2 SW-only smoke green.
4. Section 12.3 HW-path smoke green on ENA VF.
5. Section 13's 8-build CI matrix all green.
6. Section 14's knob-coverage entries present and asserting correctly.
7. mTCP comparison review report at `docs/superpowers/reviews/phase-a-hw-mtcp-compare.md` shows zero open `[ ]`.
8. RFC compliance review report at `docs/superpowers/reviews/phase-a-hw-rfc-compliance.md` shows zero open `[ ]`.

The final kept-vs-removed decision per offload is **not** gated at phase-a-hw — that's A10's job once the A/B benchmark data exists.

The tag is not pushed by A-HW's session; coordinator merges + tags + pushes.

---

## 17. Updates to parent spec `2026-04-17-dpdk-tcp-design.md`

A-HW makes minor clarifying edits to parent spec sections; does **not** restructure §8.

- §8.4 Tier 1 list: update "LLQ verified via PMD log" reference to point at this spec's Section 5 for the concrete detection mechanism.
- §8.4 feature-flag naming: change `hw-offload-llq` → `hw-verify-llq` throughout §8.4 (plus roadmap §A-HW row + A10 deliverables that reference it), reflecting the verification-only semantics locked during A-HW brainstorming.
- §9.2 `rx_hw_ts_ns` section: add a pointer to Section 10 of this spec for the implementation detail.

All parent-spec edits land in the same commit series as the A-HW implementation.

---

## 18. Risks / open items for the plan-writing pass

- Exact ENA PMD log-line strings for LLQ activation / failure (Section 5.1 step 3). Plan inspects `drivers/net/ena/ena_ethdev.c` in the DPDK 23.11 source tree to lock the literal strings before implementation.
- Whether `tcp_events.rs:164` receives the mbuf pointer directly or whether the timestamp must be read at the RX-decode boundary and threaded through the internal event struct (Section 10.3). Lean threaded-through.
- UDP TX path presence at A-HW time (Section 6.3). If no UDP TX exists today, the UDP-cksum offload branch is not wired; `offload_missing_tx_cksum_udp` is only meaningful for RX.
- Test harness location — `crates/resd-net-core/tests/` vs `tests/ffi-test/tests/` for the three smoke tests (Section 2.5). Plan picks; leaning core/tests since none need the FFI boundary.
- Confirm `EthCounters` is the right home for `offload_missing_llq` (LLQ isn't an "eth-offload" conceptually; it's an ENA PMD-internal mode). Alternative: a new `HwCounters` group. Plan decides; leaning `EthCounters` for consistency with the other `offload_missing_*` counters.
- Confirm the exact `resd_net_counters_snapshot` public struct layout the new `EthCounters` fields need to flow through (Section 11.2). Plan locks field ordering + gaps to maintain C-ABI stability against the A5.5-complete baseline.
- Pinned exact expected counter values for Section 12.1 (SW-fallback on `net_tap`). Plan captures the advertised mask from a live `dev_info_get` and bakes the expected values into the smoke-test assertions.

---

**End of spec.**
