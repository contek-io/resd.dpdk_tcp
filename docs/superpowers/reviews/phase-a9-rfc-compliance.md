# Phase A9 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent (opus 4.7)
- Date: 2026-04-21
- RFCs in scope: 9293 (§3.10.7.4 FIN), 7323 (§5 PAWS), 8985 (§6.1-§6.3 RACK-TLP), 2018 (SACK), 1982 / 9293 §3.4 (wrap-safe seq)
- Our commit: `cf5cfb23b2322c60e311da460bb0ac756705d16a`
- Branch point: `phase-a6-6-7-complete` at `2c4e0b6`

## Scope

- Files reviewed:
  - `crates/dpdk-net-core/src/tcp_input.rs` — I-8 fix site (~line 1207-1225)
  - `crates/dpdk-net-core/tests/i8_fin_piggyback_chain.rs` — directed regression (NEW)
  - `crates/dpdk-net-core/src/fault_injector.rs` — FaultInjector middleware (NEW, feature-gated)
  - `crates/dpdk-net-core/src/engine.rs` — `inject_rx_frame`, `inject_rx_chain`, `dispatch_one_rx_mbuf` split, fault-injector wiring
  - `crates/dpdk-net-core/src/counters.rs` — `FaultInjectorCounters` struct (always-present on C ABI; populated only when feature on)
  - `crates/dpdk-net-core/src/lib.rs` — feature gates for `fault_injector` and `test-inject`
  - `crates/dpdk-net-core/Cargo.toml` — `test-inject` + `fault-injector` cargo features (default off)
  - `crates/dpdk-net-core/tests/proptest_paws.rs` — RFC 7323 §5 PAWS (NEW)
  - `crates/dpdk-net-core/tests/proptest_tcp_sack.rs` — RFC 2018 SACK scoreboard (NEW)
  - `crates/dpdk-net-core/tests/proptest_tcp_seq.rs` — RFC 1982 / RFC 9293 §3.4 wrap-safe seq (NEW)
  - `crates/dpdk-net-core/tests/proptest_rack_xmit_ts.rs` — RFC 8985 §6.1-§6.3 RACK-TLP (NEW)
  - `crates/dpdk-net-core/tests/proptest_tcp_options.rs` — RFC 7323/2018/9293 option round-trip (NEW)
  - `crates/dpdk-net-core/tests/proptest_tcp_reassembly.rs` — reassembly invariants (NEW)
  - `crates/dpdk-net-core/fuzz/fuzz_targets/*.rs` — 7 cargo-fuzz targets (NEW; T1 + T1.5)
  - `tools/scapy-corpus/scripts/i8_fin_piggyback_multi_seg.py` — directed I-8 pcap (NEW)
  - `tools/scapy-fuzz-runner/` — pcap replay via `inject_rx_frame` (NEW)
  - `tools/scapy-corpus/scripts/*.py` — 5 other adversarial scripts (NEW)
  - `scripts/fuzz-smoke.sh`, `scripts/fuzz-long-run.sh`, `scripts/scapy-corpus.sh` (NEW, CI harness)

- Spec §6.3 rows verified (unchanged-claim verification):
  - RFC 9293 §3.10.7.4 (segment processing / FIN handling) — I-8 closure restores MUST behaviour on the multi-seg / OOO-drain chain path.
  - RFC 7323 §5 (PAWS) — inline gate in `tcp_input::dispatch`; `proptest_paws` encodes the §5 "strictly older rejected, equal accepted" rule against the same `tcp_seq::seq_lt` primitive the gate uses.
  - RFC 8985 §6.1-§6.3 (RACK `xmit_ts` monotonicity, detect-lost newest-wins, RACK_mark_losses_on_RTO idempotence) — `proptest_rack_xmit_ts` pins the pure helpers; no production-path behaviour change from A9.
  - RFC 2018 (SACK scoreboard non-overlap / non-touching / byte coverage) — `proptest_tcp_sack` verifies the four stored invariants (`SackScoreboard::insert` merge + `collapse` to fixed point).
  - RFC 1982 / RFC 9293 §3.4 (wrap-safe seq comparator asymmetric 2^31 window) — `proptest_tcp_seq` asserts reflexivity, irreflexivity, asymmetry (with the `0x8000_0000` antipode carve-out), and `in_window` boundary.

- Spec §6.4 deviations touched: **none changed by A9**. The standing deviations (Nagle off, delayed-ACK off, minRTO=5ms, maxRTO=1s, CC off-by-default, TFO disabled, AD-A5-5-srtt-from-syn, AD-A5-5-rack-mark-losses-on-rto, AD-A5-5-tlp-arm-on-send, AD-A5-5-tlp-pto-floor-zero, AD-A5-5-tlp-multiplier-below-2x, AD-A5-5-tlp-skip-flight-size-gate, AD-A5-5-tlp-multi-probe, AD-A5-5-tlp-skip-rtt-sample-gate, AD-A6-force-tw-skip) remain in force unmodified. `preset=rfc_compliance` is NOT introduced in A9 (deferred to S2-A per the brainstorm).

## Findings

### Must-fix (MUST/SHALL violation)

None introduced by A9. The one MUST gap open at end of A6.6-7 (I-8) is closed by this phase — see FYI I-1 below.

### Missing SHOULD (not in §6.4 allowlist)

None introduced by A9.

### Accepted deviation (covered by spec §6.4)

No new accepted-deviation entries. A9 is a test / fuzz / middleware phase — no wire behaviour change in default builds.

### FYI (informational — no action)

- **I-1** — **I-8 from `phase-a6-6-7-rfc-compliance.md` is CLOSED.** The FIN-piggyback equality at `crates/dpdk-net-core/src/tcp_input.rs:1221` now reads:

  ```rust
  if (seg.flags & TCP_FIN) != 0 && seg.seq.wrapping_add(delivered) == conn.rcv_nxt
  ```

  `delivered` is the running total of bytes accepted for this segment — head-link TCP payload (`head_take`, line 960), each chain-tail link take (`link_take` accumulated at line 1022 via `saturating_add`), AND any OOO-drained bytes appended on gap-close (line 1063 `delivered += drained_bytes`). On a single-seg + no-drain path, `delivered == seg.payload.len() as u32` so the new expression is bit-for-bit identical to the pre-fix one — the common path is untouched.

  RFC clause restored: `docs/rfcs/rfc9293.txt:3888` — "If the FIN bit is set, ... advance RCV.NXT over the FIN, and send an acknowledgment for the FIN. ... ESTABLISHED STATE + Enter the CLOSE-WAIT state." (§3.10.7.4, Eighth check the FIN bit.)

  Directed regression at `crates/dpdk-net-core/tests/i8_fin_piggyback_chain.rs` (196 lines, two test cases). The `fin_piggyback_with_chain_total_advances_to_close_wait` case genuinely exercises the bug: pre-stages an OOO segment at seq=5004 with 7 bytes, then dispatches an in-order FIN+ACK at seq=5001 with 3 bytes of head payload. The dispatch drains the OOO segment on gap-close, producing `delivered == 3 + 7 == 10` while `seg.payload.len() == 3`. Pre-fix equality: `5001 + 3 = 5004 ≠ 5011` → FIN dropped, FSM stays ESTABLISHED. Post-fix: `5001 + 10 = 5011` → FIN consumed, `rcv_nxt` advances to 5012, new_state = CLOSE_WAIT, `TxAction::Ack` emitted. This is semantically identical to the multi-seg LRO chain shape the spec described (both paths produce `delivered > seg.payload.len()`), and avoids the significantly heavier infrastructure of driving a real TAP-backed handshake to ESTABLISHED through `inject_rx_chain`. Sanity case `fin_piggyback_single_seg_unchanged_after_fix` guards the common single-seg path (no payload, no drain, `delivered == 0`, equality still matches). I-8 FYI is now CLOSED.

- **I-2** — **`preset=rfc_compliance` not introduced.** Per spec §1 and A9 brainstorm decision D1, the RFC-compliance preset is deferred to S2-A (combined with Layer G WAN A/B). A9 therefore adds zero new rows to spec §6.4. The standing trading-latency deviations remain in effect across default builds; no wire behaviour change in this phase.

- **I-3** — **Scapy adversarial corpus does not change production behaviour.** Six `tools/scapy-corpus/scripts/*.py` scripts generate deterministic pcaps that the Rust runner `tools/scapy-fuzz-runner/` replays via `engine.inject_rx_frame(frame)` against a test-inject-feature-on build. The frames are synthetic adversarial inputs (overlapping segments, malformed options, TS wraparound, SACK outside-window, RST invalid-seq, multi-seg FIN piggyback). Runner asserts no panic + invariant set from spec §6 (`snd.una ≤ snd.nxt`, `rcv_wnd` monotonic, FSM legal states, mbuf refcount balance). The stack's response to these inputs is produced by unmodified `tcp_input` / `tcp_output` code — RFC-compliant by the same audit the per-phase reviews already approved.

- **I-4** — **Test-inject hook preserves RFC semantics by construction.** `Engine::inject_rx_frame` and `Engine::inject_rx_chain` (behind `#[cfg(feature = "test-inject")]`, default off) allocate an mbuf from a dedicated lazy test-inject mempool, copy the caller's frame bytes in, and call `self.dispatch_one_rx_mbuf(mbuf)` — the same private method the production poll loop calls at `engine.rs:1978` (`for &m in &mbufs[..n] { ... self.dispatch_one_rx_mbuf(mbuf); }`). Cbindgen runs without the feature so neither method appears in `dpdk_net.h`; release-build artifacts are byte-identical to A6.6-7. No RFC clause is reachable through this surface that isn't already reachable through the real RX path.

- **I-5** — **FaultInjector changes what the stack SEES, not what it EMITS.** `FaultInjector::process` (behind `#[cfg(feature = "fault-injector")]`, default off) sits between `rte_eth_rx_burst` and L2 decode in `dispatch_one_rx_mbuf` (`engine.rs:2845-2856`). The four actions — drop (free the mbuf, emit nothing), duplicate (refcount +1, emit twice), reorder (hold in 16-slot bounded ring with FIFO eviction, lazy init), corrupt (single-byte XOR at random in-bounds offset before any emit) — operate on the inbound mbuf only. The TX path is untouched. From the RFC-compliance perspective this is equivalent to inserting a lossy/duplicating/corrupting link between the PMD and our stack: RFC responses generated in reaction (dup-ACKs on OOO receive, RST on invalid seq, PAWS reject on stale TS echoed into the corrupt-flipped payload) are produced by unmodified `tcp_input` / `tcp_output` code. Furthermore the FaultInjector's `Drop` impl frees any mbufs still held in the reorder ring at shutdown (`fault_injector.rs:337-343`), preserving mbuf refcount balance (spec §6 invariant #5). Feature-off builds carry zero bytes of FaultInjector code; counters (`FaultInjectorCounters`) are present on the C ABI but never incremented.

- **I-6** — **Six proptest suites correctly encode their RFC invariants.**
  - **`proptest_paws.rs`** (RFC 7323 §5). Pins the §5 rule by composing seven properties on top of the same `tcp_seq::seq_lt` primitive the inline PAWS gate at `tcp_input.rs` uses. `strictly_older_is_rejected` is the direct §5 clause (`docs/rfcs/rfc7323.txt` §5: "If SEG.TSval < TS.Recent ... the segment is not acceptable"). `equal_is_accepted` pins the "strictly" boundary (retransmits echo TSval unchanged). `forward_half_window_is_accepted` / `backward_half_window_is_rejected` cover the 2^31 asymmetric window and its wrap. `accept_is_exactly_not_seq_lt` is the 1-line rule cross-check. The test doc correctly notes the §5.5 24-day idle-expiry branch is orthogonal and has its own directed coverage in `tcp_input.rs`.
  - **`proptest_tcp_sack.rs`** (RFC 2018). Four properties: capacity bounded at `MAX_SACK_SCOREBOARD_ENTRIES=4` (I1), pairwise disjoint AND non-touching half-open ranges (I2 — `insert` merges adjacent blocks; `collapse` runs the merge loop to fixed point), coverage ⊂ input union (I3a — no phantom bytes after eviction), coverage == input union when input fits (I3b — eviction cannot fire). The disjoint-with-gap assertion (`a.right < b.left || b.right < a.left`) correctly matches the spec's "adjacent blocks must merge" contract.
  - **`proptest_rack_xmit_ts.rs`** (RFC 8985 §6.1-§6.3). Six properties. `xmit_ts_monotonic_across_retransmits` models the engine's retransmit-update clause (CLOCK_MONOTONIC_COARSE never moves backward). `rack_update_on_ack_xmit_ts_monotonic` pins §6.1 "RACK.xmit_ts tracks the latest acknowledged transmit time". `detect_lost_false_when_entry_newer_than_rack` is the direct §6.1 "newer by delivery order is not lost" clause. `detect_lost_idempotent` and `rack_mark_losses_on_rto_idempotent` pin the §6.2/§6.3 rules as pure (no hidden state). `rack_update_on_ack_adopts_newer_xmit_ts` pins the exact-value contract. All six exercise the actual `RackState` + `rack_mark_losses_on_rto` functions from `tcp_rack.rs`.
  - **`proptest_tcp_seq.rs`** (RFC 1982 / RFC 9293 §3.4). Five properties. `seq_le_reflexive`, `seq_lt_irreflexive`, `lt_implies_le` are the total-order axioms. `lt_asymmetric` correctly excludes the `0x8000_0000` antipode where both `a < b` and `b < a` reinterpret to `i32::MIN` under the 2^31 asymmetric-window rule — this is the exact edge the RFC 1982 / RFC 9293 §3.4 comparator is undefined for; the carve-out was explicitly added at commit `786e985` (a9 task 18 fixup). `in_window_boundary` tests `[start, start+len)` at `len=1..=2^31`.
  - **`proptest_tcp_options.rs`** (RFC 7323 + RFC 2018 + RFC 9293 §3.1). Three properties: `decode_never_panics` on arbitrary bytes, `round_trip_identity` for well-formed `TcpOpts` that fit in the 40-byte budget, `encode_decode_encode_idempotent` fixed-point. The `arb_tcp_opts` strategy correctly constrains `wscale` to `0..=14` (no clamp — `ws_clamped` is a decode-side signal not present in the encoded bytes) and `sack_block_count` to `0..=MAX_SACK_BLOCKS_DECODE=4` per RFC 2018 §3.
  - **`proptest_tcp_reassembly.rs`** (internal bookkeeping, not a user-facing RFC but supports §3.7/§3.10.7.4 in-order delivery). Five properties over `ReorderQueue`: strict seq-ordering + pairwise disjointness (I1), `total_bytes()` == sum of stored lengths (I2), `total_bytes() <= cap` (I3), insert byte accounting bounded (I4 — `newly_buffered + cap_dropped <= payload.len()`), drain contiguous + bounded (I5/I6), gap-bytes monotonically non-increasing under fixed span (I7), cap is a hard limit. FakeMbuf pattern correctly mirrors the inline reassembly tests.

- **I-7** — **Seven cargo-fuzz targets do not change production behaviour.** `crates/dpdk-net-core/fuzz/` is a cargo-fuzz subdirectory outside the main workspace (per cargo-fuzz convention). Six T1 pure-module targets (`tcp_options`, `tcp_sack`, `tcp_reassembly`, `tcp_state_fsm`, `tcp_seq`, `header_parser`) drive pure functions; one T1.5 persistent target (`engine_inject`) builds a real Engine once via existing test fixtures and per-iter calls `inject_rx_frame`. Nightly Rust is pinned in `crates/dpdk-net-core/fuzz/rust-toolchain.toml` only — the main workspace stays on stable per `feedback_rust_toolchain`. No new RFC-behaviour surface.

- **I-8** — **Merges from master pulled bug_008 + bug_010 into the diff range; neither is an A9 change, neither introduces a new RFC deviation.** `git log phase-a6-6-7-complete..HEAD` shows `a5be920` (bug_008 fix: RACK RTO age check stays in u64 ns to avoid u32 µs wrap) and `7388f7d` (bug_010 → feature: per-connection source-IP binding). Both landed on master between the A6.6-7 tag and the A9 branch start, then came in via the `a94232f` / `41fa4b7` merges. bug_008 is an RFC 8985 §6.3 compliance *improvement* (u32 µs saturating_add silently dropped age expirations every ~71 min; u64 ns saturating_sub wraps only every ~584 years). bug_010 is a feature addition (dual-NIC EC2 source-IP binding via `dpdk_net_connect_opts_t.local_addr`); no wire-format / FSM / RFC-behaviour change. Neither requires a new §6.4 entry.

- **I-9** — **No new rows needed in spec §6.4.** Verified by inspection of the §6.4 table and the A9 diff. The phase introduces: two feature-gated middleware surfaces (test-inject + fault-injector), both default off, both absent from release-build artifacts and the cbindgen-generated C header; 6 proptest suites + 7 cargo-fuzz targets (all test-only); 6 Scapy scripts + runner (all test-only); 3 CI scripts; an I-8 fix in `tcp_input.rs` that RESTORES RFC 9293 §3.10.7.4 MUST behaviour; a directed regression test for I-8. None of these change the wire semantics of a default build.

## Verdict

**PASS**

Wire bytes unchanged across A9 in default builds. The only production-path change in `tcp_input.rs` is the I-8 FIN-piggyback fix at line 1221, which restores RFC 9293 §3.10.7.4 MUST behaviour on the multi-seg / OOO-drain chain path; single-seg + no-drain paths are bit-for-bit identical to pre-fix. Test-inject hook and FaultInjector middleware are feature-gated (`test-inject` / `fault-injector`, both default off); release-build artifacts (including `dpdk_net.h`) are byte-identical to A6.6-7. Six proptest suites correctly encode their RFC invariants against the in-tree primitives the production paths use. Seven cargo-fuzz targets and six Scapy adversarial scripts exercise the stack without altering its wire behaviour. No new §6.4 deviations are required.

**I-8 closure verification: CONFIRMED.** `tcp_input.rs:1221` uses `delivered` (chain-total + OOO-drained bytes) in place of the buggy `seg.payload.len() as u32`. The directed regression at `tests/i8_fin_piggyback_chain.rs` genuinely exercises the bug via the semantically-equivalent OOO-drain path (`delivered = 3 + 7 == 10 > seg.payload.len() == 3`) and asserts CLOSE_WAIT transition. The I-8 FYI from `phase-a6-6-7-rfc-compliance.md` is now CLOSED.

Gate rule: phase may tag `phase-a9-complete`. No `[ ]` checkboxes are open in Must-fix or Missing-SHOULD.
