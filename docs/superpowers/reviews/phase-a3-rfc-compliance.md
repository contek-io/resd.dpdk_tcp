# Phase A3 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent (human-finalized 2026-04-18)
- Date: 2026-04-18
- RFCs in scope: 9293, 6691, 6528
- Our commit: finalized on `phase-a3` branch after `241e0e0` (F-1/F-2/S-1 fix commit) + recv_buf_drops counter

## Scope

- Our files reviewed:
  - `crates/dpdk-net-core/src/tcp_seq.rs`
  - `crates/dpdk-net-core/src/tcp_state.rs`
  - `crates/dpdk-net-core/src/tcp_conn.rs`
  - `crates/dpdk-net-core/src/flow_table.rs`
  - `crates/dpdk-net-core/src/iss.rs`
  - `crates/dpdk-net-core/src/tcp_output.rs`
  - `crates/dpdk-net-core/src/tcp_events.rs`
  - `crates/dpdk-net-core/src/tcp_input.rs`
  - `crates/dpdk-net-core/src/engine.rs` (TCP-input / emit_ack / emit_rst / emit_rst_for_syn_sent_bad_ack / connect / send_bytes / close_conn / reap_time_wait / TIME_WAIT deadline refresh)
  - `crates/dpdk-net-core/src/counters.rs` (TcpCounters + recv_buf_drops)
  - `crates/dpdk-net/src/lib.rs` (dpdk_net_connect / _send / _close, dpdk_net_poll drain)
- Spec §6.3 rows verified: RFC 9293 (TCP client FSM complete), RFC 6691 (MSS, clamp to local MTU), RFC 6528 (ISS generation)
- Spec §6.4 deviations touched:
  - Row 1 — Delayed ACK off (A3 per-segment baseline; burst-scope coalescing in A6) — amended 2026-04-18 to explicitly document the A3 → A6 evolution
  - Row 2 (new) — Receive-window shrinkage vs. buffer occupancy — added 2026-04-18
  - Row 3 — Nagle off (MUST-17)
  - Row 4 — TCP keepalive off (MUST-24/-25)
  - Row 6 — Congestion control off-by-default (no slow-start / cwnd in A3)

## Findings

### Must-fix (MUST/SHALL violation)

- [x] **F-1 → RESOLVED in commit `241e0e0`** — SYN_SENT rejection RST uses `<SEQ=SEG.ACK><CTL=RST>` per RFC 9293 §3.10.7.3
  - RFC clause: `docs/rfcs/rfc9293.txt:3354` — "If the ACK bit is set, If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset `<SEQ=SEG.ACK><CTL=RST>`". Also §3.5.2 case 2 (`rfc9293.txt:1486`).
  - Fix applied: added `TxAction::RstForSynSentBadAck` variant in `tcp_input.rs`; the two `handle_syn_sent` bad-ACK paths (SYN-less segment, ACK-out-of-range) return it; `emit_rst_for_syn_sent_bad_ack` helper in `engine.rs` emits `seq=incoming.ack, ack=0, flags=TCP_RST, window=0` — no ACK flag. Existing test `syn_sent_plain_ack_wrong_seq_sends_rst` updated to assert the new variant. Verified via integration test (`tcp_basic_tap` passes).

- [x] **F-2 → RESOLVED in commit `241e0e0`** — TIME_WAIT restarts the 2×MSL timeout on any in-window segment per RFC 9293 §3.10.7.8
  - RFC clause: `docs/rfcs/rfc9293.txt:3805` — "Acknowledge it, and restart the 2 MSL timeout." §3.10.7.8 at `rfc9293.txt:3925`.
  - Fix applied: in `engine.rs::tcp_input`, after `dispatch` and before `transition_conn`, when `conn.state == TimeWait && outcome.tx == TxAction::Ack`, refresh `conn.time_wait_deadline_ns = now + 2×MSL` using `saturating_add`. Retransmitted FINs now extend the reaping window.

- [x] **F-3 → promoted to AD-7** — Per-segment ACK accepted as A3 baseline; burst-scope coalescing deferred to A6. Spec §6.4 row 1 amended 2026-04-18 to explicitly document "A3 ships a simpler per-segment-ACK baseline". Not a correctness violation (every ACK is individually RFC-valid); the over-ACK pattern costs uplink bandwidth under heavy inbound bursts, which A3's integration-test load doesn't exercise. See AD-7 for the human-finalized citation.

### Missing SHOULD (not in §6.4 allowlist)

- [x] **S-1 → RESOLVED in commit `241e0e0`** — MSS advertised in SYN is clamped to NIC's actual MTU per RFC 6691 §5.1
  - RFC clause: `docs/rfcs/rfc6691.txt:259` — "TCP SHOULD use the smallest effective MTU of the interface to calculate the value to advertise in the MSS option". RFC 9293 §3.7.1 at `rfc9293.txt:1775`.
  - Fix applied: added `shim_rte_eth_dev_get_mtu` shim in `dpdk-net-sys`; `Engine::connect` queries the NIC's MTU and clamps `our_mss = min(cfg.tcp_mss, nic_mtu - 40)` (40 = IP(20) + TCP(20)). Best-effort — falls back to 1500 if the DPDK query fails.

### Accepted deviation (covered by spec §6.4 / §6.5 / plan header)

- **AD-1** — Delayed-ACK off (A3 per-segment; A6 burst-scope coalescing)
  - RFC clause: `docs/rfcs/rfc9293.txt:3487` — MUST-58/-59 aggregate ACKs. Also RFC 1122 §4.2.3.2 delayed-ACK ≤500ms SHOULD.
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:372` (amended 2026-04-18) — "off + per-segment ACK in A3; burst-scope coalescing in A6. … Phase A3 ships a simpler per-segment-ACK baseline — each inbound in-order data segment triggers one ACK in the same poll iteration. This over-ACKs relative to MUST-58 but never causes correctness issues (each ACK is individually valid). Burst-scope coalescing is finalized in A6 alongside the `preset=rfc_compliance` switch."
  - Our code behavior: handlers return `TxAction::Ack` per in-order data segment; engine emits inline. Each ACK is individually valid; A6 will defer/coalesce.

- **AD-2** — Nagle off; MUST-17 "way to disable" satisfied vacuously
  - RFC clause: `docs/rfcs/rfc9293.txt:1865` — MUST-17.
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:374` — "Nagle … off … user sends complete requests".
  - Our code behavior: `Engine::send_bytes` transmits immediately with no buffering across calls; `tcp_nagle` config exists but is unread. Nagle permanently off → MUST-17 vacuous.

- **AD-3** — TCP keepalive off (MUST-24/-25 defaults satisfied by absence)
  - RFC clause: `docs/rfcs/rfc9293.txt:2043-2044` — MUST-24/-25.
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:375` — "TCP keepalive … off … exchanges close idle".
  - Our code behavior: no keepalive timer. `idle_keepalive_sec` field on `dpdk_net_connect_opts_t` exists but unread in A3.

- **AD-4** — SYN retransmit deferred to A5 (MUST-20 "retransmit lost segments" is A5 scope)
  - RFC clause: `docs/rfcs/rfc9293.txt:1964-1986` — retransmission required for reliability.
  - Spec §6.5 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:384` — "SYN retransmit: schedule respects `connect_timeout_ms` … default 3 attempts … exponential up to the total budget." Plan header A3 scope: "Phase A3 emits the SYN exactly once".
  - Our code behavior: `Engine::connect` emits SYN once; no retry. No RTO timer. Unacked bytes on `send_bytes` are not auto-retransmitted; A5 alongside RACK-TLP.

- **AD-5** — ISS uses `std::collections::hash_map::DefaultHasher` (SipHash-1-3) skeleton; dedicated SipHash-2-4 + `/proc/sys/kernel/random/boot_id` nonce in A5
  - RFC clause: `docs/rfcs/rfc6528.txt:191-196` — ISN = M + F(4-tuple, secretkey); F() MUST NOT be computable from outside (MUST-9). `docs/rfcs/rfc9293.txt:1033` — MUST-8 clock-driven.
  - Spec §6.5 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:383` — ISS formula; plan header A3 explicitly "A3 ships a skeleton … A5 will finalize".
  - Our code behavior: `iss.rs:30-52`. `IssGen::new(0)` seeds a 128-bit secret from boot TSC. `next()` feeds secret+tuple into `DefaultHasher` and adds 1µs-tick clock outside the hash. SipHash-1-3 is keyed-hash → MUST-9 satisfied by the skeleton; MUST-8 satisfied (clock outside hash).

- **AD-6** — MSS-only SYN options; WSCALE/TS/SACK-permitted deferred to A4
  - RFC clause: `docs/rfcs/rfc9293.txt:1734-1735` — MUST-14 (send and receive MSS). Other SYN options SHOULD/MAY.
  - Spec §6.3 A3 scope + plan header.
  - Our code behavior: `engine.rs::connect` emits `mss_option: Some(our_mss)` only; `parse_mss_option` parses MSS on inbound, skips unknown option kinds per `len`. MUST-14 satisfied.

- **AD-7** (promoted from F-3) — Per-segment ACK accepted as A3 baseline
  - RFC clause: `docs/rfcs/rfc9293.txt:3485-3489` — MUST-58/-59 aggregate ACKs.
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:372` (amended 2026-04-18): "A3 ships a simpler per-segment-ACK baseline — each inbound in-order data segment triggers one ACK in the same poll iteration. This over-ACKs relative to MUST-58 but never causes correctness issues (each ACK is individually valid). Burst-scope coalescing is finalized in A6".
  - Our code behavior: `tcp_input.rs` handlers return `TxAction::Ack` per in-order data segment; `engine.rs` emits inline. Every ACK is individually RFC-valid. Extra ACK overhead (uplink bandwidth + CPU) is acceptable in A3's integration-test load and trading workload — client TX path to exchange is low-volume and not bandwidth-starved. A6 finalizes the spec-intent behavior (one ACK per poll iteration per connection).

- **AD-8** (new, added 2026-04-18) — `rcv_wnd` does NOT shrink with recv buffer occupancy; drops surfaced via `tcp.recv_buf_drops`
  - RFC clause: `docs/rfcs/rfc9293.txt:3410` — implicit: `rcv_wnd` should track free recv buffer space so peer's window management mirrors actual acceptance capacity.
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:373` (new row, added 2026-04-18): "advertise free_space; accept at full capacity. Trading workload is market-data ingress at peer line-rate. Shrinking the ingress-acceptance window to match local buffer occupancy would throttle the peer's send rate — masking a real upstream 'slow application consumer' problem as a protocol-layer artifact. … expose the drop condition via `tcp.recv_buf_drops`".
  - Memory reference: `feedback_performance_first_flow_control.md`.
  - Our code behavior: `tcp_conn.rs::new_client` sets `rcv_wnd = recv_buffer_bytes.min(u16::MAX)` at construction (never updated). `handle_established` seq-window check uses this static value. `RecvQueue::append()` clamps at `free_space` — excess bytes are dropped and counted in `tcp.recv_buf_drops` so the application sees backpressure. Outbound ACKs DO advertise the actual `recv.free_space()` (`engine.rs::emit_ack`) so well-behaved peers still throttle themselves; our wider ingress check just avoids being doubly-conservative.

### FYI (informational — no action)

- **I-1** — `tcp.rx_out_of_order` counter declared but never incremented
  - Plan AD-6 mentions OOO segments "are dropped and counted" but `handle_established` silently drops OOO payload (`tcp_input.rs:312-317`) without bumping the counter. Counter exists in `counters.rs:48`. Not an RFC violation; noted as a plan traceability gap. A4's real reassembly introduces the proper OOO accounting; for A3 traceability, consider a one-line `inc(&self.counters.tcp.rx_out_of_order)` in the OOO branch.

- **I-2** — SYN with in-window seq on synchronized connection is not handled per RFC 5961 §4 challenge-ACK (spec §6.3 lists RFC 5961 as A6 scope)
  - `parse_segment` rejects SYN+FIN and RST+SYN; a plain SYN with ACK arriving in ESTABLISHED passes parsing. Out-of-window → challenge-ACK fires (correct by accident). At `rcv_nxt` → processed as empty-payload data (no-op). RFC 5961 is A6 scope per spec §6.3.

- **I-3** — Zero receive window treats non-rcv_nxt ACK-only segments as unacceptable
  - `docs/rfcs/rfc9293.txt:972-977` — RST/URG handling required even at zero window (MUST-66). RST handled before window check → satisfied. URG not implemented (A3 defer; no spec entry). A3 doesn't create zero-window scenarios under normal operation (256 KiB recv buffer default + trading-fast consumer); theoretical concern.

- **I-4** — `cfg.tcp_nagle`, `cfg.tcp_initial_rto_ms`, `cfg.idle_keepalive_sec` config fields stored but unread
  - Carry-through from `dpdk_net_engine_config_t`. These become active in A5 (RTO) and A6 (timer wheel). No RFC concern.

- **I-5** — IPv4 TTL=64, ID=0, DF=1 matches spec §6.3 RFC 791 row ("DF always set") and is defensible per RFC 6864 (IPv4 ID only required for fragmentation; DF=1 inhibits fragmentation). `tcp_output.rs:60-64`.

- **I-6** — MUST-14 (send and receive MSS) satisfied; MUST-15 (default 536 when absent) satisfied via `parse_mss_option` fallback (`tcp_input.rs:119`); MUST-16 (effective send MSS = min of peer's MSS and local MTU) satisfied — we clamp to `peer_mss.min(cfg.tcp_mss)` in `send_bytes` (`engine.rs:866`) AND `cfg.tcp_mss` is now auto-clamped to NIC MTU in `Engine::connect` (F/S-1 fix).

- **I-7** — TCP checksum pseudo-header per RFC 9293 §3.1 implemented at `tcp_output.rs:112-122` and `tcp_input.rs:102-111`. MUST-2 (sender computes) and MUST-3 (receiver checks) satisfied. Unit test `tcp_output::tests::data_segment_with_payload_has_correct_tcp_csum` verifies round-trip.

- **I-8** — Eleven-state FSM (`tcp_state.rs:504-517`) matches RFC 9293 §3.3.2. LISTEN/SYN_RECEIVED transitions absent (client-only stack per spec §6.1).

- **I-9** — `send_rst_unmatched` (engine.rs:694-724) implements RFC 9293 §3.10.7.1 CLOSED STATE: if ACK, `<SEQ=SEG.ACK><CTL=RST>`; else `<SEQ=0><ACK=SEG.SEQ+SEG.LEN+SYN+FIN><CTL=RST,ACK>`. MUST-1 satisfied.

- **I-10** — TIME_WAIT linger for 2×MSL (MUST-13) enforced via `reap_time_wait` + deadline refresh (F-2 fix). Default `tcp_msl_ms=30_000` → 60s total linger. Refresh-on-retx-FIN now honored.

## Verdict

**PASS-WITH-DEVIATIONS** — human-finalized 2026-04-18.

Finding counts after human review:
- Must-fix (open): **0** — F-1, F-2 fixed in commit `241e0e0`; F-3 promoted to AD-7 with spec §6.4 amendment.
- Missing-SHOULD (open): **0** — S-1 fixed in commit `241e0e0`.
- Accepted-deviation (with citations): 8 — AD-1 through AD-8. AD-1..AD-6 carry over from the reviewer's draft; AD-7 (per-segment ACK, promoted from F-3) and AD-8 (rcv_wnd no-shrink, new) added 2026-04-18 with corresponding spec §6.4 amendments.
- FYI: 10 — I-1 through I-10.

Gate rule satisfied: no open `[ ]` remains in Must-fix or Missing-SHOULD. Every Accepted-deviation entry cites a concrete line in spec §6.4, §6.5, or `feedback_performance_first_flow_control.md`. The `phase-a3-complete` tag may proceed pending the mTCP comparison review gate (already PASS-WITH-ACCEPTED, human-finalized).
