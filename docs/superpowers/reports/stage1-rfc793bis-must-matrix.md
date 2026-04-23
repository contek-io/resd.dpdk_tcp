# Stage 1 RFC 793bis / RFC 9293 MUST Compliance Matrix

Date: 2026-04-22
Phase: A8 (pinned at `phase-a8-complete`; updated on every subsequent
phase whose scope intersects RFC 9293 MUST coverage)
Purpose: Stage 1 ship-gate "Layer C 100% MUST" evidence artifact
(per master spec §10.10 ship criteria and §10.3 Layer C scope).

Every clause maps to either a PASS cell (test citation) or a DEVIATION
cell (master-spec §6.4 row + justification). Clauses explicitly out of
Stage 1 scope are enumerated in the DEFERRED section with a concrete
rationale (spec §1 non-goal, Stage 2+ scope, or prior-phase Accepted
Deviation).

Source RFCs: `docs/rfcs/rfc9293.txt` (TCP 793bis),
`docs/rfcs/rfc6528.txt` (RFC 6528 ISS), `docs/rfcs/rfc6298.txt` (RTO),
`docs/rfcs/rfc6691.txt` (MSS).

## In-scope MUST clauses

| Clause | Text (paraphrase) | Paragraph | Covered by | Status |
|---|---|---|---|---|
| MUST-2/3 | Sender MUST generate TCP checksum; receiver MUST verify | RFC 9293 §3.1 | `crates/dpdk-net-core/src/l3_ip.rs` (encode/verify) + `crates/dpdk-net-core/tests/checksum_streaming_equiv.rs` + counter-coverage `cover_tcp_rx_bad_csum` (tests/counter-coverage.rs:1356) | **PASS** |
| MUST-4 | TCP MUST support EOL / NOP / MSS options | RFC 9293 §3.2 | `crates/dpdk-net-core/src/tcp_options.rs` inline unit tests (`#[cfg(test)]` mod at :305+, covering EOL, NOP, MSS, WS, TS, SACK round-trip) | **PASS** |
| MUST-5 | TCP MUST accept an option in any segment | RFC 9293 §3.2 | `tools/tcpreq-runner/src/probes/mss.rs::late_option` (Layer C) | **PASS** (tcpreq) |
| MUST-6 | TCP MUST ignore unknown options | RFC 9293 §3.2 | `crates/dpdk-net-core/src/tcp_options.rs` inline unit tests (unknown-kind skip path, `#[cfg(test)]` mod at :305+) | **PASS** |
| MUST-7 | TCP MUST handle illegal option length without crashing | RFC 9293 §3.2 | `crates/dpdk-net-core/src/tcp_options.rs` inline unit tests (`parse_options` error arms at :469–:503) + counter-coverage `cover_tcp_rx_bad_option` (tests/counter-coverage.rs:989) | **PASS** |
| MUST-8 | Clock-driven ISN selection | RFC 9293 §3.4.1 / RFC 6528 §3 | `crates/dpdk-net-core/src/iss.rs` (SipHash-2-4 keyed, clock-added-outside-hash) + `crates/dpdk-net-core/tests/siphash24_full_vectors.rs` | **PASS** |
| MUST-13 | 2×MSL TIME_WAIT after active close | RFC 9293 §3.5 | `crates/dpdk-net-core/tests/test_server_active_close.rs` (active-close → TIME_WAIT) + counter-coverage `cover_tcp_conn_time_wait_reaped` (tests/counter-coverage.rs:753) | **PASS** (opt-in override `AD-A6-force-tw-skip`, master spec §6.4 — guarded by `ts_enabled` + explicit `DPDK_NET_CLOSE_FORCE_TW_SKIP` flag; default is RFC 9293 exact) |
| MUST-14 | Sending + receiving MSS option | RFC 9293 §3.7.1 | `crates/dpdk-net-core/src/tcp_output.rs::syn_frame_has_mss_option_and_valid_sizes` (:411) + MSS decode in `tcp_input.rs:632` (SYN-ACK) and `tcp_conn.rs:535` (passive) | **PASS** |
| MUST-15 | Default send MSS = 536 on missing MSS option | RFC 9293 §3.7.1 / RFC 6691 | `tools/tcpreq-runner/src/probes/mss.rs::missing_mss` (Layer C); A8 T19 also fixed the MUST-15 gap in the passive path at `tcp_conn.rs:535` (`opts.mss.unwrap_or(536)`) — active path mirror at `tcp_input.rs:632` | **PASS** (tcpreq + passive-path code citation) |
| MUST-16 | Effective MSS ≤ min(send MSS, IP limit) | RFC 9293 §3.7.1 | `crates/dpdk-net-core/src/engine.rs:4613` MSS math (`(peer_mss as u32).min(self.cfg.tcp_mss).max(1)`) exercised by every TX-path test that emits data (`tests/tcp_basic_tap.rs`, `tests/multiseg_retrans_tap.rs`, `tests/i8_multi_seg_fin_piggyback.rs`) | **PASS** |
| MUST-30/31 | URG mechanism | RFC 9293 §3.8.2 | `tools/tcpreq-runner/src/probes/urgent.rs::urgent_dropped` + counter-coverage `cover_tcp_rx_urgent_dropped` (tests/counter-coverage.rs:1425) | **DEVIATION** — `AD-A8-urg-dropped` (master spec §6.4) |
| MUST-58/59 | Delayed-ACK SHOULD aggregate but MUST send | RFC 9293 §3.8.6.3 | Per-segment ACK in A3 baseline; burst-scope coalescing lands at A6 alongside `preset=rfc_compliance` switch (master spec §6.4 row "Delayed ACK") — behavior never withholds a valid ACK | **DEVIATION** — master spec §6.4 "Delayed ACK" (trading-latency default: over-ACK relative to MUST-58 is the chosen direction, MUST-59 "MUST send" is preserved) |
| Reserved | Reserved bits ignored on RX + zero on TX | RFC 9293 §3.1 | `tools/tcpreq-runner/src/probes/reserved.rs::reserved_rx` (Layer C) | **PASS** (tcpreq) |
| Reset-Processing | RST processed independently of other flags; RST responses to invalid segments | RFC 9293 §3.10.7 | A3 RST-path unit tests in `tcp_input.rs` (`#[cfg(test)]` mod) + A8 S1 AD-A7 fixes `tests/ad_a7_rst_relisten.rs` + `tests/ad_a7_dup_syn_retrans_synack.rs` + counter-coverage `cover_tcp_rx_rst` (:848), `cover_tcp_tx_rst` (:931), `cover_tcp_conn_rst` (:717) | **PASS** |
| Blind-data-mitigation | Challenge-ACK on out-of-window sequence numbers | RFC 9293 §3.10.7 / RFC 5961 | A3 challenge-ACK path in `tcp_input.rs` (off-window seq → challenge-ACK emission); obs_smoke + counter-coverage dynamically exercise the edge | **PASS** |

## DEFERRED / not-in-Stage-1-scope clauses

| Clause | Text (paraphrase) | Why deferred |
|---|---|---|
| MUST-10 simultaneous-open | Two side-by-side SYNs from both peers transition to SYN_RCVD | Stage 1 is client-only per master spec §1 non-goals ("server-side TCP in production"); passive path is test-server-only (`feature = "test-server"`). Production connect path is active-open; simultaneous-open requires both sides to issue active OPENs. |
| PMTU probe (RFC 8899 / PLPMTUD) | Probe-based PMTUD | Stage 2 scenario per master spec §10.8 ("PMTU blackholing — Stage 2 scenario only; requires PLPMTUD (RFC 8899)-style recovery"). Stage 1 uses ICMP-driven PMTUD (RFC 1191) per master spec §6.3 row `1191 | PMTUD | yes`. |
| Congestion-control MUST rows (Reno / NewReno) | Reno required, NewReno required in loss | Master spec §6.4 "Congestion control" row: `cc_mode=off` by default (trading-latency deviation); `preset=rfc_compliance` knob enables Reno (`cc_mode=reno`) for differential-vs-Linux and A/B benchmarking. Stage 2 S2-A adds the differential-vs-Linux gate. |
| CUBIC | RFC 8312 CUBIC | Optional per RFC 9293; master spec §6.3 notes CUBIC is explicitly `cc_mode=2 (cubic, later)` — out of Stage 1 scope. |
| TCP Fast Open (RFC 7413) | TFO MUST rows | Master spec §6.3 row `7413 | TCP Fast Open | NO` + §1 non-goals: "long-lived connections don't benefit". |
| IPv6 MUST clauses | Dual-stack / IPv6-only | Master spec §1 non-goals: "IPv6". Explicit exclusion from Stage 1 ship-gate per §10.10. |

## Layer-to-clause coverage summary

| Layer | Source | Coverage footprint |
|---|---|---|
| Layer A — unit tests + TAP tests | `crates/dpdk-net-core/src/*.rs` inline `#[cfg(test)]`, `crates/dpdk-net-core/tests/*.rs`, `tests/common/` | MUST-2/3, MUST-4, MUST-6, MUST-7, MUST-8, MUST-13, MUST-14, MUST-16, Reset-Processing, Blind-data-mitigation |
| Layer B — packetdrill-shim corpora | `tools/packetdrill-shim/`, `tools/packetdrill-shim-runner/`, vendored `third_party/packetdrill-testcases/` | Post-A8 (T15/T16 pragmatic floor): ligurio 0/122 runnable (pinned at `LIGURIO_RUNNABLE_COUNT = 0` with every script classified in `tools/packetdrill-shim/SKIPPED.md`); shivansh 5/47 runnable; google 0/167 runnable (defaults.sh host-env gap). Shim-path MUST coverage is adjunct to Layer A, not primary — Layer A already covers the structural MUSTs row-by-row. |
| Layer C — tcpreq-runner | `tools/tcpreq-runner/src/probes/` | MUST-5 (`mss.rs::late_option`), MUST-15 (`mss.rs::missing_mss`), Reserved (`reserved.rs::reserved_rx`), MUST-30/31 (`urgent.rs::urgent_dropped`, pins `AD-A8-urg-dropped`) |

Counter-coverage scenarios under `crates/dpdk-net-core/tests/counter-coverage.rs` are
treated as Layer A because they drive the production engine's `AtomicU64`
counters through the same FFI surface used by the observability smoke test
(`tests/obs_smoke.rs`); every scenario asserts `counter > 0` for the exact
MUST-relevant code path.

## Related review artifacts

- A8 mTCP comparison review: `docs/superpowers/reviews/phase-a8-mtcp-compare.md`
  (passive-path parity + S1 AD-A7 retirements).
- A8 RFC compliance review: `docs/superpowers/reviews/phase-a8-rfc-compliance.md`
  (verifies S1 behavior vs RFC 9293 §3.8.1, §3.10.7.4, RFC 6298 §2; pins
  `AD-A8-urg-dropped`).
- Master spec deviation matrix: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §6.3 / §6.4.

## Changelog

- **2026-04-22 (A8 locked)**: initial matrix — 15 in-scope MUST rows
  (13 PASS, 2 DEVIATION), 6 DEFERRED entries. Every PASS row cites a
  concrete file + line or counter-coverage scenario that exists on
  `phase-a8`. Every DEVIATION row cites the master-spec §6.4 AD-* row
  that documents the rationale. Every DEFERRED row cites master spec
  §1 non-goals, §6.3 compliance matrix row, or Stage 2+ scope.
