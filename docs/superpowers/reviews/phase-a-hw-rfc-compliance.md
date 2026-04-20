# Phase A-HW — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent
- Date: 2026-04-19
- RFCs in scope: 9293 (primary); 1071 and 1624 informational (not vendored, not in spec §6.3 matrix)
- Our commit: 467a8f2 (worktree `/home/ubuntu/resd.dpdk_tcp-a-hw`, branch `phase-a-hw`)

## Scope

- Our files reviewed:
  - `/home/ubuntu/resd.dpdk_tcp-a-hw/crates/resd-net-core/src/tcp_output.rs` (pseudo-header helper + offload finalizer)
  - `/home/ubuntu/resd.dpdk_tcp-a-hw/crates/resd-net-core/src/l3_ip.rs` (IP offload-aware RX decode + `classify_ip_rx_cksum` / `classify_l4_rx_cksum`)
  - `/home/ubuntu/resd.dpdk_tcp-a-hw/crates/resd-net-core/src/tcp_input.rs` (TCP RX software-fold path; `nic_csum_ok` passthrough)
  - `/home/ubuntu/resd.dpdk_tcp-a-hw/crates/resd-net-core/src/engine.rs` (TX offload call sites + TCP L4-cksum classification + runtime latches)
  - `/home/ubuntu/resd.dpdk_tcp-a-hw/crates/resd-net-core/src/counters.rs` (`rx_drop_cksum_bad` + `offload_missing_*` fields)
- Spec §6.3 rows verified: RFC 9293 row ("TCP / client FSM complete"). No matrix row claim changes in A-HW — offload enablement is wire-transparent.
- Spec §6.4 deviations touched: none. A-HW adds no new ADs. The parent spec §6.4 block and the A5.5 additions block are both unchanged.

## Findings

### Must-fix (MUST/SHALL violation)

None.

The two RFC 9293 §3.1 MUSTs in scope are MUST-2 ("the sender MUST generate" the TCP checksum) and MUST-3 ("the receiver MUST check it"):

- **MUST-2 (sender generates)** is satisfied on both paths.
  - Software full-fold path: `tcp_output.rs:169-177` writes the full fold produced by `tcp_checksum_split` into the TCP checksum field. Unchanged from pre-A-HW.
  - Offload path: `tcp_output.rs:311-365` (`tx_offload_finalize`) writes the 12-byte pseudo-header fold into the TCP checksum field AND sets `RTE_MBUF_F_TX_TCP_CKSUM` + `l2_len/l3_len/l4_len`, which under the DPDK TX-offload contract instructs the PMD to complete the fold over TCP header + payload before wire emission. The resulting on-wire bytes equal the full software fold bit-for-bit, as asserted by the unit test `pseudo_header_only_cksum_matches_manual_fold` (`tcp_output.rs:552-570`) combined with `tx_offload_rewrite_cksums_writes_pseudo_and_zeroes_ip` (`tcp_output.rs:583-616`). The pseudo-header byte layout — `src_ip BE (4) + dst_ip BE (4) + zero (1) + IPPROTO_TCP (1) + tcp_length BE (2)` — exactly matches RFC 9293 §3.1 Figure 2 (see `docs/rfcs/rfc9293.txt:425-448`). `tcp_seg_len` semantics ("TCP header length plus the data length in octets... does not count the 12 octets of the pseudo-header") matches the `tcp_hdr_len + payload_len` computation at `tcp_output.rs:270`.

- **MUST-3 (receiver checks)** is satisfied on both paths.
  - Software verify path: `tcp_input.rs:77-87` (`parse_segment` with `nic_csum_ok=false`) recomputes the full fold and rejects mismatches with `TcpParseError::Csum`. Unchanged from pre-A-HW.
  - Offload path with GOOD: the NIC has verified; software skips the recompute via `nic_csum_ok=true` at `engine.rs:2246-2252`. The NIC is the checksum verifier of record, which still satisfies MUST-3 ("the receiver MUST check it" — the verifier is on the RX side of the socket; the RFC is silent on whether the check must be performed in software).
  - Offload path with BAD: `engine.rs:2253-2263` drops and bumps `eth.rx_drop_cksum_bad` + `tcp.rx_bad_csum`. This matches RFC 9293 §3.8 treatment of checksum failure as a lost segment recovered by retransmission (`docs/rfcs/rfc9293.txt:1891-1898`).
  - Offload path with NONE/UNKNOWN: falls through to software verify at `engine.rs:2264-2268` — same code path as the pre-A-HW software-only build.
  - IP-cksum side is analogous: `l3_ip.rs:178-211` (`ip_decode_offload_aware`) routes GOOD → skip, BAD → drop + bump, NONE/UNKNOWN / feature-off / latch-off → `ip_decode(.., nic_csum_ok=false)` (software fold).

### Missing SHOULD (not in §6.4 allowlist)

None. No new SHOULD clauses are introduced or dropped by A-HW. The existing A3/A4/A5/A5.5 SHOULDs (delayed ACK in §6.4, Nagle in §6.4, RTO floor in §6.4, RACK-TLP §6.4 A5.5 additions) are untouched.

### Accepted deviation (covered by spec §6.4)

None new in A-HW. Existing §6.4 deviations (delayed-ACK off, Nagle off, minRTO=5ms, RTO max=1s, CC off-by-default, TFO disabled) and the A5.5-additions block carry over unchanged. A-HW is transparent at the wire protocol level, so no row moves.

### FYI (informational — no action)

- **I-1**: **RFC 9293 §3.1 pseudo-header byte layout is exact.** `tcp_pseudo_header_checksum` at `crates/resd-net-core/src/tcp_output.rs:223-235` constructs the 12-byte pseudo-header as `src_ip.to_be_bytes() (4) || dst_ip.to_be_bytes() (4) || 0 (1) || IPPROTO_TCP (1) || (tcp_seg_len as u16).to_be_bytes() (2)` — byte-for-byte matches RFC 9293 §3.1 Figure 2 (`docs/rfcs/rfc9293.txt:425-433`). The `debug_assert!` at lines 224-227 also guards the u16 bound on `tcp_length`, matching the IPv4 total-length implicit constraint called out in `docs/rfcs/rfc9293.txt:445-448`.

- **I-2**: **On-wire equivalence between software-fold and offload paths is asserted by test.** `pseudo_header_only_cksum_matches_manual_fold` (`tcp_output.rs:552-570`) proves the helper matches a manually-folded 12-byte pseudo-header. `tx_offload_rewrite_cksums_writes_pseudo_and_zeroes_ip` (`tcp_output.rs:583-616`) proves the mbuf-rewrite path emits that helper's output into the TCP cksum field and zeroes the IPv4 cksum field. The PMD's fold-completion is a hardware contract (DPDK ethdev offload spec); given the shared pseudo-header seed, the on-wire result is bit-identical to the full software fold. No RFC-visible behavior change.

- **I-3**: **RFC 1071 (Internet checksum) is not in the spec §6.3 matrix and is not vendored under `docs/rfcs/`.** The phase plan references it as the computational primitive. The implementation is the standard 16-bit ones'-complement-of-ones'-complement-sum fold in `l3_ip.rs::internet_checksum` (lines 34-48), unchanged by A-HW. No behavior change to flag. Not a BLOCK: RFC 1071 is not listed as a Stage 1 compliance RFC in parent spec §13 "Standards and compliance" (only 9293 is cited for TCP, 791/792 for IP/ICMP).

- **I-4**: **RFC 1624 (incremental checksum update) is not in scope for A-HW.** Parent spec §5.3 / A5 retransmit primitive mandates "retransmit allocates a fresh header mbuf chained to the original data mbuf — never edits an in-flight mbuf in place." This means A-HW's TX path never does in-place checksum patching that would require RFC 1624's incremental update algorithm; every TX segment is a fresh fold (either software full-fold or pseudo-header + PMD completion). Not vendored under `docs/rfcs/`; not in §6.3 matrix; not a BLOCK.

- **I-5**: **Offload feature-off builds (`--no-default-features` or per-feature opt-out) compile the offload branch away entirely.** The `#[cfg(feature = "hw-offload-tx-cksum")]` and `#[cfg(feature = "hw-offload-rx-cksum")]` gates in `tcp_output.rs:258-382` and `l3_ip.rs:118-211` ensure feature-off builds take the unconditional software-fold path — bit-identical to pre-A-HW behavior. The 8-build CI matrix (phase plan §13) asserts every off-branch compiles cleanly. No RFC deviation introduced.

- **I-6**: **The `rx_drop_cksum_bad` and `tcp.rx_bad_csum` counters on the BAD branch (`engine.rs:2253-2263`) match the observability-primitives-only stance from parent §9.1.1 and the user's `counter_policy` memory — BAD is a per-packet outcome that is slow-path-by-definition (only fires on actual corruption); the single `fetch_add` per bad packet is below the noise floor on the RX path and is documented in spec §11.1 of the A-HW design.**

- **I-7**: **Peer-visible identity of offload vs software-fold output is verifiable end-to-end.** `parse_segment(.., nic_csum_ok=false)` at `tcp_input.rs:77-87` recomputes the pseudo-header-plus-body fold from scratch using the same `internet_checksum` primitive. A loopback test harness running software-fold TX against software-verify RX would reject an offload-emitted frame only if the PMD's fold disagreed with the software fold — which would be a DPDK/NIC bug, not a TCP spec violation. The `net_tap` smoke path in plan §12.1 exercises this exact round-trip. No RFC-level concern.

- **I-8**: **No new MUST/SHOULD items from RFC 9293 become relevant on A-HW's diff.** The state-machine, options-encode, RTO, RACK-TLP, ISS, and MSS behaviors are all in earlier phases' scope (A3 / A4 / A5 / A5.5) and are unchanged by A-HW. A-HW touches only the checksum-computation location (NIC vs software) and port-configuration plumbing, neither of which is observable at the wire protocol level.

## Verdict (draft)

**PASS**

Rationale: A-HW is transparent to the TCP/IP wire protocol. The only RFC 9293 clauses in the blast radius are §3.1 MUST-2 and MUST-3, both of which are satisfied on both the offload and software paths with unit-test-level evidence of bit-for-bit on-wire equivalence. No new deviations, no new accepted-deviation rows, no open MUST/SHOULD findings.

Gate rule: phase cannot tag `phase-a-hw-complete` while any `[ ]` checkbox in Must-fix or Missing-SHOULD is open. Zero such checkboxes. Accepted-deviation section contains no entries because A-HW introduces no new deviations.
