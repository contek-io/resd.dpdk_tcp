# Phase A6.5 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent
- Date: 2026-04-20
- RFCs in scope: 1071 (Internet checksum — oracle, not vendored), 9293 (TCP), 7323 (TCP Timestamps/Window Scale), 8985 (RACK-TLP), 6298 (RTO), 2018 (SACK), 793 (legacy TCP)
- Our commit: `2bbb80053df6cf9933a0120df3ba004864d435e8`

## Scope

- Our files reviewed:
  - `crates/resd-net-core/src/l3_ip.rs` (streaming `internet_checksum(&[&[u8]])`)
  - `crates/resd-net-core/src/tcp_input.rs` (RX csum verify split-and-zero fold; `rack_lost_indexes: SmallVec<[u16; 16]>`)
  - `crates/resd-net-core/src/tcp_output.rs` (`tcp_checksum_split`, `tcp_pseudo_header_checksum`, `build_segment_inner`)
  - `crates/resd-net-core/src/tcp_reassembly.rs` (`OooSegment` mbuf-ref refactor; `drain_contiguous_from_mbuf`)
  - `crates/resd-net-core/src/tcp_rack.rs` (`rack_mark_losses_on_rto` / `_into` caller-buffer pair)
  - `crates/resd-net-core/src/tcp_retrans.rs` (`prune_below` SmallVec return, `prune_below_into_mbufs` alloc-free variant)
  - `crates/resd-net-core/src/tcp_timer_wheel.rs` (`advance` returns `SmallVec<[(TimerId, TimerNode); 8]>`)
  - `crates/resd-net-core/src/engine.rs` (TX frame scratch reuse; rack_lost_idxs_scratch; timer_ids_scratch)
  - `crates/resd-net-core/tests/checksum_streaming_equiv.rs` (streaming vs reference equivalence fuzz)
- Spec §6.3 rows verified:
  - RFC 9293 — TCP (checksum MUST-2/MUST-3; in-order reassembly + OOO semantics unchanged)
  - RFC 7323 — Timestamps/Window Scale (no change)
  - RFC 2018 — SACK (no change to sacked-flag semantics)
  - RFC 8985 — RACK-TLP (`RACK_mark_losses_on_RTO` §6.3 preserved; into-buffer API is an internal-refactor)
  - RFC 6298 — RTO (no change)
  - RFC 793 — legacy TCP semantics (subsumed by 9293; no change)
- Spec §6.4 deviations touched: none new this phase; existing `AD-A5-5-rack-mark-losses-on-rto` continues to apply to `rack_mark_losses_on_rto_into` (caller-buffer variant).

## Findings

### Must-fix (MUST/SHALL violation)

*(none)*

### Missing SHOULD (not in §6.4 allowlist)

*(none)*

### Accepted deviation (covered by spec §6.4)

- **AD-1** — RACK `mark_losses_on_RTO` pass remains applied; internal refactor to caller-buffer API only.
  - RFC clause: `docs/rfcs/rfc8985.txt:915-919` — `RACK_mark_losses_on_RTO()` pseudocode.
  - Spec §6.4 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:444` (`AD-A5-5-rack-mark-losses-on-rto`).
  - Our code behavior: `tcp_rack.rs:125-148` (`rack_mark_losses_on_rto_into`) is the alloc-free variant consumed by `engine.rs:1884-1911`. The decision logic is byte-identical to the A5.5 `rack_mark_losses_on_rto` wrapper at `tcp_rack.rs:106-116`: iterate `snd_retrans.entries`, skip `sacked || lost || end_seq ≤ snd_una`, flag lost iff `e.seq == snd_una OR xmit_us + rtt_us + reo_wnd_us ≤ now_us`. Only the container surface changed (appending to `&mut Vec<u16>` rather than returning `Vec<u16>`).

### FYI (informational — no action)

- **I-1** — RFC 1071 is the normative source for the Internet checksum fold and is NOT vendored in `docs/rfcs/`. The A6.5 plan cites RFC 1071 by reference; the fuzz test at `crates/resd-net-core/tests/checksum_streaming_equiv.rs:10-29` acts as the in-repo oracle (the pre-A6.5 single-slice fold). RFC 9293's own checksum description at `docs/rfcs/rfc9293.txt:407-415` re-states the ones'-complement-sum-with-trailing-octet-padding algorithm normatively for TCP: "If a segment contains an odd number of header and text octets, alignment can be achieved by padding the last octet with zeros on its right to form a 16-bit word for checksum purposes. The pad is not transmitted as part of the segment. While computing the checksum, the checksum field itself is replaced with zeros." The new `internet_checksum(&[&[u8]])` at `l3_ip.rs:37-68` carries an odd-byte remainder across chunk transitions via a single `Option<u8> carry` and finalizes with `(tail << 8)`, which is bit-identical to concatenate-then-fold. Not listing RFC 1071 as absent because `rfc-compliance-reviewer`'s ground-rule expects vendored files for in-scope RFCs; the clause being tested here (MUST-2 / MUST-3) lives in RFC 9293 which IS vendored.

- **I-2** — RFC 9293 MUST-2 (`docs/rfcs/rfc9293.txt:458`, "The sender MUST generate it") and MUST-3 (`docs/rfcs/rfc9293.txt:459`, "the receiver MUST check it") remain satisfied. The pseudo-header construction at `tcp_input.rs:123-128` and `tcp_output.rs:206-212` is unchanged in content: src-ip(4) + dst-ip(4) + zero(1) + PTCL=6(1) + tcp-length(2). `tcp_checksum_split` at `tcp_output.rs:196-213` folds pseudo-header || tcp-header || payload via the streaming API; the equivalence fuzz at `tests/checksum_streaming_equiv.rs:31-91` asserts bit-identical output across (a) exhaustive three-chunk lengths `0..=15`, (b) 200 random large-length triples up to 2 KiB, (c) single-slice lengths `0..=1500`.

- **I-3** — RFC 9293 §3.4 in-order delivery (segments ordered by sequence number; receiver holds out-of-order segments until gap fill) is preserved verbatim. `ReorderQueue::insert` at `tcp_reassembly.rs:195-302` maintains seq-sorted `Vec<OooSegment>` and carves incoming bytes into non-overlapping gap-slices. `drain_contiguous_from_mbuf` at `tcp_reassembly.rs:357-391` pops the contiguous prefix starting at `rcv_nxt`, skipping fully-behind segments (via `drop_segment_mbuf_ref`) and trimming the front of a partially-covered segment via `offset += skip; len -= skip`. Adjacent entries explicitly do NOT coalesce physically (zero-copy contract from mbuf refs), but drain together when `rcv_nxt` chains through them — exercised by `drain_mbuf_chains_through_touching_segments` at `tcp_reassembly.rs:478-497`. Net: gap-fill semantics and byte-order preservation match pre-A6.5.

- **I-4** — RFC 9293 §3.4 SHLD-19 (delayed ACK / per-out-of-order ack) and SACK (RFC 2018) paths are untouched; the only SACK-related code in this phase is `SendRetrans::mark_sacked` at `tcp_retrans.rs:120-128`, which is unchanged in logic. The `prune_below` return-type change from `Vec<RetransEntry>` to `SmallVec<[RetransEntry; 8]>` is API-internal; the iteration semantics at call sites use `IntoIterator` which both containers implement identically.

- **I-5** — RFC 7323 §3 Timestamps and §2.2 Window Scale code paths (`tcp_options.rs`, PAWS checks in `tcp_input.rs`) were not modified by this phase. No TS-option encode/decode, no RTT-sample source, no WS-shift application changed.

- **I-6** — RFC 6298 RTO computation (`tcp_rtt.rs`, `tcp_rto.rs`) is untouched. `engine.rs`'s RTO-fire handler at `engine.rs:1880-1940` composes the existing `rack_mark_losses_on_rto_into` helper with the existing `retransmit` primitive; the sequence of counter bumps (`tx_rto` once, `tx_retrans` N) is preserved per the A5.5 design.

- **I-7** — RFC 8985 §7 TLP paths (`tcp_tlp.rs`, `arm_tlp_pto` in `engine.rs`) were not modified by this phase. Timer wheel's `advance` return container change from `Vec<(TimerId, TimerNode)>` to `SmallVec<[...; 8]>` is consumer-agnostic (`IntoIterator` iteration).

- **I-8** — `tcp_pseudo_header_checksum` at `tcp_output.rs:223-235` (A-HW TX-offload pseudo-header-only fold) migrated to `internet_checksum(&[&buf])` without behavior change. The A-HW test `pseudo_header_only_cksum_matches_manual_fold` at `tcp_output.rs:553-570` already validates this path against a manual fold.

## Verdict (draft)

**PASS**

Zero MUST gaps, zero new SHOULD gaps. All A6.5 changes are internal-refactor / allocation-hygiene: the checksum API evolved from single-slice to slice-of-slices with a proof-of-equivalence fuzz; pseudo-header construction is byte-identical; OOO reassembly preserves insert-sort + gap-fill + drain-on-cum-ACK semantics; RACK/RTO/TLP wire behavior unchanged; no public C-ABI change; no new deviation beyond what §6.4 already lists. The existing AD-A5-5-rack-mark-losses-on-rto continues to apply to the caller-buffer variant.

Gate rule: phase may tag `phase-a6.5-complete` — no open `[ ]` items in Must-fix or Missing-SHOULD. Accepted-deviation AD-1 cites `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:444`.
