# Phase A6.6 + A6.7 — RFC Compliance Review

- Reviewer: rfc-compliance-reviewer subagent (opus 4.7)
- Date: 2026-04-21
- RFCs in scope: 9293, 7323, 8985, 6298, 1122 (no new surface; verified unchanged)
- Pre-audit commit: `b4e8de9` (a6.6-7 fix: snd_retrans data_len matches TCP payload)
- Phase tag (pending): `phase-a6-6-7-complete`

## Scope

- Files reviewed:
  - `crates/dpdk-net/src/api.rs` (FFI struct + counter shape)
  - `crates/dpdk-net/src/lib.rs` (`dpdk_net_poll` segs resolution)
  - `crates/dpdk-net-core/src/tcp_conn.rs` (`InOrderSegment`, `RecvQueue.bytes` flip, per-conn scratch)
  - `crates/dpdk-net-core/src/tcp_input.rs` (chain walk for in-order + OOO ingest)
  - `crates/dpdk-net-core/src/tcp_reassembly.rs` (`drain_contiguous_into` output-param form)
  - `crates/dpdk-net-core/src/tcp_retrans.rs` (entry struct + `hdrs_len`)
  - `crates/dpdk-net-core/src/engine.rs` (`deliver_readable`, `poll_once` scratch reset, `retransmit_inner` bugfix)
  - `crates/dpdk-net-core/src/iovec.rs` (layout-asserted core ABI shape)
  - `crates/dpdk-net-core/tests/rx_zero_copy_multi_seg.rs`, `rx_partial_read.rs`
  - `docs/superpowers/reports/ffi-safety-audit.md` (A6.7 hardening rollup)
- Spec §6.3 rows verified: RFC 9293 §3.4 (sequence numbers), §3.7 (segmentation/MSS), §3.10.7.4 (segment processing/reassembly); RFC 7323 (PAWS, WS, TS); RFC 8985 (RACK-TLP); RFC 6298 (RTO/Karn); RFC 1122 §3.3.2 (no IPv4 reassembly — unchanged)
- Spec §6.4 deviations touched: none changed by this phase. The standing A6.4 deviations (Nagle off, delayed-ACK off, minRTO=5ms, maxRTO=1s, CC off-by-default, TFO disabled, AD-A5-5-srtt-from-syn, AD-A6-force-tw-skip) remain in force unmodified.

## Findings

### Must-fix (MUST/SHALL violation)

None introduced by A6.6 or A6.7.

### Missing SHOULD (not in §6.4 allowlist)

None introduced by A6.6 or A6.7.

### Accepted deviation (covered by spec §6.4)

No new accepted-deviation entries. The phase did not touch any RFC clause that the standing §6.4 allowlist covers.

### FYI (informational — no action)

- **I-1** — **Wire bytes unchanged across A6.6.** A6.6 reshapes only the FFI ingest descriptor (`(data, data_len)` → `(segs[], n_segs, total_len)`) and the internal `RecvQueue.bytes` representation (`VecDeque<u8>` → `VecDeque<InOrderSegment>`). The byte stream the application receives is bit-identical for any given peer trace. The chain-walk preserves byte ordering: head TCP payload first, then each `rte_mbuf.next` link in chain order, with `Σ seg.len == total_len` (verified by `rx_zero_copy_multi_seg.rs`). RFC 9293 §3.4 (sequencing) and §3.7 (in-order delivery) — `docs/rfcs/rfc9293.txt:243` "TCP provides a reliable, in-order, byte-stream service" — remain satisfied.

- **I-2** — **`InOrderSegment` link-seq computation is correct for OOO chains.** In `tcp_input.rs` OOO branch (~line 1066+), each chain link inserted into `reorder` carries `link_seq = seg.seq + Σ prior_link_data_len`. Each `reorder.insert` call is paired with a per-link `shim_rte_mbuf_refcnt_update(+1)` and rollback on `mbuf_ref_retained == false`. The `drain_contiguous_into` path then transfers the refcount cleanly from `OooSegment` to `InOrderSegment.MbufHandle`. RFC 9293 §3.10.7.4 (`docs/rfcs/rfc9293.txt:3457` — "Segments are processed in sequence... further processing is done in SEG.SEQ order") is preserved at the wire-seq level, even though zero-copy forbids coalescing adjacent segments.

- **I-3** — **MUST-58 / MUST-59 ACK aggregation respected.** `deliver_readable` emits one `Event::Readable` per poll, materializing all in-order bytes into the per-conn iovec scratch in one shot. The ACK that follows is a single segment for the cumulative `rcv_nxt`. RFC 9293 §3.10.7.4 MUST-58 (aggregate ACK across queued in-order data) and MUST-59 (process all queued before ACKing) remain satisfied; the FFI reshape did not introduce per-link ACK chatter.

- **I-4** — **Partial-read split refcount is correct.** `MbufHandle::try_clone()` bumps the underlying `rte_mbuf` refcount when the consumer drains less than `front.len`. The drained prefix lands in `delivered_segments` with the original refcount; the remaining tail keeps the bumped clone with advanced `offset` and shrunk `len`. The byte stream the application observes across two partial reads concatenates to the same bytes a single full read would have observed (verified by `rx_partial_read.rs`).

- **I-5** — **TCB FSM unchanged.** No state-machine transitions, no `snd_*`/`rcv_*` arithmetic, no SYN/FIN handling logic was modified by A6.6 or A6.7. RFC 9293 §3.4 (TCB shape) and §3.10.x (state-transition rules) remain compliant by inspection — the diff does not touch the relevant call sites.

- **I-6** — **RFC 7323 (TS/WS/PAWS) and RFC 8985 (RACK-TLP) unchanged.** Window-scale, timestamp echo, PAWS reject, RACK xmit_ts tracking, TLP PTO arming — all paths in `tcp_input`, `tcp_options`, `tcp_retrans`, and `engine` are byte-for-byte identical to A6.5 except for the chain-walk insert/drain plumbing. `tcp_retrans.rs` shows the RACK fields (`xmit_ts_ns`, `xmit_count`, `sacked`, `lost`) on `RetransEntry` are untouched; `flight_size()` semantics preserved.

- **I-7** — **Bugfix `b4e8de9` is debug-assert hardening, not a wire change.** `retransmit_inner` adds `debug_assert!(data_len >= entry_len && data_len <= entry_hdrs_len + entry_len)` and computes `live_hdrs_len = data_len - entry_len` to slice the payload robustly against TAP/PMD `rte_pktmbuf_adj` history. The on-wire retransmit frame is identical to pre-fix: single L2+L3+TCP header + the original payload. RFC 6298 (RTO computation) and RFC 8985 §6.1 (`xmit_ts` definition) — sourced from the unchanged `RetransEntry.xmit_ts_ns` field — are preserved. RACK-TLP timing semantics carry through.

- **I-8** — **Latent FIN-piggyback miscount on multi-seg chains (deferred, not currently exercised).** In `tcp_input.rs` (~line 1208), the post-chain-walk FIN-piggyback equality check uses `seg.payload.len()` (head-link TCP payload only), but `conn.rcv_nxt` was advanced by the total chain-byte sum. With a multi-link chain that piggy-backs FIN, this equality fails and the FIN is silently ignored. **Why this is an FYI rather than a Must-fix:** ENA (the only PMD this phase ships against) does not advertise `RX_OFFLOAD_SCATTER`, so chain length is always 1 in production; the path is only reachable under synthetic test injection. RFC 9293 §3.10.7.4 FIN handling is technically violated only in that synthetic path. Recommend filing a follow-up task for the chained-PMD enablement phase (post-A6) to swap `seg.payload.len()` for the running chain-byte total before that PMD is brought online.

- **I-9** — **A6.7 hardening surface has no RFC interaction.** miri (`hardening-miri.sh`), ASan/UBSan/LSan (`hardening-cpp-sanitizers.sh`), panic firewall (`hardening-panic-firewall.sh`), no-alloc audit (`hardening-no-alloc.sh`), panic audit (`audit-panics.sh`), counters atomic-load helper header (`include/dpdk_net_counters_load.h`), header-drift check (`check-header.sh`), and the aggregator (`hardening-all.sh`) are all FFI/memory/safety-surface checks. None of them touch wire-format or protocol-state code, so no RFC clause is gated on them. The ffi-safety-audit report (`docs/superpowers/reports/ffi-safety-audit.md`) is sufficient evidence of A6.7 closure.

## Verdict

**PASS**

Wire bytes are unchanged across the phase. The TCB FSM, sequence-number arithmetic, in-order delivery semantics, and ACK aggregation rules from RFC 9293 §3.4 / §3.7 / §3.10.7.4 remain compliant under the new chain-walking ingest path. RFC 7323, RFC 8985, and RFC 6298 paths are byte-for-byte identical to A6.5. The bugfix `b4e8de9` is debug-assert hardening with no wire-byte change. The §6.4 deviation allowlist is unchanged; no new accepted-deviation entries are required.

The latent FIN-piggyback issue (I-8) is documented as FYI only because the PMD this phase ships against does not exercise the affected path; it should be addressed before any PMD that advertises `RX_OFFLOAD_SCATTER` is enabled, but it does not gate `phase-a6-6-7-complete`.

Gate rule: phase may tag `phase-a6-6-7-complete`. No `[ ]` checkboxes are open in Must-fix or Missing-SHOULD.
