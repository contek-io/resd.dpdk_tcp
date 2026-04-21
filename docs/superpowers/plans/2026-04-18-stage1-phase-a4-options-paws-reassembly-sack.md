# resd.dpdk_tcp Stage 1 Phase A4 — TCP Options + PAWS + OOO Reassembly + SACK Scoreboard

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Negotiate TCP options at handshake (MSS + Window Scale + Timestamps + SACK-permitted), enforce RFC 7323 PAWS on every inbound segment, reassemble out-of-order segments into the in-order recv stream via a per-connection reorder queue, and track SACK blocks in both directions — decode peer SACK blocks from incoming ACKs into a scoreboard (A5 retransmit consumes it), encode SACK blocks on outbound ACKs when we have recv-side gaps. No retransmit, no RTO, no RACK — those are A5. Phase ends with an integration-test matrix (option negotiation smoke, PAWS replay rejection, OOO reassembly delivery, SACK encode+decode round-trip) and the mandatory mTCP + RFC review gates.

**Architecture:** Three new pure-Rust modules in `dpdk-net-core`: `tcp_options` (option encoder + decoder, full-set: MSS/WS/SACK-permitted/TS + SACK blocks; consolidates + replaces `tcp_input::parse_mss_option` and `tcp_output::SegmentTx.mss_option`), `tcp_reassembly` (`ReorderQueue` of `OooSegment { seq, payload }` sorted by wrap-aware seq, overlap-merge on insert, drain-on-gap-close), `tcp_sack` (`SackScoreboard` holding up to 4 peer-received SACK blocks; insert + merge + seq-is-sacked query for A5). `tcp_conn.rs` gains option-negotiated fields (`ws_shift_out`, `ws_shift_in`, `ts_enabled`, `ts_recent`, `ts_recent_age`, `sack_enabled`) + the reorder queue + the scoreboard; `RecvQueue` grows a `reorder: ReorderQueue` field. `tcp_input.rs` gains a PAWS check ahead of the seq-window check, rewrites `handle_established`'s OOO branch to push into the reorder queue + drain on gap-close, and decodes peer SACK blocks from inbound ACKs into the scoreboard. `tcp_output.rs` replaces the narrow `SegmentTx.mss_option: Option<u16>` with a `SegmentTx.options: TcpOptsBuilder` bundle that carries any combination of MSS/WS/SACK-permitted/TS/SACK-blocks, word-padded with NOPs. `engine.rs` emits full SYN options on `connect`, emits TS + WS-scaled window on every post-handshake ACK, emits SACK blocks on ACKs when `recv.reorder` is non-empty. `counters.rs` gains 15 new slow-path counters (6 A4-scope, 9 cross-phase backfill) + introduces two hot-path counters behind new cargo feature flags (`obs-byte-counters`, `obs-poll-saturation`). `api.rs` + the FFI `dpdk_net_tcp_counters_t` grow in lockstep under the layout assertion.

**Tech Stack:** same as A3 — Rust stable, DPDK 23.11, bindgen, cbindgen. New stdlib: none (the reorder queue uses `Vec`, the SACK scoreboard uses a small fixed array). New cargo features in `dpdk-net-core/Cargo.toml`: `obs-byte-counters` (default off), `obs-poll-saturation` (default on), and a meta-feature `obs-all` that turns both on for the A8 counter-coverage audit's `--all-features` run. The integration test crate uses the same `std::net::TcpListener` TAP-pair harness as A3.

**Spec reference:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §§ 6.2 (`ws_shift_out`/`ws_shift_in`/`ts_enabled`/`ts_recent`/`ts_recent_age`/`sack_enabled` field set), 6.3 RFC matrix rows for **7323** (Timestamps + Window Scale + PAWS), **2018** (SACK), **6691** (MSS — revisited with WS interaction), 6.4 (A4 may add deviation rows if PAWS edge cases surface that diverge from RFC 7323 §5), 7.2 (`recv_reorder` mbuf-chain envisioned; A4 continues the copy-based model per AD-A4-reassembly below), 9.1 (TCP counter group — 15 new slow-path + 2 hot-path), 9.1.1 (counter-addition policy — fetch_add default, hot-path feature-gated with per-burst batching), 10.13 (mTCP review gate), 10.14 (RFC compliance review gate).

**RFCs in scope for A4** (for the §10.14 RFC compliance review): **7323** (Window Scale MUST-22/-23, Timestamps MUST-24/-25, PAWS MUST in §5), **2018** (SACK-permitted negotiation, SACK block format, selective-ack semantics), **6691** (MSS clamping under negotiated WS — a given MSS plus WS still caps advertised window at (2^16 << ws) bytes, MUST-14/-15/-16 revisited), **9293** (segment-text processing for in-order vs out-of-order segments per §3.10.7.4 / §3.10.7.5). RFCs 6298, 8985, 5961, 3168, 7413 stay out of scope (A5/A6). All text is vendored at `docs/rfcs/rfcNNNN.txt`.

**Review gates at phase sign-off** (two reports, each a blocking gate per spec §10.13 / §10.14):
1. **A4 mTCP comparison review** — `docs/superpowers/reviews/phase-a4-mtcp-compare.md`. mTCP focus areas: `mtcp/src/tcp_util.c` (`ParseTCPOptions`, `ParseTCPTimestamp`, `ParseSACKOption`, `_update_sack_table`, `SeqIsSacked`, `GenerateSACKOption` — mTCP's encoder is a stub we fill in), `tcp_out.c::GenerateTCPOptions` (SYN options + non-SYN timestamps), `tcp_in.c::ValidateSequence` (PAWS gate), `tcp_ring_buffer.c::RBPut` (hole-fill merge semantics; we diverge on storage per AD-A4-reassembly), `tcp_rb_frag_queue.c` (free-frag MPSC ring — mTCP's particular mempool strategy; we use plain `Vec`), `tcp_stream.c` + `include/tcp_stream.h` (option-negotiated fields layout on `tcp_stream`).
2. **A4 RFC compliance review** — `docs/superpowers/reviews/phase-a4-rfc-compliance.md`. RFCs: 7323, 2018, 6691, 9293.

The `phase-a4-complete` tag is blocked while either report has an open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD.

**Deviations from spec — explicitly scoped for A4 (will land in later phases):**
- **Retransmit, RTO, RACK-TLP** → A5. A4 decodes peer SACK blocks into the scoreboard; actually **using** the scoreboard for selective retransmission is A5 RACK-TLP work.
- **Congestion control** (Reno under `cc_mode=reno`) → A5 follow-up. A4 carries `cc_mode` through the config but doesn't gate send rate on cwnd.
- **ECN** (on-path ECT/CE marking) → separate flag; no Stage 1 gate.
- **`DPDK_NET_EVT_WRITABLE`, real timer wheel, `dpdk_net_flush` actually flushing, `FORCE_TW_SKIP` + RFC 6191 guard** → A6.
- **`preset=rfc_compliance` switch** (delayed-ACK on, Nagle on, `min_rto=200`, `initial_rto=1000`, `cc_mode=reno`, burst-scope ACK coalescing) → A6. A4 keeps A3's per-segment ACK baseline.
- **Mbuf-pinning zero-copy delivery model** (spec §7.2 + §7.3) → a later phase (probably A10 perf work or the A6 API surface completion). A4 continues A3's copy-based model for both in-order and OOO — documented as AD-A4-reassembly below.

**Design decisions recorded during planning (pre-plan):**

1. **Spec §9.1 write model reconciliation (P3).** Spec §9.1 previously said "Hot-path writes are `store(val+1, Ordering::Relaxed)`", which is a load-modify-store pattern: safe only under the single-owner-lcore invariant, lost-update-fragile if the invariant ever slips in a future refactor. Actual code in `crates/dpdk-net-core/src/counters.rs:141,146` uses `fetch_add(1, Ordering::Relaxed)` universally. §9.1.1 (added in the prior session) assumes `fetch_add`'s `lock xadd` cost (~8-12 cycles). **Resolution committed before this plan:** spec §9.1 amended in the A4 planning-fixes commit to say "Counter writes are `fetch_add(1, Ordering::Relaxed)` (`lock xadd` on x86_64; ~8-12 cycles uncontended)" so the two sections agree. §9.1.1 batching guidance (per-burst stack-local accumulator + single aggregate `fetch_add`) stands as the hot-path policy. No code change — only spec text. This decision is frozen for A4; future perf work may revisit under §9.1.1 rule 3 (explicit exception) with a benchmark-backed spec amendment.

2. **AD-2 revisit alongside PAWS.** Spec §6.4 AD-2 (both-edges seq-window check in `handle_established`) and A3's plan-header accepted divergence #2. PAWS (RFC 7323 §5) added in A4 rejects stale-TS-val segments before the seq-window check runs; it's a strictly stronger filter than AD-2 against wrapped-seq attacks (AD-2's original rationale). AD-2's remaining cost is marginal snd_una-advance delay on retransmits whose seq range straddles rcv_nxt — and A3 has no retransmit. **Resolution:** A4 keeps AD-2 (both-edges) as-is; PAWS is additive, not a replacement. Loosening AD-2 to mTCP's right-edge-only check deferred to A5 alongside RACK-TLP + retransmit, because the cost of rejecting in-flight retransmits only starts to bite once we generate them. A4 mTCP review documents "AD-2 persists + PAWS supersedes the anti-wrap rationale" as an annotation on AD-2.

3. **OOO reassembly data structure.** Spec §7.2 + §7.3 envision `recv_reorder` as a list of `(seq_range, mbuf_ref)` with zero copies on the receive path. A3 accepted AD-7 (in-order `recv_queue` as `VecDeque<u8>`, not mbuf-chain) so the stack already copies once from mbuf to ring on RX. Continuing the spec's mbuf-pinning model for OOO only would mean two delivery models co-existing, inconsistent. **Resolution:** A4 extends A3's copy-based model to OOO. Reorder queue is `Vec<OooSegment { seq: u32, payload: Vec<u8> }>` on `RecvQueue`, sorted by wrap-aware seq, overlap-merge on insert (mTCP `CanMerge`/`MergeFragments` semantics in `tcp_ring_buffer.c:264-285`). In-order arrival at `rcv_nxt` drains contiguous-prefix front entries into `recv.bytes`. Total buffered bytes (in-order `recv.bytes.len() + Σ reorder[i].payload.len()`) capped at `recv_buffer_bytes`; once reached, the incoming segment is partial-accepted and `tcp.recv_buf_drops` catches the overflow (same policy as A3 AD-9). Documented as AD-A4-reassembly below, extending AD-7. Mbuf-pinning zero-copy deferred to a later phase (likely alongside A10 perf bench work or A6's API-surface completion).

**Pre-emptive Accepted Divergences vs mTCP (to land in the A4 mTCP review):**

- **AD-A4-options-encoder** — Our `TcpOptsBuilder` emits MSS + SACK-permitted + TS + WS on SYN in a **fixed canonical order** with explicit NOP padding for word alignment. mTCP's `GenerateTCPOptions` uses conditional `#if TCP_OPT_TIMESTAMP_ENABLED` / `#if TCP_OPT_SACK_ENABLED` switches and varies NOP placement depending on which pair is compiled in. Net wire format is equivalent either way; our fixed order is simpler to test and avoids dead code paths.
- **AD-A4-reassembly** (extends A3's AD-7) — OOO segments stored as `Vec<OooSegment { seq, payload: Vec<u8> }>` (one memcpy per OOO segment on insert) rather than mTCP's mempool-backed `fragment_ctx` chain + linear ring buffer + `free_fragq` MPSC (zero additional copy, memcpy-on-RBPut into the linear buffer). Spec §7.2 + §7.3 envision a zero-copy mbuf chain for both in-order and OOO — A3 already diverged via AD-7 (VecDeque<u8>); A4 continues the same copy-based model for consistency. Cost: one memcpy per OOO insert + one more on gap-close drain. Benefit: no mempool sizing, no free-list, `Vec` grows + shrinks on demand within `recv_buffer_bytes`. Migration to mbuf-pinning deferred to a later phase.
- **AD-A4-sack-generate** — mTCP's `GenerateSACKOption` in `tcp_util.c:180` is a `// TODO: return 0;` stub — mTCP receives and scoreboards peer SACK blocks but never encodes its own. We **do** encode up to 3 SACK blocks on outbound ACKs when `recv.reorder` is non-empty, per RFC 2018 §4 (the sender of the data — i.e., the peer — uses our SACK to retransmit targeted segments rather than the entire window-after-snd_una). This is strictly more RFC-compliant than mTCP on the encode side. Decoder parity is maintained: our `tcp_options::parse_sack_blocks` matches mTCP's `ParseSACKOption` in `tcp_util.c:187-241` semantically.
- **AD-A4-sack-scoreboard-size** — mTCP's `sack_table` is `MAX_SACK_ENTRY` entries (typically 8). We ship `SackScoreboard` with a fixed-size array of 4 entries (RFC 2018 §3 caps the number of SACK blocks per segment at 3-4 depending on whether TS is present; 4 covers the worst-case single-ACK case and the overflow policy — merge-or-drop-oldest — keeps memory bounded). Documented inline with the rationale.
- **AD-A4-paws-challenge-ack** — On PAWS failure, mTCP's `ValidateSequence` (`tcp_in.c:131`) enqueues an ACK with `ACK_OPT_NOW`. We emit `TxAction::Ack` inline in the same poll iteration (matching A3's per-segment-ACK baseline AD-A3-ack-per-segment). The effective wire behavior is identical; this is an architectural divergence, not a protocol one. `tcp.rx_paws_rejected` counter fires once per PAWS-dropped segment.
- **AD-A4-option-strictness** (extends A3's I-9) — Our option decoder rejects malformed TS (`len != 10`), malformed WS (`len != 3`), malformed SACK-permitted (`len != 2`), malformed SACK-blocks (`len not in {10, 18, 26, 34}` — one to four (left, right) pairs with the 2-byte kind+len header), and zero/short optlen; mTCP's `ParseTCPOptions` has the I-6 infinite-loop bug on `optlen < 2` for unknown kinds (`tcp_util.c:31`) and accepts out-of-spec lengths for known options. Our stricter parser bumps `tcp.rx_bad_option` on the rejection path. A4 review documents this as strict-in-A4 without going negative on mTCP.

---

## File Structure Created or Modified in This Phase

```
crates/dpdk-net-core/
├── Cargo.toml              (MODIFIED: [features] obs-byte-counters / obs-poll-saturation / obs-all)
├── src/
│   ├── lib.rs              (MODIFIED: expose tcp_options, tcp_reassembly, tcp_sack; remove pub-use of parse_mss_option)
│   ├── counters.rs         (MODIFIED: 15 new slow-path fields + 2 hot-path fields; _pad shrinks; new tests)
│   ├── tcp_conn.rs         (MODIFIED: TcpConn option-negotiated fields + reorder queue + sack scoreboard)
│   ├── tcp_input.rs        (MODIFIED: PAWS gate, OOO branch rewrites to reassembly insert, peer SACK decode, cross-phase counter increment sites)
│   ├── tcp_output.rs       (MODIFIED: SegmentTx.options bundle replaces narrow mss_option; full option encoder; WS-scaled window writes)
│   ├── engine.rs           (MODIFIED: connect emits full SYN options, emit_ack emits TS + WS-scaled wnd + SACK when reorder nonempty, tcp_input wires new counters + ooo enqueue, drain-on-gap-close readable emission)
│   ├── tcp_options.rs      (NEW: option encode + decode; TcpOpts, TcpOptsBuilder, parse_options, parse_sack_blocks)
│   ├── tcp_reassembly.rs   (NEW: OooSegment, ReorderQueue insert/merge/drain)
│   └── tcp_sack.rs         (NEW: SackScoreboard insert/merge/query)
└── tests/
    └── tcp_options_paws_reassembly_sack_tap.rs  (NEW: 4 integration tests over TAP)

crates/dpdk-net/src/
├── api.rs                  (MODIFIED: dpdk_net_tcp_counters_t mirrors the 15 slow-path + 2 hot-path additions; layout assertion covers them)
└── lib.rs                  (no change — no new extern "C" functions; A4 is purely internal / observability)

include/dpdk_net.h          (REGENERATED via cbindgen)

examples/cpp-consumer/main.cpp
                            (MODIFIED: print the 6 A4-scope slow-path TCP counters + rx_sack_blocks)

docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md
                            (ALREADY AMENDED in the A4 planning-fixes commit: §9.1 write model;
                             NEW ROW may be added by Task 27 if PAWS reveals a deviation)
docs/superpowers/plans/stage1-phase-roadmap.md
                            (ALREADY AMENDED in the A4 planning-fixes commit: A4 counter list; A12 row;
                             MODIFIED at the end of this phase: status update at A4 sign-off)
docs/superpowers/reviews/phase-a4-mtcp-compare.md       (NEW: A4 mTCP comparison review)
docs/superpowers/reviews/phase-a4-rfc-compliance.md    (NEW: A4 RFC compliance review)
```

---

## Task 1: Extend `TcpCounters` for A4 slow-path counters

**Goal:** Land 15 new slow-path fields on `TcpCounters` — 6 A4-scope (`rx_paws_rejected`, `rx_bad_option`, `rx_reassembly_queued`, `rx_reassembly_hole_filled`, `tx_sack_blocks`, `rx_sack_blocks`) and 9 cross-phase backfill (`rx_bad_seq`, `rx_bad_ack`, `rx_dup_ack`, `rx_zero_window`, `rx_urgent_dropped`, `tx_zero_window`, `tx_window_update`, `conn_table_full`, `conn_time_wait_reaped`). Insert them between `recv_buf_drops` and `state_trans`; `_pad[3]` stays where it is and the struct grows by 15 u64 = 120 bytes (the `#[repr(C, align(64))]` absorbs the alignment round-up in implicit trailing padding). All fields zero at construction.

**Files:**
- Modify: `crates/dpdk-net-core/src/counters.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/src/counters.rs` inside `mod tests`:

```rust
    #[test]
    fn a4_new_tcp_counters_exist_and_zero() {
        let c = Counters::new();
        // A4 scope
        assert_eq!(c.tcp.rx_paws_rejected.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_bad_option.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_reassembly_queued.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_reassembly_hole_filled.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_sack_blocks.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_sack_blocks.load(Ordering::Relaxed), 0);
        // Cross-phase backfill
        assert_eq!(c.tcp.rx_bad_seq.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_bad_ack.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_dup_ack.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_zero_window.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_urgent_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_zero_window.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_window_update.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.conn_table_full.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.conn_time_wait_reaped.load(Ordering::Relaxed), 0);
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core counters::tests::a4_new_tcp_counters_exist_and_zero -- --nocapture`
Expected: FAIL with "no field `rx_paws_rejected` on type `TcpCounters`".

- [ ] **Step 3: Extend `TcpCounters` with the new fields**

In `crates/dpdk-net-core/src/counters.rs`, replace the `TcpCounters` struct body — insert the new fields between `recv_buf_drops` and `state_trans`:

```rust
#[repr(C, align(64))]
pub struct TcpCounters {
    pub rx_syn_ack: AtomicU64,
    pub rx_data: AtomicU64,
    pub rx_ack: AtomicU64,
    pub rx_rst: AtomicU64,
    pub rx_out_of_order: AtomicU64,
    pub tx_retrans: AtomicU64,
    pub tx_rto: AtomicU64,
    pub tx_tlp: AtomicU64,
    pub conn_open: AtomicU64,
    pub conn_close: AtomicU64,
    pub conn_rst: AtomicU64,
    pub send_buf_full: AtomicU64,
    pub recv_buf_delivered: AtomicU64,
    // Phase A3 additions
    pub tx_syn: AtomicU64,
    pub tx_ack: AtomicU64,
    pub tx_data: AtomicU64,
    pub tx_fin: AtomicU64,
    pub tx_rst: AtomicU64,
    pub rx_fin: AtomicU64,
    pub rx_unmatched: AtomicU64,
    pub rx_bad_csum: AtomicU64,
    pub rx_bad_flags: AtomicU64,
    pub rx_short: AtomicU64,
    /// Phase A3: bytes peer sent beyond our current recv buffer free_space.
    /// See `feedback_performance_first_flow_control.md` — we don't shrink
    /// rcv_wnd to throttle the peer; we keep accepting at full capacity and
    /// expose pressure here so the application can diagnose a slow consumer.
    pub recv_buf_drops: AtomicU64,
    // Phase A4 additions — slow-path only per spec §9.1.1.
    /// PAWS (RFC 7323 §5): segment dropped because `SEG.TSval < TS.Recent`.
    pub rx_paws_rejected: AtomicU64,
    /// TCP option decoder rejected a malformed option (runaway len, zero
    /// optlen on unknown kind, known-option wrong length). Extends A3's
    /// defensive posture (plan I-9) to WSCALE / TS / SACK-permitted / SACK.
    pub rx_bad_option: AtomicU64,
    /// OOO segment placed on the reassembly queue (fires on reorder/loss).
    pub rx_reassembly_queued: AtomicU64,
    /// Hole closed; contiguous prefix drained from reassembly into recv.
    pub rx_reassembly_hole_filled: AtomicU64,
    /// SACK blocks encoded in an outbound ACK (RFC 2018; fires only when
    /// recv.reorder is non-empty).
    pub tx_sack_blocks: AtomicU64,
    /// SACK blocks decoded from an inbound ACK (RFC 2018; fires only on
    /// peer-side loss).
    pub rx_sack_blocks: AtomicU64,
    // Cross-phase slow-path backfill — sites exist from earlier phases but
    // had no counter until A4 wired them.
    /// Segment with seq outside `rcv_wnd`; was silently dropped pre-A4.
    pub rx_bad_seq: AtomicU64,
    /// ACK acking nothing new or acking future data.
    pub rx_bad_ack: AtomicU64,
    /// Duplicate ACK (baseline for A5 fast-retransmit consumer).
    pub rx_dup_ack: AtomicU64,
    /// Peer advertised `rwnd=0` — critical trading signal ("exchange is slow").
    pub rx_zero_window: AtomicU64,
    /// URG flag segment; Stage 1 doesn't support URG, dropped.
    pub rx_urgent_dropped: AtomicU64,
    /// We advertised `rwnd=0` (our recv buffer full).
    pub tx_zero_window: AtomicU64,
    /// We emitted a pure window-update segment.
    pub tx_window_update: AtomicU64,
    /// `dpdk_net_connect` rejected because flow table at `max_connections`.
    pub conn_table_full: AtomicU64,
    /// TIME_WAIT deadline expired, connection reclaimed.
    pub conn_time_wait_reaped: AtomicU64,
    /// 11×11 state transition matrix, indexed [from][to] where from/to are
    /// `TcpState as u8`. Per spec §9.1. Unused cells stay at zero.
    pub state_trans: [[AtomicU64; 11]; 11],
    _pad: [u64; 3],
}
```

- [ ] **Step 4: Run — verify it passes**

Run: `cargo test -p dpdk-net-core counters::tests::a4_new_tcp_counters_exist_and_zero -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Run the full counters test module**

Run: `cargo test -p dpdk-net-core counters::tests --`
Expected: all counter tests pass (including the A3 tests — we didn't change their semantics).

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-core/src/counters.rs
git commit -m "a4: extend TcpCounters — 6 A4-scope + 9 cross-phase slow-path fields"
```

---

## Task 2: Mirror A4 counter fields in the FFI `dpdk_net_tcp_counters_t`

**Goal:** Keep `crates/dpdk-net/src/api.rs` `dpdk_net_tcp_counters_t` in lockstep with the core `TcpCounters`. The `const _: ()` layout assertion at the bottom of `api.rs` enforces size + alignment parity; Task 1's struct change will break that assertion until this task lands. Order + field names must match exactly so `dpdk_net_counters()`'s pointer cast is sound.

**Files:**
- Modify: `crates/dpdk-net/src/api.rs`

- [ ] **Step 1: Run the layout assertion (expected to fail after Task 1)**

Run: `cargo build -p dpdk-net`
Expected: FAIL — `size_of::<dpdk_net_tcp_counters_t>() == size_of::<CoreTcp>()` const-eval asserts fires because we added 15 u64s to `CoreTcp` but not to the FFI mirror.

- [ ] **Step 2: Mirror the fields on the FFI side**

In `crates/dpdk-net/src/api.rs`, replace the `dpdk_net_tcp_counters_t` struct body — insert the same 15 fields between `recv_buf_drops` and `state_trans`:

```rust
#[repr(C, align(64))]
pub struct dpdk_net_tcp_counters_t {
    pub rx_syn_ack: u64,
    pub rx_data: u64,
    pub rx_ack: u64,
    pub rx_rst: u64,
    pub rx_out_of_order: u64,
    pub tx_retrans: u64,
    pub tx_rto: u64,
    pub tx_tlp: u64,
    pub conn_open: u64,
    pub conn_close: u64,
    pub conn_rst: u64,
    pub send_buf_full: u64,
    pub recv_buf_delivered: u64,
    // Phase A3 additions
    pub tx_syn: u64,
    pub tx_ack: u64,
    pub tx_data: u64,
    pub tx_fin: u64,
    pub tx_rst: u64,
    pub rx_fin: u64,
    pub rx_unmatched: u64,
    pub rx_bad_csum: u64,
    pub rx_bad_flags: u64,
    pub rx_short: u64,
    /// Phase A3: bytes peer sent beyond our current recv buffer free_space.
    /// See `feedback_performance_first_flow_control.md` — we don't shrink
    /// rcv_wnd to throttle the peer; we keep accepting at full capacity and
    /// expose pressure here so the application can diagnose a slow consumer.
    pub recv_buf_drops: u64,
    // Phase A4 additions — see core counters.rs for the full field doc.
    pub rx_paws_rejected: u64,
    pub rx_bad_option: u64,
    pub rx_reassembly_queued: u64,
    pub rx_reassembly_hole_filled: u64,
    pub tx_sack_blocks: u64,
    pub rx_sack_blocks: u64,
    pub rx_bad_seq: u64,
    pub rx_bad_ack: u64,
    pub rx_dup_ack: u64,
    pub rx_zero_window: u64,
    pub rx_urgent_dropped: u64,
    pub tx_zero_window: u64,
    pub tx_window_update: u64,
    pub conn_table_full: u64,
    pub conn_time_wait_reaped: u64,
    pub state_trans: [[u64; 11]; 11],
    pub _pad: [u64; 3],
}
```

- [ ] **Step 3: Build — verify the layout assertion passes**

Run: `cargo build -p dpdk-net`
Expected: PASS.

- [ ] **Step 4: Regenerate `include/dpdk_net.h` and verify drift check**

Run: `cargo build -p dpdk-net --features cbindgen-gen && cargo test -p dpdk-net header_drift`
Expected: PASS (header regenerated; drift test reads the same file just regenerated).

If the repo uses a different drift-check command (look in `build.rs` or workspace `Cargo.toml` for a `[[test]]` named `header_drift` or similar), run that instead.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net/src/api.rs include/dpdk_net.h
git commit -m "a4: mirror new TcpCounters fields in dpdk_net_tcp_counters_t + regenerate header"
```

---

## Task 3: Create `tcp_options.rs` — types + encoder

**Goal:** Introduce a single-module option encoder covering all four Stage-1-relevant TCP options (MSS, WSCALE, SACK-permitted, Timestamps) plus SACK blocks for non-SYN ACKs. The types are a declarative `TcpOpts` snapshot + a `TcpOptsBuilder` that writes a canonical byte sequence into a caller-provided slice. Task 4 adds the decoder; Task 11 wires the builder into `SegmentTx`.

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_options.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs` (expose `pub mod tcp_options;`)

- [ ] **Step 1: Add module declaration to `lib.rs`**

Insert the line `pub mod tcp_options;` alphabetically among the existing `pub mod` entries in `crates/dpdk-net-core/src/lib.rs`.

- [ ] **Step 2: Write the failing test first**

Create `crates/dpdk-net-core/src/tcp_options.rs` with:

```rust
//! TCP option encode + decode for Stage 1 A4 scope:
//! MSS (RFC 6691), Window Scale + Timestamps (RFC 7323),
//! SACK-permitted + SACK blocks (RFC 2018).
//!
//! Encoder (this file's first half) emits options in a fixed canonical
//! order with explicit NOP padding for 4-byte word alignment. Decoder
//! (Task 4) parses bytes back into the same `TcpOpts` representation.
//! Malformed input (runaway len, wrong-length known options) is rejected
//! at parse time and bumps `tcp.rx_bad_option`; see `parse_options`'s
//! return type `Result<TcpOpts, OptionParseError>`.

// TCP option kinds per IANA.
pub const OPT_END: u8 = 0;
pub const OPT_NOP: u8 = 1;
pub const OPT_MSS: u8 = 2;
pub const OPT_WSCALE: u8 = 3;
pub const OPT_SACK_PERMITTED: u8 = 4;
pub const OPT_SACK: u8 = 5;
pub const OPT_TIMESTAMP: u8 = 8;

// Option total lengths (kind+len+value) per the respective RFCs.
pub const LEN_MSS: u8 = 4;
pub const LEN_WSCALE: u8 = 3;
pub const LEN_SACK_PERMITTED: u8 = 2;
pub const LEN_TIMESTAMP: u8 = 10;
// SACK block: 2 header + 8*N, N in 1..=4 per RFC 2018 §3.

/// Maximum number of SACK blocks we emit on an ACK. RFC 2018 §3 caps at
/// 3 when the Timestamps option is present (40-byte option budget: 10
/// for TS + 2 NOPs + at most 26 left for SACK = 3 blocks × 8 bytes
/// + 2 header). With Timestamps absent the cap is 4; we always emit
/// with Timestamps so 3 is the right ceiling.
pub const MAX_SACK_BLOCKS_EMIT: usize = 3;

/// A single SACK block (RFC 2018 §3). Seqs are host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlock {
    pub left: u32,
    pub right: u32,
}

/// Parsed TCP options + SACK blocks. Used for both RX decode and TX
/// build. `sack_blocks` is a fixed-size array to avoid allocation on
/// the hot path.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpOpts {
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_permitted: bool,
    /// TSval + TSecr per RFC 7323 §3.
    pub timestamps: Option<(u32, u32)>,
    pub sack_blocks: [SackBlock; MAX_SACK_BLOCKS_EMIT],
    pub sack_block_count: u8,
}

impl TcpOpts {
    pub fn push_sack_block(&mut self, block: SackBlock) -> bool {
        if (self.sack_block_count as usize) >= MAX_SACK_BLOCKS_EMIT {
            return false;
        }
        self.sack_blocks[self.sack_block_count as usize] = block;
        self.sack_block_count += 1;
        true
    }

    /// Byte length of the encoded option sequence, rounded up to the
    /// next 4-byte word via NOP padding.
    pub fn encoded_len(&self) -> usize {
        let mut n = 0usize;
        if self.mss.is_some() { n += LEN_MSS as usize; }
        if self.sack_permitted { n += LEN_SACK_PERMITTED as usize; }
        if self.timestamps.is_some() { n += LEN_TIMESTAMP as usize; }
        if self.wscale.is_some() { n += LEN_WSCALE as usize; }
        if self.sack_block_count > 0 {
            n += 2 + 8 * (self.sack_block_count as usize);
        }
        // Word-align.
        let rem = n % 4;
        if rem != 0 { n += 4 - rem; }
        n
    }

    /// Write the options to `out[..N]` in canonical order
    /// (MSS, SACK-permitted, Timestamps, WS, SACK-blocks), padding with
    /// NOPs (kind=1) to reach a 4-byte word boundary. Returns the number
    /// of bytes written, or `None` if `out` is too short.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let need = self.encoded_len();
        if out.len() < need { return None; }

        let mut i = 0usize;
        if let Some(mss) = self.mss {
            out[i] = OPT_MSS; out[i+1] = LEN_MSS;
            out[i+2..i+4].copy_from_slice(&mss.to_be_bytes());
            i += LEN_MSS as usize;
        }
        if self.sack_permitted {
            out[i] = OPT_SACK_PERMITTED; out[i+1] = LEN_SACK_PERMITTED;
            i += LEN_SACK_PERMITTED as usize;
        }
        if let Some((tsval, tsecr)) = self.timestamps {
            out[i] = OPT_TIMESTAMP; out[i+1] = LEN_TIMESTAMP;
            out[i+2..i+6].copy_from_slice(&tsval.to_be_bytes());
            out[i+6..i+10].copy_from_slice(&tsecr.to_be_bytes());
            i += LEN_TIMESTAMP as usize;
        }
        if let Some(ws) = self.wscale {
            out[i] = OPT_WSCALE; out[i+1] = LEN_WSCALE; out[i+2] = ws;
            i += LEN_WSCALE as usize;
        }
        if self.sack_block_count > 0 {
            let n = self.sack_block_count as usize;
            out[i] = OPT_SACK; out[i+1] = (2 + 8 * n) as u8;
            i += 2;
            for block in &self.sack_blocks[..n] {
                out[i..i+4].copy_from_slice(&block.left.to_be_bytes());
                out[i+4..i+8].copy_from_slice(&block.right.to_be_bytes());
                i += 8;
            }
        }
        // NOP-pad to the next word boundary.
        while i < need {
            out[i] = OPT_NOP;
            i += 1;
        }
        Some(need)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_syn_options_encode_in_canonical_order() {
        let mut opts = TcpOpts::default();
        opts.mss = Some(1460);
        opts.sack_permitted = true;
        opts.timestamps = Some((0xdeadbeef, 0));
        opts.wscale = Some(7);
        let mut buf = [0u8; 40];
        let n = opts.encode(&mut buf).unwrap();
        // 4 MSS + 2 SACK-perm + 10 TS + 3 WS = 19, padded to 20.
        assert_eq!(n, 20);
        // MSS
        assert_eq!(&buf[..4], &[OPT_MSS, LEN_MSS, 0x05, 0xb4]);
        // SACK-permitted
        assert_eq!(&buf[4..6], &[OPT_SACK_PERMITTED, LEN_SACK_PERMITTED]);
        // Timestamps
        assert_eq!(buf[6], OPT_TIMESTAMP);
        assert_eq!(buf[7], LEN_TIMESTAMP);
        assert_eq!(&buf[8..12], &0xdeadbeefu32.to_be_bytes());
        assert_eq!(&buf[12..16], &0u32.to_be_bytes());
        // Window Scale
        assert_eq!(&buf[16..19], &[OPT_WSCALE, LEN_WSCALE, 7]);
        // NOP pad
        assert_eq!(buf[19], OPT_NOP);
    }

    #[test]
    fn ack_with_timestamp_and_two_sack_blocks_word_aligned() {
        let mut opts = TcpOpts::default();
        opts.timestamps = Some((100, 200));
        opts.push_sack_block(SackBlock { left: 1000, right: 2000 });
        opts.push_sack_block(SackBlock { left: 3000, right: 4000 });
        let mut buf = [0u8; 40];
        let n = opts.encode(&mut buf).unwrap();
        // 10 TS + 2 SACK-hdr + 16 SACK-blocks = 28, already word-aligned.
        assert_eq!(n, 28);
        assert_eq!(buf[10], OPT_SACK);
        assert_eq!(buf[11], 2 + 16); // len = hdr + 2×(8)
        assert_eq!(&buf[12..16], &1000u32.to_be_bytes());
        assert_eq!(&buf[16..20], &2000u32.to_be_bytes());
        assert_eq!(&buf[20..24], &3000u32.to_be_bytes());
        assert_eq!(&buf[24..28], &4000u32.to_be_bytes());
    }

    #[test]
    fn empty_options_encode_to_zero_bytes() {
        let opts = TcpOpts::default();
        let mut buf = [0u8; 4];
        let n = opts.encode(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn encode_returns_none_when_out_too_small() {
        let mut opts = TcpOpts::default();
        opts.mss = Some(1460);
        let mut buf = [0u8; 2];
        assert!(opts.encode(&mut buf).is_none());
    }

    #[test]
    fn sack_block_count_caps_at_max() {
        let mut opts = TcpOpts::default();
        assert!(opts.push_sack_block(SackBlock { left: 0, right: 1 }));
        assert!(opts.push_sack_block(SackBlock { left: 2, right: 3 }));
        assert!(opts.push_sack_block(SackBlock { left: 4, right: 5 }));
        assert!(!opts.push_sack_block(SackBlock { left: 6, right: 7 }));
        assert_eq!(opts.sack_block_count, 3);
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p dpdk-net-core tcp_options::tests`
Expected: PASS (all 5 tests green).

- [ ] **Step 4: Clippy clean**

Run: `cargo clippy -p dpdk-net-core --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/lib.rs crates/dpdk-net-core/src/tcp_options.rs
git commit -m "a4: tcp_options.rs — TcpOpts + encoder (MSS/WS/SACK-perm/TS + SACK blocks)"
```

---

## Task 4: `tcp_options.rs` — decoder + defensive parser tests

**Goal:** Decode a byte slice of TCP options into a `TcpOpts` value. The parser must reject the mTCP I-6 infinite-loop on `optlen < 2` for unknown kinds, the invariance of known-option lengths (MSS = 4, WS = 3, SACK-permitted = 2, TS = 10, SACK = 2 + 8*N with N ∈ 1..=4), and truncation mid-option. On any rejection the parser returns `Err(OptionParseError)` and the caller bumps `tcp.rx_bad_option`. Normal parses ignore unknown kinds per RFC 9293 §3.1 "TCP Options" (advance by the option's `len`).

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_options.rs`

- [ ] **Step 1: Add the decoder + parser-error enum**

Append to `crates/dpdk-net-core/src/tcp_options.rs` (below the `impl TcpOpts` block, above `#[cfg(test)]`):

```rust
/// Errors from `parse_options`. Every variant maps to one `tcp.rx_bad_option`
/// bump on the caller side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionParseError {
    /// `optlen < 2` on an unknown option kind (would underflow advance).
    ShortUnknown,
    /// `optlen` on a known-kind doesn't match the RFC value.
    BadKnownLen,
    /// Option would extend past the end of the options region.
    Truncated,
    /// SACK block count isn't in 1..=MAX_SACK_BLOCKS_EMIT (zero blocks
    /// or too many).
    BadSackBlockCount,
}

/// Parse TCP options per RFC 9293 §3.1. Returns the fully populated
/// `TcpOpts`; unknown option kinds are skipped by their declared length
/// (with the defensive `optlen >= 2` check that mTCP's `ParseTCPOptions`
/// lacks, see the mTCP I-6 note in A3's review).
pub fn parse_options(opts: &[u8]) -> Result<TcpOpts, OptionParseError> {
    let mut out = TcpOpts::default();
    let mut i = 0usize;
    while i < opts.len() {
        match opts[i] {
            OPT_END => return Ok(out),
            OPT_NOP => { i += 1; continue; }
            kind => {
                if i + 1 >= opts.len() {
                    return Err(OptionParseError::Truncated);
                }
                let olen = opts[i + 1] as usize;
                if olen < 2 {
                    return Err(OptionParseError::ShortUnknown);
                }
                if i + olen > opts.len() {
                    return Err(OptionParseError::Truncated);
                }
                match kind {
                    OPT_MSS => {
                        if olen != LEN_MSS as usize {
                            return Err(OptionParseError::BadKnownLen);
                        }
                        out.mss = Some(u16::from_be_bytes([opts[i+2], opts[i+3]]));
                    }
                    OPT_WSCALE => {
                        if olen != LEN_WSCALE as usize {
                            return Err(OptionParseError::BadKnownLen);
                        }
                        out.wscale = Some(opts[i+2]);
                    }
                    OPT_SACK_PERMITTED => {
                        if olen != LEN_SACK_PERMITTED as usize {
                            return Err(OptionParseError::BadKnownLen);
                        }
                        out.sack_permitted = true;
                    }
                    OPT_TIMESTAMP => {
                        if olen != LEN_TIMESTAMP as usize {
                            return Err(OptionParseError::BadKnownLen);
                        }
                        let tsval = u32::from_be_bytes([opts[i+2], opts[i+3], opts[i+4], opts[i+5]]);
                        let tsecr = u32::from_be_bytes([opts[i+6], opts[i+7], opts[i+8], opts[i+9]]);
                        out.timestamps = Some((tsval, tsecr));
                    }
                    OPT_SACK => {
                        // len = 2 (hdr) + 8 * N, N in 1..=4.
                        let block_bytes = olen.saturating_sub(2);
                        if block_bytes == 0 || block_bytes % 8 != 0 || block_bytes / 8 > 4 {
                            return Err(OptionParseError::BadSackBlockCount);
                        }
                        // Store as many as fit in our fixed-size array; drop
                        // the excess silently (RFC-legal since SACK blocks
                        // are advisory for the sender).
                        let mut bi = i + 2;
                        for _ in 0..(block_bytes / 8) {
                            let left = u32::from_be_bytes([opts[bi], opts[bi+1], opts[bi+2], opts[bi+3]]);
                            let right = u32::from_be_bytes([opts[bi+4], opts[bi+5], opts[bi+6], opts[bi+7]]);
                            out.push_sack_block(SackBlock { left, right });
                            bi += 8;
                        }
                    }
                    _ => {
                        // Unknown kind — skip by len. olen ≥ 2 guaranteed above.
                    }
                }
                i += olen;
            }
        }
    }
    Ok(out)
}
```

- [ ] **Step 2: Append decoder tests**

Append to the `#[cfg(test)] mod tests` block in `tcp_options.rs`:

```rust
    #[test]
    fn parse_empty_options_returns_default() {
        let opts = parse_options(&[]).unwrap();
        assert_eq!(opts.mss, None);
        assert_eq!(opts.wscale, None);
        assert!(!opts.sack_permitted);
        assert_eq!(opts.timestamps, None);
        assert_eq!(opts.sack_block_count, 0);
    }

    #[test]
    fn parse_end_short_circuits() {
        let bytes = [OPT_MSS, LEN_MSS, 0x05, 0xb4, OPT_END, 0xff, 0xff];
        let opts = parse_options(&bytes).unwrap();
        assert_eq!(opts.mss, Some(1460));
    }

    #[test]
    fn parse_nop_advances_one_byte() {
        let bytes = [OPT_NOP, OPT_NOP, OPT_MSS, LEN_MSS, 0x05, 0xb4];
        let opts = parse_options(&bytes).unwrap();
        assert_eq!(opts.mss, Some(1460));
    }

    #[test]
    fn parse_full_syn_options_round_trips_encode() {
        let mut built = TcpOpts::default();
        built.mss = Some(1460);
        built.sack_permitted = true;
        built.timestamps = Some((0x1122_3344, 0x5566_7788));
        built.wscale = Some(7);
        let mut buf = [0u8; 40];
        let n = built.encode(&mut buf).unwrap();
        let parsed = parse_options(&buf[..n]).unwrap();
        assert_eq!(parsed.mss, Some(1460));
        assert_eq!(parsed.wscale, Some(7));
        assert!(parsed.sack_permitted);
        assert_eq!(parsed.timestamps, Some((0x1122_3344, 0x5566_7788)));
    }

    #[test]
    fn parse_sack_blocks_three_roundtrips() {
        let mut built = TcpOpts::default();
        built.timestamps = Some((0, 0));
        built.push_sack_block(SackBlock { left: 100, right: 200 });
        built.push_sack_block(SackBlock { left: 300, right: 400 });
        built.push_sack_block(SackBlock { left: 500, right: 600 });
        let mut buf = [0u8; 40];
        let n = built.encode(&mut buf).unwrap();
        let parsed = parse_options(&buf[..n]).unwrap();
        assert_eq!(parsed.sack_block_count, 3);
        assert_eq!(parsed.sack_blocks[0], SackBlock { left: 100, right: 200 });
        assert_eq!(parsed.sack_blocks[1], SackBlock { left: 300, right: 400 });
        assert_eq!(parsed.sack_blocks[2], SackBlock { left: 500, right: 600 });
    }

    #[test]
    fn parse_rejects_zero_optlen_unknown_kind() {
        // Kind 99 (unknown), len=0 — would infinite-loop in mTCP.
        let bytes = [99u8, 0u8, 0x42];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::ShortUnknown);
    }

    #[test]
    fn parse_rejects_wrong_mss_len() {
        // MSS with len=6 (A3's parse_mss_option would also reject).
        let bytes = [OPT_MSS, 6, 0x05, 0xb4, 0x00, 0x00];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadKnownLen);
    }

    #[test]
    fn parse_rejects_wrong_wscale_len() {
        let bytes = [OPT_WSCALE, 4, 7, 0];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadKnownLen);
    }

    #[test]
    fn parse_rejects_wrong_ts_len() {
        let bytes = [OPT_TIMESTAMP, 8, 0,0,0,0, 0,0];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadKnownLen);
    }

    #[test]
    fn parse_rejects_truncated_mss() {
        // MSS header claims 4 bytes but only 3 present.
        let bytes = [OPT_MSS, 4, 0x05];
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::Truncated);
    }

    #[test]
    fn parse_rejects_sack_with_zero_blocks() {
        let bytes = [OPT_SACK, 2]; // header only, no blocks.
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadSackBlockCount);
    }

    #[test]
    fn parse_rejects_sack_with_odd_block_bytes() {
        // 2 + 7 = odd block region.
        let mut bytes = [0u8; 9];
        bytes[0] = OPT_SACK; bytes[1] = 9;
        let err = parse_options(&bytes).unwrap_err();
        assert_eq!(err, OptionParseError::BadSackBlockCount);
    }

    #[test]
    fn parse_skips_unknown_kind_with_valid_len() {
        // Kind 99, len 4, two bytes of payload — skipped; MSS follows.
        let bytes = [99u8, 4, 0xaa, 0xbb, OPT_MSS, LEN_MSS, 0x05, 0xb4];
        let opts = parse_options(&bytes).unwrap();
        assert_eq!(opts.mss, Some(1460));
    }
```

- [ ] **Step 3: Run the decoder tests**

Run: `cargo test -p dpdk-net-core tcp_options::tests::parse_`
Expected: all `parse_*` tests green.

- [ ] **Step 4: Run the full `tcp_options` test module**

Run: `cargo test -p dpdk-net-core tcp_options::tests`
Expected: PASS (encoder + decoder tests).

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_options.rs
git commit -m "a4: tcp_options.rs — decoder with defensive parse + round-trip tests"
```

---

## Task 5: Extend `TcpConn` with option-negotiated fields (declare + default; no wiring yet)

**Goal:** Add the fields spec §6.2 calls for: `ws_shift_out`, `ws_shift_in`, `ts_enabled`, `ts_recent`, `ts_recent_age`, `sack_enabled`. Defaults mean "not negotiated" (ws_shift_* = 0, ts_enabled = false, sack_enabled = false). Wiring the fields at handshake lands in Task 15; emitting them on TX lands in Task 12 and Task 13; PAWS lands in Task 16. This task is declaration + default-init only, so it stays small and the A3 tests that construct `TcpConn` don't break.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs`

- [ ] **Step 1: Write the failing test first**

Append to `crates/dpdk-net-core/src/tcp_conn.rs` inside `mod tests`:

```rust
    #[test]
    fn a4_options_fields_default_to_not_negotiated() {
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048);
        // No WS negotiated: no left shift on either direction.
        assert_eq!(c.ws_shift_out, 0);
        assert_eq!(c.ws_shift_in, 0);
        // TS disabled until SYN-ACK confirms it.
        assert!(!c.ts_enabled);
        assert_eq!(c.ts_recent, 0);
        assert_eq!(c.ts_recent_age, 0);
        // SACK disabled until SYN-ACK confirms it.
        assert!(!c.sack_enabled);
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core tcp_conn::tests::a4_options_fields_default_to_not_negotiated`
Expected: FAIL — "no field `ws_shift_out` on type `TcpConn`".

- [ ] **Step 3: Add the fields**

In `crates/dpdk-net-core/src/tcp_conn.rs`, modify the `TcpConn` struct to insert the A4 fields and update `new_client` to default-init them. Replace the existing `TcpConn` struct with:

```rust
pub struct TcpConn {
    four_tuple: FourTuple,
    pub state: TcpState,

    // Sequence space (RFC 9293 §3.3.1). All host byte order.
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub snd_wl1: u32,
    pub snd_wl2: u32,
    pub iss: u32,

    pub rcv_nxt: u32,
    pub rcv_wnd: u32,
    pub irs: u32,

    /// MSS negotiated on SYN-ACK (peer's advertised MSS option). Defaults
    /// to 536 if the peer omits the option (RFC 9293 §3.7.1 / RFC 6691).
    pub peer_mss: u16,

    // Phase A4: option-negotiated fields per spec §6.2.
    /// Our outbound window-scale shift (applied to `rcv_wnd` when writing
    /// the TCP header's window field). `0` = no scaling (RFC 7323
    /// pre-negotiation default). Negotiated on SYN-ACK: if the peer's
    /// SYN-ACK carries a Window Scale option, we set `ws_shift_out` to
    /// our advertised shift (typically 7 for 256 KiB recv buffer).
    pub ws_shift_out: u8,
    /// Peer's window-scale shift (applied when READING inbound windows
    /// into our `snd_wnd`). Negotiated on SYN-ACK; `0` otherwise.
    pub ws_shift_in: u8,
    /// True iff both sides sent the Timestamps option in the SYN/SYN-ACK
    /// exchange (RFC 7323 §2). When true, every non-SYN segment MUST
    /// carry Timestamps (RFC 7323 §3, MUST-22).
    pub ts_enabled: bool,
    /// Last in-sequence TSval we saw from the peer (RFC 7323 §3.2
    /// TS.Recent). Used as the TSecr we echo on outbound segments.
    pub ts_recent: u32,
    /// Our `now_ns()` reading when `ts_recent` was last updated. Used
    /// by RFC 7323 §5.5 "ts_recent expiration" — we invalidate ts_recent
    /// after 24 days of idle to prevent PAWS from rejecting legitimate
    /// long-idle-flow resumes. Stage 1 trading flows rarely idle that
    /// long; the check is cheap and future-proof.
    pub ts_recent_age: u64,
    /// True iff the SYN exchange negotiated SACK-permitted. When true,
    /// outbound ACKs carry SACK blocks for recv-side gaps, and inbound
    /// ACKs may carry SACK blocks the decoder feeds into
    /// `sack_scoreboard` for A5 retransmit consumption.
    pub sack_enabled: bool,

    pub snd: SendQueue,
    pub recv: RecvQueue,

    /// Snapshot of the sequence number *we* used for our FIN, so
    /// `ProcessACK` can detect "FIN has been ACKed" unambiguously.
    /// `None` when no FIN has been emitted yet.
    pub our_fin_seq: Option<u32>,

    /// `tcp_msl_ms`-derived deadline when this connection entered
    /// TIME_WAIT. `None` in all other states. Engine's tick reaps the
    /// connection once `clock::now_ns() >= time_wait_deadline_ns`.
    pub time_wait_deadline_ns: Option<u64>,
}
```

Then update `new_client` to default-init the new fields. In the `impl TcpConn` block, replace `new_client`'s constructor literal with:

```rust
        Self {
            four_tuple: tuple,
            state: TcpState::Closed,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            iss,
            rcv_nxt: 0,
            rcv_wnd,
            irs: 0,
            peer_mss: our_mss,
            // A4 options — default "not negotiated"; Task 15 sets them
            // from the SYN-ACK options.
            ws_shift_out: 0,
            ws_shift_in: 0,
            ts_enabled: false,
            ts_recent: 0,
            ts_recent_age: 0,
            sack_enabled: false,
            snd: SendQueue::new(send_buf_bytes),
            recv: RecvQueue::new(recv_buf_bytes),
            our_fin_seq: None,
            time_wait_deadline_ns: None,
        }
```

- [ ] **Step 4: Run — verify it passes**

Run: `cargo test -p dpdk-net-core tcp_conn::tests -- --nocapture`
Expected: PASS (new test + all existing A3 tests).

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_conn.rs
git commit -m "a4: TcpConn — add ws_shift_*, ts_enabled + ts_recent + ts_recent_age, sack_enabled"
```

---

## Task 6: Create `tcp_reassembly.rs` — `OooSegment` + `ReorderQueue::insert`

**Goal:** Introduce the out-of-order segment queue. A `ReorderQueue` holds `Vec<OooSegment { seq, payload: Vec<u8> }>` sorted by wrap-aware seq order (`tcp_seq::seq_lt`). Inserts find the right position, merge overlapping/adjacent segments (mTCP `CanMerge` / `MergeFragments` semantics), and cap total buffered bytes at a construction-time limit (threaded in from the `RecvQueue` cap). This task lands the struct + insert; Task 7 lands `drain_contiguous_from_rcv_nxt`.

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_reassembly.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Add module declaration to `lib.rs`**

Add `pub mod tcp_reassembly;` alphabetically in `crates/dpdk-net-core/src/lib.rs`.

- [ ] **Step 2: Write the failing tests first**

Create `crates/dpdk-net-core/src/tcp_reassembly.rs` with the struct + insert implementation:

```rust
//! Out-of-order segment reassembly. Spec §7.2 envisions mbuf-chain
//! zero-copy storage; we continue A3's AD-7 copy-based model by holding
//! `Vec<u8>` payloads per OOO segment. See AD-A4-reassembly in the plan
//! header.
//!
//! Insertion is O(N) where N is the number of OOO segments currently
//! buffered (bounded by `recv_buffer_bytes / peer_mss`, typically < 180
//! with a 256 KiB cap and 1460-byte MSS — acceptable under trading
//! workload where OOO is rare to begin with). Merge on insert uses
//! mTCP-style `CanMerge` / `MergeFragments` semantics applied to
//! copy-based `(seq, Vec<u8>)` entries.

use crate::tcp_seq::{seq_le, seq_lt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OooSegment {
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl OooSegment {
    pub fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(self.payload.len() as u32)
    }
}

/// Outcome of `ReorderQueue::insert`. The caller uses it to decide
/// whether to bump `tcp.rx_reassembly_queued` (true when new bytes
/// were actually buffered) and how many bytes were dropped due to
/// the cap (feeds `tcp.recv_buf_drops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsertOutcome {
    /// Bytes of new (not-already-buffered) payload actually stored.
    pub newly_buffered: u32,
    /// Bytes dropped because inserting them would push
    /// `total_bytes()` past `cap`.
    pub cap_dropped: u32,
}

pub struct ReorderQueue {
    segments: Vec<OooSegment>,
    cap: u32,
    total_bytes: u32,
}

impl ReorderQueue {
    pub fn new(cap: u32) -> Self {
        Self { segments: Vec::new(), cap, total_bytes: 0 }
    }

    pub fn is_empty(&self) -> bool { self.segments.is_empty() }
    pub fn len(&self) -> usize { self.segments.len() }
    pub fn total_bytes(&self) -> u32 { self.total_bytes }
    pub fn segments(&self) -> &[OooSegment] { &self.segments }

    /// Insert a new OOO segment. Merges with neighbours where ranges
    /// overlap or touch; drops payload past `cap`. Returns an outcome
    /// summary that the caller feeds into counters.
    pub fn insert(&mut self, seq: u32, payload: &[u8]) -> InsertOutcome {
        if payload.is_empty() {
            return InsertOutcome { newly_buffered: 0, cap_dropped: 0 };
        }
        let incoming_end = seq.wrapping_add(payload.len() as u32);

        // Carve the incoming payload into gap-slices that don't overlap
        // any existing segment. Each gap-slice is then inserted and
        // merged with its neighbours.
        let mut cursor = seq;
        let mut newly_buffered = 0u32;
        let mut cap_dropped = 0u32;
        let mut to_insert: Vec<(u32, Vec<u8>)> = Vec::new();

        for existing in &self.segments {
            if seq_le(incoming_end, existing.seq) { break; }
            if seq_le(existing.end_seq(), cursor) { continue; }
            if seq_lt(cursor, existing.seq) {
                let gap_len = existing.seq.wrapping_sub(cursor) as usize;
                let off = cursor.wrapping_sub(seq) as usize;
                let take_end = off + gap_len.min(payload.len() - off);
                let remaining_cap = self.cap.saturating_sub(self.total_bytes + newly_buffered);
                let take = (take_end - off).min(remaining_cap as usize);
                if take > 0 {
                    to_insert.push((cursor, payload[off..off+take].to_vec()));
                    newly_buffered += take as u32;
                }
                if take < take_end - off {
                    cap_dropped += (take_end - off - take) as u32;
                }
                cursor = cursor.wrapping_add((take_end - off) as u32);
            }
            if seq_lt(cursor, existing.end_seq()) {
                cursor = existing.end_seq();
            }
        }

        if seq_lt(cursor, incoming_end) {
            let off = cursor.wrapping_sub(seq) as usize;
            let tail_len = payload.len() - off;
            let remaining_cap = self.cap.saturating_sub(self.total_bytes + newly_buffered);
            let take = tail_len.min(remaining_cap as usize);
            if take > 0 {
                to_insert.push((cursor, payload[off..off+take].to_vec()));
                newly_buffered += take as u32;
            }
            if take < tail_len {
                cap_dropped += (tail_len - take) as u32;
            }
        }

        for (s, p) in to_insert {
            self.insert_merged(s, p);
        }

        self.total_bytes += newly_buffered;
        InsertOutcome { newly_buffered, cap_dropped }
    }

    /// Insert `(seq, payload)` which is guaranteed not to overlap any
    /// existing segment. Merges on touch (adjacent ranges coalesce).
    fn insert_merged(&mut self, seq: u32, payload: Vec<u8>) {
        let end = seq.wrapping_add(payload.len() as u32);

        let mut idx = self.segments.len();
        for (i, s) in self.segments.iter().enumerate() {
            if seq_lt(seq, s.seq) { idx = i; break; }
        }

        let mut merged_left = false;
        if idx > 0 && self.segments[idx - 1].end_seq() == seq {
            self.segments[idx - 1].payload.extend_from_slice(&payload);
            merged_left = true;
        }

        if idx < self.segments.len() && self.segments[idx].seq == end {
            if merged_left {
                let right = self.segments.remove(idx);
                self.segments[idx - 1].payload.extend_from_slice(&right.payload);
            } else {
                let mut new_payload = payload;
                new_payload.extend_from_slice(&self.segments[idx].payload);
                self.segments[idx].seq = seq;
                self.segments[idx].payload = new_payload;
            }
        } else if !merged_left {
            self.segments.insert(idx, OooSegment { seq, payload });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queue_is_empty() {
        let q = ReorderQueue::new(1024);
        assert!(q.is_empty());
        assert_eq!(q.total_bytes(), 0);
    }

    #[test]
    fn single_insert_buffers_payload() {
        let mut q = ReorderQueue::new(1024);
        let out = q.insert(100, b"abcde");
        assert_eq!(out.newly_buffered, 5);
        assert_eq!(out.cap_dropped, 0);
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(&q.segments()[0].payload, b"abcde");
    }

    #[test]
    fn two_disjoint_inserts_stay_separate() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"aaa");
        q.insert(200, b"bbb");
        assert_eq!(q.len(), 2);
        assert_eq!(q.total_bytes(), 6);
    }

    #[test]
    fn inserts_sort_by_seq_even_if_arrival_order_reverses() {
        let mut q = ReorderQueue::new(1024);
        q.insert(200, b"bbb");
        q.insert(100, b"aaa");
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(q.segments()[1].seq, 200);
    }

    #[test]
    fn adjacent_inserts_merge_into_one() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abc");
        q.insert(103, b"def");
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(&q.segments()[0].payload, b"abcdef");
    }

    #[test]
    fn adjacent_insert_collapses_both_sides() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"aaa");
        q.insert(106, b"ccc");
        q.insert(103, b"bbb");
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq, 100);
        assert_eq!(&q.segments()[0].payload, b"aaabbbccc");
    }

    #[test]
    fn overlap_with_existing_is_deduplicated() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abcdef");
        // Existing range: [100..106). Retransmit: [103..107).
        // Overlap: [103..106). New: [106..107) — one byte.
        let out = q.insert(103, b"defg");
        assert_eq!(out.newly_buffered, 1);
        assert_eq!(out.cap_dropped, 0);
        assert_eq!(q.len(), 1);
        assert_eq!(&q.segments()[0].payload, b"abcdefg");
    }

    #[test]
    fn cap_truncates_excess_and_reports_drop() {
        let mut q = ReorderQueue::new(4);
        let out = q.insert(100, b"abcdef");
        assert_eq!(out.newly_buffered, 4);
        assert_eq!(out.cap_dropped, 2);
        assert_eq!(&q.segments()[0].payload, b"abcd");
    }

    #[test]
    fn empty_payload_insert_is_noop() {
        let mut q = ReorderQueue::new(1024);
        let out = q.insert(100, b"");
        assert_eq!(out.newly_buffered, 0);
        assert!(q.is_empty());
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p dpdk-net-core tcp_reassembly::tests`
Expected: all 9 tests green.

- [ ] **Step 4: Clippy clean**

Run: `cargo clippy -p dpdk-net-core --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/lib.rs crates/dpdk-net-core/src/tcp_reassembly.rs
git commit -m "a4: tcp_reassembly.rs — ReorderQueue insert + merge + cap"
```

---

## Task 7: `tcp_reassembly.rs` — `drain_contiguous_from` for gap-close

**Goal:** When an in-order segment at `rcv_nxt` arrives and extends `rcv_nxt` forward, drain any OOO segments whose seq range now sits at or before `rcv_nxt`. Returns their concatenated bytes and the number of segments drained (caller bumps `tcp.rx_reassembly_hole_filled` once per segment, matching mTCP's "one fragment-ctx removed per drain" event count).

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_reassembly.rs`

- [ ] **Step 1: Add the drain method**

Append to the `impl ReorderQueue` block:

```rust
    /// Pop the contiguous prefix of segments whose seq range starts at
    /// or before `rcv_nxt`. For each popped segment, yield the portion
    /// of its payload that lies at or after `rcv_nxt`. Returns the
    /// concatenated bytes and the number of segments drained.
    pub fn drain_contiguous_from(&mut self, mut rcv_nxt: u32) -> (Vec<u8>, u32) {
        let mut out = Vec::new();
        let mut drained_segments = 0u32;

        while !self.segments.is_empty() {
            let seg = &self.segments[0];
            if seq_lt(rcv_nxt, seg.seq) { break; }
            let seg_end = seg.end_seq();
            if seq_le(seg_end, rcv_nxt) {
                // Entire segment behind rcv_nxt — drop.
                self.total_bytes = self.total_bytes.saturating_sub(seg.payload.len() as u32);
                self.segments.remove(0);
                drained_segments += 1;
                continue;
            }
            let skip = rcv_nxt.wrapping_sub(seg.seq) as usize;
            out.extend_from_slice(&seg.payload[skip..]);
            rcv_nxt = seg_end;
            self.total_bytes = self.total_bytes.saturating_sub(seg.payload.len() as u32);
            self.segments.remove(0);
            drained_segments += 1;
        }
        (out, drained_segments)
    }
```

- [ ] **Step 2: Append drain tests**

Append to the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn drain_with_no_contiguous_front_returns_empty() {
        let mut q = ReorderQueue::new(1024);
        q.insert(200, b"zzz");
        let (bytes, n) = q.drain_contiguous_from(100);
        assert!(bytes.is_empty());
        assert_eq!(n, 0);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn drain_single_adjacent_segment() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abc");
        let (bytes, n) = q.drain_contiguous_from(100);
        assert_eq!(&bytes, b"abc");
        assert_eq!(n, 1);
        assert!(q.is_empty());
        assert_eq!(q.total_bytes(), 0);
    }

    #[test]
    fn drain_chains_through_touching_segments() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"aaa");
        q.insert(103, b"bbb");
        q.insert(200, b"zzz");
        let (bytes, n) = q.drain_contiguous_from(100);
        assert_eq!(&bytes, b"aaabbb");
        assert_eq!(n, 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.segments()[0].seq, 200);
    }

    #[test]
    fn drain_with_rcv_nxt_inside_segment_skips_prefix() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abcdef");
        let (bytes, n) = q.drain_contiguous_from(103);
        assert_eq!(&bytes, b"def");
        assert_eq!(n, 1);
    }

    #[test]
    fn drain_past_end_of_segment_drops_entirely() {
        let mut q = ReorderQueue::new(1024);
        q.insert(100, b"abc");
        let (bytes, n) = q.drain_contiguous_from(200);
        assert!(bytes.is_empty());
        assert_eq!(n, 1);
        assert!(q.is_empty());
    }

    #[test]
    fn drain_empty_queue_is_noop() {
        let mut q = ReorderQueue::new(1024);
        let (bytes, n) = q.drain_contiguous_from(500);
        assert!(bytes.is_empty());
        assert_eq!(n, 0);
    }
```

- [ ] **Step 3: Run all reassembly tests**

Run: `cargo test -p dpdk-net-core tcp_reassembly::tests`
Expected: 15 tests PASS (9 insert + 6 drain).

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_reassembly.rs
git commit -m "a4: tcp_reassembly.rs — drain_contiguous_from for gap-close"
```

---

## Task 8: Extend `RecvQueue` with the reorder queue

**Goal:** Hang the `ReorderQueue` off `RecvQueue`, keep in-order `bytes` alongside, and expose both `free_space` (in-order half only, matches A3) and `free_space_total` (combined — feeds the seq-window check in Task 17).

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/src/tcp_conn.rs` inside `mod tests`:

```rust
    #[test]
    fn recv_queue_has_reorder_field_and_shares_cap() {
        let rq = RecvQueue::new(1024);
        assert_eq!(rq.cap, 1024);
        assert!(rq.reorder.is_empty());
        assert_eq!(rq.reorder.total_bytes(), 0);
        assert_eq!(rq.free_space_total(), 1024);
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core tcp_conn::tests::recv_queue_has_reorder_field_and_shares_cap`
Expected: FAIL — "no field `reorder` on type `RecvQueue`".

- [ ] **Step 3: Extend `RecvQueue`**

In `crates/dpdk-net-core/src/tcp_conn.rs`, replace the `RecvQueue` struct + `impl` block with:

```rust
pub struct RecvQueue {
    pub bytes: std::collections::VecDeque<u8>,
    pub cap: u32,
    /// A4: out-of-order segments buffered past the in-order point.
    /// Shares `cap` with `bytes`; `free_space_total` reports combined room.
    pub reorder: crate::tcp_reassembly::ReorderQueue,
    /// Scratch buffer for the borrow-view exposed to
    /// `DPDK_NET_EVT_READABLE.data`. Cleared at the start of each
    /// `dpdk_net_poll` on the owning engine (not here).
    pub last_read_buf: Vec<u8>,
}

impl RecvQueue {
    pub fn new(cap: u32) -> Self {
        Self {
            bytes: std::collections::VecDeque::with_capacity(cap as usize),
            cap,
            reorder: crate::tcp_reassembly::ReorderQueue::new(cap),
            last_read_buf: Vec::new(),
        }
    }

    /// In-order free-space only (matches A3's semantic).
    pub fn free_space(&self) -> u32 {
        self.cap.saturating_sub(self.bytes.len() as u32)
    }

    /// Combined free-space across in-order bytes + reorder queue.
    pub fn free_space_total(&self) -> u32 {
        self.cap
            .saturating_sub(self.bytes.len() as u32)
            .saturating_sub(self.reorder.total_bytes())
    }

    /// Append `payload` to the in-order queue, up to in-order free-space.
    /// Returns the number of bytes accepted (may be < payload.len() if
    /// the in-order half would overflow).
    pub fn append(&mut self, payload: &[u8]) -> u32 {
        let take = payload.len().min(self.free_space() as usize);
        self.bytes.extend(&payload[..take]);
        take as u32
    }
}
```

- [ ] **Step 4: Run**

Run: `cargo test -p dpdk-net-core tcp_conn::tests`
Expected: PASS (new test + all A3 tests).

Run: `cargo test -p dpdk-net-core tcp_input::tests`
Expected: PASS — A3 tests in `tcp_input` use `recv.append` which is unchanged.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_conn.rs
git commit -m "a4: RecvQueue — co-locate ReorderQueue, expose free_space_total"
```

---

## Task 9: Create `tcp_sack.rs` — `SackScoreboard`

**Goal:** Received-side SACK scoreboard. Decoded peer SACK blocks insert + merge here; A5's RACK-TLP retransmit will consume `is_sacked(seq)`. Fixed 4-block capacity (RFC 2018 §3 per-ACK cap with Timestamps present). Merge semantics mirror mTCP's `_update_sack_table`.

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_sack.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Add module declaration**

Add `pub mod tcp_sack;` alphabetically in `crates/dpdk-net-core/src/lib.rs`.

- [ ] **Step 2: Write the tests first**

Create `crates/dpdk-net-core/src/tcp_sack.rs`:

```rust
//! Received-side SACK scoreboard (RFC 2018). Populated by tcp_input
//! from inbound-ACK SACK blocks; consumed by A5 RACK-TLP retransmit
//! (A4 only queries via `is_sacked` in integration tests).
//!
//! Storage: fixed 4-entry array + count. Merge on insert when ranges
//! touch or overlap; drop oldest on overflow. See AD-A4-sack-scoreboard-size.

use crate::tcp_options::SackBlock;
use crate::tcp_seq::{seq_le, seq_lt};

pub const MAX_SACK_SCOREBOARD_ENTRIES: usize = 4;

#[derive(Default)]
pub struct SackScoreboard {
    blocks: [SackBlock; MAX_SACK_SCOREBOARD_ENTRIES],
    count: u8,
}

impl SackScoreboard {
    pub fn new() -> Self { Self::default() }
    pub fn is_empty(&self) -> bool { self.count == 0 }
    pub fn len(&self) -> usize { self.count as usize }
    pub fn blocks(&self) -> &[SackBlock] { &self.blocks[..self.count as usize] }

    pub fn is_sacked(&self, seq: u32) -> bool {
        for b in self.blocks() {
            if seq_le(b.left, seq) && seq_lt(seq, b.right) { return true; }
        }
        false
    }

    pub fn insert(&mut self, block: SackBlock) -> bool {
        // Merge-with-existing pass.
        let mut merged_into: Option<usize> = None;
        for i in 0..(self.count as usize) {
            let cur = self.blocks[i];
            if seq_le(block.left, cur.right) && seq_le(cur.left, block.right) {
                let new_left = if seq_le(cur.left, block.left) { cur.left } else { block.left };
                let new_right = if seq_le(block.right, cur.right) { cur.right } else { block.right };
                self.blocks[i] = SackBlock { left: new_left, right: new_right };
                merged_into = Some(i);
                break;
            }
        }
        if merged_into.is_some() {
            self.collapse();
            return true;
        }
        if (self.count as usize) < MAX_SACK_SCOREBOARD_ENTRIES {
            self.blocks[self.count as usize] = block;
            self.count += 1;
        } else {
            for i in 1..MAX_SACK_SCOREBOARD_ENTRIES {
                self.blocks[i - 1] = self.blocks[i];
            }
            self.blocks[MAX_SACK_SCOREBOARD_ENTRIES - 1] = block;
        }
        true
    }

    pub fn prune_below(&mut self, snd_una: u32) {
        let mut w = 0usize;
        for i in 0..(self.count as usize) {
            let b = self.blocks[i];
            if seq_le(b.right, snd_una) { continue; }
            let pruned = SackBlock {
                left: if seq_le(b.left, snd_una) { snd_una } else { b.left },
                right: b.right,
            };
            self.blocks[w] = pruned;
            w += 1;
        }
        self.count = w as u8;
    }

    fn collapse(&mut self) {
        loop {
            let mut pair: Option<(usize, usize)> = None;
            'outer: for i in 0..(self.count as usize) {
                for j in (i + 1)..(self.count as usize) {
                    let a = self.blocks[i];
                    let b = self.blocks[j];
                    if seq_le(a.left, b.right) && seq_le(b.left, a.right) {
                        pair = Some((i, j));
                        break 'outer;
                    }
                }
            }
            let Some((i, j)) = pair else { break };
            let a = self.blocks[i];
            let b = self.blocks[j];
            let new_left = if seq_le(a.left, b.left) { a.left } else { b.left };
            let new_right = if seq_le(b.right, a.right) { a.right } else { b.right };
            self.blocks[i] = SackBlock { left: new_left, right: new_right };
            for k in (j + 1)..(self.count as usize) {
                self.blocks[k - 1] = self.blocks[k];
            }
            self.count -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scoreboard_claims_nothing_sacked() {
        let sb = SackScoreboard::new();
        assert!(!sb.is_sacked(100));
        assert_eq!(sb.len(), 0);
    }

    #[test]
    fn single_insert_reports_block() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock { left: 100, right: 200 });
        assert_eq!(sb.len(), 1);
        assert!(sb.is_sacked(100));
        assert!(sb.is_sacked(150));
        assert!(!sb.is_sacked(200));
        assert!(!sb.is_sacked(99));
    }

    #[test]
    fn touching_inserts_merge() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock { left: 100, right: 200 });
        sb.insert(SackBlock { left: 200, right: 300 });
        assert_eq!(sb.len(), 1);
        assert_eq!(sb.blocks()[0], SackBlock { left: 100, right: 300 });
    }

    #[test]
    fn overlapping_inserts_merge() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock { left: 100, right: 200 });
        sb.insert(SackBlock { left: 150, right: 250 });
        assert_eq!(sb.len(), 1);
        assert_eq!(sb.blocks()[0], SackBlock { left: 100, right: 250 });
    }

    #[test]
    fn disjoint_inserts_stay_separate() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock { left: 100, right: 200 });
        sb.insert(SackBlock { left: 300, right: 400 });
        assert_eq!(sb.len(), 2);
    }

    #[test]
    fn insert_filling_gap_collapses_three_to_one() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock { left: 100, right: 200 });
        sb.insert(SackBlock { left: 300, right: 400 });
        sb.insert(SackBlock { left: 200, right: 300 });
        assert_eq!(sb.len(), 1);
        assert_eq!(sb.blocks()[0], SackBlock { left: 100, right: 400 });
    }

    #[test]
    fn overflow_evicts_oldest() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock { left: 100, right: 150 });
        sb.insert(SackBlock { left: 200, right: 250 });
        sb.insert(SackBlock { left: 300, right: 350 });
        sb.insert(SackBlock { left: 400, right: 450 });
        assert_eq!(sb.len(), 4);
        sb.insert(SackBlock { left: 500, right: 550 });
        assert_eq!(sb.len(), 4);
        assert!(!sb.is_sacked(100));
        assert!(sb.is_sacked(500));
    }

    #[test]
    fn prune_below_drops_fully_covered_blocks() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock { left: 100, right: 200 });
        sb.insert(SackBlock { left: 300, right: 400 });
        sb.prune_below(250);
        assert_eq!(sb.len(), 1);
        assert_eq!(sb.blocks()[0], SackBlock { left: 300, right: 400 });
    }

    #[test]
    fn prune_below_trims_left_edge_of_partially_covered_block() {
        let mut sb = SackScoreboard::new();
        sb.insert(SackBlock { left: 100, right: 300 });
        sb.prune_below(200);
        assert_eq!(sb.len(), 1);
        assert_eq!(sb.blocks()[0], SackBlock { left: 200, right: 300 });
    }
}
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p dpdk-net-core tcp_sack::tests`
Expected: 9 tests PASS.

- [ ] **Step 4: Clippy clean**

Run: `cargo clippy -p dpdk-net-core --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/lib.rs crates/dpdk-net-core/src/tcp_sack.rs
git commit -m "a4: tcp_sack.rs — SackScoreboard insert + merge + is_sacked + prune"
```

---

## Task 10: Extend `TcpConn` with `sack_scoreboard` field

**Goal:** Hang the scoreboard off `TcpConn`. Task 18 wires inbound-ACK SACK-decode → scoreboard; Tasks 19+ use `prune_below(snd_una)` on snd_una advance.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/src/tcp_conn.rs` inside `mod tests`:

```rust
    #[test]
    fn a4_sack_scoreboard_starts_empty() {
        let c = TcpConn::new_client(tuple(), 1000, 1460, 1024, 2048);
        assert!(c.sack_scoreboard.is_empty());
        assert_eq!(c.sack_scoreboard.len(), 0);
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core tcp_conn::tests::a4_sack_scoreboard_starts_empty`
Expected: FAIL — "no field `sack_scoreboard` on type `TcpConn`".

- [ ] **Step 3: Add the field**

In `crates/dpdk-net-core/src/tcp_conn.rs`, add to the `TcpConn` struct (after the option fields added in Task 5):

```rust
    /// A4: received-SACK scoreboard. Populated by `tcp_input` from
    /// inbound-ACK SACK blocks; pruned on snd_una advance. A5 consumes
    /// via `is_sacked(seq)` in RACK-TLP retransmit decisions.
    pub sack_scoreboard: crate::tcp_sack::SackScoreboard,
```

In `new_client`, append to the struct literal (before `snd: SendQueue::new(...)`):

```rust
            sack_scoreboard: crate::tcp_sack::SackScoreboard::new(),
```

- [ ] **Step 4: Run**

Run: `cargo test -p dpdk-net-core tcp_conn::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_conn.rs
git commit -m "a4: TcpConn — add sack_scoreboard (populated by Task 18)"
```

---

## Task 11: Rework `SegmentTx.options` to carry `TcpOpts`; migrate call sites

**Goal:** Replace the narrow `SegmentTx.mss_option: Option<u16>` with an owned `options: TcpOpts` so callers declaratively attach any combination of MSS/WS/TS/SACK-permitted/SACK-blocks. `build_segment` delegates option encoding to `TcpOpts::encode`. A3's call sites in `engine.rs` and the `tcp_input.rs` test helper migrate to `TcpOpts { mss: Some(...), ..Default::default() }`.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_output.rs`
- Modify: `crates/dpdk-net-core/src/engine.rs` (call sites only)
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` (test helper only)

- [ ] **Step 1: Update `SegmentTx` + `build_segment`**

In `crates/dpdk-net-core/src/tcp_output.rs`, replace the top of the file (module doc + `SegmentTx` + `build_segment`) with:

```rust
//! TCP segment builders. Every builder emits a complete Ethernet + IPv4 +
//! TCP frame with optional TCP options (MSS / WS / SACK-permitted / TS /
//! SACK blocks). IPv4 header checksum is computed in software; TCP
//! checksum uses the pseudo-header form per RFC 9293 §3.1.
//!
//! Option encoding is delegated to `tcp_options::TcpOpts::encode` (canonical
//! order + NOP-word-alignment).

use crate::l2::{ETHERTYPE_IPV4, ETH_HDR_LEN};
use crate::l3_ip::{internet_checksum, IPPROTO_TCP};
use crate::tcp_options::TcpOpts;

pub const TCP_HDR_MIN: usize = 20;
pub const IPV4_HDR_MIN: usize = 20;
pub const FRAME_HDRS_MIN: usize = ETH_HDR_LEN + IPV4_HDR_MIN + TCP_HDR_MIN;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub struct SegmentTx<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// Any combination of options; use `TcpOpts::default()` for none.
    pub options: TcpOpts,
    pub payload: &'a [u8],
}

pub fn build_segment(seg: &SegmentTx, out: &mut [u8]) -> Option<usize> {
    let opts_len = seg.options.encoded_len();
    let tcp_hdr_len = TCP_HDR_MIN + opts_len;
    let total = ETH_HDR_LEN + IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len();
    if out.len() < total { return None; }

    // Ethernet
    out[0..6].copy_from_slice(&seg.dst_mac);
    out[6..12].copy_from_slice(&seg.src_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4
    let ip_start = ETH_HDR_LEN;
    let ip = &mut out[ip_start..ip_start + IPV4_HDR_MIN];
    let total_ip_len = (IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len()) as u16;
    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0x0000u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    ip[10..12].copy_from_slice(&0x0000u16.to_be_bytes());
    ip[12..16].copy_from_slice(&seg.src_ip.to_be_bytes());
    ip[16..20].copy_from_slice(&seg.dst_ip.to_be_bytes());
    let ip_csum = internet_checksum(&out[ip_start..ip_start + IPV4_HDR_MIN]);
    out[ip_start + 10] = (ip_csum >> 8) as u8;
    out[ip_start + 11] = (ip_csum & 0xff) as u8;

    // TCP header + options + payload
    let tcp_start = ip_start + IPV4_HDR_MIN;
    let th = &mut out[tcp_start..tcp_start + tcp_hdr_len];
    th[0..2].copy_from_slice(&seg.src_port.to_be_bytes());
    th[2..4].copy_from_slice(&seg.dst_port.to_be_bytes());
    th[4..8].copy_from_slice(&seg.seq.to_be_bytes());
    th[8..12].copy_from_slice(&seg.ack.to_be_bytes());
    th[12] = ((tcp_hdr_len / 4) as u8) << 4;
    th[13] = seg.flags;
    th[14..16].copy_from_slice(&seg.window.to_be_bytes());
    th[16..18].copy_from_slice(&0u16.to_be_bytes());
    th[18..20].copy_from_slice(&0u16.to_be_bytes());
    if opts_len > 0 {
        seg.options
            .encode(&mut th[TCP_HDR_MIN..TCP_HDR_MIN + opts_len])
            .expect("pre-sized exactly; encode must fit");
    }

    let payload_start = tcp_start + tcp_hdr_len;
    out[payload_start..payload_start + seg.payload.len()].copy_from_slice(seg.payload);

    let tcp_seg_len = (tcp_hdr_len + seg.payload.len()) as u32;
    let csum = tcp_checksum(
        seg.src_ip, seg.dst_ip, tcp_seg_len,
        &out[tcp_start..payload_start + seg.payload.len()],
    );
    out[tcp_start + 16] = (csum >> 8) as u8;
    out[tcp_start + 17] = (csum & 0xff) as u8;

    Some(total)
}
```

Keep `tcp_checksum` and the tests below intact; update only the references to `mss_option` in the tests (Step 3 below).

- [ ] **Step 2: Update `tcp_output::tests::base` + mutations**

In the `#[cfg(test)] mod tests` at the bottom of `tcp_output.rs`, replace `base()` with:

```rust
    fn base() -> SegmentTx<'static> {
        SegmentTx {
            src_mac: [0x02, 0, 0, 0, 0, 1],
            dst_mac: [0x02, 0, 0, 0, 0, 2],
            src_ip: 0x0a_00_00_02,
            dst_ip: 0x0a_00_00_01,
            src_port: 40000,
            dst_port: 5000,
            seq: 0x1000,
            ack: 0,
            flags: TCP_SYN,
            window: 65535,
            options: crate::tcp_options::TcpOpts {
                mss: Some(1460), ..Default::default()
            },
            payload: &[],
        }
    }
```

In `data_segment_with_payload_has_correct_tcp_csum`:

```rust
        seg.options = crate::tcp_options::TcpOpts::default();
```

(replaces the old `seg.mss_option = None;`).

In `rst_frame_has_rst_flag_and_no_options`:

```rust
        seg.options = crate::tcp_options::TcpOpts::default();
```

- [ ] **Step 3: Migrate `engine.rs` call sites**

In `crates/dpdk-net-core/src/engine.rs`, search and replace all `mss_option: Some(<expr>),` with `options: crate::tcp_options::TcpOpts { mss: Some(<expr>), ..Default::default() },` and all `mss_option: None,` with `options: crate::tcp_options::TcpOpts::default(),`. Verify every `SegmentTx { ... }` literal compiles.

- [ ] **Step 4: Migrate the `tcp_input.rs` test helper**

In `crates/dpdk-net-core/src/tcp_input.rs` `#[cfg(test)] mod tests`, replace `build_test_segment`:

```rust
    fn build_test_segment(flags: u8, mss: Option<u16>, payload: &[u8]) -> Vec<u8> {
        let seg = SegmentTx {
            src_mac: [0x02, 0, 0, 0, 0, 1],
            dst_mac: [0x02, 0, 0, 0, 0, 2],
            src_ip: 0x0a_00_00_01,
            dst_ip: 0x0a_00_00_02,
            src_port: 5000,
            dst_port: 40000,
            seq: 100,
            ack: 200,
            flags,
            window: 65535,
            options: crate::tcp_options::TcpOpts {
                mss, ..Default::default()
            },
            payload,
        };
        let mut out = vec![0u8; 256];
        let n = build_segment(&seg, &mut out).unwrap();
        out.truncate(n);
        out
    }
```

- [ ] **Step 5: Build + run all tests**

Run: `cargo test -p dpdk-net-core --lib`
Expected: PASS — every A3 test still green; tcp_output `syn_frame_has_mss_option_and_valid_sizes` still reports total=58 (4-byte MSS option, 0 pad).

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_output.rs crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/tcp_input.rs
git commit -m "a4: SegmentTx.options = TcpOpts bundle; migrate all A3 call sites"
```

---

## Task 12: `Engine::connect` emits full SYN options (MSS + WS + SACK-permitted + TS)

**Goal:** Upgrade the SYN emission path from MSS-only to the full Stage-1 option set. Our advertised WS shift is computed from `recv_buffer_bytes` — for the 256 KiB default, WS=2 suffices (65535 << 2 = 262140 ≥ 256 KiB); we use `compute_ws_shift_for(recv_buffer_bytes)` that floor-log2's up to the RFC 7323 §2.3 cap of 14. TS initial TSval is `engine.clock.now_ns() / 1000` (microsecond ticks — monotonic, wraps after 24.8 days, per RFC 7323 §4.1 guidance). TSecr on SYN is 0 (no received TSval yet). SACK-permitted is always emitted; negotiated by the peer echoing it in SYN-ACK (Task 15).

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` (the SYN-build call site in `connect`)

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/src/engine.rs` `mod tests`:

```rust
    #[test]
    fn connect_syn_carries_mss_ws_sack_perm_ts() {
        use crate::tcp_options::parse_options;
        let mut eng = test_engine();
        let _conn = eng.connect(default_connect_opts()).unwrap();
        let tx_frames = eng.drain_pending_tx();
        assert_eq!(tx_frames.len(), 1, "exactly one SYN expected");
        let frame = &tx_frames[0];
        let tcp_start = 14 + 20;
        let doff_words = (frame[tcp_start + 12] >> 4) as usize;
        let tcp_hdr_len = doff_words * 4;
        let opts = &frame[tcp_start + 20 .. tcp_start + tcp_hdr_len];
        let parsed = parse_options(opts).unwrap();
        assert_eq!(parsed.mss, Some(default_our_mss()));
        assert!(parsed.sack_permitted);
        assert!(parsed.wscale.is_some());
        assert!(parsed.timestamps.is_some());
        let (tsval, tsecr) = parsed.timestamps.unwrap();
        assert!(tsval > 0);
        assert_eq!(tsecr, 0);
    }
```

If the helpers `test_engine`, `default_connect_opts`, `default_our_mss`, `drain_pending_tx` aren't already in A3's test-module, add minimal versions (drain the engine's pending TX buffer into a `Vec<Vec<u8>>`).

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core engine::tests::connect_syn_carries_mss_ws_sack_perm_ts`
Expected: FAIL — SYN options still MSS-only.

- [ ] **Step 3: Wire the full SYN options in `connect`**

Near the top of `crates/dpdk-net-core/src/engine.rs`, add:

```rust
/// RFC 7323 §2.3: WS shift chosen so (u16::MAX << ws) >= recv_buffer_bytes,
/// bounded at 14 (RFC 7323's cap).
fn compute_ws_shift_for(recv_buffer_bytes: u32) -> u8 {
    let mut ws = 0u8;
    let mut cap = u16::MAX as u32;
    while cap < recv_buffer_bytes && ws < 14 {
        cap = (cap << 1) | 1;
        ws += 1;
    }
    ws
}
```

In the SYN build path inside `connect`, replace the `SegmentTx { ..., options: TcpOpts { mss: Some(our_mss), ..Default::default() }, ... }` block with:

```rust
        let ws_out = compute_ws_shift_for(self.config.recv_buffer_bytes);
        let tsval_initial = (self.clock.now_ns() / 1000) as u32;

        let syn_opts = crate::tcp_options::TcpOpts {
            mss: Some(our_mss),
            wscale: Some(ws_out),
            sack_permitted: true,
            timestamps: Some((tsval_initial, 0)),
            ..Default::default()
        };

        // ... compute src_mac/dst_mac/seq/etc. as before ...

        let seg = SegmentTx {
            src_mac: self.config.src_mac,
            dst_mac: self.config.gateway_mac,
            src_ip: self.config.local_ip,
            dst_ip,
            src_port: local_port,
            dst_port: peer_port,
            seq: iss,
            ack: 0,
            flags: TCP_SYN,
            window: u16::MAX, // pre-WS-negotiation: advertise maximum
            options: syn_opts,
            payload: &[],
        };

        // Record our advertised WS so handle_syn_sent can confirm it.
        conn.ws_shift_out = ws_out;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p dpdk-net-core engine::tests::connect_syn_carries_mss_ws_sack_perm_ts`
Expected: PASS.

Run: `cargo test -p dpdk-net-core engine::tests`
Expected: all A3 engine tests still pass — assertions target flag bits, not option bytes.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "a4: engine::connect emits full SYN options (MSS + WS + SACK-perm + TS)"
```

---

## Task 13: `emit_ack` carries TS option + WS-scaled window on non-SYN segments

**Goal:** When `ts_enabled`, every outbound non-SYN segment includes a Timestamps option with `TSval = now_us` and `TSecr = ts_recent`. When `ws_shift_out > 0`, the window field is `(recv.free_space() >> ws_shift_out).min(u16::MAX)`. When we end up advertising 0 (recv buffer full), bump `tcp.tx_zero_window` (slow-path backfill counter).

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` (`emit_ack` helper)

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/src/engine.rs` `mod tests`:

```rust
    #[test]
    fn post_handshake_ack_carries_ts_and_ws_scaled_window() {
        use crate::tcp_options::parse_options;
        let mut eng = test_engine();
        let conn_h = establish_conn_in_tests(&mut eng);
        {
            let c = eng.conn_mut(conn_h);
            c.ts_enabled = true;
            c.ts_recent = 0x11223344;
            c.ws_shift_out = 7;
        }
        eng.emit_ack_for_test(conn_h);
        let frame = eng.drain_pending_tx().pop().expect("one ACK");
        let tcp_start = 14 + 20;
        let window_raw = u16::from_be_bytes([frame[tcp_start + 14], frame[tcp_start + 15]]);
        let expected = {
            let c = eng.conn(conn_h);
            ((c.recv.free_space() >> 7) as u32).min(u16::MAX as u32) as u16
        };
        assert_eq!(window_raw, expected);
        let doff = (frame[tcp_start + 12] >> 4) as usize;
        let opts = &frame[tcp_start + 20 .. tcp_start + doff * 4];
        let parsed = parse_options(opts).unwrap();
        let (_tsval, tsecr) = parsed.timestamps.expect("TS option");
        assert_eq!(tsecr, 0x11223344);
    }
```

(Add `Engine::emit_ack_for_test`, `conn`, `conn_mut`, `establish_conn_in_tests` as `#[cfg(test)]` helpers on `Engine` — thin wrappers that invoke the private ACK-build path with a synthetic established conn.)

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core engine::tests::post_handshake_ack_carries_ts_and_ws_scaled_window`
Expected: FAIL — no TS option emitted.

- [ ] **Step 3: Wire TS + WS in `emit_ack`**

In `crates/dpdk-net-core/src/engine.rs`, find `emit_ack` (the method that builds the pure-ACK `SegmentTx`). Replace its option + window computation with:

```rust
    fn emit_ack(&mut self, conn_idx: usize) {
        let (ws_shift, ts_enabled, ts_recent, free, src_mac, dst_mac, src_ip, dst_ip,
             src_port, dst_port, seq, ack_seq, sack_enabled, reorder_snapshot) = {
            let conn = self.flow_table.slots[conn_idx].as_ref().expect("alive conn");
            let ro: Vec<(u32, u32)> = conn.recv.reorder.segments().iter()
                .map(|s| (s.seq, s.end_seq()))
                .collect();
            (
                conn.ws_shift_out,
                conn.ts_enabled,
                conn.ts_recent,
                conn.recv.free_space(),
                self.config.src_mac,
                self.config.gateway_mac,
                self.config.local_ip,
                conn.four_tuple().peer_ip,
                conn.four_tuple().local_port,
                conn.four_tuple().peer_port,
                conn.snd_nxt,
                conn.rcv_nxt,
                conn.sack_enabled,
                ro,
            )
        };

        let scaled = if ws_shift > 0 { free >> ws_shift } else { free };
        let window = (scaled as u32).min(u16::MAX as u32) as u16;
        if free == 0 {
            crate::counters::inc(&self.counters.tcp.tx_zero_window);
        }

        let timestamps = if ts_enabled {
            Some(((self.clock.now_ns() / 1000) as u32, ts_recent))
        } else {
            None
        };

        let mut opts = crate::tcp_options::TcpOpts {
            timestamps,
            ..Default::default()
        };

        // A4: SACK blocks on outbound ACK when we have recv-side gaps.
        if sack_enabled && !reorder_snapshot.is_empty() {
            let take = reorder_snapshot.len().min(crate::tcp_options::MAX_SACK_BLOCKS_EMIT);
            for &(left, right) in reorder_snapshot.iter().rev().take(take) {
                opts.push_sack_block(crate::tcp_options::SackBlock { left, right });
            }
            crate::counters::add(&self.counters.tcp.tx_sack_blocks, take as u64);
        }

        let seg = SegmentTx {
            src_mac, dst_mac, src_ip, dst_ip,
            src_port, dst_port,
            seq, ack: ack_seq,
            flags: TCP_ACK,
            window,
            options: opts,
            payload: &[],
        };
        self.tx_frame(&seg);
        crate::counters::inc(&self.counters.tcp.tx_ack);
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p dpdk-net-core engine::tests::post_handshake_ack_carries_ts_and_ws_scaled_window`
Expected: PASS.

Run: `cargo test -p dpdk-net-core engine::tests`
Expected: all A3 tests still pass (pure ACKs with no TS/WS/SACK when `ts_enabled=false`, `ws_shift_out=0`, `sack_enabled=false` — A3 default state is still supported).

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "a4: emit_ack — TS option, WS-scaled window, SACK blocks on reorder, tx_zero_window bump"
```

---

## Task 14: Integration sanity — SYN-ACK→ACK round-trip preserves option semantics (unit level)

**Goal:** A focused integration-style unit test that round-trips a handshake through `connect` → fake peer SYN-ACK → `handle_syn_sent` outcome, asserting that post-handshake `conn.ws_shift_in`, `conn.ts_enabled`, and `conn.sack_enabled` are set as expected. Bridges the gap between Task 12 (we emit options) and Task 15 (we parse them) BEFORE the TAP-based integration tests land.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Write the test**

Append to `crates/dpdk-net-core/src/engine.rs` `mod tests`:

```rust
    #[test]
    fn handshake_option_negotiation_end_to_end() {
        use crate::tcp_options::{parse_options, TcpOpts};

        let mut eng = test_engine();
        let conn_h = eng.connect(default_connect_opts()).unwrap();
        let syn_frame = eng.drain_pending_tx().pop().unwrap();

        // Parse the SYN we emitted; peer echoes all four options back.
        let tcp_start = 14 + 20;
        let doff = (syn_frame[tcp_start + 12] >> 4) as usize;
        let syn_opts = parse_options(&syn_frame[tcp_start + 20 .. tcp_start + doff * 4]).unwrap();
        let mut peer_syn_ack_opts = TcpOpts::default();
        peer_syn_ack_opts.mss = Some(1400);
        peer_syn_ack_opts.wscale = syn_opts.wscale; // echo our shift
        peer_syn_ack_opts.sack_permitted = true;
        peer_syn_ack_opts.timestamps = Some((0xF00DD00D, syn_opts.timestamps.unwrap().0));

        // Build the peer's SYN-ACK and feed it into the engine.
        let peer_syn_ack = make_peer_syn_ack(&eng, conn_h, peer_syn_ack_opts, 0xDEADBEEFu32);
        eng.tcp_input_for_test(&peer_syn_ack);

        let c = eng.conn(conn_h);
        assert!(c.ts_enabled);
        assert_eq!(c.ws_shift_in, syn_opts.wscale.unwrap());
        assert!(c.sack_enabled);
        assert_eq!(c.ts_recent, 0xF00DD00D);
        // The engine should have emitted our final ACK completing the
        // three-way handshake.
        let tx = eng.drain_pending_tx();
        assert_eq!(tx.len(), 1, "one final ACK expected");
    }
```

(Add `make_peer_syn_ack` as a `#[cfg(test)]` helper that constructs the full Eth+IP+TCP frame from the perspective of the peer, using `build_segment` with the peer's 4-tuple swapped.)

- [ ] **Step 2: Run the test**

Run: `cargo test -p dpdk-net-core engine::tests::handshake_option_negotiation_end_to_end`
Expected: PASS (Tasks 12 + 15 together make this pass; Task 15 lands before this task in the plan ordering so it should already be green when this test is added in final pass order).

- [ ] **Step 3: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "a4: engine::tests — full handshake option-negotiation end-to-end"
```

---

## Task 15: `handle_syn_sent` parses full negotiated options

**Goal:** On SYN-ACK, decode the peer's options via `tcp_options::parse_options` and populate `conn.peer_mss`, `conn.ws_shift_in` (peer's WS), `conn.ws_shift_out` (stays at our advertised value iff peer echoed WS; zeroed otherwise per RFC 7323 §1.3), `conn.sack_enabled` (peer echoed SACK-permitted), `conn.ts_enabled` (peer echoed TS) and `conn.ts_recent` (peer's TSval). Malformed options → `bad_option` drop.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs`

- [ ] **Step 1: Update the failing tests**

Replace the existing `syn_sent_syn_ack_transitions_to_established` test with:

```rust
    #[test]
    fn syn_sent_syn_ack_negotiates_full_option_set() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_options::TcpOpts;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        c.ws_shift_out = 7;

        let mut peer_opts = TcpOpts::default();
        peer_opts.mss = Some(1400);
        peer_opts.wscale = Some(9);
        peer_opts.sack_permitted = true;
        peer_opts.timestamps = Some((0xCAFEBABE, 0x00001001));
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5000, ack: 1001,
            flags: TCP_SYN | TCP_ACK, window: 65535,
            header_len: 20 + opts_len, payload: &[],
            options: &opts_buf[..opts_len],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Established));
        assert_eq!(out.tx, TxAction::Ack);
        assert!(out.connected);
        assert_eq!(c.peer_mss, 1400);
        assert_eq!(c.ws_shift_in, 9);
        assert_eq!(c.ws_shift_out, 7);
        assert!(c.sack_enabled);
        assert!(c.ts_enabled);
        assert_eq!(c.ts_recent, 0xCAFEBABE);
    }

    #[test]
    fn syn_sent_peer_without_wscale_zeroes_both_shifts() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_options::TcpOpts;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        c.ws_shift_out = 7;

        let mut peer_opts = TcpOpts::default();
        peer_opts.mss = Some(1400);
        peer_opts.timestamps = Some((1, 2));
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5000, ack: 1001,
            flags: TCP_SYN | TCP_ACK, window: 65535,
            header_len: 20 + opts_len, payload: &[],
            options: &opts_buf[..opts_len],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Established));
        // RFC 7323 §1.3: WS only active if both sides advertise.
        assert_eq!(c.ws_shift_in, 0);
        assert_eq!(c.ws_shift_out, 0);
    }
```

- [ ] **Step 2: Extend the `Outcome` struct**

In `crates/dpdk-net-core/src/tcp_input.rs`, replace the `Outcome` struct + `impl` with:

```rust
#[derive(Debug, Clone, Copy)]
pub struct Outcome {
    pub tx: TxAction,
    pub new_state: Option<TcpState>,
    pub delivered: u32,
    pub buf_full_drop: u32,
    /// Legacy A3 counter path. A4 always leaves this at 0 (OOO payload
    /// now goes through `reassembly_queued_bytes`); kept in the struct
    /// until an A5+ task drops it from all call sites.
    pub ooo_drop: u32,
    /// A4: bytes newly buffered into `recv.reorder` on this segment.
    /// Engine bumps `tcp.rx_reassembly_queued` once when > 0.
    pub reassembly_queued_bytes: u32,
    /// A4: OOO segments drained by the gap-close at the end of this
    /// segment's processing. Engine bumps
    /// `tcp.rx_reassembly_hole_filled` by this count.
    pub reassembly_hole_filled: u32,
    /// A4: true iff a PAWS check rejected this segment. Engine bumps
    /// `tcp.rx_paws_rejected` when true.
    pub paws_rejected: bool,
    /// A4: true iff the option decoder rejected a malformed option on
    /// this segment. Engine bumps `tcp.rx_bad_option` when true.
    pub bad_option: bool,
    /// A4: number of peer SACK blocks decoded from this segment's ACK.
    /// Engine bumps `tcp.rx_sack_blocks` by this count.
    pub sack_blocks_decoded: u32,
    pub connected: bool,
    pub closed: bool,
}

impl Outcome {
    pub fn base() -> Self {
        Self {
            tx: TxAction::None,
            new_state: None,
            delivered: 0,
            buf_full_drop: 0,
            ooo_drop: 0,
            reassembly_queued_bytes: 0,
            reassembly_hole_filled: 0,
            paws_rejected: false,
            bad_option: false,
            sack_blocks_decoded: 0,
            connected: false,
            closed: false,
        }
    }
    pub fn none() -> Self { Self::base() }
    pub fn rst() -> Self {
        Self { tx: TxAction::Rst, new_state: Some(TcpState::Closed), closed: true, ..Self::base() }
    }
}
```

Mechanical sweep: find every `Outcome { tx: ..., new_state: ..., delivered: ..., buf_full_drop: ..., ooo_drop: ..., connected: ..., closed: ... }` literal in `tcp_input.rs` and replace the field list with just the A3-familiar fields and `..Outcome::base()`, e.g.:

```rust
Outcome {
    tx: TxAction::Ack,
    new_state: Some(TcpState::Established),
    connected: true,
    ..Outcome::base()
}
```

This is a repetitive but lossless rewrite — zero-defaults for new fields preserves A3's observable behaviour.

- [ ] **Step 3: Rewrite `handle_syn_sent`'s option parse**

In `crates/dpdk-net-core/src/tcp_input.rs`, replace the A3 `conn.peer_mss = parse_mss_option(seg.options);` block and everything below it in `handle_syn_sent` with:

```rust
    let parsed_opts = match crate::tcp_options::parse_options(seg.options) {
        Ok(o) => o,
        Err(_) => {
            return Outcome {
                tx: TxAction::Rst,
                new_state: Some(TcpState::Closed),
                closed: true,
                bad_option: true,
                ..Outcome::base()
            };
        }
    };

    conn.irs = seg.seq;
    conn.rcv_nxt = seg.seq.wrapping_add(1);
    conn.snd_una = seg.ack;
    // Scale the peer's advertised window by their WS if they advertised one.
    let peer_ws = parsed_opts.wscale.unwrap_or(0);
    conn.snd_wnd = (seg.window as u32).wrapping_shl(peer_ws as u32);
    conn.snd_wl1 = seg.seq;
    conn.snd_wl2 = seg.ack;
    conn.peer_mss = parsed_opts.mss.unwrap_or(536);

    match parsed_opts.wscale {
        Some(ws_peer) => { conn.ws_shift_in = ws_peer; }
        None => { conn.ws_shift_in = 0; conn.ws_shift_out = 0; }
    }
    conn.sack_enabled = parsed_opts.sack_permitted;
    if let Some((tsval, _tsecr)) = parsed_opts.timestamps {
        conn.ts_enabled = true;
        conn.ts_recent = tsval;
    } else {
        conn.ts_enabled = false;
    }

    Outcome {
        tx: TxAction::Ack,
        new_state: Some(TcpState::Established),
        connected: true,
        ..Outcome::base()
    }
```

Also remove the `parse_mss_option` import at the top of `tcp_input.rs`; it's dead after this task. Leave the function itself in place for the `tcp_input::tests::parse_mss_*` tests — or delete those tests if you also want the function gone (your call — I'd remove the function and its tests since the fuller coverage lives in `tcp_options::tests::parse_*`).

- [ ] **Step 4: Run the tests**

Run: `cargo test -p dpdk-net-core tcp_input::tests::syn_sent_`
Expected: PASS.

Run full tcp_input tests: `cargo test -p dpdk-net-core tcp_input::tests`
Expected: all pass (the mechanical `..Outcome::base()` sweep preserves A3 semantics).

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_input.rs
git commit -m "a4: handle_syn_sent parses full options; Outcome gains A4 accounting fields"
```

---

## Task 16: `handle_established` PAWS check (RFC 7323 §5)

**Goal:** When `conn.ts_enabled`, every inbound non-RST segment must carry a Timestamps option; if the segment's TSval is strictly less than `conn.ts_recent` (wrap-aware via `tcp_seq::seq_lt`), drop + emit challenge ACK. Otherwise update `conn.ts_recent` iff the segment's seq is at or before `rcv_nxt` (RFC 7323 §4.3 MUST-25). Missing TS on a TS-enabled conn is a protocol violation → `bad_option` drop.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` (`handle_established`)

- [ ] **Step 1: Write failing tests**

Append to `crates/dpdk-net-core/src/tcp_input.rs` `mod tests`:

```rust
    fn est_conn_ts(iss: u32, irs: u32, peer_wnd: u16, ts_recent: u32) -> crate::tcp_conn::TcpConn {
        let mut c = est_conn(iss, irs, peer_wnd);
        c.ts_enabled = true;
        c.ts_recent = ts_recent;
        c
    }

    #[test]
    fn paws_drops_segment_with_stale_tsval_and_emits_challenge_ack() {
        use crate::tcp_options::TcpOpts;
        let mut c = est_conn_ts(1000, 5000, 1024, 200);
        let mut peer_opts = TcpOpts::default();
        peer_opts.timestamps = Some((100, 0));
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK, window: 65535,
            header_len: 20 + n, payload: b"xxx",
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.paws_rejected);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 0);
        assert_eq!(c.ts_recent, 200); // unchanged
    }

    #[test]
    fn paws_accepts_fresh_tsval_and_updates_ts_recent() {
        use crate::tcp_options::TcpOpts;
        let mut c = est_conn_ts(1000, 5000, 1024, 200);
        let mut peer_opts = TcpOpts::default();
        peer_opts.timestamps = Some((300, 0));
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH, window: 65535,
            header_len: 20 + n, payload: b"hello",
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg);
        assert!(!out.paws_rejected);
        assert_eq!(out.delivered, 5);
        assert_eq!(c.ts_recent, 300);
    }

    #[test]
    fn missing_ts_on_ts_enabled_conn_bumps_bad_option_and_drops() {
        let mut c = est_conn_ts(1000, 5000, 1024, 200);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH, window: 65535,
            header_len: 20, payload: b"x",
            options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert!(out.bad_option);
        assert_eq!(out.delivered, 0);
    }
```

- [ ] **Step 2: Run — verify they fail**

Run: `cargo test -p dpdk-net-core tcp_input::tests::paws_ tcp_input::tests::missing_ts_on_ts_enabled_conn_bumps_bad_option_and_drops`
Expected: FAIL.

- [ ] **Step 3: Add PAWS + options-parse in `handle_established`**

In `crates/dpdk-net-core/src/tcp_input.rs` `handle_established`, right after the seq-window check and BEFORE the ACK processing block, insert:

```rust
    // A4: parse options (TS + SACK blocks). Malformed → bad_option drop.
    let parsed_opts = if seg.options.is_empty() {
        crate::tcp_options::TcpOpts::default()
    } else {
        match crate::tcp_options::parse_options(seg.options) {
            Ok(o) => o,
            Err(_) => {
                return Outcome { tx: TxAction::None, bad_option: true, ..Outcome::base() };
            }
        }
    };

    // PAWS (RFC 7323 §5) — only when TS is negotiated. Missing TS on a
    // TS-enabled conn is RFC 7323 §3.2 MUST-24 violation.
    if conn.ts_enabled {
        match parsed_opts.timestamps {
            None => {
                return Outcome { tx: TxAction::None, bad_option: true, ..Outcome::base() };
            }
            Some((ts_val, _ts_ecr)) => {
                if crate::tcp_seq::seq_lt(ts_val, conn.ts_recent) {
                    return Outcome { tx: TxAction::Ack, paws_rejected: true, ..Outcome::base() };
                }
                // RFC 7323 §4.3 MUST-25: only update ts_recent on a
                // segment whose seq is at or before rcv_nxt.
                if crate::tcp_seq::seq_le(seg.seq, conn.rcv_nxt) {
                    conn.ts_recent = ts_val;
                }
            }
        }
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p dpdk-net-core tcp_input::tests::paws_ tcp_input::tests::missing_ts_on_ts_enabled_conn_bumps_bad_option_and_drops`
Expected: all PASS.

Run full tcp_input tests: `cargo test -p dpdk-net-core tcp_input::tests`
Expected: all pass — A3 tests have `ts_enabled=false` by default, so the PAWS block is inert for them.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_input.rs
git commit -m "a4: handle_established — PAWS + bad-option drops (RFC 7323 §5)"
```

---

## Task 17: `handle_established` OOO path — enqueue + drain

**Goal:** Replace the A3 OOO-drop branch with reassembly enqueue + drain. In-order arrival at `rcv_nxt` appends to `recv.bytes`, advances `rcv_nxt`, and drains contiguous OOO entries; OOO arrivals ahead of `rcv_nxt` insert into `recv.reorder`.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` (`handle_established`)

- [ ] **Step 1: Rewrite the failing A3 test**

Replace `established_ooo_segment_acked_but_not_delivered` in `tcp_input::tests` with:

```rust
    #[test]
    fn established_ooo_segment_queues_into_reassembly() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5100, ack: 1001,
            flags: TCP_ACK, window: 65535,
            header_len: 20, payload: b"xyz", options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 0);
        assert_eq!(out.ooo_drop, 0); // A4: legacy, always zero
        assert_eq!(out.reassembly_queued_bytes, 3);
        assert_eq!(c.rcv_nxt, 5001);
        assert_eq!(c.recv.reorder.len(), 1);
        assert_eq!(&c.recv.reorder.segments()[0].payload, b"xyz");
    }

    #[test]
    fn inorder_arrival_closes_hole_and_drains_reassembly() {
        let mut c = est_conn(1000, 5000, 1024);
        c.rcv_wnd = 4096;
        let ooo = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5010, ack: 1001,
            flags: TCP_ACK, window: 65535,
            header_len: 20, payload: b"world", options: &[],
        };
        let out_ooo = dispatch(&mut c, &ooo);
        assert_eq!(out_ooo.reassembly_queued_bytes, 5);
        assert_eq!(c.rcv_nxt, 5001);

        let inorder = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH, window: 65535,
            header_len: 20, payload: b"ninebytes", options: &[],
        };
        let out_in = dispatch(&mut c, &inorder);
        assert_eq!(out_in.delivered, 9 + 5);
        assert_eq!(out_in.reassembly_hole_filled, 1);
        assert_eq!(c.rcv_nxt, 5015);
        assert!(c.recv.reorder.is_empty());
        let got: Vec<u8> = c.recv.bytes.iter().copied().collect();
        assert_eq!(&got, b"ninebytesworld");
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core tcp_input::tests::established_ooo_segment_queues_into_reassembly tcp_input::tests::inorder_arrival_closes_hole_and_drains_reassembly`
Expected: FAIL — OOO still drops (A3 code path).

- [ ] **Step 3: Rewrite the delivery block in `handle_established`**

In `crates/dpdk-net-core/src/tcp_input.rs` `handle_established`, replace the A3 delivery block (the `if seg.seq == conn.rcv_nxt { ... } else { ooo_drop = ... }` section) with:

```rust
    let mut delivered = 0u32;
    let mut buf_full_drop = 0u32;
    let mut reassembly_queued_bytes = 0u32;
    let mut reassembly_hole_filled = 0u32;
    if !seg.payload.is_empty() {
        if seg.seq == conn.rcv_nxt {
            delivered = conn.recv.append(seg.payload);
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(delivered);
            buf_full_drop = (seg.payload.len() as u32).saturating_sub(delivered);

            let (drained_bytes, drained_count) =
                conn.recv.reorder.drain_contiguous_from(conn.rcv_nxt);
            if !drained_bytes.is_empty() {
                let appended = conn.recv.append(&drained_bytes);
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(appended);
                buf_full_drop += (drained_bytes.len() as u32).saturating_sub(appended);
                delivered += appended;
            }
            reassembly_hole_filled = drained_count;
        } else if crate::tcp_seq::seq_lt(conn.rcv_nxt, seg.seq) {
            let total_cap = conn.recv.free_space_total();
            if total_cap > 0 {
                let take = (seg.payload.len() as u32).min(total_cap);
                let outcome = conn.recv.reorder.insert(seg.seq, &seg.payload[..take as usize]);
                reassembly_queued_bytes = outcome.newly_buffered;
                buf_full_drop = outcome.cap_dropped;
                if (take as usize) < seg.payload.len() {
                    buf_full_drop += seg.payload.len() as u32 - take;
                }
            } else {
                buf_full_drop = seg.payload.len() as u32;
            }
        }
    }
```

Update the final `Outcome` return at the bottom of `handle_established` to include the A4 fields:

```rust
    Outcome {
        tx,
        new_state,
        delivered,
        buf_full_drop,
        reassembly_queued_bytes,
        reassembly_hole_filled,
        // sack_blocks_decoded populated in Task 18
        ..Outcome::base()
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p dpdk-net-core tcp_input::tests::established_ooo tcp_input::tests::inorder_arrival_closes_hole_and_drains_reassembly tcp_input::tests::established_inorder tcp_input::tests::established_recv_buf_full_flags_buf_full_drop_not_ooo`
Expected: all PASS.

Run full tcp_input tests: `cargo test -p dpdk-net-core tcp_input::tests`
Expected: all pass.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_input.rs
git commit -m "a4: handle_established OOO → reassembly enqueue + drain on gap close"
```

---

## Task 18: `handle_established` decodes peer SACK blocks into `sack_scoreboard`

**Goal:** When `conn.sack_enabled` AND the segment options include SACK blocks, feed them into `conn.sack_scoreboard.insert(...)` per block; `Outcome.sack_blocks_decoded` = the block count. After `snd_una` advance, `sack_scoreboard.prune_below(conn.snd_una)`.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` (`handle_established`)

- [ ] **Step 1: Write failing tests**

Append to `tcp_input::tests`:

```rust
    #[test]
    fn established_decodes_peer_sack_blocks_into_scoreboard() {
        use crate::tcp_options::{SackBlock, TcpOpts};
        let mut c = est_conn(1000, 5000, 1024);
        c.sack_enabled = true;
        c.snd.push(&[0u8; 20]);
        c.snd_nxt = c.snd_una.wrapping_add(20);

        let mut peer_opts = TcpOpts::default();
        peer_opts.push_sack_block(SackBlock { left: 1005, right: 1010 });
        peer_opts.push_sack_block(SackBlock { left: 1015, right: 1020 });
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1003,
            flags: TCP_ACK, window: 65535,
            header_len: 20 + n, payload: &[],
            options: &buf[..n],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.sack_blocks_decoded, 2);
        assert!(c.sack_scoreboard.is_sacked(1005));
        assert!(c.sack_scoreboard.is_sacked(1018));
        assert!(!c.sack_scoreboard.is_sacked(1003));
    }

    #[test]
    fn established_prunes_scoreboard_below_snd_una() {
        use crate::tcp_options::{SackBlock, TcpOpts};
        let mut c = est_conn(1000, 5000, 1024);
        c.sack_enabled = true;
        c.sack_scoreboard.insert(SackBlock { left: 1005, right: 1010 });
        c.sack_scoreboard.insert(SackBlock { left: 1020, right: 1030 });
        c.snd.push(&[0u8; 30]);
        c.snd_nxt = c.snd_una.wrapping_add(30);

        let peer_opts = TcpOpts::default();
        let mut buf = [0u8; 40];
        let n = peer_opts.encode(&mut buf).unwrap();

        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1015,
            flags: TCP_ACK, window: 65535,
            header_len: 20 + n, payload: &[],
            options: &buf[..n],
        };
        let _ = dispatch(&mut c, &seg);
        assert_eq!(c.snd_una, 1015);
        assert_eq!(c.sack_scoreboard.len(), 1);
        assert_eq!(c.sack_scoreboard.blocks()[0].left, 1020);
    }
```

- [ ] **Step 2: Run — verify they fail**

Run: `cargo test -p dpdk-net-core tcp_input::tests::established_decodes_peer_sack tcp_input::tests::established_prunes_scoreboard`
Expected: FAIL.

- [ ] **Step 3: Wire SACK decode + prune**

In `handle_established`, AFTER the PAWS block but BEFORE the ACK-processing block, add:

```rust
    let mut sack_blocks_decoded = 0u32;
    if conn.sack_enabled && parsed_opts.sack_block_count > 0 {
        for block in &parsed_opts.sack_blocks[..parsed_opts.sack_block_count as usize] {
            conn.sack_scoreboard.insert(*block);
        }
        sack_blocks_decoded = parsed_opts.sack_block_count as u32;
    }
```

Inside the ACK-processing block, after `conn.snd_una = seg.ack;`, add:

```rust
        if conn.sack_enabled {
            conn.sack_scoreboard.prune_below(conn.snd_una);
        }
```

Update the final `Outcome { ... ..Outcome::base() }` to include `sack_blocks_decoded`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p dpdk-net-core tcp_input::tests::established_decodes_peer_sack tcp_input::tests::established_prunes_scoreboard`
Expected: PASS.

Run full tcp_input tests: `cargo test -p dpdk-net-core tcp_input::tests`
Expected: all pass.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_input.rs
git commit -m "a4: handle_established decodes peer SACK blocks + prunes on snd_una advance"
```

---

## Task 19: Wire A4 outcome-sourced counters + backfill cross-phase counters in `engine.rs`

**Goal:** Connect the `Outcome` fields from Tasks 15-18 to the `TcpCounters` fields they correspond to, and wire the cross-phase backfill counters (`rx_bad_seq`, `rx_bad_ack`, `rx_dup_ack`, `rx_urgent_dropped`, `rx_zero_window`, `tx_window_update`, `conn_table_full`, `conn_time_wait_reaped`) at their natural slow-path increment sites. `tx_zero_window` was already wired in Task 13. Returns the engine to green with every new counter reachable by the test suite.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` (emit `rx_bad_seq`, `rx_bad_ack`, `rx_dup_ack`, `rx_urgent_dropped` flags on `Outcome` — minor extension)

- [ ] **Step 1: Extend `Outcome` with the 4 new per-segment flags**

In `crates/dpdk-net-core/src/tcp_input.rs`, add to `Outcome`:

```rust
    /// A4 backfill: true iff the incoming segment's seq was outside
    /// `rcv_wnd` and we dropped + challenge-ACKed it. Engine bumps
    /// `tcp.rx_bad_seq`.
    pub bad_seq: bool,
    /// A4 backfill: true iff the ACK field was outside `(snd_una, snd_nxt]`
    /// (acking nothing new or acking future data). Engine bumps
    /// `tcp.rx_bad_ack`.
    pub bad_ack: bool,
    /// A4 backfill: true iff the segment was a duplicate ACK (ack_seq
    /// <= snd_una with no new data). Engine bumps `tcp.rx_dup_ack`.
    pub dup_ack: bool,
    /// A4 backfill: true iff the URG flag was set and we dropped the
    /// segment. Engine bumps `tcp.rx_urgent_dropped`.
    pub urgent_dropped: bool,
    /// A4 backfill: true iff the peer's advertised window is zero.
    /// Engine bumps `tcp.rx_zero_window`.
    pub rx_zero_window: bool,
```

And add them to `Outcome::base()` defaulting to `false`.

- [ ] **Step 2: Emit the flags from the per-state handlers**

In `handle_established`, set the flags at their obvious sites:
- `bad_seq = true` on the `if !in_win { return Outcome { tx: TxAction::Ack, bad_seq: true, ..Outcome::base() }; }` path.
- `bad_ack = true` on the `else if seq_lt(conn.snd_nxt, seg.ack)` challenge-ACK path.
- `dup_ack = true` on the `else` duplicate-ACK branch (immediately below the snd_una advance `if`).
- `urgent_dropped = true` (and `tx: TxAction::None`) on a new branch at the top of `handle_established` that rejects `seg.flags & TCP_URG != 0` — add `pub const TCP_URG: u8 = 0x20;` in `tcp_output.rs` and import it in `tcp_input.rs`.
- `rx_zero_window = true` whenever the incoming `seg.window == 0` and the conn is not in SYN_SENT.

`handle_close_path` also gets the `bad_seq` flag on its out-of-window branch.

- [ ] **Step 3: Map `Outcome` fields → counter bumps in `engine.rs::tcp_input`**

In `crates/dpdk-net-core/src/engine.rs`, find the block that dispatches `tcp_input::dispatch(conn, seg)` and processes the outcome. Right after the `let outcome = dispatch(...)` line, add:

```rust
        if outcome.paws_rejected {
            crate::counters::inc(&self.counters.tcp.rx_paws_rejected);
        }
        if outcome.bad_option {
            crate::counters::inc(&self.counters.tcp.rx_bad_option);
        }
        if outcome.reassembly_queued_bytes > 0 {
            crate::counters::inc(&self.counters.tcp.rx_reassembly_queued);
        }
        if outcome.reassembly_hole_filled > 0 {
            crate::counters::add(&self.counters.tcp.rx_reassembly_hole_filled, outcome.reassembly_hole_filled as u64);
        }
        if outcome.sack_blocks_decoded > 0 {
            crate::counters::add(&self.counters.tcp.rx_sack_blocks, outcome.sack_blocks_decoded as u64);
        }
        if outcome.bad_seq {
            crate::counters::inc(&self.counters.tcp.rx_bad_seq);
        }
        if outcome.bad_ack {
            crate::counters::inc(&self.counters.tcp.rx_bad_ack);
        }
        if outcome.dup_ack {
            crate::counters::inc(&self.counters.tcp.rx_dup_ack);
        }
        if outcome.urgent_dropped {
            crate::counters::inc(&self.counters.tcp.rx_urgent_dropped);
        }
        if outcome.rx_zero_window {
            crate::counters::inc(&self.counters.tcp.rx_zero_window);
        }
```

- [ ] **Step 4: Wire `conn_table_full`, `tx_window_update`, `conn_time_wait_reaped`**

`conn_table_full` — `Engine::connect` returns `Err(Error::TooManyConns)` when the flow table is full. At that return site, `inc(&self.counters.tcp.conn_table_full);`.

`tx_window_update` — the engine emits a pure-ACK "window update" segment when `rcv_wnd` transitioned from 0 to > 0 (or the application drained enough of `recv.bytes` to open the window). A4's drain-on-gap-close in Task 17 doesn't itself trigger a window update, but the engine's `try_emit_window_update` helper (if it exists per A3) should bump this on emission. If no helper exists, wire a check inside `emit_ack` — if the prior `rcv_wnd` advertised on the last ACK was 0 and this ACK advertises > 0, bump `tx_window_update`.

`conn_time_wait_reaped` — in `Engine::reap_time_wait`, each time a TIME_WAIT conn is reclaimed, `inc(&self.counters.tcp.conn_time_wait_reaped);`.

- [ ] **Step 5: Test — every A4 counter is reachable from existing tests or new targeted ones**

Extend the existing counter-coverage test (if present) or add a new one in `engine::tests`:

```rust
    #[test]
    fn a4_counters_reachable_via_targeted_scenarios() {
        let mut eng = test_engine();
        // Scenario 1: PAWS — establish TS-enabled conn, feed a stale segment.
        // Scenario 2: bad_option — feed an established conn a zero-optlen byte.
        // Scenario 3: reassembly_queued — establish conn, feed a single OOO seg.
        // Scenario 4: reassembly_hole_filled — reassembly_queued then in-order.
        // Scenario 5: tx_sack_blocks — conn with reorder, emit_ack_for_test.
        // Scenario 6: rx_sack_blocks — feed an ACK with 2 SACK blocks.
        // Scenario 7..15: backfill counters.
        // (Each scenario is compact; the purpose is reachability, not edge-case coverage.)
        // ...implementations...
        let c = eng.counters();
        for field in [&c.tcp.rx_paws_rejected, &c.tcp.rx_bad_option,
                      &c.tcp.rx_reassembly_queued, &c.tcp.rx_reassembly_hole_filled,
                      &c.tcp.tx_sack_blocks, &c.tcp.rx_sack_blocks,
                      &c.tcp.rx_bad_seq, &c.tcp.rx_bad_ack, &c.tcp.rx_dup_ack,
                      &c.tcp.rx_zero_window, &c.tcp.rx_urgent_dropped,
                      &c.tcp.tx_zero_window, &c.tcp.tx_window_update,
                      &c.tcp.conn_table_full, &c.tcp.conn_time_wait_reaped] {
            assert!(field.load(std::sync::atomic::Ordering::Relaxed) > 0,
                    "counter not reached");
        }
    }
```

This grows into the A8 counter-coverage audit's dynamic-scenario table later.

- [ ] **Step 6: Run the full workspace test**

Run: `cargo test --workspace`
Expected: all pass.

- [ ] **Step 7: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/tcp_input.rs
git commit -m "a4: wire outcome-sourced A4 counters + 8-counter cross-phase backfill"
```

---

## Task 20: Integration test — option negotiation smoke against kernel listener (TAP)

**Goal:** End-to-end: `dpdk_net_connect` to a kernel `std::net::TcpListener` over a TAP pair. Verify the SYN we emit carries MSS + WS + SACK-permitted + TS; verify the SYN-ACK the kernel sends comes back with the same four options (Linux always negotiates all four by default); verify post-handshake `conn.ws_shift_*`, `conn.ts_enabled`, `conn.sack_enabled` all reflect the negotiation; verify one in-order data segment exchange succeeds; verify clean close.

**Files:**
- Create: `crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs`

- [ ] **Step 1: Skeleton the test file**

Create `crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs`:

```rust
//! A4 integration tests over a TAP pair against a kernel-side listener.
//! Reuses A3's tap-pair harness patterns; each test stands up its own
//! engine + listener so failures stay isolated.

mod tap_harness {
    // Copy the relevant helpers from crates/dpdk-net-core/tests/tcp_basic_tap.rs
    // (tap_pair, with_engine_on_tap, kernel_listener, etc.) — they are the
    // same inputs A4 needs. If the A3 tests factored these into a
    // crate-local helper module, import that instead.
    //
    // Alternatively, pub-use the helpers from tcp_basic_tap.rs via a shared
    // tests/common/ directory (cargo supports this). Keep duplication minimal.
}

#[test]
fn option_negotiation_smoke_against_kernel_listener() {
    use tap_harness::*;
    use std::io::{Read, Write};
    let (tap_a, tap_b) = tap_pair("a4_opt_smoke");
    let mut eng = with_engine_on_tap(tap_a);
    let listener = kernel_listener(tap_b.local_addr());
    let peer_addr = listener.local_addr().unwrap();

    let conn = eng.connect_to(peer_addr);
    let mut stream = listener.accept().unwrap().0;

    // Pump poll + read until conn reaches Established.
    poll_until_established(&mut eng, conn);
    let c = eng.conn(conn);
    assert!(c.ts_enabled, "kernel negotiated TS");
    assert!(c.sack_enabled, "kernel negotiated SACK");
    assert!(c.ws_shift_in > 0, "kernel emitted WS");
    assert!(c.ws_shift_out > 0, "we emitted WS and kernel echoed");

    // Send a byte each way to confirm steady-state ACKs carry TS.
    eng.send_bytes(conn, b"ping");
    let mut buf = [0u8; 16];
    pump_until(&mut eng, &mut stream, &mut buf, 4);
    stream.write_all(b"pong").unwrap();
    poll_until_readable(&mut eng, conn);
    let got = eng.drain_readable(conn);
    assert_eq!(got, b"pong");

    eng.close(conn);
    poll_until_closed(&mut eng, conn);
}
```

(Helpers `tap_pair`, `with_engine_on_tap`, `kernel_listener`, `poll_until_established`, `poll_until_readable`, `poll_until_closed`, `pump_until`, `drain_readable`, `connect_to`, `send_bytes`, `close` are ported from the A3 test. Refactor into a shared helper module if the duplication bites.)

- [ ] **Step 2: Run**

Run: `cargo test -p dpdk-net-core --test tcp_options_paws_reassembly_sack_tap option_negotiation_smoke_against_kernel_listener -- --nocapture`
Expected: PASS.

If the TAP smoke fails with "peer didn't send SACK" on some kernels, check `/proc/sys/net/ipv4/tcp_sack` — it should be 1 by default. If the test host has it off, either skip with a feature flag or set it in the test harness.

- [ ] **Step 3: Commit**

```sh
git add crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs
git commit -m "a4: integration test — option negotiation smoke vs kernel listener"
```

---

## Task 21: Integration test — PAWS rejects a replayed stale-TSval segment

**Goal:** Set up an established TS-enabled connection, then inject a hand-crafted inbound segment whose TSval is strictly less than the current `ts_recent`. Assert the engine drops the payload (no READABLE event), emits a challenge ACK, and bumps `tcp.rx_paws_rejected`.

**Files:**
- Modify: `crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs`

- [ ] **Step 1: Add the test**

Append to `crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs`:

```rust
#[test]
fn paws_drops_replayed_stale_tsval_segment() {
    use tap_harness::*;
    use std::io::Write;
    let (tap_a, tap_b) = tap_pair("a4_paws");
    let mut eng = with_engine_on_tap(tap_a);
    let listener = kernel_listener(tap_b.local_addr());
    let conn = eng.connect_to(listener.local_addr().unwrap());
    let mut stream = listener.accept().unwrap().0;
    poll_until_established(&mut eng, conn);

    // Peer sends 4 bytes of "good" data — this advances ts_recent.
    stream.write_all(b"good").unwrap();
    poll_until_readable(&mut eng, conn);
    let _ = eng.drain_readable(conn);
    let ts_recent_before = eng.conn(conn).ts_recent;

    // Synthesize a replay: TSval = ts_recent_before - 1.
    let replay_frame = build_peer_data_frame(
        &eng, conn,
        b"stale",
        /* tsval */ ts_recent_before.wrapping_sub(1),
        /* tsecr */ 0,
    );
    let before = eng.counters().tcp.rx_paws_rejected.load(std::sync::atomic::Ordering::Relaxed);
    eng.inject_frame(&replay_frame);
    eng.poll_once();
    let after = eng.counters().tcp.rx_paws_rejected.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(after, before + 1, "PAWS counter bumped exactly once");
    // Payload was NOT delivered.
    assert!(!eng.has_pending_readable(conn));
}
```

(Helper `build_peer_data_frame` constructs a full Ethernet+IP+TCP frame from the peer's 4-tuple with the specified payload + TS values; `inject_frame` feeds bytes directly to the engine's RX path bypassing the TAP.)

- [ ] **Step 2: Run**

Run: `cargo test -p dpdk-net-core --test tcp_options_paws_reassembly_sack_tap paws_drops_replayed_stale_tsval_segment`
Expected: PASS.

- [ ] **Step 3: Commit**

```sh
git add crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs
git commit -m "a4: integration test — PAWS rejects replayed stale-TSval segment"
```

---

## Task 22: Integration test — OOO reassembly delivers on gap close

**Goal:** Inject two data segments over TAP in reversed order: `seq=5010 "world"` first, then `seq=5001 "ninebytes"`. Verify the engine emits a single concatenated READABLE event of `b"ninebytesworld"` (14 bytes), `tcp.rx_reassembly_queued == 1`, `tcp.rx_reassembly_hole_filled == 1`.

**Files:**
- Modify: `crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs`

- [ ] **Step 1: Add the test**

Append:

```rust
#[test]
fn ooo_reassembly_delivers_on_gap_close() {
    use tap_harness::*;
    use std::sync::atomic::Ordering;
    let (tap_a, tap_b) = tap_pair("a4_ooo");
    let mut eng = with_engine_on_tap(tap_a);
    let listener = kernel_listener(tap_b.local_addr());
    let conn = eng.connect_to(listener.local_addr().unwrap());
    let _stream = listener.accept().unwrap().0;
    poll_until_established(&mut eng, conn);

    let ts_now = eng.conn(conn).ts_recent; // use the most recent peer TS value
    let ooo_frame = build_peer_data_frame_at_seq(
        &eng, conn, b"world", /* seq offset */ 9,
        /* tsval */ ts_now.wrapping_add(1), /* tsecr */ 0,
    );
    let inorder_frame = build_peer_data_frame_at_seq(
        &eng, conn, b"ninebytes", /* seq offset */ 0,
        /* tsval */ ts_now.wrapping_add(2), /* tsecr */ 0,
    );

    eng.inject_frame(&ooo_frame);
    eng.poll_once();
    assert_eq!(eng.counters().tcp.rx_reassembly_queued.load(Ordering::Relaxed), 1);
    assert!(!eng.has_pending_readable(conn));

    eng.inject_frame(&inorder_frame);
    eng.poll_once();
    assert_eq!(eng.counters().tcp.rx_reassembly_hole_filled.load(Ordering::Relaxed), 1);

    let got = eng.drain_readable(conn);
    assert_eq!(&got, b"ninebytesworld");
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p dpdk-net-core --test tcp_options_paws_reassembly_sack_tap ooo_reassembly_delivers_on_gap_close`
Expected: PASS.

- [ ] **Step 3: Commit**

```sh
git add crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs
git commit -m "a4: integration test — OOO reassembly delivers on gap close"
```

---

## Task 23: Integration test — SACK blocks encode on outbound ACK + decode on inbound ACK

**Goal:** Two sub-scenarios in one test. (1) Encode: set up an established SACK-enabled conn with an OOO segment in `recv.reorder`, force an ACK emission, verify the outbound frame's SACK option covers the OOO range. (2) Decode: inject an inbound ACK carrying two SACK blocks, verify `conn.sack_scoreboard.len() == 2` after, and verify `tcp.rx_sack_blocks` bumped by 2.

**Files:**
- Modify: `crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs`

- [ ] **Step 1: Add the test**

Append:

```rust
#[test]
fn sack_blocks_round_trip_on_tap() {
    use tap_harness::*;
    use crate::tcp_options::{parse_options, SackBlock};
    use std::sync::atomic::Ordering;

    let (tap_a, tap_b) = tap_pair("a4_sack");
    let mut eng = with_engine_on_tap(tap_a);
    let listener = kernel_listener(tap_b.local_addr());
    let conn = eng.connect_to(listener.local_addr().unwrap());
    let _stream = listener.accept().unwrap().0;
    poll_until_established(&mut eng, conn);

    // --- Encode side ---
    // Inject an OOO segment to populate recv.reorder.
    let ts_now = eng.conn(conn).ts_recent;
    let ooo = build_peer_data_frame_at_seq(
        &eng, conn, b"hhh", /* seq off */ 10,
        ts_now.wrapping_add(1), 0,
    );
    eng.inject_frame(&ooo);
    eng.poll_once();
    // The engine should have emitted an ACK carrying a SACK block.
    let tx = eng.drain_tx_frames();
    let sack_ack = tx.iter().rev().find(|f| has_sack_option(f)).expect("SACK ACK");
    let opts = extract_opts_from_frame(sack_ack);
    let parsed = parse_options(&opts).unwrap();
    assert_eq!(parsed.sack_block_count, 1);
    assert_eq!(eng.counters().tcp.tx_sack_blocks.load(Ordering::Relaxed), 1);

    // --- Decode side ---
    // Inject an ACK carrying two SACK blocks into our scoreboard.
    let two_block_ack = build_peer_ack_with_sack(
        &eng, conn,
        &[SackBlock { left: 1010, right: 1020 }, SackBlock { left: 1030, right: 1040 }],
        ts_now.wrapping_add(2), 0,
    );
    eng.inject_frame(&two_block_ack);
    eng.poll_once();
    assert_eq!(eng.counters().tcp.rx_sack_blocks.load(Ordering::Relaxed), 2);
    let c = eng.conn(conn);
    assert_eq!(c.sack_scoreboard.len(), 2);
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p dpdk-net-core --test tcp_options_paws_reassembly_sack_tap sack_blocks_round_trip_on_tap`
Expected: PASS.

- [ ] **Step 3: Commit**

```sh
git add crates/dpdk-net-core/tests/tcp_options_paws_reassembly_sack_tap.rs
git commit -m "a4: integration test — SACK blocks encode + decode round-trip"
```

---

## Task 24: Cargo feature flags + hot-path counter field declarations

**Goal:** Introduce `obs-byte-counters` (default OFF) and `obs-poll-saturation` (default ON) in `dpdk-net-core/Cargo.toml`. Declare the three hot-path counter fields (`tcp.tx_payload_bytes`, `tcp.rx_payload_bytes`, `poll.iters_with_rx_burst_max`) in `counters.rs` + `api.rs` — always present in the struct for ABI stability per spec §9.1.1. Declare the meta-feature `obs-all = ["obs-byte-counters", "obs-poll-saturation"]` for the A8 counter-coverage audit's `--features obs-all` run. Increment sites land in Tasks 25-26.

**Files:**
- Modify: `crates/dpdk-net-core/Cargo.toml`
- Modify: `crates/dpdk-net-core/src/counters.rs`
- Modify: `crates/dpdk-net/src/api.rs`

- [ ] **Step 1: Add the cargo features**

In `crates/dpdk-net-core/Cargo.toml`, add (or extend) a `[features]` section:

```toml
[features]
default = ["obs-poll-saturation"]
obs-byte-counters = []
obs-poll-saturation = []
obs-all = ["obs-byte-counters", "obs-poll-saturation"]
```

- [ ] **Step 2: Declare the hot-path counter fields (unconditional)**

In `crates/dpdk-net-core/src/counters.rs`, insert:

```rust
// TcpCounters — add two hot-path fields *before* `state_trans` (so the
// u64 layout lines up with the api.rs mirror in Step 3):
    /// HOT-PATH, feature-gated by `obs-byte-counters` (default OFF).
    /// Per-burst-batched — see spec §9.1.1. Increment site lives in
    /// engine.rs, gated by `#[cfg(feature = "obs-byte-counters")]`.
    /// Answers: "how many TCP payload bytes did this engine move?"
    /// Irreducible to eth.tx_bytes (which includes L2/L3 overhead).
    pub tx_payload_bytes: AtomicU64,
    /// HOT-PATH, feature-gated by `obs-byte-counters` (default OFF).
    /// Same rationale as `tx_payload_bytes`, applied to RX.
    pub rx_payload_bytes: AtomicU64,
```

And in `PollCounters`:

```rust
    /// HOT-PATH, feature-gated by `obs-poll-saturation` (default ON).
    /// Bumped on every poll iteration where `rx_burst` returned
    /// `max_burst` — signals "we may be falling behind the NIC". No
    /// cheap alternative; batching pattern is a single conditional
    /// `fetch_add` per poll.
    pub iters_with_rx_burst_max: AtomicU64,
```

Adjust the `_pad` arrays: `TcpCounters._pad` shrinks by 2 u64s (currently 3, becomes 1); `PollCounters._pad` shrinks by 1 (currently 12, becomes 11). If either would underflow, bump the total struct size up by one cacheline and set `_pad` to the appropriate value to preserve 64-byte alignment.

- [ ] **Step 3: Mirror in `api.rs`**

In `crates/dpdk-net/src/api.rs`, insert the matching `u64` fields (same name, same order) before `state_trans` / `_pad` respectively. Rebuild `cargo build -p dpdk-net` to verify the layout assertion.

- [ ] **Step 4: Default-zero test**

Append to `counters::tests`:

```rust
    #[test]
    fn a4_hotpath_fields_declared_and_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.tx_payload_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_payload_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(c.poll.iters_with_rx_burst_max.load(Ordering::Relaxed), 0);
    }
```

- [ ] **Step 5: Build across feature sets**

Run:
```
cargo build -p dpdk-net-core --no-default-features
cargo build -p dpdk-net-core
cargo build -p dpdk-net-core --features obs-all
```
Expected: all three build clean (no increment sites yet, so no `#[cfg]` branching affects compilation).

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-core/Cargo.toml crates/dpdk-net-core/src/counters.rs crates/dpdk-net/src/api.rs include/dpdk_net.h
git commit -m "a4: declare hot-path counter fields + obs-byte-counters / obs-poll-saturation cargo features"
```

---

## Task 25: Feature-gated hot-path increment — `tx_payload_bytes` / `rx_payload_bytes`

**Goal:** Wire per-burst-batched increments for the two byte-counter fields, gated on `#[cfg(feature = "obs-byte-counters")]`. Increment pattern per spec §9.1.1 rule 2: stack-local `u64` accumulator inside the natural burst loop; single `fetch_add` after the burst drains. Default-off builds compile the counter field into the struct but the increment site disappears.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Identify the RX and TX burst loop entry points**

In `crates/dpdk-net-core/src/engine.rs`, locate:
- The RX burst loop inside `poll_once` that iterates over `rx_burst`'s returned mbufs and dispatches into `tcp_input` — we know the incoming TCP payload length per segment from `outcome.delivered + outcome.reassembly_queued_bytes`.
- The TX burst / per-segment TX in `engine.tx_frame`/`send_bytes` — `SegmentTx.payload.len()` is the byte-counter value per data segment. ACK-only segments have `payload.len() == 0` so they contribute nothing; retransmit (A5) will also count via the same pattern.

- [ ] **Step 2: Add a per-send-call TX accumulator**

Inside `Engine::send_bytes` (the method that loops over the user buffer and emits MSS-sized segments), add a `#[cfg]`-gated accumulator that sums `payload.len()` per segment and flushes at method exit:

```rust
#[cfg(feature = "obs-byte-counters")]
let mut tx_bytes_acc: u64 = 0;

// ... inside the per-segment loop ...
#[cfg(feature = "obs-byte-counters")]
{
    tx_bytes_acc += seg.payload.len() as u64;
}

// ... at method exit ...
#[cfg(feature = "obs-byte-counters")]
{
    if tx_bytes_acc > 0 {
        crate::counters::add(&self.counters.tcp.tx_payload_bytes, tx_bytes_acc);
    }
}
```

- [ ] **Step 3: Add the per-poll RX accumulator**

Inside `Engine::poll_once`'s RX burst loop, add:

```rust
#[cfg(feature = "obs-byte-counters")]
let mut rx_bytes_acc: u64 = 0;

// ... after each `let outcome = tcp_input::dispatch(conn, seg);` call ...
#[cfg(feature = "obs-byte-counters")]
{
    rx_bytes_acc += (outcome.delivered + outcome.reassembly_queued_bytes) as u64;
}

// ... at the end of the burst loop ...
#[cfg(feature = "obs-byte-counters")]
{
    if rx_bytes_acc > 0 {
        crate::counters::add(&self.counters.tcp.rx_payload_bytes, rx_bytes_acc);
    }
}
```

`delivered + reassembly_queued_bytes` counts every payload byte we accepted (in-order delivery plus buffered-for-reassembly); drops are already accounted in `tcp.recv_buf_drops`.

- [ ] **Step 4: Feature-gated tests**

Append to `engine::tests`:

```rust
    #[cfg(feature = "obs-byte-counters")]
    #[test]
    fn obs_byte_counters_fires_when_feature_on() {
        use std::sync::atomic::Ordering;
        let mut eng = test_engine();
        let conn = establish_conn_in_tests(&mut eng);
        eng.send_bytes_for_test(conn, b"hello");
        assert_eq!(eng.counters().tcp.tx_payload_bytes.load(Ordering::Relaxed), 5);

        let inbound = build_peer_data_frame_at_seq(&eng, conn, b"ack-me", 0, 0, 0);
        eng.inject_frame(&inbound);
        eng.poll_once();
        assert_eq!(eng.counters().tcp.rx_payload_bytes.load(Ordering::Relaxed), 6);
    }

    #[cfg(not(feature = "obs-byte-counters"))]
    #[test]
    fn obs_byte_counters_stays_zero_when_feature_off() {
        use std::sync::atomic::Ordering;
        let mut eng = test_engine();
        let conn = establish_conn_in_tests(&mut eng);
        eng.send_bytes_for_test(conn, b"hello");
        assert_eq!(eng.counters().tcp.tx_payload_bytes.load(Ordering::Relaxed), 0);
    }
```

- [ ] **Step 5: Run both feature sets**

```
cargo test -p dpdk-net-core
cargo test -p dpdk-net-core --features obs-byte-counters
cargo test -p dpdk-net-core --features obs-all
```
Expected: PASS in all three.

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "a4: obs-byte-counters — per-burst batched tx/rx_payload_bytes increments"
```

---

## Task 26: Feature-gated hot-path increment — `poll.iters_with_rx_burst_max`

**Goal:** Bump `poll.iters_with_rx_burst_max` on every poll iteration where the RX burst returned `max_burst` elements, gated on `#[cfg(feature = "obs-poll-saturation")]` (default ON). Single conditional `fetch_add` per poll — near-zero cost.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Add the increment**

In `crates/dpdk-net-core/src/engine.rs::poll_once`, inside the existing `if burst_size > 0` branch where `iters_with_rx` is bumped, add:

```rust
        #[cfg(feature = "obs-poll-saturation")]
        {
            if burst_size == self.config.max_rx_burst as usize {
                crate::counters::inc(&self.counters.poll.iters_with_rx_burst_max);
            }
        }
```

(If `max_rx_burst` lives on a different struct or is a compile-time const, adjust accordingly.)

- [ ] **Step 2: Feature-gated tests**

Append to `engine::tests`:

```rust
    #[cfg(feature = "obs-poll-saturation")]
    #[test]
    fn poll_saturation_fires_when_rx_burst_full() {
        use std::sync::atomic::Ordering;
        let mut eng = test_engine();
        eng.mock_next_rx_burst_full();
        eng.poll_once();
        assert_eq!(
            eng.counters().poll.iters_with_rx_burst_max.load(Ordering::Relaxed),
            1
        );
    }

    #[cfg(not(feature = "obs-poll-saturation"))]
    #[test]
    fn poll_saturation_stays_zero_when_feature_off() {
        use std::sync::atomic::Ordering;
        let mut eng = test_engine();
        eng.mock_next_rx_burst_full();
        eng.poll_once();
        assert_eq!(
            eng.counters().poll.iters_with_rx_burst_max.load(Ordering::Relaxed),
            0
        );
    }
```

(`mock_next_rx_burst_full` is a `#[cfg(test)]` helper that arranges the test rx_burst mock to return `max_burst` items on the next call.)

- [ ] **Step 3: Run across features**

```
cargo test -p dpdk-net-core
cargo test -p dpdk-net-core --no-default-features
cargo test -p dpdk-net-core --features obs-all
```
Expected: all PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "a4: obs-poll-saturation — iters_with_rx_burst_max bump (default-on feature)"
```

---

## Task 27: Workspace sanity — fmt, clippy, all-features test, header drift

**Goal:** Pre-review sweep. Catches fmt drift, clippy warnings (`-- -D warnings`), test regressions, and feature-gated path compile/test failures.

**Files:** no files modified (automated sweep).

- [ ] **Step 1: `cargo fmt`**

Run: `cargo fmt --all --check`
Expected: no output. If it fails, `cargo fmt --all` and commit the delta separately as `chore: fmt`.

- [ ] **Step 2: `cargo clippy`**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

Run: `cargo clippy --workspace --all-targets --features obs-all -- -D warnings`
Expected: PASS.

- [ ] **Step 3: `cargo test` across feature sets**

```
cargo test --workspace
cargo test --workspace --features obs-all
cargo test --workspace --no-default-features
```
Expected: all pass.

- [ ] **Step 4: Header drift check**

Run: `cargo test -p dpdk-net header_drift` (or equivalent — see A3 Task 2 notes).
Expected: PASS.

- [ ] **Step 5: Commit fixes (if any)**

```sh
git add -A
git commit -m "a4: pre-review sanity pass"
```

Skip if nothing needed fixing.

---

## Task 28: A4 mTCP comparison review (§10.13 gate)

**Goal:** Dispatch the `mtcp-comparison-reviewer` subagent (opus per `feedback_subagent_model.md`). Produces `docs/superpowers/reviews/phase-a4-mtcp-compare.md`. Human-finalizes Accepted-divergence + verdict. Gate is blocking per spec §10.13: no open `[ ]` in Must-fix / Missed-edge-cases.

**Files:** `docs/superpowers/reviews/phase-a4-mtcp-compare.md` (NEW, authored by subagent + human).

- [ ] **Step 1: Dispatch the subagent**

Use the `Agent` tool:
- `subagent_type`: `mtcp-comparison-reviewer`
- `model`: `opus`
- `description`: `A4 mTCP comparison review`
- Prompt inputs:
  - Phase: A4
  - Plan path: `docs/superpowers/plans/2026-04-18-stage1-phase-a4-options-paws-reassembly-sack.md`
  - Phase-scoped diff: `git diff phase-a3..HEAD`
  - Spec §refs claimed: §6.2 (option fields), §6.3 RFC 7323 / 2018 / 6691 rows, §7.2 recv_reorder, §9.1 + §9.1.1 counter groups
  - mTCP focus areas:
    - `third_party/mtcp/mtcp/src/tcp_util.c` — `ParseTCPOptions`, `ParseTCPTimestamp`, `ParseSACKOption`, `_update_sack_table`, `GenerateSACKOption` (stub in mTCP)
    - `third_party/mtcp/mtcp/src/tcp_in.c` — `ValidateSequence` (PAWS gate)
    - `third_party/mtcp/mtcp/src/tcp_out.c` — `GenerateTCPOptions` (SYN options + non-SYN TS)
    - `third_party/mtcp/mtcp/src/tcp_ring_buffer.c` — `RBPut` / `CanMerge` / `MergeFragments`
    - `third_party/mtcp/mtcp/src/tcp_rb_frag_queue.c` — free-frag MPSC ring
    - `third_party/mtcp/mtcp/src/tcp_stream.c` + `include/tcp_stream.h` — option-negotiated fields
  - Pre-declared accepted divergences (AD-A4-*): options-encoder (canonical fixed order), reassembly (copy-based), sack-generate (we encode, mTCP stubs), sack-scoreboard-size (4 vs mTCP's 8), paws-challenge-ack (inline vs mTCP's `ACK_OPT_NOW` enqueue), option-strictness (stricter parse than mTCP).
- Output path: `docs/superpowers/reviews/phase-a4-mtcp-compare.md`

- [ ] **Step 2: Human-finalize**

Read the report. Verify all 6 AD-A4-* entries are present with correct mTCP citations. Promote any surfaced-during-review items to AD or fix them. Ensure no open `[ ]` in Must-fix / Missed-edge-cases. Set the verdict to **PASS** or **PASS-WITH-ACCEPTED**. Match the A3 report's template.

- [ ] **Step 3: Commit**

```sh
git add docs/superpowers/reviews/phase-a4-mtcp-compare.md
git commit -m "phase a4: mtcp comparison review report (PASS-WITH-ACCEPTED)"
```

---

## Task 29: A4 RFC compliance review (§10.14 gate)

**Goal:** Dispatch `rfc-compliance-reviewer` subagent (opus). Produces `docs/superpowers/reviews/phase-a4-rfc-compliance.md`. Human-finalizes Accepted-deviation + verdict. Gate is blocking per spec §10.14: no open `[ ]` in Must-fix / Missing-SHOULD. MUST violations must be fixed before the tag.

**Files:** `docs/superpowers/reviews/phase-a4-rfc-compliance.md` (NEW).

- [ ] **Step 1: Dispatch the subagent**

- `subagent_type`: `rfc-compliance-reviewer`
- `model`: `opus`
- `description`: `A4 RFC compliance review`
- Prompt inputs:
  - Phase: A4
  - Plan path: `docs/superpowers/plans/2026-04-18-stage1-phase-a4-options-paws-reassembly-sack.md`
  - Phase-scoped diff: `git diff phase-a3..HEAD`
  - Spec §refs claimed: §6.3 matrix rows for RFC 7323 / 2018 / 6691; §6.4 (if PAWS edge cases surface a new deviation row); §9.1 / §9.1.1
  - RFCs in scope: 7323 (WS + Timestamps + PAWS — MUST-22/-23/-24/-25), 2018 (SACK — peer-echo MUST, block format MUST), 6691 (MSS under WS — MUST-14/-15/-16), 9293 §3.10.7.4/§3.10.7.5 (segment-text in-order + OOO MUSTs)
  - Pre-declared accepted deviations (to land as Accepted-deviation):
    - AD-A4-paws-challenge-ack — inline `TxAction::Ack` vs RFC 7323 §5's suggestion; matches A3's per-segment ACK baseline.
    - AD-A4-sack-scoreboard-size — 4-block cap matches RFC 2018 §3 per-ACK max under TS; evict-oldest on overflow.
    - Copy-based reassembly model (extends A3 AD-7; spec §7.2 mbuf-chain deferred).
- Output path: `docs/superpowers/reviews/phase-a4-rfc-compliance.md`

- [ ] **Step 2: Human-finalize**

Read the report. Verify MUST-level items (RFC 7323 MUST-22/-23/-24/-25, RFC 2018 peer-echo MUST, RFC 6691 MUST-14/-15/-16 under WS, RFC 9293 §3.10.7.4/§3.10.7.5 segment-text MUSTs). If any MUST is open, FIX IT — the §10.14 gate is blocking. Finalize per the A3 template.

- [ ] **Step 3: Commit**

```sh
git add docs/superpowers/reviews/phase-a4-rfc-compliance.md
git commit -m "phase a4: rfc compliance review report (PASS-WITH-DEVIATIONS)"
```

---

## Task 30: Update roadmap + tag `phase-a4-complete`

**Goal:** Flip the A4 row in the roadmap, verify review gates green, tag.

**Files:**
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md`

- [ ] **Step 1: Update the A4 row**

Replace the A4 row in `docs/superpowers/plans/stage1-phase-roadmap.md`:

```markdown
| A4 | TCP options + PAWS + reassembly + SACK scoreboard | **Complete** ✓ | `2026-04-18-stage1-phase-a4-options-paws-reassembly-sack.md` |
```

- [ ] **Step 2: Final sanity sweep**

```
cargo build --workspace --all-targets
cargo test --workspace
cargo test --workspace --features obs-all
cargo test --workspace --no-default-features
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: green across all commands.

- [ ] **Step 3: Verify review gates green**

Confirm:
- `docs/superpowers/reviews/phase-a4-mtcp-compare.md` — **PASS** or **PASS-WITH-ACCEPTED**; no open `[ ]` in Must-fix or Missed-edge-cases.
- `docs/superpowers/reviews/phase-a4-rfc-compliance.md` — **PASS** or **PASS-WITH-DEVIATIONS**; no open `[ ]` in Must-fix or Missing-SHOULD.

If any verdict is BLOCK or any `[ ]` is open, STOP — fix and re-run the reviewer. The tag is blocked by spec §10.13 / §10.14.

- [ ] **Step 4: Commit + tag**

```sh
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "mark phase a4 complete in roadmap"
git tag -a phase-a4-complete -m "Phase A4: TCP options + PAWS + reassembly + SACK scoreboard"
```

- [ ] **Step 5: Record next phase**

Next plan file to write: `docs/superpowers/plans/YYYY-MM-DD-stage1-phase-a5-rack-rto-retransmit-iss.md` — RACK-TLP + RFC 6298 RTO + retransmit fresh-header-mbuf policy + RFC 6528 ISS finalization.

---

## Self-Review Notes

**Spec coverage for Phase A4:**
- **§6.2** option-negotiated fields (`ws_shift_*`, `ts_enabled`, `ts_recent`, `ts_recent_age`, `sack_enabled`) → Task 5.
- **§6.3 RFC 7323** (Timestamps + WS + PAWS) → Tasks 3, 4, 12, 13, 15, 16.
- **§6.3 RFC 2018** (SACK) → Tasks 3, 4, 9, 10, 14, 18, 23.
- **§6.3 RFC 6691** (MSS under WS) → Tasks 3, 4, 12, 15.
- **§7.2** `recv_reorder` → Tasks 6, 7, 8, 17 (diverges per AD-A4-reassembly).
- **§9.1** counter group → Task 1 (slow-path) + Task 24 (hot-path fields).
- **§9.1.1** counter-addition policy → Tasks 24, 25, 26.
- **§10.13** mTCP review gate → Task 28.
- **§10.14** RFC review gate → Task 29.

**Explicitly deferred to later phases:**
- RACK-TLP + RTO + retransmit → A5. A4 populates `sack_scoreboard`; A5 consumes.
- Congestion control Reno → A5 follow-up.
- `DPDK_NET_EVT_WRITABLE`, real timer wheel, `dpdk_net_flush` actually flushing, `FORCE_TW_SKIP` + RFC 6191 guard → A6.
- `preset=rfc_compliance` switch → A6.
- `events_dropped_queue_full` / `events_error_enomem` / `events_error_eperm_tw_required` counters → A6 (depend on A6 infrastructure).
- `conn_timeout_syn_sent` counter → A5 (depends on A5 RTO timer + `connect_timeout_ms`).
- Loosening AD-2 (both-edges seq-window check) to mTCP right-edge-only → A5 alongside RACK-TLP.
- Mbuf-pinning zero-copy delivery model (spec §7.2 + §7.3) → later phase (A10 perf work or A6 API surface completion).

**Placeholder scan:** No "TODO" / "TBD" / "implement later" / unexplained "Similar to Task N" in any step. Every step either has complete code, a complete command + expected outcome, or (for Tasks 28/29) a complete subagent-dispatch input list. The `Outcome::base()` sweep mentioned in Task 15 is "mechanical but lossless"; Tasks 16-19 append to it incrementally. The `mock_next_rx_burst_full` / `send_bytes_for_test` / `establish_conn_in_tests` helpers referenced across engine tests are `#[cfg(test)]` affordances whose shape follows A3's existing test harness — each task's step descriptions note this.

**Type consistency cross-check:**
- `TcpOpts` / `SackBlock` / `OptionParseError` / `MAX_SACK_BLOCKS_EMIT` defined in Task 3, used identically in Tasks 4, 9, 11, 12, 13, 14, 15, 16, 18, 20-23.
- `OooSegment` / `ReorderQueue` / `InsertOutcome` defined in Task 6-7, used in Tasks 8, 17 (enqueue + drain), 14 (snapshot for SACK emit).
- `SackScoreboard` / `MAX_SACK_SCOREBOARD_ENTRIES` defined in Task 9, used in Tasks 10, 18.
- `Outcome` extended in Task 15 (options / PAWS / SACK fields) and again in Task 19 (bad_seq / bad_ack / dup_ack / urgent_dropped / rx_zero_window). Engine-side outcome mapping happens only in Task 19 — all A4 tasks that populate new `Outcome` fields rely on the Task 19 mapping block existing by the time the final integration tests (Tasks 20-23) run.
- Counter field names match exactly between `counters.rs` (core) and `api.rs` (FFI); the `const _: ()` layout assertion enforces this.
- Internal uses HBO throughout; FFI boundary at `dpdk_net_connect_opts_t` still does NBO→HBO via `u32::from_be` / `u16::from_be` as in A3.

**Counter-assertion strategy:**
- Task 19 Step 5 adds a reachability test that drives every new A4 counter > 0 via targeted scenarios. This primes the A8 counter-coverage dynamic-scenario table so A8's audit is lookup-only rather than scenario-design.
- Slow-path backfill counters (`rx_bad_seq` etc.) fire naturally in corner-case branches exercised by Task 19's scenarios — no additional Task 27-Step-1 fmt / clippy runs should flag them as "unreachable".

**Per-task review discipline (per `feedback_per_task_review_discipline.md`):**
Every non-trivial task (Tasks 1-27 — the code-touching ones) is expected to run spec-compliance + code-quality review subagents before the next task starts when executed via `superpowers:subagent-driven-development`. The phase-end mTCP + RFC reviews (Tasks 28, 29) are additional gates, not a replacement. The pure-doc tasks (Task 30 roadmap flip) skip per-task review; they go straight to the phase-end tag.

**Review gate count (phase sign-off):**
- 1 × A4 mTCP (§10.13) — Task 28.
- 1 × A4 RFC (§10.14) — Task 29.

Both must emit green reports before Task 30's tag.

**Branching + carry-over:**
- Branch `phase-a4` was created off `phase-a3` HEAD (d0a23e8), not off the `phase-a3-complete` tag (9d1e3fd5). The two post-tag commits (`cc39950`, `d0a23e8`) are part of A3 completion per the user's directive at A4 kickoff — the tag simply landed before those polish commits arrived.
- Two carry-over commits landed on `phase-a4` before this plan:
  1. `phase a4 prep: carry-over spec + roadmap edits from prior session` — §9.1.1 counter policy, A4 counter list, A8 audit static-check rows, A10 bench-vs-mtcp expansion, A12 row.
  2. `phase a4 planning fixes: drop A5/A6 counters + reconcile §9.1 write model` — removes `events_*` / `conn_timeout_syn_sent` from A4 scope (they belong to A5/A6); amends §9.1 to match the actual `fetch_add(1, Relaxed)` code.

<!-- SELF-REVIEW APPEND HERE -->
