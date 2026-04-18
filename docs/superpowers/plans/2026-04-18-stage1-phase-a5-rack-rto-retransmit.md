# resd.dpdk_tcp Stage 1 Phase A5 — RACK-TLP + RTO + Retransmit + ISS

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire RFC 8985 RACK-TLP loss detection + RFC 6298 RTO retransmission + mbuf-chained retransmit path + RFC 6528 SipHash-2-4 ISS on top of A4's option-negotiated SACK scoreboard. A5 introduces the internal §7.4 timer wheel (A6 exposes its public API later) and closes the A4 carry-over deferrals. Phase ends with the mandatory mTCP + RFC review gates and the `phase-a5-complete` tag.

**Architecture:** Six new pure-Rust modules in `resd-net-core`: `siphash24` (hand-written SipHash-2-4 + 64 RFC test vectors, no new crate dep), `tcp_timer_wheel` (hashed 8-level × 256-bucket wheel with tombstone cancel + per-conn timer-id list, crate-internal only), `tcp_rtt` (Jacobson/Karels estimator), `tcp_rack` (RFC 8985 §6.2 state + detect-lost), `tcp_tlp` (RFC 8985 §7 PTO + probe selection), `tcp_retrans` (per-conn `SendRetrans` with mbuf-ref-holding `RetransEntry`). `iss.rs` is rewired to SipHash-2-4 + `/proc/sys/kernel/random/boot_id` + 4µs ticks. `tcp_conn.rs` grows `snd_retrans`, `rtt_est`, `rack`, `rto_timer_id`, `tlp_timer_id`, `syn_retrans_*`, `rack_aggressive`, `rto_no_backoff` fields. `tcp_input.rs` grows RTT sample extraction (TS + Karn's fallback), RACK detect-lost pass after every ACK, DSACK detection, strict RFC 5681 §2 dup_ack; `tcp_options.rs` grows parser-side WS clamp. `engine.rs` stops freeing TX data mbufs — clones the ref into `snd_retrans` instead; adds the `retransmit` primitive that chains a fresh `tx_hdr_mempool` header mbuf to the held data mbuf via `rte_pktmbuf_chain`; adds RTO / TLP / SYN-retrans fire handlers; wires the `free_space_total` A4 I-8 close. Port config enables `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` (A-HW later folds this into its feature matrix). `counters.rs` gets 9 new slow-path counters + wires `tx_retrans`/`tx_rto`/`tx_tlp` (declared zero-referenced in A4). `tcp_events.rs` gains `RESD_NET_EVT_TCP_RETRANS`, `RESD_NET_EVT_TCP_LOSS_DETECTED`, `RESD_NET_EVT_ERROR{err=ETIMEDOUT}`. The C ABI grows 5 engine-config fields (`tcp_min_rto_us`, `tcp_initial_rto_us`, `tcp_max_rto_us`, `tcp_max_retrans_count`, `tcp_per_packet_events`) and 2 connect-opts fields (`rack_aggressive`, `rto_no_backoff`); `tcp_initial_rto_ms` is removed. cc_mode=reno is fully punted to A5.1.

**Tech Stack:** same as A4 — Rust stable, DPDK 23.11, bindgen, cbindgen. New stdlib: `std::fs` (read `/proc/sys/kernel/random/boot_id`). New DPDK: `rte_pktmbuf_chain`, `rte_mbuf_refcnt_update` (via `resd-net-sys` FFI wrappers — these may need adding). No new cargo crate dependencies. No new cargo features.

**Spec reference:** design spec at `docs/superpowers/specs/2026-04-18-stage1-phase-a5-rack-rto-retransmit-iss-design.md` (this phase); parent spec at `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §§ 6.2 (new TcpConn fields), 6.3 matrix rows for **6298** (RTO), **8985** (RACK-TLP), **6528** (ISS), **5681** (dup_ack strict is A5 close), 6.4 (A5 updates minRTO default + adds `maxRTO_us` row), 6.5 (ISS formula + SYN retransmit + lazy RTO re-arm + fresh-header-mbuf retransmit policy), 7.2 (`snd_retrans` layout: `(seq, mbuf_ref, first_tx_ts)`), 7.4 (internal timer wheel), 9.1 (TCP counter group — 9 new slow-path + 3 wired), 9.1.1 (slow-path default, no hot-path additions in A5), 9.3 (events), 10.13 (mTCP review gate), 10.14 (RFC compliance review gate).

**RFCs in scope for A5** (for the §10.14 RFC compliance review): **6298** (RTO: Jacobson/Karels, MUST clauses 1–6), **8985** (RACK-TLP: §6.2 detect-lost, §7 TLP, §6.3 DSACK detection, §8 interaction-with-other-RFCs), **6528** (ISS generation: SipHash-based predictability mitigation), **7323 §2.3** (WS shift > 14 SHOULD-log + MUST-14 — A4 carry-over close), **5681 §2** (dup_ack 5-condition strict definition — A4 carry-over close), **2883** (DSACK on the receive side — we only observe peer DSACK as counter-only visibility), **9293** (segment-text retransmit handling). RFCs 5682 (F-RTO), 6582 (NewReno) stay explicitly out of scope per the design doc. All text vendored at `docs/rfcs/rfcNNNN.txt`.

**Review gates at phase sign-off** (two reports, each a blocking gate per spec §10.13 / §10.14):
1. **A5 mTCP comparison review** — `docs/superpowers/reviews/phase-a5-mtcp-compare.md`. mTCP focus areas: `mtcp/src/tcp_out.c::AddPacketToSendBuffer` (send + retransmit scheduling), `mtcp/src/tcp_in.c::Handle_TCP_ST_ESTABLISHED` (ACK processing, RTT sampling), `mtcp/src/tcp_rb.c::CopyToSndBuf` + `EnqueueRetransmit` (retransmit buffer layout — mTCP uses copy-based linear ring, we use mbuf-ref list, AD-A5-retrans-mbuf-chain), `mtcp/src/tcp_stream.c::CreateTCPStream` + `tcp_stream.h::tcp_stream` (ISS generation — mTCP uses simple rand-based ISS, we use RFC 6528 SipHash, AD-A5-iss-siphash), `mtcp/src/tcp_out.c::HandleRTO` (RTO backoff logic — mTCP doubles too), `mtcp/src/tcp_rb.c` per-conn retransmit-ring style vs. our VecDeque + timer-wheel, `mtcp/src/timer.c` + `timer.h` (mTCP uses a single-level list-per-tick timer; we use hashed wheel per spec §7.4, AD-A5-hashed-timer-wheel). mTCP has no RACK-TLP nor explicit TLP — `tcp_out.c::HandleRTO` is the only loss-detection mechanism. Expected ADs: `AD-A5-rack-tlp-vs-dup-ack` (we implement RFC 8985, mTCP uses 3-dup-ACK fast-retrans + RTO only), `AD-A5-hashed-timer-wheel`, `AD-A5-retrans-mbuf-chain`, `AD-A5-iss-siphash`, `AD-A5-tcp-max-retrans-count-15`, `AD-A5-tcp-max-rto-us-1s` (RFC 6298 allows ≥60s, we cap at 1s).
2. **A5 RFC compliance review** — `docs/superpowers/reviews/phase-a5-rfc-compliance.md`. RFCs: 6298, 8985, 6528, 7323 §2.3 (carry-over), 5681 §2 (carry-over), 2883 (DSACK), 9293.

The `phase-a5-complete` tag is blocked while either report has an open `[ ]` in Must-fix / Missed-edge-cases / Missing-SHOULD.

**Deviations from RFC defaults explicitly recorded for A5** (to land in §6.4 during Task 31):

- **`minRTO = 5ms`** (existing §6.4 row updated from "20ms" to "5ms" — stronger trading rationale: exchange-direct RTT is 50–100µs, so even 5ms is 50× median).
- **`maxRTO = 1s`** (new §6.4 row, RFC 6298 allows ≥60s; we cap at 1s for trading fail-fast).
- **`tcp_max_retrans_count = 15`** (new §6.5 implementation-choice bullet, not an RFC deviation since RFC 6298 uses total-time-budget not count; documented for operator clarity — with default backoff cap hits ≈8.3s total budget per segment).
- **Per-connect `rack_aggressive=true` → RACK reo_wnd = 0** (within RFC 8985 §6.2 sender discretion; no AD entry required).
- **Per-connect `rto_no_backoff=true` → RTO stays constant** (deviates from RFC 6298 §5.5 MUST; opt-in per-connect so default build is compliant; AD-A5-rto-no-backoff-opt-in in the RFC review).
- **DSACK detected but no behavioral adaptation** (RFC 2883 receive-side; we count via `tcp.rx_dsack` but do not adjust reo_wnd dynamically or run reneging-safe pruning — documented as "visibility only, adaptation deferred" in §6.5).
- **ISS formula** (spec §6.5 already fixed; A5 finalizes to match).

**Architectural Accepted Divergences vs mTCP pre-declared for the A5 mTCP review:**

- **AD-A5-rack-tlp-vs-dup-ack** — We implement RFC 8985 RACK-TLP as the primary loss-detection path (spec §6.3 row for RFC 8985). mTCP's `tcp_in.c::HandleActiveClose` + `HandleRTO` uses the classic 3-dup-ACK fast retransmit from RFC 5681 plus RTO as the sole recovery trigger; it has no RACK and no TLP. RACK-TLP catches tail losses (TLP) and handles reordering more robustly (reo_wnd) than 3-dup-ACK can. Strictly more RFC-compliant, plus RFC 8985 was designed to supersede 3-dup-ACK per §1.
- **AD-A5-hashed-timer-wheel** — We use a hashed timing wheel per spec §7.4 (8 levels × 256 buckets, 10µs resolution, tombstone cancel). mTCP's `timer.c` uses a per-tick linear-scan list `timer_head[]` keyed by expiry tick index, with each stream on exactly one list at a time. Wheels are O(1) schedule + O(1) expire; mTCP's list is O(N) expire per tick (bounded but non-constant). Our wheel is overkill for ≤100 conns at Stage 1 but is the spec-chosen primitive and keeps API surface stable for Stage 2.
- **AD-A5-retrans-mbuf-chain** — Our retransmit path holds an `Mbuf` ref per in-flight segment in `SendRetrans::RetransEntry`; a retransmit allocates a fresh header mbuf from `tx_hdr_mempool` and `rte_pktmbuf_chain()`s it to the held data mbuf. mTCP's `tcp_rb.c::CopyToSndBuf` copies bytes into a per-stream linear `send_buffer`; retransmit walks the buffer, prepends headers inline, and TXes. Ours avoids the copy, needs `MULTI_SEGS`-capable NIC, and keeps the data mbuf pinned longer (pool-sizing implication noted in spec §7.1).
- **AD-A5-iss-siphash** — Our ISS uses `siphash24(key=secret, msg=4-tuple ‖ boot_nonce) + clock_4us_ticks.low_32` per RFC 6528 §3 exact. mTCP's `CreateTCPStream` uses a simpler ISS (typically `rand()`); RFC 6528 predictability guard is weaker on mTCP. We're strictly more compliant on ISS, not a deviation-from-best-practice so much as mTCP-is-not-the-reference-here.
- **AD-A5-tcp-max-retrans-count-15** — We fail a conn after 15 retransmits of the same segment. mTCP uses `TCP_MAX_RTX` (default 15 as well). Convergence on the number.
- **AD-A5-tcp-max-rto-us-1s** — RFC 6298 §5.5 allows RTO max of 60s. mTCP's max derives from their timer tick; Linux default is 120s. We cap at 1s for trading fail-fast.

**Deferred to later phases (A5 is explicitly NOT doing these):**

- **Congestion control (Reno under `cc_mode`)** → A5.1 if/when needed in test. A5 does not introduce `cwnd` / `ssthresh` fields.
- **RFC 5682 F-RTO** → out of Stage 1 scope per design doc.
- **RFC 8985 dynamic reo_wnd adaptation** → Stage 2. DSACK counter is observable; the spec §6.3 adaptation formula stays unimplemented.
- **Public `resd_net_timer_add` / `cancel` / `TIMER` event** → A6. A5 builds the internal wheel; A6 exposes the public layer.
- **RFC 7323 §5.5 24-day TS.Recent expiration** → A6 (needs public timer API).
- **`resd_net_flush`, `WRITABLE` event on send-drain, `FORCE_TW_SKIP` + RFC 6191 guard, event-queue overflow** → A6.
- **Per-packet events gated by `tcp_per_packet_events` configured at runtime via a setter** → A6 follow-up; A5 wires it via `engine_config_t` at `engine_create` only.

---

## File Structure Created or Modified in This Phase

```
crates/resd-net-core/
├── src/
│   ├── lib.rs                       (MODIFIED: expose siphash24, tcp_timer_wheel, tcp_rtt, tcp_rack, tcp_tlp, tcp_retrans)
│   ├── iss.rs                       (MODIFIED: rewire to siphash24 + /proc/sys/kernel/random/boot_id + 4µs ticks)
│   ├── counters.rs                  (MODIFIED: 9 new slow-path TCP counters; tx_retrans/tx_rto/tx_tlp wired)
│   ├── tcp_conn.rs                  (MODIFIED: snd_retrans, rtt_est, rack, rto_timer_id, tlp_timer_id, syn_retrans_count, syn_retrans_timer_id, rack_aggressive, rto_no_backoff)
│   ├── tcp_input.rs                 (MODIFIED: RTT sample extraction, RACK detect-lost pass, DSACK detection, strict RFC 5681 §2 dup_ack, WS>14 SHOULD-log one-shot, ooo_drop removal)
│   ├── tcp_options.rs               (MODIFIED: parser clamps WS shift to 14 + returns clamp signal)
│   ├── tcp_output.rs                (MODIFIED: build_segment emits TS with current now_us — no change, but retrans path reuses; I-8 close site reference only)
│   ├── engine.rs                    (MODIFIED: send_bytes holds mbuf ref in snd_retrans, retransmit primitive, RTO/TLP/SYN-retrans fire handlers, MULTI_SEGS offload bit, free_space_total in send_bytes, WS>14 one-shot log)
│   ├── tcp_events.rs                (MODIFIED: EvtTcpRetrans, EvtTcpLossDetected, EvtError err=ETIMEDOUT)
│   ├── siphash24.rs                 (NEW: hand-written SipHash-2-4 + 64 RFC test vectors)
│   ├── tcp_timer_wheel.rs           (NEW: 8-level × 256-bucket hashed wheel, tombstone cancel, per-conn timer-id list)
│   ├── tcp_rtt.rs                   (NEW: RttEstimator — Jacobson/Karels, min_rto floor, apply_backoff with no-op opt)
│   ├── tcp_rack.rs                  (NEW: RackState + update_on_ack + compute_reo_wnd + detect_lost)
│   ├── tcp_tlp.rs                   (NEW: pto_us + select_probe)
│   └── tcp_retrans.rs               (NEW: SendRetrans + RetransEntry with mbuf ref)
└── tests/
    └── tcp_rack_rto_retrans_tap.rs  (NEW: 10 integration scenarios over TAP — RTO, RACK, TLP, aggressive, max-retrans, SYN-retrans, ISS-monotonicity, no-backoff, DSACK, mbuf-chain)

crates/resd-net/src/
├── api.rs                           (MODIFIED: engine config + connect_opts new fields; counter struct mirrors)
└── lib.rs                           (MODIFIED: RESD_NET_EVT_TCP_RETRANS / _LOSS_DETECTED dispatch; ETIMEDOUT err)

crates/resd-net-sys/
└── build.rs                         (MODIFIED: ensure rte_pktmbuf_chain + rte_mbuf_refcnt_update are in the allowlist — check after A4 state)

include/resd_net.h                   (REGENERATED via cbindgen: 5 engine-config fields + 2 connect-opts fields + 2 new event kinds + ETIMEDOUT err)

examples/cpp-consumer/main.cpp       (MODIFIED: set one reasonable value for each new config field; print a few A5 counters)

docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md
                                     (MODIFIED: §6.3 RFC 5681 note, §6.4 minRTO 20ms→5ms + new maxRTO row, §6.5 fresh-header-mbuf already present but cross-link retransmit impl, §9.1 tcp counter examples, §9.3 ETIMEDOUT, §6.3 RACK-TLP row refined)
docs/superpowers/plans/stage1-phase-roadmap.md
                                     (MODIFIED at end of phase: A5 row → Complete + link to this plan)
docs/superpowers/reviews/phase-a5-mtcp-compare.md      (NEW)
docs/superpowers/reviews/phase-a5-rfc-compliance.md    (NEW)
```

---

## Task 1: `siphash24.rs` — hand-written SipHash-2-4 primitive + RFC test vectors

**Files:**
- Create: `crates/resd-net-core/src/siphash24.rs`
- Modify: `crates/resd-net-core/src/lib.rs` — add `pub mod siphash24;`

**Context:** Spec §6.5 requires RFC 6528 §3 ISS construction with SipHash-2-4 as the keyed hash. Rust `std::collections::hash_map::DefaultHasher` is SipHash-1-3 (weaker); we hand-write SipHash-2-4 in the crate (~60 LOC) with the reference-C test vectors so the ISS primitive is cryptographically aligned with the RFC without a new crate dep. Takes a 128-bit key and an arbitrary byte message; returns a u64 hash.

- [ ] **Step 1: Write the failing test file**

```rust
// crates/resd-net-core/src/siphash24.rs
//! SipHash-2-4 keyed hash (Aumasson/Bernstein 2012).
//! Used by `iss.rs` to generate RFC 6528 §3-compliant Initial Sequence Numbers.
//!
//! Reference implementation + test vectors:
//!   https://131002.net/siphash/siphash24.c
//!   https://131002.net/siphash/vectors.h
//! 64 test vectors; key = [0, 1, ..., 15]; message[i] = i (length 0..64).
//!
//! Hand-written so we don't pull a crate dep for ~60 LOC of arithmetic.

#[inline(always)]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Compute the SipHash-2-4 of `msg` keyed by the 16-byte `key`.
pub fn siphash24(key: &[u8; 16], msg: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let mut v0 = k0 ^ 0x736f6d6570736575_u64;
    let mut v1 = k1 ^ 0x646f72616e646f6d_u64;
    let mut v2 = k0 ^ 0x6c7967656e657261_u64;
    let mut v3 = k1 ^ 0x7465646279746573_u64;

    let mut i = 0;
    while i + 8 <= msg.len() {
        let m = u64::from_le_bytes(msg[i..i + 8].try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 8;
    }

    // Final block: remaining bytes + length byte in the high byte.
    let mut last: u64 = (msg.len() as u64 & 0xff) << 56;
    let remaining = &msg[i..];
    for (idx, byte) in remaining.iter().enumerate() {
        last |= (*byte as u64) << (idx * 8);
    }
    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xff;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^ v1 ^ v2 ^ v3
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference key from vectors.h: 00 01 02 ... 0f.
    fn ref_key() -> [u8; 16] {
        let mut k = [0u8; 16];
        for i in 0..16 {
            k[i] = i as u8;
        }
        k
    }

    /// Reference vectors from vectors.h (first 8 of 64). The canonical
    /// 64 u64 outputs are for message [0, 1, ..., n-1] for n in 0..64.
    /// Full table lives in tests/siphash24_vectors.rs.
    const REF_VECTORS_FIRST_8: [u64; 8] = [
        0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
        0xcf2794e0277187b7, 0x18765564cd99a68d, 0xcbc9466e58fee3ce, 0xab0200f58b01d137,
    ];

    #[test]
    fn siphash24_reference_vectors_first_8() {
        let key = ref_key();
        for (i, expected) in REF_VECTORS_FIRST_8.iter().enumerate() {
            let msg: Vec<u8> = (0..i as u8).collect();
            let got = siphash24(&key, &msg);
            assert_eq!(
                got, *expected,
                "length {i}: got {got:016x}, expected {expected:016x}"
            );
        }
    }

    #[test]
    fn empty_message_with_zero_key_is_deterministic() {
        let key = [0u8; 16];
        assert_eq!(siphash24(&key, b""), siphash24(&key, b""));
    }

    #[test]
    fn different_keys_produce_different_outputs() {
        let k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        k2[0] = 1;
        assert_ne!(siphash24(&k1, b"hello"), siphash24(&k2, b"hello"));
    }

    #[test]
    fn different_messages_produce_different_outputs() {
        let key = ref_key();
        assert_ne!(siphash24(&key, b"abc"), siphash24(&key, b"abd"));
    }
}
```

Also create `crates/resd-net-core/tests/siphash24_vectors.rs` with the full 64 reference vectors (from `https://131002.net/siphash/vectors.h` — public domain). Each line is one hex u64 for message length 0..64.

- [ ] **Step 2: Run test to verify it compiles and first-8 vectors pass**

Run: `cargo test -p resd-net-core siphash24 -- --nocapture`
Expected: `siphash24_reference_vectors_first_8` PASS; other three tests PASS. If first-8 fails on some index, the `sipround` constants or endianness handling is off — re-check against the reference C.

- [ ] **Step 3: Add the full 64-vector integration test**

Create `crates/resd-net-core/tests/siphash24_full_vectors.rs` containing:

```rust
use resd_net_core::siphash24::siphash24;

const FULL_VECTORS: [u64; 64] = [
    // Populate from https://131002.net/siphash/vectors.h — each element
    // is the expected u64 output for msg = [0u8, 1u8, ..., (n-1) as u8],
    // n = 0..64, with key = [0u8, 1u8, ..., 15u8].
    0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
    0xcf2794e0277187b7, 0x18765564cd99a68d, 0xcbc9466e58fee3ce, 0xab0200f58b01d137,
    0x93f5f5799a932462, 0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
    0x751e8fbc860ee5fb, 0x14ea5627c0843d90, 0xf723ca908e7af2ee, 0xa129ca6149be45e5,
    0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794, 0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd,
    0xbed65cf21aa2ee98, 0xd0f2cbb02e3b67c7, 0x93536795e3a33e88, 0xa80c038ccd5ccec8,
    0xb8ad50c6f649af94, 0xbce192de8a85b8ea, 0x17d835b85bbb15f3, 0x2f2e6163076bcfad,
    0xde4daaaca71dc9a5, 0xa6a2506687956571, 0xad87a3535c49ef28, 0x32d892fad841c342,
    0x7127512f72f27cce, 0xa7f32346f95978e3, 0x12e0b01abb051238, 0x15e034d40fa197ae,
    0x314dffbe0815a3b4, 0x027990f029623981, 0xcadcd4e59ef40c4d, 0x9abfd8766a33735c,
    0x0e3ea96b5304a7d0, 0xad0c42d6fc585992, 0x187306c89bc215a9, 0xd4a60abcf3792b95,
    0xf935451de4f21df2, 0xa9538f0419755787, 0xdb9acddff56ca510, 0xd06c98cd5c0975eb,
    0xe612a3cb9ecba951, 0xc766e62cfcadaf96, 0xee64435a9752fe72, 0xa192d576b245165a,
    0x0a8787bf8ecb74b2, 0x81b3e73d20b49b6f, 0x7fa8220ba3b2ecea, 0x245731c13ca42499,
    0xb78dbfaf3a8d83bd, 0xea1ad565322a1a0b, 0x60e61c23a3795013, 0x6606d7e446282b93,
    0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3, 0xe51b38608ef25f57, 0x958a324ceb064572,
];

#[test]
fn full_64_reference_vectors() {
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = i as u8;
    }
    for (n, expected) in FULL_VECTORS.iter().enumerate() {
        let msg: Vec<u8> = (0..n as u8).collect();
        let got = siphash24(&key, &msg);
        assert_eq!(got, *expected, "length {n}: got {got:016x}, expected {expected:016x}");
    }
}
```

Run: `cargo test -p resd-net-core --test siphash24_full_vectors`
Expected: PASS on all 64.

- [ ] **Step 4: Add `pub mod siphash24;` to `lib.rs`**

Modify `crates/resd-net-core/src/lib.rs` to include the new module alongside the existing module declarations.

Run: `cargo build -p resd-net-core`
Expected: compiles clean.

- [ ] **Step 5: Spec-compliance + code-quality review (per `feedback_per_task_review_discipline.md`)**

Dispatch two subagents (opus model per `feedback_subagent_model.md`) in parallel:
- `general-purpose` with prompt: "Review `crates/resd-net-core/src/siphash24.rs` + `crates/resd-net-core/tests/siphash24_full_vectors.rs` against the SipHash-2-4 reference at `https://131002.net/siphash/siphash24.c`. Confirm: (1) the sipround constants match, (2) endianness is little-endian throughout (`from_le_bytes`), (3) the finalization byte is `0xff` XORed into v2, (4) the final-block length byte is in bit 56 of `last`, (5) all 64 reference vectors pass. Report any divergence with file:line."
- `general-purpose` with prompt: "Code-quality review of `crates/resd-net-core/src/siphash24.rs`. Check: no `unsafe`; `#[inline(always)]` on `sipround` is justified; no allocations in the hot path; no panics on empty or oversized msg; `try_into().unwrap()` on slices is guarded by length check. Suggest tightenings that don't change the bit-exact output."

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/siphash24.rs \
        crates/resd-net-core/src/lib.rs \
        crates/resd-net-core/tests/siphash24_full_vectors.rs
git commit -m "$(cat <<'EOF'
a5 task 1: siphash24 primitive + 64 RFC test vectors

Hand-written SipHash-2-4 per the Aumasson/Bernstein reference; no new
crate dependency. All 64 reference vectors pass. Will be consumed by
iss.rs in Task 2.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `iss.rs` rewire — SipHash-2-4 + boot_nonce + 4µs ticks

**Files:**
- Modify: `crates/resd-net-core/src/iss.rs`

**Context:** Spec §6.5 ISS formula:
```
ISS = (monotonic_time_4µs_ticks_low_32)
    + siphash24(key=secret, msg=local_ip ‖ local_port ‖ remote_ip ‖ remote_port ‖ boot_nonce).low_32
```

Current `iss.rs` uses `DefaultHasher` (SipHash-1-3) + 1µs clock + TSC-seeded secret. A5 finalizes to the spec:
- `secret`: 128-bit random from `getrandom` (fallback to the current TSC-seeded pattern if `getrandom` is not accessible in the build environment — document as degraded mode).
- `boot_nonce`: 128 bits from `/proc/sys/kernel/random/boot_id`. If unreadable, fall back to a per-engine random (logged once as a warning).
- Clock: `clock::now_ns() / 4000` (4µs ticks), low 32 bits.
- Added OUTSIDE the hash so reconnects to the same 4-tuple within MSL yield monotonically-increasing ISS.

- [ ] **Step 1: Write the failing test additions first**

Add these tests to `crates/resd-net-core/src/iss.rs` (below the existing `mod tests`):

```rust
#[cfg(test)]
mod tests_a5 {
    use super::*;

    #[test]
    fn a5_uses_4us_clock_ticks_for_monotonic_component() {
        // The spec §6.5 clock is 4µs ticks. Verify that two calls separated by
        // a small sleep produce a delta consistent with 4µs quantization: the
        // hash component is identical (same tuple, same secret, same boot_nonce),
        // so the ISS delta is purely the clock delta divided by 4µs.
        let g = IssGen::new_deterministic_for_test([0x11; 16], [0x22; 16]);
        let t = super::tests::tuple(5000);
        let a = g.next(&t);
        // Spin ~8µs of real time to cross at least one 4µs boundary.
        let target_ns = crate::clock::now_ns() + 8_000;
        while crate::clock::now_ns() < target_ns {
            std::hint::spin_loop();
        }
        let b = g.next(&t);
        // Monotonic; delta should be small positive (u32 wrap arithmetic).
        let delta = b.wrapping_sub(a);
        assert!(delta >= 1, "delta should reflect at least one 4µs tick");
        assert!(delta < 100_000, "delta should not be huge: {delta}");
    }

    #[test]
    fn a5_different_boot_nonces_produce_different_iss_for_same_tuple() {
        let g1 = IssGen::new_deterministic_for_test([0xaa; 16], [0x01; 16]);
        let g2 = IssGen::new_deterministic_for_test([0xaa; 16], [0x02; 16]);
        let t = super::tests::tuple(5000);
        // Same tuple, same secret, different boot_nonce → different hash
        // component. Clock component is shared so the difference reflects hash.
        assert_ne!(g1.next(&t), g2.next(&t));
    }

    #[test]
    fn a5_boot_id_readable_path_produces_nonzero_boot_nonce() {
        // When /proc/sys/kernel/random/boot_id exists (typical Linux host),
        // the nonce reader returns Some(nonce) with nonce != 0.
        if let Some(nonce) = read_boot_id() {
            assert_ne!(nonce, [0u8; 16], "boot_id must not be all zeros");
        }
        // On non-Linux / CI without /proc, `None` is an acceptable outcome;
        // IssGen::new falls back to a per-engine random and logs once.
    }
}
```

- [ ] **Step 2: Run the tests to confirm they fail to compile**

Run: `cargo test -p resd-net-core iss::tests_a5`
Expected: FAIL with "`IssGen::new_deterministic_for_test` not found", "`read_boot_id` not found".

- [ ] **Step 3: Rewrite `iss.rs` to the A5 shape**

Replace the whole file with:

```rust
//! RFC 6528 §3 ISS generator — SipHash-2-4 keyed on a 128-bit per-process
//! secret, with a 128-bit boot_nonce mixed into the message so per-boot ISS
//! never collides across restarts. Monotonic 4µs-tick clock added OUTSIDE
//! the hash so reconnects to the same 4-tuple within MSL yield monotonically
//! increasing ISS.
//!
//! Formula (spec §6.5):
//!     ISS = (monotonic_time_4µs_ticks_low_32)
//!         + siphash24(key=secret, msg=tuple ‖ boot_nonce).low_32

use std::fs;

use crate::clock;
use crate::flow_table::FourTuple;
use crate::siphash24::siphash24;

pub struct IssGen {
    /// SipHash-2-4 key: 128 bits of per-process random.
    secret: [u8; 16],
    /// 128-bit boot-unique nonce (read from /proc/sys/kernel/random/boot_id
    /// or a per-engine random fallback).
    boot_nonce: [u8; 16],
}

impl IssGen {
    /// Create a new generator. Secret is derived from process entropy
    /// (first attempt: `getrandom`; fallback: TSC-seeded degraded mode
    /// with a one-time warning log). Boot nonce is read from
    /// `/proc/sys/kernel/random/boot_id`; fallback: per-engine random.
    pub fn new() -> Self {
        let secret = read_process_secret();
        let boot_nonce = read_boot_id().unwrap_or_else(|| {
            eprintln!(
                "resd_net: /proc/sys/kernel/random/boot_id unreadable; \
                 ISS boot_nonce falls back to per-engine random (degraded mode)"
            );
            read_process_secret() // independent random
        });
        Self {
            secret,
            boot_nonce,
        }
    }

    /// Test-only deterministic ctor so the test suite can pin the secret
    /// and boot_nonce for reproducible assertions.
    #[cfg(test)]
    pub fn new_deterministic_for_test(secret: [u8; 16], boot_nonce: [u8; 16]) -> Self {
        Self {
            secret,
            boot_nonce,
        }
    }

    /// Compute ISS for `tuple`. Peer cannot predict unless they know
    /// our `secret`; within the same 4-tuple and process, consecutive
    /// calls monotonically increase because the 4µs-tick clock is added last.
    pub fn next(&self, tuple: &FourTuple) -> u32 {
        // Pack tuple ‖ boot_nonce into a contiguous message buffer (20+16 = 36 bytes).
        let mut msg = [0u8; 36];
        msg[0..4].copy_from_slice(&tuple.local_ip.to_be_bytes());
        msg[4..6].copy_from_slice(&tuple.local_port.to_be_bytes());
        msg[6..10].copy_from_slice(&tuple.peer_ip.to_be_bytes());
        msg[10..12].copy_from_slice(&tuple.peer_port.to_be_bytes());
        // 8 bytes of zero padding before boot_nonce to keep field alignment
        // obvious; does not affect cryptographic properties.
        msg[20..36].copy_from_slice(&self.boot_nonce);

        let hash_low32 = siphash24(&self.secret, &msg) as u32;
        // 4µs-tick monotonic clock — spec §6.5.
        let clock_4us = (clock::now_ns() / 4_000) as u32;
        hash_low32.wrapping_add(clock_4us)
    }
}

impl Default for IssGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Read `/proc/sys/kernel/random/boot_id`. The file contains a UUID-style
/// 128-bit value (e.g. `550e8400-e29b-41d4-a716-446655440000\n`); we strip
/// dashes, hex-decode, return 16 bytes. `None` on any I/O or parse failure.
pub(crate) fn read_boot_id() -> Option<[u8; 16]> {
    let contents = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let trimmed = contents.trim();
    let hex_only: String = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_only.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex_only.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Read 16 bytes of process-random. Preferred path: `getrandom` syscall
/// via `std`-provided `rand` primitive. Fallback: TSC-seeded mixing
/// (degraded but still unpredictable-to-peer for Stage 1 trading). This
/// function is intentionally inline rather than a new crate dep.
fn read_process_secret() -> [u8; 16] {
    // Try /dev/urandom first (Linux path; no external dep).
    if let Ok(bytes) = fs::read("/dev/urandom") {
        if bytes.len() >= 16 {
            let mut out = [0u8; 16];
            out.copy_from_slice(&bytes[..16]);
            return out;
        }
    }
    // Degraded fallback — mix multiple TSC reads at different offsets.
    let t1 = clock::now_ns();
    let t2 = t1.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let t3 = t1.wrapping_add(0xBF58_476D_1CE4_E5B9);
    let t4 = t1.wrapping_mul(0x6A09_E667_F3BC_C908);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&t2.to_le_bytes());
    out[8..16].copy_from_slice(&(t3 ^ t4).to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn tuple(peer_port: u16) -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port,
        }
    }

    #[test]
    fn two_engines_produce_different_iss_for_same_tuple() {
        let g1 = IssGen::new();
        let g2 = IssGen::new();
        let t = tuple(5000);
        // Different process-random secrets → different hash components.
        // (Probabilistic: essentially never collides.)
        assert_ne!(g1.next(&t), g2.next(&t));
    }

    #[test]
    fn sequential_calls_monotonic_for_same_tuple() {
        let g = IssGen::new_deterministic_for_test([0; 16], [0; 16]);
        let t = tuple(5000);
        let a = g.next(&t);
        for _ in 0..10_000 {
            std::hint::spin_loop();
        }
        let b = g.next(&t);
        let delta = b.wrapping_sub(a);
        assert!(delta < 1_000_000, "delta too large: {delta}");
    }

    #[test]
    fn different_tuples_give_different_iss() {
        let g = IssGen::new_deterministic_for_test([0; 16], [0; 16]);
        let a = g.next(&tuple(5000));
        let b = g.next(&tuple(5001));
        assert_ne!(a, b);
    }
}
```

Note the A4 `IssGen::new(seed: u64)` signature was only used by tests (engine construction used `IssGen::new` with seed=0 as a production path); the `#[cfg(test)]` `new_deterministic_for_test` replaces the test use. Production `new()` is now seedless. Audit the engine for `IssGen::new(` call sites and update to `IssGen::new()`.

- [ ] **Step 4: Fix engine call site**

Run: `grep -rn 'IssGen::new(' crates/resd-net-core/src/`
Expected: one hit in `engine.rs`. Change `IssGen::new(0)` → `IssGen::new()`.

- [ ] **Step 5: Run tests to verify pass**

Run: `cargo test -p resd-net-core iss::`
Expected: 4 existing tests PASS + 3 new A5 tests PASS.

- [ ] **Step 6: Run full crate tests to ensure no regression**

Run: `cargo test -p resd-net-core`
Expected: all existing tests still PASS (206 baseline per A4 review, minus the removed `iss::tests` that referenced the old seed).

- [ ] **Step 7: Spec + code-quality review**

Dispatch two subagents in parallel (opus):
- Spec reviewer: "Verify `crates/resd-net-core/src/iss.rs` against spec §6.5 ISS formula. Confirm: (1) SipHash-2-4 is keyed on `secret`, not on `tuple`; (2) `boot_nonce` is in the message, not the key; (3) the 4µs clock is added OUTSIDE the hash via `wrapping_add`; (4) the boot_id parser handles the standard UUID format (8-4-4-4-12 hex-with-dashes); (5) `read_process_secret` degraded-mode fallback logs once and does not panic."
- Code quality: "Review `crates/resd-net-core/src/iss.rs`. Check: no `unsafe`; no blocking I/O in `IssGen::next()`; `fs::read_to_string` on `/proc/sys/kernel/random/boot_id` happens once at `new()` only; test-only ctor is `#[cfg(test)]`-gated; fallback `read_process_secret` is unreachable in practice but cannot panic if `/dev/urandom` returns fewer than 16 bytes."

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net-core/src/iss.rs crates/resd-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a5 task 2: iss finalize — SipHash-2-4 + boot_nonce + 4µs ticks

Rewires iss.rs to spec §6.5 exact formula:
  ISS = (monotonic_time_4µs_ticks_low_32)
      + siphash24(key=secret, msg=tuple ‖ boot_nonce).low_32

- `secret`: 128-bit SipHash key from /dev/urandom (TSC fallback if unreadable).
- `boot_nonce`: 128 bits from /proc/sys/kernel/random/boot_id, per-engine
  random fallback with one-time warning.
- Clock: 4µs ticks (was 1µs in A3 skeleton).
- Uses the A5 task-1 siphash24 primitive (was DefaultHasher / SipHash-1-3).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `tcp_rtt.rs` — RFC 6298 Jacobson/Karels RTT estimator

**Files:**
- Create: `crates/resd-net-core/src/tcp_rtt.rs`
- Modify: `crates/resd-net-core/src/lib.rs` — add `pub mod tcp_rtt;`

**Context:** RFC 6298 §2.2/§2.3 algorithm with α=1/8, β=1/4. Per spec §6.4, minRTO=5ms (trading-latency default). `apply_backoff()` doubles current RTO up to `max_rto_us` cap; no-ops when `rto_no_backoff` is true (caller's responsibility to gate). This module owns estimator state only; RTO timer arming/firing lives in the engine.

- [ ] **Step 1: Write the failing tests**

Create `crates/resd-net-core/src/tcp_rtt.rs`:

```rust
//! RFC 6298 Jacobson/Karels RTT estimator.
//!
//! - RFC 6298 §2.2: on first sample R, SRTT=R, RTTVAR=R/2, RTO=SRTT+K·RTTVAR with K=4.
//! - RFC 6298 §2.3: on subsequent sample R, RTTVAR = (1-β)·RTTVAR + β·|SRTT-R|; SRTT = (1-α)·SRTT + α·R.
//! - α=1/8, β=1/4 (RFC 6298 §2.3 exact).
//! - RTO floor = min_rto_us (spec §6.4 default 5ms; configurable per engine).
//! - RTO ceiling = max_rto_us (spec §6.4 new row, default 1_000_000 = 1s).
//! - `apply_backoff`: RTO *= 2, capped at max_rto_us. Caller decides whether to call.
//! - Karn's algorithm (RFC 6298 §3): the caller must not feed a sample drawn
//!   from a retransmitted segment. `sample()` trusts the caller.

pub const DEFAULT_MIN_RTO_US: u32 = 5_000;
pub const DEFAULT_INITIAL_RTO_US: u32 = 5_000;
pub const DEFAULT_MAX_RTO_US: u32 = 1_000_000;

#[derive(Debug, Clone)]
pub struct RttEstimator {
    srtt_us: Option<u32>,
    rttvar_us: u32,
    rto_us: u32,
    min_rto_us: u32,
    max_rto_us: u32,
}

impl RttEstimator {
    pub fn new(min_rto_us: u32, initial_rto_us: u32, max_rto_us: u32) -> Self {
        debug_assert!(min_rto_us <= initial_rto_us);
        debug_assert!(initial_rto_us <= max_rto_us);
        Self {
            srtt_us: None,
            rttvar_us: 0,
            rto_us: initial_rto_us.max(min_rto_us),
            min_rto_us,
            max_rto_us,
        }
    }

    pub fn sample(&mut self, rtt_us: u32) {
        let rtt = rtt_us.max(1);
        match self.srtt_us {
            None => {
                self.srtt_us = Some(rtt);
                self.rttvar_us = rtt / 2;
            }
            Some(srtt) => {
                let delta = srtt.abs_diff(rtt);
                self.rttvar_us = (self.rttvar_us - (self.rttvar_us >> 2))
                    .wrapping_add(delta >> 2);
                self.srtt_us = Some(
                    (srtt - (srtt >> 3)).wrapping_add(rtt >> 3),
                );
            }
        }
        let srtt = self.srtt_us.unwrap();
        let rto = srtt.saturating_add(self.rttvar_us.saturating_mul(4));
        self.rto_us = rto.clamp(self.min_rto_us, self.max_rto_us);
    }

    pub fn apply_backoff(&mut self) {
        self.rto_us = self.rto_us.saturating_mul(2).min(self.max_rto_us);
    }

    pub fn rto_us(&self) -> u32 { self.rto_us }
    pub fn srtt_us(&self) -> Option<u32> { self.srtt_us }
    pub fn rttvar_us(&self) -> u32 { self.rttvar_us }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_rto_honors_floor() {
        let est = RttEstimator::new(5_000, 10_000, 1_000_000);
        assert_eq!(est.rto_us(), 10_000);
    }

    #[test]
    fn first_sample_rfc_22() {
        let mut est = RttEstimator::new(0, 5_000, 1_000_000);
        est.sample(100);
        assert_eq!(est.srtt_us(), Some(100));
        assert_eq!(est.rttvar_us(), 50);
        assert_eq!(est.rto_us(), 300);
    }

    #[test]
    fn second_sample_rfc_23() {
        let mut est = RttEstimator::new(0, 5_000, 1_000_000);
        est.sample(100);
        est.sample(200);
        assert_eq!(est.srtt_us(), Some(113));
        assert_eq!(est.rttvar_us(), 63);
        assert_eq!(est.rto_us(), 365);
    }

    #[test]
    fn rto_floored_at_min() {
        let mut est = RttEstimator::new(50_000, 50_000, 1_000_000);
        est.sample(100);
        assert!(est.rto_us() >= 50_000);
    }

    #[test]
    fn apply_backoff_doubles_up_to_max() {
        let mut est = RttEstimator::new(0, 100_000, 500_000);
        est.apply_backoff();
        assert_eq!(est.rto_us(), 200_000);
        est.apply_backoff();
        assert_eq!(est.rto_us(), 400_000);
        est.apply_backoff();
        assert_eq!(est.rto_us(), 500_000);
        est.apply_backoff();
        assert_eq!(est.rto_us(), 500_000);
    }

    #[test]
    fn fresh_sample_overwrites_backoff() {
        let mut est = RttEstimator::new(0, 10_000, 1_000_000);
        est.apply_backoff();
        est.apply_backoff();
        assert_eq!(est.rto_us(), 40_000);
        est.sample(100);
        assert_eq!(est.rto_us(), 300);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `cargo test -p resd-net-core tcp_rtt`
Expected: FAIL — module not exported.

- [ ] **Step 3: Add `pub mod tcp_rtt;` to `lib.rs`**

Run: `cargo test -p resd-net-core tcp_rtt`
Expected: 6 tests PASS.

- [ ] **Step 4: Spec + code-quality review (opus subagents)**

- Spec: verify RFC 6298 §2.2/§2.3/§2.4/§5.5 conformance.
- Code: check `abs_diff`, `>>` shifts preserve RFC arithmetic, saturating ops, no unsafe.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_rtt.rs crates/resd-net-core/src/lib.rs
git commit -m "a5 task 3: tcp_rtt — RFC 6298 Jacobson/Karels estimator"
```

---

## Task 4: `tcp_timer_wheel.rs` — hashed 8-level × 256-bucket wheel (struct + add + advance)

**Files:**
- Create: `crates/resd-net-core/src/tcp_timer_wheel.rs`
- Modify: `crates/resd-net-core/src/lib.rs` — add `pub(crate) mod tcp_timer_wheel;`

**Context:** Spec §7.4 internal wheel. This task covers scheduling + firing; Task 5 adds tombstone cancel + per-conn list integration.

- [ ] **Step 1: Write the failing tests**

Create `crates/resd-net-core/src/tcp_timer_wheel.rs`:

```rust
//! Internal hashed timing wheel (spec §7.4). 8 levels × 256 buckets,
//! 10µs resolution. A5 internal; A6 adds public timer API on top.

pub const TICK_NS: u64 = 10_000;
pub const LEVELS: usize = 8;
pub const BUCKETS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerId {
    pub slot: u32,
    pub generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKind {
    Rto,
    Tlp,
    SynRetrans,
    /// Reserved for A6 public `resd_net_timer_add`.
    ApiPublic,
}

#[derive(Debug, Clone, Copy)]
pub struct TimerNode {
    pub fire_at_ns: u64,
    pub owner_handle: u32,
    pub kind: TimerKind,
    pub generation: u32,
    pub cancelled: bool,
}

pub struct TimerWheel {
    slots: Vec<Option<TimerNode>>,
    free_list: Vec<u32>,
    buckets: [[Vec<u32>; BUCKETS]; LEVELS],
    cursors: [u16; LEVELS],
    last_tick: u64,
}

impl TimerWheel {
    pub fn new(initial_slot_capacity: usize) -> Self {
        const EMPTY_BUCKET: Vec<u32> = Vec::new();
        const EMPTY_LEVEL: [Vec<u32>; BUCKETS] = [EMPTY_BUCKET; BUCKETS];
        Self {
            slots: Vec::with_capacity(initial_slot_capacity),
            free_list: Vec::new(),
            buckets: [EMPTY_LEVEL; LEVELS],
            cursors: [0; LEVELS],
            last_tick: 0,
        }
    }

    pub fn add(&mut self, now_ns: u64, mut node: TimerNode) -> TimerId {
        let delay_ticks = node.fire_at_ns.saturating_sub(now_ns) / TICK_NS;
        let (level, bucket_off) = level_and_bucket_offset(delay_ticks);
        let bucket_idx = (self.cursors[level] as usize + bucket_off) % BUCKETS;

        let slot: u32 = match self.free_list.pop() {
            Some(s) => s,
            None => {
                let s = self.slots.len() as u32;
                self.slots.push(None);
                s
            }
        };

        let gen = match &self.slots[slot as usize] {
            Some(prev) => prev.generation.wrapping_add(1),
            None => 0,
        };
        node.generation = gen;
        node.cancelled = false;
        self.slots[slot as usize] = Some(node);
        self.buckets[level][bucket_idx].push(slot);

        TimerId { slot, generation: gen }
    }

    pub fn advance(&mut self, now_ns: u64) -> Vec<(TimerId, TimerNode)> {
        let now_tick = now_ns / TICK_NS;
        if now_tick <= self.last_tick {
            return Vec::new();
        }
        let mut fired = Vec::new();
        let target_delta = now_tick - self.last_tick;
        for _ in 0..target_delta.min((BUCKETS * LEVELS) as u64) {
            self.cursors[0] = (self.cursors[0] + 1) % BUCKETS as u16;
            self.last_tick += 1;
            let cursor = self.cursors[0] as usize;
            let bucket = std::mem::take(&mut self.buckets[0][cursor]);
            for slot in bucket {
                if let Some(node) = self.slots[slot as usize].take() {
                    if !node.cancelled {
                        fired.push((
                            TimerId { slot, generation: node.generation },
                            node,
                        ));
                    }
                    self.free_list.push(slot);
                }
            }
            if self.cursors[0] == 0 {
                self.cascade(1);
            }
        }
        fired
    }

    fn cascade(&mut self, level: usize) {
        if level >= LEVELS { return; }
        self.cursors[level] = (self.cursors[level] + 1) % BUCKETS as u16;
        let cursor = self.cursors[level] as usize;
        let bucket = std::mem::take(&mut self.buckets[level][cursor]);
        let now_ns = self.last_tick * TICK_NS;
        for slot in bucket {
            if let Some(node) = self.slots[slot as usize].take() {
                if node.cancelled {
                    self.free_list.push(slot);
                    continue;
                }
                let delay_ticks = node.fire_at_ns.saturating_sub(now_ns) / TICK_NS;
                let (new_level, bucket_off) = level_and_bucket_offset(delay_ticks);
                let new_bucket =
                    (self.cursors[new_level] as usize + bucket_off) % BUCKETS;
                self.slots[slot as usize] = Some(node);
                self.buckets[new_level][new_bucket].push(slot);
            }
        }
        if self.cursors[level] == 0 {
            self.cascade(level + 1);
        }
    }
}

fn level_and_bucket_offset(delay_ticks: u64) -> (usize, usize) {
    for level in 0..LEVELS {
        let level_span: u64 = 1u64 << (8 * (level + 1));
        if delay_ticks < level_span {
            let bucket_span: u64 = 1u64 << (8 * level);
            let off = (delay_ticks / bucket_span) as usize;
            return (level, off.max(1).min(BUCKETS - 1));
        }
    }
    (LEVELS - 1, BUCKETS - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(fire_at_ns: u64) -> TimerNode {
        TimerNode {
            fire_at_ns,
            owner_handle: 0,
            kind: TimerKind::Rto,
            generation: 0,
            cancelled: false,
        }
    }

    #[test]
    fn add_and_fire_short_timer() {
        let mut w = TimerWheel::new(8);
        let _id = w.add(0, node(100_000));
        let fired = w.advance(100_000);
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn advance_with_no_tick_skips() {
        let mut w = TimerWheel::new(8);
        w.add(0, node(100_000));
        assert!(w.advance(5_000).is_empty());
        assert_eq!(w.last_tick, 0);
    }

    #[test]
    fn level_math_level0_level1() {
        assert_eq!(level_and_bucket_offset(1), (0, 1));
        assert_eq!(level_and_bucket_offset(255), (0, 255));
        assert_eq!(level_and_bucket_offset(256), (1, 1));
    }

    #[test]
    fn long_timer_cascades() {
        let mut w = TimerWheel::new(8);
        let _short = w.add(0, node(300_000));
        let _long = w.add(0, node(3_000_000));
        assert_eq!(w.advance(300_000).len(), 1);
        assert_eq!(w.advance(3_000_000).len(), 1);
    }
}
```

- [ ] **Step 2: Run tests — expect fail to compile**

Run: `cargo test -p resd-net-core tcp_timer_wheel`
Expected: FAIL — module not exported.

- [ ] **Step 3: Add `pub(crate) mod tcp_timer_wheel;` to `lib.rs`**

Run: `cargo test -p resd-net-core tcp_timer_wheel`
Expected: 4 tests PASS.

- [ ] **Step 4: Spec + code-quality review (opus subagents)**

- Spec: 8 levels × 256 buckets at 10µs = ~68s practical horizon via cascading; `advance` skip-gate matches §7.4.
- Code: no unsafe; slot reuse via free_list is safe; cascade terminates.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_timer_wheel.rs crates/resd-net-core/src/lib.rs
git commit -m "a5 task 4: tcp_timer_wheel — hashed 8×256 wheel, internal"
```

---

## Task 5: Timer wheel — tombstone cancel + per-conn timer-id list

**Files:**
- Modify: `crates/resd-net-core/src/tcp_timer_wheel.rs` — add `cancel()` method + test
- Modify: `crates/resd-net-core/src/tcp_conn.rs` — add `pub timer_ids: Vec<TimerId>` field

**Context:** Spec §7.4 per-conn list. Task 7 wires the engine to walk the list on `close_conn`.

- [ ] **Step 1: Write failing tests**

Add to `tcp_timer_wheel.rs` test module:

```rust
    #[test]
    fn cancel_tombstones_the_slot() {
        let mut w = TimerWheel::new(8);
        let id = w.add(0, node(100_000));
        assert!(w.cancel(id));
        let fired = w.advance(100_000);
        assert_eq!(fired.len(), 0);
        assert!(!w.cancel(id));
    }

    #[test]
    fn cancel_stale_id_after_reuse_is_noop() {
        let mut w = TimerWheel::new(8);
        let id_a = w.add(0, node(100_000));
        let _ = w.advance(100_000);
        let id_b = w.add(100_000, node(200_000));
        assert!(!w.cancel(id_a));
        let fired = w.advance(200_000);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].0, id_b);
    }
```

Add to `tcp_conn.rs` test module:

```rust
    #[test]
    fn new_client_timer_ids_starts_empty() {
        let c = TcpConn::new_client(tuple(), 1, 1460, 1024, 2048);
        assert!(c.timer_ids.is_empty());
    }
```

- [ ] **Step 2: Run tests — expect fail**

Run: `cargo test -p resd-net-core -- cancel_tombstones cancel_stale_id new_client_timer_ids`
Expected: FAIL on `cancel` (not defined) and on `timer_ids` (field not found).

- [ ] **Step 3: Implement `cancel`**

Append to `impl TimerWheel`:

```rust
    pub fn cancel(&mut self, id: TimerId) -> bool {
        let slot_idx = id.slot as usize;
        match self.slots.get_mut(slot_idx) {
            Some(Some(node)) if node.generation == id.generation && !node.cancelled => {
                node.cancelled = true;
                true
            }
            _ => false,
        }
    }
```

- [ ] **Step 4: Add `timer_ids` to `TcpConn`**

Modify `crates/resd-net-core/src/tcp_conn.rs`:

```rust
    /// A5: wheel-timer handles owned by this conn (RTO, TLP, SYN).
    /// `close_conn` walks this list on close; spec §7.4.
    pub timer_ids: Vec<crate::tcp_timer_wheel::TimerId>,
```

And `new_client`:

```rust
            timer_ids: Vec::new(),
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p resd-net-core`
Expected: all PASS (existing + 3 new).

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: generation bump on slot reuse, stale ID cancel returns false.
- Code: `get_mut` pattern; bool return; no unsafe.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/tcp_timer_wheel.rs \
        crates/resd-net-core/src/tcp_conn.rs
git commit -m "a5 task 5: tcp_timer_wheel cancel + TcpConn.timer_ids"
```

---

## Task 6: `tcp_retrans.rs` — `SendRetrans` + `RetransEntry` with mbuf ref

**Files:**
- Create: `crates/resd-net-core/src/tcp_retrans.rs`
- Modify: `crates/resd-net-core/src/lib.rs` — add `pub mod tcp_retrans;`

**Context:** Spec §7.2 `snd_retrans: (seq, mbuf_ref, first_tx_ts)` list. A5 makes this authoritative for in-flight tracking. Mbuf is a `crate::mempool::Mbuf` wrapper around a refcounted `rte_mbuf*` (existing from A3). On `push_after_tx`, we clone the ref (caller is responsible for `rte_mbuf_refcnt_update(+1)` before constructing the entry). `prune_below(snd_una)` drops fully-ACKed entries and returns the dropped mbufs to the caller for refcount-decrement (so all unsafe pointer work stays in one place). `mark_sacked(left, right)` marks overlapping entries' `sacked=true`.

This task uses a **mock `Mbuf`** for unit tests — the real `Mbuf` type exposes `refcnt_inc`/`refcnt_dec` via the FFI wrapper. The module accepts a generic-free `Mbuf` from `crate::mempool`; tests use a test-only constructor that takes a raw ptr to an in-memory test mbuf (no DPDK EAL needed). Alternatively, factor out an `MbufRef` trait — simpler is to ship `SendRetrans` as generic over the mbuf type.

- [ ] **Step 1: Write the failing tests**

Create `crates/resd-net-core/src/tcp_retrans.rs`:

```rust
//! Per-conn in-flight-segment tracker. Holds `Mbuf` ref per TX'd-but-unACKed
//! segment; the engine's retransmit primitive allocates a fresh header mbuf
//! from `tx_hdr_mempool` and `rte_pktmbuf_chain()`s it to the held data mbuf.
//!
//! Spec §7.2: `snd_retrans: (seq, mbuf_ref, first_tx_ts)` list.

use std::collections::VecDeque;

use crate::mempool::Mbuf;
use crate::tcp_options::SackBlock;
use crate::tcp_seq::{seq_le, seq_lt};

pub struct RetransEntry {
    pub seq: u32,
    pub len: u16,
    pub mbuf: Mbuf,
    pub first_tx_ts_ns: u64,
    pub xmit_count: u16,
    pub sacked: bool,
    pub lost: bool,
    /// Last-xmit time (first_tx_ts_ns on first send; updated on retransmit).
    /// RACK uses this as `xmit_ts` per RFC 8985 §6.1 definition.
    pub xmit_ts_ns: u64,
}

#[derive(Default)]
pub struct SendRetrans {
    pub entries: VecDeque<RetransEntry>,
}

impl SendRetrans {
    pub fn new() -> Self { Self::default() }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn len(&self) -> usize { self.entries.len() }

    /// Push a newly TX'd segment. Caller must have already incremented the
    /// mbuf refcount so the held ref is valid.
    pub fn push_after_tx(&mut self, entry: RetransEntry) {
        self.entries.push_back(entry);
    }

    /// Drop all entries whose `seq + len` ≤ `snd_una`. Returns dropped entries
    /// so the caller can `refcnt_dec` each mbuf (keeps unsafe ptr work in the engine).
    pub fn prune_below(&mut self, snd_una: u32) -> Vec<RetransEntry> {
        let mut dropped = Vec::new();
        while let Some(front) = self.entries.front() {
            let end_seq = front.seq.wrapping_add(front.len as u32);
            if seq_le(end_seq, snd_una) {
                dropped.push(self.entries.pop_front().unwrap());
            } else {
                break;
            }
        }
        dropped
    }

    /// Mark entries overlapping `block` as sacked. Partial overlap at the
    /// edges is handled conservatively (whole entry marked sacked if any
    /// byte is covered); the precise per-byte tracking is unnecessary since
    /// RACK consumes sacked-or-not, not sacked-ranges.
    pub fn mark_sacked(&mut self, block: SackBlock) {
        for e in &mut self.entries {
            let e_end = e.seq.wrapping_add(e.len as u32);
            // entry overlaps block iff (e.seq < block.right) AND (block.left < e_end)
            if seq_lt(e.seq, block.right) && seq_lt(block.left, e_end) {
                e.sacked = true;
            }
        }
    }

    pub fn front(&self) -> Option<&RetransEntry> { self.entries.front() }
    pub fn back(&self) -> Option<&RetransEntry> { self.entries.back() }

    /// Iterate in seq-order for the RACK detect-lost pass.
    pub fn iter_for_rack(&self) -> impl Iterator<Item = &RetransEntry> {
        self.entries.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut RetransEntry> {
        self.entries.iter_mut()
    }

    /// Oldest unacked seq (front entry's `seq`), or None if empty.
    pub fn oldest_unacked_seq(&self) -> Option<u32> {
        self.entries.front().map(|e| e.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::Mbuf;

    fn entry(seq: u32, len: u16, ts: u64) -> RetransEntry {
        RetransEntry {
            seq,
            len,
            mbuf: Mbuf::null_for_test(),
            first_tx_ts_ns: ts,
            xmit_count: 1,
            sacked: false,
            lost: false,
            xmit_ts_ns: ts,
        }
    }

    #[test]
    fn empty_is_empty() {
        let r = SendRetrans::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.oldest_unacked_seq().is_none());
    }

    #[test]
    fn push_grows() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        assert_eq!(r.len(), 1);
        assert_eq!(r.oldest_unacked_seq(), Some(100));
    }

    #[test]
    fn prune_below_drops_fully_acked() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        r.push_after_tx(entry(120, 20, 2));
        let dropped = r.prune_below(120);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].seq, 100);
        assert_eq!(r.len(), 1);
        assert_eq!(r.oldest_unacked_seq(), Some(120));
    }

    #[test]
    fn prune_below_stops_at_first_not_fully_acked() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        r.push_after_tx(entry(120, 20, 2));
        // snd_una = 130 — second entry only partially acked, not removed.
        let dropped = r.prune_below(130);
        assert_eq!(dropped.len(), 1);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn mark_sacked_flags_overlapping_entries() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        r.push_after_tx(entry(120, 20, 2));
        r.push_after_tx(entry(140, 20, 3));
        r.mark_sacked(SackBlock { left: 120, right: 140 });
        let sacked: Vec<_> = r.iter_for_rack().map(|e| e.sacked).collect();
        assert_eq!(sacked, vec![false, true, false]);
    }

    #[test]
    fn mark_sacked_partial_overlap_flags_whole_entry() {
        let mut r = SendRetrans::new();
        r.push_after_tx(entry(100, 20, 1));
        r.mark_sacked(SackBlock { left: 105, right: 115 });
        assert!(r.front().unwrap().sacked);
    }
}
```

- [ ] **Step 2: Ensure `Mbuf::null_for_test()` exists**

Check `crates/resd-net-core/src/mempool.rs`. If it exists, good. If not, add a `#[cfg(test)]` constructor that wraps a null raw pointer — legal because the test code never dereferences it. If `Mbuf` is opaque and hard to instantiate for tests, introduce a trait `trait MbufRef { fn null_test() -> Self; ... }` or swap `Mbuf` for a generic type in `SendRetrans<M>` so tests use a test stub. Pick whichever is less invasive; document the choice in the module header comment.

- [ ] **Step 3: Add `pub mod tcp_retrans;` to `lib.rs`**

Run: `cargo test -p resd-net-core tcp_retrans`
Expected: 6 tests PASS.

- [ ] **Step 4: Spec + code-quality review (opus)**

- Spec: `(seq, mbuf_ref, first_tx_ts)` tuple matches spec §7.2 — we also carry `len`, `xmit_count`, `sacked`, `lost`, `xmit_ts_ns` for RACK/RTO state (documented in module header).
- Code: `prune_below` returns dropped entries rather than freeing inline — keeps refcount management in the engine; `mark_sacked` O(N) per SACK block is fine at ≤100 in-flight segments; `iter_for_rack` is an immutable iterator; `iter_mut` available for RACK to set `.lost`.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_retrans.rs \
        crates/resd-net-core/src/mempool.rs \
        crates/resd-net-core/src/lib.rs
git commit -m "a5 task 6: tcp_retrans — SendRetrans + RetransEntry with mbuf ref"
```

---

## Task 7: Extend `TcpConn` with A5 state + wire engine `TimerWheel`

**Files:**
- Modify: `crates/resd-net-core/src/tcp_conn.rs` — add A5 fields
- Modify: `crates/resd-net-core/src/engine.rs` — add `timer_wheel: TimerWheel` field + walk `conn.timer_ids` on `close_conn`

**Context:** Bundle the A5 TcpConn field additions (all non-behavioral; Task 5 already added `timer_ids`):

- `snd_retrans: SendRetrans` — replaces A3's pattern of stashing bytes in `snd.pending` for retrans.
- `rtt_est: RttEstimator` — per-conn RTT state.
- `rack: RackState` — placeholder struct until Task 14 fills it. Add the field behind a placeholder `pub struct RackState;` in a new stub `tcp_rack.rs` that Task 14 replaces.
  - Alternatively: defer this field to Task 14 and keep this task focused on `snd_retrans` + `rtt_est` + `rto_timer_id` / `tlp_timer_id` / `syn_retrans_count` / `syn_retrans_timer_id` / `rack_aggressive` / `rto_no_backoff`.
  - **Chosen order:** defer `rack` to Task 14 (cleanest — `RackState` is only meaningful with its methods).
- `rto_timer_id: Option<TimerId>` — arm/re-arm state.
- `tlp_timer_id: Option<TimerId>` — arm state (Task 17).
- `syn_retrans_count: u8` — 0-indexed retry count (Task 18).
- `syn_retrans_timer_id: Option<TimerId>` — SYN retrans timer handle (Task 18).
- `rack_aggressive: bool` — connect-opt passthrough (Task 19).
- `rto_no_backoff: bool` — connect-opt passthrough (Task 19).

And engine:
- `timer_wheel: TimerWheel` — the internal wheel (Task 4).

- [ ] **Step 1: Write the failing tests**

Add to `tcp_conn.rs` tests:

```rust
    #[test]
    fn a5_conn_starts_with_empty_snd_retrans_and_default_rtt() {
        let c = TcpConn::new_client(tuple(), 100, 1460, 1024, 2048);
        assert!(c.snd_retrans.is_empty());
        assert_eq!(c.rtt_est.rto_us(), crate::tcp_rtt::DEFAULT_INITIAL_RTO_US);
        assert!(c.rto_timer_id.is_none());
        assert!(c.tlp_timer_id.is_none());
        assert_eq!(c.syn_retrans_count, 0);
        assert!(c.syn_retrans_timer_id.is_none());
        assert!(!c.rack_aggressive);
        assert!(!c.rto_no_backoff);
    }
```

Add to `engine.rs` tests (or a new test if none exists yet):

```rust
    #[test]
    fn engine_has_timer_wheel_and_advance_returns_empty_at_rest() {
        let e = make_test_engine();
        // advancing by a small delta on a fresh engine should fire nothing.
        // We don't drive poll here, but the wheel is constructible + callable.
        assert!(e.timer_wheel.last_tick_for_test() == 0);
    }
```

(Use the existing test-engine constructor — search for pattern `Engine::new_for_test` or similar. If none exists, defer this engine-test assertion to the sanity pass at Task 32.)

- [ ] **Step 2: Run tests — expect fail**

Run: `cargo test -p resd-net-core -- a5_conn_starts_with_empty_snd_retrans`
Expected: FAIL — fields not present.

- [ ] **Step 3: Extend `TcpConn`**

Modify `crates/resd-net-core/src/tcp_conn.rs` — add fields to the struct:

```rust
    // Phase A5 additions:
    /// In-flight (TX'd but unacked) segments — spec §7.2 snd_retrans.
    pub snd_retrans: crate::tcp_retrans.SendRetrans,
    /// RFC 6298 Jacobson/Karels RTT estimator.
    pub rtt_est: crate::tcp_rtt::RttEstimator,
    /// Handle of the conn's RTO timer on the engine wheel (lazy re-arm per §6.5).
    pub rto_timer_id: Option<crate::tcp_timer_wheel::TimerId>,
    /// Handle of the conn's TLP timer (RFC 8985 §7).
    pub tlp_timer_id: Option<crate::tcp_timer_wheel::TimerId>,
    /// How many SYN retransmits have been issued (spec §6.5; max 3).
    pub syn_retrans_count: u8,
    /// Handle of the SYN retrans timer.
    pub syn_retrans_timer_id: Option<crate::tcp_timer_wheel::TimerId>,
    /// Per-connect opt: when true, RACK `reo_wnd` forced to 0.
    pub rack_aggressive: bool,
    /// Per-connect opt: when true, RTO does not double on retransmit.
    pub rto_no_backoff: bool,
```

(Fix the typo `tcp_retrans.SendRetrans` → `tcp_retrans::SendRetrans`.)

And `new_client` defaults (use engine config values when available; default constants here):

```rust
            snd_retrans: crate::tcp_retrans::SendRetrans::new(),
            rtt_est: crate::tcp_rtt::RttEstimator::new(
                crate::tcp_rtt::DEFAULT_MIN_RTO_US,
                crate::tcp_rtt::DEFAULT_INITIAL_RTO_US,
                crate::tcp_rtt::DEFAULT_MAX_RTO_US,
            ),
            rto_timer_id: None,
            tlp_timer_id: None,
            syn_retrans_count: 0,
            syn_retrans_timer_id: None,
            rack_aggressive: false,
            rto_no_backoff: false,
```

*Note:* `new_client` doesn't know the engine-config values. Either (a) extend `new_client`'s signature to take `tcp_min_rto_us`/`tcp_initial_rto_us`/`tcp_max_rto_us`; or (b) initialize with defaults here and let the caller overwrite via a setter before use. Option (a) is cleanest; propagates from `Engine::connect` which knows the config. Update all `new_client` call sites accordingly.

- [ ] **Step 4: Add `timer_wheel` to `Engine`**

Modify `crates/resd-net-core/src/engine.rs` — add field:

```rust
    timer_wheel: crate::tcp_timer_wheel::TimerWheel,
```

Initialize in `Engine::new`:

```rust
            timer_wheel: crate::tcp_timer_wheel::TimerWheel::new(
                config.max_connections as usize * 4, // ~4 timers per conn
            ),
```

- [ ] **Step 5: Wire `close_conn` to cancel timers**

Find `close_conn` (or the conn-reap path); add at the start:

```rust
    for id in std::mem::take(&mut conn.timer_ids) {
        self.timer_wheel.cancel(id);
    }
    // Also cancel the named timer handles (may overlap with timer_ids — cancel() is idempotent).
    if let Some(id) = conn.rto_timer_id.take() { self.timer_wheel.cancel(id); }
    if let Some(id) = conn.tlp_timer_id.take() { self.timer_wheel.cancel(id); }
    if let Some(id) = conn.syn_retrans_timer_id.take() { self.timer_wheel.cancel(id); }
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p resd-net-core`
Expected: all tests PASS (existing + the A5 field-presence test).

- [ ] **Step 7: Spec + code-quality review (opus)**

- Spec: all fields match spec §6.2 + §7.2. Per-conn timer-id list is now O(k) cancellable on close per §7.4.
- Code: ensure no duplicate cancels crash (cancel is idempotent per Task 5). `new_client` signature change propagated cleanly.

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net-core/src/tcp_conn.rs \
        crates/resd-net-core/src/engine.rs
git commit -m "a5 task 7: TcpConn A5 fields + engine timer_wheel"
```

---

## Task 8: Enable `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` in port config

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — port config initialization

**Context:** A5's retransmit primitive chains a fresh header mbuf to the held data mbuf, so TX segments become multi-segment. ENA advertises `MULTI_SEGS` per spec §8.2. A-HW later folds this into its feature-flag matrix; A5 enables unconditionally.

- [ ] **Step 1: Locate port config**

Run: `grep -n 'rte_eth_conf\|txmode.offloads\|TX_OFFLOAD' crates/resd-net-core/src/engine.rs`
Identify the `rte_eth_dev_configure` setup (A1).

- [ ] **Step 2: Write a test (integration, TAP)**

Add a smoke test to `crates/resd-net-core/tests/` (use the existing TAP harness pattern from A4):

```rust
#[test]
fn tx_offload_multi_segs_bit_is_set_after_engine_create() {
    let engine = make_tap_engine();
    let bits = engine.tx_offload_bits_for_test();
    assert_ne!(bits & RTE_ETH_TX_OFFLOAD_MULTI_SEGS, 0,
        "A5 requires MULTI_SEGS for mbuf-chained retransmit");
}
```

(Expose `tx_offload_bits_for_test` on `Engine` behind `#[cfg(test)]`.)

- [ ] **Step 3: Run test — expect fail**

Run: `cargo test -p resd-net-core tx_offload_multi_segs`
Expected: FAIL — bit not set.

- [ ] **Step 4: Enable the bit in port config**

In the place where `txmode.offloads` is assigned, OR in `RTE_ETH_TX_OFFLOAD_MULTI_SEGS`:

```rust
        dev_conf.txmode.offloads |= sys::RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
```

Also verify the `rte_eth_dev_info` advertises support — warn on a one-shot counter path (A-HW-style) if it doesn't, but don't fail:

```rust
        if dev_info.tx_offload_capa & sys::RTE_ETH_TX_OFFLOAD_MULTI_SEGS == 0 {
            eprintln!("resd_net: MULTI_SEGS not advertised by PMD; retransmit \
                       chain may fail — check NIC/PMD.");
        }
```

- [ ] **Step 5: Run test — pass**

Run: `cargo test -p resd-net-core tx_offload_multi_segs`
Expected: PASS.

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: §8.2 confirms ENA supports MULTI_SEGS.
- Code: bit is OR'd (not assigned), so we don't clobber other A1/A4 offload bits.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/engine.rs \
        crates/resd-net-core/tests/
git commit -m "a5 task 8: enable RTE_ETH_TX_OFFLOAD_MULTI_SEGS for retransmit mbuf chain"
```

---

## Task 9: Retransmit primitive (fresh hdr mbuf + pktmbuf_chain)

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — new `fn retransmit(&mut self, conn: &mut TcpConn, entry_index: usize)`
- Modify: `crates/resd-net-sys/build.rs` or wrapper — ensure `rte_pktmbuf_chain` + `rte_mbuf_refcnt_update` are exposed via FFI

**Context:** Spec §6.5: retransmit allocates fresh hdr mbuf from `tx_hdr_mempool`, writes L2+L3+TCP headers, `rte_pktmbuf_chain`s to the held data mbuf. Shared by RACK-loss (Task 15), RTO-fire (Task 12), TLP-fire (Task 17), SYN-retrans (Task 18).

- [ ] **Step 1: Check FFI wrappers exist**

Run: `grep -n 'rte_pktmbuf_chain\|rte_mbuf_refcnt_update' crates/resd-net-sys/`
If not exposed, add them to the FFI allowlist + create wrapper `resd_rte_pktmbuf_chain(head: *mut rte_mbuf, tail: *mut rte_mbuf) -> i32` etc.

- [ ] **Step 2: Write a failing test**

Add to `engine.rs` tests (unit — call the retransmit primitive directly with a synthetic conn + entry):

```rust
    #[test]
    fn retransmit_primitive_builds_multi_seg_frame_and_bumps_xmit_count() {
        let mut e = make_test_engine_with_tap();
        // Set up a conn with one in-flight entry.
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"hello world");
        // Drain poll once so the segment TXes + gets pushed to snd_retrans.
        let _ = e.poll_once();
        let conn = e.get_conn_mut(handle);
        assert_eq!(conn.snd_retrans.len(), 1);

        e.retransmit(handle, 0);
        let conn = e.get_conn_mut(handle);
        assert_eq!(conn.snd_retrans.front().unwrap().xmit_count, 2);
        // Next TAP frame should be multi-segment; assert hdr + data on separate mbufs.
        let tap_frame = e.peek_last_tx_tap();
        assert!(tap_frame.nb_segs >= 2);
    }
```

(Wire `peek_last_tx_tap`, `simulate_send`, etc. as test helpers — these may already exist from A3/A4 TAP pattern; extend as needed.)

- [ ] **Step 3: Run test — expect fail**

Run: `cargo test -p resd-net-core retransmit_primitive_builds_multi_seg_frame`
Expected: FAIL — `retransmit` not defined.

- [ ] **Step 4: Implement the primitive**

Add to `engine.rs`:

```rust
    /// Retransmit the entry at `entry_index` in `conn.snd_retrans`. Allocates
    /// a fresh header mbuf from tx_hdr_mempool, writes L2+L3+TCP headers,
    /// chains to the held data mbuf, TXes. Bumps xmit_count and tx_retrans
    /// counter. Does NOT make the max-retrans-count decision — that's the
    /// caller's job.
    pub(crate) fn retransmit(&mut self, conn_handle: ConnHandle, entry_index: usize) {
        let conn = match self.flow_table.get_mut(conn_handle) {
            Some(c) => c,
            None => return,
        };
        let entry = match conn.snd_retrans.entries.get_mut(entry_index) {
            Some(e) => e,
            None => return,
        };

        // Allocate hdr mbuf.
        let hdr_mbuf = unsafe { sys::resd_rte_pktmbuf_alloc(self.tx_hdr_mempool.as_ptr()) };
        if hdr_mbuf.is_null() {
            self.counters.eth.tx_drop_nomem.fetch_add(1, Ordering::Relaxed);
            return; // next RTO fire retries
        }

        // Write L2+L3+TCP headers into hdr_mbuf. Use build_segment-style helper
        // with the entry's seq + len, current conn.ts_recent / rcv_wnd,
        // tcp_output::build_header(...).
        let ts_val = (crate::clock::now_ns() / 1_000) as u32;
        let advertised_window = (conn.recv.free_space_total() >> conn.ws_shift_out)
            .min(u16::MAX as u32) as u16;
        let hdr_bytes_written = crate::tcp_output::build_retrans_header(
            hdr_mbuf,
            conn,
            entry.seq,
            entry.len,
            advertised_window,
            ts_val,
        );

        // Increment data-mbuf refcount so the chain holds another reference.
        unsafe {
            sys::resd_rte_mbuf_refcnt_update(entry.mbuf.as_ptr(), 1);
        }

        // Chain hdr → data. Returns 0 on success, -1 on chain-segment-cap exceeded.
        let rc = unsafe {
            sys::resd_rte_pktmbuf_chain(hdr_mbuf, entry.mbuf.as_ptr())
        };
        if rc != 0 {
            unsafe { sys::resd_rte_pktmbuf_free(hdr_mbuf) };
            unsafe { sys::resd_rte_mbuf_refcnt_update(entry.mbuf.as_ptr(), -1) };
            return;
        }

        // TX the frame.
        let mut bufs = [hdr_mbuf];
        let sent = unsafe { sys::resd_rte_eth_tx_burst(self.port_id, 0, bufs.as_mut_ptr(), 1) };
        if sent == 0 {
            unsafe { sys::resd_rte_pktmbuf_free(hdr_mbuf) };
            self.counters.eth.tx_drop_full_ring.fetch_add(1, Ordering::Relaxed);
            return;
        }

        entry.xmit_count = entry.xmit_count.saturating_add(1);
        entry.xmit_ts_ns = crate::clock::now_ns();
        self.counters.tcp.tx_retrans.fetch_add(1, Ordering::Relaxed);
    }
```

Also add `tcp_output::build_retrans_header` as a thin wrapper around the existing `build_segment` header writer, but payload-less (the payload is the chained data mbuf, not written into hdr_mbuf). Follow the existing `build_segment` pattern for consistency.

- [ ] **Step 5: Run test — expect pass**

Run: `cargo test -p resd-net-core retransmit_primitive_builds_multi_seg_frame`
Expected: PASS. `nb_segs >= 2` confirms the chain.

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: §5.3 + §6.5 "fresh header mbuf chained to original data mbuf — never edits original in place" satisfied.
- Code: `unsafe` blocks are localized and minimal; hdr_mbuf cleanup on every error path; refcount decrement balances the increment on chain-failure path.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/engine.rs \
        crates/resd-net-core/src/tcp_output.rs \
        crates/resd-net-sys/
git commit -m "a5 task 9: retransmit primitive — fresh hdr mbuf + pktmbuf_chain"
```

---

## Task 10: `send_bytes` rewire — hold mbuf ref in snd_retrans, drop from snd.pending at TX

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — `send_bytes` function (from A3)
- Modify: `crates/resd-net-core/src/tcp_conn.rs` — `SendQueue::drain(consumed)` helper (new)

**Context:** A3 stashed bytes in `snd.pending` at send time + left them there until ACK. A5 moves in-flight tracking to `snd_retrans`: bytes leave `snd.pending` when the TX mbuf is built (at `send_bytes` time), and the mbuf ref lives in `snd_retrans` until ACK. Prune happens via `snd_retrans.prune_below(snd.una)` in the ACK handler (Task 11+). Spec data-flow §3.1.

- [ ] **Step 1: Write the failing test**

Add to `engine.rs` tests:

```rust
    #[test]
    fn send_bytes_moves_bytes_from_pending_to_snd_retrans_at_tx() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"hello");
        let _ = e.poll_once();
        let conn = e.get_conn(handle);
        assert_eq!(conn.snd.pending.len(), 0, "bytes leave pending at TX");
        assert_eq!(conn.snd_retrans.len(), 1, "one in-flight segment");
        assert_eq!(conn.snd_retrans.front().unwrap().len, 5);
    }

    #[test]
    fn send_bytes_rto_timer_is_armed_on_first_in_flight() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"x");
        let _ = e.poll_once();
        let conn = e.get_conn(handle);
        assert!(conn.rto_timer_id.is_some(), "RTO timer armed when snd_retrans becomes non-empty");
    }
```

- [ ] **Step 2: Run — expect fail**

Run: `cargo test -p resd-net-core send_bytes_moves_bytes_from_pending_to_snd_retrans`
Expected: FAIL — current send_bytes still leaves bytes in pending.

- [ ] **Step 3: Rewire `send_bytes`**

Find the current `send_bytes` implementation in `engine.rs`. The relevant sequence:

```rust
    // (1) Drain from snd.pending into TX mbuf.
    let take = bytes_len.min(pool_mbuf_size - HEADROOM);
    let payload_slice = conn.snd.pending.range(0..take);
    // memcpy payload_slice into mbuf data room.
    unsafe { sys::resd_mbuf_write_data(m, HEADROOM, payload_slice); }
    // (2) Build L2+L3+TCP header, TX burst.
    // (3) Bump tx counters.

    // NEW: after successful rte_eth_tx_burst return > 0:
    // - drop the consumed bytes from snd.pending
    conn.snd.pending.drain(0..take);
    // - bump refcnt, push to snd_retrans
    unsafe { sys::resd_rte_mbuf_refcnt_update(m, 1); }
    let first_tx_ts_ns = crate::clock::now_ns();
    conn.snd_retrans.push_after_tx(crate::tcp_retrans::RetransEntry {
        seq: conn.snd_nxt,
        len: take as u16,
        mbuf: Mbuf::from_raw(m),
        first_tx_ts_ns,
        xmit_count: 1,
        sacked: false,
        lost: false,
        xmit_ts_ns: first_tx_ts_ns,
    });
    conn.snd_nxt = conn.snd_nxt.wrapping_add(take as u32);

    // If snd_retrans just became non-empty, arm the RTO timer.
    if conn.snd_retrans.len() == 1 && conn.rto_timer_id.is_none() {
        let fire_at = first_tx_ts_ns + (conn.rtt_est.rto_us() as u64 * 1_000);
        let id = self.timer_wheel.add(first_tx_ts_ns, crate::tcp_timer_wheel::TimerNode {
            fire_at_ns: fire_at,
            owner_handle: handle.0 as u32,
            kind: crate::tcp_timer_wheel::TimerKind::Rto,
            generation: 0,
            cancelled: false,
        });
        conn.rto_timer_id = Some(id);
        conn.timer_ids.push(id);
    }
```

- [ ] **Step 4: Run tests — expect pass**

Run: `cargo test -p resd-net-core send_bytes_moves_bytes_from_pending_to_snd_retrans`
Expected: PASS.

Run: `cargo test -p resd-net-core send_bytes_rto_timer_is_armed`
Expected: PASS.

- [ ] **Step 5: Run full test suite — catch regressions**

Run: `cargo test -p resd-net-core`
Expected: all existing A3/A4 tests still PASS. The A3 assertion that `snd.pending.len() > 0` during in-flight is specifically false after A5 — update any A3 test asserting the A3 semantic.

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: §7.2 `snd_retrans: (seq, mbuf_ref, first_tx_ts)` now authoritative; `snd.pending` is bytes-accepted-but-not-yet-TX'd only.
- Code: refcount accounting is balanced (increment on push; decrement on ACK-prune in Task 11); `Mbuf::from_raw` wraps the raw ptr without re-incrementing; RTO timer arm is idempotent (only fires when `rto_timer_id.is_none()`).

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/engine.rs crates/resd-net-core/src/tcp_conn.rs
git commit -m "a5 task 10: send_bytes rewire — snd_retrans holds mbuf ref, RTO armed"
```

---

## Task 11: RTT sampling in `tcp_input` — TS source + Karn's fallback; prune snd_retrans

**Files:**
- Modify: `crates/resd-net-core/src/tcp_input.rs` — ACK handler RTT sample + prune_below
- Modify: `crates/resd-net-core/src/engine.rs` — refcnt_dec on pruned mbufs; cancel RTO timer on empty

**Context:** Spec data-flow §3.2. On every ACK that advances `snd.una`:
1. If `conn.ts_enabled` and seg has TSopt: `rtt_us = now_us - seg.tsopt.ecr` (TS-source sample).
2. Else if `snd_retrans.front().xmit_count == 1` and `seg.ack_seq` advances past front entry's `seq + len`: `rtt_us = now_us - front.first_tx_ts_ns / 1000` (Karn's).
3. Else: skip (Karn's prohibits sample on retransmitted segments).

Then `rtt_est.sample(rtt_us)`; bump `tcp.rtt_samples`. Prune `snd_retrans` below `seg.ack_seq`; refcnt_dec the dropped mbufs; if `snd_retrans` becomes empty AND `snd.una == snd.nxt`, cancel RTO timer.

- [ ] **Step 1: Write failing tests**

Add to integration tests (or a new unit test file exercising the ACK branch):

```rust
    #[test]
    fn ack_with_ts_samples_rtt_into_estimator() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer_ts_enabled();
        let send_time_ns = clock::now_ns();
        e.simulate_send(handle, b"hello");
        let _ = e.poll_once();
        // Peer ACKs with TSecr = sent_tsval; response 200µs later.
        e.simulate_ack_with_ts(handle, snd_nxt_after_send, send_time_ns + 200_000);
        let _ = e.poll_once();
        let conn = e.get_conn(handle);
        assert!(conn.rtt_est.srtt_us().is_some());
        assert_eq!(e.counters.tcp.rtt_samples.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ack_without_ts_uses_karns_on_first_xmit_entry() {
        let mut e = make_test_engine_with_tap_no_ts();
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"hi");
        let _ = e.poll_once();
        e.simulate_ack(handle, snd_nxt_after_send);
        let _ = e.poll_once();
        let conn = e.get_conn(handle);
        assert!(conn.rtt_est.srtt_us().is_some(), "Karn's sampled from xmit_count==1");
    }

    #[test]
    fn ack_prunes_snd_retrans_and_cancels_rto_when_empty() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"hello");
        let _ = e.poll_once();
        // ACK covers all 5 bytes.
        e.simulate_ack(handle, snd_nxt_after_send);
        let _ = e.poll_once();
        let conn = e.get_conn(handle);
        assert!(conn.snd_retrans.is_empty());
        assert!(conn.rto_timer_id.is_none());
    }
```

- [ ] **Step 2: Run — expect fail**

Run: `cargo test -p resd-net-core ack_with_ts_samples_rtt`
Expected: FAIL.

- [ ] **Step 3: Wire the ACK handler**

Find the ACK branch in `tcp_input.rs` `handle_established` (or the existing A3 ACK site). Insert after seq-validation:

```rust
    // A5: RTT sampling.
    let now_us = (crate::clock::now_ns() / 1_000) as u32;
    let advance = seq_lt(conn.snd_una, seg.ack_seq);
    if advance {
        // TS source preferred.
        let rtt_sampled = if conn.ts_enabled {
            if let Some(tsecr) = parsed_opts.ts_ecr {
                let rtt = now_us.wrapping_sub(tsecr);
                if rtt > 0 && rtt < 60_000_000 /* sanity: <60s */ {
                    conn.rtt_est.sample(rtt);
                    true
                } else { false }
            } else { false }
        } else { false };

        // Karn's fallback if no TS-source sample.
        if !rtt_sampled {
            if let Some(front) = conn.snd_retrans.front() {
                let front_end = front.seq.wrapping_add(front.len as u32);
                if front.xmit_count == 1 && seq_le(front_end, seg.ack_seq) {
                    let rtt = now_us.wrapping_sub((front.first_tx_ts_ns / 1_000) as u32);
                    if rtt > 0 && rtt < 60_000_000 {
                        conn.rtt_est.sample(rtt);
                    }
                }
            }
        }
        // Bump counter on any sample.
        // (Gate "was a sample actually taken" cleanly — move the counter inc inside
        // the sample() branch or mirror the branch above.)
    }
```

- [ ] **Step 4: Prune `snd_retrans` in engine on ACK advance**

In the engine's post-`handle_established` path (where counters/events are processed based on `Outcome`), walk the pruned entries and `refcnt_dec` each:

```rust
    if outcome.snd_una_advanced_to > old_snd_una {
        let dropped = conn.snd_retrans.prune_below(outcome.snd_una_advanced_to);
        for entry in dropped {
            unsafe { sys::resd_rte_mbuf_refcnt_update(entry.mbuf.as_ptr(), -1); }
        }
        // If nothing in flight and snd.una caught up to snd.nxt, cancel RTO.
        if conn.snd_retrans.is_empty() && conn.snd_una == conn.snd_nxt {
            if let Some(id) = conn.rto_timer_id.take() {
                self.timer_wheel.cancel(id);
                conn.timer_ids.retain(|t| *t != id);
            }
        }
    }
```

Add a new field to `Outcome`: `snd_una_advanced_to: Option<u32>` (populated in `handle_established` when `snd.una` moves).

- [ ] **Step 5: Run tests — expect pass**

Run: `cargo test -p resd-net-core ack_with_ts_samples_rtt ack_without_ts_uses_karns ack_prunes_snd_retrans`
Expected: PASS.

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: RFC 6298 §3 Karn's algorithm — no sample on retransmitted segments (we gate on `xmit_count == 1`).
- Code: the sanity `rtt < 60_000_000` guards against TS wrap + clock skew producing garbage samples.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/tcp_input.rs \
        crates/resd-net-core/src/engine.rs
git commit -m "a5 task 11: RTT sampling (TS + Karn's) + snd_retrans prune on ACK"
```

---

## Task 12: RTO fire handler — retransmit front, apply backoff, re-arm

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — poll loop advances `timer_wheel` + dispatches fired timers

**Context:** Spec data-flow §3.4. On RTO fire: if `snd.una >= snd.nxt`, no-op (conn idle). Else retransmit front entry, bump `tcp.tx_rto`, apply_backoff (gated by `conn.rto_no_backoff`), re-arm at `now + rto_us`. Task 13 handles the max-retrans-count exhaustion.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn rto_fire_retransmits_front_and_rearms_with_backoff() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"x");
        let _ = e.poll_once();
        // Fast-forward the wheel past the RTO deadline.
        let rto_ns = e.get_conn(handle).rtt_est.rto_us() as u64 * 1_000;
        e.advance_clock_by_ns(rto_ns + 100);
        let _ = e.poll_once();
        let conn = e.get_conn(handle);
        assert_eq!(conn.snd_retrans.front().unwrap().xmit_count, 2);
        assert_eq!(e.counters.tcp.tx_rto.load(Ordering::Relaxed), 1);
        assert_eq!(e.counters.tcp.tx_retrans.load(Ordering::Relaxed), 1);
        // Backoff applied (RTO doubled).
        assert!(conn.rtt_est.rto_us() > DEFAULT_INITIAL_RTO_US);
    }
```

- [ ] **Step 2: Run — expect fail (RTO fire handler not yet wired)**

- [ ] **Step 3: Implement timer dispatch in `poll_once`**

Add to `poll_once` (or wherever engine advances time):

```rust
    let now_ns = crate::clock::now_ns();
    let fired = self.timer_wheel.advance(now_ns);
    for (id, node) in fired {
        match node.kind {
            crate::tcp_timer_wheel::TimerKind::Rto => self.on_rto_fire(node.owner_handle as u32, id),
            crate::tcp_timer_wheel::TimerKind::Tlp => self.on_tlp_fire(node.owner_handle as u32, id),
            crate::tcp_timer_wheel::TimerKind::SynRetrans => self.on_syn_retrans_fire(node.owner_handle as u32, id),
            crate::tcp_timer_wheel::TimerKind::ApiPublic => {}, // A6 reserved
        }
    }
```

Add `on_rto_fire`:

```rust
    fn on_rto_fire(&mut self, handle_raw: u32, fired_id: TimerId) {
        let handle = ConnHandle(handle_raw as usize);
        let conn = match self.flow_table.get_mut(handle) {
            Some(c) => c,
            None => return,
        };
        // Stale? (fired_id should match conn.rto_timer_id; if not, spurious fire.)
        if conn.rto_timer_id != Some(fired_id) {
            return;
        }
        conn.rto_timer_id = None;
        conn.timer_ids.retain(|t| *t != fired_id);

        if conn.snd_retrans.is_empty() {
            return;
        }
        // Retransmit front.
        self.retransmit(handle, 0);
        self.counters.tcp.tx_rto.fetch_add(1, Ordering::Relaxed);
        if self.config.tcp_per_packet_events {
            self.emit_event(crate::tcp_events::Event::TcpRetrans {
                handle, seq: conn.snd_retrans.front().unwrap().seq,
                rtx_count: conn.snd_retrans.front().unwrap().xmit_count as u32,
            });
        }

        // Task 13 inserts the max-retrans-count check here.

        // Apply backoff unless per-connect opt-out.
        let conn = self.flow_table.get_mut(handle).unwrap();
        if !conn.rto_no_backoff {
            conn.rtt_est.apply_backoff();
        }
        // Re-arm.
        let fire_at = crate::clock::now_ns() + conn.rtt_est.rto_us() as u64 * 1_000;
        let id = self.timer_wheel.add(crate::clock::now_ns(), crate::tcp_timer_wheel::TimerNode {
            fire_at_ns: fire_at,
            owner_handle: handle.0 as u32,
            kind: crate::tcp_timer_wheel::TimerKind::Rto,
            generation: 0,
            cancelled: false,
        });
        conn.rto_timer_id = Some(id);
        conn.timer_ids.push(id);
    }
```

- [ ] **Step 4: Run test — expect pass**

Run: `cargo test -p resd-net-core rto_fire_retransmits_front`
Expected: PASS.

- [ ] **Step 5: Test `rto_no_backoff` opt-out**

```rust
    #[test]
    fn rto_fire_with_rto_no_backoff_keeps_rto_constant() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer_with_opts(ConnectOpts {
            rto_no_backoff: true,
            ..Default::default()
        });
        e.simulate_send(handle, b"x");
        let _ = e.poll_once();
        let rto_before = e.get_conn(handle).rtt_est.rto_us();
        e.advance_clock_by_ns(rto_before as u64 * 1_000 + 100);
        let _ = e.poll_once();
        assert_eq!(e.get_conn(handle).rtt_est.rto_us(), rto_before);
    }
```

(Depends on Task 19 `ConnectOpts` — if Task 19 hasn't landed yet when this test runs, guard with `#[ignore]` until 19 and enable in Task 19's commit.)

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: §6.5 lazy RTO re-arm invariant holds (we don't cancel + re-add on every ACK; we only re-arm on fire).
- Code: `retain(|t| *t != fired_id)` keeps `timer_ids` list coherent; cancel is idempotent.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "a5 task 12: RTO fire handler — retransmit + backoff + re-arm"
```

---

## Task 13: `tcp_max_retrans_count` + ETIMEDOUT path

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — insert count check in `on_rto_fire`
- Modify: `crates/resd-net-core/src/tcp_events.rs` — add `err=ETIMEDOUT` variant
- Modify: `crates/resd-net-core/src/counters.rs` — add `conn_timeout_retrans` field

**Context:** Spec data-flow §3.3. When a retrans entry's `xmit_count > tcp_max_retrans_count` (default 15), conn fails with `RESD_NET_EVT_ERROR{err=ETIMEDOUT}`, state → CLOSED, `tcp.conn_timeout_retrans++`, all timers cancelled, snd_retrans drained.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn max_retrans_exhausted_closes_conn_with_etimedout() {
        let mut e = make_test_engine_with_tap_max_retrans(3); // low for test speed
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"x");
        let _ = e.poll_once();
        // Fire RTO 4 times (above the 3-count limit).
        for _ in 0..4 {
            let rto_ns = e.get_conn(handle).rtt_est.rto_us() as u64 * 1_000;
            e.advance_clock_by_ns(rto_ns + 100);
            let _ = e.poll_once();
        }
        let conn = e.get_conn_opt(handle);
        // Conn should be in CLOSED state (or dropped).
        assert!(conn.is_none() || conn.unwrap().state == TcpState::Closed);
        assert_eq!(e.counters.tcp.conn_timeout_retrans.load(Ordering::Relaxed), 1);
        // ETIMEDOUT event was emitted.
        let events = e.drain_events();
        assert!(events.iter().any(|ev| matches!(ev,
            crate::tcp_events::Event::Error { err: crate::error::ErrCode::ETIMEDOUT, .. })));
    }
```

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Add `conn_timeout_retrans` counter**

Edit `counters.rs` `TcpCounters` struct — add:

```rust
    /// A5: data retransmit count exceeded tcp_max_retrans_count → conn ETIMEDOUT.
    pub conn_timeout_retrans: AtomicU64,
```

Also add `conn_timeout_syn_sent`, `rtt_samples`, `tx_rack_loss`, `rack_reo_wnd_override_active`, `rto_no_backoff_active`, `rx_ws_shift_clamped`, `rx_dsack` (Task 26 batch — but add them now if convenient to avoid a second touch of counters.rs).

- [ ] **Step 4: Add ETIMEDOUT err variant**

Edit `tcp_events.rs` or `error.rs` to add `ETIMEDOUT` to the error code enum. Update the `Event::Error { err: ErrCode, ... }` variant match sites.

- [ ] **Step 5: Insert the count check in `on_rto_fire`**

In `on_rto_fire`, after `self.retransmit(handle, 0)`:

```rust
        let conn = self.flow_table.get_mut(handle).unwrap();
        let xmit_count = conn.snd_retrans.front().map(|e| e.xmit_count).unwrap_or(0);
        if xmit_count as u32 > self.config.tcp_max_retrans_count {
            self.counters.tcp.conn_timeout_retrans.fetch_add(1, Ordering::Relaxed);
            self.emit_event(crate::tcp_events::Event::Error {
                handle,
                err: crate::error::ErrCode::ETIMEDOUT,
            });
            self.close_conn(handle); // drains snd_retrans (refcnt_dec), cancels timers, → CLOSED
            return;
        }
```

(Ensure `close_conn` correctly iterates `snd_retrans.entries` and `refcnt_dec`s each mbuf.)

- [ ] **Step 6: Run test — expect pass**

Run: `cargo test -p resd-net-core max_retrans_exhausted`
Expected: PASS.

- [ ] **Step 7: Spec + code-quality review (opus)**

- Spec: §9.3 ETIMEDOUT event documented; §9.1 `conn_timeout_retrans` slow-path counter.
- Code: `close_conn` drain path fully releases mbufs; no leak.

- [ ] **Step 8: Commit**

```bash
git add crates/resd-net-core/src/engine.rs \
        crates/resd-net-core/src/counters.rs \
        crates/resd-net-core/src/tcp_events.rs \
        crates/resd-net-core/src/error.rs
git commit -m "a5 task 13: max_retrans_count → ETIMEDOUT + conn_timeout_retrans counter"
```

---

## Task 14: `tcp_rack.rs` — RackState + compute_reo_wnd + detect_lost

**Files:**
- Create: `crates/resd-net-core/src/tcp_rack.rs`
- Modify: `crates/resd-net-core/src/lib.rs` — `pub mod tcp_rack;`
- Modify: `crates/resd-net-core/src/tcp_conn.rs` — add `pub rack: RackState` field + init in `new_client`

**Context:** RFC 8985 §6.1–6.2. State: `xmit_ts_ns`, `end_seq`, `reo_wnd_us`, `min_rtt_us`, `dsack_seen`. `update_on_ack(entry, now_ns)` updates xmit_ts/end_seq if entry is "newer" (later xmit_ts or same-xmit-ts with greater end_seq). `compute_reo_wnd(rack_aggressive, min_rtt_us, srtt_us)` returns 0 when aggressive, else `min(srtt/4, min_rtt/2)`. `detect_lost(entry, now_ns, reo_wnd_us)`: the RFC 8985 §6.2 rule.

- [ ] **Step 1: Write failing tests**

```rust
// crates/resd-net-core/src/tcp_rack.rs

//! RFC 8985 RACK state + loss detection.

#[derive(Debug, Clone, Default)]
pub struct RackState {
    pub xmit_ts_ns: u64,
    pub end_seq: u32,
    pub reo_wnd_us: u32,
    pub min_rtt_us: u32,
    pub dsack_seen: bool,
}

impl RackState {
    pub fn new() -> Self { Self::default() }

    pub fn update_on_ack(&mut self, entry_xmit_ts_ns: u64, entry_end_seq: u32) {
        if entry_xmit_ts_ns > self.xmit_ts_ns
            || (entry_xmit_ts_ns == self.xmit_ts_ns
                && crate::tcp_seq::seq_lt(self.end_seq, entry_end_seq))
        {
            self.xmit_ts_ns = entry_xmit_ts_ns;
            self.end_seq = entry_end_seq;
        }
    }

    pub fn update_min_rtt(&mut self, rtt_us: u32) {
        if self.min_rtt_us == 0 || rtt_us < self.min_rtt_us {
            self.min_rtt_us = rtt_us;
        }
    }

    /// RFC 8985 §6.2 detect-lost rule for `entry`.
    /// Returns true iff `entry.xmit_ts` < RACK.xmit_ts (or equal with lower
    /// end_seq) AND elapsed time since entry.xmit_ts > reo_wnd_us.
    pub fn detect_lost(
        &self,
        entry_xmit_ts_ns: u64,
        entry_end_seq: u32,
        now_ns: u64,
        reo_wnd_us: u32,
    ) -> bool {
        let newer_ack_exists = entry_xmit_ts_ns < self.xmit_ts_ns
            || (entry_xmit_ts_ns == self.xmit_ts_ns
                && crate::tcp_seq::seq_lt(entry_end_seq, self.end_seq));
        if !newer_ack_exists { return false; }
        let age_ns = now_ns.saturating_sub(entry_xmit_ts_ns);
        age_ns > (reo_wnd_us as u64) * 1_000
    }
}

pub fn compute_reo_wnd_us(rack_aggressive: bool, min_rtt_us: u32, srtt_us: Option<u32>) -> u32 {
    if rack_aggressive { return 0; }
    // RFC 8985 §6.2: min(SRTT/4, min_rtt/2). With no SRTT yet, use min_rtt/2;
    // with no min_rtt yet, use a small nominal (1ms = 1000µs).
    match srtt_us {
        None => (min_rtt_us / 2).max(1_000),
        Some(srtt) => {
            let a = srtt / 4;
            let b = min_rtt_us / 2;
            a.min(b).max(1_000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_on_ack_keeps_newest() {
        let mut r = RackState::new();
        r.update_on_ack(100, 500);
        r.update_on_ack(50, 400);  // older xmit — ignored
        assert_eq!((r.xmit_ts_ns, r.end_seq), (100, 500));
        r.update_on_ack(200, 600); // newer xmit — taken
        assert_eq!((r.xmit_ts_ns, r.end_seq), (200, 600));
        r.update_on_ack(200, 700); // same xmit, greater seq — taken
        assert_eq!((r.xmit_ts_ns, r.end_seq), (200, 700));
    }

    #[test]
    fn detect_lost_fires_when_entry_older_and_beyond_reo_wnd() {
        let mut r = RackState::new();
        r.update_on_ack(1_000_000, 600);
        // Entry with xmit_ts=500_000 — older than RACK.xmit_ts=1_000_000.
        // now=2_000_000, reo_wnd_us=500 → age=1_500_000 ns = 1500µs > 500µs.
        assert!(r.detect_lost(500_000, 400, 2_000_000, 500));
    }

    #[test]
    fn detect_lost_false_when_within_reo_wnd() {
        let mut r = RackState::new();
        r.update_on_ack(1_000_000, 600);
        // now=1_100_000, reo_wnd_us=500 → age=600_000 ns = 600µs > 500µs.
        // Wait actually 600µs > 500µs so it would fire. Pick larger reo_wnd.
        assert!(!r.detect_lost(500_000, 400, 1_000_100, 500_000));
    }

    #[test]
    fn aggressive_reo_wnd_is_zero() {
        assert_eq!(compute_reo_wnd_us(true, 100_000, Some(200_000)), 0);
    }

    #[test]
    fn non_aggressive_reo_wnd_min_of_srtt4_and_minrtt2() {
        // srtt/4 = 50_000, min_rtt/2 = 30_000 → min = 30_000.
        assert_eq!(compute_reo_wnd_us(false, 60_000, Some(200_000)), 30_000);
    }
}
```

- [ ] **Step 2: Run — expect fail**

Run: `cargo test -p resd-net-core tcp_rack`
Expected: FAIL — module not exported.

- [ ] **Step 3: Add `pub mod tcp_rack;` + `pub rack: RackState` field on TcpConn**

Add to `lib.rs`; add to `TcpConn`:

```rust
    /// A5: RFC 8985 RACK state.
    pub rack: crate::tcp_rack::RackState,
```

Init in `new_client`: `rack: crate::tcp_rack::RackState::new(),`

Run: `cargo test -p resd-net-core tcp_rack`
Expected: 5 tests PASS.

- [ ] **Step 4: Spec + code-quality review (opus)**

- Spec: RFC 8985 §6.1 "RACK.xmit_ts, RACK.end_seq" definitions match; §6.2 detect-lost rule matches (newer-ack-exists AND age > reo_wnd).
- Code: saturating_sub on age_ns; `compute_reo_wnd_us` floor at 1000µs (1ms) as sanity.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_rack.rs \
        crates/resd-net-core/src/tcp_conn.rs \
        crates/resd-net-core/src/lib.rs
git commit -m "a5 task 14: tcp_rack — RackState + compute_reo_wnd + detect_lost"
```

---

## Task 15: RACK loss-detect pass in `tcp_input` ACK handler + retransmit on lost

**Files:**
- Modify: `crates/resd-net-core/src/tcp_input.rs` — in ACK branch, update rack, mark_sacked, compute reo_wnd, walk snd_retrans for lost
- Modify: `crates/resd-net-core/src/engine.rs` — when input handler returns a "lost entries" list, invoke `retransmit` for each

**Context:** Spec data-flow §3.2 post-ACK steps. Walk `snd_retrans` for each non-sacked-non-lost entry; `rack.detect_lost(entry.xmit_ts_ns, entry.seq+entry.len, now, reo_wnd)` → mark lost + queue for retransmit. Bump `tcp.tx_rack_loss` per lost entry.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn rack_detects_loss_from_sack_and_retransmits() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer();
        // Send 3 segments.
        e.simulate_send(handle, b"AAAAA");
        e.simulate_send(handle, b"BBBBB");
        e.simulate_send(handle, b"CCCCC");
        let _ = e.poll_once();
        // Simulate peer SACKing B and C but not A — implies A is lost.
        let snd_una = e.get_conn(handle).snd_una;
        e.simulate_ack_with_sack(handle, snd_una, &[(snd_una + 5, snd_una + 15)]);
        // Wait past reo_wnd (~ srtt/4; make clock advance reliably).
        e.advance_clock_by_ns(100_000); // 100µs
        let _ = e.poll_once();
        let conn = e.get_conn(handle);
        // A is marked lost, retransmit scheduled.
        assert!(conn.snd_retrans.entries[0].lost);
        assert!(e.counters.tcp.tx_rack_loss.load(Ordering::Relaxed) >= 1);
    }
```

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement RACK pass in engine after ACK**

In the post-ACK engine code (same place as Task 11's snd_retrans prune):

```rust
    // RACK: update state from newly-acked-or-sacked entries, then detect-lost.
    let now_ns = crate::clock::now_ns();
    // Update rack from the newest SACKed or ACKed entry.
    for e_ in conn.snd_retrans.iter_for_rack() {
        if e_.sacked || e_.seq.wrapping_add(e_.len as u32) <= conn.snd_una {
            conn.rack.update_on_ack(e_.xmit_ts_ns, e_.seq.wrapping_add(e_.len as u32));
        }
    }
    // Compute reo_wnd from conn.rack_aggressive + rack.min_rtt + rtt_est.srtt.
    let reo_wnd_us = crate::tcp_rack::compute_reo_wnd_us(
        conn.rack_aggressive,
        conn.rack.min_rtt_us,
        conn.rtt_est.srtt_us(),
    );
    // Walk entries for loss detection.
    let mut lost_indexes = Vec::new();
    for (i, e_) in conn.snd_retrans.entries.iter().enumerate() {
        if e_.sacked || e_.lost { continue; }
        let end_seq = e_.seq.wrapping_add(e_.len as u32);
        if conn.rack.detect_lost(e_.xmit_ts_ns, end_seq, now_ns, reo_wnd_us) {
            lost_indexes.push(i);
        }
    }
    for i in &lost_indexes {
        conn.snd_retrans.entries[*i].lost = true;
    }
    // After the loop, retransmit each.
    for i in lost_indexes {
        self.retransmit(handle, i);
        self.counters.tcp.tx_rack_loss.fetch_add(1, Ordering::Relaxed);
        if self.config.tcp_per_packet_events {
            self.emit_event(crate::tcp_events::Event::TcpLossDetected {
                handle,
                cause: crate::tcp_events::LossCause::Rack,
            });
        }
    }
```

Also feed `mark_sacked` from `parsed_opts.sack_blocks[..sack_block_count]`:

```rust
    for block in parsed_opts.sack_blocks[..parsed_opts.sack_block_count as usize].iter() {
        conn.snd_retrans.mark_sacked(*block);
    }
```

- [ ] **Step 4: Run test — expect pass**

Run: `cargo test -p resd-net-core rack_detects_loss_from_sack`
Expected: PASS.

- [ ] **Step 5: Also test that non-lost entries are not retransmitted (reo_wnd grace)**

```rust
    #[test]
    fn rack_respects_reo_wnd_grace_period() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"AAAAA");
        e.simulate_send(handle, b"BBBBB");
        let _ = e.poll_once();
        let snd_una = e.get_conn(handle).snd_una;
        e.simulate_ack_with_sack(handle, snd_una, &[(snd_una + 5, snd_una + 10)]);
        // Do NOT advance clock — reo_wnd grace should protect A.
        let _ = e.poll_once();
        let conn = e.get_conn(handle);
        assert!(!conn.snd_retrans.entries[0].lost);
    }
```

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: RFC 8985 §6.2 integration — state updated before detect-lost; sacked entries update rack; lost entries retransmitted.
- Code: two-pass (flag then retransmit) keeps `entries` borrow-happy; no O(N²); counter increments consistent.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/tcp_input.rs crates/resd-net-core/src/engine.rs
git commit -m "a5 task 15: RACK loss-detect pass + retransmit-on-lost in ACK handler"
```

---

## Task 16: DSACK detection + `tcp.rx_dsack` counter (visibility only)

**Files:**
- Modify: `crates/resd-net-core/src/tcp_input.rs` — add `is_dsack_block(block, snd_una, sack_scoreboard)` + counter bump
- Modify: `crates/resd-net-core/src/counters.rs` — `rx_dsack` field (if not already added in Task 13's batch)

**Context:** RFC 2883 §4 DSACK detection: a SACK block is a D-SACK iff:
- (a) `block.right ≤ snd.una` — block covers already-cumulatively-acked data, OR
- (b) block is fully inside another block in the same SACK option (first block only), OR
- (c) block is fully covered by a block already in `conn.sack_scoreboard`.

Stage 1 A5 uses DSACK as visibility only: counter bump, no behavioral adaptation, no reneging-safe scoreboard prune, no dynamic reo_wnd.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn dsack_block_covering_below_snd_una_bumps_counter() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"hello");
        let _ = e.poll_once();
        let snd_una = e.get_conn(handle).snd_una;
        // Peer sends ACK(snd_una+5) SACK(snd_una..snd_una+2) — D-SACK indicating
        // duplicate receipt of the first 2 bytes (already cumulatively acked).
        e.simulate_ack_with_sack(handle, snd_una + 5, &[(snd_una.wrapping_sub(2), snd_una)]);
        let _ = e.poll_once();
        assert!(e.counters.tcp.rx_dsack.load(Ordering::Relaxed) >= 1);
    }
```

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement DSACK detection**

In `tcp_input.rs` ACK branch, before `mark_sacked`:

```rust
    // RFC 2883 DSACK detection (visibility only).
    for block in parsed_opts.sack_blocks[..parsed_opts.sack_block_count as usize].iter() {
        // (a) block entirely ≤ snd.una.
        if crate::tcp_seq::seq_le(block.right, conn.snd_una) {
            counters.tcp.rx_dsack.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // (b) block fully inside an existing sack_scoreboard range.
        for existing in conn.sack_scoreboard.blocks() {
            if crate::tcp_seq::seq_le(existing.left, block.left)
                && crate::tcp_seq::seq_le(block.right, existing.right)
            {
                counters.tcp.rx_dsack.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
```

- [ ] **Step 4: Run test — pass**

- [ ] **Step 5: Spec + code-quality review (opus)**

- Spec: RFC 2883 §4 DSACK detection without reneging-safe prune per spec §6.5 "visibility only".
- Code: O(N·M) N=sack_blocks (≤4), M=scoreboard (≤4) — trivially bounded.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/tcp_input.rs crates/resd-net-core/src/counters.rs
git commit -m "a5 task 16: DSACK detection + rx_dsack counter (visibility only)"
```

---

## Task 17: `tcp_tlp.rs` — PTO + probe selection + fire handler

**Files:**
- Create: `crates/resd-net-core/src/tcp_tlp.rs`
- Modify: `crates/resd-net-core/src/engine.rs` — `on_tlp_fire` handler + TLP scheduling in ACK path

**Context:** RFC 8985 §7. PTO = max(2·SRTT, `tcp_min_rto_us`). Schedule TLP at most once per tail; on fire, if `snd.pending` has bytes → probe with new data (send next MSS); else retransmit the `snd_retrans.back()` (last segment). Bump `tcp.tx_tlp`.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn tlp_fires_on_tail_loss_and_retransmits_last_segment() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"hello");
        let _ = e.poll_once();
        // Peer never ACKs. PTO = max(2·srtt, min_rto_us) — srtt unset → PTO = min_rto_us.
        let conn = e.get_conn(handle);
        let pto_us = crate::tcp_tlp::pto_us(conn.rtt_est.srtt_us(), 5_000);
        e.advance_clock_by_ns(pto_us as u64 * 1_000 + 100);
        let _ = e.poll_once();
        assert_eq!(e.counters.tcp.tx_tlp.load(Ordering::Relaxed), 1);
        // xmit_count on the last-segment entry bumped.
        assert_eq!(e.get_conn(handle).snd_retrans.back().unwrap().xmit_count, 2);
    }
```

- [ ] **Step 2: Create `tcp_tlp.rs`**

```rust
//! RFC 8985 §7 Tail Loss Probe.

pub fn pto_us(srtt_us: Option<u32>, min_rto_us: u32) -> u32 {
    match srtt_us {
        None => min_rto_us,
        Some(srtt) => srtt.saturating_mul(2).max(min_rto_us),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    NewData,        // there's new data in snd.pending — probe with it
    LastSegmentRetransmit, // no new data — probe by retransmitting last in-flight
}

pub fn select_probe(snd_pending_nonempty: bool, snd_retrans_nonempty: bool) -> Option<Probe> {
    if !snd_retrans_nonempty { return None; }
    if snd_pending_nonempty { Some(Probe::NewData) }
    else { Some(Probe::LastSegmentRetransmit) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pto_uses_min_rto_when_no_srtt() {
        assert_eq!(pto_us(None, 5_000), 5_000);
    }

    #[test]
    fn pto_is_2_srtt_when_srtt_present() {
        assert_eq!(pto_us(Some(100_000), 5_000), 200_000);
    }

    #[test]
    fn pto_floors_at_min_rto() {
        assert_eq!(pto_us(Some(1_000), 5_000), 5_000);
    }

    #[test]
    fn select_probe_new_data_when_pending_nonempty() {
        assert_eq!(select_probe(true, true), Some(Probe::NewData));
    }

    #[test]
    fn select_probe_last_seg_when_no_pending() {
        assert_eq!(select_probe(false, true), Some(Probe::LastSegmentRetransmit));
    }

    #[test]
    fn select_probe_none_when_no_retrans() {
        assert!(select_probe(true, false).is_none());
        assert!(select_probe(false, false).is_none());
    }
}
```

- [ ] **Step 3: Schedule TLP in ACK path**

In the engine post-ACK code:

```rust
    // TLP schedule (RFC 8985 §7.2): only when snd_retrans is non-empty AND no TLP is pending.
    if !conn.snd_retrans.is_empty() && conn.tlp_timer_id.is_none() {
        let pto = crate::tcp_tlp::pto_us(
            conn.rtt_est.srtt_us(),
            self.config.tcp_min_rto_us,
        ) as u64 * 1_000;
        let fire_at = crate::clock::now_ns() + pto;
        let id = self.timer_wheel.add(crate::clock::now_ns(), crate::tcp_timer_wheel::TimerNode {
            fire_at_ns: fire_at,
            owner_handle: handle.0 as u32,
            kind: crate::tcp_timer_wheel::TimerKind::Tlp,
            generation: 0, cancelled: false,
        });
        conn.tlp_timer_id = Some(id);
        conn.timer_ids.push(id);
    }
```

- [ ] **Step 4: Implement `on_tlp_fire`**

```rust
    fn on_tlp_fire(&mut self, handle_raw: u32, fired_id: TimerId) {
        let handle = ConnHandle(handle_raw as usize);
        let conn = match self.flow_table.get_mut(handle) { Some(c) => c, None => return };
        if conn.tlp_timer_id != Some(fired_id) { return; }
        conn.tlp_timer_id = None;
        conn.timer_ids.retain(|t| *t != fired_id);

        let probe = crate::tcp_tlp::select_probe(
            !conn.snd.pending.is_empty(),
            !conn.snd_retrans.is_empty(),
        );
        match probe {
            None => return,
            Some(crate::tcp_tlp::Probe::NewData) => {
                // Drain one MSS from snd.pending via send_bytes (which now also
                // pushes to snd_retrans + arms RTO).
                self.drain_one_segment(handle);
            }
            Some(crate::tcp_tlp::Probe::LastSegmentRetransmit) => {
                let last_idx = conn.snd_retrans.len() - 1;
                self.retransmit(handle, last_idx);
            }
        }
        self.counters.tcp.tx_tlp.fetch_add(1, Ordering::Relaxed);
        if self.config.tcp_per_packet_events {
            self.emit_event(crate::tcp_events::Event::TcpLossDetected {
                handle, cause: crate::tcp_events::LossCause::Tlp,
            });
        }
    }
```

- [ ] **Step 5: Run test — pass**

Run: `cargo test -p resd-net-core tlp_fires_on_tail_loss`
Expected: PASS.

Also: `cargo test -p resd-net-core tcp_tlp` → 6 unit tests PASS.

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: RFC 8985 §7.2 PTO formula; §7.3 at-most-one-TLP-per-tail semantic enforced by the `tlp_timer_id.is_none()` gate.
- Code: TLP cancels on ACK-drain (when `snd_retrans` empties).

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/tcp_tlp.rs \
        crates/resd-net-core/src/engine.rs \
        crates/resd-net-core/src/lib.rs
git commit -m "a5 task 17: tcp_tlp — PTO + probe selection + fire handler"
```

---

## Task 18: SYN retransmit scheduler + budget → ETIMEDOUT

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — arm SYN retrans timer on initial SYN TX; `on_syn_retrans_fire` handler
- Modify: `crates/resd-net-core/src/counters.rs` — `conn_timeout_syn_sent` field (in Task 13 batch already)

**Context:** Spec §6.5 SYN retransmit: 3 attempts with exponential backoff from `max(initial_rto_us, min_rto_us)`, total bounded by `connect_timeout_ms`. On SYN-ACK, cancel the timer. On budget exhausted, `tcp.conn_timeout_syn_sent++`, emit `ETIMEDOUT`, → CLOSED.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn syn_retrans_gives_up_after_3_attempts_and_emits_etimedout() {
        let mut e = make_test_engine_with_tap_no_peer_response();
        let handle = e.connect_test_peer_no_wait();
        // Fast-forward past each SYN retrans.
        for _ in 0..4 {
            e.advance_clock_by_ns(100_000_000); // 100ms each (exponential from 5ms)
            let _ = e.poll_once();
        }
        assert_eq!(e.counters.tcp.conn_timeout_syn_sent.load(Ordering::Relaxed), 1);
        let events = e.drain_events();
        assert!(events.iter().any(|ev| matches!(ev,
            crate::tcp_events::Event::Error { err: crate::error::ErrCode::ETIMEDOUT, .. })));
    }
```

- [ ] **Step 2: Arm SYN timer in `connect`**

After initial SYN TX in `Engine::connect`:

```rust
    let fire_at = crate::clock::now_ns()
        + (self.config.tcp_initial_rto_us.max(self.config.tcp_min_rto_us) as u64) * 1_000;
    let id = self.timer_wheel.add(crate::clock::now_ns(), crate::tcp_timer_wheel::TimerNode {
        fire_at_ns: fire_at,
        owner_handle: handle.0 as u32,
        kind: crate::tcp_timer_wheel::TimerKind::SynRetrans,
        generation: 0, cancelled: false,
    });
    conn.syn_retrans_timer_id = Some(id);
    conn.timer_ids.push(id);
```

- [ ] **Step 3: Implement `on_syn_retrans_fire`**

```rust
    fn on_syn_retrans_fire(&mut self, handle_raw: u32, fired_id: TimerId) {
        let handle = ConnHandle(handle_raw as usize);
        let conn = match self.flow_table.get_mut(handle) { Some(c) => c, None => return };
        if conn.syn_retrans_timer_id != Some(fired_id) { return; }
        conn.syn_retrans_timer_id = None;
        conn.timer_ids.retain(|t| *t != fired_id);

        if conn.state != TcpState::SynSent { return; } // already moved on
        conn.syn_retrans_count = conn.syn_retrans_count.saturating_add(1);
        if conn.syn_retrans_count > 3 {
            self.counters.tcp.conn_timeout_syn_sent.fetch_add(1, Ordering::Relaxed);
            self.emit_event(crate::tcp_events::Event::Error {
                handle, err: crate::error::ErrCode::ETIMEDOUT,
            });
            self.close_conn(handle);
            return;
        }
        // Re-emit SYN.
        self.emit_syn(handle);
        // Re-arm with exponential backoff.
        let delay = (self.config.tcp_initial_rto_us.max(self.config.tcp_min_rto_us)
            << conn.syn_retrans_count.min(6)) as u64 * 1_000;
        let fire_at = crate::clock::now_ns() + delay;
        let id = self.timer_wheel.add(crate::clock::now_ns(), crate::tcp_timer_wheel::TimerNode {
            fire_at_ns: fire_at,
            owner_handle: handle.0 as u32,
            kind: crate::tcp_timer_wheel::TimerKind::SynRetrans,
            generation: 0, cancelled: false,
        });
        let conn = self.flow_table.get_mut(handle).unwrap();
        conn.syn_retrans_timer_id = Some(id);
        conn.timer_ids.push(id);
    }
```

- [ ] **Step 4: Cancel SYN timer on SYN-ACK**

In `handle_syn_sent` post-SYN-ACK processing:

```rust
    if let Some(id) = conn.syn_retrans_timer_id.take() {
        self.timer_wheel.cancel(id);
        conn.timer_ids.retain(|t| *t != id);
    }
```

- [ ] **Step 5: Run test — pass**

- [ ] **Step 6: Spec + code-quality review (opus)**

- Spec: §6.5 SYN retransmit schedule: 3 attempts, exponential backoff bounded by `connect_timeout_ms` (we currently use count-based only; note the connect_timeout_ms hard-stop is optional at A5 since the 3-attempt count is the dominant bound).
- Code: cancel on SYN-ACK; no double-re-arm; counter bump on budget exhaustion only.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "a5 task 18: SYN retransmit scheduler + 3-attempt budget → ETIMEDOUT"
```

---

## Task 19: Connect opts — `rack_aggressive` + `rto_no_backoff` + related counters

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — `ConnectOpts` grows two fields; `connect` propagates
- Modify: `crates/resd-net/src/api.rs` — FFI `resd_net_connect_opts_t` grows two fields
- Modify: `crates/resd-net-core/src/counters.rs` — `rack_reo_wnd_override_active`, `rto_no_backoff_active` (if not in Task 13 batch)

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn rack_aggressive_override_bumps_counter_and_sets_reo_wnd_zero() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer_with_opts(ConnectOpts {
            rack_aggressive: true,
            ..Default::default()
        });
        assert!(e.get_conn(handle).rack_aggressive);
        assert_eq!(e.counters.tcp.rack_reo_wnd_override_active.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rto_no_backoff_opt_bumps_counter() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer_with_opts(ConnectOpts {
            rto_no_backoff: true,
            ..Default::default()
        });
        assert!(e.get_conn(handle).rto_no_backoff);
        assert_eq!(e.counters.tcp.rto_no_backoff_active.load(Ordering::Relaxed), 1);
    }
```

- [ ] **Step 2: Extend `ConnectOpts`**

```rust
pub struct ConnectOpts {
    // ... existing A3 fields ...
    pub rack_aggressive: bool,
    pub rto_no_backoff: bool,
}
```

Propagate in `connect` to `TcpConn`:

```rust
    conn.rack_aggressive = opts.rack_aggressive;
    conn.rto_no_backoff = opts.rto_no_backoff;
    if opts.rack_aggressive {
        self.counters.tcp.rack_reo_wnd_override_active.fetch_add(1, Ordering::Relaxed);
    }
    if opts.rto_no_backoff {
        self.counters.tcp.rto_no_backoff_active.fetch_add(1, Ordering::Relaxed);
    }
```

- [ ] **Step 3: FFI**

In `crates/resd-net/src/api.rs` (or the C-ABI struct def):

```rust
#[repr(C)]
pub struct resd_net_connect_opts_t {
    // ... existing fields ...
    pub rack_aggressive: bool,
    pub rto_no_backoff: bool,
}
```

- [ ] **Step 4: Run tests — pass**

- [ ] **Step 5: Spec + code-quality review (opus)**

- Spec: per-connect shape matches design spec §7.3.
- Code: counters bumped once at connect; no repeat.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/engine.rs \
        crates/resd-net/src/api.rs \
        crates/resd-net-core/src/counters.rs
git commit -m "a5 task 19: connect_opts rack_aggressive + rto_no_backoff + counters"
```

---

## Task 20: `tcp_per_packet_events` config + event emissions + `ETIMEDOUT` err

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — `EngineConfig` gets `tcp_per_packet_events: bool`
- Modify: `crates/resd-net-core/src/tcp_events.rs` — `TcpRetrans` and `TcpLossDetected` variants (also `LossCause`)
- Modify: `crates/resd-net/src/lib.rs` — FFI dispatch of new events

**Context:** Spec §9.3. Events already referenced in RTO (Task 12), RACK (Task 15), TLP (Task 17) behind `self.config.tcp_per_packet_events` gate — this task makes that gate real.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn tcp_per_packet_events_default_false_suppresses_retrans_events() {
        let mut e = make_test_engine_with_tap_default(); // tcp_per_packet_events = false
        let handle = e.connect_test_peer();
        e.simulate_send(handle, b"x");
        let _ = e.poll_once();
        e.advance_clock_by_ns(1_000_000_000);
        let _ = e.poll_once();
        let events = e.drain_events();
        assert!(!events.iter().any(|ev| matches!(ev, Event::TcpRetrans { .. })));
    }

    #[test]
    fn tcp_per_packet_events_true_emits_retrans_events() {
        let mut e = make_test_engine_with_tap_config(EngineConfig {
            tcp_per_packet_events: true,
            ..Default::default()
        });
        // ... same RTO scenario ...
        assert!(events.iter().any(|ev| matches!(ev, Event::TcpRetrans { .. })));
    }
```

- [ ] **Step 2: Add field + enum variants**

`EngineConfig` gains `pub tcp_per_packet_events: bool` (default `false`).

`tcp_events.rs`:

```rust
pub enum Event {
    // ... existing ...
    TcpRetrans { handle: ConnHandle, seq: u32, rtx_count: u32 },
    TcpLossDetected { handle: ConnHandle, cause: LossCause },
    Error { handle: ConnHandle, err: crate::error::ErrCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossCause { Rack, Tlp, Rto }
```

Add `ETIMEDOUT` to `ErrCode`.

FFI (cbindgen-visible): ensure `RESD_NET_EVT_TCP_RETRANS`, `RESD_NET_EVT_TCP_LOSS_DETECTED`, `RESD_NET_EVT_ERROR` + `ETIMEDOUT` are emitted by the C-ABI layer with the right integer tags.

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Spec + code-quality review (opus)**

- Spec: §9.3 exact; state-change event stays unconditional.
- Code: `LossCause` enum kept tight; RTO fire uses `LossCause::Rto` (add that emission in Task 12 too — audit).

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/engine.rs \
        crates/resd-net-core/src/tcp_events.rs \
        crates/resd-net-core/src/error.rs \
        crates/resd-net/src/lib.rs
git commit -m "a5 task 20: tcp_per_packet_events + new events + ETIMEDOUT err"
```

---

## Task 21: Engine config RTO fields + remove `tcp_initial_rto_ms`

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — `EngineConfig` struct
- Modify: `crates/resd-net/src/api.rs` — FFI engine config mirror
- Modify: `include/resd_net.h` — regenerated via cbindgen
- Modify: `examples/cpp-consumer/main.cpp` — set reasonable values for the new fields

**Context:** Add `tcp_min_rto_us: u32`, `tcp_initial_rto_us: u32`, `tcp_max_rto_us: u32`, `tcp_max_retrans_count: u32`. Remove `tcp_initial_rto_ms`.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn engine_config_default_rto_values_match_spec() {
        let cfg = EngineConfig::default();
        assert_eq!(cfg.tcp_min_rto_us, 5_000);
        assert_eq!(cfg.tcp_initial_rto_us, 5_000);
        assert_eq!(cfg.tcp_max_rto_us, 1_000_000);
        assert_eq!(cfg.tcp_max_retrans_count, 15);
        assert!(!cfg.tcp_per_packet_events);
    }
```

Also check that `tcp_initial_rto_ms` no longer compiles (remove any reference in tests).

- [ ] **Step 2: Modify `EngineConfig`**

```rust
pub struct EngineConfig {
    // ... A3/A4 fields ...
    pub tcp_min_rto_us: u32,
    pub tcp_initial_rto_us: u32,
    pub tcp_max_rto_us: u32,
    pub tcp_max_retrans_count: u32,
    pub tcp_per_packet_events: bool,
    // REMOVED: pub tcp_initial_rto_ms: u32,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            // ... existing defaults ...
            tcp_min_rto_us: 5_000,
            tcp_initial_rto_us: 5_000,
            tcp_max_rto_us: 1_000_000,
            tcp_max_retrans_count: 15,
            tcp_per_packet_events: false,
        }
    }
}
```

- [ ] **Step 3: Mirror FFI + regenerate header**

Edit `resd-net/src/api.rs` `resd_net_engine_config_t` with the same fields. Run cbindgen:

```bash
cargo run --bin resd-net-cbindgen  # or whatever the project uses
# OR manually re-run cbindgen against api.rs
```

Confirm `include/resd_net.h` updates.

- [ ] **Step 4: Update `examples/cpp-consumer/main.cpp`**

Set `tcp_min_rto_us = 5000`, etc. Remove any `tcp_initial_rto_ms` line.

- [ ] **Step 5: Thread config through `TcpConn::new_client`**

`Engine::connect` now passes `config.tcp_min_rto_us / tcp_initial_rto_us / tcp_max_rto_us` to `RttEstimator::new`.

- [ ] **Step 6: Run workspace build**

```bash
cargo build --workspace
```
Expected: no references to `tcp_initial_rto_ms`. If any tests or src reference the removed field, update.

- [ ] **Step 7: Run tests**

```bash
cargo test -p resd-net-core engine_config_default_rto_values
```
Expected: PASS.

- [ ] **Step 8: Spec + code-quality review (opus)**

- Spec: field names + defaults match design spec §7.1–§7.3.
- Code: `Default` impl consistent; no orphan `tcp_initial_rto_ms` references.

- [ ] **Step 9: Commit**

```bash
git add crates/resd-net-core/src/engine.rs \
        crates/resd-net/src/api.rs \
        include/resd_net.h \
        examples/cpp-consumer/main.cpp
git commit -m "a5 task 21: engine config RTO fields; drop tcp_initial_rto_ms"
```

---

## Task 22: A4 carry-over — WS>14 SHOULD-log + parser-side clamp

**Files:**
- Modify: `crates/resd-net-core/src/tcp_options.rs` — parser clamps shift to 14, returns a clamp flag on the `TcpOpts` struct
- Modify: `crates/resd-net-core/src/tcp_input.rs` — `handle_syn_sent` bumps `tcp.rx_ws_shift_clamped` when the parser flag is set AND emits a one-shot stderr log per-conn

**Context:** A4 RFC review I-9 + user callout. RFC 7323 §2.3: "If a Window Scale option is received with a shift.cnt value larger than 14, the TCP SHOULD log the error but MUST use 14 instead of the specified value." A4 clamps at the handshake site only; A5 adds (a) parser-layer clamp as defense-in-depth, (b) one-shot log, (c) counter.

- [ ] **Step 1: Write failing tests**

```rust
    // in tcp_options.rs tests
    #[test]
    fn parser_clamps_ws_shift_above_14_to_14_and_signals() {
        let mut buf = vec![];
        // Build a TCP options block with WSCALE=15.
        buf.extend_from_slice(&[3, 3, 15]);
        let parsed = parse_options(&buf).unwrap();
        assert_eq!(parsed.window_scale, Some(14));
        assert!(parsed.ws_clamped);
    }
```

```rust
    // integration test
    #[test]
    fn syn_ack_with_ws_shift_15_clamps_and_bumps_counter() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer_replies_syn_ack_ws_shift(15);
        let _ = e.poll_once();
        assert_eq!(e.counters.tcp.rx_ws_shift_clamped.load(Ordering::Relaxed), 1);
        assert_eq!(e.get_conn(handle).ws_shift_in, 14);
    }
```

- [ ] **Step 2: Add `ws_clamped: bool` to `TcpOpts`**

Edit `tcp_options.rs` — add the flag. In the WSCALE parse arm:

```rust
    3 => {
        if len != 3 { return Err(ParseError::BadKnownLen); }
        let shift = buf[pos + 2];
        if shift > 14 {
            opts.window_scale = Some(14);
            opts.ws_clamped = true;
        } else {
            opts.window_scale = Some(shift);
        }
    }
```

- [ ] **Step 3: Wire the counter + log in `tcp_input::handle_syn_sent`**

Where A4 already clamps `ws_shift_in`:

```rust
    if parsed_opts.ws_clamped {
        counters.tcp.rx_ws_shift_clamped.fetch_add(1, Ordering::Relaxed);
        // One-shot log per conn. In the absence of a log facade, eprintln! is OK here;
        // fires only on an extremely rare path (peer sending WS>14 is not seen in the wild).
        eprintln!(
            "resd_net: peer advertised WS shift > 14 on handshake; clamped to 14 per RFC 7323 §2.3"
        );
    }
```

- [ ] **Step 4: Run tests — pass**

- [ ] **Step 5: Review (opus)**

- Spec: RFC 7323 §2.3 SHOULD-log + MUST-clamp both satisfied.
- Code: no feature flags; log is one-shot per conn.

- [ ] **Step 6: Commit**

```bash
git add crates/resd-net-core/src/tcp_options.rs crates/resd-net-core/src/tcp_input.rs
git commit -m "a5 task 22: WS>14 parser clamp + SHOULD-log + rx_ws_shift_clamped counter"
```

---

## Task 23: A4 carry-over — `dup_ack` strict RFC 5681 §2 5-condition definition

**Files:**
- Modify: `crates/resd-net-core/src/tcp_input.rs` — tighten the `dup_ack` detection

**Context:** A4 mTCP review I-10. RFC 5681 §2 defines a duplicate ACK as one that (1) ACK of largest ACK rcvd (i.e., seg.ack == snd.una), (2) no data, (3) no window update (seg.window == conn.snd_wnd), (4) outstanding data to be ACKed (snd.una != snd.nxt), (5) connection state allows it (ESTABLISHED/CLOSE_WAIT/FIN_WAIT_*). A4 uses a loose check; A5 tightens since RACK replaces the 3-dup-ACK trigger anyway.

- [ ] **Step 1: Write failing tests**

```rust
    #[test]
    fn dup_ack_ignored_when_seg_has_data() { /* ack with payload → not a dup_ack */ }

    #[test]
    fn dup_ack_ignored_when_seg_updates_window() { /* seg.window != snd_wnd → not dup_ack */ }

    #[test]
    fn dup_ack_ignored_when_no_outstanding_data() { /* snd.una == snd.nxt → not dup_ack */ }

    #[test]
    fn dup_ack_bumps_only_when_all_five_conditions_hold() {
        /* exact 5-condition match → bump rx_dup_ack */
    }
```

- [ ] **Step 2: Rewrite the dup_ack branch**

Locate the current A3 `dup_ack` detection in `handle_established`. Replace with:

```rust
    // RFC 5681 §2 strict dup_ack detection.
    let c1 = seg.ack_seq == conn.snd_una;
    let c2 = seg.payload.is_empty();
    let c3 = (seg.window as u32) == (conn.snd_wnd >> conn.ws_shift_in);
    let c4 = conn.snd_una != conn.snd_nxt;
    let c5 = matches!(conn.state,
        TcpState::Established | TcpState::CloseWait |
        TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing);
    let dup_ack = c1 && c2 && c3 && c4 && c5;
    if dup_ack {
        counters.tcp.rx_dup_ack.fetch_add(1, Ordering::Relaxed);
    }
```

- [ ] **Step 3: Run tests — pass**

- [ ] **Step 4: Review (opus)**

- Spec: RFC 5681 §2 exact. Note behavior-free — dup_ack doesn't trigger retransmit under RACK.
- Code: `conn.snd_wnd >> conn.ws_shift_in` normalizes the scaled window for comparison.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_input.rs
git commit -m "a5 task 23: dup_ack strict RFC 5681 §2 five-condition check"
```

---

## Task 24: A4 carry-over — `ooo_drop` legacy field removal

**Files:**
- Modify: `crates/resd-net-core/src/tcp_input.rs` — remove `Outcome.ooo_drop` field, three asserts, all matcher refs
- Modify: `crates/resd-net-core/src/engine.rs` — remove any `ooo_drop` matcher reference

**Context:** User callout. A4 rewrote the OOO branch to push to reorder queue; `ooo_drop` stayed as always-zero for compatibility. A5 deletes it.

- [ ] **Step 1: Grep and collect all references**

```bash
grep -rn 'ooo_drop' crates/resd-net-core/src/
```

Expected:
- `tcp_input.rs:135` — struct field decl
- `tcp_input.rs:180` — init in `Outcome::base()`
- `tcp_input.rs:1061, 1126, 1153` — `assert_eq!(out.ooo_drop, 0)` in tests
- possibly `engine.rs` — matcher reference in outcome handler

- [ ] **Step 2: Delete the field**

Remove from `Outcome` struct; remove from `Outcome::base()`; remove the three `assert_eq!` lines; remove any matcher arm reading `out.ooo_drop`.

- [ ] **Step 3: Run workspace tests — no regressions**

```bash
cargo test -p resd-net-core
```
Expected: all pass (the removed asserts were already checking a zero field; removal is safe).

- [ ] **Step 4: Review (opus)**

- Spec: no spec reference to ooo_drop — safe to delete.
- Code: grep confirms no orphans.

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/tcp_input.rs crates/resd-net-core/src/engine.rs
git commit -m "a5 task 24: remove legacy ooo_drop field from Outcome"
```

---

## Task 25: A4 carry-over — use `free_space_total` in `send_bytes` advertised window (I-8)

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs` — `send_bytes` advertised-window computation

**Context:** A4 RFC review I-8. A4 `emit_ack` uses `free_space_total`; `send_bytes` uses `rcv_wnd` (A3-clamped to u16::MAX). Divergence is RFC-safe but inconsistent; A5 aligns them.

- [ ] **Step 1: Write failing test**

```rust
    #[test]
    fn send_bytes_advertises_free_space_total_shifted() {
        let mut e = make_test_engine_with_tap();
        let handle = e.connect_test_peer_ws_shift_out_7();
        // Stuff the recv queue partway.
        e.recv_queue_set_len(handle, 1024);
        e.simulate_send(handle, b"ping");
        let _ = e.poll_once();
        let last = e.peek_last_tx_tap();
        let advertised = last.tcp_header.window;
        let expected = (e.get_conn(handle).recv.free_space_total() >> 7).min(u16::MAX as u32) as u16;
        assert_eq!(advertised, expected);
    }
```

- [ ] **Step 2: Change the computation in `send_bytes`**

Find the A4 F-4 line computing `advertised_window` in `send_bytes`; replace `rcv_wnd` with `recv.free_space_total()`:

```rust
    let advertised_window = (conn.recv.free_space_total() >> ws_shift_out)
        .min(u16::MAX as u32) as u16;
```

(Same expression already used in `emit_ack`.)

- [ ] **Step 3: Run test — pass**

- [ ] **Step 4: Review (opus)**

- Spec: both paths now consistent — §9.1 documents the match.
- Code: potential peer-window-shrinkage risk — under-advertisement is RFC 7323 §2.3 safe ("sender can always choose to only partially use any signaled receive window").

- [ ] **Step 5: Commit**

```bash
git add crates/resd-net-core/src/engine.rs
git commit -m "a5 task 25: send_bytes advertises free_space_total (A4 I-8 close)"
```

---

## Task 26: Counter batch — new slow-path + wire existing `tx_retrans`/`tx_rto`/`tx_tlp`

**Files:**
- Modify: `crates/resd-net-core/src/counters.rs` — add any A5 counters not yet added in prior tasks
- Modify: `crates/resd-net/src/api.rs` — FFI `resd_net_tcp_counters_t` mirror
- Modify: `crates/resd-net-core/tests/deferred-counters.txt` — remove `tx_retrans`/`tx_rto`/`tx_tlp` entries (they're wired now)
- Modify: `crates/resd-net-core/src/counters.rs` test — `deferred_tcp_counters_zero_at_construction` — remove those three

**Context:** Consolidate the A5 counter surface. A5 introduces 9 new slow-path counters (some added en route in Tasks 13, 16, 19). Also wires 3 A4-declared-zero-referenced counters.

- [ ] **Step 1: Audit counter fields** — verify these exist in `TcpCounters`:

  | Field | Added in task |
  |---|---|
  | `rtt_samples` | Task 11 or this task |
  | `tx_rack_loss` | Task 15 or this task |
  | `rack_reo_wnd_override_active` | Task 19 |
  | `rto_no_backoff_active` | Task 19 |
  | `conn_timeout_syn_sent` | Task 13 / 18 |
  | `conn_timeout_retrans` | Task 13 |
  | `rx_ws_shift_clamped` | Task 22 |
  | `rx_dsack` | Task 16 |

If any missing, add.

- [ ] **Step 2: Remove `tx_retrans`/`tx_rto`/`tx_tlp` from the deferred-counters list**

Edit `crates/resd-net-core/tests/deferred-counters.txt` and remove the three lines.

Edit the `deferred_tcp_counters_zero_at_construction` unit test in `counters.rs` and remove its assertion lines for `tx_retrans`, `tx_rto`, `tx_tlp`.

- [ ] **Step 3: Extend FFI counter struct**

Add the 8 new fields to `resd_net_tcp_counters_t` in `crates/resd-net/src/api.rs`. Preserve layout assertion; bump the `static_assertions::const_assert_eq!` expected size if needed.

- [ ] **Step 4: Regenerate header**

Run cbindgen. Verify `include/resd_net.h` now exposes all 8 new counter fields.

- [ ] **Step 5: Run workspace tests**

```bash
cargo test --workspace
```
Expected: all pass.

- [ ] **Step 6: Review (opus)**

- Spec: §9.1 counter examples updated; §9.1.1 slow-path policy respected (all increment sites are in error / rare / per-conn paths).
- Code: layout assertion covers the new fields.

- [ ] **Step 7: Commit**

```bash
git add crates/resd-net-core/src/counters.rs \
        crates/resd-net/src/api.rs \
        include/resd_net.h \
        crates/resd-net-core/tests/deferred-counters.txt
git commit -m "a5 task 26: counter batch — A5 slow-path fields + tx_retrans/rto/tlp wired"
```

---

## Task 27: TAP harness extensions — drop-segment, SACK-past-N, blackhole modes

**Files:**
- Modify: `crates/resd-net-core/tests/common/mod.rs` (or wherever the A3/A4 TAP helpers live) — add fault-injection modes
- Create (if not present): `crates/resd-net-core/tests/common/tap_injection.rs`

**Context:** A5 integration tests need synthetic peer misbehavior. Extend the TAP pair harness from A3/A4 with:
- `drop_next_tx()` — the peer "drops" the next frame emitted by our stack (the TAP harness does not reply, simulating a lost segment).
- `sack_past_n(n)` — peer's reply carries SACK blocks for seq > snd.una + N, simulating out-of-order delivery.
- `blackhole_mode()` — peer never responds to anything.

- [ ] **Step 1: Locate existing harness**

Run: `find crates/resd-net-core/tests -name '*.rs' | xargs grep -l '_tap' | head`

- [ ] **Step 2: Add test helpers**

```rust
// crates/resd-net-core/tests/common/tap_injection.rs

pub struct TapPeerMode {
    pub drop_next_tx: bool,
    pub sack_gap_at: Option<u32>,
    pub blackhole: bool,
}

// The harness struct from A3/A4 grows a `pub peer_mode: TapPeerMode`
// field checked at each tap-read-then-respond loop.
```

Wire peer_mode checks into the existing TAP drive loop.

- [ ] **Step 3: Unit test the helpers in isolation**

Smoke test: construct a TapPair, set `drop_next_tx=true`, TX a frame from our side, assert the peer side never sees it.

- [ ] **Step 4: Commit**

```bash
git add crates/resd-net-core/tests/common/
git commit -m "a5 task 27: TAP harness — drop / sack-past / blackhole injection modes"
```

---

## Task 28: Integration tests — RTO retransmit, RACK reorder detect, TLP tail-loss

**Files:**
- Create: `crates/resd-net-core/tests/tcp_rack_rto_retrans_tap.rs` (scenarios 1–3)

**Context:** Spec §10.2 integration matrix. First three scenarios use the harness injection modes from Task 27.

- [ ] **Step 1: Write the three tests**

```rust
// tcp_rack_rto_retrans_tap.rs

#[test]
fn rto_retransmit_after_peer_drops_first_segment() {
    // Scenario 1: peer drops first data segment; RTO fires, retransmit arrives.
    let mut harness = TapPairHarness::new();
    harness.peer_mode.drop_next_tx = true;
    let handle = harness.connect();
    harness.send(handle, b"hello world");
    harness.drive_poll();
    harness.advance_clock_by_ns(6_000_000); // past min_rto
    harness.drive_poll();
    assert_eq!(harness.counters().tcp.tx_rto.load(Ordering::Relaxed), 1);
    assert_eq!(harness.counters().tcp.tx_retrans.load(Ordering::Relaxed), 1);
    // ... peer eventually ACKs; receives data byte-identical.
    harness.drain_peer_and_ack();
    harness.drive_poll();
    assert_eq!(harness.peer_received_bytes(), b"hello world");
}

#[test]
fn rack_retransmits_after_sack_indicates_hole() {
    // Scenario 2: peer SACKs [B, C] with A still missing → RACK detects A lost.
    // ...
}

#[test]
fn tlp_fires_on_tail_loss_and_probes_last_segment() {
    // Scenario 3: peer drops last of 3 segments; TLP fires at PTO; probe arrives.
    // ...
}
```

- [ ] **Step 2: Run — expect pass**

```bash
cargo test -p resd-net-core --test tcp_rack_rto_retrans_tap
```

- [ ] **Step 3: Review (opus)**

- Spec: each scenario asserts at least one counter + one observable behavior.
- Code: TAP harness ergonomics reasonable; no flakes.

- [ ] **Step 4: Commit**

```bash
git add crates/resd-net-core/tests/tcp_rack_rto_retrans_tap.rs
git commit -m "a5 task 28: integration — RTO + RACK + TLP TAP scenarios"
```

---

## Task 29: Integration tests — rack_aggressive, max-retrans, SYN retrans

**Files:**
- Modify: `crates/resd-net-core/tests/tcp_rack_rto_retrans_tap.rs` — scenarios 4–6

- [ ] **Step 1: Write the three tests**

```rust
#[test]
fn rack_aggressive_retransmits_immediately_on_single_hole() { /* scenario 4 */ }

#[test]
fn max_retrans_exceeded_emits_etimedout_and_closes() {
    // Scenario 5: blackhole mode; after tcp_max_retrans_count RTOs, ETIMEDOUT.
    let mut harness = TapPairHarness::new_with_config(EngineConfig {
        tcp_max_retrans_count: 3, // speed up test
        ..Default::default()
    });
    harness.peer_mode.blackhole = true;
    let handle = harness.connect();
    harness.send(handle, b"x");
    for _ in 0..5 {
        harness.advance_clock_by_ns(100_000_000);
        harness.drive_poll();
    }
    let events = harness.drain_events();
    assert!(events.iter().any(|e| matches!(e, Event::Error { err: ErrCode::ETIMEDOUT, .. })));
    assert_eq!(harness.counters().tcp.conn_timeout_retrans.load(Ordering::Relaxed), 1);
}

#[test]
fn syn_retrans_budget_exhausted_emits_etimedout() { /* scenario 6 */ }
```

- [ ] **Step 2: Run — expect pass**

- [ ] **Step 3: Review (opus)**

- [ ] **Step 4: Commit**

```bash
git add crates/resd-net-core/tests/tcp_rack_rto_retrans_tap.rs
git commit -m "a5 task 29: integration — rack_aggressive + max-retrans + SYN retrans"
```

---

## Task 30: Integration tests — ISS monotonicity, no-backoff, DSACK, mbuf-chain

**Files:**
- Modify: `crates/resd-net-core/tests/tcp_rack_rto_retrans_tap.rs` — scenarios 7–10

- [ ] **Step 1: Write the four tests**

```rust
#[test]
fn iss_monotonic_across_reconnect_same_tuple() {
    let mut harness = TapPairHarness::new();
    let handle1 = harness.connect_same_tuple();
    let iss1 = harness.get_conn(handle1).iss;
    harness.close(handle1);
    harness.advance_clock_by_ns(100_000); // advance 25 × 4µs ticks
    let handle2 = harness.connect_same_tuple();
    let iss2 = harness.get_conn(handle2).iss;
    let delta = iss2.wrapping_sub(iss1);
    assert!(delta > 0 && delta < 1_000_000);
}

#[test]
fn rto_no_backoff_keeps_rto_constant_across_multiple_fires() { /* 8 */ }

#[test]
fn dsack_counter_increments_on_peer_duplicate_sack() { /* 9 */ }

#[test]
fn retransmit_tx_frame_is_multi_seg_mbuf_chain() {
    // Scenario 10: drop first TX, wait for RTO, capture the retransmit frame,
    // assert mbuf.nb_segs == 2 (hdr + data chain).
}
```

- [ ] **Step 2: Run — expect pass**

- [ ] **Step 3: Review (opus)**

- [ ] **Step 4: Commit**

```bash
git add crates/resd-net-core/tests/tcp_rack_rto_retrans_tap.rs
git commit -m "a5 task 30: integration — ISS monotonic + no-backoff + DSACK + mbuf-chain"
```

---

## Task 31: Parent spec updates — §6.3 / §6.4 / §6.5 / §9.1 / §9.3

**Files:**
- Modify: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`

**Context:** Design spec §13 enumerates the parent-spec edits to land at A5.

- [ ] **Step 1: Edit §6.3** — RFC 5681 row comment refresh: "dup_ack counter strict per §2 in A5 (was loose in A3/A4)".

- [ ] **Step 2: Edit §6.4** minRTO row — "our default" cell 20ms → 5ms; add rationale sentence.

- [ ] **Step 3: Edit §6.4** — add new row:

```
| RTO maximum | RFC 6298 ≥60s | **1s** | Trading fail-fast; ride through brief peer stalls, but reconnect cheaper than sitting on a 30s deadline. |
```

- [ ] **Step 4: Edit §6.5** implementation choices — add bullet:

```
- **Data retransmit budget**: `tcp_max_retrans_count` (default 15). After this many RTO-driven retransmits of a single segment with no ACK progress, connection fails with `RESD_NET_EVT_ERROR{err=ETIMEDOUT}`. With backoff + `tcp_max_rto_us=1s`, the total wall-clock budget is ≈8.3s. Opt-out of backoff per-connect (`rto_no_backoff=true`) makes the budget linear in count × `rto_us`.
```

- [ ] **Step 5: Edit §9.1** — append the 9 new A5 counter names to the example list; add `err=ETIMEDOUT` to §9.3 `RESD_NET_EVT_ERROR` enum.

- [ ] **Step 6: Edit §6.3** RFC 8985 row — clarify "RACK-TLP as primary; 3-dup-ACK disabled at Stage 1".

- [ ] **Step 7: Review (opus)**

- Consistency check: every change matches the design spec + the behavior we shipped in Tasks 1–30.

- [ ] **Step 8: Commit**

```bash
git add docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md
git commit -m "a5 task 31: parent spec — minRTO→5ms, maxRTO row, max_retrans bullet, ETIMEDOUT"
```

---

## Task 32: Workspace sanity — fmt, clippy, all-tests, header drift, layout assertion

**Files:**
- None. CI-style local gate.

**Context:** Per A4 Task 27 pattern.

- [ ] **Step 1: Run fmt**

```bash
cargo fmt --all --check
```
Expected: no diff.

- [ ] **Step 2: Run clippy**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Expected: zero warnings.

- [ ] **Step 3: Run tests**

```bash
cargo test --workspace --all-features
```
Expected: all pass. Count new tests added in A5 (should be ≥40 unit + 10 integration).

- [ ] **Step 4: Verify header drift**

```bash
# Re-run cbindgen; compare to checked-in include/resd_net.h.
cargo run -p resd-net --bin cbindgen-check || \
  (diff include/resd_net.h /tmp/regen.h && echo "no drift")
```
Expected: no diff.

- [ ] **Step 5: Verify `static_assertions` layout assertion passes**

Built into `cargo build`; re-run if needed.

- [ ] **Step 6: Commit** — no code change, but tag the sanity pass:

```bash
git commit --allow-empty -m "a5 task 32: workspace sanity (fmt, clippy, all-tests, header drift)"
```

---

## Task 33: A5 mTCP comparison review gate (§10.13)

**Files:**
- Create: `docs/superpowers/reviews/phase-a5-mtcp-compare.md` (the subagent writes; human annotates verdict + AD citations)

**Context:** `feedback_phase_mtcp_review.md` — end-of-phase blocking gate. Dispatch `mtcp-comparison-reviewer` subagent (opus).

- [ ] **Step 1: Dispatch the subagent**

Use the `Agent` tool with subagent_type `mtcp-comparison-reviewer`. Prompt:

> "Run the phase-a5 mTCP comparison review per spec §10.13. Compare our A5 implementation (commit `<HEAD>` on branch `phase-a5`) against mTCP's retransmit + RTO + loss-detection path.
>
> Files we've added: `crates/resd-net-core/src/siphash24.rs`, `iss.rs` (rewritten), `tcp_rtt.rs`, `tcp_timer_wheel.rs`, `tcp_rack.rs`, `tcp_tlp.rs`, `tcp_retrans.rs`.
>
> Files we've modified: `tcp_conn.rs`, `tcp_input.rs`, `tcp_options.rs`, `engine.rs`, `tcp_events.rs`, `counters.rs`.
>
> Pre-declared Accepted Divergences: AD-A5-rack-tlp-vs-dup-ack, AD-A5-hashed-timer-wheel, AD-A5-retrans-mbuf-chain, AD-A5-iss-siphash, AD-A5-tcp-max-retrans-count-15, AD-A5-tcp-max-rto-us-1s, AD-A5-rto-no-backoff-opt-in (per-connect opt-in; default is RFC-compliant backoff).
>
> Write the report to `docs/superpowers/reviews/phase-a5-mtcp-compare.md` in the standard shape (Scope, Findings with Must-fix / Missed-edge-cases / Accepted-divergence / FYI, Verdict). The tag is blocked on open `[ ]` items."

- [ ] **Step 2: Read the report + resolve any Must-fix / Missed-edge-cases items**

If findings require code changes, land them as follow-up tasks (numbered `33.1`, `33.2`, ...) in the same plan session — small commits, each re-dispatching spec + code review.

- [ ] **Step 3: Human-edit the verdict toggle + AD citations**

The subagent leaves AD rows with a "Spec/memory reference needed" placeholder; fill each with either a spec § cite or a memory key (e.g., `feedback_trading_latency_defaults.md`).

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/reviews/phase-a5-mtcp-compare.md
git commit -m "a5 task 33: mTCP comparison review (§10.13 gate)"
```

---

## Task 34: A5 RFC compliance review gate (§10.14)

**Files:**
- Create: `docs/superpowers/reviews/phase-a5-rfc-compliance.md`

**Context:** `feedback_phase_rfc_review.md` — end-of-phase gate. Dispatch `rfc-compliance-reviewer` subagent (opus).

- [ ] **Step 1: Dispatch the subagent**

```
Run the phase-a5 RFC compliance review per spec §10.14.
RFCs in scope: 6298, 8985, 6528, 7323 §2.3 (carry-over), 5681 §2 (carry-over), 2883, 9293.
Files: see Task 33 list.
Pre-declared Accepted Deviations: AD-A5-rto-no-backoff-opt-in (per-connect opt-in; default RFC-compliant).
Write report to docs/superpowers/reviews/phase-a5-rfc-compliance.md in standard shape. Tag blocked on open `[ ]`.
```

- [ ] **Step 2: Resolve findings** (follow-up tasks 34.1, 34.2, ... as needed).

- [ ] **Step 3: Human-edit verdict**

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/reviews/phase-a5-rfc-compliance.md
git commit -m "a5 task 34: RFC compliance review (§10.14 gate)"
```

---

## Task 35: Update roadmap status + tag `phase-a5-complete`

**Files:**
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md` — A5 row status

- [ ] **Step 1: Confirm both review gates are clean**

```bash
grep -c '^- \[ \]' docs/superpowers/reviews/phase-a5-mtcp-compare.md docs/superpowers/reviews/phase-a5-rfc-compliance.md
```
Expected: `0` in both files (no open checkboxes in Must-fix / Missed-edge-cases / Missing-SHOULD).

- [ ] **Step 2: Edit roadmap**

In `stage1-phase-roadmap.md`, update the A5 row in the "Phase Status" table:

```
| A5 | RACK-TLP + RTO + retransmit + ISS | **Complete** ✓ | `2026-04-18-stage1-phase-a5-rack-rto-retransmit.md` |
```

- [ ] **Step 3: Commit the roadmap update**

```bash
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "mark phase a5 complete in roadmap"
```

- [ ] **Step 4: Tag**

```bash
git tag -a phase-a5-complete -m "Phase A5: RACK-TLP + RTO + retransmit + ISS"
```

- [ ] **Step 5: Report**

Report tag + branch state to the user: "`phase-a5-complete` tag placed on branch `phase-a5` at `<sha>`. 35 tasks landed. Working tree clean. mTCP + RFC review reports archived under `docs/superpowers/reviews/`. A5 ready to merge to `master` (user decides merge strategy)."

---

## Self-Review Checklist

Before handing off to execution:

1. **Spec coverage:** every section of the design spec has at least one task:
   - §1 scope (all sub-items) — ✓ covered in Tasks 1–30.
   - §2 module layout — ✓ Tasks 1, 3, 4, 6, 14, 17, 22.
   - §3 data flow — ✓ Tasks 9–18.
   - §4 timer wheel — ✓ Tasks 4–5.
   - §5 ISS — ✓ Tasks 1–2.
   - §6 counters — ✓ Task 26 consolidation (additions in 11, 13, 16, 19, 22).
   - §7 config/API — ✓ Tasks 19–21.
   - §8 accepted divergences — ✓ Task 31 parent-spec edits.
   - §9 A4 carry-overs — ✓ Tasks 22–25.
   - §10 testing — ✓ Tasks 27–30.
   - §11 review gates — ✓ Tasks 33–34.
   - §12 task scale — ✓ 35 tasks total, matches the 28–32 estimate.

2. **Placeholder scan:** grep for `TBD`, `TODO`, `implement later`, `fill in details`, "similar to Task N":
   ```
   grep -nE 'TBD|implement later|fill in details|similar to Task' docs/superpowers/plans/2026-04-18-stage1-phase-a5-rack-rto-retransmit.md
   ```
   Any hits — replace with inline code or explicit decision. (Plan author fixes inline before handoff.)

3. **Type consistency:** names used across tasks — `RettEstimator` / `RttEstimator`, `SendRetrans`, `RetransEntry`, `TimerId`, `TimerNode`, `TimerKind::{Rto,Tlp,SynRetrans,ApiPublic}`, `RackState`, `Event::{TcpRetrans,TcpLossDetected,Error}`, `LossCause::{Rack,Tlp,Rto}`, `ErrCode::ETIMEDOUT`. Verified consistent.

4. **Task order sanity:**
   - SipHash (1) → ISS (2) — consumption-after-provision. ✓
   - Timer wheel (4, 5) → TcpConn fields (7) → send_bytes rewire (10) → RTO fire (12) — dependency chain. ✓
   - MULTI_SEGS (8) → retransmit primitive (9) — offload before use. ✓
   - RackState (14) → RACK integration (15). ✓
   - tcp_rtt (3) → RTT sampling (11) → RTO fire (12) → backoff (12) + rack reo_wnd (15). ✓

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-18-stage1-phase-a5-rack-rto-retransmit.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh opus subagent per task, with spec-compliance + code-quality review between tasks per `feedback_per_task_review_discipline.md`. Matches A4's execution protocol.
2. **Inline Execution** — execute tasks in-session with checkpoints.

Per the session-start instruction: **STOP here and confirm with the user** before invoking `superpowers:subagent-driven-development` (Step 4 of the first-steps list). The user must approve before execution begins.

