# Phase A5 — RACK-TLP + RTO + Retransmit + ISS (Design Spec)

**Status:** draft for plan-writing.
**Parent spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` — A5.
**Branch:** `phase-a5` (off `bc595df`, A4 tip).
**Ships:** `phase-a5-complete` tag gated on mTCP + RFC review reports.

---

## 1. Scope

A5 lands TCP loss detection + recovery + retransmission on top of A4's option-negotiated SACK scoreboard, plus finalizes the ISS generator that A3 scaffolded.

In scope:
- **RFC 8985 RACK-TLP** (subset "b" per brainstorming): reorder-detection, TLP probe, DSACK detection as a visibility counter. No dynamic reo_wnd adaptation, no RFC 5682 F-RTO.
- **RFC 6298 RTO** with RFC 7323 TS-sampled RTT (+ Karn's fallback). Classic Jacobson/Karels (α=1/8, β=1/4). Backoff enabled by default; per-connect opt-out knob.
- **Retransmit path** per spec §5.3 / §6.5: fresh header mbuf chained to the original data mbuf — never edit in-flight mbufs in place.
- **SYN retransmit** per spec §6.5: 3 attempts, exponential backoff bounded by `connect_timeout_ms`.
- **Internal timer wheel** per spec §7.4 (hashed, 8 levels × 256 buckets, 10µs resolution, tombstone cancel, per-conn timer list). A5 consumes internally for RTO/TLP/SYN retransmit. A6 adds the public `dpdk_net_timer_add` / `cancel` / `TIMER` API layer on top.
- **ISS finalize** per spec §6.5: hand-written SipHash-2-4, boot_nonce from `/proc/sys/kernel/random/boot_id`, 4µs tick clock.
- **A4 carry-overs** close: WS>14 SHOULD-log + counter (RFC 7323 §2.3), dup_ack strict RFC 5681 §2, WS≤14 decoder-side enforcement, `ooo_drop` legacy-field removal, A4 I-8 `rcv_wnd` vs `free_space_total` divergence in `send_bytes`.
- **Counters**: wire `tx_retrans`, `tx_rto`, `tx_tlp` (declared but zero-referenced in A4); add `tx_rack_loss`, `rtt_samples`, `rack_reo_wnd_override_active`, `rto_no_backoff_active`, `conn_timeout_syn_sent`, `conn_timeout_retrans`, `rx_ws_shift_clamped`, `rx_dsack`. All slow-path per §9.1.1.
- **Events**: `DPDK_NET_EVT_TCP_RETRANS`, `DPDK_NET_EVT_TCP_LOSS_DETECTED` gated by new `tcp_per_packet_events` config; `DPDK_NET_EVT_ERROR{err=ETIMEDOUT}` on max-retrans-count or SYN-retrans-budget exhaustion.

Out of scope (A5.1 / A6 / A-HW):
- Congestion control (Reno `cc_mode`) — full punt to A5.1 "if/when needed in test". `cwnd`/`ssthresh` fields are **not** introduced by A5.
- RFC 5682 F-RTO — explicitly out per brainstorming.
- RFC 8985 dynamic reo_wnd adaptation — DSACK is counter-only; reo_wnd is `min(SRTT/4, min_RTT/2)` with no dynamic adjustment beyond that.
- Public timer API (`dpdk_net_timer_add` / `cancel` / `TIMER` event) — A6's scope.
- RFC 7323 §5.5 24-day TS.Recent expiration — punt to A6 (needs public timer API; Stage 1 trading flows don't idle 24 days per spec).
- A4 AD `AD-A4-sack-generate` — stays indefinitely (we generate SACK blocks; mTCP has TODO stub).

---

## 2. Module layout

### 2.1 New modules (`crates/dpdk-net-core/src/`)

| Module | Purpose |
|---|---|
| `siphash24.rs` | Hand-written SipHash-2-4 primitive (~60 LOC). Test vectors from the SipHash reference (Aumasson/Bernstein 2012, 64 vectors). No new crate dependency. |
| `tcp_timer_wheel.rs` | Internal hashed timing wheel per spec §7.4. 8 levels × 256 buckets, 10µs resolution, ~68s horizon. Tombstone cancel via per-node generation counter. Per-conn timer-id list for O(k) close-path cancellation. Public surface is crate-internal only. |
| `tcp_rtt.rs` | RFC 6298 Jacobson/Karels RTT estimator. Fields `srtt`, `rttvar`, `rto`. α=1/8, β=1/4. `sample(rtt_us)`, `rto_us() -> u32`, `apply_backoff()` (doubles current RTO, caps at `tcp_max_rto_us`). `apply_backoff` is skipped when the owning conn has `rto_no_backoff=true`. |
| `tcp_rack.rs` | RFC 8985 RACK state + loss-detection pass. Fields `xmit_ts`, `end_seq`, `reo_wnd`, `min_rtt`, `dsack_seen`. `update_on_ack(entry, now)`, `detect_lost(entry, now) -> bool` (§6.2 rule). `compute_reo_wnd(rack_aggressive, min_rtt, srtt)` — returns 0 when `rack_aggressive=true`, else `min(srtt/4, min_rtt/2)`. |
| `tcp_tlp.rs` | RFC 8985 §7 PTO computation + probe-type selection. `pto_us(srtt_us, min_rto_us) -> u32` = `max(2·srtt, min_rto)`. `select_probe(snd_pending_nonempty, snd_retrans_back) -> Probe` — new-data probe if pending bytes available, else last-segment retransmit probe. |
| `tcp_retrans.rs` | `SendRetrans { entries: VecDeque<RetransEntry> }` — per-conn in-flight-segment tracker. `RetransEntry { seq, len, mbuf: Mbuf, first_tx_ts_ns, xmit_count, sacked: bool, lost: bool }`. Methods: `push_after_tx`, `prune_below(snd_una)`, `mark_sacked(left, right)`, `oldest_unacked`, `iter_for_rack_pass`, `is_empty`. |

### 2.2 Modified modules

| Module | Change |
|---|---|
| `iss.rs` | Replace `DefaultHasher` with `siphash24`. Read `boot_nonce` from `/proc/sys/kernel/random/boot_id` at `IssGen::new_engine()`; fallback to `getrandom`-style process-random if the file is unreadable. Clock source switches from `clock::now_ns()/1000` (1µs) to `clock::now_ns()/4000` (4µs ticks) per spec §6.5. |
| `tcp_conn.rs` | Add fields: `snd_retrans: SendRetrans`, `rtt_est: RttEstimator`, `rack: RackState`, `rto_timer_id: Option<TimerId>`, `tlp_timer_id: Option<TimerId>`, `rack_aggressive: bool`, `rto_no_backoff: bool`, `syn_retrans_count: u8`, `syn_retrans_timer_id: Option<TimerId>`. Keep `snd.pending` (bytes accepted from user but not yet TX'd); `snd_retrans` holds mbuf refs of TX'd-but-unACKed bytes. |
| `tcp_input.rs` | RTT sample extraction (TS.Ecr preferred; Karn's fallback from non-retransmitted entries matched by ACK seq). Feed RACK on every ACK. Prune `snd_retrans` on `snd.una` advance. DSACK detection via SACK-block comparison against `snd.una` and prior SACKed ranges. Tighten dup_ack detection to RFC 5681 §2 5-condition strict check. Drop `ooo_drop` field from `Outcome` and call sites. |
| `tcp_options.rs` | WS parser-side clamp: if the Window Scale option carries shift > 14, store `14` at parse time (defense-in-depth on top of the A4 handshake-site clamp in `tcp_input.rs`). Add a parser-level "clamp applied" signal for the one-shot log counter. |
| `engine.rs` | Send path: clone mbuf ref into `snd_retrans` instead of freeing after TX. New retransmit primitive (fresh hdr mbuf from `tx_hdr_mempool` chained to held data mbuf). ACK handler invokes RTO re-arm lazily (spec §6.5). New RTO / TLP fire handlers. New SYN-retransmit scheduler + timer. `build_ack_outcome` uses `free_space_total` for advertised window (A4 I-8 close). `send_bytes` also uses `free_space_total` symmetrically (A4 I-8 close). WS>14 one-shot log + `tcp.rx_ws_shift_clamped++`. Enable `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` in port config. |
| `tcp_events.rs` | Add `DPDK_NET_EVT_TCP_RETRANS`, `DPDK_NET_EVT_TCP_LOSS_DETECTED`. Extend `DPDK_NET_EVT_ERROR` with `err=ETIMEDOUT`. |
| `counters.rs` | Add new fields: `tx_rack_loss`, `rtt_samples`, `rack_reo_wnd_override_active`, `rto_no_backoff_active`, `conn_timeout_syn_sent`, `conn_timeout_retrans`, `rx_ws_shift_clamped`, `rx_dsack`. All `AtomicU64`, slow-path. Remove entries for `tx_retrans`/`tx_rto`/`tx_tlp` from the deferred-counters whitelist; they are now wired. |
| `lib.rs` | Export new modules. |
| `include/dpdk_net.h` (cbindgen) | Add `tcp_min_rto_us`, `tcp_initial_rto_us`, `tcp_max_rto_us`, `tcp_max_retrans_count`, `tcp_per_packet_events` on engine config. Remove `tcp_initial_rto_ms` (replaced by `_us` variant). Add `rack_aggressive`, `rto_no_backoff` on `dpdk_net_connect_opts_t`. New event types + `err=ETIMEDOUT`. |

### 2.3 Dependencies introduced

- DPDK `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` bit must be set in port config; ENA advertises this per spec §8.2 so no runtime capability gate is needed on the reference target. A-HW later folds this into its feature-flag matrix without rewiring the code path.
- `getrandom` or equivalent process-random source for the `boot_id`-read fallback. Preferred path is reading `/proc/sys/kernel/random/boot_id` (a stable 128-bit value surviving process restart). If that path fails (non-Linux, chroot, etc.), fall back to a one-time per-engine random via `getrandom` (or `rte_rand` if already linked). Track in plan under the ISS-finalize task.

---

## 3. Data flow

### 3.1 TX first-send

```
dpdk_net_send(bytes)
  → snd.pending.push(bytes)                                 // bounded by send_buffer_bytes
  → engine poll drains snd.pending into MSS-sized mbufs
    from tx_data_mempool                                    // memcpy user bytes into mbuf.data
    → snd.pending.drop(consumed_len)                        // bytes leave snd.pending at TX time
    → build TCP header into reserved headroom
    → first_tx_ts_ns = clock::now_ns()
    → rte_eth_tx_burst(mbuf)
    → rte_mbuf_refcnt_update(mbuf, +1)                      // clone ref for snd_retrans
    → snd_retrans.push_after_tx(RetransEntry {
         seq, len, mbuf, first_tx_ts_ns, xmit_count: 1,
         sacked: false, lost: false,
       })
    → if snd_retrans was empty before this push:
        arm RTO timer at now + rto_us() via wheel           // sets conn.rto_timer_id
```

**`snd.pending` lifetime change vs A3**: in A3 bytes stay in `snd.pending` until ACKed. In A5 bytes leave `snd.pending` at TX time; the in-flight tracking moves to `snd_retrans` (mbuf-backed). A5 drops this behavior from A3 as part of the `send_bytes` rewire task.

### 3.2 ACK receive

```
tcp_input on ACK
  → RTT sample:
      if conn.ts_enabled && seg.tsopt.present:
         rtt_us = (now_us - seg.tsopt.ecr)                  // TS-source sample
      else if snd_retrans.front().xmit_count == 1 &&
              seg.ack_seq > snd_retrans.front().seq:
         rtt_us = (now_us - entry.first_tx_ts_us)           // Karn's source sample
      else: skip sample                                     // Karn's prohibits during retransmits
      rtt_est.sample(rtt_us); tcp.rtt_samples++
      rto_us = max(srtt + 4·rttvar, tcp_min_rto_us)
      rto backoff state resets implicitly (sample produces
      fresh value regardless of prior backoff)

  → snd_retrans.prune_below(seg.ack_seq)
      // each pruned entry: rte_mbuf_refcnt_update(-1); pool free on refcnt==0

  → if seg has SACK blocks:
      for block in sack_blocks:
        // DSACK detection (RFC 2883 §4): first SACK block whose range
        // is ≤ snd.una (already-cumulative-acked) OR fully inside a
        // range already present in conn.sack_scoreboard → DSACK.
        if dsack_block(block, snd.una, conn.sack_scoreboard):
          tcp.rx_dsack++
          // visibility only; no behavioral adaptation in Stage 1
          // (no dynamic reo_wnd, no reneging-safe scoreboard prune)
        snd_retrans.mark_sacked(block.left, block.right)
        conn.sack_scoreboard.insert(block)                   // A4 scoreboard already present

  → rack.update_on_ack(entries_newly_acked_or_sacked, now_ns)
      // updates rack.xmit_ts / end_seq / min_rtt

  → rack loss-detect pass:
      reo_wnd = rack.compute_reo_wnd(conn.rack_aggressive, min_rtt, srtt)
      for entry in snd_retrans.iter_for_rack_pass():
        if !entry.sacked && rack.detect_lost(entry, now, reo_wnd):
          entry.lost = true
          retransmit(entry)                                 // see 3.3
          tcp.tx_rack_loss++

  → TLP scheduling:
      if !snd_retrans.is_empty() && no TLP pending:
        schedule TLP at now + pto_us(srtt, min_rto_us)
        → sets conn.tlp_timer_id

  → lazy RTO re-arm:
      if snd.una advanced: leave existing wheel entry alone
      if snd_retrans.is_empty() && snd.una == snd.nxt:
        cancel conn.rto_timer_id (tombstone)
```

### 3.3 Retransmit primitive (shared by RACK, RTO, TLP, SYN)

```
retransmit(entry):
  hdr_mbuf = tx_hdr_mempool.alloc()
  if hdr_mbuf is null:
    eth.tx_drop_nomem++
    return                                                  // drop; next RTO fire retries (idempotent)

  write L2 + L3 + TCP headers into hdr_mbuf
    // TSval = now_us / 1 (current §4.1 µs tick, matches A4)
    // TSecr = conn.ts_recent
  rte_mbuf_refcnt_update(entry.mbuf, +1)                    // chain takes another ref
  rte_pktmbuf_chain(hdr_mbuf, entry.mbuf)

  rte_eth_tx_burst(hdr_mbuf)
  entry.xmit_count += 1
  tcp.tx_retrans++
  if tcp_per_packet_events: emit DPDK_NET_EVT_TCP_RETRANS

  if entry.xmit_count > tcp_max_retrans_count:              // default 15
    tcp.conn_timeout_retrans++
    emit DPDK_NET_EVT_ERROR{err=ETIMEDOUT}
    drain snd_retrans (drop mbuf refs)
    transition to CLOSED
```

### 3.4 RTO fire

```
wheel tick → RtoTimer.on_fire(handle, gen):
  if tombstone.gen != gen: no-op                            // cancelled
  conn = flow_table.get_mut(handle)
  if snd.una >= snd.nxt:
    clear conn.rto_timer_id
    return                                                  // nothing in flight
  retransmit(snd_retrans.front())
  tcp.tx_rto++
  if !conn.rto_no_backoff:
    rtt_est.apply_backoff()                                 // rto_us = min(rto_us*2, tcp_max_rto_us)
  re-arm at now + rtt_est.rto_us()
```

### 3.5 TLP fire

```
wheel tick → TlpTimer.on_fire(handle, gen):
  if tombstone.gen != gen: no-op
  conn = flow_table.get_mut(handle)
  if snd_retrans.is_empty(): return
  if snd.pending nonempty:
    probe with next MSS of new data                         // covers "tail loss with more to send"
  else:
    retransmit(snd_retrans.back())                          // last-segment probe
  tcp.tx_tlp++
  if tcp_per_packet_events: emit DPDK_NET_EVT_TCP_LOSS_DETECTED
```

### 3.6 SYN retransmit

```
Schedule: on initial SYN TX, arm SYN timer at
    max(tcp_initial_rto_us, tcp_min_rto_us)
Each fire: re-emit SYN, syn_retrans_count++, re-arm doubled
Terminate on:
  - SYN-ACK received (normal path; cancel timer)
  - syn_retrans_count > 3 OR total elapsed > connect_timeout_ms:
      tcp.conn_timeout_syn_sent++
      emit DPDK_NET_EVT_ERROR{err=ETIMEDOUT}
      transition to CLOSED
```

---

## 4. Timer wheel (internal, §7.4)

- 8 levels × 256 buckets = 2048 slots per wheel instance.
- Resolution: 10µs. Horizon (level 7): `256^8 * 10µs` ≫ 68s — well over the MSL=60s + 2·MSL long timer case. Actual scheduling demotes timers with deadline > level_0_horizon into higher levels; fire-time recomputation at each demotion.
- `now_tick > last_ticked_tick` gate skips wheel walking entirely on poll iterations where no tick has elapsed (common at high poll rates).
- Each scheduled timer node carries: `fire_at_ns`, `owner_handle`, `kind` (RTO / TLP / SYN / A6-public), `generation` (tombstone counter).
- Cancel is O(1): bump `generation` on the owning slot; fire handlers compare generation and no-op on mismatch. Storage reclaimed when the slot's wheel tick is reached.
- Per-conn timer-list: each `TcpConn` owns `Vec<TimerId>` of its scheduled timers. `close_conn` walks the list and tombstones each — O(k) for k typically ≤4 per connection (RTO + TLP + SYN + A6-public-timer).
- The wheel is per-lcore (RTC thread model, spec §3). No locks, no atomics on wheel state.

---

## 5. ISS finalize (§6.5)

```
// SipHash-2-4 is keyed on `secret`; `boot_nonce` is mixed into the
// message so per-boot ISS values don't collide with a prior boot's
// values even if `secret` is re-derived identically.
ISS = (monotonic_time_4µs_ticks_low_32)
    + siphash24(key = secret,
                msg = local_ip ‖ local_port ‖ remote_ip ‖ remote_port ‖ boot_nonce).low_32
```

- `secret`: 128-bit per-process random SipHash-2-4 **key**, initialized once at first `engine_create` and shared across engines in the same process. Derived from `getrandom` (or `rte_rand` if already linked); documented in the ISS-finalize task.
- `boot_nonce`: 128 bits from `/proc/sys/kernel/random/boot_id`. Treated as **message material**, not key material, so the SipHash `(key, msg)` contract is clean. If the file is unreadable, fall back to a per-engine random (documented as a degraded mode; logs a one-time warning).
- Clock: `clock::now_ns() / 4000` (4µs ticks) low 32 bits. Added **outside** the SipHash so reconnects to the same 4-tuple within MSL yield monotonically-increasing ISS.
- RFC 6528 §3 compliance: the hash output is keyed on an attacker-unknown secret, satisfying the "unpredictable-to-the-peer" requirement. The 4µs clock delta across reconnects ensures strict monotonicity within the same process even at sub-ms reconnect intervals.

---

## 6. Counter surface (§9.1.1, all slow-path)

| Counter (group.name) | When incremented |
|---|---|
| `tcp.tx_retrans` | Every retransmit regardless of cause |
| `tcp.tx_rto` | RTO-driven retransmit (subset of `tx_retrans`) |
| `tcp.tx_tlp` | TLP probe fired |
| `tcp.tx_rack_loss` | RACK detect-lost rule fired and retransmit was queued |
| `tcp.rtt_samples` | RTT sample absorbed by estimator (TS or Karn's) |
| `tcp.rack_reo_wnd_override_active` | Once at `connect` when `rack_aggressive=true` |
| `tcp.rto_no_backoff_active` | Once at `connect` when `rto_no_backoff=true` |
| `tcp.conn_timeout_syn_sent` | SYN retransmit budget exhausted; conn ETIMEDOUT |
| `tcp.conn_timeout_retrans` | Data retransmit budget (`tcp_max_retrans_count`) exhausted; conn ETIMEDOUT |
| `tcp.rx_ws_shift_clamped` | WS option > 14 clamped (A4 I-9 close) |
| `tcp.rx_dsack` | DSACK range observed (visibility; no behavior change) |

All increment sites are in error paths, rare-event handlers, or per-connection lifecycle — none are on the per-segment or per-poll hot path.

**Events added (spec §9.3)**:
- `DPDK_NET_EVT_TCP_RETRANS` — per-retransmit, gated by `tcp_per_packet_events`.
- `DPDK_NET_EVT_TCP_LOSS_DETECTED` — per-loss-detection-trigger (RACK flag OR TLP fire OR RTO fire), gated by `tcp_per_packet_events`.
- `DPDK_NET_EVT_ERROR{err=ETIMEDOUT}` — unconditional (always emitted).

---

## 7. Config / API surface changes

### 7.1 `dpdk_net_engine_config_t` (additions)

| Field | Type | Default | Notes |
|---|---|---|---|
| `tcp_min_rto_us` | `u32` | 5000 (5ms) | RFC 6298 min floor; conservative for WAN jitter |
| `tcp_initial_rto_us` | `u32` | 5000 (5ms) | First-RTO value before any RTT sample |
| `tcp_max_rto_us` | `u32` | 1_000_000 (1s) | Backoff cap; trading-aligned fail-fast (RFC 6298 allows 60s) |
| `tcp_max_retrans_count` | `u32` | 15 | Per-segment retransmit count before ETIMEDOUT. With default backoff cap hits ≈8.3s total budget |
| `tcp_per_packet_events` | `bool` | false | Gates `DPDK_NET_EVT_TCP_RETRANS` and `_LOSS_DETECTED` |

### 7.2 `dpdk_net_engine_config_t` (removals)

- `tcp_initial_rto_ms`: replaced by `tcp_initial_rto_us`. Header regen + consumer update.

### 7.3 `dpdk_net_connect_opts_t` (additions)

| Field | Type | Default | Notes |
|---|---|---|---|
| `rack_aggressive` | `bool` | false | When true, RACK `reo_wnd = 0` — any SACK-inferred hole triggers immediate retransmit. For order-entry sockets |
| `rto_no_backoff` | `bool` | false | When true, RTO is not doubled across retransmits (stays at `rtt_est.rto_us()`) |

### 7.4 Error code

- `DPDK_NET_EVT_ERROR.err` adds `ETIMEDOUT` — SYN-retrans-budget or data-retrans-count exhaustion.

---

## 8. Accepted divergences (new, for §6.4)

None expected at design time. Analysis:

- **`AD-A5-no-rto-backoff` was considered but dropped**: default is RFC-6298-compliant backoff; the opt-out is per-connect and does not affect the spec-defaults RFC matrix.
- **`AD-A5-rack-aggressive-reo-wnd` (per-connect)**: `reo_wnd=0` is **within RFC 8985 allowance** — §6.2 defines `RACK.reo_wnd` as `min(SRTT/4, min_RTT/2)` *but* explicitly permits values below when the sender elects tighter timing. Our opt-in knob stays spec-conformant. No AD entry needed.
- **`AD-A5-tcp-min-rto-us` default 5ms**: already covered by spec §6.4's existing `minRTO` entry (deviates from RFC 6298 RECOMMENDS 1s down to 20ms; we went one step further to 5ms on the same rationale of intra-region WAN RTT). Update the existing entry's "our default" cell from "20ms" to "5ms" and strengthen the rationale to cite exchange-direct RTT of 50–100µs. No new AD.
- **`AD-A5-tcp-max-rto-us` cap 1s**: RFC 6298 §5.5 says max RTO of "60 seconds or more" — our 1s cap is a deviation. Add new §6.4 row: "RTO maximum | RFC 6298 ≥60s | **1s** | trading fail-fast; ride through brief peer stalls, but reconnect cheaper than sitting on a 30s deadline."
- **`AD-A5-tcp-max-retrans-count` 15**: RFC 6298 does not specify a per-segment retransmit count (total time budget is the RFC concept). Our 15-count is a derived fail-fast knob. Not an RFC deviation strictly but worth listing under §6.4 for completeness, or noting in §6.5 implementation choices.

The mTCP reviewer agent will independently flag any divergences from mTCP's approach (mTCP uses a simpler per-conn RTO timer list without a hashed wheel; if that creates a surface worth documenting, the reviewer's AD entries land in `phase-a5-mtcp-compare.md`).

---

## 9. A4 carry-over closes

| Item | Source | Close site |
|---|---|---|
| WS>14 SHOULD-log | A4 RFC I-9 | `tcp_input.rs` SYN-ACK install path: one-shot log + `tcp.rx_ws_shift_clamped++` per conn on first clamp |
| dup_ack strict RFC 5681 §2 | A4 mTCP I-10 | `tcp_input.rs` ACK handler: check (1) outstanding data, (2) ACK carries no data, (3) `ack_seq == snd.una`, (4) conn in ESTABLISHED/CLOSE_WAIT/FIN_WAIT_1/FIN_WAIT_2, (5) advertised window equals current send window, before bumping `tcp.rx_dup_ack`. RACK rewrites the call site anyway |
| WS≤14 decoder-side enforcement | user | `tcp_options.rs` parser clamps shift to 14 at parse time; returns a clamp-applied signal upward for counter/log |
| `ooo_drop` legacy field | user | Delete field from `Outcome` struct; remove three zero-assertion tests; remove any matcher references |
| A4 I-8 `rcv_wnd` vs `free_space_total` divergence in `send_bytes` | A4 RFC I-8 | `engine.rs` `send_bytes`: compute advertised window from `free_space_total` symmetrically with `emit_ack` |
| RFC 7323 §5.5 24-day TS.Recent expiration | A4 RFC I-5 | **Defer to A6** (needs public timer API) |

---

## 10. Test plan (Layer A + Layer B)

### 10.1 Unit tests (Layer A)

Per-module tests land with the module in the same commit:

- `siphash24.rs`: all 64 test vectors from the SipHash reference.
- `tcp_rtt.rs`: α/β sampling arithmetic; Karn's prevents sampling on retransmitted segments; min_rto floor; `apply_backoff` doubles up to `max_rto` cap; `rto_no_backoff=true` skips `apply_backoff`.
- `tcp_rack.rs`: §6.2 detect-lost rule on synthetic entries; `reo_wnd=0` when `rack_aggressive=true`; min_rtt tracker updates.
- `tcp_timer_wheel.rs`: add/fire/cancel on each level; tombstone cancel; per-conn cancel list clears on close; bucket rollover at horizon; `now_tick > last_ticked_tick` gating skips empty poll iterations.
- `tcp_retrans.rs`: mbuf refcount symmetry (push clones ref, prune drops ref); `prune_below(snd_una)` correctness; `mark_sacked` splits partial overlaps; `oldest_unacked` stability under sparse ACKs.
- `tcp_tlp.rs`: PTO computation; probe selection (new data vs last-seg retransmit).
- `iss.rs`: 4µs tick monotonicity across µs-spaced calls; `boot_id` read path + fallback-path coverage; different-tuple ISS differs; same-tuple-within-µs is monotonic; RFC 6528 §3 unpredictability smoke (different secrets → different hashes on same tuple).

### 10.2 Integration (Layer B, TAP pair)

Each scenario is a separate `#[test]` in the existing `tcp_*_tap.rs` pattern:

1. **RTO retransmit** — peer drops first data segment; assert `tcp.tx_rto == 1`, `tcp.tx_retrans == 1`, `DPDK_NET_EVT_TCP_RETRANS` delivered when `tcp_per_packet_events=true`.
2. **RACK reorder detect** — peer SACKs segments past a hole; assert `tcp.tx_rack_loss == 1`, retransmit arrives before RTO deadline.
3. **TLP tail-loss** — peer drops last segment, no further send; assert TLP fires at PTO, peer sees probe, ACK arrives.
4. **`rack_aggressive=true`** — single-SACK-hole triggers immediate retransmit; no reo_wnd grace period.
5. **Max-retrans exhausted** — blackhole path; assert after 15 retrans `DPDK_NET_EVT_ERROR{err=ETIMEDOUT}`, state=CLOSED, `tcp.conn_timeout_retrans == 1`.
6. **SYN retransmit** — peer doesn't reply SYN-ACK; assert 3 SYNs, then ETIMEDOUT, `tcp.conn_timeout_syn_sent == 1`.
7. **ISS monotonicity across reconnect** — connect, close, reconnect same tuple within MSL; assert new ISS > old ISS.
8. **No-backoff opt-in** — connect with `rto_no_backoff=true`, induce multiple RTO fires; assert RTO stays constant (no doubling).
9. **DSACK counter** — induce spurious retransmit; peer DSACKs; assert `tcp.rx_dsack ≥ 1`.
10. **mbuf-chain retransmit** — capture TAP of a retransmit frame; assert header + payload arrive in a multi-seg frame (`mbuf->nb_segs == 2`).

### 10.3 A4 carry-over tests

- WS>14 clamp: `tcp.rx_ws_shift_clamped == 1` after one peer with shift=15; second conn with same peer does not re-bump (per-conn one-shot).
- `tcp_options.rs` parser rejects shift=16 directly (decoder-side clamp asserts return value).
- dup_ack strict: data-carrying ACK, ACK with new data, ACK with mismatched window all fail at least one of the 5 conditions and do NOT bump `tcp.rx_dup_ack`.
- `ooo_drop` removed: compile-time by deletion.
- I-8 close: captured window in `send_bytes`-emitted segments equals `free_space_total >> ws_shift_out`.

---

## 11. Review gates

Per `feedback_phase_mtcp_review.md` + `feedback_phase_rfc_review.md`, the `phase-a5-complete` tag is gated on two independent review reports:

- `docs/superpowers/reviews/phase-a5-mtcp-compare.md` — `mtcp-comparison-reviewer` subagent (opus, per `feedback_subagent_model.md`). Compares A5 against mTCP's retransmit/RTO path (`tcp_out.c`, `tcp_rb.c`, `tcp_timer.c`). Expected ADs: `AD-A5-hashed-timer-wheel` (we use hashed wheel vs mTCP's per-conn list); possibly `AD-A5-mbuf-chained-retransmit` if mTCP's retransmit is byte-copy based; `AD-A5-tlp-probe-type-selection` if mTCP uses a different probe strategy. Gate is PASS-WITH-ACCEPTED when no open Must-fix / Missed-edge-cases checkboxes remain.
- `docs/superpowers/reviews/phase-a5-rfc-compliance.md` — `rfc-compliance-reviewer` subagent (opus). Verifies against RFC 6298 (RTO), RFC 8985 (RACK-TLP), RFC 6528 (ISS), RFC 7323 §2.3 (WS clamp) as the A4 carry-over close. Gate is PASS-WITH-DEVIATIONS when all MUSTs satisfied and SHOULDs either satisfied or accepted in §6.4.

Per `feedback_per_task_review_discipline.md`, every non-trivial implementation task also gets spec-compliance + code-quality reviewer subagents before moving on (opus model).

---

## 12. Rough task scale

~28–32 tasks across the following groups (per-task plan detail will be finalized in the plan file):

- SipHash-2-4 primitive + vectors (1)
- ISS finalize: boot_nonce read, 4µs ticks, rewire (2)
- Timer wheel: struct + add/fire (2)
- Timer wheel: tombstone cancel + per-conn list (1)
- Timer wheel: lazy RTO re-arm invariant + tests (1)
- RTT estimator module + tests (1)
- RTT sampling integration: TS source + Karn's fallback in `tcp_input.rs` (2)
- `snd_retrans` module: struct + push/prune/sack (2)
- `send_bytes` rewire: mbuf ref into snd_retrans (1)
- Retransmit primitive: fresh hdr + chain orig data mbuf (2)
- `MULTI_SEGS` TX offload enable in port config (1)
- RACK state + detect_lost (2)
- DSACK detection + counter (1)
- TLP PTO + probe selection (2)
- RTO fire handler + backoff + `rto_no_backoff` opt-out (2)
- `tcp_max_retrans_count` + ETIMEDOUT path (1)
- SYN retransmit scheduler (2)
- `rack_aggressive` + `rto_no_backoff` wiring from connect_opts + counters (1)
- Per-packet events + `tcp_per_packet_events` config field (1)
- Counter additions + zero-reference wiring (1)
- A4 carry-over: WS>14 SHOULD-log + counter (1)
- A4 carry-over: dup_ack strict 5-condition (1)
- A4 carry-over: WS≤14 decoder-side enforcement (1)
- A4 carry-over: `ooo_drop` removal + test cleanup (1)
- A4 carry-over: I-8 `free_space_total` in `send_bytes` (1)
- Config-field additions + header regen (1)
- Integration TAP tests — grouped ~3 per task (3)
- mTCP review gate + report draft (1)
- RFC review gate + report draft (1)

Each task is a single-focus, surgical change with an acceptance test at its boundary. Tasks that modify the engine TX/RX hot path carry an explicit "no measurable cost" reviewer note per §9.1.1 (hot-path counter policy analog).

---

## 13. Updates to parent spec `2026-04-17-dpdk-tcp-design.md`

Small edits to the parent spec land in the same commit as this phase design doc:

- §6.4 row for `minRTO`: update "our default" cell from "20ms (tunable)" to "5ms (tunable)" and strengthen the rationale.
- §6.4 new row: "RTO maximum | RFC 6298 ≥60s | 1s | trading fail-fast rationale as above."
- §6.5 SYN retransmit bullet: cite `tcp_max_retrans_count=15` for clarity (data retrans budget, not SYN).
- §9.1 counter examples: add `tx_rack_loss` to the tcp-group example list (already covered abstractly by "examples" phrasing but worth being explicit).
- §9.3 events: `err=ETIMEDOUT` added to the `DPDK_NET_EVT_ERROR` error enum.
- §6.3 RFC matrix row for RFC 5681: note that dup_ack counter is now strict per-§2 (previously loose in A3/A4).

---

## 14. Performance notes

- **RACK detect-lost pass** walks `snd_retrans` on every ACK. At Stage 1's ≤100 connections with typical in-flight depth of a few dozen MSS-sized segments per conn, this is trivially bounded. If benchmark data later shows pressure, a next-lost-pointer optimization (skip re-checking entries already marked lost) is the natural first lever; not needed for Stage 1 ship.
- **Lazy RTO re-arm** (§3.2) trades at most one no-op timer fire per RTO window for O(1) ACK-path cost. The no-op fire handler is a generation-counter compare + two seq loads — negligible.
- **Timer wheel `now_tick > last_ticked_tick` gate** (spec §7.4) skips wheel walking entirely on poll iterations where no 10µs tick has elapsed. At typical poll rates (hundreds of kHz) most iterations skip the wheel.
- **`snd_retrans` data structure**: `VecDeque` suffices at Stage 1 depth. If depth grows (Stage 2 multi-queue + bulk flows) a skip-list or interval-tree may be warranted.

## 15. Open items for the plan-writing pass

- **Per-task order**: ensure SipHash → ISS finalize come early (no dependencies on retransmit); timer-wheel lands before RTO fire handler; `snd_retrans` lands before retransmit primitive; RACK/TLP land after retransmit primitive.
- **Bundling**: the 10 Layer-B tests could be grouped 3-3-4 across 3 commits for review cadence, or run at the end in a single commit — plan decides.
- **Test fixtures**: the TAP harness needs a "drop segment N" injection for test 1 (RTO), a "SACK past N" injection for test 2 (RACK), and a "blackhole" mode for tests 5/6. Plan task for harness extension before the tests themselves.
