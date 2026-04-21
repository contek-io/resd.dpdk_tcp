# resd.dpdk_tcp Stage 1 Phase A3 — TCP Handshake + Basic Data Transfer

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Phase A2 `tcp_input_stub` with a real client-side TCP path: `dpdk_net_connect` issues a SYN, the stack processes SYN-ACK and emits ACK, `dpdk_net_send` enqueues bytes that TX out as MSS-sized segments, inbound data segments deliver via `DPDK_NET_EVT_READABLE`, and `dpdk_net_close` performs a clean FIN exchange ending in TIME_WAIT → CLOSED. No retransmit, no TCP options beyond MSS, no SACK, no PAWS, no reassembly — all deferred to A4/A5. The phase ends with an end-to-end integration test that handshakes, echoes bytes, and closes cleanly against a kernel-side TCP listener over a TAP pair, plus the mandatory mTCP comparison review.

**Architecture:** Eight new pure-Rust modules in `dpdk-net-core`: `tcp_seq` (wrap-safe seq comparisons), `tcp_state` (11-state enum per RFC 9293 §3.3.2), `flow_table` (handle-indexed slot array + 4-tuple hash for RX lookup), `iss` (RFC 6528 SipHash-based ISS generator — skeleton; A5 finalizes), `tcp_conn` (per-connection state with minimum A3 fields from spec §6.2), `tcp_output` (SYN / ACK / data / FIN / RST frame builders + TCP+IP pseudo-header checksum), `tcp_events` (internal FIFO event queue consumed by `dpdk_net_poll`), and `tcp_input` (header parser + per-state segment handler). `engine.rs` gains a flow table, an event queue, an ISS generator, and three application-facing methods (`connect`, `send_bytes`, `close_conn`) whose work routes through those modules. The public API surface grows by three extern "C" functions (`dpdk_net_connect`, `dpdk_net_send`, `dpdk_net_close`) and `dpdk_net_poll` now fills the caller's `events_out` buffer instead of being a no-op.

**Tech Stack:** same as A2 — Rust stable, DPDK 23.11, bindgen, cbindgen. New stdlib: `std::collections::{HashMap, VecDeque}`, `std::hash::{BuildHasher, BuildHasherDefault}`. The test harness uses `std::net::TcpListener` on a kernel-side TAP interface as the peer, so there is no external process dependency (no `nc` / `ncat`).

**Spec reference:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §§ 4 (public API: `dpdk_net_connect`, `dpdk_net_send`, `DPDK_NET_EVT_CONNECTED` / `_READABLE` / `_CLOSED`), 5.2 (TX call chain), 6.1 (FSM — RFC 9293 §3.3.2 eleven-state client-side), 6.2 (`TcpConn` minimum fields for A3), 6.5 (ISS stub, SYN retransmit semantics scoped out), 7.1 (`tx_hdr_mempool` vs `tx_data_mempool`), 9.1 (TCP counter group), 10.13 (mTCP review gate), 10.14 (RFC compliance review gate).

**RFCs in scope for A3** (for the §10.14 RFC compliance review): **9293** (TCP — client FSM, segmentation, ACK generation, RST reply, TIME_WAIT, checksum), **6691** (MSS — clamp to local MTU, SYN MSS option format), **6528** (ISS generation — SipHash skeleton). RFCs 7323 / 2018 / 6298 / 8985 / 5961 / 3168 are all out of scope for A3; they land in A4–A6. All text is vendored at `docs/rfcs/rfcNNNN.txt`.

**Review gates at phase sign-off** (three reports, each one a blocking gate):
1. **A3 mTCP comparison review** (spec §10.13) — `docs/superpowers/reviews/phase-a3-mtcp-compare.md`. mTCP focus areas: `mtcp/src/tcp_in.c`, `tcp_out.c`, `tcp_stream.c`, `tcp_util.c`, `fhash.c`, `tcp_send_buffer.c`, `tcp_ring_buffer.c`.
2. **Retroactive A2 RFC compliance review** (spec §10.14, grandfathering A2) — `docs/superpowers/reviews/phase-a2-rfc-compliance.md`. RFCs in scope: 791, 792, 826, 1122, 1191. A2's plan claims these; A2 shipped without the §10.14 gate existing, and the user's directive at A3 kickoff (2026-04-18) is to run the review here rather than leaving A2 permanently unreviewed.
3. **A3 RFC compliance review** (spec §10.14) — `docs/superpowers/reviews/phase-a3-rfc-compliance.md`. RFCs in scope: 9293, 6691, 6528.

**Deviations from spec — explicitly scoped for A3:**
- **SYN retransmit** (spec §6.5): Phase A3 emits the SYN exactly once. If no SYN-ACK arrives, the connection stays in SYN_SENT until the caller times out at application level. SYN retry with exponential backoff lands in A5 alongside the real RTO timer.
- **MSS-only SYN options**: A3 emits `MSS=1460` (2-byte NOP pad for word alignment). Window-scale, timestamps, and SACK-permitted are A4. Unknown options on inbound SYN-ACK are skipped (not negotiated).
- **Window scale = 0 on both sides**. `snd_wnd` is peer's advertised window with no left shift.
- **No reassembly**: out-of-order segments are dropped and counted (`tcp.rx_out_of_order`). In-order data appends to the per-conn recv buffer; the A4 reassembly queue replaces this behaviour.
- **Per-segment ACK** (burst coalescing only, per spec §6.4): every segment that advances `rcv_nxt` triggers an ACK on the same poll iteration. Delayed-ACK scheduling (default off anyway; RFC-compliance-preset in A6) is not implemented here.
- **`DPDK_NET_EVT_WRITABLE` and true backpressure**: send buffer backpressure in A3 returns partial from `dpdk_net_send` but does NOT emit `EVT_WRITABLE` on drain — A6 wires that event. The send buffer is capped at `send_buffer_bytes` per connection.
- **Internal event borrow lifetime**: `DPDK_NET_EVT_READABLE.data` points into a per-connection `last_read_buf: Vec<u8>` that is cleared at the start of the next `dpdk_net_poll` on the same engine. Still matches the spec §4.2 contract ("valid … until the next `dpdk_net_poll` call"), but is one copy heavier than the mbuf-pinning model that arrives in a later phase.
- **RST reply on unmatched segments** (spec §5.1 `reply_rst`): implemented. Emits a bare ACK|RST with `seq=0`, `ack=their_seq+payload_len+flags_count` per RFC 9293 §3.10.7.1.
- **TIME_WAIT duration**: 2×MSL (MSL = `tcp_msl_ms` default 30000 ms). Connection sits in TIME_WAIT until a `tcp_tick` walk reaps it. A3's tick is naïve (checks deadline at end of `poll_once`); the real timer wheel arrives in A6.

**Pre-emptive Accepted Divergences vs mTCP** (to land in the A3 mTCP review):
1. **ISS**: we use RFC 6528 (SipHash of 4-tuple + boot_nonce + monotonic µs clock); mTCP uses `rand_r() % 2^32`. See spec §6.5.
2. **Sequence-window validation**: we check both edges (`rcv_nxt ≤ seq AND seq+payload_len ≤ rcv_nxt+rcv_wnd`); mTCP only checks the right edge. See RFC 9293 §3.10.7.4.
3. **`snd_una = ack_seq`** on SYN-ACK processing (rather than mTCP's `snd_una++`) — cleaner, identical result on well-formed SYN-ACK.
4. **Per-segment ACK** (not mTCP's aggregation) — consistent with spec §6.4 trading-latency defaults.
5. **MSS-only SYN options** — no WSCALE / TS / SACK-permit; A4 adds them.
6. **Flow-table layout**: `Vec<Option<TcpConn>>` indexed by handle id + `HashMap<FourTuple, u32>` for RX lookup. mTCP uses Jenkins-hash chained buckets with `NUM_BINS_FLOWS=131072`. Our ≤100-connection workload doesn't need the bin count.
7. **Recv buffer = `VecDeque<u8>`** (true ring); mTCP's `SBPut` memmoves on wrap. Same abstraction, different latency profile.

---

## File Structure Created or Modified in This Phase

```
crates/dpdk-net-core/src/
├── lib.rs               (MODIFIED: expose tcp_seq, tcp_state, flow_table, iss, tcp_conn, tcp_output, tcp_events, tcp_input)
├── counters.rs          (MODIFIED: extend TcpCounters; state_trans matrix added in a reserved _pad slot)
├── engine.rs            (MODIFIED: flow table, event queue, iss state, connect/send/close methods, tcp_input dispatch replaces stub, tx_data_frame helper, time_wait reaping)
├── error.rs             (MODIFIED: new variants for TCP paths: TooManyConns, InvalidConnHandle, PeerUnreachable)
├── tcp_seq.rs           (NEW: wrap-safe u32 seq comparisons + window membership)
├── tcp_state.rs         (NEW: TcpState enum + u8 conversion)
├── flow_table.rs        (NEW: FourTuple + FlowTable struct)
├── iss.rs               (NEW: RFC 6528 ISS generator skeleton; SipHash via std default hasher for now)
├── tcp_conn.rs          (NEW: TcpConn struct with A3-minimum fields)
├── tcp_output.rs        (NEW: segment builders + pseudo-header checksum)
├── tcp_events.rs        (NEW: internal FIFO event queue type)
└── tcp_input.rs         (NEW: TCP header parser + per-state handlers)

crates/dpdk-net-core/tests/
├── engine_smoke.rs      (no change — A1 lifecycle test)
├── l2_l3_tap.rs         (no change — A2 integration test)
└── tcp_basic_tap.rs     (NEW: TCP handshake + echo + close over TAP pair against kernel listener)

crates/dpdk-net/src/
├── lib.rs               (MODIFIED: dpdk_net_connect / dpdk_net_send / dpdk_net_close extern "C"; dpdk_net_poll fills events_out)
└── api.rs               (MODIFIED: dpdk_net_tcp_counters_t extended; NO config field additions — A3 uses existing fields)

crates/dpdk-net-sys/
└── (no change — the existing alloc/append/burst/free shims cover A3 TX paths)

include/dpdk_net.h       (REGENERATED via cbindgen)

examples/cpp-consumer/main.cpp  (MODIFIED: print tcp counters, do a connect-send-close smoke against loopback when possible)

tests/ffi-test/tests/ffi_smoke.rs  (no change — A3 adds no config fields, so the Cfg shim still matches)

docs/superpowers/plans/stage1-phase-roadmap.md  (MODIFIED: status update at A3 sign-off)
docs/superpowers/reviews/phase-a3-mtcp-compare.md      (NEW: A3 mTCP comparison review)
docs/superpowers/reviews/phase-a2-rfc-compliance.md    (NEW: retroactive A2 RFC compliance review)
docs/superpowers/reviews/phase-a3-rfc-compliance.md    (NEW: A3 RFC compliance review)
```

---

## Task 1: Extend `TcpCounters` for A3 drop / accept / state-transition reasons

**Goal:** Add the TCP counters Phase A3 will write. Reuse the existing `_pad: [u64; 3]` slot (plus an extended pad) to keep the cacheline-aligned struct intact; the layout-assertion `const _: ()` in `api.rs` enforces size + alignment parity. The `state_trans` transition matrix is 121 entries (11×11) but for A3 we only bump the slots we visit — unused slots are harmless zeros.

**Files:**
- Modify: `crates/dpdk-net-core/src/counters.rs`
- Modify: `crates/dpdk-net/src/api.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/src/counters.rs` inside `mod tests`:

```rust
    #[test]
    fn a3_new_tcp_counters_exist_and_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.tx_syn.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_ack.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_data.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_fin.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.tx_rst.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_fin.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_unmatched.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_bad_csum.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_bad_flags.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.rx_short.load(Ordering::Relaxed), 0);
        // Transition matrix is 11×11 = 121 u64s; all zero at construction.
        for row in &c.tcp.state_trans {
            for cell in row {
                assert_eq!(cell.load(Ordering::Relaxed), 0);
            }
        }
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core counters::tests::a3_new_tcp_counters_exist_and_zero`
Expected: FAIL at compile — `no field tx_syn on TcpCounters`.

- [ ] **Step 3: Extend `TcpCounters`** — replace in `crates/dpdk-net-core/src/counters.rs`:

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
    /// 11×11 state transition matrix, indexed [from][to] where from/to are
    /// `TcpState as u8`. Per spec §9.1. Unused cells stay at zero.
    pub state_trans: [[AtomicU64; 11]; 11],
    _pad: [u64; 4],
}
```

- [ ] **Step 4: Mirror into public API** — in `crates/dpdk-net/src/api.rs`, replace `dpdk_net_tcp_counters_t`:

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
    pub state_trans: [[u64; 11]; 11],
    pub _pad: [u64; 4],
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p dpdk-net-core counters::tests && cargo test -p dpdk-net api`
Expected: PASS. If the layout-assertion `const _: ()` fails, recount the `_pad` entries — a 121-entry AtomicU64 matrix + 10 u64 named fields is 131 u64s on top of the 13 original; you may need to adjust `_pad: [u64; 4]` to land on a cacheline-aligned total.

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-core/src/counters.rs crates/dpdk-net/src/api.rs
git commit -m "extend tcp counters for a3: tx/rx flag counts + state_trans matrix"
```

---

## Task 2: Extend `EngineConfig` with A3 carry-through fields

**Goal:** Forward the A3-relevant fields from the public `dpdk_net_engine_config_t` (already present since A1) into `EngineConfig` so the core crate can read them. Fields to add: `max_connections`, `recv_buffer_bytes`, `send_buffer_bytes`, `tcp_mss`, `tcp_initial_rto_ms`, `tcp_msl_ms`, `tcp_nagle`. No public-API changes — those fields already exist on `dpdk_net_engine_config_t`.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`
- Modify: `crates/dpdk-net/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/src/engine.rs` inside `mod tests`:

```rust
    #[test]
    fn default_engine_config_has_a3_fields() {
        let cfg = EngineConfig::default();
        assert_eq!(cfg.max_connections, 16);
        assert_eq!(cfg.recv_buffer_bytes, 256 * 1024);
        assert_eq!(cfg.send_buffer_bytes, 256 * 1024);
        assert_eq!(cfg.tcp_mss, 1460);
        assert_eq!(cfg.tcp_initial_rto_ms, 50);
        assert_eq!(cfg.tcp_msl_ms, 30_000);
        assert!(!cfg.tcp_nagle);
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net-core engine::tests::default_engine_config_has_a3_fields`
Expected: FAIL at compile — no field `max_connections`.

- [ ] **Step 3: Extend the `EngineConfig` struct** — replace `EngineConfig` and its `Default` in `crates/dpdk-net-core/src/engine.rs`:

```rust
/// Config passed to Engine::new.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub lcore_id: u16,
    pub port_id: u16,
    pub rx_queue_id: u16,
    pub tx_queue_id: u16,
    pub rx_ring_size: u16,
    pub tx_ring_size: u16,
    pub rx_mempool_elems: u32,
    pub mbuf_data_room: u16,

    // Phase A2 additions (host byte order for IPs; raw bytes for MAC)
    pub local_ip: u32,
    pub gateway_ip: u32,
    pub gateway_mac: [u8; 6],
    pub garp_interval_sec: u32,

    // Phase A3 additions (all carry through from the public config)
    pub max_connections: u32,
    pub recv_buffer_bytes: u32,
    pub send_buffer_bytes: u32,
    pub tcp_mss: u32,
    pub tcp_initial_rto_ms: u32,
    pub tcp_msl_ms: u32,
    pub tcp_nagle: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            lcore_id: 0,
            port_id: 0,
            rx_queue_id: 0,
            tx_queue_id: 0,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            rx_mempool_elems: 8192,
            mbuf_data_room: 2048,
            local_ip: 0,
            gateway_ip: 0,
            gateway_mac: [0u8; 6],
            garp_interval_sec: 0,
            max_connections: 16,
            recv_buffer_bytes: 256 * 1024,
            send_buffer_bytes: 256 * 1024,
            tcp_mss: 1460,
            tcp_initial_rto_ms: 50,
            tcp_msl_ms: 30_000,
            tcp_nagle: false,
        }
    }
}
```

- [ ] **Step 4: Bridge new fields in `crates/dpdk-net/src/lib.rs`** — replace the body of `dpdk_net_engine_create`:

```rust
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_engine_create(
    lcore_id: u16,
    cfg: *const dpdk_net_engine_config_t,
) -> *mut dpdk_net_engine {
    if cfg.is_null() {
        return ptr::null_mut();
    }
    let cfg = &*cfg;
    // A3 fields with 0 sentinels fall back to defaults so callers that
    // don't supply them get sensible behavior.
    let max_conns = if cfg.max_connections == 0 { 16 } else { cfg.max_connections };
    let recv_buf = if cfg.recv_buffer_bytes == 0 { 256 * 1024 } else { cfg.recv_buffer_bytes };
    let send_buf = if cfg.send_buffer_bytes == 0 { 256 * 1024 } else { cfg.send_buffer_bytes };
    let mss = if cfg.tcp_mss == 0 { 1460 } else { cfg.tcp_mss };
    let init_rto = if cfg.tcp_initial_rto_ms == 0 { 50 } else { cfg.tcp_initial_rto_ms };
    let msl = if cfg.tcp_msl_ms == 0 { 30_000 } else { cfg.tcp_msl_ms };

    let core_cfg = EngineConfig {
        lcore_id,
        port_id: cfg.port_id,
        rx_queue_id: cfg.rx_queue_id,
        tx_queue_id: cfg.tx_queue_id,
        rx_ring_size: 1024,
        tx_ring_size: 1024,
        rx_mempool_elems: 8192,
        mbuf_data_room: 2048,
        local_ip: cfg.local_ip,
        gateway_ip: cfg.gateway_ip,
        gateway_mac: cfg.gateway_mac,
        garp_interval_sec: cfg.garp_interval_sec,
        max_connections: max_conns,
        recv_buffer_bytes: recv_buf,
        send_buffer_bytes: send_buf,
        tcp_mss: mss,
        tcp_initial_rto_ms: init_rto,
        tcp_msl_ms: msl,
        tcp_nagle: cfg.tcp_nagle,
    };
    match Engine::new(core_cfg) {
        Ok(e) => box_to_raw(e),
        Err(_) => ptr::null_mut(),
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p dpdk-net-core engine::tests && cargo test -p dpdk-net`
Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net/src/lib.rs
git commit -m "forward a3 config fields (max_connections, buffers, mss, nagle) into EngineConfig"
```

---

## Task 3: `tcp_seq.rs` — wrap-safe sequence-space arithmetic

**Goal:** TCP sequence numbers are u32 with modular arithmetic; naive `<` is wrong across the 0/2^32 wraparound. RFC 9293 §3.4 defines the comparisons as signed 32-bit subtraction. Implement `seq_lt`, `seq_le`, `seq_gt`, `seq_ge`, plus `in_window(start, seq, len)` for "is `seq` in the window `[start, start+len)`?" (len is u32, zero-length means empty).

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_seq.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write the module with failing tests**

Create `crates/dpdk-net-core/src/tcp_seq.rs`:

```rust
//! Wrap-safe u32 TCP-sequence-space comparisons (RFC 9293 §3.4).
//! All comparisons are done via `a.wrapping_sub(b) as i32`, so the
//! "distance" between a and b is valid as long as they are within
//! 2^31 of each other — which is always true for in-flight TCP
//! data on a single connection.

#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
pub fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[inline]
pub fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[inline]
pub fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// True iff `seq` lies within the half-open window `[start, start+len)`.
/// `len == 0` always returns false (empty window).
#[inline]
pub fn in_window(start: u32, seq: u32, len: u32) -> bool {
    if len == 0 {
        return false;
    }
    let offset = seq.wrapping_sub(start);
    offset < len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lt_across_zero_wrap() {
        // 0xFFFFFFFF is "before" 0 in seq space.
        assert!(seq_lt(0xFFFFFFFF, 0));
        assert!(!seq_lt(0, 0xFFFFFFFF));
        assert!(seq_lt(100, 200));
        assert!(!seq_lt(200, 100));
    }

    #[test]
    fn le_equal() {
        assert!(seq_le(42, 42));
        assert!(!seq_lt(42, 42));
    }

    #[test]
    fn in_window_basic() {
        assert!(in_window(100, 100, 10));
        assert!(in_window(100, 109, 10));
        assert!(!in_window(100, 110, 10));
        assert!(!in_window(100, 99, 10));
    }

    #[test]
    fn in_window_wraps() {
        // Window crossing the zero boundary.
        assert!(in_window(0xFFFFFFF0, 0xFFFFFFF5, 0x20));
        assert!(in_window(0xFFFFFFF0, 0x0000_000F, 0x20));
        assert!(!in_window(0xFFFFFFF0, 0x0000_0010, 0x20));
    }

    #[test]
    fn in_window_zero_len_is_empty() {
        assert!(!in_window(100, 100, 0));
        assert!(!in_window(0xFFFFFFFF, 0xFFFFFFFF, 0));
    }

    #[test]
    fn gt_and_ge_reflect_lt_and_le() {
        assert!(seq_gt(200, 100));
        assert!(!seq_gt(100, 200));
        assert!(seq_ge(100, 100));
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`, add before `pub mod arp;`:

```rust
pub mod tcp_seq;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core tcp_seq::`
Expected: 6 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_seq.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add tcp_seq: wrap-safe u32 sequence-space comparisons (rfc 9293 §3.4)"
```

---

## Task 4: `tcp_state.rs` — TcpState enum with RFC 9293 §3.3.2 eleven states

**Goal:** Strongly-typed state enum that maps 1:1 to `u8` for the public `tcp_state_change` event + `state_trans[from][to]` counter indexing. Includes a `Display` impl for debug logs (no strings on hot path — spec §9.4).

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_state.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write the module + tests**

Create `crates/dpdk-net-core/src/tcp_state.rs`:

```rust
//! RFC 9293 §3.3.2 eleven-state TCP FSM. States are numbered so the
//! `state_trans[from][to]` counter matrix in `counters.rs` can be
//! indexed by `state as usize` without collisions. Also exposed as
//! `u8` for the public `DPDK_NET_EVT_TCP_STATE_CHANGE` event.
//!
//! We never transition to LISTEN in production (spec §6.1); it's
//! present only so the enum covers the full RFC set and so the
//! test-only loopback-server feature (A7) can drive it.

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
}

impl TcpState {
    pub const COUNT: usize = 11;

    /// Short fixed-width label for debug logging. No allocation.
    pub fn label(self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECEIVED",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eleven_states_with_consecutive_u8_values() {
        assert_eq!(TcpState::COUNT, 11);
        assert_eq!(TcpState::Closed as u8, 0);
        assert_eq!(TcpState::TimeWait as u8, 10);
    }

    #[test]
    fn label_is_stable_for_every_state() {
        for s in [
            TcpState::Closed, TcpState::Listen, TcpState::SynSent,
            TcpState::SynReceived, TcpState::Established,
            TcpState::FinWait1, TcpState::FinWait2, TcpState::CloseWait,
            TcpState::Closing, TcpState::LastAck, TcpState::TimeWait,
        ] {
            assert!(!s.label().is_empty());
        }
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`, add after `pub mod tcp_seq;`:

```rust
pub mod tcp_state;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core tcp_state::`
Expected: 2 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_state.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add tcp_state: rfc 9293 §3.3.2 eleven-state enum"
```

---

## Task 5: `flow_table.rs` — 4-tuple hash + handle-indexed slot array

**Goal:** Two coupled structures. `FourTuple` is `(local_ip, local_port, peer_ip, peer_port)` in host byte order; it hashes into a standard Rust `HashMap`. `FlowTable` owns a `Vec<Option<TcpConn>>` pre-warmed to `max_connections`, plus a `HashMap<FourTuple, u32>` that maps 4-tuple → slot index. Handle values returned to callers are `slot_idx + 1` so that `0` is reserved as the invalid sentinel (matches the public `dpdk_net_conn_t` convention). Insertions do not reallocate the slot `Vec`; when full, allocation returns `None`.

**Files:**
- Create: `crates/dpdk-net-core/src/flow_table.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write the module**

Create `crates/dpdk-net-core/src/flow_table.rs`:

```rust
//! 4-tuple hash and handle-indexed slot array. The hot path on RX is
//! `FlowTable::lookup_by_tuple` → slot index → `&mut TcpConn`. The
//! hot path on TX / user API is `FlowTable::get_mut(handle)` which
//! skips the hash and just indexes the slot `Vec`.
//!
//! Handle values exposed to callers are `slot_idx + 1`, so handle `0`
//! is reserved as the invalid sentinel — matching `dpdk_net_conn_t`'s
//! "0 = invalid" convention in spec §4.

use std::collections::HashMap;

use crate::tcp_conn::TcpConn;

/// 4-tuple in HOST byte order for all integer fields. All hash / compare
/// operations use this representation. Network-byte-order conversion
/// happens at the API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub local_ip: u32,
    pub local_port: u16,
    pub peer_ip: u32,
    pub peer_port: u16,
}

/// Opaque connection handle. A `u32` internally; we widen to `u64` at
/// the C ABI boundary (see `dpdk_net_conn_t`).
pub type ConnHandle = u32;

pub const INVALID_HANDLE: ConnHandle = 0;

pub struct FlowTable {
    slots: Vec<Option<TcpConn>>,
    by_tuple: HashMap<FourTuple, u32>,
}

impl FlowTable {
    pub fn new(max_connections: u32) -> Self {
        let mut slots = Vec::with_capacity(max_connections as usize);
        for _ in 0..max_connections {
            slots.push(None);
        }
        Self {
            slots,
            by_tuple: HashMap::with_capacity(max_connections as usize),
        }
    }

    pub fn capacity(&self) -> u32 {
        self.slots.len() as u32
    }

    /// Allocate a new slot for `conn`; returns the handle or `None` if full.
    /// Duplicate 4-tuple registrations are rejected — caller must close the
    /// existing connection first.
    pub fn insert(&mut self, conn: TcpConn) -> Option<ConnHandle> {
        let tuple = conn.four_tuple();
        if self.by_tuple.contains_key(&tuple) {
            return None;
        }
        let slot_idx = self.slots.iter().position(|s| s.is_none())?;
        self.slots[slot_idx] = Some(conn);
        self.by_tuple.insert(tuple, slot_idx as u32);
        Some(slot_idx as u32 + 1)
    }

    pub fn get(&self, handle: ConnHandle) -> Option<&TcpConn> {
        if handle == INVALID_HANDLE {
            return None;
        }
        let idx = (handle - 1) as usize;
        self.slots.get(idx)?.as_ref()
    }

    pub fn get_mut(&mut self, handle: ConnHandle) -> Option<&mut TcpConn> {
        if handle == INVALID_HANDLE {
            return None;
        }
        let idx = (handle - 1) as usize;
        self.slots.get_mut(idx)?.as_mut()
    }

    pub fn lookup_by_tuple(&self, tuple: &FourTuple) -> Option<ConnHandle> {
        self.by_tuple.get(tuple).copied().map(|i| i + 1)
    }

    /// Remove the connection for `handle`. Returns the removed `TcpConn` if
    /// present, else `None`. Frees both the slot and the by-tuple entry.
    pub fn remove(&mut self, handle: ConnHandle) -> Option<TcpConn> {
        if handle == INVALID_HANDLE {
            return None;
        }
        let idx = (handle - 1) as usize;
        let slot = self.slots.get_mut(idx)?;
        let conn = slot.take()?;
        self.by_tuple.remove(&conn.four_tuple());
        Some(conn)
    }

    /// Iterate all active connections — used by the naïve tick path for
    /// TIME_WAIT reaping. Not a hot-path function.
    pub fn iter_handles(&self) -> impl Iterator<Item = ConnHandle> + '_ {
        self.slots.iter().enumerate().filter_map(|(i, s)| {
            if s.is_some() {
                Some(i as u32 + 1)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_conn::TcpConn;

    fn tuple(peer_port: u16) -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port,
        }
    }

    #[test]
    fn insert_and_lookup_by_handle() {
        let mut ft = FlowTable::new(4);
        let c = TcpConn::new_client(tuple(5000), 12345, 1460, 1024, 2048);
        let h = ft.insert(c).expect("insert ok");
        assert!(h >= 1);
        assert!(ft.get(h).is_some());
    }

    #[test]
    fn lookup_by_tuple_roundtrip() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let c = TcpConn::new_client(t, 12345, 1460, 1024, 2048);
        let h = ft.insert(c).unwrap();
        assert_eq!(ft.lookup_by_tuple(&t), Some(h));
    }

    #[test]
    fn full_table_returns_none() {
        let mut ft = FlowTable::new(2);
        let a = TcpConn::new_client(tuple(5000), 1, 1460, 1024, 2048);
        let b = TcpConn::new_client(tuple(5001), 2, 1460, 1024, 2048);
        let c = TcpConn::new_client(tuple(5002), 3, 1460, 1024, 2048);
        assert!(ft.insert(a).is_some());
        assert!(ft.insert(b).is_some());
        assert!(ft.insert(c).is_none());
    }

    #[test]
    fn duplicate_tuple_rejected() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let a = TcpConn::new_client(t, 1, 1460, 1024, 2048);
        let b = TcpConn::new_client(t, 2, 1460, 1024, 2048);
        assert!(ft.insert(a).is_some());
        assert!(ft.insert(b).is_none());
    }

    #[test]
    fn remove_frees_slot_and_tuple() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let c = TcpConn::new_client(t, 1, 1460, 1024, 2048);
        let h = ft.insert(c).unwrap();
        assert!(ft.remove(h).is_some());
        assert!(ft.remove(h).is_none());
        assert!(ft.lookup_by_tuple(&t).is_none());
    }

    #[test]
    fn invalid_handle_rejected() {
        let ft = FlowTable::new(4);
        assert!(ft.get(INVALID_HANDLE).is_none());
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`, add after `pub mod tcp_state;`:

```rust
pub mod flow_table;
pub mod tcp_conn;  // exposed now because flow_table depends on it
```

(The `tcp_conn` module comes in Task 7; a one-line stub `pub struct TcpConn;` is enough for the workspace to compile this test without Task 7 yet. But since we add `tcp_conn` next, we skip the stub and land the two modules together — the `cargo test -p dpdk-net-core flow_table::` invocation below runs after Task 7.)

- [ ] **Step 3: Do not run tests yet** — `flow_table` tests reference `TcpConn::new_client`, which is Task 7. Mark the module as written but defer test execution until after Task 7 builds.

- [ ] **Step 4: Commit the module file only** (not `lib.rs` — we need `tcp_conn` first)

```sh
git add crates/dpdk-net-core/src/flow_table.rs
git commit -m "add flow_table: 4-tuple hashmap + handle-indexed slot array"
```

---

## Task 6: `iss.rs` — RFC 6528 ISS generator skeleton

**Goal:** Generate a deterministic-but-peer-unpredictable initial sequence number per RFC 6528. The formula per spec §6.5: `ISS = (monotonic_time_4µs_ticks_low_32) + SipHash64(local_ip || local_port || peer_ip || peer_port || secret || boot_nonce)`. A3 ships a skeleton that uses `std::collections::hash_map::DefaultHasher` (SipHash-1-3) as the keyed-hash; A5 swaps in a dedicated SipHash-2-4 implementation + boot_nonce from `/proc/sys/kernel/random/boot_id`. The API is stable across the swap.

**Files:**
- Create: `crates/dpdk-net-core/src/iss.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write the module**

Create `crates/dpdk-net-core/src/iss.rs`:

```rust
//! RFC 6528 §3 ISS generator — SipHash-of-4-tuple + secret + boot_nonce,
//! offset by a monotonic clock so reconnects to the same 4-tuple within
//! MSL yield monotonically-increasing ISS.
//!
//! A3 ships a skeleton using `std::collections::hash_map::DefaultHasher`
//! (SipHash-1-3) for the keyed hash. A5 will finalize per spec §6.5:
//!   - explicit SipHash-2-4 implementation (not from std)
//!   - `boot_nonce` from `/proc/sys/kernel/random/boot_id`
//!   - 4µs-tick monotonic clock (A3 uses 1µs)
//! The call signature `IssGen::next(&FourTuple)` stays the same.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::clock;
use crate::flow_table::FourTuple;

pub struct IssGen {
    /// 128-bit per-process random secret. Seeded once per engine from
    /// the best-effort entropy source (clock-derived in A3 skeleton;
    /// `getrandom` in A5 once we audit the extra dep).
    secret: [u64; 2],
}

impl IssGen {
    /// Create a new generator with a per-engine random secret. The
    /// argument is used only to seed reproducibility in tests; production
    /// code passes `0` and we derive the secret from the TSC.
    pub fn new(test_seed: u64) -> Self {
        let tsc = clock::now_ns();
        let secret = [
            tsc.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(test_seed),
            tsc.wrapping_mul(0xBF58_476D_1CE4_E5B9)
                .wrapping_add(test_seed)
                .wrapping_add(0x6A09_E667_F3BC_C908),
        ];
        Self { secret }
    }

    /// Compute ISS for `tuple`. Peer cannot predict unless they know
    /// our `secret`; within the same 4-tuple and process, consecutive
    /// calls monotonically increase because the µs clock is added last.
    pub fn next(&self, tuple: &FourTuple) -> u32 {
        let mut h = DefaultHasher::new();
        self.secret.hash(&mut h);
        tuple.hash(&mut h);
        let hash_low32 = h.finish() as u32;
        // A3: use 1µs clock low 32 bits (A5 spec calls for 4µs ticks).
        let clock_us = (clock::now_ns() / 1_000) as u32;
        hash_low32.wrapping_add(clock_us)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(peer_port: u16) -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port,
        }
    }

    #[test]
    fn two_engines_produce_different_iss_for_same_tuple() {
        let g1 = IssGen::new(1);
        let g2 = IssGen::new(2);
        // Not strictly required by RFC, but sanity: with two different
        // secrets on the same tuple the ISS should essentially never collide.
        let t = tuple(5000);
        // Poll a few times to let the clocks diverge; even the hash alone
        // should differ because the secret is different.
        assert_ne!(g1.next(&t), g2.next(&t));
    }

    #[test]
    fn sequential_calls_monotonic_for_same_tuple() {
        let g = IssGen::new(42);
        let t = tuple(5000);
        let a = g.next(&t);
        // Spin a few ns so the µs clock advances at least once.
        for _ in 0..10_000 {
            std::hint::spin_loop();
        }
        let b = g.next(&t);
        // Monotonic in the wrap-space sense (b >= a for small deltas).
        let delta = b.wrapping_sub(a);
        assert!(delta < 1_000_000, "delta too large: {delta}"); // sanity; same µs-ish.
    }

    #[test]
    fn different_tuples_give_different_iss() {
        let g = IssGen::new(42);
        let a = g.next(&tuple(5000));
        let b = g.next(&tuple(5001));
        assert_ne!(a, b);
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`, add after `pub mod flow_table;`:

```rust
pub mod iss;
```

- [ ] **Step 3: Do not run tests yet** — depends on Task 7's `TcpConn` via `flow_table`. Tests will run in Task 7's step.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/iss.rs
git commit -m "add iss: rfc 6528 iss generator skeleton (siphash via default hasher)"
```

---

## Task 7: `tcp_conn.rs` — `TcpConn` struct with A3-minimum fields

**Goal:** Implement the per-connection state per spec §6.2 but only the fields A3 actually touches. Later phases grow this struct — the point is to lock in the shape so A4+ additions are additive. Unused fields from §6.2 (`ws_shift_*`, `ts_*`, `sack_enabled`, `rack`, `cc`, timer handles) are deferred.

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_conn.rs`

- [ ] **Step 1: Write the module + tests**

Create `crates/dpdk-net-core/src/tcp_conn.rs`:

```rust
//! Per-connection state (spec §6.2, subset for Phase A3).
//! Fields deferred to A4/A5 are NOT here yet; the struct grows
//! additively. Keeping the struct small also keeps the `Vec<Option<TcpConn>>`
//! slot array cacheline-sparse — the per-slot size today is ~128 bytes.

use std::collections::VecDeque;

use crate::flow_table::FourTuple;
use crate::tcp_state::TcpState;

/// Per-connection send buffer. In A3 this is a raw byte ring; A4 will
/// gain a SACK scoreboard + in-flight tracking per spec §6.2.
pub struct SendQueue {
    /// User-submitted bytes not yet handed to `rte_eth_tx_burst`. Pop
    /// from the front in MSS-sized chunks; bytes remain here until ACKed
    /// (A3 drops on ACK; A5 will retain for retransmit).
    pub pending: VecDeque<u8>,
    pub cap: u32,
}

impl SendQueue {
    pub fn new(cap: u32) -> Self {
        Self {
            pending: VecDeque::with_capacity(cap as usize),
            cap,
        }
    }

    pub fn free_space(&self) -> u32 {
        self.cap.saturating_sub(self.pending.len() as u32)
    }

    /// Append up to `free_space` bytes; returns how many were accepted.
    pub fn push(&mut self, bytes: &[u8]) -> u32 {
        let take = bytes.len().min(self.free_space() as usize);
        self.pending.extend(&bytes[..take]);
        take as u32
    }
}

/// Per-connection receive buffer. A3 holds contiguous in-order bytes only.
/// Out-of-order segments are dropped (counted); A4 replaces this with a
/// reassembly list.
pub struct RecvQueue {
    pub bytes: VecDeque<u8>,
    pub cap: u32,
    /// Scratch buffer for the borrow-view exposed to
    /// `DPDK_NET_EVT_READABLE.data`. Cleared at the start of each
    /// `dpdk_net_poll` on the owning engine (not here).
    pub last_read_buf: Vec<u8>,
}

impl RecvQueue {
    pub fn new(cap: u32) -> Self {
        Self {
            bytes: VecDeque::with_capacity(cap as usize),
            cap,
            last_read_buf: Vec::new(),
        }
    }

    pub fn free_space(&self) -> u32 {
        self.cap.saturating_sub(self.bytes.len() as u32)
    }

    /// Append `payload` to the receive queue, up to free space.
    /// Returns the number of bytes accepted (may be < payload.len() if
    /// the queue would overflow).
    pub fn append(&mut self, payload: &[u8]) -> u32 {
        let take = payload.len().min(self.free_space() as usize);
        self.bytes.extend(&payload[..take]);
        take as u32
    }
}

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

impl TcpConn {
    /// Create a fresh client-side connection ready to emit SYN.
    /// State = SYN_SENT; `snd_una = snd_nxt = iss`; our SYN will consume
    /// one seq (bumped to `iss+1` by the caller after successful TX).
    pub fn new_client(
        tuple: FourTuple,
        iss: u32,
        our_mss: u16,
        recv_buf_bytes: u32,
        send_buf_bytes: u32,
    ) -> Self {
        let rcv_wnd = recv_buf_bytes.min(u16::MAX as u32); // A3: no WSCALE, so ≤ 65535.
        Self {
            four_tuple: tuple,
            state: TcpState::Closed, // engine transitions to SynSent once SYN is TX'd.
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            iss,
            rcv_nxt: 0,
            rcv_wnd,
            irs: 0,
            peer_mss: our_mss, // placeholder until SYN-ACK; our_mss is a sane floor.
            snd: SendQueue::new(send_buf_bytes),
            recv: RecvQueue::new(recv_buf_bytes),
            our_fin_seq: None,
            time_wait_deadline_ns: None,
        }
    }

    pub fn four_tuple(&self) -> FourTuple {
        self.four_tuple
    }

    /// True iff our FIN has been sent and ACKed (i.e. ACK covers
    /// `our_fin_seq + 1`). Implementations use this to decide FIN_WAIT_1
    /// → FIN_WAIT_2 and CLOSING → TIME_WAIT transitions.
    pub fn fin_has_been_acked(&self, ack_seq: u32) -> bool {
        match self.our_fin_seq {
            Some(fs) => {
                let required = fs.wrapping_add(1);
                // Treat ack_seq covering `required` as "FIN acked".
                !crate::tcp_seq::seq_lt(ack_seq, required)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple() -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port: 5000,
        }
    }

    #[test]
    fn new_client_sets_iss_both_una_and_nxt() {
        let c = TcpConn::new_client(tuple(), 0xDEAD_BEEF, 1460, 1024, 2048);
        assert_eq!(c.snd_una, 0xDEAD_BEEF);
        assert_eq!(c.snd_nxt, 0xDEAD_BEEF);
        assert_eq!(c.iss, 0xDEAD_BEEF);
        assert_eq!(c.state, TcpState::Closed);
    }

    #[test]
    fn rcv_wnd_clamped_to_u16_max_without_wscale() {
        let c = TcpConn::new_client(tuple(), 0, 1460, 1_000_000, 1024);
        assert_eq!(c.rcv_wnd, u16::MAX as u32);
    }

    #[test]
    fn send_queue_push_respects_cap() {
        let mut sq = SendQueue::new(4);
        assert_eq!(sq.push(b"hello"), 4);
        assert_eq!(sq.pending.len(), 4);
        assert_eq!(sq.free_space(), 0);
    }

    #[test]
    fn recv_queue_append_respects_cap() {
        let mut rq = RecvQueue::new(3);
        assert_eq!(rq.append(b"hello"), 3);
        assert_eq!(rq.bytes.len(), 3);
    }

    #[test]
    fn fin_acked_checks_fin_seq_plus_one() {
        let mut c = TcpConn::new_client(tuple(), 100, 1460, 1024, 2048);
        assert!(!c.fin_has_been_acked(150));
        c.our_fin_seq = Some(200);
        assert!(!c.fin_has_been_acked(200));
        assert!(c.fin_has_been_acked(201));
        assert!(c.fin_has_been_acked(500));
    }
}
```

- [ ] **Step 2: Run — verify PASS for tcp_conn + flow_table + iss**

Run: `cargo test -p dpdk-net-core tcp_conn:: && cargo test -p dpdk-net-core flow_table:: && cargo test -p dpdk-net-core iss::`
Expected: 5 + 6 + 3 = 14 PASS total.

- [ ] **Step 3: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_conn.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add tcp_conn: per-conn state (spec §6.2 a3-minimum fields)"
```

---

## Task 8: `tcp_output.rs` — segment builders + TCP pseudo-header checksum

**Goal:** Build complete Ethernet + IPv4 + TCP frames for every outbound segment type A3 needs: SYN (with MSS option), bare ACK, ACK+data, ACK+FIN, ACK+RST, and a standalone RST for unmatched inbound packets. The TCP checksum is computed over the pseudo-header (src_ip, dst_ip, protocol=6, tcp_length) + TCP header + payload — spec §6.3 RFC 791/793 row.

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_output.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write the module + tests**

Create `crates/dpdk-net-core/src/tcp_output.rs`:

```rust
//! TCP segment builders. Every builder emits a complete Ethernet + IPv4 +
//! TCP frame, ready to hand to `Engine::tx_frame` for burst TX. We compute
//! both the IPv4 header checksum (software — later phases will flip to NIC
//! offload) and the TCP pseudo-header checksum per RFC 9293 §3.1.
//!
//! No TCP options beyond MSS (2-byte NOP-pad appended to keep the header a
//! multiple of 4 bytes). WSCALE / TS / SACK-permitted land in Phase A4.

use crate::l2::{ETHERTYPE_IPV4, ETH_HDR_LEN};
use crate::l3_ip::{internet_checksum, IPPROTO_TCP};

pub const TCP_HDR_MIN: usize = 20;
pub const IPV4_HDR_MIN: usize = 20;
pub const FRAME_HDRS_MIN: usize = ETH_HDR_LEN + IPV4_HDR_MIN + TCP_HDR_MIN; // 54

// TCP flag bits.
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// One-segment fields the caller controls. `payload` is appended after
/// the header (possibly empty).
pub struct SegmentTx<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: u32,  // host byte order
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss_option: Option<u16>,  // Some(mss) → append MSS option on SYN
    pub payload: &'a [u8],
}

/// Write the frame into `out`, returning the number of bytes written,
/// or `None` if `out` is too small. Minimum output size is
/// `FRAME_HDRS_MIN + mss_option.map_or(0, |_| 4) + payload.len()`.
pub fn build_segment(seg: &SegmentTx, out: &mut [u8]) -> Option<usize> {
    let opts_len = if seg.mss_option.is_some() { 4 } else { 0 };
    let tcp_hdr_len = TCP_HDR_MIN + opts_len;
    let total = ETH_HDR_LEN + IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len();
    if out.len() < total {
        return None;
    }

    // Ethernet
    out[0..6].copy_from_slice(&seg.dst_mac);
    out[6..12].copy_from_slice(&seg.src_mac);
    out[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4
    let ip_start = ETH_HDR_LEN;
    let ip = &mut out[ip_start..ip_start + IPV4_HDR_MIN];
    let total_ip_len = (IPV4_HDR_MIN + tcp_hdr_len + seg.payload.len()) as u16;
    ip[0] = 0x45; // ver=4, IHL=5
    ip[1] = 0x00;
    ip[2..4].copy_from_slice(&total_ip_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0x0000u16.to_be_bytes()); // identification
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, frag_off=0
    ip[8] = 64; // TTL
    ip[9] = IPPROTO_TCP;
    ip[10..12].copy_from_slice(&0x0000u16.to_be_bytes()); // csum placeholder
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
    th[12] = ((tcp_hdr_len / 4) as u8) << 4; // data offset
    th[13] = seg.flags;
    th[14..16].copy_from_slice(&seg.window.to_be_bytes());
    th[16..18].copy_from_slice(&0u16.to_be_bytes()); // csum placeholder
    th[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent ptr
    if let Some(mss) = seg.mss_option {
        // MSS option: kind=2, len=4, 2-byte value.
        th[20] = 2;
        th[21] = 4;
        th[22..24].copy_from_slice(&mss.to_be_bytes());
    }
    // Copy payload
    let payload_start = tcp_start + tcp_hdr_len;
    out[payload_start..payload_start + seg.payload.len()].copy_from_slice(seg.payload);

    // Compute TCP checksum over pseudo-header + TCP header + payload.
    let tcp_seg_len = (tcp_hdr_len + seg.payload.len()) as u32;
    let csum = tcp_checksum(
        seg.src_ip,
        seg.dst_ip,
        tcp_seg_len,
        &out[tcp_start..payload_start + seg.payload.len()],
    );
    out[tcp_start + 16] = (csum >> 8) as u8;
    out[tcp_start + 17] = (csum & 0xff) as u8;

    Some(total)
}

/// Pseudo-header checksum per RFC 9293 §3.1. Reuses `internet_checksum`
/// by folding a scratch buffer of pseudo-header + tcp segment bytes.
fn tcp_checksum(src_ip: u32, dst_ip: u32, tcp_seg_len: u32, tcp_bytes: &[u8]) -> u16 {
    // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + proto(1) + tcp_len(2)
    let mut buf = Vec::with_capacity(12 + tcp_bytes.len());
    buf.extend_from_slice(&src_ip.to_be_bytes());
    buf.extend_from_slice(&dst_ip.to_be_bytes());
    buf.push(0);
    buf.push(IPPROTO_TCP);
    buf.extend_from_slice(&(tcp_seg_len as u16).to_be_bytes());
    buf.extend_from_slice(tcp_bytes);
    internet_checksum(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l3_ip::ip_decode;

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
            mss_option: Some(1460),
            payload: &[],
        }
    }

    #[test]
    fn syn_frame_has_mss_option_and_valid_sizes() {
        let seg = base();
        let mut out = [0u8; 128];
        let n = build_segment(&seg, &mut out).unwrap();
        // 14 eth + 20 ip + 20 tcp + 4 mss = 58.
        assert_eq!(n, 58);
        // MSS option lives at offset 14+20+20 .. +4.
        assert_eq!(out[14 + 20 + 20], 2); // kind
        assert_eq!(out[14 + 20 + 21], 4); // len
        let mss = u16::from_be_bytes([out[14 + 20 + 22], out[14 + 20 + 23]]);
        assert_eq!(mss, 1460);
    }

    #[test]
    fn frame_ipv4_header_parses_roundtrip() {
        let seg = base();
        let mut out = [0u8; 128];
        let n = build_segment(&seg, &mut out).unwrap();
        let dec = ip_decode(&out[ETH_HDR_LEN..n], 0, false).expect("ip decode");
        assert_eq!(dec.protocol, IPPROTO_TCP);
        assert_eq!(dec.src_ip, 0x0a_00_00_02);
        assert_eq!(dec.dst_ip, 0x0a_00_00_01);
    }

    #[test]
    fn data_segment_with_payload_has_correct_tcp_csum() {
        let mut seg = base();
        let payload = b"HELLO";
        seg.flags = TCP_ACK | TCP_PSH;
        seg.mss_option = None;
        seg.payload = payload;
        let mut out = [0u8; 128];
        let n = build_segment(&seg, &mut out).unwrap();
        // 14 + 20 + 20 + 5 = 59
        assert_eq!(n, 59);
        // Verify csum by recomputing: zero out the csum bytes and fold.
        let tcp_start = ETH_HDR_LEN + IPV4_HDR_MIN;
        let mut scratch = out[tcp_start..n].to_vec();
        scratch[16] = 0;
        scratch[17] = 0;
        let expected = tcp_checksum(seg.src_ip, seg.dst_ip, scratch.len() as u32, &scratch);
        let actual = u16::from_be_bytes([out[tcp_start + 16], out[tcp_start + 17]]);
        assert_eq!(expected, actual);
    }

    #[test]
    fn output_too_small_returns_none() {
        let seg = base();
        let mut out = [0u8; 50];
        assert!(build_segment(&seg, &mut out).is_none());
    }

    #[test]
    fn rst_frame_has_rst_flag_and_no_options() {
        let mut seg = base();
        seg.flags = TCP_RST | TCP_ACK;
        seg.mss_option = None;
        let mut out = [0u8; 64];
        let n = build_segment(&seg, &mut out).unwrap();
        assert_eq!(n, 54);
        assert_eq!(out[14 + 20 + 13], TCP_RST | TCP_ACK);
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`, add after `pub mod tcp_conn;`:

```rust
pub mod tcp_output;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core tcp_output::`
Expected: 5 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_output.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add tcp_output: eth+ip+tcp segment builders with pseudo-header csum"
```

---

## Task 9: `tcp_events.rs` — internal FIFO event queue

**Goal:** An internal `VecDeque<InternalEvent>` that accumulates events as TCP FSM transitions fire, drained by `dpdk_net_poll` into the caller's `events_out[]`. Spec §4.2 event-overflow policy: "fills `events_out[0..max_events]` with events in FIFO enqueue order, stops further RX-burst processing for this iteration, and leaves the overflow queued inside the engine". A3 implements the FIFO side; the rx-burst-stop interaction is implemented in the `poll_once` change (Task 18).

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_events.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write the module + tests**

Create `crates/dpdk-net-core/src/tcp_events.rs`:

```rust
//! Internal FIFO event queue. Populated by FSM transitions and data
//! delivery; drained at the top of `dpdk_net_poll` into the caller's
//! `events_out[]` array.

use std::collections::VecDeque;

use crate::flow_table::ConnHandle;
use crate::tcp_state::TcpState;

/// Event kinds internal to the engine. Translated to public
/// `dpdk_net_event_t` values at the C ABI boundary.
#[derive(Debug, Clone)]
pub enum InternalEvent {
    Connected {
        conn: ConnHandle,
        rx_hw_ts_ns: u64,
    },
    /// `byte_len` bytes are available starting at the connection's
    /// `recv.last_read_buf` scratch region. The caller promotes this
    /// to a `(data, data_len)` view at the ABI boundary.
    Readable {
        conn: ConnHandle,
        byte_len: u32,
        rx_hw_ts_ns: u64,
    },
    Closed {
        conn: ConnHandle,
        err: i32, // 0 = clean close; negative errno otherwise
    },
    StateChange {
        conn: ConnHandle,
        from: TcpState,
        to: TcpState,
    },
    Error {
        conn: ConnHandle,
        err: i32,
    },
}

pub struct EventQueue {
    q: VecDeque<InternalEvent>,
}

impl EventQueue {
    pub fn new() -> Self {
        Self { q: VecDeque::with_capacity(64) }
    }

    pub fn push(&mut self, ev: InternalEvent) {
        self.q.push_back(ev);
    }

    pub fn pop(&mut self) -> Option<InternalEvent> {
        self.q.pop_front()
    }

    pub fn len(&self) -> usize {
        self.q.len()
    }

    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
}

impl Default for EventQueue {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_ordering() {
        let mut q = EventQueue::new();
        q.push(InternalEvent::Connected { conn: 1, rx_hw_ts_ns: 0 });
        q.push(InternalEvent::Closed { conn: 1, err: 0 });
        match q.pop() {
            Some(InternalEvent::Connected { conn, .. }) => assert_eq!(conn, 1),
            other => panic!("expected Connected, got {other:?}"),
        }
        assert!(matches!(q.pop(), Some(InternalEvent::Closed { .. })));
        assert!(q.pop().is_none());
    }

    #[test]
    fn len_tracks_outstanding() {
        let mut q = EventQueue::new();
        assert!(q.is_empty());
        q.push(InternalEvent::Error { conn: 1, err: -5 });
        assert_eq!(q.len(), 1);
        let _ = q.pop();
        assert!(q.is_empty());
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`, add after `pub mod tcp_output;`:

```rust
pub mod tcp_events;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core tcp_events::`
Expected: 2 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_events.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add tcp_events: internal fifo event queue"
```

---

## Task 10: `tcp_input.rs` skeleton — header parser + per-state dispatch

**Goal:** Parse a TCP segment from an IP payload slice, extract the 4-tuple, and dispatch to per-state handlers. For now every handler is a stub that increments `tcp.rx_unmatched` — subsequent tasks fill in SYN_SENT (Task 11), ESTABLISHED (Task 12), and close-path states (Task 13). This task locks in the parser + the dispatch wiring so those tasks are additive.

**Files:**
- Create: `crates/dpdk-net-core/src/tcp_input.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write the parser + skeleton**

Create `crates/dpdk-net-core/src/tcp_input.rs`:

```rust
//! Inbound TCP segment processing. Entry point is `tcp_input_dispatch`;
//! it parses the segment, looks up the flow, and dispatches to the
//! per-state handler. Per-state handlers are in this file but live
//! in `handle_syn_sent`, `handle_established`, etc.
//!
//! Per-segment ACK policy (spec §6.4): every segment that advances
//! `rcv_nxt` or transitions state triggers an ACK on the same poll
//! iteration (wired in the handlers via `TxAction::Ack`).

use crate::flow_table::{ConnHandle, FourTuple};
use crate::tcp_conn::TcpConn;
use crate::tcp_output::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
use crate::tcp_state::TcpState;

#[derive(Debug, Clone, Copy)]
pub struct ParsedSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub header_len: usize, // bytes including options
    pub payload: &'a [u8],
    /// The raw options-bytes region, if any. A3 only peeks for MSS
    /// (RFC 6691); unknown options are skipped.
    pub options: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpParseError {
    Short,
    BadDataOffset,
    BadFlags,
    Csum,
}

/// Parse a TCP segment from `tcp_bytes` (starts at the TCP header).
/// `src_ip`/`dst_ip` are from the IPv4 header in host byte order and
/// are used for the pseudo-header checksum verification. Caller can
/// skip verification by passing `nic_csum_ok=true` when the NIC has
/// already verified the TCP checksum.
pub fn parse_segment<'a>(
    tcp_bytes: &'a [u8],
    src_ip: u32,
    dst_ip: u32,
    nic_csum_ok: bool,
) -> Result<ParsedSegment<'a>, TcpParseError> {
    if tcp_bytes.len() < 20 {
        return Err(TcpParseError::Short);
    }
    let src_port = u16::from_be_bytes([tcp_bytes[0], tcp_bytes[1]]);
    let dst_port = u16::from_be_bytes([tcp_bytes[2], tcp_bytes[3]]);
    let seq = u32::from_be_bytes([tcp_bytes[4], tcp_bytes[5], tcp_bytes[6], tcp_bytes[7]]);
    let ack = u32::from_be_bytes([tcp_bytes[8], tcp_bytes[9], tcp_bytes[10], tcp_bytes[11]]);
    let data_off_words = (tcp_bytes[12] >> 4) as usize;
    if data_off_words < 5 {
        return Err(TcpParseError::BadDataOffset);
    }
    let header_len = data_off_words * 4;
    if tcp_bytes.len() < header_len {
        return Err(TcpParseError::BadDataOffset);
    }
    let flags = tcp_bytes[13];
    // Reject obviously-broken flag combinations per RFC 9293 §3.5
    // (SYN+FIN is nonsensical; RST+SYN likewise).
    if (flags & TCP_SYN) != 0 && (flags & TCP_FIN) != 0 {
        return Err(TcpParseError::BadFlags);
    }
    if (flags & TCP_RST) != 0 && (flags & TCP_SYN) != 0 {
        return Err(TcpParseError::BadFlags);
    }
    let window = u16::from_be_bytes([tcp_bytes[14], tcp_bytes[15]]);
    let options = &tcp_bytes[20..header_len];
    let payload = &tcp_bytes[header_len..];

    if !nic_csum_ok {
        let stored = u16::from_be_bytes([tcp_bytes[16], tcp_bytes[17]]);
        let mut scratch = tcp_bytes.to_vec();
        scratch[16] = 0;
        scratch[17] = 0;
        let csum = tcp_pseudo_csum(src_ip, dst_ip, scratch.len() as u32, &scratch);
        // Folded result of header-with-zero-csum + stored-csum should sum to 0.
        if csum != stored {
            return Err(TcpParseError::Csum);
        }
    }

    Ok(ParsedSegment {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        header_len,
        payload,
        options,
    })
}

fn tcp_pseudo_csum(src_ip: u32, dst_ip: u32, tcp_seg_len: u32, tcp_bytes: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp_bytes.len());
    buf.extend_from_slice(&src_ip.to_be_bytes());
    buf.extend_from_slice(&dst_ip.to_be_bytes());
    buf.push(0);
    buf.push(crate::l3_ip::IPPROTO_TCP);
    buf.extend_from_slice(&(tcp_seg_len as u16).to_be_bytes());
    buf.extend_from_slice(tcp_bytes);
    crate::l3_ip::internet_checksum(&buf)
}

/// Parse the TCP options field for a MSS value. Returns 536 (RFC 9293
/// §3.7.1 default) when absent. Unknown options are skipped by `len`.
pub fn parse_mss_option(options: &[u8]) -> u16 {
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            0 => return 536, // End of options
            1 => { i += 1; } // NOP
            2 => {
                // MSS option
                if i + 4 > options.len() || options[i + 1] != 4 {
                    return 536;
                }
                return u16::from_be_bytes([options[i + 2], options[i + 3]]);
            }
            _ => {
                if i + 1 >= options.len() {
                    return 536;
                }
                let olen = options[i + 1] as usize;
                if olen < 2 {
                    return 536;
                }
                i += olen;
            }
        }
    }
    536
}

/// What the engine should do next after processing a segment. Emitted
/// by the per-state handlers and consumed by the engine's dispatch code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAction {
    None,
    Ack,
    Rst,
}

/// Outcome of dispatching a segment to a per-state handler.
#[derive(Debug, Clone, Copy)]
pub struct Outcome {
    pub tx: TxAction,
    pub new_state: Option<TcpState>,
    /// Number of payload bytes delivered to recv queue this segment.
    /// `> 0` implies the engine should enqueue a Readable event.
    pub delivered: u32,
    /// True iff this segment completed a handshake (SYN_SENT → ESTABLISHED).
    pub connected: bool,
    /// True iff this segment completed a clean close (→ CLOSED or
    /// entered TIME_WAIT which reaps to CLOSED).
    pub closed: bool,
}

impl Outcome {
    pub fn none() -> Self {
        Self { tx: TxAction::None, new_state: None, delivered: 0, connected: false, closed: false }
    }
    pub fn rst() -> Self {
        Self { tx: TxAction::Rst, new_state: Some(TcpState::Closed), delivered: 0, connected: false, closed: true }
    }
}

/// Per-state dispatcher. Stubs for now; concrete handlers land in
/// Tasks 11–13.
pub fn dispatch(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    match conn.state {
        TcpState::SynSent => handle_syn_sent(conn, seg),
        TcpState::Established => handle_established(conn, seg),
        TcpState::FinWait1
        | TcpState::FinWait2
        | TcpState::Closing
        | TcpState::LastAck
        | TcpState::CloseWait
        | TcpState::TimeWait => handle_close_path(conn, seg),
        _ => Outcome::none(),
    }
}

// Stubs filled in by subsequent tasks.
fn handle_syn_sent(_conn: &mut TcpConn, _seg: &ParsedSegment) -> Outcome {
    Outcome::none()
}

fn handle_established(_conn: &mut TcpConn, _seg: &ParsedSegment) -> Outcome {
    Outcome::none()
}

fn handle_close_path(_conn: &mut TcpConn, _seg: &ParsedSegment) -> Outcome {
    Outcome::none()
}

/// Build the 4-tuple from a parsed segment's ports + the IPv4 header's
/// source/destination. Caller owns the IP fields. HBO throughout.
pub fn tuple_from_segment(src_ip: u32, dst_ip: u32, seg: &ParsedSegment) -> FourTuple {
    // RX: the segment arrives FROM peer TO us. Our tuple has
    // local = our side, peer = their side.
    FourTuple {
        local_ip: dst_ip,
        local_port: seg.dst_port,
        peer_ip: src_ip,
        peer_port: seg.src_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_output::{build_segment, SegmentTx};

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
            mss_option: mss,
            payload,
        };
        let mut out = vec![0u8; 256];
        let n = build_segment(&seg, &mut out).unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn parse_ack_segment_with_payload() {
        let frame = build_test_segment(TCP_ACK | TCP_PSH, None, b"hello");
        let tcp = &frame[14 + 20..];
        let p = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, false).unwrap();
        assert_eq!(p.src_port, 5000);
        assert_eq!(p.dst_port, 40000);
        assert_eq!(p.seq, 100);
        assert_eq!(p.ack, 200);
        assert_eq!(p.payload, b"hello");
        assert_eq!(p.flags, TCP_ACK | TCP_PSH);
    }

    #[test]
    fn parse_rejects_short_segment() {
        let err = parse_segment(&[0u8; 10], 0, 0, true).unwrap_err();
        assert_eq!(err, TcpParseError::Short);
    }

    #[test]
    fn parse_rejects_syn_fin_combo() {
        let frame = build_test_segment(TCP_SYN | TCP_FIN, None, &[]);
        let tcp = &frame[14 + 20..];
        let err = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, true).unwrap_err();
        assert_eq!(err, TcpParseError::BadFlags);
    }

    #[test]
    fn parse_mss_option_present() {
        let frame = build_test_segment(TCP_SYN | TCP_ACK, Some(1460), &[]);
        let tcp = &frame[14 + 20..];
        let p = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, false).unwrap();
        assert_eq!(parse_mss_option(p.options), 1460);
    }

    #[test]
    fn parse_mss_absent_returns_default() {
        assert_eq!(parse_mss_option(&[]), 536);
    }

    #[test]
    fn bad_tcp_csum_rejected() {
        let mut frame = build_test_segment(TCP_ACK, None, b"hi");
        // Flip a payload bit — csum must now mismatch.
        frame[14 + 20 + 20] ^= 0xff;
        let tcp = &frame[14 + 20..];
        let err = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, false).unwrap_err();
        assert_eq!(err, TcpParseError::Csum);
    }

    #[test]
    fn tuple_from_segment_swaps_src_and_dst() {
        let frame = build_test_segment(TCP_ACK, None, &[]);
        let tcp = &frame[14 + 20..];
        let p = parse_segment(tcp, 0x0a_00_00_01, 0x0a_00_00_02, false).unwrap();
        let t = tuple_from_segment(0x0a_00_00_01, 0x0a_00_00_02, &p);
        assert_eq!(t.local_ip, 0x0a_00_00_02);
        assert_eq!(t.local_port, 40000);
        assert_eq!(t.peer_ip, 0x0a_00_00_01);
        assert_eq!(t.peer_port, 5000);
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`, add after `pub mod tcp_events;`:

```rust
pub mod tcp_input;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core tcp_input::`
Expected: 7 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_input.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add tcp_input skeleton: header parser + per-state dispatch (stub handlers)"
```

---

## Task 11: `handle_syn_sent` — complete client handshake on SYN-ACK

**Goal:** When a segment arrives for a SYN_SENT connection: validate it's a SYN-ACK for our ISS+1; set `rcv_nxt = irs+1`, `snd_una = ack`, peer's MSS (via options); transition to ESTABLISHED; request an ACK be sent back; flag `connected = true` so the engine emits `EVT_CONNECTED`. A non-matching ACK → RST. A SYN-only (simultaneous-open) — deferred to A4; we drop with `BadFlags` counter.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs`

- [ ] **Step 1: Write the failing tests**

Append to `crates/dpdk-net-core/src/tcp_input.rs` inside `mod tests`:

```rust
    #[test]
    fn syn_sent_syn_ack_transitions_to_established() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1); // after SYN TX
        // Craft a SYN-ACK: their seq=5000, their ack=1001 (our iss+1), MSS=1400.
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5000, ack: 1001,
            flags: TCP_SYN | TCP_ACK,
            window: 65535,
            header_len: 24,
            payload: &[],
            options: &[2, 4, 0x05, 0x78], // MSS=1400
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Established));
        assert_eq!(out.tx, TxAction::Ack);
        assert!(out.connected);
        assert_eq!(c.rcv_nxt, 5001);
        assert_eq!(c.snd_una, 1001);
        assert_eq!(c.irs, 5000);
        assert_eq!(c.peer_mss, 1400);
    }

    #[test]
    fn syn_sent_plain_ack_wrong_seq_sends_rst() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        // Bogus: ACK-only with an ack that doesn't cover our SYN.
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5000, ack: 999,
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Rst);
    }

    #[test]
    fn syn_sent_rst_matching_our_ack_closes() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;

        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::SynSent;
        c.snd_nxt = c.snd_nxt.wrapping_add(1);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 0, ack: 1001,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
        assert_eq!(out.tx, TxAction::None);
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net-core tcp_input::tests::syn_sent_`
Expected: FAIL with assertion errors (stub returns `Outcome::none()`).

- [ ] **Step 3: Implement `handle_syn_sent`** — replace the stub in `crates/dpdk-net-core/src/tcp_input.rs`:

```rust
fn handle_syn_sent(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    use crate::tcp_seq::seq_le;

    // RFC 9293 §3.10.7.3 — SYN_SENT processing.
    // RST without a valid ACK of our SYN → drop silently. With a valid
    // ACK (snd_una < ack <= snd_nxt) → close.
    if (seg.flags & TCP_RST) != 0 {
        if (seg.flags & TCP_ACK) != 0
            && seq_le(conn.snd_una.wrapping_add(1), seg.ack)
            && seq_le(seg.ack, conn.snd_nxt)
        {
            return Outcome {
                tx: TxAction::None,
                new_state: Some(TcpState::Closed),
                delivered: 0,
                connected: false,
                closed: true,
            };
        }
        return Outcome::none();
    }

    // Must have SYN to advance from SYN_SENT. Simultaneous-open (SYN
    // without ACK) transitions to SYN_RECEIVED per RFC 9293 — deferred
    // to A4. We drop it here.
    if (seg.flags & TCP_SYN) == 0 {
        return Outcome::rst();
    }

    if (seg.flags & TCP_ACK) == 0 {
        // SYN-only (simultaneous-open): deferred.
        return Outcome::none();
    }

    // ACK must cover exactly iss+1 (our SYN). Accept only when
    // snd_una+1 <= ack <= snd_nxt (RFC 9293 §3.10.7.3).
    if !seq_le(conn.snd_una.wrapping_add(1), seg.ack)
        || !seq_le(seg.ack, conn.snd_nxt)
    {
        return Outcome::rst();
    }

    // Update state per RFC 9293.
    conn.irs = seg.seq;
    conn.rcv_nxt = seg.seq.wrapping_add(1);
    conn.snd_una = seg.ack;
    conn.snd_wnd = seg.window as u32;
    conn.snd_wl1 = seg.seq;
    conn.snd_wl2 = seg.ack;
    conn.peer_mss = parse_mss_option(seg.options);

    Outcome {
        tx: TxAction::Ack,
        new_state: Some(TcpState::Established),
        delivered: 0,
        connected: true,
        closed: false,
    }
}
```

- [ ] **Step 4: Run — verify PASS**

Run: `cargo test -p dpdk-net-core tcp_input::`
Expected: 10 PASS (7 from Task 10 + 3 new).

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_input.rs
git commit -m "tcp_input: handle SYN_SENT — SYN-ACK completes handshake, rst path"
```

---

## Task 12: `handle_established` — data + ACK + FIN processing

**Goal:** In ESTABLISHED: (1) validate `seq` is in-window `[rcv_nxt, rcv_nxt+rcv_wnd)`; out-of-window → ACK with current state and drop. (2) process the ACK field: advance `snd_una` if it moves; drop ACKed bytes from `snd.pending`; update `snd_wnd`/`snd_wl1`/`snd_wl2`. (3) if payload at `seq == rcv_nxt`, deliver in-order bytes to `recv` queue (drop/count out-of-order), advance `rcv_nxt`, set `delivered = n`. (4) if FIN — advance `rcv_nxt` by 1, transition to CLOSE_WAIT, request ACK. (5) RST on any established segment immediately closes.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs`

- [ ] **Step 1: Write the failing tests**

Append to `crates/dpdk-net-core/src/tcp_input.rs` inside `mod tests`:

```rust
    fn est_conn(iss: u32, irs: u32, peer_wnd: u16) -> crate::tcp_conn::TcpConn {
        use crate::flow_table::FourTuple;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = crate::tcp_conn::TcpConn::new_client(t, iss, 1460, 1024, 2048);
        c.state = TcpState::Established;
        c.snd_una = iss.wrapping_add(1);
        c.snd_nxt = iss.wrapping_add(1);
        c.irs = irs;
        c.rcv_nxt = irs.wrapping_add(1);
        c.snd_wnd = peer_wnd as u32;
        c
    }

    #[test]
    fn established_inorder_data_delivered_and_acked() {
        let mut c = est_conn(1000, 5000, 1024);
        let payload = b"abcdef";
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_PSH,
            window: 65535,
            header_len: 20,
            payload, options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 6);
        assert_eq!(c.rcv_nxt, 5001 + 6);
        assert_eq!(c.recv.bytes.len(), 6);
        let got: Vec<u8> = c.recv.bytes.iter().copied().collect();
        assert_eq!(&got, b"abcdef");
    }

    #[test]
    fn established_ooo_segment_acked_but_not_delivered() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5100, ack: 1001, // jumps past rcv_nxt
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: b"xyz", options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.delivered, 0);
        assert_eq!(c.rcv_nxt, 5001); // unchanged
    }

    #[test]
    fn established_ack_field_advances_snd_una() {
        let mut c = est_conn(1000, 5000, 1024);
        // Simulate 5 bytes in flight: push to snd.pending and advance snd_nxt.
        c.snd.push(b"hello");
        c.snd_nxt = c.snd_una.wrapping_add(5);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1006, // acks 5 bytes
            flags: TCP_ACK,
            window: 32000,
            header_len: 20,
            payload: &[], options: &[],
        };
        let _ = dispatch(&mut c, &seg);
        assert_eq!(c.snd_una, 1006);
        assert_eq!(c.snd_wnd, 32000);
        assert_eq!(c.snd.pending.len(), 0);
    }

    #[test]
    fn established_fin_transitions_to_close_wait() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::CloseWait));
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(c.rcv_nxt, 5002); // FIN consumes one seq
    }

    #[test]
    fn established_rst_closes_immediately() {
        let mut c = est_conn(1000, 5000, 1024);
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net-core tcp_input::tests::established_`
Expected: FAIL.

- [ ] **Step 3: Implement `handle_established`** — replace the stub:

```rust
fn handle_established(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    use crate::tcp_seq::{in_window, seq_le, seq_lt};

    // RST → close per RFC 9293 §3.10.7.4.
    if (seg.flags & TCP_RST) != 0 {
        return Outcome {
            tx: TxAction::None,
            new_state: Some(TcpState::Closed),
            delivered: 0,
            connected: false,
            closed: true,
        };
    }

    // Segment must carry ACK in ESTABLISHED.
    if (seg.flags & TCP_ACK) == 0 {
        return Outcome::none();
    }

    // Sequence-window check — RFC 9293 §3.10.7.4. Accept iff either
    // the seg has no payload and seq==rcv_nxt (pure ACK), or its
    // payload's first byte lies within our recv window. Our check is
    // stricter than mTCP's (both edges); see spec §6.1 + plan header.
    let seg_len = seg.payload.len() as u32
        + ((seg.flags & TCP_FIN) != 0) as u32; // FIN consumes one
    let in_win = if seg_len == 0 {
        seg.seq == conn.rcv_nxt
    } else {
        let last = seg.seq.wrapping_add(seg_len).wrapping_sub(1);
        in_window(conn.rcv_nxt, seg.seq, conn.rcv_wnd)
            && in_window(conn.rcv_nxt, last, conn.rcv_wnd)
    };
    if !in_win {
        // Out-of-window: challenge ACK and drop.
        return Outcome { tx: TxAction::Ack, new_state: None, delivered: 0, connected: false, closed: false };
    }

    // ACK processing — RFC 9293 §3.10.7.4, "ESTABLISHED STATE" ACK handling.
    if seq_lt(conn.snd_una, seg.ack) && seq_le(seg.ack, conn.snd_nxt) {
        let acked = seg.ack.wrapping_sub(conn.snd_una) as usize;
        for _ in 0..acked.min(conn.snd.pending.len()) {
            conn.snd.pending.pop_front();
        }
        conn.snd_una = seg.ack;
        // Update send window. Only accept advances from newer segments
        // per RFC 9293 §3.10.7.4 "SND.WL1 / SND.WL2" rules.
        if seq_lt(conn.snd_wl1, seg.seq)
            || (conn.snd_wl1 == seg.seq && seq_le(conn.snd_wl2, seg.ack))
        {
            conn.snd_wnd = seg.window as u32;
            conn.snd_wl1 = seg.seq;
            conn.snd_wl2 = seg.ack;
        }
    } else if seq_lt(conn.snd_nxt, seg.ack) {
        // ACK ahead of snd_nxt → we never sent that much; challenge ACK.
        return Outcome { tx: TxAction::Ack, new_state: None, delivered: 0, connected: false, closed: false };
    }
    // Else: duplicate ACK (ack <= snd_una) — no-op for A3 (A5 uses it for fast retx).

    // Data delivery (only in-order).
    let mut delivered = 0u32;
    if !seg.payload.is_empty() && seg.seq == conn.rcv_nxt {
        delivered = conn.recv.append(seg.payload);
        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(delivered);
    }

    // FIN processing: consumes one seq and moves us to CLOSE_WAIT.
    let mut new_state = None;
    if (seg.flags & TCP_FIN) != 0
        && seg.seq.wrapping_add(seg.payload.len() as u32) == conn.rcv_nxt
    {
        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
        new_state = Some(TcpState::CloseWait);
    }

    // Emit ACK whenever we advance rcv_nxt OR take a FIN.
    let tx = if delivered > 0 || new_state == Some(TcpState::CloseWait) {
        TxAction::Ack
    } else {
        // Pure-ack segment that advanced snd_una — no response required
        // per RFC 9293 §3.10.7.4. But we still want a challenge-ack on
        // out-of-window arrivals; those returned earlier.
        TxAction::None
    };

    Outcome { tx, new_state, delivered, connected: false, closed: false }
}
```

- [ ] **Step 4: Run — verify PASS**

Run: `cargo test -p dpdk-net-core tcp_input::`
Expected: 15 PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_input.rs
git commit -m "tcp_input: handle ESTABLISHED — seq-window check, ack advance, in-order data, FIN"
```

---

## Task 13: `handle_close_path` — FIN_WAIT_1/2, CLOSING, LAST_ACK, CLOSE_WAIT, TIME_WAIT

**Goal:** Implement the five close-path states. FIN_WAIT_1 → FIN_WAIT_2 on ACK-of-our-FIN; FIN_WAIT_1 → CLOSING on peer's FIN before our FIN is ACKed; FIN_WAIT_2 → TIME_WAIT on peer's FIN; CLOSING → TIME_WAIT on ACK-of-our-FIN; TIME_WAIT silently ACKs any inbound segment; CLOSE_WAIT is dead-in-dispatch (we only leave it via application `close`, which runs through Task 17's engine code). LAST_ACK → CLOSED on ACK-of-our-FIN.

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs`

- [ ] **Step 1: Write the failing tests**

Append to `mod tests`:

```rust
    #[test]
    fn fin_wait1_ack_of_our_fin_transitions_to_fin_wait2() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::FinWait1;
        c.snd_una = 1001;
        c.snd_nxt = 1002; // after our FIN
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1002, // acks our FIN
            flags: TCP_ACK,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::FinWait2));
    }

    #[test]
    fn fin_wait2_peer_fin_transitions_to_time_wait() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::FinWait2;
        c.snd_una = 1002;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1002,
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::TimeWait));
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(c.rcv_nxt, 5002);
    }

    #[test]
    fn fin_wait1_peer_fin_without_ack_of_our_fin_transitions_to_closing() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::FinWait1;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5001;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1001, // does NOT ack our FIN
            flags: TCP_ACK | TCP_FIN,
            window: 65535,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closing));
    }

    #[test]
    fn closing_ack_of_our_fin_transitions_to_time_wait() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::Closing;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5002; // peer's FIN already consumed
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5002, ack: 1002,
            flags: TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::TimeWait));
    }

    #[test]
    fn last_ack_ack_of_our_fin_closes_connection() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::LastAck;
        c.snd_una = 1001;
        c.snd_nxt = 1002;
        c.our_fin_seq = Some(1001);
        c.irs = 5000;
        c.rcv_nxt = 5002;
        c.rcv_wnd = 1024;
        c.snd_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5002, ack: 1002,
            flags: TCP_ACK,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.new_state, Some(TcpState::Closed));
        assert!(out.closed);
    }

    #[test]
    fn time_wait_replays_ack_on_any_segment() {
        use crate::flow_table::FourTuple;
        use crate::tcp_conn::TcpConn;
        let t = FourTuple { local_ip: 0x0a_00_00_02, local_port: 40000,
                            peer_ip: 0x0a_00_00_01, peer_port: 5000 };
        let mut c = TcpConn::new_client(t, 1000, 1460, 1024, 2048);
        c.state = TcpState::TimeWait;
        c.our_fin_seq = Some(1001);
        c.rcv_nxt = 5002;
        c.rcv_wnd = 1024;
        let seg = ParsedSegment {
            src_port: 5000, dst_port: 40000,
            seq: 5001, ack: 1002,
            flags: TCP_ACK | TCP_FIN,
            window: 0,
            header_len: 20,
            payload: &[], options: &[],
        };
        let out = dispatch(&mut c, &seg);
        assert_eq!(out.tx, TxAction::Ack);
        assert_eq!(out.new_state, None); // stay in TIME_WAIT until reaper
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net-core tcp_input::tests::fin_wait1_ tcp_input::tests::fin_wait2_ tcp_input::tests::closing_ tcp_input::tests::last_ack_ tcp_input::tests::time_wait_`
Expected: FAIL.

- [ ] **Step 3: Implement `handle_close_path`** — replace the stub:

```rust
fn handle_close_path(conn: &mut TcpConn, seg: &ParsedSegment) -> Outcome {
    use crate::tcp_seq::{in_window, seq_le, seq_lt};

    // RST in any close state → CLOSED.
    if (seg.flags & TCP_RST) != 0 {
        return Outcome {
            tx: TxAction::None,
            new_state: Some(TcpState::Closed),
            delivered: 0,
            connected: false,
            closed: true,
        };
    }

    // TIME_WAIT: replay-ACK anything the peer sends; reaper will move
    // us to CLOSED via the engine tick (Task 14).
    if conn.state == TcpState::TimeWait {
        return Outcome { tx: TxAction::Ack, new_state: None, delivered: 0, connected: false, closed: false };
    }

    // Segment must have ACK in these states.
    if (seg.flags & TCP_ACK) == 0 {
        return Outcome::none();
    }

    // Window check — same rule as ESTABLISHED.
    let seg_len = seg.payload.len() as u32 + ((seg.flags & TCP_FIN) != 0) as u32;
    let in_win = if seg_len == 0 {
        seg.seq == conn.rcv_nxt
    } else {
        let last = seg.seq.wrapping_add(seg_len).wrapping_sub(1);
        in_window(conn.rcv_nxt, seg.seq, conn.rcv_wnd)
            && in_window(conn.rcv_nxt, last, conn.rcv_wnd)
    };
    if !in_win {
        return Outcome { tx: TxAction::Ack, new_state: None, delivered: 0, connected: false, closed: false };
    }

    // Advance snd_una if ack covers more of our stream.
    let fin_acked = conn.fin_has_been_acked(seg.ack);
    if seq_lt(conn.snd_una, seg.ack) && seq_le(seg.ack, conn.snd_nxt) {
        conn.snd_una = seg.ack;
    }

    let peer_has_fin = (seg.flags & TCP_FIN) != 0
        && seg.seq.wrapping_add(seg.payload.len() as u32) == conn.rcv_nxt;
    if peer_has_fin {
        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
    }

    // State transitions keyed by (current_state, fin_acked, peer_has_fin).
    let (new_state, tx) = match (conn.state, fin_acked, peer_has_fin) {
        (TcpState::FinWait1, true, true) => (Some(TcpState::TimeWait), TxAction::Ack),
        (TcpState::FinWait1, true, false) => (Some(TcpState::FinWait2), TxAction::None),
        (TcpState::FinWait1, false, true) => (Some(TcpState::Closing), TxAction::Ack),
        (TcpState::FinWait1, false, false) => (None, TxAction::None),
        (TcpState::FinWait2, _, true) => (Some(TcpState::TimeWait), TxAction::Ack),
        (TcpState::FinWait2, _, false) => (None, TxAction::None),
        (TcpState::Closing, true, _) => (Some(TcpState::TimeWait), TxAction::None),
        (TcpState::Closing, false, _) => (None, TxAction::None),
        (TcpState::LastAck, true, _) => (Some(TcpState::Closed), TxAction::None),
        (TcpState::LastAck, false, _) => (None, TxAction::None),
        (TcpState::CloseWait, _, _) => (None, TxAction::None),
        _ => (None, TxAction::None),
    };

    let closed = new_state == Some(TcpState::Closed);
    Outcome { tx, new_state, delivered: 0, connected: false, closed }
}
```

- [ ] **Step 4: Run — verify PASS**

Run: `cargo test -p dpdk-net-core tcp_input::`
Expected: 21 PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/tcp_input.rs
git commit -m "tcp_input: handle close-path states (fin_wait1/2, closing, last_ack, time_wait)"
```

---

## Task 14: Extend `error.rs` for A3 API error variants

**Goal:** Add `Error` variants `TooManyConns`, `InvalidConnHandle`, `PeerUnreachable`, `SendBufferFull` so the public-API bridge can emit meaningful errnos. The public API continues to use plain `-libc::ENOMEM`/`-ENOTCONN`/`-EINVAL` etc. at the boundary; the Rust variants exist for internal clarity.

**Files:**
- Modify: `crates/dpdk-net-core/src/error.rs`

- [ ] **Step 1: Write the failing test** (a compile-time check is enough here; no behavior to test)

Append to `crates/dpdk-net-core/src/error.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn a3_variants_format_cleanly() {
        assert!(format!("{}", Error::TooManyConns).contains("too many"));
        assert!(format!("{}", Error::InvalidConnHandle(0)).contains("0"));
        assert!(format!("{}", Error::PeerUnreachable(0xdeadbeef)).contains("deadbeef"));
        assert!(format!("{}", Error::SendBufferFull).contains("buffer"));
    }
}
```

- [ ] **Step 2: Add the variants** — extend `Error`:

```rust
    #[error("too many open connections (max_connections reached)")]
    TooManyConns,
    #[error("invalid connection handle: {0}")]
    InvalidConnHandle(u64),
    #[error("peer unreachable: ip={0:#x}")]
    PeerUnreachable(u32),
    #[error("send buffer full for this connection")]
    SendBufferFull,
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core error::`
Expected: 1 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/error.rs
git commit -m "add a3 error variants: TooManyConns, InvalidConnHandle, PeerUnreachable, SendBufferFull"
```

---

## Task 15: Engine wiring — flow_table, event_queue, iss, `tx_data_frame`, tcp_input dispatch

**Goal:** Extend `Engine` with `flow_table: RefCell<FlowTable>`, `events: RefCell<EventQueue>`, `iss: IssGen`, and a `last_ephemeral_port: Cell<u16>` to hand out outbound source ports. Replace `tcp_input_stub` with a real handler that parses the segment, looks up the conn, calls `dispatch`, emits ACK/RST via `tx_frame`, and pushes events to the queue. Add a `tx_data_frame(bytes)` helper that allocates from `tx_data_mempool` instead of `tx_hdr_mempool` (so large data segments don't exhaust the small-mbuf pool).

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Rewrite the `Engine` struct + `new` to hold A3 state**

In `crates/dpdk-net-core/src/engine.rs`, extend the imports at the top:

```rust
use std::cell::{Cell, RefCell};

use crate::arp;
use crate::counters::Counters;
use crate::flow_table::{ConnHandle, FlowTable, FourTuple, INVALID_HANDLE};
use crate::iss::IssGen;
use crate::icmp::PmtuTable;
use crate::mempool::Mempool;
use crate::tcp_events::{EventQueue, InternalEvent};
use crate::tcp_state::TcpState;
use crate::Error;
```

Replace the `Engine` struct with:

```rust
pub struct Engine {
    cfg: EngineConfig,
    counters: Box<Counters>,
    _rx_mempool: Mempool,
    tx_hdr_mempool: Mempool,
    tx_data_mempool: Mempool,
    our_mac: [u8; 6],
    pmtu: RefCell<PmtuTable>,
    last_garp_ns: RefCell<u64>,

    // Phase A3 additions
    flow_table: RefCell<FlowTable>,
    events: RefCell<EventQueue>,
    iss_gen: IssGen,
    last_ephemeral_port: Cell<u16>,
}
```

Inside `Engine::new`, right before the `Ok(Self { ... })` at the end, replace the construction block with:

```rust
        Ok(Self {
            counters,
            _rx_mempool: rx_mempool,
            tx_hdr_mempool,
            tx_data_mempool,
            our_mac,
            pmtu: RefCell::new(PmtuTable::new()),
            last_garp_ns: RefCell::new(0),
            flow_table: RefCell::new(FlowTable::new(cfg.max_connections)),
            events: RefCell::new(EventQueue::new()),
            iss_gen: IssGen::new(0),
            // RFC 6056 ephemeral port hint range: start at 49152.
            last_ephemeral_port: Cell::new(49151),
            cfg,
        })
```

(Note the `cfg` field moves to the END so `cfg.max_connections` can be read before it's moved into the struct.)

Drop the `_tx_data_mempool` prefix elsewhere too — it is `tx_data_mempool` now (used in Step 3's helper).

- [ ] **Step 2: Add the `tx_data_frame` helper + ephemeral-port allocator**

Append inside `impl Engine { ... }`:

```rust
    /// TX a full-size frame via `tx_data_mempool`. Used for TCP data
    /// segments where the frame size exceeds the small-mbuf pool's
    /// data room. Behavior is otherwise identical to `tx_frame`.
    pub(crate) fn tx_data_frame(&self, bytes: &[u8]) -> bool {
        use crate::counters::{add, inc};
        if bytes.len() > u16::MAX as usize {
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        let m = unsafe { sys::shim_rte_pktmbuf_alloc(self.tx_data_mempool.as_ptr()) };
        if m.is_null() {
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        let dst = unsafe { sys::shim_rte_pktmbuf_append(m, bytes.len() as u16) };
        if dst.is_null() {
            unsafe { sys::shim_rte_pktmbuf_free(m) };
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len());
        }
        let mut pkts = [m];
        let sent = unsafe {
            sys::shim_rte_eth_tx_burst(
                self.cfg.port_id,
                self.cfg.tx_queue_id,
                pkts.as_mut_ptr(),
                1,
            )
        } as usize;
        if sent == 1 {
            add(&self.counters.eth.tx_bytes, bytes.len() as u64);
            inc(&self.counters.eth.tx_pkts);
            true
        } else {
            unsafe { sys::shim_rte_pktmbuf_free(m) };
            inc(&self.counters.eth.tx_drop_full_ring);
            false
        }
    }

    /// Pick the next ephemeral source port in the IANA range [49152, 65535].
    /// Simple wraparound counter; collisions with existing flows in the
    /// table are not checked (at ≤100 connections the odds are negligible).
    fn next_ephemeral_port(&self) -> u16 {
        let mut p = self.last_ephemeral_port.get();
        p = p.wrapping_add(1);
        if p < 49152 {
            p = 49152;
        }
        self.last_ephemeral_port.set(p);
        p
    }

    pub(crate) fn flow_table(&self) -> std::cell::RefMut<'_, FlowTable> {
        self.flow_table.borrow_mut()
    }
    pub(crate) fn events(&self) -> std::cell::RefMut<'_, EventQueue> {
        self.events.borrow_mut()
    }
    pub(crate) fn iss_gen(&self) -> &IssGen {
        &self.iss_gen
    }
```

- [ ] **Step 3: Replace `tcp_input_stub` with real dispatch**

Replace the `tcp_input_stub` method with:

```rust
    /// Real TCP input path (A3). Parses the segment, finds the flow,
    /// dispatches to per-state handler, emits ACK/RST and events.
    fn tcp_input(&self, ip: &crate::l3_ip::L3Decoded, tcp_bytes: &[u8]) {
        use crate::counters::inc;
        use crate::tcp_input::{dispatch, parse_segment, tuple_from_segment, TxAction};

        let parsed = match parse_segment(tcp_bytes, ip.src_ip, ip.dst_ip, false) {
            Ok(p) => p,
            Err(e) => {
                match e {
                    crate::tcp_input::TcpParseError::Short => inc(&self.counters.tcp.rx_short),
                    crate::tcp_input::TcpParseError::BadFlags => inc(&self.counters.tcp.rx_bad_flags),
                    crate::tcp_input::TcpParseError::Csum => inc(&self.counters.tcp.rx_bad_csum),
                    crate::tcp_input::TcpParseError::BadDataOffset => inc(&self.counters.tcp.rx_short),
                }
                return;
            }
        };

        let tuple = tuple_from_segment(ip.src_ip, ip.dst_ip, &parsed);
        let handle = { self.flow_table.borrow().lookup_by_tuple(&tuple) };
        let Some(handle) = handle else {
            // Unmatched: reply RST per spec §5.1 `reply_rst`.
            inc(&self.counters.tcp.rx_unmatched);
            self.send_rst_unmatched(&tuple, &parsed);
            return;
        };

        // Bump per-flag counters for observability before dispatch.
        use crate::tcp_output::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
        if (parsed.flags & TCP_SYN) != 0 && (parsed.flags & TCP_ACK) != 0 {
            inc(&self.counters.tcp.rx_syn_ack);
        }
        if (parsed.flags & TCP_ACK) != 0 { inc(&self.counters.tcp.rx_ack); }
        if (parsed.flags & TCP_FIN) != 0 { inc(&self.counters.tcp.rx_fin); }
        if (parsed.flags & TCP_RST) != 0 { inc(&self.counters.tcp.rx_rst); }
        if !parsed.payload.is_empty() { inc(&self.counters.tcp.rx_data); }

        let outcome = {
            let mut ft = self.flow_table.borrow_mut();
            let Some(conn) = ft.get_mut(handle) else { return; };
            dispatch(conn, &parsed)
        };

        if let Some(new_state) = outcome.new_state {
            self.transition_conn(handle, new_state);
        }

        match outcome.tx {
            TxAction::Ack => self.emit_ack(handle),
            TxAction::Rst => {
                self.emit_rst(handle, &parsed);
                self.transition_conn(handle, TcpState::Closed);
            }
            TxAction::None => {}
        }

        if outcome.connected {
            self.events.borrow_mut().push(InternalEvent::Connected {
                conn: handle, rx_hw_ts_ns: 0,
            });
            inc(&self.counters.tcp.conn_open);
        }

        if outcome.delivered > 0 {
            self.deliver_readable(handle, outcome.delivered);
        }

        if outcome.closed {
            self.events.borrow_mut().push(InternalEvent::Closed {
                conn: handle, err: 0,
            });
            inc(&self.counters.tcp.conn_close);
            // Remove the flow on final close (but leave TIME_WAIT alive
            // for the reaper — that's handled via `transition_conn`).
            let state = self.flow_table.borrow().get(handle).map(|c| c.state);
            if state == Some(TcpState::Closed) {
                self.flow_table.borrow_mut().remove(handle);
            }
        }
    }
```

- [ ] **Step 4: Add FSM transition helper + event emitter helpers**

Append inside `impl Engine { ... }`:

```rust
    fn transition_conn(&self, handle: ConnHandle, to: TcpState) {
        use crate::counters::inc;
        let mut ft = self.flow_table.borrow_mut();
        let Some(conn) = ft.get_mut(handle) else { return; };
        let from = conn.state;
        if from == to { return; }
        conn.state = to;
        // TIME_WAIT entry: arm the reaping deadline.
        if to == TcpState::TimeWait {
            let msl_ns = (self.cfg.tcp_msl_ms as u64) * 1_000_000;
            conn.time_wait_deadline_ns = Some(crate::clock::now_ns().saturating_add(2 * msl_ns));
        }
        drop(ft);
        inc(&self.counters.tcp.state_trans[from as usize][to as usize]);
        self.events.borrow_mut().push(InternalEvent::StateChange {
            conn: handle, from, to,
        });
    }

    fn emit_ack(&self, handle: ConnHandle) {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK};
        let ft = self.flow_table.borrow();
        let Some(conn) = ft.get(handle) else { return; };
        let t = conn.four_tuple();
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: t.local_ip,
            dst_ip: t.peer_ip,
            src_port: t.local_port,
            dst_port: t.peer_port,
            seq: conn.snd_nxt,
            ack: conn.rcv_nxt,
            flags: TCP_ACK,
            window: conn.rcv_wnd.min(u16::MAX as u32) as u16,
            mss_option: None,
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
        if self.tx_frame(&buf[..n]) {
            inc(&self.counters.tcp.tx_ack);
        }
    }

    fn emit_rst(&self, handle: ConnHandle, incoming: &crate::tcp_input::ParsedSegment) {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_RST};
        let ft = self.flow_table.borrow();
        let Some(conn) = ft.get(handle) else { return; };
        let t = conn.four_tuple();
        let ack = incoming.seq.wrapping_add(incoming.payload.len() as u32);
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: t.local_ip, dst_ip: t.peer_ip,
            src_port: t.local_port, dst_port: t.peer_port,
            seq: conn.snd_nxt,
            ack,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            mss_option: None,
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
        if self.tx_frame(&buf[..n]) {
            inc(&self.counters.tcp.tx_rst);
        }
    }

    /// Reply RST to a segment whose 4-tuple has no matching flow.
    /// Per RFC 9293 §3.10.7.1: if the incoming has ACK set, seq=incoming.ack;
    /// else seq=0, ack=incoming.seq+payload_len+SYN_FLAG+FIN_FLAG, flags=RST|ACK.
    fn send_rst_unmatched(&self, tuple: &FourTuple, incoming: &crate::tcp_input::ParsedSegment) {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
        if (incoming.flags & TCP_RST) != 0 {
            return; // don't RST a RST.
        }
        let syn_len = ((incoming.flags & TCP_SYN) != 0) as u32;
        let fin_len = ((incoming.flags & TCP_FIN) != 0) as u32;
        let (seq, ack, flags) = if (incoming.flags & TCP_ACK) != 0 {
            (incoming.ack, 0, TCP_RST)
        } else {
            let ack = incoming.seq
                .wrapping_add(incoming.payload.len() as u32)
                .wrapping_add(syn_len)
                .wrapping_add(fin_len);
            (0, ack, TCP_RST | TCP_ACK)
        };
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip, dst_ip: tuple.peer_ip,
            src_port: tuple.local_port, dst_port: tuple.peer_port,
            seq, ack, flags, window: 0,
            mss_option: None, payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
        if self.tx_frame(&buf[..n]) {
            inc(&self.counters.tcp.tx_rst);
        }
    }

    fn deliver_readable(&self, handle: ConnHandle, delivered: u32) {
        use crate::counters::add;
        let mut ft = self.flow_table.borrow_mut();
        let Some(conn) = ft.get_mut(handle) else { return; };
        // Drain the VecDeque's two slices into the last_read_buf so the
        // caller sees one contiguous view. The buf is cleared at the top
        // of the next poll by the caller (see Task 18).
        conn.recv.last_read_buf.clear();
        conn.recv.last_read_buf.reserve(delivered as usize);
        let (a, b) = conn.recv.bytes.as_slices();
        // Drain only `delivered` bytes (which is what we just appended).
        let from_a = a.len().min(delivered as usize);
        conn.recv.last_read_buf.extend_from_slice(&a[..from_a]);
        let remaining = delivered as usize - from_a;
        conn.recv.last_read_buf.extend_from_slice(&b[..remaining]);
        // Advance the VecDeque head past what we just copied.
        for _ in 0..delivered {
            conn.recv.bytes.pop_front();
        }
        drop(ft);
        add(&self.counters.tcp.recv_buf_delivered, delivered as u64);
        self.events.borrow_mut().push(InternalEvent::Readable {
            conn: handle, byte_len: delivered, rx_hw_ts_ns: 0,
        });
    }
```

- [ ] **Step 5: Rewire `handle_ipv4` to call `tcp_input` instead of `tcp_input_stub`**

Replace the TCP arm inside `handle_ipv4`:

```rust
                    crate::l3_ip::IPPROTO_TCP => {
                        inc(&self.counters.ip.rx_tcp);
                        self.tcp_input(&ip, inner);
                    }
```

Remove the `tcp_input_stub` function entirely.

- [ ] **Step 6: Run build**

Run: `cargo build -p dpdk-net-core`
Expected: compiles. Tests from earlier tasks still pass on re-run.

- [ ] **Step 7: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "engine: wire flow_table + events + iss + tcp_input dispatch; add tx_data_frame"
```

---

## Task 16: Engine `connect` — emit SYN, insert into flow table

**Goal:** Add `Engine::connect(peer_ip, peer_port, local_port_hint) -> Result<ConnHandle>`. Allocates a connection slot in the flow table, generates ISS via the RFC 6528 generator, builds + transmits a SYN with the MSS option, transitions the conn to SYN_SENT, and returns the handle. SYN retransmit is NOT implemented — one attempt, then the caller's `connect_timeout_ms` handles the failure at application level.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Write the failing test** (unit-level; a real-network test is in Task 22)

Append inside `crates/dpdk-net-core/src/engine.rs`'s `mod tests`:

```rust
    #[test]
    fn connect_requires_nonzero_local_ip() {
        // We can't construct an Engine without EAL, so test via a function
        // signature check + an error path that doesn't need hardware:
        // the "local_ip==0" case is rejected early inside `Engine::connect`,
        // but we can't exercise it without an Engine. This test is a
        // compile-only smoke-check that the method's signature exists.
        fn _check(e: &Engine) {
            let _: Result<crate::flow_table::ConnHandle, crate::Error> =
                e.connect(0x0a_00_00_01, 5000, 0);
        }
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net-core engine::tests::connect_requires_nonzero_local_ip`
Expected: FAIL at compile — method `connect` doesn't exist.

- [ ] **Step 3: Implement `connect`** — append inside `impl Engine`:

```rust
    /// Open a new client-side connection. Emits a single SYN and
    /// returns the handle. The caller waits on `DPDK_NET_EVT_CONNECTED`
    /// (or times out at application level — SYN retransmit is A5).
    ///
    /// `peer_ip` / `peer_port` in host byte order.
    /// `local_port_hint`: if nonzero, used as the source port; else we
    /// pick an ephemeral port from [49152, 65535].
    pub fn connect(
        &self,
        peer_ip: u32,
        peer_port: u16,
        local_port_hint: u16,
    ) -> Result<ConnHandle, Error> {
        use crate::counters::inc;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_SYN};

        if self.cfg.local_ip == 0 {
            return Err(Error::PeerUnreachable(peer_ip));
        }
        if self.cfg.gateway_mac == [0u8; 6] {
            return Err(Error::PeerUnreachable(peer_ip));
        }
        let local_port = if local_port_hint != 0 {
            local_port_hint
        } else {
            self.next_ephemeral_port()
        };
        let tuple = FourTuple {
            local_ip: self.cfg.local_ip,
            local_port,
            peer_ip,
            peer_port,
        };
        let iss = self.iss_gen.next(&tuple);
        let our_mss = self.cfg.tcp_mss.min(u16::MAX as u32) as u16;
        let recv_wnd = self.cfg.recv_buffer_bytes.min(u16::MAX as u32);
        let conn = TcpConn::new_client(
            tuple,
            iss,
            our_mss,
            self.cfg.recv_buffer_bytes,
            self.cfg.send_buffer_bytes,
        );
        let handle = self
            .flow_table
            .borrow_mut()
            .insert(conn)
            .ok_or(Error::TooManyConns)?;

        // Build and transmit SYN.
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip,
            dst_ip: tuple.peer_ip,
            src_port: tuple.local_port,
            dst_port: tuple.peer_port,
            seq: iss,
            ack: 0,
            flags: TCP_SYN,
            window: recv_wnd.min(u16::MAX as u32) as u16,
            mss_option: Some(our_mss),
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else {
            // Header-too-small is impossible with 64-byte buf; keep explicit.
            self.flow_table.borrow_mut().remove(handle);
            return Err(Error::PeerUnreachable(peer_ip));
        };
        if !self.tx_frame(&buf[..n]) {
            self.flow_table.borrow_mut().remove(handle);
            return Err(Error::PeerUnreachable(peer_ip));
        }
        inc(&self.counters.tcp.tx_syn);

        // Bump snd_nxt past the SYN's seq and mark SYN_SENT. Direct
        // state mutation (not transition_conn) because this transition
        // has no from-state event — we're coming from the just-inserted
        // TcpState::Closed default.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.snd_nxt = iss.wrapping_add(1);
            }
        }
        self.transition_conn(handle, TcpState::SynSent);
        Ok(handle)
    }
```

- [ ] **Step 4: Run — verify PASS**

Run: `cargo test -p dpdk-net-core engine::tests::connect_requires_nonzero_local_ip`
Expected: PASS (compile succeeds).

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "engine: connect() — emit SYN with MSS option, insert flow, transition SYN_SENT"
```

---

## Task 17: Engine `send_bytes` — segment user data, emit MSS-sized TCP segments

**Goal:** `Engine::send_bytes(handle, bytes) -> i32` where the return mirrors the public `dpdk_net_send` contract: `>= 0` bytes accepted, `< 0` on error (`-ENOTCONN` if not ESTABLISHED, `-ENOMEM` if tx_data_mempool is exhausted mid-send). A3 ignores the `tcp_nagle` setting — every call sends its own segments immediately. Segmentation respects `peer_mss` (capped to our `tcp_mss`). `snd_nxt` advances as segments are emitted; bytes in the pending queue are held but in A3 we send-then-forget (no retransmit buffer).

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Implement `send_bytes`** — append inside `impl Engine`:

```rust
    /// Enqueue `bytes` on the connection's send path. Returns the number
    /// of bytes accepted (could be < bytes.len() under send-buffer or
    /// peer-window backpressure). On `tx_data_mempool` exhaustion mid-send,
    /// returns a negative errno (Err(Error::SendBufferFull) mapped to
    /// `-ENOMEM` at the public-API layer).
    pub fn send_bytes(&self, handle: ConnHandle, bytes: &[u8]) -> Result<u32, Error> {
        use crate::counters::{add, inc};
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_PSH};

        let (tuple, seq_start, snd_una, snd_wnd, peer_mss, state, rcv_nxt, rcv_wnd)
            = {
                let ft = self.flow_table.borrow();
                let Some(c) = ft.get(handle) else {
                    return Err(Error::InvalidConnHandle(handle as u64));
                };
                (c.four_tuple(), c.snd_nxt, c.snd_una, c.snd_wnd, c.peer_mss,
                 c.state, c.rcv_nxt, c.rcv_wnd)
            };
        if state != TcpState::Established {
            return Err(Error::InvalidConnHandle(handle as u64));
        }

        let mss_cap = (peer_mss as u32).min(self.cfg.tcp_mss).max(1);
        // Remaining peer-window room (relative to snd_una): snd_wnd minus
        // (snd_nxt - snd_una).
        let in_flight = seq_start.wrapping_sub(snd_una);
        let room_in_peer_wnd = snd_wnd.saturating_sub(in_flight);
        let send_buf_room = self.cfg.send_buffer_bytes.saturating_sub(in_flight);
        let mut remaining = bytes.len().min(room_in_peer_wnd as usize).min(send_buf_room as usize);
        let mut offset = 0usize;
        let mut accepted = 0u32;
        let mut cur_seq = seq_start;

        let mut frame = vec![0u8; 1600];
        while remaining > 0 {
            let take = remaining.min(mss_cap as usize);
            let payload = &bytes[offset..offset + take];
            let seg = SegmentTx {
                src_mac: self.our_mac,
                dst_mac: self.cfg.gateway_mac,
                src_ip: tuple.local_ip, dst_ip: tuple.peer_ip,
                src_port: tuple.local_port, dst_port: tuple.peer_port,
                seq: cur_seq,
                ack: rcv_nxt,
                flags: TCP_ACK | TCP_PSH,
                window: rcv_wnd.min(u16::MAX as u32) as u16,
                mss_option: None,
                payload,
            };
            if frame.len() < crate::tcp_output::FRAME_HDRS_MIN + take {
                frame.resize(crate::tcp_output::FRAME_HDRS_MIN + take, 0);
            }
            let Some(n) = build_segment(&seg, &mut frame) else {
                // Shouldn't happen; buf is sized for hdrs+take.
                break;
            };
            if !self.tx_data_frame(&frame[..n]) {
                if accepted == 0 {
                    return Err(Error::SendBufferFull);
                }
                break;
            }
            inc(&self.counters.tcp.tx_data);
            add(&self.counters.eth.rx_bytes, 0); // no-op: kept for parity with A2 pattern
            offset += take;
            accepted += take as u32;
            cur_seq = cur_seq.wrapping_add(take as u32);
            remaining -= take;
        }

        // Persist accepted bytes to `snd.pending` (for spec-future retx)
        // and advance `snd_nxt`.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                let stored = c.snd.push(&bytes[..accepted as usize]);
                // If the send buffer was too small, we may have sent
                // bytes we can't retx-track. Not an error in A3; noted
                // for A5.
                let _ = stored;
                c.snd_nxt = cur_seq;
            }
        }
        if accepted < bytes.len() as u32 {
            inc(&self.counters.tcp.send_buf_full);
        }
        Ok(accepted)
    }
```

- [ ] **Step 2: Write a unit test** — append inside `mod tests`:

```rust
    #[test]
    fn send_bytes_signature_exists() {
        fn _check(e: &Engine, h: crate::flow_table::ConnHandle) {
            let _: Result<u32, crate::Error> = e.send_bytes(h, b"x");
        }
    }
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core engine::tests::send_bytes_signature_exists`
Expected: PASS (compile succeeds).

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "engine: send_bytes — mss-sized segmentation with PSH|ACK, peer-window respect"
```

---

## Task 18: Engine `close_conn` — emit FIN and manage FIN_WAIT_1 / LAST_ACK entry

**Goal:** `Engine::close_conn(handle)` emits a FIN (ACK|FIN) from whichever state permits it, transitions to FIN_WAIT_1 (from ESTABLISHED) or LAST_ACK (from CLOSE_WAIT), and records `our_fin_seq` so `fin_has_been_acked` can detect the peer's ACK later. A call on an already-closed connection is a no-op. The `FORCE_TW_SKIP` flag is deferred to A6 (spec §6.5); A3 ignores the flag.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Implement `close_conn`** — append inside `impl Engine`:

```rust
    pub fn close_conn(&self, handle: ConnHandle) -> Result<(), Error> {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_FIN};

        let (tuple, seq, rcv_nxt, state, rcv_wnd) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else {
                return Err(Error::InvalidConnHandle(handle as u64));
            };
            (c.four_tuple(), c.snd_nxt, c.rcv_nxt, c.state, c.rcv_wnd)
        };

        // Only ESTABLISHED and CLOSE_WAIT may initiate FIN. Others are
        // already closing/closed; caller gets a successful no-op.
        let to_state = match state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return Ok(()),
        };

        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip, dst_ip: tuple.peer_ip,
            src_port: tuple.local_port, dst_port: tuple.peer_port,
            seq,
            ack: rcv_nxt,
            flags: TCP_ACK | TCP_FIN,
            window: rcv_wnd.min(u16::MAX as u32) as u16,
            mss_option: None,
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else {
            return Err(Error::PeerUnreachable(tuple.peer_ip));
        };
        if !self.tx_frame(&buf[..n]) {
            return Err(Error::PeerUnreachable(tuple.peer_ip));
        }
        inc(&self.counters.tcp.tx_fin);

        // Record our FIN seq and advance snd_nxt (FIN consumes one seq).
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.our_fin_seq = Some(seq);
                c.snd_nxt = seq.wrapping_add(1);
            }
        }
        self.transition_conn(handle, to_state);
        Ok(())
    }
```

- [ ] **Step 2: Add signature-check test** — append inside `mod tests`:

```rust
    #[test]
    fn close_conn_signature_exists() {
        fn _check(e: &Engine, h: crate::flow_table::ConnHandle) {
            let _: Result<(), crate::Error> = e.close_conn(h);
        }
    }
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core engine::tests::close_conn_signature_exists`
Expected: PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "engine: close_conn — emit FIN and enter FIN_WAIT_1 or LAST_ACK"
```

---

## Task 19: Engine poll drain — publish events + TIME_WAIT reaping

**Goal:** Rewrite `poll_once` to (a) clear each active connection's `last_read_buf` before processing so previous-iteration borrowed-views are invalidated per spec §4.2, (b) run the RX burst + `rx_frame` dispatch as today, (c) walk the flow table reaping any TIME_WAIT connection whose deadline has passed, (d) return — a new method `drain_events` handles transferring queued events into the caller's `events_out[]` array (called by the public API `dpdk_net_poll`).

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Extend `poll_once` with reaping + scratch clear**

Replace the body of `poll_once` in `crates/dpdk-net-core/src/engine.rs`:

```rust
    pub fn poll_once(&self) -> usize {
        use crate::counters::{add, inc};
        inc(&self.counters.poll.iters);

        // Clear per-conn last_read_buf so prior borrowed views are
        // invalidated per spec §4.2.
        {
            let mut ft = self.flow_table.borrow_mut();
            for h in ft.iter_handles().collect::<Vec<_>>() {
                if let Some(c) = ft.get_mut(h) {
                    c.recv.last_read_buf.clear();
                }
            }
        }

        const BURST: usize = 32;
        let mut mbufs: [*mut sys::rte_mbuf; BURST] = [std::ptr::null_mut(); BURST];
        let n = unsafe {
            sys::shim_rte_eth_rx_burst(
                self.cfg.port_id,
                self.cfg.rx_queue_id,
                mbufs.as_mut_ptr(),
                BURST as u16,
            )
        } as usize;

        if n == 0 {
            inc(&self.counters.poll.iters_idle);
            self.reap_time_wait();
            self.maybe_emit_gratuitous_arp();
            return 0;
        }

        inc(&self.counters.poll.iters_with_rx);
        add(&self.counters.eth.rx_pkts, n as u64);

        for &m in &mbufs[..n] {
            let bytes = unsafe { crate::mbuf_data_slice(m) };
            add(&self.counters.eth.rx_bytes, bytes.len() as u64);
            self.rx_frame(bytes);
            unsafe { sys::shim_rte_pktmbuf_free(m) };
        }

        self.reap_time_wait();
        self.maybe_emit_gratuitous_arp();
        n
    }

    /// Walk the flow table and move any TIME_WAIT connection past its
    /// 2×MSL deadline to CLOSED. Naïve O(N) scan in A3 — acceptable at
    /// ≤100 connections; A6's timer wheel replaces this.
    fn reap_time_wait(&self) {
        let now = crate::clock::now_ns();
        let candidates: Vec<_> = {
            let ft = self.flow_table.borrow();
            ft.iter_handles()
                .filter(|h| {
                    let Some(c) = ft.get(*h) else { return false; };
                    c.state == TcpState::TimeWait
                        && c.time_wait_deadline_ns.map_or(false, |d| now >= d)
                })
                .collect()
        };
        for h in candidates {
            self.transition_conn(h, TcpState::Closed);
            self.events.borrow_mut().push(InternalEvent::Closed { conn: h, err: 0 });
            self.flow_table.borrow_mut().remove(h);
        }
    }

    /// Drain up to `max` events from the internal queue. Returns the
    /// number of events drained. Callers in the C ABI layer translate
    /// the `InternalEvent` enum to the public union-tagged form.
    pub fn drain_events<F: FnMut(&InternalEvent, &Engine)>(&self, max: u32, mut sink: F) -> u32 {
        let mut n = 0u32;
        while n < max {
            let Some(ev) = self.events.borrow_mut().pop() else { break; };
            sink(&ev, self);
            n += 1;
        }
        n
    }
```

- [ ] **Step 2: Write a unit test** — append inside `mod tests`:

```rust
    #[test]
    fn drain_events_signature_exists() {
        fn _check(e: &Engine) {
            e.drain_events(1, |_ev, _engine| {});
        }
    }
```

- [ ] **Step 3: Run build + all prior tests**

Run: `cargo test -p dpdk-net-core`
Expected: PASS on all prior tests + the signature check.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "engine: poll_once clears borrow-view scratch + reaps TIME_WAIT; drain_events helper"
```

---

## Task 20: Public C ABI — `dpdk_net_connect`, `dpdk_net_send`, `dpdk_net_close`

**Goal:** Implement the three extern "C" functions that expose `Engine::connect`/`send_bytes`/`close_conn` to C++ callers. `dpdk_net_connect_opts_t` integer fields are interpreted per api.rs (`peer_addr` is NETWORK byte order, per the existing "network byte order IPv4" comment); we convert to host order inside the bridge. Handle values are `u64` on the public API (widened from the internal `u32`).

**Files:**
- Modify: `crates/dpdk-net/src/lib.rs`

- [ ] **Step 1: Write failing tests** — append to `crates/dpdk-net/src/lib.rs` inside `mod tests`:

```rust
    #[test]
    fn connect_null_engine_returns_einval() {
        let opts = dpdk_net_connect_opts_t {
            peer_addr: 0x0100_0a0a, // 10.0.0.1 in NBO (doesn't matter)
            peer_port: 5000u16.to_be(),
            local_addr: 0,
            local_port: 0,
            connect_timeout_ms: 0,
            idle_keepalive_sec: 0,
        };
        let mut out: u64 = 0;
        let rc = unsafe { dpdk_net_connect(std::ptr::null_mut(), &opts, &mut out) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn send_null_engine_returns_einval() {
        let rc = unsafe {
            dpdk_net_send(
                std::ptr::null_mut(),
                1u64,
                b"x".as_ptr(),
                1,
            )
        };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn close_null_engine_returns_einval() {
        let rc = unsafe { dpdk_net_close(std::ptr::null_mut(), 1u64, 0) };
        assert_eq!(rc, -libc::EINVAL);
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net tests::connect_null_engine_returns_einval`
Expected: FAIL at compile — `dpdk_net_connect` not defined.

- [ ] **Step 3: Add the extern functions** — insert into `crates/dpdk-net/src/lib.rs` before the `#[cfg(test)]` block:

```rust
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_connect(
    p: *mut dpdk_net_engine,
    opts: *const dpdk_net_connect_opts_t,
    out: *mut dpdk_net_conn_t,
) -> i32 {
    if p.is_null() || opts.is_null() || out.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(p) else { return -libc::EINVAL; };
    let opts = &*opts;
    // peer_addr comes in network byte order; convert to host order.
    let peer_ip = u32::from_be(opts.peer_addr);
    let peer_port = u16::from_be(opts.peer_port);
    let local_port = u16::from_be(opts.local_port);
    match e.connect(peer_ip, peer_port, local_port) {
        Ok(h) => {
            *out = h as dpdk_net_conn_t;
            0
        }
        Err(dpdk_net_core::Error::TooManyConns) => -libc::EMFILE,
        Err(dpdk_net_core::Error::PeerUnreachable(_)) => -libc::EHOSTUNREACH,
        Err(_) => -libc::EIO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_send(
    p: *mut dpdk_net_engine,
    conn: dpdk_net_conn_t,
    buf: *const u8,
    len: u32,
) -> i32 {
    if p.is_null() {
        return -libc::EINVAL;
    }
    if len > 0 && buf.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(p) else { return -libc::EINVAL; };
    let slice = if len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(buf, len as usize)
    };
    match e.send_bytes(conn as u32, slice) {
        Ok(n) => n as i32,
        Err(dpdk_net_core::Error::InvalidConnHandle(_)) => -libc::ENOTCONN,
        Err(dpdk_net_core::Error::SendBufferFull) => -libc::ENOMEM,
        Err(_) => -libc::EIO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_close(
    p: *mut dpdk_net_engine,
    conn: dpdk_net_conn_t,
    _flags: u32,
) -> i32 {
    // FORCE_TW_SKIP flag is A6; ignore in A3.
    if p.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(p) else { return -libc::EINVAL; };
    match e.close_conn(conn as u32) {
        Ok(()) => 0,
        Err(dpdk_net_core::Error::InvalidConnHandle(_)) => -libc::ENOTCONN,
        Err(_) => -libc::EIO,
    }
}
```

- [ ] **Step 4: Update `dpdk_net_poll` to drain the event queue**

Replace the body of `dpdk_net_poll`:

```rust
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_poll(
    p: *mut dpdk_net_engine,
    events_out: *mut dpdk_net_event_t,
    max_events: u32,
    _timeout_ns: u64,
) -> i32 {
    let Some(e) = engine_from_raw(p) else { return -libc::EINVAL; };
    e.poll_once();
    if events_out.is_null() || max_events == 0 {
        return 0;
    }
    let mut filled: u32 = 0;
    e.drain_events(max_events, |ev, engine| {
        let ts = dpdk_net_core::clock::now_ns();
        // Build the event value fully before writing it to events_out, so
        // we never read a possibly-uninitialized `kind` discriminant.
        let event: dpdk_net_event_t = match ev {
            dpdk_net_core::tcp_events::InternalEvent::Connected { conn, rx_hw_ts_ns } => {
                dpdk_net_event_t {
                    kind: dpdk_net_event_kind_t::DPDK_NET_EVT_CONNECTED,
                    conn: *conn as u64,
                    rx_hw_ts_ns: *rx_hw_ts_ns,
                    enqueued_ts_ns: ts,
                    u: dpdk_net_event_payload_t { _pad: [0u8; 16] },
                }
            }
            dpdk_net_core::tcp_events::InternalEvent::Readable { conn, byte_len, rx_hw_ts_ns } => {
                // Reach into the conn's last_read_buf for the view pointer.
                let ft = engine.flow_table();
                let (data_ptr, data_len) = match ft.get(*conn as u32) {
                    Some(c) => (c.recv.last_read_buf.as_ptr(), *byte_len),
                    None => (std::ptr::null(), 0),
                };
                dpdk_net_event_t {
                    kind: dpdk_net_event_kind_t::DPDK_NET_EVT_READABLE,
                    conn: *conn as u64,
                    rx_hw_ts_ns: *rx_hw_ts_ns,
                    enqueued_ts_ns: ts,
                    u: dpdk_net_event_payload_t {
                        readable: dpdk_net_event_readable_t { data: data_ptr, data_len },
                    },
                }
            }
            dpdk_net_core::tcp_events::InternalEvent::Closed { conn, err } => {
                dpdk_net_event_t {
                    kind: dpdk_net_event_kind_t::DPDK_NET_EVT_CLOSED,
                    conn: *conn as u64,
                    rx_hw_ts_ns: 0,
                    enqueued_ts_ns: ts,
                    u: dpdk_net_event_payload_t {
                        closed: dpdk_net_event_error_t { err: *err },
                    },
                }
            }
            dpdk_net_core::tcp_events::InternalEvent::StateChange { conn, from, to } => {
                dpdk_net_event_t {
                    kind: dpdk_net_event_kind_t::DPDK_NET_EVT_TCP_STATE_CHANGE,
                    conn: *conn as u64,
                    rx_hw_ts_ns: 0,
                    enqueued_ts_ns: ts,
                    u: dpdk_net_event_payload_t {
                        tcp_state: dpdk_net_event_tcp_state_t {
                            from_state: *from as u8, to_state: *to as u8,
                        },
                    },
                }
            }
            dpdk_net_core::tcp_events::InternalEvent::Error { conn, err } => {
                dpdk_net_event_t {
                    kind: dpdk_net_event_kind_t::DPDK_NET_EVT_ERROR,
                    conn: *conn as u64,
                    rx_hw_ts_ns: 0,
                    enqueued_ts_ns: ts,
                    u: dpdk_net_event_payload_t {
                        error: dpdk_net_event_error_t { err: *err },
                    },
                }
            }
        };
        std::ptr::write(events_out.add(filled as usize), event);
        filled += 1;
    });
    filled as i32
}
```

To satisfy the event draining closure needing `engine` mutably, we expose `Engine::flow_table()` publicly. In `crates/dpdk-net-core/src/engine.rs`, change the helper from `pub(crate)` to `pub`:

```rust
    pub fn flow_table(&self) -> std::cell::RefMut<'_, crate::flow_table::FlowTable> {
        self.flow_table.borrow_mut()
    }
```

Also expose `events` similarly (already `pub(crate)`, but change to `pub` for cross-crate use):

```rust
    pub fn events(&self) -> std::cell::RefMut<'_, crate::tcp_events::EventQueue> {
        self.events.borrow_mut()
    }
```

- [ ] **Step 5: Run — verify PASS**

Run: `cargo test -p dpdk-net`
Expected: all prior + new tests pass.

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net/src/lib.rs crates/dpdk-net-core/src/engine.rs
git commit -m "public api: dpdk_net_connect/send/close + event-queue drain in dpdk_net_poll"
```

---

## Task 21: Regenerate `include/dpdk_net.h` + verify

**Goal:** Run `cargo build -p dpdk-net` so cbindgen regenerates the public header with the new functions + counter fields. Verify the symbols appear.

**Files:**
- Modify: `include/dpdk_net.h` (generated)

- [ ] **Step 1: Regenerate**

Run: `cargo build -p dpdk-net`
Expected: header regenerates; build succeeds.

- [ ] **Step 2: Grep for the new symbols**

Run: `grep -E '(dpdk_net_connect|dpdk_net_send|dpdk_net_close|state_trans|tx_syn|tx_ack|tx_data|tx_fin|tx_rst|rx_fin|rx_unmatched)' include/dpdk_net.h`
Expected: every term appears.

- [ ] **Step 3: Drift check**

Run: `./scripts/check-header.sh`
Expected: PASS.

- [ ] **Step 4: Commit the regenerated header**

```sh
git add include/dpdk_net.h
git commit -m "regenerate dpdk_net.h for phase a3 (connect/send/close + tcp counter additions)"
```

---

## Task 22: Integration test — TAP pair + kernel listener, TCP echo + clean close

**Goal:** Full end-to-end A3 smoke: engine connects to a kernel-side `TcpListener` bound on the TAP peer IP, writes a known byte sequence, reads the echo, closes cleanly. Counters are asserted to reflect the expected packet counts (1 SYN sent, 1 SYN-ACK received, N ACKs, 1 FIN sent/received). Gated by `DPDK_NET_TEST_TAP=1` + root (DPDK TAP + neighbor-cache manipulation).

**Files:**
- Create: `crates/dpdk-net-core/tests/tcp_basic_tap.rs`

- [ ] **Step 1: Write the test file**

Create `crates/dpdk-net-core/tests/tcp_basic_tap.rs`:

```rust
//! Phase A3 TCP handshake + echo + close integration test.
//!
//! Requires DPDK_NET_TEST_TAP=1 AND root (DPDK TAP vdev + `ip neigh`
//! manipulation). Brings up `dpdktap2` on the kernel side with
//! 10.99.1.1/24, starts a std `TcpListener` on 10.99.1.1:5000 that
//! echoes bytes back, and walks the engine through connect / send /
//! receive / close.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "dpdktap2";
const OUR_IP: u32 = 0x0a_63_01_02; // 10.99.1.2
const PEER_IP: u32 = 0x0a_63_01_01; // 10.99.1.1
const PEER_PORT: u16 = 5000;

fn skip_if_not_tap() -> bool {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run");
        return true;
    }
    false
}

fn read_kernel_tap_mac(iface: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("read {path}"));
    let mut out = [0u8; 6];
    for (i, part) in s.trim().split(':').enumerate() {
        out[i] = u8::from_str_radix(part, 16).expect("hex mac");
    }
    out
}

fn bring_up_tap(iface: &str) {
    let _ = Command::new("ip").args(["link", "set", iface, "up"]).status();
    let _ = Command::new("ip").args(["addr", "add", "10.99.1.1/24", "dev", iface]).status();
}

fn pin_arp(iface: &str, ip: &str, mac: &str) {
    let _ = Command::new("ip")
        .args(["neigh", "replace", ip, "lladdr", mac, "dev", iface, "nud", "permanent"])
        .status();
}

fn mac_hex(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

#[test]
fn handshake_echo_close_over_tap() {
    if skip_if_not_tap() { return; }

    let args = [
        "dpdk-net-a3-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=dpdktap2",
        "-l", "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    // Give dpdktap2 time to come up fully.
    thread::sleep(Duration::from_millis(200));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    // Build engine config pointing at the kernel side.
    let mut cfg = EngineConfig::default();
    cfg.port_id = 0;
    cfg.local_ip = OUR_IP;
    cfg.gateway_ip = PEER_IP;
    cfg.gateway_mac = kernel_mac;
    cfg.tcp_mss = 1460;
    cfg.max_connections = 8;

    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();
    // Pin the kernel's ARP entry for us so the kernel TCP stack
    // doesn't need to resolve.
    pin_arp(TAP_IFACE, "10.99.1.2", &mac_hex(our_mac));

    // Start the echo server on a separate thread.
    let listener = TcpListener::bind("10.99.1.1:5000").expect("listener bind");
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.expect("accept");
            let mut buf = [0u8; 64];
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                if n == 0 { break; }
                s.write_all(&buf[..n]).unwrap();
            }
            let _ = done_tx.send(());
            break;
        }
    });

    // Issue connect. The SYN goes out; we poll until CONNECTED arrives.
    let handle = engine.connect(PEER_IP, PEER_PORT, 0).expect("connect");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        engine.poll_once();
        // Check events for CONNECTED.
        let mut evs = Vec::new();
        engine.drain_events(16, |ev, _| evs.push(ev.clone()));
        for ev in &evs {
            if matches!(ev, InternalEvent::Connected { conn, .. } if *conn == handle) {
                connected = true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "did not receive CONNECTED within deadline");

    // Send a known sequence and poll for the echo.
    let msg = b"dpdk-net phase a3 smoke\n";
    let accepted = engine.send_bytes(handle, msg).expect("send");
    assert_eq!(accepted as usize, msg.len());

    let mut echoed = Vec::<u8>::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && echoed.len() < msg.len() {
        engine.poll_once();
        let mut evs = Vec::new();
        engine.drain_events(16, |ev, _| evs.push(ev.clone()));
        for ev in &evs {
            if let InternalEvent::Readable { conn, byte_len, .. } = ev {
                if *conn == handle {
                    let ft = engine.flow_table();
                    if let Some(c) = ft.get(handle) {
                        echoed.extend_from_slice(&c.recv.last_read_buf[..*byte_len as usize]);
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(&echoed, msg, "echoed bytes mismatched");

    // Close cleanly.
    engine.close_conn(handle).expect("close");
    // Drive the FIN exchange + TIME_WAIT reaping to completion.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut closed = false;
    while Instant::now() < deadline && !closed {
        engine.poll_once();
        let mut evs = Vec::new();
        engine.drain_events(16, |ev, _| evs.push(ev.clone()));
        for ev in &evs {
            if matches!(ev, InternalEvent::Closed { conn, .. } if *conn == handle) {
                closed = true;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(closed, "did not receive CLOSED within deadline");

    // Verify counter deltas.
    let c = engine.counters();
    assert!(c.tcp.tx_syn.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_syn_ack.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_data.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_open.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_close.load(Ordering::Relaxed) >= 1);

    drop(engine);
    let _ = done_rx.recv_timeout(Duration::from_secs(2));
    let _ = server.join();
}
```

- [ ] **Step 2: Run the test** (requires root + DPDK TAP)

```sh
sudo -E DPDK_NET_TEST_TAP=1 $(command -v cargo) test -p dpdk-net-core --test tcp_basic_tap -- --nocapture
```

Expected: PASS. Troubleshooting: if CONNECTED never fires, check (a) `ip neigh show dev dpdktap2` has the permanent entry, (b) `/sys/class/net/dpdktap2/address` matches `kernel_mac`, (c) port 5000 isn't already bound (`ss -tln | grep 5000`), (d) the engine's `gateway_mac` printed (add a `dbg!()` if needed) matches the kernel MAC.

- [ ] **Step 3: Document running it in README**

Append to `README.md`:

````markdown

## TCP handshake + echo integration test (requires DPDK TAP + root)

```sh
sudo -E DPDK_NET_TEST_TAP=1 cargo test -p dpdk-net-core --test tcp_basic_tap -- --nocapture
```
````

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/tests/tcp_basic_tap.rs README.md
git commit -m "add TCP handshake+echo+close integration test over TAP pair"
```

---

## Task 23: C++ consumer prints TCP counters + full verification sequence

**Goal:** Extend the C++ consumer sample to read the new TCP counters through the public ABI (A2 printed IP counters; A3 adds TCP). Then run the full verification sequence: workspace build, unit tests, both TAP integration tests, header drift check, C++ consumer build, clippy.

**Files:**
- Modify: `examples/cpp-consumer/main.cpp`

- [ ] **Step 1: Extend the C++ consumer**

In `examples/cpp-consumer/main.cpp`, find the block that prints IP counters (added in A2 Task 15) and append the following after it:

```cpp
    // Phase A3: print TCP counters to confirm ABI parity.
    std::printf("tcp.tx_syn: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.tx_syn, __ATOMIC_RELAXED));
    std::printf("tcp.rx_syn_ack: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.rx_syn_ack, __ATOMIC_RELAXED));
    std::printf("tcp.tx_data: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.tx_data, __ATOMIC_RELAXED));
    std::printf("tcp.tx_fin: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.tx_fin, __ATOMIC_RELAXED));
    std::printf("tcp.rx_fin: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.rx_fin, __ATOMIC_RELAXED));
    std::printf("tcp.conn_open: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.conn_open, __ATOMIC_RELAXED));
    std::printf("tcp.conn_close: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.conn_close, __ATOMIC_RELAXED));
```

- [ ] **Step 2: Build the C++ consumer**

```sh
cargo build -p dpdk-net --release
cmake -S examples/cpp-consumer -B examples/cpp-consumer/build -DDPDK_NET_PROFILE=release
cmake --build examples/cpp-consumer/build
```

Expected: `cpp_consumer` binary builds without warnings.

- [ ] **Step 3: Run the full verification sequence**

```sh
# Workspace builds clean
cargo build --workspace --all-targets
# All unit tests pass
cargo test --workspace
# TAP integration tests pass
sudo -E DPDK_NET_TEST_TAP=1 $(command -v cargo) test -p dpdk-net-core --test engine_smoke -- --nocapture
sudo -E DPDK_NET_TEST_TAP=1 $(command -v cargo) test -p dpdk-net-core --test l2_l3_tap -- --nocapture
sudo -E DPDK_NET_TEST_TAP=1 $(command -v cargo) test -p dpdk-net-core --test tcp_basic_tap -- --nocapture
# Header hasn't drifted
./scripts/check-header.sh
# C++ consumer builds
cmake --build examples/cpp-consumer/build
# No clippy warnings
cargo clippy --workspace --all-targets -- -D warnings
```

All must succeed. If any fails, fix before proceeding to the review gates.

- [ ] **Step 4: Verify spec coverage manually**

- **§4 `dpdk_net_connect`** — `crates/dpdk-net/src/lib.rs:dpdk_net_connect`.
- **§4 `dpdk_net_send`** — `crates/dpdk-net/src/lib.rs:dpdk_net_send` with `>= 0` / `< 0` contract.
- **§4 `DPDK_NET_EVT_CONNECTED/_READABLE/_CLOSED/_TCP_STATE_CHANGE`** — emitted by `Engine::tcp_input` / `drain_events`.
- **§5.2 TX call chain** — `Engine::send_bytes` → `tcp_output::build_segment` → `tx_data_frame` → `shim_rte_eth_tx_burst`.
- **§6.1 FSM** — `tcp_state.rs` (11 states) + `tcp_input.rs` handlers covering CLOSED → SYN_SENT → ESTABLISHED → {FIN_WAIT_1|CLOSE_WAIT} → {FIN_WAIT_2|CLOSING|LAST_ACK} → TIME_WAIT → CLOSED.
- **§6.2 TcpConn minimum fields** — `tcp_conn.rs` (sequence space, rcv/snd queues, peer_mss, our_fin_seq, time_wait_deadline_ns). Deferred fields explicitly noted in the module doc.
- **§6.5 ISS stub** — `iss.rs` (DefaultHasher SipHash-1-3 + µs clock offset; A5 finalizes).
- **§7.1 `tx_data_mempool`** — used in `Engine::tx_data_frame` for data segments.
- **§9.1 TCP counter group + state_trans matrix** — `counters.rs::TcpCounters`.

- [ ] **Step 5: Commit**

```sh
git add examples/cpp-consumer/main.cpp
git commit -m "c++ consumer: print tcp counters for phase a3 visibility"
```

---

## Task 24: Dispatch the A3 mTCP comparison review (spec §10.13)

**Goal:** Run the mandatory mTCP review for Phase A3 per spec §10.13. The `mtcp-comparison-reviewer` subagent may not appear in the `subagent_type` registry — if it doesn't, dispatch a general-purpose agent and inline the reviewer's agent-file content as the prompt, same fallback A2 used.

**Files:**
- Create: `docs/superpowers/reviews/phase-a3-mtcp-compare.md`

- [ ] **Step 1: Confirm the mTCP submodule is present**

Run: `git -C third_party/mtcp rev-parse HEAD`
Expected: prints a SHA (A2 initialized it).

- [ ] **Step 2: Dispatch the reviewer**

Try dispatching with `subagent_type="mtcp-comparison-reviewer"` + `model="opus"` first. If the registry doesn't know the name, fall back to `subagent_type="general-purpose"` and inline the content of `.claude/agents/mtcp-comparison-reviewer.md` (everything after the YAML frontmatter) as the leading prompt, followed by:

```
Inputs:
- Phase number: A3
- Phase plan: docs/superpowers/plans/2026-04-18-stage1-phase-a3-tcp-basic.md
- Diff command: git diff phase-a2-complete..HEAD -- crates/ include/ examples/ tests/
- Spec refs: §4 (public API), §5.2 TX call chain, §6.1 FSM, §6.2 TcpConn, §6.5 ISS
- mTCP focus areas:
  - third_party/mtcp/mtcp/src/tcp_in.c
  - third_party/mtcp/mtcp/src/tcp_out.c
  - third_party/mtcp/mtcp/src/tcp_stream.c
  - third_party/mtcp/mtcp/src/tcp_util.c
  - third_party/mtcp/mtcp/src/fhash.c
  - third_party/mtcp/mtcp/src/tcp_send_buffer.c
  - third_party/mtcp/mtcp/src/tcp_ring_buffer.c

Write the report to docs/superpowers/reviews/phase-a3-mtcp-compare.md in the agent's mandated schema.
```

The subagent writes `docs/superpowers/reviews/phase-a3-mtcp-compare.md`.

- [ ] **Step 3: Human review — edit Accepted-divergence + verdict**

Open the report. For each entry under **Accepted divergence (draft for human review)**, replace the "Suspected rationale" line with the concrete spec-ref or memory citation. The pre-documented divergences in this plan's header (§§ "Pre-emptive Accepted Divergences vs mTCP", items 1–7) are the expected candidates; any additional divergence the subagent finds needs to be reasoned about before promoting to Accepted.

Toggle the final verdict to **PASS** or **PASS-WITH-ACCEPTED**.

- [ ] **Step 4: Gate check**

The `phase-a3-complete` tag is blocked while **any** `[ ]` remains in Must-fix or Missed-edge-cases. If something is blocking, implement the fix in a separate commit, re-run the reviewer if behavior changed, then proceed.

- [ ] **Step 5: Commit the report**

```sh
git add docs/superpowers/reviews/phase-a3-mtcp-compare.md
git commit -m "phase a3: mTCP comparison review report"
```

---

## Task 25: Dispatch the retroactive A2 RFC compliance review (spec §10.14)

**Goal:** Run the RFC-compliance gate that A2 shipped without. This catches any MUST/SHALL violations in A2's L2/L3/ICMP/ARP code that the mTCP gate wouldn't have spotted. Report lives at `docs/superpowers/reviews/phase-a2-rfc-compliance.md`.

**Files:**
- Create: `docs/superpowers/reviews/phase-a2-rfc-compliance.md`

- [ ] **Step 1: Confirm RFC text is vendored**

Run: `ls docs/rfcs/rfc{791,792,826,1122,1191}.txt`
Expected: all five files exist (they do, per commit `4b3321e`).

- [ ] **Step 2: Dispatch the reviewer** — similar fallback to Task 24

Try `subagent_type="rfc-compliance-reviewer"` with `model="opus"`. If the registry doesn't know it, fall back to `subagent_type="general-purpose"` + inline `.claude/agents/rfc-compliance-reviewer.md` content as the leading prompt, followed by:

```
Inputs:
- Phase number: A2 (retroactive review — see spec §10.14 "A2 is exempt … optionally run a retroactive A2 RFC review at A3 kickoff")
- Phase plan: docs/superpowers/plans/2026-04-17-stage1-phase-a2-l2-l3.md
- Diff command: git diff phase-a1-complete..phase-a2-complete -- crates/ include/ examples/
- RFC set in scope: 791, 792, 826, 1122, 1191
- Spec sections: §5.1, §6.3 rows for RFC 791 / 792 / 1122 / 1191, §8 (ARP)

Write the report to docs/superpowers/reviews/phase-a2-rfc-compliance.md.
Note the header must state "retroactive review (gate added after A2 shipped)".
```

- [ ] **Step 3: Human review — edit Accepted-deviation + verdict**

Walk each Accepted-deviation draft. Expected valid cites for A2:
- **spec §6.4** rows for latency-preferred behaviors (delayed-ACK off, Nagle off, no keepalive).
- Spec §6.3 rows for A2 matters: RFC 1122 IPv4 reassembly "not implemented", RFC 792 "frag-needed + dest-unreachable only".
- Memory file `feedback_trading_latency_defaults.md` covering deviations that lean on trading-latency rationale.

Any Must-fix or Missing-SHOULD items without a §6.4 citation must be addressed (code fix) or upgraded to a spec-amendment before the tag proceeds.

Toggle the verdict to **PASS** / **PASS-WITH-DEVIATIONS**.

- [ ] **Step 4: Commit the report**

```sh
git add docs/superpowers/reviews/phase-a2-rfc-compliance.md
git commit -m "phase a2: retroactive RFC compliance review (gate added post-a2 per spec §10.14)"
```

---

## Task 26: Dispatch the A3 RFC compliance review (spec §10.14)

**Goal:** Verify A3's implementation against the RFC clauses it claims to cover: RFC 9293 (TCP, primary), RFC 6691 (MSS option), RFC 6528 (ISS). Must-fix / Missing-SHOULD items block the tag.

**Files:**
- Create: `docs/superpowers/reviews/phase-a3-rfc-compliance.md`

- [ ] **Step 1: Confirm RFC text is vendored**

Run: `ls docs/rfcs/rfc{9293,6691,6528}.txt`
Expected: all three files exist.

- [ ] **Step 2: Dispatch the reviewer**

Same fallback pattern as Task 25. Inputs:

```
- Phase number: A3
- Phase plan: docs/superpowers/plans/2026-04-18-stage1-phase-a3-tcp-basic.md
- Diff command: git diff phase-a2-complete..HEAD -- crates/ include/ examples/ tests/
- RFC set in scope: 9293, 6691, 6528
- Spec sections: §4, §5.2, §6.1, §6.2, §6.3 rows for 9293 / 6691 / 6528, §6.4, §6.5, §9.1

Write the report to docs/superpowers/reviews/phase-a3-rfc-compliance.md.
```

- [ ] **Step 3: Human review — edit Accepted-deviation + verdict**

Expected Accepted-deviations in A3 (must cite §6.4 or §6.5):
- No delayed-ACK — spec §6.4 row 1 ("Delayed ACK … Our default off … 200ms ACK delay is catastrophic for trading").
- No Nagle — spec §6.4 row 2.
- No congestion control — spec §6.4 row 5.
- SYN retransmit deferred to A5 — spec §6.5 "SYN retransmit" paragraph, phase plan scope-deviation list.
- ISS via DefaultHasher (not dedicated SipHash-2-4) — spec §6.5 ISS formula + this plan's explicit "A5 finalizes" note.

Items the reviewer may flag that are NOT covered by §6.4 (examples — fix them if they come up):
- RFC 9293 MUST on TCP checksum verification → check `tcp_input::parse_segment` does verify when `nic_csum_ok=false`.
- RFC 9293 MUST on RST reply to unmatched segment → check `send_rst_unmatched` handles both ACK-set and no-ACK cases.
- RFC 9293 MUST on seq-window validation with both edges → `handle_established` / `handle_close_path` perform the check.
- RFC 6691 MSS format (kind=2, length=4, 2-byte value) → `tcp_output::build_segment` on SYN.
- RFC 6528 ISS "MUST use a PRF keyed by a secret and dependent on the 4-tuple" → `iss::IssGen::next` satisfies skeletally.

- [ ] **Step 4: Commit the report**

```sh
git add docs/superpowers/reviews/phase-a3-rfc-compliance.md
git commit -m "phase a3: rfc compliance review report"
```

---

## Task 27: Update roadmap + tag phase-a3-complete

**Goal:** Flip the A3 row in the roadmap, tag the commit.

**Files:**
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md`

- [ ] **Step 1: Update the A3 row**

Edit `docs/superpowers/plans/stage1-phase-roadmap.md` — replace the A3 row:

```markdown
| A3 | TCP handshake + basic data transfer | **Complete** ✓ | `2026-04-18-stage1-phase-a3-tcp-basic.md` |
```

- [ ] **Step 2: Final sanity sweep**

Run: `cargo build --workspace --all-targets && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: green.

- [ ] **Step 3: Verify review gates are green**

Confirm:
- `docs/superpowers/reviews/phase-a3-mtcp-compare.md` — final verdict is **PASS** or **PASS-WITH-ACCEPTED**, no open `[ ]` in Must-fix or Missed-edge-cases.
- `docs/superpowers/reviews/phase-a2-rfc-compliance.md` — final verdict is **PASS** or **PASS-WITH-DEVIATIONS**, no open `[ ]` in Must-fix or Missing-SHOULD.
- `docs/superpowers/reviews/phase-a3-rfc-compliance.md` — same rule.

If any verdict is BLOCK or any `[ ]` is open, stop — the tag is blocked by spec §10.13 / §10.14 gate rules. Fix and re-run the reviewer.

- [ ] **Step 4: Commit + tag**

```sh
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "mark phase a3 complete in roadmap"
git tag -a phase-a3-complete -m "Phase A3: TCP handshake + basic data transfer"
```

- [ ] **Step 5: Record next phase**

The next plan file to write is `docs/superpowers/plans/YYYY-MM-DD-stage1-phase-a4-options-paws-reassembly-sack.md` — TCP options + PAWS + reassembly + SACK scoreboard.

---

## Self-Review Notes

**Spec coverage for Phase A3:**
- **§4** public API (`dpdk_net_connect`, `dpdk_net_send`, `dpdk_net_close`, `DPDK_NET_EVT_CONNECTED/READABLE/CLOSED/TCP_STATE_CHANGE`) → Tasks 18 + 20.
- **§5.2** TX call chain → Task 17 (segmentation), Task 8 (header builders), Task 15 (`tx_data_frame`).
- **§6.1** FSM — RFC 9293 §3.3.2 eleven-state client-side → Tasks 4 (state enum) + 11 (SYN_SENT) + 12 (ESTABLISHED) + 13 (close-path).
- **§6.2** `TcpConn` minimum fields → Task 7.
- **§6.5** ISS stub (A5 finalizes) → Task 6.
- **§7.1** `tx_hdr_mempool` + `tx_data_mempool` → already allocated in A1; Task 15 actually uses `tx_data_mempool`.
- **§9.1** TCP counter group + `state_trans` matrix → Task 1.
- **§10.13** mTCP review gate → Task 24.
- **§10.14** RFC review gate (A3) → Task 26; retroactive A2 → Task 25.

**Explicitly deferred to later phases (cross-reference with roadmap):**
- TCP options WSCALE / timestamps / SACK-permitted → A4.
- PAWS, out-of-order reassembly, SACK scoreboard → A4.
- RACK-TLP, RTO, retransmit, full RFC 6528 ISS → A5.
- `DPDK_NET_EVT_WRITABLE`, true timer wheel, `dpdk_net_flush` actually flushing, `FORCE_TW_SKIP` with RFC 6191 guard, `preset=rfc_compliance` → A6.
- Delayed-ACK-on (RFC-compliance preset) → A6 per spec §6.4.

**Placeholder scan:** Every code block contains complete content. No "TODO"/"TBD"/"implement later" in a step. Stubs that are intentional (Task 10's per-state handler stubs, replaced in 11–13) are called out as stubs with the replacing-task reference.

**Type consistency cross-check:**
- `FourTuple` / `ConnHandle` used identically in `flow_table.rs`, `tcp_conn.rs`, `tcp_input.rs`, `engine.rs`.
- `TcpState` mapped to `u8` via `as u8` at every call site (state_trans indexing, public event payload).
- `ParsedSegment` / `Outcome` / `TxAction` used identically in `tcp_input.rs` dispatch and `Engine::tcp_input`.
- `InternalEvent` variants match the public `dpdk_net_event_kind_t` discriminants in Task 20's drain loop.
- Host-byte-order vs network-byte-order: internal uses HBO throughout (EngineConfig, FourTuple, TcpConn, ParsedSegment). Only the public `dpdk_net_connect_opts_t.peer_addr/peer_port/local_port` are NBO; Task 20 converts at the ABI boundary via `u32::from_be` / `u16::from_be`.

**Counter-assertion strategy:** Task 22 asserts counter lower bounds for each expected traffic direction (SYN sent ≥ 1, SYN-ACK received ≥ 1, data sent ≥ 1, FIN sent ≥ 1, FIN received ≥ 1, conn_open ≥ 1, conn_close ≥ 1). Tight equality is avoided because the kernel peer's TCP stack may emit delayed-ACKs or coalesced packets we can't predict exactly — the direction+presence is what matters for A3's smoke gate.

**Review gate gate count:**
- 1 × A3 mTCP (§10.13) — Task 24
- 1 × A2 retroactive RFC (§10.14) — Task 25
- 1 × A3 RFC (§10.14) — Task 26

All three must emit green reports before Task 27's tag.






