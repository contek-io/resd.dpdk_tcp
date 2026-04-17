# resd.dpdk_tcp — Design Spec

Date: 2026-04-17
Status: Draft, pending user approval

## 1. Purpose and Scope

`resd.dpdk_tcp` is a DPDK-based userspace network stack implemented in Rust and exposed to C++ applications via a stable C ABI. It is purpose-built for low-latency trading infrastructure: a trading strategy process connects to a small number (≤100) of exchange venues. The stack runs alongside user application code on the same DPDK lcore in a run-to-completion loop, with no cross-lcore rings on the hot path.

**Stage 1 is raw-TCP only.** The public surface is an epoll-like byte-stream API (connect / send / recv-via-events / close). Application-layer protocols (HTTP/1.1, TLS, WebSocket) are implemented by the application or added to the library in later stages — they are out of scope for Stage 1.

Non-goals: server-side TCP in production, IPv6, HTTP/1.1-parser-in-library (Stage 1), TLS (Stage 1), WebSocket (Stage 1), WebSocket compression, TCP Fast Open, sophisticated congestion control by default, millions of connections, kernel-compatible socket emulation.

### 1.1 Design tenets

- **Latency over throughput**: defaults favor low latency even when they diverge from RFC-recommended behavior. Any aggregation feature is opt-in.
- **Stability is a first-class feature**: safe languages, memory-correct parsers, small attack surface, WAN-tested under induced loss/reorder.
- **Observability through primitives, not framework**: stack exports raw counters, timestamps on every event, and state-change events. Aggregation (histograms, tracing, export endpoints) happens in the application using existing infrastructure.
- **RFC behavior is tested, not claimed**: conformance is proved by running opensource RFC-conformance suites against the stack; anything unclear is resolved by referring to the RFC.
- **Flexible API**: epoll-like pull model for Stage 1; callback-style or async layers can be built on top in user code or a later stage.

## 2. Architecture

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                 C++ Application (strategy, order mgr)           │
  └───────────────────────────┬─────────────────────────────────────┘
                              │ cbindgen C ABI header (resd_net.h)
  ┌───────────────────────────▼─────────────────────────────────────┐
  │  libresd_net  (Rust)                                             │
  │                                                                  │
  │  Public API (extern "C"):                                        │
  │    engine lifecycle, connection, send/recv (byte stream),        │
  │    poll, timers, observability                                   │
  │                                                                  │
  │  Per-lcore engine (run-to-completion loop):                     │
  │    rx_burst → ip → tcp → user event (READABLE)                  │
  │                               ↓                                  │
  │                         user sends → tcp → tx_burst              │
  │                                                                  │
  │  Modules (Stage 1):                                              │
  │    l2/l3/ip, tcp, flow table, timers, mempools,                  │
  │    observability-primitives                                      │
  └──────────────────────────────┬──────────────────────────────────┘
                                 │ DPDK EAL, PMD, mempool (DPDK 23.11)
                                 ▼
                           NIC (SR-IOV VF / PF)
```

### 2.1 Phases

- **Stage 1 (MVP)**: IPv4 + TCP + epoll-like byte-stream API + observability primitives. No HTTP parser, no TLS, no WebSocket. End-to-end gate: establish a TCP connection to a test peer, send/receive arbitrary bytes with correct ordering and flow control under WAN conditions (simulated via netem).
- **Stage 2**: Hardening — WAN A/B harness vs. Linux, fuzz-at-scale, documented RFC compliance matrix, shadow-mode deployment for the raw-TCP path.
- **Stage 3 (if needed)**: HTTP/1.1 client parser + encoder, layered on the Stage 1 byte-stream API. Stays in the stack for zero-copy / inline processing only if benchmarks show user-space parsing is a latency bottleneck; otherwise application does HTTP parsing.
- **Stage 4 (if needed)**: Inline TLS 1.3 (rustls with `aws-lc-rs` backend); TLS 1.2 behind a feature flag.
- **Stage 5 (if needed)**: WebSocket (RFC 6455) client; client-initiated close, client-side masking, ping/pong autoreply. No `permessage-deflate`.

Stages 3–5 are flagged "if needed" because the application may prefer to run HTTP/TLS/WS on its own (e.g., using existing well-tested libraries) once the raw-TCP path is proven. The decision to pull them into the library will be a separate brainstorm + design cycle.

### 2.2 Build / language / FFI

- Rust workspace, `cargo` build, pinning DPDK LTS 23.11 via `bindgen`.
- `cbindgen` generates `resd_net.h` for C++ consumers.
- Public API uses `extern "C"` with primitive / opaque-pointer types only — no Rust-only types leak.
- C++ integration sample ships as a test consumer.

## 3. Threading and Runtime Model

- **One engine per lcore.** Caller pins itself to an lcore before calling `resd_net_engine_create(lcore_id, &cfg)`.
- **User code lives on the same lcore as the stack.** Run-to-completion: the user's event loop repeatedly calls `resd_net_poll`, which runs rx_burst → stack → emits events → user handles events inline → user-initiated sends batch into the next tx_burst.
- **No cross-lcore rings on the hot path.** Connections are pinned to lcores at `connect()` time; the application chooses the assignment.
- **Typical deployment**: one lcore for market-data ingress (one or a few high-pps inbound connections per venue), one lcore for order entry (few latency-critical outbound connections), plus strategy/business-logic cores communicating with the stack lcores via the application's own existing mechanisms.
- **FFI safety contract**: the Rust implementation must not panic across the `extern "C"` boundary. Any Rust panic within the stack is a library bug; panics are converted to process abort via a global `panic = "abort"` policy in `Cargo.toml` (release profile). On the caller side, a C++ exception in user code stays in user code — the poll-style API has no upcall, so exceptions never cross back into Rust.

## 4. Public API (Stage 1)

This section is **normative**. It defines the stable C ABI; `include/resd_net.h` is auto-generated from the Rust side via `cbindgen` and must match exactly. Error codes are negative `errno` values; success is `0` unless otherwise documented.

```c
/* ===== Engine ===== */
typedef struct resd_net_engine resd_net_engine_t;

typedef struct {
    uint16_t port_id;
    uint16_t rx_queue_id;
    uint16_t tx_queue_id;
    uint32_t max_connections;       /* sized ≥ expected, e.g. 16 */
    uint32_t recv_buffer_bytes;     /* per-conn; default 256KiB */
    uint32_t send_buffer_bytes;     /* per-conn; default 256KiB */
    uint32_t tcp_mss;               /* 0 = derive from PMTUD */
    bool     tcp_timestamps;        /* RFC 7323; default true */
    bool     tcp_sack;              /* RFC 2018; default true */
    bool     tcp_ecn;               /* RFC 3168; default false */
    bool     tcp_nagle;             /* Nagle coalescing; default false (trading latency) */
    bool     tcp_delayed_ack;       /* default false (trading latency); true = ACK per ≥2 segments, ≤40ms */
    uint8_t  cc_mode;               /* 0=off (default), 1=reno, 2=cubic (later) */
    uint32_t tcp_min_rto_ms;        /* default 20; RFC 6298 recommends 1000 */
    uint32_t tcp_initial_rto_ms;    /* default 50 for SYN; RFC recommends 1000 */
    uint32_t tcp_msl_ms;            /* for 2×MSL TIME_WAIT; default 30000 */
    bool     tcp_per_packet_events; /* per-packet RETRANS/LOSS events; default false */
    uint8_t  preset;                /* 0=latency (all defaults above apply);
                                       1=rfc_compliance (forces nagle=true,
                                       delayed_ack=true, cc_mode=reno, min_rto=200,
                                       initial_rto=1000 — overrides above fields).
                                       Runtime-selectable per engine. */
} resd_net_engine_config_t;

resd_net_engine_t* resd_net_engine_create(uint16_t lcore_id,
                                          const resd_net_engine_config_t* cfg);
void resd_net_engine_destroy(resd_net_engine_t*);

/* ===== Connection ===== */
typedef uint64_t resd_net_conn_t;    /* opaque handle; 0 = invalid */

typedef struct {
    struct sockaddr_in peer;
    struct sockaddr_in local;        /* 0.0.0.0:0 = pick */
    uint32_t connect_timeout_ms;
    uint32_t idle_keepalive_sec;     /* 0 = off (default) */
} resd_net_connect_opts_t;

int resd_net_connect(resd_net_engine_t*,
                     const resd_net_connect_opts_t*,
                     resd_net_conn_t* out);

/* Close flags. Bitmask. */
#define RESD_NET_CLOSE_FORCE_TW_SKIP  (1u << 0)  /* honored only when RFC 6191 §4.2 conds met */

int resd_net_close(resd_net_engine_t*, resd_net_conn_t, uint32_t flags);
int resd_net_shutdown(resd_net_engine_t*, resd_net_conn_t, int how);

/* ===== Byte-stream send ===== */
/* Enqueues bytes on the connection's send queue; copies into a tx mbuf chain
 * and returns. `buf` may be reused immediately after return.
 *
 * Return value (int32_t):
 *   >= 0  number of bytes accepted, in the range [0, len]. A value < len means
 *         the per-connection send buffer reached its cap; caller waits for
 *         RESD_NET_EVT_WRITABLE before retrying the remainder.
 *   < 0   negative errno:
 *           -ENOMEM  tx mempool exhausted; retry later; a RESD_NET_EVT_ERROR
 *                    {err=ENOMEM} is also emitted for visibility
 *           -ENOTCONN  connection not in a sending state
 *           -EINVAL  bad handle / null buf with nonzero len
 *
 * Mempool exhaustion is surfaced as an error return (never as a silent short
 * accept); a short accept (0..len with no error) means backpressure from the
 * peer's receive window or our per-conn send buffer cap. */
int32_t resd_net_send(resd_net_engine_t*,
                      resd_net_conn_t,
                      const uint8_t* buf,
                      uint32_t len);

/* ===== Poll ===== */
typedef enum {
    RESD_NET_EVT_CONNECTED = 1,
    RESD_NET_EVT_READABLE,             /* raw bytes available; data/data_len set */
    RESD_NET_EVT_WRITABLE,             /* send buffer has space again */
    RESD_NET_EVT_CLOSED,               /* peer FIN or our close completed */
    RESD_NET_EVT_ERROR,
    RESD_NET_EVT_TIMER,
    RESD_NET_EVT_TCP_RETRANS,          /* stability-visibility events */
    RESD_NET_EVT_TCP_LOSS_DETECTED,
    RESD_NET_EVT_TCP_STATE_CHANGE,
} resd_net_event_kind_t;

/* Per-kind event payload. The `kind` field selects which arm of the union is
 * meaningful; other arms are undefined. */
typedef struct {
    resd_net_event_kind_t kind;
    resd_net_conn_t       conn;
    uint64_t              rx_hw_ts_ns;     /* NIC HW timestamp when available; else 0 */
    uint64_t              enqueued_ts_ns;  /* TSC when event entered user-visible form */

    union {
        struct { const uint8_t* data; uint32_t data_len; } readable;
        struct { int32_t err; } error;                     /* -errno */
        struct { int32_t err; } closed;                    /* 0 on clean close */
        struct { uint64_t timer_id; uint64_t user_data; } timer;

        /* tcp stability-visibility; present only when enabled */
        struct { uint32_t seq; uint32_t rtx_count; } tcp_retrans;
        struct { uint32_t first_seq; uint8_t trigger; } tcp_loss;  /* 0=RACK, 1=RTO, 2=TLP */
        struct { uint8_t from_state; uint8_t to_state; } tcp_state;

        /* empty arms for CONNECTED / WRITABLE — no payload */
    } u;
} resd_net_event_t;

int resd_net_poll(resd_net_engine_t*,
                  resd_net_event_t* events_out,
                  uint32_t max_events,
                  uint64_t timeout_ns);

void resd_net_flush(resd_net_engine_t*);   /* force rte_eth_tx_burst now */

/* ===== Timers & clock ===== */
uint64_t resd_net_now_ns(resd_net_engine_t*);

/* Schedule a one-shot timer. On fire, emits RESD_NET_EVT_TIMER with the same
 * timer_id echoed in events[i].u.timer.timer_id and user_data passed through.
 * Returns 0 on success and fills *timer_id_out; negative errno on failure. */
int resd_net_timer_add(resd_net_engine_t*,
                       uint64_t deadline_ns,
                       uint64_t user_data,
                       uint64_t* timer_id_out);

/* Cancel a previously-added timer. Fire is a no-op if the timer has already
 * been cancelled or has already fired. Returns 0 if cancelled before fire,
 * -ENOENT if not found, -EALREADY if the fire event has already been queued
 * (caller should still handle the RESD_NET_EVT_TIMER). */
int resd_net_timer_cancel(resd_net_engine_t*, uint64_t timer_id);

/* ===== Observability primitives ===== */
const resd_net_counters_t* resd_net_counters(resd_net_engine_t*);
```

### 4.1 Usage pattern

```c
engine = resd_net_engine_create(my_lcore, &cfg);
resd_net_connect(engine, &opts, &conn);

resd_net_event_t events[64];
while (running) {
    int n = resd_net_poll(engine, events, 64, 0);  /* 0 = busy-poll */
    for (int i = 0; i < n; i++) {
        switch (events[i].kind) {
        case RESD_NET_EVT_CONNECTED:
            resd_net_send(engine, conn, request_bytes, request_len);
            resd_net_flush(engine);
            break;
        case RESD_NET_EVT_READABLE:
            /* application parses the bytes (HTTP, WS, custom wire format, ...) */
            app_consume(conn, events[i].u.readable.data,
                               events[i].u.readable.data_len);
            break;
        case RESD_NET_EVT_WRITABLE:
            /* retry any bytes that were refused earlier */
            app_drain_pending(conn);
            break;
        case RESD_NET_EVT_CLOSED:
            app_on_close(conn, events[i].u.closed.err);
            break;
        }
    }
}
```

### 4.2 API contracts

- `resd_net_send` is synchronous: it copies bytes into the stack's tx mbuf chain and returns. No borrow-across-poll semantics for the send buffer; the caller may reuse `buf` immediately. Return contract: `>= 0` bytes accepted (possibly partial under backpressure); `< 0` is `-errno` (mempool exhaustion `-ENOMEM`, bad handle `-EINVAL`, not-connected `-ENOTCONN`). A short accept under backpressure is not an error; `-ENOMEM` is an error.
- `RESD_NET_EVT_READABLE.u.readable.data` is a **borrowed view** into mbuf memory, valid from the moment `resd_net_poll` returns until the next `resd_net_poll` call on the same engine. The stack refcount-pins every mbuf referenced by any event in `events_out[0..n]` for that window; internal stack processing (including later bursts within the same poll) must not free those mbufs. Caller must `memcpy` out if they need bytes to outlive the poll.
- Multiple `RESD_NET_EVT_READABLE` events may fire per poll iteration if received bytes span multiple mbufs; they deliver in-order, each with one contiguous mbuf-data region.
- `RESD_NET_EVT_WRITABLE` fires when the per-connection send buffer has drained by at least half its capacity after a prior full/partial send refusal.
- `resd_net_flush` drains the current TX batch via exactly one `rte_eth_tx_burst`; no-op when empty. Safe to call multiple times per poll iteration; idempotent — a follow-up call with nothing newly queued is a no-op.
- `rx_hw_ts_ns` is 0 when the NIC/PMD does not fill hardware timestamps; callers fall back to `enqueued_ts_ns`.
- **`resd_net_poll` event-overflow policy**: if more events are ready than `max_events`, the stack fills `events_out[0..max_events]` with events in FIFO enqueue order, stops further RX-burst processing for this iteration, and leaves the overflow + any unprocessed RX packets queued inside the engine. The next `resd_net_poll` call drains the queue before processing new RX. Per-connection event ordering is preserved across poll boundaries; no event kind is preempted or prioritized. Callers size `max_events` at least to `(NIC_BURST × 2)` so steady-state traffic fits; smaller sizes are valid but cause additional poll round-trips.

## 5. Data Flow

### 5.1 Per-lcore main loop

```c
while (!stop) {
    n = rte_eth_rx_burst(port, q, mbufs, BURST);
    for (i = 0; i < n; i++) {
        pkt = mbufs[i];
        if (!l2_decode(pkt)) { free(pkt); continue; }
        if (!ip_decode(pkt)) { free(pkt); continue; }
        conn = tcp_lookup(pkt);
        if (!conn) { reply_rst(pkt); free(pkt); continue; }
        tcp_input(conn, pkt);          /* advances FSM; in-order data appended to
                                          conn->recv_queue as mbuf chain */
        /* on conn->recv_queue delta: emit one or more RESD_NET_EVT_READABLE events
           referencing each mbuf's data region (zero-copy view for user) */
    }
    tcp_tick(now);                     /* retransmit, RTO, TLP, keepalive; delayed-ACK off by default */
    n = rte_eth_tx_burst(port, q, tx_mbufs, tx_count);
}
```

### 5.2 `resd_net_send` call chain (synchronous, in-line)

```
resd_net_send(conn, buf, len)
  → copy buf[0..len] into tx mbuf chain (single mbuf when len fits MSS-headroom;
                                         chain across tx_data_mempool otherwise)
  → tcp_output      (segment to MSS-aligned chunks; prepend TCP hdr in reserved
                     headroom of each segment's head mbuf; track for retransmit
                     via mbuf refcount)
  → ip_output       (prepend IP + eth hdrs in reserved headroom)
  → push to TX batch (flushed at end of poll iter, or immediately on flush())
  → return bytes-accepted (may be < len if send buffer cap hit)
```

### 5.3 Buffer ownership

- RX mbufs owned by stack; delivered to user as `&[u8]` view via `RESD_NET_EVT_READABLE.data`. Any mbuf referenced by a delivered event is refcount-pinned from `resd_net_poll` return to the next `resd_net_poll` entry; internal stack processing (including later bursts within the same poll iteration) does not free these mbufs until the caller hands the poll back.
- TX mbufs allocated from per-lcore mempool, filled bottom-up with pre-reserved headroom for eth+IP+TCP headers, pushed to next tx_burst. Bytes larger than one mbuf's payload are sent as an mbuf chain (DPDK segmented mbuf).
- Retransmit queue holds mbuf pointers with bumped refcount; on ACK the ref drops and the mbuf returns to the mempool.
- **Retransmit mbuf policy**: a retransmit allocates a fresh mbuf from `tx_hdr_mempool` (header-only, chained back to the original data mbuf) rather than editing the original in place. This costs one allocation per retransmit (rare; negligible aggregate) and eliminates the race where an mbuf currently queued for or in-flight via `rte_eth_tx_burst` would have its TCP options edited under the NIC's DMA. The original data mbuf's refcount is held for the duration; only the TCP/IP/eth header mbuf is fresh. RFC 7323 timestamp-option refresh is done by writing the new `TSval` into the fresh header mbuf.

## 6. TCP Layer

### 6.1 State machine

Full RFC 9293 §3.3.2 eleven-state FSM implemented for client side, including CLOSING / LAST_ACK / TIME_WAIT. Never transition to LISTEN in production. TIME_WAIT duration: 2×MSL (MSL default 30s, tunable).

### 6.2 Per-connection state

```rust
struct TcpConn {
    four_tuple: FourTuple,
    state: TcpState,

    // sequence space (RFC 9293 §3.3.1)
    snd_una: u32, snd_nxt: u32, snd_wnd: u32, snd_wl1: u32, snd_wl2: u32, iss: u32,
    rcv_nxt: u32, rcv_wnd: u32, irs: u32,

    // timers
    rto: Duration, srtt: Option<Duration>, rttvar: Option<Duration>,
    rtx_timer: Option<Instant>, tlp_timer: Option<Instant>,
    delayed_ack_timer: Option<Instant>, keepalive_timer: Option<Instant>,

    // options negotiated at handshake
    ws_shift_out: u8, ws_shift_in: u8,           // RFC 7323
    ts_enabled: bool, ts_recent: u32, ts_recent_age: u64,  // RFC 7323 / PAWS
    sack_enabled: bool,                           // RFC 2018
    ecn_enabled: bool,                            // RFC 3168

    // buffers
    recv: RecvQueue,   // out-of-order + in-order, as mbuf chain
    snd:  SendQueue,   // mbuf refs for retransmit; SACK scoreboard

    // loss detection
    rack: RackState,   // RFC 8985

    // congestion control: None (default); Some(RenoState) when cc_mode=reno
    cc: Option<RenoState>,

    stats: ConnStats,
}
```

### 6.3 RFC compliance matrix (Stage 1 target)

| RFC | Feature | Scope | Notes |
|---|---|---|---|
| 791 | IPv4 | full for client send/recv | TOS/DSCP passthrough, DF always set |
| 792 | ICMP | frag-needed + dest-unreachable (in-only) | drives PMTUD; drop others silently |
| 1122 §3.3.2 | IPv4 reassembly | **not implemented** | RX fragments are dropped and counted (`ip.rx_frag`); we set DF on all TX, so we never fragment outbound |
| 1122 | Host requirements (TCP §4.2) | client-side items only | deviations documented below |
| 1191 | PMTUD | yes | driven by ICMP messages |
| 9293 | TCP | client FSM complete | no LISTEN/accept |
| 7323 | Timestamps + Window Scale | yes | enables RTT + PAWS + large windows |
| 2018 | SACK | yes | essential for WAN loss recovery |
| 5681 | Congestion control | off-by-default; Reno via `cc_mode` | |
| 6298 | RTO | yes | minRTO=20ms (tunable) |
| 6582 | NewReno | with Reno mode | |
| 6691 | MSS | yes | clamp to local MTU |
| 3168 | ECN | off-by-default (flag) | |
| 8985 | RACK-TLP | yes | primary loss detection; replaces 3-dup-ACK |
| 6528 | ISS generation | yes | `ISS = (ticks_since_boot_at_4µs) + SipHash(4-tuple \|\| secret \|\| boot_nonce)` — clock outside the hash for monotonicity across reconnects |
| 5961 | Blind-data-attack mitigations | yes | challenge-ACK on out-of-window seqs |
| 7413 | TCP Fast Open | **NO** | not useful for long-lived connections |

### 6.4 Deviations from RFC defaults (by design, for trading latency)

| Default | RFC stance | Our default | Rationale |
|---|---|---|---|
| Delayed ACK | RFC 1122 SHOULD (§4.2.3.2 ≤500ms, ≥1/2 full-size segments) | **off** | 200ms ACK delay is catastrophic for trading. Within each `resd_net_poll` iteration the stack emits at most one ACK per connection covering the in-order RX delta (burst-scope coalescing, not time-based delay). This bounds ACK rate at `(conn_count × poll_rate)` Hz. On bulk inbound market-data bursts, ACK rate can approach line-rate/MSS — acceptable because the TX path to the exchange is low-volume and not bandwidth-starved. |
| Nagle (`TCP_NODELAY` inverse) | RFC 896 | **off** | user sends complete requests; coalescing is their choice |
| TCP keepalive | optional | **off** | exchanges close idle; application heartbeats are preferred |
| minRTO | RFC 6298 RECOMMENDS 1s | **20ms** (tunable) | intra-region WAN RTT is 1–10ms |
| Congestion control | RFC 5681 MUST | **off-by-default** | ≤100 connections, well-provisioned WAN; Reno available behind `cc_mode` for A/B-vs-Linux and RFC-compliance modes |
| PermitTFO (RFC 7413) | optional | **disabled** | long-lived connections don't benefit; adds 0-RTT security complexity |

### 6.5 Implementation choices

- **Flow table**: flat `Vec<Option<TcpConn>>` indexed by handle id + a hash map `(4-tuple) → handle` for RX lookup. Expected cost: ~40ns hot, ~200ns cold due to bucket cacheline miss; acceptable at ≤100 connections. If per-connection latency budget tightens, switch to a small pre-warmed array (≤8 candidates per RSS-bucket) with linear scan — faster under cache pressure at this scale.
- **Segment-level mbuf tracking**: every TX segment holds an mbuf refcount until ACK or RST. **Retransmit allocates a fresh header mbuf** chained to the original data mbuf (see §5.3) — never edits an in-flight mbuf in place.
- **ISS**: `ISS = (monotonic_time_4µs_ticks_low_32) + SipHash64(local_ip || local_port || remote_ip || remote_port || secret || boot_nonce)` per RFC 6528 §3. Clock value is added outside the hash so reconnects to the same 4-tuple within MSL yield monotonically-increasing ISS. `secret` is a 128-bit per-process random constant; `boot_nonce` survives reboots via `/proc/sys/kernel/random/boot_id` or equivalent.
- **SYN retransmit**: schedule respects `connect_timeout_ms` from `resd_net_connect_opts_t`. Default: 3 attempts with initial backoff `max(initial_rto_ms, minRTO)` (config default: `initial_rto_ms=50`), exponential up to the total budget. Never exceed `connect_timeout_ms` in total; the connection fails fast for trading, not per RFC 6298's 1s recommendation.
- **RTO timer re-arm**: lazy. On ACK, update `snd.una`; the existing wheel entry fires at its originally-scheduled deadline. When it fires, the handler re-checks `snd.una` vs `snd.nxt` — if fully ACKed, the timer cancels itself; otherwise it retransmits and re-arms. Avoids remove+insert on every ACK.
- **TIME_WAIT shortening**: `resd_net_close(engine, conn, RESD_NET_CLOSE_FORCE_TW_SKIP)` is honored only when RFC 6191 / RFC 7323 §5 conditions are met — specifically, timestamps are enabled on both sides AND `SEG.TSval > TS.Recent` at reconnect. When conditions aren't met, the flag is ignored and the connection stays in TIME_WAIT; a `RESD_NET_EVT_ERROR` with `err=EPERM_TW_REQUIRED` is emitted so the caller knows.

## 7. Memory and Buffer Model

### 7.1 Mempools (per-lcore, no cross-lcore allocation)

```
rx_mempool       : 2× NIC rx ring size × max_lcores
                   MBUF_SIZE = 2048 + RTE_PKTMBUF_HEADROOM(128)
                   HEADROOM sized for eth(14) + ip(20..60) + tcp(20..60)
tx_hdr_mempool   : small mbufs for ACK-only / RST / control / retransmit-header
tx_data_mempool  : large mbufs for user send bytes (chained when len > mbuf capacity)
timer_mempool    : fixed-object pool for timer nodes
```

Stage 1 reserves no TLS/HTTP headroom or tailroom; if Stage 3/4 adds those layers, mempool sizing is revisited and headroom/tailroom extended.

On mempool exhaustion: `rx_mempool` alloc failure drops the inbound packet and increments `eth.rx_drop_nomem`. `tx_*_mempool` failure causes `resd_net_send` (or internal retransmit scheduling) to return `-ENOMEM` / accept fewer bytes than requested, emits `RESD_NET_EVT_ERROR{err=ENOMEM}` when the caller would otherwise not learn of it, and does not corrupt the in-flight connection state. A CI test pins mempool size to a tiny value and verifies surfacing.

### 7.2 Per-connection buffers

- `recv_reorder`: out-of-order segment list, each element holds `(seq_range, mbuf_ref)`. Merged into `recv_queue` as gaps fill. Capped at `recv_buffer_bytes`.
- `recv_queue`: in-order mbuf chain delivered to user via `RESD_NET_EVT_READABLE`.
- `snd_pending`: bytes the user has asked to send but not yet handed to `rte_eth_tx_burst`. Flushed at poll end or on `resd_net_flush`.
- `snd_retrans`: `(seq, mbuf_ref, first_tx_ts)` list. Capped at `send_buffer_bytes`.

### 7.3 Zero-copy path

```
RX:  NIC DMA → mbuf.data
               → tcp_input reassembly (mbuf chain for out-of-order; no copy)
                 → RESD_NET_EVT_READABLE.data points directly into mbuf
                   → user sees zero-copy view

TX:  user buf  → memcpy into tx mbuf.data at headroom offset
                 → tcp_output prepends TCP hdr in reserved headroom
                   → ip_output prepends IP+eth in reserved headroom
                     → NIC DMA reads mbuf.data
```

Copies on Stage 1:
- **TX**: one `memcpy` from user `buf` into tx mbuf. Unavoidable because user memory isn't DMA-pinned and we can't rely on the application keeping `buf` valid for the lifetime of TCP retransmission.
- **RX reassembly**: zero copies for in-order data (mbuf chain in `recv_queue`). Out-of-order segments are held as a linked list of mbufs; no copy unless we ever coalesce for contiguous delivery (which we don't — we fire one event per mbuf).

### 7.4 Timer wheel

- Hashed timing wheel, 8 levels × 256 buckets, per-lcore arena.
- Resolution: 10 µs. Horizon: ~68 s. Longer timers (2×MSL=60s) demoted to higher-level wheel.
- Wheel advancement is gated on `now_tick > last_ticked_tick`; when no tick elapsed since last poll (common at high poll rates), wheel walking is skipped entirely.
- Per-connection timer-list: each `TcpConn` owns a linked list of its scheduled timer IDs. On connection close, the close path walks this list and marks each timer cancelled (O(k) for k per-conn timers, k typically ≤4). Cancellation is a tombstone (generation counter bump); fire handlers check the generation and no-op on a stale fire.

### 7.5 Clock

- TSC-based; invariant TSC required (`CPUID.80000007H.EDX.InvariantTSC[bit 8]` set). Check at engine creation; fail fast otherwise.
- **Single calibration shared across all engines on the host**: the first `resd_net_engine_create` call performs `(tsc0, t0) = calibrate_against(CLOCK_MONOTONIC_RAW)`; subsequent engines reuse the same epoch via a process-global atomic-init. All engines therefore share one `ns_per_tsc` conversion; cross-lcore event correlation has bounded skew (only the per-core invariant-TSC startup offset, <100ns typical on bare metal; measured and reported in WAN A/B harness).
- `resd_net_now_ns` uses `rdtsc` (not `rdtscp`) — serialization is unnecessary for ms/µs-scale latency attribution. An inline variant `resd_net_now_ns_inline()` is exposed as a `static inline` in `resd_net.h` (reads TSC via compiler intrinsic, applies `(tsc-tsc0)*ns_per_tsc + t0` with engine-calibrated constants) so users can avoid the FFI call on tight hot-paths.
- NIC hardware timestamp: dyn-field offset and flag are resolved **once** at `engine_create` via `rte_mbuf_dynfield_lookup("rte_dynfield_timestamp")` and `rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp")`. Hot-path reads are a direct `*(uint64_t*)((char*)mbuf + ts_offset)` behind an always-inline accessor. When the NIC/PMD doesn't register the dynfield, the accessor returns 0 and `rx_hw_ts_ns` in every event is 0; callers fall back to `enqueued_ts_ns`.

## 8. Hardware Assumptions

- NIC: Mellanox ConnectX-6/7 or Intel E810 class, 25/100 GbE.
- RSS enabled for connection→lcore pinning via NIC hash.
- RX hardware timestamping on.
- Checksum offload on (IP + TCP).
- TSO/LRO **off** — LRO breaks per-segment timing attribution on the RX path.
- SR-IOV VF or PF; works with bifurcated driver.
- DPDK 23.11 LTS.
- ARP: static gateway MAC seeded at startup via netlink helper (one-shot), refreshed via gratuitous ARP every N seconds. No dynamic ARP resolution on the data path.
- DNS: resolved out-of-band via `getaddrinfo()` on a control thread before `resd_net_connect`.

## 9. Observability (Primitives Only)

Stack emits primitives; application computes histograms, routes logs, runs exporters using its own existing infrastructure.

### 9.1 Counters

Per-lcore struct of `AtomicU64` counts, cacheline-grouped, lock-free-readable via:

```c
const resd_net_counters_t* resd_net_counters(resd_net_engine_t*);
```

Counter groups (Stage 1): `eth`, `ip`, `tcp`, `poll`. Examples in `eth`: `rx_pkts`, `rx_bytes`, `rx_drop_miss_mac`, `rx_drop_nomem`, `tx_pkts`, `tx_bytes`, `tx_drop_full_ring`, `tx_drop_nomem`. In `tcp`: `rx_syn_ack`, `rx_data`, `rx_out_of_order`, `tx_retrans`, `tx_rto`, `tx_tlp`, `state_trans[11][11]`, `conn_open`, `conn_close`, `conn_rst`, `send_buf_full`, `recv_buf_delivered`.

Hot-path writes are `store(val+1, Ordering::Relaxed)` on the owning lcore (zero cost on x86_64 vs. plain store). Cross-lcore snapshot readers use `load(Ordering::Relaxed)` — no torn reads. `Relaxed` is sufficient because counters are non-ordering observability data, not synchronization primitives. The alternative — "plain `u64` + `memcpy`" — is a data race by the Rust / C++ abstract machine and is rejected.

### 9.2 Timestamps on events

Every `resd_net_event_t` carries:
- `rx_hw_ts_ns` — NIC hardware timestamp (ground truth for RX).
- `enqueued_ts_ns` — TSC when the event entered user-visible form (set inside `resd_net_poll`).

For TX: `resd_net_send` returns after pushing to the TX batch; the application records its own wall-clock at that moment if it cares. `resd_net_flush` is where the NIC actually sees the packet; applications that want ground-truth TX timing can read `resd_net_now_ns()` (or the inline variant) immediately before/after flush.

### 9.3 Stability-visibility events

Delivered through the normal `resd_net_poll` interface:
- `RESD_NET_EVT_TCP_RETRANS` — seq, rtx_count.
- `RESD_NET_EVT_TCP_LOSS_DETECTED` — RACK or RTO trigger.
- `RESD_NET_EVT_TCP_STATE_CHANGE` — from/to state.
- `RESD_NET_EVT_ERROR` with `err=ENOMEM` — mempool exhaustion on TX or internal allocation; with `err=EPERM_TW_REQUIRED` — `FORCE_TW_SKIP` flag ignored because RFC 6191 conditions not met.

State changes and ERROR events are always emitted. Per-packet TCP trace events (`TCP_RETRANS`, `TCP_LOSS_DETECTED`) are gated by the `tcp_per_packet_events` config flag so they don't clutter `resd_net_poll` results when not wanted.

### 9.4 What the stack explicitly does NOT provide

- No histograms (application computes from counters + event timestamps)
- No event ring infrastructure (application uses its existing event ring)
- No admin socket, no Prometheus endpoint, no log writer
- No OpenTelemetry spans on the data path
- No string-formatted logs on the data path (ever)

### 9.5 API-boundary instrumentation

Optional cargo feature `obs-stable-boundaries`: when enabled, public API entry points are marked `#[inline(never)]` with `#[no_mangle]` for stable eBPF uprobe / PMU attachment. Disabled by default — default build lets the compiler inline for minimum latency.

## 10. Test Plan

Layered testing, phased so Stage 1 ships with a defensible test story and later stages extend.

### 10.1 Layer A — Unit tests (cargo test, all stages)

- Per-module TCP state machine tests; RFC 9293 §3.10 ("Event Processing") is the oracle.
- TCP options encoder/decoder: window scale, timestamps, SACK, MSS, unknown-option handling.
- Reassembly / SACK scoreboard tests with constructed segment sequences.
- Timer wheel, flow table, mempool wrappers.
- API contract tests: `resd_net_send` partial-accept + `WRITABLE` event, multi-burst `READABLE` delivery, borrowed-view lifetime, `FORCE_TW_SKIP` guardrails.

### 10.2 Layer B — RFC conformance via packetdrill (Luna-pattern shim)

- `tools/packetdrill-shim`: links against libresd_net, redirects packetdrill's TUN read/write to stack rx/tx hooks, and provides a **synchronous socket-shim wrapper** that drives `resd_net_poll` internally to fake blocking-syscall semantics for `connect`/`write`/`read`/`close`. With Stage 1's byte-stream API, `write` maps straight to `resd_net_send` and `read` maps to a wait-loop over `RESD_NET_EVT_READABLE`.
- **Honest scope**: this exercises our wire-level TCP FSM, not our real asynchronous API. Packetdrill tests that depend on specific socket semantics we don't implement are not runnable:
  - Anything using `SIGIO`, `FIONREAD`, `SO_RCVLOWAT`, `MSG_PEEK`, `TCP_DEFER_ACCEPT`, `TCP_CORK`, or similar socket options.
  - Tests that assert partial-`read()` return values at specific buffer boundaries.
  - Tests that depend on Linux-specific timer behavior around delayed-ACK and 3-dup-ACK (we document these as deviations).
  The untranslatable subset is enumerated in `tools/packetdrill-shim/SKIPPED.md`; stage gates count pass rate among *runnable* scripts only.
- Run these corpora:
  - `github.com/ligurio/packetdrill-testcases` — pre-written scripts covering TCP RFC behavior (RFC 793/9293 FSM, 7323 timestamps, 2018 SACK, 5681 CC, 6298 RTO, 8985 RACK, 5961 mitigations). Exact RFC coverage: verify and record per-script on first import.
  - `github.com/shivansh/TCP-IP-Regression-TestSuite` — FreeBSD regression suite.
  - `github.com/google/packetdrill` upstream — TCP FSM and options.
  - Our scripts for RFC 7323 PAWS edge cases, RFC 2018 SACK reneging / out-of-order SACK blocks, RFC 8985 RACK reorder detection and TLP trigger, RFC 5961 challenge-ACK.

### 10.3 Layer C — RFC 793bis MUST/SHOULD via tcpreq

`tcpreq` probes a TCP endpoint (typically a server) for conformance. Since `resd_net` is client-only in production, this layer requires the **stage-1 loopback-test-server** (see §10.12): a minimal server-side build of the stack behind a cargo feature flag, used only by the test harness. `tcpreq` is pointed at the loopback server and produces a pass/fail table aligned to RFC 793bis / RFC 9293 requirements (checksum validation, RST processing, MSS, illegal/unknown option handling). Output feeds the RFC compliance matrix automatically.

Client-side conformance is covered indirectly by packetdrill-shim scripts that assert on the SYN/ACK/options *we emit* given specific peer behaviors.

### 10.4 Layer D — TTCN-3 via intel/net-test-suites

Black-box mode for bring-up; white-box mode (JSON protocol) when enough internal hooks exist for state assertions.

### 10.5 Layer E — Differential fuzzing via TCP-Fuzz

- `github.com/zouyonghao/TCP-Fuzz` in differential mode: identical packet+syscall sequences fed to `libresd_net` and Linux TCP; divergence is a bug.
- **Configuration requirement**: differential-vs-Linux is meaningful only in **RFC-compliance preset** — i.e., `cc_mode=reno`, delayed-ACK on (Linux-equivalent 40ms timer), `minRTO=200ms`, Nagle default. In this mode the two stacks should produce byte-identical wire behavior for equivalent inputs. Production-config differential fuzzing would produce false-positive divergences on every documented deviation (§6.4) and is explicitly **not** a useful test.
- A second fuzz track regresses against **our own previous release**: same input → same output across versions. Catches unintended behavior changes that differential-vs-Linux misses (anything where both our old and new code diverge from Linux).
- Motivation from prior work: TCP-Fuzz found semantic bugs across multiple userspace TCP stacks that sanitizer-based fuzzing does not catch, per USENIX ATC '22 reporting.
- CI: smoke run per merge. 72h continuous run per stage cut.

### 10.6 Layer F — Property / bespoke fuzzing

- `proptest`: round-trip identities on TCP options encode/decode; reassembly scoreboard invariants under random segment orderings.
- `cargo-fuzz` / libFuzzer targets: `tcp_input` with random pre-established state and arbitrary bytes (invariants: no panics, no UB, `snd.una ≤ snd.nxt`, rcv window monotonic); IP / TCP header parser with malformed options and truncated packets.
- `scapy` for adversarial hand-crafted packets: overlapping segments, malformed options, port-reuse races, timestamp wraparound.
- `smoltcp`'s `FaultInjector` pattern ported in: stackable RX-path middleware that randomly drops/duplicates/reorders/corrupts with configurable rates, enabled via env var for local soak-testing without netem.

### 10.7 Layer G — WAN A/B vs Linux (Stage 2 hardening)

```
Producer(strategy) ─► [lcore: resd_net stack]  ─┐
                                                 ├─► exchange testnet
Producer(strategy) ─► [kernel Linux socket   ]  ─┘
```

- Inbound market data replayed from a captured pcap via fan-out to both stacks, preserving inter-arrival timing via HW timestamping.
- Identical outbound order sequences.
- Comparison: wire-level captures via **hardware tap** (NOT switch mirror port; tap insertion jitter <100ns documented and quantified via a loopback calibration run before each comparison session); end-to-end `tx_req → rx_resp` latency distributions (p50/p99/p999/max) per exchange; retransmit rate, dup-ACK rate, SACK-block usage; send-window utilization vs RTT.
- Measurement protocol: tap jitter baseline is subtracted from measured deltas; reported latency parity is `(resd_net_p999 − Linux_p999) − tap_jitter_p999`.
- Pass gate: `resd_net` p999 latency ≤ Linux p999 latency (after jitter subtraction) on all tested venues; zero RFC-conformance deltas from replay through the packetdrill shim.

### 10.8 Layer H — WAN-condition fault injection (Stage 2 hardening)

Via `tc netem` on an intermediate Linux box inline between stack NIC and exchange:
- Delay: +20ms, +50ms, +200ms, jittered.
- Loss: 0.1% / 1% / 5% random, 1% correlated bursts.
- Duplication, reordering (3-segment depth), corruption.
- PMTU blackholing (drop ICMP frag-needed) — **Stage 2 scenario only**; requires PLPMTUD (RFC 8899)-style recovery, which is not in Stage 1 scope. Stage 1 relies on ICMP-driven PMTUD (RFC 1191) and degrades gracefully to the configured MSS when ICMP is dropped.
- Asserts: no stuck connections, no unbounded retransmit, state transitions remain valid, counters show the expected signals.

### 10.9 Layer I — Online shadow mode (Stage 2 hardening)

Run `resd_net` alongside the Linux-stack path in production. The application mirrors the same byte-stream workload onto both stacks (application-side responsibility). Gate promotion on zero byte-stream divergence and p99/p999 latency parity for 7 days.

### 10.10 Stage gates

- **Stage 1 ship** (raw-TCP byte-stream):
  - Layer A: 100% unit pass.
  - Layer B: packetdrill-shim's runnable (non-skipped) scripts from ligurio + shivansh passing on TCP FSM subset.
  - Layer C: tcpreq MUST rules passing against loopback-test-server.
  - **Observability gate**: assert-exact counter values in a controlled scenario. A unit test produces N retransmits, M state transitions, K byte-stream sends; the exposed counters match exactly (not "approximately"). State-change and ERROR events are delivered in the expected order and count.
  - End-to-end smoke: establish a TCP connection to a chosen test peer (netcat, iperf3, or the loopback test server), send/receive arbitrary bytes, verify ordering and flow control under `tc netem` loss/delay.
- **Stage 2 (hardening) ship**: + Layers E/G/H passing; 7-day prod shadow with zero byte-stream divergence vs. Linux on the same workload.
- **Stage 3+ (HTTP/TLS/WS) ship gates**: defined in their respective future design specs.

### 10.11 Tooling

- `tools/packetdrill-shim` — Luna-pattern adapter + socket-shim wrapper + `SKIPPED.md` enumeration.
- `tools/tcpreq-runner` — tcpreq wrapper with RFC-compliance report output.
- `tools/tcp-fuzz-differential` — TCP-Fuzz driver with Linux oracle; runs in RFC-compliance-preset config.
- `tools/replay` — pcap replay preserving HW timestamps.
- `tools/ab-bench` — dual-stack comparison harness + reporting with tap-jitter baseline subtraction.
- `tools/fuzz-corpus` — shared corpora, auto-updated from production pcaps.

### 10.12 Loopback test server (Stage 1 tooling)

A minimal server-side build of the stack behind the cargo feature flag `test-server`. Supports `accept` on a single listening port and byte-stream echo semantics. Used only by test harnesses (packetdrill-shim, tcpreq). Not compiled into production builds. This is Stage 1 scope — without it, Stage 1's tcpreq gate is unachievable.

## 11. Benchmark Plan

Goal: quantify latency and stability under trading-representative workloads, catch regressions per-commit, and establish defensible comparisons against Linux TCP as the reference baseline. Performance is verified separately from correctness (§10) — both must pass for a stage ship.

### 11.1 Measurement discipline

Measurements are meaningless without a pinned-down environment. Every benchmark run records and asserts the following preconditions:

- CPU: `isolcpus` covering every engine lcore and every measurement-core. `nohz_full` on those lcores. `rcu_nocbs` for the same set. No IRQ affinity on benchmark cores. Governor = `performance`, no C-states below C1 (`intel_idle.max_cstate=1`), turbo documented (fixed frequency preferred for reproducibility).
- NIC: interrupt coalescing off; TSO/LRO off; RSS enabled; HW timestamping on; flow-control off on the trading link.
- Memory: 2MiB or 1GiB huge pages for DPDK mempools; numa-local mempool/lcore binding asserted at engine_create.
- Clock: TSC invariant (§7.5 precondition). `rdtsc` baseline measured per-host.
- Kernel: non-PREEMPT_RT baseline; thermal throttling events logged by `turbostat` during the run — any throttle invalidates the run.
- Build: release profile with `-C target-cpu=native -C codegen-units=1 -C lto=fat`; symbols kept for `perf`.

Each benchmark's reporting table includes the host, DPDK version, kernel, NIC+firmware, and CPU model. Runs that don't match the pinned config are rejected at analysis time, not just flagged.

### 11.2 Microbenchmarks (cargo-criterion, statistical)

Each measures one unit of work in isolation; target is the function call cost, not end-to-end latency. Reported as median and p99 with bootstrap confidence intervals.

| Benchmark | What it measures | Expected order of magnitude |
|---|---|---|
| `bench_poll_empty` | `resd_net_poll` iteration with no RX and no timers | tens of ns |
| `bench_poll_idle_with_timers` | `resd_net_poll` iteration with `tcp_tick` walking an empty wheel bucket | tens of ns |
| `bench_tsc_read_ffi` | `resd_net_now_ns` via FFI | ~5 ns |
| `bench_tsc_read_inline` | `resd_net_now_ns_inline` (header-inline) | ~1 ns |
| `bench_flow_lookup_hot` | 4-tuple hash lookup, all connections hot in cache | ~40 ns |
| `bench_flow_lookup_cold` | 4-tuple hash lookup, flow-table cacheline flushed | ~200 ns |
| `bench_tcp_input_data_segment` | `tcp_input` for a single in-order data segment, PAWS+SACK enabled | ~100-200 ns |
| `bench_tcp_input_ooo_segment` | `tcp_input` for an out-of-order segment that fills a hole | ~200-400 ns |
| `bench_send_small` | `resd_net_send` of 128 bytes (fits single mbuf) | ~150 ns |
| `bench_send_large_chain` | `resd_net_send` of 64KiB (mbuf chain) | ~1-5 µs |
| `bench_timer_add_cancel` | `resd_net_timer_add` followed by `resd_net_timer_cancel` | ~50 ns |
| `bench_counters_read` | `resd_net_counters` + read of all counter groups | ~100 ns |

### 11.3 End-to-end latency benchmarks (`tools/bench-e2e`)

Run against the loopback-test-server (same-host) and against a dedicated peer on a cross-cable link.

- **Request-response RTT** (single connection, single outstanding): `send N bytes → recv N bytes` round-trip. Histogram reported as p50/p90/p99/p999/max.
- **HW-timestamp attribution**: for each measurement, record `rx_hw_ts_ns` minus `tx_sched_ts_ns` (wire RTT); record `enqueued_ts_ns` minus `rx_hw_ts_ns` (stack RX cost); record `user_return_ns` minus `enqueued_ts_ns` (event-handler cost in the user's poll loop); record `tx_burst_ns` minus `user_send_ns` (stack TX cost). These attribution buckets sum to the wall-clock RTT — the sum identity is asserted per-measurement (any mismatch invalidates the run).
- **One-way latency**: send-only tests with synchronized clocks (PTP or shared NIC tap) to measure TX-direction latency distribution independent of the peer's response latency.
- **Head-of-line latency under load**: while a background stream saturates the link at 80% of line rate, measure RTT on a separate connection. Target: no p99 degradation vs. idle-link RTT.

### 11.4 Stability benchmarks (latency under induced stress)

Conducted via `tc netem` on an intermediate Linux box, or via `smoltcp`'s `FaultInjector` pattern for inline injection (§10.6).

| Scenario | Measurement | Pass criteria |
|---|---|---|
| 0.1% random loss, 10ms RTT | request-response latency | p999 ≤ 3× idle p999; no stuck connection over 10 minutes |
| 1% correlated burst loss | request-response latency | p999 ≤ 10× idle p999; RTO/TLP fires observable via `tcp.tx_rto` / `tcp.tx_tlp` counters |
| Reordering depth 3 | same | RACK detects reorder, no spurious retransmit per `tcp.tx_retrans` delta |
| PMTU blackhole (drop ICMP frag-needed) — **Stage 2 only** | time-to-detect via PLPMTUD | requires RFC 8899; out of Stage 1 scope (use ICMP-driven PMTUD, RFC 1191) |
| Duplication (2x) | request-response latency | no observable degradation at p99 |
| Receiver zero-window stall then recovery | time to resume | `RESD_NET_EVT_WRITABLE` fires within 1 RTT of window open |
| Send-buffer-full under slow peer | backpressure signaling | `resd_net_send` returns partial; `WRITABLE` fires on drain |

### 11.5 Comparative benchmarks vs. Linux TCP

Same hardware, same traffic, two stacks. Linux run uses `AF_PACKET` mmap sockets (best-effort user-space delivery) and a standard `connect`/`send`/`recv` socket path; both recorded separately.

- RTT distribution comparison at p50/p99/p999 across idle, loss, and reorder conditions.
- Connection-establishment time (SYN to `CONNECTED` event) distribution.
- Time-to-first-byte on fresh connections.
- Wire-level behavior equivalence when `resd_net` is in RFC-compliance preset (`cc_mode=reno`, delayed-ACK on, `minRTO=200ms`): segment-level diff via `pcap` capture should be byte-identical on identical inputs.

Publish as "latency at 95% confidence interval, resd_net vs. Linux, N=100k measurements per bucket" with machine-readable CSV output so the comparison is reproducible.

### 11.6 Throughput benchmarks (secondary)

Throughput is not the primary goal but must not collapse:

- Single-connection goodput with MTU 1500 and MTU 9000.
- Aggregate goodput with 16 / 64 / 100 concurrent connections.
- Max sustained pps at small payload sizes (indicates upper bound of the per-packet cost).

Pass criteria: within 20% of Linux single-connection goodput (Linux has years of throughput optimization; our lane is latency). If we're above Linux, log the surprise — often that means we're shortcutting something we shouldn't.

### 11.7 Regression tracking in CI

- Microbenchmarks run per-commit via `cargo criterion --baseline main`; block merge on >5% regression on any benchmark's median.
- End-to-end benchmarks run nightly on a dedicated bare-metal host; results posted to a comparison dashboard (application-side infra, §9 primitives feed it).
- Flame graphs (`perf record` + `flamegraph`) generated for the request-response hot path on each release cut; diffed against prior release.
- PMU counters (LLC misses, branch mispredicts, instructions retired) captured on the hot path for each release; large deltas investigated.

### 11.8 Tooling

- `tools/bench-micro` — cargo-criterion harness.
- `tools/bench-e2e` — end-to-end RTT harness with HW-timestamp attribution.
- `tools/bench-stress` — netem/FaultInjector driver for stability runs.
- `tools/bench-vs-linux` — dual-stack comparison harness (reuses `tools/ab-bench` from §10.11).
- `tools/bench-report` — converts CSV outputs into shareable tables, feeds the dashboard.

### 11.9 Stage gates tied to benchmarks

- **Stage 1 ship**: §11.2 microbenchmarks meet order-of-magnitude targets; §11.3 e2e p999 latency on loopback is within a small constant (documented) of the idle HW-timestamp RTT; §11.4 stress scenarios all pass criteria; no regression vs. first-merge baseline.
- **Stage 2 (hardening) ship**: §11.5 comparative benchmarks show `resd_net` p999 ≤ Linux p999 under all tested conditions; PMU counters within acceptable deltas from the Stage-1 baseline.

## 12. Out of Scope for Stage 1

- Server-side TCP in production (test-only loopback server is in Stage 1 tooling; see §10.12)
- IPv6 / RFC 2460 / 8200 / 4443 / 4861 / 4862
- **HTTP/1.1 parser/encoder inside the library** — application-layer; handled by the application or a later stage
- **TLS of any version** — application-layer; handled by the application or a later stage
- **WebSocket** — application-layer; handled by the application or a later stage
- HTTP/2 (RFC 9113), HTTP/3 (RFC 9114)
- WebSocket `permessage-deflate` (RFC 7692) — not planned for any stage
- TCP Fast Open (RFC 7413)
- Full dynamic ARP state machine (static + gratuitous refresh only)
- DNS resolver on the data path

## 13. Open Questions to Resolve Before Stage 1 Starts

**[RESOLVED]**:
- **Rust toolchain.** Latest stable, no nightly. Manual `#[cold]` annotations replace `core::intrinsics::unlikely`; allocator hooks use the stable `GlobalAlloc` trait.

**[NICE-TO-HAVE]** — can be resolved during implementation:
- Specific NIC model and firmware version for the initial target hardware. Mitigable if the design stays PMD-agnostic, but HW-timestamp dyn-field behavior varies across mlx5 vs. ice; §7.5 already handles the unsupported case.
- Ownership of `tools/packetdrill-shim` — fork the packetdrill repo, or vendor it.
- Choice of end-to-end test peer for the Stage 1 smoke gate (netcat / iperf3 / custom TCP echo / the loopback-test-server).

## 14. References

- Stage 1: RFC 9293 (TCP, 2022 consolidated), 7323 (timestamps + window scale), 2018 (SACK), 5681 (Reno congestion control), 6298 (RTO), 8985 (RACK-TLP), 5961 (blind-data mitigations), 6528 (ISS), 6191 (TIME-WAIT reduction using timestamps), 6691 (MSS), 3168 (ECN), 791/792 (IP/ICMP), 1122 (host requirements, incl. reassembly), 1191 (PMTUD).
- Later-stage references (not consulted for Stage 1): RFC 9110/9112 (HTTP semantics + /1.1), RFC 8446 (TLS 1.3), RFC 6455 (WebSocket).
- mTCP: `github.com/mtcp-stack/mtcp` (reference only, not forked).
- Alibaba Luna userspace TCP + packetdrill adaptation (referenced for the shim pattern).
- Test suites: packetdrill (Google), ligurio/packetdrill-testcases, shivansh/TCP-IP-Regression-TestSuite, TheJokr/tcpreq, intel/net-test-suites, zouyonghao/TCP-Fuzz (USENIX ATC '22), smoltcp-rs/smoltcp (for `FaultInjector` pattern), crossbario/autobahn-testsuite.
