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
                              │ cbindgen C ABI header (dpdk_net.h)
  ┌───────────────────────────▼─────────────────────────────────────┐
  │  libdpdk_net  (Rust)                                             │
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
- `cbindgen` generates `dpdk_net.h` for C++ consumers.
- Public API uses `extern "C"` with primitive / opaque-pointer types only — no Rust-only types leak.
- C++ integration sample ships as a test consumer.

## 3. Threading and Runtime Model

- **One engine per lcore.** Caller pins itself to an lcore before calling `dpdk_net_engine_create(lcore_id, &cfg)`.
- **User code lives on the same lcore as the stack.** Run-to-completion: the user's event loop repeatedly calls `dpdk_net_poll`, which runs rx_burst → stack → emits events → user handles events inline → user-initiated sends batch into the next tx_burst.
- **No cross-lcore rings on the hot path.** Connections are pinned to lcores at `connect()` time; the application chooses the assignment.
- **Typical deployment**: one lcore for market-data ingress (one or a few high-pps inbound connections per venue), one lcore for order entry (few latency-critical outbound connections), plus strategy/business-logic cores communicating with the stack lcores via the application's own existing mechanisms.
- **FFI safety contract**: the Rust implementation must not panic across the `extern "C"` boundary. Any Rust panic within the stack is a library bug; panics are converted to process abort via a global `panic = "abort"` policy in `Cargo.toml` (release profile). On the caller side, a C++ exception in user code stays in user code — the poll-style API has no upcall, so exceptions never cross back into Rust.

## 4. Public API (Stage 1)

This section is **normative**. It defines the stable C ABI; `include/dpdk_net.h` is auto-generated from the Rust side via `cbindgen` and must match exactly. Error codes are negative `errno` values; success is `0` unless otherwise documented.

```c
/* ===== Engine ===== */
typedef struct dpdk_net_engine dpdk_net_engine_t;

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
    uint32_t rtt_histogram_bucket_edges_us[15]; /* A6: 15 strictly monotonically
                                       increasing edges define 16 buckets for the
                                       per-connection RTT histogram. All-zero
                                       substitutes the DEFAULT edge set (see §4
                                       dpdk_net_tcp_rtt_histogram_t). Non-monotonic
                                       rejected at engine_create with a NULL return
                                       (-EINVAL to the caller). */
} dpdk_net_engine_config_t;

dpdk_net_engine_t* dpdk_net_engine_create(uint16_t lcore_id,
                                          const dpdk_net_engine_config_t* cfg);
void dpdk_net_engine_destroy(dpdk_net_engine_t*);

/* ===== Connection ===== */
typedef uint64_t dpdk_net_conn_t;    /* opaque handle; 0 = invalid */

typedef struct {
    struct sockaddr_in peer;
    struct sockaddr_in local;        /* 0.0.0.0:0 = pick */
    uint32_t connect_timeout_ms;
    uint32_t idle_keepalive_sec;     /* 0 = off (default) */
} dpdk_net_connect_opts_t;

int dpdk_net_connect(dpdk_net_engine_t*,
                     const dpdk_net_connect_opts_t*,
                     dpdk_net_conn_t* out);

/* Close flags. Bitmask. */
#define DPDK_NET_CLOSE_FORCE_TW_SKIP  (1u << 0)  /* honored only when RFC 6191 §4.2 conds met */

int dpdk_net_close(dpdk_net_engine_t*, dpdk_net_conn_t, uint32_t flags);
int dpdk_net_shutdown(dpdk_net_engine_t*, dpdk_net_conn_t, int how);

/* ===== Byte-stream send ===== */
/* Enqueues bytes on the connection's send queue; copies into a tx mbuf chain
 * and returns. `buf` may be reused immediately after return.
 *
 * Return value (int32_t):
 *   >= 0  number of bytes accepted, in the range [0, len]. A value < len means
 *         the per-connection send buffer reached its cap; caller waits for
 *         DPDK_NET_EVT_WRITABLE before retrying the remainder.
 *   < 0   negative errno:
 *           -ENOMEM  tx mempool exhausted; retry later; a DPDK_NET_EVT_ERROR
 *                    {err=ENOMEM} is also emitted for visibility
 *           -ENOTCONN  connection not in a sending state
 *           -EINVAL  bad handle / null buf with nonzero len
 *
 * Mempool exhaustion is surfaced as an error return (never as a silent short
 * accept); a short accept (0..len with no error) means backpressure from the
 * peer's receive window or our per-conn send buffer cap. */
int32_t dpdk_net_send(dpdk_net_engine_t*,
                      dpdk_net_conn_t,
                      const uint8_t* buf,
                      uint32_t len);

/* ===== Poll ===== */
typedef enum {
    DPDK_NET_EVT_CONNECTED = 1,
    DPDK_NET_EVT_READABLE,             /* raw bytes available; data/data_len set */
    DPDK_NET_EVT_WRITABLE,             /* send buffer has space again */
    DPDK_NET_EVT_CLOSED,               /* peer FIN or our close completed */
    DPDK_NET_EVT_ERROR,
    DPDK_NET_EVT_TIMER,
    DPDK_NET_EVT_TCP_RETRANS,          /* stability-visibility events */
    DPDK_NET_EVT_TCP_LOSS_DETECTED,
    DPDK_NET_EVT_TCP_STATE_CHANGE,
} dpdk_net_event_kind_t;

/* Per-kind event payload. The `kind` field selects which arm of the union is
 * meaningful; other arms are undefined. */
typedef struct {
    dpdk_net_event_kind_t kind;
    dpdk_net_conn_t       conn;
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
} dpdk_net_event_t;

int dpdk_net_poll(dpdk_net_engine_t*,
                  dpdk_net_event_t* events_out,
                  uint32_t max_events,
                  uint64_t timeout_ns);

void dpdk_net_flush(dpdk_net_engine_t*);   /* force rte_eth_tx_burst now */

/* ===== Timers & clock ===== */
uint64_t dpdk_net_now_ns(dpdk_net_engine_t*);

/* Schedule a one-shot timer. On fire, emits DPDK_NET_EVT_TIMER with the same
 * timer_id echoed in events[i].u.timer.timer_id and user_data passed through.
 * Returns 0 on success and fills *timer_id_out; negative errno on failure. */
int dpdk_net_timer_add(dpdk_net_engine_t*,
                       uint64_t deadline_ns,
                       uint64_t user_data,
                       uint64_t* timer_id_out);

/* Cancel a previously-added timer. Fire is a no-op if the timer has already
 * been cancelled or has already fired. Returns 0 if cancelled before fire,
 * -ENOENT otherwise (unknown / stale / already-fired id). A6 note: the
 * earlier `-EALREADY` case for "fire event already queued" collapses into
 * `-ENOENT` — callers must always drain any queued DPDK_NET_EVT_TIMER
 * events regardless of this return. */
int dpdk_net_timer_cancel(dpdk_net_engine_t*, uint64_t timer_id);

/* ===== Observability primitives ===== */
const dpdk_net_counters_t* dpdk_net_counters(dpdk_net_engine_t*);

/* ===== Introspection (A5.5 + A6) ===== */
/* Per-connection snapshot: send-path state + RTT estimator state in one call.
 * Returns 0 on success, -ENOENT if conn is not a live handle, -EINVAL on null
 * args. Slow-path; safe to call per-order for forensics tagging but do not
 * call in a per-packet hot loop (per-call cost is a flow-table lookup + nine
 * u32 loads). */
int dpdk_net_conn_stats(dpdk_net_engine_t*,
                        dpdk_net_conn_t,
                        dpdk_net_conn_stats_t* out);

/* A6: per-connection RTT histogram snapshot. 16 × u32 buckets, layout
 * determined by `dpdk_net_engine_config_t.rtt_histogram_bucket_edges_us`
 * (default edges below). `memcpy`s the current bucket array out to caller
 * memory. Slow-path; one flow-table lookup + 64-byte copy per call.
 * Returns 0 on success, -ENOENT if conn is not a live handle, -EINVAL on
 * null `out`.
 *
 * Delta-math pattern: two successive snapshots with `wrapping_sub` per
 * bucket yield the increment over the interval, even across
 * wraparound, so long as no single bucket accumulated > 2^32 samples
 * between polls. */
typedef struct {
    uint32_t buckets[16]; /* indexes 0..=15, bucket[i] = count(rtt ∈
                             (edges[i-1], edges[i]]) with edges[-1]=0
                             and bucket[15] = count(rtt > edges[14]). */
} dpdk_net_tcp_rtt_histogram_t;

int dpdk_net_conn_rtt_histogram(dpdk_net_engine_t*,
                                dpdk_net_conn_t,
                                dpdk_net_tcp_rtt_histogram_t* out);
```

**A6 default RTT histogram edges** (when `rtt_histogram_bucket_edges_us` is all-zero):
`[50, 100, 200, 300, 500, 750, 1000, 2000, 3000, 5000, 10000, 25000, 50000, 100000, 500000]` µs. Covers a typical trading WAN distribution in 16 buckets with tight resolution at the sub-millisecond end and a coarse tail out to half a second before the catch-all.

**Introspection API (A5.5 + A6).** `dpdk_net_conn_stats(engine, conn, out)` returns a 9-field `u32` POD (`snd_una`, `snd_nxt`, `snd_wnd`, `send_buf_bytes_pending`, `send_buf_bytes_free`, `srtt_us`, `rttvar_us`, `min_rtt_us`, `rto_us`) in one call. Designed for per-order forensics tagging: diffs between consecutive snapshots answer "was the order sitting in `snd.pending` under peer-rwnd backpressure?" and "was the path's `srtt_us` / `rttvar_us` steady or spiking at send time?". Slow-path; safe per order, not safe per packet. See A5.5 design spec §3.3 for the full field semantics and usage pattern. `dpdk_net_conn_rtt_histogram(engine, conn, out)` (A6) returns the connection's 16-bucket RTT histogram; edges are set engine-wide via `dpdk_net_engine_config_t.rtt_histogram_bucket_edges_us` and default to the 15-edge ladder listed above. Per-conn RTT histogram lives on `TcpConn` (one cacheline per conn), not in `dpdk_net_counters_t`. Slow-path; one flow-table lookup + 64-byte `memcpy` per call.

**Per-connect TLP tuning fields (A5.5).** `dpdk_net_connect_opts_t` carries five TLP knobs below the existing A5 `rack_aggressive` / `rto_no_backoff` entries; defaults preserve RFC 8985 exactly:

- `tlp_pto_min_floor_us: u32` — `0` inherits engine `tcp_min_rto_us` (default); `u32::MAX` = explicit no-floor; otherwise bounded to `[0, tcp_max_rto_us]`.
- `tlp_pto_srtt_multiplier_x100: u16` — integer ×100 (100 = 1.0×, 200 = 2.0× default); valid range `[100, 200]`.
- `tlp_skip_flight_size_gate: bool` — when `true`, skip the RFC 8985 §7.2 `+max(WCDelAckT, RTT/4)` PTO penalty at FlightSize=1.
- `tlp_max_consecutive_probes: u8` — TLP probes fired consecutively before RTO takes over; default `1` (A5 behavior); valid `[1, 5]`.
- `tlp_skip_rtt_sample_gate: bool` — when `true`, disable RFC 8985 §7.3 step 2 "no new RTT sample since last TLP" suppression. Required alongside `tlp_max_consecutive_probes > 1` for multi-probe cadence.

See A5.5 design spec §5.5 for valid-range table, rejection semantics at `dpdk_net_connect`, and the aggressive-preset composition example.

### 4.1 Usage pattern

```c
engine = dpdk_net_engine_create(my_lcore, &cfg);
dpdk_net_connect(engine, &opts, &conn);

dpdk_net_event_t events[64];
while (running) {
    int n = dpdk_net_poll(engine, events, 64, 0);  /* 0 = busy-poll */
    for (int i = 0; i < n; i++) {
        switch (events[i].kind) {
        case DPDK_NET_EVT_CONNECTED:
            dpdk_net_send(engine, conn, request_bytes, request_len);
            dpdk_net_flush(engine);
            break;
        case DPDK_NET_EVT_READABLE:
            /* application parses the bytes (HTTP, WS, custom wire format, ...) */
            app_consume(conn, events[i].u.readable.data,
                               events[i].u.readable.data_len);
            break;
        case DPDK_NET_EVT_WRITABLE:
            /* retry any bytes that were refused earlier */
            app_drain_pending(conn);
            break;
        case DPDK_NET_EVT_CLOSED:
            app_on_close(conn, events[i].u.closed.err);
            break;
        }
    }
}
```

### 4.2 API contracts

- `dpdk_net_send` is synchronous: it copies bytes into the stack's tx mbuf chain and returns. No borrow-across-poll semantics for the send buffer; the caller may reuse `buf` immediately. Return contract: `>= 0` bytes accepted (possibly partial under backpressure); `< 0` is `-errno` (mempool exhaustion `-ENOMEM`, bad handle `-EINVAL`, not-connected `-ENOTCONN`). A short accept under backpressure is not an error; `-ENOMEM` is an error.
- `DPDK_NET_EVT_READABLE.u.readable.data` is a **borrowed view** into mbuf memory, valid from the moment `dpdk_net_poll` returns until the next `dpdk_net_poll` call on the same engine. The stack refcount-pins every mbuf referenced by any event in `events_out[0..n]` for that window; internal stack processing (including later bursts within the same poll) must not free those mbufs. Caller must `memcpy` out if they need bytes to outlive the poll.
- Multiple `DPDK_NET_EVT_READABLE` events may fire per poll iteration if received bytes span multiple mbufs; they deliver in-order, each with one contiguous mbuf-data region.
- `DPDK_NET_EVT_WRITABLE` fires when the per-connection send buffer has drained by at least half its capacity after a prior full/partial send refusal.
- `dpdk_net_flush` drains the pending data-segment TX batch via exactly one `rte_eth_tx_burst`; no-op when empty. Control frames (ACK, SYN, FIN, RST) are emitted inline at their emit site and do NOT participate in the flush batch — `dpdk_net_flush` only pushes out the data segments that `send_bytes` / internal retransmit queued onto `tx_pending_data`. Safe to call multiple times per poll iteration; idempotent — a follow-up call with nothing newly queued is a no-op.
- `dpdk_net_close` accepts a `flags` bitmask. Currently defined: `DPDK_NET_CLOSE_FORCE_TW_SKIP` (bit 0), which requests that the TIME_WAIT 2×MSL wait be skipped. The flag is honored only when `c.ts_enabled == true` at close time (the connection negotiated RFC 7323 timestamps). When the prerequisite is met, the close path sets the per-conn `force_tw_skip` bit; `reap_time_wait` then short-circuits the 2×MSL wait. When the prerequisite is NOT met, the flag is silently dropped, a `DPDK_NET_EVT_ERROR{err=-EPERM}` event is emitted for visibility (the "EPERM_TW_REQUIRED" condition), and the normal FIN + 2×MSL TIME_WAIT sequence proceeds. Other bits in `flags` are reserved for future extension and currently ignored.
- `rx_hw_ts_ns` is 0 when the NIC/PMD does not fill hardware timestamps; callers fall back to `enqueued_ts_ns`.
- **`dpdk_net_poll` event-overflow policy**: if more events are ready than `max_events`, the stack fills `events_out[0..max_events]` with events in FIFO enqueue order, stops further RX-burst processing for this iteration, and leaves the overflow + any unprocessed RX packets queued inside the engine. The next `dpdk_net_poll` call drains the queue before processing new RX. Per-connection event ordering is preserved across poll boundaries; no event kind is preempted or prioritized. Callers size `max_events` at least to `(NIC_BURST × 2)` so steady-state traffic fits; smaller sizes are valid but cause additional poll round-trips.
- **Event-queue soft-cap contract (A5.5).** The per-engine internal event queue has a configurable soft cap (`dpdk_net_engine_config_t.event_queue_soft_cap`, default `4096`, minimum `64` — smaller configs rejected at `engine_create` with `-EINVAL`). When `push` would exceed the cap, the **oldest** queued event is dropped (`pop_front`), `obs.events_dropped` increments, and the new event is pushed. `obs.events_queue_high_water` latches the maximum observed queue depth since engine start (does not decrement). The pair tells a clean story: high-water near cap with `events_dropped == 0` is a close call; `events_dropped > 0` is actual loss and the app's poll cadence is falling behind. Drop-oldest preserves the most recent events (most useful for immediate-past forensics), matching the Linux `dmesg` ring-buffer mental model. Both counters are slow-path (`AtomicU64`, fire only on event-push boundaries). See A5.5 design spec §3.2 for the full push-path pseudocode and rationale.

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
        /* on conn->recv_queue delta: emit one or more DPDK_NET_EVT_READABLE events
           referencing each mbuf's data region (zero-copy view for user) */
    }
    tcp_tick(now);                     /* retransmit, RTO, TLP, keepalive; delayed-ACK off by default */
    n = rte_eth_tx_burst(port, q, tx_mbufs, tx_count);
}
```

### 5.2 `dpdk_net_send` call chain (synchronous, in-line)

```
dpdk_net_send(conn, buf, len)
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

- RX mbufs owned by stack; delivered to user as `&[u8]` view via `DPDK_NET_EVT_READABLE.data`. Any mbuf referenced by a delivered event is refcount-pinned from `dpdk_net_poll` return to the next `dpdk_net_poll` entry; internal stack processing (including later bursts within the same poll iteration) does not free these mbufs until the caller hands the poll back.
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
| 5681 | Congestion control | off-by-default; Reno via `cc_mode` | `dup_ack` counter strict per §2 in A5 (was loose in A3/A4). |
| 6298 | RTO | yes | minRTO=5ms, maxRTO=1s, both tunable (§6.4) |
| 6582 | NewReno | with Reno mode | |
| 6691 | MSS | yes | clamp to local MTU |
| 3168 | ECN | off-by-default (flag) | |
| 8985 | RACK-TLP | yes | A5 implements RACK-TLP as the primary loss-detection path; 3-dup-ACK fast retrans is disabled (counter visibility only via `rx_dup_ack`). **A5.5 additions:** §6.3 `RACK_mark_losses_on_RTO` pass now runs at the top of `on_rto_fire` (Task 14 — was AD-17 in A5 review, closed). §7.2 `arm_tlp_pto` now called from the `Engine::send_bytes` TX path on every new-data send (Task 15 — was AD-18 in A5 review, closed). Per-connect tuning knobs (`tlp_pto_min_floor_us`, `tlp_pto_srtt_multiplier_x100`, `tlp_skip_flight_size_gate`, `tlp_max_consecutive_probes`, `tlp_skip_rtt_sample_gate`) deviate from strict §7.2 (PTO formula) and §7.3 step 2 (RTT-sample gate) when set — default values match RFC 8985 exactly. |
| 6298 §2.2 + §3 | SRTT from SYN handshake + Karn's rule | yes (A5.5) | SRTT is seeded from the SYN handshake round-trip on the first SYN's ACK per RFC 6298 §2.2 (first-RTT seeding). Karn's rule (§3) honored via `syn_retransmit_count == 0` guard — retransmitted SYNs produce no sample. `min_rtt_us` and `rto_us` are trustworthy from the moment the connection enters ESTABLISHED. Added A5.5 Task 13. |
| 6528 | ISS generation | yes | `ISS = (ticks_since_boot_at_4µs) + SipHash(4-tuple \|\| secret \|\| boot_nonce)` — clock outside the hash for monotonicity across reconnects |
| 5961 | Blind-data-attack mitigations | yes | challenge-ACK on out-of-window seqs |
| 7413 | TCP Fast Open | **NO** | not useful for long-lived connections |

### 6.4 Deviations from RFC defaults (by design, for trading latency)

| Default | RFC stance | Our default | Rationale |
|---|---|---|---|
| Delayed ACK | RFC 1122 SHOULD (§4.2.3.2 ≤500ms, ≥1/2 full-size segments); RFC 9293 MUST-58/-59 aggregate ACKs within an RX burst | **off + per-segment ACK in A3; burst-scope coalescing in A6** | 200ms ACK delay is catastrophic for trading. The spec-intent end state is: within each `dpdk_net_poll` iteration the stack emits at most one ACK per connection covering the in-order RX delta (burst-scope coalescing, not time-based delay). **Phase A3 ships a simpler per-segment-ACK baseline** — each inbound in-order data segment triggers one ACK in the same poll iteration. This over-ACKs relative to MUST-58 but never causes correctness issues (each ACK is individually valid). Burst-scope coalescing is finalized in A6 alongside the `preset=rfc_compliance` switch. This bounds ACK rate at `(conn_count × poll_rate × inbound_segs_per_poll)` Hz under A3 and `(conn_count × poll_rate)` Hz under A6 — acceptable in both modes because the TX path to the exchange is low-volume and not bandwidth-starved. |
| Receive-window shrinkage vs. buffer occupancy | RFC 9293 §3.10.7.4 (implicit: advertise `rcv_wnd = recv-buffer free space` and use the same value for ingress acceptance) | **advertise free_space; accept at full capacity** | Trading workload is market-data ingress at peer line-rate. Shrinking the ingress-acceptance window to match local buffer occupancy would throttle the peer's send rate — masking a real upstream "slow application consumer" problem as a protocol-layer artifact. We keep the ingress seq-window check at initial capacity (`recv_buffer_bytes`, default 256 KiB) so we accept everything the peer sends, and expose the drop condition via `tcp.recv_buf_drops` (bytes dropped because `recv.append` clamped at `free_space`). The peer's retransmit path recovers the dropped bytes; the application sees the counter climb and knows to speed up its consumer. The ACK we emit always advertises the real free space so well-behaved peers still throttle themselves based on *advertised* window; our wider ingress check just avoids being doubly-conservative. See `feedback_performance_first_flow_control.md`. |
| Nagle (`TCP_NODELAY` inverse) | RFC 896 | **off** | user sends complete requests; coalescing is their choice |
| TCP keepalive | optional | **off** | exchanges close idle; application heartbeats are preferred |
| minRTO | RFC 6298 RECOMMENDS 1s | **5ms** (tunable) | Exchange-direct RTT is 50–100µs, so 5ms is already 50× median. |
| RTO maximum | RFC 6298 ≥60s | **1s** | Trading fail-fast — reconnecting is cheaper than sitting on a 30s deadline. |
| Congestion control | RFC 5681 MUST | **off-by-default** | ≤100 connections, well-provisioned WAN; Reno available behind `cc_mode` for A/B-vs-Linux and RFC-compliance modes |
| PermitTFO (RFC 7413) | optional | **disabled** | long-lived connections don't benefit; adds 0-RTT security complexity |

**A5.5 additions (Accepted Deviations beyond the above trading-latency defaults):**

| AD tag | RFC stance | Our behavior | Rationale |
|---|---|---|---|
| `AD-A5-5-srtt-from-syn` | RFC 6298 §2.2 (first-RTT seeding) + §3 (Karn's rule) | **applied** — first SRTT sample drawn from SYN handshake round-trip on the first SYN's ACK. Karn's rule (§3) honored via `syn_retransmit_count == 0` guard. | Trader-latency use case requires trustworthy RTT state from the moment ESTABLISHED fires (for `dpdk_net_conn_stats` forensics and so AD-18's arm-TLP-on-send has a valid PTO basis). Bounds-checked `[1, 60_000_000) µs`. Net-conservative under the cited §2.2. Applies to every connection (not opt-in). See A5.5 design spec §3.5. |
| `AD-A5-5-rack-mark-losses-on-rto` | RFC 8985 §6.3 SHOULD-equivalent (`RACK_mark_losses_on_RTO` pass) | **applied** — `on_rto_fire` Phase 3 walks `snd_retrans.entries` and marks lost any entry where `seq == snd.una` OR `(xmit_ts/1000) + rack.rtt_us + rack.reo_wnd_us <= now_us` before retransmitting the batch through the existing `rack_lost_indexes` loop. | Closes AD-17 (from A5 RFC review S-1 promotion). Single RTO fire now retransmits the entire §6.3-eligible tail in one burst (one `tcp.tx_rto` increment, `tcp.tx_retrans` one-per-segment). Fewer aggregate cycles than A5's one-segment-per-ACK amortization. Applies to every connection. See A5.5 design spec §3.6. |
| `AD-A5-5-tlp-arm-on-send` | RFC 8985 §7.2 SHOULD ("the sender SHOULD start or restart a loss probe PTO timer after transmitting new data") | **applied** — new `arm_tlp_pto` helper invoked from `Engine::send_bytes` TX path after the new-data segment enters `snd_retrans`. Gated on SRTT-available + no-TLP-armed + probe-budget-not-exhausted. | Closes AD-18 (from A5 RFC review + mTCP E-2). Covers the pre-first-data-ACK tail-loss window that A5 left to RTO fallback. Combined with `AD-A5-5-srtt-from-syn`, SRTT is available at every arm site post-ESTABLISHED. Applies to every connection. See A5.5 design spec §3.7. |
| `AD-A5-5-tlp-pto-floor-zero` | RFC 8985 §7.2 silent on PTO minimum; many implementations use 10 ms | **per-conn opt-in** via `tlp_pto_min_floor_us`. `0` inherits engine `tcp_min_rto_us` (default); `u32::MAX` = explicit no-floor; otherwise `[0, tcp_max_rto_us]`. | On a tight-jitter intra-region link the 10 ms floor is multiple RTTs of wasted budget. Risk: spurious probes if jitter exceeds `SRTT/4`; `tcp.tx_tlp_spurious` counter lets the app self-correct the floor upward. Defaults preserve A5 behavior exactly. See A5.5 design spec §5.5. |
| `AD-A5-5-tlp-multiplier-below-2x` | RFC 8985 §7.2 hard-codes `2·SRTT` | **per-conn opt-in** via `tlp_pto_srtt_multiplier_x100`. Integer ×100; default `200` (2.0×); valid `[100, 200]`. | `2·SRTT` is conservative for the ≥40 ms delayed-ACK budgets the RFC assumes; trading peers do not use delayed ACKs in hot paths. Risk: probe-before-peer-ACK racing; same spurious counter mitigation. Defaults preserve A5 behavior exactly. |
| `AD-A5-5-tlp-skip-flight-size-gate` | RFC 8985 §7.2 adds `+max(WCDelAckT, RTT/4)` to PTO when FlightSize == 1 | **per-conn opt-in** via `tlp_skip_flight_size_gate`. When `true`, skip the penalty regardless of FlightSize. | `WCDelAckT` default of 200 ms is four orders of magnitude larger than our target order-entry RTT; the penalty blows any latency budget. Risk: if peer has delayed-ACK on, probe fires before peer's ACK (detected as spurious via DSACK). Companion-segment mitigation tracked as §12 follow-on in A5.5 spec. |
| `AD-A5-5-tlp-multi-probe` | RFC 8985 §7.3 step 2 allows at most one pending probe at a time; silent on consecutive schedules post-probe-ACK | **per-conn opt-in** via `tlp_max_consecutive_probes`. Default `1` (A5 behavior); valid `[1, 5]`. Budget resets on any new RTT sample or newly-ACKed data. | On clean probe-ACK arrival, a second probe at PTO cadence is often cheaper than a full RTO wait for a separate tail-loss. Risk: probe amplification bounded by the `[1, 5]` cap and budget reset. See A5.5 design spec §3.4. |
| `AD-A5-5-tlp-skip-rtt-sample-gate` | RFC 8985 §7.3 step 2 suppresses TLP when no new RTT sample has been seen since the last probe | **per-conn opt-in** via `tlp_skip_rtt_sample_gate`. When `true`, disable the suppression. | Required alongside `tlp_max_consecutive_probes > 1` for multi-probe cadence. On a quiescent path with occasional lost segments, consecutive probes without intervening samples is the recovery we want. Risk: runaway probing if path is persistently broken; bounded by `tlp_max_consecutive_probes` and RTO takeover. |
| `AD-A6-force-tw-skip` | RFC 9293 §3.5 MUST-13 requires an actively-closing side to linger in TIME_WAIT for 2×MSL; §3.5 MAY-2 permits reduction per RFC 6191, whose algorithm is stated server-side | **per-close opt-in** via `dpdk_net_close(conn, DPDK_NET_CLOSE_FORCE_TW_SKIP)`, honored only when `c.ts_enabled == true` at close time. Under that prerequisite, `c.force_tw_skip` is set and `reap_time_wait` drains the TIME_WAIT conn as soon as the FIN handshake completes rather than waiting 2×MSL. When the prerequisite is NOT met, the flag is silently dropped, a `DPDK_NET_EVT_ERROR{err=-EPERM}` event (the "EPERM_TW_REQUIRED" condition per §9.3) is emitted, and normal 2×MSL behavior proceeds. Default (no flag) is RFC 9293 MUST-13 exact. | Stage 1 is client-only (no LISTEN/accept) and exchanges reopen a 4-tuple faster than 2×MSL would permit. The combination of PAWS on the peer (RFC 7323 §5) + monotonic ISS on our side (RFC 6528 §3, via `(ticks_since_boot_at_4µs) + SipHash(…)`) is the client-side analog of RFC 6191 §4.2's protections: any in-flight segment from the prior incarnation is rejected either by the peer's TSval check (PAWS) or by our ISS-monotonicity gate. Opt-in + `ts_enabled` gate + EPERM-on-prereq-fail make the deviation caller-observable and RFC-default-preserving for unguarded callers. Full rationale in §6.5 "TIME_WAIT shortening". |

**A5.5 retirements:** `AD-15` (TLP pre-fire state machine) superseded by the `tlp_recent_probes` ring + `tlp_consecutive_probes_fired` budget data structures — retirement note on `docs/superpowers/reviews/phase-a5-rfc-compliance.md`. `AD-17` and `AD-18` (A5 RFC review promotions) absorbed into the two `AD-A5-5-rack-mark-losses-on-rto` / `AD-A5-5-tlp-arm-on-send` closure rows above.

### 6.5 Implementation choices

- **Flow table**: flat `Vec<Option<TcpConn>>` indexed by handle id + a hash map `(4-tuple) → handle` for RX lookup. Expected cost: ~40ns hot, ~200ns cold due to bucket cacheline miss; acceptable at ≤100 connections. If per-connection latency budget tightens, switch to a small pre-warmed array (≤8 candidates per RSS-bucket) with linear scan — faster under cache pressure at this scale.
- **Segment-level mbuf tracking**: every TX segment holds an mbuf refcount until ACK or RST. **Retransmit allocates a fresh header mbuf** chained to the original data mbuf (see §5.3) — never edits an in-flight mbuf in place.
- **ISS**: `ISS = (monotonic_time_4µs_ticks_low_32) + SipHash64(local_ip || local_port || remote_ip || remote_port || secret || boot_nonce)` per RFC 6528 §3. Clock value is added outside the hash so reconnects to the same 4-tuple within MSL yield monotonically-increasing ISS. `secret` is a 128-bit per-process random constant; `boot_nonce` survives reboots via `/proc/sys/kernel/random/boot_id` or equivalent.
- **SYN retransmit**: schedule respects `connect_timeout_ms` from `dpdk_net_connect_opts_t`. Default: 3 attempts with initial backoff `max(initial_rto_ms, minRTO)` (config default: `initial_rto_ms=50`), exponential up to the total budget. Never exceed `connect_timeout_ms` in total; the connection fails fast for trading, not per RFC 6298's 1s recommendation.
- **Data retransmit budget**: `tcp_max_retrans_count` (default 15). After this many RTO-driven retransmits of a single segment with no ACK progress, the connection fails with `DPDK_NET_EVT_ERROR{err=ETIMEDOUT}`. With backoff + `tcp_max_rto_us=1s`, the total wall-clock budget is ≈8.3s (5 + 10 + 20 + 40 + ...). Opt-out of backoff per-connect (`rto_no_backoff=true`) makes the budget linear in `count × rto_us`.
- **RTO timer re-arm**: lazy. On ACK, update `snd.una`; the existing wheel entry fires at its originally-scheduled deadline. When it fires, the handler re-checks `snd.una` vs `snd.nxt` — if fully ACKed, the timer cancels itself; otherwise it retransmits and re-arms. Avoids remove+insert on every ACK.
- **TIME_WAIT shortening**: `dpdk_net_close(engine, conn, DPDK_NET_CLOSE_FORCE_TW_SKIP)` is honored only when `c.ts_enabled == true` at close time (the connection negotiated RFC 7323 timestamps). Under that prerequisite the close path sets `c.force_tw_skip`; `reap_time_wait` then drains the TIME_WAIT conn as soon as the FIN handshake completes rather than sitting for 2×MSL. When the prerequisite is NOT met, the flag is silently dropped, a `DPDK_NET_EVT_ERROR{err=-EPERM}` event (the "EPERM_TW_REQUIRED" condition) is emitted for visibility, and the normal FIN + 2×MSL TIME_WAIT sequence proceeds. The combination of PAWS on the peer (RFC 7323 §5) plus monotonic ISS on our side (RFC 6528; see `ISS` implementation choice above) is the client-side analog of RFC 6191 §4.2's protections: any in-flight segment from the prior incarnation is rejected either by PAWS (peer-side TSval check) or by the ISS-monotonicity gate we maintain via the `(ticks_since_boot_at_4µs) + SipHash(…)` construction. Note this is a deliberate deviation from RFC 6191 §4.2's server-side wording — the RFC's conditions address the server incarnation reopening a passive listener, whereas our client-side construction relies on the peer's own PAWS + our ISS monotonicity to achieve the same protection without waiting 2×MSL on the client side.

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

On mempool exhaustion: `rx_mempool` alloc failure drops the inbound packet and increments `eth.rx_drop_nomem`. `tx_*_mempool` failure causes `dpdk_net_send` (or internal retransmit scheduling) to return `-ENOMEM` / accept fewer bytes than requested, emits `DPDK_NET_EVT_ERROR{err=ENOMEM}` when the caller would otherwise not learn of it, and does not corrupt the in-flight connection state. A CI test pins mempool size to a tiny value and verifies surfacing.

### 7.2 Per-connection buffers

- `recv_reorder`: out-of-order segment list, each element holds `(seq_range, mbuf_ref)`. Merged into `recv_queue` as gaps fill. Capped at `recv_buffer_bytes`.
- `recv_queue`: in-order mbuf chain delivered to user via `DPDK_NET_EVT_READABLE`.
- `snd_pending`: bytes the user has asked to send but not yet handed to `rte_eth_tx_burst`. Flushed at poll end or on `dpdk_net_flush`.
- `snd_retrans`: `(seq, mbuf_ref, first_tx_ts)` list. Capped at `send_buffer_bytes`.

### 7.3 Zero-copy path

```
RX:  NIC DMA → mbuf.data
               → tcp_input reassembly (mbuf chain for out-of-order; no copy)
                 → DPDK_NET_EVT_READABLE.data points directly into mbuf
                   → user sees zero-copy view

TX:  user buf  → memcpy into tx mbuf.data at headroom offset
                 → tcp_output prepends TCP hdr in reserved headroom
                   → ip_output prepends IP+eth in reserved headroom
                     → NIC DMA reads mbuf.data
```

Copies on Stage 1:
- **TX**: one `memcpy` from user `buf` into tx mbuf. Unavoidable because user memory isn't DMA-pinned and we can't rely on the application keeping `buf` valid for the lifetime of TCP retransmission.
- **RX reassembly**: zero copies for both in-order data (mbuf chain in `recv_queue`) and out-of-order segments (mbuf refs with `(offset, len)` per segment in `ReorderQueue`). The READABLE event pins referenced mbufs until the poll iteration completes per §5.3's mbuf-lifetime contract. Drain to in-order delivery produces an mbuf list (one event per mbuf), not a concatenated byte buffer. A6.5 retired the pre-existing `Vec<u8>` OOO-segment storage.

### 7.4 Timer wheel

- Hashed timing wheel, 8 levels × 256 buckets, per-lcore arena.
- Resolution: 10 µs. Horizon: ~68 s. Longer timers (2×MSL=60s) demoted to higher-level wheel.
- Wheel advancement is gated on `now_tick > last_ticked_tick`; when no tick elapsed since last poll (common at high poll rates), wheel walking is skipped entirely.
- Per-connection timer-list: each `TcpConn` owns a linked list of its scheduled timer IDs. On connection close, the close path walks this list and marks each timer cancelled (O(k) for k per-conn timers, k typically ≤4). Cancellation is a tombstone (generation counter bump); fire handlers check the generation and no-op on a stale fire.

### 7.5 Clock

- TSC-based; invariant TSC required (`CPUID.80000007H.EDX.InvariantTSC[bit 8]` set). Check at engine creation; fail fast otherwise.
- **Single calibration shared across all engines on the host**: the first `dpdk_net_engine_create` call performs `(tsc0, t0) = calibrate_against(CLOCK_MONOTONIC_RAW)`; subsequent engines reuse the same epoch via a process-global atomic-init. All engines therefore share one `ns_per_tsc` conversion; cross-lcore event correlation has bounded skew (only the per-core invariant-TSC startup offset, <100ns typical on bare metal; measured and reported in WAN A/B harness).
- `dpdk_net_now_ns` uses `rdtsc` (not `rdtscp`) — serialization is unnecessary for ms/µs-scale latency attribution. An inline variant `dpdk_net_now_ns_inline()` is exposed as a `static inline` in `dpdk_net.h` (reads TSC via compiler intrinsic, applies `(tsc-tsc0)*ns_per_tsc + t0` with engine-calibrated constants) so users can avoid the FFI call on tight hot-paths.
- NIC hardware timestamp: dyn-field offset and flag are resolved **once** at `engine_create` via `rte_mbuf_dynfield_lookup("rte_dynfield_timestamp")` and `rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp")`. Hot-path reads are a direct `*(uint64_t*)((char*)mbuf + ts_offset)` behind an always-inline accessor. When the NIC/PMD doesn't register the dynfield, the accessor returns 0 and `rx_hw_ts_ns` in every event is 0; callers fall back to `enqueued_ts_ns`.

### 7.6 Hot-path scratch reuse policy

Hot-path code — any function reachable from `engine::poll_once`, the RX / TX burst loops, the per-segment TCP state machine, per-ACK processing, or per-tick timer fire — MUST NOT call `Vec::new`, `Vec::with_capacity`, `Box::new`, `String::from`, `format!`, or any other heap allocator on a per-segment basis. The canonical patterns are:

1. **Engine-owned scratch.** `RefCell<Vec<T>>` (or `RefCell<SmallVec<[T; N]>>`) fields on `Engine` sized at `engine_create`. Hot-path borrows with `borrow_mut()`, clears, resizes only if capacity is insufficient, then fills. Mirrors the A6 `tx_pending_data` ring precedent. Typical examples: TX frame scratch, timer-id iteration scratch, pruned-mbufs scratch.

2. **Caller-provided `&mut` buffer.** Function takes `&mut Vec<T>` or `&mut SmallVec<[T; N]>` from the caller; clears + populates. Typical example: `rack_mark_losses_on_rto_into(&mut Vec<u16>)`.

3. **`SmallVec<[T; N]>` inline-stored.** For small working sets whose P99 size fits in N. Spill to heap is correctness-neutral but costs an allocation; N sized to cover observed P99. Typical examples: RACK lost-indexes (N=16), prune-below drop list (N=8), timer-fire burst (N=8), RACK loss-event tuples (N=4).

**Gate.** The `bench-alloc-audit` regression test (§10 — Testing) enforces zero allocations on the steady-state hot path. Any new hot-path site either satisfies one of the three patterns above, or the increment is a documented exception recorded in `docs/superpowers/reports/alloc-hotpath.md` with measured cost and reviewer sign-off — same structure as §9.1.1 rule 3 for hot-path counters.

**Not governed by this rule.**
- Per-connection one-shot allocations at `connect()` / `accept()` (send/recv VecDeques, `timer_ids` list). Per-connection, not per-segment.
- Engine-creation allocations (mempools, timer-wheel slots, scratch sizing). Startup cost.
- Error-path / slow-path `String::` / `format!` in logging, `Error` variants. Per §9.1.1 parallel: slow-path cost is fine.

## 8. Hardware Assumptions

### 8.1 Target deployment environment (Stage 1 host)

Stage 1 is developed and benchmarked on the actual production-shape hardware:

- **Host**: AWS EC2, Ubuntu 22.04 LTS, kernel 6.8 (aws flavour).
- **CPU**: AMD EPYC 7R13 (Milan / Zen 3). Available ISA for packet work: AVX2, SHA-NI, VAES, VPCLMULQDQ, SSE4.2 (CRC32), RDRAND/RDSEED, CLWB. **No AVX-512** — Milan does not have it; any SIMD fast-paths must target ≤ AVX2.
- **NIC**: single **Amazon ENA** (`1d0f:ec20`) on PCIe 00:05.0. SR-IOV VF semantics via the ENA interface; bound to DPDK via `vfio-pci` at runtime.
- **DPDK**: 23.11 LTS. ENA PMD source referenced in this section from `drivers/net/ena/`.
- **Hugepages**: ≥ 1 GB of 2 MB pages reserved at boot; EAL binds them at init.

Stage 1 design defaults (single RX / single TX queue, RTC loop, one-engine-per-lcore) are sized for this environment. Multi-queue expansion is out of scope for Stage 1 (§12) but the flow table and RSS wiring are designed so that enabling it later is a port-config change, not a code rewrite.

### 8.2 ENA offload capabilities (what the NIC can do for us)

**Observed at runtime on AWS AMD EPYC Milan + ENA PMD (DPDK 23.11), verified by A-HW Task 18 bring-up**: `rx_offload_capa=0x200e`, `tx_offload_capa=0x1800e`. The ENA PMD advertises:

| Direction | Capability | DPDK flag |
|---|---|---|
| RX | IPv4 header checksum verify | `RTE_ETH_RX_OFFLOAD_IPV4_CKSUM` (bit 1) |
| RX | UDP checksum verify | `RTE_ETH_RX_OFFLOAD_UDP_CKSUM` (bit 2) |
| RX | TCP checksum verify | `RTE_ETH_RX_OFFLOAD_TCP_CKSUM` (bit 3) |
| RX | VLAN tag filtering | `RTE_ETH_RX_OFFLOAD_VLAN_FILTER` (bit 13) |
| TX | IPv4 header checksum compute | `RTE_ETH_TX_OFFLOAD_IPV4_CKSUM` (bit 1) |
| TX | UDP checksum compute | `RTE_ETH_TX_OFFLOAD_UDP_CKSUM` (bit 2) |
| TX | TCP checksum compute (SW writes pseudo-header sum only) | `RTE_ETH_TX_OFFLOAD_TCP_CKSUM` (bit 3) |
| TX | Scatter/gather (multi-segment) | `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` (bit 15) |
| TX | Multi-thread lock-free TX | `RTE_ETH_TX_OFFLOAD_MT_LOCKFREE` (bit 16) |

**Capabilities the ENA PMD does NOT advertise** (contrary to earlier readings of the DPDK source; re-confirmed against live `rte_eth_dev_info_get` at A-HW Task 18 bring-up on 2026-04-20):

| Direction | Capability | DPDK flag |
|---|---|---|
| RX | 4-tuple Toeplitz hash → `mbuf.hash.rss` | `RTE_ETH_RX_OFFLOAD_RSS_HASH` (bit 19) **— NOT advertised** |
| RX | Multi-segment (scatter) | `RTE_ETH_RX_OFFLOAD_SCATTER` — NOT advertised |
| TX | TCP Segmentation Offload | `RTE_ETH_TX_OFFLOAD_TCP_TSO` — NOT advertised |
| TX | Fast-free (skip per-mbuf pool check on TX completion) | `RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE` (bit 14) **— NOT advertised** |

The MBUF_FAST_FREE and RSS_HASH gaps are the most operationally significant: A-HW's default feature set compile-requests both, so `eth.offload_missing_mbuf_fast_free = 1` and `eth.offload_missing_rss_hash = 1` are the *expected steady state* on real ENA under DPDK 23.11. The runtime capability-gate per §8.5 drops these bits from the applied mask and flow-table's hash consumer falls back to SipHash (§8 / A-HW spec §8.2).

**ENA-specific (enabled by default in the PMD, `ena_ethdev.c:2239`): Low-Latency Queues (LLQ).** LLQ has the host write the TX descriptor + packet header directly into the NIC's MMIO BAR (device memory), eliminating the NIC-side DMA-read round-trip that would otherwise fetch descriptor + header over PCIe. On ENA this is the single largest per-send latency reduction (~0.5–1 µs off `rte_eth_tx_burst` → wire). No application action is required; the PMD auto-enables LLQ when the device exposes the memory BAR and the `enable_llq` devarg is at its default.

### 8.3 ENA non-capabilities (important absences)

The ENA PMD does **not** offer:

- **No hardware RX timestamps.** ENA does not expose the `rte_mbuf_dynfield_timestamp` dynfield; `rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp")` returns negative at startup. `dpdk_net_event_t.rx_hw_ts_ns` falls back to the TSC read captured at `rx_burst` return, per the §7.5 / §4.2 dynfield-miss path. The field stays in the ABI for future portability to hardware with PTP / per-packet timestamps.
- **No LRO.** Software GRO via `librte_gro` is available but deliberately off for trading (coalescing obscures per-segment timing attribution).
- **No `rte_flow` / Flow Director beyond the RSS indirection table.** 5-tuple → specific queue steering is available only through reprogramming the RSS indirection table, not precise rule-based steering.
- **No inline crypto / IPsec / TLS.** If TLS arrives in Stage 4 it is software-only.
- **No hardware rate pacing / traffic shaping.**
- **No header/data split on RX.**
- **No VLAN insert/strip.** (Irrelevant on EC2 anyway.)

Design consequences:
- §9.2's `rx_hw_ts_ns` is **not** ground truth on this host; §7.5's fallback path (return 0, caller uses `enqueued_ts_ns`) is the production path, not an edge case. The same dynfield-presence check in §7.5 still applies — portability to future hardware with PTP is preserved.
- §11.3 wire-RTT attribution is done by comparing TSC reads on the local host at both ends of a loopback peer, not by subtracting NIC timestamps.
- §11.6 / §11.5 do not measure TSO or LRO paths; neither is used.

### 8.4 Offload-enablement policy (tiered, driven by trading-latency goal)

**Compile-time gates.** Every offload is behind a cargo feature flag — `hw-verify-llq`, `hw-offload-tx-cksum`, `hw-offload-rx-cksum`, `hw-offload-mbuf-fast-free`, `hw-offload-rss-hash`. All default to ON. A feature-off build compiles the offload code path away entirely; the software path is what the binary executes. This lets A10's benchmark harness produce an on-vs-off A/B comparison per offload via rebuilds, without the runtime cost of a toggle on the hot path. Gates live at the code site, not on struct fields, so the C ABI is stable across feature sets (same pattern as §9.1.1 observability flags). Note `hw-verify-llq` differs from the other flags: it does not enable an offload (LLQ activation is driven by the ENA PMD's `enable_llq=X` devarg, which is **application-owned** via EAL init — the ENA PMD default is `enable_llq=1`). Instead it gates the engine's verification discipline — PMD log-scrape at EAL init + fail-hard if ENA advertised LLQ capability but LLQ did not activate. See A-HW spec §5 for the capture mechanism.

**Runtime capability gate.** Separately from the compile-time gate, every offload that is compile-time-enabled is also AND-ed against `rte_eth_dev_info_get`'s `*_offload_capa` at `engine_create`. A requested-but-unadvertised capability degrades to the software path for that engine instance, logs WARN, and bumps a one-shot counter (`eth.offload_missing_<name>`). This preserves portability to non-ENA hardware (including `net_vdev` / `net_tap` in tests) without a separate build.

**Evidence gate.** Tier 1 is the **proposed** production default — each offload only stays as a default feature if A10's offload A/B measurement harness (`tools/bench-offload-ab/`) shows a reproducible p99 improvement on this specific host/NIC beyond the measurement noise floor. An offload that does not clear the noise floor is either removed from the default feature set or kept with a rationale committed alongside the CSV evidence (for example: correctness defense-in-depth for `hw-offload-mbuf-fast-free`). The final committed default set is recorded in `docs/superpowers/reports/offload-ab.md` and reflected in `crates/dpdk-net-core/Cargo.toml`'s `default = [...]` list. The text below lists the proposed set; the source of truth post-A10 is the report.

**Tier 1 (proposed) — enable at port-config bring-up (phase A-HW adds the code + gates; phase A10 measures + decides):**

1. **LLQ**: on by default in the PMD; verified via PMD log + runtime dev-info check; no code change beyond the EAL bring-up. Startup fails if `dev_info` reports LLQ-capable but it did not activate.
2. **`RTE_ETH_TX_OFFLOAD_TCP_CKSUM`, `RTE_ETH_TX_OFFLOAD_IPV4_CKSUM`, `RTE_ETH_TX_OFFLOAD_UDP_CKSUM`**: TX path sets `ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4`, sets `mbuf.l2_len / l3_len / l4_len`, and writes only the TCP / UDP pseudo-header checksum (per RFC 9293 §3.1 / RFC 768). The software full-fold path stays in the source tree behind a capability check for the fallback case (vdev / TAP / non-ENA test harnesses).
3. **`RTE_ETH_RX_OFFLOAD_IPV4_CKSUM`, `RTE_ETH_RX_OFFLOAD_TCP_CKSUM`, `RTE_ETH_RX_OFFLOAD_UDP_CKSUM`**: RX path inspects `mbuf.ol_flags & RTE_MBUF_F_RX_*_CKSUM_MASK` and branches on the per-packet `GOOD` / `BAD` / `NONE` / `UNKNOWN` flag. `BAD` → drop with counter (`eth.rx_drop_cksum_bad`). `NONE` / `UNKNOWN` → software fold (fallback when offload is unavailable on a test device).
4. **`RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE`**: single offload bit; the TX-completion path drops the per-mbuf pool-ID check. Free latency win with one invariant: all TX mbufs come from the same per-lcore mempool, which is already true by spec §7.1.

**Tier 2 — enable when multi-queue lands (out of Stage 1 scope per §12, but spec'd so the flow table accommodates):**

5. **`RTE_ETH_RX_OFFLOAD_RSS_HASH`**: port configured with `rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP`; the flow table reads `mbuf.hash.rss` as the initial bucket index (and falls back to SipHash when the RSS-valid flag is absent). Single-queue deployments still set the RSS indirection table so every hash points to queue 0 — the hash is present for the flow-table fast-path, steering stays trivial.

**Tier 3 — deliberately NOT enabled in Stage 1:**

6. **TSO (`RTE_ETH_TX_OFFLOAD_TCP_TSO`)** — trading send sizes are sub-MSS; TSO's descriptor-setup cost is overhead, not savings.
7. **Software GRO / LRO (none on ENA anyway)** — merges segments and obscures per-segment timing attribution, which is the opposite of what trading measurement needs.
8. **Multi-segment RX/TX (`RTE_ETH_RX_OFFLOAD_SCATTER`, `RTE_ETH_TX_OFFLOAD_MULTI_SEGS`)** — unnecessary at MTU 1500 with single-mbuf payloads; adds branch complexity on the hot path. Retransmit's header-mbuf-chained-to-data-mbuf pattern (§5.3) does need multi-seg TX, so it is enabled as a dependency of retransmit; general data-path multi-seg is not.
9. **Generic Segmentation Offload (`librte_gso`)** — same argument as TSO.

### 8.5 Capability-gated bring-up (portability preservation)

`engine_create` queries `rte_eth_dev_info_get` once and ANDs the requested offload mask against `dev_info.tx_offload_capa` / `dev_info.rx_offload_capa`. Missing capabilities degrade to the software path with a startup WARN log and a one-shot counter (`eth.offload_missing_<name>`) — no runtime hot-swap. This preserves portability to non-ENA hardware (including `net_vdev` / `net_tap` in tests) without requiring a separate "offload off" build.

A startup banner logs the negotiated offload set (one line per direction) so operators can verify at deploy time. Per §9.1.1, no per-segment hot-path counter tracks "offload used" vs "offload software-path" — the startup log is authoritative because offload state does not hot-swap during a run.

### 8.6 Other assumptions (carry-over from Stage 1 initial draft)

- ARP: static gateway MAC seeded at startup via netlink helper (one-shot), refreshed via gratuitous ARP every N seconds. No dynamic ARP resolution on the data path.
- DNS: resolved out-of-band via `getaddrinfo()` on a control thread before `dpdk_net_connect`.

## 9. Observability (Primitives Only)

Stack emits primitives; application computes histograms, routes logs, runs exporters using its own existing infrastructure.

### 9.1 Counters

Per-lcore struct of `AtomicU64` counts, cacheline-grouped, lock-free-readable via:

```c
const dpdk_net_counters_t* dpdk_net_counters(dpdk_net_engine_t*);
```

Counter groups (Stage 1): `eth`, `ip`, `tcp`, `poll`, `obs` (A5.5). Examples in `eth`: `rx_pkts`, `rx_bytes`, `rx_drop_miss_mac`, `rx_drop_nomem`, `tx_pkts`, `tx_bytes`, `tx_drop_full_ring`, `tx_drop_nomem`. In `tcp`: `rx_syn_ack`, `rx_data`, `rx_out_of_order`, `tx_retrans`, `tx_rto`, `tx_tlp`, `tx_tlp_spurious` (A5.5), `state_trans[11][11]`, `conn_open`, `conn_close`, `conn_rst`, `send_buf_full`, `recv_buf_delivered`. In `obs` (A5.5, engine-internal observability signals): `events_dropped` (incremented once per event dropped from the internal event queue on soft-cap overflow), `events_queue_high_water` (latched max observed queue depth since engine start — does not decrement). The `obs` group is introduced alongside `poll`/`eth`/`ip`/`tcp` for engine-internal observability that does not fit the packet-path groups; new entries like `obs.poll_idle_ratio` or similar may land in later phases.

**A5 additions** (slow-path counters for RACK-TLP, RTO, retrans-budget, config-visibility):

- `tcp.rtt_samples` — RTT sample taken (TS source or Karn's).
- `tcp.tx_rack_loss` — RACK marked a segment lost.
- `tcp.tx_retrans` — a retransmit frame TX'd (any cause).
- `tcp.tx_rto` — RTO fire attempted a retransmit.
- `tcp.tx_tlp` — TLP fire probed the last in-flight segment.
- `tcp.conn_timeout_retrans` — `tcp_max_retrans_count` exhausted → ETIMEDOUT.
- `tcp.conn_timeout_syn_sent` — SYN retransmit budget exhausted → ETIMEDOUT.
- `tcp.rack_reo_wnd_override_active` — conn has `rack_aggressive=true`.
- `tcp.rto_no_backoff_active` — conn has `rto_no_backoff=true`.
- `tcp.rx_ws_shift_clamped` — peer advertised WS>14; clamped to 14.
- `tcp.rx_dsack` — peer sent a DSACK block (visibility only).

**A5.5 additions:**

- `tcp.tx_tlp_spurious` — prior TLP probe confirmed spurious via DSACK within a 4·SRTT plausibility window. Paired with `tcp.tx_tlp`: `spurious_ratio = tx_tlp_spurious / tx_tlp`. Above ~3–5% indicates the per-conn jitter budget is under-provisioned relative to path reality — app should raise `tlp_pto_min_floor_us` on affected sockets. Per-probe attribution (no double-counting).
- `obs.events_dropped` — event dropped from the per-engine internal event queue on soft-cap overflow. Nonzero = app poll cadence cannot keep up; `events_queue_high_water` tells you how close the pressure got and `events_dropped` tells you whether any were lost.
- `obs.events_queue_high_water` — latched max observed queue depth since engine start. Does not decrement. Combined with `events_dropped`: high-water near cap with `events_dropped == 0` is a close call; nonzero `events_dropped` is actual loss.

**A6 additions** (all slow-path counters per §9.1.1 — timer fire, lazy-expiration, flush-drain):

- `tcp.tx_api_timers_fired` — incremented once per `DPDK_NET_EVT_TIMER` emission (i.e. per public-timer fire from `dpdk_net_timer_add`). Paired with `dpdk_net_timer_add` return counts (observed externally by the caller) to answer "did my timer actually fire, or was it cancelled / stale?". Slow-path; fires at timer-fire rate, not per-segment.
- `tcp.ts_recent_expired` — incremented when the RFC 7323 §5.5 24-day `TS.Recent` lazy expiration fires on a received TS-carrying segment. Nonzero values indicate a connection that has been idle for > 24 days and is re-adopting a fresh TSval rather than PAWS-rejecting the segment. Rare on short-lived exchange connections; informational for long-held keepalive paths.
- `tcp.tx_flush_bursts` — incremented once per `rte_eth_tx_burst` call made by `drain_tx_pending_data` (via `dpdk_net_flush` or the end-of-poll drain). Paired with `tcp.tx_flush_batched_pkts` to compute the average batch size (`batched_pkts / bursts`); higher ratios indicate better amortization of the per-burst doorbell cost.
- `tcp.tx_flush_batched_pkts` — incremented by the number of mbufs actually handed to the single `rte_eth_tx_burst` inside each drain. Sum over an interval vs. `tx_pkts` tells you what fraction of TX went through the batched data-segment path vs. the inline control-frame path.

Per-connection RTT histogram is intentionally NOT in `dpdk_net_counters_t` — see `dpdk_net_conn_rtt_histogram` under the §4 Introspection API. The histogram lives on each `TcpConn` (one cacheline per conn) rather than in the engine counter struct; snapshot-delta semantics give the caller control over the aggregation interval without engine-wide contention.

Counter writes are `fetch_add(1, Ordering::Relaxed)` (`lock xadd` on x86_64; ~8-12 cycles uncontended). Cross-lcore snapshot readers use `load(Ordering::Relaxed)` — no torn reads. `Relaxed` is sufficient because counters are non-ordering observability data, not synchronization primitives. The alternative — `load(Relaxed)` + `store(val+1, Relaxed)` — is cheaper by a few cycles under the single-owner-lcore invariant but drops increments if that invariant ever slips (e.g., a future refactor moves a counter to a shared path); `fetch_add` is robust under any producer layout. The additional alternative — "plain `u64` + `memcpy`" — is a data race by the Rust / C++ abstract machine and is rejected. Slow-path counters pay the `fetch_add` cost unconditionally (see §9.1.1); hot-path counters follow the §9.1.1 policy (feature-gated + per-burst batched into a stack-local accumulator + single aggregate `fetch_add`).

### 9.1.1 Counter-addition policy

Counters are not free. Every `fetch_add` on the hot path costs cycles (~8–12 cycles uncontended `lock xadd` on x86_64, plus store-buffer flush). On a 10 M segments/sec lcore that is ~3% of one core per extra hot-path counter.

**Default policy — every counter addition must satisfy one of these:**

1. **Slow-path-only.** Increments only on error, rare lifecycle events, or per-connection (not per-segment / per-burst / per-poll). No measurable cost; no gate required. This is the default and most counters should live here.

2. **Hot-path, compile-time toggleable.** If a counter must fire on the hot path, it lands behind a cargo feature flag (default = off) and its justification is documented inline where the counter is declared. The justification must name the operational question the counter answers that cannot be answered from the existing slow-path counters, events, or externally-observable signals (PMU, pcap, NIC counters). Design the increment for minimum cost from the start: batch into a stack-local within the natural burst loop and emit one `fetch_add` per burst, not per segment.

3. **Explicit exception.** A hot-path counter shipped unconditionally (no feature gate) requires a spec amendment citing the measured cost, the benchmark that confirms it fits within §11 budgets, and the reviewer sign-off. Do not ship unconditional hot-path counters by default.

**Implication for new-counter PRs:** if the increment site is inside `tcp_input`, `tcp_output`, `engine::poll_once`, or any RX/TX burst loop, it is hot-path and rule 2 or 3 applies. Default counters-coverage audit (§10 A8) treats feature-gated counters as optional — the audit runs twice, once with default features and once with all observability features enabled, and each declared counter must be reachable in at least one of the two runs.

**ABI stability:** the `#[cfg(feature = ...)]` gate applies to the **increment site**, not the struct field. Every counter field is always allocated and exposed via `dpdk_net_counters_t`. Feature-off builds still expose the field in the C ABI but leave it at zero. This keeps the C header stable across feature sets at the cost of ~8 bytes per counter, which is acceptable given counters are cacheline-grouped and sparse.

**Canonical observability feature flags** (Stage 1):

| Flag | Default | Gates (increment sites) | Rationale |
|---|---|---|---|
| `obs-byte-counters` | **OFF** | `tcp.tx_payload_bytes`, `tcp.rx_payload_bytes` | Per-segment byte accounting; ~3% hot-path cost without batching, <0.1% with per-burst stack-local accumulator. Ops value for trading desks (market-data vs. order byte budgets) is real but not universal; opt-in. |
| `obs-poll-saturation` | **ON** | `poll.iters_with_rx_burst_max` | One extra `if/inc` per poll iteration; cost is essentially a branch since it fires only when `rx_burst` returns `max_burst`. Signals "we may be falling behind the NIC" and has no cheap alternative. Default on because the diagnostic value dominates the marginal cost; can be turned off for absolute-minimum-overhead builds via `--no-default-features`. |
| `obs-stable-boundaries` | **OFF** | (API boundary symbols, §9.5) | Already-existing flag for eBPF uprobe attachment; listed here for completeness. |

Each hot-path counter must be documented inline at its declaration with: (1) the feature flag that gates it, (2) the operational question it answers that no existing slow-path counter / event / PMU counter / NIC counter / pcap can answer, (3) the increment-batching pattern used on the hot path.

### 9.2 Timestamps on events

Every `dpdk_net_event_t` carries:
- `rx_hw_ts_ns` — NIC hardware timestamp when the PMD registers the `rte_dynflag_rx_timestamp` dynfield; 0 otherwise. On the Stage 1 deployment target (ENA, per §8.3) this dynfield is not exposed, so the field is 0 in the reference configuration and callers use `enqueued_ts_ns` as the ground-truth RX time per §7.5. The field stays in the ABI for future portability to hardware with PTP / per-packet timestamps.
- `enqueued_ts_ns` — TSC when the event entered user-visible form (set inside `dpdk_net_poll`). On ENA this is the RX ground truth.

For TX: `dpdk_net_send` returns after pushing to the TX batch; the application records its own wall-clock at that moment if it cares. `dpdk_net_flush` is where the NIC actually sees the packet; applications that want ground-truth TX timing can read `dpdk_net_now_ns()` (or the inline variant) immediately before/after flush.

### 9.3 Stability-visibility events

Delivered through the normal `dpdk_net_poll` interface:
- `DPDK_NET_EVT_TCP_RETRANS {seq, rtx_count}` — gated by `tcp_per_packet_events`.
- `DPDK_NET_EVT_TCP_LOSS_DETECTED {cause: Rack|Tlp|Rto}` — gated by `tcp_per_packet_events`.
- `DPDK_NET_EVT_TCP_STATE_CHANGE` — from/to state.
- `DPDK_NET_EVT_ERROR` with `err=ENOMEM` — mempool exhaustion on TX or internal allocation; with `err=EPERM_TW_REQUIRED` — `FORCE_TW_SKIP` flag ignored because RFC 6191 conditions not met; with `err=ETIMEDOUT` — SYN retransmit budget exhausted (4th SYN attempt) or data retransmit budget exhausted (`tcp_max_retrans_count`+1).

State changes and ERROR events are always emitted. Per-packet TCP trace events (`TCP_RETRANS`, `TCP_LOSS_DETECTED`) are gated by the `tcp_per_packet_events` config flag so they don't clutter `dpdk_net_poll` results when not wanted.

**A6 `DPDK_NET_EVT_ERROR{err=-ENOMEM}` emission sites.** ENOMEM (tx / rx mempool exhaustion) is surfaced through three distinct sites with different cadences so the caller always has actionable visibility without event-storm risk:

1. **`send_bytes` synchronous return.** When `dpdk_net_send` cannot allocate a header mbuf from `tx_hdr_mempool`, the call returns `-ENOMEM` synchronously AND emits one `DPDK_NET_EVT_ERROR{conn, err=-ENOMEM}` event per call site. The redundant event makes the condition visible to callers whose error-handling wrapper only looks at poll events (and for symmetry with the internal-retransmit path below where no sync return exists).
2. **Internal retransmit per-occurrence.** When `retransmit` (called from RTO / RACK / TLP fire handlers) cannot allocate a fresh header mbuf or the subsequent `rte_pktmbuf_chain` fails, one `DPDK_NET_EVT_ERROR{conn, err=-ENOMEM}` is emitted per occurrence. No rate limiting — retransmit failures are already rare (mempool exhaustion under persistent pressure) and each occurrence is actionable.
3. **RX mempool edge-triggered per poll iteration.** The RX path's mempool-drop counter (`eth.rx_drop_nomem`) increments per dropped packet, but the RX ENOMEM event is edge-triggered: `poll_once` snapshots `eth.rx_drop_nomem` at the top and compares against the post-RX-burst value; if `post > pre`, exactly ONE `DPDK_NET_EVT_ERROR{conn=0, err=-ENOMEM}` event is emitted for that poll iteration, regardless of how many packets were dropped. This caps the event rate at one per poll under a runaway RX-mempool-exhaustion condition, leaving `eth.rx_drop_nomem` as the ground-truth per-packet counter.

**`enqueued_ts_ns` semantic (A5.5 correction).** The `dpdk_net_event_t.enqueued_ts_ns` field is sampled at **event emission** inside the stack, **not** at `dpdk_net_poll` drain. For packet-triggered events, emission time is when the stack processed the triggering packet (not when the NIC received it — use `rx_hw_ts_ns` for NIC-arrival). For timer-triggered events (RTO fire, loss-detected), emission time is the fire instant. This eliminates the ±poll-interval skew (tens of µs at 10–100 kHz poll rates) that the pre-A5.5 drain-time sampling introduced. Field name and layout on the public ABI are unchanged; only the sampling site moves. See A5.5 design spec §3.1 for the rationale; `rx_hw_ts_ns` semantics are unchanged.

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
- API contract tests: `dpdk_net_send` partial-accept + `WRITABLE` event, multi-burst `READABLE` delivery, borrowed-view lifetime, `FORCE_TW_SKIP` guardrails.

### 10.2 Layer B — RFC conformance via packetdrill (Luna-pattern shim)

- `tools/packetdrill-shim`: links against libdpdk_net, redirects packetdrill's TUN read/write to stack rx/tx hooks, and provides a **synchronous socket-shim wrapper** that drives `dpdk_net_poll` internally to fake blocking-syscall semantics for `connect`/`write`/`read`/`close`. With Stage 1's byte-stream API, `write` maps straight to `dpdk_net_send` and `read` maps to a wait-loop over `DPDK_NET_EVT_READABLE`.
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

`tcpreq` probes a TCP endpoint (typically a server) for conformance. Since `dpdk_net` is client-only in production, this layer requires the **stage-1 loopback-test-server** (see §10.12): a minimal server-side build of the stack behind a cargo feature flag, used only by the test harness. `tcpreq` is pointed at the loopback server and produces a pass/fail table aligned to RFC 793bis / RFC 9293 requirements (checksum validation, RST processing, MSS, illegal/unknown option handling). Output feeds the RFC compliance matrix automatically.

Client-side conformance is covered indirectly by packetdrill-shim scripts that assert on the SYN/ACK/options *we emit* given specific peer behaviors.

### 10.4 Layer D — TTCN-3 via intel/net-test-suites

Black-box mode for bring-up; white-box mode (JSON protocol) when enough internal hooks exist for state assertions.

### 10.5 Layer E — Differential fuzzing via TCP-Fuzz

- `github.com/zouyonghao/TCP-Fuzz` in differential mode: identical packet+syscall sequences fed to `libdpdk_net` and Linux TCP; divergence is a bug.
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
Producer(strategy) ─► [lcore: dpdk_net stack]  ─┐
                                                 ├─► exchange testnet
Producer(strategy) ─► [kernel Linux socket   ]  ─┘
```

- Inbound market data replayed from a captured pcap via fan-out to both stacks, preserving inter-arrival timing via HW timestamping.
- Identical outbound order sequences.
- Comparison: wire-level captures via **hardware tap** (NOT switch mirror port; tap insertion jitter <100ns documented and quantified via a loopback calibration run before each comparison session); end-to-end `tx_req → rx_resp` latency distributions (p50/p99/p999/max) per exchange; retransmit rate, dup-ACK rate, SACK-block usage; send-window utilization vs RTT.
- Measurement protocol: tap jitter baseline is subtracted from measured deltas; reported latency parity is `(dpdk_net_p999 − Linux_p999) − tap_jitter_p999`.
- Pass gate: `dpdk_net` p999 latency ≤ Linux p999 latency (after jitter subtraction) on all tested venues; zero RFC-conformance deltas from replay through the packetdrill shim.

### 10.8 Layer H — WAN-condition fault injection (Stage 2 hardening)

Via `tc netem` on an intermediate Linux box inline between stack NIC and exchange:
- Delay: +20ms, +50ms, +200ms, jittered.
- Loss: 0.1% / 1% / 5% random, 1% correlated bursts.
- Duplication, reordering (3-segment depth), corruption.
- PMTU blackholing (drop ICMP frag-needed) — **Stage 2 scenario only**; requires PLPMTUD (RFC 8899)-style recovery, which is not in Stage 1 scope. Stage 1 relies on ICMP-driven PMTUD (RFC 1191) and degrades gracefully to the configured MSS when ICMP is dropped.
- Asserts: no stuck connections, no unbounded retransmit, state transitions remain valid, counters show the expected signals.

### 10.9 Layer I — Online shadow mode (Stage 2 hardening)

Run `dpdk_net` alongside the Linux-stack path in production. The application mirrors the same byte-stream workload onto both stacks (application-side responsibility). Gate promotion on zero byte-stream divergence and p99/p999 latency parity for 7 days.

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

### 10.13 Per-phase mTCP comparison review (Stage 1 process gate)

Every Stage 1 phase from A2 onward ends with a comparison review against mTCP as a mature userspace-TCP reference implementation. Scope is algorithm/correctness parity and edge-case parity (explicitly *not* architecture parity — our RTC model, epoll-like API, and Rust type system are deliberately unlike mTCP's). Phase A1 is exempt because it ships no algorithmic code.

- **Source of truth:** `github.com/mtcp-stack/mtcp` added as a git submodule at `third_party/mtcp/`, pinned to a specific SHA recorded in each review report.
- **Mechanism:** a project-local subagent at `.claude/agents/mtcp-comparison-reviewer.md` performs the comparison and emits `docs/superpowers/reviews/phase-aN-mtcp-compare.md` in a fixed schema (Must-fix / Missed edge cases / Accepted divergence / FYI / Verdict).
- **Gate:** the `phase-aN-complete` git tag cannot be placed while any unresolved `[ ]` checkbox remains in the report's Must-fix or Missed-edge-cases sections, and every Accepted-divergence entry must carry a concrete spec-section or memory-file citation.
- **Invocation:** each phase's sign-off task lists the review as an explicit step before the commit + tag step. Inputs to the subagent are the phase number, the phase plan path, the phase-scoped git diff, the spec §refs the phase claims to cover, and the mTCP focus areas (specific `mtcp/src/*.c` files corresponding to this phase's functionality).

### 10.14 Per-phase RFC compliance review (Stage 1 process gate)

A second review gate, parallel to §10.13, verifies each phase's implementation against the specific RFC clauses the phase claims to cover. Effective from **Phase A3 onward** — the gate was added after A2 shipped, so A2 is exempt (A2's mTCP gate ran; its RFC review is deferred or folded into a one-time retroactive check at A3 kickoff at the user's discretion). Scope is MUST/SHALL violations (→ Must-fix), SHOULDs not covered by the spec §6.4 deviation allowlist (→ Missing-SHOULD), and accepted deviations for §6.4 entries (→ Accepted-deviation). Informational RFC notes and clauses deferred to later phases go under FYI.

- **Source of truth:** RFC text files vendored in `docs/rfcs/rfcNNNN.txt`, fetched once via `scripts/fetch-rfcs.sh` and committed in-tree. Citations are stable line refs into these files; the reviewer does not fetch RFCs from the network. Obsoleted RFCs (793, 1323, 2581) are kept for historical reference; the reviewer prefers the current RFC in each pair unless a specific clause only exists in the older one.
- **Mechanism:** a project-local subagent at `.claude/agents/rfc-compliance-reviewer.md` performs the check and emits `docs/superpowers/reviews/phase-aN-rfc-compliance.md` in a schema matching §10.13's (Must-fix / Missing-SHOULD / Accepted-deviation / FYI / Verdict).
- **Scope bounding:** the reviewer uses the phase plan's "Spec reference" line and the spec §6.3 RFC matrix as the checklist, not an end-to-end RFC read. Clauses scoped to later phases are not flagged.
- **Gate:** identical rule to §10.13 — the `phase-aN-complete` git tag is blocked while any unresolved `[ ]` item remains in Must-fix or Missing-SHOULD, and each Accepted-deviation entry must cite a concrete line in spec §6.4.
- **Invocation:** each phase's sign-off task runs this review as a separate step after the mTCP review and before the roadmap-update / commit / tag steps.

## 11. Benchmark Plan

Goal: quantify latency and stability under trading-representative workloads, catch regressions per-commit, and establish defensible comparisons against Linux TCP as the reference baseline. Performance is verified separately from correctness (§10) — both must pass for a stage ship.

### 11.1 Measurement discipline

Measurements are meaningless without a pinned-down environment. Every benchmark run records and asserts the following preconditions:

- CPU: `isolcpus` covering every engine lcore and every measurement-core. `nohz_full` on those lcores. `rcu_nocbs` for the same set. No IRQ affinity on benchmark cores. Governor = `performance`, no C-states below C1 (`intel_idle.max_cstate=1`), turbo documented (fixed frequency preferred for reproducibility).
- NIC: interrupt coalescing off; TSO/LRO off; RSS enabled; HW timestamping on **when the PMD registers the `rte_dynflag_rx_timestamp` dynfield** — on the Stage 1 ENA deployment target (§8.3) it does not, so wire-RTT attribution in §11.3 uses the TSC-at-`rx_burst` capture via `enqueued_ts_ns` instead of NIC timestamps; flow-control off on the trading link. Offload set: the Tier 1 offloads per §8.4 are **on** (LLQ, TX/RX IPv4+TCP+UDP checksum, MBUF_FAST_FREE); software-fallback paths are exercised separately in the A-HW capability-gated bring-up test run.
- Memory: 2MiB or 1GiB huge pages for DPDK mempools; numa-local mempool/lcore binding asserted at engine_create.
- Clock: TSC invariant (§7.5 precondition). `rdtsc` baseline measured per-host.
- Kernel: non-PREEMPT_RT baseline; thermal throttling events logged by `turbostat` during the run — any throttle invalidates the run.
- Build: release profile with `-C target-cpu=native -C codegen-units=1 -C lto=fat`; symbols kept for `perf`.

Each benchmark's reporting table includes the host, DPDK version, kernel, NIC+firmware, and CPU model. Runs that don't match the pinned config are rejected at analysis time, not just flagged.

### 11.2 Microbenchmarks (cargo-criterion, statistical)

Each measures one unit of work in isolation; target is the function call cost, not end-to-end latency. Reported as median and p99 with bootstrap confidence intervals.

| Benchmark | What it measures | Expected order of magnitude |
|---|---|---|
| `bench_poll_empty` | `dpdk_net_poll` iteration with no RX and no timers | tens of ns |
| `bench_poll_idle_with_timers` | `dpdk_net_poll` iteration with `tcp_tick` walking an empty wheel bucket | tens of ns |
| `bench_tsc_read_ffi` | `dpdk_net_now_ns` via FFI | ~5 ns |
| `bench_tsc_read_inline` | `dpdk_net_now_ns_inline` (header-inline) | ~1 ns |
| `bench_flow_lookup_hot` | 4-tuple hash lookup, all connections hot in cache | ~40 ns |
| `bench_flow_lookup_cold` | 4-tuple hash lookup, flow-table cacheline flushed | ~200 ns |
| `bench_tcp_input_data_segment` | `tcp_input` for a single in-order data segment, PAWS+SACK enabled | ~100-200 ns |
| `bench_tcp_input_ooo_segment` | `tcp_input` for an out-of-order segment that fills a hole | ~200-400 ns |
| `bench_send_small` | `dpdk_net_send` of 128 bytes (fits single mbuf) | ~150 ns |
| `bench_send_large_chain` | `dpdk_net_send` of 64KiB (mbuf chain) | ~1-5 µs |
| `bench_timer_add_cancel` | `dpdk_net_timer_add` followed by `dpdk_net_timer_cancel` | ~50 ns |
| `bench_counters_read` | `dpdk_net_counters` + read of all counter groups | ~100 ns |

### 11.3 End-to-end latency benchmarks (`tools/bench-e2e`)

Run against the loopback-test-server (same-host) and against a dedicated peer on a cross-cable link.

- **Request-response RTT** (single connection, single outstanding): `send N bytes → recv N bytes` round-trip. Histogram reported as p50/p90/p99/p999/max.
- **HW-timestamp attribution** (when `rx_hw_ts_ns` is available — see §7.5 dynfield-lookup): for each measurement, record `rx_hw_ts_ns` minus `tx_sched_ts_ns` (wire RTT); record `enqueued_ts_ns` minus `rx_hw_ts_ns` (stack RX cost); record `user_return_ns` minus `enqueued_ts_ns` (event-handler cost in the user's poll loop); record `tx_burst_ns` minus `user_send_ns` (stack TX cost). These attribution buckets sum to the wall-clock RTT — the sum identity is asserted per-measurement (any mismatch invalidates the run).
- **TSC-only attribution fallback** (when `rx_hw_ts_ns == 0`, which is the production case on ENA — §8.3): the wire-RTT bucket collapses into the "stack RX cost" bucket because we cannot separate "wire + RX IRQ handling" from "PMD → rx_burst return". The attribution buckets reduce to: `tx_sched → enqueued` (wire + full RX), `enqueued → user_return` (event-handler cost), `user_send → tx_burst` (stack TX cost). The sum identity still holds and is still asserted per-measurement. Reports explicitly tag which attribution model was active so numbers from HW-TS and TSC-only hosts are never silently averaged.
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
| Receiver zero-window stall then recovery | time to resume | `DPDK_NET_EVT_WRITABLE` fires within 1 RTT of window open |
| Send-buffer-full under slow peer | backpressure signaling | `dpdk_net_send` returns partial; `WRITABLE` fires on drain |

### 11.5 Comparative benchmarks vs. Linux TCP

Same hardware, same traffic, two stacks. Linux run uses `AF_PACKET` mmap sockets (best-effort user-space delivery) and a standard `connect`/`send`/`recv` socket path; both recorded separately.

- RTT distribution comparison at p50/p99/p999 across idle, loss, and reorder conditions.
- Connection-establishment time (SYN to `CONNECTED` event) distribution.
- Time-to-first-byte on fresh connections.
- Wire-level behavior equivalence when `dpdk_net` is in RFC-compliance preset (`cc_mode=reno`, delayed-ACK on, `minRTO=200ms`): segment-level diff via `pcap` capture should be byte-identical on identical inputs.

Publish as "latency at 95% confidence interval, dpdk_net vs. Linux, N=100k measurements per bucket" with machine-readable CSV output so the comparison is reproducible.

### 11.5.1 Comparative benchmark vs. mTCP (burst throughput on reused connections)

Same hardware, same peer, two userspace DPDK stacks. Workload is a persistent connection reused across many bursts, each burst being a block of bytes pushed as fast as the stack will send them — the pattern market-data replay and order-batch flows produce.

Workload grid (product = 20 buckets):
- One connection per lcore, established once, reused for the whole run.
- Burst size K ∈ {64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB} — spans short-burst to near-continuous regimes.
- Idle gap G ∈ {0 ms (back-to-back), 1 ms, 10 ms, 100 ms} — G=0 collapses to sustained-flow, cross-checks §11.5.2.
- Each burst is K bytes in MSS-sized segments; peer is the §11.5 kernel-side TCP sink (receives + ACKs, no echo).
- `cc_mode=off` on both stacks (comparison axis is the fast-path stack, not congestion control); documented in CSV header.

Measurement contract (identical instrumentation on both stacks):
- `t0` = inline TSC read immediately before the first `dpdk_net_send` / `mtcp_write` of the burst.
- `t1` = NIC HW TX timestamp on the **last segment** of the burst (read from `rte_mbuf::tx_timestamp` once the burst drains).
- `throughput_per_burst = K / (t1 − t0)`. One sample per burst; aggregate into p50/p99/p999.
- Secondary decomposition: `t_first_wire` = HW TX timestamp on segment 1 → `initiation = t_first_wire − t0`, `steady = K / (t1 − t_first_wire)`. Surfaces whether we are losing on spin-up or sustained rate.
- Warmup: first 100 bursts per bucket discarded (mempool cold, cache cold, TSC settle).
- Pre-run checks (bucket invalid and must be re-run if any fail): peer's advertised receive window ≥ K so we aren't measuring peer-window stall; identical MSS (1460) and TX burst size on both stacks; achieved rate stays ≤ 70% of NIC max pps/bps so we aren't NIC-bound; §11.1 measurement-discipline check green.
- Sanity invariant checked at run end: `sum_over_bursts(K) == stack_tx_bytes_counter`. Divergence = the harness is lying about what it sent.

Aggregation: p50, p99, p999 of `throughput_per_burst` across ≥10k bursts per bucket. CSV schema matches §11.5 so `tools/bench-report` feeds it into the same dashboard.

Rationale: mTCP is the natural userspace-DPDK comparator, designed for sustained-flow throughput. The {K, G} grid spans the pattern we actually care about, from short intense bursts through to near-continuous high-rate delivery, and exposes whether `dpdk_net`'s small-connection-count / latency-oriented design concedes meaningful ground on burst throughput.

### 11.5.2 Comparative max sustained throughput vs. mTCP, varied application write size

Complement to §11.5.1: instead of discrete bursts, pump bytes continuously for a fixed wall-time window and measure maximum sustained rate. Exposes per-write overhead vs per-byte cost as a function of application write size — a trading client emitting many small order messages has a very different stack-call shape than one streaming bulk data, and the crossover point between call-cost-bound and byte-cost-bound is a real design parameter.

Workload grid (product = 28 buckets per stack):
- Persistent connection(s); application writes in a tight loop for T = 60 s per bucket post-warmup.
- Application write size W ∈ {64 B, 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB}.
- Connection count C ∈ {1, 4, 16, 64} — 1 isolates per-connection ceiling; 4/16/64 measure aggregate under lcore contention.
- Peer: the §11.5.1 kernel-side TCP sink.
- Same `cc_mode=off`, same MSS, same TX burst size, same pre-run checks as §11.5.1.

Measurement:
- Primary metric: sustained goodput = `(bytes ACKed in [t_warmup_end, t_warmup_end + T]) / T`, in bytes/sec, per (W, C) bucket.
- Secondary: packet rate = `segments_tx_counter_delta / T` — small-W buckets are pps-limited, not bps-limited, and reporting both makes the limit explicit.
- Warmup: 10 s pumping before the measurement window starts.
- Sanity invariant: ACKed bytes during window == `stack_tx_bytes_counter_delta` during window (minus any bytes still in-flight at `t_end`, bounded by cwnd + rwnd).

Rationale: small W tests per-call overhead (FFI dispatch, flow-table lookup, send-coalescing logic); large W tests per-byte cost (mbuf-chain setup, segmentation, header pseudo-checksum). The curve W → goodput(W) localizes where we're spending budget and whether the cross-over sits in a worse place than mTCP's. The C axis lets us tell "one hot connection" from "aggregate under contention," which for our workload profile (small connection count) are different questions with different answers.

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
- `tools/bench-vs-linux` — dual-stack comparison harness vs Linux TCP (reuses `tools/ab-bench` from §10.11).
- `tools/bench-vs-mtcp` — dual-stack comparison harness vs mTCP, two sub-workloads: `burst` (§11.5.1 burst-throughput grid) and `maxtp` (§11.5.2 sustained-throughput sweep by write size and connection count). mTCP built from `third_party/mtcp/` (already a submodule for the §10.13 review gate).
- `tools/bench-report` — converts CSV outputs into shareable tables, feeds the dashboard.

### 11.9 Stage gates tied to benchmarks

- **Stage 1 ship**: §11.2 microbenchmarks meet order-of-magnitude targets; §11.3 e2e p999 latency on loopback is within a small constant (documented) of the idle HW-timestamp RTT; §11.4 stress scenarios all pass criteria; no regression vs. first-merge baseline.
- **Stage 2 (hardening) ship**: §11.5 comparative benchmarks show `dpdk_net` p999 ≤ Linux p999 under all tested conditions; PMU counters within acceptable deltas from the Stage-1 baseline.

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
