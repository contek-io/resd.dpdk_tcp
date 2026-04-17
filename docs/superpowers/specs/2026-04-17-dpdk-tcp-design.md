# resd.dpdk_tcp — Design Spec

Date: 2026-04-17
Status: Draft, pending user approval

## 1. Purpose and Scope

`resd.dpdk_tcp` is a DPDK-based userspace network stack implemented in Rust and exposed to C++ applications via a stable C ABI. It is purpose-built for low-latency trading infrastructure: a trading strategy process connects to a small number (≤100) of exchange venues over REST (HTTP/1.1) and WebSocket, both carried on TCP/TLS. The stack runs alongside user application code on the same DPDK lcore in a run-to-completion loop, with no cross-lcore rings on the hot path.

Non-goals: server-side TCP in production, IPv6, HTTP/2, HTTP/3, WebSocket compression, TCP Fast Open, sophisticated congestion control by default, millions of connections, kernel-compatible socket emulation.

### 1.1 Design tenets

- **Latency over throughput**: defaults favor low latency even when they diverge from RFC-recommended behavior. Any aggregation feature is opt-in.
- **Stability is a first-class feature**: safe languages, memory-correct parsers, small attack surface, WAN-tested under induced loss/reorder.
- **Observability through primitives, not framework**: stack exports raw counters, timestamps on every event, and state-change events. Aggregation (histograms, tracing, export endpoints) happens in the application using existing infrastructure.
- **RFC behavior is tested, not claimed**: conformance is proved by running opensource RFC-conformance suites against the stack; anything unclear is resolved by referring to the RFC.
- **Flexible API**: epoll-like pull model for stage 1, callback-style can layer on top later.

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
  │    engine lifecycle, connection, HTTP, (TLS), (WS), poll, timers│
  │                                                                  │
  │  Per-lcore engine (run-to-completion loop):                     │
  │    rx_burst → ip → tcp → tls → http/ws → user callback          │
  │                                        ↓                         │
  │                                 user sends →  http/ws → tls      │
  │                                              → tcp → tx_burst    │
  │                                                                  │
  │  Modules:                                                        │
  │    l2/l3/ip, tcp, tls (rustls), http/1.1, ws/rfc6455,           │
  │    flow table, timers, mempools, observability-primitives        │
  └──────────────────────────────┬──────────────────────────────────┘
                                 │ DPDK EAL, PMD, mempool (DPDK 23.11)
                                 ▼
                           NIC (SR-IOV VF / PF)
```

### 2.1 Phases

- **Stage 1 (MVP)**: IPv4 + TCP + HTTP/1.1 + epoll-like API + observability primitives. No TLS, no WebSocket. End-to-end gate: place an order against a staging exchange over plaintext HTTP/1.1.
- **Stage 2**: Inline TLS 1.3 (rustls with `aws-lc-rs` backend); TLS 1.2 behind a feature flag for legacy venues.
- **Stage 3**: WebSocket (RFC 6455) client. Client-initiated close, client-side masking, ping/pong autoreply. No `permessage-deflate`.
- **Stage 4**: Hardening — WAN A/B harness, fuzz-at-scale, documented RFC compliance matrix, shadow-mode deployment.

### 2.2 Build / language / FFI

- Rust workspace, `cargo` build, pinning DPDK LTS 23.11 via `bindgen`.
- `cbindgen` generates `resd_net.h` for C++ consumers.
- Public API uses `extern "C"` with primitive / opaque-pointer types only — no Rust-only types leak.
- C++ integration sample ships as a test consumer.

## 3. Threading and Runtime Model

- **One engine per lcore.** Caller pins itself to an lcore before calling `resd_net_engine_create(lcore_id, &cfg)`.
- **User code lives on the same lcore as the stack.** Run-to-completion: the user's event loop repeatedly calls `resd_net_poll`, which runs rx_burst → stack → emits events → user handles events inline → user-initiated sends batch into the next tx_burst.
- **No cross-lcore rings on the hot path.** Connections are pinned to lcores at `connect()` time; the application chooses the assignment.
- **Typical deployment**: one lcore per market-data feed (high-pps inbound WebSocket), one lcore for order entry (few latency-critical REST/WS connections), plus strategy/business-logic cores communicating with the stack lcores via the application's own existing mechanisms.

## 4. Public API (Stage 1)

```c
/* ===== Engine ===== */
typedef struct resd_net_engine resd_net_engine_t;

typedef struct {
    uint16_t port_id;
    uint16_t rx_queue_id;
    uint16_t tx_queue_id;
    uint32_t max_connections;      /* sized ≥ expected, e.g. 16 */
    uint32_t recv_buffer_bytes;    /* per-conn; default 256KiB */
    uint32_t send_buffer_bytes;    /* per-conn; default 256KiB */
    uint32_t tcp_mss;              /* 0 = derive from PMTUD */
    bool     tcp_timestamps;       /* RFC 7323, default true */
    bool     tcp_sack;             /* RFC 2018, default true */
    bool     tcp_ecn;              /* RFC 3168, default false */
    uint8_t  cc_mode;              /* 0=off (default), 1=reno, 2=cubic (later) */
    bool     tcp_per_packet_events; /* emit RESD_NET_EVT_TCP_RETRANS etc. per packet;
                                       state-change and alert events are always emitted
                                       regardless of this flag. default false */
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
int resd_net_close(resd_net_engine_t*, resd_net_conn_t);
int resd_net_shutdown(resd_net_engine_t*, resd_net_conn_t, int how);

/* ===== HTTP/1.1 ===== */
typedef struct {
    const char*     method;
    const char*     path;
    const char*     host;
    const resd_net_header_t* headers;
    uint32_t        headers_count;
    const uint8_t*  body;                /* borrowed until resd_net_poll returns */
    uint32_t        body_len;
} resd_net_http_request_t;

int resd_net_http_request(resd_net_engine_t*,
                          resd_net_conn_t,
                          const resd_net_http_request_t*,
                          uint64_t* req_id_out);

/* ===== Poll ===== */
typedef enum {
    RESD_NET_EVT_CONNECTED = 1,
    RESD_NET_EVT_CLOSED,
    RESD_NET_EVT_ERROR,
    RESD_NET_EVT_HTTP_RESPONSE_HEAD,
    RESD_NET_EVT_HTTP_RESPONSE_BODY,
    RESD_NET_EVT_HTTP_RESPONSE_DONE,
    RESD_NET_EVT_TIMER,
    RESD_NET_EVT_TCP_RETRANS,          /* stability-visibility events */
    RESD_NET_EVT_TCP_LOSS_DETECTED,
    RESD_NET_EVT_TCP_STATE_CHANGE,
    RESD_NET_EVT_TLS_ALERT,            /* stage 2+ */
} resd_net_event_kind_t;

typedef struct {
    resd_net_event_kind_t kind;
    resd_net_conn_t       conn;
    uint64_t              req_id;
    uint16_t              http_status;
    const resd_net_header_t* headers;
    uint32_t              headers_count;
    const uint8_t*        data;            /* borrowed; valid until next poll */
    uint32_t              data_len;
    uint64_t              rx_hw_ts_ns;     /* NIC HW timestamp when available */
    uint64_t              enqueued_ts_ns;  /* TSC when event entered user-visible form */
    int32_t               err;
} resd_net_event_t;

int resd_net_poll(resd_net_engine_t*,
                  resd_net_event_t* events_out,
                  uint32_t max_events,
                  uint64_t timeout_ns);

void resd_net_flush(resd_net_engine_t*);   /* force rte_eth_tx_burst now */

/* ===== Timers & clock ===== */
uint64_t resd_net_now_ns(resd_net_engine_t*);
int      resd_net_timer_add(resd_net_engine_t*, uint64_t deadline_ns, uint64_t user_data);
int      resd_net_timer_cancel(resd_net_engine_t*, uint64_t timer_id);

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
            resd_net_http_request(engine, conn, &req, &req_id);
            resd_net_flush(engine);
            break;
        case RESD_NET_EVT_HTTP_RESPONSE_DONE:
            process_fill(events[i].data, events[i].data_len);
            break;
        }
    }
}
```

### 4.2 API contracts

- `req_id` lets the caller pipeline multiple requests and match responses without ordering assumptions.
- Headers and body pointers in events are **borrowed views** into mbuf memory, valid until the next `resd_net_poll`. Caller must copy for longer lifetime.
- `resd_net_flush` is the latency knob: call it after a latency-critical send inside an event handler to invoke `rte_eth_tx_burst` immediately rather than waiting for end-of-poll batching.

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
        tcp_input(conn, pkt);
        /* stage 2+: tls_input(conn) decrypts into conn->recv_plaintext */
        http_input(conn);              /* parse, emit events */
        user_callback(conn, event);    /* user may call resd_net_send_* inline */
    }
    tcp_tick(now);                     /* retransmit, RTO, TLP, keepalive, delayed-ACK-off-by-default */
    n = rte_eth_tx_burst(port, q, tx_mbufs, tx_count);
}
```

### 5.2 `resd_net_send` call chain (synchronous, in-line)

```
resd_net_http_request
  → http1_encode    (writes request into mbuf at reserved headroom offset)
  → tls_write       (stage 2+; rustls writes record directly into mbuf)
  → tcp_output      (segment to MSS, prepend TCP hdr in reserved headroom,
                     track for retransmit via mbuf refcount)
  → ip_output       (prepend IP + eth hdrs in reserved headroom)
  → push to TX batch (flushed at end of poll iter, or immediately on flush())
```

### 5.3 Buffer ownership

- RX mbufs owned by stack; delivered to user as `&[u8]` view; user copies if they need longer lifetime.
- TX mbufs allocated from per-lcore mempool, filled bottom-up with pre-reserved headroom for eth+IP+TCP+TLS-record headers, pushed to next tx_burst.
- Retransmit queue holds mbuf pointers with bumped refcount; on ACK the ref drops and the mbuf returns to the mempool. Retransmit reuses the same mbuf (with small in-place edit of the timestamp option if RFC 7323 is enabled).

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
| 815 | Reassembly | deferred | stub returns ICMP frag-needed |
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
| 6528 | ISS generation | yes | SipHash(4-tuple \|\| secret \|\| boot_nonce \|\| monotonic_time) |
| 5961 | Blind-data-attack mitigations | yes | challenge-ACK on out-of-window seqs |
| 7413 | TCP Fast Open | **NO** | not useful for long-lived connections |

### 6.4 Deviations from RFC defaults (by design, for trading latency)

| Default | RFC stance | Our default | Rationale |
|---|---|---|---|
| Delayed ACK | RFC 1122 SHOULD | **off** | 200ms ACK delay is catastrophic for trading; per-burst natural coalescing gives efficiency without latency cost |
| Nagle (`TCP_NODELAY` inverse) | RFC 896 | **off** | user sends complete requests; coalescing is their choice |
| TCP keepalive | optional | **off** | exchanges close idle; application heartbeats are preferred |
| minRTO | RFC 6298 RECOMMENDS 1s | **20ms** (tunable) | intra-region WAN RTT is 1–10ms |
| Congestion control | RFC 5681 MUST | **off-by-default** | ≤100 connections, well-provisioned WAN; Reno available behind `cc_mode` for A/B-vs-Linux and RFC-compliance modes |
| PermitTFO (RFC 7413) | optional | **disabled** | long-lived connections don't benefit; adds 0-RTT security complexity |

### 6.5 Implementation choices

- **Flow table**: flat `Vec<Option<TcpConn>>` indexed by handle id + a hash map `(4-tuple) → handle` for RX lookup. Linear scan would be acceptable at ≤16 connections; hash is free.
- **Segment-level mbuf tracking**: every TX segment holds an mbuf refcount until ACK or RST. Retransmit reuses the same mbuf (with in-place timestamp-option edit when RFC 7323 is on).
- **ISS**: SipHash of `(4-tuple || secret || boot_nonce || monotonic_time)` — RFC 6528.
- **SYN retransmit**: 3 attempts, exponential from 1s.
- **TIME_WAIT shortening**: allow skipping TIME_WAIT for reconnect to the same peer when the user requests it via `resd_net_close(..., FORCE_TW_SKIP)`; default obeys RFC.

## 7. Memory and Buffer Model

### 7.1 Mempools (per-lcore, no cross-lcore allocation)

```
rx_mempool       : 2× NIC rx ring size × max_lcores
                   MBUF_SIZE = 2048 + RTE_PKTMBUF_HEADROOM(192)
                   HEADROOM sized for eth(14) + ip(20..60) + tcp(20..60) + tls_rec(5..21)
tx_hdr_mempool   : small mbufs for ACK-only / RST / control
tx_data_mempool  : large mbufs for request bodies
timer_mempool    : fixed-object pool for timer nodes
```

### 7.2 Per-connection buffers

- `recv_reorder`: out-of-order segment list, each element holds `(seq_range, mbuf_ref)`. Merged into `recv_contig` as gaps fill. Capped at `recv_buffer_bytes`.
- `recv_contig`: in-order mbuf chain ready for HTTP parser.
- `snd_retrans`: `(seq, mbuf_ref, first_tx_ts)` list. Capped at `send_buffer_bytes`.
- `tls_conn` (stage 2+): `rustls::ClientConnection` with `aws-lc-rs` backend; vectored AEAD reads/writes point at mbuf data.

### 7.3 Zero-copy path

```
RX:  NIC DMA → mbuf.data → rustls.read_tls(&mbuf.data)
                            → plaintext mbuf chain
                              → HTTP parser &plaintext_mbuf.data
                                → user &event.data

TX:  &user_bytes → http_encode writes into tx mbuf at headroom
                   → rustls.write_tls(&mut tx_mbuf) encrypts in-place
                     → tcp_output prepends TCP hdr in reserved headroom
                       → ip_output prepends IP+eth in reserved headroom
                         → NIC DMA reads mbuf.data
```

Only unavoidable copy on the TX path: user body bytes into the TX mbuf at `resd_net_http_request` time. On RX, reassembly may copy only if the HTTP parser needs a contiguous view crossing an mbuf boundary — empirically rare with 1500/9000 MTU and typical REST responses.

### 7.4 Timer wheel

- Hashed timing wheel, 8 levels × 256 buckets, per-lcore arena.
- Resolution: 10 µs. Horizon: ~68 s. Longer timers (2×MSL=60s) demoted to higher-level wheel.
- Timers checked at the start and after rx_burst in each `resd_net_poll` iteration.

### 7.5 Clock

- TSC-based, calibrated once at engine startup against `CLOCK_MONOTONIC_RAW`. `resd_net_now_ns` returns `(tsc - tsc0) * ns_per_tsc + t0`.
- NIC hardware timestamp captured from mbuf's `timestamp` dyn-field when `PTYPE_HWTIMESTAMP` is set; surfaced to users as `rx_hw_ts_ns`.

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

Per-lcore struct of `u64` counts, cacheline-grouped, lock-free-readable via:

```c
const resd_net_counters_t* resd_net_counters(resd_net_engine_t*);
```

Counter groups: `eth`, `ip`, `tcp`, `tls` (stage 2+), `http`, `poll`. Examples in `eth`: `rx_pkts`, `rx_bytes`, `rx_drop_miss_mac`, `tx_pkts`, `tx_bytes`, `tx_drop_full_ring`. In `tcp`: `rx_syn_ack`, `rx_data`, `rx_out_of_order`, `tx_retrans`, `tx_rto`, `tx_tlp`, `state_trans[11][11]`, `conn_open`, `conn_close`, `conn_rst`. No atomics — plain increments. Application snapshots by `memcpy` into its own thread-local view.

### 9.2 Timestamps on events

Every `resd_net_event_t` carries:
- `rx_hw_ts_ns` — NIC hardware timestamp (ground truth for RX).
- `enqueued_ts_ns` — TSC when the event entered user-visible form (set inside `resd_net_poll`).

For TX: the HTTP request returns after pushing to the TX batch; the application records its own wall-clock at that moment if it cares. `resd_net_flush` is where the NIC actually sees the packet; applications that want ground-truth TX timing can read `resd_net_now_ns()` immediately before/after flush.

### 9.3 Stability-visibility events

Delivered through the normal `resd_net_poll` interface:
- `RESD_NET_EVT_TCP_RETRANS` — seq, rtx_count.
- `RESD_NET_EVT_TCP_LOSS_DETECTED` — RACK or RTO trigger.
- `RESD_NET_EVT_TCP_STATE_CHANGE` — from/to state.
- `RESD_NET_EVT_TLS_ALERT` (stage 2+) — alert level/description.

State changes and alerts are always emitted. Per-packet TCP trace events are gated by a boolean in `engine_config` so they don't clutter `resd_net_poll` results when not wanted.

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
- Parser tests: HTTP/1.1 encode/decode; malformed inputs (chunked encoding edge cases, header folding, CRLF in values).
- TLS record layer shim tests (stage 2+).
- Timer wheel, flow table, mempool wrappers.

### 10.2 Layer B — RFC conformance via packetdrill (Luna-pattern shim)

- `tools/packetdrill-shim`: link against libresd_net, redirect packetdrill's TUN read/write to stack rx/tx hooks. Packetdrill syscalls (`connect`, `write`, `close`) map to `resd_net_*`.
- Run these corpora:
  - `github.com/ligurio/packetdrill-testcases` — ~1,500 cases, RFC 793/761/4413.
  - `github.com/shivansh/TCP-IP-Regression-TestSuite` — FreeBSD regression suite.
  - `github.com/google/packetdrill` upstream — TCP FSM and options.
  - Our scripts for RFC 7323 PAWS edge cases, RFC 2018 SACK reneging / out-of-order SACK blocks, RFC 8985 RACK reorder detection and TLP trigger, RFC 5961 challenge-ACK.

### 10.3 Layer C — RFC 793bis MUST/SHOULD via tcpreq

Run `github.com/TheJokr/tcpreq` against the stack. Produces pass/fail table aligned to RFC 793bis / RFC 9293 requirements (checksum validation, RST processing, MSS, illegal/unknown option handling). Output feeds the RFC compliance matrix automatically.

### 10.4 Layer D — TTCN-3 via intel/net-test-suites

Black-box mode for bring-up; white-box mode (JSON protocol) when enough internal hooks exist for state assertions.

### 10.5 Layer E — Differential fuzzing via TCP-Fuzz

- `github.com/zouyonghao/TCP-Fuzz` in differential mode: identical packet+syscall sequences fed to `libresd_net` and Linux TCP; divergence is a bug.
- This operationalizes the "A/B vs Linux" goal at fuzz time rather than prod time — earlier and cheaper signal.
- TCP-Fuzz history: 56 bugs across TLDK/F-Stack/mTCP/FreeBSD/Linux; 48 semantic (RFC violations) that sanitizers would miss.
- CI: smoke run per merge. 72h continuous run per stage cut.

### 10.6 Layer F — Property / bespoke fuzzing

- `proptest`: round-trip identities on HTTP, TLS records (stage 2+), TCP options.
- `cargo-fuzz` / libFuzzer targets: HTTP response parser (seeded from real exchange captures), `tcp_input` with random pre-established state and arbitrary bytes (invariants: no panics, no UB, `snd.una ≤ snd.nxt`, rcv window monotonic), rustls + mbuf glue (stage 2+).
- `scapy` for adversarial hand-crafted packets: overlapping segments, malformed options, port-reuse races, timestamp wraparound.
- `smoltcp`'s `FaultInjector` pattern ported in: stackable RX-path middleware that randomly drops/duplicates/reorders/corrupts with configurable rates, enabled via env var for local soak-testing without netem.

### 10.7 Layer G — WAN A/B vs Linux (stage 4)

```
Producer(strategy) ─► [lcore: resd_net stack]  ─┐
                                                 ├─► exchange testnet
Producer(strategy) ─► [kernel Linux socket   ]  ─┘
```

- Inbound market data replayed from a captured pcap via fan-out to both stacks, preserving inter-arrival timing via HW timestamping.
- Identical outbound order sequences.
- Comparison: wire-level captures at mirror ports; end-to-end `tx_req → rx_resp` latency distributions (p50/p99/p999/max) per exchange; retransmit rate, dup-ACK rate, SACK-block usage; send-window utilization vs RTT.
- Pass gate: `resd_net` p999 latency ≤ Linux p999 latency on all tested venues; zero RFC-conformance deltas from replay through the packetdrill shim.

### 10.8 Layer H — WAN-condition fault injection (stage 4)

Via `tc netem` on an intermediate Linux box inline between stack NIC and exchange:
- Delay: +20ms, +50ms, +200ms, jittered.
- Loss: 0.1% / 1% / 5% random, 1% correlated bursts.
- Duplication, reordering (3-segment depth), corruption.
- PMTU blackholing (drop ICMP frag-needed; force stack to detect via RTO + MSS probe).
- Asserts: no stuck connections, no unbounded retransmit, state transitions remain valid, counters show the expected signals.

### 10.9 Layer I — Online shadow mode (stage 4)

Run `resd_net` alongside Linux-stack path in production. Same requests over both. Gate promotion on zero response-body divergence and p99/p999 parity for 7 days.

### 10.10 Stage gates

- **Stage 1 ship**: Layer A 100% unit pass; Layer B ligurio + shivansh passing on TCP FSM subset; Layer C tcpreq MUST rules passing.
- **Stage 2 (TLS) ship**: + rustls fuzz targets; TLS 1.3 interop against an exchange staging endpoint.
- **Stage 3 (WebSocket) ship**: + `crossbario/autobahn-testsuite` passing on client-side tests.
- **Stage 4 (hardening) ship**: + Layers E/G/H passing; 7-day prod shadow with zero response divergence.

### 10.11 Tooling

- `tools/packetdrill-shim` — Luna-pattern adapter.
- `tools/tcpreq-runner` — tcpreq wrapper with RFC-compliance report output.
- `tools/tcp-fuzz-differential` — TCP-Fuzz driver with Linux oracle.
- `tools/replay` — pcap replay preserving HW timestamps.
- `tools/ab-bench` — dual-stack comparison harness + reporting.
- `tools/fuzz-corpus` — shared corpora, auto-updated from production pcaps.

## 11. Out of Scope for Stage 1

- Server-side TCP in production (test-only loopback server behind a feature flag is allowed)
- IPv6 / RFC 2460 / 8200 / 4443 / 4861 / 4862
- HTTP/2 (RFC 9113), HTTP/3 (RFC 9114)
- TLS (moves to Stage 2)
- WebSocket (moves to Stage 3)
- WebSocket `permessage-deflate` (RFC 7692) — not planned for any stage
- TCP Fast Open (RFC 7413)
- Full dynamic ARP state machine (static + gratuitous refresh only)
- DNS resolver on the data path

## 12. Open Questions to Resolve Before Stage 1 Starts

- Specific NIC model and firmware version for the initial target hardware.
- Staging exchange venue for the Stage-1 end-to-end gate.
- Whether Rust nightly is allowed in CI (some DPDK-adjacent crates require it) or whether stable-only is required.
- Ownership of `tools/packetdrill-shim` — fork the packetdrill repo, or vendor it.

## 13. References

- RFC 9293 (TCP, 2022 consolidated), 7323 (timestamps + window scale), 2018 (SACK), 5681 (Reno congestion control), 6298 (RTO), 8985 (RACK-TLP), 5961 (blind-data mitigations), 6528 (ISS), 6691 (MSS), 3168 (ECN), 791/792/815 (IP/ICMP/reassembly), 1122 (host requirements), 1191 (PMTUD), 9110/9112 (HTTP semantics + /1.1).
- mTCP: `github.com/mtcp-stack/mtcp` (reference only, not forked).
- Alibaba Luna userspace TCP + packetdrill adaptation (referenced for the shim pattern).
- Test suites: packetdrill (Google), ligurio/packetdrill-testcases, shivansh/TCP-IP-Regression-TestSuite, TheJokr/tcpreq, intel/net-test-suites, zouyonghao/TCP-Fuzz, smoltcp-rs/smoltcp (for `FaultInjector` pattern), crossbario/autobahn-testsuite.
