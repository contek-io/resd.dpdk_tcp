#ifndef DPDK_NET_H
#define DPDK_NET_H

#pragma once

/* DO NOT EDIT: generated from Rust via cbindgen */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <arpa/inet.h>

#define DPDK_NET_ALIGNED(N) __attribute__((aligned(N)))


/**
 * A6 (spec §3.5): latency preset — all existing config fields honored
 * as-written (post zero-sentinel substitution).
 */
#define DPDK_NET_PRESET_LATENCY 0

/**
 * A6 (spec §3.5): RFC-compliance preset — overrides five fields per
 * parent spec §4: `tcp_nagle`, `tcp_delayed_ack`, `cc_mode`,
 * `tcp_min_rto_us`, `tcp_initial_rto_us`.
 */
#define DPDK_NET_PRESET_RFC_COMPLIANCE 1

/**
 * Close flags — bitmask for dpdk_net_close.
 */
#define DPDK_NET_CLOSE_FORCE_TW_SKIP (1 << 0)

enum dpdk_net_event_kind_t
#ifdef __cplusplus
  : uint32_t
#endif // __cplusplus
 {
  DPDK_NET_EVT_CONNECTED = 1,
  DPDK_NET_EVT_READABLE = 2,
  DPDK_NET_EVT_WRITABLE = 3,
  DPDK_NET_EVT_CLOSED = 4,
  DPDK_NET_EVT_ERROR = 5,
  DPDK_NET_EVT_TIMER = 6,
  DPDK_NET_EVT_TCP_RETRANS = 7,
  DPDK_NET_EVT_TCP_LOSS_DETECTED = 8,
  DPDK_NET_EVT_TCP_STATE_CHANGE = 9,
};
#ifndef __cplusplus
typedef uint32_t dpdk_net_event_kind_t;
#endif // __cplusplus

struct dpdk_net_engine {
  uint8_t _opaque[0];
};

struct dpdk_net_engine_config_t {
  uint16_t port_id;
  uint16_t rx_queue_id;
  uint16_t tx_queue_id;
  uint32_t max_connections;
  uint32_t recv_buffer_bytes;
  uint32_t send_buffer_bytes;
  uint32_t tcp_mss;
  bool tcp_timestamps;
  bool tcp_sack;
  bool tcp_ecn;
  bool tcp_nagle;
  bool tcp_delayed_ack;
  uint8_t cc_mode;
  uint32_t tcp_min_rto_ms;
  uint32_t tcp_min_rto_us;
  uint32_t tcp_initial_rto_us;
  uint32_t tcp_max_rto_us;
  uint32_t tcp_max_retrans_count;
  uint32_t tcp_msl_ms;
  bool tcp_per_packet_events;
  uint8_t preset;
  uint32_t local_ip;
  uint32_t gateway_ip;
  uint8_t gateway_mac[6];
  uint32_t garp_interval_sec;
  /**
   * A5.5 event-queue overflow guard (§3.2 / §5.1). Default 4096;
   * must be >= 64. Queue drops oldest on overflow.
   */
  uint32_t event_queue_soft_cap;
  /**
   * A6 (spec §5.1, §3.8): RTT histogram bucket edges, µs. 15 strictly
   * monotonically increasing edges define 16 buckets. All-zero input
   * means "use the stack's trading-tuned defaults" (see spec §3.8.2).
   * Non-monotonic rejected at `dpdk_net_engine_create` with null-return.
   */
  uint32_t rtt_histogram_bucket_edges_us[15];
  /**
   * M1 — see core `EngineConfig.ena_large_llq_hdr`. Default 0.
   */
  uint8_t ena_large_llq_hdr;
  /**
   * M2 — see core `EngineConfig.ena_miss_txc_to_sec`. Default 0
   * (PMD default 5 s). Recommended 2 or 3 for trading. Do NOT set
   * 0 with the intent of disabling the Tx-completion watchdog —
   * disabling causes severe performance degradation (ENA README
   * §5.1 caution). 0 here specifically means "use PMD default".
   */
  uint8_t ena_miss_txc_to_sec;
  /**
   * A6.6-7 Task 10: RX mempool capacity in mbufs. `0` = compute
   * default at `dpdk_net_engine_create` using:
   *   max(4 * rx_ring_size,
   *       2 * max_connections * ceil(recv_buffer_bytes / mbuf_data_room) + 4096)
   * Assumes `mbuf_data_room == 2048` bytes (DPDK default); jumbo-frame
   * deployments either raise `mbuf_data_room` or set this explicitly.
   * The resolved value is retrievable post-create via
   * `dpdk_net_rx_mempool_size()`. Non-zero caller value is used
   * verbatim (no floor clamp).
   */
  uint32_t rx_mempool_size;
};

typedef uint64_t dpdk_net_conn_t;

/**
 * Scatter-gather view over a received in-order byte range.
 * `base` points into a mempool-backed rte_mbuf data area; the pointer is
 * only valid until the next `dpdk_net_poll` on the same engine.
 *
 * ABI: 16 bytes on 64-bit targets (x86_64, ARM64 Graviton). Not 32-bit
 * compatible — Stage 1 targets are 64-bit only.
 */
struct dpdk_net_iovec_t {
  const uint8_t *base;
  uint32_t len;
  uint32_t _pad;
};

/**
 * READABLE event payload. `segs` points at an engine-owned array of
 * `dpdk_net_iovec_t` with `n_segs` entries. Multi-segment when chained
 * mbufs were received (LRO / jumbo / IP-defragmented); single-segment
 * for standard MTU packets. `total_len = Σ segs[i].len`.
 *
 * Lifetime: `segs` and every `segs[i].base` pointer are only valid
 * until the next `dpdk_net_poll` on the same engine. The engine reuses
 * per-conn scratch for the array; the backing mbufs are refcount-
 * pinned in the connection's `delivered_segments` and released at the
 * next poll iteration.
 */
struct dpdk_net_event_readable_t {
  const struct dpdk_net_iovec_t *segs;
  uint32_t n_segs;
  uint32_t total_len;
};

struct dpdk_net_event_error_t {
  int32_t err;
};

struct dpdk_net_event_timer_t {
  uint64_t timer_id;
  uint64_t user_data;
};

struct dpdk_net_event_tcp_retrans_t {
  uint32_t seq;
  uint32_t rtx_count;
};

struct dpdk_net_event_tcp_loss_t {
  uint32_t first_seq;
  uint8_t trigger;
};

struct dpdk_net_event_tcp_state_t {
  uint8_t from_state;
  uint8_t to_state;
};

/**
 * Union-of-payloads approach: we lay out the union as a byte array and
 * expose accessor helpers. cbindgen emits it as a C union.
 */
union dpdk_net_event_payload_t {
  struct dpdk_net_event_readable_t readable;
  struct dpdk_net_event_error_t error;
  struct dpdk_net_event_error_t closed;
  struct dpdk_net_event_timer_t timer;
  struct dpdk_net_event_tcp_retrans_t tcp_retrans;
  struct dpdk_net_event_tcp_loss_t tcp_loss;
  struct dpdk_net_event_tcp_state_t tcp_state;
  uint8_t _pad[16];
};

struct dpdk_net_event_t {
  dpdk_net_event_kind_t kind;
  dpdk_net_conn_t conn;
  uint64_t rx_hw_ts_ns;
  /**
   * ns timestamp (engine monotonic clock) sampled at event emission
   * inside the stack. Unrelated to `rx_hw_ts_ns`. For packet-triggered
   * events, emission time is when the stack processed the triggering
   * packet, not when the NIC received it — use `rx_hw_ts_ns` for
   * NIC-arrival time. For timer-triggered events (RTO fire, RACK / TLP
   * loss-detected), emission time is the fire instant.
   */
  uint64_t enqueued_ts_ns;
  union dpdk_net_event_payload_t u;
};

/**
 * Counters struct — exposed to application via dpdk_net_counters().
 * Fields are plain u64 on the C ABI for clean cbindgen emission, but
 * internally the stack writes them as AtomicU64 (Relaxed).
 *
 * Cross-platform atomic-load contract: C/C++ readers MUST use the
 * helper in `dpdk_net_counters_load.h`:
 *
 *     uint64_t rx = dpdk_net_load_u64(&counters->eth.rx_pkts);
 *
 * Plain dereference is only atomic on x86_64 with aligned uint64_t.
 * On ARM32 a plain read may tear; ARM64 has weaker ordering semantics
 * than x86. The helper compiles to a plain mov on x86_64 (zero cost)
 * and the correct LDREXD/LDR sequence on ARM.
 */
struct DPDK_NET_ALIGNED(64) dpdk_net_eth_counters_t {
  uint64_t rx_pkts;
  uint64_t rx_bytes;
  uint64_t rx_drop_miss_mac;
  uint64_t rx_drop_nomem;
  uint64_t tx_pkts;
  uint64_t tx_bytes;
  uint64_t tx_drop_full_ring;
  uint64_t tx_drop_nomem;
  uint64_t rx_drop_short;
  uint64_t rx_drop_unknown_ethertype;
  uint64_t rx_arp;
  uint64_t tx_arp;
  uint64_t offload_missing_rx_cksum_ipv4;
  uint64_t offload_missing_rx_cksum_tcp;
  uint64_t offload_missing_rx_cksum_udp;
  uint64_t offload_missing_tx_cksum_ipv4;
  uint64_t offload_missing_tx_cksum_tcp;
  uint64_t offload_missing_tx_cksum_udp;
  uint64_t offload_missing_mbuf_fast_free;
  uint64_t offload_missing_rss_hash;
  uint64_t offload_missing_llq;
  uint64_t offload_missing_rx_timestamp;
  uint64_t rx_drop_cksum_bad;
  uint64_t llq_wc_missing;
  uint64_t llq_header_overflow_risk;
  uint64_t eni_bw_in_allowance_exceeded;
  uint64_t eni_bw_out_allowance_exceeded;
  uint64_t eni_pps_allowance_exceeded;
  uint64_t eni_conntrack_allowance_exceeded;
  uint64_t eni_linklocal_allowance_exceeded;
  uint64_t tx_q0_linearize;
  uint64_t tx_q0_doorbells;
  uint64_t tx_q0_missed_tx;
  uint64_t tx_q0_bad_req_id;
  uint64_t rx_q0_refill_partial;
  uint64_t rx_q0_bad_desc_num;
  uint64_t rx_q0_bad_req_id;
  uint64_t rx_q0_mbuf_alloc_fail;
  uint64_t _pad[2];
};

struct DPDK_NET_ALIGNED(64) dpdk_net_ip_counters_t {
  uint64_t rx_csum_bad;
  uint64_t rx_ttl_zero;
  uint64_t rx_frag;
  uint64_t rx_icmp_frag_needed;
  uint64_t pmtud_updates;
  uint64_t rx_drop_short;
  uint64_t rx_drop_bad_version;
  uint64_t rx_drop_bad_hl;
  uint64_t rx_drop_not_ours;
  uint64_t rx_drop_unsupported_proto;
  uint64_t rx_tcp;
  uint64_t rx_icmp;
  uint64_t _pad[4];
};

struct DPDK_NET_ALIGNED(64) dpdk_net_tcp_counters_t {
  uint64_t rx_syn_ack;
  uint64_t rx_data;
  uint64_t rx_ack;
  uint64_t rx_rst;
  uint64_t rx_out_of_order;
  uint64_t tx_retrans;
  uint64_t tx_rto;
  uint64_t tx_tlp;
  uint64_t conn_open;
  uint64_t conn_close;
  uint64_t conn_rst;
  uint64_t send_buf_full;
  uint64_t recv_buf_delivered;
  uint64_t tx_syn;
  uint64_t tx_ack;
  uint64_t tx_data;
  uint64_t tx_fin;
  uint64_t tx_rst;
  uint64_t rx_fin;
  uint64_t rx_unmatched;
  uint64_t rx_bad_csum;
  uint64_t rx_bad_flags;
  uint64_t rx_short;
  /**
   * Phase A3: bytes peer sent beyond our current recv buffer free_space.
   * See `feedback_performance_first_flow_control.md` — we don't shrink
   * rcv_wnd to throttle the peer; we keep accepting at full capacity and
   * expose pressure here so the application can diagnose a slow consumer.
   */
  uint64_t recv_buf_drops;
  uint64_t rx_paws_rejected;
  uint64_t rx_bad_option;
  uint64_t rx_reassembly_queued;
  uint64_t rx_reassembly_hole_filled;
  uint64_t tx_sack_blocks;
  uint64_t rx_sack_blocks;
  uint64_t rx_bad_seq;
  uint64_t rx_bad_ack;
  uint64_t rx_dup_ack;
  uint64_t rx_zero_window;
  uint64_t rx_urgent_dropped;
  uint64_t tx_zero_window;
  uint64_t tx_window_update;
  uint64_t conn_table_full;
  uint64_t conn_time_wait_reaped;
  /**
   * HOT-PATH, feature-gated by `obs-byte-counters` (default OFF).
   * Per-burst-batched TCP payload byte counters. See core counters.rs.
   */
  uint64_t tx_payload_bytes;
  uint64_t rx_payload_bytes;
  uint64_t state_trans[11][11];
  uint64_t conn_timeout_retrans;
  uint64_t conn_timeout_syn_sent;
  uint64_t rtt_samples;
  uint64_t tx_rack_loss;
  uint64_t rack_reo_wnd_override_active;
  uint64_t rto_no_backoff_active;
  uint64_t rx_ws_shift_clamped;
  uint64_t rx_dsack;
  /**
   * A5.5 Task 11/12 — see core counters.rs for the full field doc.
   */
  uint64_t tx_tlp_spurious;
  uint64_t tx_api_timers_fired;
  uint64_t ts_recent_expired;
  uint64_t tx_flush_bursts;
  uint64_t tx_flush_batched_pkts;
  uint64_t rx_iovec_segs_total;
  uint64_t rx_multi_seg_events;
  uint64_t rx_partial_read_splits;
};

struct DPDK_NET_ALIGNED(64) dpdk_net_poll_counters_t {
  uint64_t iters;
  uint64_t iters_with_rx;
  uint64_t iters_with_tx;
  uint64_t iters_idle;
  /**
   * HOT-PATH, feature-gated by `obs-poll-saturation` (default ON).
   * See core counters.rs for the full field doc.
   */
  uint64_t iters_with_rx_burst_max;
  uint64_t _pad[11];
};

struct dpdk_net_counters_t {
  struct dpdk_net_eth_counters_t eth;
  struct dpdk_net_ip_counters_t ip;
  struct dpdk_net_tcp_counters_t tcp;
  struct dpdk_net_poll_counters_t poll;
  uint64_t obs_events_dropped;
  uint64_t obs_events_queue_high_water;
};

/**
 * A5.5 per-connection observable state snapshot (spec §5.3, §7.2.3–7.2.6).
 * Slow-path projection mirroring `dpdk_net_core::tcp_conn::ConnStats`; all
 * values are in application-useful units — bytes for the send-buffer
 * fields, microseconds (`_us`) for the RTT estimator fields. Before the
 * first RTT sample has been absorbed, `srtt_us`, `rttvar_us`, and
 * `min_rtt_us` all report 0 and `rto_us` reports the engine's configured
 * `tcp_initial_rto_us`.
 */
struct dpdk_net_conn_stats_t {
  uint32_t snd_una;
  uint32_t snd_nxt;
  uint32_t snd_wnd;
  uint32_t send_buf_bytes_pending;
  uint32_t send_buf_bytes_free;
  uint32_t srtt_us;
  uint32_t rttvar_us;
  uint32_t min_rtt_us;
  uint32_t rto_us;
};

/**
 * A6 (spec §3.8, §5.2): per-connection RTT histogram snapshot POD.
 * Exactly 64 B — one cacheline. The cbindgen header emits the
 * wraparound-semantics doc-comment from the core `rtt_histogram.rs`
 * alongside this struct; see that module for the full contract.
 */
struct dpdk_net_tcp_rtt_histogram_t {
  uint32_t bucket[16];
};

struct dpdk_net_connect_opts_t {
  uint32_t peer_addr;
  uint16_t peer_port;
  uint32_t local_addr;
  uint16_t local_port;
  uint32_t connect_timeout_ms;
  uint32_t idle_keepalive_sec;
  bool rack_aggressive;
  bool rto_no_backoff;
  /**
   * A5.5 Task 10: per-connect RFC 8985 §7.2 PTO floor (µs).
   * `0` (default) inherits engine `tcp_min_rto_us`; `u32::MAX`
   * is the explicit "no-floor" sentinel (yields `floor_us = 0`
   * in the projected `TlpConfig`). Any other value must be
   * `<= tcp_max_rto_us`, else `dpdk_net_connect` returns `-EINVAL`.
   */
  uint32_t tlp_pto_min_floor_us;
  /**
   * A5.5 Task 10: per-connect SRTT multiplier (×100) for PTO base.
   * Default (`0` → `200` at `dpdk_net_connect` entry) matches RFC
   * 8985 `2·SRTT`. Valid range post-substitution: `[100, 200]`.
   * Values outside that range cause `dpdk_net_connect` to return
   * `-EINVAL`.
   */
  uint16_t tlp_pto_srtt_multiplier_x100;
  /**
   * A5.5 Task 10: when `true`, suppresses the RFC 8985 §7.2
   * FlightSize==1 `+max(WCDelAckT, SRTT/4)` penalty (trading-
   * latency opt-out; accepts a small spurious-TLP risk on
   * delayed-ACK receivers).
   */
  bool tlp_skip_flight_size_gate;
  /**
   * A5.5 Task 10: per-connect cap on consecutive TLP probes before
   * falling through to RTO. Default (`0` → `1` at `dpdk_net_connect`
   * entry) matches A5 / RFC 8985 §7.1 single-probe behavior. Valid
   * range post-substitution: `[1, 5]`. Out-of-range causes `-EINVAL`.
   */
  uint8_t tlp_max_consecutive_probes;
  /**
   * A5.5 Task 10: when `true`, suppresses the "require an RTT sample
   * since last TLP" gate in TLP scheduling (trading-latency opt-out;
   * permits back-to-back TLPs even if no peer ACK has produced a
   * fresh RTT sample).
   */
  bool tlp_skip_rtt_sample_gate;
};

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Initialize DPDK EAL. Must be called before dpdk_net_engine_create.
 * `argv` is a C-style argv array; the function does NOT take ownership
 * (copies each argument into Rust-owned CStrings internally).
 * Safe to call multiple times; subsequent calls after the first return 0.
 * Returns 0 on success, negative errno on failure.
 */
int32_t dpdk_net_eal_init(int32_t argc, const char *const *argv);

struct dpdk_net_engine *dpdk_net_engine_create(uint16_t lcore_id,
                                               const struct dpdk_net_engine_config_t *cfg);

void dpdk_net_engine_destroy(struct dpdk_net_engine *p);

int32_t dpdk_net_poll(struct dpdk_net_engine *p,
                      struct dpdk_net_event_t *events_out,
                      uint32_t max_events,
                      uint64_t _timeout_ns);

/**
 * A6 (spec §4.2): drains the pending data-segment TX batch via one
 * `rte_eth_tx_burst`. No-op when ring empty. Idempotent.
 * Control frames (ACK, SYN, FIN, RST) are emitted inline at their
 * emit site and do not participate in the flush batch — flushing
 * never blocks or reorders control-frame emission.
 */
void dpdk_net_flush(struct dpdk_net_engine *p);

uint64_t dpdk_net_now_ns(struct dpdk_net_engine *_p);

const struct dpdk_net_counters_t *dpdk_net_counters(struct dpdk_net_engine *p);

/**
 * A6.6-7 Task 10: returns the RX mempool capacity (in mbufs) in use on
 * this engine. When the caller set `dpdk_net_engine_config_t.rx_mempool_size`
 * to a non-zero value, that value is returned verbatim. When the caller
 * left it zero, the returned value is the formula default computed at
 * `dpdk_net_engine_create` time:
 *
 *   max(4 * rx_ring_size,
 *       2 * max_connections * ceil(recv_buffer_bytes / mbuf_data_room) + 4096)
 *
 * where `mbuf_data_room` is the DPDK mbuf payload slot size (2048 bytes
 * on the standard-MTU default). The `2 * max_conns * per_conn` term is
 * "two full receive buffers' worth of mbufs per connection" so the RX
 * path never blocks on mempool exhaustion when all connections
 * concurrently hold a receive buffer of in-flight data; the `+ 4096`
 * cushion covers LRO chains, retransmit backlog, and SYN/ACK spikes.
 * The `4 * rx_ring_size` floor guarantees at least 4× the RX descriptor
 * count to keep `rte_eth_rx_burst` fully refilled.
 *
 * Returns `UINT32_MAX` if `p` is null. Slow-path (reads a single `u32`
 * field, no locks).
 *
 * # Safety
 * `p` must be a valid Engine pointer obtained from
 * `dpdk_net_engine_create`, or null.
 */
uint32_t dpdk_net_rx_mempool_size(const struct dpdk_net_engine *p);

/**
 * Slow-path: trigger an ENA-PMD xstats scrape. Reads ENI
 * allowance-exceeded + per-queue (q0) Tx/Rx counters via DPDK
 * rte_eth_xstats_get_by_id and writes them into the counters
 * snapshot. Application calls this on its own cadence (typically
 * 1 Hz). On non-ENA / non-advertising PMDs this is a cheap no-op.
 *
 * Returns 0 on success (always — failures are silent and observable
 * via the counters staying at their last value).
 * Returns -EINVAL if `p` is null.
 *
 * # Safety
 * `p` must be a valid Engine pointer obtained from
 * `dpdk_net_engine_create`.
 */
int32_t dpdk_net_scrape_xstats(struct dpdk_net_engine *p);

/**
 * M1+M2 helper: build an ENA `-a <bdf>,...=` devarg string the
 * application splices into its EAL args before calling
 * `dpdk_net_eal_init`. Writes a NUL-terminated string into `out`;
 * returns the number of bytes written EXCLUDING the trailing NUL on
 * success, or a negative errno on failure:
 *   `-EINVAL` — `bdf` or `out` is null.
 *   `-ERANGE` — `miss_txc_to_sec > 60` (see ENA README §5.1).
 *   `-ENOSPC` — `out_cap` is smaller than the required length + NUL.
 *
 * Emits `large_llq_hdr=1` only when the argument is non-zero; emits
 * `miss_txc_to=N` only when the argument is non-zero (0 = use PMD
 * default 5 s). Do NOT set 0 with the intent of disabling the Tx
 * watchdog — see ENA README §5.1 caution.
 *
 * Slow-path; called once during EAL-args construction at process
 * startup.
 *
 * # Safety
 * `bdf` must point to a NUL-terminated PCI BDF string (e.g.
 * "00:06.0"). `out` must be a writable buffer of at least `out_cap`
 * bytes.
 */
int32_t dpdk_net_recommended_ena_devargs(const char *bdf,
                                         uint8_t large_llq_hdr,
                                         uint8_t miss_txc_to_sec,
                                         char *out,
                                         uintptr_t out_cap);

/**
 * Slow-path snapshot of a connection's send-path + RTT estimator state,
 * for per-order forensics tagging (spec §5.3, §7.2.3–7.2.6). Safe to call
 * at order-emit time; not meant for hot-loop polling.
 *
 * Returns:
 *   0       on success; `out` is populated.
 *   -EINVAL engine or out is NULL.
 *   -ENOENT conn is not a live handle in the engine's flow table
 *           (never-allocated, stale post-close, or reserved `0`).
 */
int32_t dpdk_net_conn_stats(struct dpdk_net_engine *engine,
                            dpdk_net_conn_t conn,
                            struct dpdk_net_conn_stats_t *out);

/**
 * A6 (spec §3.8, §5.3): per-connection RTT histogram snapshot.
 *
 * Each bucket counts RTT samples whose value is <= the corresponding
 * edge in `rtt_histogram_bucket_edges_us[]` (bucket 15 is the catch-
 * all for values greater than the last edge). Counters are u32 per-
 * connection lifetime; applications take deltas across two snapshots
 * using unsigned wraparound subtraction. See the core `rtt_histogram.rs`
 * module doc-comment for the full wraparound contract.
 *
 * Slow-path: safe per-order for forensics tagging, safe per-minute for
 * session-health polling. Do not call in a per-segment loop.
 *
 * Returns:
 *   0       on success; `out` is populated with 64 bytes.
 *   -EINVAL engine or out is NULL.
 *   -ENOENT conn is not a live handle in the engine's flow table.
 */
int32_t dpdk_net_conn_rtt_histogram(struct dpdk_net_engine *engine,
                                    dpdk_net_conn_t conn,
                                    struct dpdk_net_tcp_rtt_histogram_t *out);

/**
 * Resolve the MAC address for `gateway_ip_host_order` by reading
 * `/proc/net/arp`. Writes 6 bytes into `out_mac`.
 * Returns 0 on success, -ENOENT if no entry, -EIO on /proc/net/arp read error,
 * -EINVAL on null out_mac.
 */
int32_t dpdk_net_resolve_gateway_mac(uint32_t gateway_ip_host_order, uint8_t *out_mac);

int32_t dpdk_net_connect(struct dpdk_net_engine *p,
                         const struct dpdk_net_connect_opts_t *opts,
                         dpdk_net_conn_t *out);

int32_t dpdk_net_send(struct dpdk_net_engine *p,
                      dpdk_net_conn_t conn,
                      const uint8_t *buf,
                      uint32_t len);

/**
 * A6 (spec §5.4, §3.4): close a connection, honoring the `flags` bitmask.
 *
 * Defined flags:
 * * `DPDK_NET_CLOSE_FORCE_TW_SKIP` — request to skip 2×MSL TIME_WAIT.
 *   Honored only when the connection negotiated timestamps
 *   (`c.ts_enabled == true`) at close time — the combination of PAWS
 *   on the peer (RFC 7323 §5) + monotonic ISS on our side (RFC 6528,
 *   spec §6.5) is the client-side analog of RFC 6191's protections.
 *   When the prerequisite is not met, the flag is silently dropped
 *   and a `DPDK_NET_EVT_ERROR{err=-EPERM}` is emitted for visibility;
 *   the normal FIN + 2×MSL TIME_WAIT sequence proceeds.
 *
 * Undefined flag bits are reserved for future extension and silently
 * ignored.
 *
 * Returns 0 on successful close initiation (FIN emitted), or:
 *   -EINVAL  engine is NULL
 *   -ENOTCONN  conn is not a live handle
 *   -EIO  internal error (TX path or flow-table)
 */
int32_t dpdk_net_close(struct dpdk_net_engine *p, dpdk_net_conn_t conn, uint32_t flags);

/**
 * A6 (spec §5.3): schedule a one-shot timer. `deadline_ns` is in the
 * engine's monotonic clock domain (see `dpdk_net_now_ns`). Rounded up
 * to the next 10 µs wheel tick; past deadlines fire on the next poll.
 * On fire, emits `DPDK_NET_EVT_TIMER` with the returned `timer_id`
 * and the caller-supplied `user_data` echoed back.
 *
 * Returns 0 on success (populates `*timer_id_out`); -EINVAL on
 * null engine/out. The populated `*timer_id_out` is a packed
 * `TimerId{slot, generation}` opaque handle — callers treat as
 * opaque but may observe the high 32 bits change on slot reuse.
 */
int32_t dpdk_net_timer_add(struct dpdk_net_engine *engine,
                           uint64_t deadline_ns,
                           uint64_t user_data,
                           uint64_t *timer_id_out);

/**
 * A6 (spec §5.3): cancel a previously-added timer. Returns 0 if
 * cancelled before fire, -ENOENT otherwise (collapses: never existed /
 * already fired and drained / already fired but not yet drained).
 * Callers must always drain any queued TIMER events regardless of
 * this return — the event queue is authoritative.
 */
int32_t dpdk_net_timer_cancel(struct dpdk_net_engine *engine, uint64_t timer_id);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* DPDK_NET_H */
