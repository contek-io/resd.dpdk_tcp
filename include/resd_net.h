#ifndef RESD_NET_H
#define RESD_NET_H

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

#define RESD_NET_ALIGNED(N) __attribute__((aligned(N)))


/**
 * Close flags — bitmask for resd_net_close.
 */
#define RESD_NET_CLOSE_FORCE_TW_SKIP (1 << 0)

enum resd_net_event_kind_t
#ifdef __cplusplus
  : uint32_t
#endif // __cplusplus
 {
  RESD_NET_EVT_CONNECTED = 1,
  RESD_NET_EVT_READABLE = 2,
  RESD_NET_EVT_WRITABLE = 3,
  RESD_NET_EVT_CLOSED = 4,
  RESD_NET_EVT_ERROR = 5,
  RESD_NET_EVT_TIMER = 6,
  RESD_NET_EVT_TCP_RETRANS = 7,
  RESD_NET_EVT_TCP_LOSS_DETECTED = 8,
  RESD_NET_EVT_TCP_STATE_CHANGE = 9,
};
#ifndef __cplusplus
typedef uint32_t resd_net_event_kind_t;
#endif // __cplusplus

struct resd_net_engine {
  uint8_t _opaque[0];
};

struct resd_net_engine_config_t {
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
  uint32_t tcp_initial_rto_ms;
  uint32_t tcp_msl_ms;
  bool tcp_per_packet_events;
  uint8_t preset;
  uint32_t local_ip;
  uint32_t gateway_ip;
  uint8_t gateway_mac[6];
  uint32_t garp_interval_sec;
};

typedef uint64_t resd_net_conn_t;

struct resd_net_event_readable_t {
  const uint8_t *data;
  uint32_t data_len;
};

struct resd_net_event_error_t {
  int32_t err;
};

struct resd_net_event_timer_t {
  uint64_t timer_id;
  uint64_t user_data;
};

struct resd_net_event_tcp_retrans_t {
  uint32_t seq;
  uint32_t rtx_count;
};

struct resd_net_event_tcp_loss_t {
  uint32_t first_seq;
  uint8_t trigger;
};

struct resd_net_event_tcp_state_t {
  uint8_t from_state;
  uint8_t to_state;
};

/**
 * Union-of-payloads approach: we lay out the union as a byte array and
 * expose accessor helpers. cbindgen emits it as a C union.
 */
union resd_net_event_payload_t {
  struct resd_net_event_readable_t readable;
  struct resd_net_event_error_t error;
  struct resd_net_event_error_t closed;
  struct resd_net_event_timer_t timer;
  struct resd_net_event_tcp_retrans_t tcp_retrans;
  struct resd_net_event_tcp_loss_t tcp_loss;
  struct resd_net_event_tcp_state_t tcp_state;
  uint8_t _pad[16];
};

struct resd_net_event_t {
  resd_net_event_kind_t kind;
  resd_net_conn_t conn;
  uint64_t rx_hw_ts_ns;
  uint64_t enqueued_ts_ns;
  union resd_net_event_payload_t u;
};

/**
 * Counters struct — exposed to application via resd_net_counters().
 * Fields are plain u64 on the C ABI for clean cbindgen emission, but
 * internally the stack writes them as AtomicU64 (Relaxed). AtomicU64
 * has identical size and alignment as u64 on x86_64 so pointer-casting
 * between resd_net_core::Counters and resd_net_counters_t is sound.
 * C/C++ readers should use `__atomic_load_n(&field, __ATOMIC_RELAXED)`
 * (or `std::atomic_ref<uint64_t>`) for strictly correct reads; on x86_64
 * this compiles to a plain `mov` so there's no runtime cost.
 */
struct RESD_NET_ALIGNED(64) resd_net_eth_counters_t {
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
  uint64_t _pad[4];
};

struct RESD_NET_ALIGNED(64) resd_net_ip_counters_t {
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

struct RESD_NET_ALIGNED(64) resd_net_tcp_counters_t {
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
  uint64_t _pad[3];
};

struct RESD_NET_ALIGNED(64) resd_net_poll_counters_t {
  uint64_t iters;
  uint64_t iters_with_rx;
  uint64_t iters_with_tx;
  uint64_t iters_idle;
  uint64_t _pad[12];
};

struct resd_net_counters_t {
  struct resd_net_eth_counters_t eth;
  struct resd_net_ip_counters_t ip;
  struct resd_net_tcp_counters_t tcp;
  struct resd_net_poll_counters_t poll;
};

struct resd_net_connect_opts_t {
  uint32_t peer_addr;
  uint16_t peer_port;
  uint32_t local_addr;
  uint16_t local_port;
  uint32_t connect_timeout_ms;
  uint32_t idle_keepalive_sec;
};

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Initialize DPDK EAL. Must be called before resd_net_engine_create.
 * `argv` is a C-style argv array; the function does NOT take ownership
 * (copies each argument into Rust-owned CStrings internally).
 * Safe to call multiple times; subsequent calls after the first return 0.
 * Returns 0 on success, negative errno on failure.
 */
int32_t resd_net_eal_init(int32_t argc, const char *const *argv);

struct resd_net_engine *resd_net_engine_create(uint16_t lcore_id,
                                               const struct resd_net_engine_config_t *cfg);

void resd_net_engine_destroy(struct resd_net_engine *p);

int32_t resd_net_poll(struct resd_net_engine *p,
                      struct resd_net_event_t *_events_out,
                      uint32_t _max_events,
                      uint64_t _timeout_ns);

void resd_net_flush(struct resd_net_engine *_p);

uint64_t resd_net_now_ns(struct resd_net_engine *_p);

const struct resd_net_counters_t *resd_net_counters(struct resd_net_engine *p);

/**
 * Resolve the MAC address for `gateway_ip_host_order` by reading
 * `/proc/net/arp`. Writes 6 bytes into `out_mac`.
 * Returns 0 on success, -ENOENT if no entry, -EIO on /proc/net/arp read error,
 * -EINVAL on null out_mac.
 */
int32_t resd_net_resolve_gateway_mac(uint32_t gateway_ip_host_order, uint8_t *out_mac);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* RESD_NET_H */
