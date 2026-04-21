#ifndef DPDK_NET_TEST_H
#define DPDK_NET_TEST_H

#pragma once

/* DO NOT EDIT: generated from Rust via cbindgen (test-server feature) */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "dpdk_net.h"

/* Typedef bridges: the production header uses struct tags (style = "tag");
 * the test header references these types without the `struct` keyword
 * because they are on our cbindgen exclude list (cbindgen can't tell
 * "tag" from "typedef" for excluded types). Declaring typedefs here
 * with the same name as the tag is legal ISO C and lets both spellings
 * resolve. */
typedef struct dpdk_net_engine dpdk_net_engine;
typedef struct dpdk_net_connect_opts_t dpdk_net_connect_opts_t;


/**
 * A single TX frame handed back by `dpdk_net_test_drain_tx_frames`.
 * `buf` points into a thread-local scratch area retained until the
 * next `drain_tx_frames` call on the same thread; callers must copy
 * the bytes out before the next drain.
 */
struct dpdk_net_test_frame_t {
  const uint8_t *buf;
  uintptr_t len;
};

/**
 * Opaque-ish listen-socket handle. Matches the core-crate
 * `dpdk_net_core::test_server::ListenHandle = u32` layout but is a
 * distinct type on the FFI surface so its identity is independent of
 * the Rust internal type.
 */
typedef uint32_t dpdk_net_listen_handle_t;

/**
 * Set the thread-local virtual clock (ns). Non-monotonic values panic.
 * Does NOT pump — the caller typically follows `set_time_ns` with an
 * `inject_frame` or another FFI entry that will pump.
 */
void dpdk_net_test_set_time_ns(uint64_t ns);

/**
 * Inject a single Ethernet-framed frame into the engine's RX pipeline
 * and run pumps to quiescence. Returns 0 on success, `-EINVAL` on a
 * null/zero-length input or null engine, `-ENOMEM` on mempool
 * exhaustion.
 */
int32_t dpdk_net_test_inject_frame(dpdk_net_engine *engine, const uint8_t *buf, uintptr_t len);

/**
 * Drain every TX-intercept frame queued since the last call, writing
 * up to `max` descriptors into `out`. Returns the number written.
 * Each `buf` pointer is backed by the thread-local scratch Vec and
 * remains valid until the next `dpdk_net_test_drain_tx_frames` call
 * on the same thread.
 */
uintptr_t dpdk_net_test_drain_tx_frames(dpdk_net_engine *_engine,
                                        struct dpdk_net_test_frame_t *out,
                                        uintptr_t max);

/**
 * Create a listen slot on (engine's primary local IP, `local_port`).
 * Returns `0` on error (null engine / duplicate slot / id overflow),
 * otherwise a 1-based handle.
 */
dpdk_net_listen_handle_t dpdk_net_test_listen(dpdk_net_engine *engine, uint16_t local_port);

/**
 * Pop the 1-deep accept queue for the given listen handle. Returns
 * `u64::MAX` when nothing is queued or the handle is unknown.
 * Does NOT pump — accept_next is a no-side-effect lookup and callers
 * typically invoke it between other pumped operations.
 */
dpdk_net_conn_t dpdk_net_test_accept_next(dpdk_net_engine *engine, dpdk_net_listen_handle_t listen);

/**
 * Thin re-wrapper around `dpdk_net_connect` that pumps on success.
 * Returns `u64::MAX` on failure, the connection handle on success.
 * `dst_ip` is in host byte order; the ABI `dpdk_net_connect_opts_t`
 * expects network-byte-order ints, so we convert at the boundary.
 */
dpdk_net_conn_t dpdk_net_test_connect(dpdk_net_engine *engine,
                                      uint32_t dst_ip,
                                      uint16_t dst_port,
                                      const dpdk_net_connect_opts_t *opts);

/**
 * Thin re-wrapper around `dpdk_net_send` that pumps on success.
 * Returns bytes accepted (non-negative) or a negative errno from
 * `dpdk_net_send`.
 */
intptr_t dpdk_net_test_send(dpdk_net_engine *engine,
                            dpdk_net_conn_t h,
                            const uint8_t *buf,
                            uintptr_t len);

/**
 * Drain at most one `dpdk_net_poll` event batch, concatenating every
 * READABLE event's scatter-gather segments targeting handle `h` into
 * `out` (up to `max` bytes). Returns bytes written, 0 if no READABLE
 * event is waiting for this handle, or `-EINVAL` on null inputs.
 */
intptr_t dpdk_net_test_recv(dpdk_net_engine *engine,
                            dpdk_net_conn_t h,
                            uint8_t *out,
                            uintptr_t max);

/**
 * Thin re-wrapper around `dpdk_net_close` that pumps on success.
 */
int32_t dpdk_net_test_close(dpdk_net_engine *engine, dpdk_net_conn_t h, uint32_t flags);

#endif /* DPDK_NET_TEST_H */
