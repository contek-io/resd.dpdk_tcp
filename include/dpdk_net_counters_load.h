#ifndef DPDK_NET_COUNTERS_LOAD_H
#define DPDK_NET_COUNTERS_LOAD_H

#pragma once

/*
 * dpdk_net_counters_load.h — atomic-load helpers for dpdk_net_counters_t.
 *
 * Counters in dpdk_net_counters_t are declared as plain uint64_t in the
 * cbindgen-generated dpdk_net.h, but Rust writes them via AtomicU64 with
 * Relaxed ordering. Cross-platform correctness requires readers use an
 * atomic load:
 *   - x86_64: aligned uint64_t load is atomic by ISA; __atomic_load_n
 *     with __ATOMIC_RELAXED compiles to plain mov. Zero cost vs naive.
 *   - ARM64: relaxed-load semantics are well-defined; LDR with acquire-
 *     relaxed is a single instruction.
 *   - ARM32: uint64_t loads are NOT atomic without LDREXD/LDRD; naive
 *     loads may tear. __atomic_load_n emits the correct sequence.
 *
 * Use dpdk_net_load_u64(&counters->eth.rx_pkts) instead of plain reads.
 */

#include <stdint.h>

static inline uint64_t dpdk_net_load_u64(const uint64_t *p) {
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}

#endif /* DPDK_NET_COUNTERS_LOAD_H */
