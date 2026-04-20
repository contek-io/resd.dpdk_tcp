#include <assert.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

int resd_rte_errno(void) {
    return rte_errno;
}

/* The burst helpers and rte_pktmbuf_free are `static inline` in DPDK
 * headers, so bindgen does not emit FFI stubs for them. Expose real
 * extern wrappers here so the Rust hot path can call them directly.
 */
uint16_t resd_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
                               struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t resd_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
                               struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

void resd_rte_pktmbuf_free(struct rte_mbuf *m) {
    rte_pktmbuf_free(m);
}

/* rte_pktmbuf_alloc is static inline; re-export. */
struct rte_mbuf *resd_rte_pktmbuf_alloc(struct rte_mempool *mp) {
    return rte_pktmbuf_alloc(mp);
}

/* rte_pktmbuf_append is static inline; re-export.
 * Returns a pointer to the appended region, or NULL on overflow. */
char *resd_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_append(m, len);
}

/* rte_eth_macaddr_get is a real extern but we re-export for shim-prefix
 * consistency. Returns 0 on success, negative errno on failure. */
int resd_rte_eth_macaddr_get(uint16_t port_id, struct rte_ether_addr *mac_addr) {
    return rte_eth_macaddr_get(port_id, mac_addr);
}

/* rte_eth_dev_get_mtu is a real extern but we re-export for shim-prefix
 * consistency. Returns 0 on success + writes MTU to *mtu, negative errno otherwise. */
int resd_rte_eth_dev_get_mtu(uint16_t port_id, uint16_t *mtu) {
    return rte_eth_dev_get_mtu(port_id, mtu);
}

/* mbuf field accessors — struct rte_mbuf is opaque to bindgen (packed
 * anonymous unions defeat its layout engine), so expose the two fields
 * our hot path needs as real C functions.
 *
 *   resd_rte_pktmbuf_data     — pointer to the first byte of packet data
 *   resd_rte_pktmbuf_data_len — length of the first (only, in Phase A2) segment
 */
void *resd_rte_pktmbuf_data(const struct rte_mbuf *m) {
    return rte_pktmbuf_mtod(m, void *);
}

uint16_t resd_rte_pktmbuf_data_len(const struct rte_mbuf *m) {
    return rte_pktmbuf_data_len(m);
}

/* rte_pktmbuf_chain is static inline; re-export. Attaches `tail` to `head`
 * updating nb_segs + pkt_len. Returns 0 on success; -EOVERFLOW if the chain
 * would exceed RTE_MBUF_MAX_NB_SEGS. */
int resd_rte_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *tail) {
    return rte_pktmbuf_chain(head, tail);
}

/* rte_mbuf_refcnt_update is static inline; re-export. Adds `v` (may be
 * negative) to the refcount. */
void resd_rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t v) {
    rte_mbuf_refcnt_update(m, v);
}

/* rte_pktmbuf_nb_segs — field accessor for test assertions + debug.
 * bindgen can't expose the rte_mbuf field layout directly. */
uint16_t resd_rte_pktmbuf_nb_segs(const struct rte_mbuf *m) {
    return m->nb_segs;
}

/* A-HW Task 7: TX offload metadata setters/getters.
 *
 * `struct rte_mbuf` is opaque in the Rust bindings (packed anonymous
 * unions defeat bindgen's layout engine), so the Rust-side finalizer
 * OR-s ol_flags and sets the l2/l3/l4_len triple through these shims.
 * The getters back unit-test assertions; production callers only need
 * the setters. */
void resd_rte_mbuf_or_ol_flags(struct rte_mbuf *m, uint64_t flags) {
    m->ol_flags |= flags;
}

void resd_rte_mbuf_set_tx_lens(struct rte_mbuf *m, uint16_t l2, uint16_t l3, uint16_t l4) {
    m->l2_len = l2;
    m->l3_len = l3;
    m->l4_len = l4;
}

uint64_t resd_rte_mbuf_get_ol_flags(const struct rte_mbuf *m) {
    return m->ol_flags;
}

/* The following mbuf getters (l2_len/l3_len/l4_len) are reserved for the
 * A-HW Task 18 smoke test (ahw_smoke_ena_hw.rs) and future diagnostic
 * tooling. They are intentionally not gated — linking them unconditionally
 * keeps the bindgen allowlist pattern (`resd_.*`) simple. See A-HW spec
 * §12.3. */
uint16_t resd_rte_mbuf_get_l2_len(const struct rte_mbuf *m) {
    return (uint16_t)m->l2_len;
}

uint16_t resd_rte_mbuf_get_l3_len(const struct rte_mbuf *m) {
    return (uint16_t)m->l3_len;
}

uint16_t resd_rte_mbuf_get_l4_len(const struct rte_mbuf *m) {
    return (uint16_t)m->l4_len;
}

/* A-HW Task 9: RSS hash accessor. `mbuf.hash` is a nested anonymous
 * union in rte_mbuf.h which bindgen does not expose cleanly, so the
 * Rust RX hot path reads `hash.rss` via this shim. Paired with the
 * flow_table::hash_bucket_for_lookup selector — only called when the
 * `hw-offload-rss-hash` feature is compiled in. */
uint32_t resd_rte_mbuf_get_rss_hash(const struct rte_mbuf *m) {
    return m->hash.rss;
}

/* A-HW Task 10: NIC-provided RX timestamp dynfield reader.
 *
 * The dynamic field offset comes from
 * rte_mbuf_dynfield_lookup("rte_dynfield_timestamp") at engine_create.
 * Reading it in Rust would require raw pointer arithmetic on the
 * opaque mbuf; doing the arithmetic in C is type-checked at compile
 * time (char* byte indexing + uint64_t load) and the one-liner keeps
 * the unsafe surface minimal on the Rust side.
 *
 * Only called when both the dynfield AND the dynflag lookup succeeded
 * (see Engine::hw_rx_ts_ns); ENA never reaches this path per spec §10.5. */
uint64_t resd_rte_mbuf_read_dynfield_u64(const struct rte_mbuf *m, int32_t offset) {
    /* x86_64 tolerates unaligned 8-byte loads, but ARM64 is strict. The
     * DPDK dynfield registrar returns an 8-byte-aligned offset for u64
     * fields; this assert catches misconfigured PMDs in debug builds
     * before a stray SIGBUS on a future ARM target. NOP when NDEBUG is
     * defined (release builds). */
    assert(offset >= 0);
    assert((offset & 0x7) == 0 && "dynfield offset must be 8-byte aligned (u64 field)");
    return *(const uint64_t *)((const char *)m + offset);
}
