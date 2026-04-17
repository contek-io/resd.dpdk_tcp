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
