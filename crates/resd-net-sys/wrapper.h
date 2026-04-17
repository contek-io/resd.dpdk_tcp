/* Single include point for bindgen. Only includes the DPDK headers
 * that the Rust stack actually uses — keeps generated bindings small.
 */
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_version.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ip_frag.h>
#include <rte_icmp.h>
#include <rte_mbuf_dyn.h>

/* `rte_errno` is a macro expanding to a thread-local int; bindgen cannot
 * reliably expose it. We provide `resd_rte_errno()` as a real extern
 * function (defined in shim.c, compiled via the `cc` crate in build.rs)
 * so bindgen emits a plain FFI stub for it.
 */
int resd_rte_errno(void);

/* Burst-path helpers and `rte_pktmbuf_free` are `static inline` in DPDK
 * headers. bindgen skips inline functions, so we re-export them from
 * shim.c as real extern symbols (prefixed `resd_`) for the Rust hot path.
 */
uint16_t resd_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
                               struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
uint16_t resd_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
                               struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
void resd_rte_pktmbuf_free(struct rte_mbuf *m);
struct rte_mbuf *resd_rte_pktmbuf_alloc(struct rte_mempool *mp);
char *resd_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len);
int resd_rte_eth_macaddr_get(uint16_t port_id, struct rte_ether_addr *mac_addr);
void *resd_rte_pktmbuf_data(const struct rte_mbuf *m);
uint16_t resd_rte_pktmbuf_data_len(const struct rte_mbuf *m);
