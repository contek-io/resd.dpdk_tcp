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
 * reliably expose it. We provide `shim_rte_errno()` as a real extern
 * function (defined in shim.c, compiled via the `cc` crate in build.rs)
 * so bindgen emits a plain FFI stub for it.
 */
int shim_rte_errno(void);

/* Burst-path helpers and `rte_pktmbuf_free` are `static inline` in DPDK
 * headers. bindgen skips inline functions, so we re-export them from
 * shim.c as real extern symbols (prefixed `shim_rte_`) for the Rust hot path.
 */
uint16_t shim_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
                               struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
uint16_t shim_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
                               struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
void shim_rte_pktmbuf_free(struct rte_mbuf *m);
struct rte_mbuf *shim_rte_pktmbuf_alloc(struct rte_mempool *mp);
char *shim_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len);
int shim_rte_eth_macaddr_get(uint16_t port_id, struct rte_ether_addr *mac_addr);
int shim_rte_eth_dev_get_mtu(uint16_t port_id, uint16_t *mtu);
void *shim_rte_pktmbuf_data(const struct rte_mbuf *m);
uint16_t shim_rte_pktmbuf_data_len(const struct rte_mbuf *m);
int shim_rte_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *tail);
void shim_rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t v);
uint16_t shim_rte_pktmbuf_nb_segs(const struct rte_mbuf *m);

/* A-HW Task 7: TX offload metadata setters. `struct rte_mbuf` is opaque
 * to bindgen (packed anonymous unions), so we can't touch ol_flags /
 * l2_len / l3_len / l4_len directly from Rust — expose OR + set via
 * shim functions. Read back for unit tests uses the paired getters. */
void shim_rte_mbuf_or_ol_flags(struct rte_mbuf *m, uint64_t flags);
void shim_rte_mbuf_set_tx_lens(struct rte_mbuf *m, uint16_t l2, uint16_t l3, uint16_t l4);
uint64_t shim_rte_mbuf_get_ol_flags(const struct rte_mbuf *m);
uint16_t shim_rte_mbuf_get_l2_len(const struct rte_mbuf *m);
uint16_t shim_rte_mbuf_get_l3_len(const struct rte_mbuf *m);
uint16_t shim_rte_mbuf_get_l4_len(const struct rte_mbuf *m);

/* A-HW Task 9: RSS hash accessor. `mbuf.hash.rss` lives in a nested
 * anonymous union that bindgen elides; the Rust RX path reads the NIC
 * Toeplitz hash through this shim and passes it to the flow_table
 * bucket selector. */
uint32_t shim_rte_mbuf_get_rss_hash(const struct rte_mbuf *m);

/* A-HW Task 10: NIC-provided RX timestamp dynfield reader.
 * The PMD-registered timestamp dynfield is stored at a dynamic offset
 * (in bytes, returned by rte_mbuf_dynfield_lookup("rte_dynfield_timestamp"))
 * from the start of rte_mbuf. The field width is uint64_t. Since
 * struct rte_mbuf is opaque to the Rust bindings (packed anonymous
 * unions defeat bindgen's layout engine), we expose the field load as
 * a real C function. Only called from the RX hot path when both the
 * dynfield AND the corresponding dynflag lookup succeeded at
 * engine_create — ENA never reaches this path (spec §10.5). */
uint64_t shim_rte_mbuf_read_dynfield_u64(const struct rte_mbuf *m, int32_t offset);

/* phase-a-hw-plus T3: prefetchable-BAR physical address for ENA WC
 * verification. The ENA PMD uses BAR2 for the prefetchable memory
 * region that must be mapped write-combining under LLQ. Returns 0
 * when the port is not a PCI device, BAR2 is unmapped, dev_info
 * fails, or the DPDK driver-SDK headers were unavailable at shim
 * build time — callers (wc_verify::verify_wc_for_ena) treat 0 as
 * "unavailable, skip verification". */
uint64_t shim_rte_eth_dev_prefetchable_bar_phys(uint16_t port_id);
