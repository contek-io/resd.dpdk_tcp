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

/* `rte_errno` is a macro expanding to a thread-local int; bindgen
 * cannot reliably expose it. Wrap it in a trivial C shim that bindgen
 * does expose. All Rust callers use `resd_rte_errno()`.
 */
static inline int resd_rte_errno(void) { return rte_errno; }
