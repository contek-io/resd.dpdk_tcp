#include <assert.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

/* phase-a-hw-plus T3: the PCI BAR physical-address reader needs to
 * deref `struct rte_pci_device`, which DPDK 23.11 exposes ONLY via the
 * driver-SDK private header (`bus_pci_driver.h`). `build.rs` probes
 * for the source tree and defines `DPDK_HAS_PCI_SDK` when the header
 * is reachable; otherwise the BAR shim degrades to "return 0" so the
 * Rust-side verification quietly skips. */
#ifdef DPDK_HAS_PCI_SDK
#include <rte_bus_pci.h>
#include <bus_pci_driver.h>
#endif

int shim_rte_errno(void) {
    return rte_errno;
}

/* The burst helpers and rte_pktmbuf_free are `static inline` in DPDK
 * headers, so bindgen does not emit FFI stubs for them. Expose real
 * extern wrappers here so the Rust hot path can call them directly.
 */
uint16_t shim_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
                               struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t shim_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
                               struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

void shim_rte_pktmbuf_free(struct rte_mbuf *m) {
    rte_pktmbuf_free(m);
}

/* rte_pktmbuf_alloc is static inline; re-export. */
struct rte_mbuf *shim_rte_pktmbuf_alloc(struct rte_mempool *mp) {
    return rte_pktmbuf_alloc(mp);
}

/* rte_pktmbuf_append is static inline; re-export.
 * Returns a pointer to the appended region, or NULL on overflow. */
char *shim_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_append(m, len);
}

/* rte_eth_macaddr_get is a real extern but we re-export for shim-prefix
 * consistency. Returns 0 on success, negative errno on failure. */
int shim_rte_eth_macaddr_get(uint16_t port_id, struct rte_ether_addr *mac_addr) {
    return rte_eth_macaddr_get(port_id, mac_addr);
}

/* rte_eth_dev_get_mtu is a real extern but we re-export for shim-prefix
 * consistency. Returns 0 on success + writes MTU to *mtu, negative errno otherwise. */
int shim_rte_eth_dev_get_mtu(uint16_t port_id, uint16_t *mtu) {
    return rte_eth_dev_get_mtu(port_id, mtu);
}

/* mbuf field accessors — struct rte_mbuf is opaque to bindgen (packed
 * anonymous unions defeat its layout engine), so expose the two fields
 * our hot path needs as real C functions.
 *
 *   shim_rte_pktmbuf_data     — pointer to the first byte of packet data
 *   shim_rte_pktmbuf_data_len — length of the first (only, in Phase A2) segment
 */
void *shim_rte_pktmbuf_data(const struct rte_mbuf *m) {
    return rte_pktmbuf_mtod(m, void *);
}

uint16_t shim_rte_pktmbuf_data_len(const struct rte_mbuf *m) {
    return rte_pktmbuf_data_len(m);
}

/* rte_pktmbuf_chain is static inline; re-export. Attaches `tail` to `head`
 * updating nb_segs + pkt_len. Returns 0 on success; -EOVERFLOW if the chain
 * would exceed RTE_MBUF_MAX_NB_SEGS. */
int shim_rte_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *tail) {
    return rte_pktmbuf_chain(head, tail);
}

/* rte_pktmbuf_adj is static inline; re-export. Advances the mbuf's
 * data_off by `len`, shrinking data_len + pkt_len by the same amount.
 * Returns the new data pointer (after the advance), or NULL if `len`
 * exceeds the segment's data_len. Used by the retransmit primitive to
 * strip the original L2+L3+TCP headers off the snd_retrans data mbuf
 * before chaining a fresh header mbuf in front of it. */
char *shim_rte_pktmbuf_adj(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_adj(m, len);
}

/* rte_mbuf_refcnt_update is static inline; re-export. Adds `v` (may be
 * negative) to the refcount. */
void shim_rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t v) {
    rte_mbuf_refcnt_update(m, v);
}

/* rte_mbuf_refcnt_read is static inline; re-export. Returns the current
 * refcount without modifying it. Used by MbufHandle::Drop's leak-detection
 * diagnostic — observes the post-dec count to flag mbufs that should have
 * been freed but weren't. */
uint16_t shim_rte_mbuf_refcnt_read(struct rte_mbuf *m) {
    return rte_mbuf_refcnt_read(m);
}

/* rte_pktmbuf_nb_segs — field accessor for test assertions + debug.
 * bindgen can't expose the rte_mbuf field layout directly. */
uint16_t shim_rte_pktmbuf_nb_segs(const struct rte_mbuf *m) {
    return m->nb_segs;
}

/* A6.6 Task 5: next-segment accessor for RX ingest chain walk. Returns
 * the next rte_mbuf in a scattered-packet chain, or NULL when `m` is
 * the last (or only) segment. ENA does not advertise RX_OFFLOAD_SCATTER
 * today so the chain is always length-1 in production, but the RX
 * ingest path calls this unconditionally so the multi-seg branch is
 * exercised in synthetic tests (T13) + automatically light up when a
 * future PMD enables scatter. bindgen can't deref struct rte_mbuf
 * fields directly (packed anonymous unions), hence the shim. */
struct rte_mbuf *shim_rte_pktmbuf_next(struct rte_mbuf *m) {
    return m->next;
}

/* A6.6-7 Task 13: mempool occupancy reader — returns the current count
 * of FREE mbufs in `mp`. The close-drains integration test uses this
 * together with `Engine::rx_mempool_size()` to compute the in-flight
 * occupancy (capacity - avail). `rte_mempool_avail_count` is a real
 * extern symbol in DPDK but re-exporting through a shim keeps the
 * bindgen allowlist consistent with `shim_rte_*`. */
unsigned shim_rte_mempool_avail_count(struct rte_mempool *mp) {
    return rte_mempool_avail_count(mp);
}

/* A-HW Task 7: TX offload metadata setters/getters.
 *
 * `struct rte_mbuf` is opaque in the Rust bindings (packed anonymous
 * unions defeat bindgen's layout engine), so the Rust-side finalizer
 * OR-s ol_flags and sets the l2/l3/l4_len triple through these shims.
 * The getters back unit-test assertions; production callers only need
 * the setters. */
void shim_rte_mbuf_or_ol_flags(struct rte_mbuf *m, uint64_t flags) {
    m->ol_flags |= flags;
}

void shim_rte_mbuf_set_tx_lens(struct rte_mbuf *m, uint16_t l2, uint16_t l3, uint16_t l4) {
    m->l2_len = l2;
    m->l3_len = l3;
    m->l4_len = l4;
}

uint64_t shim_rte_mbuf_get_ol_flags(const struct rte_mbuf *m) {
    return m->ol_flags;
}

/* The following mbuf getters (l2_len/l3_len/l4_len) are reserved for the
 * A-HW Task 18 smoke test (ahw_smoke_ena_hw.rs) and future diagnostic
 * tooling. They are intentionally not gated — linking them unconditionally
 * keeps the bindgen allowlist pattern (`shim_rte_.*`) simple. See A-HW spec
 * §12.3. */
uint16_t shim_rte_mbuf_get_l2_len(const struct rte_mbuf *m) {
    return (uint16_t)m->l2_len;
}

uint16_t shim_rte_mbuf_get_l3_len(const struct rte_mbuf *m) {
    return (uint16_t)m->l3_len;
}

uint16_t shim_rte_mbuf_get_l4_len(const struct rte_mbuf *m) {
    return (uint16_t)m->l4_len;
}

/* A-HW Task 9: RSS hash accessor. `mbuf.hash` is a nested anonymous
 * union in rte_mbuf.h which bindgen does not expose cleanly, so the
 * Rust RX hot path reads `hash.rss` via this shim. Paired with the
 * flow_table::hash_bucket_for_lookup selector — only called when the
 * `hw-offload-rss-hash` feature is compiled in. */
uint32_t shim_rte_mbuf_get_rss_hash(const struct rte_mbuf *m) {
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
uint64_t shim_rte_mbuf_read_dynfield_u64(const struct rte_mbuf *m, int32_t offset) {
    /* x86_64 tolerates unaligned 8-byte loads, but ARM64 is strict. The
     * DPDK dynfield registrar returns an 8-byte-aligned offset for u64
     * fields; this assert catches misconfigured PMDs in debug builds
     * before a stray SIGBUS on a future ARM target. NOP when NDEBUG is
     * defined (release builds). */
    assert(offset >= 0);
    assert((offset & 0x7) == 0 && "dynfield offset must be 8-byte aligned (u64 field)");
    return *(const uint64_t *)((const char *)m + offset);
}

/* phase-a-hw-plus T3: expose the prefetchable BAR (BAR2) physical
 * address for an ENA port. The ENA PMD per upstream
 * drivers/net/ena/ena_ethdev.c uses BAR2 for the prefetchable region
 * that must be mapped write-combining under LLQ. Returns 0 when the
 * port is not a PCI device, BAR2 is unmapped, or dev_info fails —
 * callers treat 0 as "unavailable, skip verification". */
uint64_t shim_rte_eth_dev_prefetchable_bar_phys(uint16_t port_id) {
#ifdef DPDK_HAS_PCI_SDK
    struct rte_eth_dev_info info;
    if (rte_eth_dev_info_get(port_id, &info) != 0) {
        return 0;
    }
    if (!info.device) {
        return 0;
    }
    struct rte_pci_device *pci = RTE_DEV_TO_PCI(info.device);
    if (!pci) {
        return 0;
    }
    return (uint64_t)pci->mem_resource[2].phys_addr;
#else
    /* DPDK driver-SDK headers unavailable at build time — cannot deref
     * `struct rte_pci_device`. Returning 0 triggers the Rust-side
     * "BAR address unavailable, skip verification" path. */
    (void)port_id;
    return 0;
#endif
}
