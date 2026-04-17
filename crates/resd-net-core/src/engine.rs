use resd_net_sys as sys;
use std::cell::RefCell;
use std::ffi::CString;
use std::sync::Mutex;

use crate::counters::Counters;
use crate::icmp::PmtuTable;
use crate::mempool::Mempool;
use crate::Error;

/// Config passed to Engine::new.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub lcore_id: u16,
    pub port_id: u16,
    pub rx_queue_id: u16,
    pub tx_queue_id: u16,
    pub rx_ring_size: u16,     // default 1024
    pub tx_ring_size: u16,     // default 1024
    pub rx_mempool_elems: u32, // default 8192
    pub mbuf_data_room: u16,   // default 2048

    // Phase A2 additions (host byte order for IPs; raw bytes for MAC)
    pub local_ip: u32,         // our IPv4 on this lcore's port; 0 = "accept any" in tests
    pub gateway_ip: u32,       // next-hop IPv4
    pub gateway_mac: [u8; 6],  // MAC to target for TX; [0;6] = "resolve at create"
    pub garp_interval_sec: u32,// 0 = disabled; else emit gratuitous ARP every N seconds
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            lcore_id: 0,
            port_id: 0,
            rx_queue_id: 0,
            tx_queue_id: 0,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            rx_mempool_elems: 8192,
            mbuf_data_room: 2048,
            local_ip: 0,
            gateway_ip: 0,
            gateway_mac: [0u8; 6],
            garp_interval_sec: 0,
        }
    }
}

/// A resd-net engine. One per lcore; owns the NIC queues, mempools, and
/// L2/L3 state for that lcore.
pub struct Engine {
    cfg: EngineConfig,
    counters: Box<Counters>,
    _rx_mempool: Mempool,
    tx_hdr_mempool: Mempool,
    _tx_data_mempool: Mempool,
    our_mac: [u8; 6],
    pmtu: RefCell<PmtuTable>,
    last_garp_ns: RefCell<u64>,
}

/// EAL is process-global; only initialize once.
static EAL_INIT: Mutex<bool> = Mutex::new(false);

pub fn eal_init(args: &[&str]) -> Result<(), Error> {
    let mut guard = EAL_INIT.lock().unwrap();
    if *guard {
        return Ok(());
    }
    let cstrs: Vec<CString> = args.iter().map(|s| CString::new(*s).unwrap()).collect();
    let mut argv: Vec<*mut libc::c_char> = cstrs.iter().map(|c| c.as_ptr() as *mut _).collect();
    // Safety: rte_eal_init mutates argv internally; we pass the constructed array.
    let rc = unsafe { sys::rte_eal_init(argv.len() as i32, argv.as_mut_ptr()) };
    if rc < 0 {
        return Err(Error::EalInit(unsafe { sys::resd_rte_errno() }));
    }
    *guard = true;
    Ok(())
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> Result<Self, Error> {
        // Fail fast on non-invariant-TSC hosts (spec §7.5). Also primes
        // the global TscEpoch so later now_ns() calls don't pay the
        // 50ms calibration cost on the hot path.
        crate::clock::init()?;

        // socket_id may be -1 (cast to 0xFFFFFFFF == SOCKET_ID_ANY) when the
        // port isn't bound to a NUMA node (common in VMs / TAP devices).
        // That's the DPDK sentinel and is valid for mempool/queue setup.
        let socket_id = unsafe { sys::rte_eth_dev_socket_id(cfg.port_id) } as i32;
        // Queue-setup FFI takes c_uint; the `as u32` cast of a negative int
        // preserves the bit pattern (-1 → 0xFFFFFFFF == SOCKET_ID_ANY).
        let socket_id_u = socket_id as u32;

        // Allocate three mempools per spec §7.1.
        let rx_mempool = Mempool::new_pktmbuf(
            &format!("rx_mp_{}", cfg.lcore_id),
            cfg.rx_mempool_elems,
            256,
            0,
            cfg.mbuf_data_room + sys::RTE_PKTMBUF_HEADROOM as u16,
            socket_id,
        )?;
        let tx_hdr_mempool = Mempool::new_pktmbuf(
            &format!("tx_hdr_mp_{}", cfg.lcore_id),
            2048,
            64,
            0,
            256,
            socket_id,
        )?;
        let tx_data_mempool = Mempool::new_pktmbuf(
            &format!("tx_data_mp_{}", cfg.lcore_id),
            4096,
            128,
            0,
            cfg.mbuf_data_room + sys::RTE_PKTMBUF_HEADROOM as u16,
            socket_id,
        )?;

        // Configure port: one RX queue + one TX queue for Phase A1.
        let eth_conf: sys::rte_eth_conf = unsafe { std::mem::zeroed() };
        let rc = unsafe { sys::rte_eth_dev_configure(cfg.port_id, 1, 1, &eth_conf as *const _) };
        if rc != 0 {
            return Err(Error::PortConfigure(cfg.port_id, unsafe {
                sys::resd_rte_errno()
            }));
        }

        let rc = unsafe {
            sys::rte_eth_rx_queue_setup(
                cfg.port_id,
                cfg.rx_queue_id,
                cfg.rx_ring_size,
                socket_id_u,
                std::ptr::null(),
                rx_mempool.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(Error::RxQueueSetup(cfg.port_id, unsafe {
                sys::resd_rte_errno()
            }));
        }

        let rc = unsafe {
            sys::rte_eth_tx_queue_setup(
                cfg.port_id,
                cfg.tx_queue_id,
                cfg.tx_ring_size,
                socket_id_u,
                std::ptr::null(),
            )
        };
        if rc < 0 {
            return Err(Error::TxQueueSetup(cfg.port_id, unsafe {
                sys::resd_rte_errno()
            }));
        }

        let rc = unsafe { sys::rte_eth_dev_start(cfg.port_id) };
        if rc < 0 {
            return Err(Error::PortStart(cfg.port_id, unsafe {
                sys::resd_rte_errno()
            }));
        }

        // Read NIC MAC via the shim. `rte_ether_addr` is a 6-byte packed struct.
        let mut mac_addr: sys::rte_ether_addr = unsafe { std::mem::zeroed() };
        let rc = unsafe { sys::resd_rte_eth_macaddr_get(cfg.port_id, &mut mac_addr) };
        if rc != 0 {
            return Err(Error::MacAddrLookup(cfg.port_id, unsafe { sys::resd_rte_errno() }));
        }
        // bindgen names the field `addr_bytes` on rte_ether_addr.
        let our_mac = mac_addr.addr_bytes;

        let counters = Box::new(Counters::new());

        Ok(Self {
            cfg,
            counters,
            _rx_mempool: rx_mempool,
            tx_hdr_mempool,
            _tx_data_mempool: tx_data_mempool,
            our_mac,
            pmtu: RefCell::new(PmtuTable::new()),
            last_garp_ns: RefCell::new(0),
        })
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn our_mac(&self) -> [u8; 6] { self.our_mac }
    pub fn our_ip(&self) -> u32 { self.cfg.local_ip }
    pub fn gateway_mac(&self) -> [u8; 6] { self.cfg.gateway_mac }
    pub fn gateway_ip(&self) -> u32 { self.cfg.gateway_ip }
    pub fn pmtu_for(&self, ip: u32) -> Option<u16> { self.pmtu.borrow().get(ip) }

    /// TX a self-contained ≤256-byte frame (ARP in Phase A2). Allocates one
    /// mbuf from tx_hdr_mempool, copies `bytes` into its data room via the
    /// `rte_pktmbuf_append` shim, then submits via a single-packet burst.
    /// Bumps `eth.tx_pkts` / `eth.tx_bytes` / `eth.tx_drop_nomem` /
    /// `eth.tx_drop_full_ring` as appropriate. Returns true if the packet
    /// was accepted by the driver.
    pub(crate) fn tx_frame(&self, bytes: &[u8]) -> bool {
        use crate::counters::{add, inc};
        // Safety: tx_hdr_mempool was created in Engine::new and is alive.
        let m = unsafe { sys::resd_rte_pktmbuf_alloc(self.tx_hdr_mempool.as_ptr()) };
        if m.is_null() {
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        // Safety: append writes into the mbuf's data room. Returns NULL if
        // the mbuf's tailroom is < len.
        let dst = unsafe { sys::resd_rte_pktmbuf_append(m, bytes.len() as u16) };
        if dst.is_null() {
            unsafe { sys::resd_rte_pktmbuf_free(m) };
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        // Safety: dst points to `bytes.len()` writable bytes inside the mbuf.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len());
        }
        let mut pkts = [m];
        let sent = unsafe {
            sys::resd_rte_eth_tx_burst(
                self.cfg.port_id,
                self.cfg.tx_queue_id,
                pkts.as_mut_ptr(),
                1,
            )
        } as usize;
        if sent == 1 {
            add(&self.counters.eth.tx_bytes, bytes.len() as u64);
            inc(&self.counters.eth.tx_pkts);
            true
        } else {
            // TX ring full; driver did not take the mbuf. Free it ourselves.
            unsafe { sys::resd_rte_pktmbuf_free(m) };
            inc(&self.counters.eth.tx_drop_full_ring);
            false
        }
    }

    /// One iteration of the run-to-completion loop.
    /// In Phase A1, this rx-bursts and drops everything, then tx-bursts nothing.
    /// Subsequent phases add real processing.
    pub fn poll_once(&self) -> usize {
        use crate::counters::inc;
        inc(&self.counters.poll.iters);

        const BURST: usize = 32;
        let mut mbufs: [*mut sys::rte_mbuf; BURST] = [std::ptr::null_mut(); BURST];
        // `rte_eth_rx_burst` is static-inline in DPDK headers, so we call
        // the `resd_` extern wrapper defined in shim.c.
        let n = unsafe {
            sys::resd_rte_eth_rx_burst(
                self.cfg.port_id,
                self.cfg.rx_queue_id,
                mbufs.as_mut_ptr(),
                BURST as u16,
            )
        } as usize;
        if n > 0 {
            inc(&self.counters.poll.iters_with_rx);
            crate::counters::add(&self.counters.eth.rx_pkts, n as u64);
            for m in &mbufs[..n] {
                // Drop each mbuf via the shim wrapper (rte_pktmbuf_free is
                // static-inline and not exposed by bindgen).
                unsafe { sys::resd_rte_pktmbuf_free(*m) };
            }
        } else {
            inc(&self.counters.poll.iters_idle);
        }
        n
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Safety: we previously started the port; stop and close on drop.
        unsafe {
            sys::rte_eth_dev_stop(self.cfg.port_id);
            sys::rte_eth_dev_close(self.cfg.port_id);
        }
        // Mempools drop via their own Drop impl.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_engine_config_has_a2_fields() {
        let cfg = EngineConfig::default();
        // Unset (caller must supply for real use).
        assert_eq!(cfg.local_ip, 0);
        assert_eq!(cfg.gateway_ip, 0);
        assert_eq!(cfg.gateway_mac, [0u8; 6]);
        // 0 = disabled (no gratuitous ARP emitted).
        assert_eq!(cfg.garp_interval_sec, 0);
    }

    #[test]
    fn engine_exposes_addressing_and_pmtu() {
        // Unit-test smoke: engine struct has the new accessors. We can't
        // actually construct an Engine without EAL, so test the types.
        fn _check(_e: &Engine) {
            let _: [u8; 6] = _e.our_mac();
            let _: u32 = _e.our_ip();
            let _: [u8; 6] = _e.gateway_mac();
            // PmtuTable read: exposed via counters-style getter for observability.
            let _: Option<u16> = _e.pmtu_for(0);
        }
        // If this compiles, the methods exist.
    }
}
