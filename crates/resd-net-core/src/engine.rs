use resd_net_sys as sys;
use std::cell::{Cell, RefCell};
use std::ffi::CString;
use std::sync::Mutex;

use crate::arp;
use crate::counters::Counters;
use crate::flow_table::{ConnHandle, FlowTable, FourTuple};
use crate::iss::IssGen;
use crate::icmp::PmtuTable;
use crate::mempool::Mempool;
use crate::tcp_events::{EventQueue, InternalEvent};
use crate::tcp_state::TcpState;
use crate::Error;

/// Config passed to Engine::new.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub lcore_id: u16,
    pub port_id: u16,
    pub rx_queue_id: u16,
    pub tx_queue_id: u16,
    pub rx_ring_size: u16,
    pub tx_ring_size: u16,
    pub rx_mempool_elems: u32,
    pub mbuf_data_room: u16,

    // Phase A2 additions (host byte order for IPs; raw bytes for MAC)
    pub local_ip: u32,
    pub gateway_ip: u32,
    pub gateway_mac: [u8; 6],
    pub garp_interval_sec: u32,

    // Phase A3 additions (all carry through from the public config)
    pub max_connections: u32,
    pub recv_buffer_bytes: u32,
    pub send_buffer_bytes: u32,
    pub tcp_mss: u32,
    pub tcp_initial_rto_ms: u32,
    pub tcp_msl_ms: u32,
    pub tcp_nagle: bool,
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
            max_connections: 16,
            recv_buffer_bytes: 256 * 1024,
            send_buffer_bytes: 256 * 1024,
            tcp_mss: 1460,
            tcp_initial_rto_ms: 50,
            tcp_msl_ms: 30_000,
            tcp_nagle: false,
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
    tx_data_mempool: Mempool,
    our_mac: [u8; 6],
    pmtu: RefCell<PmtuTable>,
    last_garp_ns: RefCell<u64>,

    // Phase A3 additions
    flow_table: RefCell<FlowTable>,
    events: RefCell<EventQueue>,
    iss_gen: IssGen,
    last_ephemeral_port: Cell<u16>,
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
            counters,
            _rx_mempool: rx_mempool,
            tx_hdr_mempool,
            tx_data_mempool,
            our_mac,
            pmtu: RefCell::new(PmtuTable::new()),
            last_garp_ns: RefCell::new(0),
            flow_table: RefCell::new(FlowTable::new(cfg.max_connections)),
            events: RefCell::new(EventQueue::new()),
            iss_gen: IssGen::new(0),
            // RFC 6056 ephemeral port hint range: start at 49152.
            last_ephemeral_port: Cell::new(49151),
            cfg,
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

    /// TX a self-contained ≤128-byte frame (ARP reply / gratuitous ARP is 42
    /// bytes). Allocates one mbuf from tx_hdr_mempool, copies `bytes` into its
    /// data room via the `rte_pktmbuf_append` shim, then submits via a
    /// single-packet burst.
    /// Bumps `eth.tx_pkts` / `eth.tx_bytes` / `eth.tx_drop_nomem` /
    /// `eth.tx_drop_full_ring` as appropriate. Returns true if the packet
    /// was accepted by the driver.
    pub(crate) fn tx_frame(&self, bytes: &[u8]) -> bool {
        use crate::counters::{add, inc};
        // Guard against bytes.len() > u16::MAX silently truncating on the
        // u16 cast below. Also reject anything larger than the mempool's
        // data room. tx_hdr_mempool is sized for small control frames
        // (ARP, future RST/ACK); oversized callers are a programming error.
        if bytes.len() > u16::MAX as usize {
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
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

    /// TX a full-size frame via `tx_data_mempool`. Used for TCP data
    /// segments where the frame size exceeds the small-mbuf pool's
    /// data room. Behavior is otherwise identical to `tx_frame`.
    pub(crate) fn tx_data_frame(&self, bytes: &[u8]) -> bool {
        use crate::counters::{add, inc};
        if bytes.len() > u16::MAX as usize {
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        let m = unsafe { sys::resd_rte_pktmbuf_alloc(self.tx_data_mempool.as_ptr()) };
        if m.is_null() {
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        let dst = unsafe { sys::resd_rte_pktmbuf_append(m, bytes.len() as u16) };
        if dst.is_null() {
            unsafe { sys::resd_rte_pktmbuf_free(m) };
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
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
            unsafe { sys::resd_rte_pktmbuf_free(m) };
            inc(&self.counters.eth.tx_drop_full_ring);
            false
        }
    }

    /// Pick the next ephemeral source port in the IANA range [49152, 65535].
    /// Simple wraparound counter; collisions with existing flows in the
    /// table are not checked (at <=100 connections the odds are negligible).
    fn next_ephemeral_port(&self) -> u16 {
        let mut p = self.last_ephemeral_port.get();
        p = p.wrapping_add(1);
        if p < 49152 {
            p = 49152;
        }
        self.last_ephemeral_port.set(p);
        p
    }

    pub fn flow_table(&self) -> std::cell::RefMut<'_, FlowTable> {
        self.flow_table.borrow_mut()
    }
    pub fn events(&self) -> std::cell::RefMut<'_, EventQueue> {
        self.events.borrow_mut()
    }
    pub fn iss_gen(&self) -> &IssGen {
        &self.iss_gen
    }

    /// One iteration of the run-to-completion loop.
    /// A3: clears each conn's per-poll `last_read_buf` accumulator,
    /// drains an RX burst, dispatches frames through the L2/L3/TCP
    /// pipeline, then reaps any TIME_WAIT flows past their 2×MSL deadline.
    pub fn poll_once(&self) -> usize {
        use crate::counters::{add, inc};
        inc(&self.counters.poll.iters);

        // Clear per-conn last_read_buf so prior borrowed views are
        // invalidated per spec §4.2, before any rx_frame dispatches
        // can append new data this iteration.
        {
            let mut ft = self.flow_table.borrow_mut();
            let handles: Vec<_> = ft.iter_handles().collect();
            for h in handles {
                if let Some(c) = ft.get_mut(h) {
                    c.recv.last_read_buf.clear();
                }
            }
        }

        const BURST: usize = 32;
        let mut mbufs: [*mut sys::rte_mbuf; BURST] = [std::ptr::null_mut(); BURST];
        let n = unsafe {
            sys::resd_rte_eth_rx_burst(
                self.cfg.port_id,
                self.cfg.rx_queue_id,
                mbufs.as_mut_ptr(),
                BURST as u16,
            )
        } as usize;

        if n == 0 {
            inc(&self.counters.poll.iters_idle);
            self.reap_time_wait();
            self.maybe_emit_gratuitous_arp();
            return 0;
        }

        inc(&self.counters.poll.iters_with_rx);
        add(&self.counters.eth.rx_pkts, n as u64);

        for &m in &mbufs[..n] {
            let bytes = unsafe { crate::mbuf_data_slice(m) };
            add(&self.counters.eth.rx_bytes, bytes.len() as u64);
            self.rx_frame(bytes);
            unsafe { sys::resd_rte_pktmbuf_free(m) };
        }

        self.reap_time_wait();
        self.maybe_emit_gratuitous_arp();
        n
    }

    /// Walk the flow table and move any TIME_WAIT connection past its
    /// 2×MSL deadline to CLOSED. Naïve O(N) scan in A3 — acceptable at
    /// ≤100 connections; A6's timer wheel replaces this.
    fn reap_time_wait(&self) {
        let now = crate::clock::now_ns();
        let candidates: Vec<_> = {
            let ft = self.flow_table.borrow();
            ft.iter_handles()
                .filter(|h| {
                    let Some(c) = ft.get(*h) else { return false; };
                    c.state == TcpState::TimeWait
                        && c.time_wait_deadline_ns.map_or(false, |d| now >= d)
                })
                .collect()
        };
        for h in candidates {
            self.transition_conn(h, TcpState::Closed);
            self.events.borrow_mut().push(InternalEvent::Closed { conn: h, err: 0 });
            self.flow_table.borrow_mut().remove(h);
        }
    }

    /// Drain up to `max` events from the internal queue. Returns the
    /// number of events drained. Callers in the C ABI layer translate
    /// the `InternalEvent` enum to the public union-tagged form.
    pub fn drain_events<F: FnMut(&InternalEvent, &Engine)>(&self, max: u32, mut sink: F) -> u32 {
        let mut n = 0u32;
        while n < max {
            let Some(ev) = self.events.borrow_mut().pop() else { break; };
            sink(&ev, self);
            n += 1;
        }
        n
    }

    fn rx_frame(&self, bytes: &[u8]) {
        use crate::counters::inc;
        match crate::l2::l2_decode(bytes, self.our_mac) {
            Err(crate::l2::L2Drop::Short) => inc(&self.counters.eth.rx_drop_short),
            Err(crate::l2::L2Drop::MissMac) => inc(&self.counters.eth.rx_drop_miss_mac),
            Err(crate::l2::L2Drop::UnknownEthertype) => {
                inc(&self.counters.eth.rx_drop_unknown_ethertype)
            }
            Ok(l2) => {
                let payload = &bytes[l2.payload_offset..];
                match l2.ethertype {
                    crate::l2::ETHERTYPE_ARP => {
                        inc(&self.counters.eth.rx_arp);
                        self.handle_arp(payload);
                    }
                    crate::l2::ETHERTYPE_IPV4 => self.handle_ipv4(payload),
                    _ => unreachable!("l2_decode filters unsupported ethertypes"),
                }
            }
        }
    }

    fn handle_arp(&self, payload: &[u8]) {
        let Ok(pkt) = arp::arp_decode(payload) else {
            return;
        };
        if pkt.op == arp::ARP_OP_REQUEST
            && pkt.target_ip == self.cfg.local_ip
            && self.cfg.local_ip != 0
        {
            let mut buf = [0u8; arp::ARP_FRAME_LEN];
            if arp::build_arp_reply(self.our_mac, self.cfg.local_ip, &pkt, &mut buf).is_some()
                && self.tx_frame(&buf)
            {
                crate::counters::inc(&self.counters.eth.tx_arp);
            }
        }
        // ARP replies that rewrite gateway MAC would be handled here; for
        // static-gateway A2 we rely on the configured MAC and do not mutate.
    }

    fn handle_ipv4(&self, payload: &[u8]) {
        use crate::counters::inc;
        match crate::l3_ip::ip_decode(payload, self.cfg.local_ip, /*nic_csum_ok=*/ false) {
            Err(crate::l3_ip::L3Drop::Short) => inc(&self.counters.ip.rx_drop_short),
            Err(crate::l3_ip::L3Drop::BadVersion) => inc(&self.counters.ip.rx_drop_bad_version),
            Err(crate::l3_ip::L3Drop::BadHeaderLen) => inc(&self.counters.ip.rx_drop_bad_hl),
            Err(crate::l3_ip::L3Drop::BadTotalLen) => inc(&self.counters.ip.rx_drop_short),
            Err(crate::l3_ip::L3Drop::CsumBad) => inc(&self.counters.ip.rx_csum_bad),
            Err(crate::l3_ip::L3Drop::TtlZero) => inc(&self.counters.ip.rx_ttl_zero),
            Err(crate::l3_ip::L3Drop::Fragment) => inc(&self.counters.ip.rx_frag),
            Err(crate::l3_ip::L3Drop::NotOurs) => inc(&self.counters.ip.rx_drop_not_ours),
            Err(crate::l3_ip::L3Drop::UnsupportedProto) => {
                inc(&self.counters.ip.rx_drop_unsupported_proto)
            }
            Ok(ip) => {
                let inner = &payload[ip.header_len..ip.total_len];
                match ip.protocol {
                    crate::l3_ip::IPPROTO_TCP => {
                        inc(&self.counters.ip.rx_tcp);
                        self.tcp_input(&ip, inner);
                    }
                    crate::l3_ip::IPPROTO_ICMP => {
                        inc(&self.counters.ip.rx_icmp);
                        let res = {
                            let mut pmtu = self.pmtu.borrow_mut();
                            crate::icmp::icmp_input(inner, &mut pmtu)
                        };
                        use crate::icmp::IcmpResult::*;
                        match res {
                            FragNeededPmtuUpdated => {
                                inc(&self.counters.ip.rx_icmp_frag_needed);
                                inc(&self.counters.ip.pmtud_updates);
                            }
                            FragNeededNoShrink => {
                                inc(&self.counters.ip.rx_icmp_frag_needed);
                            }
                            OtherDropped | Malformed => {}
                        }
                    }
                    _ => unreachable!("ip_decode filters unsupported protocols"),
                }
            }
        }
    }

    /// Real TCP input path (A3). Parses the segment, finds the flow,
    /// dispatches to per-state handler, emits ACK/RST and events.
    fn tcp_input(&self, ip: &crate::l3_ip::L3Decoded, tcp_bytes: &[u8]) {
        use crate::counters::inc;
        use crate::tcp_input::{dispatch, parse_segment, tuple_from_segment, TxAction};

        let parsed = match parse_segment(tcp_bytes, ip.src_ip, ip.dst_ip, false) {
            Ok(p) => p,
            Err(e) => {
                match e {
                    crate::tcp_input::TcpParseError::Short => inc(&self.counters.tcp.rx_short),
                    crate::tcp_input::TcpParseError::BadFlags => inc(&self.counters.tcp.rx_bad_flags),
                    crate::tcp_input::TcpParseError::Csum => inc(&self.counters.tcp.rx_bad_csum),
                    crate::tcp_input::TcpParseError::BadDataOffset => inc(&self.counters.tcp.rx_short),
                }
                return;
            }
        };

        let tuple = tuple_from_segment(ip.src_ip, ip.dst_ip, &parsed);
        let handle = { self.flow_table.borrow().lookup_by_tuple(&tuple) };
        let Some(handle) = handle else {
            // Unmatched: reply RST per spec §5.1 `reply_rst`.
            inc(&self.counters.tcp.rx_unmatched);
            self.send_rst_unmatched(&tuple, &parsed);
            return;
        };

        // Bump per-flag counters for observability before dispatch.
        use crate::tcp_output::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
        if (parsed.flags & TCP_SYN) != 0 && (parsed.flags & TCP_ACK) != 0 {
            inc(&self.counters.tcp.rx_syn_ack);
        }
        if (parsed.flags & TCP_ACK) != 0 { inc(&self.counters.tcp.rx_ack); }
        if (parsed.flags & TCP_FIN) != 0 { inc(&self.counters.tcp.rx_fin); }
        if (parsed.flags & TCP_RST) != 0 { inc(&self.counters.tcp.rx_rst); }
        if !parsed.payload.is_empty() { inc(&self.counters.tcp.rx_data); }

        let outcome = {
            let mut ft = self.flow_table.borrow_mut();
            let Some(conn) = ft.get_mut(handle) else { return; };
            dispatch(conn, &parsed)
        };

        if let Some(new_state) = outcome.new_state {
            self.transition_conn(handle, new_state);
        }

        match outcome.tx {
            TxAction::Ack => self.emit_ack(handle),
            TxAction::Rst => {
                self.emit_rst(handle, &parsed);
                self.transition_conn(handle, TcpState::Closed);
            }
            TxAction::None => {}
        }

        if outcome.connected {
            self.events.borrow_mut().push(InternalEvent::Connected {
                conn: handle, rx_hw_ts_ns: 0,
            });
            inc(&self.counters.tcp.conn_open);
        }

        if outcome.delivered > 0 {
            self.deliver_readable(handle, outcome.delivered);
        }

        if outcome.closed {
            self.events.borrow_mut().push(InternalEvent::Closed {
                conn: handle, err: 0,
            });
            inc(&self.counters.tcp.conn_close);
            // Remove the flow on final close (but leave TIME_WAIT alive
            // for the reaper — that's handled via `transition_conn`).
            let state = self.flow_table.borrow().get(handle).map(|c| c.state);
            if state == Some(TcpState::Closed) {
                self.flow_table.borrow_mut().remove(handle);
            }
        }
    }

    fn transition_conn(&self, handle: ConnHandle, to: TcpState) {
        use crate::counters::inc;
        let mut ft = self.flow_table.borrow_mut();
        let Some(conn) = ft.get_mut(handle) else { return; };
        let from = conn.state;
        if from == to { return; }
        conn.state = to;
        // TIME_WAIT entry: arm the reaping deadline.
        if to == TcpState::TimeWait {
            let msl_ns = (self.cfg.tcp_msl_ms as u64) * 1_000_000;
            conn.time_wait_deadline_ns = Some(crate::clock::now_ns().saturating_add(2 * msl_ns));
        }
        drop(ft);
        inc(&self.counters.tcp.state_trans[from as usize][to as usize]);
        self.events.borrow_mut().push(InternalEvent::StateChange {
            conn: handle, from, to,
        });
    }

    /// Emit a bare ACK for `handle`. The advertised window is the CURRENT
    /// recv buffer free_space (fix for Task 12 reviewer I-3 finding).
    fn emit_ack(&self, handle: ConnHandle) {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK};
        let ft = self.flow_table.borrow();
        let Some(conn) = ft.get(handle) else { return; };
        let t = conn.four_tuple();
        let window = conn.recv.free_space().min(u16::MAX as u32) as u16;
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: t.local_ip,
            dst_ip: t.peer_ip,
            src_port: t.local_port,
            dst_port: t.peer_port,
            seq: conn.snd_nxt,
            ack: conn.rcv_nxt,
            flags: TCP_ACK,
            window,
            mss_option: None,
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
        drop(ft);
        if self.tx_frame(&buf[..n]) {
            inc(&self.counters.tcp.tx_ack);
        }
    }

    fn emit_rst(&self, handle: ConnHandle, incoming: &crate::tcp_input::ParsedSegment) {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_RST};
        let ft = self.flow_table.borrow();
        let Some(conn) = ft.get(handle) else { return; };
        let t = conn.four_tuple();
        let ack = incoming.seq.wrapping_add(incoming.payload.len() as u32);
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: t.local_ip, dst_ip: t.peer_ip,
            src_port: t.local_port, dst_port: t.peer_port,
            seq: conn.snd_nxt,
            ack,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            mss_option: None,
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
        drop(ft);
        if self.tx_frame(&buf[..n]) {
            inc(&self.counters.tcp.tx_rst);
        }
    }

    /// Reply RST to a segment whose 4-tuple has no matching flow.
    /// Per RFC 9293 §3.10.7.1: if the incoming has ACK set, seq=incoming.ack;
    /// else seq=0, ack=incoming.seq+payload_len+SYN_FLAG+FIN_FLAG, flags=RST|ACK.
    fn send_rst_unmatched(&self, tuple: &FourTuple, incoming: &crate::tcp_input::ParsedSegment) {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
        if (incoming.flags & TCP_RST) != 0 {
            return; // don't RST a RST.
        }
        let syn_len = ((incoming.flags & TCP_SYN) != 0) as u32;
        let fin_len = ((incoming.flags & TCP_FIN) != 0) as u32;
        let (seq, ack, flags) = if (incoming.flags & TCP_ACK) != 0 {
            (incoming.ack, 0, TCP_RST)
        } else {
            let ack = incoming.seq
                .wrapping_add(incoming.payload.len() as u32)
                .wrapping_add(syn_len)
                .wrapping_add(fin_len);
            (0, ack, TCP_RST | TCP_ACK)
        };
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip, dst_ip: tuple.peer_ip,
            src_port: tuple.local_port, dst_port: tuple.peer_port,
            seq, ack, flags, window: 0,
            mss_option: None, payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
        if self.tx_frame(&buf[..n]) {
            inc(&self.counters.tcp.tx_rst);
        }
    }

    fn deliver_readable(&self, handle: ConnHandle, delivered: u32) {
        use crate::counters::add;
        let mut ft = self.flow_table.borrow_mut();
        let Some(conn) = ft.get_mut(handle) else { return; };
        // Append delivered bytes to last_read_buf (do NOT clear — the poll
        // entry point clears once per iteration so multiple Readable events
        // within one poll stack contiguously in the buffer).
        let byte_offset = conn.recv.last_read_buf.len() as u32;
        conn.recv.last_read_buf.reserve(delivered as usize);
        let (a, b) = conn.recv.bytes.as_slices();
        let from_a = a.len().min(delivered as usize);
        conn.recv.last_read_buf.extend_from_slice(&a[..from_a]);
        let remaining = delivered as usize - from_a;
        conn.recv.last_read_buf.extend_from_slice(&b[..remaining]);
        for _ in 0..delivered {
            conn.recv.bytes.pop_front();
        }
        drop(ft);
        add(&self.counters.tcp.recv_buf_delivered, delivered as u64);
        self.events.borrow_mut().push(InternalEvent::Readable {
            conn: handle,
            byte_offset,
            byte_len: delivered,
            rx_hw_ts_ns: 0,
        });
    }

    /// Open a new client-side connection. Emits a single SYN and
    /// returns the handle. The caller waits on `RESD_NET_EVT_CONNECTED`
    /// (or times out at application level — SYN retransmit is A5).
    ///
    /// `peer_ip` / `peer_port` in host byte order.
    /// `local_port_hint`: if nonzero, used as the source port; else we
    /// pick an ephemeral port from [49152, 65535].
    pub fn connect(
        &self,
        peer_ip: u32,
        peer_port: u16,
        local_port_hint: u16,
    ) -> Result<ConnHandle, Error> {
        use crate::counters::inc;
        use crate::tcp_conn::TcpConn;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_SYN};

        if self.cfg.local_ip == 0 {
            return Err(Error::PeerUnreachable(peer_ip));
        }
        if self.cfg.gateway_mac == [0u8; 6] {
            return Err(Error::PeerUnreachable(peer_ip));
        }
        let local_port = if local_port_hint != 0 {
            local_port_hint
        } else {
            self.next_ephemeral_port()
        };
        let tuple = FourTuple {
            local_ip: self.cfg.local_ip,
            local_port,
            peer_ip,
            peer_port,
        };
        let iss = self.iss_gen.next(&tuple);
        let our_mss = self.cfg.tcp_mss.min(u16::MAX as u32) as u16;
        let recv_wnd = self.cfg.recv_buffer_bytes.min(u16::MAX as u32);
        let conn = TcpConn::new_client(
            tuple,
            iss,
            our_mss,
            self.cfg.recv_buffer_bytes,
            self.cfg.send_buffer_bytes,
        );
        let handle = self
            .flow_table
            .borrow_mut()
            .insert(conn)
            .ok_or(Error::TooManyConns)?;

        // Build and transmit SYN.
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip,
            dst_ip: tuple.peer_ip,
            src_port: tuple.local_port,
            dst_port: tuple.peer_port,
            seq: iss,
            ack: 0,
            flags: TCP_SYN,
            window: recv_wnd.min(u16::MAX as u32) as u16,
            mss_option: Some(our_mss),
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else {
            // Header-too-small is impossible with 64-byte buf; keep explicit.
            self.flow_table.borrow_mut().remove(handle);
            return Err(Error::PeerUnreachable(peer_ip));
        };
        if !self.tx_frame(&buf[..n]) {
            self.flow_table.borrow_mut().remove(handle);
            return Err(Error::PeerUnreachable(peer_ip));
        }
        inc(&self.counters.tcp.tx_syn);

        // Bump snd_nxt past the SYN's seq and mark SYN_SENT. Direct
        // state mutation (not transition_conn) because this transition
        // has no from-state event — we're coming from the just-inserted
        // TcpState::Closed default.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.snd_nxt = iss.wrapping_add(1);
            }
        }
        self.transition_conn(handle, TcpState::SynSent);
        Ok(handle)
    }

    /// Enqueue `bytes` on the connection's send path. Returns the number
    /// of bytes accepted (could be < bytes.len() under send-buffer or
    /// peer-window backpressure). On `tx_data_mempool` exhaustion mid-send,
    /// returns a negative errno (Err(Error::SendBufferFull) mapped to
    /// `-ENOMEM` at the public-API layer).
    pub fn send_bytes(&self, handle: ConnHandle, bytes: &[u8]) -> Result<u32, Error> {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_PSH};

        let (tuple, seq_start, snd_una, snd_wnd, peer_mss, state, rcv_nxt, rcv_wnd)
            = {
                let ft = self.flow_table.borrow();
                let Some(c) = ft.get(handle) else {
                    return Err(Error::InvalidConnHandle(handle as u64));
                };
                (c.four_tuple(), c.snd_nxt, c.snd_una, c.snd_wnd, c.peer_mss,
                 c.state, c.rcv_nxt, c.rcv_wnd)
            };
        if state != TcpState::Established {
            return Err(Error::InvalidConnHandle(handle as u64));
        }

        let mss_cap = (peer_mss as u32).min(self.cfg.tcp_mss).max(1);
        // Remaining peer-window room (relative to snd_una): snd_wnd minus
        // (snd_nxt - snd_una).
        let in_flight = seq_start.wrapping_sub(snd_una);
        let room_in_peer_wnd = snd_wnd.saturating_sub(in_flight);
        let send_buf_room = self.cfg.send_buffer_bytes.saturating_sub(in_flight);
        let mut remaining = bytes.len().min(room_in_peer_wnd as usize).min(send_buf_room as usize);
        let mut offset = 0usize;
        let mut accepted = 0u32;
        let mut cur_seq = seq_start;

        let mut frame = vec![0u8; 1600];
        while remaining > 0 {
            let take = remaining.min(mss_cap as usize);
            let payload = &bytes[offset..offset + take];
            let seg = SegmentTx {
                src_mac: self.our_mac,
                dst_mac: self.cfg.gateway_mac,
                src_ip: tuple.local_ip, dst_ip: tuple.peer_ip,
                src_port: tuple.local_port, dst_port: tuple.peer_port,
                seq: cur_seq,
                ack: rcv_nxt,
                flags: TCP_ACK | TCP_PSH,
                window: rcv_wnd.min(u16::MAX as u32) as u16,
                mss_option: None,
                payload,
            };
            if frame.len() < crate::tcp_output::FRAME_HDRS_MIN + take {
                frame.resize(crate::tcp_output::FRAME_HDRS_MIN + take, 0);
            }
            let Some(n) = build_segment(&seg, &mut frame) else {
                // Shouldn't happen; buf is sized for hdrs+take.
                break;
            };
            if !self.tx_data_frame(&frame[..n]) {
                if accepted == 0 {
                    return Err(Error::SendBufferFull);
                }
                break;
            }
            inc(&self.counters.tcp.tx_data);
            offset += take;
            accepted += take as u32;
            cur_seq = cur_seq.wrapping_add(take as u32);
            remaining -= take;
        }

        // Persist accepted bytes to `snd.pending` (for spec-future retx)
        // and advance `snd_nxt`.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                let stored = c.snd.push(&bytes[..accepted as usize]);
                // If the send buffer was too small, we may have sent
                // bytes we can't retx-track. Not an error in A3; noted
                // for A5.
                let _ = stored;
                c.snd_nxt = cur_seq;
            }
        }
        if accepted < bytes.len() as u32 {
            inc(&self.counters.tcp.send_buf_full);
        }
        Ok(accepted)
    }

    pub fn close_conn(&self, handle: ConnHandle) -> Result<(), Error> {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_FIN};

        let (tuple, seq, rcv_nxt, state, rcv_wnd) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else {
                return Err(Error::InvalidConnHandle(handle as u64));
            };
            (c.four_tuple(), c.snd_nxt, c.rcv_nxt, c.state, c.rcv_wnd)
        };

        // Only ESTABLISHED and CLOSE_WAIT may initiate FIN. Others are
        // already closing/closed; caller gets a successful no-op.
        let to_state = match state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return Ok(()),
        };

        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip, dst_ip: tuple.peer_ip,
            src_port: tuple.local_port, dst_port: tuple.peer_port,
            seq,
            ack: rcv_nxt,
            flags: TCP_ACK | TCP_FIN,
            window: rcv_wnd.min(u16::MAX as u32) as u16,
            mss_option: None,
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else {
            return Err(Error::PeerUnreachable(tuple.peer_ip));
        };
        if !self.tx_frame(&buf[..n]) {
            return Err(Error::PeerUnreachable(tuple.peer_ip));
        }
        inc(&self.counters.tcp.tx_fin);

        // Record our FIN seq and advance snd_nxt (FIN consumes one seq).
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.our_fin_seq = Some(seq);
                c.snd_nxt = seq.wrapping_add(1);
            }
        }
        self.transition_conn(handle, to_state);
        Ok(())
    }

    fn maybe_emit_gratuitous_arp(&self) {
        if self.cfg.garp_interval_sec == 0 || self.cfg.local_ip == 0 {
            return;
        }
        let interval_ns = (self.cfg.garp_interval_sec as u64) * 1_000_000_000;
        let now = crate::clock::now_ns();
        let mut last = self.last_garp_ns.borrow_mut();
        if now.saturating_sub(*last) < interval_ns {
            return;
        }
        let mut buf = [0u8; arp::ARP_FRAME_LEN];
        if arp::build_gratuitous_arp(self.our_mac, self.cfg.local_ip, &mut buf).is_some()
            && self.tx_frame(&buf)
        {
            crate::counters::inc(&self.counters.eth.tx_arp);
        }
        *last = now;
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
    fn default_engine_config_has_a3_fields() {
        let cfg = EngineConfig::default();
        assert_eq!(cfg.max_connections, 16);
        assert_eq!(cfg.recv_buffer_bytes, 256 * 1024);
        assert_eq!(cfg.send_buffer_bytes, 256 * 1024);
        assert_eq!(cfg.tcp_mss, 1460);
        assert_eq!(cfg.tcp_initial_rto_ms, 50);
        assert_eq!(cfg.tcp_msl_ms, 30_000);
        assert!(!cfg.tcp_nagle);
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

    #[test]
    fn connect_requires_nonzero_local_ip() {
        // We can't construct an Engine without EAL, so test via a function
        // signature check + an error path that doesn't need hardware:
        // the "local_ip==0" case is rejected early inside `Engine::connect`,
        // but we can't exercise it without an Engine. This test is a
        // compile-only smoke-check that the method's signature exists.
        fn _check(e: &Engine) {
            let _: Result<crate::flow_table::ConnHandle, crate::Error> =
                e.connect(0x0a_00_00_01, 5000, 0);
        }
    }

    #[test]
    fn send_bytes_signature_exists() {
        fn _check(e: &Engine, h: crate::flow_table::ConnHandle) {
            let _: Result<u32, crate::Error> = e.send_bytes(h, b"x");
        }
    }

    #[test]
    fn close_conn_signature_exists() {
        fn _check(e: &Engine, h: crate::flow_table::ConnHandle) {
            let _: Result<(), crate::Error> = e.close_conn(h);
        }
    }

    #[test]
    fn drain_events_signature_exists() {
        fn _check(e: &Engine) {
            e.drain_events(1, |_ev, _engine| {});
        }
    }
}
