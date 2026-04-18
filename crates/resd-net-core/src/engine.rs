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

/// RFC 7323 §2.3: pick the Window Scale shift so that `(u16::MAX << ws)`
/// covers our full recv buffer. Bounded at 14 per the RFC's cap. Called
/// once at `Engine::connect` time to advertise WS in our SYN; the same
/// shift is stored on the conn as `ws_shift_out` so Task 13's data-ACK
/// path can scale `rcv_wnd` consistently.
fn compute_ws_shift_for(recv_buffer_bytes: u32) -> u8 {
    let mut ws = 0u8;
    let mut cap = u16::MAX as u32;
    while cap < recv_buffer_bytes && ws < 14 {
        cap = (cap << 1) | 1;
        ws += 1;
    }
    ws
}

/// Pure helper: build the TCP-options bundle for the SYN we emit from
/// `Engine::connect`. Split out so unit tests can exercise it without
/// constructing a full Engine (which requires EAL/DPDK).
///
/// Emits MSS + WS (from `compute_ws_shift_for`) + SACK-permitted + TS
/// (TSval = `now_ns / 1000` microsecond ticks per RFC 7323 §4.1;
/// TSecr = 0 — no received TSval yet on an initial SYN).
fn build_connect_syn_opts(
    recv_buffer_bytes: u32,
    our_mss: u16,
    now_ns: u64,
) -> crate::tcp_options::TcpOpts {
    let ws_out = compute_ws_shift_for(recv_buffer_bytes);
    let tsval_initial = (now_ns / 1000) as u32;
    crate::tcp_options::TcpOpts {
        mss: Some(our_mss),
        wscale: Some(ws_out),
        sack_permitted: true,
        timestamps: Some((tsval_initial, 0)),
        ..Default::default()
    }
}

/// Outcome of computing the window + option bundle for a bare ACK. The
/// caller drains conn state, invokes `build_ack_outcome`, and uses the
/// returned `window` / `opts` on the `SegmentTx`; counter bumps
/// (`tx_zero_window`, `tx_sack_blocks`) are driven by the flags fields
/// so the helper stays pure and unit-testable without an Engine.
#[derive(Debug, Clone, Default)]
struct AckOutcome {
    window: u16,
    opts: crate::tcp_options::TcpOpts,
    /// `true` when `free_space == 0` (recv buffer full); caller bumps
    /// `tcp.tx_zero_window`.
    zero_window: bool,
    /// Number of SACK blocks emitted; caller adds to `tcp.tx_sack_blocks`.
    sack_blocks_emitted: u32,
}

/// Pure helper: compute the window + TCP-options bundle for a bare ACK
/// (non-SYN, post-handshake). Split out so tests can exercise the WS /
/// TS / SACK matrix without an Engine (which needs EAL/DPDK).
///
/// * Window: `free_space >> ws_shift_out`, clamped to `u16::MAX`. When
///   `ws_shift_out == 0` this is the raw free-space (capped at 65535).
/// * Timestamps: when `ts_enabled`, echoes `TSval = now_us, TSecr = ts_recent`
///   per RFC 7323 §3 MUST-22.
/// * SACK blocks: when `sack_enabled` and recv-side gaps exist, emits
///   up to `MAX_SACK_BLOCKS_EMIT` blocks. RFC 2018 §4 requires the first
///   block to cover the most-recently-received data. `reorder_segments`
///   arrives sorted by seq ascending; we reverse to emit highest-seq
///   first (approximating "most recent" — exact arrival-order tracking
///   is mTCP's refinement, deferred).
fn build_ack_outcome(
    ws_shift_out: u8,
    ts_enabled: bool,
    ts_recent: u32,
    now_us: u32,
    sack_enabled: bool,
    reorder_segments: &[(u32, u32)],
    free_space: u32,
) -> AckOutcome {
    let scaled = if ws_shift_out > 0 {
        free_space >> ws_shift_out
    } else {
        free_space
    };
    let window = scaled.min(u16::MAX as u32) as u16;
    let zero_window = free_space == 0;

    let timestamps = if ts_enabled {
        Some((now_us, ts_recent))
    } else {
        None
    };

    let mut opts = crate::tcp_options::TcpOpts {
        timestamps,
        ..Default::default()
    };

    let mut sack_blocks_emitted = 0u32;
    if sack_enabled && !reorder_segments.is_empty() {
        // RFC 2018 §4: most-recent block first. Input is sorted by seq
        // ascending; reverse + take N gives highest-seq first.
        let take = reorder_segments
            .len()
            .min(crate::tcp_options::MAX_SACK_BLOCKS_EMIT);
        for &(left, right) in reorder_segments.iter().rev().take(take) {
            opts.push_sack_block(crate::tcp_options::SackBlock { left, right });
        }
        sack_blocks_emitted = take as u32;
    }

    AckOutcome {
        window,
        opts,
        zero_window,
        sack_blocks_emitted,
    }
}

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

/// A4: map an `Outcome` to per-segment `TcpCounters` bumps. Pure slow-path
/// routing — each branch bumps a different counter, no mutation of conn
/// state. Extracted from `Engine::tcp_input` so the dispatch hot-path
/// stays straight-line and the counter wiring is independently testable.
fn apply_tcp_input_counters(
    outcome: &crate::tcp_input::Outcome,
    counters: &crate::counters::TcpCounters,
) {
    use crate::counters::{add, inc};
    if outcome.paws_rejected { inc(&counters.rx_paws_rejected); }
    if outcome.bad_option { inc(&counters.rx_bad_option); }
    if outcome.reassembly_queued_bytes > 0 { inc(&counters.rx_reassembly_queued); }
    if outcome.reassembly_hole_filled > 0 {
        add(&counters.rx_reassembly_hole_filled, outcome.reassembly_hole_filled as u64);
    }
    if outcome.sack_blocks_decoded > 0 {
        add(&counters.rx_sack_blocks, outcome.sack_blocks_decoded as u64);
    }
    if outcome.bad_seq { inc(&counters.rx_bad_seq); }
    if outcome.bad_ack { inc(&counters.rx_bad_ack); }
    if outcome.dup_ack { inc(&counters.rx_dup_ack); }
    if outcome.urgent_dropped { inc(&counters.rx_urgent_dropped); }
    if outcome.rx_zero_window { inc(&counters.rx_zero_window); }
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
                        && c.time_wait_deadline_ns.is_some_and(|d| now >= d)
                })
                .collect()
        };
        for h in candidates {
            self.transition_conn(h, TcpState::Closed);
            self.events.borrow_mut().push(InternalEvent::Closed { conn: h, err: 0 });
            crate::counters::inc(&self.counters.tcp.conn_close);
            // A4 cross-phase backfill: TIME_WAIT deadline expired.
            crate::counters::inc(&self.counters.tcp.conn_time_wait_reaped);
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

        // A4: map Outcome fields → TcpCounters slow-path bumps. Groups
        // all per-segment counter wiring in one place so the dispatch
        // hot-path stays straight-line.
        apply_tcp_input_counters(&outcome, &self.counters.tcp);

        // RFC 9293 §3.10.7.8: restart the 2×MSL timer on any in-window
        // segment received in TIME_WAIT.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(conn) = ft.get_mut(handle) {
                if conn.state == TcpState::TimeWait && outcome.tx == TxAction::Ack {
                    let msl_ns = (self.cfg.tcp_msl_ms as u64) * 1_000_000;
                    conn.time_wait_deadline_ns =
                        Some(crate::clock::now_ns().saturating_add(2 * msl_ns));
                }
            }
        }

        if let Some(new_state) = outcome.new_state {
            self.transition_conn(handle, new_state);
        }

        match outcome.tx {
            TxAction::Ack => self.emit_ack(handle),
            TxAction::Rst => {
                self.emit_rst(handle, &parsed);
                self.transition_conn(handle, TcpState::Closed);
            }
            TxAction::RstForSynSentBadAck => {
                self.emit_rst_for_syn_sent_bad_ack(&tuple, &parsed);
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

        if outcome.buf_full_drop > 0 {
            crate::counters::add(
                &self.counters.tcp.recv_buf_drops,
                outcome.buf_full_drop as u64,
            );
        }

        // A3 OOO policy: no reassembly queue (AD-6). Count one OOO
        // event per segment; A4's reassembly will switch to byte-level
        // accounting. See `docs/superpowers/reviews/phase-a3-rfc-compliance.md`
        // I-1.
        if outcome.ooo_drop > 0 {
            inc(&self.counters.tcp.rx_out_of_order);
        }

        if outcome.closed {
            self.events.borrow_mut().push(InternalEvent::Closed {
                conn: handle, err: 0,
            });
            inc(&self.counters.tcp.conn_close);
            // Bump conn_rst when the close was caused by RST (either
            // inbound RST received, or we're sending one via the SYN_SENT
            // bad-ACK / sync-state Rst paths). LastAck-fin_acked closes
            // and TIME_WAIT reaper closes are clean, not counted as RST.
            let rst_close = (parsed.flags & crate::tcp_output::TCP_RST) != 0
                || matches!(outcome.tx,
                    TxAction::Rst | TxAction::RstForSynSentBadAck);
            if rst_close {
                inc(&self.counters.tcp.conn_rst);
            }
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

    /// Emit a bare ACK for `handle`. Post-handshake ACKs carry the full
    /// Stage-1 option set per spec §6.2:
    ///
    /// * Window: `recv.free_space_total() >> ws_shift_out`, clamped to
    ///   `u16::MAX` (RFC 7323 §2.2). Uses the combined in-order + reorder
    ///   capacity so we don't advertise room the peer can legally fill
    ///   past what we can actually hold once OOO segments accumulate.
    ///   Fixed in Task 12 to use CURRENT free-space over stale `rcv_wnd`;
    ///   widened in Task 17 to `free_space_total` to keep the invariant
    ///   "advertised window ≤ actual room" once `recv.reorder` is non-empty.
    /// * Timestamps: echoes `TSval=now_µs, TSecr=ts_recent` when
    ///   `ts_enabled` (RFC 7323 §3 MUST-22 — every non-SYN segment MUST
    ///   carry TS after SYN-exchange negotiation).
    /// * SACK blocks: when `sack_enabled` and the reorder queue is
    ///   non-empty, emits up to `MAX_SACK_BLOCKS_EMIT` blocks covering
    ///   recv-side gaps (RFC 2018 §4).
    ///
    /// Delegates the pure computation to `build_ack_outcome` so the WS
    /// / TS / SACK matrix can be unit-tested without constructing an
    /// Engine (which requires EAL/DPDK).
    fn emit_ack(&self, handle: ConnHandle) {
        use crate::counters::{add, inc};
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK};
        let ft = self.flow_table.borrow();
        let Some(conn) = ft.get(handle) else { return; };
        let t = conn.four_tuple();
        let ws_shift_out = conn.ws_shift_out;
        let ts_enabled = conn.ts_enabled;
        let ts_recent = conn.ts_recent;
        let sack_enabled = conn.sack_enabled;
        let free_space = conn.recv.free_space_total();
        let seq = conn.snd_nxt;
        let ack = conn.rcv_nxt;
        let last_advertised_wnd = conn.last_advertised_wnd;
        // Snapshot reorder ranges as (seq, end_seq) pairs so the pure
        // helper doesn't need to know about `OooSegment`.
        let reorder_snapshot: Vec<(u32, u32)> = conn
            .recv
            .reorder
            .segments()
            .iter()
            .map(|s| (s.seq, s.end_seq()))
            .collect();
        drop(ft);

        // TSval per RFC 7323 §4.1 = our monotonic-us reading.
        let now_us = (crate::clock::now_ns() / 1000) as u32;
        let outcome = build_ack_outcome(
            ws_shift_out,
            ts_enabled,
            ts_recent,
            now_us,
            sack_enabled,
            &reorder_snapshot,
            free_space,
        );

        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: t.local_ip,
            dst_ip: t.peer_ip,
            src_port: t.local_port,
            dst_port: t.peer_port,
            seq,
            ack,
            flags: TCP_ACK,
            window: outcome.window,
            options: outcome.opts,
            payload: &[],
        };
        // Sized to cover max TCP-options budget: 14 (eth) + 20 (ip) +
        // 20 (tcp min) + 40 (max tcp opts) = 94; round up to 128.
        let mut buf = [0u8; 128];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
        if self.tx_frame(&buf[..n]) {
            inc(&self.counters.tcp.tx_ack);
            if outcome.zero_window {
                inc(&self.counters.tcp.tx_zero_window);
            }
            // A4 cross-phase backfill: if the previously advertised window
            // was 0 and this one reopens, bump `tcp.tx_window_update`.
            // Recorded on TX success so we don't count segments the driver
            // rejected.
            if last_advertised_wnd == Some(0) && outcome.window > 0 {
                inc(&self.counters.tcp.tx_window_update);
            }
            // Record what we advertised so the next emit_ack can detect a
            // 0 → nonzero transition.
            {
                let mut ft = self.flow_table.borrow_mut();
                if let Some(c) = ft.get_mut(handle) {
                    c.last_advertised_wnd = Some(outcome.window);
                }
            }
            if outcome.sack_blocks_emitted > 0 {
                add(
                    &self.counters.tcp.tx_sack_blocks,
                    outcome.sack_blocks_emitted as u64,
                );
            }
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
            options: crate::tcp_options::TcpOpts::default(),
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
        drop(ft);
        if self.tx_frame(&buf[..n]) {
            inc(&self.counters.tcp.tx_rst);
        }
    }

    /// Per RFC 9293 §3.10.7.3 SYN_SENT: send `<SEQ=SEG.ACK><CTL=RST>`
    /// to reject an ACK that doesn't cover our SYN. No ACK flag, no window.
    fn emit_rst_for_syn_sent_bad_ack(
        &self,
        tuple: &FourTuple,
        incoming: &crate::tcp_input::ParsedSegment,
    ) {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_RST};
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip,
            dst_ip: tuple.peer_ip,
            src_port: tuple.local_port,
            dst_port: tuple.peer_port,
            seq: incoming.ack,
            ack: 0,
            flags: TCP_RST, // no ACK flag
            window: 0,
            options: crate::tcp_options::TcpOpts::default(),
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else { return; };
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
            options: crate::tcp_options::TcpOpts::default(), payload: &[],
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
        // Clamp our advertised MSS to the NIC's actual MTU minus
        // IPv4(20) + TCP(20) headers. Per RFC 6691 §5.1 / spec §6.3.
        let mut nic_mtu: u16 = 1500;
        unsafe {
            // Best-effort: on failure, fall back to default MTU.
            let _ = sys::resd_rte_eth_dev_get_mtu(self.cfg.port_id, &mut nic_mtu);
        }
        let mtu_mss = nic_mtu.saturating_sub(40) as u32; // 40 = IP(20) + TCP(20)
        let our_mss = self.cfg.tcp_mss.min(mtu_mss).min(u16::MAX as u32) as u16;
        let conn = TcpConn::new_client(
            tuple,
            iss,
            our_mss,
            self.cfg.recv_buffer_bytes,
            self.cfg.send_buffer_bytes,
        );
        let handle = match self.flow_table.borrow_mut().insert(conn) {
            Some(h) => h,
            None => {
                // A4 cross-phase backfill: flow table at `max_connections`.
                inc(&self.counters.tcp.conn_table_full);
                return Err(Error::TooManyConns);
            }
        };

        // Build and transmit SYN with the full Stage-1 option set: MSS
        // (already clamped to MTU-40 above) + Window Scale + SACK-permitted
        // + Timestamps (RFC 7323 §4.1 initial TSval). Pre-WS-negotiation,
        // we advertise the maximum unscaled window — the SYN itself has no
        // scaled-window semantics; `ws_shift_out` kicks in for non-SYN
        // segments (Task 13).
        let now_ns = crate::clock::now_ns();
        let ws_out = compute_ws_shift_for(self.cfg.recv_buffer_bytes);
        let syn_opts = build_connect_syn_opts(self.cfg.recv_buffer_bytes, our_mss, now_ns);
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
            window: u16::MAX, // pre-WS-negotiation: advertise maximum.
            options: syn_opts,
            payload: &[],
        };
        // A full SYN (MSS + WS + SACK-perm + TS, padded to 20 bytes of
        // options) produces a 14+20+20+20 = 74-byte frame; reserve 128 to
        // stay safely above that ceiling.
        let mut buf = [0u8; 128];
        let Some(n) = build_segment(&seg, &mut buf) else {
            // Header-too-small is impossible with 128-byte buf; keep explicit.
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
        // TcpState::Closed default. Also record our advertised WS shift
        // so Task 15's SYN-ACK handler can confirm it against the peer's
        // response, and Task 13's data path can scale `rcv_wnd`.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.snd_nxt = iss.wrapping_add(1);
                c.ws_shift_out = ws_out;
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
                options: crate::tcp_options::TcpOpts::default(),
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
            options: crate::tcp_options::TcpOpts::default(),
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

    // Task 12: `Engine::connect` emits full SYN options (MSS + WS + SACK-perm
    // + TS). The engine itself can't be unit-constructed (needs EAL/DPDK),
    // so we test via two seams: (1) `compute_ws_shift_for` — the pure
    // WS-shift policy; (2) `build_connect_syn_opts` — the pure option-bundle
    // builder that `connect` delegates to. Frame-level emission is covered
    // by the TAP integration test (`tcp_basic_tap.rs`) and the
    // `tcp_output::build_segment` round-trip tests.

    #[test]
    fn compute_ws_shift_for_below_64kib_returns_zero() {
        // 65535 is exactly u16::MAX — no scaling needed.
        assert_eq!(super::compute_ws_shift_for(65535), 0);
        assert_eq!(super::compute_ws_shift_for(1), 0);
        assert_eq!(super::compute_ws_shift_for(0), 0);
    }

    #[test]
    fn compute_ws_shift_for_256kib_returns_three() {
        // Trace: cap=65535 (ws=0) < 262144 → cap=131071 (ws=1) < 262144 →
        // cap=262143 (ws=2) < 262144 (by 1!) → cap=524287 (ws=3) ≥ 262144.
        assert_eq!(super::compute_ws_shift_for(256 * 1024), 3);
    }

    #[test]
    fn compute_ws_shift_for_caps_at_fourteen() {
        // RFC 7323 §2.3: WS option value MUST NOT exceed 14.
        assert_eq!(super::compute_ws_shift_for(u32::MAX), 14);
    }

    #[test]
    fn build_connect_syn_opts_has_mss_ws_sack_perm_ts() {
        // This is the data that `connect()` feeds into SegmentTx.options;
        // `tcp_output::build_segment` is already exercised by its own
        // unit tests to turn these opts into wire bytes correctly.
        let our_mss: u16 = 1460;
        let recv_buffer_bytes: u32 = 256 * 1024;
        let now_ns: u64 = 1_234_567_000; // ~1.2s since epoch; tsval will be 1_234_567 µs
        let opts = super::build_connect_syn_opts(recv_buffer_bytes, our_mss, now_ns);
        assert_eq!(opts.mss, Some(our_mss));
        assert!(opts.sack_permitted);
        assert_eq!(opts.wscale, Some(3));
        let (tsval, tsecr) = opts.timestamps.expect("timestamps set on SYN");
        assert_eq!(tsval, 1_234_567);
        assert_eq!(tsecr, 0, "SYN has no received TSval to echo");
    }

    #[test]
    fn build_connect_syn_opts_tsval_nonzero_for_nonzero_clock() {
        // Sanity: we truncate `now_ns / 1000` to u32; a realistic
        // engine-uptime reading produces a nonzero TSval.
        let opts = super::build_connect_syn_opts(65_536, 1460, 1_000);
        let (tsval, _) = opts.timestamps.expect("timestamps set");
        assert_eq!(tsval, 1);
    }

    // Task 13: post-handshake `emit_ack` carries TS option + WS-scaled
    // window + SACK blocks. The engine needs EAL/DPDK to construct, so
    // we test the pure helper `build_ack_outcome` that `emit_ack`
    // delegates to. Frame-level TS echo + SACK encoding is already
    // round-trip-tested in `tcp_options::tests`.

    #[test]
    fn build_ack_outcome_ts_and_ws_scaled_window() {
        // TS enabled + WS shift 7 + free_space well above 0 ⇒ window
        // scales down by 7 bits, TSecr echoes `ts_recent`, no SACK.
        let out = super::build_ack_outcome(
            /* ws_shift_out */ 7,
            /* ts_enabled */ true,
            /* ts_recent */ 0x1122_3344,
            /* now_us */ 0xaabb_ccdd,
            /* sack_enabled */ false,
            /* reorder */ &[],
            /* free_space */ 256 * 1024,
        );
        // 262144 >> 7 = 2048.
        assert_eq!(out.window, 2048);
        let (tsval, tsecr) = out.opts.timestamps.expect("TS option present");
        assert_eq!(tsval, 0xaabb_ccdd);
        assert_eq!(tsecr, 0x1122_3344);
        assert!(!out.zero_window);
        assert_eq!(out.sack_blocks_emitted, 0);
        assert_eq!(out.opts.sack_block_count, 0);
    }

    #[test]
    fn build_ack_outcome_ts_disabled_skips_option() {
        // Mirrors A3 defaults: no TS negotiated ⇒ no TS option.
        let out = super::build_ack_outcome(0, false, 0, 12345, false, &[], 4096);
        assert!(out.opts.timestamps.is_none());
        assert_eq!(out.window, 4096);
    }

    #[test]
    fn build_ack_outcome_ws_shift_zero_passes_free_space_through() {
        // ws_shift=0 ⇒ no scaling; clamp still bounds at u16::MAX.
        let out = super::build_ack_outcome(0, false, 0, 0, false, &[], 50_000);
        assert_eq!(out.window, 50_000);
    }

    #[test]
    fn build_ack_outcome_window_clamps_to_u16_max() {
        // Unscaled 2 MiB ⇒ clamp to 65535 (what A3 did).
        let out = super::build_ack_outcome(0, false, 0, 0, false, &[], 2 * 1024 * 1024);
        assert_eq!(out.window, u16::MAX);
    }

    #[test]
    fn build_ack_outcome_scaled_window_clamps_to_u16_max() {
        // 512 MiB >> 3 = 64 MiB ⇒ still >> u16::MAX, so clamp.
        let out = super::build_ack_outcome(3, false, 0, 0, false, &[], 512 * 1024 * 1024);
        assert_eq!(out.window, u16::MAX);
    }

    #[test]
    fn build_ack_outcome_zero_free_space_signals_zero_window_and_window_zero() {
        let out = super::build_ack_outcome(7, false, 0, 0, false, &[], 0);
        assert_eq!(out.window, 0);
        assert!(out.zero_window);
    }

    #[test]
    fn build_ack_outcome_sack_blocks_emit_in_reverse_seq_order() {
        // Reorder queue is sorted ascending — simulate three OOO ranges.
        // RFC 2018 §4: most-recent (highest-seq) block comes first.
        let reorder = [(1_000u32, 1_100u32), (2_000, 2_100), (3_000, 3_100)];
        let out = super::build_ack_outcome(0, false, 0, 0, true, &reorder, 4096);
        assert_eq!(out.sack_blocks_emitted, 3);
        assert_eq!(out.opts.sack_block_count, 3);
        // Reversed: highest seq (3000/3100) first.
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock { left: 3_000, right: 3_100 }
        );
        assert_eq!(
            out.opts.sack_blocks[1],
            crate::tcp_options::SackBlock { left: 2_000, right: 2_100 }
        );
        assert_eq!(
            out.opts.sack_blocks[2],
            crate::tcp_options::SackBlock { left: 1_000, right: 1_100 }
        );
    }

    #[test]
    fn build_ack_outcome_sack_disabled_skips_blocks_even_with_reorder() {
        // Peer didn't negotiate SACK-permitted ⇒ no blocks on wire.
        let reorder = [(100u32, 200u32)];
        let out = super::build_ack_outcome(0, false, 0, 0, false, &reorder, 4096);
        assert_eq!(out.sack_blocks_emitted, 0);
        assert_eq!(out.opts.sack_block_count, 0);
    }

    #[test]
    fn build_ack_outcome_sack_caps_at_max_blocks_emit() {
        // 5 ranges but MAX_SACK_BLOCKS_EMIT=3 ⇒ only top-3 by seq make it.
        let reorder = [
            (1_000u32, 1_100u32),
            (2_000, 2_100),
            (3_000, 3_100),
            (4_000, 4_100),
            (5_000, 5_100),
        ];
        let out = super::build_ack_outcome(0, false, 0, 0, true, &reorder, 4096);
        assert_eq!(out.sack_blocks_emitted, 3);
        assert_eq!(out.opts.sack_block_count, 3);
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock { left: 5_000, right: 5_100 }
        );
        assert_eq!(
            out.opts.sack_blocks[1],
            crate::tcp_options::SackBlock { left: 4_000, right: 4_100 }
        );
        assert_eq!(
            out.opts.sack_blocks[2],
            crate::tcp_options::SackBlock { left: 3_000, right: 3_100 }
        );
    }

    #[test]
    fn build_ack_outcome_full_matrix_ts_plus_ws_plus_sack() {
        // All three options on — verify no interaction breaks any of them.
        let reorder = [(1_000u32, 1_100u32), (2_000, 2_100)];
        let out = super::build_ack_outcome(
            /* ws_shift_out */ 7,
            /* ts_enabled */ true,
            /* ts_recent */ 0xdead_beef,
            /* now_us */ 0x1234_5678,
            /* sack_enabled */ true,
            /* reorder */ &reorder,
            /* free_space */ 256 * 1024,
        );
        assert_eq!(out.window, 2048);
        assert_eq!(out.opts.timestamps, Some((0x1234_5678, 0xdead_beef)));
        assert_eq!(out.sack_blocks_emitted, 2);
        assert_eq!(out.opts.sack_block_count, 2);
        // Most-recent (highest seq) first.
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock { left: 2_000, right: 2_100 }
        );
    }

    // Task 19: counter wiring via `apply_tcp_input_counters`. The helper
    // is pure (no Engine, no EAL) so we can exercise every Outcome-flag
    // → counter mapping via direct assertion. Engine-level counters
    // (`conn_table_full`, `conn_time_wait_reaped`, `tx_window_update`)
    // are integration-test reachable once TAP-mode tests land in Task 20+.

    #[test]
    fn apply_tcp_input_counters_maps_paws_rejected() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.paws_rejected = true;
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rx_paws_rejected.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn apply_tcp_input_counters_maps_bad_option() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.bad_option = true;
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rx_bad_option.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn apply_tcp_input_counters_reassembly_queued_increments_once() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.reassembly_queued_bytes = 42; // any nonzero
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rx_reassembly_queued.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn apply_tcp_input_counters_reassembly_hole_filled_adds_count() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.reassembly_hole_filled = 3;
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rx_reassembly_hole_filled.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn apply_tcp_input_counters_sack_blocks_decoded_adds_count() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.sack_blocks_decoded = 2;
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rx_sack_blocks.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn apply_tcp_input_counters_backfill_flags_each_bump_once() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.bad_seq = true;
        o.bad_ack = true;
        o.dup_ack = true;
        o.urgent_dropped = true;
        o.rx_zero_window = true;
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rx_bad_seq.load(Ordering::Relaxed), 1);
        assert_eq!(c.rx_bad_ack.load(Ordering::Relaxed), 1);
        assert_eq!(c.rx_dup_ack.load(Ordering::Relaxed), 1);
        assert_eq!(c.rx_urgent_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(c.rx_zero_window.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn apply_tcp_input_counters_base_outcome_no_bumps() {
        let c = crate::counters::TcpCounters::default();
        let o = crate::tcp_input::Outcome::base();
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        // Every field we touch stays at zero.
        assert_eq!(c.rx_paws_rejected.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_bad_option.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_reassembly_queued.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_reassembly_hole_filled.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_sack_blocks.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_bad_seq.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_bad_ack.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_dup_ack.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_urgent_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_zero_window.load(Ordering::Relaxed), 0);
    }
}
