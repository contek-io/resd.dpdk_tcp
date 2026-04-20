use resd_net_sys as sys;
use std::cell::{Cell, RefCell};
use std::ffi::CString;
use std::sync::Mutex;

use crate::arp;
use crate::counters::Counters;
use crate::flow_table::{ConnHandle, FlowTable, FourTuple};
use crate::icmp::PmtuTable;
use crate::iss::IssGen;
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
///   up to `MAX_SACK_BLOCKS_EMIT` blocks. RFC 2018 §4 MUST-26 requires
///   the first block to cover the segment that triggered this ACK.
///   The caller passes `trigger_range` (the seq range of the OOO insert
///   that caused the ACK); if that range falls inside a reorder block,
///   emit that block first. Remaining blocks emit in highest-seq-first
///   order (reverse of the ascending input) for RFC 2018 §4 "most recent
///   info carried through ACK loss" intent.
#[allow(clippy::too_many_arguments)]
fn build_ack_outcome(
    ws_shift_out: u8,
    ts_enabled: bool,
    ts_recent: u32,
    now_us: u32,
    sack_enabled: bool,
    reorder_segments: &[(u32, u32)],
    trigger_range: Option<(u32, u32)>,
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
        let max_emit = crate::tcp_options::MAX_SACK_BLOCKS_EMIT;

        // F-8 RFC 2018 §4 MUST-26: find the reorder block that contains
        // the triggering seq range, if any. After merge-on-insert the
        // triggering payload may have coalesced with neighbours; we match
        // by "contains `trigger.0`" which identifies the merged block.
        let trigger_idx = match trigger_range {
            Some((t_left, _)) => reorder_segments.iter().position(|&(l, r)| {
                crate::tcp_seq::seq_le(l, t_left) && crate::tcp_seq::seq_lt(t_left, r)
            }),
            None => None,
        };

        let take = reorder_segments.len().min(max_emit);
        if let Some(idx) = trigger_idx {
            // Trigger block first (RFC 2018 §4 MUST-26).
            let (l, r) = reorder_segments[idx];
            opts.push_sack_block(crate::tcp_options::SackBlock { left: l, right: r });
            sack_blocks_emitted = 1;
            // Remaining blocks: highest-seq-first, excluding the trigger.
            let remaining_cap = take.saturating_sub(1);
            let mut emitted_more = 0;
            for (i, &(left, right)) in reorder_segments.iter().enumerate().rev() {
                if i == idx {
                    continue;
                }
                if emitted_more == remaining_cap {
                    break;
                }
                opts.push_sack_block(crate::tcp_options::SackBlock { left, right });
                emitted_more += 1;
            }
            sack_blocks_emitted += emitted_more as u32;
        } else {
            // No trigger match (pure-ACK or trigger long-ago pruned):
            // fall back to highest-seq-first to approximate "most recent".
            for &(left, right) in reorder_segments.iter().rev().take(take) {
                opts.push_sack_block(crate::tcp_options::SackBlock { left, right });
            }
            sack_blocks_emitted = take as u32;
        }
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
    pub tcp_msl_ms: u32,
    pub tcp_nagle: bool,

    // Phase A5 additions
    /// A5 Task 21: RFC 6298 RTO floor (µs). Spec §6.4 default 5ms
    /// (trading-latency policy; RFC recommends 1s floor).
    pub tcp_min_rto_us: u32,
    /// A5 Task 21: first-RTO value (µs) before any RTT sample. Used
    /// for SYN arming and initial data arm.
    pub tcp_initial_rto_us: u32,
    /// A5 Task 21: RTO backoff cap (µs). Spec §6.4 default 1s
    /// (trading-aligned fail-fast; RFC 6298 allows up to 60s).
    pub tcp_max_rto_us: u32,
    /// A5 Task 21: per-segment retransmit budget. After this many
    /// RTO-driven retransmits without ACK progress, conn fails with
    /// ETIMEDOUT. Default 15 (≈8.3s wall clock with default backoff).
    pub tcp_max_retrans_count: u32,
    /// A5 Task 20: when `true`, fire handlers (RTO, RACK, TLP) emit
    /// `TcpRetrans` + `TcpLossDetected` events per retransmit / detected
    /// loss. Default `false` — counters alone satisfy the default
    /// observability contract; this flag is for forensic sessions where
    /// per-packet event logging is desired.
    pub tcp_per_packet_events: bool,

    /// A5.5 Task 5: event-queue overflow guard (§3.2 / §5.1).
    /// Default 4096; must be >= 64. Queue drops oldest on overflow.
    pub event_queue_soft_cap: u32,
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
            tcp_msl_ms: 30_000,
            tcp_nagle: false,
            tcp_min_rto_us: 5_000,
            tcp_initial_rto_us: 5_000,
            tcp_max_rto_us: 1_000_000,
            tcp_max_retrans_count: 15,
            tcp_per_packet_events: false,
            event_queue_soft_cap: 4096,
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

    // Phase A5 additions
    pub(crate) timer_wheel: RefCell<crate::tcp_timer_wheel::TimerWheel>,

    // A-HW runtime latches — populated by configure_port_offloads.
    // When a compile-enabled offload was advertised by the PMD the latch
    // is true; the corresponding hot-path branch uses the offload. When
    // false, the branch falls back to software. See spec §§6-10.
    // The `#[allow(dead_code)]` attributes go away as tasks 7/9/12 wire
    // these latches into hot-path branches.
    //
    // Task 7 consumer: `tx_tcp_frame` + the inline send_bytes mbuf fill
    // + the retransmit path all read this latch to decide whether to
    // invoke `tx_offload_finalize` on the freshly-built mbuf.
    tx_cksum_offload_active: bool,
    // Task 8 consumer: `handle_ipv4` threads this latch into
    // `ip_decode_offload_aware` (IP cksum) and `tcp_input` threads it
    // into the L4 cksum classification. Both pre-checks gate on
    // `rx_cksum_offload_active AND hw-offload-rx-cksum feature` —
    // false-either short-circuits to software verify (spec §7.2).
    rx_cksum_offload_active: bool,
    // Task 9 consumer: threaded into `flow_table::hash_bucket_for_lookup`
    // by `tcp_input` — when true (and the `hw-offload-rss-hash` feature
    // is compiled), the NIC-provided Toeplitz hash replaces the software
    // SipHash for the RX flow-table bucket pick. See spec §8.2.
    rss_hash_offload_active: bool,
    /// Offset (in bytes) from the start of rte_mbuf where the NIC-provided
    /// hardware RX timestamp lives. Populated at engine_create via
    /// rte_mbuf_dynfield_lookup("rte_dynfield_timestamp"). `None` when
    /// the PMD does not register the dynfield (expected on ENA — spec §10.5).
    /// Spec §10.1. Consumed by `hw_rx_ts_ns` which is called at the RX
    /// decode boundary in `poll_once` (Task 11).
    #[cfg(feature = "hw-offload-rx-timestamp")]
    rx_ts_offset: Option<i32>,
    /// Bitmask in ol_flags that indicates a valid RX timestamp on this
    /// mbuf. Populated via rte_mbuf_dynflag_lookup("rte_dynflag_rx_timestamp")
    /// → the returned bit position translated to (1 << bit_pos). `None` when
    /// the flag isn't registered. Expected `None` on ENA (spec §10.5).
    /// Consumed by `hw_rx_ts_ns` which is called at the RX decode boundary
    /// in `poll_once` (Task 11).
    #[cfg(feature = "hw-offload-rx-timestamp")]
    rx_ts_flag_mask: Option<u64>,
    /// Driver name captured at bring-up; used by Task 12's LLQ verification
    /// to short-circuit non-ENA drivers. See spec §5.
    #[allow(dead_code)]
    driver_name: [u8; 32],
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
    if outcome.paws_rejected {
        inc(&counters.rx_paws_rejected);
    }
    if outcome.bad_option {
        inc(&counters.rx_bad_option);
    }
    if outcome.reassembly_queued_bytes > 0 {
        inc(&counters.rx_reassembly_queued);
    }
    if outcome.reassembly_hole_filled > 0 {
        add(
            &counters.rx_reassembly_hole_filled,
            outcome.reassembly_hole_filled as u64,
        );
    }
    if outcome.sack_blocks_decoded > 0 {
        add(&counters.rx_sack_blocks, outcome.sack_blocks_decoded as u64);
    }
    if outcome.rx_dsack_count > 0 {
        add(&counters.rx_dsack, outcome.rx_dsack_count as u64);
    }
    if outcome.tx_tlp_spurious_count > 0 {
        add(
            &counters.tx_tlp_spurious,
            outcome.tx_tlp_spurious_count as u64,
        );
    }
    if outcome.bad_seq {
        inc(&counters.rx_bad_seq);
    }
    if outcome.bad_ack {
        inc(&counters.rx_bad_ack);
    }
    if outcome.dup_ack {
        inc(&counters.rx_dup_ack);
    }
    if outcome.urgent_dropped {
        inc(&counters.rx_urgent_dropped);
    }
    if outcome.rx_zero_window {
        inc(&counters.rx_zero_window);
    }
    if outcome.ws_shift_clamped {
        inc(&counters.rx_ws_shift_clamped);
    }
    if outcome.rtt_sample_taken {
        inc(&counters.rtt_samples);
    }
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

    // A-HW Task 12 fixup: install an fmemopen-backed capture of DPDK's
    // log stream for the duration of `rte_eal_init`. The ENA PMD emits
    // its LLQ "Placement policy: …" marker during `eth_ena_dev_init`,
    // which runs at PCI-probe time inside `rte_eal_init` (NOT inside
    // `rte_eth_dev_start`). Scan the captured log for activation /
    // failure markers after EAL init returns, and store the verdict in
    // a process-global OnceLock so every engine_create reads it later.
    // Capture-init failure is NON-fatal: EAL init proceeds without a
    // capture, and the engine-side verifier soft-skips with a warning.
    #[cfg(feature = "hw-verify-llq")]
    let capture = crate::llq_verify::start_log_capture().ok();

    // Safety: rte_eal_init mutates argv internally; we pass the constructed array.
    let rc = unsafe { sys::rte_eal_init(argv.len() as i32, argv.as_mut_ptr()) };

    #[cfg(feature = "hw-verify-llq")]
    if let Some(cap) = capture {
        match crate::llq_verify::finish_log_capture(cap) {
            Ok(log) => crate::llq_verify::record_eal_init_log_verdict(&log),
            Err(e) => eprintln!(
                "resd_net: log capture around rte_eal_init failed: {e:?}; \
                 LLQ verification will be skipped for net_ena engines."
            ),
        }
    }

    if rc < 0 {
        return Err(Error::EalInit(unsafe { sys::resd_rte_errno() }));
    }
    *guard = true;
    Ok(())
}

/// Per-connect options for A5. Defaults: both `false` (A5 baseline,
/// standards-conformant behavior).
///
/// * `rack_aggressive` forces RACK reo_wnd = 0 on this connection (valid
///   sender discretion per RFC 8985 §6.2; trades reorder tolerance for
///   lower detection latency — intended for stable DC / intra-region
///   links where reordering is rare).
/// * `rto_no_backoff` disables exponential RTO backoff on this connection
///   (deviates from RFC 6298 §5.5, but opt-in per-connect; the RTO stays
///   at its current value across consecutive retransmits instead of
///   doubling — intended for latency-sensitive trading paths where the
///   operator prefers faster reprobe over AIMD-style congestion backoff).
///
/// A5.5 Task 10: five TLP tuning fields mirror the C ABI
/// `resd_net_connect_opts_t::tlp_*` set. Zero-init substitution (from
/// the ABI helper `validate_and_defaults_tlp_opts`) fires before this
/// struct is built, so `multiplier_x100` / `max_consecutive_probes` /
/// `pto_min_floor_us` carry post-substitution values here.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConnectOpts {
    pub rack_aggressive: bool,
    pub rto_no_backoff: bool,
    pub tlp_pto_min_floor_us: u32,
    pub tlp_pto_srtt_multiplier_x100: u16,
    pub tlp_skip_flight_size_gate: bool,
    pub tlp_max_consecutive_probes: u8,
    pub tlp_skip_rtt_sample_gate: bool,
}

/// Bump `counter` when `requested_bit` is set but `advertised_mask` does
/// not include it. Returns the bit ANDed in — i.e., the bit itself if
/// advertised, else 0. Slow-path; called once per offload at bring-up.
///
/// Spec §4 step 5 + §9.1.1 counter-addition policy.
///
/// `allow(dead_code)` covers `--no-default-features` builds where all
/// `hw-offload-*` features are off and no call site references this
/// helper; the test module always exercises it.
#[allow(dead_code)]
fn and_offload_with_miss_counter(
    requested_bit: u64,
    advertised_mask: u64,
    counter: &std::sync::atomic::AtomicU64,
    name: &str,
    port_id: u16,
) -> u64 {
    if requested_bit == 0 {
        return 0;
    }
    if (requested_bit & advertised_mask) == 0 {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        eprintln!(
            "resd_net: PMD on port {} does not advertise {} (0x{:016x}); \
             degrading to software path for this offload",
            port_id, name, requested_bit
        );
        0
    } else {
        requested_bit
    }
}

/// Result of `configure_port_offloads` — the applied offload masks plus
/// per-engine runtime latches that gate hot-path offload-vs-software
/// branches. See spec §4 and §§6-10 for how each latch feeds later branches.
#[derive(Debug, Clone, Copy)]
struct PortConfigOutcome {
    /// Bits written to `eth_conf.rxmode.offloads` after AND with
    /// `dev_info.rx_offload_capa`.
    #[allow(dead_code)]
    applied_rx_offloads: u64,
    /// Bits written to `eth_conf.txmode.offloads` after AND with
    /// `dev_info.tx_offload_capa`.
    #[allow(dead_code)]
    applied_tx_offloads: u64,
    /// True iff TX IPv4 + TCP checksum offload bits both applied. Latches
    /// the TX hot-path offload-vs-software branch.
    tx_cksum_offload_active: bool,
    /// True iff RX IPv4 + TCP checksum offload bits both applied. Latches
    /// the RX hot-path offload-vs-software branch.
    rx_cksum_offload_active: bool,
    /// True iff RSS_HASH bit applied. Latches `mbuf.hash.rss` consumption
    /// in flow_table.rs.
    rss_hash_offload_active: bool,
    /// Driver name captured at bring-up — consumed by the LLQ verification
    /// path (Task 12) to short-circuit non-ENA drivers.
    driver_name: [u8; 32],
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

        // Counters exist before port config so the helper can bump any
        // offload-miss counters on unsupported requested bits.
        let counters = Box::new(Counters::new());

        // Port-config: dev_info query, offload AND, runtime-fallback
        // latches. Extracted into a helper so later A-HW tasks can add
        // feature-gated offload-bit branches in one place. See
        // `dpdk_consts.rs` for the `RTE_ETH_TX_OFFLOAD_MULTI_SEGS` bit
        // position (DPDK stable ethdev ABI) and spec §4 for the outcome
        // structure.
        let outcome = Self::configure_port_offloads(&cfg, &counters)?;

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

        // A-HW Task 12 fixup: LLQ verification reads the verdict that
        // `eal_init` recorded at `rte_eal_init` time. The capture window
        // must wrap EAL init — the ENA PMD emits the "Placement policy:
        // …" marker during `eth_ena_dev_init` (PCI probe, inside
        // `rte_eal_init`), NOT inside `rte_eth_dev_start`. No local
        // capture machinery is needed here. See spec §5 and
        // `crate::llq_verify` for marker pinning.
        let rc = unsafe { sys::rte_eth_dev_start(cfg.port_id) };
        if rc < 0 {
            return Err(Error::PortStart(cfg.port_id, unsafe {
                sys::resd_rte_errno()
            }));
        }

        #[cfg(feature = "hw-verify-llq")]
        crate::llq_verify::verify_llq_activation_from_global(
            cfg.port_id,
            &outcome.driver_name,
            &counters,
        )?;

        // A-HW: RSS reta program. No-op when feature off OR when
        // the latch is false OR when dev_info.reta_size == 0.
        if outcome.rss_hash_offload_active {
            let mut dev_info_post: sys::rte_eth_dev_info = unsafe { std::mem::zeroed() };
            let _ = unsafe { sys::rte_eth_dev_info_get(cfg.port_id, &mut dev_info_post) };
            Self::program_rss_reta_single_queue(cfg.port_id, &dev_info_post)?;
        }

        // A-HW Task 10: RX timestamp dynfield/dynflag lookup. Runs after
        // rte_eth_dev_start so any PMD that registers the dynfield lazily
        // on start-up has had its chance. Both lookups are expected to
        // fail on ENA (PMD does not register the dynfield — spec §10.5);
        // this is the documented steady state and the one-shot counter
        // bump records it for observability. Under the `hw-offload-rx-timestamp`
        // feature, the resulting `Option<i32>` / `Option<u64>` pair feeds
        // `Engine::hw_rx_ts_ns(mbuf)` which Task 11 threads through to
        // the RX event emission sites.
        #[cfg(feature = "hw-offload-rx-timestamp")]
        let (rx_ts_offset, rx_ts_flag_mask) = {
            use std::sync::atomic::Ordering;
            let off_rc = unsafe {
                sys::rte_mbuf_dynfield_lookup(
                    c"rte_dynfield_timestamp".as_ptr(),
                    std::ptr::null_mut(),
                )
            };
            let flag_bit = unsafe {
                sys::rte_mbuf_dynflag_lookup(
                    c"rte_dynflag_rx_timestamp".as_ptr(),
                    std::ptr::null_mut(),
                )
            };
            let offset = if off_rc >= 0 { Some(off_rc) } else { None };
            let mask = if flag_bit >= 0 { Some(1u64 << flag_bit) } else { None };
            if offset.is_none() || mask.is_none() {
                counters
                    .eth
                    .offload_missing_rx_timestamp
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "resd_net: RX timestamp dynfield/dynflag unavailable on port {} \
                     (ENA steady state — see spec §10.5)",
                    cfg.port_id
                );
            }
            (offset, mask)
        };

        // Read NIC MAC via the shim. `rte_ether_addr` is a 6-byte packed struct.
        let mut mac_addr: sys::rte_ether_addr = unsafe { std::mem::zeroed() };
        let rc = unsafe { sys::resd_rte_eth_macaddr_get(cfg.port_id, &mut mac_addr) };
        if rc != 0 {
            return Err(Error::MacAddrLookup(cfg.port_id, unsafe {
                sys::resd_rte_errno()
            }));
        }
        // bindgen names the field `addr_bytes` on rte_ether_addr.
        let our_mac = mac_addr.addr_bytes;

        Ok(Self {
            counters,
            _rx_mempool: rx_mempool,
            tx_hdr_mempool,
            tx_data_mempool,
            our_mac,
            pmtu: RefCell::new(PmtuTable::new()),
            last_garp_ns: RefCell::new(0),
            flow_table: RefCell::new(FlowTable::new(cfg.max_connections)),
            events: RefCell::new(EventQueue::with_cap(cfg.event_queue_soft_cap as usize)),
            iss_gen: IssGen::new(),
            // RFC 6056 ephemeral port hint range: start at 49152.
            last_ephemeral_port: Cell::new(49151),
            timer_wheel: RefCell::new(crate::tcp_timer_wheel::TimerWheel::new(
                (cfg.max_connections as usize).saturating_mul(4),
            )),
            tx_cksum_offload_active: outcome.tx_cksum_offload_active,
            rx_cksum_offload_active: outcome.rx_cksum_offload_active,
            rss_hash_offload_active: outcome.rss_hash_offload_active,
            #[cfg(feature = "hw-offload-rx-timestamp")]
            rx_ts_offset,
            #[cfg(feature = "hw-offload-rx-timestamp")]
            rx_ts_flag_mask,
            driver_name: outcome.driver_name,
            cfg,
        })
    }

    /// Build `rte_eth_conf` with requested offload bits, query `dev_info`
    /// to AND the request against what the PMD advertises, then call
    /// `rte_eth_dev_configure`. Returns the actually-applied masks +
    /// per-engine runtime latches that gate the hot-path
    /// offload-vs-software branches. See spec §4.
    ///
    /// `counters.eth.offload_missing_*` is bumped one-shot when a
    /// compile-enabled offload bit is not advertised by the PMD.
    fn configure_port_offloads(
        cfg: &EngineConfig,
        counters: &Counters,
    ) -> Result<PortConfigOutcome, Error> {
        use crate::dpdk_consts::RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

        // `counters` is unused when every `hw-offload-*` counter-bumping
        // feature is compiled out. The signature stays stable because the
        // latches are C-ABI-stable and future tasks (7, 8) reintroduce
        // consumers. Keep the binding alive for `-D warnings` on
        // `--no-default-features`.
        #[cfg(not(any(
            feature = "hw-offload-mbuf-fast-free",
            feature = "hw-offload-tx-cksum",
            feature = "hw-offload-rx-cksum",
            feature = "hw-offload-rss-hash",
        )))]
        let _ = counters;

        let mut eth_conf: sys::rte_eth_conf = unsafe { std::mem::zeroed() };

        // Query the PMD's offload capabilities. A5 behavior: request
        // MULTI_SEGS (needed for retransmit mbuf-chain per spec §6.5, §8.2),
        // warn if the PMD does not advertise support, and drop the bit
        // from the applied mask so rte_eth_dev_configure does not refuse
        // the unsupported request.
        let mut dev_info: sys::rte_eth_dev_info = unsafe { std::mem::zeroed() };
        let info_rc = unsafe { sys::rte_eth_dev_info_get(cfg.port_id, &mut dev_info) };
        if info_rc != 0 {
            // Spec §4 step 1: hard-fail at bring-up. Continuing with a
            // zeroed `dev_info` would silently ignore every requested
            // offload (every capability AND returns zero), ship a
            // misleading all-zero banner, and then surface the failure
            // at rte_eth_dev_configure anyway — just later and less
            // clearly.
            return Err(Error::PortInfo(cfg.port_id, info_rc));
        }

        // Capture driver name for Task 12's LLQ verification — copy up to
        // 31 bytes + NUL terminator. `rte_eth_dev_info.driver_name` is
        // `*const c_char` owned by the PMD and stable for the life of the
        // port. Populated here (pre-`rte_eth_dev_configure`) so the
        // advertised-caps banner below can print it.
        let mut driver_name = [0u8; 32];
        if !dev_info.driver_name.is_null() {
            let src = dev_info.driver_name as *const u8;
            for (i, slot) in driver_name.iter_mut().take(31).enumerate() {
                // SAFETY: src is a non-null NUL-terminated C string from the
                // PMD; we walk at most 31 bytes and stop on NUL, so we never
                // read past the end of a well-formed driver name.
                let b = unsafe { *src.add(i) };
                if b == 0 {
                    break;
                }
                *slot = b;
            }
        }

        // Advertised-caps banner — per spec §8.5, the startup log is the
        // authoritative record of what the PMD advertises. Printed BEFORE
        // any offload-branch block ANDs requested bits against the caps.
        // `dev_info.dev_flags` is a `*const u32` owned by the PMD; deref
        // through a null-check so a misbehaving PMD cannot crash the banner.
        let dev_flags_val: u32 = if dev_info.dev_flags.is_null() {
            0
        } else {
            // SAFETY: non-null pointer into a PMD-owned flag word that is
            // valid for the life of the port.
            unsafe { *dev_info.dev_flags }
        };
        eprintln!(
            "resd_net: port {} driver={} rx_offload_capa=0x{:016x} \
             tx_offload_capa=0x{:016x} dev_flags=0x{:08x}",
            cfg.port_id,
            std::str::from_utf8(
                &driver_name[..driver_name.iter().position(|&b| b == 0).unwrap_or(32)]
            ).unwrap_or("<non-utf8>"),
            dev_info.rx_offload_capa,
            dev_info.tx_offload_capa,
            dev_flags_val,
        );

        let mut applied_tx_offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
        // `applied_rx_offloads` is mutated when any RX-side offload feature
        // is enabled (rx-cksum, rss-hash). Silence `unused_mut` when no
        // rx-side offload feature is active.
        #[cfg_attr(
            not(any(
                feature = "hw-offload-rx-cksum",
                feature = "hw-offload-rss-hash",
            )),
            allow(unused_mut)
        )]
        let mut applied_rx_offloads: u64 = 0;
        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) == 0 {
            eprintln!(
                "resd_net: PMD on port {} does not advertise RTE_ETH_TX_OFFLOAD_MULTI_SEGS; \
                 A5 retransmit chain may fail — check NIC/PMD support",
                cfg.port_id
            );
            applied_tx_offloads &= !RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
        }

        // --- MBUF_FAST_FREE (hw-offload-mbuf-fast-free) ---------------
        #[cfg(feature = "hw-offload-mbuf-fast-free")]
        {
            use crate::dpdk_consts::RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
            applied_tx_offloads |= and_offload_with_miss_counter(
                RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
                dev_info.tx_offload_capa,
                &counters.eth.offload_missing_mbuf_fast_free,
                "RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE",
                cfg.port_id,
            );
        }

        // --- TX checksum (hw-offload-tx-cksum) ------------------------
        #[cfg(feature = "hw-offload-tx-cksum")]
        let tx_cksum_offload_active = {
            use crate::dpdk_consts::{
                RTE_ETH_TX_OFFLOAD_IPV4_CKSUM, RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
                RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
            };
            let ipv4 = and_offload_with_miss_counter(
                RTE_ETH_TX_OFFLOAD_IPV4_CKSUM,
                dev_info.tx_offload_capa,
                &counters.eth.offload_missing_tx_cksum_ipv4,
                "RTE_ETH_TX_OFFLOAD_IPV4_CKSUM",
                cfg.port_id,
            );
            let tcp = and_offload_with_miss_counter(
                RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
                dev_info.tx_offload_capa,
                &counters.eth.offload_missing_tx_cksum_tcp,
                "RTE_ETH_TX_OFFLOAD_TCP_CKSUM",
                cfg.port_id,
            );
            let udp = and_offload_with_miss_counter(
                RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
                dev_info.tx_offload_capa,
                &counters.eth.offload_missing_tx_cksum_udp,
                "RTE_ETH_TX_OFFLOAD_UDP_CKSUM",
                cfg.port_id,
            );
            applied_tx_offloads |= ipv4 | tcp | udp;
            // Latch the runtime flag only if IPv4 + TCP both applied.
            // UDP is optional — Stage 1 has no UDP TX path.
            ipv4 != 0 && tcp != 0
        };
        #[cfg(not(feature = "hw-offload-tx-cksum"))]
        let tx_cksum_offload_active = false;

        // --- RX checksum (hw-offload-rx-cksum) ------------------------
        #[cfg(feature = "hw-offload-rx-cksum")]
        let rx_cksum_offload_active = {
            use crate::dpdk_consts::{
                RTE_ETH_RX_OFFLOAD_IPV4_CKSUM, RTE_ETH_RX_OFFLOAD_TCP_CKSUM,
                RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
            };
            let ipv4 = and_offload_with_miss_counter(
                RTE_ETH_RX_OFFLOAD_IPV4_CKSUM,
                dev_info.rx_offload_capa,
                &counters.eth.offload_missing_rx_cksum_ipv4,
                "RTE_ETH_RX_OFFLOAD_IPV4_CKSUM",
                cfg.port_id,
            );
            let tcp = and_offload_with_miss_counter(
                RTE_ETH_RX_OFFLOAD_TCP_CKSUM,
                dev_info.rx_offload_capa,
                &counters.eth.offload_missing_rx_cksum_tcp,
                "RTE_ETH_RX_OFFLOAD_TCP_CKSUM",
                cfg.port_id,
            );
            let udp = and_offload_with_miss_counter(
                RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
                dev_info.rx_offload_capa,
                &counters.eth.offload_missing_rx_cksum_udp,
                "RTE_ETH_RX_OFFLOAD_UDP_CKSUM",
                cfg.port_id,
            );
            applied_rx_offloads |= ipv4 | tcp | udp;
            ipv4 != 0 && tcp != 0
        };
        #[cfg(not(feature = "hw-offload-rx-cksum"))]
        let rx_cksum_offload_active = false;

        // --- RSS hash (hw-offload-rss-hash) ---------------------------
        #[cfg(feature = "hw-offload-rss-hash")]
        let rss_hash_offload_active = {
            use crate::dpdk_consts::{
                RTE_ETH_RSS_NONFRAG_IPV4_TCP, RTE_ETH_RSS_NONFRAG_IPV6_TCP,
                RTE_ETH_RX_OFFLOAD_RSS_HASH,
            };
            let bit = and_offload_with_miss_counter(
                RTE_ETH_RX_OFFLOAD_RSS_HASH,
                dev_info.rx_offload_capa,
                &counters.eth.offload_missing_rss_hash,
                "RTE_ETH_RX_OFFLOAD_RSS_HASH",
                cfg.port_id,
            );
            applied_rx_offloads |= bit;
            if bit != 0 {
                // DPDK ethdev rejects rte_eth_dev_rss_reta_update and ENA's
                // ena_rss_configure() ignores rss_hf unless mq_mode & RSS_FLAG
                // is set. Parent dpdk-tcp-design.md §8.1 / A-HW spec §8 both
                // imply RSS is active; this assignment is what actually
                // enables it. See drivers/net/ena/ena_ethdev.c:2410 and
                // lib/ethdev/rte_ethdev.c:4657.
                eth_conf.rxmode.mq_mode = sys::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS;
                eth_conf.rx_adv_conf.rss_conf.rss_hf =
                    RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP;
                eth_conf.rx_adv_conf.rss_conf.rss_key = std::ptr::null_mut();
                eth_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
            }
            bit != 0
        };
        #[cfg(not(feature = "hw-offload-rss-hash"))]
        let rss_hash_offload_active = false;

        eth_conf.txmode.offloads = applied_tx_offloads;
        eth_conf.rxmode.offloads = applied_rx_offloads;

        let rc = unsafe {
            sys::rte_eth_dev_configure(cfg.port_id, 1, 1, &eth_conf as *const _)
        };
        if rc != 0 {
            return Err(Error::PortConfigure(cfg.port_id, unsafe {
                sys::resd_rte_errno()
            }));
        }

        // Negotiated-caps banner — per spec §8.5, authoritative record of
        // which offload bits the PMD actually accepted.
        eprintln!(
            "resd_net: port {} configured rx_offloads=0x{:016x} tx_offloads=0x{:016x}",
            cfg.port_id, applied_rx_offloads, applied_tx_offloads,
        );

        Ok(PortConfigOutcome {
            applied_rx_offloads,
            applied_tx_offloads,
            tx_cksum_offload_active,
            rx_cksum_offload_active,
            rss_hash_offload_active,
            driver_name,
        })
    }

    /// Read the NIC-provided hardware RX timestamp from an mbuf. Returns
    /// 0 when (a) the feature is compile-off, (b) either the dynfield or
    /// dynflag lookup returned negative at engine_create, or (c) the
    /// mbuf's ol_flags do not indicate a valid timestamp. Spec §10.2.
    ///
    /// Hot-path cost when feature is on + both lookups succeeded: one
    /// branch on `ol_flags & mask` plus one `uint64_t` load from the
    /// dynfield offset. Feature off: compile-time 0.
    ///
    /// # Safety
    /// `mbuf` must be a valid pointer to a live `rte_mbuf`. In the hot
    /// path this is satisfied by the ownership rules around
    /// `rte_eth_rx_burst`. On ENA the function always returns 0 because
    /// the dynfield/dynflag are unregistered (spec §10.5), so the unsafe
    /// field read is never reached in Stage 1.
    #[cfg(feature = "hw-offload-rx-timestamp")]
    #[inline(always)]
    pub(crate) unsafe fn hw_rx_ts_ns(&self, mbuf: *const sys::rte_mbuf) -> u64 {
        match (self.rx_ts_offset, self.rx_ts_flag_mask) {
            (Some(off), Some(mask)) => {
                // SAFETY: caller guarantees mbuf points to a live rte_mbuf;
                // the shim reads ol_flags directly (bindgen cannot expose
                // the field because of the packed anonymous unions).
                let ol_flags = unsafe { sys::resd_rte_mbuf_get_ol_flags(mbuf) };
                if ol_flags & mask != 0 {
                    // SAFETY: `off` came from rte_mbuf_dynfield_lookup →
                    // the dynfield registrar guarantees `off..off+8` lies
                    // within the mbuf, and the field width is u64.
                    unsafe { sys::resd_rte_mbuf_read_dynfield_u64(mbuf, off) }
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// Feature-off stub: always returns 0. See spec §10.4.
    ///
    /// # Safety
    /// Stub accepts any pointer; it never dereferences. Kept `unsafe`
    /// so the signature matches the feature-on variant and call sites
    /// don't need `#[cfg]`-gated call syntax.
    #[cfg(not(feature = "hw-offload-rx-timestamp"))]
    #[inline(always)]
    pub(crate) const unsafe fn hw_rx_ts_ns(&self, _mbuf: *const sys::rte_mbuf) -> u64 {
        0
    }

    /// After `rte_eth_dev_start`, program the RSS indirection table so
    /// every bucket points at queue 0. Single-queue no-op at steering
    /// time, but required so `mbuf.hash.rss` is populated on ingress and
    /// so multi-queue bring-up (Stage 2) is a config change, not a code
    /// rewrite. See spec §8.
    #[cfg(feature = "hw-offload-rss-hash")]
    fn program_rss_reta_single_queue(
        port_id: u16,
        dev_info: &sys::rte_eth_dev_info,
    ) -> Result<(), Error> {
        let reta_size = dev_info.reta_size as usize;
        if reta_size == 0 {
            // PMD doesn't expose a reprogrammable reta (e.g. net_tap).
            // Single-queue steering is implicit; skip silently.
            return Ok(());
        }
        // `rte_eth_rss_reta_entry64` covers 64 slots per struct. Allocate
        // reta_size / 64 entries (rounded up), each with `mask = u64::MAX`
        // so the update writes every slot, and `reta[*] = 0` so every
        // slot points at queue 0.
        let num_entries = reta_size.div_ceil(64);
        let mut reta: Vec<sys::rte_eth_rss_reta_entry64> =
            vec![unsafe { std::mem::zeroed() }; num_entries];
        for entry in reta.iter_mut() {
            entry.mask = u64::MAX;
            // `reta` array on the struct is `[u16; 64]` already zeroed.
        }
        let rc = unsafe {
            sys::rte_eth_dev_rss_reta_update(
                port_id,
                reta.as_mut_ptr(),
                reta_size as u16,
            )
        };
        if rc != 0 {
            // Not fatal — reta update failing on a non-steering single-queue
            // deployment is not a correctness error. Warn and continue; the
            // flow_table's SipHash fallback keeps the data path correct.
            eprintln!(
                "resd_net: port {} RSS reta program failed rc={}; \
                 flow_table falls back to SipHash.",
                port_id, rc
            );
        }
        Ok(())
    }

    #[cfg(not(feature = "hw-offload-rss-hash"))]
    fn program_rss_reta_single_queue(
        _port_id: u16,
        _dev_info: &sys::rte_eth_dev_info,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// A5.5 Task 10: expose `EngineConfig` for the ABI crate's TLP
    /// validation helper (`tcp_min_rto_us` / `tcp_max_rto_us` substitution
    /// + range checks).
    pub fn config(&self) -> &EngineConfig {
        &self.cfg
    }

    pub fn our_mac(&self) -> [u8; 6] {
        self.our_mac
    }
    pub fn our_ip(&self) -> u32 {
        self.cfg.local_ip
    }
    pub fn gateway_mac(&self) -> [u8; 6] {
        self.cfg.gateway_mac
    }
    pub fn gateway_ip(&self) -> u32 {
        self.cfg.gateway_ip
    }
    pub fn pmtu_for(&self, ip: u32) -> Option<u16> {
        self.pmtu.borrow().get(ip)
    }

    /// TX a self-contained ≤128-byte frame (ARP reply / gratuitous ARP is 42
    /// bytes). Allocates one mbuf from tx_hdr_mempool, copies `bytes` into its
    /// data room via the `rte_pktmbuf_append` shim, then submits via a
    /// single-packet burst.
    /// Bumps `eth.tx_pkts` / `eth.tx_bytes` / `eth.tx_drop_nomem` /
    /// `eth.tx_drop_full_ring` as appropriate. Returns true if the packet
    /// was accepted by the driver.
    ///
    /// This path carries non-TCP frames (ARP) only; TCP control frames use
    /// [`Engine::tx_tcp_frame`] so the A-HW `tx_offload_finalize` hook can
    /// run between mbuf-fill and tx_burst.
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
            sys::resd_rte_eth_tx_burst(self.cfg.port_id, self.cfg.tx_queue_id, pkts.as_mut_ptr(), 1)
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

    /// TX a self-contained TCP control frame (SYN / ACK / RST / FIN). Same
    /// allocation + append + tx_burst sequence as [`Engine::tx_frame`], with
    /// a `tcp_output::tx_offload_finalize` call spliced between the mbuf
    /// fill and `rte_eth_tx_burst`.
    ///
    /// When `hw-offload-tx-cksum` is compile-enabled and
    /// `tx_cksum_offload_active == true`, the finalizer flips `ol_flags`,
    /// sets the `l2/l3/l4_len` triple, and rewrites the TCP/IPv4 cksum
    /// fields to their offload form (pseudo-header-only TCP cksum, zero
    /// IPv4 cksum). Otherwise the finalizer is a no-op and the software
    /// full-fold cksums from `build_segment` ship unchanged.
    /// Spec §6.2/§6.4.
    pub(crate) fn tx_tcp_frame(
        &self,
        bytes: &[u8],
        seg: &crate::tcp_output::SegmentTx,
    ) -> bool {
        use crate::counters::{add, inc};
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
        // Safety: `m` is freshly-allocated, exclusive to us until the
        // tx_burst below; build_segment wrote a full Ethernet+IPv4+TCP
        // frame into the mbuf's data room via copy_nonoverlapping above,
        // so the finalizer's data-buffer preconditions hold.
        unsafe {
            crate::tcp_output::tx_offload_finalize(
                m,
                seg,
                seg.payload.len() as u32,
                self.tx_cksum_offload_active,
            );
        }
        let mut pkts = [m];
        let sent = unsafe {
            sys::resd_rte_eth_tx_burst(self.cfg.port_id, self.cfg.tx_queue_id, pkts.as_mut_ptr(), 1)
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

    /// TX a full-size frame via `tx_data_mempool`. Used for TCP data
    /// segments where the frame size exceeds the small-mbuf pool's
    /// data room. Behavior is otherwise identical to `tx_frame`.
    ///
    /// A5 task 10: `send_bytes` no longer calls this — it inlines the
    /// alloc+append+refcnt_bump+tx_burst sequence so it can capture the
    /// mbuf pointer for `snd_retrans`. The helper is retained for future
    /// data-frame control paths that don't need in-flight tracking.
    #[allow(dead_code)]
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
            sys::resd_rte_eth_tx_burst(self.cfg.port_id, self.cfg.tx_queue_id, pkts.as_mut_ptr(), 1)
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

    /// A5 Task 18: build and transmit a SYN for conn `handle`. Used by
    /// `connect` (initial SYN) and `on_syn_retrans_fire` (retransmits).
    /// Returns `true` on successful TX; `false` on alloc / tx-ring-full.
    ///
    /// Pre-SYN-ACK the conn has no negotiated peer_mss, so `new_client`
    /// stashes `our_mss` into `peer_mss` as a placeholder (see
    /// `TcpConn::new_client`). Reading `c.peer_mss` here reliably gives
    /// back the MSS we advertised in the initial SYN — which is exactly
    /// what retransmits must carry per RFC 9293 §3.7.1.
    fn emit_syn(&self, handle: ConnHandle) -> bool {
        use crate::tcp_output::{build_segment, SegmentTx, TCP_SYN};
        let (tuple, iss, our_mss, recv_buffer_bytes, now_ns) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else {
                return false;
            };
            (
                c.four_tuple(),
                c.iss,
                c.peer_mss,
                self.cfg.recv_buffer_bytes,
                crate::clock::now_ns(),
            )
        };
        let syn_opts = build_connect_syn_opts(recv_buffer_bytes, our_mss, now_ns);
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
        let mut buf = [0u8; 128];
        let Some(n) = build_segment(&seg, &mut buf) else {
            return false;
        };
        let tx_ok = self.tx_tcp_frame(&buf[..n], &seg);
        // A5.5 Task 13: stash SYN TX timestamp on the ORIGINAL SYN only
        // (Karn's rule — the retransmit path increments `syn_retrans_count`
        // before re-entering `emit_syn`, so this guard fires exclusively on
        // the initial connect). `handle_syn_sent` consumes the field to
        // seed SRTT from the SYN handshake round-trip (RFC 6298 §3.3 MAY).
        if tx_ok {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                if c.syn_retrans_count == 0 {
                    c.syn_tx_ts_ns = now_ns;
                }
            }
        }
        tx_ok
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
    /// A5.5 Task 7: exposed so the C ABI `resd_net_conn_stats` can feed
    /// the configured buffer size into `ConnStats::send_buf_bytes_free`
    /// without re-plumbing the whole `EngineConfig`.
    pub fn send_buffer_bytes(&self) -> u32 {
        self.cfg.send_buffer_bytes
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
            self.advance_timer_wheel();
            self.reap_time_wait();
            self.maybe_emit_gratuitous_arp();
            return 0;
        }

        inc(&self.counters.poll.iters_with_rx);
        add(&self.counters.eth.rx_pkts, n as u64);

        // Hot-path poll-saturation signal. Bumped on every poll where
        // the rx_burst returned the full `BURST` ceiling — "we may be
        // falling behind the NIC". Single conditional fetch_add per
        // poll iteration; default-on per spec §9.1.1.
        #[cfg(feature = "obs-poll-saturation")]
        {
            if n == BURST {
                inc(&self.counters.poll.iters_with_rx_burst_max);
            }
        }

        // Hot-path TCP-payload-byte accumulator. Per-burst-batched per
        // spec §9.1.1 rule 2: stack-local sum, single fetch_add after
        // the burst drains. Compiled out entirely without the feature.
        #[cfg(feature = "obs-byte-counters")]
        let mut rx_bytes_acc: u64 = 0;

        for &m in &mbufs[..n] {
            let bytes = unsafe { crate::mbuf_data_slice(m) };
            // Task 8: read ol_flags once per mbuf at the RX boundary;
            // threaded through rx_frame -> handle_ipv4 -> tcp_input so
            // the IP + L4 offload classifications can gate on the bits
            // the NIC stamped on this frame. Spec §7.2: feature-off
            // builds do NOT read ol_flags (software verify always), so
            // the shim call is compile-gated away and the parameter is
            // fed as 0. Mirrors Task 9's pattern for nic_rss_hash.
            #[cfg(feature = "hw-offload-rx-cksum")]
            let ol_flags = unsafe { sys::resd_rte_mbuf_get_ol_flags(m) };
            #[cfg(not(feature = "hw-offload-rx-cksum"))]
            let ol_flags: u64 = 0;
            // Task 9: read the NIC-provided RSS Toeplitz hash alongside
            // ol_flags. Threaded through to flow_table::hash_bucket_for_lookup
            // in tcp_input. When the feature is off, we compile the read
            // away entirely (no bindgen call) and pass 0.
            #[cfg(feature = "hw-offload-rss-hash")]
            let nic_rss_hash = unsafe { sys::resd_rte_mbuf_get_rss_hash(m) };
            #[cfg(not(feature = "hw-offload-rss-hash"))]
            let nic_rss_hash: u32 = 0;
            // Task 11: read the NIC-provided RX timestamp alongside ol_flags
            // + nic_rss_hash. `hw_rx_ts_ns` yields 0 when the feature is off,
            // when either dynfield/dynflag lookup returned negative at
            // engine_create (expected on ENA — spec §10.5), or when the
            // mbuf's ol_flags do not indicate a valid timestamp. Threaded
            // through rx_frame -> handle_ipv4 -> tcp_input to both
            // RX-origin event emission sites (Connected + Readable).
            let hw_rx_ts = unsafe { self.hw_rx_ts_ns(m) };
            add(&self.counters.eth.rx_bytes, bytes.len() as u64);
            let _accepted = self.rx_frame(bytes, ol_flags, nic_rss_hash, hw_rx_ts);
            #[cfg(feature = "obs-byte-counters")]
            {
                rx_bytes_acc += _accepted as u64;
            }
            unsafe { sys::resd_rte_pktmbuf_free(m) };
        }

        #[cfg(feature = "obs-byte-counters")]
        {
            if rx_bytes_acc > 0 {
                add(&self.counters.tcp.rx_payload_bytes, rx_bytes_acc);
            }
        }

        self.advance_timer_wheel();
        self.reap_time_wait();
        self.maybe_emit_gratuitous_arp();
        n
    }

    /// A5 Task 12: advance the timer wheel to `now_ns` and dispatch fired
    /// timers by kind. `advance()` returns an owned `Vec`, so the
    /// `timer_wheel` borrow ends at the semicolon — per-timer handlers are
    /// free to re-borrow the wheel (e.g. `on_rto_fire` re-arms).
    fn advance_timer_wheel(&self) {
        let fired = self
            .timer_wheel
            .borrow_mut()
            .advance(crate::clock::now_ns());
        for (id, node) in fired {
            match node.kind {
                crate::tcp_timer_wheel::TimerKind::Rto => {
                    self.on_rto_fire(node.owner_handle, id);
                }
                crate::tcp_timer_wheel::TimerKind::Tlp => {
                    self.on_tlp_fire(node.owner_handle, id);
                }
                crate::tcp_timer_wheel::TimerKind::SynRetrans => {
                    self.on_syn_retrans_fire(node.owner_handle, id);
                }
                crate::tcp_timer_wheel::TimerKind::ApiPublic => {
                    // Wired in A6 public timer API. Silent no-op for now.
                }
            }
        }
    }

    /// A5 Task 12: RTO fire. Retransmits the front `snd_retrans` entry,
    /// bumps `tcp.tx_rto`, applies backoff (unless `rto_no_backoff`), and
    /// re-arms the RTO timer at `now + rto_us`. Silent no-op when the
    /// fired `TimerId` is stale (doesn't match `conn.rto_timer_id`) or
    /// `snd_retrans` is already empty (ACK raced the fire). Task 13
    /// inserts the max-retrans-count check between retransmit and
    /// backoff; Task 20 inserts the `RESD_NET_EVT_TCP_RETRANS` emission.
    pub(crate) fn on_rto_fire(
        &self,
        handle: ConnHandle,
        fired_id: crate::tcp_timer_wheel::TimerId,
    ) {
        // Phase 1: validate fired_id + read flags.
        let (is_current, is_empty, rto_no_backoff) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else { return };
            let current = c.rto_timer_id == Some(fired_id);
            (current, c.snd_retrans.is_empty(), c.rto_no_backoff)
        };
        if !is_current {
            // Stale fire (pre-cancel raced, or slot reused). Ignore.
            return;
        }

        // Phase 2: clear rto_timer_id + prune timer_ids.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.rto_timer_id = None;
                c.timer_ids.retain(|t| *t != fired_id);
            }
        }

        if is_empty {
            // Nothing to retransmit (ACK just pruned the last entry before
            // the fire cancel took effect). RTO stays disarmed.
            return;
        }

        // A5.5 Task 14 (AD-17): RFC 8985 §6.3 `RACK_mark_losses_on_RTO`
        // pass. Walks `snd_retrans` and collects every entry matching
        // the §6.3 formula (front-at-snd.una OR age-expired, minus
        // sacked / already-lost / cum-acked). Retransmitting ALL of
        // them in this pass (instead of just the front, as A5 Task 12
        // did) closes the tail-recovery dribble where subsequent ACKs
        // were driving one-seg-per-ACK retrans; a single RTO fire now
        // restores the full lost burst in one shot. Fallback: if the
        // helper returns empty (should not happen since the front
        // always matches the `seq == snd_una` clause when snd_retrans
        // is non-empty), fall back to A5 front-only retransmit to
        // avoid regression.
        let lost_indexes = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else { return };
            let rtt_us = c.rtt_est.srtt_us().unwrap_or(c.rack.min_rtt_us);
            let reo_wnd = c.rack.reo_wnd_us;
            let now_us = (crate::clock::now_ns() / 1_000) as u32;
            crate::tcp_rack::rack_mark_losses_on_rto(
                &c.snd_retrans.entries,
                c.snd_una,
                rtt_us,
                reo_wnd,
                now_us,
            )
        };
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                for &idx in &lost_indexes {
                    if let Some(e) = c.snd_retrans.entries.get_mut(idx as usize) {
                        e.lost = true;
                    }
                }
            }
        }

        // Phase 3: retransmit every §6.3-eligible in-flight entry.
        // `retransmit()` bumps `tx_retrans` per call (N total), and
        // clears `entry.lost` on success so sub-sequent RACK-detect
        // passes don't see stale flags. `tx_rto` bumps exactly once
        // per fire — preserves A5 one-RTO-fire-counter semantics
        // (one `tx_rto` + N `tx_retrans`).
        if lost_indexes.is_empty() {
            // Defensive fallback — helper should always pick the front.
            self.retransmit(handle, 0);
        } else {
            for &idx in &lost_indexes {
                self.retransmit(handle, idx as usize);
            }
        }
        crate::counters::inc(&self.counters.tcp.tx_rto);

        // Task 20: forensic per-packet event emission, gated by
        // `tcp_per_packet_events`. One `TcpRetrans` per retransmitted
        // entry (N total); one `TcpLossDetected{cause: Rto}` per fire
        // (the cause belongs to the RTO itself, not per-segment).
        // Placed BEFORE the max-retrans-count check so the final RTO
        // that triggers ETIMEDOUT still emits its per-packet trail for
        // forensic reconstruction. Borrows stay narrowly scoped so no
        // nested RefCell overlap with the subsequent backoff / re-arm
        // phases.
        if self.cfg.tcp_per_packet_events {
            let emitted_ts_ns = crate::clock::now_ns();
            let retrans_snapshots: Vec<(u32, u32)> = {
                let ft = self.flow_table.borrow();
                let c = match ft.get(handle) {
                    Some(c) => c,
                    None => return,
                };
                if lost_indexes.is_empty() {
                    c.snd_retrans
                        .front()
                        .map(|e| vec![(e.seq, e.xmit_count as u32)])
                        .unwrap_or_default()
                } else {
                    lost_indexes
                        .iter()
                        .filter_map(|&i| {
                            c.snd_retrans
                                .entries
                                .get(i as usize)
                                .map(|e| (e.seq, e.xmit_count as u32))
                        })
                        .collect()
                }
            };
            let mut ev = self.events.borrow_mut();
            for (seq, rtx_count) in retrans_snapshots {
                ev.push(
                    InternalEvent::TcpRetrans {
                        conn: handle,
                        seq,
                        rtx_count,
                        emitted_ts_ns,
                    },
                    &self.counters,
                );
            }
            ev.push(
                InternalEvent::TcpLossDetected {
                    conn: handle,
                    cause: crate::tcp_events::LossCause::Rto,
                    emitted_ts_ns,
                },
                &self.counters,
            );
        }

        // Task 13: max-retrans-count check. `retransmit()` above bumped
        // `xmit_count` on the front entry; once it crosses the budget we
        // abandon the connection with ETIMEDOUT. Task 21 plumbs the
        // budget through engine config (`tcp_max_retrans_count`).
        let xmit_count = {
            let ft = self.flow_table.borrow();
            ft.get(handle)
                .and_then(|c| c.snd_retrans.front())
                .map(|e| e.xmit_count)
                .unwrap_or(0)
        };
        if xmit_count as u32 > self.cfg.tcp_max_retrans_count {
            crate::counters::inc(&self.counters.tcp.conn_timeout_retrans);
            self.force_close_etimedout(handle);
            return;
        }

        // Phase 4: apply backoff unless per-connect opt-out.
        if !rto_no_backoff {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.rtt_est.apply_backoff();
            }
        }

        // Phase 5: compute new fire_at and arm a fresh RTO timer.
        let now_ns = crate::clock::now_ns();
        let new_rto_us = {
            let ft = self.flow_table.borrow();
            ft.get(handle).map(|c| c.rtt_est.rto_us()).unwrap_or(0)
        };
        if new_rto_us == 0 {
            // Defensive: don't arm a zero-delay timer.
            return;
        }
        let fire_at_ns = now_ns + (new_rto_us as u64 * 1_000);
        let id = self.timer_wheel.borrow_mut().add(
            now_ns,
            crate::tcp_timer_wheel::TimerNode {
                fire_at_ns,
                owner_handle: handle,
                kind: crate::tcp_timer_wheel::TimerKind::Rto,
                generation: 0,
                cancelled: false,
            },
        );

        // Phase 6: write the new timer id back onto the conn.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.rto_timer_id = Some(id);
                c.timer_ids.push(id);
            }
        }
    }

    /// A5 Task 17: TLP fire (RFC 8985 §7.3). Retransmits the last
    /// `snd_retrans` entry as a probe, soliciting a SACK that may reveal a
    /// tail loss not discoverable by RACK alone. Silent no-op when the
    /// fired `TimerId` is stale (doesn't match `conn.tlp_timer_id`) or
    /// `snd_retrans` is empty by fire time.
    ///
    /// For Stage 1, `select_probe` returns `NewData` when `snd.pending` is
    /// non-empty and `LastSegmentRetransmit` otherwise. Both branches
    /// retransmit the last in-flight segment here — true NewData probing
    /// (sending from `snd.pending` via a fresh `send_bytes`-shaped path)
    /// is a Stage 2 follow-up once post-TX push is re-enabled.
    ///
    /// Borrow discipline mirrors `on_rto_fire`: three phases with no
    /// nested borrows (validate → clear-state → retransmit). Task 20
    /// will insert `RESD_NET_EVT_TCP_LOSS_DETECTED{cause: Tlp}` emission
    /// gated on `tcp_per_packet_events`.
    pub(crate) fn on_tlp_fire(
        &self,
        handle: ConnHandle,
        fired_id: crate::tcp_timer_wheel::TimerId,
    ) {
        // Phase 1: validate fired_id + read probe inputs.
        let (is_current, retrans_len, pending_empty) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else { return };
            let current = c.tlp_timer_id == Some(fired_id);
            (current, c.snd_retrans.len(), c.snd.pending.is_empty())
        };
        if !is_current {
            // Stale fire (cancel raced, or slot reused). Ignore.
            return;
        }

        // Phase 2: clear tlp_timer_id + prune timer_ids.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.tlp_timer_id = None;
                c.timer_ids.retain(|t| *t != fired_id);
            }
        }

        // Phase 3: select + execute probe. `retrans_len` is captured from
        // the Phase-1 snapshot — it can't grow between phases (the ACK
        // path is the only mutator of `snd_retrans` and we're synchronous
        // here), so `retrans_len - 1` is a valid last index at fire time.
        // `select_probe` returning `Some` implies `retrans_len > 0` (the
        // `snd_retrans_nonempty` gate inside `select_probe`), so the
        // subtraction never underflows. Stage 1: both `NewData` and
        // `LastSegmentRetransmit` probe by retransmitting the last
        // in-flight segment. True NewData probing (draining from
        // `snd.pending`) is a Stage 2 follow-up.
        if crate::tcp_tlp::select_probe(!pending_empty, retrans_len > 0).is_some() {
            let probe_idx = retrans_len - 1;
            self.retransmit(handle, probe_idx);
            crate::counters::inc(&self.counters.tcp.tx_tlp);

            // A5.5 Task 11: record the probe in the recent-probes ring,
            // bump the consecutive-probes budget, and clear sample-seen
            // so the next arm waits for a fresh RTT sample (unless
            // `tlp_skip_rtt_sample_gate` is set). Read seq + len from
            // the retransmitted entry.
            let probe_info = {
                let ft = self.flow_table.borrow();
                ft.get(handle)
                    .and_then(|c| c.snd_retrans.entries.get(probe_idx))
                    .map(|e| (e.seq, e.len))
            };
            if let Some((probe_seq, probe_len)) = probe_info {
                let now_ns = crate::clock::now_ns();
                let mut ft = self.flow_table.borrow_mut();
                if let Some(c) = ft.get_mut(handle) {
                    c.on_tlp_probe_fired(probe_seq, probe_len, now_ns);
                }
            }

            // A5 Task 20: per-packet forensic emission, gated by
            // `tcp_per_packet_events`. Order: TcpRetrans (the probe
            // segment) then TcpLossDetected{cause: Tlp}. Read seq +
            // xmit_count from the last entry after retransmit.
            if self.cfg.tcp_per_packet_events {
                let (seq, rtx_count) = {
                    let ft = self.flow_table.borrow();
                    ft.get(handle)
                        .and_then(|c| c.snd_retrans.entries.get(probe_idx))
                        .map(|e| (e.seq, e.xmit_count as u32))
                        .unwrap_or((0, 0))
                };
                let emitted_ts_ns = crate::clock::now_ns();
                let mut ev = self.events.borrow_mut();
                ev.push(
                    InternalEvent::TcpRetrans {
                        conn: handle,
                        seq,
                        rtx_count,
                        emitted_ts_ns,
                    },
                    &self.counters,
                );
                ev.push(
                    InternalEvent::TcpLossDetected {
                        conn: handle,
                        cause: crate::tcp_events::LossCause::Tlp,
                        emitted_ts_ns,
                    },
                    &self.counters,
                );
            }
        }
    }

    /// A5 Task 18: SYN-retransmit fire (spec §6.5). Budget is three
    /// retransmits plus the initial SYN = four total TXes; exponential
    /// backoff starts at `max(initial_rto_us, min_rto_us)`. On the
    /// fourth fire (count crosses three) we force-close the connection
    /// with ETIMEDOUT and bump `tcp.conn_timeout_syn_sent`.
    ///
    /// Borrow discipline mirrors `on_rto_fire` / `on_tlp_fire`: five
    /// phases with no nested RefCell borrows. Validate → clear fired id
    /// → bump count → (retrans or force-close) → re-arm.
    pub(crate) fn on_syn_retrans_fire(
        &self,
        handle: ConnHandle,
        fired_id: crate::tcp_timer_wheel::TimerId,
    ) {
        // Phase 1: validate fired_id + capture current state.
        let (is_current, in_syn_sent) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else { return };
            let current = c.syn_retrans_timer_id == Some(fired_id);
            let in_syn = c.state == TcpState::SynSent;
            (current, in_syn)
        };
        if !is_current {
            // Stale fire (cancel raced, or slot reused). Ignore.
            return;
        }

        // Phase 2: clear syn_retrans_timer_id + prune timer_ids.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.syn_retrans_timer_id = None;
                c.timer_ids.retain(|t| *t != fired_id);
            }
        }
        if !in_syn_sent {
            // SYN-ACK already landed (or conn already closed). The
            // Outcome-path cancel normally beats us, but on a race the
            // cleared id above is sufficient — nothing more to do.
            return;
        }

        // Phase 3: bump retrans count + check budget. Count semantics:
        // initial SYN = 0; fire 1/2/3 = 1/2/3 retransmit; fire 4 → > 3 →
        // abandon. Total: 3 retransmits + 1 initial = 4 SYN TXes ≈ 75 ms
        // to ETIMEDOUT with 5 ms base (5+10+20+40).
        let new_count = {
            let mut ft = self.flow_table.borrow_mut();
            match ft.get_mut(handle) {
                Some(c) => {
                    c.syn_retrans_count = c.syn_retrans_count.saturating_add(1);
                    c.syn_retrans_count
                }
                None => return,
            }
        };
        if new_count > 3 {
            crate::counters::inc(&self.counters.tcp.conn_timeout_syn_sent);
            self.force_close_etimedout(handle);
            return;
        }

        // Phase 4: re-TX SYN via the shared helper.
        self.emit_syn(handle);

        // Phase 5: re-arm with exponential backoff. `shl` clamp at 6
        // caps the backoff multiplier at 64× base (~320 ms), which is
        // well above the budget window and protects against overflow.
        // `checked_shl` returns None only for shift >= 32 — our clamp at
        // 6 means the `unwrap_or` is unreachable, but kept for safety.
        let base_us = self.cfg.tcp_initial_rto_us.max(self.cfg.tcp_min_rto_us);
        let delay_us = base_us
            .checked_shl(new_count.min(6) as u32)
            .unwrap_or(u32::MAX);
        let now_ns = crate::clock::now_ns();
        let fire_at_ns = now_ns + (delay_us as u64 * 1_000);
        let id = self.timer_wheel.borrow_mut().add(
            now_ns,
            crate::tcp_timer_wheel::TimerNode {
                fire_at_ns,
                owner_handle: handle,
                kind: crate::tcp_timer_wheel::TimerKind::SynRetrans,
                generation: 0,
                cancelled: false,
            },
        );
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.syn_retrans_timer_id = Some(id);
                c.timer_ids.push(id);
            }
        }
    }

    /// A5 Task 13: force-close a connection due to RTO or SYN-retransmit
    /// budget exhaustion. Unlike `close_conn` (which sends a FIN), this
    /// does no wire-level sending — the peer is either unresponsive or
    /// has no listener. Drains `snd_retrans` (frees held mbufs via
    /// `rte_pktmbuf_free`), cancels all conn timers (`timer_ids` plus
    /// the three named handles `rto_timer_id` / `tlp_timer_id` /
    /// `syn_retrans_timer_id`), transitions to CLOSED, emits
    /// `Error` + `Closed` (err = -ETIMEDOUT), removes the conn slot.
    ///
    /// Borrow discipline (no nested borrows across phases):
    /// P1 mut flow_table → drain + take + snapshot; P2 FFI free (no
    /// borrows); P3 mut timer_wheel; P4 transition_conn (takes its own
    /// flow_table + events borrows internally, sequentially); P5 mut
    /// events; P6 mut flow_table. Each phase's borrow ends at the
    /// block's closing `}`.
    pub(crate) fn force_close_etimedout(&self, handle: ConnHandle) {
        // Phase 1: snapshot timer ids + drain snd_retrans mbufs. Note: do
        // NOT write conn.state here — transition_conn below owns that
        // transition so StateChange emission + state_trans[from][to]
        // counter bumps (spec §9.1 core TCP observability) are not
        // skipped.
        let (timer_ids_to_cancel, dropped_entries) = {
            let mut ft = self.flow_table.borrow_mut();
            let Some(conn) = ft.get_mut(handle) else {
                return;
            };
            let mut ids: Vec<crate::tcp_timer_wheel::TimerId> = conn.timer_ids.to_vec();
            if let Some(id) = conn.rto_timer_id.take() {
                ids.push(id);
            }
            if let Some(id) = conn.tlp_timer_id.take() {
                ids.push(id);
            }
            if let Some(id) = conn.syn_retrans_timer_id.take() {
                ids.push(id);
            }
            conn.timer_ids.clear();
            let entries: Vec<crate::tcp_retrans::RetransEntry> =
                conn.snd_retrans.entries.drain(..).collect();
            (ids, entries)
        };
        // Phase 2: free mbufs (outside any RefCell borrow).
        for entry in dropped_entries {
            unsafe {
                sys::resd_rte_pktmbuf_free(entry.mbuf.as_ptr());
            }
        }
        // Phase 3: cancel timers. `cancel()` is idempotent so overlap
        // between `timer_ids` and the three named handles is benign.
        {
            let mut w = self.timer_wheel.borrow_mut();
            for id in timer_ids_to_cancel {
                w.cancel(id);
            }
        }
        // Phase 4: state transition via transition_conn — emits the
        // StateChange event and bumps state_trans[from][Closed], keeping
        // the observability contract intact on ETIMEDOUT force-close.
        self.transition_conn(handle, TcpState::Closed);
        // Phase 5: push Error + Closed events (both carry -ETIMEDOUT;
        // the C ABI boundary translates the negative errno in Task 20).
        // `libc::ETIMEDOUT` is already `i32` on Linux — no cast needed.
        // Ordered AFTER transition_conn so StateChange lands before
        // Error/Closed in the event queue, matching the ordering used
        // elsewhere when a transition accompanies terminal events.
        {
            let emitted_ts_ns = crate::clock::now_ns();
            let mut ev = self.events.borrow_mut();
            ev.push(
                InternalEvent::Error {
                    conn: handle,
                    err: -libc::ETIMEDOUT,
                    emitted_ts_ns,
                },
                &self.counters,
            );
            ev.push(
                InternalEvent::Closed {
                    conn: handle,
                    err: -libc::ETIMEDOUT,
                    emitted_ts_ns,
                },
                &self.counters,
            );
        }
        // Phase 6: remove from flow_table.
        self.flow_table.borrow_mut().remove(handle);
        crate::counters::inc(&self.counters.tcp.conn_close);
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
                    let Some(c) = ft.get(*h) else {
                        return false;
                    };
                    c.state == TcpState::TimeWait
                        && c.time_wait_deadline_ns.is_some_and(|d| now >= d)
                })
                .collect()
        };
        for h in candidates {
            self.transition_conn(h, TcpState::Closed);
            self.events.borrow_mut().push(
                InternalEvent::Closed {
                    conn: h,
                    err: 0,
                    emitted_ts_ns: crate::clock::now_ns(),
                },
                &self.counters,
            );
            crate::counters::inc(&self.counters.tcp.conn_close);
            // A4 cross-phase backfill: TIME_WAIT deadline expired.
            crate::counters::inc(&self.counters.tcp.conn_time_wait_reaped);
            // A5: cancel any armed timers owned by this conn before
            // removing its slot. `cancel()` is idempotent (Task 5), so
            // overlap between `timer_ids` and named-handle fields is fine.
            let to_cancel: Vec<crate::tcp_timer_wheel::TimerId> = {
                let ft = self.flow_table.borrow();
                if let Some(conn) = ft.get(h) {
                    let mut ids: Vec<_> = conn.timer_ids.to_vec();
                    if let Some(id) = conn.rto_timer_id {
                        ids.push(id);
                    }
                    if let Some(id) = conn.tlp_timer_id {
                        ids.push(id);
                    }
                    if let Some(id) = conn.syn_retrans_timer_id {
                        ids.push(id);
                    }
                    ids
                } else {
                    Vec::new()
                }
            };
            {
                let mut w = self.timer_wheel.borrow_mut();
                for id in to_cancel {
                    w.cancel(id);
                }
            }
            self.flow_table.borrow_mut().remove(h);
        }
    }

    /// Drain up to `max` events from the internal queue. Returns the
    /// number of events drained. Callers in the C ABI layer translate
    /// the `InternalEvent` enum to the public union-tagged form.
    pub fn drain_events<F: FnMut(&InternalEvent, &Engine)>(&self, max: u32, mut sink: F) -> u32 {
        let mut n = 0u32;
        while n < max {
            let Some(ev) = self.events.borrow_mut().pop() else {
                break;
            };
            sink(&ev, self);
            n += 1;
        }
        n
    }

    /// Returns the count of TCP payload bytes accepted from this frame
    /// (`outcome.delivered + outcome.reassembly_queued_bytes`). Always
    /// computed; only consumed by the `obs-byte-counters` accumulator
    /// in `poll_once`. LLVM elides the dead-store path when the feature
    /// is off.
    ///
    /// `ol_flags` — mbuf offload flags as stamped by the PMD. Threaded
    /// through to the IP + TCP decode sites where Task 8's HW checksum
    /// classification gates on them. Test callers that aren't exercising
    /// the offload path pass `0` (UNKNOWN → software verify).
    ///
    /// `hw_rx_ts` — the NIC-provided RX timestamp (ns) captured at the
    /// RX decode boundary via `hw_rx_ts_ns`. Threaded through to the
    /// `Connected` + `Readable` event emission sites in `tcp_input` +
    /// `deliver_readable` (spec §10.3). `0` when the NIC didn't stamp
    /// one (expected on ENA — spec §10.5).
    fn rx_frame(&self, bytes: &[u8], ol_flags: u64, nic_rss_hash: u32, hw_rx_ts: u64) -> u32 {
        use crate::counters::inc;
        match crate::l2::l2_decode(bytes, self.our_mac) {
            Err(crate::l2::L2Drop::Short) => {
                inc(&self.counters.eth.rx_drop_short);
                0
            }
            Err(crate::l2::L2Drop::MissMac) => {
                inc(&self.counters.eth.rx_drop_miss_mac);
                0
            }
            Err(crate::l2::L2Drop::UnknownEthertype) => {
                inc(&self.counters.eth.rx_drop_unknown_ethertype);
                0
            }
            Ok(l2) => {
                let payload = &bytes[l2.payload_offset..];
                match l2.ethertype {
                    crate::l2::ETHERTYPE_ARP => {
                        inc(&self.counters.eth.rx_arp);
                        self.handle_arp(payload);
                        0
                    }
                    crate::l2::ETHERTYPE_IPV4 => {
                        self.handle_ipv4(payload, ol_flags, nic_rss_hash, hw_rx_ts)
                    }
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

    /// Returns TCP payload bytes accepted by the inner `tcp_input` (or 0
    /// for non-TCP / decode-error paths). Used by `poll_once`'s
    /// `obs-byte-counters` accumulator.
    ///
    /// `ol_flags` — the RX mbuf offload flags. Dispatches to
    /// `ip_decode_offload_aware`, which routes GOOD → skip IP software
    /// verify, BAD → drop + bump `eth.rx_drop_cksum_bad` + `ip.rx_csum_bad`,
    /// NONE/UNKNOWN → software verify. Gated on the compile-time
    /// `hw-offload-rx-cksum` feature AND the runtime
    /// `rx_cksum_offload_active` latch — if either is false the
    /// offload-aware wrapper degrades to the software path.
    fn handle_ipv4(&self, payload: &[u8], ol_flags: u64, nic_rss_hash: u32, hw_rx_ts: u64) -> u32 {
        use crate::counters::inc;
        match crate::l3_ip::ip_decode_offload_aware(
            payload,
            self.cfg.local_ip,
            ol_flags,
            self.rx_cksum_offload_active,
            &self.counters,
        ) {
            Err(crate::l3_ip::L3Drop::Short) => {
                inc(&self.counters.ip.rx_drop_short);
                0
            }
            Err(crate::l3_ip::L3Drop::BadVersion) => {
                inc(&self.counters.ip.rx_drop_bad_version);
                0
            }
            Err(crate::l3_ip::L3Drop::BadHeaderLen) => {
                inc(&self.counters.ip.rx_drop_bad_hl);
                0
            }
            Err(crate::l3_ip::L3Drop::BadTotalLen) => {
                inc(&self.counters.ip.rx_drop_short);
                0
            }
            Err(crate::l3_ip::L3Drop::CsumBad) => {
                inc(&self.counters.ip.rx_csum_bad);
                0
            }
            Err(crate::l3_ip::L3Drop::TtlZero) => {
                inc(&self.counters.ip.rx_ttl_zero);
                0
            }
            Err(crate::l3_ip::L3Drop::Fragment) => {
                inc(&self.counters.ip.rx_frag);
                0
            }
            Err(crate::l3_ip::L3Drop::NotOurs) => {
                inc(&self.counters.ip.rx_drop_not_ours);
                0
            }
            Err(crate::l3_ip::L3Drop::UnsupportedProto) => {
                inc(&self.counters.ip.rx_drop_unsupported_proto);
                0
            }
            Ok(ip) => {
                let inner = &payload[ip.header_len..ip.total_len];
                match ip.protocol {
                    crate::l3_ip::IPPROTO_TCP => {
                        inc(&self.counters.ip.rx_tcp);
                        self.tcp_input(&ip, inner, ol_flags, nic_rss_hash, hw_rx_ts)
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
                        0
                    }
                    _ => unreachable!("ip_decode filters unsupported protocols"),
                }
            }
        }
    }

    /// Real TCP input path (A3). Parses the segment, finds the flow,
    /// dispatches to per-state handler, emits ACK/RST and events.
    ///
    /// Returns the count of TCP payload bytes accepted by this segment
    /// (`outcome.delivered + outcome.reassembly_queued_bytes`). Drops,
    /// errors, and pure-ACK / control segments return 0. Used by the
    /// `obs-byte-counters` accumulator in `poll_once`.
    fn tcp_input(
        &self,
        ip: &crate::l3_ip::L3Decoded,
        tcp_bytes: &[u8],
        ol_flags: u64,
        nic_rss_hash: u32,
        hw_rx_ts: u64,
    ) -> u32 {
        use crate::counters::inc;
        use crate::tcp_input::{dispatch, parse_segment, tuple_from_segment, TxAction};

        // Task 8: classify the NIC-reported L4 checksum outcome before
        // dispatching the software fold inside `parse_segment`. Gated
        // on both the compile-time `hw-offload-rx-cksum` feature AND
        // the runtime `rx_cksum_offload_active` latch (spec §7.2).
        //
        // GOOD → tell parse_segment to skip the software fold.
        // BAD  → drop + bump eth.rx_drop_cksum_bad + tcp.rx_bad_csum.
        // NONE / UNKNOWN → fall through to software verify (existing path).
        //
        // Feature-off / latch-false builds always take the software
        // verify path, same as before A-HW.
        #[allow(unused_mut)]
        let mut nic_csum_ok = false;
        #[cfg(feature = "hw-offload-rx-cksum")]
        {
            if self.rx_cksum_offload_active {
                use crate::l3_ip::{classify_l4_rx_cksum, CksumOutcome};
                use std::sync::atomic::Ordering;
                match classify_l4_rx_cksum(ol_flags) {
                    CksumOutcome::Good => {
                        nic_csum_ok = true;
                    }
                    CksumOutcome::Bad => {
                        self.counters
                            .eth
                            .rx_drop_cksum_bad
                            .fetch_add(1, Ordering::Relaxed);
                        self.counters
                            .tcp
                            .rx_bad_csum
                            .fetch_add(1, Ordering::Relaxed);
                        return 0;
                    }
                    _ => {
                        // NONE / UNKNOWN — software verify via parse_segment.
                    }
                }
            }
        }
        #[cfg(not(feature = "hw-offload-rx-cksum"))]
        {
            let _ = ol_flags;
        }

        let parsed = match parse_segment(tcp_bytes, ip.src_ip, ip.dst_ip, nic_csum_ok) {
            Ok(p) => p,
            Err(e) => {
                match e {
                    crate::tcp_input::TcpParseError::Short => inc(&self.counters.tcp.rx_short),
                    crate::tcp_input::TcpParseError::BadFlags => {
                        inc(&self.counters.tcp.rx_bad_flags)
                    }
                    crate::tcp_input::TcpParseError::Csum => inc(&self.counters.tcp.rx_bad_csum),
                    crate::tcp_input::TcpParseError::BadDataOffset => {
                        inc(&self.counters.tcp.rx_short)
                    }
                }
                return 0;
            }
        };

        let tuple = tuple_from_segment(ip.src_ip, ip.dst_ip, &parsed);
        // Task 9: pick the initial bucket hash via the RSS-aware selector.
        // Feature-off / latch-off / flag-off all fall back to siphash_4tuple.
        let bucket_hash = crate::flow_table::hash_bucket_for_lookup(
            &tuple,
            ol_flags,
            nic_rss_hash,
            self.rss_hash_offload_active,
        );
        let handle = {
            self.flow_table
                .borrow()
                .lookup_by_hash(&tuple, bucket_hash)
        };
        let Some(handle) = handle else {
            // Unmatched: reply RST per spec §5.1 `reply_rst`.
            inc(&self.counters.tcp.rx_unmatched);
            self.send_rst_unmatched(&tuple, &parsed);
            return 0;
        };

        // Bump per-flag counters for observability before dispatch.
        use crate::tcp_output::{TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
        if (parsed.flags & TCP_SYN) != 0 && (parsed.flags & TCP_ACK) != 0 {
            inc(&self.counters.tcp.rx_syn_ack);
        }
        if (parsed.flags & TCP_ACK) != 0 {
            inc(&self.counters.tcp.rx_ack);
        }
        if (parsed.flags & TCP_FIN) != 0 {
            inc(&self.counters.tcp.rx_fin);
        }
        if (parsed.flags & TCP_RST) != 0 {
            inc(&self.counters.tcp.rx_rst);
        }
        if !parsed.payload.is_empty() {
            inc(&self.counters.tcp.rx_data);
        }

        let outcome = {
            let mut ft = self.flow_table.borrow_mut();
            let Some(conn) = ft.get_mut(handle) else {
                return 0;
            };
            dispatch(conn, &parsed)
        };

        // A4: map Outcome fields → TcpCounters slow-path bumps. Groups
        // all per-segment counter wiring in one place so the dispatch
        // hot-path stays straight-line.
        apply_tcp_input_counters(&outcome, &self.counters.tcp);

        // A5 Task 15: RACK-detected lost segments — retransmit each +
        // bump `tcp.tx_rack_loss`. Runs BEFORE the Task-11 prune below
        // so the `entry_index` values collected in `handle_established`
        // remain valid (prune_below pops from the front and would shift
        // remaining entries' indexes otherwise). `retransmit` manages
        // its own flow_table borrows, so we call it in a loop without
        // holding one ourselves. `handle_established` already filtered
        // cum-ACKed entries out of `rack_lost_indexes`, so the forthcoming
        // prune won't drop any entry referenced here.
        //
        // A5 Task 20: per-packet event emission, gated on
        // `tcp_per_packet_events`. For each RACK-lost index we read
        // the retransmitted entry's seq + xmit_count (after the retrans
        // bumped xmit_count) and emit `TcpRetrans` + `TcpLossDetected
        // { cause: Rack }`. Each event pair is its own narrow borrow of
        // flow_table + events so we never hold two RefCell borrows at
        // once.
        if !outcome.rack_lost_indexes.is_empty() {
            for i in &outcome.rack_lost_indexes {
                self.retransmit(handle, *i as usize);
                crate::counters::inc(&self.counters.tcp.tx_rack_loss);
                if self.cfg.tcp_per_packet_events {
                    let (seq, rtx_count) = {
                        let ft = self.flow_table.borrow();
                        ft.get(handle)
                            .and_then(|c| c.snd_retrans.entries.get(*i as usize))
                            .map(|e| (e.seq, e.xmit_count as u32))
                            .unwrap_or((0, 0))
                    };
                    let emitted_ts_ns = crate::clock::now_ns();
                    let mut ev = self.events.borrow_mut();
                    ev.push(
                        InternalEvent::TcpRetrans {
                            conn: handle,
                            seq,
                            rtx_count,
                            emitted_ts_ns,
                        },
                        &self.counters,
                    );
                    ev.push(
                        InternalEvent::TcpLossDetected {
                            conn: handle,
                            cause: crate::tcp_events::LossCause::Rack,
                            emitted_ts_ns,
                        },
                        &self.counters,
                    );
                }
            }
        }

        // A5 task 11: on an ACK that advanced snd.una, prune snd_retrans
        // below the new snd.una and free each dropped mbuf (its stashed
        // refcount 1→0 returns the mbuf to the mempool). If snd_retrans
        // is now empty AND snd.una == snd.nxt, cancel the RTO timer (and,
        // per Task 17, the TLP timer — same queue-empty precondition).
        //
        // Borrow ordering (no double-borrow on any RefCell):
        //   1. mut-borrow flow_table, prune, release.
        //   2. `resd_rte_pktmbuf_free` FFI calls outside any borrow.
        //   3. shared-borrow flow_table to check empty + read rto/tlp timer_id, release.
        //   4. mut-borrow timer_wheel to cancel, release.
        //   5. mut-borrow flow_table to clear rto/tlp_timer_id + prune timer_ids.
        if let Some(new_snd_una) = outcome.snd_una_advanced_to {
            let dropped = {
                let mut ft = self.flow_table.borrow_mut();
                if let Some(c) = ft.get_mut(handle) {
                    c.snd_retrans.prune_below(new_snd_una)
                } else {
                    Vec::new()
                }
            };
            for entry in dropped {
                unsafe { sys::resd_rte_pktmbuf_free(entry.mbuf.as_ptr()) };
            }
            let (rto_id_to_cancel, tlp_id_to_cancel) = {
                let ft = self.flow_table.borrow();
                if let Some(c) = ft.get(handle) {
                    if c.snd_retrans.is_empty() && c.snd_una == c.snd_nxt {
                        (c.rto_timer_id, c.tlp_timer_id)
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            };
            if let Some(id) = rto_id_to_cancel {
                self.timer_wheel.borrow_mut().cancel(id);
                let mut ft = self.flow_table.borrow_mut();
                if let Some(c) = ft.get_mut(handle) {
                    c.rto_timer_id = None;
                    c.timer_ids.retain(|t| *t != id);
                }
            }
            // A5 Task 17: also cancel TLP when snd_retrans empties + snd.una
            // caught up to snd.nxt — no tail to probe once the queue drains.
            if let Some(id) = tlp_id_to_cancel {
                self.timer_wheel.borrow_mut().cancel(id);
                let mut ft = self.flow_table.borrow_mut();
                if let Some(c) = ft.get_mut(handle) {
                    c.tlp_timer_id = None;
                    c.timer_ids.retain(|t| *t != id);
                }
            }

            // A5 Task 33.2 / RFC 6298 §5.3 step 5.3: on any ACK advancing
            // snd.una that leaves snd_retrans non-empty (partial ACK),
            // restart the RTO timer with `now + rto_us`. The cancel-on-empty
            // block above handles the full-drain case; here we re-arm the
            // timer so the remaining in-flight segment gets a fresh window
            // rather than inheriting the original arming from the oldest
            // now-acked segment. Borrow ordering mirrors the Task 11/17
            // 4-phase pattern:
            //   1. shared-borrow flow_table to decide need_restart, release.
            //   2. mut-borrow flow_table to `.take()` old rto_timer_id, release.
            //   3. mut-borrow timer_wheel to cancel, release.
            //   4. shared-borrow flow_table to read rto_us + now_ns, release.
            //   5. mut-borrow timer_wheel to add new timer, release.
            //   6. mut-borrow flow_table to stash new id + push to timer_ids.
            let need_restart = {
                let ft = self.flow_table.borrow();
                ft.get(handle)
                    .map(|c| !c.snd_retrans.is_empty() && c.rto_timer_id.is_some())
                    .unwrap_or(false)
            };
            if need_restart {
                let old_id = {
                    let mut ft = self.flow_table.borrow_mut();
                    ft.get_mut(handle).and_then(|c| c.rto_timer_id.take())
                };
                if let Some(id) = old_id {
                    self.timer_wheel.borrow_mut().cancel(id);
                    let mut ft = self.flow_table.borrow_mut();
                    if let Some(c) = ft.get_mut(handle) {
                        c.timer_ids.retain(|t| *t != id);
                    }
                }
                let (rto_us, now_ns) = {
                    let ft = self.flow_table.borrow();
                    (
                        ft.get(handle).map(|c| c.rtt_est.rto_us()).unwrap_or(0),
                        crate::clock::now_ns(),
                    )
                };
                if rto_us > 0 {
                    let fire_at_ns = now_ns + (rto_us as u64 * 1_000);
                    let id = self.timer_wheel.borrow_mut().add(
                        now_ns,
                        crate::tcp_timer_wheel::TimerNode {
                            fire_at_ns,
                            owner_handle: handle,
                            kind: crate::tcp_timer_wheel::TimerKind::Rto,
                            generation: 0,
                            cancelled: false,
                        },
                    );
                    let mut ft = self.flow_table.borrow_mut();
                    if let Some(c) = ft.get_mut(handle) {
                        c.rto_timer_id = Some(id);
                        c.timer_ids.push(id);
                    }
                }
            }
        }

        // A5 Task 17 / A5.5 Task 11 / A5.5 Task 15: TLP schedule (RFC
        // 8985 §7.2 + spec §3.4). Arm a probe timer at `now + PTO` when
        // `tlp_arm_gate_passes` — snd_retrans non-empty, no TLP already
        // pending, under the per-conn consecutive-probe budget, an RTT
        // sample has been absorbed since the last TLP (unless opted-out),
        // and SRTT is available. Runs after the Task 11 prune so we
        // don't arm a probe on a queue that just emptied. Delegates to
        // the shared `arm_tlp_pto` helper so the arm-on-ACK and
        // arm-on-send (Task 15) sites stay bit-identical.
        self.arm_tlp_pto(handle);

        // A5 Task 18: cancel the SYN-retransmit timer on SYN-ACK.
        // `handle_syn_sent` `.take()`s the conn's `syn_retrans_timer_id`
        // and plumbs it up via the Outcome so we can cancel it on the
        // timer wheel without re-borrowing the flow table inside the
        // handler. `cancel()` is idempotent — a racing fire that already
        // cleared the wheel entry is a silent no-op here.
        if let Some(id) = outcome.syn_retrans_timer_to_cancel {
            self.timer_wheel.borrow_mut().cancel(id);
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.timer_ids.retain(|t| *t != id);
            }
        }

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
            self.events.borrow_mut().push(
                InternalEvent::Connected {
                    conn: handle,
                    rx_hw_ts_ns: hw_rx_ts,
                    emitted_ts_ns: crate::clock::now_ns(),
                },
                &self.counters,
            );
            inc(&self.counters.tcp.conn_open);
        }

        if outcome.delivered > 0 {
            self.deliver_readable(handle, outcome.delivered, hw_rx_ts);
        }

        if outcome.buf_full_drop > 0 {
            crate::counters::add(
                &self.counters.tcp.recv_buf_drops,
                outcome.buf_full_drop as u64,
            );
        }

        if outcome.closed {
            self.events.borrow_mut().push(
                InternalEvent::Closed {
                    conn: handle,
                    err: 0,
                    emitted_ts_ns: crate::clock::now_ns(),
                },
                &self.counters,
            );
            inc(&self.counters.tcp.conn_close);
            // Bump conn_rst when the close was caused by RST (either
            // inbound RST received, or we're sending one via the SYN_SENT
            // bad-ACK / sync-state Rst paths). LastAck-fin_acked closes
            // and TIME_WAIT reaper closes are clean, not counted as RST.
            let rst_close = (parsed.flags & crate::tcp_output::TCP_RST) != 0
                || matches!(outcome.tx, TxAction::Rst | TxAction::RstForSynSentBadAck);
            if rst_close {
                inc(&self.counters.tcp.conn_rst);
            }
            // Remove the flow on final close (but leave TIME_WAIT alive
            // for the reaper — that's handled via `transition_conn`).
            let state = self.flow_table.borrow().get(handle).map(|c| c.state);
            if state == Some(TcpState::Closed) {
                // A5: cancel any armed timers owned by this conn before
                // removing its slot. `cancel()` is idempotent (Task 5),
                // so overlap between `timer_ids` and the named-handle
                // fields is fine.
                let to_cancel: Vec<crate::tcp_timer_wheel::TimerId> = {
                    let ft = self.flow_table.borrow();
                    if let Some(conn) = ft.get(handle) {
                        let mut ids: Vec<_> = conn.timer_ids.to_vec();
                        if let Some(id) = conn.rto_timer_id {
                            ids.push(id);
                        }
                        if let Some(id) = conn.tlp_timer_id {
                            ids.push(id);
                        }
                        if let Some(id) = conn.syn_retrans_timer_id {
                            ids.push(id);
                        }
                        ids
                    } else {
                        Vec::new()
                    }
                };
                {
                    let mut w = self.timer_wheel.borrow_mut();
                    for id in to_cancel {
                        w.cancel(id);
                    }
                }
                self.flow_table.borrow_mut().remove(handle);
            }
        }

        // Hot-path TCP-payload-bytes total accepted by this segment:
        // either delivered in-order (counted in `delivered`) or buffered
        // into the A4 reorder queue (counted in `reassembly_queued_bytes`).
        // At most one of these is non-zero per segment. Out-of-order
        // payload is enqueued, not dropped. Buffer-full drops
        // (`buf_full_drop`) are NOT counted here — they're separately
        // surfaced via `recv_buf_drops`. Consumed by the
        // `obs-byte-counters` accumulator in `poll_once`.
        outcome.delivered + outcome.reassembly_queued_bytes
    }

    fn transition_conn(&self, handle: ConnHandle, to: TcpState) {
        use crate::counters::inc;
        let mut ft = self.flow_table.borrow_mut();
        let Some(conn) = ft.get_mut(handle) else {
            return;
        };
        let from = conn.state;
        if from == to {
            return;
        }
        conn.state = to;
        // TIME_WAIT entry: arm the reaping deadline.
        if to == TcpState::TimeWait {
            let msl_ns = (self.cfg.tcp_msl_ms as u64) * 1_000_000;
            conn.time_wait_deadline_ns = Some(crate::clock::now_ns().saturating_add(2 * msl_ns));
        }
        drop(ft);
        inc(&self.counters.tcp.state_trans[from as usize][to as usize]);
        self.events.borrow_mut().push(
            InternalEvent::StateChange {
                conn: handle,
                from,
                to,
                emitted_ts_ns: crate::clock::now_ns(),
            },
            &self.counters,
        );
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
        let Some(conn) = ft.get(handle) else {
            return;
        };
        let t = conn.four_tuple();
        let ws_shift_out = conn.ws_shift_out;
        let ts_enabled = conn.ts_enabled;
        let ts_recent = conn.ts_recent;
        let sack_enabled = conn.sack_enabled;
        let free_space = conn.recv.free_space_total();
        let seq = conn.snd_nxt;
        let ack = conn.rcv_nxt;
        let last_advertised_wnd = conn.last_advertised_wnd;
        // F-8 RFC 2018 §4 MUST-26: the OOO-insert that triggered this
        // ACK; drives first-block ordering in `build_ack_outcome`.
        let trigger_range = conn.last_sack_trigger;
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
            trigger_range,
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
        let Some(n) = build_segment(&seg, &mut buf) else {
            return;
        };
        if self.tx_tcp_frame(&buf[..n], &seg) {
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
            // 0 → nonzero transition. Also clear the SACK trigger (F-8):
            // its purpose was to steer first-block ordering on THIS ACK;
            // re-using it on a subsequent ACK would falsely claim the
            // triggering segment is still freshly-arrived.
            {
                let mut ft = self.flow_table.borrow_mut();
                if let Some(c) = ft.get_mut(handle) {
                    c.last_advertised_wnd = Some(outcome.window);
                    c.last_sack_trigger = None;
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
        let Some(conn) = ft.get(handle) else {
            return;
        };
        let t = conn.four_tuple();
        let ack = incoming.seq.wrapping_add(incoming.payload.len() as u32);
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: t.local_ip,
            dst_ip: t.peer_ip,
            src_port: t.local_port,
            dst_port: t.peer_port,
            seq: conn.snd_nxt,
            ack,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            options: crate::tcp_options::TcpOpts::default(),
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else {
            return;
        };
        drop(ft);
        if self.tx_tcp_frame(&buf[..n], &seg) {
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
        let Some(n) = build_segment(&seg, &mut buf) else {
            return;
        };
        if self.tx_tcp_frame(&buf[..n], &seg) {
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
            let ack = incoming
                .seq
                .wrapping_add(incoming.payload.len() as u32)
                .wrapping_add(syn_len)
                .wrapping_add(fin_len);
            (0, ack, TCP_RST | TCP_ACK)
        };
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip,
            dst_ip: tuple.peer_ip,
            src_port: tuple.local_port,
            dst_port: tuple.peer_port,
            seq,
            ack,
            flags,
            window: 0,
            options: crate::tcp_options::TcpOpts::default(),
            payload: &[],
        };
        let mut buf = [0u8; 64];
        let Some(n) = build_segment(&seg, &mut buf) else {
            return;
        };
        if self.tx_tcp_frame(&buf[..n], &seg) {
            inc(&self.counters.tcp.tx_rst);
        }
    }

    /// `rx_hw_ts_ns` — NIC-provided RX timestamp captured at the per-mbuf
    /// decode boundary in `poll_once` and threaded through the RX frame
    /// path. Stored on the `Readable` event verbatim. Mbuf is no longer
    /// in scope here (data has already moved from mbuf to `conn.recv.bytes`),
    /// so this parameter is the only way to surface the NIC timestamp to
    /// the event consumer. `0` on ENA / feature-off (spec §10.3, §10.5).
    fn deliver_readable(&self, handle: ConnHandle, delivered: u32, rx_hw_ts_ns: u64) {
        use crate::counters::add;
        let mut ft = self.flow_table.borrow_mut();
        let Some(conn) = ft.get_mut(handle) else {
            return;
        };
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
        self.events.borrow_mut().push(
            InternalEvent::Readable {
                conn: handle,
                byte_offset,
                byte_len: delivered,
                rx_hw_ts_ns,
                emitted_ts_ns: crate::clock::now_ns(),
            },
            &self.counters,
        );
    }

    /// Open a new client-side connection. Emits a single SYN and
    /// returns the handle. The caller waits on `RESD_NET_EVT_CONNECTED`
    /// (or times out at application level — SYN retransmit is A5).
    ///
    /// `peer_ip` / `peer_port` in host byte order.
    /// `local_port_hint`: if nonzero, used as the source port; else we
    /// pick an ephemeral port from [49152, 65535].
    ///
    /// Thin wrapper over `connect_with_opts` using default per-connect
    /// opts (both A5 opt-ins disabled). Prefer `connect_with_opts` when
    /// caller needs `rack_aggressive` or `rto_no_backoff`.
    pub fn connect(
        &self,
        peer_ip: u32,
        peer_port: u16,
        local_port_hint: u16,
    ) -> Result<ConnHandle, Error> {
        self.connect_with_opts(peer_ip, peer_port, local_port_hint, ConnectOpts::default())
    }

    /// `connect` variant that accepts per-connect opt-ins (A5 Task 19).
    /// See [`ConnectOpts`] for field semantics.
    pub fn connect_with_opts(
        &self,
        peer_ip: u32,
        peer_port: u16,
        local_port_hint: u16,
        opts: ConnectOpts,
    ) -> Result<ConnHandle, Error> {
        use crate::counters::inc;
        use crate::tcp_conn::TcpConn;

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
            self.cfg.tcp_min_rto_us,
            self.cfg.tcp_initial_rto_us,
            self.cfg.tcp_max_rto_us,
        );
        let handle = match self.flow_table.borrow_mut().insert(conn) {
            Some(h) => h,
            None => {
                // A4 cross-phase backfill: flow table at `max_connections`.
                inc(&self.counters.tcp.conn_table_full);
                return Err(Error::TooManyConns);
            }
        };

        // A5 Task 19: apply per-connect opts to the freshly-inserted conn,
        // BEFORE emit_syn / SYN retrans timer arm so the fields are already
        // in effect if emit_syn (or a later RTO/RACK path after SYN-ACK)
        // consults them.
        //
        // A5.5 Task 10: mirror TLP tuning fields onto the conn. The ABI
        // helper `validate_and_defaults_tlp_opts` handles zero-init
        // substitution + range validation before this site is reached
        // from `resd_net_connect`; for core-level callers (internal
        // tests, engine-direct `connect()` wrapper) that pass
        // `ConnectOpts::default()`, we apply the same substitution
        // locally so the TcpConn always sees post-substitution values.
        let tlp_multiplier = if opts.tlp_pto_srtt_multiplier_x100 == 0 {
            crate::tcp_tlp::DEFAULT_MULTIPLIER_X100
        } else {
            opts.tlp_pto_srtt_multiplier_x100
        };
        let tlp_max_probes = if opts.tlp_max_consecutive_probes == 0 {
            crate::tcp_tlp::DEFAULT_MAX_CONSECUTIVE_PROBES
        } else {
            opts.tlp_max_consecutive_probes
        };
        let tlp_floor = if opts.tlp_pto_min_floor_us == 0 {
            self.cfg.tcp_min_rto_us
        } else {
            opts.tlp_pto_min_floor_us
        };
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.rack_aggressive = opts.rack_aggressive;
                c.rto_no_backoff = opts.rto_no_backoff;
                c.tlp_pto_min_floor_us = tlp_floor;
                c.tlp_pto_srtt_multiplier_x100 = tlp_multiplier;
                c.tlp_skip_flight_size_gate = opts.tlp_skip_flight_size_gate;
                c.tlp_max_consecutive_probes = tlp_max_probes;
                c.tlp_skip_rtt_sample_gate = opts.tlp_skip_rtt_sample_gate;
            }
        }
        if opts.rack_aggressive {
            inc(&self.counters.tcp.rack_reo_wnd_override_active);
        }
        if opts.rto_no_backoff {
            inc(&self.counters.tcp.rto_no_backoff_active);
        }

        // Build and transmit SYN with the full Stage-1 option set: MSS
        // (already clamped to MTU-40 above) + Window Scale + SACK-permitted
        // + Timestamps (RFC 7323 §4.1 initial TSval). Pre-WS-negotiation,
        // we advertise the maximum unscaled window — the SYN itself has no
        // scaled-window semantics; `ws_shift_out` kicks in for non-SYN
        // segments (Task 13). Delegates to `emit_syn`, which is also the
        // retransmit path from `on_syn_retrans_fire` (Task 18).
        let ws_out = compute_ws_shift_for(self.cfg.recv_buffer_bytes);
        if !self.emit_syn(handle) {
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

        // A5 Task 18: arm the SYN retransmit timer. 3 retransmits before
        // ETIMEDOUT force-close; exponential backoff starting at
        // `max(initial_rto_us, min_rto_us)`. Re-arms each fire inside
        // `on_syn_retrans_fire`; cancelled on SYN-ACK in `handle_syn_sent`
        // via `Outcome::syn_retrans_timer_to_cancel`. Task 21 plumbs
        // `tcp_initial_rto_us` / `tcp_min_rto_us` through engine config.
        let initial_delay_us = self.cfg.tcp_initial_rto_us.max(self.cfg.tcp_min_rto_us);
        let now_ns = crate::clock::now_ns();
        let fire_at_ns = now_ns + (initial_delay_us as u64 * 1_000);
        let id = self.timer_wheel.borrow_mut().add(
            now_ns,
            crate::tcp_timer_wheel::TimerNode {
                fire_at_ns,
                owner_handle: handle,
                kind: crate::tcp_timer_wheel::TimerKind::SynRetrans,
                generation: 0,
                cancelled: false,
            },
        );
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.syn_retrans_timer_id = Some(id);
                c.timer_ids.push(id);
            }
        }

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

        let (
            tuple,
            seq_start,
            snd_una,
            snd_wnd,
            peer_mss,
            state,
            rcv_nxt,
            free_space_total,
            ws_shift_out,
            ts_enabled,
            ts_recent,
        ) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else {
                return Err(Error::InvalidConnHandle(handle as u64));
            };
            (
                c.four_tuple(),
                c.snd_nxt,
                c.snd_una,
                c.snd_wnd,
                c.peer_mss,
                c.state,
                c.rcv_nxt,
                c.recv.free_space_total(),
                c.ws_shift_out,
                c.ts_enabled,
                c.ts_recent,
            )
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
        let mut remaining = bytes
            .len()
            .min(room_in_peer_wnd as usize)
            .min(send_buf_room as usize);
        let mut offset = 0usize;
        let mut accepted = 0u32;
        let mut cur_seq = seq_start;

        // F-4 RFC 7323 §2.3 / §2.2: SEG.WND on every non-SYN segment MUST
        // be right-shifted by Rcv.Wind.Shift. `ws_shift_out` is bounded at
        // 14 by compute_ws_shift_for, so `>>` is safe. Task 25: advertise
        // `recv.free_space_total()` (in-order + reorder capacity) to keep
        // the invariant "advertised window <= actual room" once OOO
        // segments accumulate; mirrors emit_ack's post-A4 I-8 fix.
        let advertised_window = (free_space_total >> ws_shift_out).min(u16::MAX as u32) as u16;

        // Hot-path TCP-payload-byte accumulator. Per-burst-batched per
        // spec §9.1.1 rule 2: stack-local sum across the per-segment
        // loop, single fetch_add at method exit. Compiled out entirely
        // without the feature.
        #[cfg(feature = "obs-byte-counters")]
        let mut tx_bytes_acc: u64 = 0;

        let mut frame = vec![0u8; 1600];
        while remaining > 0 {
            let take = remaining.min(mss_cap as usize);
            let payload = &bytes[offset..offset + take];
            // F-6 RFC 7323 §3 MUST-22: once TS is negotiated, every
            // non-RST segment MUST carry TSopt. TSval = now_µs per
            // §4.1; TSecr = the ts_recent we snapshot'd pre-loop.
            let options = if ts_enabled {
                let tsval = (crate::clock::now_ns() / 1000) as u32;
                crate::tcp_options::TcpOpts {
                    timestamps: Some((tsval, ts_recent)),
                    ..Default::default()
                }
            } else {
                crate::tcp_options::TcpOpts::default()
            };
            let seg = SegmentTx {
                src_mac: self.our_mac,
                dst_mac: self.cfg.gateway_mac,
                src_ip: tuple.local_ip,
                dst_ip: tuple.peer_ip,
                src_port: tuple.local_port,
                dst_port: tuple.peer_port,
                seq: cur_seq,
                ack: rcv_nxt,
                flags: TCP_ACK | TCP_PSH,
                window: advertised_window,
                options,
                payload,
            };
            // Budget 40 bytes for max TCP options (RFC 9293 §3.1 limit).
            // F-6 introduces TS option on data segments; with MSS-sized
            // payloads the frame grows by 12 bytes. Keep a 40-byte
            // cushion for any future option additions under A5+.
            let needed = crate::tcp_output::FRAME_HDRS_MIN + 40 + take;
            if frame.len() < needed {
                frame.resize(needed, 0);
            }
            let Some(n) = build_segment(&seg, &mut frame) else {
                // Shouldn't happen; buf is sized for hdrs+opts+take.
                break;
            };

            // A5 task 10: inline alloc + append + refcnt_update(+1) +
            // tx_burst, capturing the mbuf pointer so it can be stashed in
            // `snd_retrans` for retransmit. `tx_data_frame` is kept for
            // control frames; `send_bytes` needs the mbuf pointer and the
            // pre-tx_burst refcount bump, so the steps are inlined here.
            let m = unsafe { sys::resd_rte_pktmbuf_alloc(self.tx_data_mempool.as_ptr()) };
            if m.is_null() {
                inc(&self.counters.eth.tx_drop_nomem);
                if accepted == 0 {
                    return Err(Error::SendBufferFull);
                }
                break;
            }
            let dst = unsafe { sys::resd_rte_pktmbuf_append(m, n as u16) };
            if dst.is_null() {
                unsafe { sys::resd_rte_pktmbuf_free(m) };
                inc(&self.counters.eth.tx_drop_nomem);
                if accepted == 0 {
                    return Err(Error::SendBufferFull);
                }
                break;
            }
            // Safety: `dst` points to `n` writable bytes inside the freshly
            // allocated mbuf's data room (see DPDK `rte_pktmbuf_append`).
            unsafe {
                std::ptr::copy_nonoverlapping(frame.as_ptr(), dst as *mut u8, n);
            }
            // A-HW Task 7: apply TX offload metadata + pseudo-header-only
            // TCP cksum rewrite to the mbuf when offload is active.
            // Safety: `m` is freshly-allocated, exclusive to us until
            // tx_burst; the data buffer was fully populated by the
            // copy_nonoverlapping above (n bytes = full L2+L3+TCP+payload),
            // so the finalizer's data-buffer preconditions hold.
            unsafe {
                crate::tcp_output::tx_offload_finalize(
                    m,
                    &seg,
                    seg.payload.len() as u32,
                    self.tx_cksum_offload_active,
                );
            }
            // Bump refcount BEFORE tx_burst: after the call, the driver
            // holds one ref (freed on TX-completion) and we hold one ref
            // that lives in `snd_retrans` until Task 11's ACK-prune path.
            // On tx_burst failure neither owner takes the mbuf, so we free
            // it twice below (each call decrements refcount by 1).
            unsafe { sys::resd_rte_mbuf_refcnt_update(m, 1) };

            let mut pkts = [m];
            let sent = unsafe {
                sys::resd_rte_eth_tx_burst(
                    self.cfg.port_id,
                    self.cfg.tx_queue_id,
                    pkts.as_mut_ptr(),
                    1,
                )
            } as usize;
            if sent != 1 {
                // Driver did not take the mbuf — free both refs (2 → 1 → 0).
                unsafe { sys::resd_rte_pktmbuf_free(m) };
                unsafe { sys::resd_rte_pktmbuf_free(m) };
                inc(&self.counters.eth.tx_drop_full_ring);
                if accepted == 0 {
                    return Err(Error::SendBufferFull);
                }
                break;
            }
            crate::counters::add(&self.counters.eth.tx_bytes, n as u64);
            inc(&self.counters.eth.tx_pkts);
            inc(&self.counters.tcp.tx_data);
            #[cfg(feature = "obs-byte-counters")]
            {
                tx_bytes_acc += take as u64;
            }

            // Stash the segment in `snd_retrans` with the live mbuf ref.
            // Also arm the RTO timer exactly once per burst (when the first
            // segment transitions `snd_retrans` from empty → non-empty and
            // no RTO timer is currently scheduled). Subsequent segments in
            // the same burst observe `was_empty == false` and skip the arm.
            let first_tx_ts_ns = crate::clock::now_ns();
            let new_entry = crate::tcp_retrans::RetransEntry {
                seq: cur_seq,
                len: take as u16,
                mbuf: crate::mempool::Mbuf::from_ptr(m),
                first_tx_ts_ns,
                xmit_count: 1,
                sacked: false,
                lost: false,
                xmit_ts_ns: first_tx_ts_ns,
            };
            {
                let mut ft = self.flow_table.borrow_mut();
                let arm_rto = if let Some(c) = ft.get_mut(handle) {
                    let was_empty = c.snd_retrans.is_empty();
                    c.snd_retrans.push_after_tx(new_entry);
                    was_empty && c.rto_timer_id.is_none()
                } else {
                    false
                };
                if arm_rto {
                    // Release flow_table before borrowing timer_wheel to
                    // avoid RefCell double-borrow risk.
                    drop(ft);
                    let rto_us = {
                        let ft2 = self.flow_table.borrow();
                        ft2.get(handle).map(|c| c.rtt_est.rto_us()).unwrap_or(0)
                    };
                    if rto_us > 0 {
                        let fire_at = first_tx_ts_ns + (rto_us as u64 * 1_000);
                        let id = self.timer_wheel.borrow_mut().add(
                            first_tx_ts_ns,
                            crate::tcp_timer_wheel::TimerNode {
                                fire_at_ns: fire_at,
                                owner_handle: handle,
                                kind: crate::tcp_timer_wheel::TimerKind::Rto,
                                generation: 0,
                                cancelled: false,
                            },
                        );
                        let mut ft2 = self.flow_table.borrow_mut();
                        if let Some(c) = ft2.get_mut(handle) {
                            c.rto_timer_id = Some(id);
                            c.timer_ids.push(id);
                        }
                    }
                }
            }

            offset += take;
            accepted += take as u32;
            cur_seq = cur_seq.wrapping_add(take as u32);
            remaining -= take;
        }

        // A5 task 10: advance `snd_nxt`. `snd_retrans` now owns in-flight
        // tracking via mbuf refs (stashed per-segment above), so the former
        // A3 `c.snd.push(&bytes[..accepted])` is removed. The `snd: SendQueue`
        // field is kept for future pre-TX staging use — `send_bytes` takes
        // bytes directly from its argument and no longer stages via `snd`.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(c) = ft.get_mut(handle) {
                c.snd_nxt = cur_seq;
            }
        }
        if accepted < bytes.len() as u32 {
            inc(&self.counters.tcp.send_buf_full);
        }

        // Flush the per-call TX-payload-bytes accumulator. Single
        // `fetch_add` regardless of segment count.
        #[cfg(feature = "obs-byte-counters")]
        {
            if tx_bytes_acc > 0 {
                crate::counters::add(&self.counters.tcp.tx_payload_bytes, tx_bytes_acc);
            }
        }

        // A5.5 Task 15: RFC 8985 §7.2 SHOULD — arm TLP PTO after
        // transmitting new data. `arm_tlp_pto` is a no-op when the gate
        // rejects (already-armed, no SRTT, budget exhausted, etc.) so
        // calling it on every non-empty send is safe. Gating on
        // `accepted > 0` skips the call when nothing left the wire.
        if accepted > 0 {
            self.arm_tlp_pto(handle);
        }

        Ok(accepted)
    }

    /// A5.5 Task 15: AD-18 close — arm the TLP PTO timer per RFC 8985
    /// §7.2 after new data is transmitted. Mirrors the A5 arm-on-ACK
    /// block in the segment-processing path and is safe to call on
    /// every send: `tlp_arm_gate_passes` rejects when nothing is in
    /// flight, a TLP is already armed, the per-conn probe budget is
    /// exhausted, the RTT-sample-seen gate is closed, or SRTT is
    /// still unavailable (Karn's-rule skip pre-first-data-ACK).
    fn arm_tlp_pto(&self, handle: ConnHandle) {
        let arm_decision = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else {
                return;
            };
            if !c.tlp_arm_gate_passes() {
                return;
            }
            // Gate asserts `srtt_us().is_some()` — safe to unwrap.
            let srtt_us = c.rtt_est.srtt_us().unwrap();
            let tlp_cfg = c.tlp_config(self.cfg.tcp_min_rto_us);
            let flight_size = c.snd_retrans.flight_size() as u32;
            Some((srtt_us, tlp_cfg, flight_size))
        };
        let Some((srtt_us, tlp_cfg, flight_size)) = arm_decision else {
            return;
        };
        let pto_us = crate::tcp_tlp::pto_us(Some(srtt_us), &tlp_cfg, flight_size);
        let now_ns = crate::clock::now_ns();
        let fire_at_ns = now_ns + (pto_us as u64 * 1_000);
        let id = self.timer_wheel.borrow_mut().add(
            now_ns,
            crate::tcp_timer_wheel::TimerNode {
                fire_at_ns,
                owner_handle: handle,
                kind: crate::tcp_timer_wheel::TimerKind::Tlp,
                generation: 0,
                cancelled: false,
            },
        );
        let mut ft = self.flow_table.borrow_mut();
        if let Some(c) = ft.get_mut(handle) {
            c.tlp_timer_id = Some(id);
            c.timer_ids.push(id);
        }
    }

    pub fn close_conn(&self, handle: ConnHandle) -> Result<(), Error> {
        use crate::counters::inc;
        use crate::tcp_output::{build_segment, SegmentTx, TCP_ACK, TCP_FIN};

        let (tuple, seq, rcv_nxt, state, free_space_total, ws_shift_out, ts_enabled, ts_recent) = {
            let ft = self.flow_table.borrow();
            let Some(c) = ft.get(handle) else {
                return Err(Error::InvalidConnHandle(handle as u64));
            };
            (
                c.four_tuple(),
                c.snd_nxt,
                c.rcv_nxt,
                c.state,
                c.recv.free_space_total(),
                c.ws_shift_out,
                c.ts_enabled,
                c.ts_recent,
            )
        };

        // Only ESTABLISHED and CLOSE_WAIT may initiate FIN. Others are
        // already closing/closed; caller gets a successful no-op.
        let to_state = match state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return Ok(()),
        };

        // F-5 RFC 7323 §2.3 / §2.2: FIN is a non-SYN segment; SEG.WND
        // MUST be right-shifted by `ws_shift_out`. `ws_shift_out` is
        // bounded at 14 so `>>` is safe.
        let advertised_window = (free_space_total >> ws_shift_out).min(u16::MAX as u32) as u16;
        // F-7 RFC 7323 §3 MUST-22: FIN is a non-RST segment; when TS
        // is negotiated, TSopt MUST be present. TSval = now_µs per §4.1.
        let fin_options = if ts_enabled {
            let tsval = (crate::clock::now_ns() / 1000) as u32;
            crate::tcp_options::TcpOpts {
                timestamps: Some((tsval, ts_recent)),
                ..Default::default()
            }
        } else {
            crate::tcp_options::TcpOpts::default()
        };

        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip,
            dst_ip: tuple.peer_ip,
            src_port: tuple.local_port,
            dst_port: tuple.peer_port,
            seq,
            ack: rcv_nxt,
            flags: TCP_ACK | TCP_FIN,
            window: advertised_window,
            options: fin_options,
            payload: &[],
        };
        // Sized to cover max TCP-options budget (matching emit_ack): 14
        // (eth) + 20 (ip) + 20 (tcp min) + 40 (max tcp opts) = 94; round
        // to 128. Earlier 64-byte buffer only held header-only FINs and
        // would fail once F-7 (TS option on FIN) lands.
        let mut buf = [0u8; 128];
        let Some(n) = build_segment(&seg, &mut buf) else {
            return Err(Error::PeerUnreachable(tuple.peer_ip));
        };
        if !self.tx_tcp_frame(&buf[..n], &seg) {
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

    /// Retransmit the entry at `entry_index` in `conn.snd_retrans`. Allocates
    /// a fresh header mbuf from `tx_hdr_mempool`, writes L2+L3+TCP headers via
    /// `build_retrans_header`, bumps the held data mbuf's refcount, chains
    /// header → data via `rte_pktmbuf_chain`, and TXes. On chain-failure or
    /// alloc-failure, cleans up mbuf references atomically; on TX-ring-full,
    /// `rte_pktmbuf_free(head)` frees the whole chain per DPDK semantics.
    ///
    /// Bumps `xmit_count` + `xmit_ts_ns` on the entry and `tcp.tx_retrans` on
    /// success. Does NOT decide whether to retransmit — that's the caller's
    /// responsibility (Tasks 12 RTO / 15 RACK / 17 TLP / 18 SYN).
    ///
    /// Spec §6.5 "retransmit primitive": fresh header mbuf chained to the
    /// original data mbuf — never edits the in-flight mbuf in place.
    #[allow(dead_code)] // wired up in Tasks 12 / 15 / 17 / 18
    pub(crate) fn retransmit(&self, conn_handle: ConnHandle, entry_index: usize) {
        use crate::counters::inc;
        use crate::tcp_output::{build_retrans_header, SegmentTx, TCP_ACK, TCP_PSH};

        // Phase 1: snapshot the SegmentTx-building inputs + the data mbuf
        // pointer and payload-for-checksum bytes. We release the flow-table
        // borrow before doing any mbuf work.
        let Some(snapshot) = ({
            let ft = self.flow_table.borrow();
            let Some(conn) = ft.get(conn_handle) else {
                return;
            };
            let Some(entry) = conn.snd_retrans.entries.get(entry_index) else {
                return;
            };
            let tuple = conn.four_tuple();
            let seg_seq = entry.seq;
            let entry_len = entry.len;
            let data_mbuf_ptr = entry.mbuf.as_ptr();
            // Advertised window mirrors `send_bytes` (F-4 RFC 7323 §2.3):
            // non-SYN segment ⇒ right-shift by ws_shift_out. Task 25:
            // advertise `recv.free_space_total()` (in-order + reorder
            // capacity) so retrans frames stay consistent with emit_ack
            // and send_bytes — never overstating room past what the
            // OOO-aware recv buffer can actually hold.
            let advertised_window =
                (conn.recv.free_space_total() >> conn.ws_shift_out).min(u16::MAX as u32) as u16;
            let ts_enabled = conn.ts_enabled;
            let ts_recent = conn.ts_recent;
            let rcv_nxt = conn.rcv_nxt;
            Some((
                tuple,
                seg_seq,
                entry_len,
                data_mbuf_ptr,
                advertised_window,
                ts_enabled,
                ts_recent,
                rcv_nxt,
            ))
        }) else {
            return;
        };
        let (
            tuple,
            seg_seq,
            entry_len,
            data_mbuf_ptr,
            advertised_window,
            ts_enabled,
            ts_recent,
            rcv_nxt,
        ) = snapshot;

        if data_mbuf_ptr.is_null() {
            // Nothing we can do — entry has no backing data mbuf.
            return;
        }

        // Phase 2: allocate the header mbuf.
        let hdr_mbuf = unsafe { sys::resd_rte_pktmbuf_alloc(self.tx_hdr_mempool.as_ptr()) };
        if hdr_mbuf.is_null() {
            inc(&self.counters.eth.tx_drop_nomem);
            return;
        }

        // Build the SegmentTx template + read the original payload bytes
        // out of the data mbuf (for the TCP-checksum fold).
        // F-6 RFC 7323 §3 MUST-22: retrans segments carry TSopt when TS
        // was negotiated. TSval = now_µs per §4.1 (fresh on each retrans
        // so Karn-safe — the first-tx RTT sample is discarded on retx).
        let options = if ts_enabled {
            let tsval = (crate::clock::now_ns() / 1000) as u32;
            crate::tcp_options::TcpOpts {
                timestamps: Some((tsval, ts_recent)),
                ..Default::default()
            }
        } else {
            crate::tcp_options::TcpOpts::default()
        };
        let seg = SegmentTx {
            src_mac: self.our_mac,
            dst_mac: self.cfg.gateway_mac,
            src_ip: tuple.local_ip,
            dst_ip: tuple.peer_ip,
            src_port: tuple.local_port,
            dst_port: tuple.peer_port,
            seq: seg_seq,
            ack: rcv_nxt,
            flags: TCP_ACK | TCP_PSH,
            window: advertised_window,
            options,
            payload: &[],
        };

        // Read the original payload bytes directly from the data mbuf for
        // the TCP checksum fold. Stage 1 is single-segment-per-data-mbuf
        // (no nested chains in `snd_retrans`), so data_len == entry_len.
        //
        // Safety: data_mbuf_ptr came from a live RetransEntry; the engine
        // holds a refcount on it via Mbuf (incremented at push-time, not
        // yet decremented — snd_retrans still owns the entry).
        let data_ptr = unsafe { sys::resd_rte_pktmbuf_data(data_mbuf_ptr) } as *const u8;
        let data_len = unsafe { sys::resd_rte_pktmbuf_data_len(data_mbuf_ptr) };
        debug_assert!(
            !data_ptr.is_null(),
            "live mbuf in snd_retrans must have a valid data pointer"
        );
        debug_assert_eq!(
            data_len, entry_len,
            "Stage 1 invariant: snd_retrans entries are single-segment"
        );
        // Safety: data_ptr + data_len describe the data region of a live
        // mbuf we hold a refcount on. The slice lifetime is bounded by
        // this function (we do not stash it past the build_retrans_header
        // call, which copies out the bytes into its checksum fold).
        let payload_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(data_ptr, data_len as usize) };

        // Phase 3: write header bytes into the hdr mbuf. Budget the same
        // 40-byte TCP-options cushion as `send_bytes` (MSS + WS + SACK-perm
        // + TS peak = 20, plus SACK blocks). Ethernet(14) + IPv4(20) +
        // TCP(20+40) = 94 bytes; round to 128.
        let mut hdr_scratch = [0u8; 128];
        let Some(hdr_n) = build_retrans_header(&seg, payload_bytes, &mut hdr_scratch) else {
            // Header-too-small is impossible for 128-byte scratch; keep explicit.
            unsafe { sys::resd_rte_pktmbuf_free(hdr_mbuf) };
            inc(&self.counters.eth.tx_drop_nomem);
            return;
        };
        let dst = unsafe { sys::resd_rte_pktmbuf_append(hdr_mbuf, hdr_n as u16) };
        if dst.is_null() {
            unsafe { sys::resd_rte_pktmbuf_free(hdr_mbuf) };
            inc(&self.counters.eth.tx_drop_nomem);
            return;
        }
        // Safety: `dst` points to `hdr_n` writable bytes inside hdr_mbuf.
        unsafe {
            std::ptr::copy_nonoverlapping(hdr_scratch.as_ptr(), dst as *mut u8, hdr_n);
        }
        // A-HW Task 7: apply TX offload metadata + pseudo-header-only
        // TCP cksum rewrite to the hdr mbuf when offload is active.
        // payload_for_csum_len is the CHAINED data mbuf's bytes count —
        // the NIC computes the fold over the header + chained payload,
        // so the pseudo-header length field must declare the full wire
        // segment size, not just the hdr mbuf's data_len.
        //
        // Safety: `hdr_mbuf` is freshly-allocated, exclusive to us until
        // chain/tx_burst; the header mbuf's data buffer holds a full
        // Ethernet+IPv4+TCP header populated by build_retrans_header via
        // the copy_nonoverlapping above, so the finalizer's data-buffer
        // preconditions hold.
        unsafe {
            crate::tcp_output::tx_offload_finalize(
                hdr_mbuf,
                &seg,
                entry_len as u32,
                self.tx_cksum_offload_active,
            );
        }

        // Phase 4: bump data mbuf's refcount and chain. The refcnt_update
        // is paired with either the chain-success (the chain now owns one
        // of the references, dropped by rte_pktmbuf_free on the chain's
        // head) or the chain-failure rollback below.
        unsafe { sys::resd_rte_mbuf_refcnt_update(data_mbuf_ptr, 1) };
        let rc = unsafe { sys::resd_rte_pktmbuf_chain(hdr_mbuf, data_mbuf_ptr) };
        if rc != 0 {
            // Chain failed (e.g. would exceed RTE_MBUF_MAX_NB_SEGS). Roll
            // back the refcnt bump and free the hdr mbuf. The hdr mbuf
            // still owns zero chained segs at this point, so freeing it
            // only releases the header; the data mbuf is untouched.
            unsafe { sys::resd_rte_pktmbuf_free(hdr_mbuf) };
            unsafe { sys::resd_rte_mbuf_refcnt_update(data_mbuf_ptr, -1) };
            inc(&self.counters.eth.tx_drop_nomem);
            return;
        }

        // Phase 5: TX the chained mbuf.
        let mut bufs = [hdr_mbuf];
        let sent = unsafe {
            sys::resd_rte_eth_tx_burst(self.cfg.port_id, self.cfg.tx_queue_id, bufs.as_mut_ptr(), 1)
        } as usize;
        if sent == 0 {
            // TX ring full. `rte_pktmbuf_free(hdr_mbuf)` walks the chain
            // and drops the data-mbuf refcount we bumped in Phase 4 as
            // part of the standard chain-free path — do NOT double-free.
            unsafe { sys::resd_rte_pktmbuf_free(hdr_mbuf) };
            inc(&self.counters.eth.tx_drop_full_ring);
            return;
        }

        // Phase 6: update per-entry state + bump counters. Re-borrow the
        // flow table mutably only now, after all mbuf work is done.
        {
            let mut ft = self.flow_table.borrow_mut();
            if let Some(conn) = ft.get_mut(conn_handle) {
                if let Some(entry) = conn.snd_retrans.entries.get_mut(entry_index) {
                    entry.xmit_count = entry.xmit_count.saturating_add(1);
                    entry.xmit_ts_ns = crate::clock::now_ns();
                    entry.lost = false;
                }
            }
        }
        inc(&self.counters.tcp.tx_retrans);
        inc(&self.counters.eth.tx_pkts);
        crate::counters::add(
            &self.counters.eth.tx_bytes,
            (hdr_n + entry_len as usize) as u64,
        );
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
        assert_eq!(cfg.tcp_msl_ms, 30_000);
        assert!(!cfg.tcp_nagle);
    }

    #[test]
    fn engine_config_default_rto_values_match_spec() {
        let cfg = EngineConfig::default();
        assert_eq!(cfg.tcp_min_rto_us, 5_000);
        assert_eq!(cfg.tcp_initial_rto_us, 5_000);
        assert_eq!(cfg.tcp_max_rto_us, 1_000_000);
        assert_eq!(cfg.tcp_max_retrans_count, 15);
        assert!(!cfg.tcp_per_packet_events);
    }

    #[test]
    fn engine_config_default_event_queue_soft_cap_matches_spec() {
        let cfg = EngineConfig::default();
        assert_eq!(cfg.event_queue_soft_cap, 4096);
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

    // A5 Task 19: ConnectOpts type + connect_with_opts signature.
    #[test]
    fn connect_opts_default_is_both_false() {
        let opts = super::ConnectOpts::default();
        assert!(!opts.rack_aggressive);
        assert!(!opts.rto_no_backoff);
    }

    #[test]
    fn connect_with_opts_signature_exists() {
        // Compile-only: engine can't be constructed without EAL. This
        // asserts the method signature + that ConnectOpts is Copy (the
        // call site below moves it into a second slot).
        fn _check(e: &Engine) {
            let opts = super::ConnectOpts::default();
            let _ = e.connect_with_opts(0, 0, 0, opts);
            let _ = e.connect_with_opts(0, 0, 0, opts);
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

    // Task 9: retransmit primitive. Full TAP-level exercise lives in
    // Task 28 (RTO/RACK/TLP integration) and Task 30 (mbuf-chain). Here we
    // compile-check the method signature — a real Engine needs EAL/DPDK,
    // so unit coverage of the body is via the `build_retrans_header` unit
    // tests in `tcp_output.rs` plus the refcount/chain hand-trace in the
    // self-review. A `retransmit(...)` call on an empty `snd_retrans` or
    // stale entry_index is a silent no-op by design.
    #[test]
    fn retransmit_signature_exists() {
        fn _check(e: &Engine, h: crate::flow_table::ConnHandle) {
            e.retransmit(h, 0);
        }
    }

    // Task 12: `on_rto_fire` signature compile-check. Body coverage
    // lives in Task 28 (RTO/RACK/TLP TAP integration) — a real fire
    // needs EAL/DPDK. The handler itself is exercised indirectly via
    // `advance_timer_wheel` from `poll_once`.
    #[test]
    fn on_rto_fire_signature_exists() {
        fn _check(
            e: &Engine,
            h: crate::flow_table::ConnHandle,
            id: crate::tcp_timer_wheel::TimerId,
        ) {
            e.on_rto_fire(h, id);
        }
    }

    // Task 13: `force_close_etimedout` signature compile-check. Body
    // coverage via Task 28 TAP integration (RTO budget-exhaustion end-
    // to-end). The method is pub(crate) so this test can reference it.
    #[test]
    fn force_close_etimedout_signature_exists() {
        fn _check(e: &Engine, h: crate::flow_table::ConnHandle) {
            e.force_close_etimedout(h);
        }
    }

    // Task 17: `on_tlp_fire` signature compile-check. Body coverage lives
    // in Task 28 (RTO/RACK/TLP TAP integration) — a real fire needs EAL/
    // DPDK. Exercised indirectly via `advance_timer_wheel` from `poll_once`.
    #[test]
    fn on_tlp_fire_signature_exists() {
        fn _check(
            e: &Engine,
            h: crate::flow_table::ConnHandle,
            id: crate::tcp_timer_wheel::TimerId,
        ) {
            e.on_tlp_fire(h, id);
        }
    }

    // Task 18: `on_syn_retrans_fire` signature compile-check. Body
    // coverage lives in Task 28 TAP integration (SYN-budget exhaustion
    // end-to-end). A real fire needs EAL/DPDK. Handler is pub(crate) so
    // this test can reference it; exercised via `advance_timer_wheel`
    // from `poll_once`.
    #[test]
    fn on_syn_retrans_fire_signature_exists() {
        fn _check(
            e: &Engine,
            h: crate::flow_table::ConnHandle,
            id: crate::tcp_timer_wheel::TimerId,
        ) {
            e.on_syn_retrans_fire(h, id);
        }
    }

    // A5.5 Task 15: `arm_tlp_pto` signature compile-check. The helper
    // is a gate-guarded slow-path call from `send_bytes` (AD-18 close).
    // Body coverage lives in Task 28 TAP integration (first-burst TLP
    // observed when SRTT < RTO). The per-conn gate — including the
    // SRTT-present check added in Task 15 — is unit-tested in
    // `tcp_conn::a5_5_tlp_hook_tests`.
    #[test]
    fn arm_tlp_pto_signature_exists() {
        fn _check(e: &Engine, h: crate::flow_table::ConnHandle) {
            e.arm_tlp_pto(h);
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
            /* trigger_range */ None,
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
        let out = super::build_ack_outcome(0, false, 0, 12345, false, &[], None, 4096);
        assert!(out.opts.timestamps.is_none());
        assert_eq!(out.window, 4096);
    }

    #[test]
    fn build_ack_outcome_ws_shift_zero_passes_free_space_through() {
        // ws_shift=0 ⇒ no scaling; clamp still bounds at u16::MAX.
        let out = super::build_ack_outcome(0, false, 0, 0, false, &[], None, 50_000);
        assert_eq!(out.window, 50_000);
    }

    #[test]
    fn build_ack_outcome_window_clamps_to_u16_max() {
        // Unscaled 2 MiB ⇒ clamp to 65535 (what A3 did).
        let out = super::build_ack_outcome(0, false, 0, 0, false, &[], None, 2 * 1024 * 1024);
        assert_eq!(out.window, u16::MAX);
    }

    #[test]
    fn build_ack_outcome_scaled_window_clamps_to_u16_max() {
        // 512 MiB >> 3 = 64 MiB ⇒ still >> u16::MAX, so clamp.
        let out = super::build_ack_outcome(3, false, 0, 0, false, &[], None, 512 * 1024 * 1024);
        assert_eq!(out.window, u16::MAX);
    }

    #[test]
    fn build_ack_outcome_zero_free_space_signals_zero_window_and_window_zero() {
        let out = super::build_ack_outcome(7, false, 0, 0, false, &[], None, 0);
        assert_eq!(out.window, 0);
        assert!(out.zero_window);
    }

    #[test]
    fn build_ack_outcome_sack_blocks_emit_in_reverse_seq_order_without_trigger() {
        // No trigger_range supplied (e.g. pure-ACK path, no OOO insert
        // in this turn). Fallback: highest-seq-first per RFC 2018 §4's
        // "most recent" intent. Locks in the pre-F-8 ordering semantics.
        let reorder = [(1_000u32, 1_100u32), (2_000, 2_100), (3_000, 3_100)];
        let out = super::build_ack_outcome(0, false, 0, 0, true, &reorder, None, 4096);
        assert_eq!(out.sack_blocks_emitted, 3);
        assert_eq!(out.opts.sack_block_count, 3);
        // Reversed: highest seq (3000/3100) first.
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock {
                left: 3_000,
                right: 3_100
            }
        );
        assert_eq!(
            out.opts.sack_blocks[1],
            crate::tcp_options::SackBlock {
                left: 2_000,
                right: 2_100
            }
        );
        assert_eq!(
            out.opts.sack_blocks[2],
            crate::tcp_options::SackBlock {
                left: 1_000,
                right: 1_100
            }
        );
    }

    #[test]
    fn build_ack_outcome_trigger_middle_block_emitted_first() {
        // F-8 RFC 2018 §4 MUST-26: the block containing the triggering
        // segment's seq range MUST come first, even when it is not the
        // highest-seq block. Trigger (400, 500) should surface the
        // [400, 500) block; remaining emit reverse-seq (highest first).
        let reorder = [(200u32, 300u32), (400, 500), (600, 700)];
        let out = super::build_ack_outcome(0, false, 0, 0, true, &reorder, Some((400, 500)), 4096);
        assert_eq!(out.sack_blocks_emitted, 3);
        assert_eq!(out.opts.sack_block_count, 3);
        // Trigger block first.
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock {
                left: 400,
                right: 500
            }
        );
        // Remaining: highest-seq-first among non-trigger.
        assert_eq!(
            out.opts.sack_blocks[1],
            crate::tcp_options::SackBlock {
                left: 600,
                right: 700
            }
        );
        assert_eq!(
            out.opts.sack_blocks[2],
            crate::tcp_options::SackBlock {
                left: 200,
                right: 300
            }
        );
    }

    #[test]
    fn build_ack_outcome_trigger_merged_into_existing_block_emits_merged_first() {
        // Trigger (420, 450) fell inside an existing block (400, 500)
        // after merge-on-insert. `build_ack_outcome` finds the merged
        // block by `left <= trigger.0 < right` and emits it first.
        let reorder = [(200u32, 300u32), (400, 500)];
        let out = super::build_ack_outcome(0, false, 0, 0, true, &reorder, Some((420, 450)), 4096);
        assert_eq!(out.sack_blocks_emitted, 2);
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock {
                left: 400,
                right: 500
            }
        );
        assert_eq!(
            out.opts.sack_blocks[1],
            crate::tcp_options::SackBlock {
                left: 200,
                right: 300
            }
        );
    }

    #[test]
    fn build_ack_outcome_trigger_no_match_falls_back_to_reverse_order() {
        // Trigger range outside all reorder blocks (e.g. it was fully
        // consumed by drain_contiguous_from before emit). Fallback to
        // reverse-seq-first.
        let reorder = [(1_000u32, 1_100u32), (2_000, 2_100)];
        let out = super::build_ack_outcome(0, false, 0, 0, true, &reorder, Some((500, 600)), 4096);
        assert_eq!(out.sack_blocks_emitted, 2);
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock {
                left: 2_000,
                right: 2_100
            }
        );
    }

    #[test]
    fn build_ack_outcome_sack_disabled_skips_blocks_even_with_reorder() {
        // Peer didn't negotiate SACK-permitted ⇒ no blocks on wire.
        let reorder = [(100u32, 200u32)];
        let out = super::build_ack_outcome(0, false, 0, 0, false, &reorder, None, 4096);
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
        let out = super::build_ack_outcome(0, false, 0, 0, true, &reorder, None, 4096);
        assert_eq!(out.sack_blocks_emitted, 3);
        assert_eq!(out.opts.sack_block_count, 3);
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock {
                left: 5_000,
                right: 5_100
            }
        );
        assert_eq!(
            out.opts.sack_blocks[1],
            crate::tcp_options::SackBlock {
                left: 4_000,
                right: 4_100
            }
        );
        assert_eq!(
            out.opts.sack_blocks[2],
            crate::tcp_options::SackBlock {
                left: 3_000,
                right: 3_100
            }
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
            /* trigger_range */ None,
            /* free_space */ 256 * 1024,
        );
        assert_eq!(out.window, 2048);
        assert_eq!(out.opts.timestamps, Some((0x1234_5678, 0xdead_beef)));
        assert_eq!(out.sack_blocks_emitted, 2);
        assert_eq!(out.opts.sack_block_count, 2);
        // Most-recent (highest seq) first.
        assert_eq!(
            out.opts.sack_blocks[0],
            crate::tcp_options::SackBlock {
                left: 2_000,
                right: 2_100
            }
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

    // A5 Task 16: DSACK counter bumped by the count in Outcome.
    #[test]
    fn apply_tcp_input_counters_rx_dsack_adds_count() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.rx_dsack_count = 2;
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rx_dsack.load(Ordering::Relaxed), 2);
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

    // A5 Task 22: parser-layer WS>14 clamp signal → counter bump.
    #[test]
    fn apply_tcp_input_counters_maps_ws_shift_clamped() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.ws_shift_clamped = true;
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rx_ws_shift_clamped.load(Ordering::Relaxed), 1);
    }

    // A5 Task 26: RTT sample taken (Task 11's Outcome flag) → counter bump.
    #[test]
    fn apply_tcp_input_counters_bumps_rtt_samples_when_flag_set() {
        let c = crate::counters::TcpCounters::default();
        let mut o = crate::tcp_input::Outcome::base();
        o.rtt_sample_taken = true;
        super::apply_tcp_input_counters(&o, &c);
        use std::sync::atomic::Ordering;
        assert_eq!(c.rtt_samples.load(Ordering::Relaxed), 1);
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
        assert_eq!(c.rx_dsack.load(Ordering::Relaxed), 0);
        assert_eq!(c.rx_ws_shift_clamped.load(Ordering::Relaxed), 0);
        assert_eq!(c.rtt_samples.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod a_hw_port_config_tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::and_offload_with_miss_counter;

    #[test]
    fn offload_miss_bumps_counter_returns_zero() {
        let ctr = AtomicU64::new(0);
        let bit: u64 = 1 << 3;
        let advertised = 0u64;
        let applied = and_offload_with_miss_counter(bit, advertised, &ctr, "tx-tcp-cksum", 0);
        assert_eq!(applied, 0);
        assert_eq!(ctr.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn offload_present_no_bump_returns_bit() {
        let ctr = AtomicU64::new(0);
        let bit: u64 = 1 << 3;
        let advertised = bit;
        let applied = and_offload_with_miss_counter(bit, advertised, &ctr, "tx-tcp-cksum", 0);
        assert_eq!(applied, bit);
        assert_eq!(ctr.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn offload_not_requested_noop() {
        let ctr = AtomicU64::new(0);
        let applied = and_offload_with_miss_counter(0, u64::MAX, &ctr, "ignored", 0);
        assert_eq!(applied, 0);
        assert_eq!(ctr.load(Ordering::Relaxed), 0);
    }
}
