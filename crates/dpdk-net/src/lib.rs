#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]

pub mod api;

use api::*;
use dpdk_net_core::clock;
use dpdk_net_core::counters::Counters;
use dpdk_net_core::engine::{self, Engine, EngineConfig};
use std::ffi::CStr;
use std::ptr;

/// A6 (spec §3.5): latency preset — all existing config fields honored
/// as-written (post zero-sentinel substitution).
pub const DPDK_NET_PRESET_LATENCY: u8 = 0;
/// A6 (spec §3.5): RFC-compliance preset — overrides five fields per
/// parent spec §4: `tcp_nagle`, `tcp_delayed_ack`, `cc_mode`,
/// `tcp_min_rto_us`, `tcp_initial_rto_us`.
pub const DPDK_NET_PRESET_RFC_COMPLIANCE: u8 = 1;

/// A6 (spec §3.5): apply a preset to a core `EngineConfig` after the
/// zero-sentinel substitution pass. The preset override is stronger
/// than defaults — any explicit caller values for the five preset
/// fields are overwritten when `preset == DPDK_NET_PRESET_RFC_COMPLIANCE`.
///
/// Returns `Err(())` for unknown presets (>= 2); `dpdk_net_engine_create`
/// surfaces that as a null-pointer return to the C caller.
pub fn apply_preset(
    preset: u8,
    core_cfg: &mut dpdk_net_core::engine::EngineConfig,
) -> Result<(), ()> {
    match preset {
        DPDK_NET_PRESET_LATENCY => Ok(()),
        DPDK_NET_PRESET_RFC_COMPLIANCE => {
            core_cfg.tcp_nagle = true;
            core_cfg.tcp_delayed_ack = true;
            core_cfg.cc_mode = 1; // Reno
            core_cfg.tcp_min_rto_us = 200_000;
            core_cfg.tcp_initial_rto_us = 1_000_000;
            Ok(())
        }
        _ => Err(()),
    }
}

/// Opaque handle — actually a Box<Engine> reinterpreted as *mut dpdk_net_engine.
struct OpaqueEngine(Engine);

fn box_to_raw(e: Engine) -> *mut dpdk_net_engine {
    Box::into_raw(Box::new(OpaqueEngine(e))) as *mut dpdk_net_engine
}

unsafe fn engine_from_raw<'a>(p: *mut dpdk_net_engine) -> Option<&'a Engine> {
    if p.is_null() {
        return None;
    }
    Some(&(&*(p as *const OpaqueEngine)).0)
}

/// Initialize DPDK EAL. Must be called before dpdk_net_engine_create.
/// `argv` is a C-style argv array; the function does NOT take ownership
/// (copies each argument into Rust-owned CStrings internally).
/// Safe to call multiple times; subsequent calls after the first return 0.
/// Returns 0 on success, negative errno on failure.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_eal_init(argc: i32, argv: *const *const libc::c_char) -> i32 {
    if argc < 0 || argv.is_null() {
        return -libc::EINVAL;
    }
    let args: Vec<String> = (0..argc as isize)
        .map(|i| {
            let p = *argv.offset(i);
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        })
        .collect();
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match engine::eal_init(&refs) {
        Ok(()) => 0,
        Err(_) => -libc::EAGAIN,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_engine_create(
    lcore_id: u16,
    cfg: *const dpdk_net_engine_config_t,
) -> *mut dpdk_net_engine {
    if cfg.is_null() {
        return ptr::null_mut();
    }
    let cfg = &*cfg;
    if cfg.event_queue_soft_cap < 64 {
        return ptr::null_mut();
    }
    // A3 fields with 0 sentinels fall back to defaults so callers that
    // don't supply them get sensible behavior.
    let max_conns = if cfg.max_connections == 0 {
        16
    } else {
        cfg.max_connections
    };
    let recv_buf = if cfg.recv_buffer_bytes == 0 {
        256 * 1024
    } else {
        cfg.recv_buffer_bytes
    };
    let send_buf = if cfg.send_buffer_bytes == 0 {
        256 * 1024
    } else {
        cfg.send_buffer_bytes
    };
    let mss = if cfg.tcp_mss == 0 { 1460 } else { cfg.tcp_mss };
    // A5 Task 21: RTO config in µs; zero means "use default".
    let min_rto_us = if cfg.tcp_min_rto_us == 0 {
        5_000
    } else {
        cfg.tcp_min_rto_us
    };
    let initial_rto_us = if cfg.tcp_initial_rto_us == 0 {
        5_000
    } else {
        cfg.tcp_initial_rto_us
    };
    let max_rto_us = if cfg.tcp_max_rto_us == 0 {
        1_000_000
    } else {
        cfg.tcp_max_rto_us
    };
    let max_retrans = if cfg.tcp_max_retrans_count == 0 {
        15
    } else {
        cfg.tcp_max_retrans_count
    };
    let msl = if cfg.tcp_msl_ms == 0 {
        30_000
    } else {
        cfg.tcp_msl_ms
    };

    let mut core_cfg = EngineConfig {
        lcore_id,
        port_id: cfg.port_id,
        rx_queue_id: cfg.rx_queue_id,
        tx_queue_id: cfg.tx_queue_id,
        rx_ring_size: 1024,
        tx_ring_size: 1024,
        rx_mempool_elems: 8192,
        mbuf_data_room: 2048,
        local_ip: cfg.local_ip,
        gateway_ip: cfg.gateway_ip,
        gateway_mac: cfg.gateway_mac,
        garp_interval_sec: cfg.garp_interval_sec,
        max_connections: max_conns,
        recv_buffer_bytes: recv_buf,
        send_buffer_bytes: send_buf,
        tcp_mss: mss,
        tcp_msl_ms: msl,
        tcp_nagle: cfg.tcp_nagle,
        // A6 Task 9 (spec §3.5): ABI-to-core pass-through. Pre-preset
        // value honored when `preset == DPDK_NET_PRESET_LATENCY`; `apply_preset`
        // below overwrites to `true` when `preset == DPDK_NET_PRESET_RFC_COMPLIANCE`.
        tcp_delayed_ack: cfg.tcp_delayed_ack,
        // A6 Task 9 (spec §3.5): ABI-to-core pass-through. Pre-preset
        // value honored when `preset == DPDK_NET_PRESET_LATENCY`; `apply_preset`
        // overwrites to `1` (Reno) when `preset == DPDK_NET_PRESET_RFC_COMPLIANCE`.
        cc_mode: cfg.cc_mode,
        tcp_min_rto_us: min_rto_us,
        tcp_initial_rto_us: initial_rto_us,
        tcp_max_rto_us: max_rto_us,
        tcp_max_retrans_count: max_retrans,
        tcp_per_packet_events: cfg.tcp_per_packet_events,
        event_queue_soft_cap: cfg.event_queue_soft_cap,
        // A6 Task 20: ABI-layer pass-through of the caller-supplied
        // bucket edges. All-zero input triggers the spec §3.8.2 default
        // substitution in `Engine::new`; non-monotonic input causes
        // `Engine::new` to reject and is surfaced here as a null-return.
        rtt_histogram_bucket_edges_us: cfg.rtt_histogram_bucket_edges_us,
        // A-HW+ T7 (ENA README §5.1): informational knobs consumed by
        // `dpdk_net_recommended_ena_devargs` (T8) and the bring-up
        // overflow-risk assertion (T9). 0 = use PMD default on both.
        ena_large_llq_hdr: cfg.ena_large_llq_hdr,
        ena_miss_txc_to_sec: cfg.ena_miss_txc_to_sec,
    };
    // A6 Task 9 (spec §3.5): apply preset override AFTER zero-sentinel
    // substitution so the preset values are never clobbered by the
    // substitution pass. Unknown presets (>= 2) null-return.
    if apply_preset(cfg.preset, &mut core_cfg).is_err() {
        return ptr::null_mut();
    }
    match Engine::new(core_cfg) {
        Ok(e) => box_to_raw(e),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_engine_destroy(p: *mut dpdk_net_engine) {
    if p.is_null() {
        return;
    }
    let _boxed = Box::from_raw(p as *mut OpaqueEngine);
    // Drop runs Engine's Drop impl.
}

/// Pure translation: `InternalEvent` → `dpdk_net_event_t`. The caller
/// resolves the `Readable` variant's (data_ptr, data_len) via the engine's
/// flow table and passes it in; for every other variant the tuple is
/// ignored. `enqueued_ts_ns` on the returned event is read from the
/// variant's `emitted_ts_ns` field — sampled at push time inside the
/// engine (A5.5 Task 1), not at drain time. Split out so the "drain copies
/// through, not re-samples" contract is unit-testable without an EAL-backed
/// Engine or a mock clock.
fn build_event_from_internal(
    ev: &dpdk_net_core::tcp_events::InternalEvent,
    readable_view: (*const u8, u32),
) -> dpdk_net_event_t {
    use dpdk_net_core::tcp_events::{InternalEvent, LossCause};
    let emitted = match ev {
        InternalEvent::Connected { emitted_ts_ns, .. }
        | InternalEvent::Readable { emitted_ts_ns, .. }
        | InternalEvent::Closed { emitted_ts_ns, .. }
        | InternalEvent::StateChange { emitted_ts_ns, .. }
        | InternalEvent::Error { emitted_ts_ns, .. }
        | InternalEvent::TcpRetrans { emitted_ts_ns, .. }
        | InternalEvent::TcpLossDetected { emitted_ts_ns, .. }
        | InternalEvent::ApiTimer { emitted_ts_ns, .. }
        | InternalEvent::Writable { emitted_ts_ns, .. } => *emitted_ts_ns,
    };
    match ev {
        InternalEvent::Connected {
            conn, rx_hw_ts_ns, ..
        } => dpdk_net_event_t {
            kind: dpdk_net_event_kind_t::DPDK_NET_EVT_CONNECTED,
            conn: *conn as u64,
            rx_hw_ts_ns: *rx_hw_ts_ns,
            enqueued_ts_ns: emitted,
            u: dpdk_net_event_payload_t { _pad: [0u8; 16] },
        },
        InternalEvent::Readable {
            conn,
            byte_len,
            rx_hw_ts_ns,
            ..
        } => dpdk_net_event_t {
            kind: dpdk_net_event_kind_t::DPDK_NET_EVT_READABLE,
            conn: *conn as u64,
            rx_hw_ts_ns: *rx_hw_ts_ns,
            enqueued_ts_ns: emitted,
            u: dpdk_net_event_payload_t {
                readable: dpdk_net_event_readable_t {
                    data: readable_view.0,
                    data_len: *byte_len,
                },
            },
        },
        InternalEvent::Closed { conn, err, .. } => dpdk_net_event_t {
            kind: dpdk_net_event_kind_t::DPDK_NET_EVT_CLOSED,
            conn: *conn as u64,
            rx_hw_ts_ns: 0,
            enqueued_ts_ns: emitted,
            u: dpdk_net_event_payload_t {
                closed: dpdk_net_event_error_t { err: *err },
            },
        },
        InternalEvent::StateChange { conn, from, to, .. } => dpdk_net_event_t {
            kind: dpdk_net_event_kind_t::DPDK_NET_EVT_TCP_STATE_CHANGE,
            conn: *conn as u64,
            rx_hw_ts_ns: 0,
            enqueued_ts_ns: emitted,
            u: dpdk_net_event_payload_t {
                tcp_state: dpdk_net_event_tcp_state_t {
                    from_state: *from as u8,
                    to_state: *to as u8,
                },
            },
        },
        InternalEvent::Error { conn, err, .. } => dpdk_net_event_t {
            kind: dpdk_net_event_kind_t::DPDK_NET_EVT_ERROR,
            conn: *conn as u64,
            rx_hw_ts_ns: 0,
            enqueued_ts_ns: emitted,
            u: dpdk_net_event_payload_t {
                error: dpdk_net_event_error_t { err: *err },
            },
        },
        // A5 Task 20: per-packet retransmit observability. Emitted
        // (only) when `tcp_per_packet_events=true`; carries the
        // just-retransmitted segment's seq + post-retrans xmit_count.
        InternalEvent::TcpRetrans {
            conn,
            seq,
            rtx_count,
            ..
        } => dpdk_net_event_t {
            kind: dpdk_net_event_kind_t::DPDK_NET_EVT_TCP_RETRANS,
            conn: *conn as u64,
            rx_hw_ts_ns: 0,
            enqueued_ts_ns: emitted,
            u: dpdk_net_event_payload_t {
                tcp_retrans: dpdk_net_event_tcp_retrans_t {
                    seq: *seq,
                    rtx_count: *rtx_count,
                },
            },
        },
        // A5 Task 20: loss-detector observability. `trigger` encodes
        // `LossCause` as `Rack=0`, `Tlp=1`, `Rto=2` (matching enum
        // order). `first_seq` is left 0 here — the paired TcpRetrans
        // event that precedes each TcpLossDetected carries the seq.
        InternalEvent::TcpLossDetected { conn, cause, .. } => {
            let trigger: u8 = match cause {
                LossCause::Rack => 0,
                LossCause::Tlp => 1,
                LossCause::Rto => 2,
            };
            dpdk_net_event_t {
                kind: dpdk_net_event_kind_t::DPDK_NET_EVT_TCP_LOSS_DETECTED,
                conn: *conn as u64,
                rx_hw_ts_ns: 0,
                enqueued_ts_ns: emitted,
                u: dpdk_net_event_payload_t {
                    tcp_loss: dpdk_net_event_tcp_loss_t {
                        first_seq: 0,
                        trigger,
                    },
                },
            }
        }
        // A6 Task 17 (spec §5.3): public-timer fire translator. The
        // wheel's `TimerId{slot, generation}` re-packs to the same u64
        // the caller originally received from `dpdk_net_timer_add`; the
        // opaque `user_data` round-trips through unchanged.
        InternalEvent::ApiTimer { timer_id, user_data, .. } => {
            dpdk_net_event_t {
                kind: dpdk_net_event_kind_t::DPDK_NET_EVT_TIMER,
                conn: 0,
                rx_hw_ts_ns: 0,
                enqueued_ts_ns: emitted,
                u: dpdk_net_event_payload_t {
                    timer: dpdk_net_event_timer_t {
                        timer_id: dpdk_net_core::engine::pack_timer_id(*timer_id),
                        user_data: *user_data,
                    },
                },
            }
        }
        // A6 Task 16 (spec §3.3): level-triggered WRITABLE hysteresis.
        // Upstream emit lives in `Engine::tcp_input` after
        // `apply_tcp_input_counters` when `outcome.writable_hysteresis_fired`
        // latches (in-flight drained to ≤ send_buffer_bytes/2 after a
        // prior send_bytes refusal). No payload — union zeroed.
        InternalEvent::Writable { conn, .. } => dpdk_net_event_t {
            kind: dpdk_net_event_kind_t::DPDK_NET_EVT_WRITABLE,
            conn: *conn as u64,
            rx_hw_ts_ns: 0,
            enqueued_ts_ns: emitted,
            u: dpdk_net_event_payload_t { _pad: [0u8; 16] },
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_poll(
    p: *mut dpdk_net_engine,
    events_out: *mut dpdk_net_event_t,
    max_events: u32,
    _timeout_ns: u64,
) -> i32 {
    let Some(e) = engine_from_raw(p) else {
        return -libc::EINVAL;
    };
    e.poll_once();
    if events_out.is_null() || max_events == 0 {
        return 0;
    }
    let mut filled: u32 = 0;
    e.drain_events(max_events, |ev, engine| {
        // Resolve the `Readable` variant's data-view pointer into the
        // connection's last_read_buf (Task 19 fix for multi-segment polls).
        // Non-Readable variants ignore the tuple.
        let readable_view: (*const u8, u32) = match ev {
            dpdk_net_core::tcp_events::InternalEvent::Readable {
                conn,
                byte_offset,
                byte_len,
                ..
            } => {
                let ft = engine.flow_table();
                match ft.get(*conn) {
                    Some(c) => {
                        let off = *byte_offset as usize;
                        let ptr = unsafe { c.recv.last_read_buf.as_ptr().add(off) };
                        (ptr, *byte_len)
                    }
                    None => (std::ptr::null(), 0),
                }
            }
            _ => (std::ptr::null(), 0),
        };
        // Build the event value fully before writing it to events_out, so
        // we never read a possibly-uninitialized `kind` discriminant.
        let event = build_event_from_internal(ev, readable_view);
        unsafe {
            std::ptr::write(events_out.add(filled as usize), event);
        }
        filled += 1;
    });
    filled as i32
}

/// A6 (spec §4.2): drains the pending data-segment TX batch via one
/// `rte_eth_tx_burst`. No-op when ring empty. Idempotent.
/// Control frames (ACK, SYN, FIN, RST) are emitted inline at their
/// emit site and do not participate in the flush batch — flushing
/// never blocks or reorders control-frame emission.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_flush(p: *mut dpdk_net_engine) {
    let Some(e) = engine_from_raw(p) else { return };
    e.flush_tx_pending_data();
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_now_ns(_p: *mut dpdk_net_engine) -> u64 {
    clock::now_ns()
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_counters(p: *mut dpdk_net_engine) -> *const dpdk_net_counters_t {
    match engine_from_raw(p) {
        Some(e) => e.counters() as *const Counters as *const dpdk_net_counters_t,
        None => ptr::null(),
    }
}

/// Slow-path: trigger an ENA-PMD xstats scrape. Reads ENI
/// allowance-exceeded + per-queue (q0) Tx/Rx counters via DPDK
/// rte_eth_xstats_get_by_id and writes them into the counters
/// snapshot. Application calls this on its own cadence (typically
/// 1 Hz). On non-ENA / non-advertising PMDs this is a cheap no-op.
///
/// Returns 0 on success (always — failures are silent and observable
/// via the counters staying at their last value).
/// Returns -EINVAL if `p` is null.
///
/// # Safety
/// `p` must be a valid Engine pointer obtained from
/// `dpdk_net_engine_create`.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_scrape_xstats(p: *mut dpdk_net_engine) -> i32 {
    match engine_from_raw(p) {
        Some(e) => {
            e.scrape_xstats();
            0
        }
        None => -libc::EINVAL,
    }
}

/// Slow-path snapshot of a connection's send-path + RTT estimator state,
/// for per-order forensics tagging (spec §5.3, §7.2.3–7.2.6). Safe to call
/// at order-emit time; not meant for hot-loop polling.
///
/// Returns:
///   0       on success; `out` is populated.
///   -EINVAL engine or out is NULL.
///   -ENOENT conn is not a live handle in the engine's flow table
///           (never-allocated, stale post-close, or reserved `0`).
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_conn_stats(
    engine: *mut dpdk_net_engine,
    conn: dpdk_net_conn_t,
    out: *mut dpdk_net_conn_stats_t,
) -> i32 {
    if engine.is_null() || out.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(engine) else {
        return -libc::EINVAL;
    };
    let handle = conn as dpdk_net_core::flow_table::ConnHandle;
    let send_buffer_bytes = e.send_buffer_bytes();
    let ft = e.flow_table();
    match ft.get_stats(handle, send_buffer_bytes) {
        Some(s) => {
            (*out).snd_una = s.snd_una;
            (*out).snd_nxt = s.snd_nxt;
            (*out).snd_wnd = s.snd_wnd;
            (*out).send_buf_bytes_pending = s.send_buf_bytes_pending;
            (*out).send_buf_bytes_free = s.send_buf_bytes_free;
            (*out).srtt_us = s.srtt_us;
            (*out).rttvar_us = s.rttvar_us;
            (*out).min_rtt_us = s.min_rtt_us;
            (*out).rto_us = s.rto_us;
            0
        }
        None => -libc::ENOENT,
    }
}

/// A6 (spec §3.8, §5.3): per-connection RTT histogram snapshot.
///
/// Each bucket counts RTT samples whose value is <= the corresponding
/// edge in `rtt_histogram_bucket_edges_us[]` (bucket 15 is the catch-
/// all for values greater than the last edge). Counters are u32 per-
/// connection lifetime; applications take deltas across two snapshots
/// using unsigned wraparound subtraction. See the core `rtt_histogram.rs`
/// module doc-comment for the full wraparound contract.
///
/// Slow-path: safe per-order for forensics tagging, safe per-minute for
/// session-health polling. Do not call in a per-segment loop.
///
/// Returns:
///   0       on success; `out` is populated with 64 bytes.
///   -EINVAL engine or out is NULL.
///   -ENOENT conn is not a live handle in the engine's flow table.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_conn_rtt_histogram(
    engine: *mut dpdk_net_engine,
    conn: dpdk_net_conn_t,
    out: *mut dpdk_net_tcp_rtt_histogram_t,
) -> i32 {
    if engine.is_null() || out.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(engine) else {
        return -libc::EINVAL;
    };
    let handle = conn as dpdk_net_core::flow_table::ConnHandle;
    let ft = e.flow_table();
    match ft.get(handle) {
        Some(c) => {
            let snap = c.rtt_histogram.snapshot();
            (*out).bucket = snap;
            0
        }
        None => -libc::ENOENT,
    }
}

/// Resolve the MAC address for `gateway_ip_host_order` by reading
/// `/proc/net/arp`. Writes 6 bytes into `out_mac`.
/// Returns 0 on success, -ENOENT if no entry, -EIO on /proc/net/arp read error,
/// -EINVAL on null out_mac.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_resolve_gateway_mac(
    gateway_ip_host_order: u32,
    out_mac: *mut u8,
) -> i32 {
    if out_mac.is_null() {
        return -libc::EINVAL;
    }
    match dpdk_net_core::arp::resolve_from_proc_arp(gateway_ip_host_order) {
        Ok(mac) => {
            std::ptr::copy_nonoverlapping(mac.as_ptr(), out_mac, 6);
            0
        }
        Err(dpdk_net_core::Error::GatewayMacNotFound(_)) => -libc::ENOENT,
        Err(_) => -libc::EIO,
    }
}

/// A5.5 Task 10: pure default-substitution + range validation for the
/// five TLP tuning knobs on `dpdk_net_connect_opts_t`. Factored out so
/// rejection paths are unit-testable without standing up a live engine.
///
/// Substitution (zero-init-friendly):
/// * `tlp_pto_srtt_multiplier_x100 == 0` → `200` (RFC 8985 2·SRTT).
/// * `tlp_max_consecutive_probes == 0` → `1` (A5 / RFC 8985 §7.1).
/// * `tlp_pto_min_floor_us == 0` → engine `tcp_min_rto_us`.
///
/// Validation (post-substitution):
/// * `tlp_pto_srtt_multiplier_x100 ∈ [100, 200]`.
/// * `tlp_max_consecutive_probes ∈ [1, 5]`.
/// * `tlp_pto_min_floor_us == u32::MAX` (explicit no-floor sentinel)
///   OR `tlp_pto_min_floor_us <= tcp_max_rto_us`.
///
/// Returns `Ok(opts_with_substitutions_applied)` or `Err(-libc::EINVAL)`.
fn validate_and_defaults_tlp_opts(
    o: &dpdk_net_connect_opts_t,
    cfg: &dpdk_net_core::engine::EngineConfig,
) -> Result<dpdk_net_connect_opts_t, i32> {
    let mut o_opts = *o;
    if o_opts.tlp_pto_srtt_multiplier_x100 == 0 {
        o_opts.tlp_pto_srtt_multiplier_x100 = dpdk_net_core::tcp_tlp::DEFAULT_MULTIPLIER_X100;
    }
    if o_opts.tlp_max_consecutive_probes == 0 {
        o_opts.tlp_max_consecutive_probes = dpdk_net_core::tcp_tlp::DEFAULT_MAX_CONSECUTIVE_PROBES;
    }
    if o_opts.tlp_pto_min_floor_us == 0 {
        o_opts.tlp_pto_min_floor_us = cfg.tcp_min_rto_us;
    }
    if !(100..=200).contains(&o_opts.tlp_pto_srtt_multiplier_x100) {
        return Err(-libc::EINVAL);
    }
    if !(1..=5).contains(&o_opts.tlp_max_consecutive_probes) {
        return Err(-libc::EINVAL);
    }
    if o_opts.tlp_pto_min_floor_us != u32::MAX && o_opts.tlp_pto_min_floor_us > cfg.tcp_max_rto_us {
        return Err(-libc::EINVAL);
    }
    Ok(o_opts)
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_connect(
    p: *mut dpdk_net_engine,
    opts: *const dpdk_net_connect_opts_t,
    out: *mut dpdk_net_conn_t,
) -> i32 {
    if p.is_null() || opts.is_null() || out.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(p) else {
        return -libc::EINVAL;
    };
    let opts = &*opts;
    // A5.5 Task 10: validate + default-substitute the TLP tuning fields
    // before engine construction. Rejects out-of-range values with
    // -EINVAL; zero-init callers land in the A5-default happy path.
    let o_opts = match validate_and_defaults_tlp_opts(opts, e.config()) {
        Ok(v) => v,
        Err(rc) => return rc,
    };
    // peer_addr comes in network byte order; convert to host order.
    let peer_ip = u32::from_be(o_opts.peer_addr);
    let peer_port = u16::from_be(o_opts.peer_port);
    let local_port = u16::from_be(o_opts.local_port);
    // A5 Task 19 / A5.5 Task 10: plumb per-connect opt-ins into
    // engine::ConnectOpts (post-substitution values).
    let connect_opts = dpdk_net_core::engine::ConnectOpts {
        rack_aggressive: o_opts.rack_aggressive,
        rto_no_backoff: o_opts.rto_no_backoff,
        tlp_pto_min_floor_us: o_opts.tlp_pto_min_floor_us,
        tlp_pto_srtt_multiplier_x100: o_opts.tlp_pto_srtt_multiplier_x100,
        tlp_skip_flight_size_gate: o_opts.tlp_skip_flight_size_gate,
        tlp_max_consecutive_probes: o_opts.tlp_max_consecutive_probes,
        tlp_skip_rtt_sample_gate: o_opts.tlp_skip_rtt_sample_gate,
    };
    match e.connect_with_opts(peer_ip, peer_port, local_port, connect_opts) {
        Ok(h) => {
            *out = h as dpdk_net_conn_t;
            0
        }
        Err(dpdk_net_core::Error::TooManyConns) => -libc::EMFILE,
        Err(dpdk_net_core::Error::PeerUnreachable(_)) => -libc::EHOSTUNREACH,
        Err(_) => -libc::EIO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_send(
    p: *mut dpdk_net_engine,
    conn: dpdk_net_conn_t,
    buf: *const u8,
    len: u32,
) -> i32 {
    if p.is_null() {
        return -libc::EINVAL;
    }
    if len > 0 && buf.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(p) else {
        return -libc::EINVAL;
    };
    let slice = if len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(buf, len as usize)
    };
    match e.send_bytes(conn as u32, slice) {
        Ok(n) => n as i32,
        Err(dpdk_net_core::Error::InvalidConnHandle(_)) => -libc::ENOTCONN,
        Err(dpdk_net_core::Error::SendBufferFull) => -libc::ENOMEM,
        Err(_) => -libc::EIO,
    }
}

/// A6 (spec §5.4, §3.4): close a connection, honoring the `flags` bitmask.
///
/// Defined flags:
/// * `DPDK_NET_CLOSE_FORCE_TW_SKIP` — request to skip 2×MSL TIME_WAIT.
///   Honored only when the connection negotiated timestamps
///   (`c.ts_enabled == true`) at close time — the combination of PAWS
///   on the peer (RFC 7323 §5) + monotonic ISS on our side (RFC 6528,
///   spec §6.5) is the client-side analog of RFC 6191's protections.
///   When the prerequisite is not met, the flag is silently dropped
///   and a `DPDK_NET_EVT_ERROR{err=-EPERM}` is emitted for visibility;
///   the normal FIN + 2×MSL TIME_WAIT sequence proceeds.
///
/// Undefined flag bits are reserved for future extension and silently
/// ignored.
///
/// Returns 0 on successful close initiation (FIN emitted), or:
///   -EINVAL  engine is NULL
///   -ENOTCONN  conn is not a live handle
///   -EIO  internal error (TX path or flow-table)
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_close(
    p: *mut dpdk_net_engine,
    conn: dpdk_net_conn_t,
    flags: u32,
) -> i32 {
    if p.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(p) else {
        return -libc::EINVAL;
    };
    match e.close_conn_with_flags(conn as u32, flags) {
        Ok(()) => 0,
        Err(dpdk_net_core::Error::InvalidConnHandle(_)) => -libc::ENOTCONN,
        Err(_) => -libc::EIO,
    }
}

/// A6 (spec §5.3): schedule a one-shot timer. `deadline_ns` is in the
/// engine's monotonic clock domain (see `dpdk_net_now_ns`). Rounded up
/// to the next 10 µs wheel tick; past deadlines fire on the next poll.
/// On fire, emits `DPDK_NET_EVT_TIMER` with the returned `timer_id`
/// and the caller-supplied `user_data` echoed back.
///
/// Returns 0 on success (populates `*timer_id_out`); -EINVAL on
/// null engine/out. The populated `*timer_id_out` is a packed
/// `TimerId{slot, generation}` opaque handle — callers treat as
/// opaque but may observe the high 32 bits change on slot reuse.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_timer_add(
    engine: *mut dpdk_net_engine,
    deadline_ns: u64,
    user_data: u64,
    timer_id_out: *mut u64,
) -> i32 {
    if engine.is_null() || timer_id_out.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(engine) else {
        return -libc::EINVAL;
    };
    let id = e.public_timer_add(deadline_ns, user_data);
    *timer_id_out = dpdk_net_core::engine::pack_timer_id(id);
    0
}

/// A6 (spec §5.3): cancel a previously-added timer. Returns 0 if
/// cancelled before fire, -ENOENT otherwise (collapses: never existed /
/// already fired and drained / already fired but not yet drained).
/// Callers must always drain any queued TIMER events regardless of
/// this return — the event queue is authoritative.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_timer_cancel(
    engine: *mut dpdk_net_engine,
    timer_id: u64,
) -> i32 {
    if engine.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(engine) else {
        return -libc::EINVAL;
    };
    let id = dpdk_net_core::engine::unpack_timer_id(timer_id);
    if e.public_timer_cancel(id) {
        0
    } else {
        -libc::ENOENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_null_cfg_returns_null() {
        let p = unsafe { dpdk_net_engine_create(0, std::ptr::null()) };
        assert!(p.is_null());
    }

    #[test]
    fn destroy_null_is_safe() {
        unsafe { dpdk_net_engine_destroy(std::ptr::null_mut()) };
    }

    #[test]
    fn poll_null_returns_einval() {
        let rc = unsafe { dpdk_net_poll(std::ptr::null_mut(), std::ptr::null_mut(), 0, 0) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn now_ns_advances() {
        let a = unsafe { dpdk_net_now_ns(std::ptr::null_mut()) };
        let b = unsafe { dpdk_net_now_ns(std::ptr::null_mut()) };
        assert!(b >= a);
    }

    #[test]
    fn a2_config_fields_pass_through() {
        // We don't actually call dpdk_net_engine_create here (no EAL).
        // Just assert the types are laid out as we expect.
        let cfg = dpdk_net_engine_config_t {
            port_id: 0,
            rx_queue_id: 0,
            tx_queue_id: 0,
            max_connections: 0,
            recv_buffer_bytes: 0,
            send_buffer_bytes: 0,
            tcp_mss: 0,
            tcp_timestamps: false,
            tcp_sack: false,
            tcp_ecn: false,
            tcp_nagle: false,
            tcp_delayed_ack: false,
            cc_mode: 0,
            tcp_min_rto_ms: 0,
            tcp_min_rto_us: 0,
            tcp_initial_rto_us: 0,
            tcp_max_rto_us: 0,
            tcp_max_retrans_count: 0,
            tcp_msl_ms: 0,
            tcp_per_packet_events: false,
            preset: 0,
            local_ip: 0x0a_00_00_02, // 10.0.0.2 (host byte order)
            gateway_ip: 0x0a_00_00_01,
            gateway_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            garp_interval_sec: 5,
            event_queue_soft_cap: 4096,
            rtt_histogram_bucket_edges_us: [0u32; 15],
            ena_large_llq_hdr: 0,
            ena_miss_txc_to_sec: 0,
        };
        assert_eq!(cfg.local_ip, 0x0a_00_00_02);
        assert_eq!(cfg.gateway_mac[2], 0xbe);
        assert_eq!(cfg.garp_interval_sec, 5);
    }

    // A5.5 Task 5: `dpdk_net_engine_create` must reject
    // `event_queue_soft_cap < 64` before any DPDK/EAL touching, so we can
    // validate the early-return path from a pure unit test. The function
    // returns a pointer type, so validation failure surfaces as a null
    // pointer (same convention as the existing null-cfg guard).
    #[test]
    fn engine_create_rejects_event_queue_soft_cap_below_64() {
        let cfg = dpdk_net_engine_config_t {
            port_id: 0,
            rx_queue_id: 0,
            tx_queue_id: 0,
            max_connections: 0,
            recv_buffer_bytes: 0,
            send_buffer_bytes: 0,
            tcp_mss: 0,
            tcp_timestamps: false,
            tcp_sack: false,
            tcp_ecn: false,
            tcp_nagle: false,
            tcp_delayed_ack: false,
            cc_mode: 0,
            tcp_min_rto_ms: 0,
            tcp_min_rto_us: 0,
            tcp_initial_rto_us: 0,
            tcp_max_rto_us: 0,
            tcp_max_retrans_count: 0,
            tcp_msl_ms: 0,
            tcp_per_packet_events: false,
            preset: 0,
            local_ip: 0,
            gateway_ip: 0,
            gateway_mac: [0u8; 6],
            garp_interval_sec: 0,
            event_queue_soft_cap: 32,
            rtt_histogram_bucket_edges_us: [0u32; 15],
            ena_large_llq_hdr: 0,
            ena_miss_txc_to_sec: 0,
        };
        let p = unsafe { dpdk_net_engine_create(0, &cfg) };
        assert!(p.is_null());
    }

    #[test]
    fn resolve_null_out_mac_returns_einval() {
        let rc = unsafe { dpdk_net_resolve_gateway_mac(0x0a_00_00_01, std::ptr::null_mut()) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn resolve_unreachable_ip_returns_enoent() {
        let mut mac = [0u8; 6];
        // 0.0.0.1 will not be in any /proc/net/arp.
        let rc = unsafe { dpdk_net_resolve_gateway_mac(0x0000_0001, mac.as_mut_ptr()) };
        assert_eq!(rc, -libc::ENOENT);
    }

    #[test]
    fn connect_null_engine_returns_einval() {
        let opts = dpdk_net_connect_opts_t {
            peer_addr: 0x0100_0a0a, // 10.0.0.1 in NBO (doesn't matter)
            peer_port: 5000u16.to_be(),
            local_addr: 0,
            local_port: 0,
            connect_timeout_ms: 0,
            idle_keepalive_sec: 0,
            rack_aggressive: false,
            rto_no_backoff: false,
            tlp_pto_min_floor_us: 0,
            tlp_pto_srtt_multiplier_x100: 0,
            tlp_skip_flight_size_gate: false,
            tlp_max_consecutive_probes: 0,
            tlp_skip_rtt_sample_gate: false,
        };
        let mut out: u64 = 0;
        let rc = unsafe { dpdk_net_connect(std::ptr::null_mut(), &opts, &mut out) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn send_null_engine_returns_einval() {
        let rc = unsafe { dpdk_net_send(std::ptr::null_mut(), 1u64, b"x".as_ptr(), 1) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn close_null_engine_returns_einval() {
        let rc = unsafe { dpdk_net_close(std::ptr::null_mut(), 1u64, 0) };
        assert_eq!(rc, -libc::EINVAL);
    }

    // A5.5 Task 2: drain path must read `emitted_ts_ns` through from the
    // InternalEvent variant, NOT re-sample the clock at drain time. Proving
    // this end-to-end via `dpdk_net_poll` would need a mock-clock engine
    // (which doesn't exist; DPDK/EAL-backed engines can't be built in a unit
    // test). Instead we exercise the pure translation helper with an
    // `emitted_ts_ns` value that could never match the drain-time clock
    // sample, and assert it flows through to `dpdk_net_event_t`.
    #[test]
    fn drain_reads_emitted_ts_ns_through_not_drain_clock() {
        use dpdk_net_core::flow_table::ConnHandle;
        use dpdk_net_core::tcp_events::{InternalEvent, LossCause};
        use dpdk_net_core::tcp_state::TcpState;

        const EMITTED: u64 = 12345;
        let cases: Vec<InternalEvent> = vec![
            InternalEvent::Connected {
                conn: ConnHandle::default(),
                rx_hw_ts_ns: 0,
                emitted_ts_ns: EMITTED,
            },
            InternalEvent::Readable {
                conn: ConnHandle::default(),
                byte_offset: 0,
                byte_len: 0,
                rx_hw_ts_ns: 0,
                emitted_ts_ns: EMITTED,
            },
            InternalEvent::Closed {
                conn: ConnHandle::default(),
                err: 0,
                emitted_ts_ns: EMITTED,
            },
            InternalEvent::StateChange {
                conn: ConnHandle::default(),
                from: TcpState::SynSent,
                to: TcpState::Established,
                emitted_ts_ns: EMITTED,
            },
            InternalEvent::Error {
                conn: ConnHandle::default(),
                err: -1,
                emitted_ts_ns: EMITTED,
            },
            InternalEvent::TcpRetrans {
                conn: ConnHandle::default(),
                seq: 0,
                rtx_count: 1,
                emitted_ts_ns: EMITTED,
            },
            InternalEvent::TcpLossDetected {
                conn: ConnHandle::default(),
                cause: LossCause::Rack,
                emitted_ts_ns: EMITTED,
            },
        ];
        for ev in &cases {
            let out = build_event_from_internal(ev, (std::ptr::null(), 0));
            assert_eq!(
                out.enqueued_ts_ns, EMITTED,
                "variant {:?} failed to copy emitted_ts_ns through",
                ev
            );
        }
    }

    // A5.5 Task 7: C ABI null-argument rejection. Full happy-path and
    // ENOENT behavior needs a live Engine (DPDK/EAL + TAP); those paths
    // are covered by dpdk-net-core's flow_table::get_stats test at the
    // projection layer. Here we pin the null-guard contract so null
    // engine or null out cannot dereference into the engine box.
    #[test]
    fn conn_stats_null_engine_returns_einval() {
        let mut out = dpdk_net_conn_stats_t::default();
        let rc = unsafe { dpdk_net_conn_stats(std::ptr::null_mut(), 0, &mut out) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn conn_stats_null_out_returns_einval_before_engine_deref() {
        // The null-out check must fire BEFORE any engine dereference, so
        // a bogus (non-null) engine pointer paired with a null `out` must
        // still return -EINVAL without segfaulting.
        let fake_engine = std::ptr::dangling_mut::<dpdk_net_engine>();
        let rc = unsafe { dpdk_net_conn_stats(fake_engine, 0, std::ptr::null_mut()) };
        assert_eq!(rc, -libc::EINVAL);
    }

    // A6 Task 18: C ABI null-argument rejection for the RTT histogram
    // snapshot extern. Happy-path + ENOENT-on-unknown-handle need a live
    // Engine (DPDK/EAL + TAP); the bucket-update contract is covered by
    // `dpdk-net-core::rtt_histogram` unit tests at the ladder layer. Here
    // we pin the null-guard contracts so malformed C callers cannot
    // dereference into the engine box.
    #[test]
    fn rtt_histogram_null_engine_returns_einval() {
        let mut out = dpdk_net_tcp_rtt_histogram_t::default();
        let rc = unsafe {
            dpdk_net_conn_rtt_histogram(std::ptr::null_mut(), 0, &mut out)
        };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn rtt_histogram_null_out_returns_einval() {
        let fake_engine = std::ptr::dangling_mut::<dpdk_net_engine>();
        let rc = unsafe {
            dpdk_net_conn_rtt_histogram(fake_engine, 0, std::ptr::null_mut())
        };
        assert_eq!(rc, -libc::EINVAL);
    }

    // A6 Task 9: `preset` (spec §3.5) must be honored in
    // `dpdk_net_engine_create`. Pinning the constants + validator here
    // lets us exercise the preset path without an EAL-backed Engine.
    #[test]
    fn preset_rfc_compliance_is_known_constant() {
        assert_eq!(DPDK_NET_PRESET_LATENCY, 0);
        assert_eq!(DPDK_NET_PRESET_RFC_COMPLIANCE, 1);
    }

    #[test]
    fn apply_preset_rfc_compliance_overrides_five_fields() {
        let mut core_cfg = dpdk_net_core::engine::EngineConfig {
            tcp_nagle: false,
            cc_mode: 0,
            tcp_min_rto_us: 5_000,
            tcp_initial_rto_us: 5_000,
            ..dpdk_net_core::engine::EngineConfig::default()
        };
        apply_preset(1, &mut core_cfg).expect("preset=1 must apply");
        assert!(core_cfg.tcp_nagle);
        assert!(core_cfg.tcp_delayed_ack);
        assert_eq!(core_cfg.cc_mode, 1);
        assert_eq!(core_cfg.tcp_min_rto_us, 200_000);
        assert_eq!(core_cfg.tcp_initial_rto_us, 1_000_000);
    }

    #[test]
    fn apply_preset_latency_leaves_fields_intact() {
        let mut core_cfg = dpdk_net_core::engine::EngineConfig {
            tcp_nagle: false,
            cc_mode: 0,
            tcp_min_rto_us: 5_000,
            tcp_initial_rto_us: 5_000,
            ..dpdk_net_core::engine::EngineConfig::default()
        };
        apply_preset(0, &mut core_cfg).expect("preset=0 must be noop");
        assert!(!core_cfg.tcp_nagle);
        assert_eq!(core_cfg.cc_mode, 0);
        assert_eq!(core_cfg.tcp_min_rto_us, 5_000);
        assert_eq!(core_cfg.tcp_initial_rto_us, 5_000);
    }

    #[test]
    fn apply_preset_unknown_rejected() {
        let mut core_cfg = dpdk_net_core::engine::EngineConfig::default();
        assert!(apply_preset(2, &mut core_cfg).is_err());
        assert!(apply_preset(255, &mut core_cfg).is_err());
    }

    // A6 Task 17: null-argument rejection contracts for the public
    // timer extern "C" wrappers. Happy-path + ENOENT-on-stale-id
    // require a live Engine (DPDK/EAL) and are covered by
    // dpdk-net-core's wheel tests at the engine layer; here we pin
    // the null-guard contracts so malformed C callers can't
    // dereference into the engine box.
    #[test]
    fn timer_add_null_engine_returns_einval() {
        let mut out: u64 = 0;
        let rc = unsafe {
            dpdk_net_timer_add(std::ptr::null_mut(), 0, 0, &mut out)
        };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn timer_add_null_out_returns_einval() {
        let fake_engine = std::ptr::dangling_mut::<dpdk_net_engine>();
        let rc = unsafe {
            dpdk_net_timer_add(fake_engine, 0, 0, std::ptr::null_mut())
        };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn timer_cancel_null_engine_returns_einval() {
        let rc = unsafe { dpdk_net_timer_cancel(std::ptr::null_mut(), 0) };
        assert_eq!(rc, -libc::EINVAL);
    }
}

#[cfg(test)]
mod a5_5_tlp_opts_tests {
    //! A5.5 Task 10: pure-Rust unit tests for
    //! `validate_and_defaults_tlp_opts`. Exercising the ABI entrypoint
    //! itself would need a live Engine (DPDK/EAL + TAP); factoring the
    //! validator out lets us pin every rejection + substitution path
    //! here without any DPDK dependency.
    use super::*;
    use dpdk_net_core::engine::EngineConfig;

    fn base_cfg() -> EngineConfig {
        EngineConfig {
            tcp_min_rto_us: 5_000,
            tcp_max_rto_us: 1_000_000,
            ..EngineConfig::default()
        }
    }

    fn zero_opts() -> dpdk_net_connect_opts_t {
        dpdk_net_connect_opts_t {
            peer_addr: 0,
            peer_port: 0,
            local_addr: 0,
            local_port: 0,
            connect_timeout_ms: 0,
            idle_keepalive_sec: 0,
            rack_aggressive: false,
            rto_no_backoff: false,
            tlp_pto_min_floor_us: 0,
            tlp_pto_srtt_multiplier_x100: 0,
            tlp_skip_flight_size_gate: false,
            tlp_max_consecutive_probes: 0,
            tlp_skip_rtt_sample_gate: false,
        }
    }

    #[test]
    fn zero_init_applies_a5_defaults() {
        let opts = zero_opts();
        let cfg = base_cfg();
        let out = validate_and_defaults_tlp_opts(&opts, &cfg)
            .expect("zero-init must substitute to valid A5 defaults");
        assert_eq!(
            out.tlp_pto_srtt_multiplier_x100,
            dpdk_net_core::tcp_tlp::DEFAULT_MULTIPLIER_X100
        );
        assert_eq!(
            out.tlp_max_consecutive_probes,
            dpdk_net_core::tcp_tlp::DEFAULT_MAX_CONSECUTIVE_PROBES
        );
        assert_eq!(out.tlp_pto_min_floor_us, cfg.tcp_min_rto_us);
    }

    fn expect_err(r: Result<dpdk_net_connect_opts_t, i32>) -> i32 {
        match r {
            Ok(_) => panic!("expected validator to reject, got Ok"),
            Err(rc) => rc,
        }
    }

    #[test]
    fn multiplier_below_100_rejected() {
        let mut opts = zero_opts();
        opts.tlp_pto_srtt_multiplier_x100 = 99;
        let rc = expect_err(validate_and_defaults_tlp_opts(&opts, &base_cfg()));
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn multiplier_above_200_rejected() {
        let mut opts = zero_opts();
        opts.tlp_pto_srtt_multiplier_x100 = 201;
        let rc = expect_err(validate_and_defaults_tlp_opts(&opts, &base_cfg()));
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn multiplier_boundary_values_accepted() {
        let mut opts = zero_opts();
        opts.tlp_pto_srtt_multiplier_x100 = 100;
        let out = validate_and_defaults_tlp_opts(&opts, &base_cfg()).unwrap();
        assert_eq!(out.tlp_pto_srtt_multiplier_x100, 100);

        opts.tlp_pto_srtt_multiplier_x100 = 200;
        let out = validate_and_defaults_tlp_opts(&opts, &base_cfg()).unwrap();
        assert_eq!(out.tlp_pto_srtt_multiplier_x100, 200);
    }

    #[test]
    fn max_consecutive_probes_above_5_rejected() {
        let mut opts = zero_opts();
        opts.tlp_max_consecutive_probes = 6;
        let rc = expect_err(validate_and_defaults_tlp_opts(&opts, &base_cfg()));
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn max_consecutive_probes_boundary_values_accepted() {
        for n in 1u8..=5 {
            let mut opts = zero_opts();
            opts.tlp_max_consecutive_probes = n;
            let out = validate_and_defaults_tlp_opts(&opts, &base_cfg()).unwrap();
            assert_eq!(out.tlp_max_consecutive_probes, n);
        }
    }

    #[test]
    fn floor_u32_max_is_explicit_no_floor() {
        let mut opts = zero_opts();
        opts.tlp_pto_min_floor_us = u32::MAX;
        let out = validate_and_defaults_tlp_opts(&opts, &base_cfg()).unwrap();
        // The sentinel passes through — the `tlp_config()` projection
        // turns it into `floor_us = 0` at PTO-compute time.
        assert_eq!(out.tlp_pto_min_floor_us, u32::MAX);
    }

    #[test]
    fn floor_above_max_rto_rejected() {
        let cfg = base_cfg();
        let mut opts = zero_opts();
        opts.tlp_pto_min_floor_us = cfg.tcp_max_rto_us + 1;
        let rc = expect_err(validate_and_defaults_tlp_opts(&opts, &cfg));
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn floor_equal_to_max_rto_accepted() {
        let cfg = base_cfg();
        let mut opts = zero_opts();
        opts.tlp_pto_min_floor_us = cfg.tcp_max_rto_us;
        let out = validate_and_defaults_tlp_opts(&opts, &cfg).unwrap();
        assert_eq!(out.tlp_pto_min_floor_us, cfg.tcp_max_rto_us);
    }

    #[test]
    fn explicit_nonzero_floor_passes_through() {
        let cfg = base_cfg();
        let mut opts = zero_opts();
        opts.tlp_pto_min_floor_us = 10_000; // 10ms, within range
        let out = validate_and_defaults_tlp_opts(&opts, &cfg).unwrap();
        assert_eq!(out.tlp_pto_min_floor_us, 10_000);
    }

    #[test]
    fn floor_zero_inherits_engine_min_rto() {
        let cfg = EngineConfig {
            tcp_min_rto_us: 12_345,
            tcp_max_rto_us: 1_000_000,
            ..EngineConfig::default()
        };
        let opts = zero_opts();
        let out = validate_and_defaults_tlp_opts(&opts, &cfg).unwrap();
        assert_eq!(out.tlp_pto_min_floor_us, 12_345);
    }

    #[test]
    fn skip_flags_pass_through_unchanged() {
        let mut opts = zero_opts();
        opts.tlp_skip_flight_size_gate = true;
        opts.tlp_skip_rtt_sample_gate = true;
        let out = validate_and_defaults_tlp_opts(&opts, &base_cfg()).unwrap();
        assert!(out.tlp_skip_flight_size_gate);
        assert!(out.tlp_skip_rtt_sample_gate);
    }
}
