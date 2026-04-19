#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]

pub mod api;

use api::*;
use resd_net_core::clock;
use resd_net_core::counters::Counters;
use resd_net_core::engine::{self, Engine, EngineConfig};
use std::ffi::CStr;
use std::ptr;

/// Opaque handle — actually a Box<Engine> reinterpreted as *mut resd_net_engine.
struct OpaqueEngine(Engine);

fn box_to_raw(e: Engine) -> *mut resd_net_engine {
    Box::into_raw(Box::new(OpaqueEngine(e))) as *mut resd_net_engine
}

unsafe fn engine_from_raw<'a>(p: *mut resd_net_engine) -> Option<&'a Engine> {
    if p.is_null() {
        return None;
    }
    Some(&(&*(p as *const OpaqueEngine)).0)
}

/// Initialize DPDK EAL. Must be called before resd_net_engine_create.
/// `argv` is a C-style argv array; the function does NOT take ownership
/// (copies each argument into Rust-owned CStrings internally).
/// Safe to call multiple times; subsequent calls after the first return 0.
/// Returns 0 on success, negative errno on failure.
#[no_mangle]
pub unsafe extern "C" fn resd_net_eal_init(argc: i32, argv: *const *const libc::c_char) -> i32 {
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
pub unsafe extern "C" fn resd_net_engine_create(
    lcore_id: u16,
    cfg: *const resd_net_engine_config_t,
) -> *mut resd_net_engine {
    if cfg.is_null() {
        return ptr::null_mut();
    }
    let cfg = &*cfg;
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

    let core_cfg = EngineConfig {
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
        tcp_min_rto_us: min_rto_us,
        tcp_initial_rto_us: initial_rto_us,
        tcp_max_rto_us: max_rto_us,
        tcp_max_retrans_count: max_retrans,
        tcp_per_packet_events: cfg.tcp_per_packet_events,
    };
    match Engine::new(core_cfg) {
        Ok(e) => box_to_raw(e),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_engine_destroy(p: *mut resd_net_engine) {
    if p.is_null() {
        return;
    }
    let _boxed = Box::from_raw(p as *mut OpaqueEngine);
    // Drop runs Engine's Drop impl.
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_poll(
    p: *mut resd_net_engine,
    events_out: *mut resd_net_event_t,
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
        let ts = resd_net_core::clock::now_ns();
        // Build the event value fully before writing it to events_out, so
        // we never read a possibly-uninitialized `kind` discriminant.
        let event: resd_net_event_t = match ev {
            resd_net_core::tcp_events::InternalEvent::Connected {
                conn,
                rx_hw_ts_ns,
                ..
            } => {
                resd_net_event_t {
                    kind: resd_net_event_kind_t::RESD_NET_EVT_CONNECTED,
                    conn: *conn as u64,
                    rx_hw_ts_ns: *rx_hw_ts_ns,
                    enqueued_ts_ns: ts,
                    u: resd_net_event_payload_t { _pad: [0u8; 16] },
                }
            }
            resd_net_core::tcp_events::InternalEvent::Readable {
                conn,
                byte_offset,
                byte_len,
                rx_hw_ts_ns,
                ..
            } => {
                // Build the borrowed-view pointer into the connection's
                // last_read_buf at the event's byte_offset (Task 19 fix
                // for multi-segment polls).
                let ft = engine.flow_table();
                let (data_ptr, data_len) = match ft.get(*conn) {
                    Some(c) => {
                        let off = *byte_offset as usize;
                        let ptr = unsafe { c.recv.last_read_buf.as_ptr().add(off) };
                        (ptr, *byte_len)
                    }
                    None => (std::ptr::null(), 0),
                };
                resd_net_event_t {
                    kind: resd_net_event_kind_t::RESD_NET_EVT_READABLE,
                    conn: *conn as u64,
                    rx_hw_ts_ns: *rx_hw_ts_ns,
                    enqueued_ts_ns: ts,
                    u: resd_net_event_payload_t {
                        readable: resd_net_event_readable_t {
                            data: data_ptr,
                            data_len,
                        },
                    },
                }
            }
            resd_net_core::tcp_events::InternalEvent::Closed { conn, err, .. } => resd_net_event_t {
                kind: resd_net_event_kind_t::RESD_NET_EVT_CLOSED,
                conn: *conn as u64,
                rx_hw_ts_ns: 0,
                enqueued_ts_ns: ts,
                u: resd_net_event_payload_t {
                    closed: resd_net_event_error_t { err: *err },
                },
            },
            resd_net_core::tcp_events::InternalEvent::StateChange { conn, from, to, .. } => {
                resd_net_event_t {
                    kind: resd_net_event_kind_t::RESD_NET_EVT_TCP_STATE_CHANGE,
                    conn: *conn as u64,
                    rx_hw_ts_ns: 0,
                    enqueued_ts_ns: ts,
                    u: resd_net_event_payload_t {
                        tcp_state: resd_net_event_tcp_state_t {
                            from_state: *from as u8,
                            to_state: *to as u8,
                        },
                    },
                }
            }
            resd_net_core::tcp_events::InternalEvent::Error { conn, err, .. } => resd_net_event_t {
                kind: resd_net_event_kind_t::RESD_NET_EVT_ERROR,
                conn: *conn as u64,
                rx_hw_ts_ns: 0,
                enqueued_ts_ns: ts,
                u: resd_net_event_payload_t {
                    error: resd_net_event_error_t { err: *err },
                },
            },
            // A5 Task 20: per-packet retransmit observability. Emitted
            // (only) when `tcp_per_packet_events=true`; carries the
            // just-retransmitted segment's seq + post-retrans xmit_count.
            resd_net_core::tcp_events::InternalEvent::TcpRetrans {
                conn,
                seq,
                rtx_count,
                ..
            } => resd_net_event_t {
                kind: resd_net_event_kind_t::RESD_NET_EVT_TCP_RETRANS,
                conn: *conn as u64,
                rx_hw_ts_ns: 0,
                enqueued_ts_ns: ts,
                u: resd_net_event_payload_t {
                    tcp_retrans: resd_net_event_tcp_retrans_t {
                        seq: *seq,
                        rtx_count: *rtx_count,
                    },
                },
            },
            // A5 Task 20: loss-detector observability. `trigger` encodes
            // `LossCause` as `Rack=0`, `Tlp=1`, `Rto=2` (matching enum
            // order). `first_seq` is left 0 here — the paired TcpRetrans
            // event that precedes each TcpLossDetected carries the seq.
            resd_net_core::tcp_events::InternalEvent::TcpLossDetected { conn, cause, .. } => {
                let trigger: u8 = match cause {
                    resd_net_core::tcp_events::LossCause::Rack => 0,
                    resd_net_core::tcp_events::LossCause::Tlp => 1,
                    resd_net_core::tcp_events::LossCause::Rto => 2,
                };
                resd_net_event_t {
                    kind: resd_net_event_kind_t::RESD_NET_EVT_TCP_LOSS_DETECTED,
                    conn: *conn as u64,
                    rx_hw_ts_ns: 0,
                    enqueued_ts_ns: ts,
                    u: resd_net_event_payload_t {
                        tcp_loss: resd_net_event_tcp_loss_t {
                            first_seq: 0,
                            trigger,
                        },
                    },
                }
            }
        };
        unsafe {
            std::ptr::write(events_out.add(filled as usize), event);
        }
        filled += 1;
    });
    filled as i32
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_flush(_p: *mut resd_net_engine) {
    // Phase A1: no-op; TX burst handled inline in poll_once.
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_now_ns(_p: *mut resd_net_engine) -> u64 {
    clock::now_ns()
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_counters(p: *mut resd_net_engine) -> *const resd_net_counters_t {
    match engine_from_raw(p) {
        Some(e) => e.counters() as *const Counters as *const resd_net_counters_t,
        None => ptr::null(),
    }
}

/// Resolve the MAC address for `gateway_ip_host_order` by reading
/// `/proc/net/arp`. Writes 6 bytes into `out_mac`.
/// Returns 0 on success, -ENOENT if no entry, -EIO on /proc/net/arp read error,
/// -EINVAL on null out_mac.
#[no_mangle]
pub unsafe extern "C" fn resd_net_resolve_gateway_mac(
    gateway_ip_host_order: u32,
    out_mac: *mut u8,
) -> i32 {
    if out_mac.is_null() {
        return -libc::EINVAL;
    }
    match resd_net_core::arp::resolve_from_proc_arp(gateway_ip_host_order) {
        Ok(mac) => {
            std::ptr::copy_nonoverlapping(mac.as_ptr(), out_mac, 6);
            0
        }
        Err(resd_net_core::Error::GatewayMacNotFound(_)) => -libc::ENOENT,
        Err(_) => -libc::EIO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_connect(
    p: *mut resd_net_engine,
    opts: *const resd_net_connect_opts_t,
    out: *mut resd_net_conn_t,
) -> i32 {
    if p.is_null() || opts.is_null() || out.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(p) else {
        return -libc::EINVAL;
    };
    let opts = &*opts;
    // peer_addr comes in network byte order; convert to host order.
    let peer_ip = u32::from_be(opts.peer_addr);
    let peer_port = u16::from_be(opts.peer_port);
    let local_port = u16::from_be(opts.local_port);
    // A5 Task 19: plumb per-connect opt-ins into engine::ConnectOpts.
    let connect_opts = resd_net_core::engine::ConnectOpts {
        rack_aggressive: opts.rack_aggressive,
        rto_no_backoff: opts.rto_no_backoff,
    };
    match e.connect_with_opts(peer_ip, peer_port, local_port, connect_opts) {
        Ok(h) => {
            *out = h as resd_net_conn_t;
            0
        }
        Err(resd_net_core::Error::TooManyConns) => -libc::EMFILE,
        Err(resd_net_core::Error::PeerUnreachable(_)) => -libc::EHOSTUNREACH,
        Err(_) => -libc::EIO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_send(
    p: *mut resd_net_engine,
    conn: resd_net_conn_t,
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
        Err(resd_net_core::Error::InvalidConnHandle(_)) => -libc::ENOTCONN,
        Err(resd_net_core::Error::SendBufferFull) => -libc::ENOMEM,
        Err(_) => -libc::EIO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_close(
    p: *mut resd_net_engine,
    conn: resd_net_conn_t,
    _flags: u32,
) -> i32 {
    // FORCE_TW_SKIP flag is A6; ignore in A3.
    if p.is_null() {
        return -libc::EINVAL;
    }
    let Some(e) = engine_from_raw(p) else {
        return -libc::EINVAL;
    };
    match e.close_conn(conn as u32) {
        Ok(()) => 0,
        Err(resd_net_core::Error::InvalidConnHandle(_)) => -libc::ENOTCONN,
        Err(_) => -libc::EIO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_null_cfg_returns_null() {
        let p = unsafe { resd_net_engine_create(0, std::ptr::null()) };
        assert!(p.is_null());
    }

    #[test]
    fn destroy_null_is_safe() {
        unsafe { resd_net_engine_destroy(std::ptr::null_mut()) };
    }

    #[test]
    fn poll_null_returns_einval() {
        let rc = unsafe { resd_net_poll(std::ptr::null_mut(), std::ptr::null_mut(), 0, 0) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn now_ns_advances() {
        let a = unsafe { resd_net_now_ns(std::ptr::null_mut()) };
        let b = unsafe { resd_net_now_ns(std::ptr::null_mut()) };
        assert!(b >= a);
    }

    #[test]
    fn a2_config_fields_pass_through() {
        // We don't actually call resd_net_engine_create here (no EAL).
        // Just assert the types are laid out as we expect.
        let cfg = resd_net_engine_config_t {
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
        };
        assert_eq!(cfg.local_ip, 0x0a_00_00_02);
        assert_eq!(cfg.gateway_mac[2], 0xbe);
        assert_eq!(cfg.garp_interval_sec, 5);
    }

    #[test]
    fn resolve_null_out_mac_returns_einval() {
        let rc = unsafe { resd_net_resolve_gateway_mac(0x0a_00_00_01, std::ptr::null_mut()) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn resolve_unreachable_ip_returns_enoent() {
        let mut mac = [0u8; 6];
        // 0.0.0.1 will not be in any /proc/net/arp.
        let rc = unsafe { resd_net_resolve_gateway_mac(0x0000_0001, mac.as_mut_ptr()) };
        assert_eq!(rc, -libc::ENOENT);
    }

    #[test]
    fn connect_null_engine_returns_einval() {
        let opts = resd_net_connect_opts_t {
            peer_addr: 0x0100_0a0a, // 10.0.0.1 in NBO (doesn't matter)
            peer_port: 5000u16.to_be(),
            local_addr: 0,
            local_port: 0,
            connect_timeout_ms: 0,
            idle_keepalive_sec: 0,
            rack_aggressive: false,
            rto_no_backoff: false,
        };
        let mut out: u64 = 0;
        let rc = unsafe { resd_net_connect(std::ptr::null_mut(), &opts, &mut out) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn send_null_engine_returns_einval() {
        let rc = unsafe { resd_net_send(std::ptr::null_mut(), 1u64, b"x".as_ptr(), 1) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn close_null_engine_returns_einval() {
        let rc = unsafe { resd_net_close(std::ptr::null_mut(), 1u64, 0) };
        assert_eq!(rc, -libc::EINVAL);
    }
}
