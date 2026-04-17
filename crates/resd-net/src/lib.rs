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
    _events_out: *mut resd_net_event_t,
    _max_events: u32,
    _timeout_ns: u64,
) -> i32 {
    match engine_from_raw(p) {
        Some(e) => {
            e.poll_once();
            0
        }
        None => -libc::EINVAL,
    }
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
            tcp_initial_rto_ms: 0,
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
}
