//! End-to-end FFI smoke test: uses the public C ABI from Rust to prove the
//! extern "C" surface is usable, not just the Rust-native one.
//!
//! - `ffi_handles_null_safely` runs always.
//! - `ffi_eal_init_and_engine_lifecycle` runs only when RESD_NET_TEST_TAP=1
//!   because it actually initializes EAL against a DPDK TAP vdev.

use std::ffi::CString;
use std::ptr;

#[link(name = "resd_net", kind = "static")]
extern "C" {
    fn resd_net_eal_init(argc: i32, argv: *const *const libc::c_char) -> i32;
    fn resd_net_engine_create(
        lcore_id: u16,
        cfg: *const core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn resd_net_engine_destroy(p: *mut core::ffi::c_void);
    fn resd_net_poll(
        p: *mut core::ffi::c_void,
        events_out: *mut core::ffi::c_void,
        max_events: u32,
        timeout_ns: u64,
    ) -> i32;
    fn resd_net_now_ns(p: *mut core::ffi::c_void) -> u64;
}

#[test]
fn ffi_handles_null_safely() {
    unsafe {
        resd_net_engine_destroy(ptr::null_mut());
        let rc = resd_net_poll(ptr::null_mut(), ptr::null_mut(), 0, 0);
        assert_eq!(rc, -libc::EINVAL);
        let ts = resd_net_now_ns(ptr::null_mut());
        assert!(ts > 0);
    }
}

#[test]
fn ffi_eal_init_and_engine_lifecycle() {
    if std::env::var("RESD_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set RESD_NET_TEST_TAP=1 to run");
        return;
    }

    let args: Vec<CString> = [
        "resd-net-ffi-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap0",
        "-l",
        "0-1",
        "--log-level=3",
    ]
    .iter()
    .map(|s| CString::new(*s).unwrap())
    .collect();
    let argv: Vec<*const libc::c_char> = args.iter().map(|c| c.as_ptr()).collect();

    let rc = unsafe { resd_net_eal_init(argv.len() as i32, argv.as_ptr()) };
    assert_eq!(rc, 0, "resd_net_eal_init failed: {rc}");

    // Byte-shim of resd_net_engine_config_t. Must match the cbindgen layout.
    // Read include/resd_net.h to confirm field order before relying on this.
    #[repr(C)]
    struct Cfg {
        port_id: u16,
        rx_queue_id: u16,
        tx_queue_id: u16,
        _pad1: u16,
        max_connections: u32,
        recv_buffer_bytes: u32,
        send_buffer_bytes: u32,
        tcp_mss: u32,
        tcp_timestamps: bool,
        tcp_sack: bool,
        tcp_ecn: bool,
        tcp_nagle: bool,
        tcp_delayed_ack: bool,
        cc_mode: u8,
        _pad2: [u8; 2],
        tcp_min_rto_ms: u32,
        tcp_initial_rto_ms: u32,
        tcp_msl_ms: u32,
        tcp_per_packet_events: bool,
        preset: u8,
        _pad3: [u8; 2],
        // Phase A2 additions
        local_ip: u32,
        gateway_ip: u32,
        gateway_mac: [u8; 6],
        _pad4: [u8; 2],
        garp_interval_sec: u32,
    }
    let cfg = Cfg {
        port_id: 0,
        rx_queue_id: 0,
        tx_queue_id: 0,
        _pad1: 0,
        max_connections: 16,
        recv_buffer_bytes: 256 * 1024,
        send_buffer_bytes: 256 * 1024,
        tcp_mss: 0,
        tcp_timestamps: true,
        tcp_sack: true,
        tcp_ecn: false,
        tcp_nagle: false,
        tcp_delayed_ack: false,
        cc_mode: 0,
        _pad2: [0; 2],
        tcp_min_rto_ms: 20,
        tcp_initial_rto_ms: 50,
        tcp_msl_ms: 30000,
        tcp_per_packet_events: false,
        preset: 0,
        _pad3: [0; 2],
        local_ip: 0,
        gateway_ip: 0,
        gateway_mac: [0u8; 6],
        _pad4: [0; 2],
        garp_interval_sec: 0,
    };

    let eng = unsafe { resd_net_engine_create(0, &cfg as *const Cfg as *const core::ffi::c_void) };
    assert!(!eng.is_null(), "resd_net_engine_create returned null");

    for _ in 0..10 {
        let rc = unsafe { resd_net_poll(eng, ptr::null_mut(), 0, 0) };
        assert_eq!(rc, 0);
    }

    unsafe { resd_net_engine_destroy(eng) };
}
