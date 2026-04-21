//! bug_010 → feature: per-connection source IP selection for dual-NIC /
//! multi-homed setups. Validates end-to-end wiring:
//!
//!   1. `ConnectOpts.local_addr == 0` → SYN source IP == engine's primary (A)
//!   2. `ConnectOpts.local_addr == B`  → SYN source IP == B (registered via
//!      `EngineConfig.secondary_local_ips` at engine create time)
//!   3. `ConnectOpts.local_addr == C`  → connect rejects with
//!      `Error::InvalidLocalAddr(C)` (maps to `-EINVAL` at the FFI boundary)
//!   4. `Engine::add_local_ip(D)` post-create → subsequent connect with
//!      `ConnectOpts.local_addr == D` succeeds with SYN source IP == D
//!
//! Requires `DPDK_NET_TEST_TAP=1` + root (DPDK TAP vdev + AF_PACKET socket
//! to observe the outbound SYN on the kernel side). Runs against a fresh
//! TAP interface `dpdktap_srcip` so it doesn't collide with other tests.
//!
//! The TCP server side is NOT plumbed — we only need the outbound SYN to
//! be emitted. The handshake never completes (no kernel listener). The
//! test reads the SYN from the TAP via AF_PACKET and asserts its IPv4
//! source address.

use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::process::Command;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, ConnectOpts, Engine, EngineConfig};

const TAP_IFACE: &str = "dpdktap_srcip";
const DPDK_PORT: u16 = 0;
// Use a distinct /24 from the other tap tests to avoid collision.
const OUR_IP_PRIMARY: u32 = 0x0a_63_19_02; // 10.99.25.2 (A)
const OUR_IP_SECONDARY: u32 = 0x0a_63_19_03; // 10.99.25.3 (B)
const OUR_IP_UNKNOWN: u32 = 0x0a_63_19_09; // 10.99.25.9 (C; never registered)
const PEER_IP: u32 = 0x0a_63_19_01; // 10.99.25.1
const PEER_PORT: u16 = 5000;

fn want_tap() -> bool {
    std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() == Some("1")
}

fn skip_if_not_tap() -> bool {
    if !want_tap() {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run");
        return true;
    }
    false
}

fn bring_up_tap(iface: &str) {
    let _ = Command::new("ip")
        .args(["link", "set", iface, "up"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.25.1/24", "dev", iface])
        .status();
}

fn pin_arp(iface: &str, ip: &str, mac: &str) {
    let _ = Command::new("ip")
        .args([
            "neigh",
            "replace",
            ip,
            "lladdr",
            mac,
            "dev",
            iface,
            "nud",
            "permanent",
        ])
        .status();
}

fn read_kernel_tap_mac(iface: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"));
    let mut out = [0u8; 6];
    for (i, part) in s.trim().split(':').enumerate() {
        out[i] = u8::from_str_radix(part, 16).expect("hex mac");
    }
    out
}

fn mac_hex(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Open an AF_PACKET SOCK_RAW socket bound to `iface`. Non-blocking so
/// the test can poll-and-timeout instead of hanging.
fn open_pkt_socket_nonblocking(iface: &str) -> c_int {
    let s = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    assert!(
        s >= 0,
        "socket() failed: {}",
        std::io::Error::last_os_error()
    );
    let c_name = CString::new(iface).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    assert!(ifindex > 0, "if_nametoindex({iface}) failed");
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = ifindex as i32;
    let rc = unsafe {
        libc::bind(
            s,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&sll) as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind failed: {}", std::io::Error::last_os_error());
    s
}

/// Drain all available frames (non-blocking). Returns the decoded source
/// IP of the first IPv4+TCP+SYN frame observed with `dst_port == expect_peer_port`.
/// Returns `None` if no such frame is observed within `deadline`.
fn capture_syn_src_ip(
    sock: c_int,
    engine: &Engine,
    deadline: Instant,
    expect_peer_port: u16,
) -> Option<u32> {
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        engine.poll_once();
        let n = unsafe {
            libc::recv(
                sock,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EAGAIN)
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            panic!("recv failed: {err}");
        }
        let n = n as usize;
        if n < 14 + 20 + 20 {
            continue;
        }
        let frame = &buf[..n];
        // Ethernet type at bytes 12..14.
        let et = u16::from_be_bytes([frame[12], frame[13]]);
        if et != 0x0800 {
            continue; // not IPv4
        }
        let ip = &frame[14..];
        if ip.len() < 20 {
            continue;
        }
        let ihl = (ip[0] & 0x0f) as usize;
        let ip_hdr_len = ihl * 4;
        if ip_hdr_len < 20 || ip.len() < ip_hdr_len {
            continue;
        }
        let proto = ip[9];
        if proto != 6 {
            // not TCP
            continue;
        }
        let src_ip = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
        let tcp = &ip[ip_hdr_len..];
        if tcp.len() < 20 {
            continue;
        }
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let flags = tcp[13];
        let syn = (flags & 0x02) != 0;
        let ack = (flags & 0x10) != 0;
        if syn && !ack && dst_port == expect_peer_port {
            return Some(src_ip);
        }
    }
    None
}

#[test]
fn per_conn_source_ip_over_tap() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-bug010-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=dpdktap_srcip",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    std::thread::sleep(Duration::from_millis(300));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    // Configure the engine with `A` as primary and `B` in the
    // Rust-side initial secondary list. Use a small MSS/max_connections
    // because we're not exchanging data.
    let cfg = EngineConfig {
        port_id: DPDK_PORT,
        local_ip: OUR_IP_PRIMARY,
        secondary_local_ips: vec![OUR_IP_SECONDARY],
        gateway_ip: PEER_IP,
        gateway_mac: kernel_mac,
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        // Push out retransmit timers so we don't observe a retransmit
        // SYN before we get a chance to capture the original.
        tcp_initial_rto_us: 10_000_000, // 10 s
        ..Default::default()
    };

    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();
    // Pin ARP for BOTH of our local IPs so the kernel doesn't clobber
    // our outbound path with ARP-resolve delays. `pin_arp` is only
    // needed for addresses we'd be resolving TO — we use these for the
    // gateway side (peer), not for ourselves.
    pin_arp(TAP_IFACE, "10.99.25.2", &mac_hex(our_mac));
    pin_arp(TAP_IFACE, "10.99.25.3", &mac_hex(our_mac));

    let sock = open_pkt_socket_nonblocking(TAP_IFACE);

    // --- Case 1: local_addr == 0 → SYN src == primary (A) ---
    let case1_opts = ConnectOpts::default(); // local_addr defaults to 0
    let h1 = engine
        .connect_with_opts(PEER_IP, PEER_PORT, 0, case1_opts)
        .expect("connect(local_addr=0) must succeed");
    let _ = h1;
    let deadline = Instant::now() + Duration::from_secs(3);
    let src1 = capture_syn_src_ip(sock, &engine, deadline, PEER_PORT)
        .expect("SYN must be captured for case 1 (local_addr=0)");
    assert_eq!(
        src1, OUR_IP_PRIMARY,
        "case 1 (local_addr=0): SYN src={:#x}, want primary {:#x}",
        src1, OUR_IP_PRIMARY
    );

    // --- Case 2: local_addr == B → SYN src == B ---
    // Use a different dst port so we can distinguish the case-2 SYN
    // from any retransmit of case-1's SYN.
    let case2_port = PEER_PORT + 1;
    let case2_opts = ConnectOpts {
        local_addr: OUR_IP_SECONDARY,
        ..ConnectOpts::default()
    };
    let h2 = engine
        .connect_with_opts(PEER_IP, case2_port, 0, case2_opts)
        .expect("connect(local_addr=B) must succeed");
    let _ = h2;
    let deadline = Instant::now() + Duration::from_secs(3);
    let src2 = capture_syn_src_ip(sock, &engine, deadline, case2_port)
        .expect("SYN must be captured for case 2 (local_addr=B)");
    assert_eq!(
        src2, OUR_IP_SECONDARY,
        "case 2 (local_addr=B): SYN src={:#x}, want secondary {:#x}",
        src2, OUR_IP_SECONDARY
    );

    // --- Case 3: local_addr == C (unknown) → Err(InvalidLocalAddr) ---
    let case3_port = PEER_PORT + 2;
    let case3_opts = ConnectOpts {
        local_addr: OUR_IP_UNKNOWN,
        ..ConnectOpts::default()
    };
    let res3 = engine.connect_with_opts(PEER_IP, case3_port, 0, case3_opts);
    match res3 {
        Err(dpdk_net_core::Error::InvalidLocalAddr(ip)) => {
            assert_eq!(ip, OUR_IP_UNKNOWN, "InvalidLocalAddr payload mismatch");
        }
        other => panic!("case 3: expected InvalidLocalAddr, got {other:?}"),
    }

    // --- Case 4: register C dynamically via add_local_ip, then succeed ---
    assert!(
        engine.add_local_ip(OUR_IP_UNKNOWN),
        "add_local_ip(C) must return true for a new IP"
    );
    assert!(
        !engine.add_local_ip(OUR_IP_UNKNOWN),
        "add_local_ip(C) must return false on second call (idempotent)"
    );
    assert!(
        !engine.add_local_ip(OUR_IP_PRIMARY),
        "add_local_ip(primary) must return false (already primary)"
    );
    assert!(
        !engine.add_local_ip(0),
        "add_local_ip(0) must return false (reserved)"
    );

    let case4_port = PEER_PORT + 3;
    let case4_opts = ConnectOpts {
        local_addr: OUR_IP_UNKNOWN,
        ..ConnectOpts::default()
    };
    let h4 = engine
        .connect_with_opts(PEER_IP, case4_port, 0, case4_opts)
        .expect("connect(local_addr=C-after-add) must succeed");
    let _ = h4;
    let deadline = Instant::now() + Duration::from_secs(3);
    let src4 = capture_syn_src_ip(sock, &engine, deadline, case4_port)
        .expect("SYN must be captured for case 4 (local_addr=C after add_local_ip)");
    assert_eq!(
        src4, OUR_IP_UNKNOWN,
        "case 4 (local_addr=C-after-add): SYN src={:#x}, want {:#x}",
        src4, OUR_IP_UNKNOWN
    );

    // Close the capture socket.
    unsafe {
        libc::close(sock);
    }
    // Engine is dropped at scope exit.
}
