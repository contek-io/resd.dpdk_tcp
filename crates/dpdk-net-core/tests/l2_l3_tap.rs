//! L2/L3 crafted-frame integration test. Requires DPDK_NET_TEST_TAP=1 and
//! root (DPDK TAP vdev + raw AF_PACKET socket). The test:
//!   1. boots EAL + engine against a DPDK TAP vdev (iface `dpdktap1` so
//!      it doesn't collide with engine_smoke.rs's `dpdktap0`)
//!   2. brings `dpdktap1` UP and assigns kernel-side addressing
//!   3. sends a sequence of L2/L3 frames via AF_PACKET/SOCK_RAW
//!   4. polls the engine and asserts counter deltas per case

use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::process::Command;
use std::sync::atomic::Ordering;

use dpdk_net_core::counters::Counters;
use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::l3_ip::internet_checksum;

const TAP_IFACE: &str = "dpdktap1";
const DPDK_PORT: u16 = 0;
const OUR_IP: u32 = 0x0a_63_00_02; // 10.99.0.2 (host byte order)
const PEER_IP: u32 = 0x0a_63_00_01; // 10.99.0.1 on the kernel side of the tap

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

fn bring_up_tap(iface: &str, cidr: &str) {
    // These commands require root — the test itself must be run via sudo.
    let _ = Command::new("ip")
        .args(["link", "set", iface, "up"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", cidr, "dev", iface])
        .status();
}

/// Open an AF_PACKET SOCK_RAW socket bound to `iface` for raw frame TX.
fn open_pkt_socket(iface: &str) -> c_int {
    let s = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
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

fn send_frame(s: c_int, iface: &str, bytes: &[u8]) {
    let c_name = CString::new(iface).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&bytes[..6]);
    let rc = unsafe {
        libc::sendto(
            s,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            0,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&sll) as libc::socklen_t,
        )
    };
    assert!(rc > 0, "sendto failed: {}", std::io::Error::last_os_error());
}

fn build_eth(dst: [u8; 6], src: [u8; 6], et: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + body.len());
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&et.to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn build_ipv4(proto: u8, src: u32, dst: u32, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut v = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        (total & 0xff) as u8,
        0x00,
        0x01,
        0x40,
        0x00,
        0x40,
        proto,
        0x00,
        0x00,
    ];
    v.extend_from_slice(&src.to_be_bytes());
    v.extend_from_slice(&dst.to_be_bytes());
    let c = internet_checksum(&[&v]);
    v[10] = (c >> 8) as u8;
    v[11] = (c & 0xff) as u8;
    v.extend_from_slice(payload);
    v
}

fn poll_until_pkts(engine: &Engine, min_pkts: u64, max_iters: usize) {
    let c = engine.counters();
    for _ in 0..max_iters {
        engine.poll_once();
        if c.eth.rx_pkts.load(Ordering::Relaxed) >= min_pkts {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn snapshot(c: &Counters) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        c.eth.rx_pkts.load(Ordering::Relaxed),
        c.eth.rx_drop_miss_mac.load(Ordering::Relaxed),
        c.eth.rx_drop_unknown_ethertype.load(Ordering::Relaxed),
        c.eth.rx_arp.load(Ordering::Relaxed),
        c.ip.rx_drop_bad_version.load(Ordering::Relaxed),
        c.ip.rx_drop_unsupported_proto.load(Ordering::Relaxed),
        c.ip.rx_frag.load(Ordering::Relaxed),
        c.ip.rx_tcp.load(Ordering::Relaxed),
        c.ip.rx_icmp.load(Ordering::Relaxed),
        c.ip.rx_icmp_frag_needed.load(Ordering::Relaxed),
        c.ip.pmtud_updates.load(Ordering::Relaxed),
    )
}

#[test]
fn crafted_frames_through_tap_pair() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a2-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=dpdktap1",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    let cfg = EngineConfig {
        port_id: DPDK_PORT,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], // arbitrary; not actually used in rx path
        garp_interval_sec: 0,                              // disabled for this test
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();

    bring_up_tap(TAP_IFACE, "10.99.0.1/24");
    // Wait for the interface to be operational.
    std::thread::sleep(std::time::Duration::from_millis(100));

    let sock = open_pkt_socket(TAP_IFACE);

    // Drain any startup noise (router advertisements, IPv6 MLD, etc.)
    // so our counter deltas are attributable.
    for _ in 0..200 {
        engine.poll_once();
    }
    let _ = snapshot(engine.counters());

    // -- Case 1: wrong destination MAC → rx_drop_miss_mac --
    let s0 = snapshot(engine.counters());
    let bad_mac = [0xee, 0xee, 0xee, 0xee, 0xee, 0xee];
    let frame = build_eth(
        bad_mac,
        [0xaa; 6],
        0x0800,
        &build_ipv4(6 /*TCP*/, PEER_IP, OUR_IP, &[0u8; 20]),
    );
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s0.0 + 1, 500);
    let s1 = snapshot(engine.counters());
    assert_eq!(s1.1, s0.1 + 1, "rx_drop_miss_mac delta");

    // -- Case 2: unknown ethertype → rx_drop_unknown_ethertype --
    let s1 = snapshot(engine.counters());
    let frame = build_eth(our_mac, [0xaa; 6], 0x86DD /*IPv6*/, &[0u8; 20]);
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s1.0 + 1, 500);
    let s2 = snapshot(engine.counters());
    assert_eq!(s2.2, s1.2 + 1);

    // -- Case 3: IPv4 TCP to us → rx_tcp bumped --
    let s2 = snapshot(engine.counters());
    let frame = build_eth(
        our_mac,
        [0xaa; 6],
        0x0800,
        &build_ipv4(6, PEER_IP, OUR_IP, &[0u8; 20]),
    );
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s2.0 + 1, 500);
    let s3 = snapshot(engine.counters());
    assert_eq!(s3.7, s2.7 + 1, "rx_tcp delta");

    // -- Case 4: IPv4 UDP (unsupported proto) → rx_drop_unsupported_proto --
    let s3 = snapshot(engine.counters());
    let frame = build_eth(
        our_mac,
        [0xaa; 6],
        0x0800,
        &build_ipv4(17 /*UDP*/, PEER_IP, OUR_IP, &[0u8; 8]),
    );
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s3.0 + 1, 500);
    let s4 = snapshot(engine.counters());
    assert_eq!(s4.5, s3.5 + 1);

    // -- Case 5: IP fragment → rx_frag --
    let s4 = snapshot(engine.counters());
    let mut frag_ip = build_ipv4(6, PEER_IP, OUR_IP, &[0u8; 20]);
    frag_ip[6] = 0x20; // set MF bit; checksum is now wrong but parse hits fragment-drop first
    let frame = build_eth(our_mac, [0xaa; 6], 0x0800, &frag_ip);
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s4.0 + 1, 500);
    let s5 = snapshot(engine.counters());
    assert_eq!(s5.6, s4.6 + 1);

    // -- Case 6: ICMP frag-needed (RFC 1191) → pmtud_updates --
    let s5 = snapshot(engine.counters());
    // Build inner: a fake IP header whose dst is some "original destination"
    // we supposedly sent traffic to. The stack indexes PMTU by that dst.
    let inner_dst: u32 = 0x0a_63_00_64_u32; // 10.99.0.100
    let mut inner = vec![
        0x45,
        0x00,
        0x00,
        0x14,
        0x00,
        0x01,
        0x40,
        0x00,
        0x40,
        6,
        0x00,
        0x00,
        (PEER_IP >> 24) as u8,
        (PEER_IP >> 16) as u8,
        (PEER_IP >> 8) as u8,
        PEER_IP as u8,
    ];
    inner.extend_from_slice(&inner_dst.to_be_bytes());
    // Build ICMP body: type=3, code=4, csum=0, unused=0, mtu=1200, then inner IP
    let mut icmp_body = vec![
        3u8,
        4,
        0,
        0,
        0,
        0,
        (1200u16 >> 8) as u8,
        (1200u16 & 0xff) as u8,
    ];
    icmp_body.extend_from_slice(&inner);
    let frame = build_eth(
        our_mac,
        [0xaa; 6],
        0x0800,
        &build_ipv4(1 /*ICMP*/, PEER_IP, OUR_IP, &icmp_body),
    );
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s5.0 + 1, 500);
    let s6 = snapshot(engine.counters());
    assert_eq!(s6.8, s5.8 + 1, "rx_icmp delta");
    assert_eq!(s6.9, s5.9 + 1, "rx_icmp_frag_needed delta");
    assert_eq!(s6.10, s5.10 + 1, "pmtud_updates delta");
    assert_eq!(engine.pmtu_for(inner_dst), Some(1200));

    // -- Case 7: ARP request to our IP → we send an ARP reply --
    let s6 = snapshot(engine.counters());
    let tx_arp_before = engine.counters().eth.tx_arp.load(Ordering::Relaxed);
    // Build an ARP request targeting OUR_IP from a hypothetical peer.
    let peer_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    let mut arp_body = [0u8; 28];
    arp_body[0..2].copy_from_slice(&1u16.to_be_bytes());
    arp_body[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    arp_body[4] = 6;
    arp_body[5] = 4;
    arp_body[6..8].copy_from_slice(&1u16.to_be_bytes()); // request
    arp_body[8..14].copy_from_slice(&peer_mac);
    arp_body[14..18].copy_from_slice(&PEER_IP.to_be_bytes());
    // target_mac left zero
    arp_body[24..28].copy_from_slice(&OUR_IP.to_be_bytes());
    let frame = build_eth([0xff; 6], peer_mac, 0x0806, &arp_body);
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s6.0 + 1, 500);
    // Allow time for the reply to have been pushed by tx_burst.
    for _ in 0..5 {
        engine.poll_once();
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let tx_arp_after = engine.counters().eth.tx_arp.load(Ordering::Relaxed);
    assert!(
        tx_arp_after > tx_arp_before,
        "tx_arp should have incremented (we replied)"
    );

    drop(engine);
    unsafe { libc::close(sock) };
}
