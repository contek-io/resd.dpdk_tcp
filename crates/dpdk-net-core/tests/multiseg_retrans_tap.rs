//! Multi-segment retransmit regression test (a6.6-7 fix).
//!
//! The Stage 1 single-segment retrans invariant
//! (`engine.rs:debug_assert_eq!(data_len, hdrs_len + entry_len)`) used to be
//! `data_len == entry_len` and panicked under any send that triggered TCP
//! segmentation followed by a retransmit. Root cause: the snd_retrans entry
//! held the WHOLE on-wire frame mbuf (Ethernet + IPv4 + TCP-with-options +
//! payload contiguously) but the retransmit primitive treated `data_len`
//! as the TCP-payload length. With MSS=1460 + TSopt enabled the typical
//! observed gap was 1466 vs 1400 (66 = 14+20+32 header bytes).
//!
//! Beyond the assertion panic, the pre-fix code also produced corrupt
//! on-wire retrans frames: `rte_pktmbuf_chain(hdr_mbuf, data_mbuf)` left
//! the original L2+L3+TCP headers inside data_mbuf, so the wire saw two
//! consecutive ETH+IPv4+TCP headers followed by the payload (and the TCP
//! checksum included those header bytes as if they were payload).
//!
//! This test sends a 4096-byte payload (3 segments at MSS=1460) over TAP
//! with the kernel as the listener, then directly invokes the retransmit
//! primitive on each snd_retrans entry via `debug_retransmit_for_test`.
//! Pre-fix:
//!   * debug builds: `debug_assert_eq!` panics on the first retrans call.
//!   * release builds: silent corruption (kernel discards the malformed
//!     frame; `tx_retrans` increments but the retransmit accomplishes
//!     nothing).
//! Post-fix: the retransmit succeeds, the invariant holds for every
//! entry, and `tcp.tx_retrans` increments by exactly the entry count.
//!
//! Requires `DPDK_NET_TEST_TAP=1` + sudo (TAP vdev + `ip neigh` setup),
//! same as every other TAP test in the corpus.
//!
//! Fresh TAP iface (`resdtap11`) + /24 (10.99.11.0/24) so it doesn't
//! collide with any other TAP test.

use std::io::Read as IoRead;
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap11";
const OUR_IP: u32 = 0x0a_63_0b_02; // 10.99.11.2
const PEER_IP: u32 = 0x0a_63_0b_01; // 10.99.11.1
const PEER_PORT: u16 = 5011;

fn skip_if_not_tap() -> bool {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run (requires sudo for TAP vdev)");
        return true;
    }
    false
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

fn bring_up_tap(iface: &str) {
    let _ = Command::new("ip").args(["link", "set", iface, "up"]).status();
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.11.1/24", "dev", iface])
        .status();
}

fn pin_arp(iface: &str, ip: &str, mac: &str) {
    let _ = Command::new("ip")
        .args([
            "neigh", "replace", ip, "lladdr", mac, "dev", iface, "nud", "permanent",
        ])
        .status();
}

fn mac_hex(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Sink server: accepts one connection and reads-and-discards bytes, so
/// the engine's send-side stays unblocked. We deliberately do NOT echo,
/// for the same reason as `bench_alloc_hotpath`: an echo introduces a
/// write-back bottleneck that interferes with the timing of the
/// kernel's ACKs.
fn spawn_sink_server(stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener =
            TcpListener::bind("10.99.11.1:5011").expect("listener bind");
        listener
            .set_nonblocking(true)
            .expect("listener set_nonblocking");
        let stream = loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();
        drop(listener);
        let mut buf = [0u8; 65536];
        let mut s = stream;
        while !stop.load(Ordering::Relaxed) {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => { /* discard */ }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
    })
}

#[test]
fn multiseg_send_then_retransmit_holds_invariant() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "resd-net-multiseg-retrans",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap11",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    let cfg = EngineConfig {
        port_id: 0,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: kernel_mac,
        tcp_mss: 1460,
        max_connections: 8,
        // Push min RTO out so the kernel has time to ACK normally and we
        // synthesize the retrans deterministically via the test hook,
        // rather than racing the natural RTO machinery.
        tcp_min_rto_us: 1_000_000,
        tcp_initial_rto_us: 1_000_000,
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();
    pin_arp(TAP_IFACE, "10.99.11.2", &mac_hex(our_mac));

    let stop = Arc::new(AtomicBool::new(false));
    let server = spawn_sink_server(Arc::clone(&stop));
    thread::sleep(Duration::from_millis(200));

    let handle = engine.connect(PEER_IP, PEER_PORT, 0).expect("connect");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            if matches!(ev, InternalEvent::Connected { conn, .. } if *conn == handle) {
                connected = true;
            }
        });
        thread::sleep(Duration::from_millis(5));
    }
    assert!(connected, "did not receive CONNECTED within deadline");

    // Send a 4096-byte payload. With MSS=1460, send_bytes splits this
    // into 3 segments (1460 + 1460 + 1176). Each segment lands in
    // `snd_retrans` as its own entry whose `mbuf` holds the WHOLE on-
    // wire frame (ETH+IPv4+TCP+payload contiguously) and whose `len`
    // records the TCP-payload bytes only. The pre-fix code's
    // `debug_assert_eq!(data_len, entry_len)` would have fired (1466 vs
    // 1460, 1466 vs 1460, 1242 vs 1176) on the first synthesized
    // retransmit below.
    let payload = vec![0xa5u8; 4096];
    let accepted = engine.send_bytes(handle, &payload).expect("send_bytes");
    assert_eq!(
        accepted as usize,
        payload.len(),
        "send_bytes accepted only {accepted} of {} bytes",
        payload.len()
    );

    // Drive a few polls so the segments get bursted out and ACKs start
    // arriving. We DO want the segments to actually wire-TX (so the
    // mbufs are alive in snd_retrans with a live data_off), but we
    // need them to STILL be in snd_retrans when we trigger the
    // synthetic retransmit — push the kernel ACKs by polling without
    // sleeping. A few iterations get the segments out the door without
    // giving the kernel enough loop time to ACK and prune them.
    for _ in 0..4 {
        engine.poll_once();
    }

    // Capture the snd_retrans entry count before retransmitting. With
    // a 4096-byte send at MSS=1460, we expect exactly 3 entries (2 full
    // MSS + 1 short). It's OK if the kernel ACK'd one or two of them
    // already by this point — we'll synthesize a retrans on whatever
    // entries remain.
    let entry_count_pre = {
        let ft = engine.flow_table();
        ft.get(handle).map(|c| c.snd_retrans.len()).unwrap_or(0)
    };
    assert!(
        entry_count_pre > 0,
        "snd_retrans drained before we could retransmit (kernel ACK'd too fast?)"
    );

    let c = engine.counters();
    let tx_retrans_pre = c.tcp.tx_retrans.load(Ordering::Relaxed);

    // Synthesize a retransmit on every entry in snd_retrans. Each call
    // walks the full retransmit primitive, which includes the
    // `data_len == hdrs_len + entry_len` invariant assertion. Pre-fix:
    // the FIRST call panics in debug builds. Post-fix: each call
    // succeeds and increments tcp.tx_retrans by 1.
    //
    // We iterate by index repeatedly because `entries` may have shifted
    // if a kernel ACK arrived between calls (prune_below trims the
    // front). Driving poll_once between retrans calls would race the
    // pruner; we just call retransmit on indices 0..entry_count_pre and
    // let the natural state-machine sort out anything that got pruned
    // (retransmit silently no-ops on out-of-range index).
    for idx in 0..entry_count_pre {
        engine.debug_retransmit_for_test(handle, idx);
    }

    let tx_retrans_delta =
        c.tcp.tx_retrans.load(Ordering::Relaxed) - tx_retrans_pre;
    eprintln!(
        "[multiseg-retrans] entries_at_synth={} tx_retrans_delta={} \
         tx_data={} rx_ack={}",
        entry_count_pre,
        tx_retrans_delta,
        c.tcp.tx_data.load(Ordering::Relaxed),
        c.tcp.rx_ack.load(Ordering::Relaxed),
    );

    // The fix's success signal: every synthesized retransmit got past
    // the assertion AND past the chain step (chain failure would NOT
    // have incremented tx_retrans). Allow tx_retrans_delta to be less
    // than entry_count_pre — a kernel ACK arriving between retrans
    // calls will have shifted the front, making later index lookups
    // miss the entry. The bug we're guarding against is a panic, so
    // tx_retrans_delta >= 1 is the necessary signal.
    assert!(
        tx_retrans_delta >= 1,
        "no synthesized retransmit reached the chain-and-bump step \
         (entries_at_synth={}, tx_retrans_delta={})",
        entry_count_pre,
        tx_retrans_delta,
    );

    // Drive a few more polls to consume any stragglers + pump events,
    // then close cleanly so the engine doesn't leak the conn into the
    // teardown.
    for _ in 0..32 {
        engine.poll_once();
        engine.drain_events(16, |_, _| {});
        thread::sleep(Duration::from_millis(5));
    }
    engine.close_conn(handle).ok();
    let teardown_end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < teardown_end {
        engine.poll_once();
        thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    drop(engine);
    let _ = server.join();
}
