//! A10 deferred-fix Stage B+ regression test: end-to-end OOO reassembly
//! mempool drift under sustained traffic, with the kernel injecting
//! reordering via `tc qdisc netem reorder`.
//!
//! This complements the direct-style `rx_reassembly_mempool_no_leak.rs`
//! (commit `209481d`) by exercising the engine's full OOO insert + drain
//! pipeline through real network traffic:
//!
//! - `engine.rs` pre-dispatch refcnt bump
//! - `tcp_input.rs` OOO branch
//! - `tcp_reassembly.rs::insert` + `drop_segment_mbuf_ref` +
//!   `drain_contiguous_into`
//!
//! That end-to-end coverage catches leak-class bugs the direct unit-style
//! test would miss — most notably the engine pre-dispatch bump's pairing
//! with the queue's retain-vs-rollback semantics.
//!
//! ## Workload shape
//!
//! Strict request/response loops (one packet per iter per direction)
//! starve `tc netem reorder` of material — there's never enough packets
//! queued at the egress qdisc to permute, so the OOO branch never fires
//! even with a reorder qdisc applied. So this test uses **pipelined
//! sends**: the main loop pushes BURST_REQUESTS 128B requests back-to-
//! back without waiting for any response, then drains. The kernel emits
//! the same number of response packets into the TAP egress queue in
//! close succession; netem's `reorder N%` permutes them, so the engine
//! receives reordered TCP segments and the OOO insert + drain pipeline
//! fires.
//!
//! ## Assertions
//!   1. `tcp.rx_reassembly_queued` exceeds MIN_OOO_OBSERVATIONS —
//!      proves the netem reorder spec actually drove segments through
//!      the OOO branch. Without this gate the drift assertion would
//!      pass vacuously if the reorder spec degenerated to a no-op.
//!   2. RX mempool free-mbuf count returns to within ±32 of the
//!      pre-test baseline.
//!
//! Gated on `DPDK_NET_TEST_TAP=1` + sudo.

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap22";
const OUR_IP: u32 = 0x0a_63_16_02; // 10.99.22.2
const PEER_IP: u32 = 0x0a_63_16_01; // 10.99.22.1
const PEER_PORT: u16 = 5022;
// Total payload bytes in the run. With BURST below, we issue
// `TOTAL_BYTES / BURST_BYTES` outer rounds; each round sends BURST_BYTES
// then drains BURST_BYTES. Tuned so the run finishes well under the test
// timeout while emitting enough packets for netem to permute.
const TOTAL_ITERATIONS: u32 = 200;
// Per-burst: how many BURST_REQUESTS we pipeline before draining. 16
// pipelined 128B requests means up to 16 ACK packets piling up in the
// kernel egress qdisc at once — plenty of material for the `reorder N%`
// spec to swap segment ordering.
const BURST_REQUESTS: u32 = 16;
// 128 bytes per request/response (single segment at MSS=1460). Multi-
// segment payloads expose unrelated TAP-PMD multi-segment quirks that
// drown the OOO signal we're after.
const PAYLOAD: usize = 128;
const DRIFT_TOLERANCE: i64 = 32;
// Empirical: pipelined 16-request bursts at `delay 5ms 1ms 25% reorder
// 50% 50%` produce hundreds of OOO observations across 200 outer iters.
// We assert > 50 as a defence-in-depth signal that the netem spec
// actually reordered traffic — if a future kernel changes netem
// semantics such that `reorder` becomes a no-op, this assertion fires
// before the drift assertion (which would incorrectly pass on a no-op
// cover).
const MIN_OOO_OBSERVATIONS: u64 = 50;

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
    let _ = Command::new("ip")
        .args(["link", "set", iface, "up"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.22.1/24", "dev", iface])
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

/// RAII guard for `tc qdisc add dev <iface> root netem <spec>` on the
/// local kernel TAP iface. Modeled on bench-stress's `NetemGuard` but
/// uses local `tc` (not SSH) since this test runs as sudo.
///
/// Drop best-effort issues `tc qdisc del dev <iface> root` so a panic in
/// the test body doesn't leave the iface with a stale netem qdisc that
/// would corrupt subsequent runs.
struct NetemGuard {
    iface: &'static str,
}

impl NetemGuard {
    fn apply(iface: &'static str, spec: &str) -> Self {
        // Best-effort: pre-clean any leftover qdisc from a previous run
        // that crashed before its Drop fired. Stderr suppressed — the
        // common "no qdisc to remove" path emits a noisy "Cannot find
        // device" line which is expected, not a failure.
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "root"])
            .stderr(std::process::Stdio::null())
            .status();
        let mut args = vec!["qdisc", "add", "dev", iface, "root", "netem"];
        args.extend(spec.split_whitespace());
        let status = Command::new("tc")
            .args(&args)
            .status()
            .expect("invoke tc");
        assert!(
            status.success(),
            "tc qdisc add netem failed (exit {:?}); is iproute2 installed and is the test running as sudo?",
            status.code()
        );
        eprintln!("[ooo-netem] applied netem on {iface}: {spec}");
        Self { iface }
    }
}

impl Drop for NetemGuard {
    fn drop(&mut self) {
        // Stderr suppressed for the same reason as the pre-clean above —
        // by drop time the TAP iface may already be torn down, in which
        // case `tc qdisc del` emits "Cannot find device" cleanly. The
        // qdisc itself goes away with the iface, so nothing to do.
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", self.iface, "root"])
            .stderr(std::process::Stdio::null())
            .status();
        eprintln!("[ooo-netem] removed netem on {}", self.iface);
    }
}

#[test]
fn rx_mempool_no_leak_with_netem_reorder() {
    if skip_if_not_tap() {
        return;
    }

    let args = [
        "dpdk-net-a10-rx-mempool-ooo-netem",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap22",
        "-l",
        "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    bring_up_tap(TAP_IFACE);
    thread::sleep(Duration::from_millis(500));

    // Apply netem reorder AFTER `eal_init` because the TAP iface is
    // created by the `net_tap0` vdev during EAL init — `tc qdisc add`
    // would silently no-op against a non-existent iface and leave the
    // run with no actual reordering.
    //
    // Spec choice: `delay 5ms 1ms 25% reorder 50% 50%` — the standard
    // "delay-based deterministic reorder". netem holds 50% of packets
    // for `delay 5ms` (with ±1ms jitter, 25% correlation) and forwards
    // the rest immediately, which guarantees reorder when the delayed
    // packets finally cross the wire after later packets.
    //
    // The `gap N` form (`reorder 50% gap 3`) requires N packets to
    // accumulate before reorder triggers; that pattern starves under a
    // strict request/response loop where there's only ever a few
    // segments in flight per RTT.
    let _netem_guard = NetemGuard::apply(TAP_IFACE, "delay 5ms 1ms 25% reorder 50% 50%");

    let kernel_mac = read_kernel_tap_mac(TAP_IFACE);

    let cfg = EngineConfig {
        port_id: 0,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: kernel_mac,
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        // Default RTO is 5ms — too aggressive against netem's 5ms ±1ms
        // delay (one-way RTT alone is ~5-10ms here). Bump to 200ms so
        // legitimate netem latency doesn't trigger spurious retransmits
        // that break the connection.
        tcp_min_rto_us: 200_000,
        tcp_initial_rto_us: 200_000,
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();
    pin_arp(TAP_IFACE, "10.99.22.2", &mac_hex(our_mac));

    let pool = engine.rx_mempool_ptr();
    assert!(!pool.is_null(), "rx mempool pointer is null");

    // Echo peer on the kernel side. Echos exactly TOTAL_ITERATIONS *
    // BURST_REQUESTS payloads back-to-back; the kernel TCP stack
    // batches its responses on the TAP egress queue where netem
    // permutes them.
    let total_count = TOTAL_ITERATIONS as u64 * BURST_REQUESTS as u64;
    let listener = TcpListener::bind(("10.99.22.1", PEER_PORT)).expect("bind echo");
    let (peer_done_tx, peer_done_rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        sock.set_nodelay(true).ok();
        let mut buf = [0u8; PAYLOAD];
        for _ in 0..total_count {
            if sock.read_exact(&mut buf).is_err() {
                break;
            }
            if sock.write_all(&buf).is_err() {
                break;
            }
        }
        let _ = peer_done_tx.send(());
    });

    // Snapshot the mempool baseline AFTER engine bring-up but BEFORE
    // the workload — same baseline semantics as `rx_mempool_no_leak.rs`.
    let avail_baseline = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    let ooo_baseline = engine
        .counters()
        .tcp
        .rx_reassembly_queued
        .load(Ordering::Relaxed);
    eprintln!(
        "[ooo-netem] baseline avail={} pool_size={} rx_reassembly_queued={}",
        avail_baseline,
        engine.rx_mempool_size(),
        ooo_baseline,
    );

    let conn = engine.connect(PEER_IP, PEER_PORT, 0).expect("connect");

    // Pump until Connected. Netem's delay applies to the SYN-ACK too.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            if matches!(ev, InternalEvent::Connected { conn: c, .. } if *c == conn) {
                connected = true;
            }
        });
        thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "connect timeout under netem reorder");

    let payload = vec![0xCDu8; PAYLOAD];
    let total_bytes = TOTAL_ITERATIONS as u64 * BURST_REQUESTS as u64 * PAYLOAD as u64;

    // -------- Pipelined send phase --------
    // Push every request back-to-back without waiting for any
    // response, interleaved with poll/drain pumps to keep the engine
    // making progress. send_bytes feeds the engine's send queue; the
    // engine emits TCP segments at MSS=1460 (each 128B request fits in
    // one segment). The kernel receives them in-order, echos back,
    // queues responses on the TAP egress where netem permutes them.
    //
    // We can't naïvely send everything in a tight loop — `send_bytes`
    // bounded by the peer window — so we interleave a poll cycle every
    // BURST_REQUESTS to drain ACKs and free up window space.
    let mut recv_total: u64 = 0;
    let total_deadline = Instant::now() + Duration::from_secs(120);
    let mut sends_remaining = TOTAL_ITERATIONS as u64 * BURST_REQUESTS as u64;
    while sends_remaining > 0 || recv_total < total_bytes {
        // Try to push up to BURST_REQUESTS more requests without
        // blocking — bail to drain if the engine refuses (window full).
        let mut burst_sent_this_cycle = 0u32;
        for _ in 0..BURST_REQUESTS {
            if sends_remaining == 0 {
                break;
            }
            let mut sent: u32 = 0;
            let send_attempt_deadline = Instant::now() + Duration::from_millis(500);
            while (sent as usize) < PAYLOAD {
                match engine.send_bytes(conn, &payload[sent as usize..]) {
                    Ok(0) => {
                        // Window full — break out and let the drain
                        // phase run; we'll come back here on the next
                        // outer cycle.
                        if Instant::now() >= send_attempt_deadline {
                            break;
                        }
                        engine.poll_once();
                        engine.drain_events(32, |ev, _| {
                            if let InternalEvent::Readable { total_len, .. } = ev {
                                recv_total = recv_total.saturating_add(*total_len as u64);
                            }
                        });
                    }
                    Ok(n) => sent = sent.saturating_add(n),
                    Err(e) => panic!("send_bytes failed: {e:?}"),
                }
            }
            if (sent as usize) == PAYLOAD {
                sends_remaining -= 1;
                burst_sent_this_cycle += 1;
            } else {
                break;
            }
        }

        // Drain phase between bursts. Each cycle gives the engine a
        // few iterations to absorb in-flight RX (ACKs + data segments
        // that netem has finally released).
        let drain_iters = if burst_sent_this_cycle == 0 { 32 } else { 8 };
        for _ in 0..drain_iters {
            engine.poll_once();
            engine.drain_events(64, |ev, _| {
                if let InternalEvent::Readable { total_len, .. } = ev {
                    recv_total = recv_total.saturating_add(*total_len as u64);
                }
            });
        }

        if Instant::now() >= total_deadline {
            let c = engine.counters();
            eprintln!(
                "[ooo-netem] global drain timeout: \
                 eth.tx_pkts={} eth.tx_drop_full_ring={} eth.rx_pkts={} \
                 tcp.rx_data={} tcp.rx_ack={} tcp.rx_reassembly_queued={} \
                 tcp.tx_retrans={} tcp.tx_data={} \
                 sends_remaining={} recv_total={}/{}",
                c.eth.tx_pkts.load(Ordering::Relaxed),
                c.eth.tx_drop_full_ring.load(Ordering::Relaxed),
                c.eth.rx_pkts.load(Ordering::Relaxed),
                c.tcp.rx_data.load(Ordering::Relaxed),
                c.tcp.rx_ack.load(Ordering::Relaxed),
                c.tcp.rx_reassembly_queued.load(Ordering::Relaxed),
                c.tcp.tx_retrans.load(Ordering::Relaxed),
                c.tcp.tx_data.load(Ordering::Relaxed),
                sends_remaining,
                recv_total,
                total_bytes,
            );
            panic!("global drain timeout under netem reorder");
        }
    }

    // Wait for the kernel echo thread to finish.
    let _ = peer_done_rx.recv_timeout(Duration::from_secs(15));

    // Final drain — give the engine extra cycles to release any
    // in-flight mbufs, particularly any straggling OOO segments still
    // in the reorder queue waiting for a gap-close that never arrived.
    for _ in 0..50 {
        engine.poll_once();
        engine.drain_events(32, |_ev, _| {});
        thread::sleep(Duration::from_millis(2));
    }

    let ooo_post = engine
        .counters()
        .tcp
        .rx_reassembly_queued
        .load(Ordering::Relaxed);
    let ooo_delta = ooo_post.saturating_sub(ooo_baseline);
    let avail_post = unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    let drift = (avail_baseline as i64) - (avail_post as i64);
    eprintln!(
        "[ooo-netem] post avail={} drift={} (baseline {}) rx_reassembly_queued_delta={}",
        avail_post, drift, avail_baseline, ooo_delta,
    );

    // Assertion (1): the netem reorder actually drove segments through
    // the OOO path. Without this gate, a future kernel/iproute2 change
    // that turns the spec into a no-op would silently produce a green
    // test that doesn't actually cover what its name claims.
    assert!(
        ooo_delta > MIN_OOO_OBSERVATIONS,
        "netem reorder did not exercise OOO path: rx_reassembly_queued delta={ooo_delta} \
         (expected > {MIN_OOO_OBSERVATIONS}). Adjust the netem spec — try \
         `reorder 50% gap 3 delay 1ms` or check whether the kernel still \
         honours the delay-based reorder syntax.",
    );

    // Assertion (2): the OOO path didn't leak. Same tolerance as the
    // in-order test — pre/post-baseline drift within ±32 mbufs covers
    // ordinary in-flight bookkeeping; anything beyond that is a leak.
    assert!(
        drift.abs() <= DRIFT_TOLERANCE,
        "RX mempool drift {drift} exceeds tolerance ±{DRIFT_TOLERANCE} \
         under netem reorder (baseline {avail_baseline}, post {avail_post}, \
         OOO delta {ooo_delta}) — likely leak in OOO insert/drain path; \
         see crates/dpdk-net-core/src/tcp_reassembly.rs",
    );

    // Surface the diagnostic counter for forensic visibility — same as
    // the in-order test. If this fires, it's the canary signal of an
    // unexpected refcnt branch hit during the OOO workload.
    let drop_unexpected = engine
        .counters()
        .tcp
        .mbuf_refcnt_drop_unexpected
        .load(Ordering::Relaxed);
    assert_eq!(
        drop_unexpected, 0,
        "mbuf_refcnt_drop_unexpected fired during OOO netem run — leak signal"
    );
}
