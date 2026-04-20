//! A-HW Task 18: HW-path smoke test on real ENA VF (spec §12.3).
//!
//! # Preconditions
//!
//! This test is marked `#[ignore]` by default. It is NOT run by
//! `cargo test`; the operator must opt in on a host that actually has
//! an ENA VF dedicated to this test. To run:
//!
//! ```sh
//! DPDK_NET_TEST_ENA=1 \
//! ENA_BDF=0000:00:06.0 \
//! ENA_LOCAL_IP=10.0.1.10 \
//! ENA_PEER_IP=10.0.1.20 \
//! ENA_PEER_PORT=4242 \
//! ENA_GATEWAY_MAC=02:00:00:00:00:01 \
//! cargo test --release --test ahw_smoke_ena_hw -- --ignored --nocapture
//! ```
//!
//! Required operator prep on the host:
//!   * AWS EC2 with a dedicated ENA VF (NOT the SSH interface).
//!   * Hugepages reserved: ≥ 1 GiB of 2 MB pages
//!     (check `cat /proc/meminfo | grep Huge`).
//!   * The ENA VF bound to `vfio-pci`
//!     (check `dpdk-devbind.py --status`).
//!   * No other process has bound the VF — DPDK's EAL-init lock is
//!     exclusive, and another process holding it will fail the test.
//!   * A paired TCP echo peer reachable at `ENA_PEER_IP:ENA_PEER_PORT`
//!     (e.g. a second VF in the same subnet with `nc -l 4242`).
//!   * An ARP entry pinning the gateway MAC (the L2 next-hop for
//!     traffic to `ENA_PEER_IP`) supplied via `ENA_GATEWAY_MAC`.
//!     Obtain via `ip neigh show` on the linux peer side or the AWS
//!     VPC route table.
//!
//! # Env vars
//!
//! | Var                   | Purpose                                            |
//! |-----------------------|----------------------------------------------------|
//! | `DPDK_NET_TEST_ENA=1` | Gate — without this, test prints skip + returns.   |
//! | `ENA_BDF`             | PCI BDF of the ENA VF (e.g. `0000:00:06.0`).       |
//! | `ENA_LOCAL_IP`        | Our IP on the VF's subnet (dotted-quad).           |
//! | `ENA_PEER_IP`         | Echo peer IP (dotted-quad).                        |
//! | `ENA_PEER_PORT`       | Echo peer port.                                    |
//! | `ENA_GATEWAY_MAC`     | L2 next-hop MAC toward the peer (`aa:bb:...:ff`).  |
//!
//! # Assertions (spec §12.3)
//!
//! With default A-HW features on real ENA (verified 2026-04-20 against
//! DPDK 23.11 `rte_eth_dev_info_get` output `rx_offload_capa=0x200e`,
//! `tx_offload_capa=0x1800e`):
//!   * `offload_missing_rx_cksum_{ipv4,tcp,udp} == 0`
//!     (ENA advertises all three).
//!   * `offload_missing_tx_cksum_{ipv4,tcp,udp} == 0`.
//!   * `offload_missing_mbuf_fast_free == 1` — ENA does NOT advertise
//!     `TX_OFFLOAD_MBUF_FAST_FREE` at DPDK 23.11 (parent spec §8.2
//!     updated 2026-04-20 to reflect runtime reality).
//!   * `offload_missing_rss_hash == 1` — ENA does NOT advertise
//!     `RX_OFFLOAD_RSS_HASH` at DPDK 23.11 (parent spec §8.2 same).
//!     `flow_table` falls back to SipHash per A-HW spec §8.2.
//!   * `offload_missing_rx_timestamp == 1` — ENA steady state, the PMD
//!     does not register `rte_dynfield_timestamp` (parent §8.3 +
//!     A-HW spec §10.5).
//!   * `offload_missing_llq == 0` — ENA PMD default `enable_llq=1`
//!     activates LLQ. Task 12's log-scrape verifier wraps `rte_eal_init`
//!     and stores a verdict. If `rte_openlog_stream` capture returns
//!     empty (observed in some containerized DPDK setups), the verifier
//!     soft-skips with a warning rather than false-failing. See
//!     `llq_verify::record_eal_init_log_verdict`.
//!   * `rx_drop_cksum_bad == 0` on well-formed echo traffic.
//!   * Every emitted event's `rx_hw_ts_ns == 0` — accessor yields 0
//!     when the dynfield is absent, which is the ENA steady state.
//!     Stage 2 hardening on a non-ENA PMD that registers the
//!     dynfield will close the positive-path assertion.
//!   * Full request-response cycle passes the same correctness
//!     oracle as the TAP-based tests.
//!
//! This test is part of the ship gate (spec §16 criterion c). The
//! operator MUST run this on the actual ENA deployment host before
//! tagging `phase-a-hw-complete`.
//!
//! # Why a separate file?
//!
//! `ahw_smoke.rs` (Tasks 16/17) is gated on `DPDK_NET_TEST_TAP=1` and
//! targets the `net_tap` PMD harness. This test is gated on
//! `DPDK_NET_TEST_ENA=1` and targets a real ENA VF. Both would be
//! invoked as `cargo test --test <name>`; keeping them separate makes
//! the operator invocation obvious + keeps skip-mode output clean.

// All imports and helpers are gated on the same feature set as the
// test body below. Under `--no-default-features` the file compiles to
// an empty unit so the CI feature matrix (Task 15) stays green without
// warnings under `-D warnings`.

#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
use std::net::TcpStream;
#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
use std::sync::atomic::Ordering;
#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
use std::time::{Duration, Instant};

#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
use dpdk_net_core::tcp_events::InternalEvent;

/// Parse `aa:bb:cc:dd:ee:ff` into `[u8; 6]`.
#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
fn parse_mac(s: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.trim().split(':').collect();
    assert_eq!(parts.len(), 6, "ENA_GATEWAY_MAC must be aa:bb:cc:dd:ee:ff");
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).expect("hex byte in ENA_GATEWAY_MAC");
    }
    out
}

/// Parse dotted-quad `10.0.1.10` into host-order `u32`.
#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
fn parse_ip(s: &str) -> u32 {
    let octets: Vec<u8> = s
        .trim()
        .split('.')
        .map(|p| p.parse::<u8>().expect("ip octet"))
        .collect();
    assert_eq!(octets.len(), 4, "dotted-quad expected");
    ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32)
}

#[test]
#[ignore = "requires real ENA VF; set DPDK_NET_TEST_ENA=1 + ENA_BDF=<bdf>"]
#[cfg(all(
    feature = "hw-verify-llq",
    feature = "hw-offload-tx-cksum",
    feature = "hw-offload-rx-cksum",
    feature = "hw-offload-mbuf-fast-free",
    feature = "hw-offload-rss-hash",
    feature = "hw-offload-rx-timestamp",
))]
fn ahw_ena_hw_path_banner_and_counters() {
    // Belt-and-braces: `#[ignore]` is the primary gate, but the env-var
    // check matches the pattern used by the TAP tests and lets CI
    // explicitly skip even if `--ignored` is passed with the env unset.
    if std::env::var("DPDK_NET_TEST_ENA").ok().as_deref() != Some("1") {
        eprintln!("ahw_smoke_ena_hw: DPDK_NET_TEST_ENA not set; skipping");
        return;
    }

    let bdf = std::env::var("ENA_BDF")
        .expect("ENA_BDF env var required (e.g. 0000:00:06.0)");
    let local_ip_s = std::env::var("ENA_LOCAL_IP")
        .expect("ENA_LOCAL_IP env var required (dotted-quad of our IP on the VF subnet)");
    let peer_ip_s = std::env::var("ENA_PEER_IP")
        .expect("ENA_PEER_IP env var required (dotted-quad of the echo peer)");
    let peer_port: u16 = std::env::var("ENA_PEER_PORT")
        .expect("ENA_PEER_PORT env var required")
        .parse()
        .expect("ENA_PEER_PORT must parse as u16");
    let gateway_mac_s = std::env::var("ENA_GATEWAY_MAC")
        .expect("ENA_GATEWAY_MAC env var required (L2 next-hop MAC toward the peer)");

    let local_ip = parse_ip(&local_ip_s);
    let peer_ip = parse_ip(&peer_ip_s);
    let gateway_mac = parse_mac(&gateway_mac_s);

    // Sanity-check reachability of the echo peer BEFORE taking the VF
    // away from the kernel. If the peer isn't listening, surface that
    // now rather than after DPDK has grabbed the VF and we've spent
    // several seconds timing out on SYN retransmits.
    //
    // NOTE: this check connects from the kernel side (whichever NIC the
    // host uses by default), NOT through DPDK. It confirms the peer is
    // up + listening; the actual HW-path test then runs through DPDK.
    match TcpStream::connect_timeout(
        &format!("{peer_ip_s}:{peer_port}").parse().expect("sockaddr"),
        Duration::from_secs(3),
    ) {
        Ok(s) => drop(s),
        Err(e) => panic!(
            "kernel-side reachability check for {peer_ip_s}:{peer_port} failed: {e}.  \
             Start an echo peer (e.g. `nc -l {peer_port}`) on a host reachable from \
             this ENA VF's subnet before running the test."
        ),
    }

    // EAL args: PCI-allowlist the ENA VF with `enable_llq=1`. The
    // `-a <bdf>,enable_llq=1` form is the ENA PMD parameter that
    // activates LLQ placement policy — required for
    // `offload_missing_llq == 0` below. No vdev, no --no-pci.
    let bdf_allowlist = format!("{bdf},enable_llq=1");
    let args = [
        "ahw_smoke_ena_hw",
        "-l",
        "0",
        "--in-memory",
        "--huge-unlink",
        "-a",
        &bdf_allowlist,
        // `eal_init` internally injects `--log-level=pmd.net.ena.driver,info`
        // when `hw-verify-llq` is on so the LLQ verifier can see the
        // INFO-level "Placement policy" marker. We do NOT set a lower
        // global `--log-level` here because DPDK's default global level
        // is INFO (7), and `rte_log` requires BOTH global AND component
        // filters to pass — a lower global level would suppress INFO
        // messages even with the component override in place.
    ];
    eal_init(&args).expect("EAL init on ENA VF");

    // Short MSL so the TIME_WAIT reaper fires fast enough for the test
    // budget — same pattern as the TAP tests.
    let cfg = EngineConfig {
        port_id: 0,
        local_ip,
        gateway_ip: peer_ip,
        gateway_mac,
        tcp_mss: 1460,
        max_connections: 8,
        tcp_msl_ms: 100,
        ..Default::default()
    };

    let engine = Engine::new(cfg).expect("engine new on ENA VF");
    let handle = engine.connect(peer_ip, peer_port, 0).expect("connect");

    // --- Drive a full request-response cycle (A3 oracle pattern) ---
    //
    // The peer is externally arranged (operator responsibility per the
    // header). A vanilla `nc -l <port>` peer does not echo by default —
    // the operator should use `ncat -l -k --exec '/bin/cat'` or similar
    // so that bytes sent flow back. We send a fixed 128-byte payload
    // and wait for the same 128 bytes to come back.
    let mut all_events: Vec<InternalEvent> = Vec::new();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut connected = false;
    while Instant::now() < deadline && !connected {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if matches!(ev, InternalEvent::Connected { conn, .. } if *conn == handle) {
                connected = true;
            }
        });
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(connected, "did not receive CONNECTED within deadline");

    let msg: [u8; 128] = {
        let mut m = [0u8; 128];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x20);
        }
        m
    };
    let accepted = engine.send_bytes(handle, &msg).expect("send");
    assert_eq!(accepted as usize, msg.len());

    let mut echoed = Vec::<u8>::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && echoed.len() < msg.len() {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if let InternalEvent::Readable {
                conn,
                mbuf_idx,
                payload_offset,
                payload_len,
                ..
            } = ev
            {
                if *conn == handle {
                    let ft = engine.flow_table();
                    if let Some(c) = ft.get(handle) {
                        let idx = *mbuf_idx as usize;
                        let mbuf_ptr = c.recv.last_read_mbufs[idx].as_ptr();
                        let data_ptr = unsafe {
                            (dpdk_net_sys::shim_rte_pktmbuf_data(mbuf_ptr) as *const u8)
                                .add(*payload_offset as usize)
                        };
                        let slice = unsafe {
                            std::slice::from_raw_parts(data_ptr, *payload_len as usize)
                        };
                        echoed.extend_from_slice(slice);
                    }
                }
            }
        });
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(&echoed[..], &msg[..], "echoed bytes mismatched");

    engine.close_conn(handle).expect("close");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut closed = false;
    while Instant::now() < deadline && !closed {
        engine.poll_once();
        engine.drain_events(16, |ev, _| {
            all_events.push(ev.clone());
            if matches!(ev, InternalEvent::Closed { conn, .. } if *conn == handle) {
                closed = true;
            }
        });
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(closed, "did not receive CLOSED within deadline");

    // --- Correctness oracle (mirrors ahw_smoke.rs) ---
    let c = engine.counters();
    assert!(c.tcp.tx_syn.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_syn_ack.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_data.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.tx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.rx_fin.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_open.load(Ordering::Relaxed) >= 1);
    assert!(c.tcp.conn_close.load(Ordering::Relaxed) >= 1);
    assert_eq!(c.tcp.rx_bad_csum.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_bad_flags.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_short.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.recv_buf_drops.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.rx_unmatched.load(Ordering::Relaxed), 0);
    assert_eq!(c.tcp.conn_rst.load(Ordering::Relaxed), 0);
    assert!(
        c.tcp.recv_buf_delivered.load(Ordering::Relaxed) >= msg.len() as u64,
        "recv_buf_delivered must reflect at least msg.len() bytes"
    );

    // --- A-HW offload-missing counter assertions (spec §12.3) ---
    //
    // ENA advertises every requested RX/TX capability under default
    // A-HW features; the AND of requested-against-advertised is
    // nonempty for each bit, so every corresponding `offload_missing_*`
    // counter must remain 0. The only documented exception is
    // `offload_missing_rx_timestamp`, which is 1 because ENA does NOT
    // register `rte_dynfield_timestamp` (parent spec §8.3 +
    // A-HW §10.5).

    assert_eq!(
        c.eth.offload_missing_rx_cksum_ipv4.load(Ordering::Relaxed),
        0,
        "ENA advertises RTE_ETH_RX_OFFLOAD_IPV4_CKSUM"
    );
    assert_eq!(
        c.eth.offload_missing_rx_cksum_tcp.load(Ordering::Relaxed),
        0,
        "ENA advertises RTE_ETH_RX_OFFLOAD_TCP_CKSUM"
    );
    assert_eq!(
        c.eth.offload_missing_rx_cksum_udp.load(Ordering::Relaxed),
        0,
        "ENA advertises RTE_ETH_RX_OFFLOAD_UDP_CKSUM"
    );
    assert_eq!(
        c.eth.offload_missing_tx_cksum_ipv4.load(Ordering::Relaxed),
        0,
        "ENA advertises RTE_ETH_TX_OFFLOAD_IPV4_CKSUM"
    );
    assert_eq!(
        c.eth.offload_missing_tx_cksum_tcp.load(Ordering::Relaxed),
        0,
        "ENA advertises RTE_ETH_TX_OFFLOAD_TCP_CKSUM"
    );
    assert_eq!(
        c.eth.offload_missing_tx_cksum_udp.load(Ordering::Relaxed),
        0,
        "ENA advertises RTE_ETH_TX_OFFLOAD_UDP_CKSUM"
    );
    // Task 18 post-commit corrections (verified on AWS ENA at DPDK 23.11,
    // 2026-04-20): the PMD's advertised mask is 0x200e (RX) / 0x1800e
    // (TX). Neither MBUF_FAST_FREE (TX bit 14) nor RSS_HASH (RX bit 19)
    // is advertised. Parent spec §8.2 updated to reflect actual runtime.
    // Both counters bump to 1 at bring-up per spec §11 — the expected
    // steady state on real ENA.
    assert_eq!(
        c.eth.offload_missing_mbuf_fast_free.load(Ordering::Relaxed),
        1,
        "ENA does NOT advertise TX_OFFLOAD_MBUF_FAST_FREE (parent §8.2)"
    );
    assert_eq!(
        c.eth.offload_missing_rss_hash.load(Ordering::Relaxed),
        1,
        "ENA does NOT advertise RX_OFFLOAD_RSS_HASH (parent §8.2)"
    );
    // LLQ verification is actively validated on real ENA (verified
    // 2026-04-20, DPDK 23.11): `eal_init` injects
    // `--log-level=pmd.net.ena.driver,info` so the ENA PMD's
    // "Placement policy: Low latency" marker emits into the captured
    // log. The verifier then matches the activation marker and counter
    // stays 0. If the capture mechanism ever degenerates (e.g. returns
    // empty), `record_eal_init_log_verdict` soft-skips rather than
    // false-failing — still counter = 0.
    assert_eq!(
        c.eth.offload_missing_llq.load(Ordering::Relaxed),
        0,
        "ENA PMD default enable_llq=1 activates LLQ; Task 12 verifier \
         captures 'Placement policy: Low latency' at EAL init and \
         confirms activation."
    );

    // THE documented exception: ENA does NOT register
    // `rte_dynfield_timestamp` at DPDK 23.11, so the dynfield-lookup
    // branch in Engine::new bumps this counter exactly once at
    // bring-up (one-shot per engine_create per spec §11).
    assert_eq!(
        c.eth.offload_missing_rx_timestamp.load(Ordering::Relaxed),
        1,
        "expected 1 on ENA (dynfield absent) — spec §10.5 steady state"
    );

    // Well-formed ENA traffic must not report cksum BAD — covers both
    // the NIC-classified path and any software-verify fallback.
    assert_eq!(
        c.eth.rx_drop_cksum_bad.load(Ordering::Relaxed),
        0,
        "well-formed ENA echo traffic must not report cksum BAD"
    );

    // --- Every event's rx_hw_ts_ns is 0 on ENA ---
    //
    // ENA does not register `rte_dynfield_timestamp`, so
    // `Engine::hw_rx_ts_ns` returns 0 for every RX mbuf. Connected
    // and Readable carry the field directly; Closed + StateChange
    // don't. Iterate over the variants that CARRY `rx_hw_ts_ns`
    // and assert. Stage 2 hardening on a non-ENA PMD that registers
    // the dynfield will close the positive-path assertion.
    let mut checked = 0usize;
    for ev in &all_events {
        match ev {
            InternalEvent::Connected { rx_hw_ts_ns, .. }
            | InternalEvent::Readable { rx_hw_ts_ns, .. } => {
                assert_eq!(
                    *rx_hw_ts_ns, 0,
                    "ENA: accessor always yields 0 (dynfield absent)"
                );
                checked += 1;
            }
            _ => {}
        }
    }
    assert!(
        checked >= 2,
        "expected at least 1 Connected + 1 Readable to carry rx_hw_ts_ns; checked {checked}"
    );

    // A-HW+ T11: verify the new ENA-observability counters + xstats scrape.
    // These assertions are the real-host gate for T1 / T3 / T5 / T9.

    // T3 — WC verification. Must be 0 on a correctly-configured host
    // (igb_uio wc_activate=1 OR patched vfio-pci). Nonzero exposes a
    // WC misconfiguration that would silently destroy LLQ perf per
    // ENA README §6.1 + §14 perf FAQ Q1.
    assert_eq!(
        engine
            .counters()
            .eth
            .llq_wc_missing
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "WC verification: prefetchable BAR not mapped write-combining; \
         check /sys/kernel/debug/x86/pat_memtype_list + ENA README §6.1"
    );

    // T9 — overflow-risk warn should fire once on ENA with the knob
    // defaulted to 0 (worst-case header 94 B + 6 B margin > 96 B LLQ
    // limit). Operators who want the warn suppressed must set
    // EngineConfig.ena_large_llq_hdr=1 and splice the devarg via T8.
    assert_eq!(
        engine
            .counters()
            .eth
            .llq_header_overflow_risk
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "M1 overflow-risk warn expected to fire once with the default knob"
    );

    // T5 / T6 — xstats scrape reads ENI allowances + per-queue q0
    // counters via rte_eth_xstats_get_by_id. The scrape must not
    // panic; allowance counter values are environment-dependent
    // (nonzero if a prior workload pushed hypervisor limits) so we
    // only assert the scrape ran.
    engine.scrape_xstats();
    let doorbells = engine
        .counters()
        .eth
        .tx_q0_doorbells
        .load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("post-scrape eth.tx_q0_doorbells = {}", doorbells);
    // doorbells may be 0 if no TX burst has happened yet — that's OK.
    // The non-panic + printable read is the assertion of interest.

    drop(engine);
}
