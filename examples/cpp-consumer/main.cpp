#include "dpdk_net.h"
#include "dpdk_net_counters_load.h"
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>

static_assert(sizeof(std::atomic<uint64_t>) == sizeof(uint64_t) &&
              alignof(std::atomic<uint64_t>) == alignof(uint64_t),
              "dpdk_net counters layout requires std::atomic<uint64_t> POD-compat");

int main() {
    dpdk_net_engine_config_t cfg{};
    cfg.port_id = 0;
    cfg.rx_queue_id = 0;
    cfg.tx_queue_id = 0;
    cfg.max_connections = 16;
    cfg.recv_buffer_bytes = 256 * 1024;
    cfg.send_buffer_bytes = 256 * 1024;
    cfg.tcp_mss = 0;
    cfg.tcp_timestamps = true;
    cfg.tcp_sack = true;
    cfg.tcp_ecn = false;
    cfg.tcp_nagle = false;
    cfg.tcp_delayed_ack = false;
    cfg.cc_mode = 0;
    cfg.tcp_min_rto_ms = 20;
    // A5 Task 21: RTO config in µs replaces the A3 single-value knob.
    cfg.tcp_min_rto_us = 5000;
    cfg.tcp_initial_rto_us = 5000;
    cfg.tcp_max_rto_us = 1000000;
    cfg.tcp_max_retrans_count = 15;
    cfg.tcp_msl_ms = 30000;
    cfg.tcp_per_packet_events = false;
    cfg.preset = 0;

    // Phase A2 addressing (left at zero — the TAP sample isn't doing real
    // traffic). Real deployments supply local_ip, gateway_ip, gateway_mac.
    cfg.local_ip = 0;
    cfg.gateway_ip = 0;
    memset(cfg.gateway_mac, 0, sizeof(cfg.gateway_mac));
    cfg.garp_interval_sec = 0;
    cfg.event_queue_soft_cap = 4096;
    // A6 Task 20: all-zero bucket edges select the stack's trading-tuned
    // defaults (spec §3.8.2). Applications that need custom edges fill
    // in 15 strictly-monotonic µs values here before engine create.
    memset(cfg.rtt_histogram_bucket_edges_us, 0,
        sizeof(cfg.rtt_histogram_bucket_edges_us));

    // Initialize EAL first. Uses DPDK TAP vdev so no real NIC is required.
    const char* eal_args[] = {
        "dpdk-net-cpp-consumer",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=dpdktap0",
        "-l", "0-1",
        "--log-level=3",
    };
    int eal_argc = (int)(sizeof(eal_args) / sizeof(eal_args[0]));
    int eal_rc = dpdk_net_eal_init(eal_argc, eal_args);
    if (eal_rc != 0) {
        std::fprintf(stderr, "dpdk_net_eal_init failed: %d\n", eal_rc);
        return 1;
    }

    struct dpdk_net_engine* eng = dpdk_net_engine_create(0, &cfg);
    if (!eng) {
        std::fprintf(stderr, "engine create failed\n");
        return 1;
    }

    uint64_t received_bytes_total = 0;
    uint64_t received_events_total = 0;
    uint64_t multi_seg_events_total = 0;
    for (int i = 0; i < 100; i++) {
        dpdk_net_event_t events[32];
        int n = dpdk_net_poll(eng, events, 32, 0);
        for (int ev_i = 0; ev_i < n; ev_i++) {
            if (events[ev_i].kind == DPDK_NET_EVT_READABLE) {
                const auto& r = events[ev_i].u.readable;
                for (uint32_t seg_i = 0; seg_i < r.n_segs; ++seg_i) {
                    received_bytes_total += r.segs[seg_i].len;
                }
                received_events_total++;
                if (r.n_segs > 1) multi_seg_events_total++;
            }
        }
    }
    std::cout << "Received " << received_events_total << " READABLE events, "
              << received_bytes_total << " bytes total, "
              << multi_seg_events_total << " were multi-seg\n";

    const dpdk_net_counters_t* counters = dpdk_net_counters(eng);
    const dpdk_net_counters_t* c = counters;
    // Counter fields are plain uint64_t but written atomically.
    // Use the dpdk_net_load_u64 helper from dpdk_net_counters_load.h
    // for strictly-correct cross-thread reads (zero-cost on x86_64,
    // correct on ARM where naive uint64_t loads may tear).
    uint64_t rx_pkts = dpdk_net_load_u64(&counters->eth.rx_pkts);
    std::cout << "rx_pkts = " << rx_pkts << "\n";
    uint64_t iters = __atomic_load_n(&c->poll.iters, __ATOMIC_RELAXED);
    std::printf("poll iters: %llu\n", (unsigned long long)iters);
    std::printf("now_ns: %llu\n",
        (unsigned long long)dpdk_net_now_ns(eng));

    // Phase A2: print IP counters to confirm they are accessible from C++.
    std::printf("ip.rx_drop_bad_version: %llu\n",
        (unsigned long long)__atomic_load_n(&c->ip.rx_drop_bad_version, __ATOMIC_RELAXED));
    std::printf("ip.rx_tcp: %llu\n",
        (unsigned long long)__atomic_load_n(&c->ip.rx_tcp, __ATOMIC_RELAXED));
    std::printf("ip.rx_icmp: %llu\n",
        (unsigned long long)__atomic_load_n(&c->ip.rx_icmp, __ATOMIC_RELAXED));
    std::printf("ip.pmtud_updates: %llu\n",
        (unsigned long long)__atomic_load_n(&c->ip.pmtud_updates, __ATOMIC_RELAXED));
    std::printf("eth.rx_arp: %llu\n",
        (unsigned long long)__atomic_load_n(&c->eth.rx_arp, __ATOMIC_RELAXED));

    // Phase A3: print TCP counters to confirm ABI parity.
    std::printf("tcp.tx_syn: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.tx_syn, __ATOMIC_RELAXED));
    std::printf("tcp.rx_syn_ack: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.rx_syn_ack, __ATOMIC_RELAXED));
    std::printf("tcp.tx_data: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.tx_data, __ATOMIC_RELAXED));
    std::printf("tcp.tx_fin: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.tx_fin, __ATOMIC_RELAXED));
    std::printf("tcp.rx_fin: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.rx_fin, __ATOMIC_RELAXED));
    std::printf("tcp.conn_open: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.conn_open, __ATOMIC_RELAXED));
    std::printf("tcp.conn_close: %llu\n",
        (unsigned long long)__atomic_load_n(&c->tcp.conn_close, __ATOMIC_RELAXED));

    // Phase A5.5 Task 7: dpdk_net_conn_stats C ABI linkage demo.
    // No real peer exists on the TAP vdev, so we can't walk a live
    // handle here; prove linkage by exercising the ENOENT branch on
    // a never-allocated handle. Real deployments call this after a
    // successful connect to tag orders with snd_nxt/srtt_us/rto_us.
    dpdk_net_conn_stats_t stats{};
    int stats_rc = dpdk_net_conn_stats(eng, /*conn=*/0xdeadbeef, &stats);
    std::printf("dpdk_net_conn_stats (unknown handle) rc=%d\n", stats_rc);
    std::printf("stats: snd_nxt=%u srtt_us=%u rto_us=%u\n",
        stats.snd_nxt, stats.srtt_us, stats.rto_us);

    dpdk_net_engine_destroy(eng);
    return 0;
}
