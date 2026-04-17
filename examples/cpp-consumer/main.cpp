#include "resd_net.h"
#include <cstdint>
#include <cstdio>
#include <cstring>

int main() {
    resd_net_engine_config_t cfg{};
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
    cfg.tcp_initial_rto_ms = 50;
    cfg.tcp_msl_ms = 30000;
    cfg.tcp_per_packet_events = false;
    cfg.preset = 0;

    // Phase A2 addressing (left at zero — the TAP sample isn't doing real
    // traffic). Real deployments supply local_ip, gateway_ip, gateway_mac.
    cfg.local_ip = 0;
    cfg.gateway_ip = 0;
    memset(cfg.gateway_mac, 0, sizeof(cfg.gateway_mac));
    cfg.garp_interval_sec = 0;

    // Initialize EAL first. Uses DPDK TAP vdev so no real NIC is required.
    const char* eal_args[] = {
        "resd-net-cpp-consumer",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap0",
        "-l", "0-1",
        "--log-level=3",
    };
    int eal_argc = (int)(sizeof(eal_args) / sizeof(eal_args[0]));
    int eal_rc = resd_net_eal_init(eal_argc, eal_args);
    if (eal_rc != 0) {
        std::fprintf(stderr, "resd_net_eal_init failed: %d\n", eal_rc);
        return 1;
    }

    struct resd_net_engine* eng = resd_net_engine_create(0, &cfg);
    if (!eng) {
        std::fprintf(stderr, "engine create failed\n");
        return 1;
    }

    for (int i = 0; i < 100; i++) {
        resd_net_event_t events[32];
        int n = resd_net_poll(eng, events, 32, 0);
        (void)n;
    }

    const resd_net_counters_t* c = resd_net_counters(eng);
    // Counter fields are plain uint64_t but written atomically.
    // Use __atomic_load_n for strictly-correct cross-thread reads.
    uint64_t iters = __atomic_load_n(&c->poll.iters, __ATOMIC_RELAXED);
    std::printf("poll iters: %llu\n", (unsigned long long)iters);
    std::printf("now_ns: %llu\n",
        (unsigned long long)resd_net_now_ns(eng));

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

    resd_net_engine_destroy(eng);
    return 0;
}
