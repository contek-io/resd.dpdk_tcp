#![no_main]
use libfuzzer_sys::fuzz_target;

use dpdk_net_core::l2::l2_decode;
use dpdk_net_core::l3_ip::ip_decode;
use dpdk_net_core::tcp_input::parse_segment;
use dpdk_net_core::tcp_options::parse_options;

fuzz_target!(|data: &[u8]| {
    // Fuzz the IP+TCP header parsers with arbitrary bytes. Property: no
    // panic, no UB, no OOB read. Complements proptest_tcp_options.rs
    // (which tests round-trip of well-formed options); this target drives
    // the parse path on malformed/truncated/adversarial input under
    // libFuzzer's coverage guidance.
    //
    // We run each public pure parser the stack exposes:
    //   * `l2_decode`   — Ethernet II framing (crates/dpdk-net-core/src/l2.rs)
    //   * `ip_decode`   — IPv4 header (crates/dpdk-net-core/src/l3_ip.rs)
    //   * `parse_segment` — TCP header + options slice (tcp_input.rs)
    //   * `parse_options` — TCP option TLVs (tcp_options.rs)
    //
    // `nic_csum_ok=true` is passed to the L3/L4 parsers: a mismatched
    // checksum is not a parse bug, so we bypass the csum-verify branch so
    // fuzzing converges on structural decode paths instead of stalling on
    // random-byte csum failures. A separate pass with `nic_csum_ok=false`
    // still runs to exercise the csum branch (fold must not panic on
    // truncated headers).
    //
    // Walking: we treat `data` as up to four independent parse inputs by
    // feeding the full buffer to each parser. libFuzzer picks features
    // per-parser; no state flows between them.

    // L2.
    let _ = l2_decode(data, [0u8; 6]);
    let _ = l2_decode(data, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);

    // L3. our_ip=0 means accept-any; we also cover a fixed our_ip to
    // trigger the `NotOurs` path on random dst_ip.
    let _ = ip_decode(data, 0, true);
    let _ = ip_decode(data, 0, false);
    let _ = ip_decode(data, 0x0a00_0001, true);

    // L4. Vary src/dst IPs so the pseudo-header fold sees different input
    // under `nic_csum_ok=false`.
    let _ = parse_segment(data, 0, 0, true);
    let _ = parse_segment(data, 0x0a00_0001, 0x0a00_0002, false);

    // TCP options.
    let _ = parse_options(data);

    // Layered pass: if L2 passes and the ethertype is IPv4, attempt IP then
    // TCP parse on the suffix. This lets libFuzzer steer toward inputs that
    // traverse multiple layers without requiring exact per-layer lengths.
    if let Ok(l2) = l2_decode(data, [0u8; 6]) {
        let rest = &data[l2.payload_offset..];
        if let Ok(l3) = ip_decode(rest, 0, true) {
            if l3.header_len <= rest.len() {
                let tcp = &rest[l3.header_len..];
                if let Ok(seg) = parse_segment(tcp, l3.src_ip, l3.dst_ip, true) {
                    let _ = parse_options(seg.options);
                }
            }
        }
    }
});
