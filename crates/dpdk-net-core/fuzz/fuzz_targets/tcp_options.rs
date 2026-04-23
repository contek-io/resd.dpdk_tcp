#![no_main]
use libfuzzer_sys::fuzz_target;
use dpdk_net_core::tcp_options::parse_options;

fuzz_target!(|data: &[u8]| {
    // Property: parse_options never panics on arbitrary bytes.
    // (Pairs with proptest_tcp_options.rs' decode_never_panics; this target
    // drives libFuzzer's coverage-guided exploration deeper than proptest's
    // 256 random cases.)
    let _ = parse_options(data);
});
