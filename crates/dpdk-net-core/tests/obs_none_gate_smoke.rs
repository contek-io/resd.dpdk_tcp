//! Compile-only smoke for obs-none gating — the gates are behind cfg
//! attrs verified by the compile itself; presence of this test exercises
//! the rust-link + test crate can build against the feature.

#[test]
fn obs_none_compiles_in_both_configs() {
    let _ = std::any::type_name::<dpdk_net_core::engine::Engine>();
}
