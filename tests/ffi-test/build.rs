//! Make the ffi-test binary link exactly like a C consumer does:
//!   - `libdpdk_net.a` from the workspace target dir (the staticlib produced
//!     by the `dpdk-net` crate; its `[dependencies]` entry in Cargo.toml
//!     is what makes Cargo build it before this test compiles).
//!   - DPDK runtime libraries, probed via pkg-config, exactly like
//!     `examples/cpp-consumer/CMakeLists.txt` does.
//!
//! We intentionally do NOT pull `dpdk-net`'s Rust symbols into the test;
//! the goal is to exercise the public C ABI (`extern "C"`), not the
//! Rust-native API.

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // The dpdk-net crate's staticlib lands in the workspace target's deps/
    // dir. During `cargo test`, the top-level target/<profile>/libdpdk_net.a
    // copy is not always refreshed in time, so point the linker at deps/
    // directly (where the canonical output lives).
    let target_dir =
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| format!("{manifest}/../../target"));
    let profile = std::env::var("PROFILE").unwrap();
    println!("cargo:rustc-link-search=native={target_dir}/{profile}/deps");
    println!("cargo:rustc-link-search=native={target_dir}/{profile}");

    // DPDK libs — same probe `dpdk-net-sys/build.rs` uses.
    pkg_config::Config::new()
        .atleast_version("23.11")
        .probe("libdpdk")
        .expect("libdpdk >= 23.11 must be discoverable via pkg-config");

    println!("cargo:rerun-if-changed=build.rs");
}
