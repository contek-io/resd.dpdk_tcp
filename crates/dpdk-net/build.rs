use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Generate into ../../include/dpdk_net.h so both the repo and consumers see it.
    let out = PathBuf::from(&crate_dir).join("../../include/dpdk_net.h");

    let cfg = cbindgen::Config::from_file(PathBuf::from(&crate_dir).join("cbindgen.toml"))
        .expect("read cbindgen.toml");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(cfg)
        .generate()
        .expect("cbindgen generate")
        .write_to_file(&out);

    println!("cargo:rerun-if-changed=src/api.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // A7 Task 8: when built with `--features test-server`, run a second
    // cbindgen pass that emits the test-only FFI surface into
    // `include/dpdk_net_test.h`. The production-header pass above
    // explicitly excludes every `dpdk_net_test_*` symbol so the split is
    // one-way: test symbols appear only in the test header, production
    // symbols appear in both (via `#include "dpdk_net.h"` in the test
    // header's `after_includes`).
    if env::var("CARGO_FEATURE_TEST_SERVER").is_ok() {
        let out_test = PathBuf::from(&crate_dir).join("../../include/dpdk_net_test.h");
        let cfg_test = cbindgen::Config::from_file(
            PathBuf::from(&crate_dir).join("cbindgen-test.toml"),
        )
        .expect("read cbindgen-test.toml");
        cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_config(cfg_test)
            .generate()
            .expect("cbindgen test generate")
            .write_to_file(&out_test);
        println!("cargo:rerun-if-changed=cbindgen-test.toml");
        println!("cargo:rerun-if-changed=src/test_ffi.rs");
    }
}
