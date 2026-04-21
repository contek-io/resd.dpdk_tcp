use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../packetdrill-shim/build.sh");
    println!("cargo:rerun-if-changed=../packetdrill-shim/patches");

    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let build_sh = crate_dir.join("../packetdrill-shim/build.sh");
    if !build_sh.exists() {
        panic!("build.sh missing at {}", build_sh.display());
    }

    // Only build when the feature is on; otherwise skip to keep
    // no-default-features fast.
    if env::var("CARGO_FEATURE_TEST_SERVER").is_err() {
        println!("cargo:warning=skipping packetdrill-shim build (feature test-server off)");
        return;
    }

    // TODO(T10): remove DPDK_NET_SHIM_SCAFFOLD_ONLY once patches land.
    let st = Command::new("bash").arg(&build_sh)
        .env("DPDK_NET_SHIM_PROFILE",
             if env::var("DPDK_NET_SHIM_DEBUG").is_ok() { "dev" } else { "release" })
        .env("DPDK_NET_SHIM_SCAFFOLD_ONLY", "1")
        .status().expect("run build.sh");
    assert!(st.success(), "packetdrill-shim build.sh failed");
}
