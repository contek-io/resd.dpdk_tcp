#![cfg(feature = "test-server")]

use std::path::PathBuf;

#[test]
fn smoke_script_exits_zero() {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    assert!(bin.exists(), "shim binary missing at {}", bin.display());
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/scripts/smoke.pkt");
    let o = packetdrill_shim_runner::invoker::run_script(&bin, &script);
    assert_eq!(o.exit, 0,
        "smoke script failed:\nstdout:\n{}\nstderr:\n{}",
        o.stdout, o.stderr);
}
