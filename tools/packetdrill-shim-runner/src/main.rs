use std::env;
use std::path::PathBuf;

fn main() {
    let mut args = env::args().skip(1);
    let script = args.next().expect("usage: pdshim-run-one <script.pkt>");
    let shim_binary: PathBuf = env::var("DPDK_NET_SHIM_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/packetdrill-shim/packetdrill")
        });
    let outcome = packetdrill_shim_runner::invoker::run_script(
        &shim_binary, std::path::Path::new(&script));
    println!("exit={}", outcome.exit);
    println!("stdout:\n{}", outcome.stdout);
    if !outcome.stderr.is_empty() { eprintln!("stderr:\n{}", outcome.stderr); }
    std::process::exit(outcome.exit);
}
