use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    let lib = pkg_config::Config::new()
        .atleast_version("23.11")
        .probe("libdpdk")
        .expect("libdpdk >= 23.11 must be discoverable via pkg-config");

    // Pass through every cflag pkg-config gives us. DPDK ships `-march=`
    // and `-include rte_config.h` in its Cflags; dropping them makes
    // clang choke on SIMD intrinsic headers.
    let pc_cflags = pkg_config::Config::new()
        .cargo_metadata(false)
        .print_system_libs(false)
        .env_metadata(false)
        .probe("libdpdk")
        .ok()
        .map(|_| std::process::Command::new("pkg-config").args(["--cflags", "libdpdk"]).output().ok())
        .flatten();

    let mut clang_args: Vec<String> = Vec::new();
    if let Some(out) = pc_cflags {
        let s = String::from_utf8_lossy(&out.stdout);
        for tok in s.split_whitespace() {
            clang_args.push(tok.to_string());
        }
    }
    // Add include paths pkg-config surfaced structurally, in case the
    // shell parse above missed anything.
    for p in &lib.include_paths {
        clang_args.push(format!("-I{}", p.display()));
    }
    // DPDK headers use GNU extensions + ISO C11.
    clang_args.push("-D_GNU_SOURCE".into());
    clang_args.push("-std=gnu11".into());
    // libclang loads its own resource directory (the one baked into the
    // library at build time). On machines with multiple clang versions the
    // default resource dir can disagree with the libclang version bindgen
    // actually picks, which makes x86 intrinsic headers fail to parse. If
    // the user (or CI) sets BINDGEN_RESOURCE_DIR, honor that; otherwise
    // auto-detect by matching LIBCLANG_PATH and fall back to probing the
    // installed clang-* binaries.
    if let Some(dir) = detect_clang_resource_dir() {
        clang_args.push(format!("-resource-dir={dir}"));
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(clang_args)
        .allowlist_function("rte_.*")
        .allowlist_type("rte_.*")
        .allowlist_var("RTE_.*")
        // DPDK 23.11 pulls in ARP/L2TPv2/GTP-PSC headers transitively. Those
        // define `#[repr(C, packed)]` structs whose fields are themselves
        // `#[repr(align(N))]` — a combination rustc rejects (E0588) and
        // that also breaks `#[derive(Debug)]`. We don't use any of these
        // protocols in the Stage 1 TCP stack, so treat them as opaque.
        .opaque_type("rte_arp_.*")
        .opaque_type("rte_l2tpv2_.*")
        .opaque_type("rte_gtp_.*")
        .derive_default(true)
        .layout_tests(false) // DPDK has packed/unaligned structs that break layout tests
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed on DPDK headers");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write bindings.rs");

    // Linker args come from pkg-config; cargo will emit -l and -L already.
}

/// Best-effort lookup of a clang resource directory that matches the
/// libclang bindgen will load.
///
/// Order of precedence:
///   1. `BINDGEN_RESOURCE_DIR` env var (explicit override).
///   2. `LIBCLANG_PATH` -> `<dir>/clang/<version>` (matches a typical
///      `/usr/lib/llvm-N/lib` layout).
///   3. Ask a discoverable `clang` binary for `-print-resource-dir`.
fn detect_clang_resource_dir() -> Option<String> {
    if let Ok(dir) = env::var("BINDGEN_RESOURCE_DIR") {
        if !dir.is_empty() {
            println!("cargo:rerun-if-env-changed=BINDGEN_RESOURCE_DIR");
            return Some(dir);
        }
    }
    println!("cargo:rerun-if-env-changed=BINDGEN_RESOURCE_DIR");
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");

    if let Ok(lib_path) = env::var("LIBCLANG_PATH") {
        let p = PathBuf::from(&lib_path).join("clang");
        if let Ok(read) = std::fs::read_dir(&p) {
            for entry in read.flatten() {
                if entry.path().is_dir() {
                    return Some(entry.path().display().to_string());
                }
            }
        }
    }

    // Try newest clang first — bindgen links against whichever libclang
    // clang-sys picks (typically the highest version on the dynamic-loader
    // search path), so we want the matching resource directory.
    for candidate in [
        "clang-22", "clang-21", "clang-20", "clang-19", "clang-18",
        "clang-17", "clang-16", "clang-15", "clang-14", "clang",
    ] {
        if let Ok(out) = std::process::Command::new(candidate)
            .arg("-print-resource-dir")
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !s.is_empty() && PathBuf::from(&s).is_dir() {
                    return Some(s);
                }
            }
        }
    }
    None
}
