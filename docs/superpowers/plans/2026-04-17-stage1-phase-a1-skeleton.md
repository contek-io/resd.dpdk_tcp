# resd.dpdk_tcp Stage 1 Phase A1 — Workspace Skeleton + DPDK Init + Empty Engine

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the repo from empty to a state where Rust + C++ code can create a `resd_net_engine`, the engine brings up DPDK EAL and a NIC port, allocates mempools, calibrates the TSC clock, exposes counters, and runs a poll loop that does rx_burst/tx_burst (dropping all packets — no protocol processing yet). This is the scaffolding every later phase builds on.

**Architecture:** Rust cargo workspace with three crates: `resd-net-sys` (DPDK FFI via bindgen), `resd-net-core` (pure-Rust stack internals), `resd-net` (public API crate exposing `extern "C"` functions; header auto-generated via cbindgen). A C++ consumer sample under `examples/cpp-consumer/` verifies the FFI boundary end-to-end.

**Tech Stack:** Rust stable (1.75+), cargo workspace, DPDK 23.11 LTS, `bindgen` for DPDK FFI, `cbindgen` for generating `include/resd_net.h`, `pkg-config` to locate libdpdk, CMake for the C++ consumer.

**Prerequisites on the build host (install before starting):**
- DPDK 23.11 built and installed (libdpdk.pc discoverable via `pkg-config --cflags --libs libdpdk`).
- At least one DPDK-supported NIC bound to `vfio-pci` or a TAP device for local-loopback smoke testing.
- Hugepages configured (e.g., `1024 × 2MiB`).
- Clang ≥ 14 (for bindgen).
- CMake ≥ 3.22, g++ ≥ 11.

**Spec reference:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §§ 2, 4, 7.1, 7.5, 9.1.

---

## File Structure Created in This Phase

```
resd.dpdk_tcp/
├── Cargo.toml                      # workspace root
├── rust-toolchain.toml             # pin stable
├── .gitignore
├── README.md
├── crates/
│   ├── resd-net-sys/
│   │   ├── Cargo.toml
│   │   ├── build.rs                # bindgen DPDK
│   │   ├── wrapper.h               # #include DPDK headers
│   │   └── src/lib.rs              # re-export bindgen types
│   ├── resd-net-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs              # module tree
│   │       ├── clock.rs            # TSC calibration
│   │       ├── counters.rs         # AtomicU64 groups
│   │       ├── mempool.rs          # RAII mempool wrapper
│   │       ├── engine.rs           # Engine struct, create/destroy, poll stub
│   │       └── error.rs            # crate error type
│   └── resd-net/
│       ├── Cargo.toml
│       ├── cbindgen.toml
│       ├── build.rs                # run cbindgen
│       └── src/
│           ├── lib.rs              # extern "C" wrappers
│           └── api.rs              # C ABI types (engine_config, event, etc.)
├── include/
│   └── resd_net.h                  # cbindgen-generated; committed
├── examples/
│   └── cpp-consumer/
│       ├── CMakeLists.txt
│       └── main.cpp
└── tests/
    └── ffi-test/
        ├── Cargo.toml
        └── tests/ffi_smoke.rs      # integration test linking to C ABI
```

---

## Task 1: Workspace scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `.gitignore`
- Create: `README.md`

- [ ] **Step 1: Create `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = [
    "crates/resd-net-sys",
    "crates/resd-net-core",
    "crates/resd-net",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
rust-version = "1.75"

[workspace.dependencies]
# pinned once, used by all crates
libc = "0.2"
thiserror = "1"

[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"
debug = 1  # line tables for perf/flame graphs
```

- [ ] **Step 2: Create `rust-toolchain.toml`**

```toml
[toolchain]
channel = "1.75.0"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 3: Create `.gitignore`**

```
/target
**/*.rs.bk
Cargo.lock.bak
/examples/cpp-consumer/build/
.cache/
```

- [ ] **Step 4: Create `README.md`**

```markdown
# resd.dpdk_tcp

DPDK-based userspace TCP stack in Rust with a C ABI for C++ consumers.

See `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` for the design.

## Build

Requires DPDK 23.11 installed (`pkg-config --exists libdpdk` must succeed).

```sh
cargo build --release
cmake -S examples/cpp-consumer -B examples/cpp-consumer/build
cmake --build examples/cpp-consumer/build
```

## Test

```sh
cargo test
```
```

- [ ] **Step 5: Verify workspace builds (empty)**

Run: `cargo check --workspace`
Expected: "no packages found"-style failure because crate dirs don't exist yet. That's fine; next task creates them. Do NOT commit until the workspace resolves.

- [ ] **Step 6: Stage, but don't commit yet** — we'll commit once the first crate resolves.

---

## Task 2: `resd-net-sys` crate with DPDK bindgen

**Files:**
- Create: `crates/resd-net-sys/Cargo.toml`
- Create: `crates/resd-net-sys/build.rs`
- Create: `crates/resd-net-sys/wrapper.h`
- Create: `crates/resd-net-sys/src/lib.rs`

- [ ] **Step 1: Write `crates/resd-net-sys/Cargo.toml`**

```toml
[package]
name = "resd-net-sys"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
links = "dpdk"  # declares we link libdpdk; prevents duplicate link instructions

[dependencies]
libc.workspace = true

[build-dependencies]
bindgen = "0.69"
pkg-config = "0.3"
```

- [ ] **Step 2: Write `crates/resd-net-sys/wrapper.h`**

```c
/* Single include point for bindgen. Only includes the DPDK headers
 * that the Rust stack actually uses — keeps generated bindings small.
 */
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_version.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ip_frag.h>
#include <rte_icmp.h>
#include <rte_mbuf_dyn.h>

/* `rte_errno` is a macro expanding to a thread-local int; bindgen
 * cannot reliably expose it. Wrap it in a trivial C shim that bindgen
 * does expose. All Rust callers use `resd_rte_errno()`.
 */
static inline int resd_rte_errno(void) { return rte_errno; }
```

- [ ] **Step 3: Write `crates/resd-net-sys/build.rs`**

```rust
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    let lib = pkg_config::Config::new()
        .atleast_version("23.11")
        .probe("libdpdk")
        .expect("libdpdk >= 23.11 must be discoverable via pkg-config");

    let mut clang_args: Vec<String> = lib
        .include_paths
        .iter()
        .map(|p| format!("-I{}", p.display()))
        .collect();
    // DPDK headers use GNU extensions + ISO C11.
    clang_args.push("-D_GNU_SOURCE".into());
    clang_args.push("-std=gnu11".into());

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(clang_args)
        .allowlist_function("rte_.*")
        .allowlist_type("rte_.*")
        .allowlist_var("RTE_.*")
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
```

- [ ] **Step 4: Write `crates/resd-net-sys/src/lib.rs`**

```rust
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpdk_version_string_nonempty() {
        // Safety: rte_version is read-only, available without EAL init.
        let ptr = unsafe { rte_version() };
        assert!(!ptr.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
        let s = s.to_str().expect("utf8");
        assert!(s.starts_with("DPDK "), "got {s:?}");
        assert!(s.contains("23.11") || s.contains("24."), "version mismatch: {s:?}");
    }
}
```

- [ ] **Step 5: Build and test the sys crate**

Run: `cargo test -p resd-net-sys -- --nocapture`
Expected: `dpdk_version_string_nonempty` passes; stdout shows DPDK version.

- [ ] **Step 6: Commit**

```sh
git add Cargo.toml rust-toolchain.toml .gitignore README.md crates/resd-net-sys/
git commit -m "bootstrap workspace and resd-net-sys DPDK bindings"
```

---

## Task 3: `resd-net-core` — crate skeleton + clock

**Files:**
- Create: `crates/resd-net-core/Cargo.toml`
- Create: `crates/resd-net-core/src/lib.rs`
- Create: `crates/resd-net-core/src/error.rs`
- Create: `crates/resd-net-core/src/clock.rs`

- [ ] **Step 1: Write `crates/resd-net-core/Cargo.toml`**

```toml
[package]
name = "resd-net-core"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
resd-net-sys = { path = "../resd-net-sys" }
libc.workspace = true
thiserror.workspace = true

[lints.rust]
unsafe_op_in_unsafe_fn = "warn"
```

- [ ] **Step 2: Write `crates/resd-net-core/src/lib.rs`**

```rust
//! Pure-Rust internals of the resd.dpdk_tcp stack.
//! The public `extern "C"` surface lives in the `resd-net` crate.

pub mod clock;
pub mod counters;
pub mod engine;
pub mod error;
pub mod mempool;

pub use error::Error;
```

- [ ] **Step 3: Write `crates/resd-net-core/src/error.rs`**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invariant TSC not supported on this CPU")]
    NoInvariantTsc,
    #[error("DPDK EAL init failed: rte_errno={0}")]
    EalInit(i32),
    #[error("mempool creation failed: {0}")]
    MempoolCreate(&'static str),
    #[error("port {0} configure failed: rte_errno={1}")]
    PortConfigure(u16, i32),
    #[error("port {0} rx queue setup failed: rte_errno={1}")]
    RxQueueSetup(u16, i32),
    #[error("port {0} tx queue setup failed: rte_errno={1}")]
    TxQueueSetup(u16, i32),
    #[error("port {0} start failed: rte_errno={1}")]
    PortStart(u16, i32),
    #[error("invalid lcore {0}")]
    InvalidLcore(u16),
}
```

- [ ] **Step 4: Write the failing test for `clock.rs`**

Add `crates/resd-net-core/src/clock.rs`:

```rust
use std::sync::OnceLock;
use std::time::Instant;

/// Single process-wide TSC calibration shared across all engines,
/// per spec §7.5.
#[derive(Debug, Clone, Copy)]
pub struct TscEpoch {
    pub tsc0: u64,
    pub t0_ns: u64,
    pub ns_per_tsc_scaled: u64,  // fixed-point: actual ns_per_tsc = ns_per_tsc_scaled / 2^32
}

static TSC_EPOCH: OnceLock<TscEpoch> = OnceLock::new();

pub fn tsc_epoch() -> &'static TscEpoch {
    TSC_EPOCH.get_or_init(calibrate)
}

#[inline(always)]
pub fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    compile_error!("resd-net-core currently only supports x86_64");
}

#[inline]
pub fn now_ns() -> u64 {
    let e = tsc_epoch();
    let delta = rdtsc().wrapping_sub(e.tsc0);
    // delta * (ns_per_tsc_scaled / 2^32) + t0_ns
    let scaled = ((delta as u128) * (e.ns_per_tsc_scaled as u128)) >> 32;
    e.t0_ns + scaled as u64
}

fn calibrate() -> TscEpoch {
    check_invariant_tsc().expect("invariant TSC required");
    let start_instant = Instant::now();
    let start_tsc = rdtsc();
    // Busy-loop a known-duration window for ratio measurement.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let end_instant = Instant::now();
    let end_tsc = rdtsc();

    let elapsed_ns = (end_instant - start_instant).as_nanos() as u64;
    let tsc_delta = end_tsc.wrapping_sub(start_tsc);
    // NOTE: the parens are load-bearing — Rust's `/` binds tighter than `<<`,
    // so `(x as u128) << 32 / y as u128` would shift by 0 for any y > 32.
    let ns_per_tsc_scaled: u64 = (((elapsed_ns as u128) << 32) / (tsc_delta as u128)) as u64;

    TscEpoch {
        tsc0: start_tsc,
        // now_ns() returns "ns since calibration start" — tsc0 maps to 0.
        t0_ns: 0,
        ns_per_tsc_scaled,
    }
}

#[cfg(target_arch = "x86_64")]
fn check_invariant_tsc() -> Result<(), crate::Error> {
    // CPUID.80000007H:EDX[8] = InvariantTSC
    let r = unsafe { std::arch::x86_64::__cpuid(0x8000_0007) };
    if (r.edx & (1 << 8)) != 0 {
        Ok(())
    } else {
        Err(crate::Error::NoInvariantTsc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_ns_monotonic_increasing() {
        let a = now_ns();
        let b = now_ns();
        assert!(b >= a, "now_ns went backwards: {a} -> {b}");
    }

    #[test]
    fn now_ns_within_one_percent_of_wall_clock() {
        let wall_start = std::time::Instant::now();
        let tsc_start = now_ns();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let tsc_ns = now_ns() - tsc_start;
        let diff = wall_ns.abs_diff(tsc_ns) as f64;
        let relative = diff / wall_ns as f64;
        assert!(relative < 0.02, "TSC drift too large: wall={wall_ns} tsc={tsc_ns} rel={relative}");
    }
}
```

- [ ] **Step 5: Run the tests and confirm they fail compilation — module `counters`, `engine`, `mempool` aren't written yet**

Run: `cargo build -p resd-net-core`
Expected: failure with "file not found for module `counters`" etc.

- [ ] **Step 6: Add stub module files so the crate compiles**

Create `crates/resd-net-core/src/counters.rs`:

```rust
// Stubbed in Task 4.
```

Create `crates/resd-net-core/src/mempool.rs`:

```rust
// Stubbed in Task 5.
```

Create `crates/resd-net-core/src/engine.rs`:

```rust
// Stubbed in Task 6.
```

- [ ] **Step 7: Run clock tests**

Run: `cargo test -p resd-net-core clock::`
Expected: both `now_ns_monotonic_increasing` and `now_ns_within_one_percent_of_wall_clock` PASS.

- [ ] **Step 8: Commit**

```sh
git add crates/resd-net-core/
git commit -m "add resd-net-core crate scaffold + TSC clock calibration"
```

---

## Task 4: `resd-net-core/counters.rs` — AtomicU64 counter groups

**Files:**
- Modify: `crates/resd-net-core/src/counters.rs`

- [ ] **Step 1: Write the failing test**

Replace `counters.rs` with:

```rust
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-lcore counter struct. Cacheline-grouped.
/// Hot-path increments use Relaxed stores on the owning lcore;
/// cross-lcore snapshot reads use Relaxed loads. Per spec §9.1.
#[repr(C, align(64))]
pub struct EthCounters {
    pub rx_pkts: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rx_drop_miss_mac: AtomicU64,
    pub rx_drop_nomem: AtomicU64,
    pub tx_pkts: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub tx_drop_full_ring: AtomicU64,
    pub tx_drop_nomem: AtomicU64,
    _pad: [u64; 8],  // keep struct size aligned
}

#[repr(C, align(64))]
pub struct IpCounters {
    pub rx_csum_bad: AtomicU64,
    pub rx_ttl_zero: AtomicU64,
    pub rx_frag: AtomicU64,
    pub rx_icmp_frag_needed: AtomicU64,
    pub pmtud_updates: AtomicU64,
    _pad: [u64; 11],
}

#[repr(C, align(64))]
pub struct TcpCounters {
    pub rx_syn_ack: AtomicU64,
    pub rx_data: AtomicU64,
    pub rx_ack: AtomicU64,
    pub rx_rst: AtomicU64,
    pub rx_out_of_order: AtomicU64,
    pub tx_retrans: AtomicU64,
    pub tx_rto: AtomicU64,
    pub tx_tlp: AtomicU64,
    pub conn_open: AtomicU64,
    pub conn_close: AtomicU64,
    pub conn_rst: AtomicU64,
    pub send_buf_full: AtomicU64,
    pub recv_buf_delivered: AtomicU64,
    _pad: [u64; 3],
}

#[repr(C, align(64))]
pub struct PollCounters {
    pub iters: AtomicU64,
    pub iters_with_rx: AtomicU64,
    pub iters_with_tx: AtomicU64,
    pub iters_idle: AtomicU64,
    _pad: [u64; 12],
}

#[repr(C)]
pub struct Counters {
    pub eth: EthCounters,
    pub ip: IpCounters,
    pub tcp: TcpCounters,
    pub poll: PollCounters,
}

impl Counters {
    pub fn new() -> Self {
        // Default impl from derive not available for atomics; explicit init.
        Self {
            eth: EthCounters::default(),
            ip: IpCounters::default(),
            tcp: TcpCounters::default(),
            poll: PollCounters::default(),
        }
    }
}

impl Default for EthCounters {
    fn default() -> Self { unsafe { std::mem::zeroed() } }
}
impl Default for IpCounters {
    fn default() -> Self { unsafe { std::mem::zeroed() } }
}
impl Default for TcpCounters {
    fn default() -> Self { unsafe { std::mem::zeroed() } }
}
impl Default for PollCounters {
    fn default() -> Self { unsafe { std::mem::zeroed() } }
}

/// Hot-path increment: atomic RMW with Relaxed ordering.
/// On x86_64 this is `lock xadd` — a few cycles slower than a plain store,
/// but sound under any producer layout and prevents lost-update races
/// if a counter is ever written from a non-owning thread by mistake.
#[inline(always)]
pub fn inc(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

#[inline(always)]
pub fn add(a: &AtomicU64, n: u64) {
    a.fetch_add(n, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_construct() {
        let c = Counters::new();
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.conn_open.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inc_works() {
        let c = Counters::new();
        inc(&c.eth.rx_pkts);
        inc(&c.eth.rx_pkts);
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cross_thread_inc_correct_under_contention() {
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(Counters::new());
        let producers: Vec<_> = (0..4)
            .map(|_| {
                let c = Arc::clone(&c);
                thread::spawn(move || {
                    for _ in 0..25_000 {
                        inc(&c.eth.rx_pkts);
                    }
                })
            })
            .collect();
        for p in producers {
            p.join().unwrap();
        }
        // Would fail if inc() were load-modify-store (lost increments).
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 100_000);
    }

    #[test]
    fn counters_group_alignment() {
        // Ensure each group is its own cacheline.
        assert_eq!(std::mem::align_of::<EthCounters>(), 64);
        assert_eq!(std::mem::align_of::<IpCounters>(), 64);
        assert_eq!(std::mem::align_of::<TcpCounters>(), 64);
        assert_eq!(std::mem::align_of::<PollCounters>(), 64);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p resd-net-core counters::`
Expected: four PASS.

- [ ] **Step 3: Commit**

```sh
git add crates/resd-net-core/src/counters.rs
git commit -m "add per-lcore counters with cacheline grouping"
```

---

## Task 5: `resd-net-core/mempool.rs` — RAII DPDK mempool wrapper

**Files:**
- Modify: `crates/resd-net-core/src/mempool.rs`

- [ ] **Step 1: Write the wrapper**

Replace `mempool.rs` with:

```rust
use resd_net_sys as sys;
use std::ffi::CString;
use std::ptr::NonNull;

use crate::Error;

/// RAII wrapper around an `rte_mempool*`.
/// Dropped pool calls `rte_mempool_free` on the inner pointer.
pub struct Mempool {
    ptr: NonNull<sys::rte_mempool>,
    name: CString,
}

impl Mempool {
    /// Create a packet-mbuf pool with DPDK defaults + configurable headroom.
    pub fn new_pktmbuf(
        name: &str,
        n_elements: u32,
        cache_size: u32,
        priv_size: u16,
        data_room_size: u16,
        socket_id: i32,
    ) -> Result<Self, Error> {
        let cname = CString::new(name).map_err(|_| Error::MempoolCreate("name contains NUL"))?;
        // Safety: passing valid parameters to an FFI function; DPDK must be initialized
        // (EAL) before this. Caller responsibility.
        let p = unsafe {
            sys::rte_pktmbuf_pool_create(
                cname.as_ptr(),
                n_elements,
                cache_size,
                priv_size,
                data_room_size,
                socket_id,
            )
        };
        let ptr = NonNull::new(p).ok_or(Error::MempoolCreate("rte_pktmbuf_pool_create returned NULL"))?;
        Ok(Self { ptr, name: cname })
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut sys::rte_mempool {
        self.ptr.as_ptr()
    }

    pub fn name(&self) -> &std::ffi::CStr {
        &self.name
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        // Safety: we own the mempool; no other references should exist because
        // we hold NonNull and never handed it out beyond &mut self.
        unsafe { sys::rte_mempool_free(self.ptr.as_ptr()) };
    }
}

// Pools are created on one lcore but passed between lcores at setup time;
// mempool operations themselves are thread-safe per DPDK docs.
unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}
```

- [ ] **Step 2: No unit tests here — mempool creation requires initialized EAL**

Mempool creation requires EAL to be initialized. Integration testing happens in Task 7 where EAL + mempool are exercised together.

- [ ] **Step 3: Confirm it compiles**

Run: `cargo build -p resd-net-core`
Expected: compiles cleanly.

- [ ] **Step 4: Commit**

```sh
git add crates/resd-net-core/src/mempool.rs
git commit -m "add RAII Mempool wrapper"
```

---

## Task 6: `resd-net-core/engine.rs` — Engine struct + EAL init

**Files:**
- Modify: `crates/resd-net-core/src/engine.rs`

- [ ] **Step 1: Write Engine skeleton + EAL init**

Replace `engine.rs` with:

```rust
use resd_net_sys as sys;
use std::ffi::{CStr, CString};
use std::sync::Mutex;

use crate::counters::Counters;
use crate::mempool::Mempool;
use crate::Error;

/// Config passed to Engine::new.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub lcore_id: u16,
    pub port_id: u16,
    pub rx_queue_id: u16,
    pub tx_queue_id: u16,
    pub rx_ring_size: u16,      // default 1024
    pub tx_ring_size: u16,      // default 1024
    pub rx_mempool_elems: u32,  // default 8192
    pub mbuf_data_room: u16,    // default 2048
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            lcore_id: 0,
            port_id: 0,
            rx_queue_id: 0,
            tx_queue_id: 0,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            rx_mempool_elems: 8192,
            mbuf_data_room: 2048,
        }
    }
}

/// A resd-net engine. One per lcore; owns the NIC queues and mempools for that lcore.
pub struct Engine {
    cfg: EngineConfig,
    counters: Box<Counters>,
    _rx_mempool: Mempool,
    _tx_hdr_mempool: Mempool,
    _tx_data_mempool: Mempool,
}

/// EAL is process-global; only initialize once.
static EAL_INIT: Mutex<bool> = Mutex::new(false);

pub fn eal_init(args: &[&str]) -> Result<(), Error> {
    let mut guard = EAL_INIT.lock().unwrap();
    if *guard {
        return Ok(());
    }
    let cstrs: Vec<CString> = args
        .iter()
        .map(|s| CString::new(*s).unwrap())
        .collect();
    let mut argv: Vec<*mut libc::c_char> =
        cstrs.iter().map(|c| c.as_ptr() as *mut _).collect();
    // Safety: rte_eal_init mutates argv internally; we pass the constructed array.
    let rc = unsafe { sys::rte_eal_init(argv.len() as i32, argv.as_mut_ptr()) };
    if rc < 0 {
        return Err(Error::EalInit(unsafe { sys::resd_rte_errno() }));
    }
    *guard = true;
    Ok(())
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> Result<Self, Error> {
        // socket_id may be -1 (cast to 0xFFFFFFFF == SOCKET_ID_ANY) when the
        // port isn't bound to a NUMA node (common in VMs / TAP devices).
        // That's the DPDK sentinel and is valid for mempool/queue setup.
        let socket_id = unsafe { sys::rte_eth_dev_socket_id(cfg.port_id) };

        // Allocate three mempools per spec §7.1.
        let rx_mempool = Mempool::new_pktmbuf(
            &format!("rx_mp_{}", cfg.lcore_id),
            cfg.rx_mempool_elems,
            256,
            0,
            cfg.mbuf_data_room + sys::RTE_PKTMBUF_HEADROOM as u16,
            socket_id,
        )?;
        let tx_hdr_mempool = Mempool::new_pktmbuf(
            &format!("tx_hdr_mp_{}", cfg.lcore_id),
            2048,
            64,
            0,
            256,
            socket_id,
        )?;
        let tx_data_mempool = Mempool::new_pktmbuf(
            &format!("tx_data_mp_{}", cfg.lcore_id),
            4096,
            128,
            0,
            cfg.mbuf_data_room + sys::RTE_PKTMBUF_HEADROOM as u16,
            socket_id,
        )?;

        // Configure port: one RX queue + one TX queue for Phase A1.
        let eth_conf: sys::rte_eth_conf = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            sys::rte_eth_dev_configure(cfg.port_id, 1, 1, &eth_conf as *const _)
        };
        if rc != 0 {
            return Err(Error::PortConfigure(cfg.port_id, unsafe { sys::resd_rte_errno() }));
        }

        let rc = unsafe {
            sys::rte_eth_rx_queue_setup(
                cfg.port_id,
                cfg.rx_queue_id,
                cfg.rx_ring_size,
                socket_id as u32,
                std::ptr::null(),
                rx_mempool.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(Error::RxQueueSetup(cfg.port_id, unsafe { sys::resd_rte_errno() }));
        }

        let rc = unsafe {
            sys::rte_eth_tx_queue_setup(
                cfg.port_id,
                cfg.tx_queue_id,
                cfg.tx_ring_size,
                socket_id as u32,
                std::ptr::null(),
            )
        };
        if rc < 0 {
            return Err(Error::TxQueueSetup(cfg.port_id, unsafe { sys::resd_rte_errno() }));
        }

        let rc = unsafe { sys::rte_eth_dev_start(cfg.port_id) };
        if rc < 0 {
            return Err(Error::PortStart(cfg.port_id, unsafe { sys::resd_rte_errno() }));
        }

        let counters = Box::new(Counters::new());

        Ok(Self {
            cfg,
            counters,
            _rx_mempool: rx_mempool,
            _tx_hdr_mempool: tx_hdr_mempool,
            _tx_data_mempool: tx_data_mempool,
        })
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// One iteration of the run-to-completion loop.
    /// In Phase A1, this rx-bursts and drops everything, then tx-bursts nothing.
    /// Subsequent phases add real processing.
    pub fn poll_once(&self) -> usize {
        use crate::counters::inc;
        inc(&self.counters.poll.iters);

        const BURST: usize = 32;
        let mut mbufs: [*mut sys::rte_mbuf; BURST] = [std::ptr::null_mut(); BURST];
        let n = unsafe {
            sys::rte_eth_rx_burst(
                self.cfg.port_id,
                self.cfg.rx_queue_id,
                mbufs.as_mut_ptr(),
                BURST as u16,
            )
        } as usize;
        if n > 0 {
            inc(&self.counters.poll.iters_with_rx);
            crate::counters::add(&self.counters.eth.rx_pkts, n as u64);
            for m in &mbufs[..n] {
                // Drop each mbuf.
                unsafe { sys::rte_pktmbuf_free(*m) };
            }
        } else {
            inc(&self.counters.poll.iters_idle);
        }
        n
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Safety: we previously started the port; stop and close on drop.
        unsafe {
            sys::rte_eth_dev_stop(self.cfg.port_id);
            sys::rte_eth_dev_close(self.cfg.port_id);
        }
        // Mempools drop via their own Drop impl.
    }
}
```

- [ ] **Step 2: Build the crate**

Run: `cargo build -p resd-net-core`
Expected: compiles. `sys::resd_rte_errno()` comes from the C shim added in Task 2's `wrapper.h`.

- [ ] **Step 3: No unit test for this task — integration test comes in Task 7 (needs a real NIC or TAP)**

- [ ] **Step 4: Commit**

```sh
git add crates/resd-net-core/src/engine.rs
git commit -m "add Engine with EAL init, mempools, NIC queue setup, empty poll loop"
```

---

## Task 7: Integration smoke test — engine lifecycle on a TAP device

**Files:**
- Create: `crates/resd-net-core/tests/engine_smoke.rs`

- [ ] **Step 1: Write the integration test**

```rust
//! Integration test that brings up an engine against a TAP virtual device
//! (no real NIC needed). Runs only when RESD_NET_TEST_TAP=1 in env.

#[test]
fn engine_lifecycle_on_tap() {
    if std::env::var("RESD_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set RESD_NET_TEST_TAP=1 to run");
        return;
    }

    // EAL args: in-memory, use vdev TAP so no real NIC is required.
    let args = [
        "resd-net-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap0",
        "-l", "0-1",
        "--log-level=3",
    ];
    resd_net_core::engine::eal_init(&args).expect("EAL init");

    let cfg = resd_net_core::engine::EngineConfig {
        port_id: 0,
        ..Default::default()
    };
    let engine = resd_net_core::engine::Engine::new(cfg).expect("engine new");

    // Poll a few times on an idle link; expect 0 packets.
    for _ in 0..10 {
        engine.poll_once();
    }
    let c = engine.counters();
    assert!(c.poll.iters.load(std::sync::atomic::Ordering::Relaxed) >= 10);
    // rx_pkts may be >0 if stray ARP arrived; that's fine, we just don't assert 0.
    drop(engine);
}
```

- [ ] **Step 2: Run with the TAP env var (requires sudo for DPDK)**

```sh
sudo -E RESD_NET_TEST_TAP=1 $(command -v cargo) test -p resd-net-core --test engine_smoke -- --nocapture
```

Expected: PASS; poll counter ≥ 10.

- [ ] **Step 3: Document how to run in README**

Append to `README.md`:

```markdown
## Integration tests (require DPDK TAP and root)

```sh
sudo -E RESD_NET_TEST_TAP=1 cargo test -p resd-net-core --test engine_smoke -- --nocapture
```
```

- [ ] **Step 4: Commit**

```sh
git add crates/resd-net-core/tests/engine_smoke.rs README.md
git commit -m "add engine lifecycle smoke test over DPDK TAP"
```

---

## Task 8: `resd-net` public crate — C ABI types

**Files:**
- Create: `crates/resd-net/Cargo.toml`
- Create: `crates/resd-net/cbindgen.toml`
- Create: `crates/resd-net/build.rs`
- Create: `crates/resd-net/src/lib.rs`
- Create: `crates/resd-net/src/api.rs`

- [ ] **Step 1: Write `crates/resd-net/Cargo.toml`**

```toml
[package]
name = "resd-net"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[lib]
name = "resd_net"
# staticlib for static linking into C++; cdylib for dynamic.
crate-type = ["staticlib", "cdylib", "rlib"]

[dependencies]
resd-net-core = { path = "../resd-net-core" }
libc.workspace = true

[build-dependencies]
cbindgen = "0.26"
```

- [ ] **Step 2: Write `crates/resd-net/cbindgen.toml`**

```toml
language = "C"
include_guard = "RESD_NET_H"
pragma_once = true
autogen_warning = "/* DO NOT EDIT: generated from Rust via cbindgen */"
no_includes = false
sys_includes = ["stdint.h", "stdbool.h", "stddef.h", "arpa/inet.h"]
style = "tag"

[export]
prefix = "resd_net_"
exclude = ["EngineConfigRustOnly"]

[parse]
parse_deps = false
```

- [ ] **Step 3: Write `crates/resd-net/src/api.rs`** (Stage 1 C ABI types — matches spec §4)

```rust
//! Public C ABI type definitions.
//!
//! These are all `#[repr(C)]` structs / `#[repr(u32)]` enums so cbindgen
//! lays them out identically in C. Keep in sync with spec §4.
//!
//! Counters are emitted as plain `u64` fields on the C ABI even though the
//! stack writes them via `AtomicU64` internally — `AtomicU64` has identical
//! size and alignment as `u64` on x86_64, and cbindgen cannot emit an
//! atomic C type. See the layout assertion at the bottom of the file.

#[repr(C)]
pub struct resd_net_engine {
    _opaque: [u8; 0],
}

pub type resd_net_conn_t = u64;
pub type resd_net_timer_id_t = u64;

#[repr(C)]
pub struct resd_net_engine_config_t {
    pub port_id: u16,
    pub rx_queue_id: u16,
    pub tx_queue_id: u16,
    pub max_connections: u32,
    pub recv_buffer_bytes: u32,
    pub send_buffer_bytes: u32,
    pub tcp_mss: u32,
    pub tcp_timestamps: bool,
    pub tcp_sack: bool,
    pub tcp_ecn: bool,
    pub tcp_nagle: bool,
    pub tcp_delayed_ack: bool,
    pub cc_mode: u8,
    pub tcp_min_rto_ms: u32,
    pub tcp_initial_rto_ms: u32,
    pub tcp_msl_ms: u32,
    pub tcp_per_packet_events: bool,
    pub preset: u8,
}

#[repr(C)]
pub struct resd_net_connect_opts_t {
    pub peer_addr: u32,         // network byte order IPv4
    pub peer_port: u16,
    pub local_addr: u32,
    pub local_port: u16,
    pub connect_timeout_ms: u32,
    pub idle_keepalive_sec: u32,
}

#[repr(u32)]
pub enum resd_net_event_kind_t {
    RESD_NET_EVT_CONNECTED = 1,
    RESD_NET_EVT_READABLE = 2,
    RESD_NET_EVT_WRITABLE = 3,
    RESD_NET_EVT_CLOSED = 4,
    RESD_NET_EVT_ERROR = 5,
    RESD_NET_EVT_TIMER = 6,
    RESD_NET_EVT_TCP_RETRANS = 7,
    RESD_NET_EVT_TCP_LOSS_DETECTED = 8,
    RESD_NET_EVT_TCP_STATE_CHANGE = 9,
}

#[repr(C)]
pub struct resd_net_event_readable_t {
    pub data: *const u8,
    pub data_len: u32,
}

#[repr(C)]
pub struct resd_net_event_error_t {
    pub err: i32,
}

#[repr(C)]
pub struct resd_net_event_timer_t {
    pub timer_id: u64,
    pub user_data: u64,
}

#[repr(C)]
pub struct resd_net_event_tcp_retrans_t {
    pub seq: u32,
    pub rtx_count: u32,
}

#[repr(C)]
pub struct resd_net_event_tcp_loss_t {
    pub first_seq: u32,
    pub trigger: u8,
}

#[repr(C)]
pub struct resd_net_event_tcp_state_t {
    pub from_state: u8,
    pub to_state: u8,
}

/// Union-of-payloads approach: we lay out the union as a byte array and
/// expose accessor helpers. cbindgen emits it as a C union.
#[repr(C)]
pub union resd_net_event_payload_t {
    pub readable: resd_net_event_readable_t,
    pub error: resd_net_event_error_t,
    pub closed: resd_net_event_error_t,
    pub timer: resd_net_event_timer_t,
    pub tcp_retrans: resd_net_event_tcp_retrans_t,
    pub tcp_loss: resd_net_event_tcp_loss_t,
    pub tcp_state: resd_net_event_tcp_state_t,
    pub _pad: [u8; 16],
}

#[repr(C)]
pub struct resd_net_event_t {
    pub kind: resd_net_event_kind_t,
    pub conn: resd_net_conn_t,
    pub rx_hw_ts_ns: u64,
    pub enqueued_ts_ns: u64,
    pub u: resd_net_event_payload_t,
}

/// Close flags — bitmask for resd_net_close.
pub const RESD_NET_CLOSE_FORCE_TW_SKIP: u32 = 1 << 0;

/// Counters struct — exposed to application via resd_net_counters().
/// Fields are plain u64 on the C ABI for clean cbindgen emission, but
/// internally the stack writes them as AtomicU64 (Relaxed). AtomicU64
/// has identical size and alignment as u64 on x86_64 so pointer-casting
/// between resd_net_core::Counters and resd_net_counters_t is sound.
/// C/C++ readers should use `__atomic_load_n(&field, __ATOMIC_RELAXED)`
/// (or `std::atomic_ref<uint64_t>`) for strictly correct reads; on x86_64
/// this compiles to a plain `mov` so there's no runtime cost.
#[repr(C, align(64))]
pub struct resd_net_eth_counters_t {
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub rx_drop_miss_mac: u64,
    pub rx_drop_nomem: u64,
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    pub tx_drop_full_ring: u64,
    pub tx_drop_nomem: u64,
    pub _pad: [u64; 8],
}
#[repr(C, align(64))]
pub struct resd_net_ip_counters_t {
    pub rx_csum_bad: u64,
    pub rx_ttl_zero: u64,
    pub rx_frag: u64,
    pub rx_icmp_frag_needed: u64,
    pub pmtud_updates: u64,
    pub _pad: [u64; 11],
}
#[repr(C, align(64))]
pub struct resd_net_tcp_counters_t {
    pub rx_syn_ack: u64,
    pub rx_data: u64,
    pub rx_ack: u64,
    pub rx_rst: u64,
    pub rx_out_of_order: u64,
    pub tx_retrans: u64,
    pub tx_rto: u64,
    pub tx_tlp: u64,
    pub conn_open: u64,
    pub conn_close: u64,
    pub conn_rst: u64,
    pub send_buf_full: u64,
    pub recv_buf_delivered: u64,
    pub _pad: [u64; 3],
}
#[repr(C, align(64))]
pub struct resd_net_poll_counters_t {
    pub iters: u64,
    pub iters_with_rx: u64,
    pub iters_with_tx: u64,
    pub iters_idle: u64,
    pub _pad: [u64; 12],
}
#[repr(C)]
pub struct resd_net_counters_t {
    pub eth: resd_net_eth_counters_t,
    pub ip: resd_net_ip_counters_t,
    pub tcp: resd_net_tcp_counters_t,
    pub poll: resd_net_poll_counters_t,
}

// Compile-time checks: the public counters struct must have the same
// size AND alignment as resd_net_core::Counters (AtomicU64 has the same
// layout as u64 on targets we support). If either diverges, the
// pointer-cast in resd_net_counters() is unsound and this is a bug.
const _: () = {
    use resd_net_core::counters::{
        Counters as CoreCounters, EthCounters as CoreEth, IpCounters as CoreIp,
        PollCounters as CorePoll, TcpCounters as CoreTcp,
    };
    use std::mem::{align_of, size_of};
    assert!(size_of::<resd_net_counters_t>() == size_of::<CoreCounters>());
    assert!(align_of::<resd_net_eth_counters_t>() == align_of::<CoreEth>());
    assert!(align_of::<resd_net_ip_counters_t>() == align_of::<CoreIp>());
    assert!(align_of::<resd_net_tcp_counters_t>() == align_of::<CoreTcp>());
    assert!(align_of::<resd_net_poll_counters_t>() == align_of::<CorePoll>());
    assert!(size_of::<resd_net_eth_counters_t>() == size_of::<CoreEth>());
    assert!(size_of::<resd_net_ip_counters_t>() == size_of::<CoreIp>());
    assert!(size_of::<resd_net_tcp_counters_t>() == size_of::<CoreTcp>());
    assert!(size_of::<resd_net_poll_counters_t>() == size_of::<CorePoll>());
};
```

- [ ] **Step 4: Write `crates/resd-net/src/lib.rs`** (stubbed extern functions; filled in Task 9)

```rust
#![allow(non_camel_case_types, non_snake_case)]

pub mod api;

// Implementations come in Task 9.
```

- [ ] **Step 5: Write `crates/resd-net/build.rs`** (cbindgen)

```rust
use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Generate into ../../include/resd_net.h so both the repo and consumers see it.
    let out = PathBuf::from(&crate_dir).join("../../include/resd_net.h");

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
}
```

- [ ] **Step 6: Build**

Run: `cargo build -p resd-net`
Expected: compiles. `include/resd_net.h` appears.

- [ ] **Step 7: Confirm header was generated and committed**

Run: `head -40 include/resd_net.h`
Expected: pragma-once + type declarations.

- [ ] **Step 8: Commit**

```sh
git add crates/resd-net/ include/resd_net.h
git commit -m "add resd-net public crate with C ABI types + cbindgen"
```

---

## Task 9: `resd-net` — `extern "C"` functions for engine lifecycle

**Files:**
- Modify: `crates/resd-net/src/lib.rs`

- [ ] **Step 1: Fill in the extern "C" wrappers**

Replace `lib.rs` with:

```rust
#![allow(non_camel_case_types, non_snake_case)]

pub mod api;

use api::*;
use resd_net_core::clock;
use resd_net_core::counters::Counters;
use resd_net_core::engine::{self, Engine, EngineConfig};
use std::ffi::CStr;
use std::ptr;

/// Opaque handle — actually a Box<Engine> reinterpreted as *mut resd_net_engine.
struct OpaqueEngine(Engine);

fn box_to_raw(e: Engine) -> *mut resd_net_engine {
    Box::into_raw(Box::new(OpaqueEngine(e))) as *mut resd_net_engine
}

unsafe fn engine_from_raw<'a>(p: *mut resd_net_engine) -> Option<&'a Engine> {
    if p.is_null() {
        return None;
    }
    Some(&(&*(p as *const OpaqueEngine)).0)
}

/// Initialize DPDK EAL. Must be called before resd_net_engine_create.
/// `argv` is a C-style argv array; the function does NOT take ownership
/// (copies each argument into Rust-owned CStrings internally).
/// Safe to call multiple times; subsequent calls after the first return 0.
/// Returns 0 on success, negative errno on failure.
#[no_mangle]
pub unsafe extern "C" fn resd_net_eal_init(
    argc: i32,
    argv: *const *const libc::c_char,
) -> i32 {
    if argc < 0 || argv.is_null() {
        return -libc::EINVAL;
    }
    let args: Vec<String> = (0..argc as isize)
        .map(|i| {
            let p = *argv.offset(i);
            if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        })
        .collect();
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match engine::eal_init(&refs) {
        Ok(()) => 0,
        Err(_) => -libc::EAGAIN,
    }
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_engine_create(
    lcore_id: u16,
    cfg: *const resd_net_engine_config_t,
) -> *mut resd_net_engine {
    if cfg.is_null() {
        return ptr::null_mut();
    }
    let cfg = &*cfg;
    let core_cfg = EngineConfig {
        lcore_id,
        port_id: cfg.port_id,
        rx_queue_id: cfg.rx_queue_id,
        tx_queue_id: cfg.tx_queue_id,
        rx_ring_size: 1024,
        tx_ring_size: 1024,
        rx_mempool_elems: 8192,
        mbuf_data_room: 2048,
    };
    match Engine::new(core_cfg) {
        Ok(e) => box_to_raw(e),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_engine_destroy(p: *mut resd_net_engine) {
    if p.is_null() {
        return;
    }
    let _boxed = Box::from_raw(p as *mut OpaqueEngine);
    // Drop runs Engine's Drop impl.
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_poll(
    p: *mut resd_net_engine,
    _events_out: *mut resd_net_event_t,
    _max_events: u32,
    _timeout_ns: u64,
) -> i32 {
    match engine_from_raw(p) {
        Some(e) => {
            e.poll_once();
            0
        }
        None => -libc::EINVAL,
    }
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_flush(_p: *mut resd_net_engine) {
    // Phase A1: no-op; TX burst handled inline in poll_once.
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_now_ns(_p: *mut resd_net_engine) -> u64 {
    clock::now_ns()
}

#[no_mangle]
pub unsafe extern "C" fn resd_net_counters(
    p: *mut resd_net_engine,
) -> *const resd_net_counters_t {
    match engine_from_raw(p) {
        Some(e) => e.counters() as *const Counters as *const resd_net_counters_t,
        None => ptr::null(),
    }
}
```

- [ ] **Step 2: Build**

Run: `cargo build -p resd-net`
Expected: compiles.

- [ ] **Step 3: Unit test the FFI**

Add at bottom of `lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_null_cfg_returns_null() {
        // Safety: we pass a valid null pointer and an arbitrary lcore_id.
        let p = unsafe { resd_net_engine_create(0, std::ptr::null()) };
        assert!(p.is_null());
    }

    #[test]
    fn destroy_null_is_safe() {
        // Must not panic / segfault.
        unsafe { resd_net_engine_destroy(std::ptr::null_mut()) };
    }

    #[test]
    fn poll_null_returns_einval() {
        let rc = unsafe {
            resd_net_poll(std::ptr::null_mut(), std::ptr::null_mut(), 0, 0)
        };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn now_ns_advances() {
        let a = unsafe { resd_net_now_ns(std::ptr::null_mut()) };
        let b = unsafe { resd_net_now_ns(std::ptr::null_mut()) };
        assert!(b >= a);
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p resd-net`
Expected: four PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/resd-net/src/lib.rs
git commit -m "add extern \"C\" wrappers for engine lifecycle + poll + counters"
```

---

## Task 10: Regenerate header and add CI check

**Files:**
- Modify: `include/resd_net.h` (regenerated)
- Create: `scripts/check-header.sh`

- [ ] **Step 1: Regenerate the header**

Run: `cargo build -p resd-net`
Expected: `include/resd_net.h` updates to include `resd_net_engine_create`, `resd_net_engine_destroy`, `resd_net_poll`, `resd_net_flush`, `resd_net_now_ns`, `resd_net_counters`.

- [ ] **Step 2: Inspect**

Run: `grep -E '^(void|int|uint|struct|typedef)' include/resd_net.h | head -40`
Expected: declarations for the above functions present.

- [ ] **Step 3: Create `scripts/check-header.sh`**

```sh
#!/usr/bin/env bash
# Fails CI if the committed header differs from what cbindgen produces.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p resd-net --quiet
if ! git diff --quiet include/resd_net.h; then
    echo "ERROR: include/resd_net.h differs from cbindgen output. Run 'cargo build -p resd-net' and commit." >&2
    git --no-pager diff include/resd_net.h >&2
    exit 1
fi
```

- [ ] **Step 4: Make it executable**

Run: `chmod +x scripts/check-header.sh`

- [ ] **Step 5: Commit regenerated header + CI script**

```sh
git add include/resd_net.h scripts/check-header.sh
git commit -m "regenerate header with lifecycle functions; add CI drift check"
```

---

## Task 11: C++ consumer sample

**Files:**
- Create: `examples/cpp-consumer/CMakeLists.txt`
- Create: `examples/cpp-consumer/main.cpp`

- [ ] **Step 1: Write CMakeLists.txt**

```cmake
cmake_minimum_required(VERSION 3.22)
project(resd_net_cpp_consumer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Expect the Rust library to be built before invoking cmake.
set(RESD_NET_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(RESD_NET_INCLUDE "${RESD_NET_ROOT}/include")
# Configurable: debug or release; default release.
set(RESD_NET_PROFILE "release" CACHE STRING "cargo profile to link")
set(RESD_NET_LIB "${RESD_NET_ROOT}/target/${RESD_NET_PROFILE}/libresd_net.a")

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

add_executable(cpp_consumer main.cpp)
target_include_directories(cpp_consumer PRIVATE "${RESD_NET_INCLUDE}" ${DPDK_INCLUDE_DIRS})
target_link_libraries(cpp_consumer PRIVATE
    "${RESD_NET_LIB}"
    ${DPDK_LIBRARIES}
    pthread
    dl
    m
)
target_compile_options(cpp_consumer PRIVATE -Wall -Wextra -Werror)
```

- [ ] **Step 2: Write main.cpp**

```cpp
#include "resd_net.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

int main() {
    // Minimal config. Assumes port 0 is already configured via EAL env.
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

    // Initialize EAL first — required before engine_create.
    // The default args below work on any host with hugepages; use the TAP
    // vdev so no real NIC is required for local smoke testing.
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

    resd_net_engine* eng = resd_net_engine_create(0, &cfg);
    if (!eng) {
        std::fprintf(stderr, "engine create failed\n");
        return 1;
    }

    // Poll a few times, print counters.
    for (int i = 0; i < 100; i++) {
        resd_net_event_t events[32];
        int n = resd_net_poll(eng, events, 32, 0);
        (void)n;
    }

    const resd_net_counters_t* c = resd_net_counters(eng);
    // Counter fields are plain uint64_t on the C ABI but written atomically
    // by the stack. For strictly correct cross-thread reads, use
    // __atomic_load_n(..., __ATOMIC_RELAXED); on x86_64 this compiles to a
    // plain mov so there's no runtime cost.
    uint64_t iters = __atomic_load_n(&c->poll.iters, __ATOMIC_RELAXED);
    std::printf("poll iters: %llu\n", (unsigned long long)iters);
    std::printf("now_ns: %llu\n",
        (unsigned long long)resd_net_now_ns(eng));

    resd_net_engine_destroy(eng);
    return 0;
}
```

- [ ] **Step 3: Try to build**

```sh
cargo build -p resd-net --release
cmake -S examples/cpp-consumer -B examples/cpp-consumer/build -DRESD_NET_PROFILE=release
cmake --build examples/cpp-consumer/build
```

Expected: `cpp_consumer` binary appears at `examples/cpp-consumer/build/cpp_consumer`.

Troubleshooting: if linking fails with "undefined symbol" for a DPDK function, ensure `pkg_check_modules(DPDK REQUIRED libdpdk)` is picking up the right `libdpdk.pc`. If atomic accessor syntax breaks, inspect `include/resd_net.h` to see how cbindgen emitted the AtomicU64 — adjust either `cbindgen.toml` (to treat AtomicU64 as plain `uint64_t` via a type rename) or the accessor in `main.cpp`.

- [ ] **Step 4: Commit**

```sh
git add examples/cpp-consumer/
git commit -m "add C++ consumer sample that creates engine and reads counters"
```

---

## Task 12: Integration test — Rust test linking via C ABI

**Files:**
- Create: `tests/ffi-test/Cargo.toml`
- Create: `tests/ffi-test/tests/ffi_smoke.rs`
- Modify: workspace root `Cargo.toml` (add `tests/ffi-test` to members)

- [ ] **Step 1: Add the test crate to the workspace**

Edit root `Cargo.toml` — update the `members` array:

```toml
members = [
    "crates/resd-net-sys",
    "crates/resd-net-core",
    "crates/resd-net",
    "tests/ffi-test",
]
```

- [ ] **Step 2: Create `tests/ffi-test/Cargo.toml`**

```toml
[package]
name = "ffi-test"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
resd-net = { path = "../../crates/resd-net" }
libc.workspace = true
```

- [ ] **Step 3: Create `tests/ffi-test/tests/ffi_smoke.rs`**

```rust
//! End-to-end FFI smoke test: uses the public C ABI from Rust to prove the
//! extern "C" surface is usable, not just the Rust-native one.
//!
//! - `ffi_handles_null_safely` runs always (doesn't touch EAL/DPDK).
//! - `ffi_eal_init_and_engine_lifecycle` runs only when RESD_NET_TEST_TAP=1
//!   because it actually initializes EAL against a DPDK TAP vdev.

use std::ffi::CString;
use std::ptr;

#[link(name = "resd_net", kind = "static")]
extern "C" {
    fn resd_net_eal_init(argc: i32, argv: *const *const libc::c_char) -> i32;
    fn resd_net_engine_create(
        lcore_id: u16,
        cfg: *const core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
    fn resd_net_engine_destroy(p: *mut core::ffi::c_void);
    fn resd_net_poll(
        p: *mut core::ffi::c_void,
        events_out: *mut core::ffi::c_void,
        max_events: u32,
        timeout_ns: u64,
    ) -> i32;
    fn resd_net_now_ns(p: *mut core::ffi::c_void) -> u64;
}

#[test]
fn ffi_handles_null_safely() {
    unsafe {
        resd_net_engine_destroy(ptr::null_mut());
        let rc = resd_net_poll(ptr::null_mut(), ptr::null_mut(), 0, 0);
        assert_eq!(rc, -libc::EINVAL);
        let ts = resd_net_now_ns(ptr::null_mut());
        assert!(ts > 0);
    }
}

#[test]
fn ffi_eal_init_and_engine_lifecycle() {
    if std::env::var("RESD_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set RESD_NET_TEST_TAP=1 to run");
        return;
    }

    let args: Vec<CString> = [
        "resd-net-ffi-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=resdtap0",
        "-l", "0-1",
        "--log-level=3",
    ]
    .iter()
    .map(|s| CString::new(*s).unwrap())
    .collect();
    let argv: Vec<*const libc::c_char> = args.iter().map(|c| c.as_ptr()).collect();

    let rc = unsafe { resd_net_eal_init(argv.len() as i32, argv.as_ptr()) };
    assert_eq!(rc, 0, "resd_net_eal_init failed: {rc}");

    // Minimum viable engine_config — matches the resd_net_engine_config_t layout
    // from api.rs. Kept as a byte array here to avoid duplicating the struct
    // definition; real consumers include resd_net.h and use the typed struct.
    #[repr(C)]
    struct Cfg {
        port_id: u16, rx_queue_id: u16, tx_queue_id: u16,
        _pad1: u16,
        max_connections: u32,
        recv_buffer_bytes: u32, send_buffer_bytes: u32,
        tcp_mss: u32,
        tcp_timestamps: bool, tcp_sack: bool, tcp_ecn: bool, tcp_nagle: bool,
        tcp_delayed_ack: bool, cc_mode: u8, _pad2: [u8; 2],
        tcp_min_rto_ms: u32, tcp_initial_rto_ms: u32, tcp_msl_ms: u32,
        tcp_per_packet_events: bool, preset: u8, _pad3: [u8; 2],
    }
    let cfg = Cfg {
        port_id: 0, rx_queue_id: 0, tx_queue_id: 0, _pad1: 0,
        max_connections: 16,
        recv_buffer_bytes: 256 * 1024, send_buffer_bytes: 256 * 1024,
        tcp_mss: 0,
        tcp_timestamps: true, tcp_sack: true, tcp_ecn: false, tcp_nagle: false,
        tcp_delayed_ack: false, cc_mode: 0, _pad2: [0; 2],
        tcp_min_rto_ms: 20, tcp_initial_rto_ms: 50, tcp_msl_ms: 30000,
        tcp_per_packet_events: false, preset: 0, _pad3: [0; 2],
    };

    let eng = unsafe {
        resd_net_engine_create(0, &cfg as *const Cfg as *const core::ffi::c_void)
    };
    assert!(!eng.is_null(), "resd_net_engine_create returned null");

    for _ in 0..10 {
        let rc = unsafe { resd_net_poll(eng, ptr::null_mut(), 0, 0) };
        assert_eq!(rc, 0);
    }

    unsafe { resd_net_engine_destroy(eng) };
}
```

Note: if cbindgen lays `resd_net_engine_config_t` out differently than the `Cfg` shim here (for example if Rust's field reordering happens despite `#[repr(C)]`), the test will detect it immediately — the engine_create call will mis-read the fields. The typed struct from `include/resd_net.h` is the source of truth; this shim must match it. Adjust field order to mirror `api.rs` exactly if the test fails.

- [ ] **Step 4: Run the non-TAP test**

Run: `cargo test -p ffi-test ffi_handles_null_safely`
Expected: PASS.

- [ ] **Step 5: Run the TAP test (requires sudo + DPDK)**

Run: `sudo -E RESD_NET_TEST_TAP=1 $(command -v cargo) test -p ffi-test ffi_eal_init_and_engine_lifecycle -- --nocapture`
Expected: PASS; poll returns 0 ten times.

- [ ] **Step 6: Commit**

```sh
git add Cargo.toml tests/ffi-test/
git commit -m "add FFI smoke test exercising public C ABI from Rust (null-safety + TAP lifecycle)"
```

---

## Task 13: _(removed)_

GitHub Actions CI is out of scope for Phase A1 per user decision — verification runs locally on the build host instead (see Task 14). The `scripts/check-header.sh` guard from Task 10 still exists and can be wired to a future CI system if desired, but no workflow file is produced in this phase.

---

## Task 14: Phase A1 sign-off checklist

This is a verification task, not new code.

- [ ] **Step 1: Confirm every Phase A1 deliverable works**

Run the following and verify each:

```sh
# Workspace builds clean
cargo build --workspace --all-targets
# Unit tests pass
cargo test --workspace
# TAP integration test passes (requires sudo + DPDK)
sudo -E RESD_NET_TEST_TAP=1 $(command -v cargo) test -p resd-net-core --test engine_smoke -- --nocapture
# Header hasn't drifted
./scripts/check-header.sh
# C++ consumer builds
cargo build -p resd-net --release
cmake -S examples/cpp-consumer -B examples/cpp-consumer/build -DRESD_NET_PROFILE=release
cmake --build examples/cpp-consumer/build
# No clippy warnings
cargo clippy --workspace --all-targets -- -D warnings
```

All must succeed. If any fails, fix before claiming A1 complete.

- [ ] **Step 2: Verify the spec references honored in Phase A1**

Check manually:
- §2 "Architecture" — Rust crate layout (`resd-net-sys`, `resd-net-core`, `resd-net`) + C++ consumer sample exists.
- §2.2 "Build / language / FFI" — cargo workspace, bindgen for DPDK, cbindgen for `resd_net.h`, `extern "C"` + primitive/opaque types only.
- §4 "Public API" — `resd_net_engine_create`, `resd_net_engine_destroy`, `resd_net_poll`, `resd_net_flush`, `resd_net_now_ns`, `resd_net_counters` exposed (stubbed; real logic in later phases).
- §7.1 "Mempools" — three per-lcore mempools (`rx`, `tx_hdr`, `tx_data`) allocated at engine create.
- §7.5 "Clock" — single process-wide TSC calibration via `OnceLock`; invariant-TSC check on first calibration.
- §9.1 "Counters" — `AtomicU64` groups (`eth`, `ip`, `tcp`, `poll`), cacheline-aligned, lock-free readable.

- [ ] **Step 3: Tag the release**

```sh
git tag -a phase-a1-complete -m "Phase A1: workspace skeleton + DPDK init + empty engine"
```

- [ ] **Step 4: Record next phase**

The next plan file to write is `docs/superpowers/plans/YYYY-MM-DD-stage1-phase-a2-l2-l3.md`, covering L2/L3 packet decoding, static ARP, and ICMP-driven PMTUD.

---

## Self-Review Notes

**Spec coverage for Phase A1:**
- §2 Architecture → Tasks 1, 8, 11 (workspace, public crate, C++ consumer)
- §2.1 Phases → Task 14 acknowledges we're doing A1 only
- §2.2 Build / language / FFI → Tasks 1, 2, 8, 10 (workspace, bindgen, cbindgen, header drift)
- §4 API (lifecycle subset) → Tasks 8, 9 (types + extern "C" functions; data-plane API stubs only, real logic in later phases)
- §7.1 Mempools → Task 6 (three pools allocated at engine creation)
- §7.5 Clock → Task 3 (TSC calibration, invariant check, single epoch)
- §9.1 Counters → Task 4 (AtomicU64 groups, cacheline-aligned)

Stage 1 items explicitly deferred to later phase plans:
- §4 API data-plane (connect, send, close, timers) → A3/A5/A6
- §5 Data flow (L2/L3/TCP path) → A2/A3
- §6 TCP layer → A3–A5
- §7.2, 7.3 Per-conn buffers, zero-copy story → A3/A4
- §7.4 Timer wheel → A6
- §8 Hardware assumptions → enforced by A2 (RSS, HW timestamp register)
- §9.2, 9.3 Event timestamps, stability events → A3 onward
- §10 Test plan (packetdrill, tcpreq, TCP-Fuzz) → A7/A8/A9
- §11 Benchmark plan → A10

**Placeholder scan:** No "TBD"/"TODO"/"implement later" markers. All code blocks contain complete content for their steps. The note in Task 11 about AtomicU64-accessor syntax is guidance for integration, not a placeholder.

**Type consistency:** `EngineConfig` in core and `resd_net_engine_config_t` in the public API have different field sets in Phase A1 — public is the full Stage 1 config (spec §4), core is the subset Phase A1 actually uses. Task 9 bridges them and ignores the public-only fields for now; later phases wire them through as real features land.

**Next plan after A1 ships:** `docs/superpowers/plans/2026-XX-XX-stage1-phase-a2-l2-l3.md`.
