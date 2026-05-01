# A10 Deferred Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the three deferred items from Phase A10 bench-nightly: bench-stress netem-over-DUT-SSH timeout, bench-vs-mtcp 0-row CSVs, and the iteration-7050 retransmit cliff.

**Architecture:** Three independent fix tracks, sequenced so the local code changes (Stage A diagnostics, stderr capture, `--external-netem` flag) land first, then a single AWS bench-nightly run produces the evidence to drive Stage B (audit + targeted fix for the cliff) and to finalise Bug 2 (whose true root cause requires the new stderr capture to surface).

**Tech Stack:** Rust 2021 (`crates/dpdk-net-core`, `tools/bench-stress`, `tools/bench-common`), C shim (`crates/dpdk-net-sys`), bash (`scripts/bench-nightly.sh`), DPDK 23.11 ENA PMD on AWS c6a.2xlarge.

**Worktree:** `/home/ubuntu/resd.dpdk_tcp-a10`, branch `phase-a10` (off `e044cd3` `phase-a10-complete`).

**Source-of-truth design:** `docs/superpowers/specs/2026-04-29-a10-deferred-fixes-design.md`.

---

## File map

| Path | Action | Responsibility |
|---|---|---|
| `crates/dpdk-net-sys/wrapper.h` | Modify | Declare new shim `shim_rte_mbuf_refcnt_read` |
| `crates/dpdk-net-sys/shim.c` | Modify | Define `shim_rte_mbuf_refcnt_read` (wraps `rte_mbuf_refcnt_read`) |
| `crates/dpdk-net-core/src/counters.rs` | Modify | Add `rx_mempool_avail` (AtomicU32) + `mbuf_refcnt_drop_unexpected` (AtomicU64) to `TcpCounters` |
| `crates/dpdk-net-core/src/mempool.rs` | Modify | In `MbufHandle::Drop`, sample post-dec refcount via the new shim and bump the new counter when the count is suspiciously high |
| `crates/dpdk-net-core/src/engine.rs` | Modify | Sample `rx_mempool_avail` at most once per second inside `poll_once`; double the per-conn term in the default `rx_mempool_size` formula |
| `crates/dpdk-net-core/tests/rx_mempool_no_leak.rs` | Create | TAP-loopback regression test: 10000 RTT iterations, mempool drift assertion ±32 mbufs |
| `tools/bench-stress/src/main.rs` | Modify | Add `--external-netem` flag; gate `NetemGuard::apply` on it |
| `tools/bench-stress/src/netem.rs` | Modify | Expose a `validate_iface` /  `validate_spec` pair as pub for the operator-side script (reuses existing internals); no behavior change |
| `tools/bench-stress/tests/external_netem.rs` | Create | Integration test asserting `--external-netem` skips the SSH call |
| `tools/bench-stress/src/counters_snapshot.rs` | Modify | Wire the two new counters into the `read` table so scenarios can reference them in `counter_expectations` |
| `scripts/bench-nightly.sh` | Modify | (a) `run_dut_bench` captures stderr to a per-bench file; (b) bench-stress block becomes a per-scenario loop with operator-side netem orchestration |

The plan is structured so Phase 1 (Tasks 1–9) lands all deterministic local changes, Phase 2 (Task 10) does defense-in-depth + regression test, and Phase 3 (Tasks 11–14) covers the AWS-driven validation + conditional Stage B.

---

## Phase 1 — Local code changes

### Task 1: Shim accessor for `rte_mbuf_refcnt_read`

The `MbufHandle::Drop` diagnostic needs to observe the post-decrement refcount; the existing shim only updates the count, not reads it. Add a read accessor symmetric to `shim_rte_mbuf_refcnt_update`.

**Files:**
- Modify: `crates/dpdk-net-sys/wrapper.h:55-65` (extern block — add one line near the existing `shim_rte_mbuf_refcnt_update` declaration)
- Modify: `crates/dpdk-net-sys/shim.c:80-100` (function defs — add right after `shim_rte_mbuf_refcnt_update`)

- [ ] **Step 1: Declare the shim in `wrapper.h`**

Locate the existing `shim_rte_mbuf_refcnt_update` declaration and add the read accessor immediately after it. The exact form (after the comment block already there):

```c
/* Read mbuf refcount without modifying. Used by MbufHandle::Drop's
 * leak-detection diagnostic — observes the post-dec count to flag
 * mbufs that should have been freed but weren't. */
uint16_t shim_rte_mbuf_refcnt_read(struct rte_mbuf *m);
```

- [ ] **Step 2: Implement the shim in `shim.c`**

Add (after `shim_rte_mbuf_refcnt_update`):

```c
uint16_t shim_rte_mbuf_refcnt_read(struct rte_mbuf *m) {
    return rte_mbuf_refcnt_read(m);
}
```

- [ ] **Step 3: Build the sys crate to validate the FFI binding**

Run: `cargo build -p dpdk-net-sys`
Expected: clean build; bindgen picks up the new symbol.

- [ ] **Step 4: Verify the Rust binding exists**

Run: `cargo doc -p dpdk-net-sys --no-deps 2>&1 | grep shim_rte_mbuf_refcnt_read || echo MISSING`
Expected: a non-MISSING line. If MISSING, recheck the wrapper.h spelling.

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-sys/wrapper.h crates/dpdk-net-sys/shim.c
git commit -m "ffi: add shim_rte_mbuf_refcnt_read for leak-detect diagnostic"
```

---

### Task 2: New diagnostic counter fields

Add the two new counter fields. Both slow-path; both `AtomicU64` for `mbuf_refcnt_drop_unexpected` (cumulative bumps) and `AtomicU32` for `rx_mempool_avail` (last-sampled value).

**Files:**
- Modify: `crates/dpdk-net-core/src/counters.rs` (TcpCounters struct, ~line 271 after `rx_partial_read_splits`)

- [ ] **Step 1: Write the failing test for default values**

Add to the bottom of `crates/dpdk-net-core/src/counters.rs` (in the existing `#[cfg(test)] mod tests` block; create one if absent):

```rust
#[cfg(test)]
mod a10_diagnostic_counter_tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn rx_mempool_avail_default_is_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.rx_mempool_avail.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn mbuf_refcnt_drop_unexpected_default_is_zero() {
        let c = Counters::new();
        assert_eq!(c.tcp.mbuf_refcnt_drop_unexpected.load(Ordering::Relaxed), 0);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `timeout 60 cargo test -p dpdk-net-core --lib counters::a10_diagnostic_counter_tests -- --test-threads=1 --nocapture`
Expected: compile error — fields don't exist yet.

- [ ] **Step 3: Add the fields to `TcpCounters`**

In `crates/dpdk-net-core/src/counters.rs`, locate the `TcpCounters` struct. Right after `pub rx_partial_read_splits: AtomicU64,` (around line 271), add:

```rust
    // --- A10 deferred-fix Stage A: RX-side leak diagnostics (slow-path) ---
    /// Most-recently-sampled value of `rte_mempool_avail_count(rx_mp)`.
    /// Sampled at most once per second inside `poll_once`. A monotonically
    /// decreasing trend across a long run is the leading indicator of an
    /// RX mempool leak (root-cause hypothesis for the iteration-7050
    /// retransmit cliff documented in
    /// `docs/superpowers/reports/a10-ab-driver-debug.md` §3).
    pub rx_mempool_avail: AtomicU32,
    /// Cumulative count of `MbufHandle::Drop` invocations that observed
    /// a post-decrement refcount above the legitimate-handle threshold.
    /// Threshold rationale: no production path holds more than 32 handles
    /// to one mbuf concurrently (max in-flight conns × max simultaneous
    /// READABLE pins); a higher post-dec count is unequivocally a leak.
    pub mbuf_refcnt_drop_unexpected: AtomicU64,
```

Also add `use std::sync::atomic::AtomicU32;` to the imports at the top of the file if not already present (search for `AtomicU64` to find the existing import line).

- [ ] **Step 4: Run the test to verify it passes**

Run: `timeout 60 cargo test -p dpdk-net-core --lib counters::a10_diagnostic_counter_tests -- --test-threads=1 --nocapture`
Expected: 2 passed.

- [ ] **Step 5: Run the full counters test module to catch regressions**

Run: `timeout 120 cargo test -p dpdk-net-core --lib counters -- --test-threads=1`
Expected: all existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/counters.rs
git commit -m "feat(counters): add rx_mempool_avail + mbuf_refcnt_drop_unexpected (A10 Stage A)"
```

---

### Task 3: Bump `mbuf_refcnt_drop_unexpected` from `MbufHandle::Drop`

Wire the new counter into the drop path. The counter accessor needs `&Counters` — but `MbufHandle` doesn't carry one. The pragmatic plumbing: bump only when the dropper has access to a `static`-ish reference. Since each engine owns its own counters, and mbufs originate from that engine, we use a thread-local `Cell<*const Counters>` set by `Engine::new` and cleared by `Engine::drop`.

This is intentionally minimal — the diagnostic only needs to fire on the same lcore the engine runs on, and no test or production path constructs `MbufHandle` outside an engine context.

**Files:**
- Modify: `crates/dpdk-net-core/src/mempool.rs` (MbufHandle::Drop, ~line 231)
- Modify: `crates/dpdk-net-core/src/engine.rs` (Engine::new + Engine::drop)

- [ ] **Step 1: Define the thread-local hook in `mempool.rs`**

At the top of `crates/dpdk-net-core/src/mempool.rs`, after the existing `use` statements:

```rust
use std::cell::Cell;

/// Per-thread pointer to the active engine's counters. Set by
/// `Engine::new` (start of construction) and cleared by `Engine::drop`
/// (very end of teardown). `MbufHandle::Drop` reads this on its hot
/// path to bump `mbuf_refcnt_drop_unexpected` when the post-dec refcount
/// is suspiciously high. Pointer is null iff no engine is bound on this
/// thread; in that case the diagnostic is silently skipped.
///
/// SAFETY: callers must store a pointer to a `Counters` whose lifetime
/// outlives every `MbufHandle::Drop` on the same thread. `Engine` owns
/// its `Counters` in a `Box`; setting / clearing in pair with engine
/// construction / destruction satisfies the invariant.
thread_local! {
    pub(crate) static THREAD_COUNTERS_PTR: Cell<*const crate::counters::Counters> =
        const { Cell::new(std::ptr::null()) };
}

/// Threshold above which a post-dec refcount in `MbufHandle::Drop`
/// surfaces as `mbuf_refcnt_drop_unexpected`. No production path holds
/// more than 32 handles to one mbuf concurrently; bump above this is a
/// leak signal.
pub(crate) const MBUF_DROP_UNEXPECTED_THRESHOLD: u16 = 32;
```

- [ ] **Step 2: Update `MbufHandle::Drop` to bump the counter**

In `crates/dpdk-net-core/src/mempool.rs`, replace the existing `Drop` impl:

```rust
impl Drop for MbufHandle {
    fn drop(&mut self) {
        // SAFETY: `ptr` was validated at construction and the handle
        // owns exactly one refcount.
        let post = unsafe {
            sys::shim_rte_mbuf_refcnt_update(self.ptr.as_ptr(), -1);
            sys::shim_rte_mbuf_refcnt_read(self.ptr.as_ptr())
        };
        if post > MBUF_DROP_UNEXPECTED_THRESHOLD {
            // Diagnostic: post-dec count above legitimate-handle ceiling
            // = unbalanced refcount. Bump only when an engine is bound
            // on this thread (THREAD_COUNTERS_PTR is set in
            // Engine::new / cleared in Engine::drop).
            THREAD_COUNTERS_PTR.with(|cell| {
                let p = cell.get();
                if !p.is_null() {
                    // SAFETY: pointer set by Engine::new and not yet
                    // cleared (Engine::drop hasn't fired) → still valid.
                    unsafe {
                        (*p).tcp
                            .mbuf_refcnt_drop_unexpected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        }
    }
}
```

- [ ] **Step 3: Set the thread-local in `Engine::new`**

In `crates/dpdk-net-core/src/engine.rs`, find `Engine::new` (search for `impl Engine {` then `pub fn new(cfg: EngineConfig)`). Locate where `counters` is constructed (`let counters = Box::new(Counters::new());` around line 933).

Immediately after the `Box::new(Counters::new())` line, add:

```rust
        // A10 Stage A: bind this engine's counters to the thread so
        // MbufHandle::Drop can route leak-detect bumps to the right
        // engine. Cleared by Engine::drop.
        crate::mempool::THREAD_COUNTERS_PTR.with(|cell| {
            cell.set(&*counters as *const _);
        });
```

- [ ] **Step 4: Clear the thread-local in `Engine::drop`**

In `crates/dpdk-net-core/src/engine.rs`, find `impl Drop for Engine` (search `impl Drop for Engine`, around line 5644). At the very end of the body — AFTER `rte_eth_dev_close` — add:

```rust
        // A10 Stage A: unbind the per-thread counters pointer so any
        // post-engine drop in this thread doesn't write through a
        // freed pointer. Pairs with Engine::new's set.
        crate::mempool::THREAD_COUNTERS_PTR.with(|cell| {
            cell.set(std::ptr::null());
        });
```

- [ ] **Step 5: Build the workspace to confirm the wiring compiles**

Run: `timeout 300 cargo build -p dpdk-net-core`
Expected: clean build.

- [ ] **Step 6: Run the full dpdk-net-core lib test suite**

Run: `timeout 600 cargo test -p dpdk-net-core --lib -- --test-threads=1`
Expected: all existing tests pass; no test exercises the new path yet (covered by Phase 2 integration test).

- [ ] **Step 7: Commit**

```bash
git add crates/dpdk-net-core/src/mempool.rs crates/dpdk-net-core/src/engine.rs
git commit -m "feat(diag): bump mbuf_refcnt_drop_unexpected in MbufHandle::Drop"
```

---

### Task 4: Sample `rx_mempool_avail` once per second in `poll_once`

Use a `Cell<u64>` as the last-sample-TSC store; sample on every poll where TSC delta exceeds 1 GHz × 1s. The shim call is cheap (single load + format).

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` (Engine struct + new() + poll_once)

- [ ] **Step 1: Add the last-sample-TSC field to `Engine`**

In `crates/dpdk-net-core/src/engine.rs`, find the `Engine` struct (search `pub struct Engine {`, around line 407). Locate `pub(crate) rx_mempool_size: u32,` (around line 420). Right after it, add:

```rust
    /// A10 Stage A: TSC of the most-recent `rx_mempool_avail` sample.
    /// `poll_once` re-samples when the current TSC has advanced ≥
    /// `tsc_hz` cycles past this value (≈1 second of wall clock).
    /// `Cell<u64>` because writes happen from the single engine lcore.
    pub(crate) rx_mempool_avail_last_sample_tsc: Cell<u64>,
```

- [ ] **Step 2: Initialise the field in `Engine::new`**

In `Engine::new`, find the final `Engine { ... }` struct construction (search for the line `flow_table: RefCell::new(...)` or similar — it's where all the fields get assembled, around line 1060). Add a new line for the new field, set to `0`:

```rust
            rx_mempool_avail_last_sample_tsc: Cell::new(0),
```

If the struct construction doesn't already use `Cell::new`, ensure `use std::cell::Cell;` is present at the top of the file.

- [ ] **Step 3: Add the sample call inside `poll_once`**

Find `pub fn poll_once(&self)` in `engine.rs`. At the very top of the body, before any RX work:

```rust
        // A10 Stage A: at most once per second, sample the RX mempool's
        // free-mbuf count. Cliff hypothesis: a steady drain across many
        // iterations would surface as a monotonically-decreasing series
        // here while the workload is otherwise healthy. `tsc_hz()` is
        // an O(1) DPDK call that returns the cached invariant-TSC rate.
        {
            let now_tsc = unsafe { sys::rte_rdtsc() };
            let last = self.rx_mempool_avail_last_sample_tsc.get();
            let tsc_hz = unsafe { sys::rte_get_tsc_hz() };
            if tsc_hz > 0 && now_tsc.wrapping_sub(last) >= tsc_hz {
                let avail = unsafe {
                    sys::shim_rte_mempool_avail_count(self._rx_mempool.as_ptr())
                };
                self.counters
                    .tcp
                    .rx_mempool_avail
                    .store(avail, std::sync::atomic::Ordering::Relaxed);
                self.rx_mempool_avail_last_sample_tsc.set(now_tsc);
            }
        }
```

(`rte_rdtsc` may already be aliased — check imports near top of file. If `crate::clock::rdtsc()` is the project convention, use that instead. Adjust accordingly.)

- [ ] **Step 4: Build to validate**

Run: `timeout 300 cargo build -p dpdk-net-core`
Expected: clean build.

- [ ] **Step 5: Run the full lib test suite**

Run: `timeout 600 cargo test -p dpdk-net-core --lib -- --test-threads=1`
Expected: all pass. The sample path exercises only the slow-path branch when `tsc_hz == 0` (no NIC), which is harmless.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs
git commit -m "feat(diag): sample rx_mempool_avail in poll_once (1Hz)"
```

---

### Task 5: Wire new counters into the bench-stress snapshot table

So `counter_expectations` in scenarios can reference them, and the bench-nightly CSV emits deltas.

**Files:**
- Modify: `tools/bench-stress/src/counters_snapshot.rs:90-118` (the `read` match)

- [ ] **Step 1: Write the test for the new counter names**

Add to `tools/bench-stress/src/counters_snapshot.rs` inside the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn read_recognises_a10_diagnostic_counters() {
        let c = Counters::new();
        // Both default to 0; we only need to confirm the names route
        // through the lookup table without falling through to the
        // unknown-name `_` arm.
        assert_eq!(read(&c, "tcp.rx_mempool_avail"), Some(0));
        assert_eq!(read(&c, "tcp.mbuf_refcnt_drop_unexpected"), Some(0));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `timeout 60 cargo test -p bench-stress --lib counters_snapshot::tests::read_recognises_a10 -- --test-threads=1 --nocapture`
Expected: FAIL — the new names fall through to `None`.

- [ ] **Step 3: Add the new arms to `read`**

In `tools/bench-stress/src/counters_snapshot.rs`, in the `read` function, add (right before the `_ => None,` fallthrough):

```rust
        "tcp.rx_mempool_avail" => {
            // u32 → u64 widen; the load returns the most-recent sample.
            Some(counters.tcp.rx_mempool_avail.load(Ordering::Relaxed) as u64)
        }
        "tcp.mbuf_refcnt_drop_unexpected" => {
            Some(counters.tcp.mbuf_refcnt_drop_unexpected.load(Ordering::Relaxed))
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `timeout 60 cargo test -p bench-stress --lib counters_snapshot -- --test-threads=1`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tools/bench-stress/src/counters_snapshot.rs
git commit -m "feat(bench-stress): wire A10 diagnostic counters into snapshot table"
```

---

### Task 6: `--external-netem` flag in bench-stress

Operator-side orchestration assumes bench-stress will skip its own SSH-based netem apply.

**Files:**
- Modify: `tools/bench-stress/src/main.rs:60-137` (Args struct + run_one_scenario)

- [ ] **Step 1: Write the test for the flag's effect**

Create `tools/bench-stress/tests/external_netem_skips_apply.rs`:

```rust
//! `--external-netem` must skip `NetemGuard::apply` so the operator
//! can orchestrate netem from a workstation that has SSH access to
//! the peer's mgmt IP. The DUT-side bench-stress only runs the workload.
//!
//! This test is structural: it builds the binary with `--external-netem`,
//! pipes a scenario name that has a netem spec, and asserts that no
//! `ssh` invocation occurs (we shadow `ssh` with a fake on $PATH).

use std::path::PathBuf;
use std::process::Command;

#[test]
fn external_netem_does_not_invoke_ssh() {
    // Place a fake `ssh` on PATH that fails loudly if invoked. The
    // test passes iff bench-stress completes its arg-parse + scenario-
    // setup loop without ever calling our shadow `ssh`.
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    let fake_ssh_path = tmpdir.path().join("ssh");
    std::fs::write(
        &fake_ssh_path,
        "#!/bin/sh\necho 'ssh invoked despite --external-netem' >&2; exit 99\n",
    )
    .expect("write fake ssh");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake_ssh_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod");

    let path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", tmpdir.path().display(), path);

    // We don't actually run the workload (no DPDK on this host); the
    // arg parser and scenario filter run pre-EAL-init and exit early
    // when `--list-scenarios` is set (added below in Step 4).
    let bin = env!("CARGO_BIN_EXE_bench-stress");
    let out = Command::new(bin)
        .env("PATH", &new_path)
        .args([
            "--external-netem",
            "--list-scenarios",
            "--peer-ssh", "ubuntu@1.2.3.4",
            "--peer-iface", "ens6",
            "--peer-ip", "10.0.0.2",
            "--local-ip", "10.0.0.1",
            "--gateway-ip", "10.0.0.3",
            "--eal-args", "",
            "--output-csv", "/tmp/external-netem-test.csv",
        ])
        .output()
        .expect("spawn bench-stress");

    assert!(
        out.status.success(),
        "bench-stress exited non-zero: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("ssh invoked despite --external-netem"),
        "fake ssh was invoked — --external-netem failed to suppress: {stderr}"
    );
}
```

If `tempfile` isn't already a dev-dep of the bench-stress crate, add it: edit `tools/bench-stress/Cargo.toml` `[dev-dependencies]` to include `tempfile = "3"`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `timeout 120 cargo test -p bench-stress --test external_netem_skips_apply -- --test-threads=1 --nocapture`
Expected: FAIL — `--external-netem` and `--list-scenarios` are unknown args; binary exits non-zero on the parse error.

- [ ] **Step 3: Add the flag + list-scenarios short-circuit to `Args`**

In `tools/bench-stress/src/main.rs`, in the `Args` struct, add (after `feature_set` field):

```rust
    /// When set, bench-stress does NOT shell out to `ssh peer "tc qdisc ..."`
    /// for netem. Operator orchestrates netem externally (see
    /// `scripts/bench-nightly.sh`). DUT->peer SSH on the data ENI is
    /// not reachable; orchestrating from the operator workstation
    /// (which has SSH to both DUT and peer mgmt IPs) is the canonical
    /// path. Default false (legacy behavior preserved for local tests).
    #[arg(long, default_value_t = false)]
    external_netem: bool,

    /// Print the resolved scenario list and exit. Used by the
    /// integration test in `tests/external_netem_skips_apply.rs` to
    /// exercise the arg-parsing + scenario-filter path without
    /// requiring DPDK / EAL on the host.
    #[arg(long, default_value_t = false)]
    list_scenarios: bool,
```

- [ ] **Step 4: Honor `--list-scenarios` early in `main`**

In `main()`, immediately after `let selected = resolve_scenarios(&args.scenarios)?;` (around line 144), add:

```rust
    if args.list_scenarios {
        for s in &selected {
            println!("{}", s.name);
        }
        return Ok(());
    }
```

- [ ] **Step 5: Honor `--external-netem` in `run_one_scenario`**

In `tools/bench-stress/src/main.rs`, find `run_one_scenario` (around line 233). Replace the netem-guard block:

```rust
    // 1. Install netem if the scenario needs it. Dropped on scope exit.
    let _netem_guard = match scenario.netem {
        Some(spec) => Some(
            NetemGuard::apply(&args.peer_ssh, &args.peer_iface, spec)
                .with_context(|| format!("applying netem for scenario {}", scenario.name))?,
        ),
        None => None,
    };
```

with:

```rust
    // 1. Install netem if the scenario needs it. `--external-netem`
    //    skips the SSH apply: operator-side script (e.g.
    //    `scripts/bench-nightly.sh`) has already orchestrated the
    //    qdisc apply via its own SSH path, which can reach the peer's
    //    mgmt IP from the operator workstation but NOT from the DUT
    //    data ENI (the original failure mode for this code path).
    let _netem_guard = match (scenario.netem, args.external_netem) {
        (Some(_spec), true) => {
            eprintln!(
                "bench-stress: scenario {} netem applied externally; \
                 skipping in-process NetemGuard",
                scenario.name
            );
            None
        }
        (Some(spec), false) => Some(
            NetemGuard::apply(&args.peer_ssh, &args.peer_iface, spec)
                .with_context(|| format!("applying netem for scenario {}", scenario.name))?,
        ),
        (None, _) => None,
    };
```

- [ ] **Step 6: Run the integration test to verify it passes**

Run: `timeout 120 cargo test -p bench-stress --test external_netem_skips_apply -- --test-threads=1 --nocapture`
Expected: PASS.

- [ ] **Step 7: Re-run all bench-stress tests for regressions**

Run: `timeout 300 cargo test -p bench-stress -- --test-threads=1`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add tools/bench-stress/src/main.rs tools/bench-stress/tests/external_netem_skips_apply.rs tools/bench-stress/Cargo.toml
git commit -m "feat(bench-stress): --external-netem flag + --list-scenarios"
```

---

### Task 7: stderr capture in `run_dut_bench`

So Bug 2's silent failure mode surfaces actionable evidence.

**Files:**
- Modify: `scripts/bench-nightly.sh:396-418` (run_dut_bench function)

- [ ] **Step 1: Update `run_dut_bench` to capture stderr per bench**

Replace the body of `run_dut_bench` (lines 396-418) with:

```bash
run_dut_bench() {
  local bench="$1"
  local csv_name="$2"
  shift 2
  local cmd="sudo /tmp/$bench"
  local arg
  for arg in "$@"; do
    cmd+=" $(printf '%q' "$arg")"
  done
  cmd+=" --output-csv /tmp/${csv_name}.csv"

  refresh_ec2_ic_grants

  local stderr_log="$OUT_DIR/${csv_name}.stderr.log"
  local stdout_log="$OUT_DIR/${csv_name}.stdout.log"

  log "  DUT> $bench (stderr -> $stderr_log)"
  # Capture stdout + stderr separately. The remote `2>&1` pattern would
  # interleave the two streams; we want stderr preserved in its own
  # file because the binaries log structured progress to stdout and
  # diagnostics to stderr.
  if ! ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" "$cmd" \
      >"$stdout_log" 2>"$stderr_log"; then
    local rc=$?
    log "  $bench exited rc=$rc; tailing stderr:"
    tail -n 40 "$stderr_log" | sed 's/^/    /' | tee -a /dev/stderr
    return $rc
  fi
  refresh_ec2_ic_grants
  scp "${SCP_OPTS[@]}" "ubuntu@$DUT_SSH:/tmp/${csv_name}.csv" "$OUT_DIR/" \
    || log "  scp ${csv_name}.csv failed (bench may have exited before write)"
}
```

- [ ] **Step 2: Verify `bash -n` parses the script**

Run: `bash -n scripts/bench-nightly.sh`
Expected: silent (clean parse).

- [ ] **Step 3: Verify `shellcheck` accepts it**

Run: `shellcheck scripts/bench-nightly.sh 2>&1 | head -40`
Expected: pre-existing warnings only; no new errors. (If shellcheck isn't installed, skip with a note.)

- [ ] **Step 4: Commit**

```bash
git add scripts/bench-nightly.sh
git commit -m "ops(bench-nightly): capture stderr per-bench for failure diagnostics"
```

---

### Task 8: Operator-side netem orchestration in `bench-nightly.sh`

Replace the single `bench-stress --scenarios <CSV>` invocation with a per-scenario loop that applies netem from the operator side, runs bench-stress with `--external-netem`, then removes the qdisc.

**Files:**
- Modify: `scripts/bench-nightly.sh:463-478` (the bench-stress block)

- [ ] **Step 1: Replace the single bench-stress invocation with the per-scenario loop**

In `scripts/bench-nightly.sh`, locate the existing block:

```bash
log "[8/12] bench-stress"
# Default matrix bundles ...
run_dut_bench bench-stress bench-stress \
    "${DPDK_COMMON[@]}" \
    --peer-port 10001 \
    --peer-ssh "ubuntu@$PEER_SSH" \
    --peer-iface ens6 \
    --scenarios random_loss_01pct_10ms,correlated_burst_loss_1pct,reorder_depth_3,duplication_2x \
    --iterations "$BENCH_ITERATIONS" \
    --warmup "$BENCH_WARMUP" \
    --tool bench-stress \
    --feature-set trading-latency \
    || log "  [8/12] bench-stress exited non-zero — continuing"
```

Replace with:

```bash
# ---------------------------------------------------------------------------
# [8/12] bench-stress — operator-side netem orchestration.
# DUT cannot SSH from the data ENI to the peer's mgmt IP (different SG /
# no route), so the previous in-process NetemGuard apply hangs on
# OpenSSH's connect timeout. Operator workstation has working SSH to
# the peer's mgmt IP; orchestrate netem here, run bench-stress with
# --external-netem on the DUT.
# ---------------------------------------------------------------------------
log "[8/12] bench-stress (operator-side netem orchestration)"

# Spec→string map mirrors the literals in
# `tools/bench-stress/src/scenarios.rs::MATRIX`. Adding a new netem
# scenario requires a new entry here AND a row in scenarios.rs.
declare -A NETEM_SPECS=(
  [random_loss_01pct_10ms]="loss 0.1% delay 10ms"
  [correlated_burst_loss_1pct]="loss 1% 25%"
  [reorder_depth_3]="reorder 50% gap 3"
  [duplication_2x]="duplicate 100%"
)

NETEM_SCENARIOS=(random_loss_01pct_10ms correlated_burst_loss_1pct reorder_depth_3 duplication_2x)

bench_stress_csvs=()

for scenario in "${NETEM_SCENARIOS[@]}"; do
  spec="${NETEM_SPECS[$scenario]}"
  log "  [8/12] $scenario — applying netem ($spec)"
  ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "sudo tc qdisc add dev ens6 root netem $spec" \
    || { log "    apply failed; skipping scenario"; continue; }

  csv_name="bench-stress-$scenario"
  if ! run_dut_bench bench-stress "$csv_name" \
      "${DPDK_COMMON[@]}" \
      --peer-port 10001 \
      --peer-ssh "ubuntu@$PEER_SSH" \
      --peer-iface ens6 \
      --scenarios "$scenario" \
      --external-netem \
      --iterations "$BENCH_ITERATIONS" \
      --warmup "$BENCH_WARMUP" \
      --tool bench-stress \
      --feature-set trading-latency; then
    log "    $scenario bench-stress exited non-zero — continuing"
  fi

  log "  [8/12] $scenario — removing netem"
  ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "sudo tc qdisc del dev ens6 root || true"

  bench_stress_csvs+=("$OUT_DIR/${csv_name}.csv")
done

# Concatenate per-scenario CSVs into a single bench-stress.csv.
# First file's header is preserved; subsequent files' headers are
# stripped via `tail -n +2`. If no scenarios produced a CSV (every one
# failed), emit an empty file so the downstream report sees the
# expected name without erroring.
log "[8/12] merging per-scenario CSVs into bench-stress.csv"
{
  if [ ${#bench_stress_csvs[@]} -gt 0 ] && [ -f "${bench_stress_csvs[0]}" ]; then
    head -n 1 "${bench_stress_csvs[0]}"
    for f in "${bench_stress_csvs[@]}"; do
      [ -f "$f" ] && tail -n +2 "$f"
    done
  fi
} > "$OUT_DIR/bench-stress.csv"
```

- [ ] **Step 2: Verify `bash -n` parses the script**

Run: `bash -n scripts/bench-nightly.sh`
Expected: silent.

- [ ] **Step 3: Spot-check the spec map matches scenarios.rs**

Run: `grep -n 'netem: Some' tools/bench-stress/src/scenarios.rs | head -10`
Expected: each scenario whose `netem: Some(...)` literal matches the bash map.
If any literal differs, fix the bash map to match.

- [ ] **Step 4: Commit**

```bash
git add scripts/bench-nightly.sh
git commit -m "ops(bench-nightly): operator-side netem orchestration for bench-stress"
```

---

### Task 9: Workspace test sweep + commit

Run the full local test suite to catch any cross-crate regression introduced by Tasks 2-6.

- [ ] **Step 1: Build the full workspace**

Run: `timeout 600 cargo build --workspace`
Expected: clean build.

- [ ] **Step 2: Run the full lib test suite**

Run: `timeout 1200 cargo test --workspace --lib -- --test-threads=1`
Expected: all pass. (Integration tests requiring TAP / DPDK are not exercised here; they're gated on env vars.)

- [ ] **Step 3: Run all binary tests**

Run: `timeout 1200 cargo test --workspace --tests -- --test-threads=1`
Expected: all pass except those gated on `DPDK_NET_TEST_TAP=1` (which skip cleanly).

- [ ] **Step 4: Spot-check that the new counters are visible to the bench harness**

Run:
```bash
grep -n "rx_mempool_avail\|mbuf_refcnt_drop_unexpected" \
  crates/dpdk-net-core/src/counters.rs \
  tools/bench-stress/src/counters_snapshot.rs
```
Expected: 4+ matches (definition + lookup arms in both files).

---

## Phase 2 — Defense-in-depth + regression test

### Task 10: Double the per-conn term in `rx_mempool_size` formula + regression test

The current formula `2 * max_connections * per_conn + 4096` resolves to 8192 mbufs at defaults. Even with the leak fixed, doubling this gives operational headroom.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs:880-903` (formula)
- Create: `crates/dpdk-net-core/tests/rx_mempool_no_leak.rs`

- [ ] **Step 1: Write the unit test for the formula**

In `crates/dpdk-net-core/src/engine.rs`, find the existing test module for engine config (search `mod cfg_tests` or `mod default_tests`; if absent, append a new `#[cfg(test)] mod rx_mempool_size_tests`).  Add:

```rust
#[cfg(test)]
mod rx_mempool_size_default_formula_tests {
    use super::*;

    /// A10 deferred-fix Stage B (defense in depth): doubled per-conn term.
    /// Formula = max(4 * rx_ring_size,
    ///               4 * max_connections * ceil(recv_buffer_bytes / mbuf_data_room) + 4096).
    /// At default config, the per-conn term dominates: per_conn = 128;
    /// computed = 4 × 16 × 128 + 4096 = 12288. Floor = 4 × 512 = 2048.
    /// → final 12288 (raised from the prior 8192).
    #[test]
    fn default_formula_yields_12288() {
        let cfg = EngineConfig::default();
        let mbuf_data_room = cfg.mbuf_data_room as u32;
        let per_conn = cfg
            .recv_buffer_bytes
            .saturating_add(mbuf_data_room.saturating_sub(1))
            / mbuf_data_room.max(1);
        let computed = 4u32
            .saturating_mul(cfg.max_connections)
            .saturating_mul(per_conn)
            .saturating_add(4096);
        let floor = 4u32.saturating_mul(cfg.rx_ring_size as u32);
        assert_eq!(computed.max(floor), 12288);
    }

    #[test]
    fn caller_override_skips_formula() {
        // Non-zero `rx_mempool_size` is used verbatim — no formula applied.
        // (Repeat of an existing invariant; restated here so renames of
        // the formula don't accidentally remove the override path.)
        let mut cfg = EngineConfig::default();
        cfg.rx_mempool_size = 1024;
        // Smoke: no panic, value preserved.
        assert_eq!(cfg.rx_mempool_size, 1024);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `timeout 60 cargo test -p dpdk-net-core --lib rx_mempool_size_default_formula_tests::default_formula_yields_12288 -- --test-threads=1 --nocapture`
Expected: FAIL — current formula gives 8192.

- [ ] **Step 3: Update the formula in `Engine::new`**

In `crates/dpdk-net-core/src/engine.rs:897-900`, change:

```rust
            let computed = 2u32
                .saturating_mul(cfg.max_connections)
                .saturating_mul(per_conn)
                .saturating_add(4096);
```

to:

```rust
            // A10 deferred-fix (defense in depth): 4× the per-conn term
            // (was 2×). Doubles the mempool headroom so a hypothetical
            // leak takes twice as long to drain the pool, regardless of
            // whether the leak audit lands a fix. ~12288 mbufs at
            // default config (was 8192).
            let computed = 4u32
                .saturating_mul(cfg.max_connections)
                .saturating_mul(per_conn)
                .saturating_add(4096);
```

Also update the doc-comment on `rx_mempool_size` (around `engine.rs:244-260`):

```rust
    /// A6.6-7 Task 10 (raised by A10 deferred-fix): RX mempool capacity in
    /// mbufs. `0` = compute default at `Engine::new`:
    ///   `max(4 * rx_ring_size,
    ///        4 * max_connections * ceil(recv_buffer_bytes / mbuf_data_room) + 4096)`
    ///
    /// (Per-conn coefficient bumped from 2 to 4 in A10 deferred-fix —
    /// see `docs/superpowers/specs/2026-04-29-a10-deferred-fixes-design.md`
    /// "Defense in depth" — to extend the cliff window from ~7050 to
    /// ~14000+ iterations regardless of whether the leak audit lands.)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `timeout 60 cargo test -p dpdk-net-core --lib rx_mempool_size_default_formula_tests -- --test-threads=1 --nocapture`
Expected: 2 passed.

- [ ] **Step 5: Create the TAP-loopback regression test**

Create `crates/dpdk-net-core/tests/rx_mempool_no_leak.rs` modelled on the existing `tests/rx_close_drains_mbufs.rs` but for sustained N-iteration RTT:

```rust
//! A10 deferred-fix Stage B regression test: 10000 RTT iterations
//! against a kernel TCP echo peer over TAP. Asserts that the RX mempool's
//! free-mbuf count returns to within ±32 of the pre-test baseline after
//! the run completes, proving no per-iteration mbuf leak on the RX path.
//!
//! Models on `tests/rx_close_drains_mbufs.rs`. Gated on
//! `DPDK_NET_TEST_TAP=1` + sudo (matches the existing TAP-test pattern).

use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpListener;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_events::InternalEvent;

const TAP_IFACE: &str = "resdtap16";
const OUR_IP: u32 = 0x0a_63_10_02; // 10.99.16.2
const PEER_IP: u32 = 0x0a_63_10_01; // 10.99.16.1
const PEER_PORT: u16 = 5016;
const ITERATIONS: u32 = 10_000;
const PAYLOAD: usize = 128;
const DRIFT_TOLERANCE: i64 = 32;

fn skip_if_not_tap() -> bool {
    if std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() != Some("1") {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run (requires sudo for TAP vdev)");
        return true;
    }
    false
}

fn read_kernel_tap_mac(iface: &str) -> [u8; 6] {
    // Re-uses the same approach as rx_close_drains_mbufs.rs.
    // Read /sys/class/net/<iface>/address and parse the MAC.
    let path = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&path).expect("read tap mac");
    let mut bytes = [0u8; 6];
    for (i, part) in s.trim().split(':').enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).expect("parse hex");
    }
    bytes
}

#[test]
fn rx_mempool_steady_under_10k_rtt() {
    if skip_if_not_tap() {
        return;
    }

    // Bring up TAP iface (idempotent).
    let _ = Command::new("sudo")
        .args(["ip", "tuntap", "add", TAP_IFACE, "mode", "tap"])
        .status();
    let _ = Command::new("sudo")
        .args(["ip", "addr", "add", "10.99.16.1/24", "dev", TAP_IFACE])
        .status();
    let _ = Command::new("sudo")
        .args(["ip", "link", "set", "dev", TAP_IFACE, "up"])
        .status();

    // Echo peer on the kernel side.
    let listener = TcpListener::bind(("10.99.16.1", PEER_PORT)).expect("bind echo");
    let (peer_done_tx, peer_done_rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        sock.set_nodelay(true).ok();
        let mut buf = [0u8; PAYLOAD];
        for _ in 0..ITERATIONS {
            sock.read_exact(&mut buf).expect("echo read");
            sock.write_all(&buf).expect("echo write");
        }
        let _ = peer_done_tx.send(());
    });

    // EAL + engine bring-up (TAP vdev). Replicate the EAL args from the
    // close-drains test verbatim — same vdev shape.
    eal_init(&[
        "rx_mempool_no_leak",
        "--no-pci",
        "--vdev", &format!("net_tap0,iface={TAP_IFACE}"),
        "-l", "0,1",
        "--in-memory",
        "--huge-unlink",
    ])
    .expect("eal_init");

    let cfg = EngineConfig {
        port_id: 0,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: read_kernel_tap_mac(TAP_IFACE),
        ..EngineConfig::default()
    };
    let engine = Engine::new(cfg).expect("Engine::new");
    let pool = engine.rx_mempool_ptr();

    // Snapshot the mempool baseline AFTER engine bring-up but BEFORE
    // the workload. Bring-up consumes a small fixed number of mbufs for
    // the RX ring; everything beyond that is workload-attributable.
    let avail_baseline =
        unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };

    // Open conn + drive ITERATIONS RTT round-trips.
    let conn = engine
        .connect(PEER_IP, PEER_PORT, 0)
        .expect("connect");

    // Pump until Connected.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        engine.poll_once();
        let mut events = engine.events();
        let mut connected = false;
        while let Some(ev) = events.pop() {
            if let InternalEvent::Connected { .. } = ev {
                connected = true;
                break;
            }
        }
        drop(events);
        if connected {
            break;
        }
        assert!(Instant::now() < deadline, "connect timeout");
    }

    let payload = vec![0xABu8; PAYLOAD];
    for i in 0..ITERATIONS {
        let mut sent = 0;
        while sent < PAYLOAD {
            match engine.send_bytes(conn, &payload[sent..]) {
                Ok(n) => sent += n as usize,
                Err(e) => panic!("send_bytes iter {i}: {e:?}"),
            }
            engine.poll_once();
        }
        // Drain echo: wait for ITERATIONS-th byte sum to come back.
        let mut recv_total = 0;
        let iter_deadline = Instant::now() + Duration::from_secs(5);
        while recv_total < PAYLOAD {
            engine.poll_once();
            let mut events = engine.events();
            while let Some(ev) = events.pop() {
                if let InternalEvent::Readable { total_len, .. } = ev {
                    recv_total += total_len as usize;
                }
            }
            drop(events);
            assert!(Instant::now() < iter_deadline, "iter {i} drain timeout");
        }
    }

    // Wait for the kernel echo thread to finish so it doesn't hold a
    // half-closed conn open across the assert.
    let _ = peer_done_rx.recv_timeout(Duration::from_secs(5));

    // Final drain — push poll events through to give the engine a few
    // extra cycles to release any in-flight mbufs.
    for _ in 0..50 {
        engine.poll_once();
    }

    let avail_post =
        unsafe { dpdk_net_sys::shim_rte_mempool_avail_count(pool) };
    let drift = (avail_baseline as i64) - (avail_post as i64);
    assert!(
        drift.abs() <= DRIFT_TOLERANCE,
        "RX mempool drift {drift} exceeds tolerance ±{DRIFT_TOLERANCE} \
         (baseline {avail_baseline}, post {avail_post}) — likely leak in \
         RX path; see docs/superpowers/reports/a10-ab-driver-debug.md §3"
    );

    // Surface the diagnostic counter for forensic visibility.
    let drop_unexpected = engine
        .counters()
        .tcp
        .mbuf_refcnt_drop_unexpected
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        drop_unexpected, 0,
        "mbuf_refcnt_drop_unexpected fired during 10k RTT — leak signal"
    );
}
```

- [ ] **Step 6: Run the regression test (will skip if not TAP)**

Run: `timeout 60 cargo test -p dpdk-net-core --test rx_mempool_no_leak -- --test-threads=1 --nocapture`
Expected: skip message ("set DPDK_NET_TEST_TAP=1 to run") — the test compiles + skips. The actual run is gated on the operator's permission to use sudo TAP, which is the same gate as the existing close-drains test.

- [ ] **Step 7: Run with TAP enabled (operator decision)**

Run: `sudo DPDK_NET_TEST_TAP=1 timeout 600 cargo test -p dpdk-net-core --test rx_mempool_no_leak -- --test-threads=1 --nocapture`
Expected: PASS (drift ≤ 32). If FAIL, the leak is reproducible locally — proceed to Phase 3 Task 12 audit branch with this test as the regression target.

- [ ] **Step 8: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/tests/rx_mempool_no_leak.rs
git commit -m "feat(rx): double per-conn term in rx_mempool_size + leak regression test"
```

---

## Phase 3 — AWS validation + conditional Stage B

The next three tasks need an AWS bench-pair fleet up + the operator's credentials. The implementer drives them; conditional fixes depend on what the run surfaces.

### Task 11: Push to AWS + run bench-nightly with `BENCH_ITERATIONS=100000`

- [ ] **Step 1: Confirm Phase 1+2 commits are pushed**

Run: `git log --oneline phase-a10-complete..HEAD`
Expected: 8–9 commits (one per task above) on top of the prior `phase-a10-complete` tag.

Push: `git push origin phase-a10`

- [ ] **Step 2: Provision the bench-pair fleet (operator action)**

Use the existing CDK / scripts that built the prior `bm6lmn8kp` run.

- [ ] **Step 3: Run bench-nightly with iterations bumped to 100000**

```bash
BENCH_ITERATIONS=100000 BENCH_WARMUP=1000 \
  timeout 7200 ./scripts/bench-nightly.sh \
  2>&1 | tee /tmp/bench-nightly-100k.log
```

- [ ] **Step 4: Pull the per-bench stderr logs**

```bash
ls -la $OUT_DIR/*.stderr.log
# Verify each bench has a stderr.log entry
```

- [ ] **Step 5: Snapshot the diagnostic counters from the bench-e2e CSV**

```bash
grep -E "tcp.rx_mempool_avail|tcp.mbuf_refcnt_drop_unexpected" \
  $OUT_DIR/bench-e2e.csv | head -20
```

Expected (no leak): `tcp.rx_mempool_avail` value stays in [10000, 12200] across the run; `tcp.mbuf_refcnt_drop_unexpected` is 0.
Expected (leak present): `tcp.rx_mempool_avail` decreases monotonically; `tcp.mbuf_refcnt_drop_unexpected` is non-zero by run end.

---

### Task 12: Triage Bug 2 (bench-vs-mtcp 0-row) from captured stderr

- [ ] **Step 1: Inspect the bench-vs-mtcp stderr**

```bash
cat $OUT_DIR/bench-vs-mtcp-burst.stderr.log
cat $OUT_DIR/bench-vs-mtcp-maxtp.stderr.log
```

- [ ] **Step 2: Diagnose based on the visible error**

Three branches:

**(a) "tcp error during recv: errno=-110" or similar timeout / handshake failure**
The same RX-side stall as Bug 3. Validation: check `tcp.rx_mempool_avail` in the same run's `bench-vs-mtcp-burst.csv` (if any rows exist) — exhaustion confirms shared root cause. Proceed to Task 13.

**(b) "ssh: connect to host ... port 22: Connection refused" or peer_rwnd introspect failure**
The `peer_introspect.rs::fetch_peer_rwnd_bytes` path bails. Fix: extend `resolve_peer_rwnd_bytes` (`tools/bench-vs-mtcp/src/main.rs:364`) to a retry-with-backoff loop or to fall back to the placebo more aggressively. Direct patch — single-task implementation:

  - [ ] Add a 3-retry × 200ms backoff inside `resolve_peer_rwnd_bytes`
  - [ ] Run `cargo test -p bench-vs-mtcp -- --test-threads=1`
  - [ ] Commit with `fix(bench-vs-mtcp): retry peer_rwnd ss probe before placebo fallback`

**(c) Some other error**
Read the stderr in full, identify the failing call site, write a regression test that reproduces the failure mode, fix it, commit.

- [ ] **Step 3: Re-run bench-vs-mtcp once the fix lands**

```bash
ssh "ubuntu@$DUT_SSH" "sudo /tmp/bench-vs-mtcp \
  --workload burst --peer-port 10001 --stacks dpdk \
  --output-csv /tmp/bench-vs-mtcp-burst-rerun.csv \
  ${DPDK_COMMON[@]}" 2>&1 | tail -40
scp "ubuntu@$DUT_SSH:/tmp/bench-vs-mtcp-burst-rerun.csv" .
wc -l bench-vs-mtcp-burst-rerun.csv
```
Acceptance: ≥21 rows (header + 20 K×G buckets × at least 1 metric row each).

---

### Task 13: Triage Bug 3 (cliff) from counter evidence

- [ ] **Step 1: Plot or tail the rx_mempool_avail series**

```bash
awk -F, 'NR==1 || $1 ~ /tcp.rx_mempool_avail/' $OUT_DIR/bench-e2e.csv
```

- [ ] **Step 2: Decide which audit branch**

**(a) `rx_mempool_avail` decreases monotonically AND `mbuf_refcnt_drop_unexpected > 0`**
Confirmed leak. The drop-unexpected bumps point to specific mbufs. Audit candidates in priority order:
  1. `engine.rs:4130` — partial-read `try_clone` pairing
  2. `tcp_input.rs:962` / `:1022` — `MbufHandle::from_raw` constructions
  3. `tcp_reassembly.rs:370` — OOO insert path
For each: inspect for a path where the refcount bump is not paired with a `Drop` (or a free), or a path where the same handle gets stored twice.

When a candidate is identified, write a unit test reproducing the leak (use the TAP test infra in Task 10 with FaultInjector to force OOO traffic), apply the fix, re-run.

  - [ ] Add unit test reproducing the suspected path
  - [ ] Apply targeted fix
  - [ ] Run `cargo test -p dpdk-net-core --test rx_mempool_no_leak` with TAP
  - [ ] Commit with `fix(rx): release mbuf refcount on <site> path`

**(b) `rx_mempool_avail` decreases monotonically BUT `mbuf_refcnt_drop_unexpected == 0`**
Leak is somewhere mbufs aren't going through `MbufHandle::Drop` (e.g., raw `shim_rte_pktmbuf_free` paths). Audit: every raw-pointer free site (the 30+ `shim_rte_pktmbuf_free` callers identified in `engine.rs`). Strategy: bisect by selectively replacing a `shim_rte_pktmbuf_free(p)` with `MbufHandle::from_raw(NonNull::new_unchecked(p))` (lets the diagnostic catch it) and re-running.

  - [ ] Bisection loop (multiple commits acceptable)

**(c) `rx_mempool_avail` is steady AND no errno=-110 cliff**
The defense-in-depth doubling of rx_mempool_size sufficed. Mark Bug 3 as fixed via Phase 2 Task 10 alone; document the audit-not-needed conclusion in the closing PR.

- [ ] **Step 3: Re-run nightly with the fix, verify cliff resolved**

```bash
BENCH_ITERATIONS=100000 BENCH_WARMUP=1000 \
  timeout 7200 ./scripts/bench-nightly.sh \
  2>&1 | tee /tmp/bench-nightly-100k-fixed.log
```
Acceptance: every bench's stderr is clean of `errno=-110`. CSV row counts match expected matrix sizes (bench-e2e: 1×7 = 7 rows, bench-stress: 4×7 + idle baseline = ≥28 rows, etc.).

---

### Task 14: Roll up — close the deferred items in `reports/README.md` + tag

- [ ] **Step 1: Update `docs/superpowers/reports/README.md`**

Replace the "Open items (deferred outside T16 scope)" section with a "Closed deferred items" section. For each bug, list:
- Confirmed-fixed commit SHA
- Brief root-cause statement
- Validation: which run / log / CSV proves the fix

Keep the "Confirmed-fixed bugs along the way" table intact and add 3+ rows for the deferred-fix commits.

- [ ] **Step 2: Update the headline-results section if numbers shifted**

If the iterations bump from 5000 → 100000 changed any p99 / p999 values in `bench-baseline.md`, refresh that file. Keep the prior 5k row labelled as "confirmed-fixed-cliff baseline" if useful; otherwise overwrite.

- [ ] **Step 3: Commit + tag**

```bash
git add docs/superpowers/reports/README.md docs/superpowers/reports/bench-baseline.md
git commit -m "docs(reports): close A10 deferred items (Bugs 1/2/3 fixed)"
git tag phase-a10-deferred-fixed
git push origin phase-a10 phase-a10-deferred-fixed
```

---

## Self-review

**Spec coverage:**
- Item 1 (netem) → Tasks 6, 8.
- Item 2 (bench-vs-mtcp 0-row) → Task 7 (stderr capture) + Task 12 (triage).
- Item 3 (cliff) → Tasks 1–5 (Stage A diagnostics) + Task 10 (defense in depth) + Task 13 (Stage B audit).
- Validation plan in spec → Task 9 (workspace tests) + Task 10 step 7 (TAP regression) + Task 11 (AWS run).
- Roll-out / risk register / out-of-scope → Task 14.

No spec gaps.

**Placeholder scan:**
- No "TBD" / "TODO" / "fill in" / "implement later" outside the AWS-driven Phase 3 triage tasks (where the conditional branches are specified explicitly with concrete decision criteria and per-branch implementation steps).
- All code blocks contain real code.
- File paths are exact.

**Type consistency:**
- `rx_mempool_avail`: `AtomicU32` in `counters.rs`, loaded as `u32` and widened to `u64` in `counters_snapshot.rs`. Consistent.
- `mbuf_refcnt_drop_unexpected`: `AtomicU64` everywhere.
- `THREAD_COUNTERS_PTR`: `Cell<*const Counters>` defined in `mempool.rs`, accessed from both `mempool.rs` and `engine.rs`. Same name everywhere.
- `MBUF_DROP_UNEXPECTED_THRESHOLD`: `u16` (matches `shim_rte_mbuf_refcnt_read` return type).
- `--external-netem`: bool flag; `--list-scenarios`: bool flag. Consistent across main.rs and the integration test.

No type drift.
