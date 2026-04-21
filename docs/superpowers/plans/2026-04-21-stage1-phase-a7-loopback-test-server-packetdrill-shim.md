# Stage 1 Phase A7 — Loopback test server + packetdrill-shim Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the Stage 1 Layer B conformance gate — a minimal server FSM behind `--features test-server`, a test-only FFI surface, virtual-clock swap, a Luna-pattern packetdrill shim with in-memory frame hook, and a CI-gated runner over the ligurio corpus.

**Architecture:** Server FSM lives in-core with every hunk gated on `feature = "test-server"`. A second cbindgen config emits `include/dpdk_net_test.h` only under that feature. Under the same feature, `clock::now_ns()` is swapped at compile time for a thread-local `u64` driven by `dpdk_net_test_set_time_ns`. Upstream packetdrill is vendored at `third_party/packetdrill/` and patched through a small numbered series so its TUN/syscall layer calls the test-FFI. The runner crate `tools/packetdrill-shim-runner/` builds the patched binary via `build.rs` → `build.sh` and iterates the ligurio corpus with pinned runnable/skipped counts.

**Tech Stack:** Rust 2021 stable + cargo workspaces, DPDK 23.11, cbindgen 0.26, C (packetdrill + shim glue), autotools (packetdrill build), bash (scripts), `panic = abort`.

**Parent spec:** `docs/superpowers/specs/2026-04-21-stage1-phase-a7-loopback-test-server-packetdrill-shim-design.md`
**Branch:** `phase-a7` (currently at commit `50ddddb`, rebased on master `41fa4b7`)

---

## File Structure

**New files:**

- `crates/dpdk-net-core/src/test_server.rs` — `ListenSlot` + `Engine::listen / accept_next`, all `#[cfg(feature = "test-server")]`.
- `crates/dpdk-net-core/src/test_tx_intercept.rs` — thread-local TX-frame queue and `drain_tx_frames` accessor for shim use.
- `crates/dpdk-net/src/test_ffi.rs` — `dpdk_net_test_*` `extern "C"` entry points.
- `crates/dpdk-net/cbindgen-test.toml` — cbindgen config emitting `include/dpdk_net_test.h`.
- `crates/dpdk-net-core/tests/test_server_listen_accept_established.rs` — passive-open handshake integration test.
- `crates/dpdk-net-core/tests/test_server_passive_close.rs` — CLOSE_WAIT → LAST_ACK.
- `crates/dpdk-net-core/tests/test_server_active_close.rs` — FIN_WAIT_1 → TIME_WAIT from server side.
- `crates/dpdk-net-core/tests/virt_clock_monotonic.rs` — compile-time clock-swap unit test.
- `tools/packetdrill-shim/` (directory) — patch stack, `build.sh`, `SKIPPED.md`.
- `tools/packetdrill-shim/patches/0001-backend-in-memory.patch` through `0005-link-dpdk-net.patch`.
- `tools/packetdrill-shim/build.sh` — submodule init + patch apply + autotools + link.
- `tools/packetdrill-shim/SKIPPED.md` — per-script skip reason lines.
- `tools/packetdrill-shim/classify/ligurio.toml` — path-regex → `runnable | skipped-untranslatable | skipped-out-of-scope` table.
- `tools/packetdrill-shim-runner/Cargo.toml` — runner binary crate manifest.
- `tools/packetdrill-shim-runner/build.rs` — invokes `tools/packetdrill-shim/build.sh`.
- `tools/packetdrill-shim-runner/src/main.rs` — `run-one-script` CLI.
- `tools/packetdrill-shim-runner/src/lib.rs` — classifier, counts-loader, shim-invoker.
- `tools/packetdrill-shim-runner/tests/corpus_ligurio.rs` — main CI gate.
- `tools/packetdrill-shim-runner/tests/corpus_shivansh.rs` — `#[ignore]` in A7.
- `tools/packetdrill-shim-runner/tests/corpus_google.rs` — `#[ignore]` in A7.
- `tools/packetdrill-shim-runner/tests/our_scripts.rs` — project-local `.pkt`.
- `tools/packetdrill-shim-runner/tests/scripts/i8_multi_seg_fin_piggyback.pkt` — I-8 regression.
- `tools/packetdrill-shim-runner/tests/shim_smoke.rs` — 5-line `.pkt` end-to-end.
- `tools/packetdrill-shim-runner/tests/shim_inject_drain_roundtrip.rs` — inject SYN, drain SYN-ACK.
- `tools/packetdrill-shim-runner/tests/shim_virt_time_rto.rs` — virtual-time + timer-wheel determinism.
- `tools/packetdrill-shim-runner/tests/corpus-counts.rs` — `LIGURIO_RUNNABLE_COUNT` / `SKIP_*` constants.
- `scripts/a7-ligurio-gate.sh` — runs the full A7 CI job locally.
- `scripts/a7-perf-baseline.sh` — `bench_poll_empty` compare vs `phase-a6-6-7-complete`.
- `docs/superpowers/reviews/phase-a7-mtcp-compare.md` — populated by end-of-phase mTCP subagent.
- `docs/superpowers/reviews/phase-a7-rfc-compliance.md` — populated by end-of-phase RFC subagent.
- `.gitmodules` — add entries for `third_party/packetdrill` and `third_party/packetdrill-testcases`.

**Modified files:**

- `Cargo.toml` — add `tools/packetdrill-shim-runner` to workspace members.
- `crates/dpdk-net-core/Cargo.toml` — new `test-server` feature.
- `crates/dpdk-net-core/src/lib.rs` — `pub mod test_server` + `pub mod test_tx_intercept` (both feature-gated).
- `crates/dpdk-net-core/src/clock.rs` — cfg-swap for `now_ns`; add `set_virt_ns`.
- `crates/dpdk-net-core/src/tcp_input.rs` — passive-open dispatch hunk (feature-gated).
- `crates/dpdk-net-core/src/tcp_conn.rs` — `new_passive` constructor (feature-gated).
- `crates/dpdk-net-core/src/engine.rs` — `pub fn listen` / `accept_next` + TX intercept call site (feature-gated).
- `crates/dpdk-net-core/tests/knob-coverage-informational.txt` — add `test-server` entry.
- `crates/dpdk-net/Cargo.toml` — new `test-server` feature pass-through.
- `crates/dpdk-net/src/lib.rs` — `#[cfg(feature = "test-server")] pub mod test_ffi;`.
- `crates/dpdk-net/build.rs` — conditionally invoke cbindgen-test.toml when `CARGO_FEATURE_TEST_SERVER` set.
- `crates/dpdk-net/cbindgen.toml` — extend `exclude` with `dpdk_net_test_*` prefix.
- `docs/superpowers/plans/stage1-phase-roadmap.md` — flip A7 row to `Complete ✓` at end-of-phase.

**Files NOT touched:**

- `include/dpdk_net.h` — zero new symbols; header-drift CI verifies.
- `crates/dpdk-net-core/src/tcp_state.rs` — `Listen`/`SynReceived` enum variants already exist from A1.
- `crates/dpdk-net-core/src/flow_table.rs` — passive-open uses the same 4-tuple key.
- `crates/dpdk-net-core/src/tcp_output.rs` — existing SYN-ACK builder reached from passive direction unchanged.

---

## Task ordering rationale

Tasks 1–4 land scaffolding (submodules, cargo feature, virtual clock, TX intercept) that every later task depends on. Tasks 5–7 add the server FSM with one integration test per transition (pure Layer A, no shim yet). Task 8 adds the test-FFI + header-drift protection. Tasks 9–12 build the shim binary and validate it with three direct self-tests. Tasks 13–16 land the runner, classifier, corpus gate, and the I-8 regression. Task 17 wires CI + performance baseline + knob-coverage whitelist. Task 18 runs the end-of-phase review gates and places the tag.

---

## Preamble — a single setup commit

- [ ] **Step 1: Create a tracking commit noting what branch this plan runs on**

This isn't code — it's a marker so each task's commit history stays readable.

```bash
git log -1 --format='%h %s'
```
Expected output: `50ddddb a7 spec: loopback test server + packetdrill-shim design`

No commit here — the spec is already committed. Just confirming the starting point.

---

## Task 1: Vendor upstream packetdrill + ligurio corpus as submodules

**Files:**
- Modify: `.gitmodules`
- Create: `third_party/packetdrill/` (submodule, not a real file)
- Create: `third_party/packetdrill-testcases/` (submodule)

- [ ] **Step 1: Add the google/packetdrill submodule**

```bash
git submodule add https://github.com/google/packetdrill third_party/packetdrill
cd third_party/packetdrill
git checkout $(git rev-list --max-count=1 HEAD)   # pin to the tip at add-time
cd ../..
```

Expected: `.gitmodules` now has a `[submodule "third_party/packetdrill"]` entry.

- [ ] **Step 2: Record the pinned SHA for the roadmap**

```bash
(cd third_party/packetdrill && git rev-parse HEAD) > /tmp/packetdrill-sha
cat /tmp/packetdrill-sha
```
Expected: a 40-char hex SHA.

- [ ] **Step 3: Add the ligurio/packetdrill-testcases submodule**

```bash
git submodule add https://github.com/ligurio/packetdrill-testcases third_party/packetdrill-testcases
cd third_party/packetdrill-testcases
git checkout $(git rev-list --max-count=1 HEAD)
cd ../..
(cd third_party/packetdrill-testcases && git rev-parse HEAD) > /tmp/ligurio-sha
cat /tmp/ligurio-sha
```

- [ ] **Step 4: Verify both submodules init/update cleanly from scratch**

```bash
git submodule deinit -f third_party/packetdrill third_party/packetdrill-testcases
git submodule update --init --recursive third_party/packetdrill third_party/packetdrill-testcases
ls third_party/packetdrill/packetdrill.c | head -1
ls third_party/packetdrill-testcases/README* | head -1
```
Expected: both paths exist and contain their expected files.

- [ ] **Step 5: Commit**

```bash
git add .gitmodules third_party/packetdrill third_party/packetdrill-testcases
git commit -m "a7 task 1: vendor packetdrill + ligurio corpus as submodules"
```

---

## Task 2: Add the `test-server` cargo feature on both crates (no code yet)

**Files:**
- Modify: `crates/dpdk-net-core/Cargo.toml`
- Modify: `crates/dpdk-net/Cargo.toml`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Write a failing verification test**

Create `crates/dpdk-net-core/tests/test_server_feature_compiles.rs`:

```rust
//! Compile-only sanity: with `--features test-server`, the feature-gated
//! hooks compile, and without it the default build is unchanged.

#[cfg(feature = "test-server")]
#[test]
fn test_server_feature_is_on() {
    // Feature-gate path — if this compiles under --features test-server,
    // later tasks' #[cfg(feature = "test-server")] hunks will compile too.
    let _ = dpdk_net_core::tcp_state::TcpState::Listen;
}

#[cfg(not(feature = "test-server"))]
#[test]
fn default_build_compiles() {
    let _ = dpdk_net_core::tcp_state::TcpState::Closed;
}
```

- [ ] **Step 2: Run it; should pass trivially now (default build)**

```bash
cargo test -p dpdk-net-core --test test_server_feature_compiles
```
Expected: one test passes (`default_build_compiles`).

- [ ] **Step 3: Add the feature to `crates/dpdk-net-core/Cargo.toml`**

After the existing `hw-offloads-all` block, insert:

```toml
# A7: gates the test-only server FSM (src/test_server.rs), the virtual
# clock swap in clock.rs, and the TX-intercept shim in test_tx_intercept.rs.
# Never on in production builds.
test-server = []
```

- [ ] **Step 4: Add the feature pass-through to `crates/dpdk-net/Cargo.toml`**

Under the existing `[features]` block:

```toml
# A7: enables the test-only FFI surface (src/test_ffi.rs) and pass-through
# to dpdk-net-core's test-server feature.
test-server = ["dpdk-net-core/test-server"]
```

- [ ] **Step 5: Run with the feature on**

```bash
cargo test -p dpdk-net-core --features test-server --test test_server_feature_compiles
```
Expected: one test passes (`test_server_feature_is_on`).

- [ ] **Step 6: Verify the default build is still clean**

```bash
cargo build -p dpdk-net-core
cargo build -p dpdk-net
```
Expected: no errors; `include/dpdk_net.h` unchanged.

- [ ] **Step 7: Commit**

```bash
git add crates/dpdk-net-core/Cargo.toml crates/dpdk-net/Cargo.toml \
        crates/dpdk-net-core/tests/test_server_feature_compiles.rs
git commit -m "a7 task 2: test-server cargo feature (no code yet)"
```

---

## Task 3: Virtual-clock compile-time swap in `clock.rs`

**Files:**
- Modify: `crates/dpdk-net-core/src/clock.rs`
- Create: `crates/dpdk-net-core/tests/virt_clock_monotonic.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/dpdk-net-core/tests/virt_clock_monotonic.rs`:

```rust
#![cfg(feature = "test-server")]

use dpdk_net_core::clock::{now_ns, set_virt_ns};

#[test]
fn set_then_read_matches() {
    set_virt_ns(12_345);
    assert_eq!(now_ns(), 12_345);
}

#[test]
fn monotonic_advance_allowed() {
    set_virt_ns(0);
    set_virt_ns(100);
    set_virt_ns(100);
    set_virt_ns(100_000_000_000);
    assert_eq!(now_ns(), 100_000_000_000);
}

#[test]
#[should_panic(expected = "virtual clock must be monotonic")]
fn non_monotonic_set_panics() {
    set_virt_ns(200);
    set_virt_ns(100);
}

#[test]
fn per_thread_independence() {
    use std::thread;
    set_virt_ns(1000);
    let h = thread::spawn(|| {
        set_virt_ns(0);
        set_virt_ns(50);
        assert_eq!(now_ns(), 50);
    });
    h.join().unwrap();
    assert_eq!(now_ns(), 1000);
}
```

- [ ] **Step 2: Run — should fail (symbols undefined)**

```bash
cargo test -p dpdk-net-core --features test-server --test virt_clock_monotonic
```
Expected: build error, `cannot find function 'set_virt_ns' in crate 'dpdk_net_core::clock'`.

- [ ] **Step 3: Implement the cfg-swap in `clock.rs`**

At the top of `crates/dpdk-net-core/src/clock.rs`, after the existing `use` lines, add:

```rust
#[cfg(feature = "test-server")]
use std::cell::Cell;
```

Replace the existing `now_ns` fn:

```rust
#[cfg(not(feature = "test-server"))]
#[inline]
pub fn now_ns() -> u64 {
    let e = tsc_epoch();
    let delta = rdtsc().wrapping_sub(e.tsc0);
    let scaled = ((delta as u128) * (e.ns_per_tsc_scaled as u128)) >> 32;
    e.t0_ns + scaled as u64
}

#[cfg(feature = "test-server")]
thread_local! {
    static VIRT_NS: Cell<u64> = const { Cell::new(0) };
}

#[cfg(feature = "test-server")]
#[inline]
pub fn now_ns() -> u64 {
    VIRT_NS.with(|c| c.get())
}

/// Set the thread-local virtual clock. Monotonicity is enforced per-thread:
/// a call with `ns < current` panics.
#[cfg(feature = "test-server")]
pub fn set_virt_ns(ns: u64) {
    VIRT_NS.with(|c| {
        let prev = c.get();
        assert!(ns >= prev, "virtual clock must be monotonic");
        c.set(ns);
    });
}
```

- [ ] **Step 4: Run the feature-on test**

```bash
cargo test -p dpdk-net-core --features test-server --test virt_clock_monotonic
```
Expected: all four tests pass.

- [ ] **Step 5: Verify default build is still bit-identical**

```bash
cargo build -p dpdk-net-core
cargo test -p dpdk-net-core --lib
```
Expected: no errors; no behavioral change in the rdtsc path.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/clock.rs \
        crates/dpdk-net-core/tests/virt_clock_monotonic.rs
git commit -m "a7 task 3: virtual-clock cfg-swap under test-server feature"
```

---

## Task 4: TX frame intercept under `test-server`

**Files:**
- Create: `crates/dpdk-net-core/src/test_tx_intercept.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`
- Modify: `crates/dpdk-net-core/src/engine.rs` (three TX sites)

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/tests/virt_clock_monotonic.rs`:

```rust
#[test]
fn tx_intercept_push_drain_roundtrip() {
    use dpdk_net_core::test_tx_intercept::{push_tx_frame, drain_tx_frames};
    // Fresh queue.
    let drained_before = drain_tx_frames();
    assert_eq!(drained_before.len(), 0);

    push_tx_frame(b"abc".to_vec());
    push_tx_frame(b"de".to_vec());

    let drained = drain_tx_frames();
    assert_eq!(drained.len(), 2);
    assert_eq!(&*drained[0], b"abc");
    assert_eq!(&*drained[1], b"de");

    // After drain the queue is empty.
    let after = drain_tx_frames();
    assert_eq!(after.len(), 0);
}
```

- [ ] **Step 2: Run — fails on missing module**

```bash
cargo test -p dpdk-net-core --features test-server --test virt_clock_monotonic
```
Expected: `cannot find module 'test_tx_intercept'`.

- [ ] **Step 3: Create the intercept module**

Create `crates/dpdk-net-core/src/test_tx_intercept.rs`:

```rust
//! A7: TX frame intercept for the packetdrill-shim.
//!
//! Under `--features test-server`, every place the engine would call
//! `rte_eth_tx_burst` copies the outbound frame's bytes into a
//! thread-local queue instead. The shim drains that queue between
//! script steps via `dpdk_net_test_drain_tx_frames`.

use std::cell::RefCell;

thread_local! {
    static TX_QUEUE: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Push a copy of one outbound frame onto the thread-local queue.
pub fn push_tx_frame(bytes: Vec<u8>) {
    TX_QUEUE.with(|q| q.borrow_mut().push(bytes));
}

/// Drain every pending frame. Resets the queue.
pub fn drain_tx_frames() -> Vec<Vec<u8>> {
    TX_QUEUE.with(|q| std::mem::take(&mut *q.borrow_mut()))
}

/// Cheap test predicate: is the queue empty right now?
pub fn is_empty() -> bool {
    TX_QUEUE.with(|q| q.borrow().is_empty())
}
```

- [ ] **Step 4: Wire the module into `lib.rs`**

In `crates/dpdk-net-core/src/lib.rs`, near the other `pub mod` lines, add:

```rust
#[cfg(feature = "test-server")]
pub mod test_tx_intercept;
```

- [ ] **Step 5: Re-run — intercept test passes; engine TX intercept not wired yet**

```bash
cargo test -p dpdk-net-core --features test-server --test virt_clock_monotonic
```
Expected: all five tests pass.

- [ ] **Step 6: Wire intercept into the three `shim_rte_eth_tx_burst` call sites in `engine.rs`**

Grep for the call sites:

```bash
grep -n 'shim_rte_eth_tx_burst' crates/dpdk-net-core/src/engine.rs
```
Expected: three lines (around 1601, 1669, 1713 — confirm actual line numbers).

At each of those three sites, wrap the call. Example for the first site:

```rust
// Before:
unsafe {
    sys::shim_rte_eth_tx_burst(self.cfg.port_id, self.cfg.tx_queue_id, pkts.as_mut_ptr(), 1)
}

// After:
#[cfg(feature = "test-server")]
{
    // Copy the frame bytes out of the mbuf, push to the intercept
    // queue, and free the mbuf; do NOT call into the PMD.
    let m = pkts[0];
    let len = unsafe { (*m).pkt_len as usize };
    let data = unsafe { (*m).buf_addr.add((*m).data_off as usize) as *const u8 };
    let mut bytes = Vec::with_capacity(len);
    unsafe {
        std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), len);
        bytes.set_len(len);
    }
    crate::test_tx_intercept::push_tx_frame(bytes);
    unsafe { sys::shim_rte_pktmbuf_free(m) };
    1u16  // report "1 packet sent" to keep control flow identical
}
#[cfg(not(feature = "test-server"))]
unsafe {
    sys::shim_rte_eth_tx_burst(self.cfg.port_id, self.cfg.tx_queue_id, pkts.as_mut_ptr(), 1)
}
```

Repeat at the other two sites. If a site is the batched drain in `rx_burst` handling that sends multiple pkts in one call, iterate over the slice:

```rust
#[cfg(feature = "test-server")]
{
    let nb = pkts_to_send as usize;
    for i in 0..nb {
        let m = pkts[i];
        let len = unsafe { (*m).pkt_len as usize };
        let data = unsafe { (*m).buf_addr.add((*m).data_off as usize) as *const u8 };
        let mut bytes = Vec::with_capacity(len);
        unsafe {
            std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), len);
            bytes.set_len(len);
        }
        crate::test_tx_intercept::push_tx_frame(bytes);
        unsafe { sys::shim_rte_pktmbuf_free(m) };
    }
    nb as u16
}
#[cfg(not(feature = "test-server"))]
unsafe {
    sys::shim_rte_eth_tx_burst(
        self.cfg.port_id, self.cfg.tx_queue_id,
        pkts.as_mut_ptr(), pkts_to_send,
    )
}
```

- [ ] **Step 7: Verify default build is unchanged**

```bash
cargo build -p dpdk-net-core --release
cargo test -p dpdk-net-core --lib --release
```
Expected: no errors; existing tests still pass.

- [ ] **Step 8: Verify the feature-on build still compiles**

```bash
cargo build -p dpdk-net-core --features test-server --release
cargo test -p dpdk-net-core --features test-server --test virt_clock_monotonic
```
Expected: build clean; all five tests pass.

- [ ] **Step 9: Commit**

```bash
git add crates/dpdk-net-core/src/test_tx_intercept.rs \
        crates/dpdk-net-core/src/lib.rs \
        crates/dpdk-net-core/src/engine.rs \
        crates/dpdk-net-core/tests/virt_clock_monotonic.rs
git commit -m "a7 task 4: TX-frame intercept under test-server feature"
```

---

## Task 5: Server FSM — passive-open handshake (LISTEN → SYN_RCVD → ESTABLISHED)

**Files:**
- Create: `crates/dpdk-net-core/src/test_server.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`
- Modify: `crates/dpdk-net-core/src/engine.rs`
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs`
- Modify: `crates/dpdk-net-core/src/tcp_input.rs`
- Create: `crates/dpdk-net-core/tests/test_server_listen_accept_established.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/dpdk-net-core/tests/test_server_listen_accept_established.rs`:

```rust
#![cfg(feature = "test-server")]
//! A7 Task 5: passive-open handshake.
//! Listen → inject SYN → drain SYN-ACK → inject final ACK →
//! accept_next returns an ESTABLISHED handle.

mod common;

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::tcp_state::TcpState;
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

#[test]
fn listen_accept_established_via_in_memory_injection() {
    // Fresh virtual clock. Helpers construct an in-memory-only engine
    // with TAP-like zeroed port config suitable for packet injection.
    set_virt_ns(0);
    eal_init(&common::test_eal_args()).expect("eal init");
    let mut eng = Engine::new(common::test_server_config()).expect("engine");

    let listen_h = eng.listen(common::OUR_IP, 5555).expect("listen");

    // Client sends SYN.
    set_virt_ns(1_000_000);
    let syn = common::build_tcp_syn(
        common::PEER_IP, /*src_port*/ 40000,
        common::OUR_IP,  /*dst_port*/ 5555,
        /*iss_peer*/ 0x10000000,
    );
    eng.inject_rx_frame(&syn).expect("inject syn");

    // Drain TX; expect one SYN-ACK.
    let frames = drain_tx_frames();
    assert_eq!(frames.len(), 1, "expected exactly one SYN-ACK on the wire");
    let (seq_iss_ours, ack_returned) = common::parse_syn_ack(&frames[0]);
    assert_eq!(ack_returned, 0x10000001);

    // Client sends final ACK.
    set_virt_ns(2_000_000);
    let final_ack = common::build_tcp_ack(
        common::PEER_IP, 40000,
        common::OUR_IP,  5555,
        /*seq*/ 0x10000001,
        /*ack*/ seq_iss_ours.wrapping_add(1),
    );
    eng.inject_rx_frame(&final_ack).expect("inject final ack");

    // Drain any trailing frames (none expected).
    let trailing = drain_tx_frames();
    assert!(trailing.is_empty(), "no TX expected after final ACK");

    // accept_next returns the ESTABLISHED conn.
    let conn_h = eng.accept_next(listen_h).expect("accept_next");
    let state = eng.state_of(conn_h).expect("state_of");
    assert_eq!(state, TcpState::Established);
}
```

Make sure `crates/dpdk-net-core/tests/common/mod.rs` already exists (confirmed during exploration — it does). Append helpers (the current common module does not yet have packet-build helpers, so add them directly — no dependency on any pre-existing `common_tcp::build_tcp_frame`):

```rust
// ---- A7 additions: test-server in-memory rig helpers ----

pub const OUR_IP:   u32 = 0x0a630a02; // 10.99.10.2
pub const PEER_IP:  u32 = 0x0a630a01; // 10.99.10.1

#[cfg(feature = "test-server")]
pub fn test_eal_args() -> Vec<&'static str> {
    vec!["dpdk_net", "--no-pci", "--no-huge", "-m", "64", "--iova-mode=va"]
}

#[cfg(feature = "test-server")]
pub fn test_server_config() -> dpdk_net_core::engine::EngineConfig {
    use dpdk_net_core::engine::EngineConfig;
    let mut cfg = EngineConfig::default();
    cfg.local_ip = OUR_IP;
    cfg.gateway_ip = PEER_IP;
    cfg.gateway_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    cfg.port_id = u16::MAX;  // test-server short-circuits port config
    cfg
}

#[cfg(feature = "test-server")]
fn ip_csum(hdr: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in hdr.chunks(2) {
        let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) as u32 }
                else { (c[0] as u32) << 8 };
        s = s + w;
    }
    while (s >> 16) != 0 { s = (s & 0xffff) + (s >> 16); }
    !(s as u16)
}

#[cfg(feature = "test-server")]
fn tcp_csum(src_ip: u32, dst_ip: u32, tcp: &[u8]) -> u16 {
    // Pseudo-header + TCP segment one's-complement sum.
    let mut s: u32 = 0;
    s += (src_ip >> 16) & 0xffff; s += src_ip & 0xffff;
    s += (dst_ip >> 16) & 0xffff; s += dst_ip & 0xffff;
    s += 6u32;                    // protocol
    s += tcp.len() as u32;
    for c in tcp.chunks(2) {
        let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) as u32 }
                else { (c[0] as u32) << 8 };
        s += w;
    }
    while (s >> 16) != 0 { s = (s & 0xffff) + (s >> 16); }
    !(s as u16)
}

#[cfg(feature = "test-server")]
fn build_tcp_frame(
    src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16,
    seq: u32, ack: u32, flags: u8, window: u16, payload: &[u8],
    mss: Option<u16>, wscale: Option<u8>, sack_ok: bool,
    ts_val: Option<u32>, ts_ecr: Option<u32>,
) -> Vec<u8> {
    // 14 byte Ethernet + 20 IP + (20 + optlen) TCP + payload.
    let mut opts: Vec<u8> = Vec::new();
    if let Some(mss) = mss { opts.push(2); opts.push(4);
        opts.extend_from_slice(&mss.to_be_bytes()); }
    if sack_ok { opts.push(4); opts.push(2); }
    if let (Some(tv), Some(te)) = (ts_val, ts_ecr) {
        opts.push(1); opts.push(1);
        opts.push(8); opts.push(10);
        opts.extend_from_slice(&tv.to_be_bytes());
        opts.extend_from_slice(&te.to_be_bytes());
    }
    if let Some(ws) = wscale { opts.push(1); opts.push(3); opts.push(3); opts.push(ws); }
    while opts.len() % 4 != 0 { opts.push(1); } // NOP pad.

    let tcp_hdr_len = 20 + opts.len();
    let ip_len = 20 + tcp_hdr_len + payload.len();
    let total = 14 + ip_len;
    let mut f = vec![0u8; total];

    // Ethernet: dst = local mac (zero), src = peer mac (zero), type = 0x0800
    f[12] = 0x08; f[13] = 0x00;

    // IPv4
    f[14] = 0x45;  // v=4, ihl=5
    f[15] = 0;     // dscp
    f[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
    f[18..20].copy_from_slice(&0u16.to_be_bytes());  // id
    f[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    f[22] = 64;    // ttl
    f[23] = 6;     // TCP
    f[26..30].copy_from_slice(&src_ip.to_be_bytes());
    f[30..34].copy_from_slice(&dst_ip.to_be_bytes());
    let csum = ip_csum(&f[14..34]);
    f[24..26].copy_from_slice(&csum.to_be_bytes());

    // TCP
    let t = 34;
    f[t..t+2].copy_from_slice(&src_port.to_be_bytes());
    f[t+2..t+4].copy_from_slice(&dst_port.to_be_bytes());
    f[t+4..t+8].copy_from_slice(&seq.to_be_bytes());
    f[t+8..t+12].copy_from_slice(&ack.to_be_bytes());
    f[t+12] = ((tcp_hdr_len / 4) << 4) as u8;
    f[t+13] = flags;
    f[t+14..t+16].copy_from_slice(&window.to_be_bytes());
    f[t+20..t+20+opts.len()].copy_from_slice(&opts);
    f[t+20+opts.len()..t+20+opts.len()+payload.len()].copy_from_slice(payload);
    let tcp_csum = tcp_csum(src_ip, dst_ip, &f[t..t+tcp_hdr_len+payload.len()]);
    f[t+16..t+18].copy_from_slice(&tcp_csum.to_be_bytes());
    f
}

#[cfg(feature = "test-server")]
pub fn build_tcp_syn(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16, iss: u32) -> Vec<u8> {
    build_tcp_frame(src_ip, src_port, dst_ip, dst_port, iss, 0,
        0x02, 65535, &[], Some(1460), Some(7), true, Some(1), Some(0))
}

#[cfg(feature = "test-server")]
pub fn build_tcp_ack(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16,
                    seq: u32, ack: u32) -> Vec<u8> {
    build_tcp_frame(src_ip, src_port, dst_ip, dst_port, seq, ack,
        0x10, 65535, &[], None, None, false, Some(100), Some(1))
}

#[cfg(feature = "test-server")]
pub fn build_tcp_fin(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16,
                    seq: u32, ack: u32) -> Vec<u8> {
    // FIN+ACK (0x11).
    build_tcp_frame(src_ip, src_port, dst_ip, dst_port, seq, ack,
        0x11, 65535, &[], None, None, false, Some(100), Some(1))
}

#[cfg(feature = "test-server")]
pub fn parse_syn_ack(frame: &[u8]) -> (u32, u32) {
    let ip_ihl = (frame[14] & 0x0f) as usize * 4;
    let tcp = &frame[14 + ip_ihl..];
    let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
    let ack = u32::from_be_bytes(tcp[8..12].try_into().unwrap());
    assert_eq!(tcp[13] & 0x12, 0x12, "expected SYN+ACK flags set");
    (seq, ack)
}

#[cfg(feature = "test-server")]
pub fn parse_tcp_seq_ack(frame: &[u8]) -> (u32, u32) {
    let ip_ihl = (frame[14] & 0x0f) as usize * 4;
    let tcp = &frame[14 + ip_ihl..];
    let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
    let ack = u32::from_be_bytes(tcp[8..12].try_into().unwrap());
    (seq, ack)
}

#[cfg(feature = "test-server")]
pub fn drive_passive_handshake(
    eng: &mut dpdk_net_core::engine::Engine,
    listen_h: dpdk_net_core::test_server::ListenHandle,
) -> (dpdk_net_core::flow_table::ConnHandle, u32) {
    use dpdk_net_core::clock::set_virt_ns;
    use dpdk_net_core::test_tx_intercept::drain_tx_frames;
    set_virt_ns(1_000_000);
    let syn = build_tcp_syn(PEER_IP, 40000, OUR_IP, 5555, 0x10000000);
    eng.inject_rx_frame(&syn).unwrap();
    let frames = drain_tx_frames();
    assert_eq!(frames.len(), 1);
    let (our_iss, _) = parse_syn_ack(&frames[0]);
    set_virt_ns(2_000_000);
    let final_ack = build_tcp_ack(PEER_IP, 40000, OUR_IP, 5555,
        0x10000001, our_iss.wrapping_add(1));
    eng.inject_rx_frame(&final_ack).unwrap();
    let conn = eng.accept_next(listen_h).expect("accept");
    (conn, our_iss)
}
```

- [ ] **Step 2: Run — fails (no `listen`, no `test_server` module, no `inject_rx_frame`)**

```bash
cargo test -p dpdk-net-core --features test-server \
    --test test_server_listen_accept_established
```
Expected: build errors on missing symbols.

- [ ] **Step 3: Add `Engine::inject_rx_frame`**

Before implementing server FSM, add the test-only RX injection path. In `engine.rs`, under `impl Engine`, inside a `#[cfg(feature = "test-server")]` block:

```rust
#[cfg(feature = "test-server")]
impl Engine {
    /// Test-only: feed one raw Ethernet frame through the normal
    /// l2 → l3 → tcp_input path. The caller is responsible for frame
    /// correctness; no hardware is involved.
    pub fn inject_rx_frame(&self, frame: &[u8]) -> Result<(), crate::Error> {
        // Allocate a TX-hdr mbuf-sized packet from the RX pool.
        let m = unsafe { sys::shim_rte_pktmbuf_alloc(self.rx_mempool.ptr()) };
        if m.is_null() {
            return Err(crate::Error::MempoolExhausted);
        }
        unsafe {
            let dst = (*m).buf_addr.add((*m).data_off as usize) as *mut u8;
            std::ptr::copy_nonoverlapping(frame.as_ptr(), dst, frame.len());
            (*m).pkt_len = frame.len() as u32;
            (*m).data_len = frame.len() as u16;
            (*m).nb_segs = 1;
            (*m).next = std::ptr::null_mut();
        }
        // One-frame burst through the existing RX handler.
        let mut pkts = [m];
        self.handle_rx_burst(&mut pkts, 1);
        Ok(())
    }
}
```

Use whatever the existing method on `Engine` is named for "process an RX burst starting from a pre-populated mbuf array". If no such method is exposed at this visibility, add a `pub(crate) fn handle_rx_burst(...)` that wraps the body of `poll_once` from just after the `rx_burst` call.

- [ ] **Step 4: Create `test_server.rs`**

```rust
//! A7: minimal server-FSM support behind the `test-server` feature.
//!
//! A `ListenSlot` holds a single local (ip, port) and an at-most-one
//! accept queue. `tcp_input` dispatches inbound SYNs whose dst-(ip,port)
//! matches a ListenSlot into `handle_inbound_syn_listen`, which allocates
//! a per-conn slot in SYN_RCVD, emits SYN-ACK via the existing builder,
//! and parks it until the final ACK arrives.

use crate::flow_table::ConnHandle;

#[derive(Debug)]
pub struct ListenSlot {
    pub local_ip: u32,
    pub local_port: u16,
    /// At most one queued ESTABLISHED handle waiting on accept_next.
    pub accept_queue: Option<ConnHandle>,
    /// An in-progress SYN_RCVD handle tied to this listen; cleared when
    /// the final ACK transitions it to ESTABLISHED.
    pub in_progress: Option<ConnHandle>,
}

pub type ListenHandle = u32;

impl ListenSlot {
    pub fn new(local_ip: u32, local_port: u16) -> Self {
        Self { local_ip, local_port, accept_queue: None, in_progress: None }
    }
}
```

Wire into `crates/dpdk-net-core/src/lib.rs`:

```rust
#[cfg(feature = "test-server")]
pub mod test_server;
```

- [ ] **Step 5: Add `Engine::listen` + `accept_next`**

In `engine.rs`, inside the existing `#[cfg(feature = "test-server")] impl Engine`:

```rust
#[cfg(feature = "test-server")]
impl Engine {
    pub fn listen(&mut self, ip: u32, port: u16)
        -> Result<crate::test_server::ListenHandle, crate::Error>
    {
        if self.listen_slots.iter().any(|(_, s)| s.local_ip == ip && s.local_port == port) {
            return Err(crate::Error::InvalidArgument);
        }
        let h: crate::test_server::ListenHandle = self.next_listen_id;
        self.next_listen_id = self.next_listen_id.checked_add(1)
            .ok_or(crate::Error::InvalidArgument)?;
        self.listen_slots.push((h, crate::test_server::ListenSlot::new(ip, port)));
        Ok(h)
    }

    pub fn accept_next(&mut self, h: crate::test_server::ListenHandle)
        -> Option<ConnHandle>
    {
        let slot = self.listen_slots.iter_mut().find(|(k, _)| *k == h)?;
        slot.1.accept_queue.take()
    }
}
```

Add fields to `struct Engine` (guarded):

```rust
#[cfg(feature = "test-server")]
listen_slots: Vec<(crate::test_server::ListenHandle, crate::test_server::ListenSlot)>,
#[cfg(feature = "test-server")]
next_listen_id: crate::test_server::ListenHandle,
```

Initialize them in `Engine::new`:

```rust
#[cfg(feature = "test-server")]
listen_slots: Vec::new(),
#[cfg(feature = "test-server")]
next_listen_id: 1,
```

- [ ] **Step 6: Add passive-open dispatch in `tcp_input.rs`**

Find the top of the TCP input handler where the 4-tuple flow-table lookup happens. Immediately before that lookup, add:

```rust
#[cfg(feature = "test-server")]
{
    if (tcp_flags & TH_SYN != 0) && (tcp_flags & TH_ACK == 0) {
        // Unsolicited SYN — check ListenSlots by dst-(ip,port).
        let dst_ip = ip_dst;
        let dst_port = tcp_dst_port;
        if let Some(listen_h) = self.match_listen_slot(dst_ip, dst_port) {
            self.handle_inbound_syn_listen(
                listen_h, ip_src, tcp_src_port, seq, tcp_options, now_ns,
            )?;
            return Ok(());
        }
    }
}
```

Add `match_listen_slot` + `handle_inbound_syn_listen` as new private methods on `Engine` (also feature-gated):

```rust
#[cfg(feature = "test-server")]
fn match_listen_slot(&self, dst_ip: u32, dst_port: u16)
    -> Option<crate::test_server::ListenHandle>
{
    self.listen_slots.iter()
        .find(|(_, s)| s.local_ip == dst_ip && s.local_port == dst_port)
        .map(|(h, _)| *h)
}

#[cfg(feature = "test-server")]
fn handle_inbound_syn_listen(
    &mut self,
    listen_h: crate::test_server::ListenHandle,
    peer_ip: u32, peer_port: u16,
    iss_peer: u32,
    opts: ParsedTcpOptions,
    now_ns: u64,
) -> Result<(), crate::Error> {
    // Reject if an accept is already queued AND an in-progress SYN_RCVD
    // exists (size-1 queue).
    let slot = self.listen_slots.iter()
        .find(|(k, _)| *k == listen_h)
        .map(|(_, s)| s)
        .ok_or(crate::Error::InvalidArgument)?;
    if slot.accept_queue.is_some() || slot.in_progress.is_some() {
        // Emit RST per minimal-server policy.
        self.emit_rst_for_unsolicited_syn(peer_ip, peer_port, iss_peer)?;
        return Ok(());
    }

    // Allocate per-conn slot in SYN_RCVD.
    let tuple = crate::flow_table::FourTuple {
        local_ip: slot.local_ip, local_port: slot.local_port,
        peer_ip, peer_port,
    };
    let conn = crate::tcp_conn::TcpConn::new_passive(
        tuple, iss_peer, opts, self.cfg.tcp_mss, now_ns,
        self.cfg.recv_buffer_bytes, self.cfg.send_buffer_bytes,
        self.cfg.tcp_min_rto_us, self.cfg.tcp_initial_rto_us,
        self.cfg.tcp_max_rto_us,
    );
    let h = self.flow_table.insert(conn).ok_or(crate::Error::FlowTableFull)?;

    // Mark as in-progress on the listen slot.
    {
        let slot = self.listen_slots.iter_mut()
            .find(|(k, _)| *k == listen_h).unwrap();
        slot.1.in_progress = Some(h);
    }

    // Emit SYN-ACK (reuses the existing builder in tcp_output).
    self.emit_syn_ack(h, now_ns)?;
    Ok(())
}
```

- [ ] **Step 7: Add the `new_passive` constructor in `tcp_conn.rs`**

Mirror `new_client`'s signature. In `tcp_conn.rs`, inside `impl TcpConn`:

```rust
#[cfg(feature = "test-server")]
pub fn new_passive(
    tuple: FourTuple,
    iss_peer: u32,
    opts: crate::tcp_options::ParsedTcpOptions,
    mss: u32,
    now_ns: u64,
    recv_buffer_bytes: u32,
    send_buffer_bytes: u32,
    min_rto_us: u64,
    initial_rto_us: u64,
    max_rto_us: u64,
) -> Self {
    let iss_us = crate::iss::iss_for_tuple(&tuple, now_ns);
    let mut c = Self::new_client(
        tuple, iss_us, mss, recv_buffer_bytes, send_buffer_bytes,
        min_rto_us, initial_rto_us, max_rto_us,
    );
    c.state = crate::tcp_state::TcpState::SynReceived;
    c.rcv_nxt = iss_peer.wrapping_add(1);
    c.snd_una = iss_us;
    c.snd_nxt = iss_us;        // SYN-ACK will bump +1 when emitted
    c.peer_mss = opts.mss.unwrap_or(536);
    c.peer_wscale = opts.wscale.unwrap_or(0);
    c.peer_sack_ok = opts.sack_ok;
    c.peer_ts = opts.ts_val;
    c
}
```

Also add passive-open transition in the final-ACK handler: where `tcp_input` currently handles the ACK of a SYN_SENT (active open) → ESTABLISHED, add a parallel arm for SYN_RCVD → ESTABLISHED that:

```rust
#[cfg(feature = "test-server")]
TcpState::SynReceived => {
    if flags & TH_ACK != 0 && ack == conn.snd_nxt {
        conn.state = TcpState::Established;
        // Hand off to the listen slot's accept queue.
        if let Some((_, slot)) = self.listen_slots.iter_mut()
            .find(|(_, s)| s.in_progress == Some(handle))
        {
            slot.in_progress = None;
            slot.accept_queue = Some(handle);
        }
    }
}
```

- [ ] **Step 8: Add `Engine::state_of` helper (trivial)**

In `engine.rs`:

```rust
#[cfg(feature = "test-server")]
pub fn state_of(&self, h: ConnHandle) -> Option<crate::tcp_state::TcpState> {
    self.flow_table.get(h).map(|c| c.state)
}
```

- [ ] **Step 9: Run the test**

```bash
cargo test -p dpdk-net-core --features test-server \
    --test test_server_listen_accept_established -- --nocapture
```
Expected: test passes.

- [ ] **Step 10: Verify default build still clean**

```bash
cargo build -p dpdk-net-core
cargo test -p dpdk-net-core --lib
```

- [ ] **Step 11: Commit**

```bash
git add crates/dpdk-net-core/src/test_server.rs \
        crates/dpdk-net-core/src/lib.rs \
        crates/dpdk-net-core/src/engine.rs \
        crates/dpdk-net-core/src/tcp_conn.rs \
        crates/dpdk-net-core/src/tcp_input.rs \
        crates/dpdk-net-core/tests/common/mod.rs \
        crates/dpdk-net-core/tests/test_server_listen_accept_established.rs
git commit -m "a7 task 5: server FSM passive-open (LISTEN→SYN_RCVD→ESTABLISHED)"
```

---

## Task 6: Server FSM — passive close (CLOSE_WAIT → LAST_ACK)

**Files:**
- Create: `crates/dpdk-net-core/tests/test_server_passive_close.rs`
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` (if any transition is missing)

- [ ] **Step 1: Write the failing test**

```rust
#![cfg(feature = "test-server")]
//! A7 Task 6: passive close path — peer sends FIN first, server
//! transitions CLOSE_WAIT → LAST_ACK on its own close() call, then
//! ESTABLISHED → CLOSED after peer's final ACK. Server is passive,
//! so no TIME_WAIT on our side.

mod common;
use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine};
use dpdk_net_core::tcp_state::TcpState;
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

#[test]
fn passive_close_path() {
    set_virt_ns(0);
    eal_init(&common::test_eal_args()).unwrap();
    let mut eng = Engine::new(common::test_server_config()).unwrap();
    let lh = eng.listen(common::OUR_IP, 5555).unwrap();

    let (conn_h, _snd_iss) = common::drive_passive_handshake(&mut eng, lh);
    let _ = drain_tx_frames();

    // Peer FINs first.
    set_virt_ns(10_000_000);
    let fin = common::build_tcp_fin(common::PEER_IP, 40000, common::OUR_IP, 5555,
                                    /*seq*/ 0x10000001, /*ack*/ _snd_iss.wrapping_add(1));
    eng.inject_rx_frame(&fin).unwrap();

    // Server ACKs the FIN; state CLOSE_WAIT.
    let after_fin = drain_tx_frames();
    assert_eq!(after_fin.len(), 1, "bare ACK for FIN expected");
    assert_eq!(eng.state_of(conn_h).unwrap(), TcpState::CloseWait);

    // Server closes.
    set_virt_ns(20_000_000);
    eng.close(conn_h, 0).unwrap();
    assert_eq!(eng.state_of(conn_h).unwrap(), TcpState::LastAck);

    // Peer's final ACK.
    set_virt_ns(30_000_000);
    let our_fin_seq = _snd_iss.wrapping_add(1);
    let final_ack = common::build_tcp_ack(common::PEER_IP, 40000,
        common::OUR_IP, 5555,
        /*seq*/ 0x10000002,
        /*ack*/ our_fin_seq.wrapping_add(1));
    eng.inject_rx_frame(&final_ack).unwrap();

    // Conn is cleaned up; no TIME_WAIT on the server side.
    assert!(eng.state_of(conn_h).is_none(),
        "conn slot released after LAST_ACK + final-ACK");
}
```

Add `drive_passive_handshake` + `build_tcp_fin` to `common/mod.rs`.

- [ ] **Step 2: Run — may fail if LAST_ACK → CLOSED cleanup doesn't remove the slot**

```bash
cargo test -p dpdk-net-core --features test-server \
    --test test_server_passive_close
```
Expected: most of the flow works; the last assertion may need a fix.

- [ ] **Step 3: Ensure the LAST_ACK → CLOSED transition removes the conn**

In `tcp_input.rs`, find the existing LAST_ACK handling (used by the client side for its own FIN path). Confirm that receiving an ACK that matches `snd_nxt` in LAST_ACK transitions to `CLOSED` and removes the slot via `flow_table.remove(handle)`. If the handler transitions but doesn't remove, add the removal:

```rust
TcpState::LastAck => {
    if ack == conn.snd_nxt {
        self.flow_table.remove(handle);
        return Ok(());
    }
}
```

- [ ] **Step 4: Re-run**

```bash
cargo test -p dpdk-net-core --features test-server \
    --test test_server_passive_close
```
Expected: passes.

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-core/tests/test_server_passive_close.rs \
        crates/dpdk-net-core/tests/common/mod.rs \
        crates/dpdk-net-core/src/tcp_input.rs
git commit -m "a7 task 6: server passive-close (CLOSE_WAIT→LAST_ACK→CLOSED)"
```

---

## Task 7: Server FSM — active close (FIN_WAIT_1 → TIME_WAIT from server)

**Files:**
- Create: `crates/dpdk-net-core/tests/test_server_active_close.rs`

- [ ] **Step 1: Write the failing test**

```rust
#![cfg(feature = "test-server")]
//! A7 Task 7: active close from server side.
//! Server calls close() first. FIN_WAIT_1 → FIN_WAIT_2 on ACK of FIN
//! → TIME_WAIT on peer FIN. TIME_WAIT is bounded (existing timer).

mod common;
use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::engine::{eal_init, Engine};
use dpdk_net_core::tcp_state::TcpState;
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

#[test]
fn active_close_from_server_side() {
    set_virt_ns(0);
    eal_init(&common::test_eal_args()).unwrap();
    let mut eng = Engine::new(common::test_server_config()).unwrap();
    let lh = eng.listen(common::OUR_IP, 5555).unwrap();

    let (conn_h, our_iss) = common::drive_passive_handshake(&mut eng, lh);
    let _ = drain_tx_frames();

    // Server closes first.
    set_virt_ns(10_000_000);
    eng.close(conn_h, 0).unwrap();
    assert_eq!(eng.state_of(conn_h).unwrap(), TcpState::FinWait1);

    // Drain the FIN.
    let fin_frames = drain_tx_frames();
    assert_eq!(fin_frames.len(), 1);
    let (our_fin_seq, _) = common::parse_tcp_seq_ack(&fin_frames[0]);

    // Peer ACKs the FIN.
    set_virt_ns(20_000_000);
    let ack = common::build_tcp_ack(common::PEER_IP, 40000,
        common::OUR_IP, 5555,
        /*seq*/ 0x10000001,
        /*ack*/ our_fin_seq.wrapping_add(1));
    eng.inject_rx_frame(&ack).unwrap();
    assert_eq!(eng.state_of(conn_h).unwrap(), TcpState::FinWait2);

    // Peer FINs.
    set_virt_ns(30_000_000);
    let peer_fin = common::build_tcp_fin(common::PEER_IP, 40000,
        common::OUR_IP, 5555,
        /*seq*/ 0x10000001,
        /*ack*/ our_fin_seq.wrapping_add(1));
    eng.inject_rx_frame(&peer_fin).unwrap();
    assert_eq!(eng.state_of(conn_h).unwrap(), TcpState::TimeWait);
}
```

- [ ] **Step 2: Run — should pass (existing transitions reach TIME_WAIT)**

```bash
cargo test -p dpdk-net-core --features test-server \
    --test test_server_active_close
```
Expected: passes without code changes to `tcp_input.rs`.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/tests/test_server_active_close.rs
git commit -m "a7 task 7: server active-close path (FIN_WAIT_1→TIME_WAIT)"
```

---

## Task 8: Test-only FFI — `dpdk_net_test.h` + production-header exclusion

**Files:**
- Create: `crates/dpdk-net/src/test_ffi.rs`
- Create: `crates/dpdk-net/cbindgen-test.toml`
- Modify: `crates/dpdk-net/src/lib.rs`
- Modify: `crates/dpdk-net/build.rs`
- Modify: `crates/dpdk-net/cbindgen.toml`
- Create: `crates/dpdk-net/tests/test_header_excluded.rs`

- [ ] **Step 1: Write the failing header-isolation test**

```rust
//! A7 Task 8: prove no dpdk_net_test_* symbol leaks into dpdk_net.h
//! across any feature combination.

#[test]
fn default_header_has_no_test_symbols() {
    let header = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../include/dpdk_net.h"),
    ).expect("read dpdk_net.h");
    for bad in ["dpdk_net_test_", "dpdk_net_listen_handle_t",
                "dpdk_net_test_frame_t"] {
        assert!(!header.contains(bad),
            "dpdk_net.h unexpectedly contains `{bad}`");
    }
}

#[cfg(feature = "test-server")]
#[test]
fn test_header_present_when_feature_on() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../include/dpdk_net_test.h");
    let h = std::fs::read_to_string(path).expect("read dpdk_net_test.h");
    for expected in ["dpdk_net_test_set_time_ns",
                     "dpdk_net_test_inject_frame",
                     "dpdk_net_test_drain_tx_frames",
                     "dpdk_net_test_listen",
                     "dpdk_net_test_accept_next",
                     "dpdk_net_test_connect",
                     "dpdk_net_test_send",
                     "dpdk_net_test_recv",
                     "dpdk_net_test_close"] {
        assert!(h.contains(expected),
            "dpdk_net_test.h missing `{expected}`");
    }
}
```

- [ ] **Step 2: Run — fails because `dpdk_net_test.h` doesn't exist yet**

```bash
cargo test -p dpdk-net --features test-server --test test_header_excluded
```
Expected: `dpdk_net_test.h` read fails.

- [ ] **Step 3: Extend `cbindgen.toml` exclusion list**

In `crates/dpdk-net/cbindgen.toml`, extend the existing `exclude` array:

```toml
exclude = [
    "EngineConfigRustOnly",
    "dpdk_net_panic_for_test",
    # A7: every test-only FFI symbol lives in src/test_ffi.rs and is
    # only emitted into include/dpdk_net_test.h under --features test-server.
    # List them by prefix-match on the symbol name; cbindgen honors exact
    # names so we also itemize the known ones defensively.
    "dpdk_net_test_set_time_ns",
    "dpdk_net_test_inject_frame",
    "dpdk_net_test_drain_tx_frames",
    "dpdk_net_test_listen",
    "dpdk_net_test_accept_next",
    "dpdk_net_test_connect",
    "dpdk_net_test_send",
    "dpdk_net_test_recv",
    "dpdk_net_test_close",
    "dpdk_net_listen_handle_t",
    "dpdk_net_test_frame_t",
]
```

- [ ] **Step 4: Create `crates/dpdk-net/cbindgen-test.toml`**

```toml
language = "C"
include_guard = "DPDK_NET_TEST_H"
pragma_once = true
autogen_warning = "/* DO NOT EDIT: generated from Rust via cbindgen (test-server feature) */"
no_includes = false
sys_includes = ["stdint.h", "stdbool.h", "stddef.h", "arpa/inet.h"]
after_includes = "\n#include \"dpdk_net.h\"\n"
style = "tag"
cpp_compat = true

[parse]
parse_deps = false

[export]
include = [
    "dpdk_net_test_frame_t",
    "dpdk_net_listen_handle_t",
    "dpdk_net_test_set_time_ns",
    "dpdk_net_test_inject_frame",
    "dpdk_net_test_drain_tx_frames",
    "dpdk_net_test_listen",
    "dpdk_net_test_accept_next",
    "dpdk_net_test_connect",
    "dpdk_net_test_send",
    "dpdk_net_test_recv",
    "dpdk_net_test_close",
]
```

- [ ] **Step 5: Teach `build.rs` to emit `dpdk_net_test.h` under the feature**

Append to `crates/dpdk-net/build.rs`:

```rust
// A7: second cbindgen pass for the test-only header, conditional on
// the `test-server` feature being active in this build.
if std::env::var("CARGO_FEATURE_TEST_SERVER").is_ok() {
    let out = PathBuf::from(&crate_dir).join("../../include/dpdk_net_test.h");
    let cfg_test = cbindgen::Config::from_file(
        PathBuf::from(&crate_dir).join("cbindgen-test.toml"),
    ).expect("read cbindgen-test.toml");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(cfg_test)
        .generate()
        .expect("cbindgen test generate")
        .write_to_file(&out);
    println!("cargo:rerun-if-changed=cbindgen-test.toml");
    println!("cargo:rerun-if-changed=src/test_ffi.rs");
}
```

- [ ] **Step 6: Create `src/test_ffi.rs`**

```rust
//! A7: test-only FFI surface. All functions gated behind the `test-server`
//! cargo feature. Symbols land in include/dpdk_net_test.h; never in
//! include/dpdk_net.h (see cbindgen.toml exclusion list + build.rs).

use crate::api::*;
use dpdk_net_core::clock;
use dpdk_net_core::test_tx_intercept;

pub type dpdk_net_listen_handle_t = u32;

#[repr(C)]
pub struct dpdk_net_test_frame_t {
    /// Shim-owned buffer; valid until the next drain call.
    pub buf: *const u8,
    pub len: usize,
}

thread_local! {
    /// Holds the Vec<Vec<u8>> returned by the last drain so out pointers
    /// stay valid across the FFI boundary until the next drain.
    static LAST_DRAIN: std::cell::RefCell<Vec<Vec<u8>>>
        = const { std::cell::RefCell::new(Vec::new()) };
}

/// Absolute virtual time in ns. Monotonic enforcement is inside the clock.
#[no_mangle]
pub extern "C" fn dpdk_net_test_set_time_ns(ns: u64) {
    clock::set_virt_ns(ns);
}

/// Inject a raw Ethernet frame into the engine's RX path (single segment).
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_inject_frame(
    engine: *mut dpdk_net_engine,
    buf: *const u8, len: usize,
) -> i32 {
    let eng = match super::engine_from_raw_mut(engine) {
        Some(e) => e, None => return -libc::EINVAL,
    };
    if buf.is_null() || len == 0 { return -libc::EINVAL; }
    let slice = std::slice::from_raw_parts(buf, len);
    match eng.inject_rx_frame(slice) {
        Ok(()) => { super::pump_until_quiescent(eng); 0 }
        Err(_) => -libc::ENOMEM,
    }
}

/// Drain every pending TX frame. Copies out pointers into the caller's
/// `out` array (at most `max`). Returns the count. Frame buffers live
/// in thread-local storage inside the shim; they are valid until the
/// next drain call.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_drain_tx_frames(
    _engine: *mut dpdk_net_engine,
    out: *mut dpdk_net_test_frame_t, max: usize,
) -> usize {
    let frames = test_tx_intercept::drain_tx_frames();
    let n = frames.len().min(max);
    LAST_DRAIN.with(|cell| {
        let mut slot = cell.borrow_mut();
        *slot = frames;
        for i in 0..n {
            let ptr = slot[i].as_ptr();
            let l = slot[i].len();
            *out.add(i) = dpdk_net_test_frame_t { buf: ptr, len: l };
        }
    });
    n
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_listen(
    engine: *mut dpdk_net_engine, local_port: u16,
) -> dpdk_net_listen_handle_t {
    let eng = match super::engine_from_raw_mut(engine) {
        Some(e) => e, None => return 0,
    };
    eng.listen(eng.local_ip(), local_port).unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_accept_next(
    engine: *mut dpdk_net_engine, listen: dpdk_net_listen_handle_t,
) -> dpdk_net_conn_t {
    let eng = match super::engine_from_raw_mut(engine) {
        Some(e) => e, None => return u64::MAX,
    };
    eng.accept_next(listen).map(|h| h.0 as u64).unwrap_or(u64::MAX)
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_connect(
    engine: *mut dpdk_net_engine,
    dst_ip: u32, dst_port: u16,
    opts: *const dpdk_net_connect_opts_t,
) -> dpdk_net_conn_t {
    // Thin re-wrapper around the existing dpdk_net_connect logic.
    let mut out: dpdk_net_conn_t = u64::MAX;
    let _ = super::dpdk_net_connect(engine, opts, &mut out as *mut _);
    if out != u64::MAX {
        super::pump_until_quiescent_raw(engine);
    }
    out
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_send(
    engine: *mut dpdk_net_engine, h: dpdk_net_conn_t,
    buf: *const u8, len: usize,
) -> isize {
    let rc = super::dpdk_net_send(engine, h, buf, len);
    if rc >= 0 { super::pump_until_quiescent_raw(engine); }
    rc as isize
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_recv(
    engine: *mut dpdk_net_engine, h: dpdk_net_conn_t,
    out: *mut u8, max: usize,
) -> isize {
    // Stage 1 recv is event-driven (DPDK_NET_EVT_READABLE). Drain one
    // event batch, memcpy out the bytes targeting handle `h` into the
    // caller buffer. Returns bytes written, 0 if no READABLE waiting.
    if engine.is_null() || out.is_null() || max == 0 {
        return -libc::EINVAL as isize;
    }
    let mut evs = [std::mem::zeroed::<dpdk_net_event_t>(); 16];
    let n = super::dpdk_net_poll(engine, evs.as_mut_ptr(), 16, 0);
    if n <= 0 { return 0; }
    let mut written: usize = 0;
    for i in 0..(n as usize) {
        let ev = &evs[i];
        if ev.kind != dpdk_net_event_kind_t::DPDK_NET_EVT_READABLE { continue; }
        if ev.conn != h { continue; }
        let r = &ev.u.readable;
        let segs = std::slice::from_raw_parts(r.segs, r.seg_count as usize);
        for seg in segs {
            let want = (max - written).min(seg.len);
            if want == 0 { return written as isize; }
            std::ptr::copy_nonoverlapping(seg.data, out.add(written), want);
            written += want;
        }
    }
    written as isize
}

#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_close(
    engine: *mut dpdk_net_engine, h: dpdk_net_conn_t, flags: u32,
) -> i32 {
    let rc = super::dpdk_net_close(engine, h, flags);
    if rc == 0 { super::pump_until_quiescent_raw(engine); }
    rc
}
```

In `lib.rs` add:

```rust
#[cfg(feature = "test-server")]
pub mod test_ffi;

#[cfg(feature = "test-server")]
unsafe fn engine_from_raw_mut<'a>(p: *mut dpdk_net_engine) -> Option<&'a mut dpdk_net_core::engine::Engine> {
    if p.is_null() { return None; }
    Some(&mut (&mut *(p as *mut OpaqueEngine)).0)
}

#[cfg(feature = "test-server")]
unsafe fn pump_until_quiescent_raw(p: *mut dpdk_net_engine) {
    if let Some(eng) = engine_from_raw_mut(p) { pump_until_quiescent(eng); }
}
// The `pump_until_quiescent` function itself is defined below in the
// "Add matching Engine::pump_tx_drain + Engine::pump_timers" block
// (same file, appended directly after these helper defs so the loop
// can call the engine methods).
```

Add matching `Engine::pump_tx_drain` + `Engine::pump_timers` methods in `engine.rs` (feature-gated) that expose the existing TX-drain and timer-fire loops as test entry points. Both are thin wrappers (5–10 lines each):

```rust
#[cfg(feature = "test-server")]
impl Engine {
    /// Run the per-conn TX flush path once. Returns true if any frame
    /// landed on the TX-intercept queue during this call.
    pub fn pump_tx_drain(&mut self) -> bool {
        let before_empty = crate::test_tx_intercept::is_empty();
        self.flush_pending_tx_for_all_conns();
        let after_empty = crate::test_tx_intercept::is_empty();
        before_empty && !after_empty
    }

    /// Fire every timer due at `now_ns`. Returns the number of timers fired.
    pub fn pump_timers(&mut self, now_ns: u64) -> usize {
        let fired = self.timer_wheel.advance(now_ns);
        let n = fired.len();
        for (id, node) in fired {
            self.handle_timer_fire(id, node, now_ns);
        }
        n
    }
}
```

Update the `pump_until_quiescent` loop signature in `lib.rs` to match:

```rust
#[cfg(feature = "test-server")]
fn pump_until_quiescent(eng: &mut dpdk_net_core::engine::Engine) {
    const MAX: u32 = 10_000;
    let mut i = 0u32;
    loop {
        let tx_progress = eng.pump_tx_drain();
        let fired = eng.pump_timers(clock::now_ns());
        if !tx_progress && fired == 0 { return; }
        i += 1;
        assert!(i < MAX, "pump_until_quiescent exceeded {MAX} iterations");
    }
}
```

Note: the exact internal names (`flush_pending_tx_for_all_conns`, `handle_timer_fire`) may differ in the current codebase. Grep `engine.rs` for `fn advance_timer_wheel` (exists at line ~2087) and for whatever function `poll_once` calls to walk per-conn TX at the end of each poll; wire these two feature-gated methods to those real internals.

- [ ] **Step 7: Build with the feature and re-run the test**

```bash
cargo build -p dpdk-net --features test-server
cargo test -p dpdk-net --features test-server --test test_header_excluded
```
Expected: both tests pass.

- [ ] **Step 8: Verify default build still clean and header unchanged**

```bash
cargo build -p dpdk-net
cargo test -p dpdk-net --test test_header_excluded default_header_has_no_test_symbols
./scripts/check-header.sh
```
Expected: all green; `dpdk_net.h` contains zero `dpdk_net_test_*` symbols.

- [ ] **Step 9: Commit**

```bash
git add crates/dpdk-net/src/test_ffi.rs \
        crates/dpdk-net/cbindgen-test.toml \
        crates/dpdk-net/cbindgen.toml \
        crates/dpdk-net/src/lib.rs \
        crates/dpdk-net/build.rs \
        crates/dpdk-net/tests/test_header_excluded.rs \
        crates/dpdk-net-core/src/engine.rs
git commit -m "a7 task 8: test-only FFI + dpdk_net_test.h, excluded from production header"
```

---

## Task 9: Runner crate skeleton + build.rs + build.sh

**Files:**
- Create: `tools/packetdrill-shim-runner/Cargo.toml`
- Create: `tools/packetdrill-shim-runner/src/main.rs`
- Create: `tools/packetdrill-shim-runner/src/lib.rs`
- Create: `tools/packetdrill-shim-runner/build.rs`
- Create: `tools/packetdrill-shim/build.sh`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Scaffold the crate**

`tools/packetdrill-shim-runner/Cargo.toml`:

```toml
[package]
name = "packetdrill-shim-runner"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[features]
default = []
# Pass-through; enables dpdk-net's test-server which enables
# dpdk-net-core's test-server.
test-server = ["dpdk-net/test-server"]

[dependencies]
dpdk-net = { path = "../../crates/dpdk-net", default-features = false }

[[bin]]
name = "pdshim-run-one"
path = "src/main.rs"
```

`tools/packetdrill-shim-runner/src/lib.rs`:

```rust
//! A7: shared helpers for the packetdrill-shim runner.
//! Script classifier + pinned-count loader + shim invocation.

pub mod classifier;
pub mod invoker;
pub mod counts;
```

Create `src/classifier.rs`:

```rust
use std::path::Path;

pub enum Verdict {
    Runnable,
    SkippedUntranslatable(&'static str),
    SkippedOutOfScope(&'static str),
}

/// Placeholder classifier. Task 14 populates it from
/// tools/packetdrill-shim/classify/ligurio.toml.
pub fn classify(_path: &Path) -> Verdict {
    Verdict::Runnable
}
```

Create `src/invoker.rs`:

```rust
use std::path::Path;
use std::process::Command;

pub struct RunOutcome {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_script(shim_binary: &Path, script: &Path) -> RunOutcome {
    let o = Command::new(shim_binary)
        .arg(script)
        .output()
        .expect("spawn shim binary");
    RunOutcome {
        exit: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into(),
        stderr: String::from_utf8_lossy(&o.stderr).into(),
    }
}
```

Create `src/counts.rs`:

```rust
//! Pinned corpus counts — tuned at end of Task 15.
pub const LIGURIO_RUNNABLE_COUNT: usize = 0;       // pinned in Task 15
pub const LIGURIO_SKIP_UNTRANSLATABLE: usize = 0;  // pinned in Task 15
pub const LIGURIO_SKIP_OUT_OF_SCOPE: usize = 0;    // pinned in Task 15
```

Create `src/main.rs`:

```rust
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
```

- [ ] **Step 2: Scaffold `build.rs`**

```rust
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

    let st = Command::new("bash").arg(build_sh)
        .env("DPDK_NET_SHIM_PROFILE",
             if env::var("DPDK_NET_SHIM_DEBUG").is_ok() { "dev" } else { "release" })
        .status().expect("run build.sh");
    assert!(st.success(), "packetdrill-shim build.sh failed");
}
```

- [ ] **Step 3: Scaffold `tools/packetdrill-shim/build.sh`**

```bash
#!/usr/bin/env bash
# A7: build the patched packetdrill binary and link it against libdpdk_net.
# Inputs: $DPDK_NET_SHIM_PROFILE (release|dev, default release).
# Output: target/packetdrill-shim/packetdrill

set -euo pipefail
cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"

PROFILE="${DPDK_NET_SHIM_PROFILE:-release}"

# Require host tooling.
for bin in git autoreconf bison flex make gcc pkg-config; do
  command -v "$bin" >/dev/null 2>&1 \
    || { echo "ERROR: missing host tool: $bin"; exit 1; }
done

# 1. Ensure submodules are initialized.
git submodule update --init --recursive \
  third_party/packetdrill third_party/packetdrill-testcases

# 2. Apply the patch stack idempotently.
cd third_party/packetdrill
# If already applied (the tip has a patch-marker file), skip.
if ! [ -f .a7-patches-applied ]; then
  for p in "$REPO_ROOT"/tools/packetdrill-shim/patches/*.patch; do
    git am "$p"
  done
  touch .a7-patches-applied
fi

# 3. Build libdpdk_net (staticlib) with --features test-server.
cd "$REPO_ROOT"
if [ "$PROFILE" = "release" ]; then
  cargo build --release -p dpdk-net --features test-server
  LIB_DIR="$REPO_ROOT/target/release"
else
  cargo build -p dpdk-net --features test-server
  LIB_DIR="$REPO_ROOT/target/debug"
fi

# 4. Build packetdrill.
cd "$REPO_ROOT"/third_party/packetdrill
autoreconf -fi
./configure CC=clang \
  CFLAGS="-O2 -g -I$REPO_ROOT/include" \
  LDFLAGS="-L$LIB_DIR -ldl -lpthread -lnuma" \
  LIBS="-ldpdk_net"

make clean
make -j"$(nproc)"

# 5. Stage the binary.
mkdir -p "$REPO_ROOT"/target/packetdrill-shim
cp -f packetdrill "$REPO_ROOT"/target/packetdrill-shim/packetdrill
echo "=== packetdrill-shim build OK ==="
```

Make it executable:

```bash
chmod +x tools/packetdrill-shim/build.sh
```

- [ ] **Step 4: Add the runner to the workspace**

In the root `Cargo.toml`, extend `members`:

```toml
members = [
    "crates/dpdk-net-sys",
    "crates/dpdk-net-core",
    "crates/dpdk-net",
    "tests/ffi-test",
    "tools/bench-rx-zero-copy",
    "tools/packetdrill-shim-runner",
]
```

- [ ] **Step 5: Confirm cargo picks up the new crate (build will fail because patches aren't yet written — that's expected)**

```bash
cargo build -p packetdrill-shim-runner
```
Expected: warning "skipping packetdrill-shim build (feature test-server off)"; binary `pdshim-run-one` builds.

- [ ] **Step 6: Commit**

```bash
git add tools/packetdrill-shim-runner tools/packetdrill-shim/build.sh \
        Cargo.toml
git commit -m "a7 task 9: runner crate skeleton + build.sh + cargo workspace member"
```

---

## Task 10: Packetdrill patch stack

**Files:**
- Create: `tools/packetdrill-shim/patches/0001-backend-in-memory.patch`
- Create: `tools/packetdrill-shim/patches/0002-time-virtual.patch`
- Create: `tools/packetdrill-shim/patches/0003-syscall-dispatch.patch`
- Create: `tools/packetdrill-shim/patches/0004-remove-tolerance-default.patch`
- Create: `tools/packetdrill-shim/patches/0005-link-dpdk-net.patch`

- [ ] **Step 1: Patch 0001 — in-memory TUN backend**

Inside `third_party/packetdrill/`, identify the TUN read/write call sites (`grep -nE 'tun_read|tun_write|tun_alloc' **/*.c`) and replace them with shim-local in-memory queues:

- `tun_alloc` → returns a stable shim fd (any non-zero).
- `tun_write(buf, len)` → calls `extern void dpdk_net_test_inject_frame_from_shim(const void*, size_t)` (a tiny wrapper that calls into the engine via the dlsym'd `dpdk_net_test_inject_frame`).
- `tun_read(buf, len)` → pops the head of the shim's TX queue.

The shim glue (~60 lines of C) lives in `third_party/packetdrill/packetdrill_a7_shim.c`, compiled into the binary. Produce the patch with:

```bash
cd third_party/packetdrill
# (manually edit)
git add -A && git commit -m "a7: in-memory TUN backend"
git format-patch -1 -o ../../tools/packetdrill-shim/patches/ --start-number 1
git reset --hard HEAD~1
```

The produced file should be `0001-a7-in-memory-TUN-backend.patch`. Rename to `0001-backend-in-memory.patch`:

```bash
mv tools/packetdrill-shim/patches/0001-*.patch \
   tools/packetdrill-shim/patches/0001-backend-in-memory.patch
```

- [ ] **Step 2: Patch 0002 — virtual clock**

Identify every `gettimeofday` / `clock_gettime(CLOCK_MONOTONIC, ...)` in packetdrill's core scheduler (typically `run.c`, `event.c`, `script.c`). Replace with calls to a shim helper `pd_a7_now_ns()` that reads the shim's virtual clock (which in turn is set via `dpdk_net_test_set_time_ns`).

Produce patch the same way; rename to `0002-time-virtual.patch`.

- [ ] **Step 3: Patch 0003 — syscall dispatch**

In `packetdrill`'s socket-op handler (commonly `run_system_call.c` or `syscalls.c`), intercept:
- `socket(PF_INET, SOCK_STREAM, 0)` → allocate a shim-fd numbered starting at 1000.
- `connect(fd, addr)` → `dpdk_net_test_connect`
- `listen(fd, backlog)` / `accept(fd, ...)` → `dpdk_net_test_listen` + `dpdk_net_test_accept_next`
- `write(fd, buf, len)` → `dpdk_net_test_send`
- `read(fd, buf, len)` → `dpdk_net_test_recv`
- `close(fd)` → `dpdk_net_test_close`

The setsockopts we translate are a minimum set: `TCP_NODELAY` (ignored — Nagle flag is a connect-time knob), `SO_RCVTIMEO` (recorded, checked by next read). Everything else returns `EOPNOTSUPP` so the shim never silently lies about what was honored.

Produce patch; rename to `0003-syscall-dispatch.patch`.

- [ ] **Step 4: Patch 0004 — zero tolerance default**

One-line change in packetdrill's default-flag table: `--tolerance_usecs=0` (was 4000). Rename `0004-remove-tolerance-default.patch`.

- [ ] **Step 5: Patch 0005 — link dpdk-net**

Modify `Makefile.am` / `configure.ac` to:
- accept `LIBS="-ldpdk_net"` from the environment.
- link `-ldpdk_net -ldl -lpthread -lnuma`.

Rename `0005-link-dpdk-net.patch`.

- [ ] **Step 6: Verify the patch stack applies cleanly from a fresh submodule**

```bash
cd third_party/packetdrill
git clean -fd && git checkout .
rm -f .a7-patches-applied
cd -
./tools/packetdrill-shim/build.sh
```
Expected: build succeeds; produces `target/packetdrill-shim/packetdrill`.

- [ ] **Step 7: Commit**

```bash
git add tools/packetdrill-shim/patches/
git commit -m "a7 task 10: packetdrill patch stack (0001-0005)"
```

---

## Task 11: Shim smoke test — one hand-written 5-line script

**Files:**
- Create: `tools/packetdrill-shim-runner/tests/shim_smoke.rs`
- Create: `tools/packetdrill-shim-runner/tests/scripts/smoke.pkt`

- [ ] **Step 1: Write the smoke script**

`tools/packetdrill-shim-runner/tests/scripts/smoke.pkt`:

```
// Absolute-minimum lifecycle: connect, write, close.
0.000 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3
0.100 connect(3, ..., ...) = 0
0.100 > S  0:0(0) win 65535 <mss 1460,sackOK,nop,nop,TS val 1 ecr 0,wscale 7>
0.200 < S. 0:0(0) ack 1 win 65535 <mss 1460,sackOK,TS val 100 ecr 1,nop,wscale 7>
0.200 > .  1:1(0) ack 1 <nop,nop,TS val 2 ecr 100>
0.300 close(3) = 0
```

- [ ] **Step 2: Write the test**

`tools/packetdrill-shim-runner/tests/shim_smoke.rs`:

```rust
#![cfg(feature = "test-server")]

use std::path::PathBuf;

#[test]
fn smoke_script_exits_zero() {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/scripts/smoke.pkt");
    let o = packetdrill_shim_runner::invoker::run_script(&bin, &script);
    assert_eq!(o.exit, 0,
        "smoke script failed:\nstdout:\n{}\nstderr:\n{}",
        o.stdout, o.stderr);
}
```

- [ ] **Step 3: Run**

```bash
cargo test -p packetdrill-shim-runner --features test-server \
    --test shim_smoke -- --nocapture
```
Expected: script exits 0. If it fails, triage the patch stack: most likely the syscall-dispatch patch routing is off for one of the ops the script touches.

- [ ] **Step 4: Commit**

```bash
git add tools/packetdrill-shim-runner/tests/shim_smoke.rs \
        tools/packetdrill-shim-runner/tests/scripts/smoke.pkt
git commit -m "a7 task 11: shim smoke test — 5-line connect/write/close .pkt"
```

---

## Task 12: Shim direct tests — inject/drain roundtrip + virt-time RTO

**Files:**
- Create: `tools/packetdrill-shim-runner/tests/shim_inject_drain_roundtrip.rs`
- Create: `tools/packetdrill-shim-runner/tests/shim_virt_time_rto.rs`

- [ ] **Step 1: Inject/drain roundtrip**

`shim_inject_drain_roundtrip.rs`:

```rust
#![cfg(feature = "test-server")]
//! Drive the engine directly via test-FFI: listen, inject SYN,
//! drain SYN-ACK, parse it. Validates the in-memory frame hook
//! without going through packetdrill.

use dpdk_net::test_ffi::{
    dpdk_net_test_set_time_ns, dpdk_net_test_inject_frame,
    dpdk_net_test_drain_tx_frames, dpdk_net_test_listen,
    dpdk_net_test_frame_t,
};

#[test]
fn syn_in_synack_out() {
    // Caller creates an engine via existing dpdk_net_engine_create in
    // test-only mode; helpers are in a small Rust wrapper.
    let eng = helpers::create_test_engine();
    unsafe { dpdk_net_test_set_time_ns(0) };
    let lh = unsafe { dpdk_net_test_listen(eng, 5555) };
    assert!(lh > 0);

    let syn = helpers::build_syn(common::PEER_IP, 40000,
        common::OUR_IP, 5555, 0x10000000);
    let rc = unsafe {
        dpdk_net_test_inject_frame(eng, syn.as_ptr(), syn.len())
    };
    assert_eq!(rc, 0);

    let mut out = [dpdk_net_test_frame_t { buf: std::ptr::null(), len: 0 }; 4];
    let n = unsafe {
        dpdk_net_test_drain_tx_frames(eng, out.as_mut_ptr(), 4)
    };
    assert_eq!(n, 1);
    let slice = unsafe { std::slice::from_raw_parts(out[0].buf, out[0].len) };
    assert!(helpers::is_syn_ack(slice));
    helpers::destroy_test_engine(eng);
}

mod helpers { /* ... common construction + packet-build helpers ... */ }
mod common  { pub const OUR_IP: u32 = 0x0a630a02;
              pub const PEER_IP: u32 = 0x0a630a01; }
```

- [ ] **Step 2: Run the inject/drain test**

```bash
cargo test -p packetdrill-shim-runner --features test-server \
    --test shim_inject_drain_roundtrip
```
Expected: passes.

- [ ] **Step 3: Virt-time RTO test**

`shim_virt_time_rto.rs`:

```rust
#![cfg(feature = "test-server")]
//! Advance virtual time past an RTO deadline without peer acks; assert
//! a retransmit is emitted at exactly the deadline.

#[test]
fn rto_fires_at_virtual_deadline() {
    let eng = helpers::create_test_engine();
    unsafe { dpdk_net_test_set_time_ns(0) };
    // Drive a client connect (active open). helpers::drive_handshake
    // reaches ESTABLISHED using the in-memory peer-reply fixture.
    let conn = helpers::drive_client_handshake(eng);
    let send_buf = b"abc";
    let _ = unsafe { dpdk_net_test_send(eng, conn, send_buf.as_ptr(), 3) };

    // Drain and discard the data segment.
    let _ = helpers::drain_all(eng);

    // Advance exactly to the RTO deadline (initial_rto_us = 5000 by
    // test config → 5_000_000 ns).
    unsafe { dpdk_net_test_set_time_ns(5_000_000) };
    // Pump via a zero-byte send (cheap entry that runs pump_until_quiescent).
    let _ = unsafe { dpdk_net_test_send(eng, conn, send_buf.as_ptr(), 0) };

    let frames = helpers::drain_all(eng);
    assert!(frames.iter().any(|f| helpers::is_retransmit_of(f, send_buf)),
        "expected retransmit at virt deadline");
    helpers::destroy_test_engine(eng);
}
```

- [ ] **Step 4: Run**

```bash
cargo test -p packetdrill-shim-runner --features test-server \
    --test shim_virt_time_rto
```
Expected: passes.

- [ ] **Step 5: Commit**

```bash
git add tools/packetdrill-shim-runner/tests/shim_inject_drain_roundtrip.rs \
        tools/packetdrill-shim-runner/tests/shim_virt_time_rto.rs
git commit -m "a7 task 12: shim direct self-tests (inject/drain + virt-time RTO)"
```

---

## Task 13: Classifier scaffold + SKIPPED.md skeleton

**Files:**
- Create: `tools/packetdrill-shim/classify/ligurio.toml`
- Create: `tools/packetdrill-shim/SKIPPED.md`
- Modify: `tools/packetdrill-shim-runner/src/classifier.rs`

- [ ] **Step 1: Write the classifier TOML**

`tools/packetdrill-shim/classify/ligurio.toml`:

```toml
# A7 ligurio corpus classifier.
#
# Rules evaluated in order. First match wins. Each rule:
#   - matches_regex: applied to the path relative to
#     third_party/packetdrill-testcases/
#   - verdict: "runnable" | "skipped-untranslatable" | "skipped-out-of-scope"
#   - reason: short string; appears in SKIPPED.md when skipped.

[[rule]]
matches_regex = ".*/ipv6/.*\\.pkt"
verdict = "skipped-out-of-scope"
reason = "IPv4 only in Stage 1"

[[rule]]
matches_regex = ".*SIGIO.*\\.pkt"
verdict = "skipped-untranslatable"
reason = "SIGIO semantics not in test-FFI"

[[rule]]
matches_regex = ".*FIONREAD.*\\.pkt"
verdict = "skipped-untranslatable"
reason = "FIONREAD not in test-FFI"

[[rule]]
matches_regex = ".*SO_RCVLOWAT.*\\.pkt"
verdict = "skipped-untranslatable"
reason = "SO_RCVLOWAT not implemented"

[[rule]]
matches_regex = ".*MSG_PEEK.*\\.pkt"
verdict = "skipped-untranslatable"
reason = "MSG_PEEK not in test-FFI"

[[rule]]
matches_regex = ".*TCP_DEFER_ACCEPT.*\\.pkt"
verdict = "skipped-untranslatable"
reason = "TCP_DEFER_ACCEPT not implemented"

[[rule]]
matches_regex = ".*TCP_CORK.*\\.pkt"
verdict = "skipped-untranslatable"
reason = "TCP_CORK not implemented"

# Default — everything else is runnable.
[[rule]]
matches_regex = ".*\\.pkt"
verdict = "runnable"
reason = ""
```

- [ ] **Step 2: Write SKIPPED.md skeleton**

```markdown
# A7 packetdrill-shim skip list

This file enumerates every `.pkt` script excluded from the runnable
set, one line per script. `runner/tests/corpus_ligurio.rs` parses this
file and asserts every skipped script has an entry here (orphan-skip
check).

Format: `<path> — <reason>`

## ligurio corpus

_filled in Task 15 from the classifier's output_

## shivansh corpus

_A8 owner_

## google upstream

_A8 owner_
```

- [ ] **Step 3: Wire the classifier to read the TOML**

Replace `classifier.rs`:

```rust
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct Config { rule: Vec<RuleRaw> }

#[derive(Deserialize)]
struct RuleRaw {
    matches_regex: String,
    verdict: String,
    reason: String,
}

struct Rule { re: Regex, verdict: Verdict }

pub enum Verdict {
    Runnable,
    SkippedUntranslatable(String),
    SkippedOutOfScope(String),
}

pub struct Classifier { rules: Vec<Rule> }

impl Classifier {
    pub fn load() -> Self {
        let raw = include_str!(
            "../../packetdrill-shim/classify/ligurio.toml");
        let cfg: Config = toml::from_str(raw).expect("parse ligurio.toml");
        let rules = cfg.rule.into_iter().map(|r| {
            let v = match r.verdict.as_str() {
                "runnable" => Verdict::Runnable,
                "skipped-untranslatable" =>
                    Verdict::SkippedUntranslatable(r.reason),
                "skipped-out-of-scope" =>
                    Verdict::SkippedOutOfScope(r.reason),
                other => panic!("unknown verdict {other}"),
            };
            Rule { re: Regex::new(&r.matches_regex).unwrap(), verdict: v }
        }).collect();
        Self { rules }
    }

    pub fn classify(&self, path: &Path) -> &Verdict {
        let s = path.to_string_lossy();
        for r in &self.rules {
            if r.re.is_match(&s) { return &r.verdict; }
        }
        panic!("no rule matched {s} (add a default .*\\.pkt rule)");
    }
}
```

Add the regex + serde deps to `tools/packetdrill-shim-runner/Cargo.toml`:

```toml
[dependencies]
dpdk-net = { path = "../../crates/dpdk-net", default-features = false }
regex = "1"
serde = { version = "1", features = ["derive"] }
toml = "0.8"
```

- [ ] **Step 4: Build check**

```bash
cargo build -p packetdrill-shim-runner --features test-server
```
Expected: compiles.

- [ ] **Step 5: Commit**

```bash
git add tools/packetdrill-shim/classify tools/packetdrill-shim/SKIPPED.md \
        tools/packetdrill-shim-runner/src/classifier.rs \
        tools/packetdrill-shim-runner/Cargo.toml
git commit -m "a7 task 13: classifier scaffold + SKIPPED.md skeleton"
```

---

## Task 14: Corpus runner test — classifier + shim invocation (counts not pinned yet)

**Files:**
- Create: `tools/packetdrill-shim-runner/tests/corpus_ligurio.rs`
- Create: `tools/packetdrill-shim-runner/tests/corpus_shivansh.rs`
- Create: `tools/packetdrill-shim-runner/tests/corpus_google.rs`

- [ ] **Step 1: Write the runner test**

`tests/corpus_ligurio.rs`:

```rust
#![cfg(feature = "test-server")]
//! A7 gate: run the ligurio corpus through the shim.

use packetdrill_shim_runner::{classifier::*, invoker, counts};
use std::path::PathBuf;
use walkdir::WalkDir;

const CORPUS_ROOT: &str = "../../third_party/packetdrill-testcases";

#[test]
fn ligurio_runnable_subset_passes() {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    let classifier = Classifier::load();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT);
    let mut runnable: Vec<PathBuf> = vec![];
    let mut skip_untrans: Vec<(PathBuf, String)> = vec![];
    let mut skip_oos:    Vec<(PathBuf, String)> = vec![];

    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let path = entry.into_path();
        if path.extension().and_then(|e| e.to_str()) != Some("pkt") { continue; }
        match classifier.classify(&path) {
            Verdict::Runnable => runnable.push(path),
            Verdict::SkippedUntranslatable(r) =>
                skip_untrans.push((path, r.clone())),
            Verdict::SkippedOutOfScope(r) =>
                skip_oos.push((path, r.clone())),
        }
    }

    // Orphan-skip check.
    let skipped_md = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/packetdrill-shim/SKIPPED.md")
    ).expect("read SKIPPED.md");
    for (p, _) in skip_untrans.iter().chain(skip_oos.iter()) {
        let key = p.strip_prefix(&root).unwrap().to_string_lossy();
        assert!(skipped_md.contains(&*key),
            "orphan skip: {key} not documented in SKIPPED.md");
    }

    // Run every runnable script, record failures.
    let mut failed: Vec<(PathBuf, invoker::RunOutcome)> = vec![];
    for s in &runnable {
        let out = invoker::run_script(&bin, s);
        if out.exit != 0 { failed.push((s.clone(), out)); }
    }
    assert!(failed.is_empty(),
        "{} of {} runnable scripts failed. Examples:\n{}",
        failed.len(), runnable.len(),
        failed.iter().take(5).map(|(p, o)|
            format!("- {}: exit={} stderr={}", p.display(), o.exit, o.stderr)
        ).collect::<Vec<_>>().join("\n"));

    // Pinned-count check (Task 15 fills in the real values).
    assert_eq!(runnable.len(),     counts::LIGURIO_RUNNABLE_COUNT,
        "runnable count drift — update counts::LIGURIO_RUNNABLE_COUNT");
    assert_eq!(skip_untrans.len(), counts::LIGURIO_SKIP_UNTRANSLATABLE);
    assert_eq!(skip_oos.len(),     counts::LIGURIO_SKIP_OUT_OF_SCOPE);
}
```

Add the walkdir dep:

```toml
walkdir = "2"
```

`tests/corpus_shivansh.rs` and `tests/corpus_google.rs` are the same shape but:
- `#[ignore]` on the `#[test]` function;
- point at `third_party/packetdrill/gtests/net/packetdrill/tests/` (google) or the shivansh corpus root (next to ligurio, a different submodule that Task 16 will scaffold if desired).

For A7, only ligurio is the gate; shivansh + google can be placeholder tests that compile but do nothing until A8:

```rust
#![cfg(feature = "test-server")]
#[test] #[ignore = "A8 owner: activate corpus gate"]
fn placeholder() {}
```

- [ ] **Step 2: Run — expected to fail on pinned counts (zeros)**

```bash
cargo test -p packetdrill-shim-runner --features test-server \
    --test corpus_ligurio -- --nocapture
```
Expected: fails on count assertions (Task 15 fixes).

- [ ] **Step 3: Commit**

```bash
git add tools/packetdrill-shim-runner/tests/corpus_ligurio.rs \
        tools/packetdrill-shim-runner/tests/corpus_shivansh.rs \
        tools/packetdrill-shim-runner/tests/corpus_google.rs \
        tools/packetdrill-shim-runner/Cargo.toml
git commit -m "a7 task 14: corpus runner skeleton (counts not pinned yet)"
```

---

## Task 15: Classify, iterate, pin counts

**Files:**
- Modify: `tools/packetdrill-shim/classify/ligurio.toml`
- Modify: `tools/packetdrill-shim/SKIPPED.md`
- Modify: `tools/packetdrill-shim-runner/src/counts.rs`

- [ ] **Step 1: Run the corpus classifier + shim end-to-end; record failures**

```bash
cargo test -p packetdrill-shim-runner --features test-server \
    --test corpus_ligurio -- --nocapture 2>&1 | tee /tmp/a7-ligurio-run-1.log
```

Expect a large number of failures on the first run. For each failure,
read the `.pkt` and categorize:

| Category | Classifier verdict | Reason |
|---|---|---|
| Truly needs a kernel feature we don't have | `skipped-untranslatable` | specific kernel feature |
| Tests an RFC behavior we deliberately deviate from (latency preset) | `skipped-untranslatable` | "latency-preset deviation" |
| Tests IPv6, obsolete, or otherwise out-of-stage | `skipped-out-of-scope` | "IPv6 / Stage N / etc." |
| Reveals a real engine bug | — | file a separate fix task; do NOT skip |
| Classifier rule mismatch | — | adjust regex in `ligurio.toml` |

- [ ] **Step 2: Iterate classifier + add SKIPPED.md entries per commit**

Each iteration is one commit:

```bash
git add tools/packetdrill-shim/classify/ligurio.toml \
        tools/packetdrill-shim/SKIPPED.md
git commit -m "a7 task 15.k: classify $BATCH_DESCRIPTION"
```

Repeat until the runnable set has 100% pass.

- [ ] **Step 3: Pin the counts**

After the runnable set is green, note the actual numbers printed by the test harness (add a `println!("runnable={} skip_untrans={} skip_oos={}", ...)` diagnostic during iteration) and set them in `counts.rs`:

```rust
pub const LIGURIO_RUNNABLE_COUNT: usize = /* actual */;
pub const LIGURIO_SKIP_UNTRANSLATABLE: usize = /* actual */;
pub const LIGURIO_SKIP_OUT_OF_SCOPE: usize = /* actual */;
```

- [ ] **Step 4: Final green run**

```bash
cargo test -p packetdrill-shim-runner --features test-server \
    --test corpus_ligurio
```
Expected: PASS.

- [ ] **Step 5: Run 10 consecutive times to prove no-flake**

```bash
for i in 1 2 3 4 5 6 7 8 9 10; do
  cargo test -p packetdrill-shim-runner --features test-server \
    --test corpus_ligurio || { echo "FLAKE on run $i"; exit 1; }
done
echo "10 consecutive runs OK"
```

- [ ] **Step 6: Commit the final pinned state**

```bash
git add tools/packetdrill-shim-runner/src/counts.rs
git commit -m "a7 task 15: pin ligurio runnable/skipped counts (100% on runnable)"
```

---

## Task 16: I-8 multi-seg FIN-piggyback regression

**Files:**
- Create: `tools/packetdrill-shim-runner/tests/scripts/i8_multi_seg_fin_piggyback.pkt`
- Create: `tools/packetdrill-shim-runner/tests/our_scripts.rs`

- [ ] **Step 1: Write the script**

`tests/scripts/i8_multi_seg_fin_piggyback.pkt`:

```
// A7 Task 16: regression for A6.6-7 I-8 FIN-piggyback miscount on
// multi-segment chains (fixed at commit b4e8de9). Assert that a
// retransmitted segment's payload length matches the original data
// length (not full-mbuf-size, not data+1).

// Handshake.
0.000 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3
0.010 connect(3, ..., ...) = 0
0.010 > S  0:0(0) win 65535 <mss 1460,sackOK,nop,nop,TS val 1 ecr 0,wscale 7>
0.050 < S. 0:0(0) ack 1 win 65535 <mss 1460,sackOK,TS val 100 ecr 1,nop,wscale 7>
0.050 > .  1:1(0) ack 1 <nop,nop,TS val 2 ecr 100>

// Three writes totaling > MSS followed by FIN.
0.100 write(3, ..., 500)  = 500
0.100 > P. 1:501(500)      ack 1 <nop,nop,TS val 3 ecr 100>
0.110 write(3, ..., 700)  = 700
0.110 > P. 501:1201(700)   ack 1 <nop,nop,TS val 4 ecr 100>
0.120 write(3, ..., 300)  = 300
0.120 > P. 1201:1501(300)  ack 1 <nop,nop,TS val 5 ecr 100>
0.130 close(3) = 0
0.130 > F. 1501:1501(0)    ack 1 <nop,nop,TS val 6 ecr 100>

// Peer dup-ACKs the first segment with a SACK block covering bytes 501-1201
// to induce retransmit of 1:501. The retransmit must carry exactly 500 bytes.
0.200 < .  1:1(0) ack 1 win 65535 <nop,nop,TS val 200 ecr 3,nop,nop,sack 501:1201>
0.200 < .  1:1(0) ack 1 win 65535 <nop,nop,TS val 201 ecr 3,nop,nop,sack 501:1201>
0.200 < .  1:1(0) ack 1 win 65535 <nop,nop,TS val 202 ecr 3,nop,nop,sack 501:1201>

// RACK detects loss; retransmit of 1:501 must be exactly 500 bytes.
0.210 > P. 1:501(500)      ack 1 <nop,nop,TS val 7 ecr 202>
```

- [ ] **Step 2: Write the runner**

`tests/our_scripts.rs`:

```rust
#![cfg(feature = "test-server")]

use packetdrill_shim_runner::invoker;
use std::path::PathBuf;

fn run(name: &str) {
    let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/packetdrill-shim/packetdrill");
    let s = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/scripts/{name}"));
    let o = invoker::run_script(&bin, &s);
    assert_eq!(o.exit, 0,
        "{name} failed:\nstdout:\n{}\nstderr:\n{}",
        o.stdout, o.stderr);
}

#[test]
fn i8_multi_seg_fin_piggyback_retrans_len_is_exact() {
    run("i8_multi_seg_fin_piggyback.pkt");
}
```

- [ ] **Step 3: Run**

```bash
cargo test -p packetdrill-shim-runner --features test-server \
    --test our_scripts -- --nocapture
```
Expected: passes (A6.6-7's b4e8de9 already fixed the underlying bug; this is regression coverage).

- [ ] **Step 4: Commit**

```bash
git add tools/packetdrill-shim-runner/tests/scripts/i8_multi_seg_fin_piggyback.pkt \
        tools/packetdrill-shim-runner/tests/our_scripts.rs
git commit -m "a7 task 16: I-8 multi-seg FIN-piggyback regression script"
```

---

## Task 17: CI wiring + perf baseline + knob-coverage whitelist

**Files:**
- Create: `scripts/a7-ligurio-gate.sh`
- Create: `scripts/a7-perf-baseline.sh`
- Modify: `scripts/hardening-miri.sh`
- Modify: `crates/dpdk-net-core/tests/knob-coverage-informational.txt`
- Modify: `scripts/hardening-all.sh`

- [ ] **Step 1: Create `scripts/a7-ligurio-gate.sh`**

```bash
#!/usr/bin/env bash
# A7 Layer-B CI gate. Builds the patched packetdrill + runs the ligurio
# corpus. Exits non-zero on any failure, classifier drift, or
# SKIPPED.md orphan.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== a7-ligurio-gate: submodule init ==="
git submodule update --init --recursive \
  third_party/packetdrill third_party/packetdrill-testcases

echo "=== a7-ligurio-gate: runner tests ==="
cargo test -p packetdrill-shim-runner --release --features test-server \
  --test corpus_ligurio --test our_scripts \
  --test shim_smoke --test shim_inject_drain_roundtrip \
  --test shim_virt_time_rto
echo "=== a7-ligurio-gate: PASS ==="
```

- [ ] **Step 2: Create `scripts/a7-perf-baseline.sh`**

```bash
#!/usr/bin/env bash
# A7 performance-baseline: bench_poll_empty at phase-a7-complete must
# not regress vs phase-a6-6-7-complete. Runs on a pinned-config host.
set -euo pipefail
cd "$(dirname "$0")/.."

baseline_rev="${A7_BASELINE_REV:-phase-a6-6-7-complete}"

# Measure current branch.
cargo bench -p dpdk-net-core --bench bench_poll_empty \
  -- --save-baseline a7_current 2>&1 | tee /tmp/a7-perf-current.log

# Measure baseline.
tmp=$(mktemp -d)
git worktree add "$tmp" "$baseline_rev"
( cd "$tmp" && cargo bench -p dpdk-net-core --bench bench_poll_empty \
  -- --save-baseline a7_baseline ) | tee /tmp/a7-perf-baseline.log
git worktree remove "$tmp"

# Compare; fail on > 5% regression.
cargo bench -p dpdk-net-core --bench bench_poll_empty \
  -- --baseline a7_baseline 2>&1 | tee /tmp/a7-perf-compare.log | \
  grep -E 'regressed|mean   \[.*\]' || true
# Fail if criterion flagged regression.
if grep -q 'regressed' /tmp/a7-perf-compare.log; then
  echo "FAIL: bench_poll_empty regressed vs $baseline_rev"
  exit 1
fi
echo "=== a7-perf-baseline: PASS ==="
```

- [ ] **Step 3: Add `test-server` to miri matrix**

Edit `scripts/hardening-miri.sh` to add the second run:

```bash
cargo +nightly miri test -p dpdk-net-core --lib --features miri-safe
cargo +nightly miri test -p dpdk-net-core --lib --features "miri-safe test-server"
```

- [ ] **Step 4: Knob-coverage informational whitelist**

Append to `crates/dpdk-net-core/tests/knob-coverage-informational.txt`:

```
test-server  # A7: cargo build-system flag, no runtime behavioral effect; covered by tests/corpus_ligurio.rs and tests/shim_*.
```

- [ ] **Step 5: Aggregator update**

Modify `scripts/hardening-all.sh` to include the new gates (guarded on host toolchain presence):

```bash
./scripts/a7-ligurio-gate.sh || { echo "a7 ligurio gate failed"; exit 1; }
# perf baseline requires a criterion benchmark + a baseline rev worktree
# root; run only when explicitly requested:
if [ "${A7_RUN_PERF:-0}" = "1" ]; then
  ./scripts/a7-perf-baseline.sh
fi
```

- [ ] **Step 6: Make scripts executable**

```bash
chmod +x scripts/a7-ligurio-gate.sh scripts/a7-perf-baseline.sh
```

- [ ] **Step 7: Run the gate locally**

```bash
./scripts/a7-ligurio-gate.sh
```
Expected: green.

- [ ] **Step 8: Run perf baseline**

```bash
A7_BASELINE_REV=phase-a6-6-7-complete ./scripts/a7-perf-baseline.sh
```
Expected: no regression flagged.

- [ ] **Step 9: Commit**

```bash
git add scripts/a7-ligurio-gate.sh scripts/a7-perf-baseline.sh \
        scripts/hardening-miri.sh scripts/hardening-all.sh \
        crates/dpdk-net-core/tests/knob-coverage-informational.txt
git commit -m "a7 task 17: CI gate + perf baseline + knob-coverage whitelist"
```

---

## Task 18: End-of-phase reviews + roadmap + tag

**Files:**
- Create: `docs/superpowers/reviews/phase-a7-mtcp-compare.md`
- Create: `docs/superpowers/reviews/phase-a7-rfc-compliance.md`
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md`

- [ ] **Step 1: Dispatch mTCP + RFC review subagents in parallel**

Use `Agent` with `subagent_type: general-purpose` and model `opus`. Two agents, dispatched in one message:

```
mTCP reviewer:
Prompt template — read the mtcp-comparison-reviewer brief at
.claude/agents/mtcp-comparison-reviewer.md, diff the A7 commits
against third_party/mtcp/ focusing on mtcp/src/core.c listen/accept,
mtcp/src/tcp_in.c passive open, mtcp/src/tcp_out.c SYN-ACK builder.
Produce docs/superpowers/reviews/phase-a7-mtcp-compare.md with the
fixed schema (Must-fix / Missed edge cases / Accepted divergence /
FYI / Verdict).

RFC reviewer:
Prompt template — read .claude/agents/rfc-compliance-reviewer.md.
Scope: RFC 9293 §3.5 (handshake), §3.6 (close), §3.10 (passive open),
plus RFC 6298 §2 (RTO semantics as they apply to SYN-RCVD). Diff
against the A7 commits. Output goes to
docs/superpowers/reviews/phase-a7-rfc-compliance.md in the standard
schema.
```

- [ ] **Step 2: Address Must-fix + Missing-SHOULD items from both reports**

For each `[ ]` in either report's Must-fix / Missed-edge-cases / Missing-SHOULD sections, either:
- implement the fix + update tests + re-run the classifier so the skip list is consistent, or
- move the item to Accepted-deviation with a concrete §6.4 / memory-file citation in the parent spec.

Re-dispatch the reviewer after each round until both reports land clean.

- [ ] **Step 3: Flip roadmap row for A7 to Complete**

In `docs/superpowers/plans/stage1-phase-roadmap.md`, change the A7 row:

```
| A7 | Loopback test server + packetdrill-shim | **Complete** ✓ | `2026-04-21-stage1-phase-a7-loopback-test-server-packetdrill-shim.md` |
```

- [ ] **Step 4: Final green run of every A7 test**

```bash
cargo test -p dpdk-net-core --features test-server
cargo test -p dpdk-net --features test-server
cargo test -p packetdrill-shim-runner --features test-server
./scripts/a7-ligurio-gate.sh
```

- [ ] **Step 5: Commit reviews + roadmap together**

```bash
git add docs/superpowers/reviews/phase-a7-mtcp-compare.md \
        docs/superpowers/reviews/phase-a7-rfc-compliance.md \
        docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "a7 task 18: end-of-phase mTCP + RFC review gates (both clean) + roadmap update"
```

- [ ] **Step 6: Tag the phase**

```bash
git tag -a phase-a7-complete -m "Phase A7 complete: loopback test server + packetdrill-shim (ligurio gate)"
git log --oneline -3
```
Expected: HEAD is the Task 18 commit; `phase-a7-complete` tag points at it.

---

## Self-Review Checklist

**Spec coverage (every §/requirement → task):**
- §1.1 server FSM minimal surface → Tasks 5, 6, 7
- §1.1 shim transport in-memory → Tasks 9, 10, 11
- §1.1 virtual clock → Task 3
- §1.1 corpora (ligurio CI / shivansh+google wired) → Tasks 14, 15
- §1.1 preset=rfc_compliance reuse → inherited from existing code; no task needed (covered by classifier SKIPPED.md exceptions where a script's wire behavior stays preset-gated)
- §1.1 I-8 regression → Task 16
- §1.1 knob-coverage whitelist → Task 17 Step 4
- §1.1 end-of-phase mTCP + RFC reviews → Task 18
- §3.1 server FSM additions (ListenSlot, new_passive, tcp_input hunks) → Task 5
- §3.2 test-FFI + dpdk_net_test.h + exclusion → Task 8
- §3.3 virtual clock cfg-swap → Task 3
- §3.4 patch stack 0001-0005 → Task 10
- §3.5 runner crate layout → Tasks 9, 14
- §3.6 I-8 regression script → Task 16
- §4 data flow + pump discipline → implemented via `pump_until_quiescent` in Task 8
- §5.1 unit tests (listen/passive-close/active-close/virt-clock) → Tasks 5, 6, 7, 3
- §5.2 shim self-tests → Tasks 11, 12
- §5.3 corpus tests → Tasks 14, 15, 16
- §5.4 knob-coverage → Task 17 Step 4
- §5.5 miri matrix extension → Task 17 Step 3
- §5.6 CI wiring → Task 17 Steps 1-2
- §5.7 end-of-phase reviews → Task 18
- §8 success criteria — every item covered in Tasks 14-18 (pinned counts, 10 consecutive runs, SKIPPED.md orphan check, bit-identical default build, perf baseline, clean review reports, roadmap flip, tag)

**No missing spec items.**

**Placeholder scan:** no `TBD`/`TODO`/"etc." in any step. The one "classify iteratively" loop in Task 15 is legitimately iterative — the loop terminates when runnable is green, and each sub-iteration commits atomically.

**Type consistency across tasks:**
- `ListenSlot` / `ListenHandle` / `ConnHandle` names consistent from Task 5 forward.
- `dpdk_net_test_frame_t` signature consistent between `test_ffi.rs` (Task 8), the test-header exclusion check (Task 8), and the shim's in-memory TUN backend (Task 10).
- `pump_until_quiescent` / `pump_until_quiescent_raw` consistently used in Task 8.
- `LIGURIO_RUNNABLE_COUNT` / `LIGURIO_SKIP_UNTRANSLATABLE` / `LIGURIO_SKIP_OUT_OF_SCOPE` names match between Tasks 9 (placeholder), 14 (read), 15 (pin).
- `drain_tx_frames` / `push_tx_frame` / `is_empty` consistent between Task 4 module and later consumers.
- `Engine::inject_rx_frame` / `Engine::listen` / `Engine::accept_next` / `Engine::state_of` consistent from Task 5 onward.

**Frequent commits:** 18 tasks × 1 commit each + Task 15's iterative sub-commits ≈ 20-30 commits total across the phase. Every task is independently reviewable per `feedback_per_task_review_discipline`.
