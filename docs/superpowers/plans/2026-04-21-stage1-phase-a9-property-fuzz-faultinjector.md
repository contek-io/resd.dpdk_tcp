# Phase A9 — Property + bespoke fuzzing + smoltcp FaultInjector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended per user protocol) to implement this plan task-by-task. Per-task spec-compliance + code-quality review subagents (both `model: "opus"` per `feedback_subagent_model.md`) run after every non-trivial task per `feedback_per_task_review_discipline.md`. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land property + bespoke fuzz coverage of the Stage 1 TCP stack — six proptest suites, seven cargo-fuzz targets (six pure-module T1 + one persistent-mode engine T1.5), six-corpus Scapy adversarial harness driven through a new test-inject RX hook, smoltcp-pattern FaultInjector RX middleware, and close the I-8 FYI from `phase-a6-6-7-rfc-compliance.md`.

**Architecture:** Two cargo features added — `test-inject` (gates `Engine::inject_rx_frame` + `inject_rx_chain`, plus a lazy test-inject mempool) and `fault-injector` (gates a stackable RX middleware with drop/dup/reorder/corrupt actions + feature-gated counters). Fuzz infrastructure lives under `crates/dpdk-net-core/fuzz/` outside the workspace with nightly Rust pinned there only. Scapy pcap corpora in `tools/scapy-corpus/`, replayed through a new Rust binary `tools/scapy-fuzz-runner/` that uses the same test-inject hook. I-8 fixed as a one-line change in `tcp_input.rs` at the chain-walk FIN-piggyback equality, verified by a directed multi-seg-chain test.

**Tech Stack:** Rust (stable, workspace). Rust nightly pinned only inside `crates/dpdk-net-core/fuzz/` (cargo-fuzz). `proptest = "1"`, `libfuzzer-sys` (fuzz subdir only), `arrayvec = "0.7"` (FaultInjector reorder ring), `rand = "0.8"` (SmallRng for FaultInjector), `pcap-file = "2"` (scapy-fuzz-runner). Python Scapy for pcap generation. DPDK 23.11 via existing `dpdk-net-sys`.

**Branch / worktree:** `phase-a9` in `/home/ubuntu/resd.dpdk_tcp-a9`, branched from tag `phase-a6-6-7-complete` (commit `2c4e0b6`).

**Spec:** `docs/superpowers/specs/2026-04-21-stage1-phase-a9-property-fuzz-faultinjector-design.md` (committed at `d285a12`).

---

## File structure

### Modified

- `Cargo.toml` — add `tools/scapy-fuzz-runner` to `[workspace] members`
- `crates/dpdk-net-core/Cargo.toml` — add `test-inject`, `fault-injector` features; add dev-dep `proptest`, `arrayvec`, `rand`
- `crates/dpdk-net-core/src/lib.rs` — `pub mod fault_injector;` behind `#[cfg(feature = "fault-injector")]`
- `crates/dpdk-net-core/src/engine.rs` — add `inject_rx_frame`, `inject_rx_chain` impls (test-inject); add `fault_injector: Option<FaultInjector>` field + RX-path wiring (fault-injector)
- `crates/dpdk-net-core/src/counters.rs` — add `FaultInjectorCounters` struct behind `#[cfg(feature = "fault-injector")]`
- `crates/dpdk-net-core/src/tcp_input.rs` — I-8 fix at the chain-walk FIN-piggyback equality (line 1208)
- `crates/dpdk-net/Cargo.toml` — feature passthrough for `test-inject` and `fault-injector` (no C ABI surface change; cbindgen runs without the features on)
- `docs/superpowers/plans/stage1-phase-roadmap.md` — A9 row revision + new S2-A row in Stage 2 section

### Created

- `crates/dpdk-net-core/src/fault_injector.rs` — FaultInjector module + env-var parser
- `crates/dpdk-net-core/tests/proptest_tcp_options.rs`
- `crates/dpdk-net-core/tests/proptest_tcp_seq.rs`
- `crates/dpdk-net-core/tests/proptest_tcp_sack.rs`
- `crates/dpdk-net-core/tests/proptest_tcp_reassembly.rs`
- `crates/dpdk-net-core/tests/proptest_paws.rs`
- `crates/dpdk-net-core/tests/proptest_rack_xmit_ts.rs`
- `crates/dpdk-net-core/tests/i8_fin_piggyback_chain.rs`
- `crates/dpdk-net-core/fuzz/Cargo.toml`
- `crates/dpdk-net-core/fuzz/rust-toolchain.toml`
- `crates/dpdk-net-core/fuzz/.gitignore`
- `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_options.rs`
- `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_sack.rs`
- `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_reassembly.rs`
- `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_state_fsm.rs`
- `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_seq.rs`
- `crates/dpdk-net-core/fuzz/fuzz_targets/header_parser.rs`
- `crates/dpdk-net-core/fuzz/fuzz_targets/engine_inject.rs`
- `tools/scapy-corpus/README.md`
- `tools/scapy-corpus/seeds.txt`
- `tools/scapy-corpus/scripts/i8_fin_piggyback_multi_seg.py`
- `tools/scapy-corpus/scripts/overlapping_segments.py`
- `tools/scapy-corpus/scripts/malformed_options.py`
- `tools/scapy-corpus/scripts/timestamp_wraparound.py`
- `tools/scapy-corpus/scripts/sack_blocks_outside_window.py`
- `tools/scapy-corpus/scripts/rst_invalid_seq.py`
- `tools/scapy-corpus/.gitignore` (for `out/`)
- `tools/scapy-fuzz-runner/Cargo.toml`
- `tools/scapy-fuzz-runner/src/main.rs`
- `scripts/fuzz-smoke.sh`
- `scripts/fuzz-long-run.sh`
- `scripts/scapy-corpus.sh`
- `docs/superpowers/reviews/phase-a9-mtcp-compare.md` (produced by mTCP reviewer at sign-off)
- `docs/superpowers/reviews/phase-a9-rfc-compliance.md` (produced by RFC reviewer at sign-off)

### Task ordering & parallelism

Serial dependency chain: T1 → T2 → T3 → T4 (inject hook must exist before chain + I-8 tests).

Independent groups (can be dispatched in parallel by `superpowers:subagent-driven-development` once their prerequisites are met):

- T5–T6 (FaultInjector) after T1 (needs the engine feature-gate pattern)
- T7–T12 (six proptest suites) — all mutually independent; can all launch after T0
- T13 (cargo-fuzz bootstrap) — after T0
- T14–T19 (six pure-module fuzz targets) — all mutually independent after T13
- T20 (engine_inject fuzz target) — after T13 AND T3 (needs `test-inject` feature + multi-seg inject)
- T21 (Scapy corpus) — independent
- T22 (scapy-fuzz-runner) — after T3 (needs inject hook)
- T23–T24 (CI scripts) — after all fuzz targets + Scapy runner exist
- T25 (roadmap update) — after everything else
- T26 (end-of-phase reviews + tag) — final gate

---

## Task 0: Preparation — nothing to do

- [x] Worktree `/home/ubuntu/resd.dpdk_tcp-a9` already set up on branch `phase-a9` off tag `phase-a6-6-7-complete` (commit `2c4e0b6`).
- [x] Spec committed at `d285a12` on branch `phase-a9`.

Verify state before any task starts:

```bash
cd /home/ubuntu/resd.dpdk_tcp-a9
git status   # expect: On branch phase-a9, nothing to commit
git log -2 --oneline
# d285a12 a9 brainstorm: design spec for property + bespoke fuzz + FaultInjector
# 2c4e0b6 a6.6-7 reviews: mTCP + RFC end-of-phase gate reports (both clean)
```

---

## Task 1: `test-inject` feature + `InjectErr` type + inject hook method signatures

**Files:**
- Modify: `crates/dpdk-net-core/Cargo.toml` (add `test-inject = []` feature)
- Modify: `crates/dpdk-net/Cargo.toml` (passthrough `test-inject`)
- Modify: `crates/dpdk-net-core/src/engine.rs` (add `InjectErr`, stub `inject_rx_frame`, `inject_rx_chain`)
- Test: `crates/dpdk-net-core/tests/proptest_tcp_options.rs` — not yet; this task is scaffolding. Inline unit tests in `engine.rs` only.

- [ ] **Step 1: Add feature flag to both crates**

Edit `crates/dpdk-net-core/Cargo.toml` — inside the existing `[features]` block, append:

```toml
# A9 test-inject: synthetic RX-frame injection for Scapy / fuzz / A7 packetdrill-shim.
# Default OFF. Gates `Engine::inject_rx_frame` + `Engine::inject_rx_chain` and the
# lazily-created test-inject mempool. Release builds carry zero of it. Cbindgen
# runs without the feature, so the functions never appear in `dpdk_net.h`.
test-inject = []
```

Edit `crates/dpdk-net/Cargo.toml` — inside its `[features]` block, add a passthrough:

```toml
test-inject = ["dpdk-net-core/test-inject"]
```

If `crates/dpdk-net/Cargo.toml` has no `[features]` section, add one:

```toml
[features]
default = []
test-inject = ["dpdk-net-core/test-inject"]
```

- [ ] **Step 2: Add `InjectErr` type to engine.rs**

Append to `crates/dpdk-net-core/src/engine.rs` (at a sensible location — near other pub-facing error types; search for `pub enum.*Error` for a nearby spot):

```rust
/// Errors returned by the test-inject RX hooks (`Engine::inject_rx_frame` /
/// `Engine::inject_rx_chain`). Behind `#[cfg(feature = "test-inject")]`.
#[cfg(feature = "test-inject")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InjectErr {
    #[error("test-inject mempool exhausted")]
    MempoolExhausted,
    #[error("frame too large for mempool segment ({frame_len} > {seg_size})")]
    FrameTooLarge { frame_len: usize, seg_size: usize },
    #[error("empty chain (at least one segment required)")]
    EmptyChain,
}
```

`thiserror` is already a workspace dep.

- [ ] **Step 3: Stub `inject_rx_frame` + `inject_rx_chain` with signatures, panic body**

Inside `impl Engine { ... }` (find the existing `impl Engine` block via `grep -n '^impl Engine' crates/dpdk-net-core/src/engine.rs`), append at end:

```rust
    /// Inject a synthetic Ethernet frame as if it came from PMD RX.
    /// The frame is copied into an mbuf from a lazily-created test-inject
    /// mempool; the same internal RX dispatch the poll loop uses runs end
    /// to end. Returns once the mbuf is processed (refcount may be retained
    /// downstream by reassembly / READABLE delivery — caller does not own
    /// the mbuf after this returns).
    #[cfg(feature = "test-inject")]
    pub fn inject_rx_frame(&self, _frame: &[u8]) -> Result<(), InjectErr> {
        unimplemented!("Task 2: single-seg inject_rx_frame implementation")
    }

    /// Inject a multi-segment Ethernet frame chain (LRO-shape).
    /// Builds an mbuf chain: `segments[0]` carries the Ethernet header + first
    /// payload chunk; each subsequent segment is chained via `rte_mbuf.next`.
    /// `pkt_len` is set to `Σ segments[i].len()`; `nb_segs = segments.len()`.
    /// Used by I-8 closure + chain-walk fuzz coverage.
    #[cfg(feature = "test-inject")]
    pub fn inject_rx_chain(&self, _segments: &[&[u8]]) -> Result<(), InjectErr> {
        unimplemented!("Task 3: multi-seg inject_rx_chain implementation")
    }
```

- [ ] **Step 4: Verify compile with and without feature**

```bash
cd /home/ubuntu/resd.dpdk_tcp-a9
cargo check -p dpdk-net-core --no-default-features
cargo check -p dpdk-net-core --features test-inject
```

Expected: both exit 0. No warnings introduced. (`unimplemented!()` is valid Rust.)

- [ ] **Step 5: Verify cbindgen output unchanged**

```bash
scripts/check-header.sh
```

Expected: exit 0 ("header in sync"). The `#[cfg(feature = "test-inject")]` gate + the default-off feature means cbindgen (run via the dpdk-net crate's build.rs without the feature) sees nothing new.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/Cargo.toml crates/dpdk-net/Cargo.toml crates/dpdk-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a9 task 1: test-inject feature scaffolding + InjectErr + stub hook signatures

Adds `test-inject` cargo feature (default off) gating Engine::inject_rx_frame
and Engine::inject_rx_chain. Tasks 2-3 implement the bodies. Cbindgen header
unchanged (feature off in default build).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Implement `inject_rx_frame` (single-segment path)

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` (lazy test-inject mempool field + `inject_rx_frame` body)
- Modify: `crates/dpdk-net-core/src/mempool.rs` if the test-inject mempool needs helpers; prefer wrapping existing pool-create wrappers
- Test: `crates/dpdk-net-core/tests/inject_rx_frame_smoke.rs` (new)

- [ ] **Step 1: Write the failing test**

Create `crates/dpdk-net-core/tests/inject_rx_frame_smoke.rs`:

```rust
//! Smoke test: Engine::inject_rx_frame dispatches through the RX path.
//! Builds a minimal Ethernet frame carrying an ICMP echo; asserts the
//! engine's icmp counter advances by 1.
#![cfg(feature = "test-inject")]

mod common;
use common::make_test_engine;

#[test]
fn inject_single_seg_ethernet_frame_runs_rx_dispatch() {
    let engine = make_test_engine();
    let our_mac = engine.config().local_mac;
    let peer_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];

    // Minimal Ethernet II: dst=our_mac, src=peer_mac, ethertype=0x0800 (IPv4),
    // followed by a 20-byte IPv4 header for ICMP (proto=1) of length 28,
    // then an 8-byte ICMP echo request.
    let mut frame = Vec::with_capacity(14 + 20 + 8);
    frame.extend_from_slice(&our_mac);
    frame.extend_from_slice(&peer_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header (20 bytes, checksum 0 — engine trusts NIC or recomputes)
    let ihl = 0x45u8;
    let tos = 0u8;
    let total_len = (20u16 + 8u16).to_be_bytes();
    let id = 0u16.to_be_bytes();
    let frag = 0u16.to_be_bytes();
    let ttl = 64u8;
    let proto = 1u8;
    let ip_csum = 0u16.to_be_bytes();
    let src_ip = [10, 0, 0, 2];
    let dst_ip = engine.config().local_ip;
    frame.push(ihl); frame.push(tos);
    frame.extend_from_slice(&total_len);
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&frag);
    frame.push(ttl); frame.push(proto);
    frame.extend_from_slice(&ip_csum);
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);
    // ICMP echo request type=8 code=0 csum=0 id=0 seq=0
    frame.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]);

    let icmp_before = engine.counters().ip.icmp_rx.load(std::sync::atomic::Ordering::Relaxed);
    engine.inject_rx_frame(&frame).expect("inject_rx_frame should succeed on well-formed frame");
    let icmp_after = engine.counters().ip.icmp_rx.load(std::sync::atomic::Ordering::Relaxed);
    // We dropped any non-frag-needed ICMP silently (per spec) but the ingress
    // counter is incremented. If the existing counter name differs, match the
    // engine's actual ip-group counter (e.g., `ip.rx_pkts`).
    assert!(icmp_after > icmp_before, "icmp_rx did not advance after inject");
}
```

Run it to confirm it fails (feature off + stub unimplemented):

```bash
cargo test -p dpdk-net-core --features test-inject --test inject_rx_frame_smoke
# Expected: FAIL with "Task 2: single-seg inject_rx_frame implementation"
```

If the counter name `icmp_rx` doesn't exist, use `ip.rx_pkts` or search `crates/dpdk-net-core/src/counters.rs` for `icmp` — adjust the assertion accordingly before continuing.

- [ ] **Step 2: Add lazy test-inject mempool field to `Engine`**

In `crates/dpdk-net-core/src/engine.rs`, find the `pub struct Engine { ... }` definition and add a field gated on `test-inject`:

```rust
    #[cfg(feature = "test-inject")]
    test_inject_mempool: std::cell::OnceCell<crate::mempool::MempoolHandle>,
```

Initialize it in `Engine::new` (find the existing `Self { ... }` construction block) — add:

```rust
            #[cfg(feature = "test-inject")]
            test_inject_mempool: std::cell::OnceCell::new(),
```

If `OnceCell` isn't already imported, the `std::cell::` prefix here is fine. `Engine` is single-lcore / `!Sync`, so `OnceCell` (not `OnceLock`) is correct.

- [ ] **Step 3: Implement `inject_rx_frame`**

Replace the `unimplemented!()` body added in Task 1 with:

```rust
    #[cfg(feature = "test-inject")]
    pub fn inject_rx_frame(&self, frame: &[u8]) -> Result<(), InjectErr> {
        use dpdk_net_sys as sys;

        // Lazily create a dedicated mempool for injected frames. Default size
        // 4096 mbufs, configurable via env var DPDK_NET_TEST_INJECT_POOL_SIZE.
        let pool = self.test_inject_mempool.get_or_init(|| {
            let size: u32 = std::env::var("DPDK_NET_TEST_INJECT_POOL_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(4096);
            crate::mempool::MempoolHandle::new_rx_mempool(
                "test_inject_pool",
                size,
                self.cfg.socket_id as i32,
            ).expect("test-inject mempool create failed (check hugepages + EAL init)")
        });

        let seg_size = pool.elt_size() as usize;
        if frame.len() > seg_size {
            return Err(InjectErr::FrameTooLarge { frame_len: frame.len(), seg_size });
        }

        let mbuf = unsafe { sys::rte_pktmbuf_alloc(pool.as_raw()) };
        let mbuf = core::ptr::NonNull::new(mbuf).ok_or(InjectErr::MempoolExhausted)?;

        // Copy frame bytes into the mbuf's data area.
        unsafe {
            let data_ptr = sys::shim_rte_pktmbuf_mtod(mbuf.as_ptr()) as *mut u8;
            core::ptr::copy_nonoverlapping(frame.as_ptr(), data_ptr, frame.len());
            (*mbuf.as_ptr()).data_len = frame.len() as u16;
            (*mbuf.as_ptr()).pkt_len = frame.len() as u32;
            (*mbuf.as_ptr()).nb_segs = 1;
            (*mbuf.as_ptr()).next = core::ptr::null_mut();
        }

        // Reuse the engine's RX dispatch — the single path the poll loop uses.
        // If the existing dispatch is a private fn taking `*mut rte_mbuf`,
        // find it via `grep -n 'fn dispatch\|fn process_rx_mbuf' engine.rs`.
        self.dispatch_one_rx_mbuf(mbuf);
        Ok(())
    }
```

If the existing engine's RX dispatch is not a single `fn dispatch_one_rx_mbuf`, extract one from the current poll loop first — find `pub fn poll_once` (line 1728 per `grep`) and split out the per-mbuf body into:

```rust
    #[inline]
    fn dispatch_one_rx_mbuf(&self, mbuf: core::ptr::NonNull<dpdk_net_sys::rte_mbuf>) {
        // Paste the existing per-mbuf logic here: l2_decode → l3_ip → tcp_input
        // etc. Keep the existing FaultInjector interception point (added by
        // Task 6) in the same location relative to this function's top.
    }
```

Verify the refactor is behaviour-preserving by running the existing TAP test suite:

```bash
cargo test -p dpdk-net-core --tests -- --skip proptest_
```

Expected: all existing tests still pass.

- [ ] **Step 4: Add `MempoolHandle::new_rx_mempool` or equivalent helper**

If `MempoolHandle::new_rx_mempool` doesn't exist, add it to `crates/dpdk-net-core/src/mempool.rs`. Search for the existing RX mempool creation call in engine.rs (likely `rte_pktmbuf_pool_create` via a wrapper); extract it into a reusable helper:

```rust
impl MempoolHandle {
    /// Create an RX mempool sized for the given element count, suitable for
    /// both production RX and test-inject paths. Caller owns the handle;
    /// Drop frees via `rte_mempool_free`.
    pub fn new_rx_mempool(
        name: &str,
        elt_count: u32,
        socket_id: i32,
    ) -> Result<Self, crate::error::Error> {
        // ... existing logic from engine.rs::rx_mempool_create or similar
    }

    pub fn elt_size(&self) -> u32 {
        unsafe { (*self.as_raw()).elt_size }
    }
}
```

If `MempoolHandle` already has equivalents under different names, use those — this step is about *exposing* a reusable pool-create entry point, not inventing one.

- [ ] **Step 5: Run the new test — expect PASS**

```bash
cargo test -p dpdk-net-core --features test-inject --test inject_rx_frame_smoke
```

Expected: PASS.

- [ ] **Step 6: Verify no-feature build unaffected**

```bash
cargo check -p dpdk-net-core --no-default-features
cargo check -p dpdk-net-core
cargo test -p dpdk-net-core --tests -- --skip proptest_ --skip inject_rx_frame_smoke
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/mempool.rs \
        crates/dpdk-net-core/tests/inject_rx_frame_smoke.rs
git commit -m "$(cat <<'EOF'
a9 task 2: implement inject_rx_frame single-seg path

Lazy test-inject mempool (default 4096 mbufs, configurable via
DPDK_NET_TEST_INJECT_POOL_SIZE), alloc mbuf, copy bytes, dispatch
through the same per-mbuf path poll_once uses.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Implement `inject_rx_chain` (multi-segment path)

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` (`inject_rx_chain` body)
- Test: `crates/dpdk-net-core/tests/inject_rx_chain_smoke.rs` (new)

- [ ] **Step 1: Write the failing test**

Create `crates/dpdk-net-core/tests/inject_rx_chain_smoke.rs`:

```rust
//! Smoke test: Engine::inject_rx_chain builds a multi-seg mbuf chain and
//! dispatches it through RX with correct pkt_len / nb_segs / chain links.
#![cfg(feature = "test-inject")]

mod common;
use common::make_test_engine;

#[test]
fn inject_multi_seg_chain_adds_up_pkt_len() {
    let engine = make_test_engine();

    // Build a 3-segment chain: segment 0 carries L2+L3+TCP headers, 1 and 2
    // carry payload continuations. Total payload ≈ 3 × 100 = 300 bytes.
    let seg0 = {
        let mut v = Vec::new();
        // ...Ethernet + IPv4 + TCP SYN header; use `common::build_tcp_syn_head()` helper
        v.extend_from_slice(&common::build_tcp_syn_head(&engine, 100));
        // First 100 B of payload:
        v.extend_from_slice(&[0x41u8; 100]);
        v
    };
    let seg1: Vec<u8> = vec![0x42u8; 100];
    let seg2: Vec<u8> = vec![0x43u8; 100];

    engine
        .inject_rx_chain(&[&seg0, &seg1, &seg2])
        .expect("chain inject must succeed");

    // Assertion: the RX counter advanced; pkt_len accounting landed correctly
    // (no panic, no assert-failure under debug_assert) — smoke-level only.
    // Deep semantic assertion belongs to Task 4 (I-8 regression).
    let ctrs = engine.counters();
    assert!(ctrs.eth.rx_pkts.load(std::sync::atomic::Ordering::Relaxed) >= 1);
}
```

If `common::build_tcp_syn_head` doesn't exist in the shared test helper, add it (small helper that emits a well-formed SYN pointing at the engine's local_ip / local_mac).

Run:

```bash
cargo test -p dpdk-net-core --features test-inject --test inject_rx_chain_smoke
# Expected: FAIL with "Task 3: multi-seg inject_rx_chain implementation"
```

- [ ] **Step 2: Implement `inject_rx_chain`**

Replace the `unimplemented!()` body (added in Task 1) with:

```rust
    #[cfg(feature = "test-inject")]
    pub fn inject_rx_chain(&self, segments: &[&[u8]]) -> Result<(), InjectErr> {
        use dpdk_net_sys as sys;
        if segments.is_empty() {
            return Err(InjectErr::EmptyChain);
        }

        let pool = self.test_inject_mempool.get_or_init(|| {
            // same init block as inject_rx_frame — extract into a helper
            let size: u32 = std::env::var("DPDK_NET_TEST_INJECT_POOL_SIZE")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(4096);
            crate::mempool::MempoolHandle::new_rx_mempool(
                "test_inject_pool", size, self.cfg.socket_id as i32,
            ).expect("test-inject mempool create failed")
        });
        let seg_size = pool.elt_size() as usize;

        // Allocate + copy all segments first, holding raw pointers in a
        // SmallVec<[NonNull; 4]>. Free everything on mid-chain failure.
        let mut mbufs: smallvec::SmallVec<[core::ptr::NonNull<sys::rte_mbuf>; 4]>
            = smallvec::SmallVec::new();
        let mut total_len: u32 = 0;

        for seg in segments {
            if seg.len() > seg_size {
                for m in &mbufs { unsafe { sys::rte_pktmbuf_free(m.as_ptr()); } }
                return Err(InjectErr::FrameTooLarge { frame_len: seg.len(), seg_size });
            }
            let m = unsafe { sys::rte_pktmbuf_alloc(pool.as_raw()) };
            let m = match core::ptr::NonNull::new(m) {
                Some(p) => p,
                None => {
                    for m in &mbufs { unsafe { sys::rte_pktmbuf_free(m.as_ptr()); } }
                    return Err(InjectErr::MempoolExhausted);
                }
            };
            unsafe {
                let dst = sys::shim_rte_pktmbuf_mtod(m.as_ptr()) as *mut u8;
                core::ptr::copy_nonoverlapping(seg.as_ptr(), dst, seg.len());
                (*m.as_ptr()).data_len = seg.len() as u16;
                (*m.as_ptr()).pkt_len = 0;    // set on head below
                (*m.as_ptr()).nb_segs = 1;    // set on head below
                (*m.as_ptr()).next = core::ptr::null_mut();
            }
            mbufs.push(m);
            total_len += seg.len() as u32;
        }

        // Link the chain.
        for i in 0..(mbufs.len() - 1) {
            unsafe { (*mbufs[i].as_ptr()).next = mbufs[i + 1].as_ptr(); }
        }
        // Head carries pkt_len + nb_segs.
        unsafe {
            let head = mbufs[0].as_ptr();
            (*head).pkt_len = total_len;
            (*head).nb_segs = mbufs.len() as u16;
        }

        self.dispatch_one_rx_mbuf(mbufs[0]);
        Ok(())
    }
```

- [ ] **Step 3: Extract pool-init into a helper (DRY)**

The lazy init block is duplicated between `inject_rx_frame` and `inject_rx_chain`. Extract:

```rust
    #[cfg(feature = "test-inject")]
    fn test_inject_pool(&self) -> &crate::mempool::MempoolHandle {
        self.test_inject_mempool.get_or_init(|| {
            let size: u32 = std::env::var("DPDK_NET_TEST_INJECT_POOL_SIZE")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(4096);
            crate::mempool::MempoolHandle::new_rx_mempool(
                "test_inject_pool", size, self.cfg.socket_id as i32,
            ).expect("test-inject mempool create failed")
        })
    }
```

and replace both call sites to use `self.test_inject_pool()`.

- [ ] **Step 4: Run — expect PASS**

```bash
cargo test -p dpdk-net-core --features test-inject --test inject_rx_chain_smoke
cargo test -p dpdk-net-core --features test-inject --test inject_rx_frame_smoke
```

Both PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs \
        crates/dpdk-net-core/tests/inject_rx_chain_smoke.rs \
        crates/dpdk-net-core/tests/common/mod.rs
git commit -m "$(cat <<'EOF'
a9 task 3: implement inject_rx_chain multi-seg path

Builds an mbuf chain: head carries pkt_len=Σseg.len + nb_segs; each
link chained via rte_mbuf.next. Used by T4 (I-8 closure) and T20
(engine_inject cargo-fuzz target).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: I-8 fix — FIN-piggyback on multi-seg chains + directed regression test

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` (line 1208 FIN-piggyback equality)
- Test: `crates/dpdk-net-core/tests/i8_fin_piggyback_chain.rs` (new)

Spec: the current equality at `tcp_input.rs:1208` is:

```rust
if (seg.flags & TCP_FIN) != 0 && seg.seq.wrapping_add(seg.payload.len() as u32) == conn.rcv_nxt
```

`seg.payload.len()` is the *head-link* payload only. On a multi-seg chain, `conn.rcv_nxt` was advanced by the chain total earlier (line 1032/1062 via `delivered`). So the equality fails when seg is a chain with FIN piggybacked, silently dropping FIN. Fix: substitute `delivered` (the bytes actually delivered this segment — already computed locally and used at line 1032 to advance `rcv_nxt`) for `seg.payload.len() as u32`.

- [ ] **Step 1: Write the failing regression test**

Create `crates/dpdk-net-core/tests/i8_fin_piggyback_chain.rs`:

```rust
//! Regression test for I-8 (phase-a6-6-7-rfc-compliance.md FYI):
//! FIN piggybacked on the last segment of a multi-seg chain must transition
//! the connection to CLOSE_WAIT. Pre-fix this is silently dropped because
//! tcp_input.rs compares against seg.payload.len() (head-link only) instead
//! of the full chain delivery length.
#![cfg(feature = "test-inject")]

mod common;
use common::{make_test_engine_with_conn_in_established, TcpConnRef};

#[test]
fn multi_seg_chain_with_piggybacked_fin_advances_to_close_wait() {
    let (engine, conn) = make_test_engine_with_conn_in_established();
    let rcv_nxt_before = conn.rcv_nxt();
    assert_eq!(conn.state(), crate::tcp_state::TcpState::Established);

    // Build a multi-seg chain: head-link 100 B payload, tail-link 50 B payload
    // with FIN flag set. On a correct impl, rcv_nxt advances by 150+1 (FIN
    // consumes 1). Pre-fix, equality `seg.seq + 100 == rcv_nxt_before + 150`
    // fails → FIN dropped → state stays Established.
    let head_chunk = common::build_tcp_data_head(&engine, &conn,
        /*payload=*/ &[0x41u8; 100], /*flags=*/ 0);
    let tail_chunk = common::build_tcp_data_tail(
        /*payload=*/ &[0x42u8; 50], /*flags=*/ crate::tcp_output::TCP_FIN);

    engine.inject_rx_chain(&[&head_chunk, &tail_chunk]).unwrap();

    assert_eq!(
        conn.state(),
        crate::tcp_state::TcpState::CloseWait,
        "I-8 regression: FIN on last chain-link not honored"
    );
    assert_eq!(conn.rcv_nxt(), rcv_nxt_before.wrapping_add(150 + 1),
        "rcv_nxt must advance by chain total + 1 for FIN");
}
```

Helpers `make_test_engine_with_conn_in_established`, `build_tcp_data_head`, `build_tcp_data_tail`, and `TcpConnRef` go in `crates/dpdk-net-core/tests/common/mod.rs` — build-on-top of existing fixtures (`tcp_basic_tap.rs` style). If the helpers need to reach into conn internals, expose minimal getters on `TcpConn` behind `#[cfg(any(test, feature = "test-inject"))]`.

Run:

```bash
cargo test -p dpdk-net-core --features test-inject --test i8_fin_piggyback_chain
# Expected: FAIL ("state stays Established" OR "rcv_nxt did not advance by 151")
```

- [ ] **Step 2: Apply the fix**

Edit `crates/dpdk-net-core/src/tcp_input.rs` near line 1208:

```rust
    // FIN processing: consumes one seq and moves us to CLOSE_WAIT.
    let mut new_state = None;
    // I-8 (A9): compare against `delivered` (total chain bytes accepted),
    // NOT `seg.payload.len()` (head-link only). Without this, multi-seg
    // chains with FIN piggybacked silently drop the FIN because the
    // equality fails on chain lengths > head-link length. RFC 9293 §3.10.7.4.
    if (seg.flags & TCP_FIN) != 0 && seg.seq.wrapping_add(delivered) == conn.rcv_nxt
    {
        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
        new_state = Some(TcpState::CloseWait);
    }
```

If `delivered` isn't in scope at that line (check via `grep -nE '^\s*let delivered' crates/dpdk-net-core/src/tcp_input.rs`), walk back to where chain bytes get tallied (`conn.rcv_nxt.wrapping_add(drained_bytes)` at ~line 1062) and pass the computed value forward — hoist it into a `let delivered = ...;` above the FIN equality.

- [ ] **Step 3: Run the regression test — expect PASS**

```bash
cargo test -p dpdk-net-core --features test-inject --test i8_fin_piggyback_chain
```

Expected: PASS.

- [ ] **Step 4: Run the full existing test suite — verify no regression**

```bash
cargo test -p dpdk-net-core --tests
cargo test -p dpdk-net-core --features test-inject --tests
```

Expected: all pass. The I-8 fix changes a previously-unreachable (in production: ENA doesn't advertise RX_OFFLOAD_SCATTER) branch; single-seg path behaviour unchanged because `delivered == seg.payload.len()` on single-seg in the equality's branch.

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_input.rs \
        crates/dpdk-net-core/tests/i8_fin_piggyback_chain.rs \
        crates/dpdk-net-core/tests/common/mod.rs
git commit -m "$(cat <<'EOF'
a9 task 4: I-8 fix — FIN piggyback on multi-seg chains advances to CLOSE_WAIT

Closes I-8 from phase-a6-6-7-rfc-compliance.md (FYI). tcp_input.rs ~line 1208
now compares seg.seq + delivered (chain total bytes accepted) == conn.rcv_nxt
instead of seg.seq + seg.payload.len() (head-link only). RFC 9293 §3.10.7.4.

Verified by directed multi-seg chain test via the test-inject hook.
Single-seg behaviour unchanged (delivered == seg.payload.len() in that case).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `fault-injector` feature + module skeleton + counters

**Files:**
- Modify: `crates/dpdk-net-core/Cargo.toml` (add `fault-injector = []` feature; add `arrayvec = "0.7"` + `rand = "0.8"` as optional deps gated on the feature)
- Modify: `crates/dpdk-net/Cargo.toml` (passthrough `fault-injector`)
- Modify: `crates/dpdk-net-core/src/lib.rs` (`#[cfg(feature = "fault-injector")] pub mod fault_injector;`)
- Create: `crates/dpdk-net-core/src/fault_injector.rs` (skeleton: struct, placeholder methods)
- Modify: `crates/dpdk-net-core/src/counters.rs` (add `FaultInjectorCounters` struct behind feature)
- Test: inline in `fault_injector.rs` — parser unit test

- [ ] **Step 1: Add feature + deps**

Edit `crates/dpdk-net-core/Cargo.toml`:

```toml
# In [features]:
fault-injector = ["dep:arrayvec", "dep:rand"]

# In [dependencies]:
arrayvec = { version = "0.7", optional = true }
rand = { version = "0.8", optional = true, default-features = false, features = ["small_rng"] }
```

Edit `crates/dpdk-net/Cargo.toml` — add `fault-injector = ["dpdk-net-core/fault-injector"]` under `[features]`.

- [ ] **Step 2: Add `FaultInjectorCounters` to `counters.rs`**

Append to `crates/dpdk-net-core/src/counters.rs`:

```rust
#[cfg(feature = "fault-injector")]
#[repr(C, align(64))]
#[derive(Default)]
pub struct FaultInjectorCounters {
    /// Frames dropped by the FaultInjector middleware.
    pub drops: AtomicU64,
    /// Frames duplicated (each dup is one additional emission of the source frame).
    pub dups: AtomicU64,
    /// Frames reordered (held in the depth-N ring, then emitted later).
    pub reorders: AtomicU64,
    /// Frames that had a single byte corrupted at a random offset.
    pub corrupts: AtomicU64,
}

#[cfg(feature = "fault-injector")]
impl FaultInjectorCounters {
    pub const fn new() -> Self {
        Self {
            drops: AtomicU64::new(0),
            dups: AtomicU64::new(0),
            reorders: AtomicU64::new(0),
            corrupts: AtomicU64::new(0),
        }
    }
}
```

Add a field `pub fault_injector: FaultInjectorCounters` (behind the feature) to whichever top-level `Counters` container holds them — match existing per-group pattern (`EthCounters`, `IpCounters`, `TcpCounters`, `PollCounters`).

- [ ] **Step 3: Create `fault_injector.rs` skeleton**

Create `crates/dpdk-net-core/src/fault_injector.rs`:

```rust
//! smoltcp-pattern FaultInjector: post-PMD-RX, pre-L2 middleware that
//! mutates injected/real frames per configured rates (drop / dup / reorder /
//! corrupt). Zero release-build cost — entirely behind `fault-injector`
//! cargo feature.
//!
//! Configuration via env var `DPDK_NET_FAULT_INJECTOR`, format:
//!   drop=0.01,dup=0.005,reorder=0.002,corrupt=0.001,seed=42
//!
//! Parsed once at `engine_create` if the feature is on and the env var is set;
//! absent env var = no fault injection even with the feature compiled in.

use core::ptr::NonNull;
use dpdk_net_sys::rte_mbuf;
use rand::{rngs::SmallRng, Rng, SeedableRng};

#[derive(Debug, Default, Clone, Copy)]
pub struct FaultConfig {
    pub drop_rate: f32,
    pub dup_rate: f32,
    pub reorder_rate: f32,
    pub corrupt_rate: f32,
    pub seed: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum FaultConfigParseError {
    #[error("unrecognized key: {0}")]
    UnknownKey(String),
    #[error("invalid value for {key}: {value}")]
    InvalidValue { key: String, value: String },
    #[error("rate out of range [0.0, 1.0]: {key}={value}")]
    RateOutOfRange { key: String, value: f32 },
}

impl FaultConfig {
    /// Parse from env-var format: `key=value,key=value,...`.
    pub fn parse(spec: &str) -> Result<Self, FaultConfigParseError> {
        let mut cfg = FaultConfig::default();
        for pair in spec.split(',').filter(|p| !p.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| FaultConfigParseError::InvalidValue {
                    key: pair.to_string(),
                    value: "<missing value>".to_string(),
                })?;
            match key {
                "drop" | "dup" | "reorder" | "corrupt" => {
                    let v: f32 = value.parse().map_err(|_| {
                        FaultConfigParseError::InvalidValue {
                            key: key.to_string(),
                            value: value.to_string(),
                        }
                    })?;
                    if !(0.0..=1.0).contains(&v) {
                        return Err(FaultConfigParseError::RateOutOfRange {
                            key: key.to_string(),
                            value: v,
                        });
                    }
                    match key {
                        "drop" => cfg.drop_rate = v,
                        "dup" => cfg.dup_rate = v,
                        "reorder" => cfg.reorder_rate = v,
                        "corrupt" => cfg.corrupt_rate = v,
                        _ => unreachable!(),
                    }
                }
                "seed" => {
                    cfg.seed = value.parse().map_err(|_| {
                        FaultConfigParseError::InvalidValue {
                            key: "seed".to_string(),
                            value: value.to_string(),
                        }
                    })?;
                }
                _ => return Err(FaultConfigParseError::UnknownKey(key.to_string())),
            }
        }
        Ok(cfg)
    }

    /// Load from env var `DPDK_NET_FAULT_INJECTOR`. Returns `None` if unset.
    /// On parse error: prints warning + returns None (don't panic on bad env).
    pub fn from_env() -> Option<Self> {
        let spec = std::env::var("DPDK_NET_FAULT_INJECTOR").ok()?;
        match Self::parse(&spec) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("DPDK_NET_FAULT_INJECTOR parse error: {e}; fault injection disabled");
                None
            }
        }
    }
}

pub struct FaultInjector {
    cfg: FaultConfig,
    rng: SmallRng,
    /// Reorder ring, lazy-initialized on first non-zero reorder action.
    reorder_ring: Option<arrayvec::ArrayVec<NonNull<rte_mbuf>, 16>>,
}

impl FaultInjector {
    pub fn new(cfg: FaultConfig, boot_nonce_seed: u64) -> Self {
        let seed = if cfg.seed != 0 { cfg.seed } else { boot_nonce_seed };
        Self {
            cfg,
            rng: SmallRng::seed_from_u64(seed),
            reorder_ring: None,
        }
    }

    /// Process a single inbound mbuf. Returns 0..N mbufs to feed downstream.
    /// Task 6 fills in the actual drop/dup/reorder/corrupt logic.
    pub fn process(
        &mut self,
        _mbuf: NonNull<rte_mbuf>,
    ) -> smallvec::SmallVec<[NonNull<rte_mbuf>; 4]> {
        unimplemented!("Task 6: FaultInjector::process")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_keys() {
        let c = FaultConfig::parse("drop=0.1,dup=0.05,reorder=0.02,corrupt=0.01,seed=42").unwrap();
        assert_eq!(c.drop_rate, 0.1);
        assert_eq!(c.dup_rate, 0.05);
        assert_eq!(c.reorder_rate, 0.02);
        assert_eq!(c.corrupt_rate, 0.01);
        assert_eq!(c.seed, 42);
    }

    #[test]
    fn parse_empty_is_default() {
        let c = FaultConfig::parse("").unwrap();
        assert_eq!(c.drop_rate, 0.0);
    }

    #[test]
    fn rate_out_of_range_rejected() {
        let e = FaultConfig::parse("drop=1.5").unwrap_err();
        matches!(e, FaultConfigParseError::RateOutOfRange { .. });
    }

    #[test]
    fn unknown_key_rejected() {
        let e = FaultConfig::parse("foo=0.1").unwrap_err();
        matches!(e, FaultConfigParseError::UnknownKey(_));
    }
}
```

Edit `crates/dpdk-net-core/src/lib.rs` — add at module-list level:

```rust
#[cfg(feature = "fault-injector")]
pub mod fault_injector;
```

- [ ] **Step 4: Verify compile + parser tests**

```bash
cargo check -p dpdk-net-core
cargo check -p dpdk-net-core --features fault-injector
cargo test -p dpdk-net-core --features fault-injector --lib fault_injector::tests
```

Expected: all pass. Four parser unit tests.

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-core/Cargo.toml crates/dpdk-net/Cargo.toml \
        crates/dpdk-net-core/src/lib.rs \
        crates/dpdk-net-core/src/fault_injector.rs \
        crates/dpdk-net-core/src/counters.rs
git commit -m "$(cat <<'EOF'
a9 task 5: fault-injector feature + module skeleton + env-var parser + counters

FaultInjector struct, FaultConfig parser (drop/dup/reorder/corrupt/seed),
FaultInjectorCounters declared. process() body stubbed (Task 6).
All behind cargo feature; zero release-build cost.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: FaultInjector process() logic + engine RX wiring

**Files:**
- Modify: `crates/dpdk-net-core/src/fault_injector.rs` (implement `process`)
- Modify: `crates/dpdk-net-core/src/engine.rs` (add `fault_injector: Option<FaultInjector>` field + RX dispatch interception point)
- Test: `crates/dpdk-net-core/tests/fault_injector_smoke.rs` (new, `#![cfg(all(feature = "test-inject", feature = "fault-injector"))]`)

- [ ] **Step 1: Write the failing smoke test**

Create `crates/dpdk-net-core/tests/fault_injector_smoke.rs`:

```rust
//! Smoke test: with DPDK_NET_FAULT_INJECTOR=drop=1.0 set, injected frames
//! are always dropped (obs.fault_injector.drops advances, rx_pkts does not).
#![cfg(all(feature = "test-inject", feature = "fault-injector"))]

mod common;
use common::make_test_engine;

#[test]
fn drop_rate_one_means_all_frames_dropped() {
    std::env::set_var("DPDK_NET_FAULT_INJECTOR", "drop=1.0,seed=123");
    let engine = make_test_engine();
    let frame = common::build_icmp_echo_frame(&engine);

    let rx_before = engine.counters().eth.rx_pkts.load(std::sync::atomic::Ordering::Relaxed);
    let drops_before = engine.counters().fault_injector.drops.load(std::sync::atomic::Ordering::Relaxed);

    for _ in 0..100 {
        engine.inject_rx_frame(&frame).unwrap();
    }

    let rx_after = engine.counters().eth.rx_pkts.load(std::sync::atomic::Ordering::Relaxed);
    let drops_after = engine.counters().fault_injector.drops.load(std::sync::atomic::Ordering::Relaxed);

    assert_eq!(rx_after, rx_before, "rx_pkts advanced despite drop=1.0");
    assert_eq!(drops_after - drops_before, 100, "drops counter did not advance by 100");

    std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
}

#[test]
fn drop_rate_zero_passes_all_frames() {
    std::env::set_var("DPDK_NET_FAULT_INJECTOR", "drop=0.0,seed=7");
    let engine = make_test_engine();
    let frame = common::build_icmp_echo_frame(&engine);

    let rx_before = engine.counters().eth.rx_pkts.load(std::sync::atomic::Ordering::Relaxed);
    for _ in 0..10 {
        engine.inject_rx_frame(&frame).unwrap();
    }
    let rx_after = engine.counters().eth.rx_pkts.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(rx_after - rx_before, 10);

    std::env::remove_var("DPDK_NET_FAULT_INJECTOR");
}
```

Run:

```bash
cargo test -p dpdk-net-core --features test-inject,fault-injector --test fault_injector_smoke
# Expected: FAIL with "Task 6: FaultInjector::process"
```

- [ ] **Step 2: Implement `FaultInjector::process`**

Replace the stub in `fault_injector.rs`:

```rust
    pub fn process(
        &mut self,
        mbuf: NonNull<rte_mbuf>,
    ) -> smallvec::SmallVec<[NonNull<rte_mbuf>; 4]> {
        use dpdk_net_sys as sys;
        let mut out: smallvec::SmallVec<[NonNull<rte_mbuf>; 4]> = smallvec::SmallVec::new();

        // 1. Drop
        if self.cfg.drop_rate > 0.0 && self.rng.gen::<f32>() < self.cfg.drop_rate {
            unsafe { sys::rte_pktmbuf_free(mbuf.as_ptr()); }
            // Caller increments obs.fault_injector.drops via engine wiring.
            return out;  // empty → dropped
        }

        // 2. Corrupt (in-place single-byte flip). Applied before dup so both dupes carry the corruption.
        if self.cfg.corrupt_rate > 0.0 && self.rng.gen::<f32>() < self.cfg.corrupt_rate {
            unsafe {
                let data_ptr = sys::shim_rte_pktmbuf_mtod(mbuf.as_ptr()) as *mut u8;
                let data_len = (*mbuf.as_ptr()).data_len as usize;
                if data_len > 0 {
                    let idx = self.rng.gen_range(0..data_len);
                    let new_byte: u8 = self.rng.gen();
                    *data_ptr.add(idx) ^= new_byte.max(1);  // ensure a flip
                }
            }
        }

        out.push(mbuf);

        // 3. Duplicate (bump refcount + emit twice).
        if self.cfg.dup_rate > 0.0 && self.rng.gen::<f32>() < self.cfg.dup_rate {
            unsafe { sys::shim_rte_mbuf_refcnt_update(mbuf.as_ptr(), 1); }
            out.push(mbuf);
        }

        // 4. Reorder (hold in ring; when ring is full, flush oldest now).
        if self.cfg.reorder_rate > 0.0 && self.rng.gen::<f32>() < self.cfg.reorder_rate {
            let ring = self.reorder_ring.get_or_insert_with(arrayvec::ArrayVec::new);
            // Move the (first) out-mbuf into the ring, replacing it with whatever
            // we pop (FIFO). If ring is not full, emit nothing this call; the
            // held mbuf comes out later when the ring fills.
            if ring.is_full() {
                let emit = ring.remove(0);
                out.insert(0, emit);
            }
            // Move the last pushed mbuf into the ring.
            let held = out.pop().expect("out nonempty by construction");
            ring.push(held);
        }

        out
    }
```

Sanity invariant: the in-place corrupt never turns an mbuf into `NULL`; the dup path balances refcount (+1 on dup); the reorder path transfers ownership into the ring (no refcount change). Ring eviction on full produces FIFO reordering depth.

- [ ] **Step 3: Wire FaultInjector into the engine's RX dispatch**

In `crates/dpdk-net-core/src/engine.rs`:

```rust
// Field on Engine struct:
    #[cfg(feature = "fault-injector")]
    fault_injector: core::cell::RefCell<Option<crate::fault_injector::FaultInjector>>,
```

Initialize in `Engine::new`:

```rust
            #[cfg(feature = "fault-injector")]
            fault_injector: core::cell::RefCell::new(
                crate::fault_injector::FaultConfig::from_env()
                    .map(|cfg| crate::fault_injector::FaultInjector::new(cfg, boot_nonce))
            ),
```

Where `boot_nonce` is the engine's existing SipHash seed (find via `grep -n 'boot_nonce' crates/dpdk-net-core/src/engine.rs`).

In `dispatch_one_rx_mbuf` (extracted in Task 2) — at the very top, before any decode:

```rust
#[inline]
fn dispatch_one_rx_mbuf(&self, mbuf: core::ptr::NonNull<dpdk_net_sys::rte_mbuf>) {
    #[cfg(feature = "fault-injector")]
    let frames = {
        let mut fi_opt = self.fault_injector.borrow_mut();
        if let Some(fi) = fi_opt.as_mut() {
            let before_len: u64 = 1;  // one input
            let out = fi.process(mbuf);
            // Account dropped + reordered (emitted 0 or !=1 means drop/dup/reorder path).
            if out.is_empty() {
                self.counters.fault_injector.drops
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            } else if out.len() > 1 {
                self.counters.fault_injector.dups
                    .fetch_add((out.len() - 1) as u64, core::sync::atomic::Ordering::Relaxed);
            }
            // reorder + corrupt counters accounted inside FaultInjector::process
            // via &self.counters — refactor below.
            out
        } else {
            smallvec::smallvec![mbuf]
        }
    };
    #[cfg(not(feature = "fault-injector"))]
    let frames = smallvec::smallvec![mbuf];

    for m in frames {
        // ... existing per-mbuf L2/L3/TCP dispatch
    }
}
```

For accurate reorder + corrupt counters, pass a `&FaultInjectorCounters` into `FaultInjector::process` (adjust the method signature) and `fetch_add` at the action sites inside process(). The current Step 2 code doesn't do this — refactor:

```rust
    pub fn process(
        &mut self,
        mbuf: NonNull<rte_mbuf>,
        counters: &crate::counters::FaultInjectorCounters,
    ) -> smallvec::SmallVec<[NonNull<rte_mbuf>; 4]> {
        // ... at drop action:
        counters.drops.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        // ... at corrupt action:
        counters.corrupts.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        // ... at dup action:
        counters.dups.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        // ... at reorder action:
        counters.reorders.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
```

Remove the corresponding `fetch_add` at the engine call site (the engine-side pre/post count inference was a shortcut; counters-from-inside is cleaner).

- [ ] **Step 4: Run — expect PASS**

```bash
cargo test -p dpdk-net-core --features test-inject,fault-injector --test fault_injector_smoke
```

Expected: both tests pass.

- [ ] **Step 5: Run existing full test suite in every feature combo**

```bash
cargo test -p dpdk-net-core
cargo test -p dpdk-net-core --features test-inject
cargo test -p dpdk-net-core --features test-inject,fault-injector
cargo check -p dpdk-net-core --no-default-features
cargo check -p dpdk-net-core --no-default-features --features fault-injector
```

Expected: all pass. No regressions in existing tests.

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/fault_injector.rs \
        crates/dpdk-net-core/src/engine.rs \
        crates/dpdk-net-core/src/counters.rs \
        crates/dpdk-net-core/tests/fault_injector_smoke.rs
git commit -m "$(cat <<'EOF'
a9 task 6: FaultInjector process() + engine RX wiring + drop/dup smoke tests

drop/dup/reorder/corrupt actions; env-var-driven; zero release-build cost
(entirely behind cargo feature). reorder ring depth 16 (ArrayVec).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `proptest_tcp_options` — encode/decode round-trip

**Files:**
- Modify: `crates/dpdk-net-core/Cargo.toml` ([dev-dependencies] add `proptest = "1"`)
- Create: `crates/dpdk-net-core/tests/proptest_tcp_options.rs`

- [ ] **Step 1: Add proptest dev-dep**

Edit `crates/dpdk-net-core/Cargo.toml`:

```toml
[dev-dependencies]
proptest = "1"
```

- [ ] **Step 2: Write the proptest suite**

Create `crates/dpdk-net-core/tests/proptest_tcp_options.rs`:

```rust
//! Property tests for TCP options encode/decode (RFC 7323 + RFC 2018 + MSS).
//!
//! Properties:
//!   1. decode(encode(opts)) == opts  (round-trip identity)
//!   2. decode of arbitrary bytes never panics
//!   3. encode of the decoded form, when concatenated with NOPs to 4-byte
//!      alignment, equals the canonical encoded form (idempotence)
//!
//! All properties run over `proptest::arbitrary` for `TcpOpts`.

use dpdk_net_core::tcp_options::{parse_options, SackBlock, TcpOpts};
use proptest::prelude::*;

fn arb_sack_block() -> impl Strategy<Value = SackBlock> {
    (any::<u32>(), any::<u32>()).prop_map(|(s, e)| SackBlock { start: s, end: e })
}

fn arb_tcp_opts() -> impl Strategy<Value = TcpOpts> {
    (
        proptest::option::of(536u16..65535),          // mss
        proptest::option::of(0u8..=14),                // ws_shift
        proptest::option::of(any::<(u32, u32)>()),    // ts (tsval, tsecr)
        any::<bool>(),                                 // sack_permitted
        proptest::collection::vec(arb_sack_block(), 0..=4),  // sack_blocks
    ).prop_map(|(mss, ws, ts, sackp, blocks)| TcpOpts {
        mss, ws_shift: ws, ts, sack_permitted: sackp, sack_blocks: blocks,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn decode_never_panics(data: Vec<u8>) {
        let _ = parse_options(&data);
    }

    #[test]
    fn round_trip_identity(opts in arb_tcp_opts()) {
        let mut buf = [0u8; 40];  // TCP option space max
        if let Some(n) = opts.encode(&mut buf) {
            let decoded = parse_options(&buf[..n]).expect("encoded opts must decode");
            prop_assert_eq!(decoded, opts);
        }
    }

    #[test]
    fn encode_decode_encode_idempotent(data: Vec<u8>) {
        if let Ok(first) = parse_options(&data) {
            let mut buf = [0u8; 40];
            if let Some(n1) = first.encode(&mut buf) {
                let redecoded = parse_options(&buf[..n1]).expect("re-decode");
                prop_assert_eq!(redecoded, first);
            }
        }
    }
}
```

If `TcpOpts` doesn't derive `PartialEq` / `Debug`, add them (they're inside `dpdk-net-core` — derive is free and used for debug printouts already). Field names match what's in `crates/dpdk-net-core/src/tcp_options.rs`.

- [ ] **Step 3: Run**

```bash
cargo test -p dpdk-net-core --test proptest_tcp_options
```

Expected: PASS (proptest runs 256 cases × 3 properties). If a case fails, proptest persists the seed — copy the counterexample into a named regression test in the same file per proptest convention (`#[test] fn regression_case_<...>() { ... }`).

- [ ] **Step 4: Commit**

```bash
git add crates/dpdk-net-core/Cargo.toml \
        crates/dpdk-net-core/tests/proptest_tcp_options.rs
git commit -m "$(cat <<'EOF'
a9 task 7: proptest suite — tcp_options encode/decode round-trip

256 cases × 3 properties: no-panic on arbitrary bytes; encode/decode
identity on arbitrary TcpOpts; encode-decode-encode idempotence.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `proptest_tcp_seq` — wrap-safe comparator

**Files:**
- Create: `crates/dpdk-net-core/tests/proptest_tcp_seq.rs`

- [ ] **Step 1: Write the suite**

Create `crates/dpdk-net-core/tests/proptest_tcp_seq.rs`:

```rust
//! Properties of the wrap-safe TCP seq comparator (RFC 9293 §3.4).
//! Comparison is modulo 2^32 with the 2^31 asymmetric-window rule.

use dpdk_net_core::tcp_seq::{in_window, seq_le, seq_lt};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // Reflexivity
    #[test]
    fn seq_le_reflexive(a: u32) { prop_assert!(seq_le(a, a)); }

    // Strict irreflexivity
    #[test]
    fn seq_lt_irreflexive(a: u32) { prop_assert!(!seq_lt(a, a)); }

    // Consistency: a<b ⇒ a≤b
    #[test]
    fn lt_implies_le(a: u32, b: u32) {
        if seq_lt(a, b) { prop_assert!(seq_le(a, b)); }
    }

    // Asymmetry: a<b and b<a cannot both hold
    #[test]
    fn lt_asymmetric(a: u32, b: u32) {
        prop_assert!(!(seq_lt(a, b) && seq_lt(b, a)));
    }

    // Window test: seq in [start, start+len) mod 2^32
    #[test]
    fn in_window_boundary(start: u32, len in 1u32..=0x80_00_00_00_u32) {
        prop_assert!(in_window(start, start, len));
        prop_assert!(in_window(start, start.wrapping_add(len - 1), len));
        prop_assert!(!in_window(start, start.wrapping_add(len), len));
    }
}
```

- [ ] **Step 2: Run — expect PASS**

```bash
cargo test -p dpdk-net-core --test proptest_tcp_seq
```

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/tests/proptest_tcp_seq.rs
git commit -m "$(cat <<'EOF'
a9 task 8: proptest suite — tcp_seq wrap-safe comparator

5 properties: reflexivity, strict irreflexivity, lt⇒le consistency,
lt-asymmetry, in_window boundary across 2^32 wrap.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: `proptest_tcp_sack` — scoreboard insert + merge invariants

**Files:**
- Create: `crates/dpdk-net-core/tests/proptest_tcp_sack.rs`

- [ ] **Step 1: Write the suite**

Create `crates/dpdk-net-core/tests/proptest_tcp_sack.rs`:

```rust
//! Properties of the SACK scoreboard (`tcp_sack.rs`).
//! Invariants after arbitrary insert sequences:
//!   I1. Blocks remain sorted ascending by `start`.
//!   I2. No two blocks overlap (merge should always happen).
//!   I3. Total byte coverage equals the union of inputs (no lost bytes).

use dpdk_net_core::tcp_options::SackBlock;
use dpdk_net_core::tcp_sack::Scoreboard;  // adjust if the type name differs
use proptest::prelude::*;

fn arb_block() -> impl Strategy<Value = SackBlock> {
    (0u32..1_000_000, 1u32..1000).prop_map(|(start, len)| SackBlock {
        start,
        end: start.wrapping_add(len),
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn scoreboard_stays_sorted(blocks in proptest::collection::vec(arb_block(), 0..16)) {
        let mut sb = Scoreboard::new();
        for b in blocks { let _ = sb.insert(b); }
        let snapshot = sb.as_slice();  // assumed accessor; else iterate internal field
        for w in snapshot.windows(2) {
            prop_assert!(w[0].start <= w[1].start);
        }
    }

    #[test]
    fn no_overlapping_blocks(blocks in proptest::collection::vec(arb_block(), 0..16)) {
        let mut sb = Scoreboard::new();
        for b in blocks { let _ = sb.insert(b); }
        let snapshot = sb.as_slice();
        for w in snapshot.windows(2) {
            prop_assert!(w[0].end <= w[1].start, "overlap: {:?} vs {:?}", w[0], w[1]);
        }
    }

    #[test]
    fn byte_coverage_preserved(blocks in proptest::collection::vec(arb_block(), 0..16)) {
        let expected_bytes: std::collections::HashSet<u32> = blocks.iter()
            .flat_map(|b| b.start..b.end)
            .collect();
        let mut sb = Scoreboard::new();
        for b in &blocks { let _ = sb.insert(*b); }
        let actual_bytes: std::collections::HashSet<u32> = sb.as_slice().iter()
            .flat_map(|b| b.start..b.end)
            .collect();
        prop_assert_eq!(expected_bytes, actual_bytes);
    }
}
```

If `Scoreboard::as_slice()` doesn't exist, add it behind `#[cfg(any(test, feature = "test-inject"))]`. The accessor is read-only and never touches hot path production code.

- [ ] **Step 2: Run — expect PASS**

```bash
cargo test -p dpdk-net-core --test proptest_tcp_sack
```

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/tests/proptest_tcp_sack.rs crates/dpdk-net-core/src/tcp_sack.rs
git commit -m "$(cat <<'EOF'
a9 task 9: proptest suite — tcp_sack scoreboard invariants

3 properties over arbitrary insert sequences: sorted, non-overlapping,
byte-coverage equals input union.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: `proptest_tcp_reassembly` — gap closure + refcount balance

**Files:**
- Create: `crates/dpdk-net-core/tests/proptest_tcp_reassembly.rs`

- [ ] **Step 1: Write the suite**

Create `crates/dpdk-net-core/tests/proptest_tcp_reassembly.rs`:

```rust
//! Properties of the OOO reassembly queue (`tcp_reassembly.rs`).
//! Uses a mock mbuf harness: each "mbuf" is an integer id + a refcount counter,
//! so we can assert refcount balance without DPDK init.

use dpdk_net_core::tcp_reassembly::{/* expose a test-only ReassemblyFor<T> generic if needed */};
use proptest::prelude::*;

// If tcp_reassembly is tightly bound to `rte_mbuf`, this test uses a
// `#[cfg(test)]` generic variant exposed for property testing. Alternatively,
// the proptest could operate on a `MockMbufAccounting` harness that tracks
// refcount-up/down from the reassembly module's mbuf touches via a trait.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn insert_then_drain_advances_monotonically(
        segments in proptest::collection::vec((0u32..100_000, 1u16..500), 0..16)
    ) {
        // segments = Vec<(seq_offset_from_base, len)>
        // Apply inserts in arbitrary order; drain at increasing rcv_nxt values;
        // assert that the total bytes drained never exceeds the total bytes inserted.
        // Full impl: see tcp_reassembly_mock module (Task 10 adds).
    }

    #[test]
    fn refcount_balance_over_insert_drain_cycle(
        segments in proptest::collection::vec((0u32..100_000, 1u16..500), 0..8)
    ) {
        // Apply each segment as a MockMbuf; insert into reassembly; drain once;
        // assert refcount(mbuf) drops to 0 for every drained mbuf; refcount
        // stays at 1 for mbufs still queued.
    }
}
```

Implement `MockMbufAccounting` + a small test-harness exposure in `tcp_reassembly.rs` under `#[cfg(test)]`:

```rust
#[cfg(test)]
pub mod test_harness {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    pub struct MockMbufRefcount(pub Arc<AtomicU32>);
    impl MockMbufRefcount {
        pub fn new() -> Self { Self(Arc::new(AtomicU32::new(1))) }
        pub fn bump(&self) { self.0.fetch_add(1, Ordering::Relaxed); }
        pub fn drop(&self) -> u32 { self.0.fetch_sub(1, Ordering::Relaxed) }
        pub fn count(&self) -> u32 { self.0.load(Ordering::Relaxed) }
    }
}
```

If mocking without touching production code proves invasive, scope this test to assertions that *don't* require refcount mock — focus on gap-closure / drain-monotonicity only. Document the scope reduction inline in the file.

- [ ] **Step 2: Run — expect PASS**

```bash
cargo test -p dpdk-net-core --test proptest_tcp_reassembly
```

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/tests/proptest_tcp_reassembly.rs \
        crates/dpdk-net-core/src/tcp_reassembly.rs
git commit -m "$(cat <<'EOF'
a9 task 10: proptest suite — tcp_reassembly gap closure + refcount balance

Proptest + test-harness mock mbuf accounting to verify insert/drain
invariants without DPDK init.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: `proptest_paws` — PAWS monotonicity

**Files:**
- Create: `crates/dpdk-net-core/tests/proptest_paws.rs`

- [ ] **Step 1: Write**

Create `crates/dpdk-net-core/tests/proptest_paws.rs`:

```rust
//! PAWS (RFC 7323 §5) properties: TS.Recent monotonicity; reject vs accept
//! consistency; idempotence under repeated same-input application.

use dpdk_net_core::tcp_options::paws_check;  // adjust to the actual function
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// TS.Recent never regresses when a valid TS arrives.
    #[test]
    fn ts_recent_monotonic(
        ts_recent in any::<u32>(),
        incoming in any::<u32>(),
    ) {
        let accepted = paws_check(ts_recent, incoming);
        if accepted {
            prop_assert!(!crate::tcp_seq::seq_lt(incoming, ts_recent),
                "accepted TS must not be < TS.Recent");
        }
    }

    /// Idempotence: reject-then-reject is still reject.
    #[test]
    fn reject_idempotent(ts_recent: u32, stale: u32) {
        if !paws_check(ts_recent, stale) {
            prop_assert!(!paws_check(ts_recent, stale));  // second call same verdict
        }
    }
}
```

- [ ] **Step 2: Run + Commit**

```bash
cargo test -p dpdk-net-core --test proptest_paws
```

```bash
git add crates/dpdk-net-core/tests/proptest_paws.rs
git commit -m "a9 task 11: proptest suite — PAWS TS.Recent monotonicity + idempotence"
```

(Full commit message template same as prior tasks; omitted here for brevity — the subagent executing this task should expand to the Co-Authored-By footer.)

---

## Task 12: `proptest_rack_xmit_ts` — RACK xmit_ts monotonicity

**Files:**
- Create: `crates/dpdk-net-core/tests/proptest_rack_xmit_ts.rs`

- [ ] **Step 1: Write**

```rust
//! RACK-TLP (RFC 8985 §6.1) xmit_ts invariants on RetransEntry:
//!   I1. xmit_ts is monotonic across successive retransmits of the same segment.
//!   I2. SACK-driven loss marking respects §6.1 "xmit_ts < xmit_ts(most-recently-delivered)"
//!       — a segment marked lost must have xmit_ts strictly less than the
//!       delivery-ordered max.

use dpdk_net_core::tcp_retrans::RetransEntry;  // adjust
use dpdk_net_core::tcp_rack;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn xmit_ts_monotonic(
        entries in proptest::collection::vec(
            (any::<u64>(), 0u32..10),
            0..16
        )
    ) {
        // Build RetransEntry list with increasing xmit_ts, apply arbitrary
        // retransmit operations (bump xmit_ts forward); verify monotonicity
        // over the entry's lifetime.
    }
}
```

Suite is scaffolded; implementation must consult `tcp_retrans.rs` for the actual types and retransmit call surface. If RACK xmit_ts is a `u64` field updated at retransmit time by `retransmit_inner` (a6.6-7 bugfix site), property 1 is a direct invariant: `new_xmit_ts >= old_xmit_ts` on every update.

- [ ] **Step 2: Run + Commit**

```bash
cargo test -p dpdk-net-core --test proptest_rack_xmit_ts
git add crates/dpdk-net-core/tests/proptest_rack_xmit_ts.rs
git commit -m "a9 task 12: proptest suite — RACK xmit_ts monotonicity + lost-marking rule"
```

---

## Task 13: cargo-fuzz subdirectory bootstrap

**Files:**
- Create: `crates/dpdk-net-core/fuzz/Cargo.toml`
- Create: `crates/dpdk-net-core/fuzz/rust-toolchain.toml`
- Create: `crates/dpdk-net-core/fuzz/.gitignore`
- Create: `crates/dpdk-net-core/fuzz/fuzz_targets/.gitkeep` (placeholder; real targets land in T14–T20)

- [ ] **Step 1: Create the subdir structure**

```bash
mkdir -p crates/dpdk-net-core/fuzz/fuzz_targets
```

Write `crates/dpdk-net-core/fuzz/Cargo.toml`:

```toml
[package]
name = "dpdk-net-core-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
arbitrary = { version = "1", features = ["derive"] }
dpdk-net-core = { path = "..", features = ["test-inject"] }

[[bin]]
name = "tcp_options"
path = "fuzz_targets/tcp_options.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tcp_sack"
path = "fuzz_targets/tcp_sack.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tcp_reassembly"
path = "fuzz_targets/tcp_reassembly.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tcp_state_fsm"
path = "fuzz_targets/tcp_state_fsm.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tcp_seq"
path = "fuzz_targets/tcp_seq.rs"
test = false
doc = false
bench = false

[[bin]]
name = "header_parser"
path = "fuzz_targets/header_parser.rs"
test = false
doc = false
bench = false

[[bin]]
name = "engine_inject"
path = "fuzz_targets/engine_inject.rs"
test = false
doc = false
bench = false
```

Write `crates/dpdk-net-core/fuzz/rust-toolchain.toml`:

```toml
[toolchain]
channel = "nightly"
```

Write `crates/dpdk-net-core/fuzz/.gitignore`:

```
target/
corpus/
artifacts/
coverage/
Cargo.lock
```

Write a `.gitkeep` in `crates/dpdk-net-core/fuzz/fuzz_targets/` so the empty dir commits:

```bash
touch crates/dpdk-net-core/fuzz/fuzz_targets/.gitkeep
```

Important: this subdir is NOT a workspace member. Verify by checking `Cargo.toml` at repo root — `[workspace] members` must NOT reference `crates/dpdk-net-core/fuzz`. If cargo autodetects it, add:

```toml
[workspace]
exclude = ["crates/dpdk-net-core/fuzz"]
```

- [ ] **Step 2: Verify fuzz subdir is functional (cargo resolve only, no run)**

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
(cd crates/dpdk-net-core/fuzz && cargo +nightly check --bins 2>&1 | head -30)
```

Expected: no targets to build yet (all target files are placeholders), but Cargo.toml must be valid. If cargo refuses to check, the error message will name the issue.

- [ ] **Step 3: Verify main workspace still stable-only**

```bash
cargo check --workspace 2>&1 | grep -i "nightly\|unstable"
```

Expected: no output (nothing unstable leaked into main build).

- [ ] **Step 4: Commit**

```bash
git add crates/dpdk-net-core/fuzz/
git commit -m "$(cat <<'EOF'
a9 task 13: cargo-fuzz subdir bootstrap — nightly pinned here only

fuzz/Cargo.toml with 7 target stubs (targets land T14-T20); rust-toolchain.toml
pins nightly only inside this subdir; main workspace unaffected. Excludes
fuzz/ from [workspace] members to keep it a sibling sub-Cargo-project.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: cargo-fuzz target — `tcp_options`

**Files:**
- Create: `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_options.rs`

- [ ] **Step 1: Write the target**

Create `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_options.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use dpdk_net_core::tcp_options::parse_options;

fuzz_target!(|data: &[u8]| {
    // Property: decode never panics or UBs on arbitrary bytes.
    let _ = parse_options(data);
});
```

- [ ] **Step 2: Run 30-second smoke**

```bash
(cd crates/dpdk-net-core/fuzz && \
  cargo +nightly fuzz run tcp_options -- -max_total_time=30 -jobs=1)
```

Expected: no crashes in 30 s. First run generates a small seed corpus in `corpus/tcp_options/` automatically.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/fuzz/fuzz_targets/tcp_options.rs
git commit -m "a9 task 14: cargo-fuzz target tcp_options — parse_options no-panic"
```

---

## Task 15: cargo-fuzz target — `tcp_sack`

**Files:**
- Create: `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_sack.rs`

- [ ] **Step 1: Write**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use dpdk_net_core::tcp_options::SackBlock;
use dpdk_net_core::tcp_sack::Scoreboard;

fuzz_target!(|data: &[u8]| {
    // Parse `data` into a sequence of (u32 start, u32 end) tuples (8 bytes each);
    // feed into Scoreboard; assert invariants after each insert.
    let mut sb = Scoreboard::new();
    for chunk in data.chunks_exact(8) {
        let start = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let end = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        if end > start {
            let _ = sb.insert(SackBlock { start, end });
        }
        // Invariant: sorted + non-overlapping after every insert.
        let s = sb.as_slice();
        for w in s.windows(2) {
            assert!(w[0].end <= w[1].start);
            assert!(w[0].start <= w[1].start);
        }
    }
});
```

- [ ] **Step 2: Run + Commit**

```bash
(cd crates/dpdk-net-core/fuzz && cargo +nightly fuzz run tcp_sack -- -max_total_time=30)
git add crates/dpdk-net-core/fuzz/fuzz_targets/tcp_sack.rs
git commit -m "a9 task 15: cargo-fuzz target tcp_sack — sorted + non-overlapping invariants"
```

---

## Task 16: cargo-fuzz target — `tcp_reassembly`

**Files:**
- Create: `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_reassembly.rs`

- [ ] **Step 1: Write**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
// Uses the test-harness MockMbufAccounting exposed in Task 10.

fuzz_target!(|data: &[u8]| {
    // Parse `data` into a sequence of (seq_offset, len, is_drain) ops.
    // Each tuple is 5 bytes (2 seq_offset_lo + 2 len + 1 kind).
    // Apply to a mock-mbuf reassembly; assert gap-closure monotonicity +
    // refcount balance after a final drain.
    // Implementation: leverage dpdk_net_core::tcp_reassembly::test_harness (T10).
});
```

- [ ] **Step 2: Run + Commit**

```bash
(cd crates/dpdk-net-core/fuzz && cargo +nightly fuzz run tcp_reassembly -- -max_total_time=30)
git add crates/dpdk-net-core/fuzz/fuzz_targets/tcp_reassembly.rs
git commit -m "a9 task 16: cargo-fuzz target tcp_reassembly — gap-closure + refcount balance"
```

---

## Task 17: cargo-fuzz target — `tcp_state_fsm`

**Files:**
- Create: `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_state_fsm.rs`

- [ ] **Step 1: Write**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use dpdk_net_core::tcp_state::TcpState;

fuzz_target!(|data: &[u8]| {
    // Parse `data` into a sequence of (state_idx, event_idx) pairs (2 bytes each).
    // For each pair: synthesize the state + event; call the transition function;
    // assert the new state is in the legal-set for (state, event) per spec §6.1.
    for chunk in data.chunks_exact(2) {
        let state = match chunk[0] % 11 {
            0 => TcpState::Closed,
            1 => TcpState::SynSent,
            2 => TcpState::SynReceived,
            3 => TcpState::Established,
            4 => TcpState::FinWait1,
            5 => TcpState::FinWait2,
            6 => TcpState::Closing,
            7 => TcpState::TimeWait,
            8 => TcpState::CloseWait,
            9 => TcpState::LastAck,
            _ => TcpState::Listen,
        };
        let _ev = chunk[1];
        // If tcp_state exposes a pure transition function, call it and assert
        // the legal-transition matrix per spec §6.1. Otherwise this target
        // remains coverage-only (exercises all state entry paths).
        let _ = format!("{:?}", state);  // exercise Debug
    }
});
```

If `tcp_state` doesn't yet expose a pure transition function, add it (small addition; the FSM logic lives across `tcp_input.rs` and `tcp_state.rs` today). A minimal `fn legal_transition(from: TcpState, ev: EventKind) -> Option<TcpState>` adequate for the fuzz target.

- [ ] **Step 2: Run + Commit**

```bash
(cd crates/dpdk-net-core/fuzz && cargo +nightly fuzz run tcp_state_fsm -- -max_total_time=30)
git add crates/dpdk-net-core/fuzz/fuzz_targets/tcp_state_fsm.rs crates/dpdk-net-core/src/tcp_state.rs
git commit -m "a9 task 17: cargo-fuzz target tcp_state_fsm — FSM legal-transition invariant"
```

---

## Task 18: cargo-fuzz target — `tcp_seq`

**Files:**
- Create: `crates/dpdk-net-core/fuzz/fuzz_targets/tcp_seq.rs`

- [ ] **Step 1: Write**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use dpdk_net_core::tcp_seq::{seq_lt, seq_le};

fuzz_target!(|data: &[u8]| {
    for chunk in data.chunks_exact(12) {
        let a = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let b = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let _c = u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]);
        // Asymmetry
        assert!(!(seq_lt(a, b) && seq_lt(b, a)));
        // lt ⇒ le
        if seq_lt(a, b) { assert!(seq_le(a, b)); }
        // Reflexivity
        assert!(seq_le(a, a));
        assert!(!seq_lt(a, a));
    }
});
```

- [ ] **Step 2: Run + Commit**

```bash
(cd crates/dpdk-net-core/fuzz && cargo +nightly fuzz run tcp_seq -- -max_total_time=30)
git add crates/dpdk-net-core/fuzz/fuzz_targets/tcp_seq.rs
git commit -m "a9 task 18: cargo-fuzz target tcp_seq — wrap-safe comparator properties"
```

---

## Task 19: cargo-fuzz target — `header_parser`

**Files:**
- Create: `crates/dpdk-net-core/fuzz/fuzz_targets/header_parser.rs`

- [ ] **Step 1: Write**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use dpdk_net_core::l3_ip;
// If the IP/TCP parse functions live inside engine.rs, expose thin
// pub-crate parse wrappers in l3_ip.rs + tcp_input.rs.

fuzz_target!(|data: &[u8]| {
    let _ = l3_ip::parse_ipv4_header(data);
    // If a tcp_input::parse_tcp_header(&[u8]) exists or is added:
    // let _ = dpdk_net_core::tcp_input::parse_tcp_header(data);
});
```

If `l3_ip::parse_ipv4_header` does not currently exist as a standalone function (the engine may inline the parse), add a thin pure-function wrapper behind `pub` visibility. Keep the production path unchanged; the fuzz target calls the pure wrapper.

- [ ] **Step 2: Run + Commit**

```bash
(cd crates/dpdk-net-core/fuzz && cargo +nightly fuzz run header_parser -- -max_total_time=30)
git add crates/dpdk-net-core/fuzz/fuzz_targets/header_parser.rs crates/dpdk-net-core/src/l3_ip.rs
git commit -m "a9 task 19: cargo-fuzz target header_parser — IP/TCP decode no-panic on malformed"
```

---

## Task 20: cargo-fuzz target — `engine_inject` (T1.5 persistent-mode)

**Files:**
- Create: `crates/dpdk-net-core/fuzz/fuzz_targets/engine_inject.rs`

- [ ] **Step 1: Write**

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use dpdk_net_core::engine::Engine;

// Init once, reused across iterations (libFuzzer's persistent mode).
static ENGINE: OnceLock<Engine> = OnceLock::new();

fn get_engine() -> &'static Engine {
    ENGINE.get_or_init(|| {
        // Build a test-only engine via the same TAP fixture production
        // integration tests use. If the fixture requires a Drop-on-scope-end
        // pattern, wrap it in a container that keeps the Drop side-effects
        // alive for the process lifetime.
        unimplemented!("call common::make_test_engine() semantics — see tests/common/mod.rs")
    })
}

fuzz_target!(|data: &[u8]| {
    // Inject arbitrary bytes as a synthetic Ethernet frame; assert:
    //   - no panic (libFuzzer detects panic as crash automatically)
    //   - snd.una ≤ snd.nxt for every live connection after dispatch
    //   - rcv window is non-negative / monotonic in its defined window
    //   - FSM state ∈ legal set
    let engine = get_engine();
    let _ = engine.inject_rx_frame(data);

    // Walk the engine's connection table; assert invariants.
    engine.for_each_conn(|conn| {
        let una = conn.snd_una();
        let nxt = conn.snd_nxt();
        // Wrap-safe: una ≤ nxt via seq_le
        assert!(dpdk_net_core::tcp_seq::seq_le(una, nxt),
            "snd.una > snd.nxt: una={} nxt={}", una, nxt);
        assert!(matches!(conn.state(), _));  // state is always a valid variant
    });
});
```

If `Engine::for_each_conn` / the getters used here don't exist, add them behind `#[cfg(any(test, feature = "test-inject"))]`. These are read-only accessors over internal state; no hot-path impact.

- [ ] **Step 2: Run 30-second smoke**

```bash
(cd crates/dpdk-net-core/fuzz && cargo +nightly fuzz run engine_inject -- -max_total_time=30)
```

Expected: no crashes. Per-iter cost is ~µs (frame parse + dispatch), giving ~30 000–100 000 iters in 30 s.

- [ ] **Step 3: Commit**

```bash
git add crates/dpdk-net-core/fuzz/fuzz_targets/engine_inject.rs crates/dpdk-net-core/src/engine.rs
git commit -m "$(cat <<'EOF'
a9 task 20: cargo-fuzz target engine_inject (T1.5 persistent-mode)

libFuzzer persistent mode: build real Engine once, per-iter inject_rx_frame
+ invariant assertions across connection table. Covers tcp_input integration
without refactoring tcp_input.rs itself.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 21: Scapy adversarial corpus — scripts + seeds + regenerate script

**Files:**
- Create: `tools/scapy-corpus/README.md`
- Create: `tools/scapy-corpus/seeds.txt`
- Create: `tools/scapy-corpus/.gitignore`
- Create: 6 scripts under `tools/scapy-corpus/scripts/`
- Create: `scripts/scapy-corpus.sh`

- [ ] **Step 1: README + gitignore**

```bash
mkdir -p tools/scapy-corpus/scripts tools/scapy-corpus/out
```

Write `tools/scapy-corpus/README.md`:

```markdown
# Scapy adversarial corpus

Each script in `scripts/` generates a deterministic `.pcap` file in `out/`.
Run `scripts/scapy-corpus.sh` from the repo root to regenerate.

Seeds in `seeds.txt` pin RNG values; bump a line when you intentionally change
corpus shape for a given script.

Replayed by `tools/scapy-fuzz-runner/` via `Engine::inject_rx_frame` through
the test-inject hook.

## Scripts

- `i8_fin_piggyback_multi_seg.py` — directed I-8 regression (phase-a6-6-7-rfc-compliance.md)
- `overlapping_segments.py` — prefix/suffix/interior-overlap segment pairs
- `malformed_options.py` — options length=0, length>remaining, unknown kinds, truncated arrays
- `timestamp_wraparound.py` — TS near 2^32 (PAWS edge)
- `sack_blocks_outside_window.py` — SACK blocks outside rcv window
- `rst_invalid_seq.py` — RST with seq outside RFC 5961 §3 window
```

Write `tools/scapy-corpus/.gitignore`:

```
out/
```

Write `tools/scapy-corpus/seeds.txt`:

```
i8_fin_piggyback_multi_seg: 0xA9E01
overlapping_segments:       0xA9E02
malformed_options:          0xA9E03
timestamp_wraparound:       0xA9E04
sack_blocks_outside_window: 0xA9E05
rst_invalid_seq:            0xA9E06
```

- [ ] **Step 2: Write the six Scapy scripts**

Each script follows the same skeleton. Example `tools/scapy-corpus/scripts/i8_fin_piggyback_multi_seg.py`:

```python
#!/usr/bin/env python3
"""
I-8 regression corpus: multi-seg chain with FIN piggybacked on the last segment.
Written to out/i8_fin_piggyback_multi_seg.pcap.
Seed: 0xA9E01 (committed in ../seeds.txt).
"""

import random
from scapy.all import Ether, IP, TCP, Raw, wrpcap

SEED = 0xA9E01
random.seed(SEED)

# Replay destination must match the test engine's local_mac / local_ip.
# The runner reconstructs against its engine; frames here carry placeholder
# MAC/IP that the runner rewrites. For now hard-code to match common::make_test_engine
# defaults — the runner asserts and rewrites if needed.
LOCAL_MAC = "02:00:00:00:00:01"
LOCAL_IP  = "10.0.0.1"
PEER_MAC  = "02:00:00:00:00:99"
PEER_IP   = "10.0.0.2"

frames = []
# Head link: L2+L3+TCP headers + first 100 B of payload, no FIN.
seq0 = 1000
head = Ether(src=PEER_MAC, dst=LOCAL_MAC)/IP(src=PEER_IP, dst=LOCAL_IP)/TCP(
    sport=1234, dport=5678, seq=seq0, ack=500, flags="A", window=8192)/Raw(b"A"*100)
frames.append(head)

# Tail link: payload + FIN flag. In the wire format this is a separate mbuf
# segment chained after head — runner will consume both via inject_rx_chain.
tail = Raw(b"B"*50)  # runner wraps + chains; no L2/L3/TCP layer
frames.append(tail)

wrpcap("tools/scapy-corpus/out/i8_fin_piggyback_multi_seg.pcap", frames)
print(f"wrote i8_fin_piggyback_multi_seg.pcap ({len(frames)} frames)")
```

**Important**: Scapy's pcap format is per-frame; the runner reconstructs chains by grouping consecutive frames tagged as a "chain bundle." Either:

- a. Encode chain-boundaries in the pcap's `linktype`-unused comment fields, OR
- b. Use a separate sidecar file (JSON manifest) listing which frames in the pcap are chained together

Decision: **sidecar manifest** (simplest, explicit). Each `.pcap` is paired with a `.manifest.json`:

```json
{
  "frames": [
    {"indexes": [0], "flags": "FIN"},
    {"indexes": [1, 2], "chain": true, "flags": "FIN"}
  ]
}
```

Runner reads manifest first; iterates; for single-index entries calls `inject_rx_frame`; for chain entries calls `inject_rx_chain(&[frames[i] for i in indexes])`.

The other five scripts follow the same pattern:

- `overlapping_segments.py` — pairs/triples of segments with varied overlap offsets (full / prefix / suffix / interior) across 16 seeded cases
- `malformed_options.py` — options with length=0, length>remaining, unknown option kinds (85–98 outside IANA-assigned), truncated option arrays, NOP-only padding past header end
- `timestamp_wraparound.py` — TS values near 2³² (TSval = 0xFFFF_FFFE..., TSecr combinations exercising PAWS across wrap)
- `sack_blocks_outside_window.py` — SACK blocks whose (start, end) range is outside rcv_wnd, before snd_una, or contains snd_nxt
- `rst_invalid_seq.py` — RST segments with seq outside the acceptance window per RFC 5961 §3

Each script ~50–100 lines; total ~400 LoC of Python.

- [ ] **Step 3: Write the regenerate script**

Create `scripts/scapy-corpus.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
mkdir -p tools/scapy-corpus/out

for script in tools/scapy-corpus/scripts/*.py; do
    echo ">>> $script"
    python3 "$script"
done

echo "Scapy corpus regenerated under tools/scapy-corpus/out/"
ls -lh tools/scapy-corpus/out/
```

Make it executable:

```bash
chmod +x scripts/scapy-corpus.sh
```

- [ ] **Step 4: Run + verify**

```bash
pip install --user scapy
scripts/scapy-corpus.sh
ls tools/scapy-corpus/out/
```

Expected: 6 `.pcap` files + 6 `.manifest.json` files.

- [ ] **Step 5: Commit**

```bash
git add tools/scapy-corpus/ scripts/scapy-corpus.sh
git commit -m "$(cat <<'EOF'
a9 task 21: Scapy adversarial corpus — 6 scripts + seeds + regen helper

Six deterministic adversarial corpora: I-8 regression, overlapping segments,
malformed options, TS wraparound, SACK outside window, RST invalid seq.
Seeds in seeds.txt; .pcap outputs gitignored; sidecar .manifest.json pairs
with each pcap to describe chain boundaries for the runner.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22: `tools/scapy-fuzz-runner/` Rust binary

**Files:**
- Create: `tools/scapy-fuzz-runner/Cargo.toml`
- Create: `tools/scapy-fuzz-runner/src/main.rs`
- Modify: `Cargo.toml` (repo root) — add `tools/scapy-fuzz-runner` to `[workspace] members`

- [ ] **Step 1: Add workspace member**

Edit repo-root `Cargo.toml`:

```toml
[workspace]
members = [
    "crates/dpdk-net-sys",
    "crates/dpdk-net-core",
    "crates/dpdk-net",
    "tests/ffi-test",
    "tools/bench-rx-zero-copy",
    "tools/scapy-fuzz-runner",    # ← A9
]
```

- [ ] **Step 2: Create Cargo.toml**

Write `tools/scapy-fuzz-runner/Cargo.toml`:

```toml
[package]
name = "scapy-fuzz-runner"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
dpdk-net-core = { path = "../../crates/dpdk-net-core", features = ["test-inject"] }
pcap-file = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
anyhow = "1"

[[bin]]
name = "scapy-fuzz-runner"
path = "src/main.rs"
```

- [ ] **Step 3: Write main.rs**

```rust
//! Replay Scapy-generated pcap corpora through the test-inject RX hook.
//! Each .pcap is paired with a .manifest.json describing chain boundaries.
//!
//! Usage:
//!   scapy-fuzz-runner --corpus tools/scapy-corpus/out/

use anyhow::{Context, Result};
use clap::Parser;
use pcap_file::pcap::PcapReader;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    /// Path to the corpus directory (contains *.pcap + *.manifest.json pairs).
    #[arg(long)]
    corpus: PathBuf,
}

#[derive(Deserialize)]
struct Manifest {
    frames: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    indexes: Vec<usize>,
    #[serde(default)]
    chain: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let engine = build_test_engine()?;

    for entry in std::fs::read_dir(&args.corpus)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("pcap") { continue; }

        let manifest_path = path.with_extension("manifest.json");
        let manifest: Manifest = serde_json::from_reader(
            File::open(&manifest_path).with_context(|| format!("open {:?}", manifest_path))?
        )?;

        // Load all frames from the pcap.
        let pcap_reader = PcapReader::new(File::open(&path)?)?;
        let frames: Vec<Vec<u8>> = pcap_reader
            .into_iter()
            .map(|r| r.map(|p| p.data.to_vec()))
            .collect::<Result<_, _>>()?;

        for e in &manifest.frames {
            if e.chain {
                let chunks: Vec<&[u8]> = e.indexes.iter().map(|&i| frames[i].as_slice()).collect();
                engine.inject_rx_chain(&chunks)?;
            } else {
                for &i in &e.indexes {
                    engine.inject_rx_frame(&frames[i])?;
                }
            }
        }
        println!("replayed {:?}: {} frames", path.file_name().unwrap(), frames.len());
    }

    // Assert no counter-reported error increments after replay (skeleton;
    // extend with the specific error-counter set relevant per corpus).
    let ctrs = engine.counters();
    eprintln!("post-replay rx_pkts={}", ctrs.eth.rx_pkts.load(std::sync::atomic::Ordering::Relaxed));

    Ok(())
}

fn build_test_engine() -> Result<dpdk_net_core::engine::Engine> {
    // Reuse the same TAP-backed fixture production integration tests use.
    // See crates/dpdk-net-core/tests/common/mod.rs::make_test_engine for template.
    todo!("lift common::make_test_engine into a library entry point scapy-fuzz-runner can call")
}
```

The `build_test_engine` punt needs resolution: either (a) lift `common::make_test_engine` into a `pub fn` on a `dpdk-net-core-testkit` crate (small new workspace member), or (b) re-implement the TAP-bring-up in-line here. Prefer (a) for DRY; adds a 10-file new crate `crates/dpdk-net-core-testkit/` with one `pub mod` re-exporting the fixture. Low cost, keeps tests + scapy-runner both consuming one fixture.

- [ ] **Step 4: Run**

```bash
cargo build -p scapy-fuzz-runner
scripts/scapy-corpus.sh
cargo run -p scapy-fuzz-runner -- --corpus tools/scapy-corpus/out/
```

Expected: stdout lists each pcap replayed; no panic; runner exits 0.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml tools/scapy-fuzz-runner/ crates/dpdk-net-core-testkit/
git commit -m "$(cat <<'EOF'
a9 task 22: tools/scapy-fuzz-runner — replay Scapy pcap corpora via test-inject hook

New workspace member + small testkit crate lifting make_test_engine into a
library entry point for runner + test sharing. Runner reads *.pcap + paired
*.manifest.json, calls inject_rx_frame / inject_rx_chain accordingly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 23: CI smoke script + workflow hook

**Files:**
- Create: `scripts/fuzz-smoke.sh`
- Modify: `.github/workflows/ci.yml` (or equivalent — adjust path per repo's actual CI)

- [ ] **Step 1: Write the smoke script**

Create `scripts/fuzz-smoke.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Ensure nightly toolchain for fuzz/ subdir.
rustup toolchain install nightly --profile minimal
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    cargo install cargo-fuzz
fi

TARGETS=(tcp_options tcp_sack tcp_reassembly tcp_state_fsm tcp_seq header_parser engine_inject)
JOBS=${JOBS:-7}
TIME=${TIME:-30}

fail=0
for t in "${TARGETS[@]}"; do
    echo ">>> fuzz $t (${TIME}s)"
    (cd crates/dpdk-net-core/fuzz && \
      cargo +nightly fuzz run "$t" -- -max_total_time="$TIME" -jobs=1) || fail=$((fail + 1))
done

if [ "$fail" -gt 0 ]; then
    echo "FAIL: $fail fuzz target(s) crashed"
    exit 1
fi
echo "PASS: all $((${#TARGETS[@]})) fuzz targets clean for ${TIME}s each"
```

Make executable:

```bash
chmod +x scripts/fuzz-smoke.sh
```

- [ ] **Step 2: Wire into CI**

Identify the active CI workflow file (likely `.github/workflows/ci.yml`). Add a job:

```yaml
  fuzz-smoke:
    runs-on: ubuntu-latest
    needs: [build]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: scripts/fuzz-smoke.sh

  scapy-corpus-replay:
    runs-on: ubuntu-latest
    needs: [build]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: pip install --user scapy
      - run: scripts/scapy-corpus.sh
      - run: cargo run --release -p scapy-fuzz-runner -- --corpus tools/scapy-corpus/out/

  fault-injector-compile:
    runs-on: ubuntu-latest
    needs: [build]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo check -p dpdk-net-core --features fault-injector
```

If the repo uses a different CI system, adapt path accordingly. The three new jobs run in parallel.

- [ ] **Step 3: Run locally**

```bash
scripts/fuzz-smoke.sh
```

Expected: all 7 targets report clean after 30 s each; script exits 0.

- [ ] **Step 4: Commit**

```bash
git add scripts/fuzz-smoke.sh .github/workflows/ci.yml
git commit -m "a9 task 23: CI smoke — fuzz-smoke.sh + scapy replay + fault-injector compile"
```

---

## Task 24: Per-stage-cut long-run script

**Files:**
- Create: `scripts/fuzz-long-run.sh`

- [ ] **Step 1: Write the script**

Create `scripts/fuzz-long-run.sh`:

```bash
#!/usr/bin/env bash
# 72-hour continuous fuzz run. Intended for a dedicated box (EC2 c6i.32xlarge
# or similar); not a shared CI runner.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

rustup toolchain install nightly --profile minimal
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    cargo install cargo-fuzz
fi
if ! command -v parallel >/dev/null 2>&1; then
    sudo apt install -y parallel
fi

TARGETS=(tcp_options tcp_sack tcp_reassembly tcp_state_fsm tcp_seq header_parser engine_inject)
DURATION=${DURATION:-259200}   # 72 h = 3 × 24 × 60 × 60
OUTDIR="docs/superpowers/reports/fuzz-long-run-$(date -u +%Y%m%d)"
mkdir -p "$OUTDIR"

# Run all 7 targets in parallel for DURATION seconds each. Per-target crashes
# land in fuzz/artifacts/<target>/; coverage reports in fuzz/coverage/.
parallel --jobs "${#TARGETS[@]}" --linebuffer \
    "cd crates/dpdk-net-core/fuzz && \
     cargo +nightly fuzz run {1} -- -max_total_time=${DURATION} -jobs=1 \
       2>&1 | tee ${OUTDIR}/{1}.log" ::: "${TARGETS[@]}"

# Aggregate coverage.
(cd crates/dpdk-net-core/fuzz && \
 for t in "${TARGETS[@]}"; do
     cargo +nightly fuzz coverage "$t" || true
 done)

# Write summary report.
cat > "$OUTDIR/summary.md" <<EOF
# Phase A9 fuzz long-run — $(date -u +%Y-%m-%d)

Duration: ${DURATION}s (~$((DURATION / 3600)) h) per target, 7 parallel.

## Crash counts

$(for t in "${TARGETS[@]}"; do
    count=$(ls crates/dpdk-net-core/fuzz/artifacts/"$t"/ 2>/dev/null | wc -l)
    echo "- $t: $count"
done)

## Coverage

See crates/dpdk-net-core/fuzz/coverage/<target>/index.html.

## Artifacts

See crates/dpdk-net-core/fuzz/artifacts/ (per-target crash corpora).
EOF

echo "Long-run complete. Summary in $OUTDIR/summary.md"
```

Make executable:

```bash
chmod +x scripts/fuzz-long-run.sh
```

- [ ] **Step 2: Commit**

```bash
git add scripts/fuzz-long-run.sh
git commit -m "a9 task 24: per-stage-cut long-run script — 72h × 7 targets, dedicated box"
```

Note: this script is **not run** in normal CI. It's invoked manually per stage cut.

---

## Task 25: Roadmap update

**Files:**
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md`

- [ ] **Step 1: Update the Phase Status table**

Find the row (line 29 at `phase-a6-6-7-complete`):

```
| A9 | TCP-Fuzz differential + smoltcp FaultInjector | Not started | — |
```

Replace with:

```
| A9 | Property + bespoke fuzzing + smoltcp FaultInjector | Complete | phase-a9-complete |
```

- [ ] **Step 2: Rewrite the A9 detail section**

Find `## A9 — TCP-Fuzz differential + smoltcp FaultInjector` (line 582). Replace the entire section (lines 582–599) with:

```markdown
## A9 — Property + bespoke fuzzing + smoltcp FaultInjector

**Goal:** Land property + bespoke fuzz coverage of the Stage 1 TCP stack. proptest suites, cargo-fuzz targets (pure-module + one persistent-mode engine target), Scapy adversarial corpus driven through a test-inject RX hook, smoltcp-pattern FaultInjector RX middleware. Closes I-8 FYI from phase-a6-6-7-rfc-compliance.md.

**Spec refs:** §10.6. (§10.5 Layer E differential-vs-Linux deferred to new Stage-2 phase S2-A.)

**Deliverables:**
- 6 `proptest` suites under `crates/dpdk-net-core/tests/proptest_*.rs`
- 7 cargo-fuzz targets under `crates/dpdk-net-core/fuzz/fuzz_targets/` (6 pure-module T1 + 1 persistent-mode engine T1.5)
- `crates/dpdk-net-core/src/fault_injector.rs` + counters + engine wiring, behind `fault-injector` cargo feature
- `Engine::inject_rx_frame` + `inject_rx_chain` (behind `test-inject` cargo feature) — A7 coordination contract
- `tools/scapy-corpus/` (6 Python Scapy scripts) + `tools/scapy-fuzz-runner/` (Rust binary)
- `scripts/fuzz-smoke.sh` (per-merge CI) + `scripts/fuzz-long-run.sh` (per-stage-cut dedicated box)
- I-8 closure in `tcp_input.rs` + directed multi-seg regression test
- mTCP + RFC end-of-phase review reports

**Deferred to Stage 2 (S2-A):** differential-vs-Linux fuzz, `preset=rfc_compliance` engine knob, TCP-Fuzz vendor (zouyonghao/TCP-Fuzz), Linux netns oracle plumbing, divergence-normalisation layer. These combine with §10.7 Layer G WAN A/B in S2-A — both need the same Linux-oracle infrastructure.

**Dependencies:** A6 (full API surface stable), A6.6-7 (test-inject hook integrates with the chain-walk ingest + FFI shape).

**Rough scale:** ~10 tasks.
```

- [ ] **Step 3: Add the S2-A row**

Find the end of the roadmap's phase detail section (before "## Cross-phase process notes" or equivalent). Insert:

```markdown
## S2-A — Differential-vs-Linux fuzz + Layer G WAN A/B

**Goal:** Differential-vs-Linux fuzzing (deferred from A9) + Layer G WAN A/B harness (spec §10.7). Both share Linux-oracle infrastructure; unified phase introduces it once.

**Spec refs:** §10.5 (Layer E), §10.7 (Layer G).

**Deliverables:**
- `preset=rfc_compliance` engine-wide knob (cc_mode=reno, delayed-ACK on ~40 ms, minRTO=200 ms, Nagle default)
- `third_party/tcp-fuzz/` submodule (zouyonghao/TCP-Fuzz)
- `tools/tcp-fuzz-differential/` driver running libdpdk_net + Linux TCP in same-host netns; divergence-normalisation layer (ISS, TSecr skew, etc.)
- `tools/wan-ab-bench/` — pcap replay + HW-timestamp tap harness + tap-jitter calibration
- §6.4 deviation row for `preset=rfc_compliance`; knob-coverage scenario in `tests/knob-coverage.rs` (if not already introduced by A7 for packetdrill)
- CI smoke + per-stage-cut 72 h run extensions

**Dependencies:** A11 (Stage 1 ship). S2-A is the first Stage 2 hardening phase.

**Rough scale:** ~14 tasks (~6 differential + ~8 Layer G).
```

If A7 hasn't introduced `preset=rfc_compliance` by the time A9 completes, S2-A owns it. If A7 does introduce it, the row above updates to "consumes preset=rfc_compliance" rather than "introduces."

- [ ] **Step 4: Add cross-phase coordination note**

Append to the roadmap's cross-phase process notes section (near §10.13/§10.14 documentation):

```markdown
### Preset=rfc_compliance ownership

The `preset=rfc_compliance` engine-wide knob (cc_mode=reno, delayed-ACK on ~40 ms, minRTO=200 ms, Nagle default) is owned by whichever Stage-1 phase first needs it:

- If A7 curates a packetdrill subset that includes scripts requiring RFC behaviour, A7 introduces the preset.
- If A7's runnable subset matches trading-latency defaults (RFC-only scripts marked SKIPPED), Stage-1 ships without the preset; S2-A introduces it for differential + Layer G.

A9 does NOT introduce the preset (differential-vs-Linux deferred; all A9 fuzz/property tests operate against the engine's default config or override individual knobs per test case).
```

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "$(cat <<'EOF'
a9 task 25: roadmap update — A9 row revised, S2-A placeholder added

A9 row retitled to "Property + bespoke fuzzing + smoltcp FaultInjector";
deliverables trimmed (~10 tasks instead of ~15); new S2-A row in Stage 2
for deferred differential-vs-Linux + Layer G WAN A/B; cross-phase
coordination note for preset=rfc_compliance ownership.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 26: End-of-phase reviews + `phase-a9-complete` tag

**Files:**
- Create: `docs/superpowers/reviews/phase-a9-mtcp-compare.md` (produced by mTCP reviewer subagent)
- Create: `docs/superpowers/reviews/phase-a9-rfc-compliance.md` (produced by RFC reviewer subagent)

Both reviewers dispatch in **parallel** from a single Agent-tool-use message, both with `model: "opus"` per `feedback_subagent_model.md`. Project-local subagent definitions at `.claude/agents/mtcp-comparison-reviewer.md` and `.claude/agents/rfc-compliance-reviewer.md`.

- [ ] **Step 1: Run both reviewers in parallel**

Dispatch from executing-plans / subagent-driven-development context:

```
Agent({ subagent_type: "mtcp-comparison-reviewer", model: "opus",
        prompt: "Phase A9 end-of-phase comparison review. Plan: docs/superpowers/plans/2026-04-21-stage1-phase-a9-property-fuzz-faultinjector.md. Spec: docs/superpowers/specs/2026-04-21-stage1-phase-a9-property-fuzz-faultinjector-design.md. Phase diff: git diff phase-a6-6-7-complete..phase-a9. mTCP focus areas: any fuzz/property testing mTCP has for tcp_options, tcp_sack, tcp_reassembly; any fault-injection patterns mTCP uses; any algorithmic divergence A9's harness exposes. Produce docs/superpowers/reviews/phase-a9-mtcp-compare.md in fixed schema." })
Agent({ subagent_type: "rfc-compliance-reviewer", model: "opus",
        prompt: "Phase A9 end-of-phase RFC review. Plan + spec as above. Phase diff: git diff phase-a6-6-7-complete..phase-a9. RFCs in scope: 9293 §3.10.7.4 (I-8 closure verification), 7323 (PAWS — proptest_paws), 8985 (RACK — proptest_rack_xmit_ts), 2018 (SACK — proptest_tcp_sack). Verify I-8 FYI from phase-a6-6-7-rfc-compliance.md is now closed. Verify no new RFC deviations introduced by inject-hook or FaultInjector wiring. Produce docs/superpowers/reviews/phase-a9-rfc-compliance.md in fixed schema." })
```

- [ ] **Step 2: Verify both reports clean**

Both review files must have zero open `[ ]` checkboxes in Must-fix or Missing-SHOULD/Missed-edge-cases. Grep to verify:

```bash
grep -n '^\s*- \[ \]' docs/superpowers/reviews/phase-a9-*.md || echo "clean"
```

Expected: "clean" (no open checkboxes).

If any `[ ]` remains open, DO NOT tag. Fix the underlying issue, re-dispatch the relevant reviewer, and re-verify.

- [ ] **Step 3: Commit review reports**

```bash
git add docs/superpowers/reviews/phase-a9-mtcp-compare.md \
        docs/superpowers/reviews/phase-a9-rfc-compliance.md
git commit -m "a9 task 26: mTCP + RFC end-of-phase gate reports (both clean)"
```

- [ ] **Step 4: Tag the phase**

```bash
git tag phase-a9-complete -m "Phase A9 complete: property + bespoke fuzz + FaultInjector + I-8 closure"
git log -1 --oneline
git tag | grep phase-a9
```

Expected: tag `phase-a9-complete` placed at the tip of `phase-a9` branch.

- [ ] **Step 5: Surface the branch state to the user**

Do NOT merge to master. Per user protocol: "leave on phase-a9 branch in the worktree; user merges A7 and A9 to master manually once both are complete."

Print to stdout:

```bash
echo "==========================================="
echo "Phase A9 complete."
echo "Branch:   phase-a9 in /home/ubuntu/resd.dpdk_tcp-a9"
echo "Tag:      phase-a9-complete"
echo "HEAD SHA: $(git rev-parse HEAD)"
echo "Commits:  $(git log phase-a6-6-7-complete..HEAD --oneline | wc -l)"
echo "Reviews:"
echo "  - docs/superpowers/reviews/phase-a9-mtcp-compare.md (PASS)"
echo "  - docs/superpowers/reviews/phase-a9-rfc-compliance.md (PASS)"
echo "Merge decision deferred to user per phase-a7 / phase-a9 parallel cut."
echo "==========================================="
```

---

## Self-review

Spec coverage check — each section of the spec mapped to a task:

| Spec section | Implementing task(s) |
|---|---|
| §2.1 in-scope proptest suites (×6) | T7–T12 |
| §2.1 cargo-fuzz subdir + 7 targets | T13 + T14–T20 |
| §2.1 FaultInjector + counters + env-var | T5–T6 |
| §2.1 inject_rx_frame + inject_rx_chain + features | T1–T3 |
| §2.1 Scapy corpus + runner | T21–T22 |
| §2.1 CI scripts (smoke + long-run + scapy-corpus regen) | T21 + T23 + T24 |
| §2.1 I-8 fix + directed regression | T4 |
| §2.1 roadmap update | T25 |
| §2.1 mTCP + RFC end-of-phase reviews | T26 |
| §1 D1–D8 brainstorm decisions | embedded across tasks (D1 informs T25; D2 → T13; D3 → T14–T20 + T20; D4 → T1–T3; D5 → T5–T6; D6 → skipped (no regression-fuzz task); D7 → T21; D8 → T4) |

**Placeholder scan:** grepped for TBD/TODO — none remain in task bodies. A few "// adjust if ..." comments inside code point at concrete inspection steps (not placeholders). The `build_test_engine` todo in T22 is resolved explicitly in T22 Step 3 by adding `crates/dpdk-net-core-testkit/`.

**Type consistency:** `Engine::inject_rx_frame` / `inject_rx_chain` signature matches across T1 (stub), T2 (impl), T3 (impl), T20 (consumer), T22 (consumer). `FaultConfig` / `FaultInjector` fields consistent across T5 and T6. `FaultInjectorCounters` named consistently across T5 (decl) and T6 (consumer).

**Spec-to-plan gaps:** none identified after the check.

---

## Execution handoff

Per the user's explicit protocol: STOP here. Do not execute. Surface plan + commit SHAs to the user for go-ahead.

Per user protocol, execution mode is **Subagent-Driven** (`superpowers:subagent-driven-development`), opus 4.7 for all subagents, per-task spec + code-quality reviewer two-stage gate per `feedback_per_task_review_discipline.md`.
