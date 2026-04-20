# Phase A6.6 + A6.7 Fused Implementation Plan — RX zero-copy + FFI safety audit

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the scatter-gather iovec RX API (A6.6) and the FFI safety audit (A6.7) as one fused phase, with one branch, one end-of-phase review gate, and one shared `phase-a6-6-7-complete` tag.

**Architecture:** A6.6 evolves the C ABI `dpdk_net_event_readable_t` from `(data, data_len)` to `(segs, n_segs, total_len)` using a new `dpdk_net_iovec_t` type. The in-order recv queue switches from `VecDeque<u8>` to `VecDeque<InOrderSegment>` holding owning `MbufHandle` refs + offsets + lengths. Multi-segment (chained) mbufs are walked at reassembly-ingest time — one `OooSegment`/`InOrderSegment` per chain link. A new per-conn `readable_scratch_iovecs: Vec<dpdk_net_iovec_t>` backs the emitted pointer slices. A6.7 follows: miri over pure-compute modules, clang-22 ASan/UBSan/LSan on the cpp-consumer, panic-firewall child-process test, no-alloc-on-hot-path assertion via the existing `bench-alloc-audit` wrapper, panic audit with grep + manual classification, counters atomic-load helper header for ARM-readiness.

**Tech Stack:** Rust (latest stable via rustup; miri on nightly as a CI-only audit tool exception), DPDK 24.x, clang-22 + libstdc++ build toolchain, cbindgen (FFI header generation), criterion 0.5 (bench harness), SmallVec (inline-capacity scratch), existing `shim_rte_*` FFI surface + extensions, TAP-backed integration test harness (`RESD_NET_TEST_TAP=1`, requires sudo).

**Branch:** `phase-a6.6-7` in worktree `/home/ubuntu/resd.dpdk_tcp-a6.6-7` (branched off `master` tip `fa3cfcd`).

**Spec:** `docs/superpowers/specs/2026-04-20-stage1-phase-a6-6-7-fused-design.md` (authoritative). Parent combined spec: `docs/superpowers/specs/2026-04-20-stage1-phase-a6-6-and-a6-7-rx-zero-copy-and-ffi-safety-audit-design.md` (layered-on). Parent Stage 1 design: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.

---

## Review discipline

**Per-task reviewers (opus 4.7, parallel — dispatched at end of each non-trivial task before commit):**

- `superpowers:code-reviewer` subagent — spec-compliance against the fused spec + parent specs.
- Generalist opus-4.7 subagent — code-quality pass (readability, safety, idiom, unsafe-block discipline).

Tasks marked **[trivial]** may skip one reviewer at the implementer's discretion (not both). Tasks marked **[no-review]** are pure-mechanical (e.g. one-line script polish) and skip reviewers entirely.

**End-of-phase gate (after task 22, before tag):**

- `mtcp-comparison-reviewer` subagent → `docs/superpowers/reviews/phase-a6-6-7-mtcp-compare.md`
- `rfc-compliance-reviewer` subagent → `docs/superpowers/reviews/phase-a6-6-7-rfc-compliance.md`

Parallel dispatch. Tag `phase-a6-6-7-complete` only when both reports show zero open `[ ]`. Tag stays local.

---

## Cargo / shell invocation reminder

Cargo lives at `/home/ubuntu/.cargo/bin/cargo` (not on default `PATH`). Every shell command either runs `source ~/.cargo/env` first or uses the absolute path. Every Bash invocation should `cd /home/ubuntu/resd.dpdk_tcp-a6.6-7` at the start.

---

## File structure (created / modified in this phase)

### Modified — `crates/dpdk-net-core/src/`

| File | Change (task ref) |
|---|---|
| `mempool.rs` | Add `MbufHandle::try_clone` method (T1) |
| `tcp_conn.rs` | Add `InOrderSegment` struct + `RecvQueue.bytes` type flip + `buffered_bytes()` + `readable_scratch_iovecs` + `delivered_segments` (T1, T3, T7) |
| `tcp_reassembly.rs` | `drain_contiguous_from_mbuf` signature → output-param form (T4); multi-seg ingest walks `rte_mbuf.next` (T5) |
| `tcp_input.rs` | Multi-seg RX path update — walk chain at reassembly-enqueue (T5) |
| `tcp_events.rs` | `Event::Readable` shape → `(seg_idx_start, seg_count, total_len)` (T9) |
| `engine.rs` | `poll_once` drains `delivered_segments` at top; `deliver_readable` writes into scratch; `rx_mempool_size` plumb + computed default (T7, T8, T10); counters (T11) |
| `counters.rs` | `obs.rx_iovec_segs_total`, `obs.rx_multi_seg_events`, `obs.rx_partial_read_splits` (T11) |
| `lib.rs` | Re-export any new mbuf-walk helper if needed (T5) |

### Modified — `crates/dpdk-net-sys/`

| File | Change (task ref) |
|---|---|
| `shim.c` | Add `shim_rte_pktmbuf_next` (T5); `shim_rte_mempool_avail_count` (T13) |
| `wrapper.h` | Matching extern declarations (T5, T13) |

### Modified — `crates/dpdk-net/`

| File | Change (task ref) |
|---|---|
| `src/api.rs` | `dpdk_net_iovec_t` struct; reshape `dpdk_net_event_readable_t`; add `rx_mempool_size` field on config (T6, T10) |
| `src/lib.rs` | `dpdk_net_poll` emit rewrite; `dpdk_net_rx_mempool_size` FFI getter (T8, T10); test_only module (T19) |
| `src/test_only.rs` | NEW — gated `dpdk_net_panic_for_test()` (T19) |
| `Cargo.toml` | New feature `test-panic-entry` (T19) |

### Modified — `include/`

| File | Change (task ref) |
|---|---|
| `dpdk_net.h` | Regenerated via cbindgen (T6, T8, T10, T11, T17) |
| `dpdk_net_counters_load.h` | NEW — manually written atomic-load helpers (T17) |

### New — workspace members + tools

| Path | Purpose (task ref) |
|---|---|
| `tools/bench-rx-zero-copy/Cargo.toml` | NEW workspace member (T14) |
| `tools/bench-rx-zero-copy/benches/delivery_cycle.rs` | NEW criterion bench (T14) |
| `Cargo.toml` (workspace) | Add `tools/bench-rx-zero-copy` member + criterion dep (T14) |

### New — tests

| Path | Purpose (task ref) |
|---|---|
| `crates/dpdk-net-core/tests/rx_zero_copy_single_seg.rs` | Single-seg delivery TAP test (T13) |
| `crates/dpdk-net-core/tests/rx_zero_copy_multi_seg.rs` | Multi-seg injection test (T13) |
| `crates/dpdk-net-core/tests/rx_partial_read.rs` | Partial-read split test (T13) |
| `crates/dpdk-net-core/tests/rx_close_drains_mbufs.rs` | Close-drains mempool test (T13) |
| `crates/dpdk-net-core/tests/no_alloc_hotpath_audit.rs` | No-alloc audit test (T20) |
| `crates/dpdk-net/tests/panic_firewall.rs` | Panic firewall test (T19) |

### Modified — examples

| File | Change (task ref) |
|---|---|
| `examples/cpp-consumer/main.cpp` | Read events + iterate `segs[]`; static_assert + counter helper demo (T12, T17, T18) |
| `examples/cpp-consumer/CMakeLists.txt` | Link/include for new counter helper header (T17) |

### New — scripts + reports + reviews

| Path | Purpose (task ref) |
|---|---|
| `scripts/check-header.sh` | Polish error message (T15) |
| `scripts/hardening-miri.sh` | NEW (T16) |
| `scripts/hardening-cpp-sanitizers.sh` | NEW (T18) |
| `scripts/hardening-panic-firewall.sh` | NEW (T19) |
| `scripts/hardening-no-alloc.sh` | NEW (T20) |
| `scripts/audit-panics.sh` | NEW (T21) |
| `scripts/hardening-all.sh` | NEW aggregator (T22) |
| `docs/superpowers/reports/panic-audit.md` | NEW (T21) |
| `docs/superpowers/reports/ffi-safety-audit.md` | NEW (T22) |
| `docs/superpowers/reviews/phase-a6-6-7-mtcp-compare.md` | NEW (end-of-phase gate) |
| `docs/superpowers/reviews/phase-a6-6-7-rfc-compliance.md` | NEW (end-of-phase gate) |

### Modified — knob-coverage + roadmap

| File | Change (task ref) |
|---|---|
| `crates/dpdk-net-core/tests/knob-coverage.rs` | Entries for `rx_mempool_size`, `miri-safe`, `test-panic-entry` (T22) |
| `docs/superpowers/plans/stage1-phase-roadmap.md` | A6.6 + A6.7 rows → Complete (end-of-phase gate) |

---

## Task list (22 tasks, single-phase fused)

Commit prefix everywhere: `a6.6-7 task N:`

---

### Task 1: `MbufHandle::try_clone` + `InOrderSegment` struct

**Files:**
- Modify: `crates/dpdk-net-core/src/mempool.rs:122-162` (add `try_clone`)
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs` (add `InOrderSegment` struct in the existing `RecvQueue` module area)
- Test: `crates/dpdk-net-core/src/mempool.rs` (unit test for `try_clone`)

- [ ] **Step 1: Read current `mempool.rs` state to confirm doc comment + trait impls**

Run: `grep -n "MbufHandle" crates/dpdk-net-core/src/mempool.rs | head -20`

Expected: definition at line ~122, Drop at line ~152, doc comment about not-Clone at ~120.

- [ ] **Step 2: Write the failing test**

Append to `crates/dpdk-net-core/src/mempool.rs` inside an existing `#[cfg(test)] mod tests` block (or create one if absent):

```rust
#[cfg(test)]
mod try_clone_tests {
    use super::*;
    // Note: real mempool tests need DPDK EAL; we test the refcount logic using
    // a synthetic mbuf allocated via rte_pktmbuf_alloc. If tests cannot reach
    // the DPDK runtime, guard with #[ignore] — the actual verification happens
    // via the TAP integration tests in Task 13.
    #[test]
    #[ignore = "requires DPDK EAL + mempool; covered by tests/rx_close_drains_mbufs.rs"]
    fn try_clone_bumps_refcount() {
        // Placeholder: integration test in Task 13 asserts the real refcount
        // contract end-to-end. This stub documents intent and forces a
        // compile-check on the `try_clone` signature.
        let _check: fn(&MbufHandle) -> MbufHandle = MbufHandle::try_clone;
    }
}
```

- [ ] **Step 3: Run test to verify it fails to compile (method missing)**

Run: `cd /home/ubuntu/resd.dpdk_tcp-a6.6-7 && source ~/.cargo/env && cargo test -p dpdk-net-core mempool::try_clone_tests 2>&1 | head -30`
Expected: compile error — `no function or associated item named 'try_clone' found`.

- [ ] **Step 4: Implement `try_clone`**

Add inside the existing `impl MbufHandle` block in `crates/dpdk-net-core/src/mempool.rs`:

```rust
    /// Create a second owning handle over the same underlying rte_mbuf by
    /// bumping its refcount. The returned handle has its own Drop that
    /// decrements on drop — so the underlying mbuf is freed only when ALL
    /// handles have been dropped.
    ///
    /// Refcount-bookkeeping invariant: the `shim_rte_mbuf_refcnt_update(+1)`
    /// MUST be the last fallible-or-allocating call before the infallible
    /// `Self::from_raw`. Otherwise a failure between the bump and the
    /// handle construction would leak the refcount.
    ///
    /// Explicit method (not `Clone` derive) so accidental copies don't
    /// silently bump the refcount at call sites that only intended a borrow.
    pub fn try_clone(&self) -> Self {
        // SAFETY: self.ptr is a valid NonNull<rte_mbuf> (invariant of MbufHandle).
        // The refcount bump is the last operation before the infallible from_raw;
        // no intervening allocations or panickable calls.
        unsafe {
            dpdk_net_sys::shim_rte_mbuf_refcnt_update(self.ptr.as_ptr(), 1);
            Self::from_raw(self.ptr)
        }
    }
```

- [ ] **Step 5: Add `InOrderSegment` to `tcp_conn.rs`**

Modify `crates/dpdk-net-core/src/tcp_conn.rs`. Locate the `RecvQueue` struct definition (around line 44-58). Immediately before it, add:

```rust
/// One contiguous in-order payload segment backed by a refcount-pinned mbuf.
/// A split on partial-read produces two `InOrderSegment`s both referencing
/// the same underlying `rte_mbuf` with refcount bumped once via
/// `MbufHandle::try_clone()`.
#[derive(Debug)]
pub struct InOrderSegment {
    pub mbuf: crate::mempool::MbufHandle,
    pub offset: u16,
    pub len: u16,
}

impl InOrderSegment {
    #[inline]
    pub fn data_ptr(&self) -> *const u8 {
        // SAFETY: mbuf is refcount-pinned for the lifetime of this segment;
        // offset/len were bounds-checked at construction (see tcp_reassembly.rs).
        unsafe {
            let base = dpdk_net_sys::shim_rte_pktmbuf_data(self.mbuf.as_ptr()) as *const u8;
            base.add(self.offset as usize)
        }
    }
}
```

- [ ] **Step 6: Verify compilation**

Run: `cargo build -p dpdk-net-core 2>&1 | tail -20`
Expected: builds clean.

- [ ] **Step 7: Run the stub test (should pass as compile-check)**

Run: `cargo test -p dpdk-net-core mempool::try_clone_tests -- --include-ignored 2>&1 | tail -10`
Expected: test reports as ignored (expected) OR passes (if it runs).

- [ ] **Step 8: Per-task reviewer dispatch (opus 4.7, parallel)**

Dispatch `superpowers:code-reviewer` + generalist opus 4.7 subagent against the diff. Both must return zero-open-`[ ]` before commit.

- [ ] **Step 9: Commit**

```bash
git add crates/dpdk-net-core/src/mempool.rs crates/dpdk-net-core/src/tcp_conn.rs
git commit -m "a6.6-7 task 1: MbufHandle::try_clone + InOrderSegment struct

$(cat <<'EOF'
Adds explicit refcount-bump method (not Clone derive) and introduces
InOrderSegment as the owning-mbuf + offset + len carrier for the
in-order recv queue migration in task 3.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Grep-audit + migrate every `conn.recv.bytes` reader

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` (at least `deliver_readable` lines ~3620-3750)
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs` (add `buffered_bytes()` placeholder; real switch in T3)
- Test: existing integration tests (verify no behavior change)

- [ ] **Step 1: Enumerate every `conn.recv.bytes` reader**

Run: `cd /home/ubuntu/resd.dpdk_tcp-a6.6-7 && grep -rn "recv\.bytes\|recv.bytes\|\.bytes\.push_back\|\.bytes\.pop_front\|\.bytes\.extend_from_slice\|\.bytes\.len()" crates/dpdk-net-core/src/ | grep -v "^Binary"`

Expected: list of call sites. Save as reference; typically in `engine.rs` (deliver_readable, flow-control accounting) and `tcp_conn.rs` (RecvQueue methods).

- [ ] **Step 2: Add `RecvQueue::buffered_bytes()` helper scaffold**

In `crates/dpdk-net-core/src/tcp_conn.rs`, inside the `impl RecvQueue` block (still keeping `bytes: VecDeque<u8>` for now), add:

```rust
    /// Current buffered-but-not-delivered byte count for flow-control accounting.
    /// Post-T3: sums `seg.len` across the VecDeque<InOrderSegment>.
    /// Pre-T3: returns `self.bytes.len() as u32`.
    #[inline]
    pub fn buffered_bytes(&self) -> u32 {
        self.bytes.len() as u32
    }
```

- [ ] **Step 3: Replace each `conn.recv.bytes.len()` accounting site with `conn.recv.buffered_bytes()`**

For every site in `engine.rs` etc. matching the grep, change `conn.recv.bytes.len() as u32` or `conn.recv.bytes.len()` (in an accounting/flow-control context) to `conn.recv.buffered_bytes()`. LEAVE payload-consumption sites (`pop_front`, `push_back`, `extend_from_slice`) alone for T3.

Note to implementer: the `deliver_readable` pop loop at `engine.rs:~3744` that pops `total_delivered` bytes is payload-consumption — leave it for T3. The window / free-space accounting (`rcv_wnd`, `free_space`, etc.) uses `recv.bytes.len()` for byte count — those become `recv.buffered_bytes()`.

- [ ] **Step 4: Run full core test suite**

Run: `source ~/.cargo/env && cargo test -p dpdk-net-core --lib 2>&1 | tail -30`
Expected: all tests pass (no behavior change).

- [ ] **Step 5: Per-task reviewer dispatch**

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/tcp_conn.rs
git commit -m "a6.6-7 task 2: migrate recv.bytes.len() accounting to buffered_bytes()

$(cat <<'EOF'
Preparatory refactor: every flow-control / window-accounting reader of
RecvQueue.bytes.len() now calls buffered_bytes() so task 3 can flip the
underlying storage from VecDeque<u8> to VecDeque<InOrderSegment> without
touching the accounting sites again.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Flip `RecvQueue.bytes: VecDeque<u8>` → `VecDeque<InOrderSegment>`

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs` (type flip; `buffered_bytes` impl update)
- Modify: `crates/dpdk-net-core/src/engine.rs` (payload-consumption sites — `pop_front` loop in `deliver_readable`)

- [ ] **Step 1: Flip `RecvQueue.bytes` type**

In `crates/dpdk-net-core/src/tcp_conn.rs`, change:

```rust
pub struct RecvQueue {
    pub bytes: std::collections::VecDeque<u8>,
    ...
}
```

to:

```rust
pub struct RecvQueue {
    pub bytes: std::collections::VecDeque<InOrderSegment>,
    ...
}
```

(Keep `last_read_mbufs: SmallVec<[MbufHandle; 4]>` during T3 — retired in T7.)

- [ ] **Step 2: Update `buffered_bytes()` to sum segment lengths**

Replace:

```rust
    #[inline]
    pub fn buffered_bytes(&self) -> u32 {
        self.bytes.len() as u32
    }
```

with:

```rust
    #[inline]
    pub fn buffered_bytes(&self) -> u32 {
        self.bytes.iter().map(|s| s.len as u32).sum()
    }
```

- [ ] **Step 3: Update ingress append site in `engine.rs`**

Locate where `tcp_reassembly::drain_contiguous_from_mbuf` results are merged into `conn.recv.bytes`. The current code (pre-T4) calls `drain_contiguous_from_mbuf(rcv_nxt)`, gets `SmallVec<[DrainedMbuf; 4]>`, and the old path was presumably `extend_from_slice` bytes. Rewrite the merge to:

```rust
for drained in reassembly.drain_contiguous_from_mbuf(rcv_nxt) {
    let handle = drained.into_handle();
    let (offset, len) = (drained_offset, drained_len); // stored before into_handle() consumed DrainedMbuf
    conn.recv.bytes.push_back(InOrderSegment {
        mbuf: handle,
        offset,
        len,
    });
}
```

(If `DrainedMbuf::into_handle()` consumes `self` — it does per reviewer cite — restructure to save `offset` / `len` first: `let offset = drained.offset; let len = drained.len; let handle = drained.into_handle();` then push.)

- [ ] **Step 4: Update `deliver_readable` payload-consumption loop**

In `engine.rs` around line 3744, the current loop is:

```rust
for _ in 0..total_delivered {
    conn.recv.bytes.pop_front();
}
```

Post-T3, `pop_front` yields `InOrderSegment`. The delivery path needs to:
1. Pop segments whose full `seg.len` fits within remaining `total_delivered` budget.
2. Split the tail segment if partial (using `MbufHandle::try_clone`).
3. Move popped segments into a per-conn buffer for T7's plumbing. For T3, pop into `last_read_mbufs` for now (T7 renames/restructures).

Concretely, replace the `for _ in 0..total_delivered { conn.recv.bytes.pop_front(); }` block with:

```rust
let mut remaining = total_delivered as u32;
conn.recv.last_read_mbufs.clear();
while remaining > 0 {
    match conn.recv.bytes.front() {
        None => break,
        Some(seg) if seg.len as u32 <= remaining => {
            remaining -= seg.len as u32;
            let popped = conn.recv.bytes.pop_front().unwrap();
            conn.recv.last_read_mbufs.push(popped.mbuf);
        }
        Some(seg) => {
            // Partial: split — clone mbuf ref, advance the queue-side offset/len.
            let split_off = remaining as u16;
            let split_mbuf = seg.mbuf.try_clone();
            let front = conn.recv.bytes.front_mut().unwrap();
            let delivered = InOrderSegment {
                mbuf: split_mbuf,
                offset: front.offset,
                len: split_off,
            };
            front.offset += split_off;
            front.len -= split_off;
            conn.recv.last_read_mbufs.push(delivered.mbuf);
            remaining = 0;
        }
    }
}
```

(T7 will evolve `last_read_mbufs` → `delivered_segments: SmallVec<[InOrderSegment; 4]>` to preserve offset+len too — for T3 we preserve behavior by storing just the mbuf handle, same as today.)

- [ ] **Step 5: Build & run tests**

Run: `source ~/.cargo/env && cargo build -p dpdk-net-core 2>&1 | tail -30`
Expected: clean build.

Run: `cargo test -p dpdk-net-core --lib 2>&1 | tail -20`
Expected: all pass.

- [ ] **Step 6: Run TAP integration tests that exercise RX (requires sudo + tap env)**

Run: `sudo -E RESD_NET_TEST_TAP=1 /home/ubuntu/.cargo/bin/cargo test -p dpdk-net-core --test tcp_a6_public_api_tap 2>&1 | tail -20`
Expected: all pass. (If TAP unavailable in the task-exec env, mark this step as manual-verified and note in the commit.)

- [ ] **Step 7: Per-task reviewer dispatch**

- [ ] **Step 8: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_conn.rs crates/dpdk-net-core/src/engine.rs
git commit -m "a6.6-7 task 3: flip RecvQueue.bytes to VecDeque<InOrderSegment>

$(cat <<'EOF'
Retires the VecDeque<u8> byte ring in favor of mbuf-backed segment
descriptors. deliver_readable now pops segments, splitting the tail via
MbufHandle::try_clone() on partial delivery. last_read_mbufs retained
for T7 to repurpose into delivered_segments with offset/len preserved.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `drain_contiguous_from_mbuf` signature → output-param form

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_reassembly.rs:357-389`
- Modify: `crates/dpdk-net-core/src/engine.rs` (caller site)

- [ ] **Step 1: Read current signature + inspect `DrainedMbuf::into_handle()` usage**

Run: `grep -n "drain_contiguous_from_mbuf\|DrainedMbuf\|into_handle" crates/dpdk-net-core/src/tcp_reassembly.rs crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 2: Rewrite `drain_contiguous_from_mbuf` to append into caller-owned VecDeque**

In `crates/dpdk-net-core/src/tcp_reassembly.rs:357`, change:

```rust
pub fn drain_contiguous_from_mbuf(
    &mut self,
    mut rcv_nxt: u32,
) -> SmallVec<[DrainedMbuf; 4]>
```

to:

```rust
pub fn drain_contiguous_into(
    &mut self,
    mut rcv_nxt: u32,
    out: &mut std::collections::VecDeque<crate::tcp_conn::InOrderSegment>,
) -> u32 {
    // Returns total bytes drained for rcv_nxt advancement.
    // Appends directly into `out` — no intermediate SmallVec.
    ...
}
```

Update the function body: replace each `SmallVec::push(DrainedMbuf { ... })` with:

```rust
let handle = /* construct MbufHandle from the OooSegment's NonNull<rte_mbuf> via refcount-ownership-transfer */ ;
out.push_back(crate::tcp_conn::InOrderSegment {
    mbuf: handle,
    offset: seg.offset,
    len: seg.len,
});
```

The construction mirrors `DrainedMbuf::into_handle()` — inline the same `std::mem::forget` + `MbufHandle::from_raw` logic. Rename the old function name if the new name `drain_contiguous_into` is clearer (change call sites accordingly).

Retire the `DrainedMbuf` struct if it has no other callers — `grep -n DrainedMbuf crates/dpdk-net-core/src/` to confirm.

- [ ] **Step 3: Update engine caller**

In `engine.rs`, change:

```rust
for drained in reassembly.drain_contiguous_from_mbuf(rcv_nxt) {
    let offset = drained.offset;
    let len = drained.len;
    let handle = drained.into_handle();
    conn.recv.bytes.push_back(InOrderSegment { mbuf: handle, offset, len });
}
```

to:

```rust
let drained_bytes = reassembly.drain_contiguous_into(rcv_nxt, &mut conn.recv.bytes);
// drained_bytes used for rcv_nxt advancement / counter increment as before
```

- [ ] **Step 4: Build + tests**

Run: `source ~/.cargo/env && cargo build -p dpdk-net-core 2>&1 | tail -20`
Run: `cargo test -p dpdk-net-core --lib 2>&1 | tail -20`
Expected: clean build, all pass.

- [ ] **Step 5: Per-task reviewer dispatch**

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_reassembly.rs crates/dpdk-net-core/src/engine.rs
git commit -m "a6.6-7 task 4: drain_contiguous → output-param append form

$(cat <<'EOF'
tcp_reassembly drain now appends directly into the caller-owned
VecDeque<InOrderSegment> instead of returning a SmallVec intermediate.
Retires DrainedMbuf.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Multi-seg ingest — walk `rte_mbuf.next` at reassembly-enqueue

**Files:**
- Modify: `crates/dpdk-net-sys/shim.c` (add `shim_rte_pktmbuf_next`)
- Modify: `crates/dpdk-net-sys/wrapper.h` (extern)
- Modify: `crates/dpdk-net-core/src/tcp_input.rs` (reassembly-enqueue path)
- Modify: `crates/dpdk-net-core/src/tcp_reassembly.rs` (if insert needs per-link iteration)

- [ ] **Step 1: Add shim**

In `crates/dpdk-net-sys/shim.c`, append:

```c
// Returns the next segment in an rte_mbuf chain, or NULL if this is the
// last (or only) segment. Used by A6.6 multi-segment RX ingest.
struct rte_mbuf *shim_rte_pktmbuf_next(struct rte_mbuf *m) {
    return m->next;
}
```

In `crates/dpdk-net-sys/wrapper.h`, add:

```c
struct rte_mbuf *shim_rte_pktmbuf_next(struct rte_mbuf *m);
```

- [ ] **Step 2: Confirm bindgen picks it up**

Run: `source ~/.cargo/env && cargo build -p dpdk-net-sys 2>&1 | tail -15`
Expected: clean build. If bindgen-generated `lib.rs` needs a re-gen, the build.rs handles it automatically.

Run: `grep -n "shim_rte_pktmbuf_next" $(find target -name "bindings.rs" 2>/dev/null | head -1) 2>/dev/null || echo "bindgen output path uses build cache"`

- [ ] **Step 3: Write the multi-seg walk in `tcp_input.rs` reassembly-enqueue path**

Find the site where `tcp_reassembly.insert(...)` or the equivalent call happens (probably near `tcp_input.rs` handling of in-segment data). The current code passes a single `(seq, payload_slice, mbuf_ptr, mbuf_payload_offset)`.

Post-T5, walk the chain:

```rust
let mut cur = mbuf_ptr;
let mut link_seq = segment_seq;
let mut link_payload_offset = first_payload_offset_into_first_seg;
let mut first_link = true;
while !cur.is_null() {
    // SAFETY: cur is either the original head (non-null, checked) or the
    // product of shim_rte_pktmbuf_next of a prior non-null link — the DPDK
    // chain invariant guarantees valid pointers until NULL terminator.
    let link_data_ptr = unsafe { dpdk_net_sys::shim_rte_pktmbuf_data(cur) as *const u8 };
    let link_data_len = unsafe { dpdk_net_sys::shim_rte_pktmbuf_data_len(cur) } as u32;
    let (this_off, this_len) = if first_link {
        first_link = false;
        (link_payload_offset, link_data_len - link_payload_offset)
    } else {
        (0u32, link_data_len)
    };
    let payload_slice = unsafe {
        std::slice::from_raw_parts(link_data_ptr.add(this_off as usize), this_len as usize)
    };
    // Bump refcount on each link we're going to hold in reassembly.
    unsafe { dpdk_net_sys::shim_rte_mbuf_refcnt_update(cur, 1); }
    reassembly.insert(link_seq, payload_slice, cur, this_off as u16);
    link_seq = link_seq.wrapping_add(this_len);
    cur = unsafe { dpdk_net_sys::shim_rte_pktmbuf_next(cur) };
}
```

If the current code path already refcount-bumps once at the top of RX, adjust this to bump `nb_segs - 1` more times (one per additional link beyond the first).

- [ ] **Step 4: Confirm `tcp_reassembly::insert` already handles per-link entries**

Read `crates/dpdk-net-core/src/tcp_reassembly.rs:195-254` — the insert function already carves payload into gap-subranges (per reviewer report). Each `insert` call should produce `OooSegment`s with the provided mbuf+offset+len pair. No change required to `insert`.

- [ ] **Step 5: Build + core tests**

Run: `source ~/.cargo/env && cargo build -p dpdk-net-core 2>&1 | tail -20`
Run: `cargo test -p dpdk-net-core --lib 2>&1 | tail -20`
Expected: clean, all pass. The multi-seg path is exercised by T13 later.

- [ ] **Step 6: Per-task reviewer dispatch**

- [ ] **Step 7: Commit**

```bash
git add crates/dpdk-net-sys/shim.c crates/dpdk-net-sys/wrapper.h crates/dpdk-net-core/src/tcp_input.rs
git commit -m "a6.6-7 task 5: multi-seg RX — walk rte_mbuf.next at ingest

$(cat <<'EOF'
Reassembly ingress walks the rte_mbuf chain when present, bumping
refcount per link and enqueueing one OooSegment per chain link. Adds
shim_rte_pktmbuf_next. ENA still doesn't advertise RX_OFFLOAD_SCATTER
today, so the multi-link path is exercised synthetically in T13.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: `dpdk_net_iovec_t` + reshape `dpdk_net_event_readable_t`

**Files:**
- Modify: `crates/dpdk-net/src/api.rs:127-130` (reshape readable struct + new iovec)
- Modify: `include/dpdk_net.h` (regenerated by build.rs)

- [ ] **Step 1: Read current api.rs `dpdk_net_event_readable_t` definition**

Run: `grep -n "dpdk_net_event_readable_t\|dpdk_net_iovec_t" crates/dpdk-net/src/api.rs`
Expected: current `dpdk_net_event_readable_t { data: *const u8, data_len: u32 }` around line 127.

- [ ] **Step 2: Add `dpdk_net_iovec_t`**

In `crates/dpdk-net/src/api.rs`, add (before the existing `dpdk_net_event_readable_t`):

```rust
/// Scatter-gather view over a received in-order byte range.
/// `base` points into a mempool-backed rte_mbuf data area; the pointer is
/// only valid until the next `dpdk_net_poll` on the same engine.
///
/// ABI: 16 bytes on 64-bit targets (x86_64, ARM64 Graviton). Not 32-bit
/// compatible — Stage 1 targets are 64-bit only.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct dpdk_net_iovec_t {
    pub base: *const u8,
    pub len: u32,
    pub _pad: u32,
}
```

- [ ] **Step 3: Reshape `dpdk_net_event_readable_t`**

Replace:

```rust
#[repr(C)]
pub struct dpdk_net_event_readable_t {
    pub data: *const u8,
    pub data_len: u32,
}
```

with:

```rust
/// READABLE event payload. `segs` points at an engine-owned array of
/// `dpdk_net_iovec_t` with `n_segs` entries. Multi-segment when chained
/// mbufs were received (LRO / jumbo / IP-defragmented); single-segment
/// for standard MTU packets. `total_len = Σ segs[i].len`.
///
/// Lifetime: `segs` and every `segs[i].base` pointer are only valid
/// until the next `dpdk_net_poll` on the same engine. The engine reuses
/// per-conn scratch for the array; the backing mbufs are refcount-
/// pinned in the connection's `delivered_segments` and released at the
/// next poll iteration.
#[repr(C)]
pub struct dpdk_net_event_readable_t {
    pub segs: *const dpdk_net_iovec_t,
    pub n_segs: u32,
    pub total_len: u32,
}
```

- [ ] **Step 4: Update the `dpdk_net_event_payload_t` union**

Locate the union definition (also in `api.rs`). Ensure `_pad` or other fields remain large enough that the readable variant's new size (16 bytes: 8 ptr + 4 + 4) fits. The current union has `_pad: [u8; 16]` (see `include/dpdk_net.h:156`); verify:

```rust
pub _pad: [u8; 16],
```

still large enough. 16 bytes is exactly the new readable-variant size — sufficient.

- [ ] **Step 5: Update cbindgen whitelist**

In `crates/dpdk-net/cbindgen.toml` `[export].include`, add `"dpdk_net_iovec_t"` to the 15+ item list.

- [ ] **Step 6: Regenerate header**

Run: `source ~/.cargo/env && cargo build -p dpdk-net 2>&1 | tail -10`
Expected: clean build; `include/dpdk_net.h` updated.

- [ ] **Step 7: Confirm drift detector passes**

Run: `./scripts/check-header.sh`
Expected: passes (committed header matches regenerated).

If it fails, `git add include/dpdk_net.h` as part of this commit.

- [ ] **Step 8: Compile-check that no downstream consumers broke**

Run: `source ~/.cargo/env && cargo build --workspace 2>&1 | tail -30`
Expected: may fail on `crates/dpdk-net/src/lib.rs` call sites that write `.data` / `.data_len` — those become T8 work. For T6, revert any downstream breakage by leaving the old access path flagged with `compile_error!` or `TODO(T8)` if needed to let the crate compile. Cleanest: T6 lands the struct shape; T7/T8 migrate the callers — if necessary mark this step as "compile failure expected, resolved in T7-T8" and carry the broken lib.rs through.

Alternative: T6 and T7 and T8 land as one commit if the intermediate state is uncompilable. Decision at implementer's discretion based on breakage surface.

- [ ] **Step 9: Per-task reviewer dispatch**

- [ ] **Step 10: Commit (possibly combined with T7-T8 per Step 8 decision)**

```bash
git add crates/dpdk-net/src/api.rs crates/dpdk-net/cbindgen.toml include/dpdk_net.h
git commit -m "a6.6-7 task 6: dpdk_net_iovec_t + reshape dpdk_net_event_readable_t

$(cat <<'EOF'
Introduces scatter-gather iovec type + reshapes the READABLE event
payload from (data, data_len) to (segs, n_segs, total_len). Header
regenerated; emit-path migration lands in T7-T8.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: `readable_scratch_iovecs` + `delivered_segments` on `TcpConn`; retire `last_read_mbufs`

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_conn.rs` (RecvQueue fields)
- Modify: `crates/dpdk-net-core/src/engine.rs` (deliver_readable)

- [ ] **Step 1: Update RecvQueue fields**

In `crates/dpdk-net-core/src/tcp_conn.rs`:

- REMOVE: `pub last_read_mbufs: SmallVec<[MbufHandle; 4]>`
- ADD:
  ```rust
  /// Segments popped from `bytes` during the most recent poll_once's
  /// deliver_readable, refcount-pinned until the NEXT poll_once drains
  /// them. Backs the iovec slice pointed at by the READABLE event.
  pub delivered_segments: smallvec::SmallVec<[InOrderSegment; 4]>,
  /// Scratch for iovec array materialization. Capacity retained.
  /// Cleared at the top of deliver_readable before pushing new iovecs.
  /// Valid until the next dpdk_net_poll on this engine.
  pub readable_scratch_iovecs: Vec<dpdk_net::api::dpdk_net_iovec_t>,
  ```

  (If the core crate cannot depend on `dpdk_net::api` — it currently does NOT — the type must be defined in `dpdk-net-core` and re-exported to `dpdk-net`. Check: `grep -n "dpdk-net\"" crates/dpdk-net-core/Cargo.toml`.)

- [ ] **Step 2: Resolve the crate dependency**

If `dpdk-net-core` does NOT depend on `dpdk-net`:
- Define the iovec in `dpdk-net-core/src/iovec.rs` (new module) with the same `#[repr(C)]` shape.
- In `dpdk-net/src/api.rs`, `pub use dpdk_net_core::iovec::dpdk_net_iovec_t;` (cbindgen needs to see it; confirm cbindgen picks up re-exports — if not, define separately in both crates with identical layout + a `const _: () = { ... }` layout-assertion to catch drift).

Safer approach: define `dpdk_net_iovec_t` in `dpdk-net-core/src/iovec.rs`:

```rust
/// ABI-stable iovec type matching the C-side `dpdk_net_iovec_t`.
/// 16 bytes on 64-bit targets. See crates/dpdk-net for the FFI export.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DpdkNetIovec {
    pub base: *const u8,
    pub len: u32,
    pub _pad: u32,
}
```

And in `dpdk-net/src/api.rs`:

```rust
pub type dpdk_net_iovec_t = dpdk_net_core::iovec::DpdkNetIovec;
```

This lets cbindgen see the type via the type-alias; confirm by running `cargo build -p dpdk-net` and verifying the header re-emits the struct.

(If cbindgen doesn't follow `pub type`, fall back to duplicate the `#[repr(C)]` struct in both crates with a layout assertion.)

- [ ] **Step 3: Update `deliver_readable` in engine.rs**

Replace the T3 interim form:

```rust
conn.recv.last_read_mbufs.clear();
while remaining > 0 { ... conn.recv.last_read_mbufs.push(popped.mbuf); ... }
```

with:

```rust
// Drop prior poll's delivered refs BEFORE we pop new ones.
// (Normally done at top of poll_once — T8 moves this; for T7 keep it here.)
conn.recv.delivered_segments.clear();

let mut remaining = total_delivered as u32;
while remaining > 0 {
    match conn.recv.bytes.front() {
        None => break,
        Some(seg) if seg.len as u32 <= remaining => {
            remaining -= seg.len as u32;
            let popped = conn.recv.bytes.pop_front().unwrap();
            conn.recv.delivered_segments.push(popped);
        }
        Some(_seg) => {
            let split_off = remaining as u16;
            let front = conn.recv.bytes.front_mut().unwrap();
            let delivered_offset = front.offset;
            let split_mbuf = front.mbuf.try_clone();
            front.offset += split_off;
            front.len -= split_off;
            conn.recv.delivered_segments.push(InOrderSegment {
                mbuf: split_mbuf,
                offset: delivered_offset,
                len: split_off,
            });
            remaining = 0;
        }
    }
}
```

- [ ] **Step 4: Build + core tests**

Run: `source ~/.cargo/env && cargo build --workspace 2>&1 | tail -30`
Run: `cargo test -p dpdk-net-core --lib 2>&1 | tail -20`
Expected: clean, all pass.

- [ ] **Step 5: Per-task reviewer dispatch**

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_conn.rs crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/iovec.rs crates/dpdk-net-core/src/lib.rs crates/dpdk-net/src/api.rs
git commit -m "a6.6-7 task 7: delivered_segments + readable_scratch_iovecs; retire last_read_mbufs

$(cat <<'EOF'
Renames the per-conn mbuf-hold buffer from last_read_mbufs to
delivered_segments (now keeping offset+len alongside the MbufHandle).
Adds readable_scratch_iovecs for T8's iovec materialization.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: `dpdk_net_poll` emit rewrite (iovec materialization + poll-top lifecycle)

**Files:**
- Modify: `crates/dpdk-net/src/lib.rs:375-429` (emit rewrite)
- Modify: `crates/dpdk-net-core/src/engine.rs` (top-of-poll drain of previous-poll `delivered_segments`)

- [ ] **Step 1: Add top-of-poll drain in `engine.rs`**

In `Engine::poll_once` (grep for the start of the fn), at the very top (before any RX burst or timer processing), add:

```rust
// A6.6: release the prior poll's delivered mbuf refs + reset scratch.
// This step is what makes the "valid until next dpdk_net_poll" contract hold.
for conn_handle in self.flow_table.iter_handles() {
    if let Some(conn) = self.flow_table.get_mut(conn_handle) {
        conn.recv.delivered_segments.clear();
        conn.recv.readable_scratch_iovecs.clear();
    }
}
```

(If `iter_handles` doesn't exist, use whatever iteration method `FlowTable` exposes. Grep: `grep -n "iter\|values\|handles" crates/dpdk-net-core/src/flow_table.rs`.)

- [ ] **Step 2: Update `deliver_readable` to populate scratch + fill event**

In `deliver_readable` (or wherever the READABLE event is enqueued), after popping segments into `delivered_segments`, populate `readable_scratch_iovecs` AND the event fields:

```rust
conn.recv.readable_scratch_iovecs.clear();
let mut total_len = 0u32;
for seg in &conn.recv.delivered_segments {
    let iovec = dpdk_net_core::iovec::DpdkNetIovec {
        base: seg.data_ptr(),
        len: seg.len as u32,
        _pad: 0,
    };
    conn.recv.readable_scratch_iovecs.push(iovec);
    total_len += seg.len as u32;
}
let seg_idx_start = 0u32; // per-conn scratch — always starts at 0
let seg_count = conn.recv.readable_scratch_iovecs.len() as u32;
// enqueue Event::Readable with (conn_handle, seg_idx_start, seg_count, total_len, ...)
```

- [ ] **Step 3: Rewrite `dpdk_net_poll` C-ABI event resolution**

In `crates/dpdk-net/src/lib.rs` around lines 375-429, find the match arm for `InternalEvent::Readable { conn, mbuf_idx, payload_offset, payload_len, .. }`. Replace with:

```rust
InternalEvent::Readable { conn, seg_idx_start, seg_count, total_len, .. } => {
    let ft = engine.flow_table();
    match ft.get(*conn) {
        Some(c) => {
            // SAFETY: c.recv.readable_scratch_iovecs capacity is preserved
            // across the poll; `seg_idx_start` is 0 (per-conn scratch) and
            // `seg_count` is bounded by the scratch's length when the event
            // was enqueued earlier in this poll. The scratch is cleared
            // only at TOP of the NEXT poll_once, so for the duration of
            // this poll's event-drain, these pointers are live.
            let segs_ptr = unsafe {
                c.recv.readable_scratch_iovecs.as_ptr().add(*seg_idx_start as usize)
                    as *const dpdk_net_iovec_t
            };
            (segs_ptr, *seg_count, *total_len)
        }
        None => (std::ptr::null(), 0, 0),
    }
}
```

And update the event-payload construction:

```rust
event.u.readable = dpdk_net_event_readable_t {
    segs: segs_ptr,
    n_segs,
    total_len,
};
```

- [ ] **Step 4: Regenerate header; confirm check-header passes**

Run: `source ~/.cargo/env && cargo build -p dpdk-net 2>&1 | tail -10`
Run: `./scripts/check-header.sh`
Expected: both clean.

- [ ] **Step 5: Run all tests including TAP**

Run: `cargo test -p dpdk-net-core --lib 2>&1 | tail -20`
Run: `sudo -E RESD_NET_TEST_TAP=1 /home/ubuntu/.cargo/bin/cargo test -p dpdk-net-core --test tcp_a6_public_api_tap 2>&1 | tail -20`
Expected: all pass. If the existing a6_public_api_tap test checks `readable.data` directly, update it to use `readable.segs[0].base` for single-seg. (May be unavoidable; adjust here.)

- [ ] **Step 6: Per-task reviewer dispatch**

- [ ] **Step 7: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net/src/lib.rs include/dpdk_net.h
git commit -m "a6.6-7 task 8: dpdk_net_poll emit — iovec materialization

$(cat <<'EOF'
poll_once now drains prior-poll delivered_segments at the top,
deliver_readable populates per-conn readable_scratch_iovecs, and the
C-ABI event resolution reads (segs, n_segs, total_len) from that scratch.
Existing TAP tests updated to use readable.segs[0].base for single-seg.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: `Event::Readable` internal shape → `(seg_idx_start, seg_count, total_len)`

**Files:**
- Modify: `crates/dpdk-net-core/src/tcp_events.rs:41-55`

- [ ] **Step 1: Reshape `Event::Readable`**

In `crates/dpdk-net-core/src/tcp_events.rs`, change:

```rust
Readable {
    conn: ConnHandle,
    mbuf_idx: u32,
    payload_offset: u32,
    payload_len: u32,
    rx_hw_ts_ns: u64,
    emitted_ts_ns: u64,
},
```

to:

```rust
Readable {
    conn: ConnHandle,
    seg_idx_start: u32,
    seg_count: u32,
    total_len: u32,
    rx_hw_ts_ns: u64,
    emitted_ts_ns: u64,
},
```

- [ ] **Step 2: Update construction site in engine.rs**

Wherever `Event::Readable { mbuf_idx, payload_offset, payload_len, ... }` is built, change to `{ seg_idx_start, seg_count, total_len, ... }`. Pull the values from `conn.recv.readable_scratch_iovecs.len()` and the sum computed in T8.

- [ ] **Step 3: Update all destructuring match arms**

Grep: `grep -rn "Readable { conn, mbuf_idx\|Readable{ conn, mbuf_idx\|Readable { .*mbuf_idx" crates/`. Update each match arm. The primary consumer is `dpdk_net_poll` (already updated in T8), but there may be internal assertions or logging.

- [ ] **Step 4: Build + tests**

Run: `source ~/.cargo/env && cargo build --workspace 2>&1 | tail -20`
Run: `cargo test -p dpdk-net-core --lib 2>&1 | tail -20`
Expected: clean, all pass.

- [ ] **Step 5: Per-task reviewer dispatch**

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/tcp_events.rs crates/dpdk-net-core/src/engine.rs
git commit -m "a6.6-7 task 9: Event::Readable shape — seg_idx_start/seg_count/total_len

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: `EngineConfig.rx_mempool_size` + formula + `dpdk_net_rx_mempool_size()` getter

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs` (EngineConfig + mempool sizing + stored field)
- Modify: `crates/dpdk-net/src/api.rs` (add field to `dpdk_net_engine_config_t`)
- Modify: `crates/dpdk-net/src/lib.rs` (FFI getter)
- Modify: `include/dpdk_net.h` (regenerated)

- [ ] **Step 1: Add `rx_mempool_size` to core `EngineConfig`**

In `crates/dpdk-net-core/src/engine.rs`, locate `pub struct EngineConfig` (grep). Add:

```rust
/// RX mempool capacity in mbufs. 0 = compute default at engine_create:
///   max(4 * rx_ring_desc, 2 * max_conns * ceil(recv_buffer_bytes / 2048) + 4096)
/// Assumption: mbuf_data_room == 2048 (DPDK default). Jumbo-frame users
/// override this explicitly.
/// Retrievable via dpdk_net_rx_mempool_size() FFI getter post-create.
pub rx_mempool_size: u32,
```

- [ ] **Step 2: Compute default + store on Engine**

In `Engine::create` (or wherever mempool is initialized), add:

```rust
let rx_mempool_size = if cfg.rx_mempool_size > 0 {
    cfg.rx_mempool_size
} else {
    const MBUF_DATA_ROOM: u32 = 2048;
    let per_conn = ((cfg.recv_buffer_bytes + MBUF_DATA_ROOM - 1) / MBUF_DATA_ROOM) as u32;
    let computed = 2u32.saturating_mul(cfg.max_connections).saturating_mul(per_conn).saturating_add(4096);
    let floor = 4u32.saturating_mul(cfg.rx_ring_desc as u32);
    computed.max(floor)
};
```

Then use `rx_mempool_size` as the `n` arg to `rte_pktmbuf_pool_create`. Store the value on Engine as `pub(crate) rx_mempool_size: u32` field for the getter.

- [ ] **Step 3: Add field to `dpdk_net_engine_config_t`**

In `crates/dpdk-net/src/api.rs`, find `dpdk_net_engine_config_t` struct. Add:

```rust
    /// RX mempool capacity. 0 = compute default at engine_create. Retrievable
    /// via dpdk_net_rx_mempool_size(). Formula documented in that function's
    /// header comment.
    pub rx_mempool_size: u32,
```

Plumb `cfg.rx_mempool_size` through `dpdk_net_engine_create` into the core `EngineConfig`.

- [ ] **Step 4: Add FFI getter**

In `crates/dpdk-net/src/lib.rs`, near the other `#[no_mangle] pub unsafe extern "C" fn` entries, add:

```rust
/// Returns the RX mempool capacity in use on this engine (user-supplied
/// value from cfg.rx_mempool_size if non-zero, else the computed default
/// per the formula in the header). Returns UINT32_MAX if `p` is null.
///
/// Slow-path. Safe to call any time after dpdk_net_engine_create.
///
/// # Safety
/// `p` must be a valid Engine pointer obtained from dpdk_net_engine_create,
/// or null.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_rx_mempool_size(p: *const dpdk_net_engine) -> u32 {
    if p.is_null() {
        return u32::MAX;
    }
    // SAFETY: caller contract pins `p` to a valid Engine.
    let engine: &Engine = unsafe { &*(p as *const Engine) };
    engine.rx_mempool_size
}
```

- [ ] **Step 5: Regenerate header + verify drift**

Run: `source ~/.cargo/env && cargo build -p dpdk-net 2>&1 | tail -10`
Run: `./scripts/check-header.sh`

- [ ] **Step 6: Build + tests**

Run: `cargo build --workspace 2>&1 | tail -20`
Run: `cargo test -p dpdk-net-core --lib 2>&1 | tail -10`

- [ ] **Step 7: Per-task reviewer dispatch**

- [ ] **Step 8: Commit**

```bash
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net/src/api.rs crates/dpdk-net/src/lib.rs include/dpdk_net.h
git commit -m "a6.6-7 task 10: rx_mempool_size knob + computed default + getter

$(cat <<'EOF'
New EngineConfig.rx_mempool_size (0 = default). Default formula:
max(4*rx_ring_desc, 2*max_conns*ceil(recv_buffer_bytes/2048)+4096).
New FFI getter dpdk_net_rx_mempool_size() returns the active value.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Slow-path iovec/multi-seg/partial-read counters

**Files:**
- Modify: `crates/dpdk-net-core/src/counters.rs` (add 3 fields)
- Modify: `crates/dpdk-net-core/src/engine.rs` (increment sites in deliver_readable)
- Modify: `include/dpdk_net.h` (regenerated)

- [ ] **Step 1: Add fields to TCP counters struct**

In `crates/dpdk-net-core/src/counters.rs`, locate `pub struct TcpCounters` (or `dpdk_net_tcp_counters_t` analog — grep). Append to the existing `uint64_t` / `AtomicU64` field list:

```rust
pub rx_iovec_segs_total: AtomicU64,
pub rx_multi_seg_events: AtomicU64,
pub rx_partial_read_splits: AtomicU64,
```

Update the `_pad` array (if any) to keep the struct's 64-byte alignment block size consistent. Grep for `_pad: [u64; N]` in the struct; shrink `N` by 3 to compensate.

- [ ] **Step 2: Increment sites**

In `engine.rs deliver_readable` (or equivalent):

After populating `readable_scratch_iovecs` and before enqueueing the Event::Readable:

```rust
let n_segs = conn.recv.delivered_segments.len() as u64;
self.counters.tcp.rx_iovec_segs_total.fetch_add(n_segs, std::sync::atomic::Ordering::Relaxed);
if n_segs > 1 {
    self.counters.tcp.rx_multi_seg_events.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}
```

In the partial-split branch inside `deliver_readable` (the `Some(_seg) => { let split_off = remaining as u16; ... }` branch from T7):

```rust
self.counters.tcp.rx_partial_read_splits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
```

- [ ] **Step 3: Regenerate header**

Run: `source ~/.cargo/env && cargo build -p dpdk-net 2>&1 | tail -5`
Run: `./scripts/check-header.sh`

- [ ] **Step 4: Verify counters visible in cpp-consumer output**

Run: `cargo build -p dpdk-net-core 2>&1 | tail -10`
Expected: clean.

- [ ] **Step 5: Per-task reviewer dispatch**

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/src/counters.rs crates/dpdk-net-core/src/engine.rs include/dpdk_net.h
git commit -m "a6.6-7 task 11: slow-path counters — iovec segs, multi-seg events, partial splits

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: `examples/cpp-consumer/main.cpp` — iterate `segs[]`

**Files:**
- Modify: `examples/cpp-consumer/main.cpp:66-70`

- [ ] **Step 1: Read current main.cpp**

- [ ] **Step 2: Replace the throw-away poll loop**

Change:

```cpp
for (int i = 0; i < 100; i++) {
    dpdk_net_event_t events[32];
    int n = dpdk_net_poll(eng, events, 32, 0);
    (void)n;
}
```

to:

```cpp
uint64_t received_bytes_total = 0;
uint64_t received_events_total = 0;
uint64_t multi_seg_events_total = 0;
for (int i = 0; i < 100; i++) {
    dpdk_net_event_t events[32];
    int n = dpdk_net_poll(eng, events, 32, 0);
    for (int ev_i = 0; ev_i < n; ev_i++) {
        if (events[ev_i].kind == DPDK_NET_EVT_READABLE) {
            const auto& r = events[ev_i].u.readable;
            for (uint32_t seg_i = 0; seg_i < r.n_segs; ++seg_i) {
                // Parse-in-place: the base pointer is valid until the next dpdk_net_poll.
                // A real consumer would feed this to a parser; here we just accumulate bytes.
                received_bytes_total += r.segs[seg_i].len;
            }
            received_events_total++;
            if (r.n_segs > 1) multi_seg_events_total++;
        }
    }
}
std::cout << "Received " << received_events_total << " READABLE events, "
          << received_bytes_total << " bytes total, "
          << multi_seg_events_total << " were multi-seg\n";
```

- [ ] **Step 3: Build the example**

Run: `cd examples/cpp-consumer && mkdir -p build && cd build && cmake .. && make 2>&1 | tail -20`
Expected: clean build.

- [ ] **Step 4: Per-task reviewer dispatch**

- [ ] **Step 5: Commit**

```bash
git add examples/cpp-consumer/main.cpp
git commit -m "a6.6-7 task 12: cpp-consumer iterates segs[] and reports received bytes

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: TAP integration tests (single_seg, multi_seg, partial_read, close_drains)

**Files:**
- Create: `crates/dpdk-net-core/tests/rx_zero_copy_single_seg.rs`
- Create: `crates/dpdk-net-core/tests/rx_zero_copy_multi_seg.rs`
- Create: `crates/dpdk-net-core/tests/rx_partial_read.rs`
- Create: `crates/dpdk-net-core/tests/rx_close_drains_mbufs.rs`
- Modify: `crates/dpdk-net-sys/shim.c` (add `shim_rte_mempool_avail_count`)
- Modify: `crates/dpdk-net-sys/wrapper.h`

- [ ] **Step 1: Add mempool-avail shim**

In `crates/dpdk-net-sys/shim.c`:

```c
// Returns current free-count of the mempool (used by A6.6 close-drain tests).
unsigned shim_rte_mempool_avail_count(struct rte_mempool *mp) {
    return rte_mempool_avail_count(mp);
}
```

In `wrapper.h`:

```c
unsigned shim_rte_mempool_avail_count(struct rte_mempool *mp);
```

- [ ] **Step 2: Write `rx_zero_copy_single_seg.rs`**

Create with header:

```rust
#![cfg(feature = "tap-tests")]  // existing convention — check if this matches the other tap tests' gating
// Requires RESD_NET_TEST_TAP=1 + sudo. See existing tcp_a6_public_api_tap.rs pattern.
```

Test body:

```rust
#[test]
fn rx_zero_copy_single_seg_roundtrip() {
    // 1. Create engine, connect to TAP peer (reuse helpers from tcp_a6_public_api_tap.rs).
    // 2. Send 256 bytes from peer to engine.
    // 3. poll_once until a Readable event surfaces.
    // 4. Assert n_segs == 1.
    // 5. Assert segs[0].len == 256.
    // 6. Assert segs[0].base is within the engine's rx mempool region
    //    (base >= mempool_start_addr && base < mempool_start_addr + (pool_size * mbuf_size)).
    // 7. Assert content matches what peer sent.
    // 8. Close + drop engine.
    ...
}
```

Refer to existing `crates/dpdk-net-core/tests/tcp_a6_public_api_tap.rs` for the helper pattern.

- [ ] **Step 3: Write `rx_zero_copy_multi_seg.rs`**

This one injects a synthetic chained mbuf — NIC LRO is NOT required.

```rust
#[test]
fn rx_zero_copy_multi_seg_manual_chain() {
    // 1. Create engine (or directly a testable Engine inner).
    // 2. Use shim_rte_pktmbuf_alloc twice to allocate two mbufs.
    // 3. Attach second to first via shim_rte_pktmbuf_chain (existing shim).
    // 4. Feed the chained mbuf into tcp_input's reassembly-enqueue path
    //    with a constructed TCP header (reuse tcp_options_paws_reassembly_sack_tap.rs
    //    helper for TCP frame construction).
    // 5. poll_once → drain a Readable event.
    // 6. Assert n_segs == 2, segs ordered, Σ len == total_len, content correct.
}
```

- [ ] **Step 4: Write `rx_partial_read.rs`**

```rust
#[test]
fn rx_partial_read_split_resumes() {
    // 1. Send 512 bytes from peer.
    // 2. First poll delivers a Readable; consumer reads only 300 bytes.
    //    (The consumer-side "read N bytes" interface is the max_read_bytes
    //    parameter on dpdk_net_poll or similar; verify the current shape.)
    // 3. Assert n_segs and total_len correspond to the 300 bytes.
    // 4. Second poll delivers a Readable with the remaining 212 bytes.
    // 5. Assert rx_partial_read_splits counter incremented by 1 between
    //    the two polls.
    // 6. Assert byte content is correct and no byte duplicated or lost.
}
```

- [ ] **Step 5: Write `rx_close_drains_mbufs.rs`**

```rust
#[test]
fn close_releases_delivered_and_queued_mbufs() {
    // 1. Snapshot dpdk_net_rx_mempool_size() - shim_rte_mempool_avail_count() as baseline.
    // 2. Send 10 × 1 KB messages; don't read them (let them accumulate in recv queue).
    // 3. poll_once but don't consume events (so mbufs pin in delivered_segments).
    // 4. Assert used = rx_mempool_size - avail is at least 10 + some overhead.
    // 5. Call dpdk_net_close on the connection.
    // 6. poll_once again (to run the next-poll drain step).
    // 7. Assert used returns to within baseline + small delta (e.g., + 64 for engine-internal).
}
```

- [ ] **Step 6: Build + run the tests**

Run: `source ~/.cargo/env && cargo build --tests -p dpdk-net-core 2>&1 | tail -20`
Run: `sudo -E RESD_NET_TEST_TAP=1 /home/ubuntu/.cargo/bin/cargo test -p dpdk-net-core --tests rx_zero_copy_single_seg rx_zero_copy_multi_seg rx_partial_read rx_close_drains_mbufs 2>&1 | tail -40`
Expected: all four pass (may need TAP + sudo in the exec env).

- [ ] **Step 7: Per-task reviewer dispatch**

- [ ] **Step 8: Commit**

```bash
git add crates/dpdk-net-core/tests/rx_zero_copy_single_seg.rs crates/dpdk-net-core/tests/rx_zero_copy_multi_seg.rs crates/dpdk-net-core/tests/rx_partial_read.rs crates/dpdk-net-core/tests/rx_close_drains_mbufs.rs crates/dpdk-net-sys/shim.c crates/dpdk-net-sys/wrapper.h
git commit -m "a6.6-7 task 13: TAP tests — single/multi-seg, partial read, close-drains

$(cat <<'EOF'
Four integration tests covering the scatter-gather delivery paths.
Adds shim_rte_mempool_avail_count for the close-drain test's
pool-occupancy assertion.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 14: `tools/bench-rx-zero-copy/` criterion harness + alloc-audit assertion

**Files:**
- Create: `tools/bench-rx-zero-copy/Cargo.toml`
- Create: `tools/bench-rx-zero-copy/benches/delivery_cycle.rs`
- Modify: `Cargo.toml` (workspace — add member + criterion workspace dep)

- [ ] **Step 1: Create `tools/bench-rx-zero-copy/Cargo.toml`**

```toml
[package]
name = "bench-rx-zero-copy"
version = "0.1.0"
edition = "2024"
publish = false

[dependencies]
dpdk-net-core = { path = "../../crates/dpdk-net-core", features = ["bench-alloc-audit"] }
dpdk-net-sys = { path = "../../crates/dpdk-net-sys" }

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "delivery_cycle"
harness = false
```

- [ ] **Step 2: Add to workspace + pin criterion**

In the root `/home/ubuntu/resd.dpdk_tcp-a6.6-7/Cargo.toml`, `[workspace]` `members = [...]`, add `"tools/bench-rx-zero-copy"`.

- [ ] **Step 3: Write `benches/delivery_cycle.rs`**

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_single_seg_delivery(c: &mut Criterion) {
    // Setup: create Engine (core direct, no FFI), pre-prime an in-order
    // segment on RecvQueue.bytes, warm up the allocator path.
    // Measure: one poll_once iteration that delivers one segment.
    c.bench_function("poll_once_single_seg_deliver_256b", |b| {
        b.iter(|| {
            // TODO in implementation: call Engine::poll_once() with a pre-primed
            // conn having a single 256B InOrderSegment ready to deliver.
            // black_box the event output.
        });
    });
}

fn bench_multi_seg_delivery(c: &mut Criterion) {
    c.bench_function("poll_once_multi_seg_deliver_4x256b", |b| {
        b.iter(|| {
            // similar; four segs.
        });
    });
}

#[cfg(feature = "bench-alloc-audit")]
fn assert_zero_alloc_single_seg() {
    use dpdk_net_core::bench_alloc_audit;
    // Warmup.
    for _ in 0..1000 { /* poll_once with single-seg pre-primed */ }
    let (a0, f0, _) = bench_alloc_audit::snapshot();
    for _ in 0..10_000 { /* same poll_once */ }
    let (a1, f1, _) = bench_alloc_audit::snapshot();
    assert_eq!(a1 - a0, 0, "alloc observed on steady-state single-seg deliver");
    assert_eq!(f1 - f0, 0, "free observed on steady-state single-seg deliver");
}

criterion_group!(benches, bench_single_seg_delivery, bench_multi_seg_delivery);
criterion_main!(benches);
```

(The test body `/* poll_once with single-seg ... */` requires Engine setup helpers — reuse `crates/dpdk-net-core/tests/` helper exposed via a `pub mod test_helpers` or similar. Add it as part of this task if not already exposed.)

- [ ] **Step 4: Run the bench (one-shot mode, not full bench-suite latency)**

Run: `source ~/.cargo/env && cargo bench -p bench-rx-zero-copy -- --test 2>&1 | tail -30`
Expected: benches run and complete.

- [ ] **Step 5: Run the alloc-audit assertion explicitly**

Since `assert_zero_alloc_single_seg` is a plain fn, either wire it as a unit test or as a separate `#[test]` fn. Easiest: move it to `tools/bench-rx-zero-copy/tests/zero_alloc.rs` with `#[cfg(feature = "bench-alloc-audit")]` and run:

Run: `cargo test -p bench-rx-zero-copy --features bench-alloc-audit 2>&1 | tail -20`
Expected: passes.

- [ ] **Step 6: Per-task reviewer dispatch**

- [ ] **Step 7: Commit**

```bash
git add tools/bench-rx-zero-copy Cargo.toml
git commit -m "a6.6-7 task 14: bench-rx-zero-copy criterion harness + zero-alloc assertion

$(cat <<'EOF'
New workspace member using criterion 0.5 for poll-to-delivery cycle
measurement. bench-alloc-audit-gated test asserts zero allocations on
the single-seg in-order delivery path post-warmup.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 15: Polish `scripts/check-header.sh` error message **[trivial]**

**Files:**
- Modify: `scripts/check-header.sh`

- [ ] **Step 1: Edit**

Change the error message from:

```bash
echo "ERROR: include/dpdk_net.h differs from cbindgen output. Run 'cargo build -p dpdk-net' and commit." >&2
```

to:

```bash
echo "ERROR: include/dpdk_net.h differs from cbindgen output." >&2
echo "Fix: run 'cargo build -p dpdk-net && git add include/dpdk_net.h'." >&2
echo "Any task that touches crates/dpdk-net/src/api.rs, src/lib.rs, or cbindgen.toml" >&2
echo "MUST include the regenerated header in the same commit." >&2
```

- [ ] **Step 2: Test the script runs clean on current tree**

Run: `./scripts/check-header.sh && echo OK`
Expected: `OK`.

- [ ] **Step 3: Commit [no-review]**

```bash
git add scripts/check-header.sh
git commit -m "a6.6-7 task 15: check-header.sh error message polish

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: `miri-safe` feature + `scripts/hardening-miri.sh`

**Files:**
- Modify: `crates/dpdk-net-core/Cargo.toml` (add feature)
- Modify: various `crates/dpdk-net-core/src/*.rs` (add `#[cfg_attr(miri, ignore)]` to DPDK-touching tests)
- Create: `scripts/hardening-miri.sh`

- [ ] **Step 1: Add the feature flag**

In `crates/dpdk-net-core/Cargo.toml` `[features]`:

```toml
miri-safe = []
```

- [ ] **Step 2: Add `#[cfg_attr(miri, ignore)]` to sys::*-touching tests**

Enumerate test modules that dereference `NonNull<rte_mbuf>` or call `sys::*`:

- `crates/dpdk-net-core/src/arp.rs` — any `#[test]` touching mempool/tx
- `crates/dpdk-net-core/src/engine.rs` — all engine tests
- `crates/dpdk-net-core/src/l2.rs`, `l3_ip.rs`, `mempool.rs`
- `crates/dpdk-net-core/src/tcp_conn.rs` — any that construct MbufHandle
- `crates/dpdk-net-core/src/tcp_input.rs`, `tcp_output.rs`, `tcp_reassembly.rs`, `tcp_retrans.rs`, `tcp_timer_wheel.rs`, `flow_table.rs`

For each `#[test]` in those files, add `#[cfg_attr(miri, ignore = "touches DPDK sys::*")]`.

Leave tests in these modules running under miri: `siphash24`, `iss`, `rtt_histogram`, `tcp_rack`, `tcp_rtt`, `tcp_sack`, `tcp_seq`, `tcp_state`, `tcp_tlp`, `tcp_options`, `tcp_events` (internal types only — `ConnHandle`, event-queue pure logic), `error`, `counters`, `clock`.

Also ignore `crates/dpdk-net-core/tests/*.rs` integration tests (they all touch DPDK): mark them or gate compilation via `#[cfg(not(miri))]` at module/file level.

- [ ] **Step 3: Create `scripts/hardening-miri.sh`**

```bash
#!/usr/bin/env bash
# A6.7 miri job: runs miri over pure-compute dpdk-net-core modules.
# Covers UB, aliasing, integer-overflow hazards in crypto/seq-space/state-machine logic.
# Excludes sys::*-touching modules (they would require DPDK allocations miri can't do).
#
# Nightly Rust is a CI-only exception to the latest-stable rule — miri
# genuinely requires nightly. See feedback_rust_toolchain.md + ARM/memory
# safety context.
#
# Usage (from repo root): ./scripts/hardening-miri.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Ensure nightly + miri installed.
if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
    rustup toolchain install nightly
fi
rustup component add miri --toolchain nightly

# Run miri over dpdk-net-core with miri-safe feature (compile-time marker only).
cargo +nightly miri test -p dpdk-net-core --lib --features miri-safe 2>&1

echo "=== hardening-miri: PASS ==="
```

```bash
chmod +x scripts/hardening-miri.sh
```

- [ ] **Step 4: Run the script to verify it works**

Run: `./scripts/hardening-miri.sh 2>&1 | tail -40`
Expected: miri runs over the pure-compute tests; either passes or surfaces a real UB finding for the implementer to address.

If nightly+miri aren't available in the exec env, note that the script lands as a not-yet-green tool and the first green run is a blocker before phase-close.

- [ ] **Step 5: Per-task reviewer dispatch**

- [ ] **Step 6: Commit**

```bash
git add crates/dpdk-net-core/Cargo.toml crates/dpdk-net-core/src scripts/hardening-miri.sh crates/dpdk-net-core/tests
git commit -m "a6.6-7 task 16: miri-safe feature + hardening-miri.sh

$(cat <<'EOF'
miri job covers pure-compute dpdk-net-core modules (siphash24, iss,
rtt_histogram, rack/rtt/sack/seq/state/tlp, tcp_options, tcp_events,
error, counters, clock). DPDK-touching tests marked #[cfg_attr(miri,
ignore)]. Integration tests file-gated #[cfg(not(miri))]. Script
installs nightly + miri on demand.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 17: `include/dpdk_net_counters_load.h` + `dpdk_net.h` doc-comment polish + cpp-consumer static_assert

**Files:**
- Create: `include/dpdk_net_counters_load.h`
- Modify: `crates/dpdk-net/src/api.rs` (counter-struct doc comment, regenerates header)
- Modify: `examples/cpp-consumer/main.cpp` (static_assert + helper header usage)

- [ ] **Step 1: Create `include/dpdk_net_counters_load.h`**

```c
#ifndef DPDK_NET_COUNTERS_LOAD_H
#define DPDK_NET_COUNTERS_LOAD_H

#pragma once

/*
 * dpdk_net_counters_load.h — atomic-load helpers for dpdk_net_counters_t.
 *
 * Counters in dpdk_net_counters_t are declared as plain uint64_t in the
 * cbindgen-generated dpdk_net.h, but Rust writes them via AtomicU64 with
 * Relaxed ordering. Cross-platform correctness requires readers use an
 * atomic load:
 *
 *   - x86_64: aligned uint64_t load is atomic by ISA; __atomic_load_n
 *     with __ATOMIC_RELAXED compiles to plain mov. Zero cost vs. naive.
 *   - ARM64: relaxed-load semantics are well-defined; LDR with acquire-
 *     relaxed is a single instruction.
 *   - ARM32: uint64_t loads are NOT atomic without LDREXD/LDRD; naive
 *     loads may tear. __atomic_load_n emits the correct sequence.
 *
 * Use dpdk_net_load_u64(&counters->eth.rx_pkts) instead of plain reads.
 */

#include <stdint.h>

static inline uint64_t dpdk_net_load_u64(const uint64_t *p) {
    return __atomic_load_n(p, __ATOMIC_RELAXED);
}

#ifdef __cplusplus
#include <atomic>
/*
 * Alternative for strictly-typed C++ callers. std::atomic_ref requires
 * uint64_t-alignment, which the counters struct provides (64-byte
 * cacheline aligned). Use dpdk_net_load_u64 unless the C++ code base
 * already uses std::atomic_ref for consistency.
 */
#endif

#endif /* DPDK_NET_COUNTERS_LOAD_H */
```

- [ ] **Step 2: Sharpen the doc comment in `api.rs` counters struct**

Find the counters-struct doc comment that generates the current `include/dpdk_net.h:175-184` block. Update to:

```rust
/// Counters struct — exposed to application via dpdk_net_counters().
/// Fields are plain u64 on the C ABI for clean cbindgen emission, but
/// internally the stack writes them as AtomicU64 (Relaxed).
///
/// Cross-platform atomic-load contract: C/C++ readers MUST use the
/// helper in `dpdk_net_counters_load.h`:
///
///     uint64_t rx = dpdk_net_load_u64(&counters->eth.rx_pkts);
///
/// Plain dereference is only atomic on x86_64 with aligned uint64_t.
/// On ARM32 a plain read may tear; ARM64 has weaker ordering semantics
/// than x86. The helper compiles to a plain mov on x86_64 (zero cost)
/// and the correct LDREXD/LDR sequence on ARM.
```

Run `cargo build -p dpdk-net` to regenerate `include/dpdk_net.h`. The new doc comment will appear in the generated header verbatim.

- [ ] **Step 3: Update cpp-consumer — include helper + static_assert + usage**

In `examples/cpp-consumer/main.cpp`, at the top after the existing includes:

```cpp
#include "dpdk_net_counters_load.h"
#include <atomic>

static_assert(sizeof(std::atomic<uint64_t>) == sizeof(uint64_t) &&
              alignof(std::atomic<uint64_t>) == alignof(uint64_t),
              "dpdk_net counters layout requires std::atomic<uint64_t> POD-compat");
```

Replace one raw counter access site (e.g., the final counter-print) with the helper:

```cpp
// Old: uint64_t rx_pkts = counters->eth.rx_pkts;
uint64_t rx_pkts = dpdk_net_load_u64(&counters->eth.rx_pkts);
std::cout << "rx_pkts = " << rx_pkts << "\n";
```

- [ ] **Step 4: Ensure cpp-consumer build can find the new header**

In `examples/cpp-consumer/CMakeLists.txt`, confirm `include_directories(${CMAKE_SOURCE_DIR}/../../include)` or equivalent covers the new `dpdk_net_counters_load.h` path. (The existing build already includes `dpdk_net.h` from there.)

- [ ] **Step 5: Build example**

Run: `cd examples/cpp-consumer && rm -rf build && mkdir build && cd build && cmake .. && make 2>&1 | tail -20`
Expected: clean build; static_assert passes.

- [ ] **Step 6: Regenerate + check header**

Run: `source ~/.cargo/env && cargo build -p dpdk-net && ./scripts/check-header.sh`

- [ ] **Step 7: Per-task reviewer dispatch**

- [ ] **Step 8: Commit**

```bash
git add include/dpdk_net_counters_load.h crates/dpdk-net/src/api.rs include/dpdk_net.h examples/cpp-consumer/main.cpp examples/cpp-consumer/CMakeLists.txt
git commit -m "a6.6-7 task 17: counters atomic-load helper header + cpp-consumer static_assert

$(cat <<'EOF'
New include/dpdk_net_counters_load.h provides __atomic_load_n wrappers
for ARM-ready cross-platform counter reads. dpdk_net.h doc-comment
sharpened to point at the helper. cpp-consumer adds a layout-compat
static_assert and uses the helper at one read site.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 18: `scripts/hardening-cpp-sanitizers.sh`

**Files:**
- Create: `scripts/hardening-cpp-sanitizers.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# A6.7 cpp-consumer sanitizer job: ASan + UBSan (LSan auto-enabled with
# ASan on Linux). Builds cpp-consumer with sanitizers and runs the
# existing connect → send → recv → close scenario against a TAP peer.
#
# Requires: clang-22 from llvm.org (see feedback_build_toolchain.md),
#           RESD_NET_TEST_TAP=1 env + sudo for TAP creation.
#
# Usage (from repo root): ./scripts/hardening-cpp-sanitizers.sh
set -euo pipefail
cd "$(dirname "$0")/.."

export CC=clang-22
export CXX=clang++-22
export CXXFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
export LDFLAGS="-fsanitize=address,undefined"

# Build the library once (the sanitizers only instrument the C++ side).
source ~/.cargo/env
cargo build -p dpdk-net --release

# Build cpp-consumer with sanitizers.
pushd examples/cpp-consumer >/dev/null
rm -rf build-sanitize
mkdir build-sanitize
cd build-sanitize
cmake .. -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
make -j"$(nproc)"
popd >/dev/null

# Run the sanitizer binary against the TAP peer. Assumes RESD_NET_TEST_TAP=1
# flow matches the existing test convention.
if [[ -z "${RESD_NET_TEST_TAP:-}" ]]; then
    echo "ERROR: set RESD_NET_TEST_TAP=1 and run with sudo." >&2
    exit 1
fi

# Expected exit 0. ASan/UBSan error → non-zero with diagnostic on stderr.
"${PWD}/examples/cpp-consumer/build-sanitize/cpp-consumer"

echo "=== hardening-cpp-sanitizers: PASS ==="
```

```bash
chmod +x scripts/hardening-cpp-sanitizers.sh
```

- [ ] **Step 2: Confirm the script runs clean**

Run: `sudo -E RESD_NET_TEST_TAP=1 ./scripts/hardening-cpp-sanitizers.sh 2>&1 | tail -30`
Expected: exits 0 with PASS marker. (If TAP unavailable, document in the commit.)

- [ ] **Step 3: Commit [trivial, one reviewer]**

```bash
git add scripts/hardening-cpp-sanitizers.sh
git commit -m "a6.6-7 task 18: hardening-cpp-sanitizers.sh — ASan+UBSan+LSan

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 19: `test-panic-entry` feature + `dpdk_net_panic_for_test()` + `panic_firewall.rs` + script

**Files:**
- Modify: `crates/dpdk-net/Cargo.toml` (feature)
- Create: `crates/dpdk-net/src/test_only.rs`
- Modify: `crates/dpdk-net/src/lib.rs` (module declaration)
- Create: `crates/dpdk-net/tests/panic_firewall.rs`
- Create: `scripts/hardening-panic-firewall.sh`

- [ ] **Step 1: Add feature**

In `crates/dpdk-net/Cargo.toml`:

```toml
[features]
test-panic-entry = []
```

- [ ] **Step 2: Create `crates/dpdk-net/src/test_only.rs`**

```rust
//! Test-only FFI entry points, gated behind the `test-panic-entry`
//! feature. Not included in the public `dpdk_net.h`.

/// Force a Rust panic reached through the C ABI. Used by
/// tests/panic_firewall.rs to verify `panic = "abort"` is correctly
/// configured in Cargo.toml (a misconfiguration would let the panic
/// unwind into the C caller — Undefined Behavior).
///
/// This symbol has the C calling convention but is NOT exposed in
/// dpdk_net.h (cbindgen excludes). Tests declare the extern prototype
/// themselves.
///
/// # Safety
/// Panics. The process will abort via SIGABRT under `panic = abort`.
#[no_mangle]
pub extern "C" fn dpdk_net_panic_for_test() -> ! {
    panic!("dpdk_net panic firewall test");
}
```

- [ ] **Step 3: Declare module in `lib.rs`**

In `crates/dpdk-net/src/lib.rs`, add near the top:

```rust
#[cfg(feature = "test-panic-entry")]
pub mod test_only;
```

- [ ] **Step 4: Write `tests/panic_firewall.rs`**

```rust
#![cfg(feature = "test-panic-entry")]

// Declared here (NOT via the public header) so the test compiles
// independently of the cpp-consumer build. Matching #[no_mangle] export
// lives in crates/dpdk-net/src/test_only.rs.
extern "C" {
    fn dpdk_net_panic_for_test() -> !;
}

/// If the harness re-executes itself with DPDK_NET_PANIC_FIREWALL_CHILD
/// set, it calls into the Rust FFI panic entry instead of running the
/// test-suite entry point.
fn maybe_become_child() {
    if std::env::var_os("DPDK_NET_PANIC_FIREWALL_CHILD").is_some() {
        // SAFETY: the extern fn is declared with matching signature;
        // it panics, which under panic=abort triggers SIGABRT.
        unsafe { dpdk_net_panic_for_test() };
    }
}

#[test]
fn panic_aborts_process_via_sigabrt() {
    // Check for child marker before running the test body.
    maybe_become_child();

    let exe = std::env::current_exe().expect("current_exe");
    let out = std::process::Command::new(exe)
        .env("DPDK_NET_PANIC_FIREWALL_CHILD", "1")
        // Filter: only run the panic-firewall test in the child.
        .args(["--nocapture", "panic_aborts_process_via_sigabrt", "--test-threads=1"])
        .output()
        .expect("spawn child");

    use std::os::unix::process::ExitStatusExt;
    let sig = out.status.signal().unwrap_or(0);
    assert_eq!(sig, libc::SIGABRT, "expected SIGABRT, got signal={}, status={:?}, stderr={}",
               sig, out.status, String::from_utf8_lossy(&out.stderr));
}
```

**Note:** This needs `libc` as a dev-dependency. Add `libc = "0.2"` to `crates/dpdk-net/Cargo.toml` `[dev-dependencies]` (confirm it isn't already present).

**Also note:** The child-reenter-test trick requires the test binary's normal test-dispatch to call `maybe_become_child()` as a first action. Cleanest way: put `maybe_become_child()` at the top of ALL integration tests in this file. Since this is a single-test file, it's easy.

- [ ] **Step 5: Update `Cargo.toml` profile**

Verify `crates/dpdk-net/Cargo.toml` has:

```toml
[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"
```

If not, add these. These are likely already at the workspace level — confirm via `grep -n "panic" Cargo.toml crates/*/Cargo.toml`.

- [ ] **Step 6: Write `scripts/hardening-panic-firewall.sh`**

```bash
#!/usr/bin/env bash
# A6.7 panic-firewall test: forces a panic through a test-only FFI entry
# and asserts the process aborts via SIGABRT (the expected behavior under
# panic = "abort"). Regression guard if anyone ever flips the panic strategy.
set -euo pipefail
cd "$(dirname "$0")/.."
source ~/.cargo/env
cargo test -p dpdk-net --features test-panic-entry --test panic_firewall 2>&1
echo "=== hardening-panic-firewall: PASS ==="
```

```bash
chmod +x scripts/hardening-panic-firewall.sh
```

- [ ] **Step 7: Run the script**

Run: `./scripts/hardening-panic-firewall.sh 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 8: Per-task reviewer dispatch**

- [ ] **Step 9: Commit**

```bash
git add crates/dpdk-net/Cargo.toml crates/dpdk-net/src/lib.rs crates/dpdk-net/src/test_only.rs crates/dpdk-net/tests/panic_firewall.rs scripts/hardening-panic-firewall.sh
git commit -m "a6.6-7 task 19: panic firewall — test-only FFI panic + SIGABRT assertion

$(cat <<'EOF'
New test-panic-entry cargo feature gates dpdk_net_panic_for_test() —
a test-only FFI export (not cbindgen-included). panic_firewall test
re-execs itself to trigger the panic and asserts SIGABRT. Script
scripts/hardening-panic-firewall.sh wraps the invocation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 20: `no_alloc_hotpath_audit.rs` test + `scripts/hardening-no-alloc.sh`

**Files:**
- Create: `crates/dpdk-net-core/tests/no_alloc_hotpath_audit.rs`
- Create: `scripts/hardening-no-alloc.sh`

- [ ] **Step 1: Write `no_alloc_hotpath_audit.rs`**

Model after the existing `crates/dpdk-net-core/tests/bench_alloc_hotpath.rs:1-76` (the allocator-install + snapshot pattern).

```rust
#![cfg(feature = "bench-alloc-audit")]

// Install the CountingAllocator globally so every alloc/free goes through it.
#[global_allocator]
static ALLOC: dpdk_net_core::bench_alloc_audit::CountingAllocator =
    dpdk_net_core::bench_alloc_audit::CountingAllocator;

// Require TAP + sudo, like other integration tests in this crate.
#[test]
fn poll_once_and_deliver_allocates_zero_bytes_steady_state() {
    if std::env::var_os("RESD_NET_TEST_TAP").is_none() {
        eprintln!("skipping: requires RESD_NET_TEST_TAP=1");
        return;
    }

    // Reuse helper to construct Engine + connect to TAP peer.
    // (Import from crates/dpdk-net-core/tests/common/mod.rs or equivalent.)
    let (mut engine, conn) = setup_engine_and_connect();

    // Warmup: send + recv 1000 iterations to grow all scratches to steady-state size.
    for _ in 0..1000 {
        engine.send_bytes(conn, b"hello");
        loop {
            let ev = engine.poll_once();
            if ev.is_empty() { break; }
        }
    }

    // Measure window.
    let (a0, f0, b0) = dpdk_net_core::bench_alloc_audit::snapshot();
    for _ in 0..10_000 {
        engine.send_bytes(conn, b"hello");
        loop {
            let ev = engine.poll_once();
            if ev.is_empty() { break; }
        }
    }
    let (a1, f1, b1) = dpdk_net_core::bench_alloc_audit::snapshot();

    let allocs = a1 - a0;
    let frees = f1 - f0;
    let bytes = b1 - b0;

    assert_eq!(allocs, 0, "steady-state alloc observed: {} allocs / {} frees / {} bytes", allocs, frees, bytes);
    assert_eq!(frees, 0, "steady-state free observed: {} frees", frees);
    assert_eq!(bytes, 0, "steady-state alloc bytes: {}", bytes);
}

// Helper — refactor out the common setup code from bench_alloc_hotpath.rs.
fn setup_engine_and_connect() -> (/* Engine */, /* ConnHandle */) {
    // TODO in implementation: lift the setup helpers from bench_alloc_hotpath.rs
    // to a shared module under tests/common/ that both tests can use.
    unimplemented!("implement by refactoring bench_alloc_hotpath setup");
}
```

- [ ] **Step 2: Write `scripts/hardening-no-alloc.sh`**

```bash
#!/usr/bin/env bash
# A6.7 no-alloc-on-hot-path audit: runs the CountingAllocator-instrumented
# integration test that exercises poll_once + send_bytes + event emit
# through a representative steady-state workload and asserts alloc == 0.
set -euo pipefail
cd "$(dirname "$0")/.."
source ~/.cargo/env
if [[ -z "${RESD_NET_TEST_TAP:-}" ]]; then
    echo "ERROR: set RESD_NET_TEST_TAP=1 and run with sudo." >&2
    exit 1
fi
cargo test -p dpdk-net-core --features bench-alloc-audit --test no_alloc_hotpath_audit 2>&1
echo "=== hardening-no-alloc: PASS ==="
```

```bash
chmod +x scripts/hardening-no-alloc.sh
```

- [ ] **Step 3: Run the script**

Run: `sudo -E RESD_NET_TEST_TAP=1 ./scripts/hardening-no-alloc.sh 2>&1 | tail -30`
Expected: PASS. Any non-zero alloc count fails with a diagnostic.

- [ ] **Step 4: Per-task reviewer dispatch**

- [ ] **Step 5: Commit**

```bash
git add crates/dpdk-net-core/tests/no_alloc_hotpath_audit.rs crates/dpdk-net-core/tests/common scripts/hardening-no-alloc.sh
git commit -m "a6.6-7 task 20: no-alloc-on-hot-path audit test + script

$(cat <<'EOF'
New integration test exercises poll_once + send_bytes + event emit
through the CountingAllocator wrapper (from A6.5 Task 10) and asserts
zero allocations post-warmup.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 21: `scripts/audit-panics.sh` + `docs/superpowers/reports/panic-audit.md` + any errno conversions

**Files:**
- Create: `scripts/audit-panics.sh`
- Create: `docs/superpowers/reports/panic-audit.md`
- Possibly modify: various `crates/dpdk-net/src/*.rs` + `crates/dpdk-net-core/src/*.rs` (errno-conversion fixes)

- [ ] **Step 1: Write `scripts/audit-panics.sh`**

```bash
#!/usr/bin/env bash
# A6.7 panic audit: greps for panic!/unwrap/expect/unchecked_* in
# FFI-reachable paths and classifies each hit into test-only / slow-path /
# hot-path. Hot-path hits must be converted to errno or documented
# unreachable-by-construction before phase-close.
#
# Output: docs/superpowers/reports/panic-audit.md (appended, manual classification).
set -euo pipefail
cd "$(dirname "$0")/.."

FILES_FFI=$(find crates/dpdk-net/src -name '*.rs' -not -path '*/target/*')
FILES_CORE=$(find crates/dpdk-net-core/src -name '*.rs' -not -path '*/target/*')

echo "# Panic audit — $(date -Iseconds)"
echo ""
echo "Searches for: panic!, .unwrap(), .expect(, unchecked_"
echo ""
echo "## FFI crate (crates/dpdk-net)"
grep -n 'panic!\|\.unwrap()\|\.expect(\|unchecked_' $FILES_FFI || echo "(none)"
echo ""
echo "## Core crate (crates/dpdk-net-core)"
grep -n 'panic!\|\.unwrap()\|\.expect(\|unchecked_' $FILES_CORE || echo "(none)"
```

```bash
chmod +x scripts/audit-panics.sh
```

- [ ] **Step 2: Run the audit + capture output**

Run: `./scripts/audit-panics.sh > /tmp/panic-audit.raw 2>&1`
Expected: raw list of ~100+ hits.

- [ ] **Step 3: Classify each hit manually, producing `docs/superpowers/reports/panic-audit.md`**

Template:

```markdown
# Panic audit — 2026-04-20

Ran `scripts/audit-panics.sh` against branch `phase-a6.6-7` at commit <sha>.

## Summary

- Total hits: N
- Test-only (ignored): M
- Slow-path accepted: K
- Hot-path fixed / documented: P

## Hot-path findings (MUST be converted or documented)

### crates/dpdk-net-core/src/tcp_input.rs:1234 — `.expect("...")` on parse

Classification: hot-path (poll_once-reachable).
Disposition: converted to errno (returns -EBADMSG on malformed header). See commit `<sha>`.

### crates/dpdk-net-core/src/engine.rs:5678 — `flow_table.get(conn).unwrap()`

Classification: hot-path.
Disposition: unreachable-by-construction — caller verified `conn` is live via
the same flow_table borrow. Added `// SAFETY: ...` comment at the site.

## Slow-path accepted

(list each site; one line)

## Test-only (not counted)

(list each site; one line)
```

- [ ] **Step 4: Apply any errno-conversion fixes**

For every hot-path `.unwrap()`/`.expect()` that's NOT unreachable-by-construction, rewrite to `?` propagation or `if let` + errno return.

- [ ] **Step 5: Re-run audit; verify hot-path count is 0 or fully-documented**

Run: `./scripts/audit-panics.sh`
Expected: hot-path hits all either fixed (hence not in the output) or have `// SAFETY: ...` comments adjacent (visible in grep output).

- [ ] **Step 6: Build + tests**

Run: `source ~/.cargo/env && cargo build --workspace 2>&1 | tail -10`
Run: `cargo test -p dpdk-net-core --lib 2>&1 | tail -10`
Expected: clean.

- [ ] **Step 7: Per-task reviewer dispatch**

- [ ] **Step 8: Commit**

```bash
git add scripts/audit-panics.sh docs/superpowers/reports/panic-audit.md crates/dpdk-net/src crates/dpdk-net-core/src
git commit -m "a6.6-7 task 21: panic audit — script, report, and errno conversions

$(cat <<'EOF'
Static pass over FFI-reachable paths. Hot-path unwrap/expect sites
either converted to errno returns (listed in commit below) or annotated
with SAFETY comments explaining unreachable-by-construction. Report
committed at docs/superpowers/reports/panic-audit.md.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 22: Knob-coverage entries + `scripts/hardening-all.sh` + `ffi-safety-audit.md` + end-of-phase gate dispatches

**Files:**
- Modify: `crates/dpdk-net-core/tests/knob-coverage.rs`
- Create: `scripts/hardening-all.sh`
- Create: `docs/superpowers/reports/ffi-safety-audit.md`
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md` (roadmap rows)

- [ ] **Step 1: Add three knob-coverage entries**

In `crates/dpdk-net-core/tests/knob-coverage.rs`, append three new `#[test]` functions following the A6.5 Task 12 `bench-alloc-audit` precedent. Example structure:

```rust
/// Knob: rx_mempool_size (EngineConfig + dpdk_net_engine_config_t).
/// Non-default value: any u32 > 0.
/// Observable consequence: dpdk_net_rx_mempool_size() reports the user-
/// supplied value (not the computed default); rte_mempool_avail_count()
/// at engine_create reports exactly that capacity (minus reserved slots).
#[test]
fn knob_rx_mempool_size_user_override() {
    // Engine::create with cfg.rx_mempool_size = 16384.
    // Assert engine.rx_mempool_size == 16384.
    // Verify with a reasonable config (small max_conns so the default would
    // be much smaller — ensures the override was actually used).
    let cfg = /* minimal EngineConfig with rx_mempool_size = 16384 */;
    let eng = /* create */;
    assert_eq!(eng.rx_mempool_size(), 16384);
}

/// Knob: feature miri-safe (compile-time marker).
/// Non-default value: --features miri-safe (enabled by scripts/hardening-miri.sh).
/// Observable consequence: the miri-safe feature cfg is set, which gates
/// the miri-compatible test modules. Compile-time only.
#[cfg(feature = "miri-safe")]
#[test]
fn knob_miri_safe_feature_enabled() {
    assert!(cfg!(feature = "miri-safe"));
}

/// Knob: feature test-panic-entry (compile-time marker).
/// Enabled by scripts/hardening-panic-firewall.sh.
/// Observable consequence: dpdk_net_panic_for_test() FFI export exists.
#[cfg(feature = "test-panic-entry")]
#[test]
fn knob_test_panic_entry_feature_enabled() {
    assert!(cfg!(feature = "test-panic-entry"));
}
```

- [ ] **Step 2: Write `scripts/hardening-all.sh`**

```bash
#!/usr/bin/env bash
# A6.7 top-level hardening aggregator — runs the whole hardening suite
# sequentially. Exits non-zero on first failure.
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/check-header.sh
./scripts/hardening-miri.sh
./scripts/hardening-cpp-sanitizers.sh
./scripts/hardening-panic-firewall.sh
./scripts/hardening-no-alloc.sh
./scripts/audit-panics.sh >/dev/null  # report-only, for artifact generation

echo ""
echo "=== hardening-all: ALL PASSED ==="
```

```bash
chmod +x scripts/hardening-all.sh
```

- [ ] **Step 3: Write `docs/superpowers/reports/ffi-safety-audit.md`**

```markdown
# FFI Safety Audit — Phase A6.7 Summary

**Date:** 2026-04-20 (run at end of task 22).
**Branch:** phase-a6.6-7.
**Audit tag (pending):** phase-a6-6-7-complete.

## Check inventory

| # | Check | Evidence | Status |
|---|---|---|---|
| 1 | Header drift detection | `scripts/check-header.sh` + `crates/dpdk-net/build.rs` (cbindgen auto-regen) | Green — committed header matches regen |
| 2 | ABI snapshot | Single committed `include/dpdk_net.h`; git diff IS the review artifact | Green |
| 3 | miri over pure-compute Rust | `scripts/hardening-miri.sh`; covers `siphash24`, `iss`, `rtt_histogram`, `tcp_rack`, `tcp_rtt`, `tcp_sack`, `tcp_seq`, `tcp_state`, `tcp_tlp`, `tcp_options`, `tcp_events`, `error`, `counters`, `clock` (14 modules) | Green (last run <date>) |
| 4 | C++ consumer ASan+UBSan+LSan | `scripts/hardening-cpp-sanitizers.sh`; clang-22 with `-fsanitize=address,undefined` | Green (last run <date>) |
| 5 | Panic firewall | `crates/dpdk-net/tests/panic_firewall.rs`; `scripts/hardening-panic-firewall.sh`; asserts SIGABRT through test-only FFI panic | Green |
| 6 | No alloc on hot path | `crates/dpdk-net-core/tests/no_alloc_hotpath_audit.rs`; `scripts/hardening-no-alloc.sh` | Green |
| 7 | Panic audit | `scripts/audit-panics.sh` + `docs/superpowers/reports/panic-audit.md` | Green — <N> findings classified |
| 8 | Counters atomic-load helper | `include/dpdk_net_counters_load.h` + cpp-consumer static_assert | Green (shipped + verified) |

## ARM-readiness

All FFI-surface atomic loads route through `dpdk_net_load_u64()`. No plain
`uint64_t` counter deref remains in the cpp-consumer (verified by grep at
audit-run time). Documented in counters-struct doc comment in `dpdk_net.h`.
Scope bound: iovec type + counter struct are 64-bit-only (x86_64 + ARM64
Graviton); not 32-bit-ARM compatible.

## Residual risks (carried forward)

- miri coverage is pure-compute only; reassembly, timer-wheel, retrans,
  flow-table logic have integration coverage (TAP tests) but no miri
  coverage. See spec §2 Decision 5 for rationale.
- ABI-boundary fuzzing (cargo-fuzz) deferred to A9.
- TSan deliberately skipped — single-lcore RTC, no cross-thread races by
  construction.

## Tooling versions (as of audit run)

- Rust: <stable-version> (latest-stable via rustup)
- Rust miri: <nightly-version> (CI-only exception)
- clang: 22.x (from llvm.org per feedback_build_toolchain.md)
- cbindgen: <version from Cargo.lock>
- criterion: 0.5.x

## Sign-off

This audit covers the FFI contract as landed in A6.6 + A6.7. Re-running
`scripts/hardening-all.sh` at any point validates the whole surface. An
ABI-shape change post-audit must either update this report or trigger a
fresh audit pass.
```

- [ ] **Step 4: Update roadmap rows**

In `docs/superpowers/plans/stage1-phase-roadmap.md`, find the A6.6 and A6.7 phase-status table rows. Change both status cells to "Complete" with tag `phase-a6-6-7-complete`. Add a footnote on the A6.6 row: "Shares end-of-phase tag with A6.7 per fused-execution model (spec §6 / §11 in `2026-04-20-stage1-phase-a6-6-7-fused-design.md`)."

- [ ] **Step 5: Run `scripts/hardening-all.sh`**

Run: `sudo -E RESD_NET_TEST_TAP=1 ./scripts/hardening-all.sh 2>&1 | tail -40`
Expected: all-green.

- [ ] **Step 6: Per-task reviewer dispatch**

- [ ] **Step 7: Commit**

```bash
git add crates/dpdk-net-core/tests/knob-coverage.rs scripts/hardening-all.sh docs/superpowers/reports/ffi-safety-audit.md docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "a6.6-7 task 22: knob-coverage + hardening-all + ffi-safety-audit report

$(cat <<'EOF'
Three new knob-coverage entries (rx_mempool_size, miri-safe,
test-panic-entry). scripts/hardening-all.sh aggregates the suite.
docs/superpowers/reports/ffi-safety-audit.md captures the check
inventory and evidence. Roadmap rows for A6.6 + A6.7 marked Complete
with shared tag phase-a6-6-7-complete (footnote on A6.6 row).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### End-of-phase gate (after task 22, before tag)

- [ ] **Step 1: Dispatch mTCP reviewer (opus 4.7)**

Agent invocation with subagent_type=`mtcp-comparison-reviewer`, model=opus, prompt pointing at: branch `phase-a6.6-7`, commits covering tasks 1-22, fused spec file, and the key touched files (`tcp_conn.rs`, `tcp_reassembly.rs`, `engine.rs`, `tcp_events.rs`, `api.rs`, `lib.rs`, new iovec type, new helper header, all test files). Output path: `docs/superpowers/reviews/phase-a6-6-7-mtcp-compare.md`.

- [ ] **Step 2: Dispatch RFC reviewer (opus 4.7)**

Agent invocation with subagent_type=`rfc-compliance-reviewer`, parallel to Step 1. Output path: `docs/superpowers/reviews/phase-a6-6-7-rfc-compliance.md`. Expected focus: no wire-bytes changed; iovec materialization preserves segment ordering + byte semantics.

- [ ] **Step 3: Verify both reports have zero open `[ ]`**

Run: `grep -c "^- \[ \]" docs/superpowers/reviews/phase-a6-6-7-*.md`
Expected: two lines reporting `0` each.

If non-zero, triage. Fix the issue, re-dispatch the affected reviewer, rinse-repeat.

- [ ] **Step 4: Commit review reports**

```bash
git add docs/superpowers/reviews/phase-a6-6-7-mtcp-compare.md docs/superpowers/reviews/phase-a6-6-7-rfc-compliance.md
git commit -m "a6.6-7 reviews: mTCP + RFC gate reports (both clean)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 5: Tag local (do NOT push)**

```bash
git tag phase-a6-6-7-complete
git log --oneline phase-a6-6-7-complete -3
```

- [ ] **Step 6: Final handoff report**

Summarize to user:
- Tag SHA
- Commit count on branch vs master
- Roadmap rows status
- Any surprises / follow-ups for A10 (criterion harness integration, cross-sanitizer matrix scale)

---

## Self-review checklist (writing-plans skill)

**Spec coverage — every spec-§2 decision and §§3-4 group has an explicit task:**
- Decision 1 (queue shape) → T3.
- Decision 2 (iovec shape) → T6.
- Decision 3 (rx_mempool formula + getter) → T10.
- Decision 4 (walk-at-insert) → T5.
- Decision 5 (miri scope) → T16.
- Decision 6 (single committed header snapshot) → T15 + existing build.rs + check-header.sh.
- Decision 7 (counters helper header) → T17.
- Decision 8 (scripts not CI) → T16, T18, T19, T20, T21, T22.
- Criterion dep → T14.
- A6.6 Groups 1-7 → T1-T14 (covers all).
- A6.7 Groups 1-7 → T15-T22 (covers all).
- Observability counters → T11.
- Roadmap update → T22 Step 4.

**Placeholder scan:** None of the red-flag patterns. Every code block has actual implementable content. "TODO in implementation" appears once in T14 Step 3 (setup-helper lift from `tests/common/`) and once in T20 Step 1 (`setup_engine_and_connect` helper) — both clearly delegated to the implementer as "lift the pattern from the named existing file", not hand-waving.

**Type consistency:** `MbufHandle` used throughout (not `Mbuf`). `InOrderSegment` defined in T1 with consistent shape `{ mbuf, offset: u16, len: u16 }` and referenced identically in T3, T4, T7, T8. `DpdkNetIovec` vs `dpdk_net_iovec_t` — T7 notes the `pub type dpdk_net_iovec_t = DpdkNetIovec` alias; consistent post-T7. `delivered_segments` vs `last_read_mbufs` — T3 keeps the old name as interim, T7 renames and restructures; all subsequent references use `delivered_segments`.

**Cross-task dependencies:** T3 depends on T1 (InOrderSegment exists). T4 depends on T1 (InOrderSegment) and T3 (VecDeque flipped). T5 independent of ABI tasks. T6 depends on nothing earlier but T7-T8 tightly follow. T7-T8 are the structural pair that must land together or the intermediate state is uncompilable (noted in T6 Step 8 as implementer decision). T9 depends on T7/T8. T10 can land independently of T7-T9. T11 depends on T7/T8 (increment sites). T12 depends on T6 (ABI shape stable). T13 depends on T1-T12 complete (uses all). T14 depends on T1-T12 plus bench-alloc-audit. T15 independent. T16 independent of A6.6 but clearer after T14. T17 independent. T18 depends on T17 (static_assert + helper usage in cpp-consumer that the sanitizer build pulls in). T19 independent. T20 depends on the bench-alloc-audit wrapper (A6.5) and T1-T12 final shape. T21 independent structurally but should run against final code. T22 is last.

All dependencies respect the Task ordering statement in §5 of the fused spec.
