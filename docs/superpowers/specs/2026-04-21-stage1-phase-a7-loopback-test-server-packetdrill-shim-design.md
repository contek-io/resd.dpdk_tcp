# Stage 1 — Phase A7: Loopback test server + packetdrill-shim (design)

Date: 2026-04-21
Status: Draft, pending user approval
Branch: `phase-a7` (off tag `phase-a6-6-7-complete` / commit `2c4e0b6`)
Parent spec: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` (§10.2, §10.12, §11)
Roadmap row: `docs/superpowers/plans/stage1-phase-roadmap.md` L526–546

---

## 1. Purpose and scope

Phase A7 delivers the Stage 1 Layer B — RFC-conformance testing via the
google/packetdrill corpus (Luna-pattern shim), together with the minimal
server-FSM surface that A8's tcpreq gate needs.

The phase adds four things:

1. A minimal server-side TCP FSM (`LISTEN → SYN_RECEIVED → ESTABLISHED
   + passive/active close + bidirectional byte-stream echo`) behind the
   cargo feature `test-server`. Not compiled into production builds.
2. A test-only FFI layer — `dpdk_net_test.h`, generated only when
   building with `--features test-server`; never shipped in the public
   `dpdk_net.h` — exposing `set_time_ns`, `inject_frame`, `drain_tx_frames`,
   `listen/accept`, and synchronous `connect/send/recv/close`.
3. A Luna-pattern packetdrill shim: `third_party/packetdrill/` vendored
   as a git submodule, patched through a small series in
   `tools/packetdrill-shim/patches/` so its TUN I/O and syscall surface
   redirect to the test-only FFI. Every fake syscall pumps the engine
   to quiescence at the current virtual time before returning.
4. A CI-gated runner crate `tools/packetdrill-shim-runner/` that
   iterates the ligurio packetdrill corpus, asserts 100% pass on the
   runnable subset, and pins `(runnable_count, skipped_count)` as
   constants so silent drift fails CI.

### 1.1 In scope

- Server path: passive open; bidirectional data transfer; passive close
  (peer FINs first → CLOSE_WAIT → LAST_ACK); active close (server
  sends FIN first → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT). Accept queue
  size 1. Single listen port per test.
- Shim transport: in-memory frame hook (patched packetdrill; no TUN,
  no kernel, no sudo).
- Virtual clock swap: under `cfg(feature = "test-server")`,
  `clock::now_ns()` reads a thread-local `u64` written via
  `dpdk_net_test_set_time_ns`. Default build is unchanged.
- Corpora: **ligurio CI-gated** in A7. Shivansh + google upstream are
  wired into the runner (same classifier + runner plumbing) but their
  integration tests are `#[ignore]`d in A7; A8 flips the ignore off.
- RFC-mode preset: reuse existing `preset=rfc_compliance` as-is; no
  new engine-wide knobs.
- I-8 defer (multi-seg FIN-piggyback, deferred out of A6.6-7) closed
  by a dedicated script under `tests/scripts/` that runs inside the
  A7 corpus gate.
- Knob-coverage informational-whitelist entry for the `test-server`
  cargo feature (build flag, no runtime behavioral effect).
- End-of-phase mTCP + RFC review gates, both blocking the
  `phase-a7-complete` tag.

### 1.2 Out of scope

- tcpreq (Layer C) — A8.
- TCP-Fuzz differential + smoltcp FaultInjector — A9.
- Benchmark harness — A10.
- Production server-side API (`dpdk_net_listen / _accept` in the
  default build). Stage 1 ships client-only; the server FSM here is
  test-infrastructure behind a compile-time feature.
- Multi-connection accept queue, simultaneous-open, multi-listener.
- IPv6 packetdrill scripts (Stage 1 is IPv4-only).
- Any new wire behavior beyond what `preset=rfc_compliance` already
  toggles.
- Bench output / dashboard plumbing (owned by A10's `bench-report`).
- Linking packetdrill via DPDK TAP vdev or through a userspace TUN
  proxy — both rejected in favor of the in-memory frame hook.

---

## 2. Architecture

```
 third_party/packetdrill/                     git submodule, pinned SHA
    + tools/packetdrill-shim/patches/         patch stack (git am)
    + tools/packetdrill-shim/build.sh         init + apply + autotools + link
        ↓ links against
 libdpdk_net.a (staticlib, cargo --features test-server)
    ├── dpdk_net_test.h   cbindgen-only under --features test-server
    │      │  dpdk_net_test_set_time_ns / inject_frame / drain_tx_frames
    │      │  dpdk_net_test_listen / accept_next
    │      │  dpdk_net_test_connect / send / recv / close
    │      └── excluded from dpdk_net.h unconditionally
    └── dpdk-net-core --features test-server
         ├── src/test_server.rs      listen slot, passive-open dispatch
         ├── clock.rs                cfg-swap: thread-local virt_ns
         ├── tcp_input/tcp_output/tcp_conn   feature-gated SYN_RCVD hunks
         └── flow_table              unchanged; passive slot indexes
                                     by same 4-tuple key

 Default build (no --features test-server) is bit-identical to
 phase-a6-6-7-complete. Public dpdk_net.h contains zero new symbols.
 header-drift CI catches any leak.

 tools/packetdrill-shim-runner/   cargo binary crate
    ├── build.rs                   calls ../packetdrill-shim/build.sh
    ├── src/main.rs                run one .pkt (local debug ergonomics)
    ├── tests/corpus_ligurio.rs    CI-gated integration test
    ├── tests/corpus_shivansh.rs   #[ignore] in A7 (A8 flips)
    ├── tests/corpus_google.rs     #[ignore] in A7 (A8 flips)
    ├── tests/our_scripts.rs       tests/scripts/*.pkt (incl. I-8 regr)
    └── tests/corpus-counts.rs     LIGURIO_RUNNABLE_COUNT / SKIPPED_COUNT
```

Notes on shape:

- The server FSM lives inside dpdk-net-core rather than in a separate
  crate. Every added line is gated on `feature = "test-server"` so
  the private internals stay private in production.
- All test-only FFI lives in `crates/dpdk-net/src/test_ffi.rs`, with
  its own cbindgen config that emits `include/dpdk_net_test.h` only
  when the feature is on. The production `cbindgen.toml` adds an
  explicit exclusion list for every `dpdk_net_test_*` symbol, so
  even a mis-gate cannot leak them into `dpdk_net.h`.
- The shim binary is built by shell (build.sh), not by cargo directly,
  because packetdrill uses autotools. The cargo `build.rs` calls
  build.sh from within `tools/packetdrill-shim-runner/` so CI has a
  single `cargo test` entry point.
- mTCP is already submoduled at `third_party/mtcp/` from phase A2 for
  the §10.13 review gate — A7 follows that vendoring pattern.

---

## 3. Components

### 3.1 Server FSM additions (`dpdk-net-core`, feature `test-server`)

New module `crates/dpdk-net-core/src/test_server.rs`:

- `pub struct ListenSlot { local_ip: u32, local_port: u16,
  accept_queue: Option<ConnHandle> }` — queue size 1 by scope decision;
  additional SYNs while the slot already has a queued ESTABLISHED
  handle are rejected with RST (matches the minimal-server choice).
- `impl Engine { pub fn listen(&mut self, ip: u32, port: u16)
  -> Result<ListenHandle, Error>; pub fn accept_next(&mut self,
  listen: ListenHandle) -> Option<ConnHandle>; }` — both
  `#[cfg(feature = "test-server")]`.

Existing modules get `#[cfg(feature = "test-server")]` hunks only:

- `tcp_input.rs`: before the 4-tuple flow-table lookup, if dst-(ip,port)
  matches a ListenSlot and the segment is a SYN, allocate a per-conn
  slot in `SYN_RECEIVED`, seed ISS via the existing SipHash path, set
  `rcv.nxt = iss_peer + 1`, and arm SYN-ACK TX. If the segment is the
  expected final ACK for an in-progress SYN_RCVD slot, transition to
  ESTABLISHED and push the handle into the listen slot's accept queue.
- `tcp_state.rs`: no code changes — `Listen` and `SynReceived` enum
  variants were added at A1 and the `state_trans[from][to]` matrix
  in `counters.rs` already reserves indices for them.
- `tcp_output.rs`: the existing SYN-ACK builder already handles
  `syn=1 ack=1`; used unchanged from the passive-open direction.
- `tcp_conn.rs`: `new_from_passive_open(...)` constructor alongside
  `new_from_active_open(...)`. Both share timer_wheel entries, RACK
  state, RTT sampler, and send/recv buffers.
- `flow_table.rs`: unchanged — the passive-open slot indexes by the
  same `(local_ip, local_port, peer_ip, peer_port)` key as active-open.

Echo is **not** implemented in the engine. The shim implements echo
on top of `dpdk_net_test_recv` / `dpdk_net_test_send` when a
packetdrill script's server-behavior declaration asks for it. Keeps
the server FSM free of application policy.

### 3.2 Test-only FFI (`dpdk_net_test.h`)

New module `crates/dpdk-net/src/test_ffi.rs`, all functions
`#[cfg(feature = "test-server")]`:

```rust
#[repr(C)]
pub struct dpdk_net_test_frame_t {
    pub buf: *const u8,  // shim-owned: valid until the next drain call
    pub len: usize,
}

#[no_mangle] pub extern "C" fn dpdk_net_test_set_time_ns(ns: u64);
#[no_mangle] pub extern "C" fn dpdk_net_test_inject_frame(
    engine: *mut dpdk_net_engine_t,
    buf: *const u8, len: usize) -> i32;
#[no_mangle] pub extern "C" fn dpdk_net_test_drain_tx_frames(
    engine: *mut dpdk_net_engine_t,
    out: *mut dpdk_net_test_frame_t, max: usize) -> usize;
#[no_mangle] pub extern "C" fn dpdk_net_test_listen(
    engine: *mut dpdk_net_engine_t, local_port: u16)
    -> dpdk_net_listen_handle_t;
#[no_mangle] pub extern "C" fn dpdk_net_test_accept_next(
    engine: *mut dpdk_net_engine_t,
    listen: dpdk_net_listen_handle_t) -> dpdk_net_handle_t;
#[no_mangle] pub extern "C" fn dpdk_net_test_connect(
    engine: *mut dpdk_net_engine_t,
    dst_ip: u32, dst_port: u16,
    opts: *const dpdk_net_connect_opts_t) -> dpdk_net_handle_t;
#[no_mangle] pub extern "C" fn dpdk_net_test_send(
    engine: *mut dpdk_net_engine_t,
    h: dpdk_net_handle_t, buf: *const u8, len: usize) -> isize;
#[no_mangle] pub extern "C" fn dpdk_net_test_recv(
    engine: *mut dpdk_net_engine_t,
    h: dpdk_net_handle_t, out: *mut u8, max: usize) -> isize;
#[no_mangle] pub extern "C" fn dpdk_net_test_close(
    engine: *mut dpdk_net_engine_t,
    h: dpdk_net_handle_t, flags: u32) -> i32;
```

**Frame ownership.** The shim owns the TX-frame copy buffer that
`drain_tx_frames` returns pointers into. Those pointers are valid
until the next call to `drain_tx_frames` on the same engine, which
is the one-drain-per-step discipline the runner already follows.
Injected RX frames are copied into a fresh mbuf inside
`inject_frame`, so the caller's `buf` is consumed at call time and
never held across.

**Pump discipline.** Every test-FFI entry point except `set_time_ns`
and `accept_next` ends with `pump_until_quiescent(engine)`:

```rust
loop {
    let drained = engine.run_tx_burst();
    let fired  = engine.timer_wheel.fire_due(now_ns());
    if drained == 0 && fired == 0 { break; }
}
```

No wall-clock loop; the pump advances only as long as there is work
at the current virtual time. This is what makes the shim deterministic.

**Iteration cap.** Pump has a hard iteration cap (`MAX_PUMP_ITERS =
10_000`) to defend against pathological FSM loops. Exceeding it
returns `-EDEADLK` to the caller; the runner records the script as
errored (distinct from asserted-failed) and exits non-zero.

**cbindgen config.** `crates/dpdk-net/cbindgen-test.toml` emits to
`include/dpdk_net_test.h` and is only invoked under
`--features test-server`. The existing `cbindgen.toml` gets an
explicit exclusion list covering every `dpdk_net_test_*` prefix, so
mis-gating cannot leak test symbols into `dpdk_net.h`. The existing
header-drift CI validates both behaviors.

### 3.3 Virtual clock swap

`crates/dpdk-net-core/src/clock.rs`:

```rust
#[cfg(not(feature = "test-server"))]
#[inline] pub fn now_ns() -> u64 {
    let e = tsc_epoch();
    let delta = rdtsc().wrapping_sub(e.tsc0);
    e.t0_ns + ((delta as u128 * e.ns_per_tsc_scaled as u128) >> 32) as u64
}

#[cfg(feature = "test-server")]
thread_local! { static VIRT_NS: Cell<u64> = Cell::new(0); }

#[cfg(feature = "test-server")]
#[inline] pub fn now_ns() -> u64 { VIRT_NS.with(|c| c.get()) }

#[cfg(feature = "test-server")]
pub fn set_virt_ns(ns: u64) {
    VIRT_NS.with(|c| {
        let prev = c.get();
        assert!(ns >= prev, "virtual clock must be monotonic");
        c.set(ns);
    });
}
```

The swap is compile-time. Default-features build sees the rdtsc path
exactly as today — zero hot-path regression. The `test-server` build
sees a thread-local load (~1-2 ns), which is acceptable for test
infrastructure.

Monotonicity is enforced per-thread. Tests construct a fresh engine
per script, so the thread-local resets cleanly between scripts.

### 3.4 Packetdrill patch stack

`tools/packetdrill-shim/patches/`:

- `0001-backend-in-memory.patch` — replace `tun_alloc/tun_read/tun_write`
  with shim-local in-memory queue ops. packetdrill's scheduler unchanged.
- `0002-time-virtual.patch` — route packetdrill's own `gettimeofday`
  and `clock_gettime(CLOCK_MONOTONIC)` calls through the shim's virtual
  clock, so the script's `+50ms` and the engine's `now_ns` agree.
- `0003-syscall-dispatch.patch` — rewire `socket / connect / write /
  read / close` (and the small set of setsockopts we translate) to
  call through `dpdk_net_test_*`.
- `0004-remove-tolerance-default.patch` — drop `--tolerance_usecs`
  default from 4000 to 0 (we're deterministic; surface any drift as
  a real failure).
- `0005-link-dpdk-net.patch` — add `-ldpdk_net -lpthread -lnuma` to
  the packetdrill linker line; declare the test-FFI entries as
  `extern "C"` on the packetdrill side.

Each patch is kept small (≤ ~100 lines) so upstream rebases are
`git am` exercises rather than merges. Upstream packetdrill's parser,
scheduler, and assertion comparator remain untouched.

**Process model.** Each script runs in its own shim subprocess
(spawned by the runner via `std::process::Command`). This anchors
two invariants:

- The virtual-clock thread-local resets between scripts (fresh
  process → fresh `VIRT_NS`), so the per-thread monotonicity
  assertion never spuriously trips across script boundaries.
- A Rust panic triggers `panic = abort` → SIGABRT → non-zero exit,
  which the runner catches cleanly without corrupting any sibling
  script's state. The existing A6.7 panic-firewall guarantee is
  unchanged.

Subprocess spawn cost is negligible next to the shim's sub-second
per-script runtime. The trade-off is intentional: cleanup-on-failure
is free and the blast radius of one broken script is the one
process that runs it.

### 3.5 Runner crate (`tools/packetdrill-shim-runner/`)

- `Cargo.toml` — binary crate depending on dpdk-net with
  `default-features = false`. Declares its own pass-through
  `test-server` feature that enables the same feature on the
  `dpdk-net` dependency, so the canonical invocation
  `cargo test -p packetdrill-shim-runner --features test-server`
  reaches dpdk-net and dpdk-net-core transitively without ambiguity.
- `build.rs` — invokes `../packetdrill-shim/build.sh` to produce the
  patched binary; fails the build with a clear message if required
  host tools (autoconf, bison, flex, make, pkg-config) are missing.
- `build.sh`:
  1. `git submodule update --init --recursive third_party/packetdrill
     third_party/packetdrill-testcases`
  2. `cd third_party/packetdrill && git am ../../tools/packetdrill-shim/patches/*.patch`
  3. `autoreconf -fi && ./configure CC=clang CFLAGS=... LDFLAGS=...
     && make -j`
  4. Copy the produced binary to `target/packetdrill-shim/packetdrill`.
  Environment variable `DPDK_NET_SHIM_DEBUG=1` switches the dpdk-net
  staticlib build from release to dev profile for local iteration.
- `src/main.rs` — CLI that runs one `.pkt` file through the shim and
  prints pass/fail + any diff. Ergonomics for local debugging.
- `tests/corpus_ligurio.rs` — main A7 gate:
  1. Walk `third_party/packetdrill-testcases/**/*.pkt`.
  2. Apply classifier from `classify/ligurio.toml` (path-prefix /
     regex rules → `runnable | skipped-untranslatable |
     skipped-out-of-scope`, each with a reason string).
  3. For every runnable script: run it through the shim binary,
     assert exit 0; on failure, include stdout/stderr in the report.
  4. Assert `runnable.len() == LIGURIO_RUNNABLE_COUNT`,
     `skipped_untranslatable.len() == LIGURIO_SKIP_UNTRANSLATABLE`,
     `skipped_out_of_scope.len() == LIGURIO_SKIP_OOS` (constants in
     `tests/corpus-counts.rs`).
  5. Parse `tools/packetdrill-shim/SKIPPED.md` — every script in the
     two skipped buckets must have a line entry; orphan skips fail.
- `tests/corpus_shivansh.rs` / `tests/corpus_google.rs` — same shape,
  `#[ignore]` in A7. A8 removes the ignore.
- `tests/our_scripts.rs` — runs `tests/scripts/*.pkt` (includes the
  I-8 regression below and is the home for future
  project-specific scripts).

### 3.6 I-8 multi-segment FIN-piggyback regression

`tests/scripts/i8_multi_seg_fin_piggyback.pkt`:

- Drives the client side through a three-write sequence whose total
  exceeds MSS, with a trailing FIN on the third write.
- Induces a retransmit via a dup-ACK + SACK-block injection.
- Asserts that the retransmitted segment's payload length matches the
  originally-sent data length — not full-mbuf size and not data+1
  (the two forms the pre-A6.6-7 bug could have taken).

This closes the FYI I-8 defer from A6.6-7 (fixed at commit b4e8de9)
with a deterministic scripted regression that runs in CI.

---

## 4. Data flow

Single script run, end-to-end:

```
 Example script excerpt:
   0     socket(...)        = 3
   0.01  connect(3, ...)    = 0
   0.02  > S 0:0(0) win ... <mss 1460, sackOK, nop, nop, TS val 1 ecr 0, wscale 7>
   0.05  < S. 0:0(0) ack 1 win 65535 <mss 1460, sackOK, TS val 100 ecr 1, nop, wscale 7>
   0.06  > . 1:1(0) ack 1 <...>
   0.07  write(3, ..., 100) = 100
   0.08  > P. 1:101(100) ack 1 <...>

 Shim runtime per event:
   set_virt_ns(event.time)
   if event is syscall:
       dpdk_net_test_<op>(...)       implicit pump_until_quiescent
   elif event is inbound packet:
       dpdk_net_test_inject_frame(...)   implicit pump_until_quiescent
   elif event is expected outbound:
       actual = dpdk_net_test_drain_tx_frames(...)
       packetdrill's unchanged comparator asserts match(expected, actual)
```

**TX interception.** Under `test-server`, the final
`rte_eth_tx_burst` call in the engine's TX path is intercepted by a
thin wrapper that (a) copies frame bytes out of the mbuf, (b) pushes
into a thread-local `Vec<Vec<u8>>`, (c) frees the mbuf.
`dpdk_net_test_drain_tx_frames` reads and clears that Vec.

Only single-segment mbufs are emitted — TSO/LRO are off per spec §11
measurement discipline, and the engine already emits one mbuf per
segment. No scatter-gather across the shim boundary.

**RX injection.** `dpdk_net_test_inject_frame(buf, len)` allocates an
RX-pool mbuf (reused from the existing wiring), memcpy's the bytes
in, runs the normal `l2 → l3 → tcp_input` path exactly once, and
returns. The caller's implicit pump drains any TX response.

**Timer firing under virtual time.** `set_virt_ns(T)` updates the
thread-local. The next fake-syscall or `inject_frame` runs the pump,
which calls `timer_wheel.fire_due(T)` and walks the wheel up to T
firing every due RTO / TLP / TIME-WAIT / persist callback. This makes
RTO / TLP / delayed-ACK / TIME-WAIT scripts — previously timing-flaky
on real wall-clock — deterministically testable.

**Server-side flow.** Identical loop; the first event is typically
`socket + listen + accept` rather than `socket + connect`:

- `listen()` → `dpdk_net_test_listen(port)` → returns a listen handle.
- `accept()` → spin-pump until `dpdk_net_test_accept_next(listen)`
  returns `!= -1`. Virtual time only advances when the script
  explicitly progresses, so this is not a wall-clock spin.

The packetdrill script drives the handshake by inbound SYN / ACK
events; the server FSM transitions `LISTEN → SYN_RECEIVED →
ESTABLISHED` inline with those events.

**Error paths.**

- RX mbuf pool exhausted → `inject_frame` returns `-ENOMEM`; runner
  records the script as errored and aborts the run.
- Engine panic → `panic = abort` → SIGABRT; runner catches the
  subprocess exit code. Existing A6.7 panic-firewall guarantee holds.
- Pump exceeds `MAX_PUMP_ITERS` → `-EDEADLK`; runner records as
  errored.
- TX frame mismatch vs script expectation → packetdrill's own
  comparator reports the byte-level delta; runner logs and fails the
  script.

---

## 5. Testing

A7 is test infrastructure itself. "Testing A7" means proving the shim
behaves correctly before running the corpus through it.

### 5.1 Unit / integration tests (Layer A, dpdk-net-core)

- `test_server_listen_accept_established.rs` — hand-rolled in-memory
  rig, no shim yet: listen → inject SYN → drain SYN-ACK → inject final
  ACK → assert ESTABLISHED handle returned from `accept_next`.
- `test_server_passive_close.rs` — inject peer-FIN while ESTABLISHED;
  assert `CLOSE_WAIT → LAST_ACK` after server's own close; assert
  passive close skips TIME_WAIT per RFC 9293 §3.10.
- `test_server_active_close.rs` — server calls `dpdk_net_test_close`;
  assert `FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT` (server drove the close,
  so server holds TIME_WAIT).
- `virt_clock_monotonic.rs` — `set_virt_ns(100)` → `now_ns() == 100`;
  non-monotonic `set_virt_ns` panics; `timer_wheel.fire_due(200)`
  fires exactly the timers scheduled at `≤ 200`.

### 5.2 Shim self-tests (runner crate, Layer B infrastructure)

- `tests/shim_smoke.rs` — build.rs produces the binary; a 5-line
  hand-written `.pkt` with only `connect + write + close` runs to
  exit 0. Proves the whole build graph and shim glue.
- `tests/shim_inject_drain_roundtrip.rs` — listen; inject a SYN;
  drain TX; parse the first frame; assert SYN-ACK with expected
  seq/ack. Pure end-to-end check of the in-memory frame hook.
- `tests/shim_virt_time_rto.rs` — drive a handshake; advance virt-time
  past an RTO deadline without injecting an ACK; drain TX; assert a
  retransmit emitted at exactly `now_ns == deadline`. Proves
  virtual-time determinism for timer-driven paths.

### 5.3 Corpus tests (Layer B gate)

- `tests/corpus_ligurio.rs` — the deliverable. 100% pass on runnable,
  pinned counts on runnable / skipped-untranslatable / skipped-oos,
  orphan-skip check against `SKIPPED.md`.
- `tests/corpus_shivansh.rs` / `tests/corpus_google.rs` — scaffolds
  only; `#[ignore]` in A7, activated by A8.
- `tests/our_scripts.rs` — runs `tests/scripts/*.pkt` including the
  I-8 multi-seg FIN-piggyback regression.

### 5.4 Knob-coverage audit extension

No new behavioral engine knob is introduced (reuse existing
`preset=rfc_compliance`), so `tests/knob-coverage.rs` gets no new
entry. The `test-server` cargo feature is added to
`tests/knob-coverage-informational.txt` with reason: "build-system
flag, no runtime behavioral effect, covered by corpus integration
tests".

### 5.5 Miri / no-alloc / sanitizer audits

- `test-server` paths under miri: matching `#[cfg(miri)]` stubs where
  they touch DPDK mempools. The existing miri CI job extends its
  feature matrix to include `--features test-server`.
- Hot-path alloc audit (existing `no_alloc_hotpath_audit.rs`): unchanged.
  `test-server` paths are explicitly excluded — they are test
  infrastructure, not hot path.
- Panic firewall: unchanged. Shim binary's subprocess model already
  exercises abort-on-panic.
- ASan/UBSan: C++ consumer test unchanged. The shim binary is **not**
  added to the sanitizer matrix — packetdrill is mature and the
  Rust-side of the shim is already covered by miri.

### 5.6 CI wiring

One new job, `packetdrill-shim-ligurio`:

- Runs on the standard Linux runner (no TUN, no sudo, no DPDK hardware).
- Steps: `git submodule update --init` →
  `cargo test -p packetdrill-shim-runner --release --features test-server`.
- Fails on: build failure, any runnable-set script failure, or
  corpus-counts drift.
- Runtime budget: ≤ 10 min for ligurio (in-memory shim runs each
  script in sub-second).

Existing jobs unchanged except: miri matrix adds `--features
test-server`; header-drift CI validates that `dpdk_net_test.h` is
**absent** from the default `include/dpdk_net.h` diff.

### 5.7 End-of-phase review gates

Per `feedback_phase_mtcp_review` and `feedback_phase_rfc_review`, A7
ends with two blocking gate reports, both dispatched in parallel
using opus 4.7:

- `docs/superpowers/reviews/phase-a7-mtcp-compare.md` —
  `mtcp-comparison-reviewer` comparing the new server FSM against
  `mtcp/src/core.c` and `mtcp/src/tcp_out.c` listen/accept code paths.
  Focus: handshake flow, passive-close transitions, listen-slot model
  vs mTCP's bucketed listen table, SYN-RST policy on accept-queue-full.
- `docs/superpowers/reviews/phase-a7-rfc-compliance.md` —
  `rfc-compliance-reviewer` against RFC 9293 §3.5 (handshake), §3.6
  (close), §3.10 (passive open) for the clauses the server FSM
  implements. SHOULDs outside the latency-preset allowlist go to
  Missing-SHOULD.

The `phase-a7-complete` tag is blocked while any unresolved `[ ]`
remains in either report's Must-fix / Missed-edge-cases /
Missing-SHOULD sections, and every Accepted-deviation entry must cite
a concrete spec §6.4 line or memory-file reference.

---

## 6. Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Patch stack becomes unmaintainable as upstream packetdrill churns | Low | Pin submodule SHA; keep patches ≤ ~100 lines each; split if a single patch grows > ~200. Rebases via `git am`. |
| Virtual-clock cfg leaks into default build and regresses `bench_poll_empty` | Low-but-catastrophic-if-it-happens | cfg-swap is compile-time. A plan task runs `bench_poll_empty` at `phase-a7-complete` vs `phase-a6-6-7-complete`; any regression fails the phase sign-off. |
| Single-seg-per-inject assumption masks a multi-seg chain bug | Medium | I-8 regression covers the specific FIN-piggyback chain bug. Broader coverage is A9's FaultInjector + TCP-Fuzz territory. |
| Classifier mis-categorizes scripts → CI flake during initial pass | Medium early / low once stable | First A7 pass iterates classifier + counts + SKIPPED.md atomically per commit. Counts frozen only at end-of-phase. |
| SYN_RCVD accept-queue-full policy diverges from what ligurio scripts expect | Medium | Policy: size-1 queue, extra SYNs → RST. Scripts needing queue > 1 land on SKIPPED.md. mTCP reviewer catches divergence vs mTCP's multi-slot listen table and rules Must-fix or Accepted-divergence. |
| Shim built against LTO-release staticlib is hard to debug | Low | `DPDK_NET_SHIM_DEBUG=1` swaps to dev profile for local iteration. |
| Ligurio scripts assume Linux netns / iproute2 semantics | Medium | "Skipped-out-of-scope" bucket with explicit reasons; reviewed at end-of-phase. |
| Patched packetdrill's autotools build brittle across distros | Low (controlled runner image) | `build.sh` asserts required host tools up front; actionable error messages. |

---

## 7. Open items (resolved inside the plan, not blockers here)

- Exact signature list of `dpdk_net_test_*` entry points — draft in
  §3.2; final set fixed by the first shim self-test that compiles
  end-to-end (missing symbols surface as linker errors).
- Initial classifier rule set — first-pass taxonomy: `SIGIO /
  FIONREAD / SO_RCVLOWAT / MSG_PEEK / TCP_DEFER_ACCEPT / TCP_CORK /
  delayed-ACK timing / explicit IPv6` → untranslatable; everything
  else starts runnable and moves to skipped only with documented
  reason.
- Whether packetdrill's `--dry_run` mode is useful for smoke tests
  (confirmed during first plan task).
- Final values of `LIGURIO_RUNNABLE_COUNT` / `LIGURIO_SKIP_*` — pinned
  empirically during the first full classifier pass.

---

## 8. Success criteria (phase-a7-complete gate)

1. `cargo test -p packetdrill-shim-runner --features test-server`
   passes in CI and locally.
2. `LIGURIO_RUNNABLE_COUNT ≥ 800` (first-pass target; actual floor
   set during classification; goal is maximum coverage with every
   exclusion justified in `SKIPPED.md`).
3. 100% pass rate on the runnable set across 10 consecutive CI runs
   on `phase-a7-complete` (zero flakes).
4. Every skipped script has a one-line `SKIPPED.md` entry with reason.
   Zero orphan skips.
5. Shivansh + google corpus runners compile and report
   `(runnable_count, skipped_count)` locally via
   `cargo test -- --ignored`. A8 flips their gating on.
6. I-8 multi-seg FIN-piggyback regression script passes.
7. `include/dpdk_net.h` has zero new symbols vs `phase-a6-6-7-complete`.
   Header-drift CI is green.
8. `bench_poll_empty` shows no regression vs `phase-a6-6-7-complete`
   baseline.
9. `phase-a7-mtcp-compare.md` and `phase-a7-rfc-compliance.md` land
   clean (zero open `[ ]`).
10. Roadmap row A7 updated to `Complete ✓`; tag `phase-a7-complete`
    points at the final merge commit.

---

## 9. Rough task count

~18-22 tasks (final count decided in the plan), approximately:

1. Submodule `third_party/packetdrill` + pin SHA.
2. Submodule `third_party/packetdrill-testcases` (ligurio) + pin SHA.
3. Add `test-server` cargo feature; verify default build is bit-identical.
4. Virtual-clock cfg-swap + `virt_clock_monotonic.rs`.
5. Server FSM: `test_server.rs` + tcp_input/tcp_output/tcp_conn hunks;
   passive-open handshake test.
6. Server FSM: passive-close test (`CLOSE_WAIT → LAST_ACK`).
7. Server FSM: active-close test (`FIN_WAIT_1 → TIME_WAIT`).
8. Test-only FFI `test_ffi.rs` + `dpdk_net_test.h` cbindgen config +
   production-header exclusion list.
9. TX-intercept shim for `drain_tx_frames` + unit test.
10. Runner crate scaffold + `build.rs`.
11. Patch stack 0001–0005 + `build.sh`.
12. `shim_smoke.rs`.
13. `shim_inject_drain_roundtrip.rs` + `shim_virt_time_rto.rs`.
14. First-pass classifier `classify/ligurio.toml` + `SKIPPED.md` skeleton.
15. `corpus_ligurio.rs` + `corpus-counts.rs` pinning; iterate until
    100% on runnable.
16. `corpus_shivansh.rs` + `corpus_google.rs` scaffolds (`#[ignore]`).
17. I-8 regression script `i8_multi_seg_fin_piggyback.pkt`.
18. CI job `packetdrill-shim-ligurio`; `bench_poll_empty` perf-baseline
    check; knob-coverage informational-whitelist entry; end-of-phase
    mTCP + RFC review dispatch; roadmap update; `phase-a7-complete` tag.

Will likely decompose finer in the implementation plan per
`feedback_per_task_review_discipline`.

---

## 10. References

- Parent spec: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`
  §10.2, §10.12, §11.
- Roadmap row: `docs/superpowers/plans/stage1-phase-roadmap.md`
  L526–546.
- Prior art: Alibaba Luna userspace TCP's packetdrill adaptation
  (three production bugs found via this exact pattern).
- Corpora:
  - `github.com/google/packetdrill` (upstream)
  - `github.com/ligurio/packetdrill-testcases` (A7 CI gate)
  - `github.com/shivansh/TCP-IP-Regression-TestSuite` (wired, A8-gated)
- Feedback memories applied: `feedback_trading_latency_defaults`
  (preset knob, not default), `feedback_observability_primitives_only`
  (no new counters), `feedback_subagent_model` (opus 4.7 for
  reviewers), `feedback_per_task_review_discipline` (per-task two-stage
  review), `feedback_phase_mtcp_review` + `feedback_phase_rfc_review`
  (end-of-phase blocking gates), `feedback_counter_policy` (n/a; no
  new counters), `feedback_performance_first_flow_control` (n/a),
  `reference_tcp_test_suites` (Luna pattern + corpus URLs).
