# A10 bench-nightly A/B-driver debug

Source-level forensics for three reproducible failures surfaced by Phase A10
bench-nightly run `bl16x36lb` (2026-04-23T19:45:13Z) on AWS `c6a.2xlarge`.
Evidence sourced from `/tmp/bench-nightly-run.log` + repo state at branch
`phase-a10`. No AWS/hardware calls made during this analysis.

## Bug 1 — `bench-offload-ab` baseline "connection closed during handshake: err=0"

### Hypothesis
Two compounding defects. (a) Every fresh DPDK process's **first** outbound
connection deterministically picks ephemeral source port **49152**, because
`Engine::new` seeds `last_ephemeral_port = 49151` and the very first call
to `next_ephemeral_port` increments to 49152. On a re-run against the same
peer within the peer-kernel TIME_WAIT window (~60 s), the peer's prior
connection on `49152 ↔ 10001` is still in TIME_WAIT and rejects our new
SYN — in Linux kernel TCP this typically manifests as a challenge-ACK or
a bad-ACK SYN/ACK responding to the new SYN. (b) Our SYN_SENT input
handler then classifies the response as `RstForSynSentBadAck` and raises
`outcome.closed = true`, which engine.rs hard-codes as `err: 0` —
erasing the real error (ECONNRESET / EPROTO) from the bench runner's
visibility.

Evidence chain in log: the **first** bench that opens a DPDK connection
to peer:10001 after a prior test wound down — bench-stress "idle
baseline" (line 156), bench-offload-ab baseline (line 197), and
bench-vs-mtcp (line 227) — all raise the identical `err=0` during
handshake. bench-e2e / bench-vs-linux *succeed* because they run
earlier against the fresh peer-side listener.

### Supporting code refs
- `crates/dpdk-net-core/src/engine.rs:1077-1078` — seed `last_ephemeral_port: Cell::new(49151)`
- `crates/dpdk-net-core/src/engine.rs:1885-1893` — `next_ephemeral_port` (pre-increment, so first = 49152 every time)
- `crates/dpdk-net-core/src/tcp_input.rs:380-413` — four SYN_SENT paths that set `outcome.closed = true` + `TxAction::RstForSynSentBadAck`/`Rst`
- `crates/dpdk-net-core/src/engine.rs:3703-3715` — `if outcome.closed { … Closed { err: 0, … } }` — hard-coded zero errno loses the protocol cause
- `tools/bench-ab-runner/src/workload.rs:218-220` — the user-visible `anyhow::bail!("connection closed during handshake: err={err}")`

### Proposed fix
Two-part; both small, independent.

1. **Randomise ephemeral-port seed** — replace the constant 49151 seed
   with a per-process random byte pair within `[49152, 65535]`, reusing
   the existing `IssGen::secret` (already per-process random):

   ```rust
   // engine.rs around line 1078
   let seed_bytes = &iss_gen.secret[0..2];
   let seed = u16::from_le_bytes([seed_bytes[0], seed_bytes[1]]);
   let init_port = 49152u16.saturating_add(seed % (65535 - 49152));
   last_ephemeral_port: Cell::new(init_port),
   ```

2. **Plumb a close-errno hint through `Outcome`** — add
   `pub close_errno: Option<i32>` to `Outcome` in `tcp_input.rs`;
   populate `Some(-libc::ECONNRESET)` at the `TxAction::Rst*` sites
   (lines 366, 382, 398, 409); propagate to `InternalEvent::Closed.err`
   at engine.rs:3709.

### Verification plan (no AWS)
- **Unit test** in `crates/dpdk-net-core/src/engine.rs` tests module:
  spin up two `Engine::new_for_test()` instances back-to-back in the
  same process; assert their first `next_ephemeral_port()` returns
  differ.
- **Unit test** in `tcp_input.rs` module: feed a `ParsedSegment` that
  triggers `RstForSynSentBadAck` into a SYN_SENT `TcpConn`; assert
  `outcome.close_errno == Some(-libc::ECONNRESET)`.
- **Integration** via existing `tests/ffi-test/tests/ffi_smoke.rs`
  (already wires TAP + full stack): extend to do two sequential
  connects without peer-side waits and assert second connect's ports
  differ.

## Bug 2 — `bench-obs-overhead` obs-none config SIGSEGV (exit 139)

### Hypothesis
Not an `obs-none` code bug. The `bench-ab-runner` binary shipped to the
DUT is **compiled once** (see `scripts/bench-nightly.sh:286-298`) and
reused across every A/B config via `--skip-rebuild`. So
`bench-offload-ab` and `bench-obs-overhead` invoke the *same* ELF with
the same cargo features; `--feature-set obs-none` is metadata, not a
rebuild trigger. The difference that drives Bug 2's distinct SIGSEGV —
when Bug 1 raised a clean handshake-error on the same binary ~0.5 s
earlier — is **residual DPDK shared state on the host**.

Each `bench-ab-runner` process calls `rte_eal_init` (engine.rs:655-719)
then `rte_eal_cleanup` via the `EalGuard` Drop in
`tools/bench-ab-runner/src/main.rs:146-159`. On repeated runs against
stock EAL args (`-l 2-3 -n 4 -a 0000:00:06.0,…`), the hugepage-backed
memzones and rte_rings under `/var/run/dpdk/rte/` and
`/dev/hugepages/rtemap_*` persist across process exit. The 4th
process's `rte_eth_dev_close` (fired from `Drop for Engine` at
engine.rs:5627-5636) OR the subsequent `rte_eal_cleanup` then segfaults
walking a partially-torn-down memzone.

Confirming signal: the SIGSEGV follows **normal** `ena_rx_queue_release`
/ `ena_tx_queue_release` PMD messages (log lines 204-210) —
`rte_eth_dev_close` ran at least far enough to invoke the PMD's queue
release callbacks before segfaulting elsewhere in libdpdk's teardown.

### Supporting code refs
- `scripts/bench-nightly.sh:279` — EAL_ARGS missing `--in-memory --huge-unlink`; these are the documented isolation flags for re-run safety
- `tools/bench-ab-runner/src/main.rs:114-159` — EAL init + `EalGuard` drop ordering (correct, but relies on cleanup actually working)
- `crates/dpdk-net-core/src/engine.rs:5627-5636` — `Drop for Engine` calls `rte_eth_dev_stop` + `rte_eth_dev_close`, does not touch EAL state (correctly separated)
- `tests/ffi-test/tests/ffi_smoke.rs:48` — precedent: our own FFI smoke test already passes `--in-memory` for the same reason
- `tools/bench-offload-ab/src/main.rs:277-322` — spawns `bench-ab-runner` once per A/B config
- `tools/bench-obs-overhead/src/main.rs:306-334` — identical spawn pattern

### Proposed fix
Three-line edit in `scripts/bench-nightly.sh:279`:

```diff
-EAL_ARGS="${EAL_ARGS:--l 2-3 -n 4 -a 0000:00:06.0,large_llq_hdr=1,miss_txc_to=3}"
+EAL_ARGS="${EAL_ARGS:--l 2-3 -n 4 --in-memory --huge-unlink -a 0000:00:06.0,large_llq_hdr=1,miss_txc_to=3}"
```

`--in-memory` keeps DPDK metadata out of `/var/run/dpdk/rte/`;
`--huge-unlink` removes the `rtemap_*` backing files after mmap so they
don't survive `rte_eal_cleanup` failure. Combined, this gives each
`bench-ab-runner` invocation a clean slate regardless of prior-process
cleanup behaviour.

### Verification plan (no AWS)
- **Local reproduction** on this workstation: run the existing
  `tests/ffi-test/tests/ffi_smoke.rs` **twice back-to-back** without
  `--in-memory` (temporary local override) and observe second run
  SIGSEGV; then re-run with `--in-memory --huge-unlink` and observe
  both pass. (`cargo test -p ffi-test --test ffi_smoke --
   --test-threads=1 --nocapture`, 60 s timeout).
- **CI-safe unit test**: add a `#[test]` in a fresh `dpdk-net-core`
  module that spawns two `EngineConfig`-backed `Engine::new` in
  succession on a TAP port (tests/integration already has TAP
  scaffolding) and asserts both return `Ok`.

## Bug 3 — deterministic `errno=-110` cliff near iteration 7051

### Hypothesis
Not conclusively single-rooted, but narrowed to RX mempool exhaustion
rather than event-queue / retrans-budget / timer-wheel growth. The
default `rx_mempool_size` resolves to **8192 mbufs** under stock config
(`max_connections=16`, `recv_buffer_bytes=256 KiB`, `mbuf_data_room=2048`);
the ENA PMD pre-allocates 512 mbufs for the RX ring at `rte_eth_rx_queue_setup`,
leaving **~7680 headroom** for in-flight workload traffic. Observed
cliff values (7051, 7055, 7051) sit within that window once the 500-
iter warmup and initial ARP/SYN transients (~100 mbufs) are accounted
for — which is close enough to the numerical ceiling to indicate a slow
mbuf refcount leak on the RX path (~1 leaked mbuf per request/response
iteration). Symptom: mempool exhausted → `rte_eth_rx_burst` returns 0
→ ACKs stop going out → peer's `write()` eventually blocks / RST's →
our RTO fires → 15× exponential backoff → `force_close_etimedout` at
engine.rs:2404-2408 raises the `InternalEvent::Error { err: -110 }`
that the runner surfaces.

Strongest candidate leak site: the partial-read `try_clone` refcount
bump at engine.rs:4114 — `split_mbuf = front.mbuf.try_clone()` bumps
refcount, the clone gets pushed into `delivered_segments` and dropped
at next-poll `clear()`, but the in-queue remainder retains the original
bump. If the partial-read bookkeeping ever double-bumps or the Drop
path is skipped (e.g. flow-table slot overwrite via handle reuse), the
mbuf refcount stays at 1 after the app is done and the mbuf never
returns to its mempool.

Alternative: AWS-side per-flow accounting; but at observed rates
(~55k pps steady) we're well below the documented c6a.2xlarge per-flow
ceilings, so this is the lower-probability branch.

### Supporting code refs
- `crates/dpdk-net-core/src/engine.rs:880-903` — `rx_mempool_size` formula (default 8192)
- `crates/dpdk-net-core/src/engine.rs:367-369` — `rx_ring_size=512` (a24ef56)
- `crates/dpdk-net-core/src/engine.rs:4084-4135` — `deliver_readable` pop loop + partial-read `try_clone` path
- `crates/dpdk-net-core/src/mempool.rs:219-228` — `MbufHandle::try_clone` (explicit refcount bump)
- `crates/dpdk-net-core/src/mempool.rs:231-241` — `MbufHandle::Drop` (explicit refcount dec)
- `crates/dpdk-net-core/src/engine.rs:2393-2408` — ETIMEDOUT force-close after retrans budget
- `scripts/bench-nightly.sh` commit `671062a` — workaround rationale

### Proposed fix
**First**, add diagnostic before chasing code. Extend the slow-path
counter set with `tcp.rx_mempool_avail` (polled via
`rte_mempool_avail_count` at idle iters in `poll_once`) and
`tcp.mbuf_refcnt_leaks` (bumped by `MbufHandle::Drop` when the
post-dec count is unexpectedly > 0). This flushes to CSV every run
and makes the cliff *prove itself* on the next re-run.

**Then**, conditional fix depending on the counter evidence: if
`rx_mempool_avail` monotonically decreases, audit the `try_clone` +
`delivered_segments.clear()` pairing for non-split paths that
accidentally invoke try_clone (engine.rs:4100-4103 full-pop uses
`pop_front().unwrap()` which transfers the existing refcount — should
NOT leak; but audit for a path that double-`try_clone`s). If
`rx_mempool_avail` stays steady, the cliff is AWS-side and is
workaround-only.

### Verification plan (no AWS)
- **Unit test**: add a `#[test]` that constructs an `Engine`, queries
  the initial `rte_mempool_avail_count`, does 10,000 loopback RTT
  iterations via the existing TAP harness in
  `tests/ffi-test/tests/ffi_smoke.rs`, and asserts post-run
  `rte_mempool_avail_count` is within ±32 of initial. (A leak of 1
  mbuf/iter would drain the pool to ≤0 long before iter 10k — the
  assertion would fail on the second test run).
- **Fault injection**: use the existing `fault_injector.rs` to
  synthesize out-of-order payloads that force `delivered_segments`
  splits on every iteration; assert `rx_mempool_avail` does not
  decrease.
