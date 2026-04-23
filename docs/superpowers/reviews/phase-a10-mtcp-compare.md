# Phase A10 — mTCP Comparison Review

- **Reviewer:** `mtcp-comparison-reviewer` subagent (opus 4.7)
- **Date:** 2026-04-23
- **mTCP submodule SHA:** `0463aad5ecb6b5bca85903156ce1e314a58efc19` (referenced via `/home/ubuntu/resd.dpdk_tcp/third_party/mtcp/`; not initialized in the A10 worktree but pinned by spec §11.3)
- **Our commit:** `488ddff` (tip of `phase-a10` at review dispatch, branched from `1cf754a`)

## Scope

**Our files reviewed:**
- `tools/bench-vs-mtcp/src/lib.rs`
- `tools/bench-vs-mtcp/src/burst.rs`
- `tools/bench-vs-mtcp/src/maxtp.rs`
- `tools/bench-vs-mtcp/src/dpdk_burst.rs`
- `tools/bench-vs-mtcp/src/dpdk_maxtp.rs`
- `tools/bench-vs-mtcp/src/mtcp.rs`
- `tools/bench-vs-mtcp/src/preflight.rs`
- `tools/bench-vs-mtcp/src/peer_introspect.rs`
- `tools/bench-vs-mtcp/src/main.rs`

**mTCP files referenced** (sibling main-repo checkout):
- `third_party/mtcp/apps/perf/client.c` — mTCP's `iperf`-like throughput tool
- `third_party/mtcp/apps/example/epwget.c` — mTCP HTTP client benchmark
- `third_party/mtcp/mtcp/src/clock.c:12` — `clock_gettime(CLOCK_MONOTONIC, ...)`
- `third_party/mtcp/mtcp/src/config.c:41` — `cc = "reno"` default
- `third_party/mtcp/mtcp/src/dpdk_module.c:375` — single `rte_eth_tx_burst`, no HW TX timestamp
- `third_party/mtcp/mtcp/src/tcp_out.c:271-551` — `snd_una` accounting

**Spec sections in scope:** §11.1 (measurement discipline), §11.5 (grids), §11.5.1 (burst K×G=20), §11.5.2 (maxtp W×C=28), §11.3 (CSV schema), §11.2 (sanity invariants).

---

## Findings

### Must-fix (correctness divergence)

**None for Phase A10 as-landed.** The mTCP runner path is deliberately stubbed (`mtcp::Error::Unimplemented`), so no executable mTCP behavior exists to diverge yet. All must-fix items below are marked for the follow-up task that lands the real mTCP peer; they are recorded here so the gate catches them at that time.

### Missed edge cases (mTCP handles, we don't)

- [ ] **E-1** — CC mode is not pinned on the mTCP side (fairness gap for eventual comparison)
  - mTCP: `third_party/mtcp/mtcp/src/config.c:41` — `g_config.mos->cc = "reno"` is the built-in default; mTCP's perf tool (`apps/perf/client.c`) does not override it.
  - Our equivalent: `tools/bench-vs-mtcp/src/mtcp.rs::MtcpConfig` — no `cc_mode` field. Our dpdk_net runners run with `cc_mode=off` (spec §11.5 requirement), which means when real mTCP lands we'll silently compare our "off" path against mTCP's "reno" path and publish skewed numbers.
  - Impact: moderate — only bites once the stub is replaced, but it is easy to forget because neither the CLI args nor the stub mentions CC mode. Spec §11.5 explicitly mandates `cc_mode=off` on both sides for the burst + maxtp grids.
  - Proposed fix: before landing the real mTCP runner, add a `cc_mode: String` field to `MtcpConfig` with a `validate_config` check that enforces `"off"` (or equivalently "no-cc"/bypass), and document in the tool README that mTCP's config file must be regenerated with `cc = none` (or whatever the chosen mTCP fork exposes as a bypass) before each run. If the chosen mTCP variant does not expose a cc-off mode, either (a) record this as an accepted divergence in the CSV `dimensions_json` or (b) enable Reno on our side too — whichever matches the parent spec's intent.

- [ ] **E-2** — Pre-run MSS / TX-burst agreement check is self-comparing on the mTCP side
  - Our equivalent: `tools/bench-vs-mtcp/src/preflight.rs::check_mss_and_burst_agreement` — current call site in `main.rs` passes `args.mss` for both sides (trivially true).
  - mTCP: `third_party/mtcp/mtcp/src/config.c` — mTCP's MSS is derived from its config file (`mss` knob) and TX burst from `send_thresh` / `send_ring_size`. There is no accessible runtime-introspection surface; values are set at `mtcp_init()` and not exported.
  - Impact: low-to-moderate — the check silently becomes a no-op for the mTCP side. When the numbers diverge from published mTCP benchmarks the human investigating will have no protection from a config skew.
  - Proposed fix: when landing the real mTCP runner, teach `peer_introspect` (or a new `mtcp_introspect`) to read the peer's mTCP config file over SSH (`cat /opt/mtcp/etc/mtcp.conf | grep -E 'mss|send_(thresh|ring_size)'`) and feed those values into `check_mss_and_burst_agreement` rather than passing `args.mss` twice.

### Accepted divergence (intentional — draft for human review)

- **AD-1** — Clock domain divergence: dpdk_net uses TSC; mTCP's own measurement path uses `CLOCK_MONOTONIC`
  - mTCP: `third_party/mtcp/mtcp/src/clock.c:12` — `clock_gettime(CLOCK_MONOTONIC, &now)` is the sole measurement clock in mTCP; `apps/perf/client.c` brackets with `gettimeofday()`.
  - Ours: `tools/bench-vs-mtcp/src/dpdk_burst.rs` + `dpdk_maxtp.rs` — rdtsc via `rte_rdtsc_precise()` for both per-burst and aggregate timing (TSC-at-rte_eth_tx_burst-return, since ENA does not expose TX-HW-timestamp dynfield).
  - Suspected rationale: the dpdk_net tool deliberately stays in TSC-space because the DPDK fast path doesn't cross a syscall boundary. mTCP's `CLOCK_MONOTONIC` path is fine for their batch-grained "1M connections/sec"-style measurements but not for the sub-microsecond bracketing our §11.5.1 burst grid is designed to capture. This is two different measurement primitives, not a bug on either side.
  - Spec/memory reference needed: needs explicit note in spec §11.5 (or a follow-up §11.5.3) saying "dpdk_net brackets with TSC; mTCP brackets with its native clock; comparison is valid because both measure elapsed intervals within a single process, but cross-run absolute timestamps are not comparable." The bench-report tool must label the `t0_abs_ns` / `t1_abs_ns` columns accordingly per-stack.

- **AD-2** — mTCP runner is `Error::Unimplemented` at the end of Phase A10
  - mTCP: the runner is expected to drive a pre-built mTCP peer binary at `/opt/mtcp-peer/bench-peer` on the remote host; that AMI does not exist yet (Plan A AMI-bake is parallel work).
  - Ours: `tools/bench-vs-mtcp/src/mtcp.rs::run_burst_workload` and `run_maxtp_workload` both return `Err(Error::Unimplemented)` after running shape-validation on `MtcpConfig`/`MaxtpConfig`.
  - Suspected rationale: the A10 phase plan Task 12 explicitly mandates that the CSV schema (`dimensions_json.stack = "mtcp"`) and CLI shape must be locked down now so bench-report can handle mTCP rows without schema drift, even though the real runner lands later.
  - Spec/memory reference needed: the A10 plan `docs/superpowers/plans/2026-04-21-stage1-phase-a10-benchmark-harness.md` Task 12 already authorizes this; the phase-completion commit should cite that authorization explicitly. Follow-up task (post-AMI-bake) must flip the stub to a real `ssh` + `bench-peer` invocation and re-run the phase mTCP gate.

- **AD-3** — Sanity invariant check is disabled unless `obs-byte-counters` feature is built
  - mTCP: no direct analog; mTCP's perf tools do not publish the `tcp.tx_payload_bytes` counter we rely on.
  - Ours: `tools/bench-vs-mtcp/src/preflight.rs::check_sanity_invariant` relies on the `tcp.tx_payload_bytes` counter, which in our crate is only compiled in when the `obs-byte-counters` feature is enabled (hot-path counter gated per `feedback_counter_policy.md`).
  - Suspected rationale: hot-path counter policy requires opt-in; the benchmark tool is expected to be the primary `obs-byte-counters` consumer and run with the feature on.
  - Spec/memory reference needed: the harness's README / CI recipe should mandate `cargo build --release --features obs-byte-counters -p bench-vs-mtcp` (or equivalent) so the invariant is actually exercised. Without it, §11.2's sum-over-bursts check degrades to a log message rather than a verification.

### FYI (informational — no action required)

- **I-1** — mTCP's published benchmarks (`apps/perf/client.c`) use `BUF_LEN=8192` and a fixed `--size` arg for bulk transfer; they do not sweep a K×G grid. Our §11.5.1 grid (K = {64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB}, G = {0, 1, 10, 100 ms}) is a deliberate superset. When the real mTCP runner lands, the mTCP side will need a small per-run driver that re-invokes `perf` with each K value rather than running a single transfer — call this out in the follow-up task plan.
- **I-2** — mTCP's `dpdk_module.c:375` does a single `rte_eth_tx_burst` without any TX HW-timestamp handling. This means even on NICs that do expose TX HW-TS (ConnectX-5+), neither stack will be measuring via HW-TS during the A10 runs. The TSC-at-return fallback in our `dpdk_burst.rs` is effectively the only measurement regime both stacks agree on. If the production target ever moves off ENA to a NIC with HW-TS, the spec should state whether to re-enable HW-TS on our side (and accept cross-stack measurement asymmetry) or keep TSC on both for parity.
- **I-3** — `third_party/mtcp/` is NOT initialized inside the A10 worktree; the reviewer sourced the mTCP comparison from the sibling main-repo checkout at the same pinned SHA. No blocker, but a `git submodule update --init --recursive third_party/mtcp` should be added to the A10 worktree setup documentation or the phase-complete commit so future reviewers don't have to chase it.
- **I-4** — `dpdk_maxtp.rs`'s `SndUnaAccumulator` (u32 wrap handling) has no mTCP equivalent — mTCP's `tcp_out.c:271-551` keeps `snd_una` as `uint32_t` and doesn't need a 64-bit accumulator because their published perf tool brackets shorter windows. Our 60-second maxtp window (§11.5.2) at 10+ Gbps absolutely can wrap u32, so this accumulator is correct and is not something to copy from mTCP — noting it for completeness.
- **I-5** — The `Stack::as_dimension()` strings `"dpdk_net"` and `"mtcp"` are stable (`lib.rs:48-53`), and the mTCP stub already writes `"mtcp"` into `dimensions_json.stack` at shape-validation time. The CSV schema guarantee (bench-report groups cleanly, no silent conflation) is in place; this was one of the human's explicit dispatch asks and it is satisfied.

---

## Verdict

**PASS-WITH-ACCEPTED**

Open-checkbox counts:
- Must-fix: 0
- Missed-edge-cases: 2 (E-1 CC-mode fairness, E-2 MSS introspection) — **recommended demoted to follow-up** since the mTCP runner is stubbed and neither can currently produce a meaningful result.
- Accepted-divergence entries: 3 (AD-1 clock domain, AD-2 mTCP stub, AD-3 sanity-invariant feature gate)

### Gate reasoning

No correctness divergence exists in the currently-landing code, because the mTCP execution path is deliberately `Error::Unimplemented`. The `[ ]` checkboxes under Missed-edge-cases (E-1, E-2) are both scoped to "when the real mTCP runner lands" — they are not blocking Phase A10's tag, but they MUST be the first two items of the follow-up task's acceptance criteria, and the follow-up task must re-dispatch the phase mTCP gate before it ships.

### Follow-up actions (before landing real mTCP runner, post-phase-a10)

1. **E-1 acceptance criterion:** `MtcpConfig` gains a `cc_mode: String` field; `validate_config` enforces `"off"`; follow-up task commits a mTCP config file / launch script with `cc = none` (or equivalent per the chosen mTCP fork).
2. **E-2 acceptance criterion:** `peer_introspect` (or new `mtcp_introspect`) reads `mss` / `send_thresh` / `send_ring_size` from the peer's mTCP config via SSH; `check_mss_and_burst_agreement` consumes real values.
3. Re-dispatch `mtcp-comparison-reviewer` before the follow-up task ships.

### Disposition by human

The reviewer's recommendation — demote E-1 and E-2 to follow-up — is **accepted**. Both are scoped to code paths that currently return `Error::Unimplemented` (the mTCP runner stub), so neither produces a meaningful result against the committed A10 deliverable. They are recorded in the **Follow-up actions** section above as acceptance criteria for the next-phase mTCP runner landing; that landing will re-run this gate before shipping.

AD-1 / AD-2 / AD-3 accepted as intentional divergences. Citations:
- **AD-1:** Spec §11.5 notes the dpdk_net / mTCP clock-domain split is expected; bench-report's CSV schema tags rows per-stack via `dimensions_json.stack`, so elapsed-interval comparison is valid while absolute timestamps remain per-stack.
- **AD-2:** A10 plan `docs/superpowers/plans/2026-04-21-stage1-phase-a10-benchmark-harness.md` Task 12 explicitly authorized the `Error::Unimplemented` stub for the MVP. Follow-up task's acceptance criterion: real `ssh` + `/opt/mtcp-peer/bench-peer` invocation, re-run this gate.
- **AD-3:** `feedback_counter_policy` requires hot-path counters be opt-in features. `tcp.tx_payload_bytes` ships under `obs-byte-counters`; bench-nightly enables it when invoking bench-vs-mtcp so the `sum_over_bursts(K) == stack_tx_bytes_counter` invariant fires.

**Gate status:** PASS (conditional on the above follow-up-task commitments). Phase-a10-complete tag is NOT blocked by this review.
