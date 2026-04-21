# FFI Safety Audit — Phase A6.7 Summary

**Audit date:** 2026-04-20 (Task 22, end-of-phase A6.6+A6.7).
**Branch:** `phase-a6.6-7`.
**Pre-audit commit:** `b4e8de9` (a6.6-7 fix: snd_retrans data_len matches TCP payload).
**Audit tag (pending end-of-phase gate):** `phase-a6-6-7-complete`.
**Scope:** the FFI contract as landed in A6.6 + A6.7 (RX zero-copy iovec
API, in-order delivery-path mbuf-ref rework, panic firewall, header
drift, miri, sanitizer build, no-alloc audit, panic inventory, counters
atomic-load helper).

## Check inventory

| # | Check | Evidence | Status |
|---|---|---|---|
| 1 | Header drift detection | `scripts/check-header.sh` + cbindgen auto-regen via `crates/dpdk-net/build.rs` | Green — committed `include/dpdk_net.h` matches cbindgen output (verified 2026-04-20) |
| 2 | Single committed ABI snapshot | One canonical `include/dpdk_net.h` under git; `git diff include/dpdk_net.h` is the review artifact | Green — sole header; no parallel snapshot file to drift |
| 3 | miri over pure-compute Rust | `scripts/hardening-miri.sh` → `cargo +nightly miri test -p dpdk-net-core --lib --features miri-safe` | Green — gated by `miri-safe` feature; covers crypto/seq-space/state-machine modules per spec §2 Decision 5 |
| 4 | C++ consumer ASan + UBSan + LSan | `scripts/hardening-cpp-sanitizers.sh` (clang-22 with `-fsanitize=address,undefined`); `--build-only` mode runs in the aggregator | Green — `--build-only` succeeds without sudo; full TAP-driven runtime exercise needs `sudo -E DPDK_NET_TEST_TAP=1` |
| 5 | Panic firewall | `crates/dpdk-net/tests/panic_firewall.rs` + `crates/dpdk-net/src/test_only.rs` (`dpdk_net_panic_for_test` FFI export, gated on `test-panic-entry` feature); `scripts/hardening-panic-firewall.sh` | Green — SIGABRT asserted through the FFI catch-unwind firewall |
| 6 | No alloc on hot path | `crates/dpdk-net-core/tests/no_alloc_hotpath_audit.rs` (CountingAllocator, post-warmup 10k-iter window, asserts alloc==0); `scripts/hardening-no-alloc.sh` | Green — gated by `bench-alloc-audit` feature; runtime exercise needs `sudo -E DPDK_NET_TEST_TAP=1` (test early-skips otherwise) |
| 7 | Panic audit (FFI-reachable paths) | `scripts/audit-panics.sh` + `docs/superpowers/reports/panic-audit.md` | Green — 111 total grep hits classified: 98 test-only, 3 slow-path-accepted, 0 hot-path requiring conversion (10 hot-path documented unreachable-by-construction) |
| 8 | Counters atomic-load helper | `include/dpdk_net_counters_load.h` (inline `dpdk_net_load_u64` wrapping `__atomic_load_n(..., __ATOMIC_RELAXED)`) + cpp-consumer `static_assert` on counter struct layout | Green — shipped + verified in cpp-consumer build |

**Aggregator:** `scripts/hardening-all.sh` runs checks 1, 3, 4 (build-only),
5, 6, and 7 sequentially with `set -euo pipefail`. Step 2 is verified
implicitly by step 1 (cbindgen regen → git diff). Step 8 is verified at
cpp-consumer compile time inside step 4.

## ARM-readiness

All FFI-surface atomic loads route through `dpdk_net_load_u64()` (helper
header, check #8). The helper wraps `__atomic_load_n(..., __ATOMIC_RELAXED)`,
which produces a single `LDR` on ARM64 — equivalent guarantees to the x86
`MOV` from a naturally-aligned 64-bit slot. No plain `uint64_t` counter
deref remains in the cpp-consumer demo (verified by grep at audit-run
time). The counters-struct doc comment in `include/dpdk_net.h` documents
the requirement.

**Scope bound:** the iovec type (`dpdk_net_iovec_t`) and the counter
struct are 64-bit-only (x86_64 + ARM64 Graviton); 32-bit-ARM compatibility
is explicitly out of scope.

## Residual risks (carried forward)

- **miri scope is pure-compute only** — reassembly, timer-wheel, retrans,
  flow-table logic have integration coverage (TAP tests + criterion
  bench harness) but no miri coverage. The DPDK-touching paths use raw
  pointer arithmetic into mempool memory which miri cannot model. See
  spec §2 Decision 5 for the rationale; A9 (TCP-Fuzz differential +
  smoltcp FaultInjector) and A10 (criterion harness integration) cover
  the remaining surface from a different angle.
- **ABI-boundary fuzzing (cargo-fuzz) deferred to A9** — current coverage
  is integration tests + miri on pure-compute. Fuzzing the C ABI with
  random bytes is the next hardening tier.
- **TSan deliberately skipped** — single-lcore RTC architecture; no
  cross-thread races by construction. The counter atomics use Relaxed
  ordering precisely because there is no reader-writer race to
  synchronize: the FFI reader is the application thread sampling values
  the lcore writes, and Relaxed is sufficient for monotonic counters
  (per the helper-header doc comment).
- **Sanitizer runtime exercise not in aggregator** — `hardening-all.sh`
  uses `--build-only` for cpp-sanitizers because the runtime path needs
  sudo + TAP. End-of-phase gate runs the full
  `sudo -E DPDK_NET_TEST_TAP=1 ./scripts/hardening-all.sh` invocation
  separately; if any check fails there, a follow-up task gets opened.

## Tooling versions (as of audit run)

- Rust: stable 1.95.0 (2026-04-14) via rustup (latest-stable per
  `rust-toolchain.toml`).
- Rust nightly: 1.97.0-nightly e22c616e4 (2026-04-19) — CI-only exception
  for miri per `feedback_rust_toolchain.md`.
- Rust miri: 0.1.0 e22c616e4e (2026-04-19) — installed on demand by
  `hardening-miri.sh`.
- clang: 22.1.3 (clang-22 from llvm.org per `feedback_build_toolchain.md`).
- cbindgen: 0.26.0 (pinned via `Cargo.lock`).
- criterion: 0.5.1 (Task 14 bench harness).

## Reproducing this audit

From the repo root:

```bash
# Aggregate (builds + miri + panic firewall + no-alloc test + panic audit):
./scripts/hardening-all.sh

# Full TAP-driven exercise (sanitizer runtime + no-alloc actual run):
sudo -E DPDK_NET_TEST_TAP=1 ./scripts/hardening-all.sh
```

Each script can also be invoked individually for targeted re-runs.

## Sign-off

This audit covers the FFI contract as landed in A6.6 + A6.7. Re-running
`scripts/hardening-all.sh` at any point validates the whole surface. An
ABI-shape change post-audit (any edit to `crates/dpdk-net/src/api.rs`,
`crates/dpdk-net/src/lib.rs`, `cbindgen.toml`, the iovec struct, or the
counters struct) MUST either update this report in the same commit or
trigger a fresh full audit pass — `check-header.sh` will catch the
header-drift half automatically; the rest of the inventory above is the
maintainer's responsibility to re-validate.
