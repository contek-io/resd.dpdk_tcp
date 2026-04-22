#!/usr/bin/env bash
# A6.7 top-level hardening aggregator — runs the whole hardening suite
# sequentially. Exits non-zero on first failure.
#
# Steps (in order):
#   1. check-header.sh                      — cbindgen header drift
#   2. hardening-miri.sh                    — miri over pure-compute modules
#   3. hardening-cpp-sanitizers.sh --build-only — ASan+UBSan+LSan compile gate
#   4. hardening-panic-firewall.sh          — SIGABRT firewall test
#   5. hardening-no-alloc.sh                — CountingAllocator hot-path audit
#   6. a7-ligurio-gate.sh                   — packetdrill shim + corpus gate
#   7. a7-perf-baseline.sh (opt-in)         — perf baseline, runs only if A7_RUN_PERF=1
#   8. audit-panics.sh                      — report-only panic inventory
#
# Notes on env requirements:
#   - hardening-miri.sh installs nightly Rust + miri component on first run.
#   - hardening-cpp-sanitizers.sh requires clang-22 (CC/CXX); --build-only
#     skips the runtime exercise so no sudo / TAP / DPDK is needed at the
#     aggregator-only level.
#   - hardening-no-alloc.sh emits a WARN if DPDK_NET_TEST_TAP is not set;
#     the underlying test early-skips, exit code stays 0.
#   - a7-ligurio-gate.sh needs the `test-server` feature to compile but
#     no sudo / TAP / DPDK device; it's the A7 equivalent of the phase-B
#     hardening-* scripts.
#   - a7-perf-baseline.sh is opt-in via A7_RUN_PERF=1 — the default
#     aggregator run doesn't exercise the perf bench because bench_poll_empty
#     isn't authored yet (A7 scope is test-server plumbing, not benches).
#   - The full TAP-driven sanitizer + no-alloc runtime exercise needs
#     `sudo -E DPDK_NET_TEST_TAP=1` and is the responsibility of the
#     end-of-phase gate run, not this aggregator.
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/check-header.sh
./scripts/hardening-miri.sh
./scripts/hardening-cpp-sanitizers.sh --build-only
./scripts/hardening-panic-firewall.sh
./scripts/hardening-no-alloc.sh
./scripts/a7-ligurio-gate.sh || { echo "a7 ligurio gate failed"; exit 1; }
# Perf baseline requires a criterion benchmark + a baseline rev worktree
# root; run only when explicitly requested:
if [ "${A7_RUN_PERF:-0}" = "1" ]; then
  ./scripts/a7-perf-baseline.sh
fi
./scripts/audit-panics.sh > /dev/null  # report-only; outputs not surfaced here

echo ""
echo "=== hardening-all: ALL PASSED ==="
