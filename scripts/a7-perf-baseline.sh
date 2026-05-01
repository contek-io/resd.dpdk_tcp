#!/usr/bin/env bash
# A7 Task 17: perf baseline stub for the test-server rig.
#
# Intent: exercise the virtual-clock + TX-intercept fast path under a
# representative workload (poll-empty sweeps) so A8+ performance work
# has a reference number. This is deliberately a STUB in A7 because
# the target bench (`bench_poll_empty`) hasn't been authored yet —
# the Phase-A7 ticket scope is "land the test-server plumbing", not
# "land the benches that consume it".
#
# Behavior:
#   - If `bench_poll_empty` (as an integration test or a criterion
#     bench) exists, run it.
#   - If it does not, emit a WARN and exit 0. The WARN is visible in
#     the aggregator run so the gap is tracked; it does not fail the
#     phase because A7's acceptance criteria don't require the bench
#     to already be written.
#
# Usage (from repo root): ./scripts/a7-perf-baseline.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source ~/.cargo/env 2>/dev/null || true

# Probe for the bench as an integration test under `--features test-server`.
# `cargo test --test bench_poll_empty` prints an error and exits non-zero
# if the test doesn't exist; we intercept that gracefully.
if cargo test -p dpdk-net-core --features test-server --test bench_poll_empty --no-run 2>/dev/null; then
    echo "=== a7-perf-baseline: running bench_poll_empty ==="
    cargo test -p dpdk-net-core --features test-server --test bench_poll_empty --release -- --nocapture 2>&1
    echo "=== a7-perf-baseline: PASS ==="
else
    echo "WARN: bench_poll_empty not present yet — A7 perf baseline is a stub." >&2
    echo "      A8+ work will author the bench; this script is the wiring slot." >&2
    echo "=== a7-perf-baseline: SKIPPED (stub) ==="
fi
