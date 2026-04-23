#!/usr/bin/env bash
# A9 fuzz smoke: run each cargo-fuzz target for a short fixed budget.
# Intended for per-merge CI (not the 72h stage-cut run, which is scripts/fuzz-long-run.sh).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Ensure nightly toolchain for the fuzz/ subdir.
rustup toolchain install nightly --profile minimal 2>&1 | tail -3
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    cargo install cargo-fuzz
fi

TARGETS=(tcp_options tcp_sack tcp_reassembly tcp_state_fsm tcp_seq header_parser engine_inject)
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
echo "PASS: all ${#TARGETS[@]} fuzz targets clean for ${TIME}s each"
