#!/usr/bin/env bash
# A6.7 miri job: runs miri over pure-compute dpdk-net-core modules.
# Covers UB, aliasing, integer-overflow hazards in crypto/seq-space/state-machine logic.
# Excludes sys::*-touching modules (they would require DPDK allocations miri cannot do).
#
# Nightly Rust is a CI-only exception to the latest-stable rule — miri
# genuinely requires nightly. See feedback_rust_toolchain.md.
#
# Usage (from repo root): ./scripts/hardening-miri.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
    rustup toolchain install nightly
fi
rustup component add miri --toolchain nightly

cargo +nightly miri test -p dpdk-net-core --lib --features miri-safe 2>&1

# A7 T17: matrix entry for the `test-server` feature. The test-server
# path adds `inject_rx_frame` / `drain_tx_frames` / virt-clock surfaces
# that compile into the lib build; running miri over them gates against
# UB regressions in those paths when the feature is enabled. Kept as its
# own invocation (not merged with the miri-safe line above) because the
# two feature sets are orthogonal: `miri-safe` excludes DPDK FFI,
# `test-server` adds test-only FFI, and miri resolves features
# additively per invocation — a single `--features miri-safe,test-server`
# would pull in whichever set the crate's feature resolver merged. One
# line per feature keeps the semantic boundaries explicit.
cargo +nightly miri test -p dpdk-net-core --lib --features "miri-safe test-server" 2>&1

echo "=== hardening-miri: PASS ==="
