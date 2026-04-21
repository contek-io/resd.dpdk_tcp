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

echo "=== hardening-miri: PASS ==="
