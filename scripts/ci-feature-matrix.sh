#!/usr/bin/env bash
# scripts/ci-feature-matrix.sh
#
# A-HW 8-build CI feature matrix per spec §13. Every feature-off branch
# compiles in exactly one build. Also runs `cargo test` on each config to
# catch regressions.
#
# Usage (from repo root): ./scripts/ci-feature-matrix.sh
# Exits non-zero on first failure.

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

CRATE="-p resd-net-core"
COMMON_FEATURES="obs-poll-saturation"

echo "=== Build 1/8: default features ==="
cargo build --release ${CRATE}

echo "=== Test 1/8: default features ==="
cargo test --release ${CRATE}

echo "=== Build 2/8: --no-default-features ==="
cargo build --release ${CRATE} --no-default-features

echo "=== Test 2/8: --no-default-features (with obs-poll-saturation) ==="
cargo test --release ${CRATE} --no-default-features --features ${COMMON_FEATURES}

ALL_HW=(
  hw-verify-llq
  hw-offload-tx-cksum
  hw-offload-rx-cksum
  hw-offload-mbuf-fast-free
  hw-offload-rss-hash
  hw-offload-rx-timestamp
)

for ((i=0; i<${#ALL_HW[@]}; i++)); do
  off="${ALL_HW[$i]}"
  features="${COMMON_FEATURES}"
  for other in "${ALL_HW[@]}"; do
    if [[ "$other" != "$off" ]]; then
      features="${features},${other}"
    fi
  done
  echo "=== Build $((i+3))/8: --no-default-features --features \"${features}\"  (${off} OFF) ==="
  cargo build --release ${CRATE} --no-default-features --features "${features}"
  echo "=== Test $((i+3))/8: ${off} OFF (knob-coverage + full test suite) ==="
  cargo test --release ${CRATE} --no-default-features --features "${features}"
done

echo ""
echo "=== All 8 builds + tests passed ==="
