#!/usr/bin/env bash
# Jenkins agent bootstrap. Consolidates the apt-get + rustup + pip install
# steps that each deleted GHA workflow used to duplicate inline.
#
# Idempotent: apt-get re-installs are fine, `rustup toolchain install` is a
# no-op if the toolchain is already present, `cargo install cargo-fuzz` is
# guarded by `command -v`.
#
# Usage (on a fresh Jenkins agent): bash scripts/ci-install-deps.sh
set -euo pipefail
cd "$(dirname "$0")/.."

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    libdpdk-dev pkg-config clang libclang-dev \
    libnuma-dev ripgrep bison flex make gcc \
    python3-pip parallel

pkg-config --modversion libdpdk

if ! command -v rustup >/dev/null 2>&1; then
    echo "ERROR: rustup not installed. Install from https://rustup.rs first." >&2
    exit 1
fi
rustup toolchain install stable --profile minimal
rustup toolchain install nightly --profile minimal
rustup component add miri --toolchain nightly

if ! command -v cargo-fuzz >/dev/null 2>&1; then
    cargo install cargo-fuzz
fi

python3 -m pip install --user scapy

echo "=== ci-install-deps: PASS ==="
