#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source ~/.cargo/env
cargo test -p dpdk-net --features test-panic-entry --test panic_firewall 2>&1
echo "=== hardening-panic-firewall: PASS ==="
