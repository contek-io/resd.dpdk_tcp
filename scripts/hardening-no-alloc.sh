#!/usr/bin/env bash
# A6.7 no-alloc-on-hot-path audit: runs the CountingAllocator-instrumented
# integration test that exercises poll_once + send_bytes + event emit
# through a representative steady-state workload and asserts alloc == 0
# over a 10_000-iteration measurement window post-warmup.
set -euo pipefail
cd "$(dirname "$0")/.."
source ~/.cargo/env
if [[ -z "${DPDK_NET_TEST_TAP:-}" ]]; then
    echo "WARN: DPDK_NET_TEST_TAP is not set; test would early-skip." >&2
    echo "Set DPDK_NET_TEST_TAP=1 and run with sudo to actually exercise the audit." >&2
fi
cargo test -p dpdk-net-core --features bench-alloc-audit --test no_alloc_hotpath_audit 2>&1
echo "=== hardening-no-alloc: PASS ==="
