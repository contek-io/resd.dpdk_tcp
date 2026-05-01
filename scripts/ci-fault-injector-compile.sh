#!/usr/bin/env bash
# A9 fault-injector compile gate. Exists as its own file so Jenkins can
# wire a named stage to it without embedding a cargo line in the pipeline.
#
# This stage catches compile-time regressions only; runtime UAF detection
# for `inject_rx_chain` / `FaultInjector::process` requires sanitizers on a
# TAP-capable host and is covered by hardening-cpp-sanitizers.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo check -p dpdk-net-core --features fault-injector

echo "=== ci-fault-injector-compile: PASS ==="
