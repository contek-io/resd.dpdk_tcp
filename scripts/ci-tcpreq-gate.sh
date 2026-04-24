#!/usr/bin/env bash
# Phase A8 Task 23 (spec §6.1). Runs the 4 tcpreq-runner probes
# (M4 workstream, Tasks 18-21):
#   - probe_mss       (MSS honors peer advertisement)
#   - probe_reserved  (reserved bit set -> RST / drop)
#   - probe_urgent    (URG treatment; AD-A8-urg-dropped documented deviation
#                      asserted as PASS)
# Gate rule per spec §6.1: 100% pass. URG probe passes by asserting the
# documented deviation.
set -euo pipefail
cd "$(dirname "$0")/.."

timeout 300 cargo test -p tcpreq-runner -- --test-threads=1

echo "=== ci-tcpreq-gate: PASS ==="
