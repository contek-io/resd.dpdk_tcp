#!/usr/bin/env bash
# CI orchestrator: runs the static audit under both feature sets,
# then the dynamic audit test + obs_smoke under default features.
#
# The `counter-coverage` and `obs_smoke` integration tests land in
# Phase A8 T5–T10; until then `cargo test` will fail because the test
# files do not yet exist. The script is committed early so the CI
# workflow definition can reference it — it goes green once T10
# completes.

set -euo pipefail
cd "$(dirname "$0")/.."

bash scripts/counter-coverage-static.sh --no-default-features
bash scripts/counter-coverage-static.sh --all-features

timeout 240 cargo test -p dpdk-net-core --test counter-coverage --features test-server \
  -- --test-threads=1
timeout 180 cargo test -p dpdk-net-core --test obs_smoke --features test-server

bash scripts/knob-coverage-static.sh

echo "ci-counter-coverage: PASS"
