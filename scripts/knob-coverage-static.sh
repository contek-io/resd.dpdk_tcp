#!/usr/bin/env bash
# M3 (A8 T17) knob-coverage static drift detector.
#
# Spec §5.2. Cross-checks the hand-maintained field-name registries
# (`ENGINE_CONFIG_FIELD_NAMES` in crates/dpdk-net-core/src/engine.rs and
# `CONNECT_OPTS_FIELD_NAMES` in crates/dpdk-net-core/src/tcp_conn.rs)
# against the knob-coverage.rs scenarios + informational whitelist.
#
# Fails if a new `EngineConfig` / `ConnectOpts` field lands without
# either a scenario in tests/knob-coverage.rs or an entry in
# tests/knob-coverage-informational.txt.
#
# Usage: scripts/knob-coverage-static.sh
# Invoked by CI after the counter-coverage gate.

set -euo pipefail
cd "$(dirname "$0")/.."

timeout 60 cargo test -p dpdk-net-core --test knob-coverage \
  knob_coverage_enumerates_every_behavioral_field

echo "knob-coverage-static: PASS"
