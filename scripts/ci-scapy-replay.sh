#!/usr/bin/env bash
# A9 Scapy adversarial corpus replay. Regenerates the pcap corpus via
# Scapy, then feeds it through scapy-fuzz-runner via the test-inject hook.
#
# Requires Python3 + Scapy on the agent (see ci-install-deps.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

bash scripts/scapy-corpus.sh
cargo run --release -p scapy-fuzz-runner -- --corpus tools/scapy-corpus/out/

echo "=== ci-scapy-replay: PASS ==="
