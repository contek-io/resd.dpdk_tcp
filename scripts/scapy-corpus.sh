#!/usr/bin/env bash
# Regenerate all Scapy adversarial corpus pcaps + manifests under
# tools/scapy-corpus/out/ (gitignored).
#
# Seeds live in tools/scapy-corpus/seeds.txt; each script seeds its own RNG
# so output is deterministic for a fixed seeds.txt + Scapy version.
#
# Consumed by tools/scapy-fuzz-runner/ (T22) via the test-inject hook.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! python3 -c "import scapy" >/dev/null 2>&1; then
    echo "ERROR: Scapy not importable. Install via: pip install --user scapy" >&2
    exit 1
fi

mkdir -p tools/scapy-corpus/out

for script in tools/scapy-corpus/scripts/*.py; do
    echo ">>> $script"
    python3 "$script"
done

echo
echo "Scapy corpus regenerated under tools/scapy-corpus/out/"
ls -lh tools/scapy-corpus/out/
