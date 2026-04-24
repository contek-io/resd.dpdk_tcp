#!/usr/bin/env bash
# Nightly fuzz job — NOT part of per-merge. Runs the same per-target
# crash-detection loop as fuzz-smoke.sh with a fatter per-target budget
# (~10 min × 7 targets ≈ 70 min total).
#
# Intended to be scheduled by Jenkins as a separate nightly job. The 72h
# stage-cut run lives in scripts/fuzz-long-run.sh and stays out-of-band.
set -euo pipefail
cd "$(dirname "$0")/.."

export TIME=${TIME:-600}
exec bash scripts/fuzz-smoke.sh
