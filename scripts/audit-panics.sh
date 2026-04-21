#!/usr/bin/env bash
# A6.7 panic audit: greps for panic!/unwrap/expect/unchecked_* in
# FFI-reachable paths and classifies each hit. Hot-path findings must
# be converted to errno or documented unreachable-by-construction.
#
# Output is the raw grep — manual classification lives in
# docs/superpowers/reports/panic-audit.md.
set -euo pipefail
cd "$(dirname "$0")/.."

FILES_FFI=$(find crates/dpdk-net/src -name '*.rs' -not -path '*/target/*')
FILES_CORE=$(find crates/dpdk-net-core/src -name '*.rs' -not -path '*/target/*')

echo "# Panic audit — $(date -Iseconds)"
echo ""
echo "Searches for: panic!, .unwrap(), .expect(, unchecked_"
echo ""
echo "## FFI crate (crates/dpdk-net)"
grep -n 'panic!\|\.unwrap()\|\.expect(\|unchecked_' $FILES_FFI || echo "(none)"
echo ""
echo "## Core crate (crates/dpdk-net-core)"
grep -n 'panic!\|\.unwrap()\|\.expect(\|unchecked_' $FILES_CORE || echo "(none)"
