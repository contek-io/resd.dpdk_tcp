#!/usr/bin/env bash
# Phase A8 Task 23 (spec §6.1). Shim-driven corpus gates: ligurio + shivansh
# + google packetdrill corpora. Each corpus test pins its runnable count and
# fails on any script that is classified runnable but errors at runtime
# (orphan-skip check).
#
# S2 adds server-mode support via patch 0006-server-drain.patch and the
# smoke_server_mode.rs test; this script runs that smoke first.
#
# Shim build (tools/packetdrill-shim/build.sh) uses git/bison/flex/make
# plus libdpdk to patch + compile the upstream google/packetdrill source
# against libdpdk_net.a (dpdk-net crate built with the test-server
# feature).
set -euo pipefail
cd "$(dirname "$0")/.."

bash tools/packetdrill-shim/build.sh

timeout 300 cargo test -p packetdrill-shim-runner \
    --features test-server --test smoke_server_mode

timeout 900 cargo test -p packetdrill-shim-runner \
    --features test-server --test corpus_ligurio

timeout 900 cargo test -p packetdrill-shim-runner \
    --features test-server --test corpus_shivansh

timeout 900 cargo test -p packetdrill-shim-runner \
    --features test-server --test corpus_google

echo "=== ci-packetdrill-corpus: PASS ==="
