#!/usr/bin/env bash
# A7 Task 17: CI gate for the packetdrill shim + ligurio corpus.
#
# Runs the test-server / shim-runner slice that together constitute the
# A7 "shim works + corpus counts are pinned" contract. Deliberately
# does NOT invoke `cargo test -p dpdk-net-core --features test-server`
# wholesale: the test-server feature swaps `clock::now_ns` for a
# thread-local virtual clock, which means tests written before A7
# existed (e.g., `iss_monotonic_across_reconnect_same_tuple` in
# tcp_rack_rto_retrans_tap.rs) that spin on real wall-clock advancement
# will hang. We enumerate the A7-specific integration tests by name
# instead — every test in this list is guarded by
# `#![cfg(feature = "test-server")]` at file scope.
#
# Steps (in order):
#
#   1. dpdk-net-core test-server integration slice. Covers the server
#      FSM (T5/T6/T7), the test-only FFI + TX intercept (T4/T8), the
#      virtual clock (T3), and the I-8 multi-seg FIN-piggyback
#      regression (T16).
#
#   2. packetdrill-shim-runner tests under the same `test-server`
#      feature. Covers the shim-runner classifier (T13), the corpus
#      runner scaffold (T14/T15), and the two shim direct self-tests
#      (T12: shim_inject_drain_roundtrip + shim_virt_time_rto). The
#      T15 pinned-counts assertion inside `ligurio_runnable_subset_passes`
#      (corpus_ligurio.rs) fails the gate if the classifier's verdict
#      distribution drifts from the committed counts.rs values.
#
#   3. dry-classify binary build pass. Rebuilds the classifier binary
#      from scratch as a smoke test — the pinned-counts assertion
#      lives in step 2 above; this step is just a compile check.
#
# This script is the entry the A7 end-of-phase gate (T18) wraps into
# hardening-all.sh. Each step exits non-zero on first failure.
#
# Usage (from repo root): ./scripts/a7-ligurio-gate.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source ~/.cargo/env 2>/dev/null || true

echo "=== a7-ligurio-gate: step 1/3 — dpdk-net-core test-server slice ==="
# Enumerate A7-specific integration tests explicitly; see header comment
# for why we don't run the full integration-test set under test-server.
cargo test -p dpdk-net-core --features test-server \
    --test test_server_feature_compiles \
    --test test_server_listen_accept_established \
    --test test_server_passive_close \
    --test test_server_active_close \
    --test virt_clock_monotonic \
    --test i8_multi_seg_fin_piggyback \
    2>&1

echo "=== a7-ligurio-gate: step 2/3 — packetdrill-shim-runner --features test-server ==="
cargo test -p packetdrill-shim-runner --features test-server 2>&1

echo "=== a7-ligurio-gate: step 3/3 — dry-classify binary build ==="
cargo build -p packetdrill-shim-runner --features test-server --bin dry-classify 2>&1

echo ""
echo "=== a7-ligurio-gate: ALL PASSED ==="
