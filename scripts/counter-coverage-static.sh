#!/usr/bin/env bash
# Static counter-coverage audit — verifies every name in
# ALL_COUNTER_NAMES has at least one increment site in the current
# cargo feature set, honoring the deferred + feature-gated whitelists.
#
# Usage: counter-coverage-static.sh [--no-default-features | --all-features]
# Invoked twice by ci-counter-coverage.sh; union of the two runs must
# cover every counter.
#
# Mutation patterns recognized (multi-line aware):
#   - <group>.<field>.fetch_add( ... )  / fetch_max / store
#   - counters::inc(&...<field>) / counters::add(&...<field>, ...)
#   - bare inc(&...<field>) / add(&...<field>, ...) after local `use`
#   - &<ref>.<field>[ , ) ] passed to a helper (e.g. and_offload_with_miss_counter)
#
# Chains may span multiple lines (ripgrep --multiline-dotall).
#
# Spec §3.3 + §5.1 rationale:
#   - Deferred counters live in tests/deferred-counters.txt (allowed to
#     be absent in all builds; documents declared-but-unwired fields).
#   - Feature-gated counters live in tests/feature-gated-counters.txt
#     (allowed absent in --no-default-features; required in --all-features).

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <--no-default-features|--all-features>" >&2
  exit 2
fi
FEATURE_FLAG="$1"
case "$FEATURE_FLAG" in
  --no-default-features) BUILD_MODE="default-off" ;;
  --all-features)        BUILD_MODE="all-features" ;;
  *) echo "bad flag: $FEATURE_FLAG" >&2; exit 2 ;;
esac

# Extract ALL_COUNTER_NAMES by running the tiny example that prints it.
# Using the example (rather than parsing Rust with regex) is more correct
# and stays in lockstep with the real constant.
names=$(cargo run -q -p dpdk-net-core "$FEATURE_FLAG" --example counter-names-dump)

# Read whitelists (skip comment + blank lines; first whitespace-separated
# field is the counter name).
deferred=$(grep -v '^\s*#' crates/dpdk-net-core/tests/deferred-counters.txt \
           | awk '{print $1}' | grep -vE '^\s*$' || true)

if [[ "$BUILD_MODE" == "default-off" ]]; then
  # Feature-gated counters are permitted to be absent in this build.
  feature_gated=$(grep -v '^\s*#' crates/dpdk-net-core/tests/feature-gated-counters.txt \
                  | awk '{print $1}' | grep -vE '^\s*$' || true)
else
  feature_gated=""   # all-features build must reach every non-deferred counter
fi

fail=0
while IFS= read -r name; do
  [[ -z "$name" ]] && continue
  if echo "$deferred"      | grep -qxF "$name"; then continue; fi
  if echo "$feature_gated" | grep -qxF "$name"; then continue; fi

  # Translate "tcp.rx_syn" → regex over the field name. Group prefix
  # (e.g., "tcp") does not appear in every call site (some functions
  # take &TcpCounters directly, so the local var is named `counters`
  # without `.tcp.`); field-name match is the reliable anchor.
  field=${name#*.}

  # Multi-line-aware pattern. Rust source uses four mutation shapes:
  #   (a) direct chain ending in fetch_add / fetch_max / store (possibly
  #       broken across lines: `counters\n    .eth\n    .offload_missing_llq\n
  #       .fetch_add(...)`)
  #   (b) inc(&<...>.field) or add(&<...>.field, ...) — with or without
  #       the `counters::` prefix (local `use crate::counters::{inc, add};`
  #       makes the bare form common)
  #   (c) &<...>.field passed as an argument — e.g.,
  #       and_offload_with_miss_counter(...,&counters.eth.offload_missing_rss_hash, ...)
  pattern="(\.${field}\s*\.\s*(fetch_add|fetch_max|store)\b"
  pattern+="|(inc|add)\s*\(\s*&[^,)]*\.${field}\b"
  pattern+="|&[^,)]*\.${field}\s*[,)])"

  # Search the crate source trees (both dpdk-net-core and dpdk-net), but
  # exclude counters.rs itself: it contains the struct declaration,
  # ALL_COUNTER_NAMES string literals, the lookup_counter match arms
  # (`&c.tcp.rx_syn_ack` under a match pattern), and construction-time
  # tests that `.load()` each field. None of those are real increment
  # sites.
  if ! rg -U --multiline -q "$pattern" \
         crates/dpdk-net-core/src/ crates/dpdk-net/src/ \
         --glob '!counters.rs'; then
    echo "MISS: $name (no increment site found in $BUILD_MODE build)" >&2
    fail=1
  fi
done <<< "$names"

if [[ "$fail" -ne 0 ]]; then
  echo "counter-coverage-static: FAIL (unreachable counters in $BUILD_MODE build)" >&2
  exit 1
fi

echo "counter-coverage-static: PASS ($BUILD_MODE build)"
