#!/usr/bin/env bash
# Fetch the project-wide RFC reference set into docs/rfcs/ for the
# rfc-compliance-reviewer subagent. Idempotent — skips RFCs already present.
# The fetched files are committed in-tree and serve as the pinned source of
# truth. Some RFCs in the list are obsoleted (e.g. 793, 1323, 2581); they are
# kept for historical reference. The reviewer should prefer the current RFC
# in each pair unless a specific clause only exists in the older one.
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
OUT_DIR="$REPO_ROOT/docs/rfcs"
mkdir -p "$OUT_DIR"

# --- IP layer ---
IP_RFCS=(
  791   # IPv4
  792   # ICMP
  815   # IP Datagram Reassembly Algorithms
  826   # ARP (not in user-provided list; required for Phase A2)
  1122  # Host requirements (IP + TCP sections)
  1191  # Path MTU Discovery
  # IPv6 family — Stage 2+ scope, vendored for future phases
  2460  # IPv6 (original)
  8200  # IPv6 (current)
  4443  # ICMPv6
  4861  # IPv6 Neighbor Discovery
  4862  # IPv6 SLAAC
)

# --- TCP + transport ---
TCP_RFCS=(
  768   # UDP (companion reference)
  793   # TCP (original; obsoleted by 9293)
  9293  # TCP (2022 consolidated)
  1323  # TCP high-performance extensions (obsoleted by 7323)
  7323  # TCP timestamps + window scale + PAWS
  2018  # TCP SACK
  2581  # TCP congestion control (obsoleted by 5681)
  5681  # TCP congestion control (current)
  3168  # ECN
  3390  # Increasing TCP's Initial Window
  5961  # Blind-data mitigations (not in user list; Stage 1 required per spec §14)
  6191  # TIME-WAIT reduction using timestamps (not in user list; Stage 1 required per spec §14)
  6298  # RTO
  6528  # Defending against sequence-number attacks (ISS)
  6582  # NewReno modification to fast recovery
  6691  # TCP Options and MSS
  7413  # TCP Fast Open
  8985  # RACK-TLP
)

RFCS=("${IP_RFCS[@]}" "${TCP_RFCS[@]}")

for rfc in "${RFCS[@]}"; do
  out="$OUT_DIR/rfc${rfc}.txt"
  if [[ -s "$out" ]]; then
    echo "skip rfc${rfc} (already present)"
    continue
  fi
  url="https://www.rfc-editor.org/rfc/rfc${rfc}.txt"
  echo "fetch $url"
  curl -fsSL --retry 3 --retry-delay 2 "$url" -o "$out"
done

echo "done: $(ls -1 "$OUT_DIR" | wc -l) RFC files in $OUT_DIR"
