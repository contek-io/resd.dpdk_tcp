#!/usr/bin/env bash
# check-bench-preconditions.sh — spec §4.1 + §4.2 (A10 T3).
#
# Canonical preconditions checker for the Stage 1 benchmark harness.
# Emits one JSON object to stdout per invocation:
#
#   {
#     "mode": "strict|lenient",
#     "checks": {
#       "isolcpus":          {"pass": true, "value": "2-7"},
#       ...
#       "wc_active":         {"pass": true, "value": "deferred"}
#     },
#     "overall_pass": true
#   }
#
# The AMI has an identical copy at /usr/local/bin/check-bench-preconditions
# (synced from resd.aws-infra-setup/assets/ at sister-plan T6).
#
# Exit codes:
#   strict  mode, overall_pass=false -> exit 1
#   strict  mode, overall_pass=true  -> exit 0
#   lenient mode, any outcome        -> exit 0
#
# Every check is error-resilient: missing files/tools record
# "fail|<reason>" (or "pass|skipped" for ENA-iface checks on a dev host
# with no ENA NIC), never aborting.
#
# The wc_active probe is DEFERRED — the real check is performed
# in-process by bench-ab-runner after engine bring-up (spec §4.1).
set -euo pipefail

MODE="strict"
JSON_FMT=1

while (($#)); do
  case "$1" in
    --mode)
      MODE="${2:-strict}"
      shift 2
      ;;
    --no-json)
      JSON_FMT=0
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "$MODE" != "strict" && "$MODE" != "lenient" ]]; then
  echo "invalid --mode: $MODE (want strict|lenient)" >&2
  exit 2
fi

declare -A RESULTS

# Best-effort ENA-style interface lookup — first device whose name
# starts with "en" or is literally eth1. Returns empty string when
# none is present (dev-host path; callers must treat as "skipped").
detect_ena_iface() {
  ip -o link 2>/dev/null | awk -F': ' '/ en|eth1/ {print $2; exit}'
}

check_isolcpus() {
  local v
  v=$(cat /sys/devices/system/cpu/isolated 2>/dev/null || true)
  if [[ -n "$v" ]]; then
    RESULTS[isolcpus]="pass|$v"
  else
    RESULTS[isolcpus]="fail|empty"
  fi
}

check_nohz_full() {
  local v
  v=$(cat /sys/devices/system/cpu/nohz_full 2>/dev/null || true)
  if [[ -n "$v" ]]; then
    RESULTS[nohz_full]="pass|$v"
  else
    RESULTS[nohz_full]="fail|empty"
  fi
}

check_rcu_nocbs() {
  local v
  v=$(grep -oE 'rcu_nocbs=[^ ]*' /proc/cmdline 2>/dev/null | sed 's/rcu_nocbs=//' || true)
  if [[ -n "$v" ]]; then
    RESULTS[rcu_nocbs]="pass|$v"
  else
    RESULTS[rcu_nocbs]="fail|empty"
  fi
}

check_governor() {
  local g
  g=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true)
  if [[ "$g" == "performance" ]]; then
    RESULTS[governor]="pass|performance"
  else
    RESULTS[governor]="fail|${g:-unreadable}"
  fi
}

check_cstate_max() {
  # Allow only C0 + C1 to be enabled; state[2-9]/disable must read "1"
  # on every CPU. Missing files (no cpuidle states beyond C1) counts
  # as pass — there is nothing deeper to disable.
  local bad=0
  local f
  # nullglob avoids a literal-glob iteration when no matches exist.
  shopt -s nullglob
  for f in /sys/devices/system/cpu/cpu*/cpuidle/state[2-9]/disable; do
    if [[ "$(cat "$f" 2>/dev/null || echo 0)" != "1" ]]; then
      bad=1
    fi
  done
  shopt -u nullglob
  if [[ $bad -eq 0 ]]; then
    RESULTS[cstate_max]="pass|C1"
  else
    RESULTS[cstate_max]="fail|deep-cstate-enabled"
  fi
}

check_tsc_invariant() {
  if grep -q 'constant_tsc' /proc/cpuinfo 2>/dev/null \
     && grep -q 'nonstop_tsc' /proc/cpuinfo 2>/dev/null; then
    RESULTS[tsc_invariant]="pass|"
  else
    RESULTS[tsc_invariant]="fail|not-invariant"
  fi
}

check_coalesce_off() {
  local iface
  iface=$(detect_ena_iface)
  if [[ -z "$iface" ]]; then
    RESULTS[coalesce_off]="pass|skipped"
    return
  fi
  if ethtool -c "$iface" 2>/dev/null | grep -q "^rx-usecs: 0"; then
    RESULTS[coalesce_off]="pass|$iface"
  else
    RESULTS[coalesce_off]="fail|$iface:nonzero-usecs"
  fi
}

check_tso_off() {
  local iface
  iface=$(detect_ena_iface)
  if [[ -z "$iface" ]]; then
    RESULTS[tso_off]="pass|skipped"
    return
  fi
  if ethtool -k "$iface" 2>/dev/null | grep -q "^tcp-segmentation-offload: off"; then
    RESULTS[tso_off]="pass|$iface"
  else
    RESULTS[tso_off]="fail|$iface:tso-on"
  fi
}

check_lro_off() {
  local iface
  iface=$(detect_ena_iface)
  if [[ -z "$iface" ]]; then
    RESULTS[lro_off]="pass|skipped"
    return
  fi
  if ethtool -k "$iface" 2>/dev/null | grep -q "^large-receive-offload: off"; then
    RESULTS[lro_off]="pass|$iface"
  else
    RESULTS[lro_off]="fail|$iface:lro-on"
  fi
}

check_rss_on() {
  local iface
  iface=$(detect_ena_iface)
  if [[ -z "$iface" ]]; then
    RESULTS[rss_on]="pass|skipped"
    return
  fi
  if ethtool -x "$iface" 2>/dev/null | grep -q "indirection table"; then
    RESULTS[rss_on]="pass|$iface"
  else
    RESULTS[rss_on]="fail|$iface:no-rss"
  fi
}

check_thermal_throttle() {
  # Snapshot of past throttle counts. Always passes here — the
  # harness re-reads at run end and does its own delta check.
  local throttles
  throttles=$(
    cat /sys/devices/system/cpu/cpu*/thermal_throttle/*_throttle_count 2>/dev/null \
      | awk '{s+=$1} END{print s+0}'
  )
  RESULTS[thermal_throttle]="pass|${throttles:-0}"
}

check_hugepages_reserved() {
  local pages
  pages=$(awk '/^HugePages_Total:/ {print $2}' /proc/meminfo 2>/dev/null || true)
  pages="${pages:-0}"
  if [[ "$pages" =~ ^[0-9]+$ && "$pages" -ge 1024 ]]; then
    RESULTS[hugepages_reserved]="pass|$pages"
  else
    RESULTS[hugepages_reserved]="fail|$pages"
  fi
}

check_irqbalance_off() {
  # systemctl may be absent (non-systemd host) — treat as pass
  # (nothing to disable) rather than tripping the whole harness.
  if ! command -v systemctl >/dev/null 2>&1; then
    RESULTS[irqbalance_off]="pass|no-systemd"
    return
  fi
  if systemctl is-active irqbalance >/dev/null 2>&1; then
    RESULTS[irqbalance_off]="fail|active"
  else
    RESULTS[irqbalance_off]="pass|"
  fi
}

check_wc_active() {
  # Deferred: the real Write-Combining probe requires the DPDK engine
  # to be running against the ENA BAR, and so is performed in-process
  # by bench-ab-runner between engine bring-up and workload start
  # (spec §4.1). We emit pass|deferred so strict-mode pre-run doesn't
  # fail on an inherently-out-of-scope probe.
  RESULTS[wc_active]="pass|deferred"
}

# Run every check. Each is already internally error-resilient; the
# trailing `|| true` belts-and-braces against any unexpected `set -e`
# tripwire inside a check body.
for fn in \
  check_isolcpus \
  check_nohz_full \
  check_rcu_nocbs \
  check_governor \
  check_cstate_max \
  check_tsc_invariant \
  check_coalesce_off \
  check_tso_off \
  check_lro_off \
  check_rss_on \
  check_thermal_throttle \
  check_hugepages_reserved \
  check_irqbalance_off \
  check_wc_active
do
  "$fn" || RESULTS["${fn#check_}"]="fail|internal-error"
done

# Escape a string for inclusion inside a JSON double-quoted literal.
# We only have to worry about backslash and double-quote in practice
# (our values are interface names, CPU lists, integers); control chars
# are not expected but are stripped defensively.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  # Strip any remaining control bytes (< 0x20) — they would produce
  # an invalid JSON string.
  s=$(printf '%s' "$s" | tr -d '\000-\037')
  printf '%s' "$s"
}

# Emit the JSON object and compute overall_pass.
overall_pass=true
ORDER=(
  isolcpus
  nohz_full
  rcu_nocbs
  governor
  cstate_max
  tsc_invariant
  coalesce_off
  tso_off
  lro_off
  rss_on
  thermal_throttle
  hugepages_reserved
  irqbalance_off
  wc_active
)

if [[ $JSON_FMT -eq 1 ]]; then
  printf '{'
  printf '"mode":"%s",' "$MODE"
  printf '"checks":{'
  first=1
  for k in "${ORDER[@]}"; do
    v="${RESULTS[$k]-fail|missing}"
    passed="${v%%|*}"
    value="${v#*|}"
    [[ "$passed" == "pass" ]] || overall_pass=false
    if [[ $first -eq 0 ]]; then
      printf ','
    fi
    first=0
    if [[ "$passed" == "pass" ]]; then
      pass_bool=true
    else
      pass_bool=false
    fi
    printf '"%s":{"pass":%s,"value":"%s"}' \
      "$k" "$pass_bool" "$(json_escape "$value")"
  done
  printf '},'
  printf '"overall_pass":%s' "$overall_pass"
  printf '}\n'
else
  # Human-readable fallback for --no-json. Still computes overall_pass
  # so the exit code logic below works.
  for k in "${ORDER[@]}"; do
    v="${RESULTS[$k]-fail|missing}"
    passed="${v%%|*}"
    value="${v#*|}"
    [[ "$passed" == "pass" ]] || overall_pass=false
    printf '%-20s %-4s %s\n' "$k" "$passed" "$value"
  done
  printf 'overall_pass=%s mode=%s\n' "$overall_pass" "$MODE"
fi

if [[ "$MODE" == "strict" && "$overall_pass" == "false" ]]; then
  exit 1
fi
exit 0
