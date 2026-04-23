#!/usr/bin/env bash
# check-perf-host.sh — host-config precondition checker for bench runs.
# Exits 0 if the host matches the pinned bench-latency config; non-zero otherwise.
# Called at the top of every bench run. No --lenient mode in iteration.
set -euo pipefail

fail=0
say() { echo "[check-perf-host] $*"; }
bad() { echo "[check-perf-host] FAIL: $*" >&2; fail=1; }

# CPU model
model=$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo)
[[ "$model" == *"AMD EPYC 7R13"* ]] || bad "cpu model mismatch: got '$model', want EPYC 7R13"
say "cpu model: $model"

# Governor
gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
[[ "$gov" == "performance" ]] || bad "governor not performance: '$gov'"
say "governor: $gov"

# Frequency pinning state (record, don't fail — turbo state noted in CSV)
cur_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo "unknown")
max_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null || echo "unknown")
say "cpu0 freq: cur=$cur_freq max=$max_freq"

# THP
thp=$(cat /sys/kernel/mm/transparent_hugepage/enabled)
[[ "$thp" == *"[never]"* ]] || bad "transparent hugepages not disabled: '$thp'"
say "THP: $thp"

# NMI watchdog
nmi=$(cat /proc/sys/kernel/nmi_watchdog)
[[ "$nmi" == "0" ]] || bad "NMI watchdog enabled: '$nmi'"
say "nmi_watchdog: $nmi"

# Huge pages
if [[ -d /mnt/huge ]]; then
  say "hugepages: /mnt/huge mounted"
else
  bad "hugepages mount /mnt/huge missing"
fi
nr_hp=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo 0)
[[ "$nr_hp" -ge 128 ]] || bad "hugepages-2048kB count low: $nr_hp (need >= 128)"
say "hugepages-2048kB: $nr_hp"

# isolcpus / nohz_full / rcu_nocbs — present in /proc/cmdline
cmd=$(cat /proc/cmdline)
for k in isolcpus nohz_full rcu_nocbs; do
  if [[ "$cmd" == *"$k"* ]]; then
    val=$(echo "$cmd" | grep -oE "${k}=[^ ]+")
    say "$val"
  else
    say "WARNING: $k not in cmdline (dev box — ok for uProf-only workflows, NOT ok for measurement)"
  fi
done

# DPDK version visible
pkg-config --modversion libdpdk 2>/dev/null | sed 's/^/[check-perf-host] libdpdk: /'

if [[ $fail -ne 0 ]]; then
  echo "[check-perf-host] FAIL — host config mismatch; fix before running benchmarks" >&2
  exit 1
fi
echo "[check-perf-host] OK"
exit 0
