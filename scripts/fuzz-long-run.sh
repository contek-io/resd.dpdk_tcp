#!/usr/bin/env bash
# A9 per-stage-cut fuzz run. Intended for a dedicated box (EC2 c6i.32xlarge
# or similar); NOT a shared CI runner. Runs all 7 fuzz targets in parallel
# for DURATION seconds each (default 72h = 259200s).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

rustup toolchain install nightly --profile minimal 2>&1 | tail -3
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    cargo install cargo-fuzz
fi
if ! command -v parallel >/dev/null 2>&1; then
    echo "GNU parallel required: apt install -y parallel" >&2
    exit 1
fi

TARGETS=(tcp_options tcp_sack tcp_reassembly tcp_state_fsm tcp_seq header_parser engine_inject)
DURATION=${DURATION:-259200}   # 72 h
DATE=$(date -u +%Y%m%d)
# Absolute so the `cd crates/dpdk-net-core/fuzz` inside parallel's subshells
# still writes logs to the right place.
OUTDIR="$PWD/docs/superpowers/reports/fuzz-long-run-${DATE}"
mkdir -p "$OUTDIR"

# Run all 7 targets in parallel for DURATION seconds each.
# Per-target crashes land in fuzz/artifacts/<target>/.
parallel --jobs "${#TARGETS[@]}" --linebuffer \
    "cd crates/dpdk-net-core/fuzz && \
     cargo +nightly fuzz run {1} -- -max_total_time=${DURATION} -jobs=1 \
       2>&1 | tee ${OUTDIR}/{1}.log" ::: "${TARGETS[@]}"

# Aggregate coverage report per target.
(cd crates/dpdk-net-core/fuzz && \
 for t in "${TARGETS[@]}"; do
     cargo +nightly fuzz coverage "$t" 2>&1 | tail -3 || true
 done)

# Write summary report.
cat > "$OUTDIR/summary.md" <<EOF
# Phase A9 fuzz long-run — $(date -u +%Y-%m-%d)

Duration: ${DURATION}s (~$((DURATION / 3600)) h) per target, ${#TARGETS[@]} parallel.
Box: $(hostname)
Kernel: $(uname -r)
CPU: $(nproc) logical cores

## Crash counts per target

$(for t in "${TARGETS[@]}"; do
    count=$(ls crates/dpdk-net-core/fuzz/artifacts/"$t"/ 2>/dev/null | wc -l)
    echo "- $t: $count"
done)

## Coverage

See crates/dpdk-net-core/fuzz/coverage/<target>/index.html per target.

## Artifacts

Per-target crash corpora in crates/dpdk-net-core/fuzz/artifacts/.
Per-target stdout logs in $OUTDIR/<target>.log.
EOF

echo "Long-run complete. Summary in $OUTDIR/summary.md"
