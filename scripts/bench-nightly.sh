#!/usr/bin/env bash
# scripts/bench-nightly.sh — end-to-end A10 nightly bench orchestrator.
#
# Spec §12 / §14 end-to-end pipeline:
#   1. Prereq check (resd-aws-infra, cargo, jq, ssh, aws creds).
#   2. Provision bench-pair fleet (DUT + peer) via resd-aws-infra.
#   3. cargo build --release --workspace.
#   4. SCP compiled bench binaries + preconditions checker + peer binaries
#      to DUT and peer hosts (under /tmp).
#   5. Start peer echo-server (bench-e2e/bench-stress/bench-vs-mtcp) +
#      linux-tcp-sink (bench-vs-linux) on the peer host.
#   6. Run on DUT: bench-e2e, bench-stress, bench-vs-linux (mode A+B),
#      bench-offload-ab, bench-obs-overhead, bench-vs-mtcp (burst+maxtp).
#   7. Run locally: cargo bench -p bench-micro + summarize.
#   8. Pull CSVs back to target/bench-results/<timestamp>/.
#   9. Invoke bench-report → JSON + HTML + Markdown.
#  10. Teardown fleet (trap EXIT so partial runs still deprovision).
#
# Entry points:
#   ./scripts/bench-nightly.sh                  # full orchestrated run
#   ./scripts/bench-nightly.sh --dry-run        # prereq check + plan only
#   ./scripts/bench-nightly.sh --help
#
# Prerequisite env vars:
#   OUT_DIR        (optional) output dir; default target/bench-results/<ts>/
#   MY_CIDR        (optional) operator /32 for SSH allow-list; default
#                  auto-discovered via ifconfig.me
#   NIC_MAX_BPS    (optional) peer NIC line rate for bench-vs-mtcp
#                  saturation guard; default 100 Gbps (c6in.metal ENA)
#   SKIP_TEARDOWN  (optional) set to 1 to skip the trap EXIT teardown;
#                  useful for debugging failed runs
#
# Runbook: see scripts/bench-nightly.md.
set -euo pipefail

# ---------------------------------------------------------------------------
# Arg parsing — dry-run + help only; per-bench knobs come from env.
# ---------------------------------------------------------------------------
DRY_RUN=0
while (($#)); do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      sed -n '2,33p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1 (try --help)" >&2
      exit 2
      ;;
  esac
done

OUT_DIR="${OUT_DIR:-target/bench-results/$(date -u +%Y-%m-%dT%H-%M-%SZ)}"
mkdir -p "$OUT_DIR"

log() { echo "[bench-nightly] $*" >&2; }

# ---------------------------------------------------------------------------
# [1/11] Prereq check — fail fast if anything required is missing.
# ---------------------------------------------------------------------------
log "[1/11] prereq check"

REQUIRED_BINS=(resd-aws-infra cargo jq ssh scp curl aws)
missing=0
for bin in "${REQUIRED_BINS[@]}"; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    log "  MISSING: $bin"
    missing=$((missing + 1))
  fi
done
if ((missing > 0)); then
  log "prereq check failed — $missing binary/binaries missing"
  log "resd-aws-infra: install sister project from resd.aws-infra-setup"
  exit 2
fi

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  log "AWS credentials not configured (aws sts get-caller-identity failed)"
  exit 2
fi

log "  all prereqs present"

# Dry-run exits here — the caller just wanted the prereq gate + plan.
if ((DRY_RUN)); then
  log "--dry-run: prereq check OK; would now provision bench-pair"
  log "--dry-run: output dir would be $OUT_DIR"
  rmdir "$OUT_DIR" 2>/dev/null || true
  exit 0
fi

# ---------------------------------------------------------------------------
# [2/11] Provision bench-pair fleet via resd-aws-infra.
# ---------------------------------------------------------------------------
log "[2/11] provisioning bench-pair fleet via resd-aws-infra"

OPERATOR_CIDR="${MY_CIDR:-$(curl -fsS https://ifconfig.me)/32}"
log "  operator-ssh-cidr=$OPERATOR_CIDR"

STACK_JSON="$(resd-aws-infra setup bench-pair \
    --operator-ssh-cidr "$OPERATOR_CIDR" --json)"

# Teardown on exit. Honour SKIP_TEARDOWN=1 for debug sessions.
teardown_fleet() {
  if [ "${SKIP_TEARDOWN:-0}" != 1 ]; then
    resd-aws-infra teardown bench-pair --wait || true
  else
    log "SKIP_TEARDOWN=1; leaving stack up"
  fi
}
trap teardown_fleet EXIT

DUT_SSH="$(jq -r .DutSshEndpoint <<<"$STACK_JSON")"
PEER_SSH="$(jq -r .PeerSshEndpoint <<<"$STACK_JSON")"
DUT_IP="$(jq -r .DutDataEniIp <<<"$STACK_JSON")"
PEER_IP="$(jq -r .PeerDataEniIp <<<"$STACK_JSON")"
AMI_ID="$(jq -r .AmiId <<<"$STACK_JSON")"

for var in DUT_SSH PEER_SSH DUT_IP PEER_IP AMI_ID; do
  val="${!var}"
  if [ -z "$val" ] || [ "$val" = "null" ]; then
    log "resd-aws-infra setup bench-pair --json missing $var"
    log "got: $STACK_JSON"
    exit 3
  fi
done

log "  DUT ssh=$DUT_SSH data-ip=$DUT_IP"
log "  peer ssh=$PEER_SSH data-ip=$PEER_IP"
log "  AMI=$AMI_ID"

# Gateway IP derivation: data-subnet gateway is typically the first host
# in the /24. We assume the CDK stack (see resd.aws-infra-setup) puts
# DUT and peer on a shared /24 subnet and .1 is the VPC router. Operators
# can override via GATEWAY_IP if the stack diverges.
GATEWAY_IP="${GATEWAY_IP:-$(awk -F. '{printf "%s.%s.%s.1", $1,$2,$3}' <<<"$DUT_IP")}"
log "  gateway-ip=$GATEWAY_IP"

NIC_MAX_BPS="${NIC_MAX_BPS:-100000000000}"  # 100 Gbps default for c6in.metal
log "  nic-max-bps=$NIC_MAX_BPS"

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)
SCP_OPTS=(-o StrictHostKeyChecking=accept-new)

# EAL args — ENA hot-path flags per spec §11 (large_llq_hdr=1,
# miss_txc_to=3) on PCI slot 0000:00:06.0 (c6in.metal default). The
# script takes EAL_ARGS from env if the operator wants to override for
# a different instance type or PCI slot.
EAL_ARGS="${EAL_ARGS:--l 2-3 -n 4 -a 0000:00:06.0,large_llq_hdr=1,miss_txc_to=3}"

# ---------------------------------------------------------------------------
# [3/11] Build all release binaries.
# ---------------------------------------------------------------------------
log "[3/11] cargo build --release --workspace"
cargo build --release --workspace

# ---------------------------------------------------------------------------
# [4/11] SCP binaries + scripts to DUT and peer hosts.
# ---------------------------------------------------------------------------
log "[4/11] deploying binaries to DUT + peer"

DUT_BINS=(
  target/release/bench-e2e
  target/release/bench-stress
  target/release/bench-vs-linux
  target/release/bench-offload-ab
  target/release/bench-obs-overhead
  target/release/bench-vs-mtcp
  target/release/bench-ab-runner
)
PEER_BINS=(
  tools/bench-e2e/peer/echo-server
  tools/bench-vs-linux/peer/linux-tcp-sink
)
SHARED_SCRIPTS=(scripts/check-bench-preconditions.sh)

for bin in "${DUT_BINS[@]}" "${PEER_BINS[@]}" "${SHARED_SCRIPTS[@]}"; do
  if [ ! -f "$bin" ]; then
    log "missing after build: $bin"
    exit 4
  fi
done

log "  -> DUT ($DUT_SSH)"
scp "${SCP_OPTS[@]}" \
    "${DUT_BINS[@]}" "${SHARED_SCRIPTS[@]}" \
    "ubuntu@${DUT_SSH}:/tmp/"

log "  -> peer ($PEER_SSH)"
scp "${SCP_OPTS[@]}" \
    "${PEER_BINS[@]}" "${SHARED_SCRIPTS[@]}" \
    "ubuntu@${PEER_SSH}:/tmp/"

# ---------------------------------------------------------------------------
# [5/11] Start peer services (echo-server for bench-e2e/stress/vs-mtcp;
#        linux-tcp-sink for bench-vs-linux mode A). Both backgrounded
#        and logged; the bench-pair teardown reaps them implicitly.
# ---------------------------------------------------------------------------
log "[5/11] starting peer services on $PEER_SSH"
ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "nohup /tmp/echo-server 10001 >/tmp/echo-server.log 2>&1 &"
ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "nohup /tmp/linux-tcp-sink 10002 >/tmp/linux-tcp-sink.log 2>&1 &"

# Give the peer services a moment to bind listen sockets.
sleep 1

# ---------------------------------------------------------------------------
# Helper: run a bench binary on the DUT over SSH, then pull its CSV
# back to $OUT_DIR. All benches follow the pattern:
#   sudo /tmp/<bench> --<flags> --output-csv /tmp/<bench>.csv
# ---------------------------------------------------------------------------
run_dut_bench() {
  local bench="$1"
  local csv_name="$2"
  shift 2
  local cmd="sudo /tmp/$bench"
  local arg
  for arg in "$@"; do
    # Quote every arg for the remote shell. Tolerates spaces / commas in
    # --eal-args without shell-injection.
    cmd+=" $(printf '%q' "$arg")"
  done
  cmd+=" --output-csv /tmp/${csv_name}.csv"

  log "  DUT> $bench"
  ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" "$cmd"
  scp "${SCP_OPTS[@]}" "ubuntu@$DUT_SSH:/tmp/${csv_name}.csv" "$OUT_DIR/"
}

# Common args shared across bench-e2e / bench-stress / bench-vs-linux /
# bench-vs-mtcp (DPDK stacks). bench-offload-ab / bench-obs-overhead are
# A/B drivers that shell out to bench-ab-runner internally, so they take
# a narrower arg set.
DPDK_COMMON=(
  --peer-ip "$PEER_IP"
  --local-ip "$DUT_IP"
  --gateway-ip "$GATEWAY_IP"
  --eal-args "$EAL_ARGS"
  --lcore 2
  --precondition-mode strict
)

# ---------------------------------------------------------------------------
# [6/11] bench-e2e — request/response RTT + A-HW Task 18 assertions.
# ---------------------------------------------------------------------------
log "[6/11] bench-e2e (with --assert-hw-task-18)"
run_dut_bench bench-e2e bench-e2e \
    "${DPDK_COMMON[@]}" \
    --peer-port 10001 \
    --assert-hw-task-18 \
    --tool bench-e2e \
    --feature-set trading-latency

# ---------------------------------------------------------------------------
# [7/11] bench-stress — netem + FaultInjector matrix (peer-host netem
# needs peer SSH + iface name).
# ---------------------------------------------------------------------------
log "[7/11] bench-stress"
run_dut_bench bench-stress bench-stress \
    "${DPDK_COMMON[@]}" \
    --peer-port 10001 \
    --peer-ssh "ubuntu@$PEER_SSH" \
    --peer-iface ens6 \
    --tool bench-stress \
    --feature-set trading-latency

# ---------------------------------------------------------------------------
# [8/11] bench-vs-linux — mode A (RTT) + mode B (wire-diff).
# Mode A: dpdk + linux stacks (afpacket is a T8 stub → dropped in
#   lenient mode; we keep strict + drop afpacket from --stacks).
# Mode B: wire-diff consumes pcaps. The live tcpdump orchestration is a
#   T15-B follow-up; for the MVP we skip mode B if no pcaps are staged.
# ---------------------------------------------------------------------------
log "[8/11] bench-vs-linux mode A (RTT comparison)"
run_dut_bench bench-vs-linux bench-vs-linux-rtt \
    "${DPDK_COMMON[@]}" \
    --mode rtt \
    --peer-port 10002 \
    --peer-iface ens6 \
    --stacks dpdk,linux \
    --tool bench-vs-linux \
    --feature-set trading-latency

# Mode B: wire-diff — requires pcap inputs. T15-B (follow-up) wires in
# live tcpdump orchestration on both hosts. For now, if the operator has
# staged pcaps into $OUT_DIR/pcaps/{local,peer}.pcap beforehand we run
# mode B; otherwise we emit a skip note.
if [ -f "$OUT_DIR/pcaps/local.pcap" ] && [ -f "$OUT_DIR/pcaps/peer.pcap" ]; then
  log "[8b/11] bench-vs-linux mode B (wire-diff)"
  # Mode B runs locally (no EAL needed — pcap MVP).
  ./target/release/bench-vs-linux \
      --mode wire-diff \
      --peer-ip "$PEER_IP" \
      --local-pcap "$OUT_DIR/pcaps/local.pcap" \
      --peer-pcap "$OUT_DIR/pcaps/peer.pcap" \
      --output-csv "$OUT_DIR/bench-vs-linux-wire-diff.csv" \
      --feature-set rfc-compliance \
      --precondition-mode lenient
else
  log "[8b/11] bench-vs-linux mode B skipped — no pcaps in $OUT_DIR/pcaps/ "
  log "        (live tcpdump orchestration deferred to T15-B)"
fi

# ---------------------------------------------------------------------------
# [9/11] bench-offload-ab + bench-obs-overhead — A/B drivers. These
# rebuild the workspace per config, so they cannot run in parallel with
# each other. They run on the DUT because they invoke bench-ab-runner
# which opens an EAL. Output goes into the driver's output-dir plus a
# Markdown report; we pull both into $OUT_DIR.
# ---------------------------------------------------------------------------
log "[9/11] bench-offload-ab"
ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
    "sudo /tmp/bench-offload-ab \
        --peer-ip $PEER_IP \
        --local-ip $DUT_IP \
        --gateway-ip $GATEWAY_IP \
        --peer-port 10001 \
        --eal-args $(printf '%q' "$EAL_ARGS") \
        --lcore 2 \
        --precondition-mode strict \
        --output-dir /tmp/bench-offload-ab \
        --report-path /tmp/bench-offload-ab/offload-ab.md \
        --runner-bin /tmp/bench-ab-runner \
        --skip-rebuild"
scp -r "${SCP_OPTS[@]}" \
    "ubuntu@$DUT_SSH:/tmp/bench-offload-ab" "$OUT_DIR/"

log "[9b/11] bench-obs-overhead"
ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
    "sudo /tmp/bench-obs-overhead \
        --peer-ip $PEER_IP \
        --local-ip $DUT_IP \
        --gateway-ip $GATEWAY_IP \
        --peer-port 10001 \
        --eal-args $(printf '%q' "$EAL_ARGS") \
        --lcore 2 \
        --precondition-mode strict \
        --output-dir /tmp/bench-obs-overhead \
        --report-path /tmp/bench-obs-overhead/obs-overhead.md \
        --runner-bin /tmp/bench-ab-runner \
        --skip-rebuild"
scp -r "${SCP_OPTS[@]}" \
    "ubuntu@$DUT_SSH:/tmp/bench-obs-overhead" "$OUT_DIR/"

# ---------------------------------------------------------------------------
# [10/11] bench-vs-mtcp burst + maxtp grids.
# mTCP stub is strict-mode-fatal; pass --stacks dpdk to run the DPDK
# arm only until Plan 2 T21 lands the real bench-peer binary.
# ---------------------------------------------------------------------------
log "[10/11] bench-vs-mtcp burst grid"
run_dut_bench bench-vs-mtcp bench-vs-mtcp-burst \
    "${DPDK_COMMON[@]}" \
    --workload burst \
    --peer-port 10001 \
    --stacks dpdk \
    --tool bench-vs-mtcp \
    --feature-set trading-latency \
    --nic-max-bps "$NIC_MAX_BPS"

log "[10b/11] bench-vs-mtcp maxtp grid"
run_dut_bench bench-vs-mtcp bench-vs-mtcp-maxtp \
    "${DPDK_COMMON[@]}" \
    --workload maxtp \
    --peer-port 10001 \
    --stacks dpdk \
    --tool bench-vs-mtcp \
    --feature-set trading-latency \
    --nic-max-bps "$NIC_MAX_BPS"

# ---------------------------------------------------------------------------
# [11/11] Local bench-micro + summarize + bench-report.
# bench-micro runs locally (pure in-process criterion targets, no NIC
# needed). obs-none disables observability so we get the "clean" curve.
# ---------------------------------------------------------------------------
log "[11/11] bench-micro (local) + summarize + bench-report"

# Per spec §5: bench-micro runs with obs-none so counter sites don't
# skew the criterion sample. The caller can override BENCH_MICRO_ARGS.
BENCH_MICRO_ARGS="${BENCH_MICRO_ARGS:---no-default-features}"
# shellcheck disable=SC2086 # BENCH_MICRO_ARGS is intentionally word-split
cargo bench -p bench-micro $BENCH_MICRO_ARGS

./target/release/summarize target/criterion "$OUT_DIR/bench-micro.csv"

./target/release/bench-report \
    --input "$OUT_DIR" \
    --output-json "$OUT_DIR/report.json" \
    --output-html "$OUT_DIR/report.html" \
    --output-md "$OUT_DIR/report.md"

log "[done] results in $OUT_DIR"
log "       JSON:     $OUT_DIR/report.json"
log "       HTML:     $OUT_DIR/report.html"
log "       Markdown: $OUT_DIR/report.md"
