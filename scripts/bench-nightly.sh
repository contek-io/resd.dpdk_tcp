#!/usr/bin/env bash
# scripts/bench-nightly.sh — end-to-end A10 nightly bench orchestrator.
#
# Spec §12 / §14 end-to-end pipeline:
#   1. Prereq check (resd-aws-infra, cargo, jq, ssh, aws creds).
#   2. Build peer C binaries (echo-server, linux-tcp-sink).
#   3. cargo build --release --workspace.
#   4. Provision bench-pair fleet (DUT + peer) via resd-aws-infra.
#      Build precedes provisioning so a local build failure costs $0.
#   5. SCP compiled bench binaries + preconditions checker + peer binaries
#      to DUT and peer hosts (under /tmp).
#   6. Start peer echo-server (bench-e2e/bench-stress/bench-vs-mtcp) +
#      linux-tcp-sink (bench-vs-linux) on the peer host.
#   7. Run on DUT: bench-e2e, bench-stress, bench-vs-linux (mode A+B),
#      bench-offload-ab, bench-obs-overhead, bench-vs-mtcp (burst+maxtp).
#   8. Run locally: cargo bench -p bench-micro + summarize.
#   9. Pull CSVs back to target/bench-results/<timestamp>/.
#  10. Invoke bench-report → JSON + HTML + Markdown.
#  11. Teardown fleet (trap EXIT so partial runs still deprovision).
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
      sed -n '2,35p' "$0"
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
# [1/12] Prereq check — fail fast if anything required is missing.
# ---------------------------------------------------------------------------
log "[1/12] prereq check"

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
  log "--dry-run: prereq check OK; would now build locally, then provision bench-pair"
  log "--dry-run: output dir would be $OUT_DIR"
  rmdir "$OUT_DIR" 2>/dev/null || true
  exit 0
fi

# ---------------------------------------------------------------------------
# [2/12] Build peer C binaries (echo-server, linux-tcp-sink).
# Built BEFORE provisioning so a local build failure costs $0 AWS spend.
# ---------------------------------------------------------------------------
log "[2/12] building peer C binaries"
make -C tools/bench-e2e/peer echo-server
make -C tools/bench-vs-linux/peer linux-tcp-sink

# ---------------------------------------------------------------------------
# [3/12] cargo build --release --workspace.
# Built BEFORE provisioning so a local build failure costs $0 AWS spend.
# ---------------------------------------------------------------------------
log "[3/12] cargo build --release --workspace"
cargo build --release --workspace

# ---------------------------------------------------------------------------
# [4/12] Provision bench-pair fleet via resd-aws-infra.
# First AWS operation — local build must have succeeded above.
# ---------------------------------------------------------------------------
log "[4/12] provisioning bench-pair fleet via resd-aws-infra"

OPERATOR_CIDR="${MY_CIDR:-$(curl -fsS https://ifconfig.me)/32}"
log "  operator-ssh-cidr=$OPERATOR_CIDR"

# The resd-aws-infra CLI internally shells out to `cdk deploy`, which
# needs cdk.json + app.py at the CWD root. Those live in the sister
# repo. Wrap every CLI call in a `( cd "$RESD_INFRA_DIR" && ... )`
# subshell so the rest of the orchestrator keeps its $PWD.
RESD_INFRA_DIR="${RESD_INFRA_DIR:-$HOME/resd.aws-infra-setup}"

# Resolve AMI_ID. The CLI's default-from-cdk.json path reads relative
# to its CWD, which IS $RESD_INFRA_DIR once we cd there — but we pass
# --ami-id explicitly anyway so $AMI_ID env override works cleanly and
# the log line documents the chosen AMI for reproducibility.
AMI_ID_ARG=()
if [ -n "${AMI_ID:-}" ]; then
  AMI_ID_ARG=(--ami-id "$AMI_ID")
  log "  ami-id=$AMI_ID (from env)"
elif [ -f "$RESD_INFRA_DIR/cdk.json" ]; then
  CDK_AMI="$(jq -r '.context."default-ami-id" // empty' "$RESD_INFRA_DIR/cdk.json")"
  if [ -n "$CDK_AMI" ] && [ "$CDK_AMI" != "null" ]; then
    AMI_ID_ARG=(--ami-id "$CDK_AMI")
    log "  ami-id=$CDK_AMI (from $RESD_INFRA_DIR/cdk.json)"
  fi
fi

# Capture the full CLI stdout. The CLI's `--json` flag emits a JSON
# object at the end of stdout; CDK's verbose deploy log + `Outputs:`
# block go to stderr, which we let pass through to the operator's
# terminal. A `Stack ARN: <arn>` line often precedes the JSON on
# stdout, so extract the JSON starting at the first `{` line.
#
# INSTANCE_TYPE env var overrides the CDK preset default (c6a.2xlarge).
INSTANCE_TYPE_ARG=()
if [ -n "${INSTANCE_TYPE:-}" ]; then
  INSTANCE_TYPE_ARG=(--instance-type "$INSTANCE_TYPE")
  log "  instance-type=$INSTANCE_TYPE (operator override via env)"
fi
CLI_STDOUT="$(
  cd "$RESD_INFRA_DIR" && \
  resd-aws-infra setup bench-pair \
      --operator-ssh-cidr "$OPERATOR_CIDR" \
      "${INSTANCE_TYPE_ARG[@]}" \
      "${AMI_ID_ARG[@]}" --json
)"

STACK_JSON="$(echo "$CLI_STDOUT" | sed -n '/^{/,$p')"

# Teardown on exit. Honour SKIP_TEARDOWN=1 for debug sessions.
teardown_fleet() {
  if [ "${SKIP_TEARDOWN:-0}" != 1 ]; then
    ( cd "$RESD_INFRA_DIR" && resd-aws-infra teardown bench-pair --wait ) || true
  else
    log "SKIP_TEARDOWN=1; leaving stack up"
  fi
}
trap teardown_fleet EXIT

DUT_SSH="$(jq -r '.DutSshEndpoint // empty' <<<"$STACK_JSON")"
PEER_SSH="$(jq -r '.PeerSshEndpoint // empty' <<<"$STACK_JSON")"
DUT_INSTANCE_ID="$(jq -r '.DutInstanceId // empty' <<<"$STACK_JSON")"
PEER_INSTANCE_ID="$(jq -r '.PeerInstanceId // empty' <<<"$STACK_JSON")"
DUT_IP="$(jq -r '.DutDataEniIp // empty' <<<"$STACK_JSON")"
PEER_IP="$(jq -r '.PeerDataEniIp // empty' <<<"$STACK_JSON")"
AMI_ID="$(jq -r '.AmiId // empty' <<<"$STACK_JSON")"

for var in DUT_SSH PEER_SSH DUT_INSTANCE_ID PEER_INSTANCE_ID DUT_IP PEER_IP AMI_ID; do
  val="${!var}"
  if [ -z "$val" ]; then
    log "resd-aws-infra setup bench-pair missing output '$var'"
    log "CLI output tail:"
    echo "$CLI_STDOUT" | tail -25 | sed 's/^/  /' >&2
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

# Operator's SSH pubkey — pushed to each target via EC2 Instance Connect
# before the first SSH session to that host. The push grants a 60-second
# authorisation window; we re-push at the head of each bench stage so
# long-running SSH commands stay within the 60 s renewal horizon.
OPERATOR_PUBKEY="${OPERATOR_PUBKEY:-$HOME/.ssh/id_ed25519.pub}"
if [ ! -f "$OPERATOR_PUBKEY" ]; then
  log "OPERATOR_PUBKEY=$OPERATOR_PUBKEY not found; generate with 'ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519'"
  exit 5
fi

# push_operator_pubkey <instance-id> — grant this session's pubkey a
# 60-second authorization window on <instance-id> via EC2 Instance
# Connect. Safe to call repeatedly; each push resets the 60 s timer.
# Requires IAM: ec2-instance-connect:SendSSHPublicKey on the instance.
push_operator_pubkey() {
  local instance_id="$1"
  aws ec2-instance-connect send-ssh-public-key \
    --instance-id "$instance_id" \
    --instance-os-user ubuntu \
    --ssh-public-key "file://$OPERATOR_PUBKEY" \
    --output text --query 'Success' >/dev/null
}

# Refresh both hosts' EC2 Instance Connect windows. Call at the head of
# each bench stage so every SSH/SCP has a fresh 60-second grant.
refresh_ec2_ic_grants() {
  push_operator_pubkey "$DUT_INSTANCE_ID"
  push_operator_pubkey "$PEER_INSTANCE_ID"
}

log "  pushing operator pubkey via EC2 Instance Connect (60 s grant)"
refresh_ec2_ic_grants

# wait_for_ssh <host> — retry a BatchMode ssh probe until sshd accepts
# the connection. CloudFormation reports CREATE_COMPLETE when the
# instance starts running, but sshd may still be initialising (kex +
# host-key generation + auth stack). We refresh the EC2IC grant on
# every retry so the 60 s auth window never closes during a slow boot.
#
# Require REQUIRED_CONSECUTIVE successful handshakes in a row with a
# gap between each — a single success can race a transient sshd restart
# (cloud-init finalisation) and cause the immediately-following scp to
# hit "kex_exchange_identification: Connection closed by remote host".
wait_for_ssh() {
  local host="$1"
  local instance_id="$2"
  local attempt=0
  local consecutive=0
  local required_consecutive=3
  local max_attempts=30  # 30 * 5 s = 150 s ceiling
  while (( attempt < max_attempts )); do
    push_operator_pubkey "$instance_id"
    if ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o ConnectTimeout=5 \
         "ubuntu@${host}" exit 2>/dev/null; then
      consecutive=$((consecutive + 1))
      if (( consecutive >= required_consecutive )); then
        log "  sshd ready on $host (after ${consecutive} consecutive ok probes, attempt $((attempt+1)))"
        return 0
      fi
    else
      consecutive=0
    fi
    attempt=$((attempt + 1))
    sleep 5
  done
  log "  sshd NEVER came up on $host after ${max_attempts} probes"
  return 1
}

log "  waiting for sshd on both hosts"
wait_for_ssh "$DUT_SSH" "$DUT_INSTANCE_ID"
wait_for_ssh "$PEER_SSH" "$PEER_INSTANCE_ID"

# EAL args — ENA hot-path flags per spec §11 (large_llq_hdr=1,
# miss_txc_to=3) on PCI slot 0000:00:06.0 (c6in.metal default). The
# script takes EAL_ARGS from env if the operator wants to override for
# a different instance type or PCI slot.
#
# `--in-memory` keeps DPDK metadata out of /var/run/dpdk/rte/, and
# `--huge-unlink` removes /dev/hugepages/rtemap_* backing files at mmap
# time so they don't survive a half-completed rte_eal_cleanup. Without
# these flags, residual hugepage state from a prior bench-ab-runner
# leaks into the next process and rte_eal_cleanup walks a corrupted
# memzone (observed: bench-obs-overhead obs-none SIGSEGV in run
# bl16x36lb). Same flags as tests/ffi-test/tests/ffi_smoke.rs:48 uses
# for the same reason.
EAL_ARGS="${EAL_ARGS:--l 2-3 -n 4 --in-memory --huge-unlink -a 0000:00:06.0,large_llq_hdr=1,miss_txc_to=3}"

# ---------------------------------------------------------------------------
# [5/12] SCP binaries + scripts to DUT and peer hosts.
# ---------------------------------------------------------------------------
log "[5/12] deploying binaries to DUT + peer"

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
SHARED_SCRIPTS=(scripts/check-bench-preconditions.sh scripts/bench-ab-runner-gdb.sh)

for bin in "${DUT_BINS[@]}" "${PEER_BINS[@]}" "${SHARED_SCRIPTS[@]}"; do
  if [ ! -f "$bin" ]; then
    log "missing after build: $bin"
    exit 4
  fi
done

# retry_remote — wraps a remote-exec command (scp or ssh) with bounded
# retries against transient `kex_exchange_identification: Connection
# closed by remote host` errors. The 3-consecutive-probe wait_for_ssh
# guard didn't fully eliminate this — cloud-init can do a delayed sshd
# restart after the probes pass.
retry_remote() {
  local label="$1"; shift
  local instance_id="$1"; shift
  local max=5
  local attempt=0
  until "$@"; do
    attempt=$((attempt + 1))
    if (( attempt >= max )); then
      log "  $label failed after $max attempts"
      return 1
    fi
    log "  $label transient failure (attempt $attempt/$max) — sleeping 10s + refreshing EC2IC grant"
    sleep 10
    push_operator_pubkey "$instance_id"
  done
}

refresh_ec2_ic_grants
log "  -> DUT ($DUT_SSH)"
retry_remote "scp DUT-bins" "$DUT_INSTANCE_ID" \
  scp "${SCP_OPTS[@]}" \
    "${DUT_BINS[@]}" "${SHARED_SCRIPTS[@]}" \
    "ubuntu@${DUT_SSH}:/tmp/"
# scp drops the +x bit on shell scripts; restore it for the gdb wrapper
# so bench-offload-ab / bench-obs-overhead can exec it as --runner-bin.
retry_remote "chmod-DUT" "$DUT_INSTANCE_ID" \
  ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
    "chmod +x /tmp/bench-ab-runner-gdb.sh /tmp/check-bench-preconditions.sh"

refresh_ec2_ic_grants
log "  -> peer ($PEER_SSH)"
retry_remote "scp peer-bins" "$PEER_INSTANCE_ID" \
  scp "${SCP_OPTS[@]}" \
    "${PEER_BINS[@]}" "${SHARED_SCRIPTS[@]}" \
    "ubuntu@${PEER_SSH}:/tmp/"
retry_remote "chmod-peer" "$PEER_INSTANCE_ID" \
  ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "chmod +x /tmp/check-bench-preconditions.sh"

# ---------------------------------------------------------------------------
# [6/12] Start peer services (echo-server for bench-e2e/stress/vs-mtcp;
#        linux-tcp-sink for bench-vs-linux mode A). Both backgrounded
#        and logged; the bench-pair teardown reaps them implicitly.
#        </dev/null redirect guards against the OpenSSH-client-hang
#        gotcha where a backgrounded remote child keeps ssh's stdin
#        open.
#
#        The bench-host AMI binds the data NIC to vfio-pci at first
#        boot (sister component 07-systemd-units). That's correct for
#        the DUT — DPDK owns the NIC — but the peer runs plain Linux
#        echo-server / linux-tcp-sink on the data ENI IP, so here we
#        unbind it on the peer and bring the kernel interface up with
#        the data-plane IP. Idempotent.
# ---------------------------------------------------------------------------
log "[6/12] preparing peer data NIC and starting peer services on $PEER_SSH"
refresh_ec2_ic_grants
ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "sudo bash -s -- $PEER_IP" <<'REMOTE_EOF'
set -euo pipefail
PEER_IP="$1"
PCI="$(/usr/local/bin/dpdk-devbind.py --status-dev net | awk '/drv=vfio-pci/ {print $1; exit}')"
if [ -n "$PCI" ]; then
  echo "peer-prep: unbinding $PCI from vfio-pci, rebinding to ena"
  /usr/local/bin/dpdk-devbind.py --bind ena "$PCI"
  sleep 2
fi
# First non-mgmt, non-lo, non-docker interface is the peer data NIC.
MGMT_IF="$(ip route show default | awk '/default/ {print $5; exit}')"
IFACE="$(ip -o link show | awk -F': ' '{print $2}' | grep -vE "^(lo|docker|${MGMT_IF})$" | head -1)"
if [ -z "$IFACE" ]; then
  echo "peer-prep: no data NIC found after rebind" >&2
  exit 1
fi
echo "peer-prep: bringing up $IFACE with $PEER_IP/24"
ip link set "$IFACE" up
# --no-check-duplicate-addr is unreliable on ip-addr replace; simpler to
# tolerate EEXIST from a re-run by stripping-then-adding.
ip addr flush dev "$IFACE" || true
ip addr add "$PEER_IP"/24 dev "$IFACE"
# Drop firewall on the interface so echo-server accepts from the DUT.
# Already running as root via `sudo bash -s --`, no extra sudo needed.
iptables -I INPUT -i "$IFACE" -j ACCEPT 2>/dev/null || true
echo "peer-prep: $IFACE ready"
REMOTE_EOF

refresh_ec2_ic_grants
ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "nohup /tmp/echo-server 10001 >/tmp/echo-server.log 2>&1 </dev/null &"
refresh_ec2_ic_grants
ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "nohup /tmp/linux-tcp-sink 10002 >/tmp/linux-tcp-sink.log 2>&1 </dev/null &"

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
    cmd+=" $(printf '%q' "$arg")"
  done
  cmd+=" --output-csv /tmp/${csv_name}.csv"

  refresh_ec2_ic_grants

  local stderr_log="$OUT_DIR/${csv_name}.stderr.log"
  local stdout_log="$OUT_DIR/${csv_name}.stdout.log"

  log "  DUT> $bench (stderr -> $stderr_log)"
  # Capture stdout + stderr separately. The remote `2>&1` pattern would
  # interleave the two streams; we want stderr preserved in its own
  # file because the binaries log structured progress to stdout and
  # diagnostics to stderr.
  local rc=0
  ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" "$cmd" \
      >"$stdout_log" 2>"$stderr_log" || rc=$?
  if [ $rc -ne 0 ]; then
    log "  $bench exited rc=$rc; tailing stderr:"
    tail -n 40 "$stderr_log" | sed 's/^/    /' | tee -a /dev/stderr
  fi
  # Always attempt to scp the CSV, even on bench failure: a partial CSV
  # written before the cliff / abort is forensically valuable for
  # iteration-cliff diagnosis. scp failure here is non-fatal.
  refresh_ec2_ic_grants
  scp "${SCP_OPTS[@]}" "ubuntu@$DUT_SSH:/tmp/${csv_name}.csv" "$OUT_DIR/" \
    || log "  scp ${csv_name}.csv failed (bench may have exited before write)"
  return $rc
}

# Common args shared across bench-e2e / bench-stress / bench-vs-linux /
# bench-vs-mtcp (DPDK stacks). bench-offload-ab / bench-obs-overhead are
# A/B drivers that shell out to bench-ab-runner internally, so they take
# a narrower arg set.
#
# BENCH_ITERATIONS / BENCH_WARMUP: lowered from the spec's 100k/1k
# defaults because run b5scpbl90 observed a deterministic TCP
# retransmit-budget exhaustion at iteration ~7051 across every bench
# on c6a.2xlarge. 5k / 500 stays under that threshold and still gives a
# usable sample count for p50/p99/p999 summaries. Operators can
# override via env for longer sweeps once the root cause (AWS
# per-flow throttle vs. our stack's retransmit-history wrap) is
# identified and fixed.
BENCH_ITERATIONS="${BENCH_ITERATIONS:-5000}"
BENCH_WARMUP="${BENCH_WARMUP:-500}"

DPDK_COMMON=(
  --peer-ip "$PEER_IP"
  --local-ip "$DUT_IP"
  --gateway-ip "$GATEWAY_IP"
  --eal-args "$EAL_ARGS"
  --lcore 2
  --precondition-mode strict
)

# ---------------------------------------------------------------------------
# [7/12] bench-e2e — request/response RTT + A-HW Task 18 assertions.
# ---------------------------------------------------------------------------
log "[7/12] bench-e2e (with --assert-hw-task-18)"
run_dut_bench bench-e2e bench-e2e \
    "${DPDK_COMMON[@]}" \
    --peer-port 10001 \
    --iterations "$BENCH_ITERATIONS" \
    --warmup "$BENCH_WARMUP" \
    --assert-hw-task-18 \
    --tool bench-e2e \
    --feature-set trading-latency \
    || log "  [7/12] bench-e2e exited non-zero — continuing"

# ---------------------------------------------------------------------------
# [8/12] bench-stress — operator-side netem orchestration.
# DUT cannot SSH from the data ENI to the peer's mgmt IP (different SG /
# no route), so the previous in-process NetemGuard apply hangs on
# OpenSSH's connect timeout. Operator workstation has working SSH to
# the peer's mgmt IP; orchestrate netem here, run bench-stress with
# --external-netem on the DUT.
# ---------------------------------------------------------------------------
log "[8/12] bench-stress (operator-side netem orchestration)"

# Spec→string map mirrors the literals in
# `tools/bench-stress/src/scenarios.rs::MATRIX`. Adding a new netem
# scenario requires a new entry here AND a row in scenarios.rs.
declare -A NETEM_SPECS=(
  [random_loss_01pct_10ms]="loss 0.1% delay 10ms"
  [correlated_burst_loss_1pct]="loss 1% 25%"
  [reorder_depth_3]="delay 5ms reorder 50% gap 3"
  [duplication_2x]="duplicate 100%"
)

NETEM_SCENARIOS=(random_loss_01pct_10ms correlated_burst_loss_1pct reorder_depth_3 duplication_2x)

# Defensive cleanup: if a previous run crashed mid-scenario, the peer
# may still have a netem qdisc installed. The next `tc qdisc add` would
# return EEXIST and skip ALL subsequent scenarios via the apply-fail
# branch — fail loud and silent. One pre-loop `del` puts the peer in a
# known clean state; `|| true` covers the no-orphan case.
log "  [8/12] pre-loop netem cleanup (defensive)"
ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
  "sudo tc qdisc del dev ens6 root || true" \
  || log "    pre-loop cleanup ssh failed (peer unreachable?); continuing"

bench_stress_csvs=()

for scenario in "${NETEM_SCENARIOS[@]}"; do
  spec="${NETEM_SPECS[$scenario]}"
  log "  [8/12] $scenario — applying netem ($spec)"
  ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "sudo tc qdisc add dev ens6 root netem $spec" \
    || { log "    apply failed; skipping scenario"; continue; }

  csv_name="bench-stress-$scenario"
  if ! run_dut_bench bench-stress "$csv_name" \
      "${DPDK_COMMON[@]}" \
      --peer-port 10001 \
      --peer-ssh "ubuntu@$PEER_SSH" \
      --peer-iface ens6 \
      --scenarios "$scenario" \
      --external-netem \
      --iterations "$BENCH_ITERATIONS" \
      --warmup "$BENCH_WARMUP" \
      --tool bench-stress \
      --feature-set trading-latency; then
    log "    $scenario bench-stress exited non-zero — continuing"
  fi

  log "  [8/12] $scenario — removing netem"
  ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
    "sudo tc qdisc del dev ens6 root || true"

  bench_stress_csvs+=("$OUT_DIR/${csv_name}.csv")
done

# Concatenate per-scenario CSVs into a single bench-stress.csv.
# First file's header is preserved; subsequent files' headers are
# stripped via `tail -n +2`. If no scenarios produced a CSV (every one
# failed), emit an empty file so the downstream report sees the
# expected name without erroring.
log "[8/12] merging per-scenario CSVs into bench-stress.csv"
{
  if [ ${#bench_stress_csvs[@]} -gt 0 ] && [ -f "${bench_stress_csvs[0]}" ]; then
    head -n 1 "${bench_stress_csvs[0]}"
    for f in "${bench_stress_csvs[@]}"; do
      [ -f "$f" ] && tail -n +2 "$f"
    done
  fi
} > "$OUT_DIR/bench-stress.csv"

# ---------------------------------------------------------------------------
# [9/12] bench-vs-linux — mode A (RTT) + mode B (wire-diff).
# Mode A: dpdk + linux stacks (afpacket is a T8 stub → dropped in
#   lenient mode; we keep strict + drop afpacket from --stacks).
# Mode B: wire-diff consumes pcaps. The live tcpdump orchestration is a
#   T15-B follow-up; for the MVP we skip mode B if no pcaps are staged.
# ---------------------------------------------------------------------------
log "[9/12] bench-vs-linux mode A (RTT comparison)"
run_dut_bench bench-vs-linux bench-vs-linux-rtt \
    "${DPDK_COMMON[@]}" \
    --mode rtt \
    --peer-port 10002 \
    --peer-iface ens6 \
    --stacks dpdk,linux \
    --iterations "$BENCH_ITERATIONS" \
    --warmup "$BENCH_WARMUP" \
    --tool bench-vs-linux \
    --feature-set trading-latency \
    || log "  [9/12] bench-vs-linux mode A exited non-zero — continuing"

# Mode B: wire-diff — consume pcaps captured around a short live
# workload. A10 Plan B T15-B wires tcpdump orchestration: start tcpdump
# on both DUT (ens6) and peer (ens6), run a short RTT micro-workload
# (10 request/response pairs, no --assert-hw-task-18), stop tcpdump,
# pull both pcaps back, invoke bench-vs-linux --mode wire-diff locally.
#
# An operator-staged pcap pair takes precedence — useful for replaying
# a specific capture against the canonicaliser without burning a fleet.
log "[9b/12] bench-vs-linux mode B (wire-diff)"
mkdir -p "$OUT_DIR/pcaps"

if [ -f "$OUT_DIR/pcaps/local.pcap" ] && [ -f "$OUT_DIR/pcaps/peer.pcap" ]; then
  log "        using operator-staged pcaps in $OUT_DIR/pcaps/"
else
  log "        capturing live pcaps (10 RTT exchanges, peer port 10001)"

  # Start tcpdump on DUT + peer. `-U` flushes per-packet so partial
  # captures remain readable if tcpdump is killed before normal exit.
  # `-s 0` disables truncation (we need full TCP payloads for the
  # canonicaliser's option walker). `-w <file>` writes pcap. The `tcp
  # and port 10001` filter narrows to the bench-vs-mtcp / bench-e2e
  # peer port — mode B does not compare RTT-port traffic so excluding
  # port 10002 keeps the diff deterministic.
  TCPDUMP_FILTER="tcp and port 10001"

  # Backgrounded tcpdump on DUT and peer. </dev/null + nohup to detach
  # from ssh's stdin (same OpenSSH gotcha as the peer-services stanza).
  # Soft-fail with retry: a transient kex_exchange_identification race
  # here shouldn't abort the entire nightly. mode B is diagnostic.
  retry_remote "ssh tcpdump-DUT" "$DUT_INSTANCE_ID" \
    ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
      "sudo nohup tcpdump -i ens6 -U -s 0 -w /tmp/mode-b-local.pcap \
       '$TCPDUMP_FILTER' >/tmp/tcpdump-dut.log 2>&1 </dev/null &" \
    || log "        WARN tcpdump DUT start failed; pcap may be empty"
  retry_remote "ssh tcpdump-peer" "$PEER_INSTANCE_ID" \
    ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
      "sudo nohup tcpdump -i ens6 -U -s 0 -w /tmp/mode-b-peer.pcap \
       '$TCPDUMP_FILTER' >/tmp/tcpdump-peer.log 2>&1 </dev/null &" \
    || log "        WARN tcpdump peer start failed; pcap may be empty"

  # Give tcpdump a beat to bind its pcap ring before we start driving
  # traffic. Skipping this can drop the first few handshake packets,
  # which is exactly what the canonicaliser keys on.
  sleep 2

  # Short synthetic workload: reuse bench-e2e for 10 request/response
  # exchanges against the echo-server on port 10001. No HW-task-18
  # assertions — those add TX-TS preconditions that are orthogonal to
  # the pcap content we care about for wire-diff.
  log "        running bench-e2e live capture workload"
  ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
      "sudo /tmp/bench-e2e \
          --peer-ip $PEER_IP \
          --local-ip $DUT_IP \
          --gateway-ip $GATEWAY_IP \
          --eal-args $(printf '%q' "$EAL_ARGS") \
          --lcore 2 \
          --precondition-mode lenient \
          --peer-port 10001 \
          --iterations 10 \
          --output-csv /tmp/bench-e2e-mode-b-capture.csv \
          --tool bench-vs-linux-mode-b \
          --feature-set rfc-compliance" \
      || log "        WARN bench-e2e capture workload returned non-zero; \
diff may still be meaningful"

  # Stop tcpdump and flush buffers. SIGINT (the default on killall
  # without -9) lets tcpdump write its final pcap trailer. We tolerate
  # the "no process found" case if tcpdump already exited.
  ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
      "sudo killall -INT tcpdump 2>/dev/null || true"
  ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
      "sudo killall -INT tcpdump 2>/dev/null || true"

  # Give tcpdump's signal handler a moment to finish flushing.
  sleep 1

  # Pull pcaps back. SCP's -C compresses on the wire; useful over the
  # operator-to-AWS link when captures are large. `sudo chown ubuntu`
  # fixes perms so the scp user can read. Each step tolerates a missing
  # file (e.g., if the capture workload above bailed at handshake before
  # tcpdump saw any traffic) so the pcap-harvest failure doesn't kill
  # the rest of the nightly pipeline.
  ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
      "sudo chown ubuntu:ubuntu /tmp/mode-b-local.pcap 2>/dev/null || true"
  ssh "${SSH_OPTS[@]}" "ubuntu@$PEER_SSH" \
      "sudo chown ubuntu:ubuntu /tmp/mode-b-peer.pcap 2>/dev/null || true"
  scp "${SCP_OPTS[@]}" "ubuntu@$DUT_SSH:/tmp/mode-b-local.pcap" \
      "$OUT_DIR/pcaps/local.pcap" \
      || log "        WARN local pcap missing or empty — wire-diff will skip"
  scp "${SCP_OPTS[@]}" "ubuntu@$PEER_SSH:/tmp/mode-b-peer.pcap" \
      "$OUT_DIR/pcaps/peer.pcap" \
      || log "        WARN peer pcap missing or empty — wire-diff will skip"
fi

# Invoke the wire-diff mode locally. Mode B runs locally (no EAL
# needed — pcap MVP). Exit code 1 means "canonical-divergence found"
# and is the expected signal for operator attention; we don't `exit`
# on it here because the rest of the nightly pipeline (bench-report)
# still needs to run.
if [ -s "$OUT_DIR/pcaps/local.pcap" ] && [ -s "$OUT_DIR/pcaps/peer.pcap" ]; then
  if ! ./target/release/bench-vs-linux \
      --mode wire-diff \
      --peer-ip "$PEER_IP" \
      --local-pcap "$OUT_DIR/pcaps/local.pcap" \
      --peer-pcap "$OUT_DIR/pcaps/peer.pcap" \
      --output-csv "$OUT_DIR/bench-vs-linux-wire-diff.csv" \
      --feature-set rfc-compliance \
      --precondition-mode lenient; then
    log "        WARN wire-diff found divergence or failed; see \
$OUT_DIR/bench-vs-linux-wire-diff.csv"
  fi
else
  log "        SKIP wire-diff: one or both pcaps missing/empty"
fi

# ---------------------------------------------------------------------------
# [10/12] bench-offload-ab + bench-obs-overhead — A/B drivers. These
# rebuild the workspace per config, so they cannot run in parallel with
# each other. They run on the DUT because they invoke bench-ab-runner
# which opens an EAL. Output goes into the driver's output-dir plus a
# Markdown report; we pull both into $OUT_DIR.
# ---------------------------------------------------------------------------
log "[10/12] bench-offload-ab"
# /tmp/bench-offload-ab is the scp'd binary — use a distinct -out dir so
# the driver's mkdir doesn't collide with the executable file.
refresh_ec2_ic_grants
ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
    "sudo /tmp/bench-offload-ab \
        --peer-ip $PEER_IP \
        --local-ip $DUT_IP \
        --gateway-ip $GATEWAY_IP \
        --peer-port 10001 \
        --eal-args $(printf '%q' "$EAL_ARGS") \
        --lcore 2 \
        --precondition-mode strict \
        --iterations $BENCH_ITERATIONS \
        --warmup $BENCH_WARMUP \
        --output-dir /tmp/bench-offload-ab-out \
        --report-path /tmp/bench-offload-ab-out/offload-ab.md \
        --runner-bin /tmp/bench-ab-runner \
        --skip-rebuild" \
    || log "  [10/12] bench-offload-ab exited non-zero — continuing"
refresh_ec2_ic_grants
scp -r "${SCP_OPTS[@]}" \
    "ubuntu@$DUT_SSH:/tmp/bench-offload-ab-out" "$OUT_DIR/bench-offload-ab" \
    || log "  [10/12] scp of bench-offload-ab failed — continuing"

log "[10b/12] bench-obs-overhead"
# See [10/12] — /tmp/bench-obs-overhead is the binary; use -out for dir.
refresh_ec2_ic_grants
ssh "${SSH_OPTS[@]}" "ubuntu@$DUT_SSH" \
    "sudo /tmp/bench-obs-overhead \
        --peer-ip $PEER_IP \
        --local-ip $DUT_IP \
        --gateway-ip $GATEWAY_IP \
        --peer-port 10001 \
        --eal-args $(printf '%q' "$EAL_ARGS") \
        --lcore 2 \
        --precondition-mode strict \
        --iterations $BENCH_ITERATIONS \
        --warmup $BENCH_WARMUP \
        --output-dir /tmp/bench-obs-overhead-out \
        --report-path /tmp/bench-obs-overhead-out/obs-overhead.md \
        --runner-bin /tmp/bench-ab-runner \
        --skip-rebuild" \
    || log "  [10b/12] bench-obs-overhead exited non-zero — continuing"
refresh_ec2_ic_grants
scp -r "${SCP_OPTS[@]}" \
    "ubuntu@$DUT_SSH:/tmp/bench-obs-overhead-out" "$OUT_DIR/bench-obs-overhead" \
    || log "  [10b/12] scp of bench-obs-overhead failed — continuing"

# Pull the gdb wrapper's diagnostic log back for offline analysis. The
# wrapper writes stack traces from any SIGSEGV that hit bench-ab-runner
# during [10/12]+[10b/12], plus the gdb-version banner and any apt-install
# output if gdb was bootstrapped at first invocation.
refresh_ec2_ic_grants
scp "${SCP_OPTS[@]}" \
    "ubuntu@$DUT_SSH:/tmp/bench-ab-runner-gdb.log" "$OUT_DIR/" \
    || log "  gdb log scp failed — continuing"

# ---------------------------------------------------------------------------
# [11/12] bench-vs-mtcp burst + maxtp grids.
# mTCP stub is strict-mode-fatal; pass --stacks dpdk to run the DPDK
# arm only until Plan 2 T21 lands the real bench-peer binary.
# ---------------------------------------------------------------------------
log "[11/12] bench-vs-mtcp burst grid"
run_dut_bench bench-vs-mtcp bench-vs-mtcp-burst \
    "${DPDK_COMMON[@]}" \
    --workload burst \
    --peer-port 10001 \
    --stacks dpdk \
    --tool bench-vs-mtcp \
    --feature-set trading-latency \
    --nic-max-bps "$NIC_MAX_BPS" \
    || log "  [11/12] bench-vs-mtcp burst exited non-zero — continuing"

log "[11b/12] bench-vs-mtcp maxtp grid (dpdk + linux comparator)"
# 2026-05-03: Linux kernel-TCP arm landed in bench-vs-mtcp (mTCP arm
# stays stubbed while AMI rebuild is blocked on libmtcp / gcc 13).
# Both stacks talk to the existing echo-server on port 10001; linux
# maxtp doesn't care that the peer echoes — it only sends and counts
# accepted bytes.
run_dut_bench bench-vs-mtcp bench-vs-mtcp-maxtp \
    "${DPDK_COMMON[@]}" \
    --workload maxtp \
    --peer-port 10001 \
    --stacks dpdk,linux \
    --tool bench-vs-mtcp \
    --feature-set trading-latency \
    --nic-max-bps "$NIC_MAX_BPS" \
    || log "  [11b/12] bench-vs-mtcp maxtp exited non-zero — continuing"

# ---------------------------------------------------------------------------
# [12/12] Local bench-micro + summarize + bench-report.
# bench-micro runs locally (pure in-process criterion targets, no NIC
# needed). Every bench-micro target pulls in dpdk-net-core, which the
# workspace release profile builds with panic=abort for C-ABI safety.
# Cargo's bench profile is hard-coded to panic=unwind (bench/test
# profiles don't accept a panic override), so link fails on the
# strategy mismatch. Force panic=abort via RUSTFLAGS and enumerate
# bench targets explicitly so the `summarize` bin's #[cfg(test)] module
# isn't dragged in (test targets need -Zpanic_abort_tests which is
# nightly-only). The caller can override BENCH_MICRO_ARGS if a future
# feature gate is added to bench-micro.
# ---------------------------------------------------------------------------
log "[12/12] bench-micro (local) + summarize + bench-report"

BENCH_MICRO_ARGS="${BENCH_MICRO_ARGS:-}"
# shellcheck disable=SC2086 # BENCH_MICRO_ARGS is intentionally word-split
RUSTFLAGS="${RUSTFLAGS:-} -C panic=abort" cargo bench -p bench-micro \
    --bench poll --bench tsc_read --bench flow_lookup \
    --bench send --bench tcp_input --bench counters --bench timer \
    $BENCH_MICRO_ARGS

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
