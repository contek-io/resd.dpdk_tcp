# bench-nightly.sh runbook

End-to-end orchestrator for the A10 Stage 1 benchmark harness (spec §12 / §14).

## What it does

1. Provisions a `bench-pair` fleet (DUT + peer, shared `/24`, placement group)
   via `resd-aws-infra setup bench-pair --json` from the sister project
   `resd.aws-infra-setup`.
2. `cargo build --release --workspace`.
3. SCPs compiled bench binaries + `check-bench-preconditions.sh` + peer
   binaries (`echo-server`, `linux-tcp-sink`) to DUT + peer under `/tmp/`.
4. Starts peer services:
   - `echo-server` on port 10001 (bench-e2e, bench-stress, bench-vs-mtcp)
   - `linux-tcp-sink` on port 10002 (bench-vs-linux mode A)
5. Runs on the DUT over SSH:
   - `bench-e2e --assert-hw-task-18`
   - `bench-stress` (netem + FaultInjector sweep)
   - `bench-vs-linux --mode rtt`
   - `bench-vs-linux --mode wire-diff` (only if pcaps staged — see below)
   - `bench-offload-ab` (A/B feature-matrix driver with `--skip-rebuild`)
   - `bench-obs-overhead` (A/B obs-feature-matrix driver with `--skip-rebuild`)
   - `bench-vs-mtcp --workload burst`
   - `bench-vs-mtcp --workload maxtp`
6. Runs locally:
   - `cargo bench -p bench-micro --no-default-features`
   - `target/release/summarize target/criterion $OUT_DIR/bench-micro.csv`
7. Invokes `target/release/bench-report` to produce
   `report.{json,html,md}` under `$OUT_DIR`.
8. Tears the fleet down (`trap EXIT`), even on partial failure.

## Prerequisites

Installed + on `PATH`:

- `resd-aws-infra` — sister project CLI (see
  [`resd.aws-infra-setup`](https://github.com/contek-io/resd.aws-infra-setup)).
  The first AMI must be baked (`resd-aws-infra bake-image --recipe-version 1.0.0`);
  `cdk bootstrap` run once per AWS account/region.
- `cargo` — Rust toolchain (latest stable via `rustup`).
- `jq` — JSON scraping from the `--json` stack output.
- `ssh`, `scp`, `curl` — SSH into the provisioned hosts.
- `aws` — AWS CLI with credentials; `aws sts get-caller-identity` must succeed.
- `shellcheck` (dev-only) — pre-commit check.

## Env vars

| Var | Default | Purpose |
|---|---|---|
| `OUT_DIR` | `target/bench-results/<UTC-timestamp>/` | destination for CSVs + reports |
| `MY_CIDR` | auto (`curl ifconfig.me`) | operator `/32` for the bench-pair SG |
| `GATEWAY_IP` | `<DUT /24>.1` | data-subnet default gateway; override if the CDK stack diverges |
| `NIC_MAX_BPS` | `100000000000` (100 Gbps) | NIC line-rate cap for bench-vs-mtcp saturation guard (spec §11.1 check 3) |
| `EAL_ARGS` | `-l 2-3 -n 4 -a 0000:00:06.0,large_llq_hdr=1,miss_txc_to=3` | DPDK EAL args; c6in.metal ENA defaults |
| `BENCH_MICRO_ARGS` | `--no-default-features` | extra args for `cargo bench -p bench-micro` |
| `SKIP_TEARDOWN` | `0` | set to `1` to leave the stack running after exit (debug) |

## Running

```bash
cd /path/to/resd.dpdk_tcp
./scripts/bench-nightly.sh
```

Dry-run (prereq check only, no provisioning):

```bash
./scripts/bench-nightly.sh --dry-run
```

Help:

```bash
./scripts/bench-nightly.sh --help
```

## Expected output

```
target/bench-results/2026-04-21T12-00-00Z/
├── bench-e2e.csv
├── bench-stress.csv
├── bench-vs-linux-rtt.csv
├── bench-vs-linux-wire-diff.csv    # only if pcaps staged
├── bench-offload-ab/               # nested by driver
│   ├── <run-id>.csv
│   └── offload-ab.md
├── bench-obs-overhead/             # nested by driver
│   ├── <run-id>.csv
│   └── obs-overhead.md
├── bench-vs-mtcp-burst.csv
├── bench-vs-mtcp-maxtp.csv
├── bench-micro.csv
├── report.json
├── report.html
└── report.md
```

## bench-vs-linux mode B (wire-diff)

Mode B consumes pre-captured pcaps. The live `tcpdump` orchestration
(start on both hosts → run a workload → stop captures → SCP back) is
deferred to **T15-B** (see plan file, "T15-B post-MVP follow-up"
section). Until then, operators who want a wire-diff row can stage
pcaps into `$OUT_DIR/pcaps/{local,peer}.pcap` before the run — the
script detects those and runs mode B locally.

## Cost

Approximate AWS spend for one full nightly run (us-east-1 on-demand):

- Stack up-time: ~45–60 min for the full sweep
- 2 × c6in.metal: ~$12/hr combined (on-demand list)
- Expected total: ~$10–13 per nightly run

Use spot instances via the sister project's future overrides to cut
this further once a stable baseline is established.

## Troubleshooting

- **`resd-aws-infra not found`** — install the sister project
  (`git clone https://github.com/contek-io/resd.aws-infra-setup &&
  pip install -e .`); rebake the AMI if needed.
- **`rte_eth_dev_get_port_by_name` / EAL bring-up failures** —
  verify `vfio-pci` is bound on the DUT data NIC:
  `ssh ubuntu@$DUT_SSH "lspci -k -s 0000:00:06.0"`. The baked AMI
  should handle this via the `WC-patched vfio-pci` component (sister
  plan T5); if it doesn't, the AMI build is stale — rebake.
- **`check-bench-preconditions` strict-mode failures on the DUT** —
  the pinned CPUs / hugepages / isolcpus aren't set. Check
  `/proc/cmdline` matches the AMI's tuned GRUB config. A rebake of
  the AMI fixes this; a stack re-create doesn't (it just re-uses the
  stale AMI).
- **Partial run** — stack stays up if the script dies mid-run; rerun
  with `SKIP_TEARDOWN=0 resd-aws-infra teardown bench-pair --wait`
  once you've grabbed whatever partial output landed under `$OUT_DIR`.

## Deferred follow-ups (T15-B)

This runbook tracks T15-A. The T15-B follow-up lands:

- **T9-I1** — shared L2/L3/L4 parser in `tools/bench-vs-linux/src/normalize.rs`
  (factor `discover_pins` + `rewrite_frame` Ethernet/IPv4/TCP bounds checks).
- **T9-I2** — port-reuse discrimination in canonicalisation
  (SYN-timestamp or per-SYN instance counter keying `FlowState.iss`).
- **T9-I5** — integration test: differing local/peer pcap packet
  counts produce non-zero `diff_bytes` with accurate
  `local_packets`/`peer_packets` CSV cells.
- **T12-I4** — real peer-rwnd introspection in bench-vs-mtcp preflight
  (either `Engine::last_peer_rwnd(conn)` engine hook, or
  `ssh peer "ss -ti | grep -A1 <dut>:<port>"` scrape).
- **T9 minor** — `CanonError::MalformedSackOption`, single option
  walker, extract synth-pcap builder.
- **Mode B live capture** — tcpdump start/stop + SCP + wire-diff
  invocation in this script instead of requiring pre-staged pcaps.
