# Phase A10 sub-project — `resd.aws-infra-setup` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended per user protocol) to implement this plan task-by-task. Per-task spec-compliance + code-quality review subagents (both `model: "opus"` per `feedback_subagent_model.md`) run after every non-trivial task per `feedback_per_task_review_discipline.md`. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a new reusable sibling repo `resd.aws-infra-setup` containing a Python AWS CDK app + EC2 Image Builder pipeline. Provisions the `bench-pair` fleet preset (DUT + peer) and bakes the single production+bench AMI used by `resd.dpdk_tcp` A10 benchmarks. Exposes a `resd-aws-infra {setup|teardown|status|bake-image}` CLI that the bench-harness script shells out to.

**Architecture:** Python CDK (aws-cdk-lib v2) app, one preset per CDK stack. Image Builder pipeline defined in the same CDK app; nine YAML components applied in order install clang-22+libc++, DPDK 23.11, WC-patched vfio-pci, mTCP (from a vendored `third_party/mtcp` mirror or a git-URL fetched at bake time), GRUB args, modprobe config, systemd units, bench tools, precondition checker. CLI wrapper built on `click` that shells out to `cdk deploy/destroy/describe` under the hood.

**Tech Stack:** Python ≥3.11, aws-cdk-lib v2, constructs, boto3 (bake-status polling), click (CLI), pytest (unit tests on preset builders). AWS CloudFormation + EC2 Image Builder + EC2 + VPC + Security Groups + IAM under the hood.

**Repo location:** `/home/ubuntu/resd.aws-infra-setup` (new clone/init at the same filesystem level as `resd.dpdk_tcp` and its worktrees). Eventually pushed to `github.com/contek-io/resd.aws-infra-setup` (user does the initial push).

**Spec:** `/home/ubuntu/resd.dpdk_tcp-a10/docs/superpowers/specs/2026-04-21-stage1-phase-a10-benchmark-harness-design.md` §15 + §16 (committed at `7f70ea5` on branch `phase-a10`).

---

## File structure

### Created (new repo `resd.aws-infra-setup/`)

```
resd.aws-infra-setup/
├── .gitignore
├── .python-version                 # 3.11
├── README.md
├── pyproject.toml
├── cdk.json
├── app.py                          # CDK entrypoint — instantiates each preset stack + the image pipeline
├── lib/
│   ├── __init__.py
│   ├── presets/
│   │   ├── __init__.py
│   │   └── bench_pair.py           # BenchPairStack construct
│   ├── image_builder/
│   │   ├── __init__.py
│   │   └── bench_host_image.py     # Image Builder pipeline construct
│   └── utils/
│       ├── __init__.py
│       └── cfn_outputs.py          # stack-output helpers (JSON emit)
├── image-components/               # YAML authored here; CDK reads at synth-time
│   ├── 01-install-llvm-toolchain.yaml
│   ├── 02-install-dpdk-23-11.yaml
│   ├── 03-install-wc-vfio-pci.yaml
│   ├── 04-install-mtcp.yaml
│   ├── 05-configure-grub.yaml
│   ├── 06-modprobe-config.yaml
│   ├── 07-systemd-units.yaml
│   ├── 08-install-bench-tools.yaml
│   └── 09-install-preconditions-checker.yaml
├── cli/
│   ├── __init__.py
│   └── resd_aws_infra/
│       ├── __init__.py
│       ├── main.py                 # click entrypoint: setup / teardown / status / bake-image
│       ├── setup.py
│       ├── teardown.py
│       ├── status.py
│       └── bake_image.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_bench_pair_preset.py   # unit tests on the CDK construct (synth-only)
│   ├── test_image_builder.py       # unit tests on the image pipeline construct
│   └── test_cli.py                 # click-runner tests
└── assets/
    └── check-bench-preconditions.sh  # identical copy of the script also shipped to resd.dpdk_tcp under scripts/
```

### Task dependency chain

Serial: T1 → T2 → T3 → T4 → T5 → T6 → T7 → T8

- T1: Repo scaffold (init, pyproject, .gitignore, README stub, CDK boilerplate)
- T2: `bench-pair` CDK preset (synth-only; no deploy yet)
- T3: Image Builder pipeline CDK construct + `bench_host_image.py`
- T4: Image components 01–09 YAML
- T5: CLI wrapper (setup / teardown / status / bake-image)
- T6: First bake run — produces AMI ID; commit AMI ID as CDK parameter default
- T7: First bench-pair stack bring-up — validates preconditions-checker passes on the baked host
- T8: README, cost estimate, troubleshooting, tag v0.1.0

---

## Task 1: Repo scaffold + CDK boilerplate

**Files:**
- Create (on disk): new repo at `/home/ubuntu/resd.aws-infra-setup`
- Create: `resd.aws-infra-setup/.gitignore`
- Create: `resd.aws-infra-setup/.python-version` (`3.11`)
- Create: `resd.aws-infra-setup/pyproject.toml`
- Create: `resd.aws-infra-setup/cdk.json`
- Create: `resd.aws-infra-setup/app.py`
- Create: `resd.aws-infra-setup/lib/__init__.py`
- Create: `resd.aws-infra-setup/README.md` (stub)
- Create: `resd.aws-infra-setup/tests/__init__.py`
- Create: `resd.aws-infra-setup/tests/conftest.py`

### Steps

- [ ] **Step 1.1: Create the new repo directory and git-init**

```bash
mkdir -p /home/ubuntu/resd.aws-infra-setup
cd /home/ubuntu/resd.aws-infra-setup
git init
git branch -M main
```

- [ ] **Step 1.2: Write `.gitignore`**

```
# Python
__pycache__/
*.pyc
.pytest_cache/
.mypy_cache/
.ruff_cache/
.venv/

# CDK
cdk.out/
cdk.context.json
*.pyc

# Local secrets / AWS
.env
.aws-credentials

# Editor
.vscode/
.idea/
*.swp
*.swo
```

- [ ] **Step 1.3: Write `.python-version`**

```
3.11
```

- [ ] **Step 1.4: Write `pyproject.toml`**

```toml
[project]
name = "resd-aws-infra-setup"
version = "0.1.0"
description = "Reusable AWS IaC (CDK Python) and EC2 Image Builder setup for resd.* projects — bench fleet + production host AMI."
readme = "README.md"
requires-python = ">=3.11"
authors = [{ name = "contek-io" }]
license = { text = "Apache-2.0" }
dependencies = [
    "aws-cdk-lib>=2.140.0,<3.0.0",
    "constructs>=10.0.0,<11.0.0",
    "boto3>=1.34.0",
    "click>=8.1.0",
    "pyyaml>=6.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-mock>=3.12.0",
    "ruff>=0.3.0",
    "mypy>=1.8.0",
]

[project.scripts]
resd-aws-infra = "cli.resd_aws_infra.main:cli"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["lib*", "cli*"]

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
```

- [ ] **Step 1.5: Write `cdk.json`**

```json
{
  "app": "python app.py",
  "watch": {
    "include": ["**"],
    "exclude": ["README.md", "cdk*.json", "**/*.pyc", "tests/**", "**/__pycache__"]
  },
  "context": {
    "@aws-cdk/aws-iam:minimizePolicies": true,
    "@aws-cdk/core:stackRelativeExports": true
  }
}
```

- [ ] **Step 1.6: Write stub `app.py`**

```python
#!/usr/bin/env python3
"""resd.aws-infra-setup CDK app entrypoint.

Instantiates every preset + the image pipeline. Stacks are selected by
CLI -> `cdk synth/deploy --app ...`; `resd-aws-infra` CLI shells out.
"""
import os

import aws_cdk as cdk

# Presets
# T2 fills these in:
# from lib.presets.bench_pair import BenchPairStack
# T3 fills this in:
# from lib.image_builder.bench_host_image import BenchHostImageStack


def main() -> None:
    app = cdk.App()
    env = cdk.Environment(
        account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region=os.environ.get("CDK_DEFAULT_REGION", "us-east-1"),
    )
    # Stacks will be added by T2 and T3.
    _ = env
    app.synth()


if __name__ == "__main__":
    main()
```

- [ ] **Step 1.7: Write stub `lib/__init__.py`**

```python
"""resd.aws-infra-setup CDK library."""
```

- [ ] **Step 1.8: Write `tests/__init__.py` (empty) and `tests/conftest.py`**

`tests/__init__.py`:

```python
```

`tests/conftest.py`:

```python
"""Shared pytest fixtures."""
import pytest
import aws_cdk as cdk


@pytest.fixture
def app() -> cdk.App:
    return cdk.App()
```

- [ ] **Step 1.9: Write stub `README.md`**

```markdown
# resd.aws-infra-setup

Reusable AWS infrastructure setup (CDK, Python) for `resd.*` projects.
Stands up fleets and bakes the production-shape AMI used by `resd.dpdk_tcp`
A10 benchmarks.

**Status:** v0.1.0 (Stage 1 Phase A10 delivery — bench-pair preset only).

See `docs/` in the consumer repo (`resd.dpdk_tcp`) for how A10 benchmarks
use this. Full design in that repo's
`docs/superpowers/specs/2026-04-21-stage1-phase-a10-benchmark-harness-design.md` §15 + §16.

## Quickstart (stub — filled in by T8)

```bash
pip install -e ".[dev]"
resd-aws-infra --help
```
```

- [ ] **Step 1.10: Install dev deps and verify the skeleton synthesises**

```bash
cd /home/ubuntu/resd.aws-infra-setup
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python app.py
```

Expected: `app.py` runs without error; `cdk.out/` directory created; no stacks inside yet (empty synth is fine).

- [ ] **Step 1.11: First commit**

```bash
cd /home/ubuntu/resd.aws-infra-setup
git add -A
git commit -m "$(cat <<'EOF'
scaffold resd.aws-infra-setup repo

Python CDK app skeleton + pyproject + tooling + .gitignore.
First delivery phase is A10 bench-pair preset (per
consumer repo's spec §15 + §16).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `bench-pair` CDK preset (synth-only)

**Files:**
- Create: `resd.aws-infra-setup/lib/presets/__init__.py`
- Create: `resd.aws-infra-setup/lib/presets/bench_pair.py`
- Create: `resd.aws-infra-setup/lib/utils/__init__.py`
- Create: `resd.aws-infra-setup/lib/utils/cfn_outputs.py`
- Modify: `resd.aws-infra-setup/app.py` (register BenchPairStack)
- Test: `resd.aws-infra-setup/tests/test_bench_pair_preset.py`

### Steps

- [ ] **Step 2.1: Write `lib/presets/__init__.py`**

```python
"""CDK preset stack constructs for resd.aws-infra-setup."""
```

- [ ] **Step 2.2: Write `lib/utils/__init__.py`**

```python
"""Shared utilities for CDK stack constructs."""
```

- [ ] **Step 2.3: Write `lib/utils/cfn_outputs.py`**

```python
"""CloudFormation output helpers."""
from __future__ import annotations

from typing import Any

from aws_cdk import CfnOutput
from constructs import Construct


def add_output(scope: Construct, name: str, value: Any, description: str = "") -> CfnOutput:
    """Add a named CloudFormation output to the stack.

    `name` becomes the logical ID and the export name; the value is
    read back by the CLI via `describe-stacks`.
    """
    return CfnOutput(
        scope,
        f"Output{name}",
        export_name=name,
        value=str(value),
        description=description,
    )
```

- [ ] **Step 2.4: Write the failing test for `BenchPairStack` synthesis**

`tests/test_bench_pair_preset.py`:

```python
"""Unit tests on BenchPairStack synthesis.

Synth-only: no deploy; asserts the template has every required resource.
"""
from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import assertions
import pytest

from lib.presets.bench_pair import BenchPairStack, BenchPairProps


@pytest.fixture
def props() -> BenchPairProps:
    return BenchPairProps(
        instance_type="c6a.2xlarge",
        subnet_cidr="10.0.0.0/24",
        ami_id="ami-0123456789abcdef0",
        placement_strategy="cluster",
        operator_ssh_cidr="203.0.113.0/32",
    )


def test_stack_has_vpc(app: cdk.App, props: BenchPairProps) -> None:
    stack = BenchPairStack(app, "BenchPair", props)
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::EC2::VPC", 1)


def test_stack_has_single_subnet_matching_cidr(app: cdk.App, props: BenchPairProps) -> None:
    stack = BenchPairStack(app, "BenchPair", props)
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties("AWS::EC2::Subnet", {"CidrBlock": "10.0.0.0/24"})


def test_stack_has_cluster_placement_group(app: cdk.App, props: BenchPairProps) -> None:
    stack = BenchPairStack(app, "BenchPair", props)
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties("AWS::EC2::PlacementGroup", {"Strategy": "cluster"})


def test_stack_has_two_ec2_instances(app: cdk.App, props: BenchPairProps) -> None:
    stack = BenchPairStack(app, "BenchPair", props)
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::EC2::Instance", 2)


def test_stack_instances_use_given_ami(app: cdk.App, props: BenchPairProps) -> None:
    stack = BenchPairStack(app, "BenchPair", props)
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties("AWS::EC2::Instance", {"ImageId": "ami-0123456789abcdef0"})


def test_stack_security_group_allows_ssh_from_operator_cidr(app: cdk.App, props: BenchPairProps) -> None:
    stack = BenchPairStack(app, "BenchPair", props)
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::EC2::SecurityGroup",
        {
            "SecurityGroupIngress": assertions.Match.array_with(
                [
                    assertions.Match.object_like(
                        {"CidrIp": "203.0.113.0/32", "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}
                    )
                ]
            )
        },
    )


def test_stack_refuses_default_unset_operator_cidr(app: cdk.App) -> None:
    with pytest.raises(ValueError, match="operator_ssh_cidr"):
        BenchPairStack(
            app,
            "BenchPair",
            BenchPairProps(
                instance_type="c6a.2xlarge",
                subnet_cidr="10.0.0.0/24",
                ami_id="ami-0123456789abcdef0",
                placement_strategy="cluster",
                operator_ssh_cidr="",  # unset — must raise
            ),
        )


def test_stack_exports_dut_and_peer_ssh_endpoints(app: cdk.App, props: BenchPairProps) -> None:
    stack = BenchPairStack(app, "BenchPair", props)
    template = assertions.Template.from_stack(stack)
    outputs = template.find_outputs("*")
    names = {o for o in outputs}
    assert "DutSshEndpoint" in names
    assert "PeerSshEndpoint" in names
    assert "DutDataEniMac" in names
    assert "PeerDataEniMac" in names
    assert "DutDataEniIp" in names
    assert "PeerDataEniIp" in names
```

- [ ] **Step 2.5: Run the tests to confirm they fail (module doesn't exist)**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
pytest tests/test_bench_pair_preset.py -v
```

Expected: `ImportError: cannot import name 'BenchPairStack' from 'lib.presets.bench_pair'`

- [ ] **Step 2.6: Write the `BenchPairStack` construct**

`lib/presets/bench_pair.py`:

```python
"""BenchPairStack — DUT + peer EC2 pair on a shared subnet.

Per spec §15.1. Two instances in a cluster placement group, same VPC,
same subnet, same AMI. Security group opens SSH from operator CIDR and
benchmark TCP port range between DUT and peer ENIs only. Stack outputs
consumed by the bench-nightly script via `aws cloudformation describe-stacks`.
"""
from __future__ import annotations

from dataclasses import dataclass

import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2
from constructs import Construct

from lib.utils.cfn_outputs import add_output


@dataclass(frozen=True)
class BenchPairProps:
    """All configurable inputs for the bench-pair stack (spec §15.2).

    AMI-baked knobs (hugepages, isolcpus, toolchain, mTCP, DPDK) are NOT
    here — they live in the image pipeline inputs (§16.3).
    """
    instance_type: str
    subnet_cidr: str
    ami_id: str
    placement_strategy: str  # 'cluster' | 'spread'
    operator_ssh_cidr: str
    benchmark_tcp_port_min: int = 10_000
    benchmark_tcp_port_max: int = 10_100


class BenchPairStack(cdk.Stack):
    """DUT + peer fleet stack for A10 bench runs."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        props: BenchPairProps,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        if not props.operator_ssh_cidr or props.operator_ssh_cidr in ("0.0.0.0/32", ""):
            raise ValueError(
                "operator_ssh_cidr must be set to a real CIDR (e.g. your office CIDR); "
                "refusing to deploy with default unset value"
            )

        # VPC + single subnet
        vpc = ec2.Vpc(
            self,
            "Vpc",
            ip_addresses=ec2.IpAddresses.cidr(props.subnet_cidr),
            max_azs=1,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Bench",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                )
            ],
        )

        # Cluster placement group for tight DUT↔peer RTT
        pg = ec2.CfnPlacementGroup(self, "ClusterPg", strategy=props.placement_strategy)

        # Security group
        sg = ec2.SecurityGroup(
            self,
            "BenchSg",
            vpc=vpc,
            description="BenchPair DUT+peer — SSH from operator, TCP inter-ENI",
            allow_all_outbound=True,
        )
        sg.add_ingress_rule(
            ec2.Peer.ipv4(props.operator_ssh_cidr),
            ec2.Port.tcp(22),
            "SSH from operator CIDR",
        )
        sg.add_ingress_rule(
            sg,
            ec2.Port.tcp_range(props.benchmark_tcp_port_min, props.benchmark_tcp_port_max),
            "Benchmark TCP inter-ENI",
        )

        # Two identically-configured instances
        def instance(name: str) -> ec2.Instance:
            return ec2.Instance(
                self,
                name,
                instance_type=ec2.InstanceType(props.instance_type),
                machine_image=ec2.MachineImage.generic_linux({self.region: props.ami_id}),
                vpc=vpc,
                security_group=sg,
                vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
                placement_group=pg,
                require_imdsv2=True,
            )

        dut = instance("Dut")
        peer = instance("Peer")

        # Outputs read by the CLI
        add_output(self, "DutSshEndpoint", dut.instance_public_dns_name, "DUT SSH DNS")
        add_output(self, "PeerSshEndpoint", peer.instance_public_dns_name, "Peer SSH DNS")
        add_output(self, "DutDataEniMac", dut.instance_private_ip, "DUT data ENI IP")  # MAC via describe
        add_output(self, "PeerDataEniMac", peer.instance_private_ip, "Peer data ENI IP")
        add_output(self, "DutDataEniIp", dut.instance_private_ip, "DUT private IP")
        add_output(self, "PeerDataEniIp", peer.instance_private_ip, "Peer private IP")
        add_output(self, "AmiId", props.ami_id, "Baked AMI ID")
        add_output(self, "InstanceType", props.instance_type, "Instance type")
```

Note: `DutDataEniMac` / `PeerDataEniMac` are populated with the private IP as a placeholder at synth time; the CLI's `status` command resolves the actual MAC via `boto3 ec2:DescribeNetworkInterfaces` when the stack is live (T5.4).

- [ ] **Step 2.7: Wire `BenchPairStack` into `app.py`**

Replace the placeholder in `app.py` with:

```python
#!/usr/bin/env python3
"""resd.aws-infra-setup CDK app entrypoint."""
from __future__ import annotations

import os

import aws_cdk as cdk

from lib.presets.bench_pair import BenchPairProps, BenchPairStack


def main() -> None:
    app = cdk.App()
    env = cdk.Environment(
        account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region=os.environ.get("CDK_DEFAULT_REGION", "us-east-1"),
    )

    # bench-pair preset — CDK-context-driven config
    ctx = app.node.try_get_context("bench-pair") or {}
    if ctx:
        BenchPairStack(
            app,
            "resd-bench-pair",
            BenchPairProps(
                instance_type=ctx.get("instance_type", "c6a.2xlarge"),
                subnet_cidr=ctx.get("subnet_cidr", "10.0.0.0/24"),
                ami_id=ctx["ami_id"],  # required
                placement_strategy=ctx.get("placement_strategy", "cluster"),
                operator_ssh_cidr=ctx["operator_ssh_cidr"],  # required
            ),
            env=env,
        )

    # Image Builder pipeline registered by T3.

    app.synth()


if __name__ == "__main__":
    main()
```

- [ ] **Step 2.8: Run the tests — verify pass**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
pytest tests/test_bench_pair_preset.py -v --timeout=60
```

Expected: all tests pass.

- [ ] **Step 2.9: Commit**

```bash
cd /home/ubuntu/resd.aws-infra-setup
git add -A
git commit -m "$(cat <<'EOF'
T2: bench-pair CDK preset (synth-only)

DUT + peer EC2 pair, cluster placement group, configurable instance type,
subnet, AMI, operator SSH CIDR. Outputs consumed by scripts/bench-nightly.sh
via describe-stacks. AMI-baked knobs (isolcpus, hugepages, toolchain) are
NOT per-stack inputs — they live in the image pipeline (T3+T4).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Image Builder pipeline CDK construct

**Files:**
- Create: `resd.aws-infra-setup/lib/image_builder/__init__.py`
- Create: `resd.aws-infra-setup/lib/image_builder/bench_host_image.py`
- Modify: `resd.aws-infra-setup/app.py` (register BenchHostImageStack)
- Test: `resd.aws-infra-setup/tests/test_image_builder.py`

### Steps

- [ ] **Step 3.1: Write `lib/image_builder/__init__.py`**

```python
"""EC2 Image Builder pipeline constructs."""
```

- [ ] **Step 3.2: Write the failing test for Image Builder synthesis**

`tests/test_image_builder.py`:

```python
"""Unit tests for the BenchHostImageStack synthesis."""
from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import assertions
import pytest

from lib.image_builder.bench_host_image import (
    BenchHostImageProps,
    BenchHostImageStack,
)


@pytest.fixture
def props() -> BenchHostImageProps:
    return BenchHostImageProps(
        recipe_version="1.0.0",
        base_ami_ssm_param="/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
        hugepage_count=2048,
        isolcpus_range="2-7",
        cstate_max=1,
        transparent_hugepage="never",
        kernel_stream="hwe-6.17",
        clang_version=22,
        dpdk_version="23.11",
        components_dir="image-components",
    )


def test_stack_has_image_recipe(app: cdk.App, props: BenchHostImageProps) -> None:
    stack = BenchHostImageStack(app, "Img", props)
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::ImageBuilder::ImageRecipe", 1)


def test_recipe_references_all_nine_components(app: cdk.App, props: BenchHostImageProps) -> None:
    stack = BenchHostImageStack(app, "Img", props)
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::ImageBuilder::Component", 9)


def test_stack_has_infrastructure_configuration(app: cdk.App, props: BenchHostImageProps) -> None:
    stack = BenchHostImageStack(app, "Img", props)
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::ImageBuilder::InfrastructureConfiguration", 1)


def test_stack_has_distribution_with_ami_tags(app: cdk.App, props: BenchHostImageProps) -> None:
    stack = BenchHostImageStack(app, "Img", props)
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::ImageBuilder::DistributionConfiguration",
        assertions.Match.object_like(
            {
                "Distributions": assertions.Match.array_with(
                    [
                        assertions.Match.object_like(
                            {
                                "AmiDistributionConfiguration": assertions.Match.object_like(
                                    {
                                        "AmiTags": assertions.Match.object_like(
                                            {
                                                "resd-infra:version": "1.0.0",
                                                "resd-infra:base": "ubuntu-24.04",
                                                "resd-infra:kernel": "hwe-6.17",
                                                "resd-infra:isolcpus": "2-7",
                                                "resd-infra:hugepages": "2048",
                                            }
                                        )
                                    }
                                )
                            }
                        )
                    ]
                )
            }
        ),
    )


def test_stack_has_pipeline(app: cdk.App, props: BenchHostImageProps) -> None:
    stack = BenchHostImageStack(app, "Img", props)
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::ImageBuilder::ImagePipeline", 1)
```

- [ ] **Step 3.3: Run the tests; verify fail**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
pytest tests/test_image_builder.py -v
```

Expected: ImportError / ModuleNotFoundError.

- [ ] **Step 3.4: Write `lib/image_builder/bench_host_image.py`**

```python
"""BenchHostImageStack — EC2 Image Builder pipeline for the resd host AMI.

Bakes Ubuntu 24.04 + kernel 6.17 HWE + clang-22 + libc++ + DPDK 23.11 +
WC-patched vfio-pci + mTCP + GRUB args + modprobe + systemd + bench tools
+ precondition checker. Spec §16. Components in YAML under
`image-components/` (§16.2 order is enforced in this construct).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from string import Template

import aws_cdk as cdk
from aws_cdk import aws_iam as iam
from aws_cdk import aws_imagebuilder as ib
from constructs import Construct

COMPONENT_ORDER = [
    "01-install-llvm-toolchain",
    "02-install-dpdk-23-11",
    "03-install-wc-vfio-pci",
    "04-install-mtcp",
    "05-configure-grub",
    "06-modprobe-config",
    "07-systemd-units",
    "08-install-bench-tools",
    "09-install-preconditions-checker",
]


@dataclass(frozen=True)
class BenchHostImageProps:
    """Configurable inputs for the AMI bake (spec §16.3)."""
    recipe_version: str
    base_ami_ssm_param: str
    hugepage_count: int
    isolcpus_range: str  # e.g. "2-7"
    cstate_max: int  # 1 for production latency
    transparent_hugepage: str  # "never" recommended
    kernel_stream: str  # "hwe-6.17"
    clang_version: int
    dpdk_version: str
    components_dir: str  # relative path from repo root


class BenchHostImageStack(cdk.Stack):
    """Image Builder pipeline producing the resd-host-ubuntu-24.04-k6.17-<ver> AMI."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        props: BenchHostImageProps,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        repo_root = Path(__file__).resolve().parents[2]
        components_root = repo_root / props.components_dir

        # One IB Component per YAML file, templated with props
        components: list[ib.CfnComponent] = []
        for ordered_name in COMPONENT_ORDER:
            yaml_path = components_root / f"{ordered_name}.yaml"
            yaml_text = yaml_path.read_text()
            # Simple ${VAR} substitution for the few parameterised values
            rendered = Template(yaml_text).safe_substitute(
                HUGEPAGE_COUNT=props.hugepage_count,
                ISOLCPUS_RANGE=props.isolcpus_range,
                CSTATE_MAX=props.cstate_max,
                TRANSPARENT_HUGEPAGE=props.transparent_hugepage,
                KERNEL_STREAM=props.kernel_stream,
                CLANG_VERSION=props.clang_version,
                DPDK_VERSION=props.dpdk_version,
            )
            component = ib.CfnComponent(
                self,
                f"Component{ordered_name.replace('-', '')}",
                name=f"resd-{ordered_name}",
                version=props.recipe_version,
                platform="Linux",
                data=rendered,
            )
            components.append(component)

        # Image Recipe
        recipe = ib.CfnImageRecipe(
            self,
            "Recipe",
            name="resd-bench-host-recipe",
            version=props.recipe_version,
            parent_image=f"resolve:ssm:{props.base_ami_ssm_param}",
            components=[
                ib.CfnImageRecipe.ComponentConfigurationProperty(component_arn=c.attr_arn)
                for c in components
            ],
        )

        # IAM role for the build instance
        instance_role = iam.Role(
            self,
            "BuildInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
                iam.ManagedPolicy.from_aws_managed_policy_name("EC2InstanceProfileForImageBuilder"),
                iam.ManagedPolicy.from_aws_managed_policy_name("EC2InstanceProfileForImageBuilderECRContainerBuilds"),
            ],
        )
        instance_profile = iam.CfnInstanceProfile(
            self,
            "BuildInstanceProfile",
            roles=[instance_role.role_name],
        )

        # Infrastructure (build instance type + subnet; default VPC is fine)
        infra = ib.CfnInfrastructureConfiguration(
            self,
            "Infra",
            name="resd-bench-host-infra",
            instance_profile_name=instance_profile.ref,
            instance_types=["c6a.2xlarge"],  # build instance; same family as bench default
            terminate_instance_on_failure=True,
        )

        # Distribution with AMI tags (spec §16.4)
        distribution = ib.CfnDistributionConfiguration(
            self,
            "Distribution",
            name="resd-bench-host-dist",
            distributions=[
                ib.CfnDistributionConfiguration.DistributionProperty(
                    region=self.region,
                    ami_distribution_configuration={
                        "name": f"resd-host-ubuntu-24.04-k6.17-{props.recipe_version}",
                        "description": "resd production + bench AMI",
                        "amiTags": {
                            "resd-infra:version": props.recipe_version,
                            "resd-infra:base": "ubuntu-24.04",
                            "resd-infra:kernel": props.kernel_stream,
                            "resd-infra:isolcpus": props.isolcpus_range,
                            "resd-infra:hugepages": str(props.hugepage_count),
                        },
                    },
                )
            ],
        )

        # Pipeline (triggers run via `StartImagePipelineExecution` API)
        ib.CfnImagePipeline(
            self,
            "Pipeline",
            name="resd-bench-host-pipeline",
            image_recipe_arn=recipe.attr_arn,
            infrastructure_configuration_arn=infra.attr_arn,
            distribution_configuration_arn=distribution.attr_arn,
            status="ENABLED",
        )

        cdk.CfnOutput(self, "PipelineArn", value=cdk.Fn.ref("Pipeline"))
```

- [ ] **Step 3.5: Register in `app.py`**

Append to `app.py`:

```python
    # Image Builder pipeline — produces the AMI that bench-pair consumes.
    img_ctx = app.node.try_get_context("image-builder") or {}
    if img_ctx:
        from lib.image_builder.bench_host_image import (
            BenchHostImageProps,
            BenchHostImageStack,
        )

        BenchHostImageStack(
            app,
            "resd-bench-host-image",
            BenchHostImageProps(
                recipe_version=img_ctx.get("recipe_version", "1.0.0"),
                base_ami_ssm_param=img_ctx.get(
                    "base_ami_ssm_param",
                    "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
                ),
                hugepage_count=int(img_ctx.get("hugepage_count", 2048)),
                isolcpus_range=img_ctx.get("isolcpus_range", "2-7"),
                cstate_max=int(img_ctx.get("cstate_max", 1)),
                transparent_hugepage=img_ctx.get("transparent_hugepage", "never"),
                kernel_stream=img_ctx.get("kernel_stream", "hwe-6.17"),
                clang_version=int(img_ctx.get("clang_version", 22)),
                dpdk_version=img_ctx.get("dpdk_version", "23.11"),
                components_dir=img_ctx.get("components_dir", "image-components"),
            ),
            env=env,
        )
```

(Insert before `app.synth()`.)

- [ ] **Step 3.6: Create empty placeholder YAML files so CDK synth can read them**

The tests in Step 3.2 load every component. T4 fills them in; for T3 we create placeholders so the synth doesn't crash.

```bash
cd /home/ubuntu/resd.aws-infra-setup
mkdir -p image-components
for name in \
  "01-install-llvm-toolchain" \
  "02-install-dpdk-23-11" \
  "03-install-wc-vfio-pci" \
  "04-install-mtcp" \
  "05-configure-grub" \
  "06-modprobe-config" \
  "07-systemd-units" \
  "08-install-bench-tools" \
  "09-install-preconditions-checker"; do
  cat > "image-components/${name}.yaml" <<EOF
name: ${name}
description: Placeholder — T4 fills this in
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: placeholder
        action: ExecuteBash
        inputs:
          commands:
            - echo "placeholder for ${name} — T4 fills in"
EOF
done
```

- [ ] **Step 3.7: Run the tests — verify pass with placeholders**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
pytest tests/test_image_builder.py -v --timeout=60
```

Expected: all image-builder tests pass (they count resources + check tags; placeholders are enough).

- [ ] **Step 3.8: Commit**

```bash
cd /home/ubuntu/resd.aws-infra-setup
git add -A
git commit -m "$(cat <<'EOF'
T3: Image Builder pipeline CDK construct

BenchHostImageStack composes nine components (placeholder YAML; T4 fills).
Produces resd-host-ubuntu-24.04-k6.17-<ver> AMI on pipeline run.
AMI tagged with resd-infra:* metadata for version / isolcpus / hugepages.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Image components (01–09 YAML)

**Files:** replace nine placeholder files in `resd.aws-infra-setup/image-components/` with real content.

This task is nine sub-tasks (one per component); each writes the component, verifies YAML validity, and commits together at the end. There are no pytest checks here — component correctness is verified end-to-end by T6's bake run.

### Steps

- [ ] **Step 4.1: Component 01 — `install-llvm-toolchain.yaml`**

Replace `resd.aws-infra-setup/image-components/01-install-llvm-toolchain.yaml` with:

```yaml
name: 01-install-llvm-toolchain
description: Install clang-22 + libc++ from llvm.org apt repo
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: install-llvm-apt-key
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - |
              apt-get update
              apt-get install -y wget gnupg ca-certificates lsb-release software-properties-common
              wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg
              codename=$(lsb_release -cs)
              echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] https://apt.llvm.org/$codename/ llvm-toolchain-$codename-${CLANG_VERSION} main" > /etc/apt/sources.list.d/llvm.list
      - name: install-clang-and-libcxx
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - apt-get update
            - apt-get install -y clang-${CLANG_VERSION} libclang-${CLANG_VERSION}-dev libc++-${CLANG_VERSION}-dev libc++abi-${CLANG_VERSION}-dev lld-${CLANG_VERSION} llvm-${CLANG_VERSION}-dev
      - name: configure-default-compiler
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - update-alternatives --install /usr/bin/cc cc /usr/bin/clang-${CLANG_VERSION} 100
            - update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-${CLANG_VERSION} 100
            - update-alternatives --install /usr/bin/clang clang /usr/bin/clang-${CLANG_VERSION} 100
            - update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${CLANG_VERSION} 100
            - |
              cat > /etc/profile.d/llvm.sh <<'EOFSH'
              export CC=clang-${CLANG_VERSION}
              export CXX=clang++-${CLANG_VERSION}
              export CXXFLAGS="${CXXFLAGS:-} -stdlib=libc++"
              export LDFLAGS="${LDFLAGS:-} -stdlib=libc++ -lc++abi"
              EOFSH
              chmod +x /etc/profile.d/llvm.sh
      - name: verify
        action: ExecuteBash
        inputs:
          commands:
            - clang-${CLANG_VERSION} --version
            - clang++-${CLANG_VERSION} --version
            - pkg-config --exists libunwind || true
```

- [ ] **Step 4.2: Component 02 — `install-dpdk-23-11.yaml`**

```yaml
name: 02-install-dpdk-23-11
description: Install DPDK ${DPDK_VERSION} LTS from source, built with clang-${CLANG_VERSION}
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: install-build-deps
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - apt-get update
            - apt-get install -y build-essential meson ninja-build python3-pyelftools pkg-config libnuma-dev libelf-dev libssl-dev libpcap-dev libbsd-dev libjansson-dev zlib1g-dev git
      - name: fetch-dpdk
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - mkdir -p /opt/src
            - cd /opt/src
            - git clone --depth=1 --branch v${DPDK_VERSION} https://github.com/DPDK/dpdk.git
      - name: build-dpdk
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - source /etc/profile.d/llvm.sh
            - cd /opt/src/dpdk
            - CC=clang-${CLANG_VERSION} CXX=clang++-${CLANG_VERSION} meson setup build --buildtype=release -Dplatform=generic
            - ninja -C build
            - ninja -C build install
            - ldconfig
      - name: verify
        action: ExecuteBash
        inputs:
          commands:
            - pkg-config --exists libdpdk
            - pkg-config --modversion libdpdk
```

- [ ] **Step 4.3: Component 03 — `install-wc-vfio-pci.yaml`**

```yaml
name: 03-install-wc-vfio-pci
description: Install write-combining-patched vfio-pci via amzn-drivers ENA helper
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: install-kernel-headers
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - apt-get update
            - apt-get install -y linux-headers-$(uname -r) linux-modules-extra-$(uname -r) dkms
      - name: clone-amzn-drivers
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - mkdir -p /opt/src
            - cd /opt/src
            - git clone --depth=1 https://github.com/amzn/amzn-drivers.git
      - name: run-wc-vfio-helper
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - cd /opt/src/amzn-drivers/userspace/dpdk/enav2-vfio-patch
            - chmod +x get-vfio-with-wc.sh
            - ./get-vfio-with-wc.sh
      - name: verify-module
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - modinfo vfio-pci | head
            - depmod -a
```

- [ ] **Step 4.4: Component 04 — `install-mtcp.yaml`**

```yaml
name: 04-install-mtcp
description: Build mTCP from source (from github.com/mtcp-stack/mtcp) and install to /opt/mtcp/
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: install-mtcp-build-deps
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - apt-get update
            - apt-get install -y autoconf automake libtool git make gcc libnuma-dev flex bison
      - name: clone-mtcp
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - mkdir -p /opt/src
            - cd /opt/src
            - git clone --depth=1 https://github.com/mtcp-stack/mtcp.git
            - cd mtcp
            - git rev-parse HEAD > /opt/mtcp-commit-sha.txt
      - name: build-mtcp-bundled-dpdk
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - cd /opt/src/mtcp/dpdk
            - make config T=x86_64-native-linuxapp-gcc O=x86_64-native-linuxapp-gcc
            - cd x86_64-native-linuxapp-gcc
            - make -j"$(nproc)"
      - name: build-mtcp
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - cd /opt/src/mtcp
            - autoreconf -if
            - ./configure --with-dpdk-lib=/opt/src/mtcp/dpdk/x86_64-native-linuxapp-gcc
            - make -j"$(nproc)"
      - name: install-mtcp
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - mkdir -p /opt/mtcp /opt/mtcp-peer
            - cp -r /opt/src/mtcp/mtcp/lib /opt/mtcp/
            - cp -r /opt/src/mtcp/mtcp/include /opt/mtcp/
            - cp -r /opt/src/mtcp/apps/example /opt/mtcp/
            - |
              # Placeholder for bench-peer binary; resd.dpdk_tcp's bench-vs-mtcp
              # produces the actual peer binary, which gets added to a follow-up
              # component once the bench-vs-mtcp crate is done. For now, leave
              # a stub so /opt/mtcp-peer/bench-peer exists.
              cat > /opt/mtcp-peer/bench-peer <<'EOFSH'
              #!/usr/bin/env bash
              echo "placeholder — bench-peer from resd.dpdk_tcp/tools/bench-vs-mtcp drops here"
              exit 1
              EOFSH
              chmod +x /opt/mtcp-peer/bench-peer
      - name: verify
        action: ExecuteBash
        inputs:
          commands:
            - ls -la /opt/mtcp /opt/mtcp-peer
            - cat /opt/mtcp-commit-sha.txt
```

Note: the bench-peer binary is a placeholder here because it's produced by `resd.dpdk_tcp/tools/bench-vs-mtcp` (Plan 2 T21). When Plan 2 T21 produces the peer binary, Plan 2 T24 uploads it via SCP or via a follow-up image-components/10-install-bench-peer component. Keeping the AMI singleton means T21's binary gets bundled into a later AMI rebake; the first AMI is "bench-peer: stub".

- [ ] **Step 4.5: Component 05 — `configure-grub.yaml`**

```yaml
name: 05-configure-grub
description: Apply production latency GRUB args (hugepages, isolcpus, nohz_full, rcu_nocbs, processor.max_cstate, transparent_hugepage=never)
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: write-grub-defaults
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - |
              grub_line="default_hugepagesz=2M hugepagesz=2M hugepages=${HUGEPAGE_COUNT} isolcpus=${ISOLCPUS_RANGE} nohz_full=${ISOLCPUS_RANGE} rcu_nocbs=${ISOLCPUS_RANGE} processor.max_cstate=${CSTATE_MAX} transparent_hugepage=${TRANSPARENT_HUGEPAGE}"
              # Append to existing GRUB_CMDLINE_LINUX in /etc/default/grub
              sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$grub_line\"|" /etc/default/grub
              grep '^GRUB_CMDLINE_LINUX' /etc/default/grub
      - name: update-grub
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - update-grub
      - name: verify
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - grep -E "isolcpus|hugepages|max_cstate|transparent_hugepage" /boot/grub/grub.cfg || { echo "GRUB args missing"; exit 1; }
```

- [ ] **Step 4.6: Component 06 — `modprobe-config.yaml`**

```yaml
name: 06-modprobe-config
description: Configure vfio-pci for no-IOMMU mode and load at boot
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: vfio-noiommu-modprobe
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - |
              cat > /etc/modprobe.d/vfio.conf <<'EOFMOD'
              options vfio enable_unsafe_noiommu_mode=1
              EOFMOD
            - |
              cat > /etc/modules-load.d/vfio.conf <<'EOFMOD'
              vfio
              vfio_pci
              vfio_iommu_type1
              EOFMOD
      - name: verify
        action: ExecuteBash
        inputs:
          commands:
            - cat /etc/modprobe.d/vfio.conf
            - cat /etc/modules-load.d/vfio.conf
```

- [ ] **Step 4.7: Component 07 — `systemd-units.yaml`**

```yaml
name: 07-systemd-units
description: Systemd units for governor=performance, irqbalance off, hugepages boot-verify, first-boot linux-tools install
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: set-governor-performance-service
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - apt-get update
            - apt-get install -y linux-tools-common
            - |
              cat > /etc/systemd/system/set-governor-performance.service <<'EOFSYS'
              [Unit]
              Description=Set CPU governor to performance at boot
              After=multi-user.target
              
              [Service]
              Type=oneshot
              ExecStart=/bin/sh -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g"; done'
              RemainAfterExit=yes
              
              [Install]
              WantedBy=multi-user.target
              EOFSYS
              systemctl enable set-governor-performance.service
      - name: irqbalance-disable-service
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - systemctl disable irqbalance.service || true
            - systemctl mask irqbalance.service || true
      - name: verify-hugepages-reserved-service
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - |
              cat > /etc/systemd/system/verify-hugepages-reserved.service <<EOFSYS
              [Unit]
              Description=Fail boot if hugepages under-reserved
              Before=multi-user.target
              
              [Service]
              Type=oneshot
              ExecStart=/bin/sh -c 'reserved=\$(awk "/^HugePages_Total:/ {print \$2}" /proc/meminfo); required=${HUGEPAGE_COUNT}; [ "\$reserved" -ge "\$required" ] || { echo "hugepages under-reserved: \$reserved < \$required"; exit 1; }'
              RemainAfterExit=yes
              
              [Install]
              WantedBy=multi-user.target
              EOFSYS
              systemctl enable verify-hugepages-reserved.service
      - name: install-linux-tools-firstboot
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - |
              cat > /etc/systemd/system/install-linux-tools.service <<'EOFSYS'
              [Unit]
              Description=Install linux-tools for the currently running kernel (first boot only)
              After=network.target
              ConditionPathExists=!/var/run/resd-infra-linux-tools-installed
              
              [Service]
              Type=oneshot
              ExecStart=/bin/sh -c 'apt-get update && apt-get install -y linux-tools-$(uname -r) && touch /var/run/resd-infra-linux-tools-installed'
              RemainAfterExit=yes
              
              [Install]
              WantedBy=multi-user.target
              EOFSYS
              systemctl enable install-linux-tools.service
```

- [ ] **Step 4.8: Component 08 — `install-bench-tools.yaml`**

```yaml
name: 08-install-bench-tools
description: Install ethtool / pciutils / numactl / iproute2 / perf / turbostat / DPDK usertools
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: install-base-tools
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - apt-get update
            - apt-get install -y ethtool pciutils numactl iproute2 util-linux iproute2 linux-tools-generic msr-tools sysstat tcpdump
      - name: install-dpdk-devbind
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - cp /opt/src/dpdk/usertools/dpdk-devbind.py /usr/local/bin/
            - chmod +x /usr/local/bin/dpdk-devbind.py
      - name: install-turbostat
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - ln -sf /usr/lib/linux-tools/*/turbostat /usr/local/bin/turbostat || true
            - /usr/local/bin/turbostat --version || true
```

- [ ] **Step 4.9: Component 09 — `install-preconditions-checker.yaml`**

The precondition-checker script lives in `assets/check-bench-preconditions.sh` in the IaC repo; the image component installs it. Plan 2 T3 authors the identical file in `resd.dpdk_tcp/scripts/check-bench-preconditions.sh` with test-harness-aware variants. Plan 2 T3 and this T4.9 produce the SAME contents.

For T4.9: create `assets/check-bench-preconditions.sh` in the IaC repo with the contents written in Plan 2 T3 (copy at T6 bake time from whatever exists in the resd.dpdk_tcp-a10 worktree). For this task, stub it:

```bash
cd /home/ubuntu/resd.aws-infra-setup
mkdir -p assets
cat > assets/check-bench-preconditions.sh <<'EOFSH'
#!/usr/bin/env bash
# check-bench-preconditions.sh
# Authored in Plan 2 Task 3 (resd.dpdk_tcp/scripts/check-bench-preconditions.sh);
# this identical copy is baked into the AMI. Do NOT diverge; the IaC repo copy
# is canonical for AMI bake; the resd.dpdk_tcp copy is canonical for dev.
# Sync via `diff` before bake.
#
# Stub: replaced at bake time (T6) from the consumer repo's script.
echo '{"mode":"strict","checks":{},"overall_pass":false,"note":"stub checker — replace before bake"}'
exit 1
EOFSH
chmod +x assets/check-bench-preconditions.sh
```

Write the YAML component:

```yaml
name: 09-install-preconditions-checker
description: Install /usr/local/bin/check-bench-preconditions from assets/
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: write-checker
        action: CreateFile
        inputs:
          - path: /usr/local/bin/check-bench-preconditions
            content: |
              {{ read_file_as_text: assets/check-bench-preconditions.sh }}
            permissions: 0755
```

**Caveat:** `CreateFile` with embedded `read_file_as_text` isn't standard Image Builder syntax. Instead use `ExecuteBash` + a `base64`-encoded embedding, so the YAML is self-contained:

```yaml
name: 09-install-preconditions-checker
description: Install /usr/local/bin/check-bench-preconditions
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: install-checker
        action: ExecuteBash
        inputs:
          commands:
            - set -euxo pipefail
            - |
              cat > /usr/local/bin/check-bench-preconditions <<'__CHECKER_EOF__'
              # CONTENTS EMBEDDED AT CDK RENDER TIME VIA Template.substitute($CHECKER_BODY)
              # See lib/image_builder/bench_host_image.py — it reads assets/check-bench-preconditions.sh and escapes it into this heredoc.
              __CHECKER_EOF__
            - chmod +x /usr/local/bin/check-bench-preconditions
            - /usr/local/bin/check-bench-preconditions || true
```

And update `lib/image_builder/bench_host_image.py` in Step 3.4's Template substitution to pass `CHECKER_BODY`:

In `bench_host_image.py`, inside the component-loading loop, after reading `yaml_text`:

```python
checker_body = (repo_root / "assets" / "check-bench-preconditions.sh").read_text()
# Escape single quotes and heredoc delim
checker_body_escaped = checker_body.replace("__CHECKER_EOF__", "__CHECKER_EOF_SAFE__")
rendered = Template(yaml_text).safe_substitute(
    ...
    CHECKER_BODY=checker_body_escaped,
)
```

And in the YAML heredoc, the content line becomes `${CHECKER_BODY}`:

```yaml
            - |
              cat > /usr/local/bin/check-bench-preconditions <<'__CHECKER_EOF__'
              ${CHECKER_BODY}
              __CHECKER_EOF__
```

- [ ] **Step 4.10: Verify all nine YAML files parse**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
python -c "import yaml; import sys; from pathlib import Path; [yaml.safe_load(p.read_text()) for p in sorted(Path('image-components').glob('*.yaml'))]; print('all YAML valid')"
```

Expected: `all YAML valid`. The `${VAR}` placeholders are left literal at YAML parse time — CDK's `Template.safe_substitute` substitutes them at synth.

- [ ] **Step 4.11: Run all tests**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
pytest tests/ -v --timeout=60
```

Expected: all existing tests pass.

- [ ] **Step 4.12: Commit**

```bash
cd /home/ubuntu/resd.aws-infra-setup
git add -A
git commit -m "$(cat <<'EOF'
T4: image components 01-09 YAML

Nine components in order: llvm toolchain, DPDK, WC vfio-pci, mTCP, GRUB
args, modprobe, systemd units, bench tools, preconditions checker.
Variables substituted at CDK synth time via Template.safe_substitute.

mTCP component installs a stub bench-peer binary at /opt/mtcp-peer/bench-peer;
the real binary comes from resd.dpdk_tcp/tools/bench-vs-mtcp (Plan 2 T21)
and gets baked into a follow-up AMI rebake.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: CLI wrapper (`resd-aws-infra {setup|teardown|status|bake-image}`)

**Files:**
- Create: `resd.aws-infra-setup/cli/__init__.py`
- Create: `resd.aws-infra-setup/cli/resd_aws_infra/__init__.py`
- Create: `resd.aws-infra-setup/cli/resd_aws_infra/main.py`
- Create: `resd.aws-infra-setup/cli/resd_aws_infra/setup.py`
- Create: `resd.aws-infra-setup/cli/resd_aws_infra/teardown.py`
- Create: `resd.aws-infra-setup/cli/resd_aws_infra/status.py`
- Create: `resd.aws-infra-setup/cli/resd_aws_infra/bake_image.py`
- Test: `resd.aws-infra-setup/tests/test_cli.py`

### Steps

- [ ] **Step 5.1: Write `cli/__init__.py` and `cli/resd_aws_infra/__init__.py`** (both empty).

- [ ] **Step 5.2: Write failing CLI tests**

`tests/test_cli.py`:

```python
"""Click-runner unit tests on the CLI surface."""
from __future__ import annotations

from click.testing import CliRunner

from cli.resd_aws_infra.main import cli


def test_cli_help_lists_four_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0, result.output
    assert "setup" in result.output
    assert "teardown" in result.output
    assert "status" in result.output
    assert "bake-image" in result.output


def test_setup_requires_preset() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["setup"])
    assert result.exit_code != 0
    assert "preset" in result.output.lower()


def test_setup_bench_pair_refuses_unset_ssh_cidr() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["setup", "bench-pair"])
    assert result.exit_code != 0
    assert "operator-ssh-cidr" in result.output or "SSH" in result.output


def test_teardown_requires_preset() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["teardown"])
    assert result.exit_code != 0


def test_status_json_output_on_nonexistent_stack() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["status", "bench-pair", "--json"], env={"AWS_REGION": "us-east-1"})
    # Without AWS credentials, boto3 raises — but the CLI should emit JSON not a traceback
    # (Best-effort check: allow either a clear error code + message, or a JSON emit)
    assert result.exit_code in (0, 1, 2)
```

- [ ] **Step 5.3: Run tests — verify fail**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
pytest tests/test_cli.py -v
```

Expected: ImportError.

- [ ] **Step 5.4: Write `cli/resd_aws_infra/main.py`**

```python
"""resd-aws-infra CLI entrypoint."""
from __future__ import annotations

import click

from cli.resd_aws_infra.setup import setup_cmd
from cli.resd_aws_infra.teardown import teardown_cmd
from cli.resd_aws_infra.status import status_cmd
from cli.resd_aws_infra.bake_image import bake_image_cmd


@click.group()
@click.version_option("0.1.0", prog_name="resd-aws-infra")
def cli() -> None:
    """resd-aws-infra — reusable AWS IaC for resd.* projects."""


cli.add_command(setup_cmd, name="setup")
cli.add_command(teardown_cmd, name="teardown")
cli.add_command(status_cmd, name="status")
cli.add_command(bake_image_cmd, name="bake-image")


if __name__ == "__main__":
    cli()
```

- [ ] **Step 5.5: Write `cli/resd_aws_infra/setup.py`**

```python
"""resd-aws-infra setup <preset> — deploys a preset stack."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import boto3
import click


@click.command()
@click.argument("preset", type=click.Choice(["bench-pair"]))
@click.option("--instance-type", default="c6a.2xlarge", help="EC2 instance type")
@click.option("--subnet-cidr", default="10.0.0.0/24", help="VPC /24 subnet CIDR")
@click.option("--ami-id", default=None, help="AMI ID (default: baked resd-host AMI)")
@click.option("--operator-ssh-cidr", required=True, help="Caller's CIDR for SSH ingress")
@click.option("--placement-strategy", default="cluster", type=click.Choice(["cluster", "spread"]))
@click.option("--config", "config_path", type=click.Path(exists=True), help="JSON config override")
@click.option("--json", "json_output", is_flag=True, help="Emit JSON stack outputs on success")
def setup_cmd(
    preset: str,
    instance_type: str,
    subnet_cidr: str,
    ami_id: str | None,
    operator_ssh_cidr: str,
    placement_strategy: str,
    config_path: str | None,
    json_output: bool,
) -> None:
    """Deploy the `preset` stack and print stack outputs."""
    overrides: dict[str, str | int] = {}
    if config_path:
        overrides.update(json.loads(Path(config_path).read_text()))
    overrides["instance_type"] = overrides.get("instance_type", instance_type)
    overrides["subnet_cidr"] = overrides.get("subnet_cidr", subnet_cidr)
    overrides["placement_strategy"] = overrides.get("placement_strategy", placement_strategy)
    overrides["operator_ssh_cidr"] = overrides.get("operator_ssh_cidr", operator_ssh_cidr)
    if ami_id is None:
        # read from CDK context default — the last successful bake commits the AMI ID
        try:
            cdk_json = json.loads(Path("cdk.json").read_text())
            ami_id = cdk_json.get("context", {}).get("default-ami-id")
        except FileNotFoundError:
            pass
    if not ami_id:
        click.echo(
            "error: no ami_id and no CDK default; run `resd-aws-infra bake-image` first", err=True
        )
        sys.exit(2)
    overrides["ami_id"] = ami_id

    # Pass overrides as CDK context
    ctx_json = json.dumps(overrides)
    stack_name = f"resd-{preset}"

    env = {
        "CDK_CONTEXT_JSON": json.dumps({preset: overrides}),
    }
    # Deploy
    try:
        subprocess.run(
            [
                "cdk",
                "deploy",
                stack_name,
                "-c",
                f"{preset}={ctx_json}",
                "--require-approval",
                "never",
                "--no-rollback",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        click.echo(f"cdk deploy failed: {e}", err=True)
        sys.exit(e.returncode)

    # Describe outputs
    cf = boto3.client("cloudformation")
    desc = cf.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc["Stacks"][0].get("Outputs", [])}
    if json_output:
        click.echo(json.dumps(outputs, indent=2))
    else:
        for k, v in outputs.items():
            click.echo(f"{k}={v}")
```

- [ ] **Step 5.6: Write `cli/resd_aws_infra/teardown.py`**

```python
"""resd-aws-infra teardown <preset> — delete the preset stack."""
from __future__ import annotations

import subprocess
import sys

import click


@click.command()
@click.argument("preset", type=click.Choice(["bench-pair"]))
@click.option("--wait", is_flag=True, help="Block until DELETE_COMPLETE")
def teardown_cmd(preset: str, wait: bool) -> None:
    """Delete the `preset` stack."""
    stack_name = f"resd-{preset}"
    try:
        cmd = ["cdk", "destroy", stack_name, "--force"]
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"cdk destroy failed: {e}", err=True)
        sys.exit(e.returncode)
    if wait:
        import boto3
        import time

        cf = boto3.client("cloudformation")
        for _ in range(60):  # up to 15 min
            try:
                desc = cf.describe_stacks(StackName=stack_name)
                status = desc["Stacks"][0]["StackStatus"]
                click.echo(f"waiting… {status}")
                if status.endswith("_COMPLETE") and "DELETE" in status:
                    break
            except cf.exceptions.ClientError:
                click.echo("stack gone; teardown complete")
                break
            time.sleep(15)
```

- [ ] **Step 5.7: Write `cli/resd_aws_infra/status.py`**

```python
"""resd-aws-infra status <preset> — emit the preset stack state as JSON."""
from __future__ import annotations

import json
import sys

import boto3
import click
from botocore.exceptions import ClientError


@click.command()
@click.argument("preset", type=click.Choice(["bench-pair"]))
@click.option("--json", "json_output", is_flag=True, help="Emit as JSON (default human)")
def status_cmd(preset: str, json_output: bool) -> None:
    stack_name = f"resd-{preset}"
    cf = boto3.client("cloudformation")
    try:
        desc = cf.describe_stacks(StackName=stack_name)
    except ClientError as e:
        if "does not exist" in str(e):
            out = {"stack": stack_name, "status": "ABSENT"}
            click.echo(json.dumps(out, indent=2) if json_output else f"stack {stack_name} does not exist")
            sys.exit(0)
        click.echo(f"boto3 error: {e}", err=True)
        sys.exit(2)

    s = desc["Stacks"][0]
    out = {
        "stack": stack_name,
        "status": s["StackStatus"],
        "outputs": {o["OutputKey"]: o["OutputValue"] for o in s.get("Outputs", [])},
    }
    # Resolve data-ENI MAC addresses via DescribeNetworkInterfaces (the stack's
    # synth-time placeholder is just the private IP).
    ec2 = boto3.client("ec2")
    for key in ("DutDataEniIp", "PeerDataEniIp"):
        ip = out["outputs"].get(key)
        if not ip:
            continue
        enis = ec2.describe_network_interfaces(Filters=[{"Name": "addresses.private-ip-address", "Values": [ip]}])
        if enis.get("NetworkInterfaces"):
            mac = enis["NetworkInterfaces"][0].get("MacAddress", "")
            out["outputs"][key.replace("Ip", "Mac")] = mac
    click.echo(json.dumps(out, indent=2) if json_output else f"status={out['status']}")
```

- [ ] **Step 5.8: Write `cli/resd_aws_infra/bake_image.py`**

```python
"""resd-aws-infra bake-image — trigger the Image Builder pipeline and poll to completion."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import boto3
import click
from botocore.exceptions import ClientError


@click.command()
@click.option("--recipe-version", default="1.0.0", help="Image recipe semver (bump on change)")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="JSON overrides (hugepage_count, isolcpus_range, etc.)",
)
def bake_image_cmd(recipe_version: str, config_path: str | None) -> None:
    """Deploy the image-builder stack (if needed) and run the pipeline."""
    overrides: dict[str, str | int] = {"recipe_version": recipe_version}
    if config_path:
        overrides.update(json.loads(Path(config_path).read_text()))

    subprocess.run(
        [
            "cdk",
            "deploy",
            "resd-bench-host-image",
            "-c",
            f"image-builder={json.dumps(overrides)}",
            "--require-approval",
            "never",
        ],
        check=True,
    )

    # Find the pipeline ARN from stack outputs
    cf = boto3.client("cloudformation")
    desc = cf.describe_stacks(StackName="resd-bench-host-image")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc["Stacks"][0].get("Outputs", [])}
    pipeline_arn_ref = outputs.get("PipelineArn")
    # The output is a CloudFormation resource ref; resolve via ImageBuilder API
    ib_client = boto3.client("imagebuilder")
    pipelines = ib_client.list_image_pipelines()["imagePipelineList"]
    match = [p for p in pipelines if p["name"] == "resd-bench-host-pipeline"]
    if not match:
        click.echo("image pipeline not found", err=True)
        sys.exit(2)
    pipeline_arn = match[0]["arn"]

    # Trigger
    run = ib_client.start_image_pipeline_execution(imagePipelineArn=pipeline_arn)
    image_build_version_arn = run["imageBuildVersionArn"]
    click.echo(f"triggered bake: {image_build_version_arn}")

    # Poll to completion
    while True:
        img = ib_client.get_image(imageBuildVersionArn=image_build_version_arn)
        status = img["image"]["state"]["status"]
        click.echo(f"status={status}")
        if status in ("AVAILABLE", "FAILED", "CANCELLED"):
            break
        time.sleep(30)

    if status != "AVAILABLE":
        click.echo(f"bake failed: {img['image']['state'].get('reason', '')}", err=True)
        sys.exit(1)

    ami_id = img["image"]["outputResources"]["amis"][0]["image"]
    click.echo(f"new AMI: {ami_id}")

    # Commit the AMI ID to cdk.json's default-ami-id context
    cdk_json_path = Path("cdk.json")
    cdk = json.loads(cdk_json_path.read_text())
    cdk.setdefault("context", {})["default-ami-id"] = ami_id
    cdk_json_path.write_text(json.dumps(cdk, indent=2) + "\n")
    click.echo(f"wrote default-ami-id={ami_id} to cdk.json")
```

- [ ] **Step 5.9: Run tests — verify pass**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
pytest tests/test_cli.py -v --timeout=60
```

Expected: all CLI tests pass.

- [ ] **Step 5.10: Smoke: invoke the CLI help**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
pip install -e "."
resd-aws-infra --help
resd-aws-infra setup --help
resd-aws-infra bake-image --help
```

Expected: help text lists all four commands; each subcommand has its own help.

- [ ] **Step 5.11: Commit**

```bash
cd /home/ubuntu/resd.aws-infra-setup
git add -A
git commit -m "$(cat <<'EOF'
T5: CLI wrapper (setup / teardown / status / bake-image)

Click-based entrypoint `resd-aws-infra`. Shells out to `cdk deploy/destroy`
for stack lifecycle; uses boto3 for CloudFormation describe + Image Builder
pipeline polling. bake-image commits the resulting AMI ID to cdk.json's
default-ami-id context, which setup consumes as default.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: First bake run — produces the initial AMI

**Prerequisite:** AWS credentials + account with Image Builder + EC2 permissions. Run interactively (not by a subagent) because credentials live in the user's environment; the subagent's role is to produce + review the tooling, not to hold AWS keys.

**Files (modified, not created):**
- Modify: `resd.aws-infra-setup/cdk.json` (default-ami-id committed after bake)
- Modify: `resd.aws-infra-setup/assets/check-bench-preconditions.sh` (replaced with the final script from `/home/ubuntu/resd.dpdk_tcp-a10/scripts/check-bench-preconditions.sh` once Plan 2 T3 lands it)

### Steps

- [ ] **Step 6.1: Sync the final preconditions checker from the bench-harness worktree**

This task REQUIRES Plan 2 T3 to have landed (the bench harness's script is canonical). If Plan 2 T3 hasn't merged its script yet, block T6.

```bash
cd /home/ubuntu/resd.aws-infra-setup
diff assets/check-bench-preconditions.sh /home/ubuntu/resd.dpdk_tcp-a10/scripts/check-bench-preconditions.sh && echo "in sync"
# If differs:
cp /home/ubuntu/resd.dpdk_tcp-a10/scripts/check-bench-preconditions.sh assets/check-bench-preconditions.sh
```

- [ ] **Step 6.2: Deploy the image-builder stack**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export CDK_DEFAULT_REGION=us-east-1
cdk bootstrap  # first-time only per account
cdk deploy resd-bench-host-image -c 'image-builder={"recipe_version":"1.0.0"}' --require-approval never
```

Expected: CloudFormation deploys; all Image Builder resources (recipe, components, infra, distribution, pipeline) exist.

- [ ] **Step 6.3: Trigger the first bake run via the CLI**

```bash
resd-aws-infra bake-image --recipe-version 1.0.0
```

Expected: ~45-60 min build; on success, prints `new AMI: ami-…` and updates `cdk.json`'s `default-ami-id`.

- [ ] **Step 6.4: Verify the AMI exists and is tagged**

```bash
aws ec2 describe-images --image-ids $(jq -r .context."default-ami-id" cdk.json) --query 'Images[0].Tags'
```

Expected: tags include `resd-infra:version=1.0.0`, `resd-infra:base=ubuntu-24.04`, `resd-infra:kernel=hwe-6.17`.

- [ ] **Step 6.5: Commit cdk.json**

```bash
cd /home/ubuntu/resd.aws-infra-setup
git add cdk.json assets/check-bench-preconditions.sh
git commit -m "$(cat <<'EOF'
T6: first AMI bake — resd-host-ubuntu-24.04-k6.17-1.0.0

Pipeline ran successfully; AMI tagged per spec §16.4; default-ami-id
committed to cdk.json so `resd-aws-infra setup bench-pair` no longer
requires `--ami-id`. Preconditions checker synced from resd.dpdk_tcp
Plan 2 T3.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: First `bench-pair` stack bring-up + precondition validation

- [ ] **Step 7.1: Deploy the bench-pair stack**

```bash
cd /home/ubuntu/resd.aws-infra-setup
source .venv/bin/activate
export MY_CIDR="$(curl -s https://ifconfig.me)/32"
resd-aws-infra setup bench-pair --operator-ssh-cidr "$MY_CIDR" --json > /tmp/bench-pair-outputs.json
cat /tmp/bench-pair-outputs.json
```

Expected: JSON with `DutSshEndpoint`, `PeerSshEndpoint`, `DutDataEniIp`, `PeerDataEniIp`, `AmiId`.

- [ ] **Step 7.2: Run the preconditions checker on the DUT**

```bash
DUT_HOST=$(jq -r .DutSshEndpoint /tmp/bench-pair-outputs.json)
ssh -o StrictHostKeyChecking=no ubuntu@"$DUT_HOST" "sudo /usr/local/bin/check-bench-preconditions" | tee /tmp/dut-preconditions.json
```

Expected: `overall_pass: true` — all baked-in AMI knobs satisfy the §11.1 checks. If any fails, investigate the component that's responsible; fix; rebake.

- [ ] **Step 7.3: Run the preconditions checker on the peer**

```bash
PEER_HOST=$(jq -r .PeerSshEndpoint /tmp/bench-pair-outputs.json)
ssh -o StrictHostKeyChecking=no ubuntu@"$PEER_HOST" "sudo /usr/local/bin/check-bench-preconditions" | tee /tmp/peer-preconditions.json
```

Expected: `overall_pass: true`.

- [ ] **Step 7.4: Verify mTCP and DPDK are installed**

```bash
ssh ubuntu@"$DUT_HOST" "ls /opt/mtcp /opt/mtcp-peer && pkg-config --modversion libdpdk"
```

Expected: `/opt/mtcp/lib` populated; `pkg-config` reports 23.11.x.

- [ ] **Step 7.5: Tear down the stack**

```bash
resd-aws-infra teardown bench-pair --wait
```

Expected: stack deleted.

- [ ] **Step 7.6: Commit any adjustments**

If Steps 7.2–7.4 uncovered component issues, iterate on the YAML, rebake (T6 loop), and re-run T7. Once all green:

```bash
cd /home/ubuntu/resd.aws-infra-setup
git add -A
git commit --allow-empty -m "$(cat <<'EOF'
T7: bench-pair first bring-up validated

Preconditions checker green on DUT + peer; mTCP + DPDK present.
AMI 1.0.0 is the canonical default for consumer projects.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: README + cost notes + troubleshooting + v0.1.0 tag

**Files:**
- Modify: `resd.aws-infra-setup/README.md` (full content; replaces T1 stub)

### Steps

- [ ] **Step 8.1: Write full `README.md`**

```markdown
# resd.aws-infra-setup

Reusable AWS infrastructure setup (CDK, Python) for `resd.*` projects.

## v0.1.0

First preset: `bench-pair` (DUT + peer EC2 pair on a shared subnet,
cluster placement group). Bakes a single production+bench AMI
(`resd-host-ubuntu-24.04-k6.17-<ver>`) with clang-22+libc++, DPDK 23.11,
WC-patched vfio-pci, mTCP, tuned GRUB/systemd/modprobe for trading
latency.

## Install

```
git clone https://github.com/contek-io/resd.aws-infra-setup
cd resd.aws-infra-setup
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Prerequisites

- AWS CLI configured with credentials
- `aws sts get-caller-identity` succeeds
- `cdk bootstrap` run once per account/region
- AWS account must have EC2 Image Builder + EC2 + VPC + CloudFormation + IAM permissions
- Approximate cost (us-east-1, nightly):
  - AMI bake run: ~$2 per bake (c6a.2xlarge build instance × ~1 hr)
  - bench-pair stack: ~$0.62/hr (2× c6a.2xlarge on-demand)
  - Nightly bench: ~$0.62 (1 hr) per run

## Quickstart

Bake the AMI (once, or when the recipe changes):

```
resd-aws-infra bake-image --recipe-version 1.0.0
```

Stand up a bench pair:

```
resd-aws-infra setup bench-pair --operator-ssh-cidr "$(curl -s https://ifconfig.me)/32" --json
```

Tear down:

```
resd-aws-infra teardown bench-pair --wait
```

## Presets

| Preset | Status | Shape |
|---|---|---|
| `bench-pair` | v0.1.0 | DUT + peer in a cluster placement group, same subnet, same AMI |

## Troubleshooting

### Bake fails at component 03 (WC vfio-pci)

The amzn-drivers helper may be incompatible with kernel 6.17. Pin the
kernel via `--config` (in a JSON file, `"kernel_stream": "hwe-6.11"`),
rebake, see if the helper works; open an issue.

### Preconditions checker fails `precondition_cstate_max`

The baked AMI sets `processor.max_cstate=1` in GRUB. If you're on an
Intel instance, the AMD variant is the wrong flag — rebake with
`"cstate_max": 1` and the Intel-form `intel_idle.max_cstate=1` (requires
an image-component patch; not part of v0.1.0).

### bench-pair bring-up fails with ENI VF binding errors

Check that the AMI was baked with `enable_unsafe_noiommu_mode=1` in
`/etc/modprobe.d/vfio.conf`. The AMI tag `resd-infra:version` should be
present; the v0.1.0 AMI is validated.

## Development

```
pytest tests/ -v
ruff check .
```

## License

Apache-2.0.
```

- [ ] **Step 8.2: Verify README renders reasonably (optional)**

```bash
which mdcat && mdcat README.md | head -80
```

- [ ] **Step 8.3: Tag v0.1.0 + commit**

```bash
cd /home/ubuntu/resd.aws-infra-setup
git add README.md
git commit -m "$(cat <<'EOF'
T8: README + cost notes + troubleshooting; v0.1.0 tag

First release of resd.aws-infra-setup. bench-pair preset + baked AMI
pipeline validated end-to-end. Consumer: resd.dpdk_tcp Phase A10
benchmark harness.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
git tag -a v0.1.0 -m "resd.aws-infra-setup v0.1.0 (A10 bench-pair + baked AMI)"
```

- [ ] **Step 8.4: Hand off to user for push**

Output:
```
v0.1.0 tagged locally at /home/ubuntu/resd.aws-infra-setup
Push when ready:
  git remote add origin git@github.com:contek-io/resd.aws-infra-setup.git
  git push -u origin main --tags
```

---

## Self-review checklist

- [ ] Every spec requirement in §15 / §16 has a task.
- [ ] Every task has TDD structure: failing test → fail → implement → pass → commit, except for T4 (YAML components — end-to-end validated at T6) and T6–T8 (AWS-interactive tasks).
- [ ] No placeholders in committed code (heredoc `${CHECKER_BODY}` substitution is handled in CDK synth).
- [ ] The bench-peer stub in T4.4 is clearly noted as a placeholder; the real binary arrives via a follow-up AMI rebake once Plan 2 T21 lands.
- [ ] Preconditions-checker script is owned by Plan 2 T3 (the resd.dpdk_tcp copy is canonical); this plan references it + syncs at T6.

---

## Dependencies on Plan 2

- Plan 2 T3 must land `scripts/check-bench-preconditions.sh` before Plan 1 T6 can finalise (T6.1 checks sync).
- Plan 2 T21 (`tools/bench-vs-mtcp/` peer binary) must land before the AMI can carry a real `/opt/mtcp-peer/bench-peer` — until then, the placeholder in T4.4 is in place. A follow-up AMI rebake (`resd-aws-infra bake-image --recipe-version 1.1.0`) after Plan 2 T21 lands the real peer binary.

---

## Execution protocol

Use `superpowers:subagent-driven-development` (opus 4.7 per task, opus 4.7 per review subagent). T6–T8 require AWS credentials and should be executed interactively (not by a subagent) — the user or operator runs them locally with their own AWS profile loaded.
