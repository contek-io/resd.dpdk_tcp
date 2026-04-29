# Code-quality review — a10-dpdk24-adopt

**Reviewer:** opus 4.7 reviewer subagent (T6.4)
**Branch:** a10-dpdk24-adopt
**Worktree path:** `/home/ubuntu/resd.dpdk_tcp-a10-dpdk24`
**Branch HEAD at review:** `bd18ef5` (just-landed T6.3 review report) on top of `a1b909e`
**Reviewed unique-to-W2 commits:** 9 (per `git log --cherry-pick --right-only a10-perf-23.11...HEAD`)

## Verdict

**APPROVED**

Worktree-2's only code change is a mechanical DPDK pkg-config version bump (`23.11` → `24.11`) plus a small new shell script that switches `PKG_CONFIG_PATH` for the worktree. Both are correctly written, internally consistent, and verified to work on this multiarch Ubuntu/x86_64 host. The remaining 8 unique-to-W2 commits are documentation files under `docs/superpowers/reports/perf-dpdk24/`. No accidental code drift.

## Findings

| # | Severity | Commit | File:line | Issue | Recommendation |
|---|---|---|---|---|---|

No code-quality findings. (One cosmetic doc finding on filename underscore/hyphen drift was raised in the T6.3 spec-compliance review and is not duplicated here.)

## What was reviewed

`git diff a10-perf-23.11..HEAD --stat -- ':(exclude)docs/'` yields exactly two files:

```
 crates/dpdk-net-sys/build.rs | 6 +++---
 scripts/use-dpdk24.sh        | 7 +++++++
 2 files changed, 10 insertions(+), 3 deletions(-)
```

Both files are part of `e4b02c1` (`a10-dpdk24: bump atleast_version 23.11 → 24.11`). Every other unique-to-W2 commit touches only files under `docs/superpowers/reports/perf-dpdk24/` (8 markdown files: `summary.md`, `baseline-rebase.md`, `adopt-rte-lcore-var.md`, `adopt-rte-ptr-compress.md`, `adopt-rte-bit-atomic.md`, `adopt-ena-tx-logger.md`, `deferrals.md`, `port-forward-poll-H1.md`).

## `crates/dpdk-net-sys/build.rs` change

Diff:
```
-        .atleast_version("23.11")
+        .atleast_version("24.11")
         .probe("libdpdk")
-        .expect("libdpdk >= 23.11 must be discoverable via pkg-config");
+        .expect("libdpdk >= 24.11 must be discoverable via pkg-config");
...
-        // DPDK 23.11 pulls in ARP/L2TPv2/GTP-PSC headers transitively. Those
+        // DPDK 24.11 pulls in ARP/L2TPv2/GTP-PSC headers transitively. Those
```

Three coordinated edits: the `atleast_version` argument, the `expect` panic message, and the explanatory comment about ARP/L2TPv2/GTP-PSC opaque types. All three reference "24.11" consistently after the change — no lingering "23.11" reference in build.rs (verified via `grep -n "23\.11" crates/dpdk-net-sys/build.rs` which returned zero hits).

The change is the literal recipe in spec §1 D6 ("Bump `atleast_version("23.11")` → `atleast_version("24.11")`") executed faithfully. The bindgen invocation, allowlist patterns, opaque-type list, and resource-dir detection logic are untouched.

## `scripts/use-dpdk24.sh` review

Full content of the new script (7 lines):

```bash
#!/usr/bin/env bash
# Source this before cargo commands in this worktree:
#   source scripts/use-dpdk24.sh
export PKG_CONFIG_PATH=/usr/local/dpdk-24.11/lib/x86_64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH:-}
export LD_LIBRARY_PATH=/usr/local/dpdk-24.11/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}
echo "[use-dpdk24] PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
pkg-config --modversion libdpdk
```

Path correctness on this host:
- `uname -m` returns `x86_64`; `dpkg --print-architecture` returns `amd64`. Multiarch directory is `x86_64-linux-gnu`.
- `/usr/local/dpdk-24.11/lib/x86_64-linux-gnu/pkgconfig/libdpdk.pc` exists (verified `ls -la`).
- `PKG_CONFIG_PATH=/usr/local/dpdk-24.11/lib/x86_64-linux-gnu/pkgconfig pkg-config --modversion libdpdk` returns `24.11.0` (verified).
- `librte_*.so` files exist under `/usr/local/dpdk-24.11/lib/x86_64-linux-gnu/` (verified `ls`); `LD_LIBRARY_PATH` correctly points there for runtime `.so` resolution.

Style review:
- `#!/usr/bin/env bash` shebang is appropriate for a `source`-able script (will not actually exec; `env bash` is conventional).
- `${PKG_CONFIG_PATH:-}` and `${LD_LIBRARY_PATH:-}` use parameter-expansion default-empty form — safely prepends to the env var even when previously unset, no `unbound variable` failure under `set -u`.
- Trailing `pkg-config --modversion libdpdk` confirms-and-displays the resolved DPDK version on source — useful sanity print, surfaces any mismatch immediately.
- `[use-dpdk24]` echo line provides a sourced-from-this-script breadcrumb in shell history.
- File is `chmod +x` per the diff (`new mode 100755`), although `source` doesn't require it; harmless and consistent with `scripts/check-perf-host.sh` which is also exec-bit-set.

The colon-prepend `:${PKG_CONFIG_PATH:-}` results in a leading colon when the var was previously unset (e.g. `/usr/local/dpdk-24.11/.../pkgconfig:`); pkg-config tolerates this (treats trailing empty path entry as harmless), and the trailing colon is the documented bash convention for "if there's an existing PKG_CONFIG_PATH preserve it." Same convention for LD_LIBRARY_PATH. Not a finding.

The script is idempotent under repeated `source` (each invocation re-prepends `/usr/local/dpdk-24.11/lib/x86_64-linux-gnu/pkgconfig:` even if it's already there) — minor cosmetic, but for a worktree-local toolchain switch script this is fine; the duplicates don't change resolution behavior.

## ARM portability check

The user's `project_arm_roadmap` memory says don't bake x86_64-only assumptions into ABI/FFI. The new `scripts/use-dpdk24.sh` hardcodes `x86_64-linux-gnu` in two paths. This is **acceptable** because:
- The script is a developer-convenience pinned to the specific `/usr/local/dpdk-24.11` install on the current AWS dev host.
- On a future ARM host, the equivalent would be `aarch64-linux-gnu`, and the script would be replaced (or the path would need to be parameterized via `$(dpkg-architecture -qDEB_HOST_MULTIARCH)` or `pkg-config` discovery).
- `crates/dpdk-net-sys/build.rs` itself uses pkg-config probing — no architecture string baked in. The actual ABI/FFI code is portable.

When the project grows to ARM testing, this script will need an architecture-aware variant; that's a future concern, not a current finding. Filed as a forward-looking note rather than a finding.

## No-accidental-code-changes verification

Confirmed via `git diff a10-perf-23.11..HEAD --stat -- ':(exclude)docs/'`:
- Only `crates/dpdk-net-sys/build.rs` (3 hunks, +3 -3 = 6 lines changed) and `scripts/use-dpdk24.sh` (new, 7 lines) appear.
- No accidental drift to `crates/dpdk-net-core/`, `tools/`, `include/`, or any other code path between W2 and W1.
- Per `summary.md` Phase 1 attestation: "1064 passed, 1 failed (pre-existing api.rs:288 doctest from base — not introduced by this effort), 10 ignored; harness tests: 5/5 pass; bench compile-check: all 30+ benches compile." No fix commits required between version bump and clean test sweep — consistent with a zero-API-drift rebase.
- Documentation files (`docs/superpowers/reports/perf-dpdk24/*.md`) are observational reports, not policy/spec changes. They live under `docs/` and have no runtime effect.

## Notes

- The single code change (build.rs + use-dpdk24.sh) was already test-verified during T4.2-4.4 per the review prompt note: "clean rebase, 1064 tests pass, 5 harness tests pass." The code-quality reviewer's job here is to verify the change is **mechanically correct and stylistically clean**, which it is.
- All eight unique-to-W2 documentation commits are well-scoped per-task report files. Each report has a consistent header (Worktree, Branch HEAD, DPDK version), a section structure (What changed → Survey result → Decision → A/B → Caveats / future-work), and cross-links to the spec/plan + adjacent reports. The structural consistency aids future readers.
- `scripts/use-dpdk24.sh` is parallel in style to `scripts/check-perf-host.sh` (cherry-picked from a10-perf base). Both live under `scripts/`, both are bash, both have descriptive header comments. Consistent project convention.
- The four per-API adoption reports honestly distinguish "N/A" (no candidate sites) from "deferred-to-e2e" (candidate exists but bench-micro can't measure). The taxonomy is well-defined and applied consistently.
- The `summary.md` "Cherry-pick candidate set for Phase 6" guidance correctly identifies that no W2-specific code commits should land on master directly — Phase 6 should pick from W1 for code, optionally pick W2's survey reports as documentation. This is consistent with the exploratory-landing policy in spec §7.2.

No code-quality blockers. Ready for Phase 6 integration decision.
