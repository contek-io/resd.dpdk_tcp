#!/bin/bash
# bench-ab-runner-gdb.sh — wrapper that runs /tmp/bench-ab-runner under
# gdb-batch and captures a stack trace on SIGSEGV. Used to diagnose the
# silent exit-139 crash observed on the Nth DPDK process invocation in a
# bench-nightly session (see docs/superpowers/reports/a10-ab-driver-debug-v2.md).
#
# stdout/stderr pass through to the parent (bench-offload-ab /
# bench-obs-overhead) so the runner's CSV harvest stays intact. gdb's
# own diagnostic + the post-crash backtrace land in
# /tmp/bench-ab-runner-gdb.log so they don't pollute the CSV stream.

set -u

GDB_LOG="/tmp/bench-ab-runner-gdb.log"

{
    echo
    echo "=== $(date -u +%FT%TZ) gdb wrapper invocation ==="
    echo "wrapper pid: $$"
    echo "args: $*"
} >>"$GDB_LOG"

# Best-effort install if gdb isn't present yet — costs ~5 s on first
# invocation, no-op afterwards. Idempotent + tolerant of network blips.
if ! command -v gdb >/dev/null 2>&1; then
    {
        echo "gdb not installed, attempting apt-get install -y gdb"
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gdb 2>&1 | tail -5
    } >>"$GDB_LOG" 2>&1
fi

if ! command -v gdb >/dev/null 2>&1; then
    echo "ERROR: gdb still not on PATH; running binary directly without trace" >&2
    exec /tmp/bench-ab-runner "$@"
fi

# `--batch --quiet` — no interactive prompt, no banner.
# `set logging redirect on` + `set logging on` — gdb's commands write to
#   GDB_LOG only; the inferior's stdout/stderr keep flowing to parent.
# `handle SIGPIPE nostop noprint pass` — DPDK can EPIPE on echo-server
#   shutdown; don't let gdb halt for that.
# After `run` returns (program exit OR signal), we always print bt+threads+mappings.
exec gdb \
    --batch \
    --quiet \
    -ex "set logging file $GDB_LOG" \
    -ex 'set logging overwrite off' \
    -ex 'set logging redirect on' \
    -ex 'set logging on' \
    -ex 'set pagination off' \
    -ex 'set print thread-events off' \
    -ex 'handle SIGPIPE nostop noprint pass' \
    -ex 'run' \
    -ex 'printf "\n=== STACK TRACE (current thread) ===\n"' \
    -ex 'bt full' \
    -ex 'printf "\n=== ALL THREAD STACKS ===\n"' \
    -ex 'thread apply all bt' \
    -ex 'printf "\n=== INFERIOR STATUS ===\n"' \
    -ex 'info inferior' \
    -ex 'info program' \
    -ex 'printf "\n=== PROC MAPPINGS (head) ===\n"' \
    -ex 'info proc mappings' \
    -ex 'quit' \
    --args /tmp/bench-ab-runner "$@"
