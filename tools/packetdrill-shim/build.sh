#!/usr/bin/env bash
# A7 task 10: build the patched packetdrill binary and link it against
# libdpdk_net (test-server feature). google/packetdrill uses a plain
# Makefile.Linux (no autotools), so we drive the build via EXT_CFLAGS /
# EXT_LIBS — the hooks added by patch 0004.
#
# Inputs (env): DPDK_NET_SHIM_PROFILE (release|dev, default release)
# Output:       target/packetdrill-shim/packetdrill

set -euo pipefail
cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"

PROFILE="${DPDK_NET_SHIM_PROFILE:-release}"

REQUIRED_BINS=(git bison flex make gcc pkg-config)
for bin in "${REQUIRED_BINS[@]}"; do
  command -v "$bin" >/dev/null 2>&1 \
    || { echo "ERROR: missing host tool: $bin"; exit 1; }
done

# 1. Ensure submodules are initialized.
git submodule update --init --recursive \
  third_party/packetdrill third_party/packetdrill-testcases

# 2. Apply the patch stack idempotently. We probe for a patch-applied
#    file that only exists after 0001 lands (dpdk_net_shim.c), so the
#    marker survives `git submodule update` wiping the worktree. The
#    glob loop picks up all patches/*.patch in order, including 0007
#    (A8.5 T6 env-stubs); the submodule pin in the outer repo already
#    has them baked in as commits, so normal rebuilds skip this block.
cd third_party/packetdrill
if ! [ -f gtests/net/packetdrill/dpdk_net_shim.c ]; then
  shopt -s nullglob
  patches=("$REPO_ROOT"/tools/packetdrill-shim/patches/*.patch)
  shopt -u nullglob
  if [ "${#patches[@]}" -gt 0 ]; then
    for p in "${patches[@]}"; do
      git am "$p"
    done
  fi
fi

# 3. Build libdpdk_net.a (staticlib) with --features test-server.
cd "$REPO_ROOT"
if [ "$PROFILE" = "release" ]; then
  cargo build --release -p dpdk-net --features test-server
  LIB_DIR="$REPO_ROOT/target/release"
else
  cargo build -p dpdk-net --features test-server
  LIB_DIR="$REPO_ROOT/target/debug"
fi
if [ ! -f "$LIB_DIR/libdpdk_net.a" ]; then
  echo "ERROR: libdpdk_net.a not found under $LIB_DIR" >&2
  exit 1
fi

# 4. Assemble the DPDK link line. libdpdk_net.a is a Rust staticlib and
#    transitively pulls in the DPDK C ABI, so we also need the DPDK libs
#    via pkg-config. The Rust staticlib itself wants -lm -lpthread -ldl
#    which the Makefile already supplies.
DPDK_CFLAGS="$(pkg-config --cflags libdpdk 2>/dev/null || true)"
DPDK_LIBS="$(pkg-config --libs libdpdk 2>/dev/null || true)"

EXT_CFLAGS="-I$REPO_ROOT/include $DPDK_CFLAGS"
# Order matters: object files first, then libdpdk_net.a, then DPDK libs,
# then OS libs. Use -l:libdpdk_net.a to force the archive (not the .so)
# so the shim binary doesn't need LD_LIBRARY_PATH at runtime. The
# Makefile already appends -lpthread -lrt -ldl after EXT_LIBS, so we
# don't need to repeat them.
EXT_LIBS="-L$LIB_DIR -l:libdpdk_net.a $DPDK_LIBS -lnuma -lm"

# 5. Build packetdrill via Makefile.Linux.
cd "$REPO_ROOT"/third_party/packetdrill/gtests/net/packetdrill
make -f Makefile.Linux clean 2>/dev/null || true
make -f Makefile.Linux -j"$(nproc)" \
  EXT_CFLAGS="$EXT_CFLAGS" \
  EXT_LIBS="$EXT_LIBS" \
  packetdrill

# 6. Stage the binary.
mkdir -p "$REPO_ROOT"/target/packetdrill-shim
cp -f packetdrill "$REPO_ROOT"/target/packetdrill-shim/packetdrill
echo "=== packetdrill-shim build OK: $REPO_ROOT/target/packetdrill-shim/packetdrill ==="
