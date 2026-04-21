#!/usr/bin/env bash
# A7: build the patched packetdrill binary and link it against libdpdk_net.
# Inputs: $DPDK_NET_SHIM_PROFILE (release|dev, default release).
# Output: target/packetdrill-shim/packetdrill

set -euo pipefail
cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"

PROFILE="${DPDK_NET_SHIM_PROFILE:-release}"

# Require host tooling. In scaffold-only mode we only need git (for
# submodule init); autotools/make aren't invoked until T10 turns off
# scaffold-only.
if [ -n "${DPDK_NET_SHIM_SCAFFOLD_ONLY:-}" ]; then
  REQUIRED_BINS=(git)
else
  REQUIRED_BINS=(git autoreconf bison flex make gcc pkg-config)
fi
for bin in "${REQUIRED_BINS[@]}"; do
  command -v "$bin" >/dev/null 2>&1 \
    || { echo "ERROR: missing host tool: $bin"; exit 1; }
done

# 1. Ensure submodules are initialized.
git submodule update --init --recursive \
  third_party/packetdrill third_party/packetdrill-testcases

# 2. Apply the patch stack idempotently.
cd third_party/packetdrill
# If already applied (the tip has a patch-marker file), skip.
if ! [ -f .a7-patches-applied ]; then
  shopt -s nullglob
  patches=("$REPO_ROOT"/tools/packetdrill-shim/patches/*.patch)
  shopt -u nullglob
  if [ "${#patches[@]}" -gt 0 ]; then
    for p in "${patches[@]}"; do
      git am "$p"
    done
  fi
  touch .a7-patches-applied
fi

# Scaffold-only short-circuit: T9 commits this file before T10's patch
# stack exists, so we stage a stub binary and skip the expensive cargo
# re-entry + autotools/make step. T10 drops the env var.
if [ -n "${DPDK_NET_SHIM_SCAFFOLD_ONLY:-}" ]; then
  # Determine packetdrill source dir just for the log message.
  if [ -f configure.ac ] || [ -f configure.in ]; then
    PD_DIR="$REPO_ROOT/third_party/packetdrill"
  else
    PD_DIR="$REPO_ROOT/third_party/packetdrill/gtests/net/packetdrill"
  fi
  echo "=== packetdrill-shim: scaffold-only mode (DPDK_NET_SHIM_SCAFFOLD_ONLY=1) ==="
  echo "packetdrill source dir: $PD_DIR"
  mkdir -p "$REPO_ROOT"/target/packetdrill-shim
  cat > "$REPO_ROOT"/target/packetdrill-shim/packetdrill <<'EOF'
#!/usr/bin/env bash
echo "packetdrill shim stub — T10 must land the patch stack before use" >&2
exit 1
EOF
  chmod +x "$REPO_ROOT"/target/packetdrill-shim/packetdrill
  exit 0
fi

# 3. Build libdpdk_net (staticlib) with --features test-server.
cd "$REPO_ROOT"
if [ "$PROFILE" = "release" ]; then
  cargo build --release -p dpdk-net --features test-server
  LIB_DIR="$REPO_ROOT/target/release"
else
  cargo build -p dpdk-net --features test-server
  LIB_DIR="$REPO_ROOT/target/debug"
fi

# 4. Build packetdrill.
cd "$REPO_ROOT"/third_party/packetdrill
# google/packetdrill uses autotools inside gtests/net/packetdrill; adapt
# to whichever layout this pinned SHA has. If the top-level configure.ac
# doesn't exist, descend to gtests/net/packetdrill.
if [ -f configure.ac ] || [ -f configure.in ]; then
  PD_DIR="$REPO_ROOT/third_party/packetdrill"
else
  PD_DIR="$REPO_ROOT/third_party/packetdrill/gtests/net/packetdrill"
fi
cd "$PD_DIR"
if [ ! -f configure.ac ] && [ ! -f configure.in ] && [ ! -f Makefile ]; then
  echo "ERROR: packetdrill source dir has no autotools or Makefile; did the submodule update?"
  exit 1
fi
if [ -f configure.ac ] || [ -f configure.in ]; then
  autoreconf -fi
  ./configure CC=clang \
    CFLAGS="-O2 -g -I$REPO_ROOT/include" \
    LDFLAGS="-L$LIB_DIR -ldl -lpthread -lnuma" \
    LIBS="-ldpdk_net"
fi
make clean 2>/dev/null || true
make -j"$(nproc)"

# 5. Stage the binary.
mkdir -p "$REPO_ROOT"/target/packetdrill-shim
if [ -f packetdrill ]; then
  cp -f packetdrill "$REPO_ROOT"/target/packetdrill-shim/packetdrill
elif [ -f gtests/net/packetdrill/packetdrill ]; then
  cp -f gtests/net/packetdrill/packetdrill "$REPO_ROOT"/target/packetdrill-shim/packetdrill
else
  echo "ERROR: cannot find produced packetdrill binary"
  exit 1
fi
echo "=== packetdrill-shim build OK ==="
