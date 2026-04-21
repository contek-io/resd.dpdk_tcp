#!/usr/bin/env bash
# A6.7 cpp-consumer sanitizer job: ASan + UBSan (LSan auto-enabled with
# ASan on Linux). Builds cpp-consumer with sanitizers and runs the
# scripted connect → send → recv → close scenario against a TAP peer.
#
# Requires:
#   - clang-22 from llvm.org (see feedback_build_toolchain.md)
#   - DPDK_NET_TEST_TAP=1 env + sudo for TAP creation when actually
#     exercising the runtime path. The build itself does not require sudo.
#
# Usage (from repo root): ./scripts/hardening-cpp-sanitizers.sh [--build-only]
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD_ONLY=0
if [[ "${1:-}" == "--build-only" ]]; then
    BUILD_ONLY=1
fi

export CC="${CC:-clang-22}"
export CXX="${CXX:-clang++-22}"

# The Rust library is compiled normally — sanitizers instrument the C++
# side only. Build first so the static archive exists.
source ~/.cargo/env
cargo build --release -p dpdk-net

# Build cpp-consumer with sanitizers in a dedicated directory.
SANITIZE_DIR="examples/cpp-consumer/build-sanitize"
rm -rf "${SANITIZE_DIR}"
mkdir -p "${SANITIZE_DIR}"
pushd "${SANITIZE_DIR}" >/dev/null
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
make -j"$(nproc)"
popd >/dev/null

if [[ "${BUILD_ONLY}" == "1" ]]; then
    echo "=== hardening-cpp-sanitizers: build-only PASS ==="
    exit 0
fi

# Runtime path: requires TAP + sudo. The cpp-consumer's static_assert
# fires at compile time (T17 added it); ASan/UBSan/LSan errors fire on
# the run.
if [[ -z "${DPDK_NET_TEST_TAP:-}" ]]; then
    echo "WARN: DPDK_NET_TEST_TAP is not set; skipping runtime exercise." >&2
    echo "Set DPDK_NET_TEST_TAP=1 and run with sudo to exercise the sanitized binary." >&2
    echo "=== hardening-cpp-sanitizers: build-only PASS (runtime skipped) ==="
    exit 0
fi

# Expected exit 0 on a clean run; ASan/UBSan errors → non-zero with
# diagnostic on stderr.
"${PWD}/${SANITIZE_DIR}/cpp_consumer"

echo "=== hardening-cpp-sanitizers: PASS ==="
