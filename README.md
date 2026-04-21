# resd.dpdk_tcp

DPDK-based userspace TCP stack in Rust with a C ABI for C++ consumers.

See `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` for the design.

## Build

Requires DPDK 23.11 installed (`pkg-config --exists libdpdk` must succeed).

```sh
cargo build --release          # add --locked for reproducible builds
cmake -S examples/cpp-consumer -B examples/cpp-consumer/build
cmake --build examples/cpp-consumer/build
```

## Test

```sh
cargo test
```

## Integration tests (require DPDK TAP and root)

```sh
sudo -E DPDK_NET_TEST_TAP=1 cargo test -p dpdk-net-core --test engine_smoke -- --nocapture
```

## L2/L3 integration tests (require DPDK TAP and root)

```sh
sudo -E DPDK_NET_TEST_TAP=1 cargo test -p dpdk-net-core --test l2_l3_tap -- --nocapture
```

## TCP handshake + echo integration test (requires DPDK TAP + root)

```sh
sudo -E DPDK_NET_TEST_TAP=1 cargo test -p dpdk-net-core --test tcp_basic_tap -- --nocapture
```
