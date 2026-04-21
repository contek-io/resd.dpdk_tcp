//! ABI-stable iovec type — scatter-gather element used by the READABLE
//! event payload. Mirrors the C-side `dpdk_net_iovec_t` in `dpdk-net/src/api.rs`;
//! a layout assertion in that crate confirms the two definitions stay in sync.
//!
//! 16 bytes on 64-bit targets (x86_64, ARM64 Graviton — the Stage 1 targets).
//! Not 32-bit compatible.
//!
//! The duplicate-struct-with-layout-assert pattern is used here because the
//! `dpdk-net` crate's `cbindgen.toml` has `parse_deps = false`, which means a
//! `pub type` alias across crates would NOT be picked up by cbindgen's emit.
//! The FFI crate ships its own `dpdk_net_iovec_t` with identical `#[repr(C)]`
//! layout; the layout assertion in that crate is the deterministic guarantee
//! the two stay byte-compatible.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DpdkNetIovec {
    pub base: *const u8,
    pub len: u32,
    pub _pad: u32,
}
