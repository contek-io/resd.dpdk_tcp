//! Shared synthetic-pcap builder for `tests/normalize_roundtrip.rs`
//! and `tests/differing_counts.rs` (A10 T15-B).
//!
//! Refactored out of `tests/normalize_roundtrip.rs` in T15-B so later
//! pcap-fixture-consuming tests don't each re-invent the synth stack.
//!
//! Rust cargo-test "common module" convention: living under
//! `tests/common/mod.rs`, consumed via `mod common;` inside each
//! integration-test binary. Integration-test files are separate
//! binaries; cargo silently turns any `common/` subfolder with a
//! `mod.rs` into a source file for each test target that `mod common;`
//! it. That's why this file is `mod.rs`, not an `.rs` sibling.

#![allow(dead_code)]

pub mod synth;
