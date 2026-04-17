//! Pure-Rust internals of the resd.dpdk_tcp stack.
//! The public `extern "C"` surface lives in the `resd-net` crate.

pub mod clock;
pub mod counters;
pub mod engine;
pub mod error;
pub mod l2;
pub mod l3_ip;
pub mod mempool;

pub use error::Error;
