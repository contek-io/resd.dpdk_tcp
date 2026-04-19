//! Named constants for DPDK 23.11 bit positions we consume in A-HW.
//!
//! Source: DPDK 23.11 `lib/ethdev/rte_ethdev.h` + `lib/mbuf/rte_mbuf_core.h`.
//! These are `RTE_BIT64(N)`-based macros that bindgen does not expand into
//! Rust `const`s, so we mirror the bit positions here. When DPDK changes
//! these values in a future LTS we need to re-pin — but they are part of
//! the stable ethdev / mbuf ABI and have not moved across 22.11 → 23.11.
//!
//! Spec reference: docs/superpowers/specs/2026-04-19-stage1-phase-a-hw-ena-offload-design.md

#![allow(dead_code)] // Some consts are feature-gated at the call site.

// ---- TX offload capability / conf bits (rte_ethdev.h) ---------------

pub const RTE_ETH_TX_OFFLOAD_IPV4_CKSUM: u64 = 1u64 << 1;
pub const RTE_ETH_TX_OFFLOAD_UDP_CKSUM: u64 = 1u64 << 2;
pub const RTE_ETH_TX_OFFLOAD_TCP_CKSUM: u64 = 1u64 << 3;
pub const RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE: u64 = 1u64 << 14;
pub const RTE_ETH_TX_OFFLOAD_MULTI_SEGS: u64 = 1u64 << 15;

// ---- RX offload capability / conf bits (rte_ethdev.h) ---------------

pub const RTE_ETH_RX_OFFLOAD_IPV4_CKSUM: u64 = 1u64 << 1;
pub const RTE_ETH_RX_OFFLOAD_UDP_CKSUM: u64 = 1u64 << 2;
pub const RTE_ETH_RX_OFFLOAD_TCP_CKSUM: u64 = 1u64 << 3;
pub const RTE_ETH_RX_OFFLOAD_RSS_HASH: u64 = 1u64 << 19;

// ---- RSS hash flags (64-bit rss_hf) ---------------------------------

pub const RTE_ETH_RSS_NONFRAG_IPV4_TCP: u64 = 1u64 << 13;
pub const RTE_ETH_RSS_NONFRAG_IPV6_TCP: u64 = 1u64 << 19;

// ---- mbuf.ol_flags RX classification bits (rte_mbuf_core.h) ---------

pub const RTE_MBUF_F_RX_RSS_HASH: u64 = 1u64 << 1;
pub const RTE_MBUF_F_RX_L4_CKSUM_BAD: u64 = 1u64 << 3;
pub const RTE_MBUF_F_RX_IP_CKSUM_BAD: u64 = 1u64 << 4;
pub const RTE_MBUF_F_RX_L4_CKSUM_GOOD: u64 = 1u64 << 8;
pub const RTE_MBUF_F_RX_IP_CKSUM_GOOD: u64 = 1u64 << 7;
/// Two-bit encoding for IP cksum status. Matching (ol_flags & MASK)
/// yields one of four distinct values:
/// 0=UNKNOWN, BAD_BIT=BAD, GOOD_BIT=GOOD, (BAD|GOOD)=NONE.
pub const RTE_MBUF_F_RX_IP_CKSUM_MASK: u64 =
    RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_GOOD;
pub const RTE_MBUF_F_RX_L4_CKSUM_MASK: u64 =
    RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD;
pub const RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN: u64 = 0;
pub const RTE_MBUF_F_RX_IP_CKSUM_NONE: u64 = RTE_MBUF_F_RX_IP_CKSUM_MASK;
pub const RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN: u64 = 0;
pub const RTE_MBUF_F_RX_L4_CKSUM_NONE: u64 = RTE_MBUF_F_RX_L4_CKSUM_MASK;

// ---- mbuf.ol_flags TX classification bits (rte_mbuf_core.h) ---------

/// 2-bit L4 proto field at bits 52-53. TCP = 01.
pub const RTE_MBUF_F_TX_TCP_CKSUM: u64 = 1u64 << 52;
/// 2-bit L4 proto field at bits 52-53. UDP = 11.
pub const RTE_MBUF_F_TX_UDP_CKSUM: u64 = 3u64 << 52;
pub const RTE_MBUF_F_TX_L4_MASK: u64 = 3u64 << 52;
pub const RTE_MBUF_F_TX_IP_CKSUM: u64 = 1u64 << 54;
pub const RTE_MBUF_F_TX_IPV4: u64 = 1u64 << 55;
pub const RTE_MBUF_F_TX_IPV6: u64 = 1u64 << 56;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_positions_match_dpdk_23_11_ethdev_header() {
        // Pinned values from lib/ethdev/rte_ethdev.h + lib/mbuf/rte_mbuf_core.h.
        // Failure here means DPDK changed the bit layout — do NOT blindly fix.
        assert_eq!(RTE_ETH_TX_OFFLOAD_IPV4_CKSUM, 0x0000_0000_0000_0002);
        assert_eq!(RTE_ETH_TX_OFFLOAD_TCP_CKSUM, 0x0000_0000_0000_0008);
        assert_eq!(RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE, 0x0000_0000_0000_4000);
        assert_eq!(RTE_ETH_TX_OFFLOAD_MULTI_SEGS, 0x0000_0000_0000_8000);
        assert_eq!(RTE_ETH_RX_OFFLOAD_TCP_CKSUM, 0x0000_0000_0000_0008);
        assert_eq!(RTE_ETH_RX_OFFLOAD_RSS_HASH, 0x0000_0000_0008_0000);
        assert_eq!(RTE_ETH_RSS_NONFRAG_IPV4_TCP, 0x0000_0000_0000_2000);
        assert_eq!(RTE_MBUF_F_RX_RSS_HASH, 0x0000_0000_0000_0002);
        assert_eq!(RTE_MBUF_F_RX_IP_CKSUM_MASK, 0x0000_0000_0000_0090);
        assert_eq!(RTE_MBUF_F_RX_L4_CKSUM_MASK, 0x0000_0000_0000_0108);
        assert_eq!(RTE_MBUF_F_TX_TCP_CKSUM, 0x0010_0000_0000_0000);
        assert_eq!(RTE_MBUF_F_TX_IP_CKSUM, 0x0040_0000_0000_0000);
        assert_eq!(RTE_MBUF_F_TX_IPV4, 0x0080_0000_0000_0000);
    }
}
