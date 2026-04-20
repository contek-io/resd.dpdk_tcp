//! 4-tuple hash and handle-indexed slot array. The hot path on RX is
//! `FlowTable::lookup_by_tuple` → slot index → `&mut TcpConn`. The
//! hot path on TX / user API is `FlowTable::get_mut(handle)` which
//! skips the hash and just indexes the slot `Vec`.
//!
//! Handle values exposed to callers are `slot_idx + 1`, so handle `0`
//! is reserved as the invalid sentinel — matching `resd_net_conn_t`'s
//! "0 = invalid" convention in spec §4.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};

use crate::tcp_conn::{ConnStats, TcpConn};

/// 4-tuple in HOST byte order for all integer fields. All hash / compare
/// operations use this representation. Network-byte-order conversion
/// happens at the API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub local_ip: u32,
    pub local_port: u16,
    pub peer_ip: u32,
    pub peer_port: u16,
}

/// Opaque connection handle. A `u32` internally; we widen to `u64` at
/// the C ABI boundary (see `resd_net_conn_t`).
pub type ConnHandle = u32;

pub const INVALID_HANDLE: ConnHandle = 0;

/// Fold the 4-tuple through the same hasher `HashMap<FourTuple, _>` uses
/// internally (`std::hash::RandomState` → SipHash-1-3 with a per-process
/// random seed) and truncate to `u32` for bucket-index use. This is the
/// software fallback path for `hash_bucket_for_lookup` when either the
/// `hw-offload-rss-hash` feature is off, the engine's RSS latch is off,
/// or the mbuf did not stamp `RTE_MBUF_F_RX_RSS_HASH` in `ol_flags`.
///
/// Determinism within a process: the std hasher uses a random seed, so
/// the numeric value is stable within one process run but varies across
/// runs. The tests in this module therefore compare pairs of calls within
/// one run, not against a pre-baked constant.
pub fn siphash_4tuple(tup: &FourTuple) -> u32 {
    // Use a lazily-initialised shared seed so every `siphash_4tuple` in
    // one process folds into the same bucket index. `HashMap` does the
    // same via its embedded `RandomState`; we rebuild one here because
    // the table's hasher is an implementation detail (not exposed
    // through `HashMap::hasher()` on older std versions we stay
    // compatible with).
    use std::sync::OnceLock;
    static SEED: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
    let rs = SEED.get_or_init(std::collections::hash_map::RandomState::new);
    let mut h = rs.build_hasher();
    // Fold the canonical host-byte-order 4-tuple. Ordering matters for
    // stability across lookups — matches `FourTuple`'s `Hash` derive.
    h.write_u32(tup.local_ip);
    h.write_u16(tup.local_port);
    h.write_u32(tup.peer_ip);
    h.write_u16(tup.peer_port);
    h.finish() as u32
}

/// Pick the initial flow-table bucket hash for a received segment. When
/// the `hw-offload-rss-hash` feature is compile-on AND the engine's
/// `rss_hash_offload_active` latch is true AND the mbuf's `ol_flags`
/// set `RTE_MBUF_F_RX_RSS_HASH`, return the NIC-provided Toeplitz hash
/// directly — saving a software SipHash fold on the RX hot path.
///
/// Falls back to `siphash_4tuple(tup)` for:
/// - feature-off builds,
/// - runtime latch off (PMD did not advertise RSS hash offload),
/// - mbuf `ol_flags` without the `RX_RSS_HASH` bit (e.g. non-IPv4-TCP
///   frames that RSS does not hash — ICMP, ARP-shaped frames).
///
/// Spec §8.2.
#[cfg(feature = "hw-offload-rss-hash")]
pub fn hash_bucket_for_lookup(
    tup: &FourTuple,
    ol_flags: u64,
    nic_rss_hash: u32,
    rss_active: bool,
) -> u32 {
    use crate::dpdk_consts::RTE_MBUF_F_RX_RSS_HASH;
    if rss_active && (ol_flags & RTE_MBUF_F_RX_RSS_HASH) != 0 {
        return nic_rss_hash;
    }
    siphash_4tuple(tup)
}

/// Feature-off variant. Signature identical so callers don't need to
/// `#[cfg]`-wrap the call site. Always computes `siphash_4tuple`.
#[cfg(not(feature = "hw-offload-rss-hash"))]
pub fn hash_bucket_for_lookup(
    tup: &FourTuple,
    _ol_flags: u64,
    _nic_rss_hash: u32,
    _rss_active: bool,
) -> u32 {
    siphash_4tuple(tup)
}

pub struct FlowTable {
    slots: Vec<Option<TcpConn>>,
    by_tuple: HashMap<FourTuple, u32>,
}

impl FlowTable {
    pub fn new(max_connections: u32) -> Self {
        let mut slots = Vec::with_capacity(max_connections as usize);
        for _ in 0..max_connections {
            slots.push(None);
        }
        Self {
            slots,
            by_tuple: HashMap::with_capacity(max_connections as usize),
        }
    }

    pub fn capacity(&self) -> u32 {
        self.slots.len() as u32
    }

    /// Allocate a new slot for `conn`; returns the handle or `None` if full.
    /// Duplicate 4-tuple registrations are rejected — caller must close the
    /// existing connection first.
    pub fn insert(&mut self, conn: TcpConn) -> Option<ConnHandle> {
        let tuple = conn.four_tuple();
        if self.by_tuple.contains_key(&tuple) {
            return None;
        }
        let slot_idx = self.slots.iter().position(|s| s.is_none())?;
        self.slots[slot_idx] = Some(conn);
        self.by_tuple.insert(tuple, slot_idx as u32);
        Some(slot_idx as u32 + 1)
    }

    pub fn get(&self, handle: ConnHandle) -> Option<&TcpConn> {
        if handle == INVALID_HANDLE {
            return None;
        }
        let idx = (handle - 1) as usize;
        self.slots.get(idx)?.as_ref()
    }

    pub fn get_mut(&mut self, handle: ConnHandle) -> Option<&mut TcpConn> {
        if handle == INVALID_HANDLE {
            return None;
        }
        let idx = (handle - 1) as usize;
        self.slots.get_mut(idx)?.as_mut()
    }

    pub fn lookup_by_tuple(&self, tuple: &FourTuple) -> Option<ConnHandle> {
        self.by_tuple.get(tuple).copied().map(|i| i + 1)
    }

    /// RX hot-path lookup that accepts a pre-computed bucket hash from
    /// `hash_bucket_for_lookup`. Today the backing store is still a
    /// `HashMap<FourTuple, _>` so `bucket_hash` is informational only —
    /// the HashMap probes by its own internal hasher, and we still
    /// resolve by the full `FourTuple` key. The hash is plumbed through
    /// now for forward-compat with a Stage-2 flat-bucket table where the
    /// NIC Toeplitz hash will pick the initial probe slot directly.
    ///
    /// Callers that don't have an mbuf (e.g. API-initiated flow work
    /// or tests) should stay on `lookup_by_tuple`.
    pub fn lookup_by_hash(
        &self,
        tuple: &FourTuple,
        #[allow(unused_variables)] bucket_hash: u32,
    ) -> Option<ConnHandle> {
        // TODO (Stage 2): when we swap `by_tuple` for a flat bucket
        // array, use `bucket_hash` as the initial probe index.
        let _ = bucket_hash;
        self.lookup_by_tuple(tuple)
    }

    /// Slow-path stats snapshot; see `TcpConn::stats`.
    pub fn get_stats(&self, handle: ConnHandle, send_buffer_bytes: u32) -> Option<ConnStats> {
        self.get(handle).map(|c| c.stats(send_buffer_bytes))
    }

    /// Remove the connection for `handle`. Returns the removed `TcpConn` if
    /// present, else `None`. Frees both the slot and the by-tuple entry.
    pub fn remove(&mut self, handle: ConnHandle) -> Option<TcpConn> {
        if handle == INVALID_HANDLE {
            return None;
        }
        let idx = (handle - 1) as usize;
        let slot = self.slots.get_mut(idx)?;
        let conn = slot.take()?;
        self.by_tuple.remove(&conn.four_tuple());
        Some(conn)
    }

    /// Iterate all active connections — used by the naïve tick path for
    /// TIME_WAIT reaping. Not a hot-path function.
    pub fn iter_handles(&self) -> impl Iterator<Item = ConnHandle> + '_ {
        self.slots.iter().enumerate().filter_map(|(i, s)| {
            if s.is_some() {
                Some(i as u32 + 1)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_conn::TcpConn;

    fn tuple(peer_port: u16) -> FourTuple {
        FourTuple {
            local_ip: 0x0a_00_00_02,
            local_port: 40000,
            peer_ip: 0x0a_00_00_01,
            peer_port,
        }
    }

    #[test]
    fn insert_and_lookup_by_handle() {
        let mut ft = FlowTable::new(4);
        let c = TcpConn::new_client(tuple(5000), 12345, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        let h = ft.insert(c).expect("insert ok");
        assert!(h >= 1);
        assert!(ft.get(h).is_some());
    }

    #[test]
    fn lookup_by_tuple_roundtrip() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let c = TcpConn::new_client(t, 12345, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        let h = ft.insert(c).unwrap();
        assert_eq!(ft.lookup_by_tuple(&t), Some(h));
    }

    #[test]
    fn full_table_returns_none() {
        let mut ft = FlowTable::new(2);
        let a = TcpConn::new_client(tuple(5000), 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        let b = TcpConn::new_client(tuple(5001), 2, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        let c = TcpConn::new_client(tuple(5002), 3, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(ft.insert(a).is_some());
        assert!(ft.insert(b).is_some());
        assert!(ft.insert(c).is_none());
    }

    #[test]
    fn duplicate_tuple_rejected() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let a = TcpConn::new_client(t, 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        let b = TcpConn::new_client(t, 2, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        assert!(ft.insert(a).is_some());
        assert!(ft.insert(b).is_none());
    }

    #[test]
    fn remove_frees_slot_and_tuple() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let c = TcpConn::new_client(t, 1, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        let h = ft.insert(c).unwrap();
        assert!(ft.remove(h).is_some());
        assert!(ft.remove(h).is_none());
        assert!(ft.lookup_by_tuple(&t).is_none());
    }

    #[test]
    fn invalid_handle_rejected() {
        let ft = FlowTable::new(4);
        assert!(ft.get(INVALID_HANDLE).is_none());
    }

    #[test]
    fn get_mut_roundtrip_mutation() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let c = TcpConn::new_client(t, 42, 1460, 1024, 2048, 5000, 5000, 1_000_000);
        let h = ft.insert(c).unwrap();
        // Mutate via get_mut and observe via get.
        ft.get_mut(h).unwrap().state = crate::tcp_state::TcpState::SynSent;
        assert_eq!(
            ft.get(h).unwrap().state,
            crate::tcp_state::TcpState::SynSent
        );
    }

    #[test]
    fn iter_handles_skips_freed_slots() {
        let mut ft = FlowTable::new(4);
        let h1 = ft
            .insert(TcpConn::new_client(
                tuple(5000),
                1,
                1460,
                1024,
                2048,
                5000,
                5000,
                1_000_000,
            ))
            .unwrap();
        let h2 = ft
            .insert(TcpConn::new_client(
                tuple(5001),
                2,
                1460,
                1024,
                2048,
                5000,
                5000,
                1_000_000,
            ))
            .unwrap();
        let h3 = ft
            .insert(TcpConn::new_client(
                tuple(5002),
                3,
                1460,
                1024,
                2048,
                5000,
                5000,
                1_000_000,
            ))
            .unwrap();
        ft.remove(h2);
        let got: Vec<_> = ft.iter_handles().collect();
        assert_eq!(got, vec![h1, h3]);
    }

    #[cfg(feature = "hw-offload-rss-hash")]
    #[test]
    fn rss_hash_used_when_flag_set_and_latch_on() {
        use crate::dpdk_consts::RTE_MBUF_F_RX_RSS_HASH;
        let tup = FourTuple {
            local_ip: 0x0a000001,
            local_port: 1,
            peer_ip: 0x0a000002,
            peer_port: 2,
        };
        let nic_hash: u32 = 0xdeadbeef;
        let ol_flags = RTE_MBUF_F_RX_RSS_HASH;
        let picked = hash_bucket_for_lookup(&tup, ol_flags, nic_hash, /*rss_active=*/ true);
        assert_eq!(picked, nic_hash);
    }

    #[cfg(feature = "hw-offload-rss-hash")]
    #[test]
    fn rss_hash_unused_when_flag_clear() {
        let tup = FourTuple {
            local_ip: 0x0a000001,
            local_port: 1,
            peer_ip: 0x0a000002,
            peer_port: 2,
        };
        // No RSS_HASH flag in ol_flags → fall back to SipHash. Two calls
        // with the SAME tuple but different nic_rss_hash values must
        // return the SAME result, because the nic_rss_hash is ignored
        // when the flag is clear.
        let picked = hash_bucket_for_lookup(&tup, 0, 0xdeadbeef, true);
        let again = hash_bucket_for_lookup(&tup, 0, 0xbeefdead, true);
        assert_eq!(
            picked, again,
            "when ol_flags missing RSS_HASH, nic_rss_hash must be ignored and SipHash used"
        );
        // And it should equal the direct SipHash path.
        assert_eq!(picked, siphash_4tuple(&tup));
    }

    #[cfg(feature = "hw-offload-rss-hash")]
    #[test]
    fn rss_hash_unused_when_latch_off() {
        use crate::dpdk_consts::RTE_MBUF_F_RX_RSS_HASH;
        let tup = FourTuple {
            local_ip: 0x0a000001,
            local_port: 1,
            peer_ip: 0x0a000002,
            peer_port: 2,
        };
        // Even with the flag set, if the latch is off (runtime fallback
        // when PMD didn't advertise), we fall back to SipHash.
        let picked_latch_off =
            hash_bucket_for_lookup(&tup, RTE_MBUF_F_RX_RSS_HASH, 0xdeadbeef, false);
        let sw_fallback = hash_bucket_for_lookup(&tup, 0, 0, true); // SipHash path
        assert_eq!(picked_latch_off, sw_fallback);
    }
}
