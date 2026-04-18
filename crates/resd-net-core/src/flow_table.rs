//! 4-tuple hash and handle-indexed slot array. The hot path on RX is
//! `FlowTable::lookup_by_tuple` → slot index → `&mut TcpConn`. The
//! hot path on TX / user API is `FlowTable::get_mut(handle)` which
//! skips the hash and just indexes the slot `Vec`.
//!
//! Handle values exposed to callers are `slot_idx + 1`, so handle `0`
//! is reserved as the invalid sentinel — matching `resd_net_conn_t`'s
//! "0 = invalid" convention in spec §4.

use std::collections::HashMap;

use crate::tcp_conn::TcpConn;

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
        let c = TcpConn::new_client(tuple(5000), 12345, 1460, 1024, 2048);
        let h = ft.insert(c).expect("insert ok");
        assert!(h >= 1);
        assert!(ft.get(h).is_some());
    }

    #[test]
    fn lookup_by_tuple_roundtrip() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let c = TcpConn::new_client(t, 12345, 1460, 1024, 2048);
        let h = ft.insert(c).unwrap();
        assert_eq!(ft.lookup_by_tuple(&t), Some(h));
    }

    #[test]
    fn full_table_returns_none() {
        let mut ft = FlowTable::new(2);
        let a = TcpConn::new_client(tuple(5000), 1, 1460, 1024, 2048);
        let b = TcpConn::new_client(tuple(5001), 2, 1460, 1024, 2048);
        let c = TcpConn::new_client(tuple(5002), 3, 1460, 1024, 2048);
        assert!(ft.insert(a).is_some());
        assert!(ft.insert(b).is_some());
        assert!(ft.insert(c).is_none());
    }

    #[test]
    fn duplicate_tuple_rejected() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let a = TcpConn::new_client(t, 1, 1460, 1024, 2048);
        let b = TcpConn::new_client(t, 2, 1460, 1024, 2048);
        assert!(ft.insert(a).is_some());
        assert!(ft.insert(b).is_none());
    }

    #[test]
    fn remove_frees_slot_and_tuple() {
        let mut ft = FlowTable::new(4);
        let t = tuple(5000);
        let c = TcpConn::new_client(t, 1, 1460, 1024, 2048);
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
}
