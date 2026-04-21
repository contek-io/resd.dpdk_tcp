//! A7 Task 5: minimal server-FSM support behind the `test-server` feature.
//!
//! A `ListenSlot` holds a single local (ip, port) and an at-most-one
//! accept queue. `Engine::tcp_input` dispatches inbound SYNs whose
//! dst-(ip,port) matches a `ListenSlot` into `handle_inbound_syn_listen`,
//! which allocates a per-conn slot in SYN_RCVD, emits SYN-ACK via the
//! existing builder, and parks it until the final ACK arrives. Additional
//! SYNs that land while an accept is queued OR an in-progress SYN_RCVD
//! exists are rejected with RST + ACK.

use crate::flow_table::ConnHandle;

/// Opaque handle for a listening socket; `1`-based so `0` is available
/// as an "uninitialized" sentinel in caller code if desired.
pub type ListenHandle = u32;

/// A single listening endpoint. Capacity is intentionally one:
/// the phase-A7 scope is a single pending conn + a single accepted
/// conn, no multi-accept queue and no SO_REUSEPORT.
#[derive(Debug)]
pub struct ListenSlot {
    pub local_ip: u32,
    pub local_port: u16,
    /// At most one queued ESTABLISHED handle waiting on `accept_next`.
    pub accept_queue: Option<ConnHandle>,
    /// An in-progress SYN_RCVD handle tied to this listen; cleared when
    /// the final ACK transitions it to ESTABLISHED.
    pub in_progress: Option<ConnHandle>,
}

impl ListenSlot {
    pub fn new(local_ip: u32, local_port: u16) -> Self {
        Self {
            local_ip,
            local_port,
            accept_queue: None,
            in_progress: None,
        }
    }
}
