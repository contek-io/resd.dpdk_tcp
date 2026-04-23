//! A7: TX frame intercept for the packetdrill-shim.
//!
//! Under `--features test-server`, every place the engine would call
//! `rte_eth_tx_burst` copies the outbound frame's bytes into a
//! thread-local queue instead. The shim drains that queue between
//! script steps via `dpdk_net_test_drain_tx_frames`.

use std::cell::RefCell;

thread_local! {
    static TX_QUEUE: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Push a copy of one outbound frame onto the thread-local queue.
pub fn push_tx_frame(bytes: Vec<u8>) {
    TX_QUEUE.with(|q| q.borrow_mut().push(bytes));
}

/// Drain every pending frame. Resets the queue.
pub fn drain_tx_frames() -> Vec<Vec<u8>> {
    TX_QUEUE.with(|q| std::mem::take(&mut *q.borrow_mut()))
}

/// Cheap test predicate: is the queue empty right now?
pub fn is_empty() -> bool {
    TX_QUEUE.with(|q| q.borrow().is_empty())
}
