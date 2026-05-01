# A10 SIGSEGV — codex second opinion

## My hypothesis
Hypothesis: `Engine` teardown has a lifetime inversion: it closes the ENA port while Rust-owned state can still contain mbuf references, then normal field teardown frees mempools before the later mbuf-owning fields are gone. This is the single most likely root cause of the silent exit 139. Multi-phase tools leave more live connection/RX/TX state at process exit, so they reliably hit teardown with outstanding mbufs; simpler one-shot tools often exit with those containers empty.

## Code evidence
- `crates/dpdk-net-core/src/engine.rs:415-461` declares mempools before later mbuf owner containers:
  ```rust
  _rx_mempool: Mempool,
  tx_hdr_mempool: Mempool,
  tx_data_mempool: Mempool,
  flow_table: RefCell<FlowTable>,
  pub(crate) tx_pending_data: RefCell<Vec<NonNull<sys::rte_mbuf>>>,
  ```
- `crates/dpdk-net-core/src/engine.rs:5643-5650` closes the port in `Drop` before field destructors run:
  ```rust
  sys::rte_eth_dev_stop(self.cfg.port_id);
  sys::rte_eth_dev_close(self.cfg.port_id);
  // Mempools drop via their own Drop impl.
  ```
- `crates/dpdk-net-core/src/mempool.rs:104-108` frees pools, and `:231-239` decrements owning mbuf refs:
  ```rust
  sys::rte_mempool_free(self.ptr.as_ptr())
  sys::shim_rte_mbuf_refcnt_update(self.ptr.as_ptr(), -1)
  ```
- `crates/dpdk-net-core/src/flow_table.rs:102-104` stores `TcpConn`s. `crates/dpdk-net-core/src/tcp_conn.rs:83-88` and `:301-308` show live conns can retain RX mbufs in `recv.bytes`, `recv.reorder`, and `delivered_segments`.
- `crates/dpdk-net-core/src/tcp_reassembly.rs:399-407` confirms `ReorderQueue::Drop` releases held OOO mbuf refs.
- `crates/dpdk-net-core/src/engine.rs:4588-4653` pushes the same TX mbuf into `tx_pending_data` and `snd_retrans` after a refcount bump. `crates/dpdk-net-core/src/tcp_conn.rs:235-236` stores `snd_retrans`; `crates/dpdk-net-core/src/tcp_retrans.rs:21-47` stores `RetransEntry { mbuf: Mbuf }`.
- Conditional path: `crates/dpdk-net-core/src/engine.rs:586-587` gates `fault_injector` behind `#[cfg(feature = "fault-injector")]`; `crates/dpdk-net-core/src/fault_injector.rs:333-340` frees mbufs still held in its reorder ring during drop.

## Why this matches the observed fingerprint
The observed `ena_rx_queue_release` / `ena_tx_queue_release` lines mean `rte_eth_dev_close` was reached. In this code, that happens before `flow_table`, `tx_pending_data`, `fault_injector`, and the mempools are destructed. After close, remaining Rust destructors still call DPDK mbuf/pool primitives (`rte_mempool_free`, `shim_rte_mbuf_refcnt_update`, `shim_rte_pktmbuf_free`). If ENA queue release has already torn down queue/pool associations, those late frees can segfault inside DPDK/PMD code with no Rust panic, exactly matching exit 139 after PMD release logs.

The crash distribution also fits: `bench-stress`, `bench-vs-mtcp`, repeated `bench-e2e`, and subprocess `bench-ab-runner` execute more scenarios per process or after more traffic, so there is more opportunity to leave RX delivered segments, OOO segments, retrans entries, or a nonempty pending TX ring alive at drop.

## Disagreements with the Claude subagents (if any)
I disagree with the v2 recommendation to focus on `rte_eal_cleanup` first. The code-local ordering bug is sufficient: `Engine::drop` closes the port at `engine.rs:5647-5648`, while mbuf-owning state is still present at `engine.rs:447`, `:461`, and conditionally `:587`.

I also disagree with "drop mempools after `rte_eth_dev_close`" as the main fix. The surgical invariant should be stronger: release all Rust-side mbuf owners before port close, then let empty mempools die.

## Minimal fix
In `crates/dpdk-net-core/src/engine.rs:5643`, change `Drop for Engine` to perform explicit mbuf-owner teardown before `rte_eth_dev_stop` / `rte_eth_dev_close`:

```diff
 impl Drop for Engine {
     fn drop(&mut self) {
+        self.teardown_mbuf_owners_before_port_close();
         unsafe {
             sys::rte_eth_dev_stop(self.cfg.port_id);
             sys::rte_eth_dev_close(self.cfg.port_id);
         }
     }
 }
```

That helper should drain/free `tx_pending_data`, drain each conn's `snd_retrans` with `shim_rte_pktmbuf_free`, drop/clear `flow_table` so RX `MbufHandle` and `ReorderQueue` refs release, and `take()` the feature-gated `fault_injector` when compiled.

## Verification
Without AWS/NIC: add a host-only drop-order unit test using fake/shim DPDK free functions that record calls and assert all mbuf-owner releases precede `rte_eth_dev_close`. Add a `test-inject` local TAP loopback test that creates readable data, OOO data, pending TX, and retrans state, then drops `Engine` and asserts no mbuf refs remain. Miri can cover the Rust drop-order helper shape if DPDK FFI calls are mocked behind `#[cfg(test)]`.
