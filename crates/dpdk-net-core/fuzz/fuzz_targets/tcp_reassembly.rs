#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;
use std::ptr::NonNull;

use dpdk_net_core::tcp_conn::InOrderSegment;
use dpdk_net_core::tcp_reassembly::ReorderQueue;
use dpdk_net_core::tcp_seq::seq_le;
use dpdk_net_sys::rte_mbuf;

// Coverage-guided fuzz of `ReorderQueue` structural invariants (pairs
// with tests/proptest_tcp_reassembly.rs). Drives arbitrary interleavings
// of `insert` and `drain_contiguous_into` against a single fake-mbuf
// backing buffer. After every operation we re-check:
//
//   I1. `total_bytes() <= cap` always.
//   I2. Stored segments are pairwise disjoint in [seq, seq+len) — the
//       carve-on-insert path must never leave overlapping entries.
//
// Fake-mbuf backing: the queue's refcount bookkeeping calls
// `shim_rte_mbuf_refcnt_update(ptr, +/-1)`, which is a pure 16-bit RMW
// on the refcnt field at a small offset — it never derefs payload,
// never frees, and never touches the mempool. A zeroed 256-byte Vec
// that outlives every `MbufHandle` drop is therefore a safe backing.
// This is the same pattern used by `proptest_tcp_reassembly.rs` and by
// the inline unit tests in `src/tcp_reassembly.rs` (which forget their
// output VecDeques because proptest/unit test runs don't have
// LeakSanitizer; the fuzz target runs under ASAN+LSAN, so we instead
// let the natural Drop chain run — the refcnt decrements just scribble
// safely on `fake`).
//
// Declaration order: `fake` is declared BEFORE `q`, so Rust drops `q`
// first at end-of-iteration; `q`'s Drop decrements refcounts on any
// still-queued segments into the still-live `fake` bytes. Drained
// `InOrderSegment`s likewise live inside `out` on the stack and are
// dropped before `fake` when `out` goes out of scope at the end of the
// branch.
fuzz_target!(|data: &[u8]| {
    let mut fake = vec![0u8; 256];
    let mbuf: NonNull<rte_mbuf> =
        NonNull::new(fake.as_mut_ptr() as *mut rte_mbuf).unwrap();

    // Cap chosen large enough to rarely hit cap-drop for the 5-byte
    // command stream, small enough to bound per-iteration memory.
    // Sequence base sits well away from u32 wrap so wrap-aware
    // `seq_le` reduces to plain `<=` for the bounded `seq_offset` (u16).
    let cap: u32 = 16 * 1024;
    let mut q = ReorderQueue::new(cap);
    let base_seq: u32 = 1_000_000;

    // Decode input as a stream of 5-byte commands:
    //   [0..2]  u16 LE seq offset (added to base_seq)
    //   [2..4]  u16 LE payload length (clamped to <= 256)
    //   [4]     bit 0 — 1 = drain, 0 = insert
    for chunk in data.chunks_exact(5) {
        let seq_offset = u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
        let len = (u16::from_le_bytes([chunk[2], chunk[3]]) as u32).min(256);
        let is_drain = (chunk[4] & 1) == 1;

        if is_drain {
            let mut out: VecDeque<InOrderSegment> = VecDeque::new();
            let _ = q.drain_contiguous_into(
                base_seq.wrapping_add(seq_offset),
                u32::MAX,
                &mut out,
            );
            // `out` is dropped here: each InOrderSegment's MbufHandle
            // Drop decrements the refcnt in `fake` — safe, since `fake`
            // outlives `out`.
        } else if len > 0 {
            let payload = vec![0u8; len as usize];
            let seq = base_seq.wrapping_add(seq_offset);
            let _ = q.insert(seq, &payload, mbuf, 0);
        }

        // I1: `total_bytes()` never exceeds `cap`.
        assert!(
            q.total_bytes() <= cap,
            "total_bytes {} exceeds cap {}",
            q.total_bytes(),
            cap,
        );

        // I2: stored segments are pairwise disjoint on half-open
        // [seq, seq+len). We use `seq_le` for wrap-aware ordering even
        // though the bounded input keeps us clear of wrap.
        let segs = q.segments();
        for i in 0..segs.len() {
            let a = &segs[i];
            let a_end = a.seq.wrapping_add(a.len as u32);
            for j in (i + 1)..segs.len() {
                let b = &segs[j];
                let b_end = b.seq.wrapping_add(b.len as u32);
                assert!(
                    seq_le(a_end, b.seq) || seq_le(b_end, a.seq),
                    "overlap: seq={} len={} vs seq={} len={}",
                    a.seq,
                    a.len,
                    b.seq,
                    b.len,
                );
            }
        }
    }

    // End-of-iteration: `q` falls out of scope first (declared after
    // `fake`), so `ReorderQueue::Drop` decrements refcounts on any
    // still-queued segments while `fake` is still alive; then `fake`
    // is freed. No leak, no UAF.
});
