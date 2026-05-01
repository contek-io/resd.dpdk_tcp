//! bench-micro::tcp_input — spec §11.2 targets 7 + 8.
//!
//! `bench_tcp_input_data_segment` measures `tcp_input::dispatch` for an
//! in-order data segment with PAWS + SACK enabled.
//! `bench_tcp_input_ooo_segment` measures the same for an OOO segment
//! that queues into the reassembly buffer.
//!
//! # Setup parity with in-tree unit tests
//!
//! These benches use the same TcpConn construction pattern as
//! `crates/dpdk-net-core/src/tcp_input.rs::tests::est_conn` and
//! `established_ooo_segment_queues_into_reassembly`. We cannot import
//! those helpers directly — they live under `#[cfg(test)]` — so the
//! setup is open-coded here but mirrors the shapes.
//!
//! A fake `rte_mbuf` pointer backed by boxed 256-B storage covers the
//! refcount-shim dereferences made by the reassembly path. The shim
//! only touches the first cacheline's `refcnt` field.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dpdk_net_core::engine::DEFAULT_RTT_HISTOGRAM_EDGES_US;
use dpdk_net_core::flow_table::FourTuple;
use dpdk_net_core::tcp_conn::TcpConn;
use dpdk_net_core::tcp_input::{dispatch, MbufInsertCtx, ParsedSegment};
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::TCP_ACK;
use dpdk_net_core::tcp_state::TcpState;
use std::time::Duration;

const TEST_SEND_BUF_BYTES: u32 = 256 * 1024;

/// Shared ESTABLISHED-state conn construction. Mirrors the in-tree
/// `tcp_input::tests::est_conn` shape; TS + SACK are opt-in per caller
/// so the OOO bench (target 8) can measure reassembly-queue enqueue
/// without PAWS early-rejecting segments that arrive without a
/// Timestamps option.
fn make_est_conn(
    iss: u32,
    irs: u32,
    peer_wnd: u16,
    ts: Option<u32>,
    sack: bool,
) -> TcpConn {
    let t = FourTuple {
        local_ip: 0x0a_00_00_02,
        local_port: 40000,
        peer_ip: 0x0a_00_00_01,
        peer_port: 5000,
    };
    let mut c = TcpConn::new_client(t, iss, 1460, 1024, 2048, 5000, 5000, 1_000_000);
    c.state = TcpState::Established;
    c.snd_una = iss.wrapping_add(1);
    c.snd_nxt = iss.wrapping_add(1);
    c.irs = irs;
    c.rcv_nxt = irs.wrapping_add(1);
    c.snd_wnd = peer_wnd as u32;
    if let Some(ts_recent) = ts {
        c.ts_enabled = true;
        c.ts_recent = ts_recent;
    }
    c.sack_enabled = sack;
    c
}

fn bench_tcp_input_data_segment(c: &mut Criterion) {
    c.bench_function("bench_tcp_input_data_segment", |b| {
        // Encode a minimal Timestamps option. SACK_PERMITTED was already
        // exchanged on the handshake; we don't repeat it per-segment.
        let peer_opts = TcpOpts {
            timestamps: Some((0x0000_1000, 0xCAFEBABE)),
            ..Default::default()
        };
        let mut opts_buf = [0u8; 40];
        let opts_len = peer_opts.encode(&mut opts_buf).expect("encode opts");
        let payload = [0xABu8; 64];

        // Fake mbuf storage for the in-order append path's refcount shim.
        let mut fake_storage: Box<[u8; 256]> = Box::new([0u8; 256]);
        let mbuf_ctx = MbufInsertCtx {
            mbuf: unsafe {
                std::ptr::NonNull::new_unchecked(
                    fake_storage.as_mut_ptr() as *mut dpdk_net_sys::rte_mbuf
                )
            },
            payload_offset: 54,
        };

        b.iter_batched_ref(
            // Per-iteration setup: fresh conn so each dispatch sees an
            // in-order segment at rcv_nxt (5001), rather than the state
            // advancing after the first iteration.
            || make_est_conn(1000, 5000, 1024, Some(200), true),
            |c| {
                // Increment TSval slightly so PAWS accepts. Using a
                // fresh conn per-iteration means ts_recent == 200 on
                // entry, so TSval=300 is always in-window.
                let seg = ParsedSegment {
                    src_port: 5000,
                    dst_port: 40000,
                    seq: 5001,
                    ack: 1001,
                    flags: TCP_ACK,
                    window: 65535,
                    header_len: 20 + opts_len,
                    payload: &payload,
                    options: &opts_buf[..opts_len],
                };
                let out = dispatch(
                    black_box(c),
                    black_box(&seg),
                    &DEFAULT_RTT_HISTOGRAM_EDGES_US,
                    TEST_SEND_BUF_BYTES,
                    Some(mbuf_ctx),
                );
                black_box(out);
            },
            criterion::BatchSize::SmallInput,
        );

        // Keep fake_storage alive until the TcpConn's (and therefore the
        // ReorderQueue's) Drop observes the refcnt field.
        let _ = &mut fake_storage;
    });
}

fn bench_tcp_input_ooo_segment(c: &mut Criterion) {
    c.bench_function("bench_tcp_input_ooo_segment", |b| {
        // OOO segment: seq > rcv_nxt, so it queues into the reorder
        // buffer. No options payload (matches the in-tree OOO test's
        // minimalism at tcp_input.rs:1866).
        //
        // IMPORTANT: TS stays disabled here. If `conn.ts_enabled` were
        // true, `dispatch` would PAWS-early-reject any segment lacking
        // a Timestamps option (tcp_input.rs:606-614), returning before
        // touching the reassembly queue. The point of this target is
        // to measure reassembly-queue enqueue cost (~200-400 ns per
        // spec §11.2), not PAWS rejection (~27 ns).
        let payload = [0x42u8; 64];

        let mut fake_storage: Box<[u8; 256]> = Box::new([0u8; 256]);
        let mbuf_ctx = MbufInsertCtx {
            mbuf: unsafe {
                std::ptr::NonNull::new_unchecked(
                    fake_storage.as_mut_ptr() as *mut dpdk_net_sys::rte_mbuf
                )
            },
            payload_offset: 54,
        };

        b.iter_batched_ref(
            || make_est_conn(1000, 5000, 1024, None, false),
            |c| {
                // seq=5100 > rcv_nxt=5001 → reassembly queue path.
                let seg = ParsedSegment {
                    src_port: 5000,
                    dst_port: 40000,
                    seq: 5100,
                    ack: 1001,
                    flags: TCP_ACK,
                    window: 65535,
                    header_len: 20,
                    payload: &payload,
                    options: &[],
                };
                let out = dispatch(
                    black_box(c),
                    black_box(&seg),
                    &DEFAULT_RTT_HISTOGRAM_EDGES_US,
                    TEST_SEND_BUF_BYTES,
                    Some(mbuf_ctx),
                );
                black_box(out);
            },
            criterion::BatchSize::SmallInput,
        );
        let _ = &mut fake_storage;
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100);
    targets = bench_tcp_input_data_segment, bench_tcp_input_ooo_segment
}
criterion_main!(benches);
