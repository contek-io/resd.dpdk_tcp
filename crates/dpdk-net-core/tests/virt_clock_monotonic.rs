#![cfg(feature = "test-server")]

use dpdk_net_core::clock::{now_ns, set_virt_ns};

#[test]
fn set_then_read_matches() {
    set_virt_ns(12_345);
    assert_eq!(now_ns(), 12_345);
}

#[test]
fn monotonic_advance_allowed() {
    set_virt_ns(0);
    set_virt_ns(100);
    set_virt_ns(100);
    set_virt_ns(100_000_000_000);
    assert_eq!(now_ns(), 100_000_000_000);
}

#[test]
#[should_panic(expected = "virtual clock must be monotonic")]
fn non_monotonic_set_panics() {
    set_virt_ns(200);
    set_virt_ns(100);
}

#[test]
fn per_thread_independence() {
    use std::thread;
    set_virt_ns(1000);
    let h = thread::spawn(|| {
        set_virt_ns(0);
        set_virt_ns(50);
        assert_eq!(now_ns(), 50);
    });
    h.join().unwrap();
    assert_eq!(now_ns(), 1000);
}

#[test]
fn tx_intercept_push_drain_roundtrip() {
    use dpdk_net_core::test_tx_intercept::{push_tx_frame, drain_tx_frames};
    // Fresh queue.
    let drained_before = drain_tx_frames();
    assert_eq!(drained_before.len(), 0);

    push_tx_frame(b"abc".to_vec());
    push_tx_frame(b"de".to_vec());

    let drained = drain_tx_frames();
    assert_eq!(drained.len(), 2);
    assert_eq!(&*drained[0], b"abc");
    assert_eq!(&*drained[1], b"de");

    // After drain the queue is empty.
    let after = drain_tx_frames();
    assert_eq!(after.len(), 0);
}
