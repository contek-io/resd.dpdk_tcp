//! A5 TAP fault-injection harness smoke test.
//! Full integration scenarios in Tasks 28-30.

mod common;

#[test]
fn tap_peer_mode_module_compiles() {
    let m = common::TapPeerMode::new().with_drop_next_tx();
    assert!(m.drop_next_tx);
}
