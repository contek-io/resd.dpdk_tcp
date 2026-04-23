#![no_main]
//! Coverage-only fuzz target for `dpdk_net_core::tcp_state`.
//!
//! Scope: `tcp_state.rs` currently exposes ONLY the eleven-state enum
//! `TcpState` plus `TcpState::label()` and `TcpState::COUNT`. There is no
//! pure `apply_event` / `legal_transition` function to drive with random
//! `(state, event)` tuples — the FSM edges live inline in the packet
//! handlers (engine/flow_table), which aren't pure and can't be safely
//! fuzzed in isolation.
//!
//! We therefore run a coverage-only target: map each input byte onto one
//! of the eleven variants (mod `TcpState::COUNT`) and exercise the two
//! pure paths (`label()` and `Debug`) plus `PartialEq`/`Eq`/`Copy`. This
//! ensures:
//!   1. Every variant is reachable under libFuzzer coverage instrumentation.
//!   2. `label()` never panics (returns `&'static str` for every variant).
//!   3. Future changes that add panicking paths to any of these helpers
//!      are caught.
//! Once a richer pure transition helper lands in `tcp_state.rs`, this
//! target should be upgraded to drive `(state, event)` pairs against it
//! with a canonical-state invariant.

use libfuzzer_sys::fuzz_target;
use dpdk_net_core::tcp_state::TcpState;

fn state_from_byte(b: u8) -> TcpState {
    match (b as usize) % TcpState::COUNT {
        0 => TcpState::Closed,
        1 => TcpState::Listen,
        2 => TcpState::SynSent,
        3 => TcpState::SynReceived,
        4 => TcpState::Established,
        5 => TcpState::FinWait1,
        6 => TcpState::FinWait2,
        7 => TcpState::CloseWait,
        8 => TcpState::Closing,
        9 => TcpState::LastAck,
        _ => TcpState::TimeWait,
    }
}

fuzz_target!(|data: &[u8]| {
    // Pairwise walk so we also exercise `PartialEq` on mixed variants.
    let mut prev: Option<TcpState> = None;
    for &b in data {
        let s = state_from_byte(b);

        // label() — must always return a non-empty &'static str.
        let lbl = s.label();
        assert!(!lbl.is_empty());

        // Debug — must not panic for any variant.
        let _ = format!("{:?}", s);

        // Exercise Copy + PartialEq against the prior state.
        if let Some(p) = prev {
            let _ = p == s;
            // Copy through a local binding to exercise the Copy impl.
            let copied = s;
            assert_eq!(copied.label(), s.label());
        }
        prev = Some(s);

        // Round-trip `as u8` — the `#[repr(u8)]` discriminant must stay
        // in [0, COUNT). If someone later reorders variants and breaks
        // the contiguous 0..=10 range, this catches it.
        let discriminant = s as u8;
        assert!((discriminant as usize) < TcpState::COUNT);
    }
});
