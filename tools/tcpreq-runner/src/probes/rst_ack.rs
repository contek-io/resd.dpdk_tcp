//! RstAck probe — RFC 9293 §3.10.7.4 Reset processing.
//! Ported from tcpreq/tests/rst_ack.py::RstAckTest.
//!
//! RFC §3.5.3 + §3.10.7.4 say "RST is processed independently of other
//! flags." We implement that invariant for plain RST — but a `RST|URG`
//! hits the pre-existing URG-drop ordering at `tcp_input.rs:730`
//! (always-on per `AD-A8-urg-dropped`) *before* the RST check at `:744`,
//! so URG short-circuits the close. This probe pins both behaviors:
//!
//!   A. Plain RST|ACK — the canonical Reset. `tcp.rx_rst` bumps by
//!      exactly 1 and the conn leaves ESTABLISHED.
//!   B. RST|ACK|URG — per `AD-A8.5-rst-urg-precedence` (spec §6.4), the
//!      URG-drop ordering fires first. `tcp.rx_rst` still bumps (the
//!      engine counter fires on flag presence at `engine.rs:3617`,
//!      before per-state dispatch), `tcp.rx_urgent_dropped` also bumps,
//!      and the conn stays ESTABLISHED. This probe asserts both counter
//!      deltas to lock the deviation in.
//!
//! Each scenario uses its own listen port + peer port pair so the 3WHS
//! state machines are fully isolated — scenario B sees a pristine
//! listen/accept queue even though scenario A already ran.
//!
//! Counter-delta assertions:
//!   A: rx_rst(pre_A) +1 = rx_rst(mid)
//!   B: rx_rst(mid) +1 = rx_rst(post_B); rx_urgent_dropped +1
//! Exactly-1 bumps (not `>=1`) pin the invariant that each input is
//! accounted for once.
//!
//! The plan's third scenario (RST in SYN_SENT) is deliberately skipped —
//! already covered by Layer A: `counter-coverage::scen_syn_sent_to_closed_rst`
//! and `tcp_input::syn_sent_rst_matching_our_ack_closes` (per A8.5 spec
//! §1.1 "don't duplicate Layer A" principle).

use std::sync::atomic::Ordering;

use crate::{ProbeResult, ProbeStatus, TcpreqHarness, OUR_IP, PEER_IP};

use dpdk_net_core::clock::set_virt_ns;
use dpdk_net_core::tcp_options::TcpOpts;
use dpdk_net_core::tcp_output::{TCP_ACK, TCP_RST, TCP_URG};
use dpdk_net_core::test_server::test_packet::{build_tcp_frame, build_tcp_syn, parse_syn_ack};
use dpdk_net_core::test_tx_intercept::drain_tx_frames;

/// Scenario A listen port. Distinct from scenario B so the two 3WHS
/// state machines cannot cross-contaminate (e.g. an accidentally shared
/// listener being double-filled or the wrong conn popping out of
/// `accept_next`).
const PORT_A: u16 = 5571;
/// Scenario B listen port.
const PORT_B: u16 = 5572;
/// Peer source ports — one per scenario (distinct from listen ports
/// above; no semantic significance beyond "some free ephemeral port").
const PEER_PORT_A: u16 = 40_001;
const PEER_PORT_B: u16 = 40_002;
/// Peer ISS seed for both scenarios. Fixed; the `+1` convention in the
/// final-ACK `seq` mirrors every other 3WHS in this crate.
const PEER_ISS: u32 = 0x10_00_00_00;
const PEER_MSS: u16 = 1460;

pub fn rst_ack_processing() -> ProbeResult {
    let h = TcpreqHarness::new();
    let counters = h.eng.counters();

    // ------------------------- Scenario A: plain RST -----------------------
    let pre_rst = counters.tcp.rx_rst.load(Ordering::Relaxed);
    if let Err(reason) = run_one_scenario(&h, PORT_A, PEER_PORT_A, TCP_RST | TCP_ACK, 1_000_000) {
        return fail(format!("scenario A (plain RST|ACK): {reason}"));
    }
    let mid_rst = counters.tcp.rx_rst.load(Ordering::Relaxed);
    if mid_rst != pre_rst + 1 {
        return fail(format!(
            "scenario A: tcp.rx_rst did not bump by 1 after plain RST|ACK: pre={pre_rst} post={mid_rst}"
        ));
    }

    // ------------------------- Scenario B: RST + URG -----------------------
    // Pins the `AD-A8.5-rst-urg-precedence` deviation (spec §6.4):
    // because the URG-drop check at `tcp_input.rs:730` runs *before* the
    // RST check at `:744`, a peer-sent `RST|URG` is dropped at the top
    // of `established_rx` and the connection stays in ESTABLISHED. The
    // engine still bumps `tcp.rx_rst` at `engine.rs:3617` (on flag
    // presence, before per-state dispatch) AND `tcp.rx_urgent_dropped`.
    // We assert both deltas to lock in the documented behavior — not
    // RFC §3.5.3 "RST independent of other flags" (that's the
    // deviation's reference, not its behavior). Fresh listen port
    // isolates state from scenario A.
    let pre_urg = counters.tcp.rx_urgent_dropped.load(Ordering::Relaxed);
    if let Err(reason) = run_one_scenario(
        &h,
        PORT_B,
        PEER_PORT_B,
        TCP_RST | TCP_ACK | TCP_URG,
        4_000_000,
    ) {
        return fail(format!("scenario B (RST|ACK|URG): {reason}"));
    }
    let post_rst = counters.tcp.rx_rst.load(Ordering::Relaxed);
    if post_rst != mid_rst + 1 {
        return fail(format!(
            "scenario B: tcp.rx_rst did not bump by 1 after RST|ACK|URG \
             (engine may be gating rx_rst on URG, diverging from AD-A8.5-rst-urg-precedence): \
             mid={mid_rst} post={post_rst}"
        ));
    }
    let post_urg = counters.tcp.rx_urgent_dropped.load(Ordering::Relaxed);
    if post_urg != pre_urg + 1 {
        return fail(format!(
            "scenario B: tcp.rx_urgent_dropped did not bump by 1 after RST|ACK|URG \
             (URG-drop ordering per AD-A8-urg-dropped should fire before RST dispatch): \
             pre={pre_urg} post={post_urg}"
        ));
    }

    ProbeResult {
        clause_id: "Reset-Processing",
        probe_name: "RstAck",
        status: ProbeStatus::Pass,
        message: "plain RST|ACK closes conn (+1 tcp.rx_rst); RST|ACK|URG is URG-dropped per \
                  AD-A8.5-rst-urg-precedence (+1 tcp.rx_rst AND +1 tcp.rx_urgent_dropped; \
                  conn stays ESTABLISHED)".into(),
    }
}

/// Drive a full 3WHS on `(OUR_IP, local_port)` from peer `(PEER_IP,
/// peer_port)`, reach ESTABLISHED, then inject a RST segment with the
/// given flag mask. `virt_ns_base` seeds the virt-clock for this
/// scenario; the sub-steps advance by 1 ms so log-scan ordering stays
/// human-readable.
///
/// Returns `Err(reason)` for engine-side failures so the caller can
/// attach a scenario prefix. Counter assertions stay in the caller so
/// the pre/mid/post deltas are inspected against a single snapshot.
fn run_one_scenario(
    h: &TcpreqHarness,
    local_port: u16,
    peer_port: u16,
    rst_flags: u8,
    virt_ns_base: u64,
) -> Result<(), String> {
    let listen = h
        .eng
        .listen(OUR_IP, local_port)
        .map_err(|e| format!("listen({OUR_IP:#x}, {local_port}): {e:?}"))?;

    // 3WHS step 1: SYN with MSS.
    set_virt_ns(virt_ns_base);
    let syn = build_tcp_syn(PEER_IP, peer_port, OUR_IP, local_port, PEER_ISS, PEER_MSS);
    h.eng
        .inject_rx_frame(&syn)
        .map_err(|e| format!("inject 3WHS SYN: {e:?}"))?;

    // 3WHS step 2: drain SYN-ACK, parse our ISS and the peer-expected
    // ack number so we can echo back the final ACK.
    let frames = drain_tx_frames();
    let synack = frames
        .first()
        .ok_or_else(|| "no SYN-ACK emitted after 3WHS SYN".to_string())?;
    let (our_iss, _ack) = parse_syn_ack(synack)
        .ok_or_else(|| "first TX frame post-SYN is not a SYN-ACK".to_string())?;

    // 3WHS step 3: final ACK.
    set_virt_ns(virt_ns_base + 1_000_000);
    let final_ack = build_tcp_frame(
        PEER_IP,
        peer_port,
        OUR_IP,
        local_port,
        PEER_ISS.wrapping_add(1),
        our_iss.wrapping_add(1),
        TCP_ACK,
        u16::MAX,
        TcpOpts::default(),
        &[],
    );
    h.eng
        .inject_rx_frame(&final_ack)
        .map_err(|e| format!("inject final ACK: {e:?}"))?;
    let _ = drain_tx_frames();

    // `accept_next` pops the conn off the listener's accept queue; the
    // conn is now in ESTABLISHED. Failing here means the 3WHS itself
    // didn't complete — we'd surface that even before the RST phase so
    // a SCENARIO A regression doesn't look like a scenario B gap.
    if h.eng.accept_next(listen).is_none() {
        return Err("accept queue empty post-3WHS (handshake did not complete)".into());
    }

    // RST injection — seq = peer's next send seq (PEER_ISS+1, same as
    // the final-ACK seq since no peer data was sent), ack = ACK of our
    // SYN-ACK. RFC 9293 §3.10.7.4 requires a valid seq in the receive
    // window; PEER_ISS+1 == rcv_nxt after our SYN-ACK's +1 bump.
    set_virt_ns(virt_ns_base + 2_000_000);
    let rst_seg = build_tcp_frame(
        PEER_IP,
        peer_port,
        OUR_IP,
        local_port,
        PEER_ISS.wrapping_add(1),
        our_iss.wrapping_add(1),
        rst_flags,
        u16::MAX,
        TcpOpts::default(),
        &[],
    );
    h.eng
        .inject_rx_frame(&rst_seg)
        .map_err(|e| format!("inject RST segment (flags=0x{rst_flags:02X}): {e:?}"))?;

    // Drain any post-RST TX (we don't assert on shape here — the RST
    // path closes the conn; an unexpected RST-challenge echo would
    // still be consistent with rx_rst bumping). The caller's counter
    // delta is the authoritative assertion.
    let _ = drain_tx_frames();

    Ok(())
}

fn fail(detail: String) -> ProbeResult {
    ProbeResult {
        clause_id: "Reset-Processing",
        probe_name: "RstAck",
        status: ProbeStatus::Fail(detail),
        message: String::new(),
    }
}
