//! RstAck probe — RFC 9293 §3.10.7.4 Reset processing.
//! Ported from tcpreq/tests/rst_ack.py::RstAckTest.
//!
//! Spec §1.1 A: "RST is processed independently of other flags." A
//! valid RST in ESTABLISHED MUST close the connection regardless of
//! whether URG (or other non-error flag combinations) are co-set. The
//! `tcp.rx_rst` counter MUST bump for every such RST received.
//!
//! The probe runs two scenarios on fresh 3WHS-completed connections:
//!
//!   A. Plain RST|ACK — the canonical Reset. Expected: `tcp.rx_rst`
//!      bumps by exactly 1.
//!   B. RST|ACK|URG — RST with an incidental URG bit set. Expected:
//!      still processed as RST; `tcp.rx_rst` bumps by exactly 1 (on
//!      top of scenario A's bump).
//!
//! Each scenario uses its own listen port + peer port pair so the 3WHS
//! state machines are fully isolated — scenario B sees a pristine
//! listen/accept queue even though scenario A already ran.
//!
//! Counter-delta assertion (A then B): rx_rst(pre_A) +1 = rx_rst(mid),
//! rx_rst(mid) +1 = rx_rst(post_B). Exactly-1 bumps (not `>=1`) pin the
//! invariant that each RST is accounted for once, and that the RST+URG
//! path doesn't accidentally bump the counter twice via a stray URG
//! handler.
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
    // Spec §1.1 A: "RST is processed independently of other flags." The
    // URG bit must not gate RST dispatch. A fresh listen port + 3WHS
    // ensures we're closing a connection that was just established —
    // the scenario A conn is already in Closed, so it can't also bump.
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
            "scenario B: tcp.rx_rst did not bump by 1 after RST|ACK|URG (engine may be gating RST on !URG): \
             mid={mid_rst} post={post_rst}"
        ));
    }

    ProbeResult {
        clause_id: "Reset-Processing",
        probe_name: "RstAck",
        status: ProbeStatus::Pass,
        message: "plain RST|ACK and RST|ACK|URG both processed independently of other flags; \
                  tcp.rx_rst bumped +1 per RST (spec §1.1 A)"
            .into(),
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
