//! A8 T21: integration test for the Urgent probe (RFC 9293 MUST-30/31).
//!
//! Unlike T19's MissingMSS and T20's Reserved-RX, the Urgent probe's
//! PASSING status is a `Deviation`, not a `Pass`. This pins the A8
//! documented deviation `AD-A8-urg-dropped` (spec §6.4): the Stage 1
//! stack drops URG-flagged inbound segments silently and bumps
//! `tcp.rx_urgent_dropped`. The test asserts the probe reaches that
//! deviation verdict — any drift (status = `Pass` or `Fail`) indicates
//! either the deviation was closed (needs spec §6.4 retirement note)
//! or the drop behavior regressed.
//!
//! The harness's internal serialization Mutex (crate-wide `ENGINE_SERIALIZE`)
//! funnels parallel cargo-test workers so this probe cannot race on
//! DPDK mempool-name collisions during `Engine::new`.

use tcpreq_runner::probes::urgent::urgent_dropped;
use tcpreq_runner::ProbeStatus;

#[test]
fn urgent_segment_dropped_per_documented_deviation() {
    let r = urgent_dropped();
    assert_eq!(r.clause_id, "MUST-30/31");
    assert_eq!(r.probe_name, "Urgent");
    match &r.status {
        ProbeStatus::Deviation(cite) => {
            assert_eq!(
                *cite, "AD-A8-urg-dropped",
                "urgent probe must cite AD-A8-urg-dropped from spec §6.4; got cite={cite:?}"
            );
        }
        other => panic!(
            "expected ProbeStatus::Deviation(\"AD-A8-urg-dropped\"); got {other:?} \
             (message: {msg:?})",
            msg = r.message
        ),
    }
}
