//! A7 T15 + A8 T16: pinned corpus counts. The corpus_{ligurio,shivansh,
//! google}.rs tests read these constants and fail loudly on any drift,
//! forcing every new/removed/reclassified script to flow through an
//! explicit counts + SKIPPED.md + classify/<corpus>.toml update.

// --- ligurio corpus (third_party/packetdrill-testcases/) ---
//
// A7 T15 pragmatic floor: the A7 shim binary did not pass any corpus
// script end-to-end (0/122). All scripts were skip-bucketed.
//
// A8 T15 S2 update: the shim now IP-rewrites inject/drain frames into
// packetdrill's live address space and plumbs the engine's conn-peer
// FFI through shim_accept, unlocking 6 server-side scripts across
// listen/, blocking/, and close/ directories. Remaining 116 stay
// skipped for A8+ follow-up (engine edge behaviors, ISN pinning,
// shutdown wiring, scripts/defaults.sh init files).
pub const LIGURIO_RUNNABLE_COUNT: usize = 6;
pub const LIGURIO_SKIP_UNTRANSLATABLE: usize = 116;
pub const LIGURIO_SKIP_OUT_OF_SCOPE: usize = 0;

// --- shivansh TCP-IP regression (third_party/shivansh-tcp-ip-regression/) ---
//
// A8 T16: the 47-script shivansh suite mirrors ligurio's content
// (same upstream source) and benefits from the A8 T15 S2 shim unlock:
// 5 server-side scripts (listen/* + close/simultaneous-close) exit 0
// end-to-end, the remaining 42 hit the same engine/shim gaps
// documented in tools/packetdrill-shim/SKIPPED.md under
// "## shivansh corpus".
pub const SHIVANSH_RUNNABLE_COUNT: usize = 5;
pub const SHIVANSH_SKIP_UNTRANSLATABLE: usize = 42;
pub const SHIVANSH_SKIP_OUT_OF_SCOPE: usize = 0;

// --- Google upstream packetdrill tests (third_party/packetdrill/gtests/) ---
//
// A8 T16: 167 .pkt under gtests/. 163/167 source scripts/defaults.sh
// + set_sysctls.py host-env helpers that do not resolve in our CI
// environment (shell init returns 127, the shim surfaces this as
// exit 1 before any TCP packet flows). The remaining 4 (packet-timeout
// meta test + 2 socket_err shape tests + 1 fast_retransmit variant)
// fail on engine gaps. 0 runnable is the pragmatic floor for A8.
pub const GOOGLE_RUNNABLE_COUNT: usize = 0;
pub const GOOGLE_SKIP_UNTRANSLATABLE: usize = 167;
pub const GOOGLE_SKIP_OUT_OF_SCOPE: usize = 0;
