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
// A8 T16 (initial): 167 .pkt under gtests/. All 167 were blocked at
// the shell-init step because 163/167 source `../common/defaults.sh`
// / `set_sysctls.py`, and those upstream scripts call `sysctl -q` /
// write to /proc/sys/net/... -- unavailable inside the shim.
//
// A8.5 T6: patch 0007 + A8.5 T6 invoker-cwd fix removed the shell-
// init blocker. The invoker now chdirs into the script's directory
// before spawning the shim so relative paths resolve, and stub
// defaults.sh / set_sysctls.py in the submodule reduce the init
// block to a no-op. Empirically, all 167 scripts now progress past
// init; 0 still exit 0 end-to-end because every script hits a deeper
// engine or shim gap (93 fail on the SYN-ACK TCP options shape, the
// rest on fcntl(O_NONBLOCK) flag-shape drift, accept()/connect()
// plumbing, sysctl-dependent behaviors, or unimplemented options).
// The 4 packetdrill-meta scripts (fast_retransmit, socket_err, etc.)
// still fail on the same gaps as before.
//
// GOOGLE_RUNNABLE_COUNT stays at 0 -- the engine gaps behind the 167
// skips are out of T6 scope. See SKIPPED.md for per-script blockers.
pub const GOOGLE_RUNNABLE_COUNT: usize = 0;
pub const GOOGLE_SKIP_UNTRANSLATABLE: usize = 167;
pub const GOOGLE_SKIP_OUT_OF_SCOPE: usize = 0;
