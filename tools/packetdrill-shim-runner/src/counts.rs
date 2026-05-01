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
//
// A8.5 T8 update: patch 0008 routes the shutdown(fd, how) syscall to
// the T7 dpdk_net_shutdown public API. Under AD-A8.5-shutdown-no-half-
// close, SHUT_RD/SHUT_WR return EOPNOTSUPP. SHUT_RDWR dispatches to
// full close. The 11 ligurio shutdown/*.pkt scripts all probe Linux
// half-close semantics (either directly via SHUT_RD/SHUT_WR, or
// indirectly via post-SHUT_RDWR read=0/write=EPIPE expectations), so
// none unlock under T8. LIGURIO_RUNNABLE_COUNT stays at 6; skip
// reasons in classify/ligurio.toml + SKIPPED.md now cite the spec
// deviation explicitly.
//
// A8.5 T9 update: spec §1.1 G + §7 "crash-safety corpus" introduces
// a new classifier verdict "runnable-no-crash" — scripts whose pass
// criterion is *engine-crash-safety* under unexpected peer behavior
// (malformed ICMP, bad syscall arguments, PMTU / frag-needed
// events). These scripts cannot exit 0 because the engine doesn't
// reproduce the scripted wire shape (ICMP delivery / PMTU state
// machine / frag-needed handling isn't modeled), but the goal is
// that they must never trigger a SIGSEGV / SIGABRT / signal kill.
// Each script is soak-tested 100× before being pinned under this
// verdict. LIGURIO_NO_CRASH_COUNT tracks the count; the
// corpus_ligurio test asserts every no-crash script exits with a
// non-signal status (exit < 128).
pub const LIGURIO_RUNNABLE_COUNT: usize = 6;
pub const LIGURIO_NO_CRASH_COUNT: usize = 6;
pub const LIGURIO_SKIP_UNTRANSLATABLE: usize = 110;
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
