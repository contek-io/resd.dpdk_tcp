# Panic audit — 2026-04-20

Ran `scripts/audit-panics.sh` against branch `phase-a6.6-7` at commit
`72f8f15ced064bc0cdb65064c58700f5dd9b1e33`.

The script greps for `panic!`, `.unwrap()`, `.expect(`, and `unchecked_*`
across `crates/dpdk-net/src/**.rs` and `crates/dpdk-net-core/src/**.rs`.
Each hit is classified below into one of three buckets:

- **test-only** — inside `#[cfg(test)]`, `#[test]`, `tests/`, or feature-
  gated test entries. Excluded from the production panic surface.
- **slow-path** — engine-create, validation pre-init, or one-time
  initialization paths. Accepted because they fire at most once per
  process and cannot occur on the data path.
- **hot-path** — reachable from `poll_once`, `send_bytes`, or
  `deliver_readable`. Each MUST be either converted to errno OR
  documented unreachable-by-construction.

## Summary

- Total hits across crates/dpdk-net + crates/dpdk-net-core: **111**
- Test-only (excluded): **98**
- Slow-path accepted: **3**
- Hot-path fixed (converted to errno): **0**
- Hot-path documented unreachable-by-construction: **10**

No errno conversions were required: every hot-path site is either a
peek-then-pop on a checked `Some(_)`, a fixed-size slice `try_into()`, a
pre-sized buffer `encode()`, or a value just-set on the line above —
none are reachable failure modes.

## Hot-path findings (action required → all unreachable-by-construction)

### crates/dpdk-net-core/src/tcp_retrans.rs:79 — `self.entries.pop_front().unwrap()`

Classification: hot-path (`poll_once` → `prune_below`, used by tests and
non-hot-path callers; the hot-path peer `prune_below_into_mbufs` shares
the same pattern at line 105).
Disposition: unreachable — guarded by the immediately-preceding
`while let Some(front) = self.entries.front()` peek. Existing code
relies on the peek-then-pop invariant; no SAFETY comment needed since
the loop structure already documents the guard.

### crates/dpdk-net-core/src/tcp_retrans.rs:105 — `self.entries.pop_front().unwrap()`

Classification: hot-path (`poll_once` → `prune_below_into_mbufs`).
Disposition: unreachable — same peek-then-pop pattern as line 79
(loop entry is `while let Some(front) = self.entries.front()`).

### crates/dpdk-net-core/src/tcp_output.rs:158 — `seg.options.encode(...).expect("pre-sized exactly; encode must fit")`

Classification: hot-path (`build_segment` is called from `poll_once`'s
TX path on every emitted segment).
Disposition: unreachable-by-construction — `tcp_hdr_len` includes
`opts_len`, the destination slice is `&mut th[TCP_HDR_MIN..TCP_HDR_MIN
+ opts_len]` (exactly `opts_len` bytes), and `encode` writes at most
`opts_len` bytes by construction. The expect message documents the
invariant; no further annotation needed.

### crates/dpdk-net-core/src/tcp_rtt.rs:51 — `self.srtt_us.unwrap()`

Classification: hot-path (`sample` is called from RTT-sample handling
inside `poll_once`'s ACK processing).
Disposition: unreachable-by-construction — the `match` immediately
above sets `self.srtt_us = Some(...)` in BOTH arms (None branch sets
to `Some(rtt)`, Some branch sets to `Some(...)`). The unwrap is on
the line directly following the match, with no intervening writes.
The existing inline comment notes "safe to unwrap" patterns
elsewhere; this site is structurally the same.

### crates/dpdk-net-core/src/siphash24.rs:31 — `key[0..8].try_into().unwrap()`

Classification: hot-path (siphash24 is invoked on every RX flow lookup
via `flow_table::siphash_4tuple`).
Disposition: unreachable-by-construction — `key` is `&[u8; 16]`, so
`key[0..8]` is a slice of length 8, and `try_into()` to `[u8; 8]`
cannot fail. Type-system guaranteed.

### crates/dpdk-net-core/src/siphash24.rs:32 — `key[8..16].try_into().unwrap()`

Classification: hot-path (same path as line 31).
Disposition: unreachable-by-construction — same reasoning
(`key[8..16]` has length 8 from a `&[u8; 16]`).

### crates/dpdk-net-core/src/siphash24.rs:40 — `msg[i..i + 8].try_into().unwrap()`

Classification: hot-path (siphash24 inner-loop slice conversion).
Disposition: unreachable-by-construction — the enclosing `while i + 8
<= msg.len()` guard ensures `msg[i..i+8]` always has length 8, so the
`try_into()` to `[u8; 8]` cannot fail. Loop predicate guarantees it.

### crates/dpdk-net-core/src/engine.rs:3754 — `conn.recv.bytes.pop_front().unwrap()`

Classification: hot-path (`deliver_readable`-reachable; this is the
in-order segment delivery loop).
Disposition: unreachable-by-construction — guarded by the matching
`Some(seg) if seg.len as u32 <= remaining` arm above, which only
fires when `front()` returned `Some(_)`. The pop happens immediately
under that match arm with no intervening mutation of `recv.bytes`.
The `None` arm `break`s out before reaching this site.

### crates/dpdk-net-core/src/engine.rs:3764 — `conn.recv.bytes.front_mut().unwrap()`

Classification: hot-path (`deliver_readable`-reachable; partial-pop
split branch).
Disposition: unreachable-by-construction — same `Some(_seg)` match
arm guards entry to this branch. The borrow checker forces
`front()` immediate-prior `front_mut()` to return the same
`Some(_)` because there are no intervening pops.

### crates/dpdk-net-core/src/engine.rs:4373 — `c.rtt_est.srtt_us().unwrap()`

Classification: hot-path (`arm_tlp_pto` is called from `poll_once`'s
post-TX TLP arming).
Disposition: unreachable-by-construction — guarded by
`c.tlp_arm_gate_passes()` which asserts `srtt_us().is_some()` per
its own `tcp_conn::tlp_arm_gate_passes` contract. The existing
inline comment "Gate asserts `srtt_us().is_some()` — safe to
unwrap" already documents this. Verified by reading
`tcp_conn::tlp_arm_gate_passes` (returns false when `srtt_us` is
None).

## Slow-path accepted

### crates/dpdk-net-core/src/clock.rs:52 — `check_invariant_tsc().expect(...)`

Inside `calibrate()`, called once via `OnceLock::get_or_init`.
Defense-in-depth: `clock::init()` is supposed to fail-fast at engine
creation when invariant TSC is missing (`Error::NoInvariantTsc`); the
expect is the last-resort guard if `now_ns()` is invoked without a
prior `init()`. Process-startup-only; cannot occur during
`poll_once`. Existing comment documents the expectation.

### crates/dpdk-net-core/src/engine.rs:587 — `EAL_INIT.lock().unwrap()`

Inside `eal_init`, runs once per process. Mutex `unwrap` only fails
on poison, which would only occur if a prior thread panicked while
holding the EAL init lock — and `panic = "abort"` already terminates
the process before that can happen. Consistent with std-lib idioms
for process-global mutexes.

### crates/dpdk-net-core/src/engine.rs:613 — `CString::new(*s).unwrap()`

Inside `eal_init`, runs once per process. `CString::new` only fails
on interior NUL bytes; EAL args are constructed by the FFI shim
from validated C strings or static `&str` literals (no embedded
NULs by construction). Validation happens in `dpdk_net_engine_create`
before reaching this point.

## Test-only (not counted)

Sites inside `#[cfg(test)]` modules, `#[test]` blocks, or the
`test-panic-entry` feature gate. These cannot be reached from FFI
production builds.

### crates/dpdk-net (FFI crate)

- `dpdk-net/src/test_only.rs:16` — `panic!("dpdk_net panic firewall test")` — feature-gated `test-panic-entry`, intentional firewall verification target.
- `dpdk-net/src/lib.rs:1212` — preset-RFC test.
- `dpdk-net/src/lib.rs:1229` — preset-latency test.
- `dpdk-net/src/lib.rs:1315` — TLP zero-init test.
- `dpdk-net/src/lib.rs:1329` — TLP rejection-helper `expect_err` panic.
- `dpdk-net/src/lib.rs:1354,1358,1375,1384,1404,1413,1425,1434` — TLP boundary/passthrough tests.
- `dpdk-net/src/lib.rs:1445,1521,1539,1560` — `CString::new` in EAL init test fixtures.

### crates/dpdk-net-core (Core crate)

- `tcp_retrans.rs:237` — sacked-flag test.
- `tcp_output.rs:414,429,430,445,473,494,505,534,543,601` — segment-build tests.
- `arp.rs:232,235,251,253,266,282,304,321` — ARP roundtrip + parse tests.
- `tcp_rtt.rs` (no production hits other than line 51, which is hot-path above).
- `l3_ip.rs:373,383` — `ip_decode` accepted-path tests.
- `counters.rs:419` — multi-thread counter test.
- `engine.rs:5137,5148,5175` — `build_connect_syn_opts` / `build_ack_outcome` tests.
- `engine.rs:5567,5591,5663,5668` — RTT-histogram + `force_tw_skip` reap tests.
- `tcp_input.rs:1379,1389,1430,1462,1523,1574,1619,1658,1830,2262,2297,2356,2395,2526,2568,2612` — segment build/parse + options encode + recv-bytes structural tests.
- `l2.rs:90` — `l2_decode` accepted-path test.
- `flow_table.rs:228,239,272,291,293,295,315,327,339` — insert/get/get_mut tests.
- `tcp_events.rs:209,276,291` — event-queue match-arm tests.
- `tcp_options.rs:318,349,364,388,399,406,418,419,443,444,528,546,563,571,576` — encode/parse roundtrip tests.
- `tcp_conn.rs:1009,1025,1026,1086,1104` — TLP recent-probes accounting tests.

## Notes

The audit script is intentionally a coarse grep — it does not
distinguish `unwrap()` on `Result` versus `Option`, nor does it
recognize `unwrap_or` / `unwrap_or_else` (those don't match
`.unwrap()` exactly). The classifications above were produced by
reading each hit in context, including walking the test-mod
boundaries (e.g., `tcp_input.rs:1341` opens `mod tests`, so all
hits at line ≥ 1342 are test-only).

Re-running the script after future edits should produce the same
hot-path count (10) and slow-path count (3) until any of those sites
change. New hits introduced by future code MUST be classified before
phase-close.
