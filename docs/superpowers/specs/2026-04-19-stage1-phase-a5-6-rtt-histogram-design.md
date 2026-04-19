# Phase A5.6 — Per-connection RTT histogram (Design Spec)

**Status:** ABSORBED INTO A6. This file is retained as design-input for the A6 brainstorm — A6's own spec subsumes the content here. Do not start a standalone A5.6 phase; the RTT histogram work lands under A6's branch, plan, review gate, and tag.
**Parent spec:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md`.
**Absorbed into:** `docs/superpowers/specs/2026-04-19-stage1-phase-a6-public-api-completeness-design.md` (authored during A6 brainstorm).
**Sibling (shipped):** `docs/superpowers/specs/2026-04-18-stage1-phase-a5-5-event-log-forensics-design.md` (A5.5 scalar `stats()` getter; A6 adds time-windowed distribution shape via the content below).
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` — A6 (merged; former A5.6 row removed).

---

## 1. Scope

A5.6 adds a per-connection RTT histogram so the application can observe RTT distribution shape over any window size it chooses, without per-sample event overhead and without lossy scalar aggregation.

**Motivation**: A5.5's `resd_net_conn_stats()` exposes current smoothed SRTT / RTTVAR / min_RTT — good for per-order tagging, but RTTVAR collapses spike variance into one number and SRTT loses distribution tail shape. Full per-sample event streaming (gated by a flag) was considered and rejected as too expensive at trading segment rates. A coarse lifetime histogram captures distribution shape while remaining bounded-cost at any sample rate.

**Use case**: app polls the histogram at its own cadence (typically 1-minute windows for session-health monitoring, finer for incident forensics). Delta between two snapshots = RTT distribution over that window. Sample-rate-independent: a window with 10 samples or 10 million samples still costs 64 bytes to read.

In scope:
- **16 log-spaced `u32` buckets per `TcpConn`** (exactly 64 B — one cacheline).
- **Runtime-configurable bucket edges** via a new `resd_net_engine_config_t` field.
- **New extern "C" getter** `resd_net_conn_rtt_histogram`.
- **Wraparound semantics** documented: app takes delta via `wrapping_sub` on a per-bucket basis. Correct as long as a single bucket does not accumulate > 2³² samples between app polls — trivially satisfied for any realistic polling cadence.

Out of scope:
- Per-sample RTT events (`RESD_NET_EVT_RTT_SAMPLE`) — deferred; histogram covers the stated minute-to-hour-scale use case more cheaply.
- Raw-samples ring — deferred; the user-facing analytical need (distribution shape over time windows) is met by the histogram without per-sample storage.
- Engine-wide / global histogram — per-conn is the useful granularity; engine-wide can be computed by summing per-conn if ever needed.
- Bucket-edge changes mid-session — edges are fixed at `engine_create`; changing them would invalidate accumulated counts.
- Amending A5.5 — A5.6 lands as a separate, additive phase after A5.5 ships.

---

## 2. Module layout

### 2.1 Modified modules (`crates/resd-net-core/src/`)

| Module | Change |
|---|---|
| `tcp_conn.rs` | Add `rtt_histogram: [u32; 16]` field on `TcpConn` (64 B inline; zero-init). Add `rtt_histogram_update(&mut self, rtt_us: u32, edges: &[u32; 15])` method that selects the bucket via a 15-comparison ladder (or binary search — equivalent at N=16 for the branch predictor) and `wrapping_add(1)` the chosen `u32`. `wrapping_add` is used so each bucket silently rolls over without panicking; the application's differencing of two snapshots via `wrapping_sub` is correct as long as no bucket sees > 2³² samples between polls. |
| `tcp_input.rs` | One-line addition inside the existing `rtt_est.sample(rtt_us)` call site (A5): immediately after the existing `tcp.rtt_samples++`, call `conn.rtt_histogram_update(rtt_us, &engine.rtt_histogram_edges)`. Cost: 15-comparison ladder + one `wrapping_add`. No atomics (per-conn state, single-lcore RTC model). |
| `engine.rs` | Store `rtt_histogram_edges: [u32; 15]` on the `Engine` struct, initialized from `resd_net_engine_config_t::rtt_histogram_bucket_edges_us[15]` at `engine_create`. Validation: all-zero input means "use defaults"; otherwise require strictly monotonically increasing edges (each `edges[i] < edges[i+1]`), reject with `-EINVAL` at `engine_create`. |

### 2.2 Modified modules (`crates/resd-net/src/`)

| Module | Change |
|---|---|
| `api.rs` | Add `resd_net_engine_config_t::rtt_histogram_bucket_edges_us[15]` (15 × `uint32_t`, 60 B; all-zero = use defaults). Add POD struct `resd_net_tcp_rtt_histogram_t { uint32_t bucket[16] }` (64 B, one cacheline). Add extern "C" function `resd_net_conn_rtt_histogram(engine, conn, out) → i32` returning 0 on success, `-ENOENT` on unknown handle. |
| `lib.rs` | Implement `resd_net_conn_rtt_histogram`: flow-table lookup, `std::ptr::write` the 16-entry array into the caller's out struct. Slow-path — safe per-order for forensic tagging, safe per-minute for session-health polling; do not call in a per-segment loop. |
| `include/resd_net.h` (cbindgen-regenerated) | New struct `resd_net_tcp_rtt_histogram_t`. New function `resd_net_conn_rtt_histogram`. New engine config field `rtt_histogram_bucket_edges_us[15]`. |

### 2.3 Dependencies introduced

None. No new crate deps, no new DPDK offload bits, no wire-format changes.

---

## 3. Data flow

### 3.1 Bucket selection

```rust
fn select_bucket(rtt_us: u32, edges: &[u32; 15]) -> usize {
    // Linear ladder — at N=16, this is small enough that branch prediction
    // on a stable RTT distribution makes this effectively zero-cost. Binary
    // search is equivalent for branch-predictor-cold paths; LLVM is free to
    // lower to either.
    for i in 0..15 {
        if rtt_us <= edges[i] { return i; }
    }
    15   // gt_edges[14] catch-all
}

fn rtt_histogram_update(&mut self, rtt_us: u32, edges: &[u32; 15]) {
    let bucket = select_bucket(rtt_us, edges);
    self.rtt_histogram[bucket] = self.rtt_histogram[bucket].wrapping_add(1);
}
```

Call site: inside `rtt_est.sample()` path in `tcp_input.rs`, after the existing `tcp.rtt_samples++`. Total added cost per RTT sample: one branch ladder + one `wrapping_add(1)` on cache-resident state ≈ 5–10 ns. No atomic (per-conn state, RTC model).

### 3.2 Default bucket edges

When the caller leaves `rtt_histogram_bucket_edges_us[]` as all-zeros at `engine_create`, the engine populates defaults tuned for trading-exchange RTT ranges:

```
  {   50,  100,  200,  300,  500,  750,
    1000, 2000, 3000, 5000, 10000, 25000,
   50000, 100000, 500000 }  // µs
```

This gives 16 buckets with dense resolution in the 50µs–1ms range (colo / same-region hot path), medium resolution 1–50ms (same-region under load / cross-region), coarse >50ms (pathological). Rationale: most of the distribution mass for a healthy exchange gateway lives in 100–500µs; finer resolution there yields more actionable forensic shape than uniform log spacing.

### 3.3 Application-side wraparound handling

Documented contract in the cbindgen-emitted header's doc-comment on the struct:

```c
/// Per-connection RTT histogram. Each bucket counts RTT samples whose value
/// is <= the corresponding edge in rtt_histogram_bucket_edges_us[] (bucket 15
/// is the catch-all for values greater than the last edge).
///
/// Counters are per-connection lifetime and are u32. Wraparound is expected
/// on long-running connections at high sample rates; the application takes
/// deltas across two snapshots using unsigned wraparound subtraction:
///
///     uint32_t delta = (snap_t2.bucket[i] - snap_t1.bucket[i]);  // wraps correctly
///
/// Correctness caveat: this works as long as NO SINGLE BUCKET accumulates
/// more than 2^32 samples between consecutive polls. At 1M samples/sec that's
/// a ~71-minute window; realistic order-entry sample rates (1k–10k samples
/// per connection per second) give > 50 days of headroom. Applications that
/// poll once per minute or finer cannot hit this limit.
///
/// The counter is NOT atomic from the application's perspective: readers
/// observe a consistent-enough 64-byte snapshot for histogram-delta math on
/// x86_64 (single-lcore engine model; the application reads from the same
/// thread that writes). Do not read from a different thread than the engine's
/// poll thread.
typedef struct resd_net_tcp_rtt_histogram {
    uint32_t bucket[16];
} resd_net_tcp_rtt_histogram_t;
```

### 3.4 Application use pattern

```c
// Once at startup:
resd_net_tcp_rtt_histogram_t prev;
resd_net_conn_rtt_histogram(engine, conn, &prev);

// Periodic (e.g., every 60 s):
resd_net_tcp_rtt_histogram_t cur;
resd_net_conn_rtt_histogram(engine, conn, &cur);
uint32_t delta[16];
for (int i = 0; i < 16; ++i) {
    delta[i] = cur.bucket[i] - prev.bucket[i];   // wrapping_sub, correct under overflow
}
// ... analyze delta[] shape for the last window ...
prev = cur;
```

---

## 4. Counter surface

The histogram lives on `TcpConn` and is read via the new getter — it does NOT extend `resd_net_counters_t`. Rationale: `resd_net_counters_t` is engine-wide; the histogram is per-connection. Mixing per-conn data into the engine-wide counter struct would break the model. The getter-based access pattern matches A5.5's `resd_net_conn_stats()`.

No new fields on `resd_net_counters_t`.

---

## 5. Config / API surface changes

### 5.1 `resd_net_engine_config_t` (additions)

| Field | Type | Default | Notes |
|---|---|---|---|
| `rtt_histogram_bucket_edges_us` | `uint32_t[15]` | all-zeros (→ stack applies defaults per §3.2) | 15 strictly monotonically increasing edges defining 16 buckets. Non-monotonic edges rejected at `engine_create` with `-EINVAL`. |

### 5.2 New POD struct

```c
typedef struct resd_net_tcp_rtt_histogram {
    uint32_t bucket[16];    // exactly 64 B / one cacheline
} resd_net_tcp_rtt_histogram_t;
```

### 5.3 New extern "C" function

```c
int resd_net_conn_rtt_histogram(
    resd_net_engine* engine,
    uint64_t conn,
    resd_net_tcp_rtt_histogram_t* out
);
```

Returns `0` on success, `-EINVAL` on null pointers, `-ENOENT` on unknown handle. Thread-safety: same single-lcore contract as every other API.

---

## 6. Accepted divergences

None. A5.6 adds observability only; no RFC clauses are touched. mTCP does not expose per-conn RTT histograms — scope difference, not behavioral divergence. No new ADs for either review.

---

## 7. Test plan

### 7.1 Unit tests (Layer A)

- **Bucket selection**: given the default edges, RTT values `{ 10, 50, 75, 150, 1000, 2000, 30000, 600000 }` µs land in buckets `{ 0, 0, 1, 2, 6, 7, 11, 15 }` respectively.
- **Wraparound**: `rtt_histogram_update` called 2³² + 5 times with identical RTT returns bucket value = 5 (wraparound confirmed).
- **Monotonic-edges validation**: `engine_create` rejects `[100, 200, 150, ...]` with `-EINVAL`; accepts `[100, 200, 300, ...]`; accepts all-zero (applies defaults).
- **Default edges applied on all-zero**: after `engine_create` with zeroed edges, verify the engine's stored edges match §3.2 defaults.

### 7.2 Integration (Layer B, TAP pair)

1. **Distribution shape** — establish a connection, drive N RTT samples with controlled values spanning three buckets; poll histogram; assert exact sample counts in the three expected buckets and zero elsewhere.
2. **Minute-window delta** — poll histogram at t=0, drive M samples, poll at t=60s; assert `cur[i] - prev[i]` (wrapping) matches the generated distribution for each bucket.
3. **Unknown handle** — `resd_net_conn_rtt_histogram(engine, 0xdead_beef, &out)` returns `-ENOENT`, `out` unchanged.
4. **Null out** — returns `-EINVAL`, no crash.
5. **Overlapped histograms** — two concurrent connections accumulate independent histograms; polling one does not affect the other's counts.
6. **Post-A5.5 integration** — `stats().srtt_us` and `rtt_histogram` are both populated from the same sample path; after N samples, `srtt_us > 0` implies at least one `bucket[i] > 0`.

### 7.3 A8 counter-coverage + knob-coverage entries

- Counter-coverage: the 16 histogram buckets are *not* in `resd_net_counters_t` (they're per-conn, not engine-wide), so the existing counter-coverage audit does not reach them. Add a sibling audit in `tests/per-conn-histogram-coverage.rs`: require at least one scenario that drives each of the 16 buckets > 0 (achievable with a single test that sweeps RTT across the bucket range).
- Knob-coverage: `rtt_histogram_bucket_edges_us` (engine-wide) — scenario: override defaults with a tight custom edge set, assert distribution lands in the custom buckets (not the defaults).

---

## 8. Review gates

- `docs/superpowers/reviews/phase-a5-6-mtcp-compare.md` — `mtcp-comparison-reviewer`. Expected brief: mTCP has no per-conn RTT histogram; scope difference, no ADs.
- `docs/superpowers/reviews/phase-a5-6-rfc-compliance.md` — `rfc-compliance-reviewer`. Expected trivial: no wire behavior, no RFC clauses touched.

---

## 9. Rough task scale

~3 tasks:

1. `rtt_histogram: [u32; 16]` field on `TcpConn` + `rtt_histogram_update` method + unit tests (bucket selection + wraparound). (1)
2. `Engine::rtt_histogram_edges` + `engine_create` validation + integration into `rtt_est.sample()` call site in `tcp_input.rs`. (1)
3. `resd_net_tcp_rtt_histogram_t` POD + extern "C" `resd_net_conn_rtt_histogram` + integration tests 7.2.1–7.2.6 + mTCP + RFC review reports + A8 audit entries. (1)

Each task is surgical, touches one concern, carries its own tests.

---

## 10. Updates to parent spec `2026-04-17-dpdk-tcp-design.md`

Small edits in the same commit as A5.6's final task:

- §4 API: add `resd_net_conn_rtt_histogram` under the introspection paragraph (alongside `resd_net_conn_stats` from A5.5).
- §9.1 counter examples: note that per-conn RTT histogram lives on `TcpConn` read via the getter, not in `resd_net_counters_t`.

---

## 11. Performance notes

- Per-sample write cost: 15-comparison ladder (or LLVM-lowered binary search) + one `wrapping_add` on cache-resident state. ≈ 5–10 ns. No atomic needed — RTC model, per-conn state, no cross-lcore access.
- Per-conn memory: 64 B histogram + 60 B edges on the engine shared across conns = 64 B per conn incremental (edges are engine-wide). 100 conns × 64 B = 6.4 KB total. Trivial.
- Per-call read cost: one flow-table lookup + one 64 B memcpy. Slow-path (per-minute or per-order, not per-segment).
- Cacheline behavior: `rtt_histogram` is on its own cacheline (64 B), so writes don't false-share with other hot `TcpConn` fields. Place the field on a `#[repr(align(64))]`-annotated sub-struct or use `#[repr(align(64))]` on `TcpConn` layout if other cache hot-spots warrant it; leave decision to the implementation task based on `TcpConn`'s post-A5 layout.

---

## 12. Open items for the plan-writing pass

- **Default edge set** (§3.2): 15 edges chosen for trading-exchange RTT ranges. If profiling on a real workload shows mass outside the chosen buckets, edges can be tuned at the default level before A5.6 ships. Users override via the config field regardless.
- **`TcpConn` cacheline placement**: decide during implementation whether to align `rtt_histogram` on its own cacheline or accept co-location with nearby fields. Depends on post-A5.5 `TcpConn` layout and which fields are hot on the ACK path vs the histogram-write path.
- **Engine-wide summary** (optional): if applications commonly want engine-wide RTT distribution (sum across all conns), a helper `resd_net_engine_rtt_histogram` could sum the 16 buckets across all live conns on demand. Out of A5.6 scope; revisit if requested.
- **Post-A5.6 sibling `RESD_NET_EVT_RTT_SAMPLE` event**: still deferred. A5.6's histogram covers the minute-to-hour observability need; per-sample events stay in the "add if a specific use case surfaces" bucket.
