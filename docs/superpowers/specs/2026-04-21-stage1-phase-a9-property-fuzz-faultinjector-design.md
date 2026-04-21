# Phase A9 — Property + bespoke fuzzing & smoltcp FaultInjector (Design Spec)

**Status:** Design approved (brainstorm 2026-04-21). Implementation plan to land at `docs/superpowers/plans/2026-04-21-stage1-phase-a9-property-fuzz-faultinjector.md`.
**Parent spec (Stage 1 design):** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` — §10.6 (Layer F — Property / bespoke fuzzing).
**Roadmap row:** `docs/superpowers/plans/stage1-phase-roadmap.md` § A9 (revised by this phase; see §10 below).
**Branch / worktree:** `phase-a9` in `/home/ubuntu/resd.dpdk_tcp-a9`, branched from tag `phase-a6-6-7-complete` (commit `2c4e0b6`).
**End-of-phase tag:** `phase-a9-complete`. Stays local; user merges to master manually together with the parallel A7 branch.

---

## 0. Purpose of this spec

A9 lands the *property + bespoke fuzzing* slice of spec §10.6 against the Stage 1 stack as it stands at `phase-a6-6-7-complete`. The phase delivers six pure-module property test suites, seven cargo-fuzz targets (six pure-module + one persistent-mode engine target), a Scapy adversarial corpus driven through a new test-inject RX hook, the smoltcp-pattern FaultInjector RX middleware, and a directed regression test that closes the I-8 FYI from `phase-a6-6-7-rfc-compliance.md` (FIN-piggyback miscount on multi-seg chains).

**Differential-vs-Linux fuzzing (Layer E, spec §10.5) is explicitly NOT in this phase.** The brainstorm dropped it after re-reading §10.10 — the Stage 1 ship gate does not list Layer E; it lists Layers A/B/C plus observability + smoke. Layer E naturally combines with the Stage 2 §10.7 Layer G WAN A/B harness (both compare wire bytes against a Linux oracle, both need `preset=rfc_compliance` and same-host netns plumbing). Both deliverables move to a new Stage 2 phase row, **S2-A** (see §10.4 below). `preset=rfc_compliance` becomes the responsibility of whichever Stage-1 phase first needs it for its own use (likely A7 if any curated packetdrill scripts require RFC behavior; otherwise introduced at S2-A).

This is the brainstorm-derived design that becomes the implementation plan. The plan operationalises this spec into ordered tasks under the `superpowers:writing-plans` skill.

---

## 1. Brainstorm decisions

The 2026-04-21 brainstorm closed eight decisions. Each is recorded with the option chosen + rationale.

### D1 — Differential-vs-Linux fuzzing dropped from A9

**Choice:** drop. **Defer to S2-A.**

**Rationale:** every other A9 deliverable (proptest, cargo-fuzz, Scapy corpus, FaultInjector, the test-inject hook) is invariant-based and needs no oracle. Only the differential track required `preset=rfc_compliance`, the TCP-Fuzz vendor (zouyonghao/TCP-Fuzz), Linux netns oracle plumbing, and a divergence-normalisation layer. Building all of that for a track that the Stage 1 ship gate does not require (§10.10) is not justified now. Stage-2 Layer G WAN A/B also targets Linux comparison; combining gives one Linux-oracle infrastructure investment serving both consumers.

### D2 — cargo-fuzz toolchain

**Choice:** F1 — cargo-fuzz with nightly Rust pinned in `crates/dpdk-net-core/fuzz/rust-toolchain.toml` only.

**Rationale:** the no-nightly rule (`feedback_rust_toolchain.md`) targets the shipping artifact. `fuzz/` is auxiliary tooling, never linked into the C-ABI artifact, never built by default `cargo build --workspace`. Pinning nightly inside the fuzz subdirectory is the established pattern (bytecodealliance, rust-lang/regex). cargo-fuzz is the choice §10.6 already names; deviating to honggfuzz-rs/afl.rs trades ergonomics + ecosystem mindshare for a stable-toolchain purity that brings no production benefit.

### D3 — cargo-fuzz target scope

**Choice:** T1.5 — six pure-module fuzz targets + one persistent-mode engine target via the test-inject hook + a directed Scapy I-8 test.

**Nomenclature** (used in §5.4 and §6 below): **T1** = pure-module fuzz targets (no Engine state, ns/iter, found in `crates/dpdk-net-core/fuzz/fuzz_targets/{tcp_options,tcp_sack,tcp_reassembly,tcp_state_fsm,tcp_seq,header_parser}.rs`). **T1.5** = T1 plus one persistent-mode `engine_inject` target that builds a real `Engine` via existing test fixtures during libFuzzer init and per-iter calls `inject_rx_frame(data)` (µs/iter, integration coverage of `tcp_input` without refactoring it). **T2** = headless engine constructor that bypasses `rte_eal_init` (rejected — substantial refactor). **T3** = extracted pure `process_segment` function (rejected — 3115-line `tcp_input.rs` refactor with behaviour-preservation risk).

**Rationale:** T1 (pure-module only) misses integration bugs across modules (the I-8 class). T2/T3 require a substantial refactor of `tcp_input.rs` (3115 lines) for headless engine construction or pure `process_segment` extraction; behaviour-preservation risk during refactor is real. T1.5 reuses the test-inject hook A9 already builds for Scapy + FaultInjector; adds one persistent-mode target where libFuzzer initialisation builds the engine once and per-iter calls `inject_rx_frame(data)`. That covers full `tcp_input` integration without touching `tcp_input.rs` itself. The known I-8 bug gets a directed Scapy test (deterministic, single-shot) rather than relying on stochastic discovery — efficient when the bug class is already named.

### D4 — Test-inject RX hook design (A7 coordination contract)

**Choice:** Ethernet-frame injection point, separate test-inject mempool (lazy), single-seg + multi-seg variants, cargo feature `test-inject` (default off), Rust-only API surface (no `extern "C"` in A9).

**Rationale:** Ethernet is the most realistic boundary — runs the same L2 → L3 → tcp_input path the production poll loop does. Separate mempool avoids exhausting the engine's production RX mempool during fuzz bursts and keeps fuzz state isolated from production sizing logic. Multi-seg variant is needed for I-8 closure + LRO-shape testing. Cargo feature gates all inject code, the test mempool, and the chain helper — release builds carry zero of it; cbindgen runs without the feature so the inject functions never appear in `dpdk_net.h`. A7's packetdrill-shim references the same Rust function names; A7 owns whether to add an `extern "C"` wrapper for its C-side use.

### D5 — FaultInjector layout

**Choice:** single file `crates/dpdk-net-core/src/fault_injector.rs`, behind cargo feature `fault-injector` (default off).

**Rationale:** YAGNI for a separate crate when there's one production-shape consumer (the engine RX dispatch). One file, one feature gate, one call site in the engine. Counters for accounting (`obs.fault_injector_drops/dups/reorders/corrupts`) live behind the same feature in `counters.rs`. Env-var configuration parsed once at `engine_create` when the feature is on; hot-path cost is one feature-gated call into `FaultInjector::process(mbuf)`.

### D6 — Regression-fuzz-vs-prior-release deferred out of A9

**Choice:** defer; revisit after the first Stage-1 release tag (post-A11) or once a meaningful baseline exists.

**Rationale:** A9 branches from `phase-a6-6-7-complete`; there is no prior Stage-1 release. A regression baseline equal to the current branch base produces no signal. Right home is post-A11 once `stage-1-ship` exists, or as an ongoing post-merge gate added when the second release cuts.

### D7 — Scapy corpus output format

**Choice:** `.pcap` files in `tools/scapy-corpus/out/` (gitignored; deterministic seeds committed in `tools/scapy-corpus/scripts/`).

**Rationale:** pcap is the standard wire-trace format. Replayable by tcpreplay / Wireshark for debugging; trivially diffable. Rust harness reads via the `pcap-file` crate. A JSON/YAML descriptor format (option C) would invent a project-local DSL; raw bytes (option B) loses framing metadata. pcap is the right wire format.

### D8 — I-8 closure inside A9

**Choice:** close. Directed Scapy test + corresponding Rust integration test + one-line fix in `tcp_input.rs` at the chain-walk FIN-piggyback site.

**Rationale:** the test infrastructure A9 builds (test-inject hook + multi-seg chain ingest) is the first to actually exercise the affected path. Filing a follow-up task to close it later means re-loading context for a one-line fix; closing inside A9 reuses the warmed context.

---

## 2. Scope

### 2.1 In scope

- Six `proptest` suites under `crates/dpdk-net-core/tests/proptest_*.rs`
- `crates/dpdk-net-core/fuzz/` cargo-fuzz subdirectory with seven targets (six T1 + one T1.5) and pinned nightly toolchain
- `crates/dpdk-net-core/src/fault_injector.rs` plus engine wiring + counters, all behind `fault-injector` feature
- `inject_rx_frame` + `inject_rx_chain` methods on `Engine`, behind `test-inject` feature
- `tools/scapy-corpus/` (Python Scapy scripts) + `tools/scapy-fuzz-runner/` (Rust binary that replays pcaps via the test-inject hook)
- `scripts/fuzz-smoke.sh` (per-merge) + `scripts/fuzz-long-run.sh` (per-stage-cut)
- I-8 fix in `tcp_input.rs` + directed regression test
- Roadmap update: A9 row revised; new S2-A row added in Stage 2 section
- End-of-phase mTCP + RFC compliance review reports (parallel, opus 4.7)

### 2.2 Out of scope

- Differential vs Linux TCP, `preset=rfc_compliance` engine knob, TCP-Fuzz vendor, Linux netns oracle, divergence-normalisation layer (→ S2-A)
- Regression-fuzz-vs-prior-release (no Stage 1 baseline yet; revisit post-A11)
- T2/T3 `tcp_input.rs` refactor for headless / extracted-pure-function fuzzing (T1.5 covers integration; refactor would be its own phase if ever)
- Production wire behaviour changes; new production hot-path counters (the `obs.fault_injector_*` set is feature-gated and inactive in default builds)
- `extern "C"` exposure of the test-inject hook (A7 owns that decision)
- Benchmark harness (A10), tcpreq (A8), packetdrill (A7), HTTP/TLS/WS

---

## 3. Architecture

```
crates/dpdk-net-core/
├── src/
│   ├── engine.rs              + inject_rx_frame, inject_rx_chain   #[cfg(feature="test-inject")]
│   │                          + fault_injector wiring               #[cfg(feature="fault-injector")]
│   ├── fault_injector.rs      NEW                                   #[cfg(feature="fault-injector")]
│   ├── tcp_input.rs           I-8 fix at the chain-walk FIN-piggyback equality
│   └── counters.rs            + obs.fault_injector_*                #[cfg(feature="fault-injector")]
└── tests/
    ├── proptest_tcp_options.rs       NEW
    ├── proptest_tcp_sack.rs          NEW
    ├── proptest_tcp_reassembly.rs    NEW
    ├── proptest_tcp_seq.rs           NEW
    ├── proptest_rack_xmit_ts.rs      NEW
    ├── proptest_paws.rs              NEW
    └── i8_fin_piggyback_chain.rs     NEW (directed regression for I-8)

crates/dpdk-net-core/fuzz/                NEW (cargo-fuzz subdir; not a workspace member)
├── rust-toolchain.toml      channel = "nightly"
├── Cargo.toml               package = "dpdk-net-core-fuzz"; libfuzzer-sys dep
├── .gitignore               artifacts/, corpus/, coverage/
└── fuzz_targets/
    ├── tcp_options.rs       T1 — encode/decode round-trip
    ├── tcp_sack.rs          T1 — scoreboard insert/merge invariants
    ├── tcp_reassembly.rs    T1 — gap closure + refcount balance
    ├── tcp_state_fsm.rs     T1 — FSM transitions on (state, event) pairs
    ├── tcp_seq.rs           T1 — wrap-safe seq comparator
    ├── header_parser.rs     T1 — IP+TCP decode on malformed/truncated input
    └── engine_inject.rs     T1.5 — persistent: init Engine once, per-iter inject_rx_frame

tools/
├── scapy-corpus/            NEW
│   ├── README.md
│   ├── scripts/
│   │   ├── i8_fin_piggyback_multi_seg.py     directed I-8 regression
│   │   ├── overlapping_segments.py
│   │   ├── malformed_options.py              (length=0, length>remaining, unknown kinds)
│   │   ├── timestamp_wraparound.py           (TS near 2^32)
│   │   ├── sack_blocks_outside_window.py
│   │   └── rst_invalid_seq.py
│   ├── seeds.txt            deterministic Scapy seeds (committed)
│   └── out/                 *.pcap (gitignored; generated by `make scapy-corpus`)
└── scapy-fuzz-runner/       NEW Rust binary; reads pcaps via pcap-file crate;
                                drives test-inject hook against a real engine

scripts/
├── fuzz-smoke.sh            NEW per-merge (30 s × 7 targets, parallel)
├── fuzz-long-run.sh         NEW per-stage-cut (72 h dedicated box, all 7 targets parallel)
└── scapy-corpus.sh          NEW regenerates tools/scapy-corpus/out/ from scripts/
```

No new workspace members for `fuzz/` (cargo-fuzz convention: separate sub-Cargo.toml outside the workspace). `tools/scapy-fuzz-runner/` IS a new workspace member.

---

## 4. Data flow

### 4.1 Test-inject path (T1.5 + Scapy + future A7 packetdrill-shim)

```
test / fuzz target / Scapy harness
   │
   ▼  &[u8] (Ethernet frame)  or  &[&[u8]] (multi-seg chain)
Engine::inject_rx_frame / inject_rx_chain     #[cfg(feature="test-inject")]
   │  alloc mbuf(s) from lazy test-inject mempool
   │  copy frame bytes in (single-seg) or build mbuf chain (multi-seg)
   ▼  *mut rte_mbuf
Engine::dispatch_one_mbuf(mbuf)               same internal path the poll loop uses
   │
   ▼
[FaultInjector chain]                         #[cfg(feature="fault-injector")]
   │  drop / dup / reorder(depth) / corrupt(byte_idx) at configured rates
   ▼  *mut rte_mbuf or NULL (drop)
l2_decode → l3_ip_decode → tcp_input → reassembly → READABLE event
```

Engine internal dispatch reuses the existing poll-loop code path. The inject hook is "early enough that the FaultInjector intercepts injected frames the same way it would intercept real PMD RX frames" — so a single Scapy + FaultInjector run can stress both the wire-shape variation and the stack's loss/dup/reorder resilience together.

### 4.2 FaultInjector intercept

FaultInjector intercepts at **post-PMD-RX, pre-L2-decode**. Operates on `(mbuf, rng_state)` → `Action`:

```rust
enum Action {
    Pass,
    Drop,
    Duplicate,                        // emit twice
    Reorder { depth: u8 },            // hold in ring, emit `depth` frames later
    CorruptByte { idx: u16, value: u8 },
}
```

The reorder action uses a small per-engine ring (default depth 4, configurable). Holds frames until either the ring is full (oldest evicted to dispatch) or a configurable flush threshold. Lazy ring init on first non-zero reorder rate; zero allocation otherwise. All rates are float `[0.0, 1.0]` configured via env var:

```
DPDK_NET_FAULT_INJECTOR=drop=0.01,dup=0.005,reorder=0.002,corrupt=0.001,seed=42
```

Parsed once at `engine_create` when the feature is on. Default seed is the engine's `boot_nonce` for reproducibility; `seed=N` overrides for deterministic replay.

### 4.3 Production path

Release builds (neither `test-inject` nor `fault-injector` feature on) carry zero overhead:

- All `inject_rx_*` methods are absent (`#[cfg(feature="test-inject")]` on the impl block)
- All FaultInjector code is absent (`#[cfg(feature="fault-injector")]` on the module + the engine's call site)
- `fault_injector` counters not declared in `dpdk_net_counters_t`'s default-feature build
- Bit-identical to A6.6-7 production behaviour

The A6.7 panic-firewall + no-alloc-on-hot-path audits remain unaffected (release builds carry zero new code touched by either invariant).

---

## 5. Component specifications

### 5.1 Engine — test-inject hook (A7 coordination contract)

```rust
#[cfg(feature = "test-inject")]
impl Engine {
    /// Inject a synthetic Ethernet frame as if it came from PMD RX.
    /// The frame is copied into a mbuf from a lazily-created test-inject
    /// mempool; the same internal RX dispatch the poll loop uses runs end
    /// to end. Returns once the mbuf is processed (refcount may be retained
    /// downstream by reassembly / READABLE delivery — caller does not own
    /// the mbuf after this returns).
    pub fn inject_rx_frame(&self, frame: &[u8]) -> Result<(), InjectErr>;

    /// Inject a multi-segment Ethernet frame chain (LRO-shape).
    /// Builds an mbuf chain with `segments[0]` carrying the Ethernet header
    /// + first payload chunk and each subsequent segment chained via
    /// `rte_mbuf.next`. `total_len` is set to `Σ segments[i].len()`.
    /// Used by I-8 closure + chain-walk fuzz coverage.
    pub fn inject_rx_chain(&self, segments: &[&[u8]]) -> Result<(), InjectErr>;
}

#[derive(Debug, thiserror::Error)]
pub enum InjectErr {
    #[error("test-inject mempool exhausted")]
    MempoolExhausted,
    #[error("frame too large for mempool segment ({frame} > {seg_size})")]
    FrameTooLarge { frame: usize, seg_size: usize },
    #[error("empty chain")]
    EmptyChain,
}
```

Cbindgen runs without the `test-inject` feature; neither function appears in `dpdk_net.h`. A7's packetdrill-shim references these names verbatim (Rust-side); A7 decides whether to publish an `extern "C"` wrapper for its C-side use.

The lazy test-inject mempool is created on first call (Mutex-guarded `OnceCell` to avoid TOCTOU under unlikely concurrent first-call). Sized for a fuzz burst (default 4096 mbufs, configurable via env var `DPDK_NET_TEST_INJECT_POOL_SIZE` at engine_create).

### 5.2 FaultInjector

```rust
// crates/dpdk-net-core/src/fault_injector.rs
#[cfg(feature = "fault-injector")]
pub(crate) struct FaultInjector {
    drop_rate: f32,
    dup_rate: f32,
    reorder_rate: f32,
    corrupt_rate: f32,
    rng: SmallRng,                          // seeded once at engine_create
    reorder_ring: Option<ArrayDeque<NonNull<rte_mbuf>, 16>>,  // lazy
}

#[cfg(feature = "fault-injector")]
impl FaultInjector {
    pub fn from_env(boot_nonce_seed: u64) -> Option<Self>;
    pub fn process(&mut self, mbuf: NonNull<rte_mbuf>)
        -> SmallVec<[NonNull<rte_mbuf>; 4]>;  // 0..N output frames
}

// engine.rs RX dispatch:
#[cfg(feature = "fault-injector")]
let frames = if let Some(fi) = &mut self.fault_injector {
    fi.process(mbuf)
} else {
    smallvec![mbuf]
};
#[cfg(not(feature = "fault-injector"))]
let frames = smallvec![mbuf];
for m in frames { dispatch_one_mbuf(m); }
```

Counters declared in `counters.rs` under the same feature gate:

```rust
#[cfg(feature = "fault-injector")]
#[derive(Default)]
pub struct FaultInjectorCounters {
    pub drops: AtomicU64,
    pub dups: AtomicU64,
    pub reorders: AtomicU64,
    pub corrupts: AtomicU64,
}
```

Exposed in `dpdk_net_counters_t` only when the feature is on (parallel to existing `#[cfg]` patterns for `obs-byte-counters`).

### 5.3 proptest suites

Six suites under `crates/dpdk-net-core/tests/proptest_*.rs`:

| File | Properties asserted |
|---|---|
| `proptest_tcp_options.rs` | encode(decode(bytes)) == bytes for valid options; decode fails gracefully (no panic) on malformed; MSS / WS / SACK-permitted / Timestamps round-trip |
| `proptest_tcp_sack.rs` | scoreboard remains sorted + non-overlapping after random insert sequences; merging adjacent blocks preserves byte coverage; drain at `snd.una` removes covered blocks |
| `proptest_tcp_reassembly.rs` | gaps shrink monotonically as in-order segments arrive; drain delivers a contiguous prefix; mbuf refcount balance over insert-then-drain cycles (using a mock mbuf accounting harness — no DPDK init) |
| `proptest_tcp_seq.rs` | `seq_lt` / `seq_lte` / `seq_gt` / `seq_gte` total-order properties hold across 2³² wrap (asymmetric 2³¹-window definition) |
| `proptest_rack_xmit_ts.rs` | RACK xmit_ts on `RetransEntry` is monotonic across retransmits of the same segment; SACK-driven loss marking respects the §6.1 invariant |
| `proptest_paws.rs` | PAWS reject rule monotonic in TS.Recent; valid TS-echo always accepted; invalid TS-echo always rejected; idempotent under repeated application |

All suites use `proptest = "1"` workspace-pinned. Each suite runs by default in `cargo test`; per-property iteration count default to 256 (proptest standard); CI smoke uses default.

### 5.4 cargo-fuzz targets

Subdirectory `crates/dpdk-net-core/fuzz/` outside the workspace (per cargo-fuzz convention). `Cargo.toml` declares libfuzzer-sys; `rust-toolchain.toml` pins nightly.

| Target | Type | Strategy |
|---|---|---|
| `tcp_options` | T1 pure | `decode(data)` then `encode(decode(data))` — assert no panic; if decoded OK, encode-decode round-trip equals canonical form |
| `tcp_sack` | T1 pure | parse data into a sequence of `(insert_block_start, length)` ops; apply to scoreboard; assert invariants after each op |
| `tcp_reassembly` | T1 pure | parse data into `(seq_offset, len, is_drain)` ops; apply to a mock-mbuf reassembly; assert gap-closure + refcount balance |
| `tcp_state_fsm` | T1 pure | parse data into `(current_state, event_kind)` pairs; assert transition lands in legal set per §6.1 |
| `tcp_seq` | T1 pure | parse data into `(a, b, c)` u32 triples; assert seq comparator total-order properties |
| `header_parser` | T1 pure | drive `l3_ip::decode` + `tcp_input::parse_header` on raw bytes; assert no panic, no UB, no out-of-bounds |
| `engine_inject` | T1.5 persistent | `LIBFUZZER_PERSISTENT_INIT`: build Engine via existing test fixtures (TAP-backed). Per-iter: `engine.inject_rx_frame(data)`; assert no panic + invariants `snd.una ≤ snd.nxt`, rcv-window monotonic, FSM state ∈ legal set, mbuf refcount balance |

Each target gets a starter corpus in `corpus/<target>/` (a few seed inputs, gitignored — generated on first CI run). Crash inputs land in `artifacts/<target>/` (gitignored; CI uploads on failure).

### 5.5 Scapy adversarial corpus

Six Python Scapy scripts in `tools/scapy-corpus/scripts/`, each generating a deterministic pcap of test frames into `tools/scapy-corpus/out/<script-name>.pcap`. Seeds committed in `tools/scapy-corpus/seeds.txt` for reproducibility.

| Script | Frames generated |
|---|---|
| `i8_fin_piggyback_multi_seg.py` | Multi-seg chain with FIN piggybacked on the last segment of a chain whose head-link payload is shorter than the chain total. **Directed I-8 regression.** |
| `overlapping_segments.py` | Pairs/triples of segments with varied overlap offsets (full overlap, prefix overlap, suffix overlap, interior overlap) |
| `malformed_options.py` | Options with length=0, length > remaining, unknown option kinds, truncated option arrays, NOP-only padding past the header end |
| `timestamp_wraparound.py` | TS values near 2³²; TSecr/TSval combinations that exercise the PAWS edge near wrap |
| `sack_blocks_outside_window.py` | SACK blocks whose seq range is outside the receive window, before/after `snd.una`, or contains snd.nxt |
| `rst_invalid_seq.py` | RST segments with seq outside the valid acceptance window per RFC 5961 §3 |

`tools/scapy-fuzz-runner/` (Rust binary, workspace member): reads each pcap via `pcap-file = "2"`, iterates frames, calls `engine.inject_rx_frame(frame)` against a TAP-backed engine. Asserts no panic; reports any nonzero counter the script's fixture didn't expect.

### 5.6 I-8 closure

`tcp_input.rs` at the post-chain-walk FIN-piggyback equality check (~line 1208 per the A6.6-7 RFC review): replace `seg.payload.len()` (head-link only) with the running chain-byte total computed during the chain walk. Concretely, the chain-walk loop already accumulates `chain_total_len` (verified in `rx_zero_copy_multi_seg.rs`); use that value in the equality.

Verification:
- `tools/scapy-corpus/scripts/i8_fin_piggyback_multi_seg.py` — deterministic pcap with the bug-triggering frame
- `crates/dpdk-net-core/tests/i8_fin_piggyback_chain.rs` — Rust integration test that calls `engine.inject_rx_chain(...)` with the same shape and asserts FSM transitions to CLOSE_WAIT
- The RFC compliance reviewer at end-of-phase verifies the I-8 FYI from `phase-a6-6-7-rfc-compliance.md` is closed

---

## 6. Testing strategy & invariants

| Layer | Tool | Targets | Iter cost | Bug class caught |
|---|---|---|---|---|
| Property | `proptest` | 6 suites | µs/iter | per-module invariant violations |
| cargo-fuzz T1 | libFuzzer | 6 pure-module targets | ns/iter | UB, panics, parser/codec bugs |
| cargo-fuzz T1.5 | libFuzzer (persistent) | `engine_inject` | µs/iter | tcp_input integration bugs (incl. I-8 territory) |
| Adversarial | Scapy → pcap → inject hook | 6 scripts + I-8 directed | ms/iter | hand-crafted edge cases |
| Soak | FaultInjector under existing tap-tests | env-var configured | ambient | integration robustness under loss/dup/reorder/corrupt |

Invariants asserted across all fuzz/inject paths:

1. No panic; no UB (sanitizers clean — ASan/UBSan in CI matrix where toolchain supports)
2. `snd.una ≤ snd.nxt` (mod 2³², per spec §6.5 wrap-safe comparator)
3. Receive window is monotonic over a connection's lifetime when no drops occur
4. FSM state ∈ legal set per spec §6.1
5. mbuf refcount balance over inject-then-drain cycle (refcount-leak audit reuses A6.5/A6.7 hardening pattern)
6. Counter values do not panic on read (atomic-load-helper from A6.7)

---

## 7. CI integration

### 7.1 Per-merge

Added to existing CI matrix. Wall-clock budget: ~5 min total beyond current baseline.

```yaml
# .github/workflows/ci.yml (or equivalent)
- name: proptest
  run: cargo test --workspace --tests
  # proptest_* tests run as part of normal cargo test

- name: cargo-fuzz smoke
  run: scripts/fuzz-smoke.sh
  # 30 s per target × 7 targets, parallel up to runner CPU count

- name: scapy adversarial corpus
  run: |
    pip install scapy
    scripts/scapy-corpus.sh
    cargo run -p scapy-fuzz-runner --release -- \
      --corpus tools/scapy-corpus/out/

- name: fault-injector compile gate
  run: cargo check --features fault-injector
  # Soak run is local-only; CI verifies the feature still builds
```

### 7.2 Per-stage-cut

Manual workflow `fuzz-long-run.yml`, dispatched from a dedicated EC2 box (not shared CI runner — needs 72 h continuous + sized for max parallel fuzz).

```bash
# scripts/fuzz-long-run.sh
parallel --jobs 7 --linebuffer ::: \
  "cargo +nightly fuzz run tcp_options       -- -max_total_time=259200" \
  "cargo +nightly fuzz run tcp_sack          -- -max_total_time=259200" \
  "cargo +nightly fuzz run tcp_reassembly    -- -max_total_time=259200" \
  "cargo +nightly fuzz run tcp_state_fsm     -- -max_total_time=259200" \
  "cargo +nightly fuzz run tcp_seq           -- -max_total_time=259200" \
  "cargo +nightly fuzz run header_parser     -- -max_total_time=259200" \
  "cargo +nightly fuzz run engine_inject     -- -max_total_time=259200"
# Publish coverage + crash report to docs/superpowers/reports/fuzz-long-run-<date>.md
```

The smoke gate is fast enough for the standard CI runner; long-run is intentional, manual, and produces a durable report committed back to `docs/superpowers/reports/`.

---

## 8. Knob coverage interaction

`fault-injector` env-var configuration is **not** part of `dpdk_net_engine_config_t` or `dpdk_net_connect_opts_t` — it's a feature-gated env-var-driven side channel. This is out of scope for the §A8 knob-coverage audit per that audit's own charter (purely informational fields and non-config-struct configuration are excluded). When A8 lands, file an entry in `tests/knob-coverage-informational.txt` if the audit's static parser flags the feature gate.

`test-inject` similarly does not introduce engine-config or connect-opts fields. Same exclusion applies.

---

## 9. End-of-phase gate

Per `feedback_phase_mtcp_review.md` and `feedback_phase_rfc_review.md`:

- **mTCP comparison reviewer** (project-local subagent at `.claude/agents/mtcp-comparison-reviewer.md`, opus 4.7). Report: `docs/superpowers/reviews/phase-a9-mtcp-compare.md`. Scope: how mTCP handles fuzz/property testing of equivalent modules (tcp_options, tcp_sack, tcp_reassembly, fault-injection patterns); flag any algorithmic divergence A9's harness exposes.
- **RFC compliance reviewer** (project-local subagent at `.claude/agents/rfc-compliance-reviewer.md`, opus 4.7). Report: `docs/superpowers/reviews/phase-a9-rfc-compliance.md`. Scope: I-8 closure verification (FIN handling on multi-seg chains restored per RFC 9293 §3.10.7.4); confirm the I-8 FYI from phase-a6-6-7-rfc-compliance.md is now closed; verify no new RFC deviations introduced by inject-hook or FaultInjector wiring.

Both subagents dispatched in parallel from a single message. The `phase-a9-complete` tag is blocked while either report has any unresolved `[ ]` checkbox in Must-fix or Missing-SHOULD/Missed-edge-cases.

Per-task two-stage review (spec-compliance + code-quality reviewer subagents, both opus 4.7) applies to every non-trivial implementation step per `feedback_per_task_review_discipline.md`.

---

## 10. Roadmap update

Phase plan includes a task to update `docs/superpowers/plans/stage1-phase-roadmap.md`:

### 10.1 A9 row revision

```
| A9 | Property + bespoke fuzzing + smoltcp FaultInjector | Not started | — |
```

becomes (after this phase tags):

```
| A9 | Property + bespoke fuzzing + smoltcp FaultInjector | Complete | phase-a9-complete |
```

### 10.2 A9 detail section revision

Replace the existing A9 deliverables block with the trimmed scope (10 deliverables, ~10 tasks instead of ~15):

- 6 `proptest` suites
- 7 cargo-fuzz targets (6 pure-module + 1 persistent-mode engine)
- `tools/scapy-corpus/` + `tools/scapy-fuzz-runner/`
- `crates/dpdk-net-core/src/fault_injector.rs` + engine wiring + counters (all behind `fault-injector` feature)
- `inject_rx_frame` + `inject_rx_chain` on Engine (behind `test-inject` feature)
- I-8 closure
- `scripts/fuzz-smoke.sh` + `scripts/fuzz-long-run.sh` + `scripts/scapy-corpus.sh`
- mTCP + RFC end-of-phase reviews

Add a "Deferred (→ S2-A)" sub-section: differential-vs-Linux fuzz, `preset=rfc_compliance` engine knob, TCP-Fuzz vendor (zouyonghao/TCP-Fuzz), Linux netns oracle plumbing, divergence-normalisation layer.

### 10.3 New Stage 2 phase row

Insert after existing Stage-2 hardening notes:

```
| S2-A | Differential-vs-Linux fuzz + Layer G WAN A/B (TCP-Fuzz vendor + preset=rfc_compliance + Linux netns oracle) | Not started | — |
```

with detail section combining the deferred A9 differential work + spec §10.7 Layer G WAN A/B harness. Both share the Linux-oracle infrastructure; the unified phase introduces it once.

### 10.4 Cross-phase coordination note

`preset=rfc_compliance` is the responsibility of whichever Stage-1 phase first needs it for its own use:

- If A7's curated packetdrill-shim corpus contains scripts that require RFC behaviour (delayed-ACK timing, Nagle batching, Linux-equivalent CC), A7 introduces `preset=rfc_compliance` as part of A7. A9 (this phase) consumes nothing.
- If A7 curates its corpus to match our trading-latency defaults (or marks RFC-only scripts SKIPPED), nothing in Stage 1 needs the preset; S2-A introduces it.

Either way, A9 introduces no preset and adds no new §6.4 deviation row this phase.

---

## 11. Memory items consumed

Already in MEMORY.md and applied in this design:

- `feedback_trading_latency_defaults` — preset is a knob, not a default; A9 does not add the preset
- `feedback_observability_primitives_only` — FaultInjector counters are primitives; no aggregation in-stack
- `feedback_subagent_model` — opus 4.7 for all subagent dispatches (per-task reviews + end-of-phase reviews)
- `feedback_per_task_review_discipline` — spec-compliance + code-quality reviewer subagents per non-trivial step
- `feedback_phase_mtcp_review` + `feedback_phase_rfc_review` — end-of-phase blocking gates
- `feedback_counter_policy` — `fault_injector` counters behind cargo feature; zero hot-path cost in default builds
- `feedback_performance_first_flow_control` — fault-injector models lossy network at ingress; doesn't alter our flow-control behaviour
- `feedback_rust_toolchain` — main workspace stays stable; nightly pinned only inside `crates/dpdk-net-core/fuzz/`
- `reference_tcp_test_suites` — TCP-Fuzz lineage (deferred to S2-A); smoltcp FaultInjector pattern (this phase); Scapy adversarial corpus (this phase)
- `project_arm_roadmap` — fault-injector + test-inject use no x86_64-only atomic/layout assumptions

---

## 12. Approximate task count

~10 tasks (down from the roadmap's original ~15 after dropping differential):

1. Test-inject hook: `inject_rx_frame` + `inject_rx_chain` on Engine + lazy test-inject mempool + `InjectErr` + `test-inject` cargo feature
2. FaultInjector module + engine wiring + counters + env-var parser, all behind `fault-injector` feature
3. cargo-fuzz subdirectory bootstrap (Cargo.toml, rust-toolchain.toml, .gitignore) + 6 pure-module fuzz targets
4. cargo-fuzz `engine_inject` target (T1.5 persistent-mode)
5. 6 proptest suites
6. `tools/scapy-corpus/` Python scripts + seeds + Makefile-style regenerate script
7. `tools/scapy-fuzz-runner/` Rust binary + pcap-file integration + invariant assertions
8. I-8 fix in `tcp_input.rs` + directed Scapy script + Rust integration test
9. CI integration: `scripts/fuzz-smoke.sh` + `scripts/fuzz-long-run.sh` + `scripts/scapy-corpus.sh` + workflow YAML hooks
10. Roadmap update + sign-off (mTCP + RFC reviewers, parallel, opus 4.7) + tag `phase-a9-complete`

Each task above carries the per-task two-stage subagent review (spec-compliance + code-quality) per `feedback_per_task_review_discipline.md`.
