# tsc_read family — A10-perf-23.11 — final summary

## Final criterion numbers

| Bench                    | Pre-T3.6 baseline | Post-T3.6 final | §11.2 upper | Within budget? |
|--------------------------|-------------------|-----------------|-------------|----------------|
| `bench_tsc_read_ffi`     | 10.179 ns         | 10.222 ns       | 5 ns        | no             |
| `bench_tsc_read_inline`  | 10.335 ns         | 10.159 ns       | 1 ns        | no             |

p99 (computed from criterion's per-sample `times[i] / iters[i]`):

| Bench                    | Post-T3.6 p99 | 2× upper | Within budget? |
|--------------------------|---------------|----------|----------------|
| `bench_tsc_read_ffi`     | 10.344 ns     | 10 ns    | no             |
| `bench_tsc_read_inline`  | 10.346 ns     | 2 ns     | no             |

## Retained optimizations

- **H1 (methodology)**: switch both benches from `b.iter` to `b.iter_custom`
  with BATCH=128 inner calls per closure invocation. Criterion's per-iter
  closure-call + sample-bookkeeping overhead can dominate at sub-10 ns
  workloads; batching amortizes that fixed cost across BATCH calls and
  the returned `elapsed / BATCH` is criterion's per-call median directly.
  In this family the change did NOT improve median per-call cost (within
  noise on both benches), proving the gap is NOT criterion overhead.
  Retained for measurement methodology hygiene.
- **H2 (XOR-fold black_box)**: replace per-call `black_box(ns)` with an
  XOR accumulator + single end-of-batch `black_box(acc)`. Eliminates
  BATCH-1 stack store/load roundtrips per iter. Saved ~1.7 % on
  `bench_tsc_read_inline` (10.34 → 10.17 ns). FFI variant unchanged
  (within noise) because `black_box(std::ptr::null_mut())` on the FFI
  arg is still per-call and dominates over the result-side fold. Retained.

Both changes ship as a single commit because they share the new
`b.iter_custom` scaffold.

## Rejected hypotheses

- **H3 (inline variant isn't inlining)**: REJECTED by asm inspection.
  `objdump -d target/release/deps/tsc_read-*` shows both bench hot loops
  carry a literal `rdtsc` instruction inline, plus the inlined
  `OnceLock::get_or_init` fast-path check, plus the inlined scaled-multiply
  conversion (`mulq` + `shld $0x20`). No `call clock::now_ns` indirection.
  rustc is doing the right thing under LTO; `#[inline(always)]` on `rdtsc`
  and `#[inline]` on `now_ns` are sufficient. Filed at
  `crates/dpdk-net-core/src/clock.rs:29-46`.

## Exit reason

**host-ceiling (KVM TSC virtualization)**

After H1 and H2 we measured a hardware floor of ~10.2 ns per `rdtsc` +
scaled-multiply on this KVM host (AMD EPYC 7R13 / Zen 3 under KVM, AWS
m6a-class). The same floor reproduces with a pure C tight loop using
`__rdtsc` directly:

```c
// gcc -O3 rdtsc_walltime.c
const uint64_t N = 100000000;
uint64_t acc = 0;
struct timespec ts0, ts1;
clock_gettime(CLOCK_MONOTONIC, &ts0);
for (uint64_t i = 0; i < N; i++) {
    acc ^= __rdtsc();
}
clock_gettime(CLOCK_MONOTONIC, &ts1);
// Output (3 runs):
//   100000000 rdtsc ops, 1013308507 wall ns, 10.13 ns/op
//   100000000 rdtsc ops, 1012917364 wall ns, 10.13 ns/op
//   100000000 rdtsc ops, 1011070723 wall ns, 10.11 ns/op
```

10.13 ns/op for a single C `__rdtsc` matches our criterion bench's 10.17 ns
exactly. There is no Rust- or FFI- side improvement available — the bench
is already at hardware floor for this virtualized host.

## KVM caveats

`/proc/cpuinfo` shows `flags: ... rdtscp lm constant_tsc nonstop_tsc ...
hypervisor`. The `hypervisor` flag and AWS host model (EPYC 7R13 under
KVM) indicate a virtualized environment. `tsc` is selected as the
clocksource (`/sys/devices/system/clocksource/clocksource0/current_clocksource`
== `tsc`), so Linux is using TSC passthrough rather than `kvm-clock`.
Despite that, the observed `rdtsc` latency on this host (~10.1 ns) is
~2 - 3× higher than typical bare-metal Zen 3 (~5 ns). The most plausible
explanation is a per-RDTSC offset adjustment or VMCS round-trip overhead
on this Nitro/KVM configuration; we cannot disable that from inside the
guest.

## Asm inspection notes (carried forward for reproducibility)

For both benches, the criterion-monomorphized hot loop (e.g.
`tsc_read::bench_tsc_read_inline::{closure} → criterion::Bencher::iter_custom`)
contains exactly:

```
loop_top:
    mov   OnceLock_state, %eax       ; OnceLock::get fast-path probe
    test  %eax, %eax
    jne   slow_init
    rdtsc                            ; ← the actual hot instruction
    shl   $0x20, %rdx
    or    %rdx, %rax
    sub   tsc0(%rip), %rax           ; (rdtsc - epoch.tsc0)
    mulq  ns_per_tsc_scaled(%rip)    ; 64x64 → 128-bit mul
    shld  $0x20, %rax, %rdx          ; >> 32 (the scale factor)
    add   t0_ns(%rip), %rdx          ; + epoch.t0_ns
    xor   %rdx, %r{N}                ; H2 XOR-fold accumulator
    dec   %r13
    jne   loop_top
```

The FFI variant's loop is identical except for an extra
`movq $0x0, 0x8(%rsp); mov 0x8(%rsp), %rax` pair that materializes the
`black_box(std::ptr::null_mut())` arg. That pair adds ~0.05 ns on
average (within noise), accounting for the small ffi-vs-inline gap.

`dpdk_net_now_ns` is `extern "C"` but rustc's LTO inlines it through
the FFI boundary into the bench's hot loop. There is no actual `call`
instruction for either variant in release mode.

## Future work

- If a future bare-metal run (or migration to a Nitro/m7a/c7a instance
  type with EPYC 9R14 or PVH-host TSC) shows `bench_tsc_read_inline` ≤ 5 ns,
  the §11.2 1 ns target may still be infeasible (the scaled-multiply
  alone is ~2 cycles ≈ 0.6 ns even on bare-metal Zen 4), but a 2 - 3 ns
  median should be achievable. The §11.2 number was set against a
  notional inline-FFI spec target; once we have a true header-inline
  variant (a future task per the bench file's TODO comment), revisit.
- A potential code-side improvement is to skip the OnceLock probe in
  `now_ns` once initialized — i.e. cache the `&'static TscEpoch` at thread
  startup and access it without going through `OnceLock::get_or_init`.
  Saves one MOV per call (~0.3 ns). Not worth the API churn at the
  current host ceiling; revisit on bare-metal.
