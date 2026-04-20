//! LLQ activation verification via PMD log-scrape (A-HW Task 12 / spec §5).
//!
//! Amazon ENA's Low-Latency Queue (LLQ) mode is an ENA-internal state with
//! no clean DPDK API to query post-`rte_eth_dev_start`. The PMD emits a
//! structured "Placement policy: <mode>" log line during `eth_ena_dev_init`
//! and, on failure paths, a "LLQ is not supported" / "Fallback to host mode
//! policy" diagnostic. We redirect the DPDK log stream to an in-memory
//! buffer for the duration of bring-up, then string-match the capture.
//!
//! Markers pinned against DPDK 23.11 (`drivers/net/ena/ena_ethdev.c`):
//!   - `PMD_DRV_LOG(INFO, "Placement policy: %s\n", ...)` where `%s` is
//!     literally `"Low latency"` on success and `"Regular"` on fallback
//!     (ena_ethdev.c:2273-2277).
//!   - `PMD_DRV_LOG(INFO, "LLQ is not supported. Fallback to host mode
//!     policy.\n")` on advertise-missing (ena_ethdev.c:2044-2045).
//!
//! Future DPDK upgrades that change these strings will fail engine startup
//! rather than silently running without LLQ — the fail-safe direction
//! required by parent §8.4 Tier 1 / A-HW spec §5.
//!
//! # Capture-timing correction (Task 12 fixup)
//!
//! The ENA "Placement policy" log line is printed during `eth_ena_dev_init`
//! — which runs at `rte_eal_init` / PCI bus-scan time, NOT during the
//! `rte_eth_dev_start` callback. Task 12's original implementation installed
//! the capture around `rte_eth_dev_start`, opening the capture window AFTER
//! the PMD had already emitted its markers. On real ENA hosts the captured
//! buffer was therefore empty and verification failed hard on every
//! bring-up. This fixup moves the capture into the Rust-side `eal_init`
//! helper so it wraps `rte_eal_init` (see `engine::eal_init`). The
//! capture-time log is scanned once for the activation / failure markers,
//! and the resulting `LlqVerdict` is stored in a process-global
//! `OnceLock`. `Engine::new` reads the stored verdict per-engine instead of
//! running its own capture — multiple engine creates on the same host
//! share one EAL-init verdict because EAL init happens once per process.
//!
//! Reference: `/tmp/dpdk/drivers/net/ena/ena_ethdev.c` — marker emission
//! at lines 2273-2277 (inside `ena_parse_devargs` → `eth_ena_dev_init`
//! → PCI probe, all under `rte_eal_init`). `ena_start` (called from
//! `rte_eth_dev_start`) emits no LLQ markers.

use crate::counters::Counters;
use crate::error::Error;
use resd_net_sys as sys;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

/// Size of the in-memory log-capture buffer. 16 KiB is ample headroom for
/// bring-up: the ENA PMD typically logs ~30-50 lines of ~100 bytes each.
const CAPTURE_BUF_SIZE: usize = 16 * 1024;

/// Captured-log context. `orig_stream` is the DPDK log stream in effect
/// before the redirect — restored in `finish_log_capture`. `buf` owns the
/// backing memory for `memstream` (fmemopen writes into it).
pub(crate) struct LogCaptureCtx {
    /// Original DPDK log stream (bindgen's `FILE*` — `*mut sys::FILE`).
    /// Restored via `rte_openlog_stream` in `finish_log_capture`.
    orig_stream: *mut sys::FILE,
    /// Owned, heap-allocated backing buffer for the fmemopen memstream.
    /// Kept alive until after `fclose(memstream)` in `finish_log_capture`.
    buf: Box<[u8; CAPTURE_BUF_SIZE]>,
    /// libc `FILE*` returned by fmemopen — this is what DPDK writes into.
    /// Closed by `finish_log_capture`.
    memstream: *mut libc::FILE,
}

/// Open an fmemopen-backed memstream, redirect the DPDK log stream into
/// it, and return the capture context. The caller must eventually call
/// `finish_log_capture` to restore the original stream and read out the
/// captured text.
///
/// On failure either `fmemopen` or `rte_openlog_stream` can return error;
/// both map to `Error::LogCaptureInit` so the caller surfaces it the same
/// way as other bring-up faults. The `eal_init` caller treats capture-init
/// failures as non-fatal (EAL init proceeds without a capture — the
/// engine-side verifier will then soft-skip with a warning).
pub(crate) fn start_log_capture() -> Result<LogCaptureCtx, Error> {
    let mut buf: Box<[u8; CAPTURE_BUF_SIZE]> = Box::new([0u8; CAPTURE_BUF_SIZE]);
    // Mode `"w+"` opens read-write and auto-NUL-terminates the buffer
    // after each write (glibc fmemopen behavior — POSIX-compliant).
    let memstream = unsafe {
        libc::fmemopen(
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            c"w+".as_ptr() as *const _,
        )
    };
    if memstream.is_null() {
        return Err(Error::LogCaptureInit("fmemopen returned NULL".to_string()));
    }
    // Bindgen names DPDK's `FILE*` type as `sys::FILE` and libc's own
    // `FILE*` as `libc::FILE`. They are nominally distinct Rust types but
    // both are opaque `_IO_FILE*` at the C ABI, so the pointer cast is
    // valid in both directions.
    let orig = unsafe { sys::rte_log_get_stream() };
    let rc = unsafe { sys::rte_openlog_stream(memstream as *mut sys::FILE) };
    if rc != 0 {
        unsafe { libc::fclose(memstream) };
        return Err(Error::LogCaptureInit(format!(
            "rte_openlog_stream returned {rc}"
        )));
    }
    Ok(LogCaptureCtx {
        orig_stream: orig,
        buf,
        memstream,
    })
}

/// Flush the memstream, restore the original DPDK log stream, close the
/// memstream, and return the captured text as an owned `String`. The
/// fmemopen-backed buffer is NUL-terminated after each write (glibc's
/// documented behavior for `"w+"` mode), so we trim at the first NUL.
pub(crate) fn finish_log_capture(ctx: LogCaptureCtx) -> Result<String, Error> {
    // Flush + restore + close, in that order. Restore first would risk
    // a race with a still-active DPDK log emitter on another thread, but
    // bring-up is single-threaded per spec §7, so the order is only for
    // tidiness.
    unsafe {
        libc::fflush(ctx.memstream);
        sys::rte_openlog_stream(ctx.orig_stream);
        libc::fclose(ctx.memstream);
    }
    let end = ctx.buf.iter().position(|&b| b == 0).unwrap_or(ctx.buf.len());
    Ok(String::from_utf8_lossy(&ctx.buf[..end]).into_owned())
}

/// Activation markers pinned against DPDK 23.11
/// (`drivers/net/ena/ena_ethdev.c` lines 2273-2277). The PMD emits
/// literal `"Placement policy: Low latency"` on success — we match that
/// substring, NOT the bare `"Placement policy:"` prefix (which would
/// also match the `"Regular"` fallback line and falsely pass).
const LLQ_ACTIVATION_MARKERS: &[&str] = &[
    "Placement policy: Low latency",
    "LLQ supported",
    "using LLQ",
];

/// Failure markers. Any of these substrings in the captured log means
/// LLQ did not activate (explicit diagnostic path in the PMD). Pinned
/// against ena_ethdev.c:2034-2062.
const LLQ_FAILURE_MARKERS: &[&str] = &[
    "LLQ is not supported",
    "Fallback to disabled LLQ",
    "LLQ is not enabled",
    "NOTE: LLQ has been disabled",
    "Placement policy: Regular",
    "Fallback to host mode policy",
];

/// Scan verdict derived from a captured log. Built by
/// `scan_log_for_verdict` (the pure scanner) and consumed by both the
/// global-verdict path (`record_eal_init_log_verdict` →
/// `verify_llq_activation_from_global`) and the direct-log path
/// (`verify_llq_activation` — retained for the existing unit tests).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct LlqVerdict {
    pub has_activation: bool,
    pub has_failure: bool,
    /// Whether the capture actually ran. If `false`, eal_init never called
    /// `record_eal_init_log_verdict` (e.g. tests bypassing eal_init).
    /// `verify_llq_activation_from_global` treats "no verdict recorded"
    /// as "skip verification" rather than "failure" — legitimate when
    /// multiple engine creates share one EAL init, or when unit-test
    /// setups bypass resd_net_eal_init entirely.
    pub captured: bool,
}

/// Pure scanner: inspect a captured log buffer for LLQ activation / failure
/// markers. Shared between `record_eal_init_log_verdict` (capture-time
/// scan inside `eal_init`) and `verify_llq_activation` (test-facing
/// wrapper that preserves the pre-fixup call signature).
pub(crate) fn scan_log_for_verdict(captured_log: &str) -> LlqVerdict {
    let has_activation = LLQ_ACTIVATION_MARKERS
        .iter()
        .any(|m| captured_log.contains(m));
    let has_failure = LLQ_FAILURE_MARKERS
        .iter()
        .any(|m| captured_log.contains(m));
    LlqVerdict {
        has_activation,
        has_failure,
        captured: true,
    }
}

/// Process-global verdict captured at `rte_eal_init` time. EAL init runs
/// once per process, so a single `OnceLock` is enough; subsequent
/// engine creates all read the same stored verdict.
static EAL_INIT_VERDICT: OnceLock<LlqVerdict> = OnceLock::new();

/// Called from `engine::eal_init` immediately AFTER `rte_eal_init`
/// returns, handing in the captured log text. Scans for ENA LLQ
/// activation + failure markers and stores the verdict globally for
/// later engine-create consumption.
pub(crate) fn record_eal_init_log_verdict(captured_log: &str) {
    let verdict = scan_log_for_verdict(captured_log);
    // First-writer wins. `eal_init` guards against re-entry via its
    // Mutex<bool> latch, so under normal use this set() always succeeds.
    let _ = EAL_INIT_VERDICT.set(verdict);
}

/// Called from `Engine::new` per-engine. Returns `Ok(())` when:
///   - `driver_name != "net_ena"` (short-circuit; LLQ is ENA-specific).
///   - EAL init did not record a verdict (e.g. unit-test setups that
///     bypass `resd_net_eal_init`). Emits a warning to stderr but does
///     not fail bring-up — real-ENA production MUST flow through
///     `eal_init`, which DOES capture.
///   - Verdict shows `has_activation && !has_failure`.
///
/// Returns `Err(LlqActivationFailed)` + bumps `offload_missing_llq`
/// otherwise (ENA driver AND verdict present AND
/// `has_failure || !has_activation`).
pub(crate) fn verify_llq_activation_from_global(
    port_id: u16,
    driver_name: &[u8; 32],
    counters: &Counters,
) -> Result<(), Error> {
    let driver_str = std::str::from_utf8(
        &driver_name[..driver_name.iter().position(|&b| b == 0).unwrap_or(32)],
    )
    .unwrap_or("");
    if driver_str != "net_ena" {
        // LLQ is ENA-specific; short-circuit for every other PMD
        // (`net_tap`, `net_vdev`, `net_mlx5`, `net_ixgbe`, ...).
        return Ok(());
    }
    let Some(verdict) = EAL_INIT_VERDICT.get() else {
        // No verdict recorded — EAL init path didn't capture. This
        // happens in unit-test setups that bypass resd_net_eal_init, or
        // if the capture-init step inside `eal_init` failed (non-fatal).
        // Treat as a soft-skip rather than a failure; real-ENA bring-up
        // MUST flow through `eal_init` which captures the log.
        eprintln!(
            "resd_net: port {} driver=net_ena but no EAL-init LLQ capture recorded; \
             skipping LLQ verification. Ensure resd_net_eal_init runs on real ENA hosts.",
            port_id
        );
        return Ok(());
    };
    if !verdict.captured {
        return Ok(());
    }
    if verdict.has_failure || !verdict.has_activation {
        counters
            .eth
            .offload_missing_llq
            .fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "resd_net: port {} driver=net_ena but LLQ did not activate at EAL init \
             (has_failure={}, has_activation={}). Failing hard per spec §5.",
            port_id, verdict.has_failure, verdict.has_activation
        );
        return Err(Error::LlqActivationFailed(port_id));
    }
    Ok(())
}

/// Test-facing wrapper: preserves the pre-fixup direct-log signature
/// used by `llq_verify::tests`. Engine bring-up no longer calls this —
/// it goes through `verify_llq_activation_from_global` which reads the
/// stored verdict instead. The logic is identical to the ENA branch of
/// `verify_llq_activation_from_global` except that the verdict is
/// computed from the caller-supplied log instead of the OnceLock.
///
/// `allow(dead_code)` covers builds where only tests exercise this
/// helper — the engine bring-up path no longer references it.
#[allow(dead_code)]
pub(crate) fn verify_llq_activation(
    port_id: u16,
    driver_name: &[u8; 32],
    captured_log: &str,
    counters: &Counters,
) -> Result<(), Error> {
    let driver_str = std::str::from_utf8(
        &driver_name[..driver_name.iter().position(|&b| b == 0).unwrap_or(32)],
    )
    .unwrap_or("");
    if driver_str != "net_ena" {
        return Ok(());
    }
    let verdict = scan_log_for_verdict(captured_log);
    if verdict.has_failure || !verdict.has_activation {
        counters
            .eth
            .offload_missing_llq
            .fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "resd_net: port {} driver=net_ena but LLQ did not activate at bring-up \
             (has_failure={}, has_activation={}). Failing hard per spec §5.\n\
             --- captured PMD log ---\n{}\n--- end log ---",
            port_id, verdict.has_failure, verdict.has_activation, captured_log
        );
        return Err(Error::LlqActivationFailed(port_id));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::counters::Counters;

    fn dn(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let b = s.as_bytes();
        out[..b.len()].copy_from_slice(b);
        out
    }

    #[test]
    fn non_ena_driver_short_circuits_even_without_markers() {
        let counters = Counters::new();
        let res = verify_llq_activation(0, &dn("net_tap"), "", &counters);
        assert!(res.is_ok(), "net_tap must short-circuit regardless of log");
        assert_eq!(
            counters.eth.offload_missing_llq.load(Ordering::Relaxed),
            0,
            "non-ena driver must not bump the counter"
        );
    }

    #[test]
    fn ena_with_activation_marker_succeeds() {
        let counters = Counters::new();
        let log = "some preamble\nPlacement policy: Low latency\ntrailing\n";
        let res = verify_llq_activation(0, &dn("net_ena"), log, &counters);
        assert!(res.is_ok(), "activation marker must succeed");
        assert_eq!(
            counters.eth.offload_missing_llq.load(Ordering::Relaxed),
            0,
        );
    }

    #[test]
    fn ena_with_placement_policy_regular_is_failure() {
        let counters = Counters::new();
        // "Placement policy: Regular" means LLQ fell back to host mode —
        // NOT LLQ activation. Verify we do NOT match the bare
        // "Placement policy:" prefix and fail this case.
        let log = "Placement policy: Regular\n";
        let res = verify_llq_activation(0, &dn("net_ena"), log, &counters);
        assert!(matches!(res, Err(Error::LlqActivationFailed(0))));
        assert_eq!(
            counters.eth.offload_missing_llq.load(Ordering::Relaxed),
            1,
        );
    }

    #[test]
    fn ena_with_failure_marker_fails_even_if_activation_also_present() {
        let counters = Counters::new();
        let log = "Placement policy: Low latency\nLLQ is not supported\n";
        let res = verify_llq_activation(0, &dn("net_ena"), log, &counters);
        // Failure marker present → fails regardless of activation marker.
        assert!(matches!(res, Err(Error::LlqActivationFailed(0))));
        assert_eq!(
            counters.eth.offload_missing_llq.load(Ordering::Relaxed),
            1,
        );
    }

    #[test]
    fn ena_with_empty_log_fails() {
        let counters = Counters::new();
        let res = verify_llq_activation(0, &dn("net_ena"), "", &counters);
        assert!(matches!(res, Err(Error::LlqActivationFailed(0))));
        assert_eq!(
            counters.eth.offload_missing_llq.load(Ordering::Relaxed),
            1,
        );
    }

    #[test]
    fn ena_with_enable_llq_disabled_marker_fails() {
        let counters = Counters::new();
        let log = "NOTE: LLQ has been disabled as per user's request. \
                   This may lead to a huge performance degradation!\n";
        let res = verify_llq_activation(0, &dn("net_ena"), log, &counters);
        assert!(matches!(res, Err(Error::LlqActivationFailed(0))));
    }

    #[test]
    fn scan_log_for_verdict_activation_only() {
        let v = scan_log_for_verdict("Placement policy: Low latency\n");
        assert!(v.has_activation);
        assert!(!v.has_failure);
        assert!(v.captured);
    }

    #[test]
    fn scan_log_for_verdict_failure_only() {
        let v = scan_log_for_verdict("LLQ is not supported\n");
        assert!(!v.has_activation);
        assert!(v.has_failure);
        assert!(v.captured);
    }

    #[test]
    fn scan_log_for_verdict_both() {
        let v = scan_log_for_verdict("Placement policy: Low latency\nLLQ is not supported\n");
        assert!(v.has_activation);
        assert!(v.has_failure);
        assert!(v.captured);
    }

    #[test]
    fn scan_log_for_verdict_empty() {
        let v = scan_log_for_verdict("");
        assert!(!v.has_activation);
        assert!(!v.has_failure);
        assert!(v.captured);
    }

    #[test]
    fn from_global_non_ena_short_circuits_even_without_verdict() {
        // The non-ENA short-circuit happens BEFORE touching the OnceLock,
        // so this test is safe regardless of whether an earlier test (or
        // an earlier test run, under `cargo test --release`, which shares
        // a process with the `llq_verify` tests here) populated
        // EAL_INIT_VERDICT.
        let counters = Counters::new();
        let res = verify_llq_activation_from_global(0, &dn("net_tap"), &counters);
        assert!(res.is_ok());
        assert_eq!(
            counters.eth.offload_missing_llq.load(Ordering::Relaxed),
            0,
        );
    }
}
