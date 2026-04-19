//! LLQ activation verification via PMD log-scrape (A-HW Task 12 / spec §5).
//!
//! Amazon ENA's Low-Latency Queue (LLQ) mode is an ENA-internal state with
//! no clean DPDK API to query post-`rte_eth_dev_start`. The PMD emits a
//! structured "Placement policy: <mode>" log line during `eth_ena_dev_init`
//! (PCI probe) and, on failure paths, emits a "LLQ is not supported" /
//! "Fallback to host mode policy" diagnostic. We redirect the DPDK log
//! stream to an in-memory buffer for the duration of bring-up, then
//! string-match the capture for those markers.
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
//! # Log-timing caveat
//!
//! The ENA "Placement policy" log line is printed during `eth_ena_dev_init`
//! — which runs at `rte_eal_init` / PCI bus-scan time, NOT during the
//! `rte_eth_dev_start` callback. If the capture is installed only around
//! `rte_eth_dev_start` (as A-HW spec §5 and Task 12 specify), the Placement
//! policy line will NOT appear in the captured buffer, so `has_activation`
//! will be false and `verify_llq_activation` will fail hard even when LLQ
//! actually activated. The correct bring-up site for the capture is
//! actually "straddle `rte_eal_init` → `rte_eth_dev_start`" so that probe
//! logs are captured too. Task 12's scope pins the capture to dev_start
//! only; a follow-up task should widen the window (or move the capture to
//! `init_eal` in engine.rs). This file implements the dev_start-scoped
//! behavior as specified.

use crate::counters::Counters;
use crate::error::Error;
use resd_net_sys as sys;
use std::sync::atomic::Ordering;

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
/// way as other bring-up faults.
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

/// Inspect the captured PMD log for LLQ activation / failure markers.
/// Non-ENA drivers short-circuit (`Ok(())`). On ENA:
///   - Failure marker present OR activation marker absent → bump
///     `counters.eth.offload_missing_llq`, emit a diagnostic to stderr
///     with the full captured log, and return `Error::LlqActivationFailed`.
///   - Activation marker present AND no failure marker → `Ok(())`.
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
        // LLQ is ENA-specific; short-circuit for every other PMD
        // (`net_tap`, `net_vdev`, `net_mlx5`, `net_ixgbe`, ...).
        return Ok(());
    }
    let has_activation = LLQ_ACTIVATION_MARKERS
        .iter()
        .any(|m| captured_log.contains(m));
    let has_failure = LLQ_FAILURE_MARKERS
        .iter()
        .any(|m| captured_log.contains(m));
    if has_failure || !has_activation {
        counters
            .eth
            .offload_missing_llq
            .fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "resd_net: port {} driver=net_ena but LLQ did not activate at bring-up \
             (has_failure={}, has_activation={}). Failing hard per spec §5.\n\
             --- captured PMD log ---\n{}\n--- end log ---",
            port_id, has_failure, has_activation, captured_log
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
}
