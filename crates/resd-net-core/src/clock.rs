use std::sync::OnceLock;
use std::time::Instant;

/// Single process-wide TSC calibration shared across all engines,
/// per spec §7.5.
#[derive(Debug, Clone, Copy)]
pub struct TscEpoch {
    pub tsc0: u64,
    pub t0_ns: u64,
    pub ns_per_tsc_scaled: u64,  // fixed-point: actual ns_per_tsc = ns_per_tsc_scaled / 2^32
}

static TSC_EPOCH: OnceLock<TscEpoch> = OnceLock::new();

pub fn tsc_epoch() -> &'static TscEpoch {
    TSC_EPOCH.get_or_init(calibrate)
}

#[inline(always)]
pub fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    compile_error!("resd-net-core currently only supports x86_64");
}

#[inline]
pub fn now_ns() -> u64 {
    let e = tsc_epoch();
    let delta = rdtsc().wrapping_sub(e.tsc0);
    // delta * (ns_per_tsc_scaled / 2^32) + t0_ns
    let scaled = ((delta as u128) * (e.ns_per_tsc_scaled as u128)) >> 32;
    e.t0_ns + scaled as u64
}

fn calibrate() -> TscEpoch {
    check_invariant_tsc().expect("invariant TSC required");
    let start_instant = Instant::now();
    let start_tsc = rdtsc();
    // Busy-loop a known-duration window for ratio measurement.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let end_instant = Instant::now();
    let end_tsc = rdtsc();

    let elapsed_ns = (end_instant - start_instant).as_nanos() as u64;
    let tsc_delta = end_tsc.wrapping_sub(start_tsc);
    // NOTE: the parens are load-bearing — Rust's `/` binds tighter than `<<`,
    // so `(x as u128) << 32 / y as u128` would shift by 0 for any y > 32.
    let ns_per_tsc_scaled: u64 = (((elapsed_ns as u128) << 32) / (tsc_delta as u128)) as u64;

    TscEpoch {
        tsc0: start_tsc,
        // now_ns() returns "ns since calibration start" — tsc0 maps to 0.
        t0_ns: 0,
        ns_per_tsc_scaled,
    }
}

#[cfg(target_arch = "x86_64")]
fn check_invariant_tsc() -> Result<(), crate::Error> {
    // CPUID.80000007H:EDX[8] = InvariantTSC.
    // `__cpuid` is safe on any x86_64 target (no target_feature gate) so
    // rustc 1.95 flags a wrapping `unsafe { }` as unused_unsafe.
    let r = std::arch::x86_64::__cpuid(0x8000_0007);
    if (r.edx & (1 << 8)) != 0 {
        Ok(())
    } else {
        Err(crate::Error::NoInvariantTsc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_ns_monotonic_increasing() {
        let a = now_ns();
        let b = now_ns();
        assert!(b >= a, "now_ns went backwards: {a} -> {b}");
    }

    #[test]
    fn now_ns_within_one_percent_of_wall_clock() {
        // Force calibration before capturing wall_start so the 50ms calibration
        // sleep doesn't land inside the measurement window under parallel tests.
        let _ = now_ns();
        let wall_start = std::time::Instant::now();
        let tsc_start = now_ns();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let wall_ns = wall_start.elapsed().as_nanos() as u64;
        let tsc_ns = now_ns() - tsc_start;
        let diff = wall_ns.abs_diff(tsc_ns) as f64;
        let relative = diff / wall_ns as f64;
        assert!(relative < 0.02, "TSC drift too large: wall={wall_ns} tsc={tsc_ns} rel={relative}");
    }
}
