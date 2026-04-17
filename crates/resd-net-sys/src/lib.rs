#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::all,
    clippy::pedantic
)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpdk_version_string_nonempty() {
        // Safety: rte_version is read-only, available without EAL init.
        let ptr = unsafe { rte_version() };
        assert!(!ptr.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
        let s = s.to_str().expect("utf8");
        println!("{s}"); // surfaced under `cargo test -- --nocapture`
        assert!(s.starts_with("DPDK "), "got {s:?}");
        assert!(
            s.contains("23.11") || s.contains("24."),
            "version mismatch: {s:?}"
        );
    }

    #[test]
    fn resd_rte_errno_linkable() {
        // Just prove the symbol links and can be called. Value before EAL init
        // is typically 0 but could be any int; we only care that linking works.
        let _ = unsafe { resd_rte_errno() };
    }

    #[test]
    fn resd_mbuf_shim_symbols_linkable() {
        // Just prove the symbols link — actually calling them needs EAL.
        let _a: unsafe extern "C" fn(*mut rte_mempool) -> *mut rte_mbuf = resd_rte_pktmbuf_alloc;
        let _b: unsafe extern "C" fn(*mut rte_mbuf, u16) -> *mut std::os::raw::c_char =
            resd_rte_pktmbuf_append;
        let _c: unsafe extern "C" fn(u16, *mut rte_ether_addr) -> i32 = resd_rte_eth_macaddr_get;
        let _d: unsafe extern "C" fn(*const rte_mbuf) -> *mut std::os::raw::c_void =
            resd_rte_pktmbuf_data;
        let _e: unsafe extern "C" fn(*const rte_mbuf) -> u16 = resd_rte_pktmbuf_data_len;
    }
}
