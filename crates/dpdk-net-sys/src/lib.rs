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
    fn shim_rte_errno_linkable() {
        // Just prove the symbol links and can be called. Value before EAL init
        // is typically 0 but could be any int; we only care that linking works.
        let _ = unsafe { shim_rte_errno() };
    }

    #[test]
    fn shim_mbuf_symbols_linkable() {
        // Just prove the symbols link — actually calling them needs EAL.
        let _a: unsafe extern "C" fn(*mut rte_mempool) -> *mut rte_mbuf = shim_rte_pktmbuf_alloc;
        let _b: unsafe extern "C" fn(*mut rte_mbuf, u16) -> *mut std::os::raw::c_char =
            shim_rte_pktmbuf_append;
        let _c: unsafe extern "C" fn(u16, *mut rte_ether_addr) -> i32 = shim_rte_eth_macaddr_get;
        let _d: unsafe extern "C" fn(*const rte_mbuf) -> *mut std::os::raw::c_void =
            shim_rte_pktmbuf_data;
        let _e: unsafe extern "C" fn(*const rte_mbuf) -> u16 = shim_rte_pktmbuf_data_len;
    }

    #[test]
    fn shim_mbuf_offload_symbols_linkable() {
        // A-HW Task 7: prove the ol_flags / tx-len shim symbols link.
        // Actually calling them needs a live rte_mbuf (so EAL + mempool).
        let _a: unsafe extern "C" fn(*mut rte_mbuf, u64) = shim_rte_mbuf_or_ol_flags;
        let _b: unsafe extern "C" fn(*mut rte_mbuf, u16, u16, u16) = shim_rte_mbuf_set_tx_lens;
        let _c: unsafe extern "C" fn(*const rte_mbuf) -> u64 = shim_rte_mbuf_get_ol_flags;
        let _d: unsafe extern "C" fn(*const rte_mbuf) -> u16 = shim_rte_mbuf_get_l2_len;
        let _e: unsafe extern "C" fn(*const rte_mbuf) -> u16 = shim_rte_mbuf_get_l3_len;
        let _f: unsafe extern "C" fn(*const rte_mbuf) -> u16 = shim_rte_mbuf_get_l4_len;
        // A-HW Task 9: RSS hash accessor shim symbol.
        let _g: unsafe extern "C" fn(*const rte_mbuf) -> u32 = shim_rte_mbuf_get_rss_hash;
        // A-HW Task 10: RX timestamp dynfield read shim symbol.
        let _h: unsafe extern "C" fn(*const rte_mbuf, i32) -> u64 =
            shim_rte_mbuf_read_dynfield_u64;
    }
}
