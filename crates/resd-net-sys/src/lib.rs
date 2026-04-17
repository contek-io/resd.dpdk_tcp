#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]

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
        assert!(s.contains("23.11") || s.contains("24."), "version mismatch: {s:?}");
    }
}
