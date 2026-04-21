//! A-HW+ pure-unit smoke. No DPDK; no real EAL; runs on every CI worker.
//! Asserts the slow-path observability primitives behave per spec.

#[test]
fn wc_verify_smoke() {
    use dpdk_net_core::wc_verify::{parse_pat_memtype_list, WcVerdict};
    let sample = "PAT: [mem 0x00000000fe900000-0x00000000fea00000] write-combining\n";
    assert_eq!(
        parse_pat_memtype_list(sample, 0xfe900000),
        WcVerdict::WriteCombining
    );
    assert_eq!(
        parse_pat_memtype_list(sample, 0xfea00000),
        WcVerdict::NotFound
    );
}

#[test]
fn xstats_map_apply_smoke() {
    use dpdk_net_core::ena_xstats::{XstatMap, XSTAT_NAMES};

    // apply() is pub(crate) and scrape() needs DPDK EAL, so this smoke
    // exercises the reachable surface: XSTAT_NAMES as the slot-index
    // ground truth + from_lookup round-trips. The counter-write path
    // is covered by the inline tests inside ena_xstats.rs.
    let map = XstatMap::from_lookup(|_| Some(0));

    // XSTAT_NAMES is the ground truth for which slots the scraper
    // writes. All 13 names must be present.
    assert_eq!(XSTAT_NAMES.len(), 13);
    // Spot-check the first and last names match the expected ENA PMD
    // literals — a name typo would silently break the xstat-id resolver.
    assert_eq!(XSTAT_NAMES[0], "bw_in_allowance_exceeded");
    assert_eq!(XSTAT_NAMES[XSTAT_NAMES.len() - 1], "rx_q0_mbuf_alloc_fail");

    // Every lookup slot populated → ids vector has the same length.
    assert_eq!(map.ids.len(), XSTAT_NAMES.len());
    // Spot-check ids contents.
    assert_eq!(map.ids[0], Some(0));
    assert_eq!(map.ids[12], Some(0));
}

#[test]
fn xstats_map_unadvertised_has_none_slots() {
    use dpdk_net_core::ena_xstats::{XstatMap, XSTAT_NAMES};
    // Only the first 5 names (ENI allowances) advertised; rest None.
    let map = XstatMap::from_lookup(|n| {
        if XSTAT_NAMES.iter().position(|x| x == &n).is_some_and(|i| i < 5) {
            Some(0)
        } else {
            None
        }
    });
    assert_eq!(map.ids.len(), 13);
    for i in 0..5 {
        assert!(map.ids[i].is_some(), "slot {} should be advertised", i);
    }
    for i in 5..13 {
        assert!(map.ids[i].is_none(), "slot {} should be None", i);
    }
}
