use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invariant TSC not supported on this CPU")]
    NoInvariantTsc,
    #[error("DPDK EAL init failed: rte_errno={0}")]
    EalInit(i32),
    #[error("mempool creation failed: {0}")]
    MempoolCreate(&'static str),
    #[error("port {0} dev_info query failed: rte_errno={1}")]
    PortInfo(u16, i32),
    #[error("port {0} configure failed: rte_errno={1}")]
    PortConfigure(u16, i32),
    #[error("port {0} rx queue setup failed: rte_errno={1}")]
    RxQueueSetup(u16, i32),
    #[error("port {0} tx queue setup failed: rte_errno={1}")]
    TxQueueSetup(u16, i32),
    #[error("port {0} start failed: rte_errno={1}")]
    PortStart(u16, i32),
    #[error("invalid lcore {0}")]
    InvalidLcore(u16),
    #[error("gateway MAC not found in /proc/net/arp for ip {0:#x}")]
    GatewayMacNotFound(u32),
    #[error("failed to read /proc/net/arp: {0}")]
    ProcArpRead(String),
    #[error("default gateway not found in /proc/net/route (iface filter: {0:?})")]
    GatewayIpNotFound(Option<String>),
    #[error("failed to read /proc/net/route: {0}")]
    ProcRouteRead(String),
    #[error("could not read NIC MAC for port {0}: rte_errno={1}")]
    MacAddrLookup(u16, i32),
    #[error("too many open connections (max_connections reached)")]
    TooManyConns,
    #[error("invalid connection handle: {0}")]
    InvalidConnHandle(u64),
    #[error("peer unreachable: ip={0:#x}")]
    PeerUnreachable(u32),
    #[error("send buffer full for this connection")]
    SendBufferFull,
    /// LLQ activation verification failed per spec §5.
    /// Fires when hw-verify-llq is compile-enabled AND the driver is
    /// net_ena AND the PMD log shows no activation marker (or a failure
    /// marker) around rte_eth_dev_start.
    #[error("LLQ activation failed on port {0}: no activation marker found in PMD log")]
    LlqActivationFailed(u16),
    /// Log capture init failed — fmemopen/rte_openlog_stream returned error.
    /// Fires only when hw-verify-llq is compile-enabled.
    #[error("log capture init failed: {0}")]
    LogCaptureInit(String),
    /// A6 (spec §3.8.3): `rtt_histogram_bucket_edges_us` was non-monotonic
    /// or had an equal-adjacent pair. `engine_create` rejects with null-return.
    #[error("invalid histogram edges (not strictly monotonic)")]
    InvalidHistogramEdges,
    /// bug_010 → feature: `ConnectOpts.local_addr` is non-zero but does not
    /// match `EngineConfig.local_ip` nor appear in `secondary_local_ips`.
    /// Mapped to `-EINVAL` at the FFI boundary (`dpdk_net_connect`).
    #[error("invalid local source IP for connect: {0:#x}")]
    InvalidLocalAddr(u32),
}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn a3_variants_format_cleanly() {
        assert!(format!("{}", Error::TooManyConns).contains("too many"));
        assert!(format!("{}", Error::InvalidConnHandle(0)).contains("0"));
        assert!(format!("{}", Error::PeerUnreachable(0xdeadbeef)).contains("deadbeef"));
        assert!(format!("{}", Error::SendBufferFull).contains("buffer"));
    }
}
