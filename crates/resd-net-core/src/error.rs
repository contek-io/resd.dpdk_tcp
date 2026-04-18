use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invariant TSC not supported on this CPU")]
    NoInvariantTsc,
    #[error("DPDK EAL init failed: rte_errno={0}")]
    EalInit(i32),
    #[error("mempool creation failed: {0}")]
    MempoolCreate(&'static str),
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
