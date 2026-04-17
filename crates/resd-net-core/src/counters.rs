use std::sync::atomic::{AtomicU64, Ordering};

/// Per-lcore counter struct. Cacheline-grouped.
/// Hot-path increments use Relaxed stores on the owning lcore;
/// cross-lcore snapshot reads use Relaxed loads. Per spec §9.1.
#[repr(C, align(64))]
pub struct EthCounters {
    pub rx_pkts: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rx_drop_miss_mac: AtomicU64,
    pub rx_drop_nomem: AtomicU64,
    pub tx_pkts: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub tx_drop_full_ring: AtomicU64,
    pub tx_drop_nomem: AtomicU64,
    // Phase A2 additions
    pub rx_drop_short: AtomicU64,
    pub rx_drop_unknown_ethertype: AtomicU64,
    pub rx_arp: AtomicU64,
    pub tx_arp: AtomicU64,
    _pad: [u64; 4],
}

#[repr(C, align(64))]
pub struct IpCounters {
    pub rx_csum_bad: AtomicU64,
    pub rx_ttl_zero: AtomicU64,
    pub rx_frag: AtomicU64,
    pub rx_icmp_frag_needed: AtomicU64,
    pub pmtud_updates: AtomicU64,
    // Phase A2 additions
    pub rx_drop_short: AtomicU64,
    pub rx_drop_bad_version: AtomicU64,
    pub rx_drop_bad_hl: AtomicU64,
    pub rx_drop_not_ours: AtomicU64,
    pub rx_drop_unsupported_proto: AtomicU64,
    pub rx_tcp: AtomicU64,
    pub rx_icmp: AtomicU64,
    _pad: [u64; 4],
}

#[repr(C, align(64))]
pub struct TcpCounters {
    pub rx_syn_ack: AtomicU64,
    pub rx_data: AtomicU64,
    pub rx_ack: AtomicU64,
    pub rx_rst: AtomicU64,
    pub rx_out_of_order: AtomicU64,
    pub tx_retrans: AtomicU64,
    pub tx_rto: AtomicU64,
    pub tx_tlp: AtomicU64,
    pub conn_open: AtomicU64,
    pub conn_close: AtomicU64,
    pub conn_rst: AtomicU64,
    pub send_buf_full: AtomicU64,
    pub recv_buf_delivered: AtomicU64,
    _pad: [u64; 3],
}

#[repr(C, align(64))]
pub struct PollCounters {
    pub iters: AtomicU64,
    pub iters_with_rx: AtomicU64,
    pub iters_with_tx: AtomicU64,
    pub iters_idle: AtomicU64,
    _pad: [u64; 12],
}

#[repr(C)]
pub struct Counters {
    pub eth: EthCounters,
    pub ip: IpCounters,
    pub tcp: TcpCounters,
    pub poll: PollCounters,
}

impl Counters {
    pub fn new() -> Self {
        // Default impl from derive not available for atomics; explicit init.
        Self {
            eth: EthCounters::default(),
            ip: IpCounters::default(),
            tcp: TcpCounters::default(),
            poll: PollCounters::default(),
        }
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for EthCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
impl Default for IpCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
impl Default for TcpCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
impl Default for PollCounters {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// Hot-path increment: atomic RMW with Relaxed ordering.
/// On x86_64 this is `lock xadd` — a few cycles slower than a plain store,
/// but sound under any producer layout and prevents lost-update races
/// if a counter is ever written from a non-owning thread by mistake.
#[inline(always)]
pub fn inc(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

#[inline(always)]
pub fn add(a: &AtomicU64, n: u64) {
    a.fetch_add(n, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_construct() {
        let c = Counters::new();
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 0);
        assert_eq!(c.tcp.conn_open.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inc_works() {
        let c = Counters::new();
        inc(&c.eth.rx_pkts);
        inc(&c.eth.rx_pkts);
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cross_thread_inc_correct_under_contention() {
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(Counters::new());
        let producers: Vec<_> = (0..4)
            .map(|_| {
                let c = Arc::clone(&c);
                thread::spawn(move || {
                    for _ in 0..25_000 {
                        inc(&c.eth.rx_pkts);
                    }
                })
            })
            .collect();
        for p in producers {
            p.join().unwrap();
        }
        // Would fail if inc() were load-modify-store (lost increments).
        assert_eq!(c.eth.rx_pkts.load(Ordering::Relaxed), 100_000);
    }

    #[test]
    fn counters_group_alignment() {
        // Ensure each group is its own cacheline.
        assert_eq!(std::mem::align_of::<EthCounters>(), 64);
        assert_eq!(std::mem::align_of::<IpCounters>(), 64);
        assert_eq!(std::mem::align_of::<TcpCounters>(), 64);
        assert_eq!(std::mem::align_of::<PollCounters>(), 64);
    }

    #[test]
    fn a2_new_counters_exist_and_zero() {
        let c = Counters::new();
        // eth additions
        assert_eq!(c.eth.rx_drop_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_drop_unknown_ethertype.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_arp.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.tx_arp.load(Ordering::Relaxed), 0);
        // ip additions
        assert_eq!(c.ip.rx_drop_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_bad_version.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_bad_hl.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_not_ours.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_unsupported_proto.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_tcp.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_icmp.load(Ordering::Relaxed), 0);
    }
}
