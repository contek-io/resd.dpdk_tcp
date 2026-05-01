//! Linux kernel TCP path: plain `std::net::TcpStream`, measured with
//! `std::time::Instant::now()`. Mode A baseline for comparison against
//! `dpdk_net`.
//!
//! # Why blocking `read_exact` / `write_all`
//!
//! The workload is strictly synchronous request-response with small
//! (128 B) payloads and `TCP_NODELAY` enabled. Blocking I/O is the
//! kernel equivalent of bench-e2e's `request_response_attributed`
//! inner loop — one send, wait for the full echo, stamp exit. Non-
//! blocking would add epoll overhead to the RTT we're trying to
//! measure.
//!
//! # Socket options
//!
//! Uses `std::net::TcpStream` with `set_nodelay(true)` for per-write
//! latency (disables Nagle). `TCP_QUICKACK` is NOT set today —
//! delayed ACK on the kernel side may add ~40 ms to the first echo;
//! this is documented in spec §8 as a known skew vs dpdk_net's
//! per-segment ACK. If a future task wants quick-ack on the kernel
//! path, use `libc::setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, ...)`
//! with Linux-only cfg guards.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

/// Connect deadline for the initial kernel-TCP handshake. Same shape
/// as bench-e2e's `CONNECT_TIMEOUT`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-iteration RTT ceiling against wedge. Same shape as bench-e2e's
/// `RTT_TIMEOUT`.
const RTT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect to `(peer_ip, peer_port)` via the kernel TCP path. Returns
/// a stream with `TCP_NODELAY` set — callers flip `set_read_timeout` /
/// `set_write_timeout` afterwards per-call.
///
/// `peer_ip` is in host byte order to match bench-e2e's convention
/// (the dpdk path uses host-order u32 throughout).
pub fn connect(peer_ip_host_order: u32, peer_port: u16) -> anyhow::Result<TcpStream> {
    let octets = peer_ip_host_order.to_be_bytes();
    let addr = SocketAddrV4::new(Ipv4Addr::from(octets), peer_port);
    let stream = TcpStream::connect_timeout(&addr.into(), CONNECT_TIMEOUT)?;
    // Disable Nagle so small requests don't stall waiting for an ACK
    // before shipping. bench-e2e's echo-server has TCP_NODELAY on the
    // listen + accept sockets; we flip it on the client side too.
    stream.set_nodelay(true)?;
    // Match the per-iteration deadline used in the measurement loop.
    stream.set_read_timeout(Some(RTT_TIMEOUT))?;
    stream.set_write_timeout(Some(RTT_TIMEOUT))?;
    Ok(stream)
}

/// One measured request-response round-trip over a kernel TCP
/// connection. Mirrors bench-e2e's `request_response_attributed` in
/// shape but without attribution buckets — the kernel path has no
/// equivalent of TSC-at-tx-sched / HW-TS-at-NIC-RX that bench-e2e
/// reads from the dpdk engine.
///
/// `request` is written verbatim, `response_bytes` is the exact
/// number of bytes expected back (echo contract).
pub fn request_response_once(
    stream: &mut TcpStream,
    request: &[u8],
    response_bytes: usize,
) -> anyhow::Result<u64> {
    let t0 = Instant::now();
    stream.write_all(request)?;
    let mut buf = vec![0u8; response_bytes];
    stream.read_exact(&mut buf)?;
    let rtt = t0.elapsed();
    Ok(rtt.as_nanos() as u64)
}

/// Run `warmup + iterations` round-trips and return raw RTT samples in
/// nanoseconds (warmup discarded).
pub fn run_rtt_workload(
    stream: &mut TcpStream,
    request_bytes: usize,
    response_bytes: usize,
    warmup: u64,
    iterations: u64,
) -> anyhow::Result<Vec<f64>> {
    let request = vec![0u8; request_bytes];

    for i in 0..warmup {
        request_response_once(stream, &request, response_bytes)
            .map_err(|e| anyhow::anyhow!("linux_kernel warmup iter {i}: {e}"))?;
    }

    let mut samples: Vec<f64> = Vec::with_capacity(iterations as usize);
    for i in 0..iterations {
        let rtt_ns = request_response_once(stream, &request, response_bytes)
            .map_err(|e| anyhow::anyhow!("linux_kernel measurement iter {i}: {e}"))?;
        samples.push(rtt_ns as f64);
    }
    Ok(samples)
}

