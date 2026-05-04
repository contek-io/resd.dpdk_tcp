//! Linux kernel TCP max-sustained-throughput runner — comparator arm
//! for spec §11.2.
//!
//! Drives the W × C grid against a live kernel-TCP sink peer using
//! `std::net::TcpStream` (kernel sockets, no DPDK). For each bucket,
//! opens `C` persistent connections, pumps W-byte writes round-robin
//! for T = 60 s after a 10 s warmup, and reports sustained goodput.
//!
//! # Why this exists
//!
//! The dpdk_net maxtp arm in `dpdk_maxtp.rs` measures our user-space
//! TCP stack at sustained-throughput. The mTCP arm in `mtcp.rs` is
//! stubbed (Plan A AMI rebuild blocked on libmtcp / gcc 13). To still
//! produce a meaningful comparison row, we land a kernel-TCP arm
//! here; it shares the peer (`linux-tcp-sink` on port 10002 in the
//! bench-pair script's [6/12] step) so the only delta vs dpdk_net is
//! the client-side stack.
//!
//! # Measurement contract
//!
//! Goodput is measured as bytes-actually-sent in the window (the sum
//! of `write` return values during `[t_warmup_end, t_warmup_end + T]`)
//! divided by T, in bits/sec. We don't have the dpdk_net stack's
//! `snd_una` introspection, so "ACKed bytes" maps to "bytes the
//! kernel sent + that didn't error" — which under TCP semantics
//! converges to the same number across a 60 s window because the
//! socket's send buffer + in-flight cap is small relative to the
//! window.
//!
//! Packet rate (`pps`) is harder to read from user-space without
//! `getsockopt(TCP_INFO)` parsing; we leave it at 0.0 in the sample
//! and document this in the `tx_ts_mode` field as `n/a`. bench-report
//! filters by mode so the missing pps column doesn't pollute
//! cross-stack pivots — see `dimensions_json.tx_ts_mode = "n/a"` for
//! Linux maxtp rows.
//!
//! # Multi-connection pump loop
//!
//! Mirrors `dpdk_maxtp::pump_round_robin`'s shape: for `C > 1` we open
//! `C` connections up-front and round-robin writes across them in the
//! inner hot loop. Each connection is a separate kernel socket so the
//! kernel handles per-conn TX-side fan-out itself.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::maxtp::{Bucket, MaxtpSample};

/// Connect deadline for the initial kernel-TCP handshake. Same shape
/// as bench-vs-linux's `linux_kernel.rs::CONNECT_TIMEOUT`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-bucket configuration.
pub struct LinuxMaxtpCfg {
    pub bucket: Bucket,
    /// Warmup window (mirrors dpdk_maxtp; spec §11.2: 10 s default).
    pub warmup: Duration,
    /// Measurement window (spec §11.2: 60 s default).
    pub duration: Duration,
    /// Peer IPv4 (host byte order, parity with dpdk path).
    pub peer_ip_host_order: u32,
    /// Peer TCP port. Bench-nightly script puts `linux-tcp-sink` on
    /// port 10002; CLI lets the operator override.
    pub peer_port: u16,
    /// Payload template. Caller allocates once at bucket entry so the
    /// inner loop doesn't allocate.
    pub payload: Vec<u8>,
}

/// One bucket's raw measurement product.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BucketRun {
    /// Sustained-rate sample over the measurement window (bps + pps).
    /// `pps` is 0.0 — we don't read `getsockopt(TCP_INFO).tcpi_segs_out`
    /// in this version; bench-report can filter Linux rows out of pps
    /// pivots via `dimensions_json.tx_ts_mode == "n/a"`.
    pub sample: MaxtpSample,
    /// Bytes that the kernel accepted across the measurement window
    /// (sum of successful write return values). The "goodput" of this
    /// run before T-normalisation; surfaced separately for assertion
    /// in tests.
    pub bytes_sent_in_window: u64,
}

/// Open `C` persistent connections to the peer. Each carries
/// `TCP_NODELAY = on` to mirror the dpdk_net path's per-segment send
/// behaviour (no Nagle coalescing).
pub fn open_persistent_connections(
    peer_ip_host_order: u32,
    peer_port: u16,
    conn_count: u64,
) -> anyhow::Result<Vec<TcpStream>> {
    if conn_count == 0 {
        anyhow::bail!("linux_maxtp: conn_count must be > 0");
    }
    let octets = peer_ip_host_order.to_be_bytes();
    let addr = SocketAddrV4::new(Ipv4Addr::from(octets), peer_port);
    let mut out = Vec::with_capacity(conn_count as usize);
    for i in 0..conn_count {
        let stream = TcpStream::connect_timeout(&addr.into(), CONNECT_TIMEOUT)
            .with_context(|| format!("linux_maxtp: open connection {i} to {addr}"))?;
        // TCP_NODELAY: parity with dpdk_net's per-segment send. The
        // peer (linux-tcp-sink) also sets NODELAY, so neither side
        // coalesces.
        stream
            .set_nodelay(true)
            .with_context(|| format!("linux_maxtp: set_nodelay on conn {i}"))?;
        // Non-blocking writes so a transient peer-window-full on one
        // conn doesn't stall the round-robin pump. We treat
        // `WouldBlock` exactly the way `dpdk_maxtp` treats `Ok(0)`:
        // skip to the next conn in the round.
        stream
            .set_nonblocking(true)
            .with_context(|| format!("linux_maxtp: set_nonblocking on conn {i}"))?;
        out.push(stream);
    }
    Ok(out)
}

/// Drive one bucket on the Linux side.
///
/// Sequence (parity with `dpdk_maxtp::run_bucket`):
/// 1. Pump writes for `warmup`, no sampling.
/// 2. Pump writes for `duration`, accumulating bytes-sent.
/// 3. Return `MaxtpSample::from_window(bytes_sent, 0, elapsed_ns)`.
pub fn run_bucket(cfg: &LinuxMaxtpCfg, conns: &mut [TcpStream]) -> anyhow::Result<BucketRun> {
    if conns.len() as u64 != cfg.bucket.conn_count {
        anyhow::bail!(
            "linux_maxtp: conns.len() = {} does not match bucket.conn_count = {}",
            conns.len(),
            cfg.bucket.conn_count
        );
    }
    if cfg.payload.len() as u64 != cfg.bucket.write_bytes {
        anyhow::bail!(
            "linux_maxtp: payload.len() = {} does not match bucket.write_bytes = {}",
            cfg.payload.len(),
            cfg.bucket.write_bytes
        );
    }
    if cfg.duration.as_nanos() == 0 {
        anyhow::bail!("linux_maxtp: measurement duration must be > 0");
    }

    // Warmup — pump until the warmup deadline, ignore the byte total.
    let warmup_deadline = Instant::now() + cfg.warmup;
    let _ = pump_round_robin(conns, &cfg.payload, warmup_deadline)
        .context("linux_maxtp warmup phase")?;

    // Measurement window — capture (t_start, t_end) tightly around the
    // pump call so the elapsed-ns denominator matches the byte
    // numerator's window exactly.
    let t_measure_start = Instant::now();
    let measure_deadline = t_measure_start + cfg.duration;
    let bytes_sent_in_window = pump_round_robin(conns, &cfg.payload, measure_deadline)
        .context("linux_maxtp measurement phase")?;
    let t_measure_end = Instant::now();

    let elapsed_ns = t_measure_end
        .saturating_duration_since(t_measure_start)
        .as_nanos() as u64;
    // 60 s window in ns < 2^36, comfortably inside u64.

    let sample = MaxtpSample::from_window(bytes_sent_in_window, 0, elapsed_ns);

    Ok(BucketRun {
        sample,
        bytes_sent_in_window,
    })
}

/// Pump writes round-robin across `conns` until `deadline` fires.
/// Returns the total bytes the kernel accepted on successful `write`
/// calls. Errors only on a non-`WouldBlock` write failure — TCP
/// reset, broken pipe, etc.
fn pump_round_robin(
    conns: &mut [TcpStream],
    payload: &[u8],
    deadline: Instant,
) -> anyhow::Result<u64> {
    if conns.is_empty() {
        anyhow::bail!("linux_maxtp: pump_round_robin: conns is empty");
    }
    let mut total: u64 = 0;
    // Per-conn discard buffer for draining echo bytes. The peer
    // (echo-server / linux-tcp-sink — currently both echo) writes
    // bytes back; without draining, the kernel TCP recv buffer fills
    // and the peer's `read()` blocks because its send buffer fills
    // too, which transitively backpressures our `write()` to ~0
    // throughput. Draining here on every round keeps the recv
    // buffer empty so the peer can keep accepting our writes.
    let mut discard = vec![0u8; 65536];
    // Mirror dpdk_maxtp's M1 micro-optimisation: only do the
    // between-conn deadline check on the C=1 path (otherwise the
    // outer-loop check fires often enough).
    let check_between_conns = conns.len() == 1;
    loop {
        if Instant::now() >= deadline {
            return Ok(total);
        }
        for stream in conns.iter_mut() {
            // Drain inbound (non-blocking) before writing — each
            // pass drains whatever the peer has echoed back since
            // the previous round. WouldBlock = nothing pending,
            // continue to write. EOF / hard error from read =
            // log + treat as no-op (the write below will catch
            // a genuine connection problem with a clearer error).
            let mut drained = 0;
            while drained < discard.len() * 4 {
                match stream.read(&mut discard) {
                    Ok(0) => break, // EOF — peer closed
                    Ok(n) => {
                        drained += n;
                        if n < discard.len() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break, // surface via subsequent write
                }
            }
            // Write payload.
            match stream.write(payload) {
                Ok(n) => {
                    total = total.saturating_add(n as u64);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // Peer-window full / send buffer full for this
                    // conn — skip to next conn (parity with
                    // dpdk_maxtp's Ok(0) handling).
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {
                    // EINTR — retry on the next round, no byte
                    // counted yet.
                }
                Err(e) => {
                    anyhow::bail!("linux_maxtp: write failed: {e}");
                }
            }
            if check_between_conns && Instant::now() >= deadline {
                return Ok(total);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};

    /// `open_persistent_connections` rejects `conn_count == 0` without
    /// hitting the network.
    #[test]
    fn open_rejects_zero_conn_count() {
        // 127.0.0.1:1 — never reached because conn_count == 0 short-
        // circuits.
        let err = open_persistent_connections(0x7f00_0001, 1, 0).unwrap_err();
        assert!(err.to_string().contains("conn_count must be > 0"));
    }

    /// `run_bucket` rejects mismatched `conns.len()` / `bucket.conn_count`.
    #[test]
    fn run_bucket_rejects_conn_count_mismatch() {
        // We build a real (unused) TcpStream so `conns` isn't empty.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect((IpAddr::V4(Ipv4Addr::LOCALHOST), port)).unwrap();
        let mut conns = vec![stream];

        let cfg = LinuxMaxtpCfg {
            bucket: Bucket::new(64, 4), // expects C=4
            warmup: Duration::from_millis(10),
            duration: Duration::from_millis(10),
            peer_ip_host_order: 0x7f00_0001,
            peer_port: port,
            payload: vec![0u8; 64],
        };
        let err = run_bucket(&cfg, &mut conns).unwrap_err();
        assert!(
            err.to_string().contains("does not match bucket.conn_count"),
            "expected conn_count mismatch error, got: {err}"
        );
    }

    /// `run_bucket` rejects a payload whose length doesn't match
    /// `bucket.write_bytes`.
    #[test]
    fn run_bucket_rejects_payload_length_mismatch() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect((IpAddr::V4(Ipv4Addr::LOCALHOST), port)).unwrap();
        let mut conns = vec![stream];

        let cfg = LinuxMaxtpCfg {
            bucket: Bucket::new(64, 1),
            warmup: Duration::from_millis(10),
            duration: Duration::from_millis(10),
            peer_ip_host_order: 0x7f00_0001,
            peer_port: port,
            payload: vec![0u8; 32], // wrong size
        };
        let err = run_bucket(&cfg, &mut conns).unwrap_err();
        assert!(
            err.to_string().contains("does not match bucket.write_bytes"),
            "expected write_bytes mismatch error, got: {err}"
        );
    }

    /// `run_bucket` rejects `duration == 0` (would divide by zero in
    /// `MaxtpSample::from_window`).
    #[test]
    fn run_bucket_rejects_zero_duration() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect((IpAddr::V4(Ipv4Addr::LOCALHOST), port)).unwrap();
        let mut conns = vec![stream];

        let cfg = LinuxMaxtpCfg {
            bucket: Bucket::new(64, 1),
            warmup: Duration::from_millis(10),
            duration: Duration::ZERO, // bad
            peer_ip_host_order: 0x7f00_0001,
            peer_port: port,
            payload: vec![0u8; 64],
        };
        let err = run_bucket(&cfg, &mut conns).unwrap_err();
        assert!(
            err.to_string().contains("measurement duration must be > 0"),
            "expected zero-duration error, got: {err}"
        );
    }

    /// End-to-end sanity check on a loopback peer: open two connections
    /// to a TcpListener that drains in a background thread, pump for
    /// ~50 ms, confirm the run produced a non-zero byte total and
    /// non-zero throughput, and cleaned up cleanly.
    ///
    /// This is a unit test (not behind `#[ignore]`) because it only
    /// uses loopback + a self-contained drain thread — no external
    /// peer or DPDK dependency.
    #[test]
    fn run_bucket_sanity_against_loopback_drain() {
        use std::io::Read;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(false).unwrap();

        // Background thread: accept up to 2 connections and drain them
        // until they close. Stops when `done` is set or an accept
        // errors.
        let done = Arc::new(AtomicBool::new(false));
        let done_t = done.clone();
        let bg = thread::spawn(move || {
            // Accept up to 2 conns (matches C=2 below).
            let mut sinks: Vec<TcpStream> = Vec::new();
            listener.set_nonblocking(true).unwrap();
            let accept_deadline = Instant::now() + Duration::from_secs(2);
            while sinks.len() < 2 && Instant::now() < accept_deadline {
                match listener.accept() {
                    Ok((s, _)) => {
                        s.set_nonblocking(true).ok();
                        sinks.push(s);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
            // Drain until `done` is set.
            let mut buf = vec![0u8; 8192];
            while !done_t.load(Ordering::Relaxed) {
                let mut any = false;
                for s in sinks.iter_mut() {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => {}
                        Ok(_) => any = true,
                    }
                }
                if !any {
                    thread::sleep(Duration::from_micros(100));
                }
            }
        });

        // Open 2 conns to the loopback peer.
        let mut conns = open_persistent_connections(0x7f00_0001, port, 2).unwrap();
        assert_eq!(conns.len(), 2);

        // Run a tiny bucket: W=64, C=2, warmup 10ms, measurement 50ms.
        let cfg = LinuxMaxtpCfg {
            bucket: Bucket::new(64, 2),
            warmup: Duration::from_millis(10),
            duration: Duration::from_millis(50),
            peer_ip_host_order: 0x7f00_0001,
            peer_port: port,
            payload: vec![0u8; 64],
        };
        let run = run_bucket(&cfg, &mut conns).unwrap();
        assert!(
            run.bytes_sent_in_window > 0,
            "expected non-zero bytes sent in window"
        );
        assert!(
            run.sample.goodput_bps > 0.0,
            "expected non-zero goodput, got {}",
            run.sample.goodput_bps
        );
        assert_eq!(run.sample.pps, 0.0, "Linux arm leaves pps at 0.0");

        // Tear down — drop conns + signal bg drain thread to exit.
        drop(conns);
        done.store(true, Ordering::Relaxed);
        // Best-effort join (give it 1 s).
        let _ = bg.join();
    }
}
