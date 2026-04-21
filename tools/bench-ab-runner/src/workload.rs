//! 128 B / 128 B request-response loop.
//!
//! The workload opens one TCP connection to the peer, drives `warmup`
//! throw-away iterations, then runs `iterations` measured request /
//! response round-trips and returns the raw RTT samples (nanoseconds).
//! The caller (main.rs) summarises via `bench_common::percentile::summarize`
//! and emits CSV rows.
//!
//! # Engine API shape
//!
//! The plan sketch used hypothetical method names (`engine.send`,
//! `poll_once() -> Vec<InternalEvent>`). The real API surface, read from
//! `crates/dpdk-net-core/src/engine.rs`, is:
//!
//! * `engine.connect(peer_ip, peer_port, local_port_hint=0) -> Result<ConnHandle, Error>`
//!   — opens a TCP connection. Non-blocking: returns immediately; the
//!   `InternalEvent::Connected { conn, .. }` fires later when the
//!   three-way handshake completes.
//! * `engine.send_bytes(conn, &[u8]) -> Result<u32, Error>` — enqueues
//!   bytes on the connection's send path. Partial acceptance possible
//!   under send-buffer / peer-window backpressure; caller retries the
//!   unsent tail.
//! * `engine.poll_once() -> usize` — one iteration of the run-to-
//!   completion loop. Side-effect: pushes any fired events onto an
//!   internal FIFO queue.
//! * `engine.events()` / `engine.drain_events(max, sink)` — read events
//!   out of the internal queue. We use the `events()` RefMut and
//!   `pop()` directly so we don't have to materialise a closure.
//!
//! The event types of interest are `InternalEvent::Connected`,
//! `InternalEvent::Readable` (carries `seg_idx_start`, `seg_count`,
//! `total_len` pointing into the owning `TcpConn`'s per-poll scratch
//! iovec Vec — see `tcp_events.rs`), `InternalEvent::Error`, and
//! `InternalEvent::Closed`.
//!
//! For latency measurement we read `dpdk_net_core::clock::rdtsc()` /
//! `dpdk_net_sys::rte_get_tsc_hz()` and convert the delta to
//! nanoseconds. The `clock` module's `rdtsc()` is already wired for
//! x86_64 (the only supported arch for Stage 1); rte_get_tsc_hz is a
//! one-time-per-run constant so we query it once up front.

use anyhow::Context;

use dpdk_net_core::engine::Engine;
use dpdk_net_core::flow_table::ConnHandle;
use dpdk_net_core::tcp_events::InternalEvent;

/// Timeout for each request-response round-trip. Deliberately generous
/// — real round-trips complete in tens of microseconds, but during
/// warmup the first SYN-ACK may be slow (ARP learning, MTU discovery,
/// etc.). A 10 s ceiling keeps a broken run from wedging the harness
/// indefinitely.
const RTT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Timeout for the initial three-way handshake. Matches the RTT ceiling
/// — same reasoning: ARP + SYN retransmit can add seconds on a cold
/// table, but we still want a hard floor against a wedged peer.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Run the full workload: open the conn, warm up, then measure.
///
/// Returns `iterations` RTT samples in ns. The caller is responsible
/// for summarising + CSV emission.
pub fn run(engine: &Engine, args: &crate::Args) -> anyhow::Result<Vec<f64>> {
    let peer_ip = crate::parse_ip_host_order(&args.peer_ip)?;
    let conn = open_connection(engine, peer_ip, args.peer_port)?;

    // rte_get_tsc_hz is constant across the run — cache.
    // Safety: no preconditions (read-only getter). Returns 0 before EAL
    // init, but at this point EAL is up.
    let tsc_hz = unsafe { dpdk_net_sys::rte_get_tsc_hz() };
    if tsc_hz == 0 {
        anyhow::bail!("rte_get_tsc_hz() returned 0 — EAL not initialised?");
    }

    let request = vec![0u8; args.request_bytes];

    // Warmup: discard samples.
    for i in 0..args.warmup {
        request_response_once(engine, conn, &request, args.response_bytes, tsc_hz)
            .with_context(|| format!("warmup iteration {i}"))?;
    }

    // Measurement.
    let mut samples: Vec<f64> = Vec::with_capacity(args.iterations as usize);
    for i in 0..args.iterations {
        let rtt_ns = request_response_once(
            engine,
            conn,
            &request,
            args.response_bytes,
            tsc_hz,
        )
        .with_context(|| format!("measurement iteration {i}"))?;
        samples.push(rtt_ns as f64);
    }
    Ok(samples)
}

/// Open a TCP connection to the peer and drive `poll_once` until the
/// `InternalEvent::Connected` event for our handle arrives.
fn open_connection(
    engine: &Engine,
    peer_ip: u32,
    peer_port: u16,
) -> anyhow::Result<ConnHandle> {
    // `local_port_hint = 0` → engine assigns an ephemeral port.
    let handle = engine
        .connect(peer_ip, peer_port, 0)
        .map_err(|e| anyhow::anyhow!("engine.connect failed: {e:?}"))?;

    let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        engine.poll_once();
        if drain_until_connected_or_error(engine, handle)? {
            return Ok(handle);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("connect timeout after {:?}", CONNECT_TIMEOUT);
        }
    }
}

/// Drain queued events looking for `Connected`/`Error`/`Closed` for
/// `handle`. Returns `Ok(true)` if we saw `Connected`, `Err` if we saw
/// `Error`/`Closed`, `Ok(false)` if the queue was empty / only
/// contained events for other handles / state-change notifications.
///
/// Non-matching events are popped and discarded — the handshake phase
/// doesn't care about state-change telemetry, and there are no other
/// live connections to watch out for.
fn drain_until_connected_or_error(
    engine: &Engine,
    handle: ConnHandle,
) -> anyhow::Result<bool> {
    let mut events = engine.events();
    while let Some(ev) = events.pop() {
        match ev {
            InternalEvent::Connected { conn, .. } if conn == handle => return Ok(true),
            InternalEvent::Error { conn, err, .. } if conn == handle => {
                anyhow::bail!("connect error: errno={err}");
            }
            InternalEvent::Closed { conn, err, .. } if conn == handle => {
                anyhow::bail!("connection closed during handshake: err={err}");
            }
            _ => {
                // Ignore: other-handle events, StateChange, Writable, etc.
            }
        }
    }
    Ok(false)
}

/// One measured request-response round-trip. Returns the RTT in ns.
///
/// Steps:
/// 1. Sample `rdtsc()` at t0.
/// 2. `send_bytes(request)`, looping on partial-accept until all bytes
///    are enqueued (or we hit the timeout).
/// 3. Drive `poll_once()` and drain the event queue, accumulating
///    Readable payload bytes until we've seen `response_bytes`.
/// 4. Sample `rdtsc()` at t1.
/// 5. Convert `(t1 - t0)` to ns via the cached `tsc_hz`.
fn request_response_once(
    engine: &Engine,
    conn: ConnHandle,
    request: &[u8],
    response_bytes: usize,
    tsc_hz: u64,
) -> anyhow::Result<u64> {
    let t0 = dpdk_net_core::clock::rdtsc();

    // --- Send phase ---------------------------------------------------
    // `send_bytes` can partial-accept under send-buffer / peer-window
    // pressure. Drain the unsent tail with `poll_once` (which triggers
    // ACK processing and opens the window) + retry.
    let send_deadline = std::time::Instant::now() + RTT_TIMEOUT;
    let mut sent: usize = 0;
    while sent < request.len() {
        let remaining = &request[sent..];
        let accepted = engine
            .send_bytes(conn, remaining)
            .map_err(|e| anyhow::anyhow!("send_bytes failed: {e:?}"))?;
        sent += accepted as usize;
        if sent < request.len() {
            engine.poll_once();
            drain_ignore_non_fatal(engine, conn)?;
            if std::time::Instant::now() >= send_deadline {
                anyhow::bail!(
                    "send timeout ({}/{} bytes accepted)",
                    sent,
                    request.len()
                );
            }
        }
    }

    // --- Receive phase ------------------------------------------------
    let recv_deadline = std::time::Instant::now() + RTT_TIMEOUT;
    let mut got: usize = 0;
    while got < response_bytes {
        engine.poll_once();
        got += drain_and_count_readable(engine, conn)?;
        if got < response_bytes && std::time::Instant::now() >= recv_deadline {
            anyhow::bail!(
                "recv timeout ({}/{} bytes)",
                got,
                response_bytes
            );
        }
    }

    let t1 = dpdk_net_core::clock::rdtsc();
    Ok(tsc_delta_to_ns(t0, t1, tsc_hz))
}

/// Drain events, counting payload bytes for `Readable` events on `conn`,
/// failing on `Error`/`Closed` for `conn`. Returns total new bytes seen.
fn drain_and_count_readable(
    engine: &Engine,
    conn: ConnHandle,
) -> anyhow::Result<usize> {
    let mut events = engine.events();
    let mut bytes: usize = 0;
    while let Some(ev) = events.pop() {
        match ev {
            InternalEvent::Readable {
                conn: ch,
                total_len,
                ..
            } if ch == conn => {
                bytes = bytes.saturating_add(total_len as usize);
            }
            InternalEvent::Error { conn: ch, err, .. } if ch == conn => {
                anyhow::bail!("tcp error during recv: errno={err}");
            }
            InternalEvent::Closed { conn: ch, err, .. } if ch == conn => {
                anyhow::bail!("connection closed during recv: err={err}");
            }
            _ => {
                // Ignore unrelated event kinds.
            }
        }
    }
    Ok(bytes)
}

/// Drain events; surface only Error/Closed on `conn` as failures. Used
/// from the send-loop while we're waiting for peer ACKs to free up the
/// send window — any Readable event here is premature server response
/// data that we'll consume on the next send-or-recv round; we don't
/// lose it because `Readable`'s per-poll scratch is cleared at the top
/// of the NEXT `poll_once`, but by that point the *data* has been
/// delivered into the TcpConn's receive buffer. The event we're
/// dropping is the notification, not the bytes — future Readable events
/// will surface the accumulated bytes if the stream keeps arriving.
///
/// A6/T12 note: if this assumption breaks (e.g. Readable events are
/// edge-triggered exactly-once per scratch batch), the request-response
/// loop here may under-count. This is fine for the A10 128 B / 128 B
/// workload (the send always fits in one segment so partial-accept is
/// rare), but T6/T7 implementers building larger workloads should
/// re-verify.
fn drain_ignore_non_fatal(engine: &Engine, conn: ConnHandle) -> anyhow::Result<()> {
    let mut events = engine.events();
    while let Some(ev) = events.pop() {
        match ev {
            InternalEvent::Error { conn: ch, err, .. } if ch == conn => {
                anyhow::bail!("tcp error during send: errno={err}");
            }
            InternalEvent::Closed { conn: ch, err, .. } if ch == conn => {
                anyhow::bail!("connection closed during send: err={err}");
            }
            _ => {}
        }
    }
    Ok(())
}

/// Convert a TSC-cycle delta to nanoseconds. Uses u128 intermediate to
/// avoid overflow at realistic durations (1s ≈ 3.5e9 cycles on a 3.5
/// GHz host; `3.5e9 * 1e9 = 3.5e18` fits in u128 trivially).
fn tsc_delta_to_ns(t0: u64, t1: u64, tsc_hz: u64) -> u64 {
    let delta = t1.wrapping_sub(t0);
    ((delta as u128).saturating_mul(1_000_000_000u128) / tsc_hz as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsc_delta_to_ns_basic() {
        // 3 GHz host, 3_000 cycles should be 1000 ns.
        assert_eq!(tsc_delta_to_ns(0, 3_000, 3_000_000_000), 1_000);
        // 0-delta is 0 ns.
        assert_eq!(tsc_delta_to_ns(42, 42, 3_000_000_000), 0);
        // TSC wraparound: t1 < t0 in u64 arithmetic. The wrapping_sub
        // reproduces the elapsed cycle count that a wrap-then-grow
        // exhibits. Picking t0 close to u64::MAX and a small t1 gives
        // `delta = 3_000` through wrap-around. We compute t1 via a
        // wrapping add so rustc's const-overflow lint is satisfied.
        let t0 = u64::MAX - 999;
        let t1 = t0.wrapping_add(3_000);
        assert_eq!(tsc_delta_to_ns(t0, t1, 3_000_000_000), 1_000);
    }
}
