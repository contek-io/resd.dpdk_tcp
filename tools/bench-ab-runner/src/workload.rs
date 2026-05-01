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
use dpdk_net_core::error::Error;
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

    // Carry-forward byte counter. Any Readable event that arrives while
    // we're still retrying partial-accept in the SEND phase contributes
    // bytes here so the RECEIVE phase starts from a non-zero budget
    // instead of losing them to the next `poll_once`'s scratch clear.
    // See `drain_and_accumulate_readable` for the full explanation.
    let mut carry_forward: usize = 0;

    // Warmup: discard samples.
    for i in 0..args.warmup {
        request_response_once(
            engine,
            conn,
            &request,
            args.response_bytes,
            tsc_hz,
            &mut carry_forward,
        )
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
            &mut carry_forward,
        )
        .with_context(|| format!("measurement iteration {i}"))?;
        samples.push(rtt_ns as f64);
    }
    Ok(samples)
}

/// Open a TCP connection to the peer and drive `poll_once` until the
/// `InternalEvent::Connected` event for our handle arrives.
///
/// `EngineConfig::default().gateway_mac` is the all-zero MAC, which
/// `Engine::connect_with_opts` (engine.rs:4169-4171) treats as "gateway
/// ARP not yet resolved" and rejects with `Error::PeerUnreachable`. The
/// gateway MAC is learned asynchronously via `maybe_probe_gateway_mac`,
/// which fires from inside `poll_once` (engine.rs:5501-5527). So on a
/// fresh Engine the first `connect` call almost always fails until
/// we've driven at least one `poll_once` that triggered an ARP
/// request-reply round trip.
///
/// We retry `connect` on `PeerUnreachable` with an intervening
/// `poll_once` until the connect succeeds or `CONNECT_TIMEOUT` elapses.
/// Any other error bails immediately — `PeerUnreachable` is the only
/// error that "may resolve itself if we poll longer".
fn open_connection(
    engine: &Engine,
    peer_ip: u32,
    peer_port: u16,
) -> anyhow::Result<ConnHandle> {
    // `local_port_hint = 0` → engine assigns an ephemeral port.
    let handle = retry_on_peer_unreachable(
        CONNECT_TIMEOUT,
        std::time::Duration::from_millis(10),
        || engine.connect(peer_ip, peer_port, 0),
        || {
            // PeerUnreachable: gateway MAC not yet learned. Drive the
            // poll loop so the engine's ARP probe fires; retry.
            engine.poll_once();
        },
    )?;

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

/// Retry `op` on `Error::PeerUnreachable` (ARP not yet resolved),
/// running `between` and sleeping `sleep_dur` between tries. Any other
/// error is returned immediately. Bounded by `timeout`; on timeout,
/// returns a synthetic anyhow error so the caller can produce a
/// domain-specific message.
///
/// Generic over the op's Ok type + callback. Factored out of
/// `open_connection` so the retry discipline is unit-testable without
/// a live Engine (see `retry_on_peer_unreachable_*` tests below).
fn retry_on_peer_unreachable<T, F, B>(
    timeout: std::time::Duration,
    sleep_dur: std::time::Duration,
    mut op: F,
    mut between: B,
) -> anyhow::Result<T>
where
    F: FnMut() -> Result<T, Error>,
    B: FnMut(),
{
    let start = std::time::Instant::now();
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(Error::PeerUnreachable(_)) => {
                between();
                if start.elapsed() > timeout {
                    anyhow::bail!(
                        "gateway ARP did not resolve within {:?}",
                        timeout
                    );
                }
                std::thread::sleep(sleep_dur);
            }
            Err(e) => anyhow::bail!("engine.connect failed: {e:?}"),
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
///    are enqueued (or we hit the timeout). Any Readable events that
///    fire while we're still retrying are folded into `carry_forward`
///    rather than dropped.
/// 3. Drive `poll_once()` and drain the event queue, accumulating
///    Readable payload bytes (seeded with `carry_forward`) until we've
///    seen `response_bytes`.
/// 4. Sample `rdtsc()` at t1.
/// 5. Convert `(t1 - t0)` to ns via the cached `tsc_hz`.
///
/// `carry_forward` is threaded through from the caller so any excess
/// bytes that arrived during a prior iteration's send phase (or leftover
/// from a prior receive phase that over-read) don't accrue against this
/// iteration's RTT sample but do count toward the response budget.
fn request_response_once(
    engine: &Engine,
    conn: ConnHandle,
    request: &[u8],
    response_bytes: usize,
    tsc_hz: u64,
    carry_forward: &mut usize,
) -> anyhow::Result<u64> {
    let t0 = dpdk_net_core::clock::rdtsc();

    // --- Send phase ---------------------------------------------------
    // `send_bytes` can partial-accept under send-buffer / peer-window
    // pressure. Drain the unsent tail with `poll_once` (which triggers
    // ACK processing and opens the window) + retry. If the peer
    // half-closes mid-iteration, `send_bytes` transitions `state !=
    // Established` and returns `InvalidConnHandle`; catch that and
    // surface the iteration-relative cause instead of the bare debug
    // format.
    let send_deadline = std::time::Instant::now() + RTT_TIMEOUT;
    let mut sent: usize = 0;
    while sent < request.len() {
        let remaining = &request[sent..];
        let accepted = match engine.send_bytes(conn, remaining) {
            Ok(n) => n,
            Err(Error::InvalidConnHandle(_)) => {
                anyhow::bail!(
                    "peer closed connection mid-iteration \
                     (InvalidConnHandle from send_bytes after {sent}/{} bytes)",
                    request.len()
                );
            }
            Err(e) => anyhow::bail!("send_bytes failed: {e:?}"),
        };
        sent += accepted as usize;
        if sent < request.len() {
            engine.poll_once();
            // Fold any Readable bytes that arrived during this
            // partial-accept retry into `carry_forward`. Dropping them
            // here would lose data: `deliver_readable` moves segments
            // into the conn's `delivered_segments`, and the next
            // `poll_once` calls `delivered_segments.clear()` which
            // drops the MbufHandle refcounts and releases the bytes.
            *carry_forward = carry_forward.saturating_add(
                drain_and_accumulate_readable(engine, conn)?,
            );
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
    // Seed the byte budget with anything we accumulated during the
    // send phase (or carried over from the previous iteration's
    // over-read). Zero it out immediately so a subsequent iteration
    // starts from a clean slate — the response-side drain below
    // refills the slot only if it over-reads.
    let recv_deadline = std::time::Instant::now() + RTT_TIMEOUT;
    let mut got: usize = *carry_forward;
    *carry_forward = 0;
    while got < response_bytes {
        engine.poll_once();
        got += drain_and_accumulate_readable(engine, conn)?;
        if got < response_bytes && std::time::Instant::now() >= recv_deadline {
            anyhow::bail!(
                "recv timeout ({}/{} bytes)",
                got,
                response_bytes
            );
        }
    }
    // If this iteration over-read (peer pipelined a response larger
    // than `response_bytes`), park the excess in `carry_forward` so
    // the next iteration starts with a non-zero budget instead of
    // double-counting it in its own RTT.
    if got > response_bytes {
        *carry_forward = got - response_bytes;
    }

    let t1 = dpdk_net_core::clock::rdtsc();
    Ok(tsc_delta_to_ns(t0, t1, tsc_hz))
}

/// Drain events; accumulate Readable-payload bytes on `conn`, fail on
/// Error/Closed for `conn`. Returns total new bytes seen.
///
/// Called from BOTH the send phase (where the bytes go into
/// `carry_forward`) AND the receive phase (where they go into `got`).
/// Unifying the two paths means there is exactly one place the
/// "Readable notification was for N bytes that are now sitting in the
/// conn's delivered_segments; count them" rule lives.
///
/// WHY accumulate in send phase: the initial A10 implementation
/// dropped Readable events here on the theory that the data was
/// preserved in the receive buffer for a future Readable event. That
/// was wrong. Reading `deliver_readable` (engine.rs:4005-4131) +
/// `poll_once`'s clear of `delivered_segments` (engine.rs:1936) shows
/// the next poll releases the MbufHandle refcount and the bytes are
/// gone. Any Readable event that the runner sees during a
/// partial-accept retry in send-phase describes bytes that MUST be
/// counted now — the subsequent `poll_once` will clear them.
fn drain_and_accumulate_readable(
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
    use std::cell::Cell;

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

    // --- C1 regression tests --------------------------------------------
    //
    // These document the retry-on-PeerUnreachable discipline inside
    // `open_connection`. They exercise the extracted helper with a mock
    // op closure instead of a live Engine, so they don't need a bound
    // NIC or an EAL init.

    #[test]
    fn retry_on_peer_unreachable_succeeds_after_retries() {
        // Two consecutive PeerUnreachable errors, then success. The
        // `between` callback should have fired exactly twice (once per
        // PeerUnreachable).
        let counter = Cell::new(0u32);
        let between_calls = Cell::new(0u32);
        let result = retry_on_peer_unreachable(
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(1),
            || {
                let i = counter.get();
                counter.set(i + 1);
                if i < 2 {
                    Err(Error::PeerUnreachable(0x0A00_0001))
                } else {
                    Ok(42u64)
                }
            },
            || between_calls.set(between_calls.get() + 1),
        );
        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.get(), 3);
        assert_eq!(between_calls.get(), 2);
    }

    #[test]
    fn retry_on_peer_unreachable_bails_on_other_errors() {
        // Non-PeerUnreachable errors must bail immediately without
        // retrying. Counter stays at 1 (one op call, no retry).
        let counter = Cell::new(0u32);
        let result = retry_on_peer_unreachable::<u64, _, _>(
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(1),
            || {
                counter.set(counter.get() + 1);
                Err(Error::TooManyConns)
            },
            || {},
        );
        assert!(result.is_err());
        assert_eq!(counter.get(), 1);
    }

    #[test]
    fn retry_on_peer_unreachable_times_out() {
        // Always-fail op with a tiny timeout; helper must return error
        // after roughly `timeout` elapsed (not loop forever).
        let result = retry_on_peer_unreachable::<u64, _, _>(
            std::time::Duration::from_millis(10),
            std::time::Duration::from_millis(1),
            || Err(Error::PeerUnreachable(0x0A00_0001)),
            || {},
        );
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("gateway ARP did not resolve"),
            "timeout error message should mention gateway ARP: {msg}"
        );
    }
}
