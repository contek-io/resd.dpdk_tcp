//! A7 Task 8: test-only FFI surface.
//!
//! Every entry point in this module is gated behind the `test-server`
//! cargo feature and emitted into `include/dpdk_net_test.h` by a second
//! cbindgen pass (see `build.rs`). None of these symbols land in the
//! production `include/dpdk_net.h` — the production cbindgen config
//! explicitly excludes them, and the `test_header_excluded` integration
//! test enforces the split across both feature combinations.
//!
//! Pump discipline (spec A7 §pump): every entry except `set_time_ns`
//! and `accept_next` runs `pump_until_quiescent` before returning so
//! packetdrill script steps observe a stack that has drained its TX
//! ring and fired every currently-due timer.

use crate::api::*;
use dpdk_net_core::clock;
use dpdk_net_core::test_tx_intercept;

/// Opaque-ish listen-socket handle. Matches the core-crate
/// `dpdk_net_core::test_server::ListenHandle = u32` layout but is a
/// distinct type on the FFI surface so its identity is independent of
/// the Rust internal type.
pub type dpdk_net_listen_handle_t = u32;

/// A single TX frame handed back by `dpdk_net_test_drain_tx_frames`.
/// `buf` points into a thread-local scratch area retained until the
/// next `drain_tx_frames` call on the same thread; callers must copy
/// the bytes out before the next drain.
#[repr(C)]
pub struct dpdk_net_test_frame_t {
    pub buf: *const u8,
    pub len: usize,
}

thread_local! {
    /// Scratch for `dpdk_net_test_drain_tx_frames`: owns the drained
    /// `Vec<Vec<u8>>` so the `buf` pointers we hand back remain valid
    /// until the NEXT drain call (the thread-local overwrites its
    /// contents). Matches the `valid-until-next-call` lifetime
    /// convention the production `dpdk_net_poll` readable-seg pointers
    /// use.
    static LAST_DRAIN: std::cell::RefCell<Vec<Vec<u8>>>
        = const { std::cell::RefCell::new(Vec::new()) };
}

// --- FFI entry points -------------------------------------------------

/// Set the thread-local virtual clock (ns). Non-monotonic values panic.
/// Does NOT pump — the caller typically follows `set_time_ns` with an
/// `inject_frame` or another FFI entry that will pump.
#[no_mangle]
pub extern "C" fn dpdk_net_test_set_time_ns(ns: u64) {
    clock::set_virt_ns(ns);
}

/// Inject a single Ethernet-framed frame into the engine's RX pipeline
/// and run pumps to quiescence. Returns 0 on success, `-EINVAL` on a
/// null/zero-length input or null engine, `-ENOMEM` on mempool
/// exhaustion.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_inject_frame(
    engine: *mut dpdk_net_engine,
    buf: *const u8,
    len: usize,
) -> i32 {
    let Some(eng) = super::engine_from_raw_mut(engine) else {
        return -libc::EINVAL;
    };
    if buf.is_null() || len == 0 {
        return -libc::EINVAL;
    }
    let slice = std::slice::from_raw_parts(buf, len);
    match eng.inject_rx_frame(slice) {
        Ok(()) => {
            super::pump_until_quiescent(eng);
            0
        }
        Err(_) => -libc::ENOMEM,
    }
}

/// Drain every TX-intercept frame queued since the last call, writing
/// up to `max` descriptors into `out`. Returns the number written.
/// Each `buf` pointer is backed by the thread-local scratch Vec and
/// remains valid until the next `dpdk_net_test_drain_tx_frames` call
/// on the same thread.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_drain_tx_frames(
    _engine: *mut dpdk_net_engine,
    out: *mut dpdk_net_test_frame_t,
    max: usize,
) -> usize {
    if out.is_null() || max == 0 {
        return 0;
    }
    let frames = test_tx_intercept::drain_tx_frames();
    LAST_DRAIN.with(|cell| {
        let mut slot = cell.borrow_mut();
        *slot = frames;
        let n = slot.len().min(max);
        for i in 0..n {
            *out.add(i) = dpdk_net_test_frame_t {
                buf: slot[i].as_ptr(),
                len: slot[i].len(),
            };
        }
        n
    })
}

/// Create a listen slot on (engine's primary local IP, `local_port`).
/// Returns `0` on error (null engine / duplicate slot / id overflow),
/// otherwise a 1-based handle.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_listen(
    engine: *mut dpdk_net_engine,
    local_port: u16,
) -> dpdk_net_listen_handle_t {
    let Some(eng) = super::engine_from_raw_mut(engine) else {
        return 0;
    };
    let local_ip = eng.our_ip();
    let rc = eng.listen(local_ip, local_port).unwrap_or(0);
    super::pump_until_quiescent(eng);
    rc
}

/// Pop the 1-deep accept queue for the given listen handle. Returns
/// `u64::MAX` when nothing is queued or the handle is unknown.
/// Does NOT pump — accept_next is a no-side-effect lookup and callers
/// typically invoke it between other pumped operations.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_accept_next(
    engine: *mut dpdk_net_engine,
    listen: dpdk_net_listen_handle_t,
) -> dpdk_net_conn_t {
    let Some(eng) = super::engine_from_raw_mut(engine) else {
        return u64::MAX;
    };
    eng.accept_next(listen)
        .map(|h| h as dpdk_net_conn_t)
        .unwrap_or(u64::MAX)
}

/// Thin re-wrapper around `dpdk_net_connect` that pumps on success.
/// Returns `u64::MAX` on failure, the connection handle on success.
/// `dst_ip` is in host byte order; the ABI `dpdk_net_connect_opts_t`
/// expects network-byte-order ints, so we convert at the boundary.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_connect(
    engine: *mut dpdk_net_engine,
    dst_ip: u32,
    dst_port: u16,
    opts: *const dpdk_net_connect_opts_t,
) -> dpdk_net_conn_t {
    if engine.is_null() {
        return u64::MAX;
    }
    // Build a local opts copy that respects the (ip, port) from the
    // caller even if `opts` was null or zeroed. A null `opts` maps to
    // "zero everything but the target tuple".
    let mut o: dpdk_net_connect_opts_t = if opts.is_null() {
        dpdk_net_connect_opts_t {
            peer_addr: 0,
            peer_port: 0,
            local_addr: 0,
            local_port: 0,
            connect_timeout_ms: 0,
            idle_keepalive_sec: 0,
            rack_aggressive: false,
            rto_no_backoff: false,
            tlp_pto_min_floor_us: 0,
            tlp_pto_srtt_multiplier_x100: 0,
            tlp_skip_flight_size_gate: false,
            tlp_max_consecutive_probes: 0,
            tlp_skip_rtt_sample_gate: false,
        }
    } else {
        *opts
    };
    o.peer_addr = dst_ip.to_be();
    o.peer_port = dst_port.to_be();

    let mut out: dpdk_net_conn_t = u64::MAX;
    let rc = super::dpdk_net_connect(engine, &o as *const _, &mut out as *mut _);
    if rc == 0 && out != u64::MAX {
        super::pump_until_quiescent_raw(engine);
        out
    } else {
        u64::MAX
    }
}

/// Thin re-wrapper around `dpdk_net_send` that pumps on success.
/// Returns bytes accepted (non-negative) or a negative errno from
/// `dpdk_net_send`.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_send(
    engine: *mut dpdk_net_engine,
    h: dpdk_net_conn_t,
    buf: *const u8,
    len: usize,
) -> isize {
    // `dpdk_net_send` takes `u32 len`; cap at u32::MAX to avoid
    // truncation surprises.
    let len32: u32 = if len > u32::MAX as usize {
        u32::MAX
    } else {
        len as u32
    };
    let rc = super::dpdk_net_send(engine, h, buf, len32);
    if rc >= 0 {
        super::pump_until_quiescent_raw(engine);
    }
    rc as isize
}

/// Drain at most one `dpdk_net_poll` event batch, concatenating every
/// READABLE event's scatter-gather segments targeting handle `h` into
/// `out` (up to `max` bytes). Returns bytes written, 0 if no READABLE
/// event is waiting for this handle, or `-EINVAL` on null inputs.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_recv(
    engine: *mut dpdk_net_engine,
    h: dpdk_net_conn_t,
    out: *mut u8,
    max: usize,
) -> isize {
    if engine.is_null() || out.is_null() || max == 0 {
        return -libc::EINVAL as isize;
    }
    let mut evs = std::mem::MaybeUninit::<[dpdk_net_event_t; 16]>::uninit();
    let n = super::dpdk_net_poll(
        engine,
        evs.as_mut_ptr() as *mut dpdk_net_event_t,
        16,
        0,
    );
    if n <= 0 {
        return 0;
    }
    let evs = std::slice::from_raw_parts(
        evs.as_ptr() as *const dpdk_net_event_t,
        n as usize,
    );
    let mut written: usize = 0;
    for ev in evs {
        // `dpdk_net_event_kind_t` is `#[repr(u32)]` + `#[derive(Copy, Clone)]`,
        // so we can compare the discriminant idiomatically — no raw-ptr
        // read required.
        if ev.kind as u32 != dpdk_net_event_kind_t::DPDK_NET_EVT_READABLE as u32 {
            continue;
        }
        if ev.conn != h {
            continue;
        }
        let r = &ev.u.readable;
        if r.segs.is_null() || r.n_segs == 0 {
            continue;
        }
        let segs = std::slice::from_raw_parts(r.segs, r.n_segs as usize);
        for seg in segs {
            if written >= max {
                return written as isize;
            }
            let want = (max - written).min(seg.len as usize);
            if want == 0 {
                continue;
            }
            std::ptr::copy_nonoverlapping(seg.base, out.add(written), want);
            written += want;
        }
    }
    written as isize
}

/// Thin re-wrapper around `dpdk_net_close` that pumps on success.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_close(
    engine: *mut dpdk_net_engine,
    h: dpdk_net_conn_t,
    flags: u32,
) -> i32 {
    let rc = super::dpdk_net_close(engine, h, flags);
    if rc == 0 {
        super::pump_until_quiescent_raw(engine);
    }
    rc
}

/// A8.5 T8: thin re-wrapper around `dpdk_net_shutdown` that pumps on
/// success. The packetdrill shim calls this so the FIN emitted by a
/// `SHUT_RDWR` request is flushed into the TX intercept ring before
/// the script's next `> F.` expectation is matched. `SHUT_RD` /
/// `SHUT_WR` bypass the pump (no state change).
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_shutdown(
    engine: *mut dpdk_net_engine,
    h: dpdk_net_conn_t,
    how: i32,
) -> i32 {
    let rc = super::dpdk_net_shutdown(engine, h, how);
    if rc == 0 {
        super::pump_until_quiescent_raw(engine);
    }
    rc
}

/// A8 T15 (S2): look up a connection's peer IP and port by handle. Host
/// byte order for both (same convention as `EngineConfig::local_ip`).
/// Writes into the caller's out-params on success and returns `0`;
/// returns `-EINVAL` (as `i32`) on null engine / unknown handle, leaving
/// out-params untouched. The packetdrill shim uses this after
/// `accept_next` to surface the peer tuple back through the syscall
/// `accept()` sockaddr — without this, `run_syscall_accept` fires its
/// `is_equal_port(socket->live.remote.port, htons(port))` assertion on
/// every server-side script.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_test_conn_peer(
    engine: *mut dpdk_net_engine,
    h: dpdk_net_conn_t,
    peer_ip_out: *mut u32,
    peer_port_out: *mut u16,
) -> i32 {
    let Some(eng) = super::engine_from_raw_mut(engine) else {
        return -libc::EINVAL;
    };
    // `h` is u64 at the FFI boundary but u32 internally.
    if h > u32::MAX as u64 {
        return -libc::EINVAL;
    }
    let handle = h as u32;
    // Scope the RefMut: we only need a read-only snapshot of the
    // 4-tuple, but flow_table() returns RefMut so we drop it promptly.
    let ft = {
        let flow_table = eng.flow_table();
        let Some(conn) = flow_table.get(handle) else {
            return -libc::EINVAL;
        };
        conn.four_tuple()
    };
    if !peer_ip_out.is_null() {
        *peer_ip_out = ft.peer_ip;
    }
    if !peer_port_out.is_null() {
        *peer_port_out = ft.peer_port;
    }
    0
}
