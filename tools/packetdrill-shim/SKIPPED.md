# A7 packetdrill-shim skip list

This file enumerates every `.pkt` script excluded from the runnable
set, one line per script. `corpus_ligurio.rs` parses this file and
asserts every skipped script has an entry here (orphan-skip check).

Format: `<path relative to third_party/packetdrill-testcases> — <reason>`

## ligurio corpus

### Runnable-no-crash (A8.5 T9 — spec §1.1 G crash-safety corpus)

The "runnable-no-crash" verdict pins scripts whose pass criterion is
*engine-crash-safety* under unexpected peer behavior (bad ICMP,
malformed syscall arguments, PMTU events). Each script has been
soak-tested 100× on the T9 shim without triggering any SIGSEGV /
SIGABRT / signal kill. Exit code 1 is acceptable because the engine
does not model the behaviors under test (ICMP ingress / PMTU state /
EFAULT for NULL buffers) and therefore reliably assertion-fails on
wire-shape or syscall-return mismatch; the gate catches only signal
kills (exit > 128), which are the true crash-safety regressions.

  - testcases/tcp/ICMP/icmp-all-types.pkt — A8.5 T9: ICMP ingress not modeled (exit 1 on wire-shape mismatch), soak-tested 100x with 0 crashes
  - testcases/tcp/mtu_probe/basic-v4.pkt — A8.5 T9: PMTU probe machinery not modeled (exit 1 on init/wire-shape), soak-tested 100x with 0 crashes
  - testcases/tcp/pmtu_discovery/pmtu-10pkt.pkt — A8.5 T9: PMTU discovery semantics not modeled (exit 1 on wire-shape mismatch), soak-tested 100x with 0 crashes
  - testcases/tcp/syscall_bad_arg/fastopen-invalid-buf-ptr.pkt — A8.5 T9: negative-syscall-argument error shapes not modeled (exit 1 on init/syscall-return mismatch), soak-tested 100x with 0 crashes
  - testcases/tcp/syscall_bad_arg/sendmsg-empty-iov.pkt — A8.5 T9: negative-syscall-argument error shapes not modeled (exit 1 on init/syscall-return mismatch), soak-tested 100x with 0 crashes
  - testcases/tcp/syscall_bad_arg/syscall-invalid-buf-ptr.pkt — A8.5 T9: negative-syscall-argument error shapes not modeled (exit 1 on init/syscall-return mismatch), soak-tested 100x with 0 crashes

### Runnable-but-broken (T15 pragmatic floor; revisit in A8+)

Per T15 reality-check: the A7 shim binary cannot currently pass any of
the ligurio corpus scripts end-to-end. Every corpus `.pkt` maps to one
of a small number of engine/shim gaps that are out of scope for T15
("Do NOT modify the shim patches during T15"). LIGURIO_RUNNABLE_COUNT
is pinned at 0; each script below is classified as
`skipped-untranslatable` with a category tag. A8+ work will move
scripts out of these buckets as the underlying gap is closed.

Dry-run evidence that drove this floor:
- 0/122 scripts exit 0 under the A7 shim.
- 75/122 scripts source `scripts/defaults.sh`, which requires root
  sysctl privileges and a Linux kernel environment (the shim runs in
  user space with no kernel sysctl knobs).
- 42/122 scripts time out on the first expected outbound packet
  because the shim's SYN->SYN-ACK round-trip does not currently drain
  server-emitted frames through `dpdk_net_shim_drain_next` for scripts
  that drive the engine via `listen()` + injected SYN (the inject->
  engine path works at the Rust level — see `shim_inject_drain_roundtrip`
  — but wiring the packetdrill main loop's `netdev_receive` call to
  the engine's tx-intercept queue needs A8 follow-up).
- The rest fail on TCP-option-order drift (engine emits
  `<mss,sackOK,TS,wscale,nop>`; corpus scripts expect
  `<mss,nop,wscale,sackOK,TS>`), unimplemented socket options
  (SO_ZEROCOPY, TCP_INFO, SO_TIMESTAMPING, TCP_USER_TIMEOUT,
  TCP_NOTSENT_LOWAT, TCP_MD5SIG, TCP_INQ), unimplemented syscalls
  (epoll_*, splice, pipe, sendfile), or unimplemented engine features
  (SACK shift, fast/early/limited retransmit, PMTU probe, ECN).

#### Server-side lifecycle — shim SYN->SYN-ACK round-trip gap (A8+)

  - testcases/tcp/blocking/blocking-accept.pkt — requires scripts/defaults.sh init and blocking-accept timing deltas (A8+)
  - testcases/tcp/blocking/blocking-accept_freebsd.pkt — requires scripts/defaults.sh init and blocking-accept timing deltas (A8+)
  - testcases/tcp/blocking/blocking-connect.pkt — requires scripts/defaults.sh init and blocking-accept timing deltas (A8+)
  - testcases/tcp/blocking/blocking-read.pkt — requires scripts/defaults.sh init and blocking-accept timing deltas (A8+)
  - testcases/tcp/blocking/blocking-read_freebsd.pkt — requires scripts/defaults.sh init and blocking-accept timing deltas (A8+)
  - testcases/tcp/blocking/blocking-write.pkt — requires scripts/defaults.sh init and blocking-accept timing deltas (A8+)
  - testcases/tcp/close/close-last-ack-lost.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-local-close-then-remote-fin.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-on-syn-sent.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-read-data-fin.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-remote-fin-then-close.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-unread-data-rst.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-write-data-rst.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/listen/listen-incoming-no-tcp-flags.pkt — server-side edge behavior (FreeBSD silent-drop on no-flags) needs engine parity (A8+)
  - testcases/tcp/reset/rst-non-synchronized.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-syn-sent.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-sync-est-fin-wait-1.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-sync-est-fin-wait-2.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-sync-est-time-wait.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-synchronized-established.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst_sync_close_wait.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/shutdown/shutdown-double-shut-wr.pkt — half-close semantics (SHUT_WR) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-rd-close.pkt — half-close semantics (SHUT_RD) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-rd-wr-close.pkt — half-close semantics (SHUT_RD/SHUT_WR) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-rd.pkt — half-close semantics (SHUT_RD) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-rdwr-close.pkt — SHUT_RDWR probes post-shutdown read=0/write=EPIPE (half-close); spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-rdwr-send-queue-ack-close.pkt — SHUT_RDWR probes post-shutdown read=0/write=EPIPE (half-close); spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-rdwr-write-queue-close.pkt — SHUT_RDWR probes post-shutdown read=0/write=EPIPE (half-close); spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-rdwr.pkt — SHUT_RDWR probes post-shutdown read=0/write=EPIPE (half-close); spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-recv-after-shut-rd.pkt — half-close semantics (SHUT_RD) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-wr-close.pkt — half-close semantics (SHUT_WR) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - testcases/tcp/shutdown/shutdown-wr.pkt — half-close semantics (SHUT_WR) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close

#### Syscalls returning EOPNOTSUPP in the A7 shim

  - testcases/tcp/epoll/epoll_in_edge.pkt — epoll_* returns EOPNOTSUPP in A7 shim (A8+ to wire)
  - testcases/tcp/epoll/epoll_out_edge.pkt — epoll_* returns EOPNOTSUPP in A7 shim (A8+ to wire)
  - testcases/tcp/epoll/epoll_out_edge_default_notsent_lowat.pkt — epoll_* returns EOPNOTSUPP in A7 shim (A8+ to wire)
  - testcases/tcp/epoll/epoll_out_edge_notsent_lowat.pkt — epoll_* returns EOPNOTSUPP in A7 shim (A8+ to wire)
  - testcases/tcp/splice/tcp_splice_loop_test.pkt — splice/pipe returns EOPNOTSUPP in A7 shim
  - testcases/tcp/sendfile/sendfile-simple.pkt — sendfile not wired in A7 test-FFI (needs backing fd plumbing)
  - testcases/tcp/ioctl/ioctl-siocinq-fin.pkt — ioctl SIOCINQ/SIOCOUTQ not plumbed through test-FFI

#### Unimplemented TCP / socket options

  - testcases/tcp/md5/md5-only-on-client-ack.pkt — TCP_MD5SIG option not implemented in engine
  - testcases/tcp/inq/client.pkt — TCP_INQ (SIOCINQ-style queue length) not plumbed through test-FFI
  - testcases/tcp/inq/server.pkt — TCP_INQ (SIOCINQ-style queue length) not plumbed through test-FFI
  - testcases/tcp/notsent_lowat/notsent-lowat-default.pkt — TCP_NOTSENT_LOWAT not implemented; also needs sysctl env
  - testcases/tcp/notsent_lowat/notsent-lowat-setsockopt.pkt — TCP_NOTSENT_LOWAT not implemented; also needs sysctl env
  - testcases/tcp/notsent_lowat/notsent-lowat-sysctl.pkt — TCP_NOTSENT_LOWAT not implemented; also needs sysctl env
  - testcases/tcp/tcp_info/tcp-info-last_data_recv.pkt — TCP_INFO structure not populated by engine yet
  - testcases/tcp/tcp_info/tcp-info-rwnd-limited.pkt — TCP_INFO structure not populated by engine yet
  - testcases/tcp/tcp_info/tcp-info-sndbuf-limited.pkt — TCP_INFO structure not populated by engine yet
  - testcases/tcp/timestamping/client-only-last-byte.pkt — SO_TIMESTAMPING / ancillary-data path not in test-FFI
  - testcases/tcp/timestamping/partial.pkt — SO_TIMESTAMPING / ancillary-data path not in test-FFI
  - testcases/tcp/timestamping/server.pkt — SO_TIMESTAMPING / ancillary-data path not in test-FFI
  - testcases/tcp/user_timeout/user-timeout-probe.pkt — TCP_USER_TIMEOUT not implemented
  - testcases/tcp/user_timeout/user_timeout.pkt — TCP_USER_TIMEOUT not implemented
  - testcases/tcp/zerocopy/basic.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/batch.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/client.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/closed.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/epoll_edge.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/epoll_exclusive.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/epoll_oneshot.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/fastopen-client.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/fastopen-server.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/maxfrags.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - testcases/tcp/zerocopy/small.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented

#### Unimplemented engine behavior (congestion control, recovery, etc.)

  - testcases/tcp/cwnd_moderation/cwnd-moderation-disorder-no-moderation.pkt — Congestion-window moderation heuristics not modeled
  - testcases/tcp/cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt — Congestion-window moderation heuristics not modeled
  - testcases/tcp/early_retransmit/early-retransmit.pkt — Early-retransmit (RFC 5827) not in engine
  - testcases/tcp/fast_recovery/fast-recovery.pkt — Fast-recovery state machine (RFC 6582) not in engine
  - testcases/tcp/fast_retransmit/fr-4pkt-sack-bsd.pkt — Fast-retransmit dupACK heuristic not in engine
  - testcases/tcp/limited_transmit/limited-transmit-no-sack.pkt — Limited-transmit (RFC 3042) not in engine
  - testcases/tcp/limited_transmit/limited-transmit-sack.pkt — Limited-transmit (RFC 3042) not in engine
  - testcases/tcp/sack/sack-route-refresh-ip-tos.pkt — SACK shift/coalesce logic not modeled in engine yet
  - testcases/tcp/sack/sack-shift-sacked-2-6-8-3-9-nofack.pkt — SACK shift/coalesce logic not modeled in engine yet
  - testcases/tcp/sack/sack-shift-sacked-7-3-4-8-9-fack.pkt — SACK shift/coalesce logic not modeled in engine yet
  - testcases/tcp/sack/sack-shift-sacked-7-5-6-8-9-fack.pkt — SACK shift/coalesce logic not modeled in engine yet
  - testcases/tcp/slow_start/slow-start.pkt — Slow-start exponential growth observability not modeled
  - testcases/tcp/undo/undo-fr-acks-dropped-then-dsack.pkt — Loss-undo logic (RFC 5682 / DSACK undo) not modeled
  - testcases/tcp/validate/validate-established-no-flags.pkt — Segment-validation edge cases (no-flags) not modeled
  - testcases/tcp/rto/retransmission_timeout.pkt — RTO retransmit cadence not exercised via shim yet
  - testcases/tcp/init_rto/init_rto_passive_open.pkt — Initial-RTO server-side timing not exercised via shim yet
  - testcases/tcp/initial_window/iw10-base-case.pkt — Initial-window IW10 sizing not modeled
  - testcases/tcp/initial_window/iw10-short-response.pkt — Initial-window IW10 sizing not modeled
  - testcases/tcp/receiver_rtt/rcv-rtt-with-timestamps-new.pkt — Receiver-side RTT sample extraction not modeled
  - testcases/tcp/receiver_rtt/rcv-rtt-without-timestamps-new.pkt — Receiver-side RTT sample extraction not modeled
  - testcases/tcp/ts_recent/fin_tsval.pkt — PAWS / ts_recent handling depends on timestamp-option parity
  - testcases/tcp/ts_recent/invalid_ack.pkt — PAWS / ts_recent handling depends on timestamp-option parity
  - testcases/tcp/ts_recent/reset_tsval.pkt — PAWS / ts_recent handling depends on timestamp-option parity
  - testcases/tcp/time_wait/time-wait.pkt — TIME_WAIT reuse / 2*MSL semantics not exercised via shim yet
  - testcases/tcp/ecn/ecn-uses-ect0.pkt — ECN (ECT/CE bits) behavior not modeled

#### MSS / TCP_MAXSEG socket-option + client-mode plumbing

Note: A8.5 Task 5 aligned TX TCP option emission to Linux canonical order
(`<MSS, NOP+WScale, SACKP, TS>`). Post-reorder, each of these scripts still
fails for a *different*, deeper reason than option-order drift; reasons below
reflect the real blocker observed after the reorder.

  - testcases/tcp/connect/http-get-nonblocking-ts.pkt — fcntl(O_NONBLOCK) flag-shape drift (expected 2 vs actual 2050); pre-connect fcntl plumbing
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-client-ts.pkt — client-mode `connect()` not driven by shim: SYN never emitted, scripted packet times out
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-client.pkt — client-mode `connect()` not driven by shim: SYN never emitted, scripted packet times out
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server-advmss-ipv4.pkt — SYN-ACK emits TS unconditionally (script expects no TS when client did not offer it); needs negotiation mirroring
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server-advmss-ts-ipv4.pkt — engine-side WScale mirrors buffer-derived shift, not peer-offered shift (script expects ws=6 to mirror peer, engine emits ws=3)
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server-ts.pkt — TS-clock sync gap: live outbound TS val never aligns with scripted ecr, so RX matcher can't infer echo
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server.pkt — requires scripts/defaults.sh host-env (init command exits 127)
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server_freebsd.pkt — SYN-ACK emits TS/SACKP unconditionally (script expects neither when client did not offer); needs negotiation mirroring
  - testcases/tcp/mss/mss-setsockopt-tcp_maxseg-client.pkt — requires scripts/defaults.sh host-env (init command exits 127)
  - testcases/tcp/mss/mss-setsockopt-tcp_maxseg-client_freebsd.pkt — TCP_MAXSEG setsockopt not plumbed: getsockopt returns 0 instead of user-configured value
  - testcases/tcp/mss/mss-setsockopt-tcp_maxseg-server.pkt — requires scripts/defaults.sh host-env (init command exits 127)
  - testcases/tcp/mss/mss-setsockopt-tcp_maxseg-server_freebsd.pkt — TCP_MAXSEG setsockopt not plumbed: getsockopt returns 0 instead of user-configured value

#### Other (wire shape / middleware-layer behavior)

Note: the ligurio scripts under `ICMP/`, `mtu_probe/basic-v4.pkt`,
`pmtu_discovery/`, and `syscall_bad_arg/` were migrated to the
"runnable-no-crash" verdict in A8.5 T9 (G crash-safety corpus). They
no longer appear here — the pass criterion is "no SIGSEGV / SIGABRT /
signal kill", not exit-0 end-to-end. See the "## Runnable-no-crash"
section below for details.

  - testcases/tcp/gro/gro-mss-option.pkt — GRO-specific wire-shape expectations not modeled
  - testcases/tcp/mtu_probe/basic-v6.pkt — PMTU probe machinery not modeled (also needs raw-socket/route hooks)
  - testcases/tcp/nagle/https_client.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - testcases/tcp/nagle/sendmsg_msg_more.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - testcases/tcp/nagle/sockopt_cork_nodelay.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - testcases/tcp/eor/no-coalesce-large.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - testcases/tcp/eor/no-coalesce-retrans.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - testcases/tcp/eor/no-coalesce-small.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - testcases/tcp/eor/no-coalesce-subsequent.pkt — MSG_EOR / no-coalesce boundary semantics not modeled

## shivansh corpus

### Runnable (empirically verified on A8 T15 S2 shim)

The shivansh TCP-IP regression suite is a 47-script subset borrowed
from Google packetdrill and ligurio, stand-alone (no `defaults.sh`
dependency), SPDX/MIT-licensed per-script. Five scripts exit 0
end-to-end on the current shim (same A8 T15 S2 unlock as the ligurio
runnable set). Pinned at `SHIVANSH_RUNNABLE_COUNT = 5`.

  - socket-api/listen/listen-incoming-syn-ack.pkt — A8 T16: listener rejects SYN-ACK with RST, then accepts retry SYN
  - socket-api/listen/listen-incoming-ack.pkt — A8 T16: listener rejects bare ACK with RST, then accepts retry SYN
  - socket-api/listen/listen-incoming-rst.pkt — A8 T16: listener drops unsolicited RST then accepts retry SYN
  - socket-api/listen/listen-incoming-syn-rst.pkt — A8 T16: listener drops SYN|RST combo then accepts retry SYN
  - socket-api/close/simultaneous-close.pkt — A8 T16: simultaneous-close FIN exchange after accept

### Server-side lifecycle — shim SYN->SYN-ACK round-trip gap (A8+)

  - socket-api/blocking/blocking-accept.pkt — blocking-accept EAGAIN vs shim scheduling; accept-timing deltas (A8+)
  - socket-api/blocking/blocking-read.pkt — blocking-accept EAGAIN vs shim scheduling; accept-timing deltas (A8+)
  - socket-api/close/close-last-ack-lost.pkt — close() tests all require server-side accept path (A8+)
  - socket-api/close/close-read-data-fin.pkt — close() tests all require server-side accept path (A8+)
  - socket-api/close/close-unread-data-rst.pkt — close() tests all require server-side accept path (A8+)
  - socket-api/close/close-write-data-rst.pkt — close() tests all require server-side accept path (A8+)
  - socket-api/listen/listen-incoming-no-tcp-flags.pkt — server-side edge behavior (FreeBSD silent-drop on no-flags) needs engine parity (A8+)
  - socket-api/shutdown/shutdown-rd.pkt — half-close semantics (SHUT_RD) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - socket-api/shutdown/shutdown-rdwr.pkt — SHUT_RDWR probes post-shutdown read=0/write=EPIPE (half-close); spec §6.4 AD-A8.5-shutdown-no-half-close
  - socket-api/shutdown/shutdown-wr.pkt — half-close semantics (SHUT_WR) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - tcp-fsm/reset/rst-non-synchronized.pkt — RST tests depend on server-side accept path or wire-option parity
  - tcp-fsm/reset/rst-syn-sent.pkt — RST tests depend on server-side accept path or wire-option parity
  - tcp-fsm/reset/rst-sync-est-fin-wait-1.pkt — RST tests depend on server-side accept path or wire-option parity
  - tcp-fsm/reset/rst-sync-est-fin-wait-2.pkt — RST tests depend on server-side accept path or wire-option parity
  - tcp-fsm/reset/rst-sync-est-time-wait.pkt — RST tests depend on server-side accept path or wire-option parity
  - tcp-fsm/reset/rst-synchronized-established.pkt — RST tests depend on server-side accept path or wire-option parity
  - tcp-fsm/reset/rst_sync_close_wait.pkt — RST tests depend on server-side accept path or wire-option parity

### Unimplemented engine behavior (congestion control, recovery, etc.)

  - socket-api/init_rto/init_rto_passive_open.pkt — Initial-RTO server-side timing not exercised via shim yet
  - tcp-fsm/initial_window/iw10-base-case.pkt — Initial-window IW10 sizing not modeled
  - tcp-fsm/initial_window/iw10-short-response.pkt — Initial-window IW10 sizing not modeled
  - tcp-mechanisms/early_retransmit/early-retransmit.pkt — Early-retransmit (RFC 5827) not in engine
  - tcp-mechanisms/fast_recovery/fast-recovery.pkt — Fast-recovery state machine (RFC 6582) not in engine
  - tcp-mechanisms/fast_retransmit/fr-4pkt-sack-bsd.pkt — Fast-retransmit dupACK heuristic not in engine
  - tcp-mechanisms/fr-undo/undo-fr-acks-dropped-then-dsack.pkt — Loss-undo logic (RFC 5682 / DSACK undo) not modeled
  - tcp-mechanisms/paws/paws-old-seq.pkt — PAWS / ts_recent handling depends on timestamp-option parity
  - tcp-mechanisms/paws/paws-old-timestamp.pkt — PAWS / ts_recent handling depends on timestamp-option parity
  - tcp-mechanisms/pmtu_discovery/pmtu-10pkt.pkt — PMTU discovery semantics not modeled
  - tcp-mechanisms/receiver_rtt/rcv-rtt-with-timestamps-new.pkt — Receiver-side RTT sample extraction not modeled
  - tcp-mechanisms/receiver_rtt/rcv-rtt-without-timestamps-new.pkt — Receiver-side RTT sample extraction not modeled
  - tcp-mechanisms/rto/retransmission-timeout.pkt — RTO retransmit cadence not exercised via shim yet
  - tcp-mechanisms/slow_read_attack/slow-read.pkt — Slow-read-attack scenario needs receive-window-squeeze engine plumbing (A8+)
  - tcp-mechanisms/slow_start/slow-start.pkt — Slow-start exponential growth observability not modeled

### MSS / TCP_MAXSEG socket-option + client-mode plumbing

Note: A8.5 Task 5 aligned TX TCP option emission to Linux canonical order
(`<MSS, NOP+WScale, SACKP, TS>`). Post-reorder, each of these scripts still
fails for a *different*, deeper reason than option-order drift; reasons below
reflect the real blocker observed after the reorder.

  - socket-api/connect/http-get-nonblocking-ts.pkt — fcntl(O_NONBLOCK) flag-shape drift (expected 2 vs actual 2050); pre-connect fcntl plumbing
  - tcp-fsm/mss/mss-getsockopt-tcp_maxseg-client-ts.pkt — client-mode `connect()` not driven by shim: SYN never emitted, scripted packet times out
  - tcp-fsm/mss/mss-getsockopt-tcp_maxseg-client.pkt — client-mode `connect()` not driven by shim: SYN never emitted, scripted packet times out
  - tcp-fsm/mss/mss-getsockopt-tcp_maxseg-server-advmss-ipv4.pkt — SYN-ACK emits TS unconditionally (script expects no TS when client did not offer it); needs negotiation mirroring
  - tcp-fsm/mss/mss-getsockopt-tcp_maxseg-server-advmss-ts-ipv4.pkt — engine-side WScale mirrors buffer-derived shift, not peer-offered shift (script expects ws=6 to mirror peer, engine emits ws=3)
  - tcp-fsm/mss/mss-getsockopt-tcp_maxseg-server-ts.pkt — TS-clock sync gap: live outbound TS val never aligns with scripted ecr, so RX matcher can't infer echo
  - tcp-fsm/mss/mss-getsockopt-tcp_maxseg-server.pkt — SYN-ACK emits TS/SACKP unconditionally (script expects neither when client did not offer); needs negotiation mirroring
  - tcp-fsm/mss/mss-setsockopt-tcp_maxseg-client.pkt — TCP_MAXSEG setsockopt not plumbed: getsockopt returns 0 instead of user-configured value
  - tcp-fsm/mss/mss-setsockopt-tcp_maxseg-server.pkt — TCP_MAXSEG setsockopt not plumbed: getsockopt returns 0 instead of user-configured value

### Other (wire shape / middleware-layer behavior)

  - icmp/icmp-all-types.pkt — ICMP ingress/error delivery not modeled

## google upstream

### Runnable-but-broken (A8.5 T6 pragmatic floor)

The Google upstream packetdrill tests under
`third_party/packetdrill/gtests/` (167 `.pkt` total) all fail on the
A8.5 T6 shim binary. Pinned at `GOOGLE_RUNNABLE_COUNT = 0`.

Dry-run evidence that drove this floor (post-T6):
- 0/167 scripts exit 0 under the A8.5 T6 shim.
- The init-script blocker is gone: patch 0007 stubs
  `gtests/net/common/defaults.sh` (plus the symlinked TCP variant)
  and `gtests/net/tcp/common/set_sysctls.py` to no-ops, and the
  corpus invoker now chdirs into the script's directory before
  spawning the shim so relative paths resolve. Previously all 163
  env-init-dependent scripts exited 127 at the init step; they now
  all progress into the TCP path.
- Post-T6 failure mix over the 167:
  - 93 fail on SYN-ACK wire-shape mismatch (the engine emits
    `<MSS, NOP+WScale, SACKP, TS>` unconditionally; many scripts
    expect options mirrored to the client or no TS when the client
    didn't offer it, so `ipv4_total_length` or the TCP options block
    diverges).
  - ~25 fail on `fcntl(F_GETFL)` / `fcntl(F_SETFL, O_NONBLOCK)`
    flag-shape drift (expected 2 vs actual 2050 — the shim reports
    a richer flag word than the scripts expect).
  - ~20 fail on fastopen `sendto()` returning `EBADF` where
    scripts expect `EINPROGRESS` (TCP Fast Open not implemented).
  - The remaining ~29 fail on a long tail of engine gaps
    (server-side accept timing, TCP_MAXSEG setsockopt not plumbed,
    fast_retransmit / cubic / sack / ts_recent / etc.).
- 4 packetdrill-meta scripts (fast_retransmit, socket_err shapes,
  packet-timeout) fail on errno-shape or timing gaps that Google
  uses to exercise packetdrill itself.

A8+ work: close the SYN-ACK TCP-option mirroring gap +
fcntl(O_NONBLOCK) flag-shape parity to unlock ~118 scripts, then
triage the long-tail engine gaps.

### Syscalls returning EOPNOTSUPP in the A8 shim

  - gtests/net/tcp/epoll/epoll_in_edge.pkt — epoll_* returns EOPNOTSUPP in A8 shim
  - gtests/net/tcp/epoll/epoll_out_edge.pkt — epoll_* returns EOPNOTSUPP in A8 shim
  - gtests/net/tcp/epoll/epoll_out_edge_default_notsent_lowat.pkt — epoll_* returns EOPNOTSUPP in A8 shim
  - gtests/net/tcp/epoll/epoll_out_edge_notsent_lowat.pkt — epoll_* returns EOPNOTSUPP in A8 shim
  - gtests/net/tcp/splice/tcp_splice_loop_test.pkt — splice/pipe returns EOPNOTSUPP in A8 shim
  - gtests/net/tcp/sendfile/sendfile-simple.pkt — sendfile not wired in A8 test-FFI (needs backing fd plumbing)
  - gtests/net/tcp/ioctl/ioctl-siocinq-fin.pkt — ioctl SIOCINQ/SIOCOUTQ not plumbed through test-FFI

### Unimplemented TCP / socket options

  - gtests/net/tcp/md5/md5-only-on-client-ack.pkt — TCP_MD5SIG option not implemented in engine
  - gtests/net/tcp/inq/client.pkt — TCP_INQ (SIOCINQ-style queue length) not plumbed through test-FFI
  - gtests/net/tcp/inq/server.pkt — TCP_INQ (SIOCINQ-style queue length) not plumbed through test-FFI
  - gtests/net/tcp/notsent_lowat/notsent-lowat-default.pkt — TCP_NOTSENT_LOWAT not implemented; also needs sysctl env
  - gtests/net/tcp/notsent_lowat/notsent-lowat-setsockopt.pkt — TCP_NOTSENT_LOWAT not implemented; also needs sysctl env
  - gtests/net/tcp/notsent_lowat/notsent-lowat-sysctl.pkt — TCP_NOTSENT_LOWAT not implemented; also needs sysctl env
  - gtests/net/tcp/tcp_info/tcp-info-last_data_recv.pkt — TCP_INFO structure not populated by engine yet
  - gtests/net/tcp/tcp_info/tcp-info-rwnd-limited.pkt — TCP_INFO structure not populated by engine yet
  - gtests/net/tcp/tcp_info/tcp-info-sndbuf-limited.pkt — TCP_INFO structure not populated by engine yet
  - gtests/net/tcp/timestamping/client-only-last-byte.pkt — SO_TIMESTAMPING / ancillary-data path not in test-FFI
  - gtests/net/tcp/timestamping/partial.pkt — SO_TIMESTAMPING / ancillary-data path not in test-FFI
  - gtests/net/tcp/timestamping/server.pkt — SO_TIMESTAMPING / ancillary-data path not in test-FFI
  - gtests/net/tcp/user_timeout/user-timeout-probe.pkt — TCP_USER_TIMEOUT not implemented
  - gtests/net/tcp/user_timeout/user_timeout.pkt — TCP_USER_TIMEOUT not implemented
  - gtests/net/tcp/zerocopy/basic.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/batch.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/client.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/closed.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/epoll_edge.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/epoll_exclusive.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/epoll_oneshot.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/fastopen-client.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/fastopen-server.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/maxfrags.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented
  - gtests/net/tcp/zerocopy/small.pkt — SO_ZEROCOPY / MSG_ZEROCOPY not implemented

### Unimplemented engine behavior (congestion control, recovery, etc.)

  - gtests/net/tcp/cubic/cubic-bulk-166k-idle-restart.pkt — CUBIC congestion-control algorithm not implemented
  - gtests/net/tcp/cubic/cubic-bulk-166k.pkt — CUBIC congestion-control algorithm not implemented
  - gtests/net/tcp/cubic/cubic-hystart-delay-min-rtt-jumps-downward.pkt — CUBIC congestion-control algorithm not implemented
  - gtests/net/tcp/cubic/cubic-hystart-delay-rtt-jumps-upward.pkt — CUBIC congestion-control algorithm not implemented
  - gtests/net/tcp/cubic/cubic-rack-reo-timeout-retrans-failed-incoming-data.pkt — CUBIC congestion-control algorithm not implemented
  - gtests/net/tcp/cubic/cubic-rto-ss-ca-cwnd-bump.pkt — CUBIC congestion-control algorithm not implemented
  - gtests/net/tcp/cwnd_moderation/cwnd-moderation-disorder-no-moderation.pkt — Congestion-window moderation heuristics not modeled
  - gtests/net/tcp/cwnd_moderation/cwnd-moderation-ecn-enter-cwr-no-moderation-700.pkt — Congestion-window moderation heuristics not modeled
  - gtests/net/tcp/ecn/ecn-uses-ect0.pkt — ECN (ECT/CE bits) behavior not modeled
  - gtests/net/tcp/fast_recovery/prr-ss-10pkt-lost-1.pkt — Fast-recovery state machine (RFC 6582) not in engine
  - gtests/net/tcp/fast_recovery/prr-ss-30pkt-lost-1_4-11_16.pkt — Fast-recovery state machine (RFC 6582) not in engine
  - gtests/net/tcp/fast_recovery/prr-ss-30pkt-lost1_4.pkt — Fast-recovery state machine (RFC 6582) not in engine
  - gtests/net/tcp/fast_recovery/prr-ss-ack-below-snd_una-cubic.pkt — Fast-recovery state machine (RFC 6582) not in engine
  - gtests/net/tcp/fast_retransmit/fr-4pkt-fack-last-byte.pkt — Fast-retransmit dupACK heuristic not in engine
  - gtests/net/tcp/fast_retransmit/fr-4pkt-fack-last-mss.pkt — Fast-retransmit dupACK heuristic not in engine
  - gtests/net/tcp/fast_retransmit/fr-4pkt-sack.pkt — Fast-retransmit dupACK heuristic not in engine
  - gtests/net/tcp/fast_retransmit/fr-4pkt.pkt — Fast-retransmit dupACK heuristic not in engine
  - gtests/net/tcp/limited_transmit/limited-transmit-no-sack.pkt — Limited-transmit (RFC 3042) not in engine
  - gtests/net/tcp/limited_transmit/limited-transmit-sack.pkt — Limited-transmit (RFC 3042) not in engine
  - gtests/net/tcp/sack/sack-route-refresh-ip-tos.pkt — SACK shift/coalesce logic not modeled in engine yet
  - gtests/net/tcp/sack/sack-shift-sacked-2-6-8-3-9-nofack.pkt — SACK shift/coalesce logic not modeled in engine yet
  - gtests/net/tcp/sack/sack-shift-sacked-7-3-4-8-9-fack.pkt — SACK shift/coalesce logic not modeled in engine yet
  - gtests/net/tcp/sack/sack-shift-sacked-7-5-6-8-9-fack.pkt — SACK shift/coalesce logic not modeled in engine yet
  - gtests/net/tcp/slow_start/slow-start-ack-per-1pkt.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-ack-per-2pkt-send-5pkt.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-ack-per-2pkt-send-6pkt.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-ack-per-2pkt.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-ack-per-4pkt.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-after-idle.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-after-win-update.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-app-limited-9-packets-out.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-app-limited.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/slow_start/slow-start-fq-ack-per-2pkt.pkt — Slow-start exponential growth observability not modeled
  - gtests/net/tcp/ts_recent/fin_tsval.pkt — PAWS / ts_recent handling depends on timestamp-option parity
  - gtests/net/tcp/ts_recent/invalid_ack.pkt — PAWS / ts_recent handling depends on timestamp-option parity
  - gtests/net/tcp/ts_recent/reset_tsval.pkt — PAWS / ts_recent handling depends on timestamp-option parity
  - gtests/net/tcp/validate/validate-established-no-flags.pkt — Segment-validation edge cases (no-flags) not modeled

### TCP Fast Open (RFC 7413) — not implemented in engine

  - gtests/net/tcp/fastopen/client/blocking-connect-bypass-errno.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/blocking-connect-bypass.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/blocking-sendmsg-multi-iov.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/blocking-sendto-errnos.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/blocking-sendto.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/cookie-less-sendto.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/cookie-req-timeout.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/fallback-exp-opt.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/fastopen-connect-keepalive.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/nonblocking-connect-bypass-errno.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/nonblocking-connect-bypass.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/nonblocking-sendmsg-multi-iov.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/nonblocking-sendto-empty-buf.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/nonblocking-sendto-errnos.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/nonblocking-sendto-over-mss.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/nonblocking-sendto.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/poll.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/sendto-af-unspec.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/simultaneous-fast-open.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/syn-data-icmp-unreach-frag-needed-with-seq-ipv6.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/syn-data-icmp-unreach-frag-needed-with-seq.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/syn-data-icmp-unreach-frag-needed.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/syn-data-mss.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/syn-data-only-syn-acked.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/syn-data-partial-or-over-ack.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/syn-data-rtt-from-syn-data.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/syn-data-timeout.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/synack-data.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/client/valid-cookie-format.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/basic-cookie-not-reqd.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/basic-non-tfo-listener.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/basic-rw.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/basic-zero-payload.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/client-ack-dropped-then-recovery-ms-timestamps.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/fin-close-socket.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/icmp-baseline.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/icmp-before-accept.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/listener-closed-trigger-rst.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/basic-cookie-not-reqd.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/basic-non-tfo-listener.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/basic-rw.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/basic-zero-payload.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/fin-close-socket.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/icmp-before-accept.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/listener-closed-trigger-rst.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/pure-syn-data.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/reset-after-accept.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/reset-before-accept.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/reset-close-with-unread-data.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/reset-non-tfo-socket.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/simple1.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/simple2.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/simple3.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/opt34/unread-data-closed-trigger-rst.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/pure-syn-data.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/reset-after-accept.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/reset-before-accept.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/reset-close-with-unread-data.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/reset-non-tfo-socket.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/simple1.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/simple2.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/simple3.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/sockopt-fastopen-key.pkt — TCP Fast Open (RFC 7413) not implemented in engine
  - gtests/net/tcp/fastopen/server/unread-data-closed-trigger-rst.pkt — TCP Fast Open (RFC 7413) not implemented in engine

### MSS / TCP_MAXSEG socket-option + client-mode plumbing

Note: A8.5 T5 aligned TX TCP option emission to Linux canonical order
(`<MSS, NOP+WScale, SACKP, TS>`) and A8.5 T6 removed the defaults.sh
init blocker. Post-T6 reasons below reflect the actual TCP-path
failure each script hits.

  - gtests/net/tcp/mss/mss-getsockopt-tcp_maxseg-server.pkt — SYN-ACK emits TS/SACKP unconditionally vs no-option client (post-T6; option-mirroring gap)
  - gtests/net/tcp/mss/mss-setsockopt-tcp_maxseg-client.pkt — TCP_MAXSEG setsockopt not plumbed: getsockopt returns 0 instead of user-configured value
  - gtests/net/tcp/mss/mss-setsockopt-tcp_maxseg-server.pkt — TCP_MAXSEG setsockopt not plumbed: getsockopt returns 0 instead of user-configured value

### Server-side lifecycle — engine/shim gaps after T6 init-stub (A8+)

Init blocker was removed in A8.5 T6 (patch 0007 stubs
`common/defaults.sh` + `common/set_sysctls.py`). These scripts now
progress into the TCP path and fail on the deeper blockers noted.

  - gtests/net/tcp/blocking/blocking-accept.pkt — accept() returns -1 EAGAIN before scripted SYN arrives (scheduler/accept timing; post-T6; A8+)
  - gtests/net/tcp/blocking/blocking-connect.pkt — connect() timing delta vs scripted expectation (post-T6; A8+)
  - gtests/net/tcp/blocking/blocking-read.pkt — read() blocking timing delta vs scripted expectation (post-T6; A8+)
  - gtests/net/tcp/blocking/blocking-write.pkt — SYN-ACK TCP options shape mismatch (ipv4_total_length drift; option-mirroring gap)
  - gtests/net/tcp/close/close-local-close-then-remote-fin.pkt — close() syscall return-time delta vs scripted tolerance (post-T6; A8+)
  - gtests/net/tcp/close/close-on-syn-sent.pkt — connect() returns 0 where script expects -1 ECONNRESET (RST-during-SYN-SENT path; A8+)
  - gtests/net/tcp/close/close-remote-fin-then-close.pkt — server-side accept path needed for close-after-FIN test (post-T6; A8+)
  - gtests/net/tcp/shutdown/shutdown-rd-close.pkt — half-close semantics (SHUT_RD) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - gtests/net/tcp/shutdown/shutdown-rd-wr-close.pkt — half-close semantics (SHUT_RD/SHUT_WR) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close
  - gtests/net/tcp/shutdown/shutdown-rdwr-close.pkt — SHUT_RDWR probes post-shutdown read=0/write=EPIPE (half-close); spec §6.4 AD-A8.5-shutdown-no-half-close
  - gtests/net/tcp/shutdown/shutdown-rdwr-send-queue-ack-close.pkt — SHUT_RDWR probes post-shutdown read=0/write=EPIPE (half-close); spec §6.4 AD-A8.5-shutdown-no-half-close
  - gtests/net/tcp/shutdown/shutdown-rdwr-write-queue-close.pkt — SHUT_RDWR probes post-shutdown read=0/write=EPIPE (half-close); spec §6.4 AD-A8.5-shutdown-no-half-close
  - gtests/net/tcp/shutdown/shutdown-wr-close.pkt — half-close semantics (SHUT_WR) not implemented; spec §6.4 AD-A8.5-shutdown-no-half-close

### Other (wire shape / middleware-layer behavior)

  - gtests/net/tcp/gro/gro-mss-option.pkt — GRO-specific wire-shape expectations not modeled
  - gtests/net/tcp/mtu_probe/basic-v4.pkt — PMTU probe machinery not modeled (also needs raw-socket/route hooks)
  - gtests/net/tcp/mtu_probe/basic-v6.pkt — PMTU probe machinery not modeled (also needs raw-socket/route hooks)
  - gtests/net/tcp/nagle/https_client.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - gtests/net/tcp/nagle/sendmsg_msg_more.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - gtests/net/tcp/nagle/sockopt_cork_nodelay.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - gtests/net/tcp/eor/no-coalesce-large.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - gtests/net/tcp/eor/no-coalesce-retrans.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - gtests/net/tcp/eor/no-coalesce-small.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - gtests/net/tcp/eor/no-coalesce-subsequent.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - gtests/net/tcp/syscall_bad_arg/fastopen-invalid-buf-ptr.pkt — Negative-syscall-argument error shapes not modeled in test-FFI
  - gtests/net/tcp/syscall_bad_arg/sendmsg-empty-iov.pkt — Negative-syscall-argument error shapes not modeled in test-FFI
  - gtests/net/tcp/syscall_bad_arg/syscall-invalid-buf-ptr.pkt — Negative-syscall-argument error shapes not modeled in test-FFI

### packetdrill-meta self-tests (engine / binary sanity)

  - gtests/net/packetdrill/tests/bsd/fast_retransmit/fr-4pkt-sack-bsd.pkt — Fast-retransmit dupACK heuristic not in engine
  - gtests/net/packetdrill/tests/linux/fast_retransmit/fr-4pkt-sack-linux.pkt — Fast-retransmit dupACK heuristic not in engine
  - gtests/net/packetdrill/tests/linux/packetdrill/socket_err.pkt — socket() errno-shape test: engine always returns success where script expects EAFNOSUPPORT (A8+)
  - gtests/net/packetdrill/tests/linux/packetdrill/socket_wrong_err.pkt — socket() errno-shape test: engine returns OK where script expects -EADDRINUSE (A8+)
  - gtests/net/packetdrill/tests/packet-timeout.pkt — packet-timeout meta test: engine tolerance/timing gap vs scripted budget (post-T6 stubs)
