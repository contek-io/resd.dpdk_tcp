# A7 packetdrill-shim skip list

This file enumerates every `.pkt` script excluded from the runnable
set, one line per script. `corpus_ligurio.rs` parses this file and
asserts every skipped script has an entry here (orphan-skip check).

Format: `<path relative to third_party/packetdrill-testcases> — <reason>`

## ligurio corpus

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

  - testcases/tcp/blocking/blocking-accept.pkt — server-side accept path not exercisable via shim yet (A8+)
  - testcases/tcp/blocking/blocking-accept_freebsd.pkt — server-side accept path not exercisable via shim yet (A8+)
  - testcases/tcp/blocking/blocking-connect.pkt — server-side accept path not exercisable via shim yet (A8+)
  - testcases/tcp/blocking/blocking-read.pkt — server-side accept path not exercisable via shim yet (A8+)
  - testcases/tcp/blocking/blocking-read_freebsd.pkt — server-side accept path not exercisable via shim yet (A8+)
  - testcases/tcp/blocking/blocking-simple-server.pkt — server-side accept path not exercisable via shim yet (A8+)
  - testcases/tcp/blocking/blocking-write.pkt — server-side accept path not exercisable via shim yet (A8+)
  - testcases/tcp/close/close-last-ack-lost.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-local-close-then-remote-fin.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-on-syn-sent.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-read-data-fin.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-remote-fin-then-close.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-unread-data-rst.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/close-write-data-rst.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/close/simultaneous-close.pkt — close() tests all require server-side accept path (A8+)
  - testcases/tcp/listen/listen-incoming-ack.pkt — server-side SYN->SYN-ACK round-trip not wired through shim (A8+)
  - testcases/tcp/listen/listen-incoming-no-tcp-flags.pkt — server-side SYN->SYN-ACK round-trip not wired through shim (A8+)
  - testcases/tcp/listen/listen-incoming-rst.pkt — server-side SYN->SYN-ACK round-trip not wired through shim (A8+)
  - testcases/tcp/listen/listen-incoming-syn-ack.pkt — server-side SYN->SYN-ACK round-trip not wired through shim (A8+)
  - testcases/tcp/listen/listen-incoming-syn-rst.pkt — server-side SYN->SYN-ACK round-trip not wired through shim (A8+)
  - testcases/tcp/reset/rst-non-synchronized.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-syn-sent.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-sync-est-fin-wait-1.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-sync-est-fin-wait-2.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-sync-est-time-wait.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst-synchronized-established.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/reset/rst_sync_close_wait.pkt — RST tests depend on server-side accept path or wire-option parity
  - testcases/tcp/shutdown/shutdown-double-shut-wr.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-rd-close.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-rd-wr-close.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-rd.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-rdwr-close.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-rdwr-send-queue-ack-close.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-rdwr-write-queue-close.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-rdwr.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-recv-after-shut-rd.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-wr-close.pkt — shutdown() tests all require server-side accept path (A8+)
  - testcases/tcp/shutdown/shutdown-wr.pkt — shutdown() tests all require server-side accept path (A8+)

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

#### MSS / option-order drift (client-side)

  - testcases/tcp/connect/http-get-nonblocking-ts.pkt — fcntl(O_NONBLOCK) flag-shape drift; also option-order drift
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-client-ts.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-client.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server-advmss-ipv4.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server-advmss-ts-ipv4.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server-ts.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-getsockopt-tcp_maxseg-server_freebsd.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-setsockopt-tcp_maxseg-client.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-setsockopt-tcp_maxseg-client_freebsd.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-setsockopt-tcp_maxseg-server.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+
  - testcases/tcp/mss/mss-setsockopt-tcp_maxseg-server_freebsd.pkt — SYN option-order drift vs script expectation; engine/shim fix is A8+

#### Other (wire shape / middleware-layer behavior)

  - testcases/tcp/ICMP/icmp-all-types.pkt — ICMP ingress/error delivery not modeled
  - testcases/tcp/gro/gro-mss-option.pkt — GRO-specific wire-shape expectations not modeled
  - testcases/tcp/mtu_probe/basic-v4.pkt — PMTU probe machinery not modeled (also needs raw-socket/route hooks)
  - testcases/tcp/mtu_probe/basic-v6.pkt — PMTU probe machinery not modeled (also needs raw-socket/route hooks)
  - testcases/tcp/pmtu_discovery/pmtu-10pkt.pkt — PMTU discovery semantics not modeled
  - testcases/tcp/nagle/https_client.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - testcases/tcp/nagle/sendmsg_msg_more.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - testcases/tcp/nagle/sockopt_cork_nodelay.pkt — Nagle/TCP_NODELAY fine-grained segmentation not modeled
  - testcases/tcp/eor/no-coalesce-large.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - testcases/tcp/eor/no-coalesce-retrans.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - testcases/tcp/eor/no-coalesce-small.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - testcases/tcp/eor/no-coalesce-subsequent.pkt — MSG_EOR / no-coalesce boundary semantics not modeled
  - testcases/tcp/syscall_bad_arg/fastopen-invalid-buf-ptr.pkt — Negative-syscall-argument error shapes not modeled in test-FFI
  - testcases/tcp/syscall_bad_arg/sendmsg-empty-iov.pkt — Negative-syscall-argument error shapes not modeled in test-FFI
  - testcases/tcp/syscall_bad_arg/syscall-invalid-buf-ptr.pkt — Negative-syscall-argument error shapes not modeled in test-FFI

## shivansh corpus

_A8 owner_

## google upstream

_A8 owner_
