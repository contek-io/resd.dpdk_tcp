# tcpreq-runner skip list

The tcpreq 2020 Python codebase has 8 probe modules. A8 ports 4 and
skips the rest because they duplicate coverage already in Layer A +
Layer B. Each un-ported probe is cited below with the authoritative
covering test path.

Format: `<tcpreq module> — <reason> — <covering-test citation>`

## Ported (live in `src/probes/*.rs`)

  - tcpreq/tests/mss.py:MissingMSSTest → probes::mss::missing_mss (MUST-15)
  - tcpreq/tests/mss.py:LateOptionTest → probes::mss::late_option (MUST-5)
  - tcpreq/tests/reserved.py:ReservedBitsTest → probes::reserved::reserved_rx (Reserved-RX)
  - tcpreq/tests/urgent.py:UrgentTest → probes::urgent::urgent_dropped (MUST-30/31 documented deviation AD-A8-urg-dropped)
  - tcpreq/tests/checksum.py:ZeroChecksumTest → probes::checksum::zero_checksum (MUST-2/3)

## Skipped — duplicate Layer A/B coverage

  - tcpreq/tests/mss.py:MSSSupportTest — covered by active-open SYN emission in tcp_output + MSS encode/decode in tcp_options.rs + proptest_tcp_options.rs (MUST-14)
  - tcpreq/tests/options.py:OptionSupportTest — covered by tests/proptest_tcp_options.rs (EOL/NOP/MSS/WS/TS/SACK roundtrip) (MUST-4)
  - tcpreq/tests/options.py:UnknownOptionTest — covered by tests/proptest_tcp_options.rs (unknown-kind kept-then-dropped) (MUST-6)
  - tcpreq/tests/options.py:IllegalLengthOptionTest — covered by tests/proptest_tcp_options.rs (malformed-length path) + `tcp.rx_bad_option` counter-coverage scenario. (MUST-7)
  - tcpreq/tests/rst_ack.py — covered by A3 RST-path unit tests in tcp_input.rs + A7/A8 S1 AD-A7 fixes + `tcp.rx_rst` / `tcp.tx_rst` counter-coverage. (Reset processing)
  - tcpreq/tests/liveness.py:LivenessTest — not applicable to in-memory loopback (no preflight reachability needed).
  - tcpreq/tests/ttl_coding.py — not applicable to in-memory loopback (no middlebox / ICMP TTL-expired path).

## Meta tests (not probes)

  - MUST-8 clock-driven ISN — covered by crates/dpdk-net-core/src/iss.rs (SipHash-keyed RFC 6528 §3) + tests/siphash24_full_vectors.rs

## Stage 1 Layer C scope

The 4 ported probes cover the MUST clauses where tcpreq adds signal
beyond Layer A / Layer B. Probes whose coverage is already dense in
the Rust test suite are skipped to keep the Stage 1 gate deterministic
and maintainable.
