# tcpreq-runner skip list

The tcpreq 2020 Python codebase has 8 probe modules. A8 ported 4;
A8.5 widens the port to cover additional MUST clauses where the
engine-driven probe adds independent signal beyond Layer A / Layer B
(the `Ported` list below grows as A8.5 lands each probe). Skipped
probes duplicate coverage already in Layer A + Layer B. Each un-ported
probe is cited below with the authoritative covering test path.

Format: `<tcpreq module> — <reason> — <covering-test citation>`

## Ported (live in `src/probes/*.rs`)

  - tcpreq/tests/mss.py:MissingMSSTest → probes::mss::missing_mss (MUST-15)
  - tcpreq/tests/mss.py:LateOptionTest → probes::mss::late_option (MUST-5)
  - tcpreq/tests/reserved.py:ReservedBitsTest → probes::reserved::reserved_rx (Reserved-RX)
  - tcpreq/tests/urgent.py:UrgentTest → probes::urgent::urgent_dropped (MUST-30/31 documented deviation AD-A8-urg-dropped)
  - tcpreq/tests/checksum.py:ZeroChecksumTest → probes::checksum::zero_checksum (MUST-2/3)
  - tcpreq/tests/options.py:OptionSupportTest → probes::options::option_support (MUST-4)
  - tcpreq/tests/options.py:UnknownOptionTest → probes::options::unknown_option (MUST-6)
  - tcpreq/tests/options.py:IllegalLengthOptionTest → probes::options::illegal_length (MUST-7)
  - tcpreq/tests/mss.py:MSSSupportTest → probes::mss::mss_support (MUST-14)
  - tcpreq/tests/rst_ack.py:RstAckTest → probes::rst_ack::rst_ack_processing (Reset-Processing, Spec §1.1 A)

## Skipped — duplicate Layer A/B coverage

  - tcpreq/tests/liveness.py:LivenessTest — not applicable to in-memory loopback (no preflight reachability needed).
  - tcpreq/tests/ttl_coding.py — not applicable to in-memory loopback (no middlebox / ICMP TTL-expired path).

## Meta tests (not probes)

  - MUST-8 clock-driven ISN — covered by crates/dpdk-net-core/src/iss.rs (SipHash-keyed RFC 6528 §3) + tests/siphash24_full_vectors.rs

## Stage 1 Layer C scope

The ported probes cover the MUST clauses where tcpreq adds signal
beyond Layer A / Layer B. Probes whose coverage is already dense in
the Rust test suite are skipped to keep the Stage 1 gate deterministic
and maintainable.
