# Phase A2 — mTCP Comparison Review

- Reviewer: mtcp-comparison-reviewer subagent (dispatched via general-purpose per registry limitation)
- Date: 2026-04-17
- mTCP submodule SHA: 0463aad5ecb6b5bca85903156ce1e314a58efc19
- Our commit: 54d3573

## Scope

- Our files reviewed:
  - `crates/resd-net-core/src/l2.rs`
  - `crates/resd-net-core/src/l3_ip.rs`
  - `crates/resd-net-core/src/icmp.rs`
  - `crates/resd-net-core/src/arp.rs`
  - `crates/resd-net-core/src/engine.rs` (rx_frame / handle_arp / handle_ipv4 / tx_frame / maybe_emit_gratuitous_arp)
  - `crates/resd-net-core/src/counters.rs`
  - `crates/resd-net/src/lib.rs` (`resd_net_resolve_gateway_mac`)
- mTCP files referenced:
  - `third_party/mtcp/mtcp/src/eth_in.c`
  - `third_party/mtcp/mtcp/src/eth_out.c`
  - `third_party/mtcp/mtcp/src/ip_in.c`
  - `third_party/mtcp/mtcp/src/ip_out.c`
  - `third_party/mtcp/mtcp/src/arp.c`
  - `third_party/mtcp/mtcp/src/icmp.c`
  - `third_party/mtcp/io_engine/include/ps.h` (for `ip_fast_csum`)
- Spec sections in scope: §5.1 RX pipeline, §6.3 RFC matrix rows 791/792/1122/1191, §8 static gateway MAC.

## Findings

### Must-fix (correctness divergence)

_(no items — see Missed edge cases and Accepted divergence for the delta set)_

### Missed edge cases (mTCP handles, we don't)

- [x] **E-1** — ARP reply Ethernet frame is 42 bytes; mTCP emits 60 bytes (Ethernet minimum payload pad). **RESOLVED in commit `eb4bbc8` ("pad ARP frames to Ethernet-min 60 bytes (fix E-1)")**. Empirical validation via tcpdump on `resdtap1` confirmed our unpatched build emitted 42-byte runts (net_tap + kernel tap do not auto-pad); after the fix the TAP integration test still passes in 0.36s and frames are now 60 bytes.
  - mTCP: `third_party/mtcp/mtcp/src/arp.c:13,41,161` — `ARP_PAD_LEN 18` + `memset(arph->pad, 0, ARP_PAD_LEN)`.
  - Our fix: `crates/resd-net-core/src/arp.rs` — added `ARP_PAD_LEN = 18`, raised `ARP_FRAME_LEN` to 60, both builders zero-fill `out[42..60]`. Two regression tests (`reply_is_padded_to_ethernet_minimum`, `gratuitous_is_padded_to_ethernet_minimum`) assert the pad zeros and the 60-byte length.

### Accepted divergence (intentional — human-finalized)

- **AD-1** — We do not learn gateway MAC from inbound ARP replies (or mTCP's gratuitous-ARP learning).
  - mTCP: `third_party/mtcp/mtcp/src/arp.c:226-267` — `ProcessARPRequest` and `ProcessARPReply` both call `GetDestinationHWaddr` and then `RegisterARPEntry(arph->ar_sip, arph->ar_sha)` if missing. mTCP learns every neighbor's MAC from any ARP traffic it observes.
  - Ours: `crates/resd-net-core/src/engine.rs:324-341` — `handle_arp` only matches inbound ARP *requests for our IP* and emits a reply. `gateway_mac` lives in `cfg: EngineConfig` which is immutable after construction.
  - Rationale cited: **spec §8** ("ARP: static gateway MAC seeded at startup via netlink helper (one-shot), refreshed via gratuitous ARP every N seconds. No dynamic ARP resolution on the data path."). The `crates/resd-net-core/src/arp.rs` module-level doc states the same, and phase plan Task 7 explicitly says "static-gateway A2 we rely on the configured MAC and do not mutate." Accepted — design intent.

- **AD-2** — No ARP request queue / retry timer for unresolved neighbors.
  - mTCP: `third_party/mtcp/mtcp/src/arp.c:44-57,196-223,311-329` — global `arp_manager` with `TAILQ`, `RequestARP` enqueues and broadcasts, `ARPTimer` fires each ms to time out and retransmit at 1s.
  - Ours: gateway MAC is resolved once at `Engine::new` via `/proc/net/arp` and never refreshed.
  - Rationale cited: **spec §8** (static gateway model) + **plan Task 8** (`/proc/net/arp` resolver is the documented deviation from spec §8's "netlink helper" — simpler, no netlink-crate dep, same behavior on TAP / kernel-visible NICs; for vfio-pci the application supplies `gateway_mac` directly). Trading client has one exchange gateway per session that does not move; gratuitous-ARP emit loop (every `garp_interval_sec`) keeps peers' caches fresh for our direction. Accepted — design intent.

- **AD-3** — We drop on TTL == 0 (`L3Drop::TtlZero`, `crates/resd-net-core/src/l3_ip.rs:77-80`); mTCP does not check TTL on ingress at all.
  - mTCP: `third_party/mtcp/mtcp/src/ip_in.c` — no `ttl` check anywhere.
  - Ours: explicit drop on TTL zero; we do NOT emit ICMP Time Exceeded (we're a host, not a router; RFC 792's "SHOULD emit" is for routers).
  - Rationale cited: **spec §6.3 RFC 791 row** ("IPv4 ... full for client send/recv"). RFC 791 §3.2 requires hosts to discard packets with TTL == 0. Our side is stricter than mTCP's for defense-in-depth; the one-branch cost is trivially off the hot path (never taken on well-formed traffic). Accepted — correctness over mTCP parity.

- **AD-4** — We verify IP checksum in software on every packet; `Engine::poll_once` calls `ip_decode(..., /*nic_csum_ok=*/false)` at `crates/resd-net-core/src/engine.rs:345`.
  - mTCP: `third_party/mtcp/mtcp/src/ip_in.c:28-37` — queries hardware offload (`PKT_RX_IP_CSUM`) and falls back to software only if the offload returned -1.
  - Ours: `nic_csum_ok` param is wired through `ip_decode` but Phase A2 always passes `false` — NIC ol_flags query is future work.
  - Rationale cited: **plan Task 5 Step 3** ("Checksum: verify only when NIC didn't") + scope boundary. The Rust API is already offload-ready; flipping it on in a later phase is an engine-side wiring change, not a library API change. Accepted — forward-compatible design.

- **AD-5** — ICMP ECHO (ping) request is dropped, not replied.
  - mTCP: `third_party/mtcp/mtcp/src/icmp.c:122-125` — handles ECHO with `ProcessICMPECHORequest`, reflects back an ECHO_REPLY.
  - Ours: `crates/resd-net-core/src/icmp.rs:61-63` — any ICMP other than Type 3 / Code 4 returns `IcmpResult::OtherDropped`, silently discarded by the engine.
  - Rationale cited: **spec §6.3 RFC 792 row** ("frag-needed + dest-unreachable (in-only) | drives PMTUD; drop others silently"). Trading client is not a pingable host by design — operators ping the OS on the control plane, not the DPDK port. Accepted — spec intent.

- **AD-6** — ICMP frag-needed with `next_hop_mtu == 0` (RFC 1191 legacy plateau-table) is treated as `Malformed` and not acted on.
  - Promoted from **E-4**. mTCP doesn't implement PMTUD at all (FYI I-2), so there's no parity reference.
  - Ours: `crates/resd-net-core/src/icmp.rs:81-83` — explicit `if next_hop_mtu == 0 { return IcmpResult::Malformed; }` with an inline comment pointing at RFC 4821 PLPMTUD as Stage 2.
  - Rationale cited: **spec §10.8** (Stage 2 hardening scope — PLPMTUD / RFC 4821 explicitly out of Stage 1; graceful degradation to the configured MSS when a peer emits legacy RFC 792 ICMPs is acceptable for Stage 1). Peers/routers behind strict RFC 792 paths that emit 0 in the MTU field will simply not shrink our PMTU — no correctness failure, just a missed optimization. Accepted — documented Stage-1 scope boundary.

- **AD-7** — `icmp_input` does not verify the ICMP checksum before acting on type 3 / code 4.
  - Promoted from **E-3**. mTCP verifies in `ProcessICMPECHORequest` (`third_party/mtcp/mtcp/src/icmp.c:94`) but does not implement PMTUD, so the parity comparison is indirect.
  - Ours: trusts the type/code/next-hop-mtu fields without `internet_checksum` verification.
  - Rationale cited: **trading-latency defaults** (`feedback_trading_latency_defaults.md`) + **deployment assumption** — our target environment is a private, firewalled exchange-colocation network where on-path forgery is not part of the realistic threat model; the additional checksum branch buys security only against an attacker who is already on-path (and who could do far worse than a PMTUD shrink). The attack's worst-case impact is per-peer PMTU clamped to 68 bytes (`IPV4_MIN_MTU`) — recovers within one `garp_interval` of the attack ending because we never grow PMTU; a reconnect refreshes everything. Accepted — scoped to Stage 2 hardening if the threat model changes.

- **AD-8** — Malformed ICMP input (short packet, bad inner header) is silently dropped without a counter bump distinguishing it from `OtherDropped`.
  - Promoted from **E-2**. mTCP behavior is equivalent.
  - Ours: `crates/resd-net-core/src/engine.rs:379` collapses `IcmpResult::OtherDropped | IcmpResult::Malformed` into the same no-op match arm; only `ip.rx_icmp` (upstream) and nothing specific for malformed.
  - Rationale cited: **spec §9.4** ("No histograms ... application computes from counters + event timestamps") + **observability-primitives memory** — the Stage 1 counter schema is deliberately finite and we can add a `rx_icmp_malformed` counter in a future phase (there are still 4 `_pad` slots in `IpCounters`). Not a correctness bug; a diagnosability wish. Accepted — deferred to Stage 2 hardening or an A3+ counter-refinement pass.

### FYI (informational — no action required)

- **I-1** — Our `l2_decode` rejects all non-IPv4, non-ARP ethertypes with `L2Drop::UnknownEthertype` (counted in `eth.rx_drop_unknown_ethertype`). mTCP's `ProcessPacket` (`third_party/mtcp/mtcp/src/eth_in.c:43-47`) also drops them but calls `release_pkt` and returns TRUE with no counter. Our observability is strictly better here.

- **I-2** — mTCP does *not* implement PMTUD / RFC 1191 at all. `third_party/mtcp/mtcp/src/icmp.c:127-130` traces "Destination Unreachable message received" and returns. There is no PMTU table, no next-hop MTU lookup on egress. Our `crates/resd-net-core/src/icmp.rs` `PmtuTable` is a pure spec-driven addition with no mTCP counterpart. The comparison axis therefore degenerates on this module; all of our behavior is accepted-by-default with spec §6.3 RFC 1191 row as the sole authority.

- **I-3** — mTCP's ARP ingress (`third_party/mtcp/mtcp/src/arp.c:269-306`) does NOT validate `ar_hrd`, `ar_pro`, `ar_hln`, `ar_pln` before trusting the body. It just reads `ar_tip` at the expected offset. A crafted ARP with HRD=IEEE-1394 (htype=24) and PLN=8 would be processed as if it were Ethernet+IPv4 and could cause a targeted reply storm. Our `crates/resd-net-core/src/arp.rs:46-55` rejects all four fields explicitly — again, our side is stricter and better-observed.

- **I-4** — mTCP's `ProcessIPv4Packet` (`third_party/mtcp/mtcp/src/ip_in.c:21,25`) uses `iph->tot_len` for the length check but does *not* compare against the raw `len` received from the driver. A packet with `tot_len > len` will checksum-read past the buffer end. Ours (`crates/resd-net-core/src/l3_ip.rs:66`) bounds `total_len <= pkt.len()`. This is an mTCP latent bug, not a parity gap — no action on our side.

- **I-5** — mTCP does not enforce IPv4 fragment drop on ingress; there is no MF/frag_off check in `ProcessIPv4Packet`. Spec §6.3 RFC 1122 row excludes reassembly in Stage 1, and we drop frags explicitly (`crates/resd-net-core/src/l3_ip.rs:71-76` with `L3Drop::Fragment`). Our side is correct; noted because the subagent brief called out fragment-reassembly exhaustion as an expected edge case.

- **I-6** — Our `internet_checksum` (`crates/resd-net-core/src/l3_ip.rs:34-48`) is a straight byte-pair fold matching RFC 1071. mTCP's `ip_fast_csum` (`third_party/mtcp/io_engine/include/ps.h:67-82`) is hand-rolled x86 asm unrolled for the common IHL=5 case. Algorithmically identical result; performance is a future optimization (spec §10.6 "header-checksum loop unroll" is called out for later).

- **I-7** — Our `tx_frame` (`crates/resd-net-core/src/engine.rs:210-257`) explicitly frees the mbuf on `tx_drop_full_ring`. mTCP's `EthernetOutput` (`third_party/mtcp/mtcp/src/eth_out.c:58-80`) calls `get_wptr` which returns a pointer into a driver-managed ring; freeing on TX-full-ring is implicit in the driver semantics. No parity gap; our model is simpler since one mbuf per frame is a DPDK idiom, not a mTCP idiom.

- **I-8** (promoted from E-5) — IPv4 decoder does not reject IP options with option-length > remaining space (we don't parse options at all in Phase A2). mTCP also doesn't parse or validate options (`ip_fast_csum` just reads `ihl*4` bytes). No parity gap, no spec requirement in Stage 1. Informational.

## Verdict

**PASS-WITH-ACCEPTED** — human-finalized 2026-04-18.

Finding counts after human review:
- Must-fix: 0
- Missed edge cases (open): 0
- Missed edge cases (resolved): 1 — E-1 fixed in `eb4bbc8` (ARP frames padded to 60 bytes; empirically validated via TAP-side tcpdump capture before & after the fix)
- Accepted divergence (with citations): 8 — AD-1 through AD-8. Four original AD entries plus E-2/E-3/E-4 promoted to AD-6/7/8.
- FYI: 8 — I-1 through I-8 (E-5 demoted to I-8).

Gate rule satisfied: no open `[ ]` remains in Must-fix or Missed-edge-cases. All Accepted-divergence entries cite a concrete spec §ref or memory file. The phase-a2-complete tag may proceed.
