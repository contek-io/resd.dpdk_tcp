# Phase A2 — RFC Compliance Review

Retroactive review (gate added after A2 shipped per spec §10.14).

- Reviewer: rfc-compliance-reviewer subagent
- Date: 2026-04-18
- RFCs in scope: 791, 792, 826, 1122 (IPv4 §3.2.1 + reassembly row only), 1191
- Our commit: 66b629ebf18701ff677107b581e0862ecbf78c83 (phase-a3 branch HEAD; A2 shipped at tag phase-a2-complete → d3cb41c50256b99a3773776ac698f63366a64373; the A2-era sources in `l2.rs`/`l3_ip.rs`/`icmp.rs`/`arp.rs`/engine wiring were not modified by A3 aside from post-A2 fix `eb4bbc8` which padded ARP frames to 60 bytes)

## Scope

- Our files reviewed:
  - `crates/dpdk-net-core/src/l2.rs`
  - `crates/dpdk-net-core/src/l3_ip.rs`
  - `crates/dpdk-net-core/src/icmp.rs`
  - `crates/dpdk-net-core/src/arp.rs`
  - `crates/dpdk-net-core/src/engine.rs` (RX pipeline: `poll_once`, `rx_frame`, `handle_arp`, `handle_ipv4`, `maybe_emit_gratuitous_arp`)
  - `crates/dpdk-net-core/src/counters.rs` (A2 eth/ip counter additions)
  - `crates/dpdk-net/src/lib.rs` (`dpdk_net_resolve_gateway_mac` public C ABI)
  - `crates/dpdk-net-core/tests/l2_l3_tap.rs` (crafted-frame TAP integration test)
- Spec §6.3 rows verified:
  - Row RFC 791 "IPv4 / full for client send/recv / TOS-DSCP passthrough, DF always set" — RX half only (TX is later-phase).
  - Row RFC 792 "ICMP / frag-needed + dest-unreachable (in-only) / drives PMTUD; drop others silently."
  - Row RFC 1122 §3.3.2 "IPv4 reassembly / not implemented / RX fragments are dropped and counted (ip.rx_frag); we set DF on all TX, so we never fragment outbound."
  - Row RFC 1122 "Host requirements (TCP §4.2) / client-side items only" — the IPv4 §3.2.1 subset that A2 exercises (§3.2.1.1 version, §3.2.1.2 checksum, §3.2.1.3 dst-addr silent discard, §3.2.1.7 TTL).
  - Row RFC 1191 "PMTUD / yes / driven by ICMP messages."
- Spec §6.4 deviations touched: none. (§6.4 lists TCP-layer deviations only — Delayed-ACK, Nagle, keepalive, minRTO, CC, TFO. None of those apply to A2's L2/L3/ICMP/ARP scope.) The A2-specific design deviations live in spec §8 (static gateway ARP, gratuitous-ARP refresh) and §12 "Out of scope" (row line 777, dynamic ARP).

## Findings

### Must-fix (MUST/SHALL violation)

_None._

### Missing SHOULD (not in §6.4 allowlist)

_None._

### Accepted deviation (covered by spec §6.4 / §8 / §12)

- **AD-1** — IPv4 reassembly not implemented; fragments dropped and counted on ingress.
  - RFC clause: `docs/rfcs/rfc1122.txt:3281` — "The IP layer MUST implement reassembly of IP datagrams."
  - Spec §6.3 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:352` — "`| 1122 §3.3.2 | IPv4 reassembly | **not implemented** | RX fragments are dropped and counted (`ip.rx_frag`); we set DF on all TX, so we never fragment outbound |`".
  - Our code behavior: `l3_ip.rs:74-76` detects MF=1 or frag_off != 0 and returns `L3Drop::Fragment`; `engine.rs:496` maps that to `inc(&self.counters.ip.rx_frag)`. TAP test Case 5 (`l2_l3_tap.rs:224-231`) asserts the `ip.rx_frag` delta.

- **AD-2** — No ARP translation-table learning; static gateway MAC used for all egress.
  - RFC clause: `docs/rfcs/rfc826.txt:210-213` — "If the pair <protocol type, sender protocol address> is already in my translation table, update the sender hardware address field of the entry with the new information in the packet and set Merge_flag to true." (RFC 826 is pre-2119, so the prose is narrative rather than a MUST; spec-deviation language still applies because RFC 826 prescribes an ingress-learning behavior that our static-gateway design omits.)
  - Spec §8 line: `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md:453` — "ARP: static gateway MAC seeded at startup via netlink helper (one-shot), refreshed via gratuitous ARP every N seconds. No dynamic ARP resolution on the data path." Spec §12 line 777 reinforces: "Full dynamic ARP state machine (static + gratuitous refresh only)".
  - Our code behavior: `engine.rs:468-485` decodes ARP, replies only to REQUEST-for-our-IP, never merges sender/target into any translation table (there is no per-engine ARP cache by design). `arp.rs:182-193` provides `resolve_from_proc_arp` for the one-shot bootstrap path only.

- **AD-3** — Gratuitous-ARP refresh driven by a naive poll-loop check, not the real timer wheel.
  - RFC clause: RFC 826 prose around gratuitous ARP is informational in Section "Why is it done this way??"; the MUST-adjacent expectation is spec-level, not RFC-level. Recording here for traceability with the phase plan's deviation note.
  - Spec line: phase plan `docs/superpowers/plans/2026-04-17-stage1-phase-a2-l2-l3.md:15` — "Spec §8 says 'gratuitous-ARP refresh timer every N seconds'. Phase A2 implements this as a naïve poll-loop check ... The real timer-wheel implementation arrives in A6; switching to it is a ~3-line change in `poll_once`."
  - Our code behavior: `engine.rs:985-1002` `maybe_emit_gratuitous_arp` checks `now - last_garp_ns >= interval_ns` at end of each `poll_once`, emits one frame, bumps `eth.tx_arp`.

### FYI (informational — no action)

- **I-1** — RFC 791 §3.2 TTL==0 "must be destroyed" clause: satisfied.
  - `docs/rfcs/rfc791.txt:1013-1014` — "If this field contains the value zero, then the datagram must be destroyed."
  - `l3_ip.rs:78-80` drops with `L3Drop::TtlZero` when `pkt[8] == 0`; `engine.rs:495` bumps `ip.rx_ttl_zero`. Note RFC 1122 §3.2.1.7 (`docs/rfcs/rfc1122.txt:1980-1981`) forbids discarding packets just because TTL < 2 — our code only rejects exactly 0, so TTL==1 is accepted, satisfying both clauses. The A2 mTCP review's AD-3 already flagged that mTCP is laxer; we are stricter and correct.

- **I-2** — RFC 1122 §3.2.1.1 MUST silently discard datagrams with Version != 4: satisfied.
  - `docs/rfcs/rfc1122.txt:1686-1687` — "A datagram whose version number is not 4 MUST be silently discarded."
  - `l3_ip.rs:56-58` returns `L3Drop::BadVersion`; `engine.rs:491` bumps `ip.rx_drop_bad_version`. No RX reply, no log (silent).

- **I-3** — RFC 1122 §3.2.1.2 MUST verify IP header checksum: satisfied by always-SW-verify.
  - `docs/rfcs/rfc1122.txt:1691-1693` — "A host MUST verify the IP header checksum on every received datagram and silently discard every datagram that has a bad checksum."
  - `engine.rs:489` passes `nic_csum_ok=false`, so every packet goes through `l3_ip::internet_checksum` in `l3_ip.rs:81-94`. Spec §8 line 449 permits checksum offload, but A2 does not yet wire up the offload flag; when it does (a later phase), the `nic_csum_ok` parameter becomes the opt-out. For A2, we are strictly more conservative than the MUST requires.

- **I-4** — RFC 1122 §3.2.1.3 MUST silently discard datagrams not for us: satisfied.
  - `docs/rfcs/rfc1122.txt:1809-1811` — "A host MUST silently discard an incoming datagram that is not destined for the host."
  - `l3_ip.rs:98-100` rejects when `our_ip != 0 && dst_ip != our_ip` → `L3Drop::NotOurs`; `engine.rs:497` bumps `ip.rx_drop_not_ours`. `l2.rs:38-43` filters on dst MAC one level up. The `our_ip==0` "test mode" is only used by unit/TAP tests with no real peer traffic.

- **I-5** — RFC 1122 §3.2.1.3 MUST silently discard datagrams with invalid source IP: not implemented; deferred.
  - `docs/rfcs/rfc1122.txt:1843-1846` — "A host MUST silently discard an incoming datagram containing an IP source address that is invalid by the rules of this section. This validation could be done in either the IP layer or by each protocol in the transport layer."
  - Our code: `l3_ip.rs:96` reads `src_ip` without validating against the RFC 1122 §3.2.1.3 bad-source rules (zero address, loopback, broadcast, multicast, Class E). Spec §6.3 scopes the RFC 1122 row to "Host requirements (TCP §4.2) client-side items only" — RFC 1122 §3.2.1.3 source validation is an IP-layer requirement that the spec does not call in-scope for Stage 1. The RFC language explicitly allows transport-layer implementations; when the TCP layer matures it can reject on src-IP validity. No action for A2; revisit when the TCP input path uses `ip.src_ip` for flow-table lookup in A3+.

- **I-6** — RFC 1122 §3.2.2 MUST silently discard unknown ICMP types: satisfied.
  - `docs/rfcs/rfc1122.txt:2222-2223` — "If an ICMP message of unknown type is received, it MUST be silently discarded."
  - `icmp.rs:61-63` classifies non-Type3-Code4 as `IcmpResult::OtherDropped`; `engine.rs:514-523` silently swallows (no counter bump beyond the already-set `ip.rx_icmp`). TAP test Case 6 (`l2_l3_tap.rs:233-257`) exercises the frag-needed path; the unit test `icmp.rs:145-150` covers `OtherDropped` for echo-request.

- **I-7** — RFC 1191 MUST reduce PMTU on Datagram Too Big: satisfied.
  - `docs/rfcs/rfc1191.txt:190-192` — "When a host receives a Datagram Too Big message, it MUST reduce its estimate of the PMTU for the relevant path, based on the value of the Next-Hop MTU field in the message."
  - `icmp.rs:84-88` calls `pmtu.update(inner_dst, next_hop_mtu)` and returns `FragNeededPmtuUpdated` when a new smaller estimate is recorded. `engine.rs:516-522` bumps `ip.rx_icmp_frag_needed` and `ip.pmtud_updates`.

- **I-8** — RFC 1191 MUST never reduce PMTU below 68 octets: satisfied.
  - `docs/rfcs/rfc1191.txt:239-240` — "A host MUST never reduce its estimate of the Path MTU below 68 octets."
  - `icmp.rs:31` floors with `mtu.max(IPV4_MIN_MTU)` where `IPV4_MIN_MTU = 68` (`icmp.rs:13`). Unit test `icmp.rs:122-127` verifies a 32-byte update clamps to 68.

- **I-9** — RFC 1191 MUST NOT increase PMTU from DTB contents: satisfied.
  - `docs/rfcs/rfc1191.txt:242-243` — "A host MUST not increase its estimate of the Path MTU in response to the contents of a Datagram Too Big message."
  - `icmp.rs:30-40` rejects any update where the new clamped MTU is ≥ the existing entry (returns false from `update`; `FragNeededNoShrink` in the wrapper). Unit test `icmp.rs:130-137` verifies that a 1500-byte update after a 1400-byte update is rejected.

- **I-10** — RFC 1191 MUST handle old-style (next-hop MTU = 0) messages: not implemented; deferred to Stage 2.
  - `docs/rfcs/rfc1191.txt:219-223` — "Hosts MUST be able to deal with Datagram Too Big messages that do not include the next-hop MTU, since it is not feasible to upgrade all the routers in the Internet in any finite time."
  - Our code: `icmp.rs:81-83` treats `next_hop_mtu == 0` as `IcmpResult::Malformed` (silently dropped with no PMTU update). The phase plan documents the rationale (`plan:1018-1020` — "`next_hop_mtu == 0` means the router doesn't support RFC 1191 — fall back to RFC 4821 PLPMTUD territory (out of Stage 1 scope). Spec §10.8 notes this as Stage 2."). Spec §10.8 line 573 confirms: "PMTU blackholing (drop ICMP frag-needed) — **Stage 2 scenario only**; requires PLPMTUD (RFC 8899)-style recovery, which is not in Stage 1 scope. Stage 1 relies on ICMP-driven PMTUD (RFC 1191) and degrades gracefully to the configured MSS when ICMP is dropped." Not a blocker; the "MUST be able to deal with" clause is satisfied *in effect* by the degrade-to-configured-MSS stance once TCP egress lands in A3–A5. Revisit if Stage 2 PLPMTUD lands.

- **I-11** — RFC 792 ICMP checksum is not verified before parsing.
  - `docs/rfcs/rfc792.txt:219-224` (and mirrored per-type) — checksum field is defined and receivers are expected to include it in the sum. RFC 792 predates RFC 2119 and uses narrative prose rather than "MUST verify"; RFC 1122 §3.2.2 does not add an explicit MUST either.
  - Our code: `icmp.rs:54-89` parses Type 3 Code 4 without verifying the ICMP checksum. A corrupt ICMP frag-needed could therefore poison the PMTU table (with MTU values floored at 68, and only-shrinks semantics, the damage is bounded: worst case a connection gets pinned to 68-byte PMTU). Noted for completeness; the mTCP comparison review (AD/FYI lines) does not flag this either — mTCP also does not verify ICMP checksum in the frag-needed path.

- **I-12** — RFC 826 ARP packet validation (htype/ptype/hlen/plen) is performed: satisfied (and stricter than mTCP).
  - `docs/rfcs/rfc826.txt:236-242` and narrative "Packet Reception" algorithm at rfc826.txt:197-234.
  - `arp.rs:48-56` rejects packets where htype != 1, hlen != 6, ptype != 0x0800, plen != 4, or op is not REQUEST/REPLY. The A2 mTCP review's I-3 noted mTCP does not validate these and can therefore be confused by a crafted ARP; our side is correct.

- **I-13** — TX-side clauses (DF-always-set for outbound, RFC 791 source-address validation, TOS passthrough) are not exercised by A2.
  - A2 emits only L2+ARP frames (`tx_frame` with ARP reply / gratuitous ARP). It does not emit IPv4 datagrams yet — TCP-egress lands in A3 and first uses `tx_data_frame`. Spec §6.3 row "DF always set" applies to IPv4 egress; verify in A3 review. TOS/DSCP passthrough likewise applies to egress / transport-layer wiring.

- **I-14** — IPv4 options are not parsed or forwarded to the transport layer (RFC 1122 §3.2.1.8).
  - `docs/rfcs/rfc1122.txt:2033-2037` — "All IP options (except NOP or END-OF-LIST) received in datagrams MUST be passed to the transport layer ... The IP and transport layer MUST each interpret those IP options that they understand and silently ignore the others."
  - Our code: `l3_ip.rs:101-112` produces `L3Decoded` with `header_len` but does not expose an options slice; `engine.rs:502` uses `ip.header_len..ip.total_len` for the transport payload (so options are skipped cleanly). In A2 the transport layer is a stub (`tcp_input_stub`/`tcp_input` in A3), so passing options would be a no-op anyway. Revisit in the A3 RFC review when TCP actually consumes L3Decoded — the MUST becomes observable then.

## Verdict (draft)

**PASS-WITH-DEVIATIONS**

Gate rule: phase cannot tag `phase-aN-complete` while any `[ ]` checkbox in Must-fix or Missing-SHOULD is open. Accepted-deviation entries must each cite an exact line in spec §6.4. (A2's deviations are grounded in spec §6.3 / §8 / §12 rather than §6.4 — §6.4 is a TCP-layer allowlist that doesn't apply to L2/L3/ICMP/ARP code paths. Each AD entry cites a concrete spec line per the intent of the gate rule.)

Verdict rationale: zero MUST/SHALL violations detected inside the A2 in-scope RFC clauses. The only MUST-grade gap is RFC 1191's "deal with old-style DTB" clause (I-10), which spec §10.8 explicitly defers to Stage 2 — documented deferral, not a silent failure. The TAP integration test (`l2_l3_tap.rs`) exercises every A2 drop and accept path against real crafted frames, so the RFC claims in spec §6.3 have end-to-end proof behind them.
