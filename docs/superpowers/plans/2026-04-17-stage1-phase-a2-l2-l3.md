# resd.dpdk_tcp Stage 1 Phase A2 — L2/L3 + Static ARP + ICMP-in (PMTUD)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Phase A1 "rx-burst then drop everything" poll loop with real Ethernet + IPv4 decoding, a static-gateway ARP module (with ARP-reply and gratuitous-ARP emission), and ICMP frag-needed handling that drives a per-peer PMTU table. Non-TCP IPv4 packets are counted and dropped; TCP packets are handed to a `tcp_input_stub` that only bumps a counter (real TCP arrives in A3). After this phase the stack is a working L2+L3+ICMP decoder against a TAP pair with counters proving each code path.

**Architecture:** Four new pure-Rust modules in `dpdk-net-core`: `l2` (Ethernet decode + dst-MAC filter), `l3_ip` (IPv4 decode + checksum verification + fragment drop), `icmp` (type 3/code 4 frag-needed → PMTU update; everything else silently dropped), `arp` (ARP packet decode, ARP-reply build, gratuitous-ARP build, `/proc/net/arp` resolver helper). The `poll_once` loop dispatches `l2_decode → {arp_input, ip_decode → {icmp_input, tcp_input_stub}}`. Gratuitous-ARP emission runs periodically (naïve `last_tsc + interval` check at end of `poll_once` — the real timer wheel arrives in A6). DPDK shim is extended with `rte_pktmbuf_alloc` / `rte_pktmbuf_append` wrappers so Rust can build and transmit our own frames.

**Tech Stack:** same as A1 — Rust stable, DPDK 23.11, bindgen, cbindgen. New: `std::fs` for `/proc/net/arp` parsing; `libc::AF_PACKET` + `SOCK_RAW` in the integration test for crafting frames into `dpdktap0`.

**Spec reference:** `docs/superpowers/specs/2026-04-17-dpdk-tcp-design.md` §§ 5.1, 6.3 (matrix rows for RFC 791 / 792 / 1122 / 1191), §8 (ARP bullet), §9.1 (IP counter group).

**Deviations from spec to call out explicitly:**
- Spec §8 says "static gateway MAC seeded at startup via netlink helper". This plan implements a **read-`/proc/net/arp`** helper instead of real netlink (simpler, no crate dependency, same behavior for TAP and kernel-visible NICs). Users targeting vfio-pci NICs without a kernel ARP entry must pass `gateway_mac` in the config directly; the resolver helper is a convenience for kernel-visible interfaces.
- Spec §8 says "gratuitous-ARP refresh timer every N seconds". Phase A2 implements this as a naïve poll-loop check (`if now − last_garp ≥ interval { emit; }`). The real timer-wheel implementation arrives in A6; switching to it is a ~3-line change in `poll_once`.

---

## File Structure Created or Modified in This Phase

```
crates/dpdk-net-core/src/
├── lib.rs           (MODIFIED: expose l2, l3_ip, icmp, arp modules)
├── counters.rs      (MODIFIED: extend EthCounters + IpCounters)
├── engine.rs        (MODIFIED: our_mac/our_ip/gateway fields, new poll_once dispatch)
├── error.rs         (MODIFIED: new variants for MAC lookup + ARP resolve failure)
├── l2.rs            (NEW)
├── l3_ip.rs         (NEW)
├── icmp.rs          (NEW)
└── arp.rs           (NEW)

crates/dpdk-net-core/tests/
├── engine_smoke.rs  (no change — A1 lifecycle test still valid)
└── l2_l3_tap.rs     (NEW: crafted-frame integration test over TAP pair)

crates/dpdk-net/src/
├── lib.rs           (MODIFIED: dpdk_net_resolve_gateway_mac extern "C")
└── api.rs           (MODIFIED: extend dpdk_net_engine_config_t + counter structs)

crates/dpdk-net-sys/
├── shim.c           (MODIFIED: rte_pktmbuf_alloc + rte_pktmbuf_append wrappers)
└── wrapper.h        (MODIFIED: shim prototypes)

include/dpdk_net.h   (REGENERATED via cbindgen)

examples/cpp-consumer/main.cpp  (MODIFIED: print IP counters)

docs/superpowers/plans/stage1-phase-roadmap.md  (MODIFIED: status update at A2 sign-off)
```

---

## Task 1: Extend counter schema for L2/L3 drop + accept reasons

**Goal:** Add the new counters Phase A2 will write. Reuse `_pad` slots so the ABI size is unchanged; the layout-assertion `const _: ()` in `api.rs` will enforce exact match between core and public structs.

**Files:**
- Modify: `crates/dpdk-net-core/src/counters.rs`
- Modify: `crates/dpdk-net/src/api.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-core/src/counters.rs` (inside `mod tests`):

```rust
    #[test]
    fn a2_new_counters_exist_and_zero() {
        let c = Counters::new();
        // eth additions
        assert_eq!(c.eth.rx_drop_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_drop_unknown_ethertype.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.rx_arp.load(Ordering::Relaxed), 0);
        assert_eq!(c.eth.tx_arp.load(Ordering::Relaxed), 0);
        // ip additions
        assert_eq!(c.ip.rx_drop_short.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_bad_version.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_bad_hl.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_not_ours.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_drop_unsupported_proto.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_tcp.load(Ordering::Relaxed), 0);
        assert_eq!(c.ip.rx_icmp.load(Ordering::Relaxed), 0);
    }
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cargo test -p dpdk-net-core counters::tests::a2_new_counters_exist_and_zero`
Expected: FAIL at compile: "no field `rx_drop_short` on `EthCounters`" (and similar for other fields).

- [ ] **Step 3: Extend `EthCounters` and `IpCounters` in `crates/dpdk-net-core/src/counters.rs`**

Replace the existing `EthCounters` struct:

```rust
#[repr(C, align(64))]
pub struct EthCounters {
    pub rx_pkts: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rx_drop_miss_mac: AtomicU64,
    pub rx_drop_nomem: AtomicU64,
    pub tx_pkts: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub tx_drop_full_ring: AtomicU64,
    pub tx_drop_nomem: AtomicU64,
    // Phase A2 additions
    pub rx_drop_short: AtomicU64,
    pub rx_drop_unknown_ethertype: AtomicU64,
    pub rx_arp: AtomicU64,
    pub tx_arp: AtomicU64,
    _pad: [u64; 4],
}
```

Replace the existing `IpCounters` struct:

```rust
#[repr(C, align(64))]
pub struct IpCounters {
    pub rx_csum_bad: AtomicU64,
    pub rx_ttl_zero: AtomicU64,
    pub rx_frag: AtomicU64,
    pub rx_icmp_frag_needed: AtomicU64,
    pub pmtud_updates: AtomicU64,
    // Phase A2 additions
    pub rx_drop_short: AtomicU64,
    pub rx_drop_bad_version: AtomicU64,
    pub rx_drop_bad_hl: AtomicU64,
    pub rx_drop_not_ours: AtomicU64,
    pub rx_drop_unsupported_proto: AtomicU64,
    pub rx_tcp: AtomicU64,
    pub rx_icmp: AtomicU64,
    _pad: [u64; 4],
}
```

- [ ] **Step 4: Mirror into public API** — modify `crates/dpdk-net/src/api.rs`

Replace `dpdk_net_eth_counters_t`:

```rust
#[repr(C, align(64))]
pub struct dpdk_net_eth_counters_t {
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub rx_drop_miss_mac: u64,
    pub rx_drop_nomem: u64,
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    pub tx_drop_full_ring: u64,
    pub tx_drop_nomem: u64,
    // Phase A2 additions
    pub rx_drop_short: u64,
    pub rx_drop_unknown_ethertype: u64,
    pub rx_arp: u64,
    pub tx_arp: u64,
    pub _pad: [u64; 4],
}
```

Replace `dpdk_net_ip_counters_t`:

```rust
#[repr(C, align(64))]
pub struct dpdk_net_ip_counters_t {
    pub rx_csum_bad: u64,
    pub rx_ttl_zero: u64,
    pub rx_frag: u64,
    pub rx_icmp_frag_needed: u64,
    pub pmtud_updates: u64,
    // Phase A2 additions
    pub rx_drop_short: u64,
    pub rx_drop_bad_version: u64,
    pub rx_drop_bad_hl: u64,
    pub rx_drop_not_ours: u64,
    pub rx_drop_unsupported_proto: u64,
    pub rx_tcp: u64,
    pub rx_icmp: u64,
    pub _pad: [u64; 4],
}
```

- [ ] **Step 5: Run both crates' tests**

Run: `cargo test -p dpdk-net-core counters::tests && cargo test -p dpdk-net api`
Expected: PASS. The layout-assertion `const _: ()` in `api.rs` guarantees size/alignment parity; if it fails, recheck `_pad` counts.

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-core/src/counters.rs crates/dpdk-net/src/api.rs
git commit -m "extend eth + ip counter groups for phase a2 drop/accept reasons"
```

---

## Task 2: Extend `EngineConfig` with L2/L3 addressing fields

**Goal:** Carry `local_ip`, `gateway_ip`, `gateway_mac`, and `garp_interval_sec` from caller to engine. Config is in **host byte order** for integers; MAC is a plain 6-byte array.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Write the failing test**

Append to the bottom of `crates/dpdk-net-core/src/engine.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_engine_config_has_a2_fields() {
        let cfg = EngineConfig::default();
        // Unset (caller must supply for real use).
        assert_eq!(cfg.local_ip, 0);
        assert_eq!(cfg.gateway_ip, 0);
        assert_eq!(cfg.gateway_mac, [0u8; 6]);
        // 0 = disabled (no gratuitous ARP emitted).
        assert_eq!(cfg.garp_interval_sec, 0);
    }
}
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net-core engine::tests::default_engine_config_has_a2_fields`
Expected: FAIL at compile: "no field `local_ip` on type `EngineConfig`".

- [ ] **Step 3: Edit the `EngineConfig` struct**

Replace the existing `EngineConfig` in `crates/dpdk-net-core/src/engine.rs`:

```rust
/// Config passed to Engine::new.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub lcore_id: u16,
    pub port_id: u16,
    pub rx_queue_id: u16,
    pub tx_queue_id: u16,
    pub rx_ring_size: u16,     // default 1024
    pub tx_ring_size: u16,     // default 1024
    pub rx_mempool_elems: u32, // default 8192
    pub mbuf_data_room: u16,   // default 2048

    // Phase A2 additions (host byte order for IPs; raw bytes for MAC)
    pub local_ip: u32,         // our IPv4 on this lcore's port; 0 = "accept any" in tests
    pub gateway_ip: u32,       // next-hop IPv4
    pub gateway_mac: [u8; 6],  // MAC to target for TX; [0;6] = "resolve at create"
    pub garp_interval_sec: u32,// 0 = disabled; else emit gratuitous ARP every N seconds
}
```

Replace `Default::default`:

```rust
impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            lcore_id: 0,
            port_id: 0,
            rx_queue_id: 0,
            tx_queue_id: 0,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            rx_mempool_elems: 8192,
            mbuf_data_room: 2048,
            local_ip: 0,
            gateway_ip: 0,
            gateway_mac: [0u8; 6],
            garp_interval_sec: 0,
        }
    }
}
```

- [ ] **Step 4: Run test — verify PASS**

Run: `cargo test -p dpdk-net-core engine::tests::default_engine_config_has_a2_fields`
Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "add local_ip, gateway_ip, gateway_mac, garp_interval_sec to EngineConfig"
```

---

## Task 3: Mirror A2 config fields into the public C ABI

**Goal:** Same fields on the public `dpdk_net_engine_config_t`. Keep the field order matching `EngineConfig` for consistency. The bridging function in `dpdk-net/src/lib.rs` copies them through.

**Files:**
- Modify: `crates/dpdk-net/src/api.rs`
- Modify: `crates/dpdk-net/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net/src/lib.rs` inside `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn a2_config_fields_pass_through() {
        // We don't actually call dpdk_net_engine_create here (no EAL).
        // Just assert the types are laid out as we expect.
        let cfg = dpdk_net_engine_config_t {
            port_id: 0,
            rx_queue_id: 0,
            tx_queue_id: 0,
            max_connections: 0,
            recv_buffer_bytes: 0,
            send_buffer_bytes: 0,
            tcp_mss: 0,
            tcp_timestamps: false,
            tcp_sack: false,
            tcp_ecn: false,
            tcp_nagle: false,
            tcp_delayed_ack: false,
            cc_mode: 0,
            tcp_min_rto_ms: 0,
            tcp_initial_rto_ms: 0,
            tcp_msl_ms: 0,
            tcp_per_packet_events: false,
            preset: 0,
            local_ip: 0x0a_00_00_02, // 10.0.0.2 (host byte order)
            gateway_ip: 0x0a_00_00_01,
            gateway_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            garp_interval_sec: 5,
        };
        assert_eq!(cfg.local_ip, 0x0a_00_00_02);
        assert_eq!(cfg.gateway_mac[2], 0xbe);
        assert_eq!(cfg.garp_interval_sec, 5);
    }
```

- [ ] **Step 2: Run — verify it fails**

Run: `cargo test -p dpdk-net tests::a2_config_fields_pass_through`
Expected: FAIL at compile: "struct `dpdk_net_engine_config_t` has no field `local_ip`".

- [ ] **Step 3: Extend the public config in `crates/dpdk-net/src/api.rs`**

Replace `dpdk_net_engine_config_t`:

```rust
#[repr(C)]
pub struct dpdk_net_engine_config_t {
    pub port_id: u16,
    pub rx_queue_id: u16,
    pub tx_queue_id: u16,
    pub max_connections: u32,
    pub recv_buffer_bytes: u32,
    pub send_buffer_bytes: u32,
    pub tcp_mss: u32,
    pub tcp_timestamps: bool,
    pub tcp_sack: bool,
    pub tcp_ecn: bool,
    pub tcp_nagle: bool,
    pub tcp_delayed_ack: bool,
    pub cc_mode: u8,
    pub tcp_min_rto_ms: u32,
    pub tcp_initial_rto_ms: u32,
    pub tcp_msl_ms: u32,
    pub tcp_per_packet_events: bool,
    pub preset: u8,
    // Phase A2 additions (host byte order for ints, raw bytes for MAC)
    pub local_ip: u32,
    pub gateway_ip: u32,
    pub gateway_mac: [u8; 6],
    pub garp_interval_sec: u32,
}
```

- [ ] **Step 4: Bridge the new fields in `crates/dpdk-net/src/lib.rs`**

Replace the body of `dpdk_net_engine_create`:

```rust
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_engine_create(
    lcore_id: u16,
    cfg: *const dpdk_net_engine_config_t,
) -> *mut dpdk_net_engine {
    if cfg.is_null() {
        return ptr::null_mut();
    }
    let cfg = &*cfg;
    let core_cfg = EngineConfig {
        lcore_id,
        port_id: cfg.port_id,
        rx_queue_id: cfg.rx_queue_id,
        tx_queue_id: cfg.tx_queue_id,
        rx_ring_size: 1024,
        tx_ring_size: 1024,
        rx_mempool_elems: 8192,
        mbuf_data_room: 2048,
        local_ip: cfg.local_ip,
        gateway_ip: cfg.gateway_ip,
        gateway_mac: cfg.gateway_mac,
        garp_interval_sec: cfg.garp_interval_sec,
    };
    match Engine::new(core_cfg) {
        Ok(e) => box_to_raw(e),
        Err(_) => ptr::null_mut(),
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p dpdk-net`
Expected: PASS on all.

- [ ] **Step 6: Update the existing FFI smoke test struct layout**

Modify `tests/ffi-test/tests/ffi_smoke.rs` — update the `Cfg` shim struct to match the new layout. Replace the `Cfg` struct and its initialization inside `ffi_eal_init_and_engine_lifecycle`:

```rust
    #[repr(C)]
    struct Cfg {
        port_id: u16,
        rx_queue_id: u16,
        tx_queue_id: u16,
        _pad1: u16,
        max_connections: u32,
        recv_buffer_bytes: u32,
        send_buffer_bytes: u32,
        tcp_mss: u32,
        tcp_timestamps: bool,
        tcp_sack: bool,
        tcp_ecn: bool,
        tcp_nagle: bool,
        tcp_delayed_ack: bool,
        cc_mode: u8,
        _pad2: [u8; 2],
        tcp_min_rto_ms: u32,
        tcp_initial_rto_ms: u32,
        tcp_msl_ms: u32,
        tcp_per_packet_events: bool,
        preset: u8,
        _pad3: [u8; 2],
        // Phase A2 additions
        local_ip: u32,
        gateway_ip: u32,
        gateway_mac: [u8; 6],
        _pad4: [u8; 2],
        garp_interval_sec: u32,
    }
    let cfg = Cfg {
        port_id: 0,
        rx_queue_id: 0,
        tx_queue_id: 0,
        _pad1: 0,
        max_connections: 16,
        recv_buffer_bytes: 256 * 1024,
        send_buffer_bytes: 256 * 1024,
        tcp_mss: 0,
        tcp_timestamps: true,
        tcp_sack: true,
        tcp_ecn: false,
        tcp_nagle: false,
        tcp_delayed_ack: false,
        cc_mode: 0,
        _pad2: [0; 2],
        tcp_min_rto_ms: 20,
        tcp_initial_rto_ms: 50,
        tcp_msl_ms: 30000,
        tcp_per_packet_events: false,
        preset: 0,
        _pad3: [0; 2],
        local_ip: 0,
        gateway_ip: 0,
        gateway_mac: [0u8; 6],
        _pad4: [0; 2],
        garp_interval_sec: 0,
    };
```

Note: all-zero A2 fields means "TAP test bypasses addressing" — A1 lifecycle test still passes because Phase A2's poll loop treats `local_ip==0` as "accept any destination" (§ Task 10 below).

- [ ] **Step 7: Run the non-TAP ffi test**

Run: `cargo test -p ffi-test ffi_handles_null_safely`
Expected: PASS.

- [ ] **Step 8: Commit**

```sh
git add crates/dpdk-net/src/api.rs crates/dpdk-net/src/lib.rs tests/ffi-test/tests/ffi_smoke.rs
git commit -m "add local_ip, gateway_ip, gateway_mac, garp_interval_sec to public config"
```

---

## Task 4: `l2.rs` — Ethernet frame decoder

**Goal:** Pure-function Ethernet header parser operating on a `&[u8]` view. No DPDK dependency. Returns a typed `L2Decoded` with the ethertype + payload slice offset, or a typed drop reason the caller maps to a counter.

**Files:**
- Create: `crates/dpdk-net-core/src/l2.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Create `crates/dpdk-net-core/src/l2.rs`:

```rust
//! L2 Ethernet frame decoder. Operates on a raw byte slice (typically the
//! mbuf data region). No allocation. Pure. Each decision is counter-grade
//! (one counter per drop reason) so the caller can attribute every drop.

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETH_HDR_LEN: usize = 14;
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Decoded {
    pub ethertype: u16,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub payload_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Drop {
    Short,           // frame shorter than 14 bytes
    MissMac,         // dst MAC is not us and not broadcast
    UnknownEthertype,// neither IPv4 nor ARP
}

/// Decode an Ethernet II frame. Accepts broadcast (ff:ff:ff:ff:ff:ff) for ARP.
/// Non-broadcast multicast is classified as MissMac (we don't join groups in Stage 1).
/// `our_mac = [0;6]` is test mode — accept any unicast destination.
pub fn l2_decode(frame: &[u8], our_mac: [u8; 6]) -> Result<L2Decoded, L2Drop> {
    if frame.len() < ETH_HDR_LEN {
        return Err(L2Drop::Short);
    }
    let mut dst = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    let mut src = [0u8; 6];
    src.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

    let is_broadcast = dst == BROADCAST_MAC;
    let is_us = our_mac != [0u8; 6] && dst == our_mac;
    let is_any = our_mac == [0u8; 6]; // test/open-mode
    if !(is_broadcast || is_us || is_any) {
        return Err(L2Drop::MissMac);
    }

    if ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_ARP {
        return Err(L2Drop::UnknownEthertype);
    }

    Ok(L2Decoded {
        ethertype,
        src_mac: src,
        dst_mac: dst,
        payload_offset: ETH_HDR_LEN,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(dst: [u8; 6], src: [u8; 6], et: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(14 + payload.len());
        v.extend_from_slice(&dst);
        v.extend_from_slice(&src);
        v.extend_from_slice(&et.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn short_frame_dropped() {
        assert_eq!(l2_decode(&[0u8; 10], [1; 6]), Err(L2Drop::Short));
    }

    #[test]
    fn wrong_dst_mac_dropped() {
        let us = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let wrong = [0xaa; 6];
        let f = frame(wrong, [0; 6], ETHERTYPE_IPV4, &[]);
        assert_eq!(l2_decode(&f, us), Err(L2Drop::MissMac));
    }

    #[test]
    fn correct_dst_mac_accepted() {
        let us = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let f = frame(us, [0; 6], ETHERTYPE_IPV4, &[0xde, 0xad]);
        let d = l2_decode(&f, us).expect("accepted");
        assert_eq!(d.ethertype, ETHERTYPE_IPV4);
        assert_eq!(d.payload_offset, 14);
    }

    #[test]
    fn broadcast_accepted_for_arp() {
        let us = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let f = frame(BROADCAST_MAC, [0; 6], ETHERTYPE_ARP, &[]);
        assert!(l2_decode(&f, us).is_ok());
    }

    #[test]
    fn unknown_ethertype_dropped() {
        let us = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let f = frame(us, [0; 6], 0x86DD, &[]); // IPv6
        assert_eq!(l2_decode(&f, us), Err(L2Drop::UnknownEthertype));
    }

    #[test]
    fn zero_our_mac_accepts_any() {
        let dst = [0x99; 6];
        let f = frame(dst, [0; 6], ETHERTYPE_IPV4, &[]);
        assert!(l2_decode(&f, [0; 6]).is_ok());
    }
}
```

- [ ] **Step 2: Expose the module** in `crates/dpdk-net-core/src/lib.rs` (prepend inside module list):

```rust
pub mod l2;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core l2::`
Expected: 6 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/l2.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add l2.rs Ethernet decoder + unit tests for drop reasons"
```

---

## Task 5: `l3_ip.rs` — IPv4 header decoder + checksum

**Goal:** Parse IPv4 headers from a byte slice. Verify the header checksum when the caller signals the NIC didn't. Drop fragments and count them. Drop non-our destination unless `our_ip == 0` (test mode).

**Files:**
- Create: `crates/dpdk-net-core/src/l3_ip.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Create `crates/dpdk-net-core/src/l3_ip.rs`:

```rust
//! IPv4 decode. Operates on the Ethernet payload (slice starting at the IP
//! header). Returns the decoded header or a drop reason. Checksum is
//! verified only when the NIC didn't (caller passes `nic_csum_ok=true` to
//! skip). Fragments are never accepted — spec §6.3 defers IPv4 reassembly.

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L3Decoded {
    pub protocol: u8,
    pub src_ip: u32,  // host byte order
    pub dst_ip: u32,  // host byte order
    pub header_len: usize,
    pub total_len: usize,
    pub ttl: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3Drop {
    Short,             // fewer than 20 bytes
    BadVersion,        // version != 4
    BadHeaderLen,      // IHL < 5 or header extends past slice
    BadTotalLen,       // total_length < header_len or > slice
    CsumBad,           // checksum verify failed
    TtlZero,           // TTL == 0 on ingress (RFC 791; we drop rather than send ICMP)
    Fragment,          // MF=1 or frag_offset != 0
    NotOurs,           // dst_ip != our_ip (and our_ip != 0)
    UnsupportedProto,  // protocol is not TCP and not ICMP
}

/// Compute the Internet checksum (RFC 1071) over a byte slice.
/// Caller supplies the slice containing the IP header exactly.
pub fn internet_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum = sum.wrapping_add(u16::from_be_bytes([buf[i], buf[i + 1]]) as u32);
        i += 2;
    }
    if i < buf.len() {
        sum = sum.wrapping_add((buf[i] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Decode an IPv4 packet. `our_ip` in host byte order; 0 = accept any dst.
/// `nic_csum_ok`: when true the caller promises the NIC's HW csum passed.
pub fn ip_decode(pkt: &[u8], our_ip: u32, nic_csum_ok: bool) -> Result<L3Decoded, L3Drop> {
    if pkt.len() < 20 {
        return Err(L3Drop::Short);
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return Err(L3Drop::BadVersion);
    }
    let ihl = (pkt[0] & 0x0f) as usize;
    let header_len = ihl * 4;
    if ihl < 5 || header_len > pkt.len() {
        return Err(L3Drop::BadHeaderLen);
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < header_len || total_len > pkt.len() {
        return Err(L3Drop::BadTotalLen);
    }
    // Fragment detection: the flags+fragoffset field is bytes 6..8; bit 13
    // from the MSB is MF (More Fragments), low 13 bits are the offset.
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let mf = (flags_frag & 0x2000) != 0;
    let frag_off = flags_frag & 0x1fff;
    if mf || frag_off != 0 {
        return Err(L3Drop::Fragment);
    }
    let ttl = pkt[8];
    if ttl == 0 {
        return Err(L3Drop::TtlZero);
    }
    // Checksum: verify only when NIC didn't. Zero the checksum bytes in a
    // scratch copy and fold — the computed value should equal what's in the
    // header.
    if !nic_csum_ok {
        let mut scratch = [0u8; 60]; // max IP header length
        scratch[..header_len].copy_from_slice(&pkt[..header_len]);
        scratch[10] = 0;
        scratch[11] = 0;
        let computed = internet_checksum(&scratch[..header_len]);
        let stored = u16::from_be_bytes([pkt[10], pkt[11]]);
        if computed != stored {
            return Err(L3Drop::CsumBad);
        }
    }
    let protocol = pkt[9];
    let src_ip = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    let dst_ip = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
    if our_ip != 0 && dst_ip != our_ip {
        return Err(L3Drop::NotOurs);
    }
    if protocol != IPPROTO_TCP && protocol != IPPROTO_ICMP {
        return Err(L3Drop::UnsupportedProto);
    }
    Ok(L3Decoded {
        protocol,
        src_ip,
        dst_ip,
        header_len,
        total_len,
        ttl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid IPv4 header with an optional wrong-checksum flag.
    fn build_ip_hdr(
        proto: u8,
        src: u32,
        dst: u32,
        payload_len: usize,
        bad_csum: bool,
    ) -> Vec<u8> {
        let total = 20 + payload_len;
        let mut v = vec![
            0x45,                      // version 4, IHL 5
            0x00,                      // DSCP/ECN
            (total >> 8) as u8,
            (total & 0xff) as u8,      // total length
            0x00, 0x01,                // identification
            0x40, 0x00,                // flags=DF, fragment offset 0
            0x40,                      // TTL 64
            proto,                     // protocol
            0x00, 0x00,                // checksum placeholder
        ];
        v.extend_from_slice(&src.to_be_bytes());
        v.extend_from_slice(&dst.to_be_bytes());
        let cksum = internet_checksum(&v);
        v[10] = (cksum >> 8) as u8;
        v[11] = (cksum & 0xff) as u8;
        if bad_csum {
            v[10] ^= 0xff; // corrupt
        }
        v.resize(total, 0);
        v
    }

    #[test]
    fn checksum_folds_correctly() {
        let h = build_ip_hdr(IPPROTO_TCP, 0x0a000001, 0x0a000002, 0, false);
        // Scratch-zero csum bytes, recompute, compare against stored.
        let mut s = h[..20].to_vec();
        s[10] = 0;
        s[11] = 0;
        let computed = internet_checksum(&s);
        let stored = u16::from_be_bytes([h[10], h[11]]);
        assert_eq!(computed, stored);
    }

    #[test]
    fn short_packet_dropped() {
        assert_eq!(ip_decode(&[0u8; 10], 0, true), Err(L3Drop::Short));
    }

    #[test]
    fn bad_version_dropped() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[0] = 0x65; // version 6
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::BadVersion));
    }

    #[test]
    fn bad_header_len_dropped() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[0] = 0x44; // IHL 4
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::BadHeaderLen));
    }

    #[test]
    fn fragment_dropped_mf() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[6] = 0x20; // set MF bit
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::Fragment));
    }

    #[test]
    fn fragment_dropped_offset() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[6] = 0x00;
        h[7] = 0x01; // offset=1
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::Fragment));
    }

    #[test]
    fn ttl_zero_dropped() {
        let mut h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        h[8] = 0;
        // need to refresh csum after editing TTL
        h[10] = 0;
        h[11] = 0;
        let cks = internet_checksum(&h[..20]);
        h[10] = (cks >> 8) as u8;
        h[11] = (cks & 0xff) as u8;
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::TtlZero));
    }

    #[test]
    fn bad_csum_dropped_when_verifying() {
        let h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, true);
        assert_eq!(ip_decode(&h, 0, false), Err(L3Drop::CsumBad));
    }

    #[test]
    fn bad_csum_passes_when_nic_ok() {
        let h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, true);
        assert!(ip_decode(&h, 0, true).is_ok());
    }

    #[test]
    fn not_ours_dropped() {
        let h = build_ip_hdr(IPPROTO_TCP, 1, 2, 0, false);
        assert_eq!(ip_decode(&h, 99, true), Err(L3Drop::NotOurs));
    }

    #[test]
    fn unsupported_proto_dropped() {
        let h = build_ip_hdr(17 /* UDP */, 1, 2, 0, false);
        assert_eq!(ip_decode(&h, 0, true), Err(L3Drop::UnsupportedProto));
    }

    #[test]
    fn tcp_accepted() {
        let h = build_ip_hdr(IPPROTO_TCP, 1, 2, 10, false);
        let d = ip_decode(&h, 0, true).expect("accepted");
        assert_eq!(d.protocol, IPPROTO_TCP);
        assert_eq!(d.header_len, 20);
        assert_eq!(d.total_len, 30);
    }

    #[test]
    fn icmp_accepted() {
        let h = build_ip_hdr(IPPROTO_ICMP, 1, 2, 4, false);
        let d = ip_decode(&h, 0, true).expect("accepted");
        assert_eq!(d.protocol, IPPROTO_ICMP);
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`:

```rust
pub mod l3_ip;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core l3_ip::`
Expected: 13 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/l3_ip.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add l3_ip.rs IPv4 decoder + RFC 1071 checksum + fragment/TTL handling"
```

---

## Task 6: `icmp.rs` — ICMP frag-needed → PMTU table

**Goal:** Parse ICMP Type 3 Code 4 (Destination Unreachable / Fragmentation Needed, RFC 1191). Extract the "Next-Hop MTU" from the ICMP header and store in a per-peer-IP PMTU table. Drop all other ICMP types silently (spec §6.3 RFC 792 row).

**Files:**
- Create: `crates/dpdk-net-core/src/icmp.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Create `crates/dpdk-net-core/src/icmp.rs`:

```rust
//! ICMP input — we only react to Type 3 Code 4 (Fragmentation Needed /
//! DF Set) per RFC 1191. Everything else is silently dropped (spec §6.3 RFC
//! 792 row). The output is a PMTU update for the ORIGINAL destination (the
//! IP in the ICMP payload's embedded header's dst_ip field), NOT the ICMP
//! sender — the ICMP came from an intermediate router, so src_ip of the
//! outer packet is useless for PMTU attribution.

use std::collections::HashMap;

pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_CODE_FRAG_NEEDED: u8 = 4;

pub const IPV4_MIN_MTU: u16 = 68; // RFC 791: every host must accept ≥ 68-byte datagrams

#[derive(Debug, Default)]
pub struct PmtuTable {
    /// Key: destination IPv4 (host byte order) of the packet that triggered
    /// the ICMP. Value: next-hop MTU learned from the router's reply.
    entries: HashMap<u32, u16>,
}

impl PmtuTable {
    pub fn new() -> Self { Self::default() }

    pub fn get(&self, ip: u32) -> Option<u16> { self.entries.get(&ip).copied() }

    /// Update the PMTU for `ip`. Returns `true` if this updated or
    /// inserted an entry (caller bumps pmtud_updates counter).
    /// Floors at IPV4_MIN_MTU. Declines to grow (PMTU only shrinks).
    pub fn update(&mut self, ip: u32, mtu: u16) -> bool {
        let mtu = mtu.max(IPV4_MIN_MTU);
        let entry = self.entries.entry(ip).or_insert(u16::MAX);
        if mtu < *entry {
            *entry = mtu;
            true
        } else {
            false
        }
    }
}

/// Result classification for the caller's counter path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpResult {
    FragNeededPmtuUpdated,   // found, stored; caller bumps ip.rx_icmp_frag_needed + ip.pmtud_updates
    FragNeededNoShrink,      // found, but no-op (MTU not smaller than existing); caller bumps ip.rx_icmp_frag_needed only
    OtherDropped,            // not dest-unreach-frag-needed, silently dropped
    Malformed,               // too short / inner header not recognizable
}

/// Parse ICMP starting at the IPv4 payload. `ip_payload` is the slice
/// beginning at the ICMP header (after IPv4 options). Returns the action
/// classification and mutates `pmtu` on match.
pub fn icmp_input(ip_payload: &[u8], pmtu: &mut PmtuTable) -> IcmpResult {
    // ICMP header: type(1) code(1) csum(2) rest_of_header(4) ...
    if ip_payload.len() < 8 {
        return IcmpResult::Malformed;
    }
    let ty = ip_payload[0];
    let code = ip_payload[1];
    if ty != ICMP_DEST_UNREACH || code != ICMP_CODE_FRAG_NEEDED {
        return IcmpResult::OtherDropped;
    }
    // RFC 1191 layout: bytes 4..6 reserved, bytes 6..8 next-hop MTU.
    let next_hop_mtu = u16::from_be_bytes([ip_payload[6], ip_payload[7]]);
    // After the 8-byte ICMP header, the embedded original IP header starts.
    // We need at least 20 bytes of IPv4 header + 8 bytes of original transport.
    if ip_payload.len() < 8 + 20 {
        return IcmpResult::Malformed;
    }
    let inner = &ip_payload[8..];
    let version = inner[0] >> 4;
    let ihl = (inner[0] & 0x0f) as usize;
    if version != 4 || ihl < 5 || inner.len() < ihl * 4 {
        return IcmpResult::Malformed;
    }
    let inner_dst = u32::from_be_bytes([inner[16], inner[17], inner[18], inner[19]]);
    // next_hop_mtu == 0 means the router doesn't support RFC 1191 — fall back
    // to RFC 4821 PLPMTUD territory (out of Stage 1 scope). Spec §10.8 notes
    // this as Stage 2. For A2, we treat it as malformed.
    if next_hop_mtu == 0 {
        return IcmpResult::Malformed;
    }
    if pmtu.update(inner_dst, next_hop_mtu) {
        IcmpResult::FragNeededPmtuUpdated
    } else {
        IcmpResult::FragNeededNoShrink
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_inner_ip(dst: u32) -> Vec<u8> {
        let mut v = vec![
            0x45, 0x00,
            0x00, 0x14, // total_length = 20
            0, 0,
            0x40, 0x00, // DF
            0x40, 6,    // TTL 64, proto TCP
            0, 0,       // csum
            0, 0, 0, 0, // src
            0, 0, 0, 0, // dst
        ];
        v[16..20].copy_from_slice(&dst.to_be_bytes());
        v
    }

    fn build_icmp_frag(mtu: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = vec![
            ICMP_DEST_UNREACH,
            ICMP_CODE_FRAG_NEEDED,
            0x00, 0x00,      // csum (not verified by icmp_input)
            0x00, 0x00,      // unused
            (mtu >> 8) as u8, (mtu & 0xff) as u8,
        ];
        v.extend_from_slice(inner);
        v
    }

    #[test]
    fn pmtu_update_floors_to_min_mtu() {
        let mut t = PmtuTable::new();
        assert!(t.update(0x0a000001, 32));
        assert_eq!(t.get(0x0a000001), Some(IPV4_MIN_MTU));
    }

    #[test]
    fn pmtu_update_only_shrinks() {
        let mut t = PmtuTable::new();
        assert!(t.update(0x0a000001, 1400));
        assert!(!t.update(0x0a000001, 1500)); // grow rejected
        assert_eq!(t.get(0x0a000001), Some(1400));
        assert!(t.update(0x0a000001, 1280)); // shrink accepted
        assert_eq!(t.get(0x0a000001), Some(1280));
    }

    #[test]
    fn too_short_malformed() {
        let mut t = PmtuTable::new();
        assert_eq!(icmp_input(&[0u8; 4], &mut t), IcmpResult::Malformed);
    }

    #[test]
    fn other_icmp_dropped() {
        let mut t = PmtuTable::new();
        let payload = [8u8, 0, 0, 0, 0, 0, 0, 0]; // echo request
        assert_eq!(icmp_input(&payload, &mut t), IcmpResult::OtherDropped);
    }

    #[test]
    fn frag_needed_updates_pmtu() {
        let inner = build_inner_ip(0x0a000050);
        let pkt = build_icmp_frag(1400, &inner);
        let mut t = PmtuTable::new();
        assert_eq!(icmp_input(&pkt, &mut t), IcmpResult::FragNeededPmtuUpdated);
        assert_eq!(t.get(0x0a000050), Some(1400));
    }

    #[test]
    fn frag_needed_second_identical_is_no_shrink() {
        let inner = build_inner_ip(0x0a000050);
        let pkt = build_icmp_frag(1400, &inner);
        let mut t = PmtuTable::new();
        let _ = icmp_input(&pkt, &mut t);
        assert_eq!(icmp_input(&pkt, &mut t), IcmpResult::FragNeededNoShrink);
    }

    #[test]
    fn zero_mtu_malformed() {
        let inner = build_inner_ip(0x0a000050);
        let pkt = build_icmp_frag(0, &inner);
        let mut t = PmtuTable::new();
        assert_eq!(icmp_input(&pkt, &mut t), IcmpResult::Malformed);
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`:

```rust
pub mod icmp;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core icmp::`
Expected: 7 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/icmp.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add icmp.rs frag-needed parser + per-peer PMTU table"
```

---

## Task 7: `arp.rs` — ARP decode, ARP-reply build, gratuitous ARP build

**Goal:** ARP packet decoding (request + reply); builder for an ARP reply given our MAC/IP and the inbound request's sender; builder for a gratuitous ARP (announces our IP→MAC mapping so gateways pin their cache).

**Files:**
- Create: `crates/dpdk-net-core/src/arp.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Create `crates/dpdk-net-core/src/arp.rs`:

```rust
//! ARP (RFC 826) — static-gateway mode. We don't run a dynamic resolver on
//! the data path; the gateway MAC is supplied via config (or resolved
//! out-of-band). What this module provides:
//!   - decode inbound ARP (to recognize requests for our IP, and to read
//!     gratuitous replies that refresh the gateway's MAC)
//!   - build an ARP reply (so we remain reachable — peers' ARP caches
//!     expire ours if we never answer)
//!   - build a gratuitous ARP announcement (our periodic "I'm still here"
//!     per spec §8)
//!
//! All builders produce complete L2+ARP frames (42 bytes: 14 Eth + 28 ARP).

pub const ARP_HDR_LEN: usize = 28;
pub const ARP_FRAME_LEN: usize = 14 + ARP_HDR_LEN;
pub const ARP_HTYPE_ETH: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: u32,
    pub target_mac: [u8; 6],
    pub target_ip: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpDrop {
    Short,
    UnsupportedHardware,
    UnsupportedProtocol,
    UnsupportedOp,
}

/// Decode ARP starting at the Ethernet payload (28-byte ARP header).
pub fn arp_decode(eth_payload: &[u8]) -> Result<ArpPacket, ArpDrop> {
    if eth_payload.len() < ARP_HDR_LEN {
        return Err(ArpDrop::Short);
    }
    let htype = u16::from_be_bytes([eth_payload[0], eth_payload[1]]);
    let ptype = u16::from_be_bytes([eth_payload[2], eth_payload[3]]);
    let hlen = eth_payload[4];
    let plen = eth_payload[5];
    if htype != ARP_HTYPE_ETH || hlen != 6 {
        return Err(ArpDrop::UnsupportedHardware);
    }
    if ptype != ARP_PTYPE_IPV4 || plen != 4 {
        return Err(ArpDrop::UnsupportedProtocol);
    }
    let op = u16::from_be_bytes([eth_payload[6], eth_payload[7]]);
    if op != ARP_OP_REQUEST && op != ARP_OP_REPLY {
        return Err(ArpDrop::UnsupportedOp);
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&eth_payload[8..14]);
    let sender_ip = u32::from_be_bytes([
        eth_payload[14], eth_payload[15], eth_payload[16], eth_payload[17],
    ]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&eth_payload[18..24]);
    let target_ip = u32::from_be_bytes([
        eth_payload[24], eth_payload[25], eth_payload[26], eth_payload[27],
    ]);
    Ok(ArpPacket { op, sender_mac, sender_ip, target_mac, target_ip })
}

/// Build a complete Eth+ARP reply frame answering `request`.
/// Writes 42 bytes into `out`; returns 42 on success, or None if `out` is
/// too small.
pub fn build_arp_reply(
    our_mac: [u8; 6],
    our_ip: u32,
    request: &ArpPacket,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < ARP_FRAME_LEN {
        return None;
    }
    // Ethernet: dst = requester's MAC; src = us; type = ARP
    out[0..6].copy_from_slice(&request.sender_mac);
    out[6..12].copy_from_slice(&our_mac);
    out[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    // ARP body: reply announcing our_ip → our_mac
    write_arp_body(
        &mut out[14..],
        ARP_OP_REPLY,
        our_mac,
        our_ip,
        request.sender_mac,
        request.sender_ip,
    );
    Some(ARP_FRAME_LEN)
}

/// Build a gratuitous ARP request: sender = target = our IP; destination
/// MAC = broadcast. Peers update their ARP cache to our MAC on receipt.
pub fn build_gratuitous_arp(our_mac: [u8; 6], our_ip: u32, out: &mut [u8]) -> Option<usize> {
    if out.len() < ARP_FRAME_LEN {
        return None;
    }
    out[0..6].copy_from_slice(&[0xff; 6]); // broadcast
    out[6..12].copy_from_slice(&our_mac);
    out[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    write_arp_body(
        &mut out[14..],
        ARP_OP_REQUEST,
        our_mac,
        our_ip,
        [0u8; 6],   // target MAC unknown in gratuitous
        our_ip,     // target IP is us (that's what "gratuitous" means)
    );
    Some(ARP_FRAME_LEN)
}

fn write_arp_body(
    body: &mut [u8],
    op: u16,
    sender_mac: [u8; 6],
    sender_ip: u32,
    target_mac: [u8; 6],
    target_ip: u32,
) {
    body[0..2].copy_from_slice(&ARP_HTYPE_ETH.to_be_bytes());
    body[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    body[4] = 6;
    body[5] = 4;
    body[6..8].copy_from_slice(&op.to_be_bytes());
    body[8..14].copy_from_slice(&sender_mac);
    body[14..18].copy_from_slice(&sender_ip.to_be_bytes());
    body[18..24].copy_from_slice(&target_mac);
    body[24..28].copy_from_slice(&target_ip.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ArpPacket {
        ArpPacket {
            op: ARP_OP_REQUEST,
            sender_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            sender_ip: 0x0a_00_00_01,
            target_mac: [0u8; 6],
            target_ip: 0x0a_00_00_02,
        }
    }

    #[test]
    fn short_rejected() {
        assert_eq!(arp_decode(&[0u8; 10]), Err(ArpDrop::Short));
    }

    #[test]
    fn roundtrip_reply() {
        let req = sample_request();
        let mut buf = [0u8; ARP_FRAME_LEN];
        let n = build_arp_reply([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &req, &mut buf).unwrap();
        assert_eq!(n, ARP_FRAME_LEN);
        // Decode the ARP body portion back and verify.
        let decoded = arp_decode(&buf[14..]).expect("decode");
        assert_eq!(decoded.op, ARP_OP_REPLY);
        assert_eq!(decoded.sender_mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(decoded.sender_ip, 0x0a_00_00_02);
        assert_eq!(decoded.target_mac, req.sender_mac);
        assert_eq!(decoded.target_ip, req.sender_ip);
        // Ethernet header check
        assert_eq!(&buf[0..6], &req.sender_mac);
        assert_eq!(&buf[6..12], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&buf[12..14], &0x0806u16.to_be_bytes());
    }

    #[test]
    fn roundtrip_gratuitous() {
        let mut buf = [0u8; ARP_FRAME_LEN];
        let n = build_gratuitous_arp([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &mut buf).unwrap();
        assert_eq!(n, ARP_FRAME_LEN);
        let decoded = arp_decode(&buf[14..]).expect("decode");
        assert_eq!(decoded.op, ARP_OP_REQUEST);
        assert_eq!(decoded.sender_ip, 0x0a_00_00_02);
        assert_eq!(decoded.target_ip, 0x0a_00_00_02);
        // broadcast dst
        assert_eq!(&buf[0..6], &[0xff; 6]);
    }

    #[test]
    fn wrong_htype_rejected() {
        let mut body = [0u8; ARP_HDR_LEN];
        body[0..2].copy_from_slice(&5u16.to_be_bytes()); // bogus htype
        body[4] = 6;
        body[5] = 4;
        assert_eq!(arp_decode(&body), Err(ArpDrop::UnsupportedHardware));
    }

    #[test]
    fn wrong_op_rejected() {
        let req = sample_request();
        let mut buf = [0u8; ARP_FRAME_LEN];
        build_arp_reply([1, 2, 3, 4, 5, 6], 0x0a_00_00_02, &req, &mut buf).unwrap();
        buf[14 + 7] = 0x09; // corrupt op low byte
        assert_eq!(arp_decode(&buf[14..]), Err(ArpDrop::UnsupportedOp));
    }

    #[test]
    fn buffer_too_small_for_reply() {
        let req = sample_request();
        let mut buf = [0u8; 10];
        assert!(build_arp_reply([1; 6], 0, &req, &mut buf).is_none());
    }
}
```

- [ ] **Step 2: Expose the module** — in `crates/dpdk-net-core/src/lib.rs`:

```rust
pub mod arp;
```

- [ ] **Step 3: Run — verify PASS**

Run: `cargo test -p dpdk-net-core arp::`
Expected: 6 PASS.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/src/arp.rs crates/dpdk-net-core/src/lib.rs
git commit -m "add arp.rs packet decode + ARP reply + gratuitous ARP builders"
```

---

## Task 8: `/proc/net/arp` gateway-MAC resolver helper

**Goal:** Optional helper that parses `/proc/net/arp` to discover the MAC address for a given IPv4 (in host byte order). Allows the application to supply `gateway_mac` without knowing it up front — only works when the kernel has that ARP entry (TAP device or kernel-visible NIC). For production vfio-pci setups the application supplies `gateway_mac` directly.

**Files:**
- Modify: `crates/dpdk-net-core/src/arp.rs`
- Modify: `crates/dpdk-net-core/src/error.rs`

- [ ] **Step 1: Write failing test**

Append to `crates/dpdk-net-core/src/arp.rs` inside `mod tests`:

```rust
    #[test]
    fn parse_proc_arp_line_sample() {
        let line = "10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
        let (ip, mac) = super::parse_proc_arp_line(line).expect("parsed");
        assert_eq!(ip, 0x0a_00_00_01);
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_proc_arp_incomplete_entry_rejected() {
        // Flags 0x0 means entry is incomplete — don't use it.
        let line = "10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        assert!(super::parse_proc_arp_line(line).is_none());
    }

    #[test]
    fn resolve_from_proc_arp_missing_returns_not_found() {
        // Address we are extremely unlikely to have — 0.0.0.1 is never
        // a valid gateway and will not appear in any /proc/net/arp.
        let err = super::resolve_from_proc_arp(0x0000_0001).unwrap_err();
        assert!(matches!(err, crate::Error::GatewayMacNotFound(_)));
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net-core arp::tests::parse_proc_arp`
Expected: FAIL at compile: "cannot find function `parse_proc_arp_line`".

- [ ] **Step 3: Extend `crates/dpdk-net-core/src/error.rs`**

Add to the `Error` enum:

```rust
    #[error("gateway MAC not found in /proc/net/arp for ip {0:#x}")]
    GatewayMacNotFound(u32),
    #[error("failed to read /proc/net/arp: {0}")]
    ProcArpRead(String),
    #[error("could not read NIC MAC for port {0}: rte_errno={1}")]
    MacAddrLookup(u16, i32),
```

- [ ] **Step 4: Implement the resolver** — append to `crates/dpdk-net-core/src/arp.rs` above `#[cfg(test)]`:

```rust
/// Parse one line of `/proc/net/arp` into (ip_host_order, mac_bytes).
/// Returns None for the header line or for entries with flags==0x0
/// (incomplete).
pub(crate) fn parse_proc_arp_line(line: &str) -> Option<(u32, [u8; 6])> {
    // Columns: IPaddress  HWtype  Flags  HWaddress  Mask  Device
    let mut fields = line.split_whitespace();
    let ip = fields.next()?;
    let _hw = fields.next()?;
    let flags = fields.next()?;
    let mac = fields.next()?;

    if !flags.starts_with("0x") {
        return None;
    }
    let flags_u = u32::from_str_radix(&flags[2..], 16).ok()?;
    if flags_u & 0x2 == 0 {
        // ATF_COM bit not set — entry isn't complete.
        return None;
    }

    let mut octets = ip.split('.');
    let a = octets.next()?.parse::<u8>().ok()?;
    let b = octets.next()?.parse::<u8>().ok()?;
    let c = octets.next()?.parse::<u8>().ok()?;
    let d = octets.next()?.parse::<u8>().ok()?;
    let ip_u = u32::from_be_bytes([a, b, c, d]);

    let mut mac_bytes = [0u8; 6];
    let mut parts = mac.split(':');
    for b in &mut mac_bytes {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    Some((ip_u, mac_bytes))
}

/// Read `/proc/net/arp` and return the MAC address for `ip`.
pub fn resolve_from_proc_arp(ip: u32) -> Result<[u8; 6], crate::Error> {
    let text = std::fs::read_to_string("/proc/net/arp")
        .map_err(|e| crate::Error::ProcArpRead(e.to_string()))?;
    for line in text.lines().skip(1) {
        if let Some((entry_ip, mac)) = parse_proc_arp_line(line) {
            if entry_ip == ip {
                return Ok(mac);
            }
        }
    }
    Err(crate::Error::GatewayMacNotFound(ip))
}
```

- [ ] **Step 5: Run — verify PASS**

Run: `cargo test -p dpdk-net-core arp::`
Expected: 9 PASS (6 from Task 7 + 3 new).

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-core/src/arp.rs crates/dpdk-net-core/src/error.rs
git commit -m "add /proc/net/arp resolver helper + error variants"
```

---

## Task 9: Extend DPDK shim + sys crate for packet building + mbuf field access

**Goal:** Add C-shim wrappers for `rte_pktmbuf_alloc`, `rte_pktmbuf_append`, `rte_eth_macaddr_get`, plus mbuf-field accessors (`shim_rte_pktmbuf_data`, `shim_rte_pktmbuf_data_len`). **`rte_mbuf` is opaque to bindgen** because DPDK's `rte_mbuf` contains anonymous unions with packed+aligned attributes that bindgen cannot lay out — the generated struct is just `{ _address: u8 }`. This means we cannot read `buf_addr` / `data_off` / `data_len` from Rust directly; every mbuf-field access must go through a C shim.

`rte_pktmbuf_alloc`, `rte_pktmbuf_append`, and the macros `rte_pktmbuf_mtod` / `rte_pktmbuf_data_len` are `static inline` in DPDK headers; bindgen skips them. `rte_eth_macaddr_get` is a real extern, but we expose it with a `shim_rte_` prefix for consistency.

**Files:**
- Modify: `crates/dpdk-net-sys/shim.c`
- Modify: `crates/dpdk-net-sys/wrapper.h`

- [ ] **Step 1: Write the failing test**

Append to `crates/dpdk-net-sys/src/lib.rs` inside `mod tests`:

```rust
    #[test]
    fn shim_mbuf_symbols_linkable() {
        // Just prove the symbols link — actually calling them needs EAL.
        let _a: unsafe extern "C" fn(*mut rte_mempool) -> *mut rte_mbuf = shim_rte_pktmbuf_alloc;
        let _b: unsafe extern "C" fn(*mut rte_mbuf, u16) -> *mut std::os::raw::c_char =
            shim_rte_pktmbuf_append;
        let _c: unsafe extern "C" fn(u16, *mut rte_ether_addr) -> i32 = shim_rte_eth_macaddr_get;
        let _d: unsafe extern "C" fn(*const rte_mbuf) -> *mut std::os::raw::c_void =
            shim_rte_pktmbuf_data;
        let _e: unsafe extern "C" fn(*const rte_mbuf) -> u16 = shim_rte_pktmbuf_data_len;
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net-sys tests::shim_mbuf_symbols_linkable`
Expected: FAIL at compile — symbols not defined.

- [ ] **Step 3: Extend `crates/dpdk-net-sys/shim.c`**

Append:

```c
/* rte_pktmbuf_alloc is static inline; re-export. */
struct rte_mbuf *shim_rte_pktmbuf_alloc(struct rte_mempool *mp) {
    return rte_pktmbuf_alloc(mp);
}

/* rte_pktmbuf_append is static inline; re-export.
 * Returns a pointer to the appended region, or NULL on overflow. */
char *shim_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len) {
    return rte_pktmbuf_append(m, len);
}

/* rte_eth_macaddr_get is a real extern but we re-export for shim-prefix
 * consistency. Returns 0 on success, negative errno on failure. */
int shim_rte_eth_macaddr_get(uint16_t port_id, struct rte_ether_addr *mac_addr) {
    return rte_eth_macaddr_get(port_id, mac_addr);
}

/* mbuf field accessors — struct rte_mbuf is opaque to bindgen (packed
 * anonymous unions defeat its layout engine), so expose the two fields
 * our hot path needs as real C functions.
 *
 *   shim_rte_pktmbuf_data     — pointer to the first byte of packet data
 *   shim_rte_pktmbuf_data_len — length of the first (only, in Phase A2) segment
 */
void *shim_rte_pktmbuf_data(const struct rte_mbuf *m) {
    return rte_pktmbuf_mtod(m, void *);
}

uint16_t shim_rte_pktmbuf_data_len(const struct rte_mbuf *m) {
    return rte_pktmbuf_data_len(m);
}
```

- [ ] **Step 4: Extend `crates/dpdk-net-sys/wrapper.h`**

Append before the final comment:

```c
struct rte_mbuf *shim_rte_pktmbuf_alloc(struct rte_mempool *mp);
char *shim_rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len);
int shim_rte_eth_macaddr_get(uint16_t port_id, struct rte_ether_addr *mac_addr);
void *shim_rte_pktmbuf_data(const struct rte_mbuf *m);
uint16_t shim_rte_pktmbuf_data_len(const struct rte_mbuf *m);
```

- [ ] **Step 5: Run — verify PASS**

Run: `cargo test -p dpdk-net-sys tests::shim_mbuf_symbols_linkable`
Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git add crates/dpdk-net-sys/shim.c crates/dpdk-net-sys/wrapper.h crates/dpdk-net-sys/src/lib.rs
git commit -m "extend DPDK shim: mbuf alloc/append/data/len + mac getter"
```

---

## Task 10: Engine wiring — our_mac, our_ip, PMTU table, TX helpers

**Goal:** Store our MAC (read from the NIC) and our IP (from config) on the `Engine`. Initialize the PMTU table. Add a helper `tx_frame(bytes: &[u8])` that allocates an mbuf from `tx_hdr_mempool`, copies the bytes in, and submits via `shim_rte_eth_tx_burst`. This helper is the one place where mbuf-lifecycle shenanigans happen for Phase A2.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module at the bottom of `crates/dpdk-net-core/src/engine.rs`:

```rust
    #[test]
    fn engine_exposes_addressing_and_pmtu() {
        // Unit-test smoke: engine struct has the new accessors. We can't
        // actually construct an Engine without EAL, so test the types.
        fn _check(_e: &Engine) {
            let _: [u8; 6] = _e.our_mac();
            let _: u32 = _e.our_ip();
            let _: [u8; 6] = _e.gateway_mac();
            // PmtuTable read: exposed via counters-style getter for observability.
            let _: Option<u16> = _e.pmtu_for(0);
        }
        // If this compiles, the methods exist.
    }
```

- [ ] **Step 2: Run — verify FAIL**

Run: `cargo test -p dpdk-net-core engine::tests::engine_exposes_addressing_and_pmtu`
Expected: FAIL at compile — methods don't exist.

- [ ] **Step 3: Extend `Engine`** — edit `crates/dpdk-net-core/src/engine.rs`

First, add imports at the top (right after the existing `use` lines):

```rust
use std::cell::RefCell;

use crate::arp;
use crate::icmp::PmtuTable;
```

Replace the `Engine` struct definition with:

```rust
/// A dpdk-net engine. One per lcore; owns the NIC queues, mempools, and
/// L2/L3 state for that lcore.
pub struct Engine {
    cfg: EngineConfig,
    counters: Box<Counters>,
    _rx_mempool: Mempool,
    tx_hdr_mempool: Mempool,
    _tx_data_mempool: Mempool,
    our_mac: [u8; 6],
    pmtu: RefCell<PmtuTable>,
    last_garp_ns: RefCell<u64>,
}
```

(Notice `tx_hdr_mempool` is no longer `_`-prefixed — we use it now.)

Inside `Engine::new`, after `rte_eth_dev_start` succeeds, replace the `Ok(Self { ... })` at the end with:

```rust
        // Read NIC MAC via the shim. `rte_ether_addr` is a 6-byte packed struct.
        let mut mac_addr: sys::rte_ether_addr = unsafe { std::mem::zeroed() };
        let rc = unsafe { sys::shim_rte_eth_macaddr_get(cfg.port_id, &mut mac_addr) };
        if rc != 0 {
            return Err(Error::MacAddrLookup(cfg.port_id, unsafe { sys::shim_rte_errno() }));
        }
        // bindgen names the field `addr_bytes` on rte_ether_addr.
        let our_mac = mac_addr.addr_bytes;

        let counters = Box::new(Counters::new());

        Ok(Self {
            cfg,
            counters,
            _rx_mempool: rx_mempool,
            tx_hdr_mempool,
            _tx_data_mempool: tx_data_mempool,
            our_mac,
            pmtu: RefCell::new(PmtuTable::new()),
            last_garp_ns: RefCell::new(0),
        })
    }
```

Below `pub fn counters`, add accessors:

```rust
    pub fn our_mac(&self) -> [u8; 6] { self.our_mac }
    pub fn our_ip(&self) -> u32 { self.cfg.local_ip }
    pub fn gateway_mac(&self) -> [u8; 6] { self.cfg.gateway_mac }
    pub fn gateway_ip(&self) -> u32 { self.cfg.gateway_ip }
    pub fn pmtu_for(&self, ip: u32) -> Option<u16> { self.pmtu.borrow().get(ip) }

    /// TX a self-contained ≤256-byte frame (ARP in Phase A2). Allocates one
    /// mbuf from tx_hdr_mempool, copies `bytes` into its data room via the
    /// `rte_pktmbuf_append` shim, then submits via a single-packet burst.
    /// Bumps `eth.tx_pkts` / `eth.tx_bytes` / `eth.tx_drop_nomem` /
    /// `eth.tx_drop_full_ring` as appropriate. Returns true if the packet
    /// was accepted by the driver.
    pub(crate) fn tx_frame(&self, bytes: &[u8]) -> bool {
        use crate::counters::{add, inc};
        // Safety: tx_hdr_mempool was created in Engine::new and is alive.
        let m = unsafe { sys::shim_rte_pktmbuf_alloc(self.tx_hdr_mempool.as_ptr()) };
        if m.is_null() {
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        // Safety: append writes into the mbuf's data room. Returns NULL if
        // the mbuf's tailroom is < len.
        let dst = unsafe { sys::shim_rte_pktmbuf_append(m, bytes.len() as u16) };
        if dst.is_null() {
            unsafe { sys::shim_rte_pktmbuf_free(m) };
            inc(&self.counters.eth.tx_drop_nomem);
            return false;
        }
        // Safety: dst points to `bytes.len()` writable bytes inside the mbuf.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len());
        }
        let mut pkts = [m];
        let sent = unsafe {
            sys::shim_rte_eth_tx_burst(
                self.cfg.port_id,
                self.cfg.tx_queue_id,
                pkts.as_mut_ptr(),
                1,
            )
        } as usize;
        if sent == 1 {
            add(&self.counters.eth.tx_bytes, bytes.len() as u64);
            inc(&self.counters.eth.tx_pkts);
            true
        } else {
            // TX ring full; driver did not take the mbuf. Free it ourselves.
            unsafe { sys::shim_rte_pktmbuf_free(m) };
            inc(&self.counters.eth.tx_drop_full_ring);
            false
        }
    }
```

- [ ] **Step 4: Run — verify PASS**

Run: `cargo build -p dpdk-net-core && cargo test -p dpdk-net-core engine::tests`
Expected: PASS (compile-only test succeeds).

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs
git commit -m "engine: read NIC MAC, hold PMTU table, add tx_frame helper"
```

---

## Task 11: Wire L2/L3/ICMP/ARP into `poll_once`

**Goal:** Replace the Phase A1 "rx-burst then free everything" loop with real decoding + dispatch. Each drop path bumps the appropriate counter. TCP packets hit a stub that only increments `ip.rx_tcp`; real TCP arrives in A3.

**Files:**
- Modify: `crates/dpdk-net-core/src/engine.rs`
- Modify: `crates/dpdk-net-core/src/lib.rs`

- [ ] **Step 1: Write helper to extract mbuf data slice**

Append to `crates/dpdk-net-core/src/lib.rs`:

```rust
/// Helper exposed for unit tests and the poll loop.
/// Returns the byte slice backing the mbuf's first (and in Stage A2, only)
/// segment. The caller must not outlive the mbuf.
///
/// Safety: `m` must be a valid non-null mbuf pointer. Uses the C-shim
/// accessors from `dpdk-net-sys` because `rte_mbuf` is opaque to bindgen
/// (packed anonymous unions) — see Task 9 for the shim wiring.
pub unsafe fn mbuf_data_slice<'a>(m: *mut dpdk_net_sys::rte_mbuf) -> &'a [u8] {
    let ptr = unsafe { dpdk_net_sys::shim_rte_pktmbuf_data(m) } as *const u8;
    let len = unsafe { dpdk_net_sys::shim_rte_pktmbuf_data_len(m) } as usize;
    unsafe { std::slice::from_raw_parts(ptr, len) }
}
```

- [ ] **Step 2: Write the new `poll_once`** — in `crates/dpdk-net-core/src/engine.rs`

Replace the body of `Engine::poll_once` with:

```rust
    /// One iteration of the run-to-completion loop.
    /// Phase A2: decode L2/L3/ICMP/ARP. Counts every packet by its outcome.
    /// TCP dispatches to a stub that only bumps ip.rx_tcp. Real TCP is A3.
    pub fn poll_once(&self) -> usize {
        use crate::counters::{add, inc};
        inc(&self.counters.poll.iters);

        const BURST: usize = 32;
        let mut mbufs: [*mut sys::rte_mbuf; BURST] = [std::ptr::null_mut(); BURST];
        let n = unsafe {
            sys::shim_rte_eth_rx_burst(
                self.cfg.port_id,
                self.cfg.rx_queue_id,
                mbufs.as_mut_ptr(),
                BURST as u16,
            )
        } as usize;

        if n == 0 {
            inc(&self.counters.poll.iters_idle);
            self.maybe_emit_gratuitous_arp();
            return 0;
        }

        inc(&self.counters.poll.iters_with_rx);
        add(&self.counters.eth.rx_pkts, n as u64);

        for &m in &mbufs[..n] {
            // Safety: mbuf is valid for the duration of this iteration.
            let bytes = unsafe { crate::mbuf_data_slice(m) };
            add(&self.counters.eth.rx_bytes, bytes.len() as u64);

            self.rx_frame(bytes);

            // Phase A2: we free every packet at the end of the iteration.
            // Phase A3 will transfer ownership to recv_queues for TCP pkts.
            unsafe { sys::shim_rte_pktmbuf_free(m) };
        }

        self.maybe_emit_gratuitous_arp();
        n
    }

    fn rx_frame(&self, bytes: &[u8]) {
        use crate::counters::inc;
        match crate::l2::l2_decode(bytes, self.our_mac) {
            Err(crate::l2::L2Drop::Short) => inc(&self.counters.eth.rx_drop_short),
            Err(crate::l2::L2Drop::MissMac) => inc(&self.counters.eth.rx_drop_miss_mac),
            Err(crate::l2::L2Drop::UnknownEthertype) => {
                inc(&self.counters.eth.rx_drop_unknown_ethertype)
            }
            Ok(l2) => {
                let payload = &bytes[l2.payload_offset..];
                match l2.ethertype {
                    crate::l2::ETHERTYPE_ARP => {
                        inc(&self.counters.eth.rx_arp);
                        self.handle_arp(payload);
                    }
                    crate::l2::ETHERTYPE_IPV4 => self.handle_ipv4(payload),
                    _ => unreachable!("l2_decode filters unsupported ethertypes"),
                }
            }
        }
    }

    fn handle_arp(&self, payload: &[u8]) {
        let Ok(pkt) = crate::arp::arp_decode(payload) else {
            return;
        };
        if pkt.op == crate::arp::ARP_OP_REQUEST && pkt.target_ip == self.cfg.local_ip
            && self.cfg.local_ip != 0
        {
            let mut buf = [0u8; crate::arp::ARP_FRAME_LEN];
            if crate::arp::build_arp_reply(self.our_mac, self.cfg.local_ip, &pkt, &mut buf).is_some()
            {
                if self.tx_frame(&buf) {
                    crate::counters::inc(&self.counters.eth.tx_arp);
                }
            }
        }
        // ARP replies that rewrite gateway MAC would be handled here; for
        // static-gateway A2 we rely on the configured MAC and do not mutate.
    }

    fn handle_ipv4(&self, payload: &[u8]) {
        use crate::counters::inc;
        match crate::l3_ip::ip_decode(payload, self.cfg.local_ip, /*nic_csum_ok=*/false) {
            Err(crate::l3_ip::L3Drop::Short) => inc(&self.counters.ip.rx_drop_short),
            Err(crate::l3_ip::L3Drop::BadVersion) => inc(&self.counters.ip.rx_drop_bad_version),
            Err(crate::l3_ip::L3Drop::BadHeaderLen) => inc(&self.counters.ip.rx_drop_bad_hl),
            Err(crate::l3_ip::L3Drop::BadTotalLen) => inc(&self.counters.ip.rx_drop_short),
            Err(crate::l3_ip::L3Drop::CsumBad) => inc(&self.counters.ip.rx_csum_bad),
            Err(crate::l3_ip::L3Drop::TtlZero) => inc(&self.counters.ip.rx_ttl_zero),
            Err(crate::l3_ip::L3Drop::Fragment) => inc(&self.counters.ip.rx_frag),
            Err(crate::l3_ip::L3Drop::NotOurs) => inc(&self.counters.ip.rx_drop_not_ours),
            Err(crate::l3_ip::L3Drop::UnsupportedProto) => {
                inc(&self.counters.ip.rx_drop_unsupported_proto)
            }
            Ok(ip) => {
                let inner = &payload[ip.header_len..ip.total_len];
                match ip.protocol {
                    crate::l3_ip::IPPROTO_TCP => {
                        inc(&self.counters.ip.rx_tcp);
                        self.tcp_input_stub(&ip, inner);
                    }
                    crate::l3_ip::IPPROTO_ICMP => {
                        inc(&self.counters.ip.rx_icmp);
                        let res = {
                            let mut pmtu = self.pmtu.borrow_mut();
                            crate::icmp::icmp_input(inner, &mut pmtu)
                        };
                        use crate::icmp::IcmpResult::*;
                        match res {
                            FragNeededPmtuUpdated => {
                                inc(&self.counters.ip.rx_icmp_frag_needed);
                                inc(&self.counters.ip.pmtud_updates);
                            }
                            FragNeededNoShrink => {
                                inc(&self.counters.ip.rx_icmp_frag_needed);
                            }
                            OtherDropped | Malformed => {}
                        }
                    }
                    _ => unreachable!("ip_decode filters unsupported protocols"),
                }
            }
        }
    }

    /// Phase A2 TCP input stub — real FSM lands in A3.
    /// Kept separate so A3 can replace this with a real implementation
    /// without touching the L3 dispatch code above.
    fn tcp_input_stub(&self, _ip: &crate::l3_ip::L3Decoded, _tcp_payload: &[u8]) {
        // No-op. Counter already bumped in the caller.
    }

    fn maybe_emit_gratuitous_arp(&self) {
        if self.cfg.garp_interval_sec == 0 || self.cfg.local_ip == 0 {
            return;
        }
        let interval_ns = (self.cfg.garp_interval_sec as u64) * 1_000_000_000;
        let now = crate::clock::now_ns();
        let mut last = self.last_garp_ns.borrow_mut();
        if now.saturating_sub(*last) < interval_ns {
            return;
        }
        let mut buf = [0u8; crate::arp::ARP_FRAME_LEN];
        if crate::arp::build_gratuitous_arp(self.our_mac, self.cfg.local_ip, &mut buf).is_some() {
            if self.tx_frame(&buf) {
                crate::counters::inc(&self.counters.eth.tx_arp);
            }
        }
        *last = now;
    }
```

- [ ] **Step 3: Build the crate**

Run: `cargo build -p dpdk-net-core`
Expected: compiles.

- [ ] **Step 4: Run unit tests**

Run: `cargo test -p dpdk-net-core`
Expected: all prior tests still pass (engine struct recompiles; l2/l3/icmp/arp tests independent).

- [ ] **Step 5: Commit**

```sh
git add crates/dpdk-net-core/src/engine.rs crates/dpdk-net-core/src/lib.rs
git commit -m "wire l2/l3/icmp/arp into poll_once; add gratuitous-arp emit"
```

---

## Task 12: Public C ABI for `dpdk_net_resolve_gateway_mac`

**Goal:** Expose the `/proc/net/arp` resolver as an `extern "C"` helper so C++ callers can discover the gateway MAC before calling `dpdk_net_engine_create`.

**Files:**
- Modify: `crates/dpdk-net/src/lib.rs`

- [ ] **Step 1: Add the FFI wrapper**

Insert into `crates/dpdk-net/src/lib.rs` after the existing extern "C" functions (before the `#[cfg(test)]` block):

```rust
/// Resolve the MAC address for `gateway_ip_host_order` by reading
/// `/proc/net/arp`. Writes 6 bytes into `out_mac`.
/// Returns 0 on success, -ENOENT if no entry, -EIO on /proc/net/arp read error,
/// -EINVAL on null out_mac.
#[no_mangle]
pub unsafe extern "C" fn dpdk_net_resolve_gateway_mac(
    gateway_ip_host_order: u32,
    out_mac: *mut u8,
) -> i32 {
    if out_mac.is_null() {
        return -libc::EINVAL;
    }
    match dpdk_net_core::arp::resolve_from_proc_arp(gateway_ip_host_order) {
        Ok(mac) => {
            std::ptr::copy_nonoverlapping(mac.as_ptr(), out_mac, 6);
            0
        }
        Err(dpdk_net_core::Error::GatewayMacNotFound(_)) => -libc::ENOENT,
        Err(_) => -libc::EIO,
    }
}
```

- [ ] **Step 2: Write unit tests in the existing `mod tests`**

Append:

```rust
    #[test]
    fn resolve_null_out_mac_returns_einval() {
        let rc = unsafe { dpdk_net_resolve_gateway_mac(0x0a_00_00_01, std::ptr::null_mut()) };
        assert_eq!(rc, -libc::EINVAL);
    }

    #[test]
    fn resolve_unreachable_ip_returns_enoent() {
        let mut mac = [0u8; 6];
        // 0.0.0.1 will not be in any /proc/net/arp.
        let rc = unsafe { dpdk_net_resolve_gateway_mac(0x0000_0001, mac.as_mut_ptr()) };
        assert_eq!(rc, -libc::ENOENT);
    }
```

- [ ] **Step 3: Build + test**

Run: `cargo test -p dpdk-net`
Expected: PASS on all.

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net/src/lib.rs
git commit -m "add dpdk_net_resolve_gateway_mac extern C wrapper"
```

---

## Task 13: Regenerate public header + verify no drift

**Goal:** Run `cargo build -p dpdk-net` so cbindgen regenerates `include/dpdk_net.h` with the new config fields, counter fields, and `dpdk_net_resolve_gateway_mac` declaration. Verify the header compiles under C and C++.

**Files:**
- Modify: `include/dpdk_net.h` (generated)
- Modify: `crates/dpdk-net/cbindgen.toml` (if needed — only if cbindgen skips a newly-reachable type; most changes should be picked up automatically)

- [ ] **Step 1: Regenerate**

Run: `cargo build -p dpdk-net`
Expected: succeeds; `include/dpdk_net.h` updates. If cbindgen fails to see `dpdk_net_resolve_gateway_mac` (it should be reachable because it's `#[no_mangle] pub unsafe extern "C"`), double-check the signature.

- [ ] **Step 2: Grep the header for the new symbols**

Run: `grep -E '(local_ip|gateway_ip|gateway_mac|garp_interval_sec|dpdk_net_resolve_gateway_mac|rx_drop_short|rx_drop_bad_version|rx_tcp|rx_icmp)' include/dpdk_net.h`
Expected: every term appears at least once.

- [ ] **Step 3: Run the drift-check script**

Run: `./scripts/check-header.sh`
Expected: PASS (header matches cbindgen output). If it reports drift, it's because the regenerated header has uncommitted changes — commit them.

- [ ] **Step 4: Commit the regenerated header**

```sh
git add include/dpdk_net.h
git commit -m "regenerate dpdk_net.h for phase a2 config + counter + resolve_gateway_mac additions"
```

---

## Task 14: Integration test — crafted frames through TAP pair

**Goal:** Bring up a DPDK TAP vdev engine, configure the kernel side of the TAP (`dpdktap0`), send a sequence of hand-crafted Ethernet frames via AF_PACKET from the test process, poll the engine, and assert exact counter deltas for each case. Gated by `DPDK_NET_TEST_TAP=1`.

**Files:**
- Create: `crates/dpdk-net-core/tests/l2_l3_tap.rs`

- [ ] **Step 1: Write the test file**

Create `crates/dpdk-net-core/tests/l2_l3_tap.rs`:

```rust
//! L2/L3 crafted-frame integration test. Requires DPDK_NET_TEST_TAP=1 and
//! root (DPDK TAP vdev + raw AF_PACKET socket). The test:
//!   1. boots EAL + engine against a DPDK TAP vdev (iface `dpdktap1` so
//!      it doesn't collide with engine_smoke.rs's `dpdktap0`)
//!   2. brings `dpdktap1` UP and assigns kernel-side addressing
//!   3. sends a sequence of L2/L3 frames via AF_PACKET/SOCK_RAW
//!   4. polls the engine and asserts counter deltas per case

use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::process::Command;
use std::sync::atomic::Ordering;

use dpdk_net_core::counters::Counters;
use dpdk_net_core::engine::{eal_init, Engine, EngineConfig};
use dpdk_net_core::l3_ip::internet_checksum;

const TAP_IFACE: &str = "dpdktap1";
const DPDK_PORT: u16 = 0;
const OUR_IP: u32 = 0x0a_63_00_02; // 10.99.0.2 (host byte order)
const PEER_IP: u32 = 0x0a_63_00_01; // 10.99.0.1 on the kernel side of the tap

fn want_tap() -> bool {
    std::env::var("DPDK_NET_TEST_TAP").ok().as_deref() == Some("1")
}

fn skip_if_not_tap() -> bool {
    if !want_tap() {
        eprintln!("skipping; set DPDK_NET_TEST_TAP=1 to run");
        return true;
    }
    false
}

fn bring_up_tap(iface: &str, cidr: &str) {
    // These commands require root — the test itself must be run via sudo.
    let _ = Command::new("ip").args(["link", "set", iface, "up"]).status();
    let _ = Command::new("ip").args(["addr", "add", cidr, "dev", iface]).status();
}

/// Open an AF_PACKET SOCK_RAW socket bound to `iface` for raw frame TX.
fn open_pkt_socket(iface: &str) -> c_int {
    let s = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    assert!(s >= 0, "socket() failed: {}", std::io::Error::last_os_error());
    let c_name = CString::new(iface).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    assert!(ifindex > 0, "if_nametoindex({iface}) failed");
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    sll.sll_ifindex = ifindex as i32;
    let rc = unsafe {
        libc::bind(
            s,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&sll) as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind failed: {}", std::io::Error::last_os_error());
    s
}

fn send_frame(s: c_int, iface: &str, bytes: &[u8]) {
    let c_name = CString::new(iface).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&bytes[..6]);
    let rc = unsafe {
        libc::sendto(
            s,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            0,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&sll) as libc::socklen_t,
        )
    };
    assert!(rc > 0, "sendto failed: {}", std::io::Error::last_os_error());
}

fn build_eth(dst: [u8; 6], src: [u8; 6], et: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + body.len());
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&et.to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn build_ipv4(proto: u8, src: u32, dst: u32, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut v = vec![
        0x45, 0x00,
        (total >> 8) as u8, (total & 0xff) as u8,
        0x00, 0x01,
        0x40, 0x00,
        0x40, proto,
        0x00, 0x00,
    ];
    v.extend_from_slice(&src.to_be_bytes());
    v.extend_from_slice(&dst.to_be_bytes());
    let c = internet_checksum(&v);
    v[10] = (c >> 8) as u8;
    v[11] = (c & 0xff) as u8;
    v.extend_from_slice(payload);
    v
}

fn poll_until_pkts(engine: &Engine, min_pkts: u64, max_iters: usize) {
    let c = engine.counters();
    for _ in 0..max_iters {
        engine.poll_once();
        if c.eth.rx_pkts.load(Ordering::Relaxed) >= min_pkts {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn snapshot(c: &Counters) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        c.eth.rx_pkts.load(Ordering::Relaxed),
        c.eth.rx_drop_miss_mac.load(Ordering::Relaxed),
        c.eth.rx_drop_unknown_ethertype.load(Ordering::Relaxed),
        c.eth.rx_arp.load(Ordering::Relaxed),
        c.ip.rx_drop_bad_version.load(Ordering::Relaxed),
        c.ip.rx_drop_unsupported_proto.load(Ordering::Relaxed),
        c.ip.rx_frag.load(Ordering::Relaxed),
        c.ip.rx_tcp.load(Ordering::Relaxed),
        c.ip.rx_icmp.load(Ordering::Relaxed),
        c.ip.rx_icmp_frag_needed.load(Ordering::Relaxed),
        c.ip.pmtud_updates.load(Ordering::Relaxed),
    )
}

#[test]
fn crafted_frames_through_tap_pair() {
    if skip_if_not_tap() { return; }

    let args = [
        "dpdk-net-a2-test",
        "--in-memory",
        "--no-pci",
        "--vdev=net_tap0,iface=dpdktap1",
        "-l", "0-1",
        "--log-level=3",
    ];
    eal_init(&args).expect("EAL init");

    let cfg = EngineConfig {
        port_id: DPDK_PORT,
        local_ip: OUR_IP,
        gateway_ip: PEER_IP,
        gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], // arbitrary; not actually used in rx path
        garp_interval_sec: 0, // disabled for this test
        ..Default::default()
    };
    let engine = Engine::new(cfg).expect("engine new");
    let our_mac = engine.our_mac();

    bring_up_tap(TAP_IFACE, "10.99.0.1/24");
    // Wait for the interface to be operational.
    std::thread::sleep(std::time::Duration::from_millis(100));

    let sock = open_pkt_socket(TAP_IFACE);

    // Drain any startup noise (router advertisements, IPv6 MLD, etc.)
    // so our counter deltas are attributable.
    for _ in 0..200 { engine.poll_once(); }
    let _ = snapshot(engine.counters());

    // -- Case 1: wrong destination MAC → rx_drop_miss_mac --
    let s0 = snapshot(engine.counters());
    let bad_mac = [0xee, 0xee, 0xee, 0xee, 0xee, 0xee];
    let frame = build_eth(
        bad_mac, [0xaa; 6], 0x0800,
        &build_ipv4(6 /*TCP*/, PEER_IP, OUR_IP, &[0u8; 20]),
    );
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s0.0 + 1, 500);
    let s1 = snapshot(engine.counters());
    assert_eq!(s1.1, s0.1 + 1, "rx_drop_miss_mac delta");

    // -- Case 2: unknown ethertype → rx_drop_unknown_ethertype --
    let s1 = snapshot(engine.counters());
    let frame = build_eth(our_mac, [0xaa; 6], 0x86DD /*IPv6*/, &[0u8; 20]);
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s1.0 + 1, 500);
    let s2 = snapshot(engine.counters());
    assert_eq!(s2.2, s1.2 + 1);

    // -- Case 3: IPv4 TCP to us → rx_tcp bumped --
    let s2 = snapshot(engine.counters());
    let frame = build_eth(
        our_mac, [0xaa; 6], 0x0800,
        &build_ipv4(6, PEER_IP, OUR_IP, &[0u8; 20]),
    );
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s2.0 + 1, 500);
    let s3 = snapshot(engine.counters());
    assert_eq!(s3.7, s2.7 + 1, "rx_tcp delta");

    // -- Case 4: IPv4 UDP (unsupported proto) → rx_drop_unsupported_proto --
    let s3 = snapshot(engine.counters());
    let frame = build_eth(
        our_mac, [0xaa; 6], 0x0800,
        &build_ipv4(17 /*UDP*/, PEER_IP, OUR_IP, &[0u8; 8]),
    );
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s3.0 + 1, 500);
    let s4 = snapshot(engine.counters());
    assert_eq!(s4.5, s3.5 + 1);

    // -- Case 5: IP fragment → rx_frag --
    let s4 = snapshot(engine.counters());
    let mut frag_ip = build_ipv4(6, PEER_IP, OUR_IP, &[0u8; 20]);
    frag_ip[6] = 0x20; // set MF bit; checksum is now wrong but parse hits fragment-drop first
    let frame = build_eth(our_mac, [0xaa; 6], 0x0800, &frag_ip);
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s4.0 + 1, 500);
    let s5 = snapshot(engine.counters());
    assert_eq!(s5.6, s4.6 + 1);

    // -- Case 6: ICMP frag-needed (RFC 1191) → pmtud_updates --
    let s5 = snapshot(engine.counters());
    // Build inner: a fake IP header whose dst is some "original destination"
    // we supposedly sent traffic to. The stack indexes PMTU by that dst.
    let inner_dst: u32 = 0x0a_63_00_64; // 10.99.0.100
    let mut inner = vec![
        0x45, 0x00,
        0x00, 0x14, 0x00, 0x01, 0x40, 0x00, 0x40, 6, 0x00, 0x00,
        (PEER_IP >> 24) as u8, (PEER_IP >> 16) as u8, (PEER_IP >> 8) as u8, PEER_IP as u8,
    ];
    inner.extend_from_slice(&inner_dst.to_be_bytes());
    // Build ICMP body: type=3, code=4, csum=0, unused=0, mtu=1200, then inner IP
    let mut icmp_body = vec![3u8, 4, 0, 0, 0, 0, (1200u16 >> 8) as u8, 1200 as u8];
    icmp_body.extend_from_slice(&inner);
    let frame = build_eth(
        our_mac, [0xaa; 6], 0x0800,
        &build_ipv4(1 /*ICMP*/, PEER_IP, OUR_IP, &icmp_body),
    );
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s5.0 + 1, 500);
    let s6 = snapshot(engine.counters());
    assert_eq!(s6.8, s5.8 + 1, "rx_icmp delta");
    assert_eq!(s6.9, s5.9 + 1, "rx_icmp_frag_needed delta");
    assert_eq!(s6.10, s5.10 + 1, "pmtud_updates delta");
    assert_eq!(engine.pmtu_for(inner_dst), Some(1200));

    // -- Case 7: ARP request to our IP → we send an ARP reply --
    let s6 = snapshot(engine.counters());
    let tx_arp_before = engine.counters().eth.tx_arp.load(Ordering::Relaxed);
    // Build an ARP request targeting OUR_IP from a hypothetical peer.
    let peer_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    let mut arp_body = [0u8; 28];
    arp_body[0..2].copy_from_slice(&1u16.to_be_bytes());
    arp_body[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    arp_body[4] = 6;
    arp_body[5] = 4;
    arp_body[6..8].copy_from_slice(&1u16.to_be_bytes()); // request
    arp_body[8..14].copy_from_slice(&peer_mac);
    arp_body[14..18].copy_from_slice(&PEER_IP.to_be_bytes());
    // target_mac left zero
    arp_body[24..28].copy_from_slice(&OUR_IP.to_be_bytes());
    let frame = build_eth([0xff; 6], peer_mac, 0x0806, &arp_body);
    send_frame(sock, TAP_IFACE, &frame);
    poll_until_pkts(&engine, s6.0 + 1, 500);
    // Allow time for the reply to have been pushed by tx_burst.
    for _ in 0..5 { engine.poll_once(); std::thread::sleep(std::time::Duration::from_millis(2)); }
    let tx_arp_after = engine.counters().eth.tx_arp.load(Ordering::Relaxed);
    assert!(tx_arp_after > tx_arp_before, "tx_arp should have incremented (we replied)");

    drop(engine);
    unsafe { libc::close(sock) };
}
```

- [ ] **Step 2: Run the test** (requires root + DPDK TAP)

```sh
sudo -E DPDK_NET_TEST_TAP=1 $(command -v cargo) test -p dpdk-net-core --test l2_l3_tap -- --nocapture
```

Expected: PASS. If the test fails on a specific case, the counter delta assertion will pinpoint which module broke. Troubleshooting: if cases 3–7 report "delta 0" while case 1 passes, the most common cause is that `dpdktap1` came up AFTER the frame was sent; increase the `sleep(100)` after `bring_up_tap` to 500ms.

- [ ] **Step 3: Document running it in README**

Append to `README.md`:

```markdown

## L2/L3 integration tests (require DPDK TAP and root)

```sh
sudo -E DPDK_NET_TEST_TAP=1 cargo test -p dpdk-net-core --test l2_l3_tap -- --nocapture
```
```

- [ ] **Step 4: Commit**

```sh
git add crates/dpdk-net-core/tests/l2_l3_tap.rs README.md
git commit -m "add L2/L3 crafted-frame integration test over TAP pair"
```

---

## Task 15: Extend C++ consumer to print IP counters + phase sign-off

**Goal:** Show the C++ sample can read A2's new counters, confirming ABI parity. Then run the full sign-off verification sequence and tag.

**Files:**
- Modify: `examples/cpp-consumer/main.cpp`
- Modify: `docs/superpowers/plans/stage1-phase-roadmap.md`

- [ ] **Step 1: Extend `examples/cpp-consumer/main.cpp`** — add IP-counter prints before the final `dpdk_net_engine_destroy`. Locate the existing `poll iters` and `now_ns` printouts; immediately after them, insert:

```cpp
    // Phase A2: print IP counters to confirm they are accessible from C++.
    std::printf("ip.rx_drop_bad_version: %llu\n",
        (unsigned long long)__atomic_load_n(&c->ip.rx_drop_bad_version, __ATOMIC_RELAXED));
    std::printf("ip.rx_tcp: %llu\n",
        (unsigned long long)__atomic_load_n(&c->ip.rx_tcp, __ATOMIC_RELAXED));
    std::printf("ip.rx_icmp: %llu\n",
        (unsigned long long)__atomic_load_n(&c->ip.rx_icmp, __ATOMIC_RELAXED));
    std::printf("ip.pmtud_updates: %llu\n",
        (unsigned long long)__atomic_load_n(&c->ip.pmtud_updates, __ATOMIC_RELAXED));
    std::printf("eth.rx_arp: %llu\n",
        (unsigned long long)__atomic_load_n(&c->eth.rx_arp, __ATOMIC_RELAXED));
```

Also update the cfg initializer block to set the A2 fields (just inside `main`, before `dpdk_net_eal_init`):

```cpp
    // Phase A2 addressing (left at zero — the TAP sample isn't doing real
    // traffic). Real deployments supply local_ip, gateway_ip, gateway_mac.
    cfg.local_ip = 0;
    cfg.gateway_ip = 0;
    memset(cfg.gateway_mac, 0, sizeof(cfg.gateway_mac));
    cfg.garp_interval_sec = 0;
```

- [ ] **Step 2: Build the C++ consumer**

```sh
cargo build -p dpdk-net --release
cmake -S examples/cpp-consumer -B examples/cpp-consumer/build -DDPDK_NET_PROFILE=release
cmake --build examples/cpp-consumer/build
```

Expected: `cpp_consumer` binary builds without warnings.

- [ ] **Step 3: Run the sign-off verification sequence**

```sh
# Workspace builds clean
cargo build --workspace --all-targets
# All unit tests pass
cargo test --workspace
# TAP integration tests pass (sudo + DPDK required)
sudo -E DPDK_NET_TEST_TAP=1 $(command -v cargo) test -p dpdk-net-core --test engine_smoke -- --nocapture
sudo -E DPDK_NET_TEST_TAP=1 $(command -v cargo) test -p dpdk-net-core --test l2_l3_tap -- --nocapture
# Header hasn't drifted
./scripts/check-header.sh
# C++ consumer builds
cargo build -p dpdk-net --release
cmake -S examples/cpp-consumer -B examples/cpp-consumer/build -DDPDK_NET_PROFILE=release
cmake --build examples/cpp-consumer/build
# No clippy warnings
cargo clippy --workspace --all-targets -- -D warnings
```

All must succeed. If any fails, fix before claiming A2 complete.

- [ ] **Step 4: Verify spec references honored in Phase A2**

Manual check of these spec sections mapped to code:
- **§5.1 "RX up through ip_decode"** — `poll_once` → `rx_frame` → `l2_decode` → `handle_ipv4` → `ip_decode`.
- **§6.3 RFC 791 (IPv4)** — `l3_ip::ip_decode` verifies version=4, IHL ≥ 5, total_length bounds, checksum, TTL ≥ 1; drops fragments (spec row for 1122 reassembly "not implemented").
- **§6.3 RFC 792 (ICMP)** — `icmp::icmp_input` handles type 3 code 4 only; all other ICMP silently dropped.
- **§6.3 RFC 1191 (PMTUD)** — `PmtuTable::update` stores next-hop MTU keyed by inner destination; only shrinks.
- **§6.3 RFC 1122 (IPv4 reassembly not implemented)** — fragments dropped with `ip.rx_frag` bump.
- **§8 "static gateway MAC"** — `arp::resolve_from_proc_arp` + `dpdk_net_resolve_gateway_mac` FFI; `build_gratuitous_arp` for the refresh path; `handle_arp` responds to inbound ARP requests.

- [ ] **Step 5: Run mTCP comparison review (first phase to do this — see spec §10.13)**

This is the first phase to run the per-phase mTCP review gate. One-time submodule setup (only once across all phases):

```sh
git submodule add https://github.com/mtcp-stack/mtcp third_party/mtcp
(cd third_party/mtcp && git rev-parse HEAD)  # record this SHA in the report
git add .gitmodules third_party/mtcp
```

Dispatch the `mtcp-comparison-reviewer` subagent (`.claude/agents/mtcp-comparison-reviewer.md`) with:
- Phase number: **A2**
- Phase plan: `docs/superpowers/plans/2026-04-17-stage1-phase-a2-l2-l3.md`
- Diff command: `git diff phase-a1-complete..HEAD -- crates/ include/ examples/`
- Spec refs: §5.1, §6.3 rows for RFC 791 / 792 / 1122 / 1191, §8 (ARP)
- mTCP focus areas: `third_party/mtcp/mtcp/src/eth_in.c`, `eth_out.c`, `ip_in.c`, `ip_out.c`, `arp.c`, `icmp.c`

The subagent writes `docs/superpowers/reviews/phase-a2-mtcp-compare.md`. Human reviews: edits the **Accepted divergence** section with concrete spec/memory citations, promotes/demotes findings, toggles the final verdict to **PASS** or **PASS-WITH-ACCEPTED**.

**Gate:** do not proceed to Step 6 while any unresolved `[ ]` checkbox remains in Must-fix or Missed-edge-cases. If findings require code changes, implement them in a separate commit before continuing.

Commit the review:

```sh
git add docs/superpowers/reviews/phase-a2-mtcp-compare.md
git commit -m "phase a2: mTCP comparison review report"
```

- [ ] **Step 6: Update roadmap status**

Edit `docs/superpowers/plans/stage1-phase-roadmap.md` — replace the A2 row:

```markdown
| A2 | L2/L3 + static ARP + ICMP-in (PMTUD) | **Complete** ✓ | `2026-04-17-stage1-phase-a2-l2-l3.md` |
```

- [ ] **Step 7: Commit + tag**

```sh
git add examples/cpp-consumer/main.cpp docs/superpowers/plans/stage1-phase-roadmap.md
git commit -m "mark phase a2 complete in roadmap; print ip counters from c++ consumer"
git tag -a phase-a2-complete -m "Phase A2: L2/L3 + static ARP + ICMP-in (PMTUD)"
```

- [ ] **Step 8: Record next phase**

The next plan file to write is `docs/superpowers/plans/YYYY-MM-DD-stage1-phase-a3-tcp-basic.md` — TCP handshake + basic data transfer.

---

## Self-Review Notes

**Spec coverage for Phase A2:**
- §5.1 Per-lcore main loop (RX up through ip_decode) → Task 11 (poll_once dispatch)
- §6.3 RFC 791 (IPv4) → Tasks 5, 11
- §6.3 RFC 792 (ICMP in) → Tasks 6, 11
- §6.3 RFC 1122 (no IPv4 reassembly) → Task 5 (fragments dropped + counted)
- §6.3 RFC 1191 (PMTUD) → Task 6 (PmtuTable), Task 11 (wired)
- §8 ARP bullet (static gateway, gratuitous refresh) → Tasks 7, 8, 11, 12
- §9.1 IP counter group → Task 1

**Items explicitly deferred to later phases:**
- §6 TCP layer → A3–A5 (Phase A2 only provides a one-line `tcp_input_stub`)
- §7.4 timer wheel → A6 (Phase A2 uses a naïve last-send-tsc check for gratuitous ARP)
- §10.8 PMTU blackholing recovery → Stage 2 (PLPMTUD / RFC 4821)
- Dynamic gateway-MAC resolution (ARP replies mutating our gateway MAC) → kept out of Phase A2 per spec "No dynamic ARP resolution on the data path"

**Placeholder scan:** Every code block contains complete content. No "TODO"/"TBD"/"implement later". The `tcp_input_stub` is intentional — the stub IS the implementation for Phase A2.

**Type consistency cross-check:**
- `EngineConfig.local_ip` (Rust) ↔ `dpdk_net_engine_config_t.local_ip` (public API) ↔ `Cfg.local_ip` (ffi_smoke.rs) — all `u32` host-byte-order.
- `EthCounters` / `IpCounters` field lists match exactly between core and public versions; layout assertion in `api.rs` enforces size + alignment.
- `L2Decoded.payload_offset: usize` — consistently indexed by the same `bytes[l2.payload_offset..]` slice in `handle_arp`/`handle_ipv4`.
- `PmtuTable::get → Option<u16>` exposed through `Engine::pmtu_for` — same return type.
- `arp::ARP_FRAME_LEN` (42) used uniformly in Task 7 builders and Task 11 consumers.

**Counter-assertion strategy:** Task 14's test reads a snapshot, sends one frame, polls until `rx_pkts` advances by 1, then asserts the specific per-case counter delta is exactly 1. This catches any spec-violating path (e.g., a frame double-counted, or a drop silently counted against the wrong reason).
