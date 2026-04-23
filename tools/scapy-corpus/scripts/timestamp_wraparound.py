#!/usr/bin/env python3
"""
Timestamp wraparound corpus (PAWS edge cases, RFC 7323 §5).

Emits frames with TCP Timestamp option values near 2^32:
  - TS values bracketing the u32 wrap (0xFFFF_FF00 .. 0x0000_00FF)
  - sequential frames crossing the boundary
  - frame whose TSval < recent TSval by <2^31 (PAWS-reject zone)
  - frame whose TSval > recent TSval by >2^31 (PAWS-accept zone with wrap)

Each frame carries a 2-byte payload so the receiver has something to
acknowledge (PAWS runs in the tcp_input path before queueing).

Seed: 0xA9E04.
"""
import json
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SEED = 0xA9E04
random.seed(SEED)

LOCAL_MAC = "02:00:00:00:00:01"
LOCAL_IP = "10.0.0.1"
PEER_MAC = "02:00:00:00:00:99"
PEER_IP = "10.0.0.2"

SPORT = 4000
DPORT = 5678
SEQ0 = 300_000
ACK = 100
WIN = 8192


def frame(seq: int, tsval: int, tsecr: int, length: int = 2):
    payload = bytes(random.randint(0, 255) for _ in range(length))
    # Mask into u32 so scapy accepts the value.
    tsval &= 0xFFFF_FFFF
    tsecr &= 0xFFFF_FFFF
    return (
        Ether(src=PEER_MAC, dst=LOCAL_MAC)
        / IP(src=PEER_IP, dst=LOCAL_IP)
        / TCP(
            sport=SPORT,
            dport=DPORT,
            seq=seq,
            ack=ACK,
            flags="A",
            window=WIN,
            options=[("Timestamp", (tsval, tsecr))],
        )
        / Raw(payload)
    )


frames = []
manifest_entries = []

# 1. Baseline: TSval just below wrap.
frames.append(frame(SEQ0, 0xFFFF_FF00, 100))
manifest_entries.append({"indexes": [0], "flags": "ts:near_wrap_pre"})

# 2. TSval = 0xFFFF_FFFE (one short of max).
frames.append(frame(SEQ0 + 2, 0xFFFF_FFFE, 100))
manifest_entries.append({"indexes": [1], "flags": "ts:max_minus_1"})

# 3. TSval = 0xFFFF_FFFF (max u32).
frames.append(frame(SEQ0 + 4, 0xFFFF_FFFF, 100))
manifest_entries.append({"indexes": [2], "flags": "ts:max"})

# 4. Wrapped: TSval = 0 (post-wrap) — must be accepted per PAWS §5.2.
frames.append(frame(SEQ0 + 6, 0, 100))
manifest_entries.append({"indexes": [3], "flags": "ts:wrapped_to_zero"})

# 5. Wrapped: TSval = 1 (just past wrap).
frames.append(frame(SEQ0 + 8, 1, 100))
manifest_entries.append({"indexes": [4], "flags": "ts:wrapped_to_one"})

# 6. PAWS-reject zone: after accepting TSval=1, send an old TSval.
# Old value = 0x7FFF_FF01 has SEG.TSval - TS.Recent = 0x7FFF_FF00 (negative
# in wrap-around arithmetic), so should be rejected.
frames.append(frame(SEQ0 + 10, 0x7FFF_FF01, 100))
manifest_entries.append({"indexes": [5], "flags": "ts:paws_reject"})

# 7. PAWS-accept zone: TSval = 2 (just slightly newer than 1).
frames.append(frame(SEQ0 + 12, 2, 100))
manifest_entries.append({"indexes": [6], "flags": "ts:paws_accept"})

# 8. Large jump forward (TSval = 0x8000_0000) — exactly at 2^31 mark;
# implementation-defined edge.
frames.append(frame(SEQ0 + 14, 0x8000_0000, 100))
manifest_entries.append({"indexes": [7], "flags": "ts:half_wrap"})

# 9. Tiny-step sequence around wrap to exercise comparator monotonicity.
base_ts = 0xFFFF_FFF0
for i in range(1, 9):
    ts = (base_ts + i) & 0xFFFF_FFFF
    frames.append(frame(SEQ0 + 16 + 2 * i, ts, 100))
    manifest_entries.append(
        {"indexes": [len(frames) - 1], "flags": f"ts:sweep_{i}"}
    )

# 10. TSecr = 0xFFFF_FFFF (echo of peer's pre-wrap TS).
frames.append(frame(SEQ0 + 40, 10, 0xFFFF_FFFF))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "ts:tsecr_max"})

NAME = "timestamp_wraparound"
out_dir = Path(__file__).resolve().parents[1] / "out"
out_dir.mkdir(parents=True, exist_ok=True)

# Pin per-frame timestamps so wrpcap output is byte-stable.
for i, f in enumerate(frames):
    f.time = float(i)

wrpcap(str(out_dir / f"{NAME}.pcap"), frames)

manifest = {
    "description": "TCP Timestamp option wraparound / PAWS edge cases",
    "frames": manifest_entries,
}
with open(out_dir / f"{NAME}.manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"wrote {NAME}.pcap + manifest ({len(frames)} frames)")
