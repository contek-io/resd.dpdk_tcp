#!/usr/bin/env python3
"""
Overlapping-segment corpus: prefix/suffix/interior overlap pairs.

Emits pairs of segments that overlap in the sequence space:
  - prefix overlap: second segment starts before first ends, same start
  - suffix overlap: second segment extends past first's end, starting
    inside first
  - interior overlap: second segment fully contained in first
  - tail-interior: second segment's tail falls inside first (left-edge
    before first's start)

Each pair is emitted as two independent frames (not a chain); the runner
will inject each via inject_rx_frame so the reassembly logic must handle
overlap.

Seed: 0xA9E02.
"""
import json
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SEED = 0xA9E02
random.seed(SEED)

LOCAL_MAC = "02:00:00:00:00:01"
LOCAL_IP = "10.0.0.1"
PEER_MAC = "02:00:00:00:00:99"
PEER_IP = "10.0.0.2"

SPORT = 2000
DPORT = 5678
BASE_SEQ = 100_000
ACK = 42
WIN = 16384


def seg(seq: int, length: int):
    """Build a single ACK-only TCP segment with `length` random payload bytes."""
    payload = bytes(random.randint(0, 255) for _ in range(length))
    return (
        Ether(src=PEER_MAC, dst=LOCAL_MAC)
        / IP(src=PEER_IP, dst=LOCAL_IP)
        / TCP(sport=SPORT, dport=DPORT, seq=seq, ack=ACK, flags="A", window=WIN)
        / Raw(payload)
    )


frames = []
manifest_entries = []
idx = 0


def emit_pair(tag: str, first: tuple[int, int], second: tuple[int, int]) -> None:
    """Append two segments and two manifest entries tagged with `tag`."""
    global idx
    s1, l1 = first
    s2, l2 = second
    frames.append(seg(s1, l1))
    frames.append(seg(s2, l2))
    manifest_entries.append({"indexes": [idx], "flags": f"overlap:{tag}:first"})
    manifest_entries.append({"indexes": [idx + 1], "flags": f"overlap:{tag}:second"})
    idx += 2


# 1. Prefix overlap: same start, second is shorter prefix of first.
emit_pair("prefix_same_start", (BASE_SEQ, 200), (BASE_SEQ, 100))

# 2. Prefix overlap: second starts before first's end, same start but bigger.
emit_pair("prefix_expanded", (BASE_SEQ + 1000, 100), (BASE_SEQ + 1000, 200))

# 3. Suffix overlap: second starts inside first and extends past its end.
emit_pair("suffix", (BASE_SEQ + 2000, 200), (BASE_SEQ + 2100, 200))

# 4. Interior overlap: second fully contained inside first.
emit_pair("interior", (BASE_SEQ + 3000, 400), (BASE_SEQ + 3100, 100))

# 5. Tail-interior: second's tail is inside first, left-edge before first.
emit_pair("left_extend", (BASE_SEQ + 4000, 200), (BASE_SEQ + 3950, 100))

# 6. Exact duplicate.
emit_pair("exact_dup", (BASE_SEQ + 5000, 150), (BASE_SEQ + 5000, 150))

# 7. Reverse order suffix (later arrives first).
emit_pair("suffix_reversed", (BASE_SEQ + 6100, 200), (BASE_SEQ + 6000, 200))

NAME = "overlapping_segments"
out_dir = Path(__file__).resolve().parents[1] / "out"
out_dir.mkdir(parents=True, exist_ok=True)

# Pin per-frame timestamps so wrpcap output is byte-stable.
for i, f in enumerate(frames):
    f.time = float(i)

wrpcap(str(out_dir / f"{NAME}.pcap"), frames)

manifest = {
    "description": "Overlapping segment pairs (prefix/suffix/interior/dup)",
    "frames": manifest_entries,
}
with open(out_dir / f"{NAME}.manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"wrote {NAME}.pcap + manifest ({len(frames)} frames, {len(manifest_entries)} entries)")
