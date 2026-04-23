#!/usr/bin/env python3
"""
I-8 regression corpus: multi-seg chain with FIN piggybacked on last link.

Directed regression for I-8 (FIN arriving on the tail of a multi-segment
mbuf chain must be observed; should not be dropped because earlier links
lacked the flag). Two frames, grouped as a single chain via manifest.

Seed: 0xA9E01 (committed in ../seeds.txt).
"""
import json
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SEED = 0xA9E01
random.seed(SEED)

LOCAL_MAC = "02:00:00:00:00:01"
LOCAL_IP = "10.0.0.1"
PEER_MAC = "02:00:00:00:00:99"
PEER_IP = "10.0.0.2"

SPORT = 1234
DPORT = 5678
ISN = 1000
ACK = 500
WIN = 8192

HEAD_PAYLOAD_LEN = 100
TAIL_PAYLOAD_LEN = 50

frames = []

# Head link — ACK only, first half of payload.
head_payload = bytes(random.randint(0, 255) for _ in range(HEAD_PAYLOAD_LEN))
head = (
    Ether(src=PEER_MAC, dst=LOCAL_MAC)
    / IP(src=PEER_IP, dst=LOCAL_IP)
    / TCP(sport=SPORT, dport=DPORT, seq=ISN, ack=ACK, flags="A", window=WIN)
    / Raw(head_payload)
)
frames.append(head)

# Tail link — FIN|ACK, second half of payload, contiguous seq.
tail_payload = bytes(random.randint(0, 255) for _ in range(TAIL_PAYLOAD_LEN))
tail = (
    Ether(src=PEER_MAC, dst=LOCAL_MAC)
    / IP(src=PEER_IP, dst=LOCAL_IP)
    / TCP(
        sport=SPORT,
        dport=DPORT,
        seq=ISN + HEAD_PAYLOAD_LEN,
        ack=ACK,
        flags="FA",
        window=WIN,
    )
    / Raw(tail_payload)
)
frames.append(tail)

NAME = "i8_fin_piggyback_multi_seg"
out_dir = Path(__file__).resolve().parents[1] / "out"
out_dir.mkdir(parents=True, exist_ok=True)

# Pin per-frame timestamps so wrpcap output is byte-stable.
for i, f in enumerate(frames):
    f.time = float(i)

wrpcap(str(out_dir / f"{NAME}.pcap"), frames)

manifest = {
    "description": "I-8 regression: two-link chain, FIN on tail",
    "frames": [
        {"indexes": [0, 1], "chain": True, "flags": "FIN"},
    ],
}
with open(out_dir / f"{NAME}.manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"wrote {NAME}.pcap + manifest ({len(frames)} frames as 1 chain)")
