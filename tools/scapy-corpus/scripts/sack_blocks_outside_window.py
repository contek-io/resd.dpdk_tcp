#!/usr/bin/env python3
"""
SACK blocks outside rcv window corpus (RFC 2018 compliance).

Emits ACKs carrying SACK option blocks whose ranges are intentionally
out-of-window from the receiver's perspective. The receiver's SACK
processor must drop / ignore such blocks rather than applying them to
its retransmission scoreboard.

Cases:
  - Block entirely below rcv.nxt
  - Block entirely above rcv.wnd
  - Block straddling rcv.nxt (partial below)
  - Block straddling rcv.wnd (partial above)
  - Zero-length block (left == right)
  - Inverted block (left > right)
  - Duplicate blocks
  - Maximum number of blocks (4) all out-of-window
  - Block wrapping through u32 zero

We emit a neutral ACK frame as carrier; the SACK option is what matters.
The peer is assumed to have rcv.nxt=500_000 and rcv.wnd=32_768 so the
in-window range is [500_000, 532_768).

Seed: 0xA9E05.
"""
import json
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap

SEED = 0xA9E05
random.seed(SEED)

LOCAL_MAC = "02:00:00:00:00:01"
LOCAL_IP = "10.0.0.1"
PEER_MAC = "02:00:00:00:00:99"
PEER_IP = "10.0.0.2"

SPORT = 5000
DPORT = 5678
SEQ = 1_000_000
ACK = 500_000  # peer's expected rcv.nxt
WIN = 32_768

RCV_NXT = 500_000
RCV_WND = 32_768
IN_WINDOW_HI = RCV_NXT + RCV_WND  # 532_768


def ack_with_sack(blocks: list[tuple[int, int]]):
    # Scapy SAckOK vs SAck — `SAck` option stores a flat tuple of ints
    # [left0, right0, left1, right1, ...].
    flat = []
    for left, right in blocks:
        flat.append(left & 0xFFFF_FFFF)
        flat.append(right & 0xFFFF_FFFF)
    opts = [("SAck", tuple(flat))]
    return (
        Ether(src=PEER_MAC, dst=LOCAL_MAC)
        / IP(src=PEER_IP, dst=LOCAL_IP)
        / TCP(
            sport=SPORT,
            dport=DPORT,
            seq=SEQ,
            ack=ACK,
            flags="A",
            window=WIN,
            options=opts,
        )
    )


frames = []
manifest_entries = []


def emit(tag: str, blocks: list[tuple[int, int]]) -> None:
    frames.append(ack_with_sack(blocks))
    manifest_entries.append(
        {"indexes": [len(frames) - 1], "flags": f"sack:{tag}"}
    )


# 1. Block entirely below rcv.nxt.
emit("below_nxt", [(RCV_NXT - 2000, RCV_NXT - 1000)])

# 2. Block entirely above rcv.wnd.
emit("above_wnd", [(IN_WINDOW_HI + 1000, IN_WINDOW_HI + 2000)])

# 3. Block straddling rcv.nxt (partial below, partial in).
emit("straddle_nxt", [(RCV_NXT - 500, RCV_NXT + 500)])

# 4. Block straddling rcv.wnd (partial in, partial above).
emit("straddle_wnd", [(IN_WINDOW_HI - 500, IN_WINDOW_HI + 500)])

# 5. Zero-length block.
emit("zero_len", [(RCV_NXT + 1000, RCV_NXT + 1000)])

# 6. Inverted block (left > right).
emit("inverted", [(RCV_NXT + 2000, RCV_NXT + 1000)])

# 7. Duplicate blocks.
emit(
    "duplicate",
    [(RCV_NXT + 4000, RCV_NXT + 5000), (RCV_NXT + 4000, RCV_NXT + 5000)],
)

# 8. Maximum blocks (4 is the protocol ceiling when combined with TS option;
# 3 is safe without TS — we emit 3 here to stay under the 40-byte options
# limit without stacking TS).
emit(
    "max_blocks_all_oow",
    [
        (0, 100),
        (0xFFFF_0000, 0xFFFF_1000),
        (IN_WINDOW_HI + 10_000, IN_WINDOW_HI + 11_000),
    ],
)

# 9. Block wrapping through u32 zero (huge left, small right).
emit("wraps_u32", [(0xFFFF_FF00, 0x0000_0100)])

# 10. All four corners of the window (left edge below, right edge above).
emit(
    "spans_window",
    [(RCV_NXT - 10_000, IN_WINDOW_HI + 10_000)],
)

# 11. Well-formed in-window block (negative-case control) — should be
# ACCEPTED by SACK processor. Included so the runner has a positive control.
emit("in_window_ctrl", [(RCV_NXT + 1000, RCV_NXT + 2000)])

NAME = "sack_blocks_outside_window"
out_dir = Path(__file__).resolve().parents[1] / "out"
out_dir.mkdir(parents=True, exist_ok=True)

# Pin per-frame timestamps so wrpcap output is byte-stable.
for i, f in enumerate(frames):
    f.time = float(i)

wrpcap(str(out_dir / f"{NAME}.pcap"), frames)

manifest = {
    "description": "SACK blocks outside rcv window (RFC 2018)",
    "rcv_nxt": RCV_NXT,
    "rcv_wnd": RCV_WND,
    "frames": manifest_entries,
}
with open(out_dir / f"{NAME}.manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"wrote {NAME}.pcap + manifest ({len(frames)} frames)")
