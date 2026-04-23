#!/usr/bin/env python3
"""
RST with seq outside RFC 5961 §3 acceptable window.

RFC 5961 §3 hardens receivers against blind RST attacks by narrowing the
acceptable RST to SEG.SEQ == RCV.NXT (with a challenge-ACK escape for
RSTs that fall in-window but mid-stream). This corpus exercises:
  - RST below RCV.NXT (off the left edge) — must drop
  - RST above RCV.NXT + RCV.WND (off the right edge) — must drop
  - RST exactly at RCV.NXT — must accept
  - RST in-window, not at RCV.NXT — must send challenge ACK, not reset
  - RST far off-window (wraparound distances) — must drop
  - RST with bogus data / payload — data MUST be ignored per RFC 9293 §3.10.7
  - RST+SYN combination — must drop
  - RST with ACK+URG flags set — must drop (or treat per RFC 5961)

Assumes peer state rcv.nxt = 800_000, rcv.wnd = 16_384 so in-window range
is [800_000, 816_384).

Seed: 0xA9E06.
"""
import json
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SEED = 0xA9E06
random.seed(SEED)

LOCAL_MAC = "02:00:00:00:00:01"
LOCAL_IP = "10.0.0.1"
PEER_MAC = "02:00:00:00:00:99"
PEER_IP = "10.0.0.2"

SPORT = 6000
DPORT = 5678
ACK = 99
WIN = 8192

RCV_NXT = 800_000
RCV_WND = 16_384
IN_WINDOW_HI = RCV_NXT + RCV_WND


def rst(seq: int, flags: str = "R", payload: bytes = b""):
    seq &= 0xFFFF_FFFF
    pkt = (
        Ether(src=PEER_MAC, dst=LOCAL_MAC)
        / IP(src=PEER_IP, dst=LOCAL_IP)
        / TCP(sport=SPORT, dport=DPORT, seq=seq, ack=ACK, flags=flags, window=WIN)
    )
    if payload:
        pkt = pkt / Raw(payload)
    return pkt


frames = []
manifest_entries = []


def emit(tag: str, pkt) -> None:
    frames.append(pkt)
    manifest_entries.append(
        {"indexes": [len(frames) - 1], "flags": f"rst:{tag}"}
    )


# 1. RST below rcv.nxt (off left edge by 1000).
emit("below_nxt", rst(RCV_NXT - 1000))

# 2. RST above rcv.nxt + rcv.wnd (off right edge by 1000).
emit("above_wnd", rst(IN_WINDOW_HI + 1000))

# 3. RST exactly at rcv.nxt — acceptable per RFC 5961.
emit("exact_nxt", rst(RCV_NXT))

# 4. RST in-window but not at rcv.nxt — challenge-ACK, not reset.
emit("in_window_offset", rst(RCV_NXT + 4000))

# 5. RST very far below (2^30 away — wraparound distance).
emit("far_below_wrap", rst((RCV_NXT - (1 << 30)) & 0xFFFF_FFFF))

# 6. RST very far above (2^30 ahead).
emit("far_above_wrap", rst((RCV_NXT + (1 << 30)) & 0xFFFF_FFFF))

# 7. RST at right-edge sentinel (rcv.nxt + rcv.wnd exactly) — on boundary;
# depends on whether window is half-open.
emit("right_edge_exact", rst(IN_WINDOW_HI))

# 8. RST one past right edge.
emit("right_edge_plus1", rst(IN_WINDOW_HI + 1))

# 9. RST one before left edge.
emit("left_edge_minus1", rst(RCV_NXT - 1))

# 10. RST with non-empty payload (20 bytes).
payload = bytes(random.randint(0, 255) for _ in range(20))
emit("with_payload", rst(RCV_NXT + 2000, payload=payload))

# 11. RST+SYN — must be dropped unconditionally.
emit("rst_syn_combo", rst(RCV_NXT, flags="RS"))

# 12. RST+ACK (common in closing handshakes) below window.
emit("rst_ack_below", rst(RCV_NXT - 5000, flags="RA"))

# 13. RST+URG flags set.
emit("rst_urg", rst(RCV_NXT, flags="RU"))

# 14. RST with all flags set (malicious / fuzzer-ish).
emit("rst_all_flags", rst(RCV_NXT + 100, flags="FSRPAU"))

# 15. Storm of off-window RSTs (10 randomly-placed frames far outside
# the window) — exercises rate-limit / challenge-ACK budget.
random.seed(SEED + 1)
for i in range(10):
    # Place each well above IN_WINDOW_HI and below u32 max/2.
    seq = IN_WINDOW_HI + 100_000 + random.randint(0, 10_000_000)
    emit(f"storm_{i}", rst(seq))

NAME = "rst_invalid_seq"
out_dir = Path(__file__).resolve().parents[1] / "out"
out_dir.mkdir(parents=True, exist_ok=True)

# Pin per-frame timestamps so wrpcap output is byte-stable.
for i, f in enumerate(frames):
    f.time = float(i)

wrpcap(str(out_dir / f"{NAME}.pcap"), frames)

manifest = {
    "description": "RST with seq outside RFC 5961 §3 acceptable window",
    "rcv_nxt": RCV_NXT,
    "rcv_wnd": RCV_WND,
    "frames": manifest_entries,
}
with open(out_dir / f"{NAME}.manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"wrote {NAME}.pcap + manifest ({len(frames)} frames)")
