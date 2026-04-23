#!/usr/bin/env python3
"""
Malformed TCP options corpus.

Emits frames with deliberately malformed option fields, targeting the TCP
option parser's robustness:
  - length=0 (infinite-loop hazard)
  - length=1 (smaller than header byte count)
  - length > remaining bytes in options area
  - unknown option kinds (kind=0xFE, 0xFD, ...)
  - truncated: option announces more bytes than are present
  - mixed good+bad in one option block

We bypass Scapy's TCPOptions cooker by crafting the options field as a raw
bytes blob attached via a re-parsed TCP layer. The data offset (dataofs) is
set to cover the options area so the TCP layer is self-consistent; the
options payload itself is intentionally bogus.

Seed: 0xA9E03.
"""
import json
import random
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, wrpcap

SEED = 0xA9E03
random.seed(SEED)

LOCAL_MAC = "02:00:00:00:00:01"
LOCAL_IP = "10.0.0.1"
PEER_MAC = "02:00:00:00:00:99"
PEER_IP = "10.0.0.2"

SPORT = 3000
DPORT = 5678
SEQ = 500_000
ACK = 200_000
WIN = 4096


def craft(opt_bytes: bytes, syn: bool = False) -> bytes:
    """Build an Ether/IP/TCP frame whose TCP options are the given raw bytes.

    The options area is padded to a 4-byte multiple and dataofs is set
    accordingly so the TCP header is syntactically well-formed; the option
    payload is deliberately malformed per test case.
    """
    pad = (-len(opt_bytes)) % 4
    opts = opt_bytes + b"\x00" * pad
    dataofs = 5 + len(opts) // 4  # 5 = base header words

    flags = "S" if syn else "A"
    tcp = TCP(sport=SPORT, dport=DPORT, seq=SEQ, ack=ACK, flags=flags, window=WIN)
    tcp.dataofs = dataofs

    # Scapy serializes TCP options via the `options` attribute. To bypass
    # its cooker, we pack a raw TCP header and splice in our bytes.
    raw_tcp = bytes(tcp)
    # The TCP header ends at dataofs*4 once we append opts below.
    # First 20 bytes of raw_tcp are the base header; discard any existing
    # option bytes Scapy may have added (there are none for our flags).
    base = raw_tcp[:20]
    tcp_bytes = base + opts

    eth_ip = Ether(src=PEER_MAC, dst=LOCAL_MAC) / IP(src=PEER_IP, dst=LOCAL_IP)
    pkt = eth_ip / Raw(tcp_bytes)
    return pkt


frames = []
manifest_entries = []

# 1. Kind=8 (Timestamps) with length=0 — infinite-loop trap.
frames.append(craft(b"\x08\x00"))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:ts_len0"})

# 2. Kind=3 (WScale) with length=1 — less than minimum.
frames.append(craft(b"\x03\x01"))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:wscale_len1"})

# 3. Kind=2 (MSS) with length=20 but only 2 bytes present — truncated.
frames.append(craft(b"\x02\x14\x05\xb4", syn=True))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:mss_trunc"})

# 4. Kind=4 (SACK-permitted) with length=5 > its spec of 2 — length > spec.
frames.append(craft(b"\x04\x05\x00\x00\x00"))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:sackperm_overlen"})

# 5. Unknown kind 0xFE with length=4 and arbitrary data.
unk1 = bytes([0xFE, 0x04]) + bytes(random.randint(0, 255) for _ in range(2))
frames.append(craft(unk1))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:unknown_fe"})

# 6. Unknown kind 0xFD with length=2 (empty body).
frames.append(craft(b"\xfd\x02"))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:unknown_fd"})

# 7. Length > remaining: option announces 40 bytes but only 6 present.
frames.append(craft(b"\x08\x28\x00\x00\x00\x00"))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:len_gt_remaining"})

# 8. Mixed good+bad: NOP, NOP, MSS(len=4), bogus kind 0xFC(len=0).
frames.append(craft(b"\x01\x01\x02\x04\x05\xb4\xfc\x00", syn=True))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:mixed_good_bad"})

# 9. EOL followed by garbage (should terminate parse per RFC 9293).
frames.append(craft(b"\x00\xde\xad\xbe\xef"))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:eol_then_garbage"})

# 10. All zeros (kind=0 EOL immediately).
frames.append(craft(b"\x00\x00\x00\x00"))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:all_zero"})

# 11. Kind=8 (Timestamps) with length=10 (valid) but with all-ones ts values.
ts_opt = b"\x08\x0a\xff\xff\xff\xff\xff\xff\xff\xff"
frames.append(craft(ts_opt))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:ts_allones"})

# 12. Looping-hazard: NOP NOP followed by kind with length pointing backward.
# length=1 on kind=X makes cursor advance less than 2; implementations must
# reject or force-advance.
frames.append(craft(b"\x01\x01\x05\x01"))
manifest_entries.append({"indexes": [len(frames) - 1], "flags": "opt:len1_loop_hazard"})

NAME = "malformed_options"
out_dir = Path(__file__).resolve().parents[1] / "out"
out_dir.mkdir(parents=True, exist_ok=True)

# Pin per-frame timestamps so wrpcap output is byte-stable.
for i, f in enumerate(frames):
    f.time = float(i)

wrpcap(str(out_dir / f"{NAME}.pcap"), frames)

manifest = {
    "description": "Malformed TCP options (length=0, len>remaining, unknown kinds, mixed)",
    "frames": manifest_entries,
}
with open(out_dir / f"{NAME}.manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(f"wrote {NAME}.pcap + manifest ({len(frames)} frames)")
