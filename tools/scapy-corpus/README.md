# Scapy adversarial corpus

Each script in `scripts/` generates a deterministic `.pcap` + `.manifest.json`
pair in `out/` (gitignored). Regenerate all via `scripts/scapy-corpus.sh`.

Seeds in `seeds.txt` pin RNG values; bump when intentionally changing corpus
shape for a given script.

Replayed by `tools/scapy-fuzz-runner/` (T22) which reads manifests and
dispatches each entry through `Engine::inject_rx_frame` or `inject_rx_chain`.

## Scripts
- `i8_fin_piggyback_multi_seg.py` — directed I-8 regression
- `overlapping_segments.py` — prefix/suffix/interior overlap pairs
- `malformed_options.py` — length=0, length>remaining, unknown kinds
- `timestamp_wraparound.py` — TS near 2^32 (PAWS edge)
- `sack_blocks_outside_window.py` — SACK blocks outside rcv window
- `rst_invalid_seq.py` — RST with seq outside RFC 5961 §3 window

## Manifest schema

Each `<name>.manifest.json` lists frame groupings:

```json
{
  "frames": [
    {"indexes": [0], "flags": "FIN"},
    {"indexes": [1, 2], "chain": true, "flags": "FIN"}
  ]
}
```

- `indexes` — frame indexes (0-based) into the sibling pcap
- `chain` — optional; when true, runner groups the frames into an rte_mbuf
  chain and calls `inject_rx_chain` instead of `inject_rx_frame` per-frame
- `flags` — free-form string tag describing intent (diagnostic only)

## Dependencies
- Python 3
- Scapy (`pip install scapy`)

Runtime: < 10s for full regeneration.
