//! Replay Scapy-generated pcap corpora through the test-inject RX hook.
//! Each .pcap is paired with a .manifest.json describing which frames
//! are single-seg vs multi-seg chain groups.
//!
//! Usage:
//!   scapy-fuzz-runner --corpus tools/scapy-corpus/out/

use anyhow::{Context, Result};
use clap::Parser;
use pcap_file::pcap::PcapReader;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Replay Scapy pcap corpora through Engine::inject_rx_*")]
struct Args {
    /// Path to the corpus directory (contains *.pcap + *.manifest.json pairs).
    #[arg(long)]
    corpus: PathBuf,
}

#[derive(Deserialize)]
struct Manifest {
    frames: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
struct ManifestEntry {
    indexes: Vec<usize>,
    #[serde(default)]
    chain: bool,
    #[serde(default)]
    #[allow(dead_code)]
    flags: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Reuse the test fixture hoisted in T20: dpdk_net_core::test_fixtures::make_test_engine()
    let engine = match dpdk_net_core::test_fixtures::make_test_engine() {
        Some(e) => e,
        None => {
            eprintln!("scapy-fuzz-runner: DPDK_NET_TEST_TAP not set; corpus compile-checked only.");
            return Ok(());
        }
    };

    let mut pcap_count = 0;
    let mut frame_count = 0;

    for entry in std::fs::read_dir(&args.corpus)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("pcap") {
            continue;
        }

        let manifest_path = path.with_extension("manifest.json");
        let manifest: Manifest = serde_json::from_reader(
            File::open(&manifest_path)
                .with_context(|| format!("open manifest {:?}", manifest_path))?,
        )
        .with_context(|| format!("parse manifest {:?}", manifest_path))?;

        // Load all frames from the pcap into memory. pcap-file 2.x exposes
        // a `next_packet()` Option<Result<...>> rather than an Iterator impl,
        // so we drain it explicitly.
        let file = File::open(&path).with_context(|| format!("open pcap {:?}", path))?;
        let mut pcap_reader = PcapReader::new(file)?;
        let mut frames: Vec<Vec<u8>> = Vec::new();
        while let Some(pkt) = pcap_reader.next_packet() {
            let pkt = pkt.with_context(|| format!("read pcap frame {:?}", path))?;
            frames.push(pkt.data.into_owned());
        }

        for e in &manifest.frames {
            if e.chain {
                let chunks: Vec<&[u8]> = e.indexes.iter().map(|&i| frames[i].as_slice()).collect();
                engine
                    .inject_rx_chain(&chunks)
                    .with_context(|| format!("inject_rx_chain for {:?}", path))?;
                frame_count += chunks.len();
            } else {
                for &i in &e.indexes {
                    engine
                        .inject_rx_frame(&frames[i])
                        .with_context(|| format!("inject_rx_frame for {:?} idx {}", path, i))?;
                    frame_count += 1;
                }
            }
        }

        pcap_count += 1;
        println!(
            "replayed {:?}: {} frames",
            path.file_name().unwrap(),
            frames.len()
        );
    }

    let ctrs = engine.counters();
    eprintln!(
        "scapy-fuzz-runner: replayed {} pcaps / {} frames",
        pcap_count, frame_count
    );
    eprintln!(
        "  eth.rx_bytes = {}",
        ctrs.eth.rx_bytes.load(std::sync::atomic::Ordering::Relaxed)
    );
    Ok(())
}
