//! Live-interface tooling for the namespace test: send captures, count inbound frames.

use std::fs::File;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use pcap::{Active, Capture, Direction};
use pcap_file::pcap::PcapReader;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Loads every frame of the given Ethernet pcap files, in order.
fn load(files: &[PathBuf]) -> Result<Vec<Vec<u8>>, String> {
    let mut frames = Vec::new();
    for p in files {
        let f = File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let mut r = PcapReader::new(f).map_err(|e| format!("{}: {e}", p.display()))?;
        while let Some(pkt) = r.next_packet() {
            let pkt = pkt.map_err(|e| format!("{}: {e}", p.display()))?;
            frames.push(pkt.data.into_owned());
        }
    }
    // The kernel refuses frames shorter than an Ethernet header (the runt in the
    // generic scenario); they cannot go on a wire, so they are skipped.
    let all = frames.len();
    frames.retain(|f| f.len() >= 14);
    if frames.len() != all {
        eprintln!(
            "testgen: skipped {} frames shorter than 14 bytes",
            all - frames.len()
        );
    }
    Ok(frames)
}

fn open(iface: &str) -> Result<Capture<Active>, String> {
    Capture::from_device(iface)
        .map_err(err)?
        .open()
        .map_err(|e| format!("{iface}: {e}"))
}

/// Sends the frames once (or looped for `seconds`) at `rate` frames per second.
/// Returns the number of frames sent and the elapsed time.
pub fn inject(
    iface: &str,
    files: &[PathBuf],
    rate: u64,
    seconds: Option<f64>,
) -> Result<(u64, Duration), String> {
    let frames = load(files)?;
    if frames.is_empty() {
        return Err("no frames to send".into());
    }
    let mut cap = open(iface)?;
    let start = Instant::now();
    let limit = seconds.map(Duration::from_secs_f64);
    let mut sent: u64 = 0;
    let mut i = 0usize;
    let mut retries = 0u64;
    loop {
        let elapsed = start.elapsed();
        if let Some(l) = limit {
            if elapsed >= l {
                break;
            }
        } else if sent >= frames.len() as u64 {
            break;
        }
        // Frames owed by now at the requested rate; sleep when ahead of it.
        let due = (elapsed.as_secs_f64() * rate as f64) as u64 + 1;
        if sent >= due {
            std::thread::sleep(Duration::from_micros(100));
            continue;
        }
        while sent < due {
            let Some(f) = frames.get(i) else { break };
            match cap.sendpacket(f.as_slice()) {
                Ok(()) => sent += 1,
                // The transmit queue is full: back off and retry the same frame.
                Err(e) => {
                    if retries == 0 {
                        eprintln!("testgen: send: {e}");
                    }
                    retries += 1;
                    if retries > 20_000 {
                        return Err(format!("send: {e}"));
                    }
                    std::thread::sleep(Duration::from_micros(50));
                    break;
                }
            }
            i += 1;
            if i == frames.len() {
                if limit.is_none() {
                    break;
                }
                i = 0;
            }
            if limit.is_some_and(|l| start.elapsed() >= l) {
                break;
            }
        }
    }
    Ok((sent, start.elapsed()))
}

/// Counts frames arriving on `iface` (direction In) for `seconds`.
pub fn count_inbound(iface: &str, seconds: f64) -> Result<u64, String> {
    let cap = Capture::from_device(iface)
        .map_err(err)?
        .timeout(50)
        .immediate_mode(true)
        .open()
        .map_err(|e| format!("{iface}: {e}"))?;
    cap.direction(Direction::In).map_err(err)?;
    let mut cap = cap.setnonblock().map_err(err)?;
    let end = Instant::now() + Duration::from_secs_f64(seconds);
    let mut n = 0;
    while Instant::now() < end {
        match cap.next_packet() {
            Ok(_) => n += 1,
            Err(pcap::Error::TimeoutExpired) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(err(e)),
        }
    }
    Ok(n)
}
