//! pcap and pcapng writers for generated captures.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use pcap_file::DataLink;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;

/// A frame to write. `orig_len` larger than `data.len()` models a snaplen cut.
#[derive(Debug, Clone)]
pub struct TFrame {
    pub sec: i64,
    pub usec: u32,
    pub data: Vec<u8>,
    pub orig_len: Option<u32>,
}

impl TFrame {
    fn orig(&self) -> u32 {
        self.orig_len.unwrap_or(self.data.len() as u32)
    }
}

fn io_err(e: pcap_file::PcapError) -> io::Error {
    io::Error::other(e.to_string())
}

fn pcap_to<W: Write>(out: W, linktype: u32, snaplen: u32, frames: &[TFrame]) -> io::Result<W> {
    let header = PcapHeader {
        datalink: DataLink::from(linktype),
        snaplen,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(out, header).map_err(io_err)?;
    for f in frames {
        let ts = Duration::new(f.sec as u64, f.usec * 1000);
        let p = PcapPacket::new(ts, f.orig(), &f.data);
        w.write_packet(&p).map_err(io_err)?;
    }
    Ok(w.into_writer())
}

/// Ethernet, microsecond timestamps.
pub fn write_pcap(path: &Path, frames: &[TFrame]) -> io::Result<()> {
    write_pcap_linktype(path, 1, frames)
}

pub fn write_pcap_linktype(path: &Path, linktype: u32, frames: &[TFrame]) -> io::Result<()> {
    fs::write(path, pcap_bytes_linktype(linktype, frames))
}

/// Ethernet pcap whose global header carries `snaplen` (frames may have a larger `orig_len`).
pub fn write_pcap_snaplen(path: &Path, snaplen: u32, frames: &[TFrame]) -> io::Result<()> {
    fs::write(path, pcap_bytes_snaplen(1, snaplen, frames))
}

pub fn pcap_bytes(frames: &[TFrame]) -> Vec<u8> {
    pcap_bytes_linktype(1, frames)
}

fn pcap_bytes_linktype(linktype: u32, frames: &[TFrame]) -> Vec<u8> {
    pcap_bytes_snaplen(linktype, 65535, frames)
}

fn pcap_bytes_snaplen(linktype: u32, snaplen: u32, frames: &[TFrame]) -> Vec<u8> {
    // Writing into a Vec only fails for frames beyond the snaplen.
    pcap_to(Vec::new(), linktype, snaplen, frames).expect("frames fit pcap limits")
}

/// Ethernet, default (microsecond) timestamp resolution.
pub fn write_pcapng(path: &Path, frames: &[TFrame]) -> io::Result<()> {
    let tagged: Vec<(u32, TFrame)> = frames.iter().map(|f| (0, f.clone())).collect();
    write_pcapng_interfaces(path, 1, &tagged)
}

/// pcapng with `n_ifaces` Ethernet interfaces; each frame is tagged with its interface id.
pub fn write_pcapng_interfaces(
    path: &Path,
    n_ifaces: u32,
    frames: &[(u32, TFrame)],
) -> io::Result<()> {
    let mut w = PcapNgWriter::new(Vec::new()).map_err(io_err)?;
    for _ in 0..n_ifaces {
        w.write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65535))
            .map_err(io_err)?;
    }
    for (iface, f) in frames {
        // pcap-file writes the Duration as raw ticks (nanoseconds field = ticks),
        // and the default if_tsresol is microseconds.
        let ticks = f.sec as u64 * 1_000_000 + u64::from(f.usec);
        let epb = EnhancedPacketBlock {
            interface_id: *iface,
            timestamp: Duration::from_nanos(ticks),
            original_len: f.orig(),
            data: f.data.as_slice().into(),
            options: vec![],
        };
        w.write_pcapng_block(epb).map_err(io_err)?;
    }
    fs::write(path, w.into_inner())
}

/// pcapng with an `if_tsoffset` option on the interface, written by hand
/// (little-endian) so the layout is exactly known.
pub fn write_pcapng_tsoffset(path: &Path, tsoffset: i64, frames: &[TFrame]) -> io::Result<()> {
    let mut b: Vec<u8> = Vec::new();
    // Section header block, 28 bytes, unknown section length.
    b.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
    b.extend_from_slice(&28u32.to_le_bytes());
    b.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&(-1i64).to_le_bytes());
    b.extend_from_slice(&28u32.to_le_bytes());
    // Interface description block, 36 bytes.
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&36u32.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&65535u32.to_le_bytes());
    b.extend_from_slice(&14u16.to_le_bytes());
    b.extend_from_slice(&8u16.to_le_bytes());
    b.extend_from_slice(&tsoffset.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&36u32.to_le_bytes());
    for f in frames {
        let pad = (4 - f.data.len() % 4) % 4;
        let total = (32 + f.data.len() + pad) as u32;
        let ticks = f.sec as u64 * 1_000_000 + u64::from(f.usec);
        b.extend_from_slice(&6u32.to_le_bytes());
        b.extend_from_slice(&total.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        b.extend_from_slice(&(ticks as u32).to_le_bytes());
        b.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        b.extend_from_slice(&f.orig().to_le_bytes());
        b.extend_from_slice(&f.data);
        b.extend(std::iter::repeat_n(0u8, pad));
        b.extend_from_slice(&total.to_le_bytes());
    }
    fs::write(path, b)
}
