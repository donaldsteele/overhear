//! Pure-Rust reader for pcap and pcapng capture files.
//!
//! This does not apply the pcapng `if_tsoffset` option; the libpcap-backed
//! path applies it. Sub-microsecond precision is truncated.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{Block, PcapNgReader};
use pcap_file::{DataLink, PcapError};

use crate::source::{Frame, LinkType, Next, Source, SourceError, SourceStats};

const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

enum Inner {
    Pcap(PcapReader<File>),
    Ng {
        reader: PcapNgReader<File>,
        /// Raw `if_tsresol` byte of interface 0.
        tsresol: u8,
    },
}

pub struct FileSource {
    inner: Inner,
    link: LinkType,
}

fn map_err(e: PcapError) -> SourceError {
    match e {
        PcapError::IncompleteBuffer => SourceError::Truncated("incomplete record".into()),
        PcapError::IoError(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => {
            SourceError::Truncated("file ends inside a record".into())
        }
        PcapError::IoError(io) => SourceError::Io(io.to_string()),
        other => SourceError::Unsupported(other.to_string()),
    }
}

fn link_type(dl: DataLink) -> LinkType {
    match u32::from(dl) {
        1 => LinkType::Ethernet,
        n => LinkType::Other(n),
    }
}

/// Ticks per second for a pcapng `if_tsresol` byte.
fn ticks_per_sec(tsresol: u8) -> Option<u128> {
    if tsresol & 0x80 == 0 {
        10u128.checked_pow(u32::from(tsresol))
    } else {
        1u128.checked_shl(u32::from(tsresol & 0x7f))
    }
}

impl FileSource {
    pub fn open(path: &Path) -> Result<FileSource, SourceError> {
        let io = |e: std::io::Error| SourceError::Io(format!("{}: {e}", path.display()));
        let mut file = File::open(path).map_err(io)?;
        let mut magic = [0u8; 4];
        let n = file.read(&mut magic).map_err(io)?;
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        if n < 4 {
            return Err(SourceError::Truncated(
                "file too short for a capture header".into(),
            ));
        }
        if magic == PCAPNG_MAGIC {
            let mut reader = PcapNgReader::new(file).map_err(map_err)?;
            // Read up to the first interface description to learn the link type.
            loop {
                match reader.next_block() {
                    None => {
                        return Err(SourceError::Unsupported("pcapng has no interface".into()));
                    }
                    Some(Err(e)) => return Err(map_err(e)),
                    Some(Ok(Block::InterfaceDescription(idb))) => {
                        let tsresol = idb
                            .options
                            .iter()
                            .find_map(|o| match o {
                                InterfaceDescriptionOption::IfTsResol(r) => Some(*r),
                                _ => None,
                            })
                            .unwrap_or(6);
                        if ticks_per_sec(tsresol).is_none() {
                            return Err(SourceError::Unsupported("bad if_tsresol".into()));
                        }
                        return Ok(FileSource {
                            link: link_type(idb.linktype),
                            inner: Inner::Ng { reader, tsresol },
                        });
                    }
                    Some(Ok(Block::EnhancedPacket(_) | Block::SimplePacket(_))) => {
                        return Err(SourceError::Unsupported(
                            "pcapng packet before interface description".into(),
                        ));
                    }
                    Some(Ok(_)) => {}
                }
            }
        }
        let reader = PcapReader::new(file).map_err(map_err)?;
        Ok(FileSource {
            link: link_type(reader.header().datalink),
            inner: Inner::Pcap(reader),
        })
    }
}

fn fill(frame: &mut Frame, data: &[u8], orig_len: u32, sec: u64, subsec_ns: u32) {
    frame.data.clear();
    frame.data.extend_from_slice(data);
    frame.orig_len = orig_len;
    frame.ts_sec = i64::try_from(sec).unwrap_or(i64::MAX);
    frame.ts_usec = subsec_ns / 1000;
}

impl Source for FileSource {
    fn link_type(&self) -> LinkType {
        self.link
    }

    fn next_into(&mut self, frame: &mut Frame) -> Result<Next, SourceError> {
        match &mut self.inner {
            Inner::Pcap(r) => match r.next_packet() {
                None => Ok(Next::End),
                Some(Err(e)) => Err(map_err(e)),
                Some(Ok(p)) => {
                    // pcap-file already scales microsecond headers to a Duration.
                    fill(
                        frame,
                        &p.data,
                        p.orig_len,
                        p.timestamp.as_secs(),
                        p.timestamp.subsec_nanos(),
                    );
                    Ok(Next::Frame)
                }
            },
            Inner::Ng { reader, tsresol } => loop {
                match reader.next_block() {
                    None => return Ok(Next::End),
                    Some(Err(e)) => return Err(map_err(e)),
                    Some(Ok(Block::EnhancedPacket(epb))) => {
                        if epb.interface_id != 0 {
                            continue;
                        }
                        // pcap-file hands back the raw tick count as nanoseconds.
                        let ticks = epb.timestamp.as_nanos();
                        let per = ticks_per_sec(*tsresol)
                            .ok_or_else(|| SourceError::Unsupported("bad if_tsresol".into()))?;
                        let sec = ticks / per;
                        let ns = (ticks % per).saturating_mul(1_000_000_000) / per;
                        fill(
                            frame,
                            &epb.data,
                            epb.original_len,
                            u64::try_from(sec).unwrap_or(u64::MAX),
                            u32::try_from(ns).unwrap_or(0),
                        );
                        return Ok(Next::Frame);
                    }
                    Some(Ok(_)) => {}
                }
            },
        }
    }

    fn stats(&mut self) -> Option<SourceStats> {
        None
    }
}
