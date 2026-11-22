//! The libpcap-backed [`Source`], for live interfaces and capture files.

use std::path::Path;

use pcap::{Activated, Active, Capture, Error, Linktype, Offline};

use super::PlatformError;
use crate::source::{Frame, LinkType, Next, Source, SourceError, SourceStats, Waker};

const SNAPLEN: i32 = 65535;
const TIMEOUT_MS: i32 = 100;
const BUFFER_BYTES: i32 = 8 * 1024 * 1024;

struct PcapSource<T: Activated + ?Sized> {
    cap: Capture<T>,
    link: LinkType,
    live: bool,
}

fn perr(e: Error) -> PlatformError {
    PlatformError(e.to_string())
}

/// libpcap reports DLT values, which differ from the LINKTYPE values in capture
/// files for a few BSD-derived types; report the file-format number.
fn link_of(l: Linktype) -> LinkType {
    if l == Linktype::ETHERNET {
        return LinkType::Ethernet;
    }
    let n = match l.0 {
        11 => 100,
        12 => 101,
        15 => 102,
        16 => 103,
        other => other,
    };
    LinkType::Other(u32::try_from(n).unwrap_or(u32::MAX))
}

impl<T: Activated + ?Sized> PcapSource<T> {
    /// Installs the filter. A non-Ethernet capture skips it (the filter is
    /// written for Ethernet) and is rejected by the caller instead.
    fn new(mut cap: Capture<T>, live: bool, filter: &str) -> Result<Self, PlatformError> {
        let link = link_of(cap.get_datalink());
        if link == LinkType::Ethernet {
            cap.filter(filter, true).map_err(perr)?;
        }
        Ok(PcapSource { cap, link, live })
    }
}

impl<T: Activated + ?Sized> Source for PcapSource<T> {
    fn link_type(&self) -> LinkType {
        self.link
    }

    fn next_into(&mut self, frame: &mut Frame) -> Result<Next, SourceError> {
        match self.cap.next_packet() {
            Ok(p) => {
                // tv_sec is 32 bits wide on Windows.
                #[allow(clippy::useless_conversion)]
                let sec = i64::from(p.header.ts.tv_sec);
                frame.ts_sec = sec;
                frame.ts_usec = u32::try_from(p.header.ts.tv_usec).unwrap_or(0);
                frame.orig_len = p.header.len;
                frame.data.clear();
                frame.data.extend_from_slice(p.data);
                Ok(Next::Frame)
            }
            Err(Error::TimeoutExpired) => Ok(Next::Timeout),
            Err(Error::NoMorePackets) => Ok(Next::End),
            Err(Error::PcapError(m)) if m.contains("truncated") => Err(SourceError::Truncated(m)),
            Err(e) => Err(SourceError::Io(e.to_string())),
        }
    }

    fn stats(&mut self) -> Option<SourceStats> {
        if !self.live {
            return None;
        }
        let s = self.cap.stats().ok()?;
        Some(SourceStats {
            kernel_drops: u64::from(s.dropped),
            iface_drops: u64::from(s.if_dropped),
        })
    }

    fn waker(&mut self) -> Option<Waker> {
        // pcap_breakloop: the blocked read returns PCAP_ERROR_BREAK, which
        // arrives here as NoMorePackets, so `End`.
        let h = self.cap.breakloop_handle();
        Some(Box::new(move || h.breakloop()))
    }
}

pub fn open_live(
    iface: Option<&str>,
    promisc: bool,
    filter: &str,
) -> Result<Box<dyn Source>, PlatformError> {
    let inactive = match iface {
        Some(name) => Capture::from_device(name),
        None => {
            let dev = pcap::Device::lookup()
                .map_err(perr)?
                .ok_or_else(|| PlatformError("no capture interface found".into()))?;
            Capture::from_device(dev)
        }
    }
    .map_err(perr)?;
    let cap: Capture<Active> = inactive
        .snaplen(SNAPLEN)
        .promisc(promisc)
        .timeout(TIMEOUT_MS)
        .buffer_size(BUFFER_BYTES)
        .open()
        .map_err(perr)?;
    Ok(Box::new(PcapSource::new(cap, true, filter)?))
}

pub fn open_file(path: &Path, filter: &str) -> Result<Box<dyn Source>, PlatformError> {
    // libpcap itself reads standard input for the name "-".
    let cap: Capture<Offline> = Capture::from_file(path).map_err(perr)?;
    Ok(Box::new(PcapSource::new(cap, false, filter)?))
}

pub fn check_filter(filter: &str) -> Result<(), PlatformError> {
    let cap = Capture::dead(Linktype::ETHERNET).map_err(perr)?;
    cap.compile(filter, true).map(drop).map_err(perr)
}
