//! Everything that touches the operating system or libpcap lives here.

use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use crate::source::Source;

mod pcap_source;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(windows)]
use windows as imp;

/// A capture interface as the user sees it.
#[derive(Debug, Clone)]
pub struct Interface {
    /// The device name libpcap opens.
    pub name: String,
    /// A human-readable name (same as `name` on Linux).
    pub friendly: String,
    pub addrs: Vec<IpAddr>,
}

#[derive(Debug)]
pub struct PlatformError(pub String);

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlatformError {}

pub fn list_interfaces() -> Result<Vec<Interface>, PlatformError> {
    imp::list_interfaces()
}

/// Maps a friendly name to the device name; the identity on Linux.
pub fn resolve_interface(name: &str) -> Result<String, PlatformError> {
    imp::resolve_interface(name)
}

pub fn open_live(
    iface: Option<&str>,
    promisc: bool,
    filter: &str,
) -> Result<Box<dyn Source>, PlatformError> {
    pcap_source::open_live(iface, promisc, filter)
}

/// Opens a capture file; `-` reads standard input.
pub fn open_file(path: &Path, filter: &str) -> Result<Box<dyn Source>, PlatformError> {
    pcap_source::open_file(path, filter)
}

/// Compiles `filter` for Ethernet without capturing anything.
pub fn check_filter(filter: &str) -> Result<(), PlatformError> {
    pcap_source::check_filter(filter)
}

/// True when standard output is a regular file (no need to flush per packet).
pub fn stdout_is_file() -> bool {
    imp::stdout_is_file()
}

/// What `drop_privileges` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivReport {
    SwitchedUser { user: String, uid: u32, gid: u32 },
    CapabilitiesCleared,
    Unchanged,
}

#[derive(Debug, Clone, Default)]
pub struct PrivOpts {
    /// The `-Z` user; only used when started as root.
    pub user: Option<String>,
}

/// Gives up root (or any file capabilities) and forbids gaining privileges
/// again. Call after the capture is open and before reading any packet.
pub fn drop_privileges(opts: &PrivOpts) -> Result<PrivReport, PlatformError> {
    imp::drop_privileges(opts)
}

/// Makes the next SIGINT or SIGTERM kill the process: resets both to the
/// default action and re-raises SIGINT. Used for a second Ctrl-C when the
/// first did not stop the run in time.
pub fn force_exit_on_signal() {
    imp::force_exit_on_signal()
}
