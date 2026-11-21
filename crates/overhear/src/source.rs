//! The capture-source abstraction: every backend feeds frames to the engine
//! through [`Source`].

use std::fmt;

/// One captured frame. `data` is reused between calls to `next_into`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frame {
    pub ts_sec: i64,
    pub ts_usec: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    Other(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// A frame was written into the caller's buffer.
    Frame,
    /// No frame arrived within the poll interval (live sources).
    Timeout,
    /// The source is exhausted.
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SourceStats {
    pub kernel_drops: u64,
    pub iface_drops: u64,
}

#[derive(Debug)]
pub enum SourceError {
    /// The capture ended in the middle of a record.
    Truncated(String),
    /// The capture is valid but not something we can read.
    Unsupported(String),
    Io(String),
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceError::Truncated(m) => write!(f, "truncated capture: {m}"),
            SourceError::Unsupported(m) => write!(f, "unsupported capture: {m}"),
            SourceError::Io(m) => write!(f, "I/O error: {m}"),
        }
    }
}

impl std::error::Error for SourceError {}

pub trait Source: Send {
    fn link_type(&self) -> LinkType;
    /// Clears and refills `frame.data` (keeping its allocation) and sets the
    /// timestamp and original length.
    fn next_into(&mut self, frame: &mut Frame) -> Result<Next, SourceError>;
    fn stats(&mut self) -> Option<SourceStats>;
}
