//! Output back ends. The engine hands every decoded frame to a [`Renderer`].

pub mod hex;
pub mod json;
pub mod line;
pub mod verbose;

use std::io;

use jiff::tz::TimeZone;
use overhear_decode::Decoded;

use crate::source::Frame;
use crate::time::TimeStyle;

pub trait Renderer {
    fn packet(&mut self, frame: &Frame, decoded: &Decoded<'_>) -> io::Result<()>;
    fn finish(&mut self, _summary: &Summary) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Summary {
    pub packets: u64,
    pub kernel_drops: u64,
    pub channel_drops: u64,
    pub devices: usize,
    pub evictions: u64,
}

#[derive(Debug, Clone)]
pub struct TextOpts {
    pub tz: TimeZone,
    pub style: TimeStyle,
    pub hex: bool,
}

/// Most problem bytes shown in verbose and JSON output.
pub const MAX_PROBLEM_BYTES: usize = 32;

/// `C`, `S` or `Q` for the tag protocol identifier.
pub fn vlan_kind(tpid: u16) -> &'static str {
    match tpid {
        0x88a8 => "S",
        0x9100 => "Q",
        _ => "C",
    }
}

/// The problem's bytes, cut to [`MAX_PROBLEM_BYTES`]; the flag says it was cut.
pub fn problem_bytes<'a>(p: &overhear_decode::Problem, frame: &'a [u8]) -> (&'a [u8], bool) {
    let b = p.bytes(frame);
    match b.get(..MAX_PROBLEM_BYTES) {
        Some(cut) => (cut, b.len() > MAX_PROBLEM_BYTES),
        None => (b, false),
    }
}
