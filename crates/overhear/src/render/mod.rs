//! Output back ends. The engine hands every decoded frame to a [`Renderer`].

pub mod line;

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
