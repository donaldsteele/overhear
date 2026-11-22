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
    /// Drop counters grew during the run.
    fn status(&mut self, _status: &Status) -> io::Result<()> {
        Ok(())
    }
    fn finish(&mut self, _summary: &Summary) -> io::Result<()> {
        Ok(())
    }
}

/// Running drop and eviction counters, rendered when they grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Status {
    /// Seconds since the epoch.
    pub ts: i64,
    /// Dropped by the kernel or the interface.
    pub kernel_drops: u64,
    /// Dropped by overhear because the main thread fell behind.
    pub channel_drops: u64,
    pub evictions: u64,
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

#[cfg(test)]
mod tests {
    use super::json::JsonRenderer;
    use super::line::LineRenderer;
    use super::verbose::VerboseRenderer;
    use super::*;
    use std::cell::Cell;
    use std::io::Write;
    use std::rc::Rc;

    /// Discards output and counts flushes.
    struct Flushes(Rc<Cell<usize>>);

    impl Write for Flushes {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    fn opts() -> TextOpts {
        TextOpts {
            tz: TimeZone::UTC,
            style: TimeStyle::DateTime,
            hex: true,
        }
    }

    fn renderers(on: bool, n: &Rc<Cell<usize>>) -> Vec<Box<dyn Renderer>> {
        let w = || Flushes(Rc::clone(n));
        vec![
            Box::new(LineRenderer::new(w(), opts()).flush_each(on)),
            Box::new(VerboseRenderer::new(w(), opts()).flush_each(on)),
            Box::new(JsonRenderer::new(w(), TimeZone::UTC, true).flush_each(on)),
        ]
    }

    #[test]
    fn flush_each_flushes_once_per_packet() {
        let frame = Frame {
            data: vec![0xff; 60],
            orig_len: 60,
            ..Frame::default()
        };
        let decoded = overhear_decode::decode(&frame.data);
        for on in [true, false] {
            let n = Rc::new(Cell::new(0));
            for mut r in renderers(on, &n) {
                n.set(0);
                for _ in 0..3 {
                    r.packet(&frame, &decoded).expect("packet");
                }
                assert_eq!(n.get(), if on { 3 } else { 0 });
                r.finish(&Summary::default()).expect("finish");
                assert!(n.get() > if on { 3 } else { 0 }, "finish must flush");
            }
        }
    }

    #[test]
    fn json_status_flushes_when_asked() {
        let n = Rc::new(Cell::new(0));
        let mut r =
            JsonRenderer::new(Flushes(Rc::clone(&n)), TimeZone::UTC, false).flush_each(true);
        r.status(&Status::default()).expect("status");
        assert_eq!(n.get(), 1);
    }
}
