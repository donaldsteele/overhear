//! Wires sources to renderers: decode every frame, hand it on.

use std::io;

use overhear_decode::decode;

use crate::render::{Renderer, Status, Summary, TextOpts};
use crate::source::{Frame, Next, Source, SourceError, SourceStats};

pub struct Config {
    pub text: TextOpts,
}

pub struct Engine {
    #[allow(dead_code)]
    cfg: Config,
    packets: u64,
    /// Kernel plus interface drops at the last `stats` call.
    kernel_drops: u64,
    channel_drops: u64,
}

impl Engine {
    pub fn new(cfg: Config) -> Engine {
        Engine {
            cfg,
            packets: 0,
            kernel_drops: 0,
            channel_drops: 0,
        }
    }

    pub fn frame(&mut self, f: &Frame, r: &mut dyn Renderer) -> io::Result<()> {
        self.packets = self.packets.saturating_add(1);
        let decoded = decode(&f.data);
        r.packet(f, &decoded)
    }

    /// Takes the capture's running drop counters (the source's and the
    /// pipeline's) and renders a [`Status`] when either has grown since the
    /// last call. `now` is in seconds since the epoch.
    pub fn stats(
        &mut self,
        s: SourceStats,
        channel_drops: u64,
        now: i64,
        r: &mut dyn Renderer,
    ) -> io::Result<()> {
        let kernel_drops = s.kernel_drops.saturating_add(s.iface_drops);
        let grew = kernel_drops > self.kernel_drops || channel_drops > self.channel_drops;
        self.kernel_drops = kernel_drops;
        self.channel_drops = channel_drops;
        if !grew {
            return Ok(());
        }
        r.status(&Status {
            ts: now,
            kernel_drops,
            channel_drops,
            evictions: 0,
        })
    }

    /// Called about once a second with the current time (seconds since the
    /// epoch), for work that is due by time rather than by packet. Nothing is
    /// due yet.
    pub fn tick(&mut self, _now: i64, _r: &mut dyn Renderer) -> io::Result<()> {
        Ok(())
    }

    pub fn summary(&self) -> Summary {
        Summary {
            packets: self.packets,
            kernel_drops: self.kernel_drops,
            channel_drops: self.channel_drops,
            ..Summary::default()
        }
    }
}

#[derive(Debug)]
pub enum RunEnd {
    Done,
    /// Stdout went away (BrokenPipe).
    Closed,
    Truncated(String),
}

#[derive(Debug)]
pub enum RunError {
    Source(SourceError),
    Io(io::Error),
}

/// Feeds every frame of `src` to the engine until the source ends. The caller
/// calls `Renderer::finish`.
pub fn run_source(
    src: &mut dyn Source,
    engine: &mut Engine,
    r: &mut dyn Renderer,
) -> Result<RunEnd, RunError> {
    let mut frame = Frame::default();
    loop {
        match src.next_into(&mut frame) {
            Ok(Next::Frame) => match engine.frame(&frame, r) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(RunEnd::Closed),
                Err(e) => return Err(RunError::Io(e)),
            },
            Ok(Next::Timeout) => {}
            Ok(Next::End) => return Ok(RunEnd::Done),
            Err(SourceError::Truncated(m)) => return Ok(RunEnd::Truncated(m)),
            Err(e) => return Err(RunError::Source(e)),
        }
    }
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Source(e) => write!(f, "{e}"),
            RunError::Io(e) => write!(f, "write error: {e}"),
        }
    }
}

impl std::error::Error for RunError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Status;
    use crate::time::TimeStyle;
    use jiff::tz::TimeZone;
    use overhear_decode::Decoded;

    #[derive(Default)]
    struct Statuses(Vec<Status>);

    impl Renderer for Statuses {
        fn packet(&mut self, _f: &Frame, _d: &Decoded<'_>) -> io::Result<()> {
            Ok(())
        }

        fn status(&mut self, s: &Status) -> io::Result<()> {
            self.0.push(*s);
            Ok(())
        }
    }

    fn engine() -> Engine {
        Engine::new(Config {
            text: TextOpts {
                tz: TimeZone::UTC,
                style: TimeStyle::DateTime,
                hex: false,
            },
        })
    }

    fn st(kernel: u64, iface: u64) -> SourceStats {
        SourceStats {
            kernel_drops: kernel,
            iface_drops: iface,
        }
    }

    #[test]
    fn stats_render_a_status_only_when_drops_grow() {
        let mut e = engine();
        let mut r = Statuses::default();
        e.stats(st(0, 0), 0, 100, &mut r).expect("stats");
        assert!(r.0.is_empty());
        e.stats(st(2, 1), 0, 101, &mut r).expect("stats");
        e.stats(st(2, 1), 0, 102, &mut r).expect("stats");
        e.stats(st(2, 1), 5, 103, &mut r).expect("stats");
        e.stats(st(2, 1), 5, 104, &mut r).expect("stats");
        let want = [
            Status {
                ts: 101,
                kernel_drops: 3,
                channel_drops: 0,
                evictions: 0,
            },
            Status {
                ts: 103,
                kernel_drops: 3,
                channel_drops: 5,
                evictions: 0,
            },
        ];
        assert_eq!(r.0, want);
        let s = e.summary();
        assert_eq!((s.kernel_drops, s.channel_drops), (3, 5));
    }
}
