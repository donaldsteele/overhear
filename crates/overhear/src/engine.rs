//! Wires sources to renderers: decode every frame, hand it on.

use std::io;

use overhear_decode::decode;

use crate::render::{Renderer, Summary, TextOpts};
use crate::source::{Frame, Next, Source, SourceError};

pub struct Config {
    pub text: TextOpts,
}

pub struct Engine {
    #[allow(dead_code)]
    cfg: Config,
    packets: u64,
}

impl Engine {
    pub fn new(cfg: Config) -> Engine {
        Engine { cfg, packets: 0 }
    }

    pub fn frame(&mut self, f: &Frame, r: &mut dyn Renderer) -> io::Result<()> {
        self.packets = self.packets.saturating_add(1);
        let decoded = decode(&f.data);
        r.packet(f, &decoded)
    }

    pub fn summary(&self) -> Summary {
        Summary {
            packets: self.packets,
            ..Summary::default()
        }
    }
}

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
