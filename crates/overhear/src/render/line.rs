//! One line of text per packet.

use std::fmt::Write as _;
use std::io::{self, Write};

use overhear_decode::{Decoded, Packet};

use super::{Renderer, Summary, TextOpts};
use crate::proto;
use crate::source::Frame;
use crate::time::format_line;

pub struct LineRenderer<W: Write> {
    out: W,
    opts: TextOpts,
    buf: String,
}

impl<W: Write> LineRenderer<W> {
    pub fn new(out: W, opts: TextOpts) -> Self {
        LineRenderer {
            out,
            opts,
            buf: String::new(),
        }
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

impl<W: Write> Renderer for LineRenderer<W> {
    fn packet(&mut self, frame: &Frame, decoded: &Decoded<'_>) -> io::Result<()> {
        self.buf.clear();
        format_packet_line(frame, decoded, &self.opts, &mut self.buf);
        self.out.write_all(self.buf.as_bytes())
    }

    fn finish(&mut self, _summary: &Summary) -> io::Result<()> {
        self.out.flush()
    }
}

fn source_of(p: &Packet<'_>, out: &mut String) {
    match p.ip.map(|ip| ip.src()) {
        Some(ip) if !ip.is_unspecified() => {
            let _ = write!(out, "{ip}");
        }
        _ => {
            let _ = write!(out, "{}", p.eth.src);
        }
    }
}

/// Appends the full line, newline included, to `out`.
pub fn format_packet_line(frame: &Frame, decoded: &Decoded<'_>, opts: &TextOpts, out: &mut String) {
    out.push_str(&format_line(
        frame.ts_sec,
        frame.ts_usec,
        &opts.tz,
        opts.style,
    ));
    out.push(' ');
    let (tag, source) = match decoded {
        Ok(p) => {
            let mut s = String::new();
            source_of(p, &mut s);
            (proto::tag(p), s)
        }
        Err(_) => ("ETH", "-".to_string()),
    };
    let _ = write!(out, "{tag:<5} {source:<18} ");
    match decoded {
        Ok(p) => {
            let vlans = p.eth.vlans.as_slice();
            if !vlans.is_empty() {
                out.push('[');
                for (i, v) in vlans.iter().enumerate() {
                    if i > 0 {
                        out.push('.');
                    }
                    let _ = write!(out, "{}", v.id);
                }
                out.push_str("] ");
            }
            proto::summary(p, out);
            if let Some(first) = p.problems.first() {
                let _ = write!(
                    out,
                    " [malformed: {} {}]",
                    first.layer.as_str(),
                    first.reason
                );
                if p.problems.len() > 1 {
                    let _ = write!(out, " (+{} more)", p.problems.len() - 1);
                }
            }
        }
        Err(_) => {
            let _ = write!(out, "short frame ({} bytes)", frame.data.len());
        }
    }
    out.push('\n');
}
