//! Multi-line, layer-by-layer packet blocks.

use std::fmt::Write as _;
use std::io::{self, Write};

use overhear_decode::{Decoded, EthKind, Frag, IpHeader, L4, Packet, Problem};

use super::hex::hex_dump;
use super::{Renderer, Summary, TextOpts, problem_bytes, vlan_kind};
use crate::proto;
use crate::source::Frame;
use crate::time::format_line;

pub struct VerboseRenderer<W: Write> {
    out: W,
    opts: TextOpts,
    buf: String,
}

impl<W: Write> VerboseRenderer<W> {
    pub fn new(out: W, opts: TextOpts) -> Self {
        VerboseRenderer {
            out,
            opts,
            buf: String::new(),
        }
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

impl<W: Write> Renderer for VerboseRenderer<W> {
    fn packet(&mut self, frame: &Frame, decoded: &Decoded<'_>) -> io::Result<()> {
        self.buf.clear();
        format_block(frame, decoded, &self.opts, &mut self.buf);
        self.out.write_all(self.buf.as_bytes())
    }

    fn finish(&mut self, _summary: &Summary) -> io::Result<()> {
        self.out.flush()
    }
}

fn problem_line(p: &Problem, frame: &[u8], out: &mut String) {
    let (bytes, cut) = problem_bytes(p, frame);
    let _ = write!(
        out,
        "  !     {}: {} at {}: ",
        p.layer.as_str(),
        p.reason,
        p.offset
    );
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    if cut {
        out.push('…');
    }
    out.push('\n');
}

fn frag_note(f: &Frag, out: &mut String) {
    match f {
        Frag::None => {}
        Frag::First => out.push_str("  first fragment"),
        Frag::Later => out.push_str("  later fragment"),
    }
}

fn layers(p: &Packet<'_>, frame: &[u8], out: &mut String) {
    let e = &p.eth;
    let _ = write!(out, "  ETH   {} → {}  ", e.src, e.dst);
    let _ = match e.kind {
        EthKind::EtherType(t) => writeln!(out, "type 0x{t:04x}"),
        EthKind::Llc { dsap, ssap, ctrl } => {
            writeln!(
                out,
                "llc dsap 0x{dsap:02x} ssap 0x{ssap:02x} ctrl 0x{ctrl:02x}"
            )
        }
        EthKind::Snap { oui, pid } => writeln!(
            out,
            "snap oui {:02x}{:02x}{:02x} pid 0x{pid:04x}",
            oui[0], oui[1], oui[2]
        ),
    };
    for v in e.vlans.as_slice() {
        let _ = writeln!(out, "  VLAN  {} {} pcp {}", vlan_kind(v.tpid), v.id, v.pcp);
    }
    match &p.ip {
        Some(IpHeader::V4(h)) => {
            let _ = write!(
                out,
                "  IPv4  {} → {}  ttl {} proto {}",
                h.src, h.dst, h.ttl, h.proto
            );
            frag_note(&h.frag, out);
            out.push('\n');
        }
        Some(IpHeader::V6(h)) => {
            let _ = write!(
                out,
                "  IPv6  {} → {}  hop limit {} next {}",
                h.src, h.dst, h.hop_limit, h.next
            );
            frag_note(&h.frag, out);
            out.push('\n');
        }
        None => {}
    }
    match p.l4 {
        L4::Udp(u) => {
            let _ = writeln!(
                out,
                "  UDP   {} → {}  len {}",
                u.src_port, u.dst_port, u.len
            );
        }
        L4::Icmpv6 { typ, code } => {
            let _ = writeln!(out, "  ICMP6 type {typ} code {code}");
        }
        L4::None => {}
    }
    proto::verbose(p, frame, out);
    for pr in &p.problems {
        problem_line(pr, frame, out);
    }
}

/// Appends the whole block, trailing blank line included.
pub fn format_block(frame: &Frame, decoded: &Decoded<'_>, opts: &TextOpts, out: &mut String) {
    out.push_str(&format_line(
        frame.ts_sec,
        frame.ts_usec,
        &opts.tz,
        opts.style,
    ));
    let _ = write!(out, "  {} bytes", frame.orig_len);
    let caplen = frame.data.len();
    if usize::try_from(frame.orig_len).is_ok_and(|o| caplen < o) {
        let _ = write!(out, ", {caplen} captured");
    }
    out.push('\n');
    match decoded {
        Ok(p) => layers(p, &frame.data, out),
        Err(pr) => problem_line(pr, &frame.data, out),
    }
    if opts.hex {
        hex_dump(&frame.data, out);
    }
    out.push('\n');
}
