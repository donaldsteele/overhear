//! One JSON object per line.

use std::io::{self, Write};

use jiff::tz::TimeZone;
use overhear_decode::{Decoded, Frag, IpHeader, Mac, Packet, Problem};

use super::{Renderer, Status, Summary, vlan_kind};
use crate::json::JsonWriter;
use crate::proto;
use crate::source::Frame;
use crate::time::{format_iso, format_ts};

pub struct JsonRenderer<W: Write> {
    out: W,
    tz: TimeZone,
    hex: bool,
    w: JsonWriter,
    flush_each: bool,
}

impl<W: Write> JsonRenderer<W> {
    pub fn new(out: W, tz: TimeZone, hex: bool) -> Self {
        JsonRenderer {
            out,
            tz,
            hex,
            w: JsonWriter::new(),
            flush_each: false,
        }
    }

    /// Flush the writer after every line, so output reaches a terminal or pipe
    /// at once.
    pub fn flush_each(mut self, on: bool) -> Self {
        self.flush_each = on;
        self
    }

    pub fn into_inner(self) -> W {
        self.out
    }

    fn emit(&mut self) -> io::Result<()> {
        self.out.write_all(self.w.as_str().as_bytes())?;
        self.out.write_all(b"\n")?;
        if self.flush_each {
            self.out.flush()?;
        }
        Ok(())
    }
}

fn problems(w: &mut JsonWriter, list: &[Problem], frame: &[u8]) {
    if list.is_empty() {
        return;
    }
    w.arr(Some("problems"));
    for p in list {
        w.obj(None);
        w.str(Some("layer"), p.layer.as_str());
        w.str(Some("reason"), p.reason);
        w.u64(Some("offset"), u64::try_from(p.offset).unwrap_or(u64::MAX));
        w.hex(Some("hex"), p.bytes(frame));
        w.end();
    }
    w.end();
}

fn endpoint(w: &mut JsonWriter, key: &str, mac: Mac, ip: Option<std::net::IpAddr>) {
    w.obj(Some(key));
    w.mac(Some("mac"), mac);
    if let Some(ip) = ip {
        w.ip(Some("ip"), ip);
    }
    w.end();
}

fn packet_body(w: &mut JsonWriter, p: &Packet<'_>, frame: &[u8]) {
    if !p.eth.vlans.is_empty() {
        w.arr(Some("vlan"));
        for v in p.eth.vlans.as_slice() {
            w.obj(None);
            w.str(Some("type"), vlan_kind(v.tpid));
            w.u64(Some("id"), u64::from(v.id));
            w.end();
        }
        w.end();
    }
    endpoint(w, "src", p.eth.src, p.ip.map(|ip| ip.src()));
    endpoint(w, "dst", p.eth.dst, p.ip.map(|ip| ip.dst()));
    match p.ip.as_ref().map(IpHeader::frag) {
        Some(Frag::First) => w.str(Some("frag"), "first"),
        Some(Frag::Later) => w.str(Some("frag"), "later"),
        _ => {}
    }
    w.str(Some("proto"), proto::json_name(p));
    proto::json(p, w);
    problems(w, &p.problems, frame);
}

impl<W: Write> Renderer for JsonRenderer<W> {
    fn packet(&mut self, frame: &Frame, decoded: &Decoded<'_>) -> io::Result<()> {
        let w = &mut self.w;
        w.clear();
        w.obj(None);
        w.u64(Some("schema"), 1);
        w.str(Some("type"), "packet");
        w.raw_number(Some("ts"), &format_ts(frame.ts_sec, frame.ts_usec));
        match format_iso(frame.ts_sec, frame.ts_usec, &self.tz) {
            Some(t) => w.str(Some("time"), &t),
            None => w.null(Some("time")),
        }
        w.u64(Some("len"), u64::from(frame.orig_len));
        let caplen = u64::try_from(frame.data.len()).unwrap_or(u64::MAX);
        if caplen < u64::from(frame.orig_len) {
            w.u64(Some("caplen"), caplen);
        }
        match decoded {
            Ok(p) => packet_body(w, p, &frame.data),
            Err(pr) => {
                w.str(Some("proto"), "short");
                problems(w, std::slice::from_ref(pr), &frame.data);
            }
        }
        if self.hex {
            w.hex(Some("frame_hex"), &frame.data);
        }
        w.end();
        self.emit()
    }

    fn status(&mut self, s: &Status) -> io::Result<()> {
        let w = &mut self.w;
        w.clear();
        w.obj(None);
        w.u64(Some("schema"), 1);
        w.str(Some("type"), "status");
        w.bool(Some("final"), false);
        w.i64(Some("ts"), s.ts);
        w.u64(Some("kernel_drops"), s.kernel_drops);
        w.u64(Some("channel_drops"), s.channel_drops);
        w.u64(Some("evictions"), s.evictions);
        w.end();
        self.emit()
    }

    fn finish(&mut self, s: &Summary) -> io::Result<()> {
        let w = &mut self.w;
        w.clear();
        w.obj(None);
        w.u64(Some("schema"), 1);
        w.str(Some("type"), "status");
        w.bool(Some("final"), true);
        w.u64(Some("packets"), s.packets);
        w.u64(Some("kernel_drops"), s.kernel_drops);
        w.u64(Some("channel_drops"), s.channel_drops);
        w.u64(
            Some("devices"),
            u64::try_from(s.devices).unwrap_or(u64::MAX),
        );
        w.u64(Some("evictions"), s.evictions);
        w.end();
        self.emit()?;
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line() {
        let mut r = JsonRenderer::new(Vec::new(), TimeZone::UTC, false);
        r.status(&Status {
            ts: 1_700_000_000,
            kernel_drops: 3,
            channel_drops: 2,
            evictions: 0,
        })
        .expect("status");
        assert_eq!(
            String::from_utf8(r.into_inner()).expect("utf8"),
            "{\"schema\":1,\"type\":\"status\",\"final\":false,\"ts\":1700000000,\
             \"kernel_drops\":3,\"channel_drops\":2,\"evictions\":0}\n"
        );
    }
}
