//! One JSON object per line.

use std::io::{self, Write};
use std::net::IpAddr;

use jiff::tz::TimeZone;
use overhear_decode::{Decoded, Frag, IpHeader, Mac, Packet, Problem};

use super::{Renderer, Status, Summary, vlan_kind};
use crate::json::JsonWriter;
use crate::proto;
use crate::source::Frame;
use crate::time::{format_iso, format_ts};
use crate::warn::{Baseline, Expected, Output, Warning};

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

/// `ts` (epoch seconds with microseconds) and `time` (local ISO 8601, or
/// null when not representable).
fn ts_and_time(w: &mut JsonWriter, sec: i64, usec: u32, tz: &TimeZone) {
    w.raw_number(Some("ts"), &format_ts(sec, usec));
    match format_iso(sec, usec, tz) {
        Some(t) => w.str(Some("time"), &t),
        None => w.null(Some("time")),
    }
}

fn warning(w: &mut JsonWriter, x: &Warning, tz: &TimeZone) {
    w.str(Some("type"), "warning");
    ts_and_time(w, x.ts.sec, x.ts.usec, tz);
    w.str(Some("rule"), x.rule.as_str());
    w.str(Some("severity"), x.severity.as_str());
    if let Some(s) = x.segment {
        w.str(Some("segment"), &s.to_string());
    }
    w.str(Some("subject"), &x.subject);
    w.str(Some("message"), &x.message);
    w.arr(Some("macs"));
    for m in &x.macs {
        w.mac(None, *m);
    }
    w.end();
    w.arr(Some("addrs"));
    for a in &x.addrs {
        w.ip(None, *a);
    }
    w.end();
    w.u64(Some("count"), u64::from(x.count));
}

fn baseline(w: &mut JsonWriter, b: &Baseline, tz: &TimeZone) {
    w.str(Some("type"), "baseline");
    ts_and_time(w, b.ts.sec, b.ts.usec, tz);
    w.str(Some("segment"), &b.segment.to_string());
    match b.what {
        Expected::DhcpServer(ip) => {
            w.str(Some("what"), "dhcp-server");
            w.ip(Some("ip"), IpAddr::V4(ip));
        }
        Expected::Router { mac, ip } => {
            w.str(Some("what"), "router");
            w.ip(Some("ip"), IpAddr::V6(ip));
            w.mac(Some("mac"), mac);
        }
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

fn endpoint(w: &mut JsonWriter, key: &str, mac: Mac, ip: Option<IpAddr>) {
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
        ts_and_time(w, frame.ts_sec, frame.ts_usec, &self.tz);
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

    fn output(&mut self, o: &Output) -> io::Result<()> {
        let w = &mut self.w;
        w.clear();
        w.obj(None);
        w.u64(Some("schema"), 1);
        match o {
            Output::Warning(x) => warning(w, x, &self.tz),
            Output::Baseline(b) => baseline(w, b, &self.tz),
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
    use crate::observe::{Segment, Ts};
    use crate::warn::{Rule, Severity};
    use overhear_decode::Mac;
    use std::net::Ipv4Addr;

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

    #[test]
    fn warning_and_baseline_lines() {
        let ts = Ts {
            sec: 1_795_266_132,
            usec: 10_000,
        };
        let warning = Warning {
            ts,
            rule: Rule::SecondDhcpServer,
            severity: Severity::High,
            segment: Some(Segment::UNTAGGED),
            subject: "10.0.0.254".into(),
            message: "second DHCP server 10.0.0.254 (expected 10.0.0.1)".into(),
            macs: vec![
                Mac([2, 0, 0x5e, 0x10, 0, 0xfe]),
                Mac([2, 0, 0x5e, 0x10, 0, 0x39]),
            ],
            addrs: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))],
            count: 4,
        };
        let outputs = [
            Output::Warning(warning.clone()),
            Output::Warning(Warning {
                rule: Rule::CaptureDrops,
                severity: Severity::Low,
                segment: None,
                subject: "capture-drops".into(),
                message: "dropped".into(),
                macs: Vec::new(),
                addrs: Vec::new(),
                count: 1,
                ..warning
            }),
            Output::Baseline(Baseline {
                ts,
                segment: Segment::parse("200.100").expect("segment"),
                what: Expected::DhcpServer(Ipv4Addr::new(10, 0, 0, 1)),
            }),
            Output::Baseline(Baseline {
                ts,
                segment: Segment::UNTAGGED,
                what: Expected::Router {
                    mac: Mac([2, 0, 0x5e, 0x10, 0, 1]),
                    ip: "fe80::1".parse().expect("ipv6"),
                },
            }),
        ];
        let mut r = JsonRenderer::new(Vec::new(), TimeZone::UTC, false);
        for o in &outputs {
            r.output(o).expect("output");
        }
        let got = String::from_utf8(r.into_inner()).expect("utf8");
        let head = "{\"schema\":1,";
        let when = "\"ts\":1795266132.010000,\"time\":\"2026-11-21T13:02:12.010+00:00\"";
        let want = [
            format!(
                "{head}\"type\":\"warning\",{when},\"rule\":\"second-dhcp-server\",\
                 \"severity\":\"high\",\"segment\":\"untagged\",\"subject\":\"10.0.0.254\",\
                 \"message\":\"second DHCP server 10.0.0.254 (expected 10.0.0.1)\",\
                 \"macs\":[\"02:00:5e:10:00:fe\",\"02:00:5e:10:00:39\"],\
                 \"addrs\":[\"10.0.0.254\"],\"count\":4}}"
            ),
            format!(
                "{head}\"type\":\"warning\",{when},\"rule\":\"capture-drops\",\
                 \"severity\":\"low\",\"subject\":\"capture-drops\",\"message\":\"dropped\",\
                 \"macs\":[],\"addrs\":[],\"count\":1}}"
            ),
            format!(
                "{head}\"type\":\"baseline\",{when},\"segment\":\"200.100\",\
                 \"what\":\"dhcp-server\",\"ip\":\"10.0.0.1\"}}"
            ),
            format!(
                "{head}\"type\":\"baseline\",{when},\"segment\":\"untagged\",\
                 \"what\":\"router\",\"ip\":\"fe80::1\",\"mac\":\"02:00:5e:10:00:01\"}}"
            ),
        ];
        assert_eq!(got.lines().collect::<Vec<_>>(), want);
        assert!(got.ends_with('\n'));
    }
}
