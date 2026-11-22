//! SSDP presentation and observations. LOCATION URLs are shown, never
//! fetched.

use std::borrow::Cow;
use std::fmt::Write;

use overhear_decode::{Packet, Ssdp, StartLine};

use crate::escape::{LINE_FIELD_MAX, TextKind, push_text};
use crate::json::JsonWriter;
use crate::observe::{Observation, ProtoTag};

pub fn tag() -> &'static str {
    "SSDP"
}

fn field(out: &mut String, bytes: &[u8]) {
    push_text(out, bytes, TextKind::Ascii, LINE_FIELD_MAX);
}

fn field_of(m: &Ssdp<'_>, name: &str, out: &mut String) {
    field(out, m.header(name).unwrap_or(&[]));
}

fn is_alive(m: &Ssdp<'_>) -> bool {
    m.header("NTS")
        .is_some_and(|v| v.eq_ignore_ascii_case(b"ssdp:alive"))
}

/// NOTIFY `{NTS without "ssdp:"} {NT}`, M-SEARCH `search {ST}`, response
/// `response {ST} at {LOCATION}`.
pub fn summary(m: &Ssdp<'_>, out: &mut String) {
    match m.start {
        StartLine::Notify => {
            let nts = m.header("NTS").unwrap_or(&[]);
            let nts = nts.strip_prefix(b"ssdp:").unwrap_or(nts);
            let nt = m.header("NT").unwrap_or(&[]);
            if nts.is_empty() && nt.is_empty() {
                out.push_str("notify");
            }
            field(out, nts);
            if !nts.is_empty() && !nt.is_empty() {
                out.push(' ');
            }
            field(out, nt);
        }
        StartLine::MSearch => {
            out.push_str("search ");
            field_of(m, "ST", out);
        }
        StartLine::Response { .. } => {
            out.push_str("response ");
            field_of(m, "ST", out);
            out.push_str(" at ");
            field_of(m, "LOCATION", out);
        }
        StartLine::Other(line) => {
            out.push_str("other ");
            field(out, line);
        }
    }
}

pub fn verbose(m: &Ssdp<'_>, out: &mut String) {
    let _ = write!(out, "  {:<6}", tag());
    match m.start {
        StartLine::Notify => out.push_str("NOTIFY"),
        StartLine::MSearch => out.push_str("M-SEARCH"),
        StartLine::Response { status } => {
            let _ = write!(out, "response {status}");
        }
        StartLine::Other(line) => {
            out.push_str("other ");
            push_text(out, line, TextKind::Ascii, usize::MAX);
        }
    }
    out.push('\n');
    for (name, value) in &m.headers {
        out.push_str("        ");
        push_text(out, name, TextKind::Ascii, usize::MAX);
        out.push_str(": ");
        push_text(out, value, TextKind::Ascii, usize::MAX);
        out.push('\n');
    }
}

pub fn json(m: &Ssdp<'_>, w: &mut JsonWriter) {
    w.obj(Some("ssdp"));
    w.str(
        Some("start"),
        match m.start {
            StartLine::Notify => "notify",
            StartLine::MSearch => "m-search",
            StartLine::Response { .. } => "response",
            StartLine::Other(_) => "other",
        },
    );
    if let StartLine::Response { status } = m.start {
        w.u64(Some("status"), u64::from(status));
    }
    if let StartLine::Other(line) = m.start {
        w.text("line", line, TextKind::Ascii);
    }
    w.arr(Some("headers"));
    for (name, value) in &m.headers {
        w.obj(None);
        w.text("name", name, TextKind::Ascii);
        w.text("value", value, TextKind::Ascii);
        w.end();
    }
    w.end();
    w.end();
}

/// Alive announcements and responses reveal what a device offers: the
/// `urn:` service type, the SERVER string and the description URL.
pub fn observe<'a>(p: &Packet<'a>, m: &Ssdp<'a>, out: &mut Vec<Observation<'a>>) {
    let mac = p.eth.src;
    out.push(Observation::Heard {
        mac,
        proto: ProtoTag::Ssdp,
    });
    let kind = match m.start {
        StartLine::Notify if is_alive(m) => "NT",
        StartLine::Response { .. } => "ST",
        _ => return,
    };
    if let Some(v) = m.header(kind).filter(|v| v.starts_with(b"urn:")) {
        out.push(Observation::Service {
            mac,
            name: Cow::Borrowed(v),
        });
    }
    if let Some(v) = m.header("SERVER").filter(|v| !v.is_empty()) {
        out.push(Observation::Model {
            mac,
            text: Cow::Borrowed(v),
        });
    }
    if let Some(v) = m.header("LOCATION").filter(|v| !v.is_empty()) {
        out.push(Observation::Detail {
            mac,
            key: "location",
            value: Cow::Borrowed(v),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overhear_decode::{Mac, Proto, decode};
    use overhear_testgen::{eth_ipv4, ipv4_udp, mac, ssdp};
    use std::net::Ipv4Addr;

    fn v4(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, d)
    }

    fn with<R>(src: u8, payload: &[u8], f: impl FnOnce(&Packet<'_>, &Ssdp<'_>) -> R) -> R {
        let ip = ipv4_udp(
            v4(src),
            Ipv4Addr::new(239, 255, 255, 250),
            1900,
            1900,
            payload,
        );
        let fr = eth_ipv4(mac(1), mac(src), &ip);
        let p = decode(&fr).unwrap();
        let Proto::Ssdp(m) = &p.proto else {
            panic!("not ssdp")
        };
        f(&p, m)
    }

    fn line(payload: &[u8]) -> String {
        with(1, payload, |_, m| {
            let mut s = String::new();
            summary(m, &mut s);
            s
        })
    }

    const TV: &str = "urn:schemas-upnp-org:device:MediaRenderer:1";

    fn notify(nts: &str, nt: &str) -> Vec<u8> {
        ssdp(
            "NOTIFY * HTTP/1.1",
            &[
                ("HOST", "239.255.255.250:1900"),
                ("NT", nt),
                ("NTS", nts),
                ("LOCATION", "http://192.168.1.33:8008/ssdp/device-desc.xml"),
                ("SERVER", "Linux/4.4 UPnP/1.0 Chromecast/1.0"),
            ],
        )
    }

    fn response() -> Vec<u8> {
        ssdp(
            "HTTP/1.1 200 OK",
            &[
                ("ST", TV),
                ("LOCATION", "http://192.168.1.33:8008/ssdp/device-desc.xml"),
                ("SERVER", "Linux/4.4 UPnP/1.0 Chromecast/1.0"),
            ],
        )
    }

    #[test]
    fn exact_summaries() {
        assert_eq!(line(&notify("ssdp:alive", TV)), format!("alive {TV}"));
        assert_eq!(line(&notify("ssdp:byebye", TV)), format!("byebye {TV}"));
        assert_eq!(
            line(&ssdp("M-SEARCH * HTTP/1.1", &[("ST", "ssdp:all")])),
            "search ssdp:all"
        );
        assert_eq!(
            line(&response()),
            format!("response {TV} at http://192.168.1.33:8008/ssdp/device-desc.xml")
        );
        assert_eq!(
            line(&ssdp("SUBSCRIBE x HTTP/1.1", &[])),
            "other SUBSCRIBE x HTTP/1.1"
        );
    }

    #[test]
    fn notify_without_nts_or_nt() {
        assert_eq!(line(&ssdp("NOTIFY * HTTP/1.1", &[])), "notify");
        assert_eq!(line(&ssdp("NOTIFY * HTTP/1.1", &[("NT", "x")])), "x");
    }

    #[test]
    fn summary_text_is_escaped() {
        let b = ssdp(
            "HTTP/1.1 200 OK",
            &[("ST", "a\u{1b}[2Jb"), ("LOCATION", "x")],
        );
        assert_eq!(line(&b), "response a\\x1b[2Jb at x");
    }

    fn obs_of(src: u8, payload: &[u8]) -> Vec<Observation<'static>> {
        with(src, payload, |p, m| {
            let mut out = Vec::new();
            observe(p, m, &mut out);
            out.into_iter()
                .map(|o| match o {
                    Observation::Heard { mac, proto } => Observation::Heard { mac, proto },
                    Observation::Service { mac, name } => Observation::Service {
                        mac,
                        name: Cow::Owned(name.into_owned()),
                    },
                    Observation::Model { mac, text } => Observation::Model {
                        mac,
                        text: Cow::Owned(text.into_owned()),
                    },
                    Observation::Detail { mac, key, value } => Observation::Detail {
                        mac,
                        key,
                        value: Cow::Owned(value.into_owned()),
                    },
                    other => panic!("unexpected {other:?}"),
                })
                .collect()
        })
    }

    fn full(m: Mac, nt: &str) -> Vec<Observation<'static>> {
        vec![
            Observation::Heard {
                mac: m,
                proto: ProtoTag::Ssdp,
            },
            Observation::Service {
                mac: m,
                name: Cow::Owned(nt.as_bytes().to_vec()),
            },
            Observation::Model {
                mac: m,
                text: Cow::Owned(b"Linux/4.4 UPnP/1.0 Chromecast/1.0".to_vec()),
            },
            Observation::Detail {
                mac: m,
                key: "location",
                value: Cow::Owned(b"http://192.168.1.33:8008/ssdp/device-desc.xml".to_vec()),
            },
        ]
    }

    #[test]
    fn alive_and_response_are_observed() {
        let m = Mac(mac(0x33));
        assert_eq!(obs_of(0x33, &notify("ssdp:alive", TV)), full(m, TV));
        assert_eq!(obs_of(0x33, &response()), full(m, TV));
    }

    #[test]
    fn uuid_nt_is_not_a_service() {
        let m = Mac(mac(0x33));
        let got = obs_of(
            0x33,
            &notify("ssdp:alive", "uuid:2f402f80-da50-11e1-9b23-001788"),
        );
        assert_eq!(got.len(), 3);
        assert!(!got.iter().any(|o| matches!(o, Observation::Service { .. })));
        assert!(matches!(got[0], Observation::Heard { mac, .. } if mac == m));
    }

    #[test]
    fn byebye_and_search_only_hear() {
        let m = Mac(mac(5));
        let heard = vec![Observation::Heard {
            mac: m,
            proto: ProtoTag::Ssdp,
        }];
        assert_eq!(obs_of(5, &notify("ssdp:byebye", TV)), heard);
        let s = ssdp("M-SEARCH * HTTP/1.1", &[("ST", TV), ("SERVER", "x")]);
        assert_eq!(obs_of(5, &s), heard);
    }

    #[test]
    fn verbose_lists_every_header() {
        let b = ssdp("HTTP/1.1 200 OK", &[("ST", "a"), ("X-Evil", "b\u{1b}c")]);
        let s = with(1, &b, |_, m| {
            let mut s = String::new();
            verbose(m, &mut s);
            s
        });
        assert_eq!(
            s,
            "  SSDP  response 200\n        ST: a\n        X-Evil: b\\x1bc\n"
        );
    }

    #[test]
    fn json_other_start_keeps_the_line() {
        let s = with(1, b"SUBSCRIBE x\r\n\r\n", |_, m| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(m, &mut w);
            w.end();
            w.as_str().to_string()
        });
        assert_eq!(
            s,
            r#"{"ssdp":{"start":"other","line":"SUBSCRIBE x","headers":[]}}"#
        );
    }

    #[test]
    fn json_object() {
        let b = ssdp("HTTP/1.1 200 OK", &[("ST", "a"), ("SERVER", "b\u{1b}c")]);
        let s = with(1, &b, |_, m| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(m, &mut w);
            w.end();
            w.as_str().to_string()
        });
        assert_eq!(
            s,
            r#"{"ssdp":{"start":"response","status":200,"headers":[{"name":"ST","value":"a"},{"name":"SERVER","value_hex":"621b63"}]}}"#
        );
    }
}
