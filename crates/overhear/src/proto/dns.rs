//! DNS presentation and observations, shared by mDNS and the other DNS-shaped
//! protocols.

use std::borrow::Cow;
use std::fmt::Write;
use std::net::IpAddr;

use overhear_decode::{DnsMessage, Name, Packet, Question, RData, Record, Section, txt_strings};

use crate::escape::{LINE_FIELD_MAX, TextKind, push_text};
use crate::json::JsonWriter;
use crate::observe::{AnswerKind, NameSource, Observation, ProtoTag};

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;

pub fn tag() -> &'static str {
    "mDNS"
}

/// `A`, `PTR`, … or `TYPE{n}`.
fn type_name(t: u16) -> Cow<'static, str> {
    Cow::Borrowed(match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        47 => "NSEC",
        255 => "ANY",
        n => return Cow::Owned(format!("TYPE{n}")),
    })
}

fn class_name(c: u16) -> Cow<'static, str> {
    match c {
        1 => Cow::Borrowed("IN"),
        n => Cow::Owned(format!("CLASS{n}")),
    }
}

fn push_name(out: &mut String, n: &Name<'_>, max: usize) {
    push_text(out, &n.dotted(), TextKind::Utf8, max);
}

fn is_local(dotted: &[u8]) -> bool {
    dotted.len() > ".local".len()
        && dotted
            .get(dotted.len().saturating_sub(".local".len())..)
            .is_some_and(|s| s.eq_ignore_ascii_case(b".local"))
}

fn goodbye(m: &DnsMessage<'_>) -> bool {
    !m.records.is_empty() && m.records.iter().all(|r| r.ttl == 0)
}

/// The record a response is summarised by: the first PTR, else the first SRV,
/// else the first address, else the first record.
fn headline<'m, 'a>(m: &'m DnsMessage<'a>) -> Option<&'m Record<'a>> {
    let first = |f: fn(&RData<'_>) -> bool| m.records.iter().find(|r| f(&r.rdata));
    first(|d| matches!(d, RData::Ptr(_)))
        .or_else(|| first(|d| matches!(d, RData::Srv { .. })))
        .or_else(|| first(|d| matches!(d, RData::A(_) | RData::Aaaa(_))))
        .or_else(|| m.records.first())
}

pub fn summary(m: &DnsMessage<'_>, out: &mut String) {
    if !m.is_response() {
        out.push_str("query");
        if let Some(q) = m.questions.first() {
            out.push(' ');
            push_name(out, &q.name, LINE_FIELD_MAX);
            let _ = write!(out, " {}", type_name(q.qtype));
            let more = m.questions.len().saturating_sub(1);
            if more > 0 {
                let _ = write!(out, " (+{more} more)");
            }
        }
        return;
    }
    let Some(r) = headline(m) else {
        out.push_str("response");
        return;
    };
    if goodbye(m) {
        out.push_str("goodbye ");
    }
    match &r.rdata {
        RData::Ptr(t) => push_name(out, t, LINE_FIELD_MAX),
        RData::Srv { port, target, .. } => {
            push_name(out, &r.name, LINE_FIELD_MAX);
            out.push_str(" → ");
            push_name(out, target, LINE_FIELD_MAX);
            let _ = write!(out, ":{port}");
        }
        RData::A(a) => {
            push_name(out, &r.name, LINE_FIELD_MAX);
            let _ = write!(out, " → {a}");
        }
        RData::Aaaa(a) => {
            push_name(out, &r.name, LINE_FIELD_MAX);
            let _ = write!(out, " → {a}");
        }
        _ => {
            push_name(out, &r.name, LINE_FIELD_MAX);
            let _ = write!(out, " {}", type_name(r.rtype));
        }
    }
    let more = m.records.len().saturating_sub(1);
    if more > 0 {
        let _ = write!(out, " (+{more} records)");
    }
}

fn section_label(s: Section) -> &'static str {
    match s {
        Section::Answer => "AN",
        Section::Authority => "NS",
        Section::Additional => "AR",
    }
}

fn section_name(s: Section) -> &'static str {
    match s {
        Section::Answer => "answer",
        Section::Authority => "authority",
        Section::Additional => "additional",
    }
}

fn question_line(q: &Question<'_>, out: &mut String) {
    out.push_str("        Q  ");
    push_name(out, &q.name, usize::MAX);
    let _ = write!(
        out,
        " {} {}",
        type_name(q.qtype),
        class_name(q.qclass & 0x7fff)
    );
    if q.unicast_response() {
        out.push_str(" QU");
    }
    out.push('\n');
}

fn record_line(r: &Record<'_>, out: &mut String) {
    let _ = write!(out, "        {} ", section_label(r.section));
    push_name(out, &r.name, usize::MAX);
    let _ = write!(
        out,
        " {} {}",
        type_name(r.rtype),
        class_name(r.class_code())
    );
    if r.cache_flush() {
        out.push_str(" flush");
    }
    let _ = write!(out, " ttl {}", r.ttl);
    match &r.rdata {
        RData::A(a) => {
            let _ = write!(out, " {a}");
        }
        RData::Aaaa(a) => {
            let _ = write!(out, " {a}");
        }
        RData::Ptr(t) => {
            out.push(' ');
            push_name(out, t, usize::MAX);
        }
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            let _ = write!(
                out,
                " priority {priority} weight {weight} port {port} target "
            );
            push_name(out, target, usize::MAX);
        }
        RData::Txt(t) => {
            for s in txt_strings(t) {
                out.push_str(" \"");
                push_text(out, s, TextKind::Utf8, usize::MAX);
                out.push('"');
            }
        }
        RData::Other(d) => {
            if !d.is_empty() {
                out.push(' ');
                for b in *d {
                    let _ = write!(out, "{b:02x}");
                }
            }
        }
    }
    out.push('\n');
}

pub fn verbose(m: &DnsMessage<'_>, out: &mut String) {
    let _ = writeln!(
        out,
        "  mDNS  {} id {} flags 0x{:04x} questions {} records {}",
        if m.is_response() { "response" } else { "query" },
        m.id,
        m.flags,
        m.questions.len(),
        m.records.len()
    );
    for q in &m.questions {
        question_line(q, out);
    }
    for r in &m.records {
        record_line(r, out);
    }
}

pub fn json(m: &DnsMessage<'_>, w: &mut JsonWriter) {
    w.obj(Some("mdns"));
    w.u64(Some("id"), u64::from(m.id));
    w.u64(Some("flags"), u64::from(m.flags));
    w.bool(Some("response"), m.is_response());
    w.arr(Some("questions"));
    for q in &m.questions {
        w.obj(None);
        w.text("name", &q.name.dotted(), TextKind::Utf8);
        w.u64(Some("type"), u64::from(q.qtype));
        w.str(Some("type_name"), &type_name(q.qtype));
        w.u64(Some("class"), u64::from(q.qclass & 0x7fff));
        w.bool(Some("unicast_response"), q.unicast_response());
        w.end();
    }
    w.end();
    w.arr(Some("records"));
    for r in &m.records {
        w.obj(None);
        w.str(Some("section"), section_name(r.section));
        w.text("name", &r.name.dotted(), TextKind::Utf8);
        w.u64(Some("type"), u64::from(r.rtype));
        w.str(Some("type_name"), &type_name(r.rtype));
        w.u64(Some("class"), u64::from(r.class_code()));
        w.bool(Some("cache_flush"), r.cache_flush());
        w.u64(Some("ttl"), u64::from(r.ttl));
        match &r.rdata {
            RData::A(a) => w.ip(Some("addr"), IpAddr::V4(*a)),
            RData::Aaaa(a) => w.ip(Some("addr"), IpAddr::V6(*a)),
            RData::Ptr(t) => w.text("target", &t.dotted(), TextKind::Utf8),
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                w.u64(Some("priority"), u64::from(*priority));
                w.u64(Some("weight"), u64::from(*weight));
                w.u64(Some("port"), u64::from(*port));
                w.text("target", &target.dotted(), TextKind::Utf8);
            }
            RData::Txt(t) => {
                w.arr(Some("txt"));
                for s in txt_strings(t) {
                    w.text_elem(s, TextKind::Utf8);
                }
                w.end();
            }
            RData::Other(d) => w.hex(Some("data_hex"), d),
        }
        w.end();
    }
    w.end();
    w.end();
}

fn model_hint(s: &[u8]) -> Option<&[u8]> {
    let (key, value) = s.split_at(s.iter().position(|&b| b == b'=')?);
    let value = value.get(1..)?;
    (key.eq_ignore_ascii_case(b"md") || key.eq_ignore_ascii_case(b"model"))
        .then_some(value)
        .filter(|v| !v.is_empty())
}

/// Responses teach names, addresses, services and model hints. Names are
/// decompressed into owned bytes; names that failed validation teach nothing.
pub fn observe<'a>(p: &Packet<'a>, m: &DnsMessage<'a>, out: &mut Vec<Observation<'a>>) {
    let mac = p.eth.src;
    out.push(Observation::Heard {
        mac,
        proto: ProtoTag::Mdns,
    });
    if !m.is_response() {
        return;
    }
    let host = |n: &Name<'a>| {
        n.first_label()
            .filter(|l| !l.is_empty())
            .map(|l| Observation::Name {
                mac,
                name: Cow::Borrowed(l),
                source: NameSource::Mdns,
            })
    };
    for r in &m.records {
        match &r.rdata {
            RData::A(_) | RData::Aaaa(_) if r.rtype == TYPE_A || r.rtype == TYPE_AAAA => {
                let dotted = r.name.dotted();
                if !r.name.is_valid() || !is_local(&dotted) {
                    continue;
                }
                let (ip, data): (IpAddr, Vec<u8>) = match &r.rdata {
                    RData::A(a) => (IpAddr::V4(*a), a.octets().to_vec()),
                    RData::Aaaa(a) => (IpAddr::V6(*a), a.octets().to_vec()),
                    _ => continue,
                };
                out.extend(host(&r.name));
                out.push(Observation::Address { mac, ip });
                if r.cache_flush() {
                    out.push(Observation::NameAnswer {
                        mac,
                        kind: AnswerKind::MdnsUnique,
                        name: Cow::Owned(dotted),
                        data: Cow::Owned(data),
                    });
                }
            }
            RData::Ptr(t) if r.rtype == TYPE_PTR && t.is_valid() => {
                out.push(Observation::Service {
                    mac,
                    name: Cow::Owned(t.dotted()),
                });
            }
            RData::Srv { target, .. } if r.rtype == TYPE_SRV => {
                out.extend(host(target));
            }
            RData::Txt(t) if r.rtype == TYPE_TXT => {
                for v in txt_strings(t).filter_map(model_hint) {
                    out.push(Observation::Model {
                        mac,
                        text: Cow::Borrowed(v),
                    });
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{AnswerKind, Observation, ProtoTag};
    use overhear_decode::{Mac, Proto, decode};
    use overhear_testgen::{DnsBuilder, RDataSpec, eth_ipv4, ipv4_udp, mac};
    use std::borrow::Cow;
    use std::net::{IpAddr, Ipv4Addr};

    const RESPONSE: u16 = 0x8400;

    fn v4(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, d)
    }

    fn frame(src: u8, b: &DnsBuilder) -> Vec<u8> {
        let ip = ipv4_udp(
            v4(src),
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            5353,
            &b.bytes(),
        );
        eth_ipv4([0x01, 0x00, 0x5e, 0, 0, 0xfb], mac(src), &ip)
    }

    /// Runs `f` on the decoded mDNS packet in a frame from `mac(src)`.
    fn with<R>(src: u8, b: &DnsBuilder, f: impl FnOnce(&Packet<'_>, &DnsMessage<'_>) -> R) -> R {
        let fr = frame(src, b);
        let p = decode(&fr).unwrap();
        let Proto::Mdns(m) = &p.proto else {
            panic!("not mdns")
        };
        f(&p, m)
    }

    fn line(b: &DnsBuilder) -> String {
        with(1, b, |_, m| {
            let mut s = String::new();
            summary(m, &mut s);
            s
        })
    }

    fn a(name: &str, addr: u8, class: u16, ttl: u32) -> (String, u16, u16, u32, RDataSpec) {
        (name.into(), 1, class, ttl, RDataSpec::A(v4(addr)))
    }

    fn with_answers(flags: u16, rs: Vec<(String, u16, u16, u32, RDataSpec)>) -> DnsBuilder {
        let mut b = DnsBuilder::new(flags);
        for (n, t, c, ttl, r) in rs {
            b = b.answer(&n, t, c, ttl, r);
        }
        b
    }

    fn chromecast(ttl: u32) -> DnsBuilder {
        let inst = "Living-Room-TV._googlecast._tcp.local";
        DnsBuilder::new(RESPONSE)
            .answer(
                "_googlecast._tcp.local",
                12,
                1,
                ttl,
                RDataSpec::Ptr(inst.into()),
            )
            .answer(
                inst,
                33,
                0x8001,
                ttl,
                RDataSpec::Srv(8009, "Living-Room-TV.local".into()),
            )
            .answer(
                inst,
                16,
                0x8001,
                ttl,
                RDataSpec::Txt(vec!["md=Chromecast".into()]),
            )
            .answer("Living-Room-TV.local", 1, 0x8001, ttl, RDataSpec::A(v4(33)))
    }

    #[test]
    fn query_summaries() {
        let one = DnsBuilder::new(0).question("_googlecast._tcp.local", 12, 0x8001);
        assert_eq!(line(&one), "query _googlecast._tcp.local PTR");
        let two = one
            .clone()
            .question("a.local", 1, 1)
            .question("b.local", 28, 1);
        assert_eq!(line(&two), "query _googlecast._tcp.local PTR (+2 more)");
        let odd = DnsBuilder::new(0).question("x.local", 4242, 1);
        assert_eq!(line(&odd), "query x.local TYPE4242");
        assert_eq!(line(&DnsBuilder::new(0)), "query");
    }

    #[test]
    fn ptr_announcement_summary() {
        assert_eq!(
            line(&chromecast(4500)),
            "Living-Room-TV._googlecast._tcp.local (+3 records)"
        );
    }

    #[test]
    fn goodbye_summary() {
        assert_eq!(
            line(&chromecast(0)),
            "goodbye Living-Room-TV._googlecast._tcp.local (+3 records)"
        );
        // One record with a live ttl is not a goodbye.
        let b = with_answers(
            RESPONSE,
            vec![a("a.local", 5, 1, 0), a("b.local", 6, 1, 120)],
        );
        assert_eq!(line(&b), "a.local → 192.168.1.5 (+1 records)");
    }

    #[test]
    fn address_and_srv_summaries() {
        let b = with_answers(RESPONSE, vec![a("printer.local", 48, 0x8001, 120)]);
        assert_eq!(line(&b), "printer.local → 192.168.1.48");
        let v6 = DnsBuilder::new(RESPONSE).answer(
            "h.local",
            28,
            1,
            120,
            RDataSpec::Aaaa("fe80::1".parse().unwrap()),
        );
        assert_eq!(line(&v6), "h.local → fe80::1");
        // SRV beats A; PTR beats SRV.
        let srv = DnsBuilder::new(RESPONSE)
            .answer("h.local", 1, 1, 120, RDataSpec::A(v4(9)))
            .answer(
                "i._x._tcp.local",
                33,
                1,
                120,
                RDataSpec::Srv(631, "h.local".into()),
            );
        assert_eq!(line(&srv), "i._x._tcp.local → h.local:631 (+1 records)");
    }

    #[test]
    fn other_responses() {
        let txt = DnsBuilder::new(RESPONSE).answer("x.local", 16, 1, 120, RDataSpec::Txt(vec![]));
        assert_eq!(line(&txt), "x.local TXT");
        assert_eq!(line(&DnsBuilder::new(RESPONSE)), "response");
    }

    #[test]
    fn hostile_names_are_escaped_in_the_summary() {
        let b = DnsBuilder::new(RESPONSE).answer(
            "_x._tcp.local",
            12,
            1,
            120,
            RDataSpec::Ptr("a\u{1b}[2J\u{202e}b._x._tcp.local".into()),
        );
        assert_eq!(line(&b), "a\\x1b[2J\\u{202e}b._x._tcp.local");
        let bjorn = DnsBuilder::new(RESPONSE).answer(
            "_x._tcp.local",
            12,
            1,
            120,
            RDataSpec::Ptr("Bjørn's iPhone._x._tcp.local".into()),
        );
        assert_eq!(line(&bjorn), "Bjørn's iPhone._x._tcp.local");
    }

    fn obs(src: u8, b: &DnsBuilder) -> Vec<Observation<'static>> {
        with(src, b, |p, m| {
            let mut out = Vec::new();
            observe(p, m, &mut out);
            out.into_iter()
                .map(|o| match o {
                    Observation::Name { mac, name, source } => Observation::Name {
                        mac,
                        name: name.into_owned().into(),
                        source,
                    },
                    Observation::Service { mac, name } => Observation::Service {
                        mac,
                        name: name.into_owned().into(),
                    },
                    Observation::Model { mac, text } => Observation::Model {
                        mac,
                        text: text.into_owned().into(),
                    },
                    Observation::NameAnswer {
                        mac,
                        kind,
                        name,
                        data,
                    } => Observation::NameAnswer {
                        mac,
                        kind,
                        name: name.into_owned().into(),
                        data: data.into_owned().into(),
                    },
                    Observation::Heard { mac, proto } => Observation::Heard { mac, proto },
                    Observation::Address { mac, ip } => Observation::Address { mac, ip },
                    other => panic!("unexpected {other:?}"),
                })
                .collect()
        })
    }

    fn heard(src: u8) -> Observation<'static> {
        Observation::Heard {
            mac: Mac(mac(src)),
            proto: ProtoTag::Mdns,
        }
    }

    fn name(src: u8, n: &str) -> Observation<'static> {
        Observation::Name {
            mac: Mac(mac(src)),
            name: Cow::Owned(n.as_bytes().to_vec()),
            source: crate::observe::NameSource::Mdns,
        }
    }

    #[test]
    fn queries_only_say_heard() {
        let b = DnsBuilder::new(0).question("x.local", 1, 1);
        assert_eq!(obs(3, &b), vec![heard(3)]);
    }

    #[test]
    fn txt_model_hint() {
        let b = DnsBuilder::new(RESPONSE).answer(
            "x._h._tcp.local",
            16,
            1,
            120,
            RDataSpec::Txt(vec![
                "fn=Den".into(),
                "md=Chromecast".into(),
                "MODEL=MacBookPro18,1".into(),
                "mdx=no".into(),
            ]),
        );
        assert_eq!(
            obs(3, &b),
            vec![
                heard(3),
                Observation::Model {
                    mac: Mac(mac(3)),
                    text: Cow::Owned(b"Chromecast".to_vec())
                },
                Observation::Model {
                    mac: Mac(mac(3)),
                    text: Cow::Owned(b"MacBookPro18,1".to_vec())
                },
            ]
        );
    }

    #[test]
    fn announcement_observations() {
        let o = obs(0x21, &chromecast(4500));
        assert_eq!(
            o,
            vec![
                heard(0x21),
                Observation::Service {
                    mac: Mac(mac(0x21)),
                    name: Cow::Owned(b"Living-Room-TV._googlecast._tcp.local".to_vec())
                },
                name(0x21, "Living-Room-TV"),
                Observation::Model {
                    mac: Mac(mac(0x21)),
                    text: Cow::Owned(b"Chromecast".to_vec())
                },
                name(0x21, "Living-Room-TV"),
                Observation::Address {
                    mac: Mac(mac(0x21)),
                    ip: IpAddr::V4(v4(33))
                },
                Observation::NameAnswer {
                    mac: Mac(mac(0x21)),
                    kind: AnswerKind::MdnsUnique,
                    name: Cow::Owned(b"Living-Room-TV.local".to_vec()),
                    data: Cow::Owned(vec![192, 168, 1, 33])
                },
            ]
        );
    }

    #[test]
    fn cache_flush_a_gives_name_answer() {
        let flush = with_answers(RESPONSE, vec![a("printer.local", 48, 0x8001, 120)]);
        let o = obs(0x30, &flush);
        assert_eq!(o.len(), 4);
        assert_eq!(
            o[3],
            Observation::NameAnswer {
                mac: Mac(mac(0x30)),
                kind: AnswerKind::MdnsUnique,
                name: Cow::Owned(b"printer.local".to_vec()),
                data: Cow::Owned(vec![192, 168, 1, 48])
            }
        );
        // Without cache-flush, and for names outside .local, no answer.
        let plain = with_answers(RESPONSE, vec![a("printer.local", 48, 1, 120)]);
        assert_eq!(obs(0x30, &plain).len(), 3);
        let nolocal = with_answers(RESPONSE, vec![a("printer.example", 48, 0x8001, 120)]);
        assert_eq!(obs(0x30, &nolocal), vec![heard(0x30)]);
        let upper = with_answers(RESPONSE, vec![a("Printer.LOCAL", 48, 1, 120)]);
        assert_eq!(obs(0x30, &upper).len(), 3);
    }

    #[test]
    fn bad_names_teach_nothing() {
        // The second name is "b" plus a pointer to "local"; make that forward.
        let mut b = frame(
            5,
            &with_answers(
                RESPONSE,
                vec![a("a.local", 5, 0x8001, 120), a("b.local", 6, 0x8001, 120)],
            ),
        );
        let at = 14 + 20 + 8 + 12 + 9 + 14 + 2;
        b[at] = 0xc0;
        b[at + 1] = 0xf0;
        let p = decode(&b).unwrap();
        let Proto::Mdns(m) = &p.proto else {
            panic!("not mdns")
        };
        assert_eq!(m.records.len(), 2);
        assert!(m.records[0].name.is_valid() && !m.records[1].name.is_valid());
        assert_eq!(m.records[1].rdata, overhear_decode::RData::A(v4(6)));
        let mut out = Vec::new();
        observe(&p, m, &mut out);
        // Heard, then Name, Address and NameAnswer for "a.local" only.
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn verbose_lists_every_question_and_record() {
        let b = chromecast(4500).question("q.local", 255, 0x8001);
        let s = with(1, &b, |_, m| {
            let mut s = String::new();
            verbose(m, &mut s);
            s
        });
        let want = "  mDNS  response id 0 flags 0x8400 questions 1 records 4\n\
        \x20       Q  q.local ANY IN QU\n\
        \x20       AN _googlecast._tcp.local PTR IN ttl 4500 Living-Room-TV._googlecast._tcp.local\n\
        \x20       AN Living-Room-TV._googlecast._tcp.local SRV IN flush ttl 4500 priority 0 weight 0 port 8009 target Living-Room-TV.local\n\
        \x20       AN Living-Room-TV._googlecast._tcp.local TXT IN flush ttl 4500 \"md=Chromecast\"\n\
        \x20       AN Living-Room-TV.local A IN flush ttl 4500 192.168.1.33\n";
        assert_eq!(s, want);
    }

    #[test]
    fn json_object() {
        let b = DnsBuilder::new(RESPONSE).question("q.local", 1, 1).answer(
            "a\u{1b}.local",
            1,
            0x8001,
            120,
            RDataSpec::A(v4(33)),
        );
        let s = with(1, &b, |_, m| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(m, &mut w);
            w.end();
            w.as_str().to_string()
        });
        assert_eq!(
            s,
            r#"{"mdns":{"id":0,"flags":33792,"response":true,"questions":[{"name":"q.local","type":1,"type_name":"A","class":1,"unicast_response":false}],"records":[{"section":"answer","name":"a\u001b.local","type":1,"type_name":"A","class":1,"cache_flush":true,"ttl":120,"addr":"192.168.1.33"}]}}"#
        );
    }
}
