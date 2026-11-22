//! NetBIOS name service presentation and observations.

use std::borrow::Cow;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};

use overhear_decode::{NbName, NbRecord, Nbns, Packet, nb_entries};

use crate::escape::{LINE_FIELD_MAX, TextKind, push_text};
use crate::json::JsonWriter;
use crate::observe::{AnswerKind, NameSource, Observation, ProtoTag};

const TYPE_NB: u16 = 0x20;
const TYPE_NBSTAT: u16 = 0x21;

const OP_QUERY: u8 = 0;
const OP_REGISTRATION: u8 = 5;
const OP_RELEASE: u8 = 6;
const OP_WACK: u8 = 7;
const OP_REFRESH: u8 = 8;
const OP_REFRESH_ALT: u8 = 9;
const OP_MULTIHOMED: u8 = 15;

pub fn tag() -> &'static str {
    "NBNS"
}

fn type_name(t: u16) -> Cow<'static, str> {
    match t {
        TYPE_NB => Cow::Borrowed("NB"),
        TYPE_NBSTAT => Cow::Borrowed("NBSTAT"),
        n => Cow::Owned(format!("TYPE{n}")),
    }
}

/// `{trimmed}<{suffix:02x}>`, escaped as ASCII and cut at `max`.
fn push_name(out: &mut String, n: &NbName, max: usize) {
    push_text(out, n.trimmed(), TextKind::Ascii, max);
    let _ = write!(out, "<{:02x}>", n.suffix);
}

/// The unescaped display form, as carried in name answers.
fn name_bytes(n: &NbName) -> Vec<u8> {
    let mut v = n.trimmed().to_vec();
    v.extend_from_slice(format!("<{:02x}>", n.suffix).as_bytes());
    v
}

/// The address of the first NB record that has one.
fn first_addr(m: &Nbns<'_>) -> Option<Ipv4Addr> {
    m.records
        .iter()
        .filter(|r| r.rtype == TYPE_NB)
        .find_map(|r| nb_entries(r.rdata).next().map(|(_, a)| a))
}

/// The name a message is about: the first record's, else the first question's.
fn subject(m: &Nbns<'_>) -> Option<NbName> {
    m.records
        .first()
        .map(|r| r.name)
        .or_else(|| m.questions.first().map(|q| q.name))
}

pub fn summary(m: &Nbns<'_>, out: &mut String) {
    let name = subject(m);
    let ip = first_addr(m);
    let word = |out: &mut String, w: &str| {
        out.push_str(w);
        if let Some(n) = &name {
            out.push(' ');
            push_name(out, n, LINE_FIELD_MAX);
        }
        if let Some(ip) = ip {
            let _ = write!(out, " {ip}");
        }
    };
    if m.opcode == OP_WACK {
        out.push_str("wait");
        if let Some(n) = &name {
            out.push(' ');
            push_name(out, n, LINE_FIELD_MAX);
        }
        return;
    }
    if m.response {
        match (&name, m.rcode, ip) {
            (Some(n), 0, Some(ip)) => {
                push_name(out, n, LINE_FIELD_MAX);
                let _ = write!(out, " is {ip}");
            }
            (Some(n), 0, None) => {
                push_name(out, n, LINE_FIELD_MAX);
                out.push_str(
                    if m.records.first().is_some_and(|r| r.rtype == TYPE_NBSTAT) {
                        " node status"
                    } else {
                        " response"
                    },
                );
            }
            (Some(n), rcode, _) => {
                push_name(out, n, LINE_FIELD_MAX);
                let _ = write!(out, " not found (rcode {rcode})");
            }
            (None, 0, _) => out.push_str("response"),
            (None, rcode, _) => {
                let _ = write!(out, "not found (rcode {rcode})");
            }
        }
        return;
    }
    match m.opcode {
        OP_QUERY => {
            let status = m.questions.first().is_some_and(|q| q.qtype == TYPE_NBSTAT);
            out.push_str(if status { "status query" } else { "query" });
            if let Some(n) = &name {
                out.push(' ');
                push_name(out, n, LINE_FIELD_MAX);
            }
        }
        OP_REGISTRATION | OP_MULTIHOMED => word(out, "register"),
        OP_RELEASE => word(out, "release"),
        OP_REFRESH | OP_REFRESH_ALT => word(out, "refresh"),
        op => {
            let _ = write!(out, "opcode {op}");
            if let Some(n) = &name {
                out.push(' ');
                push_name(out, n, LINE_FIELD_MAX);
            }
        }
    }
}

fn record_line(r: &NbRecord<'_>, out: &mut String) {
    out.push_str("        AN ");
    push_name(out, &r.name, usize::MAX);
    let _ = write!(out, " {} ttl {}", type_name(r.rtype), r.ttl);
    if r.rtype == TYPE_NB {
        for (group, ip) in nb_entries(r.rdata) {
            let _ = write!(out, " {} {ip}", if group { "group" } else { "unique" });
        }
    } else if !r.rdata.is_empty() {
        out.push(' ');
        for b in r.rdata {
            let _ = write!(out, "{b:02x}");
        }
    }
    out.push('\n');
}

pub fn verbose(m: &Nbns<'_>, out: &mut String) {
    let _ = writeln!(
        out,
        "  {:<6}{} id {} flags 0x{:04x} opcode {} rcode {} questions {} records {}",
        tag(),
        if m.response { "response" } else { "query" },
        m.id,
        m.flags,
        m.opcode,
        m.rcode,
        m.questions.len(),
        m.records.len()
    );
    for q in &m.questions {
        out.push_str("        Q  ");
        push_name(out, &q.name, usize::MAX);
        let _ = writeln!(out, " {}", type_name(q.qtype));
    }
    for r in &m.records {
        record_line(r, out);
    }
}

fn json_name(w: &mut JsonWriter, n: &NbName) {
    w.text("name", n.trimmed(), TextKind::Ascii);
    w.u64(Some("suffix"), u64::from(n.suffix));
}

pub fn json(m: &Nbns<'_>, w: &mut JsonWriter) {
    w.obj(Some("nbns"));
    w.u64(Some("id"), u64::from(m.id));
    w.u64(Some("flags"), u64::from(m.flags));
    w.bool(Some("response"), m.response);
    w.u64(Some("opcode"), u64::from(m.opcode));
    w.u64(Some("rcode"), u64::from(m.rcode));
    w.arr(Some("questions"));
    for q in &m.questions {
        w.obj(None);
        json_name(w, &q.name);
        w.u64(Some("type"), u64::from(q.qtype));
        w.end();
    }
    w.end();
    w.arr(Some("records"));
    for r in &m.records {
        w.obj(None);
        json_name(w, &r.name);
        w.u64(Some("type"), u64::from(r.rtype));
        w.u64(Some("ttl"), u64::from(r.ttl));
        if r.rtype == TYPE_NB {
            w.arr(Some("entries"));
            for (group, ip) in nb_entries(r.rdata) {
                w.obj(None);
                w.bool(Some("group"), group);
                w.ip(Some("addr"), IpAddr::V4(ip));
                w.end();
            }
            w.end();
        } else {
            w.hex(Some("data_hex"), r.rdata);
        }
        w.end();
    }
    w.end();
    w.end();
}

/// Registrations and refreshes teach names (unique ones with their address,
/// group 00 names as the workgroup); a positive answer to a query is a name
/// answer the warn engine compares across hosts.
pub fn observe<'a>(p: &Packet<'a>, m: &Nbns<'a>, out: &mut Vec<Observation<'a>>) {
    let mac = p.eth.src;
    out.push(Observation::Heard {
        mac,
        proto: ProtoTag::Nbns,
    });
    let announces = matches!(
        m.opcode,
        OP_REGISTRATION | OP_MULTIHOMED | OP_REFRESH | OP_REFRESH_ALT
    );
    if !m.response && announces {
        for r in m.records.iter().filter(|r| r.rtype == TYPE_NB) {
            let trimmed = r.name.trimmed();
            for (group, ip) in nb_entries(r.rdata) {
                if trimmed.is_empty() {
                    continue;
                }
                if !group {
                    out.push(Observation::Name {
                        mac,
                        name: Cow::Owned(trimmed.to_vec()),
                        source: NameSource::Netbios,
                    });
                    out.push(Observation::Address {
                        mac,
                        ip: IpAddr::V4(ip),
                    });
                } else if r.name.suffix == 0 {
                    out.push(Observation::Detail {
                        mac,
                        key: "workgroup",
                        value: Cow::Owned(trimmed.to_vec()),
                    });
                }
            }
        }
    } else if m.response && m.opcode == OP_QUERY && m.rcode == 0 {
        let answer = m
            .records
            .iter()
            .filter(|r| r.rtype == TYPE_NB)
            .find_map(|r| nb_entries(r.rdata).next().map(|(_, ip)| (r, ip)));
        if let Some((r, ip)) = answer {
            out.push(Observation::NameAnswer {
                mac,
                kind: AnswerKind::Netbios,
                name: Cow::Owned(name_bytes(&r.name)),
                data: Cow::Owned(ip.octets().to_vec()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overhear_decode::{Mac, Proto, decode};
    use overhear_testgen::{eth_ipv4, ipv4_udp, mac, nb_encode, nbns};
    use std::net::Ipv4Addr;

    fn v4(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, d)
    }

    const ENC: fn(&str, u8) -> Vec<u8> = nb_encode;

    fn with<R>(src: u8, payload: &[u8], f: impl FnOnce(&Packet<'_>, &Nbns<'_>) -> R) -> R {
        let ip = ipv4_udp(v4(src), v4(255), 137, 137, payload);
        let fr = eth_ipv4(mac(1), mac(src), &ip);
        let p = decode(&fr).unwrap();
        let Proto::Nbns(m) = &p.proto else {
            panic!("not nbns")
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

    fn nb(group: bool, ip: u8) -> Vec<u8> {
        vec![if group { 0x80 } else { 0 }, 0, 192, 168, 1, ip]
    }

    /// A request carrying the name as a question and an NB record.
    fn request(op: u16, name: &str, suffix: u8, group: bool, ip: u8) -> Vec<u8> {
        nbns(
            1,
            op << 11 | 0x0110,
            &[(ENC(name, suffix), 0x20)],
            &[(vec![0xc0, 0x0c], 0x20, 300_000, nb(group, ip))],
        )
    }

    fn response(rcode: u16, name: &str, suffix: u8, ip: Option<u8>) -> Vec<u8> {
        let answers: Vec<_> = ip
            .map(|i| (ENC(name, suffix), 0x20, 300_000, nb(false, i)))
            .into_iter()
            .collect();
        nbns(1, 0x8500 | rcode, &[], &answers)
    }

    #[test]
    fn query_summaries() {
        let q = nbns(1, 0x0110, &[(ENC("FILESERVER", 0x20), 0x20)], &[]);
        assert_eq!(line(&q), "query FILESERVER<20>");
        let q = nbns(1, 0x0110, &[(ENC("FILESERVER", 0x20), 0x21)], &[]);
        assert_eq!(line(&q), "status query FILESERVER<20>");
        let q = nbns(1, 0x0010, &[(ENC("WORKGROUP", 0x1d), 0x20)], &[]);
        assert_eq!(line(&q), "query WORKGROUP<1d>");
    }

    #[test]
    fn request_summaries() {
        let ip = "192.168.1.20";
        for (op, word) in [
            (5, "register"),
            (15, "register"),
            (6, "release"),
            (8, "refresh"),
            (9, "refresh"),
        ] {
            assert_eq!(
                line(&request(op, "WORKSTATION1", 0, false, 20)),
                format!("{word} WORKSTATION1<00> {ip}"),
                "op {op}"
            );
        }
    }

    #[test]
    fn response_summaries() {
        assert_eq!(
            line(&response(0, "FILESERVER", 0x20, Some(64))),
            "FILESERVER<20> is 192.168.1.64"
        );
        let neg = nbns(1, 0x8503, &[(ENC("FILESERVER", 0x20), 0x20)], &[]);
        assert_eq!(line(&neg), "FILESERVER<20> not found (rcode 3)");
        let wack = nbns(
            1,
            0x8000 | 7 << 11,
            &[],
            &[(ENC("FILESERVER", 0x20), 0x20, 5, vec![0, 5])],
        );
        assert_eq!(line(&wack), "wait FILESERVER<20>");
    }

    #[test]
    fn summary_names_are_escaped_and_capped() {
        let q = nbns(1, 0x0110, &[(ENC("a\u{1b}[2Jb", 0), 0x20)], &[]);
        assert_eq!(line(&q), "query a\\x1b[2Jb<00>");
        let q = nbns(1, 0x0110, &[(ENC("ABCDEFGHIJKLMNO", 0), 0x20)], &[]);
        assert_eq!(line(&q), "query ABCDEFGHIJKLMNO<00>");
    }

    #[test]
    fn summary_without_a_usable_name() {
        let mut bad = ENC("X", 0);
        bad[3] = b'!';
        assert_eq!(line(&nbns(1, 0x0110, &[(bad, 0x20)], &[])), "query");
        assert_eq!(line(&nbns(1, 0x8000, &[], &[])), "response");
    }

    fn obs_of(src: u8, payload: &[u8]) -> Vec<Observation<'static>> {
        with(src, payload, |p, m| {
            let mut out = Vec::new();
            observe(p, m, &mut out);
            out.into_iter()
                .map(|o| match o {
                    Observation::Heard { mac, proto } => Observation::Heard { mac, proto },
                    Observation::Address { mac, ip } => Observation::Address { mac, ip },
                    Observation::Name { mac, name, source } => Observation::Name {
                        mac,
                        name: Cow::Owned(name.into_owned()),
                        source,
                    },
                    Observation::Detail { mac, key, value } => Observation::Detail {
                        mac,
                        key,
                        value: Cow::Owned(value.into_owned()),
                    },
                    Observation::NameAnswer {
                        mac,
                        kind,
                        name,
                        data,
                    } => Observation::NameAnswer {
                        mac,
                        kind,
                        name: Cow::Owned(name.into_owned()),
                        data: Cow::Owned(data.into_owned()),
                    },
                    other => panic!("unexpected {other:?}"),
                })
                .collect()
        })
    }

    fn heard(m: Mac) -> Observation<'static> {
        Observation::Heard {
            mac: m,
            proto: ProtoTag::Nbns,
        }
    }

    #[test]
    fn registration_teaches_name_and_address() {
        let m = Mac(mac(0x20));
        for op in [5, 15, 8, 9] {
            assert_eq!(
                obs_of(0x20, &request(op, "WORKSTATION1", 0, false, 20)),
                vec![
                    heard(m),
                    Observation::Name {
                        mac: m,
                        name: Cow::Owned(b"WORKSTATION1".to_vec()),
                        source: NameSource::Netbios
                    },
                    Observation::Address {
                        mac: m,
                        ip: IpAddr::V4(v4(20))
                    },
                ],
                "op {op}"
            );
        }
    }

    #[test]
    fn group_registration_with_suffix_00_is_the_workgroup() {
        let m = Mac(mac(0x20));
        assert_eq!(
            obs_of(0x20, &request(5, "HOME", 0, true, 20)),
            vec![
                heard(m),
                Observation::Detail {
                    mac: m,
                    key: "workgroup",
                    value: Cow::Owned(b"HOME".to_vec())
                },
            ]
        );
        // Other group names say nothing.
        assert_eq!(
            obs_of(0x20, &request(5, "HOME", 0x1e, true, 20)),
            vec![heard(m)]
        );
    }

    #[test]
    fn positive_response_is_a_name_answer() {
        let m = Mac(mac(0x40));
        assert_eq!(
            obs_of(0x40, &response(0, "FILESERVER", 0x20, Some(64))),
            vec![
                heard(m),
                Observation::NameAnswer {
                    mac: m,
                    kind: AnswerKind::Netbios,
                    name: Cow::Owned(b"FILESERVER<20>".to_vec()),
                    data: Cow::Owned(vec![192, 168, 1, 64])
                },
            ]
        );
    }

    #[test]
    fn queries_releases_and_negative_responses_only_hear() {
        let m = Mac(mac(5));
        let q = nbns(1, 0x0110, &[(ENC("FILESERVER", 0x20), 0x20)], &[]);
        let neg = nbns(1, 0x8503, &[(ENC("FILESERVER", 0x20), 0x20)], &[]);
        for b in [q, neg, request(6, "X", 0, false, 9)] {
            assert_eq!(obs_of(5, &b), vec![heard(m)]);
        }
    }

    #[test]
    fn verbose_lists_questions_and_records() {
        let b = nbns(
            1,
            0x8500,
            &[(ENC("FILESERVER", 0x20), 0x20)],
            &[(vec![0xc0, 0x0c], 0x20, 300_000, nb(false, 64))],
        );
        let s = with(1, &b, |_, m| {
            let mut s = String::new();
            verbose(m, &mut s);
            s
        });
        assert_eq!(
            s,
            "  NBNS  response id 1 flags 0x8500 opcode 0 rcode 0 questions 1 records 1\n\
             \x20       Q  FILESERVER<20> NB\n\
             \x20       AN FILESERVER<20> NB ttl 300000 unique 192.168.1.64\n"
        );
    }

    #[test]
    fn json_object() {
        let b = nbns(
            1,
            0x8500,
            &[(ENC("FILESERVER", 0x20), 0x21)],
            &[(vec![0xc0, 0x0c], 0x20, 7, nb(true, 64))],
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
            r#"{"nbns":{"id":1,"flags":34048,"response":true,"opcode":0,"rcode":0,"questions":[{"name":"FILESERVER","suffix":32,"type":33}],"records":[{"name":"FILESERVER","suffix":32,"type":32,"ttl":7,"entries":[{"group":true,"addr":"192.168.1.64"}]}]}}"#
        );
    }
}
