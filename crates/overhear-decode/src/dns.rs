//! DNS message decoder shared by mDNS, LLMNR and NetBIOS name service.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Cursor, Layer, Problem};

const MAX_NAME: usize = 255;
const MAX_HOPS: usize = 16;

/// A domain name inside a message: the message bytes and the offset of its
/// first label. Compression pointers are followed on demand; `parse` has
/// already checked that doing so terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name<'a> {
    msg: &'a [u8],
    off: usize,
    valid: bool,
}

type NameErr = &'static str;

/// Walks the labels of the name at `off`, following compression pointers,
/// and hands each label to `f`. Terminates on any input: pointers must go
/// strictly backwards, there are at most `MAX_HOPS` of them, and the name
/// may not exceed 255 bytes.
fn walk<'a>(msg: &'a [u8], off: usize, mut f: impl FnMut(&'a [u8])) -> Result<(), NameErr> {
    let mut pos = off;
    let mut total = 0usize;
    let mut hops = 0usize;
    loop {
        let len = *msg.get(pos).ok_or("truncated")?;
        match len & 0xc0 {
            0 => {
                let n = usize::from(len);
                if n == 0 {
                    return Ok(());
                }
                let start = pos.saturating_add(1);
                let label = msg.get(start..start.saturating_add(n)).ok_or("truncated")?;
                total = total.saturating_add(n).saturating_add(1);
                if total.saturating_add(1) > MAX_NAME {
                    return Err("name too long");
                }
                f(label);
                pos = start.saturating_add(n);
            }
            0xc0 => {
                let lo = *msg.get(pos.saturating_add(1)).ok_or("truncated")?;
                let target = usize::from(len & 0x3f) << 8 | usize::from(lo);
                if target >= pos {
                    return Err("compression pointer does not point backwards");
                }
                hops = hops.saturating_add(1);
                if hops > MAX_HOPS {
                    return Err("too many compression pointers");
                }
                pos = target;
            }
            _ => return Err("bad label type"),
        }
    }
}

/// Length of the name at `off` as written on the wire (up to and including
/// the terminating zero or the first pointer), or why it cannot be known.
fn wire_len(msg: &[u8], off: usize) -> Result<usize, NameErr> {
    let mut pos = off;
    loop {
        let len = *msg.get(pos).ok_or("truncated")?;
        match len & 0xc0 {
            0 if len == 0 => return Ok(pos.saturating_add(1).saturating_sub(off)),
            0 => {
                pos = pos.saturating_add(usize::from(len)).saturating_add(1);
                if pos > msg.len() {
                    return Err("truncated");
                }
            }
            0xc0 => {
                msg.get(pos.saturating_add(1)).ok_or("truncated")?;
                return Ok(pos.saturating_add(2).saturating_sub(off));
            }
            _ => return Err("bad label type"),
        }
    }
}

impl<'a> Name<'a> {
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Appends `a.b.local` (the root name is `.`); an invalid name is
    /// written as `<bad name>`.
    pub fn write_dotted(&self, out: &mut Vec<u8>) {
        if !self.valid {
            out.extend_from_slice(b"<bad name>");
            return;
        }
        let mut any = false;
        let r = walk(self.msg, self.off, |l| {
            if any {
                out.push(b'.');
            }
            any = true;
            out.extend_from_slice(l);
        });
        if r.is_ok() && !any {
            out.push(b'.');
        }
    }

    /// The first label, `None` for the root name or an invalid name.
    pub fn first_label(&self) -> Option<&'a [u8]> {
        if !self.valid {
            return None;
        }
        let mut first = None;
        let _ = walk(self.msg, self.off, |l| {
            if first.is_none() {
                first = Some(l);
            }
        });
        first
    }

    /// The dotted name as an owned byte string.
    pub fn dotted(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.write_dotted(&mut v);
        v
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Question<'a> {
    pub name: Name<'a>,
    pub qtype: u16,
    /// As on the wire; in mDNS the top bit is QU.
    pub qclass: u16,
}

impl Question<'_> {
    /// mDNS unicast-response (QU) bit.
    pub fn unicast_response(&self) -> bool {
        self.qclass & 0x8000 != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RData<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(Name<'a>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name<'a>,
    },
    Txt(&'a [u8]),
    Other(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    pub section: Section,
    pub name: Name<'a>,
    pub rtype: u16,
    /// As on the wire; in mDNS the top bit is cache-flush.
    pub class: u16,
    pub ttl: u32,
    pub rdata: RData<'a>,
}

impl Record<'_> {
    /// mDNS cache-flush bit.
    pub fn cache_flush(&self) -> bool {
        self.class & 0x8000 != 0
    }

    /// The class without the mDNS flag bit.
    pub fn class_code(&self) -> u16 {
        self.class & 0x7fff
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage<'a> {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question<'a>>,
    pub records: Vec<Record<'a>>,
}

impl DnsMessage<'_> {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// The length-prefixed strings of a TXT record; a string cut short by the end
/// of the data is yielded as far as it goes.
pub fn txt_strings(txt: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = txt;
    std::iter::from_fn(move || {
        let (&len, tail) = rest.split_first()?;
        let n = usize::from(len).min(tail.len());
        let (s, after) = tail.split_at(n);
        rest = after;
        Some(s)
    })
}

/// Reads a name at the cursor. A name whose extent on the wire cannot be
/// found stops the message (`Err`); one that merely fails validation is kept
/// as an invalid name.
fn read_name<'a>(
    r: &mut Cursor<'a>,
    msg: &'a [u8],
    start: usize,
    problems: &mut Vec<Problem>,
) -> Result<Name<'a>, ()> {
    let abs = r.pos();
    let off = abs.saturating_sub(start);
    let wire = match wire_len(msg, off) {
        Ok(w) => w,
        Err(reason) => {
            problems.push(Problem {
                layer: Layer::Dns,
                reason,
                offset: abs,
                len: if reason == "truncated" {
                    r.remaining()
                } else {
                    1
                },
            });
            return Err(());
        }
    };
    r.skip(wire).ok_or(())?;
    Ok(make_name(msg, off, abs, wire, problems))
}

fn make_name<'a>(
    msg: &'a [u8],
    off: usize,
    abs: usize,
    wire: usize,
    problems: &mut Vec<Problem>,
) -> Name<'a> {
    let valid = match walk(msg, off, |_| {}) {
        Ok(()) => true,
        Err(reason) => {
            problems.push(Problem {
                layer: Layer::Dns,
                reason,
                offset: abs,
                len: wire,
            });
            false
        }
    };
    Name { msg, off, valid }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let w: [u8; 2] = b.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(w))
}

fn rdata<'a>(
    msg: &'a [u8],
    rtype: u16,
    data: &'a [u8],
    abs: usize,
    off: usize,
    problems: &mut Vec<Problem>,
) -> RData<'a> {
    let bad = |problems: &mut Vec<Problem>, reason: &'static str| {
        problems.push(Problem {
            layer: Layer::Dns,
            reason,
            offset: abs,
            len: data.len(),
        });
        RData::Other(data)
    };
    // A name that fills `data` from `skip` on.
    let name_at = |skip: usize, problems: &mut Vec<Problem>| -> Result<Name<'a>, &'static str> {
        let rel = off.saturating_add(skip);
        let bounded = msg.get(..off.saturating_add(data.len())).unwrap_or(msg);
        let wire = wire_len(bounded, rel)?;
        if wire != data.len().saturating_sub(skip) {
            return Err("bad rdata length");
        }
        Ok(make_name(
            msg,
            rel,
            abs.saturating_add(skip),
            wire,
            problems,
        ))
    };
    match rtype {
        1 => match <[u8; 4]>::try_from(data) {
            Ok(a) => RData::A(Ipv4Addr::from(a)),
            Err(_) => bad(problems, "bad rdata length"),
        },
        28 => match <[u8; 16]>::try_from(data) {
            Ok(a) => RData::Aaaa(Ipv6Addr::from(a)),
            Err(_) => bad(problems, "bad rdata length"),
        },
        12 => match name_at(0, problems) {
            Ok(n) => RData::Ptr(n),
            Err(reason) => bad(problems, reason),
        },
        33 => {
            let (Some(priority), Some(weight), Some(port)) =
                (be16(data, 0), be16(data, 2), be16(data, 4))
            else {
                return bad(problems, "bad rdata length");
            };
            match name_at(6, problems) {
                Ok(target) => RData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                },
                Err(reason) => bad(problems, reason),
            }
        }
        16 => RData::Txt(data),
        _ => RData::Other(data),
    }
}

/// Parses a DNS message from the cursor's position. Compression pointers count
/// from the position at entry, the DNS header, whatever region the cursor has. Counts
/// that run past the data, or a name whose length cannot be found, stop the
/// parse; the questions and records read so far are kept.
pub fn parse<'a>(c: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Option<DnsMessage<'a>> {
    let begin = c.pos();
    let start = begin;
    let mut r = *c;
    let end = begin.saturating_add(r.remaining());
    let msg = r.frame().get(start..end)?;
    let (Some(id), Some(flags), Some(qd), Some(an), Some(ns), Some(ar)) =
        (r.be16(), r.be16(), r.be16(), r.be16(), r.be16(), r.be16())
    else {
        problems.push(Problem {
            layer: Layer::Dns,
            reason: "truncated",
            offset: begin,
            len: c.remaining(),
        });
        return None;
    };
    let mut m = DnsMessage {
        id,
        flags,
        questions: Vec::new(),
        records: Vec::new(),
    };
    let truncated = |r: &Cursor<'_>, problems: &mut Vec<Problem>| {
        problems.push(Problem {
            layer: Layer::Dns,
            reason: "truncated",
            offset: r.pos(),
            len: r.remaining(),
        });
    };
    'parse: {
        for _ in 0..qd {
            let Ok(name) = read_name(&mut r, msg, start, problems) else {
                break 'parse;
            };
            let (Some(qtype), Some(qclass)) = (r.be16(), r.be16()) else {
                truncated(&r, problems);
                break 'parse;
            };
            m.questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        let answers = usize::from(an);
        let authority = answers.saturating_add(usize::from(ns));
        let total = authority.saturating_add(usize::from(ar));
        for i in 0..total {
            let section = if i < answers {
                Section::Answer
            } else if i < authority {
                Section::Authority
            } else {
                Section::Additional
            };
            let Ok(name) = read_name(&mut r, msg, start, problems) else {
                break 'parse;
            };
            let (Some(rtype), Some(class), Some(ttl), Some(rdlen)) =
                (r.be16(), r.be16(), r.be32(), r.be16())
            else {
                truncated(&r, problems);
                break 'parse;
            };
            let abs = r.pos();
            let Some(data) = r.take(usize::from(rdlen)) else {
                truncated(&r, problems);
                break 'parse;
            };
            let off = abs.saturating_sub(start);
            m.records.push(Record {
                section,
                name,
                rtype,
                class,
                ttl,
                rdata: rdata(msg, rtype, data, abs, off, problems),
            });
        }
    }
    r.rest();
    *c = r;
    Some(m)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use super::*;
    use overhear_testgen::{DnsBuilder, RDataSpec};

    fn run(b: &[u8]) -> (Option<DnsMessage<'_>>, Vec<Problem>) {
        let mut c = Cursor::new(b);
        let mut p = Vec::new();
        (parse(&mut c, &mut p), p)
    }

    fn dotted(n: &Name<'_>) -> String {
        String::from_utf8(n.dotted()).unwrap()
    }

    /// A header followed by `body`, with the given counts.
    fn raw(qd: u16, an: u16, body: &[u8]) -> Vec<u8> {
        let mut m = vec![0, 0, 0, 0];
        m.extend_from_slice(&qd.to_be_bytes());
        m.extend_from_slice(&an.to_be_bytes());
        m.extend_from_slice(&[0; 4]);
        m.extend_from_slice(body);
        m
    }

    #[test]
    fn query_with_qu_bit() {
        let b = DnsBuilder::new(0)
            .question("_googlecast._tcp.local", 12, 0x8001)
            .bytes();
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert!(p.is_empty());
        assert!(!m.is_response());
        assert_eq!(m.questions.len(), 1);
        let q = &m.questions[0];
        assert_eq!(dotted(&q.name), "_googlecast._tcp.local");
        assert_eq!((q.qtype, q.qclass), (12, 0x8001));
        assert!(q.unicast_response());
    }

    #[test]
    fn compressed_ptr_target() {
        let b = DnsBuilder::new(0x8400)
            .answer(
                "_googlecast._tcp.local",
                12,
                1,
                4500,
                RDataSpec::Ptr("Living-Room-TV._googlecast._tcp.local".into()),
            )
            .bytes();
        // The target must really use a pointer.
        assert!(b.windows(2).any(|w| w[0] == 0xc0));
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert!(p.is_empty());
        assert!(m.is_response());
        assert_eq!(m.records.len(), 1);
        let RData::Ptr(t) = m.records[0].rdata else {
            panic!("not ptr")
        };
        assert!(t.is_valid());
        assert_eq!(dotted(&t), "Living-Room-TV._googlecast._tcp.local");
        assert_eq!(t.first_label(), Some(&b"Living-Room-TV"[..]));
    }

    #[test]
    fn forward_pointer_rejected() {
        let b = raw(1, 0, &[0xc0, 0x20, 0, 12, 0, 1]);
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].layer, p[0].reason),
            (Layer::Dns, "compression pointer does not point backwards")
        );
        assert_eq!((p[0].offset, p[0].len), (12, 2));
        assert_eq!(m.questions.len(), 1);
        assert!(!m.questions[0].name.is_valid());
        assert_eq!(dotted(&m.questions[0].name), "<bad name>");
        assert_eq!(m.questions[0].qtype, 12);
    }

    #[test]
    fn self_pointer_rejected() {
        let b = raw(1, 0, &[0xc0, 12, 0, 1, 0, 1]);
        let (m, p) = run(&b);
        assert_eq!(p[0].reason, "compression pointer does not point backwards");
        assert!(!m.unwrap().questions[0].name.is_valid());
    }

    #[test]
    fn label_pointer_cycle_terminates() {
        // "a" then a pointer back to "a": strictly backwards, but a loop.
        let b = raw(1, 0, &[1, b'a', 0xc0, 12, 0, 1, 0, 1]);
        let (m, p) = run(&b);
        assert_eq!(p.len(), 1);
        assert!(!m.unwrap().questions[0].name.is_valid());
    }

    #[test]
    fn pointer_chain_is_bounded() {
        // Question 0 is the root name; question k is a pointer to question
        // k-1, so it needs k hops.
        let mut body = vec![0, 0, 1, 0, 1];
        let mut prev = 12usize;
        for k in 1..40usize {
            let at = 12 + body.len();
            body.extend_from_slice(&(0xc000u16 | prev as u16).to_be_bytes());
            body.extend_from_slice(&[0, 1, 0, 1]);
            prev = at;
            let _ = k;
        }
        let b = raw(40, 0, &body);
        let (m, _) = run(&b);
        let m = m.unwrap();
        assert_eq!(m.questions.len(), 40);
        assert!(m.questions[16].name.is_valid());
        assert!(!m.questions[17].name.is_valid());
        assert!(!m.questions[39].name.is_valid());
    }

    #[test]
    fn name_over_255_rejected() {
        let mut body = Vec::new();
        for _ in 0..5 {
            body.push(63);
            body.extend_from_slice(&[b'x'; 63]);
        }
        body.push(0);
        body.extend_from_slice(&[0, 12, 0, 1]);
        // And a second question that must survive.
        body.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        let b = raw(2, 0, &body);
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].reason, "name too long");
        assert_eq!(m.questions.len(), 2);
        assert!(!m.questions[0].name.is_valid());
        assert_eq!(dotted(&m.questions[1].name), "a");
    }

    #[test]
    fn label_of_63_and_name_of_255_are_fine() {
        // 3 x 64 + 62 = 254 bytes of labels, plus the root = 255.
        let mut body = Vec::new();
        for _ in 0..3 {
            body.push(63);
            body.extend_from_slice(&[b'x'; 63]);
        }
        body.push(61);
        body.extend_from_slice(&[b'y'; 61]);
        body.push(0);
        body.extend_from_slice(&[0, 1, 0, 1]);
        let b = raw(1, 0, &body);
        let (m, p) = run(&b);
        assert!(p.is_empty(), "{p:?}");
        assert!(m.unwrap().questions[0].name.is_valid());
    }

    #[test]
    fn reserved_label_type() {
        for first in [0x40u8, 0x80] {
            let b = raw(1, 0, &[first, b'a', 0, 0, 1, 0, 1]);
            let (m, p) = run(&b);
            assert_eq!(p.len(), 1);
            assert_eq!(p[0].reason, "bad label type");
            assert!(m.unwrap().questions.is_empty());
        }
    }

    #[test]
    fn counts_exceed_data() {
        let b = DnsBuilder::new(0x8400)
            .answer(
                "a.local",
                1,
                1,
                120,
                RDataSpec::A(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .bytes();
        let mut b = b;
        b[6..8].copy_from_slice(&50u16.to_be_bytes());
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert_eq!(m.records.len(), 1);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].layer, p[0].reason), (Layer::Dns, "truncated"));
    }

    #[test]
    fn truncated_header() {
        let (m, p) = run(&[0; 11]);
        assert!(m.is_none());
        assert_eq!(p[0].reason, "truncated");
    }

    #[test]
    fn bad_name_keeps_the_rest() {
        let mut b = DnsBuilder::new(0x8400)
            .answer(
                "a.local",
                1,
                1,
                120,
                RDataSpec::A(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .answer(
                "b.local",
                1,
                1,
                120,
                RDataSpec::A(Ipv4Addr::new(10, 0, 0, 2)),
            )
            .bytes();
        // The second name is "b" plus a pointer to "local"; make the pointer
        // point forward.
        let second = 12 + 9 + 14;
        b[second + 2] = 0xc0;
        b[second + 3] = 0xf0;
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert_eq!(m.records.len(), 2);
        assert_eq!(p.len(), 1);
        assert!(m.records[0].name.is_valid());
        assert!(!m.records[1].name.is_valid());
        assert_eq!(m.records[1].rdata, RData::A(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn record_types_and_flags() {
        let b = DnsBuilder::new(0x8400)
            .answer(
                "x._h._tcp.local",
                33,
                0x8001,
                120,
                RDataSpec::Srv(8009, "tv.local".into()),
            )
            .answer(
                "tv.local",
                28,
                1,
                120,
                RDataSpec::Aaaa("fe80::1".parse().unwrap()),
            )
            .answer(
                "x._h._tcp.local",
                16,
                1,
                0,
                RDataSpec::Txt(vec!["md=Chromecast".into()]),
            )
            .answer("x._h._tcp.local", 47, 1, 5, RDataSpec::Txt(vec![]))
            .bytes();
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert!(p.is_empty(), "{p:?}");
        let r = &m.records;
        assert!(r[0].cache_flush());
        assert_eq!(r[0].class_code(), 1);
        match r[0].rdata {
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!((priority, weight, port), (0, 0, 8009));
                assert_eq!(dotted(&target), "tv.local");
            }
            _ => panic!("not srv"),
        }
        assert_eq!(r[1].rdata, RData::Aaaa("fe80::1".parse().unwrap()));
        assert_eq!(r[2].rdata, RData::Txt(b"\x0dmd=Chromecast"));
        assert_eq!(r[2].ttl, 0);
        assert_eq!(r[3].section, Section::Answer);
    }

    #[test]
    fn wrong_rdata_length_is_other() {
        let mut b = DnsBuilder::new(0x8400)
            .answer(
                "a.local",
                1,
                1,
                120,
                RDataSpec::A(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .bytes();
        let at = b.len() - 6;
        b[at..at + 2].copy_from_slice(&3u16.to_be_bytes());
        b.truncate(b.len() - 1);
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert_eq!(m.records[0].rdata, RData::Other(&[10, 0, 0]));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn truncated_rdata_stops() {
        let b = DnsBuilder::new(0x8400)
            .answer(
                "a.local",
                1,
                1,
                120,
                RDataSpec::A(Ipv4Addr::new(10, 0, 0, 1)),
            )
            .bytes();
        let (m, p) = run(&b[..b.len() - 2]);
        assert!(m.unwrap().records.is_empty());
        assert_eq!(p[0].reason, "truncated");
    }

    #[test]
    fn txt_strings_iterate() {
        let t = [3, b'a', b'b', b'c', 0, 2, b'm', b'd'];
        let v: Vec<&[u8]> = txt_strings(&t).collect();
        assert_eq!(v, vec![&b"abc"[..], &b""[..], &b"md"[..]]);
        // A string cut short is yielded as far as it goes.
        let v: Vec<&[u8]> = txt_strings(&[5, b'a']).collect();
        assert_eq!(v, vec![&b"a"[..]]);
        assert_eq!(txt_strings(&[]).count(), 0);
    }

    #[test]
    fn pointers_count_from_the_dns_header_not_the_region_start() {
        let msg = DnsBuilder::new(0x8400)
            .answer(
                "_x._tcp.local",
                12,
                1,
                120,
                RDataSpec::Ptr("i._x._tcp.local".into()),
            )
            .bytes();
        let mut frame = vec![0xee; 7];
        frame.extend_from_slice(&msg);
        let mut c = Cursor::new(&frame);
        c.skip(7).unwrap();
        let mut p = Vec::new();
        let m = parse(&mut c, &mut p).unwrap();
        assert!(p.is_empty(), "{p:?}");
        let RData::Ptr(t) = m.records[0].rdata else {
            panic!("not ptr")
        };
        assert_eq!(dotted(&t), "i._x._tcp.local");
    }

    #[test]
    fn pointer_into_header_bytes_is_not_a_crash() {
        // A pointer to offset 0 reads header bytes as labels; whatever comes
        // out, parsing terminates.
        let b = raw(1, 0, &[0xc0, 0, 0, 1, 0, 1]);
        let (m, _) = run(&b);
        assert!(m.is_some());
    }
}
