//! NetBIOS name service (RFC 1002) decoder.

use std::net::Ipv4Addr;

use crate::dns::read_name;
use crate::{Cursor, Layer, Problem};

/// A NetBIOS name: 15 space-padded characters and the type suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NbName {
    pub name: [u8; 15],
    pub suffix: u8,
}

impl NbName {
    /// The name without its trailing padding (spaces, and the NULs of a
    /// node status wildcard).
    pub fn trimmed(&self) -> &[u8] {
        let end = self
            .name
            .iter()
            .rposition(|&b| b != b' ' && b != 0)
            .map_or(0, |i| i.saturating_add(1));
        self.name.get(..end).unwrap_or(&[])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NbQuestion {
    pub name: NbName,
    pub qtype: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NbRecord<'a> {
    pub name: NbName,
    pub rtype: u16,
    pub ttl: u32,
    pub rdata: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nbns<'a> {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub flags: u16,
    pub rcode: u8,
    pub questions: Vec<NbQuestion>,
    pub records: Vec<NbRecord<'a>>,
}

/// The entries of an NB record's data: `(group, address)` per 6 bytes; a
/// partial entry at the end is ignored.
pub fn nb_entries(rdata: &[u8]) -> impl Iterator<Item = (bool, Ipv4Addr)> {
    rdata.chunks_exact(6).filter_map(|e| {
        let (flags, addr) = e.split_first_chunk::<2>()?;
        let addr: [u8; 4] = addr.try_into().ok()?;
        Some((flags[0] & 0x80 != 0, Ipv4Addr::from(addr)))
    })
}

/// Decodes the first label of a name: 32 characters 'A'..='P', two per byte.
fn decode_label(label: &[u8]) -> Result<NbName, &'static str> {
    if label.len() != 32 {
        return Err("bad NetBIOS name length");
    }
    let mut raw = [0u8; 16];
    for (out, pair) in raw.iter_mut().zip(label.chunks_exact(2)) {
        let nib = |c: Option<&u8>| {
            c.and_then(|c| c.checked_sub(b'A'))
                .filter(|n| *n < 16)
                .ok_or("bad NetBIOS name encoding")
        };
        *out = nib(pair.first())? << 4 | nib(pair.get(1))?;
    }
    let (name, suffix) = raw.split_at(15);
    Ok(NbName {
        name: name.try_into().map_err(|_| "bad NetBIOS name length")?,
        suffix: suffix.first().copied().unwrap_or(0),
    })
}

/// Reads a name at the cursor and decodes it. `Err(true)` means the message
/// cannot go on (the name's extent is unknown); `Err(false)` that only this
/// name is unusable and has been reported.
fn name<'a>(
    r: &mut Cursor<'a>,
    msg: &'a [u8],
    start: usize,
    problems: &mut Vec<Problem>,
) -> Result<NbName, bool> {
    let abs = r.pos();
    let n = read_name(r, msg, start, Layer::Nbns, problems).map_err(|()| true)?;
    if !n.is_valid() {
        return Err(false);
    }
    let first = n.first_label().unwrap_or(&[]);
    decode_label(first).map_err(|reason| {
        problems.push(Problem {
            layer: Layer::Nbns,
            reason,
            offset: abs,
            len: r.pos().saturating_sub(abs),
        });
        false
    })
}

/// Parses a NetBIOS name service message from the cursor's position. A name
/// that cannot be decoded is reported and its question or record left out; a
/// name that cannot be delimited, or counts that run past the data, stop the
/// parse with what was read so far.
pub fn parse<'a>(c: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Option<Nbns<'a>> {
    let start = c.pos();
    let mut r = *c;
    let end = start.saturating_add(r.remaining());
    let msg = r.frame().get(start..end)?;
    let (Some(id), Some(flags), Some(qd), Some(an), Some(ns), Some(ar)) =
        (r.be16(), r.be16(), r.be16(), r.be16(), r.be16(), r.be16())
    else {
        problems.push(Problem {
            layer: Layer::Nbns,
            reason: "truncated",
            offset: start,
            len: c.remaining(),
        });
        return None;
    };
    let mut m = Nbns {
        id,
        response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0xf) as u8,
        flags,
        rcode: (flags & 0xf) as u8,
        questions: Vec::new(),
        records: Vec::new(),
    };
    let truncated = |r: &Cursor<'_>, problems: &mut Vec<Problem>| {
        problems.push(Problem {
            layer: Layer::Nbns,
            reason: "truncated",
            offset: r.pos(),
            len: r.remaining(),
        });
    };
    'parse: {
        for _ in 0..qd {
            let nm = match name(&mut r, msg, start, problems) {
                Ok(n) => Some(n),
                Err(true) => break 'parse,
                Err(false) => None,
            };
            let (Some(qtype), Some(_class)) = (r.be16(), r.be16()) else {
                truncated(&r, problems);
                break 'parse;
            };
            if let Some(name) = nm {
                m.questions.push(NbQuestion { name, qtype });
            }
        }
        let total = usize::from(an)
            .saturating_add(usize::from(ns))
            .saturating_add(usize::from(ar));
        for _ in 0..total {
            let nm = match name(&mut r, msg, start, problems) {
                Ok(n) => Some(n),
                Err(true) => break 'parse,
                Err(false) => None,
            };
            let (Some(rtype), Some(_class), Some(ttl), Some(rdlen)) =
                (r.be16(), r.be16(), r.be32(), r.be16())
            else {
                truncated(&r, problems);
                break 'parse;
            };
            let Some(rdata) = r.take(usize::from(rdlen)) else {
                truncated(&r, problems);
                break 'parse;
            };
            if let Some(name) = nm {
                m.records.push(NbRecord {
                    name,
                    rtype,
                    ttl,
                    rdata,
                });
            }
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
    use crate::Layer;
    use overhear_testgen::{nb_encode, nbns};

    fn run(b: &[u8]) -> (Option<Nbns<'_>>, Vec<Problem>) {
        let mut c = Cursor::new(b);
        let mut p = Vec::new();
        (parse(&mut c, &mut p), p)
    }

    fn reasons(p: &[Problem]) -> Vec<(Layer, &'static str)> {
        p.iter().map(|p| (p.layer, p.reason)).collect()
    }

    #[test]
    fn decodes_fileserver_20() {
        let b = nbns(
            7,
            0x0110,
            &[(b"\x20EGEJEMEFFDEFFCFGEFFCCACACACACACA\0".to_vec(), 0x20)],
            &[],
        );
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert!(p.is_empty(), "{p:?}");
        assert_eq!((m.id, m.response, m.opcode, m.rcode), (7, false, 0, 0));
        assert_eq!(m.questions.len(), 1);
        let q = &m.questions[0];
        assert_eq!(q.name.trimmed(), b"FILESERVER");
        assert_eq!(q.name.suffix, 0x20);
        assert_eq!(q.qtype, 0x20);
        assert_eq!(q.name, {
            let mut n = [b' '; 15];
            n[..10].copy_from_slice(b"FILESERVER");
            NbName {
                name: n,
                suffix: 0x20,
            }
        });
    }

    #[test]
    fn header_fields() {
        // response, opcode 5, rcode 3
        let b = nbns(1, 0x8000 | 5 << 11 | 3, &[], &[]);
        let m = run(&b).0.unwrap();
        assert!(m.response);
        assert_eq!((m.opcode, m.rcode), (5, 3));
    }

    #[test]
    fn bad_encoding_char() {
        let mut name = nb_encode("FILESERVER", 0x20);
        name[5] = b'Z';
        let b = nbns(1, 0, &[(name, 0x20)], &[]);
        let (m, p) = run(&b);
        assert!(m.unwrap().questions.is_empty());
        assert_eq!(
            reasons(&p),
            vec![(Layer::Nbns, "bad NetBIOS name encoding")]
        );
    }

    #[test]
    fn bad_label_length() {
        let b = nbns(1, 0, &[(b"\x04ABCD\0".to_vec(), 0x20)], &[]);
        let (m, p) = run(&b);
        assert!(m.unwrap().questions.is_empty());
        assert_eq!(reasons(&p), vec![(Layer::Nbns, "bad NetBIOS name length")]);
        // The root name has no label at all.
        let b = nbns(1, 0, &[(vec![0], 0x20)], &[]);
        assert_eq!(
            reasons(&run(&b).1),
            vec![(Layer::Nbns, "bad NetBIOS name length")]
        );
    }

    #[test]
    fn scope_labels_are_ignored() {
        let mut name = nb_encode("HOST", 0);
        name.pop();
        name.extend_from_slice(b"\x05SCOPE\x03com\0");
        let b = nbns(1, 0, &[(name, 0x20)], &[]);
        let (m, p) = run(&b);
        assert!(p.is_empty());
        assert_eq!(m.unwrap().questions[0].name.trimmed(), b"HOST");
    }

    #[test]
    fn registration_with_pointer_name() {
        let rdata = vec![0x00, 0x00, 10, 0, 0, 7];
        let b = nbns(
            9,
            5 << 11 | 0x0110,
            &[(nb_encode("WORKSTATION1", 0), 0x20)],
            &[(vec![0xc0, 0x0c], 0x20, 300_000, rdata)],
        );
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert!(p.is_empty(), "{p:?}");
        assert_eq!(m.opcode, 5);
        assert_eq!(m.records.len(), 1);
        let r = &m.records[0];
        assert_eq!(r.name.trimmed(), b"WORKSTATION1");
        assert_eq!((r.name.suffix, r.rtype, r.ttl), (0, 0x20, 300_000));
        assert_eq!(r.rdata, &[0, 0, 10, 0, 0, 7]);
    }

    #[test]
    fn forward_pointer_name_is_dropped_not_fatal() {
        let b = nbns(1, 0, &[(vec![0xc0, 0x40], 0x20)], &[]);
        let (m, p) = run(&b);
        assert!(m.unwrap().questions.is_empty());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].layer, Layer::Nbns);
    }

    #[test]
    fn truncated_record_keeps_earlier_items() {
        let mut b = nbns(
            1,
            0x8000,
            &[(nb_encode("A", 0), 0x20)],
            &[(vec![0xc0, 0x0c], 0x20, 1, vec![0; 6])],
        );
        b.truncate(b.len() - 3);
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert_eq!(m.questions.len(), 1);
        assert!(m.records.is_empty());
        assert_eq!(reasons(&p), vec![(Layer::Nbns, "truncated")]);
        assert!(run(&[0; 5]).0.is_none());
    }

    #[test]
    fn nb_entries_group_bit() {
        let rdata = [0x80, 0, 10, 0, 0, 1, 0x00, 0, 10, 0, 0, 2, 0xff];
        let v: Vec<_> = nb_entries(&rdata).collect();
        assert_eq!(
            v,
            vec![
                (true, Ipv4Addr::new(10, 0, 0, 1)),
                (false, Ipv4Addr::new(10, 0, 0, 2))
            ]
        );
    }

    #[test]
    fn trimmed_strips_padding_only() {
        let n = NbName {
            name: *b"A B            ",
            suffix: 0,
        };
        assert_eq!(n.trimmed(), b"A B");
        let full = NbName {
            name: *b"ABCDEFGHIJKLMNO",
            suffix: 0,
        };
        assert_eq!(full.trimmed(), b"ABCDEFGHIJKLMNO");
        let empty = NbName {
            name: [b' '; 15],
            suffix: 0,
        };
        assert_eq!(empty.trimmed(), b"");
        let wildcard = NbName {
            name: *b"*\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            suffix: 0,
        };
        assert_eq!(wildcard.trimmed(), b"*");
    }
}
