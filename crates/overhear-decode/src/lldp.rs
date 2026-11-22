//! LLDP (IEEE 802.1AB) decoder.

use crate::{Cursor, Layer, Problem};

/// The most TLVs kept; the rest of the data unit is ignored.
pub const MAX_TLVS: usize = 64;
/// The most "bad TLV length" problems reported per message.
pub const MAX_BAD_TLVS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LldpTlv<'a> {
    ChassisId {
        subtype: u8,
        id: &'a [u8],
    },
    PortId {
        subtype: u8,
        id: &'a [u8],
    },
    Ttl(u16),
    PortDescr(&'a [u8]),
    SysName(&'a [u8]),
    SysDescr(&'a [u8]),
    Capabilities {
        system: u16,
        enabled: u16,
    },
    MgmtAddr {
        subtype: u8,
        addr: &'a [u8],
    },
    PortVlan(u16),
    Org {
        oui: [u8; 3],
        subtype: u8,
        data: &'a [u8],
    },
    Other {
        typ: u8,
        data: &'a [u8],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lldp<'a> {
    pub tlvs: Vec<LldpTlv<'a>>,
}

impl<'a> Lldp<'a> {
    pub fn chassis(&self) -> Option<(u8, &'a [u8])> {
        self.tlvs.iter().find_map(|t| match t {
            LldpTlv::ChassisId { subtype, id } => Some((*subtype, *id)),
            _ => None,
        })
    }

    pub fn port(&self) -> Option<(u8, &'a [u8])> {
        self.tlvs.iter().find_map(|t| match t {
            LldpTlv::PortId { subtype, id } => Some((*subtype, *id)),
            _ => None,
        })
    }

    pub fn sysname(&self) -> Option<&'a [u8]> {
        self.tlvs.iter().find_map(|t| match t {
            LldpTlv::SysName(n) => Some(*n),
            _ => None,
        })
    }

    pub fn sysdescr(&self) -> Option<&'a [u8]> {
        self.tlvs.iter().find_map(|t| match t {
            LldpTlv::SysDescr(n) => Some(*n),
            _ => None,
        })
    }

    /// The enabled-capability bits of the first Capabilities TLV, else 0.
    pub fn enabled(&self) -> u16 {
        self.tlvs
            .iter()
            .find_map(|t| match t {
                LldpTlv::Capabilities { enabled, .. } => Some(*enabled),
                _ => None,
            })
            .unwrap_or(0)
    }
}

fn problem(reason: &'static str, offset: usize, len: usize) -> Problem {
    Problem {
        layer: Layer::Lldp,
        reason,
        offset,
        len,
    }
}

const ORG_8021: [u8; 3] = [0x00, 0x80, 0xc2];

/// Decodes one TLV value; `None` when its length does not fit the type.
fn tlv(typ: u8, d: &[u8]) -> Option<LldpTlv<'_>> {
    Some(match typ {
        1 | 2 => {
            let (&subtype, id) = d.split_first()?;
            if id.is_empty() {
                return None;
            }
            if typ == 1 {
                LldpTlv::ChassisId { subtype, id }
            } else {
                LldpTlv::PortId { subtype, id }
            }
        }
        3 => LldpTlv::Ttl(u16::from_be_bytes(d.try_into().ok()?)),
        4 => LldpTlv::PortDescr(d),
        5 => LldpTlv::SysName(d),
        6 => LldpTlv::SysDescr(d),
        7 => {
            let [a, b, c, e] = <[u8; 4]>::try_from(d).ok()?;
            LldpTlv::Capabilities {
                system: u16::from_be_bytes([a, b]),
                enabled: u16::from_be_bytes([c, e]),
            }
        }
        8 => {
            let (&alen, rest) = d.split_first()?;
            let body = rest.get(..usize::from(alen))?;
            let (&subtype, addr) = body.split_first()?;
            LldpTlv::MgmtAddr { subtype, addr }
        }
        127 => {
            let (oui, rest) = d.split_at_checked(3)?;
            let oui: [u8; 3] = oui.try_into().ok()?;
            let (&subtype, data) = rest.split_first()?;
            match (oui, subtype, data) {
                (ORG_8021, 1, [a, b]) => LldpTlv::PortVlan(u16::from_be_bytes([*a, *b])),
                _ => LldpTlv::Org { oui, subtype, data },
            }
        }
        _ => LldpTlv::Other { typ, data: d },
    })
}

/// Parses an LLDP data unit from the cursor's position and consumes the rest
/// of the data. The first three TLVs must be chassis, port and TTL, else the
/// unit is rejected. An End TLV stops the parse; a TLV running past the data
/// stops it with what was read. A TLV whose length does not fit its type is
/// kept as `Other`. At most [`MAX_TLVS`] TLVs are kept.
pub fn parse<'a>(c: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Option<Lldp<'a>> {
    let mut r = *c;
    let mut tlvs = Vec::new();
    let mut found = Vec::new();
    let mut seen = 0usize;
    let mut in_order = true;
    let mut bad = 0usize;
    while !r.is_empty() {
        let at = r.pos();
        let Some(h) = r.be16() else {
            found.push(problem("truncated", at, 1));
            break;
        };
        let typ = (h >> 9) as u8;
        let len = usize::from(h & 0x1ff);
        if typ == 0 {
            break;
        }
        let Some(data) = r.take(len) else {
            found.push(problem("truncated", at, r.remaining().saturating_add(2)));
            break;
        };
        if tlvs.len() >= MAX_TLVS {
            found.push(problem(
                "too many TLVs",
                at,
                r.remaining().saturating_add(len).saturating_add(2),
            ));
            r.rest();
            break;
        }
        if seen < 3 && usize::from(typ) != seen.saturating_add(1) {
            in_order = false;
        }
        seen = seen.saturating_add(1);
        let t = tlv(typ, data).unwrap_or_else(|| {
            bad = bad.saturating_add(1);
            if bad <= MAX_BAD_TLVS {
                found.push(problem("bad TLV length", at, len.saturating_add(2)));
            }
            LldpTlv::Other { typ, data }
        });
        tlvs.push(t);
    }
    if seen < 3 || !in_order {
        let cut = found.iter().any(|p| p.reason == "truncated");
        problems.append(&mut found);
        if !cut {
            problems.push(problem("missing mandatory TLV", c.pos(), c.remaining()));
        }
        return None;
    }
    problems.append(&mut found);
    r.rest();
    *c = r;
    Some(Lldp { tlvs })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use overhear_testgen::{lldp as build, mac};

    fn run(b: &[u8]) -> (Option<Lldp<'_>>, Vec<Problem>) {
        let mut c = Cursor::new(b);
        let mut p = Vec::new();
        let r = parse(&mut c, &mut p);
        (r, p)
    }

    fn chassis() -> (u8, Vec<u8>) {
        let mut v = vec![4];
        v.extend_from_slice(&mac(1));
        (1, v)
    }

    fn port() -> (u8, Vec<u8>) {
        (2, [&[5u8][..], b"Gi1/0/24"].concat())
    }

    fn ttl() -> (u8, Vec<u8>) {
        (3, 120u16.to_be_bytes().to_vec())
    }

    fn mandatory() -> Vec<(u8, Vec<u8>)> {
        vec![chassis(), port(), ttl()]
    }

    #[test]
    fn lldp_mandatory_and_sysname() {
        let mut t = mandatory();
        t.push((4, b"uplink".to_vec()));
        t.push((5, b"core-sw1".to_vec()));
        t.push((6, b"Acme OS 1.0".to_vec()));
        t.push((7, vec![0, 0x14, 0, 0x14]));
        t.push((8, vec![5, 1, 192, 168, 1, 2, 1, 0, 0, 0, 1, 0]));
        t.push((0, vec![]));
        let b = build(&t);
        let (l, p) = run(&b);
        assert!(p.is_empty());
        let l = l.unwrap();
        assert_eq!(l.tlvs.len(), 8);
        assert_eq!(
            l.tlvs[0],
            LldpTlv::ChassisId {
                subtype: 4,
                id: &mac(1)
            }
        );
        assert_eq!(
            l.tlvs[1],
            LldpTlv::PortId {
                subtype: 5,
                id: b"Gi1/0/24"
            }
        );
        assert_eq!(l.tlvs[2], LldpTlv::Ttl(120));
        assert_eq!(l.tlvs[3], LldpTlv::PortDescr(b"uplink"));
        assert_eq!(l.tlvs[4], LldpTlv::SysName(b"core-sw1"));
        assert_eq!(l.tlvs[5], LldpTlv::SysDescr(b"Acme OS 1.0"));
        assert_eq!(
            l.tlvs[6],
            LldpTlv::Capabilities {
                system: 0x14,
                enabled: 0x14
            }
        );
        assert_eq!(
            l.tlvs[7],
            LldpTlv::MgmtAddr {
                subtype: 1,
                addr: &[192, 168, 1, 2]
            }
        );
    }

    #[test]
    fn lldp_port_vlan_org_tlv() {
        let mut t = mandatory();
        t.push((127, vec![0x00, 0x80, 0xc2, 1, 0, 10]));
        t.push((127, vec![0x00, 0x12, 0xbb, 1, 0xaa, 0xbb]));
        t.push((127, vec![0x00, 0x80, 0xc2, 1, 0]));
        t.push((9, vec![1, 2]));
        let b = build(&t);
        let (l, p) = run(&b);
        assert!(p.is_empty());
        let l = l.unwrap();
        assert_eq!(l.tlvs[3], LldpTlv::PortVlan(10));
        assert_eq!(
            l.tlvs[4],
            LldpTlv::Org {
                oui: [0, 0x12, 0xbb],
                subtype: 1,
                data: &[0xaa, 0xbb]
            }
        );
        assert_eq!(
            l.tlvs[5],
            LldpTlv::Org {
                oui: [0, 0x80, 0xc2],
                subtype: 1,
                data: &[0]
            }
        );
        assert_eq!(
            l.tlvs[6],
            LldpTlv::Other {
                typ: 9,
                data: &[1, 2]
            }
        );
    }

    #[test]
    fn lldp_tlv_beyond_data() {
        let mut t = mandatory();
        t.push((5, b"core-sw1".to_vec()));
        let b = build(&t);
        let cut = &b[..b.len() - 3];
        let (l, p) = run(cut);
        let l = l.unwrap();
        assert_eq!(l.tlvs.len(), 3);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].layer, p[0].reason), (Layer::Lldp, "truncated"));
        assert_eq!(p[0].offset, b.len() - 10);
        assert_eq!(p[0].len, 7);
    }

    #[test]
    fn lldp_missing_mandatory() {
        let b = build(&[(5, b"x".to_vec()), chassis(), port(), ttl()]);
        let (l, p) = run(&b);
        assert!(l.is_none());
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].layer, p[0].reason),
            (Layer::Lldp, "missing mandatory TLV")
        );
        let b = build(&[chassis(), port()]);
        let (l, p) = run(&b);
        assert!(l.is_none());
        assert_eq!(p[0].reason, "missing mandatory TLV");
        let (l, _) = run(&[]);
        assert!(l.is_none());
    }

    #[test]
    fn lldp_failure_leaves_cursor() {
        let b = build(&[(5, b"x".to_vec())]);
        let mut c = Cursor::new(&b);
        let mut p = Vec::new();
        assert!(parse(&mut c, &mut p).is_none());
        assert_eq!(c.pos(), 0);
    }

    #[test]
    fn lldp_end_stops() {
        let mut t = mandatory();
        t.push((0, vec![]));
        t.push((5, b"after".to_vec()));
        let b = build(&t);
        let mut c = Cursor::new(&b);
        let mut p = Vec::new();
        let l = parse(&mut c, &mut p).unwrap();
        assert_eq!(l.tlvs.len(), 3);
        assert!(p.is_empty());
        assert!(c.is_empty());
    }

    #[test]
    fn lldp_no_end_tlv_is_fine() {
        let b = build(&mandatory());
        let (l, p) = run(&b);
        assert_eq!(l.unwrap().tlvs.len(), 3);
        assert!(p.is_empty());
    }

    #[test]
    fn lldp_malformed_tlvs_are_other_with_capped_problems() {
        let mut t = mandatory();
        for _ in 0..500 {
            t.push((3, vec![1]));
        }
        let b = build(&t);
        let (l, p) = run(&b);
        let l = l.unwrap();
        assert_eq!(l.tlvs.len(), MAX_TLVS);
        assert!(matches!(l.tlvs[3], LldpTlv::Other { typ: 3, .. }));
        let bad = p.iter().filter(|p| p.reason == "bad TLV length").count();
        assert_eq!(bad, MAX_BAD_TLVS);
        assert_eq!(p.iter().filter(|p| p.reason == "too many TLVs").count(), 1);
        assert!(p.len() <= MAX_BAD_TLVS + 1);
    }

    #[test]
    fn lldp_odd_trailing_byte_is_truncated() {
        let mut b = build(&mandatory());
        b.push(0xfe);
        let (l, p) = run(&b);
        assert_eq!(l.unwrap().tlvs.len(), 3);
        assert_eq!(p[0].reason, "truncated");
    }
}
