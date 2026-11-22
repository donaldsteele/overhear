//! CDP (Cisco Discovery Protocol) decoder.

use std::net::IpAddr;

use crate::{Cursor, Layer, Problem};

/// The most TLVs kept; the rest of the data unit is ignored.
pub const MAX_TLVS: usize = 64;
/// The most TLV problems reported per message.
pub const MAX_BAD_TLVS: usize = 8;
/// The most addresses kept per Addresses TLV.
pub const MAX_ADDRS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdpTlv<'a> {
    DeviceId(&'a [u8]),
    Addresses(Vec<IpAddr>),
    PortId(&'a [u8]),
    Capabilities(u32),
    Software(&'a [u8]),
    Platform(&'a [u8]),
    NativeVlan(u16),
    Duplex(u8),
    VtpDomain(&'a [u8]),
    Other { typ: u16, data: &'a [u8] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cdp<'a> {
    pub version: u8,
    pub ttl: u8,
    pub tlvs: Vec<CdpTlv<'a>>,
}

fn problem(reason: &'static str, offset: usize, len: usize) -> Problem {
    Problem {
        layer: Layer::Cdp,
        reason,
        offset,
        len,
    }
}

const V6_PROTO: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0xdd];

/// Reads the Addresses TLV value. The count comes from the wire and is never
/// used to size anything: entries are read until the data or the count runs
/// out, and `false` is returned when the data ran out first.
fn addresses(body: &[u8]) -> Option<(Vec<IpAddr>, bool)> {
    let mut r = Cursor::new(body);
    let count = r.be32()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let entry = (|| {
            let ptype = r.u8()?;
            let plen = r.u8()?;
            let proto = r.take(usize::from(plen))?;
            let alen = r.be16()?;
            let addr = r.take(usize::from(alen))?;
            Some((ptype, proto, addr))
        })();
        let Some((ptype, proto, addr)) = entry else {
            return Some((out, false));
        };
        let ip = match (ptype, proto, addr) {
            (1, [0xcc], a) => <[u8; 4]>::try_from(a).ok().map(IpAddr::from),
            (2, p, a) if p == V6_PROTO => <[u8; 16]>::try_from(a).ok().map(IpAddr::from),
            _ => None,
        };
        if let Some(ip) = ip.filter(|_| out.len() < MAX_ADDRS) {
            out.push(ip);
        }
    }
    Some((out, true))
}

/// Parses a CDP data unit (after the SNAP header) and consumes the rest of
/// the data. A TLV shorter than its header, or running past the data, stops
/// the parse with what was read. A TLV whose length does not fit its type is
/// kept as `Other`. At most [`MAX_TLVS`] TLVs are kept.
pub fn parse<'a>(c: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Option<Cdp<'a>> {
    let mut r = *c;
    let (Some(version), Some(ttl), Some(_checksum)) = (r.u8(), r.u8(), r.be16()) else {
        problems.push(problem("truncated", c.pos(), c.remaining()));
        return None;
    };
    let mut tlvs = Vec::new();
    let mut bad = 0usize;
    let mut report = |problems: &mut Vec<Problem>, reason, offset, len| {
        bad = bad.saturating_add(1);
        if bad <= MAX_BAD_TLVS {
            problems.push(problem(reason, offset, len));
        }
    };
    while !r.is_empty() {
        let at = r.pos();
        let (Some(typ), Some(len)) = (r.be16(), r.be16()) else {
            report(problems, "truncated", at, r.remaining().saturating_add(4));
            break;
        };
        let len = usize::from(len);
        if len < 4 {
            report(problems, "bad TLV length", at, 4);
            break;
        }
        let Some(data) = r.take(len.saturating_sub(4)) else {
            report(problems, "truncated", at, r.remaining().saturating_add(4));
            break;
        };
        if tlvs.len() >= MAX_TLVS {
            report(problems, "too many TLVs", at, len);
            break;
        }
        let t = match (typ, data) {
            (1, d) => CdpTlv::DeviceId(d),
            (2, d) => match addresses(d) {
                Some((a, complete)) => {
                    if !complete {
                        report(problems, "truncated", at, len);
                    }
                    CdpTlv::Addresses(a)
                }
                None => {
                    report(problems, "bad TLV length", at, len);
                    CdpTlv::Other { typ, data }
                }
            },
            (3, d) => CdpTlv::PortId(d),
            (4, d) => match <[u8; 4]>::try_from(d) {
                Ok(b) => CdpTlv::Capabilities(u32::from_be_bytes(b)),
                Err(_) => {
                    report(problems, "bad TLV length", at, len);
                    CdpTlv::Other { typ, data }
                }
            },
            (5, d) => CdpTlv::Software(d),
            (6, d) => CdpTlv::Platform(d),
            (9, d) => CdpTlv::VtpDomain(d),
            (0x0a, d) => match <[u8; 2]>::try_from(d) {
                Ok(b) => CdpTlv::NativeVlan(u16::from_be_bytes(b)),
                Err(_) => {
                    report(problems, "bad TLV length", at, len);
                    CdpTlv::Other { typ, data }
                }
            },
            (0x0b, [d]) => CdpTlv::Duplex(*d),
            (0x0b, _) => {
                report(problems, "bad TLV length", at, len);
                CdpTlv::Other { typ, data }
            }
            _ => CdpTlv::Other { typ, data },
        };
        tlvs.push(t);
    }
    r.rest();
    *c = r;
    Some(Cdp { version, ttl, tlvs })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use overhear_testgen::cdp as build;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn run(b: &[u8]) -> (Option<Cdp<'_>>, Vec<Problem>) {
        let mut c = Cursor::new(b);
        let mut p = Vec::new();
        let r = parse(&mut c, &mut p);
        (r, p)
    }

    fn v6_addr() -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
    }

    fn addresses() -> Vec<u8> {
        let mut v = 2u32.to_be_bytes().to_vec();
        v.extend_from_slice(&[1, 1, 0xcc, 0, 4, 10, 0, 0, 2]);
        v.extend_from_slice(&[2, 8, 0xaa, 0xaa, 3, 0, 0, 0, 0x86, 0xdd, 0, 16]);
        v.extend_from_slice(&v6_addr().octets());
        v
    }

    #[test]
    fn cdp_addresses_v4_v6() {
        let b = build(&[
            (1, b"sw1".to_vec()),
            (2, addresses()),
            (3, b"GigabitEthernet1/0/1".to_vec()),
            (4, 0x28u32.to_be_bytes().to_vec()),
            (5, b"IOS 15.2".to_vec()),
            (6, b"cisco WS-C2960".to_vec()),
            (9, b"corp".to_vec()),
            (0x0a, 10u16.to_be_bytes().to_vec()),
            (0x0b, vec![1]),
            (0x1f, vec![7]),
        ]);
        let (c, p) = run(&b);
        assert!(p.is_empty());
        let c = c.unwrap();
        assert_eq!((c.version, c.ttl), (2, 180));
        assert_eq!(c.tlvs.len(), 10);
        assert_eq!(c.tlvs[0], CdpTlv::DeviceId(b"sw1"));
        assert_eq!(
            c.tlvs[1],
            CdpTlv::Addresses(vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V6(v6_addr())
            ])
        );
        assert_eq!(c.tlvs[2], CdpTlv::PortId(b"GigabitEthernet1/0/1"));
        assert_eq!(c.tlvs[3], CdpTlv::Capabilities(0x28));
        assert_eq!(c.tlvs[4], CdpTlv::Software(b"IOS 15.2"));
        assert_eq!(c.tlvs[5], CdpTlv::Platform(b"cisco WS-C2960"));
        assert_eq!(c.tlvs[6], CdpTlv::VtpDomain(b"corp"));
        assert_eq!(c.tlvs[7], CdpTlv::NativeVlan(10));
        assert_eq!(c.tlvs[8], CdpTlv::Duplex(1));
        assert_eq!(
            c.tlvs[9],
            CdpTlv::Other {
                typ: 0x1f,
                data: &[7]
            }
        );
    }

    #[test]
    fn cdp_tlv_len_2() {
        let mut b = build(&[(1, b"sw1".to_vec())]);
        b.extend_from_slice(&[0, 3, 0, 2, 9, 9, 9]);
        let (c, p) = run(&b);
        let c = c.unwrap();
        assert_eq!(c.tlvs, vec![CdpTlv::DeviceId(b"sw1")]);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].layer, p[0].reason), (Layer::Cdp, "bad TLV length"));
        assert_eq!(p[0].offset, 11);
    }

    #[test]
    fn cdp_count_too_large() {
        let mut v = u32::MAX.to_be_bytes().to_vec();
        v.extend_from_slice(&[1, 1, 0xcc, 0, 4, 10, 0, 0, 2]);
        let b = build(&[(1, b"sw1".to_vec()), (2, v)]);
        let (c, p) = run(&b);
        let c = c.unwrap();
        assert_eq!(
            c.tlvs[1],
            CdpTlv::Addresses(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))])
        );
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].layer, p[0].reason), (Layer::Cdp, "truncated"));
    }

    #[test]
    fn cdp_tlv_beyond_data() {
        let b = build(&[(1, b"switch".to_vec())]);
        let (c, p) = run(&b[..b.len() - 2]);
        assert!(c.unwrap().tlvs.is_empty());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].reason, "truncated");
    }

    #[test]
    fn cdp_header_truncated_leaves_cursor() {
        let mut c = Cursor::new(&[2, 180, 0]);
        let mut p = Vec::new();
        assert!(parse(&mut c, &mut p).is_none());
        assert_eq!(c.pos(), 0);
        assert_eq!(p[0].reason, "truncated");
    }

    #[test]
    fn cdp_wrong_size_values_are_other() {
        let b = build(&[
            (4, vec![1, 2]),
            (0x0a, vec![1]),
            (0x0b, vec![]),
            (2, vec![0]),
        ]);
        let (c, p) = run(&b);
        let c = c.unwrap();
        assert!(c.tlvs.iter().all(|t| matches!(t, CdpTlv::Other { .. })));
        assert_eq!(c.tlvs.len(), 4);
        assert!(p.iter().all(|p| p.reason == "bad TLV length"));
    }

    #[test]
    fn cdp_many_bad_tlvs_cap_problems() {
        let t: Vec<(u16, Vec<u8>)> = (0..500).map(|_| (4, vec![1])).collect();
        let b = build(&t);
        let (c, p) = run(&b);
        assert_eq!(c.unwrap().tlvs.len(), MAX_TLVS);
        assert!(p.len() <= MAX_BAD_TLVS + 1);
    }

    #[test]
    fn cdp_unknown_address_protocols_are_skipped() {
        let mut v = 2u32.to_be_bytes().to_vec();
        v.extend_from_slice(&[1, 1, 0x81, 0, 2, 1, 2]);
        v.extend_from_slice(&[1, 1, 0xcc, 0, 4, 10, 0, 0, 3]);
        let b = build(&[(2, v)]);
        let (c, p) = run(&b);
        assert!(p.is_empty());
        assert_eq!(
            c.unwrap().tlvs[0],
            CdpTlv::Addresses(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))])
        );
    }
}
