use std::net::Ipv6Addr;

use crate::{Cursor, Layer, Mac, Problem};

/// A neighbour discovery option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdOpt<'a> {
    SourceLla(Mac),
    TargetLla(Mac),
    /// `flags`: L 0x80, A 0x40.
    Prefix {
        len: u8,
        flags: u8,
        valid: u32,
        preferred: u32,
        prefix: Ipv6Addr,
    },
    Mtu(u32),
    Rdnss {
        lifetime: u32,
        servers: &'a [u8],
    },
    Dnssl {
        lifetime: u32,
        names: &'a [u8],
    },
    RouteInfo {
        len: u8,
        pref: u8,
        lifetime: u32,
        prefix: Ipv6Addr,
    },
    Other {
        typ: u8,
        data: &'a [u8],
    },
}

/// An ICMPv6 neighbour discovery message (types 133 to 137).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nd<'a> {
    RouterSolicit {
        opts: Vec<NdOpt<'a>>,
    },
    /// `flags`: M 0x80, O 0x40.
    RouterAdvert {
        cur_hop_limit: u8,
        flags: u8,
        lifetime: u16,
        reachable: u32,
        retrans: u32,
        opts: Vec<NdOpt<'a>>,
    },
    NeighborSolicit {
        target: Ipv6Addr,
        opts: Vec<NdOpt<'a>>,
    },
    /// `flags`: R 0x80, S 0x40, O 0x20.
    NeighborAdvert {
        flags: u8,
        target: Ipv6Addr,
        opts: Vec<NdOpt<'a>>,
    },
    Redirect {
        target: Ipv6Addr,
        dest: Ipv6Addr,
        opts: Vec<NdOpt<'a>>,
    },
}

impl NdOpt<'_> {
    /// The addresses of an RDNSS option; empty for any other option.
    pub fn rdnss_servers(&self) -> impl Iterator<Item = Ipv6Addr> {
        let bytes: &[u8] = match self {
            NdOpt::Rdnss { servers, .. } => servers,
            _ => &[],
        };
        bytes.chunks_exact(16).filter_map(ip6)
    }
}

impl<'a> Nd<'a> {
    pub fn opts(&self) -> &[NdOpt<'a>] {
        match self {
            Nd::RouterSolicit { opts }
            | Nd::RouterAdvert { opts, .. }
            | Nd::NeighborSolicit { opts, .. }
            | Nd::NeighborAdvert { opts, .. }
            | Nd::Redirect { opts, .. } => opts,
        }
    }
}

fn ip6(b: &[u8]) -> Option<Ipv6Addr> {
    let a: [u8; 16] = b.try_into().ok()?;
    Some(Ipv6Addr::from(a))
}

fn word32(b: &[u8], at: usize) -> Option<u32> {
    let w: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(w))
}

fn problem(reason: &'static str, offset: usize, len: usize) -> Problem {
    Problem {
        layer: Layer::Nd,
        reason,
        offset,
        len,
    }
}

/// One option of `units` * 8 bytes whose body (after type and length) is `d`.
fn option<'a>(
    typ: u8,
    units: u8,
    d: &'a [u8],
    at: usize,
    problems: &mut Vec<Problem>,
) -> NdOpt<'a> {
    let other = NdOpt::Other { typ, data: d };
    let parsed = match (typ, units) {
        (1, 1) => Mac::from_slice(d).map(NdOpt::SourceLla),
        (2, 1) => Mac::from_slice(d).map(NdOpt::TargetLla),
        (3, 4) => (|| {
            Some(NdOpt::Prefix {
                len: *d.first()?,
                flags: *d.get(1)?,
                valid: word32(d, 2)?,
                preferred: word32(d, 6)?,
                prefix: ip6(d.get(14..30)?)?,
            })
        })(),
        (5, 1) => word32(d, 2).map(NdOpt::Mtu),
        (24, 1..=3) => (|| {
            let prefix = match d.get(6..) {
                Some(p) if p.len() >= 16 => ip6(p.get(..16)?)?,
                Some(p) => {
                    let mut a = [0u8; 16];
                    for (slot, x) in a.iter_mut().zip(p) {
                        *slot = *x;
                    }
                    Ipv6Addr::from(a)
                }
                None => return None,
            };
            Some(NdOpt::RouteInfo {
                len: *d.first()?,
                pref: (d.get(1)? >> 3) & 3,
                lifetime: word32(d, 2)?,
                prefix,
            })
        })(),
        (25, u) => {
            if u < 3 || u % 2 == 0 {
                problems.push(problem("bad RDNSS length", at, d.len().saturating_add(2)));
                None
            } else {
                word32(d, 2).and_then(|lifetime| {
                    Some(NdOpt::Rdnss {
                        lifetime,
                        servers: d.get(6..)?,
                    })
                })
            }
        }
        (31, 2..) => word32(d, 2).and_then(|lifetime| {
            Some(NdOpt::Dnssl {
                lifetime,
                names: d.get(6..)?,
            })
        }),
        _ => None,
    };
    parsed.unwrap_or(other)
}

fn options<'a>(r: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Vec<NdOpt<'a>> {
    let mut opts = Vec::new();
    while !r.is_empty() {
        let at = r.pos();
        let (Some(typ), Some(units)) = (r.u8(), r.u8()) else {
            problems.push(problem(
                "truncated option",
                at,
                r.remaining().saturating_add(1),
            ));
            break;
        };
        if units == 0 {
            problems.push(problem("zero-length option", at, 2));
            break;
        }
        let body = usize::from(units).saturating_mul(8).saturating_sub(2);
        let Some(d) = r.take(body) else {
            problems.push(problem(
                "truncated option",
                at,
                r.remaining().saturating_add(2),
            ));
            break;
        };
        opts.push(option(typ, units, d, at, problems));
    }
    r.rest();
    opts
}

/// Parses a neighbour discovery message of ICMPv6 type `typ` whose body starts
/// at the cursor (after the 4-byte ICMPv6 header). A hop limit other than 255
/// is a problem but decoding goes on.
pub fn parse<'a>(
    c: &mut Cursor<'a>,
    typ: u8,
    hop_limit: u8,
    problems: &mut Vec<Problem>,
) -> Option<Nd<'a>> {
    let start = c.pos();
    let mut r = *c;
    let fixed = match typ {
        133 => 4,
        134 => 12,
        135 | 136 => 20,
        137 => 36,
        _ => return None,
    };
    let Some(b) = r.take(fixed) else {
        problems.push(problem("truncated", start, c.remaining()));
        return None;
    };
    if hop_limit != 255 {
        problems.push(problem(
            "hop limit not 255 (invalid neighbour discovery)",
            start,
            0,
        ));
    }
    let msg = |opts| -> Option<Nd<'a>> {
        Some(match typ {
            133 => Nd::RouterSolicit { opts },
            134 => Nd::RouterAdvert {
                cur_hop_limit: *b.first()?,
                flags: *b.get(1)?,
                lifetime: u16::from_be_bytes(b.get(2..4)?.try_into().ok()?),
                reachable: word32(b, 4)?,
                retrans: word32(b, 8)?,
                opts,
            },
            135 => Nd::NeighborSolicit {
                target: ip6(b.get(4..20)?)?,
                opts,
            },
            136 => Nd::NeighborAdvert {
                flags: *b.first()?,
                target: ip6(b.get(4..20)?)?,
                opts,
            },
            _ => Nd::Redirect {
                target: ip6(b.get(4..20)?)?,
                dest: ip6(b.get(20..36)?)?,
                opts,
            },
        })
    };
    let opts = options(&mut r, problems);
    let nd = msg(opts)?;
    *c = r;
    Some(nd)
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use overhear_testgen::{
        mac, nd_na, nd_ns, nd_ra, nd_rs, opt_lla, opt_prefix, opt_rdnss, opt_route,
    };

    fn a6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// Parses a builder message (type byte first) with the given hop limit.
    fn run(m: &[u8], hop: u8) -> (Option<Nd<'_>>, Vec<Problem>) {
        let mut c = Cursor::new(m);
        c.skip(4).unwrap();
        let mut p = Vec::new();
        (parse(&mut c, m[0], hop, &mut p), p)
    }

    #[test]
    fn ra_with_prefix_and_rdnss() {
        let m = nd_ra(
            1800,
            0xc0,
            &[
                opt_lla(1, mac(1)),
                opt_prefix(a6("2001:db8:1::"), 64, 0xc0),
                opt_rdnss(&[a6("2001:db8::53"), a6("2001:db8::54")]),
                opt_route(a6("fd00:1::"), 48),
            ],
        );
        let (nd, p) = run(&m, 255);
        assert!(p.is_empty(), "{p:?}");
        let Some(Nd::RouterAdvert {
            cur_hop_limit,
            flags,
            lifetime,
            opts,
            ..
        }) = nd
        else {
            panic!("not an RA")
        };
        assert_eq!((cur_hop_limit, flags, lifetime), (64, 0xc0, 1800));
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0], NdOpt::SourceLla(Mac(mac(1))));
        assert_eq!(
            opts[1],
            NdOpt::Prefix {
                len: 64,
                flags: 0xc0,
                valid: 2_592_000,
                preferred: 604_800,
                prefix: a6("2001:db8:1::")
            }
        );
        let servers: Vec<_> = opts[2].rdnss_servers().collect();
        assert_eq!(servers, vec![a6("2001:db8::53"), a6("2001:db8::54")]);
        assert_eq!(opts[0].rdnss_servers().count(), 0);
        assert_eq!(
            opts[3],
            NdOpt::RouteInfo {
                len: 48,
                pref: 0,
                lifetime: 1800,
                prefix: a6("fd00:1::")
            }
        );
    }

    #[test]
    fn hop_limit_64_flagged() {
        let m = nd_ns(a6("2001:db8::1"), &[]);
        let (nd, p) = run(&m, 64);
        assert!(matches!(nd, Some(Nd::NeighborSolicit { .. })));
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].layer, p[0].reason),
            (Layer::Nd, "hop limit not 255 (invalid neighbour discovery)")
        );
        assert!(run(&m, 255).1.is_empty());
    }

    #[test]
    fn zero_length_option_stops() {
        let mut m = nd_rs(&[opt_lla(1, mac(1))]);
        m.extend_from_slice(&[7, 0, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(&opt_lla(1, mac(2)));
        let (nd, p) = run(&m, 255);
        let Some(Nd::RouterSolicit { opts }) = nd else {
            panic!("not an RS")
        };
        assert_eq!(opts, vec![NdOpt::SourceLla(Mac(mac(1)))]);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].reason, "zero-length option");
        assert_eq!(p[0].offset, 4 + 4 + 8);
    }

    #[test]
    fn rdnss_bad_length() {
        // Length 2 units (16 bytes): not 1 + 2n.
        let mut o = vec![25, 2, 0, 0];
        o.extend_from_slice(&600u32.to_be_bytes());
        o.extend_from_slice(&[0; 8]);
        let m = nd_ra(0, 0, &[o]);
        let (nd, p) = run(&m, 255);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].reason, "bad RDNSS length");
        let Some(Nd::RouterAdvert { opts, .. }) = nd else {
            panic!("not an RA")
        };
        assert!(matches!(opts[0], NdOpt::Other { typ: 25, .. }));
        assert_eq!(opts[0].rdnss_servers().count(), 0);
    }

    #[test]
    fn na_flags_and_target() {
        let m = nd_na(0xa0, a6("2001:db8:1::50"), &[opt_lla(2, mac(4))]);
        let (nd, p) = run(&m, 255);
        assert!(p.is_empty());
        assert_eq!(
            nd,
            Some(Nd::NeighborAdvert {
                flags: 0xa0,
                target: a6("2001:db8:1::50"),
                opts: vec![NdOpt::TargetLla(Mac(mac(4)))]
            })
        );
    }

    #[test]
    fn truncated_and_unknown() {
        let m = nd_na(0, a6("::1"), &[]);
        let mut c = Cursor::new(&m[..12]);
        c.skip(4).unwrap();
        let mut p = Vec::new();
        assert!(parse(&mut c, 136, 255, &mut p).is_none());
        assert_eq!(p[0].reason, "truncated");
        assert_eq!(c.pos(), 4);
        assert!(parse(&mut c, 200, 255, &mut p).is_none());
    }

    #[test]
    fn truncated_option_keeps_earlier_ones() {
        let mut m = nd_rs(&[opt_lla(1, mac(1))]);
        m.extend_from_slice(&[1, 2, 0, 0]);
        let (nd, p) = run(&m, 255);
        assert_eq!(nd.unwrap().opts().len(), 1);
        assert_eq!(p[0].reason, "truncated option");
    }
}
