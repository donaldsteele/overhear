//! IPv6 neighbour discovery presentation and observations.

use std::fmt::Write;
use std::net::{IpAddr, Ipv6Addr};

use overhear_decode::{IpHeader, Mac, Nd, NdOpt, Packet};

use crate::escape::{TextKind, push_text};
use crate::json::JsonWriter;
use crate::observe::{Observation, ProtoTag, Role};

const FLAG_M: u8 = 0x80;
const FLAG_O: u8 = 0x40;
const NA_ROUTER: u8 = 0x80;
const NA_SOLICITED: u8 = 0x40;
const NA_OVERRIDE: u8 = 0x20;
const PREFIX_L: u8 = 0x80;
const PREFIX_A: u8 = 0x40;

pub fn tag() -> &'static str {
    "ND"
}

/// The IPv6 source address of the packet.
fn ip_src(p: &Packet<'_>) -> Option<Ipv6Addr> {
    match p.ip {
        Some(IpHeader::V6(h)) => Some(h.src),
        _ => None,
    }
}

fn target_lla(opts: &[NdOpt<'_>]) -> Option<Mac> {
    opts.iter().find_map(|o| match o {
        NdOpt::TargetLla(m) => Some(*m),
        _ => None,
    })
}

fn first_dns(opts: &[NdOpt<'_>]) -> Option<Ipv6Addr> {
    opts.iter().find_map(|o| o.rdnss_servers().next())
}

pub fn summary(p: &Packet<'_>, nd: &Nd<'_>, out: &mut String) {
    let _ = match nd {
        Nd::RouterSolicit { .. } => write!(out, "router solicitation"),
        Nd::RouterAdvert {
            flags,
            lifetime,
            opts,
            ..
        } => {
            if *lifetime == 0 {
                out.push_str("router advert lifetime 0 (not a default router)");
            } else {
                let _ = write!(out, "router advert lifetime {lifetime}s");
            }
            if flags & FLAG_M != 0 {
                out.push_str(" M");
            }
            if flags & FLAG_O != 0 {
                out.push_str(" O");
            }
            let prefixes = opts.iter().filter_map(|o| match o {
                NdOpt::Prefix { len, prefix, .. } => Some((prefix, len)),
                _ => None,
            });
            let mut n = 0usize;
            for (prefix, len) in prefixes {
                n = n.saturating_add(1);
                if n <= 2 {
                    let _ = write!(out, " prefix {prefix}/{len}");
                }
            }
            if n > 2 {
                let _ = write!(out, " (+{} prefixes)", n.saturating_sub(2));
            }
            if let Some(dns) = first_dns(opts) {
                let _ = write!(out, " dns {dns}");
            }
            Ok(())
        }
        Nd::NeighborSolicit { target, .. } => {
            if ip_src(p).is_some_and(|s| s.is_unspecified()) {
                write!(out, "duplicate address check for {target}")
            } else {
                write!(out, "neighbour solicitation for {target}")
            }
        }
        Nd::NeighborAdvert {
            flags,
            target,
            opts,
        } => {
            let at = target_lla(opts).unwrap_or(p.eth.src);
            let _ = write!(out, "{target} is-at {at}");
            if flags & NA_ROUTER != 0 {
                out.push_str(" [router]");
            }
            if flags & NA_SOLICITED == 0 {
                out.push_str(" (unsolicited)");
            }
            Ok(())
        }
        Nd::Redirect { target, dest, .. } => write!(out, "redirect {dest} via {target}"),
    };
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn pref_text(pref: u8) -> &'static str {
    match pref {
        1 => "high",
        0 => "medium",
        3 => "low",
        _ => "reserved",
    }
}

/// The names of a DNSSL option: sequences of length-prefixed labels, each name
/// ended by a zero label, joined with dots.
fn dnssl_names(b: &[u8]) -> Vec<Vec<u8>> {
    let mut names = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut rest = b;
    while let [len, tail @ ..] = rest {
        let n = usize::from(*len);
        if n == 0 {
            if !cur.is_empty() {
                names.push(std::mem::take(&mut cur));
            }
            rest = tail;
            continue;
        }
        let Some(label) = tail.get(..n) else { break };
        if !cur.is_empty() {
            cur.push(b'.');
        }
        cur.extend_from_slice(label);
        rest = tail.get(n..).unwrap_or(&[]);
    }
    if !cur.is_empty() {
        names.push(cur);
    }
    names
}

fn flag_text(flags: u8, bits: &[(u8, &str)]) -> String {
    let set: Vec<&str> = bits
        .iter()
        .filter(|(b, _)| flags & b != 0)
        .map(|(_, n)| *n)
        .collect();
    if set.is_empty() {
        "-".to_string()
    } else {
        set.join(" ")
    }
}

fn opt_line(o: &NdOpt<'_>, out: &mut String) {
    out.push_str("        ");
    let _ = match o {
        NdOpt::SourceLla(m) => write!(out, "source-lla {m}"),
        NdOpt::TargetLla(m) => write!(out, "target-lla {m}"),
        NdOpt::Prefix {
            len,
            flags,
            valid,
            preferred,
            prefix,
        } => write!(
            out,
            "prefix {prefix}/{len} flags {} valid {valid}s preferred {preferred}s",
            flag_text(*flags, &[(PREFIX_L, "L"), (PREFIX_A, "A")])
        ),
        NdOpt::Mtu(m) => write!(out, "mtu {m}"),
        NdOpt::Rdnss { lifetime, .. } => {
            let servers: Vec<String> = o.rdnss_servers().map(|a| a.to_string()).collect();
            write!(out, "rdnss lifetime {lifetime}s {}", servers.join(", "))
        }
        NdOpt::Dnssl { lifetime, names } => {
            let _ = write!(out, "dnssl lifetime {lifetime}s");
            for (i, n) in dnssl_names(names).iter().enumerate() {
                out.push_str(if i == 0 { " \"" } else { ", \"" });
                push_text(out, n, TextKind::Utf8, usize::MAX);
                out.push('"');
            }
            Ok(())
        }
        NdOpt::RouteInfo {
            len,
            pref,
            lifetime,
            prefix,
        } => write!(
            out,
            "route {prefix}/{len} pref {} lifetime {lifetime}s",
            pref_text(*pref)
        ),
        NdOpt::Other { typ, data } => write!(out, "option {typ} {}", hex(data)),
    };
    out.push('\n');
}

pub fn verbose(p: &Packet<'_>, nd: &Nd<'_>, out: &mut String) {
    out.push_str("  ND    ");
    let _ = match nd {
        Nd::RouterSolicit { .. } => write!(out, "router solicitation"),
        Nd::RouterAdvert {
            cur_hop_limit,
            flags,
            lifetime,
            reachable,
            retrans,
            ..
        } => write!(
            out,
            "router advert hop-limit {cur_hop_limit} flags {} lifetime {lifetime}s reachable {reachable}ms retrans {retrans}ms",
            flag_text(*flags & 0xc0, &[(FLAG_M, "M"), (FLAG_O, "O")])
        ),
        Nd::NeighborSolicit { target, .. } => write!(out, "neighbour solicitation target {target}"),
        Nd::NeighborAdvert { flags, target, .. } => write!(
            out,
            "neighbour advert target {target} flags {}",
            flag_text(
                *flags,
                &[(NA_ROUTER, "R"), (NA_SOLICITED, "S"), (NA_OVERRIDE, "O")]
            )
        ),
        Nd::Redirect { target, dest, .. } => {
            write!(out, "redirect destination {dest} via {target}")
        }
    };
    out.push('\n');
    let _ = p;
    for o in nd.opts() {
        opt_line(o, out);
    }
}

fn json_opt(o: &NdOpt<'_>, w: &mut JsonWriter) {
    w.obj(None);
    match o {
        NdOpt::SourceLla(m) => {
            w.str(Some("type"), "source_lla");
            w.mac(Some("mac"), *m);
        }
        NdOpt::TargetLla(m) => {
            w.str(Some("type"), "target_lla");
            w.mac(Some("mac"), *m);
        }
        NdOpt::Prefix {
            len,
            flags,
            valid,
            preferred,
            prefix,
        } => {
            w.str(Some("type"), "prefix");
            w.ip(Some("prefix"), IpAddr::V6(*prefix));
            w.u64(Some("len"), u64::from(*len));
            w.bool(Some("on_link"), flags & PREFIX_L != 0);
            w.bool(Some("autonomous"), flags & PREFIX_A != 0);
            w.u64(Some("valid"), u64::from(*valid));
            w.u64(Some("preferred"), u64::from(*preferred));
        }
        NdOpt::Mtu(m) => {
            w.str(Some("type"), "mtu");
            w.u64(Some("mtu"), u64::from(*m));
        }
        NdOpt::Rdnss { lifetime, .. } => {
            w.str(Some("type"), "rdnss");
            w.u64(Some("lifetime"), u64::from(*lifetime));
            w.arr(Some("servers"));
            for a in o.rdnss_servers() {
                w.ip(None, IpAddr::V6(a));
            }
            w.end();
        }
        NdOpt::Dnssl { lifetime, names } => {
            w.str(Some("type"), "dnssl");
            w.u64(Some("lifetime"), u64::from(*lifetime));
            w.arr(Some("names"));
            for n in dnssl_names(names) {
                w.text_elem(&n, TextKind::Utf8);
            }
            w.end();
        }
        NdOpt::RouteInfo {
            len,
            pref,
            lifetime,
            prefix,
        } => {
            w.str(Some("type"), "route");
            w.ip(Some("prefix"), IpAddr::V6(*prefix));
            w.u64(Some("len"), u64::from(*len));
            w.str(Some("pref"), pref_text(*pref));
            w.u64(Some("lifetime"), u64::from(*lifetime));
        }
        NdOpt::Other { typ, data } => {
            w.str(Some("type"), "other");
            w.u64(Some("code"), u64::from(*typ));
            w.hex(Some("hex"), data);
        }
    }
    w.end();
}

pub fn json(_p: &Packet<'_>, nd: &Nd<'_>, w: &mut JsonWriter) {
    w.obj(Some("nd"));
    match nd {
        Nd::RouterSolicit { .. } => w.str(Some("type"), "rs"),
        Nd::RouterAdvert {
            cur_hop_limit,
            flags,
            lifetime,
            reachable,
            retrans,
            ..
        } => {
            w.str(Some("type"), "ra");
            w.u64(Some("cur_hop_limit"), u64::from(*cur_hop_limit));
            w.u64(Some("flags"), u64::from(*flags));
            w.bool(Some("managed"), flags & FLAG_M != 0);
            w.bool(Some("other"), flags & FLAG_O != 0);
            w.u64(Some("lifetime"), u64::from(*lifetime));
            w.u64(Some("reachable"), u64::from(*reachable));
            w.u64(Some("retrans"), u64::from(*retrans));
        }
        Nd::NeighborSolicit { target, .. } => {
            w.str(Some("type"), "ns");
            w.ip(Some("target"), IpAddr::V6(*target));
        }
        Nd::NeighborAdvert { flags, target, .. } => {
            w.str(Some("type"), "na");
            w.u64(Some("flags"), u64::from(*flags));
            w.bool(Some("router"), flags & NA_ROUTER != 0);
            w.bool(Some("solicited"), flags & NA_SOLICITED != 0);
            w.bool(Some("override"), flags & NA_OVERRIDE != 0);
            w.ip(Some("target"), IpAddr::V6(*target));
        }
        Nd::Redirect { target, dest, .. } => {
            w.str(Some("type"), "redirect");
            w.ip(Some("target"), IpAddr::V6(*target));
            w.ip(Some("dest"), IpAddr::V6(*dest));
        }
    }
    w.arr(Some("options"));
    for o in nd.opts() {
        json_opt(o, w);
    }
    w.end();
    w.end();
}

/// Unique-local (fc00::/7) or link-local (fe80::/10).
fn local_prefix(a: &Ipv6Addr) -> bool {
    let first = a.segments().first().copied().unwrap_or(0);
    first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
}

fn global_prefix(opts: &[NdOpt<'_>]) -> bool {
    opts.iter().any(|o| {
        matches!(o, NdOpt::Prefix { flags, prefix, .. }
            if flags & PREFIX_A != 0 && !local_prefix(prefix))
    })
}

/// The frame source was heard. Link-layer address options bind a MAC to the
/// sender (or, in a neighbour advert or a redirect's target option, to the
/// target); a neighbour advert claims its target; a router advert reports the
/// router.
pub fn observe<'a>(p: &Packet<'a>, nd: &Nd<'a>, out: &mut Vec<Observation<'a>>) {
    out.push(Observation::Heard {
        mac: p.eth.src,
        proto: ProtoTag::Nd,
    });
    // RFC 4861: a hop limit other than 255 means the packet may be off-link
    // and is ignored; it is shown but teaches nothing.
    if matches!(p.ip, Some(IpHeader::V6(h)) if h.hop_limit != 255) {
        return;
    }
    let src = ip_src(p).filter(|s| !s.is_unspecified());
    for o in nd.opts() {
        let (mac, owner) = match (o, nd) {
            (NdOpt::SourceLla(m) | NdOpt::TargetLla(m), Nd::NeighborAdvert { target, .. })
            | (NdOpt::TargetLla(m), Nd::Redirect { target, .. }) => (*m, Some(*target)),
            (NdOpt::SourceLla(m) | NdOpt::TargetLla(m), _) => (*m, src),
            _ => continue,
        };
        if let Some(ip) = owner.filter(|a| !a.is_unspecified()) {
            out.push(Observation::Address {
                mac,
                ip: IpAddr::V6(ip),
            });
        }
    }
    match nd {
        Nd::NeighborAdvert { target, opts, .. } if !target.is_unspecified() => {
            out.push(Observation::Claim {
                mac: target_lla(opts).unwrap_or(p.eth.src),
                ip: IpAddr::V6(*target),
            });
        }
        Nd::RouterAdvert { lifetime, opts, .. } => {
            if let Some(src) = src {
                out.push(Observation::RouterAdvert {
                    mac: p.eth.src,
                    src,
                    lifetime: *lifetime,
                    dns: opts
                        .iter()
                        .any(|o| matches!(o, NdOpt::Rdnss { .. } | NdOpt::Dnssl { .. })),
                    global_prefix: global_prefix(opts),
                });
            }
            out.push(Observation::Role {
                mac: p.eth.src,
                role: if *lifetime > 0 {
                    Role::Router
                } else {
                    Role::RouterNoDefault
                },
            });
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overhear_decode::{Proto, decode};
    use overhear_testgen::{
        eth_ipv6, ipv6_icmp, mac, nd_na, nd_ns, nd_ra, nd_rs, opt_lla, opt_prefix, opt_rdnss,
        opt_route,
    };

    fn a6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn ll(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n)
    }

    /// Runs `f` on the ND packet `icmp` sent from `mac(src)` / `src_ip`.
    fn with<R>(
        icmp: &[u8],
        src: u8,
        src_ip: Ipv6Addr,
        hop: u8,
        f: impl FnOnce(&Packet<'_>, &Nd<'_>) -> R,
    ) -> R {
        let ip = ipv6_icmp(src_ip, a6("ff02::1"), hop, icmp);
        let frame = eth_ipv6([0x33, 0x33, 0, 0, 0, 1], mac(src), &ip);
        let p = decode(&frame).unwrap();
        let Proto::Nd(nd) = &p.proto else {
            panic!("not nd")
        };
        f(&p, nd)
    }

    fn line(icmp: &[u8], src: u8, src_ip: Ipv6Addr) -> String {
        with(icmp, src, src_ip, 255, |p, nd| {
            let mut s = String::new();
            summary(p, nd, &mut s);
            s
        })
    }

    fn obs(icmp: &[u8], src: u8, src_ip: Ipv6Addr) -> Vec<Observation<'static>> {
        with(icmp, src, src_ip, 255, |p, nd| {
            let mut o = Vec::new();
            observe(p, nd, &mut o);
            o.into_iter().map(own).collect()
        })
    }

    /// The observations used here borrow nothing; copy them out of the frame.
    fn own(o: Observation<'_>) -> Observation<'static> {
        match o {
            Observation::Heard { mac, proto } => Observation::Heard { mac, proto },
            Observation::Address { mac, ip } => Observation::Address { mac, ip },
            Observation::Claim { mac, ip } => Observation::Claim { mac, ip },
            Observation::Role { mac, role } => Observation::Role { mac, role },
            Observation::RouterAdvert {
                mac,
                src,
                lifetime,
                dns,
                global_prefix,
            } => Observation::RouterAdvert {
                mac,
                src,
                lifetime,
                dns,
                global_prefix,
            },
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn exact_summaries() {
        assert_eq!(line(&nd_rs(&[]), 2, ll(2)), "router solicitation");
        let ra = nd_ra(
            1800,
            0xc0,
            &[
                opt_prefix(a6("2001:db8:1::"), 64, 0xc0),
                opt_rdnss(&[a6("2001:db8::53")]),
            ],
        );
        assert_eq!(
            line(&ra, 1, ll(1)),
            "router advert lifetime 1800s M O prefix 2001:db8:1::/64 dns 2001:db8::53"
        );
        let ra0 = nd_ra(0, 0, &[]);
        assert_eq!(
            line(&ra0, 2, ll(2)),
            "router advert lifetime 0 (not a default router)"
        );
        let three = nd_ra(
            600,
            0,
            &[
                opt_prefix(a6("2001:db8:1::"), 64, 0x40),
                opt_prefix(a6("2001:db8:2::"), 64, 0x40),
                opt_prefix(a6("2001:db8:3::"), 64, 0x40),
                opt_prefix(a6("2001:db8:4::"), 64, 0x40),
            ],
        );
        assert_eq!(
            line(&three, 1, ll(1)),
            "router advert lifetime 600s prefix 2001:db8:1::/64 prefix 2001:db8:2::/64 (+2 prefixes)"
        );
        assert_eq!(
            line(&nd_ns(a6("2001:db8:1::50"), &[]), 4, a6("::")),
            "duplicate address check for 2001:db8:1::50"
        );
        assert_eq!(
            line(&nd_ns(a6("fe80::1"), &[]), 4, ll(4)),
            "neighbour solicitation for fe80::1"
        );
        let t = a6("2001:db8:1::50");
        assert_eq!(
            line(&nd_na(0xe0, t, &[opt_lla(2, mac(4))]), 4, ll(4)),
            "2001:db8:1::50 is-at 02:00:5e:10:00:04 [router]"
        );
        assert_eq!(
            line(&nd_na(0x20, t, &[]), 5, ll(5)),
            "2001:db8:1::50 is-at 02:00:5e:10:00:05 (unsolicited)"
        );
    }

    #[test]
    fn redirect_summary() {
        let mut m = vec![137, 0, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&ll(1).octets());
        m.extend_from_slice(&a6("2001:db8:9::1").octets());
        assert_eq!(line(&m, 2, ll(2)), "redirect 2001:db8:9::1 via fe80::1");
    }

    #[test]
    fn ra_global_prefix_flag() {
        let ra = |opts: &[Vec<u8>]| {
            obs(&nd_ra(1800, 0, opts), 1, ll(1))
                .into_iter()
                .find_map(|o| match o {
                    Observation::RouterAdvert { global_prefix, .. } => Some(global_prefix),
                    _ => None,
                })
                .unwrap()
        };
        assert!(!ra(&[opt_prefix(a6("fd00:1::"), 64, 0x40)]));
        assert!(!ra(&[opt_prefix(a6("fe80::"), 64, 0x40)]));
        assert!(!ra(&[opt_prefix(a6("2001:db8::"), 64, 0x80)]));
        assert!(ra(&[opt_prefix(a6("2001:db8::"), 64, 0x40)]));
        assert!(!ra(&[]));
    }

    #[test]
    fn ra_observations() {
        let m = Mac(mac(1));
        let o = obs(
            &nd_ra(
                1800,
                0,
                &[opt_lla(1, mac(1)), opt_rdnss(&[a6("2001:db8::53")])],
            ),
            1,
            ll(1),
        );
        assert_eq!(
            o,
            vec![
                Observation::Heard {
                    mac: m,
                    proto: ProtoTag::Nd
                },
                Observation::Address {
                    mac: m,
                    ip: IpAddr::V6(ll(1))
                },
                Observation::RouterAdvert {
                    mac: m,
                    src: ll(1),
                    lifetime: 1800,
                    dns: true,
                    global_prefix: false
                },
                Observation::Role {
                    mac: m,
                    role: Role::Router
                },
            ]
        );
        let o = obs(&nd_ra(0, 0, &[]), 1, ll(1));
        assert!(matches!(
            o.last(),
            Some(Observation::Role {
                role: Role::RouterNoDefault,
                ..
            })
        ));
    }

    #[test]
    fn hop_limit_not_255_only_heard() {
        let t = a6("2001:db8:1::50");
        for icmp in [
            nd_ra(1800, 0, &[opt_lla(1, mac(1)), opt_prefix(t, 64, 0x40)]),
            nd_na(0x60, t, &[opt_lla(2, mac(4))]),
        ] {
            let o = with(&icmp, 4, ll(4), 64, |p, nd| {
                let mut o = Vec::new();
                observe(p, nd, &mut o);
                o.into_iter().map(own).collect::<Vec<_>>()
            });
            assert_eq!(
                o,
                vec![Observation::Heard {
                    mac: Mac(mac(4)),
                    proto: ProtoTag::Nd
                }]
            );
        }
    }

    #[test]
    fn dad_ns_makes_no_claim() {
        let o = obs(&nd_ns(a6("2001:db8:1::50"), &[]), 4, a6("::"));
        assert_eq!(
            o,
            vec![Observation::Heard {
                mac: Mac(mac(4)),
                proto: ProtoTag::Nd
            }]
        );
    }

    #[test]
    fn na_claims_target() {
        let t = a6("2001:db8:1::50");
        let o = obs(&nd_na(0x60, t, &[opt_lla(2, mac(9))]), 4, ll(4));
        assert!(o.contains(&Observation::Claim {
            mac: Mac(mac(9)),
            ip: IpAddr::V6(t)
        }));
        assert!(o.contains(&Observation::Address {
            mac: Mac(mac(9)),
            ip: IpAddr::V6(t)
        }));
        let o = obs(&nd_na(0x60, t, &[]), 4, ll(4));
        assert!(o.contains(&Observation::Claim {
            mac: Mac(mac(4)),
            ip: IpAddr::V6(t)
        }));
        let o = obs(&nd_na(0x60, a6("::"), &[]), 4, ll(4));
        assert_eq!(o.len(), 1);
    }

    #[test]
    fn verbose_and_json() {
        let ra = nd_ra(
            1800,
            0x80,
            &[
                opt_lla(1, mac(1)),
                opt_prefix(a6("2001:db8:1::"), 64, 0xc0),
                opt_rdnss(&[a6("2001:db8::53")]),
                opt_route(a6("fd00:1::"), 48),
            ],
        );
        let v = with(&ra, 1, ll(1), 255, |p, nd| {
            let mut s = String::new();
            verbose(p, nd, &mut s);
            s
        });
        assert!(
            v.starts_with("  ND    router advert hop-limit 64 flags M lifetime 1800s"),
            "{v}"
        );
        assert!(v.contains("source-lla 02:00:5e:10:00:01\n"), "{v}");
        assert!(v.contains("prefix 2001:db8:1::/64 flags L A"), "{v}");
        assert!(v.contains("rdnss lifetime 600s 2001:db8::53\n"), "{v}");
        assert!(
            v.contains("route fd00:1::/48 pref medium lifetime 1800s"),
            "{v}"
        );
        let j = with(&ra, 1, ll(1), 255, |p, nd| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(p, nd, &mut w);
            w.end();
            w.as_str().to_string()
        });
        assert!(
            j.starts_with(r#"{"nd":{"type":"ra","cur_hop_limit":64,"flags":128,"#),
            "{j}"
        );
        assert!(
            j.contains(r#"{"type":"rdnss","lifetime":600,"servers":["2001:db8::53"]}"#),
            "{j}"
        );
    }
}
