use crate::ip::{self, IpHeader, Ipv6Header};
use crate::{Arp, Cursor, Dhcp, EthHeader, EthKind, Layer, Problem, arp, dhcp, ethernet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    None,
    Udp(UdpHeader),
    Icmpv6 { typ: u8, code: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proto<'a> {
    Arp(Arp),
    Dhcp(Dhcp<'a>),
    Other { payload: &'a [u8] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub eth: EthHeader,
    pub ip: Option<IpHeader>,
    pub l4: L4,
    pub proto: Proto<'a>,
    pub problems: Vec<Problem>,
}

pub type Decoded<'a> = Result<Packet<'a>, Problem>;

fn dispatch_ether<'a>(
    kind: &EthKind,
    c: &mut Cursor<'a>,
    problems: &mut Vec<Problem>,
) -> Option<Proto<'a>> {
    match kind {
        EthKind::EtherType(0x0806) => arp::parse(c, problems).map(Proto::Arp),
        _ => None,
    }
}

fn dispatch_udp<'a>(
    ip: &IpHeader,
    udp: &UdpHeader,
    c: &mut Cursor<'a>,
    problems: &mut Vec<Problem>,
) -> Option<Proto<'a>> {
    let bootp = |p: u16| matches!(p, 67 | 68);
    match ip {
        IpHeader::V4(_) if bootp(udp.src_port) || bootp(udp.dst_port) => {
            dhcp::parse(c, problems).map(Proto::Dhcp)
        }
        _ => None,
    }
}

fn dispatch_icmpv6<'a>(
    _ip: &Ipv6Header,
    _typ: u8,
    _code: u8,
    _c: &mut Cursor<'a>,
    _problems: &mut Vec<Problem>,
) -> Option<Proto<'a>> {
    None
}

/// Decodes a frame. `Err` only when the Ethernet header is incomplete.
pub fn decode(frame: &[u8]) -> Decoded<'_> {
    let mut problems = Vec::new();
    let mut c = Cursor::new(frame);
    let Some(eth) = ethernet(&mut c, &mut problems) else {
        return Err(problems.pop().unwrap_or(Problem {
            layer: Layer::Ethernet,
            reason: "truncated",
            offset: 0,
            len: frame.len(),
        }));
    };
    let mut ip = None;
    let mut l4 = L4::None;
    let proto = match eth.kind {
        EthKind::EtherType(0x0800) => match ip::ipv4(&mut c, &mut problems) {
            Some((h, has_l4)) => {
                let hdr = IpHeader::V4(h);
                ip = Some(hdr);
                if has_l4 && h.proto == 17 {
                    udp(&hdr, &mut c, &mut l4, &mut problems)
                } else {
                    other(&mut c)
                }
            }
            None => other(&mut c),
        },
        EthKind::EtherType(0x86dd) => match ip::ipv6(&mut c, &mut problems) {
            Some((h, has_l4)) => {
                let hdr = IpHeader::V6(h);
                ip = Some(hdr);
                match (has_l4, h.next) {
                    (true, 17) => udp(&hdr, &mut c, &mut l4, &mut problems),
                    (true, 58) => icmpv6(&h, &mut c, &mut l4, &mut problems),
                    _ => other(&mut c),
                }
            }
            None => other(&mut c),
        },
        kind => dispatch_ether(&kind, &mut c, &mut problems).unwrap_or_else(|| other(&mut c)),
    };
    Ok(Packet {
        eth,
        ip,
        l4,
        proto,
        problems,
    })
}

fn other<'a>(c: &mut Cursor<'a>) -> Proto<'a> {
    Proto::Other { payload: c.rest() }
}

fn udp<'a>(
    ip: &IpHeader,
    c: &mut Cursor<'a>,
    l4: &mut L4,
    problems: &mut Vec<Problem>,
) -> Proto<'a> {
    let start = c.pos();
    let (Some(src_port), Some(dst_port), Some(len), Some(_)) =
        (c.be16(), c.be16(), c.be16(), c.be16())
    else {
        problems.push(Problem {
            layer: Layer::Udp,
            reason: "truncated",
            offset: start,
            len: c.remaining(),
        });
        return other(c);
    };
    let hdr = UdpHeader {
        src_port,
        dst_port,
        len,
    };
    *l4 = L4::Udp(hdr);
    if len < 8 {
        problems.push(Problem {
            layer: Layer::Udp,
            reason: "bad length",
            offset: start.saturating_add(4),
            len: 2,
        });
        c.rest();
        return Proto::Other { payload: &[] };
    }
    let plen = usize::from(len).saturating_sub(8);
    if plen > c.remaining() {
        problems.push(Problem {
            layer: Layer::Udp,
            reason: "truncated",
            offset: start.saturating_add(4),
            len: 2,
        });
    } else if let Some(sub) = c.sub(plen) {
        *c = sub;
    }
    dispatch_udp(ip, &hdr, c, problems).unwrap_or_else(|| other(c))
}

fn icmpv6<'a>(
    ip: &Ipv6Header,
    c: &mut Cursor<'a>,
    l4: &mut L4,
    problems: &mut Vec<Problem>,
) -> Proto<'a> {
    let start = c.pos();
    let (Some(typ), Some(code), Some(_)) = (c.u8(), c.u8(), c.be16()) else {
        problems.push(Problem {
            layer: Layer::Icmpv6,
            reason: "truncated",
            offset: start,
            len: c.remaining(),
        });
        return other(c);
    };
    *l4 = L4::Icmpv6 { typ, code };
    dispatch_icmpv6(ip, typ, code, c, problems).unwrap_or_else(|| other(c))
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
    use crate::ip::Frag;
    use overhear_testgen::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn sample() -> Vec<u8> {
        eth_ipv4(
            BCAST,
            mac(5),
            &ipv4_udp(v4(10, 0, 0, 5), v4(255, 255, 255, 255), 12345, 9, b"hello"),
        )
    }

    fn prob(p: &Packet<'_>) -> Vec<(Layer, &'static str)> {
        p.problems.iter().map(|p| (p.layer, p.reason)).collect()
    }

    #[test]
    fn ipv4_udp_broadcast_reaches_other() {
        let f = sample();
        let p = decode(&f).unwrap();
        match p.ip.unwrap() {
            IpHeader::V4(h) => {
                assert_eq!(h.src, v4(10, 0, 0, 5));
                assert_eq!(h.dst, v4(255, 255, 255, 255));
                assert_eq!((h.ttl, h.proto), (64, 17));
            }
            _ => panic!("not v4"),
        }
        assert_eq!(
            p.l4,
            L4::Udp(UdpHeader {
                src_port: 12345,
                dst_port: 9,
                len: 13
            })
        );
        assert_eq!(p.proto, Proto::Other { payload: b"hello" });
        assert!(p.problems.is_empty());
    }

    #[test]
    fn ipv4_total_length_beyond_frame() {
        let mut f = sample();
        f[16..18].copy_from_slice(&200u16.to_be_bytes());
        let p = decode(&f).unwrap();
        assert_eq!(prob(&p), vec![(Layer::Ipv4, "truncated")]);
        assert!(matches!(p.l4, L4::Udp(_)));
    }

    #[test]
    fn ipv4_bad_ihl() {
        let mut f = sample();
        f[14] = 0x44;
        let p = decode(&f).unwrap();
        assert_eq!(prob(&p), vec![(Layer::Ipv4, "bad header length")]);
        assert_eq!(p.l4, L4::None);
    }

    #[test]
    fn later_fragment_not_decoded() {
        let mut f = sample();
        f[20..22].copy_from_slice(&185u16.to_be_bytes());
        let p = decode(&f).unwrap();
        assert_eq!(*p.ip.unwrap().frag(), Frag::Later);
        assert_eq!(p.l4, L4::None);
        assert!(matches!(p.proto, Proto::Other { .. }));
    }

    #[test]
    fn first_fragment_decodes_l4() {
        let mut f = sample();
        f[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        let p = decode(&f).unwrap();
        assert_eq!(*p.ip.unwrap().frag(), Frag::First);
        assert!(matches!(p.l4, L4::Udp(_)));
    }

    /// An IPv6 frame whose first header type is `next` and body is `body`.
    fn v6(body: &[u8], next: u8) -> Vec<u8> {
        let mut ip = ipv6_icmp(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 255, body);
        ip[6] = next;
        eth_ipv6(mac(1), mac(2), &ip)
    }

    #[test]
    fn ipv6_hop_by_hop_then_icmpv6() {
        let mut body = vec![58, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&[143, 0, 0, 0]);
        let f = v6(&body, 0);
        let p = decode(&f).unwrap();
        match p.ip.unwrap() {
            IpHeader::V6(h) => assert_eq!(h.next, 58),
            _ => panic!("not v6"),
        }
        assert_eq!(p.l4, L4::Icmpv6 { typ: 143, code: 0 });
        assert!(p.problems.is_empty());
    }

    #[test]
    fn nine_extension_headers() {
        let mut body = Vec::new();
        for _ in 0..8 {
            body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        }
        body.extend_from_slice(&[58, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&[143, 0, 0, 0]);
        let f = v6(&body, 0);
        let p = decode(&f).unwrap();
        assert_eq!(prob(&p), vec![(Layer::Ipv6, "too many extension headers")]);
        assert_eq!(p.l4, L4::None);
    }

    #[test]
    fn ipv6_udp_decodes() {
        let ip = ipv6_udp(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 1, 2, b"xy");
        let f = eth_ipv6(mac(1), mac(2), &ip);
        let p = decode(&f).unwrap();
        assert!(matches!(p.l4, L4::Udp(UdpHeader { len: 10, .. })));
        assert_eq!(p.proto, Proto::Other { payload: b"xy" });
    }

    #[test]
    fn udp_length_too_small() {
        let mut f = sample();
        f[38..40].copy_from_slice(&4u16.to_be_bytes());
        let p = decode(&f).unwrap();
        assert_eq!(prob(&p), vec![(Layer::Udp, "bad length")]);
        assert_eq!(p.proto, Proto::Other { payload: &[] });
    }

    #[test]
    fn vlan_tagged_ipv4_decodes() {
        let ip = ipv4_udp(v4(10, 0, 0, 5), v4(10, 0, 0, 6), 1, 2, b"hi");
        let f = eth_vlan(mac(1), mac(2), &[(0x8100, 100)], 0x0800, &ip);
        let p = decode(&f).unwrap();
        assert!(matches!(p.l4, L4::Udp(_)));
        assert_eq!(p.eth.vlans.as_slice().len(), 1);
    }

    #[test]
    fn short_frame_is_err() {
        assert!(decode(&[0; 13]).is_err());
    }

    #[test]
    fn non_ip_ethertype_is_other() {
        let f = eth(BCAST, mac(1), 0x88e1, &[7; 10]);
        let p = decode(&f).unwrap();
        assert!(p.ip.is_none());
        match p.proto {
            Proto::Other { payload } => assert_eq!(payload.len(), 46),
            _ => panic!("not other"),
        }
    }

    #[test]
    fn arp_dispatch_and_fallback() {
        let a = arp(1, mac(1), v4(10, 0, 0, 1), [0; 6], v4(10, 0, 0, 2));
        let f = eth(BCAST, mac(1), 0x0806, &a);
        let p = decode(&f).unwrap();
        assert!(matches!(p.proto, Proto::Arp(x) if x.op == 1));
        assert!(p.problems.is_empty());
        let mut bad = a.clone();
        bad[4] = 8;
        let f = eth(BCAST, mac(1), 0x0806, &bad);
        let p = decode(&f).unwrap();
        assert_eq!(
            prob(&p),
            vec![(Layer::Arp, "unsupported hardware or protocol size")]
        );
        assert!(matches!(p.proto, Proto::Other { payload } if payload.len() == 46));
    }

    fn dhcp_frame(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        eth_ipv4(
            BCAST,
            mac(5),
            &ipv4_udp(
                v4(0, 0, 0, 0),
                v4(255, 255, 255, 255),
                sport,
                dport,
                payload,
            ),
        )
    }

    #[test]
    fn dhcp_dispatch_on_ports_67_and_68() {
        let b = DhcpMsg::discover(mac(5), "h").bytes();
        for (s, d) in [(68, 67), (67, 68)] {
            let f = dhcp_frame(s, d, &b);
            let p = decode(&f).unwrap();
            assert!(matches!(&p.proto, Proto::Dhcp(x) if x.msg_type() == Some(1)));
            assert!(p.problems.is_empty());
        }
        let f = dhcp_frame(1000, 2000, &b);
        assert!(matches!(decode(&f).unwrap().proto, Proto::Other { .. }));
    }

    #[test]
    fn dhcp_short_payload_falls_back_to_other() {
        let f = dhcp_frame(68, 67, &[0; 100]);
        let p = decode(&f).unwrap();
        assert_eq!(prob(&p), vec![(Layer::Dhcp, "truncated BOOTP header")]);
        assert!(matches!(p.proto, Proto::Other { payload } if payload.len() == 100));
    }

    #[test]
    fn dhcp_ports_over_ipv6_are_other() {
        let b = DhcpMsg::discover(mac(5), "h").bytes();
        let ip = ipv6_udp(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 68, 67, &b);
        let f = eth_ipv6(mac(1), mac(2), &ip);
        assert!(matches!(decode(&f).unwrap().proto, Proto::Other { .. }));
    }
}
