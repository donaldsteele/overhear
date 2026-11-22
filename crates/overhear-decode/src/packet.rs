use crate::ip::{self, IpHeader, Ipv6Header};
use crate::{
    Arp, Cursor, Dhcp, DnsMessage, EthHeader, EthKind, Layer, Nbns, Nd, Problem, Ssdp, arp, dhcp,
    dns, ethernet, nbns, nd, ssdp,
};

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
    Nd(Nd<'a>),
    Mdns(DnsMessage<'a>),
    Llmnr(DnsMessage<'a>),
    Nbns(Nbns<'a>),
    Ssdp(Ssdp<'a>),
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
        IpHeader::V4(_) if udp.src_port == 137 || udp.dst_port == 137 => {
            nbns::parse(c, problems).map(Proto::Nbns)
        }
        _ if udp.src_port == 1900 || udp.dst_port == 1900 => {
            ssdp::parse(c, problems).map(Proto::Ssdp)
        }
        _ if udp.src_port == 5355 || udp.dst_port == 5355 => {
            dns::parse(c, problems).map(Proto::Llmnr)
        }
        _ if udp.src_port == 5353 || udp.dst_port == 5353 => {
            dns::parse(c, problems).map(Proto::Mdns)
        }
        _ => None,
    }
}

fn dispatch_icmpv6<'a>(
    ip: &Ipv6Header,
    typ: u8,
    _code: u8,
    c: &mut Cursor<'a>,
    problems: &mut Vec<Problem>,
) -> Option<Proto<'a>> {
    match typ {
        133..=137 => nd::parse(c, typ, ip.hop_limit, problems).map(Proto::Nd),
        _ => None,
    }
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
    }
    if let Some(sub) = c.sub(plen.min(c.remaining())) {
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

    #[test]
    fn mdns_dispatch_on_port_5353_over_v4_and_v6() {
        let b = DnsBuilder::new(0)
            .question("_http._tcp.local", 12, 1)
            .bytes();
        let ip4 = ipv4_udp(v4(10, 0, 0, 5), v4(224, 0, 0, 251), 5353, 5353, &b);
        let ip6 = ipv6_udp(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 5353, 5353, &b);
        for f in [
            eth_ipv4(mac(1), mac(2), &ip4),
            eth_ipv6(mac(1), mac(2), &ip6),
        ] {
            let p = decode(&f).unwrap();
            assert!(matches!(&p.proto, Proto::Mdns(m) if m.questions.len() == 1));
            assert!(p.problems.is_empty());
        }
        let ip = ipv4_udp(v4(10, 0, 0, 5), v4(224, 0, 0, 251), 5000, 5001, &b);
        let f = eth_ipv4(mac(1), mac(2), &ip);
        assert!(matches!(decode(&f).unwrap().proto, Proto::Other { .. }));
    }

    #[test]
    fn mdns_short_payload_falls_back_to_other() {
        let ip = ipv4_udp(v4(10, 0, 0, 5), v4(224, 0, 0, 251), 5353, 5353, &[0; 5]);
        let f = eth_ipv4(mac(1), mac(2), &ip);
        let p = decode(&f).unwrap();
        assert_eq!(prob(&p), vec![(Layer::Dns, "truncated")]);
        assert!(matches!(p.proto, Proto::Other { payload } if payload.len() == 5));
    }

    #[test]
    fn snaplen_cut_mdns_never_marks_garbage_valid() {
        let inst = "Living-Room-TV._googlecast._tcp.local";
        let b = DnsBuilder::new(0x8400)
            .answer(
                "_googlecast._tcp.local",
                12,
                1,
                4500,
                RDataSpec::Ptr(inst.into()),
            )
            .answer(
                inst,
                33,
                0x8001,
                4500,
                RDataSpec::Srv(8009, "Living-Room-TV.local".into()),
            )
            .answer(
                "Living-Room-TV.local",
                1,
                0x8001,
                120,
                RDataSpec::A(v4(10, 0, 0, 1)),
            )
            .bytes();
        let ip = ipv4_udp(v4(10, 0, 0, 5), v4(224, 0, 0, 251), 5353, 5353, &b);
        let full = eth_ipv4(mac(1), mac(2), &ip);
        let mut parsed_ptr = false;
        for cut in 1..120 {
            let f = &full[..full.len() - cut];
            let p = decode(f).unwrap();
            let Proto::Mdns(m) = &p.proto else { continue };
            for n in m
                .questions
                .iter()
                .map(|q| q.name)
                .chain(m.records.iter().map(|r| r.name))
            {
                if n.is_valid() {
                    let d = n.dotted();
                    assert!(d.iter().all(|b| b.is_ascii_graphic()), "cut {cut}: {d:?}");
                }
            }
            for r in &m.records {
                if let crate::RData::Ptr(t) = r.rdata {
                    assert!(t.is_valid());
                    assert_eq!(t.dotted(), inst.as_bytes(), "cut {cut}");
                    parsed_ptr = true;
                }
            }
        }
        assert!(parsed_ptr);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod name_service_tests {
    use super::*;
    use overhear_testgen::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn llmnr_dispatch_on_port_5355_over_v4_and_v6() {
        let b = DnsBuilder::new(0).question("wpad", 1, 1).bytes();
        let a = Ipv4Addr::new(10, 0, 0, 5);
        let ip4 = ipv4_udp(a, Ipv4Addr::new(224, 0, 0, 252), 50000, 5355, &b);
        let ip6 = ipv6_udp(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 5355, 50000, &b);
        for f in [
            eth_ipv4(mac(1), mac(2), &ip4),
            eth_ipv6(mac(1), mac(2), &ip6),
        ] {
            let p = decode(&f).unwrap();
            assert!(matches!(&p.proto, Proto::Llmnr(m) if m.questions.len() == 1));
            assert!(p.problems.is_empty());
        }
    }

    #[test]
    fn nbns_dispatch_on_port_137_over_v4_only() {
        let b = nbns(1, 0, &[(nb_encode("HOST", 0), 0x20)], &[]);
        let a = Ipv4Addr::new(10, 0, 0, 5);
        for (s, d) in [(137, 137), (50000, 137), (137, 50000)] {
            let f = eth_ipv4(mac(1), mac(2), &ipv4_udp(a, a, s, d, &b));
            let p = decode(&f).unwrap();
            assert!(matches!(&p.proto, Proto::Nbns(m) if m.questions.len() == 1));
        }
        let ip6 = ipv6_udp(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 137, 137, &b);
        let f = eth_ipv6(mac(1), mac(2), &ip6);
        assert!(matches!(decode(&f).unwrap().proto, Proto::Other { .. }));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod ssdp_tests {
    use super::*;
    use overhear_testgen::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ssdp_dispatch_on_port_1900_over_v4_and_v6() {
        let b = ssdp("M-SEARCH * HTTP/1.1", &[("ST", "ssdp:all")]);
        let a = Ipv4Addr::new(10, 0, 0, 5);
        let ip4 = ipv4_udp(a, Ipv4Addr::new(239, 255, 255, 250), 50000, 1900, &b);
        let ip6 = ipv6_udp(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 1900, 50000, &b);
        for f in [
            eth_ipv4(mac(1), mac(2), &ip4),
            eth_ipv6(mac(1), mac(2), &ip6),
        ] {
            let p = decode(&f).unwrap();
            assert!(matches!(&p.proto, Proto::Ssdp(m) if m.headers.len() == 1));
            assert!(p.problems.is_empty());
        }
    }
}
