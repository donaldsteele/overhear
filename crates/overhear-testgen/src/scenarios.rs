//! Named frame sequences. `testgen gen-samples` writes each as a pcap and as
//! fuzz corpus files.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::*;

const START: i64 = 1795266131;

fn stamp(frames: Vec<(Vec<u8>, Option<u32>)>) -> Vec<TFrame> {
    frames
        .into_iter()
        .enumerate()
        .map(|(i, (data, orig_len))| {
            let n = i as u32;
            TFrame {
                sec: START + i64::from(n / 4),
                usec: (n % 4) * 250_000,
                data,
                orig_len,
            }
        })
        .collect()
}

fn v4_bcast(vlans: &[(u16, u16)]) -> Vec<u8> {
    let ip = ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(255, 255, 255, 255),
        12345,
        9,
        b"hello",
    );
    eth_vlan(BCAST, mac(5), vlans, 0x0800, &ip)
}

const ALL_NODES_MAC: [u8; 6] = [0x33, 0x33, 0, 0, 0, 1];

fn all_nodes() -> Ipv6Addr {
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
}

fn link_local(n: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0x5eff, 0xfe10, n)
}

fn generic() -> Vec<TFrame> {
    let mut f = Vec::new();
    f.push((v4_bcast(&[]), None));
    let ip = ipv6_udp(link_local(6), all_nodes(), 5000, 9999, b"v6 hello");
    f.push((eth_ipv6(ALL_NODES_MAC, mac(6), &ip), None));
    f.push((
        eth([0x01, 0x00, 0x5e, 0x7f, 0, 1], mac(7), 0x88e1, &[1; 20]),
        None,
    ));
    f.push((v4_bcast(&[(0x8100, 100)]), None));
    f.push((v4_bcast(&[(0x88a8, 200), (0x8100, 100)]), None));
    f.push((vec![0xff; 13], None));
    // Later IPv4 fragment: fragment offset 185 (1480 bytes).
    let mut frag = v4_bcast(&[]);
    frag[20..22].copy_from_slice(&185u16.to_be_bytes());
    f.push((frag, None));
    f.push((
        llc(
            [0x01, 0x80, 0xc2, 0, 0, 0x14],
            mac(8),
            0xfe,
            0xfe,
            3,
            &[0; 4],
        ),
        None,
    ));
    // A 400-byte frame cut to 60 bytes by the snaplen.
    let big = ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(255, 255, 255, 255),
        12345,
        9,
        &[0x55; 358],
    );
    let mut cut = eth_ipv4(BCAST, mac(5), &big);
    cut.truncate(60);
    f.push((cut, Some(400)));
    let icmp = ipv6_icmp(link_local(10), all_nodes(), 64, &[128, 0, 0, 0, 0, 1, 0, 1]);
    f.push((eth_ipv6(ALL_NODES_MAC, mac(10), &icmp), None));
    stamp(f)
}

fn ip(d: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 1, d)
}

fn arp_frame(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
    eth(dst, src, 0x0806, payload)
}

fn arp_scenario() -> Vec<TFrame> {
    let none = [0; 6];
    let mut f = vec![(
        arp_frame(BCAST, mac(1), &arp(1, mac(1), ip(20), none, ip(1))),
        None,
    )];
    // Reply from the router.
    f.push((
        arp_frame(mac(1), mac(2), &arp(2, mac(2), ip(1), mac(1), ip(20))),
        None,
    ));
    // Probe, then the announcement that follows it.
    f.push((
        arp_frame(
            BCAST,
            mac(3),
            &arp(1, mac(3), Ipv4Addr::UNSPECIFIED, none, ip(30)),
        ),
        None,
    ));
    f.push((
        arp_frame(BCAST, mac(3), &arp(1, mac(3), ip(30), none, ip(30))),
        None,
    ));
    // .50 is claimed by mac(0x0a), then by mac(0x0b) a minute later.
    f.push((
        arp_frame(BCAST, mac(0x0a), &arp(1, mac(0x0a), ip(50), none, ip(1))),
        None,
    ));
    f.push((
        arp_frame(BCAST, mac(0x0b), &arp(1, mac(0x0b), ip(50), none, ip(1))),
        None,
    ));
    // An ARP cut off after 20 bytes.
    let mut cut = arp_frame(BCAST, mac(4), &arp(1, mac(4), ip(40), none, ip(1)));
    cut.truncate(14 + 20);
    f.push((cut, None));
    let mut frames = stamp(f);
    for t in frames.iter_mut().skip(5) {
        t.sec += 60;
    }
    frames
}

/// A DHCP message in an Ethernet/IPv4/UDP frame.
fn dhcp_frame(
    src: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ports: (u16, u16),
    vlans: &[(u16, u16)],
    payload: &[u8],
) -> Vec<u8> {
    let ip = ipv4_udp(src_ip, dst_ip, ports.0, ports.1, payload);
    eth_vlan(BCAST, src, vlans, 0x0800, &ip)
}

fn dhcp_scenario() -> Vec<TFrame> {
    let none = Ipv4Addr::UNSPECIFIED;
    let bcast = Ipv4Addr::BROADCAST;
    let client = mac(0x39);
    let (server, rogue) = (mac(1), mac(0xfe));
    let (c2s, s2c) = ((68, 67), (67, 68));
    let from_bytes =
        |m: [u8; 6], ip: Ipv4Addr, b: &[u8]| (dhcp_frame(m, ip, bcast, s2c, &[], b), None);
    let from = |m: [u8; 6], ip: Ipv4Addr, msg: &DhcpMsg| from_bytes(m, ip, &msg.bytes());
    let mut f = Vec::new();
    f.push((
        dhcp_frame(
            client,
            none,
            bcast,
            c2s,
            &[],
            &DhcpMsg::discover(client, "host-a").bytes(),
        ),
        None,
    ));
    f.push(from(
        server,
        ip(1),
        &DhcpMsg::reply(2, ip(1), ip(50), client),
    ));
    f.push(from(
        rogue,
        ip(254),
        &DhcpMsg::reply(2, ip(254), ip(51), client),
    ));
    let mut req = DhcpMsg::discover(client, "host-a");
    req.options[0] = (53, vec![3]);
    req.options.push((50, ip(50).octets().to_vec()));
    req.options.push((54, ip(1).octets().to_vec()));
    f.push((
        dhcp_frame(client, none, bcast, c2s, &[], &req.bytes()),
        None,
    ));
    f.push(from(
        server,
        ip(1),
        &DhcpMsg::reply(5, ip(1), ip(50), client),
    ));
    f.push(from(server, ip(1), &DhcpMsg::reply(6, ip(1), none, client)));

    // An offer relayed from another subnet, on VLAN 100.
    let relay_ip = Ipv4Addr::new(10, 9, 9, 1);
    let mut relayed = DhcpMsg::reply(
        2,
        Ipv4Addr::new(10, 9, 9, 9),
        Ipv4Addr::new(10, 9, 9, 50),
        mac(0x3a),
    );
    relayed.giaddr = relay_ip;
    f.push((
        dhcp_frame(
            mac(0x0a),
            relay_ip,
            bcast,
            s2c,
            &[(0x8100, 100)],
            &relayed.bytes(),
        ),
        None,
    ));

    // A DNS option of six bytes.
    let mut bad = DhcpMsg::reply(2, ip(1), ip(52), client);
    bad.options.push((6, vec![8, 8, 8, 8, 4, 4]));
    f.push(from(server, ip(1), &bad));

    // An option cut off in the middle of its data.
    let cut = DhcpMsg::reply(2, ip(1), ip(53), client).bytes();
    f.push(from_bytes(server, ip(1), &cut[..247]));

    // Options in both the file and sname fields.
    let mut over = DhcpMsg::reply(5, ip(1), ip(54), client);
    over.options.push((52, vec![3]));
    over.file = vec![12, 4, b'f', b'i', b'l', b'e', 255];
    over.sname = vec![12, 5, b's', b'n', b'a', b'm', b'e', 255];
    f.push(from(server, ip(1), &over));

    // Option 121 twice.
    let mut routes = DhcpMsg::reply(5, ip(1), ip(55), client);
    routes
        .options
        .push((121, vec![24, 10, 0, 1, 192, 168, 1, 1]));
    routes.options.push((121, vec![0, 192, 168, 1, 1]));
    f.push(from(server, ip(1), &routes));

    // A rogue server whose offer claims hardware type 6 (IEEE 802).
    let mut ieee802 = DhcpMsg::reply(2, ip(253), ip(56), client);
    ieee802.htype = 6;
    f.push(from(mac(0xfd), ip(253), &ieee802));

    // A rogue server behind an 802.1p priority tag (VLAN id 0): still the
    // untagged segment, so it warns instead of being learned.
    let tagged = DhcpMsg::reply(2, ip(252), ip(57), client);
    f.push((
        dhcp_frame(
            mac(0xfc),
            ip(252),
            bcast,
            s2c,
            &[(0x8100, 0)],
            &tagged.bytes(),
        ),
        None,
    ));
    stamp(f)
}

fn nd_scenario() -> Vec<TFrame> {
    let ll = |n: u16| Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n);
    let a6 = |s: &str| s.parse::<Ipv6Addr>().expect("literal address");
    let all_routers = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    let routers_mac = [0x33, 0x33, 0, 0, 0, 2];
    let to_all = |src: u8, src_ip: Ipv6Addr, icmp: &[u8]| {
        let ip = ipv6_icmp(src_ip, all_nodes(), 255, icmp);
        (eth_ipv6(ALL_NODES_MAC, mac(src), &ip), None)
    };
    let global = a6("2001:db8:1::");
    let target = a6("2001:db8:1::50");
    let mut f = Vec::new();
    let rs = ipv6_icmp(ll(9), all_routers, 255, &nd_rs(&[opt_lla(1, mac(9))]));
    f.push((eth_ipv6(routers_mac, mac(9), &rs), None));
    // The router, then the border router (no default route, then DNS only).
    f.push(to_all(
        1,
        ll(1),
        &nd_ra(
            1800,
            0,
            &[
                opt_lla(1, mac(1)),
                opt_prefix(global, 64, 0xc0),
                opt_rdnss(&[a6("2001:db8::53")]),
            ],
        ),
    ));
    f.push(to_all(
        2,
        ll(2),
        &nd_ra(
            0,
            0,
            &[
                opt_prefix(a6("fd00:1::"), 64, 0xc0),
                opt_route(a6("fd00:2::"), 48),
            ],
        ),
    ));
    f.push(to_all(
        2,
        ll(2),
        &nd_ra(0, 0, &[opt_rdnss(&[a6("2001:db8::53")])]),
    ));
    // A third router offers a default route.
    f.push(to_all(3, ll(3), &nd_ra(600, 0, &[])));
    // Duplicate address detection, then an unsolicited advert.
    let dad = ipv6_icmp(
        Ipv6Addr::UNSPECIFIED,
        a6("ff02::1:ff00:60"),
        255,
        &nd_ns(a6("2001:db8:1::60"), &[]),
    );
    f.push((eth_ipv6([0x33, 0x33, 0xff, 0, 0, 0x60], mac(6), &dad), None));
    f.push(to_all(
        6,
        ll(6),
        &nd_na(0x20, a6("2001:db8:1::60"), &[opt_lla(2, mac(6))]),
    ));
    // 2001:db8:1::50 is claimed by mac(4), then by mac(5) 30 s later.
    f.push(to_all(
        4,
        ll(4),
        &nd_na(0x60, target, &[opt_lla(2, mac(4))]),
    ));
    f.push(to_all(
        5,
        ll(5),
        &nd_na(0x60, target, &[opt_lla(2, mac(5))]),
    ));
    // A solicitation that did not keep its hop limit of 255.
    let bad = ipv6_icmp(ll(7), target, 64, &nd_ns(target, &[opt_lla(1, mac(7))]));
    f.push((eth_ipv6([0x33, 0x33, 0xff, 0, 0, 0x50], mac(7), &bad), None));
    // A zero-length option.
    let mut zero = nd_rs(&[]);
    zero.extend_from_slice(&[7, 0, 0, 0, 0, 0, 0, 0]);
    let ip = ipv6_icmp(ll(8), all_routers, 255, &zero);
    f.push((eth_ipv6(routers_mac, mac(8), &ip), None));
    let mut frames = stamp(f);
    // Exactly 30 s between the two adverts, then the rest follow.
    let gap = frames[8].sec * 1_000_000 + i64::from(frames[8].usec)
        - (frames[7].sec * 1_000_000 + i64::from(frames[7].usec));
    for t in frames.iter_mut().skip(8) {
        let at = t.sec * 1_000_000 + i64::from(t.usec) + 30_000_000 - gap;
        t.sec = at.div_euclid(1_000_000);
        t.usec = at.rem_euclid(1_000_000) as u32;
    }
    frames
}

fn mdns_frame(src: u8, payload: &[u8]) -> (Vec<u8>, Option<u32>) {
    let ip = ipv4_udp(ip(src), Ipv4Addr::new(224, 0, 0, 251), 5353, 5353, payload);
    (
        eth_ipv4([0x01, 0x00, 0x5e, 0, 0, 0xfb], mac(src), &ip),
        None,
    )
}

fn mdns_scenario() -> Vec<TFrame> {
    const RESPONSE: u16 = 0x8400;
    let inst = "Living-Room-TV._googlecast._tcp.local";
    let ptr = |name: &str, target: &str| {
        DnsBuilder::new(RESPONSE).answer(name, 12, 1, 4500, RDataSpec::Ptr(target.into()))
    };
    let printer = |addr: u8| {
        DnsBuilder::new(RESPONSE).answer("printer.local", 1, 0x8001, 120, RDataSpec::A(ip(addr)))
    };
    let mut f = vec![mdns_frame(
        0x20,
        &DnsBuilder::new(0)
            .question("_googlecast._tcp.local", 12, 0x8001)
            .bytes(),
    )];
    // A Chromecast announces itself, then says goodbye.
    f.push(mdns_frame(
        0x21,
        &DnsBuilder::new(RESPONSE)
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
                inst,
                16,
                0x8001,
                4500,
                RDataSpec::Txt(vec!["md=Chromecast".into()]),
            )
            .answer("Living-Room-TV.local", 1, 0x8001, 120, RDataSpec::A(ip(33)))
            .bytes(),
    ));
    f.push(mdns_frame(
        0x21,
        &DnsBuilder::new(RESPONSE)
            .answer(
                "_googlecast._tcp.local",
                12,
                1,
                0,
                RDataSpec::Ptr(inst.into()),
            )
            .bytes(),
    ));
    // Two hosts claim printer.local with different addresses.
    f.push(mdns_frame(0x30, &printer(48).bytes()));
    f.push(mdns_frame(0x31, &printer(49).bytes()));
    // A question whose name is a pointer to bytes beyond itself.
    let mut fwd = DnsBuilder::new(0).bytes();
    fwd[4..6].copy_from_slice(&1u16.to_be_bytes());
    fwd.extend_from_slice(&[0xc0, 0xf0, 0, 12, 0, 1]);
    f.push(mdns_frame(0x22, &fwd));
    // Instance names with terminal control and bidi characters, and one that
    // needs no escaping.
    f.push(mdns_frame(
        0x40,
        &ptr(
            "_airplay._tcp.local",
            "Evil\u{1b}[2J\u{202e}Name._airplay._tcp.local",
        )
        .bytes(),
    ));
    f.push(mdns_frame(
        0x41,
        &ptr(
            "_companion-link._tcp.local",
            "Bjørn's iPhone._companion-link._tcp.local",
        )
        .bytes(),
    ));
    stamp(f)
}

fn llmnr_scenario_frames() -> Vec<(Vec<u8>, Option<u32>)> {
    const RESPONSE: u16 = 0x8000;
    let query = |name: &str| {
        let ip = ipv4_udp(
            ip(0x20),
            Ipv4Addr::new(224, 0, 0, 252),
            50000,
            5355,
            &DnsBuilder::new(0).id(1).question(name, 1, 1).bytes(),
        );
        (
            eth_ipv4([0x01, 0x00, 0x5e, 0, 0, 0xfc], mac(0x20), &ip),
            None,
        )
    };
    // Unicast to the asker, as a mirror port shows it.
    let answer = |src: u8, name: &str| {
        let b = DnsBuilder::new(RESPONSE).id(1).question(name, 1, 1).answer(
            name,
            1,
            1,
            30,
            RDataSpec::A(ip(src)),
        );
        let ip = ipv4_udp(ip(src), ip(0x20), 5355, 50000, &b.bytes());
        (eth_ipv4(mac(0x20), mac(src), &ip), None)
    };
    // The same host answers for every name it is asked about.
    vec![
        query("wpad"),
        answer(0x66, "wpad"),
        answer(0x66, "fileserver"),
        answer(0x66, "printer"),
    ]
}

fn nbns_frame(src: u8, dst: [u8; 6], payload: &[u8]) -> (Vec<u8>, Option<u32>) {
    let ip = ipv4_udp(ip(src), Ipv4Addr::new(192, 168, 1, 255), 137, 137, payload);
    (eth_ipv4(dst, mac(src), &ip), None)
}

fn nbns_scenario() -> Vec<TFrame> {
    let mut f = llmnr_scenario_frames();
    let nb = |group: bool, addr: u8| vec![if group { 0x80 } else { 0 }, 0, 192, 168, 1, addr];
    // Registration (opcode 5): the name as the question, its NB record as an
    // answer that points back at it.
    let register = |name: &str, suffix: u8, group: bool, addr: u8| {
        nbns(
            0x1234,
            5 << 11 | 0x0110,
            &[(nb_encode(name, suffix), 0x20)],
            &[(vec![0xc0, 0x0c], 0x20, 300_000, nb(group, addr))],
        )
    };
    f.push(nbns_frame(
        0x50,
        BCAST,
        &register("WORKSTATION1", 0x00, false, 0x50),
    ));
    f.push(nbns_frame(0x50, BCAST, &register("HOME", 0x00, true, 0x50)));
    f.push(nbns_frame(
        0x20,
        BCAST,
        &nbns(
            0x2001,
            0x0110,
            &[(nb_encode("FILESERVER", 0x20), 0x20)],
            &[],
        ),
    ));
    // Two hosts claim to be the file server.
    let reply = |addr: u8| {
        nbns(
            0x2001,
            0x8500,
            &[],
            &[(
                nb_encode("FILESERVER", 0x20),
                0x20,
                300_000,
                nb(false, addr),
            )],
        )
    };
    f.push(nbns_frame(0x40, mac(0x20), &reply(0x40)));
    f.push(nbns_frame(0x41, mac(0x20), &reply(0x41)));
    // A name with a character outside the encoding alphabet.
    let mut bad = nb_encode("FILESERVER", 0x20);
    bad[5] = b'!';
    f.push(nbns_frame(
        0x22,
        BCAST,
        &nbns(0x3001, 0x0110, &[(bad, 0x20)], &[]),
    ));
    // A name with a terminal escape in it.
    f.push(nbns_frame(
        0x23,
        BCAST,
        &nbns(
            0x3002,
            0x0110,
            &[(nb_encode("EVIL\u{1b}[2JNAME", 0x20), 0x20)],
            &[],
        ),
    ));
    stamp(f)
}

fn ssdp_scenario() -> Vec<TFrame> {
    const MCAST: [u8; 6] = [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa];
    const TV: &str = "urn:schemas-upnp-org:device:MediaRenderer:1";
    const DESC: &str = "http://192.168.1.33:8008/ssdp/device-desc.xml";
    let group = Ipv4Addr::new(239, 255, 255, 250);
    let multicast = |src: u8, payload: &[u8]| {
        let ip = ipv4_udp(ip(src), group, 1900, 1900, payload);
        (eth_ipv4(MCAST, mac(src), &ip), None)
    };
    let mut f = Vec::new();
    let notify = |nts: &str| {
        ssdp(
            "NOTIFY * HTTP/1.1",
            &[
                ("HOST", "239.255.255.250:1900"),
                ("CACHE-CONTROL", "max-age=1800"),
                ("LOCATION", DESC),
                ("NT", TV),
                ("NTS", nts),
                ("SERVER", "Linux/4.4 UPnP/1.0 Chromecast/1.0"),
                (
                    "USN",
                    "uuid:2f402f80-da50-11e1-9b23-001788::urn:schemas-upnp-org:device:MediaRenderer:1",
                ),
            ],
        )
    };
    f.push(multicast(0x33, &notify("ssdp:alive")));
    f.push(multicast(0x33, &notify("ssdp:byebye")));
    f.push(multicast(
        0x20,
        &ssdp(
            "M-SEARCH * HTTP/1.1",
            &[
                ("HOST", "239.255.255.250:1900"),
                ("MAN", "\"ssdp:discover\""),
                ("MX", "2"),
                ("ST", "ssdp:all"),
            ],
        ),
    ));
    let reply = |src: u8, server: &str| {
        let b = ssdp(
            "HTTP/1.1 200 OK",
            &[
                ("CACHE-CONTROL", "max-age=1800"),
                ("ST", TV),
                ("LOCATION", DESC),
                ("SERVER", server),
            ],
        );
        let ip = ipv4_udp(ip(src), ip(0x20), 1900, 50000, &b);
        (eth_ipv4(mac(0x20), mac(src), &ip), None)
    };
    f.push(reply(0x33, "Linux/4.4 UPnP/1.0 Chromecast/1.0"));
    // A SERVER value with a terminal escape in it.
    f.push(reply(0x34, "Evil\u{1b}[2J/1.0 UPnP/1.0"));
    // 65 headers: the first 64 are kept.
    let names: Vec<String> = (1..=65).map(|i| format!("X-H{i}")).collect();
    let hs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "v")).collect();
    f.push(multicast(0x35, &ssdp("NOTIFY * HTTP/1.1", &hs)));
    stamp(f)
}

fn lldp_cdp_scenario() -> Vec<TFrame> {
    const LLDP_MCAST: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 0x0e];
    const CDP_MCAST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
    let id = |typ: u8, sub: u8, v: &[u8]| (typ, [&[sub][..], v].concat());
    let caps = |system: u16, enabled: u16| {
        let mut v = system.to_be_bytes().to_vec();
        v.extend_from_slice(&enabled.to_be_bytes());
        (7u8, v)
    };
    let head = |src: u8, port: &str| {
        vec![
            id(1, 4, &mac(src)),
            id(2, 5, port.as_bytes()),
            (3u8, 120u16.to_be_bytes().to_vec()),
        ]
    };
    let unit = |mut t: Vec<(u8, Vec<u8>)>| {
        t.push((0, vec![]));
        lldp(&t)
    };
    let frame = |src: u8, payload: &[u8]| (eth(LLDP_MCAST, mac(src), 0x88cc, payload), None);
    let mut f = Vec::new();
    // A switch: bridge and router capabilities, management address, port VLAN.
    let mut t = head(0x60, "Gi1/0/24");
    t.push((4, b"uplink to distribution".to_vec()));
    t.push((5, b"core-sw1".to_vec()));
    t.push((6, b"Acme Switch OS 4.2".to_vec()));
    t.push(caps(0x0014, 0x0014));
    t.push((8, vec![5, 1, 192, 168, 1, 2, 2, 0, 0, 0, 1, 0]));
    t.push((127, vec![0x00, 0x80, 0xc2, 1, 0, 10]));
    f.push(frame(0x60, &unit(t)));
    // An access point.
    let mut t = head(0x61, "eth0");
    t.push((5, b"ap-lobby".to_vec()));
    t.push((6, b"Acme AP 6 firmware 1.8".to_vec()));
    t.push(caps(0x001c, 0x0008));
    t.push((8, vec![5, 1, 192, 168, 1, 61, 2, 0, 0, 0, 1, 0]));
    f.push(frame(0x61, &unit(t)));
    // An LLDP-MED phone with a MED capabilities organization TLV.
    let mut t = head(0x62, "1");
    t.push((5, b"desk-phone-17".to_vec()));
    t.push(caps(0x0024, 0x0020));
    t.push((127, vec![0x00, 0x12, 0xbb, 1, 0x00, 0x33, 0x01]));
    f.push(frame(0x62, &unit(t)));
    // A Cisco switch speaking CDP, native VLAN 10.
    let mut addrs = 1u32.to_be_bytes().to_vec();
    addrs.extend_from_slice(&[1, 1, 0xcc, 0, 4, 192, 168, 1, 3]);
    let c = cdp(&[
        (1, b"dist-sw2.example.net".to_vec()),
        (2, addrs),
        (3, b"GigabitEthernet1/0/1".to_vec()),
        (4, 0x0000_0028u32.to_be_bytes().to_vec()),
        (5, b"Cisco IOS Software, Version 15.2(7)E".to_vec()),
        (6, b"cisco WS-C2960X-48TS-L".to_vec()),
        (9, b"corp".to_vec()),
        (0x0a, 10u16.to_be_bytes().to_vec()),
        (0x0b, vec![1]),
    ]);
    f.push((snap(CDP_MCAST, mac(0x63), [0, 0, 0x0c], 0x2000, &c), None));
    // The last TLV claims 511 bytes but the frame ends first.
    let mut t = lldp(&head(0x64, "Gi0/1"));
    t.extend_from_slice(&(((5u16) << 9) | 0x1ff).to_be_bytes());
    t.extend_from_slice(b"core-sw9");
    f.push(frame(0x64, &t));
    // A system name with a terminal escape in it.
    let mut t = head(0x65, "Gi0/2");
    t.push((5, b"evil\x1b[2Jsw".to_vec()));
    f.push(frame(0x65, &unit(t)));
    stamp(f)
}

fn stp_scenario() -> Vec<TFrame> {
    const STP_MCAST: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 0];
    let root = (0x8000, [0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
    let send = |src: u8, b: &[u8]| (llc(STP_MCAST, mac(src), 0x42, 0x42, 3, b), None);
    let mut t = bpdu(0, 0, 0, root, 4, (0x8000, mac(0x53)), 0x8001, 0);
    t.truncate(20);
    let f = vec![
        send(
            0x50,
            &bpdu(0, 0, 0, root, 4, (0x8000, mac(0x50)), 0x8001, 0),
        ),
        send(
            0x51,
            &bpdu(2, 2, 1, root, 20000, (0x9001, mac(0x51)), 0x8002, 0),
        ),
        send(0x51, &bpdu(0, 0x80, 0, root, 0, (0, [0; 6]), 0, 0)),
        send(
            0x52,
            &bpdu(3, 2, 0, root, 20000, (0xa001, mac(0x52)), 0x8003, 2),
        ),
        // A configuration BPDU cut off after 20 bytes.
        send(0x53, &t),
    ];
    stamp(f)
}

/// Every scenario as `(name, frames)`. Protocol tasks append entries.
pub fn scenarios() -> Vec<(&'static str, Vec<TFrame>)> {
    vec![
        ("generic", generic()),
        ("arp", arp_scenario()),
        ("dhcp", dhcp_scenario()),
        ("nd", nd_scenario()),
        ("mdns", mdns_scenario()),
        ("llmnr_nbns", nbns_scenario()),
        ("ssdp", ssdp_scenario()),
        ("lldp_cdp", lldp_cdp_scenario()),
        ("stp", stp_scenario()),
    ]
}
