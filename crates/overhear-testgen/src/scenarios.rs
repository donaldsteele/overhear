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

/// Every scenario as `(name, frames)`. Protocol tasks append entries.
pub fn scenarios() -> Vec<(&'static str, Vec<TFrame>)> {
    vec![("generic", generic())]
}
