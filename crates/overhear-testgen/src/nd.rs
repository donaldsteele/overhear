//! IPv6 neighbour discovery message builders. Each message starts with the
//! ICMPv6 type, code and checksum (zero), like the bytes `ipv6_icmp` carries.

use std::net::Ipv6Addr;

fn msg(typ: u8, body: &[u8], opts: &[Vec<u8>]) -> Vec<u8> {
    let mut m = vec![typ, 0, 0, 0];
    m.extend_from_slice(body);
    for o in opts {
        m.extend_from_slice(o);
    }
    m
}

/// Router advertisement: hop limit 64, the given flags and lifetime,
/// reachable and retransmit timers 0.
pub fn nd_ra(lifetime: u16, flags: u8, opts: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![64, flags];
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&[0; 8]);
    msg(134, &b, opts)
}

pub fn nd_na(flags: u8, target: Ipv6Addr, opts: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![flags, 0, 0, 0];
    b.extend_from_slice(&target.octets());
    msg(136, &b, opts)
}

pub fn nd_ns(target: Ipv6Addr, opts: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 4];
    b.extend_from_slice(&target.octets());
    msg(135, &b, opts)
}

pub fn nd_rs(opts: &[Vec<u8>]) -> Vec<u8> {
    msg(133, &[0; 4], opts)
}

/// Source (type 1) or target (type 2) link-layer address option.
pub fn opt_lla(typ: u8, mac: [u8; 6]) -> Vec<u8> {
    let mut o = vec![typ, 1];
    o.extend_from_slice(&mac);
    o
}

/// Prefix information option: valid 2592000 s, preferred 604800 s.
pub fn opt_prefix(p: Ipv6Addr, len: u8, flags: u8) -> Vec<u8> {
    let mut o = vec![3, 4, len, flags];
    o.extend_from_slice(&2_592_000u32.to_be_bytes());
    o.extend_from_slice(&604_800u32.to_be_bytes());
    o.extend_from_slice(&[0; 4]);
    o.extend_from_slice(&p.octets());
    o
}

/// RDNSS option, lifetime 600 s.
pub fn opt_rdnss(servers: &[Ipv6Addr]) -> Vec<u8> {
    let units = 1 + 2 * servers.len();
    let mut o = vec![25, units as u8, 0, 0];
    o.extend_from_slice(&600u32.to_be_bytes());
    for s in servers {
        o.extend_from_slice(&s.octets());
    }
    o
}

/// Route information option with a full 16-byte prefix, medium preference,
/// lifetime 1800 s.
pub fn opt_route(p: Ipv6Addr, len: u8) -> Vec<u8> {
    let mut o = vec![24, 3, len, 0];
    o.extend_from_slice(&1800u32.to_be_bytes());
    o.extend_from_slice(&p.octets());
    o
}
