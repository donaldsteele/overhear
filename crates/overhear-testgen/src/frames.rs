//! Ethernet frame builders for generated test data.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const BCAST: [u8; 6] = [0xff; 6];

/// `02:00:5e:10:00:nn`
pub fn mac(n: u8) -> [u8; 6] {
    [0x02, 0x00, 0x5e, 0x10, 0x00, n]
}

fn pad60(mut f: Vec<u8>) -> Vec<u8> {
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

fn header(dst: [u8; 6], src: [u8; 6]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f
}

/// Ethernet II frame, padded to 60 bytes.
pub fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    eth_vlan(dst, src, &[], ethertype, payload)
}

/// Ethernet II frame with VLAN tags `(tpid, id)`, outer first.
pub fn eth_vlan(
    dst: [u8; 6],
    src: [u8; 6],
    tags: &[(u16, u16)],
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = header(dst, src);
    for &(tpid, id) in tags {
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&(id & 0x0fff).to_be_bytes());
    }
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    pad60(f)
}

fn dot3(dst: [u8; 6], src: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut f = header(dst, src);
    f.extend_from_slice(&(body.len() as u16).to_be_bytes());
    f.extend_from_slice(body);
    pad60(f)
}

/// 802.3 frame with an LLC header, padded to 60 bytes.
pub fn llc(dst: [u8; 6], src: [u8; 6], dsap: u8, ssap: u8, ctrl: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![dsap, ssap, ctrl];
    body.extend_from_slice(payload);
    dot3(dst, src, &body)
}

/// 802.3 frame with LLC `AA AA 03` and a SNAP header, padded to 60 bytes.
pub fn snap(dst: [u8; 6], src: [u8; 6], oui: [u8; 3], pid: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![0xaa, 0xaa, 0x03];
    body.extend_from_slice(&oui);
    body.extend_from_slice(&pid.to_be_bytes());
    body.extend_from_slice(payload);
    dot3(dst, src, &body)
}

fn ipv4_checksum(h: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for w in h.chunks(2) {
        let hi = u32::from(w.first().copied().unwrap_or(0));
        let lo = u32::from(w.get(1).copied().unwrap_or(0));
        sum += (hi << 8) | lo;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_segment(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + payload.len());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    u
}

/// IPv4 + UDP datagram: TTL 64, header checksum set, UDP checksum 0.
pub fn ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp = udp_segment(sport, dport, payload);
    let mut h = vec![0x45, 0];
    h.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    h.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
    h.extend_from_slice(&src.octets());
    h.extend_from_slice(&dst.octets());
    let ck = ipv4_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    h.extend_from_slice(&udp);
    h
}

fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, next: u8, hop: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&(body.len() as u16).to_be_bytes());
    p.push(next);
    p.push(hop);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(body);
    p
}

/// IPv6 + UDP datagram: hop limit 255.
pub fn ipv6_udp(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    ipv6_packet(src, dst, 17, 255, &udp_segment(sport, dport, payload))
}

/// IPv6 packet carrying the given ICMPv6 message bytes.
pub fn ipv6_icmp(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8, icmp: &[u8]) -> Vec<u8> {
    ipv6_packet(src, dst, 58, hop_limit, icmp)
}

/// Ethernet frame (EtherType 0x0800) around an IPv4 packet.
pub fn eth_ipv4(dst: [u8; 6], src: [u8; 6], ip: &[u8]) -> Vec<u8> {
    eth(dst, src, 0x0800, ip)
}

/// Ethernet frame (EtherType 0x86dd) around an IPv6 packet.
pub fn eth_ipv6(dst: [u8; 6], src: [u8; 6], ip: &[u8]) -> Vec<u8> {
    eth(dst, src, 0x86dd, ip)
}
