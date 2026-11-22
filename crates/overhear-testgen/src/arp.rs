//! ARP payload builder.

use std::net::Ipv4Addr;

/// An Ethernet/IPv4 ARP payload (28 bytes), without the Ethernet header.
pub fn arp(op: u16, sha: [u8; 6], spa: Ipv4Addr, tha: [u8; 6], tpa: Ipv4Addr) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&0x0800u16.to_be_bytes());
    p.extend_from_slice(&[6, 4]);
    p.extend_from_slice(&op.to_be_bytes());
    p.extend_from_slice(&sha);
    p.extend_from_slice(&spa.octets());
    p.extend_from_slice(&tha);
    p.extend_from_slice(&tpa.octets());
    p
}
