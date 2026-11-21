//! Packets no protocol decoder claimed.

use std::fmt::Write;

use overhear_decode::{EthKind, Frag, IpHeader, L4, Packet};

pub fn tag(p: &Packet<'_>) -> &'static str {
    match p.ip {
        Some(ip) => {
            if *ip.frag() == Frag::Later {
                return ip_tag(&ip);
            }
            match p.l4 {
                L4::Udp(_) => "UDP",
                L4::Icmpv6 { .. } => "ICMP6",
                L4::None => ip_tag(&ip),
            }
        }
        None => match p.eth.kind {
            EthKind::EtherType(_) => "ETH",
            EthKind::Llc { .. } => "LLC",
            EthKind::Snap { .. } => "SNAP",
        },
    }
}

fn ip_tag(ip: &IpHeader) -> &'static str {
    match ip {
        IpHeader::V4(_) => "IPv4",
        IpHeader::V6(_) => "IPv6",
    }
}

/// `n` is the payload length left over after decoding.
pub fn summary(p: &Packet<'_>, n: usize, out: &mut String) {
    let _ = match p.ip {
        Some(ip) => {
            let dst = ip.dst();
            if *ip.frag() == Frag::Later {
                write!(out, "fragment → {dst} ({n} bytes)")
            } else {
                match (p.l4, ip) {
                    (L4::Udp(u), _) => {
                        write!(out, "UDP {} → {dst}:{} ({n} bytes)", u.src_port, u.dst_port)
                    }
                    (L4::Icmpv6 { typ, code }, _) => {
                        write!(out, "type {typ} code {code} → {dst}")
                    }
                    (L4::None, IpHeader::V4(h)) => {
                        write!(out, "proto {} → {dst} ({n} bytes)", h.proto)
                    }
                    (L4::None, IpHeader::V6(h)) => {
                        write!(out, "next header {} → {dst} ({n} bytes)", h.next)
                    }
                }
            }
        }
        None => match p.eth.kind {
            EthKind::EtherType(t) => write!(out, "ethertype 0x{t:04x} → {} ({n} bytes)", p.eth.dst),
            EthKind::Llc { dsap, ssap, .. } => {
                write!(out, "dsap 0x{dsap:02x} ssap 0x{ssap:02x} → {}", p.eth.dst)
            }
            EthKind::Snap { oui, pid } => write!(
                out,
                "oui {:02x}{:02x}{:02x} pid 0x{pid:04x} → {}",
                oui[0], oui[1], oui[2], p.eth.dst
            ),
        },
    };
}
