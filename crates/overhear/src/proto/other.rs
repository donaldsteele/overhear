//! Packets no protocol decoder claimed.

use std::fmt::Write;
use std::net::IpAddr;

use overhear_decode::{EthKind, Frag, IpHeader, L4, Packet};

use crate::json::JsonWriter;

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
                        let hp = match dst {
                            IpAddr::V4(a) => format!("{a}:{}", u.dst_port),
                            IpAddr::V6(a) => format!("[{a}]:{}", u.dst_port),
                        };
                        write!(out, "UDP {} → {hp} ({n} bytes)", u.src_port)
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

pub fn verbose(n: usize, _frame: &[u8], out: &mut String) {
    let _ = writeln!(out, "  DATA  {n} bytes");
}

pub fn json(p: &Packet<'_>, n: usize, w: &mut JsonWriter) {
    w.obj(Some("other"));
    match p.eth.kind {
        EthKind::EtherType(t) => w.u64(Some("ethertype"), u64::from(t)),
        EthKind::Llc { dsap, ssap, ctrl } => {
            w.obj(Some("llc"));
            w.u64(Some("dsap"), u64::from(dsap));
            w.u64(Some("ssap"), u64::from(ssap));
            w.u64(Some("ctrl"), u64::from(ctrl));
            w.end();
        }
        EthKind::Snap { oui, pid } => {
            w.obj(Some("snap"));
            w.hex(Some("oui"), &oui);
            w.u64(Some("pid"), u64::from(pid));
            w.end();
        }
    }
    match p.ip {
        Some(IpHeader::V4(h)) => w.u64(Some("ip_proto"), u64::from(h.proto)),
        Some(IpHeader::V6(h)) => w.u64(Some("ip_proto"), u64::from(h.next)),
        None => {}
    }
    match p.l4 {
        L4::Udp(u) => {
            w.u64(Some("src_port"), u64::from(u.src_port));
            w.u64(Some("dst_port"), u64::from(u.dst_port));
        }
        L4::Icmpv6 { typ, code } => {
            w.u64(Some("icmp6_type"), u64::from(typ));
            w.u64(Some("icmp6_code"), u64::from(code));
        }
        L4::None => {}
    }
    w.u64(Some("payload_len"), u64::try_from(n).unwrap_or(u64::MAX));
    w.end();
}
