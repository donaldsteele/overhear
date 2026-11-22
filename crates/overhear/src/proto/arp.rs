//! ARP presentation and observations.

use std::fmt::{self, Write};
use std::net::IpAddr;

use overhear_decode::{Arp, ArpKind, Packet};

use crate::json::JsonWriter;
use crate::observe::{Observation, ProtoTag};

/// Name of the kind in verbose and JSON output.
struct Kind(ArpKind);

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ArpKind::Request => "request",
            ArpKind::Reply => "reply",
            ArpKind::Probe => "probe",
            ArpKind::Announcement => "announcement",
            ArpKind::Other(_) => "other",
        })
    }
}

pub fn tag() -> &'static str {
    "ARP"
}

pub fn summary(a: &Arp, out: &mut String) {
    let _ = match a.kind() {
        ArpKind::Request => write!(out, "who-has {} tell {}", a.tpa, a.spa),
        ArpKind::Reply => write!(out, "{} is-at {}", a.spa, a.sha),
        ArpKind::Probe => write!(out, "probe for {}", a.tpa),
        ArpKind::Announcement => write!(out, "announces {}", a.spa),
        ArpKind::Other(op) => write!(out, "op {op}"),
    };
}

pub fn verbose(p: &Packet<'_>, a: &Arp, out: &mut String) {
    let _ = writeln!(
        out,
        "  ARP   {} sender {} {} target {} {}",
        Kind(a.kind()),
        a.sha,
        a.spa,
        a.tha,
        a.tpa
    );
    if a.sha != p.eth.src {
        let _ = writeln!(
            out,
            "  !     sender MAC {} differs from frame source {}",
            a.sha, p.eth.src
        );
    }
}

pub fn json(a: &Arp, w: &mut JsonWriter) {
    w.obj(Some("arp"));
    w.u64(Some("op"), u64::from(a.op));
    w.str(Some("kind"), &Kind(a.kind()).to_string());
    w.mac(Some("sender_mac"), a.sha);
    w.ip(Some("sender_ip"), IpAddr::V4(a.spa));
    w.mac(Some("target_mac"), a.tha);
    w.ip(Some("target_ip"), IpAddr::V4(a.tpa));
    w.end();
}

/// The frame source was heard. Every kind but a probe (whose sender address is
/// 0.0.0.0) also says the sender MAC holds the sender IP.
pub fn observe<'a>(p: &Packet<'a>, a: &Arp, out: &mut Vec<Observation<'a>>) {
    out.push(Observation::Heard {
        mac: p.eth.src,
        proto: ProtoTag::Arp,
    });
    if a.kind() != ArpKind::Probe && !a.spa.is_unspecified() {
        let ip = IpAddr::V4(a.spa);
        out.push(Observation::Address { mac: a.sha, ip });
        out.push(Observation::Claim { mac: a.sha, ip });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overhear_decode::{Mac, Proto, decode};
    use overhear_testgen::{BCAST, arp as build, eth, mac};
    use std::net::Ipv4Addr;

    fn v4(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, d)
    }

    /// Runs `f` on the decoded ARP packet in a frame from `src`.
    fn with<R>(
        op: u16,
        src: [u8; 6],
        sha: [u8; 6],
        spa: Ipv4Addr,
        tpa: Ipv4Addr,
        f: impl FnOnce(&Packet<'_>, &Arp) -> R,
    ) -> R {
        let frame = eth(BCAST, src, 0x0806, &build(op, sha, spa, [0; 6], tpa));
        let p = decode(&frame).unwrap();
        let Proto::Arp(a) = &p.proto else {
            panic!("not arp")
        };
        f(&p, a)
    }

    fn line(op: u16, spa: Ipv4Addr, tpa: Ipv4Addr) -> String {
        with(op, mac(1), mac(1), spa, tpa, |_, a| {
            let mut s = String::new();
            summary(a, &mut s);
            s
        })
    }

    #[test]
    fn summaries_for_all_five_kinds() {
        assert_eq!(
            line(1, v4(5), v4(6)),
            "who-has 192.168.1.6 tell 192.168.1.5"
        );
        assert_eq!(line(2, v4(5), v4(6)), "192.168.1.5 is-at 02:00:5e:10:00:01");
        assert_eq!(
            line(1, Ipv4Addr::UNSPECIFIED, v4(6)),
            "probe for 192.168.1.6"
        );
        assert_eq!(line(1, v4(5), v4(5)), "announces 192.168.1.5");
        assert_eq!(line(9, v4(5), v4(6)), "op 9");
    }

    /// The observations of a packet from `mac(1)`, handed to `check`.
    fn obs(op: u16, spa: Ipv4Addr, tpa: Ipv4Addr, check: impl FnOnce(Vec<Observation<'_>>)) {
        with(op, mac(1), mac(1), spa, tpa, |p, a| {
            let mut out = Vec::new();
            observe(p, a, &mut out);
            check(out);
        })
    }

    #[test]
    fn probe_makes_no_claim() {
        obs(1, Ipv4Addr::UNSPECIFIED, v4(6), |o| {
            assert_eq!(
                o,
                vec![Observation::Heard {
                    mac: Mac(mac(1)),
                    proto: ProtoTag::Arp
                }]
            );
        });
    }

    #[test]
    fn request_claims_sender() {
        let ip = IpAddr::V4(v4(5));
        let m = Mac(mac(1));
        obs(1, v4(5), v4(6), |o| {
            assert_eq!(
                o,
                vec![
                    Observation::Heard {
                        mac: m,
                        proto: ProtoTag::Arp
                    },
                    Observation::Address { mac: m, ip },
                    Observation::Claim { mac: m, ip },
                ]
            );
        });
        for (op, tpa) in [(2, 6), (1, 5), (9, 6)] {
            obs(op, v4(5), v4(tpa), |o| assert_eq!(o.len(), 3));
        }
    }

    #[test]
    fn unspecified_sender_is_not_claimed() {
        obs(2, Ipv4Addr::UNSPECIFIED, v4(6), |o| assert_eq!(o.len(), 1));
    }

    #[test]
    fn verbose_flags_sender_mac_mismatch() {
        let text = |src| {
            with(1, src, mac(1), v4(5), v4(6), |p, a| {
                let mut s = String::new();
                verbose(p, a, &mut s);
                s
            })
        };
        let head = "  ARP   request sender 02:00:5e:10:00:01 192.168.1.5 target 00:00:00:00:00:00 192.168.1.6\n";
        assert_eq!(text(mac(1)), head);
        assert_eq!(
            text(mac(2)),
            format!(
                "{head}  !     sender MAC 02:00:5e:10:00:01 differs from frame source 02:00:5e:10:00:02\n"
            )
        );
    }

    #[test]
    fn json_object() {
        let s = with(2, mac(1), mac(1), v4(5), v4(6), |_, a| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(a, &mut w);
            w.end();
            w.as_str().to_string()
        });
        assert_eq!(
            s,
            r#"{"arp":{"op":2,"kind":"reply","sender_mac":"02:00:5e:10:00:01","sender_ip":"192.168.1.5","target_mac":"00:00:00:00:00:00","target_ip":"192.168.1.6"}}"#
        );
    }
}
