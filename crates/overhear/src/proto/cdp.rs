//! CDP presentation and observations.

use std::borrow::Cow;
use std::fmt::Write;

use overhear_decode::{Cdp, CdpTlv, Packet};

use crate::escape::{LINE_FIELD_MAX, TextKind, push_text};
use crate::json::JsonWriter;
use crate::observe::{NameSource, Observation, ProtoTag, Role};

pub fn tag() -> &'static str {
    "CDP"
}

const CAPS: [(u32, &str); 8] = [
    (0x01, "router"),
    (0x02, "trans-bridge"),
    (0x04, "source-route-bridge"),
    (0x08, "switch"),
    (0x10, "host"),
    (0x20, "igmp"),
    (0x40, "repeater"),
    (0x80, "phone"),
];

fn cap_names(mask: u32) -> impl Iterator<Item = &'static str> {
    CAPS.iter()
        .filter(move |(bit, _)| mask & bit != 0)
        .map(|(_, n)| *n)
}

fn find<'c, 'a, T>(c: &'c Cdp<'a>, f: impl Fn(&'c CdpTlv<'a>) -> Option<T>) -> Option<T> {
    c.tlvs.iter().find_map(f)
}

fn device_id<'a>(c: &Cdp<'a>) -> Option<&'a [u8]> {
    find(c, |t| match t {
        CdpTlv::DeviceId(d) => Some(*d),
        _ => None,
    })
}

fn port_id<'a>(c: &Cdp<'a>) -> Option<&'a [u8]> {
    find(c, |t| match t {
        CdpTlv::PortId(d) => Some(*d),
        _ => None,
    })
}

fn platform<'a>(c: &Cdp<'a>) -> Option<&'a [u8]> {
    find(c, |t| match t {
        CdpTlv::Platform(d) => Some(*d),
        _ => None,
    })
}

fn software<'a>(c: &Cdp<'a>) -> Option<&'a [u8]> {
    find(c, |t| match t {
        CdpTlv::Software(d) => Some(*d),
        _ => None,
    })
}

fn capabilities(c: &Cdp<'_>) -> Option<u32> {
    find(c, |t| match t {
        CdpTlv::Capabilities(m) => Some(*m),
        _ => None,
    })
}

fn native_vlan(c: &Cdp<'_>) -> Option<u16> {
    find(c, |t| match t {
        CdpTlv::NativeVlan(v) => Some(*v),
        _ => None,
    })
}

fn field(out: &mut String, b: &[u8]) {
    push_text(out, b, TextKind::Utf8, LINE_FIELD_MAX);
}

/// `{device id} port {port} platform {platform}`; parts the message lacks
/// are left out.
pub fn summary(c: &Cdp<'_>, out: &mut String) {
    if let Some(d) = device_id(c) {
        field(out, d);
    }
    if let Some(p) = port_id(c) {
        out.push_str(if out.is_empty() { "port " } else { " port " });
        field(out, p);
    }
    if let Some(p) = platform(c) {
        out.push_str(if out.is_empty() {
            "platform "
        } else {
            " platform "
        });
        field(out, p);
    }
}

fn push_hex(out: &mut String, b: &[u8]) {
    for x in b {
        let _ = write!(out, "{x:02x}");
    }
}

fn duplex(d: u8) -> &'static str {
    if d == 0 { "half" } else { "full" }
}

pub fn verbose(c: &Cdp<'_>, out: &mut String) {
    let _ = writeln!(out, "  {:<6}version {} ttl {}", tag(), c.version, c.ttl);
    let all = usize::MAX;
    for t in &c.tlvs {
        out.push_str("        ");
        match t {
            CdpTlv::DeviceId(d) => {
                out.push_str("device-id ");
                push_text(out, d, TextKind::Utf8, all);
            }
            CdpTlv::Addresses(a) => {
                out.push_str("addresses");
                for ip in a {
                    let _ = write!(out, " {ip}");
                }
            }
            CdpTlv::PortId(d) => {
                out.push_str("port-id ");
                push_text(out, d, TextKind::Utf8, all);
            }
            CdpTlv::Capabilities(m) => {
                let _ = write!(out, "capabilities 0x{m:08x}");
                for n in cap_names(*m) {
                    let _ = write!(out, " {n}");
                }
            }
            CdpTlv::Software(d) => {
                out.push_str("software ");
                push_text(out, d, TextKind::Utf8, all);
            }
            CdpTlv::Platform(d) => {
                out.push_str("platform ");
                push_text(out, d, TextKind::Utf8, all);
            }
            CdpTlv::NativeVlan(v) => {
                let _ = write!(out, "native-vlan {v}");
            }
            CdpTlv::Duplex(d) => {
                let _ = write!(out, "duplex {}", duplex(*d));
            }
            CdpTlv::VtpDomain(d) => {
                out.push_str("vtp-domain ");
                push_text(out, d, TextKind::Utf8, all);
            }
            CdpTlv::Other { typ, data } => {
                let _ = write!(out, "tlv 0x{typ:02x} data ");
                push_hex(out, data);
            }
        }
        out.push('\n');
    }
}

pub fn json(c: &Cdp<'_>, w: &mut JsonWriter) {
    w.obj(Some("cdp"));
    w.u64(Some("version"), u64::from(c.version));
    w.u64(Some("ttl"), u64::from(c.ttl));
    w.arr(Some("tlvs"));
    for t in &c.tlvs {
        w.obj(None);
        let text = |w: &mut JsonWriter, name: &str, d: &[u8]| {
            w.str(Some("type"), name);
            w.text("value", d, TextKind::Utf8);
        };
        match t {
            CdpTlv::DeviceId(d) => text(w, "device-id", d),
            CdpTlv::Addresses(a) => {
                w.str(Some("type"), "addresses");
                w.arr(Some("addrs"));
                for ip in a {
                    w.str(None, &ip.to_string());
                }
                w.end();
            }
            CdpTlv::PortId(d) => text(w, "port-id", d),
            CdpTlv::Capabilities(m) => {
                w.str(Some("type"), "capabilities");
                w.u64(Some("value"), u64::from(*m));
                w.arr(Some("names"));
                for n in cap_names(*m) {
                    w.str(None, n);
                }
                w.end();
            }
            CdpTlv::Software(d) => text(w, "software", d),
            CdpTlv::Platform(d) => text(w, "platform", d),
            CdpTlv::NativeVlan(v) => {
                w.str(Some("type"), "native-vlan");
                w.u64(Some("vlan"), u64::from(*v));
            }
            CdpTlv::Duplex(d) => {
                w.str(Some("type"), "duplex");
                w.str(Some("value"), duplex(*d));
            }
            CdpTlv::VtpDomain(d) => text(w, "vtp-domain", d),
            CdpTlv::Other { typ, data } => {
                w.str(Some("type"), "other");
                w.u64(Some("code"), u64::from(*typ));
                w.hex(Some("data_hex"), data);
            }
        }
        w.end();
    }
    w.end();
    w.end();
}

/// The device id and platform, the role the capability bits imply (switch,
/// phone), and the software, port and native VLAN as details.
pub fn observe<'a>(p: &Packet<'a>, c: &Cdp<'a>, out: &mut Vec<Observation<'a>>) {
    let mac = p.eth.src;
    out.push(Observation::Heard {
        mac,
        proto: ProtoTag::Cdp,
    });
    if let Some(n) = device_id(c).filter(|n| !n.is_empty()) {
        out.push(Observation::Name {
            mac,
            name: Cow::Borrowed(n),
            source: NameSource::Cdp,
        });
    }
    if let Some(m) = platform(c).filter(|m| !m.is_empty()) {
        out.push(Observation::Model {
            mac,
            text: Cow::Borrowed(m),
        });
    }
    let caps = capabilities(c).unwrap_or(0);
    for (bit, role) in [(0x08, Role::Bridge), (0x80, Role::Phone)] {
        if caps & bit != 0 {
            out.push(Observation::Role { mac, role });
        }
    }
    let mut detail = |key: &'static str, value: Cow<'a, [u8]>| {
        if !value.is_empty() {
            out.push(Observation::Detail { mac, key, value });
        }
    };
    if let Some(s) = software(c) {
        detail("software", Cow::Borrowed(s));
    }
    if let Some(s) = port_id(c) {
        detail("port", Cow::Borrowed(s));
    }
    if let Some(v) = native_vlan(c) {
        detail("native-vlan", Cow::Owned(v.to_string().into_bytes()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overhear_decode::{Mac, Proto, decode};
    use overhear_testgen::{cdp as build, mac, snap};

    const MCAST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];

    fn addresses() -> Vec<u8> {
        let mut v = 1u32.to_be_bytes().to_vec();
        v.extend_from_slice(&[1, 1, 0xcc, 0, 4, 10, 0, 0, 2]);
        v
    }

    fn switch() -> Vec<(u16, Vec<u8>)> {
        vec![
            (1, b"sw1.example".to_vec()),
            (2, addresses()),
            (3, b"GigabitEthernet1/0/1".to_vec()),
            (4, 0x28u32.to_be_bytes().to_vec()),
            (5, b"IOS 15.2".to_vec()),
            (6, b"cisco WS-C2960".to_vec()),
            (9, b"corp".to_vec()),
            (0x0a, 10u16.to_be_bytes().to_vec()),
            (0x0b, vec![1]),
        ]
    }

    fn with<R>(src: u8, tlvs: &[(u16, Vec<u8>)], f: impl FnOnce(&Packet<'_>, &Cdp<'_>) -> R) -> R {
        let fr = snap(MCAST, mac(src), [0, 0, 0x0c], 0x2000, &build(tlvs));
        let p = decode(&fr).unwrap();
        let Proto::Cdp(c) = &p.proto else {
            panic!("not cdp: {:?}", p.proto)
        };
        f(&p, c)
    }

    fn line(tlvs: &[(u16, Vec<u8>)]) -> String {
        with(1, tlvs, |_, c| {
            let mut s = String::new();
            summary(c, &mut s);
            s
        })
    }

    #[test]
    fn exact_summaries() {
        assert_eq!(
            line(&switch()),
            "sw1.example port GigabitEthernet1/0/1 platform cisco WS-C2960"
        );
        assert_eq!(line(&[(1, b"sw1".to_vec())]), "sw1");
        assert_eq!(
            line(&[(1, b"sw\x1b1".to_vec()), (6, b"p".to_vec())]),
            "sw\\x1b1 platform p"
        );
    }

    fn detail(m: Mac, key: &'static str, v: &str) -> Observation<'static> {
        Observation::Detail {
            mac: m,
            key,
            value: Cow::Owned(v.as_bytes().to_vec()),
        }
    }

    fn obs(src: u8, tlvs: &[(u16, Vec<u8>)]) -> Vec<Observation<'static>> {
        with(src, tlvs, |p, c| {
            let mut out = Vec::new();
            observe(p, c, &mut out);
            out.into_iter()
                .map(|o| match o {
                    Observation::Heard { mac, proto } => Observation::Heard { mac, proto },
                    Observation::Name { mac, name, source } => Observation::Name {
                        mac,
                        name: Cow::Owned(name.into_owned()),
                        source,
                    },
                    Observation::Model { mac, text } => Observation::Model {
                        mac,
                        text: Cow::Owned(text.into_owned()),
                    },
                    Observation::Role { mac, role } => Observation::Role { mac, role },
                    Observation::Detail { mac, key, value } => Observation::Detail {
                        mac,
                        key,
                        value: Cow::Owned(value.into_owned()),
                    },
                    other => panic!("unexpected {other:?}"),
                })
                .collect()
        })
    }

    #[test]
    fn switch_observations() {
        let m = Mac(mac(5));
        assert_eq!(
            obs(5, &switch()),
            vec![
                Observation::Heard {
                    mac: m,
                    proto: ProtoTag::Cdp
                },
                Observation::Name {
                    mac: m,
                    name: Cow::Owned(b"sw1.example".to_vec()),
                    source: NameSource::Cdp
                },
                Observation::Model {
                    mac: m,
                    text: Cow::Owned(b"cisco WS-C2960".to_vec())
                },
                Observation::Role {
                    mac: m,
                    role: Role::Bridge
                },
                detail(m, "software", "IOS 15.2"),
                detail(m, "port", "GigabitEthernet1/0/1"),
                detail(m, "native-vlan", "10"),
            ]
        );
    }

    #[test]
    fn phone_role_and_no_role_for_others() {
        let role = |caps: u32| {
            obs(1, &[(1, b"x".to_vec()), (4, caps.to_be_bytes().to_vec())])
                .into_iter()
                .find_map(|o| match o {
                    Observation::Role { role, .. } => Some(role),
                    _ => None,
                })
        };
        assert_eq!(role(0x80), Some(Role::Phone));
        assert_eq!(role(0x08), Some(Role::Bridge));
        assert_eq!(role(0x01), None);
        assert_eq!(role(0x10), None);
    }

    #[test]
    fn verbose_lists_tlvs() {
        let t = vec![
            (1, b"sw\x1b".to_vec()),
            (2, addresses()),
            (4, 0x28u32.to_be_bytes().to_vec()),
            (0x0a, 10u16.to_be_bytes().to_vec()),
            (0x0b, vec![0]),
            (0x1f, vec![0xca, 0xfe]),
        ];
        let s = with(1, &t, |_, c| {
            let mut s = String::new();
            verbose(c, &mut s);
            s
        });
        assert_eq!(
            s,
            "  CDP   version 2 ttl 180\n\
             \x20       device-id sw\\x1b\n\
             \x20       addresses 10.0.0.2\n\
             \x20       capabilities 0x00000028 switch igmp\n\
             \x20       native-vlan 10\n\
             \x20       duplex half\n\
             \x20       tlv 0x1f data cafe\n"
        );
    }

    #[test]
    fn json_object() {
        let t = vec![
            (1, b"sw\xff".to_vec()),
            (2, addresses()),
            (3, b"Gi1".to_vec()),
            (4, 0x28u32.to_be_bytes().to_vec()),
            (0x0a, 10u16.to_be_bytes().to_vec()),
            (0x0b, vec![1]),
            (0x1f, vec![0xca, 0xfe]),
        ];
        let s = with(1, &t, |_, c| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(c, &mut w);
            w.end();
            w.as_str().to_string()
        });
        assert_eq!(
            s,
            concat!(
                r#"{"cdp":{"version":2,"ttl":180,"tlvs":["#,
                r#"{"type":"device-id","value_hex":"7377ff"},"#,
                r#"{"type":"addresses","addrs":["10.0.0.2"]},"#,
                r#"{"type":"port-id","value":"Gi1"},"#,
                r#"{"type":"capabilities","value":40,"names":["switch","igmp"]},"#,
                r#"{"type":"native-vlan","vlan":10},"#,
                r#"{"type":"duplex","value":"full"},"#,
                r#"{"type":"other","code":31,"data_hex":"cafe"}"#,
                r#"]}}"#
            )
        );
    }
}
