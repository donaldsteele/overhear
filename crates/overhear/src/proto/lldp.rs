//! LLDP presentation and observations.

use std::borrow::Cow;
use std::fmt::Write;
use std::net::IpAddr;

use overhear_decode::{Lldp, LldpTlv, Mac, Packet};

use crate::escape::{LINE_FIELD_MAX, TextKind, push_text};
use crate::json::JsonWriter;
use crate::observe::{NameSource, Observation, ProtoTag, Role};

pub fn tag() -> &'static str {
    "LLDP"
}

const CAPS: [&str; 8] = [
    "other", "repeater", "bridge", "ap", "router", "phone", "docsis", "station",
];
const CAP_BRIDGE: u16 = 1 << 2;
const CAP_AP: u16 = 1 << 3;
const CAP_PHONE: u16 = 1 << 5;

fn cap_names(mask: u16) -> impl Iterator<Item = &'static str> {
    CAPS.iter()
        .enumerate()
        .filter(move |(i, _)| mask & (1 << i) != 0)
        .map(|(_, n)| *n)
}

/// An identifier as shown to the user.
enum View<'a> {
    Mac(Mac),
    Ip(IpAddr),
    Text(&'a [u8]),
    Hex(&'a [u8]),
}

/// A network address as chassis subtype 5 or port subtype 4 carry it: an
/// address family byte, then the address.
fn net_addr(id: &[u8]) -> Option<IpAddr> {
    match id.split_first()? {
        (1, a) => <[u8; 4]>::try_from(a).ok().map(IpAddr::from),
        (2, a) => <[u8; 16]>::try_from(a).ok().map(IpAddr::from),
        _ => None,
    }
}

/// `mac` and `net` are the subtypes meaning a MAC address and a network
/// address for this kind of identifier. Anything that does not fit its
/// subtype is shown as text.
fn view(subtype: u8, id: &[u8], mac: u8, net: u8) -> View<'_> {
    if subtype == mac {
        if let Some(m) = Mac::from_slice(id) {
            return View::Mac(m);
        }
    }
    if subtype == net {
        if let Some(ip) = net_addr(id) {
            return View::Ip(ip);
        }
    }
    View::Text(id)
}

fn chassis_view(subtype: u8, id: &[u8]) -> View<'_> {
    view(subtype, id, 4, 5)
}

fn port_view(subtype: u8, id: &[u8]) -> View<'_> {
    view(subtype, id, 3, 4)
}

fn mgmt_view(subtype: u8, addr: &[u8]) -> View<'_> {
    let ip = match (subtype, addr.len()) {
        (1, 4) => <[u8; 4]>::try_from(addr).ok().map(IpAddr::from),
        (2, 16) => <[u8; 16]>::try_from(addr).ok().map(IpAddr::from),
        _ => None,
    };
    if let Some(ip) = ip {
        return View::Ip(ip);
    }
    if subtype == 6 {
        if let Some(m) = Mac::from_slice(addr) {
            return View::Mac(m);
        }
    }
    View::Hex(addr)
}

fn push_view(out: &mut String, v: &View<'_>, max: usize) {
    match v {
        View::Mac(m) => {
            let _ = write!(out, "{m}");
        }
        View::Ip(ip) => {
            let _ = write!(out, "{ip}");
        }
        View::Text(t) => push_text(out, t, TextKind::Utf8, max),
        View::Hex(h) => push_hex(out, h),
    }
}

fn push_hex(out: &mut String, b: &[u8]) {
    for x in b {
        let _ = write!(out, "{x:02x}");
    }
}

/// `{sysname or chassis id} port {port id}` and the enabled capabilities.
pub fn summary(l: &Lldp<'_>, out: &mut String) {
    match l.sysname().filter(|n| !n.is_empty()) {
        Some(n) => push_text(out, n, TextKind::Utf8, LINE_FIELD_MAX),
        None => {
            if let Some((s, id)) = l.chassis() {
                push_view(out, &chassis_view(s, id), LINE_FIELD_MAX);
            }
        }
    }
    if let Some((s, id)) = l.port() {
        out.push_str(" port ");
        push_view(out, &port_view(s, id), LINE_FIELD_MAX);
    }
    for n in cap_names(l.enabled()) {
        out.push(' ');
        out.push_str(n);
    }
}

fn push_caps(out: &mut String, mask: u16) {
    for (i, n) in cap_names(mask).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(n);
    }
}

pub fn verbose(l: &Lldp<'_>, out: &mut String) {
    for (i, t) in l.tlvs.iter().enumerate() {
        out.push_str(if i == 0 { "  LLDP  " } else { "        " });
        let all = usize::MAX;
        match t {
            LldpTlv::ChassisId { subtype, id } => {
                out.push_str("chassis ");
                push_view(out, &chassis_view(*subtype, id), all);
                let _ = write!(out, " subtype {subtype}");
            }
            LldpTlv::PortId { subtype, id } => {
                out.push_str("port ");
                push_view(out, &port_view(*subtype, id), all);
                let _ = write!(out, " subtype {subtype}");
            }
            LldpTlv::Ttl(s) => {
                let _ = write!(out, "ttl {s}");
            }
            LldpTlv::PortDescr(d) => {
                out.push_str("port-descr ");
                push_text(out, d, TextKind::Utf8, all);
            }
            LldpTlv::SysName(d) => {
                out.push_str("sysname ");
                push_text(out, d, TextKind::Utf8, all);
            }
            LldpTlv::SysDescr(d) => {
                out.push_str("sysdescr ");
                push_text(out, d, TextKind::Utf8, all);
            }
            LldpTlv::Capabilities { system, enabled } => {
                out.push_str("capabilities ");
                push_caps(out, *system);
                out.push_str(" enabled ");
                push_caps(out, *enabled);
            }
            LldpTlv::MgmtAddr { subtype, addr } => {
                out.push_str("mgmt ");
                push_view(out, &mgmt_view(*subtype, addr), all);
                let _ = write!(out, " subtype {subtype}");
            }
            LldpTlv::PortVlan(v) => {
                let _ = write!(out, "port-vlan {v}");
            }
            LldpTlv::Org { oui, subtype, data } => {
                let [a, b, c] = oui;
                let _ = write!(out, "org {a:02x}:{b:02x}:{c:02x} subtype {subtype} data ");
                push_hex(out, data);
            }
            LldpTlv::Other { typ, data } => {
                let _ = write!(out, "tlv {typ} data ");
                push_hex(out, data);
            }
        }
        out.push('\n');
    }
}

fn json_view(w: &mut JsonWriter, key: &str, v: &View<'_>) {
    match v {
        View::Mac(m) => w.mac(Some(key), *m),
        View::Ip(ip) => w.ip(Some(key), *ip),
        View::Text(t) => w.text(key, t, TextKind::Utf8),
        View::Hex(h) => {
            let k = format!("{key}_hex");
            w.hex(Some(&k), h);
        }
    }
}

fn json_caps(w: &mut JsonWriter, key: &str, mask: u16) {
    w.arr(Some(key));
    for n in cap_names(mask) {
        w.str(None, n);
    }
    w.end();
}

pub fn json(l: &Lldp<'_>, w: &mut JsonWriter) {
    w.obj(Some("lldp"));
    w.arr(Some("tlvs"));
    for t in &l.tlvs {
        w.obj(None);
        match t {
            LldpTlv::ChassisId { subtype, id } => {
                w.str(Some("type"), "chassis");
                w.u64(Some("subtype"), u64::from(*subtype));
                json_view(w, "id", &chassis_view(*subtype, id));
            }
            LldpTlv::PortId { subtype, id } => {
                w.str(Some("type"), "port");
                w.u64(Some("subtype"), u64::from(*subtype));
                json_view(w, "id", &port_view(*subtype, id));
            }
            LldpTlv::Ttl(s) => {
                w.str(Some("type"), "ttl");
                w.u64(Some("seconds"), u64::from(*s));
            }
            LldpTlv::PortDescr(d) => {
                w.str(Some("type"), "port-descr");
                w.text("value", d, TextKind::Utf8);
            }
            LldpTlv::SysName(d) => {
                w.str(Some("type"), "sysname");
                w.text("value", d, TextKind::Utf8);
            }
            LldpTlv::SysDescr(d) => {
                w.str(Some("type"), "sysdescr");
                w.text("value", d, TextKind::Utf8);
            }
            LldpTlv::Capabilities { system, enabled } => {
                w.str(Some("type"), "capabilities");
                json_caps(w, "system", *system);
                json_caps(w, "enabled", *enabled);
            }
            LldpTlv::MgmtAddr { subtype, addr } => {
                w.str(Some("type"), "mgmt");
                w.u64(Some("subtype"), u64::from(*subtype));
                json_view(w, "addr", &mgmt_view(*subtype, addr));
            }
            LldpTlv::PortVlan(v) => {
                w.str(Some("type"), "port-vlan");
                w.u64(Some("vlan"), u64::from(*v));
            }
            LldpTlv::Org { oui, subtype, data } => {
                let [a, b, c] = oui;
                w.str(Some("type"), "org");
                w.str(Some("oui"), &format!("{a:02x}:{b:02x}:{c:02x}"));
                w.u64(Some("subtype"), u64::from(*subtype));
                w.hex(Some("data_hex"), data);
            }
            LldpTlv::Other { typ, data } => {
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

fn shown(v: &View<'_>) -> Vec<u8> {
    if let View::Text(t) = v {
        return t.to_vec();
    }
    let mut s = String::new();
    push_view(&mut s, v, usize::MAX);
    s.into_bytes()
}

/// The system name and description, the roles the enabled capabilities
/// imply (the router capability is informational only), and the port,
/// management address and port VLAN as details.
pub fn observe<'a>(p: &Packet<'a>, l: &Lldp<'a>, out: &mut Vec<Observation<'a>>) {
    let mac = p.eth.src;
    out.push(Observation::Heard {
        mac,
        proto: ProtoTag::Lldp,
    });
    if let Some(n) = l.sysname().filter(|n| !n.is_empty()) {
        out.push(Observation::Name {
            mac,
            name: Cow::Borrowed(n),
            source: NameSource::Lldp,
        });
    }
    if let Some(d) = l.sysdescr().filter(|d| !d.is_empty()) {
        out.push(Observation::Model {
            mac,
            text: Cow::Borrowed(d),
        });
    }
    let enabled = l.enabled();
    for (bit, role) in [
        (CAP_BRIDGE, Role::Bridge),
        (CAP_AP, Role::AccessPoint),
        (CAP_PHONE, Role::Phone),
    ] {
        if enabled & bit != 0 {
            out.push(Observation::Role { mac, role });
        }
    }
    let mut detail = |key: &'static str, value: Vec<u8>| {
        if !value.is_empty() {
            out.push(Observation::Detail {
                mac,
                key,
                value: Cow::Owned(value),
            });
        }
    };
    if let Some((s, id)) = l.port() {
        detail("port", shown(&port_view(s, id)));
    }
    let mgmt = l.tlvs.iter().find_map(|t| match t {
        LldpTlv::MgmtAddr { subtype, addr } => Some((*subtype, *addr)),
        _ => None,
    });
    if let Some((s, a)) = mgmt {
        detail("mgmt", shown(&mgmt_view(s, a)));
    }
    let vlan = l.tlvs.iter().find_map(|t| match t {
        LldpTlv::PortVlan(v) => Some(*v),
        _ => None,
    });
    if let Some(v) = vlan {
        detail("vlan", v.to_string().into_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use overhear_decode::{Proto, decode};
    use overhear_testgen::{eth, lldp as build, mac};

    const MCAST: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 0x0e];

    fn chassis_mac(n: u8) -> (u8, Vec<u8>) {
        (1, [&[4u8][..], &mac(n)].concat())
    }

    fn port(sub: u8, id: &[u8]) -> (u8, Vec<u8>) {
        (2, [&[sub][..], id].concat())
    }

    fn ttl() -> (u8, Vec<u8>) {
        (3, 120u16.to_be_bytes().to_vec())
    }

    fn caps(system: u16, enabled: u16) -> (u8, Vec<u8>) {
        let mut v = system.to_be_bytes().to_vec();
        v.extend_from_slice(&enabled.to_be_bytes());
        (7, v)
    }

    fn switch() -> Vec<(u8, Vec<u8>)> {
        vec![
            chassis_mac(1),
            port(5, b"Gi1/0/24"),
            ttl(),
            (4, b"uplink".to_vec()),
            (5, b"core-sw1".to_vec()),
            (6, b"Acme OS 1.0".to_vec()),
            caps(0x34, 0x14),
            (8, vec![5, 1, 192, 168, 1, 2, 1, 0, 0, 0, 1, 0]),
            (127, vec![0x00, 0x80, 0xc2, 1, 0, 10]),
        ]
    }

    fn with<R>(src: u8, tlvs: &[(u8, Vec<u8>)], f: impl FnOnce(&Packet<'_>, &Lldp<'_>) -> R) -> R {
        let fr = eth(MCAST, mac(src), 0x88cc, &build(tlvs));
        let p = decode(&fr).unwrap();
        let Proto::Lldp(l) = &p.proto else {
            panic!("not lldp: {:?}", p.proto)
        };
        f(&p, l)
    }

    fn line(tlvs: &[(u8, Vec<u8>)]) -> String {
        with(1, tlvs, |_, l| {
            let mut s = String::new();
            summary(l, &mut s);
            s
        })
    }

    #[test]
    fn exact_summaries() {
        assert_eq!(line(&switch()), "core-sw1 port Gi1/0/24 bridge router");
        let no_caps = vec![
            chassis_mac(1),
            port(5, b"eth0"),
            ttl(),
            (5, b"ap-1".to_vec()),
        ];
        assert_eq!(line(&no_caps), "ap-1 port eth0");
        let ap = vec![
            chassis_mac(2),
            port(5, b"eth0"),
            ttl(),
            (5, b"ap-1".to_vec()),
            caps(0x1c, 0x0c),
        ];
        assert_eq!(line(&ap), "ap-1 port eth0 bridge ap");
    }

    #[test]
    fn summary_without_sysname_uses_chassis_id() {
        let t = vec![chassis_mac(7), port(3, &mac(8)), ttl()];
        assert_eq!(line(&t), "02:00:5e:10:00:07 port 02:00:5e:10:00:08");
        let ip = (1, vec![5, 1, 10, 0, 0, 9]);
        let t = vec![
            ip,
            port(
                4,
                &[2, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
            ttl(),
        ];
        assert_eq!(line(&t), "10.0.0.9 port fe80::1");
        let t = vec![
            (1, vec![7, b'x', 0x1b]),
            port(7, b"p"),
            ttl(),
            caps(0xff, 0xff),
        ];
        assert_eq!(
            line(&t),
            "x\\x1b port p other repeater bridge ap router phone docsis station"
        );
    }

    #[test]
    fn summary_text_is_escaped_and_cut() {
        let t = vec![
            chassis_mac(1),
            port(5, b"p"),
            ttl(),
            (5, b"evil\x1b[2Jname".to_vec()),
        ];
        assert_eq!(line(&t), "evil\\x1b[2Jname port p");
        let long = vec![b'a'; 300];
        let t = vec![chassis_mac(1), port(5, b"p"), ttl(), (5, long)];
        assert!(line(&t).starts_with(&format!("{}…", "a".repeat(LINE_FIELD_MAX - 1))));
    }

    fn own(o: Vec<Observation<'_>>) -> Vec<Observation<'static>> {
        o.into_iter()
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
    }

    fn obs(src: u8, tlvs: &[(u8, Vec<u8>)]) -> Vec<Observation<'static>> {
        with(src, tlvs, |p, l| {
            let mut out = Vec::new();
            observe(p, l, &mut out);
            own(out)
        })
    }

    fn detail(m: Mac, key: &'static str, v: &str) -> Observation<'static> {
        Observation::Detail {
            mac: m,
            key,
            value: Cow::Owned(v.as_bytes().to_vec()),
        }
    }

    #[test]
    fn switch_observations() {
        let m = Mac(mac(5));
        assert_eq!(
            obs(5, &switch()),
            vec![
                Observation::Heard {
                    mac: m,
                    proto: ProtoTag::Lldp
                },
                Observation::Name {
                    mac: m,
                    name: Cow::Owned(b"core-sw1".to_vec()),
                    source: NameSource::Lldp
                },
                Observation::Model {
                    mac: m,
                    text: Cow::Owned(b"Acme OS 1.0".to_vec())
                },
                Observation::Role {
                    mac: m,
                    role: Role::Bridge
                },
                detail(m, "port", "Gi1/0/24"),
                detail(m, "mgmt", "192.168.1.2"),
                detail(m, "vlan", "10"),
            ]
        );
    }

    #[test]
    fn ap_and_phone_roles_and_router_is_not_a_role() {
        let roles = |enabled: u16| -> Vec<Role> {
            let t = vec![chassis_mac(1), port(5, b"p"), ttl(), caps(0xff, enabled)];
            obs(1, &t)
                .into_iter()
                .filter_map(|o| match o {
                    Observation::Role { role, .. } => Some(role),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(roles(0x08), vec![Role::AccessPoint]);
        assert_eq!(roles(0x20), vec![Role::Phone]);
        assert_eq!(roles(0x10), vec![]);
        assert_eq!(
            roles(0x2c),
            vec![Role::Bridge, Role::AccessPoint, Role::Phone]
        );
        assert_eq!(roles(0x01), vec![]);
    }

    #[test]
    fn minimal_unit_only_hears_and_reports_port() {
        let m = Mac(mac(5));
        let t = vec![chassis_mac(1), port(5, b"p1"), ttl()];
        assert_eq!(
            obs(5, &t),
            vec![
                Observation::Heard {
                    mac: m,
                    proto: ProtoTag::Lldp
                },
                detail(m, "port", "p1"),
            ]
        );
    }

    #[test]
    fn verbose_shows_org_tlv_in_hex() {
        let t = vec![
            chassis_mac(3),
            port(3, &mac(4)),
            ttl(),
            (5, b"phone\x1b".to_vec()),
            (127, vec![0x00, 0x12, 0xbb, 1, 0x00, 0x33, 0x01]),
            (127, vec![0x00, 0x80, 0xc2, 1, 0, 20]),
            (9, vec![0xde, 0xad]),
        ];
        let s = with(1, &t, |_, l| {
            let mut s = String::new();
            verbose(l, &mut s);
            s
        });
        assert_eq!(
            s,
            "  LLDP  chassis 02:00:5e:10:00:03 subtype 4\n\
             \x20       port 02:00:5e:10:00:04 subtype 3\n\
             \x20       ttl 120\n\
             \x20       sysname phone\\x1b\n\
             \x20       org 00:12:bb subtype 1 data 003301\n\
             \x20       port-vlan 20\n\
             \x20       tlv 9 data dead\n"
        );
    }

    fn json_of(tlvs: &[(u8, Vec<u8>)]) -> String {
        with(1, tlvs, |_, l| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(l, &mut w);
            w.end();
            w.as_str().to_string()
        })
    }

    #[test]
    fn json_object() {
        let t = vec![
            chassis_mac(1),
            port(5, b"Gi1"),
            ttl(),
            (5, b"a\xffb".to_vec()),
            caps(0x14, 0x04),
            (8, vec![5, 1, 10, 0, 0, 1, 1, 0, 0, 0, 1, 0]),
            (127, vec![0x00, 0x80, 0xc2, 1, 0, 20]),
            (127, vec![0x00, 0x12, 0xbb, 1, 0x01]),
        ];
        assert_eq!(
            json_of(&t),
            concat!(
                r#"{"lldp":{"tlvs":["#,
                r#"{"type":"chassis","subtype":4,"id":"02:00:5e:10:00:01"},"#,
                r#"{"type":"port","subtype":5,"id":"Gi1"},"#,
                r#"{"type":"ttl","seconds":120},"#,
                r#"{"type":"sysname","value_hex":"61ff62"},"#,
                r#"{"type":"capabilities","system":["bridge","router"],"enabled":["bridge"]},"#,
                r#"{"type":"mgmt","subtype":1,"addr":"10.0.0.1"},"#,
                r#"{"type":"port-vlan","vlan":20},"#,
                r#"{"type":"org","oui":"00:12:bb","subtype":1,"data_hex":"01"}"#,
                r#"]}}"#
            )
        );
    }
}
