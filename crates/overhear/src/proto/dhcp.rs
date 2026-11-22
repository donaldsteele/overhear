//! DHCPv4 / BOOTP presentation and observations.

use std::borrow::Cow;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};

use overhear_decode::dhcp_opts::{OptType, check, enum_name, option_name, option_type};
use overhear_decode::{Dhcp, DhcpOption, Mac, OptSource, Packet};

use crate::escape::{LINE_FIELD_MAX, TextKind, is_json_text, push_text};
use crate::json::JsonWriter;
use crate::observe::{NameSource, Observation, ProtoTag, Role};

const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const DECLINE: u8 = 4;
const ACK: u8 = 5;
const NAK: u8 = 6;
const RELEASE: u8 = 7;
const INFORM: u8 = 8;

pub fn tag() -> &'static str {
    "DHCP"
}

/// The client hardware address as `{c}` in summaries: the MAC for Ethernet
/// clients, colon-separated hex of whatever `chaddr` holds otherwise.
fn client_text(d: &Dhcp<'_>) -> String {
    match d.client_mac() {
        Some(m) => m.to_string(),
        None if d.chaddr.is_empty() => "unknown".to_string(),
        None => colon_hex(d.chaddr),
    }
}

fn colon_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(3));
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

pub fn summary(d: &Dhcp<'_>, out: &mut String) {
    let c = client_text(d);
    let host = |out: &mut String| {
        if let Some(h) = d.hostname() {
            out.push_str(" \"");
            push_text(out, h, TextKind::Utf8, LINE_FIELD_MAX);
            out.push('"');
        }
    };
    let ip = |a: Option<Ipv4Addr>| a.map_or_else(|| "?".to_string(), |a| a.to_string());
    let _ = match d.msg_type() {
        Some(DISCOVER) => {
            let _ = write!(out, "DISCOVER from {c}");
            host(out);
            Ok(())
        }
        Some(OFFER) => write!(out, "OFFER {} to {c}", d.yiaddr),
        Some(REQUEST) => {
            let want = d
                .requested_ip()
                .or_else(|| (!d.ciaddr.is_unspecified()).then_some(d.ciaddr));
            let _ = write!(out, "REQUEST {} by {c}", ip(want));
            host(out);
            Ok(())
        }
        Some(ACK) => write!(out, "ACK {} to {c}", d.yiaddr),
        Some(NAK) => write!(out, "NAK to {c}"),
        Some(DECLINE) => write!(out, "DECLINE {} by {c}", ip(d.requested_ip())),
        Some(RELEASE) => write!(out, "RELEASE {} by {c}", d.ciaddr),
        Some(INFORM) => write!(out, "INFORM by {c}"),
        Some(t) => match enum_name(53, t) {
            Some(name) => write!(out, "{name} {c}"),
            None => write!(out, "type {t} {c}"),
        },
        None => match d.op {
            1 => write!(out, "BOOTP request from {c}"),
            2 => write!(out, "BOOTP reply {} to {c}", d.yiaddr),
            op => write!(out, "BOOTP op {op} {c}"),
        },
    };
}

fn op_text(op: u8) -> &'static str {
    match op {
        1 => "BOOTREQUEST",
        2 => "BOOTREPLY",
        _ => "unknown",
    }
}

fn htype_text(h: u8) -> &'static str {
    match h {
        1 => "ethernet",
        6 => "ieee802",
        7 => "arcnet",
        15 => "frame-relay",
        20 => "serial",
        _ => "other",
    }
}

/// An `sname` or `file` field: the bytes before the first NUL.
fn field(b: &[u8]) -> &[u8] {
    b.split(|&x| x == 0).next().unwrap_or(&[])
}

fn ip4_at(b: &[u8], i: usize) -> Option<Ipv4Addr> {
    let s = b.get(i..i.checked_add(4)?)?;
    let a: [u8; 4] = s.try_into().ok()?;
    Some(Ipv4Addr::from(a))
}

fn addrs(b: &[u8]) -> Vec<String> {
    b.chunks_exact(4)
        .filter_map(|c| ip4_at(c, 0))
        .map(|a| a.to_string())
        .collect()
}

fn u16s(b: &[u8]) -> Vec<i64> {
    b.chunks_exact(2)
        .filter_map(|c| <[u8; 2]>::try_from(c).ok())
        .map(|c| i64::from(u16::from_be_bytes(c)))
        .collect()
}

/// Classless routes as `dest/width via router`; `check` has vetted `b`.
fn classless_routes(b: &[u8]) -> Vec<String> {
    let mut v = Vec::new();
    let mut i = 0usize;
    while let Some(&width) = b.get(i) {
        let n = usize::from(width).div_ceil(8);
        let mut dest = [0u8; 4];
        let start = i.saturating_add(1);
        let Some(sig) = start.checked_add(n).and_then(|e| b.get(start..e)) else {
            break;
        };
        for (slot, x) in dest.iter_mut().zip(sig) {
            *slot = *x;
        }
        let rs = start.saturating_add(n);
        let Some(router) = ip4_at(b, rs) else { break };
        v.push(format!("{}/{width} via {router}", Ipv4Addr::from(dest)));
        i = rs.saturating_add(4);
    }
    v
}

/// Splits option 82 into `(sub-option, data)`; `None` when the TLVs are broken.
fn relay_subopts(b: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut v = Vec::new();
    let mut rest = b;
    while let [code, len, tail @ ..] = rest {
        let n = usize::from(*len);
        let data = tail.get(..n)?;
        v.push((*code, data));
        rest = tail.get(n..)?;
    }
    rest.is_empty().then_some(v)
}

/// A DNS name in wire format, as dotted text. Compression is not used in
/// option 81, so a pointer ends the name.
fn wire_name(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = b;
    while let [len, tail @ ..] = rest {
        let n = usize::from(*len);
        if n == 0 || n > 63 {
            break;
        }
        let Some(label) = tail.get(..n) else {
            out.extend_from_slice(tail);
            break;
        };
        if !out.is_empty() {
            out.push(b'.');
        }
        out.extend_from_slice(label);
        rest = tail.get(n..).unwrap_or(&[]);
    }
    out
}

/// Flags and the client name of option 81.
fn fqdn(data: &[u8]) -> Option<(u8, Cow<'_, [u8]>)> {
    let (&flags, rest) = data.split_first()?;
    let name = rest.get(2..)?;
    if flags & 0x04 != 0 {
        Some((flags, Cow::Owned(wire_name(name))))
    } else {
        let name = name.strip_suffix(&[0]).unwrap_or(name);
        let name = name.strip_suffix(b".").unwrap_or(name);
        Some((flags, Cow::Borrowed(name)))
    }
}

/// A typed option value, ready for both text and JSON.
enum Value<'a> {
    Text(&'a [u8]),
    Hex(&'a [u8]),
    /// `suffix` follows each number in text output.
    Nums(Vec<i64>, &'static str, bool),
    Strs(Vec<String>, bool),
    Enum(u8, Option<&'static str>),
    Fqdn(u8, Cow<'a, [u8]>),
    Relay(Vec<(u8, &'a [u8])>),
}

fn value<'a>(code: u8, data: &'a [u8]) -> Value<'a> {
    let single = data.len() == 4;
    match option_type(code) {
        OptType::Text => Value::Text(data),
        OptType::Hex => Value::Hex(data),
        OptType::Addr => Value::Strs(addrs(data), !single),
        OptType::Addrs => Value::Strs(addrs(data), true),
        OptType::AddrMasks => Value::Strs(
            data.chunks_exact(8)
                .filter_map(|c| Some(format!("{}/{}", ip4_at(c, 0)?, ip4_at(c, 4)?)))
                .collect(),
            true,
        ),
        OptType::Routes => Value::Strs(
            data.chunks_exact(8)
                .filter_map(|c| Some(format!("{} via {}", ip4_at(c, 0)?, ip4_at(c, 4)?)))
                .collect(),
            true,
        ),
        OptType::U8 => Value::Nums(
            data.iter().map(|&b| i64::from(b)).collect(),
            "",
            data.len() != 1,
        ),
        OptType::Prl => Value::Nums(data.iter().map(|&b| i64::from(b)).collect(), "", true),
        OptType::U16 => Value::Nums(u16s(data), "", data.len() != 2),
        OptType::U16s | OptType::Arch => Value::Nums(u16s(data), "", true),
        OptType::Secs => Value::Nums(
            data.chunks_exact(4)
                .filter_map(|c| <[u8; 4]>::try_from(c).ok())
                .map(|c| i64::from(u32::from_be_bytes(c)))
                .collect(),
            "s",
            !single,
        ),
        OptType::SignedSecs => Value::Nums(
            data.chunks_exact(4)
                .filter_map(|c| <[u8; 4]>::try_from(c).ok())
                .map(|c| i64::from(i32::from_be_bytes(c)))
                .collect(),
            "s",
            !single,
        ),
        OptType::Enum => match data {
            [n] => Value::Enum(*n, enum_name(code, *n)),
            _ => Value::Nums(data.iter().map(|&b| i64::from(b)).collect(), "", true),
        },
        OptType::Fqdn => match fqdn(data) {
            Some((f, n)) => Value::Fqdn(f, n),
            None => Value::Hex(data),
        },
        OptType::Relay => match relay_subopts(data) {
            Some(v) => Value::Relay(v),
            None => Value::Hex(data),
        },
        OptType::Ndi => match data {
            [t, major, minor, ..] => {
                Value::Strs(vec![format!("type {t} version {major}.{minor}")], false)
            }
            _ => Value::Hex(data),
        },
        OptType::CRoutes => Value::Strs(classless_routes(data), true),
    }
}

fn push_value(v: &Value<'_>, out: &mut String) {
    match v {
        Value::Text(b) => {
            out.push('"');
            push_text(out, b, TextKind::Utf8, usize::MAX);
            out.push('"');
        }
        Value::Hex(b) => out.push_str(&hex(b)),
        Value::Nums(n, suffix, _) => {
            for (i, x) in n.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                let _ = write!(out, "{x}{suffix}");
            }
        }
        Value::Strs(s, _) => out.push_str(&s.join(", ")),
        Value::Enum(n, Some(name)) => {
            let _ = write!(out, "{n} ({name})");
        }
        Value::Enum(n, None) => {
            let _ = write!(out, "{n}");
        }
        Value::Fqdn(flags, name) => {
            let _ = write!(out, "flags 0x{flags:02x} \"");
            push_text(out, name, TextKind::Utf8, usize::MAX);
            out.push('"');
        }
        Value::Relay(subs) => {
            for (i, (c, d)) in subs.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                let _ = write!(out, "{c}:{}", hex(d));
            }
        }
    }
}

fn source_text(s: OptSource) -> Option<&'static str> {
    match s {
        OptSource::Options => None,
        OptSource::File => Some("file"),
        OptSource::Sname => Some("sname"),
    }
}

pub fn verbose(d: &Dhcp<'_>, out: &mut String) {
    let _ = writeln!(
        out,
        "  DHCP  op {} ({}) htype {} ({}) hlen {} hops {} xid {:08x} secs {} flags 0x{:04x}",
        d.op,
        op_text(d.op),
        d.htype,
        htype_text(d.htype),
        d.hlen,
        d.hops,
        d.xid,
        d.secs,
        d.flags
    );
    let _ = writeln!(
        out,
        "        ciaddr {} yiaddr {} siaddr {} giaddr {}",
        d.ciaddr, d.yiaddr, d.siaddr, d.giaddr
    );
    let _ = writeln!(out, "        chaddr {}", colon_hex(d.chaddr));
    let (file_ol, sname_ol) = d.overloaded();
    out.push_str("        sname ");
    if sname_ol {
        out.push_str("(options)");
    } else {
        text_or_dash(out, field(d.sname));
    }
    out.push_str(" file ");
    if file_ol {
        out.push_str("(options)");
    } else {
        text_or_dash(out, field(d.file));
    }
    out.push('\n');

    let mut seen = [false; 256];
    for o in &d.options {
        let _ = write!(out, "  {:>3} {:<28} ", o.code, option_name(o.code));
        match check(o.code, o.data) {
            Ok(()) => push_value(&value(o.code, o.data), out),
            Err(reason) => {
                let _ = write!(out, "*malformed: {reason}* {}", hex(o.data));
            }
        }
        if let Some(s) = source_text(o.source) {
            let _ = write!(out, " (from {s})");
        }
        if let Some(slot) = seen.get_mut(usize::from(o.code)) {
            if *slot {
                let _ = write!(out, " (continues option {})", o.code);
            }
            *slot = true;
        }
        out.push('\n');
    }
}

fn text_or_dash(out: &mut String, b: &[u8]) {
    if b.is_empty() {
        out.push('-');
    } else {
        out.push('"');
        push_text(out, b, TextKind::Utf8, usize::MAX);
        out.push('"');
    }
}

fn json_value(v: &Value<'_>, w: &mut JsonWriter) {
    match v {
        Value::Text(b) => {
            if is_json_text(b, TextKind::Utf8) {
                w.str(Some("value"), &String::from_utf8_lossy(b));
            } else {
                w.hex(Some("hex"), b);
            }
        }
        Value::Hex(b) => w.hex(Some("hex"), b),
        Value::Nums(n, _, list) => {
            if *list {
                w.arr(Some("value"));
                for x in n {
                    w.i64(None, *x);
                }
                w.end();
            } else if let Some(x) = n.first() {
                w.i64(Some("value"), *x);
            }
        }
        Value::Strs(s, list) => {
            if *list {
                w.arr(Some("value"));
                for x in s {
                    w.str(None, x);
                }
                w.end();
            } else if let Some(x) = s.first() {
                w.str(Some("value"), x);
            }
        }
        Value::Enum(n, name) => {
            w.u64(Some("value"), u64::from(*n));
            if let Some(t) = name {
                w.str(Some("text"), t);
            }
        }
        Value::Fqdn(flags, name) => {
            w.obj(Some("value"));
            w.u64(Some("flags"), u64::from(*flags));
            w.text("name", name, TextKind::Utf8);
            w.end();
        }
        Value::Relay(subs) => {
            w.arr(Some("value"));
            for (c, d) in subs {
                w.obj(None);
                w.u64(Some("code"), u64::from(*c));
                w.hex(Some("hex"), d);
                w.end();
            }
            w.end();
        }
    }
}

fn json_option(o: &DhcpOption<'_>, w: &mut JsonWriter) {
    w.obj(None);
    w.u64(Some("code"), u64::from(o.code));
    w.str(Some("name"), option_name(o.code));
    w.u64(Some("len"), u64::try_from(o.data.len()).unwrap_or(u64::MAX));
    match check(o.code, o.data) {
        Ok(()) => json_value(&value(o.code, o.data), w),
        Err(reason) => {
            w.str(Some("malformed"), reason);
            w.hex(Some("hex"), o.data);
        }
    }
    if let Some(s) = source_text(o.source) {
        w.str(Some("source"), s);
    }
    w.end();
}

pub fn json(d: &Dhcp<'_>, w: &mut JsonWriter) {
    w.obj(Some("dhcp"));
    w.u64(Some("op"), u64::from(d.op));
    w.str(Some("op_text"), op_text(d.op));
    w.u64(Some("htype"), u64::from(d.htype));
    w.str(Some("htype_text"), htype_text(d.htype));
    w.u64(Some("hlen"), u64::from(d.hlen));
    w.u64(Some("hops"), u64::from(d.hops));
    w.str(Some("xid"), &format!("{:08x}", d.xid));
    w.u64(Some("secs"), u64::from(d.secs));
    w.u64(Some("flags"), u64::from(d.flags));
    for (k, a) in [
        ("ciaddr", d.ciaddr),
        ("yiaddr", d.yiaddr),
        ("siaddr", d.siaddr),
        ("giaddr", d.giaddr),
    ] {
        w.ip(Some(k), IpAddr::V4(a));
    }
    w.str(Some("chaddr"), &colon_hex(d.chaddr));
    let (file_ol, sname_ol) = d.overloaded();
    if sname_ol {
        w.null(Some("sname"));
    } else {
        w.text("sname", field(d.sname), TextKind::Utf8);
    }
    if file_ol {
        w.null(Some("file"));
    } else {
        w.text("file", field(d.file), TextKind::Utf8);
    }
    w.arr(Some("options"));
    for o in &d.options {
        json_option(o, w);
    }
    w.end();
    w.end();
}

fn nonempty(b: Cow<'_, [u8]>) -> Option<Cow<'_, [u8]>> {
    (!b.is_empty()).then_some(b)
}

/// The sender was heard. Client messages name and describe the client; ACKs
/// record the leased address; server replies are reported for the DHCP checks.
pub fn observe<'a>(p: &Packet<'a>, d: &Dhcp<'a>, out: &mut Vec<Observation<'a>>) {
    out.push(Observation::Heard {
        mac: p.eth.src,
        proto: ProtoTag::Dhcp,
    });
    let client: Option<Mac> = d.client_mac();
    if d.op == 1 {
        if let Some(mac) = client {
            let host = d.hostname().map(Cow::Borrowed).and_then(nonempty);
            let fq = d
                .option(81)
                .and_then(|o| fqdn(o.data))
                .and_then(|(_, n)| nonempty(n));
            for name in [host, fq].into_iter().flatten() {
                out.push(Observation::Name {
                    mac,
                    name,
                    source: NameSource::Dhcp,
                });
            }
            if let Some(text) = d
                .option(60)
                .map(|o| Cow::Borrowed(o.data))
                .and_then(nonempty)
            {
                out.push(Observation::Model { mac, text });
            }
        }
    }
    let Some(msg_type) = d.msg_type() else { return };
    let Some(client) = client else { return };
    if msg_type == ACK && !d.yiaddr.is_unspecified() {
        out.push(Observation::Address {
            mac: client,
            ip: IpAddr::V4(d.yiaddr),
        });
    }
    if matches!(msg_type, OFFER | ACK | NAK) {
        let server_id = d.server_id().or_else(|| match p.ip.map(|ip| ip.src()) {
            Some(IpAddr::V4(a)) => Some(a),
            _ => None,
        });
        let Some(server_id) = server_id else { return };
        out.push(Observation::DhcpReply {
            client,
            server_mac: p.eth.src,
            server_id,
            msg_type,
            router: d.router(),
        });
        if d.giaddr.is_unspecified() {
            out.push(Observation::Role {
                mac: p.eth.src,
                role: Role::DhcpServer,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{NameSource, ProtoTag, Role};
    use overhear_decode::{Mac, Proto, decode};
    use overhear_testgen::{BCAST, DhcpMsg, eth_ipv4, ipv4_udp, mac};
    use std::net::{IpAddr, Ipv4Addr};

    fn a(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, d)
    }

    /// Runs `f` on the packet carrying `msg`, sent from `mac(src)` / `src_ip`.
    fn with<R>(
        msg: &DhcpMsg,
        src: u8,
        src_ip: Ipv4Addr,
        f: impl FnOnce(&Packet<'_>, &Dhcp<'_>) -> R,
    ) -> R {
        let ip = ipv4_udp(src_ip, Ipv4Addr::BROADCAST, 67, 68, &msg.bytes());
        let frame = eth_ipv4(BCAST, mac(src), &ip);
        let p = decode(&frame).unwrap();
        let Proto::Dhcp(d) = &p.proto else {
            panic!("not dhcp")
        };
        f(&p, d)
    }

    fn line(msg: &DhcpMsg) -> String {
        with(msg, 1, a(1), |_, d| {
            let mut s = String::new();
            summary(d, &mut s);
            s
        })
    }

    fn verbose_of(msg: &DhcpMsg) -> String {
        with(msg, 1, a(1), |_, d| {
            let mut s = String::new();
            verbose(d, &mut s);
            s
        })
    }

    fn client_msg(t: u8) -> DhcpMsg {
        let mut m = DhcpMsg::discover(mac(0x39), "host-a");
        m.options[0] = (53, vec![t]);
        m
    }

    fn reply(t: u8) -> DhcpMsg {
        DhcpMsg::reply(t, a(1), a(50), mac(0x39))
    }

    const C: &str = "02:00:5e:10:00:39";

    #[test]
    fn summaries_by_message_type() {
        assert_eq!(
            line(&client_msg(1)),
            format!("DISCOVER from {C} \"host-a\"")
        );
        assert_eq!(line(&reply(2)), format!("OFFER 192.168.1.50 to {C}"));
        assert_eq!(line(&reply(5)), format!("ACK 192.168.1.50 to {C}"));
        assert_eq!(line(&reply(6)), format!("NAK to {C}"));

        let mut m = client_msg(3);
        m.options.push((50, a(50).octets().to_vec()));
        assert_eq!(line(&m), format!("REQUEST 192.168.1.50 by {C} \"host-a\""));
        let mut m = client_msg(3);
        m.ciaddr = a(60);
        assert_eq!(line(&m), format!("REQUEST 192.168.1.60 by {C} \"host-a\""));

        let mut m = client_msg(4);
        m.options.push((50, a(50).octets().to_vec()));
        assert_eq!(line(&m), format!("DECLINE 192.168.1.50 by {C}"));
        let mut m = client_msg(7);
        m.ciaddr = a(60);
        assert_eq!(line(&m), format!("RELEASE 192.168.1.60 by {C}"));
        assert_eq!(line(&client_msg(8)), format!("INFORM by {C}"));
        assert_eq!(line(&client_msg(9)), format!("FORCERENEW {C}"));
        assert_eq!(line(&client_msg(99)), format!("type 99 {C}"));
    }

    #[test]
    fn bootp_summaries() {
        let mut m = DhcpMsg::discover(mac(0x39), "h");
        m.cookie = false;
        assert_eq!(line(&m), format!("BOOTP request from {C}"));
        let mut m = DhcpMsg::reply(2, a(1), a(50), mac(0x39));
        m.cookie = false;
        assert_eq!(line(&m), format!("BOOTP reply 192.168.1.50 to {C}"));
    }

    #[test]
    fn hostname_is_escaped_and_cut() {
        let mut m = client_msg(1);
        m.options[1] = (12, b"a\x1b[31m\\".to_vec());
        assert_eq!(line(&m), format!("DISCOVER from {C} \"a\\x1b[31m\\\\\""));
        m.options[1] = (12, vec![b'x'; 100]);
        let want = format!("DISCOVER from {C} \"{}…\"", "x".repeat(63));
        assert_eq!(line(&m), want);
    }

    fn obs(msg: &DhcpMsg, src: u8, src_ip: Ipv4Addr) -> Vec<Observation<'static>> {
        with(msg, src, src_ip, |p, d| {
            let mut out = Vec::new();
            observe(p, d, &mut out);
            out.into_iter()
                .map(|o| match o {
                    Observation::Name { mac, name, source } => Observation::Name {
                        mac,
                        name: name.into_owned().into(),
                        source,
                    },
                    Observation::Model { mac, text } => Observation::Model {
                        mac,
                        text: text.into_owned().into(),
                    },
                    Observation::Heard { mac, proto } => Observation::Heard { mac, proto },
                    Observation::Address { mac, ip } => Observation::Address { mac, ip },
                    Observation::Role { mac, role } => Observation::Role { mac, role },
                    Observation::DhcpReply {
                        client,
                        server_mac,
                        server_id,
                        msg_type,
                        router,
                    } => Observation::DhcpReply {
                        client,
                        server_mac,
                        server_id,
                        msg_type,
                        router,
                    },
                    other => panic!("unexpected {other:?}"),
                })
                .collect()
        })
    }

    #[test]
    fn client_message_names_and_models_the_client() {
        let mut m = client_msg(1);
        m.options.push((60, b"MSFT 5.0".to_vec()));
        // FQDN: flags 0, rcodes 0, plain ASCII name
        let mut f = vec![0, 0, 0];
        f.extend_from_slice(b"host-a.lan");
        m.options.push((81, f));
        let c = Mac(mac(0x39));
        assert_eq!(
            obs(&m, 0x39, Ipv4Addr::UNSPECIFIED),
            vec![
                Observation::Heard {
                    mac: c,
                    proto: ProtoTag::Dhcp
                },
                Observation::Name {
                    mac: c,
                    name: b"host-a".to_vec().into(),
                    source: NameSource::Dhcp
                },
                Observation::Name {
                    mac: c,
                    name: b"host-a.lan".to_vec().into(),
                    source: NameSource::Dhcp
                },
                Observation::Model {
                    mac: c,
                    text: b"MSFT 5.0".to_vec().into()
                },
            ]
        );
    }

    #[test]
    fn fqdn_with_wire_encoding() {
        let mut m = client_msg(1);
        m.options[1] = (53, vec![1]);
        let mut f = vec![4, 0, 0];
        f.extend_from_slice(b"\x04host\x03lan\x00");
        m.options.push((81, f));
        let o = obs(&m, 0x39, Ipv4Addr::UNSPECIFIED);
        assert!(o.iter().any(|o| matches!(o,
            Observation::Name { name, .. } if &name[..] == b"host.lan")));
    }

    #[test]
    fn ack_records_the_leased_address() {
        let c = Mac(mac(0x39));
        let o = obs(&reply(5), 1, a(1));
        assert_eq!(
            o[1],
            Observation::Address {
                mac: c,
                ip: IpAddr::V4(a(50))
            }
        );
        let o = obs(&reply(2), 1, a(1));
        assert!(!o.iter().any(|o| matches!(o, Observation::Address { .. })));
    }

    #[test]
    fn offer_emits_dhcp_reply_with_router() {
        let o = obs(&reply(2), 1, a(1));
        assert_eq!(
            o,
            vec![
                Observation::Heard {
                    mac: Mac(mac(1)),
                    proto: ProtoTag::Dhcp
                },
                Observation::DhcpReply {
                    client: Mac(mac(0x39)),
                    server_mac: Mac(mac(1)),
                    server_id: a(1),
                    msg_type: 2,
                    router: Some(a(1)),
                },
                Observation::Role {
                    mac: Mac(mac(1)),
                    role: Role::DhcpServer
                },
            ]
        );
    }

    #[test]
    fn server_id_falls_back_to_ip_source() {
        let mut m = reply(6);
        m.options.retain(|(c, _)| *c != 54 && *c != 3);
        let o = obs(&m, 1, a(7));
        assert!(o.contains(&Observation::DhcpReply {
            client: Mac(mac(0x39)),
            server_mac: Mac(mac(1)),
            server_id: a(7),
            msg_type: 6,
            router: None,
        }));
    }

    #[test]
    fn relayed_reply_sets_no_server_role() {
        let mut m = reply(2);
        m.giaddr = Ipv4Addr::new(10, 9, 9, 1);
        let o = obs(&m, 1, a(1));
        assert_eq!(o.len(), 2);
        assert!(matches!(o[1], Observation::DhcpReply { .. }));
        assert!(!o.iter().any(|o| matches!(o, Observation::Role { .. })));
    }

    #[test]
    fn requests_from_clients_emit_no_reply() {
        let o = obs(&client_msg(3), 0x39, Ipv4Addr::UNSPECIFIED);
        assert!(!o.iter().any(|o| matches!(o, Observation::DhcpReply { .. })));
    }

    #[test]
    fn malformed_dns_option_verbose_line() {
        let mut m = reply(2);
        m.options.push((6, vec![8, 8, 8, 8, 4, 4]));
        let v = verbose_of(&m);
        assert!(
            v.lines()
                .any(|l| l == "    6 Domain Server                *malformed: length not a multiple of 4* 080808080404"),
            "{v}"
        );
    }

    #[test]
    fn verbose_header_and_typed_options() {
        let mut m = reply(5);
        m.options.push((12, b"a\x1bb".to_vec()));
        m.options.push((52, vec![1]));
        m.options.push((12, b"x".to_vec()));
        let v = verbose_of(&m);
        let want = "\
\x20\x20DHCP  op 2 (BOOTREPLY) htype 1 (ethernet) hlen 6 hops 0 xid 3903f326 secs 0 flags 0x0000
        ciaddr 0.0.0.0 yiaddr 192.168.1.50 siaddr 192.168.1.1 giaddr 0.0.0.0
        chaddr 02:00:5e:10:00:39
        sname - file (options)
   53 DHCP Msg Type                5 (ACK)
   54 DHCP Server Id               192.168.1.1
   51 Address Time                 3600s
    1 Subnet Mask                  255.255.255.0
    3 Router                       192.168.1.1
   12 Hostname                     \"a\\x1bb\"
   52 Overload                     1 (file)
   12 Hostname                     \"x\" (continues option 12)
";
        assert_eq!(v, want);
    }

    #[test]
    fn overloaded_options_are_marked() {
        let mut m = reply(5);
        m.options.push((52, vec![3]));
        m.file = vec![12, 1, b'f', 255];
        m.sname = vec![12, 1, b's', 255];
        let v = verbose_of(&m);
        assert!(v.contains("\"f\" (from file)\n"), "{v}");
        assert!(
            v.contains("\"s\" (from sname) (continues option 12)\n"),
            "{v}"
        );
        assert!(v.contains("sname (options) file (options)\n"), "{v}");
    }

    #[test]
    fn only_enum_options_show_enum_text() {
        let mut m = reply(5);
        // 25 is a u16 list; value 1 must stay plain
        m.options.push((25, vec![0, 1]));
        m.options.push((23, vec![1]));
        let v = verbose_of(&m);
        assert!(v.contains("25 MTU Plateau                  1\n"), "{v}");
        assert!(v.contains("23 Default IP TTL               1\n"), "{v}");
    }

    #[test]
    fn classless_routes_and_prl() {
        let mut m = reply(5);
        m.options
            .push((121, vec![24, 10, 0, 1, 192, 168, 1, 1, 0, 192, 168, 1, 1]));
        m.options.push((55, vec![1, 3, 6]));
        let v = verbose_of(&m);
        assert!(
            v.contains("10.0.1.0/24 via 192.168.1.1, 0.0.0.0/0 via 192.168.1.1\n"),
            "{v}"
        );
        assert!(
            v.contains("55 Parameter List               1, 3, 6\n"),
            "{v}"
        );
    }

    fn json_of(msg: &DhcpMsg) -> serde_json::Value {
        with(msg, 1, a(1), |_, d| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(d, &mut w);
            w.end();
            serde_json::from_str(w.as_str()).unwrap()
        })
    }

    #[test]
    fn json_object() {
        let mut m = reply(5);
        m.options.push((6, vec![8, 8, 8, 8, 4, 4]));
        m.options.push((12, b"h\xff".to_vec()));
        m.options.push((52, vec![1]));
        m.file = vec![12, 1, b'f', 255];
        let v = json_of(&m);
        let d = &v["dhcp"];
        assert_eq!(d["op"], 2);
        assert_eq!(d["op_text"], "BOOTREPLY");
        assert_eq!(d["htype_text"], "ethernet");
        assert_eq!(d["xid"], "3903f326");
        assert_eq!(d["flags"], 0);
        assert_eq!(d["yiaddr"], "192.168.1.50");
        assert_eq!(d["chaddr"], "02:00:5e:10:00:39");
        assert_eq!(d["sname"], "");
        assert!(d["file"].is_null());
        let o = d["options"].as_array().unwrap();
        assert_eq!(o[0]["code"], 53);
        assert_eq!(o[0]["name"], "DHCP Msg Type");
        assert_eq!(o[0]["len"], 1);
        assert_eq!(o[0]["value"], 5);
        assert_eq!(o[0]["text"], "ACK");
        assert_eq!(o[2]["value"], 3600);
        assert_eq!(o[3]["value"], "255.255.255.0");
        assert_eq!(o[4]["value"], serde_json::json!(["192.168.1.1"]));
        assert_eq!(o[5]["malformed"], "length not a multiple of 4");
        assert_eq!(o[5]["hex"], "080808080404");
        assert!(o[5].get("value").is_none());
        assert_eq!(o[6]["hex"], "68ff");
        assert_eq!(o[8]["source"], "file");
        assert_eq!(o[8]["value"], "f");
    }
}
