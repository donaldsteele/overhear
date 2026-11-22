//! DHCPv4 / BOOTP decoder.

use std::net::Ipv4Addr;

use crate::{Cursor, Layer, Mac, Problem};

/// Which area of the message an option was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptSource {
    Options,
    File,
    Sname,
}

/// One option instance. `offset` is the frame offset of its code byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpOption<'a> {
    pub code: u8,
    pub data: &'a [u8],
    pub offset: usize,
    pub source: OptSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp<'a> {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// The first `hlen` bytes of the 16-byte client hardware address field.
    pub chaddr: &'a [u8],
    pub sname: &'a [u8],
    pub file: &'a [u8],
    pub cookie: bool,
    pub options: Vec<DhcpOption<'a>>,
}

fn ip4(b: &[u8]) -> Option<Ipv4Addr> {
    let a: [u8; 4] = b.try_into().ok()?;
    Some(Ipv4Addr::from(a))
}

impl<'a> Dhcp<'a> {
    /// The first instance of option `code`.
    pub fn option(&self, code: u8) -> Option<&DhcpOption<'a>> {
        self.options.iter().find(|o| o.code == code)
    }

    pub fn msg_type(&self) -> Option<u8> {
        match self.option(53)?.data {
            [t] => Some(*t),
            _ => None,
        }
    }

    pub fn client_mac(&self) -> Option<Mac> {
        if self.htype != 1 || self.hlen != 6 {
            return None;
        }
        Mac::from_slice(self.chaddr)
    }

    pub fn server_id(&self) -> Option<Ipv4Addr> {
        ip4(self.option(54)?.data)
    }

    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        ip4(self.option(50)?.data)
    }

    pub fn hostname(&self) -> Option<&'a [u8]> {
        Some(self.option(12)?.data)
    }

    /// The first router address of option 3.
    pub fn router(&self) -> Option<Ipv4Addr> {
        ip4(self.option(3)?.data.get(..4)?)
    }

    /// Whether `(file, sname)` hold options, per option 52 in the options area.
    pub fn overloaded(&self) -> (bool, bool) {
        let v = self
            .options
            .iter()
            .find(|o| o.code == 52 && o.source == OptSource::Options)
            .and_then(|o| match o.data {
                [v] => Some(*v),
                _ => None,
            })
            .unwrap_or(0);
        (v & 1 != 0, v & 2 != 0)
    }
}

const HEADER: usize = 236;
const COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Reads the options of one area. Stops at End or the first truncated option.
fn options_area<'a>(
    mut a: Cursor<'a>,
    source: OptSource,
    out: &mut Vec<DhcpOption<'a>>,
    problems: &mut Vec<Problem>,
) {
    while let Some(code) = a.peek_u8() {
        let offset = a.pos();
        let left = a.remaining();
        a.skip(1);
        match code {
            0 => continue,
            255 => return,
            _ => {}
        }
        let Some(data) = a.u8().and_then(|n| a.take(usize::from(n))) else {
            problems.push(Problem {
                layer: Layer::Dhcp,
                reason: "truncated",
                offset,
                len: left,
            });
            return;
        };
        out.push(DhcpOption {
            code,
            data,
            offset,
            source,
        });
    }
}

/// Parses a DHCPv4 / BOOTP message. A header that is too short is reported and
/// leaves the cursor where it was.
pub fn parse<'a>(c: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Option<Dhcp<'a>> {
    let start = c.pos();
    let mut r = *c;
    let Some(mut h) = r.sub(HEADER) else {
        problems.push(Problem {
            layer: Layer::Dhcp,
            reason: "truncated BOOTP header",
            offset: start,
            len: c.remaining(),
        });
        return None;
    };
    let (op, htype, hlen, hops) = (h.u8()?, h.u8()?, h.u8()?, h.u8()?);
    let (xid, secs, flags) = (h.be32()?, h.be16()?, h.be16()?);
    let (ciaddr, yiaddr, siaddr, giaddr) = (
        ip4(h.take(4)?)?,
        ip4(h.take(4)?)?,
        ip4(h.take(4)?)?,
        ip4(h.take(4)?)?,
    );
    let chaddr_field = h.take(16)?;
    let sname_at = h.pos();
    let sname = h.take(64)?;
    let file_at = h.pos();
    let file = h.take(128)?;
    let chaddr = chaddr_field
        .get(..usize::from(hlen).min(chaddr_field.len()))
        .unwrap_or(&[]);

    let mut d = Dhcp {
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        sname,
        file,
        cookie: false,
        options: Vec::new(),
    };
    let rest = r.rest();
    if rest.starts_with(&COOKIE) {
        d.cookie = true;
        let mut opts = *c;
        opts.skip(HEADER.saturating_add(COOKIE.len()))?;
        options_area(opts, OptSource::Options, &mut d.options, problems);
        let (file_ol, sname_ol) = d.overloaded();
        if file_ol {
            if let Some(a) = c.at(file_at).and_then(|mut a| a.sub(128)) {
                options_area(a, OptSource::File, &mut d.options, problems);
            }
        }
        if sname_ol {
            if let Some(a) = c.at(sname_at).and_then(|mut a| a.sub(64)) {
                options_area(a, OptSource::Sname, &mut d.options, problems);
            }
        }
    }
    *c = r;
    Some(d)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use overhear_testgen::{DhcpMsg, mac};

    fn run(b: &[u8]) -> (Option<Dhcp<'_>>, Vec<Problem>) {
        let mut c = Cursor::new(b);
        let mut p = Vec::new();
        (parse(&mut c, &mut p), p)
    }

    fn codes(d: &Dhcp<'_>) -> Vec<u8> {
        d.options.iter().map(|o| o.code).collect()
    }

    fn msg() -> DhcpMsg {
        let mut m = DhcpMsg::discover(mac(0x39), "host-a");
        m.options = vec![(53, vec![1]), (52, vec![3])];
        m
    }

    #[test]
    fn parses_discover_options_in_order() {
        let b = DhcpMsg::discover(mac(0x39), "host-a").bytes();
        let (d, p) = run(&b);
        let d = d.unwrap();
        assert!(p.is_empty());
        assert_eq!(d.msg_type(), Some(1));
        assert_eq!(d.client_mac(), Some(Mac(mac(0x39))));
        assert_eq!(d.hostname(), Some(&b"host-a"[..]));
        assert_eq!(codes(&d), vec![53, 12, 55, 61]);
        assert_eq!(d.option(55).unwrap().data, &[1, 3, 6, 15]);
        assert_eq!((d.op, d.htype, d.hlen), (1, 1, 6));
        assert!(d.cookie);
        assert_eq!(d.options[0].offset, 240);
        assert_eq!(d.options[0].source, OptSource::Options);
    }

    #[test]
    fn overload_file_then_sname() {
        let mut m = msg();
        m.file = vec![12, 1, b'f', 255];
        m.sname = vec![12, 1, b's', 255];
        let b = m.bytes();
        let (d, p) = run(&b);
        let d = d.unwrap();
        assert!(p.is_empty());
        assert_eq!(d.overloaded(), (true, true));
        assert_eq!(codes(&d), vec![53, 52, 12, 12]);
        let srcs: Vec<_> = d.options.iter().map(|o| o.source).collect();
        assert_eq!(
            srcs,
            vec![
                OptSource::Options,
                OptSource::Options,
                OptSource::File,
                OptSource::Sname
            ]
        );
        assert_eq!(d.options[2].data, b"f");
        assert_eq!(d.options[2].offset, 108);
        assert_eq!(d.options[3].offset, 44);
        assert_eq!(d.option(12).unwrap().data, b"f");
    }

    #[test]
    fn not_overloaded_ignores_file_and_sname() {
        let mut m = DhcpMsg::discover(mac(1), "h");
        m.file = vec![12, 1, b'f', 255];
        let b = m.bytes();
        let d = run(&b).0.unwrap();
        assert_eq!(d.overloaded(), (false, false));
        assert_eq!(
            d.options
                .iter()
                .filter(|o| o.source != OptSource::Options)
                .count(),
            0
        );
    }

    #[test]
    fn overload_inside_file_ignored() {
        let mut m = msg();
        m.options = vec![(52, vec![1]), (53, vec![1])];
        m.file = vec![52, 1, 2, 12, 1, b'f', 255];
        m.sname = vec![12, 1, b's', 255];
        let b = m.bytes();
        let d = run(&b).0.unwrap();
        assert_eq!(d.overloaded(), (true, false));
        assert_eq!(codes(&d), vec![52, 53, 52, 12]);
    }

    #[test]
    fn truncated_option_keeps_earlier() {
        let b = DhcpMsg::discover(mac(0x39), "host-a").bytes();
        // options: 53 (3 bytes) then 12 len 6; cut after 3 data bytes of 12
        let cut = 240 + 3 + 2 + 3;
        let (d, p) = run(&b[..cut]);
        let d = d.unwrap();
        assert_eq!(codes(&d), vec![53]);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].layer, p[0].reason), (Layer::Dhcp, "truncated"));
        assert_eq!((p[0].offset, p[0].len), (243, 5));
        // a lone code byte at the very end
        let (d, p) = run(&b[..244]);
        assert_eq!(codes(&d.unwrap()), vec![53]);
        assert_eq!((p[0].offset, p[0].len), (243, 1));
    }

    #[test]
    fn short_header() {
        let b = DhcpMsg::discover(mac(1), "h").bytes();
        let mut c = Cursor::new(&b[..235]);
        let mut p = Vec::new();
        assert!(parse(&mut c, &mut p).is_none());
        assert_eq!(c.pos(), 0);
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].layer, p[0].reason),
            (Layer::Dhcp, "truncated BOOTP header")
        );
        assert_eq!((p[0].offset, p[0].len), (0, 235));
    }

    #[test]
    fn no_cookie_is_plain_bootp() {
        let mut m = DhcpMsg::discover(mac(1), "h");
        m.cookie = false;
        let b = m.bytes();
        let (d, p) = run(&b);
        let d = d.unwrap();
        assert!(p.is_empty());
        assert!(!d.cookie && d.options.is_empty());
        assert_eq!(d.client_mac(), Some(Mac(mac(1))));
    }

    #[test]
    fn repeated_codes_and_pad_end() {
        let mut m = DhcpMsg::discover(mac(1), "h");
        m.options = vec![(6, vec![1, 1, 1, 1]), (6, vec![2, 2, 2, 2])];
        let mut b = m.bytes();
        // insert pad bytes right after the cookie
        b.splice(240..240, [0, 0]);
        let d = run(&b).0.unwrap();
        assert_eq!(codes(&d), vec![6, 6]);
        assert_eq!(d.options[1].data, &[2, 2, 2, 2]);
        assert_eq!(d.option(6).unwrap().data, &[1, 1, 1, 1]);
        assert_eq!(d.router(), None);
    }

    #[test]
    fn accessors() {
        let m = DhcpMsg::reply(
            2,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 50),
            mac(7),
        );
        let b = m.bytes();
        let d = run(&b).0.unwrap();
        assert_eq!(d.msg_type(), Some(2));
        assert_eq!(d.server_id(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(d.yiaddr, Ipv4Addr::new(10, 0, 0, 50));
        assert_eq!(d.router(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(d.requested_ip(), None);
    }

    #[test]
    fn leaves_cursor_alone_on_failure() {
        let b = [0u8; 100];
        let mut c = Cursor::new(&b);
        assert!(parse(&mut c, &mut Vec::new()).is_none());
        assert_eq!(c.remaining(), 100);
    }

    #[test]
    fn hostile_lengths_do_not_panic() {
        let mut b = DhcpMsg::discover(mac(1), "h").bytes();
        b.truncate(240);
        b.extend_from_slice(&[52, 255, 12, 255, 1, 0xff]);
        let _ = run(&b);
        b[2] = 255; // hlen beyond chaddr
        let d = run(&b).0.unwrap();
        assert!(d.chaddr.len() <= 16);
        assert_eq!(d.client_mac(), None);
    }
}
