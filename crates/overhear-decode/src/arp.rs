use std::net::Ipv4Addr;

use crate::{Cursor, Layer, Mac, Problem};

/// An Ethernet/IPv4 ARP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub htype: u16,
    pub ptype: u16,
    pub op: u16,
    pub sha: Mac,
    pub spa: Ipv4Addr,
    pub tha: Mac,
    pub tpa: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpKind {
    Request,
    Reply,
    Probe,
    Announcement,
    Other(u16),
}

impl Arp {
    pub fn kind(&self) -> ArpKind {
        match self.op {
            1 if self.spa.is_unspecified() => ArpKind::Probe,
            1 | 2 if self.spa == self.tpa => ArpKind::Announcement,
            1 => ArpKind::Request,
            2 => ArpKind::Reply,
            op => ArpKind::Other(op),
        }
    }
}

const LEN: usize = 28;

fn ip4(b: &[u8]) -> Option<Ipv4Addr> {
    let a: [u8; 4] = b.try_into().ok()?;
    Some(Ipv4Addr::from(a))
}

/// Parses an Ethernet/IPv4 ARP message. Other hardware or protocol sizes are
/// reported as a problem and leave the cursor where it was.
pub fn parse(c: &mut Cursor<'_>, problems: &mut Vec<Problem>) -> Option<Arp> {
    let start = c.pos();
    let mut r = *c;
    let Some(b) = r.take(LEN) else {
        problems.push(Problem {
            layer: Layer::Arp,
            reason: "truncated",
            offset: start,
            len: c.remaining(),
        });
        return None;
    };
    let word = |at: usize| -> Option<u16> {
        let w: [u8; 2] = b.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(u16::from_be_bytes(w))
    };
    let (hlen, plen) = (b.get(4).copied()?, b.get(5).copied()?);
    if hlen != 6 || plen != 4 {
        problems.push(Problem {
            layer: Layer::Arp,
            reason: "unsupported hardware or protocol size",
            offset: start.saturating_add(4),
            len: 2,
        });
        return None;
    }
    let arp = Arp {
        htype: word(0)?,
        ptype: word(2)?,
        op: word(6)?,
        sha: Mac::from_slice(b.get(8..14)?)?,
        spa: ip4(b.get(14..18)?)?,
        tha: Mac::from_slice(b.get(18..24)?)?,
        tpa: ip4(b.get(24..28)?)?,
    };
    *c = r;
    Some(arp)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use overhear_testgen::{arp as build, mac};

    fn v4(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, d)
    }

    fn run(b: &[u8]) -> (Option<Arp>, Vec<Problem>) {
        let mut c = Cursor::new(b);
        let mut p = Vec::new();
        (parse(&mut c, &mut p), p)
    }

    fn kind(op: u16, spa: Ipv4Addr, tpa: Ipv4Addr) -> ArpKind {
        let (a, p) = run(&build(op, mac(1), spa, [0; 6], tpa));
        assert!(p.is_empty());
        a.unwrap().kind()
    }

    #[test]
    fn request_reply_probe_announcement_kinds() {
        assert_eq!(kind(1, v4(5), v4(6)), ArpKind::Request);
        assert_eq!(kind(2, v4(5), v4(6)), ArpKind::Reply);
        assert_eq!(kind(1, Ipv4Addr::UNSPECIFIED, v4(6)), ArpKind::Probe);
        assert_eq!(kind(1, v4(5), v4(5)), ArpKind::Announcement);
        assert_eq!(kind(2, v4(5), v4(5)), ArpKind::Announcement);
        assert_eq!(kind(3, v4(5), v4(6)), ArpKind::Other(3));
        assert_eq!(kind(2, Ipv4Addr::UNSPECIFIED, v4(6)), ArpKind::Reply);
    }

    #[test]
    fn fields_are_read() {
        let (a, _) = run(&build(2, mac(1), v4(5), mac(2), v4(6)));
        let a = a.unwrap();
        assert_eq!((a.htype, a.ptype, a.op), (1, 0x0800, 2));
        assert_eq!((a.sha, a.tha), (Mac(mac(1)), Mac(mac(2))));
        assert_eq!((a.spa, a.tpa), (v4(5), v4(6)));
    }

    #[test]
    fn truncated_arp() {
        let b = build(1, mac(1), v4(5), [0; 6], v4(6));
        let (a, p) = run(&b[..20]);
        assert!(a.is_none());
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].layer, p[0].reason), (Layer::Arp, "truncated"));
        assert_eq!((p[0].offset, p[0].len), (0, 20));
    }

    #[test]
    fn non_ethernet_arp_is_other() {
        let mut b = build(1, mac(1), v4(5), [0; 6], v4(6));
        b[4] = 8;
        let (a, p) = run(&b);
        assert!(a.is_none());
        assert_eq!(p[0].reason, "unsupported hardware or protocol size");
        b[4] = 6;
        b[5] = 16;
        assert!(run(&b).0.is_none());
    }
}
