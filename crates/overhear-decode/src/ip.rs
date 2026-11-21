use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Cursor, Layer, Problem};

/// Fragmentation state of an IP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frag {
    None,
    First,
    Later,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub proto: u8,
    pub frag: Frag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub hop_limit: u8,
    /// Upper-layer protocol, after any extension headers.
    pub next: u8,
    pub frag: Frag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

impl IpHeader {
    pub fn src(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.src),
            IpHeader::V6(h) => IpAddr::V6(h.src),
        }
    }

    pub fn dst(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.dst),
            IpHeader::V6(h) => IpAddr::V6(h.dst),
        }
    }

    pub fn frag(&self) -> &Frag {
        match self {
            IpHeader::V4(h) => &h.frag,
            IpHeader::V6(h) => &h.frag,
        }
    }
}

const MAX_EXT_HEADERS: usize = 8;

fn problem(layer: Layer, reason: &'static str, offset: usize, len: usize) -> Problem {
    Problem {
        layer,
        reason,
        offset,
        len,
    }
}

/// Decodes an IPv4 header. On `Some((header, has_l4))`, `c` covers the
/// payload (padding dropped when the total length allows). `has_l4` is false
/// when the payload must not be decoded as a transport header.
pub(crate) fn ipv4(c: &mut Cursor<'_>, problems: &mut Vec<Problem>) -> Option<(Ipv4Header, bool)> {
    let start = c.pos();
    if c.remaining() < 20 {
        problems.push(problem(Layer::Ipv4, "truncated", start, c.remaining()));
        return None;
    }
    let vihl = c.u8()?;
    c.u8()?;
    let total = usize::from(c.be16()?);
    c.be16()?;
    let ff = c.be16()?;
    let ttl = c.u8()?;
    let proto = c.u8()?;
    c.be16()?;
    let src = Ipv4Addr::from(c.be32()?);
    let dst = Ipv4Addr::from(c.be32()?);
    let frag = if ff & 0x1fff > 0 {
        Frag::Later
    } else if ff & 0x2000 != 0 {
        Frag::First
    } else {
        Frag::None
    };
    let header = Ipv4Header {
        src,
        dst,
        ttl,
        proto,
        frag,
    };
    if vihl >> 4 != 4 {
        problems.push(problem(Layer::Ipv4, "bad version", start, 1));
        return Some((header, false));
    }
    let ihl = usize::from(vihl & 0x0f);
    if ihl < 5 {
        problems.push(problem(Layer::Ipv4, "bad header length", start, 1));
        return Some((header, false));
    }
    let hlen = ihl.saturating_mul(4);
    if c.skip(hlen.saturating_sub(20)).is_none() {
        problems.push(problem(
            Layer::Ipv4,
            "truncated",
            start,
            c.remaining().saturating_add(20),
        ));
        return Some((header, false));
    }
    if total < hlen {
        problems.push(problem(
            Layer::Ipv4,
            "bad length",
            start.saturating_add(2),
            2,
        ));
        return Some((header, false));
    }
    let payload_len = total.saturating_sub(hlen);
    if payload_len > c.remaining() {
        problems.push(problem(
            Layer::Ipv4,
            "truncated",
            start.saturating_add(2),
            2,
        ));
    } else if let Some(sub) = c.sub(payload_len) {
        *c = sub;
    }
    Some((header, frag != Frag::Later))
}

/// Decodes an IPv6 header and walks its extension headers. On
/// `Some((header, has_l4))`, `c` is at the upper-layer header.
pub(crate) fn ipv6(c: &mut Cursor<'_>, problems: &mut Vec<Problem>) -> Option<(Ipv6Header, bool)> {
    let start = c.pos();
    if c.remaining() < 40 {
        problems.push(problem(Layer::Ipv6, "truncated", start, c.remaining()));
        return None;
    }
    let vtc = c.be32()?;
    let plen = usize::from(c.be16()?);
    let mut next = c.u8()?;
    let hop_limit = c.u8()?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(c.take(16)?).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(c.take(16)?).ok()?);
    let mut header = Ipv6Header {
        src,
        dst,
        hop_limit,
        next,
        frag: Frag::None,
    };
    if vtc >> 28 != 6 {
        problems.push(problem(Layer::Ipv6, "bad version", start, 1));
        return Some((header, false));
    }
    if plen > c.remaining() {
        problems.push(problem(
            Layer::Ipv6,
            "truncated",
            start.saturating_add(4),
            2,
        ));
    } else if let Some(sub) = c.sub(plen) {
        *c = sub;
    }
    let mut count = 0usize;
    while matches!(next, 0 | 43 | 44 | 51 | 60) {
        let pos = c.pos();
        count = count.saturating_add(1);
        if count > MAX_EXT_HEADERS {
            problems.push(problem(Layer::Ipv6, "too many extension headers", pos, 1));
            header.next = next;
            return Some((header, false));
        }
        let (Some(nh), Some(len)) = (c.u8(), c.u8()) else {
            problems.push(problem(Layer::Ipv6, "truncated", pos, c.remaining()));
            header.next = next;
            return Some((header, false));
        };
        let skip = match next {
            44 => {
                let (Some(fo), Some(_id)) = (c.be16(), c.be32()) else {
                    problems.push(problem(Layer::Ipv6, "truncated", pos, c.remaining()));
                    header.next = nh;
                    return Some((header, false));
                };
                if fo >> 3 > 0 {
                    header.frag = Frag::Later;
                    header.next = nh;
                    return Some((header, false));
                }
                if fo & 1 != 0 {
                    header.frag = Frag::First;
                }
                0
            }
            51 => usize::from(len)
                .saturating_add(2)
                .saturating_mul(4)
                .saturating_sub(2),
            _ => usize::from(len)
                .saturating_add(1)
                .saturating_mul(8)
                .saturating_sub(2),
        };
        if c.skip(skip).is_none() {
            problems.push(problem(Layer::Ipv6, "truncated", pos, c.remaining()));
            header.next = nh;
            return Some((header, false));
        }
        next = nh;
    }
    header.next = next;
    Some((header, true))
}
