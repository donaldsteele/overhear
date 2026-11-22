//! Expected servers given on the command line.

use std::net::{Ipv4Addr, Ipv6Addr};

use overhear_decode::Mac;

use crate::observe::Segment;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RouterId {
    Mac(Mac),
    Ip(Ipv6Addr),
}

/// `--dhcp-server` and `--router` values; a `None` segment means every
/// segment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pins {
    pub dhcp: Vec<(Ipv4Addr, Option<Segment>)>,
    pub routers: Vec<(RouterId, Option<Segment>)>,
}

fn applies(pin: Option<Segment>, seg: Segment) -> bool {
    pin.is_none_or(|p| p == seg)
}

impl Pins {
    /// The DHCP servers pinned for `seg`.
    pub fn dhcp_for(&self, seg: Segment) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.dhcp
            .iter()
            .filter(move |(_, s)| applies(*s, seg))
            .map(|(ip, _)| *ip)
    }

    /// The routers pinned for `seg`.
    pub fn routers_for(&self, seg: Segment) -> impl Iterator<Item = RouterId> + '_ {
        self.routers
            .iter()
            .filter(move |(_, s)| applies(*s, seg))
            .map(|(id, _)| *id)
    }
}

/// Splits off an optional `@VLAN`.
fn split_vlan(s: &str) -> Result<(&str, Option<Segment>), String> {
    match s.split_once('@') {
        None => Ok((s, None)),
        Some((addr, vlan)) => match Segment::parse(vlan) {
            Some(seg) => Ok((addr, Some(seg))),
            None => Err(format!(
                "'{vlan}' is not a VLAN (ids 0 to 4095, QinQ written outer.inner)"
            )),
        },
    }
}

/// `IP` or `IP@VLAN`.
pub fn parse_dhcp_pin(s: &str) -> Result<(Ipv4Addr, Option<Segment>), String> {
    let (addr, seg) = split_vlan(s)?;
    let ip = addr
        .parse()
        .map_err(|_| format!("'{addr}' is not an IPv4 address"))?;
    Ok((ip, seg))
}

/// `MAC` or `IPV6`, optionally followed by `@VLAN`.
pub fn parse_router_pin(s: &str) -> Result<(RouterId, Option<Segment>), String> {
    let (id, seg) = split_vlan(s)?;
    if let Ok(ip) = id.parse() {
        return Ok((RouterId::Ip(ip), seg));
    }
    match parse_mac(id) {
        Some(mac) => Ok((RouterId::Mac(mac), seg)),
        None => Err(format!("'{id}' is not a MAC or IPv6 address")),
    }
}

/// Six pairs of hex digits separated by `:` or `-`.
fn parse_mac(s: &str) -> Option<Mac> {
    let mut b = [0u8; 6];
    let mut parts = s.split([':', '-']);
    for slot in &mut b {
        let p = parts.next()?;
        if p.len() != 2 || !p.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        *slot = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(Mac(b))
}
