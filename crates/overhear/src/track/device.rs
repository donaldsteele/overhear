//! What is known about one MAC address.

use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

use overhear_decode::Mac;

use super::bounded::Bounded;
use super::{MAX_DETAILS, MAX_IPV4, MAX_IPV6, MAX_MODELS, MAX_NAMES, MAX_SERVICES, MAX_VLANS};
use crate::observe::{NameSource, ProtoTag, Role, Segment};

#[derive(Debug)]
pub struct Device {
    pub mac: Mac,
    pub random: bool,
    pub ipv4: Bounded<(Ipv4Addr, Segment)>,
    pub ipv6: Bounded<(Ipv6Addr, Segment)>,
    pub names: Bounded<(Box<[u8]>, NameSource)>,
    pub services: Bounded<Box<[u8]>>,
    pub models: Bounded<Box<[u8]>>,
    pub details: Bounded<(&'static str, Box<[u8]>)>,
    /// Bit set of [`Role`]s.
    pub roles: u8,
    pub vlans: Bounded<Segment>,
    /// Bit set of [`ProtoTag`]s.
    pub heard: u16,
    pub first_heard: i64,
    pub last_heard: i64,
    pub packets: u64,
}

const TAGS: [ProtoTag; 11] = [
    ProtoTag::Arp,
    ProtoTag::Dhcp,
    ProtoTag::Nd,
    ProtoTag::Mdns,
    ProtoTag::Llmnr,
    ProtoTag::Nbns,
    ProtoTag::Ssdp,
    ProtoTag::Lldp,
    ProtoTag::Cdp,
    ProtoTag::Stp,
    ProtoTag::Other,
];

fn tag_bit(t: ProtoTag) -> u16 {
    1 << (t as u16)
}

fn role_bit(r: Role) -> u8 {
    1 << (r as u8)
}

fn boxed_heap(b: &[u8]) -> usize {
    b.len()
}

impl Device {
    pub fn new(mac: Mac, ts: i64) -> Device {
        Device {
            mac,
            random: mac.is_local(),
            ipv4: Bounded::new(MAX_IPV4),
            ipv6: Bounded::new(MAX_IPV6),
            names: Bounded::new(MAX_NAMES),
            services: Bounded::new(MAX_SERVICES),
            models: Bounded::new(MAX_MODELS),
            details: Bounded::new(MAX_DETAILS),
            roles: 0,
            vlans: Bounded::new(MAX_VLANS),
            heard: 0,
            first_heard: ts,
            last_heard: ts,
            packets: 0,
        }
    }

    /// The newest name of the highest-priority source present.
    pub fn display_name(&self) -> Option<&[u8]> {
        let mut best: Option<&(Box<[u8]>, NameSource)> = None;
        for n in self.names.iter() {
            if best.is_none_or(|b| n.1 <= b.1) {
                best = Some(n);
            }
        }
        best.map(|(name, _)| &name[..])
    }

    pub fn has_role(&self, r: Role) -> bool {
        self.roles & role_bit(r) != 0
    }

    pub fn add_role(&mut self, r: Role) {
        self.roles |= role_bit(r);
    }

    pub fn mark_heard(&mut self, t: ProtoTag) {
        self.heard |= tag_bit(t);
    }

    pub fn heard_tags(&self) -> impl Iterator<Item = ProtoTag> {
        let bits = self.heard;
        TAGS.into_iter().filter(move |t| bits & tag_bit(*t) != 0)
    }

    /// Bytes this device accounts for against the memory budget.
    pub fn cost(&self) -> usize {
        size_of::<Device>()
            + self.ipv4.len() * size_of::<(Ipv4Addr, Segment)>()
            + self.ipv6.len() * size_of::<(Ipv6Addr, Segment)>()
            + self.names.len() * size_of::<(Box<[u8]>, NameSource)>()
            + self.names.iter().map(|n| boxed_heap(&n.0)).sum::<usize>()
            + self.services.len() * size_of::<Box<[u8]>>()
            + self.services.iter().map(|s| boxed_heap(s)).sum::<usize>()
            + self.models.len() * size_of::<Box<[u8]>>()
            + self.models.iter().map(|s| boxed_heap(s)).sum::<usize>()
            + self.details.len() * size_of::<(&'static str, Box<[u8]>)>()
            + self.details.iter().map(|d| boxed_heap(&d.1)).sum::<usize>()
            + self.vlans.len() * size_of::<Segment>()
    }
}
