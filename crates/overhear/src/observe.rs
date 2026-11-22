//! Protocol-neutral facts that decoders extract from packets and the device
//! table consumes.

use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use overhear_decode::{Mac, Vlans};

/// Capture time of a frame.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ts {
    pub sec: i64,
    pub usec: u32,
}

/// The VLAN stack a frame was seen on: up to four ids, outer first.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Segment {
    ids: [u16; 4],
    len: u8,
}

impl Segment {
    pub const UNTAGGED: Segment = Segment {
        ids: [0; 4],
        len: 0,
    };

    pub fn from_vlans(v: &Vlans) -> Segment {
        let mut s = Segment::UNTAGGED;
        for (slot, tag) in s.ids.iter_mut().zip(v.as_slice()) {
            *slot = tag.id;
            s.len = s.len.saturating_add(1);
        }
        s
    }

    /// Parses `"100"` or `"200.100"` (ids 0..=4095, at most four).
    pub fn parse(s: &str) -> Option<Segment> {
        let mut seg = Segment::UNTAGGED;
        for part in s.split('.') {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let id: u16 = part.parse().ok().filter(|id| *id <= 4095)?;
            *seg.ids.get_mut(usize::from(seg.len))? = id;
            seg.len = seg.len.saturating_add(1);
        }
        Some(seg)
    }

    pub fn is_untagged(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.len == 0 {
            return f.write_str("untagged");
        }
        for (i, id) in self.ids.iter().take(usize::from(self.len)).enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{id}")?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProtoTag {
    Arp,
    Dhcp,
    Nd,
    Mdns,
    Llmnr,
    Nbns,
    Ssdp,
    Lldp,
    Cdp,
    Stp,
    Other,
}

impl ProtoTag {
    pub fn as_str(self) -> &'static str {
        match self {
            ProtoTag::Arp => "ARP",
            ProtoTag::Dhcp => "DHCP",
            ProtoTag::Nd => "ND",
            ProtoTag::Mdns => "mDNS",
            ProtoTag::Llmnr => "LLMNR",
            ProtoTag::Nbns => "NBNS",
            ProtoTag::Ssdp => "SSDP",
            ProtoTag::Lldp => "LLDP",
            ProtoTag::Cdp => "CDP",
            ProtoTag::Stp => "STP",
            ProtoTag::Other => "other",
        }
    }
}

/// Where a name came from, in display priority order (highest first).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NameSource {
    Dhcp,
    Mdns,
    Netbios,
    Lldp,
    Cdp,
    Llmnr,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Router,
    RouterNoDefault,
    Bridge,
    AccessPoint,
    Phone,
    DhcpServer,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AnswerKind {
    Llmnr,
    Netbios,
    MdnsUnique,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation<'a> {
    Heard {
        mac: Mac,
        proto: ProtoTag,
    },
    Address {
        mac: Mac,
        ip: IpAddr,
    },
    Claim {
        mac: Mac,
        ip: IpAddr,
    },
    Name {
        mac: Mac,
        name: Cow<'a, [u8]>,
        source: NameSource,
    },
    Service {
        mac: Mac,
        name: Cow<'a, [u8]>,
    },
    Model {
        mac: Mac,
        text: Cow<'a, [u8]>,
    },
    Role {
        mac: Mac,
        role: Role,
    },
    Detail {
        mac: Mac,
        key: &'static str,
        value: Cow<'a, [u8]>,
    },
    DhcpReply {
        client: Mac,
        server_mac: Mac,
        server_id: Ipv4Addr,
        msg_type: u8,
        router: Option<Ipv4Addr>,
    },
    RouterAdvert {
        mac: Mac,
        src: Ipv6Addr,
        lifetime: u16,
        dns: bool,
        global_prefix: bool,
    },
    NameAnswer {
        mac: Mac,
        kind: AnswerKind,
        name: Cow<'a, [u8]>,
        data: Cow<'a, [u8]>,
    },
    StpRoot {
        root: [u8; 8],
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_display_and_parse() {
        assert_eq!(Segment::UNTAGGED.to_string(), "untagged");
        for s in ["100", "200.100", "0", "4095", "1.2.3.4"] {
            assert_eq!(Segment::parse(s).expect(s).to_string(), s);
        }
        for s in ["", "4096", "1..2", "a", "1.2.3.4.5", "-1", "+1", "1."] {
            assert_eq!(Segment::parse(s), None, "{s}");
        }
    }
}
