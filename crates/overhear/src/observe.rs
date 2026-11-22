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

    /// The segment of a frame's tags. A tag with VLAN id 0 is an 802.1p
    /// priority tag, which hosts treat as untagged, so it adds no level: a
    /// sender cannot get a segment (and a baseline) of its own with one.
    pub fn from_vlans(v: &Vlans) -> Segment {
        let mut s = Segment::UNTAGGED;
        for tag in v.as_slice() {
            if s.push(tag.id).is_none() {
                break;
            }
        }
        s
    }

    /// Adds a level below the others; id 0 adds none. `None` when full.
    fn push(&mut self, id: u16) -> Option<()> {
        if id != 0 {
            *self.ids.get_mut(usize::from(self.len))? = id;
            self.len = self.len.saturating_add(1);
        }
        Some(())
    }

    /// Parses `"100"` or `"200.100"` (ids 0..=4095, at most four). Id 0 is
    /// a priority tag, as in [`Segment::from_vlans`]: `"0"` is untagged.
    pub fn parse(s: &str) -> Option<Segment> {
        let mut seg = Segment::UNTAGGED;
        for (i, part) in s.split('.').enumerate() {
            if i >= seg.ids.len() || part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let id: u16 = part.parse().ok().filter(|id| *id <= 4095)?;
            seg.push(id)?;
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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
        for s in ["100", "200.100", "4095", "1.2.3.4"] {
            assert_eq!(Segment::parse(s).expect(s).to_string(), s);
        }
        for s in [
            "",
            "4096",
            "1..2",
            "a",
            "1.2.3.4.5",
            "-1",
            "+1",
            "1.",
            "0.0.0.0.0",
        ] {
            assert_eq!(Segment::parse(s), None, "{s}");
        }
    }

    /// The segment of a frame carrying `tags` (TPID, VLAN id), outer first.
    fn seg_of(tags: &[(u16, u16)]) -> Segment {
        let f = overhear_testgen::eth_vlan([0xff; 6], [2, 0, 0, 0, 0, 1], tags, 0x0806, &[0; 28]);
        let p = overhear_decode::decode(&f).expect("decodes");
        assert_eq!(
            p.eth.vlans.as_slice().len(),
            tags.len(),
            "tags kept for display"
        );
        Segment::from_vlans(&p.eth.vlans)
    }

    #[test]
    fn priority_tags_are_untagged() {
        // VLAN id 0 is an 802.1p priority tag: hosts treat the frame as
        // untagged, so it must not get a segment (and a baseline) of its own.
        assert_eq!(seg_of(&[]), Segment::UNTAGGED);
        assert_eq!(seg_of(&[(0x8100, 0)]), Segment::UNTAGGED);
        assert_eq!(seg_of(&[(0x8100, 100)]).to_string(), "100");
        assert_eq!(seg_of(&[(0x88a8, 0), (0x8100, 100)]).to_string(), "100");
        assert_eq!(seg_of(&[(0x88a8, 200), (0x8100, 0)]).to_string(), "200");
        // A pin written with VLAN 0 means the same.
        assert_eq!(Segment::parse("0"), Some(Segment::UNTAGGED));
        assert_eq!(Segment::parse("0.100"), Segment::parse("100"));
    }
}
