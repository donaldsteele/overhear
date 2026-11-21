/// Protocol layer a problem was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Ethernet,
    Vlan,
    Llc,
    Arp,
    Ipv4,
    Ipv6,
    Udp,
    Icmpv6,
    Dhcp,
    Nd,
    Dns,
    Nbns,
    Ssdp,
    Lldp,
    Cdp,
    Stp,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Ethernet => "ethernet",
            Layer::Vlan => "vlan",
            Layer::Llc => "llc",
            Layer::Arp => "arp",
            Layer::Ipv4 => "ipv4",
            Layer::Ipv6 => "ipv6",
            Layer::Udp => "udp",
            Layer::Icmpv6 => "icmpv6",
            Layer::Dhcp => "dhcp",
            Layer::Nd => "nd",
            Layer::Dns => "dns",
            Layer::Nbns => "nbns",
            Layer::Ssdp => "ssdp",
            Layer::Lldp => "lldp",
            Layer::Cdp => "cdp",
            Layer::Stp => "stp",
        }
    }
}

/// A decoding problem pointing at a byte range of the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Problem {
    pub layer: Layer,
    pub reason: &'static str,
    pub offset: usize,
    pub len: usize,
}

impl Problem {
    /// The offending bytes; empty when the range is outside `frame`.
    pub fn bytes<'a>(&self, frame: &'a [u8]) -> &'a [u8] {
        match self.offset.checked_add(self.len) {
            Some(end) => frame.get(self.offset..end).unwrap_or(&[]),
            None => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_out_of_range_is_empty() {
        let p = Problem {
            layer: Layer::Dns,
            reason: "truncated",
            offset: 8,
            len: 4,
        };
        assert_eq!(p.bytes(&[0u8; 10]), &[] as &[u8]);
        assert_eq!(Layer::Icmpv6.as_str(), "icmpv6");
    }

    #[test]
    fn bytes_in_range() {
        let p = Problem {
            layer: Layer::Dns,
            reason: "x",
            offset: 1,
            len: 2,
        };
        assert_eq!(p.bytes(&[1, 2, 3, 4]), &[2, 3]);
    }
}
