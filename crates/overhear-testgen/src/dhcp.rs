//! DHCPv4 payload builder.

use std::net::Ipv4Addr;

/// A BOOTP/DHCP message. `options` are written as given, then End.
#[derive(Debug, Clone)]
pub struct DhcpMsg {
    pub op: u8,
    /// Hardware type and address length (1 and 6, Ethernet, unless changed).
    pub htype: u8,
    pub hlen: u8,
    pub xid: u32,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 6],
    /// Raw `sname` field bytes, zero-padded to 64.
    pub sname: Vec<u8>,
    /// Raw `file` field bytes, zero-padded to 128.
    pub file: Vec<u8>,
    pub options: Vec<(u8, Vec<u8>)>,
    /// Write the magic cookie and options. Without it the message is plain BOOTP.
    pub cookie: bool,
}

fn fixed(field: &[u8], n: usize) -> Vec<u8> {
    let mut v: Vec<u8> = field.iter().copied().take(n).collect();
    v.resize(n, 0);
    v
}

impl DhcpMsg {
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(300);
        b.extend_from_slice(&[self.op, self.htype, self.hlen, 0]);
        b.extend_from_slice(&self.xid.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.flags.to_be_bytes());
        for a in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            b.extend_from_slice(&a.octets());
        }
        b.extend_from_slice(&fixed(&self.chaddr, 16));
        b.extend_from_slice(&fixed(&self.sname, 64));
        b.extend_from_slice(&fixed(&self.file, 128));
        if self.cookie {
            b.extend_from_slice(&[99, 130, 83, 99]);
            for (code, data) in &self.options {
                b.push(*code);
                b.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
                b.extend_from_slice(data);
            }
            b.push(255);
        }
        b
    }

    pub fn discover(mac: [u8; 6], host: &str) -> Self {
        let mut id = vec![1];
        id.extend_from_slice(&mac);
        DhcpMsg {
            op: 1,
            htype: 1,
            hlen: 6,
            xid: 0x3903_f326,
            flags: 0x8000,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac,
            sname: Vec::new(),
            file: Vec::new(),
            options: vec![
                (53, vec![1]),
                (12, host.as_bytes().to_vec()),
                (55, vec![1, 3, 6, 15]),
                (61, id),
            ],
            cookie: true,
        }
    }

    pub fn reply(msg_type: u8, server: Ipv4Addr, yiaddr: Ipv4Addr, mac: [u8; 6]) -> Self {
        DhcpMsg {
            op: 2,
            htype: 1,
            hlen: 6,
            xid: 0x3903_f326,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr,
            siaddr: server,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac,
            sname: Vec::new(),
            file: Vec::new(),
            options: vec![
                (53, vec![msg_type]),
                (54, server.octets().to_vec()),
                (51, 3600u32.to_be_bytes().to_vec()),
                (1, vec![255, 255, 255, 0]),
                (3, server.octets().to_vec()),
            ],
            cookie: true,
        }
    }
}
