//! A capture that floods the device table: every frame from a new MAC.

use std::net::Ipv4Addr;

use crate::{BCAST, DhcpMsg, DnsBuilder, RDataSpec, TFrame, arp, eth, eth_ipv4, ipv4_udp};

/// A 255-byte DNS name: three 63-byte labels and one 61-byte label.
fn long_name() -> String {
    let label = |n: usize, c: char| c.to_string().repeat(n);
    format!(
        "{}.{}.{}.{}",
        label(63, 'a'),
        label(63, 'b'),
        label(63, 'c'),
        label(61, 'd')
    )
}

/// Knuth's MMIX linear congruential generator.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 16
    }

    /// A unicast, locally administered MAC.
    fn mac(&mut self) -> [u8; 6] {
        let b = self.next().to_be_bytes();
        [(b[2] & 0xfc) | 0x02, b[3], b[4], b[5], b[6], b[7]]
    }
}

/// `n` frames, repeating DHCP DISCOVER (255-byte hostname), mDNS announcement
/// (255-byte name) and ARP announcement, each from a MAC drawn from a seeded
/// generator.
pub fn flood(n: u64) -> impl Iterator<Item = TFrame> {
    let mut rng = Lcg(0x6f76_6572_6865_6172);
    let host = "h".repeat(255);
    let name = long_name();
    (0..n).map(move |i| {
        let src = rng.mac();
        let ipa = Ipv4Addr::from(((rng.next() as u32) & 0x00ff_ffff) | 0x0a00_0000);
        let data = match i % 3 {
            0 => {
                let msg = DhcpMsg::discover(src, &host).bytes();
                let ip = ipv4_udp(Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, 68, 67, &msg);
                eth_ipv4(BCAST, src, &ip)
            }
            1 => {
                let msg = DnsBuilder::new(0x8400)
                    .answer(&name, 1, 0x8001, 120, RDataSpec::A(ipa))
                    .bytes();
                let ip = ipv4_udp(ipa, Ipv4Addr::new(224, 0, 0, 251), 5353, 5353, &msg);
                eth_ipv4([0x01, 0x00, 0x5e, 0, 0, 0xfb], src, &ip)
            }
            _ => eth(BCAST, src, 0x0806, &arp(1, src, ipa, [0; 6], ipa)),
        };
        TFrame {
            sec: 1_700_000_000 + (i / 1000) as i64,
            usec: ((i % 1000) * 1000) as u32,
            data,
            orig_len: None,
        }
    })
}
