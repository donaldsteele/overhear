//! MAC -> [`Device`] map with least-recently-heard eviction.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use overhear_decode::Mac;

use super::{Budget, Device, MAX_STR};
use crate::observe::{Observation, Segment, Ts};

/// Bytes charged per device for the map and LRU entries.
const OVERHEAD: usize = 64;

pub struct DeviceTable {
    map: HashMap<Mac, (Device, u64)>,
    lru: BTreeSet<(u64, Mac)>,
    clock: u64,
    evictions: u64,
    stp_root: Option<[u8; 8]>,
}

impl DeviceTable {
    pub fn new() -> Self {
        DeviceTable {
            map: HashMap::new(),
            lru: BTreeSet::new(),
            clock: 0,
            evictions: 0,
            stp_root: None,
        }
    }

    pub fn apply(&mut self, seg: Segment, ts: Ts, obs: &Observation, budget: &mut Budget) {
        if let Observation::StpRoot { root } = obs {
            self.stp_root = Some(*root);
            return;
        }
        let mac = match obs {
            Observation::Heard { mac, .. }
            | Observation::Address { mac, .. }
            | Observation::Claim { mac, .. }
            | Observation::Name { mac, .. }
            | Observation::Service { mac, .. }
            | Observation::Model { mac, .. }
            | Observation::Role { mac, .. }
            | Observation::Detail { mac, .. }
            | Observation::RouterAdvert { mac, .. } => *mac,
            Observation::DhcpReply { .. }
            | Observation::NameAnswer { .. }
            | Observation::StpRoot { .. } => return,
        };
        self.clock = self.clock.wrapping_add(1);
        let stamp = self.clock;
        let is_new = !self.map.contains_key(&mac);
        if is_new {
            let d = Device::new(mac, ts.sec);
            budget.adjust(0, d.cost() + OVERHEAD);
            self.lru.insert((stamp, mac));
            self.map.insert(mac, (d, stamp));
        } else if let Some((_, old)) = self.map.get_mut(&mac) {
            self.lru.remove(&(*old, mac));
            *old = stamp;
            self.lru.insert((stamp, mac));
        }
        let Some((dev, _)) = self.map.get_mut(&mac) else {
            return;
        };
        let before = dev.cost();
        mutate(dev, seg, ts, obs);
        budget.adjust(before, dev.cost());
    }

    /// Drops the least recently touched device that `protected` does not
    /// name, and returns its address.
    pub fn evict_lru(
        &mut self,
        budget: &mut Budget,
        protected: &dyn Fn(&Mac) -> bool,
    ) -> Option<Mac> {
        let key = *self.lru.iter().find(|(_, m)| !protected(m))?;
        self.lru.remove(&key);
        let (d, _) = self.map.remove(&key.1)?;
        budget.adjust(d.cost() + OVERHEAD, 0);
        self.evictions = self.evictions.saturating_add(1);
        Some(key.1)
    }

    pub fn get(&self, mac: &Mac) -> Option<&Device> {
        self.map.get(mac).map(|(d, _)| d)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.map.values().map(|(d, _)| d)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Σ(cost + overhead) from scratch; must equal the budget's `used`.
    pub fn recount(&self) -> usize {
        self.map.values().map(|(d, _)| d.cost() + OVERHEAD).sum()
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    pub fn stp_root(&self) -> Option<[u8; 8]> {
        self.stp_root
    }
}

fn cut(b: &[u8]) -> Box<[u8]> {
    b.get(..MAX_STR).unwrap_or(b).into()
}

fn mutate(d: &mut Device, seg: Segment, ts: Ts, obs: &Observation) {
    match obs {
        Observation::Heard { proto, .. } => {
            d.packets = d.packets.saturating_add(1);
            d.last_heard = ts.sec;
            if !seg.is_untagged() {
                d.vlans.push(seg);
            }
            d.mark_heard(*proto);
        }
        Observation::Address { ip, .. } | Observation::Claim { ip, .. } => match ip {
            IpAddr::V4(a) => d.ipv4.push((*a, seg)),
            IpAddr::V6(a) => d.ipv6.push((*a, seg)),
        },
        Observation::RouterAdvert { src, .. } => d.ipv6.push((*src, seg)),
        Observation::Name { name, source, .. } => d.names.push((cut(name), *source)),
        Observation::Service { name, .. } => d.services.push(cut(name)),
        Observation::Model { text, .. } => d.models.push(cut(text)),
        Observation::Role { role, .. } => d.add_role(*role),
        Observation::Detail { key, value, .. } => d.details.push((key, cut(value))),
        Observation::DhcpReply { .. }
        | Observation::NameAnswer { .. }
        | Observation::StpRoot { .. } => {}
    }
}

impl Default for DeviceTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{NameSource, ProtoTag};
    use crate::track::Tracker;
    use std::borrow::Cow;
    use std::net::{IpAddr, Ipv4Addr};

    fn mac(n: u32) -> Mac {
        let b = n.to_be_bytes();
        Mac([0x00, 0x16, b[0], b[1], b[2], b[3]])
    }

    fn ts(sec: i64) -> Ts {
        Ts { sec, usec: 0 }
    }

    const U: Segment = Segment::UNTAGGED;

    fn heard(m: Mac) -> Observation<'static> {
        Observation::Heard {
            mac: m,
            proto: ProtoTag::Arp,
        }
    }

    fn name(m: Mac, n: &'static [u8], source: NameSource) -> Observation<'static> {
        Observation::Name {
            mac: m,
            name: Cow::Borrowed(n),
            source,
        }
    }

    fn addr(m: Mac, last: u8) -> Observation<'static> {
        Observation::Address {
            mac: m,
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
        }
    }

    fn setup() -> (DeviceTable, Budget) {
        (DeviceTable::new(), Budget::new(usize::MAX))
    }

    #[test]
    fn heard_creates_device_and_counts() {
        let (mut t, mut b) = setup();
        let m = mac(1);
        t.apply(U, ts(5), &heard(m), &mut b);
        t.apply(
            Segment::parse("100").expect("seg"),
            ts(9),
            &heard(m),
            &mut b,
        );
        let d = t.get(&m).expect("device");
        assert_eq!((d.packets, d.first_heard, d.last_heard), (2, 5, 9));
        assert_eq!(d.heard_tags().collect::<Vec<_>>(), [ProtoTag::Arp]);
        assert_eq!(d.vlans.len(), 1);
        assert_eq!(t.len(), 1);
        assert_eq!(b.used(), t.recount());
    }

    #[test]
    fn addresses_capped_at_16_oldest_dropped() {
        let (mut t, mut b) = setup();
        let m = mac(1);
        t.apply(U, ts(0), &heard(m), &mut b);
        for i in 1..=17 {
            t.apply(U, ts(0), &addr(m, i), &mut b);
        }
        let d = t.get(&m).expect("device");
        assert_eq!(d.ipv4.len(), 16);
        let has = |n: u8| d.ipv4.iter().any(|(a, _)| *a == Ipv4Addr::new(10, 0, 0, n));
        assert!(!has(1) && has(17));
    }

    #[test]
    fn repeated_address_moves_to_newest() {
        let (mut t, mut b) = setup();
        let m = mac(1);
        t.apply(U, ts(0), &heard(m), &mut b);
        for i in 1..=16 {
            t.apply(U, ts(0), &addr(m, i), &mut b);
        }
        t.apply(U, ts(0), &addr(m, 1), &mut b);
        t.apply(U, ts(0), &addr(m, 17), &mut b);
        let d = t.get(&m).expect("device");
        let has = |n: u8| d.ipv4.iter().any(|(a, _)| *a == Ipv4Addr::new(10, 0, 0, n));
        assert!(has(1) && !has(2) && has(17));
        assert_eq!(d.ipv4.len(), 16);
    }

    #[test]
    fn long_strings_cut_to_255() {
        let (mut t, mut b) = setup();
        let m = mac(1);
        let long = vec![b'a'; 300];
        t.apply(U, ts(0), &heard(m), &mut b);
        let o = Observation::Name {
            mac: m,
            name: Cow::Owned(long),
            source: NameSource::Mdns,
        };
        t.apply(U, ts(0), &o, &mut b);
        let d = t.get(&m).expect("device");
        assert_eq!(d.display_name().map(<[u8]>::len), Some(255));
        assert_eq!(b.used(), t.recount());
    }

    #[test]
    fn display_name_priority() {
        let (mut t, mut b) = setup();
        let m = mac(1);
        t.apply(U, ts(0), &heard(m), &mut b);
        t.apply(U, ts(0), &name(m, b"switch", NameSource::Lldp), &mut b);
        t.apply(U, ts(0), &name(m, b"NB", NameSource::Netbios), &mut b);
        t.apply(U, ts(0), &name(m, b"mdns-host", NameSource::Mdns), &mut b);
        assert_eq!(
            t.get(&m).and_then(Device::display_name),
            Some(&b"mdns-host"[..])
        );
        t.apply(U, ts(0), &name(m, b"dhcp-host", NameSource::Dhcp), &mut b);
        assert_eq!(
            t.get(&m).and_then(Device::display_name),
            Some(&b"dhcp-host"[..])
        );
    }

    #[test]
    fn random_flag() {
        let (mut t, mut b) = setup();
        let local = mac(1);
        let local = Mac([
            0x02, local.0[1], local.0[2], local.0[3], local.0[4], local.0[5],
        ]);
        let global = Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        t.apply(U, ts(0), &heard(local), &mut b);
        t.apply(U, ts(0), &heard(global), &mut b);
        assert!(t.get(&local).expect("local").random);
        assert!(!t.get(&global).expect("global").random);
    }

    #[test]
    fn accounting_matches_recount() {
        let (mut t, mut b) = setup();
        let mut x: u64 = 1;
        let mut next = move || {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (x >> 33) as u32
        };
        let names: [&'static [u8]; 3] = [b"a", b"host-with-longer-name", b"x"];
        for i in 0..10_000 {
            let m = mac(next() % 300);
            let o = match next() % 5 {
                0 => heard(m),
                1 => addr(m, (next() % 40) as u8),
                2 => name(m, names[(next() % 3) as usize], NameSource::Mdns),
                3 => Observation::Service {
                    mac: m,
                    name: Cow::Owned(vec![b's'; (next() % 300) as usize]),
                },
                _ => Observation::Detail {
                    mac: m,
                    key: "k",
                    value: Cow::Owned(vec![1; (next() % 20) as usize]),
                },
            };
            // Heard first so the device exists.
            t.apply(U, ts(i), &heard(m), &mut b);
            t.apply(U, ts(i), &o, &mut b);
            assert_eq!(b.used(), t.recount());
        }
        assert!(t.len() <= 300);
    }

    #[test]
    fn name_for_unknown_mac_creates_device() {
        let (mut t, mut b) = setup();
        let m = mac(7);
        t.apply(U, ts(42), &name(m, b"client", NameSource::Dhcp), &mut b);
        let d = t.get(&m).expect("created");
        assert_eq!(d.display_name(), Some(&b"client"[..]));
        assert_eq!((d.packets, d.first_heard, d.last_heard), (0, 42, 42));
        assert_eq!(d.heard, 0);
        assert_eq!(b.used(), t.recount());
        t.apply(U, ts(43), &heard(m), &mut b);
        assert_eq!(t.get(&m).map(|d| d.packets), Some(1));
        assert_eq!(b.used(), t.recount());
    }
    #[test]
    fn eviction_respects_budget() {
        let mut tr = Tracker::new(64 * 1024);
        let long: Vec<u8> = vec![b'n'; 200];
        for i in 0..10_000u32 {
            let m = mac(i);
            let obs = [
                heard(m),
                Observation::Name {
                    mac: m,
                    name: Cow::Borrowed(&long),
                    source: NameSource::Mdns,
                },
            ];
            tr.apply(U, ts(i64::from(i)), &obs);
            assert_eq!(tr.budget.used(), tr.table.recount());
        }
        assert!(tr.budget.used() <= 64 * 1024);
        assert!(tr.table.len() < 10_000);
        assert!(tr.table.evictions() > 0);
        assert!(tr.table.get(&mac(9_999)).is_some());
        assert!(tr.table.get(&mac(0)).is_none());
    }

    #[test]
    fn protected_mac_survives_flood() {
        let (mut t, mut b) = setup();
        let first = mac(0);
        for i in 0..50 {
            t.apply(U, ts(0), &heard(mac(i)), &mut b);
        }
        for _ in 0..49 {
            let gone = t.evict_lru(&mut b, &|m| *m == first).expect("evicted");
            assert_ne!(gone, first);
        }
        assert_eq!(t.len(), 1);
        assert!(t.get(&first).is_some());
        assert_eq!(t.evict_lru(&mut b, &|m| *m == first), None);
        assert_eq!(b.used(), t.recount());
    }

    #[test]
    fn time_going_backwards_does_not_break_lru() {
        let (mut t, mut b) = setup();
        t.apply(U, ts(1000), &heard(mac(1)), &mut b);
        t.apply(U, ts(500), &heard(mac(2)), &mut b);
        t.apply(U, ts(100), &heard(mac(3)), &mut b);
        // Touch 1 again with an older time: 2 is now the least recent.
        t.apply(U, ts(50), &heard(mac(1)), &mut b);
        assert_eq!(t.evict_lru(&mut b, &|_| false), Some(mac(2)));
        assert_eq!(t.evict_lru(&mut b, &|_| false), Some(mac(3)));
    }
}
