//! Everything remembered about the network, under one memory budget.

pub mod bounded;
pub mod budget;
pub mod device;
pub mod table;

pub use bounded::Bounded;
pub use budget::Budget;
pub use device::Device;
pub use table::DeviceTable;

use crate::observe::{Observation, Segment, Ts};
use crate::warn::{Output, Pins, WarnEngine};

pub const MAX_IPV4: usize = 16;
pub const MAX_IPV6: usize = 16;
pub const MAX_NAMES: usize = 16;
pub const MAX_SERVICES: usize = 64;
pub const MAX_MODELS: usize = 8;
pub const MAX_DETAILS: usize = 32;
pub const MAX_VLANS: usize = 16;
/// Longest string kept; longer ones are cut.
pub const MAX_STR: usize = 255;

pub struct Tracker {
    pub budget: Budget,
    pub table: DeviceTable,
    pub warn: WarnEngine,
}

impl Tracker {
    pub fn new(max_memory: usize, pins: Pins) -> Self {
        Tracker {
            budget: Budget::new(max_memory),
            table: DeviceTable::new(),
            warn: WarnEngine::new(pins),
        }
    }

    /// Applies the observations of one frame to the device table and the
    /// warning rules (whose outputs go to `out`), then evicts the least
    /// recently heard unprotected devices until the budget holds (the last
    /// device always stays).
    pub fn apply(&mut self, seg: Segment, ts: Ts, obs: &[Observation], out: &mut Vec<Output>) {
        for o in obs {
            self.table.apply(seg, ts, o, &mut self.budget);
            self.warn.observe(seg, ts, o, &mut self.budget, out);
            while self.budget.over() && self.table.len() > 1 {
                let warn = &self.warn;
                let Some(gone) = self
                    .table
                    .evict_lru(&mut self.budget, &|m| warn.is_protected(m))
                else {
                    break;
                };
                self.warn.forget(&gone, &mut self.budget);
            }
        }
    }

    /// Called about once a second with the time in seconds since the epoch.
    pub fn tick(&mut self, now: i64, out: &mut Vec<Output>) {
        let now = Ts { sec: now, usec: 0 };
        self.warn.tick(now, &mut self.budget, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::ProtoTag;
    use overhear_decode::Mac;
    use std::net::Ipv4Addr;

    fn ts(sec: i64) -> Ts {
        Ts { sec, usec: 0 }
    }

    fn heard(mac: Mac) -> Observation<'static> {
        Observation::Heard {
            mac,
            proto: ProtoTag::Other,
        }
    }

    #[test]
    fn pinned_server_mac_survives_flood() {
        let pins = Pins {
            dhcp: vec![(Ipv4Addr::new(10, 0, 0, 1), None)],
            ..Pins::default()
        };
        let mut tr = Tracker::new(64 * 1024, pins);
        let server = Mac([0x00, 0x16, 0xff, 0, 0, 1]);
        let reply = Observation::DhcpReply {
            client: Mac([0x00, 0x16, 0xff, 0, 0, 2]),
            server_mac: server,
            server_id: Ipv4Addr::new(10, 0, 0, 1),
            msg_type: 5,
            router: Some(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let mut out = Vec::new();
        tr.apply(Segment::UNTAGGED, ts(0), &[heard(server), reply], &mut out);
        for i in 0..10_000u32 {
            let b = i.to_be_bytes();
            let m = Mac([0x00, 0x16, b[0], b[1], b[2], b[3]]);
            tr.apply(Segment::UNTAGGED, ts(i64::from(i)), &[heard(m)], &mut out);
            assert_eq!(
                tr.budget.used(),
                tr.table.recount() + tr.warn.cost(),
                "after {i}"
            );
        }
        assert!(tr.table.evictions() > 0);
        assert!(tr.budget.used() <= 64 * 1024);
        assert!(tr.table.get(&server).is_some(), "pinned server evicted");
        assert_eq!(out, []);
    }
}
