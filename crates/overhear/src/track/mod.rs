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
use crate::warn::{Output, Pins, Rule, WarnEngine};

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
        let mut evicted = false;
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
                evicted = true;
            }
        }
        if evicted {
            self.warn.operational(
                ts,
                Rule::MemoryEviction,
                "device table full, dropping least recently heard devices: possible MAC flood"
                    .into(),
                &mut self.budget,
                out,
            );
        }
    }

    /// Called about once a second with the time in seconds since the epoch.
    pub fn tick(&mut self, now: i64, out: &mut Vec<Output>) {
        let now = Ts { sec: now, usec: 0 };
        self.warn.tick(now, &mut self.budget, out);
    }

    /// At the end of a run: outputs every pending repeat summary.
    pub fn flush(&mut self, now: i64, out: &mut Vec<Output>) {
        let now = Ts { sec: now, usec: 0 };
        self.warn.flush(now, &mut self.budget, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{AnswerKind, ProtoTag};
    use crate::warn::Severity;
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

    fn flooded(tr: &mut Tracker, n: u32, secs: i64) -> Vec<Output> {
        let mut out = Vec::new();
        for i in 0..n {
            let b = i.to_be_bytes();
            let m = Mac([0x00, 0x16, b[0], b[1], b[2], b[3]]);
            let at = ts(i64::from(i) * secs / i64::from(n));
            tr.apply(Segment::UNTAGGED, at, &[heard(m)], &mut out);
        }
        out
    }

    #[test]
    fn eviction_warning_once_a_minute() {
        let mut tr = Tracker::new(64 * 1024, Pins::default());
        let out = flooded(&mut tr, 10_000, 30);
        assert!(tr.table.evictions() > 0);
        let evictions: Vec<_> = out
            .iter()
            .filter(|o| matches!(o, Output::Warning(w) if w.rule == Rule::MemoryEviction))
            .collect();
        assert_eq!(evictions.len(), 1, "{out:?}");
        let Output::Warning(w) = evictions[0] else {
            unreachable!()
        };
        assert_eq!(w.severity, Severity::Low);
        assert_eq!(w.segment, None);
        assert_eq!(w.subject, "memory-eviction");
        assert_eq!(
            w.message,
            "device table full, dropping least recently heard devices: possible MAC flood"
        );
        // A minute on, the next eviction is reported again.
        let mut more = Vec::new();
        for i in 0..2000u32 {
            let m = Mac([0x00, 0x17, 0, 0, (i >> 8) as u8, i as u8]);
            tr.apply(Segment::UNTAGGED, ts(100), &[heard(m)], &mut more);
        }
        assert_eq!(more.len(), 1);
    }

    #[test]
    fn budget_recount_includes_warn_state() {
        let mut tr = Tracker::new(64 * 1024, Pins::default());
        let mut out = Vec::new();
        for i in 0..3000u32 {
            let m = Mac([0x02, 0, 0, 0, (i >> 8) as u8, i as u8]);
            let n = (i % 7) as u8;
            let obs = [
                heard(m),
                Observation::Claim {
                    mac: m,
                    ip: Ipv4Addr::new(10, 0, n, (i % 50) as u8).into(),
                },
                Observation::NameAnswer {
                    mac: m,
                    kind: AnswerKind::Llmnr,
                    name: format!("host{}", i % 40).into_bytes().into(),
                    data: vec![n].into(),
                },
            ];
            tr.apply(Segment::UNTAGGED, ts(i64::from(i)), &obs, &mut out);
            assert_eq!(
                tr.budget.used(),
                tr.table.recount() + tr.warn.cost(),
                "after {i}"
            );
        }
        assert!(tr.table.evictions() > 0);
        assert!(tr.warn.cost() > 0);
    }

    fn claim_flood(tr: &mut Tracker, n: u32) {
        let mut out = Vec::new();
        for i in 0..n {
            let m = Mac([0x02, 0, 0, 0, 0, (i % 100) as u8]);
            let ip = Ipv4Addr::from(0x0a00_0000 + i);
            let o = Observation::Claim {
                mac: m,
                ip: ip.into(),
            };
            tr.warn
                .observe(Segment::UNTAGGED, ts(0), &o, &mut tr.budget, &mut out);
        }
    }

    fn seed_devices(tr: &mut Tracker, n: u8) {
        let mut out = Vec::new();
        for i in 0..n {
            let m = Mac([0x02, 0, 0, 0, 0, i]);
            tr.apply(Segment::UNTAGGED, ts(0), &[heard(m)], &mut out);
        }
    }

    #[test]
    fn claim_flood_is_capped() {
        let mut tr = Tracker::new(1 << 30, Pins::default());
        seed_devices(&mut tr, 100);
        claim_flood(&mut tr, 70_000);
        assert_eq!(tr.warn.state_sizes().0, 65536);
        assert_eq!(tr.budget.used(), tr.table.recount() + tr.warn.cost());
        assert_eq!(tr.table.len(), 100);
    }

    #[test]
    fn answer_flood_is_capped() {
        let mut tr = Tracker::new(1 << 30, Pins::default());
        seed_devices(&mut tr, 100);
        let mut out = Vec::new();
        for i in 0..20_000u32 {
            let o = Observation::NameAnswer {
                mac: Mac([0x02, 0, 0, 0, 0, (i % 100) as u8]),
                kind: AnswerKind::MdnsUnique,
                name: format!("n{i}").into_bytes().into(),
                data: vec![1].into(),
            };
            tr.warn
                .observe(Segment::UNTAGGED, ts(0), &o, &mut tr.budget, &mut out);
        }
        assert_eq!(tr.warn.state_sizes().1, 16384);
        assert_eq!(tr.budget.used(), tr.table.recount() + tr.warn.cost());
        assert_eq!(tr.table.len(), 100);
    }

    #[test]
    fn host_flood_is_capped() {
        let mut tr = Tracker::new(1 << 30, Pins::default());
        seed_devices(&mut tr, 100);
        let mut out = Vec::new();
        for i in 0..5000u32 {
            let b = i.to_be_bytes();
            let o = Observation::NameAnswer {
                mac: Mac([0x06, 0, b[0], b[1], b[2], b[3]]),
                kind: AnswerKind::Llmnr,
                name: b"wpad".to_vec().into(),
                data: vec![1].into(),
            };
            tr.warn
                .observe(Segment::UNTAGGED, ts(0), &o, &mut tr.budget, &mut out);
        }
        assert_eq!(tr.warn.state_sizes().2, 4096);
        assert_eq!(tr.budget.used(), tr.table.recount() + tr.warn.cost());
        assert_eq!(tr.table.len(), 100);
    }

    #[test]
    fn floods_stay_within_a_small_budget_and_keep_devices() {
        let mut tr = Tracker::new(4 << 20, Pins::default());
        seed_devices(&mut tr, 100);
        claim_flood(&mut tr, 70_000);
        let mut out = Vec::new();
        for i in 0..20_000u32 {
            let b = i.to_be_bytes();
            let o = Observation::NameAnswer {
                mac: Mac([0x02, 0, 0, 0, 0, (i % 100) as u8]),
                kind: AnswerKind::Llmnr,
                name: format!("name{i}").into_bytes().into(),
                data: b.to_vec().into(),
            };
            tr.apply(Segment::UNTAGGED, ts(0), &[o], &mut out);
        }
        assert!(tr.budget.used() <= 4 << 20, "{}", tr.budget.used());
        assert_eq!(tr.budget.used(), tr.table.recount() + tr.warn.cost());
        assert_eq!(tr.table.len(), 100);
        assert_eq!(tr.table.evictions(), 0);
    }

    #[test]
    fn evicting_a_device_forgets_its_warn_state() {
        let mut tr = Tracker::new(64 * 1024, Pins::default());
        let mut out = Vec::new();
        let m = Mac([0x02, 0, 0, 0, 0, 1]);
        let claim = Observation::Claim {
            mac: m,
            ip: Ipv4Addr::new(10, 0, 0, 1).into(),
        };
        tr.apply(Segment::UNTAGGED, ts(0), &[claim], &mut out);
        assert_eq!(tr.warn.state_sizes().0, 1);
        flooded(&mut tr, 5000, 5);
        assert!(tr.table.get(&m).is_none());
        assert_eq!(tr.warn.state_sizes().0, 0);
        assert_eq!(tr.budget.used(), tr.table.recount() + tr.warn.cost());
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
        // Only the eviction notices; nothing about the pinned server.
        assert!(
            out.iter()
                .all(|o| matches!(o, Output::Warning(w) if w.rule == Rule::MemoryEviction)),
            "{out:?}"
        );
    }

    #[test]
    fn distinct_subject_flood_is_bounded() {
        let pins = Pins {
            dhcp: vec![(Ipv4Addr::new(10, 0, 0, 1), None)],
            ..Pins::default()
        };
        let mut tr = Tracker::new(4 << 20, pins);
        let mut out = Vec::new();
        for i in 0..100u8 {
            let m = Mac([0x00, 0x16, 0xfe, 0, 0, i]);
            tr.apply(Segment::UNTAGGED, ts(0), &[heard(m)], &mut out);
        }
        // Forged replies, each naming a new server id.
        for i in 0..100_000u32 {
            let reply = Observation::DhcpReply {
                client: Mac([0x00, 0x16, 0xfe, 0, 0, 1]),
                server_mac: Mac([0x02, 0x16, 0xfe, 0, 0, 1]),
                server_id: Ipv4Addr::from(0x0b00_0000 + i),
                msg_type: 2,
                router: None,
            };
            tr.apply(
                Segment::UNTAGGED,
                ts(i64::from(i / 1000)),
                &[reply],
                &mut out,
            );
            if i % 997 == 0 {
                assert_eq!(
                    tr.budget.used(),
                    tr.table.recount() + tr.warn.cost(),
                    "after {i}"
                );
            }
        }
        assert_eq!(out.len(), 100_000);
        assert!(tr.warn.repeat_keys() <= 4096);
        assert_eq!(tr.budget.used(), tr.table.recount() + tr.warn.cost());
        assert_eq!(tr.table.len(), 100, "devices evicted");
        assert_eq!(tr.table.evictions(), 0);
    }
}
