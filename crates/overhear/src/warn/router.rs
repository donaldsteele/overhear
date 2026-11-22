//! The unexpected router rule.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::mem::size_of;
use std::net::{IpAddr, Ipv6Addr};

use overhear_decode::Mac;

use super::{Baseline, Expected, OVERHEAD, Output, Pins, RouterId, Rule, Severity, Warning};
use crate::observe::{Observation, Segment, Ts};
use crate::track::Budget;

const LEARNED_COST: usize = size_of::<(Segment, (Mac, Ipv6Addr))>() + OVERHEAD;

pub(super) struct Routers {
    /// The first default router heard, per segment without a pin.
    learned: HashMap<Segment, (Mac, Ipv6Addr)>,
}

impl Routers {
    pub(super) fn new() -> Self {
        Routers {
            learned: HashMap::new(),
        }
    }

    /// Checks a router advert against the segment's expected routers. Only
    /// a default router (lifetime > 0) is learned or warned about at high
    /// severity; any other sender warns only when it hands out DNS servers or
    /// a global prefix.
    pub(super) fn advert(
        &mut self,
        pins: &Pins,
        seg: Segment,
        ts: Ts,
        obs: &Observation,
        budget: &mut Budget,
    ) -> Option<Output> {
        let &Observation::RouterAdvert {
            mac,
            src,
            lifetime,
            dns,
            global_prefix,
        } = obs
        else {
            return None;
        };
        let pinned = pins.routers_for(seg).next().is_some();
        // A learned router must match on both MAC and address, so a rogue
        // copying just one of them still warns.
        let expected = if pinned {
            pins.routers_for(seg)
                .any(|id| id == RouterId::Mac(mac) || id == RouterId::Ip(src))
        } else {
            self.learned.get(&seg) == Some(&(mac, src))
        };
        if expected {
            return None;
        }
        if lifetime > 0 {
            if !pinned {
                if let Entry::Vacant(e) = self.learned.entry(seg) {
                    e.insert((mac, src));
                    budget.adjust(0, LEARNED_COST);
                    return Some(Output::Baseline(Baseline {
                        ts,
                        segment: seg,
                        what: Expected::Router { mac, ip: src },
                    }));
                }
            }
            let message = format!("unexpected router {src} ({mac}) advertising a default route");
            return Some(warning(ts, seg, mac, src, Severity::High, message));
        }
        let what = match (dns, global_prefix) {
            (true, true) => "DNS servers and a global prefix",
            (true, false) => "DNS servers",
            (false, true) => "a global prefix",
            (false, false) => return None,
        };
        let message = format!("router advert from {src} ({mac}) carries {what}");
        Some(warning(ts, seg, mac, src, Severity::Low, message))
    }

    pub(super) fn cost(&self) -> usize {
        self.learned.len() * LEARNED_COST
    }
}

fn warning(
    ts: Ts,
    seg: Segment,
    mac: Mac,
    src: Ipv6Addr,
    severity: Severity,
    message: String,
) -> Output {
    Output::Warning(Warning {
        ts,
        rule: Rule::UnexpectedRouter,
        severity,
        segment: Some(seg),
        subject: src.to_string(),
        message,
        macs: vec![mac],
        addrs: vec![IpAddr::V6(src)],
        count: 1,
    })
}
