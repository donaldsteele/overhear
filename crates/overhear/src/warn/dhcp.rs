//! The second DHCP server rule.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::Write as _;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};

use overhear_decode::Mac;

use super::{Baseline, Expected, OVERHEAD, Output, Pins, Rule, Severity, Warning};
use crate::observe::{Observation, Segment, Ts};
use crate::track::{Bounded, Budget};

/// Gateways remembered per segment.
const MAX_GATEWAYS: usize = 16;
/// Senders of pinned servers' replies remembered (and kept from eviction).
const MAX_PINNED_MACS: usize = 16;

const LEARNED_COST: usize = size_of::<(Segment, Ipv4Addr)>() + OVERHEAD;

fn gateways_cost(g: &Bounded<Ipv4Addr>) -> usize {
    size_of::<(Segment, Bounded<Ipv4Addr>)>() + OVERHEAD + g.len() * size_of::<Ipv4Addr>()
}

pub(super) struct Dhcp {
    /// The first server heard, per segment without a pin.
    learned: HashMap<Segment, Ipv4Addr>,
    /// Router options of replies from expected servers.
    gateways: HashMap<Segment, Bounded<Ipv4Addr>>,
    pinned_macs: Bounded<Mac>,
}

impl Dhcp {
    pub(super) fn new() -> Self {
        Dhcp {
            learned: HashMap::new(),
            gateways: HashMap::new(),
            pinned_macs: Bounded::new(MAX_PINNED_MACS),
        }
    }

    /// Checks an OFFER, ACK or NAK against the segment's expected servers.
    pub(super) fn reply(
        &mut self,
        pins: &Pins,
        seg: Segment,
        ts: Ts,
        obs: &Observation,
        budget: &mut Budget,
    ) -> Option<Output> {
        let &Observation::DhcpReply {
            client,
            server_mac,
            server_id: sid,
            msg_type,
            router,
        } = obs
        else {
            return None;
        };
        if !matches!(msg_type, 2 | 5 | 6) {
            return None;
        }
        let baseline = if pins.dhcp_for(seg).next().is_some() {
            if !pins.dhcp_for(seg).any(|p| p == sid) {
                let mut expected = Vec::new();
                for p in pins.dhcp_for(seg) {
                    if !expected.contains(&p) {
                        expected.push(p);
                    }
                }
                return Some(second(ts, seg, sid, server_mac, client, &expected));
            }
            self.protect(server_mac, budget);
            None
        } else {
            match self.learned.entry(seg) {
                Entry::Occupied(e) if *e.get() != sid => {
                    return Some(second(ts, seg, sid, server_mac, client, &[*e.get()]));
                }
                Entry::Occupied(_) => None,
                Entry::Vacant(e) => {
                    e.insert(sid);
                    budget.adjust(0, LEARNED_COST);
                    Some(Output::Baseline(Baseline {
                        ts,
                        segment: seg,
                        what: Expected::DhcpServer(sid),
                    }))
                }
            }
        };
        if let Some(r) = router {
            self.add_gateway(seg, r, budget);
        }
        baseline
    }

    fn protect(&mut self, mac: Mac, budget: &mut Budget) {
        let before = self.pinned_macs.len() * size_of::<Mac>();
        self.pinned_macs.push(mac);
        budget.adjust(before, self.pinned_macs.len() * size_of::<Mac>());
    }

    fn add_gateway(&mut self, seg: Segment, ip: Ipv4Addr, budget: &mut Budget) {
        let (before, g) = match self.gateways.entry(seg) {
            Entry::Occupied(e) => {
                let g = e.into_mut();
                (gateways_cost(g), g)
            }
            Entry::Vacant(e) => (0, e.insert(Bounded::new(MAX_GATEWAYS))),
        };
        g.push(ip);
        budget.adjust(before, gateways_cost(g));
    }

    pub(super) fn is_gateway(&self, seg: Segment, ip: Ipv4Addr) -> bool {
        self.gateways
            .get(&seg)
            .is_some_and(|g| g.iter().any(|x| *x == ip))
    }

    /// Sent a reply carrying a pinned server identifier.
    pub(super) fn is_pinned_mac(&self, mac: &Mac) -> bool {
        self.pinned_macs.iter().any(|m| m == mac)
    }

    pub(super) fn cost(&self) -> usize {
        self.learned.len() * LEARNED_COST
            + self.gateways.values().map(gateways_cost).sum::<usize>()
            + self.pinned_macs.len() * size_of::<Mac>()
    }
}

fn second(
    ts: Ts,
    seg: Segment,
    sid: Ipv4Addr,
    server_mac: Mac,
    client: Mac,
    expected: &[Ipv4Addr],
) -> Output {
    let mut message = format!("second DHCP server {sid} (expected ");
    for (i, e) in expected.iter().enumerate() {
        if i > 0 {
            message.push_str(", ");
        }
        let _ = write!(message, "{e}");
    }
    message.push(')');
    Output::Warning(Warning {
        ts,
        rule: Rule::SecondDhcpServer,
        severity: Severity::High,
        segment: Some(seg),
        subject: sid.to_string(),
        message,
        macs: vec![server_mac, client],
        addrs: vec![IpAddr::V4(sid)],
        count: 1,
    })
}
