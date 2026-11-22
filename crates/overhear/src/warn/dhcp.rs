//! The second DHCP server rule.

use std::fmt::Write as _;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};

use overhear_decode::Mac;

use super::segments::Segments;
use super::{Baseline, Expected, Output, Pins, Rule, Severity, Warning};
use crate::observe::{Observation, Segment, Ts};
use crate::track::{Bounded, Budget};

/// Senders of pinned servers' replies remembered (and kept from eviction).
const MAX_PINNED_MACS: usize = 16;

pub(super) struct Dhcp {
    pinned_macs: Bounded<Mac>,
}

impl Dhcp {
    pub(super) fn new() -> Self {
        Dhcp {
            pinned_macs: Bounded::new(MAX_PINNED_MACS),
        }
    }

    /// Checks an OFFER, ACK or NAK against the segment's expected servers.
    pub(super) fn reply(
        &mut self,
        pins: &Pins,
        segs: &mut Segments,
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
            match segs.get(seg).and_then(|l| l.dhcp) {
                Some(e) if e != sid => {
                    return Some(second(ts, seg, sid, server_mac, client, &[e]));
                }
                Some(_) => None,
                None => {
                    segs.update(seg, budget, |l| l.dhcp = Some(sid));
                    Some(Output::Baseline(Baseline {
                        ts,
                        segment: seg,
                        what: Expected::DhcpServer(sid),
                    }))
                }
            }
        };
        if let Some(r) = router {
            segs.update(seg, budget, |l| l.gateways.push(r));
        }
        baseline
    }

    fn protect(&mut self, mac: Mac, budget: &mut Budget) {
        let before = self.pinned_macs.len() * size_of::<Mac>();
        self.pinned_macs.push(mac);
        budget.adjust(before, self.pinned_macs.len() * size_of::<Mac>());
    }

    /// Sent a reply carrying a pinned server identifier.
    pub(super) fn is_pinned_mac(&self, mac: &Mac) -> bool {
        self.pinned_macs.iter().any(|m| m == mac)
    }

    pub(super) fn cost(&self) -> usize {
        self.pinned_macs.len() * size_of::<Mac>()
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
