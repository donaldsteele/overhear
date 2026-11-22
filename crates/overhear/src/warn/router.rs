//! The unexpected router rule.

use std::net::{IpAddr, Ipv6Addr};

use overhear_decode::Mac;

use super::segments::Segments;
use super::{Baseline, Expected, Output, Pins, RouterId, Rule, Severity, Warning};
use crate::observe::{Observation, Segment, Ts};
use crate::track::Budget;

/// Checks a router advert against the segment's expected routers. Only a
/// default router (lifetime > 0) is learned or warned about at high
/// severity; any other sender warns only when it hands out DNS servers or a
/// global prefix.
pub(super) fn advert(
    pins: &Pins,
    segs: &mut Segments,
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
    let learned = if pinned {
        None
    } else {
        segs.get(seg).and_then(|l| l.router)
    };
    // A learned router must match on both MAC and address, so a rogue copying
    // just one of them still warns.
    let expected = if pinned {
        pins.routers_for(seg)
            .any(|id| id == RouterId::Mac(mac) || id == RouterId::Ip(src))
    } else {
        learned == Some((mac, src))
    };
    if expected {
        return None;
    }
    if lifetime > 0 {
        if !pinned && learned.is_none() {
            segs.update(seg, budget, |l| l.router = Some((mac, src)));
            return Some(Output::Baseline(Baseline {
                ts,
                segment: seg,
                what: Expected::Router { mac, ip: src },
            }));
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
