//! The address conflict rule: an IP address claimed by a second MAC.

use std::mem::size_of;
use std::net::IpAddr;

use overhear_decode::Mac;

use super::index::{ClaimKey, Index};
use super::lru::Lru;
use super::segments::Segments;
use super::{OVERHEAD, Output, Pins, RouterId, Rule, Severity, Warning};
use crate::observe::{Observation, Segment, Ts};
use crate::track::Budget;

/// Who claimed an address, and when (seconds).
pub(super) type Claims = Lru<ClaimKey, (Mac, i64)>;

fn entry_cost(_: &ClaimKey, _: &(Mac, i64)) -> usize {
    size_of::<(ClaimKey, ((Mac, i64), u64))>() + size_of::<(u64, ClaimKey)>() + 2 * OVERHEAD
}

pub(super) fn new(cap: usize) -> Claims {
    Lru::new(cap, entry_cost)
}

/// Records the claim, warning when another MAC held the address.
pub(super) fn claim(
    claims: &mut Claims,
    index: &mut Index,
    seg: Segment,
    ts: Ts,
    obs: &Observation,
    budget: &mut Budget,
    is_expected: impl FnOnce(IpAddr) -> bool,
) -> Option<Output> {
    let &Observation::Claim { mac, ip } = obs else {
        return None;
    };
    let key = (seg, ip);
    let before = claims.get(&key).copied();
    let put = claims.put(key, (mac, ts.sec), budget, budget.limit() / super::SHARE);
    for ((s, i), (m, _)) in put.evicted {
        index.remove_claim(m, &(s, i), budget);
    }
    if let Some((old, _)) = put.replaced.filter(|(old, _)| *old != mac) {
        index.remove_claim(old, &key, budget);
    }
    index.add_claim(mac, key, budget);
    let (old, then) = before.filter(|(old, _)| *old != mac)?;
    let severity = if is_expected(ip) {
        Severity::High
    } else {
        Severity::Low
    };
    let age = age(ts.sec.saturating_sub(then).max(0));
    Some(Output::Warning(Warning {
        ts,
        rule: Rule::AddressConflict,
        severity,
        segment: Some(seg),
        subject: ip.to_string(),
        message: format!("{ip} now claimed by {mac}, was {old} {age} ago"),
        macs: vec![mac, old],
        addrs: vec![ip],
        count: 1,
    }))
}

/// Whether `ip` is an expected DHCP server, a recorded gateway or an
/// expected router's address on `seg`.
pub(super) fn expected(pins: &Pins, segs: &Segments, seg: Segment, ip: IpAddr) -> bool {
    let learned = segs.peek(seg);
    match ip {
        IpAddr::V4(a) => {
            pins.dhcp_for(seg).any(|p| p == a)
                || learned.is_some_and(|l| l.dhcp == Some(a) || l.gateways.iter().any(|g| *g == a))
        }
        IpAddr::V6(a) => {
            pins.routers_for(seg).any(|id| id == RouterId::Ip(a))
                || learned.is_some_and(|l| l.router.is_some_and(|(_, r)| r == a))
        }
    }
}

fn age(secs: i64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}
