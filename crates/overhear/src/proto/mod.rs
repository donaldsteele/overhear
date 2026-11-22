//! Per-protocol presentation. Protocol tasks add match arms here.

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod nd;
pub mod other;

use overhear_decode::{Packet, Proto};

use crate::json::JsonWriter;
use crate::observe::Observation;

/// Short tag shown in the second column; at most 5 characters.
pub fn tag(p: &Packet<'_>) -> &'static str {
    match &p.proto {
        Proto::Arp(_) => arp::tag(),
        Proto::Other { .. } => other::tag(p),
        Proto::Dhcp(_) => dhcp::tag(),
        Proto::Nd(_) => nd::tag(),
        Proto::Mdns(_) => dns::tag(),
    }
}

/// Appends the escaped summary text (no time, tag or source).
pub fn summary(p: &Packet<'_>, out: &mut String) {
    match &p.proto {
        Proto::Arp(a) => arp::summary(a, out),
        Proto::Other { payload } => other::summary(p, payload.len(), out),
        Proto::Dhcp(d) => dhcp::summary(d, out),
        Proto::Nd(n) => nd::summary(p, n, out),
        Proto::Mdns(m) => dns::summary(m, out),
    }
}

/// Appends the protocol's verbose lines, each `"  {LABEL:<6}{text}\n"`.
pub fn verbose(p: &Packet<'_>, frame: &[u8], out: &mut String) {
    match &p.proto {
        Proto::Arp(a) => arp::verbose(p, a, out),
        Proto::Other { payload } => other::verbose(payload.len(), frame, out),
        Proto::Dhcp(d) => dhcp::verbose(d, out),
        Proto::Nd(n) => nd::verbose(p, n, out),
        Proto::Mdns(m) => dns::verbose(m, out),
    }
}

/// Key of the protocol object written by [`json`].
pub fn json_name(p: &Packet<'_>) -> &'static str {
    match &p.proto {
        Proto::Arp(_) => "arp",
        Proto::Other { .. } => "other",
        Proto::Dhcp(_) => "dhcp",
        Proto::Nd(_) => "nd",
        Proto::Mdns(_) => "mdns",
    }
}

/// Writes the protocol object under the key [`json_name`].
pub fn json(p: &Packet<'_>, w: &mut JsonWriter) {
    match &p.proto {
        Proto::Arp(a) => arp::json(a, w),
        Proto::Other { payload } => other::json(p, payload.len(), w),
        Proto::Dhcp(d) => dhcp::json(d, w),
        Proto::Nd(n) => nd::json(p, n, w),
        Proto::Mdns(m) => dns::json(m, w),
    }
}

/// Appends the facts the packet reveals. `Heard` always comes first.
pub fn observe<'a>(p: &Packet<'a>, out: &mut Vec<Observation<'a>>) {
    match &p.proto {
        Proto::Arp(a) => arp::observe(p, a, out),
        Proto::Other { .. } => other::observe(p, out),
        Proto::Dhcp(d) => dhcp::observe(p, d, out),
        Proto::Nd(n) => nd::observe(p, n, out),
        Proto::Mdns(m) => dns::observe(p, m, out),
    }
}
