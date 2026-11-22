//! Per-protocol presentation. Protocol tasks add match arms here.

pub mod arp;
pub mod cdp;
pub mod dhcp;
pub mod dns;
pub mod lldp;
pub mod nbns;
pub mod nd;
pub mod other;
pub mod ssdp;
pub mod stp;

use overhear_decode::{Packet, Proto};

use self::dns::Flavor;

use crate::json::JsonWriter;
use crate::observe::Observation;

/// Short tag shown in the second column; at most 5 characters.
pub fn tag(p: &Packet<'_>) -> &'static str {
    match &p.proto {
        Proto::Arp(_) => arp::tag(),
        Proto::Other { .. } => other::tag(p),
        Proto::Dhcp(_) => dhcp::tag(),
        Proto::Nd(_) => nd::tag(),
        Proto::Mdns(_) => Flavor::Mdns.tag(),
        Proto::Llmnr(_) => Flavor::Llmnr.tag(),
        Proto::Nbns(_) => nbns::tag(),
        Proto::Ssdp(_) => ssdp::tag(),
        Proto::Lldp(_) => lldp::tag(),
        Proto::Cdp(_) => cdp::tag(),
        Proto::Stp(_) => stp::tag(),
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
        Proto::Llmnr(m) => dns::llmnr_summary(m, out),
        Proto::Nbns(m) => nbns::summary(m, out),
        Proto::Ssdp(m) => ssdp::summary(m, out),
        Proto::Lldp(m) => lldp::summary(m, out),
        Proto::Cdp(m) => cdp::summary(m, out),
        Proto::Stp(s) => stp::summary(s, out),
    }
}

/// Appends the protocol's verbose lines, each `"  {LABEL:<6}{text}\n"`.
pub fn verbose(p: &Packet<'_>, frame: &[u8], out: &mut String) {
    match &p.proto {
        Proto::Arp(a) => arp::verbose(p, a, out),
        Proto::Other { payload } => other::verbose(payload.len(), frame, out),
        Proto::Dhcp(d) => dhcp::verbose(d, out),
        Proto::Nd(n) => nd::verbose(p, n, out),
        Proto::Mdns(m) => dns::verbose(Flavor::Mdns, m, out),
        Proto::Llmnr(m) => dns::verbose(Flavor::Llmnr, m, out),
        Proto::Nbns(m) => nbns::verbose(m, out),
        Proto::Ssdp(m) => ssdp::verbose(m, out),
        Proto::Lldp(m) => lldp::verbose(m, out),
        Proto::Cdp(m) => cdp::verbose(m, out),
        Proto::Stp(s) => stp::verbose(s, out),
    }
}

/// Key of the protocol object written by [`json`].
pub fn json_name(p: &Packet<'_>) -> &'static str {
    match &p.proto {
        Proto::Arp(_) => "arp",
        Proto::Other { .. } => "other",
        Proto::Dhcp(_) => "dhcp",
        Proto::Nd(_) => "nd",
        Proto::Mdns(_) => Flavor::Mdns.json_key(),
        Proto::Llmnr(_) => Flavor::Llmnr.json_key(),
        Proto::Nbns(_) => "nbns",
        Proto::Ssdp(_) => "ssdp",
        Proto::Lldp(_) => "lldp",
        Proto::Cdp(_) => "cdp",
        Proto::Stp(_) => "stp",
    }
}

/// Writes the protocol object under the key [`json_name`].
pub fn json(p: &Packet<'_>, w: &mut JsonWriter) {
    match &p.proto {
        Proto::Arp(a) => arp::json(a, w),
        Proto::Other { payload } => other::json(p, payload.len(), w),
        Proto::Dhcp(d) => dhcp::json(d, w),
        Proto::Nd(n) => nd::json(p, n, w),
        Proto::Mdns(m) => dns::json(Flavor::Mdns, m, w),
        Proto::Llmnr(m) => dns::json(Flavor::Llmnr, m, w),
        Proto::Nbns(m) => nbns::json(m, w),
        Proto::Ssdp(m) => ssdp::json(m, w),
        Proto::Lldp(m) => lldp::json(m, w),
        Proto::Cdp(m) => cdp::json(m, w),
        Proto::Stp(s) => stp::json(s, w),
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
        Proto::Llmnr(m) => dns::llmnr_observe(p, m, out),
        Proto::Nbns(m) => nbns::observe(p, m, out),
        Proto::Ssdp(m) => ssdp::observe(p, m, out),
        Proto::Lldp(m) => lldp::observe(p, m, out),
        Proto::Cdp(m) => cdp::observe(p, m, out),
        Proto::Stp(s) => stp::observe(p, s, out),
    }
}
