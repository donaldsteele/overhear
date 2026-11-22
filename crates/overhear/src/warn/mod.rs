//! Warning rules. Consumes observations per segment, learns (or is told) the
//! expected DHCP server and default router, and produces warnings and
//! baselines for the renderers.

mod dhcp;
pub mod pins;
mod repeat;
mod router;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use overhear_decode::Mac;

pub use pins::{Pins, RouterId, parse_dhcp_pin, parse_router_pin};

use crate::observe::{Observation, Segment, Ts};
use crate::track::Budget;
use dhcp::Dhcp;
use repeat::Repeats;
use router::Routers;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    SecondDhcpServer,
    UnexpectedRouter,
    AddressConflict,
    SuspiciousNameAnswers,
    CaptureDrops,
    MemoryEviction,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::SecondDhcpServer => "second-dhcp-server",
            Rule::UnexpectedRouter => "unexpected-router",
            Rule::AddressConflict => "address-conflict",
            Rule::SuspiciousNameAnswers => "suspicious-name-answers",
            Rule::CaptureDrops => "capture-drops",
            Rule::MemoryEviction => "memory-eviction",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Severity {
    Low,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::High => "high",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub ts: Ts,
    pub rule: Rule,
    pub severity: Severity,
    /// `None` for warnings about overhear itself.
    pub segment: Option<Segment>,
    pub subject: String,
    pub message: String,
    pub macs: Vec<Mac>,
    pub addrs: Vec<IpAddr>,
    /// Occurrences this warning stands for: 1, or the repeats summarised.
    pub count: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Expected {
    DhcpServer(Ipv4Addr),
    Router { mac: Mac, ip: Ipv6Addr },
}

/// What a segment learned to expect.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Baseline {
    pub ts: Ts,
    pub segment: Segment,
    pub what: Expected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    Warning(Warning),
    Baseline(Baseline),
}

/// Bytes charged per map entry beyond its key and value.
const OVERHEAD: usize = 32;

/// Runs the rules. Everything it learns is charged to the shared [`Budget`].
pub struct WarnEngine {
    pins: Pins,
    dhcp: Dhcp,
    routers: Routers,
    repeats: Repeats,
}

impl WarnEngine {
    pub fn new(pins: Pins) -> Self {
        WarnEngine {
            pins,
            dhcp: Dhcp::new(),
            routers: Routers::new(),
            repeats: Repeats::new(),
        }
    }

    /// Applies the rules to one observation of a frame seen on `seg` at
    /// `ts`, appending what they produce to `out`.
    pub fn observe(
        &mut self,
        seg: Segment,
        ts: Ts,
        obs: &Observation,
        budget: &mut Budget,
        out: &mut Vec<Output>,
    ) {
        let found = match obs {
            Observation::DhcpReply { .. } => self.dhcp.reply(&self.pins, seg, ts, obs, budget),
            Observation::RouterAdvert { .. } => {
                self.routers.advert(&self.pins, seg, ts, obs, budget)
            }
            _ => None,
        };
        match found {
            Some(Output::Warning(w)) => self.repeats.report(w, budget, out),
            Some(b) => out.push(b),
            None => {}
        }
    }

    /// Called about once a second: outputs the repeat summaries due at `now`.
    pub fn tick(&mut self, now: Ts, budget: &mut Budget, out: &mut Vec<Output>) {
        self.repeats.tick(now, budget, out);
    }

    /// Drops what is kept about `mac` once the device table evicted it.
    /// Learned expected servers and routers stay: forgetting them in a MAC
    /// flood would make whoever speaks next the trusted one.
    pub fn forget(&mut self, _mac: &Mac, _budget: &mut Budget) {}

    /// Never evicted from the device table: routers pinned by MAC, and the
    /// senders of replies from pinned DHCP servers.
    pub fn is_protected(&self, mac: &Mac) -> bool {
        self.pins
            .routers
            .iter()
            .any(|(id, _)| *id == RouterId::Mac(*mac))
            || self.dhcp.is_pinned_mac(mac)
    }

    /// Whether an expected DHCP server named `ip` as a router on `seg`.
    pub fn is_gateway(&self, seg: Segment, ip: Ipv4Addr) -> bool {
        self.dhcp.is_gateway(seg, ip)
    }

    /// Bytes of state, counted from scratch; what this engine has charged to
    /// the budget.
    pub fn cost(&self) -> usize {
        self.dhcp.cost() + self.routers.cost() + self.repeats.cost()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::line::LineRenderer;
    use crate::render::{Renderer, TextOpts};
    use crate::time::TimeStyle;
    use jiff::tz::TimeZone;

    const U: Segment = Segment::UNTAGGED;

    fn t(sec: i64) -> Ts {
        Ts { sec, usec: 0 }
    }

    fn seg(s: &str) -> Segment {
        Segment::parse(s).expect("segment")
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().expect("ipv4")
    }

    fn ip6(s: &str) -> Ipv6Addr {
        s.parse().expect("ipv6")
    }

    fn mac(n: u8) -> Mac {
        Mac([0x02, 0x00, 0x5e, 0x10, 0x00, n])
    }

    const CLIENT: Mac = Mac([0x02, 0x00, 0x5e, 0x10, 0x00, 0x39]);

    /// A reply from `sid`, sent from a MAC ending in its last octet.
    fn reply(sid: Ipv4Addr, msg_type: u8) -> Observation<'static> {
        Observation::DhcpReply {
            client: CLIENT,
            server_mac: mac(sid.octets()[3]),
            server_id: sid,
            msg_type,
            router: None,
        }
    }

    /// A router advert from `fe80::{n}` and the MAC ending in `n`.
    fn advert(n: u8, lifetime: u16, dns: bool, global_prefix: bool) -> Observation<'static> {
        Observation::RouterAdvert {
            mac: mac(n),
            src: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(n)),
            lifetime,
            dns,
            global_prefix,
        }
    }

    struct Rig {
        w: WarnEngine,
        b: Budget,
    }

    impl Rig {
        fn new(pins: Pins) -> Rig {
            Rig {
                w: WarnEngine::new(pins),
                b: Budget::new(usize::MAX),
            }
        }

        fn see(&mut self, seg: Segment, sec: i64, obs: &Observation) -> Vec<Output> {
            let mut out = Vec::new();
            self.w.observe(seg, t(sec), obs, &mut self.b, &mut out);
            assert_eq!(self.b.used(), self.w.cost(), "budget out of step");
            out
        }

        fn tick(&mut self, sec: i64) -> Vec<Output> {
            let mut out = Vec::new();
            self.w.tick(t(sec), &mut self.b, &mut out);
            assert_eq!(self.b.used(), self.w.cost(), "budget out of step");
            out
        }
    }

    fn warnings(out: &[Output]) -> Vec<&Warning> {
        out.iter()
            .filter_map(|o| match o {
                Output::Warning(w) => Some(w),
                Output::Baseline(_) => None,
            })
            .collect()
    }

    fn only_warning(out: &[Output]) -> &Warning {
        match out {
            [Output::Warning(w)] => w,
            _ => panic!("want one warning, got {out:?}"),
        }
    }

    fn dhcp_pin(s: &str) -> Pins {
        Pins {
            dhcp: vec![parse_dhcp_pin(s).expect("pin")],
            ..Pins::default()
        }
    }

    #[test]
    fn first_dhcp_server_is_learned_and_announced() {
        let mut r = Rig::new(Pins::default());
        // DISCOVER and REQUEST are not replies.
        assert_eq!(r.see(U, 0, &reply(ip("10.0.0.9"), 1)), []);
        assert_eq!(r.see(U, 0, &reply(ip("10.0.0.9"), 3)), []);
        assert_eq!(
            r.see(U, 5, &reply(ip("10.0.0.1"), 2)),
            [Output::Baseline(Baseline {
                ts: t(5),
                segment: U,
                what: Expected::DhcpServer(ip("10.0.0.1")),
            })]
        );
        assert_eq!(r.see(U, 6, &reply(ip("10.0.0.1"), 5)), []);
    }

    #[test]
    fn second_dhcp_server_warns_high() {
        let mut r = Rig::new(Pins::default());
        r.see(U, 0, &reply(ip("10.0.0.1"), 2));
        let out = r.see(U, 7, &reply(ip("10.0.0.254"), 2));
        assert_eq!(
            only_warning(&out),
            &Warning {
                ts: t(7),
                rule: Rule::SecondDhcpServer,
                severity: Severity::High,
                segment: Some(U),
                subject: "10.0.0.254".into(),
                message: "second DHCP server 10.0.0.254 (expected 10.0.0.1)".into(),
                macs: vec![mac(254), CLIENT],
                addrs: vec![IpAddr::V4(ip("10.0.0.254"))],
                count: 1,
            }
        );
        // ACK and NAK count too.
        assert_eq!(warnings(&r.see(U, 8, &reply(ip("10.0.0.7"), 5))).len(), 1);
        assert_eq!(warnings(&r.see(U, 8, &reply(ip("10.0.0.8"), 6))).len(), 1);
    }

    #[test]
    fn pinned_server_suppresses_learning() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1"));
        assert_eq!(r.see(U, 0, &reply(ip("10.0.0.1"), 2)), []);
        let out = r.see(U, 1, &reply(ip("10.0.0.9"), 2));
        assert_eq!(
            only_warning(&out).message,
            "second DHCP server 10.0.0.9 (expected 10.0.0.1)"
        );
    }

    #[test]
    fn pinned_failover_pair_lists_both() {
        let mut pins = dhcp_pin("10.0.0.1");
        pins.dhcp.push(parse_dhcp_pin("10.0.0.2").expect("pin"));
        // The same address pinned for one VLAN is listed once.
        pins.dhcp.push(parse_dhcp_pin("10.0.0.1@100").expect("pin"));
        let mut r = Rig::new(pins);
        assert_eq!(r.see(seg("100"), 0, &reply(ip("10.0.0.2"), 5)), []);
        let out = r.see(seg("100"), 1, &reply(ip("10.0.0.9"), 2));
        assert_eq!(
            only_warning(&out).message,
            "second DHCP server 10.0.0.9 (expected 10.0.0.1, 10.0.0.2)"
        );
    }

    #[test]
    fn pins_scoped_to_vlan() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1@100"));
        let out = r.see(seg("100"), 0, &reply(ip("10.0.0.2"), 2));
        let w = only_warning(&out);
        assert_eq!(w.segment, Some(seg("100")));
        assert_eq!(
            r.see(U, 1, &reply(ip("10.0.0.2"), 2)),
            [Output::Baseline(Baseline {
                ts: t(1),
                segment: U,
                what: Expected::DhcpServer(ip("10.0.0.2")),
            })]
        );
    }

    #[test]
    fn per_segment_learning() {
        let mut r = Rig::new(Pins::default());
        let a = r.see(seg("100"), 0, &reply(ip("10.0.0.1"), 2));
        let b = r.see(seg("200"), 0, &reply(ip("10.0.0.254"), 2));
        let c = r.see(seg("200.100"), 0, &reply(ip("10.0.0.9"), 2));
        for (out, s, sid) in [
            (a, "100", "10.0.0.1"),
            (b, "200", "10.0.0.254"),
            (c, "200.100", "10.0.0.9"),
        ] {
            assert_eq!(
                out,
                [Output::Baseline(Baseline {
                    ts: t(0),
                    segment: seg(s),
                    what: Expected::DhcpServer(ip(sid)),
                })]
            );
        }
        assert_eq!(r.see(seg("100"), 1, &reply(ip("10.0.0.1"), 5)), []);
        assert_eq!(r.see(seg("200"), 1, &reply(ip("10.0.0.254"), 5)), []);
    }

    #[test]
    fn gateway_recorded_from_expected_server_only() {
        let mut r = Rig::new(Pins::default());
        let with_router = |sid: &str, gw: &str| Observation::DhcpReply {
            client: CLIENT,
            server_mac: mac(1),
            server_id: ip(sid),
            msg_type: 5,
            router: Some(ip(gw)),
        };
        r.see(U, 0, &with_router("10.0.0.1", "10.0.0.254"));
        r.see(U, 1, &with_router("10.0.0.66", "10.0.0.66"));
        assert!(r.w.is_gateway(U, ip("10.0.0.254")));
        assert!(!r.w.is_gateway(U, ip("10.0.0.66")));
        assert!(!r.w.is_gateway(seg("100"), ip("10.0.0.254")));
    }

    #[test]
    fn lifetime_zero_ula_router_is_quiet() {
        let mut r = Rig::new(Pins::default());
        assert_eq!(r.see(U, 0, &advert(3, 0, false, false)), []);
        // Not learned: the first default router still is.
        let out = r.see(U, 1, &advert(1, 1800, false, false));
        assert!(matches!(out.as_slice(), [Output::Baseline(_)]), "{out:?}");
        assert_eq!(r.see(U, 2, &advert(3, 0, false, false)), []);
    }

    #[test]
    fn lifetime_zero_with_dns_warns_low() {
        let mut r = Rig::new(Pins::default());
        let out = r.see(U, 0, &advert(2, 0, true, false));
        let w = only_warning(&out);
        assert_eq!(
            (w.rule, w.severity, w.subject.as_str(), w.message.as_str()),
            (
                Rule::UnexpectedRouter,
                Severity::Low,
                "fe80::2",
                "router advert from fe80::2 (02:00:5e:10:00:02) carries DNS servers"
            )
        );
        assert_eq!(
            (w.macs.as_slice(), w.addrs.as_slice()),
            (&[mac(2)][..], &[IpAddr::V6(ip6("fe80::2"))][..])
        );
        let out = r.see(U, 0, &advert(3, 0, false, true));
        assert_eq!(
            only_warning(&out).message,
            "router advert from fe80::3 (02:00:5e:10:00:03) carries a global prefix"
        );
        let out = r.see(U, 0, &advert(4, 0, true, true));
        assert_eq!(
            only_warning(&out).message,
            "router advert from fe80::4 (02:00:5e:10:00:04) carries DNS servers and a global prefix"
        );
    }

    #[test]
    fn second_default_router_warns_high() {
        let mut r = Rig::new(Pins::default());
        assert_eq!(
            r.see(U, 0, &advert(1, 1800, true, true)),
            [Output::Baseline(Baseline {
                ts: t(0),
                segment: U,
                what: Expected::Router {
                    mac: mac(1),
                    ip: ip6("fe80::1"),
                },
            })]
        );
        let out = r.see(U, 3, &advert(2, 1800, false, false));
        let w = only_warning(&out);
        assert_eq!(
            (w.rule, w.severity, w.segment, w.subject.as_str()),
            (Rule::UnexpectedRouter, Severity::High, Some(U), "fe80::2")
        );
        assert_eq!(
            w.message,
            "unexpected router fe80::2 (02:00:5e:10:00:02) advertising a default route"
        );
        // The learned router stays quiet, also when it stops being a default
        // router while still announcing DNS servers.
        assert_eq!(r.see(U, 4, &advert(1, 1800, true, true)), []);
        assert_eq!(r.see(U, 5, &advert(1, 0, true, true)), []);
        // Another segment learns its own.
        let out = r.see(seg("100"), 6, &advert(2, 1800, false, false));
        assert!(matches!(out.as_slice(), [Output::Baseline(_)]), "{out:?}");
    }

    #[test]
    fn learned_router_must_match_mac_and_address() {
        let mut r = Rig::new(Pins::default());
        r.see(U, 0, &advert(1, 1800, false, false));
        let from = |m: Mac, src: &str| Observation::RouterAdvert {
            mac: m,
            src: ip6(src),
            lifetime: 1800,
            dns: false,
            global_prefix: false,
        };
        assert_eq!(warnings(&r.see(U, 1, &from(mac(2), "fe80::1"))).len(), 1);
        assert_eq!(warnings(&r.see(U, 1, &from(mac(1), "fe80::2"))).len(), 1);
    }

    #[test]
    fn router_pinned_by_mac_is_exempt() {
        let pins = Pins {
            routers: vec![parse_router_pin("02:00:5e:10:00:05").expect("pin")],
            ..Pins::default()
        };
        let mut r = Rig::new(pins);
        assert_eq!(r.see(U, 0, &advert(5, 1800, true, true)), []);
        assert_eq!(r.see(U, 1, &advert(5, 0, true, true)), []);
        // Pinned segments learn nothing: any other default router warns.
        let out = r.see(U, 2, &advert(6, 1800, false, false));
        assert_eq!(only_warning(&out).severity, Severity::High);
        assert!(r.w.is_protected(&mac(5)));
        assert!(!r.w.is_protected(&mac(6)));
    }

    #[test]
    fn router_pinned_by_address_is_exempt() {
        let pins = Pins {
            routers: vec![parse_router_pin("fe80::5@100").expect("pin")],
            ..Pins::default()
        };
        let mut r = Rig::new(pins);
        assert_eq!(r.see(seg("100"), 0, &advert(5, 1800, true, true)), []);
        let out = r.see(seg("100"), 0, &advert(6, 0, true, false));
        assert_eq!(only_warning(&out).severity, Severity::Low);
        // Elsewhere the pin does not apply, and fe80::5 is learned.
        let out = r.see(U, 1, &advert(5, 1800, false, false));
        assert!(matches!(out.as_slice(), [Output::Baseline(_)]), "{out:?}");
        // Pinned by address only: its MAC is not protected.
        assert!(!r.w.is_protected(&mac(5)));
    }

    #[test]
    fn pinned_server_mac_is_protected() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1"));
        assert!(!r.w.is_protected(&mac(1)));
        r.see(U, 0, &reply(ip("10.0.0.1"), 2));
        r.see(U, 0, &reply(ip("10.0.0.9"), 2));
        assert!(r.w.is_protected(&mac(1)));
        assert!(!r.w.is_protected(&mac(9)));
        assert!(!r.w.is_protected(&CLIENT));
    }

    #[test]
    fn repeats_summarised_once_a_minute() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1"));
        let mut all = Vec::new();
        for sec in 0..5 {
            all.extend(r.see(U, sec, &reply(ip("10.0.0.254"), 2)));
        }
        assert_eq!(only_warning(&all).count, 1);
        assert_eq!(only_warning(&all).ts, t(0));
        assert_eq!(r.tick(59), []);
        let out = r.tick(61);
        let w = only_warning(&out);
        assert_eq!((w.ts, w.count), (t(61), 4));
        assert_eq!(
            w.message,
            "second DHCP server 10.0.0.254 (expected 10.0.0.1)"
        );
        assert_eq!(r.tick(200), []);
    }

    #[test]
    fn repeat_keys_are_rule_segment_and_subject() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1"));
        assert_eq!(warnings(&r.see(U, 0, &reply(ip("10.0.0.7"), 2))).len(), 1);
        assert_eq!(warnings(&r.see(U, 0, &reply(ip("10.0.0.8"), 2))).len(), 1);
        let other = seg("100");
        assert_eq!(
            warnings(&r.see(other, 0, &reply(ip("10.0.0.7"), 2))).len(),
            1
        );
        assert_eq!(warnings(&r.see(U, 1, &reply(ip("10.0.0.7"), 2))).len(), 0);
    }

    #[test]
    fn quiet_key_reports_at_once_after_a_minute() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1"));
        r.see(U, 0, &reply(ip("10.0.0.7"), 2));
        assert_eq!(r.tick(100), []);
        let out = r.see(U, 100, &reply(ip("10.0.0.7"), 2));
        assert_eq!(
            (only_warning(&out).ts, only_warning(&out).count),
            (t(100), 1)
        );
    }

    #[test]
    fn idle_keys_dropped_and_budget_released() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1"));
        let empty = r.w.cost();
        r.see(U, 0, &reply(ip("10.0.0.7"), 2));
        r.see(U, 10, &reply(ip("10.0.0.7"), 2));
        assert!(r.w.cost() > empty);
        assert_eq!(only_warning(&r.tick(70)).count, 1);
        assert_eq!(r.tick(609), []);
        assert!(r.w.cost() > empty, "dropped before 600 s idle");
        assert_eq!(r.tick(610), []);
        assert_eq!(r.w.cost(), empty);
        assert_eq!(r.b.used(), empty);
    }

    #[test]
    fn time_going_backwards_is_harmless() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1"));
        assert_eq!(
            warnings(&r.see(U, 1000, &reply(ip("10.0.0.9"), 2))).len(),
            1
        );
        assert_eq!(r.see(U, 900, &reply(ip("10.0.0.9"), 2)), []);
        assert_eq!(r.tick(800), []);
        let out = r.tick(1061);
        assert_eq!(
            (only_warning(&out).ts, only_warning(&out).count),
            (t(1061), 1)
        );
    }

    #[test]
    fn budget_tracks_all_state() {
        let mut r = Rig::new(dhcp_pin("10.0.0.1@100"));
        let mut x: u64 = 7;
        let mut next = move || {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (x >> 33) as u32
        };
        let segs = [U, seg("100"), seg("200"), seg("200.100")];
        for i in 0..5_000i64 {
            let s = segs[(next() % 4) as usize];
            let n = (next() % 12) as u8;
            let sec = i / 10;
            match next() % 4 {
                0 => {
                    let o = Observation::DhcpReply {
                        client: mac(n.wrapping_add(100)),
                        server_mac: mac(n),
                        server_id: Ipv4Addr::new(10, 0, 0, n % 4),
                        msg_type: 2,
                        router: Some(Ipv4Addr::new(10, 0, 0, n)),
                    };
                    r.see(s, sec, &o);
                }
                1 => {
                    r.see(
                        s,
                        sec,
                        &advert(n, (next() % 2) as u16, n % 3 == 0, n % 5 == 0),
                    );
                }
                2 => {
                    r.tick(sec);
                }
                _ => {
                    r.see(s, sec, &reply(Ipv4Addr::new(10, 0, 0, 1), 2));
                }
            }
        }
        assert!(r.b.used() > 0);
    }

    #[test]
    fn pin_parsing() {
        assert_eq!(parse_dhcp_pin("10.0.0.1"), Ok((ip("10.0.0.1"), None)));
        assert_eq!(
            parse_dhcp_pin("10.0.0.1@100"),
            Ok((ip("10.0.0.1"), Some(seg("100"))))
        );
        assert_eq!(
            parse_router_pin("fe80::1@200.100"),
            Ok((RouterId::Ip(ip6("fe80::1")), Some(seg("200.100"))))
        );
        assert_eq!(
            parse_router_pin("02:00:5e:10:00:01"),
            Ok((RouterId::Mac(mac(1)), None))
        );
        assert_eq!(
            parse_router_pin("02-00-5E-10-00-0A@7"),
            Ok((RouterId::Mac(mac(10)), Some(seg("7"))))
        );
        for bad in [
            "10.0.0.1@5000",
            "bogus",
            "",
            "10.0.0.1@",
            "fe80::1",
            "10.0.0.1@100@200",
        ] {
            assert!(parse_dhcp_pin(bad).is_err(), "{bad}");
        }
        for bad in [
            "bogus",
            "10.0.0.1",
            "02:00:5e:10:00",
            "02:00:5e:10:00:01:02",
            "02:00:5e:10:00:+1",
            "02:00:5e:10:00:001",
            "fe80::1@5000",
            "",
        ] {
            assert!(parse_router_pin(bad).is_err(), "{bad}");
        }
        let e = parse_dhcp_pin("10.0.0.1@5000").expect_err("vlan 5000");
        assert!(e.contains("5000"), "{e}");
    }

    #[test]
    fn renders_warning_and_note_lines() {
        let opts = TextOpts {
            tz: TimeZone::UTC,
            style: TimeStyle::DateTime,
            hex: false,
        };
        let warning = Warning {
            ts: Ts {
                sec: 1_795_266_132,
                usec: 10_000,
            },
            rule: Rule::SecondDhcpServer,
            severity: Severity::High,
            segment: Some(seg("100")),
            subject: "10.0.0.254".into(),
            message: "second DHCP server 10.0.0.254 (expected 10.0.0.1)".into(),
            macs: vec![mac(254), CLIENT],
            addrs: vec![IpAddr::V4(ip("10.0.0.254"))],
            count: 1,
        };
        let outputs = [
            Output::Warning(warning.clone()),
            Output::Warning(Warning {
                ts: t(1_795_266_192),
                segment: Some(U),
                count: 4,
                ..warning.clone()
            }),
            Output::Warning(Warning {
                segment: None,
                ..warning
            }),
            Output::Baseline(Baseline {
                ts: t(1_795_266_132),
                segment: U,
                what: Expected::DhcpServer(ip("10.0.0.1")),
            }),
            Output::Baseline(Baseline {
                ts: t(1_795_266_132),
                segment: seg("200.100"),
                what: Expected::Router {
                    mac: mac(1),
                    ip: ip6("fe80::1"),
                },
            }),
        ];
        let mut r = LineRenderer::new(Vec::new(), opts);
        for o in &outputs {
            r.output(o).expect("output");
        }
        let got = String::from_utf8(r.into_inner()).expect("utf8");
        assert_eq!(
            got,
            "2026-11-21 13:02:12.010 WARN  [100] second DHCP server 10.0.0.254 (expected 10.0.0.1)\n\
             2026-11-21 13:03:12.000 WARN  second DHCP server 10.0.0.254 (expected 10.0.0.1) \
             (repeated 4 times in the last minute)\n\
             2026-11-21 13:02:12.010 WARN  second DHCP server 10.0.0.254 (expected 10.0.0.1)\n\
             2026-11-21 13:02:12.000 NOTE  expected DHCP server 10.0.0.1 (learned)\n\
             2026-11-21 13:02:12.000 NOTE  [200.100] expected router fe80::1 (02:00:5e:10:00:01) (learned)\n"
        );
    }

    #[test]
    fn rule_and_severity_names() {
        let rules = [
            (Rule::SecondDhcpServer, "second-dhcp-server"),
            (Rule::UnexpectedRouter, "unexpected-router"),
            (Rule::AddressConflict, "address-conflict"),
            (Rule::SuspiciousNameAnswers, "suspicious-name-answers"),
            (Rule::CaptureDrops, "capture-drops"),
            (Rule::MemoryEviction, "memory-eviction"),
        ];
        for (r, s) in rules {
            assert_eq!(r.as_str(), s);
        }
        assert_eq!(
            (Severity::Low.as_str(), Severity::High.as_str()),
            ("low", "high")
        );
    }
}
