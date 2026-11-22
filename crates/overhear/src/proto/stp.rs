//! STP / RSTP / MSTP presentation and observations.

use std::fmt::Write;

use overhear_decode::{BridgeId, Packet, Stp, StpConfig};

use crate::json::JsonWriter;
use crate::observe::{Observation, ProtoTag, Role};

struct Id(BridgeId);

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}.{}", self.0.priority, self.0.mac)
    }
}

fn kind(s: &Stp) -> &'static str {
    match s.version {
        2 => "RSTP",
        3 => "MSTP",
        _ => "STP",
    }
}

fn config_text(out: &mut String, c: &StpConfig) {
    let _ = write!(
        out,
        "root {} cost {} bridge {} port 0x{:04x}",
        Id(c.root),
        c.cost,
        Id(c.bridge),
        c.port
    );
}

/// `{STP|RSTP|MSTP} root {id} cost {n} bridge {id} port 0x{port}`, ` TC` and
/// the MSTI count; or the topology change notification text.
pub fn summary(s: &Stp, out: &mut String) {
    let Some(c) = &s.config else {
        out.push_str("topology change notification");
        return;
    };
    out.push_str(kind(s));
    out.push(' ');
    config_text(out, c);
    if s.flags & 1 != 0 {
        out.push_str(" TC");
    }
    if s.version == 3 {
        let _ = write!(out, " ({} MSTIs)", s.msti_count);
    }
}

pub fn verbose(s: &Stp, out: &mut String) {
    out.push_str("  STP   ");
    out.push_str(kind(s));
    out.push(' ');
    let Some(c) = &s.config else {
        out.push_str("topology change notification\n");
        return;
    };
    config_text(out, c);
    let _ = write!(
        out,
        " flags 0x{:02x} age {}s max-age {}s hello {}s forward-delay {}s",
        s.flags,
        c.message_age >> 8,
        c.max_age >> 8,
        c.hello >> 8,
        c.forward_delay >> 8
    );
    if s.version == 3 {
        let _ = write!(out, " msti {}", s.msti_count);
    }
    out.push('\n');
}

pub fn json(s: &Stp, w: &mut JsonWriter) {
    w.obj(Some("stp"));
    w.u64(Some("version"), u64::from(s.version));
    w.u64(Some("type"), u64::from(s.bpdu_type));
    w.u64(Some("flags"), u64::from(s.flags));
    w.bool(Some("topology_change"), s.flags & 1 != 0);
    if let Some(c) = &s.config {
        w.str(Some("root"), &Id(c.root).to_string());
        w.u64(Some("cost"), u64::from(c.cost));
        w.str(Some("bridge"), &Id(c.bridge).to_string());
        w.u64(Some("port"), u64::from(c.port));
        w.u64(Some("message_age_256ths"), u64::from(c.message_age));
        w.u64(Some("max_age_256ths"), u64::from(c.max_age));
        w.u64(Some("hello_256ths"), u64::from(c.hello));
        w.u64(Some("forward_delay_256ths"), u64::from(c.forward_delay));
    }
    if s.version == 3 {
        w.u64(Some("msti_count"), u64::from(s.msti_count));
    }
    w.end();
}

/// The sender is a bridge; a configuration BPDU also names the root.
pub fn observe<'a>(p: &Packet<'a>, s: &Stp, out: &mut Vec<Observation<'a>>) {
    let mac = p.eth.src;
    out.push(Observation::Heard {
        mac,
        proto: ProtoTag::Stp,
    });
    out.push(Observation::Role {
        mac,
        role: Role::Bridge,
    });
    if let Some(c) = &s.config {
        out.push(Observation::StpRoot {
            root: c.root.to_bytes(),
        });
    }
}

pub fn tag() -> &'static str {
    "STP"
}

#[cfg(test)]
mod tests {
    use super::*;
    use overhear_decode::{Mac, Proto, decode};
    use overhear_testgen::{bpdu, llc, mac};

    const STP_MCAST: [u8; 6] = [0x01, 0x80, 0xc2, 0, 0, 0];
    const ROOT: (u16, [u8; 6]) = (0x8000, [0, 0x11, 0x22, 0x33, 0x44, 1]);

    fn with<R>(payload: &[u8], f: impl FnOnce(&Packet<'_>, &Stp) -> R) -> R {
        let frame = llc(STP_MCAST, mac(0x50), 0x42, 0x42, 3, payload);
        let p = decode(&frame).unwrap();
        let Proto::Stp(s) = &p.proto else {
            panic!("not stp")
        };
        f(&p, s)
    }

    fn cfg(version: u8, typ: u8, flags: u8, mstis: u8) -> Vec<u8> {
        bpdu(
            version,
            typ,
            flags,
            ROOT,
            19,
            (0x8001, mac(0x50)),
            0x8002,
            mstis,
        )
    }

    fn line(payload: &[u8]) -> String {
        with(payload, |_, s| {
            let mut o = String::new();
            summary(s, &mut o);
            o
        })
    }

    #[test]
    fn exact_summaries() {
        let base = "root 8000.00:11:22:33:44:01 cost 19 bridge 8001.02:00:5e:10:00:50 port 0x8002";
        assert_eq!(line(&cfg(0, 0, 0, 0)), format!("STP {base}"));
        assert_eq!(line(&cfg(2, 2, 1, 0)), format!("RSTP {base} TC"));
        assert_eq!(line(&cfg(0, 0, 1, 0)), format!("STP {base} TC"));
        assert_eq!(line(&cfg(3, 2, 0, 2)), format!("MSTP {base} (2 MSTIs)"));
        assert_eq!(line(&cfg(3, 2, 1, 2)), format!("MSTP {base} TC (2 MSTIs)"));
        assert_eq!(line(&cfg(0, 0x80, 0, 0)), "topology change notification");
        assert_eq!(tag(), "STP");
    }

    fn obs(payload: &[u8], check: impl FnOnce(Vec<Observation<'_>>)) {
        with(payload, |p, s| {
            let mut out = Vec::new();
            observe(p, s, &mut out);
            check(out);
        })
    }

    #[test]
    fn root_observation() {
        let m = Mac(mac(0x50));
        obs(&cfg(0, 0, 0, 0), |o| {
            assert_eq!(
                o,
                vec![
                    Observation::Heard {
                        mac: m,
                        proto: ProtoTag::Stp
                    },
                    Observation::Role {
                        mac: m,
                        role: Role::Bridge
                    },
                    Observation::StpRoot {
                        root: [0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01]
                    },
                ]
            )
        });
    }

    #[test]
    fn tcn_names_no_root() {
        obs(&cfg(0, 0x80, 0, 0), |o| assert_eq!(o.len(), 2));
    }

    #[test]
    fn verbose_and_json() {
        let v = with(&cfg(3, 2, 1, 2), |_, s| {
            let mut o = String::new();
            verbose(s, &mut o);
            o
        });
        assert_eq!(
            v,
            "  STP   MSTP root 8000.00:11:22:33:44:01 cost 19 bridge 8001.02:00:5e:10:00:50 port 0x8002 flags 0x01 age 0s max-age 20s hello 2s forward-delay 15s msti 2\n"
        );
        let t = with(&cfg(0, 0x80, 0, 0), |_, s| {
            let mut o = String::new();
            verbose(s, &mut o);
            o
        });
        assert_eq!(t, "  STP   STP topology change notification\n");
        let j = with(&cfg(2, 2, 1, 0), |_, s| {
            let mut w = JsonWriter::new();
            w.obj(None);
            json(s, &mut w);
            w.end();
            w.as_str().to_string()
        });
        assert_eq!(
            j,
            r#"{"stp":{"version":2,"type":2,"flags":1,"topology_change":true,"root":"8000.00:11:22:33:44:01","cost":19,"bridge":"8001.02:00:5e:10:00:50","port":32770,"message_age_256ths":0,"max_age_256ths":5120,"hello_256ths":512,"forward_delay_256ths":3840}}"#
        );
    }
}
