//! STP / RSTP / MSTP BPDU decoder.

use crate::{Cursor, Layer, Mac, Problem};

/// The most MSTI records counted (the standard allows 64).
pub const MAX_MSTIS: usize = 64;

/// Bytes of a configuration BPDU: protocol id, version, type and the body.
const CONFIG_LEN: usize = 35;
/// Fixed bytes of the MSTP section that precede the MSTI records.
const MST_FIXED: usize = 64;
const MSTI_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeId {
    /// Priority including the system-id extension.
    pub priority: u16,
    pub mac: Mac,
}

impl BridgeId {
    pub fn to_bytes(&self) -> [u8; 8] {
        let [a, b] = self.priority.to_be_bytes();
        let [c, d, e, f, g, h] = self.mac.0;
        [a, b, c, d, e, f, g, h]
    }

    fn read(c: &mut Cursor<'_>) -> Option<BridgeId> {
        let priority = c.be16()?;
        let mac = Mac::from_slice(c.take(6)?)?;
        Some(BridgeId { priority, mac })
    }
}

/// Timers are in units of 1/256 second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StpConfig {
    pub root: BridgeId,
    pub cost: u32,
    pub bridge: BridgeId,
    pub port: u16,
    pub message_age: u16,
    pub max_age: u16,
    pub hello: u16,
    pub forward_delay: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stp {
    pub version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    /// `None` for a topology change notification.
    pub config: Option<StpConfig>,
    /// MSTI records present in an MSTP BPDU, counted from the bytes there.
    pub msti_count: u8,
}

fn problem(reason: &'static str, offset: usize, len: usize) -> Problem {
    Problem {
        layer: Layer::Stp,
        reason,
        offset,
        len,
    }
}

fn config(r: &mut Cursor<'_>) -> Option<(u8, StpConfig)> {
    let flags = r.u8()?;
    let root = BridgeId::read(r)?;
    let cost = r.be32()?;
    let bridge = BridgeId::read(r)?;
    let port = r.be16()?;
    Some((
        flags,
        StpConfig {
            root,
            cost,
            bridge,
            port,
            message_age: r.be16()?,
            max_age: r.be16()?,
            hello: r.be16()?,
            forward_delay: r.be16()?,
        },
    ))
}

/// Parses one BPDU. A protocol id other than 0, an unknown BPDU type or a
/// configuration BPDU shorter than 35 bytes is rejected with a problem; the
/// cursor moves only on success. The MSTP section is counted, not decoded: the
/// MSTI count comes from the bytes present, bounded by the stated length.
pub fn parse<'a>(c: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Option<Stp> {
    let mut r = *c;
    let start = r.pos();
    let (Some(proto), Some(version), Some(bpdu_type)) = (r.be16(), r.u8(), r.u8()) else {
        problems.push(problem("truncated", start, r.remaining()));
        return None;
    };
    if proto != 0 {
        problems.push(problem("not an STP BPDU", start, 2));
        return None;
    }
    let mut stp = Stp {
        version,
        bpdu_type,
        flags: 0,
        config: None,
        msti_count: 0,
    };
    match bpdu_type {
        0x80 => {}
        0x00 | 0x02 => {
            let Some((flags, cfg)) = config(&mut r) else {
                problems.push(problem("truncated", start, c.remaining().min(CONFIG_LEN)));
                return None;
            };
            stp.flags = flags;
            stp.config = Some(cfg);
            if version >= 3 {
                let at = r.pos();
                let (Some(_v1_len), Some(v3_len)) = (r.u8(), r.be16()) else {
                    problems.push(problem("truncated", at, r.remaining()));
                    return None;
                };
                let v3_len = usize::from(v3_len);
                let have = r.remaining();
                if v3_len > have || v3_len < MST_FIXED {
                    problems.push(problem("bad MSTP length", at, have.saturating_add(3)));
                }
                let usable = v3_len.min(have).saturating_sub(MST_FIXED);
                let n = (usable / MSTI_LEN).min(MAX_MSTIS);
                stp.msti_count = u8::try_from(n).unwrap_or(u8::MAX);
            }
        }
        _ => {
            problems.push(problem("unknown BPDU type", start.saturating_add(3), 1));
            return None;
        }
    }
    r.rest();
    *c = r;
    Some(stp)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use overhear_testgen::{bpdu, mac};

    fn run(b: &[u8]) -> (Option<Stp>, Vec<Problem>) {
        let mut c = Cursor::new(b);
        let mut p = Vec::new();
        let r = parse(&mut c, &mut p);
        (r, p)
    }

    const ROOT: (u16, [u8; 6]) = (0x8000, [0, 0x11, 0x22, 0x33, 0x44, 1]);

    fn config_bytes(version: u8, typ: u8, flags: u8, mstis: u8) -> Vec<u8> {
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

    #[test]
    fn stp_config() {
        let (s, p) = run(&config_bytes(0, 0, 0, 0));
        let s = s.unwrap();
        assert!(p.is_empty());
        assert_eq!(
            (s.version, s.bpdu_type, s.flags, s.msti_count),
            (0, 0, 0, 0)
        );
        let c = s.config.unwrap();
        assert_eq!(c.root.priority, 0x8000);
        assert_eq!(c.root.mac.0, ROOT.1);
        assert_eq!(c.root.to_bytes(), [0x80, 0, 0, 0x11, 0x22, 0x33, 0x44, 1]);
        assert_eq!(c.cost, 19);
        assert_eq!(c.bridge.priority, 0x8001);
        assert_eq!(c.bridge.mac.0, mac(0x50));
        assert_eq!(c.port, 0x8002);
        assert_eq!(
            (c.message_age, c.max_age, c.hello, c.forward_delay),
            (0, 20 * 256, 2 * 256, 15 * 256)
        );
    }

    #[test]
    fn rstp_with_tc() {
        let (s, p) = run(&config_bytes(2, 2, 0x01, 0));
        let s = s.unwrap();
        assert!(p.is_empty());
        assert_eq!((s.version, s.bpdu_type, s.flags), (2, 2, 1));
        assert!(s.config.is_some());
    }

    #[test]
    fn tcn_has_no_config() {
        let (s, p) = run(&config_bytes(0, 0x80, 0, 0));
        let s = s.unwrap();
        assert!(p.is_empty());
        assert_eq!(s.bpdu_type, 0x80);
        assert!(s.config.is_none());
    }

    #[test]
    fn mstp_counts_mstis() {
        let (s, p) = run(&config_bytes(3, 2, 0, 2));
        assert!(p.is_empty());
        assert_eq!(s.unwrap().msti_count, 2);
        let (s, _) = run(&config_bytes(3, 2, 0, 0));
        assert_eq!(s.unwrap().msti_count, 0);
    }

    #[test]
    fn mstp_length_larger_than_data_is_bounded() {
        let mut b = config_bytes(3, 2, 0, 2);
        // Claim 0xffff bytes; only 2 MSTIs are there.
        b[36] = 0xff;
        b[37] = 0xff;
        let (s, p) = run(&b);
        assert_eq!(s.unwrap().msti_count, 2);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].reason, "bad MSTP length");
        // The section cut short mid-record counts whole records only.
        let mut b = config_bytes(3, 2, 0, 2);
        b.truncate(b.len() - 4);
        let (s, _) = run(&b);
        assert_eq!(s.unwrap().msti_count, 1);
        let mut b = config_bytes(2, 2, 0, 0);
        b[2] = 3;
        let (s, p) = run(&b);
        assert!(s.is_none());
        assert_eq!(p[0].reason, "truncated");
    }

    #[test]
    fn mstp_msti_count_is_capped() {
        let mut b = config_bytes(3, 2, 0, 0);
        b.extend(std::iter::repeat_n(0u8, 16 * 100));
        b[36] = 0xff;
        b[37] = 0xff;
        let (s, _) = run(&b);
        assert_eq!(usize::from(s.unwrap().msti_count), MAX_MSTIS);
    }

    #[test]
    fn truncated_config() {
        let b = config_bytes(0, 0, 0, 0);
        let mut c = Cursor::new(&b[..20]);
        let mut p = Vec::new();
        assert!(parse(&mut c, &mut p).is_none());
        assert_eq!(c.pos(), 0);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].layer, p[0].reason), (Layer::Stp, "truncated"));
        assert!(run(&b[..3]).0.is_none());
        assert!(run(&[]).0.is_none());
    }

    #[test]
    fn protocol_id_1_rejected() {
        let mut b = config_bytes(0, 0, 0, 0);
        b[1] = 1;
        let (s, p) = run(&b);
        assert!(s.is_none());
        assert_eq!(p[0].reason, "not an STP BPDU");
    }

    #[test]
    fn unknown_type_rejected() {
        let mut b = config_bytes(0, 0, 0, 0);
        b[3] = 0x55;
        let (s, p) = run(&b);
        assert!(s.is_none());
        assert_eq!(p[0].reason, "unknown BPDU type");
    }
}
