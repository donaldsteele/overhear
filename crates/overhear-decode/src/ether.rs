use crate::{Cursor, Layer, Mac, Problem};

const MAX_VLANS: usize = 4;

fn is_vlan_tpid(t: u16) -> bool {
    matches!(t, 0x8100 | 0x88a8 | 0x9100)
}

/// One VLAN tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vlan {
    pub tpid: u16,
    pub pcp: u8,
    pub id: u16,
}

/// Up to four VLAN tags, outer first, without allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vlans {
    tags: [Vlan; MAX_VLANS],
    len: usize,
}

impl Vlans {
    const EMPTY: Vlan = Vlan {
        tpid: 0,
        pcp: 0,
        id: 0,
    };

    fn new() -> Self {
        Vlans {
            tags: [Self::EMPTY; MAX_VLANS],
            len: 0,
        }
    }

    fn push(&mut self, v: Vlan) -> bool {
        match self.tags.get_mut(self.len) {
            Some(slot) => {
                *slot = v;
                self.len = self.len.saturating_add(1);
                true
            }
            None => false,
        }
    }

    pub fn as_slice(&self) -> &[Vlan] {
        self.tags.get(..self.len).unwrap_or(&[])
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthKind {
    EtherType(u16),
    Llc { dsap: u8, ssap: u8, ctrl: u8 },
    Snap { oui: [u8; 3], pid: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthHeader {
    pub dst: Mac,
    pub src: Mac,
    pub vlans: Vlans,
    pub kind: EthKind,
}

fn problem(layer: Layer, reason: &'static str, offset: usize, len: usize) -> Problem {
    Problem {
        layer,
        reason,
        offset,
        len,
    }
}

/// Decodes an Ethernet header, VLAN tags and LLC/SNAP.
/// On `Some`, `c` is at the payload. For 802.3 frames it is limited to the
/// length field, so padding is dropped.
pub fn ethernet<'a>(c: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Option<EthHeader> {
    let first = c.pos();
    if c.remaining() < 14 {
        problems.push(problem(Layer::Ethernet, "truncated", first, c.remaining()));
        return None;
    }
    let (Some(dst), Some(src)) = (
        c.take(6).and_then(Mac::from_slice),
        c.take(6).and_then(Mac::from_slice),
    ) else {
        problems.push(problem(Layer::Ethernet, "truncated", first, c.remaining()));
        return None;
    };
    let mut vlans = Vlans::new();
    let mut tl_pos = c.pos();
    let mut tl = c.be16();
    loop {
        let Some(t) = tl else {
            problems.push(problem(Layer::Ethernet, "truncated", tl_pos, c.remaining()));
            return None;
        };
        if !is_vlan_tpid(t) {
            break;
        }
        if vlans.len >= MAX_VLANS {
            problems.push(problem(Layer::Vlan, "too many VLAN tags", tl_pos, 2));
            let kind = EthKind::EtherType(t);
            return Some(EthHeader {
                dst,
                src,
                vlans,
                kind,
            });
        }
        let Some(tci) = c.be16() else {
            problems.push(problem(
                Layer::Vlan,
                "truncated",
                tl_pos,
                c.remaining().saturating_add(2),
            ));
            return None;
        };
        vlans.push(Vlan {
            tpid: t,
            pcp: (tci >> 13) as u8,
            id: tci & 0x0fff,
        });
        tl_pos = c.pos();
        tl = c.be16();
    }
    let t = tl?;
    if t >= 1536 {
        return Some(EthHeader {
            dst,
            src,
            vlans,
            kind: EthKind::EtherType(t),
        });
    }
    if t >= 1501 {
        problems.push(problem(Layer::Ethernet, "bad type/length", tl_pos, 2));
        return Some(EthHeader {
            dst,
            src,
            vlans,
            kind: EthKind::EtherType(t),
        });
    }
    // 802.3 length field
    if usize::from(t) > c.remaining() {
        problems.push(problem(Layer::Ethernet, "truncated", tl_pos, 2));
    } else if let Some(sub) = c.sub(usize::from(t)) {
        *c = sub;
    }
    let llc_pos = c.pos();
    let (Some(dsap), Some(ssap), Some(ctrl)) = (c.u8(), c.u8(), c.u8()) else {
        problems.push(problem(Layer::Llc, "truncated", llc_pos, c.remaining()));
        return None;
    };
    let kind = if (dsap, ssap, ctrl) == (0xaa, 0xaa, 0x03) {
        let snap_pos = c.pos();
        let (Some(oui), Some(pid)) = (c.take(3), c.be16()) else {
            problems.push(problem(Layer::Llc, "truncated", snap_pos, c.remaining()));
            return None;
        };
        let oui: [u8; 3] = oui.try_into().ok()?;
        EthKind::Snap { oui, pid }
    } else {
        EthKind::Llc { dsap, ssap, ctrl }
    };
    Some(EthHeader {
        dst,
        src,
        vlans,
        kind,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::Layer;
    use overhear_testgen::*;

    fn dec(f: &[u8]) -> (Option<EthHeader>, Vec<Problem>, usize) {
        let mut c = Cursor::new(f);
        let mut p = vec![];
        let h = ethernet(&mut c, &mut p);
        (h, p, c.remaining())
    }

    #[test]
    fn ethernet_ii_broadcast() {
        let (h, p, rem) = dec(&eth(BCAST, mac(0x14), 0x0800, &[0xaa; 46]));
        let h = h.unwrap();
        assert!(h.dst.is_broadcast() && h.vlans.is_empty() && p.is_empty());
        assert_eq!(h.src, Mac(mac(0x14)));
        assert!(matches!(h.kind, EthKind::EtherType(0x0800)));
        assert_eq!(rem, 46);
    }

    #[test]
    fn qinq_outer_tag_first() {
        let (h, _, _) = dec(&eth_vlan(
            BCAST,
            mac(1),
            &[(0x88a8, 200), (0x8100, 100)],
            0x0800,
            &[0; 46],
        ));
        let ids: Vec<_> = h
            .unwrap()
            .vlans
            .as_slice()
            .iter()
            .map(|v| (v.tpid, v.id))
            .collect();
        assert_eq!(ids, [(0x88a8, 200), (0x8100, 100)]);
    }

    #[test]
    fn fifth_vlan_tag_is_a_problem() {
        let tags = [
            (0x8100, 1),
            (0x8100, 2),
            (0x8100, 3),
            (0x8100, 4),
            (0x8100, 5),
        ];
        let (h, p, _) = dec(&eth_vlan(BCAST, mac(1), &tags, 0x0800, &[0; 46]));
        let h = h.unwrap();
        assert_eq!(h.vlans.as_slice().len(), 4);
        assert!(matches!(h.kind, EthKind::EtherType(0x8100)));
        assert_eq!(p[0].reason, "too many VLAN tags");
    }

    #[test]
    fn llc_payload_excludes_padding() {
        let (h, _, rem) = dec(&llc(
            [1, 0x80, 0xc2, 0, 0, 0],
            mac(1),
            0x42,
            0x42,
            0x03,
            &[0; 35],
        ));
        assert!(matches!(
            h.unwrap().kind,
            EthKind::Llc {
                dsap: 0x42,
                ssap: 0x42,
                ctrl: 0x03
            }
        ));
        assert_eq!(rem, 35);
    }

    #[test]
    fn snap_header() {
        let (h, _, rem) = dec(&snap(
            [1, 0, 0x0c, 0xcc, 0xcc, 0xcc],
            mac(1),
            [0, 0, 0x0c],
            0x2000,
            &[1, 2, 3],
        ));
        assert!(matches!(
            h.unwrap().kind,
            EthKind::Snap {
                oui: [0, 0, 0x0c],
                pid: 0x2000
            }
        ));
        assert_eq!(rem, 3);
    }

    #[test]
    fn short_frame() {
        let (h, p, _) = dec(&[0u8; 13]);
        assert!(h.is_none());
        assert_eq!(
            (p[0].layer, p[0].reason, p[0].offset),
            (Layer::Ethernet, "truncated", 0)
        );
    }

    #[test]
    fn length_field_beyond_frame() {
        let mut f = llc(BCAST, mac(1), 0x42, 0x42, 0x03, &[0; 47]);
        f[12..14].copy_from_slice(&1000u16.to_be_bytes());
        let (_, p, rem) = dec(&f);
        assert_eq!(p[0].reason, "truncated");
        assert_eq!(rem, f.len() - 17);
    }

    #[test]
    fn bad_type_length() {
        let (_, p, _) = dec(&eth(BCAST, mac(1), 0x05e0, &[0; 46]));
        assert_eq!(p[0].reason, "bad type/length");
    }
}
