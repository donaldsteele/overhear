//! What each segment learned: its DHCP server, default router and gateways.
//! At most [`MAX_SEGMENTS`] segments keep state; making room drops the least
//! recently used one, which then learns again.

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};

use overhear_decode::Mac;

use super::{MAX_SEGMENTS, OVERHEAD};
use crate::observe::Segment;
use crate::track::{Bounded, Budget};

/// Gateways remembered per segment.
const MAX_GATEWAYS: usize = 16;

pub(super) struct Learned {
    /// The first DHCP server heard, when no pin applies.
    pub dhcp: Option<Ipv4Addr>,
    /// The first default router heard, when no pin applies.
    pub router: Option<(Mac, Ipv6Addr)>,
    /// Router options of replies from expected DHCP servers.
    pub gateways: Bounded<Ipv4Addr>,
}

fn cost(l: &Learned) -> usize {
    size_of::<(Segment, (Learned, u64))>()
        + size_of::<(u64, Segment)>()
        + 2 * OVERHEAD
        + l.gateways.len() * size_of::<Ipv4Addr>()
}

pub(super) struct Segments {
    map: HashMap<Segment, (Learned, u64)>,
    /// (last use, segment), least recently used first.
    lru: BTreeSet<(u64, Segment)>,
    clock: u64,
}

impl Segments {
    pub(super) fn new() -> Self {
        Segments {
            map: HashMap::new(),
            lru: BTreeSet::new(),
            clock: 0,
        }
    }

    fn touch(&mut self, seg: Segment) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        let stamp = self.clock;
        if let Some((_, used)) = self.map.get_mut(&seg) {
            self.lru.remove(&(*used, seg));
            *used = stamp;
            self.lru.insert((stamp, seg));
        }
        stamp
    }

    /// What `seg` learned, marking it as just used.
    pub(super) fn get(&mut self, seg: Segment) -> Option<&Learned> {
        self.touch(seg);
        self.map.get(&seg).map(|(l, _)| l)
    }

    /// What `seg` learned, without marking it used.
    pub(super) fn peek(&self, seg: Segment) -> Option<&Learned> {
        self.map.get(&seg).map(|(l, _)| l)
    }

    /// Changes what `seg` learned, giving it state (and making room) when it
    /// has none, and charges the difference to the budget.
    pub(super) fn update(
        &mut self,
        seg: Segment,
        budget: &mut Budget,
        f: impl FnOnce(&mut Learned),
    ) {
        let stamp = self.touch(seg);
        if !self.map.contains_key(&seg) && self.map.len() >= MAX_SEGMENTS {
            self.drop_oldest(budget);
        }
        let (before, learned) = match self.map.entry(seg) {
            Entry::Occupied(e) => {
                let (l, _) = e.into_mut();
                (cost(l), l)
            }
            Entry::Vacant(e) => {
                self.lru.insert((stamp, seg));
                let l = Learned {
                    dhcp: None,
                    router: None,
                    gateways: Bounded::new(MAX_GATEWAYS),
                };
                let (l, _) = e.insert((l, stamp));
                (0, l)
            }
        };
        f(learned);
        budget.adjust(before, cost(learned));
    }

    fn drop_oldest(&mut self, budget: &mut Budget) {
        let Some((_, seg)) = self.lru.pop_first() else {
            return;
        };
        if let Some((l, _)) = self.map.remove(&seg) {
            budget.adjust(cost(&l), 0);
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.map.len()
    }

    pub(super) fn cost(&self) -> usize {
        self.map.values().map(|(l, _)| cost(l)).sum()
    }
}
