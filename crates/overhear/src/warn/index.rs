//! From a MAC to the keys of the state kept about it, so forgetting a device
//! touches only its own entries. The index is charged to the budget too.

use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::net::IpAddr;

use overhear_decode::Mac;

use super::OVERHEAD;
use super::names::AnswerKey;
use crate::observe::Segment;
use crate::track::Budget;

pub(super) type ClaimKey = (Segment, IpAddr);

#[derive(Default)]
pub(super) struct Keys {
    pub claims: HashSet<ClaimKey>,
    pub answers: HashSet<AnswerKey>,
    /// Segments in which the MAC has a name set.
    pub hosts: HashSet<Segment>,
    /// Bytes of the answer names held, kept as they come and go.
    names: usize,
}

const BASE: usize = size_of::<(Mac, Keys)>() + OVERHEAD;

/// Bytes a set holds: its capacity, not its length, since removals leave
/// the room (until [`Keys::shrink`]). One control byte per slot.
fn set_cost<T>(cap: usize) -> usize {
    cap * (size_of::<T>() + 1)
}

impl Keys {
    fn is_empty(&self) -> bool {
        self.claims.is_empty() && self.answers.is_empty() && self.hosts.is_empty()
    }

    fn cost(&self) -> usize {
        BASE + set_cost::<ClaimKey>(self.claims.capacity())
            + set_cost::<AnswerKey>(self.answers.capacity())
            + set_cost::<Segment>(self.hosts.capacity())
            + self.names
    }

    /// Gives back room that removals left unused.
    fn shrink(&mut self) {
        if self.claims.len() < self.claims.capacity() / 4 {
            self.claims.shrink_to_fit();
        }
        if self.answers.len() < self.answers.capacity() / 4 {
            self.answers.shrink_to_fit();
        }
        if self.hosts.len() < self.hosts.capacity() / 4 {
            self.hosts.shrink_to_fit();
        }
    }

    /// The same, with the names counted from scratch.
    fn recount(&self) -> usize {
        self.cost() - self.names + self.answers.iter().map(|k| k.2.len()).sum::<usize>()
    }
}

pub(super) struct Index {
    map: HashMap<Mac, Keys>,
}

impl Index {
    pub(super) fn new() -> Self {
        Index {
            map: HashMap::new(),
        }
    }

    /// Changes the keys of `mac` and charges the difference.
    fn edit(&mut self, mac: Mac, budget: &mut Budget, f: impl FnOnce(&mut Keys)) {
        let existing = self.map.remove(&mac);
        let before = existing.as_ref().map_or(0, Keys::cost);
        let mut keys = existing.unwrap_or_default();
        f(&mut keys);
        keys.shrink();
        if keys.is_empty() {
            budget.adjust(before, 0);
        } else {
            budget.adjust(before, keys.cost());
            self.map.insert(mac, keys);
        }
    }

    pub(super) fn add_claim(&mut self, mac: Mac, key: ClaimKey, budget: &mut Budget) {
        self.edit(mac, budget, |k| {
            k.claims.insert(key);
        });
    }

    pub(super) fn remove_claim(&mut self, mac: Mac, key: &ClaimKey, budget: &mut Budget) {
        if self.map.contains_key(&mac) {
            self.edit(mac, budget, |k| {
                k.claims.remove(key);
            });
        }
    }

    pub(super) fn add_answer(&mut self, mac: Mac, key: &AnswerKey, budget: &mut Budget) {
        self.edit(mac, budget, |k| {
            if k.answers.insert(key.clone()) {
                k.names += key.2.len();
            }
        });
    }

    pub(super) fn remove_answer(&mut self, mac: Mac, key: &AnswerKey, budget: &mut Budget) {
        if self.map.contains_key(&mac) {
            self.edit(mac, budget, |k| {
                if k.answers.remove(key) {
                    k.names -= key.2.len();
                }
            });
        }
    }

    pub(super) fn add_host(&mut self, mac: Mac, seg: Segment, budget: &mut Budget) {
        self.edit(mac, budget, |k| {
            k.hosts.insert(seg);
        });
    }

    pub(super) fn remove_host(&mut self, mac: Mac, seg: Segment, budget: &mut Budget) {
        if self.map.contains_key(&mac) {
            self.edit(mac, budget, |k| {
                k.hosts.remove(&seg);
            });
        }
    }

    /// Removes everything indexed for `mac`, releasing its cost.
    pub(super) fn take(&mut self, mac: &Mac, budget: &mut Budget) -> Option<Keys> {
        let keys = self.map.remove(mac)?;
        budget.adjust(keys.cost(), 0);
        Some(keys)
    }

    /// Bytes of the index, counted from scratch.
    pub(super) fn cost(&self) -> usize {
        self.map.values().map(Keys::recount).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removals_give_back_room_and_the_charge_follows() {
        let mut idx = Index::new();
        let mut b = Budget::new(usize::MAX);
        let mac = Mac([2, 0, 0, 0, 0, 1]);
        let key = |i: u32| (Segment::UNTAGGED, IpAddr::from(std::net::Ipv4Addr::from(i)));
        for i in 0..30_000 {
            idx.add_claim(mac, key(i), &mut b);
        }
        let full = b.used();
        assert_eq!(full, idx.cost());
        assert!(full > 30_000 * size_of::<ClaimKey>());
        for i in 1..30_000 {
            idx.remove_claim(mac, &key(i), &mut b);
        }
        assert_eq!(b.used(), idx.cost());
        assert!(b.used() < full / 100, "{} of {full}", b.used());
        let held = idx.map.get(&mac).map_or(0, |k| k.claims.capacity());
        assert!(held < 1000, "capacity {held}");
        idx.take(&mac, &mut b);
        assert_eq!((b.used(), idx.cost()), (0, 0));
    }
}
