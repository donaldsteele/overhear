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
    /// Bytes of the keys held, kept as they come and go.
    heap: usize,
}

const BASE: usize = size_of::<(Mac, Keys)>() + OVERHEAD;
const CLAIM: usize = size_of::<ClaimKey>() + OVERHEAD;
const HOST: usize = size_of::<Segment>() + OVERHEAD;

fn answer(k: &AnswerKey) -> usize {
    size_of::<AnswerKey>() + k.2.len() + OVERHEAD
}

impl Keys {
    fn is_empty(&self) -> bool {
        self.claims.is_empty() && self.answers.is_empty() && self.hosts.is_empty()
    }

    fn cost(&self) -> usize {
        BASE + self.heap
    }

    /// The same, counted from scratch.
    fn recount(&self) -> usize {
        BASE + self.claims.len() * CLAIM
            + self.answers.iter().map(answer).sum::<usize>()
            + self.hosts.len() * HOST
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
        if keys.is_empty() {
            budget.adjust(before, 0);
        } else {
            budget.adjust(before, keys.cost());
            self.map.insert(mac, keys);
        }
    }

    pub(super) fn add_claim(&mut self, mac: Mac, key: ClaimKey, budget: &mut Budget) {
        self.edit(mac, budget, |k| {
            if k.claims.insert(key) {
                k.heap += CLAIM;
            }
        });
    }

    pub(super) fn remove_claim(&mut self, mac: Mac, key: &ClaimKey, budget: &mut Budget) {
        if self.map.contains_key(&mac) {
            self.edit(mac, budget, |k| {
                if k.claims.remove(key) {
                    k.heap -= CLAIM;
                }
            });
        }
    }

    pub(super) fn add_answer(&mut self, mac: Mac, key: &AnswerKey, budget: &mut Budget) {
        self.edit(mac, budget, |k| {
            if k.answers.insert(key.clone()) {
                k.heap += answer(key);
            }
        });
    }

    pub(super) fn remove_answer(&mut self, mac: Mac, key: &AnswerKey, budget: &mut Budget) {
        if self.map.contains_key(&mac) {
            self.edit(mac, budget, |k| {
                if k.answers.remove(key) {
                    k.heap -= answer(key);
                }
            });
        }
    }

    pub(super) fn add_host(&mut self, mac: Mac, seg: Segment, budget: &mut Budget) {
        self.edit(mac, budget, |k| {
            if k.hosts.insert(seg) {
                k.heap += HOST;
            }
        });
    }

    pub(super) fn remove_host(&mut self, mac: Mac, seg: Segment, budget: &mut Budget) {
        if self.map.contains_key(&mac) {
            self.edit(mac, budget, |k| {
                if k.hosts.remove(&seg) {
                    k.heap -= HOST;
                }
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
