//! A map that keeps its least recently updated entry out of the way: when
//! full (by count or by bytes) a new key replaces the oldest. Every operation
//! is O(log n), and the cost of what it holds is charged to the budget.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use crate::track::Budget;

pub(super) struct Lru<K, V> {
    map: HashMap<K, (V, u64)>,
    /// Keys by the stamp of their last update, oldest first.
    order: BTreeMap<u64, K>,
    clock: u64,
    /// Sum of `cost_of` over the entries.
    bytes: usize,
    cap: usize,
    /// Bytes an entry costs, all of it: both copies of the key, the value and
    /// the map overhead.
    cost_of: fn(&K, &V) -> usize,
}

/// What [`Lru::put`] displaced.
pub(super) struct Put<K, V> {
    /// The value the key had.
    pub replaced: Option<V>,
    /// Entries dropped to make room.
    pub evicted: Vec<(K, V)>,
}

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    pub(super) fn new(cap: usize, cost_of: fn(&K, &V) -> usize) -> Self {
        Lru {
            map: HashMap::new(),
            order: BTreeMap::new(),
            clock: 0,
            bytes: 0,
            cap,
            cost_of,
        }
    }

    pub(super) fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k).map(|(v, _)| v)
    }

    /// Stores `v` under `k` as the most recently updated entry. Room is made
    /// by dropping the oldest entries until there are fewer than `cap` and
    /// the bytes stay within `byte_limit` (the new entry always goes in).
    pub(super) fn put(&mut self, k: K, v: V, budget: &mut Budget, byte_limit: usize) -> Put<K, V> {
        let cost = (self.cost_of)(&k, &v);
        let replaced = self.remove(&k, budget);
        let mut evicted = Vec::new();
        while self.map.len() >= self.cap.max(1)
            || (!self.map.is_empty() && self.bytes.saturating_add(cost) > byte_limit)
        {
            let Some((_, old)) = self.order.pop_first() else {
                break;
            };
            if let Some((ov, _)) = self.map.remove(&old) {
                let c = (self.cost_of)(&old, &ov);
                self.bytes = self.bytes.saturating_sub(c);
                budget.adjust(c, 0);
                evicted.push((old, ov));
            }
        }
        self.clock = self.clock.wrapping_add(1);
        self.order.insert(self.clock, k.clone());
        self.map.insert(k, (v, self.clock));
        self.bytes = self.bytes.saturating_add(cost);
        budget.adjust(0, cost);
        Put { replaced, evicted }
    }

    pub(super) fn remove(&mut self, k: &K, budget: &mut Budget) -> Option<V> {
        let (v, stamp) = self.map.remove(k)?;
        self.order.remove(&stamp);
        let c = (self.cost_of)(k, &v);
        self.bytes = self.bytes.saturating_sub(c);
        budget.adjust(c, 0);
        Some(v)
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        debug_assert_eq!(self.map.len(), self.order.len());
        self.map.len()
    }

    /// Bytes of entries, counted from scratch.
    pub(super) fn cost(&self) -> usize {
        self.map
            .iter()
            .map(|(k, (v, _))| (self.cost_of)(k, v))
            .sum()
    }
}
