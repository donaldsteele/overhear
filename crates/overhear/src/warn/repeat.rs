//! Repeat limiting: the first occurrence of a warning is reported at once,
//! later ones are counted and summarised at most once a minute per key.
//! Subjects can be chosen by whoever sends the packets, so at most
//! [`MAX_REPEAT_KEYS`] keys are kept: a new key then replaces the least
//! recently seen one with nothing pending, or failing that the least recently
//! seen one.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::net::IpAddr;

use overhear_decode::Mac;

use super::{MAX_REPEAT_KEYS, OVERHEAD, Output, Rule, Severity, Warning};
use crate::observe::{Segment, Ts};
use crate::track::Budget;

/// Seconds between reports of one key.
const WINDOW: i64 = 60;
/// Seconds after which a quiet key is forgotten.
const IDLE: i64 = 600;

type Key = (Rule, Severity, Option<Segment>, String);

/// Replacement order: keys with nothing pending first, then by last use.
type Age = (bool, u64);

struct Entry {
    /// When the key was last seen, in arrival order.
    stamp: u64,
    last_report: i64,
    last_seen: i64,
    /// Occurrences since the last report.
    pending: u32,
    /// The newest of the pending occurrences.
    latest: Option<Warning>,
}

impl Entry {
    fn age(&self) -> Age {
        (self.pending > 0, self.stamp)
    }
}

fn warning_heap(w: &Warning) -> usize {
    w.subject.len()
        + w.message.len()
        + w.macs.len() * size_of::<Mac>()
        + w.addrs.len() * size_of::<IpAddr>()
}

/// The entry in both maps, with the subject stored twice.
fn entry_cost(key: &Key, e: &Entry) -> usize {
    size_of::<(Key, Entry)>()
        + size_of::<(Age, Key)>()
        + 2 * OVERHEAD
        + 2 * key.3.len()
        + e.latest.as_ref().map_or(0, warning_heap)
}

/// Seconds from `then` to `now`; 0 when time went backwards.
fn elapsed(now: i64, then: i64) -> i64 {
    now.saturating_sub(then).max(0)
}

pub(super) struct Repeats {
    /// Ordered, so summaries due at the same tick come out in a fixed order.
    keys: BTreeMap<Key, Entry>,
    /// Every key by [`Age`], the next to replace first.
    order: BTreeMap<Age, Key>,
    clock: u64,
    /// Sum of the entry costs.
    bytes: usize,
}

impl Repeats {
    pub(super) fn new() -> Self {
        Repeats {
            keys: BTreeMap::new(),
            order: BTreeMap::new(),
            clock: 0,
            bytes: 0,
        }
    }

    /// Outputs `w` unless its key was reported less than a minute ago; then
    /// it is counted for the next summary.
    pub(super) fn report(&mut self, w: Warning, budget: &mut Budget, out: &mut Vec<Output>) {
        let now = w.ts.sec;
        self.clock = self.clock.wrapping_add(1);
        let stamp = self.clock;
        let key = (w.rule, w.severity, w.segment, w.subject.clone());
        let Some(e) = self.keys.get_mut(&key) else {
            let e = Entry {
                stamp,
                last_report: now,
                last_seen: now,
                pending: 0,
                latest: None,
            };
            let cost = entry_cost(&key, &e);
            let share = budget.limit() / super::SHARE;
            while !self.keys.is_empty()
                && (self.keys.len() >= MAX_REPEAT_KEYS || self.bytes.saturating_add(cost) > share)
            {
                self.replace_oldest(budget);
            }
            self.bytes = self.bytes.saturating_add(cost);
            budget.adjust(0, cost);
            self.order.insert(e.age(), key.clone());
            self.keys.insert(key, e);
            out.push(Output::Warning(w));
            return;
        };
        let before = entry_cost(&key, e);
        self.order.remove(&e.age());
        e.stamp = stamp;
        e.last_seen = now;
        if elapsed(now, e.last_report) < WINDOW {
            e.pending = e.pending.saturating_add(1);
            e.latest = Some(w);
        } else {
            // Quiet for a minute (or no tick since): report at once, with
            // anything still pending.
            let count = e.pending.saturating_add(1);
            e.pending = 0;
            e.latest = None;
            e.last_report = now;
            out.push(Output::Warning(Warning { count, ..w }));
        }
        let after = entry_cost(&key, e);
        self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
        budget.adjust(before, after);
        self.order.insert(e.age(), key);
    }

    fn replace_oldest(&mut self, budget: &mut Budget) {
        let Some((_, key)) = self.order.pop_first() else {
            return;
        };
        if let Some(e) = self.keys.remove(&key) {
            let c = entry_cost(&key, &e);
            self.bytes = self.bytes.saturating_sub(c);
            budget.adjust(c, 0);
        }
    }

    /// Outputs the summaries that are due and forgets keys quiet for
    /// [`IDLE`] seconds.
    pub(super) fn tick(&mut self, now: Ts, budget: &mut Budget, out: &mut Vec<Output>) {
        self.sweep(now, false, budget, out);
    }

    /// Outputs every pending summary, due or not.
    pub(super) fn flush(&mut self, now: Ts, budget: &mut Budget, out: &mut Vec<Output>) {
        self.sweep(now, true, budget, out);
    }

    fn sweep(&mut self, now: Ts, all: bool, budget: &mut Budget, out: &mut Vec<Output>) {
        let order = &mut self.order;
        let mut bytes = self.bytes;
        self.keys.retain(|key, e| {
            let before = entry_cost(key, e);
            let age = e.age();
            if e.pending > 0 && (all || elapsed(now.sec, e.last_report) >= WINDOW) {
                if let Some(latest) = e.latest.take() {
                    out.push(Output::Warning(Warning {
                        ts: now,
                        count: e.pending,
                        ..latest
                    }));
                }
                e.pending = 0;
                e.last_report = now.sec;
            }
            let keep = e.pending > 0 || elapsed(now.sec, e.last_seen) < IDLE;
            if !keep || e.age() != age {
                order.remove(&age);
            }
            if keep && e.age() != age {
                order.insert(e.age(), key.clone());
            }
            let after = if keep { entry_cost(key, e) } else { 0 };
            bytes = bytes.saturating_sub(before).saturating_add(after);
            budget.adjust(before, after);
            keep
        });
        self.bytes = bytes;
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        debug_assert_eq!(self.keys.len(), self.order.len());
        self.keys.len()
    }

    pub(super) fn cost(&self) -> usize {
        self.keys.iter().map(|(k, e)| entry_cost(k, e)).sum()
    }
}
