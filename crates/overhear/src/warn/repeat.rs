//! Repeat limiting: the first occurrence of a warning is reported at once,
//! later ones are counted and summarised at most once a minute per key.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::net::IpAddr;

use overhear_decode::Mac;

use super::{OVERHEAD, Output, Rule, Warning};
use crate::observe::{Segment, Ts};
use crate::track::Budget;

/// Seconds between reports of one key.
const WINDOW: i64 = 60;
/// Seconds after which a quiet key is forgotten.
const IDLE: i64 = 600;

type Key = (Rule, Option<Segment>, String);

struct Entry {
    last_report: i64,
    last_seen: i64,
    /// Occurrences since the last report.
    pending: u32,
    /// The newest of the pending occurrences.
    latest: Option<Warning>,
}

fn warning_heap(w: &Warning) -> usize {
    w.subject.len()
        + w.message.len()
        + w.macs.len() * size_of::<Mac>()
        + w.addrs.len() * size_of::<IpAddr>()
}

fn entry_cost(key: &Key, e: &Entry) -> usize {
    size_of::<Key>()
        + size_of::<Entry>()
        + OVERHEAD
        + key.2.len()
        + e.latest.as_ref().map_or(0, warning_heap)
}

/// Seconds from `then` to `now`; 0 when time went backwards.
fn elapsed(now: i64, then: i64) -> i64 {
    now.saturating_sub(then).max(0)
}

pub(super) struct Repeats {
    /// Ordered, so summaries due at the same tick come out in a fixed order.
    keys: BTreeMap<Key, Entry>,
}

impl Repeats {
    pub(super) fn new() -> Self {
        Repeats {
            keys: BTreeMap::new(),
        }
    }

    /// Outputs `w` unless its key was reported less than a minute ago; then
    /// it is counted for the next summary.
    pub(super) fn report(&mut self, w: Warning, budget: &mut Budget, out: &mut Vec<Output>) {
        let now = w.ts.sec;
        let key = (w.rule, w.segment, w.subject.clone());
        let Some(e) = self.keys.get_mut(&key) else {
            let e = Entry {
                last_report: now,
                last_seen: now,
                pending: 0,
                latest: None,
            };
            budget.adjust(0, entry_cost(&key, &e));
            self.keys.insert(key, e);
            out.push(Output::Warning(w));
            return;
        };
        let before = entry_cost(&key, e);
        e.last_seen = now;
        if elapsed(now, e.last_report) < WINDOW {
            e.pending = e.pending.saturating_add(1);
            e.latest = Some(w);
            budget.adjust(before, entry_cost(&key, e));
            return;
        }
        // Quiet for a minute (or no tick since): report at once, with
        // anything still pending.
        let count = e.pending.saturating_add(1);
        e.pending = 0;
        e.latest = None;
        e.last_report = now;
        budget.adjust(before, entry_cost(&key, e));
        out.push(Output::Warning(Warning { count, ..w }));
    }

    /// Outputs the summaries that are due and forgets keys quiet for
    /// [`IDLE`] seconds.
    pub(super) fn tick(&mut self, now: Ts, budget: &mut Budget, out: &mut Vec<Output>) {
        self.keys.retain(|key, e| {
            let before = entry_cost(key, e);
            if e.pending > 0 && elapsed(now.sec, e.last_report) >= WINDOW {
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
            budget.adjust(before, if keep { entry_cost(key, e) } else { 0 });
            keep
        });
    }

    pub(super) fn cost(&self) -> usize {
        self.keys.iter().map(|(k, e)| entry_cost(k, e)).sum()
    }
}
