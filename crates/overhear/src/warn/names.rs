//! Suspicious name answers: one name answered by two hosts, and one host
//! answering for many names.

use std::mem::size_of;

use overhear_decode::Mac;

use super::index::Index;
use super::lru::Lru;
use super::{OVERHEAD, Output, Rule, Severity, Warning};
use crate::escape::{TextKind, push_text};
use crate::observe::{AnswerKind, Observation, Segment, Ts};
use crate::track::{Budget, MAX_STR};

/// Seconds an answer or a name counts for.
const WINDOW: i64 = 300;
/// Distinct names that make a pattern.
const POISON_NAMES: usize = 3;

/// Segment, kind and lowercased name.
pub(super) type AnswerKey = (Segment, AnswerKind, Vec<u8>);
type HostKey = (Segment, Mac);
/// Who answered, a hash of what they said, and when (seconds).
type Answer = (Mac, u64, i64);
/// Names answered recently, oldest first.
type NameSet = Vec<(Vec<u8>, i64)>;

fn answer_cost(k: &AnswerKey, _: &Answer) -> usize {
    size_of::<(AnswerKey, (Answer, u64))>()
        + size_of::<(u64, AnswerKey)>()
        + 2 * OVERHEAD
        + 2 * k.2.len()
}

fn host_cost(_: &HostKey, v: &NameSet) -> usize {
    size_of::<(HostKey, (NameSet, u64))>()
        + size_of::<(u64, HostKey)>()
        + 2 * OVERHEAD
        + v.len() * size_of::<(Vec<u8>, i64)>()
        + v.iter().map(|(n, _)| n.len()).sum::<usize>()
}

pub(super) struct Names {
    pub(super) answers: Lru<AnswerKey, Answer>,
    pub(super) hosts: Lru<HostKey, NameSet>,
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn escaped(bytes: &[u8]) -> String {
    let mut s = String::new();
    push_text(&mut s, bytes, TextKind::Utf8, usize::MAX);
    s
}

impl Names {
    pub(super) fn new(answer_cap: usize, host_cap: usize) -> Self {
        Names {
            answers: Lru::new(answer_cap, answer_cost),
            hosts: Lru::new(host_cap, host_cost),
        }
    }

    /// Checks one answer against what other hosts said for the name, and
    /// against what this host has been answering.
    pub(super) fn answer(
        &mut self,
        index: &mut Index,
        seg: Segment,
        ts: Ts,
        obs: &Observation,
        budget: &mut Budget,
    ) -> [Option<Output>; 2] {
        let Observation::NameAnswer {
            mac,
            kind,
            name,
            data,
        } = obs
        else {
            return [None, None];
        };
        let (mac, kind) = (*mac, *kind);
        let lower: Vec<u8> = name
            .iter()
            .take(MAX_STR)
            .map(u8::to_ascii_lowercase)
            .collect();
        let hash = fnv1a(data);
        let limit = budget.limit() / super::SHARE;
        let key: AnswerKey = (seg, kind, lower);

        let two = self
            .answers
            .get(&key)
            .copied()
            .filter(|(m, h, t)| *m != mac && *h != hash && ts.sec.saturating_sub(*t) <= WINDOW)
            .map(|(old, _, _)| {
                let shown = escaped(&key.2);
                Output::Warning(Warning {
                    ts,
                    rule: Rule::SuspiciousNameAnswers,
                    severity: Severity::Low,
                    segment: Some(seg),
                    message: format!("name {shown} answered by {mac} and {old}"),
                    subject: shown,
                    macs: vec![mac, old],
                    addrs: vec![],
                    count: 1,
                })
            });
        let put = self
            .answers
            .put(key.clone(), (mac, hash, ts.sec), budget, limit);
        for (k, (m, _, _)) in put.evicted {
            index.remove_answer(m, &k, budget);
        }
        if let Some((old, _, _)) = put.replaced.filter(|(old, _, _)| *old != mac) {
            index.remove_answer(old, &key, budget);
        }
        index.add_answer(mac, &key, budget);

        let label = match kind {
            AnswerKind::Llmnr => "LLMNR",
            AnswerKind::Netbios => "NetBIOS",
            AnswerKind::MdnsUnique => return [two, None],
        };
        let pattern = self.note_name(index, (seg, mac), key.2, ts, label, budget);
        [two, pattern]
    }

    /// Adds `name` to the names `mac` answered recently; warns when that
    /// makes [`POISON_NAMES`] of them.
    fn note_name(
        &mut self,
        index: &mut Index,
        hk: HostKey,
        name: Vec<u8>,
        ts: Ts,
        label: &str,
        budget: &mut Budget,
    ) -> Option<Output> {
        let (seg, mac) = hk;
        let limit = budget.limit() / super::SHARE;
        let mut set = self.hosts.remove(&hk, budget).unwrap_or_default();
        set.retain(|(_, t)| ts.sec.saturating_sub(*t) <= WINDOW);
        let known = set.iter().position(|(n, _)| *n == name);
        if let Some(i) = known {
            set.remove(i);
        } else if set.len() >= POISON_NAMES {
            set.remove(0);
        }
        set.push((name, ts.sec));
        let warning = (known.is_none() && set.len() == POISON_NAMES).then(|| {
            let list = set
                .iter()
                .map(|(n, _)| escaped(n))
                .collect::<Vec<_>>()
                .join(", ");
            Output::Warning(Warning {
                ts,
                rule: Rule::SuspiciousNameAnswers,
                severity: Severity::High,
                segment: Some(seg),
                subject: mac.to_string(),
                message: format!(
                    "{mac} answers {label} queries for many names ({list}): \
                     the pattern of poisoning tools such as Responder"
                ),
                macs: vec![mac],
                addrs: vec![],
                count: 1,
            })
        });
        let put = self.hosts.put(hk, set, budget, limit);
        for ((s, m), _) in put.evicted {
            index.remove_host(m, s, budget);
        }
        index.add_host(mac, seg, budget);
        warning
    }
}
