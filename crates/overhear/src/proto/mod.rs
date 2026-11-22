//! Per-protocol presentation. Protocol tasks add match arms here.

pub mod other;

use overhear_decode::{Packet, Proto};

use crate::json::JsonWriter;
use crate::observe::Observation;

/// Short tag shown in the second column; at most 5 characters.
pub fn tag(p: &Packet<'_>) -> &'static str {
    match &p.proto {
        Proto::Other { .. } => other::tag(p),
    }
}

/// Appends the escaped summary text (no time, tag or source).
pub fn summary(p: &Packet<'_>, out: &mut String) {
    match &p.proto {
        Proto::Other { payload } => other::summary(p, payload.len(), out),
    }
}

/// Appends the protocol's verbose lines, each `"  {LABEL:<6}{text}\n"`.
pub fn verbose(p: &Packet<'_>, frame: &[u8], out: &mut String) {
    match &p.proto {
        Proto::Other { payload } => other::verbose(payload.len(), frame, out),
    }
}

/// Key of the protocol object written by [`json`].
pub fn json_name(p: &Packet<'_>) -> &'static str {
    match &p.proto {
        Proto::Other { .. } => "other",
    }
}

/// Writes the protocol object under the key [`json_name`].
pub fn json(p: &Packet<'_>, w: &mut JsonWriter) {
    match &p.proto {
        Proto::Other { payload } => other::json(p, payload.len(), w),
    }
}

/// Appends the facts the packet reveals. `Heard` always comes first.
pub fn observe<'a>(p: &Packet<'a>, out: &mut Vec<Observation<'a>>) {
    match &p.proto {
        Proto::Other { .. } => other::observe(p, out),
    }
}
