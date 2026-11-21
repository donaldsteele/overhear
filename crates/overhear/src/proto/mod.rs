//! Per-protocol presentation. Protocol tasks add match arms here.

pub mod other;

use overhear_decode::{Packet, Proto};

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
