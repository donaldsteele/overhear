//! Everything remembered about the network, under one memory budget.

pub mod bounded;
pub mod budget;
pub mod device;
pub mod table;

pub use bounded::Bounded;
pub use budget::Budget;
pub use device::Device;
pub use table::DeviceTable;

use crate::observe::{Observation, Segment, Ts};

pub const MAX_IPV4: usize = 16;
pub const MAX_IPV6: usize = 16;
pub const MAX_NAMES: usize = 16;
pub const MAX_SERVICES: usize = 64;
pub const MAX_MODELS: usize = 8;
pub const MAX_DETAILS: usize = 32;
pub const MAX_VLANS: usize = 16;
/// Longest string kept; longer ones are cut.
pub const MAX_STR: usize = 255;

pub struct Tracker {
    pub budget: Budget,
    pub table: DeviceTable,
}

impl Tracker {
    pub fn new(max_memory: usize) -> Self {
        Tracker {
            budget: Budget::new(max_memory),
            table: DeviceTable::new(),
        }
    }

    /// Applies the observations of one frame, then evicts the least recently
    /// heard devices until the budget holds (the last device always stays).
    pub fn apply(&mut self, seg: Segment, ts: Ts, obs: &[Observation]) {
        for o in obs {
            self.table.apply(seg, ts, o, &mut self.budget);
            while self.budget.over() && self.table.len() > 1 {
                if self.table.evict_lru(&mut self.budget, &|_| false).is_none() {
                    break;
                }
            }
        }
    }
}
