//! A big capture for the speed test: every scenario's frames in turn, from 500 devices.

use crate::TFrame;
use crate::scenarios::scenarios;

/// `n` frames taken round-robin from every scenario, with the source MAC's low two
/// bytes set to the frame number modulo 500.
pub fn perfgen(n: u64) -> impl Iterator<Item = TFrame> {
    let all: Vec<TFrame> = scenarios().into_iter().flat_map(|(_, f)| f).collect();
    (0..n).map(move |i| {
        let mut f = all[(i % all.len() as u64) as usize].clone();
        let dev = (i % 500) as u16;
        if let Some(mac) = f.data.get_mut(10..12) {
            mac.copy_from_slice(&dev.to_be_bytes());
        }
        f.sec = 1_700_000_000 + (i / 1000) as i64;
        f.usec = ((i % 1000) * 1000) as u32;
        f
    })
}
