//! STP / RSTP / MSTP BPDU builder for generated test data.

fn bridge_id(prio: u16, mac: [u8; 6]) -> Vec<u8> {
    let mut o = prio.to_be_bytes().to_vec();
    o.extend_from_slice(&mac);
    o
}

/// A BPDU (the LLC payload). `bpdu_type` 0x80 gives a 4-byte TCN; any other
/// type gets the 35-byte configuration part with timers of 0, 20, 2 and 15
/// seconds. Version 2 and up add the version 1 length byte; version 3 adds an
/// MSTP section with `mstis` zeroed 16-byte MSTI records.
#[allow(clippy::too_many_arguments)]
pub fn bpdu(
    version: u8,
    bpdu_type: u8,
    flags: u8,
    root: (u16, [u8; 6]),
    cost: u32,
    bridge: (u16, [u8; 6]),
    port: u16,
    mstis: u8,
) -> Vec<u8> {
    let mut o = vec![0, 0, version, bpdu_type];
    if bpdu_type == 0x80 {
        return o;
    }
    o.push(flags);
    o.extend_from_slice(&bridge_id(root.0, root.1));
    o.extend_from_slice(&cost.to_be_bytes());
    o.extend_from_slice(&bridge_id(bridge.0, bridge.1));
    o.extend_from_slice(&port.to_be_bytes());
    for secs in [0u16, 20, 2, 15] {
        o.extend_from_slice(&(secs * 256).to_be_bytes());
    }
    if version >= 2 {
        o.push(0);
    }
    if version >= 3 {
        let len = 64 + 16 * u16::from(mstis);
        o.extend_from_slice(&len.to_be_bytes());
        o.extend(std::iter::repeat_n(0u8, usize::from(len)));
    }
    o
}
