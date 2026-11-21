//! Ethernet frame builders for generated test data.

pub const BCAST: [u8; 6] = [0xff; 6];

/// `02:00:5e:10:00:nn`
pub fn mac(n: u8) -> [u8; 6] {
    [0x02, 0x00, 0x5e, 0x10, 0x00, n]
}

fn pad60(mut f: Vec<u8>) -> Vec<u8> {
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

fn header(dst: [u8; 6], src: [u8; 6]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f
}

/// Ethernet II frame, padded to 60 bytes.
pub fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    eth_vlan(dst, src, &[], ethertype, payload)
}

/// Ethernet II frame with VLAN tags `(tpid, id)`, outer first.
pub fn eth_vlan(
    dst: [u8; 6],
    src: [u8; 6],
    tags: &[(u16, u16)],
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut f = header(dst, src);
    for &(tpid, id) in tags {
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&(id & 0x0fff).to_be_bytes());
    }
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    pad60(f)
}

fn dot3(dst: [u8; 6], src: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut f = header(dst, src);
    f.extend_from_slice(&(body.len() as u16).to_be_bytes());
    f.extend_from_slice(body);
    pad60(f)
}

/// 802.3 frame with an LLC header, padded to 60 bytes.
pub fn llc(dst: [u8; 6], src: [u8; 6], dsap: u8, ssap: u8, ctrl: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![dsap, ssap, ctrl];
    body.extend_from_slice(payload);
    dot3(dst, src, &body)
}

/// 802.3 frame with LLC `AA AA 03` and a SNAP header, padded to 60 bytes.
pub fn snap(dst: [u8; 6], src: [u8; 6], oui: [u8; 3], pid: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![0xaa, 0xaa, 0x03];
    body.extend_from_slice(&oui);
    body.extend_from_slice(&pid.to_be_bytes());
    body.extend_from_slice(payload);
    dot3(dst, src, &body)
}
