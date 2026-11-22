//! CDP data unit builder for generated test data.

/// A CDP version 2 data unit (TTL 180, checksum 0) from `(type, value)`
/// TLVs. Each length is the value length plus the 4-byte TLV header.
pub fn cdp(tlvs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut o = vec![2, 180, 0, 0];
    for (typ, value) in tlvs {
        o.extend_from_slice(&typ.to_be_bytes());
        o.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
        o.extend_from_slice(value);
    }
    o
}
