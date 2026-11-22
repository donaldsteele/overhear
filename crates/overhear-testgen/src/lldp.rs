//! LLDP data unit builder for generated test data.

/// An LLDP data unit from `(type, value)` TLVs. Each length is computed from
/// the value; an End TLV is not appended.
pub fn lldp(tlvs: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut o = Vec::new();
    for (typ, value) in tlvs {
        let h = (u16::from(*typ) << 9) | (value.len() as u16 & 0x1ff);
        o.extend_from_slice(&h.to_be_bytes());
        o.extend_from_slice(value);
    }
    o
}
