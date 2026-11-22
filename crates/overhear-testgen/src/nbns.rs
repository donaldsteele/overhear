//! NetBIOS name service message builder for generated test data.

/// A first-level encoded NetBIOS name: length 0x20, 32 characters, root.
/// The name is upper-cased by the caller if wanted; it is space-padded to
/// 15 bytes and followed by `suffix`.
pub fn nb_encode(name: &str, suffix: u8) -> Vec<u8> {
    let mut raw: Vec<u8> = name.bytes().take(15).collect();
    raw.resize(15, b' ');
    raw.push(suffix);
    let mut o = vec![0x20];
    for b in raw {
        o.push(b'A' + (b >> 4));
        o.push(b'A' + (b & 0x0f));
    }
    o.push(0);
    o
}

/// A NetBIOS name service message. Names are wire bytes (see [`nb_encode`]),
/// so callers can pass pointers or malformed names. Questions have class IN;
/// the answers are `(name, type, ttl, rdata)` records of class IN.
pub fn nbns(
    id: u16,
    flags: u16,
    questions: &[(Vec<u8>, u16)],
    answers: &[(Vec<u8>, u16, u32, Vec<u8>)],
) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&id.to_be_bytes());
    o.extend_from_slice(&flags.to_be_bytes());
    o.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    o.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    o.extend_from_slice(&[0; 4]);
    for (name, qtype) in questions {
        o.extend_from_slice(name);
        o.extend_from_slice(&qtype.to_be_bytes());
        o.extend_from_slice(&1u16.to_be_bytes());
    }
    for (name, rtype, ttl, rdata) in answers {
        o.extend_from_slice(name);
        o.extend_from_slice(&rtype.to_be_bytes());
        o.extend_from_slice(&1u16.to_be_bytes());
        o.extend_from_slice(&ttl.to_be_bytes());
        o.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        o.extend_from_slice(rdata);
    }
    o
}
