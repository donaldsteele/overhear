//! SSDP message builder for generated test data.

/// An SSDP message: the start line and header lines, each ended by CRLF,
/// then the blank line.
pub fn ssdp(start: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(start.as_bytes());
    o.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        o.extend_from_slice(name.as_bytes());
        o.extend_from_slice(b": ");
        o.extend_from_slice(value.as_bytes());
        o.extend_from_slice(b"\r\n");
    }
    o.extend_from_slice(b"\r\n");
    o
}
