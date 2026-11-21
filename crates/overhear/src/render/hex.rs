//! Classic hex dump used by `-H`.

use std::fmt::Write;

/// Appends 16 bytes per line: offset, hex bytes, ASCII gutter.
pub fn hex_dump(bytes: &[u8], out: &mut String) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(out, "  {:04x}  ", i.saturating_mul(16));
        for n in 0..16 {
            match chunk.get(n) {
                Some(b) => {
                    let _ = write!(out, "{b:02x}");
                }
                None => out.push_str("  "),
            }
            if n < 15 {
                out.push(' ');
            }
        }
        out.push_str("  |");
        out.extend(chunk.iter().map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                char::from(b)
            } else {
                '.'
            }
        }));
        out.push_str("|\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_dump_format() {
        let bytes: Vec<u8> = (0..20).collect();
        let mut out = String::new();
        hex_dump(&bytes, &mut out);
        assert_eq!(
            out,
            "  0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  |................|\n  0010  10 11 12 13                                      |....|\n"
        );
    }
}
