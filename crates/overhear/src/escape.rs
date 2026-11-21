//! Escaping of untrusted packet text before it reaches a terminal.

use std::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextKind {
    Utf8,
    Ascii,
}

pub const LINE_FIELD_MAX: usize = 64;

/// One source character: a decoded char or a byte that could not be decoded.
#[derive(Clone, Copy)]
enum Unit {
    Char(char),
    Byte(u8),
}

fn for_each_unit(bytes: &[u8], kind: TextKind, mut f: impl FnMut(Unit) -> bool) {
    match kind {
        TextKind::Ascii => {
            for &b in bytes {
                let u = if b < 0x80 {
                    Unit::Char(char::from(b))
                } else {
                    Unit::Byte(b)
                };
                if !f(u) {
                    return;
                }
            }
        }
        TextKind::Utf8 => {
            let mut rest = bytes;
            while !rest.is_empty() {
                let (valid, bad) = match std::str::from_utf8(rest) {
                    Ok(s) => (s, 0),
                    Err(e) => {
                        let (v, _) = rest.split_at(e.valid_up_to());
                        // `v` is valid UTF-8 by construction of valid_up_to.
                        (
                            std::str::from_utf8(v).unwrap_or(""),
                            e.error_len().unwrap_or(rest.len() - v.len()),
                        )
                    }
                };
                for c in valid.chars() {
                    if !f(Unit::Char(c)) {
                        return;
                    }
                }
                let (_, tail) = rest.split_at(valid.len());
                let (bad_bytes, after) = tail.split_at(bad.min(tail.len()));
                for &b in bad_bytes {
                    if !f(Unit::Byte(b)) {
                        return;
                    }
                }
                rest = after;
            }
        }
    }
}

fn is_cf(c: char) -> bool {
    matches!(u32::from(c),
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB
        | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        | 0xE0001 | 0xE0020..=0xE007F)
}

/// True for C0, DEL, C1, U+2028, U+2029 and the Unicode Cf characters.
pub fn needs_escape(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') || is_cf(c)
}

fn push_hex_byte(out: &mut String, b: u8) {
    let _ = write!(out, "\\x{b:02x}");
}

/// Appends `bytes` to `out` with everything unsafe for a terminal escaped.
/// At most `max_chars` source characters are written; longer input is cut to
/// `max_chars - 1` characters followed by `…`.
pub fn push_text(out: &mut String, bytes: &[u8], kind: TextKind, max_chars: usize) {
    let mut total = 0usize;
    for_each_unit(bytes, kind, |_| {
        total = total.saturating_add(1);
        true
    });
    let truncated = total > max_chars;
    let keep = if truncated {
        max_chars.saturating_sub(1)
    } else {
        total
    };

    let mut n = 0usize;
    for_each_unit(bytes, kind, |u| {
        if n >= keep {
            return false;
        }
        n += 1;
        match u {
            Unit::Byte(b) => push_hex_byte(out, b),
            Unit::Char('\\') => out.push_str("\\\\"),
            Unit::Char(c) if c.is_ascii() && needs_escape(c) => push_hex_byte(out, c as u8),
            Unit::Char(c) if needs_escape(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            Unit::Char(c) => out.push(c),
        }
        true
    });
    if truncated {
        out.push('…');
    }
}

/// Whether `bytes` can be emitted verbatim as a JSON string value.
pub fn is_json_text(bytes: &[u8], kind: TextKind) -> bool {
    match kind {
        TextKind::Utf8 => std::str::from_utf8(bytes).is_ok(),
        TextKind::Ascii => bytes.iter().all(|b| (0x20..=0x7e).contains(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(b: &[u8], k: TextKind, max: usize) -> String {
        let mut s = String::new();
        push_text(&mut s, b, k, max);
        s
    }
    const M: usize = usize::MAX;

    #[test]
    fn escapes_terminal_controls() {
        assert_eq!(t(b"a\x1b[31mb\x7f", TextKind::Utf8, M), "a\\x1b[31mb\\x7f");
    }
    #[test]
    fn keeps_unicode_letters() {
        assert_eq!(
            t("Bjørn's iPhone".as_bytes(), TextKind::Utf8, M),
            "Bjørn's iPhone"
        );
    }
    #[test]
    fn escapes_bidi_and_zero_width() {
        assert_eq!(
            t("abc\u{202e}def\u{200b}".as_bytes(), TextKind::Utf8, M),
            "abc\\u{202e}def\\u{200b}"
        );
    }
    #[test]
    fn escapes_c1_and_line_separator() {
        assert_eq!(
            t("\u{85}x\u{2028}".as_bytes(), TextKind::Utf8, M),
            "\\u{85}x\\u{2028}"
        );
    }
    #[test]
    fn escapes_invalid_utf8() {
        assert_eq!(t(b"ok\xff\xfe", TextKind::Utf8, M), "ok\\xff\\xfe");
    }
    #[test]
    fn escapes_backslash() {
        assert_eq!(t(b"a\\b", TextKind::Utf8, M), "a\\\\b");
    }
    #[test]
    fn ascii_kind_escapes_high_bytes() {
        assert_eq!(t("café".as_bytes(), TextKind::Ascii, M), "caf\\xc3\\xa9");
    }
    #[test]
    fn truncates_with_ellipsis() {
        assert_eq!(
            t(&[b'a'; 100], TextKind::Utf8, 64),
            format!("{}…", "a".repeat(63))
        );
        assert_eq!(t(&[b'a'; 64], TextKind::Utf8, 64), "a".repeat(64));
    }
    #[test]
    fn json_text_rules() {
        assert!(!is_json_text(b"a\xff", TextKind::Utf8));
        assert!(is_json_text("é".as_bytes(), TextKind::Utf8));
        assert!(!is_json_text("é".as_bytes(), TextKind::Ascii));
        assert!(is_json_text(b"ok ~", TextKind::Ascii));
    }
    #[test]
    fn valid_utf8_after_invalid_still_decodes() {
        assert_eq!(
            t(b"a\xffb\xc3\xa9\xe2\x82", TextKind::Utf8, M),
            "a\\xffbé\\xe2\\x82"
        );
    }
    #[test]
    fn truncation_counts_invalid_byte_as_one_char() {
        assert_eq!(t(b"\xff\xffabc", TextKind::Utf8, 3), "\\xff\\xff…");
    }
    #[test]
    fn cf_set_edges() {
        for c in [
            '\u{ad}',
            '\u{110bd}',
            '\u{e0020}',
            '\u{e007f}',
            '\u{206f}',
            '\u{fffb}',
        ] {
            assert!(needs_escape(c), "{c:?}");
        }
        for c in ['\u{ae}', '\u{e0000}', '\u{e0080}', '\u{2065}', 'a', 'é'] {
            assert!(!needs_escape(c), "{c:?}");
        }
    }
}
