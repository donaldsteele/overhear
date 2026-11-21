//! Streaming JSON writer. Output stays valid JSON whatever bytes a packet holds.

use crate::escape::{TextKind, is_json_text, needs_escape};
use overhear_decode::Mac;
use std::fmt::Write;
use std::net::IpAddr;

const MAX_DEPTH: usize = 16;

/// Builds one JSON value into an internal string.
#[derive(Debug, Default)]
pub struct JsonWriter {
    buf: String,
    /// One flag per open container: true once it holds a value.
    needs_comma: Vec<bool>,
    closers: Vec<char>,
}

impl JsonWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.needs_comma.clear();
        self.closers.clear();
    }

    pub fn as_str(&self) -> &str {
        &self.buf
    }

    fn begin(&mut self, key: Option<&str>) {
        if let Some(flag) = self.needs_comma.last_mut() {
            if *flag {
                self.buf.push(',');
            }
            *flag = true;
        }
        if let Some(k) = key {
            self.push_string(k);
            self.buf.push(':');
        }
    }

    fn open(&mut self, key: Option<&str>, ch: char) {
        self.begin(key);
        self.buf.push(ch);
        debug_assert!(self.needs_comma.len() < MAX_DEPTH, "json nesting too deep");
        self.needs_comma.push(false);
        self.closers.push(if ch == '{' { '}' } else { ']' });
    }

    pub fn obj(&mut self, key: Option<&str>) {
        self.open(key, '{');
    }

    pub fn arr(&mut self, key: Option<&str>) {
        self.open(key, '[');
    }

    /// Closes the innermost open object or array.
    pub fn end(&mut self) {
        debug_assert!(!self.needs_comma.is_empty(), "end() with nothing open");
        self.needs_comma.pop();
        let close = self.closers.pop().unwrap_or('}');
        self.buf.push(close);
    }

    fn push_string(&mut self, s: &str) {
        self.buf.push('"');
        for c in s.chars() {
            match c {
                '"' => self.buf.push_str("\\\""),
                '\\' => self.buf.push_str("\\\\"),
                '\n' => self.buf.push_str("\\n"),
                '\r' => self.buf.push_str("\\r"),
                '\t' => self.buf.push_str("\\t"),
                c if needs_escape(c) => {
                    let mut units = [0u16; 2];
                    for u in c.encode_utf16(&mut units) {
                        let _ = write!(self.buf, "\\u{u:04x}");
                    }
                }
                c => self.buf.push(c),
            }
        }
        self.buf.push('"');
    }

    fn push_hex(&mut self, bytes: &[u8]) {
        self.buf.push('"');
        for b in bytes {
            let _ = write!(self.buf, "{b:02x}");
        }
        self.buf.push('"');
    }

    pub fn str(&mut self, key: Option<&str>, v: &str) {
        self.begin(key);
        self.push_string(v);
    }

    /// `"key":"text"`, or `"key_hex":"…"` when the bytes are not JSON text.
    pub fn text(&mut self, key: &str, bytes: &[u8], kind: TextKind) {
        if is_json_text(bytes, kind) {
            self.begin(Some(key));
            self.push_string(&String::from_utf8_lossy(bytes));
        } else {
            let mut k = String::with_capacity(key.len().saturating_add(4));
            k.push_str(key);
            k.push_str("_hex");
            self.begin(Some(&k));
            self.push_hex(bytes);
        }
    }

    /// `"text"` as an array element, or `{"hex":"…"}` when not JSON text.
    pub fn text_elem(&mut self, bytes: &[u8], kind: TextKind) {
        if is_json_text(bytes, kind) {
            self.begin(None);
            self.push_string(&String::from_utf8_lossy(bytes));
        } else {
            self.obj(None);
            self.hex(Some("hex"), bytes);
            self.end();
        }
    }

    pub fn hex(&mut self, key: Option<&str>, bytes: &[u8]) {
        self.begin(key);
        self.push_hex(bytes);
    }

    pub fn u64(&mut self, key: Option<&str>, v: u64) {
        self.begin(key);
        let _ = write!(self.buf, "{v}");
    }

    pub fn i64(&mut self, key: Option<&str>, v: i64) {
        self.begin(key);
        let _ = write!(self.buf, "{v}");
    }

    pub fn bool(&mut self, key: Option<&str>, v: bool) {
        self.begin(key);
        self.buf.push_str(if v { "true" } else { "false" });
    }

    pub fn null(&mut self, key: Option<&str>) {
        self.begin(key);
        self.buf.push_str("null");
    }

    /// Writes `v` verbatim; the caller guarantees it is a valid JSON number.
    pub fn raw_number(&mut self, key: Option<&str>, v: &str) {
        self.begin(key);
        self.buf.push_str(v);
    }

    pub fn ip(&mut self, key: Option<&str>, v: IpAddr) {
        self.begin(key);
        let _ = write!(self.buf, "\"{v}\"");
    }

    pub fn mac(&mut self, key: Option<&str>, v: Mac) {
        self.begin(key);
        let _ = write!(self.buf, "\"{v}\"");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escape::TextKind;
    use overhear_decode::Mac;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn nested_values() {
        let mut w = JsonWriter::new();
        w.obj(None);
        w.u64(Some("a"), 1);
        w.arr(Some("b"));
        w.bool(None, true);
        w.null(None);
        w.str(None, "x");
        w.end();
        w.obj(Some("c"));
        w.end();
        w.end();
        assert_eq!(w.as_str(), r#"{"a":1,"b":[true,null,"x"],"c":{}}"#);
    }

    #[test]
    fn escapes() {
        let mut w = JsonWriter::new();
        w.obj(None);
        w.str(Some("k"), "q\"\\\n\u{1b}\u{7f}\u{202e}é");
        w.end();
        assert_eq!(w.as_str(), r#"{"k":"q\"\\\n\u001b\u007f\u202eé"}"#);
    }

    #[test]
    fn astral_format_char_uses_surrogates() {
        let mut w = JsonWriter::new();
        w.str(None, "\u{E0001}");
        assert_eq!(w.as_str(), r#""\udb40\udc01""#);
    }

    #[test]
    fn text_falls_back_to_hex() {
        let mut w = JsonWriter::new();
        w.obj(None);
        w.text("name", b"a\xff", TextKind::Utf8);
        w.text("nb", "café".as_bytes(), TextKind::Ascii);
        w.arr(Some("l"));
        w.text_elem(b"\xff", TextKind::Utf8);
        w.end();
        w.end();
        assert_eq!(
            w.as_str(),
            r#"{"name_hex":"61ff","nb_hex":"636166c3a9","l":[{"hex":"ff"}]}"#
        );
    }

    #[test]
    fn every_method_produces_valid_json() {
        let mut w = JsonWriter::new();
        w.obj(None);
        w.str(Some("s"), "v");
        w.text("t", b"ok", TextKind::Utf8);
        w.hex(Some("h"), &[1, 2, 255]);
        w.u64(Some("u"), u64::MAX);
        w.i64(Some("i"), -5);
        w.bool(Some("b"), false);
        w.null(Some("n"));
        w.raw_number(Some("ts"), "1795266131.204123");
        w.ip(Some("v4"), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        w.ip(Some("v6"), IpAddr::V6(Ipv6Addr::LOCALHOST));
        w.mac(Some("m"), Mac([2, 0, 0x5e, 0x10, 0, 0x14]));
        w.arr(Some("l"));
        w.text_elem(b"a\"b", TextKind::Ascii);
        w.hex(None, &[]);
        w.end();
        w.end();
        let v: serde_json::Value = serde_json::from_str(w.as_str()).unwrap();
        assert_eq!(v["m"], "02:00:5e:10:00:14");
        assert_eq!(v["v4"], "10.0.0.1");
        assert_eq!(v["v6"], "::1");
        assert_eq!(v["l"][0], "a\"b");
        w.clear();
        assert_eq!(w.as_str(), "");
    }
}
