//! SSDP (HTTP over UDP, UPnP discovery) decoder.

use crate::{Cursor, Layer, Problem};

/// The longest line accepted, terminator excluded.
pub const MAX_LINE: usize = 1024;
/// The most headers kept.
pub const MAX_HEADERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartLine<'a> {
    Notify,
    MSearch,
    Response { status: u16 },
    Other(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssdp<'a> {
    pub start: StartLine<'a>,
    pub headers: Vec<(&'a [u8], &'a [u8])>,
}

impl<'a> Ssdp<'a> {
    /// The value of the first header called `name`, compared without case.
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| *v)
    }
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = b {
        if *first == b' ' || *first == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = b {
        if *last == b' ' || *last == b'\t' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn start_line(line: &[u8]) -> StartLine<'_> {
    if line.starts_with(b"NOTIFY ") {
        return StartLine::Notify;
    }
    if line.starts_with(b"M-SEARCH ") {
        return StartLine::MSearch;
    }
    if line.starts_with(b"HTTP/1.") {
        let status = line
            .split(|&b| b == b' ')
            .nth(1)
            .filter(|s| !s.is_empty() && s.len() <= 3 && s.iter().all(u8::is_ascii_digit))
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| s.parse::<u16>().ok());
        if let Some(status) = status {
            return StartLine::Response { status };
        }
    }
    StartLine::Other(line)
}

/// Parses an SSDP message from the cursor's position and consumes the rest
/// of the data. Lines end in CRLF or LF; a blank line ends the headers. An
/// over-long line or too many headers stop the parse with what was read;
/// a header line without a colon is skipped.
pub fn parse<'a>(c: &mut Cursor<'a>, problems: &mut Vec<Problem>) -> Option<Ssdp<'a>> {
    if c.is_empty() {
        return None;
    }
    let mut r = *c;
    let base = r.pos();
    let data = r.rest();
    let mut pos = 0usize;
    let mut start = None;
    let mut headers = Vec::new();
    while pos < data.len() {
        let tail = data.get(pos..).unwrap_or(&[]);
        let nl = tail.iter().position(|&b| b == b'\n');
        let raw = nl.map_or(tail, |i| tail.get(..i).unwrap_or(&[]));
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let offset = base.saturating_add(pos);
        pos = pos.saturating_add(nl.map_or(tail.len(), |i| i.saturating_add(1)));
        if line.len() > MAX_LINE {
            problems.push(Problem {
                layer: Layer::Ssdp,
                reason: "line too long",
                offset,
                len: line.len(),
            });
            if start.is_none() {
                start = Some(StartLine::Other(line.get(..MAX_LINE).unwrap_or(line)));
            }
            break;
        }
        if start.is_none() {
            start = Some(start_line(line));
            continue;
        }
        if line.is_empty() {
            break;
        }
        let split = line.iter().position(|&b| b == b':');
        let parts = split.and_then(|i| {
            let name = trim(line.get(..i)?);
            let value = trim(line.get(i.checked_add(1)?..)?);
            (!name.is_empty()).then_some((name, value))
        });
        let Some((name, value)) = parts else {
            problems.push(Problem {
                layer: Layer::Ssdp,
                reason: "bad header line",
                offset,
                len: line.len(),
            });
            continue;
        };
        if headers.len() >= MAX_HEADERS {
            problems.push(Problem {
                layer: Layer::Ssdp,
                reason: "too many headers",
                offset,
                len: line.len(),
            });
            break;
        }
        headers.push((name, value));
    }
    *c = r;
    Some(Ssdp {
        start: start.unwrap_or(StartLine::Other(&[])),
        headers,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use overhear_testgen::ssdp;

    fn run(b: &[u8]) -> (Option<Ssdp<'_>>, Vec<Problem>) {
        let mut p = Vec::new();
        let mut c = Cursor::new(b);
        let m = parse(&mut c, &mut p);
        (m, p)
    }

    fn reasons(p: &[Problem]) -> Vec<&'static str> {
        p.iter().map(|p| p.reason).collect()
    }

    #[test]
    fn parses_notify() {
        let b = ssdp(
            "NOTIFY * HTTP/1.1",
            &[
                ("HOST", "239.255.255.250:1900"),
                ("NT", "urn:schemas-upnp-org:device:MediaRenderer:1"),
                ("NTS", "ssdp:alive"),
            ],
        );
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert!(p.is_empty());
        assert_eq!(m.start, StartLine::Notify);
        assert_eq!(m.headers.len(), 3);
        assert_eq!(m.headers[2], (&b"NTS"[..], &b"ssdp:alive"[..]));
        let b = ssdp("M-SEARCH * HTTP/1.1", &[("ST", "ssdp:all")]);
        let (m, _) = run(&b);
        assert_eq!(m.unwrap().start, StartLine::MSearch);
        let b = ssdp("HTTP/1.1 200 OK", &[]);
        let (m, _) = run(&b);
        assert_eq!(m.unwrap().start, StartLine::Response { status: 200 });
    }

    #[test]
    fn header_lookup_case_insensitive() {
        let b = ssdp(
            "NOTIFY * HTTP/1.1",
            &[("Location", "  http://x/  "), ("nt", "a")],
        );
        let (m, _) = run(&b);
        let m = m.unwrap();
        assert_eq!(m.header("LOCATION"), Some(&b"http://x/"[..]));
        assert_eq!(m.header("NT"), Some(&b"a"[..]));
        assert_eq!(m.header("USN"), None);
    }

    #[test]
    fn sixty_five_headers() {
        let names: Vec<String> = (0..65).map(|i| format!("X-{i}")).collect();
        let hs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "v")).collect();
        let b = ssdp("NOTIFY * HTTP/1.1", &hs);
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert_eq!(m.headers.len(), MAX_HEADERS);
        assert_eq!(m.headers[63].0, b"X-63");
        assert_eq!(reasons(&p), vec!["too many headers"]);
        let b = ssdp("NOTIFY * HTTP/1.1", &hs[..64]);
        let (m, p) = run(&b);
        assert_eq!(m.unwrap().headers.len(), 64);
        assert!(p.is_empty());
    }

    #[test]
    fn long_line() {
        let long = "a".repeat(MAX_LINE + 1);
        let b = ssdp("NOTIFY * HTTP/1.1", &[("A", "1"), ("B", &long), ("C", "3")]);
        let (m, p) = run(&b);
        let m = m.unwrap();
        assert_eq!(m.headers.len(), 1);
        assert_eq!(reasons(&p), vec!["line too long"]);
        let ok = "a".repeat(MAX_LINE - 3);
        let b = ssdp("NOTIFY * HTTP/1.1", &[("B", &ok)]);
        let (m, p) = run(&b);
        assert_eq!(m.unwrap().headers.len(), 1);
        assert!(p.is_empty());
        // No newline at all.
        let b = vec![b'x'; 5000];
        let (m, p) = run(&b);
        assert!(matches!(m.unwrap().start, StartLine::Other(l) if l.len() == MAX_LINE));
        assert_eq!(reasons(&p), vec!["line too long"]);
    }

    #[test]
    fn lf_only_lines() {
        let b = b"M-SEARCH * HTTP/1.1\nST: ssdp:all\nMAN:\t\"ssdp:discover\" \n\nignored: 1\n";
        let (m, p) = run(b);
        let m = m.unwrap();
        assert!(p.is_empty());
        assert_eq!(m.start, StartLine::MSearch);
        assert_eq!(m.headers.len(), 2);
        assert_eq!(m.header("man"), Some(&b"\"ssdp:discover\""[..]));
    }

    #[test]
    fn bad_header_line_is_skipped() {
        let b = b"NOTIFY * HTTP/1.1\r\nno colon here\r\nNT: x\r\n: nameless\r\n\r\n";
        let (m, p) = run(b);
        assert_eq!(m.unwrap().headers.len(), 1);
        assert_eq!(reasons(&p), vec!["bad header line", "bad header line"]);
        assert_eq!(p[0].offset, 19);
        assert_eq!(p[0].len, 13);
    }

    #[test]
    fn binary_junk_is_other_without_panic() {
        let junk: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
        let (m, _) = run(&junk);
        assert!(matches!(m.unwrap().start, StartLine::Other(_)));
        let (m, _) = run(b"\xff\xfe\x00\r\n\r\n");
        assert!(matches!(m.unwrap().start, StartLine::Other(_)));
        let (m, _) = run(b"HTTP/1.1 abc\r\n");
        assert!(matches!(m.unwrap().start, StartLine::Other(_)));
        let mut p = Vec::new();
        let mut c = Cursor::new(b"");
        assert!(parse(&mut c, &mut p).is_none());
    }
}
