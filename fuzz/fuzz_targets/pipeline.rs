#![no_main]

use std::collections::HashSet;
use std::fmt;
use std::io;

use jiff::tz::TimeZone;
use libfuzzer_sys::fuzz_target;
use overhear::engine::{Config, Engine};
use overhear::escape::needs_escape;
use overhear::render::json::JsonRenderer;
use overhear::render::line::LineRenderer;
use overhear::render::{Renderer, Status, Summary, TextOpts};
use overhear::source::{Frame, SourceStats};
use overhear::time::TimeStyle;
use overhear::warn::{Output, Pins};
use overhear_decode::Decoded;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

const MAX_FRAMES: usize = 64;
const BUDGET: usize = 256 * 1024;

/// Hands every call to both renderers.
struct Tee<A, B>(A, B);

impl<A: Renderer, B: Renderer> Renderer for Tee<A, B> {
    fn packet(&mut self, f: &Frame, d: &Decoded<'_>) -> io::Result<()> {
        self.0.packet(f, d)?;
        self.1.packet(f, d)
    }

    fn status(&mut self, s: &Status) -> io::Result<()> {
        self.0.status(s)?;
        self.1.status(s)
    }

    fn output(&mut self, o: &Output) -> io::Result<()> {
        self.0.output(o)?;
        self.1.output(o)
    }

    fn finish(&mut self, s: &Summary) -> io::Result<()> {
        self.0.finish(s)?;
        self.1.finish(s)
    }
}

/// Parses any JSON value, failing on an object that repeats a key.
struct Strict;

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Strict, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any JSON value")
            }

            fn visit_bool<E>(self, _: bool) -> Result<Strict, E> {
                Ok(Strict)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Strict, E> {
                Ok(Strict)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Strict, E> {
                Ok(Strict)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Strict, E> {
                Ok(Strict)
            }
            fn visit_str<E>(self, _: &str) -> Result<Strict, E> {
                Ok(Strict)
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict)
            }
            fn visit_none<E>(self) -> Result<Strict, E> {
                Ok(Strict)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                while a.next_element::<Strict>()?.is_some() {}
                Ok(Strict)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut seen = HashSet::new();
                while let Some(k) = a.next_key::<String>()? {
                    if !seen.insert(k.clone()) {
                        return Err(de::Error::custom(format!("duplicate key {k:?}")));
                    }
                    a.next_value::<Strict>()?;
                }
                Ok(Strict)
            }
        }
        d.deserialize_any(V)
    }
}

/// Splits at 2-byte big-endian length prefixes; a short last frame is kept.
fn split(data: &[u8]) -> Vec<&[u8]> {
    let mut frames = Vec::new();
    let mut rest = data;
    while frames.len() < MAX_FRAMES {
        let Some((len, tail)) = rest.split_first_chunk::<2>() else {
            break;
        };
        let n = usize::from(u16::from_be_bytes(*len)).min(tail.len());
        let (frame, next) = tail.split_at(n);
        frames.push(frame);
        rest = next;
    }
    frames
}

fn check_text(text: &[u8]) {
    let text = std::str::from_utf8(text).expect("text output is valid UTF-8");
    for c in text.chars() {
        assert!(c == '\n' || !needs_escape(c), "unescaped {c:?} in {text:?}");
    }
}

fn check_json(json: &[u8]) {
    let json = std::str::from_utf8(json).expect("JSON output is valid UTF-8");
    for line in json.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("JSON line parses");
        assert_eq!(v["schema"], 1, "{line}");
        assert!(v["type"].is_string(), "{line}");
        serde_json::from_str::<Strict>(line).expect("no duplicate keys");
    }
}

fuzz_target!(|data: &[u8]| {
    let opts = TextOpts {
        tz: TimeZone::UTC,
        style: TimeStyle::DateTime,
        hex: true,
    };
    let pins = Pins {
        dhcp: vec![("192.0.2.1".parse().expect("address"), None)],
        routers: Vec::new(),
    };
    let mut engine = Engine::new(Config {
        text: opts.clone(),
        max_memory: BUDGET,
        pins,
    });
    let mut tee = Tee(
        LineRenderer::new(Vec::new(), opts),
        JsonRenderer::new(Vec::new(), TimeZone::UTC, true),
    );
    let base: i64 = 1_700_000_000;
    for (i, frame) in split(data).into_iter().enumerate() {
        let sec = base + (i as i64) * 20;
        let f = Frame {
            ts_sec: sec,
            ts_usec: 0,
            orig_len: frame.len() as u32,
            data: frame.to_vec(),
        };
        engine.frame(&f, &mut tee).expect("Vec writes succeed");
        engine.tick(sec, &mut tee).expect("Vec writes succeed");
    }
    let end = base + 10_000;
    engine
        .stats(
            SourceStats {
                kernel_drops: 1,
                iface_drops: 0,
            },
            1,
            end,
            &mut tee,
        )
        .expect("Vec writes succeed");
    engine.flush(end, &mut tee).expect("Vec writes succeed");
    tee.finish(&engine.summary()).expect("Vec writes succeed");

    let Tee(line, json) = tee;
    check_text(&line.into_inner());
    check_json(&json.into_inner());

    let t = engine.tracker();
    let used = t.budget.used();
    assert_eq!(used, t.table.recount() + t.warn.cost(), "budget out of step");
    assert!(used <= BUDGET + 64 * 1024, "budget overshoot: {used}");
});
