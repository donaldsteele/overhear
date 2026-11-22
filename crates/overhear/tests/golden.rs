use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use jiff::tz::TimeZone;
use overhear::engine::{Config, Engine, RunEnd};
use overhear::file_source::FileSource;
use overhear::pipeline::{self, Flow, PipelineOpts, run_threaded};
use overhear::render::json::JsonRenderer;
use overhear::render::line::LineRenderer;
use overhear::render::verbose::VerboseRenderer;
use overhear::render::{Renderer, TextOpts};
use overhear::time::TimeStyle;
use overhear::warn::Pins;

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

fn opts() -> TextOpts {
    TextOpts {
        tz: TimeZone::UTC,
        style: TimeStyle::DateTime,
        hex: false,
    }
}

/// Runs the capture through the threaded pipeline as `-r` does: frame
/// timestamps are the clock, and nothing is dropped.
fn run(name: &str, r: &mut dyn Renderer) {
    let src = FileSource::open(&data(&format!("{name}.pcap"))).expect("open pcap");
    let mut engine = Engine::new(Config {
        text: opts(),
        max_memory: 1 << 20,
        pins: Pins::default(),
    });
    let pipe = PipelineOpts {
        buffers: pipeline::BUFFERS,
        linger_after_end: false,
        wall_clock: false,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let mut keep_going = |_: &mut Engine, _: &mut dyn Renderer| Ok(Flow::Continue);
    let end =
        run_threaded(Box::new(src), &mut engine, r, stop, pipe, &mut keep_going).expect("run");
    assert!(matches!(end, RunEnd::Done), "{end:?}");
    r.finish(&engine.summary()).expect("finish");
}

/// Compares `got` with the golden file `file`, or rewrites it under
/// `UPDATE_GOLDEN=1`. Never passes on unequal output.
fn check(file: &str, got: &str) {
    let path = data(file);
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        fs::write(&path, got).expect("write golden");
        return;
    }
    let want = fs::read_to_string(&path).expect("read golden");
    if got != want {
        let (mut g, mut w) = (got.lines(), want.lines());
        for n in 1.. {
            let (a, b) = (g.next(), w.next());
            if a != b {
                panic!(
                    "{file}: line {n} differs\n  want: {}\n  got:  {}",
                    b.unwrap_or("<missing>"),
                    a.unwrap_or("<missing>")
                );
            }
            if a.is_none() {
                break;
            }
        }
    }
    assert_eq!(got, want, "{file}: output differs");
}

fn golden(name: &str) {
    let mut r = LineRenderer::new(Vec::new(), opts());
    run(name, &mut r);
    check(
        &format!("{name}.line"),
        &String::from_utf8(r.into_inner()).expect("utf8 output"),
    );

    let mut r = VerboseRenderer::new(Vec::new(), opts());
    run(name, &mut r);
    check(
        &format!("{name}.verbose"),
        &String::from_utf8(r.into_inner()).expect("utf8 output"),
    );

    let mut r = JsonRenderer::new(Vec::new(), TimeZone::UTC, false);
    run(name, &mut r);
    let json = String::from_utf8(r.into_inner()).expect("utf8 output");
    for (i, l) in json.lines().enumerate() {
        let v: serde_json::Value = serde_json::from_str(l)
            .unwrap_or_else(|e| panic!("{name}.jsonl line {}: {e}: {l}", i + 1));
        assert_eq!(v["schema"], 1, "{name}.jsonl line {}", i + 1);
        assert!(v.get("type").is_some(), "{name}.jsonl line {}", i + 1);
    }
    check(&format!("{name}.jsonl"), &json);
}

#[test]
fn generic() {
    golden("generic");
}

#[test]
fn arp() {
    golden("arp");
}

#[test]
fn dhcp() {
    golden("dhcp");
}

#[test]
fn nd() {
    golden("nd");
}

#[test]
fn mdns() {
    golden("mdns");
}

#[test]
fn llmnr_nbns() {
    golden("llmnr_nbns");
}

#[test]
fn ssdp() {
    golden("ssdp");
}
