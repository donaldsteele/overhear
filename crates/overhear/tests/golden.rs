use std::fs;
use std::path::PathBuf;

use jiff::tz::TimeZone;
use overhear::engine::{Config, Engine, RunEnd, run_source};
use overhear::file_source::FileSource;
use overhear::render::TextOpts;
use overhear::render::line::LineRenderer;
use overhear::time::TimeStyle;

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

fn golden(name: &str) {
    let opts = TextOpts {
        tz: TimeZone::UTC,
        style: TimeStyle::DateTime,
        hex: false,
    };
    let mut src = FileSource::open(&data(&format!("{name}.pcap"))).expect("open pcap");
    let mut engine = Engine::new(Config { text: opts.clone() });
    let mut r = LineRenderer::new(Vec::new(), opts);
    let end = run_source(&mut src, &mut engine, &mut r).expect("run");
    assert!(matches!(end, RunEnd::Done));
    let got = String::from_utf8(r.into_inner()).expect("utf8 output");

    let path = data(&format!("{name}.line"));
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        fs::write(&path, &got).expect("write golden");
        return;
    }
    let want = fs::read_to_string(&path).expect("read golden");
    if got != want {
        let (mut g, mut w) = (got.lines(), want.lines());
        for n in 1.. {
            let (a, b) = (g.next(), w.next());
            if a != b {
                panic!(
                    "{name}: line {n} differs\n  want: {}\n  got:  {}",
                    b.unwrap_or("<missing>"),
                    a.unwrap_or("<missing>")
                );
            }
            if a.is_none() {
                break;
            }
        }
    }
}

#[test]
fn generic() {
    golden("generic");
}
