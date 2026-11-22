//! Draws one frame of the live screen (`-t`) over capture files and prints
//! it as HTML, for the project site (`scripts/site-samples.sh`).
//!
//! ```text
//! live_frame LABEL WIDTH HEIGHT SORT FILE...
//! ```
//!
//! The files are read together in time order, as one merged capture would
//! be, through the same engine, renderer and drawing code as `overhear -t
//! -r`. Times are in UTC and the header clock shows the time of the last
//! frame, so the output depends only on the files.

use std::cell::RefCell;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use jiff::tz::TimeZone;
use overhear::engine::{Config, Engine, RunEnd};
use overhear::file_source::FileSource;
use overhear::pipeline::{self, Flow, PipelineOpts, run_threaded};
use overhear::render::{Renderer, TextOpts};
use overhear::source::{Frame, LinkType, Next, Source, SourceError, SourceStats};
use overhear::time::TimeStyle;
use overhear::tui::{App, Sort, TuiRenderer, draw};
use overhear::warn::Pins;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};

/// Several capture files read as one, earliest frame first; ties go to the
/// file named first.
struct Merged {
    inputs: Vec<(FileSource, Option<Frame>)>,
    /// Seconds of the newest frame handed out.
    last: Arc<AtomicI64>,
}

impl Source for Merged {
    fn link_type(&self) -> LinkType {
        LinkType::Ethernet
    }

    fn next_into(&mut self, frame: &mut Frame) -> Result<Next, SourceError> {
        for (src, head) in &mut self.inputs {
            if head.is_none() {
                let mut f = Frame::default();
                if src.next_into(&mut f)? == Next::Frame {
                    *head = Some(f);
                }
            }
        }
        let first = self
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(i, (_, h))| h.as_ref().map(|f| ((f.ts_sec, f.ts_usec), i)))
            .min();
        let Some((_, i)) = first else {
            return Ok(Next::End);
        };
        let Some(f) = self.inputs.get_mut(i).and_then(|(_, h)| h.take()) else {
            return Ok(Next::End);
        };
        self.last.fetch_max(f.ts_sec, Ordering::Relaxed);
        *frame = f;
        Ok(Next::Frame)
    }

    fn stats(&mut self) -> Option<SourceStats> {
        None
    }
}

/// The class of a cell's style in the site's stylesheet.
fn class(fg: Color, m: Modifier) -> &'static str {
    match (
        m.contains(Modifier::REVERSED),
        fg,
        m.contains(Modifier::BOLD),
    ) {
        (true, _, _) => "rv",
        (false, Color::Red, _) => "hi",
        (false, Color::Yellow, _) => "lo",
        (false, _, true) => "b",
        _ => "",
    }
}

fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
}

/// The buffer as lines of HTML: runs of one style become one `<span>`, and
/// trailing spaces are dropped unless they show (reversed video).
fn to_html(buf: &Buffer) -> String {
    let mut out = String::new();
    for y in 0..buf.area.height {
        let mut runs: Vec<(&'static str, String)> = Vec::new();
        for x in 0..buf.area.width {
            let cell = &buf[(x, y)];
            let c = class(cell.fg, cell.modifier);
            match runs.last_mut() {
                Some((last, text)) if *last == c => text.push_str(cell.symbol()),
                _ => runs.push((c, cell.symbol().to_owned())),
            }
        }
        if let Some((c, text)) = runs.last_mut() {
            if *c != "rv" {
                text.truncate(text.trim_end().len());
            }
        }
        for (c, text) in runs {
            if text.is_empty() {
                continue;
            }
            if c.is_empty() {
                push_escaped(&mut out, &text);
            } else {
                out.push_str("<span class=\"");
                out.push_str(c);
                out.push_str("\">");
                push_escaped(&mut out, &text);
                out.push_str("</span>");
            }
        }
        out.push('\n');
    }
    out
}

/// What to draw.
struct Opts {
    label: String,
    width: u16,
    height: u16,
    sort: Sort,
    files: Vec<PathBuf>,
}

/// The sort order named `name`, reached the way the `s` key steps through
/// them.
fn sort_named(name: &str) -> Option<Sort> {
    let mut s = Sort::LastHeard;
    for _ in 0..6 {
        if s.as_str() == name {
            return Some(s);
        }
        s = s.next();
    }
    None
}

fn parse(args: &[String]) -> Option<Opts> {
    let [label, width, height, sort, files @ ..] = args else {
        return None;
    };
    if files.is_empty() {
        return None;
    }
    Some(Opts {
        label: label.clone(),
        width: width.parse().ok()?,
        height: height.parse().ok()?,
        sort: sort_named(sort)?,
        files: files.iter().map(PathBuf::from).collect(),
    })
}

fn run(o: Opts) -> Result<String, String> {
    let mut inputs = Vec::new();
    for f in &o.files {
        let src = FileSource::open(f).map_err(|e| format!("{}: {e}", f.display()))?;
        inputs.push((src, None));
    }
    let last = Arc::new(AtomicI64::new(i64::MIN));
    let src = Merged {
        inputs,
        last: Arc::clone(&last),
    };
    let text = TextOpts {
        tz: TimeZone::UTC,
        style: TimeStyle::DateTime,
        hex: false,
    };
    // As `overhear -t -r` with the default memory budget and no pins.
    let mut engine = Engine::new(Config {
        text: text.clone(),
        max_memory: 64 << 20,
        pins: Pins::default(),
    });
    let mut app = App::new(o.label);
    app.tz = TimeZone::UTC;
    app.sort = o.sort;
    let app = RefCell::new(app);
    let mut renderer = TuiRenderer::new(&app, text);
    let opts = PipelineOpts {
        buffers: pipeline::BUFFERS,
        linger_after_end: false,
        wall_clock: false,
    };
    let mut hook = |_: &mut Engine, _: &mut dyn Renderer| Ok(Flow::Continue);
    let end = run_threaded(
        Box::new(src),
        &mut engine,
        &mut renderer,
        Arc::new(AtomicBool::new(false)),
        opts,
        &mut hook,
    )
    .map_err(|e| e.to_string())?;
    if !matches!(end, RunEnd::Done) {
        return Err(format!("run ended early: {end:?}"));
    }
    let clock = jiff::Timestamp::from_second(last.load(Ordering::Relaxed))
        .map_err(|e| e.to_string())?
        .to_zoned_datetime(TimeZone::UTC)
        .strftime("%H:%M:%S")
        .to_string();
    let backend = TestBackend::new(o.width, o.height);
    let mut term = Terminal::new(backend).map_err(|e| e.to_string())?;
    let app = app.borrow();
    term.draw(|f| draw(f, &app, engine.tracker(), &clock))
        .map_err(|e| e.to_string())?;
    Ok(to_html(term.backend().buffer()))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(opts) = parse(&args) else {
        eprintln!("usage: live_frame LABEL WIDTH HEIGHT SORT FILE...");
        eprintln!("  SORT: heard, mac, ip, name, vendor or packets");
        return ExitCode::from(2);
    };
    match run(opts) {
        Ok(html) => {
            print!("{html}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("live_frame: {e}");
            ExitCode::from(1)
        }
    }
}
