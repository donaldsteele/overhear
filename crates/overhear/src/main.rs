use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use jiff::tz::TimeZone;
use overhear::cli::{Mode, parse_args};
use overhear::engine::{Config, Engine, RunEnd, run_source};
use overhear::filter::build_filter;
use overhear::platform;
use overhear::render::json::JsonRenderer;
use overhear::render::line::LineRenderer;
use overhear::render::verbose::VerboseRenderer;
use overhear::render::{Renderer, TextOpts};
use overhear::source::LinkType;
use overhear::time::TimeStyle;

/// Standard output through a buffer that is flushed at the end of every line
/// when packets should show up at once (a terminal or a pipe).
struct Out {
    w: BufWriter<io::Stdout>,
    flush_lines: bool,
}

impl Write for Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.w.write(buf)?;
        if self.flush_lines && n == buf.len() && buf.ends_with(b"\n") {
            self.w.flush()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("overhear: {msg}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(code) => return code,
    };

    if args.list {
        return match platform::list_interfaces() {
            Ok(list) => {
                let mut out = io::stdout().lock();
                for i in list {
                    let addrs: Vec<String> = i.addrs.iter().map(|a| a.to_string()).collect();
                    if writeln!(out, "{}\t{}\t{}", i.name, i.friendly, addrs.join(",")).is_err() {
                        break;
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        };
    }

    let filter = build_filter(&args.filter);
    let live = args.read.is_none();
    let opened = match &args.read {
        Some(path) => platform::open_file(path, &filter),
        None => match args.iface.as_deref().map(platform::resolve_interface) {
            Some(Err(e)) => return fail(e),
            Some(Ok(name)) => platform::open_live(Some(&name), !args.no_promisc, &filter),
            None => platform::open_live(None, !args.no_promisc, &filter),
        },
    };
    let mut src = match opened {
        Ok(s) => s,
        Err(e) => return fail(e),
    };

    if let LinkType::Other(n) = src.link_type() {
        return fail(format!(
            "unsupported link type {n}: overhear decodes Ethernet only"
        ));
    }

    // Task 14 drops privileges here, after the capture is open.

    let mode = args.mode();
    let text = TextOpts {
        tz: TimeZone::system(),
        style: if live {
            TimeStyle::Time
        } else {
            TimeStyle::DateTime
        },
        hex: args.hex,
    };
    let mut engine = Engine::new(Config { text: text.clone() });
    let out = Out {
        w: BufWriter::new(io::stdout()),
        flush_lines: !platform::stdout_is_file(),
    };
    let mut renderer: Box<dyn Renderer> = match mode {
        Mode::Line => Box::new(LineRenderer::new(out, text)),
        Mode::Verbose => Box::new(VerboseRenderer::new(out, text)),
        Mode::Json => Box::new(JsonRenderer::new(out, text.tz, args.hex)),
        Mode::Tui => return fail("-t is not available yet"),
    };

    match run_source(&mut *src, &mut engine, &mut *renderer) {
        Ok(RunEnd::Done) => {
            let mut summary = engine.summary();
            if let Some(st) = src.stats() {
                summary.kernel_drops = st.kernel_drops;
            }
            match renderer.finish(&summary) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return ExitCode::SUCCESS,
                Err(e) => return fail(e),
            }
            if matches!(mode, Mode::Line | Mode::Verbose) {
                eprintln!(
                    "overhear: {} packets, {} dropped by the kernel, {} dropped by overhear, {} devices",
                    summary.packets, summary.kernel_drops, summary.channel_drops, summary.devices
                );
            }
            ExitCode::SUCCESS
        }
        Ok(RunEnd::Closed) => ExitCode::SUCCESS,
        Ok(RunEnd::Truncated(_)) => {
            let _ = renderer.finish(&engine.summary());
            let path = args
                .read
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            fail(format!("{path}: truncated capture file"))
        }
        Err(e) => fail(e),
    }
}
