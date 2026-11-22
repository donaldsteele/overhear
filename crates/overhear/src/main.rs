use std::io::{self, BufWriter, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use jiff::tz::TimeZone;
use overhear::cli::{Mode, parse_args};
use overhear::engine::{Config, Engine, RunEnd};
use overhear::filter::build_filter;
use overhear::pipeline::{self, Flow, PipelineOpts, run_threaded};
use overhear::platform::{self, PrivOpts};
use overhear::render::json::JsonRenderer;
use overhear::render::line::LineRenderer;
use overhear::render::verbose::VerboseRenderer;
use overhear::render::{Renderer, TextOpts};
use overhear::source::LinkType;
use overhear::time::TimeStyle;
use overhear::tui;

/// Writes `overhear: {msg}` to stderr. A closed stderr is ignored: there is
/// nowhere left to complain.
fn complain(msg: impl std::fmt::Display) {
    let _ = writeln!(io::stderr(), "overhear: {msg}");
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    complain(msg);
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(code) => return code,
    };
    // An unknown --proto name is a mistake on the command line, -D or not.
    let filter = match build_filter(&args.proto, &args.filter) {
        Ok(f) => f,
        Err(e) => return fail(e),
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

    let live = args.read.is_none();
    let opened = match &args.read {
        Some(path) => platform::open_file(path, &filter),
        None => match args.iface.as_deref().map(platform::resolve_interface) {
            Some(Err(e)) => return fail(e),
            Some(Ok(name)) => platform::open_live(Some(&name), !args.no_promisc, &filter),
            None => platform::open_live(None, !args.no_promisc, &filter),
        },
    };
    let src = match opened {
        Ok(s) => s,
        Err(e) => return fail(e),
    };

    if let LinkType::Other(n) = src.link_type() {
        return fail(format!(
            "unsupported link type {n}: overhear decodes Ethernet only"
        ));
    }

    // Give up root or file capabilities now that the capture is open, before
    // any packet byte is decoded.
    if let Err(e) = platform::drop_privileges(&PrivOpts {
        user: args.user.clone(),
    }) {
        return fail(e);
    }

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
    let mut engine = Engine::new(Config {
        text: text.clone(),
        max_memory: args.max_memory,
        pins: args.pins(),
    });
    // SIGINT and SIGTERM end the run normally, after the frames already
    // captured are shown.
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop);
    let handler = move || {
        // A second signal means the first did not end the run (a stalled
        // writer, a quiet stdin): die by the signal.
        if handler_stop.swap(true, Ordering::SeqCst) {
            platform::force_exit_on_signal();
        }
    };
    if let Err(e) = ctrlc::set_handler(handler) {
        return fail(format!("cannot handle signals: {e}"));
    }

    if mode == Mode::Tui {
        let label = match &args.read {
            Some(p) => p.file_name().map_or_else(
                || p.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            ),
            None => args.iface.clone().unwrap_or_else(|| "default".into()),
        };
        return match tui::run(src, &mut engine, stop, label, live, text) {
            Ok(RunEnd::Done | RunEnd::Closed) => ExitCode::SUCCESS,
            Ok(RunEnd::Truncated(_)) => fail(format!(
                "{}: truncated capture file",
                args.read
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            )),
            Err(e) => fail(e),
        };
    }

    // Packets must reach a terminal or pipe at once; a regular file can wait.
    let out = BufWriter::new(io::stdout());
    let flush = !platform::stdout_is_file();
    let mut renderer: Box<dyn Renderer> = match mode {
        Mode::Line => Box::new(LineRenderer::new(out, text).flush_each(flush)),
        Mode::Verbose => Box::new(VerboseRenderer::new(out, text).flush_each(flush)),
        Mode::Json => Box::new(JsonRenderer::new(out, text.tz, args.hex).flush_each(flush)),
        Mode::Tui => unreachable!("handled above"),
    };

    let opts = PipelineOpts {
        buffers: pipeline::BUFFERS,
        linger_after_end: false,
        wall_clock: live,
    };
    let mut keep_going = |_: &mut Engine, _: &mut dyn Renderer| Ok(Flow::Continue);
    match run_threaded(
        src,
        &mut engine,
        &mut *renderer,
        stop,
        opts,
        &mut keep_going,
    ) {
        Ok(RunEnd::Done) => {
            let summary = engine.summary();
            match renderer.finish(&summary) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return ExitCode::SUCCESS,
                Err(e) => return fail(e),
            }
            if matches!(mode, Mode::Line | Mode::Verbose) {
                complain(format_args!(
                    "{} packets, {} dropped by the kernel, {} dropped by overhear, {} devices",
                    summary.packets, summary.kernel_drops, summary.channel_drops, summary.devices
                ));
            }
            ExitCode::SUCCESS
        }
        Ok(RunEnd::Closed) => ExitCode::SUCCESS,
        Ok(RunEnd::Truncated(_)) => {
            // No finish: a final JSON status would claim the run completed.
            // Dropping the renderer writes out what is still buffered.
            drop(renderer);
            let path = args
                .read
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            fail(format!("{path}: truncated capture file"))
        }
        Err(e) => {
            drop(renderer);
            fail(e)
        }
    }
}
