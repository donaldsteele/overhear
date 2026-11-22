//! The live screen (`-t`).

pub mod app;
pub mod view;

use std::cell::RefCell;
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

pub use app::{App, TuiRenderer};
pub use view::draw;

use crate::engine::{Engine, RunEnd, RunError};
use crate::pipeline::{self, Flow, PipelineOpts, run_threaded};
use crate::render::Renderer;
use crate::source::Source;
use crate::warn::Output;

/// Like [`TuiRenderer`], but shares the [`App`] with the hook, which draws
/// from it while the pipeline owns the renderer.
struct SharedRenderer<'a>(&'a RefCell<App>);

impl Renderer for SharedRenderer<'_> {
    fn packet(
        &mut self,
        _: &crate::source::Frame,
        _: &overhear_decode::Decoded<'_>,
    ) -> io::Result<()> {
        Ok(())
    }

    fn output(&mut self, o: &Output) -> io::Result<()> {
        self.0.borrow_mut().push_output(o);
        Ok(())
    }
}

fn clock_now() -> String {
    let now = jiff::Timestamp::now().to_zoned_datetime(jiff::tz::TimeZone::system());
    now.strftime("%H:%M:%S").to_string()
}

/// Reads pending keys; true when the user asked to quit. A resize asks for
/// a redraw.
fn poll_keys(app: &RefCell<App>) -> io::Result<bool> {
    while event::poll(Duration::ZERO)? {
        match event::read()? {
            Event::Key(k) if k.kind != KeyEventKind::Release => {
                let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                match k.code {
                    KeyCode::Char('q') if !ctrl => return Ok(true),
                    KeyCode::Char('c') if ctrl => return Ok(true),
                    _ => {}
                }
            }
            Event::Resize(..) => app.borrow_mut().request_redraw(),
            _ => {}
        }
    }
    Ok(false)
}

/// Runs the live screen until `q`, Ctrl-C, `stop`, or the pipeline fails.
/// `live` is true for a capture from an interface, false for a recording
/// (see [`PipelineOpts::wall_clock`]).
/// The terminal is restored on every path out.
pub fn run(
    src: Box<dyn Source>,
    engine: &mut Engine,
    stop: Arc<AtomicBool>,
    label: String,
    live: bool,
) -> Result<RunEnd, RunError> {
    // `init` would panic on failure; `try_init` also installs the panic hook
    // that restores the terminal.
    let mut terminal = ratatui::try_init().map_err(RunError::Io)?;
    let app = RefCell::new(App::new(label));
    let mut renderer = SharedRenderer(&app);
    let mut hook = |engine: &mut Engine, _: &mut dyn Renderer| -> io::Result<Flow> {
        if poll_keys(&app)? {
            return Ok(Flow::Stop);
        }
        if app.borrow_mut().should_draw(Instant::now()) {
            let app = app.borrow();
            terminal.draw(|f| draw(f, &app, engine.tracker(), &clock_now()))?;
        }
        Ok(Flow::Continue)
    };
    let opts = PipelineOpts {
        buffers: pipeline::BUFFERS,
        linger_after_end: true,
        wall_clock: live,
    };
    let end = run_threaded(src, engine, &mut renderer, stop, opts, &mut hook);
    ratatui::restore();
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Config;
    use crate::file_source::FileSource;
    use crate::render::TextOpts;
    use crate::time::TimeStyle;
    use crate::warn::Pins;
    use jiff::tz::TimeZone;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::path::PathBuf;

    /// One frame of the DHCP golden capture, as `-t -r` would show it.
    #[test]
    fn dhcp_capture_frame() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/dhcp.pcap");
        let src = FileSource::open(&path).expect("open pcap");
        let mut engine = Engine::new(Config {
            text: TextOpts {
                tz: TimeZone::UTC,
                style: TimeStyle::DateTime,
                hex: false,
            },
            max_memory: 1 << 20,
            pins: Pins::default(),
        });
        let app = RefCell::new(App::new("dhcp.pcap".into()));
        let mut renderer = SharedRenderer(&app);
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
        .expect("run");
        assert!(matches!(end, RunEnd::Done));
        let mut term = Terminal::new(TestBackend::new(100, 20)).expect("terminal");
        let app = app.borrow();
        term.draw(|f| draw(f, &app, engine.tracker(), "12:00:00"))
            .expect("draw");
        let buf = term.backend().buffer();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        println!("{s}");
        assert!(s.contains("second DHCP server"), "{s}");
        assert!(app.total_warnings >= 1);
    }
}
