//! State of the live screen that is not in the tracker.

use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use crate::render::Renderer;
use crate::warn::{Output, Warning};
use overhear_decode::Decoded;

use crate::source::Frame;

/// Warnings kept for the warnings pane.
pub const MAX_WARNINGS: usize = 200;
/// The screen is redrawn at most this often.
pub const DRAW_PERIOD: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortMode {
    Heard,
}

impl SortMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SortMode::Heard => "heard",
        }
    }
}

pub struct App {
    /// Newest first, at most [`MAX_WARNINGS`].
    pub warnings: VecDeque<Warning>,
    /// Every warning since the start, including those that fell off the ring.
    pub total_warnings: u64,
    pub sort: SortMode,
    pub selected: usize,
    pub paused: bool,
    pub label: String,
    /// Zone of the warning times, resolved once.
    pub tz: jiff::tz::TimeZone,
    last_draw: Option<Instant>,
}

impl App {
    pub fn new(source_label: String) -> Self {
        App {
            warnings: VecDeque::new(),
            total_warnings: 0,
            sort: SortMode::Heard,
            selected: 0,
            paused: false,
            label: source_label,
            tz: jiff::tz::TimeZone::system(),
            last_draw: None,
        }
    }

    /// Remembers a warning (baselines are not shown).
    pub fn push_output(&mut self, o: &Output) {
        if let Output::Warning(w) = o {
            self.total_warnings = self.total_warnings.saturating_add(1);
            self.warnings.push_front(w.clone());
            self.warnings.truncate(MAX_WARNINGS);
        }
    }

    /// True when at least [`DRAW_PERIOD`] has passed since the last draw;
    /// a true answer counts as a draw.
    pub fn should_draw(&mut self, now: Instant) -> bool {
        let due = self
            .last_draw
            .is_none_or(|t| now.saturating_duration_since(t) >= DRAW_PERIOD);
        if due {
            self.last_draw = Some(now);
        }
        due
    }

    /// The next [`App::should_draw`] is true (after a resize).
    pub fn request_redraw(&mut self) {
        self.last_draw = None;
    }
}

/// Feeds the engine's outputs to an [`App`]; packets themselves are ignored
/// (the tracker has them).
pub struct TuiRenderer<'a> {
    pub app: &'a mut App,
}

impl Renderer for TuiRenderer<'_> {
    fn packet(&mut self, _frame: &Frame, _decoded: &Decoded<'_>) -> io::Result<()> {
        Ok(())
    }

    fn output(&mut self, o: &Output) -> io::Result<()> {
        self.app.push_output(o);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::Ts;
    use crate::warn::{Rule, Severity};

    fn warning(n: u32) -> Output {
        Output::Warning(Warning {
            ts: Ts { sec: 0, usec: 0 },
            rule: Rule::SecondDhcpServer,
            severity: Severity::High,
            segment: None,
            subject: String::new(),
            message: format!("w{n}"),
            macs: Vec::new(),
            addrs: Vec::new(),
            count: 1,
        })
    }

    #[test]
    fn should_draw_caps_rate() {
        let mut app = App::new("x".into());
        let t0 = Instant::now();
        assert!(app.should_draw(t0));
        assert!(!app.should_draw(t0 + Duration::from_millis(50)));
        assert!(app.should_draw(t0 + Duration::from_millis(100)));
    }

    #[test]
    fn warnings_ring_keeps_200() {
        let mut app = App::new("x".into());
        for n in 0..250 {
            app.push_output(&warning(n));
        }
        assert_eq!(app.warnings.len(), 200);
        assert_eq!(app.total_warnings, 250);
        assert_eq!(
            app.warnings.front().map(|w| w.message.as_str()),
            Some("w249")
        );
        assert_eq!(app.warnings.back().map(|w| w.message.as_str()), Some("w50"));
    }
}
