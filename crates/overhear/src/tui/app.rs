//! State of the live screen that is not in the tracker.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::view::{cut, escaped, vendor_short};
use crate::escape::LINE_FIELD_MAX;
use crate::pipeline::Flow;
use crate::render::line::format_packet_line;
use crate::render::{Renderer, TextOpts};
use crate::track::{Device, Tracker};
use crate::warn::{Output, Warning};
use overhear_decode::{Decoded, Mac};

use crate::source::Frame;

/// Warnings kept for the warnings pane.
pub const MAX_WARNINGS: usize = 200;
/// The screen is redrawn at most this often.
pub const DRAW_PERIOD: Duration = Duration::from_millis(100);
/// Recent lines kept per MAC.
pub const RECENT_LINES: usize = 8;
/// Characters kept of each recent line.
pub const RECENT_LINE_MAX: usize = 120;
/// MACs with recent lines (a fixed bound outside the memory budget).
pub const RECENT_MACS: usize = 256;
/// Longest filter text.
const FILTER_MAX: usize = 64;
/// Page size until the first draw says how many rows fit.
const DEFAULT_PAGE: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    LastHeard,
    Mac,
    Ip,
    Name,
    Vendor,
    Packets,
}

impl Sort {
    pub fn as_str(self) -> &'static str {
        match self {
            Sort::LastHeard => "heard",
            Sort::Mac => "mac",
            Sort::Ip => "ip",
            Sort::Name => "name",
            Sort::Vendor => "vendor",
            Sort::Packets => "packets",
        }
    }

    pub fn next(self) -> Sort {
        match self {
            Sort::LastHeard => Sort::Mac,
            Sort::Mac => Sort::Ip,
            Sort::Ip => Sort::Name,
            Sort::Name => Sort::Vendor,
            Sort::Vendor => Sort::Packets,
            Sort::Packets => Sort::LastHeard,
        }
    }
}

/// The newest lines of the most recently active MACs.
#[derive(Default)]
struct Recent {
    /// Per MAC: the tick of its last line and its lines, oldest first.
    by_mac: HashMap<Mac, (u64, VecDeque<String>)>,
    /// Tick to MAC; the first entry is the least recently active.
    order: BTreeMap<u64, Mac>,
    tick: u64,
}

impl Recent {
    fn note(&mut self, mac: Mac, line: &str) {
        self.tick = self.tick.wrapping_add(1);
        let line = cut(line.trim_end_matches(['\r', '\n']), RECENT_LINE_MAX);
        let entry = self
            .by_mac
            .entry(mac)
            .or_insert_with(|| (self.tick, VecDeque::new()));
        self.order.remove(&entry.0);
        entry.0 = self.tick;
        self.order.insert(self.tick, mac);
        if entry.1.len() == RECENT_LINES {
            entry.1.pop_front();
        }
        entry.1.push_back(line);
        while self.by_mac.len() > RECENT_MACS {
            let Some((_, old)) = self.order.pop_first() else {
                break;
            };
            self.by_mac.remove(&old);
        }
    }

    fn get(&self, mac: &Mac) -> impl Iterator<Item = &str> {
        self.by_mac
            .get(mac)
            .into_iter()
            .flat_map(|(_, l)| l.iter().map(String::as_str))
    }
}

pub struct App {
    /// Newest first, at most [`MAX_WARNINGS`].
    pub warnings: VecDeque<Warning>,
    /// Every warning since the start, including those that fell off the ring.
    pub total_warnings: u64,
    pub sort: Sort,
    pub selected: usize,
    pub paused: bool,
    pub label: String,
    /// Zone of the times shown, resolved once.
    pub tz: jiff::tz::TimeZone,
    /// The device whose detail view is open.
    pub detail: Option<Mac>,
    /// The filter text; case-insensitive.
    pub filter: String,
    /// The filter is being typed.
    pub editing: bool,
    /// Arrows scroll the warnings pane.
    pub warn_focus: bool,
    /// Warnings skipped from the newest.
    pub warn_scroll: usize,
    /// MACs shown when the table was frozen.
    frozen: Option<HashSet<Mac>>,
    recent: Recent,
    /// Rows the table showed at the last draw, for PgUp and PgDn.
    page: Cell<usize>,
    last_draw: Option<Instant>,
}

impl App {
    pub fn new(source_label: String) -> Self {
        App {
            warnings: VecDeque::new(),
            total_warnings: 0,
            sort: Sort::LastHeard,
            selected: 0,
            paused: false,
            label: source_label,
            tz: jiff::tz::TimeZone::system(),
            detail: None,
            filter: String::new(),
            editing: false,
            warn_focus: false,
            warn_scroll: 0,
            frozen: None,
            recent: Recent::default(),
            page: Cell::new(DEFAULT_PAGE),
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

    /// Remembers the packet line (already escaped) for the detail view.
    pub fn note_packet(&mut self, src: Mac, line: &str) {
        self.recent.note(src, line);
    }

    /// The remembered lines of `mac`, oldest first.
    pub fn recent_lines(&self, mac: &Mac) -> impl Iterator<Item = &str> {
        self.recent.get(mac)
    }

    /// MACs with remembered lines.
    pub fn recent_macs(&self) -> usize {
        self.recent.by_mac.len()
    }

    pub fn set_page(&self, rows: usize) {
        self.page.set(rows.max(1));
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

    fn matches(&self, d: &Device, needle: &str) -> bool {
        d.mac.to_string().contains(needle)
            || d.ipv4.iter().any(|(a, _)| a.to_string().contains(needle))
            || d.ipv6.iter().any(|(a, _)| a.to_string().contains(needle))
            || d.display_name()
                .is_some_and(|n| escaped(n, LINE_FIELD_MAX).to_lowercase().contains(needle))
            || vendor_short(d).to_lowercase().contains(needle)
    }

    /// The MACs of the table, in order. While paused, only those that were
    /// there when it was paused.
    pub fn visible_rows(&self, tracker: &Tracker) -> Vec<Mac> {
        let needle = self.filter.to_lowercase();
        let mut devices: Vec<&Device> = tracker
            .table
            .iter()
            .filter(|d| self.frozen.as_ref().is_none_or(|f| f.contains(&d.mac)))
            .filter(|d| needle.is_empty() || self.matches(d, &needle))
            .collect();
        devices.sort_by(|a, b| self.compare(a, b).then_with(|| a.mac.0.cmp(&b.mac.0)));
        devices.into_iter().map(|d| d.mac).collect()
    }

    fn compare(&self, a: &Device, b: &Device) -> std::cmp::Ordering {
        // Devices without a value sort after those with one.
        fn present<T: Ord>(a: Option<T>, b: Option<T>) -> std::cmp::Ordering {
            match (a, b) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        }
        match self.sort {
            Sort::LastHeard => b.last_heard.cmp(&a.last_heard),
            Sort::Mac => std::cmp::Ordering::Equal,
            Sort::Ip => present(first_ip(a), first_ip(b)),
            Sort::Name => present(
                a.display_name()
                    .map(|n| escaped(n, LINE_FIELD_MAX).to_lowercase()),
                b.display_name()
                    .map(|n| escaped(n, LINE_FIELD_MAX).to_lowercase()),
            ),
            Sort::Vendor => present(
                Some(vendor_short(a))
                    .filter(|v| !v.is_empty())
                    .map(|v| v.to_lowercase()),
                Some(vendor_short(b))
                    .filter(|v| !v.is_empty())
                    .map(|v| v.to_lowercase()),
            ),
            Sort::Packets => b.packets.cmp(&a.packets),
        }
    }

    fn move_selection(&mut self, key: KeyCode, len: usize) {
        let last = len.saturating_sub(1);
        let page = self.page.get();
        self.selected = match key {
            KeyCode::Up => self.selected.saturating_sub(1),
            KeyCode::Down => self.selected.saturating_add(1),
            KeyCode::PageUp => self.selected.saturating_sub(page),
            KeyCode::PageDown => self.selected.saturating_add(page),
            KeyCode::Home => 0,
            KeyCode::End => last,
            _ => self.selected,
        }
        .min(last);
    }

    fn scroll_warnings(&mut self, key: KeyCode) {
        let last = self.warnings.len().saturating_sub(1);
        let page = self.page.get();
        self.warn_scroll = match key {
            KeyCode::Up => self.warn_scroll.saturating_sub(1),
            KeyCode::Down => self.warn_scroll.saturating_add(1),
            KeyCode::PageUp => self.warn_scroll.saturating_sub(page),
            KeyCode::PageDown => self.warn_scroll.saturating_add(page),
            KeyCode::Home => 0,
            KeyCode::End => last,
            _ => self.warn_scroll,
        }
        .min(last);
    }

    fn set_filter_edit(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char(c) if !c.is_control() => {
                if self.filter.chars().count() < FILTER_MAX {
                    self.filter.push(c);
                }
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Enter => self.editing = false,
            KeyCode::Esc => {
                self.filter.clear();
                self.editing = false;
            }
            _ => return,
        }
        self.selected = 0;
    }

    /// Handles one key press.
    pub fn on_key(&mut self, key: KeyEvent, tracker: &Tracker) -> Flow {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return Flow::Stop;
        }
        if self.editing {
            if !ctrl {
                self.set_filter_edit(key.code);
            }
            return Flow::Continue;
        }
        if ctrl {
            return Flow::Continue;
        }
        if self.detail.is_some() {
            match key.code {
                KeyCode::Esc => self.detail = None,
                KeyCode::Char('q') => return Flow::Stop,
                _ => {}
            }
            return Flow::Continue;
        }
        match key.code {
            KeyCode::Char('q') => return Flow::Stop,
            KeyCode::Up
            | KeyCode::Down
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Home
            | KeyCode::End => {
                if self.warn_focus {
                    self.scroll_warnings(key.code);
                } else {
                    let len = self.visible_rows(tracker).len();
                    self.move_selection(key.code, len);
                }
            }
            KeyCode::Enter if !self.warn_focus => {
                let rows = self.visible_rows(tracker);
                self.detail = rows.get(self.selected).copied();
            }
            KeyCode::Esc => self.warn_focus = false,
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.selected = 0;
            }
            KeyCode::Char('/') => self.editing = true,
            KeyCode::Char('w') => self.warn_focus = !self.warn_focus,
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                self.frozen = self
                    .paused
                    .then(|| tracker.table.iter().map(|d| d.mac).collect());
            }
            _ => {}
        }
        Flow::Continue
    }
}

fn first_ip(d: &Device) -> Option<std::net::IpAddr> {
    match (d.ipv4.iter().next(), d.ipv6.iter().next()) {
        (Some((a, _)), _) => Some((*a).into()),
        (None, Some((a, _))) => Some((*a).into()),
        (None, None) => None,
    }
}

/// Feeds the engine's outputs and packet lines to an [`App`] shared with the
/// draw hook.
pub struct TuiRenderer<'a> {
    pub app: &'a RefCell<App>,
    opts: TextOpts,
    buf: String,
}

impl<'a> TuiRenderer<'a> {
    pub fn new(app: &'a RefCell<App>, opts: TextOpts) -> Self {
        TuiRenderer {
            app,
            opts,
            buf: String::new(),
        }
    }
}

impl Renderer for TuiRenderer<'_> {
    fn packet(&mut self, frame: &Frame, decoded: &Decoded<'_>) -> io::Result<()> {
        // A frame that did not decode has no source to file it under.
        if let Ok(p) = decoded {
            self.buf.clear();
            format_packet_line(frame, decoded, &self.opts, &mut self.buf);
            self.app.borrow_mut().note_packet(p.eth.src, &self.buf);
        }
        Ok(())
    }

    fn output(&mut self, o: &Output) -> io::Result<()> {
        self.app.borrow_mut().push_output(o);
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

    use crate::observe::{NameSource, Observation, ProtoTag, Segment};
    use crate::warn::Pins;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::borrow::Cow;

    fn mac(n: u8) -> Mac {
        Mac([0x02, 0x00, 0x5e, 0x10, 0x00, n])
    }

    fn tracker() -> Tracker {
        Tracker::new(usize::MAX, Pins::default())
    }

    fn add(t: &mut Tracker, sec: i64, m: Mac, name: &[u8]) {
        let obs = [
            Observation::Heard {
                mac: m,
                proto: ProtoTag::Mdns,
            },
            Observation::Name {
                mac: m,
                name: Cow::Owned(name.to_vec()),
                source: NameSource::Mdns,
            },
        ];
        t.apply(
            Segment::UNTAGGED,
            Ts { sec, usec: 0 },
            &obs,
            &mut Vec::new(),
        );
    }

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn press(app: &mut App, t: &Tracker, c: KeyCode) -> Flow {
        app.on_key(key(c), t)
    }

    fn type_str(app: &mut App, t: &Tracker, s: &str) {
        for c in s.chars() {
            press(app, t, KeyCode::Char(c));
        }
    }

    #[test]
    fn sort_cycles_through_all_modes() {
        let mut app = App::new("x".into());
        let t = tracker();
        let mut seen = vec![app.sort];
        for _ in 0..6 {
            press(&mut app, &t, KeyCode::Char('s'));
            seen.push(app.sort);
        }
        assert_eq!(
            seen,
            [
                Sort::LastHeard,
                Sort::Mac,
                Sort::Ip,
                Sort::Name,
                Sort::Vendor,
                Sort::Packets,
                Sort::LastHeard
            ]
        );
    }

    #[test]
    fn selection_clamped_at_ends() {
        let mut t = tracker();
        for n in 1..=3 {
            add(&mut t, i64::from(n), mac(n), b"d");
        }
        let mut app = App::new("x".into());
        press(&mut app, &t, KeyCode::Up);
        assert_eq!(app.selected, 0);
        for _ in 0..10 {
            press(&mut app, &t, KeyCode::Down);
        }
        assert_eq!(app.selected, 2);
        press(&mut app, &t, KeyCode::Home);
        assert_eq!(app.selected, 0);
        press(&mut app, &t, KeyCode::End);
        assert_eq!(app.selected, 2);
        press(&mut app, &t, KeyCode::PageDown);
        assert_eq!(app.selected, 2);
        press(&mut app, &t, KeyCode::PageUp);
        assert_eq!(app.selected, 0);
        // An empty table keeps the selection at zero.
        let mut app = App::new("x".into());
        press(&mut app, &tracker(), KeyCode::Down);
        press(&mut app, &tracker(), KeyCode::End);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn enter_opens_detail_and_esc_returns() {
        let mut t = tracker();
        add(&mut t, 1, mac(1), b"a");
        add(&mut t, 2, mac(2), b"b");
        let mut app = App::new("x".into());
        press(&mut app, &t, KeyCode::Down);
        press(&mut app, &t, KeyCode::Enter);
        // Newest first: row 0 is mac(2), row 1 is mac(1).
        assert_eq!(app.detail, Some(mac(1)));
        press(&mut app, &t, KeyCode::Esc);
        assert_eq!(app.detail, None);
        // Enter on an empty table opens nothing.
        let mut app = App::new("x".into());
        press(&mut app, &tracker(), KeyCode::Enter);
        assert_eq!(app.detail, None);
    }

    #[test]
    fn quit_keys() {
        let t = tracker();
        let mut app = App::new("x".into());
        assert_eq!(press(&mut app, &t, KeyCode::Char('q')), Flow::Stop);
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(app.on_key(ctrl_c, &t), Flow::Stop);
        // While typing a filter, q is text, Ctrl-C still stops.
        press(&mut app, &t, KeyCode::Char('/'));
        assert_eq!(press(&mut app, &t, KeyCode::Char('q')), Flow::Continue);
        assert_eq!(app.filter, "q");
        assert_eq!(app.on_key(ctrl_c, &t), Flow::Stop);
    }

    #[test]
    fn filter_narrows_rows() {
        let mut t = tracker();
        add(&mut t, 1, mac(1), b"laptop");
        add(&mut t, 2, mac(2), b"Living-Room-TV");
        let mut app = App::new("x".into());
        assert_eq!(app.visible_rows(&t).len(), 2);
        press(&mut app, &t, KeyCode::Char('/'));
        type_str(&mut app, &t, "living");
        assert_eq!(app.visible_rows(&t), vec![mac(2)]);
        press(&mut app, &t, KeyCode::Enter);
        assert!(!app.editing);
        assert_eq!(app.visible_rows(&t), vec![mac(2)]);
        // MAC text matches too; Backspace deletes; Esc cancels and clears.
        press(&mut app, &t, KeyCode::Char('/'));
        press(&mut app, &t, KeyCode::Backspace);
        assert_eq!(app.filter, "livin");
        press(&mut app, &t, KeyCode::Esc);
        assert!(app.filter.is_empty() && !app.editing);
        assert_eq!(app.visible_rows(&t).len(), 2);
        type_str(&mut app, &t, "/:10:00:01");
        assert_eq!(app.visible_rows(&t), vec![mac(1)]);
    }

    #[test]
    fn pause_freezes_rows() {
        let mut t = tracker();
        add(&mut t, 1, mac(1), b"a");
        let mut app = App::new("x".into());
        press(&mut app, &t, KeyCode::Char('p'));
        assert!(app.paused);
        add(&mut t, 2, mac(2), b"b");
        assert_eq!(app.visible_rows(&t), vec![mac(1)]);
        press(&mut app, &t, KeyCode::Char('p'));
        assert!(!app.paused);
        assert_eq!(app.visible_rows(&t), vec![mac(2), mac(1)]);
    }

    #[test]
    fn warnings_focus_scrolls_warnings_not_table() {
        let mut t = tracker();
        add(&mut t, 1, mac(1), b"a");
        add(&mut t, 2, mac(2), b"b");
        let mut app = App::new("x".into());
        for n in 0..5 {
            app.push_output(&warning(n));
        }
        press(&mut app, &t, KeyCode::Char('w'));
        press(&mut app, &t, KeyCode::Down);
        press(&mut app, &t, KeyCode::Down);
        assert_eq!((app.warn_scroll, app.selected), (2, 0));
        press(&mut app, &t, KeyCode::End);
        assert_eq!(app.warn_scroll, 4);
        press(&mut app, &t, KeyCode::Esc);
        press(&mut app, &t, KeyCode::Down);
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn recent_lines_bounded() {
        let mut app = App::new("x".into());
        for m in 0..300u16 {
            let [hi, lo] = m.to_be_bytes();
            let mac = Mac([2, 0, 0, 0, hi, lo]);
            for l in 0..10 {
                app.note_packet(mac, &format!("m{m} line {l}\n"));
            }
        }
        assert_eq!(app.recent_macs(), 256);
        // The oldest 44 MACs are gone; the newest keep the last 8 lines.
        assert_eq!(app.recent_lines(&Mac([2, 0, 0, 0, 0, 0])).count(), 0);
        let last = Mac([2, 0, 0, 0, 1, 43]);
        let lines: Vec<&str> = app.recent_lines(&last).collect();
        assert_eq!(lines.len(), 8);
        assert_eq!(lines[0], "m299 line 2");
        assert_eq!(lines[7], "m299 line 9");
    }

    #[test]
    fn recent_lines_lru_and_cut() {
        let mut app = App::new("x".into());
        let first = Mac([2, 0, 0, 0, 0, 0]);
        app.note_packet(first, &"x".repeat(500));
        assert_eq!(
            app.recent_lines(&first).next().map(|l| l.chars().count()),
            Some(120)
        );
        for m in 1..=255u16 {
            let [hi, lo] = m.to_be_bytes();
            app.note_packet(Mac([2, 0, 0, 0, hi, lo]), "a");
        }
        // Touching the oldest keeps it when the next MAC arrives.
        app.note_packet(first, "again");
        app.note_packet(Mac([2, 0, 0, 0, 9, 9]), "b");
        assert_eq!(app.recent_macs(), 256);
        assert_eq!(app.recent_lines(&first).count(), 2);
        assert_eq!(app.recent_lines(&Mac([2, 0, 0, 0, 0, 1])).count(), 0);
    }
}
