//! Drawing of the live screen.

use std::fmt::Write as _;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use super::app::App;
use crate::escape::{LINE_FIELD_MAX, TextKind, push_text};
use crate::track::{Device, Tracker};
use crate::vendor::{lookup, short};
use crate::warn::{Severity, Warning};

const MIN_WIDTH: u16 = 20;
const MIN_HEIGHT: u16 = 6;
const IP_WIDTH: usize = 15;
const NAME_WIDTH: usize = 16;
const VENDOR_WIDTH: usize = 10;
/// Source characters of a warning message kept; the pane clips the rest.
const MESSAGE_MAX: usize = 512;

/// Cuts `s` to `max` characters, ending in `…` when it was longer.
fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn escaped(bytes: &[u8], max: usize) -> String {
    let mut out = String::new();
    push_text(&mut out, bytes, TextKind::Utf8, max);
    out
}

fn header(app: &App, tracker: &Tracker, clock: &str) -> String {
    let w = app.total_warnings;
    let mut s = format!(
        " overhear  {}   {} devices   {w} warning{}",
        escaped(app.label.as_bytes(), LINE_FIELD_MAX),
        tracker.table.len(),
        if w == 1 { "" } else { "s" },
    );
    if let Some(r) = tracker.table.stp_root() {
        let [p0, p1, a, b, c, d, e, f] = r;
        let _ = write!(
            s,
            "   root {:04x}.{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}",
            u16::from_be_bytes([p0, p1])
        );
    }
    let _ = write!(s, "   {clock}");
    s
}

fn footer(app: &App) -> String {
    format!(
        " q quit  ↑↓ select  enter details  s sort: {}  / filter  w warnings  p pause",
        app.sort.as_str()
    )
}

fn row(d: &Device) -> Row<'static> {
    let ip = match (d.ipv4.iter().next(), d.ipv6.iter().next()) {
        (Some((a, _)), _) => a.to_string(),
        (None, Some((a, _))) => a.to_string(),
        (None, None) => String::new(),
    };
    let name = d
        .display_name()
        .map(|n| escaped(n, NAME_WIDTH))
        .unwrap_or_default();
    let vendor = if d.random {
        "(random)".to_owned()
    } else {
        lookup(d.mac).map(short).unwrap_or_default()
    };
    let heard: Vec<&str> = d.heard_tags().map(|t| t.as_str()).collect();
    Row::new([
        Cell::from(d.mac.to_string()),
        Cell::from(cut(&ip, IP_WIDTH)),
        Cell::from(name),
        Cell::from(escaped(vendor.as_bytes(), VENDOR_WIDTH)),
        Cell::from(heard.join(" ")),
    ])
}

fn table(f: &mut Frame, area: Rect, tracker: &Tracker) {
    let mut devices: Vec<&Device> = tracker.table.iter().collect();
    devices.sort_by(|a, b| {
        b.last_heard
            .cmp(&a.last_heard)
            .then_with(|| a.mac.0.cmp(&b.mac.0))
    });
    // The header takes one row; no point building rows that cannot show.
    let fit = usize::from(area.height.saturating_sub(1));
    let rows: Vec<Row> = devices.into_iter().take(fit).map(row).collect();
    let head = Row::new(["MAC", "IP", "NAME", "VENDOR", "HEARD"])
        .style(Style::new().add_modifier(Modifier::BOLD));
    let widths = [
        Constraint::Length(17),
        Constraint::Length(15),
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Min(0),
    ];
    f.render_widget(Table::new(rows, widths).header(head), area);
}

fn warning_line(w: &Warning) -> Line<'static> {
    let time = crate::time::format_line(
        w.ts.sec,
        w.ts.usec,
        &jiff::tz::TimeZone::system(),
        crate::time::TimeStyle::Time,
    );
    let time = time.split('.').next().unwrap_or("");
    let mut text = format!("{time}  ");
    if let Some(seg) = w.segment.filter(|s| !s.is_untagged()) {
        let _ = write!(text, "[{seg}] ");
    }
    text.push_str(&escaped(w.message.as_bytes(), MESSAGE_MAX));
    let style = match w.severity {
        Severity::High => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::Low => Style::new().fg(Color::Yellow),
    };
    Line::from(Span::styled(text, style))
}

fn warnings(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::new().borders(Borders::TOP).title(" warnings ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let lines: Vec<Line> = app
        .warnings
        .iter()
        .take(usize::from(inner.height))
        .map(warning_line)
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

/// Draws the whole screen. `clock` is the time of day for the header.
pub fn draw(f: &mut Frame, app: &App, tracker: &Tracker, clock: &str) {
    let area = f.area();
    let head = Paragraph::new(header(app, tracker, clock))
        .style(Style::new().add_modifier(Modifier::REVERSED));
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        f.render_widget(
            head,
            Rect {
                height: area.height.min(1),
                ..area
            },
        );
        return;
    }
    let pane = (area.height / 3).max(3);
    let [top, body, warn, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(pane),
        Constraint::Length(1),
    ])
    .areas(area);
    f.render_widget(head, top);
    table(f, body, tracker);
    warnings(f, warn, app);
    f.render_widget(Paragraph::new(footer(app)), foot);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::Observation;
    use crate::observe::{NameSource, ProtoTag, Segment, Ts};
    use crate::warn::{Output, Pins, Rule, Severity, Warning};
    use overhear_decode::Mac;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::borrow::Cow;
    use std::net::{IpAddr, Ipv4Addr};

    fn mac(n: u8) -> Mac {
        Mac([0x02, 0x00, 0x5e, 0x10, 0x00, n])
    }

    fn tracker() -> Tracker {
        Tracker::new(usize::MAX, Pins::default())
    }

    fn apply(t: &mut Tracker, sec: i64, obs: Observation<'_>) {
        t.apply(
            Segment::UNTAGGED,
            Ts { sec, usec: 0 },
            &[obs],
            &mut Vec::new(),
        );
    }

    fn device(t: &mut Tracker, sec: i64, m: Mac, name: &[u8], ip: [u8; 4], tags: &[ProtoTag]) {
        for &proto in tags {
            apply(t, sec, Observation::Heard { mac: m, proto });
        }
        apply(
            t,
            sec,
            Observation::Name {
                mac: m,
                name: Cow::Owned(name.to_vec()),
                source: NameSource::Mdns,
            },
        );
        apply(
            t,
            sec,
            Observation::Address {
                mac: m,
                ip: IpAddr::V4(Ipv4Addr::from(ip)),
            },
        );
    }

    fn second_server() -> Output {
        Output::Warning(Warning {
            ts: Ts { sec: 0, usec: 0 },
            rule: Rule::SecondDhcpServer,
            severity: Severity::High,
            segment: None,
            subject: String::new(),
            message: "second DHCP server 10.0.0.9 (expected 10.0.0.1)".into(),
            macs: Vec::new(),
            addrs: Vec::new(),
            count: 1,
        })
    }

    fn render(app: &App, t: &Tracker, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).expect("terminal");
        term.draw(|f| draw(f, app, t, "12:34:56")).expect("draw");
        let buf = term.backend().buffer();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn renders_header_table_and_warnings() {
        let mut t = tracker();
        device(
            &mut t,
            1,
            mac(0x14),
            b"laptop",
            [192, 168, 1, 20],
            &[ProtoTag::Arp, ProtoTag::Dhcp, ProtoTag::Mdns],
        );
        device(
            &mut t,
            2,
            mac(0x21),
            b"Living-Room-TV",
            [192, 168, 1, 33],
            &[ProtoTag::Mdns, ProtoTag::Ssdp],
        );
        let mut app = App::new("eth0".into());
        app.push_output(&second_server());
        let s = render(&app, &t, 100, 20);
        println!("{s}");
        for want in [
            " overhear ",
            "2 devices",
            "1 warning",
            "02:00:5e:10:00:14",
            "laptop",
            "ARP DHCP mDNS",
            "second DHCP server",
            "q quit",
        ] {
            assert!(s.contains(want), "missing {want:?} in\n{s}");
        }
        assert!(!s.contains("1 warnings"));
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut t = tracker();
        device(&mut t, 1, mac(1), b"a", [10, 0, 0, 1], &[ProtoTag::Arp]);
        let mut app = App::new("eth0".into());
        app.push_output(&second_server());
        for (w, h) in [(1, 1), (20, 5), (300, 100)] {
            let _ = render(&app, &t, w, h);
        }
    }

    #[test]
    fn escaped_name_in_table() {
        let mut t = tracker();
        device(
            &mut t,
            1,
            mac(1),
            b"\x1b[2Jevil",
            [10, 0, 0, 1],
            &[ProtoTag::Arp],
        );
        let s = render(&App::new("eth0".into()), &t, 100, 20);
        assert!(s.contains("\\x1b[2Jevil"), "{s}");
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn root_shown_when_known() {
        let mut t = tracker();
        apply(
            &mut t,
            1,
            Observation::StpRoot {
                root: [0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x01],
            },
        );
        let s = render(&App::new("eth0".into()), &t, 100, 20);
        assert!(s.contains("root 8000.00:11:22:33:44:01"), "{s}");
    }
}
