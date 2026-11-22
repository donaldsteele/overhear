//! Wires sources to renderers: decode every frame, hand it on.

use std::io;

use overhear_decode::decode;

use crate::observe::{Observation, Segment, Ts};
use crate::proto::observe;
use crate::render::{Renderer, Status, Summary, TextOpts};
use crate::source::{Frame, SourceError, SourceStats};
use crate::track::Tracker;
use crate::warn::{Output, Pins, Rule};

/// Empties `v` and hands back its allocation under another lifetime.
fn reuse<'a, 'b>(mut v: Vec<Observation<'a>>) -> Vec<Observation<'b>> {
    v.clear();
    // Collecting from the same-layout iterator reuses the allocation.
    #[allow(clippy::unnecessary_filter_map)]
    let out = v.into_iter().filter_map(|_| None).collect();
    out
}

pub struct Config {
    pub text: TextOpts,
    /// Budget for everything remembered about the network, in bytes.
    pub max_memory: usize,
    /// Expected DHCP servers and routers from the command line.
    pub pins: Pins,
}

pub struct Engine {
    #[allow(dead_code)]
    cfg: Config,
    packets: u64,
    /// Kernel plus interface drops at the last `stats` call.
    kernel_drops: u64,
    channel_drops: u64,
    tracker: Tracker,
    /// Observations of the frame being handled; always empty between frames.
    scratch: Vec<Observation<'static>>,
    /// Warnings and baselines waiting to be rendered; always empty between
    /// calls.
    outputs: Vec<Output>,
}

impl Engine {
    pub fn new(cfg: Config) -> Engine {
        Engine {
            tracker: Tracker::new(cfg.max_memory, cfg.pins.clone()),
            scratch: Vec::new(),
            outputs: Vec::new(),
            cfg,
            packets: 0,
            kernel_drops: 0,
            channel_drops: 0,
        }
    }

    pub fn frame(&mut self, f: &Frame, r: &mut dyn Renderer) -> io::Result<()> {
        self.packets = self.packets.saturating_add(1);
        let decoded = decode(&f.data);
        if let Ok(p) = &decoded {
            let mut obs = reuse(std::mem::take(&mut self.scratch));
            observe(p, &mut obs);
            let ts = Ts {
                sec: f.ts_sec,
                usec: f.ts_usec,
            };
            let seg = Segment::from_vlans(&p.eth.vlans);
            self.tracker.apply(seg, ts, &obs, &mut self.outputs);
            self.scratch = reuse(obs);
        }
        if let Err(e) = r.packet(f, &decoded) {
            self.outputs.clear();
            return Err(e);
        }
        self.render_outputs(r)
    }

    /// Renders the waiting warnings and baselines, in order, and clears them.
    fn render_outputs(&mut self, r: &mut dyn Renderer) -> io::Result<()> {
        let done = self.outputs.iter().try_for_each(|o| r.output(o));
        self.outputs.clear();
        done
    }

    pub fn tracker(&self) -> &Tracker {
        &self.tracker
    }

    #[cfg(test)]
    pub(crate) fn tracker_mut(&mut self) -> &mut Tracker {
        &mut self.tracker
    }

    /// Takes the capture's running drop counters (the source's and the
    /// pipeline's) and renders a [`Status`] when either has grown since the
    /// last call. `now` is in seconds since the epoch.
    pub fn stats(
        &mut self,
        s: SourceStats,
        channel_drops: u64,
        now: i64,
        r: &mut dyn Renderer,
    ) -> io::Result<()> {
        let kernel_drops = s.kernel_drops.saturating_add(s.iface_drops);
        let grew = kernel_drops > self.kernel_drops || channel_drops > self.channel_drops;
        self.kernel_drops = kernel_drops;
        self.channel_drops = channel_drops;
        if !grew {
            return Ok(());
        }
        r.status(&Status {
            ts: now,
            kernel_drops,
            channel_drops,
            evictions: self.tracker.table.evictions(),
        })?;
        let message = format!(
            "{} frames dropped ({kernel_drops} by the kernel, {channel_drops} by overhear)",
            kernel_drops.saturating_add(channel_drops)
        );
        let tracker = &mut self.tracker;
        tracker.warn.operational(
            Ts { sec: now, usec: 0 },
            Rule::CaptureDrops,
            message,
            &mut tracker.budget,
            &mut self.outputs,
        );
        self.render_outputs(r)
    }

    /// Called about once a second with the current time (seconds since the
    /// epoch), for work that is due by time rather than by packet: renders
    /// the warning summaries that are due.
    pub fn tick(&mut self, now: i64, r: &mut dyn Renderer) -> io::Result<()> {
        self.tracker.tick(now, &mut self.outputs);
        self.render_outputs(r)
    }

    /// At the end of a run (seconds since the epoch): renders every pending
    /// warning summary, due or not.
    pub fn flush(&mut self, now: i64, r: &mut dyn Renderer) -> io::Result<()> {
        self.tracker.flush(now, &mut self.outputs);
        self.render_outputs(r)
    }

    pub fn summary(&self) -> Summary {
        Summary {
            packets: self.packets,
            kernel_drops: self.kernel_drops,
            channel_drops: self.channel_drops,
            devices: self.tracker.table.len(),
            evictions: self.tracker.table.evictions(),
        }
    }
}

#[derive(Debug)]
pub enum RunEnd {
    Done,
    /// Stdout went away (BrokenPipe).
    Closed,
    Truncated(String),
}

#[derive(Debug)]
pub enum RunError {
    Source(SourceError),
    Io(io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Source(e) => write!(f, "{e}"),
            RunError::Io(e) => write!(f, "write error: {e}"),
        }
    }
}

impl std::error::Error for RunError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Status;
    use crate::time::TimeStyle;
    use jiff::tz::TimeZone;
    use overhear_decode::Decoded;

    #[derive(Default)]
    struct Statuses(Vec<Status>);

    impl Renderer for Statuses {
        fn packet(&mut self, _f: &Frame, _d: &Decoded<'_>) -> io::Result<()> {
            Ok(())
        }

        fn status(&mut self, s: &Status) -> io::Result<()> {
            self.0.push(*s);
            Ok(())
        }
    }

    fn engine() -> Engine {
        Engine::new(Config {
            text: TextOpts {
                tz: TimeZone::UTC,
                style: TimeStyle::DateTime,
                hex: false,
            },
            max_memory: 4 << 20,
            pins: Pins::default(),
        })
    }

    fn st(kernel: u64, iface: u64) -> SourceStats {
        SourceStats {
            kernel_drops: kernel,
            iface_drops: iface,
        }
    }

    #[test]
    fn frames_feed_the_device_table() {
        let mut e = engine();
        let mut r = Statuses::default();
        // Ethernet header + 4 bytes of an unclaimed ethertype, from two MACs.
        for src in [1u8, 2, 1] {
            let mut data = vec![0xff; 6];
            data.extend_from_slice(&[0, 0x16, 0, 0, 0, src]);
            data.extend_from_slice(&[0x88, 0xb5, 0, 0, 0, 0]);
            let f = Frame {
                data,
                ..Frame::default()
            };
            e.frame(&f, &mut r).expect("frame");
        }
        let s = e.summary();
        assert_eq!((s.devices, s.evictions), (2, 0));
        assert_eq!(e.tracker().budget.used(), e.tracker().table.recount());
    }

    /// Records what was rendered, in order; packets can fail with BrokenPipe.
    #[derive(Default)]
    struct Events {
        seen: Vec<String>,
        broken_pipe: bool,
    }

    impl Renderer for Events {
        fn packet(&mut self, _f: &Frame, _d: &Decoded<'_>) -> io::Result<()> {
            if self.broken_pipe {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.seen.push("packet".into());
            Ok(())
        }

        fn output(&mut self, o: &Output) -> io::Result<()> {
            self.seen.push(match o {
                Output::Warning(w) => format!("{} x{}", w.message, w.count),
                Output::Baseline(_) => "baseline".into(),
            });
            Ok(())
        }
    }

    /// An OFFER from 10.0.0.{sid}.
    fn offer(sid: u8) -> Observation<'static> {
        Observation::DhcpReply {
            client: overhear_decode::Mac([2, 0, 0, 0, 0, 0x39]),
            server_mac: overhear_decode::Mac([2, 0, 0, 0, 0, sid]),
            server_id: std::net::Ipv4Addr::new(10, 0, 0, sid),
            msg_type: 2,
            router: None,
        }
    }

    #[test]
    fn outputs_render_right_after_their_packet() {
        let mut e = engine();
        let mut sink = Vec::new();
        let t0 = Ts { sec: 0, usec: 0 };
        e.tracker
            .apply(Segment::UNTAGGED, t0, &[offer(9)], &mut sink);
        // As if the frame below had caused them.
        e.outputs = sink;
        let mut r = Events::default();
        e.frame(&Frame::default(), &mut r).expect("frame");
        e.frame(&Frame::default(), &mut r).expect("frame");
        assert_eq!(r.seen, ["packet", "baseline", "packet"]);

        // A failed packet drops its outputs too.
        let (seg, obs) = (Segment::UNTAGGED, [offer(9), offer(8)]);
        e.tracker.apply(seg, t0, &obs, &mut e.outputs);
        assert_eq!(e.outputs.len(), 1);
        r.broken_pipe = true;
        assert!(e.frame(&Frame::default(), &mut r).is_err());
        assert!(e.outputs.is_empty());
    }

    #[test]
    fn tick_renders_due_summaries() {
        let mut e = engine();
        let mut sink = Vec::new();
        for (sid, sec) in [(1, 0), (9, 1), (9, 2), (9, 3)] {
            let ts = Ts { sec, usec: 0 };
            e.tracker
                .apply(Segment::UNTAGGED, ts, &[offer(sid)], &mut sink);
        }
        assert_eq!(sink.len(), 2, "{sink:?}");
        let mut r = Events::default();
        e.tick(60, &mut r).expect("tick");
        assert!(r.seen.is_empty());
        e.tick(61, &mut r).expect("tick");
        assert_eq!(
            r.seen,
            ["second DHCP server 10.0.0.9 (expected 10.0.0.1) x2"]
        );
        assert!(e.outputs.is_empty());
    }

    #[test]
    fn stats_render_a_status_only_when_drops_grow() {
        let mut e = engine();
        let mut r = Statuses::default();
        e.stats(st(0, 0), 0, 100, &mut r).expect("stats");
        assert!(r.0.is_empty());
        e.stats(st(2, 1), 0, 101, &mut r).expect("stats");
        e.stats(st(2, 1), 0, 102, &mut r).expect("stats");
        e.stats(st(2, 1), 5, 103, &mut r).expect("stats");
        e.stats(st(2, 1), 5, 104, &mut r).expect("stats");
        let want = [
            Status {
                ts: 101,
                kernel_drops: 3,
                channel_drops: 0,
                evictions: 0,
            },
            Status {
                ts: 103,
                kernel_drops: 3,
                channel_drops: 5,
                evictions: 0,
            },
        ];
        assert_eq!(r.0, want);
        let s = e.summary();
        assert_eq!((s.kernel_drops, s.channel_drops), (3, 5));
    }

    #[test]
    fn drops_raise_one_operational_warning_a_minute() {
        let mut e = engine();
        let mut r = Events::default();
        e.stats(st(0, 0), 0, 100, &mut r).expect("stats");
        assert!(r.seen.is_empty());
        e.stats(st(2, 1), 4, 101, &mut r).expect("stats");
        assert_eq!(
            r.seen,
            ["7 frames dropped (3 by the kernel, 4 by overhear) x1"]
        );
        e.stats(st(9, 1), 4, 102, &mut r).expect("stats");
        assert_eq!(r.seen.len(), 1, "repeat-limited");
        assert_eq!(
            e.tracker().budget.used(),
            e.tracker().table.recount() + e.tracker().warn.cost()
        );
        assert!(e.outputs.is_empty());
    }
}
