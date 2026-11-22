//! The threaded pipeline. A capture thread owns the [`Source`] and reads
//! frames into a pool of reusable buffers, which it hands to the main thread
//! over a bounded channel; the main thread hands each buffer back once its
//! frame is decoded and rendered. The main thread also calls the caller's hook
//! at least every [`HOOK_PERIOD`] (the live screen reads keys and redraws
//! there) and ticks the engine once a second.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{
    self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::engine::{Engine, RunEnd, RunError};
use crate::render::Renderer;
use crate::source::{Frame, Next, Source, SourceError, SourceStats, Waker};

/// Frames in the pool (and the channel's capacity) for a normal run.
pub const BUFFERS: usize = 4096;
/// The hook runs at least this often.
pub const HOOK_PERIOD: Duration = Duration::from_millis(50);
/// How often the capture thread reports drop counters and the engine ticks.
const SECOND: Duration = Duration::from_secs(1);
/// Starting capacity of a frame buffer; a larger frame grows it.
const FRAME_CAPACITY: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineOpts {
    /// Frame buffers in the pool, and the channel's capacity.
    pub buffers: usize,
    /// After the source ends, keep calling the hook until it returns
    /// [`Flow::Stop`] (or `stop` is set) instead of returning at once.
    pub linger_after_end: bool,
    /// True for a live capture: the engine's clock is the wall clock, and
    /// when the main thread falls behind, the capture thread drops frames
    /// (and counts them) rather than stall. False for a recording: the clock
    /// is the frames' own timestamps, and the capture thread waits for a free
    /// buffer instead, so nothing is dropped.
    pub wall_clock: bool,
}

/// From the capture thread to the main thread.
enum Msg {
    Frame(Frame),
    /// The source timed out without a frame.
    Tick,
    /// The source's drop counters and the pipeline's drops so far.
    Stats(SourceStats, u64),
    /// The source ended or `stop` was seen; the capture thread is done.
    End,
    /// The source failed; the capture thread is done.
    Err(SourceError),
}

/// Runs `src` on a capture thread and feeds its frames to `engine` and `r` on
/// this thread until the source ends, the hook returns [`Flow::Stop`], or
/// output fails (`BrokenPipe` → [`RunEnd::Closed`]). Setting `stop` from
/// outside (a signal handler) ends the run once the frames already captured
/// are rendered. Every exit path stops and joins the capture thread, using
/// the source's waker (if it has one) to cut short a read blocked on a quiet
/// interface. The caller calls `Renderer::finish`.
pub fn run_threaded(
    mut src: Box<dyn Source>,
    engine: &mut Engine,
    r: &mut dyn Renderer,
    stop: Arc<AtomicBool>,
    opts: PipelineOpts,
    hook: &mut dyn FnMut(&mut Engine, &mut dyn Renderer) -> io::Result<Flow>,
) -> Result<RunEnd, RunError> {
    let buffers = opts.buffers.max(1);
    let waker = src.waker();
    let (tx, rx) = mpsc::sync_channel(buffers);
    // Never holds more than the pool's `buffers` frames.
    let (free_tx, free_rx) = mpsc::channel();
    let capture = Capture {
        src,
        tx,
        free: free_rx,
        stop: Arc::clone(&stop),
        buffers,
        lossless: !opts.wall_clock,
    };
    let handle = thread::Builder::new()
        .name("capture".into())
        .spawn(move || capture.run())
        .map_err(RunError::Io)?;
    let mut main = Main {
        rx,
        free: free_tx,
        stop: Arc::clone(&stop),
        opts,
        capture_done: false,
        lingering: false,
        frame_clock: None,
        waker,
        stopping: false,
    };
    let end = main.run(engine, r, hook);
    if !main.capture_done {
        main.stop_capture();
    }
    // Closing both channels wakes a capture thread blocked on either.
    drop(main);
    // A panic on the capture thread already ended the run (its channel
    // closed) and printed its message.
    let _ = handle.join();
    end
}

/// The capture thread's state.
struct Capture {
    src: Box<dyn Source>,
    tx: SyncSender<Msg>,
    /// Buffers handed back by the main thread.
    free: Receiver<Frame>,
    stop: Arc<AtomicBool>,
    buffers: usize,
    /// Wait for a free buffer or channel slot instead of dropping the frame.
    lossless: bool,
}

/// Where the next frame is read to.
enum Slot {
    Pooled(Frame),
    /// No buffer was free: the frame is read and dropped.
    Scratch,
}

impl Capture {
    /// Reads until the source ends or fails, `stop` is set, or the main
    /// thread goes away (a channel closes, which ends the thread quietly).
    fn run(mut self) {
        let mut allocated = 0;
        // A buffer kept for the next read: the last read timed out, or its
        // frame found the channel full.
        let mut held: Option<Frame> = None;
        let mut scratch = new_frame();
        let mut drops: u64 = 0;
        let mut last_stats = Instant::now();
        loop {
            let mut slot = match held.take() {
                Some(f) => Slot::Pooled(f),
                None => match self.take_free(&mut allocated) {
                    Some(s) => s,
                    None => return,
                },
            };
            let buf = match &mut slot {
                Slot::Pooled(f) => f,
                Slot::Scratch => &mut scratch,
            };
            match self.src.next_into(buf) {
                Ok(Next::Frame) => match slot {
                    Slot::Scratch => drops = drops.saturating_add(1),
                    Slot::Pooled(f) if self.lossless => {
                        if self.tx.send(Msg::Frame(f)).is_err() {
                            return;
                        }
                    }
                    Slot::Pooled(f) => match self.tx.try_send(Msg::Frame(f)) {
                        Ok(()) => {}
                        Err(TrySendError::Full(m)) => {
                            drops = drops.saturating_add(1);
                            if let Msg::Frame(f) = m {
                                held = Some(f);
                            }
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    },
                },
                Ok(Next::Timeout) => {
                    if let Slot::Pooled(f) = slot {
                        held = Some(f);
                    }
                    if let Err(TrySendError::Disconnected(_)) = self.tx.try_send(Msg::Tick) {
                        return;
                    }
                }
                Ok(Next::End) => return self.end(drops),
                Err(e) => {
                    let _ = self.tx.send(Msg::Err(e));
                    return;
                }
            }
            if self.stop.load(Ordering::SeqCst) {
                return self.end(drops);
            }
            if last_stats.elapsed() >= SECOND {
                last_stats = Instant::now();
                let stats = Msg::Stats(self.source_stats(), drops);
                if let Err(TrySendError::Disconnected(_)) = self.tx.try_send(stats) {
                    return;
                }
            }
        }
    }

    /// A buffer the main thread handed back, else a new one while the pool
    /// is not full, else (recordings) the next one handed back, else (live)
    /// the scratch buffer. `None`: the main thread is gone.
    fn take_free(&self, allocated: &mut usize) -> Option<Slot> {
        match self.free.try_recv() {
            Ok(f) => Some(Slot::Pooled(f)),
            Err(TryRecvError::Disconnected) => None,
            Err(TryRecvError::Empty) if *allocated < self.buffers => {
                *allocated += 1;
                Some(Slot::Pooled(new_frame()))
            }
            Err(TryRecvError::Empty) if self.lossless => self.free.recv().ok().map(Slot::Pooled),
            Err(TryRecvError::Empty) => Some(Slot::Scratch),
        }
    }

    /// The last messages: the final counters, then `End`.
    fn end(&mut self, drops: u64) {
        let stats = Msg::Stats(self.source_stats(), drops);
        if self.tx.send(stats).is_ok() {
            let _ = self.tx.send(Msg::End);
        }
    }

    fn source_stats(&mut self) -> SourceStats {
        self.src.stats().unwrap_or_default()
    }
}

/// A buffer that grew past this many times the starting capacity (a 64 KiB
/// loopback frame) is replaced when it returns to the pool, so the pool as a
/// whole stays near its nominal size.
const MAX_KEPT_FACTOR: usize = 4;

fn trim_frame(mut f: Frame) -> Frame {
    if f.data.capacity() > MAX_KEPT_FACTOR * FRAME_CAPACITY {
        f.data = Vec::with_capacity(FRAME_CAPACITY);
    }
    f
}

fn new_frame() -> Frame {
    Frame {
        data: Vec::with_capacity(FRAME_CAPACITY),
        ..Frame::default()
    }
}

/// The main thread's state.
struct Main {
    rx: Receiver<Msg>,
    /// Hands buffers back to the capture thread.
    free: Sender<Frame>,
    stop: Arc<AtomicBool>,
    opts: PipelineOpts,
    /// The capture thread sent its last message (`End` or `Err`).
    capture_done: bool,
    /// The source ended and the run waits for the hook to stop it.
    lingering: bool,
    /// Recordings: the latest frame second, the engine's clock.
    frame_clock: Option<i64>,
    /// Cuts short a read the capture thread is blocked in.
    waker: Option<Waker>,
    /// `stop_capture` ran.
    stopping: bool,
}

impl Main {
    /// Sets `stop` and wakes the capture thread, so that it sees it soon.
    fn stop_capture(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if !self.stopping {
            self.stopping = true;
            if let Some(wake) = &self.waker {
                wake();
            }
        }
    }

    fn run(
        &mut self,
        engine: &mut Engine,
        r: &mut dyn Renderer,
        hook: &mut dyn FnMut(&mut Engine, &mut dyn Renderer) -> io::Result<Flow>,
    ) -> Result<RunEnd, RunError> {
        let mut last_hook = Instant::now();
        let mut last_tick = last_hook;
        loop {
            let wait = HOOK_PERIOD.saturating_sub(last_hook.elapsed());
            if self.lingering {
                if self.stop.load(Ordering::SeqCst) {
                    return Ok(RunEnd::Done);
                }
                thread::sleep(wait);
            } else {
                // Set from outside (a signal): the capture thread ends the
                // stream with `End` once it is awake.
                if !self.stopping && self.stop.load(Ordering::SeqCst) {
                    self.stop_capture();
                }
                match self.rx.recv_timeout(wait) {
                    Ok(msg) => {
                        if let Some(end) = self.handle(msg, engine, r) {
                            return end;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        self.capture_done = true;
                        return Err(RunError::Io(io::Error::other(
                            "the capture thread stopped unexpectedly",
                        )));
                    }
                }
            }
            let now = Instant::now();
            if self.opts.wall_clock && now.duration_since(last_tick) >= SECOND {
                last_tick = now;
                if let Err(e) = engine.tick(unix_now(), r) {
                    return io_end(e);
                }
            }
            if now.duration_since(last_hook) >= HOOK_PERIOD {
                last_hook = now;
                match hook(engine, r) {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Stop) => {
                        self.stop.store(true, Ordering::SeqCst);
                        return Ok(RunEnd::Done);
                    }
                    Err(e) => return io_end(e),
                }
            }
        }
    }

    /// Handles one message from the capture thread; `Some` ends the run.
    fn handle(
        &mut self,
        msg: Msg,
        engine: &mut Engine,
        r: &mut dyn Renderer,
    ) -> Option<Result<RunEnd, RunError>> {
        match msg {
            Msg::Frame(f) => {
                let done = self.frame(&f, engine, r);
                // Fails only when the capture thread is gone; then the buffer
                // is just freed.
                let _ = self.free.send(trim_frame(f));
                done.err().map(io_end)
            }
            Msg::Tick => None,
            Msg::Stats(s, drops) => {
                let now = if self.opts.wall_clock {
                    unix_now()
                } else {
                    self.frame_clock.unwrap_or(0)
                };
                engine.stats(s, drops, now, r).err().map(io_end)
            }
            Msg::End => {
                self.capture_done = true;
                self.lingering = self.opts.linger_after_end;
                (!self.lingering).then_some(Ok(RunEnd::Done))
            }
            Msg::Err(e) => {
                self.capture_done = true;
                Some(match e {
                    SourceError::Truncated(m) => Ok(RunEnd::Truncated(m)),
                    e => Err(RunError::Source(e)),
                })
            }
        }
    }

    fn frame(&mut self, f: &Frame, engine: &mut Engine, r: &mut dyn Renderer) -> io::Result<()> {
        // A recording's clock is its frames: tick whenever it reaches a new
        // second.
        if !self.opts.wall_clock && self.frame_clock.is_none_or(|t| f.ts_sec > t) {
            self.frame_clock = Some(f.ts_sec);
            engine.tick(f.ts_sec, r)?;
        }
        engine.frame(f, r)
    }
}

/// A failed write ends the run, quietly when the reader went away.
fn io_end(e: io::Error) -> Result<RunEnd, RunError> {
    if e.kind() == io::ErrorKind::BrokenPipe {
        Ok(RunEnd::Closed)
    } else {
        Err(RunError::Io(e))
    }
}

/// Wall-clock seconds since the epoch.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use jiff::tz::TimeZone;
    use overhear_decode::Decoded;

    use crate::engine::Config;
    use crate::render::{Status, TextOpts};
    use crate::source::{Frame, LinkType, Next, SourceError, SourceStats};
    use crate::time::TimeStyle;

    #[test]
    fn oversized_buffers_are_replaced_when_returned() {
        let mut big = new_frame();
        big.data.resize(64 * 1024, 7);
        big.ts_sec = 9;
        let back = trim_frame(big);
        assert!(back.data.is_empty() && back.data.capacity() <= MAX_KEPT_FACTOR * FRAME_CAPACITY);
        assert!(back.data.capacity() >= FRAME_CAPACITY);

        let mut ok = new_frame();
        ok.data.resize(MAX_KEPT_FACTOR * FRAME_CAPACITY, 1);
        let kept = trim_frame(ok);
        assert_eq!(
            kept.data.len(),
            MAX_KEPT_FACTOR * FRAME_CAPACITY,
            "kept as is"
        );
    }

    #[derive(Clone, Copy)]
    enum Step {
        Frame,
        Timeout,
        Truncated,
        /// Blocks until woken (as libpcap does on a quiet interface), then
        /// ends.
        Block,
    }

    /// What a test can see of a `FakeSource` after it moved to the capture
    /// thread.
    #[derive(Default)]
    struct Probe {
        produced: AtomicU32,
        dropped: AtomicBool,
    }

    /// Plays back a script of steps, sleeping `delay` before each read, then
    /// ends. Frame n carries n (little-endian) in its first four bytes.
    struct FakeSource {
        steps: Box<dyn Iterator<Item = Step> + Send>,
        delay: Duration,
        probe: Arc<Probe>,
        /// Given out by `waker` when the source has one.
        wake_tx: Option<mpsc::Sender<()>>,
        wake_rx: Receiver<()>,
    }

    impl Source for FakeSource {
        fn link_type(&self) -> LinkType {
            LinkType::Ethernet
        }

        fn next_into(&mut self, f: &mut Frame) -> Result<Next, SourceError> {
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            match self.steps.next() {
                Some(Step::Frame) => {
                    let n = self.probe.produced.fetch_add(1, Ordering::SeqCst);
                    f.data.clear();
                    f.data.extend_from_slice(&n.to_le_bytes());
                    f.data.resize(60, 0);
                    f.ts_sec = 1_700_000_000 + i64::from(n / 100);
                    f.ts_usec = 0;
                    f.orig_len = 60;
                    Ok(Next::Frame)
                }
                Some(Step::Timeout) => Ok(Next::Timeout),
                Some(Step::Truncated) => Err(SourceError::Truncated("cut".into())),
                Some(Step::Block) => match self.wake_rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(()) => Ok(Next::End),
                    Err(_) => panic!("blocked read never woken"),
                },
                None => Ok(Next::End),
            }
        }

        fn stats(&mut self) -> Option<SourceStats> {
            None
        }

        fn waker(&mut self) -> Option<Waker> {
            let tx = self.wake_tx.clone()?;
            Some(Box::new(move || {
                let _ = tx.send(());
            }))
        }
    }

    impl Drop for FakeSource {
        fn drop(&mut self) {
            // Late on purpose: `dropped` is only reliably set when
            // run_threaded returns if it joined the capture thread.
            thread::sleep(Duration::from_millis(20));
            self.probe.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn fake(
        steps: impl Iterator<Item = Step> + Send + 'static,
        delay: Duration,
    ) -> (Box<dyn Source>, Arc<Probe>) {
        fake_source(steps, delay, false)
    }

    /// A source with a waker.
    fn fake_wakeable(
        steps: impl Iterator<Item = Step> + Send + 'static,
    ) -> (Box<dyn Source>, Arc<Probe>) {
        fake_source(steps, Duration::ZERO, true)
    }

    fn fake_source(
        steps: impl Iterator<Item = Step> + Send + 'static,
        delay: Duration,
        wakeable: bool,
    ) -> (Box<dyn Source>, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        let (wake_tx, wake_rx) = mpsc::channel();
        let src = FakeSource {
            steps: Box::new(steps),
            delay,
            probe: Arc::clone(&probe),
            wake_tx: wakeable.then_some(wake_tx),
            wake_rx,
        };
        (Box::new(src), probe)
    }

    /// Records packet numbers and status lines; can sleep per packet and fail
    /// with BrokenPipe on its nth packet.
    #[derive(Default)]
    struct Rec {
        seqs: Vec<u32>,
        statuses: Vec<Status>,
        sleep: Duration,
        broken_pipe_on: Option<usize>,
    }

    impl Renderer for Rec {
        fn packet(&mut self, f: &Frame, _d: &Decoded<'_>) -> io::Result<()> {
            if self.broken_pipe_on == Some(self.seqs.len() + 1) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let mut n = [0u8; 4];
            n.copy_from_slice(f.data.get(..4).expect("frame number"));
            self.seqs.push(u32::from_le_bytes(n));
            if !self.sleep.is_zero() {
                thread::sleep(self.sleep);
            }
            Ok(())
        }

        fn status(&mut self, s: &Status) -> io::Result<()> {
            self.statuses.push(*s);
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
            max_memory: 1 << 20,
        })
    }

    fn opts(buffers: usize, wall_clock: bool) -> PipelineOpts {
        PipelineOpts {
            buffers,
            linger_after_end: false,
            wall_clock,
        }
    }

    fn frames(n: usize) -> impl Iterator<Item = Step> + Send {
        std::iter::repeat_n(Step::Frame, n)
    }

    fn keep_going() -> impl FnMut(&mut Engine, &mut dyn Renderer) -> io::Result<Flow> {
        |_: &mut Engine, _: &mut dyn Renderer| Ok(Flow::Continue)
    }

    #[test]
    fn processes_all_frames_in_order_then_ends() {
        let steps = frames(300)
            .chain(std::iter::once(Step::Timeout))
            .chain(frames(200));
        let (src, probe) = fake(steps, Duration::ZERO);
        let mut e = engine();
        let mut r = Rec::default();
        let stop = Arc::new(AtomicBool::new(false));
        let end = run_threaded(
            src,
            &mut e,
            &mut r,
            stop,
            opts(BUFFERS, false),
            &mut keep_going(),
        );
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        assert_eq!(r.seqs, (0..500).collect::<Vec<u32>>());
        let s = e.summary();
        assert_eq!(s.packets, 500);
        assert_eq!(s.channel_drops, 0);
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
    }

    #[test]
    fn stop_flag_ends_a_timeout_only_source() {
        let (src, probe) = fake(std::iter::repeat(Step::Timeout), Duration::from_millis(100));
        let mut e = engine();
        let mut r = Rec::default();
        let stop = Arc::new(AtomicBool::new(false));
        let mut calls = 0;
        let mut hook = |_: &mut Engine, _: &mut dyn Renderer| {
            calls += 1;
            Ok(if calls == 3 {
                Flow::Stop
            } else {
                Flow::Continue
            })
        };
        let t0 = Instant::now();
        let end = run_threaded(
            src,
            &mut e,
            &mut r,
            Arc::clone(&stop),
            opts(BUFFERS, true),
            &mut hook,
        );
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "took {:?}",
            t0.elapsed()
        );
        assert_eq!(calls, 3, "hook called after it returned Stop");
        assert!(stop.load(Ordering::SeqCst));
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
    }

    #[test]
    fn external_stop_wakes_a_blocked_source() {
        // A quiet live interface: the read never returns on its own.
        let steps = frames(2).chain(std::iter::once(Step::Block));
        let (src, probe) = fake_wakeable(steps);
        let mut e = engine();
        let mut r = Rec::default();
        let stop = Arc::new(AtomicBool::new(false));
        let setter = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                stop.store(true, Ordering::SeqCst);
            })
        };
        let t0 = Instant::now();
        let end = run_threaded(
            src,
            &mut e,
            &mut r,
            stop,
            opts(BUFFERS, true),
            &mut keep_going(),
        );
        setter.join().expect("setter");
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "took {:?}",
            t0.elapsed()
        );
        assert_eq!(r.seqs, vec![0, 1]);
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
    }

    #[test]
    fn hook_stop_wakes_a_blocked_source() {
        let (src, probe) = fake_wakeable(std::iter::once(Step::Block));
        let mut e = engine();
        let mut r = Rec::default();
        let stop = Arc::new(AtomicBool::new(false));
        let mut hook = |_: &mut Engine, _: &mut dyn Renderer| Ok(Flow::Stop);
        let t0 = Instant::now();
        let end = run_threaded(src, &mut e, &mut r, stop, opts(BUFFERS, true), &mut hook);
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "took {:?}",
            t0.elapsed()
        );
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
    }
    #[test]
    fn tiny_pool_counts_drops() {
        let (src, probe) = fake(frames(1000), Duration::ZERO);
        let mut e = engine();
        let mut r = Rec {
            sleep: Duration::from_millis(1),
            ..Rec::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let end = run_threaded(src, &mut e, &mut r, stop, opts(2, true), &mut keep_going());
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        let s = e.summary();
        assert!(s.channel_drops > 0, "{s:?}");
        assert_eq!(s.packets + s.channel_drops, 1000, "{s:?}");
        assert!(
            r.seqs.windows(2).all(|w| w[0] < w[1]),
            "out of order: {:?}",
            r.seqs
        );
        // The drops were reported as a status before the end.
        let last = r.statuses.last().expect("a status line");
        assert_eq!(last.channel_drops, s.channel_drops);
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
    }

    #[test]
    fn recording_waits_instead_of_dropping() {
        let (src, _probe) = fake(frames(200), Duration::ZERO);
        let mut e = engine();
        let mut r = Rec {
            sleep: Duration::from_millis(1),
            ..Rec::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let end = run_threaded(src, &mut e, &mut r, stop, opts(2, false), &mut keep_going());
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        assert_eq!(r.seqs, (0..200).collect::<Vec<u32>>());
        assert_eq!(e.summary().channel_drops, 0);
        assert!(r.statuses.is_empty());
    }

    #[test]
    fn hook_runs_at_least_every_60ms_under_load() {
        // Typically 50.0 ms (50.1 ms under qemu). A host with every core busy
        // can preempt this thread past the bound now and then, so the best of
        // three runs counts; a pipeline that calls the hook only when the
        // channel runs dry fails all three.
        let limit = Duration::from_millis(60);
        let mut runs = Vec::new();
        for _ in 0..3 {
            let gaps = hook_gaps_under_load();
            let max = gaps.iter().map(|g| g.0).max().expect("gaps");
            if max < limit {
                return;
            }
            runs.push(gaps);
        }
        panic!("largest gap at least {limit:?} in every run: {runs:?}");
    }

    /// 20 gaps between hook calls, each with the packet count at its end,
    /// while a source that never times out floods the pipeline.
    fn hook_gaps_under_load() -> Vec<(Duration, u64)> {
        let (src, probe) = fake(std::iter::repeat(Step::Frame), Duration::ZERO);
        let mut e = engine();
        let mut r = Rec::default();
        let stop = Arc::new(AtomicBool::new(false));
        // Ends the run should the hook stop being called.
        let watchdog = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let t0 = Instant::now();
                while t0.elapsed() < Duration::from_secs(10) && !stop.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(10));
                }
                stop.store(true, Ordering::SeqCst);
            })
        };
        let mut last: Option<Instant> = None;
        let mut gaps = Vec::new();
        let mut hook = |e: &mut Engine, _: &mut dyn Renderer| {
            let now = Instant::now();
            if let Some(prev) = last {
                gaps.push((now - prev, e.summary().packets));
            }
            last = Some(now);
            Ok(if gaps.len() == 20 {
                Flow::Stop
            } else {
                Flow::Continue
            })
        };
        let end = run_threaded(src, &mut e, &mut r, stop, opts(BUFFERS, true), &mut hook);
        watchdog.join().expect("watchdog");
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        assert_eq!(gaps.len(), 20, "the hook stopped being called");
        // Frames kept flowing the whole time.
        assert!(gaps.windows(2).all(|w| w[1].1 > w[0].1), "{gaps:?}");
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
        gaps
    }

    #[test]
    fn broken_pipe_returns_closed() {
        // An endless recording: the capture thread blocks on the full channel
        // and must still be stopped and joined.
        let (src, probe) = fake(std::iter::repeat(Step::Frame), Duration::ZERO);
        let mut e = engine();
        let mut r = Rec {
            broken_pipe_on: Some(3),
            ..Rec::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        let end = run_threaded(
            src,
            &mut e,
            &mut r,
            Arc::clone(&stop),
            opts(BUFFERS, false),
            &mut keep_going(),
        );
        assert!(matches!(end, Ok(RunEnd::Closed)), "{end:?}");
        assert_eq!(r.seqs, vec![0, 1]);
        assert!(stop.load(Ordering::SeqCst));
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
    }

    #[test]
    fn truncated_source_after_its_frames() {
        let steps = frames(3).chain(std::iter::once(Step::Truncated));
        let (src, probe) = fake(steps, Duration::ZERO);
        let mut e = engine();
        let mut r = Rec::default();
        let stop = Arc::new(AtomicBool::new(false));
        let end = run_threaded(
            src,
            &mut e,
            &mut r,
            stop,
            opts(BUFFERS, false),
            &mut keep_going(),
        );
        assert!(
            matches!(&end, Ok(RunEnd::Truncated(m)) if m == "cut"),
            "{end:?}"
        );
        assert_eq!(r.seqs, vec![0, 1, 2]);
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
    }

    #[test]
    fn external_stop_drains_queued_frames() {
        // A live trickle; stop is set from outside (as the signal handler
        // does). Every frame read before the stop is rendered or counted.
        let (src, probe) = fake(std::iter::repeat(Step::Frame), Duration::from_millis(1));
        let mut e = engine();
        let mut r = Rec::default();
        let stop = Arc::new(AtomicBool::new(false));
        let setter = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(150));
                stop.store(true, Ordering::SeqCst);
            })
        };
        let end = run_threaded(
            src,
            &mut e,
            &mut r,
            stop,
            opts(BUFFERS, true),
            &mut keep_going(),
        );
        setter.join().expect("setter");
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        let s = e.summary();
        assert!(s.packets > 0);
        assert_eq!(
            s.packets + s.channel_drops,
            u64::from(probe.produced.load(Ordering::SeqCst))
        );
        assert!(
            probe.dropped.load(Ordering::SeqCst),
            "capture thread not joined"
        );
    }

    #[test]
    fn linger_after_end_calls_hook_until_stop() {
        let (src, _probe) = fake(frames(5), Duration::ZERO);
        let mut e = engine();
        let mut r = Rec::default();
        let stop = Arc::new(AtomicBool::new(false));
        let mut calls = 0;
        let mut hook = |_: &mut Engine, _: &mut dyn Renderer| {
            calls += 1;
            Ok(if calls == 4 {
                Flow::Stop
            } else {
                Flow::Continue
            })
        };
        let o = PipelineOpts {
            linger_after_end: true,
            ..opts(BUFFERS, false)
        };
        let end = run_threaded(src, &mut e, &mut r, stop, o, &mut hook);
        assert!(matches!(end, Ok(RunEnd::Done)), "{end:?}");
        assert_eq!(calls, 4);
        assert_eq!(r.seqs, vec![0, 1, 2, 3, 4]);
    }
}
