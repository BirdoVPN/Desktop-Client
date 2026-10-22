//! The console log sink, written by its own thread (WIN-FIX-3 P0).
//!
//! WHY. A console write is synchronous, and a console can stop taking output
//! for as long as it likes: a QuickEdit selection in a console window pauses
//! every writer until it is cleared, as do the Pause key and a paused
//! terminal, and a stdout pipe nobody reads blocks once its buffer is full.
//! The fmt layer writes from whichever thread logs, and some of those threads
//! hold locks while they do: boringtun logs `HANDSHAKE(REKEY_TIMEOUT)` every
//! 5 s, while a relay is silent, from inside the session lock the packet path
//! needs. A console that stopped taking output froze the tunnel with it (T5,
//! 2026-10-01), and every other thread that logged queued behind the paused
//! write.
//!
//! So a logging thread only queues the line; one thread of its own writes it,
//! and when the queue is full the line is dropped and counted. The console is
//! a developer's view: `birdo.log` is the record and keeps its own
//! synchronous writer. Release builds have no console at all (the Windows
//! GUI subsystem), so this matters for debug builds — the ones the live tests
//! run.
//!
//! MR-690: with one exception. boringtun's own lines are logged from inside
//! the session lock, and a `birdo.log` write that stalls (a full or
//! disconnected volume, an AV filter holding the file) stalled the packet path
//! with it, caught only by the 10–15 s stall rule. The file layer therefore
//! hands lines from boringtun's targets ([`logs_under_a_lock`]) to a queue of
//! the same kind, written to `birdo.log` by a thread of its own
//! ([`lock_free_for_boringtun`]); every other line is written as before. The
//! default filter does not enable boringtun at all; this is what keeps a
//! `RUST_LOG` that does from reaching into the packet path.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;

use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::fmt::MakeWriter;

/// Lines held for the console thread. Generous: the console only falls this
/// far behind when it has stopped taking output altogether.
const QUEUE_LINES: usize = 1024;

/// The console sink: a `MakeWriter` whose writers never block.
#[derive(Clone)]
pub struct ConsoleLog {
    queue: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
}

impl ConsoleLog {
    /// Writes to stdout.
    pub fn stdout() -> Self {
        Self::with_output(io::stdout)
    }

    /// Writes to whatever `output` returns, once per line.
    fn with_output<W, F>(output: F) -> Self
    where
        W: Write,
        F: FnMut() -> W + Send + 'static,
    {
        Self::queued("birdo-console-log", "the console", output)
    }

    /// A queue of lines that `output` takes, once per line, on a thread of
    /// its own named `thread`; `sink` names it in the note about lines that
    /// had to be dropped.
    pub fn queued<W, F>(thread: &str, sink: &'static str, mut output: F) -> Self
    where
        W: Write,
        F: FnMut() -> W + Send + 'static,
    {
        let (queue, lines) = sync_channel::<Vec<u8>>(QUEUE_LINES);
        let dropped = Arc::new(AtomicU64::new(0));
        let lost = Arc::clone(&dropped);
        // If the thread cannot be started, the queue's receiver is gone and
        // every line counts as dropped: no output, never a block.
        let _ = std::thread::Builder::new()
            .name(thread.into())
            .spawn(move || {
                for line in lines {
                    let mut out = output();
                    let missed = lost.swap(0, Ordering::Relaxed);
                    if missed > 0 {
                        let _ = writeln!(
                            out,
                            "({missed} log lines were not shown: {sink} was not taking output)"
                        );
                    }
                    let _ = out.write_all(&line);
                    let _ = out.flush();
                }
            });
        Self { queue, dropped }
    }
}

/// MR-690: is this line logged from inside a lock the packet path needs?
/// boringtun logs its timer and handshake events (`HANDSHAKE(REKEY_TIMEOUT)`
/// every 5 s while a relay is silent) while it holds the session lock.
pub fn logs_under_a_lock(meta: &tracing::Metadata<'_>) -> bool {
    let target = meta.target();
    target == "boringtun" || target.starts_with("boringtun::")
}

/// MR-690: `birdo.log`'s writer: the lines [`logs_under_a_lock`] picks go to
/// `queued` (written by its own thread, never waited for), every other line to
/// `file` as before.
pub fn lock_free_for_boringtun<F>(
    queued: ConsoleLog,
    file: F,
) -> impl for<'a> MakeWriter<'a> + Send + Sync + 'static
where
    F: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    queued
        .with_filter(logs_under_a_lock as fn(&tracing::Metadata<'_>) -> bool)
        .or_else(file)
}

/// One event's bytes, queued for the console thread when the fmt layer is
/// done with it.
pub struct ConsoleLine<'a> {
    sink: &'a ConsoleLog,
    line: Vec<u8>,
}

impl Write for ConsoleLine<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.line.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ConsoleLine<'_> {
    fn drop(&mut self) {
        if self.line.is_empty() {
            return;
        }
        if self
            .sink
            .queue
            .try_send(std::mem::take(&mut self.line))
            .is_err()
        {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl<'a> MakeWriter<'a> for ConsoleLog {
    type Writer = ConsoleLine<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        ConsoleLine {
            sink: self,
            line: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// A console that has stopped taking output: every write waits until the
    /// test lets it go.
    struct Paused {
        gate: Arc<std::sync::Mutex<mpsc::Receiver<()>>>,
        written: Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl Write for Paused {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.gate.lock().unwrap().recv();
            self.written.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The P0's trigger, at the sink: with the console paused, logging
    /// threads keep going. With the stdout writer the fmt layer used before,
    /// the first line written here would wait for as long as the console
    /// stays paused — and every thread logging after it, behind stdout's lock.
    #[test]
    fn a_paused_console_never_holds_up_a_logging_thread() {
        let (release, gate) = mpsc::channel::<()>();
        let gate = Arc::new(std::sync::Mutex::new(gate));
        let written = Arc::new(std::sync::Mutex::new(Vec::new()));
        let console = {
            let (gate, written) = (Arc::clone(&gate), Arc::clone(&written));
            ConsoleLog::with_output(move || Paused {
                gate: Arc::clone(&gate),
                written: Arc::clone(&written),
            })
        };

        let started = Instant::now();
        for i in 0..(QUEUE_LINES * 3) {
            let mut w = console.make_writer();
            writeln!(w, "HANDSHAKE(REKEY_TIMEOUT) {i}").unwrap();
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a logging thread waited for the console"
        );
        assert!(
            console.dropped.load(Ordering::Relaxed) > 0,
            "past the queue, lines are dropped and counted"
        );

        // The console comes back: what was queued reaches it, then the count
        // with the next line. That line is offered until there is room for
        // it — the backlog drains at the console's pace, not the test's.
        drop(release);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = String::from_utf8_lossy(&written.lock().unwrap()).to_string();
            if text.contains("after") {
                assert!(text.contains("HANDSHAKE(REKEY_TIMEOUT) 0"), "{text}");
                assert!(text.contains("log lines were not shown"), "{text}");
                break;
            }
            assert!(Instant::now() < deadline, "the console never caught up");
            writeln!(console.make_writer(), "after").unwrap();
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The pin on the wiring: the console layer writes through this sink, so
    /// no `tracing` call anywhere in the app can wait on the console.
    #[test]
    fn the_console_layer_writes_through_the_queue() {
        let main_rs = include_str!("../main.rs");
        assert!(
            main_rs.contains(".with_writer(crate::utils::console_log::ConsoleLog::stdout())"),
            "the console fmt layer must not write to stdout from the logging thread"
        );
        assert_eq!(
            main_rs.matches("tracing_subscriber::fmt::layer()").count(),
            2,
            "one console layer and one file layer, each with its own writer"
        );
    }

    /// A shared buffer standing in for a `birdo.log` that takes every line.
    #[derive(Clone, Default)]
    struct Taken(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Taken {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// MR-690, the residual of the P0: boringtun logs from inside the session
    /// lock the packet path needs, and its lines reached `birdo.log` through
    /// the file layer's synchronous writer — a file that stopped taking
    /// output froze the tunnel until the stall rule rebuilt it. Through the
    /// file layer's writer as `main.rs` builds it, boringtun's lines never
    /// wait for a stalled file; every other line still goes to the file
    /// directly, and none of boringtun's does.
    #[test]
    fn lines_logged_under_boringtuns_lock_never_wait_for_the_file() {
        use tracing_subscriber::layer::SubscriberExt;

        // The queue's own "birdo.log" has stopped taking output.
        let (release, gate) = mpsc::channel::<()>();
        let gate = Arc::new(std::sync::Mutex::new(gate));
        let stalled = Arc::new(std::sync::Mutex::new(Vec::new()));
        let queued = {
            let (gate, stalled) = (Arc::clone(&gate), Arc::clone(&stalled));
            ConsoleLog::queued("birdo-test-file-log", "birdo.log", move || Paused {
                gate: Arc::clone(&gate),
                written: Arc::clone(&stalled),
            })
        };
        let file = Taken::default();
        let writer = lock_free_for_boringtun(queued, {
            let file = file.clone();
            move || file.clone()
        });
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer),
        );

        tracing::subscriber::with_default(subscriber, || {
            let started = Instant::now();
            for i in 0..(QUEUE_LINES * 3) {
                tracing::warn!(target: "boringtun::noise::timers", "HANDSHAKE(REKEY_TIMEOUT) {i}");
            }
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "a line logged under boringtun's lock waited for birdo.log"
            );
            tracing::warn!(target: "birdo_vpn_desktop::vpn::manager", "our own line");
            // Only boringtun's own targets: a name that merely starts alike
            // is not one of them.
            tracing::warn!(target: "boringtunnel", "a lookalike target");
        });

        let direct = String::from_utf8_lossy(&file.0.lock().unwrap()).to_string();
        assert!(direct.contains("our own line"), "{direct}");
        assert!(direct.contains("a lookalike target"), "{direct}");
        assert!(
            !direct.contains("REKEY_TIMEOUT"),
            "a boringtun line was written by the logging thread: {direct}"
        );

        // The file comes back: what was queued reaches it.
        drop(release);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !String::from_utf8_lossy(&stalled.lock().unwrap()).contains("REKEY_TIMEOUT) 0") {
            assert!(
                Instant::now() < deadline,
                "the queued lines never reached the file"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// MR-690: the pin on the wiring: `birdo.log`'s fmt layer writes through
    /// [`lock_free_for_boringtun`].
    #[test]
    fn the_file_layer_queues_boringtuns_lines() {
        let main_rs = include_str!("../main.rs").replace('\r', "");
        assert!(
            main_rs.contains(".with_writer(crate::utils::console_log::lock_free_for_boringtun("),
            "birdo.log's fmt layer writes boringtun's lines from the thread that logged them"
        );
    }
}
