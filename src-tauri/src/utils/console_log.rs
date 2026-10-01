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

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;

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
    fn with_output<W, F>(mut output: F) -> Self
    where
        W: Write,
        F: FnMut() -> W + Send + 'static,
    {
        let (queue, lines) = sync_channel::<Vec<u8>>(QUEUE_LINES);
        let dropped = Arc::new(AtomicU64::new(0));
        let lost = Arc::clone(&dropped);
        // If the thread cannot be started, the queue's receiver is gone and
        // every line counts as dropped: no console output, never a block.
        let _ = std::thread::Builder::new()
            .name("birdo-console-log".into())
            .spawn(move || {
                for line in lines {
                    let mut out = output();
                    let missed = lost.swap(0, Ordering::Relaxed);
                    if missed > 0 {
                        let _ = writeln!(
                            out,
                            "({missed} log lines were not shown: the console was not taking output)"
                        );
                    }
                    let _ = out.write_all(&line);
                    let _ = out.flush();
                }
            });
        Self { queue, dropped }
    }
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
}
