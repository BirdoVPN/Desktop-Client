//! The emergency cleanup a tunnel dropped still holding machine state hands to
//! a thread of its own, and the waits for it (MR-823 on Windows, MR-2039 on
//! Linux).
//!
//! A tunnel's `Drop` is the last-resort teardown: a start() cancelled by the
//! manager's CONNECT_TIMEOUT, or a stop() the manager gave up on, drops the
//! tunnel with routes and DNS still installed. That cleanup spawns
//! subprocesses (netsh and ipconfig on Windows; `ip route del` and
//! `resolvectl` on Linux) and rewrites files, each of which can take seconds.
//! Run inline, it blocked whatever thread dropped the tunnel — a Tokio worker,
//! and every task queued on it, for the whole run. So it runs on a thread of
//! its own and is counted while it does: each platform's `start()` refuses to
//! set up a new tunnel underneath one, and the manager waits for it (bounded)
//! before it lifts the IPv6 block after a failed build and before it
//! publishes `Disconnected` (MR-2036).
//!
//! macOS hands nothing off (its `Drop` is unchanged), so its count stays zero
//! and every wait here returns at once.

#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Marks a `start()` refused because an emergency cleanup was still running
/// (MR-823, MR-2039). Not a handshake marker, so it surfaces as
/// AdapterFailed, which is retryable.
pub(crate) const ERR_EMERGENCY_CLEANUP_RUNNING: &str =
    "the previous tunnel is still being cleaned up";

/// The cleanups one platform's tunnels hand off, and the longest one can take.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InFlight {
    /// Cleanups handed to their own thread and not finished yet.
    pub(crate) count: &'static AtomicUsize,
    /// The longest one cleanup is expected to take: what a wait for them is
    /// bounded by (a cleanup past it is left running, see each platform's).
    pub(crate) bound: Duration,
}

impl InFlight {
    /// Wait up to [`InFlight::bound`] for every cleanup counted here to
    /// finish. Returns whether none is left.
    pub(crate) async fn settled(&self) -> bool {
        settled(self.count, self.bound).await
    }
}

/// Run a dropped tunnel's emergency cleanup off the dropping thread, counted
/// in `in_flight` until it ends.
///
/// - Inside a Tokio runtime — the case that matters: a worker dropping a
///   half-built tunnel — it runs on a dedicated thread and `Drop` returns at
///   once.
/// - Outside a runtime there is no async worker to stall, and the usual
///   reason is process exit (the runtime is already gone), where a detached
///   thread would be killed mid-cleanup. It runs inline, to completion.
/// - If the thread cannot be started it runs inline too: blocking a worker is
///   the lesser harm than skipping the cleanup.
pub(crate) fn dispatch(in_flight: &'static AtomicUsize, teardown: impl FnOnce() + Send + 'static) {
    if tokio::runtime::Handle::try_current().is_err() {
        teardown();
        return;
    }

    /// Counts the cleanup as in flight until its thread ends, however it ends
    /// (a panic included), or until a failed spawn drops it unrun.
    struct Counted(&'static AtomicUsize);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    in_flight.fetch_add(1, Ordering::SeqCst);
    let counted = Counted(in_flight);

    // Shared so a failed spawn can still run it: `spawn` drops its closure.
    let job = Arc::new(std::sync::Mutex::new(Some(teardown)));
    let for_thread = Arc::clone(&job);
    let spawned = std::thread::Builder::new()
        .name("birdo-emergency-teardown".to_string())
        .spawn(move || {
            let _counted = counted;
            let teardown = for_thread.lock().ok().and_then(|mut t| t.take());
            if let Some(teardown) = teardown {
                teardown();
            }
        });
    if let Err(e) = spawned {
        tracing::warn!("Could not start the emergency-cleanup thread ({e}) — running it inline");
        let teardown = job.lock().ok().and_then(|mut t| t.take());
        if let Some(teardown) = teardown {
            teardown();
        }
    }
}

/// Wait up to `limit` for the cleanups counted in `in_flight` to finish.
/// Returns whether none is left.
pub(crate) async fn settled(in_flight: &AtomicUsize, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while in_flight.load(Ordering::SeqCst) > 0 {
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                "A dropped tunnel's emergency cleanup is still running after {:?}",
                limit
            );
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// Run on every platform (the Windows job included): the hand-off and the
/// wait are what both tunnels' `Drop` and the manager rely on.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    /// Inside a runtime the cleanup is handed off, counted while it runs, and
    /// the wait sees it finish.
    #[tokio::test]
    async fn inside_a_runtime_the_cleanup_runs_on_its_own_thread_and_is_counted() {
        static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let started = Instant::now();
        dispatch(&IN_FLIGHT, move || {
            std::thread::sleep(Duration::from_millis(300));
            flag.store(true, Ordering::SeqCst);
        });
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "the dispatch waited for the cleanup"
        );
        assert!(!ran.load(Ordering::SeqCst), "the cleanup ran inline");
        assert_eq!(IN_FLIGHT.load(Ordering::SeqCst), 1);

        let pending = InFlight {
            count: &IN_FLIGHT,
            bound: Duration::from_secs(10),
        };
        assert!(pending.settled().await, "the cleanup never finished");
        assert!(ran.load(Ordering::SeqCst));
    }

    /// Process exit: no runtime left, so the cleanup runs inline and is done
    /// when the dispatch returns — a detached thread would be killed.
    #[test]
    fn without_a_runtime_the_cleanup_runs_inline() {
        static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        dispatch(&IN_FLIGHT, move || flag.store(true, Ordering::SeqCst));
        assert!(ran.load(Ordering::SeqCst));
        assert_eq!(IN_FLIGHT.load(Ordering::SeqCst), 0);
    }

    /// The wait is bounded: a cleanup that never ends costs the bound, and
    /// the answer says it is still running.
    #[tokio::test]
    async fn the_wait_gives_up_at_its_bound() {
        static STUCK: AtomicUsize = AtomicUsize::new(1);
        let started = Instant::now();
        assert!(!settled(&STUCK, Duration::from_millis(100)).await);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
