//! Shared ownership of a tunnel device's file descriptor (MR-820).
//!
//! The Linux and macOS packet loops hand every TUN/utun read and write to
//! `spawn_blocking`, and those closures used to capture the RAW descriptor
//! number. Nothing tied the number's lifetime to theirs. `stop()` joined the
//! loop TASK, but a closure the loop had already handed to the blocking pool is
//! not part of that task: the loop's `select!` drops the read's JoinHandle when
//! the shutdown arm wins (detaching it, it does not cancel it), and the 5 s
//! abort does the same. `stop()` then closed the fd, and a closure that ran
//! after that read from — or wrote packet bytes into — whatever descriptor the
//! process opened next under the same number (a log file, a TLS socket).
//!
//! Now the descriptor is reference-counted. Every blocking closure holds a
//! clone for exactly as long as its syscall, so the number cannot be closed —
//! let alone recycled — under it, and the descriptor is closed exactly once, by
//! whichever holder lets go last. `stop()` closes through [`close_when_idle`],
//! which first waits (bounded) for those holders to finish: that wait IS the
//! join of the in-flight read/write, and it is what makes the device actually
//! gone when `stop()` returns (Linux re-creates `birdo0` by name on the next
//! start). The last-resort `Drop` paths just let go of their reference: they
//! cannot wait, and with shared ownership they no longer need to.
//!
//! Generic over the owned value so the close protocol is tested on every
//! platform, the Windows job included, with a stand-in that records its drop.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

/// The descriptor as the packet loop and its blocking closures share it.
#[cfg(unix)]
pub(crate) type SharedFd = Arc<std::os::fd::OwnedFd>;

/// Where a tunnel keeps its device between `start()` and `stop()`.
pub(crate) type DeviceSlot<T> = RwLock<Option<Arc<T>>>;

/// How long `stop()` waits for in-flight I/O to let go of the device. The fd
/// is O_NONBLOCK ([`set_nonblocking`] is fatal on failure) and the loop is
/// already joined when this runs, so a holder is a syscall that is about to
/// return; the bound only matters if it is not.
pub(crate) const IN_FLIGHT_WAIT: Duration = Duration::from_secs(2);

/// Put a device fd in O_NONBLOCK mode, or say why not.
///
/// The wait in [`close_when_idle`] assumes every read/write on the device
/// returns at once. A BLOCKING read on an idle device would hold its reference
/// for good: a Deferred close, the device alive — and on Linux the next
/// start's TUNSETIFF on `birdo0` failing with EBUSY. So the tunnels treat a
/// failure here as fatal rather than warning and carrying on.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl(2) on a descriptor number; an invalid one fails (EBADF),
    // it does not touch memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// How often [`close_when_idle`] re-checks for remaining holders.
const POLL: Duration = Duration::from_millis(5);

/// What [`close_when_idle`] did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CloseOutcome {
    /// The slot was empty: never opened, or already closed.
    Empty,
    /// Ours was the last reference, and the device is closed.
    Closed,
    /// In-flight I/O still held the device when the wait ran out. Our
    /// reference is gone; the last holder closes the device when its syscall
    /// returns — never earlier, so never on a recycled number, and never twice.
    Deferred,
}

/// Close the device in `slot` once no in-flight I/O holds it, waiting at most
/// `wait` for that.
///
/// The device stays IN the slot across every await, and is taken and released
/// with no await in between (the N7 rule in tunnel_macos.rs). A caller that is
/// cancelled mid-wait — the manager caps a teardown and drops the future —
/// therefore leaves it where the tunnel's `Drop` finds it.
pub(crate) async fn close_when_idle<T>(slot: &DeviceSlot<T>, wait: Duration) -> CloseOutcome {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        {
            let mut guard = slot.write().await;
            let Some(device) = guard.as_ref() else {
                return CloseOutcome::Empty;
            };
            if Arc::strong_count(device) == 1 || tokio::time::Instant::now() >= deadline {
                let Some(device) = guard.take() else {
                    return CloseOutcome::Empty;
                };
                // A holder can still appear between the count and here (an
                // aborted loop that has not been dropped yet), so the unwrap
                // decides, not the count.
                return match Arc::try_unwrap(device) {
                    Ok(owned) => {
                        drop(owned);
                        CloseOutcome::Closed
                    }
                    Err(_shared) => CloseOutcome::Deferred,
                };
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Stands in for `OwnedFd`: counts how many times it was "closed".
    struct Device {
        closes: Arc<AtomicUsize>,
    }

    impl Drop for Device {
        fn drop(&mut self) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn slot_with_device() -> (DeviceSlot<Device>, Arc<AtomicUsize>) {
        let closes = Arc::new(AtomicUsize::new(0));
        let device = Device {
            closes: Arc::clone(&closes),
        };
        (RwLock::new(Some(Arc::new(device))), closes)
    }

    /// A blocking "syscall" holding its own reference for `hold`, as the
    /// packet loop's spawn_blocking closures do. Returns whether the device was
    /// ever closed while the syscall was still using it.
    fn in_flight_io(
        slot: &DeviceSlot<Device>,
        closes: &Arc<AtomicUsize>,
        hold: Duration,
    ) -> std::thread::JoinHandle<bool> {
        let held = Arc::clone(slot.try_read().unwrap().as_ref().unwrap());
        let closes = Arc::clone(closes);
        let started = Arc::new(AtomicBool::new(false));
        let started_in_thread = Arc::clone(&started);
        let handle = std::thread::spawn(move || {
            started_in_thread.store(true, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + hold;
            let mut closed_under_us = false;
            while std::time::Instant::now() < deadline {
                closed_under_us |= closes.load(Ordering::SeqCst) != 0;
                std::thread::sleep(Duration::from_millis(2));
            }
            closed_under_us |= closes.load(Ordering::SeqCst) != 0;
            drop(held);
            closed_under_us
        });
        while !started.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        handle
    }

    #[tokio::test]
    async fn nothing_in_flight_closes_at_once() {
        let (slot, closes) = slot_with_device();
        assert_eq!(
            close_when_idle(&slot, IN_FLIGHT_WAIT).await,
            CloseOutcome::Closed
        );
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert!(slot.read().await.is_none());
    }

    /// The regression: the old stop() closed while a detached read could still
    /// be running. The close must now wait for the in-flight op to let go, and
    /// the op must never observe the device closed under it.
    #[tokio::test]
    async fn the_close_waits_for_in_flight_io_and_never_closes_under_it() {
        let (slot, closes) = slot_with_device();
        let io = in_flight_io(&slot, &closes, Duration::from_millis(150));
        let started = std::time::Instant::now();

        let outcome = close_when_idle(&slot, IN_FLIGHT_WAIT).await;

        assert_eq!(outcome, CloseOutcome::Closed);
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "close_when_idle returned before the in-flight op let go"
        );
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert!(
            !io.join().unwrap(),
            "the device was closed while an in-flight op still used it"
        );
    }

    /// Past the wait, the close is handed to the last holder: never on a
    /// number still in use, and exactly once.
    #[tokio::test]
    async fn past_the_wait_the_last_holder_closes_exactly_once() {
        let (slot, closes) = slot_with_device();
        let io = in_flight_io(&slot, &closes, Duration::from_millis(300));

        let outcome = close_when_idle(&slot, Duration::from_millis(20)).await;

        assert_eq!(outcome, CloseOutcome::Deferred);
        assert!(slot.read().await.is_none(), "our reference is released");
        assert_eq!(
            closes.load(Ordering::SeqCst),
            0,
            "closed while the op still held it"
        );
        assert!(!io.join().unwrap());
        assert_eq!(
            closes.load(Ordering::SeqCst),
            1,
            "the last holder closes it once"
        );
    }

    /// N7: a stop() dropped mid-wait (the manager's teardown cap) must leave
    /// the device in the slot for the tunnel's Drop, not in nobody's hands.
    #[tokio::test]
    async fn a_cancelled_close_leaves_the_device_in_the_slot() {
        let (slot, closes) = slot_with_device();
        let io = in_flight_io(&slot, &closes, Duration::from_millis(200));

        let cancelled = tokio::time::timeout(
            Duration::from_millis(30),
            close_when_idle(&slot, IN_FLIGHT_WAIT),
        )
        .await;

        assert!(cancelled.is_err(), "the close was still waiting");
        assert!(slot.read().await.is_some(), "the device left the slot");
        assert!(!io.join().unwrap());
        assert_eq!(closes.load(Ordering::SeqCst), 0);
        // What the tunnel's Drop then does: let go of the last reference.
        drop(slot.write().await.take());
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_empty_slot_is_left_alone() {
        let slot: DeviceSlot<Device> = RwLock::new(None);
        assert_eq!(
            close_when_idle(&slot, IN_FLIGHT_WAIT).await,
            CloseOutcome::Empty
        );
    }
}
