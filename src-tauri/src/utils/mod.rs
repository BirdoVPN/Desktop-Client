//! Utility modules

// MR-654: macOS/Linux "delete the application data" (--with-app-data).
#[cfg(unix)]
pub mod app_data_removal;
pub mod console_log;
pub mod crash_report;
pub mod device_id;
pub mod elevation;
pub mod file_log;
pub mod log_policy;
pub mod log_retention;
pub mod navigation_guard;
pub mod os_rng;
#[cfg(windows)]
pub mod protected_dir;
pub mod redact;
#[cfg(unix)]
pub mod root_state;
pub mod safe_fs;
pub mod webview2;
#[cfg(windows)]
pub mod win_api;

/// Source-level guard that no address-shaped value reaches a logging macro
/// unredacted. Test-only: it reads the tree rather than running in the app.
#[cfg(test)]
mod log_hygiene;

pub use redact::redact_email;
pub use redact::redact_endpoint;
pub use redact::redact_ip;

/// Fails to compile if `$ty` implements any of the listed traits: a negative
/// trait bound, which Rust cannot state directly. Two blanket impls of one
/// generic trait make `<$ty as AmbiguousIfImpl<_>>` ambiguous exactly when
/// `$ty` implements a listed trait. This is the `static_assertions` crate's
/// `assert_not_impl_any!`, written out here instead of added as a dependency.
///
/// MR-822 uses it to keep the WireGuard private key, and the tunnel config it
/// used to live in, from becoming `Clone` or serializable again.
macro_rules! assert_not_impl_any {
    ($ty:ty: $($trait_:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $({
                #[allow(dead_code)]
                struct Invalid;
                impl<T: ?Sized + $trait_> AmbiguousIfImpl<Invalid> for T {}
            })+
            let _ = <$ty as AmbiguousIfImpl<_>>::some_item;
        };
    };
}
pub(crate) use assert_not_impl_any;

/// Create a `std::process::Command` that runs hidden on Windows (no console popup).
///
/// On Windows, subprocesses launched from a GUI app inherit the parent's console
/// allocation. Since Birdo VPN runs as a GUI app with `#![windows_subsystem = "windows"]`,
/// every `Command::new("netsh" | "powershell" | "route" | ...)` would flash a visible
/// CMD window to the user. `CREATE_NO_WINDOW` (0x0800_0000) suppresses this.
///
/// On non-Windows platforms, this returns a plain `Command`.
pub fn hidden_cmd(program: &str) -> std::process::Command {
    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut cmd = std::process::Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// `hidden_cmd`'s async twin, for subprocesses run from async code (W1-017).
///
/// A `std::process::Command` awaited nowhere blocks a runtime worker for as
/// long as the child runs, and no `tokio::time::timeout` around it can fire.
/// Pair this with [`run_bounded`], which kills the child on timeout.
pub fn hidden_async_cmd(program: &str) -> tokio::process::Command {
    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut cmd = tokio::process::Command::new(program);
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Run `cmd` to completion within `limit`. The child is killed if the limit
/// passes or the caller is cancelled (`kill_on_drop`), so nothing it does can
/// outlive the step that started it.
pub async fn run_bounded(
    cmd: &mut tokio::process::Command,
    limit: std::time::Duration,
) -> Result<std::process::Output, String> {
    cmd.kill_on_drop(true).stdin(std::process::Stdio::null());
    match tokio::time::timeout(limit, cmd.output()).await {
        Ok(result) => result.map_err(|e| e.to_string()),
        Err(_) => Err(format!("timed out after {limit:?}")),
    }
}

/// [`run_bounded`]'s twin for blocking code: run `cmd` to completion within
/// `limit`, killing the child if it has not exited by then. For short-output
/// tools (the pipes are drained once the child exits, so a child that fills
/// one first would read as hung and be cut off at the limit).
// Called on Windows (schtasks, the emergency cleanup's netsh) and on Linux
// (the teardown's `ip route` and `resolvectl revert`, MR-2039); nothing on
// macOS calls it.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn output_within(
    cmd: &mut std::process::Command,
    limit: std::time::Duration,
) -> Result<std::process::Output, String> {
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().map_err(|e| e.to_string()),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {limit:?}"));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(e.to_string());
            }
        }
    }
}

/// Run blocking `work` with `lock` held, on tokio's blocking pool instead of
/// the async worker that awaits it (MR-2000: the Linux kill switch's
/// iptables runs, each a process spawn, dozens to an activation).
///
/// The guard goes INTO the blocking task. Held across the await instead, it
/// would be released by a caller cancelled while `work` runs, and the next
/// holder would start while `work` is still going. `Err` only if the runtime
/// shut down before `work` ran; a panic in `work` is resumed here.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // the Linux kill switch is its one caller
pub async fn locked_blocking<T: Send + 'static>(
    lock: &'static tokio::sync::Mutex<()>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let held = lock.lock().await;
    let task = tokio::task::spawn_blocking(move || {
        let _held = held;
        work()
    });
    match task.await {
        Ok(done) => Ok(done),
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => Err(format!("the work did not run: {e}")),
    }
}

/// Run `work` on a thread of its own and wait for it at most `limit`; `true`
/// if it finished. Whatever `work` waits on — a lock a wedged teardown holds,
/// a log write that does not return — holds that thread, never the caller
/// past `limit` (WIN3-006: the exit fallback must exit).
pub fn run_on_helper_for(
    name: &str,
    limit: std::time::Duration,
    work: impl FnOnce() + Send + 'static,
) -> bool {
    let (done, finished) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            work();
            let _ = done.send(());
        });
    spawned.is_ok() && finished.recv_timeout(limit).is_ok()
}

/// The exit fallback's decision (WIN-FIX-3, WIN3-006), apart from `main.rs`
/// so a test can drive it: unless `done` says the exit teardown ran to its
/// end, give `cleanup` — the log line and the DNS restore, either of which
/// can wait on what a wedged teardown holds — at most `limit` on a helper
/// thread ([`run_on_helper_for`]), then `exit`. Returns whether it exited
/// (`exit` never returns in the app).
pub fn exit_unless_torn_down(
    done: &std::sync::atomic::AtomicBool,
    limit: std::time::Duration,
    cleanup: impl FnOnce() + Send + 'static,
    exit: impl FnOnce(),
) -> bool {
    if done.load(std::sync::atomic::Ordering::SeqCst) {
        return false;
    }
    run_on_helper_for("birdo-exit-cleanup", limit, cleanup);
    exit();
    true
}

/// MR-1934: the exit teardown for an exit that never asked first, apart from
/// `main.rs` so a test can drive it. On macOS, Cmd+Q, the Dock's Quit and
/// logging out reach the end of the run (`RunEvent::Exit`, tao's
/// `applicationWillTerminate`) with no `ExitRequested` before it, so the
/// teardown that request holds the exit open for never ran, and the pf block
/// and the DNS the session set outlived the app. Unless `started` says it
/// already ran (claimed here, so it runs once), `teardown` runs on a helper
/// thread ([`run_on_helper_for`]) and the caller waits for it at most
/// `limit`: whatever it waits on, the process still ends. `None` when the
/// teardown had already started, else whether it finished in time. (Not on
/// Windows, where that exit keeps the session for the next version, MR-1861.)
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub fn tear_down_unless_started(
    started: &std::sync::atomic::AtomicBool,
    limit: std::time::Duration,
    teardown: impl FnOnce() + Send + 'static,
) -> Option<bool> {
    if started.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return None;
    }
    Some(run_on_helper_for("birdo-exit-teardown", limit, teardown))
}

/// This install's device identifier: a random `desktop_<uuid-v4>`, persisted
/// per install and rotated on account deletion (not on sign-out). See
/// `utils::device_id` for why it is no longer derived from the machine.
///
/// This is the ONE device identity the desktop client presents — SSO handoff,
/// anonymous register/login, email+password login and every connect body send
/// this exact value, so every sign-in on this install lands on the same
/// `(userId, deviceId)` row in the account's device list. It survives an app
/// update and a restart (the file is read back), so the backend can reclaim
/// this install's own slot at connect time.
pub fn get_device_id() -> String {
    device_id::get()
}

/// Human-readable name for this machine, shown in the account's device list
/// ("Revoke Windows Desktop (a1b2c3)"). Lives here next to `get_device_id`
/// because every auth payload that carries the id also carries this label —
/// they have to be derived from the same place or a login can relabel the row
/// a registration just named. `commands::vpn::get_device_name` delegates here.
///
/// SEC-PII: this used to be the raw machine hostname, which on consumer
/// Windows/macOS routinely embeds the owner's real name ("Johns-MacBook-Pro"),
/// converting a pseudonymous (or anonymous-plan) account into a named one on
/// every connect and auth call. Now a generic platform label — the shape
/// Android already uses (Build.MANUFACTURER + MODEL, never the hostname) —
/// plus a short prefix of the device id so a user with several machines can
/// still tell the rows apart. The backend already receives that id in full
/// beside this label, so the suffix transmits zero new information.
pub fn get_device_name() -> String {
    let platform = if cfg!(target_os = "macos") {
        "Mac Desktop"
    } else if cfg!(target_os = "linux") {
        "Linux Desktop"
    } else if cfg!(target_os = "windows") {
        "Windows Desktop"
    } else {
        "Desktop"
    };
    let id = get_device_id();
    // Skip the constant `desktop_` prefix, or every install would read
    // "(deskto)" and the suffix would stop telling machines apart.
    let random_part = id.strip_prefix("desktop_").unwrap_or(&id);
    let suffix: String = random_part.chars().take(6).collect();
    format!("{} ({})", platform, suffix)
}

/// This build's value for the backend `platform` enum
/// (WINDOWS | MACOS | LINUX | IOS | ANDROID | UNKNOWN).
///
/// The backend only infers the platform from the User-Agent for mobile; a
/// desktop body that omits the field is stored as UNKNOWN. Every desktop auth
/// payload therefore sends it explicitly, from this single mapping, so login
/// and anonymous registration can never disagree about what this machine is.
pub fn device_platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "WINDOWS",
        "macos" => "MACOS",
        "linux" => "LINUX",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod bounded_process_tests {
    /// W1-017's test plan: a hung subprocess is cut off at the limit instead
    /// of pinning the caller for as long as it runs.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn a_hung_subprocess_is_cut_off_at_the_limit() {
        let started = std::time::Instant::now();
        let result = super::run_bounded(
            super::hidden_async_cmd("cmd.exe").args(["/c", "ping -n 30 127.0.0.1 >nul"]),
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(result.unwrap_err().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    /// The blocking twin (round 3 of the review of #222): `schtasks` runs
    /// under the settings lock, so a hung one used to hold every save, and
    /// the kill switch's preference read, with it.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_hung_blocking_subprocess_is_cut_off_at_the_limit() {
        let started = std::time::Instant::now();
        let result = super::output_within(
            super::hidden_cmd("cmd.exe").args(["/c", "ping -n 30 127.0.0.1 >nul"]),
            std::time::Duration::from_secs(1),
        );
        assert!(result.unwrap_err().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));

        let out = super::output_within(
            super::hidden_cmd("cmd.exe").args(["/c", "echo birdo"]),
            std::time::Duration::from_secs(10),
        )
        .expect("cmd.exe runs");
        assert!(String::from_utf8_lossy(&out.stdout).contains("birdo"));
    }

    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn a_quick_subprocess_returns_its_output() {
        let out = super::run_bounded(
            super::hidden_async_cmd("cmd.exe").args(["/c", "echo birdo"]),
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("cmd.exe runs");
        assert!(String::from_utf8_lossy(&out.stdout).contains("birdo"));
    }

    /// WIN3-006: work that waits on a lock nobody releases — the machine
    /// state, WFP's engine or the log writer, held by a wedged teardown —
    /// costs the caller the limit, and no more.
    #[test]
    fn a_wedged_helper_never_holds_the_caller() {
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        let lock = Arc::new(Mutex::new(()));
        let held = lock.lock().unwrap();
        let wanted = Arc::clone(&lock);
        let (tx, rx) = std::sync::mpsc::channel();
        let started = Instant::now();
        std::thread::spawn(move || {
            let _ = tx.send(super::run_on_helper_for(
                "test-wedged",
                Duration::from_millis(100),
                move || {
                    let _wedged = wanted.lock();
                },
            ));
        });
        let finished = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the caller waited on the lock");
        assert!(!finished);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(held);

        assert!(super::run_on_helper_for(
            "test-quick",
            Duration::from_secs(5),
            || {}
        ));
    }

    /// MR-2000: locked work runs on the blocking pool, not on the async
    /// worker that awaits it. On this test's runtime there is ONE worker
    /// thread, and the work waits for a task that only that worker can run:
    /// run inline, it would hold the worker and wait out its timeout.
    #[tokio::test]
    async fn locked_work_runs_off_the_async_worker() {
        use std::time::Duration;
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        let (tx, rx) = std::sync::mpsc::channel();
        let work = super::locked_blocking(&LOCK, move || {
            rx.recv_timeout(Duration::from_secs(10)).is_ok()
        });
        let signal = async move {
            tokio::task::yield_now().await;
            tx.send(()).unwrap();
        };
        let (ran, ()) = tokio::join!(work, signal);
        assert_eq!(ran, Ok(true), "the work held the async worker");
    }

    /// MR-2000: a caller cancelled while its work runs (its future dropped)
    /// does not let the next holder of the lock in before the work is done:
    /// the guard is the blocking task's, not the caller's.
    #[tokio::test]
    async fn a_cancelled_caller_holds_the_lock_until_its_work_is_done() {
        use std::time::Duration;
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let mut caller = Box::pin(super::locked_blocking(&LOCK, move || {
            started_tx.send(()).unwrap();
            let _ = done_rx.recv_timeout(Duration::from_secs(10));
        }));
        let started = tokio::task::spawn_blocking(move || {
            started_rx.recv_timeout(Duration::from_secs(10)).is_ok()
        });
        tokio::select! {
            _ = &mut caller => panic!("the work finished before it was told to"),
            went = started => assert!(went.unwrap(), "the work never started"),
        }
        drop(caller);
        assert!(
            LOCK.try_lock().is_err(),
            "a cancelled caller let the next holder in while its work ran"
        );

        done_tx.send(()).unwrap();
        let next = tokio::time::timeout(Duration::from_secs(10), LOCK.lock()).await;
        assert!(
            next.is_ok(),
            "the lock was not released once the work was done"
        );
    }

    /// WIN3-006 (REVIEW-WIN3-013, which found this a source-order pin): the
    /// exit fallback exits whatever its last steps wait on. A cleanup stuck
    /// on a lock the wedged teardown holds costs the limit, and the exit
    /// still happens; a teardown that ran to its end leaves the exit to the
    /// normal path and runs no cleanup at all.
    #[test]
    fn the_exit_fallback_exits_whatever_its_cleanup_waits_on() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        let limit = Duration::from_millis(100);
        let teardown_holds = Arc::new(Mutex::new(()));
        let held = teardown_holds.lock().unwrap();
        let exited = AtomicBool::new(false);
        let started = Instant::now();
        let wanted = Arc::clone(&teardown_holds);
        assert!(super::exit_unless_torn_down(
            &AtomicBool::new(false),
            limit,
            move || {
                let _wedged = wanted.lock();
            },
            || exited.store(true, Ordering::SeqCst),
        ));
        assert!(exited.load(Ordering::SeqCst), "it did not exit");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "it waited on the lock"
        );
        drop(held);

        let (cleaned, exited) = (Arc::new(AtomicBool::new(false)), AtomicBool::new(false));
        let mark = Arc::clone(&cleaned);
        assert!(!super::exit_unless_torn_down(
            &AtomicBool::new(true),
            limit,
            move || mark.store(true, Ordering::SeqCst),
            || exited.store(true, Ordering::SeqCst),
        ));
        assert!(!exited.load(Ordering::SeqCst));
        assert!(
            !cleaned.load(Ordering::SeqCst),
            "a finished teardown's exit ran the cleanup"
        );

        let mark = Arc::clone(&cleaned);
        assert!(super::exit_unless_torn_down(
            &AtomicBool::new(false),
            Duration::from_secs(5),
            move || mark.store(true, Ordering::SeqCst),
            || {},
        ));
        assert!(
            cleaned.load(Ordering::SeqCst),
            "a quick cleanup was skipped"
        );
    }

    /// MR-1934: an exit that arrives with the teardown never started (macOS
    /// Cmd+Q, the Dock's Quit, logout) runs it, once, and the exit waits for
    /// it; one that comes after the held exit already ran it does not run it
    /// again; and a wedged teardown costs the limit, never the exit.
    #[test]
    fn an_exit_that_never_asked_first_runs_the_teardown_once() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        let started = AtomicBool::new(false);
        let runs = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&runs);
        assert_eq!(
            super::tear_down_unless_started(&started, Duration::from_secs(5), move || {
                std::thread::sleep(Duration::from_millis(100));
                count.fetch_add(1, Ordering::SeqCst);
            }),
            Some(true)
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "the exit did not wait for the teardown"
        );
        assert!(
            started.load(Ordering::SeqCst),
            "the teardown is not claimed"
        );

        // Already ran (the held exit's teardown, or this one): not again.
        let count = Arc::clone(&runs);
        assert_eq!(
            super::tear_down_unless_started(&started, Duration::from_secs(5), move || {
                count.fetch_add(1, Ordering::SeqCst);
            }),
            None
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        // A teardown stuck on what it waits for costs the limit.
        let wedge = Arc::new(Mutex::new(()));
        let held = wedge.lock().unwrap();
        let wanted = Arc::clone(&wedge);
        let begun = Instant::now();
        assert_eq!(
            super::tear_down_unless_started(
                &AtomicBool::new(false),
                Duration::from_millis(100),
                move || {
                    let _wedged = wanted.lock();
                },
            ),
            Some(false)
        );
        assert!(
            begun.elapsed() < Duration::from_secs(5),
            "the exit waited on the teardown"
        );
        drop(held);
    }
}

#[cfg(test)]
mod device_name_tests {
    #[test]
    fn the_suffix_comes_from_the_random_part_of_the_id() {
        let name = super::get_device_name();
        assert!(!name.contains("deskto"), "{name}");
        let id = super::get_device_id();
        let expected: String = id.trim_start_matches("desktop_").chars().take(6).collect();
        assert!(name.ends_with(&format!("({expected})")), "{name} vs {id}");
    }
}
