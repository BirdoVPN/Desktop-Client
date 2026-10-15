//! Copying a credential — the 24-digit anonymous account number, the
//! account's ONLY credential — without leaving it behind (MR-1723).
//!
//! The webview's `navigator.clipboard.writeText` is an ordinary copy: on
//! Windows it lands in clipboard history (Win+V), syncs to the cloud
//! clipboard when that is on, and stays on the clipboard until something else
//! replaces it. [`copy_sensitive`] puts the text on the clipboard together
//! with the registered formats Windows' clipboard history and cloud clipboard
//! honour (<https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats#cloud-clipboard-and-clipboard-history-formats>),
//! and clears it after [`CLEAR_AFTER`] — only if it still holds exactly what
//! was copied, so nothing the user copied since is wiped.
//!
//! MR-2013: or sooner, when the app exits first ([`clear_on_exit`], from
//! `main.rs`): the delayed clear is a task of this process, and a Quit inside
//! the minute used to take it down with the process and leave the account
//! number on the clipboard for good.
//!
//! Elsewhere it answers `false` and the UI copies the ordinary way, as before.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::ipc_error::IpcError;

/// How long the copied text stays on the clipboard before it is cleared (if
/// it is still there).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const CLEAR_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// The longest text taken. The callers copy a 24-digit number; the cap keeps
/// the command from parking an arbitrary blob on the clipboard.
const MAX_LEN: usize = 256;

/// The registered formats that keep a copy out of clipboard history and the
/// cloud clipboard, each set to a `DWORD` 0. `ExcludeClipboard…` alone
/// excludes everything ("place any data on the clipboard in this format");
/// the other two say the same thing to readers that look for them.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const PRIVACY_FORMATS: [&str; 3] = [
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
];

/// The data each of [`PRIVACY_FORMATS`] carries: a little-endian `DWORD` 0.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const DWORD_ZERO: [u8; 4] = 0u32.to_le_bytes();

/// The copy whose clear has not run yet (MR-2013): the latest one, as only
/// the latest can still be on the clipboard (each copy replaces the last).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
struct Pending {
    /// Which copy this is ([`PendingClears::arm`]).
    copy: u64,
    /// The clipboard's sequence number right after it ([`should_clear`]).
    armed: u32,
    /// The text, as [`to_wide_nul`] made it. Wiped on drop.
    text: Zeroizing<Vec<u16>>,
}

/// The clear each copy still owes: taken once, by its own delayed clear or by
/// the exit, whichever comes first.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
struct PendingClears {
    next: AtomicU64,
    pending: Mutex<Option<Pending>>,
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
impl PendingClears {
    const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            pending: Mutex::new(None),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Pending>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A copy was made: it is the one a clear is owed for now. Answers which
    /// copy it is, for its delayed clear.
    fn arm(&self, armed: u32, text: Zeroizing<Vec<u16>>) -> u64 {
        let copy = self.next.fetch_add(1, Ordering::Relaxed);
        *self.slot() = Some(Pending { copy, armed, text });
        copy
    }

    /// The delayed clear of `copy`: its own pending clear, unless a later copy
    /// replaced it or the exit already took it.
    fn take_own(&self, copy: u64) -> Option<Pending> {
        let mut slot = self.slot();
        if slot.as_ref().is_some_and(|p| p.copy == copy) {
            slot.take()
        } else {
            None
        }
    }

    /// The exit: whatever clear is still owed.
    fn take_any(&self) -> Option<Pending> {
        self.slot().take()
    }
}

/// This process's copies awaiting their clear.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
static PENDING: PendingClears = PendingClears::new();

/// MR-2013: clear the last credential copy now if its delayed clear has not
/// run yet, under the same rule ([`should_clear`]): only if the clipboard
/// still holds exactly it and nothing was copied since. `main.rs` calls it as
/// the process ends (`RunEvent::Exit`, the exit fallback) and the updater
/// before its installer takes over. Synchronous and brief: one clipboard open,
/// retried for at most ~200 ms.
pub fn clear_on_exit() {
    #[cfg(target_os = "windows")]
    if let Some(pending) = PENDING.take_any() {
        match win::clear_if_unchanged(pending.armed, &pending.text) {
            Ok(true) => tracing::info!("copy_sensitive: the copy was cleared at exit"),
            Ok(false) => tracing::debug!("copy_sensitive: the clipboard changed since; left alone"),
            Err(e) => tracing::warn!("copy_sensitive: could not clear the copy at exit ({e})"),
        }
    }
}

/// Copy `text` as a credential. `Ok(true)`: it is on the clipboard, kept out
/// of clipboard history and the cloud clipboard, and is cleared after
/// [`CLEAR_AFTER`] if still there (Windows). `Ok(false)`: nothing was done on
/// this platform; the UI copies it the ordinary way. `Err`: it could not be
/// copied, and the UI says nothing was — never a fallback to an ordinary copy
/// on Windows, which is the leak this exists to stop.
#[tauri::command]
pub async fn copy_sensitive(text: String) -> Result<bool, IpcError> {
    let text = Zeroizing::new(text);
    if !acceptable(&text) {
        return Err(IpcError::unknown("There is nothing to copy."));
    }
    #[cfg(target_os = "windows")]
    {
        let wide = to_wide_nul(&text);
        let copy = wide.clone();
        let armed = tauri::async_runtime::spawn_blocking(move || win::set(&copy))
            .await
            .map_err(|_| IpcError::unknown("The clipboard could not be reached."))?
            .map_err(|e| {
                tracing::warn!("copy_sensitive: the clipboard refused the copy ({e})");
                IpcError::unknown("The clipboard could not be reached.")
            })?;
        // MR-2013: owed from now on, by this task or, if the app exits first,
        // by `clear_on_exit`.
        let copy = PENDING.arm(armed, wide);
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(CLEAR_AFTER).await;
            let Some(pending) = PENDING.take_own(copy) else {
                // A later copy owns the clipboard now, or the exit cleared it.
                return;
            };
            let cleared = tauri::async_runtime::spawn_blocking(move || {
                win::clear_if_unchanged(pending.armed, &pending.text)
            })
            .await;
            match cleared {
                Ok(Ok(true)) => tracing::debug!("copy_sensitive: the copy was cleared"),
                Ok(Ok(false)) => {
                    tracing::debug!("copy_sensitive: the clipboard changed since; left alone")
                }
                Ok(Err(e)) => tracing::warn!("copy_sensitive: could not clear the copy ({e})"),
                Err(_) => tracing::warn!("copy_sensitive: the clear did not run"),
            }
        });
        Ok(true)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}

/// Non-empty, at most [`MAX_LEN`] bytes, and no NUL (which would cut the
/// clipboard's text short).
fn acceptable(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_LEN && !text.contains('\0')
}

/// `text` as the clipboard stores it: UTF-16 with a terminating NUL. Wiped
/// on drop, like every copy of the credential this module makes.
///
/// Built in a buffer allocated once, at its final size: UTF-16 never takes
/// more units than UTF-8 takes bytes, so `len + 1` holds it all. A growing
/// `collect()` would reallocate and free the earlier, un-wiped buffers.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn to_wide_nul(text: &str) -> Zeroizing<Vec<u16>> {
    let mut wide = Zeroizing::new(Vec::with_capacity(text.len() + 1));
    wide.extend(text.encode_utf16());
    wide.push(0);
    wide
}

/// Whether the clipboard's text `held` (as stored: possibly NUL-terminated,
/// possibly with slack after it) is exactly `ours` (as [`to_wide_nul`] made
/// it).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn same_text(held: &[u16], ours: &[u16]) -> bool {
    let until_nul = |s: &[u16]| s.iter().position(|&u| u == 0).unwrap_or(s.len());
    held[..until_nul(held)] == ours[..until_nul(ours)]
}

/// Whether the delayed clear may empty the clipboard: only while it still
/// holds the copied text AND, where Windows numbers clipboard changes, nothing
/// has been put on it since — a user who copied anything after us, the same
/// digits included, keeps it. `armed` is the clipboard's sequence number right
/// after the copy; 0 means Windows gave none (no clipboard access for this
/// window station), and then only the text decides.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn should_clear(armed: u32, current: u32, still_holds_text: bool) -> bool {
    still_holds_text && (armed == 0 || current == armed)
}

#[cfg(target_os = "windows")]
mod win {
    use windows::core::{Error, Result, HSTRING};
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
        OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
    };

    /// `CF_UNICODETEXT` (winuser.h). Spelled out rather than pulling in the
    /// `Win32_System_Ole` feature for one constant.
    const CF_UNICODETEXT: u32 = 13;

    /// The clipboard, held open; closed on drop, on every path.
    struct Opened;

    impl Opened {
        /// Another process may hold the clipboard for a moment (a clipboard
        /// manager reading the previous copy), so a refusal is retried
        /// briefly before it counts.
        fn open() -> Result<Self> {
            let mut attempt = 0;
            loop {
                // SAFETY: no owner window; the clipboard is closed by `Drop`.
                match unsafe { OpenClipboard(None) } {
                    Ok(()) => return Ok(Opened),
                    Err(e) if attempt >= 9 => return Err(e),
                    Err(_) => {
                        attempt += 1;
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                }
            }
        }
    }

    impl Drop for Opened {
        fn drop(&mut self) {
            // SAFETY: only reachable after a successful OpenClipboard.
            let _ = unsafe { CloseClipboard() };
        }
    }

    /// Put `bytes` on the open clipboard as `format`. On success the system
    /// owns the memory; on failure it is freed here.
    fn put(_open: &Opened, format: u32, bytes: &[u8]) -> Result<()> {
        // SAFETY: `mem` is a fresh movable block of at least `bytes.len()`
        // bytes, written only while locked; ownership passes to the system
        // only when SetClipboardData succeeds, and is freed here otherwise.
        unsafe {
            let mem = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1))?;
            let ptr = GlobalLock(mem).cast::<u8>();
            if ptr.is_null() {
                let error = Error::from_thread();
                let _ = GlobalFree(Some(mem));
                return Err(error);
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            // Err with NO_ERROR when the lock count reaches 0: not a failure.
            let _ = GlobalUnlock(mem);
            if let Err(error) = SetClipboardData(format, Some(HANDLE(mem.0))) {
                let _ = GlobalFree(Some(mem));
                return Err(error);
            }
        }
        Ok(())
    }

    /// The registered format ids of [`super::PRIVACY_FORMATS`].
    fn privacy_formats() -> Result<[u32; 3]> {
        let mut ids = [0u32; 3];
        for (id, name) in ids.iter_mut().zip(super::PRIVACY_FORMATS) {
            // SAFETY: a NUL-terminated wide string that outlives the call.
            *id = unsafe { RegisterClipboardFormatW(&HSTRING::from(name)) };
            if *id == 0 {
                return Err(Error::from_thread());
            }
        }
        Ok(ids)
    }

    /// Replace the clipboard with `text` (UTF-16, NUL-terminated) marked to
    /// stay out of clipboard history and the cloud clipboard. Answers the
    /// clipboard's sequence number after the copy, which the delayed clear
    /// compares against. The text never goes on unmarked: if any mark fails,
    /// the clipboard is left empty and the copy fails.
    pub(super) fn set(text: &[u16]) -> Result<u32> {
        let formats = privacy_formats()?;
        let open = Opened::open()?;
        // SAFETY: the clipboard is open (`open`).
        unsafe { EmptyClipboard()? };
        let marked = formats
            .iter()
            .try_for_each(|&format| put(&open, format, &super::DWORD_ZERO));
        // SAFETY: `text` is a live slice of u16; viewing it as bytes is sound.
        let bytes = unsafe {
            std::slice::from_raw_parts(text.as_ptr().cast::<u8>(), std::mem::size_of_val(text))
        };
        if let Err(error) = marked.and_then(|()| put(&open, CF_UNICODETEXT, bytes)) {
            // SAFETY: still open.
            let _ = unsafe { EmptyClipboard() };
            return Err(error);
        }
        drop(open);
        // SAFETY: no preconditions.
        Ok(unsafe { GetClipboardSequenceNumber() })
    }

    /// Whether the open clipboard's text is exactly `ours`, compared in
    /// place: nothing the user copied is read into this process's memory.
    fn holds(_open: &Opened, ours: &[u16]) -> bool {
        // SAFETY: the clipboard is open; the data handle belongs to the
        // clipboard and is only read, while locked, within its size.
        unsafe {
            let Ok(handle) = GetClipboardData(CF_UNICODETEXT) else {
                return false;
            };
            let mem = HGLOBAL(handle.0);
            let ptr = GlobalLock(mem).cast::<u16>();
            if ptr.is_null() {
                return false;
            }
            let held = std::slice::from_raw_parts(ptr, GlobalSize(mem) / 2);
            let same = super::same_text(held, ours);
            let _ = GlobalUnlock(mem);
            same
        }
    }

    /// Empty the clipboard if it still holds what [`set`] put there (see
    /// [`super::should_clear`]). Decided and done under one open, so nothing
    /// can be copied in between. Answers whether it cleared.
    pub(super) fn clear_if_unchanged(armed: u32, ours: &[u16]) -> Result<bool> {
        let open = Opened::open()?;
        // SAFETY: no preconditions.
        let current = unsafe { GetClipboardSequenceNumber() };
        if !super::should_clear(armed, current, holds(&open, ours)) {
            return Ok(false);
        }
        // SAFETY: the clipboard is open (`open`).
        unsafe { EmptyClipboard()? };
        Ok(true)
    }

    /// What the Windows round-trip test reads and writes besides the real
    /// path (review of #289): the clipboard as it is, an ordinary copy (what
    /// another app's copy looks like), and putting the developer's own
    /// clipboard text back afterwards.
    #[cfg(test)]
    pub(super) mod probe {
        use super::*;
        use std::time::{Duration, Instant};

        /// The clipboard, opened patiently: another process (a monitor
        /// reading the last copy) may hold it for a while. `None` only when
        /// it cannot be opened at all, e.g. a session with no interactive
        /// window station.
        fn open_patiently(within: Duration) -> Option<Opened> {
            let start = Instant::now();
            loop {
                if let Ok(open) = Opened::open() {
                    return Some(open);
                }
                if start.elapsed() >= within {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        pub(crate) fn can_open() -> bool {
            open_patiently(Duration::from_secs(10)).is_some()
        }

        /// The raw bytes of `format` on the open clipboard, whole block.
        fn read(_open: &Opened, format: u32) -> Option<Vec<u8>> {
            // SAFETY: open clipboard; the block is only read, while locked,
            // within its size.
            unsafe {
                let handle = GetClipboardData(format).ok()?;
                let mem = HGLOBAL(handle.0);
                let ptr = GlobalLock(mem).cast::<u8>();
                if ptr.is_null() {
                    return None;
                }
                let bytes = std::slice::from_raw_parts(ptr, GlobalSize(mem)).to_vec();
                let _ = GlobalUnlock(mem);
                Some(bytes)
            }
        }

        fn wide(bytes: Vec<u8>) -> Vec<u16> {
            bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect()
        }

        /// What is on the clipboard now: its text, and each privacy format
        /// as (registered id, data).
        pub(crate) struct Snapshot {
            pub(crate) text: Option<Vec<u16>>,
            pub(crate) marks: Vec<(u32, Option<Vec<u8>>)>,
        }

        pub(crate) fn snapshot() -> Snapshot {
            let ids = privacy_formats().expect("the privacy formats register");
            let open = open_patiently(Duration::from_secs(10)).expect("the clipboard opens");
            Snapshot {
                text: read(&open, CF_UNICODETEXT).map(wide),
                marks: ids.iter().map(|&id| (id, read(&open, id))).collect(),
            }
        }

        /// Another app's copy of `text` (UTF-16, NUL-terminated): a new
        /// clipboard content, so the sequence number moves. It opts out of
        /// clipboard history too, only so the test leaves nothing in a
        /// developer's Win+V history.
        pub(crate) fn set_plain(text: &[u16]) -> Result<()> {
            let [exclude, ..] = privacy_formats()?;
            let open = Opened::open()?;
            // SAFETY: open clipboard; `text` viewed as bytes, as in `set`.
            unsafe {
                EmptyClipboard()?;
                put(&open, exclude, &super::super::DWORD_ZERO)?;
                let bytes = std::slice::from_raw_parts(
                    text.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(text),
                );
                put(&open, CF_UNICODETEXT, bytes)
            }
        }

        /// Puts back, on drop, the text that was on the clipboard when it
        /// was made, so running the tests on a workstation does not eat the
        /// developer's clipboard (text only; anything else is lost).
        pub(crate) struct Restore(Option<Vec<u16>>);

        impl Restore {
            pub(crate) fn save() -> Self {
                let open = open_patiently(Duration::from_secs(10));
                Self(open.and_then(|open| read(&open, CF_UNICODETEXT)).map(wide))
            }
        }

        impl Drop for Restore {
            fn drop(&mut self) {
                if let Some(text) = &self.0 {
                    for _ in 0..50 {
                        if set_plain(text).is_ok() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact registered names Windows looks for, each with a DWORD 0 —
    /// a typo in a name is a copy that silently lands in Win+V history.
    #[test]
    fn the_privacy_formats_are_the_documented_ones_set_to_zero() {
        assert_eq!(
            PRIVACY_FORMATS,
            [
                "ExcludeClipboardContentFromMonitorProcessing",
                "CanIncludeInClipboardHistory",
                "CanUploadToCloudClipboard",
            ]
        );
        assert_eq!(DWORD_ZERO, [0, 0, 0, 0]);
        assert_eq!(u32::from_le_bytes(DWORD_ZERO), 0);
        assert_eq!(CLEAR_AFTER, std::time::Duration::from_secs(60));
    }

    /// The text goes on as the clipboard stores it, and is compared the same
    /// way: up to the NUL, whatever slack the clipboard's block has after it.
    #[test]
    fn the_text_is_utf16_with_a_nul_and_compared_up_to_it() {
        let ours = to_wide_nul("123456789012345678901234");
        assert_eq!(ours.len(), 25);
        assert_eq!(ours.last(), Some(&0));
        assert!(same_text(&ours, &ours));
        let mut slack = ours.to_vec();
        slack.extend([0, 0x41, 0]);
        assert!(same_text(&slack, &ours));
        let no_nul: Vec<u16> = "123456789012345678901234".encode_utf16().collect();
        assert!(same_text(&no_nul, &ours));
        assert!(!same_text(&to_wide_nul("12345678901234567890123"), &ours));
        assert!(!same_text(&to_wide_nul("1234567890123456789012345"), &ours));
        assert!(!same_text(&to_wide_nul("something else"), &ours));
        assert!(!same_text(&[], &ours));
    }

    /// The clear empties the clipboard only while it still holds our copy
    /// and nothing was copied since — not even the same digits.
    #[test]
    fn the_clear_runs_only_if_the_clipboard_is_unchanged() {
        // Untouched since the copy.
        assert!(should_clear(41, 41, true));
        // Something else copied since: different text.
        assert!(!should_clear(41, 42, false));
        // The user copied the same digits again from somewhere else.
        assert!(!should_clear(41, 42, true));
        // The text was replaced and the number cannot tell (or both moved).
        assert!(!should_clear(41, 41, false));
        // No sequence numbers on this window station: the text decides.
        assert!(should_clear(0, 0, true));
        assert!(!should_clear(0, 0, false));
    }

    #[test]
    fn only_a_short_text_without_nul_is_taken() {
        assert!(acceptable("123456789012345678901234"));
        assert!(!acceptable(""));
        assert!(!acceptable("12\u{0}34"));
        assert!(!acceptable(&"1".repeat(MAX_LEN + 1)));
        assert!(acceptable(&"1".repeat(MAX_LEN)));
    }

    /// `to_wide_nul` allocates once, at its final size, so no un-wiped
    /// intermediate buffer is left behind (review of #289).
    #[test]
    fn the_wide_buffer_is_allocated_once() {
        for text in ["123456789012345678901234", "é", "日本", "🦆"] {
            let wide = to_wide_nul(text);
            assert_eq!(wide.capacity(), text.len() + 1, "{text}");
            assert_eq!(wide.len(), text.encode_utf16().count() + 1, "{text}");
            assert_eq!(wide.last(), Some(&0));
        }
    }

    /// Review of #289: the real round trip, on the real clipboard. A copy is
    /// read back with its text and the three privacy formats (registered,
    /// each a 4-byte zero); the delayed clear empties an untouched clipboard,
    /// and leaves it alone after another copy: of different text and, where
    /// Windows numbers clipboard changes, of the very same digits.
    ///
    /// Busy is retried. It is skipped only when the clipboard cannot be opened
    /// at all in this session, and says so on stderr either way (written past
    /// the test harness's capture, so a CI log shows whether it ran). A
    /// developer's own clipboard text is put back afterwards.
    #[cfg(target_os = "windows")]
    #[test]
    fn the_windows_copy_is_marked_and_cleared_only_if_unchanged() {
        use std::io::Write;
        let say = |line: &str| {
            let _ = writeln!(std::io::stderr(), "{line}");
        };
        if !win::probe::can_open() {
            say(
                "copy_sensitive clipboard round-trip: SKIPPED - OpenClipboard is impossible in \
                 this session (no interactive window station)",
            );
            return;
        }
        let _restore = win::probe::Restore::save();
        // Busy clipboards (a monitor reading the last copy) are retried.
        fn retry<T>(what: &str, mut f: impl FnMut() -> windows::core::Result<T>) -> T {
            let mut last = None;
            for _ in 0..50 {
                match f() {
                    Ok(value) => return value,
                    Err(e) => last = Some(e),
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            panic!("{what}: {last:?}");
        }
        let holds = |text: &[u16]| {
            win::probe::snapshot()
                .text
                .is_some_and(|held| same_text(&held, text))
        };
        let ours = to_wide_nul(&format!("birdo-copy-sensitive-test-{}", std::process::id()));

        // The copy, read back: the text and the three marks.
        let armed = retry("copy", || win::set(&ours));
        let snapshot = win::probe::snapshot();
        assert!(
            snapshot
                .text
                .as_deref()
                .is_some_and(|held| same_text(held, &ours)),
            "the text is on the clipboard"
        );
        assert_eq!(snapshot.marks.len(), PRIVACY_FORMATS.len());
        for ((id, data), name) in snapshot.marks.iter().zip(PRIVACY_FORMATS) {
            assert_ne!(*id, 0, "{name} is registered");
            let data = data
                .as_deref()
                .unwrap_or_else(|| panic!("{name} is on the clipboard"));
            assert!(data.len() >= 4, "{name}: {} bytes", data.len());
            assert_eq!(data[..4], DWORD_ZERO, "{name} is a DWORD 0");
        }

        // Untouched since the copy: cleared.
        assert!(retry("clear", || win::clear_if_unchanged(armed, &ours)));
        assert!(
            win::probe::snapshot().text.is_none(),
            "the copy was cleared"
        );

        // The same digits copied again elsewhere: the sequence number moved,
        // so it is the user's copy now and is left alone.
        let armed = retry("copy", || win::set(&ours));
        retry("another copy", || win::probe::set_plain(&ours));
        if armed != 0 {
            assert!(!retry("clear", || win::clear_if_unchanged(armed, &ours)));
            assert!(holds(&ours), "the user's copy was wiped");
        }

        // Something else copied since: left alone.
        let theirs = to_wide_nul("something the user copied");
        retry("another copy", || win::probe::set_plain(&theirs));
        assert!(!retry("clear", || win::clear_if_unchanged(armed, &ours)));
        assert!(holds(&theirs), "the user's copy was wiped");

        // MR-2013: the app exits inside the minute. The copy still owed its
        // clear is cleared then (the only test that uses `PENDING`).
        let armed = retry("copy", || win::set(&ours));
        PENDING.arm(
            armed,
            to_wide_nul(&format!("birdo-copy-sensitive-test-{}", std::process::id())),
        );
        assert!(holds(&ours));
        clear_on_exit();
        assert!(
            win::probe::snapshot().text.is_none(),
            "the exit left the copy on the clipboard"
        );

        say(&format!(
            "copy_sensitive clipboard round-trip: RAN (sequence numbers: {})",
            if armed != 0 { "yes" } else { "no, text only" }
        ));
    }

    /// MR-2013: each copy's clear is owed once, to whichever comes first: its
    /// own delayed clear, or the exit. A later copy takes the debt over (only
    /// the latest can still be on the clipboard), so an earlier copy's timer
    /// finds nothing to do, and after the exit neither does the latest's.
    #[test]
    fn a_copys_clear_is_owed_once_to_its_timer_or_the_exit() {
        let clears = PendingClears::new();
        assert!(clears.take_any().is_none(), "nothing copied, nothing owed");

        let first = clears.arm(7, to_wide_nul("111122223333444455556666"));
        let second = clears.arm(8, to_wide_nul("999988887777666655554444"));
        assert_ne!(first, second);
        assert!(
            clears.take_own(first).is_none(),
            "the later copy took it over"
        );

        // The app exits inside the minute: the exit takes the latest copy.
        let owed = clears.take_any().expect("the latest copy is owed a clear");
        assert_eq!(owed.copy, second);
        assert_eq!(owed.armed, 8);
        assert!(same_text(
            &owed.text,
            &to_wide_nul("999988887777666655554444")
        ));
        assert!(
            clears.take_own(second).is_none(),
            "the exit already cleared it"
        );
        assert!(clears.take_any().is_none());

        // Its timer, when the app stays: taken once, by its own copy only.
        let third = clears.arm(9, to_wide_nul("123412341234123412341234"));
        assert!(clears.take_own(third + 1).is_none());
        assert_eq!(clears.take_own(third).map(|p| p.armed), Some(9));
        assert!(clears.take_any().is_none());
    }

    /// MR-2013: the exit clears it. `main.rs` calls `clear_on_exit` where the
    /// process ends (`RunEvent::Exit`, and the exit fallback that exits
    /// without the teardown), and the updater before its installer exits the
    /// process (Windows).
    #[test]
    fn every_exit_clears_a_pending_copy() {
        let main = include_str!("../main.rs");
        let exit = &main[main
            .find("if matches!(event, RunEvent::Exit) {")
            .expect("the Exit arm")..];
        let exit = &exit[..exit.find("\n            }").unwrap()];
        assert!(
            exit.contains("commands::clipboard::clear_on_exit();"),
            "RunEvent::Exit"
        );
        let fallback = &main[main
            .find(".name(\"birdo-exit-fallback\".into())")
            .expect("the exit fallback")..];
        let fallback = &fallback[..fallback.find("|| std::process::exit(0),").unwrap()];
        assert!(
            fallback.contains("commands::clipboard::clear_on_exit();"),
            "the exit fallback"
        );
        let updater = include_str!("updater.rs");
        let install = &updater[updater.find("pub async fn install_update(").unwrap()..];
        let clear = install
            .find("crate::commands::clipboard::clear_on_exit();")
            .expect("the updater clears before its installer exits the process");
        assert!(clear < install.find("update.install(bundle)").unwrap());
    }

    /// Off Windows nothing is done natively: the UI copies the ordinary way.
    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn off_windows_the_ui_copies() {
        assert_eq!(copy_sensitive("123".into()).await, Ok(false));
    }

    /// Refused input is an error on every platform, never a silent no-op.
    #[tokio::test]
    async fn refused_input_is_an_error() {
        assert!(copy_sensitive(String::new()).await.is_err());
        assert!(copy_sensitive("1".repeat(MAX_LEN + 1)).await.is_err());
    }
}
