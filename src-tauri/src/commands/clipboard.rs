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
//! Elsewhere it answers `false` and the UI copies the ordinary way, as before.

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
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(CLEAR_AFTER).await;
            let cleared =
                tauri::async_runtime::spawn_blocking(move || win::clear_if_unchanged(armed, &wide))
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
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn to_wide_nul(text: &str) -> Zeroizing<Vec<u16>> {
    Zeroizing::new(text.encode_utf16().chain(std::iter::once(0)).collect())
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
